import { randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { expect, it, vi } from "vitest";
import { HAR_CAPTURE_PROVIDER_IDENTITY } from "../../../src/browser/history/CaptureRelease.js";
import { HarCaptureAdapter } from "../../../src/browser/history/HarCaptureAdapter.js";
import { HistoricalCaptureDecoder } from "../../../src/browser/history/HistoricalCaptureDecoder.js";
import { MitmproxyCaptureAdapter } from "../../../src/browser/history/MitmproxyCaptureAdapter.js";
import { inspectWebNetworkCaptureInputSchema } from "../../../src/domain/webNetworkCapture.js";
import { runOwnedCommand } from "../../../src/process/OwnedCommand.js";
import { prepareProcessOwnershipInspection } from "../../../src/process/ProcessOwnershipObservation.js";
import { historicalHar } from "../../fixtures/historicalHar.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

// Model a host whose native ownership helper cannot be prepared, such as a
// macOS Command Line Tools install whose Swift compiler rejects its own SDK.
vi.mock(
  "../../../src/process/ProcessOwnershipObservation.js",
  async (importOriginal) => ({
    ...(await importOriginal<
      typeof import("../../../src/process/ProcessOwnershipObservation.js")
    >()),
    prepareProcessOwnershipInspection: vi.fn(async () => {
      throw new Error("native ownership helper compilation failed");
    }),
  }),
);

const command = (script: string) => ({
  command: process.execPath,
  arguments: ["-e", script],
  runId: `rea-owned-child-test-${randomUUID()}`,
});

const recordedPid = async (path: string): Promise<number> => {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const text = await readFile(path, "utf8").catch(() => "");
    if (text.endsWith("\n")) return Number(text.trim());
    await delay(10);
  }
  throw new Error("Child did not record its process ID");
};

const isRunning = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

it("collects a REA-owned child without native process-group preparation", async () => {
  const snapshot = await runOwnedCommand(
    command('process.stdout.write("decoded")'),
    { timeoutMs: 5_000, diagnosticBytes: 1024 },
    { supervision: "direct-child" },
  );
  expect(snapshot).toMatchObject({
    exitCode: 0,
    signal: null,
    stdout: { text: "decoded" },
  });
  expect(prepareProcessOwnershipInspection).not.toHaveBeenCalled();
});

it("still requires native preparation for process-group commands", async () => {
  await expect(
    runOwnedCommand(command("process.exit(0)"), {
      timeoutMs: 5_000,
      diagnosticBytes: 1024,
    }),
  ).rejects.toThrow("native ownership helper compilation failed");
});

it("terminates a cancelled direct child through its live handle", async () => {
  const root = await createTestTempDirectory("rea-owned-child-cancel-");
  const pidPath = join(root, "pid");
  const controller = new AbortController();
  const result = runOwnedCommand(
    command(
      `require("node:fs").writeFileSync(${JSON.stringify(pidPath)}, process.pid + "\\n"); setInterval(() => undefined, 1000)`,
    ),
    { timeoutMs: 10_000, diagnosticBytes: 1024 },
    { supervision: "direct-child", signal: controller.signal },
  );
  const pid = await recordedPid(pidPath);
  controller.abort();
  await expect(result).rejects.toMatchObject({
    reason: "cancelled",
    cleanupFailure: null,
  });
  expect(isRunning(pid)).toBe(false);
});

it.skipIf(process.platform === "win32")(
  "escalates a deadline-expired direct child that ignores termination",
  async () => {
    const root = await createTestTempDirectory("rea-owned-child-timeout-");
    const pidPath = join(root, "pid");
    const result = runOwnedCommand(
      command(
        `process.on("SIGTERM", () => undefined); require("node:fs").writeFileSync(${JSON.stringify(pidPath)}, process.pid + "\\n"); setInterval(() => undefined, 1000)`,
      ),
      { timeoutMs: 2_000, diagnosticBytes: 1024 },
      { supervision: "direct-child" },
    );
    const pid = await recordedPid(pidPath);
    await expect(result).rejects.toMatchObject({
      reason: "timeout",
      cleanupFailure: null,
    });
    expect(isRunning(pid)).toBe(false);
  },
);

it("refuses a memory limit that a direct child cannot enforce", async () => {
  await expect(
    runOwnedCommand(
      { ...command("process.exit(0)"), memoryLimitBytes: 1024 * 1024 * 1024 },
      { timeoutMs: 5_000, diagnosticBytes: 1024 },
      { supervision: "direct-child" },
    ),
  ).rejects.toThrow(/Windows Job Object launcher/u);
});

it("declares process-group supervision for external mitmdump only", () => {
  expect(new MitmproxyCaptureAdapter({}).supervision).toBe("process-group");
  expect(new HarCaptureAdapter().supervision).toBe("direct-child");
});

it.each([
  { supervision: "process-group", memoryLimitBytes: undefined, prepared: 1 },
  { supervision: "direct-child", memoryLimitBytes: undefined, prepared: 0 },
  // Only the owned launcher enforces a requested memory limit.
  {
    supervision: "direct-child",
    memoryLimitBytes: 704 * 1024 * 1024,
    prepared: 1,
  },
] as const)(
  "routes a $supervision capture adapter with memory limit $memoryLimitBytes",
  async ({ supervision, memoryLimitBytes, prepared }) => {
    const root = await createTestTempDirectory("rea-decoder-supervision-");
    const path = join(root, "capture.har");
    await writeFile(path, JSON.stringify(historicalHar()));
    vi.mocked(prepareProcessOwnershipInspection).mockClear();
    const decoder = new HistoricalCaptureDecoder(
      [
        {
          format: "har",
          identity: HAR_CAPTURE_PROVIDER_IDENTITY,
          supervision,
          command: async () => ({
            command: process.execPath,
            arguments: ["-e", ""],
            ...(memoryLimitBytes === undefined ? {} : { memoryLimitBytes }),
          }),
        },
      ],
      process.env,
    );

    const result = await decoder.inspect(
      inspectWebNetworkCaptureInputSchema.parse({
        capture_path: path,
        format: "har",
      }),
    );

    // The stub writes no reply, so every run fails; only the owned launcher
    // depends on native ownership preparation.
    expect(result.ok).toBe(false);
    expect(prepareProcessOwnershipInspection).toHaveBeenCalledTimes(prepared);
  },
);

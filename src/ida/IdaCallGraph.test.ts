import { describe, expect, it } from "vitest";
import {
  AnalysisCancelledError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { isX86OnlyTarget, readCallGraphCallees } from "./IdaCallGraph.js";

const target = (
  architecture: "x86" | "x86_64" | "arm" | "arm64",
  available: readonly ("x86" | "x86_64" | "arm" | "arm64")[] = [architecture],
): BinaryTarget => ({
  path: "/fixture",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "mach-o",
  architecture,
  availableArchitectures: [...available],
});

const row = (
  edges: readonly { from: string; to: string; type: string }[],
  extra: Readonly<Record<string, JsonValue>> = {},
): JsonValue => [
  {
    root: "0x1000",
    nodes: [
      { addr: "0x1000", name: "main" },
      { addr: "0x20", name: "low" },
      { addr: "0x100", name: "" },
      { addr: "0x300", name: null },
    ],
    edges: [...edges],
    ...extra,
  },
];
const call = (from: string, to: string) => ({ from, to, type: "call" });

describe("architecture gate for the call graph source", () => {
  it.each([
    ["x86", target("x86"), true],
    ["x86_64", target("x86_64"), true],
    ["x86 with both x86 families", target("x86_64", ["x86", "x86_64"]), true],
    ["32-bit arm", target("arm"), false],
    ["arm64", target("arm64"), false],
    [
      "a universal target with an arm64 slice",
      target("x86_64", ["x86_64", "arm64"]),
      false,
    ],
  ])("treats %s as x86-only: %s", (_label, candidate, expected) => {
    expect(
      isX86OnlyTarget(candidate),
      "the gate follows every loadable slice",
    ).toBe(expected);
  });

  it.each([
    ["a native PE", false, true],
    ["a managed PE that IDA may load with the CLI loader", true, false],
  ])("treats %s as x86-only: %s", (_label, managed, expected) => {
    expect(
      isX86OnlyTarget({
        path: "/fixture",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "pe",
        architecture: "x86_64",
        availableArchitectures: ["x86_64"],
        executableRole: "application",
        managed,
      }),
      "a managed image is not proven to be processed as x86",
    ).toBe(expected);
  });

  it("never treats a non-executable target as x86-only", () => {
    expect(
      isX86OnlyTarget({
        path: "/fixture",
        sha256: "a".repeat(64),
        kind: "archive",
        format: "zip",
      }),
      "only executables can be proven x86-only",
    ).toBe(false);
  });
});

describe("reading callees from a depth-one call graph", () => {
  it("requests exactly the procedure as root at depth one", async () => {
    const requests: unknown[] = [];

    await readCallGraphCallees(async (tool, args) => {
      requests.push([tool, args]);
      return row([]);
    }, "0x1000");

    expect(requests, "one scoped request, no other tool").toEqual([
      ["callgraph", { roots: ["0x1000"], max_depth: 1 }],
    ]);
  });

  it("keeps only call edges that leave the requested procedure", async () => {
    const result = await readCallGraphCallees(
      async () =>
        row([
          call("0x1000", "0x20"),
          { from: "0x1000", to: "0x400", type: "jump" },
          call("0x20", "0x500"),
        ]),
      "0x1000",
    );

    expect(
      result.callees.map(({ address }) => address),
      "child edges and non-call edges are excluded",
    ).toEqual(["0x20"]);
  });

  it("orders additions numerically and names unnamed nodes by address", async () => {
    const result = await readCallGraphCallees(
      async () =>
        row([
          call("0x1000", "0x300"),
          call("0x1000", "0x100"),
          call("0x1000", "0x20"),
        ]),
      "0x1000",
    );

    expect(
      result.callees,
      "numeric order, with the address as the name of an empty or null name",
    ).toEqual([
      { address: "0x20", name: "low" },
      { address: "0x100", name: "0x100" },
      { address: "0x300", name: "0x300" },
    ]);
  });

  it.each([
    ["truncated", { truncated: true }],
    ["limit_reason", { limit_reason: "edges" }],
  ])("reports a graph flagged by %s as truncated", async (_label, extra) => {
    const result = await readCallGraphCallees(
      async () => row([call("0x1000", "0x20")], extra),
      "0x1000",
    );

    expect(
      result.limitations,
      "each truncation signal counts on its own",
    ).toEqual([
      "Upstream callgraph was truncated; additional callees remain unknown.",
    ]);
  });

  it("does not blame the root for a cap that only a child function reached", async () => {
    const result = await readCallGraphCallees(
      async () =>
        row([call("0x1000", "0x20")], {
          per_func_capped: true,
          max_edges_per_func: 200,
        }),
      "0x1000",
    );

    expect(
      result.limitations,
      "per_func_capped is graph-wide; the root's own edge count decides",
    ).toEqual([]);
  });

  it("reports a graph that saturates its per-function cap with root edges", async () => {
    const result = await readCallGraphCallees(
      async () =>
        row([call("0x1000", "0x20"), call("0x1000", "0x100")], {
          max_edges_per_func: 2,
        }),
      "0x1000",
    );

    expect(
      result.limitations,
      "reaching the cap is uncertain, so it is reported as possible truncation",
    ).toEqual([
      "Upstream callgraph may be truncated; additional callees may remain unknown.",
    ]);
  });

  it("fails the read for a reply about a different root", async () => {
    await expect(
      readCallGraphCallees(
        async () => [
          { root: "0x2000", nodes: [], edges: [call("0x1000", "0x20")] },
        ],
        "0x1000",
      ),
      "edges of another root are never observed",
    ).rejects.toThrow(/different root/u);
  });

  it("fails the read for an error row and for an unreadable reply", async () => {
    await expect(
      readCallGraphCallees(
        async () => [
          { root: "0x1000", error: "Function not found", nodes: [], edges: [] },
        ],
        "0x1000",
      ),
      "the upstream reason is kept",
    ).rejects.toThrow("Function not found");
    await expect(
      readCallGraphCallees(async () => ({ unexpected: true }), "0x1000"),
      "an unreadable reply is a producer fault",
    ).rejects.toThrow(/unreadable/u);
  });

  it("lets tool failures, truncated output, cancellation and transport failures surface unchanged", async () => {
    const failures = [
      new AnalysisProtocolError("IDA MCP tool failed: boom"),
      new AnalysisProtocolError(
        "IDA MCP truncated its output; the preview cannot establish a complete observation.",
      ),
      new AnalysisCancelledError("callgraph"),
      new Error("transport timed out"),
    ];
    for (const failure of failures)
      await expect(
        readCallGraphCallees(async () => {
          throw failure;
        }, "0x1000"),
        `${failure.message} is not turned into an observation`,
      ).rejects.toBe(failure);
  });
});

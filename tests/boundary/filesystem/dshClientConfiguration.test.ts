import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parse as parseYaml } from "yaml";

import { readClientRegistrationStatuses } from "../../../src/application/ClientRegistrationStatus.js";
import { npxRegistrationCommand } from "../../../src/application/ClientRegistrationIdentity.js";
import { configureClientConfiguration } from "../../../src/application/SetupClientConfiguration.js";
import {
  clientSkillDirectories,
  supportedClients,
} from "../../../src/application/SupportedClients.js";
import { systemUninstallHost } from "../../../src/application/Uninstall.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { clearClientLocationEnvironment } from "../../fixtures/clientEnvironment.js";

/**
 * The registration command setup writes on the host running the tests. Windows
 * wraps it in `cmd.exe /d /c`, so the expected entry follows the host too.
 */
const command = npxRegistrationCommand(process.platform);

beforeEach(clearClientLocationEnvironment);
afterEach(() => vi.unstubAllEnvs());

const dshClient = (
  env: Parameters<typeof supportedClients>[2],
  platform: NodeJS.Platform = "linux",
) =>
  supportedClients(join("/home/a"), platform, env).find(
    ({ name }) => name === "dsh",
  );

describe("DeepSeek Harness configuration paths", () => {
  it("resolves the home Cordis patch under the Harness home", () => {
    expect(dshClient({})).toEqual({
      name: "dsh",
      displayName: "DeepSeek Harness",
      configPath: join("/home/a", ".dsh", "cordis.patch.yml"),
      markerPath: join("/home/a", ".dsh"),
      format: "dsh",
    });
    // The home patch applies to every profile; DSH_HOME relocates it.
    expect(dshClient({ DSH_HOME: "/custom/harness" })?.configPath).toBe(
      join("/custom/harness", "cordis.patch.yml"),
    );
    expect(
      clientSkillDirectories(join("/home/a"), ["dsh"], {
        DSH_AGENTS_HOME: "/custom/agents",
      }),
    ).toEqual([{ client: "dsh", directory: join("/custom/agents", "skills") }]);
  });
});

describe("DeepSeek Harness Cordis patch registration", () => {
  const harnessClient = async () => {
    const home = await createTestTempDirectory("rea-dsh-");
    const client = supportedClients(home, process.platform, {}).find(
      ({ name }) => name === "dsh",
    );
    if (client?.markerPath === undefined)
      throw new Error("missing DeepSeek Harness client");
    await mkdir(client.markerPath, { recursive: true });
    return { home, client };
  };

  it("appends the rea-mcp insert, preserves user patches, and reads back", async () => {
    const { home, client } = await harnessClient();
    await writeFile(
      client.configPath,
      `# Harness home patch
- insert:
    - id: user-tool
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: other
        transport: stdio
        command: other-server
`,
    );

    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const text = await readFile(client.configPath, "utf8");
    expect(text).toContain("# Harness home patch");
    expect(parseYaml(text)).toEqual([
      {
        insert: [
          {
            id: "user-tool",
            name: "@deepseek-ai/dsh-mcp-client",
            config: {
              serverName: "other",
              transport: "stdio",
              command: "other-server",
            },
          },
        ],
      },
      {
        insert: [
          {
            id: "rea-mcp",
            name: "@deepseek-ai/dsh-mcp-client",
            config: {
              serverName: "rea",
              transport: "stdio",
              command: command[0],
              args: command.slice(1),
            },
          },
        ],
      },
    ]);

    expect(await configureClientConfiguration(client, {}, command)).toEqual({
      status: "unchanged",
    });
    expect(
      (
        await readClientRegistrationStatuses(home, undefined, {
          platform: process.platform,
          environment: {},
        })
      ).find(({ client: name }) => name === "dsh"),
    ).toMatchObject({ state: "aligned", command });

    expect((await systemUninstallHost(home).removeClient(client)).status).toBe(
      "removed",
    );
    expect(parseYaml(await readFile(client.configPath, "utf8"))).toEqual([
      {
        insert: [
          {
            id: "user-tool",
            name: "@deepseek-ai/dsh-mcp-client",
            config: {
              serverName: "other",
              transport: "stdio",
              command: "other-server",
            },
          },
        ],
      },
    ]);
  });

  it("replaces an existing rea-mcp entry without duplicating it", async () => {
    const { client } = await harnessClient();
    await writeFile(
      client.configPath,
      `- insert:
    - id: rea-mcp
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: rea
        transport: stdio
        command: stale-launcher
        args: [mcp]
`,
    );

    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const patches = parseYaml(
      await readFile(client.configPath, "utf8"),
    ) as unknown[];
    expect(patches).toHaveLength(1);
    expect((patches[0] as { insert: unknown[] }).insert).toHaveLength(1);
    expect(textOf(await readFile(client.configPath, "utf8"))).not.toContain(
      "stale-launcher",
    );
  });

  it("creates the patch list for an absent file and empties it on uninstall", async () => {
    const { home, client } = await harnessClient();
    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const created = parseYaml(
      await readFile(client.configPath, "utf8"),
    ) as unknown[];
    expect(created).toEqual([
      {
        insert: [
          {
            id: "rea-mcp",
            name: "@deepseek-ai/dsh-mcp-client",
            config: {
              serverName: "rea",
              transport: "stdio",
              command: command[0],
              args: command.slice(1),
            },
          },
        ],
      },
    ]);
    expect((await systemUninstallHost(home).removeClient(client)).status).toBe(
      "removed",
    );
    expect(await readFile(client.configPath, "utf8")).toBe("[]\n");
  });
});

const textOf = (value: unknown): string => String(value);

import { rm } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";
import {
  createIdaTarget,
  RecordingIdaMcp,
} from "../../tests/fixtures/idaMcp.js";
import {
  callGraphSession as session,
  edge,
  graphRow,
  removeCallGraphSessions,
} from "../../tests/fixtures/idaCallGraph.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { IDA_LIMITATIONS } from "./IdaProviderCapabilities.js";
import { IdaSessionClient } from "./IdaSessionClient.js";

const attachedRoots: string[] = [];
afterEach(async () => {
  await removeCallGraphSessions();
  for (const root of attachedRoots.splice(0))
    await rm(root, { recursive: true, force: true });
});

const observedTools = (rawResult: unknown): string[] =>
  z
    .object({ observations: z.array(z.object({ tool: z.string() })) })
    .parse(rawResult)
    .observations.map(({ tool }) => tool);

const EMPTY_CALLEES_LIMITATION =
  "Upstream callees reported no calls for this procedure on a target that is not proven x86-only; REA adds edges from the upstream call graph when it is available, and that graph reports calls to recognized functions only, so other call targets remain unknown.";

const callees = async (client: IdaSessionClient) => {
  const result = await client.execute("procedure_callees", {
    procedure: "main",
  });
  if (!result.ok) throw result.error;
  return result.value;
};

describe("headless IDA callee edges on non-x86 targets", () => {
  it("reads callee edges from the upstream call graph when callees reports none", async () => {
    const { client } = await session({
      callees: [],
      callgraph: graphRow([
        edge("0x1000", "0x2000"),
        edge("0x1000", "0x3000"),
        edge("0x2000", "0x4000"),
      ]),
    });
    try {
      const execution = await callees(client);

      expect(
        execution.result,
        "the two root edges are observed and the child edge is ignored",
      ).toEqual(["0x2000", "0x3000"]);
      expect(
        execution.limitations,
        "an empty callees reply is not proof of absence",
      ).toContain(EMPTY_CALLEES_LIMITATION);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("never reports an unobservable leaf as an observed empty list", async () => {
    const { client } = await session({
      callees: [],
      callgraph: graphRow([]),
    });
    try {
      const execution = await callees(client);

      expect(execution.result, "nothing was observed").toEqual([]);
      expect(
        execution.limitations,
        "the empty result carries the completeness limitation",
      ).toContain(EMPTY_CALLEES_LIMITATION);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("merges a fixed upstream's callees with the graph without duplicates or a warning", async () => {
    const { client } = await session({
      callees: [
        { addr: "0x3000", name: "printf_stub", type: "internal" },
        { addr: "0x2000", name: "square", type: "internal" },
      ],
      callgraph: graphRow([
        edge("0x1000", "0x2000"),
        edge("0x1000", "0x3000"),
        edge("0x1000", "0x2000"),
      ]),
    });
    try {
      const execution = await callees(client);

      expect(
        execution.result,
        "callees order is kept and the duplicate graph edges add nothing",
      ).toEqual(["0x3000", "0x2000"]);
      expect(
        execution.limitations,
        "a populated callees reply needs no completeness warning",
      ).not.toContain(EMPTY_CALLEES_LIMITATION);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("appends graph-only callees after the callees items, sorted by address", async () => {
    const { client } = await session({
      callees: [{ addr: "0x3000", name: "printf_stub", type: "internal" }],
      callgraph: graphRow([edge("0x1000", "0x4000"), edge("0x1000", "0x2000")]),
    });
    try {
      const execution = await callees(client);

      expect(
        execution.result,
        "existing items first, then the additions in address order",
      ).toEqual(["0x3000", "0x2000", "0x4000"]);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });
});

describe("headless IDA call graph degradation", () => {
  it.each([
    [
      "a failing call graph tool",
      { callgraphFailure: "unknown tool callgraph" },
    ],
    ["a transport-truncated reply", { callgraphTruncatedOutput: true }],
    [
      "an error row",
      {
        callgraph: [
          { root: "0x1000", error: "Function not found", nodes: [], edges: [] },
        ] as JsonValue,
      },
    ],
    ["an unreadable reply", { callgraph: { unexpected: true } as JsonValue }],
    [
      "a reply for another root",
      {
        callgraph: [{ root: "0x2000", nodes: [], edges: [] }] as JsonValue,
      },
    ],
  ])(
    "fails the callee read instead of reporting a partial list for %s",
    async (_label, graph) => {
      const { client } = await session({
        callees: [{ addr: "0x3000", name: "printf_stub", type: "internal" }],
        ...graph,
      });
      try {
        const result = await client.execute("procedure_callees", {
          procedure: "main",
        });

        if (result.ok) throw new Error("expected a producer fault");
        expect(
          result.error._tag,
          "a callgraph the producer could not give consistently is a producer fault",
        ).toBe("AnalysisProtocolError");
      } finally {
        expect((await client.close()).ok).toBe(true);
      }
    },
  );

  it.each([
    [
      "a truncated graph",
      { truncated: true, limit_reason: "edges" },
      "Upstream callgraph was truncated; additional callees remain unknown.",
    ],
    [
      "a saturated per-function cap",
      { max_edges_per_func: 2 },
      "Upstream callgraph may be truncated; additional callees may remain unknown.",
    ],
  ])(
    "keeps the edges seen and reports %s",
    async (_label, extra, limitation) => {
      const { client } = await session({
        callees: [],
        callgraph: graphRow(
          [edge("0x1000", "0x2000"), edge("0x1000", "0x3000")],
          extra,
        ),
      });
      try {
        const execution = await callees(client);

        expect(execution.result, "the observed edges are kept").toEqual([
          "0x2000",
          "0x3000",
        ]);
        expect(
          execution.limitations,
          "omitted callees are reported as unknown",
        ).toContain(limitation);
      } finally {
        expect((await client.close()).ok).toBe(true);
      }
    },
  );
});

describe("headless IDA call graph availability and cancellation", () => {
  it("takes the call graph path for a universal target whose loaded slice is unknown", async () => {
    const { client, producer } = await session(
      { callees: [], callgraph: graphRow([edge("0x1000", "0x2000")]) },
      "x86_64",
      ["x86_64", "arm64"],
    );
    try {
      const execution = await callees(client);

      expect(execution.result, "the graph edge is observed").toEqual([
        "0x2000",
      ]);
      expect(
        producer.calls.some(({ name }) => name === "callgraph"),
        "a mixed universal target cannot prove an x86 slice",
      ).toBe(true);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("stops at once when the caller cancels during the call graph request", async () => {
    const controller = new AbortController();
    const { client, producer } = await session({
      callees: [],
      callgraph: graphRow([edge("0x1000", "0x2000")]),
    });
    const inner = producer.beforeCall;
    producer.beforeCall = async (name, args) => {
      await inner?.(name, args);
      if (name === "callgraph") controller.abort();
    };
    try {
      const result = await client.execute(
        "procedure_callees",
        { procedure: "main" },
        { signal: controller.signal },
      );

      if (result.ok) throw new Error("expected cancellation");
      expect(result.error._tag, "cancellation is not swallowed").toBe(
        "AnalysisCancelledError",
      );
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("reports a server that does not advertise callgraph without requesting it", async () => {
    const { client, producer } = await session({
      tools: [
        "idb_open",
        "idb_list",
        "idb_close",
        "server_health",
        "list_funcs",
        "lookup_funcs",
        "find_regex",
        "decompile",
        "disasm",
        "callees",
        "xrefs_to",
      ],
      callees: [],
    });
    try {
      const execution = await callees(client);

      expect(execution.result, "nothing is observed").toEqual([]);
      expect(
        execution.limitations,
        "the missing tool is a limitation, not a failure",
      ).toContain(
        "Upstream callgraph was unavailable (the upstream server does not advertise it); callees may be incomplete.",
      );
      expect(
        producer.calls.some(({ name }) => name === "callgraph"),
        "an unadvertised tool is never requested",
      ).toBe(false);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("lets a transport failure of the call graph request fail the read", async () => {
    const { client, producer } = await session({
      callees: [],
      callgraph: graphRow([]),
    });
    producer.beforeCall = async (name) => {
      if (name === "callgraph") throw new Error("transport timed out");
    };
    try {
      const result = await client.execute("procedure_callees", {
        procedure: "main",
      });

      expect(result.ok, "a transport failure is not an observation").toBe(
        false,
      );
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });
});

describe("headless IDA callee edges on x86 targets", () => {
  it("keeps the requests, result, limitations and observations of an x86 read unchanged", async () => {
    const { client, producer } = await session(
      {
        callees: [
          { addr: "0x2000", name: "imported_puts", type: "external" },
          { addr: "0x3000", name: "printf_stub", type: "internal" },
        ],
      },
      "x86_64",
    );
    try {
      const execution = await callees(client);

      expect(
        execution.result,
        "externals come first, then resolved internals, exactly as before",
      ).toEqual(["0x2000", "0x3000"]);
      expect(
        execution.limitations,
        "exactly the provider's own limitations, nothing added on x86",
      ).toEqual([...IDA_LIMITATIONS]);
      expect(
        producer.calls.map(({ name }) => name),
        "no call graph request is made on an x86-only target",
      ).toEqual([
        "idb_open",
        "idb_list",
        "server_health",
        "lookup_funcs",
        "callees",
        "lookup_funcs",
        "server_health",
      ]);
      expect(
        producer.calls.find(({ name }) => name === "callees")?.args,
        "the callees request is the unchanged scoped one",
      ).toMatchObject({ addrs: ["0x1000"], limit: 500 });
      expect(
        observedTools(execution.rawResult),
        "the raw observations hold no call graph row",
      ).toEqual(["lookup_funcs", "callees", "lookup_funcs"]);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("keeps an empty x86 callees reply an observed empty list without any limitation", async () => {
    const { client, producer } = await session({ callees: [] }, "x86_64");
    try {
      const execution = await callees(client);

      expect(execution.result, "nothing is added").toEqual([]);
      expect(
        execution.limitations,
        "no completeness warning on a trustworthy x86 target",
      ).toEqual([...IDA_LIMITATIONS]);
      expect(
        producer.calls.some(({ name }) => name === "callgraph"),
        "no call graph request even for an empty reply",
      ).toBe(false);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });

  it("does not use the call graph for the legacy attached profile on an ARM target", async () => {
    const { root, target } = await createIdaTarget("arm64");
    attachedRoots.push(root);
    const producer = new RecordingIdaMcp(target, "attached");
    const client = new IdaSessionClient(
      {
        command: "fixture",
        args: [],
        env: {},
        mode: "attached",
        timeoutMs: 1000,
        workspaceRoot: root,
      },
      target,
      producer,
    );
    try {
      const result = await client.execute("procedure_callees", {
        procedure: "main",
      });

      expect(result.ok, "the legacy read still works").toBe(true);
      expect(
        producer.calls.some(({ name }) => name === "callgraph"),
        "the legacy profile has no call graph source",
      ).toBe(false);
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });
});

describe("graph-derived callee identities", () => {
  it("names a graph-only callee from the graph node without an extra lookup", async () => {
    const { client, producer } = await session({
      callees: [],
      callgraph: graphRow([edge("0x1000", "0x2000")], {}, "graph_name"),
    });
    try {
      const result = await client.execute("analyze_function", {
        procedure: "main",
      });

      if (!result.ok) throw result.error;
      expect(
        z
          .object({
            callees: z.array(
              z.object({ address: z.string(), name: z.string() }),
            ),
          })
          .parse(result.value.result).callees,
        "the dossier carries the graph node's name",
      ).toEqual([
        expect.objectContaining({ address: "0x2000", name: "graph_name" }),
      ]);
      expect(
        producer.calls
          .filter(({ name }) => name === "lookup_funcs")
          .map(({ args }) => JSON.stringify(args.queries)),
        "no lookup is made for the graph-derived callee",
      ).not.toContain(JSON.stringify(["0x2000"]));
    } finally {
      expect((await client.close()).ok).toBe(true);
    }
  });
});

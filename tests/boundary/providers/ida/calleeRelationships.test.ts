import { afterEach, expect, it } from "vitest";
import { z } from "zod";
import { EnhancedTools } from "../../../../src/application/EnhancedTools.js";
import {
  callGraphSession,
  edge,
  graphRow,
  removeCallGraphSessions,
} from "../../../fixtures/idaCallGraph.js";

afterEach(removeCallGraphSessions);

const requestedRoots = (producer: {
  calls: { name: string; args: unknown }[];
}) =>
  producer.calls
    .filter(({ name }) => name === "callgraph")
    .map(
      ({ args }) =>
        z.object({ roots: z.array(z.string()) }).parse(args).roots[0],
    )
    .sort();

const armSession = () =>
  callGraphSession({
    callees: [],
    callgraph: graphRow([edge("0x1000", "0x2000"), edge("0x1000", "0x3000")]),
    leafRoots: ["0x2000", "0x3000"],
  });

it("shows the callee edges of an ARM64 procedure in the call graph", async () => {
  const { client, producer } = await armSession();
  try {
    const result = await new EnhancedTools(client).execute("get_call_graph", {
      address: "main",
    });

    if (!result.ok) throw result.error;
    expect(
      result.value,
      "the root lists both observed callees instead of an empty observed list",
    ).toEqual({
      "0": [{ address: "0x1000", status: "ok", calls: ["0x2000", "0x3000"] }],
      "1": [
        { address: "0x2000", status: "ok", calls: [] },
        { address: "0x3000", status: "ok", calls: [] },
      ],
    });
    expect(
      requestedRoots(producer),
      "each reachable procedure is read once, with exactly its own root",
    ).toEqual(["0x1000", "0x2000", "0x3000"]);
  } finally {
    expect((await client.close()).ok).toBe(true);
  }
});

it("reaches an ARM64 callee in a call path", async () => {
  const { client } = await armSession();
  try {
    const result = await new EnhancedTools(client).execute("trace_call_path", {
      start: "main",
      goal: "0x3000",
    });

    if (!result.ok) throw result.error;
    expect(
      result.value,
      "the goal is reached through the observed edge",
    ).toMatchObject({
      goal_status: "reached",
      traversal_path: ["0x1000", "0x3000"],
    });
  } finally {
    expect((await client.close()).ok).toBe(true);
  }
});

it("traverses every ARM64 callee in a call path without a goal and records no failure", async () => {
  const { client, producer } = await armSession();
  try {
    const result = await new EnhancedTools(client).execute("trace_call_path", {
      start: "main",
    });

    if (!result.ok) throw result.error;
    expect(
      result.value,
      "the whole reachable graph is visited with exactly the observed edges and no failure",
    ).toMatchObject({
      goal_status: "not_requested",
      nodes: [
        { address: "0x1000", depth: 0 },
        { address: "0x2000", depth: 1 },
        { address: "0x3000", depth: 1 },
      ],
      edges: [
        { source_address: "0x1000", target_address: "0x2000" },
        { source_address: "0x1000", target_address: "0x3000" },
      ],
      failures: [],
      truncated: false,
    });
    expect(
      requestedRoots(producer),
      "each reachable procedure is read once, with exactly its own root",
    ).toEqual(["0x1000", "0x2000", "0x3000"]);
  } finally {
    expect((await client.close()).ok).toBe(true);
  }
});

it("records a failed ARM64 call graph read as the node's error, not as a complete node", async () => {
  const { client } = await callGraphSession({
    callees: [],
    callgraphTruncatedOutput: true,
  });
  try {
    const result = await new EnhancedTools(client).execute("get_call_graph", {
      address: "main",
    });

    if (!result.ok) throw result.error;
    expect(
      result.value,
      "the transport-truncated graph is a recorded failure and no callee list is invented",
    ).toEqual({
      "0": [
        {
          address: "0x1000",
          status: "error",
          error: expect.objectContaining({ code: "unreadable_output" }),
        },
      ],
    });
  } finally {
    expect((await client.close()).ok).toBe(true);
  }
});

import { describe, expect, test } from "bun:test";
import { parseMemoryGraph } from "../../../src/domain/schemas/brain";

const node = {
  id: "mem-graph-total-contract",
  nodeType: "technique",
  title: "Evidence-led enumeration",
  summary: "Confirm services before selecting a procedure.",
  scope: { kind: "global" },
  sensitivity: "internal",
  confidence: 0.92,
  lifecycleStatus: "verified",
  confirmationState: "not_required",
  version: 1,
  pinned: false,
  createdAt: "2026-07-17T00:00:00.000Z",
  updatedAt: "2026-07-17T00:00:00.000Z",
  edgeCount: 0,
  sourceCount: 1,
};

describe("Second Brain graph total schema", () => {
  test("keeps loaded, available, and truncation metadata internally consistent", () => {
    expect(parseMemoryGraph({
      schemaVersion: "2.4",
      view: "global",
      nodes: [node],
      edges: [],
      availableNodeCount: 2,
      truncated: true,
    })).toMatchObject({ availableNodeCount: 2, truncated: true });

    expect(() => parseMemoryGraph({
      schemaVersion: "2.4",
      view: "global",
      nodes: [node],
      edges: [],
      availableNodeCount: 0,
      truncated: false,
    })).toThrow("cannot be smaller");

    expect(() => parseMemoryGraph({
      schemaVersion: "2.4",
      view: "global",
      nodes: [node],
      edges: [],
      availableNodeCount: 2,
      truncated: false,
    })).toThrow("truncation");
  });
});

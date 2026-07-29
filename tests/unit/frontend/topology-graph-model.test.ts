import { describe, expect, test } from "bun:test";
import type {
  TopologyEdge,
  TopologyNode,
} from "../../../src/domain/types/runIntelligence";
import {
  buildTopologyGraphModel,
  hitTestTopologyGraph,
  topologyGraphFitBounds,
  topologyNodeMatchesFilters,
} from "../../../src/features/run-intelligence/topologyGraphModel";

const NOW = "2099-07-20T00:00:00.000Z";

function node(id: string, overrides: Partial<TopologyNode> = {}): TopologyNode {
  return {
    id,
    missionId: "mission-topology",
    runId: "run-topology",
    nodeType: "asset",
    primaryLabel: id,
    normalizedIdentity: id.toLocaleLowerCase(),
    scopeStatus: "allowed",
    lifecycleState: "observed",
    properties: {},
    provenance: { method: "fixture", sourceRef: `source-${id}`, sourceTool: "fixture-parser" },
    confidence: 0.9,
    verificationState: "verified",
    sensitivity: "internal",
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    evidence: [],
    ...overrides,
  };
}

function edge(
  id: string,
  sourceNodeId: string,
  targetNodeId: string,
): TopologyEdge {
  return {
    id,
    missionId: "mission-topology",
    sourceNodeId,
    targetNodeId,
    edgeType: "exposes",
    properties: {},
    provenance: { method: "fixture", sourceRef: `source-${id}`, sourceTool: "fixture-parser" },
    confidence: 0.9,
    verificationState: "verified",
    sensitivity: "internal",
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    evidence: [],
  };
}

describe("topology graph model", () => {
  test("builds truthful linear adjacency and identifies canonical unconnected nodes", () => {
    const graphNodes = [node("asset-b"), node("service-a", { nodeType: "service" }), node("isolated")];
    const model = buildTopologyGraphModel({
      nodes: graphNodes,
      edges: [edge("edge-exposes", "asset-b", "service-a")],
    }, {}, { width: 800, height: 500 });

    expect(model.nodes.map(({ id }) => id)).toEqual(["asset-b", "isolated", "service-a"]);
    expect(model.edges.map(({ id }) => id)).toEqual(["edge-exposes"]);
    expect(model.adjacency.get("asset-b")).toEqual({
      incomingEdgeIds: [],
      outgoingEdgeIds: ["edge-exposes"],
      neighborNodeIds: ["service-a"],
    });
    expect(model.adjacency.get("service-a")).toEqual({
      incomingEdgeIds: ["edge-exposes"],
      outgoingEdgeIds: [],
      neighborNodeIds: ["asset-b"],
    });
    expect(model.unconnectedNodeIds).toEqual(["isolated"]);
    expect(model.edges).toHaveLength(1);
    const assetPoint = model.pointByNodeId.get("asset-b");
    const servicePoint = model.pointByNodeId.get("service-a");
    const isolatedPoint = model.pointByNodeId.get("isolated");
    expect(assetPoint).toBeDefined();
    expect(servicePoint).toBeDefined();
    expect(isolatedPoint).toBeDefined();
    expect(isolatedPoint!.y).toBeGreaterThan(assetPoint!.y);
    expect(isolatedPoint!.y).toBeGreaterThan(servicePoint!.y);
  });

  test("filters nodes and relationships by every supported canonical field", () => {
    const asset = node("asset-one", {
      primaryLabel: "Customer portal",
      normalizedIdentity: "portal.internal",
      lifecycleState: "active",
      verificationState: "corroborated",
    });
    const service = node("service-one", {
      nodeType: "service",
      primaryLabel: "HTTPS",
      lifecycleState: "validated",
      scopeStatus: "prohibited",
      verificationState: "conflicting",
    });
    const model = buildTopologyGraphModel({
      nodes: [asset, service],
      edges: [edge("edge-one", asset.id, service.id)],
    }, {
      search: "PORTAL.INTERNAL",
      nodeTypes: ["asset"],
      lifecycleStates: ["active"],
      scopeStatuses: ["allowed"],
      verificationStates: ["corroborated"],
    }, { width: 600, height: 400 });

    expect(topologyNodeMatchesFilters(asset, {
      search: "customer portal",
      nodeTypes: ["asset"],
      lifecycleStates: ["active"],
      scopeStatuses: ["allowed"],
      verificationStates: ["corroborated"],
    })).toBe(true);
    expect(model.nodes.map(({ id }) => id)).toEqual(["asset-one"]);
    expect(model.edges).toEqual([]);
    expect(model.unconnectedNodeIds).toEqual([]);
  });

  test("ignores and diagnoses edges whose canonical endpoints are absent", () => {
    const model = buildTopologyGraphModel({
      nodes: [node("present")],
      edges: [
        edge("missing-source", "absent-source", "present"),
        edge("missing-target", "present", "absent-target"),
        edge("missing-both", "absent-a", "absent-b"),
      ],
    }, {}, { width: 400, height: 300 });

    expect(model.edges).toEqual([]);
    expect(model.ignoredEdges.map(({ edge: item, reason }) => [item.id, reason])).toEqual([
      ["missing-source", "missing_source"],
      ["missing-target", "missing_target"],
      ["missing-both", "missing_both"],
    ]);
    expect(model.unconnectedNodeIds).toEqual(["present"]);
  });

  test("produces the same layout for equivalent canonical input orderings", () => {
    const nodes = [
      node("node-c", { primaryLabel: "Gamma" }),
      node("node-a", { primaryLabel: "Alpha" }),
      node("node-b", { primaryLabel: "Beta", nodeType: "service" }),
    ];
    const first = buildTopologyGraphModel(
      { nodes, edges: [edge("edge-a", "node-a", "node-b")] },
      {},
      { width: 900, height: 600, padding: 30, nodeRadius: 10 },
    );
    const second = buildTopologyGraphModel(
      { nodes: [...nodes].reverse(), edges: [edge("edge-a", "node-a", "node-b")] },
      {},
      { width: 900, height: 600, padding: 30, nodeRadius: 10 },
    );

    expect(second.nodes.map(({ id }) => id)).toEqual(first.nodes.map(({ id }) => id));
    expect(second.points).toEqual(first.points);
    expect(first.points.every((point) => Number.isFinite(point.x) && Number.isFinite(point.y))).toBe(true);
  });

  test("exposes fit bounds and deterministic nearest-node hit testing", () => {
    const model = buildTopologyGraphModel({
      nodes: [node("node-a"), node("node-b")],
      edges: [],
    }, {}, { width: 500, height: 300, padding: 40, nodeRadius: 12 });
    const first = model.pointByNodeId.get("node-a");
    expect(first).toBeDefined();
    expect(model.fitBounds).toEqual(topologyGraphFitBounds(model.points));
    expect(model.fitBounds?.width).toBeGreaterThan(0);
    expect(hitTestTopologyGraph(model, first!.x, first!.y)?.id).toBe("node-a");
    expect(hitTestTopologyGraph(model, first!.x + 15, first!.y, 3)?.id).toBe("node-a");
    expect(hitTestTopologyGraph(model, -1_000, -1_000)).toBeUndefined();
    expect(hitTestTopologyGraph(model, Number.NaN, first!.y)).toBeUndefined();
    expect(topologyGraphFitBounds([])).toBeNull();
  });
});

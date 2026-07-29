import { describe, expect, test } from "bun:test";
import type { MemoryEdgeSummary, MemoryNodeSummary, MemoryNodeType } from "../../../src/domain/types/brain";
import {
  BRAIN_CLUSTER_ANCHORS,
  BRAIN_PROVENANCE_BANDS,
  brainAnatomyRegion,
  buildAmbientNeuronSignalRoutes,
  buildNeuronSignalRoutes,
  compactGraphLayout,
  constrainGraphPointToBrainRegion,
  graphSignalKind,
  graphMotionMode,
  graphPointIsInsideBrainRegion,
  GRAPH_EDGE_VISIBILITY,
  graphZoomPercent,
  layoutGraph,
  nodeCluster,
  placeBalancedGraphLabels,
  projectGraphPoint,
  relaxGraphLayout,
  unprojectGraphCoordinates,
} from "../../../src/features/brain/graphUtils";

function node(id: string, nodeType: MemoryNodeType): MemoryNodeSummary {
  return {
    id,
    nodeType,
    title: id,
    summary: `${nodeType} fixture`,
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 1,
    lifecycleStatus: "verified",
    confirmationState: "not_required",
    version: 1,
    pinned: false,
    createdAt: "2099-07-20T00:00:00.000Z",
    updatedAt: "2099-07-20T00:00:00.000Z",
    edgeCount: 1,
    sourceCount: 1,
  };
}

function edge(
  id: string,
  sourceNodeId: string,
  targetNodeId: string,
  edgeType: MemoryEdgeSummary["edgeType"],
): MemoryEdgeSummary {
  return {
    id,
    sourceNodeId,
    targetNodeId,
    edgeType,
    title: edgeType,
    summary: `${edgeType} fixture`,
    confidence: 1,
    lifecycleStatus: "verified",
    explanation: "Canonical fixture relationship.",
  };
}

describe("memory graph viewport status", () => {
  test("reports the bounded zoom percentage used by the canvas controls", () => {
    expect(graphZoomPercent(1)).toBe(100);
    expect(graphZoomPercent(1.2)).toBe(120);
    expect(graphZoomPercent(1 / 1.2)).toBe(83);
    expect(graphZoomPercent(0.01)).toBe(45);
    expect(graphZoomPercent(8)).toBe(280);
  });

  test("falls back safely when a non-finite camera value reaches the status projection", () => {
    expect(graphZoomPercent(Number.NaN)).toBe(100);
    expect(graphZoomPercent(Number.POSITIVE_INFINITY)).toBe(100);
  });

  test("maps accessibility and page visibility to deterministic motion modes", () => {
    expect(graphMotionMode(false, true)).toBe("orbital");
    expect(graphMotionMode(true, true)).toBe("reduced");
    expect(graphMotionMode(false, false)).toBe("paused-hidden");
    expect(graphMotionMode(true, false)).toBe("paused-hidden");
  });

  test("prevents balanced label collisions while selected and hovered labels deterministically win", () => {
    const candidates = [
      { id: "balanced-z", x: 100, y: 100, radius: 10, width: 72, height: 12, offset: 7, priority: "balanced" as const },
      { id: "hovered", x: 100, y: 100, radius: 10, width: 72, height: 12, offset: 7, priority: "hovered" as const },
      { id: "balanced-a", x: 100, y: 100, radius: 10, width: 72, height: 12, offset: 7, priority: "balanced" as const },
      { id: "selected", x: 100, y: 100, radius: 10, width: 72, height: 12, offset: 7, priority: "selected" as const },
      { id: "independent", x: 260, y: 100, radius: 10, width: 72, height: 12, offset: 7, priority: "balanced" as const },
    ];
    const first = placeBalancedGraphLabels(candidates, 3);
    const second = placeBalancedGraphLabels([...candidates].reverse(), 3);
    expect(second).toEqual(first);
    expect(first.map((placement) => placement.id)).toEqual(["independent", "hovered", "selected"]);
    expect(first.find((placement) => placement.id === "selected")).toMatchObject({ labelX: 100, labelY: 117 });
    expect(first.find((placement) => placement.id === "hovered")?.labelY).not.toBe(117);
    expect(first.some((placement) => placement.id.startsWith("balanced-"))).toBe(false);
    expect(placeBalancedGraphLabels([candidates[4]!], 3, [
      { id: "independent", x: 260, y: 100, radius: 12 },
      { id: "neighbor", x: 260, y: 124, radius: 8 },
    ])).toEqual([]);
  });

  test("organizes reusable technologies and attacks in the hemispheres while relegating mission provenance to the spinal trace", () => {
    expect(nodeCluster(node("apache-2.4.49", "technology_product"))).toBe("other");
    expect(nodeCluster(node("linux-kernel", "kernel"))).toBe("other");
    expect(nodeCluster(node("cve-2021-41773", "cve"))).toBe("attack");
    expect(nodeCluster(node("path-traversal", "attack_vector"))).toBe("attack");
    expect(nodeCluster(node("exploit.py", "script_artifact"))).toBe("tool");
    expect(nodeCluster(node("failed-precondition", "failure_mode"))).toBe("failure");
    expect(nodeCluster(node("source-run", "run"))).toBe("mission");
    expect(BRAIN_CLUSTER_ANCHORS.mission.y).toBeGreaterThan(BRAIN_CLUSTER_ANCHORS.failure.y);
    expect(BRAIN_CLUSTER_ANCHORS.operator.y).toBeGreaterThan(BRAIN_CLUSTER_ANCHORS.mission.y);
    expect(BRAIN_PROVENANCE_BANDS.mission.maxY).toBeLessThan(BRAIN_PROVENANCE_BANDS.agent.minY);
    expect(BRAIN_PROVENANCE_BANDS.agent.maxY).toBeLessThan(BRAIN_PROVENANCE_BANDS.operator.minY);
    expect(BRAIN_CLUSTER_ANCHORS.mission.y).toBeGreaterThanOrEqual(BRAIN_PROVENANCE_BANDS.mission.minY);
    expect(BRAIN_CLUSTER_ANCHORS.mission.y).toBeLessThanOrEqual(BRAIN_PROVENANCE_BANDS.mission.maxY);
    expect(BRAIN_CLUSTER_ANCHORS.agent.y).toBeGreaterThanOrEqual(BRAIN_PROVENANCE_BANDS.agent.minY);
    expect(BRAIN_CLUSTER_ANCHORS.agent.y).toBeLessThanOrEqual(BRAIN_PROVENANCE_BANDS.agent.maxY);
    expect(BRAIN_CLUSTER_ANCHORS.operator.y).toBeGreaterThanOrEqual(BRAIN_PROVENANCE_BANDS.operator.minY);
    expect(BRAIN_CLUSTER_ANCHORS.operator.y).toBeLessThanOrEqual(BRAIN_PROVENANCE_BANDS.operator.maxY);
    expect(BRAIN_CLUSTER_ANCHORS.other.x).toBeLessThan(0.5);
    expect(BRAIN_CLUSTER_ANCHORS.attack.x).toBeGreaterThan(0.5);
    expect(brainAnatomyRegion("other")).toBe("left-hemisphere");
    expect(brainAnatomyRegion("attack")).toBe("right-hemisphere");
    expect(brainAnatomyRegion("lesson")).toBe("corpus-callosum");
    expect(brainAnatomyRegion("mission")).toBe("spinal-trace");
  });

  test("keeps fixed, compact, and relationship-weighted layouts inside their anatomical regions", () => {
    const nodes = Array.from({ length: 24 }, (_, index) => [
      node(`technology-${index}`, "technology_product"),
      node(`attack-${index}`, "attack_vector"),
      node(`evidence-${index}`, "evidence"),
      node(`tool-${index}`, "script_artifact"),
      node(`failure-${index}`, "failure_mode"),
      node(`mission-${index}`, "mission"),
      node(`agent-${index}`, "agent"),
      node(`operator-${index}`, "preference"),
    ]).flat();
    const edges = nodes.slice(1).map((item, index) => edge(`edge-${index}`, nodes[index]!.id, item.id, "supports"));
    const initial = layoutGraph(nodes, 1_000, 700);
    const relaxed = relaxGraphLayout(initial, edges, 1_000, 700, 32);
    const compact = compactGraphLayout(relaxed, 1_000, 700);
    for (const collection of [initial, relaxed, compact]) {
      expect(collection.every((point) => graphPointIsInsideBrainRegion(point, 1_000, 700))).toBe(true);
      expect(collection.filter((point) => point.cluster === "other" || point.cluster === "evidence").every((point) => point.x < 500)).toBe(true);
      expect(collection.filter((point) => point.cluster === "attack" || point.cluster === "tool").every((point) => point.x > 500)).toBe(true);
      expect(collection.filter((point) => point.cluster === "mission").every((point) => Math.abs(point.x - 500) < 140)).toBe(true);
      const missionPoints = collection.filter((point) => point.cluster === "mission");
      const agentPoints = collection.filter((point) => point.cluster === "agent");
      const operatorPoints = collection.filter((point) => point.cluster === "operator");
      expect(Math.max(...missionPoints.map((point) => point.y))).toBeLessThan(Math.min(...agentPoints.map((point) => point.y)));
      expect(Math.max(...agentPoints.map((point) => point.y))).toBeLessThan(Math.min(...operatorPoints.map((point) => point.y)));
      for (const [cluster, points] of [
        ["mission", missionPoints],
        ["agent", agentPoints],
        ["operator", operatorPoints],
      ] as const) {
        const band = BRAIN_PROVENANCE_BANDS[cluster];
        expect(points.every((point) => point.y >= band.minY * 700 && point.y <= band.maxY * 700)).toBe(true);
      }
    }
    const escaped = { ...initial.find((point) => point.cluster === "attack")!, x: 80, y: 680 };
    const bounded = constrainGraphPointToBrainRegion(escaped, 1_000, 700);
    expect(graphPointIsInsideBrainRegion(bounded, 1_000, 700)).toBe(true);
    expect(bounded.x).toBeGreaterThan(500);
  });

  test("keeps canonical default edges visible without allowing them to dominate focused paths", () => {
    expect(GRAPH_EDGE_VISIBILITY.ambient).toBeGreaterThan(GRAPH_EDGE_VISIBILITY.sameRegion);
    expect(GRAPH_EDGE_VISIBILITY.sameRegion).toBeGreaterThan(GRAPH_EDGE_VISIBILITY.crossRegion);
    expect(GRAPH_EDGE_VISIBILITY.crossRegion).toBeGreaterThanOrEqual(0.2);
    expect(GRAPH_EDGE_VISIBILITY.ambient).toBeLessThan(1);
    expect(GRAPH_EDGE_VISIBILITY.selectedDimmed).toBeLessThan(GRAPH_EDGE_VISIBILITY.crossRegion);
  });

  test("keeps orbital parallax invertible so pointer dragging persists canonical coordinates", () => {
    const [point] = layoutGraph([node("apache-2.4.49", "technology_product")], 900, 600);
    expect(point).toBeDefined();
    const projected = projectGraphPoint(point!, 900, 600, Math.PI / 2, true);
    const restored = unprojectGraphCoordinates(point!, projected.x, projected.y, 900, 600, Math.PI / 2, true);
    expect(restored.x).toBeCloseTo(point!.x, 8);
    expect(restored.y).toBeCloseTo(point!.y, 8);
    expect(projectGraphPoint(point!, 900, 600, Math.PI / 2, false)).toMatchObject({
      x: point!.x,
      y: point!.y,
      scale: 1,
    });
  });

  test("makes a full-depth node visibly move during the idle orbit", () => {
    const point = {
      id: "visible-orbit",
      x: 640,
      y: 260,
      radius: 8,
      cluster: "attack" as const,
      depth: 1,
    };
    const first = projectGraphPoint(point, 900, 600, 0, true);
    const quarterTurn = projectGraphPoint(point, 900, 600, Math.PI / 2, true);
    expect(Math.hypot(quarterTurn.x - first.x, quarterTurn.y - first.y)).toBeGreaterThan(8);
    expect(Math.abs(quarterTurn.scale - first.scale)).toBeGreaterThan(0.15);
  });

  test("emits bounded neuron routes only over real edges and distinguishes hazard and recovery without relying on color", () => {
    const nodes = [
      node("vector", "attack_vector"),
      node("script", "script_artifact"),
      node("failure", "failure_mode"),
      node("recovery", "recovery"),
      node("isolated", "technology_product"),
    ];
    const edges = [
      edge("edge-script", "vector", "script", "implemented_by"),
      edge("edge-failure", "vector", "failure", "failed_because"),
      edge("edge-recovery", "failure", "recovery", "recovered_with"),
    ];
    const routes = buildNeuronSignalRoutes(nodes, edges, "vector");
    expect(routes.map((route) => route.edgeId).sort()).toEqual(["edge-failure", "edge-recovery", "edge-script"]);
    expect(routes.some((route) => route.toNodeId === "isolated")).toBe(false);
    expect(routes.find((route) => route.edgeId === "edge-failure")?.kind).toBe("hazard");
    expect(routes.find((route) => route.edgeId === "edge-recovery")?.kind).toBe("recovery");
    expect(routes.find((route) => route.edgeId === "edge-script")?.kind).toBe("knowledge");
    const nodeMap = new Map(nodes.map((item) => [item.id, item]));
    expect(graphSignalKind(edges[1]!, nodeMap)).toBe("hazard");
    expect(graphSignalKind(edges[2]!, nodeMap)).toBe("recovery");
  });

  test("balances ambient cortical pulses across real relationship regions without fabricating routes", () => {
    const nodes = [
      node("technology", "technology_product"),
      node("evidence", "evidence"),
      node("vector", "attack_vector"),
      node("script", "script_artifact"),
      node("failure", "failure_mode"),
      node("mission", "mission"),
      node("isolated", "tool"),
    ];
    const edges = [
      edge("left", "technology", "evidence", "supports"),
      edge("right", "vector", "script", "implemented_by"),
      edge("cross", "technology", "vector", "applies_to"),
      edge("hazard", "vector", "failure", "failed_because"),
      edge("provenance", "mission", "evidence", "produced"),
    ];
    const routes = buildAmbientNeuronSignalRoutes(nodes, edges, 4);
    expect(routes).toHaveLength(4);
    expect(new Set(routes.map((route) => route.edgeId)).size).toBe(routes.length);
    expect(routes.every((route) => edges.some((item) => item.id === route.edgeId))).toBe(true);
    expect(routes.some((route) => [route.fromNodeId, route.toNodeId].includes("isolated"))).toBe(false);
    expect(routes.every((route) => route.durationMs >= 3_600 && route.durationMs < 6_000)).toBe(true);
    expect(buildAmbientNeuronSignalRoutes(nodes, edges, 0)).toEqual([]);
  });
});

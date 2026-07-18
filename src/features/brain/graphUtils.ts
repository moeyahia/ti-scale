import type { MemoryEdgeSummary, MemoryNodeSummary } from "../../domain/types/brain";

export interface GraphPoint {
  id: string;
  x: number;
  y: number;
  radius: number;
  cluster: string;
}

export const GRAPH_CLUSTERS = ["operator", "mission", "attack", "tool", "evidence", "agent", "failure", "lesson", "other"] as const;
export type GraphCluster = (typeof GRAPH_CLUSTERS)[number];
const CLUSTER_ORDER: readonly GraphCluster[] = GRAPH_CLUSTERS;

export function nodeCluster(node: Pick<MemoryNodeSummary, "nodeType">): GraphCluster {
  if (node.nodeType === "operator" || node.nodeType === "preference") return "operator";
  if (["mission", "run", "plan", "phase", "step", "target", "asset", "entity", "decision"].includes(node.nodeType)) return "mission";
  if (["tactic", "technique", "procedure"].includes(node.nodeType)) return "attack";
  if (node.nodeType === "tool" || node.nodeType === "mcp_capability") return "tool";
  if (["evidence", "finding", "artifact", "report", "source"].includes(node.nodeType)) return "evidence";
  if (node.nodeType === "agent") return "agent";
  if (node.nodeType === "failure" || node.nodeType === "recovery") return "failure";
  if (node.nodeType === "lesson" || node.nodeType === "evaluation") return "lesson";
  return "other";
}

const CLUSTER_NODE_TYPES: Record<GraphCluster, MemoryNodeSummary["nodeType"]> = {
  operator: "operator",
  mission: "mission",
  attack: "technique",
  tool: "tool",
  evidence: "evidence",
  agent: "agent",
  failure: "failure",
  lesson: "lesson",
  other: "entity",
};

export interface CollapsedGraphProjection {
  readonly nodes: MemoryNodeSummary[];
  readonly edges: MemoryEdgeSummary[];
}

/** Derives canvas-only aggregate nodes while preserving canonical source data. */
export function collapseGraphClusters(
  nodes: readonly MemoryNodeSummary[],
  edges: readonly MemoryEdgeSummary[],
  collapsed: ReadonlySet<GraphCluster>,
): CollapsedGraphProjection {
  if (collapsed.size === 0) return { nodes: [...nodes], edges: [...edges] };
  const clusterByNode = new Map(nodes.map((node) => [node.id, nodeCluster(node)]));
  const mappedId = (nodeId: string) => {
    const cluster = clusterByNode.get(nodeId);
    return cluster && collapsed.has(cluster) ? `cluster:${cluster}` : nodeId;
  };
  const retained = nodes.filter((node) => !collapsed.has(nodeCluster(node)));
  for (const cluster of collapsed) {
    const members = nodes.filter((node) => nodeCluster(node) === cluster);
    if (members.length === 0) continue;
    const lifecycle = members.some((node) => node.lifecycleStatus === "disputed")
      ? "disputed"
      : members.some((node) => node.lifecycleStatus === "stale")
        ? "stale"
        : members.every((node) => node.lifecycleStatus === "verified")
          ? "verified"
          : "confirmed";
    retained.push({
      id: `cluster:${cluster}`,
      nodeType: CLUSTER_NODE_TYPES[cluster],
      title: `${cluster[0]!.toUpperCase()}${cluster.slice(1)} cluster`,
      summary: `${members.length} canonical memories collapsed for this canvas view`,
      scope: { kind: "global" },
      sensitivity: "private",
      confidence: members.reduce((sum, node) => sum + node.confidence, 0) / members.length,
      lifecycleStatus: lifecycle,
      confirmationState: members.every((node) => node.confirmationState === "confirmed") ? "confirmed" : "not_required",
      version: 1,
      pinned: false,
      createdAt: members.map((node) => node.createdAt).sort()[0]!,
      updatedAt: members.map((node) => node.updatedAt).sort().at(-1)!,
      edgeCount: members.reduce((sum, node) => sum + node.edgeCount, 0),
      sourceCount: members.reduce((sum, node) => sum + node.sourceCount, 0),
    });
  }
  const projected = new Map<string, MemoryEdgeSummary & { count: number }>();
  for (const edge of edges) {
    const sourceNodeId = mappedId(edge.sourceNodeId);
    const targetNodeId = mappedId(edge.targetNodeId);
    if (sourceNodeId === targetNodeId) continue;
    const key = `${sourceNodeId}>${targetNodeId}:${edge.edgeType}`;
    const current = projected.get(key);
    if (current) {
      current.count += 1;
      current.confidence = Math.max(current.confidence, edge.confidence);
      current.summary = `${current.count} canonical ${edge.edgeType.replaceAll("_", " ")} relationships`;
      current.explanation = `${current.count} canonical relationships are represented in this collapsed canvas edge.`;
      continue;
    }
    projected.set(key, {
      ...edge,
      id: `cluster-edge:${key}`,
      sourceNodeId,
      targetNodeId,
      title: edge.edgeType.replaceAll("_", " "),
      summary: `1 canonical ${edge.edgeType.replaceAll("_", " ")} relationship`,
      explanation: "One canonical relationship is represented in this collapsed canvas edge.",
      count: 1,
    });
  }
  return {
    nodes: retained,
    edges: [...projected.values()].map(({ count: _count, ...edge }) => edge),
  };
}

function hash(value: string): number {
  let result = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    result ^= value.charCodeAt(index);
    result = Math.imul(result, 16777619);
  }
  return result >>> 0;
}

export function layoutGraph(nodes: readonly MemoryNodeSummary[], width: number, height: number): GraphPoint[] {
  const safeWidth = Math.max(320, width);
  const safeHeight = Math.max(260, height);
  const counts = new Map<string, number>();
  return nodes.map((node) => {
    const cluster = nodeCluster(node);
    const index = counts.get(cluster) ?? 0;
    counts.set(cluster, index + 1);
    const clusterIndex = Math.max(0, CLUSTER_ORDER.indexOf(cluster));
    const clusterAngle = (clusterIndex / CLUSTER_ORDER.length) * Math.PI * 2 - Math.PI / 2;
    const centerRadius = Math.min(safeWidth, safeHeight) * 0.28;
    const centerX = safeWidth / 2 + Math.cos(clusterAngle) * centerRadius;
    const centerY = safeHeight / 2 + Math.sin(clusterAngle) * centerRadius;
    const seed = hash(node.id);
    const ring = Math.floor(index / 8) + 1;
    const angle = ((seed % 360) / 180) * Math.PI + (index % 8) * (Math.PI / 4);
    const spread = 18 + ring * 23 + (seed % 13);
    return {
      id: node.id,
      x: Math.max(24, Math.min(safeWidth - 24, centerX + Math.cos(angle) * spread)),
      y: Math.max(24, Math.min(safeHeight - 24, centerY + Math.sin(angle) * spread)),
      radius: Math.max(5, Math.min(15, 5 + Math.sqrt(Math.max(0, node.edgeCount)) * 1.8 + (node.pinned ? 2 : 0))),
      cluster,
    };
  });
}

export function compactGraphLayout(points: readonly GraphPoint[], width: number, height: number): GraphPoint[] {
  return points.map((point) => ({
    ...point,
    x: width / 2 + (point.x - width / 2) * 0.7,
    y: height / 2 + (point.y - height / 2) * 0.7,
  }));
}

/**
 * Performs a bounded deterministic spring relaxation. This is a one-shot
 * worker calculation, not an idle animation, so the operator can compare a
 * stable clustered layout with relationship-weighted spacing without burning
 * background CPU. The active graph API is capped at 1,000 nodes.
 */
export function relaxGraphLayout(
  source: readonly GraphPoint[],
  edges: readonly Pick<MemoryEdgeSummary, "sourceNodeId" | "targetNodeId">[],
  width: number,
  height: number,
  iterations = 18,
): GraphPoint[] {
  if (source.length < 2 || iterations < 1) return source.map((point) => ({ ...point }));
  const points = source.map((point) => ({ ...point }));
  const index = new Map(points.map((point, position) => [point.id, position]));
  const velocity = points.map(() => ({ x: 0, y: 0 }));
  const links = edges.flatMap((edge) => {
    const left = index.get(edge.sourceNodeId);
    const right = index.get(edge.targetNodeId);
    return left === undefined || right === undefined || left === right ? [] : [[left, right] as const];
  });
  const safeWidth = Math.max(320, width);
  const safeHeight = Math.max(260, height);
  const boundedIterations = Math.min(32, Math.floor(iterations));
  for (let iteration = 0; iteration < boundedIterations; iteration += 1) {
    for (const [leftIndex, rightIndex] of links) {
      const left = points[leftIndex]!;
      const right = points[rightIndex]!;
      const dx = right.x - left.x;
      const dy = right.y - left.y;
      const distance = Math.max(1, Math.hypot(dx, dy));
      const force = Math.max(-3, Math.min(3, (distance - 74) * 0.018));
      const fx = (dx / distance) * force;
      const fy = (dy / distance) * force;
      velocity[leftIndex]!.x += fx;
      velocity[leftIndex]!.y += fy;
      velocity[rightIndex]!.x -= fx;
      velocity[rightIndex]!.y -= fy;
    }
    // A bounded local repulsion prevents directly adjacent nodes from
    // collapsing. Avoid quadratic work for large progressive segments.
    if (points.length <= 400) {
      for (let leftIndex = 0; leftIndex < points.length; leftIndex += 1) {
        for (let rightIndex = leftIndex + 1; rightIndex < points.length; rightIndex += 1) {
          const left = points[leftIndex]!;
          const right = points[rightIndex]!;
          const dx = right.x - left.x;
          const dy = right.y - left.y;
          const distance = Math.max(1, Math.hypot(dx, dy));
          if (distance >= 42) continue;
          const force = (42 - distance) * 0.024;
          const fx = (dx / distance) * force;
          const fy = (dy / distance) * force;
          velocity[leftIndex]!.x -= fx;
          velocity[leftIndex]!.y -= fy;
          velocity[rightIndex]!.x += fx;
          velocity[rightIndex]!.y += fy;
        }
      }
    }
    points.forEach((point, position) => {
      const movement = velocity[position]!;
      movement.x *= 0.72;
      movement.y *= 0.72;
      point.x = Math.max(24, Math.min(safeWidth - 24, point.x + movement.x));
      point.y = Math.max(24, Math.min(safeHeight - 24, point.y + movement.y));
    });
  }
  return points;
}

export function shortestMemoryPath(
  edges: readonly Pick<MemoryEdgeSummary, "sourceNodeId" | "targetNodeId">[],
  from: string,
  to: string,
): string[] {
  if (from === to) return [from];
  const adjacency = new Map<string, string[]>();
  edges.forEach((edge) => {
    adjacency.set(edge.sourceNodeId, [...(adjacency.get(edge.sourceNodeId) ?? []), edge.targetNodeId]);
    adjacency.set(edge.targetNodeId, [...(adjacency.get(edge.targetNodeId) ?? []), edge.sourceNodeId]);
  });
  const queue = [from];
  const previous = new Map<string, string | null>([[from, null]]);
  while (queue.length) {
    const current = queue.shift()!;
    for (const neighbor of adjacency.get(current) ?? []) {
      if (previous.has(neighbor)) continue;
      previous.set(neighbor, current);
      if (neighbor === to) {
        const path = [to];
        let cursor: string | null = current;
        while (cursor) {
          path.push(cursor);
          cursor = previous.get(cursor) ?? null;
        }
        return path.reverse();
      }
      queue.push(neighbor);
    }
  }
  return [];
}

export function relatedNodeIds(edges: readonly MemoryEdgeSummary[], nodeId?: string): Set<string> {
  if (!nodeId) return new Set();
  const ids = new Set([nodeId]);
  edges.forEach((edge) => {
    if (edge.sourceNodeId === nodeId) ids.add(edge.targetNodeId);
    if (edge.targetNodeId === nodeId) ids.add(edge.sourceNodeId);
  });
  return ids;
}

/** Human-readable zoom state for the canvas controls and their live region. */
export function graphZoomPercent(zoom: number): number {
  if (!Number.isFinite(zoom)) return 100;
  return Math.round(Math.max(0.45, Math.min(2.8, zoom)) * 100);
}

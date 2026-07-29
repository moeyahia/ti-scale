import type { MemoryEdgeSummary, MemoryNodeSummary } from "../../domain/types/brain";

export interface GraphPoint {
  id: string;
  x: number;
  y: number;
  radius: number;
  cluster: GraphCluster;
  /** Stable visual depth used only for bounded orbital parallax. */
  depth: number;
}

export const GRAPH_CLUSTERS = ["operator", "mission", "attack", "tool", "evidence", "agent", "failure", "lesson", "other"] as const;
export type GraphCluster = (typeof GRAPH_CLUSTERS)[number];
const CLUSTER_ORDER: readonly GraphCluster[] = GRAPH_CLUSTERS;

export const GRAPH_CLUSTER_LABELS: Readonly<Record<GraphCluster, string>> = Object.freeze({
  operator: "Operator Preferences / Profile",
  mission: "Source provenance",
  attack: "Attack vectors",
  tool: "Scripts and tools",
  evidence: "Discoveries and proof",
  agent: "Runtime provenance",
  failure: "Outcomes and recovery",
  lesson: "Reusable knowledge",
  other: "Technology stack",
});

/**
 * Default relationship opacity is intentionally restrained: the graph should
 * remain readable as anatomy, while every returned canonical relationship is
 * still visible before the operator focuses a node or path.
 */
export const GRAPH_EDGE_VISIBILITY = Object.freeze({
  ambient: 0.70,
  sameRegion: 0.52,
  crossRegion: 0.22,
  selectedDimmed: 0.07,
});

export type BrainProvenanceCluster = Extract<GraphCluster, "mission" | "agent" | "operator">;

export interface BrainProvenanceBand {
  readonly minY: number;
  readonly maxY: number;
  readonly halfWidth: number;
  readonly maxColumns: number;
}

/**
 * Source, runtime, and operator provenance occupy separate vertebrae below the
 * cortex. The normalized gaps are part of the renderer contract: even a
 * relationship-weighted layout may not collapse these categories into one
 * indistinguishable block.
 */
export const BRAIN_PROVENANCE_BANDS: Readonly<Record<BrainProvenanceCluster, Readonly<BrainProvenanceBand>>> = Object.freeze({
  mission: Object.freeze({ minY: 0.735, maxY: 0.805, halfWidth: 0.13, maxColumns: 12 }),
  agent: Object.freeze({ minY: 0.835, maxY: 0.885, halfWidth: 0.09, maxColumns: 8 }),
  operator: Object.freeze({ minY: 0.915, maxY: 0.955, halfWidth: 0.065, maxColumns: 6 }),
});

/**
 * Bilateral attack-knowledge anatomy. These normalized anchors are display
 * semantics only: canonical memory type, scope, and relationships remain in
 * SQLite. The left hemisphere is technology/discovery, the right hemisphere
 * is vectors/execution, reusable knowledge bridges the cortex, and ephemeral
 * mission/runtime provenance is deliberately relegated to the spinal trace.
 */
export const BRAIN_CLUSTER_ANCHORS: Readonly<Record<GraphCluster, Readonly<{
  x: number;
  y: number;
  spreadX: number;
  spreadY: number;
}>>> = Object.freeze({
  other: Object.freeze({ x: 0.30, y: 0.35, spreadX: 0.16, spreadY: 0.19 }),
  evidence: Object.freeze({ x: 0.28, y: 0.57, spreadX: 0.14, spreadY: 0.14 }),
  attack: Object.freeze({ x: 0.70, y: 0.35, spreadX: 0.16, spreadY: 0.19 }),
  tool: Object.freeze({ x: 0.72, y: 0.57, spreadX: 0.14, spreadY: 0.14 }),
  lesson: Object.freeze({ x: 0.50, y: 0.19, spreadX: 0.12, spreadY: 0.07 }),
  failure: Object.freeze({ x: 0.50, y: 0.65, spreadX: 0.13, spreadY: 0.055 }),
  mission: Object.freeze({ x: 0.50, y: 0.77, spreadX: 0.13, spreadY: 0.035 }),
  agent: Object.freeze({ x: 0.50, y: 0.86, spreadX: 0.09, spreadY: 0.025 }),
  operator: Object.freeze({ x: 0.50, y: 0.935, spreadX: 0.065, spreadY: 0.02 }),
});

export type BrainAnatomyRegion = "left-hemisphere" | "right-hemisphere" | "corpus-callosum" | "spinal-trace";

const BRAIN_REGION_BY_CLUSTER: Readonly<Record<GraphCluster, BrainAnatomyRegion>> = Object.freeze({
  other: "left-hemisphere",
  evidence: "left-hemisphere",
  attack: "right-hemisphere",
  tool: "right-hemisphere",
  lesson: "corpus-callosum",
  failure: "corpus-callosum",
  mission: "spinal-trace",
  agent: "spinal-trace",
  operator: "spinal-trace",
});

interface BrainRegionShape {
  readonly x: number;
  readonly y: number;
  readonly radiusX: number;
  readonly radiusY: number;
}

/**
 * Canvas-only anatomical envelopes. They keep relationship-weighted physics
 * from collapsing the two semantic hemispheres back into a generic force
 * graph. They never alter canonical nodes, relationships, or persisted graph
 * coordinates.
 */
const BRAIN_REGION_SHAPES: Readonly<Record<GraphCluster, BrainRegionShape>> = Object.freeze({
  other: Object.freeze({ x: 0.30, y: 0.42, radiusX: 0.185, radiusY: 0.285 }),
  evidence: Object.freeze({ x: 0.30, y: 0.42, radiusX: 0.185, radiusY: 0.285 }),
  attack: Object.freeze({ x: 0.70, y: 0.42, radiusX: 0.185, radiusY: 0.285 }),
  tool: Object.freeze({ x: 0.70, y: 0.42, radiusX: 0.185, radiusY: 0.285 }),
  lesson: Object.freeze({ x: 0.50, y: 0.19, radiusX: 0.125, radiusY: 0.075 }),
  failure: Object.freeze({ x: 0.50, y: 0.65, radiusX: 0.14, radiusY: 0.065 }),
  mission: Object.freeze({ x: 0.50, y: 0.77, radiusX: 0.13, radiusY: 0.035 }),
  agent: Object.freeze({ x: 0.50, y: 0.86, radiusX: 0.09, radiusY: 0.025 }),
  operator: Object.freeze({ x: 0.50, y: 0.935, radiusX: 0.065, radiusY: 0.02 }),
});

export function brainAnatomyRegion(cluster: GraphCluster): BrainAnatomyRegion {
  return BRAIN_REGION_BY_CLUSTER[cluster];
}

/** Projects a point back to its lobe/bridge/spine envelope when necessary. */
export function constrainGraphPointToBrainRegion(point: GraphPoint, width: number, height: number): GraphPoint {
  const safeWidth = Math.max(320, width);
  const safeHeight = Math.max(260, height);
  const provenanceBand = point.cluster === "mission" || point.cluster === "agent" || point.cluster === "operator"
    ? BRAIN_PROVENANCE_BANDS[point.cluster]
    : undefined;
  if (provenanceBand) {
    // Preserve room for the rendered point and its bounded spinal drift. At a
    // very small viewport the center fallback remains deterministic rather
    // than allowing the minimum and maximum clamps to invert.
    const horizontalInset = point.radius + 5;
    const verticalInset = point.radius + 5;
    const rawMinX = safeWidth * (0.5 - provenanceBand.halfWidth) + horizontalInset;
    const rawMaxX = safeWidth * (0.5 + provenanceBand.halfWidth) - horizontalInset;
    const rawMinY = safeHeight * provenanceBand.minY + verticalInset;
    const rawMaxY = safeHeight * provenanceBand.maxY - verticalInset;
    const centerX = safeWidth * 0.5;
    const centerY = safeHeight * (provenanceBand.minY + provenanceBand.maxY) / 2;
    const minX = rawMinX <= rawMaxX ? rawMinX : centerX;
    const maxX = rawMinX <= rawMaxX ? rawMaxX : centerX;
    const minY = rawMinY <= rawMaxY ? rawMinY : centerY;
    const maxY = rawMinY <= rawMaxY ? rawMaxY : centerY;
    return {
      ...point,
      x: Math.max(minX, Math.min(maxX, point.x)),
      y: Math.max(minY, Math.min(maxY, point.y)),
    };
  }
  const shape = BRAIN_REGION_SHAPES[point.cluster];
  const centerX = shape.x * safeWidth;
  const centerY = shape.y * safeHeight;
  // Reserve enough room for the bounded cortical drift applied at paint time.
  const radiusX = Math.max(12, shape.radiusX * safeWidth - point.radius - 18);
  const radiusY = Math.max(12, shape.radiusY * safeHeight - point.radius - 12);
  const normalizedX = (point.x - centerX) / radiusX;
  const normalizedY = (point.y - centerY) / radiusY;
  const distance = Math.hypot(normalizedX, normalizedY);
  if (distance <= 1) return { ...point };
  const scale = 1 / distance;
  return {
    ...point,
    x: centerX + normalizedX * scale * radiusX,
    y: centerY + normalizedY * scale * radiusY,
  };
}

export function graphPointIsInsideBrainRegion(point: GraphPoint, width: number, height: number): boolean {
  const constrained = constrainGraphPointToBrainRegion(point, width, height);
  return Math.abs(constrained.x - point.x) < 0.001 && Math.abs(constrained.y - point.y) < 0.001;
}

export function nodeCluster(node: Pick<MemoryNodeSummary, "nodeType">): GraphCluster {
  if (node.nodeType === "operator" || node.nodeType === "preference") return "operator";
  if (["mission", "run", "plan", "phase", "step", "target", "asset", "entity", "decision"].includes(node.nodeType)) return "mission";
  if ([
    "tactic", "technique", "procedure", "cve", "advisory", "cwe", "misconfiguration",
    "attack_vector", "attack_tactic", "attack_technique", "attack_procedure",
    "procedure_version", "prerequisite", "attribute",
  ].includes(node.nodeType)) return "attack";
  if (["tool", "mcp_capability", "script_artifact", "tool_artifact"].includes(node.nodeType)) return "tool";
  if ([
    "evidence", "finding", "artifact", "report", "source", "discovery_pattern",
    "fingerprint_pattern", "evidence_pattern", "validation_pattern", "health_check",
  ].includes(node.nodeType)) return "evidence";
  if (node.nodeType === "agent") return "agent";
  if ([
    "failure", "failure_mode", "recovery", "outcome", "alternative", "detection",
    "remediation", "operational_hazard", "target_state_transition", "recovery_pattern",
  ].includes(node.nodeType)) return "failure";
  if (["lesson", "evaluation", "strategy", "research", "attack_lesson"].includes(node.nodeType)) return "lesson";
  if ([
    "technology_product", "exact_version_fingerprint", "version_range_fingerprint",
    "operating_system", "kernel", "framework", "runtime", "database", "firewall",
    "waf", "proxy", "security_control", "topology_pattern", "topology_role",
  ].includes(node.nodeType)) return "other";
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
      title: `${GRAPH_CLUSTER_LABELS[cluster]} cluster`,
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
  const rankedIds = new Map<GraphCluster, readonly string[]>();
  for (const cluster of CLUSTER_ORDER) {
    rankedIds.set(cluster, nodes
      .filter((node) => nodeCluster(node) === cluster)
      .map((node) => node.id)
      .sort((left, right) => left.localeCompare(right)));
  }
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  return nodes.map((node) => {
    const cluster = nodeCluster(node);
    const members = rankedIds.get(cluster) ?? [];
    const index = Math.max(0, members.indexOf(node.id));
    const anchor = BRAIN_CLUSTER_ANCHORS[cluster];
    const seed = hash(node.id);
    const rawRadius = Math.max(5, Math.min(15, 5 + Math.sqrt(Math.max(0, node.edgeCount)) * 1.8 + (node.pinned ? 2 : 0)));
    const provenanceBand = cluster === "mission" || cluster === "agent" || cluster === "operator"
      ? BRAIN_PROVENANCE_BANDS[cluster]
      : undefined;
    if (provenanceBand) {
      const aspect = Math.max(1, (provenanceBand.halfWidth * 2 * safeWidth) / ((provenanceBand.maxY - provenanceBand.minY) * safeHeight));
      const columnCount = Math.min(
        provenanceBand.maxColumns,
        Math.max(1, Math.ceil(Math.sqrt(Math.max(1, members.length) * aspect))),
      );
      const rowCount = Math.max(1, Math.ceil(members.length / columnCount));
      const column = index % columnCount;
      const row = Math.floor(index / columnCount);
      const bandCenterY = (provenanceBand.minY + provenanceBand.maxY) / 2;
      const x = columnCount === 1
        ? safeWidth * 0.5
        : safeWidth * (0.5 - provenanceBand.halfWidth + (column / (columnCount - 1)) * provenanceBand.halfWidth * 2);
      const y = rowCount === 1
        ? safeHeight * bandCenterY
        : safeHeight * (provenanceBand.minY + (row / (rowCount - 1)) * (provenanceBand.maxY - provenanceBand.minY));
      return constrainGraphPointToBrainRegion({
        id: node.id,
        x,
        y,
        radius: Math.min(rawRadius, cluster === "mission" ? 5.75 : 6.5),
        cluster,
        depth: ((seed % 2_001) - 1_000) / 1_000,
      }, safeWidth, safeHeight);
    }
    const angle = index * goldenAngle + ((seed % 360) / 180) * Math.PI;
    const fill = Math.sqrt((index + 0.65) / Math.max(1, members.length));
    const centerX = safeWidth * anchor.x;
    const centerY = safeHeight * anchor.y;
    const spreadX = safeWidth * anchor.spreadX * fill;
    const spreadY = safeHeight * anchor.spreadY * fill;
    return constrainGraphPointToBrainRegion({
      id: node.id,
      x: Math.max(24, Math.min(safeWidth - 24, centerX + Math.cos(angle) * spreadX)),
      y: Math.max(24, Math.min(safeHeight - 24, centerY + Math.sin(angle) * spreadY)),
      radius: rawRadius,
      cluster,
      depth: ((seed % 2_001) - 1_000) / 1_000,
    }, safeWidth, safeHeight);
  });
}

export interface ProjectedGraphPoint extends GraphPoint {
  scale: number;
}

export type GraphLabelPriority = "selected" | "hovered" | "balanced";

export interface GraphLabelCandidate {
  readonly id: string;
  readonly x: number;
  readonly y: number;
  readonly radius: number;
  readonly width: number;
  readonly height: number;
  readonly offset: number;
  readonly priority: GraphLabelPriority;
}

export interface GraphLabelPlacement extends GraphLabelCandidate {
  readonly labelX: number;
  readonly labelY: number;
}

export interface GraphLabelObstacle {
  readonly id: string;
  readonly x: number;
  readonly y: number;
  readonly radius: number;
}

const GRAPH_LABEL_PRIORITY: Readonly<Record<GraphLabelPriority, number>> = Object.freeze({
  selected: 0,
  hovered: 1,
  balanced: 2,
});

interface GraphLabelRect {
  readonly left: number;
  readonly top: number;
  readonly right: number;
  readonly bottom: number;
}

function graphLabelRect(
  candidate: Pick<GraphLabelCandidate, "width" | "height">,
  x: number,
  y: number,
  padding: number,
): GraphLabelRect {
  return {
    left: x - candidate.width / 2 - padding,
    top: y - padding,
    right: x + candidate.width / 2 + padding,
    bottom: y + candidate.height + padding,
  };
}

function graphLabelRectsOverlap(left: GraphLabelRect, right: GraphLabelRect): boolean {
  return left.left < right.right
    && left.right > right.left
    && left.top < right.bottom
    && left.bottom > right.top;
}

function graphLabelOverlapArea(left: GraphLabelRect, right: GraphLabelRect): number {
  const width = Math.max(0, Math.min(left.right, right.right) - Math.max(left.left, right.left));
  const height = Math.max(0, Math.min(left.bottom, right.bottom) - Math.max(left.top, right.top));
  return width * height;
}

/**
 * Resolves the default balanced-label projection without changing graph data
 * or node coordinates. Selected and hovered labels are considered first and
 * are never suppressed; ordinary balanced labels are retained only when their
 * deterministic below-node position does not collide with a higher-priority
 * label. Alternate placements are reserved for the two operator-focused
 * labels, avoiding label jitter during the continuous cortical orbit.
 */
export function placeBalancedGraphLabels(
  candidates: readonly GraphLabelCandidate[],
  collisionPadding = 3,
  obstacles: readonly GraphLabelObstacle[] = [],
): GraphLabelPlacement[] {
  const safePadding = Number.isFinite(collisionPadding) ? Math.max(0, collisionPadding) : 3;
  const occupied: Array<{ readonly ownerId?: string; readonly rect: GraphLabelRect }> = obstacles.map((obstacle) => ({
    ownerId: obstacle.id,
    rect: {
      left: obstacle.x - Math.max(0, obstacle.radius) - safePadding,
      top: obstacle.y - Math.max(0, obstacle.radius) - safePadding,
      right: obstacle.x + Math.max(0, obstacle.radius) + safePadding,
      bottom: obstacle.y + Math.max(0, obstacle.radius) + safePadding,
    },
  }));
  const placements: GraphLabelPlacement[] = [];
  const ordered = [...candidates].sort((left, right) => (
    GRAPH_LABEL_PRIORITY[left.priority] - GRAPH_LABEL_PRIORITY[right.priority]
    || left.id.localeCompare(right.id)
  ));

  for (const candidate of ordered) {
    const distance = Math.max(0, candidate.radius) + Math.max(0, candidate.offset);
    const below = { x: candidate.x, y: candidate.y + distance };
    const options = candidate.priority === "balanced"
      ? [below]
      : [
          below,
          { x: candidate.x, y: candidate.y - distance - candidate.height },
          { x: candidate.x + distance + candidate.width / 2, y: candidate.y - candidate.height / 2 },
          { x: candidate.x - distance - candidate.width / 2, y: candidate.y - candidate.height / 2 },
        ];
    const evaluated = options.map((option) => {
      const rect = graphLabelRect(candidate, option.x, option.y, safePadding);
      return {
        ...option,
        rect,
        overlap: occupied.reduce((total, other) => (
          total + (other.ownerId === candidate.id ? 0 : graphLabelOverlapArea(rect, other.rect))
        ), 0),
      };
    });
    const clear = evaluated.find((option) => occupied.every((other) => (
      other.ownerId === candidate.id || !graphLabelRectsOverlap(option.rect, other.rect)
    )));
    const chosen = clear ?? (candidate.priority === "balanced"
      ? undefined
      : evaluated.sort((left, right) => left.overlap - right.overlap || left.y - right.y || left.x - right.x)[0]);
    if (!chosen) continue;
    occupied.push({ rect: chosen.rect });
    placements.push({ ...candidate, labelX: chosen.x, labelY: chosen.y });
  }

  // Paint low-priority labels first so the two operator-focused labels remain
  // legible even in the pathological case where every alternate position is
  // occupied.
  return placements.sort((left, right) => (
    GRAPH_LABEL_PRIORITY[right.priority] - GRAPH_LABEL_PRIORITY[left.priority]
    || left.id.localeCompare(right.id)
  ));
}

/**
 * Applies a lobe-local, invertible cortical motion. Each hemisphere rotates in
 * the opposite direction while bridge/spine nodes breathe around their own
 * anchors. This makes motion perceptible without letting nodes drift across
 * the central fissure. Canonical coordinates remain stable.
 */
export function projectGraphPoint(
  point: GraphPoint,
  width: number,
  height: number,
  phase: number,
  motion = true,
): ProjectedGraphPoint {
  if (!motion) return { ...point, scale: 1 };
  const shape = BRAIN_REGION_SHAPES[point.cluster];
  const centerX = width * shape.x;
  const centerY = height * shape.y;
  const region = brainAnatomyRegion(point.cluster);
  const direction = region === "left-hemisphere" ? 1 : region === "right-hemisphere" ? -1 : point.cluster === "lesson" ? -0.45 : 0.35;
  const angle = Math.sin(phase) * 0.065 * direction * (0.8 + Math.abs(point.depth) * 0.2);
  const breathe = 0.976 + (Math.cos(phase + direction) + 1) * 0.008;
  const dx = (point.x - centerX) * breathe;
  const dy = (point.y - centerY) * breathe;
  const cosine = Math.cos(angle);
  const sine = Math.sin(angle);
  const amplitudeX = region === "spinal-trace" ? 2.5 : region === "corpus-callosum" ? 6 : 18;
  const amplitudeY = region === "spinal-trace" ? 4 : region === "corpus-callosum" ? 4 : 10;
  const driftX = point.depth * Math.sin(phase + direction * 0.8) * amplitudeX;
  const driftY = point.depth * Math.cos(phase + direction * 0.8) * amplitudeY;
  const depthScale = 1 + point.depth * Math.sin(phase + direction * 0.65) * 0.16;
  return {
    ...point,
    x: centerX + dx * cosine - dy * sine + driftX,
    y: centerY + dx * sine + dy * cosine + driftY,
    scale: Math.max(0.82, Math.min(1.18, depthScale)),
  };
}

export function unprojectGraphCoordinates(
  point: GraphPoint,
  renderedX: number,
  renderedY: number,
  width: number,
  height: number,
  phase: number,
  motion = true,
): { x: number; y: number } {
  if (!motion) return { x: renderedX, y: renderedY };
  const shape = BRAIN_REGION_SHAPES[point.cluster];
  const centerX = width * shape.x;
  const centerY = height * shape.y;
  const region = brainAnatomyRegion(point.cluster);
  const direction = region === "left-hemisphere" ? 1 : region === "right-hemisphere" ? -1 : point.cluster === "lesson" ? -0.45 : 0.35;
  const angle = Math.sin(phase) * 0.065 * direction * (0.8 + Math.abs(point.depth) * 0.2);
  const breathe = 0.976 + (Math.cos(phase + direction) + 1) * 0.008;
  const amplitudeX = region === "spinal-trace" ? 2.5 : region === "corpus-callosum" ? 6 : 18;
  const amplitudeY = region === "spinal-trace" ? 4 : region === "corpus-callosum" ? 4 : 10;
  const driftX = point.depth * Math.sin(phase + direction * 0.8) * amplitudeX;
  const driftY = point.depth * Math.cos(phase + direction * 0.8) * amplitudeY;
  const dx = renderedX - centerX - driftX;
  const dy = renderedY - centerY - driftY;
  const cosine = Math.cos(-angle);
  const sine = Math.sin(-angle);
  return {
    x: centerX + (dx * cosine - dy * sine) / breathe,
    y: centerY + (dx * sine + dy * cosine) / breathe,
  };
}

export type GraphSignalKind = "knowledge" | "hazard" | "recovery";

export interface GraphSignalRoute {
  edgeId: string;
  sourceNodeId: string;
  targetNodeId: string;
  fromNodeId: string;
  toNodeId: string;
  hop: number;
  kind: GraphSignalKind;
}

export interface AmbientGraphSignalRoute extends GraphSignalRoute {
  /** Stable 0..1 phase offset so pulses do not move in lockstep. */
  phaseOffset: number;
  /** Deliberately slow travel time for calm, continuously perceptible motion. */
  durationMs: number;
}

const HAZARD_EDGE_TYPES = new Set<MemoryEdgeSummary["edgeType"]>([
  "contradicts", "failed_in", "failed_because", "not_applicable_to", "caused",
  "leaves_in_state", "requires_recovery", "avoid_after",
]);
const RECOVERY_EDGE_TYPES = new Set<MemoryEdgeSummary["edgeType"]>([
  "recovered_by", "recovered_with", "alternative_to", "remediated_by", "mitigates",
  "safe_when", "mitigated_by",
]);

export function graphSignalKind(
  edge: Pick<MemoryEdgeSummary, "edgeType" | "sourceNodeId" | "targetNodeId">,
  nodes: ReadonlyMap<string, Pick<MemoryNodeSummary, "nodeType">>,
): GraphSignalKind {
  if (RECOVERY_EDGE_TYPES.has(edge.edgeType)) return "recovery";
  if (HAZARD_EDGE_TYPES.has(edge.edgeType)) return "hazard";
  const endpointTypes = [nodes.get(edge.sourceNodeId)?.nodeType, nodes.get(edge.targetNodeId)?.nodeType];
  if (endpointTypes.some((type) => ["recovery", "remediation", "alternative", "recovery_pattern", "health_check"].includes(type ?? ""))) return "recovery";
  if (endpointTypes.some((type) => ["failure", "failure_mode", "operational_hazard", "target_state_transition"].includes(type ?? ""))) return "hazard";
  return "knowledge";
}

/**
 * Builds a bounded signal tree from only returned canonical edges. The visual
 * pulse can never imply a relationship that is absent from the graph payload.
 */
export function buildNeuronSignalRoutes(
  nodes: readonly MemoryNodeSummary[],
  edges: readonly MemoryEdgeSummary[],
  selectedId?: string,
  maxHops = 5,
  maxRoutes = 180,
): GraphSignalRoute[] {
  if (!selectedId || !nodes.some((node) => node.id === selectedId)) return [];
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    if (!nodeMap.has(edge.sourceNodeId) || !nodeMap.has(edge.targetNodeId)) continue;
    adjacency.set(edge.sourceNodeId, [...(adjacency.get(edge.sourceNodeId) ?? []), edge.targetNodeId]);
    adjacency.set(edge.targetNodeId, [...(adjacency.get(edge.targetNodeId) ?? []), edge.sourceNodeId]);
  }
  adjacency.forEach((items, key) => adjacency.set(key, [...new Set(items)].sort((left, right) => left.localeCompare(right))));
  const distance = new Map<string, number>([[selectedId, 0]]);
  const queue = [selectedId];
  while (queue.length > 0) {
    const current = queue.shift()!;
    const hop = distance.get(current)!;
    if (hop >= maxHops) continue;
    for (const neighbor of adjacency.get(current) ?? []) {
      if (distance.has(neighbor)) continue;
      distance.set(neighbor, hop + 1);
      queue.push(neighbor);
    }
  }
  const priority: Readonly<Record<GraphSignalKind, number>> = { hazard: 0, recovery: 1, knowledge: 2 };
  return edges.flatMap((edge): GraphSignalRoute[] => {
    const sourceHop = distance.get(edge.sourceNodeId);
    const targetHop = distance.get(edge.targetNodeId);
    if (sourceHop === undefined || targetHop === undefined || Math.min(sourceHop, targetHop) >= maxHops) return [];
    const sourceFirst = sourceHop < targetHop || (sourceHop === targetHop && edge.sourceNodeId.localeCompare(edge.targetNodeId) <= 0);
    return [{
        edgeId: edge.id,
        sourceNodeId: edge.sourceNodeId,
        targetNodeId: edge.targetNodeId,
        fromNodeId: sourceFirst ? edge.sourceNodeId : edge.targetNodeId,
        toNodeId: sourceFirst ? edge.targetNodeId : edge.sourceNodeId,
        hop: Math.min(sourceHop, targetHop),
        kind: graphSignalKind(edge, nodeMap),
    }];
  }).sort((left, right) => (
    priority[left.kind] - priority[right.kind]
    || left.hop - right.hop
    || left.edgeId.localeCompare(right.edgeId)
  )).slice(0, Math.max(0, maxRoutes));
}

/**
 * Selects a small, deterministic, region-balanced set of canonical edges for
 * ambient cortical pulses. These pulses are a display affordance only: every
 * route is backed by a returned edge and never implies a missing relationship
 * or live runtime activity.
 */
export function buildAmbientNeuronSignalRoutes(
  nodes: readonly MemoryNodeSummary[],
  edges: readonly MemoryEdgeSummary[],
  maxRoutes = 14,
): AmbientGraphSignalRoute[] {
  if (maxRoutes <= 0) return [];
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const buckets = new Map<string, AmbientGraphSignalRoute[]>();
  for (const edge of edges) {
    const source = nodeMap.get(edge.sourceNodeId);
    const target = nodeMap.get(edge.targetNodeId);
    if (!source || !target || edge.sourceNodeId === edge.targetNodeId) continue;
    const seed = hash(edge.id);
    const sourceFirst = seed % 2 === 0;
    const sourceRegion = brainAnatomyRegion(nodeCluster(source));
    const targetRegion = brainAnatomyRegion(nodeCluster(target));
    const bucket = [sourceRegion, targetRegion].sort().join(":" );
    const route: AmbientGraphSignalRoute = {
      edgeId: edge.id,
      sourceNodeId: edge.sourceNodeId,
      targetNodeId: edge.targetNodeId,
      fromNodeId: sourceFirst ? edge.sourceNodeId : edge.targetNodeId,
      toNodeId: sourceFirst ? edge.targetNodeId : edge.sourceNodeId,
      hop: 0,
      kind: graphSignalKind(edge, nodeMap),
      phaseOffset: (seed % 10_000) / 10_000,
      durationMs: 3_600 + seed % 2_400,
    };
    buckets.set(bucket, [...(buckets.get(bucket) ?? []), route]);
  }
  for (const routes of buckets.values()) {
    routes.sort((left, right) => hash(left.edgeId) - hash(right.edgeId) || left.edgeId.localeCompare(right.edgeId));
  }
  const orderedBuckets = [...buckets.keys()].sort();
  const selected: AmbientGraphSignalRoute[] = [];
  while (selected.length < maxRoutes && orderedBuckets.some((key) => (buckets.get(key)?.length ?? 0) > 0)) {
    for (const key of orderedBuckets) {
      const route = buckets.get(key)?.shift();
      if (route) selected.push(route);
      if (selected.length >= maxRoutes) break;
    }
  }
  return selected;
}

export function compactGraphLayout(points: readonly GraphPoint[], width: number, height: number): GraphPoint[] {
  return points.map((point) => {
    const anchor = BRAIN_CLUSTER_ANCHORS[point.cluster];
    return constrainGraphPointToBrainRegion({
      ...point,
      x: width * anchor.x + (point.x - width * anchor.x) * 0.72,
      y: height * anchor.y + (point.y - height * anchor.y) * 0.72,
    }, width, height);
  });
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
      const sameRegion = brainAnatomyRegion(left.cluster) === brainAnatomyRegion(right.cluster);
      // Cross-region relationships stay visible, but cannot pull technologies,
      // attacks, bridge knowledge, and provenance out of their anatomy.
      const relationshipWeight = sameRegion ? 1 : 0.28;
      const force = Math.max(-3, Math.min(3, (distance - 74) * 0.018)) * relationshipWeight;
      const fx = (dx / distance) * force;
      const fy = (dy / distance) * force;
      velocity[leftIndex]!.x += fx;
      velocity[leftIndex]!.y += fy;
      velocity[rightIndex]!.x -= fx;
      velocity[rightIndex]!.y -= fy;
    }
    // Semantic gravity prevents a highly connected provenance record from
    // dragging an entire lobe into the center of a generic force-directed
    // hairball.
    points.forEach((point, position) => {
      const anchor = BRAIN_CLUSTER_ANCHORS[point.cluster];
      velocity[position]!.x += (safeWidth * anchor.x - point.x) * 0.012;
      velocity[position]!.y += (safeHeight * anchor.y - point.y) * 0.012;
    });
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
      const constrained = constrainGraphPointToBrainRegion({
        ...point,
        x: point.x + movement.x,
        y: point.y + movement.y,
      }, safeWidth, safeHeight);
      point.x = constrained.x;
      point.y = constrained.y;
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

export type GraphMotionMode = "orbital" | "reduced" | "paused-hidden";

export function graphMotionMode(reducedMotion: boolean, documentVisible: boolean): GraphMotionMode {
  if (!documentVisible) return "paused-hidden";
  return reducedMotion ? "reduced" : "orbital";
}

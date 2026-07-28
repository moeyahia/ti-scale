import type {
  ReconDigitalTwin,
  TopologyEdge,
  TopologyNode,
  TopologyVerificationState,
} from "../../domain/types/runIntelligence";

export interface TopologyGraphFilters {
  readonly search?: string;
  readonly nodeTypes?: readonly string[];
  readonly lifecycleStates?: readonly TopologyNode["lifecycleState"][];
  readonly scopeStatuses?: readonly TopologyNode["scopeStatus"][];
  readonly verificationStates?: readonly TopologyVerificationState[];
}

export interface TopologyGraphLayoutOptions {
  readonly width: number;
  readonly height: number;
  readonly padding?: number;
  readonly nodeRadius?: number;
}

export interface TopologyGraphPoint {
  readonly id: string;
  readonly x: number;
  readonly y: number;
  readonly radius: number;
}

export interface TopologyGraphBounds {
  readonly minX: number;
  readonly minY: number;
  readonly maxX: number;
  readonly maxY: number;
  readonly width: number;
  readonly height: number;
}

export interface TopologyGraphAdjacency {
  readonly incomingEdgeIds: readonly string[];
  readonly outgoingEdgeIds: readonly string[];
  readonly neighborNodeIds: readonly string[];
}

export type IgnoredTopologyEdgeReason = "missing_source" | "missing_target" | "missing_both";

export interface IgnoredTopologyEdge {
  readonly edge: TopologyEdge;
  readonly reason: IgnoredTopologyEdgeReason;
}

export interface TopologyGraphModel {
  readonly nodes: readonly TopologyNode[];
  readonly edges: readonly TopologyEdge[];
  readonly points: readonly TopologyGraphPoint[];
  readonly pointByNodeId: ReadonlyMap<string, TopologyGraphPoint>;
  readonly adjacency: ReadonlyMap<string, TopologyGraphAdjacency>;
  readonly unconnectedNodeIds: readonly string[];
  readonly ignoredEdges: readonly IgnoredTopologyEdge[];
  readonly fitBounds: TopologyGraphBounds | null;
}

interface MutableAdjacency {
  incomingEdgeIds: string[];
  outgoingEdgeIds: string[];
  neighborNodeIds: string[];
}

function finiteNonNegative(value: number | undefined, fallback: number): number {
  return value === undefined || !Number.isFinite(value) || value < 0 ? fallback : value;
}

function finitePositive(value: number, fallback: number): number {
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function searchableNodeText(node: TopologyNode): string {
  return [
    node.id,
    node.primaryLabel,
    node.normalizedIdentity,
    node.nodeType,
    node.lifecycleState,
    node.scopeStatus,
    node.verificationState,
  ].join("\n").toLocaleLowerCase();
}

function allowed<T extends string>(value: T, selected: readonly T[] | undefined): boolean {
  return selected === undefined || selected.length === 0 || selected.includes(value);
}

export function topologyNodeMatchesFilters(
  node: TopologyNode,
  filters: TopologyGraphFilters = {},
): boolean {
  const search = filters.search?.trim().toLocaleLowerCase();
  return (!search || searchableNodeText(node).includes(search))
    && allowed(node.nodeType, filters.nodeTypes)
    && allowed(node.lifecycleState, filters.lifecycleStates)
    && allowed(node.scopeStatus, filters.scopeStatuses)
    && allowed(node.verificationState, filters.verificationStates);
}

function compareNodes(left: TopologyNode, right: TopologyNode): number {
  return left.nodeType.localeCompare(right.nodeType)
    || left.primaryLabel.localeCompare(right.primaryLabel)
    || left.id.localeCompare(right.id);
}

function layoutNodes(
  nodes: readonly TopologyNode[],
  unconnectedNodeIds: ReadonlySet<string>,
  options: TopologyGraphLayoutOptions,
): TopologyGraphPoint[] {
  if (nodes.length === 0) return [];
  const width = finitePositive(options.width, 1);
  const height = finitePositive(options.height, 1);
  const radius = finiteNonNegative(options.nodeRadius, 8);
  const requestedPadding = finiteNonNegative(options.padding, 24);
  const padding = Math.min(requestedPadding, width / 2, height / 2);
  const usableWidth = Math.max(0, width - padding * 2);
  const usableHeight = Math.max(0, height - padding * 2);
  const columns = Math.max(1, Math.ceil(Math.sqrt(nodes.length * (width / height))));
  const connected = nodes.filter((node) => !unconnectedNodeIds.has(node.id));
  const unconnected = nodes.filter((node) => unconnectedNodeIds.has(node.id));
  const connectedRows = connected.length === 0 ? 0 : Math.ceil(connected.length / columns);
  const unconnectedRows = unconnected.length === 0 ? 0 : Math.ceil(unconnected.length / columns);
  const laneGapRows = connectedRows > 0 && unconnectedRows > 0 ? 1 : 0;
  const rowSlots = Math.max(1, connectedRows + laneGapRows + unconnectedRows);

  const positionGroup = (
    group: readonly TopologyNode[],
    firstRow: number,
  ): TopologyGraphPoint[] => group.map((node, index) => {
    const localRow = Math.floor(index / columns);
    const firstIndexInRow = localRow * columns;
    const nodesInRow = Math.min(columns, group.length - firstIndexInRow);
    const column = index - firstIndexInRow;
    const row = firstRow + localRow;
    return {
      id: node.id,
      x: nodesInRow === 1
        ? width / 2
        : padding + (column / (nodesInRow - 1)) * usableWidth,
      y: rowSlots === 1
        ? height / 2
        : padding + (row / (rowSlots - 1)) * usableHeight,
      radius,
    };
  });

  return [
    ...positionGroup(connected, 0),
    ...positionGroup(unconnected, connectedRows + laneGapRows),
  ];
}

export function topologyGraphFitBounds(
  points: readonly TopologyGraphPoint[],
  padding = 0,
): TopologyGraphBounds | null {
  if (points.length === 0) return null;
  const safePadding = finiteNonNegative(padding, 0);
  let minX = Number.POSITIVE_INFINITY;
  let minY = Number.POSITIVE_INFINITY;
  let maxX = Number.NEGATIVE_INFINITY;
  let maxY = Number.NEGATIVE_INFINITY;
  for (const point of points) {
    minX = Math.min(minX, point.x - point.radius - safePadding);
    minY = Math.min(minY, point.y - point.radius - safePadding);
    maxX = Math.max(maxX, point.x + point.radius + safePadding);
    maxY = Math.max(maxY, point.y + point.radius + safePadding);
  }
  return { minX, minY, maxX, maxY, width: maxX - minX, height: maxY - minY };
}

export function buildTopologyGraphModel(
  graph: Pick<ReconDigitalTwin, "nodes" | "edges">,
  filters: TopologyGraphFilters,
  layout: TopologyGraphLayoutOptions,
): TopologyGraphModel {
  const canonicalNodeIds = new Set(graph.nodes.map(({ id }) => id));
  const ignoredEdges: IgnoredTopologyEdge[] = [];
  const canonicalEdges: TopologyEdge[] = [];

  for (const edge of graph.edges) {
    const hasSource = canonicalNodeIds.has(edge.sourceNodeId);
    const hasTarget = canonicalNodeIds.has(edge.targetNodeId);
    if (!hasSource || !hasTarget) {
      ignoredEdges.push({
        edge,
        reason: !hasSource && !hasTarget
          ? "missing_both"
          : hasSource
            ? "missing_target"
            : "missing_source",
      });
      continue;
    }
    canonicalEdges.push(edge);
  }

  const nodes = graph.nodes.filter((node) => topologyNodeMatchesFilters(node, filters)).sort(compareNodes);
  const visibleNodeIds = new Set(nodes.map(({ id }) => id));
  const edges = canonicalEdges.filter((edge) => (
    visibleNodeIds.has(edge.sourceNodeId) && visibleNodeIds.has(edge.targetNodeId)
  ));
  const canonicallyConnectedNodeIds = new Set(canonicalEdges.flatMap((edge) => [
    edge.sourceNodeId,
    edge.targetNodeId,
  ]));

  const mutableAdjacency = new Map<string, MutableAdjacency>();
  for (const node of nodes) {
    mutableAdjacency.set(node.id, {
      incomingEdgeIds: [],
      outgoingEdgeIds: [],
      neighborNodeIds: [],
    });
  }
  for (const edge of edges) {
    const source = mutableAdjacency.get(edge.sourceNodeId);
    const target = mutableAdjacency.get(edge.targetNodeId);
    if (!source || !target) continue;
    source.outgoingEdgeIds.push(edge.id);
    source.neighborNodeIds.push(edge.targetNodeId);
    target.incomingEdgeIds.push(edge.id);
    target.neighborNodeIds.push(edge.sourceNodeId);
  }

  const adjacency = new Map<string, TopologyGraphAdjacency>();
  const unconnectedNodeIds: string[] = [];
  for (const node of nodes) {
    const record = mutableAdjacency.get(node.id);
    if (!record) continue;
    adjacency.set(node.id, {
      incomingEdgeIds: record.incomingEdgeIds,
      outgoingEdgeIds: record.outgoingEdgeIds,
      neighborNodeIds: record.neighborNodeIds,
    });
    if (!canonicallyConnectedNodeIds.has(node.id)) {
      unconnectedNodeIds.push(node.id);
    }
  }

  const points = layoutNodes(nodes, new Set(unconnectedNodeIds), layout);
  const pointByNodeId = new Map(points.map((point) => [point.id, point]));
  return {
    nodes,
    edges,
    points,
    pointByNodeId,
    adjacency,
    unconnectedNodeIds,
    ignoredEdges,
    fitBounds: topologyGraphFitBounds(points),
  };
}

export function hitTestTopologyGraph(
  model: Pick<TopologyGraphModel, "points">,
  x: number,
  y: number,
  tolerance = 0,
): TopologyGraphPoint | undefined {
  if (!Number.isFinite(x) || !Number.isFinite(y)) return undefined;
  const safeTolerance = finiteNonNegative(tolerance, 0);
  let match: TopologyGraphPoint | undefined;
  let matchDistanceSquared = Number.POSITIVE_INFINITY;
  for (const point of model.points) {
    const deltaX = x - point.x;
    const deltaY = y - point.y;
    const distanceSquared = deltaX * deltaX + deltaY * deltaY;
    const hitRadius = point.radius + safeTolerance;
    if (distanceSquared > hitRadius * hitRadius) continue;
    if (
      distanceSquared < matchDistanceSquared
      || (distanceSquared === matchDistanceSquared && match && point.id.localeCompare(match.id) < 0)
    ) {
      match = point;
      matchDistanceSquared = distanceSquared;
    }
  }
  return match;
}

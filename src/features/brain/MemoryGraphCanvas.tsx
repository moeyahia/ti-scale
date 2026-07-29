import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import type { MemoryEdgeSummary, MemoryNodeSummary } from "../../domain/types/brain";
import type { BrainGraphLabelDensity, PinnedGraphPositions } from "./brainGraphState";
import {
  BRAIN_ATLAS_REGIONS,
  BRAIN_ATLAS_REGION_DEFINITIONS,
  brainAtlasProjection,
  brainAtlasRegionForNode,
  brainAtlasRegionCounts,
  buildBrainAtlasCloud,
  graphPointToBrainAtlasPosition,
  projectBrainAtlasPoint,
  type BrainAtlasRegion,
} from "./brainAtlasGeometry";
import {
  BrainAtlasWebGLRenderer,
  detectBrainAtlasRenderer,
  parseBrainAtlasColor,
  type BrainAtlasColor,
  type BrainAtlasProjectedNode,
  type BrainAtlasWebGLTheme,
} from "./BrainAtlasWebGLRenderer";
import {
  brainAnatomyRegion,
  buildAmbientNeuronSignalRoutes,
  buildNeuronSignalRoutes,
  collapseGraphClusters,
  compactGraphLayout,
  constrainGraphPointToBrainRegion,
  GRAPH_EDGE_VISIBILITY,
  graphSignalKind,
  graphMotionMode,
  graphZoomPercent,
  layoutGraph,
  nodeCluster,
  placeBalancedGraphLabels,
  projectGraphPoint,
  relatedNodeIds,
  relaxGraphLayout,
  shortestMemoryPath,
  unprojectGraphCoordinates,
  type GraphCluster,
  type GraphPoint,
  type GraphSignalKind,
  type ProjectedGraphPoint,
} from "./graphUtils";
import {
  BRAIN_AMBIENT_PARTICLE_ALPHA,
  BRAIN_NODE_HIT_RADIUS_PX,
  BRAIN_NODE_VISUAL_SCALE,
  brainNodeVisualRadius,
  nearestBrainNodeHit,
  stableCollapsedClusterHit,
} from "./brainVisualLanguage";

function canvasTheme(element: HTMLCanvasElement) {
  const styles = getComputedStyle(element);
  const color = (token: string, fallback: string) => styles.getPropertyValue(token).trim() || fallback;
  return {
    canvas: color("--os-graph-canvas", "#f8f7f3"),
    cloud: color("--os-graph-cloud", "#dbe4eb"),
    node: color("--os-graph-node-titanium", "#eef3f6"),
    edge: color("--os-graph-edge", "rgba(52, 58, 64, 0.32)"),
    edgeConnected: color("--os-graph-edge-connected", "rgba(52, 58, 64, 0.70)"),
    selection: color("--os-graph-selection", "#34495e"),
    signal: color("--os-graph-signal", "#3f596a"),
    recovery: color("--os-graph-recovery", "#496a62"),
    label: color("--os-graph-label", "#292d31"),
    nodeBorder: color("--os-graph-node-border", "rgba(255, 254, 250, 0.98)"),
    accent: color("--os-accent", "#343a40"),
    danger: color("--os-danger", "#a1213a"),
  };
}

interface Camera { rotationX: number; rotationY: number; zoom: number }

const DEFAULT_CAMERA: Readonly<Camera> = Object.freeze({ rotationX: -0.08, rotationY: 0, zoom: 1 });

function webGLTheme(element: HTMLCanvasElement, theme: ReturnType<typeof canvasTheme>): BrainAtlasWebGLTheme {
  const fallback = (hex: string): BrainAtlasColor => parseBrainAtlasColor(hex, [0.4, 0.43, 0.46, 1]);
  const parse = (value: string, hex: string): BrainAtlasColor => parseBrainAtlasColor(value, fallback(hex));
  return {
    background: parse(theme.canvas, "#f8f7f3"),
    cloud: Object.fromEntries(BRAIN_ATLAS_REGIONS.map((region) => [
      region,
      parse(theme.cloud, "#dbe4eb"),
    ])) as BrainAtlasWebGLTheme["cloud"],
    node: parse(theme.node, "#eef3f6"),
    edge: parse(theme.edge, "#606870"),
    edgeConnected: parse(theme.edgeConnected, "#3f4850"),
    knowledge: parse(theme.signal, "#3f596a"),
    hazard: parse(theme.danger, "#a1213a"),
    recovery: parse(theme.recovery, "#496a62"),
    selection: parse(theme.selection, "#34495e"),
  };
}

/**
 * Deliberately slow enough to remain an operational visualization, but fast
 * enough that an operator can perceive the bilateral rotation without having
 * to stare at the canvas. Reduced-motion and hidden-tab gates still disable it.
 */
export const BRAIN_ORBIT_PERIOD_MS = 18_000;
export const BRAIN_IDLE_YAW_AMPLITUDE = 0.20;
const BRAIN_ATLAS_CLOUD = buildBrainAtlasCloud();
const IDLE_DELAY_MS = 1_200;
const SIGNAL_TRAVEL_MS = 920;
const SIGNAL_HOP_DELAY_MS = 150;
const SIGNAL_SECOND_WAVE_DELAY_MS = 280;
const MAX_FRAME_RATE_MS = 16;
// Labels are a secondary 2D overlay over the continuously animated graph.
// Re-running collision placement against a 1,000-node obstacle field on every
// orbital frame wastes the main-thread budget without making the deliberately
// slow 18-second yaw look smoother. Interactions still force an immediate
// effect/frame; passive orbit labels then track at a bounded readable cadence.
const PASSIVE_LABEL_REFRESH_MS = 120;

function signalStroke(kind: GraphSignalKind, theme: ReturnType<typeof canvasTheme>): string {
  if (kind === "hazard") return theme.danger;
  if (kind === "recovery") return theme.recovery;
  return theme.signal;
}

function applyEdgePattern(context: CanvasRenderingContext2D, kind: GraphSignalKind, zoom: number) {
  if (kind === "hazard") context.setLineDash([7 / zoom, 5 / zoom]);
  else if (kind === "recovery") context.setLineDash([2 / zoom, 3 / zoom]);
  else context.setLineDash([]);
}

function drawSignalGlyph(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  kind: GraphSignalKind,
  color: string,
  zoom: number,
  opacity = 1,
  size = 1,
) {
  const radius = 3.8 / zoom * size;
  context.save();
  context.globalAlpha *= opacity;
  context.fillStyle = color;
  context.strokeStyle = color;
  context.shadowColor = color;
  context.shadowBlur = 9 / zoom * size;
  context.lineWidth = 1 / zoom;
  context.beginPath();
  if (kind === "hazard") {
    context.moveTo(x, y - radius * 1.35);
    context.lineTo(x + radius * 1.2, y + radius);
    context.lineTo(x - radius * 1.2, y + radius);
    context.closePath();
  } else if (kind === "recovery") {
    context.rect(x - radius, y - radius, radius * 2, radius * 2);
  } else {
    context.arc(x, y, radius, 0, Math.PI * 2);
  }
  context.fill();
  context.restore();
}

function canvasNodeLabel(node: MemoryNodeSummary): string {
  if (["target", "asset"].includes(node.nodeType)) return "Ephemeral target provenance";
  if (["mission", "run"].includes(node.nodeType)) return "Source provenance";
  return node.title;
}

function drawBrainAtlasLabels({
  element,
  width,
  height,
  ratio,
  projected,
  nodeMap,
  selectedId,
  hoveredId,
  labelDensity,
  balancedLabelIds,
  illuminatedNodeIds,
  zoom,
  theme,
  showLabels,
}: {
  readonly element: HTMLCanvasElement;
  readonly width: number;
  readonly height: number;
  readonly ratio: number;
  readonly projected: ReadonlyMap<string, BrainAtlasProjectedNode>;
  readonly nodeMap: ReadonlyMap<string, MemoryNodeSummary>;
  readonly selectedId?: string;
  readonly hoveredId?: string;
  readonly labelDensity: BrainGraphLabelDensity;
  readonly balancedLabelIds: ReadonlySet<string>;
  readonly illuminatedNodeIds: ReadonlySet<string>;
  readonly zoom: number;
  readonly theme: ReturnType<typeof canvasTheme>;
  readonly showLabels: boolean;
}): void {
  const pixelWidth = Math.max(1, Math.floor(width * ratio));
  const pixelHeight = Math.max(1, Math.floor(height * ratio));
  if (element.width !== pixelWidth) element.width = pixelWidth;
  if (element.height !== pixelHeight) element.height = pixelHeight;
  const context = element.getContext("2d");
  if (!context) return;
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  if (!showLabels) return;

  const candidatePoints = labelDensity === "all"
    ? [...projected.values()]
    : [...new Set([
        ...balancedLabelIds,
        ...(selectedId ? [selectedId] : []),
        ...(hoveredId ? [hoveredId] : []),
      ])].flatMap((id) => {
        const point = projected.get(id);
        return point ? [point] : [];
      });
  const graphLabels = candidatePoints.flatMap((point) => {
    const node = nodeMap.get(point.id);
    if (!node || !point.visible) return [];
    const selected = point.id === selectedId;
    const isHovered = hoveredId === point.id;
    const balanced = labelDensity === "balanced"
      && balancedLabelIds.has(point.id)
      && (zoom >= 1.05 || node.edgeCount >= 8);
    if (labelDensity !== "all" && !selected && !isHovered && !balanced) return [];
    const displayTitle = canvasNodeLabel(node);
    const label = displayTitle.length > 34 ? `${displayTitle.slice(0, 33)}…` : displayTitle;
    const fontSize = Math.max(9, 11 / zoom);
    const font = `${selected || isHovered ? 650 : 520} ${fontSize}px Inter, system-ui, sans-serif`;
    context.font = font;
    const textWidth = context.measureText(label).width;
    const dimmed = Boolean(selectedId && !illuminatedNodeIds.has(point.id));
    return [{
      candidate: {
        id: point.id,
        x: point.x,
        y: point.y,
        radius: Math.max(5, point.radius),
        width: textWidth,
        height: fontSize * 1.25,
        offset: 7 / zoom,
        priority: selected ? "selected" as const : isHovered ? "hovered" as const : "balanced" as const,
      },
      label,
      font,
      color: selected ? theme.selection : theme.label,
      opacity: selected || isHovered ? 1 : dimmed ? 0.15 : 0.84,
    }];
  });
  const graphLabelById = new Map(graphLabels.map((item) => [item.candidate.id, item]));
  const placements = labelDensity === "all"
    ? graphLabels.map((item) => ({
        ...item.candidate,
        labelX: item.candidate.x,
        labelY: item.candidate.y + item.candidate.radius + item.candidate.offset,
      }))
    : placeBalancedGraphLabels(
        graphLabels.map((item) => item.candidate),
        3 / zoom,
        [...projected.values()].map((point) => ({ id: point.id, x: point.x, y: point.y, radius: Math.max(5, point.radius) })),
      );
  for (const placement of placements) {
    const item = graphLabelById.get(placement.id);
    if (!item) continue;
    context.globalAlpha = item.opacity;
    context.font = item.font;
    context.textAlign = "center";
    context.textBaseline = "top";
    context.fillStyle = item.color;
    context.fillText(item.label, placement.labelX, placement.labelY);
  }
  context.globalAlpha = 1;
}

export function MemoryGraphCanvas({
  nodes, edges, selectedId, rootNodeId, pathStartNodeId, onSelect, compact, physics, labelDensity,
  collapsedClusters = [], pinnedPositions = {}, onPinPosition, onClearPinnedPositions, onExpandCluster,
}: {
  nodes: MemoryNodeSummary[];
  edges: MemoryEdgeSummary[];
  selectedId?: string;
  rootNodeId?: string;
  pathStartNodeId?: string;
  onSelect: (nodeId?: string) => void;
  compact: boolean;
  physics: boolean;
  labelDensity: BrainGraphLabelDensity;
  collapsedClusters?: readonly GraphCluster[];
  pinnedPositions?: PinnedGraphPositions;
  onPinPosition?: (nodeId: string, point: { x: number; y: number }) => void;
  onClearPinnedPositions?: (nodeIds: readonly string[]) => void;
  onExpandCluster?: (cluster: GraphCluster) => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const labelCanvas = useRef<HTMLCanvasElement>(null);
  const webGLRenderer = useRef<BrainAtlasWebGLRenderer | undefined>(undefined);
  const [size, setSize] = useState({ width: 900, height: 600 });
  const [camera, setCamera] = useState<Camera>({ ...DEFAULT_CAMERA });
  const [rendererMode, setRendererMode] = useState<"webgl2" | "canvas2d">(() => detectBrainAtlasRenderer());
  const [rendererNotice, setRendererNotice] = useState("");
  const [visibleRegions, setVisibleRegions] = useState<ReadonlySet<BrainAtlasRegion>>(() => new Set(BRAIN_ATLAS_REGIONS));
  const [showLabels, setShowLabels] = useState(true);
  const [hovered, setHovered] = useState<string>();
  const [points, setPoints] = useState<GraphPoint[]>([]);
  const [layoutPending, setLayoutPending] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(() => (
    typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches
  ));
  const [documentVisible, setDocumentVisible] = useState(() => (
    typeof document === "undefined" || document.visibilityState !== "hidden"
  ));
  const layoutRequest = useRef(0);
  const layoutWorker = useRef<Worker | undefined>(undefined);
  const orbitPhase = useRef(0);
  const lastInteractionAt = useRef(0);
  const signalStartedAt = useRef(0);
  const renderedPointMap = useRef(new Map<string, ProjectedGraphPoint | BrainAtlasProjectedNode>());
  const rotationDrag = useRef<{ x: number; y: number; rotationX: number; rotationY: number; moved: boolean } | undefined>(undefined);
  const nodeDrag = useRef<{ id: string; startX: number; startY: number; originX: number; originY: number; x: number; y: number; moved: boolean } | undefined>(undefined);
  const projection = useMemo(() => collapseGraphClusters(nodes, edges, new Set(collapsedClusters)), [collapsedClusters, edges, nodes]);
  const displayNodes = projection.nodes;
  const displayEdges = projection.edges;
  const pointMap = useMemo(() => new Map(points.map((point) => [point.id, point])), [points]);
  const nodeMap = useMemo(() => new Map(displayNodes.map((node) => [node.id, node])), [displayNodes]);
  const balancedLabelIds = useMemo(() => new Set(displayNodes
    .filter((node) => !["mission", "agent", "operator"].includes(nodeCluster(node)))
    .sort((left, right) => right.edgeCount - left.edgeCount || left.title.localeCompare(right.title))
    .slice(0, 18)
    .map((node) => node.id)), [displayNodes]);
  const edgeKinds = useMemo(() => new Map(displayEdges.map((edge) => [edge.id, graphSignalKind(edge, nodeMap)])), [displayEdges, nodeMap]);
  const related = useMemo(() => relatedNodeIds(displayEdges, selectedId), [displayEdges, selectedId]);
  const pathOrigin = pathStartNodeId ?? rootNodeId;
  const path = useMemo(() => pathOrigin && selectedId ? shortestMemoryPath(displayEdges, pathOrigin, selectedId) : [], [displayEdges, pathOrigin, selectedId]);
  const pathEdges = useMemo(() => new Set(path.slice(1).map((id, index) => [path[index], id].sort().join("|"))), [path]);
  const signalRoutes = useMemo(() => buildNeuronSignalRoutes(displayNodes, displayEdges, selectedId), [displayEdges, displayNodes, selectedId]);
  const ambientSignalRoutes = useMemo(() => buildAmbientNeuronSignalRoutes(displayNodes, displayEdges), [displayEdges, displayNodes]);
  const ambientEdgeIds = useMemo(() => new Set(ambientSignalRoutes.map((route) => route.edgeId)), [ambientSignalRoutes]);
  const signalRouteByEdge = useMemo(() => new Map(signalRoutes.map((route) => [route.edgeId, route])), [signalRoutes]);
  const illuminatedNodeIds = useMemo(() => new Set([
    ...(selectedId ? [selectedId] : []),
    ...signalRoutes.flatMap((route) => [route.fromNodeId, route.toNodeId]),
  ]), [selectedId, signalRoutes]);
  const signalKindCounts = useMemo(() => signalRoutes.reduce((counts, route) => ({
    ...counts,
    [route.kind]: counts[route.kind] + 1,
  }), { knowledge: 0, hazard: 0, recovery: 0 } as Record<GraphSignalKind, number>), [signalRoutes]);
  const motionEnabled = documentVisible && !reducedMotion;
  const motionMode = graphMotionMode(reducedMotion, documentVisible);
  const regionCounts = useMemo(() => brainAtlasRegionCounts(displayNodes), [displayNodes]);

  useEffect(() => {
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const updatePreference = () => setReducedMotion(query.matches);
    const updateVisibility = () => setDocumentVisible(document.visibilityState !== "hidden");
    updatePreference();
    updateVisibility();
    query.addEventListener("change", updatePreference);
    document.addEventListener("visibilitychange", updateVisibility);
    return () => {
      query.removeEventListener("change", updatePreference);
      document.removeEventListener("visibilitychange", updateVisibility);
    };
  }, []);

  useEffect(() => {
    lastInteractionAt.current = performance.now();
  }, []);

  useEffect(() => {
    signalStartedAt.current = selectedId ? performance.now() : 0;
  }, [selectedId]);

  useEffect(() => {
    if (!host.current) return;
    const observer = new ResizeObserver(([entry]) => {
      if (!entry) return;
      setSize({ width: Math.max(320, Math.floor(entry.contentRect.width)), height: Math.max(420, Math.floor(entry.contentRect.height)) });
    });
    observer.observe(host.current);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const element = canvas.current;
    if (!element) return;
    const zoom = (event: globalThis.WheelEvent) => {
      event.preventDefault();
      lastInteractionAt.current = performance.now();
      setCamera((value) => ({
        ...value,
        zoom: Math.max(0.45, Math.min(2.8, value.zoom * (event.deltaY > 0 ? 0.9 : 1.1))),
      }));
    };
    element.addEventListener("wheel", zoom, { passive: false });
    return () => element.removeEventListener("wheel", zoom);
  }, []);

  useEffect(() => () => {
    layoutWorker.current?.terminate();
    layoutWorker.current = undefined;
  }, []);

  useEffect(() => {
    const current = webGLRenderer.current;
    if (current && (rendererMode !== "webgl2" || current.canvas !== canvas.current)) {
      current.dispose();
      webGLRenderer.current = undefined;
    }
  }, [rendererMode]);

  useEffect(() => () => {
    webGLRenderer.current?.dispose();
    webGLRenderer.current = undefined;
  }, []);

  useEffect(() => {
    const requestId = ++layoutRequest.current;
    setLayoutPending(true);
    const withPinned = (layout: GraphPoint[]) => layout.map((point) => {
      const pinned = pinnedPositions[point.id];
      return constrainGraphPointToBrainRegion(
        pinned ? { ...point, x: pinned.x, y: pinned.y } : point,
        size.width,
        size.height,
      );
    });
    if (typeof Worker === "undefined") {
      const initial = layoutGraph(displayNodes, size.width, size.height);
      const layout = physics ? relaxGraphLayout(initial, displayEdges, size.width, size.height) : initial;
      setPoints(withPinned(compact ? compactGraphLayout(layout, size.width, size.height) : layout));
      setLayoutPending(false);
      return;
    }
    const workerStart = window.setTimeout(() => {
      if (requestId !== layoutRequest.current) return;
      const worker = layoutWorker.current
        ?? new Worker(new URL("../../workers/memoryGraphLayout.worker.ts", import.meta.url), { type: "module" });
      layoutWorker.current = worker;
      worker.onmessage = (event: MessageEvent<{ requestId: number; points: GraphPoint[] }>) => {
        if (event.data.requestId !== requestId || requestId !== layoutRequest.current) return;
        setPoints(withPinned(event.data.points));
        setLayoutPending(false);
      };
      worker.onerror = (event) => {
        event.preventDefault();
        if (requestId !== layoutRequest.current) return;
        const initial = layoutGraph(displayNodes, size.width, size.height);
        const layout = physics ? relaxGraphLayout(initial, displayEdges, size.width, size.height) : initial;
        setPoints(withPinned(compact ? compactGraphLayout(layout, size.width, size.height) : layout));
        setLayoutPending(false);
        worker.terminate();
        if (layoutWorker.current === worker) layoutWorker.current = undefined;
      };
      worker.postMessage({ requestId, nodes: displayNodes, edges: displayEdges, width: size.width, height: size.height, compact, physics });
    }, 0);
    return () => window.clearTimeout(workerStart);
  }, [compact, displayEdges, displayNodes, physics, pinnedPositions, size.height, size.width]);

  useEffect(() => {
    const element = canvas.current;
    const overlay = labelCanvas.current;
    if (!element || !overlay) return;
    const ratio = Math.min(2, window.devicePixelRatio || 1);
    const theme = canvasTheme(element);
    const atlasTheme = webGLTheme(element, theme);
    let frame = 0;
    let lastFrameAt = performance.now();
    let lastPaintAt = 0;
    let lastLabelPaintAt = Number.NEGATIVE_INFINITY;
    let renderer = webGLRenderer.current;

    if (rendererMode === "webgl2") {
      try {
        if (!renderer || renderer.canvas !== element) {
          renderer?.dispose();
          renderer = new BrainAtlasWebGLRenderer(element, () => {
            setRendererNotice("The GPU context was lost. Ti-Scale switched to the equivalent Canvas 2D renderer without changing graph data.");
            setRendererMode("canvas2d");
          });
          webGLRenderer.current = renderer;
        }
        setRendererNotice("");
      } catch {
        webGLRenderer.current = undefined;
        setRendererNotice("WebGL 2 is unavailable. Ti-Scale is using the equivalent Canvas 2D renderer.");
        setRendererMode("canvas2d");
        return;
      }
    } else {
      const pixelWidth = Math.max(1, Math.floor(size.width * ratio));
      const pixelHeight = Math.max(1, Math.floor(size.height * ratio));
      if (element.width !== pixelWidth) element.width = pixelWidth;
      if (element.height !== pixelHeight) element.height = pixelHeight;
    }

    const drawCanvasFallback = (now: number, rotationY: number): Map<string, BrainAtlasProjectedNode> => {
      const context = element.getContext("2d");
      if (!context) return new Map();
      const projection = brainAtlasProjection(size.width, size.height, camera.zoom, { x: camera.rotationX, y: rotationY });
      const projectedMap = new Map<string, BrainAtlasProjectedNode>();
      const modelMap = new Map<string, ReturnType<typeof graphPointToBrainAtlasPosition>>();
      const graphPointMap = new Map(points.map((point) => [point.id, point]));
      for (const point of points) {
        const node = nodeMap.get(point.id);
        if (!node) continue;
        const region = brainAtlasRegionForNode(node);
        if (!visibleRegions.has(region)) continue;
        const model = graphPointToBrainAtlasPosition(point, node, size.width, size.height);
        const projected = projectBrainAtlasPoint(projection, model);
        modelMap.set(point.id, model);
        projectedMap.set(point.id, { ...projected, id: point.id, region, radius: point.radius * projected.scale });
      }

      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      context.clearRect(0, 0, size.width, size.height);
      context.fillStyle = theme.canvas;
      context.fillRect(0, 0, size.width, size.height);

      // Canvas2D is a complete local fallback over the same particle cloud,
      // six-region mapping, projection, canonical nodes, and real edges. No
      // decorative anatomy, image, silhouette, or inferred relationship is
      // painted behind the data.
      for (const cloudPoint of BRAIN_ATLAS_CLOUD) {
        if (!visibleRegions.has(cloudPoint.region)) continue;
        const projected = projectBrainAtlasPoint(projection, cloudPoint);
        if (!projected.visible) continue;
        const cloudColor = atlasTheme.cloud[cloudPoint.region];
        const twinkle = motionEnabled ? 0.78 + Math.sin(now / 1_000 * cloudPoint.twinkleFrequency + cloudPoint.twinklePhase) * 0.18 : 0.84;
        context.beginPath();
        const pointSize = cloudPoint.region === "stem" ? 1.45 : cloudPoint.region === "cerebellum" ? 1.2 : 1.08;
        const alpha = BRAIN_AMBIENT_PARTICLE_ALPHA[cloudPoint.region];
        context.arc(projected.x, projected.y, Math.max(0.72, projected.scale * pointSize), 0, Math.PI * 2);
        context.fillStyle = `rgba(${Math.round(cloudColor[0] * 255)},${Math.round(cloudColor[1] * 255)},${Math.round(cloudColor[2] * 255)},${Math.max(0.06, cloudColor[3] * alpha * twinkle)})`;
        context.fill();
      }

      displayEdges.forEach((edge) => {
        const source = projectedMap.get(edge.sourceNodeId);
        const target = projectedMap.get(edge.targetNodeId);
        if (!source || !target) return;
        const key = [edge.sourceNodeId, edge.targetNodeId].sort().join("|");
        const inPath = pathEdges.has(key);
        const connected = related.has(edge.sourceNodeId) && related.has(edge.targetNodeId);
        const kind = edgeKinds.get(edge.id) ?? "knowledge";
        applyEdgePattern(context, kind, camera.zoom);
        context.beginPath();
        context.moveTo(source.x, source.y);
        context.lineTo(target.x, target.y);
        context.lineWidth = inPath ? 2.5 : connected ? 1.5 : 0.8;
        context.strokeStyle = inPath ? signalStroke(kind, theme) : connected ? theme.edgeConnected : theme.edge;
        context.globalAlpha = inPath || connected ? 0.98 : selectedId ? 0.09 : 0.38;
        context.stroke();

        // Two short wings terminate at target, preserving the source → target
        // direction carried by each canonical MemoryEdge record.
        const angle = Math.atan2(target.y - source.y, target.x - source.x);
        const arrowLength = Math.max(5, 8 / camera.zoom);
        context.beginPath();
        context.moveTo(target.x, target.y);
        context.lineTo(target.x - Math.cos(angle - 0.48) * arrowLength, target.y - Math.sin(angle - 0.48) * arrowLength);
        context.moveTo(target.x, target.y);
        context.lineTo(target.x - Math.cos(angle + 0.48) * arrowLength, target.y - Math.sin(angle + 0.48) * arrowLength);
        context.stroke();
        context.globalAlpha = 1;
        context.setLineDash([]);
      });

      if (motionEnabled) {
        for (const route of ambientSignalRoutes) {
          const source = projectedMap.get(route.fromNodeId);
          const target = projectedMap.get(route.toNodeId);
          if (!source || !target) continue;
          const progress = ((now / route.durationMs) + route.phaseOffset) % 1;
          const eased = progress * progress * (3 - 2 * progress);
          drawSignalGlyph(context, source.x + (target.x - source.x) * eased, source.y + (target.y - source.y) * eased, route.kind, signalStroke(route.kind, theme), camera.zoom, selectedId ? 0.22 : 0.42, 0.62);
        }
      }

      const signalStillTravelling = motionEnabled && signalStartedAt.current > 0
        && now - signalStartedAt.current <= SIGNAL_TRAVEL_MS + SIGNAL_SECOND_WAVE_DELAY_MS + SIGNAL_HOP_DELAY_MS * 5;
      if (signalStillTravelling) {
        const elapsedSinceSelection = now - signalStartedAt.current;
        for (const route of signalRoutes) {
          const source = projectedMap.get(route.fromNodeId);
          const target = projectedMap.get(route.toNodeId);
          if (!source || !target) continue;
          const progress = (elapsedSinceSelection - route.hop * SIGNAL_HOP_DELAY_MS) / SIGNAL_TRAVEL_MS;
          if (progress < 0 || progress > 1) continue;
          const eased = progress * progress * (3 - 2 * progress);
          drawSignalGlyph(context, source.x + (target.x - source.x) * eased, source.y + (target.y - source.y) * eased, route.kind, signalStroke(route.kind, theme), camera.zoom);
        }
      }

      for (const [id, projected] of projectedMap) {
        const node = nodeMap.get(id);
        const point = graphPointMap.get(id);
        if (!node || !point || !projected.visible) continue;
        const displayPoint: ProjectedGraphPoint = { ...point, x: projected.x, y: projected.y, scale: projected.scale };
        const selected = id === selectedId;
        const isHovered = id === hovered;
        const dimmed = Boolean(selectedId && !illuminatedNodeIds.has(id));
        const radius = brainNodeVisualRadius(point.radius, projected.scale) * (isHovered ? 1.12 : 1);
        context.globalAlpha = dimmed ? 0.16 : 0.95;
        context.beginPath();
        context.arc(displayPoint.x, displayPoint.y, radius, 0, Math.PI * 2);
        context.fillStyle = theme.node;
        context.fill();
        context.strokeStyle = selected ? theme.selection : node.lifecycleStatus === "disputed" ? theme.danger : theme.nodeBorder;
        context.lineWidth = selected ? 2.5 : node.lifecycleStatus === "disputed" ? 2 : 1;
        context.stroke();
        if (selected) {
          context.beginPath();
          context.arc(projected.x, projected.y, radius + 6, 0, Math.PI * 2);
          context.setLineDash([2, 3]);
          context.strokeStyle = theme.signal;
          context.stroke();
          context.setLineDash([]);
        } else if (isHovered) {
          context.beginPath();
          context.arc(projected.x, projected.y, radius + 4, 0, Math.PI * 2);
          context.strokeStyle = theme.nodeBorder;
          context.lineWidth = 1.5;
          context.stroke();
        }
        context.globalAlpha = 1;
      }
      return projectedMap;
    };

    const draw = (now: number) => {
      const elapsed = Math.min(100, Math.max(0, now - lastFrameAt));
      lastFrameAt = now;
      const idle = now - lastInteractionAt.current >= IDLE_DELAY_MS && !rotationDrag.current && !nodeDrag.current;
      if (motionEnabled && idle) orbitPhase.current = (orbitPhase.current + elapsed / BRAIN_ORBIT_PERIOD_MS * Math.PI * 2) % (Math.PI * 2);
      const signalStillTravelling = motionEnabled && signalStartedAt.current > 0
        && now - signalStartedAt.current <= SIGNAL_TRAVEL_MS + SIGNAL_SECOND_WAVE_DELAY_MS + SIGNAL_HOP_DELAY_MS * 5;
      if (lastPaintAt > 0 && now - lastPaintAt < MAX_FRAME_RATE_MS && (motionEnabled || signalStillTravelling)) {
        frame = window.requestAnimationFrame(draw);
        return;
      }
      lastPaintAt = now;
      // Bounded yaw keeps the bilateral silhouette readable instead of
      // presenting a side-on brain a few seconds after page load.
      const rotationY = camera.rotationY + (motionEnabled ? Math.sin(orbitPhase.current) * BRAIN_IDLE_YAW_AMPLITUDE : 0);
      let renderedMap: ReadonlyMap<string, BrainAtlasProjectedNode>;
      if (renderer) {
        const result = renderer.render({
          width: size.width,
          height: size.height,
          pixelRatio: ratio,
          // Reduced motion is a genuinely static rendering contract. Passing
          // the first frame's wall-clock time still changed particle
          // brightness between otherwise identical loads because the WebGL
          // shader uses time for its twinkle phase.
          time: motionEnabled ? now : 0,
          rotation: { x: camera.rotationX, y: rotationY },
          zoom: camera.zoom,
          points,
          nodes: displayNodes,
          edges: displayEdges,
          edgeKinds,
          relatedNodeIds: related,
          selectedId,
          hoveredId: hovered,
          illuminatedNodeIds,
          selectedPathEdges: pathEdges,
          selectedSignalRoutes: motionEnabled ? signalRoutes : [],
          ambientSignalRoutes: motionEnabled ? ambientSignalRoutes : [],
          selectedSignalStartedAt: signalStartedAt.current,
          visibleRegions,
          theme: atlasTheme,
        });
        renderedMap = result.projectedNodes;
      } else {
        renderedMap = drawCanvasFallback(now, rotationY);
      }
      renderedPointMap.current = new Map(renderedMap);
      const labelRefreshDue = !Number.isFinite(lastLabelPaintAt)
        || !motionEnabled
        || Boolean(rotationDrag.current || nodeDrag.current)
        || now - lastLabelPaintAt >= PASSIVE_LABEL_REFRESH_MS;
      if (labelRefreshDue) {
        drawBrainAtlasLabels({
          element: overlay,
          width: size.width,
          height: size.height,
          ratio,
          projected: renderedMap,
          nodeMap,
          selectedId,
          hoveredId: hovered,
          labelDensity,
          balancedLabelIds,
          illuminatedNodeIds,
          zoom: camera.zoom,
          theme,
          showLabels,
        });
        lastLabelPaintAt = now;
      }

      if (motionEnabled || signalStillTravelling) frame = window.requestAnimationFrame(draw);
    };

    frame = window.requestAnimationFrame(draw);
    return () => {
      window.cancelAnimationFrame(frame);
    };
  }, [ambientSignalRoutes, balancedLabelIds, camera, displayEdges, displayNodes, edgeKinds, hovered, illuminatedNodeIds, labelDensity, motionEnabled, nodeMap, pathEdges, points, related, rendererMode, selectedId, showLabels, signalRoutes, size, visibleRegions]);

  const noteInteraction = () => { lastInteractionAt.current = performance.now(); };
  const selectNode = (nodeId?: string) => {
    noteInteraction();
    if (nodeId?.startsWith("cluster:")) {
      onExpandCluster?.(nodeId.slice("cluster:".length) as GraphCluster);
      return;
    }
    signalStartedAt.current = nodeId ? performance.now() : 0;
    onSelect(nodeId);
  };

  const screenToCanvas = (clientX: number, clientY: number) => {
    const rect = canvas.current!.getBoundingClientRect();
    return {
      x: (clientX - rect.left) * (size.width / Math.max(1, rect.width)),
      y: (clientY - rect.top) * (size.height / Math.max(1, rect.height)),
    };
  };
  const hit = (clientX: number, clientY: number): string | undefined => {
    const cursor = screenToCanvas(clientX, clientY);
    const stableAggregate = stableCollapsedClusterHit(points.map((point) => {
      const node = nodeMap.get(point.id);
      const visible = Boolean(node && visibleRegions.has(brainAtlasRegionForNode(node)));
      return {
        id: point.id,
        x: point.x,
        y: point.y,
        radius: point.radius,
        depth: point.depth,
        visible,
      };
    }), cursor);
    if (stableAggregate) return stableAggregate;
    return nearestBrainNodeHit([...renderedPointMap.current.values()].map((point) => ({
      id: point.id,
      x: point.x,
      y: point.y,
      radius: "region" in point ? point.radius : point.radius * point.scale,
      depth: point.depth,
      visible: "visible" in point ? point.visible : true,
    })), cursor);
  };
  const handlePointerDown = (event: PointerEvent<HTMLCanvasElement>) => {
    noteInteraction();
    event.currentTarget.setPointerCapture(event.pointerId);
    const nodeId = hit(event.clientX, event.clientY);
    if (nodeId) {
      if (nodeId.startsWith("cluster:")) {
        selectNode(nodeId);
        return;
      }
      const canonical = pointMap.get(nodeId)!;
      const cursor = screenToCanvas(event.clientX, event.clientY);
      nodeDrag.current = {
        id: nodeId,
        startX: cursor.x,
        startY: cursor.y,
        originX: canonical.x,
        originY: canonical.y,
        x: canonical.x,
        y: canonical.y,
        moved: false,
      };
      selectNode(nodeId);
      return;
    }
    const cursor = screenToCanvas(event.clientX, event.clientY);
    rotationDrag.current = { x: cursor.x, y: cursor.y, rotationX: camera.rotationX, rotationY: camera.rotationY, moved: false };
  };
  const handlePointerMove = (event: PointerEvent<HTMLCanvasElement>) => {
    const movingNode = nodeDrag.current;
    if (movingNode) {
      noteInteraction();
      const cursor = screenToCanvas(event.clientX, event.clientY);
      const point = pointMap.get(movingNode.id);
      if (!point) return;
      const bounded = constrainGraphPointToBrainRegion({
        ...point,
        x: movingNode.originX + (cursor.x - movingNode.startX) / Math.max(0.45, camera.zoom),
        y: movingNode.originY + (cursor.y - movingNode.startY) / Math.max(0.45, camera.zoom),
      }, size.width, size.height);
      if (Math.hypot(bounded.x - movingNode.x, bounded.y - movingNode.y) > 1) movingNode.moved = true;
      movingNode.x = bounded.x;
      movingNode.y = bounded.y;
      setPoints((current) => current.map((item) => item.id === movingNode.id ? bounded : item));
      return;
    }
    const current = rotationDrag.current;
    if (current) {
      noteInteraction();
      const cursor = screenToCanvas(event.clientX, event.clientY);
      const dx = cursor.x - current.x;
      const dy = cursor.y - current.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) current.moved = true;
      setCamera((value) => ({
        ...value,
        rotationX: Math.max(-1.15, Math.min(1.15, current.rotationX + dy * 0.006)),
        rotationY: current.rotationY + dx * 0.008,
      }));
    } else setHovered(hit(event.clientX, event.clientY));
  };
  const handlePointerUp = (event: PointerEvent<HTMLCanvasElement>) => {
    noteInteraction();
    if (nodeDrag.current) {
      const moving = nodeDrag.current;
      if (moving.moved) onPinPosition?.(moving.id, { x: moving.x, y: moving.y });
      nodeDrag.current = undefined;
      return;
    }
    if (!rotationDrag.current?.moved) selectNode(hit(event.clientX, event.clientY));
    rotationDrag.current = undefined;
  };
  const handleKeyDown = (event: KeyboardEvent<HTMLCanvasElement>) => {
    noteInteraction();
    if (event.key === "Escape") { selectNode(undefined); return; }
    if (!["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp", "Enter"].includes(event.key) || displayNodes.length === 0) return;
    event.preventDefault();
    if (event.key === "Enter" && selectedId) return;
    const current = displayNodes.findIndex((node) => node.id === selectedId);
    const delta = event.key === "ArrowLeft" || event.key === "ArrowUp" ? -1 : 1;
    selectNode(displayNodes[(current + delta + displayNodes.length) % displayNodes.length]!.id);
  };
  const toggleRegion = (region: BrainAtlasRegion) => {
    noteInteraction();
    setVisibleRegions((current) => {
      const next = new Set(current);
      if (next.has(region)) next.delete(region);
      else next.add(region);
      return next;
    });
  };
  const setAllRegions = (visible: boolean) => {
    noteInteraction();
    setVisibleRegions(visible ? new Set(BRAIN_ATLAS_REGIONS) : new Set());
  };

  return (
    <div
      ref={host}
      className="brain-canvas-host"
      data-brain-anatomy="particle-cloud-3d"
      data-region-taxonomy="attack-knowledge"
      data-background-grid="removed"
      data-background-artwork="removed"
      data-anatomy-silhouette="removed"
      data-spinal-silhouette="removed"
      data-visual-theme="dark-titanium"
      data-node-language="unified-titanium-dots"
      data-node-visual-scale={BRAIN_NODE_VISUAL_SCALE}
      data-node-hit-target-diameter-px={BRAIN_NODE_HIT_RADIUS_PX * 2}
      data-ambient-particle-contrast="bright-titanium"
      data-category-color-legend="removed"
      data-renderer={rendererMode}
      data-motion={motionMode}
      data-motion-character="anatomical-orbit"
      data-auto-rotate={motionEnabled ? "enabled" : "disabled"}
      data-camera-rotation-x={camera.rotationX.toFixed(3)}
      data-camera-rotation-y={camera.rotationY.toFixed(3)}
      data-visible-regions={BRAIN_ATLAS_REGIONS.filter((region) => visibleRegions.has(region)).join(",")}
      data-region-counts={BRAIN_ATLAS_REGIONS.map((region) => `${region}:${regionCounts[region]}`).join(",")}
      data-orbit-period-ms={BRAIN_ORBIT_PERIOD_MS}
      data-idle-yaw-amplitude={BRAIN_IDLE_YAW_AMPLITUDE}
      data-ambient-signal-count={ambientSignalRoutes.length}
      data-neuron-signal-count={signalRoutes.length}
      data-hazard-signal-count={signalKindCounts.hazard}
      data-recovery-signal-count={signalKindCounts.recovery}
      data-selected-path-edges={pathEdges.size}
      data-label-collision-policy="selected-hovered-priority"
      data-baseline-edge-detail="restrained-visible"
      data-edge-direction="source-to-target-arrowheads"
    >
      <canvas
        key={rendererMode}
        ref={canvas}
        tabIndex={0}
        role="application"
        aria-busy={layoutPending}
        aria-describedby="brain-atlas-renderer-status"
        aria-label={`Memory graph with ${displayNodes.length} nodes and ${displayEdges.length} typed, directed relationships in a six-region three-dimensional attack-knowledge particle cloud. Use arrow keys to select nodes, Escape to clear, mouse wheel to zoom, drag empty space to rotate, and drag a node to persist its position. Selecting a collapsed cluster expands it.`}
        onKeyDown={handleKeyDown}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerLeave={() => {
          noteInteraction();
          rotationDrag.current = undefined;
          nodeDrag.current = undefined;
          setHovered(undefined);
        }}
      />
      <canvas ref={labelCanvas} className="brain-atlas-label-canvas" aria-hidden="true" />
      <div className="brain-atlas-tool-rail" aria-label="Brain region controls">
        <span className="brain-atlas-tool-rail__title" aria-hidden="true">Regions</span>
        {BRAIN_ATLAS_REGIONS.map((region) => {
          const definition = BRAIN_ATLAS_REGION_DEFINITIONS[region];
          return (
            <button
              key={region}
              type="button"
              aria-label={`Toggle ${definition.label} region`}
              aria-pressed={visibleRegions.has(region)}
              title={`${definition.label}: ${definition.semantic} (${regionCounts[region]} nodes)`}
              onClick={() => toggleRegion(region)}
            >
              <span>{definition.code}</span>
              <small>{regionCounts[region]}</small>
            </button>
          );
        })}
        <button type="button" aria-label="Toggle graph labels" aria-pressed={showLabels} onClick={() => { noteInteraction(); setShowLabels((value) => !value); }}>Labels</button>
        <button type="button" aria-label="Show all brain regions" onClick={() => setAllRegions(true)}>All</button>
        <button type="button" aria-label="Hide all brain regions" onClick={() => setAllRegions(false)}>None</button>
      </div>
      <div className="brain-canvas-controls" aria-label="Graph viewport controls">
        <button onClick={() => { noteInteraction(); setCamera((value) => ({ ...value, zoom: Math.min(2.8, value.zoom * 1.2) })); }} aria-label="Zoom in">+</button>
        <button onClick={() => { noteInteraction(); setCamera((value) => ({ ...value, zoom: Math.max(0.45, value.zoom / 1.2) })); }} aria-label="Zoom out">−</button>
        <button onClick={() => { noteInteraction(); orbitPhase.current = 0; setCamera({ ...DEFAULT_CAMERA }); }}>Fit</button>
        {onClearPinnedPositions && <button onClick={() => { noteInteraction(); onClearPinnedPositions(nodes.map((node) => node.id)); }}>Reset layout</button>}
      </div>
      <div className="brain-signal-legend" aria-label="Graph relationship signal legend">
        <span data-signal-kind="knowledge"><i aria-hidden="true" />Knowledge path</span>
        <span data-signal-kind="hazard"><i aria-hidden="true" />Failure or hazard</span>
        <span data-signal-kind="recovery"><i aria-hidden="true" />Recovery path</span>
      </div>
      <p id="brain-atlas-renderer-status" className={`brain-renderer-state${rendererMode === "canvas2d" ? " is-fallback" : ""}`} role="status" aria-live="polite">
        {rendererNotice || (rendererMode === "webgl2" ? "WebGL 2 particle renderer active" : "Canvas 2D particle renderer active")}
      </p>
      <p className="os-visually-hidden" role="status" aria-live="polite">Graph viewport zoom {graphZoomPercent(camera.zoom)} percent</p>
      <p className="os-visually-hidden" aria-live="polite">{BRAIN_ATLAS_REGIONS.map((region) => `${BRAIN_ATLAS_REGION_DEFINITIONS[region].label} ${visibleRegions.has(region) ? "visible" : "hidden"}, ${regionCounts[region]} nodes`).join(". ")}</p>
      <p className="os-visually-hidden">{ambientSignalRoutes.length} ambient visual pulses trace real stored relationships. They do not represent live runtime activity.</p>
      <p className="os-visually-hidden" aria-live="polite">{selectedId ? `Selected ${displayNodes.find((node) => node.id === selectedId)?.title ?? selectedId}. ${signalRoutes.length} evidence-backed relationship paths illuminated.` : "No graph node selected"}</p>
      <p className="os-visually-hidden" aria-live="polite">{pathStartNodeId && selectedId ? path.length > 0 ? `Shortest memory path contains ${path.length} nodes` : "No path connects the selected memories in this bounded view" : "No arbitrary memory path selected"}</p>
      <p className="os-visually-hidden" role="status" aria-live="polite">{layoutPending ? "Calculating attack-knowledge brain layout" : "Attack-knowledge brain layout ready"}</p>
    </div>
  );
}

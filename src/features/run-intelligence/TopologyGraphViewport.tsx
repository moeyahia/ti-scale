import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent,
  type WheelEvent,
} from "react";
import type {
  TopologyEdge,
  TopologyNode,
} from "../../domain/types/runIntelligence";
import { Button } from "../../design-system/components/Primitives";
import {
  hitTestTopologyGraph,
  type TopologyGraphModel,
} from "./topologyGraphModel";
import "./topology-graph.css";

interface ViewportSize {
  readonly width: number;
  readonly height: number;
}

interface Camera {
  readonly zoom: number;
  readonly panX: number;
  readonly panY: number;
}

interface PointerGesture {
  readonly pointerId: number;
  readonly startX: number;
  readonly startY: number;
  readonly initialPanX: number;
  readonly initialPanY: number;
  moved: boolean;
}

const DEFAULT_SIZE: ViewportSize = Object.freeze({ width: 960, height: 520 });
const DEFAULT_CAMERA: Camera = Object.freeze({ zoom: 1, panX: 0, panY: 0 });
const MIN_ZOOM = 0.25;
const MAX_ZOOM = 2.5;
const ZOOM_STEP = 1.18;

function boundedZoom(value: number): number {
  return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, value));
}

function nodeShape(node: TopologyNode): "circle" | "diamond" | "rectangle" | "hexagon" {
  if (node.nodeType === "identity") return "diamond";
  if (["asset", "host", "cloud_asset", "container", "cluster"].includes(node.nodeType)) return "rectangle";
  if (["network", "network_zone", "subnet", "route"].includes(node.nodeType)) return "hexagon";
  return "circle";
}

function nodeFill(node: TopologyNode, styles: CSSStyleDeclaration): string {
  if (node.scopeStatus === "out_of_scope" || node.scopeStatus === "prohibited") {
    return styles.getPropertyValue("--os-danger-soft").trim() || "#f4d9de";
  }
  if (node.lifecycleState === "blocked" || node.lifecycleState === "unreachable") {
    return styles.getPropertyValue("--os-warning-soft").trim() || "#f2e4ca";
  }
  if (node.lifecycleState === "validated") {
    return styles.getPropertyValue("--os-success-soft").trim() || "#dce9e4";
  }
  return styles.getPropertyValue("--os-surface-1").trim() || "#f8f7f3";
}

function drawNodeShape(
  context: CanvasRenderingContext2D,
  shape: ReturnType<typeof nodeShape>,
  x: number,
  y: number,
  radius: number,
): void {
  context.beginPath();
  if (shape === "rectangle") {
    context.roundRect(x - radius * 1.35, y - radius, radius * 2.7, radius * 2, Math.max(2, radius * 0.3));
    return;
  }
  if (shape === "diamond") {
    context.moveTo(x, y - radius * 1.25);
    context.lineTo(x + radius * 1.25, y);
    context.lineTo(x, y + radius * 1.25);
    context.lineTo(x - radius * 1.25, y);
    context.closePath();
    return;
  }
  if (shape === "hexagon") {
    for (let index = 0; index < 6; index += 1) {
      const angle = (Math.PI / 3) * index;
      const pointX = x + Math.cos(angle) * radius * 1.25;
      const pointY = y + Math.sin(angle) * radius;
      if (index === 0) context.moveTo(pointX, pointY);
      else context.lineTo(pointX, pointY);
    }
    context.closePath();
    return;
  }
  context.arc(x, y, radius, 0, Math.PI * 2);
}

function drawArrow(
  context: CanvasRenderingContext2D,
  sourceX: number,
  sourceY: number,
  targetX: number,
  targetY: number,
  radius: number,
): void {
  const angle = Math.atan2(targetY - sourceY, targetX - sourceX);
  const arrowX = targetX - Math.cos(angle) * radius * 1.45;
  const arrowY = targetY - Math.sin(angle) * radius * 1.45;
  const size = Math.max(4, radius * 0.45);
  context.beginPath();
  context.moveTo(arrowX, arrowY);
  context.lineTo(
    arrowX - Math.cos(angle - Math.PI / 6) * size,
    arrowY - Math.sin(angle - Math.PI / 6) * size,
  );
  context.lineTo(
    arrowX - Math.cos(angle + Math.PI / 6) * size,
    arrowY - Math.sin(angle + Math.PI / 6) * size,
  );
  context.closePath();
  context.fill();
}

function edgeLabel(edge: TopologyEdge): string {
  return edge.edgeType.replaceAll("_", " ");
}

function truncateLabel(label: string): string {
  return label.length > 28 ? `${label.slice(0, 27)}…` : label;
}

function drawTopology({
  canvas,
  model,
  camera,
  selectedNodeId,
}: {
  readonly canvas: HTMLCanvasElement;
  readonly model: TopologyGraphModel;
  readonly camera: Camera;
  readonly selectedNodeId?: string;
}): void {
  const width = Math.max(1, canvas.clientWidth);
  const height = Math.max(1, canvas.clientHeight);
  const ratio = Math.min(2, window.devicePixelRatio || 1);
  const pixelWidth = Math.max(1, Math.round(width * ratio));
  const pixelHeight = Math.max(1, Math.round(height * ratio));
  if (canvas.width !== pixelWidth) canvas.width = pixelWidth;
  if (canvas.height !== pixelHeight) canvas.height = pixelHeight;
  const context = canvas.getContext("2d");
  if (!context) return;
  const styles = getComputedStyle(canvas);
  const text = styles.getPropertyValue("--os-text").trim() || "#1d2228";
  const muted = styles.getPropertyValue("--os-text-muted").trim() || "#697078";
  const line = styles.getPropertyValue("--os-line-strong").trim() || "#9aa1a8";
  const accent = styles.getPropertyValue("--os-accent").trim() || "#46515d";
  const canvasColor = styles.getPropertyValue("--os-canvas").trim() || "#f8f7f3";

  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  context.fillStyle = canvasColor;
  context.fillRect(0, 0, width, height);
  context.save();
  context.translate(camera.panX, camera.panY);
  context.scale(camera.zoom, camera.zoom);

  context.strokeStyle = line;
  context.fillStyle = line;
  context.lineWidth = 1 / camera.zoom;
  for (const edge of model.edges) {
    const source = model.pointByNodeId.get(edge.sourceNodeId);
    const target = model.pointByNodeId.get(edge.targetNodeId);
    if (!source || !target) continue;
    const selected = selectedNodeId === edge.sourceNodeId || selectedNodeId === edge.targetNodeId;
    context.globalAlpha = selected ? 0.92 : 0.48;
    context.strokeStyle = selected ? accent : line;
    context.fillStyle = selected ? accent : line;
    context.lineWidth = (selected ? 2 : 1) / camera.zoom;
    context.beginPath();
    context.moveTo(source.x, source.y);
    context.lineTo(target.x, target.y);
    context.stroke();
    drawArrow(context, source.x, source.y, target.x, target.y, target.radius);
    if (camera.zoom >= 0.9) {
      const label = edgeLabel(edge);
      context.save();
      context.globalAlpha = selected ? 0.9 : 0.66;
      context.fillStyle = muted;
      context.font = `${10 / camera.zoom}px ui-monospace, SFMono-Regular, Menlo, monospace`;
      context.textAlign = "center";
      context.fillText(label, (source.x + target.x) / 2, (source.y + target.y) / 2 - 7 / camera.zoom);
      context.restore();
    }
  }

  const nodeById = new Map(model.nodes.map((node) => [node.id, node]));
  for (const point of model.points) {
    const node = nodeById.get(point.id);
    if (!node) continue;
    const selected = selectedNodeId === node.id;
    context.globalAlpha = selectedNodeId && !selected ? 0.62 : 1;
    context.fillStyle = nodeFill(node, styles);
    context.strokeStyle = selected ? accent : line;
    context.lineWidth = (selected ? 3 : 1.25) / camera.zoom;
    drawNodeShape(context, nodeShape(node), point.x, point.y, point.radius);
    context.fill();
    context.stroke();
    if (selected) {
      context.save();
      context.strokeStyle = accent;
      context.globalAlpha = 0.32;
      context.lineWidth = 5 / camera.zoom;
      context.beginPath();
      context.arc(point.x, point.y, point.radius * 1.75, 0, Math.PI * 2);
      context.stroke();
      context.restore();
    }
    if (camera.zoom >= 0.68 || selected) {
      context.fillStyle = text;
      context.globalAlpha = selectedNodeId && !selected ? 0.72 : 0.96;
      context.font = `${selected ? 650 : 550} ${11 / camera.zoom}px Inter, system-ui, sans-serif`;
      context.textAlign = "center";
      context.fillText(truncateLabel(node.primaryLabel), point.x, point.y + point.radius + 17 / camera.zoom);
    }
  }
  context.restore();
  context.globalAlpha = 1;
}

function fitCamera(model: TopologyGraphModel, size: ViewportSize): Camera {
  const bounds = model.fitBounds;
  if (!bounds) return DEFAULT_CAMERA;
  const availableWidth = Math.max(1, size.width - 48);
  const availableHeight = Math.max(1, size.height - 48);
  const widthScale = availableWidth / Math.max(1, bounds.width);
  const heightScale = availableHeight / Math.max(1, bounds.height);
  const zoom = boundedZoom(Math.min(widthScale, heightScale));
  return {
    zoom,
    panX: size.width / 2 - (bounds.minX + bounds.width / 2) * zoom,
    panY: size.height / 2 - (bounds.minY + bounds.height / 2) * zoom,
  };
}

function zoomAroundCenter(camera: Camera, nextZoom: number, size: ViewportSize): Camera {
  const centerX = size.width / 2;
  const centerY = size.height / 2;
  const graphX = (centerX - camera.panX) / camera.zoom;
  const graphY = (centerY - camera.panY) / camera.zoom;
  return {
    zoom: nextZoom,
    panX: centerX - graphX * nextZoom,
    panY: centerY - graphY * nextZoom,
  };
}

export function TopologyGraphViewport({
  model,
  selectedNodeId,
  onSelectNode,
  controlNamespace,
}: {
  readonly model: TopologyGraphModel;
  readonly selectedNodeId?: string;
  readonly onSelectNode?: (nodeId: string) => void;
  readonly controlNamespace: string;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const gestureRef = useRef<PointerGesture | undefined>(undefined);
  const [size, setSize] = useState<ViewportSize>(DEFAULT_SIZE);
  const [camera, setCamera] = useState<Camera>(DEFAULT_CAMERA);
  const [keyboardNodeId, setKeyboardNodeId] = useState(selectedNodeId ?? model.nodes[0]?.id);
  const descriptionId = `${controlNamespace}-canvas-instructions`;

  useEffect(() => {
    if (selectedNodeId) setKeyboardNodeId(selectedNodeId);
    else if (keyboardNodeId && !model.pointByNodeId.has(keyboardNodeId)) {
      setKeyboardNodeId(model.nodes[0]?.id);
    }
  }, [keyboardNodeId, model.nodes, model.pointByNodeId, selectedNodeId]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    const measure = () => {
      const bounds = canvas.getBoundingClientRect();
      setSize({
        width: Math.max(320, Math.round(bounds.width || DEFAULT_SIZE.width)),
        height: Math.max(320, Math.round(bounds.height || DEFAULT_SIZE.height)),
      });
    };
    measure();
    if (typeof ResizeObserver === "undefined") return undefined;
    const observer = new ResizeObserver(measure);
    observer.observe(canvas);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    drawTopology({ canvas, model, camera, selectedNodeId });
  }, [camera, model, selectedNodeId, size]);

  useEffect(() => {
    setCamera(fitCamera(model, size));
  }, [model, size]);

  const applyZoom = useCallback((factor: number) => {
    setCamera((current) => {
      const nextZoom = boundedZoom(current.zoom * factor);
      return zoomAroundCenter(current, nextZoom, size);
    });
  }, [size]);

  const fit = useCallback(() => {
    setCamera(fitCamera(model, size));
  }, [model, size]);

  const pointerCoordinates = (event: PointerEvent<HTMLCanvasElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    return { x: event.clientX - bounds.left, y: event.clientY - bounds.top };
  };

  const onPointerDown = (event: PointerEvent<HTMLCanvasElement>) => {
    const point = pointerCoordinates(event);
    event.currentTarget.setPointerCapture(event.pointerId);
    gestureRef.current = {
      pointerId: event.pointerId,
      startX: point.x,
      startY: point.y,
      initialPanX: camera.panX,
      initialPanY: camera.panY,
      moved: false,
    };
  };

  const onPointerMove = (event: PointerEvent<HTMLCanvasElement>) => {
    const gesture = gestureRef.current;
    if (!gesture || gesture.pointerId !== event.pointerId) return;
    const point = pointerCoordinates(event);
    const deltaX = point.x - gesture.startX;
    const deltaY = point.y - gesture.startY;
    if (Math.abs(deltaX) + Math.abs(deltaY) > 4) gesture.moved = true;
    if (!gesture.moved) return;
    setCamera((current) => ({
      ...current,
      panX: gesture.initialPanX + deltaX,
      panY: gesture.initialPanY + deltaY,
    }));
  };

  const onPointerUp = (event: PointerEvent<HTMLCanvasElement>) => {
    const gesture = gestureRef.current;
    gestureRef.current = undefined;
    if (!gesture || gesture.pointerId !== event.pointerId) return;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    if (gesture.moved) return;
    const point = pointerCoordinates(event);
    const hit = hitTestTopologyGraph(
      model,
      (point.x - camera.panX) / camera.zoom,
      (point.y - camera.panY) / camera.zoom,
      7 / camera.zoom,
    );
    if (!hit) return;
    setKeyboardNodeId(hit.id);
    onSelectNode?.(hit.id);
  };

  const onWheel = (event: WheelEvent<HTMLCanvasElement>) => {
    event.preventDefault();
    applyZoom(event.deltaY < 0 ? ZOOM_STEP : 1 / ZOOM_STEP);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLCanvasElement>) => {
    if (model.nodes.length === 0) return;
    const currentIndex = Math.max(0, model.nodes.findIndex((node) => node.id === keyboardNodeId));
    if (["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp"].includes(event.key)) {
      event.preventDefault();
      const direction = event.key === "ArrowRight" || event.key === "ArrowDown" ? 1 : -1;
      const nextIndex = (currentIndex + direction + model.nodes.length) % model.nodes.length;
      setKeyboardNodeId(model.nodes[nextIndex]?.id);
      return;
    }
    if ((event.key === "Enter" || event.key === " ") && keyboardNodeId) {
      event.preventDefault();
      onSelectNode?.(keyboardNodeId);
    }
    if (event.key === "+" || event.key === "=") {
      event.preventDefault();
      applyZoom(ZOOM_STEP);
    }
    if (event.key === "-") {
      event.preventDefault();
      applyZoom(1 / ZOOM_STEP);
    }
    if (event.key === "0") {
      event.preventDefault();
      fit();
    }
  };

  const unconnectedNodes = useMemo(() => {
    const nodeById = new Map(model.nodes.map((node) => [node.id, node]));
    return model.unconnectedNodeIds.flatMap((id) => {
      const node = nodeById.get(id);
      return node ? [node] : [];
    });
  }, [model.nodes, model.unconnectedNodeIds]);

  return <div className="os-topology-viewport-shell">
    <div className="os-topology-viewport-toolbar" role="group" aria-label="Topology viewport controls">
      <Button
        type="button"
        variant="quiet"
        aria-label="Zoom in"
        data-control-id={`${controlNamespace}-zoom-in`}
        onClick={() => applyZoom(ZOOM_STEP)}
      >Zoom in</Button>
      <Button
        type="button"
        variant="quiet"
        aria-label="Zoom out"
        data-control-id={`${controlNamespace}-zoom-out`}
        onClick={() => applyZoom(1 / ZOOM_STEP)}
      >Zoom out</Button>
      <Button
        type="button"
        variant="quiet"
        aria-label="Fit topology"
        data-control-id={`${controlNamespace}-fit`}
        onClick={fit}
      >Fit</Button>
      <p role="status" aria-label="Topology viewport status">Topology viewport zoom {Math.round(camera.zoom * 100)} percent</p>
    </div>
    <canvas
      ref={canvasRef}
      className="os-topology-canvas"
      role="application"
      aria-label={`Recon topology with ${model.nodes.length} nodes and ${model.edges.length} canonical ${model.edges.length === 1 ? "relationship" : "relationships"}`}
      aria-describedby={descriptionId}
      tabIndex={0}
      data-control-id={`${controlNamespace}-canvas`}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={() => { gestureRef.current = undefined; }}
      onWheel={onWheel}
      onKeyDown={onKeyDown}
    />
    <p id={descriptionId} className="os-visually-hidden">
      Use arrow keys to move between canonical nodes, Enter to inspect, plus and minus to zoom, and zero to fit. Drag to pan or select a node with the pointer.
    </p>
    {keyboardNodeId && <p className="os-topology-keyboard-focus" aria-live="polite">
      Keyboard focus: {model.nodes.find((node) => node.id === keyboardNodeId)?.primaryLabel ?? keyboardNodeId}
    </p>}
    {unconnectedNodes.length > 0 && <section className="os-topology-unconnected" aria-label="Unconnected observed nodes">
      <div><p className="os-eyebrow">Relationship unknown</p><h3>Unconnected observed nodes</h3><p>These records are attributable, but no canonical edge currently connects them. Ti-Scale does not infer one.</p></div>
      <div>{unconnectedNodes.map((node) => <Button
        key={node.id}
        type="button"
        variant="quiet"
        aria-label={`Inspect ${node.primaryLabel}`}
        data-control-id={`${controlNamespace}-unconnected-selection`}
        onClick={() => onSelectNode?.(node.id)}
      >{node.primaryLabel}</Button>)}</div>
    </section>}
  </div>;
}

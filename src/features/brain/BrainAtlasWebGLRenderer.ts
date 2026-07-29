/*
 * Hand-rolled WebGL2 renderer adapted from the zero-dependency, dual-renderer
 * architecture described by Brain Atlas 0.2.1 (MIT). The projection and cloud
 * principles are credited in /THIRD_PARTY_NOTICES.md. Ti-Scale's typed,
 * directed edge geometry and attack-knowledge semantics are preserved here.
 */
import type { MemoryEdgeSummary, MemoryNodeSummary } from "../../domain/types/brain";
import {
  BRAIN_ATLAS_REGIONS,
  brainAtlasProjection,
  brainAtlasRegionForNode,
  buildBrainAtlasCloud,
  graphPointToBrainAtlasPosition,
  projectBrainAtlasPoint,
  type BrainAtlasProjectedPoint,
  type BrainAtlasRegion,
  type BrainAtlasVector3,
} from "./brainAtlasGeometry";
import type { GraphPoint, GraphSignalKind, GraphSignalRoute } from "./graphUtils";
import {
  BRAIN_AMBIENT_PARTICLE_ALPHA,
  brainNodeVisualDiameter,
} from "./brainVisualLanguage";

export type BrainAtlasColor = readonly [number, number, number, number];

export interface BrainAtlasWebGLTheme {
  readonly background: BrainAtlasColor;
  readonly cloud: Readonly<Record<BrainAtlasRegion, BrainAtlasColor>>;
  readonly node: BrainAtlasColor;
  readonly edge: BrainAtlasColor;
  readonly edgeConnected: BrainAtlasColor;
  readonly knowledge: BrainAtlasColor;
  readonly hazard: BrainAtlasColor;
  readonly recovery: BrainAtlasColor;
  readonly selection: BrainAtlasColor;
}

export interface BrainAtlasWebGLFrame {
  readonly width: number;
  readonly height: number;
  readonly pixelRatio: number;
  readonly time: number;
  readonly rotation: Readonly<{ x: number; y: number }>;
  readonly zoom: number;
  readonly points: readonly GraphPoint[];
  readonly nodes: readonly MemoryNodeSummary[];
  readonly edges: readonly MemoryEdgeSummary[];
  readonly edgeKinds: ReadonlyMap<string, GraphSignalKind>;
  readonly relatedNodeIds: ReadonlySet<string>;
  readonly selectedId?: string;
  readonly hoveredId?: string;
  readonly illuminatedNodeIds: ReadonlySet<string>;
  readonly selectedPathEdges: ReadonlySet<string>;
  readonly selectedSignalRoutes: readonly GraphSignalRoute[];
  readonly ambientSignalRoutes: readonly (GraphSignalRoute & { readonly phaseOffset: number; readonly durationMs: number })[];
  readonly selectedSignalStartedAt: number;
  readonly visibleRegions: ReadonlySet<BrainAtlasRegion>;
  readonly theme: BrainAtlasWebGLTheme;
}

export interface BrainAtlasProjectedNode extends BrainAtlasProjectedPoint {
  readonly id: string;
  readonly region: BrainAtlasRegion;
  readonly radius: number;
}

export interface BrainAtlasWebGLResult {
  readonly projectedNodes: ReadonlyMap<string, BrainAtlasProjectedNode>;
  readonly visibleNodeCount: number;
  readonly directedEdgeCount: number;
}

// Geometry is immutable. Building it once avoids allocating roughly 1,650
// objects on every animation frame.
const BRAIN_ATLAS_CLOUD = buildBrainAtlasCloud();

const POINT_VERTEX_SHADER = `#version 300 es
precision highp float;
in vec3 aPosition;
in vec4 aColor;
in float aSize;
in float aTwinklePhase;
in float aTwinkleFrequency;
in float aRole;
uniform vec2 uViewport;
uniform vec2 uRotation;
uniform float uScale;
uniform float uDistance;
uniform float uPixelRatio;
uniform float uTime;
out vec4 vColor;

void main() {
  float cosY = cos(uRotation.y);
  float sinY = sin(uRotation.y);
  float cosX = cos(uRotation.x);
  float sinX = sin(uRotation.x);
  float rotatedX = aPosition.x * cosY + aPosition.z * sinY;
  float firstDepth = -aPosition.x * sinY + aPosition.z * cosY;
  float rotatedY = aPosition.y * cosX - firstDepth * sinX;
  float depth = aPosition.y * sinX + firstDepth * cosX;
  float perspective = uDistance / max(0.25, uDistance + depth);
  vec2 pixel = vec2(
    uViewport.x * 0.5 + rotatedX * uScale * perspective,
    uViewport.y * 0.46 - rotatedY * uScale * perspective
  );
  vec2 clip = vec2(pixel.x / uViewport.x * 2.0 - 1.0, 1.0 - pixel.y / uViewport.y * 2.0);
  gl_Position = vec4(clip, clamp(-depth / 3.0, -0.95, 0.95), 1.0);
  float twinkle = aRole < 0.5 ? 0.88 + sin(uTime * aTwinkleFrequency + aTwinklePhase) * 0.12 : 1.0;
  gl_PointSize = max(1.0, aSize * perspective * uPixelRatio * twinkle);
  vColor = vec4(aColor.rgb, aColor.a * twinkle);
}`;

const POINT_FRAGMENT_SHADER = `#version 300 es
precision highp float;
in vec4 vColor;
uniform float uRing;
out vec4 outColor;

void main() {
  vec2 center = gl_PointCoord * 2.0 - 1.0;
  float distanceFromCenter = length(center);
  if (distanceFromCenter > 1.0) discard;
  float outer = 1.0 - smoothstep(0.82, 1.0, distanceFromCenter);
  float fill = 1.0 - smoothstep(0.68, 1.0, distanceFromCenter);
  float ring = smoothstep(0.54, 0.67, distanceFromCenter) * outer;
  float coverage = mix(fill, ring, uRing);
  outColor = vec4(vColor.rgb, vColor.a * coverage);
}`;

const LINE_VERTEX_SHADER = `#version 300 es
precision highp float;
in vec3 aPosition;
in vec4 aColor;
uniform vec2 uViewport;
uniform vec2 uRotation;
uniform float uScale;
uniform float uDistance;
out vec4 vColor;

void main() {
  float cosY = cos(uRotation.y);
  float sinY = sin(uRotation.y);
  float cosX = cos(uRotation.x);
  float sinX = sin(uRotation.x);
  float rotatedX = aPosition.x * cosY + aPosition.z * sinY;
  float firstDepth = -aPosition.x * sinY + aPosition.z * cosY;
  float rotatedY = aPosition.y * cosX - firstDepth * sinX;
  float depth = aPosition.y * sinX + firstDepth * cosX;
  float perspective = uDistance / max(0.25, uDistance + depth);
  vec2 pixel = vec2(
    uViewport.x * 0.5 + rotatedX * uScale * perspective,
    uViewport.y * 0.46 - rotatedY * uScale * perspective
  );
  vec2 clip = vec2(pixel.x / uViewport.x * 2.0 - 1.0, 1.0 - pixel.y / uViewport.y * 2.0);
  gl_Position = vec4(clip, clamp(-depth / 3.0, -0.95, 0.95), 1.0);
  vColor = aColor;
}`;

const LINE_FRAGMENT_SHADER = `#version 300 es
precision highp float;
in vec4 vColor;
out vec4 outColor;
void main() { outColor = vColor; }
`;

interface ProgramState {
  readonly program: WebGLProgram;
  readonly position: number;
  readonly color: number;
  readonly size?: number;
  readonly twinklePhase?: number;
  readonly twinkleFrequency?: number;
  readonly role?: number;
  readonly viewport: WebGLUniformLocation | null;
  readonly rotation: WebGLUniformLocation | null;
  readonly scale: WebGLUniformLocation | null;
  readonly distance: WebGLUniformLocation | null;
  readonly pixelRatio?: WebGLUniformLocation | null;
  readonly time?: WebGLUniformLocation | null;
  readonly ring?: WebGLUniformLocation | null;
}

function compileShader(gl: WebGL2RenderingContext, type: number, source: string): WebGLShader {
  const shader = gl.createShader(type);
  if (!shader) throw new Error("The GPU did not allocate a shader.");
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    const log = gl.getShaderInfoLog(shader) ?? "Unknown shader compilation failure.";
    gl.deleteShader(shader);
    throw new Error(log);
  }
  return shader;
}

function createProgram(gl: WebGL2RenderingContext, vertex: string, fragment: string): WebGLProgram {
  const vertexShader = compileShader(gl, gl.VERTEX_SHADER, vertex);
  const fragmentShader = compileShader(gl, gl.FRAGMENT_SHADER, fragment);
  const program = gl.createProgram();
  if (!program) throw new Error("The GPU did not allocate a shader program.");
  gl.attachShader(program, vertexShader);
  gl.attachShader(program, fragmentShader);
  gl.linkProgram(program);
  gl.deleteShader(vertexShader);
  gl.deleteShader(fragmentShader);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    const log = gl.getProgramInfoLog(program) ?? "Unknown shader link failure.";
    gl.deleteProgram(program);
    throw new Error(log);
  }
  return program;
}

function pointProgram(gl: WebGL2RenderingContext): ProgramState {
  const program = createProgram(gl, POINT_VERTEX_SHADER, POINT_FRAGMENT_SHADER);
  return {
    program,
    position: gl.getAttribLocation(program, "aPosition"),
    color: gl.getAttribLocation(program, "aColor"),
    size: gl.getAttribLocation(program, "aSize"),
    twinklePhase: gl.getAttribLocation(program, "aTwinklePhase"),
    twinkleFrequency: gl.getAttribLocation(program, "aTwinkleFrequency"),
    role: gl.getAttribLocation(program, "aRole"),
    viewport: gl.getUniformLocation(program, "uViewport"),
    rotation: gl.getUniformLocation(program, "uRotation"),
    scale: gl.getUniformLocation(program, "uScale"),
    distance: gl.getUniformLocation(program, "uDistance"),
    pixelRatio: gl.getUniformLocation(program, "uPixelRatio"),
    time: gl.getUniformLocation(program, "uTime"),
    ring: gl.getUniformLocation(program, "uRing"),
  };
}

function lineProgram(gl: WebGL2RenderingContext): ProgramState {
  const program = createProgram(gl, LINE_VERTEX_SHADER, LINE_FRAGMENT_SHADER);
  return {
    program,
    position: gl.getAttribLocation(program, "aPosition"),
    color: gl.getAttribLocation(program, "aColor"),
    viewport: gl.getUniformLocation(program, "uViewport"),
    rotation: gl.getUniformLocation(program, "uRotation"),
    scale: gl.getUniformLocation(program, "uScale"),
    distance: gl.getUniformLocation(program, "uDistance"),
  };
}

function buffer(gl: WebGL2RenderingContext): WebGLBuffer {
  const result = gl.createBuffer();
  if (!result) throw new Error("The GPU did not allocate a graph buffer.");
  return result;
}

function bindProjection(gl: WebGL2RenderingContext, state: ProgramState, frame: BrainAtlasWebGLFrame): void {
  gl.uniform2f(state.viewport, frame.width, frame.height);
  gl.uniform2f(state.rotation, frame.rotation.x, frame.rotation.y);
  gl.uniform1f(state.scale, Math.min(frame.width, frame.height) * 0.32 * frame.zoom);
  gl.uniform1f(state.distance, 3.4);
  if (state.pixelRatio !== undefined) gl.uniform1f(state.pixelRatio, frame.pixelRatio);
  if (state.time !== undefined) gl.uniform1f(state.time, frame.time / 1_000);
}

function writeColor(target: number[], color: BrainAtlasColor, alphaMultiplier = 1): void {
  target.push(color[0], color[1], color[2], Math.max(0, Math.min(1, color[3] * alphaMultiplier)));
}

function pointVertex(
  target: number[],
  position: BrainAtlasVector3,
  color: BrainAtlasColor,
  size: number,
  phase: number,
  frequency: number,
  role: number,
  alpha = 1,
): void {
  target.push(position.x, position.y, position.z);
  writeColor(target, color, alpha);
  target.push(size, phase, frequency, role);
}

function lineVertex(target: number[], position: BrainAtlasVector3, color: BrainAtlasColor, alpha = 1): void {
  target.push(position.x, position.y, position.z);
  writeColor(target, color, alpha);
}

function signalColor(kind: GraphSignalKind, theme: BrainAtlasWebGLTheme): BrainAtlasColor {
  if (kind === "hazard") return theme.hazard;
  if (kind === "recovery") return theme.recovery;
  return theme.knowledge;
}

function directionArrow(source: BrainAtlasVector3, target: BrainAtlasVector3): readonly [BrainAtlasVector3, BrainAtlasVector3] {
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const dz = target.z - source.z;
  const length = Math.max(0.001, Math.hypot(dx, dy, dz));
  const ux = dx / length;
  const uy = dy / length;
  const uz = dz / length;
  const perpendicularLength = Math.max(0.001, Math.hypot(-uy, ux));
  const px = -uy / perpendicularLength;
  const py = ux / perpendicularLength;
  const base = { x: target.x - ux * 0.075, y: target.y - uy * 0.075, z: target.z - uz * 0.075 };
  return [
    { x: base.x + px * 0.035, y: base.y + py * 0.035, z: base.z },
    { x: base.x - px * 0.035, y: base.y - py * 0.035, z: base.z },
  ];
}

export class BrainAtlasWebGLRenderer {
  readonly #gl: WebGL2RenderingContext;
  readonly #pointProgram: ProgramState;
  readonly #lineProgram: ProgramState;
  readonly #pointBuffer: WebGLBuffer;
  readonly #lineBuffer: WebGLBuffer;
  readonly #contextLost: (event: Event) => void;
  #disposed = false;

  constructor(
    readonly canvas: HTMLCanvasElement,
    onContextLost: () => void,
  ) {
    const gl = canvas.getContext("webgl2", {
      alpha: false,
      antialias: true,
      depth: true,
      premultipliedAlpha: true,
      preserveDrawingBuffer: true,
      powerPreference: "high-performance",
    });
    if (!gl) throw new Error("WebGL 2 is unavailable.");
    this.#gl = gl;
    this.#pointProgram = pointProgram(gl);
    this.#lineProgram = lineProgram(gl);
    this.#pointBuffer = buffer(gl);
    this.#lineBuffer = buffer(gl);
    this.#contextLost = (event) => {
      event.preventDefault();
      onContextLost();
    };
    canvas.addEventListener("webglcontextlost", this.#contextLost);
  }

  render(frame: BrainAtlasWebGLFrame): BrainAtlasWebGLResult {
    if (this.#disposed) throw new Error("The WebGL brain renderer is disposed.");
    const gl = this.#gl;
    const width = Math.max(1, Math.floor(frame.width * frame.pixelRatio));
    const height = Math.max(1, Math.floor(frame.height * frame.pixelRatio));
    if (this.canvas.width !== width) this.canvas.width = width;
    if (this.canvas.height !== height) this.canvas.height = height;
    gl.viewport(0, 0, width, height);
    gl.clearColor(frame.theme.background[0], frame.theme.background[1], frame.theme.background[2], 1);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
    gl.disable(gl.CULL_FACE);
    gl.disable(gl.DEPTH_TEST);
    gl.enable(gl.BLEND);

    const nodeById = new Map(frame.nodes.map((node) => [node.id, node]));
    const pointById = new Map(frame.points.map((point) => [point.id, point]));
    const modelPositions = new Map<string, BrainAtlasVector3>();
    const projectedNodes = new Map<string, BrainAtlasProjectedNode>();
    const projection = brainAtlasProjection(frame.width, frame.height, frame.zoom, frame.rotation);
    for (const [id, point] of pointById) {
      const node = nodeById.get(id);
      if (!node) continue;
      const region = brainAtlasRegionForNode(node);
      if (!frame.visibleRegions.has(region)) continue;
      const position = graphPointToBrainAtlasPosition(point, node, frame.width, frame.height);
      const projected = projectBrainAtlasPoint(projection, position);
      modelPositions.set(id, position);
      projectedNodes.set(id, {
        ...projected,
        id,
        region,
        radius: point.radius * projected.scale,
      });
    }

    this.#drawCloud(frame);
    const directedEdgeCount = this.#drawEdges(frame, modelPositions);
    this.#drawSignals(frame, modelPositions);
    this.#drawNodes(frame, modelPositions, nodeById, pointById);

    return {
      projectedNodes,
      visibleNodeCount: projectedNodes.size,
      directedEdgeCount,
    };
  }

  #drawCloud(frame: BrainAtlasWebGLFrame): void {
    const vertices: number[] = [];
    for (const point of BRAIN_ATLAS_CLOUD) {
      if (!frame.visibleRegions.has(point.region)) continue;
      const size = point.region === "stem" ? 3.0 : point.region === "cerebellum" ? 2.55 : 2.35;
      const alpha = BRAIN_AMBIENT_PARTICLE_ALPHA[point.region];
      pointVertex(vertices, point, frame.theme.cloud[point.region], size, point.twinklePhase, point.twinkleFrequency, 0, alpha);
    }
    const gl = this.#gl;
    // Dark graphite points must alpha-composite over the light Daylight canvas.
    // Additive blending drove the RGB values toward white and erased the brain.
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
    this.#drawPointVertices(frame, vertices, 0);
  }

  #drawEdges(frame: BrainAtlasWebGLFrame, positions: ReadonlyMap<string, BrainAtlasVector3>): number {
    const vertices: number[] = [];
    let count = 0;
    for (const edge of frame.edges) {
      const source = positions.get(edge.sourceNodeId);
      const target = positions.get(edge.targetNodeId);
      if (!source || !target) continue;
      const key = [edge.sourceNodeId, edge.targetNodeId].sort().join("|");
      const inPath = frame.selectedPathEdges.has(key);
      const connected = frame.relatedNodeIds.has(edge.sourceNodeId) && frame.relatedNodeIds.has(edge.targetNodeId);
      const color = inPath ? signalColor(frame.edgeKinds.get(edge.id) ?? "knowledge", frame.theme) : connected ? frame.theme.edgeConnected : frame.theme.edge;
      const alpha = frame.selectedId && !inPath && !connected ? 0.09 : inPath ? 1 : connected ? 0.88 : 0.34;
      lineVertex(vertices, source, color, alpha);
      lineVertex(vertices, target, color, alpha);
      const [leftWing, rightWing] = directionArrow(source, target);
      lineVertex(vertices, target, color, alpha);
      lineVertex(vertices, leftWing, color, alpha);
      lineVertex(vertices, target, color, alpha);
      lineVertex(vertices, rightWing, color, alpha);
      count += 1;
    }
    this.#drawLineVertices(frame, vertices);
    return count;
  }

  #drawSignals(frame: BrainAtlasWebGLFrame, positions: ReadonlyMap<string, BrainAtlasVector3>): void {
    const vertices: number[] = [];
    for (const route of frame.ambientSignalRoutes) {
      const source = positions.get(route.fromNodeId);
      const target = positions.get(route.toNodeId);
      if (!source || !target) continue;
      const progress = ((frame.time / route.durationMs) + route.phaseOffset) % 1;
      const eased = progress * progress * (3 - 2 * progress);
      pointVertex(vertices, {
        x: source.x + (target.x - source.x) * eased,
        y: source.y + (target.y - source.y) * eased,
        z: source.z + (target.z - source.z) * eased,
      }, signalColor(route.kind, frame.theme), 4.2, 0, 0, 2, frame.selectedId ? 0.24 : 0.42);
    }
    if (frame.selectedSignalStartedAt > 0) {
      const elapsed = frame.time - frame.selectedSignalStartedAt;
      for (const route of frame.selectedSignalRoutes) {
        const source = positions.get(route.fromNodeId);
        const target = positions.get(route.toNodeId);
        if (!source || !target) continue;
        const progress = (elapsed - route.hop * 150) / 920;
        if (progress < 0 || progress > 1) continue;
        const eased = progress * progress * (3 - 2 * progress);
        pointVertex(vertices, {
          x: source.x + (target.x - source.x) * eased,
          y: source.y + (target.y - source.y) * eased,
          z: source.z + (target.z - source.z) * eased,
        }, signalColor(route.kind, frame.theme), 7.2, 0, 0, 2);
      }
    }
    this.#drawPointVertices(frame, vertices, 0);
  }

  #drawNodes(
    frame: BrainAtlasWebGLFrame,
    positions: ReadonlyMap<string, BrainAtlasVector3>,
    nodes: ReadonlyMap<string, MemoryNodeSummary>,
    points: ReadonlyMap<string, GraphPoint>,
  ): void {
    const vertices: number[] = [];
    let selectedVertex: number[] | undefined;
    let hoveredVertex: number[] | undefined;
    for (const [id, position] of positions) {
      const point = points.get(id);
      const node = nodes.get(id);
      if (!point || !node) continue;
      const selected = id === frame.selectedId;
      const hovered = id === frame.hoveredId;
      const dimmed = Boolean(frame.selectedId && !frame.illuminatedNodeIds.has(id));
      const size = brainNodeVisualDiameter(point.radius) * (hovered ? 1.12 : 1);
      pointVertex(vertices, position, frame.theme.node, size, 0, 0, 1, dimmed ? 0.18 : 0.96);
      if (selected) {
        selectedVertex = [];
        pointVertex(selectedVertex, position, frame.theme.selection, size + 12, 0, 0, 1);
      } else if (hovered) {
        hoveredVertex = [];
        pointVertex(hoveredVertex, position, frame.theme.node, size + 8, 0, 0, 1, 0.86);
      }
    }
    this.#drawPointVertices(frame, vertices, 0);
    if (hoveredVertex) this.#drawPointVertices(frame, hoveredVertex, 1);
    if (selectedVertex) this.#drawPointVertices(frame, selectedVertex, 1);
  }

  #drawPointVertices(frame: BrainAtlasWebGLFrame, vertices: readonly number[], ring: number): void {
    if (vertices.length === 0) return;
    const gl = this.#gl;
    const state = this.#pointProgram;
    gl.useProgram(state.program);
    bindProjection(gl, state, frame);
    gl.uniform1f(state.ring ?? null, ring);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.#pointBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(vertices), gl.DYNAMIC_DRAW);
    const stride = 11 * Float32Array.BYTES_PER_ELEMENT;
    gl.enableVertexAttribArray(state.position);
    gl.vertexAttribPointer(state.position, 3, gl.FLOAT, false, stride, 0);
    gl.enableVertexAttribArray(state.color);
    gl.vertexAttribPointer(state.color, 4, gl.FLOAT, false, stride, 3 * Float32Array.BYTES_PER_ELEMENT);
    gl.enableVertexAttribArray(state.size!);
    gl.vertexAttribPointer(state.size!, 1, gl.FLOAT, false, stride, 7 * Float32Array.BYTES_PER_ELEMENT);
    gl.enableVertexAttribArray(state.twinklePhase!);
    gl.vertexAttribPointer(state.twinklePhase!, 1, gl.FLOAT, false, stride, 8 * Float32Array.BYTES_PER_ELEMENT);
    gl.enableVertexAttribArray(state.twinkleFrequency!);
    gl.vertexAttribPointer(state.twinkleFrequency!, 1, gl.FLOAT, false, stride, 9 * Float32Array.BYTES_PER_ELEMENT);
    gl.enableVertexAttribArray(state.role!);
    gl.vertexAttribPointer(state.role!, 1, gl.FLOAT, false, stride, 10 * Float32Array.BYTES_PER_ELEMENT);
    gl.drawArrays(gl.POINTS, 0, vertices.length / 11);
  }

  #drawLineVertices(frame: BrainAtlasWebGLFrame, vertices: readonly number[]): void {
    if (vertices.length === 0) return;
    const gl = this.#gl;
    const state = this.#lineProgram;
    gl.useProgram(state.program);
    bindProjection(gl, state, frame);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.#lineBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(vertices), gl.DYNAMIC_DRAW);
    const stride = 7 * Float32Array.BYTES_PER_ELEMENT;
    gl.enableVertexAttribArray(state.position);
    gl.vertexAttribPointer(state.position, 3, gl.FLOAT, false, stride, 0);
    gl.enableVertexAttribArray(state.color);
    gl.vertexAttribPointer(state.color, 4, gl.FLOAT, false, stride, 3 * Float32Array.BYTES_PER_ELEMENT);
    gl.drawArrays(gl.LINES, 0, vertices.length / 7);
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.canvas.removeEventListener("webglcontextlost", this.#contextLost);
    const gl = this.#gl;
    gl.deleteBuffer(this.#pointBuffer);
    gl.deleteBuffer(this.#lineBuffer);
    gl.deleteProgram(this.#pointProgram.program);
    gl.deleteProgram(this.#lineProgram.program);
  }
}

function parseHex(input: string): BrainAtlasColor | undefined {
  const value = input.trim().replace(/^#/, "");
  if (![3, 4, 6, 8].includes(value.length) || !/^[0-9a-f]+$/iu.test(value)) return undefined;
  const expanded = value.length <= 4 ? [...value].map((character) => `${character}${character}`).join("") : value;
  const alpha = expanded.length === 8 ? Number.parseInt(expanded.slice(6, 8), 16) / 255 : 1;
  return [
    Number.parseInt(expanded.slice(0, 2), 16) / 255,
    Number.parseInt(expanded.slice(2, 4), 16) / 255,
    Number.parseInt(expanded.slice(4, 6), 16) / 255,
    alpha,
  ];
}

export function parseBrainAtlasColor(input: string, fallback: BrainAtlasColor): BrainAtlasColor {
  const hex = parseHex(input);
  if (hex) return hex;
  const match = input.trim().match(/^rgba?\(([^)]+)\)$/iu);
  if (!match) return fallback;
  const parts = match[1]!.split(/[\s,\/]+/u).filter(Boolean).map(Number);
  if (parts.length < 3 || parts.slice(0, 3).some((value) => !Number.isFinite(value))) return fallback;
  return [
    Math.max(0, Math.min(255, parts[0]!)) / 255,
    Math.max(0, Math.min(255, parts[1]!)) / 255,
    Math.max(0, Math.min(255, parts[2]!)) / 255,
    Math.max(0, Math.min(1, Number.isFinite(parts[3]) ? parts[3]! : 1)),
  ];
}

export function detectBrainAtlasRenderer(): "webgl2" | "canvas2d" {
  if (typeof document === "undefined") return "canvas2d";
  const probe = document.createElement("canvas");
  try {
    // Software-backed WebGL2 is still a standards-compliant GPU API and is
    // preferable to silently opting out on virtual desktops or CI. True API
    // absence and context loss remain explicit Canvas2D fallback conditions.
    return probe.getContext("webgl2") ? "webgl2" : "canvas2d";
  } catch {
    return "canvas2d";
  }
}

export { BRAIN_ATLAS_REGIONS };

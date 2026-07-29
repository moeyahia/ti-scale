import { useEffect, useRef } from "react";
import {
  ACESFilmicToneMapping,
  Box3,
  BufferGeometry,
  Color,
  CylinderGeometry,
  DirectionalLight,
  Group,
  HemisphereLight,
  InstancedMesh,
  Material,
  Matrix4,
  Mesh,
  MeshStandardMaterial,
  Object3D,
  PerspectiveCamera,
  Quaternion,
  Scene,
  Sphere,
  SRGBColorSpace,
  Vector2,
  Vector3,
  WebGLRenderer,
} from "three";
import { GLTFLoader } from "three/addons/loaders/GLTFLoader.js";
import type { GLTF } from "three/addons/loaders/GLTFLoader.js";
import {
  assemblyReviewAssetUrl,
  type AssemblyReviewManifest,
  type AssemblyReviewModel,
} from "./assemblyReviewManifest";

export type AssemblyRuntimeCommandType =
  | "reset"
  | "fit"
  | "rotate-left"
  | "rotate-right"
  | "zoom-in"
  | "zoom-out";

export interface AssemblyRuntimeCommand {
  readonly sequence: number;
  readonly type: AssemblyRuntimeCommandType;
}

export interface AssemblyRuntimeStats {
  readonly loadedModels: number;
  readonly verifiedModels: number;
  readonly modelMeshCount: number;
  readonly fastenerInstances: number;
  readonly triangles: number;
  readonly modelBytes: number;
  readonly drawCalls: number;
  readonly visibleModelPixels: number;
  readonly visibleModelCoverage: number;
  readonly loadMilliseconds: number;
}

export interface AssemblyReviewRuntimeProps {
  readonly manifest: AssemblyReviewManifest;
  readonly progress: number;
  readonly selectedId?: string;
  readonly reducedMotion: boolean;
  readonly command: AssemblyRuntimeCommand;
  readonly onProgress: (loaded: number, total: number, label: string) => void;
  readonly onReady: (stats: AssemblyRuntimeStats) => void;
  readonly onError: (message: string) => void;
}

interface RuntimeState {
  readonly host: HTMLDivElement;
  readonly renderer: WebGLRenderer;
  readonly camera: PerspectiveCamera;
  readonly scene: Scene;
  readonly assembly: Group;
  readonly modelGroups: Map<string, Group>;
  readonly fasteners: InstancedMesh;
  readonly resizeObserver: ResizeObserver;
  readonly render: () => void;
  readonly target: Vector3;
  distance: number;
  yaw: number;
  pitch: number;
  progress: number;
  selectedId?: string;
}

const GLB_MAGIC = 0x4654_6c67;
const MAX_GLBS = 14;
const MAX_MODEL_BYTES = 2_000_000;
const DEG = Math.PI / 180;

function hex(value: ArrayBuffer): string {
  return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: ArrayBuffer): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("This browser cannot verify the assembly model digests.");
  return hex(await globalThis.crypto.subtle.digest("SHA-256", value));
}

export function assertEmbeddedReviewGlb(value: ArrayBuffer): void {
  if (value.byteLength < 20 || value.byteLength > MAX_MODEL_BYTES) throw new Error("A review model is not a bounded GLB.");
  const view = new DataView(value);
  if (view.getUint32(0, true) !== GLB_MAGIC || view.getUint32(4, true) !== 2 || view.getUint32(8, true) !== value.byteLength) {
    throw new Error("A review model is not a valid GLB 2.0 container.");
  }
  const jsonLength = view.getUint32(12, true);
  if (view.getUint32(16, true) !== 0x4e4f_534a || jsonLength <= 0 || jsonLength + 20 > value.byteLength) {
    throw new Error("A review model is missing its embedded descriptor.");
  }
  const descriptor = JSON.parse(
    new TextDecoder().decode(new Uint8Array(value, 20, jsonLength)).replace(/[\u0000\u0020]+$/u, ""),
  ) as { buffers?: Array<{ uri?: unknown }>; images?: Array<{ uri?: unknown }> };
  const external = (entries?: Array<{ uri?: unknown }>) => entries?.some((entry) => typeof entry.uri === "string") ?? false;
  if (external(descriptor.buffers) || external(descriptor.images)) throw new Error("A review GLB may not request secondary assets.");
}

function parseGlb(loader: GLTFLoader, bytes: ArrayBuffer): Promise<GLTF> {
  return new Promise((resolve, reject) => loader.parse(bytes, "", resolve, reject));
}

function countTriangles(root: Object3D): number {
  let triangles = 0;
  root.traverse((object) => {
    if (!(object instanceof Mesh)) return;
    const count = object.geometry.index?.count ?? object.geometry.getAttribute("position")?.count ?? 0;
    triangles += Math.floor(count / 3);
  });
  return triangles;
}

function materialTextures(material: Material): Array<{ dispose: () => void }> {
  return Object.values(material).filter((entry): entry is { dispose: () => void } => (
    Boolean(entry && typeof entry === "object" && "isTexture" in entry && "dispose" in entry)
  ));
}

export function cloneReviewMeshMaterial(original: Material | Material[]): Material | Material[] {
  return Array.isArray(original)
    ? original.map((material) => material.clone())
    : original.clone();
}

export function countVisibleReviewPixels(rgba: Uint8Array): number {
  if (rgba.length < 4 || rgba.length % 4 !== 0) throw new Error("The visual integrity buffer is invalid.");
  const background = [rgba[0] ?? 0, rgba[1] ?? 0, rgba[2] ?? 0] as const;
  let visible = 0;
  for (let offset = 0; offset < rgba.length; offset += 4) {
    const delta = Math.abs((rgba[offset] ?? 0) - background[0])
      + Math.abs((rgba[offset + 1] ?? 0) - background[1])
      + Math.abs((rgba[offset + 2] ?? 0) - background[2]);
    if (delta >= 18) visible += 1;
  }
  return visible;
}

function disposeObject(root: Object3D): void {
  const geometries = new Set<BufferGeometry>();
  const materials = new Set<Material>();
  root.traverse((object) => {
    if (!(object instanceof Mesh)) return;
    geometries.add(object.geometry);
    const entries = Array.isArray(object.material) ? object.material : [object.material];
    entries.forEach((material) => materials.add(material));
  });
  materials.forEach((material) => {
    materialTextures(material).forEach((texture) => texture.dispose());
    material.dispose();
  });
  geometries.forEach((geometry) => geometry.dispose());
  root.clear();
}

function smooth(value: number): number {
  const bounded = Math.max(0, Math.min(1, value));
  return bounded * bounded * (3 - 2 * bounded);
}

function modelPosition(model: AssemblyReviewModel, progress: number, target: Vector3): Vector3 {
  const assembled = model.assembly.position;
  if (progress <= 0.22) {
    const unseat = smooth(progress / 0.22);
    return target.set(assembled.x, assembled.y, assembled.z + model.explosion.unseatWorld * unseat);
  }
  const travel = smooth((progress - 0.22) / 0.78);
  const unseatedZ = assembled.z + model.explosion.unseatWorld;
  return target.set(
    assembled.x + (model.explosion.position.x - assembled.x) * travel,
    assembled.y + (model.explosion.position.y - assembled.y) * travel,
    unseatedZ + (model.explosion.position.z - unseatedZ) * travel,
  );
}

function updateModelSelection(state: RuntimeState): void {
  state.modelGroups.forEach((group, id) => {
    const selected = !state.selectedId || state.selectedId === id;
    group.traverse((object) => {
      if (!(object instanceof Mesh)) return;
      const materials = Array.isArray(object.material) ? object.material : [object.material];
      materials.forEach((material) => {
        if (!(material instanceof MeshStandardMaterial)) return;
        if (!material.userData.reviewBaseEmissive) material.userData.reviewBaseEmissive = material.emissive.getHex();
        material.emissive.setHex(selected && state.selectedId ? 0x29445c : Number(material.userData.reviewBaseEmissive));
        material.emissiveIntensity = selected && state.selectedId ? 0.28 : 1;
      });
    });
  });
}

function updateTransforms(state: RuntimeState, manifest: AssemblyReviewManifest): void {
  state.progress = Math.max(0, Math.min(1, state.progress));
  const scratch = new Vector3();
  manifest.models.forEach((model) => {
    const group = state.modelGroups.get(model.id);
    if (group) group.position.copy(modelPosition(model, state.progress, scratch));
  });
  const matrix = new Matrix4();
  const position = new Vector3();
  const quaternion = new Quaternion();
  const scale = new Vector3(1, 1, 1);
  const modelById = new Map(manifest.models.map((model) => [model.id, model]));
  manifest.fasteners.forEach((fastener, index) => {
    const owner = modelById.get(fastener.owner);
    if (!owner) return;
    modelPosition(owner, state.progress, position);
    position.add(new Vector3(fastener.ownerLocalOffset.x, fastener.ownerLocalOffset.y, fastener.ownerLocalOffset.z));
    matrix.compose(position, quaternion, scale);
    state.fasteners.setMatrixAt(index, matrix);
  });
  state.fasteners.instanceMatrix.needsUpdate = true;
  state.fasteners.computeBoundingBox();
  state.fasteners.computeBoundingSphere();
  state.render();
}

function applyView(state: RuntimeState): void {
  state.assembly.rotation.set(state.pitch, state.yaw, 0);
  state.camera.position.set(state.target.x, state.target.y, state.target.z + state.distance);
  state.camera.lookAt(state.target);
  state.camera.updateMatrixWorld(true);
  state.host.dataset.cameraYaw = state.yaw.toFixed(4);
  state.host.dataset.cameraPitch = state.pitch.toFixed(4);
  state.host.dataset.cameraDistance = state.distance.toFixed(3);
  state.host.dataset.cameraTarget = `${state.target.x.toFixed(4)},${state.target.y.toFixed(4)},${state.target.z.toFixed(4)}`;
  state.render();
}

function exposeProjectedAssemblyBounds(state: RuntimeState): void {
  state.assembly.updateMatrixWorld(true);
  state.camera.updateMatrixWorld(true);
  const bounds = new Box3().setFromObject(state.assembly);
  const { min, max } = bounds;
  const corners = [
    new Vector3(min.x, min.y, min.z), new Vector3(min.x, min.y, max.z),
    new Vector3(min.x, max.y, min.z), new Vector3(min.x, max.y, max.z),
    new Vector3(max.x, min.y, min.z), new Vector3(max.x, min.y, max.z),
    new Vector3(max.x, max.y, min.z), new Vector3(max.x, max.y, max.z),
  ].map((corner) => corner.project(state.camera));
  const minimumX = Math.min(...corners.map((corner) => corner.x));
  const maximumX = Math.max(...corners.map((corner) => corner.x));
  const minimumY = Math.min(...corners.map((corner) => corner.y));
  const maximumY = Math.max(...corners.map((corner) => corner.y));
  const margin = Math.min(minimumX + 1, 1 - maximumX, minimumY + 1, 1 - maximumY) / 2;
  state.host.dataset.projectedBounds = [minimumX, minimumY, maximumX, maximumY].map((value) => value.toFixed(6)).join(",");
  state.host.dataset.projectedMargin = margin.toFixed(6);
  state.host.dataset.projectedModels = "14";
  state.host.dataset.projectedFasteners = "26";
}

function fitView(state: RuntimeState, manifest: AssemblyReviewManifest): void {
  state.assembly.updateMatrixWorld(true);
  const bounds = new Box3().setFromObject(state.assembly);
  const sphere = bounds.getBoundingSphere(new Sphere());
  const fov = state.camera.fov * DEG;
  const verticalHalfFov = Math.max(0.1, fov / 2);
  const horizontalHalfFov = Math.atan(Math.tan(verticalHalfFov) * Math.max(0.01, state.camera.aspect));
  const limitingHalfFov = Math.max(0.1, Math.min(verticalHalfFov, horizontalHalfFov));
  const distance = sphere.radius / Math.sin(limitingHalfFov);
  const paddedDistance = distance * 1.18;
  state.target.copy(sphere.center);
  state.distance = Math.max(manifest.camera.minimumDistance, Math.min(manifest.camera.maximumDistance, paddedDistance));
  state.host.dataset.fitRequestedDistance = paddedDistance.toFixed(3);
  applyView(state);
  exposeProjectedAssemblyBounds(state);
}

function measureVisibleModelCoverage(state: RuntimeState, minimumRatio: number): { readonly pixels: number; readonly ratio: number } {
  const gl = state.renderer.getContext();
  const width = gl.drawingBufferWidth;
  const height = gl.drawingBufferHeight;
  const total = width * height;
  if (total <= 0) throw new Error("The assembly viewer has no drawable surface for its visual integrity check.");

  // The 26 fasteners already proved that the WebGL context could draw while
  // hiding a material-shape bug that made every plate invisible. Render one
  // model-only audit frame and count pixels that differ from the clear field.
  // This verifies visible plate coverage rather than trusting load counters.
  state.fasteners.visible = false;
  state.renderer.render(state.scene, state.camera);
  const rgba = new Uint8Array(total * 4);
  gl.readPixels(0, 0, width, height, gl.RGBA, gl.UNSIGNED_BYTE, rgba);
  state.fasteners.visible = true;
  state.renderer.render(state.scene, state.camera);

  const visible = countVisibleReviewPixels(rgba);
  const ratio = visible / total;
  const minimum = Math.max(128, Math.floor(total * minimumRatio));
  if (visible < minimum) {
    throw new Error(`The locked models loaded, but visible plate coverage was ${(ratio * 100).toFixed(2)}%; at least ${(minimumRatio * 100).toFixed(2)}% is required.`);
  }
  state.host.dataset.visibleModelPixels = String(visible);
  state.host.dataset.visibleModelCoverage = ratio.toFixed(6);
  return { pixels: visible, ratio };
}

function configureLights(scene: Scene, manifest: AssemblyReviewManifest): void {
  manifest.lights.forEach((input) => {
    const kind = String(input.kind ?? "");
    if (kind === "hemisphere") {
      scene.add(new HemisphereLight(String(input.sky), String(input.ground), Number(input.intensity)));
      return;
    }
    if (kind === "directional" && Array.isArray(input.position)) {
      const light = new DirectionalLight(String(input.color), Number(input.intensity));
      light.position.fromArray(input.position as number[]);
      scene.add(light);
    }
  });
}

async function loadModel(model: AssemblyReviewModel, loader: GLTFLoader, signal: AbortSignal): Promise<{ scene: Group; triangles: number; meshCount: number }> {
  const response = await fetch(assemblyReviewAssetUrl(model.path), {
    signal,
    cache: "force-cache",
    credentials: "same-origin",
    headers: { Accept: "model/gltf-binary" },
  });
  if (!response.ok) throw new Error(`${model.name} returned HTTP ${response.status}.`);
  const bytes = await response.arrayBuffer();
  if (bytes.byteLength !== model.bytes) throw new Error(`${model.name} does not match its locked byte count.`);
  assertEmbeddedReviewGlb(bytes);
  if (await sha256(bytes) !== model.sha256) throw new Error(`${model.name} failed its locked SHA-256 check.`);
  const gltf = await parseGlb(loader, bytes);
  const triangles = countTriangles(gltf.scene);
  if (triangles !== model.triangleCount) throw new Error(`${model.name} does not match its locked triangle count.`);
  let meshCount = 0;
  gltf.scene.traverse((object) => { if (object instanceof Mesh) meshCount += 1; });
  if (meshCount !== model.meshPrimitiveCount) throw new Error(`${model.name} does not match its locked mesh-primitive count.`);
  const scene = gltf.scene;
  scene.position.set(
    model.canonicalization.rootOffset.x,
    model.canonicalization.rootOffset.y,
    model.canonicalization.rootOffset.z,
  );
  scene.scale.setScalar(model.canonicalization.uniformScale);
  scene.traverse((object) => {
    if (!(object instanceof Mesh)) return;
    object.castShadow = false;
    object.receiveShadow = false;
    object.material = cloneReviewMeshMaterial(object.material);
  });
  return { scene, triangles, meshCount };
}

export default function AssemblyReviewRuntime({
  manifest,
  progress,
  selectedId,
  reducedMotion,
  command,
  onProgress,
  onReady,
  onError,
}: AssemblyReviewRuntimeProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const runtimeRef = useRef<RuntimeState | undefined>(undefined);

  useEffect(() => {
    const host = hostRef.current;
    if (!host || manifest.models.length !== MAX_GLBS) return;
    const controller = new AbortController();
    const startedAt = performance.now();
    let disposed = false;
    let frame = 0;

    const renderer = new WebGLRenderer({ antialias: true, alpha: false, powerPreference: "high-performance" });
    renderer.setPixelRatio(Math.min(devicePixelRatio, manifest.budgets.maximumDevicePixelRatio));
    renderer.outputColorSpace = SRGBColorSpace;
    renderer.toneMapping = ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.04;
    renderer.setClearColor(new Color("#f3f1ed"), 1);
    renderer.domElement.className = "assembly-review-runtime__canvas";
    renderer.domElement.tabIndex = 0;
    renderer.domElement.setAttribute("aria-label", "Interactive Ti-Scale 14-element assembly viewer");
    renderer.domElement.setAttribute("role", "application");
    host.append(renderer.domElement);

    const scene = new Scene();
    const camera = new PerspectiveCamera(manifest.camera.fieldOfViewDegrees, 1, manifest.camera.near, manifest.camera.far);
    const assembly = new Group();
    assembly.name = "TI_SCALE_14_ELEMENT_REVIEW_ASSEMBLY";
    scene.add(assembly);
    configureLights(scene, manifest);

    const fastenerGeometry = new CylinderGeometry(
      manifest.fasteners[0]?.radiusWorld ?? 0.044,
      (manifest.fasteners[0]?.radiusWorld ?? 0.044) * 0.92,
      manifest.fastenerGeometry.depthWorld,
      manifest.fastenerGeometry.radialSegments,
      1,
      false,
    );
    fastenerGeometry.rotateX(Math.PI / 2);
    const fastenerMaterial = new MeshStandardMaterial({
      color: manifest.fastenerGeometry.material.color,
      metalness: manifest.fastenerGeometry.material.metalness,
      roughness: manifest.fastenerGeometry.material.roughness,
    });
    const fasteners = new InstancedMesh(fastenerGeometry, fastenerMaterial, manifest.fastenerGeometry.count);
    fasteners.name = "TI_SCALE_DETERMINISTIC_FASTENERS_26";
    fasteners.frustumCulled = false;
    assembly.add(fasteners);

    const modelGroups = new Map<string, Group>();
    const render = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => renderer.render(scene, camera));
    };
    const runtime: RuntimeState = {
      host,
      renderer,
      camera,
      scene,
      assembly,
      modelGroups,
      fasteners,
      resizeObserver: new ResizeObserver(() => undefined),
      render,
      target: new Vector3(manifest.camera.target.x, manifest.camera.target.y, manifest.camera.target.z),
      distance: manifest.camera.position.z,
      yaw: manifest.camera.defaultYawDegrees * DEG,
      pitch: manifest.camera.defaultPitchDegrees * DEG,
      progress,
      selectedId,
    };
    runtimeRef.current = runtime;

    const resize = () => {
      const width = Math.max(1, host.clientWidth);
      const height = Math.max(1, host.clientHeight);
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      if (modelGroups.size === manifest.models.length) fitView(runtime, manifest);
      else render();
    };
    runtime.resizeObserver.disconnect();
    const resizeObserver = new ResizeObserver(resize);
    (runtime as { resizeObserver: ResizeObserver }).resizeObserver = resizeObserver;
    resizeObserver.observe(host);
    resize();

    let pointer: { id: number; at: Vector2; yaw: number; pitch: number } | undefined;
    const onPointerDown = (event: PointerEvent) => {
      pointer = { id: event.pointerId, at: new Vector2(event.clientX, event.clientY), yaw: runtime.yaw, pitch: runtime.pitch };
      renderer.domElement.setPointerCapture(event.pointerId);
    };
    const onPointerMove = (event: PointerEvent) => {
      if (!pointer || pointer.id !== event.pointerId) return;
      runtime.yaw = pointer.yaw + (event.clientX - pointer.at.x) * 0.006;
      runtime.pitch = Math.max(-0.72, Math.min(0.72, pointer.pitch + (event.clientY - pointer.at.y) * 0.005));
      applyView(runtime);
    };
    const onPointerUp = (event: PointerEvent) => {
      if (pointer?.id === event.pointerId) pointer = undefined;
    };
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      runtime.distance = Math.max(
        manifest.camera.minimumDistance,
        Math.min(manifest.camera.maximumDistance, runtime.distance + event.deltaY * 0.008),
      );
      applyView(runtime);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
        event.preventDefault();
        runtime.yaw += (event.key === "ArrowLeft" ? -1 : 1) * 8 * DEG;
      } else if (event.key === "+" || event.key === "=") {
        event.preventDefault();
        runtime.distance = Math.max(manifest.camera.minimumDistance, runtime.distance - 1);
      } else if (event.key === "-") {
        event.preventDefault();
        runtime.distance = Math.min(manifest.camera.maximumDistance, runtime.distance + 1);
      } else if (event.key.toLowerCase() === "f") {
        event.preventDefault();
        fitView(runtime, manifest);
        return;
      } else if (event.key === "Home") {
        event.preventDefault();
        runtime.yaw = manifest.camera.defaultYawDegrees * DEG;
        runtime.pitch = manifest.camera.defaultPitchDegrees * DEG;
        runtime.distance = manifest.camera.position.z;
        runtime.target.set(manifest.camera.target.x, manifest.camera.target.y, manifest.camera.target.z);
      } else return;
      applyView(runtime);
    };
    renderer.domElement.addEventListener("pointerdown", onPointerDown);
    renderer.domElement.addEventListener("pointermove", onPointerMove);
    renderer.domElement.addEventListener("pointerup", onPointerUp);
    renderer.domElement.addEventListener("pointercancel", onPointerUp);
    renderer.domElement.addEventListener("wheel", onWheel, { passive: false });
    renderer.domElement.addEventListener("keydown", onKey);

    // Delay the first static model request by one task. React's development
    // StrictMode immediately tears down its probe mount; the timer is cleared
    // below so that probe never starts or aborts a real GLB request.
    const loadTimer = window.setTimeout(() => { void (async () => {
      const loader = new GLTFLoader();
      let triangles = 0;
      let bytes = 0;
      let modelMeshCount = 0;
      try {
        for (let index = 0; index < manifest.models.length; index += 1) {
          const model = manifest.models[index]!;
          onProgress(index, manifest.models.length, `Verifying ${model.name}`);
          const loaded = await loadModel(model, loader, controller.signal);
          if (disposed) return;
          const group = new Group();
          group.name = model.id;
          group.quaternion.set(
            model.assembly.quaternion.x,
            model.assembly.quaternion.y,
            model.assembly.quaternion.z,
            model.assembly.quaternion.w,
          );
          group.scale.set(model.assembly.scale.x, model.assembly.scale.y, model.assembly.scale.z);
          group.add(loaded.scene);
          assembly.add(group);
          modelGroups.set(model.id, group);
          triangles += loaded.triangles;
          bytes += model.bytes;
          modelMeshCount += loaded.meshCount;
          onProgress(index + 1, manifest.models.length, `${model.name} verified`);
        }
        const requestedProgress = progress;
        runtime.progress = 0;
        runtime.selectedId = selectedId;
        updateTransforms(runtime, manifest);
        updateModelSelection(runtime);
        runtime.yaw = manifest.camera.defaultYawDegrees * DEG;
        runtime.pitch = manifest.camera.defaultPitchDegrees * DEG;
        applyView(runtime);
        fitView(runtime, manifest);
        renderer.render(scene, camera);
        if (modelMeshCount !== manifest.visualIntegrity.expectedModelMeshCount) {
          throw new Error(`The runtime produced ${modelMeshCount} model meshes; ${manifest.visualIntegrity.expectedModelMeshCount} are required.`);
        }
        const visibleCoverage = measureVisibleModelCoverage(runtime, manifest.visualIntegrity.minimumVisibleModelCoverage);
        const drawCalls = renderer.info.render.calls;
        if (drawCalls < manifest.visualIntegrity.minimumDrawCalls) {
          throw new Error(`The runtime produced ${drawCalls} draw calls; at least ${manifest.visualIntegrity.minimumDrawCalls} are required.`);
        }
        host.dataset.modelMeshCount = String(modelMeshCount);
        host.dataset.drawCalls = String(drawCalls);
        runtime.progress = requestedProgress;
        updateTransforms(runtime, manifest);
        fitView(runtime, manifest);
        onReady({
          loadedModels: modelGroups.size,
          verifiedModels: modelGroups.size,
          modelMeshCount,
          fastenerInstances: fasteners.count,
          triangles,
          modelBytes: bytes,
          drawCalls,
          visibleModelPixels: visibleCoverage.pixels,
          visibleModelCoverage: visibleCoverage.ratio,
          loadMilliseconds: Math.round(performance.now() - startedAt),
        });
      } catch (error) {
        if (!controller.signal.aborted) onError(error instanceof Error ? error.message : "The assembly models could not be loaded.");
      }
    })(); }, 0);

    return () => {
      disposed = true;
      window.clearTimeout(loadTimer);
      controller.abort();
      cancelAnimationFrame(frame);
      resizeObserver.disconnect();
      renderer.domElement.removeEventListener("pointerdown", onPointerDown);
      renderer.domElement.removeEventListener("pointermove", onPointerMove);
      renderer.domElement.removeEventListener("pointerup", onPointerUp);
      renderer.domElement.removeEventListener("pointercancel", onPointerUp);
      renderer.domElement.removeEventListener("wheel", onWheel);
      renderer.domElement.removeEventListener("keydown", onKey);
      disposeObject(assembly);
      fastenerGeometry.dispose();
      fastenerMaterial.dispose();
      renderer.dispose();
      renderer.forceContextLoss();
      renderer.domElement.remove();
      runtimeRef.current = undefined;
    };
  // A manifest identifies one immutable scene. Interactive props update via
  // the focused effects below without rebuilding the WebGL context.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [manifest]);

  useEffect(() => {
    const runtime = runtimeRef.current;
    if (!runtime || runtime.modelGroups.size !== manifest.models.length) return;
    runtime.progress = Math.max(0, Math.min(1, progress));
    updateTransforms(runtime, manifest);
    fitView(runtime, manifest);
  }, [manifest, progress, reducedMotion]);

  useEffect(() => {
    const runtime = runtimeRef.current;
    if (!runtime || runtime.modelGroups.size !== manifest.models.length) return;
    runtime.selectedId = selectedId;
    updateModelSelection(runtime);
    runtime.render();
  }, [manifest.models.length, selectedId]);

  useEffect(() => {
    const runtime = runtimeRef.current;
    if (!runtime || command.sequence === 0) return;
    if (command.type === "reset") {
      runtime.yaw = manifest.camera.defaultYawDegrees * DEG;
      runtime.pitch = manifest.camera.defaultPitchDegrees * DEG;
      runtime.distance = manifest.camera.position.z;
      runtime.target.set(manifest.camera.target.x, manifest.camera.target.y, manifest.camera.target.z);
    } else if (command.type === "fit") {
      fitView(runtime, manifest);
      return;
    } else if (command.type === "rotate-left") runtime.yaw -= 12 * DEG;
    else if (command.type === "rotate-right") runtime.yaw += 12 * DEG;
    else if (command.type === "zoom-in") runtime.distance = Math.max(manifest.camera.minimumDistance, runtime.distance - 1.2);
    else if (command.type === "zoom-out") runtime.distance = Math.min(manifest.camera.maximumDistance, runtime.distance + 1.2);
    applyView(runtime);
  }, [command, manifest]);

  return (
    <div
      ref={hostRef}
      className="assembly-review-runtime"
      data-reduced-motion={reducedMotion ? "true" : "false"}
      data-progress={progress.toFixed(3)}
    />
  );
}

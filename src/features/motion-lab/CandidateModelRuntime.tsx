import { useEffect, useRef } from "react";
import {
  ACESFilmicToneMapping,
  Box3,
  BufferGeometry,
  Color,
  DirectionalLight,
  Group,
  HemisphereLight,
  Material,
  Mesh,
  Object3D,
  PerspectiveCamera,
  Scene,
  SRGBColorSpace,
  Texture,
  Vector3,
  WebGLRenderer,
} from "three";
import type { GLTF } from "three/addons/loaders/GLTFLoader.js";
import type { ModelCandidateReviewAsset } from "../../domain/types/modelCandidateReview";

export interface CandidateModelRuntimeProps {
  readonly model: ModelCandidateReviewAsset;
  readonly playing: boolean;
  readonly yawDegrees: number;
  readonly visible: boolean;
  readonly onLoading: (loading: boolean) => void;
  readonly onReady: () => void;
  readonly onError: (message: string) => void;
}

const GLB_MAGIC = 0x4654_6c67;
const GLB_JSON_CHUNK = 0x4e4f_534a;
const MAX_MODEL_BYTES = 64 * 1024 * 1024;
const MAX_TEXTURE_DIMENSION = 8_192;
const MAX_DEVICE_PIXEL_RATIO = 1.75;

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: ArrayBuffer): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("This browser cannot verify the candidate model digest.");
  return hex(await globalThis.crypto.subtle.digest("SHA-256", value));
}

export function assertReviewGlb(value: ArrayBuffer): void {
  if (value.byteLength < 20 || value.byteLength > MAX_MODEL_BYTES) {
    throw new Error("The candidate is not a bounded GLB file.");
  }
  const view = new DataView(value);
  if (view.getUint32(0, true) !== GLB_MAGIC || view.getUint32(4, true) !== 2) {
    throw new Error("The candidate is not a GLB 2.0 container.");
  }
  if (view.getUint32(8, true) !== value.byteLength) {
    throw new Error("The candidate GLB length header does not match its bytes.");
  }
  const jsonLength = view.getUint32(12, true);
  if (view.getUint32(16, true) !== GLB_JSON_CHUNK || jsonLength <= 0 || jsonLength + 20 > value.byteLength) {
    throw new Error("The candidate GLB descriptor is missing or incomplete.");
  }
  let descriptor: Record<string, unknown>;
  try {
    const json = new TextDecoder().decode(new Uint8Array(value, 20, jsonLength)).replace(/[\u0000\u0020]+$/u, "");
    descriptor = JSON.parse(json) as Record<string, unknown>;
  } catch {
    throw new Error("The candidate GLB descriptor could not be parsed.");
  }
  const externalUri = (items: unknown): boolean => Array.isArray(items) && items.some((item) => (
    Boolean(item && typeof item === "object" && "uri" in item && typeof (item as { uri?: unknown }).uri === "string")
  ));
  if (externalUri(descriptor.buffers) || externalUri(descriptor.images)) {
    throw new Error("The candidate GLB may not make secondary asset requests.");
  }
}

function materialTextures(material: Material): Texture[] {
  return Object.values(material).filter((value): value is Texture => value instanceof Texture);
}

function inspectAsset(root: Object3D): { readonly triangles: number; readonly maxTextureDimension: number } {
  const geometries = new Set<BufferGeometry>();
  const textures = new Set<Texture>();
  root.traverse((object) => {
    if (!(object instanceof Mesh)) return;
    object.castShadow = false;
    object.receiveShadow = false;
    geometries.add(object.geometry);
    const materials = Array.isArray(object.material) ? object.material : [object.material];
    materials.forEach((material) => materialTextures(material).forEach((texture) => textures.add(texture)));
  });
  let triangles = 0;
  geometries.forEach((geometry) => {
    const count = geometry.index?.count ?? geometry.getAttribute("position")?.count ?? 0;
    triangles += Math.floor(count / 3);
  });
  let maxTextureDimension = 0;
  textures.forEach((texture) => {
    const image = texture.image as { width?: unknown; height?: unknown } | undefined;
    maxTextureDimension = Math.max(
      maxTextureDimension,
      typeof image?.width === "number" ? image.width : 0,
      typeof image?.height === "number" ? image.height : 0,
    );
  });
  return { triangles, maxTextureDimension };
}

function disposeObject(root: Object3D): void {
  const geometries = new Set<BufferGeometry>();
  const materials = new Set<Material>();
  const textures = new Set<Texture>();
  root.traverse((object) => {
    if (!(object instanceof Mesh)) return;
    geometries.add(object.geometry);
    const meshMaterials = Array.isArray(object.material) ? object.material : [object.material];
    meshMaterials.forEach((material) => {
      materials.add(material);
      materialTextures(material).forEach((texture) => textures.add(texture));
    });
  });
  textures.forEach((texture) => {
    (texture.image as { close?: () => void } | undefined)?.close?.();
    texture.dispose();
  });
  materials.forEach((material) => material.dispose());
  geometries.forEach((geometry) => geometry.dispose());
  root.clear();
}

async function loadCandidate(model: ModelCandidateReviewAsset, signal: AbortSignal): Promise<GLTF> {
  if (model.kind !== "model-glb" || !model.triangleCount) throw new Error("The review manifest does not describe a GLB candidate.");
  const response = await fetch(model.url, {
    signal,
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "model/gltf-binary" },
  });
  if (!response.ok) throw new Error(`The review-only model request returned HTTP ${response.status}.`);
  const declaredBytes = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredBytes) && declaredBytes !== model.bytes) {
    throw new Error("The candidate response length does not match its review manifest.");
  }
  const bytes = await response.arrayBuffer();
  if (bytes.byteLength !== model.bytes) throw new Error("The candidate byte count does not match its review manifest.");
  assertReviewGlb(bytes);
  if (await sha256(bytes) !== model.sha256) throw new Error("The candidate failed its SHA-256 integrity check.");
  const { GLTFLoader } = await import("three/addons/loaders/GLTFLoader.js");
  const gltf = await new GLTFLoader().parseAsync(bytes, "");
  const measured = inspectAsset(gltf.scene);
  if (measured.triangles !== model.triangleCount) {
    disposeObject(gltf.scene);
    throw new Error("The candidate triangle count does not match its review manifest.");
  }
  if (measured.maxTextureDimension > MAX_TEXTURE_DIMENSION) {
    disposeObject(gltf.scene);
    throw new Error("The candidate texture resolution exceeds the review renderer budget.");
  }
  return gltf;
}

export default function CandidateModelRuntime({
  model,
  playing,
  yawDegrees,
  visible,
  onLoading,
  onReady,
  onError,
}: CandidateModelRuntimeProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const rendererRef = useRef<WebGLRenderer | undefined>(undefined);
  const cameraRef = useRef<PerspectiveCamera | undefined>(undefined);
  const sceneRef = useRef<Scene | undefined>(undefined);
  const turntableRef = useRef<Group | undefined>(undefined);
  const modelRef = useRef<Object3D | undefined>(undefined);
  const modelLoadRef = useRef<{
    readonly key: string;
    readonly controller: AbortController;
    readonly promise: Promise<GLTF>;
  } | undefined>(undefined);
  const modelLoadMountedRef = useRef(false);
  const modelLoadAbortTimerRef = useRef<number | undefined>(undefined);
  const visibleRef = useRef(visible);
  const playingRef = useRef(playing);
  const yawRef = useRef(yawDegrees);
  const yawPropRef = useRef(yawDegrees);
  const callbacks = useRef({ onLoading, onReady, onError });
  callbacks.current = { onLoading, onReady, onError };
  visibleRef.current = visible;
  playingRef.current = playing;
  if (yawPropRef.current !== yawDegrees) {
    yawPropRef.current = yawDegrees;
    yawRef.current = yawDegrees;
  }

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    let renderer: WebGLRenderer;
    try {
      renderer = new WebGLRenderer({
        canvas,
        alpha: true,
        antialias: true,
        powerPreference: "high-performance",
        preserveDrawingBuffer: false,
      });
    } catch {
      callbacks.current.onLoading(false);
      callbacks.current.onError("Live 3D rendering is unavailable in this browser. Use the verified static turntable below.");
      return;
    }
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(globalThis.devicePixelRatio || 1, MAX_DEVICE_PIXEL_RATIO));
    renderer.outputColorSpace = SRGBColorSpace;
    renderer.toneMapping = ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.02;
    renderer.shadowMap.enabled = false;
    const scene = new Scene();
    const camera = new PerspectiveCamera(30, 1, 0.01, 100);
    const turntable = new Group();
    scene.add(turntable);
    const ambient = new HemisphereLight(new Color(0xffffff), new Color(0xc2c5c8), 2.2);
    const key = new DirectionalLight(0xffffff, 3.1);
    key.position.set(4, 5, 7);
    const fill = new DirectionalLight(0xbec8d4, 1.4);
    fill.position.set(-5, 1, 3);
    scene.add(ambient, key, fill);
    rendererRef.current = renderer;
    sceneRef.current = scene;
    cameraRef.current = camera;
    turntableRef.current = turntable;

    const resize = () => {
      const width = Math.max(1, canvas.clientWidth);
      const height = Math.max(1, canvas.clientHeight);
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.render(scene, camera);
    };
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);
    resize();

    return () => {
      observer.disconnect();
      renderer.setAnimationLoop(null);
      if (modelRef.current) disposeObject(modelRef.current);
      scene.clear();
      renderer.dispose();
      // React deliberately performs a mount → cleanup → remount cycle in
      // development. Losing the context synchronously makes that second
      // renderer inherit a dead context from the same canvas. Defer the hard
      // release and perform it only after a real DOM removal; ordinary
      // renderer disposal still releases all Three-owned resources now.
      queueMicrotask(() => {
        if (!canvas.isConnected) {
          renderer.forceContextLoss();
          renderer.domElement.width = 1;
          renderer.domElement.height = 1;
        }
      });
      rendererRef.current = undefined;
      cameraRef.current = undefined;
      sceneRef.current = undefined;
      turntableRef.current = undefined;
      modelRef.current = undefined;
    };
  }, []);

  useEffect(() => {
    const turntable = turntableRef.current;
    const camera = cameraRef.current;
    const renderer = rendererRef.current;
    const scene = sceneRef.current;
    if (!turntable || !camera || !renderer || !scene) return;
    modelLoadMountedRef.current = true;
    if (modelLoadAbortTimerRef.current !== undefined) {
      window.clearTimeout(modelLoadAbortTimerRef.current);
      modelLoadAbortTimerRef.current = undefined;
    }
    const key = `${model.url}:${model.sha256}`;
    let load = modelLoadRef.current;
    if (!load || load.key !== key) {
      load?.controller.abort();
      const controller = new AbortController();
      load = {
        key,
        controller,
        promise: loadCandidate(model, controller.signal),
      };
      modelLoadRef.current = load;
    }
    let active = true;
    callbacks.current.onLoading(true);
    void load.promise.then(
      (gltf) => {
        if (!active) {
          // A StrictMode cleanup is immediately followed by a remount that
          // consumes this same verified result. Dispose only when there is no
          // live consumer; the active remount owns disposal otherwise.
          if (!modelLoadMountedRef.current) disposeObject(gltf.scene);
          return;
        }
        modelRef.current = gltf.scene;
        const bounds = new Box3().setFromObject(gltf.scene);
        const center = bounds.getCenter(new Vector3());
        const size = bounds.getSize(new Vector3());
        gltf.scene.position.sub(center);
        turntable.add(gltf.scene);
        const radius = Math.max(size.x, size.y, size.z, 0.1) * 0.5;
        const distance = radius / Math.tan((camera.fov * Math.PI / 180) / 2) * 1.35;
        camera.position.set(0, radius * 0.22, distance);
        camera.near = Math.max(0.01, distance / 100);
        camera.far = Math.max(20, distance * 12);
        camera.lookAt(0, 0, 0);
        camera.updateProjectionMatrix();
        callbacks.current.onLoading(false);
        callbacks.current.onReady();
        renderer.render(scene, camera);
      },
      (error: unknown) => {
        if (!active || load.controller.signal.aborted) return;
        callbacks.current.onLoading(false);
        callbacks.current.onError(error instanceof Error ? error.message : "The candidate model could not be rendered.");
      },
    );
    return () => {
      active = false;
      modelLoadMountedRef.current = false;
      // Defer cancellation by one task so React's development-only remount
      // can reclaim the in-flight 35 MB request without creating a duplicate
      // or a false network-abort diagnostic. A real route departure still
      // cancels promptly.
      modelLoadAbortTimerRef.current = window.setTimeout(() => {
        if (!modelLoadMountedRef.current) {
          load.controller.abort();
          if (modelLoadRef.current === load) modelLoadRef.current = undefined;
        }
      }, 0);
    };
  }, [model]);

  useEffect(() => {
    const renderer = rendererRef.current;
    const scene = sceneRef.current;
    const camera = cameraRef.current;
    const turntable = turntableRef.current;
    if (!renderer || !scene || !camera || !turntable) return;
    let last = performance.now();
    const render = (time = performance.now()) => {
      const delta = Math.min(50, time - last);
      last = time;
      if (playingRef.current && visibleRef.current) yawRef.current = (yawRef.current + delta * 0.018) % 360;
      turntable.rotation.y = yawRef.current * Math.PI / 180;
      renderer.render(scene, camera);
    };
    if (visible && playing) renderer.setAnimationLoop(render);
    else {
      renderer.setAnimationLoop(null);
      render();
    }
    return () => renderer.setAnimationLoop(null);
  }, [playing, visible, yawDegrees]);

  return (
    <canvas
      ref={canvasRef}
      className="candidate-review__canvas"
      aria-label="Unapproved 3D candidate turntable"
      tabIndex={0}
      data-testid="candidate-review-canvas"
    />
  );
}

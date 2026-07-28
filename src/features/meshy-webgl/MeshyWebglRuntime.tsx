import { useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  ACESFilmicToneMapping,
  DirectionalLight,
  BufferGeometry,
  Euler,
  HemisphereLight,
  Material,
  Mesh,
  Object3D,
  PerspectiveCamera,
  Quaternion,
  Scene,
  SRGBColorSpace,
  Texture,
  Vector3,
  WebGLRenderer,
} from "three";
import type { GLTF } from "three/addons/loaders/GLTFLoader.js";
import { resolvePartTransform, type MeshyMotionPresentation } from "./meshyMotionState";
import {
  MESHY_WEBGL_LIMITS,
  meshyWebglAssetUrl,
  type MeshyWebglManifest,
  type MeshyWebglPart,
} from "./meshyWebglManifest";

export interface MeshyWebglRuntimeProps {
  readonly manifest: MeshyWebglManifest;
  readonly presentation: MeshyMotionPresentation;
  readonly visible: boolean;
  readonly onProgress: (progress: number) => void;
  readonly onReady: () => void;
  readonly onError: (message: string) => void;
}

interface BaseTransform {
  readonly position: Vector3;
  readonly quaternion: Quaternion;
  readonly scale: Vector3;
}

interface PreparedPart {
  readonly definition: MeshyWebglPart;
  readonly object: Object3D;
  readonly base: BaseTransform;
}

interface PreparedAsset {
  readonly gltf: GLTF;
  readonly scene: Object3D;
  readonly parts: readonly PreparedPart[];
}

const GLB_MAGIC = 0x4654_6c67;
const GLB_JSON_CHUNK = 0x4e4f_534a;

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: ArrayBuffer): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("The browser cannot verify the approved model digest.");
  return hex(await globalThis.crypto.subtle.digest("SHA-256", value));
}

/** Reject GLBs that could trigger unreceipted secondary network requests. */
export function assertEmbeddedGlb(value: ArrayBuffer): void {
  if (value.byteLength < 20) throw new Error("The approved model is not a complete GLB container.");
  const view = new DataView(value);
  if (view.getUint32(0, true) !== GLB_MAGIC || view.getUint32(4, true) !== 2) {
    throw new Error("The approved model is not a GLB 2.0 container.");
  }
  if (view.getUint32(8, true) !== value.byteLength) throw new Error("The approved GLB length header does not match its bytes.");
  const jsonLength = view.getUint32(12, true);
  if (view.getUint32(16, true) !== GLB_JSON_CHUNK || jsonLength <= 0 || jsonLength + 20 > value.byteLength) {
    throw new Error("The approved GLB does not contain a valid JSON descriptor.");
  }
  let descriptor: Record<string, unknown>;
  try {
    const json = new TextDecoder().decode(new Uint8Array(value, 20, jsonLength)).replace(/[\u0000\u0020]+$/u, "");
    descriptor = JSON.parse(json) as Record<string, unknown>;
  } catch {
    throw new Error("The approved GLB descriptor could not be parsed.");
  }
  const hasExternalUri = (items: unknown): boolean => Array.isArray(items) && items.some((item) => (
    Boolean(item && typeof item === "object" && "uri" in item && typeof (item as { uri?: unknown }).uri === "string")
  ));
  if (hasExternalUri(descriptor.buffers) || hasExternalUri(descriptor.images)) {
    throw new Error("The approved GLB must embed every buffer and image.");
  }
}

async function readBoundedResponse(
  response: Response,
  expectedBytes: number,
  signal: AbortSignal,
  onProgress: (progress: number) => void,
): Promise<ArrayBuffer> {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MESHY_WEBGL_LIMITS.maximumModelBytes) {
    throw new Error("The approved model response exceeds the WebGL delivery budget.");
  }
  if (Number.isFinite(declaredLength) && declaredLength > 0 && declaredLength !== expectedBytes) {
    throw new Error("The approved model response length does not match its manifest.");
  }
  if (!response.body) {
    const value = await response.arrayBuffer();
    if (value.byteLength !== expectedBytes) throw new Error("The approved model byte count does not match its manifest.");
    onProgress(1);
    return value;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  try {
    while (true) {
      if (signal.aborted) throw new DOMException("The model load was cancelled.", "AbortError");
      const next = await reader.read();
      if (next.done) break;
      received += next.value.byteLength;
      if (received > expectedBytes || received > MESHY_WEBGL_LIMITS.maximumModelBytes) {
        throw new Error("The approved model response exceeded its declared byte budget.");
      }
      chunks.push(next.value);
      onProgress(Math.min(0.9, received / expectedBytes * 0.9));
    }
  } finally {
    reader.releaseLock();
  }
  if (received !== expectedBytes) throw new Error("The approved model byte count does not match its manifest.");
  const joinedBuffer = new ArrayBuffer(received);
  const joined = new Uint8Array(joinedBuffer);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return joinedBuffer;
}

function materialTextures(material: Material): Texture[] {
  return Object.values(material).filter((value): value is Texture => value instanceof Texture);
}

function measuredGeometry(scene: Object3D): { readonly triangles: number; readonly maximumTextureDimension: number } {
  const geometries = new Set<BufferGeometry>();
  const textures = new Set<Texture>();
  scene.traverse((object) => {
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
  let maximumTextureDimension = 0;
  textures.forEach((texture) => {
    const image = texture.image as { width?: unknown; height?: unknown } | undefined;
    const width = typeof image?.width === "number" ? image.width : 0;
    const height = typeof image?.height === "number" ? image.height : 0;
    maximumTextureDimension = Math.max(maximumTextureDimension, width, height);
  });
  return { triangles, maximumTextureDimension };
}

function isAncestor(ancestor: Object3D, object: Object3D): boolean {
  for (let current = object.parent; current; current = current.parent) if (current === ancestor) return true;
  return false;
}

function prepareAsset(gltf: GLTF, manifest: MeshyWebglManifest): PreparedAsset {
  const scene = gltf.scene;
  const measurements = measuredGeometry(scene);
  if (measurements.triangles !== manifest.model.triangleCount) {
    throw new Error("The loaded model triangle count does not match its approved manifest.");
  }
  if (measurements.maximumTextureDimension > manifest.model.maximumTextureDimension) {
    throw new Error("The loaded model contains a texture larger than its approved manifest permits.");
  }
  const parts = manifest.parts.map((definition) => {
    const matches: Object3D[] = [];
    scene.traverse((object) => { if (object.name === definition.nodeName) matches.push(object); });
    if (matches.length !== 1) throw new Error(`Approved part ${definition.id} must map to exactly one GLB node.`);
    const object = matches[0]!;
    return {
      definition,
      object,
      base: {
        position: object.position.clone(),
        quaternion: object.quaternion.clone(),
        scale: object.scale.clone(),
      },
    };
  });
  for (const left of parts) for (const right of parts) {
    if (left !== right && isAncestor(left.object, right.object)) {
      throw new Error(`Approved part ${left.definition.id} cannot contain another independently animated part.`);
    }
  }
  return { gltf, scene, parts };
}

function disposeAsset(asset: PreparedAsset): void {
  const geometries = new Set<BufferGeometry>();
  const materials = new Set<Material>();
  const textures = new Set<Texture>();
  asset.scene.traverse((object) => {
    if (!(object instanceof Mesh)) return;
    geometries.add(object.geometry);
    const meshMaterials = Array.isArray(object.material) ? object.material : [object.material];
    meshMaterials.forEach((material) => {
      materials.add(material);
      materialTextures(material).forEach((texture) => textures.add(texture));
    });
  });
  textures.forEach((texture) => {
    const image = texture.image as { close?: () => void } | undefined;
    image?.close?.();
    texture.dispose();
  });
  materials.forEach((material) => material.dispose());
  geometries.forEach((geometry) => geometry.dispose());
  asset.scene.clear();
}

async function loadApprovedAsset(
  manifest: MeshyWebglManifest,
  signal: AbortSignal,
  onProgress: (progress: number) => void,
): Promise<PreparedAsset> {
  const response = await fetch(meshyWebglAssetUrl(manifest.model.path), {
    signal,
    cache: "force-cache",
    credentials: "same-origin",
    headers: { Accept: "model/gltf-binary,application/octet-stream" },
  });
  if (!response.ok) throw new Error(`The approved model request returned HTTP ${response.status}.`);
  const bytes = await readBoundedResponse(response, manifest.model.bytes, signal, onProgress);
  assertEmbeddedGlb(bytes);
  if (await sha256(bytes) !== manifest.model.sha256) throw new Error("The approved model failed its SHA-256 integrity check.");
  onProgress(0.94);
  const [{ GLTFLoader }, { MeshoptDecoder }] = await Promise.all([
    import("three/addons/loaders/GLTFLoader.js"),
    import("three/addons/libs/meshopt_decoder.module.js"),
  ]);
  const loader = new GLTFLoader();
  if (manifest.model.compression === "meshopt") loader.setMeshoptDecoder(MeshoptDecoder);
  const gltf = await loader.parseAsync(bytes, "");
  if (signal.aborted) {
    const abandoned = prepareAsset(gltf, manifest);
    disposeAsset(abandoned);
    throw new DOMException("The model load was cancelled.", "AbortError");
  }
  const prepared = prepareAsset(gltf, manifest);
  onProgress(1);
  return prepared;
}

export default function MeshyWebglRuntime({
  manifest,
  presentation,
  visible,
  onProgress,
  onReady,
  onError,
}: MeshyWebglRuntimeProps) {
  const [asset, setAsset] = useState<PreparedAsset>();
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const rendererRef = useRef<WebGLRenderer | undefined>(undefined);
  const sceneRef = useRef<Scene | undefined>(undefined);
  const cameraRef = useRef<PerspectiveCamera | undefined>(undefined);
  const visibleRef = useRef(visible);
  const callbacks = useRef({ onProgress, onReady, onError });
  callbacks.current = { onProgress, onReady, onError };
  visibleRef.current = visible;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const renderer = new WebGLRenderer({
      canvas,
      alpha: true,
      antialias: true,
      powerPreference: "high-performance",
      preserveDrawingBuffer: false,
    });
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(globalThis.devicePixelRatio || 1, MESHY_WEBGL_LIMITS.maximumDevicePixelRatio));
    renderer.shadowMap.enabled = false;
    renderer.outputColorSpace = SRGBColorSpace;
    renderer.toneMapping = ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.05;

    const scene = new Scene();
    const camera = new PerspectiveCamera(
      manifest.camera.fieldOfViewDegrees,
      1,
      manifest.camera.near,
      manifest.camera.far,
    );
    camera.position.set(manifest.camera.position.x, manifest.camera.position.y, manifest.camera.position.z);
    camera.lookAt(manifest.camera.target.x, manifest.camera.target.y, manifest.camera.target.z);
    scene.add(new HemisphereLight(0xffffff, 0xa8adb5, 2.1));
    const key = new DirectionalLight(0xffffff, 3.2);
    key.position.set(5, 7, 8);
    key.castShadow = false;
    scene.add(key);
    const fill = new DirectionalLight(0xd9e0e8, 1.6);
    fill.position.set(-6, 1, 4);
    fill.castShadow = false;
    scene.add(fill);
    const goldEdge = new DirectionalLight(0xc5a76b, 0.9);
    goldEdge.position.set(0, -5, -3);
    goldEdge.castShadow = false;
    scene.add(goldEdge);

    rendererRef.current = renderer;
    sceneRef.current = scene;
    cameraRef.current = camera;
    const render = () => {
      if (visibleRef.current) renderer.render(scene, camera);
    };
    const resize = () => {
      const width = Math.max(1, Math.floor(canvas.clientWidth));
      const height = Math.max(1, Math.floor(canvas.clientHeight));
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      render();
    };
    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(canvas);
    resize();
    const onContextLost = (event: Event) => {
      event.preventDefault();
      callbacks.current.onError("The WebGL context was lost. The approved static identity remains available.");
    };
    canvas.addEventListener("webglcontextlost", onContextLost);
    return () => {
      canvas.removeEventListener("webglcontextlost", onContextLost);
      resizeObserver.disconnect();
      renderer.setAnimationLoop(null);
      renderer.dispose();
      renderer.forceContextLoss();
      scene.clear();
      rendererRef.current = undefined;
      sceneRef.current = undefined;
      cameraRef.current = undefined;
    };
  }, [manifest.camera]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    callbacks.current.onProgress(0);
    void loadApprovedAsset(manifest, controller.signal, (progress) => callbacks.current.onProgress(progress)).then(
      (loaded) => {
        if (!active) {
          disposeAsset(loaded);
          return;
        }
        setAsset(loaded);
        callbacks.current.onReady();
      },
      (error: unknown) => {
        if (!active || (error instanceof DOMException && error.name === "AbortError")) return;
        callbacks.current.onError(error instanceof Error ? error.message : "The approved model could not be loaded safely.");
      },
    );
    return () => {
      active = false;
      controller.abort();
    };
  }, [manifest]);

  useEffect(() => {
    if (!asset || !sceneRef.current) return;
    sceneRef.current.add(asset.scene);
    rendererRef.current?.render(sceneRef.current, cameraRef.current!);
    return () => {
      sceneRef.current?.remove(asset.scene);
      disposeAsset(asset);
    };
  }, [asset]);

  useLayoutEffect(() => {
    if (!asset) return;
    asset.parts.forEach(({ definition, object, base }) => {
      const resolved = resolvePartTransform(definition, presentation);
      object.position.set(
        base.position.x + resolved.position.x,
        base.position.y + resolved.position.y,
        base.position.z + resolved.position.z,
      );
      const deltaRotation = new Quaternion().setFromEuler(new Euler(
        resolved.rotationRadians.x,
        resolved.rotationRadians.y,
        resolved.rotationRadians.z,
        "XYZ",
      ));
      object.quaternion.copy(base.quaternion).multiply(deltaRotation);
      object.scale.set(
        base.scale.x * resolved.scale.x,
        base.scale.y * resolved.scale.y,
        base.scale.z * resolved.scale.z,
      );
      object.updateMatrix();
      object.updateMatrixWorld(true);
    });
    if (visible && rendererRef.current && sceneRef.current && cameraRef.current) {
      rendererRef.current.render(sceneRef.current, cameraRef.current);
    }
  }, [asset, presentation, visible]);

  return (
    <div
      className="meshy-webgl__runtime"
      role="img"
      aria-label={`Interactive ${presentation.to.replace("-", " ")} view of the approved Ti-Scale titanium core`}
      data-webgl-active={visible ? "true" : "false"}
    >
      <canvas
        ref={canvasRef}
        aria-hidden="true"
      />
    </div>
  );
}

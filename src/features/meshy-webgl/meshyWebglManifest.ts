import { assetUrl } from "../../lib/assetUrl";

export const MESHY_WEBGL_MANIFEST_PATH = "brand-v2/source/meshy-webgl/approved-webgl-manifest.json";
export const APPROVED_IDENTITY_SOURCE_PATH = "brand-v2/source/higgsfield-motion/00-input-ti-scale-core-5634dadb.png";

export const MESHY_WEBGL_LIMITS = Object.freeze({
  maximumModelBytes: 64 * 1024 * 1024,
  maximumTriangles: 600_000,
  maximumTextureDimension: 4_096,
  maximumDevicePixelRatio: 1.75,
});

export type MeshyAssemblyState = "assembled" | "exploded" | "chassis" | "section-formation";

export interface MeshyVector3 {
  readonly x: number;
  readonly y: number;
  readonly z: number;
}

export interface MeshyPartTransform {
  /** Local offset relative to the authored transform stored in the GLB. */
  readonly position: MeshyVector3;
  /** Local Euler delta, in radians, relative to the authored GLB rotation. */
  readonly rotationRadians: MeshyVector3;
  /** Per-axis multiplier applied to the authored GLB scale. */
  readonly scale: MeshyVector3;
}

export interface MeshyWebglPart {
  readonly id: string;
  readonly nodeName: string;
  readonly sectionId: string;
  /** A normalized direction authored from this part's local surface normals. */
  readonly localNormal: MeshyVector3;
  readonly explodeDistance: number;
  readonly chassis: MeshyPartTransform;
  readonly sectionFormation: MeshyPartTransform;
}

export interface MeshyWebglManifest {
  readonly schemaVersion: 1;
  readonly status: "operator-approved";
  readonly identitySourcePath: typeof APPROVED_IDENTITY_SOURCE_PATH;
  readonly approval: {
    readonly receiptId: string;
    readonly approvedAt: string;
    readonly approvedBy: "operator";
  };
  readonly model: {
    readonly path: string;
    readonly sha256: string;
    readonly bytes: number;
    readonly triangleCount: number;
    readonly maximumTextureDimension: number;
    readonly container: "glb-embedded";
    readonly compression: "none" | "meshopt";
  };
  readonly camera: {
    readonly position: MeshyVector3;
    readonly target: MeshyVector3;
    readonly fieldOfViewDegrees: number;
    readonly near: number;
    readonly far: number;
  };
  readonly fallback: {
    readonly path: typeof APPROVED_IDENTITY_SOURCE_PATH;
    readonly alt: string;
    readonly width: 1344;
    readonly height: 768;
  };
  readonly parts: readonly MeshyWebglPart[];
}

const MODEL_ROOT = "brand-v2/optimized/meshy-webgl/";
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const RECEIPT_PATTERN = /^approval_[a-z0-9][a-z0-9_-]{7,127}$/u;

function record(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as Record<string, unknown>;
}

function string(value: unknown, name: string): string {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error(`${name} must be a non-empty string`);
  return value.trim();
}

function finite(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`${name} must be finite`);
  return value;
}

function positive(value: unknown, name: string): number {
  const parsed = finite(value, name);
  if (parsed <= 0) throw new Error(`${name} must be positive`);
  return parsed;
}

function positiveInteger(value: unknown, name: string): number {
  const parsed = positive(value, name);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${name} must be a safe integer`);
  return parsed;
}

function vector(value: unknown, name: string): MeshyVector3 {
  const input = record(value, name);
  return {
    x: finite(input.x, `${name}.x`),
    y: finite(input.y, `${name}.y`),
    z: finite(input.z, `${name}.z`),
  };
}

function normalizedVector(value: unknown, name: string): MeshyVector3 {
  const parsed = vector(value, name);
  const length = Math.hypot(parsed.x, parsed.y, parsed.z);
  if (length < 0.999 || length > 1.001) throw new Error(`${name} must be normalized`);
  return parsed;
}

function transform(value: unknown, name: string): MeshyPartTransform {
  const input = record(value, name);
  const scale = vector(input.scale, `${name}.scale`);
  if (scale.x <= 0 || scale.y <= 0 || scale.z <= 0) throw new Error(`${name}.scale components must be positive`);
  return {
    position: vector(input.position, `${name}.position`),
    rotationRadians: vector(input.rotationRadians, `${name}.rotationRadians`),
    scale,
  };
}

function localPath(value: unknown, name: string, root: string): string {
  const path = string(value, name).replace(/^\/+/, "");
  if (!path.startsWith(root) || path.includes("..") || path.includes("\\") || /[?#]/u.test(path)) {
    throw new Error(`${name} must stay inside ${root}`);
  }
  return path;
}

function isoTimestamp(value: unknown, name: string): string {
  const parsed = string(value, name);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(parsed) || Number.isNaN(Date.parse(parsed))) {
    throw new Error(`${name} must be a UTC ISO timestamp`);
  }
  return parsed;
}

function parsePart(value: unknown, index: number): MeshyWebglPart {
  const input = record(value, `parts[${index}]`);
  return {
    id: string(input.id, `parts[${index}].id`),
    nodeName: string(input.nodeName, `parts[${index}].nodeName`),
    sectionId: string(input.sectionId, `parts[${index}].sectionId`),
    localNormal: normalizedVector(input.localNormal, `parts[${index}].localNormal`),
    explodeDistance: positive(input.explodeDistance, `parts[${index}].explodeDistance`),
    chassis: transform(input.chassis, `parts[${index}].chassis`),
    sectionFormation: transform(input.sectionFormation, `parts[${index}].sectionFormation`),
  };
}

/**
 * Fail closed until a real, content-addressed model has an operator approval
 * receipt. Candidate manifests and provider job records are intentionally not
 * accepted by this parser.
 */
export function parseApprovedMeshyWebglManifest(value: unknown): MeshyWebglManifest {
  const input = record(value, "manifest");
  if (input.schemaVersion !== 1) throw new Error("manifest.schemaVersion must be 1");
  if (input.status !== "operator-approved") throw new Error("manifest.status must be operator-approved");
  if (input.identitySourcePath !== APPROVED_IDENTITY_SOURCE_PATH) {
    throw new Error("manifest.identitySourcePath does not match the approved Ti-Scale identity source");
  }

  const approval = record(input.approval, "approval");
  const receiptId = string(approval.receiptId, "approval.receiptId");
  if (!RECEIPT_PATTERN.test(receiptId)) throw new Error("approval.receiptId is not a valid operator approval receipt");
  if (approval.approvedBy !== "operator") throw new Error("approval.approvedBy must be operator");

  const model = record(input.model, "model");
  const sha256 = string(model.sha256, "model.sha256").toLowerCase();
  if (!SHA256_PATTERN.test(sha256)) throw new Error("model.sha256 must be a lowercase SHA-256 digest");
  const modelPath = localPath(model.path, "model.path", MODEL_ROOT);
  if (!modelPath.endsWith(".glb") || !modelPath.toLowerCase().includes(sha256.slice(0, 12))) {
    throw new Error("model.path must be a content-addressed .glb containing the first 12 SHA-256 characters");
  }
  const bytes = positiveInteger(model.bytes, "model.bytes");
  const triangleCount = positiveInteger(model.triangleCount, "model.triangleCount");
  const maximumTextureDimension = positiveInteger(model.maximumTextureDimension, "model.maximumTextureDimension");
  if (bytes > MESHY_WEBGL_LIMITS.maximumModelBytes) throw new Error("model.bytes exceeds the WebGL delivery budget");
  if (triangleCount > MESHY_WEBGL_LIMITS.maximumTriangles) throw new Error("model.triangleCount exceeds the WebGL delivery budget");
  if (maximumTextureDimension > MESHY_WEBGL_LIMITS.maximumTextureDimension) {
    throw new Error("model.maximumTextureDimension exceeds the WebGL delivery budget");
  }
  if (model.container !== "glb-embedded") throw new Error("model.container must be glb-embedded");
  if (model.compression !== "none" && model.compression !== "meshopt") {
    throw new Error("model.compression must be none or meshopt");
  }

  const camera = record(input.camera, "camera");
  const near = positive(camera.near, "camera.near");
  const far = positive(camera.far, "camera.far");
  const fieldOfViewDegrees = positive(camera.fieldOfViewDegrees, "camera.fieldOfViewDegrees");
  if (far <= near) throw new Error("camera.far must be greater than camera.near");
  if (fieldOfViewDegrees >= 120) throw new Error("camera.fieldOfViewDegrees must be below 120");

  const fallback = record(input.fallback, "fallback");
  if (fallback.path !== APPROVED_IDENTITY_SOURCE_PATH) throw new Error("fallback.path must use the approved identity source");
  if (fallback.width !== 1344 || fallback.height !== 768) throw new Error("fallback dimensions must match the approved identity source");

  if (!Array.isArray(input.parts) || input.parts.length < 2) throw new Error("manifest.parts must contain at least two authored parts");
  const parts = input.parts.map(parsePart);
  if (new Set(parts.map((part) => part.id)).size !== parts.length) throw new Error("manifest.parts contains duplicate IDs");
  if (new Set(parts.map((part) => part.nodeName)).size !== parts.length) throw new Error("manifest.parts contains duplicate node names");

  return {
    schemaVersion: 1,
    status: "operator-approved",
    identitySourcePath: APPROVED_IDENTITY_SOURCE_PATH,
    approval: {
      receiptId,
      approvedAt: isoTimestamp(approval.approvedAt, "approval.approvedAt"),
      approvedBy: "operator",
    },
    model: {
      path: modelPath,
      sha256,
      bytes,
      triangleCount,
      maximumTextureDimension,
      container: "glb-embedded",
      compression: model.compression,
    },
    camera: {
      position: vector(camera.position, "camera.position"),
      target: vector(camera.target, "camera.target"),
      fieldOfViewDegrees,
      near,
      far,
    },
    fallback: {
      path: APPROVED_IDENTITY_SOURCE_PATH,
      alt: string(fallback.alt, "fallback.alt"),
      width: 1344,
      height: 768,
    },
    parts,
  };
}

export function meshyWebglAssetUrl(path: string): string {
  if (path === APPROVED_IDENTITY_SOURCE_PATH) return assetUrl(path);
  return assetUrl(localPath(path, "asset path", MODEL_ROOT));
}

let manifestRequest: Promise<MeshyWebglManifest | null> | undefined;

/** One request across React Strict Mode's development mount probe. */
export function loadApprovedMeshyWebglManifest(): Promise<MeshyWebglManifest | null> {
  manifestRequest ??= fetch(assetUrl(MESHY_WEBGL_MANIFEST_PATH), {
    cache: "no-cache",
    headers: { Accept: "application/json" },
  }).then(async (response) => {
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`Approved WebGL manifest request returned HTTP ${response.status}`);
    return parseApprovedMeshyWebglManifest(await response.json());
  });
  return manifestRequest;
}

export function resetMeshyManifestRequestForTests(): void {
  manifestRequest = undefined;
}

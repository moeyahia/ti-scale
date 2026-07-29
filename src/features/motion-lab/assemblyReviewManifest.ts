import { assetUrl } from "../../lib/assetUrl";

export const ASSEMBLY_REVIEW_MANIFEST_PATH = "review-assets/ti-scale-14-elements/v1/assembly-manifest.json";

export interface AssemblyVector3 { readonly x: number; readonly y: number; readonly z: number }
export interface AssemblyQuaternion { readonly x: number; readonly y: number; readonly z: number; readonly w: number }

export interface AssemblyReviewModel {
  readonly number: number;
  readonly id: string;
  readonly name: string;
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly triangleCount: number;
  readonly meshPrimitiveCount: number;
  readonly materialFamily: "cool-brushed-titanium" | "architectural-graphite" | "champagne-gold-carrier";
  readonly pivot: {
    readonly pixel: readonly [number, number];
    readonly localModel: AssemblyVector3;
    readonly provenance: string;
  };
  readonly canonicalization: {
    readonly rootOffset: AssemblyVector3;
    readonly uniformScale: number;
    readonly provenance: string;
  };
  readonly assembly: {
    readonly position: AssemblyVector3;
    readonly quaternion: AssemblyQuaternion;
    readonly scale: AssemblyVector3;
    readonly zLayer: number;
  };
  readonly explosion: {
    readonly direction: AssemblyVector3;
    readonly unseatWorld: number;
    readonly radialDistanceWorld: number;
    readonly position: AssemblyVector3;
    readonly provenance: string;
  };
}

export interface AssemblyReviewFastener {
  readonly id: string;
  readonly owner: string;
  readonly seam: string;
  readonly pixel: readonly [number, number];
  readonly radiusWorld: number;
  readonly assembledPosition: AssemblyVector3;
  readonly ownerLocalOffset: AssemblyVector3;
  readonly jointBetween: readonly string[] | null;
}

export interface AssemblyReviewManifest {
  readonly schemaVersion: 1;
  readonly status: "review-candidate";
  readonly title: string;
  readonly reviewBoundary: "Review candidate — not approved for hero";
  readonly generatedAt: string;
  readonly sourceArtwork: {
    readonly path: string;
    readonly sha256: string;
    readonly width: number;
    readonly height: number;
    readonly visibleBoundsPixels: readonly [number, number, number, number];
    readonly protectedAperturePixels: readonly (readonly [number, number])[];
  };
  readonly camera: {
    readonly kind: "perspective";
    readonly fieldOfViewDegrees: number;
    readonly near: number;
    readonly far: number;
    readonly position: AssemblyVector3;
    readonly target: AssemblyVector3;
    readonly defaultYawDegrees: number;
    readonly defaultPitchDegrees: number;
    readonly minimumDistance: number;
    readonly maximumDistance: number;
    readonly maximumDistanceProvenance: string;
  };
  readonly lights: readonly Record<string, unknown>[];
  readonly fastenerGeometry: {
    readonly kind: "instanced-low-profile-cap";
    readonly count: 26;
    readonly radialSegments: number;
    readonly depthWorld: number;
    readonly material: { readonly color: string; readonly metalness: number; readonly roughness: number };
  };
  readonly models: readonly AssemblyReviewModel[];
  readonly fasteners: readonly AssemblyReviewFastener[];
  readonly visualIntegrity: {
    readonly expectedModelMeshCount: number;
    readonly minimumDrawCalls: number;
    readonly minimumVisibleModelCoverage: number;
    readonly assay: string;
  };
  readonly budgets: {
    readonly maximumModels: 14;
    readonly maximumFasteners: 26;
    readonly maximumTotalTriangles: number;
    readonly maximumTotalModelBytes: number;
    readonly maximumDevicePixelRatio: number;
  };
}

type JsonRecord = Record<string, unknown>;
const SHA256 = /^[a-f0-9]{64}$/u;
const REVIEW_ROOT = "review-assets/ti-scale-14-elements/v1/";

function record(value: unknown, name: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as JsonRecord;
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
  const result = finite(value, name);
  if (result <= 0) throw new Error(`${name} must be positive`);
  return result;
}

function integer(value: unknown, name: string): number {
  const result = positive(value, name);
  if (!Number.isSafeInteger(result)) throw new Error(`${name} must be a safe integer`);
  return result;
}

function tuple(value: unknown, name: string, size: number): number[] {
  if (!Array.isArray(value) || value.length !== size) throw new Error(`${name} must have ${size} values`);
  return value.map((entry, index) => finite(entry, `${name}[${index}]`));
}

function vector3(value: unknown, name: string): AssemblyVector3 {
  const [x, y, z] = tuple(value, name, 3);
  return { x, y, z };
}

function quaternion(value: unknown, name: string): AssemblyQuaternion {
  const [x, y, z, w] = tuple(value, name, 4);
  return { x, y, z, w };
}

function localPath(value: unknown, name: string, root = REVIEW_ROOT): string {
  const path = string(value, name).replace(/^\/+/, "");
  if (!path.startsWith(root) || path.includes("..") || path.includes("\\") || /[?#]/u.test(path)) {
    throw new Error(`${name} must stay inside ${root}`);
  }
  return path;
}

function parseModel(value: unknown, index: number): AssemblyReviewModel {
  const input = record(value, `models[${index}]`);
  const hash = string(input.sha256, `models[${index}].sha256`);
  if (!SHA256.test(hash)) throw new Error(`models[${index}].sha256 must be a lowercase SHA-256 digest`);
  const path = localPath(input.path, `models[${index}].path`);
  if (!path.endsWith(`${hash.slice(0, 12)}.glb`)) throw new Error(`models[${index}].path is not content addressed`);
  const materialFamily = string(input.materialFamily, `models[${index}].materialFamily`);
  if (!(["cool-brushed-titanium", "architectural-graphite", "champagne-gold-carrier"] as const).includes(materialFamily as never)) {
    throw new Error(`models[${index}].materialFamily is not recognized`);
  }
  const pivot = record(input.pivot, `models[${index}].pivot`);
  const canonicalization = record(input.canonicalization, `models[${index}].canonicalization`);
  const assembly = record(input.assembly, `models[${index}].assembly`);
  const explosion = record(input.explosion, `models[${index}].explosion`);
  const pixel = tuple(pivot.pixel, `models[${index}].pivot.pixel`, 2) as [number, number];
  return {
    number: integer(input.number, `models[${index}].number`),
    id: string(input.id, `models[${index}].id`),
    name: string(input.name, `models[${index}].name`),
    path,
    sha256: hash,
    bytes: integer(input.bytes, `models[${index}].bytes`),
    triangleCount: integer(input.triangleCount, `models[${index}].triangleCount`),
    meshPrimitiveCount: integer(input.meshPrimitiveCount, `models[${index}].meshPrimitiveCount`),
    materialFamily: materialFamily as AssemblyReviewModel["materialFamily"],
    pivot: { pixel, localModel: vector3(pivot.localModel, `models[${index}].pivot.localModel`), provenance: string(pivot.provenance, `models[${index}].pivot.provenance`) },
    canonicalization: {
      rootOffset: vector3(canonicalization.rootOffset, `models[${index}].canonicalization.rootOffset`),
      uniformScale: positive(canonicalization.uniformScale, `models[${index}].canonicalization.uniformScale`),
      provenance: string(canonicalization.provenance, `models[${index}].canonicalization.provenance`),
    },
    assembly: {
      position: vector3(assembly.position, `models[${index}].assembly.position`),
      quaternion: quaternion(assembly.quaternion, `models[${index}].assembly.quaternion`),
      scale: vector3(assembly.scale, `models[${index}].assembly.scale`),
      zLayer: finite(assembly.zLayer, `models[${index}].assembly.zLayer`),
    },
    explosion: {
      direction: vector3(explosion.direction, `models[${index}].explosion.direction`),
      unseatWorld: finite(explosion.unseatWorld, `models[${index}].explosion.unseatWorld`),
      radialDistanceWorld: positive(explosion.radialDistanceWorld, `models[${index}].explosion.radialDistanceWorld`),
      position: vector3(explosion.position, `models[${index}].explosion.position`),
      provenance: string(explosion.provenance, `models[${index}].explosion.provenance`),
    },
  };
}

function parseFastener(value: unknown, index: number): AssemblyReviewFastener {
  const input = record(value, `fasteners[${index}]`);
  const pixel = tuple(input.pixel, `fasteners[${index}].pixel`, 2) as [number, number];
  const jointBetween = input.jointBetween === null
    ? null
    : (Array.isArray(input.jointBetween) ? input.jointBetween.map((entry, item) => string(entry, `fasteners[${index}].jointBetween[${item}]`)) : null);
  return {
    id: string(input.id, `fasteners[${index}].id`),
    owner: string(input.owner, `fasteners[${index}].owner`),
    seam: string(input.seam, `fasteners[${index}].seam`),
    pixel,
    radiusWorld: positive(input.radiusWorld, `fasteners[${index}].radiusWorld`),
    assembledPosition: vector3(input.assembledPosition, `fasteners[${index}].assembledPosition`),
    ownerLocalOffset: vector3(input.ownerLocalOffset, `fasteners[${index}].ownerLocalOffset`),
    jointBetween,
  };
}

export function parseAssemblyReviewManifest(value: unknown): AssemblyReviewManifest {
  const input = record(value, "manifest");
  if (input.schemaVersion !== 1) throw new Error("manifest.schemaVersion must be 1");
  if (input.status !== "review-candidate") throw new Error("manifest.status must remain review-candidate");
  if (input.reviewBoundary !== "Review candidate — not approved for hero") throw new Error("manifest.reviewBoundary is not explicit");
  const models = Array.isArray(input.models) ? input.models.map(parseModel) : [];
  const fasteners = Array.isArray(input.fasteners) ? input.fasteners.map(parseFastener) : [];
  if (models.length !== 14 || new Set(models.map((model) => model.id)).size !== 14) throw new Error("manifest must contain 14 unique locked models");
  if (fasteners.length !== 26 || new Set(fasteners.map((fastener) => fastener.id)).size !== 26) throw new Error("manifest must contain 26 unique fasteners");
  const modelIds = new Set(models.map((model) => model.id));
  if (fasteners.some((fastener) => !modelIds.has(fastener.owner))) throw new Error("every fastener must reference a locked model owner");
  const budgets = record(input.budgets, "manifest.budgets");
  const visualIntegrity = record(input.visualIntegrity, "manifest.visualIntegrity");
  const totalBytes = models.reduce((sum, model) => sum + model.bytes, 0);
  const totalTriangles = models.reduce((sum, model) => sum + model.triangleCount, 0);
  const maximumTotalModelBytes = integer(budgets.maximumTotalModelBytes, "budgets.maximumTotalModelBytes");
  const maximumTotalTriangles = integer(budgets.maximumTotalTriangles, "budgets.maximumTotalTriangles");
  if (totalBytes > maximumTotalModelBytes || totalTriangles > maximumTotalTriangles) throw new Error("assembly exceeds its review delivery budget");
  const expectedModelMeshCount = integer(visualIntegrity.expectedModelMeshCount, "visualIntegrity.expectedModelMeshCount");
  const actualModelMeshCount = models.reduce((sum, model) => sum + model.meshPrimitiveCount, 0);
  if (expectedModelMeshCount !== actualModelMeshCount) throw new Error("visualIntegrity.expectedModelMeshCount does not match the locked GLB primitives");
  const minimumDrawCalls = integer(visualIntegrity.minimumDrawCalls, "visualIntegrity.minimumDrawCalls");
  if (minimumDrawCalls < expectedModelMeshCount + 1) throw new Error("visualIntegrity.minimumDrawCalls must cover every plate primitive and the instanced fasteners");
  const minimumVisibleModelCoverage = positive(visualIntegrity.minimumVisibleModelCoverage, "visualIntegrity.minimumVisibleModelCoverage");
  if (minimumVisibleModelCoverage < 0.03 || minimumVisibleModelCoverage > 1) throw new Error("visualIntegrity.minimumVisibleModelCoverage must be between 3% and 100%");
  const camera = record(input.camera, "manifest.camera");
  const sourceArtwork = record(input.sourceArtwork, "manifest.sourceArtwork");
  const sourceHash = string(sourceArtwork.sha256, "sourceArtwork.sha256");
  if (!SHA256.test(sourceHash)) throw new Error("sourceArtwork.sha256 must be a SHA-256 digest");
  const fastenerGeometry = record(input.fastenerGeometry, "manifest.fastenerGeometry");
  const fastenerMaterial = record(fastenerGeometry.material, "manifest.fastenerGeometry.material");
  if (fastenerGeometry.kind !== "instanced-low-profile-cap" || fastenerGeometry.count !== 26) throw new Error("fastener geometry must remain one 26-instance review mesh");
  return {
    schemaVersion: 1,
    status: "review-candidate",
    title: string(input.title, "manifest.title"),
    reviewBoundary: "Review candidate — not approved for hero",
    generatedAt: string(input.generatedAt, "manifest.generatedAt"),
    sourceArtwork: {
      path: localPath(sourceArtwork.path, "sourceArtwork.path", "brand-v2/source/higgsfield-motion/"),
      sha256: sourceHash,
      width: integer(sourceArtwork.width, "sourceArtwork.width"),
      height: integer(sourceArtwork.height, "sourceArtwork.height"),
      visibleBoundsPixels: tuple(sourceArtwork.visibleBoundsPixels, "sourceArtwork.visibleBoundsPixels", 4) as [number, number, number, number],
      protectedAperturePixels: (Array.isArray(sourceArtwork.protectedAperturePixels) ? sourceArtwork.protectedAperturePixels : []).map((point, index) => tuple(point, `sourceArtwork.protectedAperturePixels[${index}]`, 2) as [number, number]),
    },
    camera: {
      kind: "perspective",
      fieldOfViewDegrees: positive(camera.fieldOfViewDegrees, "camera.fieldOfViewDegrees"),
      near: positive(camera.near, "camera.near"),
      far: positive(camera.far, "camera.far"),
      position: vector3(camera.position, "camera.position"),
      target: vector3(camera.target, "camera.target"),
      defaultYawDegrees: finite(camera.defaultYawDegrees, "camera.defaultYawDegrees"),
      defaultPitchDegrees: finite(camera.defaultPitchDegrees, "camera.defaultPitchDegrees"),
      minimumDistance: positive(camera.minimumDistance, "camera.minimumDistance"),
      maximumDistance: positive(camera.maximumDistance, "camera.maximumDistance"),
      maximumDistanceProvenance: string(camera.maximumDistanceProvenance, "camera.maximumDistanceProvenance"),
    },
    lights: Array.isArray(input.lights) ? input.lights.map((light, index) => record(light, `lights[${index}]`)) : [],
    fastenerGeometry: {
      kind: "instanced-low-profile-cap",
      count: 26,
      radialSegments: integer(fastenerGeometry.radialSegments, "fastenerGeometry.radialSegments"),
      depthWorld: positive(fastenerGeometry.depthWorld, "fastenerGeometry.depthWorld"),
      material: {
        color: string(fastenerMaterial.color, "fastenerGeometry.material.color"),
        metalness: finite(fastenerMaterial.metalness, "fastenerGeometry.material.metalness"),
        roughness: finite(fastenerMaterial.roughness, "fastenerGeometry.material.roughness"),
      },
    },
    models,
    fasteners,
    visualIntegrity: {
      expectedModelMeshCount,
      minimumDrawCalls,
      minimumVisibleModelCoverage,
      assay: string(visualIntegrity.assay, "visualIntegrity.assay"),
    },
    budgets: {
      maximumModels: 14,
      maximumFasteners: 26,
      maximumTotalTriangles,
      maximumTotalModelBytes,
      maximumDevicePixelRatio: positive(budgets.maximumDevicePixelRatio, "budgets.maximumDevicePixelRatio"),
    },
  };
}

export function assemblyReviewAssetUrl(path: string): string {
  return assetUrl(localPath(path, "assembly review asset"));
}

export async function loadAssemblyReviewManifest(signal?: AbortSignal): Promise<AssemblyReviewManifest> {
  const response = await fetch(assetUrl(ASSEMBLY_REVIEW_MANIFEST_PATH), {
    signal,
    cache: "no-cache",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error(`The assembly review manifest returned HTTP ${response.status}.`);
  return parseAssemblyReviewManifest(await response.json());
}

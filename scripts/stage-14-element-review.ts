import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const projectRoot = resolve(new URL("..", import.meta.url).pathname);
const campaignRoot = join(
  projectRoot,
  ".artifacts/meshy-candidates/20260719-ti-scale-14-independent-elements-v1",
);
const lockPath = join(campaignRoot, "batch-production-v1/receipts/14-element-individual-lock-receipt.json");
const specPath = join(campaignRoot, "specs/elements-02-14-generation-spec-v1.json");
const segmentationPath = join(
  projectRoot,
  ".artifacts/meshy-candidates/20260718-ti-scale-core/deterministic-blockout-v2/review/approved-reference-14-plate-segmentation-v1.json",
);
const publicRoot = join(projectRoot, "public/review-assets/ti-scale-14-elements/v1");
const modelRoot = join(publicRoot, "models");

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown, name: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as JsonRecord;
}

function asArray(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  return value;
}

function asString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} must be a string`);
  return value;
}

function asNumber(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`${name} must be finite`);
  return value;
}

function vector(value: unknown, name: string, length: number): number[] {
  const result = asArray(value, name).map((entry, index) => asNumber(entry, `${name}[${index}]`));
  if (result.length !== length) throw new Error(`${name} must have ${length} values`);
  return result;
}

async function json(path: string): Promise<JsonRecord> {
  return asRecord(JSON.parse(await readFile(path, "utf8")) as unknown, path);
}

async function sha256(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function glbPrimitiveCount(path: string): Promise<number> {
  const bytes = await readFile(path);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, true) !== 0x4654_6c67 || view.getUint32(4, true) !== 2 || view.getUint32(8, true) !== bytes.byteLength) {
    throw new Error(`${path} is not a valid GLB 2.0 container.`);
  }
  const jsonLength = view.getUint32(12, true);
  const descriptor = JSON.parse(
    new TextDecoder().decode(bytes.subarray(20, 20 + jsonLength)).replace(/[\u0000\u0020]+$/u, ""),
  ) as { readonly meshes?: ReadonlyArray<{ readonly primitives?: readonly unknown[] }> };
  return (descriptor.meshes ?? []).reduce((sum, mesh) => sum + (mesh.primitives?.length ?? 0), 0);
}

function round(value: number): number {
  return Number(value.toFixed(9));
}

const lock = await json(lockPath);
const spec = await json(specPath);
const segmentation = await json(segmentationPath);
const lockElements = asArray(lock.elements, "lock.elements").map((value) => asRecord(value, "lock element"));
const specElements = asArray(spec.elements, "spec.elements").map((value) => asRecord(value, "spec element"));
const fasteners = asArray(segmentation.fasteners, "segmentation.fasteners").map((value) => asRecord(value, "fastener"));
if (lockElements.length !== 14 || specElements.length !== 13 || fasteners.length !== 26) {
  throw new Error("The review input must contain exactly 14 locked elements, 13 canonical specs, and 26 fasteners.");
}

await mkdir(modelRoot, { recursive: true });

const specificationById = new Map(specElements.map((entry) => [asString(entry.id, "spec.id"), entry]));
const models: JsonRecord[] = [];

for (const element of lockElements) {
  const number = asNumber(element.number, "element.number");
  const id = asString(element.id, "element.id");
  const name = asString(element.name, "element.name");
  const sourcePath = asString(element.model_path, `${id}.model_path`);
  const expectedHash = asString(element.model_sha256, `${id}.model_sha256`);
  const expectedBytes = asNumber(element.file_size_bytes, `${id}.file_size_bytes`);
  const meshPrimitiveCount = await glbPrimitiveCount(sourcePath);
  if (meshPrimitiveCount <= 0) throw new Error(`${id} has no renderable mesh primitives.`);
  const actualHash = await sha256(sourcePath);
  const actualBytes = (await stat(sourcePath)).size;
  if (actualHash !== expectedHash || actualBytes !== expectedBytes) {
    throw new Error(`${id} no longer matches its individual lock receipt.`);
  }
  const fileName = `${String(number).padStart(2, "0")}-${id.toLowerCase().replaceAll("_", "-")}-${expectedHash.slice(0, 12)}.glb`;
  const stagedPath = join(modelRoot, fileName);
  await copyFile(sourcePath, stagedPath);
  if (await sha256(stagedPath) !== expectedHash) throw new Error(`${id} changed while being staged.`);

  if (number === 1) {
    // Element 01 predates the pivot-local canonical export used by elements
    // 02-14. Its review transform is derived once from the audited source
    // surface, the midpoint of its two exact fasteners, and its CAD landmarks.
    const pivotPixel = [678.5, 176.5];
    const positionWorld = [
      round((pivotPixel[0] - 672) * 0.01),
      round((384 - pivotPixel[1]) * 0.01),
      0.34,
    ];
    const localPivot = [-0.88458557, 0.96789292, 0.304611142];
    const uniformScale = 0.454501938;
    const direction = [0.47, 0.62, 0.55];
    const radialDistanceWorld = 2.3;
    const unseatWorld = 0.28;
    models.push({
      number,
      id,
      name,
      path: `review-assets/ti-scale-14-elements/v1/models/${fileName}`,
      sha256: expectedHash,
      bytes: expectedBytes,
      triangleCount: 18,
      meshPrimitiveCount,
      materialFamily: "cool-brushed-titanium",
      pivot: {
        pixel: pivotPixel,
        localModel: localPivot,
        provenance: "F09/F10 midpoint projected into the deterministic CAD top surface by its audited four-corner homography",
      },
      canonicalization: {
        rootOffset: localPivot.map((value) => round(-value)),
        uniformScale,
        provenance: "uniform fit inside the audited 257 x 263 pixel source envelope; no non-uniform repair",
      },
      assembly: { position: positionWorld, quaternion: [0, 0, 0, 1], scale: [1, 1, 1], zLayer: 85 },
      explosion: {
        direction,
        unseatWorld,
        radialDistanceWorld,
        position: [
          round(positionWorld[0] + direction[0] * radialDistanceWorld),
          round(positionWorld[1] + direction[1] * radialDistanceWorld),
          round(positionWorld[2] + unseatWorld + direction[2] * radialDistanceWorld),
        ],
        provenance: "deterministic interpolation between the neighboring audited crown release corridors",
      },
    });
    continue;
  }

  const elementSpec = specificationById.get(id);
  if (!elementSpec) throw new Error(`Missing canonical transform spec for ${id}.`);
  const assembly = asRecord(elementSpec.webglAssemblyTransform, `${id}.webglAssemblyTransform`);
  const explosion = asRecord(elementSpec.explosion, `${id}.explosion`);
  const pivot = asRecord(elementSpec.pivot, `${id}.pivot`);
  const materialFamily = id.includes("GOLD")
    ? "champagne-gold-carrier"
    : id.includes("_GR_")
      ? "architectural-graphite"
      : "cool-brushed-titanium";
  models.push({
    number,
    id,
    name,
    path: `review-assets/ti-scale-14-elements/v1/models/${fileName}`,
    sha256: expectedHash,
    bytes: expectedBytes,
    triangleCount: asNumber(element.triangle_count, `${id}.triangle_count`),
    meshPrimitiveCount,
    materialFamily,
    pivot: {
      pixel: vector(pivot.pixel, `${id}.pivot.pixel`, 2),
      localModel: [0, 0, 0],
      provenance: asString(pivot.mechanicalMeaning, `${id}.pivot.mechanicalMeaning`),
    },
    canonicalization: { rootOffset: [0, 0, 0], uniformScale: 1, provenance: "pivot-local canonical GLB" },
    assembly: {
      position: vector(assembly.positionWorld, `${id}.positionWorld`, 3),
      quaternion: vector(assembly.quaternion, `${id}.quaternion`, 4),
      scale: vector(assembly.scale, `${id}.scale`, 3),
      zLayer: asNumber(assembly.zLayer, `${id}.zLayer`),
    },
    explosion: {
      direction: vector(explosion.direction, `${id}.direction`, 3),
      unseatWorld: asNumber(explosion.unseatWorld, `${id}.unseatWorld`),
      radialDistanceWorld: asNumber(explosion.radialDistanceWorld, `${id}.radialDistanceWorld`),
      position: vector(explosion.explodedPositionWorld, `${id}.explodedPositionWorld`, 3),
      provenance: "audited elements-02-14 generation specification",
    },
  });
}

const modelById = new Map(models.map((entry) => [asString(entry.id, "model.id"), entry]));
const stagedFasteners = fasteners.map((fastener) => {
  const id = asString(fastener.id, "fastener.id");
  const owner = asString(fastener.owner, `${id}.owner`);
  const pixel = vector(fastener.pixel, `${id}.pixel`, 2);
  const ownerModel = modelById.get(owner);
  if (!ownerModel) throw new Error(`${id} references unknown owner ${owner}.`);
  const ownerAssembly = asRecord(ownerModel.assembly, `${owner}.assembly`);
  const ownerPosition = vector(ownerAssembly.position, `${owner}.assembly.position`, 3);
  const assembledPosition = [
    round((pixel[0] - 672) * 0.01),
    round((384 - pixel[1]) * 0.01),
    round(ownerPosition[2] + 0.065),
  ];
  return {
    id,
    owner,
    seam: asString(fastener.seam, `${id}.seam`),
    pixel,
    radiusWorld: 0.044,
    assembledPosition,
    ownerLocalOffset: assembledPosition.map((value, index) => round(value - ownerPosition[index])),
    jointBetween: fastener.jointBetween ?? null,
  };
});

const sourceArtwork = asRecord(lock.approved_artwork, "lock.approved_artwork");
const expectedModelMeshCount = models.reduce((sum, model) => sum + asNumber(model.meshPrimitiveCount, "model.meshPrimitiveCount"), 0);
const manifest = {
  schemaVersion: 1,
  status: "review-candidate",
  title: "Ti-Scale 14-element assembly",
  reviewBoundary: "Review candidate — not approved for hero",
  generatedAt: asString(lock.locked_at, "lock.locked_at"),
  sourceArtwork: {
    path: "brand-v2/source/higgsfield-motion/00-input-ti-scale-core-5634dadb.png",
    sha256: asString(sourceArtwork.sha256, "approved_artwork.sha256"),
    width: 1344,
    height: 768,
    visibleBoundsPixels: vector(sourceArtwork.visibleArtworkBoundsPixels, "approved_artwork.visibleArtworkBoundsPixels", 4),
    protectedAperturePixels: sourceArtwork.protectedAperturePixels,
  },
  coordinateContract: {
    axes: { x: "east/right", y: "north/up", z: "toward viewer" },
    canvasCenterPixels: [672, 384],
    worldUnitsPerPixel: 0.01,
    interpolation: "unseat on Z during the first 22%, then translate through the audited outward corridor; no random rotation or physics",
  },
  camera: {
    kind: "perspective",
    fieldOfViewDegrees: 34,
    near: 0.1,
    far: 100,
    position: [0.35, 0.2, 14.5],
    target: [0, 0.15, 0.2],
    defaultYawDegrees: -5,
    defaultPitchDegrees: -3,
    minimumDistance: 8,
    maximumDistance: 32,
    maximumDistanceProvenance: "bounded review-camera extension derived from the audited progress-1 transformed sphere, the current-aspect limiting field of view, and an 18% framing margin; locked geometry and explosion transforms remain unchanged",
  },
  lights: [
    { id: "hemisphere", kind: "hemisphere", sky: "#f8fbff", ground: "#a7a099", intensity: 1.35 },
    { id: "key", kind: "directional", color: "#dcecff", intensity: 4.2, position: [4.5, 6.5, 8] },
    { id: "rim", kind: "directional", color: "#aac8df", intensity: 2.2, position: [-6, 2.5, 5] },
    { id: "gold", kind: "directional", color: "#ffd69a", intensity: 1.35, position: [5, -3.5, 6] },
    { id: "fill", kind: "directional", color: "#ffffff", intensity: 0.95, position: [-2, -4, 8] },
  ],
  fastenerGeometry: {
    kind: "instanced-low-profile-cap",
    count: 26,
    radialSegments: 20,
    depthWorld: 0.028,
    material: { color: "#c7a267", metalness: 0.92, roughness: 0.24 },
  },
  models,
  fasteners: stagedFasteners,
  visualIntegrity: {
    expectedModelMeshCount,
    minimumDrawCalls: expectedModelMeshCount + 1,
    minimumVisibleModelCoverage: 0.03,
    assay: "model-only framebuffer coverage with deterministic fasteners hidden",
  },
  budgets: {
    maximumModels: 14,
    maximumFasteners: 26,
    maximumTotalTriangles: 6_000,
    maximumTotalModelBytes: 2_000_000,
    maximumDevicePixelRatio: 1.75,
  },
  provenance: {
    lockReceiptSha256: await sha256(lockPath),
    transformSpecSha256: await sha256(specPath),
    segmentationSha256: await sha256(segmentationPath),
    paidGenerationCalls: 0,
    geometryMutated: false,
  },
};

const manifestPath = join(publicRoot, "assembly-manifest.json");
await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(JSON.stringify({
  manifest: manifestPath,
  manifestSha256: await sha256(manifestPath),
  models: models.length,
  fasteners: stagedFasteners.length,
  copiedBytes: models.reduce((sum, model) => sum + Number(model.bytes), 0),
  source: basename(lockPath),
}, null, 2));

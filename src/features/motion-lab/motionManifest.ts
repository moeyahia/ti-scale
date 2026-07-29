import { assetUrl } from "../../lib/assetUrl";

export const MOTION_LAB_MANIFEST_PATH = "brand-v2/source/higgsfield-motion/manifest.json";

export type MotionLabStatus = "generating" | "ready" | "failed";

export interface MotionLabStage {
  readonly id: string;
  readonly label: string;
  readonly summary: string;
  readonly progress: number;
  readonly imagePath: string;
  readonly imageAlt: string;
  readonly width: number;
  readonly height: number;
}

export interface MotionLabVideo {
  readonly path: string;
  readonly mimeType: "video/mp4" | "video/webm";
  readonly durationSeconds: number;
  readonly posterPath: string;
  readonly width: number;
  readonly height: number;
}

export interface MotionLabManifest {
  readonly schemaVersion: 1;
  readonly status: MotionLabStatus;
  readonly updatedAt: string;
  readonly studyTitle: string;
  readonly statusDetail: string;
  readonly stages: readonly MotionLabStage[];
  readonly motion?: MotionLabVideo;
}

const MOTION_ASSET_ROOTS = [
  "brand-v2/source/higgsfield-motion/",
  "brand-v2/optimized/higgsfield-motion/",
] as const;

function record(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function nonEmptyString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function positiveNumber(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a positive number`);
  }
  return value;
}

function localMotionPath(value: unknown, name: string): string {
  const path = nonEmptyString(value, name).replace(/^\/+/, "");
  const hasApprovedRoot = MOTION_ASSET_ROOTS.some((root) => path.startsWith(root));
  if (!hasApprovedRoot || path.includes("..") || path.includes("\\")) {
    throw new Error(`${name} must stay inside an approved motion asset root`);
  }
  return path;
}

function parseStage(value: unknown, index: number): MotionLabStage {
  const stage = record(value, `stages[${index}]`);
  const progress = typeof stage.progress === "number" ? stage.progress : Number.NaN;
  if (!Number.isFinite(progress) || progress < 0 || progress > 1) {
    throw new Error(`stages[${index}].progress must be between 0 and 1`);
  }
  return {
    id: nonEmptyString(stage.id, `stages[${index}].id`),
    label: nonEmptyString(stage.label, `stages[${index}].label`),
    summary: nonEmptyString(stage.summary, `stages[${index}].summary`),
    progress,
    imagePath: localMotionPath(stage.imagePath, `stages[${index}].imagePath`),
    imageAlt: nonEmptyString(stage.imageAlt, `stages[${index}].imageAlt`),
    width: positiveNumber(stage.width, `stages[${index}].width`),
    height: positiveNumber(stage.height, `stages[${index}].height`),
  };
}

function parseMotion(value: unknown): MotionLabVideo | undefined {
  if (value === undefined || value === null) return undefined;
  const motion = record(value, "motion");
  const mimeType = nonEmptyString(motion.mimeType, "motion.mimeType");
  if (mimeType !== "video/mp4" && mimeType !== "video/webm") {
    throw new Error("motion.mimeType must be video/mp4 or video/webm");
  }
  return {
    path: localMotionPath(motion.path, "motion.path"),
    mimeType,
    durationSeconds: positiveNumber(motion.durationSeconds, "motion.durationSeconds"),
    posterPath: localMotionPath(motion.posterPath, "motion.posterPath"),
    width: positiveNumber(motion.width, "motion.width"),
    height: positiveNumber(motion.height, "motion.height"),
  };
}

export function parseMotionLabManifest(value: unknown): MotionLabManifest {
  const manifest = record(value, "manifest");
  if (manifest.schemaVersion !== 1) throw new Error("manifest.schemaVersion must be 1");
  if (manifest.status !== "generating" && manifest.status !== "ready" && manifest.status !== "failed") {
    throw new Error("manifest.status is not recognized");
  }
  if (!Array.isArray(manifest.stages) || manifest.stages.length === 0) {
    throw new Error("manifest.stages must contain at least one real keyframe");
  }
  const stages = manifest.stages.map(parseStage).sort((left, right) => left.progress - right.progress);
  if (new Set(stages.map((stage) => stage.id)).size !== stages.length) {
    throw new Error("manifest.stages contains duplicate IDs");
  }
  return {
    schemaVersion: 1,
    status: manifest.status,
    updatedAt: nonEmptyString(manifest.updatedAt, "manifest.updatedAt"),
    studyTitle: nonEmptyString(manifest.studyTitle, "manifest.studyTitle"),
    statusDetail: nonEmptyString(manifest.statusDetail, "manifest.statusDetail"),
    stages,
    motion: parseMotion(manifest.motion),
  };
}

export function motionAssetUrl(path: string): string {
  return assetUrl(localMotionPath(path, "asset path"));
}

export async function loadMotionLabManifest(signal?: AbortSignal): Promise<MotionLabManifest | null> {
  const response = await fetch(assetUrl(MOTION_LAB_MANIFEST_PATH), {
    signal,
    cache: "no-cache",
    headers: { Accept: "application/json" },
  });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`Motion manifest request returned HTTP ${response.status}`);
  return parseMotionLabManifest(await response.json());
}

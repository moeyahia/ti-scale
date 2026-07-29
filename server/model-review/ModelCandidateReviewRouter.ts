import { createHash } from "node:crypto";
import {
  existsSync,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { Router, type Response } from "express";

export const MODEL_CANDIDATE_REVIEW_MANIFEST = "candidate-review-manifest.json";
export const MODEL_CANDIDATE_REVIEW_API = "/api/v2/motion-lab/review";

const SHA_256 = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[a-z0-9][a-z0-9-]{1,79}$/u;
const MAX_IMAGE_BYTES = 12 * 1024 * 1024;
const MAX_MODEL_BYTES = 64 * 1024 * 1024;
const ASSET_KINDS = new Set(["source-image", "turntable-image", "model-glb"]);
const REVIEW_STATUSES = new Set(["candidate", "rejected", "approved"]);
const MIME_TYPES = new Set(["image/png", "image/jpeg", "model/gltf-binary"]);

export type ModelCandidateReviewStatus = "candidate" | "rejected" | "approved";
export type ModelCandidateReviewKind = "source-image" | "turntable-image" | "model-glb";

export interface ModelCandidateReviewAsset {
  readonly id: string;
  readonly kind: ModelCandidateReviewKind;
  readonly label: string;
  readonly description: string;
  readonly mimeType: "image/png" | "image/jpeg" | "model/gltf-binary";
  readonly bytes: number;
  readonly sha256: string;
  readonly relativePath: string;
  readonly width?: number;
  readonly height?: number;
  readonly triangleCount?: number;
  readonly vertexCount?: number;
}

export interface ModelCandidateReviewManifest {
  readonly schemaVersion: 1;
  readonly candidateId: string;
  readonly status: ModelCandidateReviewStatus;
  readonly reviewState: "unreviewed" | "rejected" | "approved";
  readonly title: string;
  readonly summary: string;
  readonly generatedAt: string;
  readonly provenance: {
    readonly imageTaskId: string;
    readonly modelTaskId: string;
    readonly imageCredits: number;
    readonly modelCredits: number;
  };
  readonly approval: {
    readonly authority: "operator";
    readonly receiptId: string | null;
    readonly decidedAt: string | null;
  };
  readonly assets: readonly ModelCandidateReviewAsset[];
}

interface ResolvedAsset extends ModelCandidateReviewAsset {
  readonly absolutePath: string;
  readonly url: string;
}

interface ResolvedReview {
  readonly manifest: Omit<ModelCandidateReviewManifest, "assets"> & {
    readonly availability: "available";
    readonly assets: readonly Omit<ResolvedAsset, "absolutePath" | "relativePath">[];
  };
  readonly assets: ReadonlyMap<string, ResolvedAsset>;
}

export interface ModelCandidateReviewRouterOptions {
  /** Optional, V2-owned directory containing one local review manifest and its assets. */
  readonly reviewRoot?: string;
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} must be a non-empty string`);
  return value.trim();
}

function integer(value: unknown, name: string, minimum = 1): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new Error(`${name} must be an integer greater than or equal to ${minimum}`);
  }
  return value as number;
}

function nullableString(value: unknown, name: string): string | null {
  return value === null ? null : string(value, name);
}

function isoTimestamp(value: unknown, name: string): string {
  const result = string(value, name);
  if (!Number.isFinite(Date.parse(result))) throw new Error(`${name} must be an ISO timestamp`);
  return result;
}

function localRelativePath(value: unknown, name: string): string {
  const path = string(value, name);
  if (isAbsolute(path) || path.includes("..") || path.includes("\\") || path.startsWith("/")) {
    throw new Error(`${name} must remain inside the configured review root`);
  }
  return path;
}

function parseAsset(value: unknown, index: number): ModelCandidateReviewAsset {
  const input = record(value, `assets[${index}]`);
  const id = string(input.id, `assets[${index}].id`);
  if (!SAFE_ID.test(id)) throw new Error(`assets[${index}].id is invalid`);
  const kind = string(input.kind, `assets[${index}].kind`);
  if (!ASSET_KINDS.has(kind)) throw new Error(`assets[${index}].kind is invalid`);
  const mimeType = string(input.mimeType, `assets[${index}].mimeType`);
  if (!MIME_TYPES.has(mimeType)) throw new Error(`assets[${index}].mimeType is invalid`);
  if ((kind === "model-glb") !== (mimeType === "model/gltf-binary")) {
    throw new Error(`assets[${index}] model kind and MIME type do not agree`);
  }
  const sha256 = string(input.sha256, `assets[${index}].sha256`);
  if (!SHA_256.test(sha256)) throw new Error(`assets[${index}].sha256 is invalid`);
  const bytes = integer(input.bytes, `assets[${index}].bytes`);
  if (bytes > (kind === "model-glb" ? MAX_MODEL_BYTES : MAX_IMAGE_BYTES)) {
    throw new Error(`assets[${index}] exceeds the review delivery budget`);
  }
  const dimensions = kind === "model-glb"
    ? {
        triangleCount: integer(input.triangleCount, `assets[${index}].triangleCount`),
        vertexCount: integer(input.vertexCount, `assets[${index}].vertexCount`),
      }
    : {
        width: integer(input.width, `assets[${index}].width`),
        height: integer(input.height, `assets[${index}].height`),
      };
  return {
    id,
    kind: kind as ModelCandidateReviewKind,
    label: string(input.label, `assets[${index}].label`),
    description: string(input.description, `assets[${index}].description`),
    mimeType: mimeType as ModelCandidateReviewAsset["mimeType"],
    bytes,
    sha256,
    relativePath: localRelativePath(input.relativePath, `assets[${index}].relativePath`),
    ...dimensions,
  };
}

export function parseModelCandidateReviewManifest(value: unknown): ModelCandidateReviewManifest {
  const input = record(value, "manifest");
  if (input.schemaVersion !== 1) throw new Error("manifest.schemaVersion must be 1");
  const candidateId = string(input.candidateId, "manifest.candidateId");
  if (!SAFE_ID.test(candidateId)) throw new Error("manifest.candidateId is invalid");
  const status = string(input.status, "manifest.status");
  if (!REVIEW_STATUSES.has(status)) throw new Error("manifest.status must be candidate, rejected, or approved");
  const reviewState = string(input.reviewState, "manifest.reviewState");
  if (!new Set(["unreviewed", "rejected", "approved"]).has(reviewState)) {
    throw new Error("manifest.reviewState is invalid");
  }
  if (
    (status === "candidate" && reviewState !== "unreviewed")
    || (status !== "candidate" && reviewState !== status)
  ) throw new Error("manifest status and reviewState do not agree");

  const provenance = record(input.provenance, "manifest.provenance");
  const approval = record(input.approval, "manifest.approval");
  if (approval.authority !== "operator") throw new Error("manifest.approval.authority must be operator");
  const receiptId = nullableString(approval.receiptId, "manifest.approval.receiptId");
  const decidedAt = approval.decidedAt === null
    ? null
    : isoTimestamp(approval.decidedAt, "manifest.approval.decidedAt");
  if ((status === "candidate") !== (receiptId === null && decidedAt === null)) {
    throw new Error("only an undecided candidate may omit its operator approval receipt");
  }
  if (!Array.isArray(input.assets) || input.assets.length < 4) {
    throw new Error("manifest.assets must contain two source views, one turntable fallback, and one GLB");
  }
  const assets = input.assets.map(parseAsset);
  if (new Set(assets.map((asset) => asset.id)).size !== assets.length) {
    throw new Error("manifest.assets contains duplicate IDs");
  }
  if (assets.filter((asset) => asset.kind === "source-image").length !== 2) {
    throw new Error("manifest.assets must contain exactly two source images");
  }
  if (assets.filter((asset) => asset.kind === "turntable-image").length !== 1) {
    throw new Error("manifest.assets must contain exactly one turntable fallback");
  }
  if (assets.filter((asset) => asset.kind === "model-glb").length !== 1) {
    throw new Error("manifest.assets must contain exactly one candidate GLB");
  }
  return {
    schemaVersion: 1,
    candidateId,
    status: status as ModelCandidateReviewStatus,
    reviewState: reviewState as ModelCandidateReviewManifest["reviewState"],
    title: string(input.title, "manifest.title"),
    summary: string(input.summary, "manifest.summary"),
    generatedAt: isoTimestamp(input.generatedAt, "manifest.generatedAt"),
    provenance: {
      imageTaskId: string(provenance.imageTaskId, "manifest.provenance.imageTaskId"),
      modelTaskId: string(provenance.modelTaskId, "manifest.provenance.modelTaskId"),
      imageCredits: integer(provenance.imageCredits, "manifest.provenance.imageCredits", 0),
      modelCredits: integer(provenance.modelCredits, "manifest.provenance.modelCredits", 0),
    },
    approval: { authority: "operator", receiptId, decidedAt },
    assets,
  };
}

function contentHash(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function resolveReview(options: ModelCandidateReviewRouterOptions): ResolvedReview | undefined {
  if (!options.reviewRoot) return undefined;
  if (!isAbsolute(options.reviewRoot)) throw new Error("TI_SCALE_MOTION_REVIEW_ROOT must be absolute");
  const root = realpathSync(options.reviewRoot);
  const manifestPath = resolve(root, MODEL_CANDIDATE_REVIEW_MANIFEST);
  if (!existsSync(manifestPath) || !statSync(manifestPath).isFile()) {
    throw new Error(`Motion review manifest is missing: ${manifestPath}`);
  }
  const manifest = parseModelCandidateReviewManifest(JSON.parse(readFileSync(manifestPath, "utf8")) as unknown);
  const resolvedAssets = manifest.assets.map((asset): ResolvedAsset => {
    const absolutePath = realpathSync(resolve(root, asset.relativePath));
    if (absolutePath !== root && !absolutePath.startsWith(`${root}${sep}`)) {
      throw new Error(`Review asset ${asset.id} escapes the configured review root`);
    }
    const statistics = statSync(absolutePath);
    if (!statistics.isFile() || statistics.size !== asset.bytes) {
      throw new Error(`Review asset ${asset.id} does not match its declared byte count`);
    }
    if (contentHash(absolutePath) !== asset.sha256) {
      throw new Error(`Review asset ${asset.id} failed its SHA-256 integrity check`);
    }
    return {
      ...asset,
      absolutePath,
      url: `${MODEL_CANDIDATE_REVIEW_API}/assets/${encodeURIComponent(asset.id)}`,
    };
  });
  return {
    manifest: {
      ...manifest,
      availability: "available",
      assets: resolvedAssets.map(({ absolutePath: _absolutePath, relativePath: _relativePath, ...asset }) => asset),
    },
    assets: new Map(resolvedAssets.map((asset) => [asset.id, asset])),
  };
}

function privateReviewHeaders(response: Response): void {
  response.setHeader("Cache-Control", "private, no-store");
  response.setHeader("X-Ti-Scale-Review-Only", "true");
}

/**
 * Authenticated, read-only delivery for local candidate review. This router
 * deliberately exposes no approval or promotion mutation.
 */
export function createModelCandidateReviewRouter(options: ModelCandidateReviewRouterOptions = {}): Router {
  const router = Router();
  const review = resolveReview(options);

  router.get(MODEL_CANDIDATE_REVIEW_API, (_request, response) => {
    privateReviewHeaders(response);
    response.json(review?.manifest ?? {
      schemaVersion: 1,
      availability: "not_configured",
      humanMessage: "No isolated 3D candidate is configured for review on this Ti-Scale process.",
      remediation: "Start a local review process with TI_SCALE_MOTION_REVIEW_ROOT set to a verified candidate directory.",
    });
  });

  router.get(`${MODEL_CANDIDATE_REVIEW_API}/assets/:assetId`, (request, response) => {
    privateReviewHeaders(response);
    const asset = review?.assets.get(request.params.assetId);
    if (!asset) {
      response.status(404).json({
        schemaVersion: 1,
        error: {
          code: "motion_review_asset_not_found",
          humanMessage: "The requested review-only asset is not available in this candidate bundle.",
        },
      });
      return;
    }
    response.type(asset.mimeType);
    response.setHeader("Content-Disposition", "inline");
    // Candidate workspaces are intentionally kept outside the public build
    // and may live under a hidden local artifact directory. The exact file
    // has already passed realpath containment, regular-file, size, and digest
    // validation, so permit that verified absolute path explicitly.
    response.sendFile(asset.absolutePath, { dotfiles: "allow" });
  });

  return router;
}

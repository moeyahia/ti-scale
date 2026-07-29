import type {
  AvailableModelCandidateReview,
  ModelCandidateReview,
  ModelCandidateReviewAsset,
  ModelCandidateReviewAssetKind,
  ModelCandidateReviewStatus,
} from "../types/modelCandidateReview";

const SHA_256 = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[a-z0-9][a-z0-9-]{1,79}$/u;
const REVIEW_API_ROOT = "/api/v2/motion-lab/review/assets/";
const assetKinds = new Set(["source-image", "turntable-image", "model-glb"]);
const statuses = new Set(["candidate", "rejected", "approved"]);

function record(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
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

function parseAsset(value: unknown, index: number): ModelCandidateReviewAsset {
  const input = record(value, `assets[${index}]`);
  const id = string(input.id, `assets[${index}].id`);
  if (!SAFE_ID.test(id)) throw new Error(`assets[${index}].id is invalid`);
  const kind = string(input.kind, `assets[${index}].kind`);
  if (!assetKinds.has(kind)) throw new Error(`assets[${index}].kind is invalid`);
  const mimeType = string(input.mimeType, `assets[${index}].mimeType`);
  if (!new Set(["image/png", "image/jpeg", "model/gltf-binary"]).has(mimeType)) {
    throw new Error(`assets[${index}].mimeType is invalid`);
  }
  if ((kind === "model-glb") !== (mimeType === "model/gltf-binary")) {
    throw new Error(`assets[${index}] model kind and MIME type do not agree`);
  }
  const sha256 = string(input.sha256, `assets[${index}].sha256`);
  if (!SHA_256.test(sha256)) throw new Error(`assets[${index}].sha256 is invalid`);
  const url = string(input.url, `assets[${index}].url`);
  if (url !== `${REVIEW_API_ROOT}${encodeURIComponent(id)}`) {
    throw new Error(`assets[${index}].url must use its authenticated review-only API route`);
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
    kind: kind as ModelCandidateReviewAssetKind,
    label: string(input.label, `assets[${index}].label`),
    description: string(input.description, `assets[${index}].description`),
    mimeType: mimeType as ModelCandidateReviewAsset["mimeType"],
    bytes: integer(input.bytes, `assets[${index}].bytes`),
    sha256,
    url,
    ...dimensions,
  };
}

function parseAvailable(input: Record<string, unknown>): AvailableModelCandidateReview {
  const candidateId = string(input.candidateId, "candidateId");
  if (!SAFE_ID.test(candidateId)) throw new Error("candidateId is invalid");
  const status = string(input.status, "status");
  if (!statuses.has(status)) throw new Error("status must be candidate, rejected, or approved");
  const reviewState = string(input.reviewState, "reviewState");
  if (!new Set(["unreviewed", "rejected", "approved"]).has(reviewState)) {
    throw new Error("reviewState is invalid");
  }
  if ((status === "candidate" && reviewState !== "unreviewed") || (status !== "candidate" && status !== reviewState)) {
    throw new Error("status and reviewState do not agree");
  }
  const provenance = record(input.provenance, "provenance");
  const approval = record(input.approval, "approval");
  if (approval.authority !== "operator") throw new Error("approval.authority must be operator");
  const receiptId = nullableString(approval.receiptId, "approval.receiptId");
  const decidedAt = approval.decidedAt === null ? null : isoTimestamp(approval.decidedAt, "approval.decidedAt");
  if ((status === "candidate") !== (receiptId === null && decidedAt === null)) {
    throw new Error("only an undecided candidate may omit its operator approval receipt");
  }
  if (!Array.isArray(input.assets) || input.assets.length < 4) {
    throw new Error("assets must contain two source views, one static turntable, and one GLB");
  }
  const assets = input.assets.map(parseAsset);
  if (new Set(assets.map((asset) => asset.id)).size !== assets.length) throw new Error("assets contains duplicate IDs");
  if (assets.filter((asset) => asset.kind === "source-image").length !== 2) throw new Error("assets must contain two source images");
  if (assets.filter((asset) => asset.kind === "turntable-image").length !== 1) throw new Error("assets must contain one turntable image");
  if (assets.filter((asset) => asset.kind === "model-glb").length !== 1) throw new Error("assets must contain one model GLB");
  return {
    schemaVersion: 1,
    availability: "available",
    candidateId,
    status: status as ModelCandidateReviewStatus,
    reviewState: reviewState as AvailableModelCandidateReview["reviewState"],
    title: string(input.title, "title"),
    summary: string(input.summary, "summary"),
    generatedAt: isoTimestamp(input.generatedAt, "generatedAt"),
    provenance: {
      imageTaskId: string(provenance.imageTaskId, "provenance.imageTaskId"),
      modelTaskId: string(provenance.modelTaskId, "provenance.modelTaskId"),
      imageCredits: integer(provenance.imageCredits, "provenance.imageCredits", 0),
      modelCredits: integer(provenance.modelCredits, "provenance.modelCredits", 0),
    },
    approval: { authority: "operator", receiptId, decidedAt },
    assets,
  };
}

export function parseModelCandidateReview(value: unknown): ModelCandidateReview {
  const input = record(value, "candidate review response");
  if (input.schemaVersion !== 1) throw new Error("schemaVersion must be 1");
  if (input.availability === "not_configured") {
    return {
      schemaVersion: 1,
      availability: "not_configured",
      humanMessage: string(input.humanMessage, "humanMessage"),
      remediation: string(input.remediation, "remediation"),
    };
  }
  if (input.availability !== "available") throw new Error("availability is invalid");
  return parseAvailable(input);
}

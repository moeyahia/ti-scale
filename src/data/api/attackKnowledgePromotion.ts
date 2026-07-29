import {
  parseAttackKnowledgeBundlePage,
  parseAttackKnowledgeEvidencePage,
  parseAttackKnowledgePromotionPreview,
  parseAttackKnowledgePromotionReceipt,
} from "../../domain/schemas/attackKnowledgePromotion";
import type {
  AttackKnowledgeBundlePage,
  AttackKnowledgeEvidencePage,
  AttackKnowledgePromotionPreview,
  AttackKnowledgePromotionReceipt,
} from "../../domain/types/attackKnowledgePromotion";
import { apiRequest } from "./client";

const ROOT = "/api/v2/brain/attack-knowledge";

export function createAttackKnowledgePromotionKey(): string {
  return globalThis.crypto?.randomUUID?.() ?? `attack-promotion-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function fetchAttackKnowledgeBundles(signal: AbortSignal): Promise<AttackKnowledgeBundlePage> {
  return apiRequest(`${ROOT}/bundles?status=all`, { signal, parse: parseAttackKnowledgeBundlePage });
}

export function fetchAttackKnowledgeEvidence(
  bundleFingerprint: string,
  signal: AbortSignal,
): Promise<AttackKnowledgeEvidencePage> {
  return apiRequest(`${ROOT}/bundles/${encodeURIComponent(bundleFingerprint)}/evidence`, {
    signal,
    parse: parseAttackKnowledgeEvidencePage,
  });
}

export function previewAttackKnowledgePromotion(
  bundleFingerprint: string,
  verificationEvidenceIds: readonly string[],
): Promise<AttackKnowledgePromotionPreview> {
  return apiRequest(`${ROOT}/bundles/${encodeURIComponent(bundleFingerprint)}/preview`, {
    method: "POST",
    body: JSON.stringify({ verificationEvidenceIds }),
    parse: parseAttackKnowledgePromotionPreview,
  });
}

export function promoteAttackKnowledge(
  input: {
    readonly bundleFingerprint: string;
    readonly expectedReviewHash: string;
    readonly verificationEvidenceIds: readonly string[];
  },
  idempotencyKey: string,
): Promise<AttackKnowledgePromotionReceipt> {
  return apiRequest(`${ROOT}/bundles/${encodeURIComponent(input.bundleFingerprint)}/promote`, {
    method: "POST",
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({
      expectedReviewHash: input.expectedReviewHash,
      verificationEvidenceIds: input.verificationEvidenceIds,
    }),
    parse: parseAttackKnowledgePromotionReceipt,
  });
}

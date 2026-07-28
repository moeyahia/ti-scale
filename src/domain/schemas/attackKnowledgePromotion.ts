import type {
  AttackKnowledgeBundlePage,
  AttackKnowledgeEvidencePage,
  AttackKnowledgePromotionPreview,
  AttackKnowledgePromotionReceipt,
} from "../types/attackKnowledgePromotion";

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${label} must be text`);
  return value;
}

function nullableString(value: unknown, label: string): string | null {
  return value === null ? null : string(value, label);
}

function integer(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) throw new TypeError(`${label} must be a non-negative integer`);
  return Number(value);
}

function exactCounts(value: unknown, label: string) {
  const input = record(value, label);
  return {
    attempts: integer(input.attempts, `${label}.attempts`),
    reproducibleOutcomes: integer(input.reproducibleOutcomes, `${label}.reproducibleOutcomes`),
    evidenceItems: integer(input.evidenceItems, `${label}.evidenceItems`),
    exactResets: integer(input.exactResets, `${label}.exactResets`),
    operatorReportedAggregateResetMinimum: input.operatorReportedAggregateResetMinimum === null
      ? null
      : integer(input.operatorReportedAggregateResetMinimum, `${label}.operatorReportedAggregateResetMinimum`),
  } as const;
}

function evidence(value: unknown, label: string) {
  const input = record(value, label);
  if (input.verificationState !== "verified") throw new TypeError(`${label}.verificationState must be verified`);
  return {
    id: string(input.id, `${label}.id`),
    contentHash: string(input.contentHash, `${label}.contentHash`),
    evidenceType: string(input.evidenceType, `${label}.evidenceType`),
    acquiredAt: string(input.acquiredAt, `${label}.acquiredAt`),
    verificationState: "verified" as const,
  };
}

export function parseAttackKnowledgeBundlePage(value: unknown): AttackKnowledgeBundlePage {
  const input = record(value, "attack knowledge bundles");
  if (input.schemaVersion !== "2.4" || !Array.isArray(input.items)) {
    throw new TypeError("Attack knowledge bundle response is incompatible");
  }
  const items = input.items.map((item, index) => {
    const row = record(item, `items[${index}]`);
    if (row.status !== "staged" && row.status !== "materialized") throw new TypeError(`items[${index}].status is invalid`);
    const status = row.status as "staged" | "materialized";
    if (row.kind !== "operational_hazard" && row.kind !== "reusable_fact" && row.kind !== "reusable_bundle") throw new TypeError(`items[${index}].kind is invalid`);
    const kind = row.kind as "operational_hazard" | "reusable_fact" | "reusable_bundle";
    const candidates = record(row.candidates, `items[${index}].candidates`);
    const promoted = row.promotedReceipt === null ? null : record(row.promotedReceipt, `items[${index}].promotedReceipt`);
    return {
      bundleId: string(row.bundleId, `items[${index}].bundleId`),
      bundleFingerprint: string(row.bundleFingerprint, `items[${index}].bundleFingerprint`),
      status,
      kind,
      candidates: {
        total: integer(candidates.total, `items[${index}].candidates.total`),
        reviewed: integer(candidates.reviewed, `items[${index}].candidates.reviewed`),
        pending: integer(candidates.pending, `items[${index}].candidates.pending`),
        rejected: integer(candidates.rejected, `items[${index}].candidates.rejected`),
      },
      exactProcedureCounts: exactCounts(row.exactProcedureCounts, `items[${index}].exactProcedureCounts`),
      boundEvidenceCount: integer(row.boundEvidenceCount, `items[${index}].boundEvidenceCount`),
      firstObservedAt: string(row.firstObservedAt, `items[${index}].firstObservedAt`),
      lastObservedAt: string(row.lastObservedAt, `items[${index}].lastObservedAt`),
      promotedReceipt: promoted ? {
        id: string(promoted.id, `items[${index}].promotedReceipt.id`),
        reviewHash: string(promoted.reviewHash, `items[${index}].promotedReceipt.reviewHash`),
        auditRecordId: string(promoted.auditRecordId, `items[${index}].promotedReceipt.auditRecordId`),
        promotedAt: string(promoted.promotedAt, `items[${index}].promotedReceipt.promotedAt`),
      } : null,
    };
  });
  return { schemaVersion: "2.4", items, totalReturned: integer(input.totalReturned, "totalReturned") };
}

export function parseAttackKnowledgeEvidencePage(value: unknown): AttackKnowledgeEvidencePage {
  const input = record(value, "attack knowledge evidence");
  if (input.schemaVersion !== "2.4" || !Array.isArray(input.items)) throw new TypeError("Attack knowledge evidence response is incompatible");
  return {
    schemaVersion: "2.4",
    bundleId: string(input.bundleId, "bundleId"),
    bundleFingerprint: string(input.bundleFingerprint, "bundleFingerprint"),
    items: input.items.map((item, index) => evidence(item, `items[${index}]`)),
    totalReturned: integer(input.totalReturned, "totalReturned"),
  };
}

export function parseAttackKnowledgePromotionPreview(value: unknown): AttackKnowledgePromotionPreview {
  const input = record(value, "attack knowledge promotion preview");
  if (input.schemaVersion !== "2.4" || typeof input.ready !== "boolean" || typeof input.replay !== "boolean") {
    throw new TypeError("Attack knowledge promotion preview is incompatible");
  }
  const review = record(input.review, "review");
  const bundle = record(review.bundle, "review.bundle");
  const verification = record(review.verification, "review.verification");
  if (!Array.isArray(input.blockers) || !Array.isArray(review.candidates) || !Array.isArray(review.edges) || !Array.isArray(verification.evidence)) {
    throw new TypeError("Attack knowledge promotion preview lists are invalid");
  }
  const kind = bundle.kind;
  if (kind !== "operational_hazard" && kind !== "reusable_fact" && kind !== "reusable_bundle") throw new TypeError("review.bundle.kind is invalid");
  const profile = review.operationalHazardProfile === null ? null : record(review.operationalHazardProfile, "review.operationalHazardProfile");
  const profileAction = profile?.action;
  if (profile && !["create", "update", "reuse", "blocked"].includes(String(profileAction))) throw new TypeError("Hazard profile action is invalid");
  return {
    schemaVersion: "2.4",
    ready: input.ready,
    replay: input.replay,
    reviewHash: string(input.reviewHash, "reviewHash"),
    blockers: input.blockers.map((item, index) => {
      const blocker = record(item, `blockers[${index}]`);
      return {
        code: string(blocker.code, `blockers[${index}].code`),
        ...(typeof blocker.role === "string" ? { role: blocker.role } : {}),
        ...(typeof blocker.edgeKey === "string" ? { edgeKey: blocker.edgeKey } : {}),
        message: string(blocker.message, `blockers[${index}].message`),
      };
    }),
    review: {
      bundle: {
        id: string(bundle.id, "review.bundle.id"),
        semanticFingerprint: string(bundle.semanticFingerprint, "review.bundle.semanticFingerprint"),
        kind,
        exactProcedureCounts: exactCounts(bundle.exactProcedureCounts, "review.bundle.exactProcedureCounts"),
        firstObservedAt: string(bundle.firstObservedAt, "review.bundle.firstObservedAt"),
        lastObservedAt: string(bundle.lastObservedAt, "review.bundle.lastObservedAt"),
      },
      candidates: review.candidates.map((item, index) => {
        const candidate = record(item, `review.candidates[${index}]`);
        const node = candidate.proposedNode === null ? null : record(candidate.proposedNode, `review.candidates[${index}].proposedNode`);
        return {
          role: string(candidate.role, `review.candidates[${index}].role`),
          ordinal: integer(candidate.ordinal, `review.candidates[${index}].ordinal`),
          required: candidate.required === true,
          expectedNodeType: string(candidate.expectedNodeType, `review.candidates[${index}].expectedNodeType`),
          candidateId: string(candidate.candidateId, `review.candidates[${index}].candidateId`),
          candidateStatus: string(candidate.candidateStatus, `review.candidates[${index}].candidateStatus`),
          reviewedBy: nullableString(candidate.reviewedBy, `review.candidates[${index}].reviewedBy`),
          reviewedAt: nullableString(candidate.reviewedAt, `review.candidates[${index}].reviewedAt`),
          proposedNode: node ? {
            id: string(node.id, `review.candidates[${index}].proposedNode.id`),
            nodeType: string(node.nodeType, `review.candidates[${index}].proposedNode.nodeType`),
            version: integer(node.version, `review.candidates[${index}].proposedNode.version`),
            contentHash: string(node.contentHash, `review.candidates[${index}].proposedNode.contentHash`),
            title: string(node.title, `review.candidates[${index}].proposedNode.title`),
            summary: string(node.summary, `review.candidates[${index}].proposedNode.summary`),
          } : null,
        };
      }),
      edges: review.edges.map((item, index) => {
        const edge = record(item, `review.edges[${index}]`);
        if (edge.action !== "create" && edge.action !== "reuse" && edge.action !== "blocked") throw new TypeError(`review.edges[${index}].action is invalid`);
        return {
          edgeKey: string(edge.edgeKey, `review.edges[${index}].edgeKey`),
          sourceRole: string(edge.sourceRole, `review.edges[${index}].sourceRole`),
          targetRole: string(edge.targetRole, `review.edges[${index}].targetRole`),
          edgeType: string(edge.edgeType, `review.edges[${index}].edgeType`),
          action: edge.action,
        };
      }),
      operationalHazardProfile: profile ? {
        action: profileAction as "create" | "update" | "reuse" | "blocked",
        hazardNodeId: nullableString(profile.hazardNodeId, "review.operationalHazardProfile.hazardNodeId"),
        expectedVersion: profile.expectedVersion === null ? null : integer(profile.expectedVersion, "review.operationalHazardProfile.expectedVersion"),
      } : null,
      verification: {
        minimumEvidenceItems: integer(verification.minimumEvidenceItems, "review.verification.minimumEvidenceItems"),
        evidence: verification.evidence.map((item, index) => evidence(item, `review.verification.evidence[${index}]`)),
      },
    },
  };
}

export function parseAttackKnowledgePromotionReceipt(value: unknown): AttackKnowledgePromotionReceipt {
  const input = record(value, "attack knowledge promotion receipt");
  if (input.schemaVersion !== "2.4" || (input.status !== "materialized" && input.status !== "replayed") || !Array.isArray(input.edgeIds)) {
    throw new TypeError("Attack knowledge promotion receipt is incompatible");
  }
  return {
    schemaVersion: "2.4",
    status: input.status,
    receiptId: string(input.receiptId, "receiptId"),
    bundleId: string(input.bundleId, "bundleId"),
    reviewHash: string(input.reviewHash, "reviewHash"),
    auditRecordId: string(input.auditRecordId, "auditRecordId"),
    edgeIds: input.edgeIds.map((item, index) => string(item, `edgeIds[${index}]`)),
    hazardProfileNodeId: nullableString(input.hazardProfileNodeId, "hazardProfileNodeId"),
    hazardProfileVersion: input.hazardProfileVersion === null ? null : integer(input.hazardProfileVersion, "hazardProfileVersion"),
    promotedAt: string(input.promotedAt, "promotedAt"),
  };
}

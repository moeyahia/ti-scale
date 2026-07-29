export type AttackKnowledgeBundleStatus = "staged" | "materialized";

export interface AttackKnowledgeBundleSummary {
  readonly bundleId: string;
  readonly bundleFingerprint: string;
  readonly status: AttackKnowledgeBundleStatus;
  readonly kind: "operational_hazard" | "reusable_fact" | "reusable_bundle";
  readonly candidates: {
    readonly total: number;
    readonly reviewed: number;
    readonly pending: number;
    readonly rejected: number;
  };
  readonly exactProcedureCounts: {
    readonly attempts: number;
    readonly reproducibleOutcomes: number;
    readonly evidenceItems: number;
    readonly exactResets: number;
    readonly operatorReportedAggregateResetMinimum: number | null;
  };
  readonly boundEvidenceCount: number;
  readonly firstObservedAt: string;
  readonly lastObservedAt: string;
  readonly promotedReceipt: {
    readonly id: string;
    readonly reviewHash: string;
    readonly auditRecordId: string;
    readonly promotedAt: string;
  } | null;
}

export interface AttackKnowledgeBundlePage {
  readonly schemaVersion: "2.4";
  readonly items: readonly AttackKnowledgeBundleSummary[];
  readonly totalReturned: number;
}

export interface AttackKnowledgeEvidenceBinding {
  readonly id: string;
  readonly contentHash: string;
  readonly evidenceType: string;
  readonly acquiredAt: string;
  readonly verificationState: "verified";
}

export interface AttackKnowledgeEvidencePage {
  readonly schemaVersion: "2.4";
  readonly bundleId: string;
  readonly bundleFingerprint: string;
  readonly items: readonly AttackKnowledgeEvidenceBinding[];
  readonly totalReturned: number;
}

export interface AttackKnowledgePromotionBlocker {
  readonly code: string;
  readonly role?: string;
  readonly edgeKey?: string;
  readonly message: string;
}

export interface AttackKnowledgePromotionCandidateDiff {
  readonly role: string;
  readonly ordinal: number;
  readonly required: boolean;
  readonly expectedNodeType: string;
  readonly candidateId: string;
  readonly candidateStatus: string;
  readonly reviewedBy: string | null;
  readonly reviewedAt: string | null;
  readonly proposedNode: {
    readonly id: string;
    readonly nodeType: string;
    readonly version: number;
    readonly contentHash: string;
    readonly title: string;
    readonly summary: string;
  } | null;
}

export interface AttackKnowledgePromotionEdgeDiff {
  readonly edgeKey: string;
  readonly sourceRole: string;
  readonly targetRole: string;
  readonly edgeType: string;
  readonly action: "create" | "reuse" | "blocked";
}

export interface AttackKnowledgePromotionPreview {
  readonly schemaVersion: "2.4";
  readonly ready: boolean;
  readonly replay: boolean;
  readonly reviewHash: string;
  readonly blockers: readonly AttackKnowledgePromotionBlocker[];
  readonly review: {
    readonly bundle: {
      readonly id: string;
      readonly semanticFingerprint: string;
      readonly kind: "operational_hazard" | "reusable_fact" | "reusable_bundle";
      readonly exactProcedureCounts: AttackKnowledgeBundleSummary["exactProcedureCounts"];
      readonly firstObservedAt: string;
      readonly lastObservedAt: string;
    };
    readonly candidates: readonly AttackKnowledgePromotionCandidateDiff[];
    readonly edges: readonly AttackKnowledgePromotionEdgeDiff[];
    readonly operationalHazardProfile: {
      readonly action: "create" | "update" | "reuse" | "blocked";
      readonly hazardNodeId: string | null;
      readonly expectedVersion: number | null;
    } | null;
    readonly verification: {
      readonly minimumEvidenceItems: number;
      readonly evidence: readonly AttackKnowledgeEvidenceBinding[];
    };
  };
}

export interface AttackKnowledgePromotionReceipt {
  readonly schemaVersion: "2.4";
  readonly status: "materialized" | "replayed";
  readonly receiptId: string;
  readonly bundleId: string;
  readonly reviewHash: string;
  readonly auditRecordId: string;
  readonly edgeIds: readonly string[];
  readonly hazardProfileNodeId: string | null;
  readonly hazardProfileVersion: number | null;
  readonly promotedAt: string;
}

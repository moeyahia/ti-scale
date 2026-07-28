export type CveApplicability =
  | "confirmed"
  | "likely"
  | "possible"
  | "not_applicable"
  | "insufficient_evidence";

export type CveSourceKind = "cve_org" | "nvd" | "mitre" | "cisa" | "vendor";
export type KevStatus = "listed" | "not_listed" | "unknown";
export type CveApplicabilityReviewDecision =
  | "confirm_applicability"
  | "mark_not_applicable"
  | "request_more_evidence";
export type CveApplicabilityReviewState =
  | "unreviewed"
  | "confirmed"
  | "not_applicable"
  | "more_evidence_requested";

export type CveIntelligenceJson =
  | string
  | number
  | boolean
  | null
  | readonly CveIntelligenceJson[]
  | { readonly [key: string]: CveIntelligenceJson };

export interface CveSourceLink {
  readonly kind: CveSourceKind;
  readonly url: string;
  readonly label: string;
}

export interface CveApplicabilityReviewReceipt {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly cveApplicabilityId: string;
  readonly version: number;
  readonly decision: CveApplicabilityReviewDecision;
  readonly previousApplicability: CveApplicability;
  readonly resultingApplicability: Extract<
    CveApplicability,
    "confirmed" | "not_applicable" | "insufficient_evidence"
  >;
  readonly reason: string;
  readonly actor: {
    readonly type: "operator" | "agent" | "worker" | "system";
    readonly id: string;
  };
  readonly expectedRecordUpdatedAt: string;
  readonly auditRecordId: string;
  readonly eventId: string;
  readonly createdAt: string;
}

export interface CveApplicabilityRecord {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly assetNodeId?: string;
  readonly serviceNodeId?: string;
  readonly cveId: string;
  readonly title: string;
  readonly description: string;
  readonly component: string;
  readonly detectedVersion?: string;
  readonly affectedRange?: string;
  readonly cpeOrPackage: Readonly<Record<string, CveIntelligenceJson>>;
  readonly applicability: CveApplicability;
  readonly confidence: number;
  readonly reasoningSummary: string;
  readonly cvss: Readonly<Record<string, CveIntelligenceJson>>;
  readonly cwe: readonly string[];
  readonly epss?: number;
  readonly kevStatus?: KevStatus;
  readonly exploitMaturity?: string;
  readonly publishedAt?: string;
  readonly modifiedAt?: string;
  readonly sourceLinks: readonly CveSourceLink[];
  readonly sourceRetrievedAt: string;
  readonly sourceVersion?: string;
  readonly discoveryAgentId?: string;
  readonly versionEvidenceId?: string;
  readonly reviewState: CveApplicabilityReviewState;
  readonly reviewVersion: number;
  readonly latestReview?: CveApplicabilityReviewReceipt;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CveApplicabilityList {
  readonly schemaVersion: "2.4";
  readonly items: readonly CveApplicabilityRecord[];
}

export interface CveApplicabilityDetail {
  readonly schemaVersion: "2.4";
  readonly record: CveApplicabilityRecord;
}

export interface CveApplicabilityReviewDetail {
  readonly schemaVersion: "2.4";
  readonly record: CveApplicabilityRecord;
  readonly receipt: CveApplicabilityReviewReceipt;
}

export interface ReviewCveApplicabilityRequest {
  readonly expectedRunId: string;
  readonly decision: CveApplicabilityReviewDecision;
  readonly reason: string;
  readonly expectedReviewVersion: number;
  readonly expectedUpdatedAt: string;
}

export interface CveApplicabilityFilter {
  readonly runId?: string;
  readonly assetNodeId?: string;
  readonly serviceNodeId?: string;
  readonly applicability?: CveApplicability;
  readonly limit?: number;
}

export interface MissionScopedNvdDetail {
  readonly schemaVersion: "ti-scale.mission-nvd-detail.v1";
  readonly summary: string;
  readonly context: {
    readonly missionId: string;
    readonly runId: string;
    readonly stepId: string;
    readonly reviewedCveRef: string;
    readonly applicability: CveApplicability;
    readonly confidence: number;
    readonly reviewedAt: string;
  };
  readonly detail: {
    readonly cveId: string;
    readonly publishedAt?: string;
    readonly lastModifiedAt?: string;
    readonly strongestCvss?: {
      readonly version: string;
      readonly baseScore: number;
      readonly baseSeverity: "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";
    };
    readonly weaknesses: readonly string[];
    readonly referenceCount: number;
    /** The public description text is deliberately absent from this contract. */
    readonly externalDescription: {
      readonly contentSha256: string;
      readonly classification: "external_untrusted";
      readonly lifecycle: "quarantined";
      readonly promptEligible: false;
    };
  };
  readonly provenance: {
    readonly authority: "NIST National Vulnerability Database";
    readonly api: "NVD API 2.0";
    readonly recordUrl: string;
    readonly retrievedAt: string;
    readonly invocationId: string;
    readonly connectionId: string;
    readonly toolName: "get_cve_details";
    readonly configurationSha256: string;
    readonly capabilityManifestSha256: string;
    readonly inputSha256: string;
    readonly resultSha256: string;
    readonly startedAt: string;
    readonly completedAt: string;
    readonly auditRecordId: string;
    readonly redaction: {
      readonly apiUrl: "removed";
      readonly externalDescriptionText: "quarantined_not_returned";
      readonly externalReferences: "count_only";
      readonly providerErrorBody: "never_retained";
    };
  };
  readonly targetInteraction: false;
  readonly executionAuthority: "none";
}

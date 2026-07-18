export type OperationalSensitivity = "public" | "internal" | "private" | "restricted";

export type OperationalJsonValue =
  | string
  | number
  | boolean
  | null
  | readonly OperationalJsonValue[]
  | { readonly [key: string]: OperationalJsonValue };

export interface OperationalTruthPage<T> {
  readonly schemaVersion: "2.4";
  readonly items: readonly T[];
  readonly nextCursor: string | null;
}

export interface EngagementLogRecordV24 {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly planId?: string;
  readonly stepId?: string;
  readonly actionId?: string;
  readonly attackAttemptId?: string;
  readonly assetId?: string;
  readonly agentId?: string;
  readonly providerTurnId?: string;
  readonly toolCallId?: string;
  readonly severity: "debug" | "info" | "notice" | "warning" | "error" | "critical";
  readonly domain: string;
  readonly recordType: string;
  readonly humanSummary: string;
  readonly technicalPayload: OperationalJsonValue;
  readonly contentHash: string;
  readonly sensitivity: OperationalSensitivity;
  readonly traceId?: string;
  readonly spanId?: string;
  readonly occurredAt: string;
  readonly createdAt: string;
}

export interface ObservationV24 {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly assetId?: string;
  readonly observationType: string;
  readonly statement: string;
  readonly normalizedValue: OperationalJsonValue;
  readonly confidence: number;
  readonly verificationState: "unverified" | "corroborated" | "conflicting" | "stale" | "rejected";
  readonly sourceAgentId?: string;
  readonly sourceTool?: string;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
  readonly sensitivity: OperationalSensitivity;
  readonly sources: readonly {
    readonly logRecordId: string;
    readonly parserId: string;
    readonly parserVersion: string;
  }[];
  readonly createdAt: string;
}

export type EvidenceCandidateStateV24 = "candidate" | "validating" | "promoted" | "rejected" | "demoted";

export interface EvidenceCandidateV24 {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly observationId?: string;
  readonly artifactId?: string;
  readonly evidenceType: string;
  readonly label: string;
  readonly meaning: string;
  readonly promotionReason: string;
  readonly validationRequirements: readonly string[];
  readonly state: EvidenceCandidateStateV24;
  readonly sensitivity: OperationalSensitivity;
  readonly proposedBy: string;
  readonly reviewedBy?: string;
  readonly reviewReason?: string;
  readonly promotedEvidenceId?: string;
  readonly createdAt: string;
  readonly reviewedAt?: string;
}

export interface VerifiedEvidenceV24 {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly source: string;
  readonly acquiredAt: string;
  readonly target: string;
  readonly evidenceType: string;
  readonly contentHash: string;
  readonly provenance: OperationalJsonValue;
  readonly confidence: number;
  readonly sensitivity: OperationalSensitivity;
  readonly verificationState: "verified";
  readonly summary: string;
  readonly artifactId?: string;
  readonly createdBy: string;
  readonly createdAt: string;
}

export interface EvidenceCustodyEventV24 {
  readonly id: string;
  readonly evidenceId: string;
  readonly eventType: string;
  readonly actor: string;
  readonly details: OperationalJsonValue;
  readonly occurredAt: string;
}

export interface EngagementLogDetailV24 {
  readonly schemaVersion: "2.4";
  readonly log: EngagementLogRecordV24;
}

export interface ObservationDetailV24 {
  readonly schemaVersion: "2.4";
  readonly observation: ObservationV24;
}

export interface EvidenceCandidateDetailV24 {
  readonly schemaVersion: "2.4";
  readonly candidate: EvidenceCandidateV24;
}

export type EvidenceCandidateMutationV24 = EvidenceCandidateDetailV24;

export interface VerifiedEvidenceMutationV24 {
  readonly schemaVersion: "2.4";
  readonly evidence: VerifiedEvidenceV24;
}

export interface VerifiedEvidenceDetailV24 extends VerifiedEvidenceMutationV24 {
  readonly chainOfCustody: readonly EvidenceCustodyEventV24[];
}

export const FAILURE_CATEGORIES_V24 = [
  "authentication_missing",
  "dependency_missing",
  "mcp_unavailable",
  "provider_unavailable",
  "rate_limit",
  "provider_refused",
  "provider_enforcement_incompatible",
  "target_unreachable",
  "scope_denied",
  "policy_denied",
  "guided_decision_missing",
  "invalid_input",
  "deterministic_tool_error",
  "timeout",
  "worker_lost",
  "plan_dependency_unresolved",
  "evidence_insufficient",
  "no_progress_loop",
  "budget_exhausted",
  "restart_recovery_required",
  "migration_integrity_error",
  "unknown",
] as const;

export type FailureCategoryV24 = (typeof FAILURE_CATEGORIES_V24)[number];
export type FailureDiagnosisStateV24 = "active" | "resolved" | "superseded" | "terminal";
export type FailureOperatorActionKindV24 =
  | "test_connection"
  | "configure_dependency"
  | "use_compatible_fallback"
  | "retry_bounded"
  | "resume_checkpoint"
  | "reassign"
  | "amend_plan"
  | "skip"
  | "start_new_run"
  | "terminate_gracefully";

export interface FailureDiagnosisV24 {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly assignmentId?: string;
  readonly actionId?: string;
  readonly attackAttemptId?: string;
  readonly subjectType: "mission" | "run" | "step" | "assignment" | "action" | "attack_attempt";
  readonly subjectId: string;
  readonly humanReason: string;
  readonly category: FailureCategoryV24;
  readonly code: string;
  readonly originatingComponent: string;
  readonly lastSuccessEventId?: string;
  readonly failedComponentRef?: string;
  readonly targetSummary?: string;
  readonly policyOrDependency?: string;
  readonly rawErrorLogId?: string;
  readonly retryHistory: OperationalJsonValue;
  readonly progressBeforeFailure: OperationalJsonValue;
  readonly preservedReferences: readonly {
    readonly kind: "event" | "log" | "evidence" | "artifact" | "checkpoint" | "finding" | "memory";
    readonly id: string;
    readonly meaning: string;
  }[];
  readonly retryable: boolean;
  readonly automaticRecovery: OperationalJsonValue;
  readonly remediation: string;
  readonly operatorActions: readonly {
    readonly kind: FailureOperatorActionKindV24;
    readonly label: string;
    readonly consequence: string;
    readonly requiresConfirmation: boolean;
  }[];
  readonly objectiveImpact: string;
  readonly state: FailureDiagnosisStateV24;
  readonly createdAt: string;
  readonly resolvedAt?: string;
}

export interface FailureDiagnosisListV24 {
  readonly schemaVersion: "2.4";
  readonly items: readonly FailureDiagnosisV24[];
}

export interface FailureDiagnosisDetailV24 {
  readonly schemaVersion: "2.4";
  readonly diagnosis: FailureDiagnosisV24;
}

export type FailureDiagnosisMutationV24 = FailureDiagnosisDetailV24;

export interface ResolveFailureDiagnosisRequestV24 {
  readonly actionKind: FailureOperatorActionKindV24;
  readonly verifiedOutcome: string;
  readonly confirmed: true;
}

export interface OperationalTruthPageQueryV24 {
  readonly runId?: string;
  readonly stepId?: string;
  readonly cursor?: string;
  readonly limit?: number;
}

export interface EvidenceCandidateQueryV24 extends OperationalTruthPageQueryV24 {
  readonly state?: EvidenceCandidateStateV24;
}

export interface FailureDiagnosisQueryV24 {
  readonly states?: readonly FailureDiagnosisStateV24[];
  readonly limit?: number;
}

export interface VerifyEvidenceCandidateRequestV24 {
  readonly reason: string;
  readonly source: string;
  readonly target: string;
  readonly acquiredAt: string;
  readonly confidence: number;
  readonly provenance: {
    readonly method: string;
    readonly explanation: string;
    readonly sources: readonly {
      readonly kind: "observation" | "engagement_log" | "artifact" | "operator_supplied";
      readonly id: string;
    }[];
  };
  readonly custody: readonly {
    readonly eventType: "acquired" | "transferred" | "stored" | "validated";
    readonly actor: string;
    readonly occurredAt: string;
    readonly details?: OperationalJsonValue;
  }[];
  readonly satisfiedAdditionalRequirements?: readonly string[];
  readonly expectedContentHash?: string;
}

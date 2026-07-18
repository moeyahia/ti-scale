export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export type Sensitivity = "public" | "internal" | "private" | "restricted";
export type LogSeverity = "debug" | "info" | "notice" | "warning" | "error" | "critical";
export type ObservationVerificationState = "unverified" | "corroborated" | "conflicting" | "stale" | "rejected";
export type EvidenceCandidateState = "candidate" | "validating" | "promoted" | "rejected" | "demoted";

export interface OperationalActor {
  readonly id: string;
  readonly type: "operator" | "agent" | "worker" | "system";
}

export interface EngagementLogRecord {
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
  readonly severity: LogSeverity;
  readonly domain: string;
  readonly recordType: string;
  readonly humanSummary: string;
  readonly technicalPayload: JsonValue;
  readonly contentHash: string;
  readonly sensitivity: Sensitivity;
  readonly traceId?: string;
  readonly spanId?: string;
  readonly occurredAt: string;
  readonly createdAt: string;
}

export interface AppendEngagementLogInput {
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
  readonly severity: LogSeverity;
  readonly domain: string;
  readonly recordType: string;
  readonly humanSummary: string;
  readonly technicalPayload: unknown;
  readonly sensitivity: Sensitivity;
  readonly traceId?: string;
  readonly spanId?: string;
  readonly occurredAt: string;
}

export interface ObservationSource {
  readonly logRecordId: string;
  readonly parserId: string;
  readonly parserVersion: string;
}

export interface Observation {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly assetId?: string;
  readonly observationType: string;
  readonly statement: string;
  readonly normalizedValue: JsonValue;
  readonly confidence: number;
  readonly verificationState: ObservationVerificationState;
  readonly sourceAgentId?: string;
  readonly sourceTool?: string;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
  readonly sensitivity: Sensitivity;
  readonly sources: readonly ObservationSource[];
  readonly createdAt: string;
}

export interface CreateObservationInput {
  readonly missionId: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly assetId?: string;
  readonly observationType: string;
  readonly statement: string;
  readonly normalizedValue: unknown;
  readonly confidence: number;
  readonly verificationState?: Extract<ObservationVerificationState, "unverified" | "corroborated" | "conflicting">;
  readonly sourceAgentId?: string;
  readonly sourceTool?: string;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
  readonly sensitivity: Sensitivity;
  readonly sources: readonly ObservationSource[];
}

export const CORE_EVIDENCE_REQUIREMENTS = [
  "immutable_content_hash",
  "attributable_provenance",
  "normalized_target",
  "acquired_time",
  "chain_of_custody",
] as const;

export interface EvidenceCandidate {
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
  readonly state: EvidenceCandidateState;
  readonly sensitivity: Sensitivity;
  readonly proposedBy: string;
  readonly reviewedBy?: string;
  readonly reviewReason?: string;
  readonly promotedEvidenceId?: string;
  readonly createdAt: string;
  readonly reviewedAt?: string;
}

export interface ProposeEvidenceCandidateInput {
  readonly missionId: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly observationId?: string;
  readonly artifactId?: string;
  readonly evidenceType: string;
  readonly label: string;
  readonly meaning: string;
  readonly promotionReason: string;
  readonly additionalValidationRequirements?: readonly string[];
  readonly sensitivity: Sensitivity;
  readonly proposedBy: string;
}

export interface EvidenceProvenanceSource {
  readonly kind: "observation" | "engagement_log" | "artifact" | "operator_supplied";
  readonly id: string;
}

export interface EvidenceProvenance {
  readonly method: string;
  readonly explanation: string;
  readonly sources: readonly EvidenceProvenanceSource[];
}

export interface EvidenceCustodyEventInput {
  readonly eventType: "acquired" | "transferred" | "stored" | "validated";
  readonly actor: string;
  readonly occurredAt: string;
  readonly details?: unknown;
}

export interface VerifyEvidenceCandidateInput {
  readonly candidateId: string;
  readonly actor: OperationalActor;
  readonly reason: string;
  readonly source: string;
  readonly target: string;
  readonly acquiredAt: string;
  readonly confidence: number;
  readonly provenance: EvidenceProvenance;
  readonly custody: readonly EvidenceCustodyEventInput[];
  readonly satisfiedAdditionalRequirements?: readonly string[];
  readonly expectedContentHash?: string;
}

export interface VerifiedEvidence {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly source: string;
  readonly acquiredAt: string;
  readonly target: string;
  readonly evidenceType: string;
  readonly contentHash: string;
  readonly provenance: JsonValue;
  readonly confidence: number;
  readonly sensitivity: Sensitivity;
  readonly verificationState: "verified";
  readonly summary: string;
  readonly artifactId?: string;
  readonly createdBy: string;
  readonly createdAt: string;
}

export interface EvidenceCustodyEvent {
  readonly id: string;
  readonly evidenceId: string;
  readonly eventType: string;
  readonly actor: string;
  readonly details: JsonValue;
  readonly occurredAt: string;
}

export interface OperationalTruthPageCursor {
  readonly createdAt: string;
  readonly id: string;
}

export interface OperationalTruthPage<T> {
  readonly items: readonly T[];
  readonly nextCursor?: OperationalTruthPageCursor;
}

export interface CandidateDecisionInput {
  readonly candidateId: string;
  readonly actor: OperationalActor;
  readonly reason: string;
}

export interface FindingVerificationReadiness {
  readonly findingId: string;
  readonly sufficient: boolean;
  readonly supportingEvidenceIds: readonly string[];
  readonly rejectedEvidenceIds: readonly string[];
  readonly contradictoryEvidenceIds: readonly string[];
  readonly reasons: readonly string[];
}

export interface VerifyFindingInput {
  readonly findingId: string;
  readonly expectedVersion: number;
  readonly actor: OperationalActor;
  readonly reason: string;
}

export const FAILURE_CATEGORIES = [
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

export type FailureCategory = typeof FAILURE_CATEGORIES[number];
export type FailureSubjectType = "mission" | "run" | "step" | "assignment" | "action" | "attack_attempt";
export type FailureDiagnosisState = "active" | "resolved" | "superseded" | "terminal";

export const FAILURE_OPERATOR_ACTION_KINDS = [
  "test_connection",
  "configure_dependency",
  "use_compatible_fallback",
  "retry_bounded",
  "resume_checkpoint",
  "reassign",
  "amend_plan",
  "skip",
  "start_new_run",
  "terminate_gracefully",
] as const;

export type FailureOperatorActionKind = typeof FAILURE_OPERATOR_ACTION_KINDS[number];

export interface FailureOperatorAction {
  readonly kind: FailureOperatorActionKind;
  readonly label: string;
  readonly consequence: string;
  readonly requiresConfirmation: boolean;
}

export interface FailureReference {
  readonly kind: "event" | "log" | "evidence" | "artifact" | "checkpoint" | "finding" | "memory";
  readonly id: string;
  readonly meaning: string;
}

export interface FailureDiagnosis {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly assignmentId?: string;
  readonly actionId?: string;
  readonly attackAttemptId?: string;
  readonly subjectType: FailureSubjectType;
  readonly subjectId: string;
  readonly humanReason: string;
  readonly category: FailureCategory;
  readonly code: string;
  readonly originatingComponent: string;
  readonly lastSuccessEventId?: string;
  readonly failedComponentRef?: string;
  readonly targetSummary?: string;
  readonly policyOrDependency?: string;
  readonly rawErrorLogId?: string;
  readonly retryHistory: JsonValue;
  readonly progressBeforeFailure: JsonValue;
  readonly preservedReferences: readonly FailureReference[];
  readonly retryable: boolean;
  readonly automaticRecovery: JsonValue;
  readonly remediation: string;
  readonly operatorActions: readonly FailureOperatorAction[];
  readonly objectiveImpact: string;
  readonly state: FailureDiagnosisState;
  readonly createdAt: string;
  readonly resolvedAt?: string;
}

export interface CreateFailureDiagnosisInput {
  readonly missionId: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly assignmentId?: string;
  readonly actionId?: string;
  readonly attackAttemptId?: string;
  readonly subjectType: FailureSubjectType;
  readonly subjectId: string;
  readonly humanReason: string;
  readonly category: FailureCategory;
  readonly code: string;
  readonly originatingComponent: string;
  readonly lastSuccessEventId?: string;
  readonly failedComponentRef?: string;
  readonly targetSummary?: string;
  readonly policyOrDependency?: string;
  readonly rawErrorLogId?: string;
  readonly retryHistory?: unknown;
  readonly progressBeforeFailure?: unknown;
  readonly preservedReferences?: readonly FailureReference[];
  readonly retryable: boolean;
  readonly automaticRecovery?: unknown;
  readonly remediation: string;
  readonly operatorActions: readonly FailureOperatorAction[];
  readonly objectiveImpact: string;
  readonly terminal?: boolean;
  readonly actor: OperationalActor;
}

export interface ResolveFailureDiagnosisInput {
  readonly diagnosisId: string;
  readonly actor: OperationalActor;
  readonly actionKind: FailureOperatorActionKind;
  readonly verifiedOutcome: string;
  readonly confirmed: boolean;
}

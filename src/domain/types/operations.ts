export type OperationsStatus =
  | "available" | "busy" | "degraded" | "offline" | "quarantined"
  | "healthy" | "unhealthy" | "unknown" | "operational";

export interface OperationsPage<T> {
  schemaVersion: "2.4";
  items: T[];
  nextCursor: string | null;
}

export interface MissionReference { id: string; name: string }
export interface Correlation { traceId: string | null; spanId: string | null; contextPackId?: string | null }

export type DecisionInboxKind =
  | "guided_decision"
  | "autonomous_contract"
  | "autonomous_exception"
  | "administrative_approval";

interface DecisionInboxBase {
  id: string;
  kind: DecisionInboxKind;
  mission: (MissionReference & { engagementId: string | null }) | null;
  run: { id: string; status: string; journey: "autonomous" | "guided" } | null;
  status: string;
  title: string;
  summary: string;
  createdAt: string;
  resolvedAt: string | null;
  expiresAt: string | null;
  deepLink: string;
}

export interface GuidedDecisionInboxRecord extends DecisionInboxBase {
  kind: "guided_decision";
  mission: MissionReference & { engagementId: string | null };
  run: { id: string; status: string; journey: "guided" };
  exactStep: {
    stepId: string;
    actionFingerprint: string;
    requestedParameters: unknown;
    rationale: string;
    riskClass: string;
    reversibility: string;
    decisionActor: string | null;
    decisionReason: string | null;
  };
}

export interface AutonomousContractInboxRecord extends DecisionInboxBase {
  kind: "autonomous_contract";
  mission: MissionReference & { engagementId: string | null };
  contract: {
    version: number;
    hash: string;
    state: "draft" | "confirmed" | "superseded" | "revoked";
    confirmedBy: string | null;
    confirmedAt: string | null;
  };
}

export interface AutonomousExceptionInboxRecord extends DecisionInboxBase {
  kind: "autonomous_exception";
  mission: MissionReference & { engagementId: string | null };
  run: { id: string; status: string; journey: "autonomous" };
  exception: {
    eventType: string;
    sequence: number;
    phase: "active" | "post_run";
    code: string | null;
    category: string | null;
    traceId: string | null;
    details: unknown;
  };
}

export interface AdministrativeApprovalInboxRecord extends DecisionInboxBase {
  kind: "administrative_approval";
  approval: {
    approvalType: string;
    requestedBy: string;
    policyRule: string | null;
    request: unknown;
    decidedBy: string | null;
    reviewAvailable: boolean;
    reviewUnavailableReason: string | null;
  };
}

export type DecisionInboxRecord =
  | GuidedDecisionInboxRecord
  | AutonomousContractInboxRecord
  | AutonomousExceptionInboxRecord
  | AdministrativeApprovalInboxRecord;

export interface AdministrativeApprovalReviewRecord {
  schemaVersion: "2.4";
  approval: {
    id: string;
    missionId: string | null;
    runId: string | null;
    approvalType: string;
    status: "approved" | "rejected";
    decidedBy: string;
    decidedAt: string;
    decisionReason: string;
    runtimeStateChanged: false;
    autonomousActionUnblocked: false;
  };
}

export interface AgentRecord {
  id: string;
  role: string;
  displayName: string;
  status: string;
  version: string;
  lastHeartbeatAt: string | null;
  updatedAt: string;
  providerPolicy: unknown;
  toolPolicy: unknown;
  configuration: unknown;
  assignmentHealth: {
    queueDepth: number; active: number; completed: number; failed: number;
    successRate: number | null; meanCompletionSeconds: number | null; lastAssignmentAt: string | null;
  };
  health: HealthStatus | null;
  capabilities?: AgentCapability[];
  healthHistory?: HealthStatus[];
}

export interface AgentCapability { name: string; source: string; enabled: boolean; metadata: unknown }
export interface AgentAssignment {
  id: string; status: string; mission: MissionReference & { engagementId: string | null };
  run: { id: string; status: string; journey: "autonomous" | "guided"; progress: number | null };
  step: { id: string; phase: string; title: string } | null;
  lease: { owner: string | null; acquiredAt: string | null; lastHeartbeatAt: string | null; expiresAt: string | null; expired: boolean };
  startedAt: string | null; endedAt: string | null; updatedAt: string;
}

export type RecoveryActionKind = "resume" | "replan" | "reassign" | "change_provider" | "terminate";
export interface RecoveryActionAvailability {
  kind: RecoveryActionKind; label: string; available: boolean; reason: string;
  command: "resume" | "replan" | "reassign" | "change_provider" | "cancel" | null;
}
export interface RecoveryMutationRecord {
  schemaVersion: "2.4";
  mutation: {
    kind: "replan" | "reassign" | "change_provider";
    eventId: string; checkpointId: string; continuationId: string | null;
    agentId: string | null; assignmentId: string | null;
    providerId: string | null; providerRouteVersion: number | null;
  };
  run: {
    id: string; journey: "autonomous" | "guided"; status: string; version: number;
    planId: string; planVersion: number; stepId: string; assignmentId: string;
  };
}
export interface RunRecoveryRecord {
  schemaVersion: "2.4";
  recoveryRequired: boolean;
  run: {
    id: string; missionId: string; missionName: string; journey: "autonomous" | "guided"; status: string; version: number;
    statusReason: string | null; currentStepId: string | null; currentOwnerId: string | null;
    nextAction: string | null; leaseExpiresAt: string | null;
  };
  boundary: {
    planId: string; planVersion: number; stepId: string; assignmentId: string; agentId: string; actionKind: string | null;
  } | null;
  reassignmentCandidates: Array<{
    agentId: string; displayName: string; status: "available"; capabilities: string[];
  }>;
  providerCandidates: Array<{
    providerId: string; status: "healthy"; supportsGuided: boolean; enforcesAutonomousBoundary: boolean;
    reportsExactTokenUsage: boolean; reportsExactCostUsage: boolean;
  }>;
  detection: {
    summary: string; category: string | null;
    evidence: Array<{ id: string; eventType: string; summary: string; occurredAt: string; sequence: number }>;
    failedActions: Array<{
      id: string; status: string; intentSummary: string; resultSummary: string | null;
      errorCategory: string | null; retryCount: number; endedAt: string | null;
    }>;
  };
  checkpoint: {
    id: string; eventSequence: number; planVersion: number | null; createdAt: string; stateHash: string;
    inFlightClassification: string | null; completedActionCount: number;
    inFlightActions: Array<{ id: string; status: string; idempotent: boolean; destructive: boolean }>;
  } | null;
  attempts: {
    retryCount: number; retryLimit: number | null; retriesRemaining: number | null;
    replanCount: number; replanLimit: number | null; replansRemaining: number | null;
  };
  proposedRecovery: {
    kind: "automatic_recovery" | "guided_decision" | "operator_resume" | "safe_stop" | "failed_safely" | "none";
    summary: string; basis: string; impact: { time: string; cost: string; scope: string };
  };
  guidedDecision: { id: string; stepId: string; actionFingerprint: string; rationale: string; riskClass: string; expiresAt: string } | null;
  failedAttemptMemories: Array<{
    kind: "memory" | "lesson"; id: string; title: string; status: string;
    confidence: number | null; failureCategory: string | null;
  }>;
  actions: RecoveryActionAvailability[];
}

export interface FollowUpRunRecord {
  schemaVersion: "2.4";
  sourceRunId: string;
  run: {
    id: string; missionId: string; missionName: string; journey: "autonomous" | "guided";
    status: "planning"; statusReason: string; nextAction: string; createdAt: string;
  };
  selectedLessons: Array<{
    id: string; nodeId: string; statement: string; selectionState: "eligible_for_planning";
  }>;
  nextUrl: string;
}

export interface EvidenceRecord {
  id: string; mission: MissionReference; runId: string | null; stepId: string | null; actionId: string | null;
  run?: { id: string } | null;
  source: string; acquiredAt: string; target: string | null; evidenceType: string; contentHash: string;
  recordClass: "evidence" | "operational_log";
  provenance: unknown; confidence: number | null; sensitivity: string; verificationState: string;
  summary: string; hasExtractedText: boolean; artifactId: string | null; createdBy: string; createdAt: string;
  artifact?: { id: string; artifactType: string } | null;
  chainOfCustody?: Array<{ id: string; eventType: string; actor: string; details: unknown; occurredAt: string }>;
}

export interface FindingRecord {
  id: string; mission: MissionReference; runId: string | null; title: string; severity: string;
  run?: { id: string } | null;
  confidence: number | null; affectedScope: string; description: string; impact: string;
  reproductionNotes: string | null; remediation: string | null; reviewStatus: string; operatorOverride: boolean;
  version: number; evidenceCount: number; verifiedEvidenceCount: number; createdAt: string; updatedAt: string;
  evidence?: Array<{ id: string; relationship: string; summary: string; evidenceType: string; verificationState: string; contentHash: string; addedAt: string }>;
}

export interface ArtifactRecord {
  id: string; mission: MissionReference; runId: string | null; stepId: string | null; actionId: string | null;
  run?: { id: string } | null;
  journey: "autonomous" | "guided";
  artifactType: string; contentHash: string; byteSize: number; mediaType: string; sensitivity: string;
  metadata: unknown; storage: { scheme: string; available: boolean };
  evaluation: { id: string; evidenceCoverage: number | null } | null; contextPackIds: string[]; createdAt: string;
  evidence?: Array<{
    id: string; summary: string; evidenceType: string; verificationState: string;
    contentHash: string; acquiredAt: string;
  }>;
  /** Present on canonical detail responses; list projections remain metadata-only. */
  delivery?: {
    state: "ready" | "metadata_only" | "reconciliation_required" | "quarantined";
    downloadable: boolean;
    code: string;
    reason: string;
    remediation: string | null;
    verifiedEvidenceCount: number;
  };
}

export interface ActionRecord {
  id: string;
  mission: MissionReference;
  runId: string;
  journey: "autonomous" | "guided";
  step: { id: string; phase: string; title: string } | null;
  agentId: string | null;
  actionType: string;
  actionClass: string;
  target: string | null;
  status: "queued" | "running" | "succeeded" | "failed" | "cancelled" | "timed_out" | "denied";
  intentSummary: string;
  resultSummary: string | null;
  errorCategory: string | null;
  retryCount: number;
  guidedDecisionId: string | null;
  contractId: string | null;
  contextPackId: string | null;
  correlation: { traceId: string | null; spanId: string | null };
  startedAt: string | null;
  endedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface EventRecord {
  id: string; occurredAt: string; eventType: string; mission: MissionReference | null; runId: string | null;
  sequence: number | null; actor: { type: string; id: string | null }; summary: string; payload: unknown;
  eventSchemaVersion: number; journey: "autonomous" | "guided" | null; correlation: Correlation;
  sensitivity: string; redaction: unknown;
}

export interface LogRecord {
  id: string; occurredAt: string; severity: string; domain: string; message: string; attributes: unknown;
  mission: MissionReference | null; runId: string | null; stepId: string | null; actionId: string | null;
  correlation: Correlation; sensitivity: string;
}

export type TraceStatus = "active" | "completed" | "failed";
export type TraceRecordKind = "event" | "log" | "action" | "tool_call";
export interface TraceSummaryRecord {
  id: string; traceId: string; status: TraceStatus; summary: string;
  mission: MissionReference | null; missionCount: number; runId: string | null; runCount: number;
  journey: "autonomous" | "guided" | null; startedAt: string; endedAt: string; durationMs: number;
  counts: { events: number; logs: number; actions: number; toolCalls: number; errors: number };
}
export interface TraceRecord {
  id: string; sourceId: string; kind: TraceRecordKind; title: string; summary: string; status: string;
  mission: MissionReference | null; runId: string | null; stepId: string | null; actionId: string | null;
  agentId: string | null; startedAt: string; endedAt: string; durationMs: number;
  correlation: { traceId: string; spanId: string | null; parentSpanId: string | null };
  raw: unknown;
}
export interface TraceDetailRecord {
  schemaVersion: "2.4";
  trace: TraceSummaryRecord;
  records: OperationsPage<TraceRecord>;
}

export interface HealthStatus {
  id?: string; componentType?: string; componentId?: string; status: string; metrics: unknown;
  message: string | null; capturedAt: string;
}

export interface EvaluationRecord {
  id: string; mission: MissionReference; run: { id: string; status: string }; journey: "autonomous" | "guided";
  scores: unknown; metrics: unknown; retrospective: string; evidenceCoverage: number | null; createdBy: string; createdAt: string;
  budget: EvaluationBudget;
  comparison: EvaluationComparison;
}

export type EvaluationBudgetKey = "wallClockMs" | "providerTokens" | "estimatedCost" | "toolCalls" | "retries" | "replans";
export interface EvaluationBudgetMetric {
  key: EvaluationBudgetKey;
  label: string;
  unit: "milliseconds" | "count" | "cost";
  limit: number | null;
  usage: number | null;
  limitStatus: "configured" | "not_configured";
  usageStatus: "recorded_exact" | "recorded_estimate" | "unknown";
  status: "within_limit" | "limit_reached" | "limit_exceeded" | "not_configured" | "unknown_usage";
  limitSource: "terminal_run_budget" | null;
  usageSource: "terminal_run" | "run_evaluation" | "canonical_records" | null;
}
export interface EvaluationBudget { metrics: EvaluationBudgetMetric[] }

export interface EvaluationComparisonMetric {
  key: string; label: string; unit: "ratio" | "milliseconds" | "count" | "cost";
  favorableDirection: "higher" | "lower"; current: number; prior: number; delta: number;
  relativeDelta: number | null; movement: "favorable" | "unfavorable" | "unchanged";
}

export interface EvaluationComparison {
  status: "available" | "insufficient_data";
  basis: "same_mission_and_journey" | "same_engagement_and_journey" | null;
  reason: string;
  prior: { evaluationId: string; runId: string; terminalStatus: "completed" | "failed" | "cancelled"; evaluatedAt: string } | null;
  terminalStatusMatch: boolean | null;
  metrics: EvaluationComparisonMetric[];
  summary: string;
  createdAt: string;
}

export interface LessonRecord {
  id: string; statement: string; lessonType: string; applicabilityScope: string; engagementId: string | null;
  mission: MissionReference | null; failureCategory: string | null; retryConditions: string | null; confidence: number | null;
  expectedBenefit: string; risk: string; status: string; authoringAgentId: string | null; reviewedBy: string | null;
  reviewedAt: string | null; expiresAt: string | null; supersedesLessonId: string | null; evidenceCount: number;
  supportingEvidenceCount: number; usageCount: number; createdAt: string; updatedAt: string;
  evidence?: Array<{ evidenceId: string | null; runId: string | null; relationship: string; rationale: string; evidenceSummary: string | null; createdAt: string }>;
}

export interface LessonUsageRecord {
  id: string; lesson: { id: string; statement: string }; mission: MissionReference; runId: string;
  stepId: string | null; actionId: string | null; contextPackId: string | null; influenceSummary: string;
  outcome: string | null; measuredImpact: unknown; usedAt: string;
}

export interface ProviderRecord {
  id: string; provider: string; model: string | null; status: string; turnCount: number; completedCount: number;
  failedCount: number; meanLatencyMs: number | null; inputTokens: number; outputTokens: number;
  estimatedCost: number | null; lastTurnAt: string | null;
}

export interface McpRecord {
  id: string; name: string; transport: string; endpointRedacted: string | null; status: string;
  capabilities: unknown; policy: unknown; lastCheckedAt: string | null; updatedAt: string;
}

export interface PolicyRecord {
  id: string; sourceType: string; label: string; policy: unknown; sensitivity: string; updatedAt: string;
}

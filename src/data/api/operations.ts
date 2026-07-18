import {
  parseActionPage, parseAgent, parseAgentAssignments, parseAgents, parseArtifact, parseArtifactPage, parseEvaluationPage,
  parseEventPage, parseEvidence, parseEvidencePage, parseFinding, parseFindingPage, parseHealthPage,
  parseLesson, parseLessonPage, parseLessonUsagePage, parseLogPage, parseMcpPage, parsePolicyPage, parseProviderPage,
  parseFindingReview, parseFollowUpRun, parseLessonReview, parseRecoveryMutation, parseRunRecovery, parseTraceDetail, parseTracePage,
  parseAdministrativeApprovalReview, parseDecisionInboxPage,
} from "../../domain/schemas/operations";
import type {
  ActionRecord, AgentAssignment, AgentRecord, ArtifactRecord, EvaluationRecord, EventRecord, EvidenceRecord, FindingRecord,
  AdministrativeApprovalReviewRecord, DecisionInboxRecord,
  FollowUpRunRecord,
  HealthStatus, LessonRecord, LessonUsageRecord, LogRecord, McpRecord, OperationsPage, PolicyRecord, ProviderRecord,
  RecoveryMutationRecord, RunRecoveryRecord, TraceDetailRecord, TraceSummaryRecord,
} from "../../domain/types/operations";
import { apiRequest } from "./client";

export const OPERATIONS_ENDPOINTS = {
  agents: "/api/v2/agents",
  evidence: "/api/v2/intelligence/evidence",
  evidenceRunExport: "/api/v2/intelligence/evidence/runs",
  findings: "/api/v2/intelligence/findings",
  artifacts: "/api/v2/intelligence/artifacts",
  actions: "/api/v2/operations/actions",
  traces: "/api/v2/observability/traces",
  events: "/api/v2/observability/events",
  logs: "/api/v2/observability/logs",
  auditRunExport: "/api/v2/observability/audit/runs",
  health: "/api/v2/observability/health",
  evaluations: "/api/v2/learning/evaluations",
  lessons: "/api/v2/learning/lessons",
  lessonUsage: "/api/v2/learning/usage",
  reports: "/api/v2/reports",
  runCompletionExport: "/api/v2/reports/runs",
  providers: "/api/v2/system/providers",
  mcp: "/api/v2/system/mcp",
  systemHealth: "/api/v2/system/health",
  policies: "/api/v2/system/policies",
  recovery: "/api/v2/operations/runs",
  decisionInbox: "/api/v2/decision-inbox",
  administrativeApprovals: "/api/v2/administrative-approvals",
} as const;

export type QueryValue = string | number | boolean | null | undefined;
export interface ExactRecoveryBoundaryInput {
  expectedRunVersion: number;
  expectedPlanId: string;
  expectedPlanVersion: number;
  expectedStepId: string;
  expectedAssignmentId: string;
  expectedCheckpointId: string;
  expectedCheckpointStateHash: string;
  expectedCheckpointEventSequence: number;
}
export function queryPath(path: string, query: Record<string, QueryValue>): string {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => { if (value !== undefined && value !== null && value !== "") params.set(key, String(value)); });
  const serialized = params.toString();
  return serialized ? `${path}?${serialized}` : path;
}

function get<T>(path: string, parse: (payload: unknown) => T, signal?: AbortSignal): Promise<T> {
  return apiRequest(path, { method: "GET", signal, parse });
}
function mutate<T>(path: string, body: unknown, parse: (payload: unknown) => T, idempotencyKey: string, signal?: AbortSignal): Promise<T> {
  return apiRequest(path, { method: "POST", signal, headers: { "Idempotency-Key": idempotencyKey }, body: JSON.stringify(body), parse });
}

export const operationsApi = {
  agents: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<AgentRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.agents, query), parseAgents, signal),
  agent: (id: string, signal?: AbortSignal): Promise<AgentRecord> => get(`${OPERATIONS_ENDPOINTS.agents}/${encodeURIComponent(id)}`, parseAgent, signal),
  assignments: (id: string, query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<AgentAssignment>> => get(queryPath(`${OPERATIONS_ENDPOINTS.agents}/${encodeURIComponent(id)}/assignments`, query), parseAgentAssignments, signal),
  evidence: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<EvidenceRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.evidence, query), parseEvidencePage, signal),
  evidenceDetail: (id: string, signal?: AbortSignal): Promise<EvidenceRecord> => get(`${OPERATIONS_ENDPOINTS.evidence}/${encodeURIComponent(id)}`, parseEvidence, signal),
  findings: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<FindingRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.findings, query), parseFindingPage, signal),
  finding: (id: string, signal?: AbortSignal): Promise<FindingRecord> => get(`${OPERATIONS_ENDPOINTS.findings}/${encodeURIComponent(id)}`, parseFinding, signal),
  reviewFinding: (id: string, body: { expectedVersion: number; status: string; reason: string; operatorOverride?: boolean }, key: string, signal?: AbortSignal) => mutate(`${OPERATIONS_ENDPOINTS.findings}/${encodeURIComponent(id)}/review`, body, parseFindingReview, key, signal),
  artifacts: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<ArtifactRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.artifacts, query), parseArtifactPage, signal),
  artifact: (id: string, signal?: AbortSignal): Promise<ArtifactRecord> => get(`${OPERATIONS_ENDPOINTS.artifacts}/${encodeURIComponent(id)}`, parseArtifact, signal),
  artifactDownloadUrl: (id: string): string => `${OPERATIONS_ENDPOINTS.artifacts}/${encodeURIComponent(id)}/download`,
  evidenceRunExportUrl: (runId: string): string => `${OPERATIONS_ENDPOINTS.evidenceRunExport}/${encodeURIComponent(runId)}/export`,
  actions: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<ActionRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.actions, query), parseActionPage, signal),
  traces: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<TraceSummaryRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.traces, query), parseTracePage, signal),
  trace: (traceId: string, query: Record<string, QueryValue>, signal?: AbortSignal): Promise<TraceDetailRecord> => get(queryPath(`${OPERATIONS_ENDPOINTS.traces}/${encodeURIComponent(traceId)}`, query), parseTraceDetail, signal),
  events: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<EventRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.events, query), parseEventPage, signal),
  logs: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<LogRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.logs, query), parseLogPage, signal),
  runAuditExportUrl: (runId: string): string => `${OPERATIONS_ENDPOINTS.auditRunExport}/${encodeURIComponent(runId)}/export`,
  health: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<HealthStatus>> => get(queryPath(OPERATIONS_ENDPOINTS.health, query), parseHealthPage, signal),
  evaluations: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<EvaluationRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.evaluations, query), parseEvaluationPage, signal),
  lessons: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<LessonRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.lessons, query), parseLessonPage, signal),
  lesson: (id: string, signal?: AbortSignal): Promise<LessonRecord> => get(`${OPERATIONS_ENDPOINTS.lessons}/${encodeURIComponent(id)}`, parseLesson, signal),
  reviewLesson: (id: string, body: { expectedUpdatedAt: string; status: string; reason: string }, key: string, signal?: AbortSignal) => mutate(`${OPERATIONS_ENDPOINTS.lessons}/${encodeURIComponent(id)}/review`, body, parseLessonReview, key, signal),
  lessonUsage: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<LessonUsageRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.lessonUsage, query), parseLessonUsagePage, signal),
  reports: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<ArtifactRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.reports, query), parseArtifactPage, signal),
  report: (id: string, signal?: AbortSignal): Promise<ArtifactRecord> => get(`${OPERATIONS_ENDPOINTS.reports}/${encodeURIComponent(id)}`, parseArtifact, signal),
  runCompletionExportUrl: (runId: string): string => `${OPERATIONS_ENDPOINTS.runCompletionExport}/${encodeURIComponent(runId)}/export`,
  providers: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<ProviderRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.providers, query), parseProviderPage, signal),
  mcp: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<McpRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.mcp, query), parseMcpPage, signal),
  systemHealth: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<HealthStatus>> => get(queryPath(OPERATIONS_ENDPOINTS.systemHealth, query), parseHealthPage, signal),
  policies: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<PolicyRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.policies, query), parsePolicyPage, signal),
  recovery: (runId: string, signal?: AbortSignal): Promise<RunRecoveryRecord> => get(`${OPERATIONS_ENDPOINTS.recovery}/${encodeURIComponent(runId)}/recovery`, parseRunRecovery, signal),
  requestRecoveryReplan: (
    runId: string,
    body: ExactRecoveryBoundaryInput & { strategyReason: string },
    key: string,
    signal?: AbortSignal,
  ): Promise<RecoveryMutationRecord> => mutate(
    `${OPERATIONS_ENDPOINTS.recovery}/${encodeURIComponent(runId)}/recovery/replan`,
    body,
    parseRecoveryMutation,
    key,
    signal,
  ),
  reassignRecoverySpecialist: (
    runId: string,
    body: ExactRecoveryBoundaryInput & {
      targetAgentId: string; capability: string; reason: string;
      guidedDecisionId?: string; expectedDecisionFingerprint?: string;
    },
    key: string,
    signal?: AbortSignal,
  ): Promise<RecoveryMutationRecord> => mutate(
    `${OPERATIONS_ENDPOINTS.recovery}/${encodeURIComponent(runId)}/recovery/reassign`,
    body,
    parseRecoveryMutation,
    key,
    signal,
  ),
  changeRecoveryProvider: (
    runId: string,
    body: ExactRecoveryBoundaryInput & {
      providerId: string; reason: string;
      guidedDecisionId?: string; expectedDecisionFingerprint?: string;
    },
    key: string,
    signal?: AbortSignal,
  ): Promise<RecoveryMutationRecord> => mutate(
    `${OPERATIONS_ENDPOINTS.recovery}/${encodeURIComponent(runId)}/recovery/provider`,
    body,
    parseRecoveryMutation,
    key,
    signal,
  ),
  decisionInbox: (query: Record<string, QueryValue>, signal?: AbortSignal): Promise<OperationsPage<DecisionInboxRecord>> => get(queryPath(OPERATIONS_ENDPOINTS.decisionInbox, query), parseDecisionInboxPage, signal),
  reviewAdministrativeApproval: (
    approvalId: string,
    body: { status: "approved" | "rejected"; reason: string },
    key: string,
    signal?: AbortSignal,
  ): Promise<AdministrativeApprovalReviewRecord> => mutate(
    `${OPERATIONS_ENDPOINTS.administrativeApprovals}/${encodeURIComponent(approvalId)}/review`,
    body,
    parseAdministrativeApprovalReview,
    key,
    signal,
  ),
  createFollowUpRun: (
    runId: string,
    body: { reason: string; selectedLessonIds: string[] },
    key: string,
    signal?: AbortSignal,
  ): Promise<FollowUpRunRecord> => mutate(
    `${OPERATIONS_ENDPOINTS.recovery}/${encodeURIComponent(runId)}/follow-up`,
    body,
    parseFollowUpRun,
    key,
    signal,
  ),
};

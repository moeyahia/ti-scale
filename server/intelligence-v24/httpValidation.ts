import { z } from "zod";
import { invalid } from "./errors";
import {
  FAILURE_CATEGORIES,
  FAILURE_OPERATOR_ACTION_KINDS,
  type AppendEngagementLogInput,
  type CandidateDecisionInput,
  type CreateFailureDiagnosisInput,
  type CreateObservationInput,
  type EvidenceCandidateState,
  type OperationalActor,
  type OperationalTruthPageCursor,
  type ProposeEvidenceCandidateInput,
  type ResolveFailureDiagnosisInput,
  type VerifyEvidenceCandidateInput,
  type VerifyFindingInput,
} from "./types";
import { identifier, isoTimestamp } from "./validation";

const ID_PATTERN = /^[A-Za-z0-9._:@/-]{1,240}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;
const ID = z.string().trim().regex(ID_PATTERN);
const SHORT_TEXT = z.string().trim().min(1).max(500);
const TEXT = z.string().trim().min(1).max(4_000);
const TIMESTAMP = z.string().trim().min(1).max(100);
const SENSITIVITY = z.enum(["public", "internal", "private", "restricted"]);
const ACTOR_TYPES = new Set<OperationalActor["type"]>(["operator", "agent", "worker", "system"]);
const CANDIDATE_STATES = new Set<EvidenceCandidateState>([
  "candidate", "validating", "promoted", "rejected", "demoted",
]);

const appendLogBody = z.object({
  runId: ID.optional(),
  planId: ID.optional(),
  stepId: ID.optional(),
  actionId: ID.optional(),
  attackAttemptId: ID.optional(),
  assetId: ID.optional(),
  agentId: ID.optional(),
  providerTurnId: ID.optional(),
  toolCallId: ID.optional(),
  severity: z.enum(["debug", "info", "notice", "warning", "error", "critical"]),
  domain: SHORT_TEXT,
  recordType: SHORT_TEXT,
  humanSummary: TEXT,
  technicalPayload: z.unknown(),
  sensitivity: SENSITIVITY,
  traceId: ID.optional(),
  spanId: ID.optional(),
  occurredAt: TIMESTAMP,
}).strict();

const observationSource = z.object({
  logRecordId: ID,
  parserId: ID,
  parserVersion: z.string().trim().min(1).max(100),
}).strict();

const observationBody = z.object({
  runId: ID.optional(),
  stepId: ID.optional(),
  assetId: ID.optional(),
  observationType: SHORT_TEXT,
  statement: TEXT,
  normalizedValue: z.unknown(),
  confidence: z.number().finite().min(0).max(1),
  verificationState: z.enum(["unverified", "corroborated", "conflicting"]).optional(),
  sourceAgentId: ID.optional(),
  sourceTool: SHORT_TEXT.optional(),
  firstSeenAt: TIMESTAMP,
  lastSeenAt: TIMESTAMP,
  sensitivity: SENSITIVITY,
  sources: z.array(observationSource).min(1).max(50),
}).strict();

const candidateBody = z.object({
  runId: ID.optional(),
  stepId: ID.optional(),
  observationId: ID.optional(),
  artifactId: ID.optional(),
  evidenceType: SHORT_TEXT,
  label: SHORT_TEXT,
  meaning: TEXT,
  promotionReason: z.string().trim().min(1).max(2_000),
  additionalValidationRequirements: z.array(z.string().trim().min(1).max(200)).max(95).optional(),
  sensitivity: SENSITIVITY,
}).strict();

const decisionBody = z.object({ reason: z.string().trim().min(1).max(2_000) }).strict();

const provenanceSource = z.object({
  kind: z.enum(["observation", "engagement_log", "artifact", "operator_supplied"]),
  id: ID,
}).strict();

const verifyCandidateBody = z.object({
  reason: z.string().trim().min(1).max(2_000),
  source: SHORT_TEXT,
  target: z.string().trim().min(1).max(1_000),
  acquiredAt: TIMESTAMP,
  confidence: z.number().finite().min(0).max(1),
  provenance: z.object({
    method: SHORT_TEXT,
    explanation: z.string().trim().min(1).max(2_000),
    sources: z.array(provenanceSource).min(1).max(100),
  }).strict(),
  custody: z.array(z.object({
    eventType: z.enum(["acquired", "transferred", "stored", "validated"]),
    actor: ID,
    occurredAt: TIMESTAMP,
    details: z.unknown().optional(),
  }).strict()).min(1).max(100),
  satisfiedAdditionalRequirements: z.array(z.string().trim().min(1).max(200)).max(100).optional(),
  expectedContentHash: z.string().regex(/^[a-f0-9]{64}$/u).optional(),
}).strict();

const verifyFindingBody = z.object({
  expectedVersion: z.number().int().positive(),
  reason: z.string().trim().min(1).max(2_000),
}).strict();

const failureReference = z.object({
  kind: z.enum(["event", "log", "evidence", "artifact", "checkpoint", "finding", "memory"]),
  id: ID,
  meaning: z.string().trim().min(1).max(1_000),
}).strict();

const failureAction = z.object({
  kind: z.enum([
    "test_connection", "configure_dependency", "use_compatible_fallback",
    "retry_bounded", "resume_checkpoint", "reassign", "amend_plan", "skip",
    "start_new_run", "terminate_gracefully",
  ]),
  label: z.string().trim().min(1).max(300),
  consequence: z.string().trim().min(1).max(1_000),
  requiresConfirmation: z.boolean(),
}).strict();

const failureBody = z.object({
  stepId: ID.optional(),
  assignmentId: ID.optional(),
  actionId: ID.optional(),
  attackAttemptId: ID.optional(),
  subjectType: z.enum(["mission", "run", "step", "assignment", "action", "attack_attempt"]),
  subjectId: ID,
  humanReason: TEXT,
  category: z.enum(FAILURE_CATEGORIES),
  code: ID,
  originatingComponent: ID,
  lastSuccessEventId: ID.optional(),
  failedComponentRef: z.string().trim().min(1).max(1_000).optional(),
  targetSummary: z.string().trim().min(1).max(2_000).optional(),
  policyOrDependency: z.string().trim().min(1).max(2_000).optional(),
  rawErrorLogId: ID.optional(),
  retryHistory: z.unknown().optional(),
  progressBeforeFailure: z.unknown().optional(),
  preservedReferences: z.array(failureReference).max(100).optional(),
  retryable: z.boolean(),
  automaticRecovery: z.unknown().optional(),
  remediation: TEXT,
  operatorActions: z.array(failureAction).min(1).max(20),
  objectiveImpact: TEXT,
  terminal: z.boolean().optional(),
}).strict();

const resolveFailureBody = z.object({
  actionKind: z.enum(FAILURE_OPERATOR_ACTION_KINDS),
  verifiedOutcome: z.string().trim().min(16).max(4_000),
  confirmed: z.literal(true),
}).strict();

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (result.success) return result.data;
  const fields = [...new Set(result.error.issues.map((issue) => issue.path.join(".") || "body"))];
  throw invalid(
    "invalid_request_body",
    `Request body failed validation for: ${fields.slice(0, 10).join(", ")}`,
    "Correct the named fields and submit the request again.",
  );
}

export function authenticatedActor(value: OperationalActor | undefined): OperationalActor {
  if (!value || !ACTOR_TYPES.has(value.type)) {
    throw invalid("authentication_required", "An authenticated operational identity is required");
  }
  return { id: identifier(value.id, "actor.id"), type: value.type };
}

export function requiredIdempotencyKey(value: string | undefined): string {
  const key = value?.trim();
  if (!key || !IDEMPOTENCY_KEY.test(key)) {
    throw invalid(
      "idempotency_key_required",
      "A valid Idempotency-Key header containing 8-200 safe characters is required",
    );
  }
  return key;
}

export function appendLogInput(missionId: string, value: unknown): AppendEngagementLogInput {
  return { missionId, ...parse(appendLogBody, value) };
}

export function observationInput(missionId: string, value: unknown): CreateObservationInput {
  return { missionId, ...parse(observationBody, value) };
}

export function candidateInput(
  missionId: string,
  value: unknown,
  actor: OperationalActor,
): ProposeEvidenceCandidateInput {
  return { missionId, ...parse(candidateBody, value), proposedBy: actor.id };
}

export function candidateDecisionInput(
  candidateId: string,
  value: unknown,
  actor: OperationalActor,
): CandidateDecisionInput {
  return { candidateId, actor, ...parse(decisionBody, value) };
}

export function verifyEvidenceInput(
  candidateId: string,
  value: unknown,
  actor: OperationalActor,
): VerifyEvidenceCandidateInput {
  return { candidateId, actor, ...parse(verifyCandidateBody, value) };
}

export function verifyFindingInput(
  findingId: string,
  value: unknown,
  actor: OperationalActor,
): VerifyFindingInput {
  return { findingId, actor, ...parse(verifyFindingBody, value) };
}

export function failureDiagnosisInput(
  missionId: string,
  runId: string,
  value: unknown,
  actor: OperationalActor,
): CreateFailureDiagnosisInput {
  return { missionId, runId, actor, ...parse(failureBody, value) };
}

export function resolveFailureInput(
  diagnosisId: string,
  value: unknown,
  actor: OperationalActor,
): ResolveFailureDiagnosisInput {
  return { diagnosisId, actor, ...parse(resolveFailureBody, value) };
}

export function singleQuery(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw invalid("invalid_query", `${label} must occur exactly once`);
  return value;
}

export function queryIdentifier(value: unknown, label: string): string | undefined {
  const query = singleQuery(value, label);
  return query === undefined || query === "" ? undefined : identifier(query, label);
}

export function pageLimit(value: unknown): number {
  const query = singleQuery(value, "limit");
  if (query === undefined) return 50;
  if (!/^\d+$/u.test(query)) throw invalid("invalid_page_limit", "limit must be an integer from 1 through 100");
  const limit = Number(query);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw invalid("invalid_page_limit", "limit must be an integer from 1 through 100");
  }
  return limit;
}

export function encodePageCursor(cursor: OperationalTruthPageCursor): string {
  return Buffer.from(JSON.stringify(cursor), "utf8").toString("base64url");
}

export function pageCursor(value: unknown): OperationalTruthPageCursor | undefined {
  const encoded = singleQuery(value, "cursor");
  if (encoded === undefined) return undefined;
  try {
    const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as unknown;
    const result = z.object({ createdAt: TIMESTAMP, id: ID }).strict().safeParse(decoded);
    if (!result.success) throw new Error("invalid cursor shape");
    const parsed = result.data;
    return { createdAt: isoTimestamp(parsed.createdAt, "cursor.createdAt"), id: parsed.id };
  } catch {
    throw invalid("invalid_page_cursor", "The pagination cursor is invalid", "Restart without a cursor.");
  }
}

export function candidateState(value: unknown): EvidenceCandidateState | undefined {
  const query = singleQuery(value, "state");
  if (query === undefined || query === "") return undefined;
  if (!CANDIDATE_STATES.has(query as EvidenceCandidateState)) {
    throw invalid("invalid_candidate_state", "state is not a supported evidence-candidate state");
  }
  return query as EvidenceCandidateState;
}

export function failureStates(value: unknown): readonly ("active" | "resolved" | "superseded" | "terminal")[] {
  const query = singleQuery(value, "states");
  if (query === undefined || query === "") return ["active", "terminal"];
  const allowed = new Set<string>(["active", "resolved", "superseded", "terminal"]);
  const states = [...new Set(query.split(","))];
  if (states.length === 0 || states.some((state) => !allowed.has(state))) {
    throw invalid("invalid_failure_states", "states contains an unsupported failure-diagnosis state");
  }
  return states as readonly ("active" | "resolved" | "superseded" | "terminal")[];
}

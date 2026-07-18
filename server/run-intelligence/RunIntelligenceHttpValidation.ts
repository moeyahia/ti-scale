import { z } from "zod";
import { canonicalObject, canonicalValue, type JsonValue } from "./serialization";
import { invalidHttpInput } from "./RunIntelligenceHttpError";
import type {
  CreateAttackAttemptInput,
  CreateTopologyEdgeInput,
  CreateTopologyNodeInput,
  RecordOsiObservationInput,
} from "./types";

const ID_PATTERN = /^[A-Za-z0-9._:@-]{1,240}$/u;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{8,200}$/u;
const ID = z.string().trim().regex(ID_PATTERN);
const SHORT_TEXT = z.string().trim().min(1).max(500);
const TEXT = z.string().trim().min(1).max(4_000);
const TIMESTAMP = z.string().trim().min(1).max(100).refine(
  (value) => Number.isFinite(Date.parse(value)),
  { message: "must be a timestamp" },
);
const CONFIDENCE = z.number().finite().min(0).max(1);
const JSON_OBJECT = z.unknown().transform((value, context) => {
  try {
    return canonicalObject(value);
  } catch {
    context.addIssue({ code: "custom", message: "must be a safe JSON object" });
    return z.NEVER;
  }
});
const JSON_VALUE = z.unknown().transform((value, context) => {
  try {
    return canonicalValue(value);
  } catch {
    context.addIssue({ code: "custom", message: "must be safe JSON" });
    return z.NEVER;
  }
});
const EMPTY_BODY = z.object({}).strict();

const provenance = z.object({
  method: SHORT_TEXT,
  sourceRef: z.string().trim().min(1).max(1_000),
  sourceAgentId: ID.optional(),
  sourceTool: SHORT_TEXT.optional(),
  observationIds: z.array(ID).max(100).optional(),
}).strict().superRefine((value, context) => {
  if (!value.sourceAgentId && !value.sourceTool) {
    context.addIssue({
      code: "custom",
      path: ["sourceAgentId"],
      message: "sourceAgentId or sourceTool is required",
    });
  }
});

const topologyEvidence = z.object({
  evidenceId: ID,
  relationship: z.enum(["supports", "contradicts", "source"]),
}).strict();

const attackAttemptBody = z.object({
  planId: ID.optional(),
  stepId: ID.optional(),
  targetAssetId: ID.optional(),
  targetServiceId: ID.optional(),
  objective: TEXT,
  techniqueId: ID.optional(),
  techniqueName: SHORT_TEXT,
  actionClass: SHORT_TEXT,
  prerequisites: z.array(JSON_VALUE).max(100).optional(),
  normalizedParameters: JSON_OBJECT.optional(),
  assignedAgentId: ID.optional(),
  modelAssignmentId: ID.optional(),
}).strict();

const stateTransitionBody = z.object({
  kind: z.literal("state"),
  expectedVersion: z.number().int().positive(),
  status: z.enum(["ready", "running", "blocked", "waiting_conditions", "cancelled"]),
  reason: TEXT.optional(),
  at: TIMESTAMP.optional(),
}).strict();

const outcomeEvidence = z.object({
  evidenceId: ID,
  relationship: z.enum(["supports", "contradicts", "context", "outcome"]),
}).strict();

const outcomeTransitionBody = z.object({
  kind: z.literal("outcome"),
  expectedVersion: z.number().int().positive(),
  outcome: z.enum(["succeeded", "failed", "safely_aborted"]),
  outcomeSummary: TEXT,
  failureCategory: SHORT_TEXT.optional(),
  failureDiagnosisId: ID.optional(),
  evidence: z.array(outcomeEvidence).max(100).optional(),
  endedAt: TIMESTAMP.optional(),
}).strict();

const topologyNodeBody = z.object({
  runId: ID.optional(),
  nodeType: SHORT_TEXT,
  primaryLabel: z.string().trim().min(1).max(1_000),
  normalizedIdentity: z.string().trim().min(1).max(1_000),
  scopeStatus: z.enum(["allowed", "prohibited", "unknown", "out_of_scope"]),
  lifecycleState: z.enum(["planned", "active", "validated", "blocked", "unreachable", "observed", "stale"]),
  properties: JSON_OBJECT.optional(),
  provenance,
  confidence: CONFIDENCE,
  verificationState: z.enum(["unverified", "corroborated", "verified", "conflicting", "stale"]),
  sensitivity: z.enum(["public", "internal", "private", "restricted"]),
  firstSeenAt: TIMESTAMP,
  lastSeenAt: TIMESTAMP,
  evidence: z.array(topologyEvidence).min(1).max(100),
}).strict();

const topologyEdgeBody = z.object({
  sourceNodeId: ID,
  targetNodeId: ID,
  edgeType: SHORT_TEXT,
  properties: JSON_OBJECT.optional(),
  provenance,
  confidence: CONFIDENCE,
  verificationState: z.enum(["unverified", "corroborated", "verified", "conflicting", "stale"]),
  sensitivity: z.enum(["public", "internal", "private", "restricted"]),
  firstSeenAt: TIMESTAMP,
  lastSeenAt: TIMESTAMP,
  evidence: z.array(topologyEvidence).min(1).max(100),
}).strict();

const osiLayer = z.union([
  z.literal(1), z.literal(2), z.literal(3), z.literal(4), z.literal(5), z.literal(6), z.literal(7),
]);

const osiObservationBody = z.object({
  layer: osiLayer,
  category: SHORT_TEXT,
  value: TEXT,
  versionValue: z.string().trim().min(1).max(1_000).optional(),
  derivation: z.enum(["observed", "actively_verified", "inferred", "user_supplied"]),
  confidence: CONFIDENCE,
  evidenceId: ID,
  observedAt: TIMESTAMP,
  conflictGroupId: ID.optional(),
}).strict();

export type AttackAttemptTransitionBody =
  | z.infer<typeof stateTransitionBody>
  | z.infer<typeof outcomeTransitionBody>;

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (result.success) return result.data;
  const fields = [...new Set(result.error.issues.map((issue) => issue.path.join(".") || "body"))];
  throw invalidHttpInput(
    "invalid_run_intelligence_request",
    `Run-intelligence request failed validation for: ${fields.slice(0, 10).join(", ")}`,
  );
}

export function stableIdentifier(value: unknown, label: string): string {
  const result = ID.safeParse(value);
  if (!result.success) throw invalidHttpInput("invalid_run_intelligence_identifier", `${label} is not a valid stable identifier`);
  return result.data;
}

export function requiredIdempotencyKey(value: string | undefined): string {
  const key = value?.trim();
  if (!key || !IDEMPOTENCY_KEY_PATTERN.test(key)) {
    throw invalidHttpInput(
      "run_intelligence_idempotency_key_required",
      "A valid Idempotency-Key header containing 8-200 safe characters is required",
      "Supply a unique Idempotency-Key and reuse it only when replaying the same mutation.",
    );
  }
  return key;
}

export function queryIdentifier(value: unknown, label: string): string | undefined {
  if (value === undefined || value === "") return undefined;
  if (typeof value !== "string") throw invalidHttpInput("invalid_run_intelligence_query", `${label} must occur exactly once`);
  return stableIdentifier(value, label);
}

export function queryLimit(value: unknown): number {
  if (value === undefined) return 50;
  if (typeof value !== "string" || !/^\d+$/u.test(value)) {
    throw invalidHttpInput("invalid_run_intelligence_limit", "limit must be an integer from 1 through 100");
  }
  const limit = Number(value);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw invalidHttpInput("invalid_run_intelligence_limit", "limit must be an integer from 1 through 100");
  }
  return limit;
}

export function emptyMutationBody(value: unknown): Readonly<Record<string, never>> {
  return parse(EMPTY_BODY, value ?? {});
}

export function createAttackAttemptInput(
  missionId: string,
  runId: string,
  value: unknown,
): CreateAttackAttemptInput {
  const body = parse(attackAttemptBody, value);
  return { missionId, runId, ...body };
}

export function attackAttemptTransitionBody(value: unknown): AttackAttemptTransitionBody {
  return parse(z.discriminatedUnion("kind", [stateTransitionBody, outcomeTransitionBody]), value);
}

export function createTopologyNodeInput(missionId: string, value: unknown): CreateTopologyNodeInput {
  return { missionId, ...parse(topologyNodeBody, value) };
}

export function createTopologyEdgeInput(missionId: string, value: unknown): CreateTopologyEdgeInput {
  return { missionId, ...parse(topologyEdgeBody, value) };
}

export function recordOsiObservationInput(assetNodeId: string, value: unknown): RecordOsiObservationInput {
  return { assetNodeId, ...parse(osiObservationBody, value) };
}

export function canonicalMutationRequest(value: unknown): JsonValue {
  return canonicalValue(value);
}

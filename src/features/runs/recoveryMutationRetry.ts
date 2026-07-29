import { ApiError } from "../../data/api/client";
import type { RunRecoveryRecord } from "../../domain/types/operations";
import { BROWSER_STORAGE_KEYS } from "../../lib/browserNamespaces";

export const RECOVERY_MUTATION_ATTEMPT_SCHEMA_VERSION = 1 as const;
export const RECOVERY_MUTATION_ATTEMPT_TTL_MS = 10 * 60_000;

export type RecoveryOperationCommand =
  | "replan"
  | "reassign"
  | "change_provider"
  | "resume"
  | "cancel";

export type RecoveryAttemptDisposition = "dispatching" | "retryable" | "uncertain";
export type RecoveryFailureDisposition = "retryable" | "uncertain" | "fresh_review";

interface RepresentedRecoveryBoundary {
  readonly runVersion: number;
  readonly runStatus: string;
  readonly planId: string | null;
  readonly planVersion: number | null;
  readonly stepId: string | null;
  readonly assignmentId: string | null;
  readonly checkpointId: string | null;
  readonly checkpointStateHash: string | null;
  readonly checkpointEventSequence: number | null;
  readonly guidedDecisionId: string | null;
  readonly guidedDecisionFingerprint: string | null;
}

export interface RecoveryMutationAttempt {
  readonly schemaVersion: typeof RECOVERY_MUTATION_ATTEMPT_SCHEMA_VERSION;
  readonly kind: "recovery_operation_attempt";
  readonly actorId: string;
  readonly runId: string;
  readonly command: RecoveryOperationCommand;
  readonly idempotencyKey: string;
  /** Exact compact JSON bytes sent by the first deliberate submission. */
  readonly serializedBody: string;
  /** SHA-256 of serializedBody; the body is compact canonical request JSON. */
  readonly bodySha256: string;
  readonly representedBoundary: RepresentedRecoveryBoundary;
  readonly disposition: RecoveryAttemptDisposition;
  readonly failureCode: string | null;
  readonly createdAt: string;
  readonly expiresAt: string;
}

type RecoveryAttemptStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

const COMMANDS = new Set<RecoveryOperationCommand>([
  "replan",
  "reassign",
  "change_provider",
  "resume",
  "cancel",
]);
const DISPOSITIONS = new Set<RecoveryAttemptDisposition>(["dispatching", "retryable", "uncertain"]);
const IDENTIFIER = /^[A-Za-z0-9._:@/-]{1,240}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/u;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*/iu;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u;
const COMMON_TOKEN = /\b(?:sk|gh[pousr]|xox[baprs]|AIza)[-_][A-Za-z0-9_-]{12,}\b/u;
const TOKEN_ASSIGNMENT = /\b(?:api[_-]?(?:key|token)|authorization|auth[_-]?token|client[_-]?secret|credential|password|passwd|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|token)\s*[:=]\s*["']?[^\s,;"'&]{4,}/iu;
const URL_CREDENTIALS = /[a-z][a-z0-9+.-]*:\/\/[^\s/@:]+:[^\s/@]+@/iu;
const MAXIMUM_SERIALIZED_BODY_BYTES = 12_000;

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key))
    && keys.every((key) => allowed.has(key));
}

function identifier(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER.test(value);
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function safeText(value: unknown, maximum: number): value is string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) return false;
  return !PRIVATE_KEY.test(value)
    && !BEARER.test(value)
    && !JWT.test(value)
    && !COMMON_TOKEN.test(value)
    && !TOKEN_ASSIGNMENT.test(value)
    && !URL_CREDENTIALS.test(value);
}

const EXACT_BOUNDARY_KEYS = [
  "expectedRunVersion",
  "expectedPlanId",
  "expectedPlanVersion",
  "expectedStepId",
  "expectedAssignmentId",
  "expectedCheckpointId",
  "expectedCheckpointStateHash",
  "expectedCheckpointEventSequence",
] as const;

function exactBoundary(body: Record<string, unknown>): boolean {
  return positiveInteger(body.expectedRunVersion)
    && identifier(body.expectedPlanId)
    && positiveInteger(body.expectedPlanVersion)
    && identifier(body.expectedStepId)
    && identifier(body.expectedAssignmentId)
    && identifier(body.expectedCheckpointId)
    && typeof body.expectedCheckpointStateHash === "string"
    && SHA256.test(body.expectedCheckpointStateHash)
    && nonNegativeInteger(body.expectedCheckpointEventSequence);
}

function optionalGuidedBinding(body: Record<string, unknown>): boolean {
  const hasDecision = body.guidedDecisionId !== undefined;
  const hasFingerprint = body.expectedDecisionFingerprint !== undefined;
  return hasDecision === hasFingerprint
    && (!hasDecision || (
      identifier(body.guidedDecisionId)
      && typeof body.expectedDecisionFingerprint === "string"
      && SHA256.test(body.expectedDecisionFingerprint)
    ));
}

function validBody(command: RecoveryOperationCommand, serializedBody: string): Record<string, unknown> | null {
  if (!serializedBody || new TextEncoder().encode(serializedBody).byteLength > MAXIMUM_SERIALIZED_BODY_BYTES) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(serializedBody) as unknown;
  } catch {
    return null;
  }
  const body = record(parsed);
  // Requiring the same compact serialization prevents storage mutation from
  // changing whitespace, property order, omitted values, or represented bytes.
  if (!body || JSON.stringify(body) !== serializedBody) return null;
  if (command === "cancel") {
    return exactKeys(body, ["reason"]) && safeText(body.reason, 2_000) ? body : null;
  }
  if (command === "resume") {
    const required = [
      "reason",
      "expectedRunVersion",
      "expectedRunStatus",
      "expectedCheckpointId",
      "expectedCheckpointStateHash",
      "expectedCheckpointEventSequence",
    ] as const;
    return exactKeys(body, required)
      && safeText(body.reason, 2_000)
      && positiveInteger(body.expectedRunVersion)
      && body.expectedRunStatus === "blocked"
      && identifier(body.expectedCheckpointId)
      && typeof body.expectedCheckpointStateHash === "string"
      && SHA256.test(body.expectedCheckpointStateHash)
      && nonNegativeInteger(body.expectedCheckpointEventSequence)
      ? body
      : null;
  }
  if (command === "replan") {
    return exactKeys(body, [...EXACT_BOUNDARY_KEYS, "strategyReason"])
      && exactBoundary(body)
      && safeText(body.strategyReason, 4_000)
      && body.strategyReason.trim().length >= 12
      ? body
      : null;
  }
  const guided = ["guidedDecisionId", "expectedDecisionFingerprint"] as const;
  if (command === "reassign") {
    return exactKeys(
      body,
      [...EXACT_BOUNDARY_KEYS, "targetAgentId", "capability", "reason"],
      guided,
    )
      && exactBoundary(body)
      && identifier(body.targetAgentId)
      && identifier(body.capability)
      && safeText(body.reason, 2_000)
      && optionalGuidedBinding(body)
      ? body
      : null;
  }
  return exactKeys(
    body,
    [...EXACT_BOUNDARY_KEYS, "providerId", "modelId", "modelConfigurationHash", "reason"],
    guided,
  )
    && exactBoundary(body)
    && identifier(body.providerId)
    && identifier(body.modelId)
    && typeof body.modelConfigurationHash === "string"
    && SHA256.test(body.modelConfigurationHash)
    && safeText(body.reason, 2_000)
    && optionalGuidedBinding(body)
    ? body
    : null;
}

async function sha256Text(value: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function representedBoundary(recovery: RunRecoveryRecord): RepresentedRecoveryBoundary {
  return {
    runVersion: recovery.run.version,
    runStatus: recovery.run.status,
    planId: recovery.boundary?.planId ?? null,
    planVersion: recovery.boundary?.planVersion ?? null,
    stepId: recovery.boundary?.stepId ?? null,
    assignmentId: recovery.boundary?.assignmentId ?? null,
    checkpointId: recovery.checkpoint?.id ?? null,
    checkpointStateHash: recovery.checkpoint?.stateHash ?? null,
    checkpointEventSequence: recovery.checkpoint?.eventSequence ?? null,
    guidedDecisionId: recovery.guidedDecision?.id ?? null,
    guidedDecisionFingerprint: recovery.guidedDecision?.actionFingerprint ?? null,
  };
}

function validRepresentedBoundary(value: unknown): value is RepresentedRecoveryBoundary {
  const boundary = record(value);
  if (!boundary || !exactKeys(boundary, [
    "runVersion",
    "runStatus",
    "planId",
    "planVersion",
    "stepId",
    "assignmentId",
    "checkpointId",
    "checkpointStateHash",
    "checkpointEventSequence",
    "guidedDecisionId",
    "guidedDecisionFingerprint",
  ])) return false;
  return positiveInteger(boundary.runVersion)
    && typeof boundary.runStatus === "string"
    && boundary.runStatus.length > 0
    && (boundary.planId === null || identifier(boundary.planId))
    && (boundary.planVersion === null || positiveInteger(boundary.planVersion))
    && (boundary.stepId === null || identifier(boundary.stepId))
    && (boundary.assignmentId === null || identifier(boundary.assignmentId))
    && (boundary.checkpointId === null || identifier(boundary.checkpointId))
    && (boundary.checkpointStateHash === null || (
      typeof boundary.checkpointStateHash === "string" && SHA256.test(boundary.checkpointStateHash)
    ))
    && (boundary.checkpointEventSequence === null || nonNegativeInteger(boundary.checkpointEventSequence))
    && (boundary.guidedDecisionId === null || identifier(boundary.guidedDecisionId))
    && (boundary.guidedDecisionFingerprint === null || (
      typeof boundary.guidedDecisionFingerprint === "string" && SHA256.test(boundary.guidedDecisionFingerprint)
    ));
}

async function parseAttempt(
  value: unknown,
  actorId: string,
  runId: string,
  now: Date,
): Promise<RecoveryMutationAttempt | null> {
  const attempt = record(value);
  if (!attempt || !exactKeys(attempt, [
    "schemaVersion",
    "kind",
    "actorId",
    "runId",
    "command",
    "idempotencyKey",
    "serializedBody",
    "bodySha256",
    "representedBoundary",
    "disposition",
    "failureCode",
    "createdAt",
    "expiresAt",
  ])) return null;
  if (
    attempt.schemaVersion !== RECOVERY_MUTATION_ATTEMPT_SCHEMA_VERSION
    || attempt.kind !== "recovery_operation_attempt"
    || attempt.actorId !== actorId
    || !identifier(attempt.actorId)
    || attempt.runId !== runId
    || !identifier(attempt.runId)
    || typeof attempt.command !== "string"
    || !COMMANDS.has(attempt.command as RecoveryOperationCommand)
    || typeof attempt.idempotencyKey !== "string"
    || !IDEMPOTENCY_KEY.test(attempt.idempotencyKey)
    || typeof attempt.serializedBody !== "string"
    || typeof attempt.bodySha256 !== "string"
    || !SHA256.test(attempt.bodySha256)
    || typeof attempt.disposition !== "string"
    || !DISPOSITIONS.has(attempt.disposition as RecoveryAttemptDisposition)
    || (attempt.failureCode !== null && (typeof attempt.failureCode !== "string" || attempt.failureCode.length > 160))
    || typeof attempt.createdAt !== "string"
    || typeof attempt.expiresAt !== "string"
    || !validRepresentedBoundary(attempt.representedBoundary)
  ) return null;
  const createdAt = Date.parse(attempt.createdAt);
  const expiresAt = Date.parse(attempt.expiresAt);
  if (
    !Number.isFinite(createdAt)
    || !Number.isFinite(expiresAt)
    || expiresAt <= now.getTime()
    || expiresAt <= createdAt
    || expiresAt - createdAt > RECOVERY_MUTATION_ATTEMPT_TTL_MS
    || createdAt > now.getTime() + 30_000
  ) return null;
  if (!validBody(attempt.command as RecoveryOperationCommand, attempt.serializedBody)) return null;
  if (await sha256Text(attempt.serializedBody) !== attempt.bodySha256) return null;
  return attempt as unknown as RecoveryMutationAttempt;
}

export function recoveryMutationAttemptStorageKey(actorId: string, runId: string): string {
  return `${BROWSER_STORAGE_KEYS.recoveryMutationIntentPrefix}.${encodeURIComponent(actorId)}.${encodeURIComponent(runId)}`;
}

export function availableRecoveryAttemptStorage(): RecoveryAttemptStorage | null {
  try {
    if (typeof globalThis.sessionStorage === "undefined") return null;
    return globalThis.sessionStorage;
  } catch {
    return null;
  }
}

export async function createRecoveryMutationAttempt(input: {
  readonly actorId: string;
  readonly runId: string;
  readonly command: RecoveryOperationCommand;
  readonly body: Readonly<Record<string, unknown>>;
  readonly idempotencyKey: string;
  readonly recovery: RunRecoveryRecord;
  readonly now?: Date;
}): Promise<RecoveryMutationAttempt> {
  const now = input.now ?? new Date();
  const serializedBody = JSON.stringify(input.body);
  if (
    !identifier(input.actorId)
    || !identifier(input.runId)
    || input.recovery.run.id !== input.runId
    || !IDEMPOTENCY_KEY.test(input.idempotencyKey)
    || !validBody(input.command, serializedBody)
  ) {
    throw new Error(
      "This recovery request cannot be retained safely. Remove credential-like material and review the exact current action.",
    );
  }
  return {
    schemaVersion: RECOVERY_MUTATION_ATTEMPT_SCHEMA_VERSION,
    kind: "recovery_operation_attempt",
    actorId: input.actorId,
    runId: input.runId,
    command: input.command,
    idempotencyKey: input.idempotencyKey,
    serializedBody,
    bodySha256: await sha256Text(serializedBody),
    representedBoundary: representedBoundary(input.recovery),
    disposition: "dispatching",
    failureCode: null,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + RECOVERY_MUTATION_ATTEMPT_TTL_MS).toISOString(),
  };
}

export function withRecoveryAttemptFailure(
  attempt: RecoveryMutationAttempt,
  disposition: Exclude<RecoveryAttemptDisposition, "dispatching">,
  error: Error,
): RecoveryMutationAttempt {
  return {
    ...attempt,
    disposition,
    failureCode: error instanceof ApiError ? error.code : null,
  };
}

export async function saveRecoveryMutationAttempt(
  storage: RecoveryAttemptStorage | null | undefined,
  attempt: RecoveryMutationAttempt,
  now = new Date(),
): Promise<boolean> {
  if (
    !storage
    || !await parseAttempt(attempt, attempt.actorId, attempt.runId, now)
  ) return false;
  try {
    storage.setItem(
      recoveryMutationAttemptStorageKey(attempt.actorId, attempt.runId),
      JSON.stringify(attempt),
    );
    return true;
  } catch {
    return false;
  }
}

export async function loadRecoveryMutationAttempt(
  storage: RecoveryAttemptStorage | null | undefined,
  actorId: string,
  runId: string,
  now = new Date(),
): Promise<RecoveryMutationAttempt | null> {
  if (!storage) return null;
  const key = recoveryMutationAttemptStorageKey(actorId, runId);
  try {
    const raw = storage.getItem(key);
    if (!raw) return null;
    const parsed = await parseAttempt(JSON.parse(raw) as unknown, actorId, runId, now);
    if (!parsed) {
      storage.removeItem(key);
      return null;
    }
    if (parsed.disposition !== "dispatching") return parsed;
    const uncertain = { ...parsed, disposition: "uncertain" as const, failureCode: null };
    storage.setItem(key, JSON.stringify(uncertain));
    return uncertain;
  } catch {
    try { storage.removeItem(key); } catch {}
    return null;
  }
}

export function clearRecoveryMutationAttempt(
  storage: RecoveryAttemptStorage | null | undefined,
  actorId: string,
  runId: string,
): void {
  try {
    storage?.removeItem(recoveryMutationAttemptStorageKey(actorId, runId));
  } catch {}
}

export function classifyRecoveryMutationFailure(error: Error): RecoveryFailureDisposition {
  if (!(error instanceof ApiError)) return "uncertain";
  if (error.code === "invalid_response_schema" || error.code === "unexpected_response") return "uncertain";
  return error.retryable ? "retryable" : "fresh_review";
}

export function recoveryAttemptMatchesProjection(
  attempt: RecoveryMutationAttempt,
  recovery: RunRecoveryRecord,
): boolean {
  if (
    recovery.run.id !== attempt.runId
    || JSON.stringify(representedBoundary(recovery)) !== JSON.stringify(attempt.representedBoundary)
  ) return false;
  const body = validBody(attempt.command, attempt.serializedBody);
  if (!body) return false;
  const available = recovery.actions.some((action) => action.command === attempt.command && action.available);
  if (!available) return false;
  if (attempt.command === "reassign") {
    const candidate = recovery.reassignmentCandidates.find((item) => item.agentId === body.targetAgentId);
    return Boolean(candidate?.capabilities.includes(String(body.capability)));
  }
  if (attempt.command === "change_provider") {
    return recovery.providerCandidates.some((candidate) =>
      candidate.enabled
      && candidate.providerId === body.providerId
      && candidate.modelId === body.modelId
      && candidate.modelConfigurationHash === body.modelConfigurationHash);
  }
  if (attempt.command === "resume") {
    return recovery.run.status === "blocked"
      && recovery.checkpoint !== null
      && recovery.checkpoint.inFlightActions.length === 0;
  }
  return true;
}

export function recoveryAttemptCommandLabel(command: RecoveryOperationCommand): string {
  if (command === "replan") return "bounded replan";
  if (command === "reassign") return "specialist reassignment";
  if (command === "change_provider") return "provider/model change";
  if (command === "resume") return "checkpoint resume";
  return "graceful termination";
}

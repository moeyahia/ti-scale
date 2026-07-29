import { ApiError } from "../../data/api/client";
import type {
  ResearchExperimentRunStatus,
} from "../../domain/types/research";

export const RESEARCH_EXPERIMENT_ATTEMPT_SCHEMA_VERSION = 1 as const;
export const RESEARCH_EXPERIMENT_ATTEMPT_TTL_MS = 10 * 60_000;
export const RESEARCH_EXPERIMENT_ATTEMPT_STORAGE_PREFIX =
  "ti-scale.research.experiment-intent.v1";

export type ResearchExperimentAttemptDisposition =
  | "dispatching"
  | "retryable"
  | "uncertain"
  | "reconcile";
export type ResearchExperimentFailureDisposition =
  | "retryable"
  | "uncertain"
  | "reconcile";

interface ResearchExperimentAttemptBase {
  readonly schemaVersion:
    typeof RESEARCH_EXPERIMENT_ATTEMPT_SCHEMA_VERSION;
  readonly kind: "research_experiment_attempt";
  readonly actorId: string;
  readonly experimentId: string;
  readonly idempotencyKey: string;
  /** Exact compact JSON bytes represented and dispatched by the operator. */
  readonly serializedBody: string;
  readonly bodySha256: string;
  readonly disposition: ResearchExperimentAttemptDisposition;
  readonly failureCode: string | null;
  readonly createdAt: string;
  readonly expiresAt: string;
}

export interface ResearchExperimentStartAttempt
  extends ResearchExperimentAttemptBase {
  readonly action: "start";
  readonly scenarioId: string;
  readonly seed: string;
  readonly runId: null;
  readonly reason: null;
  /** A start is represented only while the experiment has no prior run. */
  readonly expectedLatestRunId: null;
}

export interface ResearchExperimentCancelAttempt
  extends ResearchExperimentAttemptBase {
  readonly action: "cancel";
  readonly scenarioId: null;
  readonly seed: null;
  readonly runId: string;
  readonly reason: string;
  readonly expectedLatestRunId: string;
}

export type ResearchExperimentAttempt =
  | ResearchExperimentStartAttempt
  | ResearchExperimentCancelAttempt;

export interface ResearchExperimentProjection {
  readonly experimentId: string;
  readonly scenarioId: string;
  readonly experimentStatus: string;
  readonly latestRunId: string | null;
  readonly latestRunStatus: ResearchExperimentRunStatus | null;
}

type AttemptStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

const IDENTIFIER = /^[A-Za-z0-9._:@/-]{1,240}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;
const SEED = /^[A-Za-z0-9._:-]{1,160}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const DISPOSITIONS = new Set<ResearchExperimentAttemptDisposition>([
  "dispatching",
  "retryable",
  "uncertain",
  "reconcile",
]);
const TERMINAL_RUN_STATUSES = new Set<ResearchExperimentRunStatus>([
  "completed",
  "failed",
  "cancelled",
  "early_aborted",
]);
const PRIVATE_KEY =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/u;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*/iu;
const JWT =
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u;
const COMMON_TOKEN =
  /\b(?:sk|gh[pousr]|xox[baprs]|AIza)[-_][A-Za-z0-9_-]{12,}\b/u;
const TOKEN_ASSIGNMENT =
  /\b(?:api[_-]?(?:key|token)|authorization|auth[_-]?token|client[_-]?secret|credential|password|passwd|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|token)\s*[:=]\s*["']?[^\s,;"'&]{4,}/iu;
const URL_CREDENTIALS =
  /[a-z][a-z0-9+.-]*:\/\/[^\s/@:]+:[^\s/@]+@/iu;
const UNSAFE_READABLE_CONTROL_CHARACTER =
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function exactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  const expected = new Set(keys);
  return Object.keys(value).length === keys.length
    && keys.every((key) =>
      Object.prototype.hasOwnProperty.call(value, key))
    && Object.keys(value).every((key) => expected.has(key));
}

function safeReadableText(
  value: unknown,
  minimum: number,
  maximum: number,
): value is string {
  if (
    typeof value !== "string"
    || value.trim().length < minimum
    || value.length > maximum
    || UNSAFE_READABLE_CONTROL_CHARACTER.test(value)
  ) return false;
  return !PRIVATE_KEY.test(value)
    && !BEARER.test(value)
    && !JWT.test(value)
    && !COMMON_TOKEN.test(value)
    && !TOKEN_ASSIGNMENT.test(value)
    && !URL_CREDENTIALS.test(value);
}

function parseStartBody(
  serializedBody: string,
): { readonly scenarioId: string; readonly seed: string } | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serializedBody) as unknown;
  } catch {
    return null;
  }
  const body = record(parsed);
  if (
    !body
    || JSON.stringify(body) !== serializedBody
    || !exactKeys(body, ["scenarioId", "seed"])
    || typeof body.scenarioId !== "string"
    || !IDENTIFIER.test(body.scenarioId)
    || typeof body.seed !== "string"
    || !SEED.test(body.seed)
  ) return null;
  return { scenarioId: body.scenarioId, seed: body.seed };
}

function parseCancelBody(
  serializedBody: string,
): { readonly reason: string } | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serializedBody) as unknown;
  } catch {
    return null;
  }
  const body = record(parsed);
  if (
    !body
    || JSON.stringify(body) !== serializedBody
    || !exactKeys(body, ["reason"])
    || !safeReadableText(body.reason, 3, 1_000)
  ) return null;
  return { reason: body.reason.trim() };
}

async function sha256Text(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function serializeResearchExperimentStartRequest(input: {
  readonly scenarioId: string;
  readonly seed: string;
}): string {
  return JSON.stringify({
    scenarioId: input.scenarioId,
    seed: input.seed,
  });
}

export function serializeResearchExperimentCancelRequest(input: {
  readonly reason: string;
}): string {
  return JSON.stringify({ reason: input.reason });
}

export function researchExperimentAttemptStorageKey(
  actorId: string,
  experimentId: string,
): string {
  return `${RESEARCH_EXPERIMENT_ATTEMPT_STORAGE_PREFIX}.${encodeURIComponent(actorId)}.${encodeURIComponent(experimentId)}`;
}

export function availableResearchExperimentStorage(): AttemptStorage | null {
  try {
    return typeof globalThis.sessionStorage === "undefined"
      ? null
      : globalThis.sessionStorage;
  } catch {
    return null;
  }
}

export async function createResearchExperimentStartAttempt(input: {
  readonly actorId: string;
  readonly experimentId: string;
  readonly scenarioId: string;
  readonly seed: string;
  readonly idempotencyKey: string;
  readonly now?: Date;
}): Promise<ResearchExperimentStartAttempt> {
  const now = input.now ?? new Date();
  const serializedBody = serializeResearchExperimentStartRequest({
    scenarioId: input.scenarioId,
    seed: input.seed.trim(),
  });
  const body = parseStartBody(serializedBody);
  if (
    !IDENTIFIER.test(input.actorId)
    || !IDENTIFIER.test(input.experimentId)
    || !IDEMPOTENCY_KEY.test(input.idempotencyKey)
    || !body
  ) throw new Error("This exact Research run cannot be retained safely.");
  return {
    schemaVersion: RESEARCH_EXPERIMENT_ATTEMPT_SCHEMA_VERSION,
    kind: "research_experiment_attempt",
    action: "start",
    actorId: input.actorId,
    experimentId: input.experimentId,
    scenarioId: body.scenarioId,
    seed: body.seed,
    runId: null,
    reason: null,
    expectedLatestRunId: null,
    idempotencyKey: input.idempotencyKey,
    serializedBody,
    bodySha256: await sha256Text(serializedBody),
    disposition: "dispatching",
    failureCode: null,
    createdAt: now.toISOString(),
    expiresAt: new Date(
      now.getTime() + RESEARCH_EXPERIMENT_ATTEMPT_TTL_MS,
    ).toISOString(),
  };
}

export async function createResearchExperimentCancelAttempt(input: {
  readonly actorId: string;
  readonly experimentId: string;
  readonly runId: string;
  readonly reason: string;
  readonly idempotencyKey: string;
  readonly now?: Date;
}): Promise<ResearchExperimentCancelAttempt> {
  const now = input.now ?? new Date();
  const serializedBody = serializeResearchExperimentCancelRequest({
    reason: input.reason.trim(),
  });
  const body = parseCancelBody(serializedBody);
  if (
    !IDENTIFIER.test(input.actorId)
    || !IDENTIFIER.test(input.experimentId)
    || !IDENTIFIER.test(input.runId)
    || !IDEMPOTENCY_KEY.test(input.idempotencyKey)
    || !body
  ) throw new Error("This exact Research cancellation cannot be retained safely.");
  return {
    schemaVersion: RESEARCH_EXPERIMENT_ATTEMPT_SCHEMA_VERSION,
    kind: "research_experiment_attempt",
    action: "cancel",
    actorId: input.actorId,
    experimentId: input.experimentId,
    scenarioId: null,
    seed: null,
    runId: input.runId,
    reason: body.reason,
    expectedLatestRunId: input.runId,
    idempotencyKey: input.idempotencyKey,
    serializedBody,
    bodySha256: await sha256Text(serializedBody),
    disposition: "dispatching",
    failureCode: null,
    createdAt: now.toISOString(),
    expiresAt: new Date(
      now.getTime() + RESEARCH_EXPERIMENT_ATTEMPT_TTL_MS,
    ).toISOString(),
  };
}

function parseAttemptShape(
  value: unknown,
  actorId: string,
  experimentId: string,
  now: Date,
): ResearchExperimentAttempt | null {
  const attempt = record(value);
  const keys = [
    "schemaVersion",
    "kind",
    "action",
    "actorId",
    "experimentId",
    "scenarioId",
    "seed",
    "runId",
    "reason",
    "expectedLatestRunId",
    "idempotencyKey",
    "serializedBody",
    "bodySha256",
    "disposition",
    "failureCode",
    "createdAt",
    "expiresAt",
  ];
  if (
    !attempt
    || !exactKeys(attempt, keys)
    || attempt.schemaVersion !== RESEARCH_EXPERIMENT_ATTEMPT_SCHEMA_VERSION
    || attempt.kind !== "research_experiment_attempt"
    || attempt.actorId !== actorId
    || !IDENTIFIER.test(actorId)
    || attempt.experimentId !== experimentId
    || !IDENTIFIER.test(experimentId)
    || (
      attempt.action !== "start"
      && attempt.action !== "cancel"
    )
    || typeof attempt.idempotencyKey !== "string"
    || !IDEMPOTENCY_KEY.test(attempt.idempotencyKey)
    || typeof attempt.serializedBody !== "string"
    || typeof attempt.bodySha256 !== "string"
    || !SHA256.test(attempt.bodySha256)
    || typeof attempt.disposition !== "string"
    || !DISPOSITIONS.has(
      attempt.disposition as ResearchExperimentAttemptDisposition,
    )
    || (
      attempt.failureCode !== null
      && (
        typeof attempt.failureCode !== "string"
        || attempt.failureCode.length > 160
      )
    )
    || typeof attempt.createdAt !== "string"
    || typeof attempt.expiresAt !== "string"
  ) return null;
  const createdAt = Date.parse(attempt.createdAt);
  const expiresAt = Date.parse(attempt.expiresAt);
  if (
    !Number.isFinite(createdAt)
    || !Number.isFinite(expiresAt)
    || createdAt > now.getTime() + 30_000
    || expiresAt <= now.getTime()
    || expiresAt <= createdAt
    || expiresAt - createdAt > RESEARCH_EXPERIMENT_ATTEMPT_TTL_MS
  ) return null;
  if (attempt.action === "start") {
    const body = parseStartBody(attempt.serializedBody);
    if (
      !body
      || attempt.scenarioId !== body.scenarioId
      || attempt.seed !== body.seed
      || attempt.runId !== null
      || attempt.reason !== null
      || attempt.expectedLatestRunId !== null
    ) return null;
  } else {
    const body = parseCancelBody(attempt.serializedBody);
    if (
      !body
      || attempt.scenarioId !== null
      || attempt.seed !== null
      || typeof attempt.runId !== "string"
      || !IDENTIFIER.test(attempt.runId)
      || attempt.reason !== body.reason
      || attempt.expectedLatestRunId !== attempt.runId
    ) return null;
  }
  return attempt as unknown as ResearchExperimentAttempt;
}

async function parseAttempt(
  value: unknown,
  actorId: string,
  experimentId: string,
  now: Date,
): Promise<ResearchExperimentAttempt | null> {
  const attempt = parseAttemptShape(value, actorId, experimentId, now);
  if (!attempt) return null;
  return await sha256Text(attempt.serializedBody) === attempt.bodySha256
    ? attempt
    : null;
}

export async function saveResearchExperimentAttempt(
  storage: AttemptStorage | null | undefined,
  attempt: ResearchExperimentAttempt,
  now = new Date(),
): Promise<boolean> {
  if (
    !storage
    || !await parseAttempt(
      attempt,
      attempt.actorId,
      attempt.experimentId,
      now,
    )
  ) return false;
  try {
    storage.setItem(
      researchExperimentAttemptStorageKey(
        attempt.actorId,
        attempt.experimentId,
      ),
      JSON.stringify(attempt),
    );
    return true;
  } catch {
    return false;
  }
}

export async function loadResearchExperimentAttempt(
  storage: AttemptStorage | null | undefined,
  actorId: string,
  experimentId: string,
  now = new Date(),
): Promise<ResearchExperimentAttempt | null> {
  if (!storage) return null;
  const key = researchExperimentAttemptStorageKey(actorId, experimentId);
  try {
    const raw = storage.getItem(key);
    if (!raw) return null;
    const parsed = await parseAttempt(
      JSON.parse(raw) as unknown,
      actorId,
      experimentId,
      now,
    );
    if (!parsed) {
      storage.removeItem(key);
      return null;
    }
    if (parsed.disposition !== "dispatching") return parsed;
    const uncertain = {
      ...parsed,
      disposition: "uncertain" as const,
      failureCode: null,
    };
    storage.setItem(key, JSON.stringify(uncertain));
    return uncertain;
  } catch {
    try {
      storage.removeItem(key);
    } catch {}
    return null;
  }
}

export function clearResearchExperimentAttempt(
  storage: AttemptStorage | null | undefined,
  actorId: string,
  experimentId: string,
): void {
  try {
    storage?.removeItem(
      researchExperimentAttemptStorageKey(actorId, experimentId),
    );
  } catch {}
}

export function classifyResearchExperimentFailure(
  error: Error,
): ResearchExperimentFailureDisposition {
  if (!(error instanceof ApiError)) return "uncertain";
  if (
    error.code === "invalid_response_schema"
    || error.code === "unexpected_response"
  ) return "uncertain";
  return error.retryable ? "retryable" : "reconcile";
}

export function withResearchExperimentFailure(
  attempt: ResearchExperimentAttempt,
  disposition: ResearchExperimentFailureDisposition,
  error: Error,
): ResearchExperimentAttempt {
  return {
    ...attempt,
    disposition,
    failureCode: error instanceof ApiError ? error.code : null,
  };
}

export function researchExperimentAttemptMatchesProjection(
  attempt: ResearchExperimentAttempt,
  projection: ResearchExperimentProjection,
): boolean {
  if (projection.experimentId !== attempt.experimentId) return false;
  if (attempt.action === "start") {
    return projection.scenarioId === attempt.scenarioId
      && projection.experimentStatus === "queued"
      && projection.latestRunId === attempt.expectedLatestRunId
      && projection.latestRunStatus === null;
  }
  return projection.latestRunId === attempt.runId
    && (
      projection.latestRunStatus === "queued"
      || projection.latestRunStatus === "running"
    );
}

export function researchExperimentAttemptOutcomeReached(
  attempt: ResearchExperimentAttempt,
  projection: ResearchExperimentProjection,
): boolean {
  if (projection.experimentId !== attempt.experimentId) return false;
  if (attempt.action === "start") {
    return projection.latestRunId !== null;
  }
  return projection.latestRunId === attempt.runId
    && projection.latestRunStatus !== null
    && TERMINAL_RUN_STATUSES.has(projection.latestRunStatus);
}

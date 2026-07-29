import { ApiError } from "../../data/api/client";
import type {
  HumanResearchPromotionAction,
  ResearchPromotionLifecycleRecord,
} from "../../domain/types/research";
import { BROWSER_STORAGE_KEYS } from "../../lib/browserNamespaces";
import { canonicalResearchPromotionDecision } from "../../../shared/ResearchPromotionDecision";

export const RESEARCH_PROMOTION_ATTEMPT_SCHEMA_VERSION = 2 as const;
export const RESEARCH_PROMOTION_ATTEMPT_TTL_MS = 10 * 60_000;

export type ResearchPromotionAttemptDisposition =
  | "dispatching"
  | "retryable"
  | "uncertain";
export type ResearchPromotionFailureDisposition =
  | "retryable"
  | "uncertain"
  | "fresh_review";

export interface ResearchPromotionAttempt {
  readonly schemaVersion: typeof RESEARCH_PROMOTION_ATTEMPT_SCHEMA_VERSION;
  readonly kind: "research_promotion_attempt";
  readonly actorId: string;
  readonly experimentId: string;
  readonly expectedVersion: number;
  readonly action: HumanResearchPromotionAction;
  readonly idempotencyKey: string;
  /** Exact compact JSON bytes dispatched by the first deliberate decision. */
  readonly serializedBody: string;
  readonly bodySha256: string;
  /** Hash of the exact normalized decision the server must persist. */
  readonly decisionFingerprint: string;
  readonly disposition: ResearchPromotionAttemptDisposition;
  readonly failureCode: string | null;
  readonly createdAt: string;
  readonly expiresAt: string;
}

type AttemptStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

const ACTIONS = new Set<HumanResearchPromotionAction>([
  "approve_human_review",
  "reject_human_review",
  "start_shadow",
  "approve_canary",
  "start_canary",
  "verify",
  "reject",
  "mark_stale",
  "supersede",
  "rollback",
]);
const DISPOSITIONS = new Set<ResearchPromotionAttemptDisposition>([
  "dispatching",
  "retryable",
  "uncertain",
]);
const IDENTIFIER = /^[A-Za-z0-9._:@/-]{1,240}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const PRIVATE_KEY =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/u;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*/iu;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u;
const COMMON_TOKEN = /\b(?:sk|gh[pousr]|xox[baprs]|AIza)[-_][A-Za-z0-9_-]{12,}\b/u;
const TOKEN_ASSIGNMENT =
  /\b(?:api[_-]?(?:key|token)|authorization|auth[_-]?token|client[_-]?secret|credential|password|passwd|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|token)\s*[:=]\s*["']?[^\s,;"'&]{4,}/iu;
const URL_CREDENTIALS = /[a-z][a-z0-9+.-]*:\/\/[^\s/@:]+:[^\s/@]+@/iu;
const ANY_CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const UNSAFE_READABLE_CONTROL_CHARACTER =
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;
const MAXIMUM_SERIALIZED_BODY_BYTES = 40_000;

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
  const allowed = new Set([...required, ...optional]);
  return required.every((key) =>
    Object.prototype.hasOwnProperty.call(value, key))
    && Object.keys(value).every((key) => allowed.has(key));
}

function safeText(
  value: unknown,
  minimum: number,
  maximum: number,
  allowReadableWhitespace = false,
): value is string {
  if (
    typeof value !== "string"
    || value.trim().length < minimum
    || value.length > maximum
    || (
      allowReadableWhitespace
        ? UNSAFE_READABLE_CONTROL_CHARACTER.test(value)
        : ANY_CONTROL_CHARACTER.test(value)
    )
  ) return false;
  return !PRIVATE_KEY.test(value)
    && !BEARER.test(value)
    && !JWT.test(value)
    && !COMMON_TOKEN.test(value)
    && !TOKEN_ASSIGNMENT.test(value)
    && !URL_CREDENTIALS.test(value);
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

interface ParsedPromotionBody {
  readonly expectedVersion: number;
  readonly action: HumanResearchPromotionAction;
  readonly rationale: string;
  readonly evidenceRefs: readonly string[];
  readonly targetStrategyVersionId?: string;
  readonly canaryBounds?: {
    readonly maxMissions: number;
    readonly maxWallClockMs: number;
  };
}

function parseBody(serializedBody: string): ParsedPromotionBody | null {
  if (
    !serializedBody
    || new TextEncoder().encode(serializedBody).byteLength >
      MAXIMUM_SERIALIZED_BODY_BYTES
  ) return null;
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
    || !exactKeys(
      body,
      ["expectedVersion", "action", "rationale", "evidenceRefs"],
      ["targetStrategyVersionId", "canaryBounds"],
    )
    || !positiveInteger(body.expectedVersion)
    || typeof body.action !== "string"
    || !ACTIONS.has(body.action as HumanResearchPromotionAction)
    || !safeText(body.rationale, 3, 4_000, true)
    || !Array.isArray(body.evidenceRefs)
    || body.evidenceRefs.length < 1
    || body.evidenceRefs.length > 50
    || body.evidenceRefs.some((item) => !safeText(item, 1, 500))
    || new Set(body.evidenceRefs).size !== body.evidenceRefs.length
  ) return null;
  const action = body.action as HumanResearchPromotionAction;
  if (action === "rollback") {
    if (
      !safeText(body.targetStrategyVersionId, 1, 255)
      || body.canaryBounds !== undefined
    ) return null;
  } else if (action === "start_canary") {
    const bounds = record(body.canaryBounds);
    if (
      body.targetStrategyVersionId !== undefined
      || !bounds
      || !exactKeys(bounds, ["maxMissions", "maxWallClockMs"])
      || !positiveInteger(bounds.maxMissions)
      || bounds.maxMissions > 10
      || !positiveInteger(bounds.maxWallClockMs)
      || bounds.maxWallClockMs < 60_000
      || bounds.maxWallClockMs > 86_400_000
    ) return null;
  } else if (
    body.targetStrategyVersionId !== undefined
    || body.canaryBounds !== undefined
  ) return null;
  return {
    expectedVersion: body.expectedVersion,
    action,
    rationale: body.rationale.trim(),
    evidenceRefs: [
      ...new Set(
        (body.evidenceRefs as string[]).map((reference) => reference.trim()),
      ),
    ],
    ...(typeof body.targetStrategyVersionId === "string"
      ? { targetStrategyVersionId: body.targetStrategyVersionId.trim() }
      : {}),
    ...(body.canaryBounds
      ? {
          canaryBounds: {
            maxMissions: (body.canaryBounds as Record<string, number>)
              .maxMissions,
            maxWallClockMs: (body.canaryBounds as Record<string, number>)
              .maxWallClockMs,
          },
        }
      : {}),
  };
}

async function sha256Text(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function parseAttemptShape(
  value: unknown,
  actorId: string,
  experimentId: string,
  now: Date,
): ResearchPromotionAttempt | null {
  const attempt = record(value);
  if (
    !attempt
    || !exactKeys(attempt, [
      "schemaVersion",
      "kind",
      "actorId",
      "experimentId",
      "expectedVersion",
      "action",
      "idempotencyKey",
      "serializedBody",
      "bodySha256",
      "decisionFingerprint",
      "disposition",
      "failureCode",
      "createdAt",
      "expiresAt",
    ])
    || attempt.schemaVersion !== RESEARCH_PROMOTION_ATTEMPT_SCHEMA_VERSION
    || attempt.kind !== "research_promotion_attempt"
    || attempt.actorId !== actorId
    || !IDENTIFIER.test(actorId)
    || attempt.experimentId !== experimentId
    || !IDENTIFIER.test(experimentId)
    || !positiveInteger(attempt.expectedVersion)
    || typeof attempt.action !== "string"
    || !ACTIONS.has(attempt.action as HumanResearchPromotionAction)
    || typeof attempt.idempotencyKey !== "string"
    || !IDEMPOTENCY_KEY.test(attempt.idempotencyKey)
    || typeof attempt.serializedBody !== "string"
    || typeof attempt.bodySha256 !== "string"
    || !SHA256.test(attempt.bodySha256)
    || typeof attempt.decisionFingerprint !== "string"
    || !SHA256.test(attempt.decisionFingerprint)
    || typeof attempt.disposition !== "string"
    || !DISPOSITIONS.has(attempt.disposition as ResearchPromotionAttemptDisposition)
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
  const body = parseBody(attempt.serializedBody);
  const createdAt = Date.parse(attempt.createdAt);
  const expiresAt = Date.parse(attempt.expiresAt);
  if (
    !body
    || body.expectedVersion !== attempt.expectedVersion
    || body.action !== attempt.action
    || !Number.isFinite(createdAt)
    || !Number.isFinite(expiresAt)
    || createdAt > now.getTime() + 30_000
    || expiresAt <= now.getTime()
    || expiresAt <= createdAt
    || expiresAt - createdAt > RESEARCH_PROMOTION_ATTEMPT_TTL_MS
  ) return null;
  return attempt as unknown as ResearchPromotionAttempt;
}

async function parseAttempt(
  value: unknown,
  actorId: string,
  experimentId: string,
  now: Date,
): Promise<ResearchPromotionAttempt | null> {
  const attempt = parseAttemptShape(value, actorId, experimentId, now);
  if (!attempt) return null;
  const body = parseBody(attempt.serializedBody);
  if (!body) return null;
  const [bodySha256, decisionFingerprint] = await Promise.all([
    sha256Text(attempt.serializedBody),
    sha256Text(canonicalResearchPromotionDecision({
      expectedVersion: body.expectedVersion,
      action: body.action,
      actorId: attempt.actorId,
      rationale: body.rationale,
      evidenceRefs: body.evidenceRefs,
      ...(body.targetStrategyVersionId
        ? { targetStrategyVersionId: body.targetStrategyVersionId }
        : {}),
      ...(body.canaryBounds ? { canaryBounds: body.canaryBounds } : {}),
    })),
  ]);
  return bodySha256 === attempt.bodySha256
    && decisionFingerprint === attempt.decisionFingerprint
    ? attempt
    : null;
}

export function researchPromotionAttemptStorageKey(
  actorId: string,
  experimentId: string,
): string {
  return `${BROWSER_STORAGE_KEYS.researchPromotionIntentPrefix}.${encodeURIComponent(actorId)}.${encodeURIComponent(experimentId)}`;
}

export function availableResearchPromotionStorage(): AttemptStorage | null {
  try {
    return typeof globalThis.sessionStorage === "undefined"
      ? null
      : globalThis.sessionStorage;
  } catch {
    return null;
  }
}

export async function createResearchPromotionAttempt(input: {
  readonly actorId: string;
  readonly experimentId: string;
  readonly serializedBody: string;
  readonly idempotencyKey: string;
  readonly now?: Date;
}): Promise<ResearchPromotionAttempt> {
  const now = input.now ?? new Date();
  const body = parseBody(input.serializedBody);
  if (
    !IDENTIFIER.test(input.actorId)
    || !IDENTIFIER.test(input.experimentId)
    || !IDEMPOTENCY_KEY.test(input.idempotencyKey)
    || !body
  ) {
    throw new Error(
      "This Research decision cannot be retained safely. Remove credential-like material and review the represented evidence references.",
    );
  }
  return {
    schemaVersion: RESEARCH_PROMOTION_ATTEMPT_SCHEMA_VERSION,
    kind: "research_promotion_attempt",
    actorId: input.actorId,
    experimentId: input.experimentId,
    expectedVersion: body.expectedVersion,
    action: body.action,
    idempotencyKey: input.idempotencyKey,
    serializedBody: input.serializedBody,
    bodySha256: await sha256Text(input.serializedBody),
    decisionFingerprint: await sha256Text(
      canonicalResearchPromotionDecision({
        expectedVersion: body.expectedVersion,
        action: body.action,
        actorId: input.actorId,
        rationale: body.rationale,
        evidenceRefs: body.evidenceRefs,
        ...(body.targetStrategyVersionId
          ? { targetStrategyVersionId: body.targetStrategyVersionId }
          : {}),
        ...(body.canaryBounds ? { canaryBounds: body.canaryBounds } : {}),
      }),
    ),
    disposition: "dispatching",
    failureCode: null,
    createdAt: now.toISOString(),
    expiresAt: new Date(
      now.getTime() + RESEARCH_PROMOTION_ATTEMPT_TTL_MS,
    ).toISOString(),
  };
}

export function withResearchPromotionFailure(
  attempt: ResearchPromotionAttempt,
  disposition: Exclude<ResearchPromotionAttemptDisposition, "dispatching">,
  error: Error,
): ResearchPromotionAttempt {
  return {
    ...attempt,
    disposition,
    failureCode: error instanceof ApiError ? error.code : null,
  };
}

export async function saveResearchPromotionAttempt(
  storage: AttemptStorage | null | undefined,
  attempt: ResearchPromotionAttempt,
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
      researchPromotionAttemptStorageKey(
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

export async function loadResearchPromotionAttempt(
  storage: AttemptStorage | null | undefined,
  actorId: string,
  experimentId: string,
  now = new Date(),
): Promise<ResearchPromotionAttempt | null> {
  if (!storage) return null;
  const key = researchPromotionAttemptStorageKey(actorId, experimentId);
  try {
    const raw = storage.getItem(key);
    if (!raw) return null;
    const attempt = await parseAttempt(
      JSON.parse(raw) as unknown,
      actorId,
      experimentId,
      now,
    );
    if (!attempt) {
      storage.removeItem(key);
      return null;
    }
    if (attempt.disposition !== "dispatching") return attempt;
    const uncertain = {
      ...attempt,
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

export function clearResearchPromotionAttempt(
  storage: AttemptStorage | null | undefined,
  actorId: string,
  experimentId: string,
): void {
  try {
    storage?.removeItem(
      researchPromotionAttemptStorageKey(actorId, experimentId),
    );
  } catch {}
}

export function classifyResearchPromotionFailure(
  error: Error,
): ResearchPromotionFailureDisposition {
  if (!(error instanceof ApiError)) return "uncertain";
  if (
    error.code === "invalid_response_schema"
    || error.code === "unexpected_response"
  ) return "uncertain";
  return error.retryable ? "retryable" : "fresh_review";
}

export function researchPromotionAttemptMatchesProjection(
  attempt: ResearchPromotionAttempt,
  promotion: ResearchPromotionLifecycleRecord,
): boolean {
  return promotion.experimentId === attempt.experimentId
    && promotion.version === attempt.expectedVersion
    && promotion.availableHumanActions.includes(attempt.action);
}

export type ResearchPromotionOutcomeAttribution =
  | "same_actor"
  | "other_actor"
  | "other_decision"
  | "not_reached";

export function classifyResearchPromotionOutcomeAttribution(
  attempt: ResearchPromotionAttempt,
  promotion: ResearchPromotionLifecycleRecord,
): ResearchPromotionOutcomeAttribution {
  if (
    promotion.experimentId !== attempt.experimentId
    || promotion.version <= attempt.expectedVersion
  ) return "not_reached";
  const transition = promotion.transitions.find((candidate) =>
    candidate.version === attempt.expectedVersion + 1
    && candidate.action === attempt.action
    && candidate.actorKind === "human_reviewer");
  if (!transition) return "not_reached";
  if (transition.actorId !== attempt.actorId) return "other_actor";
  return transition.decisionFingerprint === attempt.decisionFingerprint
    ? "same_actor"
    : "other_decision";
}

export function researchPromotionOutcomeReached(
  attempt: ResearchPromotionAttempt,
  promotion: ResearchPromotionLifecycleRecord,
): boolean {
  return classifyResearchPromotionOutcomeAttribution(attempt, promotion)
    === "same_actor";
}

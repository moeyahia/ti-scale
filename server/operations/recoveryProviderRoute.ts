import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { ActionRepository, CheckpointRepository, RunRepository } from "../orchestration";

export const RECOVERY_PROVIDER_ROUTE_SCHEMA_VERSION = 1 as const;
/**
 * A provider health attestation is usable for at most two minutes by default.
 * Callers may configure a shorter/longer bounded window, but every selection
 * and dispatch still revalidates the snapshot timestamp and fails closed.
 */
export const DEFAULT_RECOVERY_PROVIDER_HEALTH_MAX_AGE_MS = 120_000;

export function recoveryProviderHealthMaxAge(value?: number): number {
  const candidate = value ?? DEFAULT_RECOVERY_PROVIDER_HEALTH_MAX_AGE_MS;
  if (!Number.isSafeInteger(candidate) || candidate < 1_000 || candidate > 15 * 60_000) {
    throw new RangeError("Recovery provider health max age must be between 1 second and 15 minutes");
  }
  return candidate;
}

export function isRecoveryProviderHealthFresh(
  capturedAt: string,
  now: string,
  maxAgeMs = DEFAULT_RECOVERY_PROVIDER_HEALTH_MAX_AGE_MS,
): boolean {
  const captured = Date.parse(capturedAt);
  const current = Date.parse(now);
  const age = current - captured;
  return Number.isFinite(captured) && Number.isFinite(current) && age >= 0 && age <= maxAgeMs;
}

/** The projection timestamp is not an attestation timestamp. */
export function recoveryProviderAttestedAt(metrics: Readonly<Record<string, unknown>>): string {
  const value = metrics.attestedAt;
  return typeof value === "string" && Number.isFinite(Date.parse(value)) ? value : "";
}

/**
 * Read the provider breaker from the latest hash-verified durable checkpoint.
 * A selected recovery route is executable only while this returns `closed`.
 */
export function recoveryProviderCircuitState(
  database: SqliteDatabase,
  runId: string,
  providerId: string,
): "closed" | "open" | "half_open" {
  const actions = new ActionRepository(database);
  const checkpoints = new CheckpointRepository(database, actions);
  const run = new RunRepository(database).get(runId);
  const control = checkpoints.restoreControl(runId, run.control);
  return control.circuits[`provider:${providerId}`]?.state ?? "closed";
}

export interface RecoveryProviderRouteBinding {
  readonly schemaVersion: typeof RECOVERY_PROVIDER_ROUTE_SCHEMA_VERSION;
  readonly version: number;
  readonly runId: string;
  readonly journey: "autonomous" | "guided";
  readonly providerId: string;
  readonly planId: string;
  readonly planVersion: number;
  readonly stepId: string;
  readonly assignmentId: string;
  readonly contract?: {
    readonly id: string;
    readonly version: number;
    readonly hash: string;
  };
  readonly guidedDecision?: {
    readonly id: string;
    readonly fingerprint: string;
  };
  readonly selectedBy: string;
  readonly selectedAt: string;
}

export interface RecoveryProviderRouteTombstone {
  readonly schemaVersion: typeof RECOVERY_PROVIDER_ROUTE_SCHEMA_VERSION;
  readonly invalidated: true;
  readonly runId: string;
  readonly previousProviderId: string;
  readonly previousVersion: number;
  readonly planId: string;
  readonly stepId: string;
  readonly assignmentId: string;
  readonly reason: "assignment_changed";
  readonly invalidatedBy: string;
  readonly invalidatedAt: string;
}

function requiredString(value: unknown): string {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

function positiveInteger(value: unknown): number {
  return Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : 0;
}

/** Opaque key prevents a caller-controlled run ID from becoming a settings namespace. */
export function recoveryProviderRouteSettingKey(runId: string): string {
  const digest = createHash("sha256").update(runId, "utf8").digest("hex");
  return `ti_scale.recovery.provider_route.${digest}`;
}

export function parseRecoveryProviderRouteBinding(value: unknown): RecoveryProviderRouteBinding | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  const journey = item.journey;
  const contractValue = item.contract;
  const decisionValue = item.guidedDecision;
  const contract = contractValue && typeof contractValue === "object" && !Array.isArray(contractValue)
    ? contractValue as Record<string, unknown>
    : null;
  const decision = decisionValue && typeof decisionValue === "object" && !Array.isArray(decisionValue)
    ? decisionValue as Record<string, unknown>
    : null;
  const base = {
    schemaVersion: item.schemaVersion,
    version: positiveInteger(item.version),
    runId: requiredString(item.runId),
    providerId: requiredString(item.providerId),
    planId: requiredString(item.planId),
    planVersion: positiveInteger(item.planVersion),
    stepId: requiredString(item.stepId),
    assignmentId: requiredString(item.assignmentId),
    selectedBy: requiredString(item.selectedBy),
    selectedAt: requiredString(item.selectedAt),
  };
  if (
    base.schemaVersion !== RECOVERY_PROVIDER_ROUTE_SCHEMA_VERSION ||
    (journey !== "autonomous" && journey !== "guided") ||
    !base.version || !base.runId || !base.providerId || !base.planId ||
    !base.planVersion || !base.stepId || !base.assignmentId || !base.selectedBy ||
    !base.selectedAt || !Number.isFinite(Date.parse(base.selectedAt))
  ) return null;

  if (journey === "autonomous") {
    if (!contract) return null;
    const id = requiredString(contract.id);
    const version = positiveInteger(contract.version);
    const hash = requiredString(contract.hash);
    if (!id || !version || !/^[a-f0-9]{32,}$/iu.test(hash)) return null;
    return { ...base, schemaVersion: 1, journey, contract: { id, version, hash } };
  }

  if (!decision) return null;
  const id = requiredString(decision.id);
  const fingerprint = requiredString(decision.fingerprint);
  if (!id || !fingerprint) return null;
  return { ...base, schemaVersion: 1, journey, guidedDecision: { id, fingerprint } };
}

export function parseRecoveryProviderRouteTombstone(value: unknown): RecoveryProviderRouteTombstone | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  const tombstone: RecoveryProviderRouteTombstone = {
    schemaVersion: RECOVERY_PROVIDER_ROUTE_SCHEMA_VERSION,
    invalidated: true,
    runId: requiredString(item.runId),
    previousProviderId: requiredString(item.previousProviderId),
    previousVersion: positiveInteger(item.previousVersion),
    planId: requiredString(item.planId),
    stepId: requiredString(item.stepId),
    assignmentId: requiredString(item.assignmentId),
    reason: "assignment_changed",
    invalidatedBy: requiredString(item.invalidatedBy),
    invalidatedAt: requiredString(item.invalidatedAt),
  };
  if (
    item.schemaVersion !== RECOVERY_PROVIDER_ROUTE_SCHEMA_VERSION || item.invalidated !== true ||
    item.reason !== "assignment_changed" || !tombstone.runId || !tombstone.previousProviderId ||
    !tombstone.previousVersion || !tombstone.planId || !tombstone.stepId ||
    !tombstone.assignmentId || !tombstone.invalidatedBy ||
    !Number.isFinite(Date.parse(tombstone.invalidatedAt))
  ) return null;
  return tombstone;
}

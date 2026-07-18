import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import type { JsonValue } from "../events";
import type { CircuitBreakerSnapshot, ProgressSnapshot } from "../supervisor";
import { FAILURE_CATEGORIES } from "../supervisor";
import type { ActionRepository } from "./ActionRepository";
import { canonicalJson, hashJson } from "./serialization";
import type {
  DurableControlState,
  DurableRun,
  PersistedCheckpointState,
} from "./types";

interface CheckpointRow {
  readonly id: string;
  readonly journey: DurableRun["run"]["journey"];
  readonly event_sequence: number;
  readonly state_json: string;
  readonly state_hash: string;
  readonly created_at: string;
}

export interface StoredCheckpoint {
  readonly id: string;
  readonly journey: DurableRun["run"]["journey"];
  readonly eventSequence: number;
  readonly state: PersistedCheckpointState;
  readonly stateHash: string;
  readonly createdAt: string;
}

function asJson(value: unknown): JsonValue {
  return JSON.parse(canonicalJson(value)) as JsonValue;
}

function circuitSnapshots(value: unknown): Record<string, CircuitBreakerSnapshot> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const output: Record<string, CircuitBreakerSnapshot> = {};
  for (const [key, candidate] of Object.entries(value as Record<string, unknown>)) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue;
    const item = candidate as Record<string, unknown>;
    if (
      (item.state === "closed" || item.state === "open" || item.state === "half_open") &&
      typeof item.consecutiveFailures === "number" &&
      typeof item.halfOpenSuccesses === "number" &&
      typeof item.halfOpenInFlight === "number"
    ) {
      output[key] = {
        state: item.state,
        consecutiveFailures: item.consecutiveFailures,
        halfOpenSuccesses: item.halfOpenSuccesses,
        halfOpenInFlight: item.halfOpenInFlight,
        ...(typeof item.openedAt === "number" ? { openedAt: item.openedAt } : {}),
      };
    }
  }
  return output;
}

function recoverySnapshot(value: unknown): DurableControlState["recovery"] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const item = value as Record<string, unknown>;
  if (
    (item.kind !== "retry" && item.kind !== "replan") ||
    typeof item.failedActionId !== "string" || !item.failedActionId ||
    typeof item.notBefore !== "string" || !Number.isFinite(Date.parse(item.notBefore)) ||
    typeof item.reason !== "string" || !item.reason
  ) return undefined;
  return {
    kind: item.kind,
    failedActionId: item.failedActionId,
    notBefore: item.notBefore,
    reason: item.reason,
  };
}

function planningRetrySnapshot(value: unknown): DurableControlState["planningRetry"] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const item = value as Record<string, unknown>;
  if (
    typeof item.continuationId !== "string" || !item.continuationId ||
    typeof item.failureCategory !== "string" ||
    !FAILURE_CATEGORIES.includes(item.failureCategory as typeof FAILURE_CATEGORIES[number]) ||
    typeof item.retryCount !== "number" || !Number.isSafeInteger(item.retryCount) || item.retryCount < 1 ||
    typeof item.notBefore !== "string" || !Number.isFinite(Date.parse(item.notBefore)) ||
    typeof item.errorCode !== "string" || !item.errorCode
  ) return undefined;
  return {
    continuationId: item.continuationId,
    failureCategory: item.failureCategory as typeof FAILURE_CATEGORIES[number],
    retryCount: item.retryCount,
    notBefore: item.notBefore,
    errorCode: item.errorCode,
  };
}

export class CheckpointRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly actions: ActionRepository,
  ) {}

  restoreControl(runId: string, fallback: DurableControlState): DurableControlState {
    const latest = this.latest(runId);
    if (!latest) return fallback;
    const raw = latest.state.control;
    return {
      ...fallback,
      circuits: circuitSnapshots(raw.circuits),
      progress:
        raw.progress && typeof raw.progress === "object" && !Array.isArray(raw.progress)
          ? (raw.progress as ProgressSnapshot)
          : fallback.progress,
      planningRetry: planningRetrySnapshot(raw.planningRetry),
      recovery: recoverySnapshot(raw.recovery),
    };
  }

  create(input: {
    run: DurableRun;
    eventSequence: number;
    now: string;
    inFlightClassification?: string;
  }): StoredCheckpoint {
    const completedActionIds = this.actions.completedIds(input.run.run.id);
    const inFlight = this.actions.inFlight(input.run.run.id);
    const state: PersistedCheckpointState = {
      schemaVersion: 1,
      run: {
        id: input.run.run.id,
        missionId: input.run.run.missionId,
        journey: input.run.run.journey,
        state: input.run.run.state,
        stateVersion: input.run.run.stateVersion,
        reason: input.run.run.stateReason,
        leaseOwner: input.run.lease?.ownerId ?? null,
        leaseExpiresAt: input.run.lease?.expiresAt ?? null,
      },
      control: {
        budget: asJson(input.run.control.budget),
        retryCount: input.run.control.retryCount,
        replanCount: input.run.control.replanCount,
        circuits: asJson(input.run.control.circuits),
        progress: asJson(input.run.control.progress),
        ...(input.run.control.planningRetry
          ? { planningRetry: asJson(input.run.control.planningRetry) }
          : {}),
        ...(input.run.control.recovery
          ? { recovery: asJson(input.run.control.recovery) }
          : {}),
      },
      completedActionIds,
      inFlightActions: inFlight.map((action) => ({
        id: action.id,
        status: action.status,
        idempotent: action.idempotent,
        destructive: action.destructive,
      })),
      lastEventSequence: input.eventSequence,
    };
    const checkpointId = `checkpoint_${randomUUID()}`;
    const stateHash = hashJson(state);
    const plan = this.database
      .prepare("SELECT version FROM plans WHERE id = (SELECT current_plan_id FROM runs WHERE id = ?)")
      .get(input.run.run.id) as { version: number } | undefined;
    this.database
      .prepare(`
        INSERT INTO checkpoints (
          id, mission_id, run_id, journey, event_sequence, plan_version,
          state_json, state_hash, in_flight_classification, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        checkpointId,
        input.run.run.missionId,
        input.run.run.id,
        input.run.run.journey,
        input.eventSequence,
        plan?.version ?? null,
        canonicalJson(state),
        stateHash,
        input.inFlightClassification ?? null,
        input.now,
      );
    return {
      id: checkpointId,
      journey: input.run.run.journey,
      eventSequence: input.eventSequence,
      state,
      stateHash,
      createdAt: input.now,
    };
  }

  latest(runId: string): StoredCheckpoint | undefined {
    const row = this.database
      .prepare(`
        SELECT id, journey, event_sequence, state_json, state_hash, created_at
        FROM checkpoints WHERE run_id = ?
        ORDER BY event_sequence DESC, created_at DESC LIMIT 1
      `)
      .get(runId) as CheckpointRow | undefined;
    if (!row) return undefined;
    const state = JSON.parse(row.state_json) as PersistedCheckpointState;
    if (row.journey !== state.run.journey) {
      throw new Error(`Checkpoint journey mismatch: ${row.id}`);
    }
    if (hashJson(state) !== row.state_hash) throw new Error(`Checkpoint hash mismatch: ${row.id}`);
    return {
      id: row.id,
      journey: row.journey,
      eventSequence: row.event_sequence,
      state,
      stateHash: row.state_hash,
      createdAt: row.created_at,
    };
  }
}

import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { redactSensitiveText } from "../guided-commander/validation";
import { canonicalJson, parseObject } from "../orchestration/serialization";

export const RUNTIME_CONTINUATION_KINDS = [
  "plan_ready_to_dispatch",
  "planning_retry_to_dispatch",
  "autonomous_retry_to_dispatch",
  "guided_approval_to_dispatch",
  "action_result_to_advance",
  "guided_failure_to_recover",
  "evaluation_pending",
  "cancellation_finalize_pending",
  "resume_recovery_pending",
] as const;

export type RuntimeContinuationKind = typeof RUNTIME_CONTINUATION_KINDS[number];
export type RuntimeContinuationStatus = "pending" | "processing" | "completed" | "cancelled";

export interface RuntimeContinuation {
  readonly id: string;
  readonly runId: string;
  readonly kind: RuntimeContinuationKind;
  readonly sourceId: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly status: RuntimeContinuationStatus;
  readonly attemptCount: number;
  readonly availableAt: string;
  readonly leaseOwner: string | null;
  readonly leaseExpiresAt: string | null;
  readonly lastError: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly completedAt: string | null;
}

interface ContinuationRow {
  readonly id: string;
  readonly run_id: string;
  readonly kind: RuntimeContinuationKind;
  readonly source_id: string;
  readonly payload_json: string;
  readonly status: RuntimeContinuationStatus;
  readonly attempt_count: number;
  readonly available_at: string;
  readonly lease_owner: string | null;
  readonly lease_expires_at: string | null;
  readonly last_error: string | null;
  readonly created_at: string;
  readonly updated_at: string;
  readonly completed_at: string | null;
}

function mapRow(row: ContinuationRow): RuntimeContinuation {
  return {
    id: row.id,
    runId: row.run_id,
    kind: row.kind,
    sourceId: row.source_id,
    payload: parseObject(row.payload_json),
    status: row.status,
    attemptCount: row.attempt_count,
    availableAt: row.available_at,
    leaseOwner: row.lease_owner,
    leaseExpiresAt: row.lease_expires_at,
    lastError: row.last_error,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    completedAt: row.completed_at,
  };
}

function requireText(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function safeIdentifier(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const redacted = redactSensitiveText(value.trim()).text.slice(0, 256);
  return redacted ? redacted : undefined;
}

function sanitizedPayload(
  kind: RuntimeContinuationKind,
  payload: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, string>> {
  if (!payload || kind === "cancellation_finalize_pending") return {};
  const keys: readonly string[] = kind === "plan_ready_to_dispatch"
    ? ["stepId"]
    : kind === "planning_retry_to_dispatch"
      ? ["failureCategory", "retryCount", "errorCode"]
    : kind === "autonomous_retry_to_dispatch"
      ? ["actionId", "stepId"]
    : kind === "guided_approval_to_dispatch"
      ? ["decisionId", "stepId"]
      : kind === "action_result_to_advance" || kind === "guided_failure_to_recover"
        ? ["actionId", "stepId"]
        : kind === "evaluation_pending"
          ? ["terminalStatus"]
          : ["actionId", "decisionId"];
  const output: Record<string, string> = {};
  for (const key of keys) {
    const value = safeIdentifier(payload[key]);
    if (value) output[key] = value;
  }
  return output;
}

function safeError(value: string, fallback: string): string {
  return (redactSensitiveText(value.trim()).text || fallback).slice(0, 512);
}

/**
 * Canonical, cross-process continuation queue for runtime state transitions.
 *
 * Callers enqueue while already inside the transaction that commits the
 * prerequisite state. Claims are owner-token fenced, and an abandoned
 * `processing` row becomes reclaimable only after its persisted lease expires.
 */
export class RuntimeContinuationRepository {
  constructor(readonly database: SqliteDatabase) {}

  enqueue(input: {
    readonly runId: string;
    readonly kind: RuntimeContinuationKind;
    readonly sourceId: string;
    readonly payload?: Readonly<Record<string, unknown>>;
    readonly now: string;
    readonly availableAt?: string;
  }): RuntimeContinuation {
    const runId = requireText(input.runId, "runId");
    const sourceId = requireText(input.sourceId, "sourceId");
    const id = `continuation_${randomUUID()}`;
    this.database.prepare(`
      INSERT INTO runtime_continuations (
        id, run_id, kind, source_id, payload_json, status, attempt_count,
        available_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)
      ON CONFLICT(run_id, kind, source_id) DO NOTHING
    `).run(
      id,
      runId,
      input.kind,
      sourceId,
      canonicalJson(sanitizedPayload(input.kind, input.payload)),
      input.availableAt ?? input.now,
      input.now,
      input.now,
    );
    return this.getByKey(runId, input.kind, sourceId);
  }

  get(id: string): RuntimeContinuation {
    const row = this.database.prepare(`
      SELECT * FROM runtime_continuations WHERE id = ?
    `).get(id) as ContinuationRow | undefined;
    if (!row) throw new Error(`Runtime continuation not found: ${id}`);
    return mapRow(row);
  }

  getByKey(runId: string, kind: RuntimeContinuationKind, sourceId: string): RuntimeContinuation {
    const row = this.database.prepare(`
      SELECT * FROM runtime_continuations
      WHERE run_id = ? AND kind = ? AND source_id = ?
    `).get(runId, kind, sourceId) as ContinuationRow | undefined;
    if (!row) throw new Error(`Runtime continuation not found: ${runId}/${kind}/${sourceId}`);
    return mapRow(row);
  }

  listForRun(runId: string): RuntimeContinuation[] {
    return (this.database.prepare(`
      SELECT * FROM runtime_continuations
      WHERE run_id = ? ORDER BY created_at, id
    `).all(runId) as ContinuationRow[]).map(mapRow);
  }

  readyRunIds(now: string, limit = 50): string[] {
    return (this.database.prepare(`
      SELECT run_id, MIN(created_at) AS first_created
      FROM runtime_continuations
      WHERE (status = 'pending' AND available_at <= ?)
         OR (status = 'processing' AND lease_expires_at <= ?)
      GROUP BY run_id
      ORDER BY first_created, run_id
      LIMIT ?
    `).all(now, now, limit) as Array<{ run_id: string }>).map((row) => row.run_id);
  }

  /**
   * Repair only canonical predecessor states that predate (or raced before)
   * continuation enqueueing. New writes must enqueue atomically at source; this
   * scan is intentionally conservative and never repeats an in-flight action.
   */
  reconcileFromCanonicalState(now: string): number {
    return inImmediateTransaction(this.database, () => {
      let repaired = 0;
      const enqueue = (input: Parameters<RuntimeContinuationRepository["enqueue"]>[0]) => {
        const before = this.database.prepare(`
          SELECT id FROM runtime_continuations
          WHERE run_id = ? AND kind = ? AND source_id = ?
        `).get(input.runId, input.kind, input.sourceId) as { id: string } | undefined;
        this.enqueue(input);
        if (!before) repaired += 1;
      };

      const cancellations = this.database.prepare(`
        SELECT e.id AS event_id, e.run_id
        FROM events e
        JOIN runs r ON r.id = e.run_id
        WHERE e.event_type = 'run.cancellation_requested'
          AND r.status NOT IN ('completed', 'failed', 'cancelled')
          AND NOT EXISTS (
            SELECT 1 FROM events terminal
            WHERE terminal.run_id = e.run_id
              AND terminal.sequence > e.sequence
              AND terminal.event_type IN ('run.cancelled', 'run.cancellation_failed')
          )
      `).all() as Array<{ event_id: string; run_id: string }>;
      for (const row of cancellations) {
        enqueue({
          runId: row.run_id,
          kind: "cancellation_finalize_pending",
          sourceId: row.event_id,
          now,
        });
      }

      const readyAutonomous = this.database.prepare(`
        SELECT r.id AS run_id, r.current_plan_id AS plan_id, ps.id AS step_id
        FROM runs r
        JOIN plans p ON p.id = r.current_plan_id AND p.status = 'active'
        JOIN plan_steps ps ON ps.id = r.current_step_id AND ps.plan_id = p.id
        WHERE r.journey = 'autonomous' AND r.status = 'running'
          AND ps.status = 'ready'
          AND NOT EXISTS (
            SELECT 1 FROM actions a
            WHERE a.run_id = r.id AND a.step_id = ps.id
          )
      `).all() as Array<{ run_id: string; plan_id: string; step_id: string }>;
      for (const row of readyAutonomous) {
        enqueue({
          runId: row.run_id,
          kind: "plan_ready_to_dispatch",
          sourceId: row.plan_id,
          payload: { stepId: row.step_id },
          now,
        });
      }

      const approvedGuided = this.database.prepare(`
        SELECT gd.run_id, gd.id AS decision_id, gd.step_id
        FROM guided_decisions gd
        JOIN runs r ON r.id = gd.run_id
        WHERE r.journey = 'guided'
          AND r.status IN ('waiting_guided_decision', 'running')
          AND gd.status = 'approved'
          AND NOT EXISTS (
            SELECT 1 FROM actions a WHERE a.guided_decision_id = gd.id
          )
      `).all() as Array<{ run_id: string; decision_id: string; step_id: string }>;
      for (const row of approvedGuided) {
        enqueue({
          runId: row.run_id,
          kind: "guided_approval_to_dispatch",
          sourceId: row.decision_id,
          payload: { decisionId: row.decision_id, stepId: row.step_id },
          now,
        });
      }

      const succeeded = this.database.prepare(`
        SELECT a.run_id, a.id AS action_id, a.step_id
        FROM actions a
        JOIN runs r ON r.id = a.run_id
        JOIN plan_steps ps ON ps.id = a.step_id
        WHERE r.status = 'running' AND a.status = 'succeeded'
          AND ps.status NOT IN ('completed', 'skipped', 'cancelled')
      `).all() as Array<{ run_id: string; action_id: string; step_id: string }>;
      for (const row of succeeded) {
        enqueue({
          runId: row.run_id,
          kind: "action_result_to_advance",
          sourceId: row.action_id,
          payload: { actionId: row.action_id, stepId: row.step_id },
          now,
        });
      }

      const guidedFailures = this.database.prepare(`
        SELECT a.run_id, a.id AS action_id, a.step_id
        FROM actions a
        JOIN runs r ON r.id = a.run_id
        WHERE r.journey = 'guided' AND r.status = 'recovering'
          AND a.status IN ('failed', 'timed_out', 'denied')
          AND a.ended_at = (
            SELECT MAX(latest.ended_at) FROM actions latest
            WHERE latest.run_id = a.run_id
              AND latest.status IN ('failed', 'timed_out', 'denied')
          )
      `).all() as Array<{ run_id: string; action_id: string; step_id: string }>;
      for (const row of guidedFailures) {
        enqueue({
          runId: row.run_id,
          kind: "guided_failure_to_recover",
          sourceId: row.action_id,
          payload: { actionId: row.action_id, stepId: row.step_id },
          now,
        });
      }

      const evaluations = this.database.prepare(`
        SELECT r.id AS run_id, p.id AS plan_id
        FROM runs r
        JOIN plans p ON p.id = r.current_plan_id
        WHERE r.status = 'running' AND p.status = 'completed'
          AND NOT EXISTS (SELECT 1 FROM run_evaluations re WHERE re.run_id = r.id)
      `).all() as Array<{ run_id: string; plan_id: string }>;
      for (const row of evaluations) {
        enqueue({
          runId: row.run_id,
          kind: "evaluation_pending",
          sourceId: row.plan_id,
          now,
        });
      }

      const resumed = this.database.prepare(`
        SELECT r.id AS run_id, CAST(r.version AS TEXT) AS source_id
        FROM runs r
        WHERE r.status = 'recovering'
          AND NOT EXISTS (
            SELECT 1 FROM actions a
            WHERE a.run_id = r.id AND a.status IN ('queued', 'running')
          )
          AND NOT EXISTS (
            SELECT 1 FROM actions failed
            WHERE failed.run_id = r.id
              AND failed.status IN ('failed', 'timed_out', 'denied')
          )
      `).all() as Array<{ run_id: string; source_id: string }>;
      for (const row of resumed) {
        enqueue({
          runId: row.run_id,
          kind: "resume_recovery_pending",
          sourceId: row.source_id,
          now,
        });
      }
      return repaired;
    });
  }

  claimNext(input: {
    readonly runId: string;
    readonly workerId: string;
    readonly now: string;
    readonly leaseTtlMs: number;
    readonly kinds?: readonly RuntimeContinuationKind[];
  }): RuntimeContinuation | null {
    if (!Number.isFinite(input.leaseTtlMs) || input.leaseTtlMs <= 0) {
      throw new RangeError("Continuation leaseTtlMs must be positive");
    }
    const workerId = requireText(input.workerId, "workerId");
    return inImmediateTransaction(this.database, () => {
      const kindFilter = input.kinds?.length
        ? `AND kind IN (${input.kinds.map(() => "?").join(",")})`
        : "";
      const parameters: unknown[] = [input.runId, input.now, input.now, ...(input.kinds ?? [])];
      const candidate = this.database.prepare(`
        SELECT id, attempt_count FROM runtime_continuations
        WHERE run_id = ?
          AND (
            (status = 'pending' AND available_at <= ?)
            OR (status = 'processing' AND lease_expires_at <= ?)
          )
          ${kindFilter}
        ORDER BY created_at, id LIMIT 1
      `).get(...parameters) as { id: string; attempt_count: number } | undefined;
      if (!candidate) return null;
      const attempt = candidate.attempt_count + 1;
      const ownerToken = `${workerId}:${candidate.id}:${attempt}`;
      const expiresAt = new Date(Date.parse(input.now) + input.leaseTtlMs).toISOString();
      const claimed = this.database.prepare(`
        UPDATE runtime_continuations
        SET status = 'processing', attempt_count = ?, lease_owner = ?,
          lease_expires_at = ?, updated_at = ?, last_error = NULL
        WHERE id = ? AND (
          (status = 'pending' AND available_at <= ?)
          OR (status = 'processing' AND lease_expires_at <= ?)
        )
      `).run(attempt, ownerToken, expiresAt, input.now, candidate.id, input.now, input.now);
      return claimed.changes === 1 ? this.get(candidate.id) : null;
    });
  }

  claimById(input: {
    readonly id: string;
    readonly workerId: string;
    readonly now: string;
    readonly leaseTtlMs: number;
  }): RuntimeContinuation {
    if (!Number.isFinite(input.leaseTtlMs) || input.leaseTtlMs <= 0) {
      throw new RangeError("Continuation leaseTtlMs must be positive");
    }
    const workerId = requireText(input.workerId, "workerId");
    return inImmediateTransaction(this.database, () => {
      const candidate = this.get(input.id);
      if (
        !(
          (candidate.status === "pending" && candidate.availableAt <= input.now) ||
          (candidate.status === "processing" && (candidate.leaseExpiresAt ?? "") <= input.now)
        )
      ) {
        throw new Error(`Runtime continuation is not claimable: ${input.id}`);
      }
      const attempt = candidate.attemptCount + 1;
      const ownerToken = `${workerId}:${candidate.id}:${attempt}`;
      const expiresAt = new Date(Date.parse(input.now) + input.leaseTtlMs).toISOString();
      const claimed = this.database.prepare(`
        UPDATE runtime_continuations
        SET status = 'processing', attempt_count = ?, lease_owner = ?,
          lease_expires_at = ?, updated_at = ?, last_error = NULL
        WHERE id = ? AND (
          (status = 'pending' AND available_at <= ?)
          OR (status = 'processing' AND lease_expires_at <= ?)
        )
      `).run(attempt, ownerToken, expiresAt, input.now, input.id, input.now, input.now);
      if (claimed.changes !== 1) throw new Error(`Runtime continuation claim fence lost: ${input.id}`);
      return this.get(input.id);
    });
  }

  complete(id: string, ownerToken: string, now: string): RuntimeContinuation {
    const completed = this.database.prepare(`
      UPDATE runtime_continuations
      SET status = 'completed', lease_owner = NULL, lease_expires_at = NULL,
        completed_at = ?, updated_at = ?, last_error = NULL
      WHERE id = ? AND status = 'processing' AND lease_owner = ?
        AND lease_expires_at > ?
    `).run(now, now, id, ownerToken, now);
    if (completed.changes !== 1) {
      throw new Error(`Runtime continuation completion fence lost: ${id}`);
    }
    return this.get(id);
  }

  heartbeat(
    id: string,
    ownerToken: string,
    now: string,
    leaseTtlMs: number,
  ): RuntimeContinuation {
    if (!Number.isFinite(leaseTtlMs) || leaseTtlMs <= 0) {
      throw new RangeError("Continuation leaseTtlMs must be positive");
    }
    const expiresAt = new Date(Date.parse(now) + leaseTtlMs).toISOString();
    const renewed = this.database.prepare(`
      UPDATE runtime_continuations
      SET lease_expires_at = ?, updated_at = ?
      WHERE id = ? AND status = 'processing' AND lease_owner = ?
        AND lease_expires_at > ?
    `).run(expiresAt, now, id, ownerToken, now);
    if (renewed.changes !== 1) {
      throw new Error(`Runtime continuation heartbeat fence lost: ${id}`);
    }
    return this.get(id);
  }

  retry(input: {
    readonly id: string;
    readonly ownerToken: string;
    readonly now: string;
    readonly availableAt: string;
    readonly error: string;
  }): RuntimeContinuation {
    const message = safeError(input.error, "Continuation handler failed");
    const released = this.database.prepare(`
      UPDATE runtime_continuations
      SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL,
        available_at = ?, updated_at = ?, last_error = ?
      WHERE id = ? AND status = 'processing' AND lease_owner = ?
        AND lease_expires_at > ?
    `).run(input.availableAt, input.now, message, input.id, input.ownerToken, input.now);
    if (released.changes !== 1) {
      throw new Error(`Runtime continuation retry fence lost: ${input.id}`);
    }
    return this.get(input.id);
  }

  fail(input: {
    readonly id: string;
    readonly ownerToken: string;
    readonly now: string;
    readonly error: string;
  }): RuntimeContinuation {
    const message = safeError(input.error, "Continuation retry budget exhausted");
    const failed = this.database.prepare(`
      UPDATE runtime_continuations
      SET status = 'cancelled', lease_owner = NULL, lease_expires_at = NULL,
        updated_at = ?, last_error = ?
      WHERE id = ? AND status = 'processing' AND lease_owner = ?
        AND lease_expires_at > ?
    `).run(input.now, message, input.id, input.ownerToken, input.now);
    if (failed.changes !== 1) {
      throw new Error(`Runtime continuation failure fence lost: ${input.id}`);
    }
    return this.get(input.id);
  }

  cancelOpen(runId: string, now: string, reason: string): number {
    return this.database.prepare(`
      UPDATE runtime_continuations
      SET status = 'cancelled', lease_owner = NULL, lease_expires_at = NULL,
        updated_at = ?, last_error = ?
      WHERE run_id = ? AND status IN ('pending', 'processing')
    `).run(now, safeError(reason, "Run reached a terminal state"), runId).changes;
  }
}

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
  "memory_projection_pending",
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
  constructor(
    readonly database: SqliteDatabase,
    private readonly assertMutationAuthority?: (runId: string) => void,
  ) {}

  private assertRunMutation(runId: string): void {
    this.assertMutationAuthority?.(runId);
  }

  private runIdForContinuation(id: string): string {
    const row = this.database.prepare(
      "SELECT run_id FROM runtime_continuations WHERE id = ?",
    ).get(id) as { run_id: string } | undefined;
    if (!row) throw new Error(`Runtime continuation not found: ${id}`);
    return row.run_id;
  }

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
    return inImmediateTransaction(this.database, () => {
      this.assertRunMutation(runId);
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
    });
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

  readyRunIds(
    now: string,
    limit = 50,
    controlPlane?: "legacy" | "ti_scale",
  ): string[] {
    return (this.database.prepare(`
      SELECT rc.run_id, MIN(rc.created_at) AS first_created
      FROM runtime_continuations rc
      JOIN runs r ON r.id = rc.run_id
      JOIN missions m ON m.id = r.mission_id
      WHERE (
        (rc.status = 'pending' AND rc.available_at <= ?)
        OR (rc.status = 'processing' AND rc.lease_expires_at <= ?)
      )
        AND (? IS NULL OR (r.control_plane = ? AND m.control_plane = ?))
        AND NOT EXISTS (
          SELECT 1
          FROM plan_change_inflight_resolutions gate
          LEFT JOIN plan_change_requests fresh
            ON fresh.id = gate.fresh_request_id
          WHERE gate.run_id = rc.run_id
            AND (
              gate.status IN ('waiting_for_terminal_work', 'failed')
              OR (
                gate.status = 'ready_for_review'
                AND COALESCE(fresh.status, 'proposed')
                  IN ('proposed', 'validated')
              )
            )
        )
      GROUP BY rc.run_id
      ORDER BY first_created, rc.run_id
      LIMIT ?
    `).all(
      now,
      now,
      controlPlane ?? null,
      controlPlane ?? null,
      controlPlane ?? null,
      limit,
    ) as Array<{ run_id: string }>).map((row) => row.run_id);
  }

  /**
   * Repair only canonical predecessor states that predate (or raced before)
   * continuation enqueueing. New writes must enqueue atomically at source; this
   * scan is intentionally conservative and never repeats an in-flight action.
   */
  reconcileFromCanonicalState(
    now: string,
    controlPlane?: "legacy" | "ti_scale",
    supportedJourneys: readonly ("autonomous" | "guided")[] = ["autonomous", "guided"],
  ): number {
    const journeys = new Set(supportedJourneys);
    if (
      journeys.size === 0
      || [...journeys].some((journey) => journey !== "autonomous" && journey !== "guided")
    ) {
      throw new RangeError("Continuation reconciliation requires guided and/or autonomous journey scope");
    }
    return inImmediateTransaction(this.database, () => {
      let repaired = 0;
      const ownership = controlPlane
        ? `AND r.control_plane = '${controlPlane}' AND m.control_plane = '${controlPlane}'`
        : "";
      const enqueue = (input: Parameters<RuntimeContinuationRepository["enqueue"]>[0]) => {
        const run = this.database.prepare("SELECT journey FROM runs WHERE id = ?")
          .get(input.runId) as { journey: "autonomous" | "guided" } | undefined;
        if (!run || !journeys.has(run.journey)) return;
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
        JOIN missions m ON m.id = r.mission_id
        WHERE e.event_type = 'run.cancellation_requested'
          AND r.status NOT IN ('completed', 'failed', 'cancelled')
          ${ownership}
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
        JOIN missions m ON m.id = r.mission_id
        JOIN plans p ON p.id = r.current_plan_id AND p.status = 'active'
        JOIN plan_steps ps ON ps.id = r.current_step_id AND ps.plan_id = p.id
        WHERE r.journey = 'autonomous' AND r.status = 'running'
          ${ownership}
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
        JOIN missions m ON m.id = r.mission_id
        WHERE r.journey = 'guided'
          ${ownership}
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
        JOIN missions m ON m.id = r.mission_id
        JOIN plan_steps ps ON ps.id = a.step_id
        WHERE r.status = 'running' AND a.status = 'succeeded'
          ${ownership}
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
        JOIN missions m ON m.id = r.mission_id
        WHERE r.journey = 'guided' AND r.status = 'recovering'
          ${ownership}
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
        JOIN missions m ON m.id = r.mission_id
        JOIN plans p ON p.id = r.current_plan_id
        WHERE r.status = 'running' AND p.status = 'completed'
          ${ownership}
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

      // Terminal memory/Vault projection is a separate, post-commit concern.
      // Reconstruct a missing continuation from the canonical evaluation so a
      // process that died after evaluation commit cannot strand its graph in
      // SQLite without the configured human-readable Vault projection.
      const memoryProjections = this.database.prepare(`
        SELECT re.run_id, re.id AS evaluation_id
        FROM run_evaluations re
        JOIN runs r ON r.id = re.run_id
        JOIN missions m ON m.id = r.mission_id AND m.id = re.mission_id
        WHERE 1 = 1
          ${ownership}
          AND NOT EXISTS (
            SELECT 1 FROM runtime_continuations rc
            WHERE rc.run_id = re.run_id
              AND rc.kind = 'memory_projection_pending'
              AND rc.source_id = re.id
          )
        ORDER BY re.created_at, re.id
      `).all() as Array<{ run_id: string; evaluation_id: string }>;
      for (const row of memoryProjections) {
        enqueue({
          runId: row.run_id,
          kind: "memory_projection_pending",
          sourceId: row.evaluation_id,
          now,
        });
      }

      const resumed = this.database.prepare(`
        SELECT r.id AS run_id, CAST(r.version AS TEXT) AS source_id
        FROM runs r
        JOIN missions m ON m.id = r.mission_id
        WHERE r.status = 'recovering'
          ${ownership}
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
      this.assertRunMutation(input.runId);
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
          AND NOT EXISTS (
            SELECT 1
            FROM plan_change_inflight_resolutions gate
            LEFT JOIN plan_change_requests fresh
              ON fresh.id = gate.fresh_request_id
            WHERE gate.run_id = runtime_continuations.run_id
              AND (
                gate.status IN ('waiting_for_terminal_work', 'failed')
                OR (
                  gate.status = 'ready_for_review'
                  AND COALESCE(fresh.status, 'proposed')
                    IN ('proposed', 'validated')
                )
              )
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
      this.assertRunMutation(candidate.runId);
      const gated = this.database.prepare(`
        SELECT 1
        FROM plan_change_inflight_resolutions gate
        LEFT JOIN plan_change_requests fresh ON fresh.id = gate.fresh_request_id
        WHERE gate.run_id = ?
          AND (
            gate.status IN ('waiting_for_terminal_work', 'failed')
            OR (
              gate.status = 'ready_for_review'
              AND COALESCE(fresh.status, 'proposed') IN ('proposed', 'validated')
            )
          )
        LIMIT 1
      `).get(candidate.runId);
      if (gated) {
        throw new Error(
          `Runtime continuation is fenced by an open plan amendment: ${input.id}`,
        );
      }
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
    return inImmediateTransaction(this.database, () => {
      this.assertRunMutation(this.runIdForContinuation(id));
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
    });
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
    return inImmediateTransaction(this.database, () => {
      this.assertRunMutation(this.runIdForContinuation(id));
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
    });
  }

  retry(input: {
    readonly id: string;
    readonly ownerToken: string;
    readonly now: string;
    readonly availableAt: string;
    readonly error: string;
  }): RuntimeContinuation {
    return inImmediateTransaction(this.database, () => {
      this.assertRunMutation(this.runIdForContinuation(input.id));
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
    });
  }

  fail(input: {
    readonly id: string;
    readonly ownerToken: string;
    readonly now: string;
    readonly error: string;
  }): RuntimeContinuation {
    return inImmediateTransaction(this.database, () => {
      this.assertRunMutation(this.runIdForContinuation(input.id));
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
    });
  }

  cancelOpen(runId: string, now: string, reason: string): number {
    return inImmediateTransaction(this.database, () => {
      this.assertRunMutation(runId);
      return this.database.prepare(`
        UPDATE runtime_continuations
        SET status = 'cancelled', lease_owner = NULL, lease_expires_at = NULL,
          updated_at = ?, last_error = ?
        WHERE run_id = ? AND status IN ('pending', 'processing')
      `).run(now, safeError(reason, "Run reached a terminal state"), runId).changes;
    });
  }
}

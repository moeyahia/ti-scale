import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { conflict, forbidden, notFound } from "./errors";
import { missionScopeSql, sensitivitySql } from "./scope";
import type {
  AdministrativeApprovalReviewProjection,
  DecisionInboxItem,
  DecisionInboxKind,
  OperationsAccessPolicy,
  OperationsActor,
  OperationsPage,
} from "./types";
import { OPERATIONS_SCHEMA_VERSION } from "./types";
import {
  canonicalJson,
  decodeCursor,
  encodeCursor,
  parseJson,
  sanitizeJson,
  sanitizeJsonWithRedaction,
  sha256,
} from "./validation";

type Row = Record<string, any>;

export interface DecisionInboxOptions {
  readonly limit: number;
  readonly cursor?: string;
  readonly kind?: DecisionInboxKind;
  readonly status?: string;
  readonly missionId?: string;
  readonly runId?: string;
  readonly query?: string;
  readonly from?: string;
  readonly to?: string;
}

export interface AdministrativeApprovalReviewInput {
  readonly status: "approved" | "rejected";
  readonly reason: string;
}

const EXCEPTION_EVENT_TYPES = [
  "run.autonomous_safe_stopped",
  "run.safe_stopped",
  "run.failed_safely",
  "run.cancellation_failed",
  "run.continuation_blocked",
  "run.recovery_blocked",
  "action.pre_dispatch_denied",
  "policy.denied",
  "budget.exhausted",
  "run.budget_exhausted",
] as const;

const TERMINAL_RUN_STATES = new Set(["completed", "failed", "cancelled"]);

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function contractTitle(version: number, state: string): string {
  return state === "draft"
    ? `Autonomous contract v${version} awaiting confirmation`
    : `Autonomous contract v${version}`;
}

function exceptionTitle(eventType: string): string {
  if (eventType === "action.pre_dispatch_denied") return "Autonomous dispatch denied";
  if (eventType === "run.cancellation_failed") return "Autonomous cancellation exception";
  if (eventType === "run.continuation_blocked") return "Autonomous continuation blocked";
  if (eventType === "run.recovery_blocked") return "Autonomous recovery blocked";
  if (eventType === "policy.denied") return "Autonomous policy denial";
  if (eventType === "budget.exhausted" || eventType === "run.budget_exhausted") return "Autonomous budget exception";
  if (eventType.includes("safe_stop") || eventType.includes("safe_stopped")) return "Autonomous safe stop";
  return "Autonomous post-run exception";
}

function administrativeReviewAvailability(row: Row, now: string): {
  readonly available: boolean;
  readonly reason: string | null;
} {
  if (row.status !== "pending") return { available: false, reason: "This administrative record is already resolved." };
  if (row.expires_at && Date.parse(row.expires_at) <= Date.parse(now)) {
    return { available: false, reason: "This administrative approval has expired." };
  }
  if (row.run_journey === "autonomous" && row.run_status && !TERMINAL_RUN_STATES.has(row.run_status)) {
    return {
      available: false,
      reason: "A running Autonomous mission cannot be unblocked through the administrative inbox.",
    };
  }
  return { available: true, reason: null };
}

/**
 * Canonical, scope-enforced decision projections. This repository never
 * derives attention from run text and never changes runtime state.
 */
export class DecisionInboxRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  list(
    access: OperationsAccessPolicy,
    options: DecisionInboxOptions,
  ): OperationsPage<DecisionInboxItem> {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("e.sensitivity", access);
    const parts: string[] = [];
    const params: unknown[] = [];
    const include = (kind: DecisionInboxKind): boolean => !options.kind || options.kind === kind;

    if (include("guided_decision")) {
      parts.push(`
        SELECT gd.created_at AS sort_at, 'guided:' || gd.id AS sort_id,
          gd.id, 'guided_decision' AS kind,
          m.id AS mission_id, m.name AS mission_name, m.engagement_id,
          r.id AS run_id, r.status AS run_status, r.journey AS run_journey,
          CASE WHEN gd.status = 'pending' AND gd.expires_at <= ? THEN 'expired' ELSE gd.status END AS status,
          'Guided exact-step decision' AS title, gd.rationale AS summary,
          gd.created_at, gd.decided_at AS resolved_at, gd.expires_at,
          gd.step_id, gd.requested_action_fingerprint, gd.requested_parameters_json,
          gd.rationale, gd.risk_class, gd.reversibility, gd.decision_actor,
          gd.decision_reason,
          NULL AS contract_version, NULL AS contract_hash, NULL AS confirmed_by,
          NULL AS confirmed_at,
          NULL AS event_type, NULL AS event_sequence, NULL AS event_payload_json,
          NULL AS event_redaction_json, NULL AS event_sensitivity, NULL AS trace_id,
          NULL AS approval_type, NULL AS requested_by, NULL AS policy_rule,
          NULL AS approval_request_json, NULL AS approval_decided_by
        FROM guided_decisions gd
        JOIN missions m ON m.id = gd.mission_id
        JOIN runs r ON r.id = gd.run_id
        WHERE r.journey = 'guided' AND ${scope.sql}
      `);
      params.push(this.clock().toISOString(), ...scope.params);
    }

    if (include("autonomous_contract")) {
      parts.push(`
        SELECT mc.created_at AS sort_at, 'contract:' || mc.id AS sort_id,
          mc.id, 'autonomous_contract' AS kind,
          m.id AS mission_id, m.name AS mission_name, m.engagement_id,
          r.id AS run_id, r.status AS run_status, r.journey AS run_journey,
          mc.state AS status,
          'Autonomous mission contract' AS title,
          CASE
            WHEN mc.state = 'draft' THEN 'Versioned contract awaiting deliberate confirmation before launch.'
            WHEN mc.state = 'confirmed' THEN 'Signed Autonomous authority and operating boundaries.'
            WHEN mc.state = 'superseded' THEN 'Historical contract retained for immutable run lineage.'
            ELSE 'Contract authority was revoked for future work.'
          END AS summary,
          mc.created_at, mc.confirmed_at AS resolved_at, NULL AS expires_at,
          NULL AS step_id, NULL AS requested_action_fingerprint,
          NULL AS requested_parameters_json, NULL AS rationale, NULL AS risk_class,
          NULL AS reversibility, NULL AS decision_actor, NULL AS decision_reason,
          mc.version AS contract_version, mc.contract_hash, mc.confirmed_by,
          mc.confirmed_at,
          NULL AS event_type, NULL AS event_sequence, NULL AS event_payload_json,
          NULL AS event_redaction_json, NULL AS event_sensitivity, NULL AS trace_id,
          NULL AS approval_type, NULL AS requested_by, NULL AS policy_rule,
          NULL AS approval_request_json, NULL AS approval_decided_by
        FROM mission_contracts mc
        JOIN missions m ON m.id = mc.mission_id
        LEFT JOIN runs r ON r.id = (
          SELECT cr.id FROM runs cr WHERE cr.contract_id = mc.id
          ORDER BY cr.created_at DESC, cr.id DESC LIMIT 1
        )
        WHERE m.journey = 'autonomous' AND ${scope.sql}
      `);
      params.push(...scope.params);
    }

    if (include("autonomous_exception")) {
      parts.push(`
        SELECT e.occurred_at AS sort_at, 'exception:' || e.id AS sort_id,
          e.id, 'autonomous_exception' AS kind,
          m.id AS mission_id, m.name AS mission_name, m.engagement_id,
          r.id AS run_id, r.status AS run_status, r.journey AS run_journey,
          CASE WHEN r.status IN ('completed', 'failed', 'cancelled') THEN 'post_run' ELSE 'attention' END AS status,
          'Autonomous exception' AS title, e.summary,
          e.occurred_at AS created_at, r.ended_at AS resolved_at, NULL AS expires_at,
          NULL AS step_id, NULL AS requested_action_fingerprint,
          NULL AS requested_parameters_json, NULL AS rationale, NULL AS risk_class,
          NULL AS reversibility, NULL AS decision_actor, NULL AS decision_reason,
          NULL AS contract_version, NULL AS contract_hash, NULL AS confirmed_by,
          NULL AS confirmed_at,
          e.event_type, e.sequence AS event_sequence, e.payload_json AS event_payload_json,
          e.redaction_json AS event_redaction_json, e.sensitivity AS event_sensitivity,
          e.trace_id,
          NULL AS approval_type, NULL AS requested_by, NULL AS policy_rule,
          NULL AS approval_request_json, NULL AS approval_decided_by
        FROM events e
        JOIN runs r ON r.id = e.run_id
        JOIN missions m ON m.id = e.mission_id
        WHERE e.journey = 'autonomous'
          AND e.event_type IN (${EXCEPTION_EVENT_TYPES.map(() => "?").join(",")})
          AND ${scope.sql} AND ${sensitivity.sql}
      `);
      params.push(...EXCEPTION_EVENT_TYPES, ...scope.params, ...sensitivity.params);
    }

    if (include("administrative_approval")) {
      parts.push(`
        SELECT a.created_at AS sort_at, 'approval:' || a.id AS sort_id,
          a.id, 'administrative_approval' AS kind,
          m.id AS mission_id, m.name AS mission_name, m.engagement_id,
          r.id AS run_id, r.status AS run_status, r.journey AS run_journey,
          CASE WHEN a.status = 'pending' AND a.expires_at IS NOT NULL AND a.expires_at <= ?
            THEN 'expired' ELSE a.status END AS status,
          'Administrative approval' AS title, a.reason AS summary,
          a.created_at, a.decided_at AS resolved_at, a.expires_at,
          NULL AS step_id, NULL AS requested_action_fingerprint,
          NULL AS requested_parameters_json, NULL AS rationale, NULL AS risk_class,
          NULL AS reversibility, NULL AS decision_actor, NULL AS decision_reason,
          NULL AS contract_version, NULL AS contract_hash, NULL AS confirmed_by,
          NULL AS confirmed_at,
          NULL AS event_type, NULL AS event_sequence, NULL AS event_payload_json,
          NULL AS event_redaction_json, NULL AS event_sensitivity, NULL AS trace_id,
          a.approval_type, a.requested_by, a.policy_rule,
          a.request_json AS approval_request_json, a.decided_by AS approval_decided_by
        FROM approvals a
        LEFT JOIN runs r ON r.id = a.run_id
        LEFT JOIN missions m ON m.id = COALESCE(a.mission_id, r.mission_id)
        WHERE ((m.id IS NOT NULL AND ${scope.sql}) OR (m.id IS NULL AND ? = 1))
      `);
      params.push(
        this.clock().toISOString(),
        ...scope.params,
        access.allowUnscopedSystemData ? 1 : 0,
      );
    }

    if (parts.length === 0) {
      return { schemaVersion: OPERATIONS_SCHEMA_VERSION, items: [], nextCursor: null };
    }

    const clauses = ["1"];
    const outerParams: unknown[] = [];
    if (options.status) { clauses.push("status = ?"); outerParams.push(options.status); }
    if (options.missionId) { clauses.push("mission_id = ?"); outerParams.push(options.missionId); }
    if (options.runId) { clauses.push("run_id = ?"); outerParams.push(options.runId); }
    if (options.from) { clauses.push("sort_at >= ?"); outerParams.push(options.from); }
    if (options.to) { clauses.push("sort_at <= ?"); outerParams.push(options.to); }
    if (options.query) {
      clauses.push(`instr(lower(
        coalesce(id, '') || ' ' || coalesce(mission_name, '') || ' ' ||
        coalesce(run_id, '') || ' ' || coalesce(title, '') || ' ' ||
        coalesce(summary, '') || ' ' || coalesce(approval_type, '') || ' ' ||
        coalesce(event_type, '')
      ), lower(?)) > 0`);
      outerParams.push(options.query);
    }
    const decoded = decodeCursor(options.cursor);
    if (decoded) {
      clauses.push("(sort_at < ? OR (sort_at = ? AND sort_id < ?))");
      outerParams.push(decoded.sort, decoded.sort, decoded.id);
    }

    const rows = this.database.prepare(`
      SELECT * FROM (${parts.join(" UNION ALL ")}) inbox
      WHERE ${clauses.join(" AND ")}
      ORDER BY sort_at DESC, sort_id DESC
      LIMIT ?
    `).all(...params, ...outerParams, options.limit + 1) as Row[];
    const hasMore = rows.length > options.limit;
    const visible = hasMore ? rows.slice(0, options.limit) : rows;
    const last = visible.at(-1);
    return {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      items: visible.map((row) => this.map(row, access)),
      nextCursor: hasMore && last ? encodeCursor(last.sort_at, last.sort_id) : null,
    };
  }

  reviewAdministrativeApproval(
    approvalId: string,
    input: AdministrativeApprovalReviewInput,
    idempotencyKey: string,
    actor: OperationsActor,
    access: OperationsAccessPolicy,
  ): AdministrativeApprovalReviewProjection {
    if (!access.canReviewAdministrativeApprovals || !["reviewer", "admin"].includes(actor.type)) {
      throw forbidden("This identity cannot review administrative approvals.");
    }
    return inImmediateTransaction(this.database, () => {
      const scope = missionScopeSql("m", access);
      const row = this.database.prepare(`
        SELECT a.*, r.status AS run_status, r.journey AS run_journey,
          m.id AS scoped_mission_id, m.journey AS mission_journey
        FROM approvals a
        LEFT JOIN runs r ON r.id = a.run_id
        LEFT JOIN missions m ON m.id = COALESCE(a.mission_id, r.mission_id)
        WHERE a.id = ?
          AND ((m.id IS NOT NULL AND ${scope.sql}) OR (m.id IS NULL AND ? = 1))
      `).get(approvalId, ...scope.params, access.allowUnscopedSystemData ? 1 : 0) as Row | undefined;
      if (!row) throw notFound("Administrative approval");

      const key = `idempotency.operations.administrative_approval.${sha256(`${actor.id}\u0000${idempotencyKey}`)}`;
      const requestHash = sha256(canonicalJson({ actor: actor.id, approvalId, input }));
      const replay = this.idempotencyReplay(key, requestHash);
      if (replay) return replay as unknown as AdministrativeApprovalReviewProjection;

      const now = this.clock().toISOString();
      const availability = administrativeReviewAvailability(row, now);
      if (!availability.available) {
        throw conflict(
          availability.reason ?? "This administrative approval cannot be reviewed.",
          row.run_journey === "autonomous" && row.run_status && !TERMINAL_RUN_STATES.has(row.run_status)
            ? "Pause and create a versioned contract amendment or wait for a terminal safe stop; do not use approval to resume Autonomous work."
            : "Refresh the decision inbox before trying again.",
        );
      }

      const update = this.database.prepare(`
        UPDATE approvals SET status = ?, decided_by = ?, decided_at = ?
        WHERE id = ? AND status = 'pending'
      `).run(input.status, actor.id, now, approvalId);
      if (update.changes !== 1) throw conflict("The administrative approval changed after it was loaded.");

      const response: AdministrativeApprovalReviewProjection = {
        schemaVersion: OPERATIONS_SCHEMA_VERSION,
        approval: {
          id: approvalId,
          missionId: row.scoped_mission_id ?? null,
          runId: row.run_id ?? null,
          approvalType: row.approval_type,
          status: input.status,
          decidedBy: actor.id,
          decidedAt: now,
          decisionReason: input.reason,
          runtimeStateChanged: false,
          autonomousActionUnblocked: false,
        },
      };
      this.appendAudit({
        row,
        actor,
        status: input.status,
        reason: input.reason,
        occurredAt: now,
      });
      this.database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'restricted', 1, ?, ?)
      `).run(key, canonicalJson({ requestHash, response }), actor.id, now);
      return response;
    });
  }

  private map(row: Row, access: OperationsAccessPolicy): DecisionInboxItem {
    const mission = row.mission_id
      ? { id: row.mission_id, name: row.mission_name, engagementId: row.engagement_id }
      : null;
    const run = row.run_id
      ? { id: row.run_id, status: row.run_status, journey: row.run_journey }
      : null;
    const base = {
      id: row.id,
      mission,
      run,
      status: row.status,
      title: row.title,
      summary: sanitizeJson(row.summary),
      createdAt: row.created_at,
      resolvedAt: row.resolved_at,
      expiresAt: row.expires_at,
    };

    if (row.kind === "guided_decision") {
      return {
        ...base,
        kind: "guided_decision",
        mission: mission!,
        run: run as { id: string; status: string; journey: "guided" },
        deepLink: `/guided/${encodeURIComponent(row.mission_id)}`,
        exactStep: {
          stepId: row.step_id,
          actionFingerprint: row.requested_action_fingerprint,
          requestedParameters: sanitizeJson(parseJson(row.requested_parameters_json)),
          rationale: sanitizeJson(row.rationale),
          riskClass: row.risk_class,
          reversibility: sanitizeJson(row.reversibility),
          decisionActor: row.decision_actor,
          decisionReason: row.decision_reason ? sanitizeJson(row.decision_reason) : null,
        },
      };
    }
    if (row.kind === "autonomous_contract") {
      const version = Number(row.contract_version);
      return {
        ...base,
        kind: "autonomous_contract",
        mission: mission!,
        title: contractTitle(version, row.status),
        deepLink: `/missions/${encodeURIComponent(row.mission_id)}?tab=settings`,
        contract: {
          version,
          hash: row.contract_hash,
          state: row.status,
          confirmedBy: row.confirmed_by,
          confirmedAt: row.confirmed_at,
        },
      };
    }
    if (row.kind === "autonomous_exception") {
      const payload = sanitizeJsonWithRedaction(
        parseJson(row.event_payload_json),
        parseJson(row.event_redaction_json),
      );
      const record = payload && typeof payload === "object" && !Array.isArray(payload)
        ? payload as Record<string, unknown>
        : {};
      return {
        ...base,
        kind: "autonomous_exception",
        mission: mission!,
        run: run as { id: string; status: string; journey: "autonomous" },
        title: exceptionTitle(row.event_type),
        deepLink: `/missions/${encodeURIComponent(row.mission_id)}/runs/${encodeURIComponent(row.run_id)}`,
        exception: {
          eventType: row.event_type,
          sequence: Number(row.event_sequence),
          phase: TERMINAL_RUN_STATES.has(row.run_status) ? "post_run" : "active",
          code: stringValue(record.code),
          category: stringValue(record.category),
          traceId: row.trace_id,
          details: payload,
        },
      };
    }

    const availability = administrativeReviewAvailability(row, this.clock().toISOString());
    return {
      ...base,
      kind: "administrative_approval",
      deepLink: mission
        ? `/missions/${encodeURIComponent(mission.id)}${run ? `/runs/${encodeURIComponent(run.id)}` : ""}`
        : "/system/policies",
      approval: {
        approvalType: row.approval_type,
        requestedBy: row.requested_by,
        policyRule: row.policy_rule,
        request: sanitizeJson(parseJson(row.approval_request_json)),
        decidedBy: row.approval_decided_by,
        reviewAvailable: Boolean(access.canReviewAdministrativeApprovals && availability.available),
        reviewUnavailableReason: access.canReviewAdministrativeApprovals
          ? availability.reason
          : "This identity does not have administrative review permission.",
      },
    };
  }

  private idempotencyReplay(
    key: string,
    requestHash: string,
  ): Record<string, unknown> | undefined {
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?").get(key) as Row | undefined;
    if (!row) return undefined;
    const value = JSON.parse(row.value_json) as { requestHash?: string; response?: Record<string, unknown> };
    if (value.requestHash !== requestHash || !value.response) {
      throw conflict(
        "The idempotency key was already used for a different administrative review.",
        "Use a new Idempotency-Key for a materially different request.",
      );
    }
    return value.response;
  }

  private appendAudit(input: {
    readonly row: Row;
    readonly actor: OperationsActor;
    readonly status: "approved" | "rejected";
    readonly reason: string;
    readonly occurredAt: string;
  }): void {
    const previous = this.database.prepare(`
      SELECT record_hash FROM audit_records ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get() as { record_hash: string } | undefined;
    const id = `audit_${randomUUID()}`;
    const journey = input.row.run_journey ?? input.row.mission_journey ?? null;
    const details = {
      from: input.row.status,
      to: input.status,
      approvalType: input.row.approval_type,
      policyRule: input.row.policy_rule,
      runtimeStateChanged: false,
      autonomousActionUnblocked: false,
    };
    const hashInput = {
      id,
      missionId: input.row.scoped_mission_id ?? null,
      runId: input.row.run_id ?? null,
      journey,
      actorType: input.actor.type,
      actorId: input.actor.id,
      action: `administrative_approval.${input.status}`,
      resourceType: "administrative_approval",
      resourceId: input.row.id,
      reason: input.reason,
      details,
      previousHash: previous?.record_hash ?? null,
      occurredAt: input.occurredAt,
    };
    const recordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(hashInput)}`);
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json,
        previous_hash, record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      input.row.scoped_mission_id ?? null,
      input.row.run_id ?? null,
      journey,
      input.actor.type,
      input.actor.id,
      hashInput.action,
      hashInput.resourceType,
      input.row.id,
      input.reason,
      canonicalJson(details),
      previous?.record_hash ?? null,
      recordHash,
      input.occurredAt,
    );
  }
}

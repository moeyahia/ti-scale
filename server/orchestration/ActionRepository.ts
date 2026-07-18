import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import {
  FAILURE_CATEGORIES,
  type ActionObservation,
  type FailureCategory,
} from "../supervisor";
import { DurableOrchestrationError, type DurableAction, type DurableActionIntent } from "./types";
import { canonicalJson, parseObject } from "./serialization";

interface ActionRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly step_id: string | null;
  readonly action_type: string;
  readonly action_class: string;
  readonly fingerprint: string;
  readonly normalized_arguments_json: string;
  readonly scoped_target: string | null;
  readonly status: DurableAction["status"];
  readonly intent_summary: string;
  readonly result_summary: string | null;
  readonly error_category: string | null;
  readonly retry_count: number;
  readonly progress_signature: string | null;
  readonly guided_decision_id: string | null;
  readonly contract_id: string | null;
  readonly context_pack_id: string | null;
  readonly started_at: string | null;
  readonly ended_at: string | null;
  readonly created_at: string;
}

interface EventPayloadRow {
  readonly payload_json: string;
}

function metadata(row: ActionRow): {
  arguments: Readonly<Record<string, unknown>>;
  kind: DurableAction["kind"];
  idempotent: boolean;
  destructive: boolean;
} {
  const stored = parseObject(row.normalized_arguments_json);
  const orchestration = stored.orchestration && typeof stored.orchestration === "object"
    ? (stored.orchestration as Record<string, unknown>)
    : {};
  const input = stored.input && typeof stored.input === "object" && !Array.isArray(stored.input)
    ? (stored.input as Record<string, unknown>)
    : {};
  const kind = orchestration.kind;
  return {
    arguments: input,
    kind:
      kind === "provider_turn" || kind === "replan" || kind === "delegation" || kind === "manual"
        ? kind
        : "tool",
    idempotent: orchestration.idempotent === true,
    destructive: orchestration.destructive === true,
  };
}

function failureCategory(value: string | null): FailureCategory | null {
  return value && (FAILURE_CATEGORIES as readonly string[]).includes(value)
    ? (value as FailureCategory)
    : null;
}

function mapAction(row: ActionRow): DurableAction {
  const details = metadata(row);
  return {
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    stepId: row.step_id ?? "",
    actionType: row.action_type,
    actionClass: row.action_class,
    fingerprint: row.fingerprint,
    arguments: details.arguments,
    target: row.scoped_target ?? "",
    kind: details.kind,
    intentSummary: row.intent_summary,
    status: row.status,
    idempotent: details.idempotent,
    destructive: details.destructive,
    guidedDecisionId: row.guided_decision_id,
    contractId: row.contract_id,
    contextPackId: row.context_pack_id,
    resultSummary: row.result_summary,
    errorCategory: failureCategory(row.error_category),
    retryCount: row.retry_count,
    progressSignature: row.progress_signature,
    createdAt: row.created_at,
    startedAt: row.started_at,
    endedAt: row.ended_at,
  };
}

export class ActionRepository {
  constructor(private readonly database: SqliteDatabase) {}

  create(input: {
    intent: DurableActionIntent;
    fingerprint: string;
    guidedDecisionId?: string;
    contractId?: string;
    now: string;
  }): DurableAction {
    const actionId = `action_${randomUUID()}`;
    this.database
      .prepare(`
        INSERT INTO actions (
          id, mission_id, run_id, step_id, assignment_id, parent_action_id,
          action_type, action_class, fingerprint, normalized_arguments_json,
          scoped_target, status, intent_summary, guided_decision_id, contract_id,
          context_pack_id, trace_id, span_id, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        actionId,
        input.intent.missionId,
        input.intent.runId,
        input.intent.stepId,
        input.intent.assignmentId ?? null,
        input.intent.parentActionId ?? null,
        input.intent.actionType,
        input.intent.actionClass,
        input.fingerprint,
        canonicalJson({
          input: input.intent.arguments,
          orchestration: {
            target: input.intent.target,
            kind: input.intent.kind,
            idempotent: input.intent.idempotent,
            destructive: input.intent.destructive,
            planVersion: input.intent.planVersion,
          },
        }),
        input.intent.target,
        input.intent.intentSummary,
        input.guidedDecisionId ?? null,
        input.contractId ?? null,
        input.intent.contextPackId ?? null,
        input.intent.traceId ?? null,
        input.intent.spanId ?? null,
        input.now,
        input.now,
        input.now,
      );
    return this.get(actionId);
  }

  get(actionId: string): DurableAction {
    const row = this.database.prepare("SELECT * FROM actions WHERE id = ?").get(actionId) as ActionRow | undefined;
    if (!row) throw new DurableOrchestrationError("action_not_found", `Action not found: ${actionId}`);
    return mapAction(row);
  }

  complete(input: {
    actionId: string;
    success: boolean;
    summary: string;
    category?: FailureCategory;
    progressSignature: string;
    now: string;
  }): DurableAction {
    const status = input.success ? "succeeded" : input.category === "timeout" ? "timed_out" : "failed";
    const result = this.database
      .prepare(`
        UPDATE actions SET status = ?, result_summary = ?, error_category = ?,
          progress_signature = ?, ended_at = ?, updated_at = ?
        WHERE id = ? AND status = 'running'
      `)
      .run(
        status,
        input.summary,
        input.category ?? null,
        input.progressSignature,
        input.now,
        input.now,
        input.actionId,
      );
    if (result.changes !== 1) {
      throw new DurableOrchestrationError("action_not_running", "Only one result may complete a running action");
    }
    return this.get(input.actionId);
  }

  cancelActive(runId: string, summary: string, now: string): number {
    return this.database
      .prepare(`
        UPDATE actions SET status = 'cancelled', result_summary = ?,
          ended_at = ?, updated_at = ?
        WHERE run_id = ? AND status IN ('queued', 'running')
      `)
      .run(summary, now, now, runId).changes;
  }

  inFlight(runId: string): DurableAction[] {
    return (this.database
      .prepare("SELECT * FROM actions WHERE run_id = ? AND status IN ('queued', 'running') ORDER BY created_at, id")
      .all(runId) as ActionRow[]).map(mapAction);
  }

  completedIds(runId: string): string[] {
    return (this.database
      .prepare(`
        SELECT id FROM actions
        WHERE run_id = ? AND status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'denied')
        ORDER BY ended_at, id
      `)
      .all(runId) as Array<{ id: string }>).map((row) => row.id);
  }

  observations(runId: string, limit = 50): ActionObservation[] {
    const rows = this.database
      .prepare(`
        SELECT payload_json FROM events
        WHERE run_id = ? AND event_type = 'action.completed'
        ORDER BY sequence DESC LIMIT ?
      `)
      .all(runId, limit) as EventPayloadRow[];
    return rows.reverse().flatMap((row) => {
      const value = parseObject(row.payload_json);
      if (
        typeof value.actionId !== "string" ||
        typeof value.actionFingerprint !== "string" ||
        typeof value.meaningfulProgress !== "boolean" ||
        typeof value.progressSignatureAfter !== "string" ||
        typeof value.completedAt !== "string"
      ) return [];
      const category = typeof value.errorCategory === "string"
        ? failureCategory(value.errorCategory)
        : null;
      const kind = value.actionKind;
      return [{
        actionId: value.actionId,
        actionFingerprint: value.actionFingerprint,
        meaningfulProgress: value.meaningfulProgress,
        progressSignatureAfter: value.progressSignatureAfter,
        completedAt: value.completedAt,
        ...(category ? { errorCategory: category } : {}),
        ...(kind === "tool" || kind === "provider_turn" || kind === "replan" || kind === "delegation" || kind === "manual"
          ? { actionKind: kind }
          : {}),
        ...(typeof value.planFingerprint === "string" ? { planFingerprint: value.planFingerprint } : {}),
        ...(value.routingViolation === true ? { routingViolation: true } : {}),
      }];
    });
  }
}

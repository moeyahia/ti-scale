import type { SqliteDatabase } from "../db";
import { notFound } from "../operations/errors";
import { missionScopeSql, sensitivitySql } from "../operations/scope";
import type { OperationsAccessPolicy, OperationsPage } from "../operations/types";
import { OPERATIONS_SCHEMA_VERSION } from "../operations/types";
import {
  decodeCursor,
  encodeCursor,
  parseJson,
  sanitizeJson,
  sanitizeJsonWithRedaction,
} from "../operations/validation";
import type {
  TraceDetailProjection,
  TraceRecordKind,
  TraceRecordProjection,
  TraceStatus,
  TraceSummaryProjection,
} from "./types";

type Row = Record<string, any>;

export interface TraceListOptions {
  readonly limit: number;
  readonly cursor?: string;
  readonly missionId?: string;
  readonly runId?: string;
  readonly traceId?: string;
  readonly query?: string;
  readonly status?: TraceStatus;
  readonly from?: string;
  readonly to?: string;
}

export interface TraceDetailOptions {
  readonly limit: number;
  readonly cursor?: string;
}

function redactedJson(value: unknown, kind?: TraceRecordKind): unknown {
  const sanitized = sanitizeJson(typeof value === "string" ? parseJson(value) : value);
  if (kind !== "event" || !sanitized || typeof sanitized !== "object" || Array.isArray(sanitized)) {
    return sanitized;
  }
  const event = sanitized as Record<string, unknown>;
  return {
    ...event,
    payload: sanitizeJsonWithRedaction(event.payload, event.redaction),
  };
}

function text(value: unknown): string {
  return String(sanitizeJson(value ?? ""));
}

function durationMs(startedAt: string, endedAt: string, explicit?: unknown): number {
  if (explicit !== null && explicit !== undefined && Number.isFinite(Number(explicit))) {
    return Math.max(0, Math.round(Number(explicit)));
  }
  const elapsed = Date.parse(endedAt) - Date.parse(startedAt);
  return Number.isFinite(elapsed) ? Math.max(0, elapsed) : 0;
}

function statusFor(row: Row): TraceStatus {
  if (Number(row.error_count ?? 0) > 0) return "failed";
  if (Number(row.active_count ?? 0) > 0) return "active";
  return "completed";
}

function cursorPredicate(
  cursor: ReturnType<typeof decodeCursor>,
  timeExpression: string,
  idExpression: string,
): { readonly sql: string; readonly params: readonly unknown[] } {
  return cursor
    ? {
        sql: `(${timeExpression} < ? OR (${timeExpression} = ? AND ${idExpression} < ?))`,
        params: [cursor.sort, cursor.sort, cursor.id],
      }
    : { sql: "1", params: [] };
}

/** Scope-enforced projections over real canonical event/log/action/tool-call correlation. */
export class TraceRepository {
  constructor(private readonly database: SqliteDatabase) {}

  listTraces(
    access: OperationsAccessPolicy,
    options: TraceListOptions,
  ): OperationsPage<TraceSummaryProjection> {
    const records = this.visibleSummaryRecords(access, options);
    const cursor = decodeCursor(options.cursor);
    const outerClauses: string[] = [];
    const outerParams: unknown[] = [];
    if (options.query) {
      outerClauses.push("query_match = 1");
    }
    if (options.status) {
      outerClauses.push("trace_status = ?");
      outerParams.push(options.status);
    }
    if (cursor) {
      outerClauses.push("(last_at < ? OR (last_at = ? AND trace_id < ?))");
      outerParams.push(cursor.sort, cursor.sort, cursor.id);
    }
    const rows = this.database.prepare(`
      WITH visible_records AS (
        ${records.sql}
      ), ranked AS (
        SELECT *, row_number() OVER (
          PARTITION BY trace_id ORDER BY ended_at DESC, record_key DESC
        ) AS recency_rank
        FROM visible_records
      ), aggregated AS (
        SELECT trace_id,
          MIN(started_at) AS started_at,
          MAX(ended_at) AS last_at,
          COUNT(DISTINCT mission_id) AS mission_count,
          MIN(mission_id) AS mission_id,
          MIN(mission_name) AS mission_name,
          COUNT(DISTINCT run_id) AS run_count,
          MIN(run_id) AS run_id,
          COUNT(DISTINCT journey) AS journey_count,
          MIN(journey) AS journey,
          SUM(CASE WHEN record_kind = 'event' THEN 1 ELSE 0 END) AS event_count,
          SUM(CASE WHEN record_kind = 'log' THEN 1 ELSE 0 END) AS log_count,
          SUM(CASE WHEN record_kind = 'action' THEN 1 ELSE 0 END) AS action_count,
          SUM(CASE WHEN record_kind = 'tool_call' THEN 1 ELSE 0 END) AS tool_call_count,
          SUM(is_error) AS error_count,
          SUM(is_active) AS active_count,
          MAX(CASE WHEN recency_rank = 1 THEN semantic_summary END) AS latest_summary,
          ${options.query ? "MAX(CASE WHEN instr(lower(search_text), lower(?)) > 0 THEN 1 ELSE 0 END)" : "1"} AS query_match,
          CASE
            WHEN SUM(is_error) > 0 THEN 'failed'
            WHEN SUM(is_active) > 0 THEN 'active'
            ELSE 'completed'
          END AS trace_status
        FROM ranked
        GROUP BY trace_id
      )
      SELECT *, trace_id AS id, last_at AS sort_at
      FROM aggregated
      ${outerClauses.length ? `WHERE ${outerClauses.join(" AND ")}` : ""}
      ORDER BY last_at DESC, trace_id DESC
      LIMIT ?
    `).all(
      ...records.params,
      ...(options.query ? [options.query] : []),
      ...outerParams,
      options.limit + 1,
    ) as Row[];
    const hasMore = rows.length > options.limit;
    const visible = hasMore ? rows.slice(0, options.limit) : rows;
    const last = visible.at(-1);
    return {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      items: visible.map((row) => this.mapTraceSummary(row)),
      nextCursor: hasMore && last ? encodeCursor(last.last_at, last.trace_id) : null,
    };
  }

  getTrace(
    traceId: string,
    access: OperationsAccessPolicy,
    options: TraceDetailOptions,
  ): TraceDetailProjection {
    const trace = this.listTraces(access, { limit: 1, traceId }).items[0];
    if (!trace) throw notFound("Trace");
    return {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      trace,
      records: this.listTraceRecords(traceId, access, options),
    };
  }

  private visibleSummaryRecords(
    access: OperationsAccessPolicy,
    options: Omit<TraceListOptions, "limit" | "cursor" | "query" | "status">,
  ): { readonly sql: string; readonly params: readonly unknown[] } {
    const missionScope = missionScopeSql("m", access);
    const eventSensitivity = sensitivitySql("e.sensitivity", access);
    const logSensitivity = sensitivitySql("l.sensitivity", access);
    const eventVisibility = access.allowUnscopedSystemData
      ? `(e.mission_id IS NULL OR ${missionScope.sql})`
      : `(e.mission_id IS NOT NULL AND ${missionScope.sql})`;
    const logVisibility = access.allowUnscopedSystemData
      ? `(l.mission_id IS NULL OR ${missionScope.sql})`
      : `(l.mission_id IS NOT NULL AND ${missionScope.sql})`;
    const common = (
      alias: string,
      time: string,
      missionColumn: string,
      runColumn: string,
    ): { readonly clauses: string[]; readonly params: unknown[] } => {
      const clauses: string[] = [];
      const params: unknown[] = [];
      if (options.traceId) { clauses.push(`${alias}.trace_id = ?`); params.push(options.traceId); }
      if (options.missionId) { clauses.push(`${missionColumn} = ?`); params.push(options.missionId); }
      if (options.runId) { clauses.push(`${runColumn} = ?`); params.push(options.runId); }
      if (options.from) { clauses.push(`${time} >= ?`); params.push(options.from); }
      if (options.to) { clauses.push(`${time} <= ?`); params.push(options.to); }
      return { clauses, params };
    };
    const event = common("e", "e.occurred_at", "e.mission_id", "e.run_id");
    const log = common("l", "l.occurred_at", "l.mission_id", "l.run_id");
    const action = common("a", "coalesce(a.started_at, a.created_at)", "a.mission_id", "a.run_id");
    const tool = common("a", "coalesce(tc.started_at, tc.created_at)", "a.mission_id", "a.run_id");
    return {
      sql: `
        SELECT e.trace_id, 'event:' || e.id AS record_key, 'event' AS record_kind,
          e.occurred_at AS started_at, e.occurred_at AS ended_at,
          e.mission_id, m.name AS mission_name, e.run_id, e.journey,
          e.summary AS semantic_summary,
          e.trace_id || ' ' || e.event_type || ' ' || e.summary AS search_text,
          CASE WHEN lower(e.event_type) LIKE '%failed%' OR lower(e.event_type) LIKE '%error%' OR lower(e.event_type) LIKE '%denied%' THEN 1 ELSE 0 END AS is_error,
          0 AS is_active
        FROM events e LEFT JOIN missions m ON m.id = e.mission_id
        WHERE e.trace_id IS NOT NULL AND ${eventVisibility} AND ${eventSensitivity.sql}
          ${event.clauses.length ? `AND ${event.clauses.join(" AND ")}` : ""}
        UNION ALL
        SELECT l.trace_id, 'log:' || l.id, 'log', l.occurred_at, l.occurred_at,
          l.mission_id, m.name, l.run_id, r.journey, l.message,
          l.trace_id || ' ' || l.domain || ' ' || l.severity || ' ' || l.message,
          CASE WHEN l.severity IN ('error', 'fatal') THEN 1 ELSE 0 END, 0
        FROM structured_logs l
        LEFT JOIN missions m ON m.id = l.mission_id
        LEFT JOIN runs r ON r.id = l.run_id
        WHERE l.trace_id IS NOT NULL AND ${logVisibility} AND ${logSensitivity.sql}
          ${log.clauses.length ? `AND ${log.clauses.join(" AND ")}` : ""}
        UNION ALL
        SELECT a.trace_id, 'action:' || a.id, 'action',
          coalesce(a.started_at, a.created_at), coalesce(a.ended_at, a.updated_at),
          a.mission_id, m.name, a.run_id, r.journey,
          coalesce(a.result_summary, a.intent_summary),
          a.trace_id || ' ' || a.action_type || ' ' || a.action_class || ' ' || a.intent_summary || ' ' || coalesce(a.result_summary, ''),
          CASE WHEN a.status IN ('failed', 'timed_out', 'denied') THEN 1 ELSE 0 END,
          CASE WHEN a.status IN ('queued', 'running') THEN 1 ELSE 0 END
        FROM actions a JOIN missions m ON m.id = a.mission_id JOIN runs r ON r.id = a.run_id
        WHERE a.trace_id IS NOT NULL AND ${missionScope.sql}
          ${action.clauses.length ? `AND ${action.clauses.join(" AND ")}` : ""}
        UNION ALL
        SELECT a.trace_id, 'tool_call:' || tc.id, 'tool_call',
          coalesce(tc.started_at, tc.created_at), coalesce(tc.ended_at, tc.started_at, tc.created_at),
          a.mission_id, m.name, a.run_id, r.journey,
          coalesce(tc.output_summary, tc.provider || ' / ' || tc.tool_name),
          a.trace_id || ' ' || tc.provider || ' ' || tc.tool_name || ' ' || coalesce(tc.output_summary, ''),
          CASE WHEN tc.status IN ('failed', 'timed_out', 'denied') THEN 1 ELSE 0 END,
          CASE WHEN tc.status IN ('queued', 'running') THEN 1 ELSE 0 END
        FROM tool_calls tc JOIN actions a ON a.id = tc.action_id
        JOIN missions m ON m.id = a.mission_id JOIN runs r ON r.id = a.run_id
        WHERE a.trace_id IS NOT NULL AND ${missionScope.sql}
          ${tool.clauses.length ? `AND ${tool.clauses.join(" AND ")}` : ""}
      `,
      params: [
        ...missionScope.params, ...eventSensitivity.params, ...event.params,
        ...missionScope.params, ...logSensitivity.params, ...log.params,
        ...missionScope.params, ...action.params,
        ...missionScope.params, ...tool.params,
      ],
    };
  }

  private listTraceRecords(
    traceId: string,
    access: OperationsAccessPolicy,
    options: TraceDetailOptions,
  ): OperationsPage<TraceRecordProjection> {
    const cursor = decodeCursor(options.cursor);
    const missionScope = missionScopeSql("m", access);
    const eventSensitivity = sensitivitySql("e.sensitivity", access);
    const logSensitivity = sensitivitySql("l.sensitivity", access);
    const eventVisibility = access.allowUnscopedSystemData
      ? `(e.mission_id IS NULL OR ${missionScope.sql})`
      : `(e.mission_id IS NOT NULL AND ${missionScope.sql})`;
    const logVisibility = access.allowUnscopedSystemData
      ? `(l.mission_id IS NULL OR ${missionScope.sql})`
      : `(l.mission_id IS NOT NULL AND ${missionScope.sql})`;
    const eventCursor = cursorPredicate(cursor, "e.occurred_at", "'event:' || e.id");
    const logCursor = cursorPredicate(cursor, "l.occurred_at", "'log:' || l.id");
    const actionCursor = cursorPredicate(cursor, "coalesce(a.started_at, a.created_at)", "'action:' || a.id");
    const toolCursor = cursorPredicate(cursor, "coalesce(tc.started_at, tc.created_at)", "'tool_call:' || tc.id");
    const perSourceLimit = options.limit + 1;

    // Each source query is independently capped before merging. At most
    // 4 * (limit + 1) rows enter application memory, even for a 100k-event trace.
    const events = this.database.prepare(`
      SELECT 'event:' || e.id AS record_key, e.id AS source_id, 'event' AS kind,
        e.event_type AS title, e.summary, 'observed' AS status,
        e.mission_id, m.name AS mission_name, e.run_id, NULL AS step_id,
        NULL AS action_id, CASE WHEN e.actor_type = 'agent' THEN e.actor_id END AS agent_id,
        e.occurred_at AS started_at, e.occurred_at AS ended_at, 0 AS duration_ms,
        e.trace_id, e.span_id, NULL AS parent_span_id,
        json_object('eventType', e.event_type, 'sequence', e.sequence,
          'actor', json_object('type', e.actor_type, 'id', e.actor_id),
          'payload', json(e.payload_json), 'redaction', json(e.redaction_json),
          'schemaVersion', e.schema_version, 'contextPackId', e.context_pack_id) AS raw_json
      FROM events e LEFT JOIN missions m ON m.id = e.mission_id
      WHERE e.trace_id = ? AND ${eventVisibility} AND ${eventSensitivity.sql} AND ${eventCursor.sql}
      ORDER BY e.occurred_at DESC, record_key DESC LIMIT ?
    `).all(traceId, ...missionScope.params, ...eventSensitivity.params, ...eventCursor.params, perSourceLimit) as Row[];
    const logs = this.database.prepare(`
      SELECT 'log:' || l.id AS record_key, l.id AS source_id, 'log' AS kind,
        l.domain AS title, l.message AS summary, l.severity AS status,
        l.mission_id, m.name AS mission_name, l.run_id, l.step_id, l.action_id,
        NULL AS agent_id, l.occurred_at AS started_at, l.occurred_at AS ended_at,
        0 AS duration_ms, l.trace_id, l.span_id, NULL AS parent_span_id,
        json_object('severity', l.severity, 'domain', l.domain,
          'attributes', json(l.attributes_json), 'sensitivity', l.sensitivity) AS raw_json
      FROM structured_logs l LEFT JOIN missions m ON m.id = l.mission_id
      WHERE l.trace_id = ? AND ${logVisibility} AND ${logSensitivity.sql} AND ${logCursor.sql}
      ORDER BY l.occurred_at DESC, record_key DESC LIMIT ?
    `).all(traceId, ...missionScope.params, ...logSensitivity.params, ...logCursor.params, perSourceLimit) as Row[];
    const actions = this.database.prepare(`
      SELECT 'action:' || a.id AS record_key, a.id AS source_id, 'action' AS kind,
        a.action_type AS title, coalesce(a.result_summary, a.intent_summary) AS summary,
        a.status, a.mission_id, m.name AS mission_name, a.run_id, a.step_id, a.id AS action_id,
        coalesce(ass.agent_id, ps.assigned_agent_id) AS agent_id,
        coalesce(a.started_at, a.created_at) AS started_at,
        coalesce(a.ended_at, a.updated_at) AS ended_at,
        (julianday(coalesce(a.ended_at, a.updated_at)) - julianday(coalesce(a.started_at, a.created_at))) * 86400000 AS duration_ms,
        a.trace_id, a.span_id, parent.span_id AS parent_span_id,
        json_object('actionType', a.action_type, 'actionClass', a.action_class,
          'target', a.scoped_target, 'status', a.status,
          'intentSummary', a.intent_summary, 'resultSummary', a.result_summary,
          'errorCategory', a.error_category, 'retryCount', a.retry_count,
          'guidedDecisionId', a.guided_decision_id, 'contractId', a.contract_id,
          'contextPackId', a.context_pack_id) AS raw_json
      FROM actions a JOIN missions m ON m.id = a.mission_id
      LEFT JOIN assignments ass ON ass.id = a.assignment_id
      LEFT JOIN plan_steps ps ON ps.id = a.step_id
      LEFT JOIN actions parent ON parent.id = a.parent_action_id
        AND parent.mission_id = a.mission_id AND parent.run_id = a.run_id
      WHERE a.trace_id = ? AND ${missionScope.sql} AND ${actionCursor.sql}
      ORDER BY started_at DESC, record_key DESC LIMIT ?
    `).all(traceId, ...missionScope.params, ...actionCursor.params, perSourceLimit) as Row[];
    const tools = this.database.prepare(`
      SELECT 'tool_call:' || tc.id AS record_key, tc.id AS source_id, 'tool_call' AS kind,
        tc.provider || ' / ' || tc.tool_name AS title,
        coalesce(tc.output_summary, 'Tool call completed without a semantic output summary') AS summary,
        tc.status, a.mission_id, m.name AS mission_name, a.run_id, a.step_id, a.id AS action_id,
        coalesce(ass.agent_id, ps.assigned_agent_id) AS agent_id,
        coalesce(tc.started_at, tc.created_at) AS started_at,
        coalesce(tc.ended_at, tc.started_at, tc.created_at) AS ended_at,
        tc.latency_ms AS duration_ms, a.trace_id, a.span_id,
        parent.span_id AS parent_span_id,
        json_object('provider', tc.provider, 'toolName', tc.tool_name,
          'mcpServerId', tc.mcp_server_id, 'status', tc.status,
          'errorCategory', tc.error_category, 'latencyMs', tc.latency_ms,
          'outputSummary', tc.output_summary,
          'redactedPayload', CASE WHEN tc.redacted_payload_json IS NULL THEN NULL ELSE json(tc.redacted_payload_json) END) AS raw_json
      FROM tool_calls tc JOIN actions a ON a.id = tc.action_id
      JOIN missions m ON m.id = a.mission_id
      LEFT JOIN assignments ass ON ass.id = a.assignment_id
      LEFT JOIN plan_steps ps ON ps.id = a.step_id
      LEFT JOIN actions parent ON parent.id = a.parent_action_id
        AND parent.mission_id = a.mission_id AND parent.run_id = a.run_id
      WHERE a.trace_id = ? AND ${missionScope.sql} AND ${toolCursor.sql}
      ORDER BY started_at DESC, record_key DESC LIMIT ?
    `).all(traceId, ...missionScope.params, ...toolCursor.params, perSourceLimit) as Row[];

    const merged = [...events, ...logs, ...actions, ...tools]
      .sort((left, right) => right.started_at.localeCompare(left.started_at) || right.record_key.localeCompare(left.record_key));
    const hasMore = merged.length > options.limit;
    const visible = hasMore ? merged.slice(0, options.limit) : merged;
    const last = visible.at(-1);
    return {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      items: visible.map((row) => this.mapTraceRecord(row)),
      nextCursor: hasMore && last ? encodeCursor(last.started_at, last.record_key) : null,
    };
  }

  private mapTraceSummary(row: Row): TraceSummaryProjection {
    const startedAt = String(row.started_at);
    const endedAt = String(row.last_at);
    const missionCount = Number(row.mission_count ?? 0);
    const runCount = Number(row.run_count ?? 0);
    const recordCount = Number(row.event_count ?? 0) + Number(row.log_count ?? 0)
      + Number(row.action_count ?? 0) + Number(row.tool_call_count ?? 0);
    const latest = text(row.latest_summary);
    return {
      id: row.trace_id,
      traceId: row.trace_id,
      status: statusFor(row),
      summary: latest || `${recordCount} correlated operational records`,
      mission: missionCount === 1 && row.mission_id
        ? { id: row.mission_id, name: row.mission_name ?? row.mission_id }
        : null,
      missionCount,
      runId: runCount === 1 ? row.run_id : null,
      runCount,
      journey: Number(row.journey_count ?? 0) === 1 ? row.journey : null,
      startedAt,
      endedAt,
      durationMs: durationMs(startedAt, endedAt),
      counts: {
        events: Number(row.event_count ?? 0),
        logs: Number(row.log_count ?? 0),
        actions: Number(row.action_count ?? 0),
        toolCalls: Number(row.tool_call_count ?? 0),
        errors: Number(row.error_count ?? 0),
      },
    };
  }

  private mapTraceRecord(row: Row): TraceRecordProjection {
    const startedAt = String(row.started_at);
    const endedAt = String(row.ended_at ?? row.started_at);
    return {
      id: row.record_key,
      sourceId: row.source_id,
      kind: row.kind as TraceRecordKind,
      title: text(row.title),
      summary: text(row.summary),
      status: String(row.status),
      mission: row.mission_id ? { id: row.mission_id, name: row.mission_name ?? row.mission_id } : null,
      runId: row.run_id,
      stepId: row.step_id,
      actionId: row.action_id,
      agentId: row.agent_id,
      startedAt,
      endedAt,
      durationMs: durationMs(startedAt, endedAt, row.duration_ms),
      correlation: {
        traceId: row.trace_id,
        spanId: row.span_id,
        parentSpanId: row.parent_span_id,
      },
      raw: redactedJson(row.raw_json, row.kind as TraceRecordKind),
    };
  }
}

import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { conflict, forbidden, notFound } from "./errors";
import { lessonScopeSql, missionScopeSql, sensitivitySql } from "./scope";
import type {
  ActionProjection,
  AgentProjection,
  ArtifactProjection,
  AssignmentProjection,
  EvaluationBudgetMetricProjection,
  EvaluationProjection,
  EvaluationComparisonProjection,
  EventProjection,
  EvidenceProjection,
  FindingProjection,
  HealthProjection,
  LessonProjection,
  LessonUsageProjection,
  LogProjection,
  McpProjection,
  OperationsActor,
  OperationsAccessPolicy,
  OperationsPage,
  PolicyProjection,
  ProviderProjection,
  RunCompletionExport,
} from "./types";
import { OPERATIONS_SCHEMA_VERSION } from "./types";
import { AttackChainLessonRepository } from "../learning";
import { evidenceRecordSql, verifiedEvidenceSql } from "../domain/evidence-semantics";
import {
  canonicalJson,
  decodeCursor,
  encodeCursor,
  ftsQuery,
  isSensitiveSettingKey,
  parseJson,
  sanitizeJson,
  sanitizeJsonWithRedaction,
  sha256,
  type CursorValue,
} from "./validation";

export interface PageOptions {
  readonly limit: number;
  readonly cursor?: string;
}

export interface AgentPageOptions extends PageOptions {
  readonly status?: string;
  readonly query?: string;
  readonly includeInternal?: boolean;
}

interface DatedRow {
  readonly id: string;
  readonly sort_at: string;
}

type Row = Record<string, any>;

function page<T>(
  rows: readonly Row[],
  limit: number,
  map: (row: Row) => T,
): OperationsPage<T> {
  const hasMore = rows.length > limit;
  const visible = hasMore ? rows.slice(0, limit) : rows;
  const last = visible.at(-1) as DatedRow | undefined;
  return {
    schemaVersion: OPERATIONS_SCHEMA_VERSION,
    items: visible.map(map),
    nextCursor: hasMore && last ? encodeCursor(last.sort_at, last.id) : null,
  };
}

function cursorClause(cursor: CursorValue | undefined, column: string, idColumn: string): {
  readonly sql: string;
  readonly params: readonly unknown[];
} {
  return cursor
    ? { sql: `(${column} < ? OR (${column} = ? AND ${idColumn} < ?))`, params: [cursor.sort, cursor.sort, cursor.id] }
    : { sql: "1", params: [] };
}

function json(value: unknown): unknown {
  return sanitizeJson(typeof value === "string" ? parseJson(value) : value);
}

const OPERATIONAL_LOG_EVIDENCE_TYPE = "command_output";

function evidenceRecordClass(row: Row): EvidenceProjection["recordClass"] {
  const evidenceType = String(row.evidence_type).trim().toLocaleLowerCase("en-US");
  const unreviewedMcpToolResult = String(row.source).trim().toLocaleLowerCase("en-US").startsWith("mcp:")
    && evidenceType === "tool_result"
    && Number(row.has_verification_custody ?? 0) === 0;
  return evidenceType === OPERATIONAL_LOG_EVIDENCE_TYPE || unreviewedMcpToolResult
    ? "operational_log"
    : "evidence";
}

const FILE_LOCATION = /\bfile:\/\/[^\s,;)'"<>]+/giu;
const POSIX_LOCATION = /(^|[\s'"(])\/(?:[^/\s'"()]+\/)*[^/\s'"()]+/gu;
const WINDOWS_LOCATION = /\b[A-Za-z]:\\(?:[^\\\s'"()]+\\)*[^\\\s'"()]+/gu;
const TRAVERSAL_LOCATION = /(^|[\s'"(])(?:\.\.[\\/])+(?:[^\s'"()]+[\\/]?)+/gu;

/** Preserve semantic metadata while never projecting producer-supplied filesystem locations. */
function artifactMetadata(
  value: unknown,
  artifactId: string,
  depth = 0,
  property?: string,
): unknown {
  const sanitized = depth === 0 ? json(value) : value;
  if (depth > 8) return "[REDACTED: depth limit]";
  if (typeof sanitized === "string") {
    const canonicalDownloadUrl = `/api/v2/reports/${encodeURIComponent(artifactId)}/download`;
    if (property === "downloadUrl" && sanitized === canonicalDownloadUrl) return sanitized;
    return sanitized
      .replace(FILE_LOCATION, "[REDACTED LOCATION]")
      .replace(POSIX_LOCATION, "$1[REDACTED LOCATION]")
      .replace(WINDOWS_LOCATION, "[REDACTED LOCATION]")
      .replace(TRAVERSAL_LOCATION, "$1[REDACTED LOCATION]");
  }
  if (Array.isArray(sanitized)) {
    return sanitized.map((item) => artifactMetadata(item, artifactId, depth + 1));
  }
  if (sanitized && typeof sanitized === "object") {
    return Object.fromEntries(Object.entries(sanitized as Record<string, unknown>)
      .map(([key, item]) => [key, artifactMetadata(item, artifactId, depth + 1, key)]));
  }
  return sanitized;
}

function storageProjection(uri: string): { readonly scheme: string; readonly available: boolean } {
  const scheme = /^([a-z][a-z0-9+.-]*):/iu.exec(uri)?.[1]?.toLocaleLowerCase("en-US") ?? "file";
  return { scheme, available: Boolean(uri) };
}

function rounded(value: unknown, digits = 2): number | null {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return null;
  const multiplier = 10 ** digits;
  return Math.round(Number(value) * multiplier) / multiplier;
}

function objectValue(value: unknown): Record<string, unknown> {
  const parsed = typeof value === "string" ? parseJson(value) : value;
  return parsed && typeof parsed === "object" && !Array.isArray(parsed)
    ? parsed as Record<string, unknown>
    : {};
}

function nonNegativeNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function firstNumber(source: Record<string, unknown>, keys: readonly string[]): number | null {
  for (const key of keys) {
    const value = nonNegativeNumber(source[key]);
    if (value !== null) return value;
  }
  return null;
}

function measuredDuration(row: Row, metrics: Record<string, unknown>, usage: Record<string, unknown>): {
  readonly value: number | null;
  readonly source: EvaluationBudgetMetricProjection["usageSource"];
} {
  const terminalUsage = nonNegativeNumber(usage.wallClockMs);
  if (terminalUsage !== null) return { value: terminalUsage, source: "terminal_run" };
  const evaluated = nonNegativeNumber(metrics.durationMs);
  if (evaluated !== null) return { value: evaluated, source: "run_evaluation" };
  const started = typeof row.run_started_at === "string" ? Date.parse(row.run_started_at) : Number.NaN;
  const ended = typeof row.run_ended_at === "string" ? Date.parse(row.run_ended_at) : Number.NaN;
  return Number.isFinite(started) && Number.isFinite(ended) && ended >= started
    ? { value: ended - started, source: "terminal_run" }
    : { value: null, source: null };
}

function budgetMetric(input: {
  readonly key: EvaluationBudgetMetricProjection["key"];
  readonly label: string;
  readonly unit: EvaluationBudgetMetricProjection["unit"];
  readonly limit: number | null;
  readonly usage: number | null;
  readonly usageStatus: EvaluationBudgetMetricProjection["usageStatus"];
  readonly usageSource: EvaluationBudgetMetricProjection["usageSource"];
}): EvaluationBudgetMetricProjection {
  const status: EvaluationBudgetMetricProjection["status"] = input.usage === null
    ? "unknown_usage"
    : input.limit === null
      ? "not_configured"
      : input.usage > input.limit
        ? "limit_exceeded"
        : input.usage === input.limit
          ? "limit_reached"
          : "within_limit";
  return {
    ...input,
    limitStatus: input.limit === null ? "not_configured" : "configured",
    limitSource: input.limit === null ? null : "terminal_run_budget",
    status,
  };
}

function evaluationBudget(row: Row): { readonly metrics: readonly EvaluationBudgetMetricProjection[] } {
  const limits = objectValue(row.budget_json);
  const usage = objectValue(row.budget_usage_json);
  const metrics = objectValue(row.metrics_json);
  const wallClockLimit = firstNumber(limits, ["wallClockMs"])
    ?? (firstNumber(limits, ["timeBudgetMinutes"]) !== null
      ? firstNumber(limits, ["timeBudgetMinutes"])! * 60_000
      : null);
  const duration = measuredDuration(row, metrics, usage);

  const providerTurnCount = Math.max(0, Number(row.provider_turn_count ?? 0));
  const tokenCompleteCount = Math.max(0, Number(row.provider_token_complete_count ?? 0));
  const costCompleteCount = Math.max(0, Number(row.provider_cost_complete_count ?? 0));
  const evaluatedProviderTurnCount = nonNegativeNumber(metrics.providerTurnCount);
  const explicitTokens = nonNegativeNumber(usage.providerTokens);
  const exactTokens = explicitTokens !== null
    ? explicitTokens
    : providerTurnCount > 0 && tokenCompleteCount === providerTurnCount
      ? Number(row.provider_token_sum ?? 0)
      : providerTurnCount === 0 && evaluatedProviderTurnCount === 0
        ? 0
      : null;
  const explicitCost = nonNegativeNumber(usage.estimatedCost);
  const recordedCost = explicitCost !== null
    ? explicitCost
    : providerTurnCount > 0 && costCompleteCount === providerTurnCount
      ? Number(row.provider_cost_sum ?? 0)
      : providerTurnCount === 0 && evaluatedProviderTurnCount === 0
        ? 0
      : null;

  const measured = (
    usageKey: string,
    metricKey: string,
    fallback: number,
  ): { readonly value: number; readonly source: EvaluationBudgetMetricProjection["usageSource"] } => {
    const terminal = nonNegativeNumber(usage[usageKey]);
    if (terminal !== null) return { value: terminal, source: "terminal_run" };
    const evaluated = nonNegativeNumber(metrics[metricKey]);
    if (evaluated !== null) return { value: evaluated, source: "run_evaluation" };
    return { value: Math.max(0, fallback), source: "canonical_records" };
  };
  const toolCalls = measured("toolCalls", "toolCallCount", Number(row.tool_call_count ?? 0));
  const retries = measured(
    "retries",
    "retryCount",
    Number(row.run_retry_count ?? 0) + Number(row.action_retry_count ?? 0),
  );
  const replans = measured("replans", "replanCount", Number(row.run_replan_count ?? 0));

  return { metrics: [
    budgetMetric({ key: "wallClockMs", label: "Wall-clock time", unit: "milliseconds", limit: wallClockLimit, usage: duration.value, usageStatus: duration.value === null ? "unknown" : "recorded_exact", usageSource: duration.source }),
    budgetMetric({ key: "providerTokens", label: "Provider tokens", unit: "count", limit: firstNumber(limits, ["providerTokens", "tokenBudget"]), usage: exactTokens, usageStatus: exactTokens === null ? "unknown" : "recorded_exact", usageSource: exactTokens === null ? null : explicitTokens === null ? "canonical_records" : "terminal_run" }),
    budgetMetric({ key: "estimatedCost", label: "Estimated cost", unit: "cost", limit: firstNumber(limits, ["estimatedCost", "costBudget"]), usage: recordedCost, usageStatus: recordedCost === null ? "unknown" : "recorded_estimate", usageSource: recordedCost === null ? null : explicitCost === null ? "canonical_records" : "terminal_run" }),
    budgetMetric({ key: "toolCalls", label: "Tool calls", unit: "count", limit: firstNumber(limits, ["toolCalls"]), usage: toolCalls.value, usageStatus: "recorded_exact", usageSource: toolCalls.source }),
    budgetMetric({ key: "retries", label: "Retries", unit: "count", limit: firstNumber(limits, ["retries", "retryBudget"]), usage: retries.value, usageStatus: "recorded_exact", usageSource: retries.source }),
    budgetMetric({ key: "replans", label: "Replans", unit: "count", limit: firstNumber(limits, ["replans", "replanBudget"]), usage: replans.value, usageStatus: "recorded_exact", usageSource: replans.source }),
  ] };
}

function collectPages<T>(
  load: (cursor?: string) => OperationsPage<T>,
  maximum = 1_000,
): { readonly items: readonly T[]; readonly truncated: boolean } {
  const items: T[] = [];
  let cursor: string | undefined;
  do {
    const result = load(cursor);
    const remaining = maximum - items.length;
    items.push(...result.items.slice(0, remaining));
    if (!result.nextCursor) return { items, truncated: false };
    if (items.length >= maximum) return { items, truncated: true };
    cursor = result.nextCursor;
  } while (cursor);
  return { items, truncated: false };
}

function agentConfiguration(row: Row): Record<string, unknown> {
  return objectValue(row.configuration_json);
}

function isUserFacingAgent(row: Row): boolean {
  const value = agentConfiguration(row).userFacing;
  // Compatibility for records created before the standalone roster marker.
  // RuntimeProjectionService explicitly marks every current/stale adapter,
  // so production never relies on this fallback to classify components.
  return value === undefined || value === true;
}

function agentRuntimeBindingIds(row: Row): readonly string[] {
  const configuration = agentConfiguration(row);
  const configured = Array.isArray(configuration.runtimeBindingAgentIds)
    ? configuration.runtimeBindingAgentIds.filter(
        (value): value is string => typeof value === "string" && value.length > 0,
      )
    : [];
  return [...new Set([String(row.id), ...configured])];
}

function publicProductAgentConfiguration(
  configuration: Record<string, unknown>,
): Record<string, unknown> {
  if (configuration.productAgent !== true) return configuration;
  const {
    runtimeBindingAgentIds,
    runtimeBindingVersions,
    ...publicConfiguration
  } = configuration;
  const bindingIds = Array.isArray(runtimeBindingAgentIds)
    ? runtimeBindingAgentIds.filter(
        (value): value is string => typeof value === "string" && value.length > 0,
      )
    : [];
  const versionById = new Map(
    Array.isArray(runtimeBindingVersions)
      ? runtimeBindingVersions.flatMap((value) => {
          const item = objectValue(value);
          return typeof item.id === "string" && typeof item.version === "string"
            ? [[item.id, item.version] as const]
            : [];
        })
      : [],
  );
  const runtimeBindings = bindingIds.map((id) => ({
    id,
    version: versionById.get(id) ?? null,
  }));
  return {
    ...publicConfiguration,
    runtimeBindings,
    runtimeBindingCount: runtimeBindings.length,
    runtimeBindingsVersioned: runtimeBindings.every(({ version }) => version !== null),
  };
}

function publicProductAgentPolicy(
  value: unknown,
  productAgent: boolean,
): unknown {
  const policy = objectValue(json(value));
  if (!productAgent) return policy;
  const bindings = Array.isArray(policy.runtimeBindings)
    ? policy.runtimeBindings
    : [];
  return {
    ...policy,
    runtimeBindings: bindings.map((binding) => {
      const item = objectValue(binding);
      return {
        ...(typeof item.agentId === "string" ? { agentId: item.agentId } : {}),
        ...("policy" in item ? { policy: item.policy } : {}),
      };
    }),
    runtimeBindingCount: bindings.length,
  };
}

function assertInternalAgentAccess(
  access: OperationsAccessPolicy,
  includeInternal: boolean,
): void {
  if (includeInternal && !access.allowUnscopedSystemData) {
    throw forbidden("Internal runtime components are not available in this access scope.");
  }
}

/** Read-only, scope-enforcing projections over the canonical V2 schema. */
export class OperationsRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  listAgents(
    access: OperationsAccessPolicy,
    options: AgentPageOptions,
  ): OperationsPage<AgentProjection> {
    assertInternalAgentAccess(access, options.includeInternal === true);
    const cursor = decodeCursor(options.cursor);
    const cursorPart = cursorClause(cursor, "a.updated_at", "a.id");
    const rows = this.database.prepare(`
      SELECT a.*, a.updated_at AS sort_at
      FROM agents a
      WHERE ${cursorPart.sql}
        ${options.includeInternal ? "" : "AND COALESCE(json_extract(a.configuration_json, '$.userFacing'), 1) = 1"}
        ${options.status ? "AND a.status = ?" : ""}
        ${options.query ? "AND instr(lower(a.id || ' ' || a.display_name || ' ' || a.role || ' ' || a.status), lower(?)) > 0" : ""}
      ORDER BY a.updated_at DESC, a.id DESC
      LIMIT ?
    `).all(
      ...cursorPart.params,
      ...(options.status ? [options.status] : []),
      ...(options.query ? [options.query] : []),
      options.limit + 1,
    ) as Row[];
    return page(rows, options.limit, (row) => this.mapAgent(row, access));
  }

  getAgent(
    agentId: string,
    access: OperationsAccessPolicy,
    options: Readonly<{ readonly includeInternal?: boolean }> = {},
  ): Record<string, unknown> {
    assertInternalAgentAccess(access, options.includeInternal === true);
    const row = this.database.prepare("SELECT *, updated_at AS sort_at FROM agents WHERE id = ?").get(agentId) as Row | undefined;
    if (!row || (!options.includeInternal && !isUserFacingAgent(row))) throw notFound("Agent");
    const agent = this.mapAgent(row, access);
    const capabilities = this.database.prepare(`
      SELECT capability, source, enabled, metadata_json
      FROM agent_capabilities WHERE agent_id = ?
      ORDER BY enabled DESC, capability, source
    `).all(agentId) as Row[];
    const recentHealth = this.database.prepare(`
      SELECT id, status, metrics_json, message, captured_at
      FROM health_snapshots
      WHERE component_type = 'agent' AND component_id = ?
      ORDER BY captured_at DESC, id DESC LIMIT 20
    `).all(agentId) as Row[];
    return {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      ...agent,
      capabilities: capabilities.map((item) => ({
        name: item.capability,
        source: item.source,
        enabled: Boolean(item.enabled),
        metadata: json(item.metadata_json),
      })),
      healthHistory: recentHealth.map((item) => ({
        id: item.id,
        status: item.status,
        metrics: json(item.metrics_json),
        message: item.message ? sanitizeJson(item.message) : null,
        capturedAt: item.captured_at,
      })),
    };
  }

  listAgentAssignments(
    agentId: string,
    access: OperationsAccessPolicy,
    options: PageOptions & { readonly status?: string; readonly includeInternal?: boolean },
  ): OperationsPage<AssignmentProjection> {
    assertInternalAgentAccess(access, options.includeInternal === true);
    const agent = this.database.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as Row | undefined;
    if (!agent || (!options.includeInternal && !isUserFacingAgent(agent))) throw notFound("Agent");
    const bindingIds = agentRuntimeBindingIds(agent);
    const scope = missionScopeSql("m", access);
    const cursor = decodeCursor(options.cursor);
    const cursorPart = cursorClause(cursor, "a.updated_at", "a.id");
    const rows = this.database.prepare(`
      SELECT a.id, a.status, a.lease_owner, a.lease_acquired_at,
        a.last_heartbeat_at, a.lease_expires_at, a.started_at, a.ended_at,
        a.created_at, a.updated_at, a.updated_at AS sort_at,
        r.id AS run_id, r.status AS run_status, r.journey, r.progress,
        m.id AS mission_id, m.name AS mission_name, m.engagement_id,
        ps.id AS step_id, ps.phase, ps.title AS step_title
      FROM assignments a
      JOIN runs r ON r.id = a.run_id
      JOIN missions m ON m.id = r.mission_id
      LEFT JOIN plan_steps ps ON ps.id = a.step_id
      WHERE a.agent_id IN (${bindingIds.map(() => "?").join(",")})
        AND ${scope.sql} AND ${cursorPart.sql}
        ${options.status ? "AND a.status = ?" : ""}
      ORDER BY a.updated_at DESC, a.id DESC
      LIMIT ?
    `).all(...bindingIds, ...scope.params, ...cursorPart.params, ...(options.status ? [options.status] : []), options.limit + 1) as Row[];
    const now = this.clock().getTime();
    return page(rows, options.limit, (row) => ({
      id: row.id,
      status: row.status,
      mission: { id: row.mission_id, name: row.mission_name, engagementId: row.engagement_id },
      run: { id: row.run_id, status: row.run_status, journey: row.journey, progress: rounded(row.progress, 4) },
      step: row.step_id ? { id: row.step_id, phase: row.phase, title: row.step_title } : null,
      lease: {
        owner: row.lease_owner,
        acquiredAt: row.lease_acquired_at,
        lastHeartbeatAt: row.last_heartbeat_at,
        expiresAt: row.lease_expires_at,
        expired: Boolean(row.lease_expires_at && Date.parse(row.lease_expires_at) <= now),
      },
      startedAt: row.started_at,
      endedAt: row.ended_at,
      updatedAt: row.updated_at,
    }));
  }

  private mapAgent(row: Row, access: OperationsAccessPolicy): AgentProjection {
    const bindingIds = agentRuntimeBindingIds(row);
    const scope = missionScopeSql("m", access);
    const metrics = this.database.prepare(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN a.status IN ('queued', 'active', 'blocked') THEN 1 ELSE 0 END) AS queue_depth,
        SUM(CASE WHEN a.status = 'active' THEN 1 ELSE 0 END) AS active,
        SUM(CASE WHEN a.status = 'completed' THEN 1 ELSE 0 END) AS completed,
        SUM(CASE WHEN a.status = 'failed' THEN 1 ELSE 0 END) AS failed,
        AVG(CASE WHEN a.ended_at IS NOT NULL AND a.started_at IS NOT NULL
          THEN (julianday(a.ended_at) - julianday(a.started_at)) * 86400 END) AS mean_completion_seconds,
        MAX(a.updated_at) AS last_assignment_at
      FROM assignments a
      JOIN runs r ON r.id = a.run_id
      JOIN missions m ON m.id = r.mission_id
      WHERE a.agent_id IN (${bindingIds.map(() => "?").join(",")}) AND ${scope.sql}
    `).get(...bindingIds, ...scope.params) as Row;
    const decided = Number(metrics.completed ?? 0) + Number(metrics.failed ?? 0);
    const health = this.database.prepare(`
      SELECT status, message, metrics_json, captured_at
      FROM health_snapshots WHERE component_type = 'agent' AND component_id = ?
      ORDER BY captured_at DESC, id DESC LIMIT 1
    `).get(row.id) as Row | undefined;
    const configuration = agentConfiguration(row);
    const productAgent = configuration.productAgent === true;
    const productHealth = configuration.productAgent === true
      ? {
          status: row.status === "available" || row.status === "busy"
            ? "healthy"
            : row.status === "degraded"
              ? "degraded"
              : "unhealthy",
          message: row.status === "available" || row.status === "busy"
            ? `${row.display_name} has at least one current runtime binding.`
            : `${row.display_name} has no currently available runtime binding.`,
          metrics: {
            runtimeBindingCount: Math.max(0, bindingIds.length - 1),
            ...(configuration.readiness && typeof configuration.readiness === "object"
              ? configuration.readiness as Record<string, unknown>
              : {}),
          },
          capturedAt: row.updated_at,
        }
      : null;
    return {
      id: row.id,
      role: row.role,
      displayName: row.display_name,
      status: row.status,
      version: row.version,
      lastHeartbeatAt: row.last_heartbeat_at,
      updatedAt: row.updated_at,
      providerPolicy: publicProductAgentPolicy(row.provider_policy_json, productAgent),
      toolPolicy: publicProductAgentPolicy(row.tool_policy_json, productAgent),
      configuration: publicProductAgentConfiguration(objectValue(json(row.configuration_json))),
      assignmentHealth: {
        queueDepth: Number(metrics.queue_depth ?? 0),
        active: Number(metrics.active ?? 0),
        completed: Number(metrics.completed ?? 0),
        failed: Number(metrics.failed ?? 0),
        successRate: decided > 0 ? rounded(Number(metrics.completed ?? 0) / decided, 4) : null,
        meanCompletionSeconds: rounded(metrics.mean_completion_seconds),
        lastAssignmentAt: metrics.last_assignment_at,
      },
      health: health ? {
        status: health.status,
        message: health.message ? sanitizeJson(health.message) : null,
        metrics: json(health.metrics_json),
        capturedAt: health.captured_at,
      } : productHealth,
    };
  }

  listEvidence(
    access: OperationsAccessPolicy,
    options: PageOptions & {
      readonly missionId?: string;
      readonly runId?: string;
      readonly evidenceType?: string;
      readonly recordClass?: "evidence" | "operational_log" | "all";
      readonly verificationState?: string;
      readonly query?: string;
      readonly from?: string;
      readonly to?: string;
    },
  ): OperationsPage<EvidenceProjection> {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("e.sensitivity", access);
    const cursorPart = cursorClause(decodeCursor(options.cursor), "e.acquired_at", "e.id");
    const clauses = [scope.sql, sensitivity.sql, cursorPart.sql];
    const params: unknown[] = [...scope.params, ...sensitivity.params, ...cursorPart.params];
    if (options.missionId) { clauses.push("e.mission_id = ?"); params.push(options.missionId); }
    if (options.runId) { clauses.push("e.run_id = ?"); params.push(options.runId); }
    if (options.evidenceType) { clauses.push("e.evidence_type = ?"); params.push(options.evidenceType); }
    const recordClass = options.recordClass ?? "evidence";
    if (recordClass === "evidence") {
      clauses.push(evidenceRecordSql("e"));
    } else if (recordClass === "operational_log") {
      clauses.push(`NOT (${evidenceRecordSql("e")})`);
    }
    if (options.verificationState) { clauses.push("e.verification_state = ?"); params.push(options.verificationState); }
    if (options.from) { clauses.push("e.acquired_at >= ?"); params.push(options.from); }
    if (options.to) { clauses.push("e.acquired_at <= ?"); params.push(options.to); }
    if (options.query) { clauses.push("e.rowid IN (SELECT rowid FROM evidence_fts WHERE evidence_fts MATCH ?)"); params.push(ftsQuery(options.query)); }
    const rows = this.database.prepare(`
      SELECT e.*, e.acquired_at AS sort_at, m.name AS mission_name,
        EXISTS(
          SELECT 1 FROM evidence_chain_events verification
          WHERE verification.evidence_id = e.id AND verification.event_type = 'verified'
        ) AS has_verification_custody,
        linked_run.id AS linked_run_id
      FROM evidence e JOIN missions m ON m.id = e.mission_id
      LEFT JOIN runs linked_run ON linked_run.id = e.run_id AND linked_run.mission_id = e.mission_id
      WHERE ${clauses.join(" AND ")}
      ORDER BY e.acquired_at DESC, e.id DESC LIMIT ?
    `).all(...params, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => this.mapEvidence(row));
  }

  getEvidence(id: string, access: OperationsAccessPolicy): Record<string, unknown> {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("e.sensitivity", access);
    const row = this.database.prepare(`
      SELECT e.*, e.acquired_at AS sort_at, m.name AS mission_name,
        EXISTS(
          SELECT 1 FROM evidence_chain_events verification
          WHERE verification.evidence_id = e.id AND verification.event_type = 'verified'
        ) AS has_verification_custody,
        linked_run.id AS linked_run_id
      FROM evidence e JOIN missions m ON m.id = e.mission_id
      LEFT JOIN runs linked_run ON linked_run.id = e.run_id AND linked_run.mission_id = e.mission_id
      WHERE e.id = ? AND ${scope.sql} AND ${sensitivity.sql}
    `).get(id, ...scope.params, ...sensitivity.params) as Row | undefined;
    if (!row) throw notFound("Evidence");
    const chain = this.database.prepare(`
      SELECT id, event_type, actor, details_json, occurred_at
      FROM evidence_chain_events WHERE evidence_id = ? ORDER BY occurred_at, id
    `).all(id) as Row[];
    const artifactScope = missionScopeSql("artifact_mission", access);
    const artifactSensitivity = sensitivitySql("artifact.sensitivity", access);
    const artifact = row.artifact_id ? this.database.prepare(`
      SELECT artifact.id, artifact.artifact_type
      FROM artifacts artifact
      JOIN missions artifact_mission ON artifact_mission.id = artifact.mission_id
      WHERE artifact.id = ? AND artifact.mission_id = ?
        AND ${artifactScope.sql} AND ${artifactSensitivity.sql}
    `).get(
      row.artifact_id,
      row.mission_id,
      ...artifactScope.params,
      ...artifactSensitivity.params,
    ) as Row | undefined : undefined;
    return {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      ...this.mapEvidence(row),
      artifact: artifact ? {
        id: artifact.id,
        artifactType: artifact.artifact_type,
      } : null,
      chainOfCustody: chain.map((item) => ({
        id: item.id,
        eventType: item.event_type,
        actor: item.actor,
        details: json(item.details_json),
        occurredAt: item.occurred_at,
      })),
    };
  }

  private mapEvidence(row: Row): EvidenceProjection {
    return {
      id: row.id,
      mission: { id: row.mission_id, name: row.mission_name },
      runId: row.run_id,
      run: row.linked_run_id ? { id: row.linked_run_id } : null,
      stepId: row.step_id,
      actionId: row.action_id,
      source: sanitizeJson(row.source),
      acquiredAt: row.acquired_at,
      target: row.target,
      evidenceType: row.evidence_type,
      recordClass: evidenceRecordClass(row),
      contentHash: row.content_hash,
      provenance: json(row.provenance_json),
      confidence: rounded(row.confidence, 4),
      sensitivity: row.sensitivity,
      verificationState: row.verification_state,
      summary: sanitizeJson(row.summary),
      hasExtractedText: Boolean(row.extracted_text),
      artifactId: row.artifact_id,
      createdBy: row.created_by,
      createdAt: row.created_at,
    };
  }

  listFindings(
    access: OperationsAccessPolicy,
    options: PageOptions & {
      readonly missionId?: string;
      readonly runId?: string;
      readonly severity?: string;
      readonly reviewStatus?: string;
      readonly query?: string;
    },
  ): OperationsPage<FindingProjection> {
    const scope = missionScopeSql("m", access);
    const evidenceSensitivity = sensitivitySql("e.sensitivity", access);
    const cursorPart = cursorClause(decodeCursor(options.cursor), "f.updated_at", "f.id");
    const clauses = [scope.sql, cursorPart.sql];
    const params: unknown[] = [...evidenceSensitivity.params, ...scope.params, ...cursorPart.params];
    if (options.missionId) { clauses.push("f.mission_id = ?"); params.push(options.missionId); }
    if (options.runId) { clauses.push("f.run_id = ?"); params.push(options.runId); }
    if (options.severity) { clauses.push("f.severity = ?"); params.push(options.severity); }
    if (options.reviewStatus) { clauses.push("f.review_status = ?"); params.push(options.reviewStatus); }
    if (options.query) { clauses.push("f.rowid IN (SELECT rowid FROM findings_fts WHERE findings_fts MATCH ?)"); params.push(ftsQuery(options.query)); }
    const rows = this.database.prepare(`
      SELECT f.*, f.updated_at AS sort_at, m.name AS mission_name,
        linked_run.id AS linked_run_id,
        SUM(CASE WHEN e.id IS NOT NULL AND ${evidenceRecordSql("e")} THEN 1 ELSE 0 END) AS evidence_count,
        SUM(CASE WHEN e.id IS NOT NULL AND ${verifiedEvidenceSql("e")} THEN 1 ELSE 0 END) AS verified_evidence_count
      FROM findings f JOIN missions m ON m.id = f.mission_id
      LEFT JOIN runs linked_run ON linked_run.id = f.run_id AND linked_run.mission_id = f.mission_id
      LEFT JOIN finding_evidence fe ON fe.finding_id = f.id
      LEFT JOIN evidence e ON e.id = fe.evidence_id AND ${evidenceSensitivity.sql}
      WHERE ${clauses.join(" AND ")}
      GROUP BY f.id
      ORDER BY f.updated_at DESC, f.id DESC LIMIT ?
    `).all(...params, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => this.mapFinding(row));
  }

  getFinding(id: string, access: OperationsAccessPolicy): Record<string, unknown> {
    const scope = missionScopeSql("m", access);
    const evidenceSensitivity = sensitivitySql("e.sensitivity", access);
    const row = this.database.prepare(`
      SELECT f.*, f.updated_at AS sort_at, m.name AS mission_name,
        linked_run.id AS linked_run_id,
        SUM(CASE WHEN e.id IS NOT NULL AND ${evidenceRecordSql("e")} THEN 1 ELSE 0 END) AS evidence_count,
        SUM(CASE WHEN e.id IS NOT NULL AND ${verifiedEvidenceSql("e")} THEN 1 ELSE 0 END) AS verified_evidence_count
      FROM findings f JOIN missions m ON m.id = f.mission_id
      LEFT JOIN runs linked_run ON linked_run.id = f.run_id AND linked_run.mission_id = f.mission_id
      LEFT JOIN finding_evidence fe ON fe.finding_id = f.id
      LEFT JOIN evidence e ON e.id = fe.evidence_id AND ${evidenceSensitivity.sql}
      WHERE f.id = ? AND ${scope.sql} GROUP BY f.id
    `).get(...evidenceSensitivity.params, id, ...scope.params) as Row | undefined;
    if (!row) throw notFound("Finding");
    const links = this.database.prepare(`
      SELECT fe.relationship, fe.added_at, e.id, e.summary, e.evidence_type,
        e.verification_state, e.content_hash
      FROM finding_evidence fe JOIN evidence e ON e.id = fe.evidence_id
      WHERE fe.finding_id = ? AND ${evidenceSensitivity.sql} ORDER BY fe.added_at, e.id
    `).all(id, ...evidenceSensitivity.params) as Row[];
    return {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      ...this.mapFinding(row),
      evidence: links.map((item) => ({
        id: item.id,
        relationship: item.relationship,
        summary: sanitizeJson(item.summary),
        evidenceType: item.evidence_type,
        verificationState: item.verification_state,
        contentHash: item.content_hash,
        addedAt: item.added_at,
      })),
    };
  }

  private mapFinding(row: Row): FindingProjection {
    return {
      id: row.id,
      mission: { id: row.mission_id, name: row.mission_name },
      runId: row.run_id,
      run: row.linked_run_id ? { id: row.linked_run_id } : null,
      title: sanitizeJson(row.title),
      severity: row.severity,
      confidence: rounded(row.confidence, 4),
      affectedScope: sanitizeJson(row.affected_scope),
      description: sanitizeJson(row.description),
      impact: sanitizeJson(row.impact),
      reproductionNotes: row.reproduction_notes ? sanitizeJson(row.reproduction_notes) : null,
      remediation: row.remediation ? sanitizeJson(row.remediation) : null,
      reviewStatus: row.review_status,
      operatorOverride: Boolean(row.operator_override),
      version: row.version,
      evidenceCount: Number(row.evidence_count ?? 0),
      verifiedEvidenceCount: Number(row.verified_evidence_count ?? 0),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  listArtifacts(
    access: OperationsAccessPolicy,
    options: PageOptions & { readonly missionId?: string; readonly runId?: string; readonly artifactType?: string; readonly reportsOnly?: boolean },
  ): OperationsPage<ArtifactProjection> {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("a.sensitivity", access);
    const cursorPart = cursorClause(decodeCursor(options.cursor), "a.created_at", "a.id");
    const clauses = [scope.sql, sensitivity.sql, cursorPart.sql];
    const params: unknown[] = [...scope.params, ...sensitivity.params, ...cursorPart.params];
    if (options.missionId) { clauses.push("a.mission_id = ?"); params.push(options.missionId); }
    if (options.runId) { clauses.push("a.run_id = ?"); params.push(options.runId); }
    if (options.artifactType) { clauses.push("a.artifact_type = ?"); params.push(options.artifactType); }
    if (options.reportsOnly) clauses.push("lower(a.artifact_type) LIKE '%report%'");
    const rows = this.database.prepare(`
      SELECT a.*, a.created_at AS sort_at, m.name AS mission_name,
        linked_run.id AS linked_run_id,
        re.id AS evaluation_id, re.evidence_coverage,
        producing_action.context_pack_id AS action_context_pack_id
      FROM artifacts a JOIN missions m ON m.id = a.mission_id
      LEFT JOIN runs linked_run ON linked_run.id = a.run_id AND linked_run.mission_id = a.mission_id
      LEFT JOIN run_evaluations re ON re.run_id = a.run_id
      LEFT JOIN actions producing_action ON producing_action.id = a.action_id
      WHERE ${clauses.join(" AND ")}
      ORDER BY a.created_at DESC, a.id DESC LIMIT ?
    `).all(...params, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => this.mapArtifact(row));
  }

  getArtifact(id: string, access: OperationsAccessPolicy): Record<string, unknown> {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("a.sensitivity", access);
    const row = this.database.prepare(`
      SELECT a.*, a.created_at AS sort_at, m.name AS mission_name,
        linked_run.id AS linked_run_id,
        re.id AS evaluation_id, re.evidence_coverage,
        producing_action.context_pack_id AS action_context_pack_id
      FROM artifacts a JOIN missions m ON m.id = a.mission_id
      LEFT JOIN runs linked_run ON linked_run.id = a.run_id AND linked_run.mission_id = a.mission_id
      LEFT JOIN run_evaluations re ON re.run_id = a.run_id
      LEFT JOIN actions producing_action ON producing_action.id = a.action_id
      WHERE a.id = ? AND ${scope.sql} AND ${sensitivity.sql}
    `).get(id, ...scope.params, ...sensitivity.params) as Row | undefined;
    if (!row) throw notFound("Artifact");
    const evidenceScope = missionScopeSql("evidence_mission", access);
    const evidenceSensitivity = sensitivitySql("evidence.sensitivity", access);
    const evidence = this.database.prepare(`
      SELECT evidence.id, evidence.summary, evidence.evidence_type,
        evidence.verification_state, evidence.content_hash, evidence.acquired_at
      FROM evidence
      JOIN missions evidence_mission ON evidence_mission.id = evidence.mission_id
      WHERE evidence.artifact_id = ? AND evidence.mission_id = ?
        AND ${evidenceScope.sql} AND ${evidenceSensitivity.sql}
      ORDER BY evidence.acquired_at DESC, evidence.id DESC
    `).all(
      id,
      row.mission_id,
      ...evidenceScope.params,
      ...evidenceSensitivity.params,
    ) as Row[];
    return {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      ...this.mapArtifact(row),
      evidence: evidence.map((item) => ({
        id: item.id,
        summary: sanitizeJson(item.summary),
        evidenceType: item.evidence_type,
        verificationState: item.verification_state,
        contentHash: item.content_hash,
        acquiredAt: item.acquired_at,
      })),
    };
  }

  private mapArtifact(row: Row): ArtifactProjection {
    return {
      id: row.id,
      mission: { id: row.mission_id, name: row.mission_name },
      runId: row.run_id,
      run: row.linked_run_id ? { id: row.linked_run_id } : null,
      stepId: row.step_id,
      actionId: row.action_id,
      journey: row.journey,
      artifactType: row.artifact_type,
      contentHash: row.content_hash,
      byteSize: Number(row.byte_size),
      mediaType: row.media_type,
      sensitivity: row.sensitivity,
      metadata: artifactMetadata(row.metadata_json, String(row.id)),
      storage: storageProjection(row.storage_uri),
      evaluation: row.evaluation_id ? { id: row.evaluation_id, evidenceCoverage: rounded(row.evidence_coverage, 4) } : null,
      contextPackIds: row.action_context_pack_id ? [String(row.action_context_pack_id)] : [],
      createdAt: row.created_at,
    };
  }

  listActions(
    access: OperationsAccessPolicy,
    options: PageOptions & {
      readonly missionId?: string;
      readonly runId?: string;
      readonly stepId?: string;
      readonly status?: string;
      readonly actionType?: string;
    },
  ): OperationsPage<ActionProjection> {
    const scope = missionScopeSql("m", access);
    const cursorPart = cursorClause(decodeCursor(options.cursor), "a.updated_at", "a.id");
    const clauses = [scope.sql, cursorPart.sql];
    const params: unknown[] = [...scope.params, ...cursorPart.params];
    if (options.missionId) { clauses.push("a.mission_id = ?"); params.push(options.missionId); }
    if (options.runId) { clauses.push("a.run_id = ?"); params.push(options.runId); }
    if (options.stepId) { clauses.push("a.step_id = ?"); params.push(options.stepId); }
    if (options.status) { clauses.push("a.status = ?"); params.push(options.status); }
    if (options.actionType) { clauses.push("a.action_type = ?"); params.push(options.actionType); }
    const rows = this.database.prepare(`
      SELECT a.*, a.updated_at AS sort_at, m.name AS mission_name, r.journey,
        ps.phase AS step_phase, ps.title AS step_title,
        COALESCE(ass.agent_id, ps.assigned_agent_id) AS agent_id
      FROM actions a
      JOIN missions m ON m.id = a.mission_id
      JOIN runs r ON r.id = a.run_id
      LEFT JOIN plan_steps ps ON ps.id = a.step_id
      LEFT JOIN assignments ass ON ass.id = a.assignment_id
      WHERE ${clauses.join(" AND ")}
      ORDER BY a.updated_at DESC, a.id DESC LIMIT ?
    `).all(...params, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => ({
      id: row.id,
      mission: { id: row.mission_id, name: row.mission_name },
      runId: row.run_id,
      journey: row.journey,
      step: row.step_id ? { id: row.step_id, phase: row.step_phase, title: row.step_title } : null,
      agentId: row.agent_id,
      actionType: row.action_type,
      actionClass: row.action_class,
      target: row.scoped_target,
      status: row.status,
      intentSummary: String(sanitizeJson(row.intent_summary)),
      resultSummary: row.result_summary ? String(sanitizeJson(row.result_summary)) : null,
      errorCategory: row.error_category,
      retryCount: Number(row.retry_count ?? 0),
      guidedDecisionId: row.guided_decision_id,
      contractId: row.contract_id,
      contextPackId: row.context_pack_id,
      correlation: { traceId: row.trace_id, spanId: row.span_id },
      startedAt: row.started_at,
      endedAt: row.ended_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  listEvents(
    access: OperationsAccessPolicy,
    options: PageOptions & {
      readonly missionId?: string;
      readonly runId?: string;
      readonly eventType?: string;
      readonly journey?: string;
      readonly traceId?: string;
      readonly actorId?: string;
      readonly from?: string;
      readonly to?: string;
    },
  ): OperationsPage<EventProjection> {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("e.sensitivity", access);
    const cursorPart = cursorClause(decodeCursor(options.cursor), "e.occurred_at", "e.id");
    const missionVisibility = access.allowUnscopedSystemData
      ? `(e.mission_id IS NULL OR ${scope.sql})`
      : `(e.mission_id IS NOT NULL AND ${scope.sql})`;
    const clauses = [missionVisibility, sensitivity.sql, cursorPart.sql];
    const params: unknown[] = [...scope.params, ...sensitivity.params, ...cursorPart.params];
    if (options.missionId) { clauses.push("e.mission_id = ?"); params.push(options.missionId); }
    if (options.runId) { clauses.push("e.run_id = ?"); params.push(options.runId); }
    if (options.eventType) { clauses.push("e.event_type = ?"); params.push(options.eventType); }
    if (options.journey) { clauses.push("e.journey = ?"); params.push(options.journey); }
    if (options.traceId) { clauses.push("e.trace_id = ?"); params.push(options.traceId); }
    if (options.actorId) { clauses.push("e.actor_id = ?"); params.push(options.actorId); }
    if (options.from) { clauses.push("e.occurred_at >= ?"); params.push(options.from); }
    if (options.to) { clauses.push("e.occurred_at <= ?"); params.push(options.to); }
    const rows = this.database.prepare(`
      SELECT e.*, e.occurred_at AS sort_at, m.name AS mission_name
      FROM events e LEFT JOIN missions m ON m.id = e.mission_id
      WHERE ${clauses.join(" AND ")}
      ORDER BY e.occurred_at DESC, e.id DESC LIMIT ?
    `).all(...params, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => ({
      id: row.id,
      occurredAt: row.occurred_at,
      eventType: row.event_type,
      mission: row.mission_id ? { id: row.mission_id, name: row.mission_name } : null,
      runId: row.run_id,
      sequence: row.sequence,
      actor: { type: row.actor_type, id: row.actor_id },
      summary: sanitizeJson(row.summary),
      payload: sanitizeJsonWithRedaction(parseJson(row.payload_json), parseJson(row.redaction_json)),
      schemaVersion: row.schema_version,
      journey: row.journey,
      correlation: { traceId: row.trace_id, spanId: row.span_id, contextPackId: row.context_pack_id },
      sensitivity: row.sensitivity,
      redaction: json(row.redaction_json),
    }));
  }

  listLogs(
    access: OperationsAccessPolicy,
    options: PageOptions & {
      readonly missionId?: string;
      readonly runId?: string;
      readonly stepId?: string;
      readonly actionId?: string;
      readonly severity?: string;
      readonly domain?: string;
      readonly traceId?: string;
      readonly query?: string;
      readonly from?: string;
      readonly to?: string;
    },
  ): OperationsPage<LogProjection> {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("l.sensitivity", access);
    const cursorPart = cursorClause(decodeCursor(options.cursor), "l.occurred_at", "l.id");
    const missionVisibility = access.allowUnscopedSystemData
      ? `(l.mission_id IS NULL OR ${scope.sql})`
      : `(l.mission_id IS NOT NULL AND ${scope.sql})`;
    const clauses = [missionVisibility, sensitivity.sql, cursorPart.sql];
    const params: unknown[] = [...scope.params, ...sensitivity.params, ...cursorPart.params];
    if (options.missionId) { clauses.push("l.mission_id = ?"); params.push(options.missionId); }
    if (options.runId) { clauses.push("l.run_id = ?"); params.push(options.runId); }
    if (options.stepId) { clauses.push("l.step_id = ?"); params.push(options.stepId); }
    if (options.actionId) { clauses.push("l.action_id = ?"); params.push(options.actionId); }
    if (options.severity) { clauses.push("l.severity = ?"); params.push(options.severity); }
    if (options.domain) { clauses.push("l.domain = ?"); params.push(options.domain); }
    if (options.traceId) { clauses.push("l.trace_id = ?"); params.push(options.traceId); }
    if (options.from) { clauses.push("l.occurred_at >= ?"); params.push(options.from); }
    if (options.to) { clauses.push("l.occurred_at <= ?"); params.push(options.to); }
    if (options.query) { clauses.push("l.rowid IN (SELECT rowid FROM structured_logs_fts WHERE structured_logs_fts MATCH ?)"); params.push(ftsQuery(options.query)); }
    const rows = this.database.prepare(`
      SELECT l.*, l.occurred_at AS sort_at, m.name AS mission_name
      FROM structured_logs l LEFT JOIN missions m ON m.id = l.mission_id
      WHERE ${clauses.join(" AND ")}
      ORDER BY l.occurred_at DESC, l.id DESC LIMIT ?
    `).all(...params, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => ({
      id: row.id,
      occurredAt: row.occurred_at,
      severity: row.severity,
      domain: row.domain,
      message: sanitizeJson(row.message),
      attributes: json(row.attributes_json),
      mission: row.mission_id ? { id: row.mission_id, name: row.mission_name } : null,
      runId: row.run_id,
      stepId: row.step_id,
      actionId: row.action_id,
      correlation: { traceId: row.trace_id, spanId: row.span_id },
      sensitivity: row.sensitivity,
    }));
  }

  listHealth(
    access: OperationsAccessPolicy,
    options: PageOptions & { readonly componentType?: string; readonly componentId?: string; readonly status?: string; readonly from?: string; readonly to?: string },
  ): OperationsPage<HealthProjection> {
    if (!access.allowUnscopedSystemData) throw forbidden("System health is not available in this access scope.");
    const cursorPart = cursorClause(decodeCursor(options.cursor), "h.captured_at", "h.id");
    const clauses = [cursorPart.sql];
    const params: unknown[] = [...cursorPart.params];
    if (options.componentType) { clauses.push("h.component_type = ?"); params.push(options.componentType); }
    if (options.componentId) { clauses.push("h.component_id = ?"); params.push(options.componentId); }
    if (options.status) { clauses.push("h.status = ?"); params.push(options.status); }
    if (options.from) { clauses.push("h.captured_at >= ?"); params.push(options.from); }
    if (options.to) { clauses.push("h.captured_at <= ?"); params.push(options.to); }
    const rows = this.database.prepare(`
      SELECT h.*, h.captured_at AS sort_at FROM health_snapshots h
      WHERE ${clauses.join(" AND ")}
      ORDER BY h.captured_at DESC, h.id DESC LIMIT ?
    `).all(...params, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => ({
      id: row.id,
      componentType: row.component_type,
      componentId: row.component_id,
      status: row.status,
      metrics: json(row.metrics_json),
      message: row.message ? sanitizeJson(row.message) : null,
      capturedAt: row.captured_at,
    }));
  }

  listEvaluations(
    access: OperationsAccessPolicy,
    options: PageOptions & { readonly missionId?: string; readonly runId?: string; readonly journey?: string },
  ): OperationsPage<EvaluationProjection> {
    const scope = missionScopeSql("m", access);
    const cursorPart = cursorClause(decodeCursor(options.cursor), "re.created_at", "re.id");
    const clauses = [scope.sql, cursorPart.sql];
    const params: unknown[] = [...scope.params, ...cursorPart.params];
    if (options.missionId) { clauses.push("re.mission_id = ?"); params.push(options.missionId); }
    if (options.runId) { clauses.push("re.run_id = ?"); params.push(options.runId); }
    if (options.journey) { clauses.push("re.journey = ?"); params.push(options.journey); }
    const rows = this.database.prepare(`
      SELECT re.*, re.created_at AS sort_at, m.name AS mission_name, r.status AS run_status,
        r.budget_json, r.budget_usage_json, r.retry_count AS run_retry_count,
        r.replan_count AS run_replan_count, r.started_at AS run_started_at,
        r.ended_at AS run_ended_at,
        (SELECT COUNT(*) FROM provider_turns pt WHERE pt.run_id = re.run_id) AS provider_turn_count,
        (SELECT COUNT(*) FROM provider_turns pt
          WHERE pt.run_id = re.run_id AND pt.input_tokens IS NOT NULL AND pt.output_tokens IS NOT NULL
        ) AS provider_token_complete_count,
        (SELECT COUNT(*) FROM provider_turns pt
          WHERE pt.run_id = re.run_id AND pt.estimated_cost IS NOT NULL
        ) AS provider_cost_complete_count,
        (SELECT COALESCE(SUM(pt.input_tokens + pt.output_tokens), 0) FROM provider_turns pt
          WHERE pt.run_id = re.run_id AND pt.input_tokens IS NOT NULL AND pt.output_tokens IS NOT NULL
        ) AS provider_token_sum,
        (SELECT COALESCE(SUM(pt.estimated_cost), 0) FROM provider_turns pt
          WHERE pt.run_id = re.run_id AND pt.estimated_cost IS NOT NULL
        ) AS provider_cost_sum,
        (SELECT COUNT(*) FROM tool_calls tc
          JOIN actions action ON action.id = tc.action_id WHERE action.run_id = re.run_id
        ) AS tool_call_count,
        (SELECT COALESCE(SUM(action.retry_count), 0) FROM actions action
          WHERE action.run_id = re.run_id
        ) AS action_retry_count,
        rec.comparison_status, rec.basis AS comparison_basis,
        rec.reason AS comparison_reason,
        rec.prior_evaluation_id AS comparison_prior_evaluation_id,
        rec.prior_run_id AS comparison_prior_run_id,
        rec.prior_terminal_status AS comparison_prior_terminal_status,
        rec.terminal_status_match AS comparison_terminal_status_match,
        rec.metrics_json AS comparison_metrics_json,
        rec.summary AS comparison_summary,
        rec.created_at AS comparison_created_at,
        pre.mission_id AS comparison_prior_mission_id,
        pre.created_at AS comparison_prior_evaluated_at
      FROM run_evaluations re
      JOIN missions m ON m.id = re.mission_id
      JOIN runs r ON r.id = re.run_id
      LEFT JOIN run_evaluation_comparisons rec ON rec.evaluation_id = re.id
      LEFT JOIN run_evaluations pre ON pre.id = rec.prior_evaluation_id
      WHERE ${clauses.join(" AND ")}
      ORDER BY re.created_at DESC, re.id DESC LIMIT ?
    `).all(...params, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => ({
      id: row.id,
      mission: { id: row.mission_id, name: row.mission_name },
      run: { id: row.run_id, status: row.run_status },
      journey: row.journey,
      scores: json(row.scores_json),
      metrics: json(row.metrics_json),
      retrospective: sanitizeJson(row.retrospective),
      evidenceCoverage: rounded(row.evidence_coverage, 4),
      createdBy: row.created_by,
      createdAt: row.created_at,
      budget: evaluationBudget(row),
      comparison: this.mapEvaluationComparison(row, access),
    }));
  }

  private mapEvaluationComparison(
    row: Row,
    access: OperationsAccessPolicy,
  ): EvaluationComparisonProjection {
    if (!row.comparison_status) {
      return {
        status: "insufficient_data",
        basis: null,
        reason: "legacy_evaluation_not_compared",
        prior: null,
        terminalStatusMatch: null,
        metrics: [],
        summary: "Insufficient comparable data: this evaluation does not contain a canonical comparison record.",
        createdAt: row.created_at,
      };
    }

    if (row.comparison_prior_mission_id) {
      const priorScope = missionScopeSql("m", access);
      const visible = this.database.prepare(`
        SELECT 1 FROM missions m WHERE m.id = ? AND ${priorScope.sql}
      `).get(row.comparison_prior_mission_id, ...priorScope.params);
      if (!visible) {
        return {
          status: "insufficient_data",
          basis: null,
          reason: "comparison_outside_access_scope",
          prior: null,
          terminalStatusMatch: null,
          metrics: [],
          summary: "Insufficient comparable data is available within the current authorization scope.",
          createdAt: row.comparison_created_at ?? row.created_at,
        };
      }
    }

    const prior = row.comparison_prior_evaluation_id && row.comparison_prior_run_id
      && row.comparison_prior_terminal_status && row.comparison_prior_evaluated_at
      ? {
          evaluationId: row.comparison_prior_evaluation_id,
          runId: row.comparison_prior_run_id,
          terminalStatus: row.comparison_prior_terminal_status,
          evaluatedAt: row.comparison_prior_evaluated_at,
        }
      : null;
    return {
      status: row.comparison_status,
      basis: row.comparison_basis,
      reason: row.comparison_reason,
      prior,
      terminalStatusMatch: row.comparison_terminal_status_match === null
        ? null
        : row.comparison_terminal_status_match === 1,
      metrics: json(row.comparison_metrics_json ?? "[]") as EvaluationComparisonProjection["metrics"],
      summary: sanitizeJson(row.comparison_summary),
      createdAt: row.comparison_created_at ?? row.created_at,
    };
  }

  listLessons(
    access: OperationsAccessPolicy,
    options: PageOptions & { readonly status?: string; readonly lessonType?: string; readonly missionId?: string; readonly runId?: string; readonly query?: string },
  ): OperationsPage<LessonProjection> {
    const scope = lessonScopeSql("l", access);
    const cursorPart = cursorClause(decodeCursor(options.cursor), "l.updated_at", "l.id");
    const clauses = [scope.sql, cursorPart.sql];
    const params: unknown[] = [...scope.params, ...cursorPart.params];
    if (options.status) { clauses.push("l.status = ?"); params.push(options.status); }
    if (options.lessonType) { clauses.push("l.lesson_type = ?"); params.push(options.lessonType); }
    if (options.missionId) { clauses.push("l.mission_id = ?"); params.push(options.missionId); }
    if (options.runId) {
      const linkedRunScope = missionScopeSql("run_mission", access);
      clauses.push(`EXISTS (
        SELECT 1 FROM lesson_evidence run_link
        JOIN runs linked_run ON linked_run.id = run_link.run_id
        JOIN missions run_mission ON run_mission.id = linked_run.mission_id
        WHERE run_link.lesson_id = l.id AND run_link.run_id = ? AND ${linkedRunScope.sql}
      )`);
      params.push(options.runId, ...linkedRunScope.params);
    }
    if (options.query) { clauses.push("l.rowid IN (SELECT rowid FROM lessons_fts WHERE lessons_fts MATCH ?)"); params.push(ftsQuery(options.query)); }
    const rows = this.database.prepare(`
      SELECT l.*, l.updated_at AS sort_at, m.name AS mission_name,
        COUNT(le.rowid) AS evidence_count,
        SUM(CASE WHEN le.relationship = 'supports' THEN 1 ELSE 0 END) AS supporting_evidence_count,
        (SELECT COUNT(*) FROM lesson_usage lu WHERE lu.lesson_id = l.id) AS usage_count,
        (SELECT MAX(version) FROM lesson_attack_chain_details acd WHERE acd.lesson_id = l.id) AS attack_chain_version
      FROM lessons l LEFT JOIN missions m ON m.id = l.mission_id
      LEFT JOIN lesson_evidence le ON le.lesson_id = l.id
      WHERE ${clauses.join(" AND ")}
      GROUP BY l.id
      ORDER BY l.updated_at DESC, l.id DESC LIMIT ?
    `).all(...params, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => this.mapLesson(row));
  }

  getLesson(id: string, access: OperationsAccessPolicy): Record<string, unknown> {
    const scope = lessonScopeSql("l", access);
    const evidenceSensitivity = sensitivitySql("e.sensitivity", access);
    const row = this.database.prepare(`
      SELECT l.*, l.updated_at AS sort_at, m.name AS mission_name,
        COUNT(le.rowid) AS evidence_count,
        SUM(CASE WHEN le.relationship = 'supports' THEN 1 ELSE 0 END) AS supporting_evidence_count,
        (SELECT COUNT(*) FROM lesson_usage lu WHERE lu.lesson_id = l.id) AS usage_count,
        (SELECT MAX(version) FROM lesson_attack_chain_details acd WHERE acd.lesson_id = l.id) AS attack_chain_version
      FROM lessons l LEFT JOIN missions m ON m.id = l.mission_id
      LEFT JOIN lesson_evidence le ON le.lesson_id = l.id
      WHERE l.id = ? AND ${scope.sql} GROUP BY l.id
    `).get(id, ...scope.params) as Row | undefined;
    if (!row) throw notFound("Lesson");
    const evidence = this.database.prepare(`
      SELECT le.evidence_id, le.run_id, le.relationship, le.rationale, le.created_at,
        e.summary AS evidence_summary
      FROM lesson_evidence le LEFT JOIN evidence e ON e.id = le.evidence_id
      WHERE le.lesson_id = ? AND (le.evidence_id IS NULL OR ${evidenceSensitivity.sql})
      ORDER BY le.created_at, le.rowid
    `).all(id, ...evidenceSensitivity.params) as Row[];
    const attackChain = new AttackChainLessonRepository(this.database).getLatest(id);
    return {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      ...this.mapLesson(row),
      evidence: evidence.map((item) => ({
        evidenceId: item.evidence_id,
        runId: item.run_id,
        relationship: item.relationship,
        rationale: sanitizeJson(item.rationale),
        evidenceSummary: item.evidence_summary ? sanitizeJson(item.evidence_summary) : null,
        createdAt: item.created_at,
      })),
      attackChain: attackChain ? {
        id: attackChain.id,
        version: attackChain.version,
        techniqueName: sanitizeJson(attackChain.techniqueName),
        techniqueCategory: attackChain.techniqueCategory,
        summary: sanitizeJson(attackChain.summary),
        expectedOutcome: sanitizeJson(attackChain.expectedOutcome),
        reuseGuidance: sanitizeJson(attackChain.reuseGuidance),
        contentHash: attackChain.contentHash,
        items: attackChain.items.map((item) => ({
          type: item.type,
          ordinal: item.ordinal,
          content: sanitizeJson(item.content),
        })),
        provenance: attackChain.sources.map((source) => ({
          sourceType: source.sourceType,
          sourceHash: source.sourceHash,
          hasRunReference: Boolean(source.runId),
          hasEvidenceReference: Boolean(source.evidenceId),
          createdAt: source.createdAt,
        })),
        createdBy: attackChain.createdBy,
        createdAt: attackChain.createdAt,
      } : null,
    };
  }

  private mapLesson(row: Row): LessonProjection {
    return {
      id: row.id,
      statement: sanitizeJson(row.statement),
      lessonType: row.lesson_type,
      applicabilityScope: row.applicability_scope,
      engagementId: row.engagement_id,
      mission: row.mission_id ? { id: row.mission_id, name: row.mission_name } : null,
      failureCategory: row.failure_category,
      retryConditions: row.retry_conditions ? sanitizeJson(row.retry_conditions) : null,
      confidence: rounded(row.confidence, 4),
      expectedBenefit: sanitizeJson(row.expected_benefit),
      risk: sanitizeJson(row.risk),
      status: row.status,
      authoringAgentId: row.authoring_agent_id,
      reviewedBy: row.reviewed_by,
      reviewedAt: row.reviewed_at,
      expiresAt: row.expires_at,
      supersedesLessonId: row.supersedes_lesson_id,
      evidenceCount: Number(row.evidence_count ?? 0),
      supportingEvidenceCount: Number(row.supporting_evidence_count ?? 0),
      usageCount: Number(row.usage_count ?? 0),
      attackChainDetails: {
        available: row.attack_chain_version !== null && row.attack_chain_version !== undefined,
        latestVersion: row.attack_chain_version === null || row.attack_chain_version === undefined
          ? null
          : Number(row.attack_chain_version),
      },
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  listLessonUsage(
    access: OperationsAccessPolicy,
    options: PageOptions & { readonly lessonId?: string; readonly missionId?: string; readonly runId?: string },
  ): OperationsPage<LessonUsageProjection> {
    const scope = missionScopeSql("m", access);
    const cursorPart = cursorClause(decodeCursor(options.cursor), "lu.used_at", "lu.id");
    const clauses = [scope.sql, cursorPart.sql];
    const params: unknown[] = [...scope.params, ...cursorPart.params];
    if (options.lessonId) { clauses.push("lu.lesson_id = ?"); params.push(options.lessonId); }
    if (options.missionId) { clauses.push("lu.mission_id = ?"); params.push(options.missionId); }
    if (options.runId) { clauses.push("lu.run_id = ?"); params.push(options.runId); }
    const rows = this.database.prepare(`
      SELECT lu.*, lu.used_at AS sort_at, l.statement, m.name AS mission_name
      FROM lesson_usage lu JOIN lessons l ON l.id = lu.lesson_id
      JOIN missions m ON m.id = lu.mission_id
      WHERE ${clauses.join(" AND ")}
      ORDER BY lu.used_at DESC, lu.id DESC LIMIT ?
    `).all(...params, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => ({
      id: row.id,
      lesson: { id: row.lesson_id, statement: sanitizeJson(row.statement) },
      mission: { id: row.mission_id, name: row.mission_name },
      runId: row.run_id,
      stepId: row.step_id,
      actionId: row.action_id,
      contextPackId: row.context_pack_id,
      influenceSummary: sanitizeJson(row.influence_summary),
      outcome: row.outcome ? sanitizeJson(row.outcome) : null,
      measuredImpact: json(row.measured_impact_json),
      usedAt: row.used_at,
    }));
  }

  listProviders(
    access: OperationsAccessPolicy,
    options: PageOptions,
  ): OperationsPage<ProviderProjection> {
    const scope = missionScopeSql("m", access);
    const cursor = decodeCursor(options.cursor);
    const visibility = access.allowUnscopedSystemData
      ? `(pt.run_id IS NULL OR ${scope.sql})`
      : `(pt.run_id IS NOT NULL AND ${scope.sql})`;
    const cursorSql = cursor
      ? `(last_turn_at < ? OR (last_turn_at = ? AND id < ?))`
      : "1";
    const cursorParams = cursor ? [cursor.sort, cursor.sort, cursor.id] : [];
    const rows = this.database.prepare(`
      WITH provider_rollup AS (
        SELECT lower(hex(pt.provider || ':' || coalesce(pt.model, ''))) AS id,
          pt.provider, pt.model, MAX(pt.started_at) AS last_turn_at,
          COUNT(*) AS turn_count,
          SUM(CASE WHEN pt.status = 'completed' THEN 1 ELSE 0 END) AS completed_count,
          SUM(CASE WHEN pt.status = 'failed' THEN 1 ELSE 0 END) AS failed_count,
          AVG(pt.latency_ms) AS mean_latency_ms,
          SUM(coalesce(pt.input_tokens, 0)) AS input_tokens,
          SUM(coalesce(pt.output_tokens, 0)) AS output_tokens,
          SUM(coalesce(pt.estimated_cost, 0)) AS estimated_cost
        FROM provider_turns pt
        LEFT JOIN runs r ON r.id = pt.run_id
        LEFT JOIN missions m ON m.id = r.mission_id
        WHERE ${visibility}
        GROUP BY pt.provider, pt.model
      )
      SELECT *, last_turn_at AS sort_at FROM provider_rollup
      WHERE ${cursorSql}
      ORDER BY last_turn_at DESC, id DESC LIMIT ?
    `).all(...scope.params, ...cursorParams, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => ({
      id: row.id,
      provider: row.provider,
      model: row.model,
      status: Number(row.failed_count) > 0 && Number(row.completed_count) === 0 ? "degraded" : "operational",
      turnCount: Number(row.turn_count),
      completedCount: Number(row.completed_count),
      failedCount: Number(row.failed_count),
      meanLatencyMs: rounded(row.mean_latency_ms),
      inputTokens: Number(row.input_tokens),
      outputTokens: Number(row.output_tokens),
      estimatedCost: rounded(row.estimated_cost, 6),
      lastTurnAt: row.last_turn_at,
    }));
  }

  listMcpServers(access: OperationsAccessPolicy, options: PageOptions & { readonly status?: string }): OperationsPage<McpProjection> {
    if (!access.allowUnscopedSystemData) throw forbidden("MCP connection state is not available in this access scope.");
    const cursorPart = cursorClause(decodeCursor(options.cursor), "m.updated_at", "m.id");
    const rows = this.database.prepare(`
      SELECT m.*, m.updated_at AS sort_at FROM mcp_servers m
      WHERE ${cursorPart.sql} ${options.status ? "AND m.status = ?" : ""}
      ORDER BY m.updated_at DESC, m.id DESC LIMIT ?
    `).all(...cursorPart.params, ...(options.status ? [options.status] : []), options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => ({
      id: row.id,
      name: row.name,
      transport: row.transport,
      endpointRedacted: row.endpoint_redacted ? sanitizeJson(row.endpoint_redacted) : null,
      status: row.status,
      capabilities: json(row.capabilities_json),
      policy: json(row.policy_json),
      lastCheckedAt: row.last_checked_at,
      updatedAt: row.updated_at,
    }));
  }

  listSystemPolicies(access: OperationsAccessPolicy, options: PageOptions): OperationsPage<PolicyProjection> {
    if (!access.allowUnscopedSystemData) throw forbidden("System policy projections are not available in this access scope.");
    const cursorPart = cursorClause(decodeCursor(options.cursor), "sort_at", "id");
    const sensitivity = sensitivitySql("sensitivity", access);
    const rows = this.database.prepare(`
      WITH policies AS (
        SELECT 'agent:' || id AS id, 'agent' AS source_type, display_name AS label,
          json_object('providerPolicy', json(provider_policy_json), 'toolPolicy', json(tool_policy_json)) AS policy_json,
          updated_at AS sort_at, 'internal' AS sensitivity
        FROM agents
        UNION ALL
        SELECT 'mcp:' || id, 'mcp', name, policy_json, updated_at, 'internal' FROM mcp_servers
        UNION ALL
        SELECT 'setting:' || key, 'setting', key, value_json, updated_at, sensitivity
        FROM settings
        WHERE (key LIKE 'policy.%' OR key LIKE 'authorization.%' OR key LIKE 'security.policy.%' OR key LIKE 'runtime.policy.%')
      )
      SELECT * FROM policies WHERE ${sensitivity.sql} AND ${cursorPart.sql}
      ORDER BY sort_at DESC, id DESC LIMIT ?
    `).all(...sensitivity.params, ...cursorPart.params, options.limit + 1) as Row[];
    return page(rows, options.limit, (row) => ({
      id: row.id,
      sourceType: row.source_type,
      label: row.label,
      policy: row.source_type === "setting" && isSensitiveSettingKey(row.label)
        ? "[REDACTED]"
        : json(row.policy_json),
      sensitivity: row.sensitivity,
      updatedAt: row.sort_at,
    }));
  }

  listReports(access: OperationsAccessPolicy, options: PageOptions & { readonly missionId?: string; readonly runId?: string }): OperationsPage<ArtifactProjection> {
    return this.listArtifacts(access, { ...options, reportsOnly: true });
  }

  getReport(id: string, access: OperationsAccessPolicy): Record<string, unknown> {
    const artifact = this.getArtifact(id, access);
    if (typeof artifact.artifactType !== "string" || !artifact.artifactType.toLocaleLowerCase("en-US").includes("report")) {
      throw notFound("Report");
    }
    return artifact;
  }

  /**
   * Authorize and resolve the canonical scope needed by the mandatory
   * reporting Brain hook without constructing the report first. Keeping this
   * preflight separate prevents a required Autonomous context failure from
   * producing or auditing an export.
   */
  getRunCompletionReportingScope(
    runId: string,
    access: OperationsAccessPolicy,
  ): {
    readonly missionId: string;
    readonly runId: string;
    readonly journey: "autonomous" | "guided";
    readonly status: string;
    readonly memoryPolicyJson: string;
  } {
    const scope = missionScopeSql("m", access);
    const row = this.database.prepare(`
      SELECT r.id, r.mission_id, r.journey, r.status, m.memory_policy_json
      FROM runs r JOIN missions m ON m.id = r.mission_id
      WHERE r.id = ? AND ${scope.sql}
    `).get(runId, ...scope.params) as Row | undefined;
    if (!row) throw notFound("Run");
    if (!["completed", "failed", "cancelled"].includes(row.status)) {
      throw conflict(
        "A completion export is available only after the run reaches a terminal state.",
        "Complete, fail safely, or cancel the run before exporting its completion record.",
      );
    }
    return {
      missionId: row.mission_id,
      runId: row.id,
      journey: row.journey,
      status: row.status,
      memoryPolicyJson: row.memory_policy_json,
    };
  }

  /**
   * Produce a scope-checked completion bundle containing operational metadata
   * only. Raw evidence bodies, tool/provider payloads, artifact locations,
   * conversation bodies, and memory-note content are deliberately excluded.
   */
  getRunCompletionExport(
    runId: string,
    access: OperationsAccessPolicy,
    reportingContext: RunCompletionExport["reportingContext"],
  ): RunCompletionExport {
    const scope = missionScopeSql("m", access);
    const row = this.database.prepare(`
      SELECT r.*, m.name AS mission_name, m.objective, m.engagement_id,
        m.authorization_status, m.success_criteria_json
      FROM runs r JOIN missions m ON m.id = r.mission_id
      WHERE r.id = ? AND ${scope.sql}
    `).get(runId, ...scope.params) as Row | undefined;
    if (!row) throw notFound("Run");
    if (!["completed", "failed", "cancelled"].includes(row.status)) {
      throw conflict(
        "A completion export is available only after the run reaches a terminal state.",
        "Complete, fail safely, or cancel the run before exporting its completion record.",
      );
    }

    const evidencePage = collectPages((cursor) => this.listEvidence(access, { runId, limit: 100, cursor }));
    const findingPage = collectPages((cursor) => this.listFindings(access, { runId, limit: 100, cursor }));
    const artifactPage = collectPages((cursor) => this.listArtifacts(access, { runId, limit: 100, cursor }));
    const evaluationPage = collectPages((cursor) => this.listEvaluations(access, { runId, limit: 100, cursor }));
    const lessonPage = collectPages((cursor) => this.listLessons(access, {
      missionId: row.mission_id,
      runId,
      limit: 100,
      cursor,
    }));
    const lessonUsagePage = collectPages((cursor) => this.listLessonUsage(access, { runId, limit: 100, cursor }));
    const eventPage = collectPages((cursor) => this.listEvents(access, { runId, limit: 100, cursor }));

    const actionRows = this.database.prepare(`
      SELECT id, step_id, action_type, action_class, status, intent_summary,
        result_summary, error_category, retry_count, context_pack_id, started_at, ended_at
      FROM actions WHERE run_id = ? ORDER BY created_at, id LIMIT 1001
    `).all(runId) as Row[];
    const guidedRows = this.database.prepare(`
      SELECT id, status, decision_reason, rationale, created_at, decided_at
      FROM guided_decisions WHERE run_id = ? ORDER BY created_at, id LIMIT 1001
    `).all(runId) as Row[];
    const approvalRows = this.database.prepare(`
      SELECT id, status, reason, policy_rule, created_at, decided_at
      FROM approvals WHERE run_id = ? ORDER BY created_at, id LIMIT 1001
    `).all(runId) as Row[];
    const contextRows = this.database.prepare(`
      SELECT mcp.id, mcp.purpose, mcp.created_at,
        COUNT(mci.node_id) AS retrieved_items,
        SUM(CASE WHEN mci.used = 1 THEN 1 ELSE 0 END) AS used_items,
        SUM(CASE WHEN mci.corrected = 1 THEN 1 ELSE 0 END) AS corrected_items
      FROM memory_context_packs mcp
      LEFT JOIN memory_context_items mci ON mci.context_pack_id = mcp.id
      WHERE mcp.run_id = ?
      GROUP BY mcp.id ORDER BY mcp.created_at, mcp.id LIMIT 1001
    `).all(runId) as Row[];
    const stepRows = this.database.prepare(`
      SELECT ps.id, ps.status, ps.title
      FROM plan_steps ps
      WHERE ps.run_id = ?
        AND ps.plan_id = (SELECT p.id FROM plans p WHERE p.run_id = ? ORDER BY p.version DESC LIMIT 1)
        AND ps.status NOT IN ('completed', 'skipped', 'cancelled')
      ORDER BY ps.ordinal, ps.id LIMIT 1001
    `).all(runId, runId) as Row[];

    const actions = actionRows.slice(0, 1_000).map((item) => ({
      id: item.id,
      stepId: item.step_id,
      actionType: item.action_type,
      actionClass: item.action_class,
      status: item.status,
      intentSummary: sanitizeJson(item.intent_summary),
      resultSummary: item.result_summary ? sanitizeJson(item.result_summary) : null,
      errorCategory: item.error_category,
      retryCount: Number(item.retry_count ?? 0),
      contextPackId: item.context_pack_id,
      startedAt: item.started_at,
      endedAt: item.ended_at,
    }));
    const guidedDecisions = guidedRows.slice(0, 1_000).map((item) => ({
      id: item.id,
      decisionType: "guided" as const,
      status: item.status,
      reason: sanitizeJson(item.decision_reason ?? item.rationale),
      policyRule: null,
      createdAt: item.created_at,
      decidedAt: item.decided_at,
    }));
    const administrativeDecisions = approvalRows.slice(0, 1_000).map((item) => ({
      id: item.id,
      decisionType: "administrative" as const,
      status: item.status,
      reason: sanitizeJson(item.reason),
      policyRule: item.policy_rule,
      createdAt: item.created_at,
      decidedAt: item.decided_at,
    }));
    const decisions = [...guidedDecisions, ...administrativeDecisions]
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    const context = contextRows.slice(0, 1_000).map((item) => ({
      id: item.id,
      purpose: sanitizeJson(item.purpose),
      usedItems: Number(item.used_items ?? 0),
      retrievedItems: Number(item.retrieved_items ?? 0),
      correctedItems: Number(item.corrected_items ?? 0),
      createdAt: item.created_at,
    }));
    const unresolvedItems: RunCompletionExport["unresolvedItems"] = [
      ...stepRows.slice(0, 1_000).map((item) => ({
        type: "step" as const, id: item.id, status: item.status, summary: sanitizeJson(item.title),
      })),
      ...findingPage.items.filter((item) => !["verified", "accepted_risk", "rejected"].includes(item.reviewStatus)).map((item) => ({
        type: "finding" as const, id: item.id, status: item.reviewStatus, summary: item.title,
      })),
      ...decisions.filter((item) => item.status === "pending").map((item) => ({
        type: "decision" as const, id: item.id, status: item.status, summary: item.reason,
      })),
    ];

    const metadata = {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      exportKind: "run_completion_metadata" as const,
      generatedAt: this.clock().toISOString(),
      reportingContext,
      mission: {
        id: row.mission_id,
        name: row.mission_name,
        objective: sanitizeJson(row.objective),
        engagementId: row.engagement_id,
        journey: row.journey,
        authorizationStatus: row.authorization_status,
        successCriteria: json(row.success_criteria_json),
      },
      run: {
        id: row.id,
        journey: row.journey,
        status: row.status,
        statusReason: row.status_reason ? sanitizeJson(row.status_reason) : null,
        progress: rounded(row.progress, 4),
        retryCount: Number(row.retry_count ?? 0),
        replanCount: Number(row.replan_count ?? 0),
        startedAt: row.started_at,
        endedAt: row.ended_at,
        budgetUsage: json(row.budget_usage_json),
      },
      evaluation: evaluationPage.items,
      evidence: evidencePage.items.map((item) => ({
        id: item.id,
        acquiredAt: item.acquiredAt,
        target: item.target,
        evidenceType: item.evidenceType,
        contentHash: item.contentHash,
        confidence: item.confidence,
        sensitivity: item.sensitivity,
        verificationState: item.verificationState,
        summary: item.summary,
        artifactId: item.artifactId,
      })),
      findings: findingPage.items.map((item) => ({
        id: item.id,
        title: item.title,
        severity: item.severity,
        confidence: item.confidence,
        affectedScope: item.affectedScope,
        reviewStatus: item.reviewStatus,
        evidenceCount: item.evidenceCount,
        verifiedEvidenceCount: item.verifiedEvidenceCount,
        updatedAt: item.updatedAt,
      })),
      artifacts: artifactPage.items.map((item) => ({
        id: item.id,
        artifactType: item.artifactType,
        contentHash: item.contentHash,
        byteSize: item.byteSize,
        mediaType: item.mediaType,
        sensitivity: item.sensitivity,
        storageScheme: item.storage.scheme,
        createdAt: item.createdAt,
      })),
      reports: artifactPage.items.filter((item) => item.artifactType.toLocaleLowerCase("en-US").includes("report")).map((item) => ({
        id: item.id,
        artifactType: item.artifactType,
        contentHash: item.contentHash,
        byteSize: item.byteSize,
        mediaType: item.mediaType,
        sensitivity: item.sensitivity,
        storageScheme: item.storage.scheme,
        createdAt: item.createdAt,
      })),
      events: eventPage.items.map((item) => ({
        id: item.id,
        occurredAt: item.occurredAt,
        eventType: item.eventType,
        sequence: item.sequence,
        summary: item.summary,
        contextPackId: item.correlation.contextPackId,
      })),
      actions,
      decisions,
      memoryContext: context,
      lessons: { proposedOrVerified: lessonPage.items, reused: lessonUsagePage.items },
      unresolvedItems,
      truncation: {
        evidence: evidencePage.truncated,
        findings: findingPage.truncated,
        artifacts: artifactPage.truncated,
        evaluations: evaluationPage.truncated,
        lessons: lessonPage.truncated,
        lessonUsage: lessonUsagePage.truncated,
        events: eventPage.truncated,
        actions: actionRows.length > 1_000,
        decisions: guidedRows.length > 1_000 || approvalRows.length > 1_000,
        memoryContext: contextRows.length > 1_000,
        unresolvedSteps: stepRows.length > 1_000,
      },
      privacy: {
        metadataOnly: true as const,
        omitted: [
          "raw evidence and extracted text",
          "event, provider, tool, and conversation payloads",
          "artifact paths, URLs, and file contents",
          "memory-note bodies and retrieval queries",
          "credentials, tokens, and authentication material",
        ],
      },
    };
    return {
      ...metadata,
      integrity: { algorithm: "sha256", digest: sha256(canonicalJson(metadata)) },
    };
  }

  recordRunCompletionExport(exported: RunCompletionExport, actor: OperationsActor): void {
    inImmediateTransaction(this.database, () => {
      const previous = this.database.prepare(`
        SELECT record_hash FROM audit_records ORDER BY occurred_at DESC, id DESC LIMIT 1
      `).get() as { readonly record_hash: string } | undefined;
      const id = `audit_${randomUUID()}`;
      const details = {
        exportKind: exported.exportKind,
        exportHash: exported.integrity.digest,
        metadataOnly: true,
        reportingContext: {
          contextPackId: exported.reportingContext.contextPackId,
          status: exported.reportingContext.status,
          retrievedItems: exported.reportingContext.retrievedItems,
          appliedItems: exported.reportingContext.appliedItems,
        },
        counts: {
          evidence: exported.evidence.length,
          findings: exported.findings.length,
          artifacts: exported.artifacts.length,
          events: exported.events.length,
          actions: exported.actions.length,
        },
        truncation: exported.truncation,
      };
      const record = {
        id,
        missionId: exported.mission.id,
        runId: exported.run.id,
        journey: exported.run.journey,
        actorType: actor.type,
        actorId: actor.id,
        action: "run.completion_exported",
        resourceType: "run",
        resourceId: exported.run.id,
        reason: "Authorized operator exported the terminal run completion metadata bundle.",
        details,
        previousHash: previous?.record_hash ?? null,
        occurredAt: exported.generatedAt,
      };
      const recordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(record)}`);
      this.database.prepare(`
        INSERT INTO audit_records (
          id, mission_id, run_id, journey, actor_type, actor_id, action,
          resource_type, resource_id, reason, details_json,
          previous_hash, record_hash, occurred_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        exported.mission.id,
        exported.run.id,
        exported.run.journey,
        actor.type,
        actor.id,
        record.action,
        record.resourceType,
        record.resourceId,
        record.reason,
        canonicalJson(details),
        previous?.record_hash ?? null,
        recordHash,
        exported.generatedAt,
      );
    });
  }

  databaseFingerprint(): string {
    const counts = this.database.prepare(`
      SELECT
        (SELECT COUNT(*) FROM missions) AS missions,
        (SELECT COUNT(*) FROM events) AS events,
        (SELECT COUNT(*) FROM evidence) AS evidence,
        (SELECT COUNT(*) FROM findings) AS findings,
        (SELECT COUNT(*) FROM lessons) AS lessons
    `).get() as Row;
    return sha256(JSON.stringify(counts));
  }
}

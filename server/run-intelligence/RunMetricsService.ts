import { inImmediateTransaction, type SqliteDatabase } from "../db";
import { evidenceRecordSql, verifiedEvidenceSql } from "../domain/evidence-semantics";
import { canonicalJson, hashCanonical, parseJsonObject, sha256 } from "./serialization";
import {
  RUN_METRIC_SCHEMA_VERSION,
  RunIntelligenceError,
  type MetricDrillDownFilter,
  type MetricDrillDownReference,
  type MetricDrillDownResource,
  type RunMetric,
  type RunMetricCategory,
  type RunMetricKey,
  type RunMetricMeasurement,
  type RunMetricsSnapshot,
  type RunMetricsSourceCounts,
  type RunMetricUnit,
} from "./types";

interface RunRow {
  readonly id: string;
  readonly mission_id: string;
  readonly status: string;
  readonly started_at: string | null;
  readonly ended_at: string | null;
  readonly updated_at: string;
  readonly retry_count: number;
  readonly replan_count: number;
}

interface StatusCountRow {
  readonly status: string;
  readonly count: number;
}

interface TypeCountRow {
  readonly value: string;
  readonly count: number;
}

interface AssignmentRow {
  readonly id: string;
  readonly step_id: string | null;
  readonly agent_id: string;
  readonly status: string;
  readonly started_at: string | null;
  readonly ended_at: string | null;
  readonly created_at: string;
}

interface ProviderTurnRow {
  readonly input_tokens: number | null;
  readonly output_tokens: number | null;
  readonly estimated_cost: number | null;
  readonly latency_ms: number | null;
}

interface SnapshotRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly through_event_sequence: number;
  readonly metric_schema_version: string;
  readonly metrics_json: string;
  readonly source_counts_json: string;
  readonly recomputation_hash: string;
  readonly computed_at: string;
}

interface CountRow {
  readonly count: number;
}

interface NullableTimeRow {
  readonly value: string | null;
}

interface SequenceRow {
  readonly sequence: number | null;
  readonly occurred_at: string | null;
}

interface SumRow {
  readonly value: number | null;
}

const ASSET_NODE_TYPES = ["asset", "host", "network_device", "cloud_asset", "container", "cluster"] as const;
const SERVICE_NODE_TYPES = ["service", "application", "website", "endpoint", "database"] as const;
const METRIC_KEYS = new Set<RunMetricKey>([
  "elapsed_ms", "plan_versions", "steps_total", "steps_completed", "steps_failed", "steps_blocked",
  "steps_skipped", "plan_completion_ratio", "unique_agents", "assignments_total", "assignments_completed",
  "assignments_failed", "assignments_blocked", "current_concurrent_agents", "peak_concurrent_agents",
  "agent_handoffs", "average_assignment_duration_ms", "maximum_assignment_duration_ms",
  "attack_attempts_total", "attack_attempts_started", "attack_attempts_succeeded", "attack_attempts_failed",
  "attack_attempts_safely_aborted", "attack_attempts_blocked", "attack_attempts_waiting_conditions",
  "topology_nodes", "assets_discovered", "services_discovered", "topology_edges", "osi_observations",
  "engagement_log_records", "observations", "evidence_candidates", "verified_evidence", "findings",
  "verified_findings", "artifacts", "finding_evidence_coverage_ratio", "actions_total", "actions_failed",
  "action_retries", "run_retries", "replans", "tool_calls_total", "tool_calls_succeeded", "tool_calls_failed",
  "tool_calls_denied", "tool_calls_timed_out", "provider_turns", "provider_tokens", "estimated_provider_cost",
  "average_provider_latency_ms", "time_to_first_evidence_ms", "events", "context_packs", "used_context_items",
  "verified_lessons_used",
]);

const SOURCE_COUNT_KEYS: readonly (keyof RunMetricsSourceCounts)[] = [
  "plans", "planSteps", "assignments", "actions", "toolCalls", "attackAttempts", "topologyNodes",
  "topologyEdges", "osiObservations", "logRecords", "observations", "evidenceCandidates", "evidence",
  "findings", "artifacts", "providerTurns", "events", "contextPacks", "lessonUsage",
];

function count(database: SqliteDatabase, sql: string, ...parameters: unknown[]): number {
  const row = database.prepare(sql).get(...parameters) as CountRow;
  return Number(row.count);
}

function statusCounts(rows: readonly StatusCountRow[]): ReadonlyMap<string, number> {
  return new Map(rows.map((row) => [row.status, Number(row.count)]));
}

function typeCounts(rows: readonly TypeCountRow[]): ReadonlyMap<string, number> {
  return new Map(rows.map((row) => [row.value, Number(row.count)]));
}

function numberFor(map: ReadonlyMap<string, number>, key: string): number {
  return map.get(key) ?? 0;
}

function sumFor(map: ReadonlyMap<string, number>, keys: readonly string[]): number {
  return keys.reduce((total, key) => total + numberFor(map, key), 0);
}

function rounded(value: number): number {
  return Number(value.toFixed(6));
}

function duration(start: string | null, end: string | null): number | null {
  const startMs = start ? Date.parse(start) : Number.NaN;
  const endMs = end ? Date.parse(end) : Number.NaN;
  return Number.isFinite(startMs) && Number.isFinite(endMs) && endMs >= startMs ? endMs - startMs : null;
}

function assignmentAnalytics(assignments: readonly AssignmentRow[], horizon: string): {
  readonly currentAgents: number;
  readonly peakAgents: number;
  readonly handoffs: number;
  readonly averageDurationMs: number | null;
  readonly maximumDurationMs: number | null;
} {
  const currentAgents = new Set(assignments.filter(({ status }) => status === "active").map(({ agent_id }) => agent_id)).size;
  const horizonMs = Date.parse(horizon);
  const timeline: Array<{ readonly time: number; readonly order: 0 | 1; readonly agentId: string; readonly delta: -1 | 1 }> = [];
  const durations: number[] = [];
  for (const assignment of assignments) {
    const started = assignment.started_at ? Date.parse(assignment.started_at) : Number.NaN;
    if (!Number.isFinite(started)) continue;
    const ended = assignment.ended_at ? Date.parse(assignment.ended_at) : horizonMs;
    if (!Number.isFinite(ended) || ended < started) continue;
    timeline.push({ time: started, order: 1, agentId: assignment.agent_id, delta: 1 });
    if (assignment.ended_at) timeline.push({ time: ended, order: 0, agentId: assignment.agent_id, delta: -1 });
    durations.push(ended - started);
  }
  timeline.sort((left, right) => left.time - right.time || left.order - right.order || left.agentId.localeCompare(right.agentId));
  const activeByAgent = new Map<string, number>();
  let peakAgents = 0;
  for (const event of timeline) {
    const next = Math.max(0, (activeByAgent.get(event.agentId) ?? 0) + event.delta);
    if (next === 0) activeByAgent.delete(event.agentId);
    else activeByAgent.set(event.agentId, next);
    peakAgents = Math.max(peakAgents, activeByAgent.size);
  }

  const byStep = new Map<string, AssignmentRow[]>();
  for (const assignment of assignments) {
    if (!assignment.step_id) continue;
    const rows = byStep.get(assignment.step_id) ?? [];
    rows.push(assignment);
    byStep.set(assignment.step_id, rows);
  }
  let handoffs = 0;
  for (const rows of byStep.values()) {
    rows.sort((left, right) => {
      const leftTime = left.started_at ?? left.created_at;
      const rightTime = right.started_at ?? right.created_at;
      return leftTime.localeCompare(rightTime) || left.id.localeCompare(right.id);
    });
    for (let index = 1; index < rows.length; index += 1) {
      if (rows[index - 1]!.agent_id !== rows[index]!.agent_id) handoffs += 1;
    }
  }
  return {
    currentAgents,
    peakAgents,
    handoffs,
    averageDurationMs: durations.length === 0 ? null : rounded(durations.reduce((total, value) => total + value, 0) / durations.length),
    maximumDurationMs: durations.length === 0 ? null : Math.max(...durations),
  };
}

function filter(field: MetricDrillDownFilter["field"], value: MetricDrillDownFilter["value"], operator: MetricDrillDownFilter["operator"] = "eq"): MetricDrillDownFilter {
  return { field, operator, value };
}

function drillDown(input: Omit<MetricDrillDownReference, "id">): MetricDrillDownReference {
  return { id: `metric_ref_${hashCanonical(input).slice(0, 24)}`, ...input };
}

function reference(input: {
  readonly role?: MetricDrillDownReference["role"];
  readonly resource: MetricDrillDownResource;
  readonly missionId: string;
  readonly runId: string;
  readonly aggregation?: MetricDrillDownReference["aggregation"];
  readonly field?: string;
  readonly filters?: readonly MetricDrillDownFilter[];
}): MetricDrillDownReference {
  return drillDown({
    role: input.role ?? "primary",
    resource: input.resource,
    missionId: input.missionId,
    runId: input.runId,
    aggregation: input.aggregation ?? "records",
    field: input.field ?? null,
    filters: [filter("run_id", input.runId), ...(input.filters ?? [])],
  });
}

function metric(input: {
  readonly key: RunMetricKey;
  readonly label: string;
  readonly category: RunMetricCategory;
  readonly unit?: RunMetricUnit;
  readonly value: number | null;
  readonly measurement?: RunMetricMeasurement;
  readonly drillDown: readonly MetricDrillDownReference[];
}): RunMetric {
  if (input.drillDown.length === 0) throw new Error(`Metric ${input.key} needs a drill-down reference`);
  return {
    key: input.key,
    label: input.label,
    category: input.category,
    unit: input.unit ?? "count",
    value: input.value,
    measurement: input.measurement ?? "exact",
    drillDown: input.drillDown,
  };
}

function parseStoredMetrics(value: string): RunMetric[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.length !== METRIC_KEYS.size) {
    throw new RunIntelligenceError("metrics_snapshot_corrupt", "Stored run metrics have an invalid shape");
  }
  const keys = new Set<string>();
  for (const item of parsed) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new RunIntelligenceError("metrics_snapshot_corrupt", "Stored run metric is invalid");
    }
    const key = (item as Record<string, unknown>).key;
    if (typeof key !== "string" || !METRIC_KEYS.has(key as RunMetricKey) || keys.has(key)) {
      throw new RunIntelligenceError("metrics_snapshot_corrupt", "Stored run metric key is invalid or duplicated");
    }
    keys.add(key);
  }
  return parsed as RunMetric[];
}

function parseSourceCounts(value: string): RunMetricsSourceCounts {
  const parsed = parseJsonObject(value, "Run metrics source counts");
  for (const key of SOURCE_COUNT_KEYS) {
    if (typeof parsed[key] !== "number" || !Number.isSafeInteger(parsed[key]) || parsed[key] < 0) {
      throw new RunIntelligenceError("metrics_snapshot_corrupt", `Run metrics source count ${key} is invalid`);
    }
  }
  return parsed as unknown as RunMetricsSourceCounts;
}

function mapSnapshot(row: SnapshotRow): RunMetricsSnapshot {
  if (row.metric_schema_version !== RUN_METRIC_SCHEMA_VERSION) {
    throw new RunIntelligenceError("metrics_schema_mismatch", "Stored run metrics use an unsupported schema version");
  }
  return {
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    throughEventSequence: row.through_event_sequence,
    metricSchemaVersion: RUN_METRIC_SCHEMA_VERSION,
    metrics: parseStoredMetrics(row.metrics_json),
    sourceCounts: parseSourceCounts(row.source_counts_json),
    recomputationHash: row.recomputation_hash,
    computedAt: row.computed_at,
  };
}

export class RunMetricsService {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  compute(runId: string): RunMetricsSnapshot {
    return inImmediateTransaction(this.database, () => this.#compute(runId, this.clock().toISOString()));
  }

  recomputeAndStore(runId: string): RunMetricsSnapshot {
    return inImmediateTransaction(this.database, () => {
      const computed = this.#compute(runId, this.clock().toISOString());
      const existing = this.database.prepare(`
        SELECT * FROM run_metrics_snapshots
        WHERE run_id = ? AND through_event_sequence = ? AND metric_schema_version = ?
      `).get(runId, computed.throughEventSequence, RUN_METRIC_SCHEMA_VERSION) as SnapshotRow | undefined;
      if (existing) {
        if (existing.recomputation_hash !== computed.recomputationHash) {
          throw new RunIntelligenceError(
            "canonical_state_changed_without_event",
            "Canonical run records changed without advancing the event sequence; refusing to rewrite the reproducible snapshot",
          );
        }
        return mapSnapshot(existing);
      }
      this.database.prepare(`
        INSERT INTO run_metrics_snapshots (
          id, mission_id, run_id, through_event_sequence, metric_schema_version,
          metrics_json, source_counts_json, recomputation_hash, computed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        computed.id,
        computed.missionId,
        computed.runId,
        computed.throughEventSequence,
        computed.metricSchemaVersion,
        canonicalJson(computed.metrics),
        canonicalJson(computed.sourceCounts),
        computed.recomputationHash,
        computed.computedAt,
      );
      return this.get(computed.id);
    });
  }

  get(snapshotId: string): RunMetricsSnapshot {
    const row = this.database.prepare("SELECT * FROM run_metrics_snapshots WHERE id = ?").get(snapshotId) as SnapshotRow | undefined;
    if (!row) throw new RunIntelligenceError("metrics_snapshot_not_found", `Run metrics snapshot not found: ${snapshotId}`);
    return mapSnapshot(row);
  }

  list(runId: string, limit = 50): RunMetricsSnapshot[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new RunIntelligenceError("invalid_metrics_snapshot_limit", "Run metrics snapshot limit must be an integer from 1 through 100");
    }
    const run = this.database.prepare("SELECT id FROM runs WHERE id = ?").get(runId);
    if (!run) throw new RunIntelligenceError("run_not_found", `Run not found: ${runId}`);
    const rows = this.database.prepare(`
      SELECT * FROM run_metrics_snapshots WHERE run_id = ?
      ORDER BY through_event_sequence DESC, computed_at DESC, id DESC LIMIT ?
    `).all(runId, limit) as SnapshotRow[];
    return rows.map(mapSnapshot);
  }

  latest(runId: string): RunMetricsSnapshot | null {
    const row = this.database.prepare(`
      SELECT * FROM run_metrics_snapshots WHERE run_id = ?
      ORDER BY through_event_sequence DESC, computed_at DESC, id DESC LIMIT 1
    `).get(runId) as SnapshotRow | undefined;
    return row ? mapSnapshot(row) : null;
  }

  #compute(runId: string, computedAt: string): RunMetricsSnapshot {
    const run = this.database.prepare(`
      SELECT id, mission_id, status, started_at, ended_at, updated_at,
        retry_count, replan_count FROM runs WHERE id = ?
    `).get(runId) as RunRow | undefined;
    if (!run) throw new RunIntelligenceError("run_not_found", `Run not found: ${runId}`);
    const missionId = run.mission_id;
    const sequence = this.database.prepare(`
      SELECT MAX(sequence) AS sequence, MAX(occurred_at) AS occurred_at
      FROM events WHERE run_id = ?
    `).get(runId) as SequenceRow;
    const throughEventSequence = Number(sequence.sequence ?? 0);
    const horizon = run.ended_at ?? sequence.occurred_at ?? run.updated_at;

    const planStatus = statusCounts(this.database.prepare(`
      SELECT status, COUNT(*) AS count FROM plan_steps WHERE run_id = ? GROUP BY status ORDER BY status
    `).all(runId) as StatusCountRow[]);
    const assignmentRows = this.database.prepare(`
      SELECT id, step_id, agent_id, status, started_at, ended_at, created_at
      FROM assignments WHERE run_id = ? ORDER BY created_at, id
    `).all(runId) as AssignmentRow[];
    const assignmentStatus = statusCounts(this.database.prepare(`
      SELECT status, COUNT(*) AS count FROM assignments WHERE run_id = ? GROUP BY status ORDER BY status
    `).all(runId) as StatusCountRow[]);
    const assignmentStats = assignmentAnalytics(assignmentRows, horizon);
    const attackStatus = statusCounts(this.database.prepare(`
      SELECT status, COUNT(*) AS count FROM attack_attempts WHERE run_id = ? GROUP BY status ORDER BY status
    `).all(runId) as StatusCountRow[]);
    const topologyTypes = typeCounts(this.database.prepare(`
      SELECT node_type AS value, COUNT(*) AS count FROM topology_nodes
      WHERE run_id = ? GROUP BY node_type ORDER BY node_type
    `).all(runId) as TypeCountRow[]);
    const actionStatus = statusCounts(this.database.prepare(`
      SELECT status, COUNT(*) AS count FROM actions WHERE run_id = ? GROUP BY status ORDER BY status
    `).all(runId) as StatusCountRow[]);
    const toolStatus = statusCounts(this.database.prepare(`
      SELECT tc.status, COUNT(*) AS count FROM tool_calls tc
      JOIN actions a ON a.id = tc.action_id WHERE a.run_id = ?
      GROUP BY tc.status ORDER BY tc.status
    `).all(runId) as StatusCountRow[]);
    const providerTurns = this.database.prepare(`
      SELECT input_tokens, output_tokens, estimated_cost, latency_ms
      FROM provider_turns WHERE run_id = ? ORDER BY started_at, id
    `).all(runId) as ProviderTurnRow[];

    const sourceCounts: RunMetricsSourceCounts = {
      plans: count(this.database, "SELECT COUNT(*) AS count FROM plans WHERE run_id = ?", runId),
      planSteps: count(this.database, "SELECT COUNT(*) AS count FROM plan_steps WHERE run_id = ?", runId),
      assignments: assignmentRows.length,
      actions: count(this.database, "SELECT COUNT(*) AS count FROM actions WHERE run_id = ?", runId),
      toolCalls: count(this.database, "SELECT COUNT(*) AS count FROM tool_calls tc JOIN actions a ON a.id = tc.action_id WHERE a.run_id = ?", runId),
      attackAttempts: count(this.database, "SELECT COUNT(*) AS count FROM attack_attempts WHERE run_id = ?", runId),
      topologyNodes: count(this.database, "SELECT COUNT(*) AS count FROM topology_nodes WHERE run_id = ?", runId),
      topologyEdges: count(this.database, `
        SELECT COUNT(DISTINCT te.id) AS count FROM topology_edges te
        JOIN topology_nodes source ON source.id = te.source_node_id
        JOIN topology_nodes target ON target.id = te.target_node_id
        WHERE source.run_id = ? AND target.run_id = ?
      `, runId, runId),
      osiObservations: count(this.database, `
        SELECT COUNT(*) AS count FROM asset_layer_observations alo
        JOIN topology_nodes tn ON tn.id = alo.asset_node_id WHERE tn.run_id = ?
      `, runId),
      logRecords: count(this.database, "SELECT COUNT(*) AS count FROM engagement_log_records WHERE run_id = ?", runId),
      observations: count(this.database, "SELECT COUNT(*) AS count FROM observations WHERE run_id = ?", runId),
      evidenceCandidates: count(this.database, "SELECT COUNT(*) AS count FROM evidence_candidates WHERE run_id = ?", runId),
      evidence: count(this.database, `SELECT COUNT(*) AS count FROM evidence WHERE run_id = ? AND ${evidenceRecordSql("evidence")}`, runId),
      findings: count(this.database, "SELECT COUNT(*) AS count FROM findings WHERE run_id = ?", runId),
      artifacts: count(this.database, "SELECT COUNT(*) AS count FROM artifacts WHERE run_id = ?", runId),
      providerTurns: providerTurns.length,
      events: count(this.database, "SELECT COUNT(*) AS count FROM events WHERE run_id = ?", runId),
      contextPacks: count(this.database, "SELECT COUNT(*) AS count FROM memory_context_packs WHERE run_id = ?", runId),
      lessonUsage: count(this.database, "SELECT COUNT(*) AS count FROM lesson_usage WHERE run_id = ?", runId),
    };

    const refs = (resource: MetricDrillDownResource, filters: readonly MetricDrillDownFilter[] = [], options: {
      readonly role?: MetricDrillDownReference["role"];
      readonly aggregation?: MetricDrillDownReference["aggregation"];
      readonly field?: string;
    } = {}): MetricDrillDownReference => reference({ resource, missionId, runId, filters, ...options });
    const stepTotal = sourceCounts.planSteps;
    const stepCompleted = numberFor(planStatus, "completed");
    const elapsedMs = duration(run.started_at, horizon);
    const attackStarted = count(this.database, "SELECT COUNT(*) AS count FROM attack_attempts WHERE run_id = ? AND started_at IS NOT NULL", runId);
    const uniqueAgents = new Set(assignmentRows.map(({ agent_id }) => agent_id)).size;
    const actionRetries = Number((this.database.prepare("SELECT COALESCE(SUM(retry_count), 0) AS value FROM actions WHERE run_id = ?").get(runId) as SumRow).value ?? 0);
    const verifiedEvidence = count(this.database, `SELECT COUNT(*) AS count FROM evidence WHERE run_id = ? AND ${verifiedEvidenceSql("evidence")}`, runId);
    const verifiedFindings = count(this.database, "SELECT COUNT(*) AS count FROM findings WHERE run_id = ? AND review_status = 'verified'", runId);
    const coveredFindings = count(this.database, `
      SELECT COUNT(*) AS count FROM findings f
      WHERE f.run_id = ? AND EXISTS (
        SELECT 1 FROM finding_evidence fe JOIN evidence e ON e.id = fe.evidence_id
        WHERE fe.finding_id = f.id AND ${verifiedEvidenceSql("e")}
      )
    `, runId);
    const firstEvidence = this.database.prepare(`
      SELECT MIN(acquired_at) AS value FROM evidence WHERE run_id = ? AND ${verifiedEvidenceSql("evidence")}
    `).get(runId) as NullableTimeRow;
    const firstEvidenceMs = duration(run.started_at, firstEvidence.value);
    const usedContextItems = count(this.database, `
      SELECT COUNT(*) AS count FROM memory_context_items mci
      JOIN memory_context_packs mcp ON mcp.id = mci.context_pack_id
      WHERE mcp.run_id = ? AND mci.used = 1
    `, runId);
    const verifiedLessonsUsed = count(this.database, `
      SELECT COUNT(DISTINCT lu.lesson_id) AS count FROM lesson_usage lu
      JOIN lessons l ON l.id = lu.lesson_id WHERE lu.run_id = ? AND l.status = 'verified'
    `, runId);

    const tokenKnown = providerTurns.filter((turn) => turn.input_tokens !== null && turn.output_tokens !== null);
    const tokens = tokenKnown.reduce((total, turn) => total + (turn.input_tokens ?? 0) + (turn.output_tokens ?? 0), 0);
    const costKnown = providerTurns.filter((turn) => turn.estimated_cost !== null);
    const costs = costKnown.reduce((total, turn) => total + (turn.estimated_cost ?? 0), 0);
    const latencyKnown = providerTurns.filter((turn) => turn.latency_ms !== null);
    const averageLatency = latencyKnown.length === 0
      ? null
      : rounded(latencyKnown.reduce((total, turn) => total + (turn.latency_ms ?? 0), 0) / latencyKnown.length);
    const measured = (known: number, total: number): RunMetricMeasurement => total === 0 || known === total ? "exact" : known === 0 ? "not_observed" : "partial";

    const metrics: RunMetric[] = [
      metric({ key: "elapsed_ms", label: "Elapsed execution time", category: "objective", unit: "milliseconds", value: elapsedMs, measurement: elapsedMs === null ? "not_observed" : "derived", drillDown: [refs("runs", [], { aggregation: "duration", field: "started_at,ended_at" })] }),
      metric({ key: "plan_versions", label: "Plan versions", category: "objective", value: sourceCounts.plans, drillDown: [refs("plans")] }),
      metric({ key: "steps_total", label: "Steps planned", category: "objective", value: stepTotal, drillDown: [refs("plan_steps")] }),
      metric({ key: "steps_completed", label: "Steps completed", category: "objective", value: stepCompleted, drillDown: [refs("plan_steps", [filter("status", "completed")])] }),
      metric({ key: "steps_failed", label: "Steps failed", category: "objective", value: numberFor(planStatus, "failed"), drillDown: [refs("plan_steps", [filter("status", "failed")])] }),
      metric({ key: "steps_blocked", label: "Steps blocked", category: "objective", value: numberFor(planStatus, "blocked"), drillDown: [refs("plan_steps", [filter("status", "blocked")])] }),
      metric({ key: "steps_skipped", label: "Steps skipped", category: "objective", value: numberFor(planStatus, "skipped"), drillDown: [refs("plan_steps", [filter("status", "skipped")])] }),
      metric({ key: "plan_completion_ratio", label: "Plan completion", category: "objective", unit: "ratio", value: stepTotal === 0 ? null : rounded(stepCompleted / stepTotal), measurement: stepTotal === 0 ? "not_observed" : "derived", drillDown: [refs("plan_steps", [filter("status", "completed")], { role: "numerator" }), refs("plan_steps", [], { role: "denominator" })] }),
      metric({ key: "unique_agents", label: "Unique agents assigned", category: "orchestration", value: uniqueAgents, drillDown: [refs("assignments", [], { aggregation: "distinct", field: "agent_id" })] }),
      metric({ key: "assignments_total", label: "Assignments", category: "orchestration", value: sourceCounts.assignments, drillDown: [refs("assignments")] }),
      metric({ key: "assignments_completed", label: "Assignments completed", category: "orchestration", value: numberFor(assignmentStatus, "completed"), drillDown: [refs("assignments", [filter("status", "completed")])] }),
      metric({ key: "assignments_failed", label: "Assignments failed", category: "orchestration", value: numberFor(assignmentStatus, "failed"), drillDown: [refs("assignments", [filter("status", "failed")])] }),
      metric({ key: "assignments_blocked", label: "Assignments blocked", category: "orchestration", value: numberFor(assignmentStatus, "blocked"), drillDown: [refs("assignments", [filter("status", "blocked")])] }),
      metric({ key: "current_concurrent_agents", label: "Current concurrent agents", category: "orchestration", value: assignmentStats.currentAgents, drillDown: [refs("assignments", [filter("status", "active")], { aggregation: "distinct", field: "agent_id" })] }),
      metric({ key: "peak_concurrent_agents", label: "Peak concurrent agents", category: "orchestration", value: assignmentStats.peakAgents, measurement: "derived", drillDown: [refs("assignments", [], { aggregation: "max_concurrency", field: "agent_id,started_at,ended_at" })] }),
      metric({ key: "agent_handoffs", label: "Agent handoffs", category: "orchestration", value: assignmentStats.handoffs, measurement: "derived", drillDown: [refs("assignments", [], { aggregation: "records", field: "step_id,agent_id,started_at" })] }),
      metric({ key: "average_assignment_duration_ms", label: "Average assignment duration", category: "orchestration", unit: "milliseconds", value: assignmentStats.averageDurationMs, measurement: assignmentStats.averageDurationMs === null ? "not_observed" : "derived", drillDown: [refs("assignments", [], { aggregation: "average", field: "started_at,ended_at" })] }),
      metric({ key: "maximum_assignment_duration_ms", label: "Maximum assignment duration", category: "orchestration", unit: "milliseconds", value: assignmentStats.maximumDurationMs, measurement: assignmentStats.maximumDurationMs === null ? "not_observed" : "derived", drillDown: [refs("assignments", [], { aggregation: "maximum", field: "started_at,ended_at" })] }),
      metric({ key: "attack_attempts_total", label: "Attack attempts", category: "attempts", value: sourceCounts.attackAttempts, drillDown: [refs("attack_attempts")] }),
      metric({ key: "attack_attempts_started", label: "Attack attempts started", category: "attempts", value: attackStarted, drillDown: [refs("attack_attempts", [filter("started_at", null, "is_not_null")])] }),
      metric({ key: "attack_attempts_succeeded", label: "Attack attempts succeeded", category: "attempts", value: numberFor(attackStatus, "succeeded"), drillDown: [refs("attack_attempts", [filter("status", "succeeded")])] }),
      metric({ key: "attack_attempts_failed", label: "Attack attempts failed", category: "attempts", value: numberFor(attackStatus, "failed"), drillDown: [refs("attack_attempts", [filter("status", "failed")])] }),
      metric({ key: "attack_attempts_safely_aborted", label: "Attack attempts safely aborted", category: "attempts", value: numberFor(attackStatus, "safely_aborted"), drillDown: [refs("attack_attempts", [filter("status", "safely_aborted")])] }),
      metric({ key: "attack_attempts_blocked", label: "Attack attempts blocked", category: "attempts", value: numberFor(attackStatus, "blocked"), drillDown: [refs("attack_attempts", [filter("status", "blocked")])] }),
      metric({ key: "attack_attempts_waiting_conditions", label: "Attack attempts awaiting conditions", category: "attempts", value: numberFor(attackStatus, "waiting_conditions"), drillDown: [refs("attack_attempts", [filter("status", "waiting_conditions")])] }),
      metric({ key: "topology_nodes", label: "Topology nodes", category: "discovery", value: sourceCounts.topologyNodes, drillDown: [refs("topology_nodes")] }),
      metric({ key: "assets_discovered", label: "Assets discovered", category: "discovery", value: sumFor(topologyTypes, ASSET_NODE_TYPES), drillDown: [refs("topology_nodes", [filter("node_type", ASSET_NODE_TYPES, "in")])] }),
      metric({ key: "services_discovered", label: "Services discovered", category: "discovery", value: sumFor(topologyTypes, SERVICE_NODE_TYPES), drillDown: [refs("topology_nodes", [filter("node_type", SERVICE_NODE_TYPES, "in")])] }),
      metric({ key: "topology_edges", label: "Topology relationships", category: "discovery", value: sourceCounts.topologyEdges, drillDown: [refs("topology_edges")] }),
      metric({ key: "osi_observations", label: "OSI and stack observations", category: "discovery", value: sourceCounts.osiObservations, drillDown: [refs("asset_layer_observations")] }),
      metric({ key: "engagement_log_records", label: "Engagement log records", category: "evidence", value: sourceCounts.logRecords, drillDown: [refs("engagement_log_records")] }),
      metric({ key: "observations", label: "Parsed observations", category: "evidence", value: sourceCounts.observations, drillDown: [refs("observations")] }),
      metric({ key: "evidence_candidates", label: "Evidence candidates", category: "evidence", value: sourceCounts.evidenceCandidates, drillDown: [refs("evidence_candidates")] }),
      metric({ key: "verified_evidence", label: "Verified evidence", category: "evidence", value: verifiedEvidence, drillDown: [refs("evidence", [filter("verification_state", "verified")])] }),
      metric({ key: "findings", label: "Findings", category: "evidence", value: sourceCounts.findings, drillDown: [refs("findings")] }),
      metric({ key: "verified_findings", label: "Verified findings", category: "evidence", value: verifiedFindings, drillDown: [refs("findings", [filter("review_status", "verified")])] }),
      metric({ key: "artifacts", label: "Artifacts", category: "evidence", value: sourceCounts.artifacts, drillDown: [refs("artifacts")] }),
      metric({ key: "finding_evidence_coverage_ratio", label: "Finding evidence coverage", category: "evidence", unit: "ratio", value: sourceCounts.findings === 0 ? null : rounded(coveredFindings / sourceCounts.findings), measurement: sourceCounts.findings === 0 ? "not_observed" : "derived", drillDown: [refs("findings", [filter("verification_state", "rejected", "not_eq")], { role: "numerator", aggregation: "records_with_relation", field: "finding_evidence.evidence_id" }), refs("findings", [], { role: "denominator" })] }),
      metric({ key: "actions_total", label: "Actions", category: "reliability", value: sourceCounts.actions, drillDown: [refs("actions")] }),
      metric({ key: "actions_failed", label: "Actions failed", category: "reliability", value: numberFor(actionStatus, "failed"), drillDown: [refs("actions", [filter("status", "failed")])] }),
      metric({ key: "action_retries", label: "Action retries", category: "reliability", value: actionRetries, drillDown: [refs("actions", [], { aggregation: "sum", field: "retry_count" })] }),
      metric({ key: "run_retries", label: "Run retries", category: "reliability", value: run.retry_count, drillDown: [refs("runs", [], { aggregation: "sum", field: "retry_count" })] }),
      metric({ key: "replans", label: "Replans", category: "reliability", value: run.replan_count, drillDown: [refs("runs", [], { aggregation: "sum", field: "replan_count" })] }),
      metric({ key: "tool_calls_total", label: "Tool calls", category: "reliability", value: sourceCounts.toolCalls, drillDown: [refs("tool_calls")] }),
      metric({ key: "tool_calls_succeeded", label: "Tool calls succeeded", category: "reliability", value: numberFor(toolStatus, "succeeded"), drillDown: [refs("tool_calls", [filter("status", "succeeded")])] }),
      metric({ key: "tool_calls_failed", label: "Tool calls failed", category: "reliability", value: numberFor(toolStatus, "failed"), drillDown: [refs("tool_calls", [filter("status", "failed")])] }),
      metric({ key: "tool_calls_denied", label: "Tool calls denied", category: "reliability", value: numberFor(toolStatus, "denied"), drillDown: [refs("tool_calls", [filter("status", "denied")])] }),
      metric({ key: "tool_calls_timed_out", label: "Tool calls timed out", category: "reliability", value: numberFor(toolStatus, "timed_out"), drillDown: [refs("tool_calls", [filter("status", "timed_out")])] }),
      metric({ key: "provider_turns", label: "Provider turns", category: "resources", value: sourceCounts.providerTurns, drillDown: [refs("provider_turns")] }),
      metric({ key: "provider_tokens", label: "Provider tokens", category: "resources", value: providerTurns.length === 0 ? 0 : tokenKnown.length === 0 ? null : tokens, measurement: measured(tokenKnown.length, providerTurns.length), drillDown: [refs("provider_turns", [], { aggregation: "sum", field: "input_tokens,output_tokens" })] }),
      metric({ key: "estimated_provider_cost", label: "Estimated provider cost", category: "resources", unit: "cost", value: providerTurns.length === 0 ? 0 : costKnown.length === 0 ? null : rounded(costs), measurement: measured(costKnown.length, providerTurns.length), drillDown: [refs("provider_turns", [], { aggregation: "sum", field: "estimated_cost" })] }),
      metric({ key: "average_provider_latency_ms", label: "Average provider latency", category: "resources", unit: "milliseconds", value: averageLatency, measurement: providerTurns.length === 0 ? "not_observed" : measured(latencyKnown.length, providerTurns.length), drillDown: [refs("provider_turns", [], { aggregation: "average", field: "latency_ms" })] }),
      metric({ key: "time_to_first_evidence_ms", label: "Time to first meaningful evidence", category: "evidence", unit: "milliseconds", value: firstEvidenceMs, measurement: firstEvidenceMs === null ? "not_observed" : "derived", drillDown: [refs("evidence", [], { aggregation: "duration", field: "acquired_at" })] }),
      metric({ key: "events", label: "Canonical events", category: "reliability", value: sourceCounts.events, drillDown: [refs("events")] }),
      metric({ key: "context_packs", label: "Context Packs", category: "learning", value: sourceCounts.contextPacks, drillDown: [refs("memory_context_packs")] }),
      metric({ key: "used_context_items", label: "Memory items used", category: "learning", value: usedContextItems, drillDown: [refs("memory_context_items", [filter("used", 1)])] }),
      metric({ key: "verified_lessons_used", label: "Verified lessons used", category: "learning", value: verifiedLessonsUsed, drillDown: [refs("lesson_usage", [filter("lesson_status", "verified")], { aggregation: "distinct", field: "lesson_id" })] }),
    ];
    if (metrics.length !== METRIC_KEYS.size || new Set(metrics.map(({ key }) => key)).size !== METRIC_KEYS.size) {
      throw new Error("Run metric registry is incomplete or duplicated");
    }
    const hashInput = {
      metricSchemaVersion: RUN_METRIC_SCHEMA_VERSION,
      missionId,
      runId,
      throughEventSequence,
      metrics,
      sourceCounts,
    };
    const recomputationHash = hashCanonical(hashInput);
    return {
      id: `run_metrics_${sha256(`${runId}\0${throughEventSequence}\0${RUN_METRIC_SCHEMA_VERSION}\0${recomputationHash}`).slice(0, 24)}`,
      missionId,
      runId,
      throughEventSequence,
      metricSchemaVersion: RUN_METRIC_SCHEMA_VERSION,
      metrics,
      sourceCounts,
      recomputationHash,
      computedAt,
    };
  }
}

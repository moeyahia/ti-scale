import { inImmediateTransaction, type SqliteDatabase } from "../db";

export type RunComparisonStatus = "available" | "insufficient_data";
export type RunComparisonBasis = "same_mission_and_journey" | "same_engagement_and_journey";
export type ComparisonDirection = "higher" | "lower";
export type ComparisonMovement = "favorable" | "unfavorable" | "unchanged";

export interface RunComparisonMetric {
  readonly key: string;
  readonly label: string;
  readonly unit: "ratio" | "milliseconds" | "count" | "cost";
  readonly favorableDirection: ComparisonDirection;
  readonly current: number;
  readonly prior: number;
  readonly delta: number;
  readonly relativeDelta: number | null;
  readonly movement: ComparisonMovement;
}

export interface StoredRunComparison {
  readonly status: RunComparisonStatus;
  readonly basis: RunComparisonBasis | null;
  readonly reason: string;
  readonly priorEvaluationId: string | null;
  readonly priorRunId: string | null;
  readonly priorTerminalStatus: "completed" | "failed" | "cancelled" | null;
  readonly terminalStatusMatch: boolean | null;
  readonly metrics: readonly RunComparisonMetric[];
  readonly summary: string;
  readonly createdAt: string;
}

export interface RecordRunComparisonInput {
  readonly evaluationId: string;
  readonly runId: string;
  readonly missionId: string;
  readonly engagementId: string | null;
  readonly journey: "autonomous" | "guided";
  readonly terminalStatus: "completed" | "failed" | "cancelled";
  readonly endedAt: string | null;
  readonly evaluationCreatedAt: string;
  readonly scores: Readonly<Record<string, unknown>>;
  readonly metrics: Readonly<Record<string, unknown>>;
  readonly evidenceCoverage: number;
}

interface ComparisonRow {
  readonly comparison_status: RunComparisonStatus;
  readonly basis: RunComparisonBasis | null;
  readonly reason: string;
  readonly prior_evaluation_id: string | null;
  readonly prior_run_id: string | null;
  readonly prior_terminal_status: "completed" | "failed" | "cancelled" | null;
  readonly terminal_status_match: number | null;
  readonly metrics_json: string;
  readonly summary: string;
  readonly created_at: string;
}

interface CandidateRow {
  readonly evaluation_id: string;
  readonly run_id: string;
  readonly mission_id: string;
  readonly terminal_status: "completed" | "failed" | "cancelled";
  readonly scores_json: string;
  readonly metrics_json: string;
  readonly evidence_coverage: number;
}

interface MetricDefinition {
  readonly key: string;
  readonly label: string;
  readonly source: "score" | "metric" | "coverage";
  readonly unit: RunComparisonMetric["unit"];
  readonly favorableDirection: ComparisonDirection;
}

const METRICS: readonly MetricDefinition[] = [
  { key: "objectiveCompletion", label: "Objective completion", source: "score", unit: "ratio", favorableDirection: "higher" },
  { key: "evidenceCoverage", label: "Evidence coverage", source: "coverage", unit: "ratio", favorableDirection: "higher" },
  { key: "evidenceQuality", label: "Evidence quality", source: "score", unit: "ratio", favorableDirection: "higher" },
  { key: "policyCompliance", label: "Policy compliance", source: "score", unit: "ratio", favorableDirection: "higher" },
  { key: "journeyAdherence", label: "Journey adherence", source: "score", unit: "ratio", favorableDirection: "higher" },
  { key: "durationMs", label: "Elapsed time", source: "metric", unit: "milliseconds", favorableDirection: "lower" },
  { key: "timeToFirstMeaningfulEvidenceMs", label: "Time to first meaningful evidence", source: "metric", unit: "milliseconds", favorableDirection: "lower" },
  { key: "noProgressActionCount", label: "No-progress actions", source: "metric", unit: "count", favorableDirection: "lower" },
  { key: "repeatedActionRate", label: "Repeated-action rate", source: "metric", unit: "ratio", favorableDirection: "lower" },
  { key: "retryRate", label: "Retry rate", source: "metric", unit: "ratio", favorableDirection: "lower" },
  { key: "recoverySuccessRate", label: "Recovery success rate", source: "metric", unit: "ratio", favorableDirection: "higher" },
  { key: "memoryContextPrecision", label: "Memory context precision", source: "metric", unit: "ratio", favorableDirection: "higher" },
  { key: "preferenceCorrectionRate", label: "Preference correction rate", source: "metric", unit: "ratio", favorableDirection: "lower" },
  { key: "toolCallSuccessRate", label: "Tool-call success rate", source: "metric", unit: "ratio", favorableDirection: "higher" },
  { key: "providerTokens", label: "Provider tokens", source: "metric", unit: "count", favorableDirection: "lower" },
  { key: "estimatedCost", label: "Estimated cost", source: "metric", unit: "cost", favorableDirection: "lower" },
] as const;

function parseObject(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

function finiteNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function round(value: number): number {
  return Number(value.toFixed(6));
}

function parseComparisonMetrics(value: string): RunComparisonMetric[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed as RunComparisonMetric[] : [];
  } catch {
    return [];
  }
}

function comparisonFromRow(row: ComparisonRow): StoredRunComparison {
  return {
    status: row.comparison_status,
    basis: row.basis,
    reason: row.reason,
    priorEvaluationId: row.prior_evaluation_id,
    priorRunId: row.prior_run_id,
    priorTerminalStatus: row.prior_terminal_status,
    terminalStatusMatch: row.terminal_status_match === null ? null : row.terminal_status_match === 1,
    metrics: parseComparisonMetrics(row.metrics_json),
    summary: row.summary,
    createdAt: row.created_at,
  };
}

function valueFor(
  definition: MetricDefinition,
  evaluation: { readonly scores: Readonly<Record<string, unknown>>; readonly metrics: Readonly<Record<string, unknown>>; readonly evidenceCoverage: number },
): number | null {
  if (definition.source === "coverage") return finiteNumber(evaluation.evidenceCoverage);
  return finiteNumber(definition.source === "score"
    ? evaluation.scores[definition.key]
    : evaluation.metrics[definition.key]);
}

function metricComparison(
  definition: MetricDefinition,
  current: number,
  prior: number,
): RunComparisonMetric {
  const delta = round(current - prior);
  const movement: ComparisonMovement = Math.abs(delta) < 0.000001
    ? "unchanged"
    : (definition.favorableDirection === "higher" ? delta > 0 : delta < 0)
      ? "favorable"
      : "unfavorable";
  return {
    key: definition.key,
    label: definition.label,
    unit: definition.unit,
    favorableDirection: definition.favorableDirection,
    current: round(current),
    prior: round(prior),
    delta,
    relativeDelta: prior === 0 ? null : round(delta / Math.abs(prior)),
    movement,
  };
}

/**
 * Persists one deterministic, immutable comparison for each terminal evaluation.
 * Selection never crosses an engagement: exact mission continuity is preferred,
 * followed by an earlier evaluation in the same engagement and journey.
 */
export class RunComparisonService {
  constructor(private readonly database: SqliteDatabase) {}

  get(evaluationId: string): StoredRunComparison | null {
    const row = this.database.prepare(`
      SELECT * FROM run_evaluation_comparisons WHERE evaluation_id = ?
    `).get(evaluationId) as ComparisonRow | undefined;
    return row ? comparisonFromRow(row) : null;
  }

  record(input: RecordRunComparisonInput): StoredRunComparison {
    return inImmediateTransaction(this.database, () => this.#record(input));
  }

  #record(input: RecordRunComparisonInput): StoredRunComparison {
    const existing = this.get(input.evaluationId);
    if (existing && existing.reason !== "legacy_evaluation_not_compared") return existing;
    if (existing) {
      this.database.prepare("DELETE FROM run_evaluation_comparisons WHERE evaluation_id = ?")
        .run(input.evaluationId);
    }

    const cutoff = input.endedAt ?? input.evaluationCreatedAt;
    const candidate = this.database.prepare(`
      SELECT re.id AS evaluation_id, re.run_id, re.mission_id,
        pr.status AS terminal_status, re.scores_json, re.metrics_json,
        re.evidence_coverage
      FROM run_evaluations re
      JOIN runs pr ON pr.id = re.run_id
      JOIN missions pm ON pm.id = re.mission_id
      WHERE re.run_id != ? AND re.journey = ?
        AND pr.status IN ('completed', 'failed', 'cancelled')
        AND (pm.id = ? OR (? IS NOT NULL AND pm.engagement_id = ?))
        AND COALESCE(pr.ended_at, re.created_at) <= ?
      ORDER BY
        CASE WHEN pm.id = ? THEN 0 ELSE 1 END,
        CASE WHEN pr.status = ? THEN 0 ELSE 1 END,
        COALESCE(pr.ended_at, re.created_at) DESC,
        re.created_at DESC,
        re.id DESC
      LIMIT 1
    `).get(
      input.runId,
      input.journey,
      input.missionId,
      input.engagementId,
      input.engagementId,
      cutoff,
      input.missionId,
      input.terminalStatus,
    ) as CandidateRow | undefined;

    if (!candidate) {
      return this.#insert(input, {
        status: "insufficient_data",
        basis: null,
        reason: "no_prior_same_scope_evaluation",
        priorEvaluationId: null,
        priorRunId: null,
        priorTerminalStatus: null,
        terminalStatusMatch: null,
        metrics: [],
        summary: "Insufficient comparable data: no earlier evaluated run exists in this mission or in the same engagement and journey.",
        createdAt: input.evaluationCreatedAt,
      });
    }

    const prior = {
      scores: parseObject(candidate.scores_json),
      metrics: parseObject(candidate.metrics_json),
      evidenceCoverage: candidate.evidence_coverage,
    };
    const current = { scores: input.scores, metrics: input.metrics, evidenceCoverage: input.evidenceCoverage };
    const metrics = METRICS.flatMap((definition) => {
      const currentValue = valueFor(definition, current);
      const priorValue = valueFor(definition, prior);
      return currentValue === null || priorValue === null
        ? []
        : [metricComparison(definition, currentValue, priorValue)];
    });
    const basis: RunComparisonBasis = candidate.mission_id === input.missionId
      ? "same_mission_and_journey"
      : "same_engagement_and_journey";
    const terminalStatusMatch = candidate.terminal_status === input.terminalStatus;

    if (metrics.length === 0) {
      return this.#insert(input, {
        status: "insufficient_data",
        basis,
        reason: "no_shared_canonical_metrics",
        priorEvaluationId: candidate.evaluation_id,
        priorRunId: candidate.run_id,
        priorTerminalStatus: candidate.terminal_status,
        terminalStatusMatch,
        metrics: [],
        summary: "Insufficient comparable data: an earlier in-scope evaluation exists, but it shares no canonical measured metrics with this run.",
        createdAt: input.evaluationCreatedAt,
      });
    }

    const favorable = metrics.filter((metric) => metric.movement === "favorable").length;
    const unfavorable = metrics.filter((metric) => metric.movement === "unfavorable").length;
    const unchanged = metrics.filter((metric) => metric.movement === "unchanged").length;
    const basisLabel = basis === "same_mission_and_journey" ? "same-mission" : "same-engagement";
    const outcomeLabel = terminalStatusMatch ? "the same terminal outcome" : "a different terminal outcome";
    const summary = `Compared with one earlier ${basisLabel} ${input.journey} run with ${outcomeLabel}: ${favorable} measured direction${favorable === 1 ? "" : "s"} favorable, ${unfavorable} unfavorable, and ${unchanged} unchanged. This descriptive comparison does not establish that the system improved.`;
    return this.#insert(input, {
      status: "available",
      basis,
      reason: "canonical_prior_selected",
      priorEvaluationId: candidate.evaluation_id,
      priorRunId: candidate.run_id,
      priorTerminalStatus: candidate.terminal_status,
      terminalStatusMatch,
      metrics,
      summary,
      createdAt: input.evaluationCreatedAt,
    });
  }

  #insert(input: RecordRunComparisonInput, comparison: StoredRunComparison): StoredRunComparison {
    this.database.prepare(`
      INSERT INTO run_evaluation_comparisons (
        evaluation_id, run_id, comparison_status, basis, reason,
        prior_evaluation_id, prior_run_id, prior_terminal_status,
        terminal_status_match, metrics_json, summary, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      input.evaluationId,
      input.runId,
      comparison.status,
      comparison.basis,
      comparison.reason,
      comparison.priorEvaluationId,
      comparison.priorRunId,
      comparison.priorTerminalStatus,
      comparison.terminalStatusMatch === null ? null : comparison.terminalStatusMatch ? 1 : 0,
      JSON.stringify(comparison.metrics),
      comparison.summary,
      comparison.createdAt,
    );
    return comparison;
  }
}

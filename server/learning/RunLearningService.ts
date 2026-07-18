import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import type { EventRepository } from "../events";
import { MemoryRepository } from "../memory";
import { evidenceRecordSql, verifiedEvidenceSql } from "../domain/evidence-semantics";
import {
  findRejectableSecrets,
  findReusableContentIdentifiers,
  redactLessonText,
} from "./AttackLesson";
import type { MissionCompletionEvaluation } from "../command-runtime/types";
import { AttackChainLearningService, canonicalLessonMemoryNodeId } from "./AttackChainLessonRepository";
import {
  projectSafeAttackChain,
  type CanonicalLearningAction,
  type CanonicalLearningToolCall,
} from "./SafeAttackChainProjection";
import {
  RunComparisonService,
  type StoredRunComparison,
} from "./RunComparisonService";

export type EvaluatedTerminalStatus = "completed" | "failed" | "cancelled";

export interface RecordRunEvaluationInput {
  readonly runId: string;
  readonly terminalStatus: EvaluatedTerminalStatus;
  readonly createdBy: string;
  readonly outcome?: MissionCompletionEvaluation;
}

export interface StoredRunEvaluation {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly journey: "autonomous" | "guided";
  readonly terminalStatus: EvaluatedTerminalStatus;
  readonly scores: Readonly<Record<string, number | null>>;
  readonly metrics: Readonly<Record<string, number | string | null>>;
  readonly retrospective: string;
  readonly evidenceCoverage: number;
  readonly createdBy: string;
  readonly createdAt: string;
  readonly comparison: StoredRunComparison;
  readonly proposedLessonIds: readonly string[];
}

interface RunRow {
  readonly id: string;
  readonly mission_id: string;
  readonly journey: "autonomous" | "guided";
  readonly status: string;
  readonly engagement_id: string | null;
  readonly started_at: string | null;
  readonly ended_at: string | null;
  readonly created_at: string;
  readonly retry_count: number;
  readonly replan_count: number;
  readonly budget_json: string;
  readonly budget_usage_json: string;
}

interface EvaluationRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly journey: "autonomous" | "guided";
  readonly scores_json: string;
  readonly metrics_json: string;
  readonly retrospective: string;
  readonly evidence_coverage: number;
  readonly created_by: string;
  readonly created_at: string;
}

interface AggregateRow {
  readonly count: number;
  readonly succeeded?: number | null;
  readonly failed?: number | null;
  readonly denied?: number | null;
  readonly cancelled?: number | null;
  readonly unique_count?: number | null;
  readonly retries?: number | null;
  readonly verified?: number | null;
  readonly reports?: number | null;
  readonly completed?: number | null;
  readonly exact_bound?: number | null;
  readonly corrections?: number | null;
  readonly used?: number | null;
  readonly corrected?: number | null;
  readonly tokens?: number | null;
  readonly cost?: number | null;
  readonly first_meaningful_at?: string | null;
  readonly with_progress?: number | null;
}

interface ServiceOptions {
  readonly clock?: () => Date;
  readonly events?: EventRepository;
}

interface EvaluationCalculation {
  readonly scores: Record<string, number | null>;
  readonly metrics: Record<string, number | string | null>;
  readonly retrospective: string;
  readonly evidenceCoverage: number;
}

const AUTHORING_AGENT = "run-evaluator";
const SAFE_ACTION_DOMAINS = [
  ["recon", "reconnaissance"],
  ["enumerat", "enumeration"],
  ["evidence", "evidence collection"],
  ["validat", "validation"],
  ["analys", "analysis"],
  ["report", "reporting"],
  ["recover", "recovery"],
] as const;

function attackChainCategory(domain: string): import("./AttackLesson").TechniqueCategory {
  if (domain === "reconnaissance" || domain === "enumeration") return "recon";
  if (domain === "reporting" || domain === "validation" || domain === "evidence collection") return "defensive_detection";
  return "post_exploitation";
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function stableId(prefix: string, value: string): string {
  return `${prefix}_${sha256(value).slice(0, 32)}`;
}

function parseJsonObject(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function ratio(numerator: number, denominator: number, whenEmpty = 0): number {
  if (denominator <= 0) return whenEmpty;
  return Number(Math.max(0, Math.min(1, numerator / denominator)).toFixed(4));
}

function count(value: number | null | undefined): number {
  return Number.isFinite(value) ? Number(value) : 0;
}

function safeActionDomain(actionClasses: readonly string[]): string {
  const joined = actionClasses.join(" ").toLocaleLowerCase("en-US");
  for (const [signal, label] of SAFE_ACTION_DOMAINS) {
    if (joined.includes(signal)) return label;
  }
  return "specialist execution";
}

function assertReusableStatementIsSafe(statement: string): void {
  if (redactLessonText(statement) !== statement || findRejectableSecrets(statement).length > 0) {
    throw new Error("Generated lesson statement contained secret material");
  }
  if (findReusableContentIdentifiers(statement).length > 0) {
    throw new Error("Generated lesson statement contained target-specific material");
  }
}

function evaluationFromRow(
  row: EvaluationRow,
  terminalStatus: EvaluatedTerminalStatus,
  comparison: StoredRunComparison,
  proposedLessonIds: readonly string[],
): StoredRunEvaluation {
  return {
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    journey: row.journey,
    terminalStatus,
    scores: parseJsonObject(row.scores_json) as Record<string, number | null>,
    metrics: parseJsonObject(row.metrics_json) as Record<string, number | string | null>,
    retrospective: row.retrospective,
    evidenceCoverage: row.evidence_coverage,
    createdBy: row.created_by,
    createdAt: row.created_at,
    comparison,
    proposedLessonIds,
  };
}

/**
 * Evidence-gated terminal evaluation and candidate-learning pipeline.
 *
 * All values are computed from canonical records. Reusable lesson prose is
 * assembled only from controlled vocabulary; mission names, objectives,
 * targets, provider output, credentials and raw evidence never enter it.
 */
export class RunLearningService {
  readonly #memory: MemoryRepository;
  readonly #comparisons: RunComparisonService;
  readonly #clock: () => Date;

  constructor(
    readonly database: SqliteDatabase,
    readonly options: ServiceOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#memory = new MemoryRepository(database, { clock: this.#clock });
    this.#comparisons = new RunComparisonService(database);
  }

  recordTerminalEvaluation(input: RecordRunEvaluationInput): StoredRunEvaluation {
    return inImmediateTransaction(this.database, () => {
      const run = this.database.prepare(`
        SELECT r.id, r.mission_id, r.journey, r.status, m.engagement_id,
          r.started_at, r.ended_at, r.created_at, r.retry_count, r.replan_count,
          r.budget_json, r.budget_usage_json
        FROM runs r JOIN missions m ON m.id = r.mission_id WHERE r.id = ?
      `).get(input.runId) as RunRow | undefined;
      if (!run) throw new Error(`Cannot evaluate missing run: ${input.runId}`);
      if (run.status !== input.terminalStatus) {
        throw new Error(`Run ${input.runId} is ${run.status}, not ${input.terminalStatus}`);
      }

      const prior = this.database.prepare("SELECT * FROM run_evaluations WHERE run_id = ?")
        .get(input.runId) as EvaluationRow | undefined;
      if (prior) {
        const comparison = this.#comparisons.record({
          evaluationId: prior.id,
          runId: run.id,
          missionId: run.mission_id,
          engagementId: run.engagement_id,
          journey: run.journey,
          terminalStatus: input.terminalStatus,
          endedAt: run.ended_at,
          evaluationCreatedAt: prior.created_at,
          scores: parseJsonObject(prior.scores_json),
          metrics: parseJsonObject(prior.metrics_json),
          evidenceCoverage: prior.evidence_coverage,
        });
        return evaluationFromRow(prior, input.terminalStatus, comparison, this.#lessonIdsForRun(input.runId));
      }

      const now = this.#clock().toISOString();
      const calculated = this.#calculate(run, input.outcome, input.terminalStatus);
      const evaluationId = stableId("eval", run.id);
      this.database.prepare(`
        INSERT INTO run_evaluations (
          id, mission_id, run_id, journey, scores_json, metrics_json,
          retrospective, evidence_coverage, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        evaluationId,
        run.mission_id,
        run.id,
        run.journey,
        JSON.stringify(calculated.scores),
        JSON.stringify(calculated.metrics),
        calculated.retrospective,
        calculated.evidenceCoverage,
        input.createdBy,
        now,
      );
      const comparison = this.#comparisons.record({
        evaluationId,
        runId: run.id,
        missionId: run.mission_id,
        engagementId: run.engagement_id,
        journey: run.journey,
        terminalStatus: input.terminalStatus,
        endedAt: run.ended_at,
        evaluationCreatedAt: now,
        scores: calculated.scores,
        metrics: calculated.metrics,
        evidenceCoverage: calculated.evidenceCoverage,
      });

      const evaluationNodeId = this.#persistEvaluationNode({
        evaluationId,
        run,
        calculated,
        now,
      });
      const proposedLessonIds = this.#proposeLessons({
        evaluationId,
        evaluationNodeId,
        run,
        terminalStatus: input.terminalStatus,
        evidenceCoverage: calculated.evidenceCoverage,
        now,
      });

      this.options.events?.append({
        missionId: run.mission_id,
        runId: run.id,
        journey: run.journey,
        eventType: "run.evaluation_recorded",
        actorType: "agent",
        actorId: input.createdBy,
        summary: `Recorded the evidence-gated ${run.journey} terminal evaluation`,
        payload: {
          evaluationId,
          terminalStatus: input.terminalStatus,
          evidenceCoverage: calculated.evidenceCoverage,
          comparisonStatus: comparison.status,
          comparisonBasis: comparison.basis,
          proposedLessonIds: [...proposedLessonIds],
        },
      });

      const row = this.database.prepare("SELECT * FROM run_evaluations WHERE id = ?")
        .get(evaluationId) as EvaluationRow;
      return evaluationFromRow(row, input.terminalStatus, comparison, proposedLessonIds);
    });
  }

  #calculate(
    run: RunRow,
    outcome: MissionCompletionEvaluation | undefined,
    terminalStatus: EvaluatedTerminalStatus,
  ): EvaluationCalculation {
    const actions = this.database.prepare(`
      SELECT COUNT(*) AS count,
        SUM(status = 'succeeded') AS succeeded,
        SUM(status = 'failed') AS failed,
        SUM(status = 'denied') AS denied,
        SUM(status = 'cancelled') AS cancelled,
        COUNT(DISTINCT fingerprint) AS unique_count,
        SUM(retry_count) AS retries,
        SUM(progress_signature IS NOT NULL AND length(trim(progress_signature)) > 0) AS with_progress
      FROM actions WHERE run_id = ?
    `).get(run.id) as AggregateRow;
    const actionCount = count(actions.count);
    const succeededActions = count(actions.succeeded);
    const failedActions = count(actions.failed);
    const deniedActions = count(actions.denied);
    const cancelledActions = count(actions.cancelled);
    const uniqueActions = count(actions.unique_count);
    const actionRetries = count(actions.retries);
    const actionsWithProgress = count(actions.with_progress);
    const noProgressActionCount = Math.max(0, actionCount - actionsWithProgress);

    const evidence = this.database.prepare(`
      SELECT
        SUM(CASE WHEN ${evidenceRecordSql("evidence")} THEN 1 ELSE 0 END) AS count,
        SUM(CASE WHEN ${verifiedEvidenceSql("evidence")} THEN 1 ELSE 0 END) AS verified,
        MIN(CASE WHEN ${verifiedEvidenceSql("evidence")} THEN acquired_at END) AS first_meaningful_at
      FROM evidence WHERE run_id = ?
    `).get(run.id) as AggregateRow;
    const evidenceCount = count(evidence.count);
    const verifiedEvidenceCount = count(evidence.verified);

    const findings = this.database.prepare(`
      SELECT COUNT(*) AS count,
        SUM(review_status = 'verified' AND (
          operator_override = 1 OR EXISTS (
            SELECT 1 FROM finding_evidence fe WHERE fe.finding_id = findings.id
          )
        )) AS verified
      FROM findings WHERE run_id = ?
    `).get(run.id) as AggregateRow;
    const findingCount = count(findings.count);
    const verifiedFindingCount = count(findings.verified);

    const assignments = this.database.prepare(`
      SELECT COUNT(*) AS count, SUM(status = 'completed') AS completed
      FROM assignments WHERE run_id = ?
    `).get(run.id) as AggregateRow;
    const assignmentCount = count(assignments.count);
    const completedAssignments = count(assignments.completed);

    const toolCalls = this.database.prepare(`
      SELECT COUNT(*) AS count, SUM(status = 'succeeded') AS succeeded
      FROM tool_calls WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
    `).get(run.id) as AggregateRow;
    const toolCallCount = count(toolCalls.count);
    const succeededToolCalls = count(toolCalls.succeeded);

    const providerTurns = this.database.prepare(`
      SELECT COUNT(*) AS count, SUM(status = 'completed') AS completed,
        SUM(COALESCE(input_tokens, 0) + COALESCE(output_tokens, 0)) AS tokens,
        SUM(COALESCE(estimated_cost, 0)) AS cost
      FROM provider_turns WHERE run_id = ?
    `).get(run.id) as AggregateRow;
    const providerTurnCount = count(providerTurns.count);
    const completedProviderTurns = count(providerTurns.completed);
    const providerTokens = count(providerTurns.tokens);
    const estimatedCost = Number(providerTurns.cost ?? 0);

    const guided = this.database.prepare(`
      SELECT COUNT(*) AS count,
        SUM(status IN ('approved', 'manual')) AS exact_bound,
        SUM(status IN ('rejected', 'alternative')) AS corrections
      FROM guided_decisions WHERE run_id = ?
    `).get(run.id) as AggregateRow;
    const guidedDecisionCount = count(guided.count);
    const exactGuidedDecisionCount = count(guided.exact_bound);
    const operatorCorrectionCount = count(guided.corrections);
    const unboundGuidedActions = Number((this.database.prepare(`
      SELECT COUNT(*) AS count FROM actions
      WHERE run_id = ? AND guided_decision_id IS NULL
    `).get(run.id) as AggregateRow).count);

    const context = this.database.prepare(`
      SELECT COUNT(mci.node_id) AS count, SUM(mci.used) AS used,
        SUM(mci.corrected) AS corrected
      FROM memory_context_packs mcp
      LEFT JOIN memory_context_items mci ON mci.context_pack_id = mcp.id
      WHERE mcp.run_id = ?
    `).get(run.id) as AggregateRow;
    const memoriesRetrieved = count(context.count);
    const memoriesUsed = count(context.used);
    const memoriesCorrected = count(context.corrected);

    const events = this.database.prepare(`
      SELECT
        SUM(event_type LIKE 'policy.%' AND event_type NOT LIKE '%.allowed') AS denied,
        SUM(event_type LIKE 'run.recovery%' OR
          (event_type = 'run.state_changed' AND payload_json LIKE '%\"recovering\"%')) AS retries,
        SUM(event_type = 'run.state_changed' AND payload_json LIKE '%waiting_guided_decision%') AS corrections
      FROM events WHERE run_id = ?
    `).get(run.id) as AggregateRow;
    const policyViolationCount = count(events.denied) + deniedActions;
    const recoveryCount = count(events.retries);
    const autonomousUserWaitCount = run.journey === "autonomous" ? count(events.corrections) : 0;

    const artifacts = this.database.prepare(`
      SELECT COUNT(*) AS count,
        SUM(artifact_type IN ('mission_report', 'report')) AS reports
      FROM artifacts WHERE run_id = ?
    `).get(run.id) as AggregateRow;
    const artifactCount = count(artifacts.count);
    const reportCount = count(artifacts.reports);

    const criteria = outcome?.criteria ?? [];
    const satisfiedCriteria = criteria.filter((criterion) => criterion.satisfied).length;
    const verifiedIds = new Set((this.database.prepare(`
      SELECT id FROM evidence WHERE run_id = ? AND ${verifiedEvidenceSql("evidence")}
    `).all(run.id) as Array<{ id: string }>).map((row) => row.id));
    const evidenceBackedCriteria = criteria.filter((criterion) =>
      criterion.satisfied && criterion.evidenceIds.some((evidenceId) => verifiedIds.has(evidenceId))).length;
    const successCriteriaCoverage = criteria.length > 0
      ? ratio(satisfiedCriteria, criteria.length)
      : terminalStatus === "completed" ? 1 : 0;
    const evidenceCoverage = criteria.length > 0
      ? ratio(evidenceBackedCriteria, criteria.length)
      : ratio(verifiedEvidenceCount, Math.max(1, evidenceCount));

    const budget = parseJsonObject(run.budget_json);
    const usage = parseJsonObject(run.budget_usage_json);
    const startedAt = run.started_at ?? run.created_at;
    const endedAt = run.ended_at ?? this.#clock().toISOString();
    const durationMs = Math.max(0, Date.parse(endedAt) - Date.parse(startedAt));
    const firstMeaningfulEvidenceAt = evidence.first_meaningful_at ?? null;
    const firstMeaningfulEvidenceTimestamp = firstMeaningfulEvidenceAt === null
      ? Number.NaN
      : Date.parse(firstMeaningfulEvidenceAt);
    const timeToFirstMeaningfulEvidenceMs = Number.isFinite(firstMeaningfulEvidenceTimestamp)
      ? Math.max(0, firstMeaningfulEvidenceTimestamp - Date.parse(startedAt))
      : null;
    const wallClockLimit = numberValue(budget.wallClockMs)
      ?? (numberValue(budget.timeBudgetMinutes) !== null
        ? numberValue(budget.timeBudgetMinutes)! * 60_000
        : null);
    const timeEfficiency = wallClockLimit === null || wallClockLimit === 0
      ? null
      : ratio(Math.max(0, wallClockLimit - durationMs), wallClockLimit, 0);
    const tokenLimit = numberValue(budget.providerTokens) ?? numberValue(budget.tokenBudget);
    const tokenEfficiency = tokenLimit === null || tokenLimit === 0
      ? null
      : ratio(Math.max(0, tokenLimit - providerTokens), tokenLimit, 0);
    const costLimit = numberValue(budget.estimatedCost) ?? numberValue(budget.costBudget);
    const costEfficiency = costLimit === null || costLimit === 0
      ? null
      : ratio(Math.max(0, costLimit - estimatedCost), costLimit, 0);

    const repeatedActionRate = ratio(Math.max(0, actionCount - uniqueActions), actionCount);
    const retryRate = ratio(run.retry_count + actionRetries, Math.max(1, actionCount + run.retry_count + actionRetries));
    const evidenceQuality = ratio(verifiedEvidenceCount, evidenceCount);
    const findingQuality = findingCount > 0 ? ratio(verifiedFindingCount, findingCount) : null;
    const journeyAdherence = run.journey === "autonomous"
      ? (autonomousUserWaitCount === 0 && guidedDecisionCount === 0 ? 1 : 0)
      : ratio(actionCount - unboundGuidedActions, actionCount, 1);
    const policyCompliance = ratio(Math.max(0, actionCount - policyViolationCount), actionCount, policyViolationCount === 0 ? 1 : 0);
    const recoveryQuality = recoveryCount === 0 ? 1 : terminalStatus === "completed" ? 1 : 0;
    const memoryContextPrecision = memoriesRetrieved > 0
      ? ratio(memoriesUsed, memoriesRetrieved)
      : null;
    const preferenceCorrectionRate = memoriesRetrieved > 0
      ? ratio(memoriesCorrected, memoriesRetrieved)
      : null;
    const operatorInterventionCount = run.journey === "guided"
      ? guidedDecisionCount
      : autonomousUserWaitCount;
    const toolCallSuccessRate = toolCallCount > 0
      ? ratio(succeededToolCalls, toolCallCount)
      : null;

    const scores: Record<string, number | null> = {
      objectiveCompletion: terminalStatus === "completed" && outcome?.success !== false ? 1 : 0,
      successCriteriaCoverage,
      evidenceQuality,
      findingQuality,
      policyCompliance,
      journeyAdherence,
      memoryUsefulness: memoriesRetrieved > 0 ? ratio(memoriesUsed - memoriesCorrected, memoriesRetrieved) : null,
      timeEfficiency,
      tokenEfficiency,
      costEfficiency,
      toolCallEfficiency: toolCallCount > 0 ? ratio(succeededToolCalls, toolCallCount) : null,
      repeatedActionAvoidance: Number((1 - repeatedActionRate).toFixed(4)),
      retryAvoidance: Number((1 - retryRate).toFixed(4)),
      recoveryQuality,
      delegationQuality: assignmentCount > 0 ? ratio(completedAssignments, assignmentCount) : null,
      reportQuality: artifactCount > 0 ? ratio(reportCount, 1) : null,
      uncertaintyCalibration: criteria.length > 0 ? evidenceCoverage : null,
    };
    const metrics: Record<string, number | string | null> = {
      terminalStatus,
      durationMs,
      timeToFirstMeaningfulEvidenceMs,
      actionCount,
      succeededActions,
      failedActions,
      deniedActions,
      cancelledActions,
      uniqueActionFingerprints: uniqueActions,
      actionsWithMeaningfulProgress: actionsWithProgress,
      noProgressActionCount,
      repeatedActionRate,
      retryCount: run.retry_count + actionRetries,
      retryRate,
      replanCount: run.replan_count,
      evidenceCount,
      verifiedEvidenceCount,
      findingCount,
      verifiedFindingCount,
      assignmentCount,
      completedAssignments,
      toolCallCount,
      succeededToolCalls,
      toolCallSuccessRate,
      providerTurnCount,
      completedProviderTurns,
      providerTokens: numberValue(usage.providerTokens) ?? providerTokens,
      estimatedCost: numberValue(usage.estimatedCost) ?? estimatedCost,
      guidedDecisionCount,
      exactGuidedDecisionCount,
      operatorCorrectionCount,
      operatorInterventionCount,
      autonomousUserWaitCount,
      policyViolationCount,
      recoveryCount,
      recoverySuccessRate: recoveryCount > 0 ? recoveryQuality : null,
      artifactCount,
      reportCount,
      memoriesRetrieved,
      memoriesUsed,
      memoriesCorrected,
      memoryContextPrecision,
      preferenceCorrectionRate,
      successCriteriaCount: criteria.length,
      satisfiedCriteriaCount: satisfiedCriteria,
      evidenceBackedCriteriaCount: evidenceBackedCriteria,
    };
    const retrospective = [
      `${run.journey === "autonomous" ? "Autonomous" : "Guided"} run ended ${terminalStatus}.`,
      `${satisfiedCriteria}/${criteria.length} evaluated success criteria were satisfied; ${evidenceBackedCriteria}/${criteria.length} were backed by verified retained evidence.`,
      `${succeededActions}/${actionCount} actions succeeded, with ${Math.round(repeatedActionRate * 100)}% repeated-action rate and ${run.retry_count + actionRetries} retries.`,
      `${policyViolationCount} policy violations and ${operatorCorrectionCount} operator corrections were recorded.`,
    ].join(" ");
    return { scores, metrics, retrospective, evidenceCoverage };
  }

  #persistEvaluationNode(input: {
    evaluationId: string;
    run: RunRow;
    calculated: EvaluationCalculation;
    now: string;
  }): string {
    const nodeId = stableId("mem_eval", input.evaluationId);
    if (this.#memory.getNode(nodeId, true)) return nodeId;
    this.#memory.createNode({
      id: nodeId,
      nodeType: "evaluation",
      title: `${input.run.journey === "autonomous" ? "Autonomous" : "Guided"} run evaluation`,
      summary: input.calculated.retrospective,
      body: "Evidence-gated terminal assessment. Open the linked canonical evaluation for complete metrics.",
      scope: { kind: "mission", missionId: input.run.mission_id },
      sensitivity: "private",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "not_required",
      provenance: {
        method: "derived",
        explanation: "Calculated from canonical run, action, evidence, finding, policy and journey records.",
        sources: [{
          sourceType: "run_evaluation",
          sourceId: input.evaluationId,
          acquiredAt: input.now,
          sourceHash: sha256(JSON.stringify(input.calculated)),
        }],
      },
      authorType: "agent",
      authorId: AUTHORING_AGENT,
      retentionPolicy: { allowAutonomous: true, allowGuided: true },
    });
    return nodeId;
  }

  #proposeLessons(input: {
    evaluationId: string;
    evaluationNodeId: string;
    run: RunRow;
    terminalStatus: EvaluatedTerminalStatus;
    evidenceCoverage: number;
    now: string;
  }): string[] {
    if (input.terminalStatus === "cancelled") return [];
    const verifiedEvidenceIds = (this.database.prepare(`
      SELECT id FROM evidence WHERE run_id = ? AND ${verifiedEvidenceSql("evidence")} ORDER BY id
    `).all(input.run.id) as Array<{ id: string }>).map((row) => row.id);
    if (input.terminalStatus === "completed" && verifiedEvidenceIds.length === 0) return [];

    const actionClasses = (this.database.prepare(`
      SELECT DISTINCT action_class FROM actions WHERE run_id = ? ORDER BY action_class
    `).all(input.run.id) as Array<{ action_class: string }>).map((row) => row.action_class);
    const domain = safeActionDomain(actionClasses);
    const statement = input.terminalStatus === "completed"
      ? `For comparable authorized ${domain} work, use bounded specialist steps and require verified evidence before declaring success.`
      : `For comparable authorized ${domain} work, do not repeat a failed action unless the failure category or execution conditions materially change.`;
    assertReusableStatementIsSafe(statement);

    const applicabilityScope = input.run.engagement_id ? "engagement" : "mission";
    const engagementId = input.run.engagement_id;
    const missionId = input.run.engagement_id ? null : input.run.mission_id;
    const scopeKey = input.run.engagement_id ?? input.run.mission_id;
    const lessonType = input.terminalStatus === "completed" ? "attack_chain" : "failed_attempt";
    const lessonId = stableId("lesson", `${lessonType}\n${applicabilityScope}\n${scopeKey}\n${statement.toLocaleLowerCase("en-US")}`);
    const existing = this.database.prepare(`
      SELECT id, status FROM lessons
      WHERE lower(statement) = lower(?) AND lesson_type = ? AND applicability_scope = ?
        AND engagement_id IS ? AND mission_id IS ?
        AND status NOT IN ('rejected', 'superseded')
      ORDER BY created_at LIMIT 1
    `).get(statement, lessonType, applicabilityScope, engagementId, missionId) as { id: string; status: string } | undefined;
    const effectiveLessonId = existing?.id ?? lessonId;
    if (!existing) {
      const expiresAt = new Date(Date.parse(input.now) + 90 * 24 * 60 * 60 * 1_000).toISOString();
      this.database.prepare(`
        INSERT INTO lessons (
          id, statement, lesson_type, applicability_scope, engagement_id, mission_id,
          failure_category, retry_conditions, confidence, expected_benefit, risk,
          status, authoring_agent_id, expires_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?, ?, ?)
      `).run(
        effectiveLessonId,
        statement,
        lessonType,
        applicabilityScope,
        engagementId,
        missionId,
        input.terminalStatus === "failed" ? "run_failed" : null,
        input.terminalStatus === "failed"
          ? "Retry only after the classified failure or relevant execution conditions materially change."
          : null,
        Number(Math.min(0.9, 0.55 + input.evidenceCoverage * 0.35).toFixed(4)),
        input.terminalStatus === "completed"
          ? "Preserve evidence quality while reducing unsupported completion claims."
          : "Avoid repeating an ineffective action without a materially different basis.",
        "May overgeneralize from one run; independent evidence review is required before verification.",
        AUTHORING_AGENT,
        expiresAt,
        input.now,
        input.now,
      );
    }

    this.#linkLessonSupport(effectiveLessonId, input.run.id, null, input.now);
    for (const evidenceId of verifiedEvidenceIds) {
      this.#linkLessonSupport(effectiveLessonId, null, evidenceId, input.now);
    }
    if (
      input.terminalStatus === "completed" &&
      (!existing || existing.status === "proposed")
    ) {
      this.#retainCompletedAttackChain({
        lessonId: effectiveLessonId,
        evaluationId: input.evaluationId,
        run: input.run,
        verifiedEvidenceIds,
        domain,
      });
    }
    const lessonNodeId = this.#persistLessonNode({
      lessonId: effectiveLessonId,
      run: input.run,
      statement,
      now: input.now,
    });
    const edgeId = stableId("medge", `${input.evaluationNodeId}\nproduced\n${lessonNodeId}`);
    const edgeExists = this.database.prepare("SELECT 1 FROM memory_edges WHERE id = ?").get(edgeId);
    if (!edgeExists) {
      this.#memory.createEdge({
        id: edgeId,
        sourceNodeId: input.evaluationNodeId,
        targetNodeId: lessonNodeId,
        edgeType: "produced",
        title: "Produced candidate lesson",
        summary: "The terminal evaluation produced an evidence-linked candidate for independent review.",
        scope: input.run.engagement_id
          ? { kind: "engagement", engagementId: input.run.engagement_id }
          : { kind: "mission", missionId: input.run.mission_id },
        sensitivity: "private",
        confidence: 0.75,
        lifecycleStatus: "candidate",
        provenance: {
          method: "derived",
          explanation: "The candidate was derived from the terminal evaluation and its canonical support links.",
          sources: [{ sourceType: "run_evaluation", sourceId: input.evaluationId, acquiredAt: input.now }],
        },
        explanation: "Links a DB-derived run evaluation to an unverified candidate lesson.",
        authorType: "agent",
        authorId: AUTHORING_AGENT,
      });
    }
    if (!existing) {
      this.options.events?.append({
        missionId: input.run.mission_id,
        runId: input.run.id,
        journey: input.run.journey,
        eventType: "learning.lesson_proposed",
        actorType: "agent",
        actorId: AUTHORING_AGENT,
        summary: "Proposed an evidence-linked lesson for independent review",
        payload: { lessonId: effectiveLessonId, evaluationId: input.evaluationId, status: "proposed" },
      });
    }
    return [effectiveLessonId];
  }

  #retainCompletedAttackChain(input: {
    lessonId: string;
    evaluationId: string;
    run: RunRow;
    verifiedEvidenceIds: readonly string[];
    domain: string;
  }): void {
    const actionRows = this.database.prepare(`
      SELECT id, action_type, action_class, normalized_arguments_json
      FROM actions
      WHERE run_id = ? AND status = 'succeeded'
      ORDER BY ended_at, id
    `).all(input.run.id) as Array<{
      id: string;
      action_type: string;
      action_class: string;
      normalized_arguments_json: string;
    }>;
    const toolCallRows = this.database.prepare(`
      SELECT tc.id, tc.action_id, tc.tool_name, tc.normalized_arguments_json
      FROM tool_calls tc
      JOIN actions a ON a.id = tc.action_id
      WHERE a.run_id = ? AND a.status = 'succeeded' AND tc.status = 'succeeded'
      ORDER BY a.ended_at, a.id, tc.created_at, tc.id
    `).all(input.run.id) as Array<{
      id: string;
      action_id: string;
      tool_name: string;
      normalized_arguments_json: string;
    }>;
    const actions: CanonicalLearningAction[] = actionRows.map((row) => ({
      id: row.id,
      actionType: row.action_type,
      actionClass: row.action_class,
      normalizedArgumentsJson: row.normalized_arguments_json,
    }));
    const toolCalls: CanonicalLearningToolCall[] = toolCallRows.map((row) => ({
      id: row.id,
      actionId: row.action_id,
      toolName: row.tool_name,
      normalizedArgumentsJson: row.normalized_arguments_json,
    }));
    const projection = projectSafeAttackChain({ actions, toolCalls, fallbackDomain: input.domain });
    const evaluation = this.database.prepare(`
      SELECT scores_json, metrics_json FROM run_evaluations WHERE id = ?
    `).get(input.evaluationId) as { scores_json: string; metrics_json: string } | undefined;
    const sourceHash = sha256(JSON.stringify(evaluation ?? { evaluationId: input.evaluationId }));
    const sources = [
      {
        sourceType: "run_evaluation" as const,
        sourceId: input.evaluationId,
        sourceHash,
        runId: input.run.id,
      },
      ...input.verifiedEvidenceIds.map((evidenceId) => ({
        sourceType: "run_evaluation" as const,
        sourceId: input.evaluationId,
        sourceHash,
        runId: input.run.id,
        evidenceId,
      })),
    ];
    new AttackChainLearningService(this.database, { clock: this.#clock }).retainCandidateDetails(
      input.lessonId,
      {
        title: `Bounded ${input.domain} chain with verified evidence`,
        techniqueName: `${input.domain.slice(0, 1).toLocaleUpperCase("en-US")}${input.domain.slice(1)} workflow`,
        techniqueCategory: attackChainCategory(input.domain),
        summary: `Apply bounded ${input.domain} through assigned specialists and retain verified evidence before advancing.`,
        prerequisites: [
          "Confirmed authorization and normalized target scope",
          "The assigned specialist and required capability are available",
        ],
        observedSignals: [
          "A bounded specialist action produces a distinct verified evidence record",
        ],
        orderedSteps: projection.orderedSteps,
        tools: projection.tools,
        publicReferences: projection.publicReferences,
        validationCheckpoints: [
          "Confirm each claimed result is linked to a verified immutable evidence ID before advancing",
        ],
        failureRecovery: [
          "If an action produces no new evidence, classify the failure and materially change conditions before one bounded retry",
        ],
        antiReuseWarnings: projection.antiReuseWarnings,
        expectedOutcome: "The bounded workflow advances only when verified evidence supports the result",
        reuseGuidance: "Retrieve only after independent approval and only when the prerequisite signals match",
        confidence: Number(Math.min(0.9, 0.55 + input.verifiedEvidenceIds.length * 0.05).toFixed(4)),
        scope: input.run.engagement_id ? "project" : "mission",
        sources,
      },
      AUTHORING_AGENT,
    );
  }

  #linkLessonSupport(
    lessonId: string,
    runId: string | null,
    evidenceId: string | null,
    now: string,
  ): void {
    const exists = this.database.prepare(`
      SELECT 1 FROM lesson_evidence
      WHERE lesson_id = ? AND evidence_id IS ? AND run_id IS ? AND relationship = 'supports'
    `).get(lessonId, evidenceId, runId);
    if (exists) return;
    this.database.prepare(`
      INSERT INTO lesson_evidence (
        lesson_id, evidence_id, run_id, relationship, rationale, created_at
      ) VALUES (?, ?, ?, 'supports', ?, ?)
    `).run(
      lessonId,
      evidenceId,
      runId,
      evidenceId
        ? "Verified immutable evidence directly supports this candidate."
        : "The canonical terminal run and evaluation support this candidate.",
      now,
    );
  }

  #persistLessonNode(input: {
    lessonId: string;
    run: RunRow;
    statement: string;
    now: string;
  }): string {
    const nodeId = canonicalLessonMemoryNodeId(input.lessonId);
    if (this.#memory.getNode(nodeId, true)) return nodeId;
    this.#memory.createNode({
      id: nodeId,
      nodeType: "lesson",
      title: "Candidate operational lesson",
      summary: input.statement,
      body: "Pending independent evidence review. This agent-authored candidate is not trusted planning context.",
      scope: input.run.engagement_id
        ? { kind: "engagement", engagementId: input.run.engagement_id }
        : { kind: "mission", missionId: input.run.mission_id },
      sensitivity: "private",
      confidence: 0.75,
      lifecycleStatus: "candidate",
      confirmationState: "pending",
      provenance: {
        method: "derived",
        explanation: "Proposed by the run evaluator from canonical terminal records; not self-approved.",
        sources: [{ sourceType: "lesson", sourceId: input.lessonId, acquiredAt: input.now }],
      },
      authorType: "agent",
      authorId: AUTHORING_AGENT,
      retentionPolicy: { allowAutonomous: false, allowGuided: false },
    });
    return nodeId;
  }

  #lessonIdsForRun(runId: string): string[] {
    return (this.database.prepare(`
      SELECT DISTINCT lesson_id FROM lesson_evidence WHERE run_id = ? ORDER BY lesson_id
    `).all(runId) as Array<{ lesson_id: string }>).map((row) => row.lesson_id);
  }
}

import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import type { EventRepository } from "../events";
import {
  MemoryRepository,
  terminalAttackKnowledgeReviewRetentionPolicy,
  type ContextPackItemDisposition,
  type MemoryNode,
} from "../memory";
import {
  CanonicalMissionMemoryGraph,
  type BrainContextResult,
} from "../brain-runtime";
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
import {
  CANONICAL_REPORT_ARTIFACT_COMMITMENT_SCHEMA_VERSION,
  CANONICAL_REPORT_ARTIFACT_TYPES,
  type CanonicalReportArtifactCommitment,
} from "../reports";

export type EvaluatedTerminalStatus = "completed" | "failed" | "cancelled";

export interface RecordRunEvaluationInput {
  readonly runId: string;
  readonly terminalStatus: EvaluatedTerminalStatus;
  readonly createdBy: string;
  readonly outcome?: MissionCompletionEvaluation;
  readonly terminalLessonMemoryApplication?: TerminalLessonMemoryApplication;
  /**
   * Accepted only inside the compensated Autonomous terminal closeout.
   * The closeout owner must materialize and verify this exact artifact pair
   * before its outer transaction is allowed to commit.
   */
  readonly terminalReportCommitment?: CanonicalReportArtifactCommitment;
}

export interface TerminalLessonMemoryApplication {
  readonly contextPackId: string;
  readonly candidateStatementHash: string;
  readonly disposition:
    | "propose"
    | "reuse_verified_lesson"
    | "reuse_verified_lesson_with_contradiction";
  readonly reusedLessonId?: string;
  readonly usedNodeIds: readonly string[];
  readonly contradictionNodeIds: readonly string[];
  readonly contextDispositions: readonly ContextPackItemDisposition[];
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

function validateTerminalReportCommitment(
  commitment: CanonicalReportArtifactCommitment | undefined,
  run: RunRow,
  terminalStatus: EvaluatedTerminalStatus,
): CanonicalReportArtifactCommitment | undefined {
  if (!commitment) return undefined;
  const expectedTypes = [
    CANONICAL_REPORT_ARTIFACT_TYPES.markdown,
    CANONICAL_REPORT_ARTIFACT_TYPES.json,
  ] as const;
  if (
    run.journey !== "autonomous"
    || terminalStatus === "cancelled"
    || commitment.schemaVersion !== CANONICAL_REPORT_ARTIFACT_COMMITMENT_SCHEMA_VERSION
    || commitment.runId !== run.id
    || !Number.isSafeInteger(commitment.reportVersion)
    || commitment.reportVersion < 1
    || commitment.reportVersion > 999
    || !Array.isArray(commitment.artifactTypes)
    || commitment.artifactTypes.length !== expectedTypes.length
    || commitment.artifactTypes.some((type, index) => type !== expectedTypes[index])
  ) {
    throw new Error("Terminal report commitment does not match the canonical Autonomous report boundary");
  }
  return commitment;
}

interface ServiceOptions {
  readonly clock?: () => Date;
  readonly events?: EventRepository;
  readonly memoryGraph?: CanonicalMissionMemoryGraph;
  /** Called only after the evaluation transaction commits. */
  readonly projectMemoryNodes?: (nodeIds: readonly string[]) => void;
}

interface EvaluationCalculation {
  readonly scores: Record<string, number | null>;
  readonly metrics: Record<string, number | string | null>;
  readonly retrospective: string;
  readonly evidenceCoverage: number;
}

interface TerminalLessonCandidate {
  readonly statement: string;
  readonly statementHash: string;
  readonly lessonType: "attack_chain" | "failed_attempt";
  readonly domain: string;
}

interface ReviewedLessonMatch {
  readonly lessonId: string;
  readonly node: MemoryNode;
  readonly rank: number;
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

function completedConfidence(status: EvaluatedTerminalStatus): number {
  return status === "completed" ? 0.75 : 0.6;
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

function normalizeLessonStatement(value: string): string {
  return value.normalize("NFKC").trim().replace(/\s+/gu, " ").toLocaleLowerCase("en-US");
}

function terminalLessonCandidate(
  actionClasses: readonly string[],
  terminalStatus: Exclude<EvaluatedTerminalStatus, "cancelled">,
): TerminalLessonCandidate {
  const domain = safeActionDomain(actionClasses);
  const statement = terminalStatus === "completed"
    ? `For comparable authorized ${domain} work, use bounded specialist steps and require verified evidence before declaring success.`
    : `For comparable authorized ${domain} work, do not repeat a failed action unless the failure category or execution conditions materially change.`;
  assertReusableStatementIsSafe(statement);
  return {
    statement,
    statementHash: sha256(normalizeLessonStatement(statement)),
    lessonType: terminalStatus === "completed" ? "attack_chain" : "failed_attempt",
    domain,
  };
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
  readonly #memoryGraph: CanonicalMissionMemoryGraph;
  readonly #comparisons: RunComparisonService;
  readonly #clock: () => Date;

  constructor(
    readonly database: SqliteDatabase,
    readonly options: ServiceOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#memory = new MemoryRepository(database, { clock: this.#clock });
    this.#memoryGraph = options.memoryGraph ?? new CanonicalMissionMemoryGraph(database, { clock: this.#clock });
    this.#comparisons = new RunComparisonService(database);
  }

  /**
   * Apply only independently reviewed, evidence-linked lesson memory to the
   * deterministic terminal candidate. Retrieval is not treated as influence:
   * this compiler accounts for every Context Pack item and selects only the
   * exact reviewed lesson that prevents a duplicate plus any explicit,
   * evidence-linked failure contradiction connected to that lesson.
   *
   * No provider is called, no fuzzy semantic judgment is made, and no lesson
   * lifecycle is changed.
   */
  compileTerminalLessonMemoryApplication(input: {
    readonly runId: string;
    readonly terminalStatus: Exclude<EvaluatedTerminalStatus, "cancelled">;
    readonly context: BrainContextResult;
  }): TerminalLessonMemoryApplication {
    const run = this.database.prepare(`
      SELECT r.id, r.mission_id, r.journey, r.status, m.engagement_id,
        r.started_at, r.ended_at, r.created_at, r.retry_count, r.replan_count,
        r.budget_json, r.budget_usage_json
      FROM runs r JOIN missions m ON m.id = r.mission_id WHERE r.id = ?
    `).get(input.runId) as RunRow | undefined;
    if (!run) throw new Error(`Cannot apply lesson memory to missing run: ${input.runId}`);
    if (run.journey !== "autonomous") {
      throw new Error("Terminal lesson memory application is reserved for Autonomous runs");
    }
    if (
      input.context.hook !== "lesson_proposal"
      || input.context.contextPack.runId !== run.id
      || input.context.contextPack.missionId !== run.mission_id
      || input.context.contextPack.journey !== "autonomous"
      || input.context.contextPack.scopePolicy.journey !== "autonomous"
      || input.context.contextPack.scopePolicy.missionId !== run.mission_id
      || (
        run.engagement_id !== null
        && input.context.contextPack.scopePolicy.engagementId !== run.engagement_id
      )
    ) {
      throw new Error("Lesson Context Pack does not match the terminal Autonomous run scope");
    }

    const actionClasses = (this.database.prepare(`
      SELECT DISTINCT action_class FROM actions WHERE run_id = ? ORDER BY action_class
    `).all(run.id) as Array<{ action_class: string }>).map((row) => row.action_class);
    const candidate = terminalLessonCandidate(actionClasses, input.terminalStatus);
    const ignoredReasons = new Map<string, string>();
    const matches: ReviewedLessonMatch[] = [];

    input.context.items.forEach((item, rank) => {
      const node = item.node;
      const eligibility = this.#reviewedLessonMatch({
        node,
        rank,
        run,
        candidate,
        allowGlobal: input.context.contextPack.scopePolicy.allowGlobal === true,
      });
      if (eligibility.match) {
        matches.push(eligibility.match);
      } else {
        ignoredReasons.set(node.id, eligibility.reason);
      }
    });

    matches.sort((left, right) => {
      const scopeRank = (node: MemoryNode): number =>
        node.scope.kind === "mission" ? 0 : node.scope.kind === "engagement" ? 1 : 2;
      return scopeRank(left.node) - scopeRank(right.node)
        || left.rank - right.rank
        || left.lessonId.localeCompare(right.lessonId);
    });
    const selected = matches[0];
    for (const duplicate of matches.slice(1)) {
      ignoredReasons.set(
        duplicate.node.id,
        "A more specific independently reviewed lesson supplied the exact duplicate-prevention basis.",
      );
    }

    const contradictionNodeIds: string[] = [];
    if (selected) {
      const contextFailures = new Map(input.context.items
        .filter(({ node }) => node.nodeType === "failure" || node.nodeType === "failure_mode")
        .map(({ node }) => [node.id, node] as const));
      for (const edge of this.#memory.listEdges(selected.node.id)) {
        if (
          edge.edgeType !== "contradicts"
          || (edge.lifecycleStatus !== "confirmed" && edge.lifecycleStatus !== "verified")
          || edge.provenance.sources.length === 0
          || !this.#scopeApplies(edge.scope, run, input.context.contextPack.scopePolicy.allowGlobal === true)
        ) continue;
        const otherNodeId = edge.sourceNodeId === selected.node.id
          ? edge.targetNodeId
          : edge.sourceNodeId;
        const failure = contextFailures.get(otherNodeId);
        if (
          !failure
          || !this.#eligibleAutonomousNode(
            failure,
            run,
            input.context.contextPack.scopePolicy.allowGlobal === true,
          )
          || !this.#nodeHasCanonicalEvidenceLink(failure.id)
        ) continue;
        contradictionNodeIds.push(failure.id);
      }
    }
    contradictionNodeIds.sort();

    const selectedNodeIds = new Set([
      ...(selected ? [selected.node.id] : []),
      ...contradictionNodeIds,
    ]);
    const contradictionSet = new Set(contradictionNodeIds);
    const contextDispositions: ContextPackItemDisposition[] = input.context.items.map((item) => {
      if (selected?.node.id === item.node.id) {
        return {
          nodeId: item.node.id,
          used: true,
          relevanceReason: item.relevanceReason,
          influenceSummary: contradictionNodeIds.length > 0
            ? "An exact independently reviewed lesson suppressed a duplicate candidate while its explicit failure contradiction remained visible for human review."
            : "An exact independently reviewed lesson suppressed a duplicate candidate and retained the current run as additional support.",
        };
      }
      if (contradictionSet.has(item.node.id)) {
        return {
          nodeId: item.node.id,
          used: true,
          relevanceReason: item.relevanceReason,
          influenceSummary: "An explicit evidence-linked failure contradiction was preserved; it did not demote, promote, or rewrite the reviewed lesson.",
        };
      }
      return {
        nodeId: item.node.id,
        used: false,
        relevanceReason: item.relevanceReason,
        ignoredReason: ignoredReasons.get(item.node.id)
          ?? (selectedNodeIds.size > 0
            ? "This item did not supply the exact reviewed lesson or an explicit evidence-linked contradiction used by the deterministic decision."
            : "This item did not provide an exact independently reviewed, evidence-linked lesson match for deterministic deduplication."),
      };
    });

    return {
      contextPackId: input.context.contextPack.id,
      candidateStatementHash: candidate.statementHash,
      disposition: selected
        ? contradictionNodeIds.length > 0
          ? "reuse_verified_lesson_with_contradiction"
          : "reuse_verified_lesson"
        : "propose",
      ...(selected ? { reusedLessonId: selected.lessonId } : {}),
      usedNodeIds: [...selectedNodeIds].sort(),
      contradictionNodeIds,
      contextDispositions,
    };
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
        this.#memoryGraph.ensureEvaluation(prior.id);
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

      const reportCommitment = validateTerminalReportCommitment(
        input.terminalReportCommitment,
        run,
        input.terminalStatus,
      );
      const now = this.#clock().toISOString();
      const calculated = this.#calculate(
        run,
        input.outcome,
        input.terminalStatus,
        reportCommitment,
      );
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

      const graph = this.#memoryGraph.ensureEvaluation(evaluationId);
      const proposedLessonIds = graph.status === "materialized" && graph.evaluationNodeId
        ? this.#proposeLessons({
            evaluationId,
            evaluationNodeId: graph.evaluationNodeId,
            run,
            terminalStatus: input.terminalStatus,
            evidenceCoverage: calculated.evidenceCoverage,
            now,
            memoryApplication: input.terminalLessonMemoryApplication,
          })
        : [];
      const reusableTerminalNodeIds = proposedLessonIds.length > 0
        ? this.#persistReusableTerminalAttackKnowledge({
            evaluationId,
            run,
            terminalStatus: input.terminalStatus,
            proposedLessonIds,
            now,
          })
        : [];

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
          reusableTerminalNodeIds: [...reusableTerminalNodeIds],
          lessonMemoryDisposition: input.terminalLessonMemoryApplication?.disposition ?? "not_applied",
          reusedLessonId: input.terminalLessonMemoryApplication?.reusedLessonId ?? null,
        },
      });

      const row = this.database.prepare("SELECT * FROM run_evaluations WHERE id = ?")
        .get(evaluationId) as EvaluationRow;
      return evaluationFromRow(row, input.terminalStatus, comparison, proposedLessonIds);
    });
  }

  /**
   * Project the privacy-safe terminal graph only from an explicit post-commit
   * boundary. MissionRuntimeEngine invokes this through a durable continuation
   * so a process crash between the canonical commit and the optional Vault
   * handoff is restart-safe. A sink may throw before accepting the handoff, or
   * it may isolate optional filesystem failures by persisting a degraded Vault
   * audit for later repair/reconciliation. Either outcome leaves the terminal
   * evaluation and canonical memory graph committed and authoritative.
   */
  projectTerminalMemory(runId: string): readonly string[] {
    if (this.database.inTransaction) {
      throw new Error("Terminal memory projection requires a committed database boundary");
    }
    const evaluation = this.database.prepare(`
      SELECT id FROM run_evaluations WHERE run_id = ?
    `).get(runId) as { id: string } | undefined;
    if (!evaluation) throw new Error(`Cannot project missing run evaluation: ${runId}`);

    const graph = this.#memoryGraph.ensureEvaluation(evaluation.id);
    const nodeIds = new Set(graph.nodeIds);
    for (const lessonId of this.#lessonIdsForRun(runId)) {
      const nodeId = canonicalLessonMemoryNodeId(lessonId);
      // Forgotten nodes remain tombstoned and must never be recreated or
      // exported by replay/reconciliation.
      if (this.#memory.getNode(nodeId)) nodeIds.add(nodeId);
    }
    for (const nodeId of this.#reusableTerminalNodeIds(evaluation.id, runId)) {
      nodeIds.add(nodeId);
    }
    for (const nodeId of this.#usedPlanningAttackProcedureNodeIds(runId)) {
      nodeIds.add(nodeId);
    }
    const selected = [...nodeIds];
    if (selected.length > 0) this.options.projectMemoryNodes?.(selected);
    return selected;
  }

  #usedPlanningAttackProcedureNodeIds(runId: string): readonly string[] {
    return (this.database.prepare(`
      SELECT DISTINCT node.id
      FROM memory_context_packs pack
      JOIN memory_context_items item ON item.context_pack_id = pack.id
      JOIN memory_nodes node ON node.id = item.node_id
      WHERE pack.run_id = ?
        AND pack.journey = 'autonomous'
        AND pack.purpose LIKE 'Mission planning:%'
        AND item.used = 1
        AND length(trim(COALESCE(item.influence_summary, ''))) > 0
        AND node.node_type = 'attack_procedure'
        AND node.scope = 'global'
        AND node.engagement_id IS NULL
        AND node.mission_id IS NULL
        AND node.lifecycle_status IN ('confirmed', 'verified')
        AND node.confirmation_state = 'confirmed'
        AND (node.expires_at IS NULL OR node.expires_at > ?)
      ORDER BY node.id
    `).all(runId, this.#clock().toISOString()) as Array<{ id: string }>).map(({ id }) => id);
  }

  #persistReusableTerminalAttackKnowledge(input: {
    evaluationId: string;
    run: RunRow;
    terminalStatus: EvaluatedTerminalStatus;
    proposedLessonIds: readonly string[];
    now: string;
  }): readonly string[] {
    if (input.run.journey !== "autonomous" || input.terminalStatus === "cancelled") return [];
    const procedureNodeIds = this.#usedPlanningAttackProcedureNodeIds(input.run.id);
    if (procedureNodeIds.length === 0) return [];

    const retainedNodeIds = new Set<string>();
    for (const procedureNodeId of procedureNodeIds) {
      const outcomeNodeId = stableId(
        "mem",
        `terminal-attack-outcome\n${input.evaluationId}\n${procedureNodeId}\n${input.terminalStatus}`,
      );
      if (!this.#memory.getNode(outcomeNodeId, true)) {
        const completed = input.terminalStatus === "completed";
        this.#memory.createNode({
          id: outcomeNodeId,
          nodeType: "outcome",
          title: completed
            ? "Candidate bounded procedure outcome"
            : "Candidate failed procedure outcome",
          summary: completed
            ? "A reviewed procedure contributed to a bounded run that completed with verified retained evidence."
            : "A reviewed procedure was used during planning, but the bounded run did not complete successfully.",
          body: completed
            ? "Reuse remains conditional on a matching product, version, prerequisites, authorization, and independent review of this candidate."
            : "Do not treat this as a successful technique. Reuse requires an independently reviewed cause and materially changed conditions.",
          scope: { kind: "global" },
          sensitivity: "private",
          confidence: completed ? 0.75 : 0.6,
          lifecycleStatus: "candidate",
          confirmationState: "pending",
          provenance: {
            method: "derived",
            explanation: "Generalized from the canonical terminal evaluation after a confirmed attack procedure was attributed as used during planning.",
            sources: [{
              sourceType: "run_evaluation",
              sourceId: input.evaluationId,
              acquiredAt: input.now,
            }],
          },
          authorType: "agent",
          authorId: AUTHORING_AGENT,
          retentionPolicy: terminalAttackKnowledgeReviewRetentionPolicy(),
        });
      }
      const outcomeNode = this.#memory.getNode(outcomeNodeId);
      if (!outcomeNode || outcomeNode.lifecycleStatus !== "candidate") continue;
      retainedNodeIds.add(outcomeNodeId);

      const outcomeEdgeId = stableId(
        "medge",
        `${procedureNodeId}\nproduces_outcome\n${outcomeNodeId}`,
      );
      if (!this.database.prepare("SELECT 1 FROM memory_edges WHERE id = ?").get(outcomeEdgeId)) {
        this.#memory.createEdge({
          id: outcomeEdgeId,
          sourceNodeId: procedureNodeId,
          targetNodeId: outcomeNodeId,
          edgeType: "produces_outcome",
          title: "Produced reviewable outcome",
          summary: "The reviewed procedure is linked to a generalized terminal outcome pending operator review.",
          scope: { kind: "global" },
          sensitivity: "private",
          confidence: completedConfidence(input.terminalStatus),
          lifecycleStatus: "candidate",
          provenance: {
            method: "derived",
            explanation: "The link exists only because the procedure was persisted as used in the Autonomous planning Context Pack.",
            sources: [{
              sourceType: "run_evaluation",
              sourceId: input.evaluationId,
              acquiredAt: input.now,
            }],
          },
          explanation: "Connects a reviewed reusable procedure to its generalized, untrusted terminal outcome.",
          authorType: "agent",
          authorId: AUTHORING_AGENT,
        });
      }
    }

    for (const lessonId of input.proposedLessonIds) {
      const lessonNodeId = stableId(
        "mem",
        `terminal-attack-lesson\n${input.evaluationId}\n${lessonId}`,
      );
      if (!this.#memory.getNode(lessonNodeId, true)) {
        this.#memory.createNode({
          id: lessonNodeId,
          nodeType: "attack_lesson",
          title: "Candidate reusable attack lesson",
          summary: input.terminalStatus === "completed"
            ? "Keep the reviewed procedure bounded and require verified retained evidence before declaring success."
            : "Do not repeat the reviewed procedure until the failure cause is independently reviewed and execution conditions materially change.",
          body: "This generalized lesson is pending operator review and cannot influence Autonomous or Guided execution in its current state.",
          scope: { kind: "global" },
          sensitivity: "private",
          confidence: input.terminalStatus === "completed" ? 0.75 : 0.6,
          lifecycleStatus: "candidate",
          confirmationState: "pending",
          provenance: {
            method: "derived",
            explanation: "Generalized from an evidence-gated private lesson proposal without copying mission, target, or engagement content.",
            sources: [{
              sourceType: "lesson",
              sourceId: lessonId,
              acquiredAt: input.now,
            }],
          },
          authorType: "agent",
          authorId: AUTHORING_AGENT,
          retentionPolicy: terminalAttackKnowledgeReviewRetentionPolicy(),
        });
      }
      const lessonNode = this.#memory.getNode(lessonNodeId);
      if (!lessonNode || lessonNode.lifecycleStatus !== "candidate") continue;
      retainedNodeIds.add(lessonNodeId);

      for (const procedureNodeId of procedureNodeIds) {
        const lessonEdgeId = stableId(
          "medge",
          `${lessonNodeId}\nimproves\n${procedureNodeId}`,
        );
        if (this.database.prepare("SELECT 1 FROM memory_edges WHERE id = ?").get(lessonEdgeId)) continue;
        this.#memory.createEdge({
          id: lessonEdgeId,
          sourceNodeId: lessonNodeId,
          targetNodeId: procedureNodeId,
          edgeType: "improves",
          title: "Proposes a bounded procedure improvement",
          summary: "The candidate lesson proposes a reviewable execution constraint for the reviewed procedure.",
          scope: { kind: "global" },
          sensitivity: "private",
          confidence: completedConfidence(input.terminalStatus),
          lifecycleStatus: "candidate",
          provenance: {
            method: "derived",
            explanation: "The candidate lesson and procedure are linked only after persisted planning attribution and terminal evaluation.",
            sources: [{
              sourceType: "lesson",
              sourceId: lessonId,
              acquiredAt: input.now,
            }],
          },
          explanation: "Keeps a proposed improvement visibly untrusted until independent operator review.",
          authorType: "agent",
          authorId: AUTHORING_AGENT,
        });
      }
    }
    return [...retainedNodeIds].sort();
  }

  #reusableTerminalNodeIds(evaluationId: string, runId: string): readonly string[] {
    const sourceIds = [evaluationId, ...this.#lessonIdsForRun(runId)];
    if (sourceIds.length === 0) return [];
    return (this.database.prepare(`
      SELECT DISTINCT node.id
      FROM memory_nodes node
      JOIN memory_sources source ON source.node_id = node.id
      WHERE node.node_type IN ('outcome', 'attack_lesson')
        AND node.lifecycle_status != 'forgotten'
        AND source.source_id IN (${sourceIds.map(() => "?").join(",")})
      ORDER BY node.id
    `).all(...sourceIds) as Array<{ id: string }>).map(({ id }) => id);
  }

  #reviewedLessonMatch(input: {
    node: MemoryNode;
    rank: number;
    run: RunRow;
    candidate: TerminalLessonCandidate;
    allowGlobal: boolean;
  }): { match?: ReviewedLessonMatch; reason: string } {
    if (input.node.nodeType !== "lesson") {
      return {
        reason: input.node.nodeType === "failure" || input.node.nodeType === "failure_mode"
          ? "Failure memory is applied only through an explicit confirmed or verified contradiction to the selected reviewed lesson."
          : "Only canonical lesson nodes can suppress a terminal lesson candidate.",
      };
    }
    if (!this.#eligibleAutonomousNode(input.node, input.run, input.allowGlobal)) {
      return {
        reason: "The lesson is no longer confirmed or verified, scope-safe, current, unexpired, and approved for Autonomous use.",
      };
    }
    if (input.node.lifecycleStatus !== "verified") {
      return {
        reason: "A confirmed memory may inform review, but only an independently verified lesson can suppress a new lesson candidate.",
      };
    }
    const lessonSourceIds = input.node.provenance.sources
      .filter(({ sourceType }) => sourceType === "lesson")
      .map(({ sourceId }) => sourceId)
      .sort();
    for (const lessonId of lessonSourceIds) {
      if (canonicalLessonMemoryNodeId(lessonId) !== input.node.id) continue;
      const lesson = this.database.prepare(`
        SELECT l.id, l.statement, l.lesson_type, l.status, l.applicability_scope,
          l.engagement_id, l.mission_id, l.authoring_agent_id, l.reviewed_by
        FROM lessons l
        WHERE l.id = ? AND l.status = 'verified'
          AND l.reviewed_by IS NOT NULL
          AND (l.authoring_agent_id IS NULL OR l.reviewed_by != l.authoring_agent_id)
          AND EXISTS (
            SELECT 1
            FROM lesson_evidence le
            LEFT JOIN evidence e ON e.id = le.evidence_id
            WHERE le.lesson_id = l.id AND le.relationship = 'supports'
              AND (
                (le.evidence_id IS NOT NULL AND ${verifiedEvidenceSql("e")})
                OR (
                  le.run_id IS NOT NULL
                  AND EXISTS (
                    SELECT 1 FROM run_evaluations evaluation
                    WHERE evaluation.run_id = le.run_id
                  )
                )
              )
          )
      `).get(lessonId) as {
        id: string;
        statement: string;
        lesson_type: string;
        status: string;
        applicability_scope: string;
        engagement_id: string | null;
        mission_id: string | null;
        authoring_agent_id: string | null;
        reviewed_by: string;
      } | undefined;
      if (!lesson) continue;
      if (
        lesson.lesson_type !== input.candidate.lessonType
        || normalizeLessonStatement(lesson.statement)
          !== normalizeLessonStatement(input.candidate.statement)
        || normalizeLessonStatement(input.node.summary)
          !== normalizeLessonStatement(input.candidate.statement)
      ) continue;
      const rowScopeMatches = input.node.scope.kind === "global"
        ? lesson.applicability_scope === "global"
          && lesson.engagement_id === null
          && lesson.mission_id === null
        : input.node.scope.kind === "engagement"
          ? lesson.engagement_id === input.node.scope.engagementId
          : lesson.mission_id === input.node.scope.missionId;
      if (!rowScopeMatches) continue;
      return {
        match: { lessonId: lesson.id, node: input.node, rank: input.rank },
        reason: "",
      };
    }
    return {
      reason: "The lesson is not an exact independently reviewed, evidence-linked match for this deterministic candidate.",
    };
  }

  #eligibleAutonomousNode(node: MemoryNode, run: RunRow, allowGlobal: boolean): boolean {
    const current = this.#memory.getNode(node.id);
    if (
      !current
      || current.version !== node.version
      || current.lifecycleStatus !== node.lifecycleStatus
      || (node.lifecycleStatus !== "confirmed" && node.lifecycleStatus !== "verified")
      || (
        node.confirmationState !== "confirmed"
        && node.confirmationState !== "not_required"
      )
      || node.retentionPolicy.allowAutonomous !== true
      || (
        Array.isArray(node.retentionPolicy.journeys)
        && !node.retentionPolicy.journeys.includes("autonomous")
      )
      || (
        node.expiresAt !== undefined
        && Date.parse(node.expiresAt) <= this.#clock().getTime()
      )
    ) return false;
    return this.#scopeApplies(node.scope, run, allowGlobal);
  }

  #scopeApplies(scope: MemoryNode["scope"], run: RunRow, allowGlobal: boolean): boolean {
    if (scope.kind === "global") return allowGlobal;
    if (scope.kind === "engagement") {
      return run.engagement_id !== null && scope.engagementId === run.engagement_id;
    }
    return scope.missionId === run.mission_id;
  }

  #nodeHasCanonicalEvidenceLink(nodeId: string): boolean {
    const direct = this.database.prepare(`
      SELECT 1
      FROM memory_sources source
      WHERE source.node_id = ?
        AND (
          EXISTS (
            SELECT 1 FROM evidence e
            WHERE (e.id = source.evidence_id OR e.id = source.source_id)
              AND ${verifiedEvidenceSql("e")}
          )
          OR (
            source.source_type = 'run_evaluation'
            AND EXISTS (
              SELECT 1 FROM run_evaluations evaluation
              WHERE evaluation.id = source.source_id
            )
          )
          OR (
            source.source_type = 'failure_diagnosis'
            AND EXISTS (
              SELECT 1 FROM failure_diagnoses diagnosis
              WHERE diagnosis.id = source.source_id
            )
          )
        )
      LIMIT 1
    `).get(nodeId);
    if (direct) return true;
    for (const edge of this.#memory.listEdges(nodeId)) {
      if (
        (edge.edgeType !== "supports" && edge.edgeType !== "verified_by")
        || edge.lifecycleStatus !== "verified"
        || edge.provenance.sources.length === 0
      ) continue;
      const relatedId = edge.sourceNodeId === nodeId ? edge.targetNodeId : edge.sourceNodeId;
      const related = this.#memory.getNode(relatedId);
      if (
        related?.lifecycleStatus === "verified"
        && (related.nodeType === "evidence" || related.nodeType === "evaluation")
      ) return true;
    }
    return false;
  }

  #calculate(
    run: RunRow,
    outcome: MissionCompletionEvaluation | undefined,
    terminalStatus: EvaluatedTerminalStatus,
    reportCommitment: CanonicalReportArtifactCommitment | undefined,
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
          (event_type = 'run.state_changed'
            AND json_extract(payload_json, '$.to') = 'recovering')) AS retries,
        SUM(event_type = 'run.state_changed' AND payload_json LIKE '%waiting_guided_decision%') AS corrections
      FROM events WHERE run_id = ?
    `).get(run.id) as AggregateRow;
    const policyViolationCount = count(events.denied) + deniedActions;
    const recoveryCount = count(events.retries);
    const autonomousUserWaitCount = run.journey === "autonomous" ? count(events.corrections) : 0;

    const artifacts = this.database.prepare(`
      SELECT COUNT(*) AS count,
        SUM(artifact_type IN (?, ?)) AS reports
      FROM artifacts WHERE run_id = ?
    `).get(
      CANONICAL_REPORT_ARTIFACT_TYPES.markdown,
      CANONICAL_REPORT_ARTIFACT_TYPES.json,
      run.id,
    ) as AggregateRow;
    const existingReportTypes = new Set((this.database.prepare(`
      SELECT artifact_type FROM artifacts
      WHERE run_id = ? AND artifact_type IN (?, ?)
        AND json_extract(metadata_json, '$.reportVersion') = ?
    `).all(
      run.id,
      CANONICAL_REPORT_ARTIFACT_TYPES.markdown,
      CANONICAL_REPORT_ARTIFACT_TYPES.json,
      reportCommitment?.reportVersion ?? -1,
    ) as Array<{ readonly artifact_type: string }>).map(({ artifact_type }) => artifact_type));
    const committedMissingReportCount = reportCommitment?.artifactTypes
      .filter((artifactType) => !existingReportTypes.has(artifactType)).length ?? 0;
    const artifactCount = count(artifacts.count) + committedMissingReportCount;
    const reportCount = count(artifacts.reports) + committedMissingReportCount;

    const criteria = outcome?.criteria ?? [];
    const satisfiedCriteria = criteria.filter((criterion) => criterion.satisfied).length;
    const verifiedIds = new Set((this.database.prepare(`
      SELECT id FROM evidence WHERE run_id = ? AND ${verifiedEvidenceSql("evidence")}
    `).all(run.id) as Array<{ id: string }>).map((row) => row.id));
    const evidenceBackedCriteria = criteria.filter((criterion) =>
      criterion.satisfied && criterion.evidenceIds.some((evidenceId) => verifiedIds.has(evidenceId))).length;
    // Objective completion and objective verification are deliberately
    // separate. A bounded "check whether" Guided step can finish when its
    // exact action and terminal tool receipt answer the question, even when
    // policy retains the raw output only as an Engagement Log. That is valid
    // workflow completion, but it is not verified-evidence completion.
    const objectiveCompleted = terminalStatus === "completed"
      && outcome?.success === true
      && (criteria.length === 0 || satisfiedCriteria === criteria.length);
    const successCriteriaCoverage = criteria.length > 0
      ? ratio(satisfiedCriteria, criteria.length)
      : objectiveCompleted ? 1 : 0;
    const evidenceCoverage = criteria.length > 0
      ? ratio(evidenceBackedCriteria, criteria.length)
      : ratio(verifiedEvidenceCount, Math.max(1, evidenceCount));
    const verifiedObjectiveCompletion = criteria.length > 0
      ? objectiveCompleted && evidenceBackedCriteria === criteria.length ? 1 : 0
      : null;
    const completionBasis = !objectiveCompleted
      ? outcome ? "outcome_not_completed" : "outcome_not_evaluated"
      : criteria.length === 0
        ? "explicit_outcome_without_criteria"
        : evidenceBackedCriteria === criteria.length
          ? "verified_evidence"
          : evidenceBackedCriteria > 0
            ? "partially_verified_evidence"
            : "canonical_result_without_verified_evidence";

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
      objectiveCompletion: objectiveCompleted ? 1 : 0,
      verifiedObjectiveCompletion,
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
      reportQuality: reportCount > 0 ? ratio(reportCount, 2) : null,
      uncertaintyCalibration: criteria.length > 0 ? evidenceCoverage : null,
    };
    const metrics: Record<string, number | string | null> = {
      terminalStatus,
      completionBasis,
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
      objectiveCompleted
        ? verifiedObjectiveCompletion === 1
          ? "The completed objective is linked to verified retained evidence."
          : "The objective is workflow-complete from a canonical result only; no verified retained evidence supports a stronger claim, and Engagement Log output was not counted as evidence."
        : "No successful objective completion was recorded by the outcome evaluator.",
      `${succeededActions}/${actionCount} actions succeeded, with ${Math.round(repeatedActionRate * 100)}% repeated-action rate and ${run.retry_count + actionRetries} retries.`,
      `${policyViolationCount} policy violations and ${operatorCorrectionCount} operator corrections were recorded.`,
    ].join(" ");
    return { scores, metrics, retrospective, evidenceCoverage };
  }

  #proposeLessons(input: {
    evaluationId: string;
    evaluationNodeId: string;
    run: RunRow;
    terminalStatus: EvaluatedTerminalStatus;
    evidenceCoverage: number;
    now: string;
    memoryApplication?: TerminalLessonMemoryApplication;
  }): string[] {
    if (input.terminalStatus === "cancelled") return [];
    const verifiedEvidenceIds = (this.database.prepare(`
      SELECT id FROM evidence WHERE run_id = ? AND ${verifiedEvidenceSql("evidence")} ORDER BY id
    `).all(input.run.id) as Array<{ id: string }>).map((row) => row.id);
    if (input.terminalStatus === "completed" && verifiedEvidenceIds.length === 0) return [];

    const actionClasses = (this.database.prepare(`
      SELECT DISTINCT action_class FROM actions WHERE run_id = ? ORDER BY action_class
    `).all(input.run.id) as Array<{ action_class: string }>).map((row) => row.action_class);
    const candidate = terminalLessonCandidate(actionClasses, input.terminalStatus);
    const { domain, statement, lessonType } = candidate;
    if (
      input.memoryApplication
      && input.memoryApplication.candidateStatementHash !== candidate.statementHash
    ) {
      throw new Error("Terminal lesson memory application no longer matches the canonical candidate");
    }
    if (
      input.memoryApplication?.disposition === "reuse_verified_lesson"
      || input.memoryApplication?.disposition === "reuse_verified_lesson_with_contradiction"
    ) {
      if (!input.memoryApplication.reusedLessonId) {
        throw new Error("A reused terminal lesson application requires a reviewed lesson ID");
      }
      this.#reuseReviewedLesson({
        evaluationId: input.evaluationId,
        evaluationNodeId: input.evaluationNodeId,
        run: input.run,
        now: input.now,
        statement,
        lessonType,
        verifiedEvidenceIds,
        application: input.memoryApplication,
      });
      return [];
    }

    const applicabilityScope = input.run.engagement_id ? "engagement" : "mission";
    const engagementId = input.run.engagement_id;
    const missionId = input.run.engagement_id ? null : input.run.mission_id;
    const scopeKey = input.run.engagement_id ?? input.run.mission_id;
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

  #reuseReviewedLesson(input: {
    evaluationId: string;
    evaluationNodeId: string;
    run: RunRow;
    now: string;
    statement: string;
    lessonType: TerminalLessonCandidate["lessonType"];
    verifiedEvidenceIds: readonly string[];
    application: TerminalLessonMemoryApplication;
  }): void {
    const lesson = this.database.prepare(`
      SELECT id, statement, lesson_type, status, authoring_agent_id, reviewed_by
      FROM lessons
      WHERE id = ? AND status = 'verified'
        AND reviewed_by IS NOT NULL
        AND (authoring_agent_id IS NULL OR reviewed_by != authoring_agent_id)
        AND EXISTS (
          SELECT 1 FROM lesson_evidence
          WHERE lesson_id = lessons.id AND relationship = 'supports'
        )
    `).get(input.application.reusedLessonId) as {
      id: string;
      statement: string;
      lesson_type: string;
      status: string;
      authoring_agent_id: string | null;
      reviewed_by: string;
    } | undefined;
    const lessonNodeId = canonicalLessonMemoryNodeId(input.application.reusedLessonId!);
    const lessonNode = this.#memory.getNode(lessonNodeId);
    const contextPack = this.database.prepare(`
      SELECT mission_id, run_id, journey
      FROM memory_context_packs WHERE id = ?
    `).get(input.application.contextPackId) as {
      mission_id: string | null;
      run_id: string | null;
      journey: string;
    } | undefined;
    if (
      !lesson
      || lesson.lesson_type !== input.lessonType
      || normalizeLessonStatement(lesson.statement) !== normalizeLessonStatement(input.statement)
      || !lessonNode
      || lessonNode.lifecycleStatus !== "verified"
      || lessonNode.retentionPolicy.allowAutonomous !== true
      || !input.application.usedNodeIds.includes(lessonNodeId)
      || !contextPack
      || contextPack.mission_id !== input.run.mission_id
      || contextPack.run_id !== input.run.id
      || contextPack.journey !== "autonomous"
    ) {
      throw new Error("The reviewed lesson reuse decision is stale or no longer evidence-linked");
    }

    this.#linkLessonSupport(lesson.id, input.run.id, null, input.now);
    for (const evidenceId of input.verifiedEvidenceIds) {
      this.#linkLessonSupport(lesson.id, null, evidenceId, input.now);
    }

    const usageId = stableId(
      "lusage",
      `${lesson.id}\n${input.run.id}\n${input.application.contextPackId}\nterminal_deduplication`,
    );
    if (!this.database.prepare("SELECT 1 FROM lesson_usage WHERE id = ?").get(usageId)) {
      this.database.prepare(`
        INSERT INTO lesson_usage (
          id, lesson_id, mission_id, run_id, context_pack_id,
          influence_summary, outcome, measured_impact_json, used_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, '{}', ?)
      `).run(
        usageId,
        lesson.id,
        input.run.mission_id,
        input.run.id,
        input.application.contextPackId,
        input.application.contradictionNodeIds.length > 0
          ? "Suppressed an exact duplicate candidate while preserving explicit failure contradiction context for independent review."
          : "Suppressed an exact duplicate candidate and reused the independently reviewed lesson.",
        input.application.contradictionNodeIds.length > 0
          ? "duplicate_suppressed_with_contradiction_preserved"
          : "duplicate_suppressed",
        input.now,
      );
    }

    const edgeId = stableId("medge", `${lessonNodeId}\nused_in\n${input.evaluationNodeId}`);
    if (!this.database.prepare("SELECT 1 FROM memory_edges WHERE id = ?").get(edgeId)) {
      this.#memory.createEdge({
        id: edgeId,
        sourceNodeId: lessonNodeId,
        targetNodeId: input.evaluationNodeId,
        edgeType: "used_in",
        title: "Reviewed lesson reused",
        summary: "An independently reviewed lesson prevented a duplicate terminal candidate.",
        scope: input.run.engagement_id
          ? { kind: "engagement", engagementId: input.run.engagement_id }
          : { kind: "mission", missionId: input.run.mission_id },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "verified",
        provenance: {
          method: "derived",
          explanation: "Deterministic exact-statement deduplication reused an independently reviewed evidence-linked lesson.",
          sources: [{
            sourceType: "run_evaluation",
            sourceId: input.evaluationId,
            acquiredAt: input.now,
          }],
        },
        explanation: "The reviewed lesson influenced terminal learning by preventing a duplicate proposal; its status was not changed.",
        authorType: "system",
        authorId: AUTHORING_AGENT,
      });
    }

    this.options.events?.append({
      missionId: input.run.mission_id,
      runId: input.run.id,
      journey: input.run.journey,
      eventType: "learning.lesson_reused",
      actorType: "agent",
      actorId: AUTHORING_AGENT,
      summary: input.application.contradictionNodeIds.length > 0
        ? "Reused a reviewed lesson and preserved explicit failure contradiction context"
        : "Reused a reviewed lesson instead of proposing a duplicate",
      payload: {
        lessonId: lesson.id,
        evaluationId: input.evaluationId,
        contextPackId: input.application.contextPackId,
        contradictionNodeIds: [...input.application.contradictionNodeIds],
        lifecycleChanged: false,
      },
    });
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

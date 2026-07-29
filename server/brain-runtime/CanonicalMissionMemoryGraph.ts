import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  getMemoryControlPolicy,
  MemoryRepository,
  type MemoryNodeType,
} from "../memory";

const AUTHOR_ID = "system:canonical-mission-memory";

interface MissionRow {
  readonly id: string;
  readonly journey: "autonomous" | "guided";
  readonly status: string;
  readonly engagement_id: string | null;
}

interface RunRow {
  readonly id: string;
  readonly mission_id: string;
  readonly journey: "autonomous" | "guided";
  readonly status: string;
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
  readonly created_at: string;
}

export interface CanonicalMemoryGraphSelection {
  readonly status: "materialized" | "skipped_by_policy" | "forgotten";
  readonly missionNodeId: string;
  readonly runNodeId?: string;
  readonly evaluationNodeId?: string;
  readonly nodeIds: readonly string[];
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function stableId(prefix: string, canonicalId: string): string {
  return `${prefix}_${sha256(canonicalId).slice(0, 32)}`;
}

export function canonicalMissionMemoryNodeId(missionId: string): string {
  return stableId("mem_mission", missionId);
}

export function canonicalRunMemoryNodeId(runId: string): string {
  return stableId("mem_run", runId);
}

export function canonicalRunEvaluationMemoryNodeId(evaluationId: string): string {
  return stableId("mem_eval", evaluationId);
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

function sourceHash(value: Readonly<Record<string, unknown>>): string {
  const ordered = Object.keys(value).sort().reduce<Record<string, unknown>>((result, key) => {
    result[key] = value[key];
    return result;
  }, {});
  return sha256(JSON.stringify(ordered));
}

/**
 * Idempotently materializes privacy-safe anchors for the current canonical
 * V2 mission graph. User objectives, target identifiers and raw tool output
 * deliberately stay in their canonical stores; these nodes carry only
 * controlled lifecycle metadata and stable provenance links.
 */
export class CanonicalMissionMemoryGraph {
  readonly #memory: MemoryRepository;

  constructor(
    readonly database: SqliteDatabase,
    options: { readonly clock?: () => Date } = {},
  ) {
    this.#memory = new MemoryRepository(database, options);
  }

  ensureMission(missionId: string): CanonicalMemoryGraphSelection {
    return inImmediateTransaction(this.database, () => {
      const mission = this.#mission(missionId);
      const missionNodeId = canonicalMissionMemoryNodeId(mission.id);
      if (!this.#operationalRetentionAllowed()) {
        return { status: "skipped_by_policy", missionNodeId, nodeIds: [] };
      }
      const existing = this.#memory.getNode(missionNodeId, true);
      if (existing?.lifecycleStatus === "forgotten") {
        return { status: "forgotten", missionNodeId, nodeIds: [] };
      }
      this.#createNodeIfMissing({
        id: missionNodeId,
        nodeType: "mission",
        title: `${mission.journey === "autonomous" ? "Autonomous" : "Guided"} mission`,
        summary: `Canonical ${mission.journey} mission lifecycle record. Initial retained status: ${mission.status}.`,
        body: "This privacy-safe graph anchor links the mission to its runs, evaluations, and retained outcomes. Open the canonical mission record for operator-supplied details.",
        mission,
        sourceType: "mission",
        sourceId: mission.id,
        sourceHash: sourceHash({
          id: mission.id,
          journey: mission.journey,
          status: mission.status,
          engagementId: mission.engagement_id,
        }),
      });
      return { status: "materialized", missionNodeId, nodeIds: [missionNodeId] };
    });
  }

  ensureRun(runId: string): CanonicalMemoryGraphSelection {
    return inImmediateTransaction(this.database, () => {
      const run = this.#run(runId);
      const mission = this.#mission(run.mission_id);
      if (run.journey !== mission.journey) {
        throw new Error("Canonical run journey does not match its mission");
      }
      const runNodeId = canonicalRunMemoryNodeId(run.id);
      if (!this.#operationalRetentionAllowed()) {
        return {
          status: "skipped_by_policy",
          missionNodeId: canonicalMissionMemoryNodeId(mission.id),
          runNodeId,
          nodeIds: [],
        };
      }
      const missionSelection = this.ensureMission(mission.id);
      if (missionSelection.status !== "materialized") {
        return { ...missionSelection, runNodeId };
      }
      const existing = this.#memory.getNode(runNodeId, true);
      if (existing?.lifecycleStatus === "forgotten") {
        return {
          status: "forgotten",
          missionNodeId: missionSelection.missionNodeId,
          runNodeId,
          nodeIds: missionSelection.nodeIds,
        };
      }
      this.#createNodeIfMissing({
        id: runNodeId,
        nodeType: "run",
        title: `${run.journey === "autonomous" ? "Autonomous" : "Guided"} mission run`,
        summary: `Canonical ${run.journey} run used for mission planning, phase transitions, evaluation, and closeout. Initial retained status: ${run.status}.`,
        body: "This node identifies one durable execution attempt. Operational details remain in the canonical run, event, action, and evidence records.",
        mission,
        sourceType: "run",
        sourceId: run.id,
        sourceHash: sourceHash({ id: run.id, missionId: run.mission_id, journey: run.journey }),
      });
      this.#createEdgeIfMissing({
        sourceNodeId: runNodeId,
        targetNodeId: missionSelection.missionNodeId,
        edgeType: "belongs_to",
        title: "Run belongs to mission",
        summary: "The durable execution attempt belongs to this exact canonical mission.",
        explanation: "The runs.mission_id foreign key is the authoritative relationship.",
        mission,
        sourceType: "run",
        sourceId: run.id,
      });
      return {
        status: "materialized",
        missionNodeId: missionSelection.missionNodeId,
        runNodeId,
        nodeIds: [missionSelection.missionNodeId, runNodeId],
      };
    });
  }

  ensureEvaluation(evaluationId: string): CanonicalMemoryGraphSelection {
    return inImmediateTransaction(this.database, () => {
      const evaluation = this.#evaluation(evaluationId);
      const run = this.#run(evaluation.run_id);
      if (evaluation.mission_id !== run.mission_id || evaluation.journey !== run.journey) {
        throw new Error("Canonical evaluation does not match its run and journey");
      }
      const evaluationNodeId = canonicalRunEvaluationMemoryNodeId(evaluation.id);
      if (!this.#operationalRetentionAllowed()) {
        return {
          status: "skipped_by_policy",
          missionNodeId: canonicalMissionMemoryNodeId(run.mission_id),
          runNodeId: canonicalRunMemoryNodeId(run.id),
          evaluationNodeId,
          nodeIds: [],
        };
      }
      const selection = this.ensureRun(run.id);
      if (selection.status !== "materialized") {
        return { ...selection, evaluationNodeId };
      }
      const existing = this.#memory.getNode(evaluationNodeId, true);
      if (existing?.lifecycleStatus === "forgotten") {
        return {
          ...selection,
          status: "forgotten",
          evaluationNodeId,
        };
      }
      if (!existing) {
        const calculated = {
          scores: parseJsonObject(evaluation.scores_json),
          metrics: parseJsonObject(evaluation.metrics_json),
          retrospective: evaluation.retrospective,
          evidenceCoverage: evaluation.evidence_coverage,
        };
        this.#memory.createNode({
          id: evaluationNodeId,
          nodeType: "evaluation",
          title: `${run.journey === "autonomous" ? "Autonomous" : "Guided"} run evaluation`,
          summary: evaluation.retrospective,
          body: "Evidence-gated terminal assessment. Open the linked canonical evaluation for complete metrics.",
          scope: { kind: "mission", missionId: run.mission_id },
          sensitivity: "private",
          confidence: 1,
          lifecycleStatus: "verified",
          confirmationState: "not_required",
          provenance: {
            method: "derived",
            explanation: "Calculated from canonical run, action, evidence, finding, policy and journey records.",
            sources: [{
              sourceType: "run_evaluation",
              sourceId: evaluation.id,
              acquiredAt: evaluation.created_at,
              sourceHash: sha256(JSON.stringify(calculated)),
            }],
          },
          authorType: "agent",
          authorId: "run-evaluator",
          retentionPolicy: { allowAutonomous: true, allowGuided: true },
        });
      }
      this.linkEvaluation(run.id, evaluationNodeId, evaluation.id);
      return {
        status: "materialized",
        missionNodeId: selection.missionNodeId,
        runNodeId: selection.runNodeId,
        evaluationNodeId,
        nodeIds: [...selection.nodeIds, evaluationNodeId],
      };
    });
  }

  linkEvaluation(runId: string, evaluationNodeId: string, evaluationId: string): readonly string[] {
    return inImmediateTransaction(this.database, () => {
      const selection = this.ensureRun(runId);
      if (selection.status !== "materialized" || !selection.runNodeId) {
        return selection.nodeIds;
      }
      const run = this.#run(runId);
      const mission = this.#mission(run.mission_id);
      const evaluationNode = this.#memory.getNode(evaluationNodeId, true);
      if (!evaluationNode) throw new Error(`Memory node not found: ${evaluationNodeId}`);
      if (evaluationNode.lifecycleStatus === "forgotten") return selection.nodeIds;
      this.#createEdgeIfMissing({
        sourceNodeId: evaluationNodeId,
        targetNodeId: selection.runNodeId,
        edgeType: "derived_from",
        title: "Evaluation derived from run",
        summary: "The evidence-gated evaluation was calculated from this exact canonical run.",
        explanation: "The run_evaluations.run_id foreign key and evaluation provenance establish this relationship.",
        mission,
        sourceType: "run_evaluation",
        sourceId: evaluationId,
      });
      return [...selection.nodeIds, evaluationNodeId];
    });
  }

  #mission(id: string): MissionRow {
    const row = this.database.prepare(`
      SELECT id, journey, status, engagement_id FROM missions WHERE id = ?
    `).get(id) as MissionRow | undefined;
    if (!row) throw new Error(`Canonical mission does not exist: ${id}`);
    return row;
  }

  #run(id: string): RunRow {
    const row = this.database.prepare(`
      SELECT id, mission_id, journey, status FROM runs WHERE id = ?
    `).get(id) as RunRow | undefined;
    if (!row) throw new Error(`Canonical run does not exist: ${id}`);
    return row;
  }

  #evaluation(id: string): EvaluationRow {
    const row = this.database.prepare(`
      SELECT id, mission_id, run_id, journey, scores_json, metrics_json,
        retrospective, evidence_coverage, created_at
      FROM run_evaluations WHERE id = ?
    `).get(id) as EvaluationRow | undefined;
    if (!row) throw new Error(`Canonical run evaluation does not exist: ${id}`);
    return row;
  }

  #operationalRetentionAllowed(): boolean {
    const control = getMemoryControlPolicy(this.database);
    return control.enabled && control.operationalMemoryEnabled;
  }

  #createNodeIfMissing(input: {
    readonly id: string;
    readonly nodeType: MemoryNodeType;
    readonly title: string;
    readonly summary: string;
    readonly body: string;
    readonly mission: MissionRow;
    readonly sourceType: string;
    readonly sourceId: string;
    readonly sourceHash: string;
  }): void {
    if (this.#memory.getNode(input.id, true)) return;
    this.#memory.createNode({
      id: input.id,
      nodeType: input.nodeType,
      title: input.title,
      summary: input.summary,
      body: input.body,
      scope: {
        kind: "mission",
        missionId: input.mission.id,
        ...(input.mission.engagement_id ? { engagementId: input.mission.engagement_id } : {}),
      },
      sensitivity: "private",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "not_required",
      provenance: {
        method: "derived",
        explanation: "Privacy-safe graph anchor derived from a canonical Ti-Scale domain record.",
        sources: [{
          sourceType: input.sourceType,
          sourceId: input.sourceId,
          acquiredAt: this.#memory.now(),
          sourceHash: input.sourceHash,
        }],
      },
      authorType: "system",
      authorId: AUTHOR_ID,
      retentionPolicy: { allowAutonomous: true, allowGuided: true },
    });
  }

  #createEdgeIfMissing(input: {
    readonly sourceNodeId: string;
    readonly targetNodeId: string;
    readonly edgeType: "belongs_to" | "derived_from";
    readonly title: string;
    readonly summary: string;
    readonly explanation: string;
    readonly mission: MissionRow;
    readonly sourceType: string;
    readonly sourceId: string;
  }): void {
    const edgeId = stableId(
      "medge",
      `${input.sourceNodeId}\n${input.edgeType}\n${input.targetNodeId}`,
    );
    if (this.database.prepare("SELECT 1 FROM memory_edges WHERE id = ?").get(edgeId)) return;
    this.#memory.createEdge({
      id: edgeId,
      sourceNodeId: input.sourceNodeId,
      targetNodeId: input.targetNodeId,
      edgeType: input.edgeType,
      title: input.title,
      summary: input.summary,
      scope: {
        kind: "mission",
        missionId: input.mission.id,
        ...(input.mission.engagement_id ? { engagementId: input.mission.engagement_id } : {}),
      },
      sensitivity: "private",
      confidence: 1,
      lifecycleStatus: "verified",
      provenance: {
        method: "derived",
        explanation: "Relationship derived from a canonical Ti-Scale foreign-key or provenance link.",
        sources: [{
          sourceType: input.sourceType,
          sourceId: input.sourceId,
          acquiredAt: this.#memory.now(),
        }],
      },
      explanation: input.explanation,
      authorType: "system",
      authorId: AUTHOR_ID,
    });
  }
}

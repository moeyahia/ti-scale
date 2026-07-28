import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import { getMemoryControlPolicy } from "../memory";
import type { ConnectedVaultProjectionReport } from "../vault/ConnectedVaultMemoryProjector";
import { ConnectedVaultMemoryProjector } from "../vault/ConnectedVaultMemoryProjector";
import {
  CanonicalMissionMemoryGraph,
  canonicalMissionMemoryNodeId,
  canonicalRunEvaluationMemoryNodeId,
  canonicalRunMemoryNodeId,
} from "./CanonicalMissionMemoryGraph";

interface MissionRow {
  readonly id: string;
}

interface RunRow {
  readonly id: string;
  readonly mission_id: string;
}

interface EvaluationRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
}

interface NodeRow {
  readonly id: string;
  readonly node_type: string;
  readonly mission_id: string | null;
  readonly lifecycle_status: string;
  readonly sensitivity: string;
  readonly version: number;
}

interface EdgeRow {
  readonly id: string;
  readonly mission_id: string | null;
  readonly lifecycle_status: string;
}

interface ExpectedNode {
  readonly id: string;
  readonly nodeType: "mission" | "run" | "evaluation";
  readonly missionId: string;
  readonly sourceType: "mission" | "run" | "run_evaluation";
  readonly sourceId: string;
  readonly dependencyNodeIds: readonly string[];
}

interface ExpectedEdge {
  readonly sourceNodeId: string;
  readonly targetNodeId: string;
  readonly edgeType: "belongs_to" | "derived_from";
  readonly missionId: string;
}

export interface CanonicalMemoryReconciliationConflict {
  readonly resourceType: "memory_node" | "memory_edge";
  readonly resourceId: string;
  readonly reason: string;
}

export interface CanonicalMemoryReconciliationAnalysis {
  readonly policy: {
    readonly enabled: boolean;
    readonly operationalMemoryEnabled: boolean;
    readonly version: number;
  };
  readonly scanned: {
    readonly missions: number;
    readonly runs: number;
    readonly evaluations: number;
  };
  readonly expectedNodeIds: readonly string[];
  readonly missingNodeIds: readonly string[];
  readonly missingEdges: readonly ExpectedEdge[];
  readonly forgottenNodeIds: readonly string[];
  readonly skippedByForgottenDependencyNodeIds: readonly string[];
  readonly skippedEdgeKeys: readonly string[];
  readonly skippedByPolicyNodeIds: readonly string[];
  readonly skippedByPolicyEdgeKeys: readonly string[];
  readonly existingProjectionPendingNodeIds: readonly string[];
  readonly privacyQuarantinedEdges: readonly {
    readonly edgeId: string;
    readonly reasonCode: "reusable_private_boundary";
    readonly sourceNodeType: string;
    readonly targetNodeType: string;
    readonly detectedAt: string;
  }[];
  readonly conflicts: readonly CanonicalMemoryReconciliationConflict[];
}

export interface CanonicalMemoryReconciliationReport {
  readonly analysis: CanonicalMemoryReconciliationAnalysis;
  readonly createdNodeIds: readonly string[];
  readonly createdEdges: readonly ExpectedEdge[];
  readonly auditRecordIds: readonly string[];
  readonly projection: ConnectedVaultProjectionReport;
  readonly completedAt: string;
}

function edgeKey(edge: ExpectedEdge): string {
  return `${edge.sourceNodeId}:${edge.edgeType}:${edge.targetNodeId}`;
}

function emptyProjection(): ConnectedVaultProjectionReport {
  return {
    requestedNodeIds: [],
    skippedByPolicyNodeIds: [],
    attempted: 0,
    synchronized: 0,
    attentionRequired: 0,
    skippedByPolicy: 0,
    failures: 0,
  };
}

/**
 * One-shot, idempotent repair for V2-owned mission memory anchors.
 *
 * The service never reads objectives, targets, raw output, Context Packs, or
 * imported legacy control-plane rows. Operator-forgotten identities remain
 * tombstoned. Projection is an export-only post-commit operation; Vault edits
 * are left vault-ahead or conflicted for deliberate operator review.
 */
export class CanonicalMemoryReconciliationService {
  readonly #graph: CanonicalMissionMemoryGraph;
  readonly #audit: AuditTrailWriter;
  readonly #clock: () => Date;

  constructor(
    readonly database: SqliteDatabase,
    readonly projector?: ConnectedVaultMemoryProjector,
    options: { readonly clock?: () => Date } = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#graph = new CanonicalMissionMemoryGraph(database, { clock: this.#clock });
    this.#audit = new AuditTrailWriter(database);
  }

  analyze(): CanonicalMemoryReconciliationAnalysis {
    const policy = getMemoryControlPolicy(this.database);
    const { missions, runs, evaluations } = this.#canonicalRows();
    const expectedNodes = this.#expectedNodes(missions, runs, evaluations);
    const expectedEdges = this.#expectedEdges(runs, evaluations);
    const conflicts: CanonicalMemoryReconciliationConflict[] = [];
    const forgotten = new Set<string>();
    const missing = new Set<string>();
    const stored = new Map<string, NodeRow>();

    for (const expected of expectedNodes) {
      const row = this.database.prepare(`
        SELECT id, node_type, mission_id, lifecycle_status, sensitivity, version
        FROM memory_nodes WHERE id = ?
      `).get(expected.id) as NodeRow | undefined;
      if (!row) {
        missing.add(expected.id);
        continue;
      }
      stored.set(expected.id, row);
      if (row.lifecycle_status === "forgotten") {
        forgotten.add(expected.id);
        continue;
      }
      const source = this.database.prepare(`
        SELECT 1 FROM memory_sources
        WHERE node_id = ? AND source_type = ? AND source_id = ?
      `).get(expected.id, expected.sourceType, expected.sourceId);
      if (
        row.node_type !== expected.nodeType
        || row.mission_id !== expected.missionId
        || row.lifecycle_status !== "verified"
        || row.sensitivity !== "private"
        || !source
      ) {
        conflicts.push({
          resourceType: "memory_node",
          resourceId: expected.id,
          reason: "The deterministic canonical identity is occupied by a node with incompatible type, scope, lifecycle, sensitivity, or provenance.",
        });
      }
    }

    const skippedByForgottenDependency = new Set<string>();
    for (const expected of expectedNodes) {
      if (forgotten.has(expected.id)) continue;
      if (expected.dependencyNodeIds.some((nodeId) => (
        forgotten.has(nodeId) || skippedByForgottenDependency.has(nodeId)
      ))) {
        skippedByForgottenDependency.add(expected.id);
        missing.delete(expected.id);
      }
    }

    const missingEdges: ExpectedEdge[] = [];
    const skippedEdgeKeys: string[] = [];
    for (const expected of expectedEdges) {
      const blockedByForgotten = [expected.sourceNodeId, expected.targetNodeId].some((nodeId) => (
        forgotten.has(nodeId) || skippedByForgottenDependency.has(nodeId)
      ));
      if (blockedByForgotten) {
        skippedEdgeKeys.push(edgeKey(expected));
        continue;
      }
      const row = this.database.prepare(`
        SELECT id, mission_id, lifecycle_status FROM memory_edges
        WHERE source_node_id = ? AND edge_type = ? AND target_node_id = ?
        ORDER BY version DESC LIMIT 1
      `).get(expected.sourceNodeId, expected.edgeType, expected.targetNodeId) as EdgeRow | undefined;
      if (!row) {
        missingEdges.push(expected);
        continue;
      }
      if (row.mission_id !== expected.missionId || row.lifecycle_status !== "verified") {
        conflicts.push({
          resourceType: "memory_edge",
          resourceId: row.id,
          reason: "The canonical relationship exists with incompatible mission scope or lifecycle.",
        });
      }
    }

    const retentionAllowed = policy.enabled && policy.operationalMemoryEnabled;
    const missingNodeIds = retentionAllowed
      ? [...missing].filter((nodeId) => !skippedByForgottenDependency.has(nodeId)).sort()
      : [];
    const effectiveMissingEdges = retentionAllowed ? missingEdges : [];
    const skippedByPolicyNodeIds = retentionAllowed
      ? []
      : expectedNodes
          .filter(({ id }) => !forgotten.has(id))
          .map(({ id }) => id)
          .sort();
    const skippedByPolicyEdgeKeys = retentionAllowed
      ? []
      : expectedEdges.map(edgeKey).sort();
    const existingProjectionPendingNodeIds = retentionAllowed
      ? expectedNodes
          .map(({ id }) => id)
          .filter((nodeId) => stored.has(nodeId) && !forgotten.has(nodeId))
          .filter((nodeId) => this.#needsProjection(nodeId, false))
          .sort()
      : [];
    const hasPrivacyQuarantine = Boolean(this.database.prepare(`
      SELECT 1 FROM sqlite_master
      WHERE type = 'table' AND name = 'memory_edge_privacy_quarantine'
    `).get());
    const privacyQuarantinedEdges = hasPrivacyQuarantine
      ? (this.database.prepare(`
          SELECT edge_id, reason_code, source_node_type, target_node_type, detected_at
          FROM memory_edge_privacy_quarantine
          ORDER BY detected_at, edge_id
        `).all() as Array<{
          edge_id: string;
          reason_code: "reusable_private_boundary";
          source_node_type: string;
          target_node_type: string;
          detected_at: string;
        }>).map((row) => ({
          edgeId: row.edge_id,
          reasonCode: row.reason_code,
          sourceNodeType: row.source_node_type,
          targetNodeType: row.target_node_type,
          detectedAt: row.detected_at,
        }))
      : [];

    return {
      policy: {
        enabled: policy.enabled,
        operationalMemoryEnabled: policy.operationalMemoryEnabled,
        version: policy.version,
      },
      scanned: {
        missions: missions.length,
        runs: runs.length,
        evaluations: evaluations.length,
      },
      expectedNodeIds: expectedNodes.map(({ id }) => id).sort(),
      missingNodeIds,
      missingEdges: effectiveMissingEdges,
      forgottenNodeIds: [...forgotten].sort(),
      skippedByForgottenDependencyNodeIds: [...skippedByForgottenDependency].sort(),
      skippedEdgeKeys: skippedEdgeKeys.sort(),
      skippedByPolicyNodeIds,
      skippedByPolicyEdgeKeys,
      existingProjectionPendingNodeIds,
      privacyQuarantinedEdges,
      conflicts,
    };
  }

  reconcile(): CanonicalMemoryReconciliationReport {
    let committedAnalysis!: CanonicalMemoryReconciliationAnalysis;
    const createdNodeIds: string[] = [];
    const createdEdges: ExpectedEdge[] = [];
    const auditRecordIds: string[] = [];
    const forceProjection = new Set<string>();

    inImmediateTransaction(this.database, () => {
      committedAnalysis = this.analyze();
      if (committedAnalysis.conflicts.length > 0) {
        throw new Error("Canonical memory reconciliation is blocked by identity conflicts");
      }
      if (!committedAnalysis.policy.enabled || !committedAnalysis.policy.operationalMemoryEnabled) return;

      const missingNodes = new Set(committedAnalysis.missingNodeIds);
      const missingEdges = new Set(committedAnalysis.missingEdges.map(edgeKey));
      const { missions, runs, evaluations } = this.#canonicalRows();
      for (const mission of missions) this.#graph.ensureMission(mission.id);
      for (const run of runs) this.#graph.ensureRun(run.id);
      for (const evaluation of evaluations) this.#graph.ensureEvaluation(evaluation.id);

      for (const nodeId of missingNodes) {
        const created = this.database.prepare("SELECT 1 FROM memory_nodes WHERE id = ?")
          .get(nodeId);
        if (created) {
          createdNodeIds.push(nodeId);
          forceProjection.add(nodeId);
        }
      }
      for (const edge of committedAnalysis.missingEdges) {
        if (!missingEdges.has(edgeKey(edge))) continue;
        const created = this.database.prepare(`
          SELECT 1 FROM memory_edges
          WHERE source_node_id = ? AND edge_type = ? AND target_node_id = ?
        `).get(edge.sourceNodeId, edge.edgeType, edge.targetNodeId);
        if (created) {
          createdEdges.push(edge);
          forceProjection.add(edge.sourceNodeId);
          forceProjection.add(edge.targetNodeId);
        }
      }

      const changesByMission = new Map<string, { nodes: string[]; edges: string[] }>();
      const add = (missionId: string) => {
        let value = changesByMission.get(missionId);
        if (!value) {
          value = { nodes: [], edges: [] };
          changesByMission.set(missionId, value);
        }
        return value;
      };
      const expectedById = new Map(this.#expectedNodes(missions, runs, evaluations)
        .map((node) => [node.id, node] as const));
      for (const nodeId of createdNodeIds) {
        const expected = expectedById.get(nodeId);
        if (expected) add(expected.missionId).nodes.push(nodeId);
      }
      for (const edge of createdEdges) add(edge.missionId).edges.push(edgeKey(edge));
      for (const [missionId, changes] of changesByMission) {
        auditRecordIds.push(this.#audit.append({
          missionId,
          actor: { type: "system", id: "system:canonical-memory-reconciliation" },
          action: "memory.canonical_graph_reconciled",
          resourceType: "memory_graph",
          resourceId: missionId,
          reason: "Materialized missing privacy-safe canonical V2 mission graph anchors and relationships.",
          details: {
            createdNodeIds: changes.nodes.sort(),
            createdEdgeKeys: changes.edges.sort(),
            memoryControlVersion: committedAnalysis.policy.version,
          },
          occurredAt: this.#clock().toISOString(),
        }));
      }
    });

    let projection = emptyProjection();
    if (committedAnalysis.policy.enabled && committedAnalysis.policy.operationalMemoryEnabled && this.projector) {
      const candidates = committedAnalysis.expectedNodeIds.filter((nodeId) => (
        !committedAnalysis.forgottenNodeIds.includes(nodeId)
        && !committedAnalysis.skippedByForgottenDependencyNodeIds.includes(nodeId)
        && this.database.prepare("SELECT 1 FROM memory_nodes WHERE id = ?").get(nodeId)
        && this.#needsProjection(nodeId, forceProjection.has(nodeId))
      ));
      if (candidates.length > 0) projection = this.projector.project(candidates);
    }

    return {
      analysis: committedAnalysis,
      createdNodeIds: createdNodeIds.sort(),
      createdEdges,
      auditRecordIds,
      projection,
      completedAt: this.#clock().toISOString(),
    };
  }

  #canonicalRows(): {
    readonly missions: readonly MissionRow[];
    readonly runs: readonly RunRow[];
    readonly evaluations: readonly EvaluationRow[];
  } {
    const missions = this.database.prepare(`
      SELECT id FROM missions WHERE control_plane = 'ti_scale' ORDER BY id
    `).all() as MissionRow[];
    const runs = this.database.prepare(`
      SELECT r.id, r.mission_id FROM runs r
      JOIN missions m ON m.id = r.mission_id
      WHERE r.control_plane = 'ti_scale' AND m.control_plane = 'ti_scale'
      ORDER BY r.id
    `).all() as RunRow[];
    const evaluations = this.database.prepare(`
      SELECT e.id, e.mission_id, e.run_id FROM run_evaluations e
      JOIN runs r ON r.id = e.run_id
      JOIN missions m ON m.id = e.mission_id AND m.id = r.mission_id
      WHERE r.control_plane = 'ti_scale' AND m.control_plane = 'ti_scale'
      ORDER BY e.id
    `).all() as EvaluationRow[];
    return { missions, runs, evaluations };
  }

  #expectedNodes(
    missions: readonly MissionRow[],
    runs: readonly RunRow[],
    evaluations: readonly EvaluationRow[],
  ): readonly ExpectedNode[] {
    return [
      ...missions.map((mission): ExpectedNode => ({
        id: canonicalMissionMemoryNodeId(mission.id),
        nodeType: "mission",
        missionId: mission.id,
        sourceType: "mission",
        sourceId: mission.id,
        dependencyNodeIds: [],
      })),
      ...runs.map((run): ExpectedNode => ({
        id: canonicalRunMemoryNodeId(run.id),
        nodeType: "run",
        missionId: run.mission_id,
        sourceType: "run",
        sourceId: run.id,
        dependencyNodeIds: [canonicalMissionMemoryNodeId(run.mission_id)],
      })),
      ...evaluations.map((evaluation): ExpectedNode => ({
        id: canonicalRunEvaluationMemoryNodeId(evaluation.id),
        nodeType: "evaluation",
        missionId: evaluation.mission_id,
        sourceType: "run_evaluation",
        sourceId: evaluation.id,
        dependencyNodeIds: [
          canonicalMissionMemoryNodeId(evaluation.mission_id),
          canonicalRunMemoryNodeId(evaluation.run_id),
        ],
      })),
    ];
  }

  #expectedEdges(
    runs: readonly RunRow[],
    evaluations: readonly EvaluationRow[],
  ): readonly ExpectedEdge[] {
    return [
      ...runs.map((run): ExpectedEdge => ({
        sourceNodeId: canonicalRunMemoryNodeId(run.id),
        targetNodeId: canonicalMissionMemoryNodeId(run.mission_id),
        edgeType: "belongs_to",
        missionId: run.mission_id,
      })),
      ...evaluations.map((evaluation): ExpectedEdge => ({
        sourceNodeId: canonicalRunEvaluationMemoryNodeId(evaluation.id),
        targetNodeId: canonicalRunMemoryNodeId(evaluation.run_id),
        edgeType: "derived_from",
        missionId: evaluation.mission_id,
      })),
    ];
  }

  #needsProjection(nodeId: string, force: boolean): boolean {
    if (!this.projector) return false;
    const connections = this.database.prepare(`
      SELECT id FROM vault_connections WHERE status = 'connected' ORDER BY id
    `).all() as Array<{ id: string }>;
    if (connections.length === 0) return false;
    const node = this.database.prepare("SELECT version FROM memory_nodes WHERE id = ?")
      .get(nodeId) as { version: number } | undefined;
    if (!node) return false;
    for (const connection of connections) {
      try {
        this.projector.bridge.assertConnectionNodeAllowed(connection.id, nodeId);
      } catch (error) {
        const message = error instanceof Error ? error.message.toLocaleLowerCase("en-US") : "";
        if (
          message.includes("outside the vault connection")
          || message.includes("memory lifecycle")
          || message.includes("private operational provenance")
          || message.includes("synchronization is not permitted")
        ) continue;
        return true;
      }
      if (force) return true;
      const state = this.database.prepare(`
        SELECT status, database_version FROM vault_sync_state
        WHERE connection_id = ? AND node_id = ?
        ORDER BY rowid DESC LIMIT 1
      `).get(connection.id, nodeId) as {
        status: string;
        database_version: number | null;
      } | undefined;
      if (!state || state.status !== "synced" || state.database_version !== node.version) return true;
    }
    return false;
  }
}

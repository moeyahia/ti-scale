import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdtempSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  getMemoryControlPolicy,
  MemoryRepository,
  updateMemoryControlPolicy,
} from "../../memory";
import {
  ConnectedVaultMemoryProjector,
  ObsidianVaultBridge,
  VaultPathPolicy,
} from "../../vault";
import {
  CanonicalMemoryReconciliationService,
  CanonicalMissionMemoryGraph,
  canonicalMissionMemoryNodeId,
  canonicalRunEvaluationMemoryNodeId,
  canonicalRunMemoryNodeId,
} from "../index";
import { runCanonicalMemoryReconciliationCli } from "../cli";

const NOW = "2026-07-19T12:00:00.000Z";
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function setup() {
  const directory = mkdtempSync(join(tmpdir(), "canonical-brain-reconcile-"));
  temporaryDirectories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "canonical.sqlite") });
  migrateDatabase(database);
  const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
  const bridge = new ObsidianVaultBridge(
    database,
    memory,
    new VaultPathPolicy(join(directory, "vaults")),
    { clock: () => new Date(NOW) },
  );
  return { directory, database, memory, bridge };
}

function seedMissionRun(
  database: ReturnType<typeof createDatabaseConnection>,
  input: {
    readonly missionId: string;
    readonly runId: string;
    readonly controlPlane?: "ti_scale" | "legacy";
    readonly withEvaluation?: boolean;
  },
): string | undefined {
  const controlPlane = input.controlPlane ?? "ti_scale";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      created_by, control_plane, created_at, updated_at
    ) VALUES (?, 'Canonical fixture', 'Exercise privacy-safe graph repair',
      'guided', 'completed', 'verified', ?, 'operator:test', ?, ?, ?)
  `).run(input.missionId, `engagement-${input.missionId}`, controlPlane, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, budget_json, budget_usage_json,
      control_plane, started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, 'guided', 'completed', '{}', '{}', ?, ?, ?, ?, ?)
  `).run(input.runId, input.missionId, controlPlane, NOW, NOW, NOW, NOW);
  if (!input.withEvaluation) return undefined;
  const evaluationId = `evaluation-${input.runId}`;
  database.prepare(`
    INSERT INTO run_evaluations (
      id, mission_id, run_id, journey, scores_json, metrics_json,
      retrospective, evidence_coverage, created_by, created_at
    ) VALUES (?, ?, ?, 'guided', '{"objectiveCompletion":0}',
      '{"completionBasis":"outcome_not_evaluated"}',
      'The bounded workflow ended without a verified objective claim.', 0,
      'run-evaluator', ?)
  `).run(evaluationId, input.missionId, input.runId, NOW);
  return evaluationId;
}

describe("CanonicalMemoryReconciliationService", () => {
  test("CLI is read-only by default and reconciles forward without a backup", async () => {
    const { database, bridge, directory } = setup();
    const databasePath = database.name;
    const vaultRoot = join(directory, "vaults");
    seedMissionRun(database, { missionId: "mission-cli", runId: "run-cli" });
    bridge.connect({
      id: "vault-cli-reconcile",
      vaultPath: "Ti-Scale-Brain",
      displayName: "CLI reconciliation fixture",
      syncScope: {
        missionIds: ["mission-cli"],
        sensitivities: ["private"],
        lifecycleStatuses: ["verified"],
      },
      permissionGranted: true,
    });
    database.close();

    const dryOutput: string[] = [];
    expect(await runCanonicalMemoryReconciliationCli([
      "reconcile",
      "--db",
      databasePath,
      "--vault-root",
      vaultRoot,
    ], {}, (value) => dryOutput.push(value))).toBe(0);
    expect(JSON.parse(dryOutput.join("")).mode).toBe("dry_run");
    let inspection = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    expect(inspection.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get()).toEqual({ count: 0 });
    inspection.close();

    const executeOutput: string[] = [];
    expect(await runCanonicalMemoryReconciliationCli([
      "reconcile",
      "--execute",
      "--db",
      databasePath,
      "--vault-root",
      vaultRoot,
    ], {}, (value) => executeOutput.push(value))).toBe(0);
    const result = JSON.parse(executeOutput.join("")) as {
      mode: string;
      backup: null;
      backupPolicy: string;
      report: { createdNodeIds: string[]; createdEdges: unknown[] };
    };
    expect(result.mode).toBe("execute");
    expect(result.backup).toBeNull();
    expect(result.backupPolicy).toBe("disabled_by_operator");
    expect(existsSync(join(directory, "backups"))).toBe(false);
    expect(result.report.createdNodeIds).toHaveLength(2);
    expect(result.report.createdEdges).toHaveLength(1);
    inspection = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    expect(inspection.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get()).toEqual({ count: 2 });
    inspection.close();

    await expect(runCanonicalMemoryReconciliationCli([
      "reconcile",
      "--execute",
      "--db",
      databasePath,
      "--vault-root",
      vaultRoot,
      "--backup-dir",
      join(directory, "forbidden-backups"),
    ], {}, () => undefined)).rejects.toThrow("--backup-dir is unavailable");
    expect(existsSync(join(directory, "forbidden-backups"))).toBe(false);
  });

  test("repairs only Ti-Scale-owned anchors, keeps operational provenance private, and is idempotent", () => {
    const { database, bridge, directory } = setup();
    try {
      const evaluationId = seedMissionRun(database, {
        missionId: "mission-current-a",
        runId: "run-current-a",
        withEvaluation: true,
      })!;
      seedMissionRun(database, {
        missionId: "mission-current-b",
        runId: "run-current-b",
      });
      seedMissionRun(database, {
        missionId: "mission-imported",
        runId: "run-imported",
        controlPlane: "legacy",
        withEvaluation: true,
      });
      database.prepare(`
        INSERT INTO memory_context_packs (
          id, mission_id, run_id, journey, purpose, scope_policy_json,
          context_budget, retrieval_metrics_json, created_by, created_at
        ) VALUES ('context-immutable', 'mission-current-a', 'run-current-a',
          'guided', 'Preserved historical pack', '{}', 100, '{}', 'agent:test', ?)
      `).run(NOW);
      const contextBefore = database.prepare(`
        SELECT * FROM memory_context_packs WHERE id = 'context-immutable'
      `).get();
      const connection = bridge.connect({
        id: "vault-canonical-reconcile",
        vaultPath: "Ti-Scale-Brain",
        displayName: "Canonical reconciliation fixture",
        syncScope: {
          missionIds: ["mission-current-a", "mission-current-b"],
          sensitivities: ["private"],
          lifecycleStatuses: ["verified"],
        },
        permissionGranted: true,
      });
      const service = new CanonicalMemoryReconciliationService(
        database,
        new ConnectedVaultMemoryProjector(database, bridge, { clock: () => new Date(NOW) }),
        { clock: () => new Date(NOW) },
      );

      const dryRun = service.analyze();
      expect(dryRun.scanned).toEqual({ missions: 2, runs: 2, evaluations: 1 });
      expect(dryRun.missingNodeIds).toHaveLength(5);
      expect(dryRun.missingEdges).toHaveLength(3);
      expect(dryRun.conflicts).toEqual([]);
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get()).toEqual({ count: 0 });

      const first = service.reconcile();
      expect(first.createdNodeIds).toHaveLength(5);
      expect(first.createdEdges).toHaveLength(3);
      expect(first.projection).toMatchObject({
        attempted: 0,
        synchronized: 0,
        skippedByPolicy: 0,
        attentionRequired: 0,
        failures: 0,
      });
      expect(first.projection.requestedNodeIds).toEqual([]);
      expect(first.projection.skippedByPolicyNodeIds).toEqual([]);
      expect(first.auditRecordIds).toHaveLength(2);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM memory_nodes
        WHERE id IN (?, ?, ?, ?, ?)
      `).get(
        canonicalMissionMemoryNodeId("mission-current-a"),
        canonicalRunMemoryNodeId("run-current-a"),
        canonicalRunEvaluationMemoryNodeId(evaluationId),
        canonicalMissionMemoryNodeId("mission-current-b"),
        canonicalRunMemoryNodeId("run-current-b"),
      )).toEqual({ count: 5 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM memory_nodes
        WHERE id IN (?, ?, ?)
      `).get(
        canonicalMissionMemoryNodeId("mission-imported"),
        canonicalRunMemoryNodeId("run-imported"),
        canonicalRunEvaluationMemoryNodeId("evaluation-run-imported"),
      )).toEqual({ count: 0 });
      const evaluationNodeId = canonicalRunEvaluationMemoryNodeId(evaluationId);
      const rendered = bridge.renderNode(evaluationNodeId, connection);
      expect(existsSync(join(connection.vaultPath, rendered.relativePath))).toBe(false);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM vault_sync_state WHERE connection_id = ?
      `).get(connection.id)).toEqual({ count: 0 });
      expect(database.prepare(`
        SELECT * FROM memory_context_packs WHERE id = 'context-immutable'
      `).get()).toEqual(contextBefore);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM memory_context_items
        WHERE context_pack_id = 'context-immutable'
      `).get()).toEqual({ count: 0 });

      const auditCount = database.prepare("SELECT COUNT(*) AS count FROM audit_records").get();
      const replay = service.reconcile();
      expect(replay.createdNodeIds).toEqual([]);
      expect(replay.createdEdges).toEqual([]);
      expect(replay.projection.requestedNodeIds).toEqual([]);
      expect(replay.auditRecordIds).toEqual([]);
      expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records").get()).toEqual(auditCount);
      expect(service.analyze()).toMatchObject({
        missingNodeIds: [],
        missingEdges: [],
        existingProjectionPendingNodeIds: [],
        conflicts: [],
      });
    } finally {
      database.close();
    }
  });

  test("respects disabled operational retention and preserves forgotten tombstones", () => {
    const { database, memory } = setup();
    try {
      const evaluationId = seedMissionRun(database, {
        missionId: "mission-policy",
        runId: "run-policy",
        withEvaluation: true,
      })!;
      const control = getMemoryControlPolicy(database);
      updateMemoryControlPolicy({
        database,
        expectedVersion: control.version,
        actor: "operator:test",
        now: NOW,
        policy: {
          ...control,
          enabled: true,
          operationalMemoryEnabled: false,
        },
      });
      const disabled = new CanonicalMemoryReconciliationService(database, undefined, {
        clock: () => new Date(NOW),
      });
      expect(disabled.analyze().skippedByPolicyNodeIds).toHaveLength(3);
      expect(disabled.reconcile()).toMatchObject({ createdNodeIds: [], createdEdges: [] });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get()).toEqual({ count: 0 });

      const disabledControl = getMemoryControlPolicy(database);
      updateMemoryControlPolicy({
        database,
        expectedVersion: disabledControl.version,
        actor: "operator:test",
        now: NOW,
        policy: { ...disabledControl, operationalMemoryEnabled: true },
      });
      const graph = new CanonicalMissionMemoryGraph(database, { clock: () => new Date(NOW) });
      graph.ensureEvaluation(evaluationId);
      const runNodeId = canonicalRunMemoryNodeId("run-policy");
      memory.forgetNode(runNodeId, "operator:test", "Exercise canonical tombstone handling");

      const missionForgottenEvaluation = seedMissionRun(database, {
        missionId: "mission-forgotten-anchor",
        runId: "run-forgotten-anchor",
        withEvaluation: true,
      })!;
      graph.ensureEvaluation(missionForgottenEvaluation);
      const missionNodeId = canonicalMissionMemoryNodeId("mission-forgotten-anchor");
      memory.forgetNode(missionNodeId, "operator:test", "Exercise mission-anchor forgetting");

      const evaluationForgottenId = seedMissionRun(database, {
        missionId: "mission-forgotten-evaluation",
        runId: "run-forgotten-evaluation",
        withEvaluation: true,
      })!;
      graph.ensureEvaluation(evaluationForgottenId);
      const evaluationNodeId = canonicalRunEvaluationMemoryNodeId(evaluationForgottenId);
      memory.forgetNode(evaluationNodeId, "operator:test", "Exercise evaluation-anchor forgetting");

      const service = new CanonicalMemoryReconciliationService(database, undefined, {
        clock: () => new Date(NOW),
      });
      const analysis = service.analyze();
      expect(analysis.forgottenNodeIds).toEqual([evaluationNodeId, missionNodeId, runNodeId].sort());
      expect(analysis.skippedByForgottenDependencyNodeIds)
        .toContain(canonicalRunEvaluationMemoryNodeId(evaluationId));
      expect(analysis.skippedByForgottenDependencyNodeIds)
        .toContain(canonicalRunMemoryNodeId("run-forgotten-anchor"));
      expect(analysis.skippedByForgottenDependencyNodeIds)
        .toContain(canonicalRunEvaluationMemoryNodeId(missionForgottenEvaluation));
      expect(analysis.skippedEdgeKeys).toHaveLength(5);
      expect(() => service.reconcile()).not.toThrow();
      expect((database.prepare(`
        SELECT lifecycle_status FROM memory_nodes WHERE id = ?
      `).get(runNodeId) as { lifecycle_status: string }).lifecycle_status).toBe("forgotten");
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM memory_edges
        WHERE source_node_id = ? OR target_node_id = ?
      `).get(runNodeId, runNodeId)).toEqual({ count: 0 });
      expect((database.prepare(`
        SELECT lifecycle_status FROM memory_nodes WHERE id = ?
      `).get(missionNodeId) as { lifecycle_status: string }).lifecycle_status).toBe("forgotten");
      expect((database.prepare(`
        SELECT lifecycle_status FROM memory_nodes WHERE id = ?
      `).get(evaluationNodeId) as { lifecycle_status: string }).lifecycle_status).toBe("forgotten");
    } finally {
      database.close();
    }
  });

  test("reports deterministic identity collisions without mutating canonical state", () => {
    const { database, memory } = setup();
    try {
      seedMissionRun(database, { missionId: "mission-conflict", runId: "run-conflict" });
      memory.createNode({
        id: canonicalMissionMemoryNodeId("mission-conflict"),
        nodeType: "artifact",
        title: "Conflicting deterministic identity",
        summary: "A non-canonical node occupies the stable anchor identity.",
        scope: { kind: "mission", missionId: "mission-conflict" },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: {
          method: "derived",
          explanation: "Collision fixture",
          sources: [{ sourceType: "artifact", sourceId: "fixture", acquiredAt: NOW }],
        },
        authorType: "system",
      });
      const service = new CanonicalMemoryReconciliationService(database);
      expect(service.analyze().conflicts).toHaveLength(1);
      expect(() => service.reconcile()).toThrow("blocked by identity conflicts");
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });
});

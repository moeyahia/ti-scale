import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CanonicalMemoryReconciliationService,
  CanonicalMissionMemoryGraph,
  canonicalMissionMemoryNodeId,
  canonicalRunMemoryNodeId,
} from "../../brain-runtime";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { EventRepository } from "../../events";
import { RunLearningService } from "../../learning/RunLearningService";
import { MemoryRepository } from "../../memory";
import {
  ConnectedVaultMemoryProjector,
  ObsidianVaultBridge,
  VaultPathPolicy,
} from "../index";

const temporaryDirectories: string[] = [];
const NOW = "2026-07-19T10:00:00.000Z";

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function seedTerminalRun(
  database: ReturnType<typeof createDatabaseConnection>,
  input: { readonly missionId: string; readonly runId: string; readonly engagementId: string },
): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      created_by, created_at, updated_at
    ) VALUES (?, 'Projection fixture', 'Exercise the local projection boundary',
      'guided', 'completed', 'verified', ?, 'operator', ?, ?)
  `).run(input.missionId, input.engagementId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, budget_json, budget_usage_json,
      started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, 'guided', 'completed', '{}', '{}', ?, ?, ?, ?)
  `).run(input.runId, input.missionId, NOW, NOW, NOW, NOW);
}

describe("ConnectedVaultMemoryProjector", () => {
  test("keeps terminal mission records as private provenance outside the reusable Attack Vault", () => {
    const directory = mkdtempSync(join(tmpdir(), "connected-vault-projector-"));
    temporaryDirectories.push(directory);
    const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
    migrateDatabase(database);
    const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
    const bridge = new ObsidianVaultBridge(
      database,
      memory,
      new VaultPathPolicy(join(directory, "allowed-vaults")),
      { clock: () => new Date(NOW) },
    );
    const connection = bridge.connect({
      id: "vault-runtime-projection",
      vaultPath: "Ti-Scale-Brain",
      displayName: "Runtime projection fixture",
      syncScope: {
        sensitivities: ["private"],
        lifecycleStatuses: ["verified", "confirmed", "candidate"],
      },
      permissionGranted: true,
    });
    const projector = new ConnectedVaultMemoryProjector(database, bridge, {
      clock: () => new Date(NOW),
    });
    const projectionReports: ReturnType<typeof projector.project>[] = [];
    const learning = new RunLearningService(database, {
      clock: () => new Date(NOW),
      events: new EventRepository(database),
      projectMemoryNodes: (nodeIds) => {
        expect(database.inTransaction).toBe(false);
        projectionReports.push(projector.project(nodeIds));
      },
    });
    try {
      seedTerminalRun(database, {
        missionId: "mission-vault-runtime",
        runId: "run-vault-runtime",
        engagementId: "engagement-vault-runtime",
      });
      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity,
          verification_state, summary, created_by, created_at
        ) VALUES (
          'evidence-vault-runtime', 'mission-vault-runtime',
          'run-vault-runtime', 'specialist', ?, 'private-target.example',
          'service_observation', ?, '{}', 1, 'restricted', 'verified',
          'Immutable evidence contains token=never-project-this',
          'agent:recon', ?
        )
      `).run(NOW, "a".repeat(64), NOW);
      learning.recordTerminalEvaluation({
        runId: "run-vault-runtime",
        terminalStatus: "completed",
        createdBy: "run-supervisor",
        outcome: {
          success: true,
          summary: "The bounded result has verified immutable evidence.",
          criteria: [{
            criterion: "Retain verified evidence",
            satisfied: true,
            explanation: "The canonical evidence record is verified.",
            evidenceIds: ["evidence-vault-runtime"],
          }],
        },
      });
      learning.projectTerminalMemory("run-vault-runtime");

      expect(projectionReports).toEqual([expect.objectContaining({
        attempted: 0,
        synchronized: 0,
        attentionRequired: 0,
        skippedByPolicy: 4,
        failures: 0,
      })]);
      const evaluationNodeId = (database.prepare(`
        SELECT id FROM memory_nodes WHERE node_type = 'evaluation'
      `).get() as { id: string }).id;
      const missionNodeId = canonicalMissionMemoryNodeId("mission-vault-runtime");
      const runNodeId = canonicalRunMemoryNodeId("run-vault-runtime");
      const lessonNodeId = (database.prepare(`
        SELECT id FROM memory_nodes WHERE node_type = 'lesson'
      `).get() as { id: string }).id;
      expect(projectionReports[0]?.skippedByPolicyNodeIds).toEqual(
        [missionNodeId, runNodeId, evaluationNodeId, lessonNodeId].sort(),
      );
      for (const nodeId of [missionNodeId, runNodeId, evaluationNodeId, lessonNodeId]) {
        const rendered = bridge.renderNode(nodeId, connection);
        const path = join(connection.vaultPath, rendered.relativePath);
        expect(existsSync(path)).toBe(false);
      }
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM vault_sync_state
        WHERE connection_id = ? AND status = 'synced'
      `).get(connection.id)).toEqual({ count: 0 });
      const firstProjectionAudit = database.prepare(`
        SELECT details_json FROM audit_records
        WHERE mission_id = 'mission-vault-runtime'
          AND action = 'memory.vault_projection_completed'
        ORDER BY rowid DESC LIMIT 1
      `).get() as { details_json: string };
      expect(JSON.parse(firstProjectionAudit.details_json)).toMatchObject({
        attempted: 0,
        synchronized: 0,
        skippedByPolicy: 4,
        skippedByPolicyNodeIds: [evaluationNodeId, lessonNodeId, missionNodeId, runNodeId].sort(),
      });
      expect(database.prepare(`SELECT status FROM vault_connections WHERE id = ?`)
        .get(connection.id)).toEqual({ status: "connected" });
    } finally {
      database.close();
    }
  });

  test("does not degrade a connection when canonical mission records are intentionally private", () => {
    const directory = mkdtempSync(join(tmpdir(), "connected-vault-repair-"));
    temporaryDirectories.push(directory);
    const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
    migrateDatabase(database);
    const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
    class FailFirstProjectionPolicy extends VaultPathPolicy {
      shouldFail = true;
      override atomicWrite(...args: Parameters<VaultPathPolicy["atomicWrite"]>) {
        if (this.shouldFail) {
          this.shouldFail = false;
          throw new Error("Injected optional Vault filesystem failure");
        }
        return super.atomicWrite(...args);
      }
    }
    const bridge = new ObsidianVaultBridge(
      database,
      memory,
      new FailFirstProjectionPolicy(join(directory, "allowed-vaults")),
      { clock: () => new Date(NOW) },
    );
    const connection = bridge.connect({
      id: "vault-runtime-repair",
      vaultPath: "Ti-Scale-Brain",
      displayName: "Runtime repair fixture",
      syncScope: {
        missionIds: ["mission-vault-repair"],
        sensitivities: ["private"],
        lifecycleStatuses: ["verified"],
      },
      permissionGranted: true,
    });
    const projector = new ConnectedVaultMemoryProjector(database, bridge, {
      clock: () => new Date(NOW),
    });
    try {
      seedTerminalRun(database, {
        missionId: "mission-vault-repair",
        runId: "run-vault-repair",
        engagementId: "engagement-vault-repair",
      });
      const graph = new CanonicalMissionMemoryGraph(database, {
        clock: () => new Date(NOW),
      }).ensureRun("run-vault-repair");
      const missionNodeId = canonicalMissionMemoryNodeId("mission-vault-repair");
      const first = projector.project(graph.nodeIds);
      expect(first).toMatchObject({
        requestedNodeIds: graph.nodeIds,
        attempted: 0,
        synchronized: 0,
        attentionRequired: 0,
        skippedByPolicy: 2,
        skippedByPolicyNodeIds: [...graph.nodeIds].sort(),
        failures: 0,
      });
      expect(database.prepare(`
        SELECT status FROM vault_connections WHERE id = ?
      `).get(connection.id)).toEqual({ status: "connected" });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM vault_sync_state WHERE connection_id = ?
      `).get(connection.id)).toEqual({ count: 0 });
      const completedAudit = database.prepare(`
        SELECT reason, details_json FROM audit_records
        WHERE mission_id = 'mission-vault-repair'
          AND action = 'memory.vault_projection_completed'
        ORDER BY rowid DESC LIMIT 1
      `).get() as { reason: string; details_json: string };
      expect(completedAudit.reason).toContain("policy-ineligible nodes remain durable");
      expect(JSON.parse(completedAudit.details_json)).toMatchObject({
        nodeIds: expect.arrayContaining(graph.nodeIds),
        skippedByPolicy: 2,
        failures: 0,
      });
      const repaired = new CanonicalMemoryReconciliationService(
        database,
        projector,
        { clock: () => new Date(NOW) },
      ).reconcile();
      expect(repaired.createdNodeIds).toEqual([]);
      expect(repaired.createdEdges).toEqual([]);
      expect(repaired.projection).toMatchObject({
        requestedNodeIds: [],
        attempted: 0,
        synchronized: 0,
        skippedByPolicy: 0,
        failures: 0,
      });
      const repairedPath = join(
        connection.vaultPath,
        bridge.renderNode(missionNodeId, connection).relativePath,
      );
      expect(existsSync(repairedPath)).toBe(false);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM vault_sync_state
        WHERE connection_id = ? AND node_id = ?
      `).get(connection.id, missionNodeId)).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });
});

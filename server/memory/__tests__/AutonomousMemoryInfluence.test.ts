import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  AUTONOMOUS_ACTIVE_VAULT_REJECTION,
  AUTONOMOUS_LIFECYCLE_REJECTION,
  MemoryRepository,
  SecondBrainService,
  activeConnectedVaultBackedMemoryNodeIds,
} from "../index";

const NOW = "2026-07-23T12:00:00.000Z";

function fixture() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  const repository = new MemoryRepository(database, {
    clock: () => new Date(NOW),
  });
  return { database, repository, brain: new SecondBrainService(repository) };
}

function createAttackNode(repository: MemoryRepository, id: string) {
  return repository.createNode({
    id,
    nodeType: "attack_procedure",
    title: "Reusable bounded HTTP validation sequence",
    summary: "Verify the current product and version before one reversible request.",
    body: "Stop when the health gate fails; do not repeat the request without a fresh state transition.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 1,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "Operator-confirmed reusable procedure from attributable local evidence.",
      sources: [{
        sourceType: "operator_review",
        sourceId: `review-${id}`,
        sourceHash: "a".repeat(64),
        acquiredAt: NOW,
      }],
    },
    authorType: "operator",
    authorId: "operator:test",
    retentionPolicy: { allowAutonomous: true, allowGuided: true },
  });
}

function connectHealthyVault(
  database: ReturnType<typeof createDatabaseConnection>,
  connectionId = "vault-active",
): void {
  database.prepare(`
    INSERT INTO vault_connections (
      id, vault_path, display_name, status, sync_scope_json,
      permission_granted_at, last_sync_at, created_at, updated_at
    ) VALUES (?, ?, 'Active attack knowledge Vault', 'connected', '{}', ?, ?, ?, ?)
  `).run(connectionId, `/tmp/${connectionId}`, NOW, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO audit_records (
      id, actor_type, actor_id, action, resource_type, resource_id,
      reason, details_json, record_hash, occurred_at
    ) VALUES (?, 'operator', 'operator:test', 'vault.health.verified',
      'vault_connection', ?, 'Round trip passed', '{}', ?, ?)
  `).run(`audit-${connectionId}`, connectionId, "b".repeat(64), NOW);
}

function synchronize(
  database: ReturnType<typeof createDatabaseConnection>,
  nodeId: string,
  connectionId = "vault-active",
): void {
  const node = database.prepare(`
    SELECT version FROM memory_nodes WHERE id = ?
  `).get(nodeId) as { readonly version: number };
  const version = database.prepare(`
    SELECT content_hash FROM memory_versions WHERE node_id = ? AND version = ?
  `).get(nodeId, node.version) as { readonly content_hash: string };
  database.prepare(`
    INSERT INTO vault_sync_state (
      id, connection_id, node_id, relative_path, database_version,
      vault_content_hash, database_content_hash, status,
      last_scanned_at, last_synced_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'synced', ?, ?)
    ON CONFLICT(connection_id, relative_path) DO UPDATE SET
      database_version = excluded.database_version,
      vault_content_hash = excluded.vault_content_hash,
      database_content_hash = excluded.database_content_hash,
      status = 'synced',
      last_scanned_at = excluded.last_scanned_at,
      last_synced_at = excluded.last_synced_at
  `).run(
    `sync-${nodeId}`,
    connectionId,
    nodeId,
    `Attack Knowledge/${nodeId}.md`,
    node.version,
    version.content_hash,
    version.content_hash,
    NOW,
    NOW,
  );
}

describe("Autonomous memory influence boundary", () => {
  test("rejects a stale node even when its current Vault sync row still says synced", () => {
    const { database, repository } = fixture();
    try {
      const node = createAttackNode(repository, "mem_11111111111111111111111111111111");
      connectHealthyVault(database);
      synchronize(database, node.id);
      const pack = repository.persistContextPack({
        id: "context-stale-synced",
        journey: "autonomous",
        purpose: "Select a bounded reusable procedure",
        scopePolicy: {
          journey: "autonomous",
          allowGlobal: true,
          maximumSensitivity: "private",
          allowedStatuses: ["confirmed", "verified"],
          allowedScopeClasses: ["confirmed_attack_knowledge"],
          contextBudget: 2_000,
        },
        contextBudget: 2_000,
        createdBy: "planner",
        items: [{
          node,
          score: 1,
          relevanceReason: "Exact reviewed procedure",
          signals: ["exact"],
        }],
      });
      repository.correctNode(node.id, {
        lifecycleStatus: "stale",
        confirmationState: "confirmed",
        authorType: "operator",
        authorId: "operator:test",
        changeReason: "The procedure requires a fresh independent review",
      });
      // Reproduce the reported edge case explicitly: the row claims a current
      // successful sync even though the canonical lifecycle is now stale.
      synchronize(database, node.id);

      expect(database.prepare(`
        SELECT lifecycle_status FROM memory_nodes WHERE id = ?
      `).get(node.id)).toEqual({ lifecycle_status: "stale" });
      expect(activeConnectedVaultBackedMemoryNodeIds(database, [node.id]))
        .toEqual(new Set());
      repository.setContextItemDisposition(pack.id, {
        nodeId: node.id,
        used: true,
        relevanceReason: "The prior procedure appeared relevant",
        influenceSummary: "Would have changed the chosen validation sequence",
      });
      expect(database.prepare(`
        SELECT used, influence_summary, ignored_reason
        FROM memory_context_items
        WHERE context_pack_id = ? AND node_id = ?
      `).get(pack.id, node.id)).toEqual({
        used: 0,
        influence_summary: null,
        ignored_reason: AUTONOMOUS_LIFECYCLE_REJECTION,
      });
    } finally {
      database.close();
    }
  });

  test("records an explicit rejection instead of claiming unsynchronized dynamic memory influenced Autonomous", () => {
    const { database, repository } = fixture();
    try {
      const node = createAttackNode(repository, "mem_22222222222222222222222222222222");
      connectHealthyVault(database);
      const pack = repository.persistContextPack({
        id: "context-not-vault-backed",
        journey: "autonomous",
        purpose: "Dynamic reusable procedure candidate",
        scopePolicy: {
          journey: "autonomous",
          allowGlobal: true,
          maximumSensitivity: "private",
          allowedStatuses: ["confirmed", "verified"],
          allowedScopeClasses: ["confirmed_attack_knowledge"],
          contextBudget: 2_000,
        },
        contextBudget: 2_000,
        createdBy: "planner",
        items: [{
          node,
          score: 1,
          relevanceReason: "Lexically similar reusable procedure",
          signals: ["lexical"],
        }],
      });
      repository.setContextItemDisposition(pack.id, {
        nodeId: node.id,
        used: true,
        relevanceReason: "Lexically similar reusable procedure",
        influenceSummary: "Would have changed the chosen validation sequence",
      });
      expect(database.prepare(`
        SELECT used, influence_summary, ignored_reason
        FROM memory_context_items
        WHERE context_pack_id = ? AND node_id = ?
      `).get(pack.id, node.id)).toEqual({
        used: 0,
        influence_summary: null,
        ignored_reason: AUTONOMOUS_ACTIVE_VAULT_REJECTION,
      });
    } finally {
      database.close();
    }
  });

  test("rejects a contradictory unconfirmed reusable node during Autonomous retrieval", () => {
    const { database, repository, brain } = fixture();
    try {
      const node = createAttackNode(repository, "mem_33333333333333333333333333333333");
      // Model a malformed imported row to prove the retrieval boundary does
      // not trust lifecycle status alone.
      database.prepare(`
        UPDATE memory_nodes SET confirmation_state = 'pending' WHERE id = ?
      `).run(node.id);
      const trace = brain.retrieval.retrieveWithTrace("bounded HTTP validation", {
        journey: "autonomous",
        allowGlobal: true,
        maximumSensitivity: "private",
        allowedStatuses: ["confirmed", "verified"],
        allowedScopeClasses: ["confirmed_attack_knowledge"],
        exactNodeIds: [node.id],
        exactNodeIdsOnly: true,
        contextBudget: 2_000,
      });
      expect(trace.items).toEqual([]);
      expect(trace.rejected).toEqual([
        expect.objectContaining({ reason: "confirmation_state_denied" }),
      ]);
    } finally {
      database.close();
    }
  });
});

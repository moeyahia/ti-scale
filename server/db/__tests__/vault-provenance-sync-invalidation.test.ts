import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, DATABASE_MIGRATIONS, migrateDatabase } from "../index";
import { MemoryRepository } from "../../memory";

const NOW = "2026-07-21T14:00:00.000Z";

function synchronizedState(database: ReturnType<typeof createDatabaseConnection>, nodeId: string): void {
  database.prepare(`
    INSERT INTO vault_connections (
      id, vault_path, display_name, status, sync_scope_json,
      permission_granted_at, created_at, updated_at
    ) VALUES ('vault-provenance-test', '/tmp/vault-provenance-test',
      'Vault provenance test', 'connected', '{}', ?, ?, ?)
  `).run(NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO vault_sync_state (
      id, connection_id, node_id, relative_path, database_version,
      vault_content_hash, database_content_hash, status,
      last_scanned_at, last_synced_at
    ) VALUES ('vault-sync-provenance-test', 'vault-provenance-test', ?,
      '70 Lessons/Provenance test.md', 1, ?, ?, 'synced', ?, ?)
  `).run(nodeId, "a".repeat(64), "b".repeat(64), NOW, NOW);
}

function resetSynchronizedState(database: ReturnType<typeof createDatabaseConnection>): void {
  database.prepare(`
    UPDATE vault_sync_state
    SET status = 'synced', database_content_hash = ?, error_message = NULL
    WHERE id = 'vault-sync-provenance-test'
  `).run("b".repeat(64));
}

describe("Vault provenance synchronization invalidation", () => {
  test("new source custody invalidates a synced note without changing the memory version", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database, DATABASE_MIGRATIONS.filter((migration) => migration.version <= 36));
      const sourceHash = "c".repeat(64);
      const candidateId = "candidate-provenance-invalidation";
      const migrationId = "migration-provenance-invalidation";
      const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
      const node = memory.createNode({
        id: "mem_vault_provenance_invalidation",
        nodeType: "lesson",
        title: "Provenance synchronization invariant",
        summary: "A synchronized note must be reconsidered when exact source custody grows.",
        body: "The memory body itself remains unchanged.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "confirmed",
        confirmationState: "confirmed",
        provenance: {
          method: "imported",
          explanation: "A deterministic historical source-custody fixture.",
          sources: [{
            sourceType: "historical_attack_knowledge_source_candidate",
            sourceId: `${candidateId}:${migrationId}`,
            sourceHash,
            acquiredAt: NOW,
          }],
        },
        authorType: "import",
        authorId: "provenance-test",
      });
      synchronizedState(database, node.id);
      const versionBefore = memory.requireNode(node.id).version;

      database.prepare(`
        INSERT INTO memory_sources (
          id, node_id, source_type, source_id, source_hash,
          acquired_at, created_at
        ) VALUES ('memory-source-new-provenance', ?, 'fixture',
          'new-exact-provenance', ?, ?, ?)
      `).run(node.id, "d".repeat(64), NOW, NOW);

      expect(database.prepare(`
        SELECT status, vault_content_hash, database_content_hash, error_message
        FROM vault_sync_state WHERE id = 'vault-sync-provenance-test'
      `).get()).toEqual({
        status: "database_ahead",
        vault_content_hash: "a".repeat(64),
        database_content_hash: null,
        error_message: null,
      });
      expect(memory.requireNode(node.id).version).toBe(versionBefore);

      resetSynchronizedState(database);
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          created_by, created_at, updated_at, control_plane
        ) VALUES ('mission-custody-import', 'Custody import',
          'Retain private source custody.', 'guided', 'archived', 'unverified',
          'system:historical-attack-knowledge-import', ?, ?, 'legacy')
      `).run(NOW, NOW);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, created_at, updated_at, control_plane
        ) VALUES ('run-custody-import', 'mission-custody-import', 'guided',
          'completed', ?, ?, 'legacy')
      `).run(NOW, NOW);
      database.prepare(`
        INSERT INTO historical_attack_knowledge_import_contexts (
          migration_id, mission_id, run_id, created_at
        ) VALUES (?, 'mission-custody-import', 'run-custody-import', ?)
      `).run(migrationId, NOW);
      database.prepare(`
        INSERT INTO evidence_candidates (
          id, mission_id, run_id, evidence_type, label, meaning,
          promotion_reason, state, sensitivity, proposed_by, created_at
        ) VALUES (?, 'mission-custody-import', 'run-custody-import', 'artifact',
          'Historical private source', 'Preserves exact source custody.',
          'Independent review required.', 'candidate', 'private',
          'system:historical-attack-knowledge-extractor', ?)
      `).run(candidateId, NOW);
      database.prepare(`
        INSERT INTO historical_attack_knowledge_source_candidates (
          candidate_id, source_hash, byte_size, created_at
        ) VALUES (?, ?, 128, ?)
      `).run(candidateId, sourceHash, NOW);
      const sourceReference = "legacy-private-source://provenance-invalidation";
      database.prepare(`
        INSERT INTO historical_attack_knowledge_source_occurrences (
          candidate_id, migration_id, source_reference, source_hash,
          modified_at, observed_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).run(candidateId, migrationId, sourceReference, sourceHash, NOW, NOW);
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          created_by, created_at, updated_at, control_plane
        ) VALUES ('mission-private-origin', 'Private source collection',
          'Retain exact private source custody.', 'guided', 'archived',
          'unverified', 'system:historical-private-source-projection', ?, ?, 'legacy')
      `).run(NOW, NOW);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, created_at, updated_at, control_plane
        ) VALUES ('run-private-origin', 'mission-private-origin', 'guided',
          'completed', ?, ?, 'legacy')
      `).run(NOW, NOW);
      database.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, journey, artifact_type, storage_uri,
          content_hash, byte_size, sensitivity, metadata_json, created_at
        ) VALUES ('artifact-private-origin', 'mission-private-origin',
          'run-private-origin', 'guided', 'legacy_private_source_custody', ?, ?,
          128, 'private', '{}', ?)
      `).run(sourceReference, sourceHash, NOW);
      const historicalMemorySource = database.prepare(`
        SELECT id FROM memory_sources
        WHERE node_id = ?
          AND source_type = 'historical_attack_knowledge_source_candidate'
          AND source_id = ?
      `).get(node.id, `${candidateId}:${migrationId}`) as { id: string };
      database.prepare(`
        INSERT INTO historical_private_source_bindings (
          memory_source_id, source_candidate_id, migration_id, source_reference,
          source_hash, mission_id, run_id, artifact_id, binding_method,
          binding_receipt_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, 'mission-private-origin', 'run-private-origin',
          'artifact-private-origin', 'private_source_projection', ?, ?)
      `).run(
        historicalMemorySource.id,
        candidateId,
        migrationId,
        sourceReference,
        sourceHash,
        "e".repeat(64),
        NOW,
      );

      expect(database.prepare(`
        SELECT status, database_content_hash
        FROM vault_sync_state WHERE id = 'vault-sync-provenance-test'
      `).get()).toEqual({ status: "database_ahead", database_content_hash: null });
      expect(memory.requireNode(node.id).version).toBe(versionBefore);

      // Simulate a row that became stale before the insert trigger existed.
      // Migration 037 must catch this exact pre-existing private binding even
      // though the node version and source timestamp did not change. Later
      // additive migrations, including provider-turn lineage and the private
      // Research holdout admission boundary, must preserve that invalidation.
      resetSynchronizedState(database);
      expect(migrateDatabase(database).applied.map(({ version }) => version)).toEqual([
        37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
        57, 58, 59, 60,
      ]);
      expect(database.prepare(`
        SELECT status, database_content_hash
        FROM vault_sync_state WHERE id = 'vault-sync-provenance-test'
      `).get()).toEqual({ status: "database_ahead", database_content_hash: null });
      expect(memory.requireNode(node.id).version).toBe(versionBefore);

      database.prepare(`
        UPDATE vault_sync_state
        SET status = 'vault_ahead', database_content_hash = ?, error_message = 'review operator edit'
        WHERE id = 'vault-sync-provenance-test'
      `).run("f".repeat(64));
      database.prepare(`
        INSERT INTO memory_sources (
          id, node_id, source_type, source_id, source_hash,
          acquired_at, created_at
        ) VALUES ('memory-source-after-vault-edit', ?, 'fixture',
          'source-after-vault-edit', ?, ?, ?)
      `).run(node.id, "1".repeat(64), NOW, NOW);
      expect(database.prepare(`
        SELECT status, database_content_hash, error_message
        FROM vault_sync_state WHERE id = 'vault-sync-provenance-test'
      `).get()).toEqual({
        status: "vault_ahead",
        database_content_hash: "f".repeat(64),
        error_message: "review operator edit",
      });
    } finally {
      database.close();
    }
  });
});

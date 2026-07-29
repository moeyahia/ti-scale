import type { Migration } from "../types";

/**
 * One-time repair for provenance that was attached before migration 036 could
 * invalidate synchronized projections. Exact historical custody was not part
 * of the memory-node version, so any synced node with one of those bindings is
 * conservatively re-projected. Other provenance is repaired only when its
 * source row is demonstrably newer than the last successful synchronization.
 *
 * Operator-owned vault-ahead/conflict/quarantined/deleted states are never
 * replaced by this migration.
 */
export const existingVaultProvenanceReconciliationMigration: Migration = {
  version: 37,
  name: "existing_vault_provenance_reconciliation",
  sql: String.raw`
UPDATE vault_sync_state
SET status = 'database_ahead',
    database_content_hash = NULL,
    error_message = NULL
WHERE status = 'synced'
  AND node_id IS NOT NULL
  AND (
    EXISTS (
      SELECT 1
      FROM memory_sources source
      JOIN historical_private_source_bindings binding
        ON binding.memory_source_id = source.id
      WHERE source.node_id = vault_sync_state.node_id
    )
    OR EXISTS (
      SELECT 1
      FROM memory_sources source
      WHERE source.node_id = vault_sync_state.node_id
        AND (
          vault_sync_state.last_synced_at IS NULL
          OR source.created_at > vault_sync_state.last_synced_at
        )
    )
  );
`,
};

import type { Migration } from "../types";

/**
 * Reusable note content is not the only input to an Obsidian projection.
 * Provenance source rows and their exact private-custody bindings are rendered
 * into the note's metadata without incrementing memory_nodes.version. Mark a
 * previously synchronized note database-ahead whenever either input grows so
 * the next bounded sync cannot incorrectly skip the new custody information.
 *
 * Deliberately preserve vault-ahead/conflict/quarantined/deleted states: a new
 * database source must never erase an operator edit or an existing review
 * requirement.
 */
export const vaultProvenanceSyncInvalidationMigration: Migration = {
  version: 36,
  name: "vault_provenance_sync_invalidation",
  sql: String.raw`
CREATE TRIGGER memory_sources_vault_provenance_invalidate
AFTER INSERT ON memory_sources
BEGIN
  UPDATE vault_sync_state
  SET status = 'database_ahead',
      database_content_hash = NULL,
      error_message = NULL
  WHERE node_id = NEW.node_id
    AND status = 'synced';
END;

CREATE TRIGGER historical_private_source_bindings_vault_provenance_invalidate
AFTER INSERT ON historical_private_source_bindings
BEGIN
  UPDATE vault_sync_state
  SET status = 'database_ahead',
      database_content_hash = NULL,
      error_message = NULL
  WHERE node_id = (
    SELECT node_id
    FROM memory_sources
    WHERE id = NEW.memory_source_id
  )
    AND status = 'synced';
END;
`,
};

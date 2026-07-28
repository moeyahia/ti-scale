import type { Migration } from "../types";

/**
 * Durable extractor-page reconciliation and terminal custody immutability.
 *
 * A migration may span several process attempts. Each successfully completed
 * extractor page is retained here before the next page begins, allowing the
 * terminal reconciliation to report the complete durable job rather than
 * only work performed by the final process. Once a migration is completed,
 * its verified source-object custody rows cannot be rewritten or deleted.
 */
export const legacyMigrationReconciliationIntegrityMigration: Migration = {
  version: 31,
  name: "legacy_migration_reconciliation_integrity",
  sql: String.raw`
CREATE TABLE legacy_migration_extraction_batches (
  migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  extractor_kind TEXT NOT NULL CHECK (extractor_kind IN ('manifest', 'generic')),
  scope_key TEXT NOT NULL CHECK (length(scope_key) = 64),
  page_key TEXT NOT NULL CHECK (length(page_key) = 64),
  sequence INTEGER NOT NULL CHECK (sequence >= 1),
  report_json TEXT NOT NULL
    CHECK (json_valid(report_json) AND json_type(report_json) = 'object'),
  report_hash TEXT NOT NULL CHECK (length(report_hash) = 64),
  created_at TEXT NOT NULL,
  PRIMARY KEY (migration_id, extractor_kind, scope_key, page_key),
  UNIQUE (migration_id, extractor_kind, scope_key, sequence),
  UNIQUE (migration_id, report_hash)
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_legacy_migration_extraction_batches_job
  ON legacy_migration_extraction_batches(migration_id, extractor_kind, scope_key, sequence);

CREATE TRIGGER legacy_migration_extraction_batches_no_update
BEFORE UPDATE ON legacy_migration_extraction_batches BEGIN
  SELECT RAISE(ABORT, 'legacy migration extraction reconciliation batches are immutable');
END;

CREATE TRIGGER legacy_migration_extraction_batches_no_delete
BEFORE DELETE ON legacy_migration_extraction_batches BEGIN
  SELECT RAISE(ABORT, 'legacy migration extraction reconciliation batches are retained');
END;

CREATE TRIGGER legacy_migration_source_objects_completed_no_update
BEFORE UPDATE ON legacy_migration_source_objects
WHEN EXISTS (
  SELECT 1 FROM legacy_migration_runs
  WHERE id = OLD.migration_id AND status = 'completed'
)
BEGIN
  SELECT RAISE(ABORT, 'completed legacy migration source-object custody is immutable');
END;

CREATE TRIGGER legacy_migration_source_objects_completed_no_delete
BEFORE DELETE ON legacy_migration_source_objects
WHEN EXISTS (
  SELECT 1 FROM legacy_migration_runs
  WHERE id = OLD.migration_id AND status = 'completed'
)
BEGIN
  SELECT RAISE(ABORT, 'completed legacy migration source-object custody is retained');
END;
`,
};

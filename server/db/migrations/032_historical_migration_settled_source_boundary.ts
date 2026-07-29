import type { Migration } from "../types";

/**
 * Persists the optional historical-source settling boundary so a resumed job
 * uses the exact original cutoff instead of silently admitting newer files.
 */
export const historicalMigrationSettledSourceBoundaryMigration: Migration = {
  version: 32,
  name: "historical_migration_settled_source_boundary",
  compatibilityAddColumns: [{
    table: "legacy_migration_runs",
    columns: [
      {
        name: "settle_seconds",
        definition: "INTEGER CHECK (settle_seconds IS NULL OR settle_seconds BETWEEN 60 AND 86400)",
      },
      { name: "settle_cutoff_at", definition: "TEXT" },
    ],
  }],
  sql: String.raw`
CREATE INDEX idx_legacy_migration_runs_settle_cutoff
  ON legacy_migration_runs(settle_cutoff_at)
  WHERE settle_cutoff_at IS NOT NULL;

CREATE TRIGGER legacy_migration_settle_boundary_insert_guard
BEFORE INSERT ON legacy_migration_runs
WHEN (NEW.settle_seconds IS NULL) != (NEW.settle_cutoff_at IS NULL)
  OR (NEW.settle_seconds IS NOT NULL AND NEW.settle_seconds NOT BETWEEN 60 AND 86400)
BEGIN
  SELECT RAISE(ABORT, 'legacy migration settled-source boundary is incomplete or outside policy');
END;

CREATE TRIGGER legacy_migration_settle_boundary_immutable
BEFORE UPDATE OF settle_seconds, settle_cutoff_at ON legacy_migration_runs
WHEN OLD.settle_seconds IS NOT NEW.settle_seconds
  OR OLD.settle_cutoff_at IS NOT NEW.settle_cutoff_at
BEGIN
  SELECT RAISE(ABORT, 'legacy migration settled-source boundary is immutable');
END;
`,
};

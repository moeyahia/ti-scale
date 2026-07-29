import type { Migration } from "../types";

/**
 * Brain provenance resolves an opaque historical source reference back to its
 * verified migration record. Without this access path, every displayed
 * provenance origin scans the complete legacy source-object table.
 */
export const brainProvenanceSourceLookupMigration: Migration = {
  version: 39,
  name: "brain_provenance_source_lookup",
  requiresVerifiedBackup: true,
  sql: String.raw`
CREATE INDEX IF NOT EXISTS idx_legacy_source_objects_reference_verified
  ON legacy_migration_source_objects(source_reference, verified_at DESC, source_id);
`,
};

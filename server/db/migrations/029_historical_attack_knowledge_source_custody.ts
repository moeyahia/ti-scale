import type { Migration } from "../types";

/**
 * Private source custody for attack-knowledge-only historical reparsing.
 *
 * The imported source path remains solely in legacy_migration_source_objects.
 * These canonical rows retain an opaque reference, the immutable source hash,
 * an unverified evidence candidate, and the exact compiler bundle/receipt
 * relationship. No source content, target label, address, mission history, or
 * per-file artifact is projected into reusable memory.
 */
export const historicalAttackKnowledgeSourceCustodyMigration: Migration = {
  version: 29,
  name: "historical_attack_knowledge_source_custody",
  compatibilityAddColumns: [
    {
      table: "legacy_migration_runs",
      columns: [
        { name: "source_retention", definition: "TEXT NOT NULL DEFAULT 'protected-copy' CHECK (source_retention IN ('protected-copy', 'verified-reference'))" },
        { name: "source_retention_acknowledged_at", definition: "TEXT" },
        { name: "brain_projection_mode", definition: "TEXT NOT NULL DEFAULT 'legacy-engagement' CHECK (brain_projection_mode IN ('legacy-engagement', 'attack-knowledge-only'))" },
        { name: "brain_projection_acknowledged_at", definition: "TEXT" },
      ],
    },
    {
      table: "legacy_migration_sources",
      columns: [
        { name: "source_reference", definition: "TEXT" },
        { name: "source_retention", definition: "TEXT NOT NULL DEFAULT 'protected-copy' CHECK (source_retention IN ('protected-copy', 'verified-reference'))" },
        { name: "source_device", definition: "INTEGER" },
        { name: "source_inode", definition: "INTEGER" },
        { name: "verified_at", definition: "TEXT" },
      ],
    },
    {
      table: "legacy_migration_quarantine",
      columns: [
        { name: "source_content_sha256", definition: "TEXT" },
        { name: "byte_size", definition: "INTEGER CHECK (byte_size IS NULL OR byte_size >= 0)" },
        { name: "source_created_at", definition: "TEXT" },
        { name: "source_modified_at", definition: "TEXT" },
        { name: "protected_backup_ref", definition: "TEXT" },
        { name: "protected_backup_sha256", definition: "TEXT" },
        { name: "backup_mode", definition: "TEXT CHECK (backup_mode IS NULL OR backup_mode IN ('byte_copy', 'metadata_only'))" },
        { name: "source_reference", definition: "TEXT" },
        { name: "retention_mode", definition: "TEXT CHECK (retention_mode IS NULL OR retention_mode IN ('protected-copy', 'verified-reference'))" },
        { name: "source_device", definition: "INTEGER" },
        { name: "source_inode", definition: "INTEGER" },
      ],
    },
  ],
  sql: String.raw`
-- Canonical ownership of the legacy migration inventory. The repository keeps
-- its additive compatibility checks for databases created before migration
-- 029, but a fresh canonical database no longer relies on constructor-time
-- DDL before historical source-custody tables are used.
CREATE TABLE IF NOT EXISTS legacy_migration_runs (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'rolled_back')),
  source_roots_json TEXT NOT NULL CHECK (json_valid(source_roots_json)),
  database_path TEXT NOT NULL,
  output_directory TEXT NOT NULL,
  database_backup_path TEXT,
  database_backup_sha256 TEXT,
  reconciliation_path TEXT,
  rollback_json TEXT CHECK (rollback_json IS NULL OR json_valid(rollback_json)),
  error_summary TEXT,
  source_retention TEXT NOT NULL DEFAULT 'protected-copy' CHECK (source_retention IN ('protected-copy', 'verified-reference')),
  source_retention_acknowledged_at TEXT,
  brain_projection_mode TEXT NOT NULL DEFAULT 'legacy-engagement' CHECK (brain_projection_mode IN ('legacy-engagement', 'attack-knowledge-only')),
  brain_projection_acknowledged_at TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS legacy_migration_sources (
  id TEXT PRIMARY KEY,
  migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  source_path TEXT NOT NULL,
  relative_path TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_identity TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
  modified_at TEXT NOT NULL,
  backup_relative_path TEXT,
  source_reference TEXT,
  source_retention TEXT NOT NULL DEFAULT 'protected-copy' CHECK (source_retention IN ('protected-copy', 'verified-reference')),
  source_device INTEGER,
  source_inode INTEGER,
  verified_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'importing', 'completed', 'failed')),
  error_summary TEXT,
  discovered_at TEXT NOT NULL,
  completed_at TEXT,
  UNIQUE (migration_id, source_path)
) STRICT;

CREATE TABLE IF NOT EXISTS legacy_migration_items (
  id TEXT PRIMARY KEY,
  migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  source_id TEXT NOT NULL REFERENCES legacy_migration_sources(id) ON DELETE RESTRICT,
  source_identity TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  item_key TEXT NOT NULL,
  item_hash TEXT NOT NULL,
  target_table TEXT,
  target_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('imported', 'deduplicated', 'quarantined', 'skipped')),
  importer_version INTEGER NOT NULL DEFAULT 1,
  error_category TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (source_identity, item_key, item_hash, importer_version)
) STRICT;

CREATE TABLE IF NOT EXISTS legacy_migration_source_objects (
  id TEXT PRIMARY KEY,
  migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  source_id TEXT NOT NULL REFERENCES legacy_migration_sources(id) ON DELETE RESTRICT,
  object_key TEXT NOT NULL,
  source_reference TEXT NOT NULL,
  source_path TEXT NOT NULL,
  object_kind TEXT NOT NULL CHECK (object_kind IN ('accepted', 'quarantined', 'symlink', 'source')),
  classification TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
  modified_at TEXT NOT NULL,
  source_device INTEGER NOT NULL,
  source_inode INTEGER NOT NULL,
  verification_status TEXT NOT NULL CHECK (verification_status IN ('verified_reference')),
  verified_at TEXT NOT NULL,
  UNIQUE (migration_id, source_id, object_key)
) STRICT;

CREATE TABLE IF NOT EXISTS legacy_migration_quarantine (
  id TEXT PRIMARY KEY,
  migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  source_sha256 TEXT NOT NULL,
  source_path TEXT NOT NULL,
  item_key TEXT NOT NULL,
  item_hash TEXT,
  category TEXT NOT NULL,
  reason TEXT NOT NULL,
  redacted_excerpt TEXT,
  source_content_sha256 TEXT,
  byte_size INTEGER CHECK (byte_size IS NULL OR byte_size >= 0),
  source_created_at TEXT,
  source_modified_at TEXT,
  protected_backup_ref TEXT,
  protected_backup_sha256 TEXT,
  backup_mode TEXT CHECK (backup_mode IS NULL OR backup_mode IN ('byte_copy', 'metadata_only')),
  source_reference TEXT,
  retention_mode TEXT CHECK (retention_mode IS NULL OR retention_mode IN ('protected-copy', 'verified-reference')),
  source_device INTEGER,
  source_inode INTEGER,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS legacy_migration_reconciliation (
  migration_id TEXT PRIMARY KEY REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  report_json TEXT NOT NULL CHECK (json_valid(report_json)),
  report_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS legacy_migration_inventory_receipts (
  migration_id TEXT PRIMARY KEY REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  receipt_hash TEXT NOT NULL CHECK (length(receipt_hash) = 64),
  object_count INTEGER NOT NULL CHECK (object_count >= 0),
  byte_count INTEGER NOT NULL CHECK (byte_count >= 0),
  created_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_legacy_sources_hash_status
  ON legacy_migration_sources(source_sha256, status);
CREATE INDEX IF NOT EXISTS idx_legacy_items_source_status
  ON legacy_migration_items(source_sha256, status);
CREATE INDEX IF NOT EXISTS idx_legacy_items_source_key_hash_version
  ON legacy_migration_items(source_sha256, item_key, item_hash, importer_version);
CREATE INDEX IF NOT EXISTS idx_legacy_items_identity_status
  ON legacy_migration_items(source_identity, status);
CREATE INDEX IF NOT EXISTS idx_legacy_source_objects_hash
  ON legacy_migration_source_objects(source_sha256, object_kind);
CREATE INDEX IF NOT EXISTS idx_legacy_quarantine_source
  ON legacy_migration_quarantine(source_sha256, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_legacy_quarantine_backup_ref
  ON legacy_migration_quarantine(protected_backup_ref);

CREATE TABLE historical_attack_knowledge_import_contexts (
  migration_id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL UNIQUE REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE historical_attack_knowledge_source_candidates (
  candidate_id TEXT PRIMARY KEY REFERENCES evidence_candidates(id) ON DELETE RESTRICT,
  source_hash TEXT NOT NULL UNIQUE CHECK (length(source_hash) = 64),
  byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE historical_attack_knowledge_source_occurrences (
  candidate_id TEXT NOT NULL REFERENCES historical_attack_knowledge_source_candidates(candidate_id) ON DELETE RESTRICT,
  migration_id TEXT NOT NULL REFERENCES historical_attack_knowledge_import_contexts(migration_id) ON DELETE RESTRICT,
  source_reference TEXT NOT NULL CHECK (source_reference GLOB 'legacy-private-source://*'),
  source_hash TEXT NOT NULL CHECK (length(source_hash) = 64),
  modified_at TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  PRIMARY KEY (candidate_id, migration_id, source_reference)
) WITHOUT ROWID, STRICT;

CREATE TABLE historical_attack_knowledge_bundle_sources (
  bundle_id TEXT NOT NULL REFERENCES attack_knowledge_bundles(id) ON DELETE RESTRICT,
  receipt_id TEXT NOT NULL,
  candidate_id TEXT NOT NULL REFERENCES historical_attack_knowledge_source_candidates(candidate_id) ON DELETE RESTRICT,
  source_hash TEXT NOT NULL CHECK (length(source_hash) = 64),
  binding_hash TEXT NOT NULL CHECK (length(binding_hash) = 64),
  linked_at TEXT NOT NULL,
  PRIMARY KEY (bundle_id, receipt_id, candidate_id),
  FOREIGN KEY (bundle_id, receipt_id)
    REFERENCES attack_knowledge_bundle_receipts(bundle_id, receipt_id) ON DELETE RESTRICT
) WITHOUT ROWID, STRICT;

CREATE TABLE historical_attack_knowledge_verified_bundle_links (
  bundle_id TEXT NOT NULL REFERENCES attack_knowledge_bundles(id) ON DELETE RESTRICT,
  receipt_id TEXT NOT NULL,
  candidate_id TEXT NOT NULL REFERENCES historical_attack_knowledge_source_candidates(candidate_id) ON DELETE RESTRICT,
  evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
  source_hash TEXT NOT NULL CHECK (length(source_hash) = 64),
  verification_audit_id TEXT NOT NULL REFERENCES audit_records(id) ON DELETE RESTRICT,
  verified_by TEXT NOT NULL CHECK (length(trim(verified_by)) > 0),
  verified_at TEXT NOT NULL,
  PRIMARY KEY (bundle_id, receipt_id, evidence_id),
  FOREIGN KEY (bundle_id, receipt_id, candidate_id)
    REFERENCES historical_attack_knowledge_bundle_sources(bundle_id, receipt_id, candidate_id)
    ON DELETE RESTRICT
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_historical_attack_source_hash
  ON historical_attack_knowledge_source_candidates(source_hash, candidate_id);
CREATE INDEX idx_historical_attack_source_candidate_state
  ON historical_attack_knowledge_source_candidates(candidate_id, source_hash);
CREATE INDEX idx_historical_attack_source_occurrence_migration
  ON historical_attack_knowledge_source_occurrences(migration_id, candidate_id);
CREATE INDEX idx_historical_attack_bundle_source_candidate
  ON historical_attack_knowledge_bundle_sources(candidate_id, bundle_id);
CREATE INDEX idx_historical_attack_verified_evidence
  ON historical_attack_knowledge_verified_bundle_links(evidence_id, bundle_id);

CREATE TRIGGER historical_attack_import_context_scope_insert
BEFORE INSERT ON historical_attack_knowledge_import_contexts
WHEN NOT EXISTS (
  SELECT 1 FROM runs r
  JOIN missions m ON m.id = r.mission_id
  WHERE r.id = NEW.run_id
    AND r.mission_id = NEW.mission_id
    AND r.status = 'completed'
    AND m.status = 'archived'
    AND m.created_by = 'system:historical-attack-knowledge-import'
)
BEGIN
  SELECT RAISE(ABORT, 'historical attack import context must remain internal and terminal');
END;

CREATE TRIGGER historical_attack_source_candidate_integrity_insert
BEFORE INSERT ON historical_attack_knowledge_source_candidates
WHEN NOT EXISTS (
  SELECT 1
  FROM evidence_candidates candidate
  WHERE candidate.id = NEW.candidate_id
    AND candidate.state = 'candidate'
    AND candidate.sensitivity = 'private'
    AND candidate.proposed_by = 'system:historical-attack-knowledge-extractor'
    AND candidate.observation_id IS NULL
    AND candidate.artifact_id IS NULL
)
BEGIN
  SELECT RAISE(ABORT, 'historical attack source candidate integrity mismatch');
END;

CREATE TRIGGER historical_attack_source_occurrence_integrity_insert
BEFORE INSERT ON historical_attack_knowledge_source_occurrences
WHEN NOT EXISTS (
  SELECT 1 FROM historical_attack_knowledge_import_contexts context
  WHERE context.migration_id = NEW.migration_id
)
OR NOT EXISTS (
  SELECT 1
  FROM evidence_candidates candidate
  JOIN historical_attack_knowledge_source_candidates source
    ON source.candidate_id = NEW.candidate_id
  WHERE candidate.id = NEW.candidate_id
    AND source.source_hash = NEW.source_hash
    AND candidate.sensitivity = 'private'
    AND candidate.proposed_by = 'system:historical-attack-knowledge-extractor'
)
BEGIN
  SELECT RAISE(ABORT, 'historical attack source occurrence integrity mismatch');
END;

CREATE TRIGGER historical_attack_bundle_source_integrity_insert
BEFORE INSERT ON historical_attack_knowledge_bundle_sources
WHEN NEW.source_hash IS NOT (
    SELECT source_hash FROM historical_attack_knowledge_source_candidates
    WHERE candidate_id = NEW.candidate_id
  )
  OR NOT EXISTS (
    SELECT 1 FROM attack_knowledge_bundle_receipts linked
    WHERE linked.bundle_id = NEW.bundle_id AND linked.receipt_id = NEW.receipt_id
  )
BEGIN
  SELECT RAISE(ABORT, 'historical attack bundle source integrity mismatch');
END;

CREATE TRIGGER historical_attack_verified_bundle_link_integrity_insert
BEFORE INSERT ON historical_attack_knowledge_verified_bundle_links
WHEN NEW.source_hash IS NOT (
    SELECT source_hash FROM historical_attack_knowledge_source_candidates
    WHERE candidate_id = NEW.candidate_id
  )
  OR NOT EXISTS (
    SELECT 1
    FROM evidence_candidates candidate
    JOIN evidence canonical ON canonical.id = candidate.promoted_evidence_id
    WHERE candidate.id = NEW.candidate_id
      AND candidate.state = 'promoted'
      AND canonical.id = NEW.evidence_id
      AND canonical.content_hash = NEW.source_hash
      AND canonical.verification_state = 'verified'
      AND lower(trim(canonical.evidence_type)) <> 'command_output'
      AND EXISTS (
        SELECT 1 FROM evidence_chain_events custody
        WHERE custody.evidence_id = canonical.id AND custody.event_type = 'verified'
      )
  )
  OR NOT EXISTS (
    SELECT 1 FROM audit_records audit
    WHERE audit.id = NEW.verification_audit_id
      AND audit.action = 'historical_attack_source.verified'
      AND audit.resource_type = 'evidence_candidate'
      AND audit.resource_id = NEW.candidate_id
      AND audit.actor_type = 'operator'
      AND audit.actor_id = NEW.verified_by
  )
BEGIN
  SELECT RAISE(ABORT, 'historical attack verified bundle link integrity mismatch');
END;

CREATE TRIGGER historical_attack_import_contexts_no_update
BEFORE UPDATE ON historical_attack_knowledge_import_contexts BEGIN
  SELECT RAISE(ABORT, 'historical attack import contexts are immutable');
END;
CREATE TRIGGER legacy_migration_inventory_receipts_no_update
BEFORE UPDATE ON legacy_migration_inventory_receipts BEGIN
  SELECT RAISE(ABORT, 'legacy migration inventory receipts are immutable');
END;
CREATE TRIGGER legacy_migration_inventory_receipts_no_delete
BEFORE DELETE ON legacy_migration_inventory_receipts BEGIN
  SELECT RAISE(ABORT, 'legacy migration inventory receipts are retained for reconciliation');
END;
CREATE TRIGGER historical_attack_import_contexts_no_delete
BEFORE DELETE ON historical_attack_knowledge_import_contexts BEGIN
  SELECT RAISE(ABORT, 'historical attack import contexts are retained for reconciliation');
END;
CREATE TRIGGER historical_attack_source_candidates_no_update
BEFORE UPDATE ON historical_attack_knowledge_source_candidates BEGIN
  SELECT RAISE(ABORT, 'historical attack source candidate links are immutable');
END;
CREATE TRIGGER historical_attack_source_candidates_no_delete
BEFORE DELETE ON historical_attack_knowledge_source_candidates BEGIN
  SELECT RAISE(ABORT, 'historical attack source candidate links are retained for reconciliation');
END;
CREATE TRIGGER historical_attack_source_occurrences_no_update
BEFORE UPDATE ON historical_attack_knowledge_source_occurrences BEGIN
  SELECT RAISE(ABORT, 'historical attack source occurrences are immutable');
END;
CREATE TRIGGER historical_attack_source_occurrences_no_delete
BEFORE DELETE ON historical_attack_knowledge_source_occurrences BEGIN
  SELECT RAISE(ABORT, 'historical attack source occurrences are retained for reconciliation');
END;
CREATE TRIGGER historical_attack_bundle_sources_no_update
BEFORE UPDATE ON historical_attack_knowledge_bundle_sources BEGIN
  SELECT RAISE(ABORT, 'historical attack bundle source links are immutable');
END;
CREATE TRIGGER historical_attack_bundle_sources_no_delete
BEFORE DELETE ON historical_attack_knowledge_bundle_sources BEGIN
  SELECT RAISE(ABORT, 'historical attack bundle source links are retained for reconciliation');
END;
CREATE TRIGGER historical_attack_verified_bundle_links_no_update
BEFORE UPDATE ON historical_attack_knowledge_verified_bundle_links BEGIN
  SELECT RAISE(ABORT, 'historical attack verified bundle links are immutable');
END;
CREATE TRIGGER historical_attack_verified_bundle_links_no_delete
BEFORE DELETE ON historical_attack_knowledge_verified_bundle_links BEGIN
  SELECT RAISE(ABORT, 'historical attack verified bundle links are retained for reconciliation');
END;
`,
};

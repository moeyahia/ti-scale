import type { Migration } from "../types";

/**
 * Durable staging for the private-to-reusable Attack Knowledge Compiler.
 *
 * Private engagement records never enter these tables. A keyed receipt binds
 * the source privately, while the reusable bundle contains only validated,
 * generalized facts. Candidate nodes remain in the existing review queue and
 * graph/profile materialization is recorded only after operator confirmation.
 */
export const attackKnowledgeCompilerMigration: Migration = {
  version: 20,
  name: "attack_knowledge_compiler",
  sql: String.raw`
CREATE TABLE attack_knowledge_bundles (
  id TEXT PRIMARY KEY,
  semantic_fingerprint TEXT NOT NULL UNIQUE CHECK (length(semantic_fingerprint) = 64),
  sanitized_bundle_json TEXT NOT NULL
    CHECK (json_valid(sanitized_bundle_json) AND json_type(sanitized_bundle_json) = 'object'),
  status TEXT NOT NULL CHECK (status IN ('staged', 'materialized')),
  exact_procedure_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (exact_procedure_attempt_count >= 0),
  exact_procedure_reproducibility_count INTEGER NOT NULL DEFAULT 0 CHECK (exact_procedure_reproducibility_count >= 0),
  exact_procedure_evidence_count INTEGER NOT NULL DEFAULT 0 CHECK (exact_procedure_evidence_count >= 0),
  exact_procedure_reset_count INTEGER NOT NULL DEFAULT 0 CHECK (exact_procedure_reset_count >= 0),
  operator_reported_reset_count_minimum INTEGER
    CHECK (operator_reported_reset_count_minimum IS NULL OR operator_reported_reset_count_minimum >= 0),
  first_observed_at TEXT NOT NULL,
  last_observed_at TEXT NOT NULL,
  materialized_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (exact_procedure_attempt_count >= exact_procedure_reproducibility_count),
  CHECK (exact_procedure_evidence_count >= exact_procedure_reproducibility_count),
  CHECK (operator_reported_reset_count_minimum IS NULL OR operator_reported_reset_count_minimum >= exact_procedure_reset_count)
) STRICT;

CREATE TABLE attack_knowledge_provenance_receipts (
  id TEXT PRIMARY KEY,
  source_class TEXT NOT NULL CHECK (source_class IN ('current', 'historical')),
  source_hash TEXT NOT NULL CHECK (length(source_hash) = 64),
  evidence_count INTEGER NOT NULL CHECK (evidence_count >= 1),
  observed_at TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER attack_knowledge_receipts_no_update
BEFORE UPDATE ON attack_knowledge_provenance_receipts BEGIN
  SELECT RAISE(ABORT, 'attack knowledge provenance receipts are immutable');
END;

CREATE TRIGGER attack_knowledge_receipts_no_delete
BEFORE DELETE ON attack_knowledge_provenance_receipts BEGIN
  SELECT RAISE(ABORT, 'attack knowledge provenance receipts are immutable');
END;

CREATE TABLE attack_knowledge_bundle_receipts (
  bundle_id TEXT NOT NULL REFERENCES attack_knowledge_bundles(id) ON DELETE CASCADE,
  receipt_id TEXT NOT NULL REFERENCES attack_knowledge_provenance_receipts(id) ON DELETE RESTRICT,
  exact_procedure_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (exact_procedure_attempt_count >= 0),
  exact_procedure_reproducibility_count INTEGER NOT NULL DEFAULT 0 CHECK (exact_procedure_reproducibility_count >= 0),
  exact_procedure_evidence_count INTEGER NOT NULL DEFAULT 0 CHECK (exact_procedure_evidence_count >= 0),
  exact_procedure_reset_count INTEGER NOT NULL DEFAULT 0 CHECK (exact_procedure_reset_count >= 0),
  operator_reported_reset_count_minimum INTEGER
    CHECK (operator_reported_reset_count_minimum IS NULL OR operator_reported_reset_count_minimum >= 0),
  linked_at TEXT NOT NULL,
  PRIMARY KEY (bundle_id, receipt_id),
  CHECK (exact_procedure_attempt_count >= exact_procedure_reproducibility_count),
  CHECK (exact_procedure_evidence_count >= exact_procedure_reproducibility_count),
  CHECK (operator_reported_reset_count_minimum IS NULL OR operator_reported_reset_count_minimum >= exact_procedure_reset_count)
) WITHOUT ROWID, STRICT;

CREATE TABLE attack_knowledge_candidate_registry (
  content_fingerprint TEXT PRIMARY KEY CHECK (length(content_fingerprint) = 64),
  candidate_id TEXT NOT NULL UNIQUE REFERENCES memory_candidates(id) ON DELETE RESTRICT,
  node_type TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE attack_knowledge_bundle_candidates (
  bundle_id TEXT NOT NULL REFERENCES attack_knowledge_bundles(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  content_fingerprint TEXT NOT NULL
    REFERENCES attack_knowledge_candidate_registry(content_fingerprint) ON DELETE RESTRICT,
  required INTEGER NOT NULL DEFAULT 1 CHECK (required IN (0, 1)),
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  linked_at TEXT NOT NULL,
  PRIMARY KEY (bundle_id, role),
  UNIQUE (bundle_id, ordinal)
) WITHOUT ROWID, STRICT;

CREATE TABLE attack_knowledge_bundle_edges (
  bundle_id TEXT NOT NULL REFERENCES attack_knowledge_bundles(id) ON DELETE CASCADE,
  edge_key TEXT NOT NULL,
  source_role TEXT NOT NULL,
  target_role TEXT NOT NULL,
  edge_type TEXT NOT NULL,
  materialized_edge_id TEXT REFERENCES memory_edges(id) ON DELETE SET NULL,
  materialized_at TEXT,
  PRIMARY KEY (bundle_id, edge_key)
) WITHOUT ROWID, STRICT;

CREATE TABLE attack_knowledge_compiler_runs (
  id TEXT PRIMARY KEY,
  request_fingerprint TEXT NOT NULL UNIQUE CHECK (length(request_fingerprint) = 64),
  bundle_id TEXT NOT NULL REFERENCES attack_knowledge_bundles(id) ON DELETE CASCADE,
  receipt_id TEXT NOT NULL REFERENCES attack_knowledge_provenance_receipts(id) ON DELETE RESTRICT,
  source_class TEXT NOT NULL CHECK (source_class IN ('current', 'historical')),
  status TEXT NOT NULL CHECK (status IN ('compiling', 'interrupted', 'staged', 'materialized')),
  checkpoint_ordinal INTEGER NOT NULL DEFAULT 0 CHECK (checkpoint_ordinal >= 0),
  reconciliation_json TEXT NOT NULL DEFAULT '{}'
    CHECK (json_valid(reconciliation_json) AND json_type(reconciliation_json) = 'object'),
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
) STRICT;

CREATE TABLE attack_knowledge_quarantine_records (
  fingerprint TEXT PRIMARY KEY CHECK (length(fingerprint) = 64),
  source_class TEXT NOT NULL CHECK (source_class IN ('current', 'historical', 'unknown')),
  reason_categories_json TEXT NOT NULL
    CHECK (json_valid(reason_categories_json) AND json_type(reason_categories_json) = 'array'),
  occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count >= 1),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_attack_knowledge_bundles_status_updated
  ON attack_knowledge_bundles(status, updated_at DESC);
CREATE INDEX idx_attack_knowledge_receipts_source
  ON attack_knowledge_provenance_receipts(source_class, observed_at DESC);
CREATE INDEX idx_attack_knowledge_bundle_receipts_receipt
  ON attack_knowledge_bundle_receipts(receipt_id, bundle_id);
CREATE INDEX idx_attack_knowledge_bundle_candidates_fingerprint
  ON attack_knowledge_bundle_candidates(content_fingerprint, bundle_id);
CREATE INDEX idx_attack_knowledge_compiler_runs_status
  ON attack_knowledge_compiler_runs(status, updated_at DESC);
CREATE INDEX idx_attack_knowledge_quarantine_last_seen
  ON attack_knowledge_quarantine_records(last_seen_at DESC);
`,
};

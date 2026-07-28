import type { Migration } from "../types";

/**
 * Immutable operator authorization and resumable execution records for
 * homogeneous historical attack-knowledge promotion batches.
 *
 * The authorization document contains only reusable bundle/source hashes and
 * bounded budgets. Private paths and source excerpts remain in the verified
 * reference inventory and never enter these records.
 */
export const historicalAttackKnowledgeBatchPromotionMigration: Migration = {
  version: 30,
  name: "historical_attack_knowledge_batch_promotion",
  sql: String.raw`
CREATE TABLE historical_attack_knowledge_batch_authorizations (
  id TEXT PRIMARY KEY,
  authorization_hash TEXT NOT NULL UNIQUE CHECK (length(authorization_hash) = 64),
  review_document_json TEXT NOT NULL
    CHECK (json_valid(review_document_json) AND json_type(review_document_json) = 'object'),
  actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) > 0),
  reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
  selection_after_fingerprint TEXT,
  max_records INTEGER NOT NULL CHECK (max_records BETWEEN 1 AND 1000),
  max_source_bytes INTEGER NOT NULL CHECK (max_source_bytes BETWEEN 1 AND 1073741824),
  max_duration_ms INTEGER NOT NULL CHECK (max_duration_ms BETWEEN 1 AND 3600000),
  reviewed_record_count INTEGER NOT NULL CHECK (reviewed_record_count BETWEEN 1 AND 1000),
  reviewed_source_bytes INTEGER NOT NULL CHECK (reviewed_source_bytes >= 0),
  acknowledged_objective_fact_review INTEGER NOT NULL CHECK (acknowledged_objective_fact_review = 1),
  audit_record_id TEXT NOT NULL UNIQUE REFERENCES audit_records(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL,
  CHECK (selection_after_fingerprint IS NULL OR length(selection_after_fingerprint) = 64)
) STRICT;

CREATE TABLE historical_attack_knowledge_batch_runs (
  id TEXT PRIMARY KEY,
  authorization_id TEXT NOT NULL UNIQUE
    REFERENCES historical_attack_knowledge_batch_authorizations(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('authorized', 'running', 'partial', 'completed', 'failed')),
  last_processed_fingerprint TEXT,
  staged_count INTEGER NOT NULL DEFAULT 0 CHECK (staged_count >= 0),
  rejected_count INTEGER NOT NULL DEFAULT 0 CHECK (rejected_count >= 0),
  verified_count INTEGER NOT NULL DEFAULT 0 CHECK (verified_count >= 0),
  promoted_count INTEGER NOT NULL DEFAULT 0 CHECK (promoted_count >= 0),
  source_bytes_processed INTEGER NOT NULL DEFAULT 0 CHECK (source_bytes_processed >= 0),
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  error_category TEXT,
  CHECK (last_processed_fingerprint IS NULL OR length(last_processed_fingerprint) = 64)
) STRICT;

CREATE TABLE historical_attack_knowledge_batch_items (
  batch_id TEXT NOT NULL REFERENCES historical_attack_knowledge_batch_runs(id) ON DELETE RESTRICT,
  bundle_id TEXT NOT NULL REFERENCES attack_knowledge_bundles(id) ON DELETE RESTRICT,
  semantic_fingerprint TEXT NOT NULL CHECK (length(semantic_fingerprint) = 64),
  source_candidate_ids_json TEXT NOT NULL
    CHECK (json_valid(source_candidate_ids_json) AND json_type(source_candidate_ids_json) = 'array'),
  source_hashes_json TEXT NOT NULL
    CHECK (json_valid(source_hashes_json) AND json_type(source_hashes_json) = 'array'),
  source_bytes INTEGER NOT NULL CHECK (source_bytes >= 0),
  disposition TEXT NOT NULL CHECK (disposition IN ('pending', 'rejected', 'promoted')),
  reason_categories_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(reason_categories_json) AND json_type(reason_categories_json) = 'array'),
  verification_evidence_ids_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(verification_evidence_ids_json) AND json_type(verification_evidence_ids_json) = 'array'),
  promotion_review_hash TEXT CHECK (promotion_review_hash IS NULL OR length(promotion_review_hash) = 64),
  promotion_receipt_id TEXT REFERENCES attack_knowledge_promotion_receipts(id) ON DELETE RESTRICT,
  started_at TEXT,
  completed_at TEXT,
  PRIMARY KEY (batch_id, bundle_id),
  UNIQUE (batch_id, semantic_fingerprint)
) WITHOUT ROWID, STRICT;

CREATE TABLE historical_attack_knowledge_batch_rejections (
  bundle_id TEXT PRIMARY KEY REFERENCES attack_knowledge_bundles(id) ON DELETE RESTRICT,
  semantic_fingerprint TEXT NOT NULL UNIQUE CHECK (length(semantic_fingerprint) = 64),
  reason_categories_json TEXT NOT NULL
    CHECK (json_valid(reason_categories_json) AND json_type(reason_categories_json) = 'array'),
  authorization_id TEXT NOT NULL
    REFERENCES historical_attack_knowledge_batch_authorizations(id) ON DELETE RESTRICT,
  actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) > 0),
  rejected_at TEXT NOT NULL
) STRICT;

CREATE TABLE historical_attack_knowledge_batch_events (
  id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL REFERENCES historical_attack_knowledge_batch_runs(id) ON DELETE RESTRICT,
  sequence INTEGER NOT NULL CHECK (sequence >= 1),
  event_type TEXT NOT NULL,
  bundle_id TEXT REFERENCES attack_knowledge_bundles(id) ON DELETE RESTRICT,
  details_json TEXT NOT NULL
    CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
  previous_hash TEXT,
  record_hash TEXT NOT NULL CHECK (length(record_hash) = 64),
  occurred_at TEXT NOT NULL,
  UNIQUE (batch_id, sequence),
  UNIQUE (batch_id, record_hash),
  CHECK (previous_hash IS NULL OR length(previous_hash) = 64)
) STRICT;

CREATE TABLE historical_attack_knowledge_batch_reconciliations (
  id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL REFERENCES historical_attack_knowledge_batch_runs(id) ON DELETE RESTRICT,
  sequence INTEGER NOT NULL CHECK (sequence >= 1),
  report_json TEXT NOT NULL
    CHECK (json_valid(report_json) AND json_type(report_json) = 'object'),
  report_hash TEXT NOT NULL CHECK (length(report_hash) = 64),
  created_at TEXT NOT NULL,
  UNIQUE (batch_id, sequence),
  UNIQUE (batch_id, report_hash)
) STRICT;

CREATE INDEX idx_historical_attack_batch_run_status
  ON historical_attack_knowledge_batch_runs(status, updated_at DESC);
CREATE INDEX idx_historical_attack_batch_item_disposition
  ON historical_attack_knowledge_batch_items(batch_id, disposition, semantic_fingerprint);
CREATE INDEX idx_historical_attack_batch_event_sequence
  ON historical_attack_knowledge_batch_events(batch_id, sequence);

CREATE TRIGGER historical_attack_batch_authorizations_no_update
BEFORE UPDATE ON historical_attack_knowledge_batch_authorizations BEGIN
  SELECT RAISE(ABORT, 'historical attack batch authorizations are immutable');
END;
CREATE TRIGGER historical_attack_batch_authorizations_no_delete
BEFORE DELETE ON historical_attack_knowledge_batch_authorizations BEGIN
  SELECT RAISE(ABORT, 'historical attack batch authorizations are immutable');
END;
CREATE TRIGGER historical_attack_batch_authorizations_integrity_insert
BEFORE INSERT ON historical_attack_knowledge_batch_authorizations
WHEN NOT EXISTS (
  SELECT 1 FROM audit_records audit
  WHERE audit.id = NEW.audit_record_id
    AND audit.action = 'historical_attack_batch.authorized'
    AND audit.resource_type = 'historical_attack_knowledge_batch_authorization'
    AND audit.resource_id = NEW.id
    AND audit.actor_type = 'operator'
    AND audit.actor_id = NEW.actor_id
)
BEGIN
  SELECT RAISE(ABORT, 'historical attack batch authorization audit mismatch');
END;
CREATE TRIGGER historical_attack_batch_rejections_no_update
BEFORE UPDATE ON historical_attack_knowledge_batch_rejections BEGIN
  SELECT RAISE(ABORT, 'historical attack batch rejections are immutable');
END;
CREATE TRIGGER historical_attack_batch_rejections_no_delete
BEFORE DELETE ON historical_attack_knowledge_batch_rejections BEGIN
  SELECT RAISE(ABORT, 'historical attack batch rejections are immutable');
END;
CREATE TRIGGER historical_attack_batch_events_no_update
BEFORE UPDATE ON historical_attack_knowledge_batch_events BEGIN
  SELECT RAISE(ABORT, 'historical attack batch events are immutable');
END;
CREATE TRIGGER historical_attack_batch_events_no_delete
BEFORE DELETE ON historical_attack_knowledge_batch_events BEGIN
  SELECT RAISE(ABORT, 'historical attack batch events are immutable');
END;
CREATE TRIGGER historical_attack_batch_reconciliations_no_update
BEFORE UPDATE ON historical_attack_knowledge_batch_reconciliations BEGIN
  SELECT RAISE(ABORT, 'historical attack batch reconciliations are immutable');
END;
CREATE TRIGGER historical_attack_batch_reconciliations_no_delete
BEFORE DELETE ON historical_attack_knowledge_batch_reconciliations BEGIN
  SELECT RAISE(ABORT, 'historical attack batch reconciliations are immutable');
END;
`,
};

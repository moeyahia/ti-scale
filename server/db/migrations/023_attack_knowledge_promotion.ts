import type { Migration } from "../types";

/**
 * Immutable operator-review receipts for the staged Attack Knowledge Compiler.
 *
 * A receipt is written only in the same transaction that resolves every
 * candidate role, materializes every staged relationship, creates/updates the
 * operational-hazard profile, appends its audit record, and marks the bundle
 * materialized. The stored review document is the exact input to the
 * operator-visible SHA-256 review hash, which makes retry/replay deterministic.
 */
export const attackKnowledgePromotionMigration: Migration = {
  version: 23,
  name: "attack_knowledge_promotion",
  sql: String.raw`
CREATE TABLE attack_knowledge_promotion_receipts (
  id TEXT PRIMARY KEY,
  bundle_id TEXT NOT NULL REFERENCES attack_knowledge_bundles(id) ON DELETE RESTRICT,
  promotion_sequence INTEGER NOT NULL CHECK (promotion_sequence >= 1),
  review_hash TEXT NOT NULL CHECK (length(review_hash) = 64),
  review_document_json TEXT NOT NULL
    CHECK (json_valid(review_document_json) AND json_type(review_document_json) = 'object'),
  actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) > 0),
  candidate_resolution_json TEXT NOT NULL
    CHECK (json_valid(candidate_resolution_json) AND json_type(candidate_resolution_json) = 'array'),
  edge_ids_json TEXT NOT NULL
    CHECK (json_valid(edge_ids_json) AND json_type(edge_ids_json) = 'array'),
  hazard_profile_node_id TEXT REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  hazard_profile_version INTEGER CHECK (
    hazard_profile_version IS NULL OR hazard_profile_version >= 1
  ),
  audit_record_id TEXT NOT NULL UNIQUE REFERENCES audit_records(id) ON DELETE RESTRICT,
  audit_record_hash TEXT NOT NULL CHECK (length(audit_record_hash) = 64),
  promoted_at TEXT NOT NULL,
  UNIQUE (bundle_id, promotion_sequence),
  UNIQUE (bundle_id, review_hash),
  CHECK (
    (hazard_profile_node_id IS NULL AND hazard_profile_version IS NULL)
    OR
    (hazard_profile_node_id IS NOT NULL AND hazard_profile_version IS NOT NULL)
  )
) STRICT;

CREATE INDEX idx_attack_knowledge_promotion_bundle_time
  ON attack_knowledge_promotion_receipts(bundle_id, promotion_sequence DESC, promoted_at DESC);
CREATE INDEX idx_attack_knowledge_promotion_actor_time
  ON attack_knowledge_promotion_receipts(actor_id, promoted_at DESC);

CREATE TRIGGER attack_knowledge_promotion_receipts_no_update
BEFORE UPDATE ON attack_knowledge_promotion_receipts BEGIN
  SELECT RAISE(ABORT, 'attack knowledge promotion receipts are immutable');
END;

CREATE TRIGGER attack_knowledge_promotion_receipts_no_delete
BEFORE DELETE ON attack_knowledge_promotion_receipts BEGIN
  SELECT RAISE(ABORT, 'attack knowledge promotion receipts are immutable');
END;

CREATE TRIGGER attack_knowledge_promotion_receipts_integrity_insert
BEFORE INSERT ON attack_knowledge_promotion_receipts
WHEN 'materialized' IS NOT (
    SELECT status FROM attack_knowledge_bundles WHERE id = NEW.bundle_id
  )
  OR EXISTS (
    SELECT 1 FROM attack_knowledge_bundle_edges
    WHERE bundle_id = NEW.bundle_id AND materialized_edge_id IS NULL
  )
  OR NEW.audit_record_hash IS NOT (
    SELECT record_hash FROM audit_records WHERE id = NEW.audit_record_id
  )
  OR (
    NEW.hazard_profile_node_id IS NOT NULL
    AND NEW.hazard_profile_version IS NOT (
      SELECT version FROM operational_hazard_profiles
      WHERE node_id = NEW.hazard_profile_node_id
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'attack knowledge promotion receipt integrity mismatch');
END;
`,
};

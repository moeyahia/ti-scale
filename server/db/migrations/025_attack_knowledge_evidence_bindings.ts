import type { Migration } from "../types";

/** Private canonical-evidence bindings for reusable attack-knowledge reviews. */
export const attackKnowledgeEvidenceBindingsMigration: Migration = {
  version: 25,
  name: "attack_knowledge_evidence_bindings",
  sql: String.raw`
CREATE TABLE attack_knowledge_bundle_evidence_bindings (
  bundle_id TEXT NOT NULL,
  receipt_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
  content_hash TEXT NOT NULL CHECK (length(content_hash) = 64),
  acquired_at TEXT NOT NULL,
  bound_at TEXT NOT NULL,
  PRIMARY KEY (bundle_id, evidence_id),
  FOREIGN KEY (bundle_id, receipt_id)
    REFERENCES attack_knowledge_bundle_receipts(bundle_id, receipt_id)
    ON DELETE RESTRICT
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_attack_knowledge_evidence_receipt
  ON attack_knowledge_bundle_evidence_bindings(receipt_id, evidence_id);

CREATE TRIGGER attack_knowledge_evidence_bindings_no_update
BEFORE UPDATE ON attack_knowledge_bundle_evidence_bindings BEGIN
  SELECT RAISE(ABORT, 'attack knowledge evidence bindings are immutable');
END;

CREATE TRIGGER attack_knowledge_evidence_bindings_no_delete
BEFORE DELETE ON attack_knowledge_bundle_evidence_bindings BEGIN
  SELECT RAISE(ABORT, 'attack knowledge evidence bindings are immutable');
END;

CREATE TRIGGER attack_knowledge_evidence_bindings_integrity_insert
BEFORE INSERT ON attack_knowledge_bundle_evidence_bindings
WHEN 'staged' IS NOT (
    SELECT status FROM attack_knowledge_bundles WHERE id = NEW.bundle_id
  )
  OR NEW.content_hash IS NOT (
    SELECT content_hash FROM evidence WHERE id = NEW.evidence_id
  )
  OR NEW.acquired_at IS NOT (
    SELECT acquired_at FROM evidence WHERE id = NEW.evidence_id
  )
  OR 'verified' IS NOT (
    SELECT verification_state FROM evidence WHERE id = NEW.evidence_id
  )
  OR 'command_output' IS lower(trim((
    SELECT evidence_type FROM evidence WHERE id = NEW.evidence_id
  )))
  OR NOT EXISTS (
    SELECT 1 FROM evidence_chain_events custody
    WHERE custody.evidence_id = NEW.evidence_id AND custody.event_type = 'verified'
  )
BEGIN
  SELECT RAISE(ABORT, 'attack knowledge evidence binding integrity mismatch');
END;

CREATE TRIGGER attack_knowledge_promotion_verification_integrity_insert
BEFORE INSERT ON attack_knowledge_promotion_receipts
WHEN json_extract(NEW.review_document_json, '$.schemaVersion') IS NOT 2
  OR json_type(NEW.review_document_json, '$.verification.evidence') IS NOT 'array'
  OR json_type(NEW.review_document_json, '$.verification.minimumEvidenceItems') IS NOT 'integer'
  OR json_array_length(NEW.review_document_json, '$.verification.evidence')
    < json_extract(NEW.review_document_json, '$.verification.minimumEvidenceItems')
  OR EXISTS (
    SELECT 1
    FROM json_each(NEW.review_document_json, '$.verification.evidence') reviewed
    WHERE NOT EXISTS (
      SELECT 1
      FROM attack_knowledge_bundle_evidence_bindings binding
      JOIN evidence canonical ON canonical.id = binding.evidence_id
      WHERE binding.bundle_id = NEW.bundle_id
        AND binding.evidence_id = json_extract(reviewed.value, '$.id')
        AND binding.content_hash = json_extract(reviewed.value, '$.contentHash')
        AND binding.acquired_at = json_extract(reviewed.value, '$.acquiredAt')
        AND canonical.content_hash = binding.content_hash
        AND canonical.acquired_at = binding.acquired_at
        AND canonical.verification_state = 'verified'
        AND lower(trim(canonical.evidence_type)) <> 'command_output'
        AND EXISTS (
          SELECT 1 FROM evidence_chain_events custody
          WHERE custody.evidence_id = canonical.id AND custody.event_type = 'verified'
        )
    )
  )
  OR EXISTS (
    SELECT 1 FROM json_each(NEW.candidate_resolution_json) candidate
    WHERE NOT EXISTS (
      SELECT 1 FROM memory_nodes node
      WHERE node.id = json_extract(candidate.value, '$.proposedNode.id')
        AND node.lifecycle_status = 'verified'
        AND node.confirmation_state = 'confirmed'
    )
  )
  OR EXISTS (
    SELECT 1 FROM json_each(NEW.edge_ids_json) reviewed_edge
    WHERE NOT EXISTS (
      SELECT 1 FROM memory_edges edge
      WHERE edge.id = reviewed_edge.value AND edge.lifecycle_status = 'verified'
    )
  )
  OR NOT EXISTS (
    SELECT 1
    FROM audit_records promotion_audit
    JOIN audit_records verification_audit
      ON verification_audit.id = json_extract(
        promotion_audit.details_json, '$.verificationAuditId'
      )
    WHERE promotion_audit.id = NEW.audit_record_id
      AND verification_audit.record_hash = json_extract(
        promotion_audit.details_json, '$.verificationAuditHash'
      )
      AND verification_audit.action = 'attack_knowledge.verification_approved'
      AND verification_audit.resource_type = 'attack_knowledge_bundle'
      AND verification_audit.resource_id = NEW.bundle_id
      AND verification_audit.actor_type = 'operator'
      AND verification_audit.actor_id = NEW.actor_id
      AND json_extract(verification_audit.details_json, '$.reviewHash') = NEW.review_hash
      AND json_array_length(verification_audit.details_json, '$.evidenceIds')
        = json_array_length(NEW.review_document_json, '$.verification.evidence')
      AND NOT EXISTS (
        SELECT 1
        FROM json_each(NEW.review_document_json, '$.verification.evidence') reviewed
        WHERE json_extract(reviewed.value, '$.id') NOT IN (
          SELECT value FROM json_each(verification_audit.details_json, '$.evidenceIds')
        )
      )
  )
BEGIN
  SELECT RAISE(ABORT, 'attack knowledge promotion verification integrity mismatch');
END;
`,
};

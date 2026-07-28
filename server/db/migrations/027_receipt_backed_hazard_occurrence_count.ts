import type { Migration } from "../types";

/**
 * A reset count is safety-authoritative only when it can be recomputed from
 * the immutable local reset-controller, occurrence, compiler-receipt, and
 * canonical-evidence chain. Historical imports and compiler-supplied numeric
 * claims deliberately do not participate in this projection.
 */
export const receiptBackedHazardOccurrenceCountMigration: Migration = {
  version: 27,
  name: "receipt_backed_hazard_occurrence_count",
  sql: String.raw`
ALTER TABLE operational_hazard_profiles
  ADD COLUMN receipt_backed_occurrence_count INTEGER NOT NULL DEFAULT 0
    CHECK (receipt_backed_occurrence_count >= 0);

CREATE VIEW operational_hazard_receipt_backed_counts AS
SELECT
  candidate.proposed_node_id AS hazard_node_id,
  COUNT(DISTINCT occurrence.id) AS receipt_backed_occurrence_count
FROM operational_hazard_occurrences occurrence
JOIN operational_reset_control_receipts reset_receipt
  ON reset_receipt.id = occurrence.reset_control_receipt_id
 AND reset_receipt.receipt_key_hash = occurrence.reset_control_receipt_hash
 AND reset_receipt.mission_id = occurrence.mission_id
 AND reset_receipt.run_id = occurrence.run_id
 AND reset_receipt.recovery_action_id = occurrence.recovery_action_id
 AND reset_receipt.target_asset_id IS occurrence.target_asset_id
 AND reset_receipt.target_service_id IS occurrence.target_service_id
 AND reset_receipt.target_context_fingerprint = occurrence.target_context_fingerprint
JOIN attack_knowledge_provenance_receipts provenance
  ON provenance.id = occurrence.provenance_receipt_id
 AND provenance.source_class = 'current'
JOIN attack_knowledge_bundle_receipts bundle_receipt
  ON bundle_receipt.bundle_id = occurrence.bundle_id
 AND bundle_receipt.receipt_id = occurrence.provenance_receipt_id
JOIN attack_knowledge_compiler_runs compiler_run
  ON compiler_run.bundle_id = occurrence.bundle_id
 AND compiler_run.receipt_id = occurrence.provenance_receipt_id
 AND compiler_run.source_class = 'current'
 AND compiler_run.status IN ('staged', 'materialized')
JOIN attack_knowledge_bundle_candidates bundle_candidate
  ON bundle_candidate.bundle_id = occurrence.bundle_id
 AND bundle_candidate.role = 'hazard'
JOIN attack_knowledge_candidate_registry registry
  ON registry.content_fingerprint = bundle_candidate.content_fingerprint
JOIN memory_candidates candidate
  ON candidate.id = registry.candidate_id
 AND candidate.proposed_node_id IS NOT NULL
 AND candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
JOIN memory_nodes hazard_node
  ON hazard_node.id = candidate.proposed_node_id
 AND hazard_node.node_type = 'operational_hazard'
 AND hazard_node.scope = 'global'
 AND hazard_node.lifecycle_status IN ('confirmed', 'verified')
 AND hazard_node.confirmation_state = 'confirmed'
WHERE occurrence.exact_attempt_count = 1
  AND occurrence.exact_reproducibility_count = 1
  AND occurrence.exact_reset_count = 1
  AND provenance.evidence_count = json_array_length(occurrence.evidence_ids_json)
  AND json_array_length(occurrence.evidence_ids_json) >= 1
  AND (
    SELECT COUNT(*)
    FROM attack_knowledge_bundle_evidence_bindings binding
    WHERE binding.bundle_id = occurrence.bundle_id
      AND binding.receipt_id = occurrence.provenance_receipt_id
  ) = json_array_length(occurrence.evidence_ids_json)
  AND NOT EXISTS (
    SELECT 1 FROM json_each(occurrence.evidence_ids_json) selected
    WHERE NOT EXISTS (
      SELECT 1
      FROM attack_knowledge_bundle_evidence_bindings binding
      JOIN evidence proof ON proof.id = binding.evidence_id
      WHERE binding.bundle_id = occurrence.bundle_id
        AND binding.receipt_id = occurrence.provenance_receipt_id
        AND binding.evidence_id = selected.value
        AND proof.verification_state = 'verified'
        AND lower(trim(proof.evidence_type)) <> 'command_output'
        AND EXISTS (
          SELECT 1 FROM evidence_chain_events custody
          WHERE custody.evidence_id = proof.id AND custody.event_type = 'verified'
        )
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM attack_knowledge_bundle_evidence_bindings binding
    WHERE binding.bundle_id = occurrence.bundle_id
      AND binding.receipt_id = occurrence.provenance_receipt_id
      AND binding.evidence_id NOT IN (
        SELECT value FROM json_each(occurrence.evidence_ids_json)
      )
  )
GROUP BY candidate.proposed_node_id;

UPDATE operational_hazard_profiles
SET receipt_backed_occurrence_count = COALESCE((
  SELECT receipt_backed_occurrence_count
  FROM operational_hazard_receipt_backed_counts canonical
  WHERE canonical.hazard_node_id = operational_hazard_profiles.node_id
), 0);

CREATE TRIGGER operational_hazard_profiles_receipt_count_insert
BEFORE INSERT ON operational_hazard_profiles
WHEN NEW.receipt_backed_occurrence_count IS NOT COALESCE((
  SELECT receipt_backed_occurrence_count
  FROM operational_hazard_receipt_backed_counts canonical
  WHERE canonical.hazard_node_id = NEW.node_id
), 0)
BEGIN
  SELECT RAISE(ABORT, 'operational hazard receipt-backed count must be derived from canonical receipts');
END;

CREATE TRIGGER operational_hazard_profiles_receipt_count_update
BEFORE UPDATE ON operational_hazard_profiles
WHEN NEW.receipt_backed_occurrence_count IS NOT COALESCE((
  SELECT receipt_backed_occurrence_count
  FROM operational_hazard_receipt_backed_counts canonical
  WHERE canonical.hazard_node_id = NEW.node_id
), 0)
BEGIN
  SELECT RAISE(ABORT, 'operational hazard receipt-backed count must be derived from canonical receipts');
END;

CREATE TRIGGER operational_hazard_occurrence_refresh_profile_count
AFTER INSERT ON operational_hazard_occurrences
BEGIN
  UPDATE operational_hazard_profiles
  SET receipt_backed_occurrence_count = COALESCE((
    SELECT receipt_backed_occurrence_count
    FROM operational_hazard_receipt_backed_counts canonical
    WHERE canonical.hazard_node_id = operational_hazard_profiles.node_id
  ), 0)
  WHERE node_id IN (
    SELECT candidate.proposed_node_id
    FROM attack_knowledge_bundle_candidates bundle_candidate
    JOIN attack_knowledge_candidate_registry registry
      ON registry.content_fingerprint = bundle_candidate.content_fingerprint
    JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
    WHERE bundle_candidate.bundle_id = NEW.bundle_id
      AND bundle_candidate.role = 'hazard'
      AND candidate.proposed_node_id IS NOT NULL
  );
END;
`,
};

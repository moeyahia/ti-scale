import type { Migration } from "../types";

/**
 * Correct the historical reported-outcome insert guard for the canonical
 * two-hash custody model.
 *
 * `attack_knowledge_provenance_receipts.source_hash` identifies the sanitized
 * compiler segment/record. `historical_attack_knowledge_bundle_sources.source_hash`
 * identifies the raw verified-reference source object. They are deliberately
 * different identities and must never be equated. The immutable receipt stays
 * bound through (bundle_id, receipt_id); raw-source custody is proven through
 * the candidate occurrence, completed inventory receipt, and exact verified
 * source-object hash.
 */
export const historicalReportedOutcomeTwoHashCustodyMigration: Migration = {
  version: 41,
  name: "historical_reported_outcome_two_hash_custody",
  sql: String.raw`
DROP TRIGGER historical_reported_outcome_integrity_insert;

CREATE TRIGGER historical_reported_outcome_integrity_insert
BEFORE INSERT ON historical_reported_outcome_claims
WHEN NOT EXISTS (
  SELECT 1
  FROM historical_attack_knowledge_bundle_sources source
  JOIN attack_knowledge_bundles bundle ON bundle.id = source.bundle_id
  JOIN attack_knowledge_provenance_receipts receipt ON receipt.id = source.receipt_id
  JOIN evidence_candidates candidate ON candidate.id = source.candidate_id
  JOIN audit_records audit ON audit.id = NEW.audit_record_id
  WHERE source.bundle_id = NEW.bundle_id
    AND source.receipt_id = NEW.receipt_id
    AND source.candidate_id = NEW.source_candidate_id
    AND source.source_hash = NEW.source_hash
    AND bundle.semantic_fingerprint = NEW.bundle_semantic_fingerprint
    AND receipt.source_class = 'historical'
    AND candidate.sensitivity = 'private'
    AND candidate.proposed_by = 'system:historical-attack-knowledge-extractor'
    AND audit.record_hash = NEW.audit_record_hash
    AND audit.mission_id = candidate.mission_id
    AND audit.run_id IS candidate.run_id
    AND audit.action = 'historical_reported_outcome.classified'
    AND audit.resource_type = 'historical_reported_outcome_claim'
    AND audit.resource_id = NEW.id
    AND audit.actor_id = NEW.actor_id
    AND audit.reason = NEW.reason
    AND EXISTS (
      SELECT 1
      FROM historical_attack_knowledge_source_occurrences occurrence
      JOIN historical_attack_knowledge_import_contexts context
        ON context.migration_id = occurrence.migration_id
      JOIN legacy_migration_runs migration
        ON migration.id = occurrence.migration_id
       AND migration.status = 'completed'
       AND migration.source_retention = 'verified-reference'
       AND migration.brain_projection_mode = 'attack-knowledge-only'
      JOIN legacy_migration_inventory_receipts inventory
        ON inventory.migration_id = occurrence.migration_id
      JOIN legacy_migration_source_objects source_object
        ON source_object.migration_id = occurrence.migration_id
       AND source_object.source_reference = occurrence.source_reference
       AND source_object.source_sha256 = occurrence.source_hash
       AND source_object.verification_status = 'verified_reference'
       AND source_object.object_kind IN ('accepted', 'source')
      WHERE occurrence.candidate_id = source.candidate_id
        AND occurrence.source_hash = source.source_hash
    )
)
BEGIN
  SELECT RAISE(ABORT, 'historical reported outcome requires exact two-hash source custody, bundle identity, and audit receipt');
END;
`,
};

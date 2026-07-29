import type { Migration } from "../types";

/**
 * Source-reported historical outcomes are deliberately separate from the
 * evidence-backed reusable_knowledge_outcome_links table. These rows record
 * only a deterministic interpretation of a sanitized historical bundle and
 * its existing private-source custody binding. They never create an
 * AttackAttempt and can never satisfy the canonical success/failure trigger.
 */
export const historicalReportedOutcomesMigration: Migration = {
  version: 40,
  name: "historical_reported_outcomes",
  requiresVerifiedBackup: true,
  sql: String.raw`
CREATE TABLE historical_reported_outcome_claims (
  id TEXT PRIMARY KEY,
  bundle_id TEXT NOT NULL REFERENCES attack_knowledge_bundles(id) ON DELETE RESTRICT,
  receipt_id TEXT NOT NULL,
  source_candidate_id TEXT NOT NULL,
  source_hash TEXT NOT NULL CHECK (length(source_hash) = 64),
  bundle_semantic_fingerprint TEXT NOT NULL CHECK (length(bundle_semantic_fingerprint) = 64),
  classification TEXT NOT NULL CHECK (
    classification IN ('reported_success', 'reported_failure', 'mixed', 'unknown')
  ),
  classification_confidence REAL NOT NULL CHECK (
    classification_confidence >= 0 AND classification_confidence <= 1
  ),
  basis_categories_json TEXT NOT NULL CHECK (
    json_valid(basis_categories_json) AND json_type(basis_categories_json) = 'array'
  ),
  policy_version TEXT NOT NULL CHECK (length(trim(policy_version)) BETWEEN 1 AND 128),
  classification_receipt_hash TEXT NOT NULL UNIQUE
    CHECK (length(classification_receipt_hash) = 64),
  review_hash TEXT NOT NULL CHECK (length(review_hash) = 64),
  actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) BETWEEN 1 AND 256),
  reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 1200),
  audit_record_id TEXT NOT NULL UNIQUE REFERENCES audit_records(id) ON DELETE RESTRICT,
  audit_record_hash TEXT NOT NULL CHECK (length(audit_record_hash) = 64),
  created_at TEXT NOT NULL,
  UNIQUE (bundle_id, receipt_id, source_candidate_id, policy_version),
  FOREIGN KEY (bundle_id, receipt_id, source_candidate_id)
    REFERENCES historical_attack_knowledge_bundle_sources(bundle_id, receipt_id, candidate_id)
    ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_historical_reported_outcome_classification
  ON historical_reported_outcome_claims(classification, bundle_semantic_fingerprint);
CREATE INDEX idx_historical_reported_outcome_bundle
  ON historical_reported_outcome_claims(bundle_id, policy_version, classification);
CREATE INDEX idx_historical_reported_outcome_source
  ON historical_reported_outcome_claims(source_hash, policy_version);

CREATE VIEW historical_reported_outcome_node_claims AS
SELECT DISTINCT
  candidate.proposed_node_id AS memory_node_id,
  claim.id AS claim_id,
  claim.bundle_id,
  claim.source_hash,
  claim.classification,
  claim.classification_confidence,
  claim.policy_version,
  claim.classification_receipt_hash,
  claim.created_at
FROM historical_reported_outcome_claims claim
JOIN attack_knowledge_bundle_candidates bundle_candidate
  ON bundle_candidate.bundle_id = claim.bundle_id
JOIN attack_knowledge_candidate_registry registry
  ON registry.content_fingerprint = bundle_candidate.content_fingerprint
JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
JOIN memory_nodes node ON node.id = candidate.proposed_node_id
WHERE candidate.proposed_node_id IS NOT NULL
  AND node.scope = 'global'
  AND node.engagement_id IS NULL
  AND node.mission_id IS NULL
  AND node.lifecycle_status <> 'forgotten'
  AND node.node_type IN (
    'technology_product', 'exact_version_fingerprint', 'version_range_fingerprint',
    'operating_system', 'kernel', 'framework', 'runtime', 'database', 'firewall',
    'waf', 'proxy', 'security_control', 'topology_pattern', 'topology_role', 'cve',
    'advisory', 'cwe', 'misconfiguration', 'attack_vector', 'prerequisite',
    'attribute', 'discovery_pattern', 'fingerprint_pattern', 'script_artifact',
    'tool_artifact', 'outcome', 'failure_mode', 'alternative', 'evidence_pattern',
    'validation_pattern', 'detection', 'remediation', 'strategy', 'research',
    'procedure_version', 'operational_hazard', 'target_state_transition',
    'recovery_pattern', 'health_check', 'attack_tactic', 'attack_technique',
    'attack_procedure', 'attack_lesson'
  );

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
    AND receipt.source_hash = NEW.source_hash
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
)
BEGIN
  SELECT RAISE(ABORT, 'historical reported outcome requires exact source custody, bundle identity, and audit receipt');
END;

CREATE TRIGGER historical_reported_outcome_no_update
BEFORE UPDATE ON historical_reported_outcome_claims BEGIN
  SELECT RAISE(ABORT, 'historical reported outcome claims are immutable');
END;

CREATE TRIGGER historical_reported_outcome_no_delete
BEFORE DELETE ON historical_reported_outcome_claims BEGIN
  SELECT RAISE(ABORT, 'historical reported outcome claims are immutable');
END;
`,
};

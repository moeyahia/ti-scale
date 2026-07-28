import type { Migration } from "../types";

/**
 * Evidence-backed, many-to-many outcome classification for reusable attack
 * knowledge. Existing memory is intentionally not backfilled: prose, node
 * type, titles, and historical compiler claims are not authoritative attack
 * outcomes.
 */
export const reusableKnowledgeOutcomesMigration: Migration = {
  version: 33,
  name: "reusable_knowledge_outcomes",
  requiresVerifiedBackup: true,
  sql: String.raw`
CREATE TABLE reusable_knowledge_outcome_links (
  id TEXT PRIMARY KEY,
  memory_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  attack_attempt_id TEXT NOT NULL REFERENCES attack_attempts(id) ON DELETE RESTRICT,
  evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
  outcome_tag TEXT NOT NULL CHECK (outcome_tag IN ('success', 'failed')),
  actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) BETWEEN 1 AND 256),
  reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 1200),
  audit_record_id TEXT NOT NULL UNIQUE REFERENCES audit_records(id) ON DELETE RESTRICT,
  audit_record_hash TEXT NOT NULL CHECK (length(audit_record_hash) = 64),
  created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
  UNIQUE (memory_node_id, attack_attempt_id, evidence_id, outcome_tag)
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_reusable_knowledge_outcomes_node_tag
  ON reusable_knowledge_outcome_links(memory_node_id, outcome_tag, attack_attempt_id);
CREATE INDEX idx_reusable_knowledge_outcomes_attempt_tag
  ON reusable_knowledge_outcome_links(attack_attempt_id, outcome_tag, memory_node_id);
CREATE INDEX idx_reusable_knowledge_outcomes_evidence
  ON reusable_knowledge_outcome_links(evidence_id, memory_node_id);

CREATE VIEW reusable_knowledge_outcome_counts AS
SELECT
  memory_node_id,
  outcome_tag,
  COUNT(DISTINCT attack_attempt_id) AS attack_attempt_count,
  COUNT(DISTINCT evidence_id) AS evidence_count
FROM reusable_knowledge_outcome_links
GROUP BY memory_node_id, outcome_tag;

-- The tag is derived from the canonical terminal AttackAttempt. The proof
-- must be verified, non-command evidence in the same mission/run and already
-- linked to that exact attempt as supporting or outcome evidence. A verified
-- custody event is mandatory for every classification, including local tool
-- output that would otherwise pass the broader evidence-record predicate.
CREATE TRIGGER reusable_knowledge_outcomes_integrity_insert
BEFORE INSERT ON reusable_knowledge_outcome_links
WHEN NOT EXISTS (
  SELECT 1
  FROM memory_nodes memory
  JOIN attack_attempts attempt ON attempt.id = NEW.attack_attempt_id
  JOIN evidence proof ON proof.id = NEW.evidence_id
  JOIN attack_attempt_evidence attempt_proof
    ON attempt_proof.attack_attempt_id = attempt.id
   AND attempt_proof.evidence_id = proof.id
   AND attempt_proof.relationship IN ('supports', 'outcome')
  JOIN attack_attempt_knowledge_contexts reviewed_context
    ON reviewed_context.attack_attempt_id = attempt.id
  WHERE memory.id = NEW.memory_node_id
    AND memory.node_type IN (
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
    )
    AND memory.scope = 'global'
    AND memory.engagement_id IS NULL
    AND memory.mission_id IS NULL
    AND memory.lifecycle_status = 'verified'
    AND memory.confirmation_state = 'confirmed'
    AND (
      memory.id = reviewed_context.procedure_node_id
      OR memory.id = reviewed_context.procedure_version_node_id
      OR EXISTS (
        SELECT 1 FROM json_each(reviewed_context.product_node_ids_json) member
        WHERE member.value = memory.id
      )
      OR EXISTS (
        SELECT 1 FROM json_each(reviewed_context.version_node_ids_json) member
        WHERE member.value = memory.id
      )
      OR EXISTS (
        SELECT 1 FROM json_each(reviewed_context.stack_node_ids_json) member
        WHERE member.value = memory.id
      )
      OR EXISTS (
        SELECT 1 FROM json_each(reviewed_context.prerequisite_node_ids_json) member
        WHERE member.value = memory.id
      )
      OR EXISTS (
        SELECT 1 FROM json_each(reviewed_context.observed_state_node_ids_json) member
        WHERE member.value = memory.id
      )
    )
    AND (
      (NEW.outcome_tag = 'success' AND attempt.status = 'succeeded')
      OR (NEW.outcome_tag = 'failed' AND attempt.status = 'failed')
    )
    AND proof.mission_id = attempt.mission_id
    AND proof.run_id = attempt.run_id
    AND proof.verification_state = 'verified'
    AND lower(trim(proof.evidence_type)) <> 'command_output'
    AND EXISTS (
      SELECT 1
      FROM evidence_chain_events custody
      WHERE custody.evidence_id = proof.id
        AND custody.event_type = 'verified'
    )
    AND EXISTS (
      SELECT 1 FROM audit_records audit
      WHERE audit.id = NEW.audit_record_id
        AND audit.record_hash = NEW.audit_record_hash
        AND audit.mission_id = attempt.mission_id
        AND audit.run_id = attempt.run_id
        AND audit.action = 'reusable_knowledge.outcome_classified'
        AND audit.resource_type = 'reusable_knowledge_outcome_link'
        AND audit.resource_id = NEW.id
        AND audit.actor_id = NEW.actor_id
        AND audit.reason = NEW.reason
    )
)
BEGIN
  SELECT RAISE(ABORT, 'reusable knowledge outcome requires reviewed attempt membership, a matching terminal outcome, verified evidence, and an audit receipt');
END;

CREATE TRIGGER reusable_knowledge_outcomes_no_update
BEFORE UPDATE ON reusable_knowledge_outcome_links BEGIN
  SELECT RAISE(ABORT, 'reusable knowledge outcome links are immutable');
END;

CREATE TRIGGER reusable_knowledge_outcomes_no_delete
BEFORE DELETE ON reusable_knowledge_outcome_links BEGIN
  SELECT RAISE(ABORT, 'reusable knowledge outcome links are immutable');
END;

CREATE TRIGGER reusable_knowledge_outcomes_attempt_immutable
BEFORE UPDATE OF
  mission_id, run_id, target_asset_id, target_service_id, objective,
  technique_id, technique_name, action_class, prerequisites_json,
  normalized_parameters_json, status, outcome_summary, failure_category
ON attack_attempts
WHEN EXISTS (
  SELECT 1 FROM reusable_knowledge_outcome_links link
  WHERE link.attack_attempt_id = OLD.id
)
AND (
  OLD.mission_id IS NOT NEW.mission_id
  OR OLD.run_id IS NOT NEW.run_id
  OR OLD.target_asset_id IS NOT NEW.target_asset_id
  OR OLD.target_service_id IS NOT NEW.target_service_id
  OR OLD.objective IS NOT NEW.objective
  OR OLD.technique_id IS NOT NEW.technique_id
  OR OLD.technique_name IS NOT NEW.technique_name
  OR OLD.action_class IS NOT NEW.action_class
  OR OLD.prerequisites_json IS NOT NEW.prerequisites_json
  OR OLD.normalized_parameters_json IS NOT NEW.normalized_parameters_json
  OR OLD.status IS NOT NEW.status
  OR OLD.outcome_summary IS NOT NEW.outcome_summary
  OR OLD.failure_category IS NOT NEW.failure_category
)
BEGIN
  SELECT RAISE(ABORT, 'classified attack attempt outcome is immutable');
END;

CREATE TRIGGER reusable_knowledge_outcomes_evidence_immutable
BEFORE UPDATE OF
  mission_id, run_id, source, acquired_at, evidence_type, content_hash,
  provenance_json, verification_state
ON evidence
WHEN EXISTS (
  SELECT 1 FROM reusable_knowledge_outcome_links link
  WHERE link.evidence_id = OLD.id
)
AND (
  OLD.mission_id IS NOT NEW.mission_id
  OR OLD.run_id IS NOT NEW.run_id
  OR OLD.source IS NOT NEW.source
  OR OLD.acquired_at IS NOT NEW.acquired_at
  OR OLD.evidence_type IS NOT NEW.evidence_type
  OR OLD.content_hash IS NOT NEW.content_hash
  OR OLD.provenance_json IS NOT NEW.provenance_json
  OR OLD.verification_state IS NOT NEW.verification_state
)
BEGIN
  SELECT RAISE(ABORT, 'classified outcome evidence is immutable');
END;

CREATE TRIGGER reusable_knowledge_outcomes_attempt_evidence_no_update
BEFORE UPDATE ON attack_attempt_evidence
WHEN EXISTS (
  SELECT 1 FROM reusable_knowledge_outcome_links link
  WHERE link.attack_attempt_id = OLD.attack_attempt_id
    AND link.evidence_id = OLD.evidence_id
)
BEGIN
  SELECT RAISE(ABORT, 'classified attack-attempt evidence binding is immutable');
END;

CREATE TRIGGER reusable_knowledge_outcomes_attempt_evidence_no_delete
BEFORE DELETE ON attack_attempt_evidence
WHEN EXISTS (
  SELECT 1 FROM reusable_knowledge_outcome_links link
  WHERE link.attack_attempt_id = OLD.attack_attempt_id
    AND link.evidence_id = OLD.evidence_id
)
BEGIN
  SELECT RAISE(ABORT, 'classified attack-attempt evidence binding is immutable');
END;

CREATE TRIGGER reusable_knowledge_outcomes_context_no_delete
BEFORE DELETE ON attack_attempt_knowledge_contexts
WHEN EXISTS (
  SELECT 1 FROM reusable_knowledge_outcome_links link
  WHERE link.attack_attempt_id = OLD.attack_attempt_id
)
BEGIN
  SELECT RAISE(ABORT, 'classified attack-attempt knowledge binding is immutable');
END;

CREATE TRIGGER reusable_knowledge_outcomes_context_no_update
BEFORE UPDATE ON attack_attempt_knowledge_contexts
WHEN EXISTS (
  SELECT 1 FROM reusable_knowledge_outcome_links link
  WHERE link.attack_attempt_id = OLD.attack_attempt_id
)
BEGIN
  SELECT RAISE(ABORT, 'classified attack-attempt knowledge binding is immutable');
END;

CREATE TRIGGER reusable_knowledge_outcomes_custody_no_update
BEFORE UPDATE ON evidence_chain_events
WHEN OLD.event_type = 'verified'
  AND EXISTS (
    SELECT 1 FROM reusable_knowledge_outcome_links link
    WHERE link.evidence_id = OLD.evidence_id
  )
BEGIN
  SELECT RAISE(ABORT, 'classified outcome evidence custody is immutable');
END;

CREATE TRIGGER reusable_knowledge_outcomes_custody_no_delete
BEFORE DELETE ON evidence_chain_events
WHEN OLD.event_type = 'verified'
  AND EXISTS (
    SELECT 1 FROM reusable_knowledge_outcome_links link
    WHERE link.evidence_id = OLD.evidence_id
  )
BEGIN
  SELECT RAISE(ABORT, 'classified outcome evidence custody is immutable');
END;

CREATE TRIGGER reusable_knowledge_outcomes_memory_boundary_update
BEFORE UPDATE OF node_type, scope, engagement_id, mission_id ON memory_nodes
WHEN EXISTS (
  SELECT 1 FROM reusable_knowledge_outcome_links link
  WHERE link.memory_node_id = OLD.id
)
AND (
  NEW.node_type NOT IN (
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
  )
  OR NEW.scope <> 'global'
  OR NEW.engagement_id IS NOT NULL
  OR NEW.mission_id IS NOT NULL
)
BEGIN
  SELECT RAISE(ABORT, 'classified reusable knowledge must remain in the global reusable boundary');
END;
`,
};

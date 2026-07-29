import type { Migration } from "../types";

/**
 * Immutable, evidence-linked operational-hazard health assessments and
 * single-use safer-attempt authorizations. Private target identity remains in
 * canonical mission/topology records; these records retain only a SHA-256
 * context fingerprint and exact foreign-key bindings.
 */
export const operationalHazardHealthGateMigration: Migration = {
  version: 22,
  name: "operational_hazard_health_gate",
  sql: String.raw`
ALTER TABLE attack_attempts
  ADD COLUMN recovery_source_attack_attempt_id TEXT
  REFERENCES attack_attempts(id) ON DELETE RESTRICT;

CREATE INDEX idx_attack_attempt_recovery_source
  ON attack_attempts(recovery_source_attack_attempt_id)
  WHERE recovery_source_attack_attempt_id IS NOT NULL;

CREATE TRIGGER attack_attempt_recovery_source_immutable
BEFORE UPDATE OF recovery_source_attack_attempt_id ON attack_attempts
WHEN NEW.recovery_source_attack_attempt_id IS NOT OLD.recovery_source_attack_attempt_id
BEGIN
  SELECT RAISE(ABORT, 'attack attempt recovery source is immutable');
END;

CREATE TRIGGER attack_attempt_recovery_source_scope_insert
BEFORE INSERT ON attack_attempts
WHEN NEW.recovery_source_attack_attempt_id IS NOT NULL AND (
  NEW.recovery_source_attack_attempt_id = NEW.id
  OR NEW.mission_id IS NOT (
    SELECT mission_id FROM attack_attempts WHERE id = NEW.recovery_source_attack_attempt_id
  )
  OR NEW.run_id IS NOT (
    SELECT run_id FROM attack_attempts WHERE id = NEW.recovery_source_attack_attempt_id
  )
  OR NEW.target_asset_id IS NOT (
    SELECT target_asset_id FROM attack_attempts WHERE id = NEW.recovery_source_attack_attempt_id
  )
  OR NEW.target_service_id IS NOT (
    SELECT target_service_id FROM attack_attempts WHERE id = NEW.recovery_source_attack_attempt_id
  )
  OR (SELECT status FROM attack_attempts WHERE id = NEW.recovery_source_attack_attempt_id)
    NOT IN ('waiting_conditions', 'blocked')
)
BEGIN
  SELECT RAISE(ABORT, 'attack attempt recovery source scope mismatch');
END;

CREATE TABLE attack_attempt_action_bindings (
  attack_attempt_id TEXT PRIMARY KEY REFERENCES attack_attempts(id) ON DELETE RESTRICT,
  action_type TEXT NOT NULL CHECK (length(trim(action_type)) > 0),
  action_class TEXT NOT NULL CHECK (length(trim(action_class)) > 0),
  normalized_arguments_json TEXT NOT NULL
    CHECK (json_valid(normalized_arguments_json) AND json_type(normalized_arguments_json) = 'object'),
  scoped_target TEXT NOT NULL CHECK (length(trim(scoped_target)) > 0),
  binding_hash TEXT NOT NULL CHECK (length(binding_hash) = 64),
  created_at TEXT NOT NULL
) WITHOUT ROWID, STRICT;

CREATE TRIGGER attack_attempt_action_bindings_no_update
BEFORE UPDATE ON attack_attempt_action_bindings BEGIN
  SELECT RAISE(ABORT, 'attack attempt action bindings are immutable');
END;

CREATE TRIGGER attack_attempt_action_bindings_no_delete
BEFORE DELETE ON attack_attempt_action_bindings BEGIN
  SELECT RAISE(ABORT, 'attack attempt action bindings are immutable');
END;

CREATE TRIGGER attack_attempt_action_binding_scope_insert
BEFORE INSERT ON attack_attempt_action_bindings
WHEN NEW.action_class IS NOT (
  SELECT action_class FROM attack_attempts WHERE id = NEW.attack_attempt_id
)
BEGIN
  SELECT RAISE(ABORT, 'attack attempt action binding scope mismatch');
END;

CREATE TABLE operational_hazard_local_evaluators (
  evaluator_version TEXT PRIMARY KEY,
  evaluator_hash TEXT NOT NULL UNIQUE CHECK (length(evaluator_hash) = 64),
  algorithm TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled = 1),
  created_at TEXT NOT NULL
) WITHOUT ROWID, STRICT;

INSERT INTO operational_hazard_local_evaluators (
  evaluator_version, evaluator_hash, algorithm, enabled, created_at
) VALUES (
  'operational-hazard-health/v1',
  '1fc264f4cbe1b50304d693e4fe3be76ad68904f5edce085320d3d972154e8388',
  'Verified local evidence with healthAssessment.schema=ti_scale.operational_health/v1 and a boolean baselineRestored result.',
  1,
  '2026-07-20T00:00:00.000Z'
);

CREATE TRIGGER operational_hazard_local_evaluators_no_update
BEFORE UPDATE ON operational_hazard_local_evaluators BEGIN
  SELECT RAISE(ABORT, 'operational hazard local evaluators are immutable');
END;

CREATE TRIGGER operational_hazard_local_evaluators_no_delete
BEFORE DELETE ON operational_hazard_local_evaluators BEGIN
  SELECT RAISE(ABORT, 'operational hazard local evaluators are immutable');
END;

CREATE TRIGGER attack_attempt_knowledge_core_immutable
BEFORE UPDATE ON attack_attempt_knowledge_contexts
WHEN NEW.procedure_node_id IS NOT OLD.procedure_node_id
  OR NEW.procedure_version_node_id IS NOT OLD.procedure_version_node_id
  OR NEW.product_node_ids_json IS NOT OLD.product_node_ids_json
  OR NEW.version_node_ids_json IS NOT OLD.version_node_ids_json
  OR NEW.stack_node_ids_json IS NOT OLD.stack_node_ids_json
  OR NEW.prerequisite_node_ids_json IS NOT OLD.prerequisite_node_ids_json
  OR NEW.observed_state_node_ids_json IS NOT OLD.observed_state_node_ids_json
  OR NEW.normalized_parameters_json IS NOT OLD.normalized_parameters_json
  OR NEW.load IS NOT OLD.load
  OR NEW.concurrency IS NOT OLD.concurrency
  OR NEW.timing_window_ms IS NOT OLD.timing_window_ms
BEGIN
  SELECT RAISE(ABORT, 'attack attempt knowledge binding is immutable');
END;

CREATE TABLE operational_hazard_health_assessments (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  hazard_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  hazard_profile_version INTEGER NOT NULL CHECK (hazard_profile_version > 0),
  blocked_attack_attempt_id TEXT NOT NULL REFERENCES attack_attempts(id) ON DELETE RESTRICT,
  procedure_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  procedure_version_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  source_target_asset_id TEXT REFERENCES topology_nodes(id) ON DELETE RESTRICT,
  source_target_service_id TEXT REFERENCES topology_nodes(id) ON DELETE RESTRICT,
  target_context_fingerprint TEXT NOT NULL CHECK (length(target_context_fingerprint) = 64),
  represented_health_check_action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE RESTRICT,
  verified_evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
  verified_evidence_hash TEXT NOT NULL CHECK (length(verified_evidence_hash) = 64),
  evaluator_kind TEXT NOT NULL CHECK (evaluator_kind = 'local_evaluator'),
  evaluator_version TEXT NOT NULL,
  evaluator_hash TEXT NOT NULL CHECK (length(evaluator_hash) = 64),
  context_pack_id TEXT NOT NULL REFERENCES memory_context_packs(id) ON DELETE RESTRICT,
  result TEXT NOT NULL CHECK (result IN ('pass', 'fail')),
  exact_procedure_attempt_count INTEGER NOT NULL CHECK (exact_procedure_attempt_count >= 1),
  exact_procedure_reproducibility_count INTEGER NOT NULL
    CHECK (exact_procedure_reproducibility_count >= 1),
  exact_procedure_reset_count INTEGER NOT NULL DEFAULT 0 CHECK (exact_procedure_reset_count >= 0),
  operator_reported_reset_count_minimum INTEGER
    CHECK (operator_reported_reset_count_minimum IS NULL OR operator_reported_reset_count_minimum >= 0),
  recovery_cost_json TEXT NOT NULL DEFAULT '{}'
    CHECK (json_valid(recovery_cost_json) AND json_type(recovery_cost_json) = 'object'),
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  assessment_hash TEXT NOT NULL UNIQUE CHECK (length(assessment_hash) = 64),
  audit_record_id TEXT NOT NULL UNIQUE REFERENCES audit_records(id) ON DELETE RESTRICT,
  audit_record_hash TEXT NOT NULL CHECK (length(audit_record_hash) = 64),
  CHECK (expires_at > issued_at),
  CHECK (source_target_asset_id IS NOT NULL OR source_target_service_id IS NOT NULL),
  CHECK (exact_procedure_attempt_count >= exact_procedure_reproducibility_count),
  CHECK (
    operator_reported_reset_count_minimum IS NULL
    OR operator_reported_reset_count_minimum >= exact_procedure_reset_count
  ),
  UNIQUE (
    run_id, hazard_node_id, hazard_profile_version,
    represented_health_check_action_id, verified_evidence_id
  )
) STRICT;

CREATE TABLE operational_hazard_retry_authorizations (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  health_assessment_id TEXT NOT NULL REFERENCES operational_hazard_health_assessments(id) ON DELETE RESTRICT,
  hazard_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  hazard_profile_version INTEGER NOT NULL CHECK (hazard_profile_version > 0),
  source_attack_attempt_id TEXT NOT NULL REFERENCES attack_attempts(id) ON DELETE RESTRICT,
  authorized_attack_attempt_id TEXT NOT NULL UNIQUE REFERENCES attack_attempts(id) ON DELETE RESTRICT,
  source_procedure_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  source_procedure_version_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  source_parameter_fingerprint TEXT NOT NULL CHECK (length(source_parameter_fingerprint) = 64),
  authorized_procedure_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  authorized_procedure_version_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  authorized_parameter_fingerprint TEXT NOT NULL CHECK (length(authorized_parameter_fingerprint) = 64),
  authorized_action_binding_hash TEXT NOT NULL CHECK (length(authorized_action_binding_hash) = 64),
  authorization_basis TEXT NOT NULL CHECK (authorization_basis IN (
    'distinct_procedure_version', 'distinct_parameters', 'explicit_alternative'
  )),
  target_context_fingerprint TEXT NOT NULL CHECK (length(target_context_fingerprint) = 64),
  max_attempts INTEGER NOT NULL DEFAULT 1 CHECK (max_attempts = 1),
  automatic_retry INTEGER NOT NULL DEFAULT 0 CHECK (automatic_retry = 0),
  context_pack_id TEXT NOT NULL REFERENCES memory_context_packs(id) ON DELETE RESTRICT,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  authorization_hash TEXT NOT NULL UNIQUE CHECK (length(authorization_hash) = 64),
  audit_record_id TEXT NOT NULL UNIQUE REFERENCES audit_records(id) ON DELETE RESTRICT,
  audit_record_hash TEXT NOT NULL CHECK (length(audit_record_hash) = 64),
  CHECK (expires_at > issued_at),
  CHECK (source_attack_attempt_id <> authorized_attack_attempt_id),
  CHECK (
    (authorization_basis = 'explicit_alternative'
      AND source_procedure_node_id <> authorized_procedure_node_id)
    OR
    (authorization_basis = 'distinct_procedure_version'
      AND source_procedure_node_id = authorized_procedure_node_id
      AND source_procedure_version_node_id <> authorized_procedure_version_node_id)
    OR
    (authorization_basis = 'distinct_parameters'
      AND source_procedure_node_id = authorized_procedure_node_id
      AND source_procedure_version_node_id = authorized_procedure_version_node_id
      AND source_parameter_fingerprint <> authorized_parameter_fingerprint)
  )
) STRICT;

CREATE TABLE operational_hazard_retry_consumptions (
  authorization_id TEXT PRIMARY KEY REFERENCES operational_hazard_retry_authorizations(id) ON DELETE RESTRICT,
  attack_attempt_id TEXT NOT NULL UNIQUE REFERENCES attack_attempts(id) ON DELETE RESTRICT,
  action_id TEXT NOT NULL UNIQUE REFERENCES actions(id) ON DELETE RESTRICT,
  context_pack_id TEXT NOT NULL REFERENCES memory_context_packs(id) ON DELETE RESTRICT,
  consumed_at TEXT NOT NULL,
  consumption_hash TEXT NOT NULL UNIQUE CHECK (length(consumption_hash) = 64),
  audit_record_id TEXT NOT NULL UNIQUE REFERENCES audit_records(id) ON DELETE RESTRICT,
  audit_record_hash TEXT NOT NULL CHECK (length(audit_record_hash) = 64)
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_hazard_health_assessment_scope
  ON operational_hazard_health_assessments(run_id, hazard_node_id, issued_at DESC);
CREATE INDEX idx_hazard_health_assessment_expiry
  ON operational_hazard_health_assessments(result, expires_at);
CREATE INDEX idx_hazard_retry_authorization_scope
  ON operational_hazard_retry_authorizations(run_id, authorized_attack_attempt_id, expires_at);
CREATE INDEX idx_hazard_retry_authorization_assessment
  ON operational_hazard_retry_authorizations(health_assessment_id, issued_at DESC);

CREATE TRIGGER operational_hazard_health_assessments_no_update
BEFORE UPDATE ON operational_hazard_health_assessments BEGIN
  SELECT RAISE(ABORT, 'operational hazard health assessments are immutable');
END;

CREATE TRIGGER operational_hazard_health_assessments_no_delete
BEFORE DELETE ON operational_hazard_health_assessments BEGIN
  SELECT RAISE(ABORT, 'operational hazard health assessments are immutable');
END;

CREATE TRIGGER operational_hazard_retry_authorizations_no_update
BEFORE UPDATE ON operational_hazard_retry_authorizations BEGIN
  SELECT RAISE(ABORT, 'operational hazard retry authorizations are immutable');
END;

CREATE TRIGGER operational_hazard_retry_authorizations_no_delete
BEFORE DELETE ON operational_hazard_retry_authorizations BEGIN
  SELECT RAISE(ABORT, 'operational hazard retry authorizations are immutable');
END;

CREATE TRIGGER operational_hazard_retry_consumptions_no_update
BEFORE UPDATE ON operational_hazard_retry_consumptions BEGIN
  SELECT RAISE(ABORT, 'operational hazard retry consumptions are immutable');
END;

CREATE TRIGGER operational_hazard_retry_consumptions_no_delete
BEFORE DELETE ON operational_hazard_retry_consumptions BEGIN
  SELECT RAISE(ABORT, 'operational hazard retry consumptions are immutable');
END;

CREATE TRIGGER operational_hazard_health_assessment_scope_insert
BEFORE INSERT ON operational_hazard_health_assessments
WHEN NEW.mission_id IS NOT (SELECT mission_id FROM runs WHERE id = NEW.run_id)
  OR NEW.mission_id IS NOT (SELECT mission_id FROM attack_attempts WHERE id = NEW.blocked_attack_attempt_id)
  OR NEW.run_id IS NOT (SELECT run_id FROM attack_attempts WHERE id = NEW.blocked_attack_attempt_id)
  OR NEW.mission_id IS NOT (SELECT mission_id FROM actions WHERE id = NEW.represented_health_check_action_id)
  OR NEW.run_id IS NOT (SELECT run_id FROM actions WHERE id = NEW.represented_health_check_action_id)
  OR NEW.mission_id IS NOT (SELECT mission_id FROM evidence WHERE id = NEW.verified_evidence_id)
  OR NEW.run_id IS NOT (SELECT run_id FROM evidence WHERE id = NEW.verified_evidence_id)
  OR NEW.represented_health_check_action_id IS NOT (SELECT action_id FROM evidence WHERE id = NEW.verified_evidence_id)
  OR NEW.verified_evidence_hash IS NOT (SELECT content_hash FROM evidence WHERE id = NEW.verified_evidence_id)
  OR 'verified' IS NOT (SELECT verification_state FROM evidence WHERE id = NEW.verified_evidence_id)
  OR NEW.evaluator_hash IS NOT (
    SELECT evaluator_hash FROM operational_hazard_local_evaluators
    WHERE evaluator_version = NEW.evaluator_version AND enabled = 1
  )
  OR NEW.result IS NOT (
    SELECT CASE json_extract(provenance_json, '$.healthAssessment.baselineRestored')
      WHEN 1 THEN 'pass' WHEN 0 THEN 'fail' ELSE NULL END
    FROM evidence WHERE id = NEW.verified_evidence_id
      AND json_extract(provenance_json, '$.healthAssessment.schema') = 'ti_scale.operational_health/v1'
  )
  OR NEW.run_id IS NOT (SELECT run_id FROM memory_context_packs WHERE id = NEW.context_pack_id)
  OR NEW.hazard_profile_version IS NOT (SELECT version FROM operational_hazard_profiles WHERE node_id = NEW.hazard_node_id)
  OR NEW.exact_procedure_attempt_count IS NOT (SELECT attempt_count FROM operational_hazard_profiles WHERE node_id = NEW.hazard_node_id)
  OR NEW.exact_procedure_reproducibility_count IS NOT (SELECT reproducibility_count FROM operational_hazard_profiles WHERE node_id = NEW.hazard_node_id)
  OR NEW.exact_procedure_reset_count IS NOT COALESCE((
    SELECT CAST(json_extract(recovery_cost_json, '$.resetCount') AS INTEGER)
    FROM operational_hazard_profiles WHERE node_id = NEW.hazard_node_id
  ), 0)
  OR NEW.operator_reported_reset_count_minimum IS NOT (
    SELECT CAST(json_extract(recovery_cost_json, '$.operatorReportedResetCountMinimum') AS INTEGER)
    FROM operational_hazard_profiles WHERE node_id = NEW.hazard_node_id
  )
  OR NEW.procedure_node_id IS NOT (SELECT procedure_node_id FROM operational_hazard_profiles WHERE node_id = NEW.hazard_node_id)
  OR NEW.procedure_version_node_id IS NOT (SELECT procedure_version_node_id FROM operational_hazard_profiles WHERE node_id = NEW.hazard_node_id)
  OR NEW.procedure_node_id IS NOT (SELECT procedure_node_id FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = NEW.blocked_attack_attempt_id)
  OR NEW.procedure_version_node_id IS NOT (SELECT procedure_version_node_id FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = NEW.blocked_attack_attempt_id)
  OR NEW.source_target_asset_id IS NOT (SELECT target_asset_id FROM attack_attempts WHERE id = NEW.blocked_attack_attempt_id)
  OR NEW.source_target_service_id IS NOT (SELECT target_service_id FROM attack_attempts WHERE id = NEW.blocked_attack_attempt_id)
  OR NEW.audit_record_hash IS NOT (SELECT record_hash FROM audit_records WHERE id = NEW.audit_record_id)
BEGIN
  SELECT RAISE(ABORT, 'operational hazard health assessment scope mismatch');
END;

CREATE TRIGGER operational_hazard_retry_authorization_scope_insert
BEFORE INSERT ON operational_hazard_retry_authorizations
WHEN NEW.mission_id IS NOT (SELECT mission_id FROM runs WHERE id = NEW.run_id)
  OR NEW.mission_id IS NOT (SELECT mission_id FROM attack_attempts WHERE id = NEW.source_attack_attempt_id)
  OR NEW.run_id IS NOT (SELECT run_id FROM attack_attempts WHERE id = NEW.source_attack_attempt_id)
  OR NEW.mission_id IS NOT (SELECT mission_id FROM attack_attempts WHERE id = NEW.authorized_attack_attempt_id)
  OR NEW.run_id IS NOT (SELECT run_id FROM attack_attempts WHERE id = NEW.authorized_attack_attempt_id)
  OR NEW.source_attack_attempt_id IS NOT (
    SELECT recovery_source_attack_attempt_id FROM attack_attempts
    WHERE id = NEW.authorized_attack_attempt_id
  )
  OR (SELECT target_asset_id FROM attack_attempts WHERE id = NEW.source_attack_attempt_id)
    IS NOT (SELECT target_asset_id FROM attack_attempts WHERE id = NEW.authorized_attack_attempt_id)
  OR (SELECT target_service_id FROM attack_attempts WHERE id = NEW.source_attack_attempt_id)
    IS NOT (SELECT target_service_id FROM attack_attempts WHERE id = NEW.authorized_attack_attempt_id)
  OR NEW.run_id IS NOT (SELECT run_id FROM operational_hazard_health_assessments WHERE id = NEW.health_assessment_id)
  OR 'pass' IS NOT (SELECT result FROM operational_hazard_health_assessments WHERE id = NEW.health_assessment_id)
  OR NEW.hazard_node_id IS NOT (SELECT hazard_node_id FROM operational_hazard_health_assessments WHERE id = NEW.health_assessment_id)
  OR NEW.hazard_profile_version IS NOT (SELECT hazard_profile_version FROM operational_hazard_health_assessments WHERE id = NEW.health_assessment_id)
  OR NEW.target_context_fingerprint IS NOT (SELECT target_context_fingerprint FROM operational_hazard_health_assessments WHERE id = NEW.health_assessment_id)
  OR NEW.context_pack_id IS NOT (SELECT context_pack_id FROM operational_hazard_health_assessments WHERE id = NEW.health_assessment_id)
  OR NEW.source_procedure_node_id IS NOT (SELECT procedure_node_id FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = NEW.source_attack_attempt_id)
  OR NEW.source_procedure_version_node_id IS NOT (SELECT procedure_version_node_id FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = NEW.source_attack_attempt_id)
  OR NEW.authorized_procedure_node_id IS NOT (SELECT procedure_node_id FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = NEW.authorized_attack_attempt_id)
  OR NEW.authorized_procedure_version_node_id IS NOT (SELECT procedure_version_node_id FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = NEW.authorized_attack_attempt_id)
  OR NEW.authorized_action_binding_hash IS NOT (
    SELECT binding_hash FROM attack_attempt_action_bindings
    WHERE attack_attempt_id = NEW.authorized_attack_attempt_id
  )
  OR NEW.audit_record_hash IS NOT (SELECT record_hash FROM audit_records WHERE id = NEW.audit_record_id)
BEGIN
  SELECT RAISE(ABORT, 'operational hazard retry authorization scope mismatch');
END;

CREATE TRIGGER operational_hazard_retry_consumption_scope_insert
BEFORE INSERT ON operational_hazard_retry_consumptions
WHEN NEW.attack_attempt_id IS NOT (SELECT authorized_attack_attempt_id FROM operational_hazard_retry_authorizations WHERE id = NEW.authorization_id)
  OR NEW.context_pack_id IS NOT (SELECT context_pack_id FROM operational_hazard_retry_authorizations WHERE id = NEW.authorization_id)
  OR (SELECT run_id FROM actions WHERE id = NEW.action_id) IS NOT (
    SELECT run_id FROM operational_hazard_retry_authorizations WHERE id = NEW.authorization_id
  )
  OR (SELECT step_id FROM actions WHERE id = NEW.action_id) IS NOT (
    SELECT step_id FROM attack_attempts WHERE id = NEW.attack_attempt_id
  )
  OR NEW.audit_record_hash IS NOT (SELECT record_hash FROM audit_records WHERE id = NEW.audit_record_id)
BEGIN
  SELECT RAISE(ABORT, 'operational hazard retry consumption scope mismatch');
END;
`,
};

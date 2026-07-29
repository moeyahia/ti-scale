import type { Migration } from "../types";

/**
 * A reviewed real-candidate procedure is discovered and activated after the
 * mission has current evidence and a represented attack step. The static
 * adapter/profile is only a conditional capability at launch; these records
 * are the run-scoped authority required before any candidate procedure can be
 * dispatched.
 *
 * Activation headers are immutable. Provider attestations are append-only so
 * restart/resume can renew liveness without rewriting the original custody
 * receipt.
 */
export const runScopedCandidateLinuxProcedureActivationsMigration:
Migration = {
  version: 62,
  name: "run_scoped_candidate_linux_procedure_activations",
  sql: String.raw`
CREATE TABLE reviewed_candidate_linux_procedure_activations (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
  step_id TEXT NOT NULL REFERENCES plan_steps(id) ON DELETE RESTRICT,
  attack_attempt_id TEXT NOT NULL
    REFERENCES attack_attempts(id) ON DELETE RESTRICT,
  target_node_id TEXT NOT NULL
    REFERENCES topology_nodes(id) ON DELETE RESTRICT,
  exact_target TEXT NOT NULL CHECK (length(trim(exact_target)) > 0),
  source_post_exploit_spec_id TEXT NOT NULL
    REFERENCES candidate_linux_post_exploit_specs(id) ON DELETE RESTRICT,
  post_exploit_spec_id TEXT NOT NULL UNIQUE
    REFERENCES candidate_linux_post_exploit_specs(id) ON DELETE RESTRICT,
  script_artifact_id TEXT NOT NULL UNIQUE
    REFERENCES script_artifacts(id) ON DELETE RESTRICT,
  script_content_hash TEXT NOT NULL CHECK (
    length(script_content_hash) = 64
    AND script_content_hash NOT GLOB '*[^0-9a-f]*'
  ),
  exploit_outcome_observer_spec_id TEXT NOT NULL UNIQUE
    REFERENCES exploit_outcome_observer_specs(id) ON DELETE RESTRICT,
  exploit_outcome_observer_spec_hash TEXT NOT NULL CHECK (
    length(exploit_outcome_observer_spec_hash) = 64
    AND exploit_outcome_observer_spec_hash NOT GLOB '*[^0-9a-f]*'
  ),
  script_validation_artifact_id TEXT NOT NULL
    REFERENCES artifacts(id) ON DELETE RESTRICT,
  script_validation_artifact_hash TEXT NOT NULL CHECK (
    length(script_validation_artifact_hash) = 64
    AND script_validation_artifact_hash NOT GLOB '*[^0-9a-f]*'
  ),
  represented_action_binding_hash TEXT NOT NULL CHECK (
    length(represented_action_binding_hash) = 64
    AND represented_action_binding_hash NOT GLOB '*[^0-9a-f]*'
  ),
  profile_id TEXT NOT NULL CHECK (length(trim(profile_id)) > 0),
  profile_sha256 TEXT NOT NULL CHECK (
    length(profile_sha256) = 64
    AND profile_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  transport_binding_id TEXT NOT NULL CHECK (
    length(trim(transport_binding_id)) > 0
  ),
  procedure_executable_path TEXT NOT NULL CHECK (
    procedure_executable_path GLOB '/*'
    AND instr(procedure_executable_path, char(10)) = 0
    AND instr(procedure_executable_path, char(13)) = 0
  ),
  procedure_executable_sha256 TEXT NOT NULL CHECK (
    length(procedure_executable_sha256) = 64
    AND procedure_executable_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  idempotency_key_hash TEXT NOT NULL CHECK (
    length(idempotency_key_hash) = 64
    AND idempotency_key_hash NOT GLOB '*[^0-9a-f]*'
  ),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  activation_receipt_json TEXT NOT NULL CHECK (
    json_valid(activation_receipt_json)
    AND json_type(activation_receipt_json) = 'object'
  ),
  activation_receipt_hash TEXT NOT NULL UNIQUE CHECK (
    length(activation_receipt_hash) = 64
    AND activation_receipt_hash NOT GLOB '*[^0-9a-f]*'
  ),
  activated_by TEXT NOT NULL CHECK (length(trim(activated_by)) > 0),
  activated_at TEXT NOT NULL,
  revoked_at TEXT,
  revocation_reason TEXT,
  UNIQUE (run_id, attack_attempt_id),
  UNIQUE (run_id, idempotency_key_hash),
  CHECK (
    (status = 'active' AND revoked_at IS NULL AND revocation_reason IS NULL)
    OR (
      status = 'revoked'
      AND revoked_at IS NOT NULL
      AND length(trim(revocation_reason)) > 0
    )
  )
) STRICT;

CREATE INDEX idx_reviewed_candidate_procedure_activation_run_status
  ON reviewed_candidate_linux_procedure_activations(
    run_id, status, activated_at DESC
  );

CREATE INDEX idx_reviewed_candidate_procedure_activation_spec
  ON reviewed_candidate_linux_procedure_activations(
    post_exploit_spec_id, status
  );

CREATE TABLE reviewed_candidate_linux_procedure_attestations (
  id TEXT PRIMARY KEY,
  activation_id TEXT NOT NULL
    REFERENCES reviewed_candidate_linux_procedure_activations(id)
    ON DELETE RESTRICT,
  provider_receipt_hash TEXT NOT NULL CHECK (
    length(provider_receipt_hash) = 64
    AND provider_receipt_hash NOT GLOB '*[^0-9a-f]*'
  ),
  provider_receipt_json TEXT NOT NULL CHECK (
    json_valid(provider_receipt_json)
    AND json_type(provider_receipt_json) = 'object'
  ),
  run_scoped_receipt_hash TEXT NOT NULL UNIQUE CHECK (
    length(run_scoped_receipt_hash) = 64
    AND run_scoped_receipt_hash NOT GLOB '*[^0-9a-f]*'
  ),
  run_scoped_receipt_json TEXT NOT NULL CHECK (
    json_valid(run_scoped_receipt_json)
    AND json_type(run_scoped_receipt_json) = 'object'
  ),
  observed_at TEXT NOT NULL,
  expires_at TEXT NOT NULL CHECK (expires_at > observed_at),
  recorded_at TEXT NOT NULL,
  UNIQUE (activation_id, provider_receipt_hash)
) STRICT;

CREATE INDEX idx_reviewed_candidate_procedure_attestation_current
  ON reviewed_candidate_linux_procedure_attestations(
    activation_id, expires_at DESC, observed_at DESC
  );

CREATE TRIGGER trg_reviewed_candidate_procedure_activation_lineage_insert
BEFORE INSERT ON reviewed_candidate_linux_procedure_activations
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM missions AS mission
    JOIN runs AS run
      ON run.id = NEW.run_id
      AND run.mission_id = mission.id
      AND run.journey = 'autonomous'
      AND run.control_plane = 'ti_scale'
      AND run.status IN ('planning', 'running', 'recovering')
      AND run.current_plan_id = NEW.plan_id
    JOIN mission_contracts AS contract
      ON contract.id = run.contract_id
      AND contract.mission_id = mission.id
      AND contract.state = 'confirmed'
      AND contract.version = run.contract_version_bound
      AND contract.contract_hash = run.contract_hash_bound
    JOIN plans AS plan
      ON plan.id = NEW.plan_id
      AND plan.run_id = run.id
      AND plan.status = 'active'
    JOIN plan_steps AS step
      ON step.id = NEW.step_id
      AND step.plan_id = plan.id
      AND step.run_id = run.id
    JOIN topology_nodes AS target
      ON target.id = NEW.target_node_id
      AND target.mission_id = mission.id
      AND target.run_id = run.id
      AND target.scope_status = 'allowed'
      AND target.verification_state = 'verified'
      AND NEW.exact_target IN (
        target.normalized_identity, target.primary_label
      )
    JOIN mission_targets AS scope
      ON scope.mission_id = mission.id
      AND scope.disposition = 'allowed'
      AND scope.normalized_target = NEW.exact_target
    JOIN script_artifacts AS script
      ON script.id = NEW.script_artifact_id
      AND script.mission_id = mission.id
      AND script.run_id = run.id
      AND (script.plan_id IS NULL OR script.plan_id = plan.id)
      AND (script.step_id IS NULL OR script.step_id = step.id)
      AND (
        script.target_node_id IS NULL
        OR script.target_node_id = target.id
      )
      AND script.content_hash = NEW.script_content_hash
      AND script.validation_state = 'approved'
      AND script.test_artifact_id = NEW.script_validation_artifact_id
    JOIN artifacts AS validation
      ON validation.id = script.test_artifact_id
      AND validation.mission_id = mission.id
      AND validation.run_id = run.id
      AND (
        validation.step_id IS NULL
        OR validation.step_id = step.id
      )
      AND validation.artifact_type IN (
        'script_test_result', 'generated_script_test', 'test_result'
      )
      AND validation.content_hash =
        NEW.script_validation_artifact_hash
    JOIN candidate_linux_post_exploit_specs AS spec
      ON spec.id = NEW.post_exploit_spec_id
      AND spec.script_artifact_id = script.id
      AND spec.transport_type = 'candidate_runtime_session_v1'
      AND spec.transport_binding_id = NEW.transport_binding_id
      AND spec.status = 'active'
    JOIN exploit_outcome_observer_specs AS observer
      ON observer.id = NEW.exploit_outcome_observer_spec_id
      AND observer.id = spec.exploit_outcome_observer_spec_id
      AND observer.script_artifact_id = script.id
      AND observer.script_content_hash = script.content_hash
      AND observer.spec_hash =
        NEW.exploit_outcome_observer_spec_hash
      AND observer.status = 'active'
    JOIN candidate_linux_post_exploit_specs AS source_spec
      ON source_spec.id = NEW.source_post_exploit_spec_id
      AND source_spec.transport_type = 'candidate_runtime_session_v1'
      AND source_spec.transport_binding_id = NEW.transport_binding_id
      AND source_spec.status = 'active'
      AND spec.created_by IN (
        'system:cloned-from:' || source_spec.id,
        'system:validated-candidate-from:' || source_spec.id
      )
      AND spec.expected_principal = source_spec.expected_principal
      AND spec.expected_uid = source_spec.expected_uid
      AND spec.declared_user_flag_path =
        source_spec.declared_user_flag_path
      AND spec.declared_root_flag_path =
        source_spec.declared_root_flag_path
    JOIN script_artifacts AS source_script
      ON source_script.id = source_spec.script_artifact_id
      AND source_script.validation_state = 'approved'
    JOIN exploit_outcome_observer_specs AS source_observer
      ON source_observer.id =
        source_spec.exploit_outcome_observer_spec_id
      AND source_observer.script_artifact_id = source_script.id
      AND source_observer.script_content_hash =
        source_script.content_hash
      AND source_observer.status = 'active'
    JOIN attack_attempts AS attempt
      ON attempt.id = NEW.attack_attempt_id
      AND attempt.mission_id = mission.id
      AND attempt.run_id = run.id
      AND attempt.plan_id = plan.id
      AND attempt.step_id = step.id
      AND attempt.target_asset_id = target.id
      AND attempt.action_class = 'exploit_validation'
      AND attempt.status IN ('ready', 'running')
      AND EXISTS (
        SELECT 1 FROM json_each(attempt.prerequisites_json)
        WHERE value = script.id
      )
    JOIN attack_attempt_action_bindings AS action_binding
      ON action_binding.attack_attempt_id = attempt.id
      AND action_binding.action_class = attempt.action_class
      AND action_binding.scoped_target = NEW.exact_target
      AND action_binding.binding_hash =
        NEW.represented_action_binding_hash
    WHERE mission.id = NEW.mission_id
      AND mission.journey = 'autonomous'
      AND mission.control_plane = 'ti_scale'
      AND mission.authorization_status = 'verified'
      AND EXISTS (
        SELECT 1
        FROM json_each(
          json_extract(
            contract.action_policy_json,
            '$.allowedActionClasses'
          )
        )
        WHERE value = 'exploit_validation'
      )
  ) THEN RAISE(
    ABORT,
    'reviewed candidate procedure activation lineage is invalid'
  ) END;
END;

CREATE TRIGGER trg_reviewed_candidate_procedure_activation_immutable
BEFORE UPDATE ON reviewed_candidate_linux_procedure_activations
WHEN
  NEW.id != OLD.id
  OR NEW.mission_id != OLD.mission_id
  OR NEW.run_id != OLD.run_id
  OR NEW.plan_id != OLD.plan_id
  OR NEW.step_id != OLD.step_id
  OR NEW.attack_attempt_id != OLD.attack_attempt_id
  OR NEW.target_node_id != OLD.target_node_id
  OR NEW.exact_target != OLD.exact_target
  OR NEW.source_post_exploit_spec_id != OLD.source_post_exploit_spec_id
  OR NEW.post_exploit_spec_id != OLD.post_exploit_spec_id
  OR NEW.script_artifact_id != OLD.script_artifact_id
  OR NEW.script_content_hash != OLD.script_content_hash
  OR NEW.exploit_outcome_observer_spec_id
    != OLD.exploit_outcome_observer_spec_id
  OR NEW.exploit_outcome_observer_spec_hash
    != OLD.exploit_outcome_observer_spec_hash
  OR NEW.script_validation_artifact_id
    != OLD.script_validation_artifact_id
  OR NEW.script_validation_artifact_hash
    != OLD.script_validation_artifact_hash
  OR NEW.represented_action_binding_hash
    != OLD.represented_action_binding_hash
  OR NEW.profile_id != OLD.profile_id
  OR NEW.profile_sha256 != OLD.profile_sha256
  OR NEW.transport_binding_id != OLD.transport_binding_id
  OR NEW.procedure_executable_path != OLD.procedure_executable_path
  OR NEW.procedure_executable_sha256
    != OLD.procedure_executable_sha256
  OR NEW.idempotency_key_hash != OLD.idempotency_key_hash
  OR NEW.activation_receipt_json != OLD.activation_receipt_json
  OR NEW.activation_receipt_hash != OLD.activation_receipt_hash
  OR NEW.activated_by != OLD.activated_by
  OR NEW.activated_at != OLD.activated_at
BEGIN
  SELECT RAISE(
    ABORT,
    'reviewed candidate procedure activation authority is immutable'
  );
END;

CREATE TRIGGER trg_reviewed_candidate_procedure_attestation_active_insert
BEFORE INSERT ON reviewed_candidate_linux_procedure_attestations
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM reviewed_candidate_linux_procedure_activations AS activation
    WHERE activation.id = NEW.activation_id
      AND activation.status = 'active'
  ) THEN RAISE(
    ABORT,
    'reviewed candidate procedure attestation requires an active activation'
  ) END;
END;

CREATE TRIGGER trg_reviewed_candidate_procedure_attestation_immutable
BEFORE UPDATE ON reviewed_candidate_linux_procedure_attestations
BEGIN
  SELECT RAISE(
    ABORT,
    'reviewed candidate procedure attestations are append-only'
  );
END;
`,
};

import type { Migration } from "../types";

/**
 * Target-free, pre-plan admission for a distinct reviewed procedure provider.
 *
 * The exploit ScriptArtifact and the procedure provider intentionally have
 * independent byte identities. An admission binds both hashes to one source
 * profile and records the locally validated eight-operation conformance
 * receipt before a derived plan can reference the candidate.
 */
export const reviewedCandidateLinuxProcedureAdmissionsMigration:
Migration = {
  version: 63,
  name: "reviewed_candidate_linux_procedure_admissions",
  sql: String.raw`
CREATE TABLE reviewed_candidate_linux_procedure_admissions (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  source_post_exploit_spec_id TEXT NOT NULL
    REFERENCES candidate_linux_post_exploit_specs(id) ON DELETE RESTRICT,
  post_exploit_spec_id TEXT NOT NULL UNIQUE
    REFERENCES candidate_linux_post_exploit_specs(id) ON DELETE RESTRICT,
  source_script_artifact_id TEXT NOT NULL
    REFERENCES script_artifacts(id) ON DELETE RESTRICT,
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
  procedure_protocol_version TEXT NOT NULL CHECK (
    procedure_protocol_version =
      'ti-scale.reviewed-real-candidate-linux-procedure.v1'
  ),
  provider_attestation_json TEXT NOT NULL CHECK (
    json_valid(provider_attestation_json)
    AND json_type(provider_attestation_json) = 'object'
  ),
  provider_attestation_hash TEXT NOT NULL CHECK (
    length(provider_attestation_hash) = 64
    AND provider_attestation_hash NOT GLOB '*[^0-9a-f]*'
  ),
  provider_conformance_json TEXT NOT NULL CHECK (
    json_valid(provider_conformance_json)
    AND json_type(provider_conformance_json) = 'object'
  ),
  provider_conformance_hash TEXT NOT NULL CHECK (
    length(provider_conformance_hash) = 64
    AND provider_conformance_hash NOT GLOB '*[^0-9a-f]*'
  ),
  admission_receipt_json TEXT NOT NULL CHECK (
    json_valid(admission_receipt_json)
    AND json_type(admission_receipt_json) = 'object'
  ),
  admission_receipt_hash TEXT NOT NULL UNIQUE CHECK (
    length(admission_receipt_hash) = 64
    AND admission_receipt_hash NOT GLOB '*[^0-9a-f]*'
  ),
  idempotency_key_hash TEXT NOT NULL CHECK (
    length(idempotency_key_hash) = 64
    AND idempotency_key_hash NOT GLOB '*[^0-9a-f]*'
  ),
  status TEXT NOT NULL CHECK (status IN ('admitted', 'revoked')),
  admitted_by TEXT NOT NULL CHECK (length(trim(admitted_by)) > 0),
  admitted_at TEXT NOT NULL,
  revoked_at TEXT,
  revocation_reason TEXT,
  UNIQUE (run_id, idempotency_key_hash),
  CHECK (
    (status = 'admitted' AND revoked_at IS NULL AND revocation_reason IS NULL)
    OR (
      status = 'revoked'
      AND revoked_at IS NOT NULL
      AND length(trim(revocation_reason)) > 0
    )
  )
) STRICT;

CREATE INDEX idx_reviewed_candidate_procedure_admission_run_status
  ON reviewed_candidate_linux_procedure_admissions(
    run_id, status, admitted_at DESC
  );

CREATE TRIGGER trg_reviewed_candidate_procedure_admission_lineage_insert
BEFORE INSERT ON reviewed_candidate_linux_procedure_admissions
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
    JOIN script_artifacts AS script
      ON script.id = NEW.script_artifact_id
      AND script.mission_id = mission.id
      AND script.run_id = run.id
      AND script.content_hash = NEW.script_content_hash
      AND script.validation_state = 'approved'
      AND script.test_artifact_id IS NOT NULL
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
      AND observer.spec_hash = NEW.exploit_outcome_observer_spec_hash
      AND observer.status = 'active'
    JOIN candidate_linux_post_exploit_specs AS source_spec
      ON source_spec.id = NEW.source_post_exploit_spec_id
      AND source_spec.transport_type = 'candidate_runtime_session_v1'
      AND source_spec.transport_binding_id = NEW.transport_binding_id
      AND source_spec.status = 'active'
      AND spec.created_by = 'system:cloned-from:' || source_spec.id
      AND spec.expected_principal = source_spec.expected_principal
      AND spec.expected_uid = source_spec.expected_uid
      AND spec.declared_user_flag_path =
        source_spec.declared_user_flag_path
      AND spec.declared_root_flag_path =
        source_spec.declared_root_flag_path
    JOIN script_artifacts AS source_script
      ON source_script.id = NEW.source_script_artifact_id
      AND source_script.id = source_spec.script_artifact_id
      AND source_script.validation_state = 'approved'
      AND source_script.content_hash = script.content_hash
    WHERE mission.id = NEW.mission_id
      AND mission.journey = 'autonomous'
      AND mission.control_plane = 'ti_scale'
      AND mission.authorization_status = 'verified'
      AND NEW.procedure_executable_sha256 != NEW.script_content_hash
  ) THEN RAISE(
    ABORT,
    'reviewed candidate procedure admission lineage is invalid'
  ) END;
END;

CREATE TRIGGER trg_reviewed_candidate_procedure_admission_immutable
BEFORE UPDATE ON reviewed_candidate_linux_procedure_admissions
WHEN
  NEW.id != OLD.id
  OR NEW.mission_id != OLD.mission_id
  OR NEW.run_id != OLD.run_id
  OR NEW.source_post_exploit_spec_id != OLD.source_post_exploit_spec_id
  OR NEW.post_exploit_spec_id != OLD.post_exploit_spec_id
  OR NEW.source_script_artifact_id != OLD.source_script_artifact_id
  OR NEW.script_artifact_id != OLD.script_artifact_id
  OR NEW.script_content_hash != OLD.script_content_hash
  OR NEW.exploit_outcome_observer_spec_id
    != OLD.exploit_outcome_observer_spec_id
  OR NEW.exploit_outcome_observer_spec_hash
    != OLD.exploit_outcome_observer_spec_hash
  OR NEW.profile_id != OLD.profile_id
  OR NEW.profile_sha256 != OLD.profile_sha256
  OR NEW.transport_binding_id != OLD.transport_binding_id
  OR NEW.procedure_executable_path != OLD.procedure_executable_path
  OR NEW.procedure_executable_sha256
    != OLD.procedure_executable_sha256
  OR NEW.procedure_protocol_version != OLD.procedure_protocol_version
  OR NEW.provider_attestation_json != OLD.provider_attestation_json
  OR NEW.provider_attestation_hash != OLD.provider_attestation_hash
  OR NEW.provider_conformance_json != OLD.provider_conformance_json
  OR NEW.provider_conformance_hash != OLD.provider_conformance_hash
  OR NEW.admission_receipt_json != OLD.admission_receipt_json
  OR NEW.admission_receipt_hash != OLD.admission_receipt_hash
  OR NEW.idempotency_key_hash != OLD.idempotency_key_hash
  OR NEW.admitted_by != OLD.admitted_by
  OR NEW.admitted_at != OLD.admitted_at
BEGIN
  SELECT RAISE(
    ABORT,
    'reviewed candidate procedure admission authority is immutable'
  );
END;

ALTER TABLE reviewed_candidate_linux_procedure_activations
  ADD COLUMN procedure_admission_id TEXT
    REFERENCES reviewed_candidate_linux_procedure_admissions(id)
    ON DELETE RESTRICT;

CREATE UNIQUE INDEX idx_reviewed_candidate_procedure_activation_admission
  ON reviewed_candidate_linux_procedure_activations(procedure_admission_id)
  WHERE procedure_admission_id IS NOT NULL;

DROP TRIGGER IF EXISTS
  trg_reviewed_candidate_procedure_activation_lineage_insert;

CREATE TRIGGER trg_reviewed_candidate_procedure_activation_lineage_insert
BEFORE INSERT ON reviewed_candidate_linux_procedure_activations
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM reviewed_candidate_linux_procedure_admissions AS admission
    JOIN missions AS mission
      ON mission.id = admission.mission_id
      AND mission.id = NEW.mission_id
      AND mission.journey = 'autonomous'
      AND mission.control_plane = 'ti_scale'
      AND mission.authorization_status = 'verified'
    JOIN runs AS run
      ON run.id = admission.run_id
      AND run.id = NEW.run_id
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
    WHERE admission.id = NEW.procedure_admission_id
      AND admission.status = 'admitted'
      AND admission.mission_id = NEW.mission_id
      AND admission.run_id = NEW.run_id
      AND admission.source_post_exploit_spec_id =
        NEW.source_post_exploit_spec_id
      AND admission.post_exploit_spec_id = NEW.post_exploit_spec_id
      AND admission.script_artifact_id = NEW.script_artifact_id
      AND admission.script_content_hash = NEW.script_content_hash
      AND admission.exploit_outcome_observer_spec_id =
        NEW.exploit_outcome_observer_spec_id
      AND admission.exploit_outcome_observer_spec_hash =
        NEW.exploit_outcome_observer_spec_hash
      AND admission.profile_id = NEW.profile_id
      AND admission.profile_sha256 = NEW.profile_sha256
      AND admission.transport_binding_id = NEW.transport_binding_id
      AND admission.procedure_executable_path =
        NEW.procedure_executable_path
      AND admission.procedure_executable_sha256 =
        NEW.procedure_executable_sha256
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
    'reviewed candidate procedure activation lineage or admission is invalid'
  ) END;
END;

CREATE TRIGGER
  trg_reviewed_candidate_procedure_activation_admission_immutable
BEFORE UPDATE OF procedure_admission_id
ON reviewed_candidate_linux_procedure_activations
WHEN NEW.procedure_admission_id IS NOT OLD.procedure_admission_id
BEGIN
  SELECT RAISE(
    ABORT,
    'reviewed candidate procedure activation admission is immutable'
  );
END;
`,
};

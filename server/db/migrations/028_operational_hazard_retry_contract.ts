import type { Migration } from "../types";

/**
 * Makes recovery authorization depend on an exact reviewed alternative and
 * typed, locally verified proof for every retry-valid condition. Nullable
 * columns preserve historical records, while insert triggers fail closed for
 * every assessment/authorization created after this migration.
 */
export const operationalHazardRetryContractMigration: Migration = {
  version: 28,
  name: "operational_hazard_retry_contract",
  sql: String.raw`
ALTER TABLE operational_hazard_profiles
  ADD COLUMN reviewed_retry_contract_json TEXT
    CHECK (
      reviewed_retry_contract_json IS NULL
      OR (json_valid(reviewed_retry_contract_json)
        AND json_type(reviewed_retry_contract_json) = 'object')
    );

INSERT INTO operational_hazard_local_evaluators (
  evaluator_version, evaluator_hash, algorithm, enabled, created_at
) VALUES (
  'operational-hazard-health/v2',
  'a5deb63c76404c368d0fd360cf7240786031399416329467e6daf9d10447af14',
  'Verified local baseline plus the exact complete boolean retry-condition proof set bound to the reviewed retry contract.',
  1,
  '2026-07-20T00:00:00.000Z'
);

ALTER TABLE operational_hazard_health_assessments
  ADD COLUMN retry_contract_hash TEXT
    CHECK (retry_contract_hash IS NULL OR length(retry_contract_hash) = 64);
ALTER TABLE operational_hazard_health_assessments
  ADD COLUMN reviewed_alternative_hash TEXT
    CHECK (reviewed_alternative_hash IS NULL OR length(reviewed_alternative_hash) = 64);
ALTER TABLE operational_hazard_health_assessments
  ADD COLUMN retry_condition_proofs_json TEXT
    CHECK (
      retry_condition_proofs_json IS NULL
      OR (json_valid(retry_condition_proofs_json)
        AND json_type(retry_condition_proofs_json) = 'array')
    );
ALTER TABLE operational_hazard_health_assessments
  ADD COLUMN retry_condition_proofs_hash TEXT
    CHECK (retry_condition_proofs_hash IS NULL OR length(retry_condition_proofs_hash) = 64);

ALTER TABLE operational_hazard_retry_authorizations
  ADD COLUMN health_assessment_hash TEXT
    CHECK (health_assessment_hash IS NULL OR length(health_assessment_hash) = 64);
ALTER TABLE operational_hazard_retry_authorizations
  ADD COLUMN retry_contract_hash TEXT
    CHECK (retry_contract_hash IS NULL OR length(retry_contract_hash) = 64);
ALTER TABLE operational_hazard_retry_authorizations
  ADD COLUMN reviewed_alternative_hash TEXT
    CHECK (reviewed_alternative_hash IS NULL OR length(reviewed_alternative_hash) = 64);
ALTER TABLE operational_hazard_retry_authorizations
  ADD COLUMN retry_condition_proofs_hash TEXT
    CHECK (retry_condition_proofs_hash IS NULL OR length(retry_condition_proofs_hash) = 64);

DROP TRIGGER operational_hazard_health_assessment_scope_insert;
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
    SELECT CASE
      WHEN json_extract(provenance_json, '$.healthAssessment.baselineRestored') = 1
        AND NOT EXISTS (
          SELECT 1 FROM json_each(provenance_json, '$.healthAssessment.retryConditionResults') result
          WHERE result.type <> 'true'
        )
      THEN 'pass' ELSE 'fail' END
    FROM evidence WHERE id = NEW.verified_evidence_id
      AND json_extract(provenance_json, '$.healthAssessment.schema') = 'ti_scale.operational_health/v2'
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

CREATE TRIGGER operational_hazard_health_assessment_retry_contract_insert
BEFORE INSERT ON operational_hazard_health_assessments
WHEN NEW.retry_contract_hash IS NULL
  OR NEW.reviewed_alternative_hash IS NULL
  OR NEW.retry_condition_proofs_json IS NULL
  OR NEW.retry_condition_proofs_hash IS NULL
  OR (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
      WHERE node_id = NEW.hazard_node_id) IS NULL
  OR json_array_length(NEW.retry_condition_proofs_json) = 0
  OR json_array_length(NEW.retry_condition_proofs_json) IS NOT json_array_length(
      (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
       WHERE node_id = NEW.hazard_node_id),
      '$.retryValidConditions'
    )
  OR EXISTS (
    SELECT 1
    FROM json_each(
      (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
       WHERE node_id = NEW.hazard_node_id),
      '$.retryValidConditions'
    ) condition
    WHERE 1 IS NOT (
      SELECT COUNT(*) FROM json_each(NEW.retry_condition_proofs_json) proof
      WHERE json_extract(proof.value, '$.conditionId') = json_extract(condition.value, '$.id')
        AND json_extract(proof.value, '$.evidenceKey') = json_extract(condition.value, '$.evidenceKey')
    )
  )
  OR EXISTS (
    SELECT 1 FROM json_each(NEW.retry_condition_proofs_json) proof
    WHERE json_extract(proof.value, '$.verifiedEvidenceId') IS NOT NEW.verified_evidence_id
      OR json_extract(proof.value, '$.verifiedEvidenceHash') IS NOT NEW.verified_evidence_hash
      OR json_extract(proof.value, '$.evaluatorVersion') IS NOT 'operational-hazard-health/v2'
      OR json_extract(proof.value, '$.evaluatorHash') IS NOT
        'a5deb63c76404c368d0fd360cf7240786031399416329467e6daf9d10447af14'
      OR json_type(proof.value, '$.satisfied') NOT IN ('true', 'false')
      OR NOT EXISTS (
        SELECT 1
        FROM json_each(
          (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
           WHERE node_id = NEW.hazard_node_id),
          '$.retryValidConditions'
        ) condition
        WHERE json_extract(condition.value, '$.id') = json_extract(proof.value, '$.conditionId')
          AND json_extract(condition.value, '$.evidenceKey') = json_extract(proof.value, '$.evidenceKey')
      )
  )
  OR (NEW.result = 'pass' AND EXISTS (
    SELECT 1 FROM json_each(NEW.retry_condition_proofs_json) proof
    WHERE json_type(proof.value, '$.satisfied') <> 'true'
  ))
BEGIN
  SELECT RAISE(ABORT, 'operational hazard retry conditions require complete local proof');
END;

CREATE TRIGGER operational_hazard_retry_authorization_contract_insert
BEFORE INSERT ON operational_hazard_retry_authorizations
WHEN NEW.health_assessment_hash IS NULL
  OR NEW.retry_contract_hash IS NULL
  OR NEW.reviewed_alternative_hash IS NULL
  OR NEW.retry_condition_proofs_hash IS NULL
  OR NEW.health_assessment_hash IS NOT (
    SELECT assessment_hash FROM operational_hazard_health_assessments
    WHERE id = NEW.health_assessment_id
  )
  OR NEW.retry_contract_hash IS NOT (
    SELECT retry_contract_hash FROM operational_hazard_health_assessments
    WHERE id = NEW.health_assessment_id
  )
  OR NEW.reviewed_alternative_hash IS NOT (
    SELECT reviewed_alternative_hash FROM operational_hazard_health_assessments
    WHERE id = NEW.health_assessment_id
  )
  OR NEW.retry_condition_proofs_hash IS NOT (
    SELECT retry_condition_proofs_hash FROM operational_hazard_health_assessments
    WHERE id = NEW.health_assessment_id
  )
  OR NEW.source_procedure_node_id IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id),
    '$.source.procedureNodeId'
  )
  OR NEW.source_procedure_version_node_id IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id),
    '$.source.procedureVersionNodeId'
  )
  OR NEW.authorized_procedure_node_id IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id),
    '$.alternative.procedureNodeId'
  )
  OR NEW.authorized_procedure_version_node_id IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id),
    '$.alternative.procedureVersionNodeId'
  )
  OR (SELECT normalized_parameters_json FROM attack_attempt_knowledge_contexts
      WHERE attack_attempt_id = NEW.source_attack_attempt_id) IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id),
    '$.source.normalizedParameters'
  )
  OR (SELECT normalized_parameters_json FROM attack_attempt_knowledge_contexts
      WHERE attack_attempt_id = NEW.authorized_attack_attempt_id) IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id),
    '$.alternative.normalizedParameters'
  )
  OR (SELECT load FROM attack_attempt_knowledge_contexts
      WHERE attack_attempt_id = NEW.source_attack_attempt_id) IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id), '$.source.load'
  )
  OR (SELECT concurrency FROM attack_attempt_knowledge_contexts
      WHERE attack_attempt_id = NEW.source_attack_attempt_id) IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id), '$.source.concurrency'
  )
  OR (SELECT timing_window_ms FROM attack_attempt_knowledge_contexts
      WHERE attack_attempt_id = NEW.source_attack_attempt_id) IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id), '$.source.timingWindowMs'
  )
  OR (SELECT load FROM attack_attempt_knowledge_contexts
      WHERE attack_attempt_id = NEW.authorized_attack_attempt_id) IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id), '$.alternative.load'
  )
  OR (SELECT concurrency FROM attack_attempt_knowledge_contexts
      WHERE attack_attempt_id = NEW.authorized_attack_attempt_id) IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id), '$.alternative.concurrency'
  )
  OR (SELECT timing_window_ms FROM attack_attempt_knowledge_contexts
      WHERE attack_attempt_id = NEW.authorized_attack_attempt_id) IS NOT json_extract(
    (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
     WHERE node_id = NEW.hazard_node_id), '$.alternative.timingWindowMs'
  )
  OR (
    json_extract(
      (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
       WHERE node_id = NEW.hazard_node_id), '$.alternativeKind'
    ) = 'explicit_alternative'
    AND NEW.authorization_basis <> 'explicit_alternative'
  )
  OR (
    json_extract(
      (SELECT reviewed_retry_contract_json FROM operational_hazard_profiles
       WHERE node_id = NEW.hazard_node_id), '$.alternativeKind'
    ) = 'structured_delta'
    AND NEW.authorization_basis = 'explicit_alternative'
  )
BEGIN
  SELECT RAISE(ABORT, 'operational hazard retry authorization contract mismatch');
END;
`,
};

import type { Migration } from "../types";

/**
 * Append-only private attribution for operational-hazard/reset observations.
 * Reusable candidates retain only keyed receipts produced by the compiler;
 * canonical mission, target, attempt, event, and evidence IDs stay here.
 */
export const operationalHazardObservationsMigration: Migration = {
  version: 24,
  name: "operational_hazard_observations",
  sql: String.raw`
CREATE TABLE operational_reset_authorizations (
  id TEXT PRIMARY KEY,
  authorization_key_hash TEXT NOT NULL UNIQUE CHECK (length(authorization_key_hash) = 64),
  authorization_hmac TEXT NOT NULL CHECK (length(authorization_hmac) = 64),
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  recovery_action_id TEXT NOT NULL UNIQUE REFERENCES actions(id) ON DELETE RESTRICT,
  target_asset_id TEXT REFERENCES topology_nodes(id) ON DELETE RESTRICT,
  target_service_id TEXT REFERENCES topology_nodes(id) ON DELETE RESTRICT,
  target_context_fingerprint TEXT NOT NULL CHECK (length(target_context_fingerprint) = 64),
  issued_by TEXT NOT NULL CHECK (issued_by = 'local-reset-controller'),
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (target_asset_id IS NOT NULL OR target_service_id IS NOT NULL)
) STRICT;

CREATE TABLE operational_reset_control_receipts (
  id TEXT PRIMARY KEY,
  receipt_key_hash TEXT NOT NULL UNIQUE CHECK (length(receipt_key_hash) = 64),
  receipt_hmac TEXT NOT NULL CHECK (length(receipt_hmac) = 64),
  authorization_id TEXT NOT NULL UNIQUE REFERENCES operational_reset_authorizations(id) ON DELETE RESTRICT,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  recovery_action_id TEXT NOT NULL UNIQUE REFERENCES actions(id) ON DELETE RESTRICT,
  target_asset_id TEXT REFERENCES topology_nodes(id) ON DELETE RESTRICT,
  target_service_id TEXT REFERENCES topology_nodes(id) ON DELETE RESTRICT,
  target_context_fingerprint TEXT NOT NULL CHECK (length(target_context_fingerprint) = 64),
  controller_id_hash TEXT NOT NULL CHECK (length(controller_id_hash) = 64),
  reset_operation_id_hash TEXT NOT NULL UNIQUE CHECK (length(reset_operation_id_hash) = 64),
  target_generation_id_hash TEXT NOT NULL CHECK (length(target_generation_id_hash) = 64),
  receipt_fingerprint TEXT NOT NULL CHECK (length(receipt_fingerprint) = 64),
  post_reset_health_evidence_id TEXT NOT NULL UNIQUE REFERENCES evidence(id) ON DELETE RESTRICT,
  issued_by TEXT NOT NULL CHECK (issued_by = 'local-reset-controller'),
  issued_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (target_context_fingerprint, target_generation_id_hash),
  CHECK (target_asset_id IS NOT NULL OR target_service_id IS NOT NULL)
) STRICT;

CREATE TABLE operational_hazard_occurrences (
  id TEXT PRIMARY KEY,
  occurrence_key_hash TEXT NOT NULL UNIQUE CHECK (length(occurrence_key_hash) = 64),
  request_key_hash TEXT NOT NULL UNIQUE CHECK (length(request_key_hash) = 64),
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  attack_attempt_id TEXT NOT NULL REFERENCES attack_attempts(id) ON DELETE RESTRICT,
  recovery_action_id TEXT NOT NULL UNIQUE REFERENCES actions(id) ON DELETE RESTRICT,
  recovery_event_id TEXT NOT NULL UNIQUE REFERENCES events(id) ON DELETE RESTRICT,
  target_asset_id TEXT REFERENCES topology_nodes(id) ON DELETE RESTRICT,
  target_service_id TEXT REFERENCES topology_nodes(id) ON DELETE RESTRICT,
  target_context_fingerprint TEXT NOT NULL CHECK (length(target_context_fingerprint) = 64),
  reset_control_receipt_id TEXT NOT NULL UNIQUE
    REFERENCES operational_reset_control_receipts(id) ON DELETE RESTRICT,
  reset_control_receipt_hash TEXT NOT NULL UNIQUE CHECK (length(reset_control_receipt_hash) = 64),
  evidence_ids_json TEXT NOT NULL
    CHECK (json_valid(evidence_ids_json) AND json_type(evidence_ids_json) = 'array'),
  bundle_id TEXT NOT NULL REFERENCES attack_knowledge_bundles(id) ON DELETE RESTRICT,
  provenance_receipt_id TEXT NOT NULL REFERENCES attack_knowledge_provenance_receipts(id) ON DELETE RESTRICT,
  knowledge_hash TEXT NOT NULL CHECK (length(knowledge_hash) = 64),
  exact_attempt_count INTEGER NOT NULL DEFAULT 1 CHECK (exact_attempt_count = 1),
  exact_reproducibility_count INTEGER NOT NULL DEFAULT 1 CHECK (exact_reproducibility_count = 1),
  exact_reset_count INTEGER NOT NULL DEFAULT 1 CHECK (exact_reset_count = 1),
  recorded_by TEXT NOT NULL CHECK (length(trim(recorded_by)) > 0),
  audit_record_id TEXT NOT NULL UNIQUE REFERENCES audit_records(id) ON DELETE RESTRICT,
  audit_record_hash TEXT NOT NULL CHECK (length(audit_record_hash) = 64),
  observed_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (target_asset_id IS NOT NULL OR target_service_id IS NOT NULL)
) STRICT;

CREATE TABLE operational_hazard_aggregate_reset_observations (
  id TEXT PRIMARY KEY,
  request_key_hash TEXT NOT NULL UNIQUE CHECK (length(request_key_hash) = 64),
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  reported_minimum INTEGER NOT NULL CHECK (reported_minimum >= 1),
  statement_event_id TEXT NOT NULL UNIQUE REFERENCES events(id) ON DELETE RESTRICT,
  recorded_by TEXT NOT NULL CHECK (length(trim(recorded_by)) > 0),
  audit_record_id TEXT NOT NULL UNIQUE REFERENCES audit_records(id) ON DELETE RESTRICT,
  audit_record_hash TEXT NOT NULL CHECK (length(audit_record_hash) = 64),
  reported_at TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE operational_hazard_observation_jobs (
  event_id TEXT PRIMARY KEY REFERENCES events(id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'processing', 'completed', 'quarantined')),
  occurrence_id TEXT REFERENCES operational_hazard_occurrences(id) ON DELETE RESTRICT,
  failure_category TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  available_at TEXT NOT NULL,
  lease_owner TEXT,
  lease_expires_at TEXT,
  claimed_at TEXT,
  completed_at TEXT,
  updated_at TEXT NOT NULL,
  CHECK (
    (status = 'processing' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND claimed_at IS NOT NULL)
    OR (status != 'processing' AND lease_owner IS NULL AND lease_expires_at IS NULL)
  )
) STRICT;

CREATE VIEW operational_hazard_reset_totals AS
SELECT
  scope.mission_id,
  scope.run_id,
  COALESCE(exact.exact_reset_count, 0) AS exact_attributable_reset_count,
  aggregate.operator_reported_reset_minimum,
  MAX(
    COALESCE(aggregate.operator_reported_reset_minimum, 0)
      - COALESCE(exact.exact_reset_count, 0),
    0
  ) AS minimum_unattributed_reset_count
FROM (
  SELECT mission_id, run_id FROM operational_hazard_occurrences
  UNION
  SELECT mission_id, run_id FROM operational_hazard_aggregate_reset_observations
) scope
LEFT JOIN (
  SELECT mission_id, run_id, COUNT(*) AS exact_reset_count
  FROM operational_hazard_occurrences GROUP BY mission_id, run_id
) exact ON exact.mission_id = scope.mission_id AND exact.run_id = scope.run_id
LEFT JOIN (
  SELECT mission_id, run_id, MAX(reported_minimum) AS operator_reported_reset_minimum
  FROM operational_hazard_aggregate_reset_observations GROUP BY mission_id, run_id
) aggregate ON aggregate.mission_id = scope.mission_id AND aggregate.run_id = scope.run_id;

CREATE INDEX idx_operational_hazard_occurrences_scope_time
  ON operational_hazard_occurrences(mission_id, run_id, observed_at DESC);
CREATE INDEX idx_operational_hazard_occurrences_bundle
  ON operational_hazard_occurrences(bundle_id, observed_at DESC);
CREATE INDEX idx_operational_hazard_aggregate_scope_time
  ON operational_hazard_aggregate_reset_observations(mission_id, run_id, reported_at DESC);
CREATE INDEX idx_operational_hazard_jobs_status_available
  ON operational_hazard_observation_jobs(status, available_at, event_id);

CREATE TRIGGER operational_reset_control_receipts_no_update
BEFORE UPDATE ON operational_reset_control_receipts BEGIN
  SELECT RAISE(ABORT, 'operational reset-control receipts are immutable');
END;
CREATE TRIGGER operational_reset_authorizations_no_update
BEFORE UPDATE ON operational_reset_authorizations BEGIN
  SELECT RAISE(ABORT, 'operational reset authorizations are immutable');
END;
CREATE TRIGGER operational_reset_authorizations_no_delete
BEFORE DELETE ON operational_reset_authorizations BEGIN
  SELECT RAISE(ABORT, 'operational reset authorizations are immutable');
END;

CREATE TRIGGER operational_reset_authorizations_scope_insert
BEFORE INSERT ON operational_reset_authorizations
WHEN NOT EXISTS (
  SELECT 1 FROM actions action
  WHERE action.id = NEW.recovery_action_id
    AND action.mission_id = NEW.mission_id
    AND action.run_id = NEW.run_id
    AND action.status = 'running'
    AND action.action_type IN ('target_reset', 'environment_reset')
    AND json_extract(action.normalized_arguments_json,
      '$.input.operationalHazardReset.schemaVersion') = 'ti_scale.operational_hazard_reset/v1'
)
BEGIN
  SELECT RAISE(ABORT, 'operational reset authorization scope mismatch');
END;
CREATE TRIGGER operational_reset_control_receipts_no_delete
BEFORE DELETE ON operational_reset_control_receipts BEGIN
  SELECT RAISE(ABORT, 'operational reset-control receipts are immutable');
END;

CREATE TRIGGER operational_reset_control_receipts_scope_insert
BEFORE INSERT ON operational_reset_control_receipts
WHEN NOT EXISTS (
  SELECT 1 FROM actions action
  JOIN operational_reset_authorizations authorization
    ON authorization.id = NEW.authorization_id
   AND authorization.recovery_action_id = action.id
  JOIN evidence post ON post.id = NEW.post_reset_health_evidence_id
  WHERE action.id = NEW.recovery_action_id
    AND action.mission_id = NEW.mission_id
    AND action.run_id = NEW.run_id
    AND action.status = 'succeeded'
    AND action.action_type IN ('target_reset', 'environment_reset')
    AND authorization.mission_id = NEW.mission_id
    AND authorization.run_id = NEW.run_id
    AND authorization.target_asset_id IS NEW.target_asset_id
    AND authorization.target_service_id IS NEW.target_service_id
    AND authorization.target_context_fingerprint = NEW.target_context_fingerprint
    AND authorization.expires_at >= NEW.issued_at
    AND post.mission_id = NEW.mission_id
    AND post.run_id = NEW.run_id
    AND post.action_id = NEW.recovery_action_id
    AND post.evidence_type = 'health_check_result'
    AND post.verification_state = 'verified'
    AND post.source = 'local-operational-reset-evaluator'
    AND post.created_by = 'local-operational-reset-evaluator'
    AND json_extract(post.provenance_json,
      '$.healthAssessment.schema') = 'ti_scale.operational_health/v1'
    AND json_extract(post.provenance_json,
      '$.healthAssessment.phase') = 'after_reset'
    AND json_extract(post.provenance_json,
      '$.healthAssessment.resetCompleted') IS 1
    AND json_extract(post.provenance_json,
      '$.healthAssessment.baselineRestored') IS 1
    AND json_extract(post.provenance_json,
      '$.healthAssessment.targetContextFingerprint') IS NEW.target_context_fingerprint
    AND json_extract(post.provenance_json,
      '$.healthAssessment.resetControlReceiptFingerprint') IS NEW.receipt_fingerprint
    AND EXISTS (SELECT 1 FROM evidence_chain_events custody
      WHERE custody.evidence_id = post.id AND custody.event_type = 'verified')
)
BEGIN
  SELECT RAISE(ABORT, 'operational reset-control receipt scope mismatch');
END;

CREATE TRIGGER operational_hazard_occurrences_no_update
BEFORE UPDATE ON operational_hazard_occurrences BEGIN
  SELECT RAISE(ABORT, 'operational hazard occurrences are immutable');
END;
CREATE TRIGGER operational_hazard_occurrences_no_delete
BEFORE DELETE ON operational_hazard_occurrences BEGIN
  SELECT RAISE(ABORT, 'operational hazard occurrences are immutable');
END;
CREATE TRIGGER operational_hazard_aggregate_no_update
BEFORE UPDATE ON operational_hazard_aggregate_reset_observations BEGIN
  SELECT RAISE(ABORT, 'operational hazard aggregate observations are immutable');
END;
CREATE TRIGGER operational_hazard_aggregate_no_delete
BEFORE DELETE ON operational_hazard_aggregate_reset_observations BEGIN
  SELECT RAISE(ABORT, 'operational hazard aggregate observations are immutable');
END;

CREATE TRIGGER operational_hazard_occurrence_scope_insert
BEFORE INSERT ON operational_hazard_occurrences
WHEN NOT EXISTS (
  SELECT 1 FROM attack_attempts attempt
  JOIN events recovery
    ON recovery.id = NEW.recovery_event_id
   AND recovery.mission_id = attempt.mission_id
   AND recovery.run_id = attempt.run_id
  JOIN runs run
    ON run.id = attempt.run_id
   AND run.mission_id = attempt.mission_id
  WHERE attempt.id = NEW.attack_attempt_id
    AND attempt.mission_id = NEW.mission_id
    AND attempt.run_id = NEW.run_id
    AND attempt.target_asset_id IS NEW.target_asset_id
    AND attempt.target_service_id IS NEW.target_service_id
    AND (attempt.target_asset_id IS NOT NULL OR attempt.target_service_id IS NOT NULL)
    AND attempt.status IN ('failed', 'safely_aborted', 'blocked', 'waiting_conditions')
    AND recovery.event_type = 'operational_hazard.reset_verified'
    AND json_extract(recovery.payload_json, '$.attackAttemptId') IS NEW.attack_attempt_id
    AND json_extract(recovery.payload_json, '$.recoveryActionId') IS NEW.recovery_action_id
    AND json_extract(recovery.payload_json, '$.targetContextFingerprint') IS NEW.target_context_fingerprint
    AND length(json_extract(recovery.payload_json, '$.resetControlReceiptFingerprint')) = 64
    AND json_extract(recovery.payload_json, '$.resetControlReceiptFingerprint')
      NOT GLOB '*[^0-9a-f]*'
    AND json_extract(recovery.payload_json, '$.resetControlReceiptId') IS NEW.reset_control_receipt_id
    AND json_extract(recovery.payload_json, '$.resetKind') = 'target_reset'
    AND json(json_extract(recovery.payload_json, '$.verifiedEvidenceIds')) = json(NEW.evidence_ids_json)
    AND EXISTS (
      SELECT 1 FROM operational_reset_control_receipts receipt
      WHERE receipt.id = NEW.reset_control_receipt_id
        AND receipt.receipt_key_hash = NEW.reset_control_receipt_hash
        AND receipt.mission_id = NEW.mission_id
        AND receipt.run_id = NEW.run_id
        AND receipt.recovery_action_id = NEW.recovery_action_id
        AND receipt.target_asset_id IS NEW.target_asset_id
        AND receipt.target_service_id IS NEW.target_service_id
        AND receipt.target_context_fingerprint = NEW.target_context_fingerprint
        AND receipt.receipt_fingerprint =
          json_extract(recovery.payload_json, '$.resetControlReceiptFingerprint')
    )
    AND EXISTS (
      SELECT 1 FROM actions recovery_action
      WHERE recovery_action.id = NEW.recovery_action_id
        AND recovery_action.mission_id = NEW.mission_id
        AND recovery_action.run_id = NEW.run_id
        AND recovery_action.status = 'succeeded'
        AND recovery_action.action_type IN ('target_reset', 'environment_reset')
        AND json_extract(recovery_action.normalized_arguments_json,
          '$.input.operationalHazardReset.schemaVersion') = 'ti_scale.operational_hazard_reset/v1'
        AND json_extract(recovery_action.normalized_arguments_json,
          '$.input.operationalHazardReset.attackAttemptId') IS NEW.attack_attempt_id
        AND json_extract(recovery_action.normalized_arguments_json,
          '$.input.operationalHazardReset.targetAssetId') IS NEW.target_asset_id
        AND json_extract(recovery_action.normalized_arguments_json,
          '$.input.operationalHazardReset.targetServiceId') IS NEW.target_service_id
        AND json_type(recovery_action.normalized_arguments_json,
          '$.input.operationalHazardReset.preResetHealthEvidenceId') = 'text'
        AND json_type(recovery_action.normalized_arguments_json,
          '$.input.operationalHazardReset.postResetHealthEvidenceId') = 'text'
        AND EXISTS (
          SELECT 1 FROM topology_nodes target
          WHERE target.id = COALESCE(NEW.target_service_id, NEW.target_asset_id)
            AND target.mission_id = NEW.mission_id
            AND recovery_action.scoped_target IN (target.primary_label, target.normalized_identity)
        )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'operational hazard occurrence scope mismatch');
END;

CREATE TRIGGER operational_hazard_occurrence_evidence_insert
BEFORE INSERT ON operational_hazard_occurrences
WHEN json_array_length(NEW.evidence_ids_json) < 1
  OR EXISTS (
    SELECT 1 FROM json_each(NEW.evidence_ids_json) item
    LEFT JOIN evidence proof ON proof.id = item.value
    WHERE proof.id IS NULL
      OR proof.mission_id IS NOT NEW.mission_id
      OR proof.run_id IS NOT NEW.run_id
      OR proof.action_id IS NOT NEW.recovery_action_id
      OR proof.evidence_type != 'target_reset_result'
      OR proof.verification_state != 'verified'
      OR proof.source != 'local-operational-reset-evaluator'
      OR proof.created_by != 'local-operational-reset-evaluator'
      OR json_extract(proof.provenance_json,
        '$.resetAssessment.schema') != 'ti_scale.operational_reset/v1'
      OR json_extract(proof.provenance_json,
        '$.resetAssessment.resetCompleted') IS NOT 1
      OR json_extract(proof.provenance_json,
        '$.resetAssessment.baselineRestored') IS NOT 1
      OR json_extract(proof.provenance_json,
        '$.resetAssessment.attackAttemptId') IS NOT NEW.attack_attempt_id
      OR json_extract(proof.provenance_json,
        '$.resetAssessment.recoveryActionId') IS NOT NEW.recovery_action_id
      OR json_extract(proof.provenance_json,
        '$.resetAssessment.targetContextFingerprint') IS NOT NEW.target_context_fingerprint
      OR json_extract(proof.provenance_json,
        '$.resetAssessment.resetControlReceiptFingerprint') IS NOT
        json_extract((SELECT payload_json FROM events WHERE id = NEW.recovery_event_id),
          '$.resetControlReceiptFingerprint')
      OR json_extract(proof.provenance_json,
        '$.resetAssessment.resetControlReceiptId') IS NOT NEW.reset_control_receipt_id
      OR json_extract(proof.provenance_json,
        '$.resetAssessment.preResetHealthEvidenceId') IS NOT (
          SELECT json_extract(action.normalized_arguments_json,
            '$.input.operationalHazardReset.preResetHealthEvidenceId')
          FROM actions action WHERE action.id = NEW.recovery_action_id
        )
      OR json_extract(proof.provenance_json,
        '$.resetAssessment.postResetHealthEvidenceId') IS NOT (
          SELECT json_extract(action.normalized_arguments_json,
            '$.input.operationalHazardReset.postResetHealthEvidenceId')
          FROM actions action WHERE action.id = NEW.recovery_action_id
        )
      OR NOT EXISTS (
        SELECT 1 FROM actions action
        JOIN evidence pre ON pre.id = json_extract(action.normalized_arguments_json,
          '$.input.operationalHazardReset.preResetHealthEvidenceId')
        JOIN evidence post ON post.id = json_extract(action.normalized_arguments_json,
          '$.input.operationalHazardReset.postResetHealthEvidenceId')
        WHERE action.id = NEW.recovery_action_id
          AND pre.mission_id IS NEW.mission_id AND pre.run_id IS NEW.run_id
          AND post.mission_id IS NEW.mission_id AND post.run_id IS NEW.run_id
          AND pre.action_id IS NEW.recovery_action_id
          AND post.action_id IS NEW.recovery_action_id
          AND pre.evidence_type = 'health_check_result'
          AND post.evidence_type = 'health_check_result'
          AND pre.verification_state = 'verified'
          AND post.verification_state = 'verified'
          AND pre.source = 'local-operational-reset-evaluator'
          AND post.source = 'local-operational-reset-evaluator'
          AND pre.created_by = 'local-operational-reset-evaluator'
          AND post.created_by = 'local-operational-reset-evaluator'
          AND json_extract(pre.provenance_json,
            '$.healthAssessment.schema') = 'ti_scale.operational_health/v1'
          AND json_extract(post.provenance_json,
            '$.healthAssessment.schema') = 'ti_scale.operational_health/v1'
          AND json_extract(pre.provenance_json,
            '$.healthAssessment.phase') = 'before_reset'
          AND json_extract(post.provenance_json,
            '$.healthAssessment.phase') = 'after_reset'
          AND json_extract(pre.provenance_json,
            '$.healthAssessment.baselineRestored') IS 0
          AND json_extract(post.provenance_json,
            '$.healthAssessment.baselineRestored') IS 1
          AND json_extract(post.provenance_json,
            '$.healthAssessment.resetCompleted') IS 1
          AND json_extract(post.provenance_json,
            '$.healthAssessment.resetControlReceipt.schema') = 'ti_scale.reset_control_receipt/v1'
          AND json_extract(post.provenance_json,
            '$.healthAssessment.resetControlReceipt.issuer') = 'local-reset-controller'
          AND json_type(post.provenance_json,
            '$.healthAssessment.resetControlReceipt.controllerId') = 'text'
          AND json_type(post.provenance_json,
            '$.healthAssessment.resetControlReceipt.resetOperationId') = 'text'
          AND json_type(post.provenance_json,
            '$.healthAssessment.resetControlReceipt.targetGenerationId') = 'text'
          AND length(json_extract(post.provenance_json,
            '$.healthAssessment.resetControlReceiptFingerprint')) = 64
          AND json_extract(post.provenance_json,
            '$.healthAssessment.resetControlReceiptFingerprint') =
            json_extract(proof.provenance_json,
              '$.resetAssessment.resetControlReceiptFingerprint')
          AND json_extract(pre.provenance_json,
            '$.healthAssessment.attackAttemptId') IS NEW.attack_attempt_id
          AND json_extract(post.provenance_json,
            '$.healthAssessment.attackAttemptId') IS NEW.attack_attempt_id
          AND json_extract(pre.provenance_json,
            '$.healthAssessment.recoveryActionId') IS NEW.recovery_action_id
          AND json_extract(post.provenance_json,
            '$.healthAssessment.recoveryActionId') IS NEW.recovery_action_id
          AND json_extract(pre.provenance_json,
            '$.healthAssessment.targetContextFingerprint') IS NEW.target_context_fingerprint
          AND json_extract(post.provenance_json,
            '$.healthAssessment.targetContextFingerprint') IS NEW.target_context_fingerprint
          AND EXISTS (SELECT 1 FROM evidence_chain_events c
            WHERE c.evidence_id = pre.id AND c.event_type = 'verified')
          AND EXISTS (SELECT 1 FROM evidence_chain_events c
            WHERE c.evidence_id = post.id AND c.event_type = 'verified')
      )
      OR NOT EXISTS (
        SELECT 1 FROM evidence_chain_events custody
        WHERE custody.evidence_id = proof.id AND custody.event_type = 'verified'
      )
  )
BEGIN
  SELECT RAISE(ABORT, 'operational hazard occurrence evidence mismatch');
END;

CREATE TRIGGER operational_hazard_occurrence_integrity_insert
BEFORE INSERT ON operational_hazard_occurrences
WHEN NEW.audit_record_hash IS NOT (
    SELECT record_hash FROM audit_records WHERE id = NEW.audit_record_id
  )
  OR NOT EXISTS (
    SELECT 1 FROM audit_records audit
    WHERE audit.id = NEW.audit_record_id
      AND audit.mission_id IS NEW.mission_id
      AND audit.run_id IS NEW.run_id
      AND audit.action = 'operational_hazard.reset_occurrence_staged'
      AND audit.resource_type = 'operational_hazard_occurrence'
      AND audit.resource_id IS NEW.id
      AND json_extract(audit.details_json, '$.recoveryEventId') IS NEW.recovery_event_id
      AND json_extract(audit.details_json, '$.recoveryActionId') IS NEW.recovery_action_id
      AND json_extract(audit.details_json, '$.attackAttemptId') IS NEW.attack_attempt_id
      AND json_extract(audit.details_json, '$.resetControlReceiptId') IS NEW.reset_control_receipt_id
      AND json_extract(audit.details_json, '$.resetControlReceiptHash') IS NEW.reset_control_receipt_hash
  )
  OR NEW.bundle_id IS NOT (
    SELECT bundle_id FROM attack_knowledge_compiler_runs
    WHERE receipt_id = NEW.provenance_receipt_id AND status = 'staged'
    ORDER BY completed_at DESC LIMIT 1
  )
BEGIN
  SELECT RAISE(ABORT, 'operational hazard occurrence integrity mismatch');
END;

CREATE TRIGGER operational_hazard_aggregate_scope_insert
BEFORE INSERT ON operational_hazard_aggregate_reset_observations
WHEN NOT EXISTS (
  SELECT 1 FROM events statement
  JOIN runs run ON run.id = statement.run_id AND run.mission_id = statement.mission_id
  WHERE statement.id = NEW.statement_event_id
    AND statement.mission_id = NEW.mission_id
    AND statement.run_id = NEW.run_id
    AND statement.event_type = 'operational_hazard.aggregate_reset_minimum_reported'
    AND statement.actor_type = 'operator'
    AND statement.actor_id IS NEW.recorded_by
    AND json_extract(statement.payload_json, '$.reportedMinimum') IS NEW.reported_minimum
    AND json_extract(statement.payload_json, '$.procedureAttribution') IS NULL
)
  OR NEW.audit_record_hash IS NOT (
    SELECT record_hash FROM audit_records WHERE id = NEW.audit_record_id
  )
  OR NOT EXISTS (
    SELECT 1 FROM audit_records audit
    WHERE audit.id = NEW.audit_record_id
      AND audit.mission_id IS NEW.mission_id
      AND audit.run_id IS NEW.run_id
      AND audit.actor_type = 'operator'
      AND audit.actor_id IS NEW.recorded_by
      AND audit.action = 'operational_hazard.aggregate_reset_minimum_reported'
      AND audit.resource_type = 'operational_hazard_aggregate_reset_observation'
      AND audit.resource_id IS NEW.id
      AND json_extract(audit.details_json, '$.reportedMinimum') IS NEW.reported_minimum
      AND json_extract(audit.details_json, '$.statementEventId') IS NEW.statement_event_id
      AND json_extract(audit.details_json, '$.procedureAttribution') IS NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'operational hazard aggregate observation integrity mismatch');
END;

CREATE TRIGGER operational_hazard_reset_event_enqueue
AFTER INSERT ON events
WHEN NEW.event_type = 'operational_hazard.reset_verified'
BEGIN
  INSERT INTO operational_hazard_observation_jobs (
    event_id, status, attempt_count, available_at, updated_at
  ) VALUES (NEW.id, 'pending', 0, NEW.occurred_at, NEW.created_at)
  ON CONFLICT(event_id) DO NOTHING;
END;
`,
};

import type { Migration } from "../types";

/**
 * Durable Research Lab promotion lifecycle.
 *
 * The existing Research Lab tables contain the immutable benchmark inputs and
 * experiment outputs. This migration adds the missing durable promotion
 * projection and append-only transition ledger. Rollback advances a separate
 * activation version that points at an already verified strategy; it never
 * copies a bundle or restores database/filesystem state. The activation
 * source_experiment_id is the experiment whose human decision created the
 * activation. For a forward rollback, its integrity receipt intentionally
 * belongs to the different target experiment that produced the selected
 * verified strategy.
 */
export const researchPromotionLifecycleMigration: Migration = {
  version: 50,
  name: "research_promotion_lifecycle",
  sql: String.raw`
ALTER TABLE integrity_receipts ADD COLUMN algorithm TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (algorithm IN ('legacy_unverified', 'hmac-sha256'));

ALTER TABLE integrity_receipts ADD COLUMN evaluator_version TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (length(trim(evaluator_version)) > 0);

ALTER TABLE integrity_receipts ADD COLUMN evaluation_stage TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (
    evaluation_stage IN (
      'legacy_unverified', 'development', 'validation',
      'hidden_holdout', 'shadow', 'canary'
    )
  );

ALTER TABLE integrity_receipts ADD COLUMN evaluation_action TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (
    evaluation_action IN (
      'legacy_unverified',
      'development_pass', 'development_fail',
      'validation_pass', 'validation_fail',
      'hidden_holdout_pass', 'hidden_holdout_fail',
      'shadow_pass', 'shadow_fail',
      'canary_pass', 'canary_fail'
    )
  );

ALTER TABLE integrity_receipts ADD COLUMN evaluation_result TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (evaluation_result IN ('legacy_unverified', 'pass', 'fail'));

ALTER TABLE integrity_receipts ADD COLUMN evaluation_attempt_id TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (length(trim(evaluation_attempt_id)) > 0);

ALTER TABLE integrity_receipts ADD COLUMN hard_gate_failures_json TEXT NOT NULL
  DEFAULT '[]'
  CHECK (
    json_valid(hard_gate_failures_json)
    AND json_type(hard_gate_failures_json) = 'array'
  );

ALTER TABLE benchmark_snapshots ADD COLUMN container_image_digest TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (
    container_image_digest = 'legacy_unverified'
    OR container_image_digest GLOB 'sha256:*'
  );

ALTER TABLE strategy_deployments ADD COLUMN isolation_mode TEXT NOT NULL
  DEFAULT 'no_live_effect'
  CHECK (isolation_mode IN ('no_live_effect', 'bounded_canary'));

ALTER TABLE strategy_deployments ADD COLUMN max_missions INTEGER
  CHECK (max_missions IS NULL OR max_missions BETWEEN 1 AND 10);

ALTER TABLE strategy_deployments ADD COLUMN max_wall_clock_ms INTEGER
  CHECK (
    max_wall_clock_ms IS NULL
    OR max_wall_clock_ms BETWEEN 60000 AND 86400000
  );

ALTER TABLE strategy_deployments ADD COLUMN lifecycle_version INTEGER NOT NULL
  DEFAULT 1
  CHECK (lifecycle_version > 0);

CREATE TABLE research_promotion_lifecycles (
  experiment_id TEXT PRIMARY KEY
    REFERENCES experiments(id) ON DELETE RESTRICT,
  campaign_id TEXT NOT NULL
    REFERENCES research_campaigns(id) ON DELETE RESTRICT,
  strategy_version_id TEXT NOT NULL UNIQUE
    REFERENCES strategy_versions(id) ON DELETE RESTRICT,
  promotion_record_json TEXT NOT NULL
    CHECK (json_valid(promotion_record_json)),
  record_hash TEXT NOT NULL
    CHECK (length(record_hash) = 64),
  version INTEGER NOT NULL CHECK (version > 0),
  created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
  updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0)
) STRICT;

CREATE TABLE research_promotion_transitions (
  id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL
    REFERENCES research_promotion_lifecycles(experiment_id)
    ON DELETE RESTRICT,
  strategy_version_id TEXT NOT NULL
    REFERENCES strategy_versions(id) ON DELETE RESTRICT,
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  lifecycle_version INTEGER NOT NULL CHECK (lifecycle_version > 0),
  from_state TEXT NOT NULL CHECK (
    from_state IN (
      'proposed', 'policy_rejected', 'queued', 'running',
      'early_aborted', 'failed', 'benchmarked', 'holdout_failed',
      'shadow_ready', 'shadow_running', 'canary_ready',
      'canary_running', 'verified', 'rejected', 'stale',
      'superseded', 'rolled_back'
    )
  ),
  to_state TEXT NOT NULL CHECK (
    to_state IN (
      'proposed', 'policy_rejected', 'queued', 'running',
      'early_aborted', 'failed', 'benchmarked', 'holdout_failed',
      'shadow_ready', 'shadow_running', 'canary_ready',
      'canary_running', 'verified', 'rejected', 'stale',
      'superseded', 'rolled_back'
    )
  ),
  action TEXT NOT NULL CHECK (
    action IN (
      'policy_accept', 'policy_reject', 'start_benchmark',
      'development_pass', 'development_fail',
      'validation_pass', 'validation_fail',
      'hidden_holdout_pass', 'hidden_holdout_fail',
      'approve_human_review', 'reject_human_review',
      'start_shadow', 'shadow_pass', 'shadow_fail',
      'approve_canary', 'start_canary',
      'canary_pass', 'canary_fail', 'verify',
      'reject', 'mark_stale', 'supersede', 'rollback'
    )
  ),
  actor_kind TEXT NOT NULL CHECK (
    actor_kind IN ('local_policy', 'local_evaluator', 'human_reviewer')
  ),
  actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) > 0),
  rationale TEXT NOT NULL CHECK (
    length(trim(rationale)) BETWEEN 3 AND 4000
  ),
  evidence_refs_json TEXT NOT NULL CHECK (
    json_valid(evidence_refs_json)
    AND json_type(evidence_refs_json) = 'array'
    AND json_array_length(evidence_refs_json) > 0
  ),
  hard_gate_failures_json TEXT NOT NULL DEFAULT '[]' CHECK (
    json_valid(hard_gate_failures_json)
    AND json_type(hard_gate_failures_json) = 'array'
  ),
  integrity_receipt_id TEXT
    REFERENCES integrity_receipts(id) ON DELETE RESTRICT,
  exposure_receipt_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (
    json_valid(exposure_receipt_ids_json)
    AND json_type(exposure_receipt_ids_json) = 'array'
  ),
  deployment_id TEXT
    REFERENCES strategy_deployments(id) ON DELETE RESTRICT,
  previous_record_hash TEXT NOT NULL
    CHECK (length(previous_record_hash) = 64),
  resulting_record_hash TEXT NOT NULL
    CHECK (length(resulting_record_hash) = 64),
  audit_record_id TEXT NOT NULL UNIQUE
    REFERENCES audit_records(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
  UNIQUE (experiment_id, sequence),
  UNIQUE (experiment_id, lifecycle_version)
) STRICT;

CREATE TABLE research_strategy_activation_versions (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL
    REFERENCES research_campaigns(id) ON DELETE RESTRICT,
  previous_activation_id TEXT
    REFERENCES research_strategy_activation_versions(id) ON DELETE RESTRICT,
  selected_strategy_version_id TEXT NOT NULL
    REFERENCES strategy_versions(id) ON DELETE RESTRICT,
  source_experiment_id TEXT NOT NULL
    REFERENCES experiments(id) ON DELETE RESTRICT,
  ordinal INTEGER NOT NULL CHECK (ordinal > 0),
  action TEXT NOT NULL CHECK (
    action IN ('verified_selection', 'forward_rollback')
  ),
  reason TEXT NOT NULL CHECK (
    length(trim(reason)) BETWEEN 3 AND 4000
  ),
  actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) > 0),
  integrity_receipt_id TEXT NOT NULL
    REFERENCES integrity_receipts(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
  UNIQUE (campaign_id, ordinal)
) STRICT;

ALTER TABLE strategy_rollbacks ADD COLUMN activation_version_id TEXT
  REFERENCES research_strategy_activation_versions(id) ON DELETE RESTRICT;

CREATE INDEX idx_research_promotion_campaign_time
  ON research_promotion_lifecycles(campaign_id, updated_at DESC);

CREATE INDEX idx_research_promotion_transition_time
  ON research_promotion_transitions(
    experiment_id,
    sequence DESC,
    created_at DESC
  );

CREATE INDEX idx_research_activation_campaign_ordinal
  ON research_strategy_activation_versions(campaign_id, ordinal DESC);

CREATE UNIQUE INDEX idx_research_evaluator_receipt_single_use
  ON research_promotion_transitions(integrity_receipt_id)
  WHERE action IN (
    'development_pass', 'development_fail',
    'validation_pass', 'validation_fail',
    'hidden_holdout_pass', 'hidden_holdout_fail',
    'shadow_pass', 'shadow_fail',
    'canary_pass', 'canary_fail'
  );

CREATE UNIQUE INDEX idx_research_evaluator_attempt_single_receipt
  ON integrity_receipts(experiment_id, evaluation_attempt_id)
  WHERE algorithm = 'hmac-sha256';

CREATE TRIGGER trg_research_activation_scope_chain_insert
BEFORE INSERT ON research_strategy_activation_versions
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM strategy_versions strategy
    WHERE strategy.id = NEW.selected_strategy_version_id
      AND strategy.campaign_id = NEW.campaign_id
      AND strategy.status = 'verified'
  )
  THEN RAISE(
    ABORT,
    'Research activation selected strategy is not verified in its campaign'
  ) END;

  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM experiments source
    WHERE source.id = NEW.source_experiment_id
      AND source.campaign_id = NEW.campaign_id
  )
  THEN RAISE(
    ABORT,
    'Research activation decision source is outside its campaign'
  ) END;

  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM integrity_receipts receipt
    JOIN experiments target
      ON target.id = receipt.experiment_id
    WHERE receipt.id = NEW.integrity_receipt_id
      AND receipt.algorithm = 'hmac-sha256'
      AND target.campaign_id = NEW.campaign_id
      AND target.candidate_strategy_id = NEW.selected_strategy_version_id
  )
  THEN RAISE(
    ABORT,
    'Research activation receipt does not bind its selected strategy'
  ) END;

  SELECT CASE WHEN (
    NEW.previous_activation_id IS NULL
    AND (
      NEW.ordinal <> 1
      OR EXISTS (
        SELECT 1
        FROM research_strategy_activation_versions existing
        WHERE existing.campaign_id = NEW.campaign_id
      )
    )
  ) OR (
    NEW.previous_activation_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1
      FROM research_strategy_activation_versions previous
      WHERE previous.id = NEW.previous_activation_id
        AND previous.campaign_id = NEW.campaign_id
        AND NEW.ordinal = previous.ordinal + 1
        AND previous.ordinal = (
          SELECT MAX(latest.ordinal)
          FROM research_strategy_activation_versions latest
          WHERE latest.campaign_id = NEW.campaign_id
        )
    )
  )
  THEN RAISE(
    ABORT,
    'Research activation previous pointer or ordinal is invalid'
  ) END;

  SELECT CASE WHEN (
    NEW.action = 'verified_selection'
    AND NOT EXISTS (
      SELECT 1
      FROM experiments source
      WHERE source.id = NEW.source_experiment_id
        AND source.candidate_strategy_id = NEW.selected_strategy_version_id
    )
  ) OR (
    NEW.action = 'forward_rollback'
    AND EXISTS (
      SELECT 1
      FROM experiments source
      WHERE source.id = NEW.source_experiment_id
        AND source.candidate_strategy_id = NEW.selected_strategy_version_id
    )
  )
  THEN RAISE(
    ABORT,
    'Research activation action does not match its decision source'
  ) END;
END;

CREATE TRIGGER trg_research_promotion_scope_insert
BEFORE INSERT ON research_promotion_lifecycles
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM experiments experiment
    WHERE experiment.id = NEW.experiment_id
      AND experiment.campaign_id = NEW.campaign_id
      AND experiment.candidate_strategy_id = NEW.strategy_version_id
  )
  THEN RAISE(
    ABORT,
    'Research promotion scope does not match its experiment candidate'
  ) END;
END;

CREATE TRIGGER trg_research_promotion_transition_scope_insert
BEFORE INSERT ON research_promotion_transitions
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM research_promotion_lifecycles lifecycle
    WHERE lifecycle.experiment_id = NEW.experiment_id
      AND lifecycle.strategy_version_id = NEW.strategy_version_id
      AND lifecycle.version + 1 = NEW.lifecycle_version
      AND lifecycle.record_hash = NEW.previous_record_hash
  )
  THEN RAISE(
    ABORT,
    'Research promotion transition is not based on the current lifecycle'
  ) END;

  SELECT CASE WHEN NEW.integrity_receipt_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM integrity_receipts receipt
    WHERE receipt.id = NEW.integrity_receipt_id
      AND receipt.experiment_id = NEW.experiment_id
      AND receipt.algorithm = 'hmac-sha256'
  )
  THEN RAISE(
    ABORT,
    'Research promotion integrity receipt is missing or unverified'
  ) END;

  SELECT CASE WHEN (
    NEW.action IN (
      'development_pass', 'development_fail',
      'validation_pass', 'validation_fail',
      'hidden_holdout_pass', 'hidden_holdout_fail',
      'shadow_pass', 'shadow_fail',
      'canary_pass', 'canary_fail'
    )
    AND NOT EXISTS (
      SELECT 1
      FROM integrity_receipts receipt
      WHERE receipt.id = NEW.integrity_receipt_id
        AND receipt.experiment_id = NEW.experiment_id
        AND receipt.algorithm = 'hmac-sha256'
        AND receipt.evaluation_action = NEW.action
        AND receipt.evaluation_stage = CASE
          WHEN NEW.action LIKE 'development_%' THEN 'development'
          WHEN NEW.action LIKE 'validation_%' THEN 'validation'
          WHEN NEW.action LIKE 'hidden_holdout_%' THEN 'hidden_holdout'
          WHEN NEW.action LIKE 'shadow_%' THEN 'shadow'
          WHEN NEW.action LIKE 'canary_%' THEN 'canary'
        END
        AND receipt.evaluation_result = CASE
          WHEN NEW.action LIKE '%_pass' THEN 'pass'
          ELSE 'fail'
        END
        AND receipt.hard_gate_failures_json = NEW.hard_gate_failures_json
        AND receipt.exposure_receipt_ids_json =
          NEW.exposure_receipt_ids_json
    )
  )
  THEN RAISE(
    ABORT,
    'Research evaluator transition receipt is missing or misbound'
  ) END;

  SELECT CASE WHEN (
    NEW.integrity_receipt_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1
      FROM integrity_receipts receipt
      WHERE receipt.id = NEW.integrity_receipt_id
        AND receipt.exposure_receipt_ids_json =
          NEW.exposure_receipt_ids_json
    )
  )
  THEN RAISE(
    ABORT,
    'Research promotion exposure list does not match its signed receipt'
  ) END;

  SELECT CASE WHEN NOT (
    (NEW.action = 'policy_accept'
      AND NEW.from_state = 'proposed' AND NEW.to_state = 'queued'
      AND NEW.actor_kind = 'local_policy')
    OR (NEW.action = 'policy_reject'
      AND NEW.from_state = 'proposed' AND NEW.to_state = 'policy_rejected'
      AND NEW.actor_kind = 'local_policy')
    OR (NEW.action = 'start_benchmark'
      AND NEW.from_state = 'queued' AND NEW.to_state = 'running'
      AND NEW.actor_kind = 'local_evaluator')
    OR (NEW.action = 'development_pass'
      AND NEW.from_state = 'running' AND NEW.to_state = 'running'
      AND NEW.actor_kind = 'local_evaluator')
    OR (NEW.action = 'development_fail'
      AND NEW.from_state = 'running' AND NEW.to_state = 'early_aborted'
      AND NEW.actor_kind = 'local_evaluator')
    OR (NEW.action = 'validation_pass'
      AND NEW.from_state = 'running' AND NEW.to_state = 'benchmarked'
      AND NEW.actor_kind = 'local_evaluator'
      AND json_extract((
        SELECT promotion_record_json
        FROM research_promotion_lifecycles
        WHERE experiment_id = NEW.experiment_id
      ), '$.milestones.developmentPassed') = 1)
    OR (NEW.action = 'validation_fail'
      AND NEW.from_state = 'running' AND NEW.to_state = 'failed'
      AND NEW.actor_kind = 'local_evaluator'
      AND json_extract((
        SELECT promotion_record_json
        FROM research_promotion_lifecycles
        WHERE experiment_id = NEW.experiment_id
      ), '$.milestones.developmentPassed') = 1)
    OR (NEW.action = 'hidden_holdout_pass'
      AND NEW.from_state = 'benchmarked' AND NEW.to_state = 'benchmarked'
      AND NEW.actor_kind = 'local_evaluator'
      AND json_extract((
        SELECT promotion_record_json
        FROM research_promotion_lifecycles
        WHERE experiment_id = NEW.experiment_id
      ), '$.milestones.validationPassed') = 1)
    OR (NEW.action = 'hidden_holdout_fail'
      AND NEW.from_state = 'benchmarked' AND NEW.to_state = 'holdout_failed'
      AND NEW.actor_kind = 'local_evaluator'
      AND json_extract((
        SELECT promotion_record_json
        FROM research_promotion_lifecycles
        WHERE experiment_id = NEW.experiment_id
      ), '$.milestones.validationPassed') = 1)
    OR (NEW.action = 'approve_human_review'
      AND NEW.from_state = 'benchmarked' AND NEW.to_state = 'shadow_ready'
      AND NEW.actor_kind = 'human_reviewer'
      AND json_extract((
        SELECT promotion_record_json
        FROM research_promotion_lifecycles
        WHERE experiment_id = NEW.experiment_id
      ), '$.milestones.hiddenHoldoutPassed') = 1)
    OR (NEW.action = 'reject_human_review'
      AND NEW.from_state = 'benchmarked' AND NEW.to_state = 'rejected'
      AND NEW.actor_kind = 'human_reviewer')
    OR (NEW.action = 'start_shadow'
      AND NEW.from_state = 'shadow_ready' AND NEW.to_state = 'shadow_running'
      AND NEW.actor_kind = 'human_reviewer')
    OR (NEW.action = 'shadow_pass'
      AND NEW.from_state = 'shadow_running' AND NEW.to_state = 'shadow_running'
      AND NEW.actor_kind = 'local_evaluator')
    OR (NEW.action = 'shadow_fail'
      AND NEW.from_state = 'shadow_running' AND NEW.to_state = 'rejected'
      AND NEW.actor_kind = 'local_evaluator')
    OR (NEW.action = 'approve_canary'
      AND NEW.from_state = 'shadow_running' AND NEW.to_state = 'canary_ready'
      AND NEW.actor_kind = 'human_reviewer'
      AND json_extract((
        SELECT promotion_record_json
        FROM research_promotion_lifecycles
        WHERE experiment_id = NEW.experiment_id
      ), '$.milestones.shadowPassed') = 1)
    OR (NEW.action = 'start_canary'
      AND NEW.from_state = 'canary_ready' AND NEW.to_state = 'canary_running'
      AND NEW.actor_kind = 'human_reviewer')
    OR (NEW.action = 'canary_pass'
      AND NEW.from_state = 'canary_running' AND NEW.to_state = 'canary_running'
      AND NEW.actor_kind = 'local_evaluator')
    OR (NEW.action = 'canary_fail'
      AND NEW.from_state = 'canary_running' AND NEW.to_state = 'rejected'
      AND NEW.actor_kind = 'local_evaluator')
    OR (NEW.action = 'verify'
      AND NEW.from_state = 'canary_running' AND NEW.to_state = 'verified'
      AND NEW.actor_kind = 'human_reviewer'
      AND json_extract((
        SELECT promotion_record_json
        FROM research_promotion_lifecycles
        WHERE experiment_id = NEW.experiment_id
      ), '$.milestones.canaryPassed') = 1)
    OR (NEW.action = 'reject'
      AND NEW.to_state = 'rejected'
      AND NEW.from_state IN (
        'proposed', 'queued', 'running', 'shadow_ready',
        'shadow_running', 'canary_ready', 'canary_running'
      )
      AND NEW.actor_kind = 'human_reviewer')
    OR (NEW.action = 'mark_stale'
      AND NEW.from_state = 'verified' AND NEW.to_state = 'stale'
      AND NEW.actor_kind = 'human_reviewer')
    OR (NEW.action = 'supersede'
      AND NEW.from_state = 'verified' AND NEW.to_state = 'superseded'
      AND NEW.actor_kind = 'human_reviewer')
    OR (NEW.action = 'rollback'
      AND NEW.from_state = 'verified' AND NEW.to_state = 'rolled_back'
      AND NEW.actor_kind = 'human_reviewer')
  )
  THEN RAISE(
    ABORT,
    'Research promotion action, state, or actor authority is invalid'
  ) END;

  SELECT CASE WHEN EXISTS (
    SELECT 1
    FROM json_each(NEW.exposure_receipt_ids_json) selected
    LEFT JOIN provider_exposure_receipts exposure
      ON exposure.id = selected.value
      AND exposure.experiment_id = NEW.experiment_id
      AND exposure.blocked = 0
      AND exposure.input_classification = 'sanitized_research_brief'
    WHERE exposure.id IS NULL
  )
  THEN RAISE(
    ABORT,
    'Research promotion exposure receipt is missing, blocked, or misbound'
  ) END;

  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM audit_records audit
    WHERE audit.id = NEW.audit_record_id
      AND audit.resource_type = 'research_promotion'
      AND audit.resource_id = NEW.experiment_id
  )
  THEN RAISE(
    ABORT,
    'Research promotion transition audit binding is invalid'
  ) END;
END;

CREATE TRIGGER trg_research_promotion_lifecycle_update_guard
BEFORE UPDATE ON research_promotion_lifecycles
BEGIN
  SELECT CASE WHEN
    NEW.experiment_id IS NOT OLD.experiment_id
    OR NEW.campaign_id IS NOT OLD.campaign_id
    OR NEW.strategy_version_id IS NOT OLD.strategy_version_id
    OR NEW.created_at IS NOT OLD.created_at
    OR NEW.version <> OLD.version + 1
    OR NOT json_valid(NEW.promotion_record_json)
    OR NEW.record_hash = OLD.record_hash
    OR NOT EXISTS (
      SELECT 1
      FROM research_promotion_transitions transition
      WHERE transition.experiment_id = OLD.experiment_id
        AND transition.lifecycle_version = NEW.version
        AND transition.previous_record_hash = OLD.record_hash
        AND transition.resulting_record_hash = NEW.record_hash
        AND transition.from_state =
          json_extract(OLD.promotion_record_json, '$.state')
        AND transition.to_state =
          json_extract(NEW.promotion_record_json, '$.state')
        AND transition.sequence =
          json_array_length(NEW.promotion_record_json, '$.history')
        AND json_extract(
          NEW.promotion_record_json,
          '$.history[#-1].sequence'
        ) = transition.sequence
        AND json_extract(
          NEW.promotion_record_json,
          '$.history[#-1].from'
        ) = transition.from_state
        AND json_extract(
          NEW.promotion_record_json,
          '$.history[#-1].to'
        ) = transition.to_state
        AND json_extract(
          NEW.promotion_record_json,
          '$.history[#-1].actorId'
        ) = transition.actor_id
        AND json_extract(
          NEW.promotion_record_json,
          '$.history[#-1].actorKind'
        ) = transition.actor_kind
    )
  THEN RAISE(
    ABORT,
    'Research promotion lifecycle update is not bound to its transition'
  ) END;
END;

CREATE TRIGGER trg_research_shadow_isolation_insert
BEFORE INSERT ON strategy_deployments
WHEN NEW.deployment_stage = 'shadow'
BEGIN
  SELECT CASE WHEN NEW.isolation_mode <> 'no_live_effect'
    OR NEW.max_missions IS NOT NULL
  THEN RAISE(
    ABORT,
    'Shadow evaluation must have no live execution effect'
  ) END;
END;

CREATE TRIGGER trg_research_canary_bounds_insert
BEFORE INSERT ON strategy_deployments
WHEN NEW.deployment_stage = 'canary'
BEGIN
  SELECT CASE WHEN NEW.isolation_mode <> 'bounded_canary'
    OR NEW.max_missions IS NULL
    OR NEW.max_wall_clock_ms IS NULL
  THEN RAISE(
    ABORT,
    'Canary evaluation requires explicit mission and time bounds'
  ) END;
END;

CREATE TRIGGER trg_research_verified_deployment_insert_denied
BEFORE INSERT ON strategy_deployments
WHEN NEW.deployment_stage = 'verified'
BEGIN
  SELECT RAISE(
    ABORT,
    'Research verification selects a strategy but cannot deploy it'
  );
END;

CREATE TRIGGER trg_research_deployment_boundary_update
BEFORE UPDATE ON strategy_deployments
WHEN
  OLD.strategy_version_id IS NOT NEW.strategy_version_id
  OR OLD.deployment_stage IS NOT NEW.deployment_stage
  OR OLD.scope_json IS NOT NEW.scope_json
  OR OLD.approved_by IS NOT NEW.approved_by
  OR OLD.started_at IS NOT NEW.started_at
  OR OLD.created_at IS NOT NEW.created_at
  OR OLD.isolation_mode IS NOT NEW.isolation_mode
  OR OLD.max_missions IS NOT NEW.max_missions
  OR OLD.max_wall_clock_ms IS NOT NEW.max_wall_clock_ms
  OR OLD.lifecycle_version IS NOT NEW.lifecycle_version
BEGIN
  SELECT RAISE(
    ABORT,
    'Research deployment scope, isolation, bounds, and provenance are immutable'
  );
END;

CREATE TRIGGER trg_research_deployment_immutable_delete
BEFORE DELETE ON strategy_deployments
BEGIN
  SELECT RAISE(ABORT, 'Research strategy deployments are immutable');
END;

CREATE TRIGGER trg_research_transition_immutable_update
BEFORE UPDATE ON research_promotion_transitions
BEGIN
  SELECT RAISE(ABORT, 'Research promotion transitions are immutable');
END;

CREATE TRIGGER trg_research_transition_immutable_delete
BEFORE DELETE ON research_promotion_transitions
BEGIN
  SELECT RAISE(ABORT, 'Research promotion transitions are immutable');
END;

CREATE TRIGGER trg_research_activation_immutable_update
BEFORE UPDATE ON research_strategy_activation_versions
BEGIN
  SELECT RAISE(ABORT, 'Research strategy activations are immutable');
END;

CREATE TRIGGER trg_research_activation_immutable_delete
BEFORE DELETE ON research_strategy_activation_versions
BEGIN
  SELECT RAISE(ABORT, 'Research strategy activations are immutable');
END;

CREATE TRIGGER trg_integrity_receipt_immutable_update
BEFORE UPDATE ON integrity_receipts
BEGIN
  SELECT RAISE(ABORT, 'Research integrity receipts are immutable');
END;

CREATE TRIGGER trg_integrity_receipt_immutable_delete
BEFORE DELETE ON integrity_receipts
BEGIN
  SELECT RAISE(ABORT, 'Research integrity receipts are immutable');
END;

CREATE TRIGGER trg_provider_exposure_receipt_immutable_update
BEFORE UPDATE ON provider_exposure_receipts
WHEN OLD.experiment_id IS NOT NULL OR NEW.experiment_id IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'Research provider exposure receipts are immutable');
END;

CREATE TRIGGER trg_provider_exposure_receipt_immutable_delete
BEFORE DELETE ON provider_exposure_receipts
WHEN OLD.experiment_id IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'Research provider exposure receipts are immutable');
END;

CREATE TRIGGER trg_promotion_review_immutable_update
BEFORE UPDATE ON promotion_reviews
BEGIN
  SELECT RAISE(ABORT, 'Research promotion reviews are immutable');
END;

CREATE TRIGGER trg_promotion_review_immutable_delete
BEFORE DELETE ON promotion_reviews
BEGIN
  SELECT RAISE(ABORT, 'Research promotion reviews are immutable');
END;

CREATE TRIGGER trg_strategy_rollback_immutable_update
BEFORE UPDATE ON strategy_rollbacks
BEGIN
  SELECT RAISE(ABORT, 'Research strategy rollbacks are immutable');
END;

CREATE TRIGGER trg_strategy_rollback_immutable_delete
BEFORE DELETE ON strategy_rollbacks
BEGIN
  SELECT RAISE(ABORT, 'Research strategy rollbacks are immutable');
END;
`,
};

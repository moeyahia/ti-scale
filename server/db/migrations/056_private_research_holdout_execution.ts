import type { Migration } from "../types";

/**
 * Adds the private hidden-holdout commitment boundary and extends the local
 * execution admission guards to validation and hidden-holdout stages.
 *
 * Only SHA-256 receipts and commitments are persisted. Operator-private
 * fixture identity, fixture input, and ground truth remain outside SQLite in
 * the trusted local descriptor registry.
 */
export const privateResearchHoldoutExecutionMigration: Migration = {
  version: 56,
  name: "private_research_holdout_execution",
  sql: String.raw`
CREATE TABLE private_research_holdout_bindings (
  benchmark_snapshot_id TEXT PRIMARY KEY
    REFERENCES benchmark_snapshots(id) ON DELETE RESTRICT,
  catalog_id TEXT NOT NULL CHECK (
    catalog_id IN (
      'repeated_no_progress_action_reduction',
      'specialist_routing_quality',
      'memory_retrieval_precision'
    )
  ),
  descriptor_version_hash TEXT NOT NULL
    CHECK (length(descriptor_version_hash) = 64),
  descriptor_source_sha256 TEXT NOT NULL
    CHECK (length(descriptor_source_sha256) = 64),
  descriptor_canonical_sha256 TEXT NOT NULL
    CHECK (length(descriptor_canonical_sha256) = 64),
  scenario_commitment TEXT NOT NULL
    CHECK (length(scenario_commitment) = 64),
  hidden_scenario_hash TEXT NOT NULL
    CHECK (length(hidden_scenario_hash) = 64),
  opaque_scenario_id_hash TEXT NOT NULL
    CHECK (length(opaque_scenario_id_hash) = 64),
  created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0)
) STRICT;

CREATE INDEX idx_private_research_holdout_commitment
  ON private_research_holdout_bindings(
    descriptor_canonical_sha256,
    catalog_id,
    scenario_commitment
  );

CREATE TRIGGER trg_private_research_holdout_binding_insert
BEFORE INSERT ON private_research_holdout_bindings
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM benchmark_snapshots snapshot
    JOIN benchmark_snapshot_scenarios membership
      ON membership.snapshot_id = snapshot.id
    JOIN benchmark_scenarios scenario
      ON scenario.id = membership.scenario_id
    WHERE snapshot.id = NEW.benchmark_snapshot_id
      AND snapshot.family_id =
        'builtin-research-family-' || NEW.catalog_id || '-v1'
      AND scenario.split = 'hidden_holdout'
      AND scenario.active = 1
      AND scenario.scenario_hash = NEW.hidden_scenario_hash
      AND scenario.ground_truth_ref =
        'private-holdout://commitment/' || NEW.scenario_commitment
  ) OR (
    SELECT COUNT(*)
    FROM benchmark_snapshot_scenarios membership
    JOIN benchmark_scenarios scenario
      ON scenario.id = membership.scenario_id
    WHERE membership.snapshot_id = NEW.benchmark_snapshot_id
      AND scenario.split = 'hidden_holdout'
  ) <> 1
  THEN RAISE(
    ABORT,
    'Private Research holdout binding does not match one committed hidden scenario'
  ) END;
END;

CREATE TRIGGER trg_private_research_holdout_binding_no_update
BEFORE UPDATE ON private_research_holdout_bindings
BEGIN
  SELECT RAISE(
    ABORT,
    'Private Research holdout bindings are immutable'
  );
END;

CREATE TRIGGER trg_private_research_holdout_binding_no_delete
BEFORE DELETE ON private_research_holdout_bindings
BEGIN
  SELECT RAISE(
    ABORT,
    'Private Research holdout bindings are immutable'
  );
END;

DROP TRIGGER trg_research_admission_exact_bindings_insert;

CREATE TRIGGER trg_research_admission_exact_bindings_insert
BEFORE INSERT ON research_experiment_admissions
WHEN NEW.execution_authorization_hash <> 'legacy_unverified'
BEGIN
  SELECT CASE WHEN
    NEW.status <> 'admitted'
    OR NEW.started_at IS NOT NULL
    OR NEW.ended_at IS NOT NULL
    OR NEW.terminal_result_hash IS NOT NULL
  THEN RAISE(
    ABORT,
    'Research admission must begin in the admitted state'
  ) END;

  SELECT CASE WHEN
    length(NEW.charter_hash) <> 64
    OR length(NEW.baseline_strategy_hash) <> 64
    OR length(NEW.candidate_strategy_hash) <> 64
    OR length(NEW.seed_hash) <> 64
    OR length(NEW.execution_authorization_hash) <> 64
    OR NEW.worker_process_id IS NULL
    OR NEW.worker_process_id < 1
    OR NEW.worker_process_start_ticks IS NULL
    OR length(trim(NEW.worker_process_start_ticks)) = 0
    OR json_extract(
      NEW.admission_payload_json,
      '$.executionAuthorizationHash'
    ) <> NEW.execution_authorization_hash
    OR json_extract(NEW.admission_payload_json, '$.candidateStrategyHash')
      <> NEW.candidate_strategy_hash
    OR json_extract(NEW.admission_payload_json, '$.seedHash')
      <> NEW.seed_hash
  THEN RAISE(
    ABORT,
    'Research admission payload is incomplete or differently hashed'
  ) END;

  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM experiment_runs run
    JOIN experiments experiment
      ON experiment.id = run.experiment_id
    JOIN research_campaigns campaign
      ON campaign.id = experiment.campaign_id
    JOIN research_charters charter
      ON charter.id = experiment.charter_id
    JOIN strategy_versions baseline
      ON baseline.id = experiment.baseline_strategy_id
    JOIN strategy_versions candidate
      ON candidate.id = experiment.candidate_strategy_id
    JOIN benchmark_snapshots snapshot
      ON snapshot.id = experiment.benchmark_snapshot_id
    JOIN benchmark_snapshot_scenarios membership
      ON membership.snapshot_id = snapshot.id
     AND membership.scenario_id = run.scenario_id
    JOIN benchmark_scenarios scenario
      ON scenario.id = membership.scenario_id
    JOIN research_promotion_lifecycles lifecycle
      ON lifecycle.experiment_id = experiment.id
     AND lifecycle.campaign_id = campaign.id
     AND lifecycle.strategy_version_id = candidate.id
    WHERE run.id = NEW.experiment_run_id
      AND run.experiment_id = NEW.experiment_id
      AND run.scenario_id = NEW.scenario_id
      AND run.status = 'queued'
      AND scenario.active = 1
      AND campaign.status IN ('approved', 'running')
      AND charter.id = NEW.charter_id
      AND charter.charter_hash = NEW.charter_hash
      AND charter.approved_by = campaign.owner
      AND baseline.id = NEW.baseline_strategy_id
      AND baseline.bundle_hash = NEW.baseline_strategy_hash
      AND baseline.campaign_id = campaign.id
      AND candidate.id = NEW.candidate_strategy_id
      AND candidate.bundle_hash = NEW.candidate_strategy_hash
      AND candidate.campaign_id = campaign.id
      AND snapshot.execution_environment_kind = 'local_bwrap'
      AND length(snapshot.execution_environment_identity_hash) = 64
      AND json_extract(NEW.admission_payload_json, '$.seed') = run.seed
      AND (
        (
          scenario.split = 'development'
          AND experiment.status = 'queued'
          AND json_extract(lifecycle.promotion_record_json, '$.state')
            = 'queued'
          AND json_extract(
            lifecycle.promotion_record_json,
            '$.milestones.developmentPassed'
          ) = 0
        )
        OR
        (
          scenario.split = 'validation'
          AND experiment.status = 'benchmarked'
          AND json_extract(lifecycle.promotion_record_json, '$.state')
            = 'running'
          AND json_extract(
            lifecycle.promotion_record_json,
            '$.milestones.developmentPassed'
          ) = 1
          AND json_extract(
            lifecycle.promotion_record_json,
            '$.milestones.validationPassed'
          ) = 0
        )
        OR
        (
          scenario.split = 'hidden_holdout'
          AND experiment.status = 'benchmarked'
          AND json_extract(lifecycle.promotion_record_json, '$.state')
            = 'benchmarked'
          AND json_extract(
            lifecycle.promotion_record_json,
            '$.milestones.validationPassed'
          ) = 1
          AND json_extract(
            lifecycle.promotion_record_json,
            '$.milestones.hiddenHoldoutPassed'
          ) = 0
          AND EXISTS (
            SELECT 1
            FROM private_research_holdout_bindings binding
            WHERE binding.benchmark_snapshot_id = snapshot.id
              AND binding.hidden_scenario_hash = scenario.scenario_hash
              AND scenario.ground_truth_ref =
                'private-holdout://commitment/'
                || binding.scenario_commitment
          )
        )
      )
  ) THEN RAISE(
    ABORT,
    'Research admission is outside its ordered charter, strategy, seed, or snapshot stage'
  ) END;
END;

DROP TRIGGER trg_research_run_insert_guard;

CREATE TRIGGER trg_research_run_insert_guard
BEFORE INSERT ON experiment_runs
BEGIN
  SELECT CASE WHEN
    NEW.status <> 'queued'
    OR NEW.worker_id <> 'pending'
    OR NEW.started_at IS NOT NULL
    OR NEW.ended_at IS NOT NULL
    OR NOT EXISTS (
      SELECT 1
      FROM experiments experiment
      JOIN benchmark_snapshot_scenarios membership
        ON membership.snapshot_id = experiment.benchmark_snapshot_id
      JOIN benchmark_scenarios scenario
        ON scenario.id = membership.scenario_id
      JOIN research_promotion_lifecycles lifecycle
        ON lifecycle.experiment_id = experiment.id
       AND lifecycle.strategy_version_id =
         experiment.candidate_strategy_id
      WHERE experiment.id = NEW.experiment_id
        AND membership.scenario_id = NEW.scenario_id
        AND scenario.active = 1
        AND (
          (
            scenario.split = 'development'
            AND experiment.status = 'queued'
            AND json_extract(lifecycle.promotion_record_json, '$.state')
              = 'queued'
            AND json_extract(
              lifecycle.promotion_record_json,
              '$.milestones.developmentPassed'
            ) = 0
          )
          OR
          (
            scenario.split = 'validation'
            AND experiment.status = 'benchmarked'
            AND json_extract(lifecycle.promotion_record_json, '$.state')
              = 'running'
            AND json_extract(
              lifecycle.promotion_record_json,
              '$.milestones.developmentPassed'
            ) = 1
            AND json_extract(
              lifecycle.promotion_record_json,
              '$.milestones.validationPassed'
            ) = 0
          )
          OR
          (
            scenario.split = 'hidden_holdout'
            AND experiment.status = 'benchmarked'
            AND json_extract(lifecycle.promotion_record_json, '$.state')
              = 'benchmarked'
            AND json_extract(
              lifecycle.promotion_record_json,
              '$.milestones.validationPassed'
            ) = 1
            AND json_extract(
              lifecycle.promotion_record_json,
              '$.milestones.hiddenHoldoutPassed'
            ) = 0
            AND EXISTS (
              SELECT 1
              FROM private_research_holdout_bindings binding
              WHERE binding.benchmark_snapshot_id =
                experiment.benchmark_snapshot_id
                AND binding.hidden_scenario_hash =
                  scenario.scenario_hash
                AND scenario.ground_truth_ref =
                  'private-holdout://commitment/'
                  || binding.scenario_commitment
            )
          )
        )
    )
  THEN RAISE(
    ABORT,
    'Research run must enter through the next ordered benchmark stage'
  ) END;
END;
`,
};

import type { Migration } from "../types";

/**
 * Binds every local Research execution to its human charter, exact strategy
 * pair, seed, candidate bytes, policy authorization, snapshot membership, and
 * truthful local-bwrap identity.
 *
 * This forward-only migration creates no database or filesystem backup,
 * snapshot copy, archive, or safety duplicate.
 */
export const researchExecutionIntegrityMigration: Migration = {
  version: 54,
  name: "research_execution_integrity",
  sql: String.raw`
ALTER TABLE benchmark_snapshots
  ADD COLUMN execution_environment_kind TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (
    execution_environment_kind IN (
      'legacy_unverified', 'local_bwrap', 'oci_container'
    )
  );

ALTER TABLE benchmark_snapshots
  ADD COLUMN execution_environment_identity_hash TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (
    execution_environment_identity_hash = 'legacy_unverified'
    OR length(execution_environment_identity_hash) = 64
  );

ALTER TABLE integrity_receipts
  ADD COLUMN execution_environment_kind TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (
    execution_environment_kind IN (
      'legacy_unverified', 'local_bwrap', 'oci_container'
    )
  );

ALTER TABLE integrity_receipts
  ADD COLUMN execution_environment_identity_hash TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (
    execution_environment_identity_hash = 'legacy_unverified'
    OR length(execution_environment_identity_hash) = 64
  );

CREATE TABLE benchmark_snapshot_scenarios (
  snapshot_id TEXT NOT NULL
    REFERENCES benchmark_snapshots(id) ON DELETE RESTRICT,
  scenario_id TEXT NOT NULL
    REFERENCES benchmark_scenarios(id) ON DELETE RESTRICT,
  ordinal INTEGER NOT NULL CHECK (ordinal > 0),
  PRIMARY KEY (snapshot_id, scenario_id),
  UNIQUE (snapshot_id, ordinal)
) STRICT;

ALTER TABLE research_experiment_admissions
  ADD COLUMN charter_id TEXT NOT NULL DEFAULT 'legacy_unverified';
ALTER TABLE research_experiment_admissions
  ADD COLUMN charter_hash TEXT NOT NULL DEFAULT 'legacy_unverified'
  CHECK (charter_hash = 'legacy_unverified' OR length(charter_hash) = 64);
ALTER TABLE research_experiment_admissions
  ADD COLUMN baseline_strategy_id TEXT NOT NULL DEFAULT 'legacy_unverified';
ALTER TABLE research_experiment_admissions
  ADD COLUMN baseline_strategy_hash TEXT NOT NULL DEFAULT 'legacy_unverified'
  CHECK (
    baseline_strategy_hash = 'legacy_unverified'
    OR length(baseline_strategy_hash) = 64
  );
ALTER TABLE research_experiment_admissions
  ADD COLUMN candidate_strategy_id TEXT NOT NULL DEFAULT 'legacy_unverified';
ALTER TABLE research_experiment_admissions
  ADD COLUMN candidate_strategy_hash TEXT NOT NULL DEFAULT 'legacy_unverified'
  CHECK (
    candidate_strategy_hash = 'legacy_unverified'
    OR length(candidate_strategy_hash) = 64
  );
ALTER TABLE research_experiment_admissions
  ADD COLUMN seed_hash TEXT NOT NULL DEFAULT 'legacy_unverified'
  CHECK (seed_hash = 'legacy_unverified' OR length(seed_hash) = 64);
ALTER TABLE research_experiment_admissions
  ADD COLUMN execution_authorization_hash TEXT NOT NULL
  DEFAULT 'legacy_unverified'
  CHECK (
    execution_authorization_hash = 'legacy_unverified'
    OR length(execution_authorization_hash) = 64
  );
ALTER TABLE research_experiment_admissions
  ADD COLUMN admission_payload_json TEXT NOT NULL DEFAULT '{}'
  CHECK (json_valid(admission_payload_json));
ALTER TABLE research_experiment_admissions
  ADD COLUMN worker_process_id INTEGER;
ALTER TABLE research_experiment_admissions
  ADD COLUMN worker_process_start_ticks TEXT;

CREATE INDEX idx_research_snapshot_scenario_split
  ON benchmark_snapshot_scenarios(snapshot_id, ordinal, scenario_id);

CREATE INDEX idx_research_admission_worker_process
  ON research_experiment_admissions(
    status, worker_process_id, worker_process_start_ticks
  );

CREATE TRIGGER trg_research_snapshot_scenario_bind_insert
BEFORE INSERT ON benchmark_snapshot_scenarios
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM benchmark_snapshots snapshot
    JOIN benchmark_scenarios scenario
      ON scenario.id = NEW.scenario_id
    WHERE snapshot.id = NEW.snapshot_id
      AND scenario.family_id = snapshot.family_id
      AND scenario.active = 1
  ) THEN RAISE(
    ABORT,
    'Research snapshot scenario is inactive or outside the benchmark family'
  ) END;
END;

CREATE TRIGGER trg_research_snapshot_no_update
BEFORE UPDATE ON benchmark_snapshots
BEGIN
  SELECT RAISE(ABORT, 'Research benchmark snapshots are immutable');
END;

CREATE TRIGGER trg_research_snapshot_no_delete
BEFORE DELETE ON benchmark_snapshots
BEGIN
  SELECT RAISE(ABORT, 'Research benchmark snapshots are immutable');
END;

CREATE TRIGGER trg_research_snapshot_scenario_no_update
BEFORE UPDATE ON benchmark_snapshot_scenarios
BEGIN
  SELECT RAISE(
    ABORT,
    'Research snapshot memberships are immutable'
  );
END;

CREATE TRIGGER trg_research_snapshot_scenario_no_delete
BEFORE DELETE ON benchmark_snapshot_scenarios
BEGIN
  SELECT RAISE(
    ABORT,
    'Research snapshot memberships are immutable'
  );
END;

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
    WHERE run.id = NEW.experiment_run_id
      AND run.experiment_id = NEW.experiment_id
      AND run.scenario_id = NEW.scenario_id
      AND run.status = 'queued'
      AND scenario.split = 'development'
      AND experiment.status = 'queued'
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
  ) THEN RAISE(
    ABORT,
    'Research admission is outside its charter, strategy, seed, or snapshot'
  ) END;
END;

CREATE TRIGGER trg_research_receipt_consumer_exact
BEFORE UPDATE OF consumed_at, consumed_by_run_id
ON research_execution_receipts
WHEN OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM research_experiment_admissions admission
    WHERE admission.experiment_run_id = NEW.consumed_by_run_id
      AND admission.experiment_id = NEW.experiment_id
      AND admission.scenario_id = NEW.scenario_id
      AND (
        (NEW.receipt_kind = 'lab'
          AND admission.lab_receipt_id = NEW.id)
        OR
        (NEW.receipt_kind = 'worker'
          AND admission.worker_receipt_id = NEW.id)
      )
  ) THEN RAISE(
    ABORT,
    'Research receipt consumer does not match its exact admission'
  ) END;
END;

CREATE TRIGGER trg_research_admission_transition
BEFORE UPDATE ON research_experiment_admissions
BEGIN
  SELECT CASE WHEN
    NEW.id <> OLD.id
    OR NEW.experiment_run_id <> OLD.experiment_run_id
    OR NEW.experiment_id <> OLD.experiment_id
    OR NEW.scenario_id <> OLD.scenario_id
    OR NEW.lab_receipt_id <> OLD.lab_receipt_id
    OR NEW.worker_receipt_id <> OLD.worker_receipt_id
    OR NEW.reset_generation <> OLD.reset_generation
    OR NEW.admission_hash <> OLD.admission_hash
    OR NEW.admission_signature <> OLD.admission_signature
    OR NEW.admitted_at <> OLD.admitted_at
    OR NEW.charter_id <> OLD.charter_id
    OR NEW.charter_hash <> OLD.charter_hash
    OR NEW.baseline_strategy_id <> OLD.baseline_strategy_id
    OR NEW.baseline_strategy_hash <> OLD.baseline_strategy_hash
    OR NEW.candidate_strategy_id <> OLD.candidate_strategy_id
    OR NEW.candidate_strategy_hash <> OLD.candidate_strategy_hash
    OR NEW.seed_hash <> OLD.seed_hash
    OR NEW.execution_authorization_hash
      <> OLD.execution_authorization_hash
    OR NEW.admission_payload_json <> OLD.admission_payload_json
    OR NEW.worker_process_id <> OLD.worker_process_id
    OR NEW.worker_process_start_ticks <> OLD.worker_process_start_ticks
    OR OLD.status IN ('completed', 'failed', 'cancelled')
    OR NOT (
      (OLD.status = 'admitted' AND NEW.status = 'running')
      OR
      (
        OLD.status = 'running'
        AND NEW.status IN ('completed', 'failed', 'cancelled')
      )
    )
  THEN RAISE(
    ABORT,
    'Research admission transition or immutable binding is invalid'
  ) END;

  SELECT CASE WHEN NEW.status = 'running' AND (
    NEW.started_at IS NULL
    OR NEW.ended_at IS NOT NULL
    OR NEW.terminal_result_hash IS NOT NULL
    OR NOT EXISTS (
      SELECT 1
      FROM research_execution_receipts lab
      JOIN research_execution_receipts worker
        ON worker.id = NEW.worker_receipt_id
      WHERE lab.id = NEW.lab_receipt_id
        AND lab.consumed_by_run_id = NEW.experiment_run_id
        AND worker.consumed_by_run_id = NEW.experiment_run_id
        AND lab.consumed_at IS NOT NULL
        AND worker.consumed_at IS NOT NULL
    )
  ) THEN RAISE(
    ABORT,
    'Research admission cannot run before both exact receipts are consumed'
  ) END;

  SELECT CASE WHEN NEW.status IN ('completed', 'failed', 'cancelled')
    AND (
      NEW.started_at IS NULL
      OR NEW.ended_at IS NULL
      OR NEW.ended_at < NEW.started_at
      OR NEW.terminal_result_hash IS NULL
      OR length(NEW.terminal_result_hash) <> 64
    )
  THEN RAISE(
    ABORT,
    'Research terminal admission requires ordered times and a result hash'
  ) END;
END;

CREATE TRIGGER trg_research_admission_no_delete
BEFORE DELETE ON research_experiment_admissions
BEGIN
  SELECT RAISE(
    ABORT,
    'Research admissions are immutable audit records'
  );
END;

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
      WHERE experiment.id = NEW.experiment_id
        AND experiment.status = 'queued'
        AND membership.scenario_id = NEW.scenario_id
        AND scenario.active = 1
        AND scenario.split = 'development'
    )
  THEN RAISE(
    ABORT,
    'Research run must enter through the queued development workflow'
  ) END;
END;

CREATE TRIGGER trg_research_run_transition_guard
BEFORE UPDATE ON experiment_runs
BEGIN
  SELECT CASE WHEN
    NEW.id <> OLD.id
    OR NEW.experiment_id <> OLD.experiment_id
    OR NEW.scenario_id <> OLD.scenario_id
    OR NEW.seed <> OLD.seed
    OR NEW.created_at <> OLD.created_at
    OR OLD.status IN ('completed', 'failed', 'cancelled', 'early_aborted')
    OR NOT (
      (
        OLD.status = 'queued'
        AND NEW.status IN ('running', 'cancelled', 'failed', 'early_aborted')
      )
      OR
      (
        OLD.status = 'running'
        AND NEW.status IN (
          'completed', 'failed', 'cancelled', 'early_aborted'
        )
      )
    )
  THEN RAISE(
    ABORT,
    'Research run transition or immutable binding is invalid'
  ) END;

  SELECT CASE WHEN NEW.status = 'running' AND (
    NEW.started_at IS NULL
    OR NEW.ended_at IS NOT NULL
    OR NOT EXISTS (
      SELECT 1
      FROM research_experiment_admissions admission
      WHERE admission.experiment_run_id = NEW.id
        AND admission.status = 'running'
    )
  ) THEN RAISE(
    ABORT,
    'Research run cannot start without its running signed admission'
  ) END;

  SELECT CASE WHEN OLD.status = 'running'
    AND NEW.status IN ('completed', 'failed', 'cancelled', 'early_aborted')
    AND (
      NEW.started_at IS NULL
      OR NEW.ended_at IS NULL
      OR NEW.ended_at < NEW.started_at
      OR NOT EXISTS (
        SELECT 1
        FROM research_experiment_admissions admission
        WHERE admission.experiment_run_id = NEW.id
          AND (
            admission.status = NEW.status
            OR (
              NEW.status = 'early_aborted'
              AND admission.status = 'failed'
            )
          )
      )
    )
  THEN RAISE(
    ABORT,
    'Research terminal run lacks its exact terminal admission'
  ) END;

  SELECT CASE WHEN OLD.status = 'queued'
    AND NEW.status IN ('cancelled', 'failed', 'early_aborted')
    AND (
      NEW.started_at IS NOT NULL
      OR NEW.ended_at IS NULL
    )
  THEN RAISE(
    ABORT,
    'Queued Research cancellation has invalid timing'
  ) END;
END;
`,
};

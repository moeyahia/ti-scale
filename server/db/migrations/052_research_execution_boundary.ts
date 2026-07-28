import type { Migration } from "../types";

/**
 * Durable one-use admission ledger for local synthetic Research execution.
 * This migration is forward-only and creates no database/filesystem backup,
 * snapshot, copy, or archive.
 */
export const researchExecutionBoundaryMigration: Migration = {
  version: 52,
  name: "research_execution_boundary",
  sql: String.raw`
CREATE TABLE research_execution_receipts (
  id TEXT PRIMARY KEY,
  receipt_kind TEXT NOT NULL CHECK (receipt_kind IN ('lab', 'worker')),
  experiment_id TEXT NOT NULL
    REFERENCES experiments(id) ON DELETE RESTRICT,
  scenario_id TEXT NOT NULL
    REFERENCES benchmark_scenarios(id) ON DELETE RESTRICT,
  boot_id TEXT NOT NULL CHECK (length(trim(boot_id)) > 0),
  key_id TEXT NOT NULL CHECK (length(key_id) = 64),
  benchmark_snapshot_hash TEXT NOT NULL
    CHECK (length(benchmark_snapshot_hash) = 64),
  evaluator_hash TEXT NOT NULL CHECK (length(evaluator_hash) = 64),
  tool_manifest_hash TEXT NOT NULL CHECK (length(tool_manifest_hash) = 64),
  reset_generation TEXT NOT NULL CHECK (length(reset_generation) = 64),
  challenge_hash TEXT NOT NULL CHECK (length(challenge_hash) = 64),
  subject_identity_hash TEXT NOT NULL
    CHECK (length(subject_identity_hash) = 64),
  evidence_hash TEXT NOT NULL CHECK (length(evidence_hash) = 64),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  algorithm TEXT NOT NULL CHECK (algorithm = 'hmac-sha256'),
  signature TEXT NOT NULL CHECK (length(signature) = 64),
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  consumed_by_run_id TEXT
    REFERENCES experiment_runs(id) ON DELETE RESTRICT,
  CHECK (
    (consumed_at IS NULL AND consumed_by_run_id IS NULL)
    OR (consumed_at IS NOT NULL AND consumed_by_run_id IS NOT NULL)
  ),
  UNIQUE (receipt_kind, challenge_hash),
  UNIQUE (receipt_kind, signature)
) STRICT;

CREATE TABLE research_experiment_admissions (
  id TEXT PRIMARY KEY,
  experiment_run_id TEXT NOT NULL UNIQUE
    REFERENCES experiment_runs(id) ON DELETE RESTRICT,
  experiment_id TEXT NOT NULL
    REFERENCES experiments(id) ON DELETE RESTRICT,
  scenario_id TEXT NOT NULL
    REFERENCES benchmark_scenarios(id) ON DELETE RESTRICT,
  lab_receipt_id TEXT NOT NULL UNIQUE
    REFERENCES research_execution_receipts(id) ON DELETE RESTRICT,
  worker_receipt_id TEXT NOT NULL UNIQUE
    REFERENCES research_execution_receipts(id) ON DELETE RESTRICT,
  reset_generation TEXT NOT NULL CHECK (length(reset_generation) = 64),
  admission_hash TEXT NOT NULL UNIQUE CHECK (length(admission_hash) = 64),
  admission_signature TEXT NOT NULL CHECK (length(admission_signature) = 64),
  status TEXT NOT NULL CHECK (
    status IN ('admitted', 'running', 'completed', 'failed', 'cancelled')
  ),
  admitted_at TEXT NOT NULL,
  started_at TEXT,
  ended_at TEXT,
  terminal_result_hash TEXT CHECK (
    terminal_result_hash IS NULL OR length(terminal_result_hash) = 64
  )
) STRICT;

CREATE INDEX idx_research_execution_receipt_expiry
  ON research_execution_receipts(
    receipt_kind,
    expires_at,
    consumed_at
  );

CREATE INDEX idx_research_admission_experiment_status
  ON research_experiment_admissions(
    experiment_id,
    status,
    admitted_at DESC
  );

CREATE TRIGGER trg_research_execution_receipt_consume_once
BEFORE UPDATE ON research_execution_receipts
BEGIN
  SELECT CASE WHEN
    OLD.consumed_at IS NOT NULL
    OR NEW.id <> OLD.id
    OR NEW.receipt_kind <> OLD.receipt_kind
    OR NEW.experiment_id <> OLD.experiment_id
    OR NEW.scenario_id <> OLD.scenario_id
    OR NEW.boot_id <> OLD.boot_id
    OR NEW.key_id <> OLD.key_id
    OR NEW.benchmark_snapshot_hash <> OLD.benchmark_snapshot_hash
    OR NEW.evaluator_hash <> OLD.evaluator_hash
    OR NEW.tool_manifest_hash <> OLD.tool_manifest_hash
    OR NEW.reset_generation <> OLD.reset_generation
    OR NEW.challenge_hash <> OLD.challenge_hash
    OR NEW.subject_identity_hash <> OLD.subject_identity_hash
    OR NEW.evidence_hash <> OLD.evidence_hash
    OR NEW.payload_json <> OLD.payload_json
    OR NEW.algorithm <> OLD.algorithm
    OR NEW.signature <> OLD.signature
    OR NEW.issued_at <> OLD.issued_at
    OR NEW.expires_at <> OLD.expires_at
    OR NEW.consumed_at IS NULL
    OR NEW.consumed_by_run_id IS NULL
  THEN RAISE(ABORT, 'Research execution receipt is immutable or already consumed')
  END;
END;

CREATE TRIGGER trg_research_execution_receipt_no_delete
BEFORE DELETE ON research_execution_receipts
BEGIN
  SELECT RAISE(ABORT, 'Research execution receipts are immutable audit records');
END;

CREATE TRIGGER trg_research_admission_bindings_insert
BEFORE INSERT ON research_experiment_admissions
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM experiment_runs run
    WHERE run.id = NEW.experiment_run_id
      AND run.experiment_id = NEW.experiment_id
      AND run.scenario_id = NEW.scenario_id
      AND run.status = 'queued'
  ) THEN RAISE(
    ABORT,
    'Research admission does not bind one queued experiment run'
  ) END;

  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM research_execution_receipts lab
    JOIN research_execution_receipts worker
      ON worker.id = NEW.worker_receipt_id
    WHERE lab.id = NEW.lab_receipt_id
      AND lab.receipt_kind = 'lab'
      AND worker.receipt_kind = 'worker'
      AND lab.experiment_id = NEW.experiment_id
      AND worker.experiment_id = NEW.experiment_id
      AND lab.scenario_id = NEW.scenario_id
      AND worker.scenario_id = NEW.scenario_id
      AND lab.reset_generation = NEW.reset_generation
      AND worker.reset_generation = NEW.reset_generation
      AND lab.benchmark_snapshot_hash = worker.benchmark_snapshot_hash
      AND lab.evaluator_hash = worker.evaluator_hash
      AND lab.tool_manifest_hash = worker.tool_manifest_hash
      AND lab.boot_id = worker.boot_id
      AND lab.consumed_at IS NULL
      AND worker.consumed_at IS NULL
  ) THEN RAISE(
    ABORT,
    'Research admission receipts are missing, swapped, stale, or differently bound'
  ) END;
END;
`,
};

import type { Migration } from "../types";

/**
 * Persist terminal Brain/Vault projection as an independently replayable
 * post-commit continuation. SQLite CHECK constraints cannot be widened in
 * place, so the V2-only queue is rebuilt while preserving every owner fence,
 * eligibility timestamp, attempt counter, and uniqueness key.
 */
export const terminalMemoryProjectionContinuationMigration: Migration = {
  version: 17,
  name: "terminal_memory_projection_continuation",
  sql: `
DROP INDEX idx_runtime_continuations_ready;
DROP INDEX idx_runtime_continuations_run_status;

ALTER TABLE runtime_continuations RENAME TO runtime_continuations_v16;

CREATE TABLE runtime_continuations (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN (
    'plan_ready_to_dispatch',
    'planning_retry_to_dispatch',
    'autonomous_retry_to_dispatch',
    'guided_approval_to_dispatch',
    'action_result_to_advance',
    'guided_failure_to_recover',
    'evaluation_pending',
    'memory_projection_pending',
    'cancellation_finalize_pending',
    'resume_recovery_pending'
  )),
  source_id TEXT NOT NULL CHECK (length(trim(source_id)) > 0),
  payload_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload_json)),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'processing', 'completed', 'cancelled')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  available_at TEXT NOT NULL,
  lease_owner TEXT,
  lease_expires_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  UNIQUE (run_id, kind, source_id),
  CHECK (
    (status = 'processing' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR
    (status <> 'processing' AND lease_owner IS NULL AND lease_expires_at IS NULL)
  ),
  CHECK ((status = 'completed' AND completed_at IS NOT NULL) OR status <> 'completed')
) STRICT;

INSERT INTO runtime_continuations (
  id, run_id, kind, source_id, payload_json, status, attempt_count,
  available_at, lease_owner, lease_expires_at, last_error, created_at,
  updated_at, completed_at
)
SELECT
  id, run_id, kind, source_id, payload_json, status, attempt_count,
  available_at, lease_owner, lease_expires_at, last_error, created_at,
  updated_at, completed_at
FROM runtime_continuations_v16;

DROP TABLE runtime_continuations_v16;

CREATE INDEX idx_runtime_continuations_ready
  ON runtime_continuations(status, available_at, lease_expires_at, created_at);

CREATE INDEX idx_runtime_continuations_run_status
  ON runtime_continuations(run_id, status, created_at);
`,
};

import type { Migration } from "../types";

/**
 * Durable, restart-safe choreography for an operator amendment that intersects
 * represented work. This is canonical runtime state, not a database snapshot:
 * it records the exact work boundary, the operator's one selected resolution,
 * and the fresh proposal produced after that boundary settles.
 */
export const planChangeInflightResolutionMigration: Migration = {
  version: 51,
  name: "plan_change_inflight_resolution",
  sql: String.raw`
CREATE TABLE plan_change_inflight_resolutions (
  id TEXT PRIMARY KEY,
  plan_change_request_id TEXT NOT NULL UNIQUE
    REFERENCES plan_change_requests(id) ON DELETE RESTRICT,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  base_plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
  mode TEXT NOT NULL CHECK (
    mode IN (
      'checkpoint_finish_idempotent_work',
      'checkpoint_cancel_affected_work'
    )
  ),
  status TEXT NOT NULL CHECK (
    status IN (
      'waiting_for_terminal_work',
      'ready_for_review',
      'failed'
    )
  ),
  affected_step_ids_json TEXT NOT NULL CHECK (
    json_valid(affected_step_ids_json)
    AND json_type(affected_step_ids_json) = 'array'
  ),
  affected_assignment_ids_json TEXT NOT NULL CHECK (
    json_valid(affected_assignment_ids_json)
    AND json_type(affected_assignment_ids_json) = 'array'
  ),
  affected_action_ids_json TEXT NOT NULL CHECK (
    json_valid(affected_action_ids_json)
    AND json_type(affected_action_ids_json) = 'array'
  ),
  affected_attack_attempt_ids_json TEXT NOT NULL CHECK (
    json_valid(affected_attack_attempt_ids_json)
    AND json_type(affected_attack_attempt_ids_json) = 'array'
  ),
  affected_decision_ids_json TEXT NOT NULL CHECK (
    json_valid(affected_decision_ids_json)
    AND json_type(affected_decision_ids_json) = 'array'
  ),
  source_checkpoint_id TEXT NOT NULL
    REFERENCES checkpoints(id) ON DELETE RESTRICT,
  source_checkpoint_state_hash TEXT NOT NULL
    CHECK (length(source_checkpoint_state_hash) = 64),
  source_checkpoint_event_sequence INTEGER NOT NULL
    CHECK (source_checkpoint_event_sequence >= 0),
  fresh_request_id TEXT
    REFERENCES plan_change_requests(id) ON DELETE RESTRICT,
  requested_by TEXT NOT NULL CHECK (length(trim(requested_by)) > 0),
  reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 3 AND 2000),
  settle_deadline_at TEXT NOT NULL,
  last_heartbeat_at TEXT NOT NULL,
  failure_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  resolved_at TEXT,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0)
) STRICT;

CREATE INDEX idx_plan_change_resolution_run_status
  ON plan_change_inflight_resolutions(run_id, status, updated_at DESC);

CREATE INDEX idx_plan_change_resolution_settle_deadline
  ON plan_change_inflight_resolutions(status, settle_deadline_at)
  WHERE status = 'waiting_for_terminal_work';

CREATE INDEX idx_plan_change_resolution_fresh_request
  ON plan_change_inflight_resolutions(fresh_request_id)
  WHERE fresh_request_id IS NOT NULL;
`,
};

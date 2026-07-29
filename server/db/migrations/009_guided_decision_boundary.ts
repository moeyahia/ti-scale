import type { Migration } from "../types";

/**
 * A Guided run can expose exactly one pending represented decision. Legacy
 * duplicates are ambiguous authority, so migration cancels every duplicate
 * decision and blocks the affected nonterminal run instead of choosing one.
 */
export const guidedDecisionBoundaryMigration: Migration = {
  version: 9,
  name: "guided_decision_single_pending_boundary",
  sql: String.raw`
CREATE TEMP TABLE _guided_duplicate_pending_runs (
  run_id TEXT PRIMARY KEY
) STRICT;

INSERT INTO _guided_duplicate_pending_runs (run_id)
SELECT run_id
FROM guided_decisions
WHERE status = 'pending'
GROUP BY run_id
HAVING COUNT(*) > 1;

UPDATE assignments
SET status = 'blocked',
    lease_owner = NULL,
    lease_acquired_at = NULL,
    last_heartbeat_at = NULL,
    lease_expires_at = NULL,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE run_id IN (SELECT run_id FROM _guided_duplicate_pending_runs)
  AND status IN ('queued', 'active');

UPDATE plan_steps
SET status = 'blocked',
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id IN (
  SELECT step_id
  FROM guided_decisions
  WHERE status = 'pending'
    AND run_id IN (SELECT run_id FROM _guided_duplicate_pending_runs)
)
  AND status IN ('pending', 'ready', 'running', 'waiting_guided_decision', 'recovering');

UPDATE guided_decisions
SET status = 'cancelled',
    decision_actor = 'migration:guided-decision-boundary-v9',
    decision_reason = 'Cancelled fail-closed because this run had multiple pending Guided decisions',
    decided_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE status = 'pending'
  AND run_id IN (SELECT run_id FROM _guided_duplicate_pending_runs);

UPDATE runs
SET status = 'blocked',
    status_reason = 'Guided decision authority was ambiguous; legacy pending decisions were cancelled fail-closed',
    next_action_summary = 'Review the blocked checkpoint and create one new exact Guided decision',
    lease_owner = NULL,
    lease_acquired_at = NULL,
    lease_expires_at = NULL,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    version = version + 1
WHERE id IN (SELECT run_id FROM _guided_duplicate_pending_runs)
  AND status NOT IN ('completed', 'failed', 'cancelled');

DROP TABLE _guided_duplicate_pending_runs;

CREATE UNIQUE INDEX idx_guided_decisions_one_pending_per_run
  ON guided_decisions(run_id)
  WHERE status = 'pending';
`,
};

import type { Migration } from "../types";

/**
 * Planning advice and execution authority are distinct model-assignment
 * purposes. Existing rows remain execution assignments by default, while the
 * purpose-aware unique index permits one immutable planning pin and one
 * immutable execution pin for the same exact agent/scope.
 */
export const modelAssignmentPurposeMigration: Migration = {
  version: 57,
  name: "model_assignment_purpose",
  sql: String.raw`
ALTER TABLE agent_model_assignments ADD COLUMN assignment_purpose TEXT
  NOT NULL DEFAULT 'execution'
  CHECK (assignment_purpose IN ('execution', 'planning'));

DROP INDEX idx_agent_model_assignments_pinned_scope;

CREATE UNIQUE INDEX idx_agent_model_assignments_pinned_scope
  ON agent_model_assignments(
    assignment_purpose,
    agent_id,
    ifnull(mission_id, ''),
    ifnull(run_id, ''),
    ifnull(step_id, '')
  )
  WHERE pinned = 1;

CREATE INDEX idx_agent_model_assignments_run_purpose
  ON agent_model_assignments(run_id, assignment_purpose, agent_id, pinned);
`,
};

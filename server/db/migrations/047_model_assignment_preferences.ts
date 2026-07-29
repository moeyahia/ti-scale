import type { Migration } from "../types";

/**
 * Operator-managed model preferences are versioned independently from the
 * immutable model catalog and the resolved assignment receipts.
 *
 * A preference row is one immutable version for one exact resolution scope.
 * Appending a successor is an optimistic compare-and-swap: the caller must
 * name the current row and supply exactly current.version + 1. The insert
 * retires that predecessor in the same statement. Historical configuration
 * choices and the resolved agent_model_assignments remain untouched.
 */
export const modelAssignmentPreferencesMigration: Migration = {
  version: 47,
  name: "model_assignment_preferences",
  sql: String.raw`
CREATE TABLE model_assignment_preferences (
  id TEXT PRIMARY KEY,
  scope_type TEXT NOT NULL CHECK (
    scope_type IN ('global', 'agent', 'mission', 'run', 'step')
  ),
  scope_id TEXT NOT NULL CHECK (
    length(trim(scope_id)) BETWEEN 1 AND 200
  ),
  agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
  mission_id TEXT REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT REFERENCES runs(id) ON DELETE RESTRICT,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE RESTRICT,
  primary_configuration_id TEXT NOT NULL
    REFERENCES model_configurations(id) ON DELETE RESTRICT,
  fallback_configuration_id TEXT
    REFERENCES model_configurations(id) ON DELETE RESTRICT,
  version INTEGER NOT NULL CHECK (version > 0),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  is_current INTEGER NOT NULL DEFAULT 1 CHECK (is_current IN (0, 1)),
  supersedes_preference_id TEXT
    REFERENCES model_assignment_preferences(id) ON DELETE RESTRICT,
  resolution_reason TEXT NOT NULL CHECK (
    length(trim(resolution_reason)) > 0
  ),
  created_by TEXT NOT NULL CHECK (length(trim(created_by)) > 0),
  created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
  CHECK (
    fallback_configuration_id IS NULL
    OR fallback_configuration_id != primary_configuration_id
  ),
  CHECK (is_current = 1 OR active = 0),
  CHECK (
    (version = 1 AND supersedes_preference_id IS NULL)
    OR (version > 1 AND supersedes_preference_id IS NOT NULL)
  ),
  CHECK (
    (
      scope_type = 'global'
      AND scope_id = 'global'
      AND agent_id IS NULL
      AND mission_id IS NULL
      AND run_id IS NULL
      AND step_id IS NULL
    )
    OR (
      scope_type = 'agent'
      AND agent_id IS NOT NULL
      AND scope_id = agent_id
      AND mission_id IS NULL
      AND run_id IS NULL
      AND step_id IS NULL
    )
    OR (
      scope_type = 'mission'
      AND agent_id IS NOT NULL
      AND mission_id IS NOT NULL
      AND scope_id = mission_id
      AND run_id IS NULL
      AND step_id IS NULL
    )
    OR (
      scope_type = 'run'
      AND agent_id IS NOT NULL
      AND mission_id IS NOT NULL
      AND run_id IS NOT NULL
      AND scope_id = run_id
      AND step_id IS NULL
    )
    OR (
      scope_type = 'step'
      AND agent_id IS NOT NULL
      AND mission_id IS NOT NULL
      AND run_id IS NOT NULL
      AND step_id IS NOT NULL
      AND scope_id = step_id
    )
  )
) STRICT;

CREATE UNIQUE INDEX idx_model_assignment_preferences_scope_version
  ON model_assignment_preferences(
    scope_type,
    scope_id,
    ifnull(agent_id, ''),
    version
  );

CREATE UNIQUE INDEX idx_model_assignment_preferences_current_scope
  ON model_assignment_preferences(
    scope_type,
    scope_id,
    ifnull(agent_id, '')
  )
  WHERE is_current = 1;

CREATE INDEX idx_model_assignment_preferences_resolution
  ON model_assignment_preferences(
    agent_id,
    mission_id,
    run_id,
    step_id,
    active,
    is_current
  );

CREATE INDEX idx_model_assignment_preferences_history
  ON model_assignment_preferences(
    scope_type,
    scope_id,
    agent_id,
    version DESC
  );

CREATE INDEX idx_model_assignment_preferences_primary
  ON model_assignment_preferences(primary_configuration_id, is_current);

CREATE INDEX idx_model_assignment_preferences_fallback
  ON model_assignment_preferences(fallback_configuration_id, is_current)
  WHERE fallback_configuration_id IS NOT NULL;

CREATE TRIGGER trg_model_assignment_preference_lineage
BEFORE INSERT ON model_assignment_preferences
BEGIN
  SELECT CASE
    WHEN NEW.scope_type IN ('run', 'step') AND NOT EXISTS (
      SELECT 1
      FROM runs
      WHERE id = NEW.run_id
        AND mission_id = NEW.mission_id
    )
    THEN RAISE(
      ABORT,
      'model preference run does not belong to its mission'
    )
  END;

  SELECT CASE
    WHEN NEW.scope_type = 'step' AND NOT EXISTS (
      SELECT 1
      FROM plan_steps
      WHERE id = NEW.step_id
        AND run_id = NEW.run_id
    )
    THEN RAISE(
      ABORT,
      'model preference step does not belong to its run'
    )
  END;

  SELECT CASE
    WHEN NEW.version = 1 AND EXISTS (
      SELECT 1
      FROM model_assignment_preferences existing
      WHERE existing.scope_type = NEW.scope_type
        AND existing.scope_id = NEW.scope_id
        AND existing.agent_id IS NEW.agent_id
    )
    THEN RAISE(
      ABORT,
      'model preference scope already has version history'
    )
  END;

  SELECT CASE
    WHEN NEW.version > 1 AND NOT EXISTS (
      SELECT 1
      FROM model_assignment_preferences predecessor
      WHERE predecessor.id = NEW.supersedes_preference_id
        AND predecessor.scope_type = NEW.scope_type
        AND predecessor.scope_id = NEW.scope_id
        AND predecessor.agent_id IS NEW.agent_id
        AND predecessor.mission_id IS NEW.mission_id
        AND predecessor.run_id IS NEW.run_id
        AND predecessor.step_id IS NEW.step_id
        AND predecessor.version = NEW.version - 1
        AND predecessor.is_current = 1
    )
    THEN RAISE(
      ABORT,
      'model preference successor does not match current scope version'
    )
  END;

  UPDATE model_assignment_preferences
  SET active = 0, is_current = 0
  WHERE NEW.version > 1
    AND id = NEW.supersedes_preference_id;
END;

CREATE TRIGGER trg_model_assignment_preference_immutable_update
BEFORE UPDATE ON model_assignment_preferences
WHEN NOT (
  OLD.is_current = 1
  AND NEW.is_current = 0
  AND NEW.active = 0
  AND NEW.id IS OLD.id
  AND NEW.scope_type IS OLD.scope_type
  AND NEW.scope_id IS OLD.scope_id
  AND NEW.agent_id IS OLD.agent_id
  AND NEW.mission_id IS OLD.mission_id
  AND NEW.run_id IS OLD.run_id
  AND NEW.step_id IS OLD.step_id
  AND NEW.primary_configuration_id IS OLD.primary_configuration_id
  AND NEW.fallback_configuration_id IS OLD.fallback_configuration_id
  AND NEW.version IS OLD.version
  AND NEW.supersedes_preference_id IS OLD.supersedes_preference_id
  AND NEW.resolution_reason IS OLD.resolution_reason
  AND NEW.created_by IS OLD.created_by
  AND NEW.created_at IS OLD.created_at
)
BEGIN
  SELECT RAISE(
    ABORT,
    'model assignment preference versions are immutable'
  );
END;

CREATE TRIGGER trg_model_assignment_preference_immutable_delete
BEFORE DELETE ON model_assignment_preferences
BEGIN
  SELECT RAISE(
    ABORT,
    'model assignment preference history cannot be deleted'
  );
END;
`,
};

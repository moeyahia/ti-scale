import type { Migration } from "../types";

/**
 * Execution authority and specialist reasoning advice must never share one
 * mutable preference key. Existing preference history remains execution by
 * default; new planning-purpose rows describe advisor-only reasoning for a
 * specialist and can be resolved and pinned independently.
 */
export const specialistAdvisoryModelPreferencesMigration: Migration = {
  version: 61,
  name: "specialist_advisory_model_preferences",
  sql: String.raw`
ALTER TABLE model_assignment_preferences ADD COLUMN assignment_purpose TEXT
  NOT NULL DEFAULT 'execution'
  CHECK (assignment_purpose IN ('execution', 'planning'));

DROP INDEX idx_model_assignment_preferences_scope_version;
DROP INDEX idx_model_assignment_preferences_current_scope;
DROP INDEX idx_model_assignment_preferences_resolution;
DROP INDEX idx_model_assignment_preferences_history;

CREATE UNIQUE INDEX idx_model_assignment_preferences_scope_version
  ON model_assignment_preferences(
    assignment_purpose,
    scope_type,
    scope_id,
    ifnull(agent_id, ''),
    version
  );

CREATE UNIQUE INDEX idx_model_assignment_preferences_current_scope
  ON model_assignment_preferences(
    assignment_purpose,
    scope_type,
    scope_id,
    ifnull(agent_id, '')
  )
  WHERE is_current = 1;

CREATE INDEX idx_model_assignment_preferences_resolution
  ON model_assignment_preferences(
    assignment_purpose,
    agent_id,
    mission_id,
    run_id,
    step_id,
    active,
    is_current
  );

CREATE INDEX idx_model_assignment_preferences_history
  ON model_assignment_preferences(
    assignment_purpose,
    scope_type,
    scope_id,
    agent_id,
    version DESC
  );

DROP TRIGGER trg_model_assignment_preference_lineage;
DROP TRIGGER trg_model_assignment_preference_immutable_update;
DROP TRIGGER trg_model_assignment_preference_immutable_delete;

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
      WHERE existing.assignment_purpose = NEW.assignment_purpose
        AND existing.scope_type = NEW.scope_type
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
        AND predecessor.assignment_purpose = NEW.assignment_purpose
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
  AND NEW.assignment_purpose IS OLD.assignment_purpose
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

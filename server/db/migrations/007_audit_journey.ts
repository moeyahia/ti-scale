import type { Migration } from "../types";

export const auditJourneyMigration: Migration = {
  version: 7,
  name: "audit_report_checkpoint_journey_invariants",
  sql: String.raw`
ALTER TABLE artifacts
  ADD COLUMN journey TEXT CHECK (journey IS NULL OR journey IN ('autonomous', 'guided'));

UPDATE artifacts
SET journey = COALESCE(
  (SELECT r.journey FROM runs r WHERE r.id = artifacts.run_id),
  (SELECT m.journey FROM missions m WHERE m.id = artifacts.mission_id)
);

CREATE TRIGGER artifacts_require_journey
BEFORE INSERT ON artifacts
WHEN NEW.journey IS NULL
BEGIN
  SELECT RAISE(ABORT, 'artifacts require a journey');
END;

CREATE TRIGGER artifacts_match_mission_journey
BEFORE INSERT ON artifacts
WHEN NEW.journey IS NOT NULL AND NEW.journey IS NOT (
  SELECT m.journey FROM missions m WHERE m.id = NEW.mission_id
)
BEGIN
  SELECT RAISE(ABORT, 'artifact journey must match mission journey');
END;

CREATE TRIGGER artifacts_match_run_journey
BEFORE INSERT ON artifacts
WHEN NEW.run_id IS NOT NULL AND NEW.journey IS NOT NULL AND NEW.journey IS NOT (
  SELECT r.journey FROM runs r WHERE r.id = NEW.run_id
)
BEGIN
  SELECT RAISE(ABORT, 'artifact journey must match run journey');
END;

CREATE TRIGGER artifacts_preserve_journey
BEFORE UPDATE OF journey, mission_id, run_id ON artifacts
WHEN NEW.journey IS NULL
  OR NEW.journey IS NOT (SELECT m.journey FROM missions m WHERE m.id = NEW.mission_id)
  OR (NEW.run_id IS NOT NULL AND NEW.journey IS NOT (SELECT r.journey FROM runs r WHERE r.id = NEW.run_id))
BEGIN
  SELECT RAISE(ABORT, 'artifact journey must remain canonical');
END;

ALTER TABLE checkpoints
  ADD COLUMN journey TEXT CHECK (journey IS NULL OR journey IN ('autonomous', 'guided'));

UPDATE checkpoints
SET journey = (SELECT r.journey FROM runs r WHERE r.id = checkpoints.run_id);

CREATE TRIGGER checkpoints_require_journey
BEFORE INSERT ON checkpoints
WHEN NEW.journey IS NULL
BEGIN
  SELECT RAISE(ABORT, 'checkpoints require a journey');
END;

CREATE TRIGGER checkpoints_match_run_journey
BEFORE INSERT ON checkpoints
WHEN NEW.journey IS NOT NULL AND NEW.journey IS NOT (
  SELECT r.journey FROM runs r WHERE r.id = NEW.run_id
)
BEGIN
  SELECT RAISE(ABORT, 'checkpoint journey must match run journey');
END;

CREATE TRIGGER checkpoints_preserve_journey
BEFORE UPDATE OF journey, mission_id, run_id ON checkpoints
WHEN NEW.journey IS NULL
  OR NEW.journey IS NOT (SELECT r.journey FROM runs r WHERE r.id = NEW.run_id)
  OR NEW.mission_id IS NOT (SELECT r.mission_id FROM runs r WHERE r.id = NEW.run_id)
BEGIN
  SELECT RAISE(ABORT, 'checkpoint journey and mission must remain canonical');
END;

ALTER TABLE audit_records
  ADD COLUMN journey TEXT CHECK (journey IS NULL OR journey IN ('autonomous', 'guided'));

-- Existing audit rows predate the first-class journey column. The immutable
-- trigger is removed only for this deterministic metadata backfill. Historical
-- record hashes remain unchanged because legacy hash payloads did not contain a
-- journey field.
DROP TRIGGER audit_records_no_update;

UPDATE audit_records
SET journey = COALESCE(
  (SELECT r.journey FROM runs r WHERE r.id = audit_records.run_id),
  (SELECT m.journey FROM missions m WHERE m.id = audit_records.mission_id)
)
WHERE mission_id IS NOT NULL OR run_id IS NOT NULL;

CREATE TRIGGER audit_records_no_update
BEFORE UPDATE ON audit_records BEGIN
  SELECT RAISE(ABORT, 'audit records are immutable');
END;

CREATE TRIGGER audit_records_require_scoped_journey
BEFORE INSERT ON audit_records
WHEN (NEW.mission_id IS NOT NULL OR NEW.run_id IS NOT NULL) AND NEW.journey IS NULL
BEGIN
  SELECT RAISE(ABORT, 'mission and run audit records require a journey');
END;

CREATE TRIGGER audit_records_match_mission_journey
BEFORE INSERT ON audit_records
WHEN NEW.mission_id IS NOT NULL AND NEW.journey IS NOT NULL AND NEW.journey IS NOT (
  SELECT m.journey FROM missions m WHERE m.id = NEW.mission_id
)
BEGIN
  SELECT RAISE(ABORT, 'audit journey must match mission journey');
END;

CREATE TRIGGER audit_records_match_run_journey
BEFORE INSERT ON audit_records
WHEN NEW.run_id IS NOT NULL AND NEW.journey IS NOT NULL AND NEW.journey IS NOT (
  SELECT r.journey FROM runs r WHERE r.id = NEW.run_id
)
BEGIN
  SELECT RAISE(ABORT, 'audit journey must match run journey');
END;

CREATE INDEX idx_audit_journey_time
  ON audit_records(journey, occurred_at DESC)
  WHERE journey IS NOT NULL;

CREATE INDEX idx_artifacts_journey_time ON artifacts(journey, created_at DESC);
CREATE INDEX idx_checkpoints_journey_time ON checkpoints(journey, created_at DESC);
`,
};

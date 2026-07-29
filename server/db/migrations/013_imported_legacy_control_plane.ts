import type { Migration } from "../types";

/**
 * Repair the ownership assigned by the historical importers before V2.4.
 *
 * Only records with importer provenance and an importer-generated run ID are
 * eligible. This deliberately leaves V2-native missions/runs untouched. Any
 * future ownership transfer is an explicit operation performed after this
 * one-time repair, never an inference made by the migration.
 */
export const importedLegacyControlPlaneMigration: Migration = {
  version: 13,
  name: "imported_legacy_control_plane",
  sql: `
UPDATE control_plane_leases
SET
  control_plane = 'legacy',
  heartbeat_at = CASE
    WHEN released_at IS NULL THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ELSE heartbeat_at
  END,
  expires_at = CASE
    WHEN released_at IS NULL THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ELSE expires_at
  END,
  released_at = COALESCE(released_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  version = version + 1
WHERE EXISTS (
  SELECT 1
  FROM runs AS imported_run
  JOIN missions AS imported_mission ON imported_mission.id = imported_run.mission_id
  WHERE imported_run.id = control_plane_leases.run_id
    AND imported_mission.created_by IN ('import:legacy', 'import:legacy-engagement')
    AND (
      (
        length(imported_run.id) = 51
        AND substr(imported_run.id, 1, 11) = 'run_legacy_'
        AND substr(imported_run.id, 12) NOT GLOB '*[^0-9a-f]*'
      )
      OR (
        length(imported_run.id) = 62
        AND substr(imported_run.id, 1, 22) = 'run_engagement_legacy_'
        AND substr(imported_run.id, 23) NOT GLOB '*[^0-9a-f]*'
      )
    )
)
AND (control_plane <> 'legacy' OR released_at IS NULL);

UPDATE runs
SET
  control_plane = 'legacy',
  lease_owner = NULL,
  lease_acquired_at = NULL,
  last_heartbeat_at = NULL,
  lease_expires_at = NULL,
  version = version + 1
WHERE EXISTS (
  SELECT 1
  FROM missions AS imported_mission
  WHERE imported_mission.id = runs.mission_id
    AND imported_mission.created_by IN ('import:legacy', 'import:legacy-engagement')
)
AND (
  (
    length(runs.id) = 51
    AND substr(runs.id, 1, 11) = 'run_legacy_'
    AND substr(runs.id, 12) NOT GLOB '*[^0-9a-f]*'
  )
  OR (
    length(runs.id) = 62
    AND substr(runs.id, 1, 22) = 'run_engagement_legacy_'
    AND substr(runs.id, 23) NOT GLOB '*[^0-9a-f]*'
  )
)
AND (
  control_plane <> 'legacy'
  OR lease_owner IS NOT NULL
  OR lease_acquired_at IS NOT NULL
  OR last_heartbeat_at IS NOT NULL
  OR lease_expires_at IS NOT NULL
);

UPDATE missions
SET control_plane = 'legacy', version = version + 1
WHERE created_by IN ('import:legacy', 'import:legacy-engagement')
  AND control_plane <> 'legacy';
`,
};

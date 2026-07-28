import type { Migration } from "../types";

/**
 * Access-controlled historical source projection and operator-profile graph.
 *
 * Reusable attack knowledge remains global and target-free. These tables are
 * deliberately not memory edges: they bind an immutable memory provenance row
 * to the private mission/run/artifact that owns the exact source bytes. The
 * operator graph itself continues to use the canonical memory_nodes and
 * memory_edges tables, so no additional projection table is required for it.
 */
export const privateSourceCustodyAndOperatorGraphMigration: Migration = {
  version: 34,
  name: "private_source_custody_and_operator_graph",
  requiresVerifiedBackup: true,
  sql: String.raw`
CREATE TABLE historical_private_source_collections (
  source_identity TEXT PRIMARY KEY CHECK (length(source_identity) = 64),
  mission_id TEXT NOT NULL UNIQUE REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL
) WITHOUT ROWID, STRICT;

CREATE TABLE historical_private_source_bindings (
  memory_source_id TEXT NOT NULL REFERENCES memory_sources(id) ON DELETE RESTRICT,
  source_candidate_id TEXT NOT NULL,
  migration_id TEXT NOT NULL,
  source_reference TEXT NOT NULL CHECK (source_reference GLOB 'legacy-private-source://*'),
  source_hash TEXT NOT NULL CHECK (length(source_hash) = 64),
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
  binding_method TEXT NOT NULL CHECK (binding_method IN (
    'existing_legacy_projection', 'private_source_projection'
  )),
  binding_receipt_hash TEXT NOT NULL CHECK (length(binding_receipt_hash) = 64),
  created_at TEXT NOT NULL,
  PRIMARY KEY (memory_source_id, source_reference),
  FOREIGN KEY (source_candidate_id, migration_id, source_reference)
    REFERENCES historical_attack_knowledge_source_occurrences(
      candidate_id, migration_id, source_reference
    ) ON DELETE RESTRICT
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_historical_private_source_binding_artifact
  ON historical_private_source_bindings(artifact_id, memory_source_id);
CREATE INDEX idx_historical_private_source_binding_origin
  ON historical_private_source_bindings(mission_id, run_id, artifact_id);

CREATE TRIGGER historical_private_source_collection_integrity_insert
BEFORE INSERT ON historical_private_source_collections
WHEN NOT EXISTS (
  SELECT 1
  FROM missions mission
  JOIN runs run ON run.id = NEW.run_id
  WHERE mission.id = NEW.mission_id
    AND run.mission_id = mission.id
    AND mission.created_by = 'system:historical-private-source-projection'
    AND mission.status = 'archived'
    AND mission.engagement_id IS NULL
    AND mission.control_plane = 'legacy'
    AND run.status = 'completed'
    AND run.control_plane = 'legacy'
)
BEGIN
  SELECT RAISE(ABORT, 'private source collection must use an isolated terminal legacy projection');
END;

CREATE TRIGGER historical_private_source_binding_integrity_insert
BEFORE INSERT ON historical_private_source_bindings
WHEN NOT EXISTS (
  SELECT 1
  FROM memory_sources memory_source
  JOIN historical_attack_knowledge_source_occurrences occurrence
    ON occurrence.candidate_id = NEW.source_candidate_id
   AND occurrence.migration_id = NEW.migration_id
   AND occurrence.source_reference = NEW.source_reference
  JOIN artifacts artifact ON artifact.id = NEW.artifact_id
  JOIN runs run ON run.id = NEW.run_id
  WHERE memory_source.id = NEW.memory_source_id
    AND memory_source.source_type = 'historical_attack_knowledge_source_candidate'
    AND memory_source.source_id = NEW.source_candidate_id || ':' || NEW.migration_id
    AND memory_source.source_hash = NEW.source_hash
    AND occurrence.source_hash = NEW.source_hash
    AND artifact.mission_id = NEW.mission_id
    AND artifact.run_id = NEW.run_id
    AND artifact.content_hash = NEW.source_hash
    AND artifact.sensitivity IN ('private', 'restricted')
    AND run.mission_id = NEW.mission_id
)
BEGIN
  SELECT RAISE(ABORT, 'private source binding must resolve exact immutable source custody');
END;

CREATE TRIGGER historical_private_source_collections_no_update
BEFORE UPDATE ON historical_private_source_collections BEGIN
  SELECT RAISE(ABORT, 'private source collections are immutable');
END;
CREATE TRIGGER historical_private_source_collections_no_delete
BEFORE DELETE ON historical_private_source_collections BEGIN
  SELECT RAISE(ABORT, 'private source collections are retained for custody reconciliation');
END;
CREATE TRIGGER historical_private_source_bindings_no_update
BEFORE UPDATE ON historical_private_source_bindings BEGIN
  SELECT RAISE(ABORT, 'private source bindings are immutable');
END;
CREATE TRIGGER historical_private_source_bindings_no_delete
BEFORE DELETE ON historical_private_source_bindings BEGIN
  SELECT RAISE(ABORT, 'private source bindings are retained for custody reconciliation');
END;
`,
};

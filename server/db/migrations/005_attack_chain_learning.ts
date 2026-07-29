import type { Migration } from "../types";

/** Structured, append-only executable learning distinct from the lesson review record. */
export const attackChainLearningMigration: Migration = {
  version: 5,
  name: "normalized_attack_chain_learning",
  sql: String.raw`
CREATE TABLE lesson_attack_chain_details (
  id TEXT PRIMARY KEY,
  lesson_id TEXT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
  schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  version INTEGER NOT NULL CHECK (version > 0),
  technique_name TEXT NOT NULL CHECK (length(trim(technique_name)) > 0),
  technique_category TEXT NOT NULL CHECK (length(trim(technique_category)) > 0),
  summary TEXT NOT NULL CHECK (length(trim(summary)) > 0),
  expected_outcome TEXT NOT NULL,
  reuse_guidance TEXT NOT NULL,
  content_hash TEXT NOT NULL CHECK (length(content_hash) = 64),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (lesson_id, version),
  UNIQUE (lesson_id, content_hash)
) STRICT;

CREATE TABLE lesson_attack_chain_items (
  id TEXT PRIMARY KEY,
  detail_id TEXT NOT NULL REFERENCES lesson_attack_chain_details(id) ON DELETE CASCADE,
  item_type TEXT NOT NULL CHECK (item_type IN (
    'prerequisite', 'observed_signal', 'ordered_step', 'tool',
    'public_reference', 'validation_checkpoint', 'failure_recovery',
    'anti_reuse_warning'
  )),
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  content TEXT NOT NULL CHECK (length(trim(content)) > 0),
  content_hash TEXT NOT NULL CHECK (length(content_hash) = 64),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  UNIQUE (detail_id, item_type, ordinal),
  UNIQUE (detail_id, item_type, content_hash)
) STRICT;

CREATE TABLE lesson_attack_chain_sources (
  id TEXT PRIMARY KEY,
  lesson_id TEXT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
  detail_id TEXT NOT NULL REFERENCES lesson_attack_chain_details(id) ON DELETE CASCADE,
  source_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  source_hash TEXT,
  run_id TEXT REFERENCES runs(id) ON DELETE RESTRICT,
  evidence_id TEXT REFERENCES evidence(id) ON DELETE RESTRICT,
  provenance_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(provenance_json)),
  created_at TEXT NOT NULL,
  UNIQUE (lesson_id, source_type, source_id, run_id, evidence_id)
) STRICT;

CREATE INDEX idx_attack_chain_details_lesson_version
  ON lesson_attack_chain_details(lesson_id, version DESC);
CREATE INDEX idx_attack_chain_items_detail_type_order
  ON lesson_attack_chain_items(detail_id, item_type, ordinal);
CREATE INDEX idx_attack_chain_sources_lesson
  ON lesson_attack_chain_sources(lesson_id, source_type, created_at DESC);

CREATE TRIGGER attack_chain_details_no_update
BEFORE UPDATE ON lesson_attack_chain_details BEGIN
  SELECT RAISE(ABORT, 'attack-chain detail versions are append-only');
END;
CREATE TRIGGER attack_chain_items_no_update
BEFORE UPDATE ON lesson_attack_chain_items BEGIN
  SELECT RAISE(ABORT, 'attack-chain detail items are append-only');
END;
CREATE TRIGGER attack_chain_sources_no_update
BEFORE UPDATE ON lesson_attack_chain_sources BEGIN
  SELECT RAISE(ABORT, 'attack-chain provenance sources are append-only');
END;

CREATE TRIGGER verified_attack_chains_require_executable_evidence
BEFORE UPDATE OF status ON lessons
WHEN NEW.status = 'verified' AND NEW.lesson_type = 'attack_chain'
  AND (
    NOT EXISTS (
      SELECT 1 FROM lesson_attack_chain_details d WHERE d.lesson_id = NEW.id
    )
    OR NOT EXISTS (
      SELECT 1 FROM lesson_attack_chain_items i
      WHERE i.detail_id = (
        SELECT id FROM lesson_attack_chain_details
        WHERE lesson_id = NEW.id ORDER BY version DESC LIMIT 1
      ) AND i.item_type IN ('prerequisite', 'observed_signal')
    )
    OR NOT EXISTS (
      SELECT 1 FROM lesson_attack_chain_items i
      WHERE i.detail_id = (
        SELECT id FROM lesson_attack_chain_details
        WHERE lesson_id = NEW.id ORDER BY version DESC LIMIT 1
      ) AND i.item_type = 'ordered_step'
    )
    OR NOT EXISTS (
      SELECT 1 FROM lesson_attack_chain_items i
      WHERE i.detail_id = (
        SELECT id FROM lesson_attack_chain_details
        WHERE lesson_id = NEW.id ORDER BY version DESC LIMIT 1
      ) AND i.item_type = 'tool'
    )
    OR NOT EXISTS (
      SELECT 1 FROM lesson_attack_chain_items i
      WHERE i.detail_id = (
        SELECT id FROM lesson_attack_chain_details
        WHERE lesson_id = NEW.id ORDER BY version DESC LIMIT 1
      ) AND i.item_type = 'public_reference'
    )
    OR NOT EXISTS (
      SELECT 1 FROM lesson_attack_chain_items i
      WHERE i.detail_id = (
        SELECT id FROM lesson_attack_chain_details
        WHERE lesson_id = NEW.id ORDER BY version DESC LIMIT 1
      ) AND i.item_type = 'validation_checkpoint'
    )
    OR NOT EXISTS (
      SELECT 1 FROM lesson_attack_chain_items i
      WHERE i.detail_id = (
        SELECT id FROM lesson_attack_chain_details
        WHERE lesson_id = NEW.id ORDER BY version DESC LIMIT 1
      ) AND i.item_type = 'failure_recovery'
    )
    OR NOT EXISTS (
      SELECT 1 FROM lesson_evidence le
      WHERE le.lesson_id = NEW.id AND le.relationship = 'supports' AND le.evidence_id IS NOT NULL
    )
    OR NOT EXISTS (
      SELECT 1 FROM lesson_evidence le
      WHERE le.lesson_id = NEW.id AND le.relationship = 'supports' AND le.run_id IS NOT NULL
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'verified attack chains require complete executable details, evidence, and source run');
END;
`,
};

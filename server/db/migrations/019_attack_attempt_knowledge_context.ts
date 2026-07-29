import type { Migration } from "../types";

/**
 * Binds one first-class attack attempt to generalized, reusable attack
 * knowledge. Operational target identifiers remain on attack_attempts; this
 * table stores only global attack-centric memory-node identifiers and
 * normalized execution characteristics used by the local hazard matcher.
 */
export const attackAttemptKnowledgeContextMigration: Migration = {
  version: 19,
  name: "attack_attempt_knowledge_context",
  sql: String.raw`
CREATE TABLE attack_attempt_knowledge_contexts (
  attack_attempt_id TEXT PRIMARY KEY REFERENCES attack_attempts(id) ON DELETE CASCADE,
  procedure_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  procedure_version_node_id TEXT REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  product_node_ids_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(product_node_ids_json) AND json_type(product_node_ids_json) = 'array'),
  version_node_ids_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(version_node_ids_json) AND json_type(version_node_ids_json) = 'array'),
  stack_node_ids_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(stack_node_ids_json) AND json_type(stack_node_ids_json) = 'array'),
  prerequisite_node_ids_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(prerequisite_node_ids_json) AND json_type(prerequisite_node_ids_json) = 'array'),
  observed_state_node_ids_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(observed_state_node_ids_json) AND json_type(observed_state_node_ids_json) = 'array'),
  normalized_parameters_json TEXT NOT NULL DEFAULT '{}'
    CHECK (json_valid(normalized_parameters_json) AND json_type(normalized_parameters_json) = 'object'),
  load REAL CHECK (load IS NULL OR load >= 0),
  concurrency INTEGER CHECK (concurrency IS NULL OR concurrency >= 1),
  timing_window_ms INTEGER CHECK (timing_window_ms IS NULL OR timing_window_ms >= 0),
  context_pack_id TEXT REFERENCES memory_context_packs(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_attack_attempt_knowledge_procedure
  ON attack_attempt_knowledge_contexts(procedure_node_id, procedure_version_node_id, updated_at DESC);
CREATE INDEX idx_attack_attempt_knowledge_context_pack
  ON attack_attempt_knowledge_contexts(context_pack_id)
  WHERE context_pack_id IS NOT NULL;
`,
};

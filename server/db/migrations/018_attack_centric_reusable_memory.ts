import type { Migration } from "../types";

/**
 * Widen the immutable memory taxonomy without rewriting any values. SQLite
 * cannot alter CHECK constraints in place, so this startup-only migration uses
 * the runner's verified-backup/FK-off boundary, preserves rowids, recreates
 * every index and FTS trigger, and rebuilds the external-content FTS index.
 */
export const attackCentricReusableMemoryMigration: Migration = {
  version: 18,
  name: "attack_centric_reusable_memory",
  requiresForeignKeysDisabled: true,
  requiresVerifiedBackup: true,
  sql: String.raw`
CREATE TABLE memory_nodes_v18 (
  id TEXT PRIMARY KEY,
  node_type TEXT NOT NULL CHECK (node_type IN (
    'operator', 'preference', 'mission', 'run', 'plan', 'phase', 'step', 'agent',
    'tool', 'mcp_capability', 'tactic', 'technique', 'procedure', 'target', 'asset',
    'entity', 'decision', 'evidence', 'finding', 'artifact', 'failure', 'recovery',
    'evaluation', 'lesson', 'report', 'source',
    'technology_product', 'exact_version_fingerprint', 'version_range_fingerprint',
    'operating_system', 'kernel', 'framework', 'runtime', 'database', 'firewall',
    'waf', 'proxy', 'security_control', 'topology_pattern', 'topology_role', 'cve',
    'advisory', 'cwe', 'misconfiguration', 'attack_vector', 'prerequisite',
    'attribute', 'discovery_pattern', 'fingerprint_pattern', 'script_artifact',
    'tool_artifact', 'outcome', 'failure_mode', 'alternative', 'evidence_pattern',
    'validation_pattern', 'detection', 'remediation', 'strategy', 'research',
    'procedure_version', 'operational_hazard', 'target_state_transition',
    'recovery_pattern', 'health_check', 'attack_tactic', 'attack_technique',
    'attack_procedure', 'attack_lesson'
  )),
  title TEXT NOT NULL CHECK (length(trim(title)) > 0),
  summary TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL,
  engagement_id TEXT,
  mission_id TEXT REFERENCES missions(id) ON DELETE SET NULL,
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  lifecycle_status TEXT NOT NULL CHECK (lifecycle_status IN (
    'candidate', 'confirmed', 'verified', 'disputed', 'stale', 'superseded', 'forgotten'
  )),
  confirmation_state TEXT NOT NULL CHECK (confirmation_state IN ('not_required', 'pending', 'confirmed', 'rejected')),
  provenance_json TEXT NOT NULL CHECK (json_valid(provenance_json)),
  author_type TEXT NOT NULL CHECK (author_type IN ('operator', 'agent', 'system', 'import')),
  author_id TEXT,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  retention_policy_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(retention_policy_json)),
  expires_at TEXT,
  pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

INSERT INTO memory_nodes_v18 (
  rowid, id, node_type, title, summary, body, scope, engagement_id, mission_id,
  sensitivity, confidence, lifecycle_status, confirmation_state,
  provenance_json, author_type, author_id, version, retention_policy_json,
  expires_at, pinned, created_at, updated_at
)
SELECT
  rowid, id, node_type, title, summary, body, scope, engagement_id, mission_id,
  sensitivity, confidence, lifecycle_status, confirmation_state,
  provenance_json, author_type, author_id, version, retention_policy_json,
  expires_at, pinned, created_at, updated_at
FROM memory_nodes;

DROP TABLE memory_nodes;
ALTER TABLE memory_nodes_v18 RENAME TO memory_nodes;

CREATE INDEX idx_memory_nodes_type_status_scope_updated ON memory_nodes(node_type, lifecycle_status, scope, updated_at DESC);
CREATE INDEX idx_memory_nodes_engagement_status ON memory_nodes(engagement_id, lifecycle_status, updated_at DESC);
CREATE INDEX idx_memory_nodes_mission_type ON memory_nodes(mission_id, node_type);

CREATE TRIGGER memory_nodes_fts_insert AFTER INSERT ON memory_nodes BEGIN
  INSERT INTO memory_nodes_fts(rowid, title, summary, body)
  VALUES (new.rowid, new.title, new.summary, new.body);
END;
CREATE TRIGGER memory_nodes_fts_delete AFTER DELETE ON memory_nodes BEGIN
  INSERT INTO memory_nodes_fts(memory_nodes_fts, rowid, title, summary, body)
  VALUES ('delete', old.rowid, old.title, old.summary, old.body);
END;
CREATE TRIGGER memory_nodes_fts_update AFTER UPDATE ON memory_nodes BEGIN
  INSERT INTO memory_nodes_fts(memory_nodes_fts, rowid, title, summary, body)
  VALUES ('delete', old.rowid, old.title, old.summary, old.body);
  INSERT INTO memory_nodes_fts(rowid, title, summary, body)
  VALUES (new.rowid, new.title, new.summary, new.body);
END;
INSERT INTO memory_nodes_fts(memory_nodes_fts) VALUES ('rebuild');

CREATE TABLE memory_edges_v18 (
  id TEXT PRIMARY KEY,
  source_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE CASCADE,
  target_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE CASCADE,
  edge_type TEXT NOT NULL CHECK (edge_type IN (
    'prefers', 'applies_to', 'belongs_to', 'executed_by', 'delegated_to', 'used_in',
    'targets', 'produced', 'supports', 'contradicts', 'depends_on', 'derived_from',
    'learned_from', 'failed_in', 'recovered_by', 'similar_to', 'supersedes',
    'verified_by', 'mentioned_in', 'influenced', 'has_exact_version',
    'has_version_range', 'version_in_range', 'runs_on', 'built_with', 'uses_runtime',
    'uses_database', 'protected_by', 'has_topology_role', 'matches_fingerprint',
    'discovered_by', 'fingerprinted_by', 'affects', 'classified_as', 'exploits',
    'requires', 'has_attribute', 'implemented_by', 'tested_against',
    'produces_outcome', 'failed_because', 'recovered_with', 'alternative_to',
    'validated_by', 'detected_by', 'remediated_by', 'applicable_to',
    'not_applicable_to', 'mitigates', 'bypasses', 'improves', 'caused',
    'leaves_in_state', 'requires_recovery', 'avoid_after', 'safe_when', 'mitigated_by'
  )),
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  scope TEXT NOT NULL,
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  lifecycle_status TEXT NOT NULL CHECK (lifecycle_status IN (
    'candidate', 'confirmed', 'verified', 'disputed', 'stale', 'superseded', 'forgotten'
  )),
  provenance_json TEXT NOT NULL CHECK (json_valid(provenance_json)),
  explanation TEXT NOT NULL,
  author_type TEXT NOT NULL CHECK (author_type IN ('operator', 'agent', 'system', 'import')),
  author_id TEXT,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  engagement_id TEXT,
  mission_id TEXT REFERENCES missions(id) ON DELETE SET NULL,
  CHECK (source_node_id != target_node_id),
  UNIQUE (source_node_id, edge_type, target_node_id, version)
) STRICT;

INSERT INTO memory_edges_v18 (
  id, source_node_id, target_node_id, edge_type, title, summary, scope,
  sensitivity, confidence, lifecycle_status, provenance_json, explanation,
  author_type, author_id, version, expires_at, created_at, updated_at,
  engagement_id, mission_id
)
SELECT
  id, source_node_id, target_node_id, edge_type, title, summary, scope,
  sensitivity, confidence, lifecycle_status, provenance_json, explanation,
  author_type, author_id, version, expires_at, created_at, updated_at,
  engagement_id, mission_id
FROM memory_edges;

DROP TABLE memory_edges;
ALTER TABLE memory_edges_v18 RENAME TO memory_edges;

CREATE INDEX idx_memory_edges_source_type_target ON memory_edges(source_node_id, edge_type, target_node_id);
CREATE INDEX idx_memory_edges_target_type_source ON memory_edges(target_node_id, edge_type, source_node_id);
CREATE INDEX idx_memory_edges_scope_engagement ON memory_edges(scope, engagement_id, updated_at);
CREATE INDEX idx_memory_edges_scope_mission ON memory_edges(scope, mission_id, updated_at);

CREATE TABLE operational_hazard_profiles (
  node_id TEXT PRIMARY KEY REFERENCES memory_nodes(id) ON DELETE CASCADE,
  procedure_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  procedure_version_node_id TEXT REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  product_node_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(product_node_ids_json) AND json_type(product_node_ids_json) = 'array'),
  version_node_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(version_node_ids_json) AND json_type(version_node_ids_json) = 'array'),
  stack_node_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(stack_node_ids_json) AND json_type(stack_node_ids_json) = 'array'),
  prerequisite_node_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(prerequisite_node_ids_json) AND json_type(prerequisite_node_ids_json) = 'array'),
  observed_state_node_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(observed_state_node_ids_json) AND json_type(observed_state_node_ids_json) = 'array'),
  ordered_steps_json TEXT NOT NULL CHECK (json_valid(ordered_steps_json) AND json_type(ordered_steps_json) = 'array'),
  normalized_parameters_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(normalized_parameters_json) AND json_type(normalized_parameters_json) = 'object'),
  load_min REAL,
  concurrency_min INTEGER CHECK (concurrency_min IS NULL OR concurrency_min >= 1),
  timing_window_ms INTEGER CHECK (timing_window_ms IS NULL OR timing_window_ms >= 0),
  observed_symptom TEXT NOT NULL CHECK (length(trim(observed_symptom)) > 0),
  affected_component TEXT NOT NULL CHECK (length(trim(affected_component)) > 0),
  state_before TEXT NOT NULL CHECK (length(trim(state_before)) > 0),
  state_after TEXT NOT NULL CHECK (length(trim(state_after)) > 0),
  state_transition_node_id TEXT REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  reproducibility_count INTEGER NOT NULL CHECK (reproducibility_count >= 1),
  attempt_count INTEGER NOT NULL CHECK (attempt_count >= reproducibility_count),
  recovery_pattern_node_id TEXT REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  recovery_action_summary TEXT NOT NULL CHECK (length(trim(recovery_action_summary)) > 0),
  recovery_cost_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(recovery_cost_json) AND json_type(recovery_cost_json) = 'object'),
  unsafe_retry_conditions_json TEXT NOT NULL CHECK (json_valid(unsafe_retry_conditions_json) AND json_type(unsafe_retry_conditions_json) = 'array'),
  safe_retry_gate_json TEXT NOT NULL CHECK (json_valid(safe_retry_gate_json) AND json_type(safe_retry_gate_json) = 'array'),
  alternative_sequence_json TEXT NOT NULL CHECK (json_valid(alternative_sequence_json) AND json_type(alternative_sequence_json) = 'array'),
  alternative_procedure_node_id TEXT REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  applicability_constraints_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(applicability_constraints_json) AND json_type(applicability_constraints_json) = 'object'),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  observed_at TEXT NOT NULL,
  fresh_until TEXT,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_operational_hazard_procedure_freshness
  ON operational_hazard_profiles(procedure_node_id, procedure_version_node_id, fresh_until, confidence DESC);
CREATE INDEX idx_operational_hazard_recovery
  ON operational_hazard_profiles(recovery_pattern_node_id, alternative_procedure_node_id);
`,
};

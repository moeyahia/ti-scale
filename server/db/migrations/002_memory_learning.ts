import type { Migration } from "../types";

export const memoryLearningMigration: Migration = {
  version: 2,
  name: "second_brain_learning_vault",
  sql: String.raw`
CREATE TABLE memory_nodes (
  id TEXT PRIMARY KEY,
  node_type TEXT NOT NULL CHECK (node_type IN (
    'operator', 'preference', 'mission', 'run', 'plan', 'phase', 'step', 'agent',
    'tool', 'mcp_capability', 'tactic', 'technique', 'procedure', 'target', 'asset',
    'entity', 'decision', 'evidence', 'finding', 'artifact', 'failure', 'recovery',
    'evaluation', 'lesson', 'report', 'source'
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

CREATE TABLE memory_edges (
  id TEXT PRIMARY KEY,
  source_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE CASCADE,
  target_node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE CASCADE,
  edge_type TEXT NOT NULL CHECK (edge_type IN (
    'prefers', 'applies_to', 'belongs_to', 'executed_by', 'delegated_to', 'used_in',
    'targets', 'produced', 'supports', 'contradicts', 'depends_on', 'derived_from',
    'learned_from', 'failed_in', 'recovered_by', 'similar_to', 'supersedes',
    'verified_by', 'mentioned_in', 'influenced'
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
  CHECK (source_node_id != target_node_id),
  UNIQUE (source_node_id, edge_type, target_node_id, version)
) STRICT;

CREATE TABLE memory_sources (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE CASCADE,
  source_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  mission_id TEXT REFERENCES missions(id) ON DELETE SET NULL,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
  evidence_id TEXT REFERENCES evidence(id) ON DELETE RESTRICT,
  source_hash TEXT,
  excerpt_redacted TEXT,
  acquired_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (node_id, source_type, source_id)
) STRICT;

CREATE TABLE memory_versions (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version > 0),
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  body TEXT NOT NULL,
  properties_json TEXT NOT NULL CHECK (json_valid(properties_json)),
  lifecycle_status TEXT NOT NULL,
  author_type TEXT NOT NULL,
  author_id TEXT,
  change_reason TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (node_id, version)
) STRICT;

CREATE TABLE memory_candidates (
  id TEXT PRIMARY KEY,
  proposed_node_id TEXT REFERENCES memory_nodes(id) ON DELETE SET NULL,
  candidate_type TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  proposed_scope TEXT NOT NULL,
  engagement_id TEXT,
  mission_id TEXT REFERENCES missions(id) ON DELETE SET NULL,
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  source_json TEXT NOT NULL CHECK (json_valid(source_json)),
  status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'edited_confirmed', 'merged', 'rejected', 'suppressed')),
  proposed_by TEXT NOT NULL,
  reviewed_by TEXT,
  reviewed_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE memory_embeddings (
  node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE CASCADE,
  model TEXT NOT NULL,
  provider TEXT NOT NULL,
  dimensions INTEGER NOT NULL CHECK (dimensions > 0),
  embedding BLOB NOT NULL,
  content_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (node_id, model, provider)
) STRICT;

CREATE TABLE memory_context_packs (
  id TEXT PRIMARY KEY,
  mission_id TEXT REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES runs(id) ON DELETE CASCADE,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  action_id TEXT REFERENCES actions(id) ON DELETE SET NULL,
  message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
  journey TEXT NOT NULL CHECK (journey IN ('autonomous', 'guided')),
  purpose TEXT NOT NULL,
  query_redacted TEXT,
  scope_policy_json TEXT NOT NULL CHECK (json_valid(scope_policy_json)),
  context_budget INTEGER NOT NULL CHECK (context_budget >= 0),
  retrieval_metrics_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(retrieval_metrics_json)),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE memory_context_items (
  context_pack_id TEXT NOT NULL REFERENCES memory_context_packs(id) ON DELETE CASCADE,
  node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  rank INTEGER NOT NULL CHECK (rank >= 0),
  retrieval_score REAL NOT NULL,
  used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1)),
  relevance_reason TEXT NOT NULL,
  influence_summary TEXT,
  ignored_reason TEXT,
  corrected INTEGER NOT NULL DEFAULT 0 CHECK (corrected IN (0, 1)),
  PRIMARY KEY (context_pack_id, node_id)
) STRICT;

CREATE TABLE memory_suppressions (
  id TEXT PRIMARY KEY,
  suppression_hash TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL,
  engagement_id TEXT,
  category TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_by TEXT NOT NULL,
  expires_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE preference_profiles (
  id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  engagement_id TEXT,
  mission_type TEXT,
  preference_key TEXT NOT NULL,
  value_json TEXT NOT NULL CHECK (json_valid(value_json)),
  confirmation_state TEXT NOT NULL CHECK (confirmation_state IN ('candidate', 'confirmed', 'disputed', 'stale', 'forgotten')),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  source_node_id TEXT REFERENCES memory_nodes(id) ON DELETE SET NULL,
  consent_policy TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  confirmed_at TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (operator_id, scope, engagement_id, mission_type, preference_key, version)
) STRICT;

CREATE TABLE preference_observations (
  id TEXT PRIMARY KEY,
  profile_id TEXT REFERENCES preference_profiles(id) ON DELETE CASCADE,
  preference_key TEXT NOT NULL,
  observed_value_json TEXT NOT NULL CHECK (json_valid(observed_value_json)),
  source_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  consent_state TEXT NOT NULL CHECK (consent_state IN ('not_requested', 'pending', 'granted', 'denied')),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE vault_connections (
  id TEXT PRIMARY KEY,
  vault_path TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('disconnected', 'connecting', 'connected', 'degraded', 'error')),
  sync_scope_json TEXT NOT NULL CHECK (json_valid(sync_scope_json)),
  permission_granted_at TEXT NOT NULL,
  last_sync_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE vault_sync_state (
  id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES vault_connections(id) ON DELETE CASCADE,
  node_id TEXT REFERENCES memory_nodes(id) ON DELETE SET NULL,
  relative_path TEXT NOT NULL,
  database_version INTEGER,
  vault_content_hash TEXT,
  database_content_hash TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'synced', 'database_ahead', 'vault_ahead', 'conflict', 'quarantined', 'deleted')),
  last_scanned_at TEXT,
  last_synced_at TEXT,
  error_message TEXT,
  UNIQUE (connection_id, relative_path)
) STRICT;

CREATE TABLE vault_conflicts (
  id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES vault_connections(id) ON DELETE CASCADE,
  sync_state_id TEXT NOT NULL REFERENCES vault_sync_state(id) ON DELETE CASCADE,
  node_id TEXT REFERENCES memory_nodes(id) ON DELETE SET NULL,
  base_hash TEXT,
  database_hash TEXT NOT NULL,
  vault_hash TEXT NOT NULL,
  database_version_json TEXT NOT NULL CHECK (json_valid(database_version_json)),
  vault_version_text TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'resolved_database', 'resolved_vault', 'resolved_merged', 'dismissed')),
  resolution_reason TEXT,
  resolved_by TEXT,
  resolved_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE lessons (
  id TEXT PRIMARY KEY,
  statement TEXT NOT NULL CHECK (length(trim(statement)) > 0),
  lesson_type TEXT NOT NULL,
  applicability_scope TEXT NOT NULL,
  engagement_id TEXT,
  mission_id TEXT REFERENCES missions(id) ON DELETE SET NULL,
  failure_category TEXT,
  retry_conditions TEXT,
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  expected_benefit TEXT NOT NULL,
  risk TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('proposed', 'under_review', 'verified', 'rejected', 'stale', 'superseded')),
  authoring_agent_id TEXT,
  reviewed_by TEXT,
  reviewed_at TEXT,
  expires_at TEXT,
  supersedes_lesson_id TEXT REFERENCES lessons(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (status != 'verified' OR reviewed_by IS NOT NULL),
  CHECK (status != 'verified' OR reviewed_by != authoring_agent_id)
) STRICT;

CREATE TABLE lesson_evidence (
  lesson_id TEXT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
  evidence_id TEXT REFERENCES evidence(id) ON DELETE RESTRICT,
  run_id TEXT REFERENCES runs(id) ON DELETE RESTRICT,
  relationship TEXT NOT NULL CHECK (relationship IN ('supports', 'contradicts', 'counterexample')),
  rationale TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (evidence_id IS NOT NULL OR run_id IS NOT NULL),
  UNIQUE (lesson_id, evidence_id, run_id, relationship)
) STRICT;

CREATE TABLE lesson_usage (
  id TEXT PRIMARY KEY,
  lesson_id TEXT NOT NULL REFERENCES lessons(id) ON DELETE RESTRICT,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  action_id TEXT REFERENCES actions(id) ON DELETE SET NULL,
  context_pack_id TEXT REFERENCES memory_context_packs(id) ON DELETE SET NULL,
  influence_summary TEXT NOT NULL,
  outcome TEXT,
  measured_impact_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(measured_impact_json)),
  used_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_memory_nodes_type_status_scope_updated ON memory_nodes(node_type, lifecycle_status, scope, updated_at DESC);
CREATE INDEX idx_memory_nodes_engagement_status ON memory_nodes(engagement_id, lifecycle_status, updated_at DESC);
CREATE INDEX idx_memory_nodes_mission_type ON memory_nodes(mission_id, node_type);
CREATE INDEX idx_memory_edges_source_type_target ON memory_edges(source_node_id, edge_type, target_node_id);
CREATE INDEX idx_memory_edges_target_type_source ON memory_edges(target_node_id, edge_type, source_node_id);
CREATE INDEX idx_memory_sources_mission_run_time ON memory_sources(mission_id, run_id, acquired_at DESC);
CREATE INDEX idx_memory_sources_source ON memory_sources(source_type, source_id);
CREATE INDEX idx_memory_candidates_status_created ON memory_candidates(status, created_at DESC);
CREATE INDEX idx_context_packs_run_time ON memory_context_packs(run_id, created_at DESC);
CREATE INDEX idx_context_items_node_used ON memory_context_items(node_id, used);
CREATE INDEX idx_preference_profile_scope_key ON preference_profiles(operator_id, scope, preference_key, updated_at DESC);
CREATE INDEX idx_preference_observations_key_time ON preference_observations(preference_key, created_at DESC);
CREATE INDEX idx_vault_sync_path_status_time ON vault_sync_state(connection_id, relative_path, status, last_scanned_at DESC);
CREATE INDEX idx_vault_conflicts_status_time ON vault_conflicts(status, created_at DESC);
CREATE INDEX idx_lessons_status_scope ON lessons(status, applicability_scope, updated_at DESC);
CREATE INDEX idx_lesson_usage_lesson_run ON lesson_usage(lesson_id, run_id, used_at DESC);

CREATE TRIGGER memory_versions_no_update
BEFORE UPDATE ON memory_versions BEGIN
  SELECT RAISE(ABORT, 'memory versions are append-only');
END;
CREATE TRIGGER memory_versions_no_delete
BEFORE DELETE ON memory_versions BEGIN
  SELECT RAISE(ABORT, 'memory versions are append-only');
END;
CREATE TRIGGER lessons_require_evidence
BEFORE UPDATE OF status ON lessons
WHEN NEW.status = 'verified'
  AND NOT EXISTS (SELECT 1 FROM lesson_evidence WHERE lesson_id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'verified lessons require linked evidence');
END;
`,
};

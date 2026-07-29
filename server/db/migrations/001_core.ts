import type { Migration } from "../types";

export const coreMigration: Migration = {
  version: 1,
  name: "core_mission_runtime",
  sql: String.raw`
CREATE TABLE missions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL CHECK (length(trim(name)) > 0),
  objective TEXT NOT NULL CHECK (length(trim(objective)) > 0),
  journey TEXT NOT NULL CHECK (journey IN ('autonomous', 'guided')),
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN (
    'draft', 'ready', 'active', 'paused', 'completed', 'failed', 'cancelled', 'archived'
  )),
  authorization_status TEXT NOT NULL DEFAULT 'unverified' CHECK (authorization_status IN (
    'unverified', 'verified', 'expired', 'revoked'
  )),
  engagement_id TEXT,
  scope_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(scope_json)),
  success_criteria_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(success_criteria_json)),
  retention_policy_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(retention_policy_json)),
  memory_policy_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(memory_policy_json)),
  created_by TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE mission_targets (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  target TEXT NOT NULL CHECK (length(trim(target)) > 0),
  target_type TEXT NOT NULL,
  disposition TEXT NOT NULL DEFAULT 'allowed' CHECK (disposition IN ('allowed', 'prohibited')),
  normalized_target TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  UNIQUE (mission_id, disposition, normalized_target)
) STRICT;

CREATE TABLE mission_constraints (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  constraint_type TEXT NOT NULL,
  value_json TEXT NOT NULL CHECK (json_valid(value_json)),
  source TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (mission_id, constraint_type, source)
) STRICT;

CREATE TABLE mission_contracts (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version > 0),
  state TEXT NOT NULL CHECK (state IN ('draft', 'confirmed', 'superseded', 'revoked')),
  contract_hash TEXT NOT NULL CHECK (length(contract_hash) >= 32),
  authorization_json TEXT NOT NULL CHECK (json_valid(authorization_json)),
  action_policy_json TEXT NOT NULL CHECK (json_valid(action_policy_json)),
  budgets_json TEXT NOT NULL CHECK (json_valid(budgets_json)),
  safe_stop_json TEXT NOT NULL CHECK (json_valid(safe_stop_json)),
  deliverables_json TEXT NOT NULL CHECK (json_valid(deliverables_json)),
  memory_scopes_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(memory_scopes_json)),
  confirmed_by TEXT,
  confirmed_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (mission_id, version),
  UNIQUE (mission_id, contract_hash)
) STRICT;

CREATE TABLE runs (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  journey TEXT NOT NULL CHECK (journey IN ('autonomous', 'guided')),
  status TEXT NOT NULL CHECK (status IN (
    'queued', 'planning', 'awaiting_contract_confirmation', 'running',
    'waiting_guided_decision', 'blocked', 'recovering', 'completed', 'failed', 'cancelled'
  )),
  contract_id TEXT REFERENCES mission_contracts(id) ON DELETE RESTRICT,
  current_plan_id TEXT,
  current_step_id TEXT,
  current_owner_id TEXT,
  progress REAL NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 1),
  status_reason TEXT,
  next_action_summary TEXT,
  budget_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(budget_json)),
  budget_usage_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(budget_usage_json)),
  retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
  replan_count INTEGER NOT NULL DEFAULT 0 CHECK (replan_count >= 0),
  lease_owner TEXT,
  lease_acquired_at TEXT,
  last_heartbeat_at TEXT,
  lease_expires_at TEXT,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  CHECK (journey != 'autonomous' OR status != 'waiting_guided_decision')
) STRICT;

CREATE TABLE plans (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version > 0),
  status TEXT NOT NULL CHECK (status IN ('draft', 'active', 'superseded', 'completed', 'abandoned')),
  strategy_summary TEXT NOT NULL,
  rationale_summary TEXT,
  plan_hash TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  activated_at TEXT,
  UNIQUE (run_id, version),
  UNIQUE (run_id, plan_hash)
) STRICT;

CREATE TABLE plan_steps (
  id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  phase TEXT NOT NULL,
  title TEXT NOT NULL,
  objective TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'pending', 'ready', 'running', 'waiting_guided_decision', 'blocked',
    'recovering', 'completed', 'failed', 'skipped', 'cancelled'
  )),
  success_criteria_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(success_criteria_json)),
  dependencies_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(dependencies_json)),
  action_class TEXT,
  risk_class TEXT,
  assigned_agent_id TEXT,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (plan_id, ordinal)
) STRICT;

CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('available', 'busy', 'degraded', 'offline', 'quarantined')),
  provider_policy_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(provider_policy_json)),
  tool_policy_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(tool_policy_json)),
  configuration_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(configuration_json)),
  version TEXT NOT NULL,
  last_heartbeat_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE agent_capabilities (
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  capability TEXT NOT NULL,
  source TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  PRIMARY KEY (agent_id, capability, source)
) STRICT;

CREATE TABLE assignments (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('queued', 'active', 'blocked', 'completed', 'failed', 'cancelled')),
  lease_owner TEXT,
  lease_acquired_at TEXT,
  last_heartbeat_at TEXT,
  lease_expires_at TEXT,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE actions (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  assignment_id TEXT REFERENCES assignments(id) ON DELETE SET NULL,
  parent_action_id TEXT REFERENCES actions(id) ON DELETE SET NULL,
  action_type TEXT NOT NULL,
  action_class TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  normalized_arguments_json TEXT NOT NULL CHECK (json_valid(normalized_arguments_json)),
  scoped_target TEXT,
  status TEXT NOT NULL CHECK (status IN (
    'queued', 'running', 'succeeded', 'failed', 'cancelled', 'timed_out', 'denied'
  )),
  intent_summary TEXT NOT NULL,
  result_summary TEXT,
  error_category TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
  progress_signature TEXT,
  guided_decision_id TEXT,
  contract_id TEXT REFERENCES mission_contracts(id) ON DELETE RESTRICT,
  context_pack_id TEXT,
  trace_id TEXT,
  span_id TEXT,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE tool_calls (
  id TEXT PRIMARY KEY,
  action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  mcp_server_id TEXT,
  normalized_arguments_json TEXT NOT NULL CHECK (json_valid(normalized_arguments_json)),
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'timed_out', 'denied')),
  error_category TEXT,
  latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
  output_summary TEXT,
  redacted_payload_json TEXT CHECK (redacted_payload_json IS NULL OR json_valid(redacted_payload_json)),
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE guided_decisions (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  step_id TEXT NOT NULL REFERENCES plan_steps(id) ON DELETE CASCADE,
  requested_action_fingerprint TEXT NOT NULL,
  requested_parameters_json TEXT NOT NULL CHECK (json_valid(requested_parameters_json)),
  rationale TEXT NOT NULL,
  risk_class TEXT NOT NULL,
  reversibility TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'manual', 'alternative', 'rejected', 'expired', 'cancelled')),
  decision_actor TEXT,
  decision_reason TEXT,
  decided_at TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  mission_id TEXT REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES runs(id) ON DELETE CASCADE,
  approval_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')),
  requested_by TEXT NOT NULL,
  decided_by TEXT,
  reason TEXT NOT NULL,
  policy_rule TEXT,
  request_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(request_json)),
  expires_at TEXT,
  decided_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE run_event_sequences (
  run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
  last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0)
) STRICT;

CREATE TABLE events (
  id TEXT PRIMARY KEY,
  mission_id TEXT REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT REFERENCES runs(id) ON DELETE CASCADE,
  sequence INTEGER,
  event_type TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('operator', 'agent', 'worker', 'provider', 'tool', 'system')),
  actor_id TEXT,
  summary TEXT NOT NULL CHECK (length(trim(summary)) > 0),
  payload_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload_json)),
  schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  journey TEXT NOT NULL CHECK (journey IN ('autonomous', 'guided')),
  trace_id TEXT,
  span_id TEXT,
  sensitivity TEXT NOT NULL DEFAULT 'internal' CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  redaction_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(redaction_json)),
  context_pack_id TEXT,
  created_at TEXT NOT NULL,
  CHECK ((run_id IS NULL AND sequence IS NULL) OR (run_id IS NOT NULL AND sequence > 0)),
  UNIQUE (run_id, sequence)
) STRICT;

CREATE TABLE event_outbox (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE REFERENCES events(id) ON DELETE CASCADE,
  topic TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivering', 'delivered', 'failed')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  available_at TEXT NOT NULL,
  claimed_by TEXT,
  claimed_at TEXT,
  delivered_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE evidence (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  action_id TEXT REFERENCES actions(id) ON DELETE SET NULL,
  source TEXT NOT NULL,
  acquired_at TEXT NOT NULL,
  target TEXT,
  evidence_type TEXT NOT NULL,
  content_hash TEXT NOT NULL CHECK (length(content_hash) >= 32),
  provenance_json TEXT NOT NULL CHECK (json_valid(provenance_json)),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  verification_state TEXT NOT NULL CHECK (verification_state IN ('unverified', 'verified', 'disputed', 'rejected')),
  summary TEXT NOT NULL,
  extracted_text TEXT,
  artifact_id TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE evidence_chain_events (
  id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details_json)),
  occurred_at TEXT NOT NULL
) STRICT;

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  affected_scope TEXT NOT NULL,
  description TEXT NOT NULL,
  impact TEXT NOT NULL,
  reproduction_notes TEXT,
  remediation TEXT,
  review_status TEXT NOT NULL CHECK (review_status IN ('draft', 'under_review', 'verified', 'rejected', 'accepted_risk')),
  operator_override INTEGER NOT NULL DEFAULT 0 CHECK (operator_override IN (0, 1)),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE finding_evidence (
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
  relationship TEXT NOT NULL DEFAULT 'supports' CHECK (relationship IN ('supports', 'contradicts', 'context')),
  added_at TEXT NOT NULL,
  PRIMARY KEY (finding_id, evidence_id, relationship)
) STRICT;

CREATE TABLE artifacts (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  action_id TEXT REFERENCES actions(id) ON DELETE SET NULL,
  artifact_type TEXT NOT NULL,
  storage_uri TEXT NOT NULL,
  content_hash TEXT NOT NULL CHECK (length(content_hash) >= 32),
  byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
  media_type TEXT,
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE checkpoints (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  event_sequence INTEGER NOT NULL CHECK (event_sequence >= 0),
  plan_version INTEGER,
  state_json TEXT NOT NULL CHECK (json_valid(state_json)),
  state_hash TEXT NOT NULL,
  in_flight_classification TEXT,
  context_pack_id TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (run_id, event_sequence)
) STRICT;

CREATE TABLE run_evaluations (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE CASCADE,
  journey TEXT NOT NULL CHECK (journey IN ('autonomous', 'guided')),
  scores_json TEXT NOT NULL CHECK (json_valid(scores_json)),
  metrics_json TEXT NOT NULL CHECK (json_valid(metrics_json)),
  retrospective TEXT NOT NULL,
  evidence_coverage REAL NOT NULL CHECK (evidence_coverage >= 0 AND evidence_coverage <= 1),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE conversations (
  id TEXT PRIMARY KEY,
  mission_id TEXT REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES runs(id) ON DELETE CASCADE,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  conversation_type TEXT NOT NULL CHECK (conversation_type IN ('guided', 'commander', 'global', 'system')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE messages (
  id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('operator', 'assistant', 'system', 'tool')),
  body TEXT NOT NULL,
  structured_content_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(structured_content_json)),
  context_pack_id TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE provider_turns (
  id TEXT PRIMARY KEY,
  run_id TEXT REFERENCES runs(id) ON DELETE CASCADE,
  conversation_id TEXT REFERENCES conversations(id) ON DELETE SET NULL,
  message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
  provider TEXT NOT NULL,
  model TEXT,
  status TEXT NOT NULL CHECK (status IN ('started', 'completed', 'failed', 'cancelled')),
  input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
  output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
  estimated_cost REAL CHECK (estimated_cost IS NULL OR estimated_cost >= 0),
  latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
  error_category TEXT,
  started_at TEXT NOT NULL,
  ended_at TEXT
) STRICT;

CREATE TABLE mcp_servers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  transport TEXT NOT NULL,
  endpoint_redacted TEXT,
  status TEXT NOT NULL CHECK (status IN ('unknown', 'healthy', 'degraded', 'offline', 'quarantined')),
  capabilities_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(capabilities_json)),
  policy_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(policy_json)),
  last_checked_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE health_snapshots (
  id TEXT PRIMARY KEY,
  component_type TEXT NOT NULL,
  component_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('healthy', 'degraded', 'unhealthy', 'unknown')),
  metrics_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metrics_json)),
  message TEXT,
  captured_at TEXT NOT NULL
) STRICT;

CREATE TABLE notifications (
  id TEXT PRIMARY KEY,
  mission_id TEXT REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES runs(id) ON DELETE CASCADE,
  notification_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'error', 'critical')),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  read_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE audit_records (
  id TEXT PRIMARY KEY,
  mission_id TEXT REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT REFERENCES runs(id) ON DELETE RESTRICT,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  reason TEXT,
  details_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details_json)),
  previous_hash TEXT,
  record_hash TEXT NOT NULL,
  occurred_at TEXT NOT NULL
) STRICT;

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL CHECK (json_valid(value_json)),
  sensitivity TEXT NOT NULL DEFAULT 'internal' CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE structured_logs (
  id TEXT PRIMARY KEY,
  mission_id TEXT REFERENCES missions(id) ON DELETE SET NULL,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  action_id TEXT REFERENCES actions(id) ON DELETE SET NULL,
  severity TEXT NOT NULL CHECK (severity IN ('trace', 'debug', 'info', 'warn', 'error', 'fatal')),
  domain TEXT NOT NULL,
  message TEXT NOT NULL,
  attributes_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attributes_json)),
  trace_id TEXT,
  span_id TEXT,
  sensitivity TEXT NOT NULL DEFAULT 'internal' CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  occurred_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_missions_status_updated ON missions(status, updated_at DESC);
CREATE INDEX idx_missions_engagement_updated ON missions(engagement_id, updated_at DESC);
CREATE INDEX idx_targets_mission_disposition ON mission_targets(mission_id, disposition);
CREATE INDEX idx_runs_mission_status_updated ON runs(mission_id, status, updated_at DESC);
CREATE INDEX idx_runs_status_heartbeat ON runs(status, last_heartbeat_at);
CREATE INDEX idx_steps_run_order_status ON plan_steps(run_id, ordinal, status);
CREATE INDEX idx_assignments_run_status ON assignments(run_id, status);
CREATE INDEX idx_assignments_agent_status ON assignments(agent_id, status);
CREATE INDEX idx_actions_step_status ON actions(step_id, status);
CREATE INDEX idx_actions_run_fingerprint ON actions(run_id, fingerprint, created_at DESC);
CREATE INDEX idx_tool_calls_action_status ON tool_calls(action_id, status);
CREATE INDEX idx_guided_decisions_status_created ON guided_decisions(status, created_at DESC);
CREATE INDEX idx_approvals_status_created ON approvals(status, created_at DESC);
CREATE INDEX idx_events_run_sequence ON events(run_id, sequence);
CREATE INDEX idx_events_trace_time ON events(trace_id, occurred_at DESC);
CREATE INDEX idx_events_type_time ON events(event_type, occurred_at DESC);
CREATE INDEX idx_outbox_delivery ON event_outbox(status, available_at, created_at);
CREATE INDEX idx_evidence_mission_type_time ON evidence(mission_id, evidence_type, acquired_at DESC);
CREATE INDEX idx_evidence_hash ON evidence(content_hash);
CREATE INDEX idx_findings_mission_severity_status ON findings(mission_id, severity, review_status);
CREATE INDEX idx_artifacts_mission_type ON artifacts(mission_id, artifact_type, created_at DESC);
CREATE INDEX idx_checkpoints_run_sequence ON checkpoints(run_id, event_sequence DESC);
CREATE INDEX idx_messages_conversation_time ON messages(conversation_id, created_at);
CREATE INDEX idx_provider_turns_run_time ON provider_turns(run_id, started_at DESC);
CREATE INDEX idx_health_component_time ON health_snapshots(component_type, component_id, captured_at DESC);
CREATE INDEX idx_notifications_unread_time ON notifications(read_at, created_at DESC);
CREATE INDEX idx_audit_resource_time ON audit_records(resource_type, resource_id, occurred_at DESC);
CREATE INDEX idx_logs_severity_domain_time ON structured_logs(severity, domain, occurred_at DESC);
CREATE INDEX idx_logs_trace_time ON structured_logs(trace_id, occurred_at DESC);

CREATE TRIGGER events_no_update
BEFORE UPDATE ON events BEGIN
  SELECT RAISE(ABORT, 'events are append-only');
END;
CREATE TRIGGER events_no_delete
BEFORE DELETE ON events BEGIN
  SELECT RAISE(ABORT, 'events are append-only');
END;
CREATE TRIGGER audit_records_no_update
BEFORE UPDATE ON audit_records BEGIN
  SELECT RAISE(ABORT, 'audit records are immutable');
END;
CREATE TRIGGER audit_records_no_delete
BEFORE DELETE ON audit_records BEGIN
  SELECT RAISE(ABORT, 'audit records are immutable');
END;
CREATE TRIGGER evidence_no_update
BEFORE UPDATE ON evidence BEGIN
  SELECT RAISE(ABORT, 'evidence records are immutable');
END;
CREATE TRIGGER evidence_no_delete
BEFORE DELETE ON evidence BEGIN
  SELECT RAISE(ABORT, 'evidence records are immutable');
END;
CREATE TRIGGER findings_require_evidence
BEFORE UPDATE OF review_status ON findings
WHEN NEW.review_status = 'verified' AND NEW.operator_override = 0
  AND NOT EXISTS (SELECT 1 FROM finding_evidence WHERE finding_id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'verified findings require linked evidence');
END;
`,
};

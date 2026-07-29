import type { Migration } from "../types";

/**
 * V2.4 operational-truth domains. This migration is additive: migrations 1–9
 * keep their reviewed checksums and can still be verified independently.
 */
export const v24OperationalTruthMigration: Migration = {
  version: 10,
  name: "v24_operational_truth",
  sql: `
ALTER TABLE missions ADD COLUMN control_plane TEXT NOT NULL DEFAULT 'ti_scale'
  CHECK (control_plane IN ('legacy', 'ti_scale'));
ALTER TABLE runs ADD COLUMN control_plane TEXT NOT NULL DEFAULT 'ti_scale'
  CHECK (control_plane IN ('legacy', 'ti_scale'));

CREATE TABLE control_plane_leases (
  run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
  control_plane TEXT NOT NULL CHECK (control_plane IN ('legacy', 'ti_scale')),
  lease_owner TEXT NOT NULL,
  lease_token_hash TEXT NOT NULL,
  acquired_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  released_at TEXT,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0)
) STRICT;

CREATE TABLE capability_registry_snapshots (
  id TEXT PRIMARY KEY,
  registry_kind TEXT NOT NULL CHECK (registry_kind IN (
    'action_classes', 'evidence_types', 'deliverables', 'mission_templates',
    'agents', 'tools', 'mcp', 'providers', 'models', 'failure_taxonomy'
  )),
  schema_version TEXT NOT NULL,
  source_hash TEXT NOT NULL CHECK (length(source_hash) >= 32),
  source_refs_json TEXT NOT NULL CHECK (json_valid(source_refs_json)),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  captured_at TEXT NOT NULL,
  UNIQUE (registry_kind, source_hash)
) STRICT;

CREATE TABLE engagement_log_records (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  plan_id TEXT REFERENCES plans(id) ON DELETE SET NULL,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  action_id TEXT REFERENCES actions(id) ON DELETE SET NULL,
  attack_attempt_id TEXT,
  asset_id TEXT,
  agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
  provider_turn_id TEXT REFERENCES provider_turns(id) ON DELETE SET NULL,
  tool_call_id TEXT REFERENCES tool_calls(id) ON DELETE SET NULL,
  severity TEXT NOT NULL CHECK (severity IN ('debug', 'info', 'notice', 'warning', 'error', 'critical')),
  domain TEXT NOT NULL,
  record_type TEXT NOT NULL,
  human_summary TEXT NOT NULL,
  technical_payload_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(technical_payload_json)),
  content_hash TEXT NOT NULL CHECK (length(content_hash) >= 32),
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  trace_id TEXT,
  span_id TEXT,
  occurred_at TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE observations (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  asset_id TEXT,
  observation_type TEXT NOT NULL,
  statement TEXT NOT NULL,
  normalized_value_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(normalized_value_json)),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  verification_state TEXT NOT NULL CHECK (verification_state IN ('unverified', 'corroborated', 'conflicting', 'stale', 'rejected')),
  source_agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
  source_tool TEXT,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE observation_log_sources (
  observation_id TEXT NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
  log_record_id TEXT NOT NULL REFERENCES engagement_log_records(id) ON DELETE RESTRICT,
  parser_id TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (observation_id, log_record_id)
) STRICT;

CREATE TABLE evidence_candidates (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  observation_id TEXT REFERENCES observations(id) ON DELETE SET NULL,
  artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
  evidence_type TEXT NOT NULL,
  label TEXT NOT NULL,
  meaning TEXT NOT NULL,
  promotion_reason TEXT NOT NULL,
  validation_requirements_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(validation_requirements_json)),
  state TEXT NOT NULL CHECK (state IN ('candidate', 'validating', 'promoted', 'rejected', 'demoted')),
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  proposed_by TEXT NOT NULL,
  reviewed_by TEXT,
  review_reason TEXT,
  promoted_evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  reviewed_at TEXT
) STRICT;

CREATE TABLE attack_attempts (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  plan_id TEXT REFERENCES plans(id) ON DELETE SET NULL,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  target_asset_id TEXT,
  target_service_id TEXT,
  objective TEXT NOT NULL,
  technique_id TEXT,
  technique_name TEXT NOT NULL,
  action_class TEXT NOT NULL,
  prerequisites_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(prerequisites_json)),
  normalized_parameters_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(normalized_parameters_json)),
  status TEXT NOT NULL CHECK (status IN (
    'planned', 'ready', 'running', 'succeeded', 'failed', 'safely_aborted',
    'blocked', 'waiting_conditions', 'cancelled'
  )),
  outcome_summary TEXT,
  failure_category TEXT,
  failure_diagnosis_id TEXT,
  assigned_agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
  model_assignment_id TEXT,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0)
) STRICT;

CREATE TABLE attack_attempt_evidence (
  attack_attempt_id TEXT NOT NULL REFERENCES attack_attempts(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
  relationship TEXT NOT NULL CHECK (relationship IN ('supports', 'contradicts', 'context', 'outcome')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (attack_attempt_id, evidence_id, relationship)
) STRICT;

CREATE TABLE failure_diagnoses (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  assignment_id TEXT REFERENCES assignments(id) ON DELETE SET NULL,
  action_id TEXT REFERENCES actions(id) ON DELETE SET NULL,
  attack_attempt_id TEXT REFERENCES attack_attempts(id) ON DELETE SET NULL,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('mission', 'run', 'step', 'assignment', 'action', 'attack_attempt')),
  subject_id TEXT NOT NULL,
  human_reason TEXT NOT NULL,
  category TEXT NOT NULL,
  code TEXT NOT NULL,
  originating_component TEXT NOT NULL,
  last_success_event_id TEXT REFERENCES events(id) ON DELETE SET NULL,
  failed_component_ref TEXT,
  target_summary TEXT,
  policy_or_dependency TEXT,
  raw_error_log_id TEXT REFERENCES engagement_log_records(id) ON DELETE SET NULL,
  retry_history_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(retry_history_json)),
  progress_before_failure_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(progress_before_failure_json)),
  preserved_refs_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(preserved_refs_json)),
  retryable INTEGER NOT NULL CHECK (retryable IN (0, 1)),
  automatic_recovery_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(automatic_recovery_json)),
  remediation TEXT NOT NULL,
  operator_actions_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(operator_actions_json)),
  objective_impact TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active', 'resolved', 'superseded', 'terminal')),
  created_at TEXT NOT NULL,
  resolved_at TEXT
) STRICT;

CREATE TABLE run_metrics_snapshots (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  through_event_sequence INTEGER NOT NULL CHECK (through_event_sequence >= 0),
  metric_schema_version TEXT NOT NULL,
  metrics_json TEXT NOT NULL CHECK (json_valid(metrics_json)),
  source_counts_json TEXT NOT NULL CHECK (json_valid(source_counts_json)),
  recomputation_hash TEXT NOT NULL CHECK (length(recomputation_hash) >= 32),
  computed_at TEXT NOT NULL,
  UNIQUE (run_id, through_event_sequence, metric_schema_version)
) STRICT;

CREATE TABLE topology_nodes (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  node_type TEXT NOT NULL,
  primary_label TEXT NOT NULL,
  normalized_identity TEXT NOT NULL,
  scope_status TEXT NOT NULL CHECK (scope_status IN ('allowed', 'prohibited', 'unknown', 'out_of_scope')),
  lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('planned', 'active', 'validated', 'blocked', 'unreachable', 'observed', 'stale')),
  properties_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(properties_json)),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  verification_state TEXT NOT NULL CHECK (verification_state IN ('unverified', 'corroborated', 'verified', 'conflicting', 'stale')),
  originating_agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
  originating_tool TEXT,
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (mission_id, node_type, normalized_identity)
) STRICT;

CREATE TABLE topology_edges (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  source_node_id TEXT NOT NULL REFERENCES topology_nodes(id) ON DELETE CASCADE,
  target_node_id TEXT NOT NULL REFERENCES topology_nodes(id) ON DELETE CASCADE,
  edge_type TEXT NOT NULL,
  properties_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(properties_json)),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  verification_state TEXT NOT NULL CHECK (verification_state IN ('unverified', 'corroborated', 'verified', 'conflicting', 'stale')),
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  CHECK (source_node_id != target_node_id),
  UNIQUE (mission_id, source_node_id, edge_type, target_node_id)
) STRICT;

CREATE TABLE topology_evidence_links (
  subject_type TEXT NOT NULL CHECK (subject_type IN ('node', 'edge')),
  subject_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
  relationship TEXT NOT NULL CHECK (relationship IN ('supports', 'contradicts', 'source')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (subject_type, subject_id, evidence_id, relationship)
) STRICT;

CREATE TABLE asset_layer_observations (
  id TEXT PRIMARY KEY,
  asset_node_id TEXT NOT NULL REFERENCES topology_nodes(id) ON DELETE CASCADE,
  osi_layer INTEGER NOT NULL CHECK (osi_layer BETWEEN 1 AND 7),
  category TEXT NOT NULL,
  value TEXT NOT NULL,
  version_value TEXT,
  derivation TEXT NOT NULL CHECK (derivation IN ('observed', 'actively_verified', 'inferred', 'user_supplied', 'not_observed')),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
  observed_at TEXT NOT NULL,
  conflict_group_id TEXT,
  UNIQUE (asset_node_id, osi_layer, category, value, observed_at)
) STRICT;

CREATE TABLE cve_applicability_records (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  asset_node_id TEXT REFERENCES topology_nodes(id) ON DELETE SET NULL,
  service_node_id TEXT REFERENCES topology_nodes(id) ON DELETE SET NULL,
  cve_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  component TEXT NOT NULL,
  detected_version TEXT,
  affected_range TEXT,
  cpe_or_package_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(cpe_or_package_json)),
  applicability TEXT NOT NULL CHECK (applicability IN ('confirmed', 'likely', 'possible', 'not_applicable', 'insufficient_evidence')),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  reasoning_summary TEXT NOT NULL,
  cvss_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(cvss_json)),
  cwe_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(cwe_json)),
  epss REAL CHECK (epss IS NULL OR (epss >= 0 AND epss <= 1)),
  kev_status TEXT CHECK (kev_status IS NULL OR kev_status IN ('listed', 'not_listed', 'unknown')),
  exploit_maturity TEXT,
  published_at TEXT,
  modified_at TEXT,
  source_links_json TEXT NOT NULL CHECK (json_valid(source_links_json)),
  source_retrieved_at TEXT NOT NULL,
  source_version TEXT,
  discovery_agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
  version_evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (mission_id, cve_id, asset_node_id, service_node_id)
) STRICT;

CREATE TABLE plan_change_requests (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  base_plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
  requested_by TEXT NOT NULL,
  request_text TEXT,
  normalized_change_json TEXT NOT NULL CHECK (json_valid(normalized_change_json)),
  structured_diff_json TEXT NOT NULL CHECK (json_valid(structured_diff_json)),
  affected_refs_json TEXT NOT NULL CHECK (json_valid(affected_refs_json)),
  dependency_impact_json TEXT NOT NULL CHECK (json_valid(dependency_impact_json)),
  policy_validation_json TEXT NOT NULL CHECK (json_valid(policy_validation_json)),
  readiness_impact_json TEXT NOT NULL CHECK (json_valid(readiness_impact_json)),
  budget_impact_json TEXT NOT NULL CHECK (json_valid(budget_impact_json)),
  inflight_impact_json TEXT NOT NULL CHECK (json_valid(inflight_impact_json)),
  status TEXT NOT NULL CHECK (status IN ('proposed', 'validated', 'rejected', 'applied', 'cancelled')),
  result_plan_id TEXT REFERENCES plans(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0)
) STRICT;

CREATE TABLE plan_step_versions (
  id TEXT PRIMARY KEY,
  plan_step_id TEXT NOT NULL REFERENCES plan_steps(id) ON DELETE CASCADE,
  plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version > 0),
  snapshot_json TEXT NOT NULL CHECK (json_valid(snapshot_json)),
  snapshot_hash TEXT NOT NULL CHECK (length(snapshot_hash) >= 32),
  change_request_id TEXT REFERENCES plan_change_requests(id) ON DELETE SET NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (plan_step_id, version)
) STRICT;

CREATE TABLE script_artifacts (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  plan_id TEXT REFERENCES plans(id) ON DELETE SET NULL,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  attack_attempt_id TEXT REFERENCES attack_attempts(id) ON DELETE SET NULL,
  target_node_id TEXT REFERENCES topology_nodes(id) ON DELETE SET NULL,
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  language TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  content_hash TEXT NOT NULL CHECK (length(content_hash) >= 32),
  layman_explanation TEXT NOT NULL,
  technical_purpose TEXT NOT NULL,
  inputs_json TEXT NOT NULL CHECK (json_valid(inputs_json)),
  expected_outputs_json TEXT NOT NULL CHECK (json_valid(expected_outputs_json)),
  prerequisites_json TEXT NOT NULL CHECK (json_valid(prerequisites_json)),
  touches_json TEXT NOT NULL CHECK (json_valid(touches_json)),
  side_effects_json TEXT NOT NULL CHECK (json_valid(side_effects_json)),
  cleanup_notes TEXT NOT NULL,
  secrets_handling TEXT NOT NULL,
  evidence_expectations_json TEXT NOT NULL CHECK (json_valid(evidence_expectations_json)),
  validation_state TEXT NOT NULL CHECK (validation_state IN ('unvalidated', 'linted', 'tested', 'approved', 'rejected')),
  test_artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (mission_id, name, version)
) STRICT;

CREATE TABLE page_captures (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE SET NULL,
  asset_node_id TEXT REFERENCES topology_nodes(id) ON DELETE SET NULL,
  service_node_id TEXT REFERENCES topology_nodes(id) ON DELETE SET NULL,
  normalized_url TEXT NOT NULL,
  response_status INTEGER CHECK (response_status IS NULL OR response_status BETWEEN 100 AND 599),
  title TEXT,
  viewport_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(viewport_json)),
  screenshot_artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
  full_page_artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
  content_hash TEXT NOT NULL CHECK (length(content_hash) >= 32),
  certificate_metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(certificate_metadata_json)),
  captured_by_agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
  capture_tool TEXT NOT NULL,
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  redaction_state TEXT NOT NULL CHECK (redaction_state IN ('not_required', 'pending', 'redacted', 'quarantined')),
  captured_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (mission_id, normalized_url, content_hash)
) STRICT;

CREATE TABLE model_configurations (
  id TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  returned_model_id TEXT,
  reasoning_effort TEXT,
  context_policy_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(context_policy_json)),
  capabilities_json TEXT NOT NULL CHECK (json_valid(capabilities_json)),
  context_limit INTEGER CHECK (context_limit IS NULL OR context_limit > 0),
  cost_class TEXT NOT NULL CHECK (cost_class IN ('low', 'standard', 'high', 'unknown')),
  latency_class TEXT NOT NULL CHECK (latency_class IN ('fast', 'standard', 'slow', 'unknown')),
  disclosure_class TEXT NOT NULL CHECK (disclosure_class IN ('public_only', 'sanitized_internal', 'local_only', 'unavailable')),
  enforcement_mode TEXT NOT NULL CHECK (enforcement_mode IN ('enforced', 'observe_only', 'advisory_only', 'unavailable')),
  auth_state TEXT NOT NULL CHECK (auth_state IN ('healthy', 'missing', 'expired', 'degraded', 'unknown')),
  health_state TEXT NOT NULL CHECK (health_state IN ('healthy', 'degraded', 'offline', 'unknown')),
  catalog_source TEXT NOT NULL,
  catalog_retrieved_at TEXT NOT NULL,
  configuration_source TEXT NOT NULL CHECK (configuration_source IN ('inherited', 'recommended', 'manual', 'research_verified')),
  prompt_template_hash TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  UNIQUE (provider_id, model_id, version)
) STRICT;

CREATE TABLE agent_model_assignments (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  mission_id TEXT REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES runs(id) ON DELETE CASCADE,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE CASCADE,
  primary_configuration_id TEXT NOT NULL REFERENCES model_configurations(id) ON DELETE RESTRICT,
  fallback_configuration_id TEXT REFERENCES model_configurations(id) ON DELETE RESTRICT,
  inheritance_level TEXT NOT NULL CHECK (inheritance_level IN ('global', 'agent', 'mission', 'run', 'step')),
  pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
  resolution_reason TEXT NOT NULL,
  resolved_at TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE provider_exposure_receipts (
  id TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  provider_turn_id TEXT REFERENCES provider_turns(id) ON DELETE SET NULL,
  mission_id TEXT REFERENCES missions(id) ON DELETE SET NULL,
  run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
  experiment_id TEXT,
  disclosure_policy_version TEXT NOT NULL,
  input_classification TEXT NOT NULL,
  selected_context_ids_json TEXT NOT NULL CHECK (json_valid(selected_context_ids_json)),
  rejected_context_ids_json TEXT NOT NULL CHECK (json_valid(rejected_context_ids_json)),
  sanitization_actions_json TEXT NOT NULL CHECK (json_valid(sanitization_actions_json)),
  untrusted_content_envelope_hash TEXT,
  exposed_payload_hash TEXT NOT NULL CHECK (length(exposed_payload_hash) >= 32),
  blocked INTEGER NOT NULL CHECK (blocked IN (0, 1)),
  block_reason TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE research_campaigns (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  purpose TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('draft', 'approved', 'running', 'paused', 'completed', 'stopped', 'rejected')),
  owner TEXT NOT NULL,
  budgets_json TEXT NOT NULL CHECK (json_valid(budgets_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE research_charters (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES research_campaigns(id) ON DELETE RESTRICT,
  version INTEGER NOT NULL CHECK (version > 0),
  immutable_scope_json TEXT NOT NULL CHECK (json_valid(immutable_scope_json)),
  mutable_dimensions_json TEXT NOT NULL CHECK (json_valid(mutable_dimensions_json)),
  forbidden_paths_json TEXT NOT NULL CHECK (json_valid(forbidden_paths_json)),
  budgets_json TEXT NOT NULL CHECK (json_valid(budgets_json)),
  charter_hash TEXT NOT NULL CHECK (length(charter_hash) >= 32),
  approved_by TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  UNIQUE (campaign_id, version)
) STRICT;

CREATE TABLE research_dimensions (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES research_campaigns(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  schema_path TEXT NOT NULL,
  trials INTEGER NOT NULL DEFAULT 0 CHECK (trials >= 0),
  mean_improvement REAL NOT NULL DEFAULT 0,
  variance REAL NOT NULL DEFAULT 0 CHECK (variance >= 0),
  failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
  safety_failure_count INTEGER NOT NULL DEFAULT 0 CHECK (safety_failure_count >= 0),
  last_attempted_at TEXT,
  UNIQUE (campaign_id, name)
) STRICT;

CREATE TABLE strategy_versions (
  id TEXT PRIMARY KEY,
  campaign_id TEXT REFERENCES research_campaigns(id) ON DELETE SET NULL,
  parent_id TEXT REFERENCES strategy_versions(id) ON DELETE RESTRICT,
  version INTEGER NOT NULL CHECK (version > 0),
  bundle_json TEXT NOT NULL CHECK (json_valid(bundle_json)),
  bundle_hash TEXT NOT NULL CHECK (length(bundle_hash) >= 32),
  status TEXT NOT NULL CHECK (status IN (
    'proposed', 'policy_rejected', 'queued', 'running', 'early_aborted', 'failed',
    'benchmarked', 'holdout_failed', 'shadow_ready', 'shadow_running',
    'canary_ready', 'canary_running', 'verified', 'rejected', 'stale',
    'superseded', 'rolled_back'
  )),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (campaign_id, version)
) STRICT;

CREATE TABLE strategy_patches (
  id TEXT PRIMARY KEY,
  strategy_version_id TEXT NOT NULL REFERENCES strategy_versions(id) ON DELETE CASCADE,
  base_strategy_version_id TEXT NOT NULL REFERENCES strategy_versions(id) ON DELETE RESTRICT,
  json_patch_json TEXT NOT NULL CHECK (json_valid(json_patch_json)),
  policy_validation_json TEXT NOT NULL CHECK (json_valid(policy_validation_json)),
  patch_hash TEXT NOT NULL CHECK (length(patch_hash) >= 32),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE benchmark_families (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  evaluator_version TEXT NOT NULL,
  hard_gates_json TEXT NOT NULL CHECK (json_valid(hard_gates_json)),
  metrics_json TEXT NOT NULL CHECK (json_valid(metrics_json)),
  promotion_criteria_json TEXT NOT NULL CHECK (json_valid(promotion_criteria_json)),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE benchmark_scenarios (
  id TEXT PRIMARY KEY,
  family_id TEXT NOT NULL REFERENCES benchmark_families(id) ON DELETE CASCADE,
  split TEXT NOT NULL CHECK (split IN ('development', 'validation', 'hidden_holdout')),
  name TEXT NOT NULL,
  scenario_hash TEXT NOT NULL CHECK (length(scenario_hash) >= 32),
  ground_truth_ref TEXT NOT NULL,
  environment_digest TEXT NOT NULL,
  budget_json TEXT NOT NULL CHECK (json_valid(budget_json)),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL,
  UNIQUE (family_id, split, scenario_hash)
) STRICT;

CREATE TABLE benchmark_snapshots (
  id TEXT PRIMARY KEY,
  family_id TEXT NOT NULL REFERENCES benchmark_families(id) ON DELETE RESTRICT,
  evaluator_hash TEXT NOT NULL CHECK (length(evaluator_hash) >= 32),
  scenario_set_hash TEXT NOT NULL CHECK (length(scenario_set_hash) >= 32),
  tool_manifest_hash TEXT NOT NULL CHECK (length(tool_manifest_hash) >= 32),
  snapshot_hash TEXT NOT NULL CHECK (length(snapshot_hash) >= 32),
  created_at TEXT NOT NULL,
  UNIQUE (family_id, snapshot_hash)
) STRICT;

CREATE TABLE experiments (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES research_campaigns(id) ON DELETE RESTRICT,
  charter_id TEXT NOT NULL REFERENCES research_charters(id) ON DELETE RESTRICT,
  dimension_id TEXT NOT NULL REFERENCES research_dimensions(id) ON DELETE RESTRICT,
  baseline_strategy_id TEXT NOT NULL REFERENCES strategy_versions(id) ON DELETE RESTRICT,
  candidate_strategy_id TEXT NOT NULL REFERENCES strategy_versions(id) ON DELETE RESTRICT,
  benchmark_snapshot_id TEXT NOT NULL REFERENCES benchmark_snapshots(id) ON DELETE RESTRICT,
  hypothesis TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'proposed', 'policy_rejected', 'queued', 'running', 'early_aborted', 'failed',
    'benchmarked', 'holdout_failed', 'shadow_ready', 'shadow_running',
    'canary_ready', 'canary_running', 'verified', 'rejected', 'stale',
    'superseded', 'rolled_back'
  )),
  public_llm_spec_hash TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE experiment_runs (
  id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
  scenario_id TEXT NOT NULL REFERENCES benchmark_scenarios(id) ON DELETE RESTRICT,
  seed TEXT NOT NULL,
  worker_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'early_aborted')),
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (experiment_id, scenario_id, seed)
) STRICT;

CREATE TABLE experiment_metrics (
  id TEXT PRIMARY KEY,
  experiment_run_id TEXT NOT NULL REFERENCES experiment_runs(id) ON DELETE CASCADE,
  metric_name TEXT NOT NULL,
  metric_value REAL NOT NULL,
  unit TEXT NOT NULL,
  direction TEXT NOT NULL CHECK (direction IN ('higher_better', 'lower_better', 'gate')),
  authoritative INTEGER NOT NULL CHECK (authoritative IN (0, 1)),
  evaluator_version TEXT NOT NULL,
  computed_at TEXT NOT NULL,
  UNIQUE (experiment_run_id, metric_name, evaluator_version)
) STRICT;

CREATE TABLE experiment_events (
  id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
  experiment_run_id TEXT REFERENCES experiment_runs(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  event_type TEXT NOT NULL,
  summary TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'internal', 'private', 'restricted')),
  occurred_at TEXT NOT NULL,
  UNIQUE (experiment_id, sequence)
) STRICT;

CREATE TABLE experiment_failures (
  id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
  experiment_run_id TEXT REFERENCES experiment_runs(id) ON DELETE SET NULL,
  gate_code TEXT,
  category TEXT NOT NULL,
  human_reason TEXT NOT NULL,
  evidence_refs_json TEXT NOT NULL CHECK (json_valid(evidence_refs_json)),
  terminal INTEGER NOT NULL CHECK (terminal IN (0, 1)),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE near_misses (
  id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
  dimension_id TEXT NOT NULL REFERENCES research_dimensions(id) ON DELETE RESTRICT,
  mechanism TEXT NOT NULL,
  improvement_json TEXT NOT NULL CHECK (json_valid(improvement_json)),
  regression_json TEXT NOT NULL CHECK (json_valid(regression_json)),
  retrieval_tags_json TEXT NOT NULL CHECK (json_valid(retrieval_tags_json)),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE integrity_receipts (
  id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL REFERENCES experiments(id) ON DELETE RESTRICT,
  charter_hash TEXT NOT NULL,
  strategy_hashes_json TEXT NOT NULL CHECK (json_valid(strategy_hashes_json)),
  evaluator_hash TEXT NOT NULL,
  benchmark_snapshot_hash TEXT NOT NULL,
  container_image_digest TEXT NOT NULL,
  tool_manifest_hash TEXT NOT NULL,
  provider_model_json TEXT NOT NULL CHECK (json_valid(provider_model_json)),
  context_pack_ids_json TEXT NOT NULL CHECK (json_valid(context_pack_ids_json)),
  random_seeds_json TEXT NOT NULL CHECK (json_valid(random_seeds_json)),
  event_hash TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  metrics_hash TEXT NOT NULL,
  exposure_receipt_ids_json TEXT NOT NULL CHECK (json_valid(exposure_receipt_ids_json)),
  signature TEXT NOT NULL,
  signed_at TEXT NOT NULL,
  UNIQUE (experiment_id, signature)
) STRICT;

CREATE TABLE promotion_reviews (
  id TEXT PRIMARY KEY,
  strategy_version_id TEXT NOT NULL REFERENCES strategy_versions(id) ON DELETE RESTRICT,
  from_stage TEXT NOT NULL,
  to_stage TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('advance', 'reject', 'rollback')),
  reviewer TEXT NOT NULL,
  rationale TEXT NOT NULL,
  evidence_refs_json TEXT NOT NULL CHECK (json_valid(evidence_refs_json)),
  decided_at TEXT NOT NULL
) STRICT;

CREATE TABLE strategy_deployments (
  id TEXT PRIMARY KEY,
  strategy_version_id TEXT NOT NULL REFERENCES strategy_versions(id) ON DELETE RESTRICT,
  deployment_stage TEXT NOT NULL CHECK (deployment_stage IN ('shadow', 'canary', 'verified')),
  scope_json TEXT NOT NULL CHECK (json_valid(scope_json)),
  status TEXT NOT NULL CHECK (status IN ('ready', 'running', 'completed', 'stopped', 'rolled_back')),
  approved_by TEXT NOT NULL,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE strategy_rollbacks (
  id TEXT PRIMARY KEY,
  deployment_id TEXT NOT NULL REFERENCES strategy_deployments(id) ON DELETE RESTRICT,
  from_strategy_id TEXT NOT NULL REFERENCES strategy_versions(id) ON DELETE RESTRICT,
  to_strategy_id TEXT NOT NULL REFERENCES strategy_versions(id) ON DELETE RESTRICT,
  reason TEXT NOT NULL,
  initiated_by TEXT NOT NULL,
  integrity_verified INTEGER NOT NULL CHECK (integrity_verified IN (0, 1)),
  rolled_back_at TEXT NOT NULL
) STRICT;

CREATE TABLE research_context_packs (
  id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL,
  disclosure_policy_version TEXT NOT NULL,
  context_hash TEXT NOT NULL CHECK (length(context_hash) >= 32),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE research_context_items (
  context_pack_id TEXT NOT NULL REFERENCES research_context_packs(id) ON DELETE CASCADE,
  memory_node_id TEXT REFERENCES memory_nodes(id) ON DELETE SET NULL,
  selected INTEGER NOT NULL CHECK (selected IN (0, 1)),
  reason_category TEXT NOT NULL,
  relevance REAL NOT NULL CHECK (relevance >= 0 AND relevance <= 1),
  disclosure_class TEXT NOT NULL,
  PRIMARY KEY (context_pack_id, memory_node_id, reason_category)
) STRICT;

CREATE INDEX idx_control_plane_leases_plane_expiry ON control_plane_leases(control_plane, expires_at);
CREATE INDEX idx_registry_kind_time ON capability_registry_snapshots(registry_kind, captured_at DESC);
CREATE INDEX idx_engagement_logs_run_time ON engagement_log_records(run_id, occurred_at DESC);
CREATE INDEX idx_engagement_logs_domain_severity_time ON engagement_log_records(domain, severity, occurred_at DESC);
CREATE INDEX idx_observations_mission_type_time ON observations(mission_id, observation_type, last_seen_at DESC);
CREATE INDEX idx_evidence_candidates_mission_state_time ON evidence_candidates(mission_id, state, created_at DESC);
CREATE INDEX idx_attack_attempts_run_status_time ON attack_attempts(run_id, status, updated_at DESC);
CREATE INDEX idx_attack_attempts_target_technique ON attack_attempts(target_asset_id, technique_id, status);
CREATE INDEX idx_failure_diagnoses_run_state_time ON failure_diagnoses(run_id, state, created_at DESC);
CREATE INDEX idx_failure_diagnoses_category_code ON failure_diagnoses(category, code, created_at DESC);
CREATE INDEX idx_run_metrics_latest ON run_metrics_snapshots(run_id, through_event_sequence DESC);
CREATE INDEX idx_topology_nodes_mission_type_state ON topology_nodes(mission_id, node_type, lifecycle_state);
CREATE INDEX idx_topology_edges_source_type_target ON topology_edges(source_node_id, edge_type, target_node_id);
CREATE INDEX idx_topology_edges_target_type_source ON topology_edges(target_node_id, edge_type, source_node_id);
CREATE INDEX idx_asset_layers_asset_layer ON asset_layer_observations(asset_node_id, osi_layer);
CREATE INDEX idx_cve_applicability_asset_state ON cve_applicability_records(asset_node_id, applicability, cve_id);
CREATE INDEX idx_plan_changes_run_status_time ON plan_change_requests(run_id, status, created_at DESC);
CREATE INDEX idx_scripts_mission_step_time ON script_artifacts(mission_id, step_id, created_at DESC);
CREATE INDEX idx_page_captures_asset_time ON page_captures(asset_node_id, captured_at DESC);
CREATE INDEX idx_model_config_provider_health ON model_configurations(provider_id, enforcement_mode, health_state);
CREATE INDEX idx_agent_model_resolved ON agent_model_assignments(agent_id, mission_id, run_id, step_id, resolved_at DESC);
CREATE INDEX idx_exposure_receipts_mission_time ON provider_exposure_receipts(mission_id, created_at DESC);
CREATE INDEX idx_research_campaign_status_time ON research_campaigns(status, updated_at DESC);
CREATE INDEX idx_strategy_status_time ON strategy_versions(status, created_at DESC);
CREATE INDEX idx_experiments_campaign_status_time ON experiments(campaign_id, status, updated_at DESC);
CREATE INDEX idx_experiment_runs_experiment_status ON experiment_runs(experiment_id, status);
CREATE INDEX idx_experiment_events_experiment_sequence ON experiment_events(experiment_id, sequence);
CREATE INDEX idx_near_misses_dimension_time ON near_misses(dimension_id, created_at DESC);
CREATE INDEX idx_promotions_strategy_time ON promotion_reviews(strategy_version_id, decided_at DESC);
`,
};

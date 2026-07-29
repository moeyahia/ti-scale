import type { Migration } from "../types";

/**
 * Closes the remaining mutation and deletion paths in the durable Research
 * record. Mutable status projections retain their reviewed state transitions;
 * benchmark definitions, candidate bytes, evaluator results, failures, and
 * provenance ledgers are append-only.
 *
 * This forward-only migration creates no backup, snapshot copy, archive, or
 * duplicate database.
 */
export const researchHistoryIntegrityMigration: Migration = {
  version: 55,
  name: "research_history_integrity",
  sql: String.raw`
CREATE TRIGGER trg_research_admission_binding_nonnull_update
BEFORE UPDATE ON research_experiment_admissions
WHEN
  OLD.execution_authorization_hash <> 'legacy_unverified'
  AND (
    NEW.worker_process_id IS NULL
    OR NEW.worker_process_start_ticks IS NULL
    OR length(trim(NEW.worker_process_start_ticks)) = 0
    OR NEW.worker_process_id IS NOT OLD.worker_process_id
    OR NEW.worker_process_start_ticks IS NOT OLD.worker_process_start_ticks
  )
BEGIN
  SELECT RAISE(
    ABORT,
    'Research admission worker identity is immutable and non-null'
  );
END;

CREATE TRIGGER trg_research_campaign_binding_update
BEFORE UPDATE ON research_campaigns
WHEN
  NEW.id IS NOT OLD.id
  OR NEW.name IS NOT OLD.name
  OR NEW.purpose IS NOT OLD.purpose
  OR NEW.owner IS NOT OLD.owner
  OR NEW.budgets_json IS NOT OLD.budgets_json
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
  SELECT RAISE(
    ABORT,
    'Research campaign ownership, charter inputs, and creation identity are immutable'
  );
END;

CREATE TRIGGER trg_research_dimension_binding_update
BEFORE UPDATE ON research_dimensions
WHEN
  NEW.id IS NOT OLD.id
  OR NEW.campaign_id IS NOT OLD.campaign_id
  OR NEW.name IS NOT OLD.name
  OR NEW.schema_path IS NOT OLD.schema_path
BEGIN
  SELECT RAISE(
    ABORT,
    'Research dimension identity and mutable strategy path are immutable'
  );
END;

CREATE TRIGGER trg_research_strategy_binding_update
BEFORE UPDATE ON strategy_versions
WHEN
  NEW.id IS NOT OLD.id
  OR NEW.campaign_id IS NOT OLD.campaign_id
  OR NEW.parent_id IS NOT OLD.parent_id
  OR NEW.version IS NOT OLD.version
  OR NEW.bundle_json IS NOT OLD.bundle_json
  OR NEW.bundle_hash IS NOT OLD.bundle_hash
  OR NEW.created_by IS NOT OLD.created_by
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
  SELECT RAISE(
    ABORT,
    'Research strategy bytes and provenance are immutable'
  );
END;

CREATE TRIGGER trg_research_experiment_binding_update
BEFORE UPDATE ON experiments
WHEN
  NEW.id IS NOT OLD.id
  OR NEW.campaign_id IS NOT OLD.campaign_id
  OR NEW.charter_id IS NOT OLD.charter_id
  OR NEW.dimension_id IS NOT OLD.dimension_id
  OR NEW.baseline_strategy_id IS NOT OLD.baseline_strategy_id
  OR NEW.candidate_strategy_id IS NOT OLD.candidate_strategy_id
  OR NEW.benchmark_snapshot_id IS NOT OLD.benchmark_snapshot_id
  OR NEW.hypothesis IS NOT OLD.hypothesis
  OR NEW.public_llm_spec_hash IS NOT OLD.public_llm_spec_hash
  OR NEW.created_by IS NOT OLD.created_by
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
  SELECT RAISE(
    ABORT,
    'Research experiment charter, strategy, evaluator, and proposal bindings are immutable'
  );
END;

CREATE TRIGGER trg_research_charter_no_update
BEFORE UPDATE ON research_charters
BEGIN
  SELECT RAISE(ABORT, 'Research charters are immutable');
END;

CREATE TRIGGER trg_research_patch_no_update
BEFORE UPDATE ON strategy_patches
BEGIN
  SELECT RAISE(ABORT, 'Research strategy patches are immutable');
END;

CREATE TRIGGER trg_research_benchmark_family_no_update
BEFORE UPDATE ON benchmark_families
BEGIN
  SELECT RAISE(ABORT, 'Research benchmark families are immutable');
END;

CREATE TRIGGER trg_research_benchmark_scenario_no_update
BEFORE UPDATE ON benchmark_scenarios
BEGIN
  SELECT RAISE(ABORT, 'Research benchmark scenarios are immutable');
END;

CREATE TRIGGER trg_research_metric_no_update
BEFORE UPDATE ON experiment_metrics
BEGIN
  SELECT RAISE(ABORT, 'Research evaluator metrics are immutable');
END;

CREATE TRIGGER trg_research_event_no_update
BEFORE UPDATE ON experiment_events
BEGIN
  SELECT RAISE(ABORT, 'Research experiment events are append-only');
END;

CREATE TRIGGER trg_research_failure_no_update
BEFORE UPDATE ON experiment_failures
BEGIN
  SELECT RAISE(ABORT, 'Research experiment failures are append-only');
END;

CREATE TRIGGER trg_research_near_miss_no_update
BEFORE UPDATE ON near_misses
BEGIN
  SELECT RAISE(ABORT, 'Research near misses are append-only');
END;

CREATE TRIGGER trg_research_context_pack_no_update
BEFORE UPDATE ON research_context_packs
BEGIN
  SELECT RAISE(ABORT, 'Research context packs are immutable');
END;

CREATE TRIGGER trg_research_context_item_no_update
BEFORE UPDATE ON research_context_items
BEGIN
  SELECT RAISE(ABORT, 'Research context items are immutable');
END;

CREATE TRIGGER trg_research_campaign_no_delete
BEFORE DELETE ON research_campaigns
BEGIN
  SELECT RAISE(ABORT, 'Research campaigns cannot be deleted');
END;

CREATE TRIGGER trg_research_charter_no_delete
BEFORE DELETE ON research_charters
BEGIN
  SELECT RAISE(ABORT, 'Research charters cannot be deleted');
END;

CREATE TRIGGER trg_research_dimension_no_delete
BEFORE DELETE ON research_dimensions
BEGIN
  SELECT RAISE(ABORT, 'Research dimensions cannot be deleted');
END;

CREATE TRIGGER trg_research_strategy_no_delete
BEFORE DELETE ON strategy_versions
BEGIN
  SELECT RAISE(ABORT, 'Research strategy versions cannot be deleted');
END;

CREATE TRIGGER trg_research_patch_no_delete
BEFORE DELETE ON strategy_patches
BEGIN
  SELECT RAISE(ABORT, 'Research strategy patches cannot be deleted');
END;

CREATE TRIGGER trg_research_benchmark_family_no_delete
BEFORE DELETE ON benchmark_families
BEGIN
  SELECT RAISE(ABORT, 'Research benchmark families cannot be deleted');
END;

CREATE TRIGGER trg_research_benchmark_scenario_no_delete
BEFORE DELETE ON benchmark_scenarios
BEGIN
  SELECT RAISE(ABORT, 'Research benchmark scenarios cannot be deleted');
END;

CREATE TRIGGER trg_research_experiment_no_delete
BEFORE DELETE ON experiments
BEGIN
  SELECT RAISE(ABORT, 'Research experiments cannot be deleted');
END;

CREATE TRIGGER trg_research_run_no_delete
BEFORE DELETE ON experiment_runs
BEGIN
  SELECT RAISE(ABORT, 'Research experiment runs cannot be deleted');
END;

CREATE TRIGGER trg_research_metric_no_delete
BEFORE DELETE ON experiment_metrics
BEGIN
  SELECT RAISE(ABORT, 'Research evaluator metrics cannot be deleted');
END;

CREATE TRIGGER trg_research_event_no_delete
BEFORE DELETE ON experiment_events
BEGIN
  SELECT RAISE(ABORT, 'Research experiment events cannot be deleted');
END;

CREATE TRIGGER trg_research_failure_no_delete
BEFORE DELETE ON experiment_failures
BEGIN
  SELECT RAISE(ABORT, 'Research experiment failures cannot be deleted');
END;

CREATE TRIGGER trg_research_near_miss_no_delete
BEFORE DELETE ON near_misses
BEGIN
  SELECT RAISE(ABORT, 'Research near misses cannot be deleted');
END;

CREATE TRIGGER trg_research_context_pack_no_delete
BEFORE DELETE ON research_context_packs
BEGIN
  SELECT RAISE(ABORT, 'Research context packs cannot be deleted');
END;

CREATE TRIGGER trg_research_context_item_no_delete
BEFORE DELETE ON research_context_items
BEGIN
  SELECT RAISE(ABORT, 'Research context items cannot be deleted');
END;

CREATE TRIGGER trg_research_promotion_lifecycle_no_delete
BEFORE DELETE ON research_promotion_lifecycles
BEGIN
  SELECT RAISE(ABORT, 'Research promotion lifecycles cannot be deleted');
END;
`,
};

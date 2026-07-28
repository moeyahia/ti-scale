import type { Migration } from "../types";

/**
 * A provider turn must be attributable to the exact product agent and pinned
 * model assignment that selected it.  These columns are nullable for imported
 * and pre-v2.4.8 history, but new runtime code writes the complete binding.
 *
 * The partial unique index also closes a race in first-use Guided assignment
 * pinning without rewriting immutable historical assignment receipts.
 */
export const providerTurnAgentBindingMigration: Migration = {
  version: 48,
  name: "provider_turn_agent_binding",
  sql: String.raw`
ALTER TABLE provider_turns ADD COLUMN agent_id TEXT
  REFERENCES agents(id) ON DELETE SET NULL;

ALTER TABLE provider_turns ADD COLUMN model_assignment_id TEXT
  REFERENCES agent_model_assignments(id) ON DELETE SET NULL;

ALTER TABLE provider_turns ADD COLUMN model_configuration_id TEXT
  REFERENCES model_configurations(id) ON DELETE SET NULL;

ALTER TABLE provider_turns ADD COLUMN model_assignment_configuration_hash TEXT
  CHECK (
    model_assignment_configuration_hash IS NULL
    OR (
      length(model_assignment_configuration_hash) = 64
      AND model_assignment_configuration_hash NOT GLOB '*[^0-9a-f]*'
    )
  );

ALTER TABLE provider_turns ADD COLUMN prompt_template_hash TEXT
  CHECK (
    prompt_template_hash IS NULL
    OR (
      length(prompt_template_hash) = 64
      AND prompt_template_hash NOT GLOB '*[^0-9a-f]*'
    )
  );

ALTER TABLE provider_turns ADD COLUMN context_pack_id TEXT
  REFERENCES memory_context_packs(id) ON DELETE SET NULL;

CREATE INDEX idx_provider_turns_agent_time
  ON provider_turns(agent_id, started_at DESC, id DESC)
  WHERE agent_id IS NOT NULL;

CREATE INDEX idx_provider_turns_model_assignment
  ON provider_turns(model_assignment_id, started_at DESC, id DESC)
  WHERE model_assignment_id IS NOT NULL;

CREATE INDEX idx_provider_turns_context_pack
  ON provider_turns(context_pack_id, started_at DESC, id DESC)
  WHERE context_pack_id IS NOT NULL;

CREATE UNIQUE INDEX idx_agent_model_assignments_pinned_scope
  ON agent_model_assignments(
    agent_id,
    ifnull(mission_id, ''),
    ifnull(run_id, ''),
    ifnull(step_id, '')
  )
  WHERE pinned = 1;
`,
};

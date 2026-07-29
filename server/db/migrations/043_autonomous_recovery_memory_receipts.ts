import type { Migration } from "../types";

/** Durable proof of exactly which retrieved memory changed a recovery decision. */
export const autonomousRecoveryMemoryReceiptsMigration: Migration = {
  version: 43,
  name: "autonomous_recovery_memory_receipts",
  sql: String.raw`
CREATE TABLE recovery_memory_decision_receipts (
  id TEXT PRIMARY KEY,
  schema_version TEXT NOT NULL,
  compiler_version TEXT NOT NULL,
  hook TEXT NOT NULL CHECK (hook IN ('failure', 'replan')),
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
  step_id TEXT NOT NULL REFERENCES plan_steps(id) ON DELETE CASCADE,
  context_pack_id TEXT NOT NULL REFERENCES memory_context_packs(id) ON DELETE RESTRICT,
  failure_category TEXT NOT NULL,
  baseline_decision_json TEXT NOT NULL CHECK (json_valid(baseline_decision_json)),
  resolved_decision_json TEXT NOT NULL CHECK (json_valid(resolved_decision_json)),
  effects_json TEXT NOT NULL CHECK (json_valid(effects_json)),
  candidate_node_ids_json TEXT NOT NULL CHECK (json_valid(candidate_node_ids_json)),
  applied_node_ids_json TEXT NOT NULL CHECK (json_valid(applied_node_ids_json)),
  ignored_node_ids_json TEXT NOT NULL CHECK (json_valid(ignored_node_ids_json)),
  ignored_reasons_json TEXT NOT NULL CHECK (json_valid(ignored_reasons_json)),
  receipt_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  UNIQUE (action_id, context_pack_id, hook)
) STRICT;

CREATE INDEX idx_recovery_memory_receipts_run_created
  ON recovery_memory_decision_receipts(run_id, created_at DESC, id);
CREATE INDEX idx_recovery_memory_receipts_context
  ON recovery_memory_decision_receipts(context_pack_id, created_at DESC, id);
`,
};

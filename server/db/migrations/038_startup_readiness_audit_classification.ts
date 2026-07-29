import type { Migration } from "../types";

/**
 * Content-free provider readiness probes are durable operational audit, but
 * they are not operator/mission state. Classify the three linked records
 * explicitly so release rollback drift checks can ignore only this tightly
 * constrained telemetry lineage while retaining every schema and normal row.
 */
export const startupReadinessAuditClassificationMigration: Migration = {
  version: 38,
  name: "startup_readiness_audit_classification",
  requiresVerifiedBackup: true,
  sql: String.raw`
ALTER TABLE provider_turns ADD COLUMN release_data_class TEXT NOT NULL DEFAULT 'canonical'
  CHECK (release_data_class IN ('canonical', 'startup_readiness'));
ALTER TABLE memory_context_packs ADD COLUMN release_data_class TEXT NOT NULL DEFAULT 'canonical'
  CHECK (release_data_class IN ('canonical', 'startup_readiness'));
ALTER TABLE provider_exposure_receipts ADD COLUMN release_data_class TEXT NOT NULL DEFAULT 'canonical'
  CHECK (release_data_class IN ('canonical', 'startup_readiness'));

CREATE INDEX idx_provider_turns_release_data_class
  ON provider_turns(release_data_class, started_at, id);
CREATE INDEX idx_memory_context_packs_release_data_class
  ON memory_context_packs(release_data_class, created_at, id);
CREATE INDEX idx_provider_exposure_receipts_release_data_class
  ON provider_exposure_receipts(release_data_class, created_at, id);

CREATE TRIGGER startup_readiness_provider_turn_insert_guard
BEFORE INSERT ON provider_turns
WHEN NEW.release_data_class = 'startup_readiness'
  AND (
    NEW.id NOT LIKE 'provider-readiness-%'
    OR NEW.provider IS NOT 'openrouter'
    OR NEW.run_id IS NOT NULL
    OR NEW.conversation_id IS NOT NULL
    OR NEW.message_id IS NOT NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'startup readiness provider turn classification is invalid');
END;

CREATE TRIGGER startup_readiness_provider_turn_class_immutable
BEFORE UPDATE OF release_data_class ON provider_turns
WHEN OLD.release_data_class IS NOT NEW.release_data_class
BEGIN
  SELECT RAISE(ABORT, 'provider turn release data classification is immutable');
END;

CREATE TRIGGER startup_readiness_provider_turn_update_guard
BEFORE UPDATE ON provider_turns
WHEN OLD.release_data_class = 'startup_readiness'
  AND (
    NEW.release_data_class IS NOT 'startup_readiness'
    OR NEW.id NOT LIKE 'provider-readiness-%'
    OR NEW.provider IS NOT 'openrouter'
    OR NEW.run_id IS NOT NULL
    OR NEW.conversation_id IS NOT NULL
    OR NEW.message_id IS NOT NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'startup readiness provider turn classification is invalid');
END;

CREATE TRIGGER startup_readiness_context_pack_insert_guard
BEFORE INSERT ON memory_context_packs
WHEN NEW.release_data_class = 'startup_readiness'
  AND (
    NEW.mission_id IS NOT NULL
    OR NEW.run_id IS NOT NULL
    OR NEW.step_id IS NOT NULL
    OR NEW.action_id IS NOT NULL
    OR NEW.message_id IS NOT NULL
    OR NEW.journey IS NOT 'guided'
    OR NEW.purpose IS NOT 'Content-free public-provider readiness audit'
    OR NEW.query_redacted IS NOT 'content-free readiness acknowledgement'
    OR NEW.context_budget IS NOT 0
    OR NEW.scope_policy_json IS NOT '{"allowGlobal":false,"allowedStatuses":["confirmed","verified"],"contextBudget":0,"exactNodeIds":[],"exactNodeIdsOnly":true,"graphDepth":0,"journey":"guided","maximumSensitivity":"public"}'
    OR NEW.retrieval_metrics_json IS NOT '{"retrievedCount":0,"source":"openrouter-content-free-readiness"}'
    OR NEW.created_by IS NOT 'openrouter-readiness-monitor'
  )
BEGIN
  SELECT RAISE(ABORT, 'startup readiness context pack classification is invalid');
END;

CREATE TRIGGER startup_readiness_context_pack_class_immutable
BEFORE UPDATE OF release_data_class ON memory_context_packs
WHEN OLD.release_data_class IS NOT NEW.release_data_class
BEGIN
  SELECT RAISE(ABORT, 'context pack release data classification is immutable');
END;

CREATE TRIGGER startup_readiness_context_pack_update_guard
BEFORE UPDATE ON memory_context_packs
WHEN OLD.release_data_class = 'startup_readiness'
  AND (
    NEW.release_data_class IS NOT 'startup_readiness'
    OR NEW.mission_id IS NOT NULL
    OR NEW.run_id IS NOT NULL
    OR NEW.step_id IS NOT NULL
    OR NEW.action_id IS NOT NULL
    OR NEW.message_id IS NOT NULL
    OR NEW.journey IS NOT 'guided'
    OR NEW.purpose IS NOT 'Content-free public-provider readiness audit'
    OR NEW.query_redacted IS NOT 'content-free readiness acknowledgement'
    OR NEW.context_budget IS NOT 0
    OR NEW.scope_policy_json IS NOT '{"allowGlobal":false,"allowedStatuses":["confirmed","verified"],"contextBudget":0,"exactNodeIds":[],"exactNodeIdsOnly":true,"graphDepth":0,"journey":"guided","maximumSensitivity":"public"}'
    OR NEW.retrieval_metrics_json IS NOT '{"retrievedCount":0,"source":"openrouter-content-free-readiness"}'
    OR NEW.created_by IS NOT 'openrouter-readiness-monitor'
  )
BEGIN
  SELECT RAISE(ABORT, 'startup readiness context pack classification is invalid');
END;

CREATE TRIGGER startup_readiness_context_items_forbidden
BEFORE INSERT ON memory_context_items
WHEN EXISTS (
  SELECT 1 FROM memory_context_packs pack
  WHERE pack.id = NEW.context_pack_id
    AND pack.release_data_class = 'startup_readiness'
)
BEGIN
  SELECT RAISE(ABORT, 'startup readiness context packs cannot contain memory items');
END;

CREATE TRIGGER startup_readiness_exposure_receipt_insert_guard
BEFORE INSERT ON provider_exposure_receipts
WHEN NEW.release_data_class = 'startup_readiness'
  AND (
    NEW.provider_id IS NOT 'openrouter'
    OR NEW.mission_id IS NOT NULL
    OR NEW.run_id IS NOT NULL
    OR NEW.experiment_id IS NOT NULL
    OR NEW.disclosure_policy_version IS NOT 'brain-provider-context-v1'
    OR NEW.input_classification IS NOT 'public'
    OR NEW.selected_context_ids_json IS NOT '[]'
    OR NEW.rejected_context_ids_json IS NOT '[]'
    OR NEW.sanitization_actions_json IS NOT '[]'
    OR NEW.blocked IS NOT 0
    OR NEW.block_reason IS NOT NULL
    OR NEW.provider_turn_id IS NULL
    OR NEW.context_pack_id IS NULL
    OR NOT EXISTS (
      SELECT 1 FROM provider_turns turn
      WHERE turn.id = NEW.provider_turn_id
        AND turn.release_data_class = 'startup_readiness'
    )
    OR NOT EXISTS (
      SELECT 1 FROM memory_context_packs pack
      WHERE pack.id = NEW.context_pack_id
        AND pack.release_data_class = 'startup_readiness'
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'startup readiness exposure receipt classification is invalid');
END;

CREATE TRIGGER startup_readiness_exposure_receipt_class_immutable
BEFORE UPDATE OF release_data_class ON provider_exposure_receipts
WHEN OLD.release_data_class IS NOT NEW.release_data_class
BEGIN
  SELECT RAISE(ABORT, 'provider exposure release data classification is immutable');
END;

CREATE TRIGGER startup_readiness_exposure_receipt_update_guard
BEFORE UPDATE ON provider_exposure_receipts
WHEN OLD.release_data_class = 'startup_readiness'
  AND (
    NEW.release_data_class IS NOT 'startup_readiness'
    OR NEW.provider_id IS NOT 'openrouter'
    OR NEW.mission_id IS NOT NULL
    OR NEW.run_id IS NOT NULL
    OR NEW.experiment_id IS NOT NULL
    OR NEW.disclosure_policy_version IS NOT 'brain-provider-context-v1'
    OR NEW.input_classification IS NOT 'public'
    OR NEW.selected_context_ids_json IS NOT '[]'
    OR NEW.rejected_context_ids_json IS NOT '[]'
    OR NEW.sanitization_actions_json IS NOT '[]'
    OR NEW.blocked IS NOT 0
    OR NEW.block_reason IS NOT NULL
    OR NEW.provider_turn_id IS NULL
    OR NEW.context_pack_id IS NULL
    OR NOT EXISTS (
      SELECT 1 FROM provider_turns turn
      WHERE turn.id = NEW.provider_turn_id
        AND turn.release_data_class = 'startup_readiness'
    )
    OR NOT EXISTS (
      SELECT 1 FROM memory_context_packs pack
      WHERE pack.id = NEW.context_pack_id
        AND pack.release_data_class = 'startup_readiness'
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'startup readiness exposure receipt classification is invalid');
END;
`,
};

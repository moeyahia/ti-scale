import type { Migration } from "../types";

/**
 * One activation receipt may bind a lifecycle subject only once. The runtime
 * already treats a repeated subject as an idempotent read or a conflict; this
 * index makes that invariant race-safe at the canonical database boundary.
 */
export const autonomousActivationBindingSubjectUniquenessMigration:
Migration = {
  version: 60,
  name: "autonomous_activation_binding_subject_uniqueness",
  sql: String.raw`
CREATE UNIQUE INDEX idx_autonomous_activation_binding_subject
  ON autonomous_activation_bindings(
    receipt_id, binding_type, subject_id
  );
`,
};

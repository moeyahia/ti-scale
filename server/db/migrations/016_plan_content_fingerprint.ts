import type { Migration } from "../types";

/**
 * Separate semantic plan equivalence from immutable version identity.
 *
 * `plan_hash` is retained as the unique receipt for one exact persisted plan
 * version. `content_hash` is deliberately non-unique so a reviewed rollback
 * may recreate an older strategy after an intervening version while runtime
 * loop detection can still reject an immediately equivalent replan.
 *
 * Existing rows used `plan_hash` as their content fingerprint. Version zero
 * records that provenance so the runtime can recompute the normalized current
 * fingerprint from canonical plan records before comparing a new replan.
 */
export const planContentFingerprintMigration: Migration = {
  version: 16,
  name: "plan_content_fingerprint",
  sql: `
ALTER TABLE plans ADD COLUMN content_hash TEXT
  CHECK (content_hash IS NULL OR length(content_hash) = 64);

ALTER TABLE plans ADD COLUMN content_hash_version INTEGER NOT NULL DEFAULT 0
  CHECK (content_hash_version IN (0, 1));

UPDATE plans SET content_hash = plan_hash WHERE content_hash IS NULL;

CREATE INDEX idx_plans_run_content_hash
  ON plans(run_id, content_hash, version);
`,
};

import type { Migration } from "../types";

/**
 * Bind each public-provider dispatch to the exact canonical request body and
 * the already-started provider turn/Brain disclosure receipt. Existing
 * receipts remain historical and cannot authorize a new dispatch until every
 * authorization column is populated transactionally.
 */
export const providerRequestAuthorizationMigration: Migration = {
  version: 15,
  name: "provider_request_authorization",
  sql: `
ALTER TABLE provider_turns ADD COLUMN model_configuration_hash TEXT
  CHECK (model_configuration_hash IS NULL OR length(model_configuration_hash) = 64);

ALTER TABLE provider_exposure_receipts ADD COLUMN context_pack_id TEXT
  REFERENCES memory_context_packs(id) ON DELETE SET NULL;

ALTER TABLE provider_exposure_receipts ADD COLUMN model_configuration_hash TEXT
  CHECK (model_configuration_hash IS NULL OR length(model_configuration_hash) = 64);

ALTER TABLE provider_exposure_receipts ADD COLUMN request_body_hash TEXT
  CHECK (request_body_hash IS NULL OR length(request_body_hash) = 64);

ALTER TABLE provider_exposure_receipts ADD COLUMN request_body_bytes INTEGER
  CHECK (request_body_bytes IS NULL OR request_body_bytes > 0);

ALTER TABLE provider_exposure_receipts ADD COLUMN request_contract_version TEXT;
ALTER TABLE provider_exposure_receipts ADD COLUMN request_endpoint TEXT;
ALTER TABLE provider_exposure_receipts ADD COLUMN request_authorized_at TEXT;

CREATE UNIQUE INDEX idx_provider_exposure_turn_authorized
  ON provider_exposure_receipts(provider_turn_id)
  WHERE request_authorized_at IS NOT NULL;

CREATE INDEX idx_provider_exposure_request_hash
  ON provider_exposure_receipts(request_body_hash)
  WHERE request_body_hash IS NOT NULL;
`,
};

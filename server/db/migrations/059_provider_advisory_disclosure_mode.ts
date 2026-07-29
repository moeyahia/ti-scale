import type { Migration } from "../types";

/**
 * Bind advisor-only planning disclosures to the exact mode signed in the
 * Autonomous contract. Nullable columns preserve historical Brain, Guided and
 * Research Lab receipts; the advisory policy namespace must populate all
 * fields together and may never mutate them after insertion.
 */
export const providerAdvisoryDisclosureModeMigration: Migration = {
  version: 59,
  name: "provider_advisory_disclosure_mode",
  sql: String.raw`
ALTER TABLE provider_exposure_receipts
  ADD COLUMN advisory_planning_request_id TEXT
  CHECK (
    advisory_planning_request_id IS NULL
    OR length(trim(advisory_planning_request_id)) BETWEEN 1 AND 240
  );

ALTER TABLE provider_exposure_receipts
  ADD COLUMN planning_disclosure_mode TEXT
  CHECK (
    planning_disclosure_mode IS NULL
    OR planning_disclosure_mode IN ('public_only', 'sanitized_internal')
  );

ALTER TABLE provider_exposure_receipts
  ADD COLUMN advisory_identity_hash TEXT
  CHECK (
    advisory_identity_hash IS NULL
    OR (
      length(advisory_identity_hash) = 64
      AND advisory_identity_hash NOT GLOB '*[^0-9a-f]*'
    )
  );

CREATE UNIQUE INDEX idx_provider_advisory_identity_hash
  ON provider_exposure_receipts(advisory_identity_hash)
  WHERE advisory_identity_hash IS NOT NULL;

CREATE INDEX idx_provider_advisory_planning_mode
  ON provider_exposure_receipts(
    planning_disclosure_mode, request_authorized_at, created_at
  )
  WHERE planning_disclosure_mode IS NOT NULL;

CREATE TRIGGER provider_advisory_disclosure_identity_required
BEFORE INSERT ON provider_exposure_receipts
WHEN NEW.disclosure_policy_version = 'autonomous-planning-exposure-v1'
  AND (
    NEW.advisory_planning_request_id IS NULL
    OR NEW.planning_disclosure_mode IS NULL
    OR NEW.advisory_identity_hash IS NULL
    OR NEW.mission_id IS NULL
    OR NEW.run_id IS NULL
    OR NEW.context_pack_id IS NULL
    OR NEW.provider_turn_id IS NULL
    OR NEW.model_configuration_hash IS NULL
    OR NEW.release_data_class IS NOT 'canonical'
  )
BEGIN
  SELECT RAISE(ABORT, 'Provider advisory receipts require an exact signed disclosure identity');
END;

CREATE TRIGGER non_advisory_disclosure_identity_forbidden
BEFORE INSERT ON provider_exposure_receipts
WHEN NEW.disclosure_policy_version <> 'autonomous-planning-exposure-v1'
  AND (
    NEW.advisory_planning_request_id IS NOT NULL
    OR NEW.planning_disclosure_mode IS NOT NULL
    OR NEW.advisory_identity_hash IS NOT NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'Non-advisory receipts cannot claim a planning disclosure identity');
END;

CREATE TRIGGER provider_advisory_disclosure_identity_immutable
BEFORE UPDATE OF
  advisory_planning_request_id, planning_disclosure_mode,
  advisory_identity_hash
ON provider_exposure_receipts
WHEN OLD.advisory_planning_request_id IS NOT NEW.advisory_planning_request_id
  OR OLD.planning_disclosure_mode IS NOT NEW.planning_disclosure_mode
  OR OLD.advisory_identity_hash IS NOT NEW.advisory_identity_hash
BEGIN
  SELECT RAISE(ABORT, 'Provider advisory disclosure identity is immutable');
END;
`,
};

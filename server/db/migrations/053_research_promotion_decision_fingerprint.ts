import type { Migration } from "../types";

/**
 * Bind every new human promotion transition to the exact normalized decision
 * that produced it. Existing rows remain readable without a fingerprint; the
 * response-loss reconciler treats those legacy rows as unattributable.
 *
 * This migration is forward-only and creates no backup, snapshot, copy, or
 * archive.
 */
export const researchPromotionDecisionFingerprintMigration: Migration = {
  version: 53,
  name: "research_promotion_decision_fingerprint",
  sql: String.raw`
ALTER TABLE research_promotion_transitions
  ADD COLUMN decision_fingerprint TEXT
  CHECK (
    decision_fingerprint IS NULL
    OR (
      length(decision_fingerprint) = 64
      AND decision_fingerprint NOT GLOB '*[^0-9a-f]*'
    )
  );

CREATE INDEX idx_research_promotion_decision_fingerprint
  ON research_promotion_transitions(
    experiment_id,
    lifecycle_version,
    decision_fingerprint
  );

CREATE TRIGGER trg_research_promotion_decision_fingerprint_insert
BEFORE INSERT ON research_promotion_transitions
BEGIN
  SELECT CASE WHEN (
    NEW.actor_kind = 'human_reviewer'
    AND NEW.decision_fingerprint IS NULL
  ) OR (
    NEW.actor_kind <> 'human_reviewer'
    AND NEW.decision_fingerprint IS NOT NULL
  )
  THEN RAISE(
    ABORT,
    'Research human decision fingerprint binding is invalid'
  ) END;
END;
`,
};

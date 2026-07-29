import type { Migration } from "../types";

/**
 * Human applicability review is independent from automated CVE discovery.
 *
 * The canonical record carries only the current review projection and a
 * monotonic compare-and-swap version. Every accepted decision is retained in
 * an immutable receipt that is bound to both the hash-linked audit trail and
 * the durable run event/outbox stream.
 */
export const cveApplicabilityReviewLifecycleMigration: Migration = {
  version: 49,
  name: "cve_applicability_review_lifecycle",
  sql: String.raw`
ALTER TABLE cve_applicability_records ADD COLUMN review_state TEXT NOT NULL
  DEFAULT 'unreviewed'
  CHECK (
    review_state IN (
      'unreviewed',
      'confirmed',
      'not_applicable',
      'more_evidence_requested'
    )
  );

ALTER TABLE cve_applicability_records ADD COLUMN review_version INTEGER NOT NULL
  DEFAULT 0
  CHECK (review_version >= 0);

CREATE TABLE cve_applicability_review_receipts (
  id TEXT PRIMARY KEY,
  cve_applicability_id TEXT NOT NULL
    REFERENCES cve_applicability_records(id) ON DELETE RESTRICT,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  review_version INTEGER NOT NULL CHECK (review_version > 0),
  decision TEXT NOT NULL CHECK (
    decision IN (
      'confirm_applicability',
      'mark_not_applicable',
      'request_more_evidence'
    )
  ),
  previous_applicability TEXT NOT NULL CHECK (
    previous_applicability IN (
      'confirmed',
      'likely',
      'possible',
      'not_applicable',
      'insufficient_evidence'
    )
  ),
  resulting_applicability TEXT NOT NULL CHECK (
    resulting_applicability IN (
      'confirmed',
      'not_applicable',
      'insufficient_evidence'
    )
  ),
  reason TEXT NOT NULL CHECK (
    length(trim(reason)) BETWEEN 3 AND 4000
  ),
  actor_type TEXT NOT NULL CHECK (
    actor_type IN ('operator', 'agent', 'worker', 'system')
  ),
  actor_id TEXT NOT NULL CHECK (
    length(trim(actor_id)) BETWEEN 1 AND 240
  ),
  expected_record_updated_at TEXT NOT NULL CHECK (
    length(trim(expected_record_updated_at)) > 0
  ),
  audit_record_id TEXT NOT NULL UNIQUE
    REFERENCES audit_records(id) ON DELETE RESTRICT,
  event_id TEXT NOT NULL UNIQUE REFERENCES events(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
  UNIQUE (cve_applicability_id, review_version)
) STRICT;

CREATE INDEX idx_cve_review_receipts_mission_time
  ON cve_applicability_review_receipts(
    mission_id,
    created_at DESC,
    id DESC
  );

CREATE INDEX idx_cve_review_receipts_run_time
  ON cve_applicability_review_receipts(
    run_id,
    created_at DESC,
    id DESC
  );

CREATE TRIGGER trg_cve_review_receipt_scope
BEFORE INSERT ON cve_applicability_review_receipts
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1
      FROM cve_applicability_records record
      JOIN runs run ON run.id = NEW.run_id
      WHERE record.id = NEW.cve_applicability_id
        AND record.mission_id = NEW.mission_id
        AND record.run_id = NEW.run_id
        AND run.mission_id = NEW.mission_id
    )
    THEN RAISE(
      ABORT,
      'CVE review receipt scope does not match its record'
    )
  END;

  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1
      FROM audit_records audit
      WHERE audit.id = NEW.audit_record_id
        AND audit.mission_id = NEW.mission_id
        AND audit.run_id = NEW.run_id
        AND audit.resource_type = 'cve_applicability_review'
        AND audit.resource_id = NEW.id
    )
    THEN RAISE(
      ABORT,
      'CVE review receipt audit evidence does not match'
    )
  END;

  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1
      FROM events event
      WHERE event.id = NEW.event_id
        AND event.mission_id = NEW.mission_id
        AND event.run_id = NEW.run_id
        AND event.event_type = 'cve_applicability_reviewed'
    )
    THEN RAISE(
      ABORT,
      'CVE review receipt event evidence does not match'
    )
  END;
END;

CREATE TRIGGER trg_cve_review_receipt_immutable_update
BEFORE UPDATE ON cve_applicability_review_receipts
BEGIN
  SELECT RAISE(ABORT, 'CVE review receipts are immutable');
END;

CREATE TRIGGER trg_cve_review_receipt_immutable_delete
BEFORE DELETE ON cve_applicability_review_receipts
BEGIN
  SELECT RAISE(ABORT, 'CVE review receipts are immutable');
END;
`,
};

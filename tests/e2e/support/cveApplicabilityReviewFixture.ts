import { CveApplicabilityService } from "../../../server/cve-intelligence/CveApplicabilityService";
import { acquireTestRunMutationAuthority } from "../../../server/control-plane/TestRunMutationAuthority";
import {
  createDatabaseConnection,
  type SqliteDatabase,
} from "../../../server/db";
import { E2E_DATABASE_PATH } from "./environment";

export interface CveApplicabilityReviewFixtureScope {
  readonly missionId: string;
  readonly runId: string;
  readonly cveRecordId: string;
}

export interface CveApplicabilityReviewFixtureSnapshot {
  readonly record: {
    readonly applicability: string;
    readonly reviewState: string;
    readonly reviewVersion: number;
    readonly updatedAt: string;
  };
  readonly receipts: readonly {
    readonly id: string;
    readonly reviewVersion: number;
    readonly decision: string;
    readonly reason: string;
    readonly auditRecordId: string;
    readonly eventId: string;
    readonly auditAction: string;
    readonly auditResourceType: string;
    readonly auditResourceId: string;
    readonly eventType: string;
    readonly outboxId: string;
    readonly outboxEventId: string;
    readonly outboxTopic: string;
    readonly outboxStatus: string;
    readonly outboxAttemptCount: number;
    readonly outboxClaimedBy: string | null;
    readonly outboxClaimedAt: string | null;
    readonly outboxDeliveredAt: string | null;
    readonly outboxLastError: string | null;
  }[];
}

function database(): SqliteDatabase {
  if (!E2E_DATABASE_PATH) {
    throw new Error("The isolated Playwright database path was not configured");
  }
  return createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
}

export function authorizeCveApplicabilityReviewFixture(
  connection: SqliteDatabase,
  runId: string,
): void {
  acquireTestRunMutationAuthority(connection, runId);
}

/**
 * Advance the same canonical record through the real domain service while the
 * browser intentionally retains its older projection. This creates a durable,
 * mission-scoped optimistic-concurrency fixture without intercepting the
 * rejected mutation or editing production state directly.
 */
export function commitCompetingCveApplicabilityReview(
  fixture: CveApplicabilityReviewFixtureScope,
): {
  readonly receiptId: string;
  readonly reviewVersion: number;
  readonly updatedAt: string;
} {
  const connection = database();
  try {
    authorizeCveApplicabilityReviewFixture(connection, fixture.runId);
    const service = new CveApplicabilityService(connection);
    const current = service.get(fixture.cveRecordId);
    if (
      current.missionId !== fixture.missionId
      || current.runId !== fixture.runId
    ) {
      throw new Error("The competing CVE review fixture escaped its mission/run scope");
    }
    const result = service.review({
      missionId: fixture.missionId,
      recordId: fixture.cveRecordId,
      expectedRunId: fixture.runId,
      decision: "mark_not_applicable",
      reason: "A concurrent operator reviewed the retained version comparison and marked this exact candidate not applicable.",
      expectedReviewVersion: current.reviewVersion,
      expectedUpdatedAt: current.updatedAt,
    }, {
      type: "operator",
      id: "e2e-competing-cve-reviewer",
    });
    return {
      receiptId: result.receipt.id,
      reviewVersion: result.record.reviewVersion,
      updatedAt: result.record.updatedAt,
    };
  } finally {
    connection.close();
  }
}

export function readCveApplicabilityReviewFixtureSnapshot(
  fixture: CveApplicabilityReviewFixtureScope,
): CveApplicabilityReviewFixtureSnapshot {
  const connection = database();
  try {
    const record = connection.prepare(`
      SELECT applicability, review_state, review_version, updated_at
      FROM cve_applicability_records
      WHERE id = ? AND mission_id = ? AND run_id = ?
    `).get(
      fixture.cveRecordId,
      fixture.missionId,
      fixture.runId,
    ) as {
      applicability: string;
      review_state: string;
      review_version: number;
      updated_at: string;
    } | undefined;
    if (!record) {
      throw new Error(`CVE applicability fixture is missing: ${fixture.cveRecordId}`);
    }
    const receipts = connection.prepare(`
      SELECT
        receipt.id,
        receipt.review_version,
        receipt.decision,
        receipt.reason,
        receipt.audit_record_id,
        receipt.event_id,
        audit.action AS audit_action,
        audit.resource_type AS audit_resource_type,
        audit.resource_id AS audit_resource_id,
        event.event_type,
        outbox.id AS outbox_id,
        outbox.event_id AS outbox_event_id,
        outbox.topic AS outbox_topic,
        outbox.status AS outbox_status,
        outbox.attempt_count AS outbox_attempt_count,
        outbox.claimed_by AS outbox_claimed_by,
        outbox.claimed_at AS outbox_claimed_at,
        outbox.delivered_at AS outbox_delivered_at,
        outbox.last_error AS outbox_last_error
      FROM cve_applicability_review_receipts receipt
      JOIN audit_records audit ON audit.id = receipt.audit_record_id
      JOIN events event ON event.id = receipt.event_id
      JOIN event_outbox outbox ON outbox.event_id = event.id
      WHERE receipt.cve_applicability_id = ?
        AND receipt.mission_id = ?
        AND receipt.run_id = ?
      ORDER BY receipt.review_version, receipt.id
    `).all(
      fixture.cveRecordId,
      fixture.missionId,
      fixture.runId,
    ) as Array<{
      id: string;
      review_version: number;
      decision: string;
      reason: string;
      audit_record_id: string;
      event_id: string;
      audit_action: string;
      audit_resource_type: string;
      audit_resource_id: string;
      event_type: string;
      outbox_id: string;
      outbox_event_id: string;
      outbox_topic: string;
      outbox_status: string;
      outbox_attempt_count: number;
      outbox_claimed_by: string | null;
      outbox_claimed_at: string | null;
      outbox_delivered_at: string | null;
      outbox_last_error: string | null;
    }>;
    return {
      record: {
        applicability: record.applicability,
        reviewState: record.review_state,
        reviewVersion: record.review_version,
        updatedAt: record.updated_at,
      },
      receipts: receipts.map((receipt) => ({
        id: receipt.id,
        reviewVersion: receipt.review_version,
        decision: receipt.decision,
        reason: receipt.reason,
        auditRecordId: receipt.audit_record_id,
        eventId: receipt.event_id,
        auditAction: receipt.audit_action,
        auditResourceType: receipt.audit_resource_type,
        auditResourceId: receipt.audit_resource_id,
        eventType: receipt.event_type,
        outboxId: receipt.outbox_id,
        outboxEventId: receipt.outbox_event_id,
        outboxTopic: receipt.outbox_topic,
        outboxStatus: receipt.outbox_status,
        outboxAttemptCount: receipt.outbox_attempt_count,
        outboxClaimedBy: receipt.outbox_claimed_by,
        outboxClaimedAt: receipt.outbox_claimed_at,
        outboxDeliveredAt: receipt.outbox_delivered_at,
        outboxLastError: receipt.outbox_last_error,
      })),
    };
  } finally {
    connection.close();
  }
}

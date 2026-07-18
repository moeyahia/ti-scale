import { acquireTestRunMutationAuthority } from "../../../server/control-plane/TestRunMutationAuthority";
import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { OperationalTruthService } from "../../../server/intelligence-v24/OperationalTruthService";
import { hashCanonical } from "../../../server/missions/canonical";
import { MissionRepository } from "../../../server/missions/MissionRepository";
import { validateMissionCreateRequest } from "../../../server/missions/validation";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_START_MS = Date.parse("2026-07-16T13:00:00.000Z");
const PAGE_FIXTURE_COUNT = 26;

export const OPERATIONAL_TRUTH_MAIN_LABEL = "HTTPS service exposure";
export const OPERATIONAL_TRUTH_MAIN_SUMMARY = "The authorized target exposed TCP port 443 during the assessment window.";
export const OPERATIONAL_TRUTH_REJECT_LABEL = "Uncorroborated response-header claim";
export const OPERATIONAL_TRUTH_ADDITIONAL_REQUIREMENT = "second_source_corroborated";
export const OPERATIONAL_TRUTH_REDACTED_SECRET = "fixture-secret-that-must-never-render";

export interface OperationalTruthFixture {
  readonly missionId: string;
  readonly runId: string;
  readonly mainLogId: string;
  readonly mainObservationId: string;
  readonly mainCandidateId: string;
  readonly rejectCandidateId: string;
  readonly seededVerifiedEvidenceCount: number;
}

export interface OperationalTruthCandidateSnapshot {
  readonly id: string;
  readonly state: string;
  readonly reviewedBy: string | null;
  readonly reviewReason: string | null;
  readonly promotedEvidenceId: string | null;
}

export interface OperationalTruthEvidenceSnapshot {
  readonly id: string;
  readonly source: string;
  readonly target: string;
  readonly confidence: number;
  readonly contentHash: string;
  readonly verificationState: string;
  readonly summary: string;
  readonly createdBy: string;
  readonly provenance: unknown;
}

export interface OperationalTruthCustodySnapshot {
  readonly eventType: string;
  readonly actor: string;
  readonly occurredAt: string;
  readonly details: unknown;
}

export interface OperationalTruthAuditSnapshot {
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId: string | null;
  readonly actorId: string | null;
  readonly reason: string | null;
  readonly recordHash: string;
}

export interface OperationalTruthSnapshot {
  readonly mainCandidate: OperationalTruthCandidateSnapshot;
  readonly rejectCandidate: OperationalTruthCandidateSnapshot;
  readonly totalEvidenceCount: number;
  readonly mainEvidence?: OperationalTruthEvidenceSnapshot;
  readonly custody: readonly OperationalTruthCustodySnapshot[];
  readonly audits: readonly OperationalTruthAuditSnapshot[];
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("The isolated Playwright database path was not configured");
  return E2E_DATABASE_PATH;
}

function fixtureTimestamp(index: number): string {
  return new Date(FIXTURE_START_MS + index * 1_000).toISOString();
}

export function createOperationalTruthFixture(instanceId: string): OperationalTruthFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const request = validateMissionCreateRequest({
      journey: "guided",
      launch: true,
      authorizationConfirmed: true,
      title: "Operational truth evidence-gate browser fixture",
      objective: "Review attributable reconnaissance records and independently verify only evidence that passes the canonical gate.",
      target: "https://operational-truth.example.test",
      explanationDepth: "balanced",
      executionPreference: "manual",
      evidenceExpectations: ["Immutable provenance and complete chain of custody"],
    });
    const created = inImmediateTransaction(database, () => {
      const mission = new MissionRepository(database).create({
        request,
        requestHash: hashCanonical(request),
        idempotencyKey: `operational-truth-e2e-${namespace}`,
        actorId: "e2e-local-operator",
      });
      // Publish the disposable run and its trusted E2E controller authority
      // atomically. Otherwise the standalone runtime's 500 ms scheduler can
      // claim the planning run between mission commit and fixture setup,
      // correctly fencing the later browser mutation with HTTP 409.
      acquireTestRunMutationAuthority(database, mission.run.id);
      return mission;
    });

    let idSequence = 0;
    let clockSequence = 0;
    const truth = new OperationalTruthService(database, {
      clock: () => new Date(FIXTURE_START_MS + clockSequence++ * 1_000),
      idFactory: (prefix) => `${prefix}_truth_e2e_${namespace}_${String(++idSequence).padStart(5, "0")}`,
    });

    for (let index = 0; index < PAGE_FIXTURE_COUNT; index += 1) {
      const observedAt = fixtureTimestamp(index);
      const log = truth.appendEngagementLog({
        missionId: created.mission.id,
        runId: created.run.id,
        severity: "info",
        domain: "fixture.pagination",
        recordType: "structured_scan_result",
        humanSummary: `Pagination fixture service observation ${String(index + 1).padStart(2, "0")}.`,
        technicalPayload: { target: `198.51.100.${index + 1}`, port: 10_000 + index, state: "open" },
        sensitivity: "internal",
        occurredAt: observedAt,
      });
      const observation = truth.createObservation({
        missionId: created.mission.id,
        runId: created.run.id,
        observationType: "pagination_service",
        statement: `Fixture service ${String(index + 1).padStart(2, "0")} was observed for cursor pagination.`,
        normalizedValue: { target: `198.51.100.${index + 1}`, port: 10_000 + index, transport: "tcp" },
        confidence: 0.9,
        verificationState: "corroborated",
        sourceTool: "fixture-structured-parser",
        firstSeenAt: observedAt,
        lastSeenAt: observedAt,
        sensitivity: "internal",
        sources: [{ logRecordId: log.id, parserId: "fixture-parser", parserVersion: "2.4.0" }],
      });
      const candidate = truth.proposeEvidenceCandidate({
        missionId: created.mission.id,
        runId: created.run.id,
        observationId: observation.id,
        evidenceType: "service_discovery_proof",
        label: `Pagination evidence ${String(index + 1).padStart(2, "0")}`,
        meaning: `Verified pagination evidence record ${String(index + 1).padStart(2, "0")}.`,
        promotionReason: "The deterministic fixture requires more than one canonical cursor page in every truth stage.",
        additionalValidationRequirements: [],
        sensitivity: "internal",
        proposedBy: `fixture-agent-${namespace}`,
      });
      const reviewer = { id: `fixture-reviewer-${namespace}`, type: "operator" as const };
      truth.promoteCandidate({
        candidateId: candidate.id,
        actor: reviewer,
        reason: "Begin independent fixture validation for cursor pagination coverage.",
      });
      truth.verifyCandidate({
        candidateId: candidate.id,
        actor: reviewer,
        reason: "The fixture source, target, provenance, immutable hash, and custody were independently reviewed.",
        source: "Deterministic operational-truth pagination fixture",
        target: `198.51.100.${index + 1}:${10_000 + index}/tcp`,
        acquiredAt: observedAt,
        confidence: 0.9,
        provenance: {
          method: "Structured fixture observation with independent review",
          explanation: "The retained log and normalized observation provide attributable local pagination evidence.",
          sources: [
            { kind: "observation", id: observation.id },
            { kind: "engagement_log", id: log.id },
          ],
        },
        custody: [{
          eventType: "acquired",
          actor: `fixture-collector-${namespace}`,
          occurredAt: observedAt,
          details: { fixture: "cursor-pagination", index },
        }],
        satisfiedAdditionalRequirements: [],
      });
    }

    const mainObservedAt = fixtureTimestamp(PAGE_FIXTURE_COUNT + 1);
    const mainLog = truth.appendEngagementLog({
      missionId: created.mission.id,
      runId: created.run.id,
      severity: "notice",
      domain: "recon.service-discovery",
      recordType: "structured_scan_result",
      humanSummary: "Authorized reconnaissance observed HTTPS on TCP port 443; this remains a technical log until reviewed.",
      technicalPayload: {
        target: "operational-truth.example.test",
        port: 443,
        transport: "tcp",
        state: "open",
        apiToken: OPERATIONAL_TRUTH_REDACTED_SECRET,
      },
      sensitivity: "restricted",
      occurredAt: mainObservedAt,
    });
    const mainObservation = truth.createObservation({
      missionId: created.mission.id,
      runId: created.run.id,
      observationType: "service_exposure",
      statement: "TCP port 443 appeared open on the authorized target.",
      normalizedValue: {
        target: "operational-truth.example.test:443/tcp",
        port: 443,
        transport: "tcp",
        service: "https",
      },
      confidence: 0.85,
      verificationState: "corroborated",
      sourceTool: "normalized-recon-parser",
      firstSeenAt: mainObservedAt,
      lastSeenAt: mainObservedAt,
      sensitivity: "restricted",
      sources: [{ logRecordId: mainLog.id, parserId: "service-exposure-parser", parserVersion: "2.4.0" }],
    });
    const mainCandidate = truth.proposeEvidenceCandidate({
      missionId: created.mission.id,
      runId: created.run.id,
      observationId: mainObservation.id,
      evidenceType: "port_service_scan_result",
      label: OPERATIONAL_TRUTH_MAIN_LABEL,
      meaning: OPERATIONAL_TRUTH_MAIN_SUMMARY,
      promotionReason: "The structured observation may support a service-exposure claim after independent corroboration and custody review.",
      additionalValidationRequirements: [OPERATIONAL_TRUTH_ADDITIONAL_REQUIREMENT],
      sensitivity: "restricted",
      proposedBy: `fixture-recon-agent-${namespace}`,
    });
    const rejectCandidate = truth.proposeEvidenceCandidate({
      missionId: created.mission.id,
      runId: created.run.id,
      observationId: mainObservation.id,
      evidenceType: "unverified_header_claim",
      label: OPERATIONAL_TRUTH_REJECT_LABEL,
      meaning: "A single response header may identify an application product without sufficient corroboration.",
      promotionReason: "The fixture preserves a plausible but deliberately insufficient claim for audited rejection.",
      additionalValidationRequirements: ["independent_product_confirmation"],
      sensitivity: "internal",
      proposedBy: `fixture-web-agent-${namespace}`,
    });

    return {
      missionId: created.mission.id,
      runId: created.run.id,
      mainLogId: mainLog.id,
      mainObservationId: mainObservation.id,
      mainCandidateId: mainCandidate.id,
      rejectCandidateId: rejectCandidate.id,
      seededVerifiedEvidenceCount: PAGE_FIXTURE_COUNT,
    };
  } finally {
    database.close();
  }
}

export function readOperationalTruthSnapshot(fixture: OperationalTruthFixture): OperationalTruthSnapshot {
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const readCandidate = (id: string): OperationalTruthCandidateSnapshot => {
      const row = database.prepare(`
        SELECT id, state, reviewed_by, review_reason, promoted_evidence_id
        FROM evidence_candidates WHERE id = ?
      `).get(id) as {
        readonly id: string;
        readonly state: string;
        readonly reviewed_by: string | null;
        readonly review_reason: string | null;
        readonly promoted_evidence_id: string | null;
      } | undefined;
      if (!row) throw new Error(`Operational-truth candidate ${id} is missing`);
      return {
        id: row.id,
        state: row.state,
        reviewedBy: row.reviewed_by,
        reviewReason: row.review_reason,
        promotedEvidenceId: row.promoted_evidence_id,
      };
    };
    const mainCandidate = readCandidate(fixture.mainCandidateId);
    const rejectCandidate = readCandidate(fixture.rejectCandidateId);
    const countRow = database.prepare("SELECT COUNT(*) AS count FROM evidence WHERE mission_id = ?")
      .get(fixture.missionId) as { readonly count: number };
    const evidenceRow = mainCandidate.promotedEvidenceId
      ? database.prepare(`
          SELECT id, source, target, confidence, content_hash, verification_state,
                 summary, created_by, provenance_json
          FROM evidence WHERE id = ?
        `).get(mainCandidate.promotedEvidenceId) as {
          readonly id: string;
          readonly source: string;
          readonly target: string;
          readonly confidence: number;
          readonly content_hash: string;
          readonly verification_state: string;
          readonly summary: string;
          readonly created_by: string;
          readonly provenance_json: string;
        } | undefined
      : undefined;
    const mainEvidence = evidenceRow ? {
      id: evidenceRow.id,
      source: evidenceRow.source,
      target: evidenceRow.target,
      confidence: evidenceRow.confidence,
      contentHash: evidenceRow.content_hash,
      verificationState: evidenceRow.verification_state,
      summary: evidenceRow.summary,
      createdBy: evidenceRow.created_by,
      provenance: JSON.parse(evidenceRow.provenance_json) as unknown,
    } : undefined;
    const custody = mainCandidate.promotedEvidenceId
      ? (database.prepare(`
          SELECT event_type, actor, occurred_at, details_json
          FROM evidence_chain_events WHERE evidence_id = ?
          ORDER BY occurred_at, rowid
        `).all(mainCandidate.promotedEvidenceId) as Array<{
          readonly event_type: string;
          readonly actor: string;
          readonly occurred_at: string;
          readonly details_json: string;
        }>).map((row) => ({
          eventType: row.event_type,
          actor: row.actor,
          occurredAt: row.occurred_at,
          details: JSON.parse(row.details_json) as unknown,
        }))
      : [];
    const audits = (database.prepare(`
      SELECT action, resource_type, resource_id, actor_id, reason, record_hash
      FROM audit_records
      WHERE mission_id = ?
        AND (resource_id IN (?, ?) OR resource_id = ?)
      ORDER BY occurred_at, rowid
    `).all(
      fixture.missionId,
      fixture.mainCandidateId,
      fixture.rejectCandidateId,
      mainCandidate.promotedEvidenceId,
    ) as Array<{
      readonly action: string;
      readonly resource_type: string;
      readonly resource_id: string | null;
      readonly actor_id: string | null;
      readonly reason: string | null;
      readonly record_hash: string;
    }>).map((row) => ({
      action: row.action,
      resourceType: row.resource_type,
      resourceId: row.resource_id,
      actorId: row.actor_id,
      reason: row.reason,
      recordHash: row.record_hash,
    }));
    return {
      mainCandidate,
      rejectCandidate,
      totalEvidenceCount: Number(countRow.count),
      ...(mainEvidence ? { mainEvidence } : {}),
      custody,
      audits,
    };
  } finally {
    database.close();
  }
}

import { createDatabaseConnection } from "../../../server/db";
import { OperationalTruthService } from "../../../server/intelligence-v24/OperationalTruthService";
import { hashCanonical } from "../../../server/missions/canonical";
import { MissionRepository } from "../../../server/missions/MissionRepository";
import { validateMissionCreateRequest } from "../../../server/missions/validation";
import {
  AttackAttemptService,
  ReconDigitalTwinService,
  RunMetricsService,
} from "../../../server/run-intelligence";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_TIME = "2026-07-16T20:00:00.000Z";
const TARGET = "https://run-metrics-fixture.example.test";
const EVIDENCE_SUMMARY = "Verified HTTPS exposure on the authorized run-metrics fixture.";

export interface RunMetricsFixture {
  readonly missionId: string;
  readonly runId: string;
  readonly assetNodeId: string;
  readonly evidenceId: string;
  readonly evidenceHash: string;
  readonly attackAttemptId: string;
  readonly snapshotId: string;
  readonly recomputationHash: string;
  readonly evidenceSummary: string;
  readonly techniqueName: string;
}

export interface RunMetricsFixtureState {
  readonly snapshotCount: number;
  readonly snapshotId: string;
  readonly recomputationHash: string;
  readonly attackAttemptCount: number;
  readonly attemptEvidenceCount: number;
  readonly evidenceCount: number;
  readonly evidenceHash: string;
}

interface CountRow { readonly count: number }
interface SnapshotRow { readonly id: string; readonly recomputation_hash: string }
interface EvidenceRow { readonly content_hash: string }

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Run-metrics E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

export function createRunMetricsFixture(instanceId: string): RunMetricsFixture {
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
      title: "Canonical run-intelligence browser fixture",
      objective: "Inspect reproducible run metrics and their attributable canonical records.",
      target: TARGET,
      explanationDepth: "balanced",
      executionPreference: "manual",
      evidenceExpectations: ["Verified target exposure with immutable provenance"],
    });
    const created = new MissionRepository(database).create({
      request,
      requestHash: hashCanonical(request),
      idempotencyKey: `run-metrics-e2e-${namespace}`,
      actorId: "e2e-local-operator",
    });

    let sequence = 0;
    const clock = () => new Date(FIXTURE_TIME);
    const truth = new OperationalTruthService(database, {
      clock,
      idFactory: (prefix) => `${prefix}_run_metrics_e2e_${namespace}_${++sequence}`,
    });
    const log = truth.appendEngagementLog({
      missionId: created.mission.id,
      runId: created.run.id,
      severity: "notice",
      domain: "recon.service-exposure",
      recordType: "structured_scan_result",
      humanSummary: "The authorized fixture exposed HTTPS on TCP port 443.",
      technicalPayload: {
        target: TARGET,
        transport: "tcp",
        port: 443,
        protocol: "https",
        verificationMethod: "isolated_fixture_observation",
      },
      sensitivity: "internal",
      occurredAt: FIXTURE_TIME,
    });
    const observation = truth.createObservation({
      missionId: created.mission.id,
      runId: created.run.id,
      observationType: "service_exposure",
      statement: "HTTPS was observed on TCP port 443 of the authorized fixture.",
      normalizedValue: { target: TARGET, transport: "tcp", port: 443, protocol: "https" },
      confidence: 0.99,
      verificationState: "corroborated",
      sourceTool: "e2e-run-metrics-fixture",
      firstSeenAt: FIXTURE_TIME,
      lastSeenAt: FIXTURE_TIME,
      sensitivity: "internal",
      sources: [{
        logRecordId: log.id,
        parserId: "run-metrics-fixture-parser",
        parserVersion: "1.0.0",
      }],
    });
    const candidate = truth.proposeEvidenceCandidate({
      missionId: created.mission.id,
      runId: created.run.id,
      observationId: observation.id,
      evidenceType: "port_service_scan_result",
      label: "Authorized HTTPS exposure",
      meaning: EVIDENCE_SUMMARY,
      promotionReason: "The attributable service observation supports the represented validation attempt.",
      additionalValidationRequirements: [],
      sensitivity: "internal",
      proposedBy: `agent-run-metrics-${namespace}`,
    });
    const reviewer = { id: `e2e-run-metrics-reviewer-${namespace}`, type: "operator" as const };
    truth.promoteCandidate({
      candidateId: candidate.id,
      actor: reviewer,
      reason: "Begin independent validation of the attributable fixture observation.",
    });
    const evidence = truth.verifyCandidate({
      candidateId: candidate.id,
      actor: reviewer,
      reason: "The target, source record, normalized observation, immutable hash, and provenance were reviewed.",
      source: "Isolated local run-intelligence fixture",
      target: `${TARGET}:443/tcp`,
      acquiredAt: FIXTURE_TIME,
      confidence: 0.99,
      provenance: {
        method: "isolated_fixture_observation",
        explanation: "A deterministic local record was normalized and independently verified for browser traversal.",
        sources: [
          { kind: "observation", id: observation.id },
          { kind: "engagement_log", id: log.id },
        ],
      },
      custody: [{
        eventType: "acquired",
        actor: "e2e-run-metrics-fixture",
        occurredAt: FIXTURE_TIME,
        details: { sourceLogId: log.id, parserId: "run-metrics-fixture-parser" },
      }],
      satisfiedAdditionalRequirements: [],
    });

    const topology = new ReconDigitalTwinService(database, clock);
    const asset = topology.createNode({
      missionId: created.mission.id,
      runId: created.run.id,
      nodeType: "asset",
      primaryLabel: "run-metrics-web-01",
      normalizedIdentity: "run-metrics-fixture.example.test",
      scopeStatus: "allowed",
      lifecycleState: "validated",
      properties: {
        addresses: ["192.0.2.84"],
        hostName: "run-metrics-fixture.example.test",
        services: [{ port: 443, transport: "tcp", protocol: "https" }],
      },
      provenance: {
        method: "isolated fixture observation",
        sourceRef: evidence.id,
        sourceTool: "e2e-run-metrics-fixture",
        observationIds: [observation.id],
      },
      confidence: 0.99,
      verificationState: "verified",
      sensitivity: "internal",
      firstSeenAt: FIXTURE_TIME,
      lastSeenAt: FIXTURE_TIME,
      evidence: [{ evidenceId: evidence.id, relationship: "supports" }],
    });

    const techniqueName = "Authorized HTTPS exposure validation";
    const attempts = new AttackAttemptService(database, clock);
    let attempt = attempts.create({
      missionId: created.mission.id,
      runId: created.run.id,
      targetAssetId: asset.id,
      objective: "Validate one represented HTTPS exposure without changing the target.",
      techniqueId: "T1595.002",
      techniqueName,
      actionClass: "vulnerability_scanning_configuration_assessment",
      prerequisites: ["The target remains inside the explicit local fixture scope."],
      normalizedParameters: { target: TARGET, port: 443, transport: "tcp", readOnly: true },
    });
    attempt = attempts.transition({ attemptId: attempt.id, expectedVersion: attempt.version, status: "ready" });
    attempt = attempts.transition({ attemptId: attempt.id, expectedVersion: attempt.version, status: "running" });
    attempt = attempts.complete({
      attemptId: attempt.id,
      expectedVersion: attempt.version,
      outcome: "succeeded",
      outcomeSummary: "The represented HTTPS exposure was validated by immutable local evidence.",
      evidence: [{ evidenceId: evidence.id, relationship: "outcome" }],
    });

    const snapshot = new RunMetricsService(database, clock).recomputeAndStore(created.run.id);
    return {
      missionId: created.mission.id,
      runId: created.run.id,
      assetNodeId: asset.id,
      evidenceId: evidence.id,
      evidenceHash: evidence.contentHash,
      attackAttemptId: attempt.id,
      snapshotId: snapshot.id,
      recomputationHash: snapshot.recomputationHash,
      evidenceSummary: EVIDENCE_SUMMARY,
      techniqueName,
    };
  } finally {
    database.close();
  }
}

export function readRunMetricsFixtureState(fixture: RunMetricsFixture): RunMetricsFixtureState {
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const snapshotCount = database.prepare("SELECT COUNT(*) AS count FROM run_metrics_snapshots WHERE run_id = ?")
      .get(fixture.runId) as CountRow;
    const snapshot = database.prepare(`
      SELECT id, recomputation_hash FROM run_metrics_snapshots
      WHERE run_id = ? ORDER BY through_event_sequence DESC, computed_at DESC, id DESC LIMIT 1
    `).get(fixture.runId) as SnapshotRow | undefined;
    const attackAttemptCount = database.prepare("SELECT COUNT(*) AS count FROM attack_attempts WHERE run_id = ?")
      .get(fixture.runId) as CountRow;
    const attemptEvidenceCount = database.prepare("SELECT COUNT(*) AS count FROM attack_attempt_evidence WHERE attack_attempt_id = ?")
      .get(fixture.attackAttemptId) as CountRow;
    const evidenceCount = database.prepare("SELECT COUNT(*) AS count FROM evidence WHERE id = ? AND mission_id = ? AND run_id = ?")
      .get(fixture.evidenceId, fixture.missionId, fixture.runId) as CountRow;
    const evidence = database.prepare("SELECT content_hash FROM evidence WHERE id = ?")
      .get(fixture.evidenceId) as EvidenceRow | undefined;
    if (!snapshot || !evidence) throw new Error("The canonical run-metrics fixture is incomplete");
    return {
      snapshotCount: Number(snapshotCount.count),
      snapshotId: snapshot.id,
      recomputationHash: snapshot.recomputation_hash,
      attackAttemptCount: Number(attackAttemptCount.count),
      attemptEvidenceCount: Number(attemptEvidenceCount.count),
      evidenceCount: Number(evidenceCount.count),
      evidenceHash: evidence.content_hash,
    };
  } finally {
    database.close();
  }
}

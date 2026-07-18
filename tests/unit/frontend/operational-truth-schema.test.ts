import { describe, expect, test } from "bun:test";
import {
  parseEngagementLogDetail,
  parseEngagementLogPage,
  parseEvidenceCandidateDetail,
  parseEvidenceCandidateMutation,
  parseEvidenceCandidatePage,
  parseFailureDiagnosisDetail,
  parseFailureDiagnosisList,
  parseFailureDiagnosisMutation,
  parseObservationDetail,
  parseObservationPage,
  parseVerifiedEvidenceDetail,
  parseVerifiedEvidenceMutation,
  parseVerifiedEvidencePage,
} from "../../../src/domain/schemas/operationalTruth";

const NOW = "2026-07-16T10:00:00.000Z";
const HASH = "a".repeat(64);

const log = {
  id: "log-one",
  missionId: "mission-one",
  runId: "run-one",
  planId: "plan-one",
  stepId: "step-one",
  actionId: "action-one",
  attackAttemptId: "attempt-one",
  assetId: "asset-one",
  agentId: "ReconScout",
  providerTurnId: "turn-one",
  toolCallId: "tool-call-one",
  severity: "notice",
  domain: "tool.nmap",
  recordType: "command_output",
  humanSummary: "Recon completed and retained a redacted technical log.",
  technicalPayload: { redacted: true, payload: { stdout: "443/tcp open" } },
  contentHash: HASH,
  sensitivity: "private",
  traceId: "trace-one",
  spanId: "span-one",
  occurredAt: NOW,
  createdAt: NOW,
} as const;

const observation = {
  id: "observation-one",
  missionId: "mission-one",
  runId: "run-one",
  stepId: "step-one",
  assetId: "asset-one",
  observationType: "open_port",
  statement: "TCP port 443 appeared open on the authorized target.",
  normalizedValue: { port: 443, transport: "tcp" },
  confidence: 0.8,
  verificationState: "corroborated",
  sourceAgentId: "ReconScout",
  sourceTool: "nmap",
  firstSeenAt: NOW,
  lastSeenAt: NOW,
  sensitivity: "private",
  sources: [{ logRecordId: "log-one", parserId: "nmap-xml", parserVersion: "1.0.0" }],
  createdAt: NOW,
} as const;

const candidate = {
  id: "candidate-one",
  missionId: "mission-one",
  runId: "run-one",
  stepId: "step-one",
  observationId: "observation-one",
  evidenceType: "port_service_scan",
  label: "HTTPS service exposure",
  meaning: "The scan may support the service inventory.",
  promotionReason: "Retain this attributable observation for review.",
  validationRequirements: [
    "immutable_content_hash",
    "attributable_provenance",
    "normalized_target",
    "acquired_time",
    "chain_of_custody",
  ],
  state: "candidate",
  sensitivity: "private",
  proposedBy: "ReconScout",
  createdAt: NOW,
} as const;

const promotedCandidate = {
  ...candidate,
  state: "promoted",
  reviewedBy: "operator-one",
  reviewReason: "The source and custody were independently reviewed.",
  promotedEvidenceId: "evidence-one",
  reviewedAt: NOW,
} as const;

const evidence = {
  id: "evidence-one",
  missionId: "mission-one",
  runId: "run-one",
  stepId: "step-one",
  source: "nmap XML parser and redacted scan output",
  acquiredAt: NOW,
  target: "lab.internal:443/tcp",
  evidenceType: "port_service_scan",
  contentHash: HASH,
  provenance: {
    method: "Structured parser with operator review",
    sources: [{ kind: "observation", id: "observation-one" }],
  },
  confidence: 0.9,
  sensitivity: "private",
  verificationState: "verified",
  summary: "HTTPS service exposure",
  createdBy: "operator-one",
  createdAt: NOW,
} as const;

const custody = {
  id: "custody-one",
  evidenceId: "evidence-one",
  eventType: "verified",
  actor: "operator-one",
  details: { candidateId: "candidate-one" },
  occurredAt: NOW,
} as const;

const diagnosis = {
  id: "failure-one",
  missionId: "mission-one",
  runId: "run-one",
  stepId: "step-one",
  assignmentId: "assignment-one",
  actionId: "action-one",
  attackAttemptId: "attempt-one",
  subjectType: "run",
  subjectId: "run-one",
  humanReason: "The provider exceeded its bounded response deadline twice.",
  category: "timeout",
  code: "provider_deadline_exceeded",
  originatingComponent: "provider-client",
  lastSuccessEventId: "event-one",
  failedComponentRef: "provider/openai",
  targetSummary: "Authorized lab target",
  policyOrDependency: "provider readiness",
  rawErrorLogId: "log-error-one",
  retryHistory: [{ attempt: 1, outcome: "timeout" }],
  progressBeforeFailure: { completedPhase: "reconnaissance" },
  preservedReferences: [{ kind: "checkpoint", id: "checkpoint-one", meaning: "Last safe checkpoint" }],
  retryable: true,
  automaticRecovery: [{ action: "bounded_backoff", outcome: "exhausted" }],
  remediation: "Test provider health before one bounded retry.",
  operatorActions: [{
    kind: "retry_bounded",
    label: "Retry once",
    consequence: "Uses one remaining retry only after readiness succeeds.",
    requiresConfirmation: true,
  }],
  objectiveImpact: "The run cannot advance, but its checkpoint is preserved.",
  state: "active",
  createdAt: NOW,
} as const;

describe("operational-truth frontend schema boundary", () => {
  test("parses every list and detail envelope without dropping correlation fields", () => {
    expect(parseEngagementLogPage({ schemaVersion: "2.4", items: [log], nextCursor: "cursor-one" }))
      .toMatchObject({ items: [{ actionId: "action-one", providerTurnId: "turn-one" }], nextCursor: "cursor-one" });
    expect(parseEngagementLogDetail({ schemaVersion: "2.4", log }).log.traceId).toBe("trace-one");

    expect(parseObservationPage({ schemaVersion: "2.4", items: [observation], nextCursor: null }).items[0]?.sources)
      .toEqual(observation.sources);
    expect(parseObservationDetail({ schemaVersion: "2.4", observation }).observation.normalizedValue)
      .toEqual({ port: 443, transport: "tcp" });

    expect(parseEvidenceCandidatePage({ schemaVersion: "2.4", items: [candidate], nextCursor: null }).items[0]?.state)
      .toBe("candidate");
    expect(parseEvidenceCandidateDetail({ schemaVersion: "2.4", candidate }).candidate.proposedBy).toBe("ReconScout");
    expect(parseEvidenceCandidateMutation({ schemaVersion: "2.4", candidate: promotedCandidate }).candidate.promotedEvidenceId)
      .toBe("evidence-one");

    expect(parseVerifiedEvidencePage({ schemaVersion: "2.4", items: [evidence], nextCursor: null }).items[0]?.target)
      .toBe("lab.internal:443/tcp");
    expect(parseVerifiedEvidenceMutation({ schemaVersion: "2.4", evidence }).evidence.verificationState).toBe("verified");
    expect(parseVerifiedEvidenceDetail({ schemaVersion: "2.4", evidence, chainOfCustody: [custody] }).chainOfCustody)
      .toEqual([custody]);

    expect(parseFailureDiagnosisList({ schemaVersion: "2.4", items: [diagnosis] }).items[0])
      .toMatchObject({ category: "timeout", assignmentId: "assignment-one", retryable: true });
    expect(parseFailureDiagnosisDetail({ schemaVersion: "2.4", diagnosis }).diagnosis.operatorActions[0]?.kind)
      .toBe("retry_bounded");
    const resolved = { ...diagnosis, state: "resolved", resolvedAt: NOW } as const;
    expect(parseFailureDiagnosisMutation({ schemaVersion: "2.4", diagnosis: resolved }).diagnosis.state).toBe("resolved");
  });

  test("rejects unsupported schema versions and malformed page cursors", () => {
    expect(() => parseEngagementLogPage({ schemaVersion: "2.3", items: [log], nextCursor: null }))
      .toThrow("unsupported Ti-Scale schema version");
    expect(() => parseEngagementLogPage({ schemaVersion: "2.4", items: [log], nextCursor: 42 }))
      .toThrow("nextCursor must be a string or null");
  });

  test("rejects evidence downgrades, broken hashes, and cross-record custody", () => {
    expect(() => parseVerifiedEvidenceMutation({
      schemaVersion: "2.4",
      evidence: { ...evidence, verificationState: "candidate" },
    })).toThrow("verified evidence state is invalid");
    expect(() => parseVerifiedEvidenceMutation({
      schemaVersion: "2.4",
      evidence: { ...evidence, contentHash: "not-a-sha256" },
    })).toThrow("lowercase SHA-256 digest");
    expect(() => parseVerifiedEvidenceDetail({
      schemaVersion: "2.4",
      evidence,
      chainOfCustody: [{ ...custody, evidenceId: "evidence-other" }],
    })).toThrow("references another evidence record");
  });

  test("requires review provenance and a verified link for promoted candidates", () => {
    expect(() => parseEvidenceCandidateMutation({
      schemaVersion: "2.4",
      candidate: { ...candidate, state: "promoted" },
    })).toThrow("missing its review provenance");
    expect(() => parseEvidenceCandidateMutation({
      schemaVersion: "2.4",
      candidate: { ...promotedCandidate, promotedEvidenceId: undefined },
    })).toThrow("missing its verified evidence link");
  });

  test("rejects unknown failure categories and inconsistent resolution state", () => {
    expect(() => parseFailureDiagnosisDetail({
      schemaVersion: "2.4",
      diagnosis: { ...diagnosis, category: "generic_error" },
    })).toThrow("failure diagnosis.category is invalid");
    expect(() => parseFailureDiagnosisDetail({
      schemaVersion: "2.4",
      diagnosis: { ...diagnosis, state: "resolved" },
    })).toThrow("resolution state and timestamp are inconsistent");
    expect(() => parseFailureDiagnosisDetail({
      schemaVersion: "2.4",
      diagnosis: { ...diagnosis, retryHistory: { unsafe: undefined } },
    })).toThrow("is not JSON-compatible");
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import type { SqliteDatabase } from "../../db";
import { BrainContextService } from "../../brain-runtime";
import { MemoryRepository, SecondBrainService } from "../../memory";
import { OperationalTruthError } from "../errors";
import { OperationalTruthService } from "../OperationalTruthService";
import type { EvidenceProvenance } from "../types";
import { deterministicOptions, NOW, seedAgent, seedFinding, testDatabase } from "./fixtures";

const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function service() {
  const database = testDatabase();
  databases.push(database);
  seedAgent(database);
  return { database, truth: new OperationalTruthService(database, deterministicOptions()) };
}

function appendRaw(truth: OperationalTruthService, missionId = "mission-one", runId = "run-one") {
  return truth.appendEngagementLog({
    missionId,
    runId,
    planId: `plan-${runId}`,
    stepId: `step-${runId}`,
    agentId: "ReconScout",
    severity: "info",
    domain: "tool.nmap",
    recordType: "command_output",
    humanSummary: "Service scan completed against the authorized target.",
    technicalPayload: {
      stdout: "443/tcp open https",
      token: "sensitive-value-must-not-persist",
      apiToken: "camel-case-api-token-must-not-persist",
      nested: { clientSecret: "nested-secret-must-not-persist", monkey: "safe-value" },
    },
    sensitivity: "private",
    occurredAt: NOW,
  });
}

function observationAndCandidate(truth: OperationalTruthService, additional = ["second_source_corroborated"]) {
  const log = appendRaw(truth);
  const observation = truth.createObservation({
    missionId: "mission-one",
    runId: "run-one",
    stepId: "step-run-one",
    observationType: "open_port",
    statement: "TCP port 443 appeared open on the authorized target.",
    normalizedValue: { transport: "tcp", port: 443, state: "open" },
    confidence: 0.8,
    sourceAgentId: "ReconScout",
    sourceTool: "nmap",
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    sensitivity: "private",
    sources: [{ logRecordId: log.id, parserId: "nmap-xml", parserVersion: "1.0.0" }],
  });
  const candidate = truth.proposeEvidenceCandidate({
    missionId: "mission-one",
    runId: "run-one",
    stepId: "step-run-one",
    observationId: observation.id,
    evidenceType: "port_service_scan",
    label: "HTTPS service exposure",
    meaning: "The authorized target exposed TCP port 443 during the assessment window.",
    promotionReason: "The parsed observation may support the service inventory.",
    additionalValidationRequirements: additional,
    sensitivity: "private",
    proposedBy: "ReconScout",
  });
  return { log, observation, candidate };
}

function provenance(observationId: string, logId: string): EvidenceProvenance {
  return {
    method: "Structured nmap parser with operator review",
    explanation: "The service observation is bound to the retained redacted scan record.",
    sources: [
      { kind: "observation", id: observationId },
      { kind: "engagement_log", id: logId },
    ],
  };
}

function verifyInput(candidateId: string, observationId: string, logId: string) {
  return {
    candidateId,
    actor: { id: "reviewer-one", type: "operator" as const },
    reason: "The source, target, hash, provenance, and custody requirements were independently reviewed.",
    source: "nmap XML parser and retained redacted scan output",
    target: "lab.internal:443/tcp",
    acquiredAt: NOW,
    confidence: 0.9,
    provenance: provenance(observationId, logId),
    custody: [{
      eventType: "acquired" as const,
      actor: "ReconScout",
      occurredAt: NOW,
      details: { sourceLogId: logId },
    }],
    satisfiedAdditionalRequirements: ["second_source_corroborated"],
  };
}

describe("V2.4 operational truth ladder", () => {
  test("raw command output remains a redacted engagement log and creates no evidence-like records", () => {
    const { database, truth } = service();
    const log = appendRaw(truth);

    expect(log.recordType).toBe("command_output");
    expect(log.technicalPayload).toEqual({
      redacted: true,
      payload: {
        stdout: "443/tcp open https",
        token: "[REDACTED]",
        apiToken: "[REDACTED]",
        nested: { clientSecret: "[REDACTED]", monkey: "safe-value" },
      },
    });
    expect(JSON.stringify(log)).not.toContain("camel-case-api-token-must-not-persist");
    expect(JSON.stringify(log)).not.toContain("nested-secret-must-not-persist");
    expect(log.contentHash).toMatch(/^[a-f0-9]{64}$/);
    expect(database.prepare("SELECT COUNT(*) AS count FROM observations").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
  });

  test("creates an attributable observation and candidate only through explicit calls", () => {
    const { database, truth } = service();
    const { log, observation, candidate } = observationAndCandidate(truth);

    expect(observation.sources).toEqual([{ logRecordId: log.id, parserId: "nmap-xml", parserVersion: "1.0.0" }]);
    expect(candidate.state).toBe("candidate");
    expect(candidate.validationRequirements).toEqual([
      "immutable_content_hash",
      "attributable_provenance",
      "normalized_target",
      "acquired_time",
      "chain_of_custody",
      "second_source_corroborated",
    ]);
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records").get()).toEqual({ count: 2 });
  });

  test("verification is atomic and fails until every custom, provenance, and custody gate passes", () => {
    const { database, truth } = service();
    const { log, observation, candidate } = observationAndCandidate(truth);
    expect(truth.promoteCandidate({
      candidateId: candidate.id,
      actor: { id: "reviewer-one", type: "operator" },
      reason: "Begin explicit validation against the candidate requirements.",
    }).state).toBe("validating");

    const base = verifyInput(candidate.id, observation.id, log.id);
    expect(() => truth.verifyCandidate({ ...base, satisfiedAdditionalRequirements: [] }))
      .toThrow(OperationalTruthError);
    expect(() => truth.verifyCandidate({ ...base, provenance: { ...base.provenance, sources: [{ kind: "observation", id: observation.id }] } }))
      .toThrow(OperationalTruthError);
    expect(() => truth.verifyCandidate({ ...base, custody: [] }))
      .toThrow(OperationalTruthError);
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    expect(truth.repository.getCandidate(candidate.id).state).toBe("validating");

    const evidence = truth.verifyCandidate(base);
    expect(evidence.verificationState).toBe("verified");
    expect(evidence.contentHash).toMatch(/^[a-f0-9]{64}$/);
    expect(evidence.target).toBe("lab.internal:443/tcp");
    expect(truth.repository.getCandidate(candidate.id)).toMatchObject({
      state: "promoted",
      promotedEvidenceId: evidence.id,
    });
    expect(database.prepare(`
      SELECT event_type FROM evidence_chain_events WHERE evidence_id = ? ORDER BY rowid
    `).all(evidence.id)).toEqual([{ event_type: "acquired" }, { event_type: "verified" }]);
    expect(() => database.prepare("UPDATE evidence SET summary = 'tampered' WHERE id = ?").run(evidence.id))
      .toThrow("evidence records are immutable");
  });

  test("reject and demote are explicit state transitions and demotion invalidates finding readiness", () => {
    const { truth } = service();
    seedFinding(truth.repository.database, "finding-demoted");
    const first = observationAndCandidate(truth, []);
    const rejected = truth.rejectCandidate({
      candidateId: first.candidate.id,
      actor: { id: "reviewer-one", type: "operator" },
      reason: "The candidate does not add useful proof.",
    });
    expect(rejected.state).toBe("rejected");
    expect(() => truth.promoteCandidate({
      candidateId: first.candidate.id,
      actor: { id: "reviewer-one", type: "operator" },
      reason: "Attempt an invalid transition.",
    })).toThrow(OperationalTruthError);

    const second = observationAndCandidate(truth, []);
    truth.promoteCandidate({
      candidateId: second.candidate.id,
      actor: { id: "reviewer-one", type: "operator" },
      reason: "Validate this separate candidate.",
    });
    const evidence = truth.verifyCandidate({
      ...verifyInput(second.candidate.id, second.observation.id, second.log.id),
      satisfiedAdditionalRequirements: [],
    });
    expect(truth.demoteCandidate({
      candidateId: second.candidate.id,
      actor: { id: "reviewer-two", type: "operator" },
      reason: "A later review found this evidence unsuitable for active claims.",
    }).state).toBe("demoted");
    truth.linkEvidenceToFinding({
      findingId: "finding-demoted",
      evidenceId: evidence.id,
      relationship: "supports",
      actor: { id: "reviewer-two", type: "operator" },
      reason: "Link the immutable history to demonstrate readiness exclusion.",
    });
    expect(truth.findingVerificationReadiness("finding-demoted")).toMatchObject({
      sufficient: false,
      supportingEvidenceIds: [],
      rejectedEvidenceIds: [evidence.id],
    });
  });

  test("finding verification refuses insufficient evidence and succeeds with promoted custody-complete evidence", () => {
    const { database, truth } = service();
    seedFinding(database, "finding-one");
    expect(() => truth.verifyFinding({
      findingId: "finding-one",
      expectedVersion: 1,
      actor: { id: "reviewer-one", type: "operator" },
      reason: "Attempt verification before attaching proof.",
    })).toThrow(OperationalTruthError);
    expect(database.prepare("SELECT review_status, version FROM findings WHERE id = 'finding-one'").get())
      .toEqual({ review_status: "under_review", version: 1 });

    const flow = observationAndCandidate(truth, []);
    truth.promoteCandidate({
      candidateId: flow.candidate.id,
      actor: { id: "reviewer-one", type: "operator" },
      reason: "Begin validation of the supporting service observation.",
    });
    const evidence = truth.verifyCandidate({
      ...verifyInput(flow.candidate.id, flow.observation.id, flow.log.id),
      satisfiedAdditionalRequirements: [],
    });
    truth.linkEvidenceToFinding({
      findingId: "finding-one",
      evidenceId: evidence.id,
      relationship: "supports",
      actor: { id: "reviewer-one", type: "operator" },
      reason: "Attach verified proof to the reviewed finding.",
    });
    expect(truth.verifyFinding({
      findingId: "finding-one",
      expectedVersion: 1,
      actor: { id: "reviewer-two", type: "operator" },
      reason: "The finding is supported by immutable verified evidence.",
    })).toMatchObject({ sufficient: true, supportingEvidenceIds: [evidence.id] });
    expect(database.prepare("SELECT review_status, version, operator_override FROM findings WHERE id = 'finding-one'").get())
      .toEqual({ review_status: "verified", version: 2, operator_override: 0 });
    expect(() => truth.demoteCandidate({
      candidateId: flow.candidate.id,
      actor: { id: "reviewer-two", type: "operator" },
      reason: "Attempt to invalidate evidence behind a verified claim.",
    })).toThrow(OperationalTruthError);
  });

  test("finding verification persists scoped Brain context before the canonical review transition", () => {
    const database = testDatabase();
    databases.push(database);
    seedAgent(database);
    new MemoryRepository(database).createNode({
      id: "memory-finding-validation",
      nodeType: "lesson",
      title: "Finding validation provenance",
      summary: "Validate findings against scoped verified evidence, custody, and provenance.",
      scope: { kind: "mission", missionId: "mission-one" },
      sensitivity: "internal",
      confidence: 0.95,
      lifecycleStatus: "verified",
      confirmationState: "not_required",
      provenance: {
        method: "derived",
        explanation: "Derived from a prior local evidence-quality evaluation.",
        sources: [{ sourceType: "run_evaluation", sourceId: "evaluation-finding-validation", acquiredAt: NOW }],
      },
      authorType: "agent",
      authorId: "run-evaluator",
      retentionPolicy: { allowAutonomous: true, allowGuided: true },
    });
    const context = new BrainContextService({
      database,
      secondBrain: new SecondBrainService(new MemoryRepository(database)),
    });
    const truth = new OperationalTruthService(database, {
      ...deterministicOptions(),
      brainContext: context,
    });
    seedFinding(database, "finding-brain-context");
    const flow = observationAndCandidate(truth, []);
    truth.promoteCandidate({
      candidateId: flow.candidate.id,
      actor: { id: "reviewer-one", type: "operator" },
      reason: "Begin validation of the supporting service observation.",
    });
    const evidence = truth.verifyCandidate({
      ...verifyInput(flow.candidate.id, flow.observation.id, flow.log.id),
      satisfiedAdditionalRequirements: [],
    });
    truth.linkEvidenceToFinding({
      findingId: "finding-brain-context",
      evidenceId: evidence.id,
      relationship: "supports",
      actor: { id: "reviewer-one", type: "operator" },
      reason: "Attach verified proof to the reviewed finding.",
    });
    truth.verifyFinding({
      findingId: "finding-brain-context",
      expectedVersion: 1,
      actor: { id: "reviewer-two", type: "operator" },
      reason: "Validate the evidence-linked finding with scoped context.",
    });
    expect(context.coverage({ missionId: "mission-one", runId: "run-one" })).toMatchObject({
      coveredHooks: ["finding_validation"],
      invocations: [{ hook: "finding_validation", status: "ready", retrievedCount: 1 }],
    });
    const ordered = database.prepare(`
      SELECT action FROM audit_records
      WHERE run_id = 'run-one' AND action IN ('brain.context_hook.invoked', 'finding.verified')
      ORDER BY rowid
    `).all() as Array<{ action: string }>;
    expect(ordered.map(({ action }) => action)).toEqual([
      "brain.context_hook.invoked",
      "finding.verified",
    ]);
    expect(database.prepare(`
      SELECT used, influence_summary, ignored_reason
      FROM memory_context_items
      WHERE node_id = ?
    `).get("memory-finding-validation")).toEqual({
      used: 0,
      influence_summary: null,
      ignored_reason: expect.stringContaining("did not independently verify"),
    });
  });

  test("cross-mission source linkage is rejected without partial observation state", () => {
    const { database, truth } = service();
    const foreign = appendRaw(truth, "mission-two", "run-two");
    expect(() => truth.createObservation({
      missionId: "mission-one",
      runId: "run-one",
      stepId: "step-run-one",
      observationType: "open_port",
      statement: "This must not cross engagement scope.",
      normalizedValue: { port: 443 },
      confidence: 0.5,
      firstSeenAt: NOW,
      lastSeenAt: NOW,
      sensitivity: "private",
      sources: [{ logRecordId: foreign.id, parserId: "parser", parserVersion: "1" }],
    })).toThrow(OperationalTruthError);
    expect(database.prepare("SELECT COUNT(*) AS count FROM observations").get()).toEqual({ count: 0 });
  });
});

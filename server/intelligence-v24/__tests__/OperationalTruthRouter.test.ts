import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { ControlPlaneLeaseService } from "../../control-plane";
import type { SqliteDatabase } from "../../db";
import { FailureDiagnosisService } from "../FailureDiagnosisService";
import { createOperationalTruthRouter } from "../OperationalTruthRouter";
import { OperationalTruthService } from "../OperationalTruthService";
import type { OperationalActor } from "../types";
import { deterministicOptions, NOW, seedAgent, seedFinding, testDatabase } from "./fixtures";

const servers: Server[] = [];
const databases: SqliteDatabase[] = [];
const LEASE_OWNER = "operational-truth-runtime";
const LEASE_TOKEN = "operational-truth-runtime-token-000000";
const TAKEOVER_OWNER = "operational-truth-takeover";
const TAKEOVER_TOKEN = "operational-truth-takeover-token-0000";

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const database of databases.splice(0)) database.close();
});

interface ErrorEnvelope {
  readonly error: {
    readonly code: string;
    readonly humanMessage: string;
    readonly category: string;
    readonly retryable: boolean;
    readonly traceId: string;
  };
}

async function body<T>(response: Response): Promise<T> {
  return response.json() as Promise<T>;
}

async function application(config: { readonly includeLeaseResolver?: boolean } = {}) {
  const database = testDatabase();
  databases.push(database);
  seedAgent(database);
  const leases = new ControlPlaneLeaseService(database);
  leases.acquire({
    runId: "run-one",
    controlPlane: "ti_scale",
    leaseOwner: LEASE_OWNER,
    leaseToken: LEASE_TOKEN,
    ttlMs: 300_000,
    now: new Date(NOW),
  });
  let actor: OperationalActor | undefined = { id: "ReconScout", type: "agent" };
  let authorized = true;
  let leaseMode: "valid" | "missing" | "heartbeat" | "takeover" = "valid";
  let leaseChecks = 0;
  const repositoryOptions = deterministicOptions();
  const app = express();
  app.use(express.json({ limit: "128kb" }));
  app.use(createOperationalTruthRouter({
    database,
    ...repositoryOptions,
    resolveActor: () => actor,
    authorize: (_request, _actor, request) => authorized && request.missionId === "mission-one",
    ...(config.includeLeaseResolver === false
      ? {}
      : {
          assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
            leaseChecks += 1;
            if (leaseMode === "missing") return undefined;
            if (leaseMode === "heartbeat" && leaseChecks === 2) {
              leases.heartbeat({
                runId,
                controlPlane: "ti_scale",
                leaseOwner: LEASE_OWNER,
                leaseToken: LEASE_TOKEN,
                ttlMs: 300_000,
                now: new Date("2026-07-16T10:00:01.000Z"),
              });
              return leases.assertMutationAuthority({
                runId,
                controlPlane: "ti_scale",
                leaseOwner: LEASE_OWNER,
                leaseToken: LEASE_TOKEN,
                now: new Date("2026-07-16T10:00:01.000Z"),
              });
            }
            if (leaseMode === "takeover" && leaseChecks === 2) {
              leases.release({
                runId,
                controlPlane: "ti_scale",
                leaseOwner: LEASE_OWNER,
                leaseToken: LEASE_TOKEN,
                now: new Date("2026-07-16T10:00:01.000Z"),
              });
              leases.acquire({
                runId,
                controlPlane: "ti_scale",
                leaseOwner: TAKEOVER_OWNER,
                leaseToken: TAKEOVER_TOKEN,
                ttlMs: 300_000,
                now: new Date("2026-07-16T10:00:02.000Z"),
              });
              return leases.assertMutationAuthority({
                runId,
                controlPlane: "ti_scale",
                leaseOwner: TAKEOVER_OWNER,
                leaseToken: TAKEOVER_TOKEN,
                now: new Date("2026-07-16T10:00:02.000Z"),
              });
            }
            return leases.assertMutationAuthority({
              runId,
              controlPlane: "ti_scale",
              leaseOwner: LEASE_OWNER,
              leaseToken: LEASE_TOKEN,
              now: new Date(NOW),
            });
          },
        }),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    database,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v2/operational-truth`,
    setActor: (value: OperationalActor | undefined) => { actor = value; },
    setAuthorized: (value: boolean) => { authorized = value; },
    setLeaseMode: (value: typeof leaseMode) => { leaseMode = value; leaseChecks = 0; },
  };
}

function mutation(bodyValue: unknown, key: string): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": key },
    body: JSON.stringify(bodyValue),
  };
}

function logRequest(summary = "Service scan completed against the authorized target") {
  return {
    runId: "run-one",
    planId: "plan-run-one",
    stepId: "step-run-one",
    severity: "info",
    domain: "tool.nmap",
    recordType: "command_output",
    humanSummary: summary,
    technicalPayload: { stdout: "443/tcp open https", token: "must-not-persist" },
    sensitivity: "private",
    occurredAt: NOW,
  };
}

function failureRequestBody() {
  return {
    subjectType: "run",
    subjectId: "run-one",
    humanReason: "The provider exceeded its bounded response deadline without returning a result.",
    category: "timeout",
    code: "provider_deadline_exceeded",
    originatingComponent: "provider-client",
    retryHistory: [{ attempt: 1, outcome: "timeout" }],
    progressBeforeFailure: { lastCompletedPhase: "reconnaissance" },
    retryable: true,
    automaticRecovery: [{ action: "bounded_backoff", outcome: "exhausted" }],
    remediation: "Test provider health, then retry once after the circuit breaker permits it.",
    operatorActions: [{
      kind: "retry_bounded",
      label: "Retry once",
      consequence: "Uses one remaining retry after readiness succeeds.",
      requiresConfirmation: true,
    }],
    objectiveImpact: "The run cannot advance, but its checkpoint is preserved.",
  } as const;
}

function seededCandidate(database: SqliteDatabase, suffix: string) {
  let sequence = 0;
  const truth = new OperationalTruthService(database, {
    clock: () => new Date(NOW),
    idFactory: (prefix) => `${prefix}_seed_${suffix}_${++sequence}`,
  });
  const log = truth.appendEngagementLog({
    missionId: "mission-one",
    runId: "run-one",
    stepId: "step-run-one",
    agentId: "ReconScout",
    severity: "info",
    domain: "tool.nmap",
    recordType: "command_output",
    humanSummary: `Seeded service scan ${suffix} completed.`,
    technicalPayload: { stdout: "443/tcp open https" },
    sensitivity: "private",
    occurredAt: NOW,
  });
  const observation = truth.createObservation({
    missionId: "mission-one",
    runId: "run-one",
    stepId: "step-run-one",
    observationType: "open_port",
    statement: `Seeded observation ${suffix} reported TCP port 443 open.`,
    normalizedValue: { port: 443, transport: "tcp" },
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
    label: `Seeded HTTPS evidence ${suffix}`,
    meaning: `Seeded observation ${suffix} may support the service inventory.`,
    promotionReason: "Retain this attributable candidate for explicit review.",
    sensitivity: "private",
    proposedBy: "ReconScout",
  });
  return { truth, log, observation, candidate };
}

describe("OperationalTruthRouter V2 boundary", () => {
  test("requires a trusted lease resolver, rejects imported ownership, allows heartbeat, and fences takeover and replay", async () => {
    const withoutResolver = await application({ includeLeaseResolver: false });
    const absentResolver = await fetch(
      `${withoutResolver.url}/missions/mission-one/logs`,
      mutation(logRequest("A resolver-less write must fail closed."), "truth-authority-no-resolver"),
    );
    expect(absentResolver.status).toBe(409);
    expect(await body<ErrorEnvelope>(absentResolver)).toMatchObject({
      error: { code: "control_plane_lease_missing", category: "state_conflict" },
    });
    expect(withoutResolver.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get())
      .toEqual({ count: 0 });

    const fixture = await application();
    fixture.setLeaseMode("missing");
    const missingProof = await fetch(
      `${fixture.url}/missions/mission-one/logs`,
      mutation(logRequest("A proof-less write must fail closed."), "truth-authority-no-proof"),
    );
    expect(missingProof.status).toBe(409);
    expect((await body<ErrorEnvelope>(missingProof)).error.code).toBe("control_plane_lease_missing");

    fixture.setLeaseMode("valid");
    fixture.database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = 'mission-one'").run();
    const importedMission = await fetch(
      `${fixture.url}/missions/mission-one/logs`,
      mutation(logRequest("Imported mission history is read-only."), "truth-authority-legacy-mission"),
    );
    expect(importedMission.status).toBe(409);
    expect((await body<ErrorEnvelope>(importedMission)).error.code).toBe("control_plane_mismatch");
    fixture.database.prepare("UPDATE missions SET control_plane = 'ti_scale' WHERE id = 'mission-one'").run();

    fixture.database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = 'run-one'").run();
    const importedRun = await fetch(
      `${fixture.url}/missions/mission-one/logs`,
      mutation(logRequest("Imported run history is read-only."), "truth-authority-legacy-run"),
    );
    expect(importedRun.status).toBe(409);
    expect((await body<ErrorEnvelope>(importedRun)).error.code).toBe("control_plane_mismatch");
    fixture.database.prepare("UPDATE runs SET control_plane = 'ti_scale' WHERE id = 'run-one'").run();

    let missionOnlySequence = 0;
    const missionOnlyTruth = new OperationalTruthService(fixture.database, {
      clock: () => new Date(NOW),
      idFactory: (prefix) => `${prefix}_mission_only_${++missionOnlySequence}`,
    });
    const missionOnlyLog = missionOnlyTruth.appendEngagementLog({
      missionId: "mission-one",
      severity: "info",
      domain: "legacy.import",
      recordType: "imported_command_output",
      humanSummary: "Imported mission-only output remains available for historical review.",
      technicalPayload: { imported: true },
      sensitivity: "private",
      occurredAt: NOW,
    });
    const missionOnlyObservation = missionOnlyTruth.createObservation({
      missionId: "mission-one",
      observationType: "imported_observation",
      statement: "Imported historical observation has no canonical run association.",
      normalizedValue: { imported: true },
      confidence: 0.5,
      firstSeenAt: NOW,
      lastSeenAt: NOW,
      sensitivity: "private",
      sources: [{ logRecordId: missionOnlyLog.id, parserId: "legacy-import", parserVersion: "1" }],
    });
    const missionOnlyCandidate = missionOnlyTruth.proposeEvidenceCandidate({
      missionId: "mission-one",
      observationId: missionOnlyObservation.id,
      evidenceType: "operator_supplied",
      label: "Imported mission-only candidate",
      meaning: "Historical context without a canonical run stays read-only.",
      promotionReason: "Preserve provenance without granting V2 mutation authority.",
      sensitivity: "private",
      proposedBy: "legacy-importer",
    });
    fixture.setActor({ id: "reviewer-one", type: "operator" });
    const missionOnlyMutation = await fetch(
      `${fixture.url}/missions/mission-one/evidence-candidates/${missionOnlyCandidate.id}/promote`,
      mutation({ reason: "A mission-only imported candidate must not be mutated." }, "truth-authority-mission-only"),
    );
    expect(missionOnlyMutation.status).toBe(403);
    expect((await body<ErrorEnvelope>(missionOnlyMutation)).error.code).toBe("operational_truth_policy_denied");
    expect(missionOnlyTruth.repository.getCandidate(missionOnlyCandidate.id).state).toBe("candidate");
    const logsBeforeHeartbeat = (fixture.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get() as { count: number }).count;

    fixture.setLeaseMode("heartbeat");
    const heartbeatRequest = mutation(
      logRequest("A normal runtime heartbeat must preserve the controller's authority."),
      "truth-authority-heartbeat",
    );
    const heartbeat = await fetch(`${fixture.url}/missions/mission-one/logs`, heartbeatRequest);
    expect(heartbeat.status, await heartbeat.clone().text()).toBe(201);
    expect(heartbeat.headers.get("idempotency-replayed")).toBe("false");
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get())
      .toEqual({ count: logsBeforeHeartbeat + 1 });

    fixture.setLeaseMode("missing");
    const replayWithoutAuthority = await fetch(`${fixture.url}/missions/mission-one/logs`, heartbeatRequest);
    expect(replayWithoutAuthority.status).toBe(409);
    expect((await body<ErrorEnvelope>(replayWithoutAuthority)).error.code).toBe("control_plane_lease_missing");
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get())
      .toEqual({ count: logsBeforeHeartbeat + 1 });

    fixture.setLeaseMode("takeover");
    const takeover = await fetch(
      `${fixture.url}/missions/mission-one/logs`,
      mutation(logRequest("A stale controller must not commit after takeover."), "truth-authority-takeover"),
    );
    expect(takeover.status).toBe(409);
    expect((await body<ErrorEnvelope>(takeover)).error.code).toBe("control_plane_lease_fence_invalid");
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get())
      .toEqual({ count: logsBeforeHeartbeat + 1 });
  });

  test("applies the lease fence to every operational-truth, evidence, finding, and failure mutation", async () => {
    const fixture = await application();
    fixture.setActor({ id: "reviewer-one", type: "operator" });
    const source = seededCandidate(fixture.database, "authority-source");
    const promoteFlow = seededCandidate(fixture.database, "authority-promote");
    const rejectFlow = seededCandidate(fixture.database, "authority-reject");
    const demoteFlow = seededCandidate(fixture.database, "authority-demote");
    demoteFlow.truth.promoteCandidate({
      candidateId: demoteFlow.candidate.id,
      actor: { id: "seed-reviewer", type: "operator" },
      reason: "Prepare a promoted candidate for the fenced demotion route.",
    });
    demoteFlow.truth.verifyCandidate({
      candidateId: demoteFlow.candidate.id,
      actor: { id: "seed-reviewer", type: "operator" },
      reason: "Prepare immutable evidence for the fenced demotion route.",
      source: "Seeded structured scan parser",
      target: "lab.internal:443/tcp",
      acquiredAt: NOW,
      confidence: 0.9,
      provenance: {
        method: "Structured seeded parser",
        explanation: "The observation remains bound to its immutable source log.",
        sources: [
          { kind: "observation", id: demoteFlow.observation.id },
          { kind: "engagement_log", id: demoteFlow.log.id },
        ],
      },
      custody: [{ eventType: "acquired", actor: "ReconScout", occurredAt: NOW }],
    });
    const verifyFlow = seededCandidate(fixture.database, "authority-verify");
    verifyFlow.truth.promoteCandidate({
      candidateId: verifyFlow.candidate.id,
      actor: { id: "seed-reviewer", type: "operator" },
      reason: "Prepare a validating candidate for the fenced verification route.",
    });
    seedFinding(fixture.database, "finding-authority");
    let failureSequence = 0;
    const seededFailure = new FailureDiagnosisService(fixture.database, {
      clock: () => new Date(NOW),
      idFactory: (prefix) => `${prefix}_authority_${++failureSequence}`,
    }).create({
      missionId: "mission-one",
      runId: "run-one",
      actor: { id: "run-supervisor", type: "system" },
      ...failureRequestBody(),
    });
    const before = {
      logs: (fixture.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get() as { count: number }).count,
      observations: (fixture.database.prepare("SELECT COUNT(*) AS count FROM observations").get() as { count: number }).count,
      candidates: (fixture.database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get() as { count: number }).count,
      failures: (fixture.database.prepare("SELECT COUNT(*) AS count FROM failure_diagnoses").get() as { count: number }).count,
    };
    const verificationBody = {
      reason: "The canonical source and custody were independently reviewed.",
      source: "Seeded structured scan parser",
      target: "lab.internal:443/tcp",
      acquiredAt: NOW,
      confidence: 0.9,
      provenance: {
        method: "Structured seeded parser",
        explanation: "The observation remains bound to its immutable source log.",
        sources: [
          { kind: "observation", id: verifyFlow.observation.id },
          { kind: "engagement_log", id: verifyFlow.log.id },
        ],
      },
      custody: [{ eventType: "acquired", actor: "ReconScout", occurredAt: NOW }],
    };
    const cases: readonly { readonly label: string; readonly path: string; readonly request: RequestInit }[] = [
      { label: "log", path: "/missions/mission-one/logs", request: mutation(logRequest("Fenced log."), "truth-all-fence-log") },
      { label: "observation", path: "/missions/mission-one/observations", request: mutation({
        runId: "run-one", stepId: "step-run-one", observationType: "open_port",
        statement: "A fenced observation must not persist.", normalizedValue: { port: 443 }, confidence: 0.8,
        firstSeenAt: NOW, lastSeenAt: NOW, sensitivity: "private",
        sources: [{ logRecordId: source.log.id, parserId: "nmap-xml", parserVersion: "1.0.0" }],
      }, "truth-all-fence-observation") },
      { label: "candidate", path: "/missions/mission-one/evidence-candidates", request: mutation({
        runId: "run-one", stepId: "step-run-one", observationId: source.observation.id,
        evidenceType: "port_service_scan", label: "Fenced candidate",
        meaning: "A fenced candidate must not persist.", promotionReason: "Exercise the shared authority boundary.", sensitivity: "private",
      }, "truth-all-fence-candidate") },
      { label: "promote", path: `/missions/mission-one/evidence-candidates/${promoteFlow.candidate.id}/promote`, request: mutation({ reason: "Fenced promotion." }, "truth-all-fence-promote") },
      { label: "reject", path: `/missions/mission-one/evidence-candidates/${rejectFlow.candidate.id}/reject`, request: mutation({ reason: "Fenced rejection." }, "truth-all-fence-reject") },
      { label: "demote", path: `/missions/mission-one/evidence-candidates/${demoteFlow.candidate.id}/demote`, request: mutation({ reason: "Fenced demotion." }, "truth-all-fence-demote") },
      { label: "verify evidence", path: `/missions/mission-one/evidence-candidates/${verifyFlow.candidate.id}/verify`, request: mutation(verificationBody, "truth-all-fence-verify") },
      { label: "verify finding", path: "/missions/mission-one/findings/finding-authority/verify", request: mutation({ expectedVersion: 1, reason: "Fenced finding verification." }, "truth-all-fence-finding") },
      { label: "create failure", path: "/missions/mission-one/runs/run-one/failure-diagnoses", request: mutation(failureRequestBody(), "truth-all-fence-failure") },
      { label: "resolve failure", path: `/missions/mission-one/runs/run-one/failure-diagnoses/${seededFailure.id}/resolve`, request: mutation({
        actionKind: "retry_bounded", verifiedOutcome: "Provider readiness recovered and the bounded probe succeeded.", confirmed: true,
      }, "truth-all-fence-resolve") },
    ];
    fixture.setLeaseMode("missing");
    for (const entry of cases) {
      const response = await fetch(`${fixture.url}${entry.path}`, entry.request);
      expect(response.status, `${entry.label}: ${await response.clone().text()}`).toBe(409);
      expect((await body<ErrorEnvelope>(response)).error.code, entry.label).toBe("control_plane_lease_missing");
    }
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get()).toEqual({ count: before.logs });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM observations").get()).toEqual({ count: before.observations });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get()).toEqual({ count: before.candidates });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM failure_diagnoses").get()).toEqual({ count: before.failures });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM settings WHERE key LIKE 'idempotency.operational_truth_v24.%'").get())
      .toEqual({ count: 0 });
  });

  test("drives the explicit log-to-verified-evidence ladder and finding gate without automatic promotion", async () => {
    const fixture = await application();
    const logResponse = await fetch(
      `${fixture.url}/missions/mission-one/logs`,
      mutation(logRequest(), "truth-log-create-0001"),
    );
    expect(logResponse.status, await logResponse.clone().text()).toBe(201);
    expect(logResponse.headers.get("idempotency-replayed")).toBe("false");
    const logBody = await body<{
      readonly schemaVersion: "2.4";
      readonly log: { readonly id: string; readonly agentId: string; readonly technicalPayload: unknown };
    }>(logResponse);
    expect(logBody).toMatchObject({
      schemaVersion: "2.4",
      log: {
        agentId: "ReconScout",
        technicalPayload: {
          redacted: true,
          payload: { stdout: "443/tcp open https", token: "[REDACTED]" },
        },
      },
    });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM observations").get()).toEqual({ count: 0 });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });

    const replay = await fetch(
      `${fixture.url}/missions/mission-one/logs`,
      mutation(logRequest(), "truth-log-create-0001"),
    );
    expect(replay.status).toBe(201);
    expect(replay.headers.get("idempotency-replayed")).toBe("true");
    expect(await body<typeof logBody>(replay)).toEqual(logBody);
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get()).toEqual({ count: 1 });

    const observationResponse = await fetch(
      `${fixture.url}/missions/mission-one/observations`,
      mutation({
        runId: "run-one",
        stepId: "step-run-one",
        observationType: "open_port",
        statement: "TCP port 443 appeared open on the authorized target.",
        normalizedValue: { transport: "tcp", port: 443, state: "open" },
        confidence: 0.8,
        sourceTool: "nmap",
        firstSeenAt: NOW,
        lastSeenAt: NOW,
        sensitivity: "private",
        sources: [{ logRecordId: logBody.log.id, parserId: "nmap-xml", parserVersion: "1.0.0" }],
      }, "truth-observation-0001"),
    );
    expect(observationResponse.status).toBe(201);
    const observationBody = await body<{
      readonly observation: { readonly id: string; readonly sourceAgentId: string };
    }>(observationResponse);
    expect(observationBody.observation.sourceAgentId).toBe("ReconScout");

    const candidateResponse = await fetch(
      `${fixture.url}/missions/mission-one/evidence-candidates`,
      mutation({
        runId: "run-one",
        stepId: "step-run-one",
        observationId: observationBody.observation.id,
        evidenceType: "port_service_scan",
        label: "HTTPS service exposure",
        meaning: "The authorized target exposed TCP port 443 during the assessment window.",
        promotionReason: "The parsed observation may support the service inventory.",
        sensitivity: "private",
      }, "truth-candidate-0001"),
    );
    expect(candidateResponse.status).toBe(201);
    const candidateBody = await body<{
      readonly candidate: { readonly id: string; readonly state: string; readonly proposedBy: string };
    }>(candidateResponse);
    expect(candidateBody.candidate).toMatchObject({ state: "candidate", proposedBy: "ReconScout" });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });

    fixture.setActor({ id: "reviewer-one", type: "operator" });
    const promoteResponse = await fetch(
      `${fixture.url}/missions/mission-one/evidence-candidates/${candidateBody.candidate.id}/promote`,
      mutation({ reason: "Begin independent validation of the attributable service observation." }, "truth-promote-0001"),
    );
    expect(promoteResponse.status).toBe(200);
    expect(await body<{ readonly candidate: { readonly state: string } }>(promoteResponse))
      .toMatchObject({ candidate: { state: "validating" } });

    const verifyResponse = await fetch(
      `${fixture.url}/missions/mission-one/evidence-candidates/${candidateBody.candidate.id}/verify`,
      mutation({
        reason: "The canonical source, target, hash, provenance, and custody were independently reviewed.",
        source: "nmap XML parser and retained redacted scan output",
        target: "lab.internal:443/tcp",
        acquiredAt: NOW,
        confidence: 0.9,
        provenance: {
          method: "Structured nmap parser with operator review",
          explanation: "The service observation is bound to its retained redacted scan record.",
          sources: [
            { kind: "observation", id: observationBody.observation.id },
            { kind: "engagement_log", id: logBody.log.id },
          ],
        },
        custody: [{
          eventType: "acquired",
          actor: "ReconScout",
          occurredAt: NOW,
          details: { sourceLogId: logBody.log.id },
        }],
      }, "truth-verify-0001"),
    );
    expect(verifyResponse.status).toBe(201);
    const verifyBody = await body<{
      readonly evidence: { readonly id: string; readonly verificationState: string; readonly contentHash: string };
    }>(verifyResponse);
    expect(verifyBody.evidence.verificationState).toBe("verified");
    expect(verifyBody.evidence.contentHash).toMatch(/^[a-f0-9]{64}$/u);

    const evidenceList = await body<{
      readonly items: readonly { readonly id: string }[];
      readonly nextCursor: string | null;
    }>(await fetch(`${fixture.url}/missions/mission-one/verified-evidence?runId=run-one`));
    expect(evidenceList).toMatchObject({ items: [{ id: verifyBody.evidence.id }], nextCursor: null });
    const evidenceDetail = await body<{
      readonly evidence: { readonly id: string };
      readonly chainOfCustody: readonly { readonly eventType: string }[];
    }>(await fetch(`${fixture.url}/missions/mission-one/verified-evidence/${verifyBody.evidence.id}`));
    expect(evidenceDetail.chainOfCustody.map((event) => event.eventType)).toEqual(["acquired", "verified"]);

    seedFinding(fixture.database, "finding-router");
    new OperationalTruthService(fixture.database).linkEvidenceToFinding({
      findingId: "finding-router",
      evidenceId: verifyBody.evidence.id,
      relationship: "supports",
      actor: { id: "reviewer-one", type: "operator" },
      reason: "Attach the verified service proof to the reviewed finding.",
    });
    const readiness = await body<{
      readonly readiness: { readonly sufficient: boolean; readonly supportingEvidenceIds: readonly string[] };
    }>(await fetch(`${fixture.url}/missions/mission-one/findings/finding-router/verification-readiness`));
    expect(readiness.readiness).toMatchObject({ sufficient: true, supportingEvidenceIds: [verifyBody.evidence.id] });
    const findingResponse = await fetch(
      `${fixture.url}/missions/mission-one/findings/finding-router/verify`,
      mutation({
        expectedVersion: 1,
        reason: "The finding is supported by promoted, immutable, custody-complete evidence.",
      }, "truth-finding-verify-0001"),
    );
    expect(findingResponse.status).toBe(200);
    expect(fixture.database.prepare("SELECT review_status, operator_override FROM findings WHERE id = ?")
      .get("finding-router")).toEqual({ review_status: "verified", operator_override: 0 });

    const candidateList = await body<{
      readonly items: readonly { readonly id: string; readonly state: string }[];
    }>(await fetch(`${fixture.url}/missions/mission-one/evidence-candidates?state=promoted`));
    expect(candidateList.items).toEqual([expect.objectContaining({ id: candidateBody.candidate.id, state: "promoted" })]);
  });

  test("persists, reads, lists, idempotently replays, and resolves structured failure diagnoses", async () => {
    const fixture = await application();
    fixture.setActor({ id: "run-supervisor", type: "system" });
    const createRequest = mutation({
      subjectType: "run",
      subjectId: "run-one",
      humanReason: "The provider exceeded the bounded response deadline twice without returning a result.",
      category: "timeout",
      code: "provider_deadline_exceeded",
      originatingComponent: "provider-client",
      retryHistory: [{ attempt: 1, outcome: "timeout" }, { attempt: 2, outcome: "timeout" }],
      progressBeforeFailure: { lastCompletedPhase: "reconnaissance", uniqueEvidence: 1 },
      retryable: true,
      automaticRecovery: [{ action: "bounded_backoff", outcome: "exhausted" }],
      remediation: "Test provider health, then retry once after the circuit breaker permits it.",
      operatorActions: [{
        kind: "retry_bounded",
        label: "Retry once",
        consequence: "Uses one remaining retry after readiness succeeds.",
        requiresConfirmation: true,
      }],
      objectiveImpact: "The run cannot advance, but its checkpoint is preserved.",
    }, "truth-failure-create-0001");
    const first = await fetch(
      `${fixture.url}/missions/mission-one/runs/run-one/failure-diagnoses`,
      createRequest,
    );
    expect(first.status).toBe(201);
    const created = await body<{
      readonly diagnosis: { readonly id: string; readonly category: string; readonly state: string };
    }>(first);
    expect(created.diagnosis).toMatchObject({ category: "timeout", state: "active" });
    const replay = await fetch(
      `${fixture.url}/missions/mission-one/runs/run-one/failure-diagnoses`,
      createRequest,
    );
    expect(replay.headers.get("idempotency-replayed")).toBe("true");
    expect(await body<typeof created>(replay)).toEqual(created);
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM failure_diagnoses").get()).toEqual({ count: 1 });

    const list = await body<{ readonly items: readonly { readonly id: string }[] }>(await fetch(
      `${fixture.url}/missions/mission-one/runs/run-one/failure-diagnoses?states=active&limit=10`,
    ));
    expect(list.items).toEqual([expect.objectContaining({ id: created.diagnosis.id })]);
    const detail = await body<{ readonly diagnosis: { readonly id: string; readonly retryable: boolean } }>(await fetch(
      `${fixture.url}/missions/mission-one/runs/run-one/failure-diagnoses/${created.diagnosis.id}`,
    ));
    expect(detail.diagnosis).toMatchObject({ id: created.diagnosis.id, retryable: true });

    fixture.setActor({ id: "operator-one", type: "operator" });
    const legacyFreeForm = await fetch(
      `${fixture.url}/missions/mission-one/runs/run-one/failure-diagnoses/${created.diagnosis.id}/resolve`,
      mutation({ resolution: "A client-authored free-form audit reason must no longer be accepted." }, "truth-failure-legacy-0001"),
    );
    expect(legacyFreeForm.status).toBe(400);
    expect((await body<ErrorEnvelope>(legacyFreeForm)).error.code).toBe("invalid_request_body");
    const undeclared = await fetch(
      `${fixture.url}/missions/mission-one/runs/run-one/failure-diagnoses/${created.diagnosis.id}/resolve`,
      mutation({
        actionKind: "start_new_run",
        verifiedOutcome: "A new run was created even though this diagnosis did not declare that recovery route.",
        confirmed: true,
      }, "truth-failure-undeclared-0001"),
    );
    expect(undeclared.status).toBe(400);
    expect((await body<ErrorEnvelope>(undeclared)).error.code).toBe("undeclared_failure_resolution_action");
    const unconfirmed = await fetch(
      `${fixture.url}/missions/mission-one/runs/run-one/failure-diagnoses/${created.diagnosis.id}/resolve`,
      mutation({
        actionKind: "retry_bounded",
        verifiedOutcome: "Provider readiness succeeded and the bounded retry produced an attributable result.",
        confirmed: false,
      }, "truth-failure-unconfirmed-0001"),
    );
    expect(unconfirmed.status).toBe(400);
    expect((await body<ErrorEnvelope>(unconfirmed)).error.code).toBe("invalid_request_body");
    expect(fixture.database.prepare("SELECT state FROM failure_diagnoses WHERE id = ?").get(created.diagnosis.id))
      .toEqual({ state: "active" });
    const resolved = await fetch(
      `${fixture.url}/missions/mission-one/runs/run-one/failure-diagnoses/${created.diagnosis.id}/resolve`,
      mutation({
        actionKind: "retry_bounded",
        verifiedOutcome: "Provider health recovered and the bounded readiness probe succeeded.",
        confirmed: true,
      }, "truth-failure-resolve-0001"),
    );
    expect(resolved.status).toBe(200);
    expect(await body<{ readonly diagnosis: { readonly state: string } }>(resolved))
      .toMatchObject({ diagnosis: { state: "resolved" } });
    const resolvedList = await body<{ readonly items: readonly { readonly id: string }[] }>(await fetch(
      `${fixture.url}/missions/mission-one/runs/run-one/failure-diagnoses?states=resolved`,
    ));
    expect(resolvedList.items).toEqual([expect.objectContaining({ id: created.diagnosis.id })]);
    const resolutionAudit = fixture.database.prepare(`
      SELECT actor_id, reason, details_json FROM audit_records
      WHERE action = 'failure_diagnosis.resolved' AND resource_id = ?
    `).get(created.diagnosis.id) as { actor_id: string; reason: string; details_json: string };
    expect(resolutionAudit).toMatchObject({
      actor_id: "operator-one",
      reason: "Declared recovery action: retry_bounded — Retry once. Operator-verified outcome: Provider health recovered and the bounded readiness probe succeeded.",
    });
    expect(JSON.parse(resolutionAudit.details_json)).toMatchObject({
      actionKind: "retry_bounded",
      actionLabel: "Retry once",
      confirmed: true,
      from: "active",
      to: "resolved",
    });

    fixture.setActor({ id: "run-supervisor", type: "system" });
    const terminalCreate = await fetch(
      `${fixture.url}/missions/mission-one/runs/run-one/failure-diagnoses`,
      mutation({
        subjectType: "run",
        subjectId: "run-one",
        humanReason: "The ended run retained a terminal dependency diagnosis for explicit reconciliation.",
        category: "dependency_missing",
        code: "terminal_dependency_missing",
        originatingComponent: "readiness",
        retryable: false,
        remediation: "Create a separate readiness-verified run after configuring the dependency.",
        operatorActions: [{
          kind: "start_new_run",
          label: "Start a new run",
          consequence: "Creates a separate run without resuming terminal work in place.",
          requiresConfirmation: true,
        }],
        objectiveImpact: "The terminal run remains preserved.",
        terminal: true,
      }, "truth-failure-terminal-create-0001"),
    );
    expect(terminalCreate.status).toBe(201);
    const terminal = await body<{ readonly diagnosis: { readonly id: string; readonly state: string } }>(terminalCreate);
    expect(terminal.diagnosis.state).toBe("terminal");
    fixture.setActor({ id: "operator-one", type: "operator" });
    const terminalResolved = await fetch(
      `${fixture.url}/missions/mission-one/runs/run-one/failure-diagnoses/${terminal.diagnosis.id}/resolve`,
      mutation({
        actionKind: "start_new_run",
        verifiedOutcome: "A separate readiness-verified run was created and the terminal diagnosis was reconciled.",
        confirmed: true,
      }, "truth-failure-terminal-resolve-0001"),
    );
    expect(terminalResolved.status).toBe(200);
    expect(await body<{ readonly diagnosis: { readonly state: string } }>(terminalResolved))
      .toMatchObject({ diagnosis: { state: "resolved" } });
    const terminalAudit = fixture.database.prepare(`
      SELECT details_json FROM audit_records
      WHERE action = 'failure_diagnosis.resolved' AND resource_id = ?
    `).get(terminal.diagnosis.id) as { details_json: string };
    expect(JSON.parse(terminalAudit.details_json)).toMatchObject({ from: "terminal", to: "resolved" });
  });

  test("serves scoped details and exposes reject, demote, and insufficient-finding gates over HTTP", async () => {
    const fixture = await application();
    fixture.setActor({ id: "reviewer-one", type: "operator" });
    const rejectedFlow = seededCandidate(fixture.database, "reject");

    const logDetail = await body<{ readonly log: { readonly id: string } }>(await fetch(
      `${fixture.url}/missions/mission-one/logs/${rejectedFlow.log.id}`,
    ));
    expect(logDetail.log.id).toBe(rejectedFlow.log.id);
    const observationDetail = await body<{ readonly observation: { readonly id: string } }>(await fetch(
      `${fixture.url}/missions/mission-one/observations/${rejectedFlow.observation.id}`,
    ));
    expect(observationDetail.observation.id).toBe(rejectedFlow.observation.id);
    const candidateDetail = await body<{ readonly candidate: { readonly id: string } }>(await fetch(
      `${fixture.url}/missions/mission-one/evidence-candidates/${rejectedFlow.candidate.id}`,
    ));
    expect(candidateDetail.candidate.id).toBe(rejectedFlow.candidate.id);

    const rejected = await fetch(
      `${fixture.url}/missions/mission-one/evidence-candidates/${rejectedFlow.candidate.id}/reject`,
      mutation({ reason: "Independent review found that this candidate adds no useful proof." }, "truth-reject-0001"),
    );
    expect(rejected.status).toBe(200);
    expect(await body<{ readonly candidate: { readonly state: string } }>(rejected))
      .toMatchObject({ candidate: { state: "rejected" } });

    const demotedFlow = seededCandidate(fixture.database, "demote");
    demotedFlow.truth.promoteCandidate({
      candidateId: demotedFlow.candidate.id,
      actor: { id: "seed-reviewer", type: "operator" },
      reason: "Begin explicit validation for the demotion route fixture.",
    });
    const evidence = demotedFlow.truth.verifyCandidate({
      candidateId: demotedFlow.candidate.id,
      actor: { id: "seed-reviewer", type: "operator" },
      reason: "The canonical seeded source and custody requirements were reviewed.",
      source: "Seeded structured scan parser",
      target: "lab.internal:443/tcp",
      acquiredAt: NOW,
      confidence: 0.9,
      provenance: {
        method: "Structured seeded parser",
        explanation: "The observation remains bound to its immutable source log.",
        sources: [
          { kind: "observation", id: demotedFlow.observation.id },
          { kind: "engagement_log", id: demotedFlow.log.id },
        ],
      },
      custody: [{ eventType: "acquired", actor: "ReconScout", occurredAt: NOW }],
    });
    const demoted = await fetch(
      `${fixture.url}/missions/mission-one/evidence-candidates/${demotedFlow.candidate.id}/demote`,
      mutation({ reason: "Later review found the proof unsuitable for active claims." }, "truth-demote-0001"),
    );
    expect(demoted.status).toBe(200);
    expect(await body<{ readonly candidate: { readonly state: string } }>(demoted))
      .toMatchObject({ candidate: { state: "demoted" } });
    const evidenceDetail = await body<{
      readonly chainOfCustody: readonly { readonly eventType: string }[];
    }>(await fetch(`${fixture.url}/missions/mission-one/verified-evidence/${evidence.id}`));
    expect(evidenceDetail.chainOfCustody.map((event) => event.eventType))
      .toEqual(["acquired", "verified", "demoted"]);

    seedFinding(fixture.database, "finding-insufficient-router");
    const insufficient = await fetch(
      `${fixture.url}/missions/mission-one/findings/finding-insufficient-router/verify`,
      mutation({
        expectedVersion: 1,
        reason: "Attempt finding verification without linked supporting evidence.",
      }, "truth-finding-insufficient-0001"),
    );
    expect(insufficient.status).toBe(409);
    expect(await body<ErrorEnvelope>(insufficient)).toMatchObject({
      error: { code: "verified_evidence_required", category: "evidence_insufficient" },
    });
    expect(fixture.database.prepare("SELECT review_status, version FROM findings WHERE id = ?")
      .get("finding-insufficient-router")).toEqual({ review_status: "under_review", version: 1 });
  });

  test("requires authentication, mission authorization, human review, and strict request bodies", async () => {
    const fixture = await application();
    fixture.setActor(undefined);
    const unauthenticated = await fetch(`${fixture.url}/missions/mission-one/logs`, {
      headers: { "X-Request-ID": "truth-auth-required" },
    });
    expect(unauthenticated.status).toBe(401);
    expect(await body<ErrorEnvelope>(unauthenticated)).toMatchObject({
      error: {
        code: "authentication_required",
        category: "authentication_missing",
        retryable: false,
        traceId: "truth-auth-required",
      },
    });

    fixture.setActor({ id: "ReconScout", type: "agent" });
    fixture.setAuthorized(false);
    const forbidden = await fetch(`${fixture.url}/missions/mission-one/logs`);
    expect(forbidden.status).toBe(403);
    expect((await body<ErrorEnvelope>(forbidden)).error.category).toBe("policy_denied");

    fixture.setAuthorized(true);
    const missingKey = await fetch(`${fixture.url}/missions/mission-one/logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(logRequest()),
    });
    expect(missingKey.status).toBe(400);
    expect((await body<ErrorEnvelope>(missingKey)).error.code).toBe("idempotency_key_required");

    const spoofed = await fetch(`${fixture.url}/missions/mission-one/logs`, mutation({
      ...logRequest(),
      agentId: "other-agent",
    }, "truth-agent-spoof-0001"));
    expect(spoofed.status).toBe(403);

    const unknownField = await fetch(`${fixture.url}/missions/mission-one/logs`, mutation({
      ...logRequest(),
      actor: { id: "spoofed", type: "operator" },
    }, "truth-unknown-field-0001"));
    expect(unknownField.status).toBe(400);
    expect((await body<ErrorEnvelope>(unknownField)).error.code).toBe("invalid_request_body");
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get()).toEqual({ count: 0 });

    const reviewerDenied = await fetch(
      `${fixture.url}/missions/mission-one/evidence-candidates/not-present/promote`,
      mutation({ reason: "Attempt agent review." }, "truth-agent-review-0001"),
    );
    expect(reviewerDenied.status).toBe(403);
  });

  test("rejects idempotency-key conflicts and cross-mission resource disclosure", async () => {
    const fixture = await application();
    const first = await fetch(
      `${fixture.url}/missions/mission-one/logs`,
      mutation(logRequest("First bounded scan result."), "truth-conflict-key-0001"),
    );
    expect(first.status).toBe(201);
    const firstBody = await body<{ readonly log: { readonly id: string } }>(first);
    const conflict = await fetch(
      `${fixture.url}/missions/mission-one/logs`,
      mutation(logRequest("Materially changed scan result."), "truth-conflict-key-0001"),
    );
    expect(conflict.status).toBe(409);
    expect((await body<ErrorEnvelope>(conflict)).error.code).toBe("operational_truth_state_conflict");
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get()).toEqual({ count: 1 });

    fixture.setActor({ id: "reviewer-one", type: "operator" });
    const hidden = await fetch(`${fixture.url}/missions/mission-one/logs/${firstBody.log.id.replace("log_", "missing_")}`);
    expect(hidden.status).toBe(404);

    fixture.setActor({ id: "ReconScout", type: "agent" });
    const foreign = await fetch(
      `${fixture.url}/missions/mission-two/logs`,
      mutation({ ...logRequest(), runId: "run-two", planId: "plan-run-two", stepId: "step-run-two" }, "truth-foreign-log-0001"),
    );
    expect(foreign.status).toBe(403);
    const foreignCount = fixture.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records WHERE mission_id = 'mission-two'").get();
    expect(foreignCount).toEqual({ count: 0 });
  });

  test("paginates bounded log reads with stable opaque cursors", async () => {
    const fixture = await application();
    for (const [index, summary] of ["First scan completed.", "Second scan completed."].entries()) {
      const response = await fetch(
        `${fixture.url}/missions/mission-one/logs`,
        mutation(logRequest(summary), `truth-page-log-000${index + 1}`),
      );
      expect(response.status).toBe(201);
    }
    const first = await body<{
      readonly items: readonly { readonly id: string }[];
      readonly nextCursor: string | null;
    }>(await fetch(`${fixture.url}/missions/mission-one/logs?limit=1`));
    expect(first.items).toHaveLength(1);
    expect(first.nextCursor).toBeString();
    const second = await body<{
      readonly items: readonly { readonly id: string }[];
      readonly nextCursor: string | null;
    }>(await fetch(`${fixture.url}/missions/mission-one/logs?limit=1&cursor=${encodeURIComponent(first.nextCursor ?? "")}`));
    expect(second.items).toHaveLength(1);
    expect(second.items[0]?.id).not.toBe(first.items[0]?.id);
    expect(second.nextCursor).toBeNull();
  });
});

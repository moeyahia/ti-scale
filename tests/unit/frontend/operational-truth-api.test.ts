/// <reference lib="dom" />

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { operationalTruthApi } from "../../../src/data/api/operationalTruth";

const NOW = "2026-07-16T10:00:00.000Z";
const HASH = "b".repeat(64);
const log = {
  id: "log/one", missionId: "mission/one", runId: "run/one", severity: "info",
  domain: "tool.nmap", recordType: "command_output", humanSummary: "Authorized scan completed.",
  technicalPayload: { stdout: "443/tcp open" }, contentHash: HASH, sensitivity: "private",
  occurredAt: NOW, createdAt: NOW,
} as const;
const observation = {
  id: "observation/one", missionId: "mission/one", runId: "run/one", observationType: "open_port",
  statement: "TCP port 443 appeared open.", normalizedValue: { port: 443 }, confidence: 0.8,
  verificationState: "unverified", firstSeenAt: NOW, lastSeenAt: NOW, sensitivity: "private",
  sources: [{ logRecordId: "log/one", parserId: "nmap-xml", parserVersion: "1.0.0" }], createdAt: NOW,
} as const;
const candidate = {
  id: "candidate/one", missionId: "mission/one", runId: "run/one", observationId: "observation/one",
  evidenceType: "port_service_scan", label: "HTTPS service exposure",
  meaning: "The observation may support the service inventory.",
  promotionReason: "Retain the attributable observation for explicit review.",
  validationRequirements: [
    "immutable_content_hash", "attributable_provenance", "normalized_target", "acquired_time", "chain_of_custody",
  ],
  state: "candidate", sensitivity: "private", proposedBy: "ReconScout", createdAt: NOW,
} as const;
const evidence = {
  id: "evidence/one", missionId: "mission/one", runId: "run/one",
  source: "nmap XML parser", acquiredAt: NOW, target: "lab.internal:443/tcp",
  evidenceType: "port_service_scan", contentHash: HASH,
  provenance: { method: "parser", sources: [{ kind: "observation", id: "observation/one" }] },
  confidence: 0.9, sensitivity: "private", verificationState: "verified",
  summary: "HTTPS service exposure", createdBy: "operator-one", createdAt: NOW,
} as const;
const custody = {
  id: "custody-one", evidenceId: "evidence/one", eventType: "verified", actor: "operator-one",
  details: { candidateId: "candidate/one" }, occurredAt: NOW,
} as const;
const diagnosis = {
  id: "failure/one", missionId: "mission/one", runId: "run/one", subjectType: "run", subjectId: "run/one",
  humanReason: "The provider exceeded the bounded response deadline.", category: "timeout",
  code: "provider_deadline_exceeded", originatingComponent: "provider-client", retryHistory: [],
  progressBeforeFailure: { phase: "reconnaissance" }, preservedReferences: [], retryable: true,
  automaticRecovery: [], remediation: "Test provider health before a bounded retry.",
  operatorActions: [{
    kind: "retry_bounded", label: "Retry once", consequence: "Uses one remaining retry.", requiresConfirmation: true,
  }],
  objectiveImpact: "The run is paused with its checkpoint preserved.", state: "active", createdAt: NOW,
} as const;

interface FetchCall { readonly path: string; readonly init?: RequestInit }

let originalFetch: typeof globalThis.fetch;
let originalDocument: PropertyDescriptor | undefined;
let calls: FetchCall[];
let responses: unknown[];

beforeEach(() => {
  originalFetch = globalThis.fetch;
  originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  calls = [];
  responses = [];
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: { cookie: "ti_scale_csrf=csrf-proof" },
  });
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ path: typeof input === "string" ? input : input.toString(), init });
    const payload = responses.shift();
    if (payload === undefined) throw new Error("No mocked operational-truth response remains");
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json", "X-Request-Id": "request-one" },
    });
  }) as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalDocument) Object.defineProperty(globalThis, "document", originalDocument);
  else Reflect.deleteProperty(globalThis, "document");
});

describe("operational-truth API client", () => {
  test("uses canonical scoped URLs for every list and detail read", async () => {
    responses.push(
      { schemaVersion: "2.4", items: [log], nextCursor: null },
      { schemaVersion: "2.4", log },
      { schemaVersion: "2.4", items: [observation], nextCursor: null },
      { schemaVersion: "2.4", observation },
      { schemaVersion: "2.4", items: [candidate], nextCursor: null },
      { schemaVersion: "2.4", candidate },
      { schemaVersion: "2.4", items: [evidence], nextCursor: null },
      { schemaVersion: "2.4", evidence, chainOfCustody: [custody] },
      { schemaVersion: "2.4", items: [diagnosis] },
      { schemaVersion: "2.4", diagnosis },
    );

    expect((await operationalTruthApi.listLogs("mission/one", {
      runId: "run/one", stepId: "step/one", cursor: "cursor+one", limit: 25,
    })).items[0]?.id).toBe("log/one");
    expect((await operationalTruthApi.log("mission/one", "log/one")).log.id).toBe("log/one");
    expect((await operationalTruthApi.listObservations("mission/one", { runId: "run/one" })).items[0]?.id)
      .toBe("observation/one");
    expect((await operationalTruthApi.observation("mission/one", "observation/one")).observation.id)
      .toBe("observation/one");
    expect((await operationalTruthApi.listEvidenceCandidates("mission/one", { state: "candidate", limit: 10 })).items[0]?.id)
      .toBe("candidate/one");
    expect((await operationalTruthApi.evidenceCandidate("mission/one", "candidate/one")).candidate.id)
      .toBe("candidate/one");
    expect((await operationalTruthApi.listVerifiedEvidence("mission/one", { runId: "run/one" })).items[0]?.id)
      .toBe("evidence/one");
    expect((await operationalTruthApi.verifiedEvidence("mission/one", "evidence/one")).chainOfCustody[0]?.id)
      .toBe("custody-one");
    expect((await operationalTruthApi.listFailureDiagnoses("mission/one", "run/one", {
      states: ["active", "terminal"], limit: 40,
    })).items[0]?.id).toBe("failure/one");
    expect((await operationalTruthApi.failureDiagnosis("mission/one", "run/one", "failure/one")).diagnosis.id)
      .toBe("failure/one");

    expect(calls.map((call) => call.path)).toEqual([
      "/api/v2/operational-truth/missions/mission%2Fone/logs?runId=run%2Fone&stepId=step%2Fone&cursor=cursor%2Bone&limit=25",
      "/api/v2/operational-truth/missions/mission%2Fone/logs/log%2Fone",
      "/api/v2/operational-truth/missions/mission%2Fone/observations?runId=run%2Fone",
      "/api/v2/operational-truth/missions/mission%2Fone/observations/observation%2Fone",
      "/api/v2/operational-truth/missions/mission%2Fone/evidence-candidates?limit=10&state=candidate",
      "/api/v2/operational-truth/missions/mission%2Fone/evidence-candidates/candidate%2Fone",
      "/api/v2/operational-truth/missions/mission%2Fone/verified-evidence?runId=run%2Fone",
      "/api/v2/operational-truth/missions/mission%2Fone/verified-evidence/evidence%2Fone",
      "/api/v2/operational-truth/missions/mission%2Fone/runs/run%2Fone/failure-diagnoses?states=active%2Cterminal&limit=40",
      "/api/v2/operational-truth/missions/mission%2Fone/runs/run%2Fone/failure-diagnoses/failure%2Fone",
    ]);
    expect(calls.every((call) => (call.init?.method ?? "GET") === "GET")).toBe(true);
  });

  test("sends deliberate candidate decisions, evidence verification, and diagnosis resolution with idempotency", async () => {
    const reviewed = {
      ...candidate,
      reviewedBy: "operator-one",
      reviewReason: "Independent review completed.",
      reviewedAt: NOW,
    } as const;
    responses.push(
      { schemaVersion: "2.4", candidate: { ...reviewed, state: "validating" } },
      { schemaVersion: "2.4", candidate: { ...reviewed, state: "rejected" } },
      { schemaVersion: "2.4", candidate: { ...reviewed, state: "demoted", promotedEvidenceId: "evidence/one" } },
      { schemaVersion: "2.4", evidence },
      { schemaVersion: "2.4", diagnosis: { ...diagnosis, state: "resolved", resolvedAt: NOW } },
    );

    await operationalTruthApi.promoteEvidenceCandidate(
      "mission/one", "candidate/one", "Begin independent validation.", "promote-key-0001",
    );
    await operationalTruthApi.rejectEvidenceCandidate(
      "mission/one", "candidate/one", "The source is not attributable.", "reject-key-0001",
    );
    await operationalTruthApi.demoteEvidenceCandidate(
      "mission/one", "candidate/one", "Dependent review reopened the evidence.", "demote-key-0001",
    );
    await operationalTruthApi.verifyEvidenceCandidate(
      "mission/one",
      "candidate/one",
      {
        reason: "The immutable source and custody were independently reviewed.",
        source: "nmap XML parser",
        target: "lab.internal:443/tcp",
        acquiredAt: NOW,
        confidence: 0.9,
        provenance: {
          method: "Structured parser with operator review",
          explanation: "The observation remains linked to its redacted source log.",
          sources: [
            { kind: "observation", id: "observation/one" },
            { kind: "engagement_log", id: "log/one" },
          ],
        },
        custody: [{ eventType: "acquired", actor: "ReconScout", occurredAt: NOW }],
      },
      "verify-key-0001",
    );
    await operationalTruthApi.resolveFailureDiagnosis(
      "mission/one",
      "run/one",
      "failure/one",
      {
        actionKind: "retry_bounded",
        verifiedOutcome: "Provider health recovered and the bounded readiness probe passed.",
        confirmed: true,
      },
      "resolve-key-0001",
    );

    expect(calls.map((call) => call.path)).toEqual([
      "/api/v2/operational-truth/missions/mission%2Fone/evidence-candidates/candidate%2Fone/promote",
      "/api/v2/operational-truth/missions/mission%2Fone/evidence-candidates/candidate%2Fone/reject",
      "/api/v2/operational-truth/missions/mission%2Fone/evidence-candidates/candidate%2Fone/demote",
      "/api/v2/operational-truth/missions/mission%2Fone/evidence-candidates/candidate%2Fone/verify",
      "/api/v2/operational-truth/missions/mission%2Fone/runs/run%2Fone/failure-diagnoses/failure%2Fone/resolve",
    ]);
    expect(calls.map((call) => new Headers(call.init?.headers).get("Idempotency-Key"))).toEqual([
      "promote-key-0001", "reject-key-0001", "demote-key-0001", "verify-key-0001", "resolve-key-0001",
    ]);
    expect(calls.every((call) => new Headers(call.init?.headers).get("X-Ti-Scale-CSRF") === "csrf-proof"))
      .toBe(true);
    expect(calls.map((call) => JSON.parse(String(call.init?.body)))).toEqual([
      { reason: "Begin independent validation." },
      { reason: "The source is not attributable." },
      { reason: "Dependent review reopened the evidence." },
      {
        reason: "The immutable source and custody were independently reviewed.",
        source: "nmap XML parser",
        target: "lab.internal:443/tcp",
        acquiredAt: NOW,
        confidence: 0.9,
        provenance: {
          method: "Structured parser with operator review",
          explanation: "The observation remains linked to its redacted source log.",
          sources: [
            { kind: "observation", id: "observation/one" },
            { kind: "engagement_log", id: "log/one" },
          ],
        },
        custody: [{ eventType: "acquired", actor: "ReconScout", occurredAt: NOW }],
      },
      {
        actionKind: "retry_bounded",
        verifiedOutcome: "Provider health recovered and the bounded readiness probe passed.",
        confirmed: true,
      },
    ]);
  });
});

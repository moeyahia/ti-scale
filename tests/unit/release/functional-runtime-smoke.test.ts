import { describe, expect, test } from "bun:test";
import {
  EXPECTED_AUTONOMOUS_ACTION_CLASS_IDS,
  EXPECTED_GUIDED_TOOL_IDS,
  FUNCTIONAL_RUNTIME_PROOF_CONFIRMATION,
  assertConnectedBrain,
  assertCanonicalAutonomousIpReport,
  assertExactRuntimeReadiness,
  assertFunctionalRuntimeLiveness,
  functionalRuntimeProofUsage,
  parseFunctionalRuntimeProofArguments,
} from "../../../scripts/smoke-functional-runtime";

const NOW = new Date("2026-07-20T04:00:00.000Z");
const OBSERVED_AT = "2026-07-20T03:59:30.000Z";
const EXPIRES_AT = "2026-07-20T04:01:00.000Z";

function capabilityEntry(
  kind: "tool" | "tool_dependency",
  id: string,
  testKind: "local_executable_attestation" | "manifest_dependency",
) {
  return {
    component: { kind, id },
    testKind,
    status: "pass",
    availability: "available",
    freshness: { state: "fresh", observedAt: OBSERVED_AT, expiresAt: EXPIRES_AT },
    executionAuthorization: { state: "not_granted", grantsMissionExecution: false },
  };
}

function selfTests() {
  const dependencies = [
    "operator-activation",
    "executable-integrity",
    "isolated-target-free-readiness",
    "direct-argv-adapter",
    "workspace-confinement",
    "result-sink",
    "cancellation",
  ];
  return {
    schemaVersion: "2.4",
    readOnly: true,
    grantsMissionExecution: false,
    accounting: { runtimeRegistryRead: true, manifestValid: true, complete: true },
    results: EXPECTED_GUIDED_TOOL_IDS.flatMap((toolId) => [
      capabilityEntry("tool", toolId, "local_executable_attestation"),
      ...dependencies.map((dependency) => capabilityEntry(
        "tool_dependency",
        `${toolId}/${dependency}`,
        "manifest_dependency",
      )),
    ]),
  };
}

function health(readyToolIds: readonly string[] = EXPECTED_GUIDED_TOOL_IDS) {
  return {
    schemaVersion: "2.4",
    status: "healthy",
    database: { healthy: true },
    eventStream: { status: "healthy" },
    execution: {
      autonomous: "ready",
      guided: "ready",
      guidedToolExecution: "ready",
      localCommanderGuidance: "ready",
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
    },
    dependencies: {
      autonomousRuntime: {
        status: "ready",
        readyActionClassIds: EXPECTED_AUTONOMOUS_ACTION_CLASS_IDS,
        components: {
          localProcessExecution: true,
          mcpExecution: false,
          enforcingProvider: true,
          resultAwareSpecialistExecution: true,
          durableActionBoundary: true,
          exactRuntimeManifest: true,
        },
      },
      guidedLocalToolExecution: {
        status: "ready",
        executionBinding: "reviewed_local_process",
        readyToolIds,
        exactDecisionRequired: true,
        providerContact: false,
        mcpTransport: false,
        expiresAt: EXPIRES_AT,
      },
      secondBrain: { status: "healthy", canonicalStoreAvailable: true },
    },
  };
}

describe("functional runtime production proof", () => {
  test("keeps constant-time process liveness distinct from rich runtime readiness", () => {
    expect(() => assertFunctionalRuntimeLiveness({
      schemaVersion: "2.4",
      status: "healthy",
      service: "ti-scale",
      database: { healthy: true },
      eventStream: { status: "healthy" },
    })).not.toThrow();
    expect(() => assertFunctionalRuntimeLiveness({
      schemaVersion: "2.4",
      status: "healthy",
      database: { healthy: false },
      eventStream: { status: "healthy" },
    })).toThrow("liveness is not fully healthy");
  });

  test("requires the exact explicit mutation confirmation", () => {
    expect(() => parseFunctionalRuntimeProofArguments([
      "--execute",
      "--confirm",
      FUNCTIONAL_RUNTIME_PROOF_CONFIRMATION,
    ])).not.toThrow();
    expect(() => parseFunctionalRuntimeProofArguments([])).toThrow(functionalRuntimeProofUsage());
    expect(() => parseFunctionalRuntimeProofArguments([
      "--execute",
      "--confirm",
      "wrong",
    ])).toThrow(functionalRuntimeProofUsage());
    expect(() => parseFunctionalRuntimeProofArguments([
      "--execute",
      "--confirm",
      FUNCTIONAL_RUNTIME_PROOF_CONFIRMATION,
      "--token-file",
      "/tmp/token",
    ])).toThrow(functionalRuntimeProofUsage());
  });

  test("accepts only the exact seven-tool Guided and three-class Autonomous readiness proof", () => {
    expect(assertExactRuntimeReadiness(health(), selfTests(), NOW)).toEqual({
      guidedToolIds: EXPECTED_GUIDED_TOOL_IDS,
      capabilityReceiptExpiresAt: EXPIRES_AT,
    });
    expect(() => assertExactRuntimeReadiness(
      health(EXPECTED_GUIDED_TOOL_IDS.filter((id) => id !== "kali:nmap-tcp-connect-service-scan")),
      selfTests(),
      NOW,
    )).toThrow("exact reviewed inventory");
    const incompleteAutonomous = health() as any;
    incompleteAutonomous.dependencies.autonomousRuntime.readyActionClassIds = [
      "dns_domain_certificate_discovery",
      "active_host_discovery",
    ];
    expect(() => assertExactRuntimeReadiness(incompleteAutonomous, selfTests(), NOW))
      .toThrow("exact reviewed inventory");
    const blocked = health() as any;
    blocked.execution.autonomous = "unavailable";
    expect(() => assertExactRuntimeReadiness(blocked, selfTests(), NOW))
      .toThrow("not simultaneously ready");
    const commanderUnavailable = health() as any;
    commanderUnavailable.execution.localCommanderGuidance = "unavailable";
    expect(() => assertExactRuntimeReadiness(commanderUnavailable, selfTests(), NOW))
      .toThrow("not simultaneously ready");
    expect(() => assertExactRuntimeReadiness(health(), selfTests(), new Date(EXPIRES_AT)))
      .toThrow("stale");
  });

  test("reports lifecycle node semantics and a round-trip verified connected Vault", () => {
    const result = assertConnectedBrain(
      {
        schemaVersion: "2.4",
        status: "healthy",
        database: { status: "healthy" },
        search: { status: "healthy" },
        vault: { connected: 1 },
      },
      {
        counts: {
          confirmed: 4,
          verified: 12,
          candidateNodes: 3,
          stale: 2,
          disputed: 1,
          edges: 18,
          contextPacks: 7,
        },
      },
      {
        connections: [{
          id: "vault-ti-scale",
          displayName: "Ti-Scale-Brain",
          status: "connected",
          pathAvailable: true,
          trackedNoteCount: 16,
          healthChecks: { write: true, read: true, rename: true, delete: true },
        }],
        conflicts: [],
      },
    );
    expect(result.connectionId).toBe("vault-ti-scale");
    expect(result.receipt).toMatchObject({
      visibleNodes: 22,
      edges: 18,
      contextPacks: 7,
      trackedVaultNotes: 16,
      openConflicts: 0,
    });
  });

  test("accepts only a redacted canonical Autonomous IP report with explicit truth stages", () => {
    const report = {
      schemaVersion: "2.4-report.1",
      mission: { id: "mission-ip" },
      run: { id: "run-ip", journey: "autonomous", status: "completed" },
      engagementLogs: {
        classification: "technical_record_not_evidence",
        rawPayloadsOmitted: true,
      },
      observations: {
        classification: "parsed_statement_not_automatically_verified",
        rawValuesOmitted: true,
      },
      verifiedEvidence: {
        classification: "canonical_verified_evidence_only",
        records: [
          { evidenceType: "host_liveness_proof" },
          { evidenceType: "port_service_scan_result" },
        ],
        extractedTextOmitted: true,
        provenancePayloadOmitted: true,
      },
      findings: {
        verified: [],
        reviewRequired: [],
        unverifiedClaimsNotAsserted: true,
      },
      topology: {
        nodes: [{ id: "asset", verificationState: "unverified" }],
        edges: [],
        propertiesOmitted: true,
      },
      contextPacks: {
        records: [{ id: "context-ip" }],
        memoryContentOmitted: true,
      },
      privacy: { redacted: true },
    };
    expect(assertCanonicalAutonomousIpReport(
      report,
      "mission-ip",
      "run-ip",
      ["host_liveness_proof", "port_service_scan_result"],
      1,
      0,
    )).toEqual({ verifiedEvidence: 2, topologyNodes: 1, topologyEdges: 0 });

    const overclaimed = structuredClone(report) as any;
    overclaimed.findings.verified.push({ id: "fabricated-finding" });
    expect(() => assertCanonicalAutonomousIpReport(
      overclaimed,
      "mission-ip",
      "run-ip",
      ["host_liveness_proof", "port_service_scan_result"],
      1,
      0,
    )).toThrow("taxonomy, scope, or privacy contract drifted");

    const promotedTopology = structuredClone(report) as any;
    promotedTopology.topology.nodes[0].verificationState = "verified";
    expect(() => assertCanonicalAutonomousIpReport(
      promotedTopology,
      "mission-ip",
      "run-ip",
      ["host_liveness_proof", "port_service_scan_result"],
      1,
      0,
    )).toThrow("taxonomy, scope, or privacy contract drifted");
  });
});

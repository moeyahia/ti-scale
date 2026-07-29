import { afterEach, describe, expect, test } from "bun:test";
import { runtimeV2Api } from "../../../src/data/api/runtimeV2";
import {
  parseAutonomousActivationReceiptDetail,
  parseAutonomousActivationReceiptHistory,
  parseRunSnapshot,
} from "../../../src/domain/schemas/runtimeV2";

const originalFetch = globalThis.fetch;
const HASH = "a".repeat(64);

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function summary(overrides: Record<string, unknown> = {}) {
  return {
    id: "receipt-proof",
    runId: "run-proof",
    generation: 2,
    issuedAt: "2026-07-28T12:00:00.000Z",
    expiresAt: "2026-07-28T14:00:00.000Z",
    planningRoute: "provider_advisory",
    plannerId: "VulnIntel",
    planningModelAssignmentId: "assignment-planning",
    selectedActionClassCount: 1,
    activatedActionClassCount: 1,
    modelRouteCount: 2,
    toolRouteCount: 1,
    bindingCount: 1,
    runtimeGenerationHash: HASH,
    brainContextPackId: "context-proof",
    receiptHash: HASH,
    integrity: {
      status: "verified",
      code: null,
      verifiedAt: "2026-07-28T12:01:00.000Z",
      humanMessage: "Canonical records match.",
      remediation: null,
    },
    ...overrides,
  };
}

function receipt() {
  return {
    id: "receipt-proof",
    schemaVersion: "2.4",
    missionId: "mission-proof",
    runId: "run-proof",
    contractId: "contract-proof",
    generation: 2,
    contractVersion: 1,
    contractHash: HASH,
    runtimeGenerationHash: HASH,
    modelAssignmentSetHash: HASH,
    evidencePolicyHash: HASH,
    brainContextPackId: "context-proof",
    brainContextPackHash: HASH,
    planning: {
      route: "provider_advisory",
      selection: {
        route: "provider_advisory",
        agentId: "VulnIntel",
        primaryConfigurationId: "configuration-planning",
        fallbackConfigurationId: null,
        enforcementMode: "advisor_only",
        disclosureClass: "sanitized_internal",
        executionAuthority: "none",
      },
      selectionHash: HASH,
      plannerId: "VulnIntel",
      modelAssignmentId: "assignment-planning",
      primaryConfigurationId: "configuration-planning",
      fallbackConfigurationId: null,
      primaryConfigurationHash: HASH,
      fallbackConfigurationHash: null,
    },
    selectedActionClassIds: ["port_service_enumeration"],
    selectedActionClassCount: 1,
    activatedActionClassCount: 1,
    routeSetHash: HASH,
    issuedBy: "operator:test",
    issuedAt: "2026-07-28T12:00:00.000Z",
    expiresAt: "2026-07-28T14:00:00.000Z",
    receiptHash: HASH,
    items: [{
      actionClassId: "port_service_enumeration",
      agentId: "ReconScout",
      executionModelAssignmentId: "assignment-execution",
      executionPrimaryConfigurationId: "configuration-execution",
      executionFallbackConfigurationId: null,
      toolId: "nmap-service-scan",
      toolBindingKind: "local",
      mcpServerId: null,
      toolActivationReceiptId: "tool-receipt",
      toolActivationReceiptHash: HASH,
      toolManifestHash: HASH,
      evidenceTypeIds: ["port_service_scan_result"],
      evidenceProducerIds: ["nmap-normalizer"],
      routeExpiresAt: "2026-07-28T14:00:00.000Z",
      routeHash: HASH,
      createdAt: "2026-07-28T12:00:00.000Z",
    }],
    bindings: [{
      id: "binding-proof",
      receiptId: "receipt-proof",
      sequence: 1,
      bindingType: "launch",
      subjectId: "run-proof",
      subjectDigest: HASH,
      runtimeGenerationHash: HASH,
      planId: null,
      stepId: null,
      actionId: null,
      contextPackId: "context-proof",
      providerTurnId: null,
      previousBindingHash: null,
      boundBy: "operator:test",
      boundAt: "2026-07-28T12:00:00.000Z",
      bindingHash: HASH,
    }],
  };
}

describe("Autonomous Activation Proof frontend contract", () => {
  test("parses verified, expired, and integrity-failed compact projections", () => {
    const parsed = parseAutonomousActivationReceiptHistory({
      schemaVersion: "2.4",
      items: [
        summary(),
        summary({
          id: "receipt-expired",
          generation: 1,
          planningRoute: "local_deterministic",
          plannerId: "ti-scale.local-autonomous-contract-planner.v1",
          planningModelAssignmentId: null,
          integrity: {
            status: "expired",
            code: "activation_receipt_expired",
            verifiedAt: "2026-07-28T15:00:00.000Z",
            humanMessage: "This proof expired.",
            remediation: "Re-run readiness.",
          },
        }),
        summary({
          id: "receipt-drift",
          integrity: {
            status: "integrity_failure",
            code: "activation_receipt_runtime_generation_drift",
            verifiedAt: "2026-07-28T12:01:00.000Z",
            humanMessage: "Runtime generation changed.",
            remediation: "Keep the run stopped.",
          },
        }),
      ],
    });
    expect(parsed.items.map(({ integrity }) => integrity.status)).toEqual([
      "verified",
      "expired",
      "integrity_failure",
    ]);
    expect(parsed.items[1]?.planningRoute).toBe("local_deterministic");
  });

  test("parses exact detail routes and rejects malformed integrity hashes or lineage", () => {
    const payload = {
      schemaVersion: "2.4",
      summary: summary(),
      receipt: receipt(),
    };
    expect(parseAutonomousActivationReceiptDetail(payload).receipt.items[0])
      .toMatchObject({
        actionClassId: "port_service_enumeration",
        executionModelAssignmentId: "assignment-execution",
        toolId: "nmap-service-scan",
      });
    expect(() => parseAutonomousActivationReceiptDetail({
      ...payload,
      summary: summary({ runtimeGenerationHash: "not-a-hash" }),
    })).toThrow("runtimeGenerationHash must be a SHA-256");
    expect(() => parseAutonomousActivationReceiptDetail({
      ...payload,
      summary: summary({ runId: "another-run" }),
    })).toThrow("lineage is invalid");
  });

  test("retains backward-compatible missing compact proof as explicit null", () => {
    const parsed = parseRunSnapshot({
      schemaVersion: "2.4",
      run: {
        id: "run-proof",
        missionId: "mission-proof",
        missionName: "Proof mission",
        objective: "Verify the exact activation proof.",
        journey: "autonomous",
        status: "planning",
        statusReason: null,
        progress: 0.1,
        nextAction: "Complete readiness",
        currentPlanId: null,
        currentStepId: null,
        currentOwnerId: null,
        lastHeartbeatAt: null,
        leaseExpiresAt: null,
        startedAt: null,
        endedAt: null,
        createdAt: "2026-07-28T12:00:00.000Z",
        updatedAt: "2026-07-28T12:00:00.000Z",
        version: 1,
      },
      latestCheckpoint: null,
    });
    expect(parsed.currentAutonomousActivationReceipt).toBeNull();
  });

  test("uses encoded run-scoped history and exact detail endpoints", async () => {
    const calls: string[] = [];
    globalThis.fetch = (async (input) => {
      calls.push(String(input));
      return new Response(JSON.stringify(
        calls.length === 1
          ? { schemaVersion: "2.4", items: [summary()] }
          : {
              schemaVersion: "2.4",
              summary: summary(),
              receipt: receipt(),
            },
      ), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    await runtimeV2Api.activationReceipts("run/proof", 25);
    await runtimeV2Api.activationReceipt("run/proof", "receipt/proof");
    expect(calls).toEqual([
      "/api/v2/runs/run%2Fproof/autonomous-activation-receipts?limit=25",
      "/api/v2/runs/run%2Fproof/autonomous-activation-receipts/receipt%2Fproof",
    ]);
  });
});

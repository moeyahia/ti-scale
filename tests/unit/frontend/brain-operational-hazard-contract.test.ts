import { describe, expect, test } from "bun:test";
import { parseMemoryNodeDetail } from "../../../src/domain/schemas/brain";

const timestamp = "2026-07-20T12:00:00.000Z";

const reference = (id: string, nodeType: "attack_procedure" | "procedure_version" | "technology_product" | "exact_version_fingerprint" | "framework" | "prerequisite" | "health_check" | "recovery_pattern") => ({
  id,
  nodeType,
  title: id.replaceAll("-", " "),
  summary: "Generalized reusable attack knowledge.",
  confidence: 0.96,
  lifecycleStatus: "verified",
});

const payload = {
  schemaVersion: "2.4",
  node: {
    id: "hazard-worker-hang",
    nodeType: "operational_hazard",
    title: "Bounded worker request can hang",
    summary: "Repeated requests can leave the execution worker unresponsive.",
    body: "Reusable operational guardrail.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.96,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    version: 1,
    pinned: false,
    createdAt: timestamp,
    updatedAt: timestamp,
    authorType: "operator",
    provenance: {
      method: "derived",
      explanation: "Operator-reviewed local evidence was generalized before retention.",
      sources: [{ sourceType: "private_receipt", sourceId: "receipt-0123456789abcdef0123", acquiredAt: timestamp }],
    },
    retentionPolicy: {},
  },
  sources: [{ sourceType: "private_receipt", sourceId: "receipt-0123456789abcdef0123", acquiredAt: timestamp }],
  versions: [{ version: 1, title: "Bounded worker request can hang", summary: "Reusable guardrail.", changedAt: timestamp, changedBy: "operator" }],
  backlinks: [],
  outgoing: [],
  usage: [],
  operationalHazard: {
    procedure: reference("procedure-bounded-check", "attack_procedure"),
    procedureVersion: reference("procedure-version-one", "procedure_version"),
    affectedProducts: [reference("product-managed-worker", "technology_product")],
    affectedVersions: [reference("version-worker-one", "exact_version_fingerprint")],
    affectedStack: [reference("stack-managed-runtime", "framework")],
    prerequisites: [reference("prerequisite-health", "prerequisite")],
    observedStates: [reference("health-worker-probe", "health_check")],
    orderedSequence: ["Confirm health", "Run one bounded request", "Checkpoint the result"],
    normalizedExecution: {
      parameters: { automaticRetries: 0, healthProbeRequired: true, payloadShape: "bounded-scalar" },
      loadMinimum: 1,
      concurrencyMinimum: 1,
      timingWindowMs: 5_000,
    },
    applicabilityConstraints: {
      requireExactProcedureVersion: true,
      requireAllStackNodes: true,
      requireAllPrerequisites: true,
      requireObservedState: true,
    },
    symptom: {
      observed: "The worker stopped returning bounded results",
      affectedComponent: "Managed execution worker",
    },
    stateTransition: { before: "Health probe passed", after: "Execution worker stopped responding" },
    corroboration: { exactHangCount: 2, observedAttemptCount: 3, operatorReportedResetMinimum: 11 },
    safeHealthGate: ["A fresh minimal health probe returns the expected scalar result"],
    unsafeRetryConditions: ["The health probe does not return"],
    recovery: {
      summary: "Recycle the disposable worker before selecting a safer represented route",
      pattern: reference("recovery-worker-recycle", "recovery_pattern"),
      cost: { resetCount: 2, operatorReportedResetCountMinimum: 11, requiresDisposableTargetReset: true },
    },
    alternatives: {
      sequence: ["Restore a clean worker", "Use the lower-risk diagnostic"],
      procedure: reference("procedure-lower-risk", "attack_procedure"),
    },
    confidence: 0.95,
    freshness: { observedAt: timestamp, freshUntil: "2099-07-20T12:00:00.000Z", status: "current" },
    provenanceReceipt: {
      profileVersion: 1,
      sourceCount: 1,
      receiptIds: ["receipt-0123456789abcdef0123"],
      receiptHash: "a".repeat(64),
      recordedAt: timestamp,
    },
  },
};

describe("Operational hazard node-detail contract", () => {
  test("preserves the structured execution boundary and keeps corroborated hangs separate from reported resets", () => {
    const detail = parseMemoryNodeDetail(payload);
    expect(detail.operationalHazard).toMatchObject({
      procedure: { id: "procedure-bounded-check", title: "procedure bounded check" },
      affectedVersions: [{ id: "version-worker-one" }],
      affectedStack: [{ id: "stack-managed-runtime" }],
      normalizedExecution: {
        parameters: { automaticRetries: 0, healthProbeRequired: true, payloadShape: "bounded-scalar" },
        loadMinimum: 1,
        concurrencyMinimum: 1,
        timingWindowMs: 5_000,
      },
      corroboration: {
        exactHangCount: 2,
        observedAttemptCount: 3,
        operatorReportedResetMinimum: 11,
      },
      provenanceReceipt: { sourceCount: 1, receiptIds: ["receipt-0123456789abcdef0123"] },
    });
  });

  test("rejects an unknown applicability rule instead of silently weakening the display contract", () => {
    expect(() => parseMemoryNodeDetail({
      ...payload,
      operationalHazard: {
        ...payload.operationalHazard,
        applicabilityConstraints: { futureUnsafeRule: true },
      },
    })).toThrow("applicability constraint is unsupported");
  });
});

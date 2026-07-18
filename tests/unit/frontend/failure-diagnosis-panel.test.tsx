import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { FailureDiagnosisV24 } from "../../../src/domain/types/operationalTruth";
import {
  buildFailureResolutionRequest,
  declaredFailureActions,
  FailureDiagnosisDetailView,
} from "../../../src/features/runs/FailureDiagnosisPanel";

const NOW = "2026-07-16T10:00:00.000Z";

const diagnosis: FailureDiagnosisV24 = {
  id: "failure-provider-timeout",
  missionId: "mission-authorized-lab",
  runId: "run-authorized-lab",
  stepId: "step-service-validation",
  actionId: "action-provider-analysis",
  subjectType: "action",
  subjectId: "action-provider-analysis",
  humanReason: "The provider exceeded the bounded response deadline while analyzing the verified service inventory.",
  category: "timeout",
  code: "provider_deadline_exceeded",
  originatingComponent: "provider-client",
  lastSuccessEventId: "event-service-inventory-persisted",
  failedComponentRef: "provider-turn-42",
  targetSummary: "Authorized lab asset web-01",
  policyOrDependency: "provider circuit breaker",
  rawErrorLogId: "log-provider-timeout-redacted",
  retryHistory: [{ attempt: 1, category: "timeout", bounded: true }],
  progressBeforeFailure: { phase: "service analysis", verifiedEvidence: 3 },
  preservedReferences: [
    { kind: "checkpoint", id: "checkpoint-41", meaning: "Last durable plan and budget boundary" },
    { kind: "evidence", id: "evidence-service-inventory", meaning: "Verified service inventory remains intact" },
  ],
  retryable: true,
  automaticRecovery: [{ action: "open_circuit", result: "provider isolated for 30 seconds" }],
  remediation: "Test provider health, then use the one bounded retry declared below.",
  operatorActions: [
    {
      kind: "test_connection",
      label: "Test provider connection",
      consequence: "Runs a non-executing readiness probe.",
      requiresConfirmation: false,
    },
    {
      kind: "retry_bounded",
      label: "Retry once",
      consequence: "Uses the single retry remaining in the signed mission budget.",
      requiresConfirmation: true,
    },
  ],
  objectiveImpact: "The current step cannot advance, but the plan, checkpoint, and three verified evidence records are preserved.",
  state: "active",
  createdAt: NOW,
};

describe("Failure Diagnosis resolution boundary", () => {
  test("builds an audited resolution only from a server-declared action", () => {
    expect(buildFailureResolutionRequest(
      diagnosis,
      "retry_bounded",
      "The health probe passed and the single bounded retry completed successfully.",
      true,
    )).toEqual({
      actionKind: "retry_bounded",
      verifiedOutcome: "The health probe passed and the single bounded retry completed successfully.",
      confirmed: true,
    });

    expect(() => buildFailureResolutionRequest(
      diagnosis,
      "start_new_run",
      "A new run was started even though the server did not declare that action.",
      true,
    )).toThrow("declared by the server");
    expect(() => buildFailureResolutionRequest(diagnosis, "retry_bounded", "It worked.", true))
      .toThrow("at least 16 characters");
    expect(() => buildFailureResolutionRequest(
      diagnosis,
      "retry_bounded",
      "The retry was independently verified.",
      false,
    )).toThrow("Confirm that the declared action");
    expect(() => buildFailureResolutionRequest(
      { ...diagnosis, state: "resolved" },
      "retry_bounded",
      "The retry was independently verified.",
      true,
    ))
      .toThrow("active or terminal");
  });

  test("does not infer another action from retryability or failure category", () => {
    expect(declaredFailureActions({
      operatorActions: [diagnosis.operatorActions[0]!],
    }).map((action) => action.kind)).toEqual(["test_connection"]);
  });

  test("keeps terminal diagnosis reconciliation behind the same typed action and confirmation gate", () => {
    const terminal = { ...diagnosis, state: "terminal" as const };
    expect(buildFailureResolutionRequest(
      terminal,
      "test_connection",
      "The terminal provider record was independently reconciled after a healthy readiness probe.",
      true,
    )).toEqual({
      actionKind: "test_connection",
      verifiedOutcome: "The terminal provider record was independently reconciled after a healthy readiness probe.",
      confirmed: true,
    });
    const markup = renderToStaticMarkup(<FailureDiagnosisDetailView
      diagnosis={terminal}
      onResolve={() => undefined}
    />);
    expect(markup).toContain("Verified resolution outcome");
    expect(markup).toContain("Record audited resolution");
  });
});

describe("Failure Diagnosis explanation", () => {
  test("renders cause, provenance, recovery, impact, preserved records, and only declared actions", () => {
    const markup = renderToStaticMarkup(<FailureDiagnosisDetailView
      diagnosis={diagnosis}
      onResolve={() => undefined}
    />);

    expect(markup).toContain("The provider exceeded the bounded response deadline");
    expect(markup).toContain("provider_deadline_exceeded");
    expect(markup).toContain("provider-client");
    expect(markup).toContain("event-service-inventory-persisted");
    expect(markup).toContain("provider-turn-42");
    expect(markup).toContain("log-provider-timeout-redacted");
    expect(markup).toContain("Retryable only through a declared bounded action");
    expect(markup).toContain("1 automatic recovery attempt recorded");
    expect(markup).toContain("Last durable plan and budget boundary");
    expect(markup).toContain("Verified service inventory remains intact");
    expect(markup).toContain("Test provider health, then use the one bounded retry");
    expect(markup).toContain("The current step cannot advance");
    expect(markup).toContain("Test provider connection");
    expect(markup).toContain("Retry once");
    expect(markup).not.toContain("Start a new run");
    expect(markup).toContain("Selecting an action here does not execute it");
    expect(markup).toContain("Record audited resolution");
    expect(markup).toContain("immutable audit trail");
  });

  test("keeps original declared actions visible after resolution but removes the resolution form", () => {
    const markup = renderToStaticMarkup(<FailureDiagnosisDetailView
      diagnosis={{ ...diagnosis, state: "resolved", resolvedAt: "2026-07-16T10:05:00.000Z" }}
      onResolve={() => undefined}
    />);

    expect(markup).toContain("Retry once");
    expect(markup).toContain("cannot be resolved again");
    expect(markup).not.toContain("Verified resolution outcome");
    expect(markup).not.toContain("Record audited resolution");
  });
});

import { describe, expect, test } from "bun:test";
import { fingerprintAction, normalizeFingerprintValue } from "../ActionFingerprint";
import { enforceJourneyActionBoundary } from "../JourneyActionBoundary";
import type { ActionIntent, GuidedDecision } from "../types";

function action(overrides: Partial<ActionIntent> = {}): ActionIntent {
  return {
    missionId: "mission-1",
    actionType: "network_scan",
    arguments: { ports: [80, 443], timing: "T3" },
    target: "10.10.10.10",
    runId: "run-1",
    stepId: "step-1",
    planVersion: 2,
    precedingState: { evidence: ["ev-1"] },
    ...overrides,
  };
}

function decision(intent: ActionIntent, overrides: Partial<GuidedDecision> = {}): GuidedDecision {
  return {
    id: "decision-1",
    missionId: "mission-1",
    runId: intent.runId,
    stepId: intent.stepId,
    journey: "guided",
    actionFingerprint: fingerprintAction(intent).hash,
    status: "authorized",
    authorizedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2026-01-01T01:00:00Z",
    version: 1,
    ...overrides,
  };
}

describe("action fingerprints", () => {
  test("object key order and volatile tracing values do not hide repetition", () => {
    const first = action({
      arguments: { target: "x", requestId: "one", nested: { trace_id: "trace-a", value: 3 } },
    });
    const second = action({
      arguments: { nested: { value: 3, trace_id: "trace-b" }, requestId: "two", target: "x" },
    });
    expect(fingerprintAction(first).hash).toBe(fingerprintAction(second).hash);
  });

  test("material parameters, target, step, and plan version change the fingerprint", () => {
    const base = fingerprintAction(action()).hash;
    expect(fingerprintAction(action({ arguments: { ports: [22] } })).hash).not.toBe(base);
    expect(fingerprintAction(action({ target: "10.10.10.11" })).hash).not.toBe(base);
    expect(fingerprintAction(action({ stepId: "step-2" })).hash).not.toBe(base);
    expect(fingerprintAction(action({ planVersion: 3 })).hash).not.toBe(base);
  });

  test("normalization is recursive, stable, and does not mutate input", () => {
    const value = { z: "  value\r\n", timestamp: "now", a: [2, { nonce: "x", keep: true }] };
    expect(normalizeFingerprintValue(value)).toEqual({ a: [2, { keep: true }], z: "value" });
    expect(value.timestamp).toBe("now");
  });

  test("custom volatile-key policy is honored without applying hidden defaults", () => {
    const withTimestamp = action({ arguments: { timestamp: "one", requestId: "same" } });
    const changedTimestamp = action({ arguments: { timestamp: "two", requestId: "same" } });
    expect(
      fingerprintAction(withTimestamp, { volatileKeys: new Set(["request_id"]) }).hash,
    ).not.toBe(fingerprintAction(changedTimestamp, { volatileKeys: new Set(["request_id"]) }).hash);
  });
});

describe("journey action boundary", () => {
  test("Guided authorization consumes one exact represented action", () => {
    const intent = action();
    const result = enforceJourneyActionBoundary({
      journey: "guided",
      action: intent,
      guidedDecision: decision(intent),
      now: "2026-01-01T00:10:00Z",
    });
    expect(result.allowed).toBe(true);
    if (result.allowed) {
      expect(result.consumedDecision?.status).toBe("consumed");
      expect(result.consumedDecision?.version).toBe(2);
    }
  });

  test("Guided rejects changed parameters, wrong scope, expired, and reused decisions", () => {
    const represented = action();
    const changed = action({ arguments: { ports: [80, 443, 8080], timing: "T3" } });
    expect(
      enforceJourneyActionBoundary({
        journey: "guided",
        action: changed,
        guidedDecision: decision(represented),
        now: "2026-01-01T00:10:00Z",
      }),
    ).toMatchObject({ allowed: false, reason: "guided_action_changed" });
    expect(
      enforceJourneyActionBoundary({
        journey: "guided",
        action: represented,
        guidedDecision: decision(represented, { stepId: "step-other" }),
        now: "2026-01-01T00:10:00Z",
      }),
    ).toMatchObject({ allowed: false, reason: "guided_decision_scope_mismatch" });
    expect(
      enforceJourneyActionBoundary({
        journey: "guided",
        action: represented,
        guidedDecision: decision(represented, { missionId: "mission-other" }),
        now: "2026-01-01T00:10:00Z",
      }),
    ).toMatchObject({ allowed: false, reason: "guided_decision_scope_mismatch" });
    expect(
      enforceJourneyActionBoundary({
        journey: "guided",
        action: represented,
        guidedDecision: decision(represented, { expiresAt: "2026-01-01T00:09:00Z" }),
        now: "2026-01-01T00:10:00Z",
      }),
    ).toMatchObject({ allowed: false, reason: "guided_decision_expired" });
    expect(
      enforceJourneyActionBoundary({
        journey: "guided",
        action: represented,
        guidedDecision: decision(represented, { expiresAt: "not-a-date" }),
        now: "2026-01-01T00:10:00Z",
      }),
    ).toMatchObject({ allowed: false, reason: "guided_decision_expired" });
    expect(
      enforceJourneyActionBoundary({
        journey: "guided",
        action: represented,
        guidedDecision: decision(represented, { status: "consumed", consumedAt: "2026-01-01T00:05:00Z" }),
        now: "2026-01-01T00:10:00Z",
      }),
    ).toMatchObject({ allowed: false, reason: "guided_decision_consumed" });
  });

  test("Guided never executes without an explicit authorized decision", () => {
    expect(
      enforceJourneyActionBoundary({ journey: "guided", action: action(), now: "2026-01-01T00:10:00Z" }),
    ).toMatchObject({ allowed: false, reason: "guided_decision_required" });
    expect(
      enforceJourneyActionBoundary({
        journey: "guided",
        action: action(),
        guidedDecision: decision(action(), { status: "pending" }),
        now: "2026-01-01T00:10:00Z",
      }),
    ).toMatchObject({ allowed: false, reason: "guided_decision_not_authorized" });
  });

  test("Autonomous allows only signed-contract action classes and exact targets", () => {
    const contract = {
      runId: "run-1",
      version: 2,
      status: "signed" as const,
      allowedActionTypes: ["network_scan"],
      prohibitedActionTypes: ["destructive_reset"],
      allowedTargets: ["10.10.10.10"],
    };
    expect(
      enforceJourneyActionBoundary({
        journey: "autonomous",
        action: action(),
        autonomousContract: contract,
        now: "2026-01-01T00:10:00Z",
      }).allowed,
    ).toBe(true);
    expect(
      enforceJourneyActionBoundary({
        journey: "autonomous",
        action: action({ target: "10.10.10.99" }),
        autonomousContract: contract,
        now: "2026-01-01T00:10:00Z",
      }),
    ).toMatchObject({ allowed: false, reason: "autonomous_target_not_allowed" });
    expect(
      enforceJourneyActionBoundary({
        journey: "autonomous",
        action: action({ actionType: "destructive_reset" }),
        autonomousContract: contract,
        now: "2026-01-01T00:10:00Z",
      }),
    ).toMatchObject({ allowed: false, reason: "autonomous_action_not_allowed" });
    expect(
      enforceJourneyActionBoundary({
        journey: "autonomous",
        action: action(),
        autonomousContract: { ...contract, status: "draft" },
        now: "2026-01-01T00:10:00Z",
      }),
    ).toMatchObject({ allowed: false, reason: "autonomous_contract_not_signed" });
  });
});

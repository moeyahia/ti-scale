import { describe, expect, test } from "bun:test";
import { fingerprintAction } from "../ActionFingerprint";
import { RunSupervisor } from "../RunSupervisor";
import type { ActionIntent, GuidedDecision, SupervisedRun } from "../types";

function runningRun(journey: "autonomous" | "guided"): SupervisedRun {
  return {
    id: "run-1",
    missionId: "mission-1",
    journey,
    state: "running",
    launched: true,
    contractVersion: journey === "autonomous" ? 1 : undefined,
    contractConfirmedAt: journey === "autonomous" ? "2026-01-01T00:00:00Z" : undefined,
    stateVersion: 3,
    stateReason: "Executing",
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  };
}

const action: ActionIntent = {
  missionId: "mission-1",
  actionType: "scan",
  arguments: { ports: [80] },
  target: "target-1",
  runId: "run-1",
  stepId: "step-1",
  planVersion: 1,
};

describe("RunSupervisor orchestration foundation", () => {
  test("gates actions before a provider/tool is called", () => {
    const supervisor = new RunSupervisor();
    expect(
      supervisor.authorizeAction({
        run: runningRun("autonomous"),
        action,
        now: "2026-01-01T00:00:01Z",
        autonomousContract: {
          runId: "run-1",
          version: 1,
          status: "signed",
          allowedActionTypes: ["scan"],
          allowedTargets: ["target-1"],
        },
      }).allowed,
    ).toBe(true);

    const guidedDecision: GuidedDecision = {
      id: "decision-1",
      missionId: "mission-1",
      runId: "run-1",
      stepId: "step-1",
      journey: "guided",
      actionFingerprint: fingerprintAction(action).hash,
      status: "authorized",
      expiresAt: "2026-01-01T01:00:00Z",
      version: 1,
    };
    expect(
      supervisor.authorizeAction({
        run: runningRun("guided"),
        action,
        guidedDecision,
        now: "2026-01-01T00:00:01Z",
      }),
    ).toMatchObject({ allowed: true, consumedDecision: { status: "consumed" } });
  });

  test("does not authorize any action unless the run is actively running", () => {
    expect(
      new RunSupervisor().authorizeAction({
        run: { ...runningRun("guided"), state: "waiting_guided_decision" },
        action,
        now: "2026-01-01T00:00:01Z",
      }),
    ).toMatchObject({ allowed: false });
    expect(
      new RunSupervisor().authorizeAction({
        run: runningRun("guided"),
        action: { ...action, missionId: "mission-other" },
        now: "2026-01-01T00:00:01Z",
      }),
    ).toMatchObject({ allowed: false, reason: "action_run_mismatch" });
  });

  test("rejects stale Autonomous contract versions at the supervisor boundary", () => {
    expect(
      new RunSupervisor().authorizeAction({
        run: runningRun("autonomous"),
        action,
        now: "2026-01-01T00:00:01Z",
        autonomousContract: {
          runId: "run-1",
          version: 2,
          status: "signed",
          allowedActionTypes: ["scan"],
          allowedTargets: ["target-1"],
        },
      }),
    ).toMatchObject({ allowed: false, reason: "autonomous_contract_not_signed" });
  });

  test("combines progress, loop, and budget evaluation into a deterministic directive", () => {
    const supervisor = new RunSupervisor();
    const result = supervisor.evaluateCompletedAction({
      history: [
        {
          actionId: "a1",
          actionFingerprint: "repeat",
          meaningfulProgress: false,
          progressSignatureAfter: "same",
          completedAt: "2026-01-01T00:00:01Z",
        },
        {
          actionId: "a2",
          actionFingerprint: "repeat",
          meaningfulProgress: false,
          progressSignatureAfter: "same",
          completedAt: "2026-01-01T00:00:02Z",
        },
      ],
      observation: {
        actionId: "a3",
        actionFingerprint: "repeat",
        completedAt: "2026-01-01T00:00:03Z",
      },
      before: {},
      after: {},
      budgetState: { limits: { toolCalls: 5 }, usage: { toolCalls: 2 } },
      budgetDelta: { toolCalls: 1 },
    });
    expect(result.directive).toBe("recover");
    expect(result.loops.map((finding) => finding.kind)).toContain("identical_action");
  });

  test("budget exhaustion takes precedence over loop recovery", () => {
    const supervisor = new RunSupervisor({ loopDetector: { identicalFingerprintLimit: 1 } });
    const result = supervisor.evaluateCompletedAction({
      history: [],
      observation: {
        actionId: "a1",
        actionFingerprint: "repeat",
        completedAt: "2026-01-01T00:00:01Z",
      },
      before: {},
      after: {},
      budgetState: { limits: { toolCalls: 0 }, usage: { toolCalls: 0 } },
      budgetDelta: { toolCalls: 1 },
    });
    expect(result.directive).toBe("block_budget");
    expect(result.humanReason).toContain("toolCalls");
  });

  test("recovery decisions preserve journey invariants", () => {
    const supervisor = new RunSupervisor();
    const autonomous = supervisor.decideRecovery({
      journey: "autonomous",
      category: "scope_conflict",
      retriesUsed: 0,
      retrySafe: false,
      inContract: false,
      materiallyNewReplanAvailable: false,
      replanBudgetAvailable: false,
    });
    expect(autonomous.recovery.kind).toBe("safe_stop");
    const guided = supervisor.decideRecovery({
      journey: "guided",
      category: "scope_conflict",
      retriesUsed: 0,
      retrySafe: false,
      inContract: false,
      materiallyNewReplanAvailable: false,
      replanBudgetAvailable: false,
    });
    expect(guided.recovery.kind).toBe("waiting_guided_decision");
  });
});

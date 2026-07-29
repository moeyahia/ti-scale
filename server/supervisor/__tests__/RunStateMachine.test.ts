import { describe, expect, test } from "bun:test";
import { RunSupervisor } from "../RunSupervisor";
import { InvalidRunTransitionError, allowedRunTransitions, transitionRun } from "../RunStateMachine";
import type { Journey, SupervisedRun } from "../types";
import { isJourney, isRunState, isTerminalRunState } from "../types";

function run(journey: Journey, state: SupervisedRun["state"] = "queued"): SupervisedRun {
  return {
    id: "run-1",
    missionId: "mission-1",
    journey,
    state,
    launched: state !== "queued" && state !== "planning" && state !== "awaiting_contract_confirmation",
    contractVersion: journey === "autonomous" ? 1 : undefined,
    contractConfirmedAt: state === "running" && journey === "autonomous" ? "2026-01-01T00:00:00Z" : undefined,
    stateVersion: 0,
    stateReason: "fixture",
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  };
}

describe("journey-aware run state machine", () => {
  test("runtime guards reject unknown journeys and lifecycle states", () => {
    expect(isJourney("guided")).toBe(true);
    expect(isJourney("provider-specific")).toBe(false);
    expect(isRunState("recovering")).toBe(true);
    expect(isRunState("waiting_input")).toBe(false);
    expect(isTerminalRunState("cancelled")).toBe(true);
    expect(isTerminalRunState("running")).toBe(false);
  });
  test("Autonomous follows preflight then launches only with a confirmed contract", () => {
    const planning = transitionRun(run("autonomous"), "planning", {
      reason: "Build the plan",
      now: "2026-01-01T00:00:01Z",
    }).run;
    const awaiting = transitionRun(planning, "awaiting_contract_confirmation", {
      reason: "Review contract",
      now: "2026-01-01T00:00:02Z",
    }).run;
    expect(() =>
      transitionRun(awaiting, "running", {
        reason: "Launch",
        now: "2026-01-01T00:00:03Z",
      }),
    ).toThrow(/confirmed mission contract/);
    const launched = transitionRun(awaiting, "running", {
      reason: "Contract signed",
      now: "2026-01-01T00:00:03Z",
      contractConfirmed: true,
    }).run;
    expect(launched.launched).toBe(true);
    expect(launched.contractConfirmedAt).toBe("2026-01-01T00:00:03Z");
  });

  test("Autonomous can never enter a Guided user-wait state", () => {
    expect(allowedRunTransitions("running", "autonomous")).not.toContain("waiting_guided_decision");
    expect(() =>
      transitionRun(run("autonomous", "running"), "waiting_guided_decision", {
        reason: "Ask operator",
        now: "2026-01-01T00:01:00Z",
        guidedDecisionId: "decision-1",
      }),
    ).toThrow(InvalidRunTransitionError);
  });

  test("Guided cannot use the Autonomous contract-confirmation state", () => {
    expect(allowedRunTransitions("planning", "guided")).not.toContain("awaiting_contract_confirmation");
    expect(() =>
      transitionRun(run("guided", "planning"), "awaiting_contract_confirmation", {
        reason: "Wrong journey",
        now: "2026-01-01T00:01:00Z",
      }),
    ).toThrow(/Illegal guided/);
  });

  test("Guided waiting and resume are bound to one exact decision id", () => {
    const running = run("guided", "running");
    expect(() =>
      transitionRun(running, "waiting_guided_decision", {
        reason: "Choose next step",
        now: "2026-01-01T00:01:00Z",
      }),
    ).toThrow(/exact pending decision id/);
    const waiting = transitionRun(running, "waiting_guided_decision", {
      reason: "Choose next step",
      now: "2026-01-01T00:01:00Z",
      guidedDecisionId: "decision-1",
    }).run;
    expect(waiting.pendingGuidedDecisionId).toBe("decision-1");
    expect(() =>
      transitionRun(waiting, "running", {
        reason: "Different decision",
        now: "2026-01-01T00:02:00Z",
        guidedDecisionId: "decision-2",
      }),
    ).toThrow(/does not match/);
    expect(
      transitionRun(waiting, "running", {
        reason: "Exact decision resolved",
        now: "2026-01-01T00:02:00Z",
        guidedDecisionId: "decision-1",
      }).run.pendingGuidedDecisionId,
    ).toBeUndefined();
  });

  test("terminal states reject all transitions and record an ended time", () => {
    const completed = transitionRun(run("guided", "running"), "completed", {
      reason: "Criteria verified",
      now: "2026-01-01T00:03:00Z",
    }).run;
    expect(completed.endedAt).toBe("2026-01-01T00:03:00Z");
    expect(() =>
      transitionRun(completed, "running", { reason: "Resume", now: "2026-01-01T00:04:00Z" }),
    ).toThrow(/Terminal/);
  });

  test("every transition needs a reason and emits durable checkpoint intent", () => {
    expect(() =>
      transitionRun(run("guided"), "planning", { reason: "  ", now: "2026-01-01T00:00:01Z" }),
    ).toThrow(/human-readable reason/);
    const result = transitionRun(run("guided"), "planning", {
      reason: "Explain mission",
      now: "2026-01-01T00:00:01Z",
    });
    expect(result.checkpointRequired).toBe(true);
    expect(result.events.map((event) => event.type)).toEqual([
      "run.state_changed",
      "run.checkpoint_required",
    ]);
    expect(result.events.every((event) => event.journey === "guided")).toBe(true);
  });

  test("RunSupervisor creates explicit queued runs", () => {
    const supervisor = new RunSupervisor();
    const created = supervisor.createRun({
      id: "run-new",
      missionId: "mission-new",
      journey: "autonomous",
      now: "2026-01-01T00:00:00Z",
      contractVersion: 1,
    });
    expect(created).toMatchObject({ state: "queued", launched: false, journey: "autonomous", stateVersion: 0 });
    expect(
      supervisor.transition(created, "planning", {
        reason: "Supervisor starts planning",
        now: "2026-01-01T00:00:01Z",
      }).run.state,
    ).toBe("planning");
  });
});

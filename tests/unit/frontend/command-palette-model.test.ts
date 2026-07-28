import { describe, expect, test } from "bun:test";
import type { MissionSummary } from "../../../src/domain/types/commandOs";
import type { RuntimeRun } from "../../../src/domain/types/runtimeV2";
import {
  commandMutationErrorMessage,
  contextualRunCommands,
  missionCommand,
  rankPaletteCommands,
  runCommand,
} from "../../../src/app/command-palette/commandPaletteModel";

const timestamp = "2026-07-22T08:00:00.000Z";

function mission(journey: "autonomous" | "guided"): MissionSummary {
  return {
    id: `mission:${journey}`,
    title: `${journey === "autonomous" ? "Autonomous" : "Guided"} palette fixture`,
    journey,
    status: journey === "autonomous" ? "planning" : "waiting_guided_decision",
    missionStatus: "active",
    authorizationStatus: "verified",
    engagementId: null,
    scope: { allowedTargets: ["lab:palette"], allowedTargetCount: 1, prohibitedTargetCount: 0 },
    createdAt: timestamp,
    updatedAt: timestamp,
    runId: `run:${journey}`,
    activeRunId: `run:${journey}`,
    runStartedAt: timestamp,
    runEndedAt: null,
    currentPhase: journey === "autonomous" ? "mission-phase-token" : "guided-phase",
    progress: 0,
    currentOwner: null,
    team: [],
    provider: null,
    risk: "low",
    evidenceCount: 0,
    highestFindingSeverity: null,
    decisionState: journey === "guided" ? "pending" : null,
    recoveryState: null,
    lastMeaningfulEvent: null,
    budget: { limits: {}, usage: {} },
    nextAction: "Inspect one bounded fixture",
  };
}

function run(journey: "autonomous" | "guided"): RuntimeRun {
  return {
    id: `run:${journey}`,
    missionId: `mission:${journey}`,
    missionName: `${journey === "autonomous" ? "Autonomous" : "Guided"} palette fixture`,
    objective: "Prove one exact stable palette destination.",
    journey,
    status: journey === "autonomous" ? "planning" : "waiting_guided_decision",
    statusReason: "Fixture-only read path",
    progress: 0,
    nextAction: "Inspect one bounded fixture",
    currentPlanId: "plan:palette",
    currentStepId: "step:palette",
    currentOwnerId: journey === "autonomous" ? "run-owner-token" : "guided-owner",
    lastHeartbeatAt: null,
    leaseExpiresAt: null,
    startedAt: timestamp,
    endedAt: null,
    createdAt: timestamp,
    updatedAt: timestamp,
    version: 1,
  };
}

describe("command palette journey record routing", () => {
  test("maps Autonomous mission and run records to exact stable V2 routes", () => {
    const autonomousMission = missionCommand(mission("autonomous"));
    const autonomousRun = runCommand(run("autonomous"));

    expect(autonomousMission).toMatchObject({
      kind: "mission",
      description: "Autonomous mission · planning",
      path: "/missions/mission%3Aautonomous",
    });
    expect(autonomousRun).toMatchObject({
      kind: "run",
      description: "Autonomous run · planning · run:autonomous",
      path: "/live/run%3Aautonomous",
    });
    expect(rankPaletteCommands([autonomousMission], "mission-phase-token"))
      .toEqual([autonomousMission]);
    expect(rankPaletteCommands([autonomousRun], "run-owner-token"))
      .toEqual([autonomousRun]);
  });

  test("keeps Guided records on the collaborative mission route", () => {
    expect(missionCommand(mission("guided")).path).toBe("/guided/mission%3Aguided");
    expect(runCommand(run("guided")).path).toBe("/guided/mission%3Aguided");
  });

  test("offers resume only for a nonterminal blocked run while the editor independently verifies its checkpoint", () => {
    const blocked = { ...run("guided"), status: "blocked" as const };
    expect(contextualRunCommands(blocked).map((command) => command.action))
      .toEqual(["resume", "cancel"]);
    expect(contextualRunCommands({ ...blocked, status: "cancelled" }).map((command) => command.action))
      .toEqual([]);
  });

  test("renders a rejected mutation with its human explanation, remediation, and trace", () => {
    const rejected = Object.assign(new Error("Internal conflict detail"), {
      humanMessage: "The reviewed command no longer matches the current run.",
      remediation: "Refresh the run and review the exact boundary before trying again.",
      traceId: "trace-palette-rejection",
    });
    expect(commandMutationErrorMessage(rejected)).toBe(
      "The reviewed command no longer matches the current run. " +
      "Next: Refresh the run and review the exact boundary before trying again. " +
      "Trace trace-palette-rejection",
    );
    expect(commandMutationErrorMessage(new Error("Network unavailable"))).toBe("Network unavailable");
    expect(commandMutationErrorMessage({ reason: "not-an-error" })).toBe("The command could not be completed.");
  });
});

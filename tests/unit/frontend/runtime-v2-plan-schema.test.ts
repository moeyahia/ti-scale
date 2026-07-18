import { describe, expect, test } from "bun:test";
import { parsePlans } from "../../../src/domain/schemas/runtimeV2";

function planPayload(dependencyStepIds: unknown): unknown {
  return {
    schemaVersion: "2.4",
    items: [{
      id: "plan-one",
      runId: "run-one",
      version: 1,
      status: "active",
      strategySummary: "Collect bounded observations",
      rationaleSummary: "Respect the dependency graph",
      createdAt: "2026-07-16T16:00:00.000Z",
      activatedAt: "2026-07-16T16:00:00.000Z",
      steps: [{
        id: "step-dependent",
        ordinal: 1,
        phase: "reconnaissance",
        title: "Inspect the service",
        objective: "Inspect the authorized service",
        status: "ready",
        assignedAgentId: "ReconScout",
        riskClass: "low",
        successCriteria: ["One attributable observation"],
        dependencyStepIds,
        action: {
          actionType: "service_enumeration",
          actionClass: "port_service_enumeration",
          target: "fixture.local",
          arguments: { ports: [443] },
          intentSummary: "Inspect the authorized HTTPS service",
          kind: "tool",
          idempotent: true,
          destructive: false,
        },
        explanation: "Collect one bounded observation.",
        rationale: "Reduce uncertainty.",
        reversibility: "Read-only.",
      }],
    }],
  };
}

describe("V2 plan dependency parser", () => {
  test("retains required stable prerequisite step IDs", () => {
    const result = parsePlans(planPayload(["step-prerequisite"]));
    expect(result.items[0]?.steps[0]?.dependencyStepIds).toEqual(["step-prerequisite"]);
  });

  test("rejects missing, non-array, and non-string dependency projections", () => {
    expect(() => parsePlans(planPayload(undefined))).toThrow("dependencyStepIds must be an array");
    expect(() => parsePlans(planPayload("step-prerequisite"))).toThrow("dependencyStepIds must be an array");
    expect(() => parsePlans(planPayload(["step-prerequisite", 7]))).toThrow(
      "dependencyStepIds[1] must be a string",
    );
  });
});

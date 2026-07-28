import { describe, expect, test } from "bun:test";
import {
  journeyModeLabel,
  projectJourneyReadiness,
} from "../../../src/features/overview/journeyReadiness";
import type { ReadinessCheck } from "../../../src/domain/types/commandOs";

function check(
  id: string,
  status: ReadinessCheck["status"],
  journeys: ReadinessCheck["journeys"],
): ReadinessCheck {
  return { id, status, journeys, label: id, impact: `${id} ${status}` };
}

describe("Overview per-journey readiness", () => {
  test("keeps Guided manual work available while Autonomous is unavailable", () => {
    const view = projectJourneyReadiness([
      check("execution_boundary_autonomous", "fail", ["autonomous"]),
      check("provider_execution_autonomous", "fail", ["autonomous"]),
      check("execution_boundary_guided", "pass", ["guided"]),
      check("provider_execution_guided", "warn", ["guided"]),
      check("mcp_execution_guided", "warn", ["guided"]),
    ]);

    expect(view.autonomous).toEqual({ mode: "unavailable", blockers: 2, warnings: 0 });
    expect(view.guided).toEqual({ mode: "manual-only", blockers: 0, warnings: 2 });
    expect(journeyModeLabel(view.guided.mode)).toBe("Manual-only ready");
  });

  test("shows agent-run only after an explicit exact-step execution check passes", () => {
    const local = projectJourneyReadiness([
      check("execution_boundary_guided", "pass", ["guided"]),
      check("guided_local_tool_execution", "pass", ["guided"]),
      check("provider_execution_guided", "warn", ["guided"]),
    ]);
    const mcp = projectJourneyReadiness([
      check("execution_boundary_guided", "pass", ["guided"]),
      check("mcp_execution_guided", "pass", ["guided"]),
    ]);

    expect(local.guided.mode).toBe("agent-run");
    expect(mcp.guided.mode).toBe("agent-run");
  });

  test("does not call Guided usable when its exact-step boundary failed", () => {
    const view = projectJourneyReadiness([
      check("execution_boundary_guided", "fail", ["guided"]),
      check("mcp_execution_guided", "warn", ["guided"]),
    ]);

    expect(view.guided).toEqual({ mode: "unavailable", blockers: 1, warnings: 1 });
  });

  test("keeps shared warnings scoped without turning them into launch blockers", () => {
    const view = projectJourneyReadiness([
      check("authorization_scope", "warn", ["autonomous", "guided"]),
      check("execution_boundary_autonomous", "pass", ["autonomous"]),
      check("execution_boundary_guided", "pass", ["guided"]),
      check("mcp_execution_guided", "pass", ["guided"]),
    ]);

    expect(view.autonomous).toEqual({ mode: "ready", blockers: 0, warnings: 1 });
    expect(view.guided).toEqual({ mode: "agent-run", blockers: 0, warnings: 1 });
  });
});

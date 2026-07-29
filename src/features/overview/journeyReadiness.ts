import type { Journey, ReadinessCheck } from "../../domain/types/commandOs";

export type AutonomousJourneyMode = "ready" | "unavailable";
export type GuidedJourneyMode = "agent-run" | "manual-only" | "unavailable";

export interface JourneyReadinessView {
  readonly autonomous: {
    readonly mode: AutonomousJourneyMode;
    readonly blockers: number;
    readonly warnings: number;
  };
  readonly guided: {
    readonly mode: GuidedJourneyMode;
    readonly blockers: number;
    readonly warnings: number;
  };
}

function journeyChecks(checks: readonly ReadinessCheck[], journey: Journey): readonly ReadinessCheck[] {
  return checks.filter((check) => check.journeys.includes(journey));
}

function count(checks: readonly ReadinessCheck[], status: ReadinessCheck["status"]): number {
  return checks.filter((check) => check.status === status).length;
}

/**
 * The Overview is an unscoped system view, so its aggregate readiness score
 * must not be presented as the state of either mission journey. A Guided
 * manual boundary remains usable while provider/MCP/tool execution is absent.
 * Conversely, agent-run is shown only when an explicit exact-step execution
 * check passes; a lack of failures alone is not execution authority.
 */
export function projectJourneyReadiness(
  checks: readonly ReadinessCheck[],
): JourneyReadinessView {
  const autonomousChecks = journeyChecks(checks, "autonomous");
  const guidedChecks = journeyChecks(checks, "guided");
  const autonomousBlockers = count(autonomousChecks, "fail");
  const guidedBlockers = count(guidedChecks, "fail");
  const guidedManualBoundary = guidedChecks.some((check) =>
    check.id === "execution_boundary_guided" && check.status === "pass");
  const guidedAgentRunBoundary = guidedChecks.some((check) =>
    (check.id === "guided_local_tool_execution"
      || check.id === "mcp_execution_guided")
    && check.status === "pass");

  return {
    autonomous: {
      mode: autonomousChecks.length > 0 && autonomousBlockers === 0
        ? "ready"
        : "unavailable",
      blockers: autonomousBlockers,
      warnings: count(autonomousChecks, "warn"),
    },
    guided: {
      mode: guidedChecks.length === 0 || guidedBlockers > 0 || !guidedManualBoundary
        ? "unavailable"
        : guidedAgentRunBoundary
          ? "agent-run"
          : "manual-only",
      blockers: guidedBlockers,
      warnings: count(guidedChecks, "warn"),
    },
  };
}

export function journeyModeLabel(mode: AutonomousJourneyMode | GuidedJourneyMode): string {
  if (mode === "agent-run") return "Agent-run ready";
  if (mode === "manual-only") return "Manual-only ready";
  if (mode === "ready") return "Ready";
  return "Unavailable";
}

export function journeyModePill(mode: AutonomousJourneyMode | GuidedJourneyMode): string {
  if (mode === "ready" || mode === "agent-run") return "ready";
  if (mode === "manual-only") return "degraded";
  return "unavailable";
}

import type { Journey, RunState } from "../supervisor";

export interface LegacyStateMapping {
  readonly state: RunState;
  readonly requiresReview: boolean;
  readonly reason: string;
}

/**
 * Pure compatibility mapping. It deliberately converts every Autonomous
 * legacy user-wait state into a safe blocked state instead of preserving a
 * hidden approval dependency after launch.
 */
export function mapLegacyRunState(
  legacyState: string,
  journey: Journey,
): LegacyStateMapping {
  switch (legacyState.trim().toLowerCase()) {
    case "created":
    case "queued":
      return { state: "queued", requiresReview: false, reason: "Legacy run was queued" };
    case "planning":
      return { state: "planning", requiresReview: false, reason: "Legacy run was planning" };
    case "awaiting_plan_approval":
      return journey === "autonomous"
        ? {
            state: "awaiting_contract_confirmation",
            requiresReview: true,
            reason: "Legacy plan approval must be converted into a pre-launch contract confirmation",
          }
        : {
            state: "waiting_guided_decision",
            requiresReview: true,
            reason: "Legacy Guided plan approval requires one explicit represented decision",
          };
    case "executing":
    case "running":
      return { state: "running", requiresReview: false, reason: "Legacy execution was active" };
    case "awaiting_user_input":
    case "waiting_input":
    case "awaiting_action_approval":
      return journey === "autonomous"
        ? {
            state: "blocked",
            requiresReview: true,
            reason: "Autonomous legacy user-wait state was safe-stopped for contract review",
          }
        : {
            state: "waiting_guided_decision",
            requiresReview: true,
            reason: "Legacy user-wait state requires an exact Guided decision",
          };
    case "blocked":
      return { state: "blocked", requiresReview: true, reason: "Legacy run was blocked" };
    case "recovering":
      return { state: "recovering", requiresReview: true, reason: "Legacy recovery requires reconciliation" };
    case "completed":
      return { state: "completed", requiresReview: false, reason: "Legacy run completed" };
    case "failed":
      return { state: "failed", requiresReview: false, reason: "Legacy run failed" };
    case "cancelled":
    case "canceled":
    case "stopped":
      return { state: "cancelled", requiresReview: false, reason: "Legacy run was cancelled" };
    default:
      return {
        state: "blocked",
        requiresReview: true,
        reason: `Unknown legacy state '${legacyState}' was mapped fail-closed`,
      };
  }
}

import type { RuntimeRun } from "../../domain/types/runtimeV2";

type RunStatusIdentity = Pick<RuntimeRun, "journey" | "status" | "statusReason">;

/**
 * Keep journey language consistent anywhere a durable run is summarized.
 * Autonomous states describe the execution contract rather than exposing a
 * raw state-machine token; the persisted reason remains the authoritative
 * explanation beside this concise label.
 */
export function runStatusLabel(run: RunStatusIdentity): string {
  if (run.journey !== "autonomous") return run.status.replaceAll("_", " ");
  switch (run.status) {
    case "queued": return "Queued for autonomous execution";
    case "planning": return "Planning autonomously";
    case "awaiting_contract_confirmation": return "Awaiting contract confirmation";
    case "running": return "Executing autonomously";
    case "waiting_guided_decision": return "Autonomous invariant violation: waiting for operator";
    case "blocked":
      return /(?:outside (?:the )?(?:signed )?contract|out[- ]of[- ]contract|prohibited (?:action )?class|outside (?:the )?authorized scope)/iu.test(run.statusReason ?? "")
        ? "Safe-stopped: outside contract"
        : "Safe-stopped";
    case "recovering": return "Recovering autonomously";
    case "completed": return "Completed autonomously";
    case "failed": return "Failed safely";
    case "cancelled": return "Cancelled safely";
  }
}

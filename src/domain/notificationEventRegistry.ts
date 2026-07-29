export type NotificationEventJourney = "autonomous" | "guided";
export type NotificationEventSeverity = "info" | "warning" | "error" | "critical";

export interface NotificationEventDefinition {
  readonly allowedJourneys: readonly NotificationEventJourney[];
  readonly notificationType: string;
  readonly severity: NotificationEventSeverity;
  readonly title: string;
  readonly body: string;
}

const BOTH_JOURNEYS = Object.freeze(["autonomous", "guided"] as const);
const AUTONOMOUS_ONLY = Object.freeze(["autonomous"] as const);
const GUIDED_ONLY = Object.freeze(["guided"] as const);

/**
 * Canonical registry for semantic events that create an in-app notification.
 * Both the server projector and browser event stream consume this exact map so
 * an ordinary operational event cannot trigger a pointless notification read.
 */
export const NOTIFICATION_EVENT_REGISTRY: Readonly<Record<string, NotificationEventDefinition>> = Object.freeze({
  "guided.decision_requested": {
    allowedJourneys: GUIDED_ONLY,
    notificationType: "guided_decision_ready",
    severity: "warning",
    title: "Guided step ready",
    body: "A represented Guided step is ready for your deliberate decision.",
  },
  "guided.commander.recovery_ready": {
    allowedJourneys: GUIDED_ONLY,
    notificationType: "guided_recovery_ready",
    severity: "warning",
    title: "Guided recovery ready",
    body: "A bounded recovery step is ready for your deliberate decision.",
  },
  "run.guided_blocked": {
    allowedJourneys: GUIDED_ONLY,
    notificationType: "guided_run_blocked",
    severity: "error",
    title: "Guided run blocked",
    body: "The Guided run stopped at a durable boundary and needs your review.",
  },
  "run.autonomous_safe_stopped": {
    allowedJourneys: AUTONOMOUS_ONLY,
    notificationType: "autonomous_safe_stop",
    severity: "critical",
    title: "Autonomous run safe-stopped",
    body: "The run stopped safely because no permitted in-contract path remained.",
  },
  "run.safe_stopped": {
    allowedJourneys: AUTONOMOUS_ONLY,
    notificationType: "autonomous_safe_stop",
    severity: "critical",
    title: "Autonomous run safe-stopped",
    body: "The run stopped safely at its enforced operating boundary.",
  },
  "run.failed_safely": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "run_failed_safely",
    severity: "error",
    title: "Run failed safely",
    body: "The run ended without weakening its authorization or safety policy.",
  },
  "run.recovery_started": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "recovery_required",
    severity: "warning",
    title: "Run recovery started",
    body: "The supervisor detected a recoverable interruption and started bounded recovery.",
  },
  "run.recovery_blocked": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "recovery_blocked",
    severity: "critical",
    title: "Run recovery blocked",
    body: "Bounded recovery could not continue safely and requires operator review.",
  },
  "run.continuation_blocked": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "continuation_blocked",
    severity: "critical",
    title: "Run continuation blocked",
    body: "Durable continuation stopped because replay could not be proven safe.",
  },
  "run.cancellation_failed": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "cancellation_failed",
    severity: "critical",
    title: "Cancellation requires review",
    body: "Child-work cleanup was not confirmed and the run stopped for review.",
  },
  "action.pre_dispatch_denied": {
    allowedJourneys: AUTONOMOUS_ONLY,
    notificationType: "autonomous_dispatch_denied",
    severity: "critical",
    title: "Autonomous dispatch denied",
    body: "An action was denied before dispatch by the enforced mission boundary.",
  },
  "policy.denied": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "policy_denied",
    severity: "critical",
    title: "Policy denied an action",
    body: "The runtime prevented an action that did not satisfy current policy.",
  },
  "budget.exhausted": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "budget_exhausted",
    severity: "error",
    title: "Run budget exhausted",
    body: "The run reached an enforced operating budget and stopped further work.",
  },
  "run.budget_exhausted": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "budget_exhausted",
    severity: "error",
    title: "Run budget exhausted",
    body: "The run reached an enforced operating budget and stopped further work.",
  },
  "run.success_validated": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "run_completed",
    severity: "info",
    title: "Mission outcome validated",
    body: "The run completed and its success criteria were evaluated.",
  },
  "run.completed": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "run_completed",
    severity: "info",
    title: "Run completed",
    body: "The run reached a terminal completion state and is ready for review.",
  },
  "run.success_criteria_failed": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "run_failed",
    severity: "error",
    title: "Mission criteria not met",
    body: "The terminal evaluation found that the mission success criteria were not met.",
  },
  "run.cancelled": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "run_cancelled",
    severity: "info",
    title: "Run cancelled",
    body: "The run and its child work reached a confirmed cancelled state.",
  },
  "memory.candidate_created": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "memory_candidate_ready",
    severity: "info",
    title: "Memory candidate ready",
    body: "A reviewable memory candidate is waiting in the Memory Inbox.",
  },
  "approval.requested": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "approval_requested",
    severity: "warning",
    title: "Administrative approval requested",
    body: "A scoped administrative approval record is ready for review.",
  },
  "vault.conflict_detected": {
    allowedJourneys: BOTH_JOURNEYS,
    notificationType: "vault_conflict",
    severity: "warning",
    title: "Obsidian vault conflict",
    body: "A versioned vault conflict is waiting for side-by-side resolution.",
  },
});

export function notificationDefinitionFor(
  eventType: string,
  journey: NotificationEventJourney,
): NotificationEventDefinition | undefined {
  const definition = NOTIFICATION_EVENT_REGISTRY[eventType];
  return definition?.allowedJourneys.includes(journey) ? definition : undefined;
}

export function isActionableNotificationEvent(
  eventType: string,
  journey: NotificationEventJourney,
): boolean {
  return notificationDefinitionFor(eventType, journey) !== undefined;
}

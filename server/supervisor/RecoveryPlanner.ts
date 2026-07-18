import type { FailureCategory } from "./ErrorTaxonomy";
import type { RetryDecision } from "./RetryPolicy";
import type { Journey } from "./types";

export type RecoveryDecision =
  | { kind: "retry"; delayMs: number; reason: string }
  | { kind: "bounded_alternative"; alternativeId: string; reason: string }
  | { kind: "reassign"; agentId: string; reason: string }
  | { kind: "replan"; reason: string }
  | { kind: "waiting_guided_decision"; reason: string; recommendation: string }
  | { kind: "safe_stop"; reason: string; exceptionCode: string }
  | { kind: "fail"; reason: string };

export interface RecoveryInput {
  journey: Journey;
  category: FailureCategory;
  retryDecision: RetryDecision;
  retrySafe: boolean;
  inContract: boolean;
  boundedAlternativeId?: string;
  reassignmentAgentId?: string;
  materiallyNewReplanAvailable: boolean;
  replanBudgetAvailable: boolean;
  guidedRecommendation?: string;
}

export function planRecovery(input: Readonly<RecoveryInput>): RecoveryDecision {
  if (input.journey === "guided") {
    return {
      kind: "waiting_guided_decision",
      reason: `Guided recovery needs an explicit operator decision after ${input.category}.`,
      recommendation: input.guidedRecommendation ?? "Review the failure and choose a bounded recovery step.",
    };
  }
  if (input.inContract && input.retrySafe && input.retryDecision.retry) {
    return {
      kind: "retry",
      delayMs: input.retryDecision.delayMs ?? 0,
      reason: `Retrying transient ${input.category} failure within policy.`,
    };
  }
  if (input.inContract && input.boundedAlternativeId) {
    return {
      kind: "bounded_alternative",
      alternativeId: input.boundedAlternativeId,
      reason: "Using a bounded in-contract alternative after the failed action.",
    };
  }
  if (input.inContract && input.reassignmentAgentId) {
    return {
      kind: "reassign",
      agentId: input.reassignmentAgentId,
      reason: "Reassigning to a capable specialist within the mission contract.",
    };
  }
  if (input.inContract && input.materiallyNewReplanAvailable && input.replanBudgetAvailable) {
    return { kind: "replan", reason: "New facts support a materially different in-contract plan." };
  }
  if (!input.inContract) {
    return {
      kind: "safe_stop",
      reason: "No safe in-contract recovery path remains.",
      exceptionCode: "outside_contract",
    };
  }
  return { kind: "fail", reason: `No safe recovery remains for ${input.category}.` };
}

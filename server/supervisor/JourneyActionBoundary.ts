import { fingerprintAction } from "./ActionFingerprint";
import type {
  ActionIntent,
  AutonomousContractBoundary,
  GuidedDecision,
  Journey,
} from "./types";

export type ActionBoundaryFailure =
  | "action_run_mismatch"
  | "run_not_running"
  | "autonomous_contract_not_signed"
  | "autonomous_action_not_allowed"
  | "autonomous_target_not_allowed"
  | "guided_decision_required"
  | "guided_decision_not_authorized"
  | "guided_decision_expired"
  | "guided_decision_consumed"
  | "guided_decision_scope_mismatch"
  | "guided_action_changed";

export type ActionBoundaryResult =
  | { allowed: true; actionFingerprint: string; consumedDecision?: GuidedDecision }
  | { allowed: false; reason: ActionBoundaryFailure; humanMessage: string };

function targetAllowed(target: string, allowedTargets: readonly string[]): boolean {
  const normalized = target.trim();
  return allowedTargets.some((candidate) => candidate.trim() === normalized);
}

export function enforceJourneyActionBoundary(input: {
  journey: Journey;
  action: Readonly<ActionIntent>;
  now: string;
  autonomousContract?: Readonly<AutonomousContractBoundary>;
  guidedDecision?: Readonly<GuidedDecision>;
}): ActionBoundaryResult {
  const actionFingerprint = fingerprintAction(input.action).hash;
  if (input.journey === "autonomous") {
    const contract = input.autonomousContract;
    if (!contract || contract.status !== "signed" || contract.runId !== input.action.runId) {
      return {
        allowed: false,
        reason: "autonomous_contract_not_signed",
        humanMessage: "The Autonomous action has no matching signed mission contract.",
      };
    }
    const actionType = input.action.actionType.trim().toLowerCase();
    const prohibited = (contract.prohibitedActionTypes ?? []).map((value) => value.trim().toLowerCase());
    const allowed = contract.allowedActionTypes.map((value) => value.trim().toLowerCase());
    if (prohibited.includes(actionType) || !allowed.includes(actionType)) {
      return {
        allowed: false,
        reason: "autonomous_action_not_allowed",
        humanMessage: "The action type is outside the signed Autonomous contract.",
      };
    }
    if (!targetAllowed(input.action.target, contract.allowedTargets)) {
      return {
        allowed: false,
        reason: "autonomous_target_not_allowed",
        humanMessage: "The action target is outside the signed Autonomous contract.",
      };
    }
    return { allowed: true, actionFingerprint };
  }

  const decision = input.guidedDecision;
  if (!decision) {
    return {
      allowed: false,
      reason: "guided_decision_required",
      humanMessage: "Guided execution requires an explicit decision for this exact step.",
    };
  }
  if (decision.status === "consumed") {
    return {
      allowed: false,
      reason: "guided_decision_consumed",
      humanMessage: "This Guided decision has already been used.",
    };
  }
  if (decision.status !== "authorized") {
    return {
      allowed: false,
      reason: "guided_decision_not_authorized",
      humanMessage: "The Guided decision is not authorized.",
    };
  }
  const nowMs = Date.parse(input.now);
  const expiresAtMs = Date.parse(decision.expiresAt);
  if (!Number.isFinite(nowMs) || !Number.isFinite(expiresAtMs) || nowMs >= expiresAtMs) {
    return {
      allowed: false,
      reason: "guided_decision_expired",
      humanMessage: "The Guided decision expired before execution.",
    };
  }
  if (
    decision.journey !== "guided" ||
    decision.missionId !== input.action.missionId ||
    decision.runId !== input.action.runId ||
    decision.stepId !== input.action.stepId
  ) {
    return {
      allowed: false,
      reason: "guided_decision_scope_mismatch",
      humanMessage: "The Guided decision belongs to a different run or step.",
    };
  }
  if (decision.actionFingerprint !== actionFingerprint) {
    return {
      allowed: false,
      reason: "guided_action_changed",
      humanMessage: "The represented Guided action or parameters changed and require a new decision.",
    };
  }
  return {
    allowed: true,
    actionFingerprint,
    consumedDecision: {
      ...decision,
      status: "consumed",
      consumedAt: input.now,
      version: decision.version + 1,
    },
  };
}

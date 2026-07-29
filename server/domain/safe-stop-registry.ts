export interface SafeStopDefinition {
  readonly id: string;
  readonly label: string;
  readonly explanation: string;
  readonly remediation: string;
  readonly mandatory: boolean;
  readonly userRemovable: boolean;
}

const mandatory = (
  id: string,
  label: string,
  explanation: string,
  remediation: string,
): SafeStopDefinition => ({ id, label, explanation, remediation, mandatory: true, userRemovable: false });

const optional = (
  id: string,
  label: string,
  explanation: string,
  remediation: string,
): SafeStopDefinition => ({ id, label, explanation, remediation, mandatory: false, userRemovable: true });

export const MANDATORY_PLATFORM_SAFE_STOPS = [
  mandatory("target_outside_authorized_scope", "Target is outside authorized scope", "A normalized action target is not inside the signed mission scope.", "Correct the scope in a versioned mission or start a new authorized run."),
  mandatory("authorization_or_policy_unverifiable", "Authorization or policy cannot be verified", "The runtime cannot prove the authority or policy needed for the next action.", "Restore the policy dependency or create a newly reviewed contract."),
  mandatory("prohibited_action_class", "Action crosses a prohibited class", "The next action belongs to a class the signed contract forbids.", "Choose an in-scope alternative or create a separately reviewed future run."),
  mandatory("prohibited_destructive_impact", "Prohibited destructive impact detected", "Observed or projected impact would be destructive where destruction is forbidden.", "Preserve the checkpoint and validate the path without executing it."),
  mandatory("provider_disclosure_violation", "Provider disclosure would violate policy", "Sensitive content would be disclosed to a provider that is not approved for its classification.", "Use a compatible local or sanitized route; never weaken disclosure policy."),
  mandatory("repeated_no_progress_loop", "Repeated no-progress loop reached its bound", "The supervisor detected repeated equivalent actions without meaningful progress.", "Consult failure memory, choose a materially different bounded strategy, or terminate safely."),
  mandatory("cancellation_requested", "Cancellation requested", "The operator or system requested cooperative cancellation.", "Complete cleanup, release leases, and preserve the terminal checkpoint."),
  mandatory("runtime_or_evaluator_integrity_failure", "Runtime or evaluator integrity failed", "A trusted runtime, evidence, benchmark, or evaluator integrity check failed.", "Stop work and repair or re-verify the trusted component before another run."),
] as const satisfies readonly SafeStopDefinition[];

export const OPTIONAL_MISSION_SAFE_STOPS = [
  optional("target_identity_mismatch", "Target identity differs from expected", "Observed identity conflicts with the target the operator intended to assess.", "Verify the target and amend the authorized scope before continuing."),
  optional("service_instability_detected", "Service instability or lockout risk detected", "The target shows instability, throttling, or authentication lockout risk.", "Reduce rate, restore service health, or start a new bounded run."),
  optional("credential_attempt_threshold_reached", "Credential attempt threshold reached", "The configured credential-attempt ceiling has been reached.", "Review the attempt record and explicitly set a new future-run threshold if authorized."),
  optional("target_unreachable", "Target became unreachable", "A required target cannot be reached from the authorized execution context.", "Test routing and availability, then resume from the checkpoint or mark it unreachable."),
  optional("specified_high_value_objective_achieved", "Named objective achieved", "A configured proof boundary or high-value objective has been reached.", "Review preserved proof and decide whether a follow-up mission is needed."),
  optional("budget_reached", "Mission budget reached", "A time, token, cost, tool, retry, storage, or artifact budget is exhausted.", "Review resource use and start a new versioned run with a justified budget."),
  optional("exploitability_ambiguous_after_alternatives", "Exploitability remains ambiguous", "The configured number of materially different validation alternatives did not resolve applicability.", "Report the uncertainty or gather new evidence in a future run."),
  optional("required_dependency_unavailable", "Required dependency is unavailable", "A required provider, MCP server, tool, credential, or local dependency is unavailable.", "Restore or replace the dependency with a compatible in-contract route."),
  optional("evidence_insufficient_to_proceed", "Evidence is insufficient to proceed safely", "The next action lacks the prerequisite evidence required by policy.", "Gather the missing evidence or stop with the uncertainty recorded."),
  optional("named_business_process_encountered", "Named sensitive system or process encountered", "Discovery reached a system or business process configured as a stopping boundary.", "Preserve the discovery and obtain a separately reviewed future scope if needed."),
] as const satisfies readonly SafeStopDefinition[];

export const SAFE_STOP_DEFINITIONS = [
  ...MANDATORY_PLATFORM_SAFE_STOPS,
  ...OPTIONAL_MISSION_SAFE_STOPS,
] as const;

export const OPTIONAL_SAFE_STOP_IDS = OPTIONAL_MISSION_SAFE_STOPS.map(({ id }) => id);

const safeStopIds = new Set(SAFE_STOP_DEFINITIONS.map(({ id }) => id));
if (safeStopIds.size !== SAFE_STOP_DEFINITIONS.length) {
  throw new Error("Safe-stop registry contains duplicate IDs.");
}

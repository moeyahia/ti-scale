import type {
  WindowsIdentityFailureCode,
  WindowsIdentityFailureDefinition,
  WindowsIdentityRawResult,
} from "./types";

const definition = (
  code: WindowsIdentityFailureCode,
  category: WindowsIdentityFailureDefinition["category"],
  humanMessage: string,
  retryable = false,
): WindowsIdentityFailureDefinition => Object.freeze({
  code,
  category,
  retryable,
  humanMessage,
});

const definitions: readonly WindowsIdentityFailureDefinition[] = Object.freeze([
  definition("windows_identity_request_invalid", "invalid_input", "The identity-enumeration request is not schema-valid."),
  definition("windows_identity_target_not_canonical", "invalid_input", "Use one canonical IP address or lowercase hostname; ranges, files, URLs, and target lists are not accepted."),
  definition("windows_identity_target_outside_scope", "scope_conflict", "The exact identity target is not in the mission's current allowed scope."),
  definition("windows_identity_authorization_unverified", "authorization_denied", "The mission authorization is not currently verified."),
  definition("windows_identity_action_class_denied", "policy_denied", "The mission policy does not permit Active Directory and identity operations."),
  definition("windows_identity_autonomous_not_approved", "policy_denied", "This reviewed identity pack is Guided-only until a separate Autonomous enforcement review is completed."),
  definition("windows_identity_guided_decision_required", "policy_denied", "A current operator decision is required for this exact Guided action."),
  definition("windows_identity_guided_action_changed", "policy_denied", "The target, tool, credential reference, or parameters changed after the Guided decision."),
  definition("windows_identity_credential_reference_invalid", "invalid_input", "Use one opaque systemd credential-bundle reference; reusable authentication material is not accepted in the request."),
  definition("windows_identity_credential_binding_missing", "authentication_missing", "The requested credential bundle has no current private execution binding."),
  definition("windows_identity_credential_binding_changed", "policy_denied", "The private credential binding no longer matches the exact run and action."),
  definition("windows_identity_credential_binding_expired", "authentication_missing", "The private credential binding expired before execution."),
  definition("windows_identity_tool_unavailable", "dependency_missing", "The reviewed local identity tool has no current complete readiness receipt."),
  definition("windows_identity_tool_identity_changed", "dependency_missing", "The installed identity tool no longer matches its reviewed executable identity."),
  definition("windows_identity_workspace_not_confined", "policy_denied", "The execution adapter did not prove that tool state and output are confined to the engagement workspace."),
  definition("windows_identity_adapter_not_bounded", "policy_denied", "The execution adapter did not prove direct argv, output, cancellation, and credential-isolation boundaries."),
  definition("windows_identity_concurrency_exhausted", "policy_denied", "Another identity operation already owns the single bounded execution slot for this run."),
  definition("windows_identity_cancelled", "operator_rejection", "The identity operation was cancelled and its process group was cleaned up."),
  definition("windows_identity_timed_out", "timeout", "The identity operation exceeded its fixed wall-clock deadline.", true),
  definition("windows_identity_output_limit", "deterministic_tool_error", "The identity tool exceeded its fixed output budget and was stopped."),
  definition("windows_identity_authentication_rejected", "deterministic_tool_error", "The target rejected the supplied credential reference; an unchanged retry is not justified."),
  definition("windows_identity_target_unreachable", "transient_network", "The exact target could not be reached from the current execution context.", true),
  definition("windows_identity_tool_deterministic_error", "deterministic_tool_error", "The identity tool returned a deterministic error for this exact input."),
]);

export const WINDOWS_IDENTITY_FAILURE_TAXONOMY: Readonly<
  Record<WindowsIdentityFailureCode, WindowsIdentityFailureDefinition>
> = Object.freeze(Object.fromEntries(
  definitions.map((item) => [item.code, item] as const),
)) as Readonly<Record<WindowsIdentityFailureCode, WindowsIdentityFailureDefinition>>;

export function windowsIdentityFailure(code: WindowsIdentityFailureCode): WindowsIdentityFailureDefinition {
  return WINDOWS_IDENTITY_FAILURE_TAXONOMY[code];
}

/** Classifies only terminal tool outcomes; policy/preflight codes are explicit earlier. */
export function classifyWindowsIdentityTerminalResult(
  result: WindowsIdentityRawResult,
): WindowsIdentityFailureDefinition | null {
  if (result.cancelled) return windowsIdentityFailure("windows_identity_cancelled");
  if (result.timedOut) return windowsIdentityFailure("windows_identity_timed_out");
  if (result.outputTruncated) return windowsIdentityFailure("windows_identity_output_limit");
  if (result.exitCode === 0) return null;
  const text = `${result.stdout}\n${result.stderr}`.toLowerCase();
  if (/logon failure|nt_status_logon_failure|invalid credentials|ldap_bind:\s*invalid credentials/u.test(text)) {
    return windowsIdentityFailure("windows_identity_authentication_rejected");
  }
  if (/connection refused|network is unreachable|no route to host|host is down|name or service not known|timed out/u.test(text)) {
    return windowsIdentityFailure("windows_identity_target_unreachable");
  }
  return windowsIdentityFailure("windows_identity_tool_deterministic_error");
}

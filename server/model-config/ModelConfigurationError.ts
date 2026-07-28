export class ModelConfigurationError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
    readonly category:
      | "invalid_input"
      | "not_found"
      | "scope_conflict"
      | "state_conflict"
      | "policy_denied"
      | "dependency_missing",
    readonly remediation: string,
    readonly retryable = false,
  ) {
    super(message);
    this.name = "ModelConfigurationError";
  }
}

export function invalidModelConfiguration(
  code: string,
  message: string,
  remediation = "Correct the model-configuration request and retry.",
): ModelConfigurationError {
  return new ModelConfigurationError(
    code,
    message,
    400,
    "invalid_input",
    remediation,
  );
}

export function modelConfigurationNotFound(
  code: string,
  message: string,
  remediation: string,
): ModelConfigurationError {
  return new ModelConfigurationError(
    code,
    message,
    404,
    "not_found",
    remediation,
  );
}

export function modelConfigurationConflict(
  code: string,
  message: string,
  remediation: string,
): ModelConfigurationError {
  return new ModelConfigurationError(
    code,
    message,
    409,
    "state_conflict",
    remediation,
  );
}

export function modelConfigurationScopeConflict(
  message: string,
): ModelConfigurationError {
  return new ModelConfigurationError(
    "model_configuration_scope_conflict",
    message,
    409,
    "scope_conflict",
    "Use an agent, mission, run, and step that belong to the same canonical scope.",
  );
}

export function modelConfigurationUnavailable(
  message: string,
  remediation = "Refresh live provider readiness and choose a currently available model configuration.",
): ModelConfigurationError {
  return new ModelConfigurationError(
    "model_configuration_unavailable",
    message,
    409,
    "state_conflict",
    remediation,
  );
}

export function modelConfigurationPolicyDenied(
  message: string,
  remediation: string,
): ModelConfigurationError {
  return new ModelConfigurationError(
    "model_configuration_policy_denied",
    message,
    409,
    "policy_denied",
    remediation,
  );
}

export type RunIntelligenceHttpErrorCategory =
  | "authentication_missing"
  | "invalid_input"
  | "not_found"
  | "policy_denied"
  | "scope_conflict"
  | "state_conflict"
  | "evidence_insufficient";

/** Checked error used only at the authenticated run-intelligence HTTP boundary. */
export class RunIntelligenceHttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly category: RunIntelligenceHttpErrorCategory,
    readonly remediation?: string,
  ) {
    super(message);
    this.name = "RunIntelligenceHttpError";
  }
}

export function invalidHttpInput(
  code: string,
  message: string,
  remediation = "Correct the named fields and submit the request again.",
): RunIntelligenceHttpError {
  return new RunIntelligenceHttpError(400, code, message, "invalid_input", remediation);
}

export function authenticationRequired(): RunIntelligenceHttpError {
  return new RunIntelligenceHttpError(
    401,
    "run_intelligence_authentication_required",
    "An authenticated run-intelligence identity is required",
    "authentication_missing",
    "Sign in again before accessing mission intelligence.",
  );
}

export function runIntelligencePolicyDenied(): RunIntelligenceHttpError {
  return new RunIntelligenceHttpError(
    403,
    "run_intelligence_policy_denied",
    "This identity cannot perform the requested run-intelligence action",
    "policy_denied",
    "Use an identity with explicit access to the mission and requested capability.",
  );
}

export function runIntelligenceResourceNotFound(resource: string): RunIntelligenceHttpError {
  return new RunIntelligenceHttpError(
    404,
    `${resource}_not_found`,
    `${resource.replaceAll("_", " ")} was not found in the requested scope`,
    "not_found",
    "Refresh the parent mission or run and use a canonical resource link.",
  );
}

export function idempotencyConflict(): RunIntelligenceHttpError {
  return new RunIntelligenceHttpError(
    409,
    "run_intelligence_idempotency_conflict",
    "Idempotency-Key was already used for a materially different mutation",
    "state_conflict",
    "Use a new Idempotency-Key for the changed request.",
  );
}

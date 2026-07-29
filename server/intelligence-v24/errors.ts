export type OperationalTruthErrorCategory =
  | "invalid_input"
  | "not_found"
  | "scope_conflict"
  | "state_conflict"
  | "evidence_insufficient"
  | "policy_denied";

export class OperationalTruthError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly category: OperationalTruthErrorCategory,
    readonly remediation?: string,
  ) {
    super(message);
    this.name = "OperationalTruthError";
  }
}

export function invalid(code: string, message: string, remediation?: string): OperationalTruthError {
  return new OperationalTruthError(code, message, "invalid_input", remediation);
}

export function missing(resource: string): OperationalTruthError {
  return new OperationalTruthError(
    `${resource}_not_found`,
    `${resource.replaceAll("_", " ")} was not found`,
    "not_found",
  );
}

export function scopeConflict(message: string): OperationalTruthError {
  return new OperationalTruthError("operational_truth_scope_conflict", message, "scope_conflict");
}

export function stateConflict(message: string, remediation?: string): OperationalTruthError {
  return new OperationalTruthError("operational_truth_state_conflict", message, "state_conflict", remediation);
}

export function insufficient(message: string, remediation: string): OperationalTruthError {
  return new OperationalTruthError("verified_evidence_required", message, "evidence_insufficient", remediation);
}

export function policyDenied(message: string, remediation?: string): OperationalTruthError {
  return new OperationalTruthError("operational_truth_policy_denied", message, "policy_denied", remediation);
}

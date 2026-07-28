export type OpenRouterConnectionErrorCategory =
  | "authentication_required"
  | "invalid_input"
  | "state_conflict"
  | "security_boundary"
  | "persistence"
  | "provider_unavailable";

/**
 * A deliberately redacted provider-configuration error.
 *
 * Never attach the submitted credential, request body, filesystem cause, or
 * upstream response to this object: the generic HTTP boundary may report its
 * name and the V2 router serializes the safe fields below.
 */
export class OpenRouterConnectionError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
    readonly category: OpenRouterConnectionErrorCategory,
    readonly remediation: string,
    readonly retryable = false,
  ) {
    super(message);
    this.name = "OpenRouterConnectionError";
  }
}

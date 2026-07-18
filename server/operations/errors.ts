export class OperationsApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly options: {
      readonly humanMessage?: string;
      readonly retryable?: boolean;
      readonly category?: string;
      readonly details?: unknown;
      readonly remediation?: string;
    } = {},
  ) {
    super(message);
    this.name = "OperationsApiError";
  }
}

export function notFound(resource: string): OperationsApiError {
  return new OperationsApiError(404, "operations_resource_not_found", `${resource} was not found`, {
    humanMessage: `The requested ${resource.toLocaleLowerCase("en-US")} does not exist or is outside your authorized scope.`,
    category: "not_found",
  });
}

export function forbidden(message: string, remediation?: string): OperationsApiError {
  return new OperationsApiError(403, "operations_policy_denied", message, {
    humanMessage: message,
    category: "policy_denied",
    remediation,
  });
}

export function conflict(message: string, remediation?: string): OperationsApiError {
  return new OperationsApiError(409, "operations_state_conflict", message, {
    humanMessage: message,
    category: "conflict",
    remediation: remediation ?? "Refresh the resource and retry against its current version.",
  });
}

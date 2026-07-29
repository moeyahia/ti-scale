import type { JsonValue } from "../events";

export class MissionApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly options: {
      readonly humanMessage?: string;
      readonly retryable?: boolean;
      readonly category?: string;
      readonly details?: JsonValue;
      readonly remediation?: string;
    } = {},
  ) {
    super(message);
    this.name = "MissionApiError";
  }
}

export class MissionValidationError extends MissionApiError {
  constructor(readonly issues: readonly string[]) {
    super(400, "invalid_mission_request", "Mission request validation failed", {
      humanMessage: "The mission could not be created because required information is missing or invalid.",
      category: "invalid_input",
      details: { issues: [...issues] },
      remediation: "Correct the listed fields and submit the mission again.",
    });
    this.name = "MissionValidationError";
  }
}

export class IdempotencyConflictError extends MissionApiError {
  constructor() {
    super(
      409,
      "idempotency_key_conflict",
      "The idempotency key was already used with a different request",
      {
        humanMessage: "This submission key already belongs to a different mission request.",
        category: "conflict",
        remediation: "Generate a new idempotency key before submitting a materially different mission.",
      },
    );
    this.name = "IdempotencyConflictError";
  }
}

export class AutonomousReadinessError extends MissionApiError {
  constructor(details: JsonValue) {
    super(
      409,
      "autonomous_readiness_blocked",
      "Autonomous launch failed its readiness gate",
      {
        humanMessage: "Autonomous execution cannot start until every required launch dependency is ready.",
        category: "dependency_missing",
        details,
        remediation: "Resolve each failed Autonomous readiness check, then launch the same contract again.",
      },
    );
    this.name = "AutonomousReadinessError";
  }
}

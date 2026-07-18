import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import type { GuidedCommanderRepository } from "./GuidedCommanderRepository";
import { GuidedCommanderError, validatePathId } from "./validation";

const SCHEMA_VERSION = "2.4" as const;
const ACTOR_ID = /^[^\u0000-\u001F\u007F]{1,256}$/u;
const CURSOR = /^[A-Za-z0-9_-]{1,1024}$/u;

export interface GuidedTranscriptReadScope {
  readonly missionId: string;
  readonly runId: string;
}

export interface GuidedTranscriptReadRouterDependencies {
  readonly repository: Pick<GuidedCommanderRepository, "transcript">;
  readonly resolveActor: (request: Request) => string | undefined;
  readonly authorize: (
    request: Request,
    actorId: string,
    scope: GuidedTranscriptReadScope,
  ) => boolean;
}

class GuidedTranscriptReadError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly category: string,
    readonly remediation?: string,
  ) {
    super(message);
    this.name = "GuidedTranscriptReadError";
  }
}

function invalidInput(code: string, message: string): GuidedTranscriptReadError {
  return new GuidedTranscriptReadError(
    400,
    code,
    message,
    "invalid_input",
    "Correct the request using the published Guided transcript filters and canonical IDs.",
  );
}

function actorId(
  dependencies: GuidedTranscriptReadRouterDependencies,
  request: Request,
): string {
  const resolved = dependencies.resolveActor(request);
  const normalized = typeof resolved === "string" ? resolved.trim().normalize("NFKC") : "";
  if (!ACTOR_ID.test(normalized)) {
    throw new GuidedTranscriptReadError(
      401,
      "guided_transcript_authentication_required",
      "Sign in before reading the Guided transcript.",
      "authentication_missing",
      "Authenticate with the isolated Ti-Scale session and retry.",
    );
  }
  return normalized;
}

function onlyQueryKeys(request: Request): void {
  const allowed = new Set(["runId", "stepId", "cursor", "limit"]);
  const unsupported = Object.keys(request.query).filter((key) => !allowed.has(key));
  if (unsupported.length > 0) {
    throw invalidInput(
      "unsupported_guided_transcript_filter",
      `Unsupported Guided transcript filter: ${unsupported[0]}.`,
    );
  }
}

function requiredRunId(value: unknown): string {
  return validatePathId(value, "runId");
}

function optionalStepId(value: unknown): string | undefined {
  return value === undefined ? undefined : validatePathId(value, "stepId");
}

function optionalCursor(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !CURSOR.test(value)) {
    throw invalidInput("invalid_transcript_cursor", "Transcript cursor is invalid.");
  }
  return value;
}

function boundedLimit(value: unknown): number {
  if (value === undefined) return 100;
  if (
    typeof value !== "string"
    || !/^(?:[1-9]|[1-9][0-9]|1[0-9]{2}|200)$/u.test(value)
  ) {
    throw invalidInput("invalid_transcript_limit", "Transcript limit must be 1 through 200.");
  }
  return Number(value);
}

function sendError(response: Response, traceId: string, error: unknown): void {
  if (error instanceof GuidedTranscriptReadError) {
    sendV2Error(response, traceId, {
      status: error.status,
      code: error.code,
      message: error.message,
      humanMessage: error.message,
      retryable: false,
      category: error.category,
      ...(error.remediation ? { remediation: error.remediation } : {}),
    });
    return;
  }
  if (error instanceof GuidedCommanderError) {
    sendV2Error(response, traceId, {
      status: error.status,
      code: error.code,
      message: error.message,
      humanMessage: error.options.humanMessage ?? error.message,
      retryable: error.options.retryable ?? false,
      category: error.options.category ?? (error.status === 404 ? "not_found" : "guided_commander"),
      ...(error.options.details === undefined ? {} : { details: error.options.details }),
      ...(error.options.remediation ? { remediation: error.options.remediation } : {}),
    });
    return;
  }
  sendV2Error(response, traceId, {
    status: 500,
    code: "guided_transcript_read_internal_error",
    message: "Guided transcript could not be read",
    humanMessage: "The read-only Guided transcript projection encountered an internal error.",
    retryable: false,
    category: "internal",
    remediation: "Use the request ID to inspect redacted server diagnostics before retrying.",
  });
}

/**
 * Authenticated read-only projection over durable Guided Commander messages.
 * It deliberately has no provider port, Second Brain mutation service, plan
 * mutation service, or execution capability.
 */
export function createGuidedTranscriptReadRouter(
  dependencies: GuidedTranscriptReadRouterDependencies,
): Router {
  const router = Router();

  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  router.get(
    "/api/v2/guided/:missionId/commander/transcript",
    (request, response): void => {
      const traceId = attachV2RequestId(request, response);
      try {
        const actor = actorId(dependencies, request);
        onlyQueryKeys(request);
        const missionId = validatePathId(request.params.missionId, "missionId");
        const runId = requiredRunId(request.query.runId);
        const scope = { missionId, runId };
        if (!dependencies.authorize(request, actor, scope)) {
          throw new GuidedTranscriptReadError(
            403,
            "guided_transcript_policy_denied",
            "This identity cannot read the requested Guided transcript.",
            "policy_denied",
            "Use an identity with explicit access to this Guided mission and run.",
          );
        }
        const stepId = optionalStepId(request.query.stepId);
        const cursor = optionalCursor(request.query.cursor);
        response.json({
          schemaVersion: SCHEMA_VERSION,
          ...dependencies.repository.transcript({
            missionId,
            runId,
            ...(stepId ? { stepId } : {}),
            ...(cursor ? { cursor } : {}),
            limit: boundedLimit(request.query.limit),
          }),
        });
      } catch (error) {
        sendError(response, traceId, error);
      }
    },
  );

  router.all(
    "/api/v2/guided/:missionId/commander/transcript",
    (request, response): void => {
      const traceId = attachV2RequestId(request, response);
      response.setHeader("Allow", "GET");
      sendV2Error(response, traceId, {
        status: 405,
        code: "guided_transcript_read_method_not_allowed",
        message: "The Guided transcript projection is read-only",
        humanMessage: "This endpoint exposes durable Guided messages but cannot change them.",
        retryable: false,
        category: "method_not_allowed",
        remediation: "Use a separately authorized Guided decision endpoint for supported actions.",
      });
    },
  );

  return router;
}

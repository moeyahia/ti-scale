import { Router, type Request, type Response } from "express";
import type { SqliteDatabase } from "../db";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import { MissionApiError, validateIdempotencyKey } from "../missions";
import { ResearchLabRepository, type ResearchRuntimeReadiness } from "./ResearchLabRepository";

export interface ResearchLabRouterDependencies {
  readonly database: SqliteDatabase;
  readonly resolveActor: (request: Request) => string;
  readonly readRuntimeReadiness?: () => ResearchRuntimeReadiness;
}

function bodyObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new MissionApiError(400, "invalid_research_request", "Research request body must be an object", {
      humanMessage: "The Research Lab request must be a JSON object.", category: "invalid_input",
    });
  }
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, label: string, maximum = 1_000): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.trim().length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new MissionApiError(400, "invalid_research_request", `${label} is invalid`, {
      humanMessage: `${label} is missing, too long, or malformed.`, category: "invalid_input",
    });
  }
  return value.trim();
}

function actor(request: Request, dependencies: ResearchLabRouterDependencies): string {
  const result = dependencies.resolveActor(request).trim();
  if (!result) throw new MissionApiError(401, "operator_identity_required", "Operator identity is required", {
    humanMessage: "Sign in as a named operator before changing Research Lab state.", category: "authentication_missing",
  });
  return result;
}

function sendError(response: Response, traceId: string, error: unknown): void {
  if (error instanceof MissionApiError) {
    sendV2Error(response, traceId, {
      status: error.status,
      code: error.code,
      message: error.message,
      humanMessage: error.options.humanMessage ?? error.message,
      retryable: error.options.retryable ?? false,
      category: error.options.category ?? "research",
      ...(error.options.details === undefined ? {} : { details: error.options.details }),
      ...(error.options.remediation ? { remediation: error.options.remediation } : {}),
    });
    return;
  }
  sendV2Error(response, traceId, {
    status: 500,
    code: "research_internal_error",
    message: "Research Lab could not complete the request",
    humanMessage: "The local Research Lab encountered an internal error.",
    retryable: false,
    category: "internal",
    remediation: "Inspect the correlated local audit and structured logs before retrying.",
  });
}

export function createResearchLabRouter(dependencies: ResearchLabRouterDependencies): Router {
  const repository = new ResearchLabRepository(dependencies.database, dependencies.readRuntimeReadiness);
  const router = Router();
  router.get("/api/v2/research", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      actor(request, dependencies);
      response.json(repository.snapshot());
    } catch (error) { sendError(response, traceId, error); }
  });
  router.post("/api/v2/research/campaigns", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const body = bodyObject(request.body);
      response.status(201).json(repository.createCampaign({
        catalogId: requiredString(body.catalogId, "Campaign track", 120),
        ownerAcknowledged: body.ownerAcknowledged === true,
        actorId: actor(request, dependencies),
        idempotencyKey: validateIdempotencyKey(request.get("Idempotency-Key")),
      }));
    } catch (error) { sendError(response, traceId, error); }
  });
  router.post("/api/v2/research/campaigns/:campaignId/stop", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const body = bodyObject(request.body);
      response.json(repository.stopCampaign({
        campaignId: requiredString(request.params.campaignId, "Campaign ID", 255),
        expectedUpdatedAt: requiredString(body.expectedUpdatedAt, "Expected campaign timestamp", 80),
        reason: requiredString(body.reason, "Stop reason", 1_000),
        actorId: actor(request, dependencies),
        idempotencyKey: validateIdempotencyKey(request.get("Idempotency-Key")),
      }));
    } catch (error) { sendError(response, traceId, error); }
  });
  return router;
}

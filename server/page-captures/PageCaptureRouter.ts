import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import type { SqliteDatabase } from "../db";
import type { OperationalActor } from "../intelligence-v24/types";
import { RunIntelligenceHttpError } from "../run-intelligence/RunIntelligenceHttpError";
import { RunIntelligenceIdempotencyStore } from "../run-intelligence/RunIntelligenceIdempotencyStore";
import { PageCaptureService } from "./PageCaptureService";
import { PageCaptureError } from "./types";
import {
  pageCaptureIdempotencyKey,
  parseCreatePageCaptureInput,
  parsePageCaptureListFilter,
  stablePageCaptureIdentifier,
} from "./validation";

const SCHEMA_VERSION = "2.4" as const;

export type PageCaptureCapability = "read_page_captures" | "manage_page_captures";

export interface PageCaptureAuthorizationRequest {
  readonly missionId: string;
  readonly runId?: string;
  readonly capability: PageCaptureCapability;
}

export interface PageCaptureRouterDependencies {
  readonly database: SqliteDatabase;
  readonly resolveActor: (request: Request) => OperationalActor | undefined;
  readonly authorize: (
    request: Request,
    actor: OperationalActor,
    authorization: PageCaptureAuthorizationRequest,
  ) => boolean;
  readonly clock?: () => Date;
  readonly basePath?: string;
}

function validatedBasePath(value: string | undefined): string {
  const result = value ?? "/api/v2";
  if (!result.startsWith("/") || result.endsWith("/") || /[?#]/u.test(result)) {
    throw new Error("PageCaptureRouter basePath must be absolute without a trailing slash");
  }
  return result;
}

function authenticatedActor(value: OperationalActor | undefined): OperationalActor {
  if (!value || !["operator", "agent", "worker", "system"].includes(value.type)) {
    throw new PageCaptureError("page_capture_authentication_required", "An authenticated page-capture identity is required");
  }
  return { id: stablePageCaptureIdentifier(value.id, "actor.id"), type: value.type };
}

function errorDescriptor(error: PageCaptureError): {
  readonly status: number;
  readonly category: string;
  readonly remediation: string;
} {
  if (error.code === "page_capture_authentication_required") {
    return { status: 401, category: "authentication_missing", remediation: "Sign in again before accessing page captures." };
  }
  if (error.code === "page_capture_policy_denied") {
    return { status: 403, category: "policy_denied", remediation: "Use an identity with explicit page-capture access to this mission." };
  }
  if (error.code.endsWith("_not_found") || error.code === "page_capture_not_found") {
    return { status: 404, category: "not_found", remediation: "Refresh mission intelligence and use a canonical page-capture link." };
  }
  if (error.code === "page_capture_data_corrupt") {
    return { status: 500, category: "data_integrity", remediation: "Run V2 database integrity checks and reconcile the affected capture record." };
  }
  if (
    error.code.includes("scope_mismatch")
    || error.code.includes("out_of_scope")
    || error.code.includes("prohibited")
    || error.code.includes("authorization_unverified")
    || error.code.includes("actor_mismatch")
  ) {
    return { status: 409, category: "scope_conflict", remediation: "Use only verified authorization and records from the same mission, run, plan step, and target scope." };
  }
  if (
    error.code.includes("hash_mismatch")
    || error.code.includes("sensitivity_downgrade")
    || error.code.includes("finding_evidence")
    || error.code.includes("artifact_required")
  ) {
    return { status: 409, category: "evidence_insufficient", remediation: "Attach immutable in-scope screenshot artifacts and already-linked canonical evidence." };
  }
  if (error.code === "page_capture_already_exists") {
    return { status: 409, category: "state_conflict", remediation: "Use the existing immutable capture or replay the original idempotent request." };
  }
  return { status: 400, category: "invalid_input", remediation: "Correct the named page-capture fields and submit the request again." };
}

function sendError(response: Response, traceId: string, error: unknown): void {
  if (error instanceof RunIntelligenceHttpError) {
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
  if (error instanceof PageCaptureError) {
    const descriptor = errorDescriptor(error);
    sendV2Error(response, traceId, {
      status: descriptor.status,
      code: error.code,
      message: error.message,
      humanMessage: error.message,
      retryable: false,
      category: descriptor.category,
      remediation: descriptor.remediation,
    });
    return;
  }
  sendV2Error(response, traceId, {
    status: 500,
    code: "page_capture_internal_error",
    message: "Page-capture service could not complete the request",
    humanMessage: "The page-capture service encountered an internal error.",
    retryable: false,
    category: "internal",
    remediation: "Use the request ID to inspect redacted structured logs before retrying.",
  });
}

/** Router-ready V2 page-capture routes. Mounting remains an application decision. */
export function createPageCaptureRouter(dependencies: PageCaptureRouterDependencies): Router {
  const router = Router();
  const prefix = validatedBasePath(dependencies.basePath);
  const service = new PageCaptureService(dependencies.database, dependencies.clock);
  const idempotency = new RunIntelligenceIdempotencyStore(dependencies.database, dependencies.clock);

  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  router.get(`${prefix}/missions/:missionId/intelligence/page-captures`, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = authenticatedActor(dependencies.resolveActor(request));
      const missionId = stablePageCaptureIdentifier(request.params.missionId, "missionId");
      const filter = parsePageCaptureListFilter(missionId, request.query as Record<string, unknown>);
      if (!dependencies.authorize(request, actor, {
        missionId,
        ...(filter.runId ? { runId: filter.runId } : {}),
        capability: "read_page_captures",
      })) throw new PageCaptureError("page_capture_policy_denied", "This identity cannot read page captures for the mission");
      response.json({ schemaVersion: SCHEMA_VERSION, ...service.list(filter) });
    } catch (error) { sendError(response, traceId, error); }
  });

  router.get(`${prefix}/missions/:missionId/intelligence/page-captures/:captureId`, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = authenticatedActor(dependencies.resolveActor(request));
      const missionId = stablePageCaptureIdentifier(request.params.missionId, "missionId");
      const record = service.get(missionId, stablePageCaptureIdentifier(request.params.captureId, "captureId"));
      if (!dependencies.authorize(request, actor, {
        missionId,
        ...(record.runId ? { runId: record.runId } : {}),
        capability: "read_page_captures",
      })) throw new PageCaptureError("page_capture_policy_denied", "This identity cannot read the requested page capture");
      response.json({ schemaVersion: SCHEMA_VERSION, record });
    } catch (error) { sendError(response, traceId, error); }
  });

  router.post(`${prefix}/missions/:missionId/intelligence/page-captures`, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = authenticatedActor(dependencies.resolveActor(request));
      const missionId = stablePageCaptureIdentifier(request.params.missionId, "missionId");
      const input = parseCreatePageCaptureInput(missionId, request.body);
      if (!dependencies.authorize(request, actor, {
        missionId,
        runId: input.runId,
        capability: "manage_page_captures",
      })) throw new PageCaptureError("page_capture_policy_denied", "This identity cannot record page captures for the mission");
      const result = idempotency.execute(
        `page_capture.create:${missionId}`,
        pageCaptureIdempotencyKey(request.get("Idempotency-Key")),
        actor,
        input,
        () => ({ schemaVersion: SCHEMA_VERSION, record: service.create(input, actor) }),
      );
      response.setHeader("Idempotency-Replayed", result.replayed ? "true" : "false");
      response.status(result.replayed ? 200 : 201).json(result.response);
    } catch (error) { sendError(response, traceId, error); }
  });

  return router;
}

import { Router, type Request, type Response } from "express";
import {
  ControlPlaneLeaseError,
  RunMutationAuthorityGuard,
  describeRunMutationAuthorityError,
  type AssertRunMutationLease,
  type AuthorizedRunMutation,
} from "../control-plane";
import type { SqliteDatabase } from "../db";
import type { BrainContextService } from "../brain-runtime";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import type { SecondBrainService } from "../memory";
import { GuidedCommanderRepository } from "./GuidedCommanderRepository";
import { GuidedCommanderService } from "./GuidedCommanderService";
import { createGuidedMemoryCandidateRouter } from "./GuidedMemoryCandidateRouter";
import type { GuidedCommanderOptions, GuidedCommanderPort } from "./types";
import {
  GuidedCommanderError,
  validateContextualActionRequest,
  validateIdempotencyKey,
  validateInterpretResultRequest,
  validatePathId,
} from "./validation";

export interface GuidedCommanderRouterDependencies {
  readonly database: SqliteDatabase;
  readonly port: GuidedCommanderPort;
  readonly resolveActor: (request: Request) => string;
  readonly secondBrain?: SecondBrainService;
  readonly brainContext?: BrainContextService;
  readonly options?: GuidedCommanderOptions;
  /** Trusted server callback; raw control-plane tokens never cross HTTP. */
  readonly assertRunMutationLease?: AssertRunMutationLease;
}

function normalizeError(error: unknown): GuidedCommanderError {
  if (error instanceof ControlPlaneLeaseError) {
    const descriptor = describeRunMutationAuthorityError(error);
    return new GuidedCommanderError(descriptor.status, descriptor.code, error.message, {
      humanMessage: error.message,
      category: descriptor.category,
      retryable: descriptor.retryable,
      remediation: descriptor.remediation,
    });
  }
  if (error instanceof GuidedCommanderError) return error;
  if (error instanceof TypeError || error instanceof RangeError) {
    return new GuidedCommanderError(422, "guided_validation_failed", "Guided Commander validation failed", {
      humanMessage: "The Guided request could not be safely validated.",
      category: "invalid_input",
    });
  }
  return new GuidedCommanderError(500, "guided_commander_internal_error", "Guided Commander request failed", {
    humanMessage: "The Guided conversation service could not safely complete this request.",
    category: "internal",
    remediation: "Use the trace ID to inspect structured server events before retrying.",
  });
}

function sendError(response: Response, error: unknown, traceId: string): void {
  const normalized = normalizeError(error);
  sendV2Error(response, traceId, {
    status: normalized.status,
    code: normalized.code,
    message: normalized.message,
    humanMessage: normalized.options.humanMessage ?? normalized.message,
    retryable: normalized.options.retryable ?? false,
    category: normalized.options.category ?? "guided_commander",
    ...(normalized.options.details === undefined ? {} : { details: normalized.options.details }),
    ...(normalized.options.remediation ? { remediation: normalized.options.remediation } : {}),
  });
}

function operatorId(dependencies: GuidedCommanderRouterDependencies, request: Request): string {
  const actor = dependencies.resolveActor(request).trim();
  if (!actor || actor.length > 256) {
    throw new GuidedCommanderError(401, "operator_identity_required", "Operator identity is required", {
      humanMessage: "Sign in before using the Guided Commander.",
      category: "authentication_missing",
    });
  }
  return actor;
}

function requiredRunId(request: Request): string {
  return validatePathId(request.query.runId, "runId");
}

function boundedLimit(value: unknown): number {
  if (value === undefined) return 100;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 200) {
    throw new GuidedCommanderError(400, "invalid_transcript_limit", "Transcript limit must be 1 through 200", {
      category: "invalid_input",
    });
  }
  return parsed;
}

/** Mount after authentication and bounded JSON parsing middleware. */
export function createGuidedCommanderRouter(
  dependencies: GuidedCommanderRouterDependencies,
): Router {
  const repository = new GuidedCommanderRepository(dependencies.database, dependencies.options);
  const service = new GuidedCommanderService({
    repository,
    port: dependencies.port,
    secondBrain: dependencies.secondBrain,
    brainContext: dependencies.brainContext,
    options: dependencies.options,
  });
  const mutationAuthority = new RunMutationAuthorityGuard(
    dependencies.database,
    dependencies.options?.clock,
  );
  const router = Router();
  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  const route = (
    handler: (request: Request, response: Response, traceId: string) => void | Promise<void>,
  ) => async (request: Request, response: Response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      await handler(request, response, traceId);
    } catch (error) {
      sendError(response, error, traceId);
    }
  };

  router.get("/api/v2/guided/:missionId/commander/transcript", route((request, response) => {
    const missionId = validatePathId(request.params.missionId, "missionId");
    const runId = requiredRunId(request);
    const stepId = typeof request.query.stepId === "string"
      ? validatePathId(request.query.stepId, "stepId")
      : undefined;
    const cursor = typeof request.query.cursor === "string" ? request.query.cursor : undefined;
    response.json({
      schemaVersion: "2.4",
      ...service.transcript({
        missionId,
        runId,
        ...(stepId ? { stepId } : {}),
        ...(cursor ? { cursor } : {}),
        limit: boundedLimit(request.query.limit),
      }),
    });
  }));

  const providerAction = (action: "explain_more" | "show_next_step" | "use_another_approach") =>
    route(async (request, response) => {
      const missionId = validatePathId(request.params.missionId, "missionId");
      const actorId = operatorId(dependencies, request);
      const key = validateIdempotencyKey(request.get("Idempotency-Key"));
      const body = validateContextualActionRequest(request.body);
      const authority = authorizeMutation(
        mutationAuthority,
        dependencies,
        missionId,
        body.runId,
        actorId,
      );
      const controller = new AbortController();
      const abort = () => controller.abort();
      request.once("aborted", abort);
      try {
        const result = await service.respond({
          missionId,
          action,
          request: body,
          idempotencyKey: key,
          actorId,
          signal: controller.signal,
          assertMutationAuthority: authority.assertCurrent,
        });
        response.json({ schemaVersion: "2.4", result });
      } finally {
        request.off("aborted", abort);
      }
    });

  router.post(
    "/api/v2/guided/:missionId/commander/explain-more",
    providerAction("explain_more"),
  );
  router.post(
    "/api/v2/guided/:missionId/commander/show-next-step",
    providerAction("show_next_step"),
  );
  router.post(
    "/api/v2/guided/:missionId/commander/use-another-approach",
    providerAction("use_another_approach"),
  );

  router.post("/api/v2/guided/:missionId/commander/interpret-result", route(async (request, response) => {
    const missionId = validatePathId(request.params.missionId, "missionId");
    const actorId = operatorId(dependencies, request);
    const key = validateIdempotencyKey(request.get("Idempotency-Key"));
    const body = validateInterpretResultRequest(request.body);
    const authority = authorizeMutation(
      mutationAuthority,
      dependencies,
      missionId,
      body.runId,
      actorId,
    );
    const controller = new AbortController();
    const abort = () => controller.abort();
    request.once("aborted", abort);
    try {
      const result = await service.interpret({
        missionId,
        request: body,
        idempotencyKey: key,
        actorId,
        signal: controller.signal,
        assertMutationAuthority: authority.assertCurrent,
      });
      response.json({
        schemaVersion: "2.4",
        result,
        ingestion: {
          multipartSupported: false,
          acceptedSources: ["paste", "text_upload"],
          rawContentRetained: false,
        },
      });
    } finally {
      request.off("aborted", abort);
    }
  }));

  router.use(createGuidedMemoryCandidateRouter({
    database: dependencies.database,
    resolveActor: dependencies.resolveActor,
    secondBrain: dependencies.secondBrain,
    options: dependencies.options,
    ...(dependencies.assertRunMutationLease
      ? { assertRunMutationLease: dependencies.assertRunMutationLease }
      : {}),
  }));

  return router;
}

function authorizeMutation(
  guard: RunMutationAuthorityGuard,
  dependencies: GuidedCommanderRouterDependencies,
  missionId: string,
  runId: string,
  actorId: string,
): AuthorizedRunMutation {
  // Resolve trusted runtime authority before the Guided service may consult a
  // replay record, reserve a provider turn, acquire evidence, or write memory.
  const authority = guard.authorize({
    runId,
    actorId,
    mode: "lease",
    ...(dependencies.assertRunMutationLease
      ? { assertLease: dependencies.assertRunMutationLease }
      : {}),
  });
  if (authority.scope.missionId !== missionId) {
    throw new GuidedCommanderError(404, "guided_scope_not_found", "Guided run does not belong to this mission", {
      humanMessage: "The Guided run is unavailable or does not belong to this mission.",
      category: "not_found",
      remediation: "Refresh the mission and use the current canonical Guided step link.",
    });
  }
  return authority;
}

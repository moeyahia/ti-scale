import { Router, type Request, type Response } from "express";
import {
  ControlPlaneLeaseError,
  RunMutationAuthorityGuard,
  describeRunMutationAuthorityError,
  type AssertRunMutationLease,
} from "../control-plane";
import type { SqliteDatabase } from "../db";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import type { SecondBrainService } from "../memory";
import { GuidedCommanderRepository } from "./GuidedCommanderRepository";
import { GuidedCommanderService } from "./GuidedCommanderService";
import type { GuidedCommanderOptions } from "./types";
import {
  GuidedCommanderError,
  validateDoNotRememberRequest,
  validateIdempotencyKey,
  validatePathId,
  validateRememberRequest,
} from "./validation";

export interface GuidedMemoryCandidateRouterDependencies {
  readonly database: SqliteDatabase;
  readonly resolveActor: (request: Request) => string;
  readonly secondBrain?: SecondBrainService;
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
    return new GuidedCommanderError(422, "guided_validation_failed", "Guided memory validation failed", {
      humanMessage: "The Guided memory request could not be safely validated.",
      category: "invalid_input",
    });
  }
  return new GuidedCommanderError(500, "guided_memory_internal_error", "Guided memory request failed", {
    humanMessage: "The local Second Brain service could not safely complete this request.",
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
    category: normalized.options.category ?? "guided_memory",
    ...(normalized.options.details === undefined ? {} : { details: normalized.options.details }),
    ...(normalized.options.remediation ? { remediation: normalized.options.remediation } : {}),
  });
}

function operatorId(
  dependencies: GuidedMemoryCandidateRouterDependencies,
  request: Request,
): string {
  const actor = dependencies.resolveActor(request).trim();
  if (!actor || actor.length > 256) {
    throw new GuidedCommanderError(401, "operator_identity_required", "Operator identity is required", {
      humanMessage: "Sign in before creating or suppressing a memory candidate.",
      category: "authentication_missing",
    });
  }
  return actor;
}

/**
 * Local-only Guided memory mutations. No provider port, tool registry, or
 * execution adapter is accepted by this boundary; candidates remain pending
 * until reviewed through the canonical Second Brain lifecycle.
 */
export function createGuidedMemoryCandidateRouter(
  dependencies: GuidedMemoryCandidateRouterDependencies,
): Router {
  const service = new GuidedCommanderService({
    repository: new GuidedCommanderRepository(dependencies.database, dependencies.options),
    secondBrain: dependencies.secondBrain,
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
    handler: (request: Request, response: Response) => void,
  ) => (request: Request, response: Response): void => {
    const traceId = attachV2RequestId(request, response);
    try {
      handler(request, response);
    } catch (error) {
      sendError(response, error, traceId);
    }
  };

  router.post("/api/v2/guided/:missionId/commander/remember", route((request, response) => {
    const missionId = validatePathId(request.params.missionId, "missionId");
    const actorId = operatorId(dependencies, request);
    const body = validateRememberRequest(request.body);
    const idempotencyKey = validateIdempotencyKey(request.get("Idempotency-Key"));
    const authority = mutationAuthority.authorize({
      runId: body.runId,
      actorId,
      mode: "lease",
      ...(dependencies.assertRunMutationLease
        ? { assertLease: dependencies.assertRunMutationLease }
        : {}),
    });
    assertMissionScope(authority.scope.missionId, missionId);
    const result = service.remember({
      missionId,
      request: body,
      idempotencyKey,
      actorId,
      assertMutationAuthority: authority.assertCurrent,
    });
    response.status(201).json({ schemaVersion: "2.4", result });
  }));

  router.post("/api/v2/guided/:missionId/commander/do-not-remember", route((request, response) => {
    const missionId = validatePathId(request.params.missionId, "missionId");
    const actorId = operatorId(dependencies, request);
    const body = validateDoNotRememberRequest(request.body);
    const idempotencyKey = validateIdempotencyKey(request.get("Idempotency-Key"));
    const authority = mutationAuthority.authorize({
      runId: body.runId,
      actorId,
      mode: "lease",
      ...(dependencies.assertRunMutationLease
        ? { assertLease: dependencies.assertRunMutationLease }
        : {}),
    });
    assertMissionScope(authority.scope.missionId, missionId);
    const result = service.doNotRemember({
      missionId,
      request: body,
      idempotencyKey,
      actorId,
      assertMutationAuthority: authority.assertCurrent,
    });
    response.json({ schemaVersion: "2.4", result });
  }));

  return router;
}

function assertMissionScope(ownedMissionId: string, requestedMissionId: string): void {
  if (ownedMissionId !== requestedMissionId) {
    throw new GuidedCommanderError(404, "guided_scope_not_found", "Guided run does not belong to this mission", {
      humanMessage: "The Guided run is unavailable or does not belong to this mission.",
      category: "not_found",
      remediation: "Refresh the mission and use the current canonical Guided step link.",
    });
  }
}

import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import {
  BrainContextHookError,
  parseMissionMemoryPolicy,
  retrieveMissionBrainContext,
  type BrainContextResult,
  type BrainContextService,
} from "../brain-runtime";
import {
  ControlPlaneLeaseError,
  RunMutationAuthorityGuard,
  describeRunMutationAuthorityError,
  type AssertRunMutationLease,
} from "../control-plane";
import type { SqliteDatabase } from "../db";
import { PlanChangeIdempotencyStore } from "./PlanChangeIdempotencyStore";
import { PlanChangeService } from "./PlanChangeService";
import type {
  PlanChangeActor,
  PlanChangeAffectedWorkStopReceipt,
} from "./types";
import { PlanChangeError } from "./types";
import {
  identifier,
  parseApplyPlanChangeInput,
  parseCreatePlanChangeInput,
  parseEditPlanChangeInput,
  parseFinalizePlanChangeInflightInput,
  parseRejectPlanChangeInput,
  parseResolvePlanChangeInflightInput,
  requiredIdempotencyKey,
} from "./validation";

export type PlanChangeCapability = "read_plan_changes" | "manage_plan_changes" | "apply_plan_changes";

export interface PlanChangeAuthorizationRequest {
  readonly missionId: string;
  readonly runId: string;
  readonly capability: PlanChangeCapability;
  readonly requestId?: string;
}

export interface PlanChangeRouterDependencies {
  readonly database: SqliteDatabase;
  readonly resolveActor: (request: Request) => PlanChangeActor | undefined;
  readonly authorize: (
    request: Request,
    actor: PlanChangeActor,
    authorization: PlanChangeAuthorizationRequest,
  ) => boolean;
  readonly clock?: () => Date;
  readonly basePath?: string;
  /** Trusted server callback; raw control-plane tokens never cross HTTP. */
  readonly assertRunMutationLease?: AssertRunMutationLease;
  /** Shared local Brain boundary; the composition root must supply this in production. */
  readonly brainContext?: BrainContextService;
  /**
   * Trusted runtime-only cancellation. It must return only after every exact
   * affected child process has stopped; the router verifies the receipt
   * before canonical action status is allowed to change.
   */
  readonly cancelAffectedWork?: (input: {
    readonly runId: string;
    readonly actionIds: readonly string[];
    readonly reason: string;
  }) => Promise<PlanChangeAffectedWorkStopReceipt>;
}

function basePath(value: string | undefined): string {
  const result = value ?? "/api/v2";
  if (!result.startsWith("/") || result.endsWith("/") || /[?#]/u.test(result)) throw new Error("PlanChangeRouter basePath is invalid");
  return result;
}

function runScope(database: SqliteDatabase, runId: string): { readonly missionId: string; readonly runId: string } {
  const row = database.prepare("SELECT mission_id FROM runs WHERE id = ?").get(runId) as { readonly mission_id: string } | undefined;
  if (!row) throw new PlanChangeError("plan_change_run_not_found", `Run not found: ${runId}`, "not_found", 404, "Refresh the mission and use a canonical run link.");
  return { missionId: row.mission_id, runId };
}

function actor(value: PlanChangeActor | undefined): PlanChangeActor {
  if (!value || !["operator", "reviewer", "admin"].includes(value.type)) {
    throw new PlanChangeError("plan_change_authentication_required", "Authenticated operator identity is required", "policy_denied", 401, "Sign in to the isolated Ti-Scale control plane.");
  }
  return { id: identifier(value.id, "actor.id"), type: value.type };
}

function sendError(response: Response, traceId: string, error: unknown): void {
  if (error instanceof BrainContextHookError) {
    sendV2Error(response, traceId, {
      status: error.code === "brain_context_unavailable" ? 503 : 500,
      code: error.code,
      message: error.message,
      humanMessage: error.code === "brain_context_unavailable"
        ? "The plan amendment did not proceed because required scoped Second Brain context is unavailable."
        : "The plan amendment did not proceed because its Second Brain context receipt could not be established.",
      retryable: error.code === "brain_context_unavailable",
      category: "dependency_missing",
      details: { hook: error.hook, auditRecordId: error.auditRecordId ?? null },
      remediation: "Restore the local Second Brain dependency and retry against the unchanged plan version.",
    });
    return;
  }
  if (error instanceof ControlPlaneLeaseError) {
    const descriptor = describeRunMutationAuthorityError(error);
    sendV2Error(response, traceId, {
      status: descriptor.status,
      code: descriptor.code,
      message: error.message,
      humanMessage: error.message,
      retryable: descriptor.retryable,
      category: descriptor.category,
      remediation: descriptor.remediation,
    });
    return;
  }
  if (error instanceof PlanChangeError) {
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
  sendV2Error(response, traceId, {
    status: 500,
    code: "plan_change_internal_error",
    message: "Plan change service could not complete the request",
    humanMessage: "The versioned plan-change service encountered an internal error.",
    retryable: false,
    category: "internal",
    remediation: "Use the request ID to inspect redacted V2 logs before retrying.",
  });
}

/** Authenticated, policy-authorized V2.4 route boundary for plan proposals. */
export function createPlanChangeRouter(dependencies: PlanChangeRouterDependencies): Router {
  const router = Router();
  const prefix = basePath(dependencies.basePath);
  const service = new PlanChangeService(dependencies.database, dependencies.clock);
  const idempotency = new PlanChangeIdempotencyStore(dependencies.database, dependencies.clock);
  const mutationAuthority = new RunMutationAuthorityGuard(dependencies.database, dependencies.clock);

  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  const retrieveReplanContext = (
    context: { readonly actor: PlanChangeActor; readonly missionId: string; readonly runId: string },
    purpose: "propose" | "edit" | "apply",
  ): BrainContextResult | undefined => {
    if (!dependencies.brainContext) return undefined;
    const scope = dependencies.database.prepare(`
      SELECT r.journey, m.memory_policy_json
      FROM runs r JOIN missions m ON m.id = r.mission_id
      WHERE r.id = ? AND r.mission_id = ?
    `).get(context.runId, context.missionId) as {
      readonly journey: "autonomous" | "guided";
      readonly memory_policy_json: string;
    } | undefined;
    if (!scope) {
      throw new PlanChangeError(
        "plan_change_run_not_found",
        "Plan amendment mission/run scope is unavailable",
        "not_found",
        404,
        "Refresh the mission and use its canonical run link.",
      );
    }
    const result = retrieveMissionBrainContext({
      brainContext: dependencies.brainContext,
      hook: "replan",
      journey: scope.journey,
      missionId: context.missionId,
      runId: context.runId,
      actorId: context.actor.id,
      actorType: "operator",
      query: `Retrieve scoped plan, evidence, failure, recovery, and verified-lesson context before the deterministic ${purpose} plan-amendment boundary.`,
      queryRedacted: `Retrieve bounded scoped context before ${purpose} plan amendment.`,
      memoryPolicy: parseMissionMemoryPolicy(scope.memory_policy_json),
    });
    dependencies.brainContext.recordUnusedContext(
      result,
      "The deterministic plan-amendment boundary preserved the operator's represented diff and used memory only for availability and audit context; it did not silently reinterpret the requested change.",
    );
    return result;
  };

  const route = (
    capability: PlanChangeCapability,
    handler: (request: Request, response: Response, context: { readonly actor: PlanChangeActor; readonly missionId: string; readonly runId: string }) => void | Promise<void>,
  ) => async (request: Request, response: Response): Promise<void> => {
    const traceId = attachV2RequestId(request, response);
    try {
      const resolvedActor = actor(dependencies.resolveActor(request));
      const scope = runScope(dependencies.database, identifier(request.params.runId, "runId"));
      const requestId = request.params.requestId === undefined ? undefined : identifier(request.params.requestId, "requestId");
      if (!dependencies.authorize(request, resolvedActor, { ...scope, capability, ...(requestId ? { requestId } : {}) })) {
        throw new PlanChangeError("plan_change_policy_denied", "Plan-change capability is not authorized for this run", "policy_denied", 403, "Request access from the mission owner or an authorized reviewer.");
      }
      if (requestId) {
        const planChange = service.get(requestId);
        if (planChange.runId !== scope.runId || planChange.missionId !== scope.missionId) {
          throw new PlanChangeError("plan_change_not_found", "Plan change request is not present in this run", "not_found", 404, "Use a canonical link from the selected run.");
        }
      }
      await handler(request, response, { actor: resolvedActor, ...scope });
    } catch (error) {
      sendError(response, traceId, error);
    }
  };

  const mutateAsync = async (
    request: Request,
    response: Response,
    context: { readonly actor: PlanChangeActor; readonly runId: string },
    scope: string,
    requestValue: unknown,
    status: number,
    operation: () => Promise<unknown>,
  ): Promise<void> => {
    const authority = mutationAuthority.authorize({
      runId: context.runId,
      actorId: context.actor.id,
      mode: "lease",
      ...(dependencies.assertRunMutationLease
        ? { assertLease: dependencies.assertRunMutationLease }
        : {}),
    });
    const result = await idempotency.executeAsync(
      scope,
      requiredIdempotencyKey(request.get("Idempotency-Key")),
      context.actor,
      requestValue,
      async () => {
        authority.assertCurrent();
        const responseValue = await operation();
        authority.assertCurrent();
        return responseValue;
      },
    );
    response.setHeader("Idempotency-Replayed", result.replayed ? "true" : "false");
    response.status(status).json(result.response);
  };

  const mutate = (
    request: Request,
    response: Response,
    context: { readonly actor: PlanChangeActor; readonly runId: string },
    scope: string,
    requestValue: unknown,
    status: number,
    operation: (brainContext: BrainContextResult | undefined) => unknown,
    brainPreflight?: () => BrainContextResult | undefined,
  ): void => {
    // Resolve the trusted runtime proof before consulting durable replay state;
    // idempotency must never authorize a caller after its lease was fenced.
    const authority = mutationAuthority.authorize({
      runId: context.runId,
      actorId: context.actor.id,
      mode: "lease",
      ...(dependencies.assertRunMutationLease
        ? { assertLease: dependencies.assertRunMutationLease }
        : {}),
    });
    // Run the Brain hook after trusted lease authorization but before replay
    // lookup. Required-Autonomous failure receipts therefore survive any
    // refused mutation transaction, and a replay cannot bypass current Brain
    // policy merely because an older response exists.
    const brainContext = brainPreflight?.();
    const result = idempotency.execute(
      scope,
      requiredIdempotencyKey(request.get("Idempotency-Key")),
      context.actor,
      requestValue,
      () => {
        authority.assertCurrent();
        return operation(brainContext);
      },
    );
    response.setHeader("Idempotency-Replayed", result.replayed ? "true" : "false");
    response.status(status).json(result.response);
  };

  router.get(`${prefix}/runs/:runId/plan-changes`, route("read_plan_changes", (_request, response, context) => {
    response.json({ schemaVersion: "2.4", items: service.list(context.runId) });
  }));

  router.get(`${prefix}/runs/:runId/plan-changes/:requestId`, route("read_plan_changes", (request, response) => {
    response.json({ schemaVersion: "2.4", request: service.get(identifier(request.params.requestId, "requestId")) });
  }));

  router.get(`${prefix}/runs/:runId/plan-changes/:requestId/inflight-resolution`, route("read_plan_changes", (request, response) => {
    response.json({
      schemaVersion: "2.4",
      resolution: service.getInflightResolution(
        identifier(request.params.requestId, "requestId"),
      ) ?? null,
    });
  }));

  router.post(`${prefix}/runs/:runId/plan-changes`, route("manage_plan_changes", (request, response, context) => {
    const input = parseCreatePlanChangeInput(context.missionId, context.runId, request.body);
    mutate(request, response, context, `plan_change.propose:${context.runId}`, input, 201, (brainContext) => ({
      schemaVersion: "2.4",
      request: service.propose(input, context.actor),
      contextPackId: brainContext?.contextPack.id ?? null,
    }), () => retrieveReplanContext(context, "propose"));
  }));

  router.put(`${prefix}/runs/:runId/plan-changes/:requestId`, route("manage_plan_changes", (request, response, context) => {
    const requestId = identifier(request.params.requestId, "requestId");
    const input = parseEditPlanChangeInput(requestId, request.body);
    mutate(request, response, context, `plan_change.edit:${context.runId}:${requestId}`, input, 200, (brainContext) => ({
      schemaVersion: "2.4",
      request: service.edit(input, context.actor),
      contextPackId: brainContext?.contextPack.id ?? null,
    }), () => retrieveReplanContext(context, "edit"));
  }));

  router.post(`${prefix}/runs/:runId/plan-changes/:requestId/apply`, route("apply_plan_changes", (request, response, context) => {
    const requestId = identifier(request.params.requestId, "requestId");
    const input = parseApplyPlanChangeInput(requestId, request.body);
    mutate(request, response, context, `plan_change.apply:${context.runId}:${requestId}`, input, 200, (brainContext) => ({
      schemaVersion: "2.4",
      ...service.apply(input, context.actor),
      contextPackId: brainContext?.contextPack.id ?? null,
    }), () => retrieveReplanContext(context, "apply"));
  }));

  router.post(`${prefix}/runs/:runId/plan-changes/:requestId/reject`, route("manage_plan_changes", (request, response, context) => {
    const requestId = identifier(request.params.requestId, "requestId");
    const input = parseRejectPlanChangeInput(requestId, request.body);
    mutate(request, response, context, `plan_change.reject:${context.runId}:${requestId}`, input, 200, () => ({
      schemaVersion: "2.4",
      request: service.reject(input, context.actor),
    }));
  }));

  router.post(`${prefix}/runs/:runId/plan-changes/:requestId/resolve-inflight`, route("manage_plan_changes", async (request, response, context) => {
    const requestId = identifier(request.params.requestId, "requestId");
    const input = parseResolvePlanChangeInflightInput(requestId, request.body);
    await mutateAsync(
      request,
      response,
      context,
      `plan_change.resolve_inflight:${context.runId}:${requestId}`,
      input,
      200,
      async () => {
        let resolution = service.beginInflightResolution(input, context.actor);
        if (input.mode === "checkpoint_cancel_affected_work") {
          if (!dependencies.cancelAffectedWork) {
            throw new PlanChangeError(
              "plan_change_exact_cancellation_unavailable",
              "The trusted runtime does not expose exact affected-child cancellation",
              "dependency_missing",
              503,
              "Restore the Ti-Scale runtime cancellation port; full-run cancellation is never substituted.",
            );
          }
          const runningActionIds = (dependencies.database.prepare(`
            SELECT id FROM actions
            WHERE run_id = ? AND status = 'running'
              AND id IN (SELECT value FROM json_each(?))
            ORDER BY id
          `).all(
            context.runId,
            JSON.stringify(resolution.affectedActionIds),
          ) as Array<{ readonly id: string }>).map((row) => row.id);
          const receipt = await dependencies.cancelAffectedWork({
            runId: context.runId,
            actionIds: runningActionIds,
            reason: input.reason,
          });
          const expected = [...runningActionIds].sort();
          const stopped = [...new Set(receipt.stoppedActionIds)].sort();
          if (
            expected.length !== stopped.length
            || expected.some((actionId, index) => actionId !== stopped[index])
          ) {
            throw new PlanChangeError(
              "plan_change_cancellation_receipt_mismatch",
              "The trusted runtime did not confirm the exact affected child set",
              "state_conflict",
              409,
              "Keep the dispatch fence active and inspect the runtime cancellation receipt.",
            );
          }
          resolution = service.confirmAffectedCancellation(
            requestId,
            resolution.version,
            context.actor,
            receipt,
          );
        }
        return { schemaVersion: "2.4", resolution };
      },
    );
  }));

  router.post(`${prefix}/runs/:runId/plan-changes/:requestId/inflight-resolution/finalize`, route("manage_plan_changes", (request, response, context) => {
    const requestId = identifier(request.params.requestId, "requestId");
    const input = parseFinalizePlanChangeInflightInput(requestId, request.body);
    mutate(
      request,
      response,
      context,
      `plan_change.finalize_inflight:${context.runId}:${requestId}`,
      input,
      200,
      () => ({
        schemaVersion: "2.4",
        ...service.finalizeInflightResolution(input, context.actor),
      }),
    );
  }));

  return router;
}

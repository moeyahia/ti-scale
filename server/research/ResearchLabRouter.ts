import { Router, type Request, type Response } from "express";
import type { SqliteDatabase } from "../db";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import { MissionApiError, validateIdempotencyKey } from "../missions";
import type { IntegrityAuthority } from "./IntegrityVerifier";
import type {
  ExperimentRunner,
  ResearchExperimentRunRecord,
} from "./ExperimentRunner";
import { ResearchLabRepository, type ResearchRuntimeReadiness } from "./ResearchLabRepository";
import type { PrivateResearchHoldoutRegistry } from "./PrivateResearchHoldout";
import {
  HUMAN_RESEARCH_PROMOTION_ACTIONS,
  ResearchPromotionLifecycleRepository,
  type HumanResearchPromotionAction,
} from "./ResearchPromotionLifecycleRepository";

export interface ResearchLabRouterDependencies {
  readonly database: SqliteDatabase;
  readonly resolveActor: (
    request: Request,
  ) => ResearchPromotionActor | undefined;
  readonly authorizePromotion: (
    request: Request,
    actor: ResearchPromotionActor,
    operation: {
      readonly experimentId: string;
      readonly action: HumanResearchPromotionAction;
    },
  ) => boolean;
  readonly readRuntimeReadiness?: () => ResearchRuntimeReadiness;
  readonly integrityAuthority?: IntegrityAuthority;
  /** Trusted local-only descriptor registry. Never serialize it or its scenario IDs. */
  readonly privateHoldout?: PrivateResearchHoldoutRegistry;
  readonly experimentRunner?: Pick<
    ExperimentRunner,
    "enqueue" | "enqueueStage" | "read" | "cancel" | "cancelCampaign"
  >;
  readonly authorizeExecution?: (
    request: Request,
    actor: ResearchPromotionActor,
    operation: {
      readonly action: "start" | "read" | "cancel";
      readonly experimentId: string;
      readonly runId?: string;
    },
  ) => boolean;
}

export interface ResearchPromotionActor {
  readonly id: string;
  readonly type: "operator" | "reviewer" | "admin";
}

function bodyObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new MissionApiError(400, "invalid_research_request", "Research request body must be an object", {
      humanMessage: "The Research Lab request must be a JSON object.", category: "invalid_input",
    });
  }
  return value as Record<string, unknown>;
}

function requiredString(
  value: unknown,
  label: string,
  maximum = 1_000,
  allowReadableWhitespace = false,
): string {
  const unsafeControl = allowReadableWhitespace
    ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u
    : /[\u0000-\u001f\u007f]/u;
  if (
    typeof value !== "string"
    || value.trim().length === 0
    || value.trim().length > maximum
    || unsafeControl.test(value)
  ) {
    throw new MissionApiError(400, "invalid_research_request", `${label} is invalid`, {
      humanMessage: `${label} is missing, too long, or malformed.`, category: "invalid_input",
    });
  }
  return value.trim();
}

function requiredStringArray(value: unknown, label: string): string[] {
  if (
    !Array.isArray(value)
    || value.length === 0
    || value.length > 50
    || value.some((item) =>
      typeof item !== "string"
      || item.trim().length === 0
      || item.trim().length > 500
      || /[\u0000-\u001f\u007f]/u.test(item))
  ) {
    throw new MissionApiError(400, "invalid_research_request", `${label} is invalid`, {
      humanMessage: `${label} must contain one to fifty stable references.`,
      category: "invalid_input",
    });
  }
  const result = value.map((item) => (item as string).trim());
  if (new Set(result).size !== result.length) {
    throw new MissionApiError(400, "invalid_research_request", `${label} contains duplicate references`, {
      humanMessage: `${label} must contain unique stable references.`,
      category: "invalid_input",
    });
  }
  return result;
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new MissionApiError(400, "invalid_research_request", `${label} is invalid`, {
      humanMessage: `${label} must be a positive integer.`,
      category: "invalid_input",
    });
  }
  return value as number;
}

function humanPromotionAction(value: unknown): HumanResearchPromotionAction {
  const action = requiredString(value, "Promotion action", 80);
  if (!HUMAN_RESEARCH_PROMOTION_ACTIONS.includes(action as HumanResearchPromotionAction)) {
    throw new MissionApiError(400, "invalid_research_request", "Promotion action is invalid", {
      humanMessage: "Choose one of the currently represented human promotion actions.",
      category: "invalid_input",
    });
  }
  return action as HumanResearchPromotionAction;
}

function actor(
  request: Request,
  dependencies: ResearchLabRouterDependencies,
): ResearchPromotionActor {
  const resolved = dependencies.resolveActor(request);
  const id = resolved?.id.trim() ?? "";
  if (!resolved || !id) throw new MissionApiError(401, "operator_identity_required", "Operator identity is required", {
    humanMessage: "Sign in as a named operator before changing Research Lab state.", category: "authentication_missing",
  });
  return { id, type: resolved.type };
}

function isSqliteBusy(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const code = (error as { readonly code?: unknown }).code;
  return typeof code === "string"
    && (code === "SQLITE_BUSY" || code.startsWith("SQLITE_BUSY_"));
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
  if (isSqliteBusy(error)) {
    response.setHeader("Retry-After", "1");
    sendV2Error(response, traceId, {
      status: 503,
      code: "research_store_busy",
      message: "The Research Lab store is temporarily busy",
      humanMessage: "Another local operation is briefly updating the Research Lab.",
      retryable: true,
      category: "persistence",
      remediation: "Try this exact change again; Ti-Scale will reuse its original submission key.",
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

function publicRunRecord(
  run: ResearchExperimentRunRecord,
  privateHoldout?: PrivateResearchHoldoutRegistry,
): ResearchExperimentRunRecord {
  if (!privateHoldout?.isPrivateScenario(run.scenarioId)) return run;
  return Object.freeze({
    ...run,
    scenarioId: "private-hidden-holdout",
  });
}

export function createResearchLabRouter(dependencies: ResearchLabRouterDependencies): Router {
  const repository = new ResearchLabRepository(
    dependencies.database,
    dependencies.readRuntimeReadiness,
    undefined,
    dependencies.privateHoldout,
  );
  const promotions = new ResearchPromotionLifecycleRepository(
    dependencies.database,
    dependencies.integrityAuthority,
  );
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
        actorId: actor(request, dependencies).id,
        idempotencyKey: validateIdempotencyKey(request.get("Idempotency-Key")),
      }));
    } catch (error) { sendError(response, traceId, error); }
  });
  router.post("/api/v2/research/campaigns/:campaignId/stop", async (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const body = bodyObject(request.body);
      const campaignId = requiredString(
        request.params.campaignId,
        "Campaign ID",
        255,
      );
      const stoppingActor = actor(request, dependencies);
      const reason = requiredString(body.reason, "Stop reason", 1_000);
      const idempotencyKey = validateIdempotencyKey(
        request.get("Idempotency-Key"),
      );
      const activeRuns = dependencies.database.prepare(`
        SELECT COUNT(*) AS count
        FROM experiment_runs run
        JOIN experiments experiment ON experiment.id = run.experiment_id
        WHERE experiment.campaign_id = ?
          AND run.status IN ('queued', 'running')
      `).get(campaignId) as { readonly count: number };
      if (activeRuns.count > 0 && !dependencies.experimentRunner) {
        throw new MissionApiError(
          503,
          "research_cancellation_not_ready",
          "Active Research runs cannot be stopped without the exact runner boundary",
          {
            humanMessage: "This campaign still owns active isolated work, but its cancellation controller is unavailable.",
            category: "dependency_unavailable",
            remediation: "Restore the local Research runner, then stop the campaign so worker cleanup can be proven.",
          },
        );
      }
      if (dependencies.experimentRunner) {
        await dependencies.experimentRunner.cancelCampaign({
          campaignId,
          actorId: stoppingActor.id,
          reason,
          idempotencyKey: `${idempotencyKey}:campaign-runs`,
        });
      }
      response.json(repository.stopCampaign({
        campaignId,
        expectedUpdatedAt: requiredString(body.expectedUpdatedAt, "Expected campaign timestamp", 80),
        reason,
        actorId: stoppingActor.id,
        idempotencyKey,
      }));
    } catch (error) { sendError(response, traceId, error); }
  });
  router.post("/api/v2/research/campaigns/:campaignId/setup", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const body = bodyObject(request.body);
      response.status(201).json(
        repository.approveAndQueueBuiltInExperiment({
          campaignId: requiredString(
            request.params.campaignId,
            "Campaign ID",
            255,
          ),
          expectedUpdatedAt: requiredString(
            body.expectedUpdatedAt,
            "Expected campaign timestamp",
            80,
          ),
          candidatePresetId: requiredString(
            body.candidatePresetId,
            "Candidate preset",
            255,
          ),
          ownerApproval: body.ownerApproval === true,
          actorId: actor(request, dependencies).id,
          idempotencyKey: validateIdempotencyKey(
            request.get("Idempotency-Key"),
          ),
        }),
      );
    } catch (error) { sendError(response, traceId, error); }
  });
  router.post("/api/v2/research/experiments/:experimentId/runs", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const executionActor = actor(request, dependencies);
      const experimentId = requiredString(
        request.params.experimentId,
        "Experiment ID",
        255,
      );
      if (
        dependencies.authorizeExecution
        && !dependencies.authorizeExecution(
          request,
          executionActor,
          { action: "start", experimentId },
        )
      ) {
        throw new MissionApiError(
          403,
          "research_execution_forbidden",
          "Research execution requires the human campaign owner",
          {
            humanMessage: "Only the named human campaign owner may start this bounded experiment.",
            category: "authorization_denied",
          },
        );
      }
      const readiness = dependencies.readRuntimeReadiness?.() ?? {
        disposableLabReady: false,
        isolatedWorkerReady: false,
        integritySigningKeyReady: false,
      };
      if (
        !dependencies.experimentRunner
        || !readiness.disposableLabReady
        || !readiness.isolatedWorkerReady
        || !readiness.integritySigningKeyReady
      ) {
        throw new MissionApiError(
          503,
          "research_execution_not_ready",
          "Research execution dependencies are not ready",
          {
            humanMessage: "The disposable fixture, exact isolated worker, or local integrity signer has not passed its current challenge.",
            category: "dependency_unavailable",
            remediation: "Review Research readiness and retry only after every local execution-boundary check passes.",
          },
        );
      }
      const body = bodyObject(request.body);
      response.status(202).json({
        schemaVersion: "2.4",
        run: publicRunRecord(
          dependencies.experimentRunner.enqueue({
            experimentId,
            scenarioId: requiredString(
              body.scenarioId,
              "Development benchmark scenario ID",
              255,
            ),
            seed: requiredString(body.seed, "Experiment seed", 160),
            actorId: executionActor.id,
            idempotencyKey: validateIdempotencyKey(
              request.get("Idempotency-Key"),
            ),
          }),
          dependencies.privateHoldout,
        ),
      });
    } catch (error) { sendError(response, traceId, error); }
  });
  router.post(
    "/api/v2/research/experiments/:experimentId/stages/:stage/runs",
    (request, response) => {
      const traceId = attachV2RequestId(request, response);
      try {
        const executionActor = actor(request, dependencies);
        const experimentId = requiredString(
          request.params.experimentId,
          "Experiment ID",
          255,
        );
        const stage = requiredString(
          request.params.stage,
          "Research stage",
          80,
        );
        if (stage !== "validation" && stage !== "hidden_holdout") {
          throw new MissionApiError(
            400,
            "research_stage_invalid",
            "Only validation and hidden_holdout use the server-resolved stage route",
            {
              humanMessage:
                "Choose validation or hidden holdout after the preceding benchmark stage passes.",
              category: "invalid_input",
            },
          );
        }
        if (
          dependencies.authorizeExecution
          && !dependencies.authorizeExecution(
            request,
            executionActor,
            { action: "start", experimentId },
          )
        ) {
          throw new MissionApiError(
            403,
            "research_execution_forbidden",
            "Research execution requires the human campaign owner",
            {
              humanMessage:
                "Only the named human campaign owner may start this bounded experiment stage.",
              category: "authorization_denied",
            },
          );
        }
        const readiness = dependencies.readRuntimeReadiness?.() ?? {
          disposableLabReady: false,
          isolatedWorkerReady: false,
          integritySigningKeyReady: false,
        };
        if (
          !dependencies.experimentRunner
          || !readiness.disposableLabReady
          || !readiness.isolatedWorkerReady
          || !readiness.integritySigningKeyReady
        ) {
          throw new MissionApiError(
            503,
            "research_execution_not_ready",
            "Research execution dependencies are not ready",
            {
              humanMessage:
                "The disposable fixture, exact isolated worker, or local integrity signer has not passed its current challenge.",
              category: "dependency_unavailable",
              remediation:
                "Review Research readiness and retry only after every local execution-boundary check passes.",
            },
          );
        }
        if (stage === "hidden_holdout" && !dependencies.privateHoldout) {
          throw new MissionApiError(
            503,
            "research_private_holdout_unavailable",
            "The trusted private hidden-holdout descriptor is not configured",
            {
              humanMessage:
                "This Research service has no hash-pinned operator-owned hidden-holdout descriptor.",
              category: "dependency_unavailable",
              remediation:
                "Configure the private holdout descriptor, then restart only the Research service.",
            },
          );
        }
        const body = bodyObject(request.body);
        if (
          Object.keys(body).length !== 1
          || !Object.hasOwn(body, "seed")
        ) {
          throw new MissionApiError(
            400,
            "research_stage_request_invalid",
            "Stage execution accepts only a seed; the server resolves the immutable scenario",
            {
              humanMessage:
                "Provide only the experiment seed. Ti-Scale selects the next immutable benchmark fixture locally.",
              category: "invalid_input",
            },
          );
        }
        const run = dependencies.experimentRunner.enqueueStage({
          experimentId,
          stage,
          seed: requiredString(body.seed, "Experiment seed", 160),
          actorId: executionActor.id,
          idempotencyKey: validateIdempotencyKey(
            request.get("Idempotency-Key"),
          ),
        });
        response.status(202).json({
          schemaVersion: "2.4",
          run: publicRunRecord(run, dependencies.privateHoldout),
        });
      } catch (error) { sendError(response, traceId, error); }
    },
  );
  router.get("/api/v2/research/experiments/:experimentId/runs/:runId", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const executionActor = actor(request, dependencies);
      const experimentId = requiredString(
        request.params.experimentId,
        "Experiment ID",
        255,
      );
      const runId = requiredString(
        request.params.runId,
        "Experiment run ID",
        255,
      );
      if (
        dependencies.authorizeExecution
        && !dependencies.authorizeExecution(
          request,
          executionActor,
          { action: "read", experimentId, runId },
        )
      ) {
        throw new MissionApiError(
          403,
          "research_execution_forbidden",
          "Research run access is not authorized",
          {
            humanMessage: "Your current role cannot inspect this Research experiment run.",
            category: "authorization_denied",
          },
        );
      }
      if (!dependencies.experimentRunner) {
        throw new MissionApiError(
          503,
          "research_execution_not_ready",
          "Research execution is not configured",
          {
            humanMessage: "The local Research execution boundary is not configured.",
            category: "dependency_unavailable",
          },
        );
      }
      const run = dependencies.experimentRunner.read(runId);
      if (run.experimentId !== experimentId) {
        throw new MissionApiError(
          404,
          "research_experiment_run_not_found",
          "The requested Research experiment run does not exist",
          {
            humanMessage: "That run does not belong to the requested experiment.",
            category: "not_found",
          },
        );
      }
      response.json({
        schemaVersion: "2.4",
        run: publicRunRecord(run, dependencies.privateHoldout),
      });
    } catch (error) { sendError(response, traceId, error); }
  });
  router.post("/api/v2/research/experiments/:experimentId/runs/:runId/cancel", async (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const executionActor = actor(request, dependencies);
      const experimentId = requiredString(
        request.params.experimentId,
        "Experiment ID",
        255,
      );
      const runId = requiredString(
        request.params.runId,
        "Experiment run ID",
        255,
      );
      if (
        dependencies.authorizeExecution
        && !dependencies.authorizeExecution(
          request,
          executionActor,
          { action: "cancel", experimentId, runId },
        )
      ) {
        throw new MissionApiError(
          403,
          "research_execution_forbidden",
          "Research cancellation requires the human campaign owner",
          {
            humanMessage: "Only the named campaign owner may cancel this bounded run.",
            category: "authorization_denied",
          },
        );
      }
      if (!dependencies.experimentRunner) {
        throw new MissionApiError(
          503,
          "research_execution_not_ready",
          "Research execution is not configured",
          {
            humanMessage: "The local Research execution boundary is not configured.",
            category: "dependency_unavailable",
          },
        );
      }
      const body = bodyObject(request.body);
      const run = dependencies.experimentRunner.read(runId);
      if (run.experimentId !== experimentId) {
        throw new MissionApiError(
          404,
          "research_experiment_run_not_found",
          "The requested Research experiment run does not exist",
          {
            humanMessage: "That run does not belong to the requested experiment.",
            category: "not_found",
          },
        );
      }
      response.json({
        schemaVersion: "2.4",
        run: publicRunRecord(
          await dependencies.experimentRunner.cancel({
            runId,
            actorId: executionActor.id,
            reason: requiredString(
              body.reason,
              "Cancellation reason",
              1_000,
              true,
            ),
            idempotencyKey: validateIdempotencyKey(
              request.get("Idempotency-Key"),
            ),
          }),
          dependencies.privateHoldout,
        ),
      });
    } catch (error) { sendError(response, traceId, error); }
  });
  router.post("/api/v2/research/experiments/:experimentId/promotion", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const body = bodyObject(request.body);
      const canary = body.canaryBounds === undefined
        ? undefined
        : bodyObject(body.canaryBounds);
      const experimentId = requiredString(
          request.params.experimentId,
          "Experiment ID",
          255,
        );
      const action = humanPromotionAction(body.action);
      const promotionActor = actor(request, dependencies);
      if (!dependencies.authorizePromotion(
        request,
        promotionActor,
        { experimentId, action },
      )) {
        throw new MissionApiError(
          403,
          "research_promotion_forbidden",
          "Research promotion requires an authorized human reviewer",
          {
            humanMessage: "Your current role cannot approve, reject, verify, or roll back this strategy.",
            category: "authorization_denied",
            remediation: "Sign in as the configured campaign reviewer or administrator.",
          },
        );
      }
      response.json(promotions.applyHumanTransition({
        experimentId,
        expectedVersion: positiveInteger(
          body.expectedVersion,
          "Expected lifecycle version",
        ),
        action,
        actorId: promotionActor.id,
        rationale: requiredString(
          body.rationale,
          "Promotion rationale",
          4_000,
          true,
        ),
        evidenceRefs: requiredStringArray(body.evidenceRefs, "Promotion evidence"),
        ...(typeof body.targetStrategyVersionId === "string"
          ? {
              targetStrategyVersionId: requiredString(
                body.targetStrategyVersionId,
                "Rollback target strategy",
                255,
              ),
            }
          : {}),
        ...(canary
          ? {
              canaryBounds: {
                maxMissions: positiveInteger(
                  canary.maxMissions,
                  "Canary mission limit",
                ),
                maxWallClockMs: positiveInteger(
                  canary.maxWallClockMs,
                  "Canary time limit",
                ),
              },
            }
          : {}),
        idempotencyKey: validateIdempotencyKey(
          request.get("Idempotency-Key"),
        ),
      }));
    } catch (error) { sendError(response, traceId, error); }
  });
  return router;
}

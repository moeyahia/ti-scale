import { Router, type Request, type Response } from "express";
import type { SqliteDatabase } from "../db";
import {
  MISSION_TEMPLATE_IDS,
  emptyRuntimeSourceManifests,
  type MissionTemplateId,
  type RuntimeSourceManifests,
} from "../domain";
import {
  MissionIntakeService,
  MissionIntakeValidationError,
  validateMissionIntakeRequest,
} from "../intake";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import {
  BrainContextHookError,
  BrainContextService,
  CanonicalMissionMemoryGraph,
} from "../brain-runtime";
import { MemoryRepository, SecondBrainService } from "../memory";
import {
  ControlPlaneLeaseError,
  RunMutationAuthorityGuard,
  describeRunMutationAuthorityError,
  type AssertRunMutationLease,
  type AuthorizedRunMutation,
} from "../control-plane";
import {
  MissionApiError,
  AutonomousBranchService,
  MissionPortfolioService,
  MISSION_PORTFOLIO_LIMITS,
  MissionRepository,
  MissionService,
  OverviewRepository,
  ReadinessService,
  validateIdempotencyKey,
  validateMissionCreateRequest,
  validateMissionPreflightRequest,
  type Journey,
  type MissionPortfolioFilterState,
  type ReadinessCheckProvider,
} from "../missions";
import type { ModelConfigurationService } from "../model-config";

export interface CommandOsRouterDependencies {
  readonly database: SqliteDatabase;
  readonly readinessProviders: readonly ReadinessCheckProvider[];
  readonly resolveActor: (request: Request) => string;
  /** Shared canonical Brain boundary used by intake and active runtimes. */
  readonly brainContext?: BrainContextService;
  /** Shared application clock for deterministic freshness and intake tests. */
  readonly clock?: () => Date;
  readonly readRuntimeManifests?: () => RuntimeSourceManifests;
  /** Scoped model preferences and immutable run/step assignment resolver. */
  readonly modelConfigurations?: ModelConfigurationService;
  /** Optional post-commit projection into configured human-readable stores. */
  readonly projectMemoryNodes?: (nodeIds: readonly string[]) => void;
  /** Trusted runtime callback; HTTP callers never submit raw lease tokens. */
  readonly assertRunMutationLease?: AssertRunMutationLease;
}

function sendError(response: Response, error: unknown, requestTraceId: string): void {
  if (error instanceof ControlPlaneLeaseError) {
    const descriptor = describeRunMutationAuthorityError(error);
    sendV2Error(response, requestTraceId, {
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
  if (error instanceof MissionIntakeValidationError) {
    sendV2Error(response, requestTraceId, {
      status: 400,
      code: "invalid_mission_intake",
      message: "Mission intake could not be normalized",
      humanMessage: error.issues[0] ?? "Review the mission intake and correct the highlighted values.",
      retryable: false,
      category: "invalid_input",
      details: { issues: [...error.issues] },
      remediation: "Correct the listed values. Only authorization acknowledgement and one target are required when recommended defaults are used.",
    });
    return;
  }
  if (error instanceof BrainContextHookError) {
    sendV2Error(response, requestTraceId, {
      status: error.code === "brain_context_unavailable" ? 503 : 500,
      code: error.code,
      message: error.message,
      humanMessage: error.code === "brain_context_unavailable"
        ? "The signed mission requires Second Brain context, so launch stopped safely before a run was committed."
        : "Mission intake could not establish a durable, auditable Second Brain Context Pack, so launch did not continue.",
      retryable: error.code === "brain_context_unavailable",
      category: "dependency_missing",
      details: { hook: error.hook, auditRecordId: error.auditRecordId ?? null },
      remediation: "Restore the local Second Brain dependency or remove required memory from a newly reviewed contract; do not bypass the signed memory policy.",
    });
    return;
  }
  const known = error instanceof MissionApiError;
  sendV2Error(response, requestTraceId, known
    ? {
        status: error.status,
        code: error.code,
        message: error.message,
        humanMessage: error.options.humanMessage ?? error.message,
        retryable: error.options.retryable ?? false,
        category: error.options.category ?? "mission",
        ...(error.options.details === undefined ? {} : { details: error.options.details }),
        ...(error.options.remediation ? { remediation: error.options.remediation } : {}),
      }
    : {
        status: 500,
        code: "ti_scale_internal_error",
        message: "Ti-Scale could not complete the request",
        humanMessage: "The mission service encountered an internal error.",
        retryable: false,
        category: "internal",
        remediation: "Use the trace ID to inspect structured server logs before retrying.",
      });
}

function boundedLimit(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 100) {
    throw new MissionApiError(400, "invalid_pagination", "Invalid mission page limit", {
      humanMessage: "Mission page size must be an integer between 1 and 100.",
      category: "invalid_input",
      remediation: "Use a limit from 1 through 100.",
    });
  }
  return parsed;
}

function journeyFilter(value: unknown): Journey | undefined {
  if (value === undefined) return undefined;
  if (value === "autonomous" || value === "guided") return value;
  throw new MissionApiError(400, "invalid_journey_filter", "Invalid journey filter", {
    humanMessage: "Journey must be Autonomous or Guided.",
    category: "invalid_input",
  });
}

function optionalFilter(value: unknown, label: string, maximum: number): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") {
    throw new MissionApiError(400, "invalid_portfolio_filter", `${label} filter is invalid`, {
      humanMessage: `${label} must be a text value.`,
      category: "invalid_input",
    });
  }
  const result = value.trim();
  if (!result || result.length > maximum || /[\u0000-\u001f\u007f]/u.test(result)) {
    throw new MissionApiError(400, "invalid_portfolio_filter", `${label} filter is invalid`, {
      humanMessage: `${label} is empty, too long, or contains control characters.`,
      category: "invalid_input",
    });
  }
  return result;
}

function choiceFilter<const T extends string>(
  value: unknown,
  label: string,
  choices: readonly T[],
): T | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value === "string" && choices.includes(value as T)) return value as T;
  throw new MissionApiError(400, "invalid_portfolio_filter", `${label} filter is invalid`, {
    humanMessage: `${label} must be one of: ${choices.join(", ")}.`,
    category: "invalid_input",
  });
}

function normalizedDateFilter(value: unknown, label: string, endOfDay = false): string | undefined {
  const source = optionalFilter(value, label, 40);
  if (!source) return undefined;
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/u.test(source);
  const candidate = dateOnly
    ? `${source}T${endOfDay ? "23:59:59.999" : "00:00:00.000"}Z`
    : source;
  const parsed = Date.parse(candidate);
  if (!Number.isFinite(parsed)) {
    throw new MissionApiError(400, "invalid_portfolio_date", `${label} filter is invalid`, {
      humanMessage: `${label} must be an ISO-8601 date or timestamp.`,
      category: "invalid_input",
    });
  }
  return new Date(parsed).toISOString();
}

function nonNegativeVersion(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new MissionApiError(400, "invalid_version", `${label} is invalid`, {
      humanMessage: `${label} must be a non-negative integer.`,
      category: "invalid_input",
    });
  }
  return Number(value);
}

function portfolioState(value: unknown): MissionPortfolioFilterState {
  const state = bodyObject(value);
  const journey = state.journey === "autonomous" || state.journey === "guided" ? state.journey : "";
  const evidence = choiceFilter(state.evidence, "Evidence", ["present", "none"] as const) ?? "";
  const recoveryState = choiceFilter(
    state.recoveryState, "Recovery state", ["recovering", "blocked", "none"] as const,
  ) ?? "";
  const updatedFrom = optionalFilter(state.updatedFrom, "Updated from", 40) ?? "";
  const updatedTo = optionalFilter(state.updatedTo, "Updated to", 40) ?? "";
  if (updatedFrom && !Number.isFinite(Date.parse(updatedFrom))) {
    throw new MissionApiError(400, "invalid_saved_view", "Saved view start date is invalid", {
      humanMessage: "The saved view start date must be ISO-8601.", category: "invalid_input",
    });
  }
  if (updatedTo && !Number.isFinite(Date.parse(updatedTo))) {
    throw new MissionApiError(400, "invalid_saved_view", "Saved view end date is invalid", {
      humanMessage: "The saved view end date must be ISO-8601.", category: "invalid_input",
    });
  }
  return {
    query: optionalFilter(state.query, "Search", 300) ?? "",
    journey,
    status: optionalFilter(state.status, "Status", 80) ?? "",
    engagement: optionalFilter(state.engagement, "Engagement", 240) ?? "",
    target: optionalFilter(state.target, "Target", 300) ?? "",
    agent: optionalFilter(state.agent, "Agent", 200) ?? "",
    provider: optionalFilter(state.provider, "Provider", 200) ?? "",
    updatedFrom,
    updatedTo,
    risk: optionalFilter(state.risk, "Risk", 80) ?? "",
    evidence,
    findingSeverity: choiceFilter(
      state.findingSeverity, "Finding severity", ["informational", "low", "medium", "high", "critical"] as const,
    ) ?? "",
    decisionState: choiceFilter(
      state.decisionState, "Decision state",
      ["pending", "approved", "manual", "alternative", "rejected", "expired", "cancelled"] as const,
    ) ?? "",
    recoveryState,
    view: state.view === "board" ? "board" : "table",
  };
}

function missionSelection(value: unknown): string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > MISSION_PORTFOLIO_LIMITS.bulkMissions) {
    throw new MissionApiError(400, "invalid_mission_selection", "Mission selection is invalid", {
      humanMessage: `Select between 1 and ${MISSION_PORTFOLIO_LIMITS.bulkMissions} missions.`,
      category: "invalid_input",
    });
  }
  const ids = value.map((candidate) => stableId(candidate, "Mission ID"));
  if (new Set(ids).size !== ids.length) {
    throw new MissionApiError(400, "duplicate_mission_selection", "Mission selection contains duplicates", {
      humanMessage: "Each mission may appear only once in a bulk operation.",
      category: "invalid_input",
    });
  }
  return ids;
}

function bodyObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new MissionApiError(400, "invalid_request", "Request body must be an object", {
      humanMessage: "The request body must be a JSON object.",
      category: "invalid_input",
    });
  }
  return value as Record<string, unknown>;
}

function stableId(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(value)) {
    throw new MissionApiError(400, "invalid_identifier", `${label} is invalid`, {
      humanMessage: `${label} is missing or malformed.`,
      category: "invalid_input",
    });
  }
  return value;
}

function positiveVersion(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw new MissionApiError(400, "invalid_version", `${label} is invalid`, {
      humanMessage: `${label} must be a positive integer.`,
      category: "invalid_input",
    });
  }
  return Number(value);
}

function branchMode(value: unknown): "unchanged_contract" | "contract_amendment" {
  if (value === "unchanged_contract" || value === "contract_amendment") return value;
  throw new MissionApiError(400, "invalid_branch_mode", "Autonomous branch mode is invalid", {
    humanMessage: "Choose either the unchanged signed contract or a versioned contract amendment.",
    category: "invalid_input",
  });
}

function authenticatedActor(request: Request, dependencies: CommandOsRouterDependencies): string {
  const actorId = dependencies.resolveActor(request).trim();
  if (!actorId) {
    throw new MissionApiError(401, "operator_identity_required", "Operator identity is required", {
      humanMessage: "An authenticated operator identity is required for this Autonomous contract decision.",
      category: "authentication_missing",
      remediation: "Sign in again and retry the operation.",
    });
  }
  return actorId;
}

/**
 * Mount with `app.use(createCommandOsRouter(deps))`. The factory deliberately
 * requires concrete readiness providers and an authenticated actor resolver.
 */
export function createCommandOsRouter(
  dependencies: CommandOsRouterDependencies,
): Router {
  const readiness = new ReadinessService(dependencies.readinessProviders);
  const missions = new MissionRepository(dependencies.database, dependencies.clock);
  const service = new MissionService(
    missions,
    new OverviewRepository(dependencies.database),
    readiness,
    dependencies.brainContext ?? new BrainContextService({
      database: dependencies.database,
      secondBrain: new SecondBrainService(new MemoryRepository(dependencies.database)),
    }),
    dependencies.readRuntimeManifests ?? emptyRuntimeSourceManifests,
    new CanonicalMissionMemoryGraph(dependencies.database),
    dependencies.projectMemoryNodes,
    dependencies.modelConfigurations,
  );
  const branches = new AutonomousBranchService(
    dependencies.database,
    service,
    dependencies.clock ?? (() => new Date()),
    dependencies.modelConfigurations,
  );
  const portfolio = new MissionPortfolioService(dependencies.database);
  const mutationAuthority = new RunMutationAuthorityGuard(dependencies.database);
  const intake = new MissionIntakeService({
    readRuntimeManifests: dependencies.readRuntimeManifests ?? emptyRuntimeSourceManifests,
    ...(dependencies.modelConfigurations
      ? { modelConfigurations: dependencies.modelConfigurations }
      : {}),
    ...(dependencies.clock ? { clock: dependencies.clock } : {}),
  });
  const router = Router();

  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  router.get("/api/v2/overview", async (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      response.json(await service.getOverview());
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.get("/api/v2/registries/intake", (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      authenticatedActor(request, dependencies);
      const journey = request.query.journey === "guided" ? "guided" : "autonomous";
      const templateCandidate = typeof request.query.templateId === "string"
        ? request.query.templateId
        : "safe_recon";
      if (!MISSION_TEMPLATE_IDS.includes(templateCandidate as MissionTemplateId)) {
        throw new MissionIntakeValidationError([`Unknown mission template: ${templateCandidate}.`]);
      }
      response.json(intake.snapshot(journey, templateCandidate as MissionTemplateId));
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.post("/api/v2/registries/intake/resolve", (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      authenticatedActor(request, dependencies);
      response.json(intake.resolve(validateMissionIntakeRequest(request.body)));
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.get("/api/v2/missions", (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      const cursor = typeof request.query.cursor === "string" ? request.query.cursor : undefined;
      const status = typeof request.query.status === "string" && request.query.status.trim()
        ? request.query.status.trim()
        : undefined;
      const query = typeof request.query.query === "string" && request.query.query.trim()
        ? request.query.query.trim()
        : undefined;
      if (status && status.length > 80) {
        throw new MissionApiError(400, "invalid_status_filter", "Invalid status filter", {
          humanMessage: "The mission status filter is too long.",
          category: "invalid_input",
        });
      }
      if (query && query.length > 300) {
        throw new MissionApiError(400, "invalid_mission_search", "Invalid mission search", {
          humanMessage: "Mission search must be at most 300 characters.",
          category: "invalid_input",
        });
      }
      const updatedFrom = normalizedDateFilter(request.query.updatedFrom, "Updated from");
      const updatedTo = normalizedDateFilter(request.query.updatedTo, "Updated to", true);
      if (updatedFrom && updatedTo && updatedFrom > updatedTo) {
        throw new MissionApiError(400, "invalid_portfolio_date_range", "Mission date range is invalid", {
          humanMessage: "Updated from must be earlier than or equal to updated to.",
          category: "invalid_input",
        });
      }
      response.json(
        service.list({
          cursor,
          limit: boundedLimit(request.query.limit),
          journey: journeyFilter(request.query.journey),
          status,
          query,
          engagement: optionalFilter(request.query.engagement, "Engagement", 240),
          target: optionalFilter(request.query.target, "Target", 300),
          agent: optionalFilter(request.query.agent, "Agent", 200),
          provider: optionalFilter(request.query.provider, "Provider", 200),
          updatedFrom,
          updatedTo,
          risk: optionalFilter(request.query.risk, "Risk", 80),
          evidence: choiceFilter(request.query.evidence, "Evidence", ["present", "none"] as const),
          findingSeverity: choiceFilter(
            request.query.findingSeverity, "Finding severity",
            ["informational", "low", "medium", "high", "critical"] as const,
          ),
          decisionState: choiceFilter(
            request.query.decisionState, "Decision state",
            ["pending", "approved", "manual", "alternative", "rejected", "expired", "cancelled"] as const,
          ),
          recoveryState: choiceFilter(
            request.query.recoveryState, "Recovery state", ["recovering", "blocked", "none"] as const,
          ),
        }),
      );
    } catch (error) {
      const normalized = error instanceof RangeError
        ? new MissionApiError(400, "invalid_cursor", error.message, {
            humanMessage: "The mission cursor is invalid or expired.",
            category: "invalid_input",
            remediation: "Restart pagination without a cursor.",
          })
        : error;
      sendError(response, normalized, requestTraceId);
    }
  });

  router.get("/api/v2/missions/saved-views", (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      response.json(portfolio.listSavedViews(authenticatedActor(request, dependencies)));
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.post("/api/v2/missions/saved-views", (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      const actorId = authenticatedActor(request, dependencies);
      const body = bodyObject(request.body);
      const name = optionalFilter(body.name, "Saved view name", 80);
      if (!name) {
        throw new MissionApiError(400, "invalid_saved_view_name", "Saved view name is required", {
          humanMessage: "Enter a name for this mission view.", category: "invalid_input",
        });
      }
      response.json(portfolio.saveView({
        actorId,
        idempotencyKey: validateIdempotencyKey(request.get("Idempotency-Key")),
        expectedVersion: nonNegativeVersion(body.expectedVersion, "Saved view version"),
        name,
        state: portfolioState(body.state),
      }));
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.delete("/api/v2/missions/saved-views/:viewId", (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      const actorId = authenticatedActor(request, dependencies);
      const body = bodyObject(request.body);
      response.json(portfolio.deleteView({
        actorId,
        idempotencyKey: validateIdempotencyKey(request.get("Idempotency-Key")),
        expectedVersion: nonNegativeVersion(body.expectedVersion, "Saved view version"),
        viewId: stableId(request.params.viewId, "Saved view ID"),
      }));
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.post("/api/v2/missions/bulk/archive", (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      const actorId = authenticatedActor(request, dependencies);
      const body = bodyObject(request.body);
      if (body.confirm !== true) {
        throw new MissionApiError(400, "bulk_confirmation_required", "Bulk archive requires confirmation", {
          humanMessage: "Explicitly confirm the exact mission selection before archiving.",
          category: "invalid_input",
        });
      }
      const missionIds = missionSelection(body.missionIds);
      const mutationAuthorities = portfolio.archiveAuthorityScopes(missionIds).map((scope) => {
        const authority = authorizeMissionMutation(
          mutationAuthority,
          dependencies,
          scope.missionId,
          scope.runId,
          actorId,
        );
        return { ...scope, assertCurrent: authority.assertCurrent };
      });
      response.json(portfolio.archive({
        actorId,
        idempotencyKey: validateIdempotencyKey(request.get("Idempotency-Key")),
        missionIds,
        mutationAuthorities,
      }));
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.post("/api/v2/missions/bulk/export", (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      const actorId = authenticatedActor(request, dependencies);
      const body = bodyObject(request.body);
      if (body.confirm !== true) {
        throw new MissionApiError(400, "bulk_confirmation_required", "Bulk export requires confirmation", {
          humanMessage: "Explicitly confirm the exact mission selection before exporting metadata.",
          category: "invalid_input",
        });
      }
      response.json(portfolio.exportMetadata({
        actorId,
        idempotencyKey: validateIdempotencyKey(request.get("Idempotency-Key")),
        missionIds: missionSelection(body.missionIds),
      }));
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.post("/api/v2/missions/autonomous/preflight", async (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      const actorId = dependencies.resolveActor(request).trim();
      if (!actorId) {
        throw new MissionApiError(401, "operator_identity_required", "Operator identity is required", {
          humanMessage: "An authenticated operator identity is required to review an Autonomous contract.",
          category: "authentication_missing",
          remediation: "Sign in again and rerun contract preflight.",
        });
      }
      const missionRequest = validateMissionPreflightRequest(request.body);
      if (missionRequest.journey !== "autonomous") {
        throw new MissionApiError(400, "autonomous_contract_required", "Autonomous contract required", {
          humanMessage: "This preflight endpoint accepts Autonomous contracts only.",
          category: "invalid_input",
        });
      }
      response.json(await service.preflightAutonomous(missionRequest));
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.get("/api/v2/missions/:missionId/autonomous-branches/context", (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      authenticatedActor(request, dependencies);
      const missionId = stableId(request.params.missionId, "Mission ID");
      const sourceRunId = stableId(request.query.sourceRunId, "Source run ID");
      response.json(branches.context(missionId, sourceRunId));
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.post("/api/v2/missions/:missionId/autonomous-branches/preflight", async (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      const actorId = authenticatedActor(request, dependencies);
      const body = bodyObject(request.body);
      const mode = branchMode(body.mode);
      let amendmentRequest;
      if (mode === "contract_amendment") {
        amendmentRequest = validateMissionCreateRequest(body.request);
        if (amendmentRequest.journey !== "autonomous") {
          throw new MissionApiError(400, "autonomous_contract_required", "Autonomous contract required", {
            humanMessage: "A contract amendment must remain an Autonomous contract.",
            category: "invalid_input",
          });
        }
      }
      const result = await branches.preflight(
        stableId(request.params.missionId, "Mission ID"),
        {
          sourceRunId: stableId(body.sourceRunId, "Source run ID"),
          sourceRunVersion: positiveVersion(body.sourceRunVersion, "Source run version"),
          mode,
          reason: typeof body.reason === "string" ? body.reason : "",
          ...(amendmentRequest?.journey === "autonomous" ? { request: amendmentRequest } : {}),
        },
        validateIdempotencyKey(request.get("Idempotency-Key")),
        actorId,
        authorizeMissionMutation(
          mutationAuthority,
          dependencies,
          stableId(request.params.missionId, "Mission ID"),
          stableId(body.sourceRunId, "Source run ID"),
          actorId,
        ).assertCurrent,
      );
      response.status(result.contract.state === "draft" ? 201 : 200).json(result);
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.post("/api/v2/missions/:missionId/autonomous-branches", async (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      const actorId = authenticatedActor(request, dependencies);
      const body = bodyObject(request.body);
      const review = body.review && typeof body.review === "object" && !Array.isArray(body.review)
        ? body.review as Record<string, unknown>
        : {};
      const hash = typeof review.hash === "string" ? review.hash : "";
      if (!/^[a-f0-9]{64}$/u.test(hash)) {
        throw new MissionApiError(400, "invalid_contract_hash", "Contract review hash is invalid", {
          humanMessage: "Review and submit the exact server-issued SHA-256 contract digest.",
          category: "invalid_input",
        });
      }
      const result = await branches.createBranch(
        stableId(request.params.missionId, "Mission ID"),
        {
          sourceRunId: stableId(body.sourceRunId, "Source run ID"),
          sourceRunVersion: positiveVersion(body.sourceRunVersion, "Source run version"),
          mode: branchMode(body.mode),
          reason: typeof body.reason === "string" ? body.reason : "",
          ...(body.draftContractId === undefined
            ? {}
            : { draftContractId: stableId(body.draftContractId, "Draft contract ID") }),
          review: { version: positiveVersion(review.version, "Contract review version"), hash },
        },
        validateIdempotencyKey(request.get("Idempotency-Key")),
        actorId,
        authorizeMissionMutation(
          mutationAuthority,
          dependencies,
          stableId(request.params.missionId, "Mission ID"),
          stableId(body.sourceRunId, "Source run ID"),
          actorId,
        ).assertCurrent,
      );
      response.status(201).setHeader("Location", result.nextUrl).json(result);
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.post("/api/v2/missions", async (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      const actorId = dependencies.resolveActor(request).trim();
      if (!actorId) {
        throw new MissionApiError(401, "operator_identity_required", "Operator identity is required", {
          humanMessage: "An authenticated operator identity is required to create a mission.",
          category: "authentication_missing",
          remediation: "Sign in again and retry the mission submission.",
        });
      }
      const idempotencyKey = validateIdempotencyKey(request.get("Idempotency-Key"));
      const missionRequest = validateMissionCreateRequest(request.body);
      const created = await service.create(missionRequest, idempotencyKey, actorId);
      response.status(201).setHeader("Location", created.nextUrl).json(created);
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  return router;
}

function authorizeMissionMutation(
  guard: RunMutationAuthorityGuard,
  dependencies: CommandOsRouterDependencies,
  missionId: string,
  runId: string,
  actorId: string,
): AuthorizedRunMutation {
  const authority = guard.authorize({
    runId,
    actorId,
    mode: "lease",
    ...(dependencies.assertRunMutationLease
      ? { assertLease: dependencies.assertRunMutationLease }
      : {}),
  });
  if (authority.scope.missionId !== missionId) {
    throw new MissionApiError(404, "mission_run_scope_not_found", "Run does not belong to this mission", {
      humanMessage: "The selected run is unavailable or no longer belongs to this mission.",
      category: "not_found",
      remediation: "Refresh the mission and use its current canonical run link.",
    });
  }
  return authority;
}

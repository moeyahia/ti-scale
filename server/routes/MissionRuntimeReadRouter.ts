import { Router, type Request, type Response } from "express";
import {
  RuntimeRepository,
  type RuntimeRunProjection,
} from "../command-runtime/RuntimeRepository";
import { CommandRuntimeError } from "../command-runtime/types";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import type { CheckpointRepository } from "../orchestration";
import type { RunState } from "../supervisor";

const SCHEMA_VERSION = "2.4" as const;
const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,239}$/u;
const ACTOR_ID = /^[^\u0000-\u001F\u007F]{1,256}$/u;
const RUN_STATES = new Set<RunState>([
  "queued",
  "planning",
  "awaiting_contract_confirmation",
  "running",
  "waiting_guided_decision",
  "blocked",
  "recovering",
  "completed",
  "failed",
  "cancelled",
]);
const DECISION_STATES = new Set([
  "pending",
  "approved",
  "manual",
  "alternative",
  "rejected",
  "expired",
  "cancelled",
]);

export interface RuntimeReadRunScope {
  readonly missionId: string;
  readonly runId: string;
}

export interface MissionRuntimeReadRouterDependencies {
  readonly repository: RuntimeRepository;
  readonly checkpoints: Pick<CheckpointRepository, "latest">;
  readonly resolveActor: (request: Request) => string | undefined;
  readonly authorizeMission: (
    request: Request,
    actorId: string,
    missionId: string,
  ) => boolean;
  readonly authorizeRun: (
    request: Request,
    actorId: string,
    scope: RuntimeReadRunScope,
  ) => boolean;
}

class RuntimeReadHttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly category: string,
    readonly remediation?: string,
  ) {
    super(message);
    this.name = "RuntimeReadHttpError";
  }
}

function authenticationRequired(): RuntimeReadHttpError {
  return new RuntimeReadHttpError(
    401,
    "runtime_read_authentication_required",
    "Sign in before reading mission runtime state.",
    "authentication_missing",
    "Authenticate with the isolated Ti-Scale session and retry.",
  );
}

function policyDenied(): RuntimeReadHttpError {
  return new RuntimeReadHttpError(
    403,
    "runtime_read_policy_denied",
    "This identity cannot read the requested mission runtime state.",
    "policy_denied",
    "Use an identity with explicit access to this mission and run.",
  );
}

function invalidInput(code: string, message: string): RuntimeReadHttpError {
  return new RuntimeReadHttpError(
    400,
    code,
    message,
    "invalid_input",
    "Correct the request using the published runtime-read filters and canonical IDs.",
  );
}

function authorizationWindowExhausted(): RuntimeReadHttpError {
  return new RuntimeReadHttpError(
    409,
    "runtime_read_authorization_window_exhausted",
    "The bounded runtime read window contains mixed authorization scopes.",
    "scope_conflict",
    "Narrow the search, journey, status, or run filter so the authorized result fits in one bounded read window.",
  );
}

function actorId(dependencies: MissionRuntimeReadRouterDependencies, request: Request): string {
  const resolved = dependencies.resolveActor(request);
  const normalized = typeof resolved === "string" ? resolved.trim().normalize("NFKC") : "";
  if (!ACTOR_ID.test(normalized)) throw authenticationRequired();
  return normalized;
}

function pathId(value: unknown, field: string): string {
  if (typeof value !== "string") throw invalidInput("invalid_resource_id", `${field} is invalid.`);
  const normalized = value.trim().normalize("NFKC");
  if (!RESOURCE_ID.test(normalized)) throw invalidInput("invalid_resource_id", `${field} is invalid.`);
  return normalized;
}

function onlyQueryKeys(request: Request, allowed: ReadonlySet<string>): void {
  const unsupported = Object.keys(request.query).filter((key) => !allowed.has(key));
  if (unsupported.length > 0) {
    throw invalidInput("unsupported_runtime_filter", `Unsupported runtime filter: ${unsupported[0]}.`);
  }
}

function optionalQueryText(value: unknown, field: string, maximum = 300): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw invalidInput(`invalid_${field}`, `${field} must be supplied once.`);
  const normalized = value.trim().normalize("NFKC");
  if (
    !normalized
    || normalized.length > maximum
    || /[\u0000-\u001F\u007F]/u.test(normalized)
  ) throw invalidInput(`invalid_${field}`, `${field} is invalid.`);
  return normalized;
}

function boundedLimit(value: unknown, fallback: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || !/^(?:[1-9]|[1-9][0-9]|100)$/u.test(value)) {
    throw invalidInput("invalid_pagination", "limit must be an integer from 1 through 100.");
  }
  return Number(value);
}

function journeyFilter(value: unknown): "autonomous" | "guided" | undefined {
  const normalized = optionalQueryText(value, "journey", 10);
  if (normalized === undefined) return undefined;
  if (normalized !== "autonomous" && normalized !== "guided") {
    throw invalidInput("invalid_journey_filter", "journey must be autonomous or guided.");
  }
  return normalized;
}

function runStateFilter(value: unknown): RunState | undefined {
  const normalized = optionalQueryText(value, "run_status", 40);
  if (normalized === undefined) return undefined;
  if (!RUN_STATES.has(normalized as RunState)) {
    throw invalidInput("invalid_run_status", "status is not a canonical run state.");
  }
  return normalized as RunState;
}

function decisionStateFilter(value: unknown): string | undefined {
  const normalized = optionalQueryText(value, "decision_status", 40);
  if (normalized === undefined) return undefined;
  if (!DECISION_STATES.has(normalized)) {
    throw invalidInput("invalid_decision_status", "status is not a canonical Guided decision state.");
  }
  return normalized;
}

function sendError(response: Response, traceId: string, error: unknown): void {
  if (error instanceof RuntimeReadHttpError) {
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
  if (error instanceof CommandRuntimeError) {
    sendV2Error(response, traceId, {
      status: error.status,
      code: error.code,
      message: error.message,
      humanMessage: error.options.humanMessage ?? error.message,
      retryable: error.options.retryable ?? false,
      category: error.options.category ?? (error.status === 404 ? "not_found" : "runtime"),
      ...(error.options.details === undefined ? {} : { details: error.options.details }),
      ...(error.options.remediation ? { remediation: error.options.remediation } : {}),
    });
    return;
  }
  sendV2Error(response, traceId, {
    status: 500,
    code: "runtime_read_internal_error",
    message: "Mission runtime state could not be read",
    humanMessage: "The read-only mission runtime projection encountered an internal error.",
    retryable: false,
    category: "internal",
    remediation: "Use the request ID to inspect redacted server diagnostics before retrying.",
  });
}

function canReadMission(
  dependencies: MissionRuntimeReadRouterDependencies,
  request: Request,
  actor: string,
  missionId: string,
): boolean {
  return dependencies.authorizeMission(request, actor, missionId);
}

function canReadRun(
  dependencies: MissionRuntimeReadRouterDependencies,
  request: Request,
  actor: string,
  run: RuntimeReadRunScope,
  missionAlreadyAuthorized = false,
): boolean {
  return (missionAlreadyAuthorized || canReadMission(dependencies, request, actor, run.missionId))
    && dependencies.authorizeRun(request, actor, run);
}

function assertMissionAuthorized(
  dependencies: MissionRuntimeReadRouterDependencies,
  request: Request,
  actor: string,
  missionId: string,
): void {
  if (!canReadMission(dependencies, request, actor, missionId)) throw policyDenied();
}

function assertRunAuthorized(
  dependencies: MissionRuntimeReadRouterDependencies,
  request: Request,
  actor: string,
  run: RuntimeReadRunScope,
): void {
  if (!canReadRun(dependencies, request, actor, run)) throw policyDenied();
}

function runScope(run: RuntimeRunProjection): RuntimeReadRunScope {
  return { missionId: run.missionId, runId: run.id };
}

function storedRunScope(
  dependencies: MissionRuntimeReadRouterDependencies,
  runId: string,
): RuntimeReadRunScope {
  const run = dependencies.repository.getPlanningRun(runId);
  return { missionId: run.missionId, runId: run.id };
}

/**
 * Authenticated read-only projection over durable mission runtime records.
 * It deliberately has no planner, execution port, supervisor, or mutation
 * routes. The V2 composition root decides when this boundary is mounted.
 */
export function createMissionRuntimeReadRouter(
  dependencies: MissionRuntimeReadRouterDependencies,
): Router {
  const router = Router();

  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  const read = (
    handler: (request: Request, response: Response, actor: string) => void,
  ) => (request: Request, response: Response): void => {
    const traceId = attachV2RequestId(request, response);
    try {
      handler(request, response, actorId(dependencies, request));
    } catch (error) {
      sendError(response, traceId, error);
    }
  };

  router.get("/api/v2/missions/:missionId/runtime", read((request, response, actor) => {
    onlyQueryKeys(request, new Set());
    const missionId = pathId(request.params.missionId, "missionId");
    // Resolve only the parent record before authorization; enumerate child
    // runs only after the mission boundary has admitted the request.
    dependencies.repository.getMission(missionId);
    assertMissionAuthorized(dependencies, request, actor, missionId);
    const snapshot = dependencies.repository.getMissionRuntime(missionId);
    response.json({
      schemaVersion: SCHEMA_VERSION,
      mission: snapshot.mission,
      runs: snapshot.runs.filter((run) => canReadRun(
        dependencies,
        request,
        actor,
        runScope(run),
        true,
      )),
    });
  }));

  router.get("/api/v2/runs", read((request, response, actor) => {
    onlyQueryKeys(request, new Set(["query", "journey", "status", "limit"]));
    const journey = journeyFilter(request.query.journey);
    const status = runStateFilter(request.query.status);
    const query = optionalQueryText(request.query.query, "run_search");
    const limit = boundedLimit(request.query.limit, 50);
    const candidates = dependencies.repository.listRunProjections({
      ...(journey ? { journey } : {}),
      ...(status ? { status } : {}),
      ...(query ? { query } : {}),
      limit: 100,
    });
    const permitted = candidates
      .filter((run) => canReadRun(dependencies, request, actor, runScope(run)));
    // RuntimeRepository deliberately bounds reads at 100. If an identity has
    // mixed scope and the requested page is not filled, never imply that this
    // truncated authorization window is complete. Single-operator preview
    // reads (the current deployment model) are unaffected.
    if (candidates.length === 100 && permitted.length < limit && permitted.length < candidates.length) {
      throw authorizationWindowExhausted();
    }
    response.json({
      schemaVersion: SCHEMA_VERSION,
      items: permitted.slice(0, limit),
    });
  }));

  router.get("/api/v2/runs/:runId", read((request, response, actor) => {
    onlyQueryKeys(request, new Set());
    const runId = pathId(request.params.runId, "runId");
    assertRunAuthorized(dependencies, request, actor, storedRunScope(dependencies, runId));
    const run = dependencies.repository.getRunProjection(runId);
    response.json({
      schemaVersion: SCHEMA_VERSION,
      run,
      latestCheckpoint: dependencies.checkpoints.latest(runId) ?? null,
    });
  }));

  router.get("/api/v2/runs/:runId/plans", read((request, response, actor) => {
    onlyQueryKeys(request, new Set());
    const runId = pathId(request.params.runId, "runId");
    assertRunAuthorized(dependencies, request, actor, storedRunScope(dependencies, runId));
    response.json({
      schemaVersion: SCHEMA_VERSION,
      items: dependencies.repository.listPlans(runId),
    });
  }));

  router.get("/api/v2/decisions", read((request, response, actor) => {
    onlyQueryKeys(request, new Set(["status", "runId", "query", "limit"]));
    const status = decisionStateFilter(request.query.status);
    const requestedRunId = request.query.runId === undefined
      ? undefined
      : pathId(request.query.runId, "runId");
    const query = optionalQueryText(request.query.query, "decision_search");
    const limit = boundedLimit(request.query.limit, 100);

    if (requestedRunId) {
      assertRunAuthorized(
        dependencies,
        request,
        actor,
        storedRunScope(dependencies, requestedRunId),
      );
      response.json({
        schemaVersion: SCHEMA_VERSION,
        items: dependencies.repository.listDecisions({
          ...(status ? { status } : {}),
          runId: requestedRunId,
          ...(query ? { query } : {}),
          limit,
        }),
      });
      return;
    }

    const authorization = new Map<string, boolean>();
    const candidates = dependencies.repository.listDecisions({
      ...(status ? { status } : {}),
      ...(query ? { query } : {}),
      limit: 100,
    });
    const permitted = candidates.filter((decision) => {
      const known = authorization.get(decision.runId);
      if (known !== undefined) return known;
      const run = dependencies.repository.getRunProjection(decision.runId);
      const permitted = canReadRun(dependencies, request, actor, runScope(run));
      authorization.set(decision.runId, permitted);
      return permitted;
    });
    if (candidates.length === 100 && permitted.length < limit && permitted.length < candidates.length) {
      throw authorizationWindowExhausted();
    }
    response.json({ schemaVersion: SCHEMA_VERSION, items: permitted.slice(0, limit) });
  }));

  const rejectWrite = (request: Request, response: Response): void => {
    const traceId = attachV2RequestId(request, response);
    response.setHeader("Allow", "GET");
    sendV2Error(response, traceId, {
      status: 405,
      code: "runtime_read_method_not_allowed",
      message: "This runtime projection is read-only",
      humanMessage: "This endpoint exposes durable runtime state but cannot change it.",
      retryable: false,
      category: "method_not_allowed",
      remediation: "Use a separately authorized mission-control endpoint for supported mutations.",
    });
  };
  router.all("/api/v2/missions/:missionId/runtime", rejectWrite);
  router.all("/api/v2/runs", rejectWrite);
  router.all("/api/v2/runs/:runId", rejectWrite);
  router.all("/api/v2/runs/:runId/plans", rejectWrite);
  router.all("/api/v2/decisions", rejectWrite);

  return router;
}

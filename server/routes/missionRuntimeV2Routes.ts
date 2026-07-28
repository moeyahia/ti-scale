import { Router, type Request, type RequestHandler, type Response } from "express";
import {
  CommandRuntimeError,
  type MissionRuntimeEngine,
  type ResumeRunBoundary,
} from "../command-runtime";
import { DurableOrchestrationError } from "../orchestration";
import {
  ControlPlaneLeaseError,
  describeRunMutationAuthorityError,
} from "../control-plane";
import type { JsonValue } from "../events";
import { canonicalJson, hashCanonical } from "../missions/canonical";
import { redactSensitiveText } from "../guided-commander/validation";
import { sanitizeJson } from "../operations/validation";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import { encodeRuntimeRunCursor, parseRuntimeRunQuery } from "./RuntimeRunQuery";

export interface MissionRuntimeV2RouterDependencies {
  readonly runtime: MissionRuntimeEngine;
  readonly resolveActor: (request: Request) => string;
}

function runtimeError(error: unknown): CommandRuntimeError {
  if (error instanceof CommandRuntimeError) return error;
  if (error instanceof ControlPlaneLeaseError) {
    const descriptor = describeRunMutationAuthorityError(error);
    const humanMessage = error.code === "control_plane_mismatch"
      ? "This mission and run are controlled elsewhere, so Ti-Scale made no changes."
      : error.code === "run_not_found"
        ? "This run is no longer available, so Ti-Scale made no changes."
        : error.code === "journey_unsupported"
          ? "This Ti-Scale runtime does not support the run's journey, so it made no changes."
          : "Ti-Scale could not prove current mutation authority for this run, so it made no changes.";
    return new CommandRuntimeError(
      descriptor.status,
      descriptor.code,
      error.message,
      {
        humanMessage,
        retryable: descriptor.retryable,
        category: descriptor.category,
        remediation: descriptor.remediation,
      },
    );
  }
  if (error instanceof DurableOrchestrationError) {
    const missing = error.code.endsWith("_not_found");
    return new CommandRuntimeError(missing ? 404 : 409, error.code, error.message, {
      humanMessage: error.message,
      category: missing ? "not_found" : "runtime",
    });
  }
  return new CommandRuntimeError(500, "command_runtime_internal_error", "Command runtime request failed", {
    humanMessage: "The runtime could not safely complete this request.",
    category: "internal",
    remediation: "Use the trace ID to inspect structured runtime events before retrying.",
  });
}

function sendError(response: Response, error: unknown, traceId: string): void {
  const known = runtimeError(error);
  sendV2Error(response, traceId, {
    status: known.status,
    code: known.code,
    message: known.message,
    humanMessage: known.options.humanMessage ?? known.message,
    retryable: known.options.retryable ?? false,
    category: known.options.category ?? "runtime",
    ...(known.options.details === undefined ? {} : { details: known.options.details }),
    ...(known.options.remediation ? { remediation: known.options.remediation } : {}),
  });
}

function actor(dependencies: MissionRuntimeV2RouterDependencies, request: Request): string {
  const value = dependencies.resolveActor(request).trim();
  if (!value) {
    throw new CommandRuntimeError(401, "operator_identity_required", "Operator identity is required", {
      humanMessage: "Sign in before making a mission control decision.",
      category: "authentication_missing",
    });
  }
  return value;
}

function idempotencyKey(request: Request): string {
  const value = request.get("Idempotency-Key")?.trim();
  if (!value || !/^[a-zA-Z0-9._:-]{8,200}$/u.test(value)) {
    throw new CommandRuntimeError(400, "idempotency_key_required", "A valid Idempotency-Key is required", {
      humanMessage: "This mutation requires a stable submission key so it cannot run twice.",
      category: "invalid_input",
    });
  }
  return value;
}

function pathId(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new CommandRuntimeError(400, "invalid_resource_id", `${label} is invalid`, {
      category: "invalid_input",
    });
  }
  const normalized = value.trim();
  if (!/^[a-zA-Z0-9._:-]{1,240}$/u.test(normalized)) {
    throw new CommandRuntimeError(400, "invalid_resource_id", `${label} is invalid`, {
      category: "invalid_input",
    });
  }
  return normalized;
}

function bodyObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new CommandRuntimeError(400, "invalid_request_body", "Request body must be an object", {
      category: "invalid_input",
    });
  }
  return value as Record<string, unknown>;
}

function optionalReason(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !value.trim() || value.trim().length > 2_000) {
    throw new CommandRuntimeError(400, "invalid_reason", "Reason must be a non-empty string up to 2,000 characters", {
      category: "invalid_input",
    });
  }
  const normalized = value.trim().normalize("NFKC");
  if (redactSensitiveText(normalized).redactionCount > 0) {
    throw new CommandRuntimeError(422, "sensitive_material_not_retained", "Operator reason contains authentication material", {
      humanMessage: "The operator reason was rejected because immutable decision and audit records cannot retain credentials or authentication material.",
      category: "policy_denied",
      remediation: "Remove the sensitive value and reference protected evidence or credentials by an opaque ID.",
    });
  }
  return normalized;
}

function requiredReason(value: unknown): string {
  const reason = optionalReason(value);
  if (!reason) throw new CommandRuntimeError(400, "reason_required", "A reason is required", { category: "invalid_input" });
  return reason;
}

function requiredPositiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw new CommandRuntimeError(400, "invalid_resume_boundary", `${label} must be a positive integer`, {
      humanMessage: "Refresh the run before resuming; its exact version boundary is missing or invalid.",
      category: "invalid_input",
    });
  }
  return Number(value);
}

function requiredNonNegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new CommandRuntimeError(400, "invalid_resume_boundary", `${label} must be a non-negative integer`, {
      humanMessage: "Refresh the run before resuming; its exact checkpoint sequence is missing or invalid.",
      category: "invalid_input",
    });
  }
  return Number(value);
}

function resumeBoundary(body: Record<string, unknown>): ResumeRunBoundary {
  if (body.expectedRunStatus !== "blocked") {
    throw new CommandRuntimeError(400, "invalid_resume_boundary", "Expected run status must be blocked", {
      humanMessage: "Resume is available only for the exact blocked run state shown in the Recovery Panel.",
      category: "invalid_input",
    });
  }
  if (
    typeof body.expectedCheckpointStateHash !== "string" ||
    !/^[a-f0-9]{64}$/u.test(body.expectedCheckpointStateHash)
  ) {
    throw new CommandRuntimeError(400, "invalid_resume_boundary", "Expected checkpoint state hash is invalid", {
      humanMessage: "Refresh the run before resuming; its verified checkpoint digest is missing or invalid.",
      category: "invalid_input",
    });
  }
  return {
    expectedRunVersion: requiredPositiveInteger(body.expectedRunVersion, "Expected run version"),
    expectedRunStatus: "blocked",
    expectedCheckpointId: pathId(body.expectedCheckpointId, "expectedCheckpointId"),
    expectedCheckpointStateHash: body.expectedCheckpointStateHash,
    expectedCheckpointEventSequence: requiredNonNegativeInteger(
      body.expectedCheckpointEventSequence,
      "Expected checkpoint event sequence",
    ),
  };
}

function expectedFingerprint(body: Record<string, unknown>, actual: string): void {
  if (typeof body.expectedFingerprint !== "string" || body.expectedFingerprint !== actual) {
    throw new CommandRuntimeError(409, "guided_action_changed", "Expected action fingerprint does not match", {
      humanMessage: "The Guided action card changed or was stale. Review the current exact step before deciding.",
      category: "conflict",
    });
  }
}

function expectedParameters(body: Record<string, unknown>, actual: JsonValue): string {
  if (!Object.prototype.hasOwnProperty.call(body, "expectedParameters")) {
    throw new CommandRuntimeError(400, "expected_parameters_required", "Exact represented parameters are required", {
      humanMessage: "Refresh the Guided action card before using this exact-step control.",
      category: "invalid_input",
    });
  }
  let supplied: string;
  let represented: string;
  try {
    supplied = canonicalJson(body.expectedParameters);
    // The decision inbox deliberately projects secret-bearing fields as
    // `[REDACTED]`; requiring the browser to echo the hidden canonical value
    // would make every otherwise legal decision mutation impossible. Compare
    // against that same deterministic public projection while the independent
    // action fingerprint continues to bind the complete canonical action that
    // the runtime—not the request body—will execute.
    represented = canonicalJson(sanitizeJson(actual));
  } catch {
    throw new CommandRuntimeError(400, "invalid_expected_parameters", "Expected parameters must be valid JSON", {
      category: "invalid_input",
    });
  }
  if (supplied !== represented) {
    throw new CommandRuntimeError(409, "guided_parameters_changed", "Expected represented parameters do not match", {
      humanMessage: "The Guided action parameters changed or were stale. Review the current exact step before deciding.",
      category: "conflict",
    });
  }
  return hashCanonical(actual);
}

function asJson(value: unknown): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

type RuntimeMutation = (
  scope: string,
  handler: (request: Request, operatorId: string, commandId: string) => Promise<JsonValue> | JsonValue,
  preflight?: (request: Request) => void,
  validate?: (request: Request) => void,
  replayGuard?: (request: Request, replay: JsonValue) => void,
  claimGuard?: (request: Request, commandId: string) => void,
) => RequestHandler;

function runtimeRouterBoundary(dependencies: MissionRuntimeV2RouterDependencies) {
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

  const mutation = (
    scope: string,
    handler: (request: Request, operatorId: string, commandId: string) => Promise<JsonValue> | JsonValue,
    preflight?: (request: Request) => void,
    validate?: (request: Request) => void,
    replayGuard?: (request: Request, replay: JsonValue) => void,
    claimGuard?: (request: Request, commandId: string) => void,
  ) => route(async (request, response) => {
    const key = idempotencyKey(request);
    const operatorId = actor(dependencies, request);
    // Never retain the caller's raw idempotency key in mission events or
    // immutable audit. The stable digest is sufficient to bind a runtime
    // commit to the HTTP reservation that authorized it.
    const commandId = hashCanonical({ scope, key, operatorId });
    validate?.(request);
    // An idempotency receipt belongs to the authenticated operator as well as
    // the canonical request. Knowledge of another operator's key must never
    // replay their privileged mutation response.
    const requestIdentity = { operatorId, params: request.params, body: request.body ?? {} };
    // Idempotency is not an authorization cache. Ownership, reservation, and
    // first-application boundary checks share one write reservation. A second
    // HTTP worker can therefore observe only a completed result or a bounded
    // in-progress claim; it cannot invoke the runtime concurrently.
    const claim = dependencies.runtime.repository.transaction(() => {
      preflight?.(request);
      const result = dependencies.runtime.repository.claimIdempotent(
        scope,
        key,
        requestIdentity,
        operatorId,
        new Date().toISOString(),
        30_000,
      );
      if (result.kind === "completed") replayGuard?.(request, result.response);
      if (result.kind === "claimed") claimGuard?.(request, commandId);
      return result;
    });
    if (claim.kind === "completed") {
      response.json(claim.response);
      return;
    }
    if (claim.kind === "in_progress") {
      throw new CommandRuntimeError(409, "idempotency_request_in_progress", "The mutation is already in progress", {
        humanMessage: "This exact command is already being processed by a fenced worker.",
        retryable: true,
        category: "conflict",
        remediation: `Retry after ${claim.leaseExpiresAt}; the same key will return the accepted result once durable.`,
      });
    }
    const abandonOwnedClaim = (): void => {
      dependencies.runtime.repository.transaction(() => {
        dependencies.runtime.repository.abandonIdempotentClaim(
          scope,
          key,
          requestIdentity,
          claim.ownerToken,
        );
      });
    };
    let heartbeatFailure: unknown;
    const claimHeartbeat = setInterval(() => {
      try {
        dependencies.runtime.repository.transaction(() => {
          preflight?.(request);
          return dependencies.runtime.repository.heartbeatIdempotentClaim(
            scope,
            key,
            requestIdentity,
            claim.ownerToken,
            operatorId,
            new Date().toISOString(),
            30_000,
          );
        });
      } catch (error) {
        try {
          abandonOwnedClaim();
          heartbeatFailure = error;
        } catch (cleanupError) {
          heartbeatFailure = cleanupError;
        }
        clearInterval(claimHeartbeat);
      }
    }, 10_000);
    let payload: JsonValue;
    try {
      payload = await handler(request, operatorId, commandId);
    } catch (error) {
      if (error instanceof ControlPlaneLeaseError) abandonOwnedClaim();
      throw error;
    } finally {
      clearInterval(claimHeartbeat);
    }
    if (heartbeatFailure) throw heartbeatFailure;
    let completed: JsonValue;
    try {
      completed = dependencies.runtime.repository.transaction(() => {
        preflight?.(request);
        return dependencies.runtime.repository.completeIdempotentClaim(
          scope,
          key,
          requestIdentity,
          payload,
          claim.ownerToken,
          operatorId,
          new Date().toISOString(),
        );
      });
    } catch (error) {
      if (error instanceof ControlPlaneLeaseError) abandonOwnedClaim();
      throw error;
    }
    response.json(completed);
  });

  return { router, route, mutation };
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function assertResumeReplayCurrent(
  dependencies: MissionRuntimeV2RouterDependencies,
  request: Request,
  replay: JsonValue,
): void {
  const runId = pathId(request.params.runId, "runId");
  const cached = record(replay);
  const cachedRun = record(cached.run);
  const cachedCheckpoint = record(cached.latestCheckpoint);
  let latest: ReturnType<MissionRuntimeEngine["coordinator"]["getLatestCheckpoint"]>;
  try {
    latest = dependencies.runtime.coordinator.getLatestCheckpoint(runId);
  } catch {
    throw new CommandRuntimeError(409, "resume_idempotent_replay_stale", "Cached resume checkpoint failed integrity verification", {
      humanMessage: "The run changed after this resume command was accepted, so its cached result cannot be replayed.",
      category: "data_integrity",
      remediation: "Refresh the run and inspect its current verified checkpoint before taking another action.",
    });
  }
  const current = dependencies.runtime.repository.getRunProjection(runId);
  if (
    cachedRun.id !== current.id ||
    cachedRun.version !== current.version ||
    cachedRun.status !== current.status ||
    !latest ||
    cachedCheckpoint.id !== latest.id ||
    cachedCheckpoint.stateHash !== latest.stateHash ||
    cachedCheckpoint.eventSequence !== latest.eventSequence
  ) {
    throw new CommandRuntimeError(409, "resume_idempotent_replay_stale", "Cached resume result is no longer canonical", {
      humanMessage: "The run changed after this resume command was accepted, so its cached result cannot be replayed.",
      category: "conflict",
      remediation: "Refresh the run and use a new idempotency key only for a newly represented action.",
    });
  }
}

function mountRunControlRoutes(
  router: Router,
  dependencies: MissionRuntimeV2RouterDependencies,
  mutation: RuntimeMutation,
): void {
  for (const command of ["pause", "resume", "cancel"] as const) {
    router.post(`/api/v2/runs/:runId/${command}`, mutation(`run.${command}`, async (request, operatorId, commandId) => {
      const runId = pathId(request.params.runId, "runId");
      const body = bodyObject(request.body);
      const reason = requiredReason(body.reason);
      if (command === "pause") dependencies.runtime.pauseRun(runId, operatorId, reason, commandId);
      if (command === "resume") dependencies.runtime.resumeRun(runId, operatorId, reason, resumeBoundary(body), commandId);
      if (command === "cancel") await dependencies.runtime.cancelRun(runId, operatorId, reason, commandId);
      return asJson({
        schemaVersion: "2.4",
        run: dependencies.runtime.repository.getRunProjection(runId),
        latestCheckpoint: dependencies.runtime.coordinator.getLatestCheckpoint(runId) ?? null,
      });
    }, (request) => {
      dependencies.runtime.assertV2ControlPlaneOwnership(pathId(request.params.runId, "runId"));
    }, (request) => {
      const body = bodyObject(request.body);
      requiredReason(body.reason);
      if (command === "resume") resumeBoundary(body);
    }, command === "resume"
      ? (request, replay) => assertResumeReplayCurrent(dependencies, request, replay)
      : undefined, command === "resume"
      ? (request, commandId) => {
          const runId = pathId(request.params.runId, "runId");
          dependencies.runtime.assertResumeRunBoundary(
            runId,
            resumeBoundary(bodyObject(request.body)),
            commandId,
          );
        }
      : undefined));
  }
}

function assertDecisionMutationOwnership(
  dependencies: MissionRuntimeV2RouterDependencies,
  request: Request,
): void {
  const decisionId = pathId(request.params.decisionId, "decisionId");
  const decision = dependencies.runtime.repository.getDecision(decisionId);
  dependencies.runtime.assertV2ControlPlaneOwnership(decision.runId);
}

/**
 * Mount only operator run intervention controls. This lets a host expose the
 * durable pause/resume/cancel boundary without also advertising Guided or
 * Autonomous execution routes that its provider/MCP runtime cannot enforce.
 */
export function createMissionRunControlV2Router(
  dependencies: MissionRuntimeV2RouterDependencies,
): Router {
  const { router, mutation } = runtimeRouterBoundary(dependencies);
  mountRunControlRoutes(router, dependencies, mutation);
  return router;
}

/** Mount after authentication and JSON parsing middleware. */
export function createMissionRuntimeV2Router(
  dependencies: MissionRuntimeV2RouterDependencies,
): Router {
  const { router, route, mutation } = runtimeRouterBoundary(dependencies);

  router.get("/api/v2/missions/:missionId/runtime", route((request, response) => {
    const missionId = pathId(request.params.missionId, "missionId");
    response.json({ schemaVersion: "2.4", ...dependencies.runtime.repository.getMissionRuntime(missionId) });
  }));

  router.get("/api/v2/runs", route((request, response) => {
    const filters = parseRuntimeRunQuery(request.query as Record<string, unknown>);
    const page = dependencies.runtime.repository.listRunProjectionPage({
      ...(filters.query ? { query: filters.query } : {}),
      ...(filters.journey ? { journey: filters.journey } : {}),
      ...(filters.status ? { status: filters.status } : {}),
      ...(filters.statuses ? { statuses: filters.statuses } : {}),
      ...(filters.cursor ? { cursor: filters.cursor } : {}),
      limit: filters.limit,
    });
    response.json({
      schemaVersion: "2.4",
      items: page.items,
      nextCursor: page.nextCursor
        ? encodeRuntimeRunCursor(page.nextCursor, filters.filterHash)
        : null,
    });
  }));

  router.get("/api/v2/runs/:runId", route((request, response) => {
    const runId = pathId(request.params.runId, "runId");
    response.json({
      schemaVersion: "2.4",
      run: dependencies.runtime.repository.getRunProjection(runId),
      latestCheckpoint: dependencies.runtime.coordinator.getLatestCheckpoint(runId) ?? null,
    });
  }));

  router.get("/api/v2/runs/:runId/plans", route((request, response) => {
    const runId = pathId(request.params.runId, "runId");
    dependencies.runtime.repository.getRunProjection(runId);
    response.json({ schemaVersion: "2.4", items: dependencies.runtime.repository.listPlans(runId) });
  }));

  router.get("/api/v2/decisions", route((request, response) => {
    const allowed = new Set(["pending", "approved", "manual", "alternative", "rejected", "expired", "cancelled"]);
    const status = typeof request.query.status === "string" ? request.query.status.trim() : undefined;
    if (status && !allowed.has(status)) {
      throw new CommandRuntimeError(400, "invalid_decision_status", "Decision status filter is invalid", { category: "invalid_input" });
    }
    const runId = typeof request.query.runId === "string" ? pathId(request.query.runId, "runId") : undefined;
    const query = typeof request.query.query === "string" ? request.query.query.trim() : undefined;
    if (query && query.length > 300) {
      throw new CommandRuntimeError(400, "invalid_decision_search", "Decision search is too long", { category: "invalid_input" });
    }
    const limit = request.query.limit === undefined ? 100 : Number(request.query.limit);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new CommandRuntimeError(400, "invalid_pagination", "Decision limit must be 1 through 100", { category: "invalid_input" });
    }
    response.json({
      schemaVersion: "2.4",
      items: dependencies.runtime.repository.listDecisions({ status, runId, query, limit }),
    });
  }));

  router.post("/api/v2/guided-decisions/:decisionId/approve", mutation("decision.approve", async (request, operatorId) => {
    const decisionId = pathId(request.params.decisionId, "decisionId");
    const body = bodyObject(request.body);
    const decision = dependencies.runtime.repository.requireCurrentPendingDecision(decisionId);
    expectedFingerprint(body, decision.actionFingerprint);
    expectedParameters(body, decision.requestedParameters);
    const action = await dependencies.runtime.approveGuidedDecision(
      decisionId,
      operatorId,
      optionalReason(body.reason),
    );
    return asJson({ schemaVersion: "2.4", decisionId, status: "approved", action });
  }, (request) => assertDecisionMutationOwnership(dependencies, request)));

  router.post("/api/v2/runs/:runId/operational-hazards/retry-authorizations", mutation(
    "operational-hazard.retry-authorize",
    async (request, operatorId) => {
      const runId = pathId(request.params.runId, "runId");
      const body = bodyObject(request.body);
      const healthAssessmentId = pathId(body.healthAssessmentId, "healthAssessmentId");
      const attackAttemptId = pathId(body.attackAttemptId, "attackAttemptId");
      const ttlMs = body.ttlMs === undefined ? undefined : Number(body.ttlMs);
      if (ttlMs !== undefined && (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 3_600_000)) {
        throw new CommandRuntimeError(400, "invalid_hazard_authorization_expiry", "Authorization expiry must be one second through one hour", {
          category: "invalid_input",
        });
      }
      const authorization = dependencies.runtime.authorizeOperationalHazardRecovery({
        runId,
        healthAssessmentId,
        attackAttemptId,
        operatorId,
        ...(ttlMs === undefined ? {} : { ttlMs }),
      });
      return asJson({ schemaVersion: "2.4", authorization });
    },
    (request) => {
      const runId = pathId(request.params.runId, "runId");
      dependencies.runtime.assertV2ControlPlaneOwnership(runId);
      const body = bodyObject(request.body);
      pathId(body.healthAssessmentId, "healthAssessmentId");
      pathId(body.attackAttemptId, "attackAttemptId");
    },
  ));

  router.post("/api/v2/guided-decisions/:decisionId/reject", mutation("decision.reject", async (request, operatorId) => {
    const decisionId = pathId(request.params.decisionId, "decisionId");
    const body = bodyObject(request.body);
    const decision = dependencies.runtime.repository.requireCurrentPendingDecision(decisionId);
    expectedFingerprint(body, decision.actionFingerprint);
    expectedParameters(body, decision.requestedParameters);
    await dependencies.runtime.rejectGuidedDecision(decisionId, operatorId, requiredReason(body.reason));
    return { schemaVersion: "2.4", decisionId, status: "rejected" };
  }, (request) => assertDecisionMutationOwnership(dependencies, request)));

  router.post("/api/v2/guided-decisions/:decisionId/manual-result", mutation("decision.manual", async (request, operatorId) => {
    const decisionId = pathId(request.params.decisionId, "decisionId");
    const body = bodyObject(request.body);
    const decision = dependencies.runtime.repository.requireCurrentPendingDecision(decisionId);
    expectedFingerprint(body, decision.actionFingerprint);
    expectedParameters(body, decision.requestedParameters);
    if (typeof body.evidenceId !== "string") {
      throw new CommandRuntimeError(400, "interpreted_evidence_required", "Commander-interpreted evidence is required", {
        humanMessage: "Submit the manual output for interpretation before completing this exact step.",
        category: "invalid_input",
        remediation: "Use the Guided workspace result form, review the interpretation, then accept it to advance.",
      });
    }
    const evidenceId = pathId(body.evidenceId, "evidenceId");
    const receipt = await dependencies.runtime.submitManualGuidedResult(
      decisionId,
      operatorId,
      evidenceId,
    );
    return asJson({ schemaVersion: "2.4", decisionId, status: "manual", receipt });
  }, (request) => assertDecisionMutationOwnership(dependencies, request)));

  router.post("/api/v2/guided-decisions/:decisionId/skip", mutation("decision.skip", async (request, operatorId) => {
    const decisionId = pathId(request.params.decisionId, "decisionId");
    const body = bodyObject(request.body);
    const decision = dependencies.runtime.requireCurrentGuidedDecisionBoundary(decisionId);
    expectedFingerprint(body, decision.actionFingerprint);
    expectedParameters(body, decision.requestedParameters);
    const receipt = await dependencies.runtime.skipGuidedDecision(
      decisionId,
      operatorId,
      requiredReason(body.reason),
    );
    return asJson({ schemaVersion: "2.4", decisionId, status: "skipped", receipt });
  }, (request) => assertDecisionMutationOwnership(dependencies, request)));

  router.post("/api/v2/guided-decisions/:decisionId/stop", mutation("decision.stop", async (request, operatorId, commandId) => {
    const decisionId = pathId(request.params.decisionId, "decisionId");
    const body = bodyObject(request.body);
    const decision = dependencies.runtime.repository.getDecision(decisionId);
    expectedFingerprint(body, decision.actionFingerprint);
    expectedParameters(body, decision.requestedParameters);
    dependencies.runtime.repository.requireCurrentPendingDecision(decisionId);
    const reason = requiredReason(body.reason);
    await dependencies.runtime.stopGuidedMission(
      decisionId,
      operatorId,
      reason,
      commandId,
    );
    return asJson({
      schemaVersion: "2.4",
      decisionId,
      status: "cancelled",
      run: dependencies.runtime.repository.getRunProjection(decision.runId),
    });
  }, (request) => assertDecisionMutationOwnership(dependencies, request)));

  mountRunControlRoutes(router, dependencies, mutation);

  return router;
}

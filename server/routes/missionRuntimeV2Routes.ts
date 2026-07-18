import { Router, type Request, type RequestHandler, type Response } from "express";
import {
  CommandRuntimeError,
  type MissionRuntimeEngine,
  type ResumeRunBoundary,
} from "../command-runtime";
import { DurableOrchestrationError } from "../orchestration";
import { ControlPlaneLeaseError } from "../control-plane";
import type { JsonValue } from "../events";
import { canonicalJson, hashCanonical } from "../missions/canonical";
import type { RunState } from "../supervisor";
import { redactSensitiveText } from "../guided-commander/validation";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";

export interface MissionRuntimeV2RouterDependencies {
  readonly runtime: MissionRuntimeEngine;
  readonly resolveActor: (request: Request) => string;
}

function runtimeError(error: unknown): CommandRuntimeError {
  if (error instanceof CommandRuntimeError) return error;
  if (error instanceof ControlPlaneLeaseError) {
    return new CommandRuntimeError(
      error.code === "run_not_found" ? 404 : 409,
      `control_plane_${error.code}`,
      error.message,
      {
        humanMessage: error.code === "control_plane_mismatch"
          ? "This run belongs to another control plane and Ti-Scale refused to mutate it."
          : "Ti-Scale could not prove exclusive mutation authority for this run.",
        retryable: error.retryable,
        category: error.code === "run_not_found" ? "not_found" : "conflict",
        remediation: error.retryable
          ? "Wait for the current fenced controller to release or expire, then resume from the durable checkpoint."
          : "Open the run through its owning control plane; do not attempt concurrent control.",
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
    represented = canonicalJson(actual);
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
    let heartbeatFailure: unknown;
    const claimHeartbeat = setInterval(() => {
      try {
        dependencies.runtime.repository.transaction(() =>
          dependencies.runtime.repository.heartbeatIdempotentClaim(
            scope,
            key,
            requestIdentity,
            claim.ownerToken,
            operatorId,
            new Date().toISOString(),
            30_000,
          ));
      } catch (error) {
        heartbeatFailure = error;
        clearInterval(claimHeartbeat);
      }
    }, 10_000);
    let payload: JsonValue;
    try {
      payload = await handler(request, operatorId, commandId);
    } finally {
      clearInterval(claimHeartbeat);
    }
    if (heartbeatFailure) throw heartbeatFailure;
    const completed = dependencies.runtime.repository.transaction(() =>
      dependencies.runtime.repository.completeIdempotentClaim(
        scope,
        key,
        requestIdentity,
        payload,
        claim.ownerToken,
        operatorId,
        new Date().toISOString(),
      ));
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
    const allowedStates = new Set([
      "queued", "planning", "awaiting_contract_confirmation", "running",
      "waiting_guided_decision", "blocked", "recovering", "completed", "failed", "cancelled",
    ]);
    const journey = typeof request.query.journey === "string" ? request.query.journey.trim() : undefined;
    if (journey && journey !== "autonomous" && journey !== "guided") {
      throw new CommandRuntimeError(400, "invalid_journey_filter", "Run journey filter is invalid", { category: "invalid_input" });
    }
    const status = typeof request.query.status === "string" ? request.query.status.trim() : undefined;
    if (status && !allowedStates.has(status)) {
      throw new CommandRuntimeError(400, "invalid_run_status", "Run status filter is invalid", { category: "invalid_input" });
    }
    const query = typeof request.query.query === "string" ? request.query.query.trim() : undefined;
    if (query && query.length > 300) {
      throw new CommandRuntimeError(400, "invalid_run_search", "Run search is too long", { category: "invalid_input" });
    }
    const limit = request.query.limit === undefined ? 50 : Number(request.query.limit);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new CommandRuntimeError(400, "invalid_pagination", "Run limit must be 1 through 100", { category: "invalid_input" });
    }
    response.json({
      schemaVersion: "2.4",
      items: dependencies.runtime.repository.listRunProjections({
        ...(query ? { query } : {}),
        ...(journey ? { journey: journey as "autonomous" | "guided" } : {}),
        ...(status ? { status: status as RunState } : {}),
        limit,
      }),
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
  }));

  router.post("/api/v2/guided-decisions/:decisionId/reject", mutation("decision.reject", async (request, operatorId) => {
    const decisionId = pathId(request.params.decisionId, "decisionId");
    const body = bodyObject(request.body);
    const decision = dependencies.runtime.repository.requireCurrentPendingDecision(decisionId);
    expectedFingerprint(body, decision.actionFingerprint);
    expectedParameters(body, decision.requestedParameters);
    await dependencies.runtime.rejectGuidedDecision(decisionId, operatorId, requiredReason(body.reason));
    return { schemaVersion: "2.4", decisionId, status: "rejected" };
  }));

  router.post("/api/v2/guided-decisions/:decisionId/manual-result", mutation("decision.manual", async (request, operatorId) => {
    const decisionId = pathId(request.params.decisionId, "decisionId");
    const body = bodyObject(request.body);
    const decision = dependencies.runtime.repository.getDecision(decisionId);
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
    const evidence = dependencies.runtime.repository.database.prepare(`
      SELECT json_extract(chain.details_json, '$.summary') AS summary
      FROM evidence e
      JOIN evidence_chain_events chain
        ON chain.evidence_id = e.id AND chain.event_type = 'interpreted'
      WHERE e.id = ? AND e.mission_id = ? AND e.run_id = ? AND e.step_id = ?
        AND e.action_id IS NULL AND e.evidence_type = 'guided_text_result'
        AND e.verification_state = 'unverified'
      ORDER BY chain.occurred_at DESC, chain.id DESC LIMIT 1
    `).get(evidenceId, decision.missionId, decision.runId, decision.stepId) as {
      summary: string;
    } | undefined;
    if (!evidence?.summary.trim()) {
      throw new CommandRuntimeError(409, "interpreted_evidence_not_current", "Interpreted evidence does not belong to the current exact step", {
        humanMessage: "The reviewed observation is stale, already consumed, or belongs to another step.",
        category: "scope_conflict",
        remediation: "Refresh the Guided workspace and interpret output for the current represented action.",
      });
    }
    const receipt = await dependencies.runtime.submitManualGuidedResult(
      decisionId,
      operatorId,
      evidence.summary,
      evidenceId,
    );
    return asJson({ schemaVersion: "2.4", decisionId, status: "manual", receipt });
  }));

  router.post("/api/v2/guided-decisions/:decisionId/skip", mutation("decision.skip", async (request, operatorId) => {
    const decisionId = pathId(request.params.decisionId, "decisionId");
    const body = bodyObject(request.body);
    const decision = dependencies.runtime.repository.getDecision(decisionId);
    expectedFingerprint(body, decision.actionFingerprint);
    expectedParameters(body, decision.requestedParameters);
    const receipt = await dependencies.runtime.skipGuidedDecision(
      decisionId,
      operatorId,
      requiredReason(body.reason),
    );
    return asJson({ schemaVersion: "2.4", decisionId, status: "skipped", receipt });
  }));

  router.post("/api/v2/guided-decisions/:decisionId/stop", mutation("decision.stop", async (request, operatorId, commandId) => {
    const decisionId = pathId(request.params.decisionId, "decisionId");
    const body = bodyObject(request.body);
    const decision = dependencies.runtime.repository.getDecision(decisionId);
    expectedFingerprint(body, decision.actionFingerprint);
    const parameterHash = expectedParameters(body, decision.requestedParameters);
    dependencies.runtime.repository.requireCurrentPendingDecision(decisionId);
    const reason = requiredReason(body.reason);
    await dependencies.runtime.cancelRun(decision.runId, operatorId, reason, commandId);
    const now = new Date().toISOString();
    dependencies.runtime.repository.transaction(() => {
      dependencies.runtime.repository.events.append({
        missionId: decision.missionId,
        runId: decision.runId,
        journey: "guided",
        eventType: "guided.mission_stopped",
        actorType: "operator",
        actorId: operatorId,
        summary: "Operator stopped the mission from the exact represented Guided step",
        payload: {
          decisionId,
          stepId: decision.stepId,
          actionFingerprint: decision.actionFingerprint,
          parameterHash,
          reason,
        },
        sensitivity: "private",
      });
      dependencies.runtime.repository.appendAudit({
        missionId: decision.missionId,
        runId: decision.runId,
        actorId: operatorId,
        action: "guided.mission_stopped",
        resourceType: "guided_decision",
        resourceId: decisionId,
        reason,
        details: {
          stepId: decision.stepId,
          actionFingerprint: decision.actionFingerprint,
          parameterHash,
        },
        now,
      });
    });
    return asJson({
      schemaVersion: "2.4",
      decisionId,
      status: "cancelled",
      run: dependencies.runtime.repository.getRunProjection(decision.runId),
    });
  }));

  mountRunControlRoutes(router, dependencies, mutation);

  return router;
}

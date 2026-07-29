import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import {
  BrainContextHookError,
  BrainContextService,
  parseMissionMemoryPolicy,
  retrieveMissionBrainContext,
} from "../brain-runtime";
import { MemoryRepository, SecondBrainService } from "../memory";
import { OperationsApiError } from "../operations/errors";
import { OperationsRepository } from "../operations/OperationsRepository";
import { RecoveryRepository } from "../operations/RecoveryRepository";
import { RecoveryMutationRepository } from "../operations/RecoveryMutationRepository";
import { FollowUpRunRepository } from "../operations/FollowUpRunRepository";
import { OperationsReviewRepository } from "../operations/OperationsReviewRepository";
import { DecisionInboxRepository } from "../operations/DecisionInboxRepository";
import { SecureExportService } from "../operations/SecureExportService";
import { CanonicalMissionReportService } from "../reports";
import { TraceRepository } from "../observability/TraceRepository";
import {
  ControlPlaneLeaseError,
  RunMutationAuthorityGuard,
  describeRunMutationAuthorityError,
} from "../control-plane";
import { validateAccessPolicy } from "../operations/scope";
import type {
  OperationsContext,
  OperationsRouterDependencies,
} from "../operations/types";
import {
  boundedLimit,
  identifier,
  object,
  optionalEnum,
  optionalIdentifier,
  optionalSearch,
  optionalTimestamp,
  requiredIdempotencyKey,
  requiredPositiveInteger,
  requiredSafeReason,
  requiredText,
} from "../operations/validation";

const AGENT_STATUSES = new Set(["available", "busy", "degraded", "offline", "quarantined"] as const);
const ASSIGNMENT_STATUSES = new Set(["queued", "active", "blocked", "completed", "failed", "cancelled"] as const);
const VERIFICATION_STATES = new Set(["unverified", "verified", "disputed", "rejected"] as const);
const EVIDENCE_RECORD_CLASSES = new Set(["evidence", "operational_log", "all"] as const);
const SEVERITIES = new Set(["informational", "low", "medium", "high", "critical"] as const);
const FINDING_STATUSES = new Set(["draft", "under_review", "verified", "rejected", "accepted_risk"] as const);
const FINDING_REVIEW_STATUSES = new Set(["under_review", "verified", "rejected", "accepted_risk"] as const);
const JOURNEYS = new Set(["autonomous", "guided"] as const);
const LOG_SEVERITIES = new Set(["trace", "debug", "info", "warn", "error", "fatal"] as const);
const HEALTH_STATUSES = new Set(["healthy", "degraded", "unhealthy", "unknown"] as const);
const LESSON_STATUSES = new Set(["proposed", "under_review", "verified", "rejected", "stale", "superseded"] as const);
const LESSON_REVIEW_STATUSES = new Set(["under_review", "verified", "rejected", "stale", "superseded"] as const);
const MCP_STATUSES = new Set(["unknown", "healthy", "degraded", "offline", "quarantined"] as const);
const ACTION_STATUSES = new Set(["queued", "running", "succeeded", "failed", "cancelled", "timed_out", "denied"] as const);
const TRACE_STATUSES = new Set(["active", "completed", "failed"] as const);
const ACTOR_TYPES = new Set(["operator", "reviewer", "admin", "agent", "system"] as const);
const DECISION_INBOX_KINDS = new Set([
  "guided_decision",
  "autonomous_contract",
  "autonomous_exception",
  "administrative_approval",
] as const);
const ADMINISTRATIVE_REVIEW_STATUSES = new Set(["approved", "rejected"] as const);

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
  if (error instanceof BrainContextHookError) {
    const unavailable = error.code === "brain_context_unavailable";
    sendV2Error(response, requestTraceId, {
      status: unavailable ? 503 : 500,
      code: error.code,
      message: "Required reporting context could not be established",
      humanMessage: unavailable
        ? "The completion report was not produced because this Autonomous contract requires Second Brain context that is currently unavailable."
        : "The completion report was not produced because its required Context Pack or audit receipt could not be persisted safely.",
      retryable: unavailable,
      category: unavailable ? "dependency_unavailable" : "integrity_failure",
      details: { hook: error.hook, auditRecordId: error.auditRecordId ?? null },
      remediation: unavailable
        ? "Restore the local Second Brain dependency, verify the signed memory selection, and retry the export."
        : "Inspect the trace and local database health before retrying; do not bypass the reporting context gate.",
    });
    return;
  }
  const known = error instanceof OperationsApiError;
  sendV2Error(response, requestTraceId, known
    ? {
        status: error.status,
        code: error.code,
        message: error.message,
        humanMessage: error.options.humanMessage ?? error.message,
        retryable: error.options.retryable ?? false,
        category: error.options.category ?? "operations",
        ...(error.options.details === undefined ? {} : { details: error.options.details }),
        ...(error.options.remediation ? { remediation: error.options.remediation } : {}),
      }
    : {
        status: 500,
        code: "operations_internal_error",
        message: "Ti-Scale operations could not complete the request",
        humanMessage: "The operations service encountered an internal error.",
        retryable: false,
        category: "internal",
        remediation: "Use the trace ID to inspect redacted structured logs before retrying.",
      });
}

function context(request: Request, dependencies: OperationsRouterDependencies): OperationsContext {
  const actor = dependencies.resolveActor(request);
  if (!actor || typeof actor.id !== "string" || !actor.id.trim() || !ACTOR_TYPES.has(actor.type)) {
    throw new OperationsApiError(401, "operator_identity_required", "An authenticated operations identity is required", {
      humanMessage: "Sign in again before accessing operational data.",
      category: "authentication_missing",
    });
  }
  const actorId = identifier(actor.id, "Actor ID");
  const normalizedActor = { id: actorId, type: actor.type } as const;
  const access = dependencies.resolveAccess(request, normalizedActor);
  validateAccessPolicy(access);
  return { actor: normalizedActor, access };
}

function value(request: Request, name: string): string | undefined {
  const candidate = request.query[name];
  if (candidate === undefined) return undefined;
  if (typeof candidate !== "string") {
    throw new OperationsApiError(400, "invalid_filter", `${name} must occur once`, {
      humanMessage: `The ${name} filter must have one value.`,
      category: "invalid_input",
    });
  }
  return candidate;
}

function cursor(request: Request): string | undefined {
  return value(request, "cursor");
}

function limit(request: Request): number {
  return boundedLimit(value(request, "limit"));
}

function includeInternal(request: Request): boolean {
  const candidate = value(request, "includeInternal");
  if (candidate === undefined) return false;
  if (candidate !== "1") {
    throw new OperationsApiError(400, "invalid_filter", "includeInternal must be 1", {
      humanMessage: "Use includeInternal=1 to request authorized internal runtime components.",
      category: "invalid_input",
    });
  }
  return true;
}

function completionExportFilename(runId: string): string {
  const safe = runId.replace(/[^A-Za-z0-9._-]/gu, "_").slice(0, 96) || "run";
  return `ti-scale-${safe}-completion.json`;
}

function secureExportFilename(runId: string, kind: "evidence" | "audit"): string {
  const safe = runId.replace(/[^A-Za-z0-9._-]/gu, "_").slice(0, 96) || "run";
  return `ti-scale-${safe}-${kind}.json`;
}

function inertDownloadHeaders(
  response: Response,
  filename: string,
  contentType: string,
  byteLength: number,
): void {
  response.setHeader("Content-Type", contentType);
  response.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  response.setHeader("Content-Length", String(byteLength));
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Content-Security-Policy", "sandbox");
  response.setHeader("Cache-Control", "no-store");
}

function sendJsonDownload(response: Response, filename: string, payload: unknown): void {
  const body = `${JSON.stringify(payload)}\n`;
  inertDownloadHeaders(
    response,
    filename,
    "application/json; charset=utf-8",
    Buffer.byteLength(body, "utf8"),
  );
  response.status(200).send(body);
}

function plainFilter(request: Request, name: string, maximum = 200): string | undefined {
  const candidate = value(request, name);
  if (candidate === undefined || candidate === "") return undefined;
  if (!candidate.trim() || candidate.length > maximum || /[\u0000-\u001F]/u.test(candidate)) {
    throw new OperationsApiError(400, "invalid_filter", `${name} is invalid`, {
      humanMessage: `The ${name} filter is invalid.`,
      category: "invalid_input",
    });
  }
  return candidate.trim();
}

function identifierArray(value: unknown, label: string, maximum = 20): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > maximum) {
    throw new OperationsApiError(400, "invalid_request", `${label} is invalid`, {
      humanMessage: `${label} must be an array containing at most ${maximum} stable identifiers.`,
      category: "invalid_input",
    });
  }
  return value.map((item, index) => {
    if (typeof item !== "string") {
      throw new OperationsApiError(400, "invalid_request", `${label}[${index}] is invalid`, {
        category: "invalid_input",
      });
    }
    return identifier(item, `${label}[${index}]`);
  });
}

function exactRecoveryExpectation(body: Record<string, unknown>) {
  const checkpointStateHash = requiredText(body.expectedCheckpointStateHash, "Expected checkpoint state hash", 64);
  if (!/^[a-f0-9]{64}$/u.test(checkpointStateHash)) {
    throw new OperationsApiError(400, "invalid_request", "Expected checkpoint state hash is invalid", {
      humanMessage: "Expected checkpoint state hash must be a lowercase SHA-256 digest.",
      category: "invalid_input",
    });
  }
  if (!Number.isSafeInteger(body.expectedCheckpointEventSequence) || Number(body.expectedCheckpointEventSequence) < 0) {
    throw new OperationsApiError(400, "invalid_request", "Expected checkpoint event sequence is invalid", {
      humanMessage: "Expected checkpoint event sequence must be a non-negative integer.",
      category: "invalid_input",
    });
  }
  return {
    expectedRunVersion: requiredPositiveInteger(body.expectedRunVersion, "Expected run version"),
    expectedPlanId: identifier(body.expectedPlanId, "Expected plan ID"),
    expectedPlanVersion: requiredPositiveInteger(body.expectedPlanVersion, "Expected plan version"),
    expectedStepId: identifier(body.expectedStepId, "Expected step ID"),
    expectedAssignmentId: identifier(body.expectedAssignmentId, "Expected assignment ID"),
    expectedCheckpointId: identifier(body.expectedCheckpointId, "Expected checkpoint ID"),
    expectedCheckpointStateHash: checkpointStateHash,
    expectedCheckpointEventSequence: Number(body.expectedCheckpointEventSequence),
  };
}

function handle(
  dependencies: OperationsRouterDependencies,
  operation: (request: Request, response: Response, ctx: OperationsContext) => void | Promise<void>,
) {
  return async (request: Request, response: Response): Promise<void> => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      await operation(request, response, context(request, dependencies));
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  };
}

/**
 * Mount with `app.use(createOperationsRouter(deps))` after authentication and
 * JSON body parsing. The host must resolve both actor identity and scope.
 */
export function createOperationsRouter(dependencies: OperationsRouterDependencies): Router {
  const repository = new OperationsRepository(dependencies.database, dependencies.clock);
  const brainContext = dependencies.brainContext ?? new BrainContextService({
    database: dependencies.database,
    secondBrain: new SecondBrainService(new MemoryRepository(dependencies.database)),
  });
  const recovery = new RecoveryRepository(dependencies.database, {
    providerRouteIds: dependencies.providerRouteIds,
    clock: dependencies.clock,
    providerHealthMaxAgeMs: dependencies.providerHealthMaxAgeMs,
    agentHeartbeatMaxAgeMs: dependencies.agentHeartbeatMaxAgeMs,
  });
  const recoveryMutations = new RecoveryMutationRepository(dependencies.database, {
    clock: dependencies.clock,
    providerRouteIds: dependencies.providerRouteIds,
    providerHealthMaxAgeMs: dependencies.providerHealthMaxAgeMs,
    agentHeartbeatMaxAgeMs: dependencies.agentHeartbeatMaxAgeMs,
  });
  const followUps = new FollowUpRunRepository(dependencies.database, dependencies.clock);
  const mutationAuthority = new RunMutationAuthorityGuard(dependencies.database, dependencies.clock);
  const reviews = new OperationsReviewRepository(dependencies.database, dependencies.clock);
  const decisions = new DecisionInboxRepository(dependencies.database, dependencies.clock);
  const traces = new TraceRepository(dependencies.database);
  const secureExports = new SecureExportService(dependencies.database, {
    vaultPathPolicy: dependencies.vaultPathPolicy,
    maximumArtifactBytes: dependencies.maximumArtifactDownloadBytes,
    maximumExportBytes: dependencies.maximumSecureExportBytes,
    maximumExportRecords: dependencies.maximumSecureExportRecords,
    clock: dependencies.clock,
  });
  const missionReports = new CanonicalMissionReportService(dependencies.database, {
    ...(dependencies.reportArtifactRoot
      ? { artifactRoot: dependencies.reportArtifactRoot }
      : {}),
    ...(dependencies.clock ? { clock: dependencies.clock } : {}),
  });
  const router = Router();
  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  router.get("/api/v2/agents", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listAgents(access, {
      limit: limit(request), cursor: cursor(request),
      status: optionalEnum(value(request, "status"), AGENT_STATUSES, "status"),
      query: optionalSearch(value(request, "query")),
      includeInternal: includeInternal(request),
    }));
  }));
  router.get("/api/v2/agents/:agentId", handle(dependencies, (request, response, { access }) => {
    response.json(repository.getAgent(
      identifier(request.params.agentId, "Agent ID"),
      access,
      { includeInternal: includeInternal(request) },
    ));
  }));
  router.get("/api/v2/agents/:agentId/assignments", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listAgentAssignments(identifier(request.params.agentId, "Agent ID"), access, {
      limit: limit(request), cursor: cursor(request),
      status: optionalEnum(value(request, "status"), ASSIGNMENT_STATUSES, "status"),
      includeInternal: includeInternal(request),
    }));
  }));

  router.get("/api/v2/decision-inbox", handle(dependencies, (request, response, { access }) => {
    response.json(decisions.list(access, {
      limit: limit(request),
      cursor: cursor(request),
      kind: optionalEnum(value(request, "kind"), DECISION_INBOX_KINDS, "kind"),
      status: plainFilter(request, "status", 80),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
      query: optionalSearch(value(request, "query")),
      from: optionalTimestamp(value(request, "from"), "from"),
      to: optionalTimestamp(value(request, "to"), "to"),
    }));
  }));
  router.post("/api/v2/administrative-approvals/:approvalId/review", handle(dependencies, (request, response, ctx) => {
    const body = object(request.body);
    const status = optionalEnum(body.status, ADMINISTRATIVE_REVIEW_STATUSES, "status");
    if (!status) {
      throw new OperationsApiError(400, "invalid_request", "Administrative review status is required", {
        category: "invalid_input",
      });
    }
    response.json(decisions.reviewAdministrativeApproval(
      identifier(request.params.approvalId, "Administrative approval ID"),
      { status, reason: requiredSafeReason(body.reason, "Administrative decision reason", 2_000) },
      requiredIdempotencyKey(request.get("Idempotency-Key")),
      ctx.actor,
      ctx.access,
    ));
  }));

  router.get("/api/v2/intelligence/evidence", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listEvidence(access, {
      limit: limit(request), cursor: cursor(request),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
      evidenceType: plainFilter(request, "evidenceType"),
      recordClass: optionalEnum(value(request, "recordClass"), EVIDENCE_RECORD_CLASSES, "recordClass"),
      verificationState: optionalEnum(value(request, "verificationState"), VERIFICATION_STATES, "verificationState"),
      query: optionalSearch(value(request, "query")),
      from: optionalTimestamp(value(request, "from"), "from"),
      to: optionalTimestamp(value(request, "to"), "to"),
    }));
  }));
  router.get("/api/v2/intelligence/evidence/:evidenceId", handle(dependencies, (request, response, { access }) => {
    response.json(repository.getEvidence(identifier(request.params.evidenceId, "Evidence ID"), access));
  }));
  router.get("/api/v2/intelligence/evidence/runs/:runId/export", handle(dependencies, (request, response, ctx) => {
    const runId = identifier(request.params.runId, "Run ID");
    sendJsonDownload(
      response,
      secureExportFilename(runId, "evidence"),
      secureExports.exportEvidenceBundle(runId, ctx.actor, ctx.access),
    );
  }));

  router.get("/api/v2/intelligence/findings", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listFindings(access, {
      limit: limit(request), cursor: cursor(request),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
      severity: optionalEnum(value(request, "severity"), SEVERITIES, "severity"),
      reviewStatus: optionalEnum(value(request, "reviewStatus"), FINDING_STATUSES, "reviewStatus"),
      query: optionalSearch(value(request, "query")),
    }));
  }));
  router.get("/api/v2/intelligence/findings/:findingId", handle(dependencies, (request, response, { access }) => {
    response.json(repository.getFinding(identifier(request.params.findingId, "Finding ID"), access));
  }));
  router.post("/api/v2/intelligence/findings/:findingId/review", handle(dependencies, (request, response, ctx) => {
    const body = object(request.body);
    const status = optionalEnum(body.status, FINDING_REVIEW_STATUSES, "status");
    if (!status) throw new OperationsApiError(400, "invalid_request", "Finding review status is required", { category: "invalid_input" });
    const reason = requiredText(body.reason, "Review reason", 2_000);
    const operatorOverride = body.operatorOverride === undefined ? false : body.operatorOverride;
    if (typeof operatorOverride !== "boolean") throw new OperationsApiError(400, "invalid_request", "operatorOverride must be boolean", { category: "invalid_input" });
    if (operatorOverride && reason.length < 12) throw new OperationsApiError(400, "invalid_request", "Evidence override reason is too short", { category: "invalid_input" });
    response.json(reviews.reviewFinding(
      identifier(request.params.findingId, "Finding ID"),
      { expectedVersion: requiredPositiveInteger(body.expectedVersion, "expectedVersion"), status, reason, operatorOverride },
      requiredIdempotencyKey(request.get("Idempotency-Key")), ctx.actor, ctx.access,
    ));
  }));

  router.get("/api/v2/intelligence/artifacts", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listArtifacts(access, {
      limit: limit(request), cursor: cursor(request),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
      artifactType: plainFilter(request, "artifactType"),
    }));
  }));
  router.get("/api/v2/intelligence/artifacts/:artifactId", handle(dependencies, (request, response, { access }) => {
    const artifactId = identifier(request.params.artifactId, "Artifact ID");
    response.json({
      ...repository.getArtifact(artifactId, access),
      delivery: secureExports.describeArtifactDelivery(artifactId, access),
    });
  }));
  router.get("/api/v2/intelligence/artifacts/:artifactId/download", handle(dependencies, (request, response, ctx) => {
    const download = secureExports.downloadArtifact(
      identifier(request.params.artifactId, "Artifact ID"),
      ctx.actor,
      ctx.access,
    );
    inertDownloadHeaders(
      response,
      download.filename,
      download.mediaType,
      download.byteSize,
    );
    response.status(200).send(download.body);
  }));

  router.get("/api/v2/operations/actions", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listActions(access, {
      limit: limit(request), cursor: cursor(request),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
      stepId: optionalIdentifier(value(request, "stepId"), "Step ID"),
      status: optionalEnum(value(request, "status"), ACTION_STATUSES, "status"),
      actionType: plainFilter(request, "actionType"),
    }));
  }));

  router.get("/api/v2/observability/events", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listEvents(access, {
      limit: limit(request), cursor: cursor(request),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
      eventType: plainFilter(request, "eventType"),
      journey: optionalEnum(value(request, "journey"), JOURNEYS, "journey"),
      traceId: optionalIdentifier(value(request, "traceId"), "Trace ID"),
      actorId: optionalIdentifier(value(request, "actorId"), "Actor ID"),
      from: optionalTimestamp(value(request, "from"), "from"),
      to: optionalTimestamp(value(request, "to"), "to"),
    }));
  }));
  router.get("/api/v2/observability/traces", handle(dependencies, (request, response, { access }) => {
    response.json(traces.listTraces(access, {
      limit: limit(request), cursor: cursor(request),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
      traceId: optionalIdentifier(value(request, "traceId"), "Trace ID"),
      query: optionalSearch(value(request, "query")),
      status: optionalEnum(value(request, "status"), TRACE_STATUSES, "status"),
      from: optionalTimestamp(value(request, "from"), "from"),
      to: optionalTimestamp(value(request, "to"), "to"),
    }));
  }));
  router.get("/api/v2/observability/traces/:traceId", handle(dependencies, (request, response, { access }) => {
    response.json(traces.getTrace(
      identifier(request.params.traceId, "Trace ID"),
      access,
      { limit: limit(request), cursor: cursor(request) },
    ));
  }));
  router.get("/api/v2/observability/logs", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listLogs(access, {
      limit: limit(request), cursor: cursor(request),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
      stepId: optionalIdentifier(value(request, "stepId"), "Step ID"),
      actionId: optionalIdentifier(value(request, "actionId"), "Action ID"),
      severity: optionalEnum(value(request, "severity"), LOG_SEVERITIES, "severity"),
      domain: plainFilter(request, "domain"),
      traceId: optionalIdentifier(value(request, "traceId"), "Trace ID"),
      query: optionalSearch(value(request, "query")),
      from: optionalTimestamp(value(request, "from"), "from"),
      to: optionalTimestamp(value(request, "to"), "to"),
    }));
  }));
  router.get("/api/v2/observability/health", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listHealth(access, {
      limit: limit(request), cursor: cursor(request),
      componentType: plainFilter(request, "componentType"),
      componentId: optionalIdentifier(value(request, "componentId"), "Component ID"),
      status: optionalEnum(value(request, "status"), HEALTH_STATUSES, "status"),
      from: optionalTimestamp(value(request, "from"), "from"),
      to: optionalTimestamp(value(request, "to"), "to"),
    }));
  }));
  router.get("/api/v2/observability/audit/runs/:runId/export", handle(dependencies, (request, response, ctx) => {
    const runId = identifier(request.params.runId, "Run ID");
    sendJsonDownload(
      response,
      secureExportFilename(runId, "audit"),
      secureExports.exportAuditRecords(runId, ctx.actor, ctx.access),
    );
  }));
  router.get("/api/v2/operations/runs/:runId/recovery", handle(dependencies, (request, response, { access }) => {
    response.json(recovery.getRunRecovery(identifier(request.params.runId, "Run ID"), access));
  }));
  router.post("/api/v2/operations/runs/:runId/recovery/replan", handle(dependencies, (request, response, ctx) => {
    const runId = identifier(request.params.runId, "Run ID");
    const body = object(request.body);
    const authority = mutationAuthority.authorize({
      runId,
      actorId: ctx.actor.id,
      mode: "lease",
      ...(dependencies.assertRunMutationLease
        ? { assertLease: dependencies.assertRunMutationLease }
        : {}),
    });
    const projection = recoveryMutations.requestReplan(
      runId,
      {
        ...exactRecoveryExpectation(body),
        strategyReason: requiredSafeReason(body.strategyReason, "Materially different strategy", 4_000),
      },
      requiredIdempotencyKey(request.get("Idempotency-Key")),
      ctx.actor,
      ctx.access,
      authority.assertCurrent,
    );
    response.json(projection);
    if (projection.mutation.continuationId) {
      dependencies.notifyRecoveryContinuation?.({
        runId,
        continuationId: projection.mutation.continuationId,
      });
    }
  }));
  router.post("/api/v2/operations/runs/:runId/recovery/reassign", handle(dependencies, (request, response, ctx) => {
    const runId = identifier(request.params.runId, "Run ID");
    const body = object(request.body);
    const authority = mutationAuthority.authorize({
      runId,
      actorId: ctx.actor.id,
      mode: "lease",
      ...(dependencies.assertRunMutationLease
        ? { assertLease: dependencies.assertRunMutationLease }
        : {}),
    });
    response.json(recoveryMutations.reassignSpecialist(
      runId,
      {
        ...exactRecoveryExpectation(body),
        targetAgentId: identifier(body.targetAgentId, "Target specialist ID"),
        capability: identifier(body.capability, "Declared capability"),
        guidedDecisionId: optionalIdentifier(body.guidedDecisionId, "Guided decision ID"),
        expectedDecisionFingerprint: optionalIdentifier(body.expectedDecisionFingerprint, "Expected decision fingerprint"),
        reason: requiredSafeReason(body.reason, "Reassignment reason", 2_000),
      },
      requiredIdempotencyKey(request.get("Idempotency-Key")),
      ctx.actor,
      ctx.access,
      authority.assertCurrent,
    ));
  }));
  router.post("/api/v2/operations/runs/:runId/recovery/provider", handle(dependencies, (request, response, ctx) => {
    const runId = identifier(request.params.runId, "Run ID");
    const body = object(request.body);
    const authority = mutationAuthority.authorize({
      runId,
      actorId: ctx.actor.id,
      mode: "lease",
      ...(dependencies.assertRunMutationLease
        ? { assertLease: dependencies.assertRunMutationLease }
        : {}),
    });
    response.json(recoveryMutations.changeProvider(
      runId,
      {
        ...exactRecoveryExpectation(body),
        providerId: identifier(body.providerId, "Provider route ID"),
        modelId: identifier(body.modelId, "Provider model ID"),
        modelConfigurationHash: (() => {
          const hash = requiredText(body.modelConfigurationHash, "Provider model configuration hash", 64);
          if (!/^[a-f0-9]{64}$/u.test(hash)) {
            throw new OperationsApiError(400, "invalid_request", "Provider model configuration hash is invalid", {
              humanMessage: "Provider model configuration hash must be the exact lowercase SHA-256 digest from live readiness.",
              category: "invalid_input",
            });
          }
          return hash;
        })(),
        guidedDecisionId: optionalIdentifier(body.guidedDecisionId, "Guided decision ID"),
        expectedDecisionFingerprint: optionalIdentifier(body.expectedDecisionFingerprint, "Expected decision fingerprint"),
        reason: requiredSafeReason(body.reason, "Provider routing reason", 2_000),
      },
      requiredIdempotencyKey(request.get("Idempotency-Key")),
      ctx.actor,
      ctx.access,
      authority.assertCurrent,
    ));
  }));
  router.post("/api/v2/operations/runs/:runId/follow-up", handle(dependencies, (request, response, ctx) => {
    const body = object(request.body);
    const sourceRunId = identifier(request.params.runId, "Source run ID");
    const authority = mutationAuthority.authorize({
      runId: sourceRunId,
      actorId: ctx.actor.id,
      mode: "lease",
      ...(dependencies.assertRunMutationLease
        ? { assertLease: dependencies.assertRunMutationLease }
        : {}),
    });
    const created = followUps.create(
      sourceRunId,
      {
        reason: requiredSafeReason(body.reason, "Follow-up reason", 2_000),
        selectedLessonIds: identifierArray(body.selectedLessonIds, "selectedLessonIds"),
      },
      requiredIdempotencyKey(request.get("Idempotency-Key")),
      ctx.actor,
      ctx.access,
      authority.assertCurrent,
    );
    response.status(201).json(created);
  }));

  router.get("/api/v2/learning/evaluations", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listEvaluations(access, {
      limit: limit(request), cursor: cursor(request),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
      journey: optionalEnum(value(request, "journey"), JOURNEYS, "journey"),
    }));
  }));
  router.get("/api/v2/learning/lessons", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listLessons(access, {
      limit: limit(request), cursor: cursor(request),
      status: optionalEnum(value(request, "status"), LESSON_STATUSES, "status"),
      lessonType: plainFilter(request, "lessonType"),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
      query: optionalSearch(value(request, "query")),
    }));
  }));
  router.get("/api/v2/learning/lessons/:lessonId", handle(dependencies, (request, response, { access }) => {
    response.json(repository.getLesson(identifier(request.params.lessonId, "Lesson ID"), access));
  }));
  router.post("/api/v2/learning/lessons/:lessonId/review", handle(dependencies, (request, response, ctx) => {
    const body = object(request.body);
    const status = optionalEnum(body.status, LESSON_REVIEW_STATUSES, "status");
    if (!status) throw new OperationsApiError(400, "invalid_request", "Lesson review status is required", { category: "invalid_input" });
    response.json(reviews.reviewLesson(
      identifier(request.params.lessonId, "Lesson ID"),
      {
        expectedUpdatedAt: optionalTimestamp(body.expectedUpdatedAt, "expectedUpdatedAt") ?? requiredText(body.expectedUpdatedAt, "expectedUpdatedAt"),
        status,
        reason: requiredText(body.reason, "Review reason", 2_000),
      },
      requiredIdempotencyKey(request.get("Idempotency-Key")), ctx.actor, ctx.access,
    ));
  }));
  router.get("/api/v2/learning/usage", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listLessonUsage(access, {
      limit: limit(request), cursor: cursor(request),
      lessonId: optionalIdentifier(value(request, "lessonId"), "Lesson ID"),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
    }));
  }));

  router.get("/api/v2/reports", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listReports(access, {
      limit: limit(request), cursor: cursor(request),
      missionId: optionalIdentifier(value(request, "missionId"), "Mission ID"),
      runId: optionalIdentifier(value(request, "runId"), "Run ID"),
    }));
  }));
  router.post("/api/v2/reports/runs/:runId/generate", handle(dependencies, (request, response, ctx) => {
    const body = object(request.body);
    const reportVersion = body.reportVersion === undefined
      ? 1
      : requiredPositiveInteger(body.reportVersion, "Report version");
    const generated = missionReports.generate(
      identifier(request.params.runId, "Run ID"),
      reportVersion,
      ctx.actor,
      ctx.access,
      requiredIdempotencyKey(request.get("Idempotency-Key")),
    );
    response.status(201).json(generated);
  }));
  router.get("/api/v2/reports/runs/:runId/export", handle(dependencies, (request, response, ctx) => {
    const runId = identifier(request.params.runId, "Run ID");
    const reportingScope = repository.getRunCompletionReportingScope(runId, ctx.access);
    const contextResult = retrieveMissionBrainContext({
      brainContext,
      hook: "reporting",
      journey: reportingScope.journey,
      missionId: reportingScope.missionId,
      runId: reportingScope.runId,
      actorId: ctx.actor.id,
      actorType: ctx.actor.type === "agent" || ctx.actor.type === "system"
        ? ctx.actor.type
        : "operator",
      query: "Prepare a traceable terminal completion report using confirmed reporting preferences and evidence-linked mission outcomes.",
      queryRedacted: "Prepare a traceable terminal completion report using scoped confirmed preferences and evidence-linked outcomes.",
      memoryPolicy: parseMissionMemoryPolicy(reportingScope.memoryPolicyJson),
    });
    if (contextResult.items.length > 0) {
      brainContext.recordUnusedContext(
        contextResult,
        "The signed Ti-Scale JSON format and local privacy boundary are fixed; retrieved memory was retained as report provenance but did not override canonical report contents.",
      );
    }
    const influenceSummary = contextResult.status === "degraded"
      ? "Second Brain context was unavailable; Guided policy used an audited empty Context Pack and fixed local report defaults."
      : contextResult.status === "no_relevant_memory"
        ? "No relevant confirmed memory was found; the fixed local report contract supplied the defaults."
        : "Confirmed context was retrieved and retained as report provenance; fixed contract and privacy rules remained authoritative."
    const exported = repository.getRunCompletionExport(runId, ctx.access, {
      contextPackId: contextResult.contextPack.id,
      status: contextResult.status,
      retrievedItems: contextResult.items.length,
      appliedItems: 0,
      degradation: contextResult.degradation
        ? {
            code: contextResult.degradation.code,
            explanation: "Second Brain context was unavailable; audited fixed report defaults were used.",
          }
        : null,
      influenceSummary,
    });
    repository.recordRunCompletionExport(exported, ctx.actor);
    const filename = completionExportFilename(runId);
    response.status(200);
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    response.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    response.setHeader("Content-Security-Policy", "sandbox");
    response.send(`${JSON.stringify(exported, null, 2)}\n`);
  }));
  router.get("/api/v2/reports/:artifactId/download", handle(dependencies, (request, response, { access }) => {
    const download = missionReports.download(
      identifier(request.params.artifactId, "Report artifact ID"),
      access,
    );
    inertDownloadHeaders(response, download.filename, download.mediaType, download.byteSize);
    response.setHeader("Digest", `sha-256=${Buffer.from(download.contentHash, "hex").toString("base64")}`);
    response.status(200).send(download.body);
  }));
  router.get("/api/v2/reports/:artifactId", handle(dependencies, (request, response, { access }) => {
    response.json(repository.getReport(identifier(request.params.artifactId, "Report artifact ID"), access));
  }));

  router.get("/api/v2/system/providers", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listProviders(access, { limit: limit(request), cursor: cursor(request) }));
  }));
  router.get("/api/v2/system/mcp", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listMcpServers(access, {
      limit: limit(request), cursor: cursor(request),
      status: optionalEnum(value(request, "status"), MCP_STATUSES, "status"),
    }));
  }));
  router.get("/api/v2/system/health", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listHealth(access, {
      limit: limit(request), cursor: cursor(request),
      componentType: plainFilter(request, "componentType"),
      componentId: optionalIdentifier(value(request, "componentId"), "Component ID"),
      status: optionalEnum(value(request, "status"), HEALTH_STATUSES, "status"),
    }));
  }));
  router.get("/api/v2/system/policies", handle(dependencies, (request, response, { access }) => {
    response.json(repository.listSystemPolicies(access, { limit: limit(request), cursor: cursor(request) }));
  }));

  return router;
}

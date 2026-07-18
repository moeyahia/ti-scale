import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import {
  ControlPlaneLeaseError,
  RunMutationAuthorityGuard,
  describeRunMutationAuthorityError,
  type AssertRunMutationLease,
} from "../control-plane";
import type { SqliteDatabase } from "../db";
import { BrainContextHookError, type BrainContextService } from "../brain-runtime";
import { missing, OperationalTruthError, policyDenied, scopeConflict } from "./errors";
import { FailureDiagnosisService } from "./FailureDiagnosisService";
import {
  appendLogInput,
  authenticatedActor,
  candidateDecisionInput,
  candidateInput,
  candidateState,
  encodePageCursor,
  failureDiagnosisInput,
  failureStates,
  observationInput,
  pageCursor,
  pageLimit,
  queryIdentifier,
  requiredIdempotencyKey,
  resolveFailureInput,
  verifyEvidenceInput,
  verifyFindingInput,
} from "./httpValidation";
import { OperationalTruthService } from "./OperationalTruthService";
import type { RepositoryOptions } from "./OperationalTruthRepository";
import { RouterIdempotencyStore } from "./RouterIdempotencyStore";
import type { JsonValue, OperationalActor, OperationalTruthPage } from "./types";
import { identifier } from "./validation";

const SCHEMA_VERSION = "2.4" as const;

export type OperationalTruthCapability =
  | "read"
  | "ingest"
  | "review_evidence"
  | "verify_finding"
  | "diagnose"
  | "resolve_diagnosis";

export interface OperationalTruthAuthorizationRequest {
  readonly missionId: string;
  readonly capability: OperationalTruthCapability;
}

export interface OperationalTruthRouterDependencies extends RepositoryOptions {
  readonly database: SqliteDatabase;
  readonly brainContext?: BrainContextService;
  readonly resolveActor: (request: Request) => OperationalActor | undefined;
  readonly authorize: (
    request: Request,
    actor: OperationalActor,
    authorization: OperationalTruthAuthorizationRequest,
  ) => boolean;
  readonly basePath?: string;
  /** Trusted server callback; raw control-plane tokens never cross HTTP. */
  readonly assertRunMutationLease?: AssertRunMutationLease;
}

interface RouteContext {
  readonly actor: OperationalActor;
  readonly missionId: string;
}

type RouteHandler = (request: Request, response: Response, context: RouteContext) => void;

function basePath(value: string | undefined): string {
  const normalized = value ?? "/api/v2/operational-truth";
  if (!normalized.startsWith("/") || normalized.endsWith("/") || /[?#]/u.test(normalized)) {
    throw new Error("OperationalTruthRouter basePath must be an absolute path without a trailing slash");
  }
  return normalized;
}

function statusFor(error: OperationalTruthError): number {
  if (error.code === "authentication_required") return 401;
  if (error.code === "sensitive_material_rejected") return 422;
  switch (error.category) {
    case "not_found": return 404;
    case "policy_denied": return 403;
    case "scope_conflict":
    case "state_conflict":
    case "evidence_insufficient": return 409;
    case "invalid_input": return 400;
  }
}

function sendError(response: Response, error: unknown, traceId: string): void {
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
  if (error instanceof BrainContextHookError) {
    sendV2Error(response, traceId, {
      status: error.code === "brain_context_unavailable" ? 503 : 500,
      code: error.code,
      message: error.message,
      humanMessage: error.code === "brain_context_unavailable"
        ? "Finding verification did not proceed because required scoped Second Brain context is unavailable."
        : "Finding verification did not proceed because its Second Brain context receipt could not be established.",
      retryable: error.code === "brain_context_unavailable",
      category: "dependency_missing",
      details: { hook: error.hook, auditRecordId: error.auditRecordId ?? null },
      remediation: "Restore the local Second Brain dependency and retry verification against the unchanged finding version.",
    });
    return;
  }
  if (error instanceof OperationalTruthError) {
    const authentication = error.code === "authentication_required";
    sendV2Error(response, traceId, {
      status: statusFor(error),
      code: error.code,
      message: error.message,
      humanMessage: error.message,
      retryable: false,
      category: authentication ? "authentication_missing" : error.category,
      ...(error.remediation ? { remediation: error.remediation } : {}),
    });
    return;
  }
  sendV2Error(response, traceId, {
    status: 500,
    code: "operational_truth_internal_error",
    message: "Operational truth could not complete the request",
    humanMessage: "The operational-truth service encountered an internal error.",
    retryable: false,
    category: "internal",
    remediation: "Use the request ID to inspect redacted structured logs before retrying.",
  });
}

function requireHumanReviewer(actor: OperationalActor): void {
  if (actor.type !== "operator") {
    throw policyDenied(
      "A human operator must perform evidence and finding review mutations",
      "Use an authenticated operator identity or call the internal service through an approved supervisor workflow.",
    );
  }
}

function pageEnvelope<T>(result: OperationalTruthPage<T>): JsonValue {
  return {
    schemaVersion: SCHEMA_VERSION,
    items: result.items as unknown as JsonValue,
    nextCursor: result.nextCursor ? encodePageCursor(result.nextCursor) : null,
  };
}

function assertMission(actual: string, expected: string, resource: string): void {
  if (actual !== expected) throw missing(resource);
}

function mutableRunId(runId: string | undefined, resource: string): string {
  if (runId) return runId;
  throw policyDenied(
    `${resource} is not linked to a canonical run and remains read-only in Ti-Scale`,
    "Import or reconcile the record with its originating V2-owned run before attempting a mutation.",
  );
}

/**
 * Authenticated V2 HTTP boundary for the operational-truth ladder.
 * This factory is intentionally unmounted; the V2 composition root owns cutover.
 */
export function createOperationalTruthRouter(
  dependencies: OperationalTruthRouterDependencies,
): Router {
  const truth = new OperationalTruthService(dependencies.database, dependencies);
  const failures = new FailureDiagnosisService(dependencies.database, dependencies);
  const idempotency = new RouterIdempotencyStore(dependencies.database, dependencies.clock);
  const mutationAuthority = new RunMutationAuthorityGuard(dependencies.database, dependencies.clock);
  const router = Router();
  const prefix = basePath(dependencies.basePath);

  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  const route = (capability: OperationalTruthCapability, handler: RouteHandler) =>
    (request: Request, response: Response): void => {
      const traceId = attachV2RequestId(request, response);
      try {
        const actor = authenticatedActor(dependencies.resolveActor(request));
        const missionId = identifier(request.params.missionId, "missionId");
        if (!dependencies.authorize(request, actor, { missionId, capability })) {
          throw policyDenied(
            "This identity cannot perform the requested operational-truth action for this mission",
            "Use an identity with explicit access to the mission and requested capability.",
          );
        }
        handler(request, response, { actor, missionId });
      } catch (error) {
        sendError(response, error, traceId);
      }
    };

  const mutation = (
    request: Request,
    response: Response,
    context: RouteContext,
    runId: string,
    scope: string,
    status: number,
    operation: () => unknown,
  ): void => {
    // Resolve the trusted runtime proof before consulting durable replay state;
    // an idempotency receipt must never become a mutation-authority cache.
    const authority = mutationAuthority.authorize({
      runId,
      actorId: context.actor.id,
      mode: "lease",
      ...(dependencies.assertRunMutationLease
        ? { assertLease: dependencies.assertRunMutationLease }
        : {}),
    });
    if (authority.scope.missionId !== context.missionId) {
      throw scopeConflict("Mutation run does not belong to the operational-truth mission");
    }
    const key = requiredIdempotencyKey(request.get("Idempotency-Key"));
    const result = idempotency.execute(
      scope,
      key,
      context.actor,
      {
        missionId: context.missionId,
        // Express 5 exposes route and query parameters as null-prototype
        // framework objects. Copy only their enumerable decoded values into
        // plain JSON records before the strict immutable-idempotency
        // serializer sees them.
        params: { ...request.params },
        query: { ...request.query },
        body: request.body,
      },
      () => {
        // This callback executes inside RouterIdempotencyStore's IMMEDIATE
        // transaction for both the operational mutation and its receipt.
        authority.assertCurrent();
        return operation();
      },
    );
    response.setHeader("Idempotency-Replayed", result.replayed ? "true" : "false");
    response.status(status).json(result.response);
  };

  router.get(`${prefix}/missions/:missionId/logs`, route("read", (request, response, context) => {
    const runId = queryIdentifier(request.query.runId, "runId");
    const stepId = queryIdentifier(request.query.stepId, "stepId");
    const cursor = pageCursor(request.query.cursor);
    response.json(pageEnvelope(truth.repository.listLogs({
      missionId: context.missionId,
      ...(runId ? { runId } : {}),
      ...(stepId ? { stepId } : {}),
      limit: pageLimit(request.query.limit),
      ...(cursor ? { cursor } : {}),
    })));
  }));

  router.post(`${prefix}/missions/:missionId/logs`, route("ingest", (request, response, context) => {
    const input = appendLogInput(context.missionId, request.body);
    if (context.actor.type === "agent" && input.agentId && input.agentId !== context.actor.id) {
      throw policyDenied("An agent cannot attribute an engagement log to another agent");
    }
    const attributed = context.actor.type === "agent" ? { ...input, agentId: context.actor.id } : input;
    mutation(request, response, context, mutableRunId(attributed.runId, "Engagement log"), "log.create", 201, () => ({
      schemaVersion: SCHEMA_VERSION,
      log: truth.appendEngagementLog(attributed),
    }));
  }));

  router.get(`${prefix}/missions/:missionId/logs/:logId`, route("read", (request, response, context) => {
    const log = truth.repository.getLog(identifier(request.params.logId, "logId"));
    assertMission(log.missionId, context.missionId, "engagement_log_record");
    response.json({ schemaVersion: SCHEMA_VERSION, log });
  }));

  router.get(`${prefix}/missions/:missionId/observations`, route("read", (request, response, context) => {
    const runId = queryIdentifier(request.query.runId, "runId");
    const stepId = queryIdentifier(request.query.stepId, "stepId");
    const cursor = pageCursor(request.query.cursor);
    response.json(pageEnvelope(truth.repository.listObservations({
      missionId: context.missionId,
      ...(runId ? { runId } : {}),
      ...(stepId ? { stepId } : {}),
      limit: pageLimit(request.query.limit),
      ...(cursor ? { cursor } : {}),
    })));
  }));

  router.post(`${prefix}/missions/:missionId/observations`, route("ingest", (request, response, context) => {
    const input = observationInput(context.missionId, request.body);
    if (context.actor.type === "agent" && input.sourceAgentId && input.sourceAgentId !== context.actor.id) {
      throw policyDenied("An agent cannot attribute an observation to another agent");
    }
    const attributed = context.actor.type === "agent"
      ? { ...input, sourceAgentId: context.actor.id }
      : input;
    mutation(request, response, context, mutableRunId(attributed.runId, "Observation"), "observation.create", 201, () => ({
      schemaVersion: SCHEMA_VERSION,
      observation: truth.createObservation(attributed),
    }));
  }));

  router.get(`${prefix}/missions/:missionId/observations/:observationId`, route("read", (request, response, context) => {
    const observation = truth.repository.getObservation(identifier(request.params.observationId, "observationId"));
    assertMission(observation.missionId, context.missionId, "observation");
    response.json({ schemaVersion: SCHEMA_VERSION, observation });
  }));

  router.get(`${prefix}/missions/:missionId/evidence-candidates`, route("read", (request, response, context) => {
    const runId = queryIdentifier(request.query.runId, "runId");
    const stepId = queryIdentifier(request.query.stepId, "stepId");
    const cursor = pageCursor(request.query.cursor);
    const state = candidateState(request.query.state);
    response.json(pageEnvelope(truth.repository.listCandidates({
      missionId: context.missionId,
      ...(runId ? { runId } : {}),
      ...(stepId ? { stepId } : {}),
      ...(state ? { state } : {}),
      limit: pageLimit(request.query.limit),
      ...(cursor ? { cursor } : {}),
    })));
  }));

  router.post(`${prefix}/missions/:missionId/evidence-candidates`, route("ingest", (request, response, context) => {
    const input = candidateInput(context.missionId, request.body, context.actor);
    mutation(request, response, context, mutableRunId(input.runId, "Evidence candidate"), "candidate.create", 201, () => ({
      schemaVersion: SCHEMA_VERSION,
      candidate: truth.proposeEvidenceCandidate(input),
    }));
  }));

  router.get(`${prefix}/missions/:missionId/evidence-candidates/:candidateId`, route("read", (request, response, context) => {
    const candidate = truth.repository.getCandidate(identifier(request.params.candidateId, "candidateId"));
    assertMission(candidate.missionId, context.missionId, "evidence_candidate");
    response.json({ schemaVersion: SCHEMA_VERSION, candidate });
  }));

  const candidateMutation = (
    action: "promote" | "reject" | "demote",
    operation: "review_evidence",
  ) => route(operation, (request, response, context) => {
    requireHumanReviewer(context.actor);
    const candidateId = identifier(request.params.candidateId, "candidateId");
    const current = truth.repository.getCandidate(candidateId);
    assertMission(current.missionId, context.missionId, "evidence_candidate");
    const input = candidateDecisionInput(candidateId, request.body, context.actor);
    const execute = action === "promote"
      ? () => truth.promoteCandidate(input)
      : action === "reject"
        ? () => truth.rejectCandidate(input)
        : () => truth.demoteCandidate(input);
    mutation(request, response, context, mutableRunId(current.runId, "Evidence candidate"), `candidate.${action}`, 200, () => ({
      schemaVersion: SCHEMA_VERSION,
      candidate: execute(),
    }));
  });

  router.post(
    `${prefix}/missions/:missionId/evidence-candidates/:candidateId/promote`,
    candidateMutation("promote", "review_evidence"),
  );
  router.post(
    `${prefix}/missions/:missionId/evidence-candidates/:candidateId/reject`,
    candidateMutation("reject", "review_evidence"),
  );
  router.post(
    `${prefix}/missions/:missionId/evidence-candidates/:candidateId/demote`,
    candidateMutation("demote", "review_evidence"),
  );

  router.post(
    `${prefix}/missions/:missionId/evidence-candidates/:candidateId/verify`,
    route("review_evidence", (request, response, context) => {
      requireHumanReviewer(context.actor);
      const candidateId = identifier(request.params.candidateId, "candidateId");
      const current = truth.repository.getCandidate(candidateId);
      assertMission(current.missionId, context.missionId, "evidence_candidate");
      const input = verifyEvidenceInput(candidateId, request.body, context.actor);
      mutation(request, response, context, mutableRunId(current.runId, "Evidence candidate"), "candidate.verify", 201, () => ({
        schemaVersion: SCHEMA_VERSION,
        evidence: truth.verifyCandidate(input),
      }));
    }),
  );

  router.get(`${prefix}/missions/:missionId/verified-evidence`, route("read", (request, response, context) => {
    const runId = queryIdentifier(request.query.runId, "runId");
    const stepId = queryIdentifier(request.query.stepId, "stepId");
    const cursor = pageCursor(request.query.cursor);
    response.json(pageEnvelope(truth.repository.listVerifiedEvidence({
      missionId: context.missionId,
      ...(runId ? { runId } : {}),
      ...(stepId ? { stepId } : {}),
      limit: pageLimit(request.query.limit),
      ...(cursor ? { cursor } : {}),
    })));
  }));

  router.get(`${prefix}/missions/:missionId/verified-evidence/:evidenceId`, route("read", (request, response, context) => {
    const evidence = truth.repository.getVerifiedEvidence(identifier(request.params.evidenceId, "evidenceId"));
    assertMission(evidence.missionId, context.missionId, "evidence");
    response.json({
      schemaVersion: SCHEMA_VERSION,
      evidence,
      chainOfCustody: truth.repository.listEvidenceCustody(evidence.id),
    });
  }));

  router.get(
    `${prefix}/missions/:missionId/findings/:findingId/verification-readiness`,
    route("read", (request, response, context) => {
      const findingId = identifier(request.params.findingId, "findingId");
      truth.repository.assertFindingMission(findingId, context.missionId);
      response.json({
        schemaVersion: SCHEMA_VERSION,
        readiness: truth.findingVerificationReadiness(findingId),
      });
    }),
  );

  router.post(
    `${prefix}/missions/:missionId/findings/:findingId/verify`,
    route("verify_finding", (request, response, context) => {
      requireHumanReviewer(context.actor);
      const findingId = identifier(request.params.findingId, "findingId");
      const current = truth.repository.findingRow(findingId);
      assertMission(current.mission_id, context.missionId, "finding");
      const input = verifyFindingInput(findingId, request.body, context.actor);
      mutation(request, response, context, mutableRunId(current.run_id ?? undefined, "Finding"), "finding.verify", 200, () => ({
        schemaVersion: SCHEMA_VERSION,
        readiness: truth.verifyFinding(input),
      }));
    }),
  );

  router.get(
    `${prefix}/missions/:missionId/runs/:runId/failure-diagnoses`,
    route("read", (request, response, context) => {
      const runId = identifier(request.params.runId, "runId");
      truth.repository.assertCanonicalScope({ missionId: context.missionId, runId });
      response.json({
        schemaVersion: SCHEMA_VERSION,
        items: failures.listForRun(runId, failureStates(request.query.states), pageLimit(request.query.limit)),
      });
    }),
  );

  router.post(
    `${prefix}/missions/:missionId/runs/:runId/failure-diagnoses`,
    route("diagnose", (request, response, context) => {
      const runId = identifier(request.params.runId, "runId");
      truth.repository.assertCanonicalScope({ missionId: context.missionId, runId });
      const input = failureDiagnosisInput(context.missionId, runId, request.body, context.actor);
      mutation(request, response, context, runId, "failure.create", 201, () => ({
        schemaVersion: SCHEMA_VERSION,
        diagnosis: failures.create(input),
      }));
    }),
  );

  router.get(
    `${prefix}/missions/:missionId/runs/:runId/failure-diagnoses/:diagnosisId`,
    route("read", (request, response, context) => {
      const runId = identifier(request.params.runId, "runId");
      const diagnosis = failures.get(identifier(request.params.diagnosisId, "diagnosisId"));
      assertMission(diagnosis.missionId, context.missionId, "failure_diagnosis");
      if (diagnosis.runId !== runId) throw missing("failure_diagnosis");
      response.json({ schemaVersion: SCHEMA_VERSION, diagnosis });
    }),
  );

  router.post(
    `${prefix}/missions/:missionId/runs/:runId/failure-diagnoses/:diagnosisId/resolve`,
    route("resolve_diagnosis", (request, response, context) => {
      if (context.actor.type !== "operator" && context.actor.type !== "system") {
        throw policyDenied("Only an operator or trusted supervisor may resolve a failure diagnosis");
      }
      const runId = identifier(request.params.runId, "runId");
      const diagnosisId = identifier(request.params.diagnosisId, "diagnosisId");
      const current = failures.get(diagnosisId);
      assertMission(current.missionId, context.missionId, "failure_diagnosis");
      if (current.runId !== runId) throw missing("failure_diagnosis");
      const input = resolveFailureInput(diagnosisId, request.body, context.actor);
      mutation(request, response, context, runId, "failure.resolve", 200, () => ({
        schemaVersion: SCHEMA_VERSION,
        diagnosis: failures.resolve(input),
      }));
    }),
  );

  return router;
}

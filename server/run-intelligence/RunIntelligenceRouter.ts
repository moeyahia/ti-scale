import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import {
  ControlPlaneLeaseError,
  RunMutationAuthorityGuard,
  describeRunMutationAuthorityError,
  type AssertRunMutationLease,
  type RunMutationAuthorityMode,
} from "../control-plane";
import type { SqliteDatabase } from "../db";
import { BrainContextHookError, type BrainContextService } from "../brain-runtime";
import { AttackAttemptService } from "./AttackAttemptService";
import { ReconDigitalTwinService } from "./ReconDigitalTwinService";
import {
  authenticationRequired,
  RunIntelligenceHttpError,
  runIntelligencePolicyDenied,
  runIntelligenceResourceNotFound,
} from "./RunIntelligenceHttpError";
import {
  attackAttemptTransitionBody,
  createAttackAttemptInput,
  createTopologyEdgeInput,
  createTopologyNodeInput,
  emptyMutationBody,
  queryIdentifier,
  queryLimit,
  recordOsiObservationInput,
  requiredIdempotencyKey,
  stableIdentifier,
} from "./RunIntelligenceHttpValidation";
import { RunIntelligenceIdempotencyStore } from "./RunIntelligenceIdempotencyStore";
import { RunMetricsService } from "./RunMetricsService";
import { RunIntelligenceError } from "./types";

const SCHEMA_VERSION = "2.4" as const;
const ACTOR_TYPES = new Set<RunIntelligenceActor["type"]>([
  "operator", "reviewer", "admin", "agent", "worker", "system",
]);

export interface RunIntelligenceActor {
  readonly id: string;
  readonly type: "operator" | "reviewer" | "admin" | "agent" | "worker" | "system";
}

export type RunIntelligenceCapability =
  | "read_metrics"
  | "recompute_metrics"
  | "read_attack_attempts"
  | "manage_attack_attempts"
  | "read_topology"
  | "manage_topology";

export type RunIntelligenceResource = "metrics" | "attack_attempts" | "topology" | "osi";

export interface RunIntelligenceAuthorizationRequest {
  readonly missionId: string;
  readonly runId?: string;
  readonly capability: RunIntelligenceCapability;
  readonly resource: RunIntelligenceResource;
}

export interface RunIntelligenceRouterDependencies {
  readonly database: SqliteDatabase;
  readonly resolveActor: (request: Request) => RunIntelligenceActor | undefined;
  readonly authorize: (
    request: Request,
    actor: RunIntelligenceActor,
    authorization: RunIntelligenceAuthorizationRequest,
  ) => boolean;
  readonly basePath?: string;
  readonly clock?: () => Date;
  /** Trusted server callback; raw control-plane tokens never cross HTTP. */
  readonly assertRunMutationLease?: AssertRunMutationLease;
  readonly brainContext?: BrainContextService;
}

interface RouteContext {
  readonly actor: RunIntelligenceActor;
  readonly missionId: string;
  readonly runId?: string;
}

type RouteHandler = (request: Request, response: Response, context: RouteContext) => void;

function normalizedBasePath(value: string | undefined): string {
  const normalized = value ?? "/api/v2";
  if (!normalized.startsWith("/") || normalized.endsWith("/") || /[?#]/u.test(normalized)) {
    throw new Error("RunIntelligenceRouter basePath must be an absolute path without a trailing slash");
  }
  return normalized;
}

function authenticatedActor(value: RunIntelligenceActor | undefined): RunIntelligenceActor {
  if (!value || !ACTOR_TYPES.has(value.type)) throw authenticationRequired();
  return { id: stableIdentifier(value.id, "actor.id"), type: value.type };
}

function serviceErrorDescriptor(error: RunIntelligenceError): {
  readonly status: number;
  readonly category: string;
  readonly remediation: string;
} | null {
  if (
    error.code === "metrics_snapshot_corrupt"
    || error.code === "metrics_schema_mismatch"
    || error.code === "topology_properties_corrupt"
    || error.code === "topology_provenance_corrupt"
  ) return null;
  if (error.code.endsWith("_not_found")) {
    return {
      status: 404,
      category: "not_found",
      remediation: "Refresh the parent mission or run and use a canonical resource link.",
    };
  }
  if (
    error.code.includes("mismatch")
    || error.code.includes("scope")
    || error.code === "self_topology_edge"
  ) {
    return {
      status: 409,
      category: "scope_conflict",
      remediation: "Use resources that belong to the authorized mission and run.",
    };
  }
  if (
    error.code.includes("evidence_required")
    || error.code.includes("requires_verified_evidence")
    || error.code === "evidence_rejected"
    || error.code.endsWith("_evidence_rejected")
    || error.code === "corroboration_requires_multiple_sources"
    || error.code === "conflict_evidence_required"
    || error.code === "osi_verification_mismatch"
  ) {
    return {
      status: 409,
      category: "evidence_insufficient",
      remediation: "Attach canonical in-scope evidence that satisfies the requested verification state.",
    };
  }
  if (
    error.code.includes("transition")
    || error.code === "canonical_state_changed_without_event"
  ) {
    return {
      status: 409,
      category: "state_conflict",
      remediation: "Reload the current version and retry only if the transition remains valid.",
    };
  }
  return {
    status: 400,
    category: "invalid_input",
    remediation: "Correct the request using canonical mission, run, evidence, and topology references.",
  };
}

function sendError(response: Response, traceId: string, error: unknown): void {
  if (error instanceof BrainContextHookError) {
    sendV2Error(response, traceId, {
      status: error.code === "brain_context_unavailable" ? 503 : 500,
      code: error.code,
      message: error.message,
      humanMessage: error.code === "brain_context_unavailable"
        ? `The represented attack attempt did not start because required Second Brain context for ${error.hook.replaceAll("_", " ")} is unavailable.`
        : "The represented attack attempt did not start because its Second Brain context receipt could not be established.",
      retryable: error.code === "brain_context_unavailable",
      category: "dependency_missing",
      details: { hook: error.hook, auditRecordId: error.auditRecordId ?? null },
      remediation: "Restore the local Second Brain dependency and retry this unchanged represented transition.",
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
  if (error instanceof RunIntelligenceHttpError) {
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
  if (error instanceof RunIntelligenceError) {
    const descriptor = serviceErrorDescriptor(error);
    if (descriptor) {
      sendV2Error(response, traceId, {
        status: descriptor.status,
        code: error.code,
        message: error.message,
        humanMessage: error.message,
        retryable: false,
        category: descriptor.category,
        remediation: descriptor.remediation,
      });
      return;
    }
  }
  sendV2Error(response, traceId, {
    status: 500,
    code: "run_intelligence_internal_error",
    message: "Run intelligence could not complete the request",
    humanMessage: "The run-intelligence service encountered an internal error.",
    retryable: false,
    category: "internal",
    remediation: "Use the request ID to inspect redacted structured logs before retrying.",
  });
}

function runScope(database: SqliteDatabase, runId: string): { readonly missionId: string; readonly runId: string } {
  const row = database.prepare("SELECT mission_id FROM runs WHERE id = ?").get(runId) as
    | { readonly mission_id: string }
    | undefined;
  if (!row) throw new RunIntelligenceError("run_not_found", `Run not found: ${runId}`);
  return { missionId: row.mission_id, runId };
}

function assertMissionExists(database: SqliteDatabase, missionId: string): void {
  if (!database.prepare("SELECT id FROM missions WHERE id = ?").get(missionId)) {
    throw new RunIntelligenceError("mission_not_found", `Mission not found: ${missionId}`);
  }
}

function assertRunResource(actualRunId: string, expectedRunId: string, resource: string): void {
  if (actualRunId !== expectedRunId) throw runIntelligenceResourceNotFound(resource);
}

function assertMissionResource(actualMissionId: string, expectedMissionId: string, resource: string): void {
  if (actualMissionId !== expectedMissionId) throw runIntelligenceResourceNotFound(resource);
}

function canonicalMutationContext(
  database: SqliteDatabase,
  context: RouteContext,
  runId: string | null | undefined,
  resource: string,
): RouteContext & { readonly runId: string } {
  if (!runId) {
    throw new ControlPlaneLeaseError(
      "control_plane_mismatch",
      `${resource} is not linked to a canonical run and remains read-only in Ti-Scale`,
    );
  }
  const scope = runScope(database, runId);
  if (scope.missionId !== context.missionId) {
    throw new RunIntelligenceError("run_mission_mismatch", `${resource} run does not belong to the supplied mission`);
  }
  return { ...context, runId };
}

/**
 * Authenticated V2 boundary for reproducible metrics, attack attempts, and the
 * evidence-backed recon twin. Intentionally unmounted: the composition root
 * owns preview exposure and its authentication middleware order.
 */
export function createRunIntelligenceRouter(dependencies: RunIntelligenceRouterDependencies): Router {
  const metrics = new RunMetricsService(dependencies.database, dependencies.clock);
  const attempts = new AttackAttemptService(dependencies.database, dependencies.clock, dependencies.brainContext);
  const topology = new ReconDigitalTwinService(dependencies.database, dependencies.clock);
  const idempotency = new RunIntelligenceIdempotencyStore(dependencies.database, dependencies.clock);
  const mutationAuthority = new RunMutationAuthorityGuard(dependencies.database, dependencies.clock);
  const router = Router();
  const prefix = normalizedBasePath(dependencies.basePath);

  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  const runRoute = (
    capability: RunIntelligenceCapability,
    resource: RunIntelligenceResource,
    handler: RouteHandler,
  ) => (request: Request, response: Response): void => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = authenticatedActor(dependencies.resolveActor(request));
      const scope = runScope(dependencies.database, stableIdentifier(request.params.runId, "runId"));
      if (!dependencies.authorize(request, actor, { ...scope, capability, resource })) {
        throw runIntelligencePolicyDenied();
      }
      handler(request, response, { actor, ...scope });
    } catch (error) {
      sendError(response, traceId, error);
    }
  };

  const missionRoute = (
    capability: RunIntelligenceCapability,
    resource: RunIntelligenceResource,
    handler: RouteHandler,
  ) => (request: Request, response: Response): void => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = authenticatedActor(dependencies.resolveActor(request));
      const missionId = stableIdentifier(request.params.missionId, "missionId");
      assertMissionExists(dependencies.database, missionId);
      const runId = queryIdentifier(request.query.runId, "runId");
      if (runId) {
        const scope = runScope(dependencies.database, runId);
        if (scope.missionId !== missionId) {
          throw new RunIntelligenceError("run_mission_mismatch", "Run does not belong to the supplied mission");
        }
      }
      if (!dependencies.authorize(request, actor, {
        missionId,
        ...(runId ? { runId } : {}),
        capability,
        resource,
      })) throw runIntelligencePolicyDenied();
      handler(request, response, { actor, missionId, ...(runId ? { runId } : {}) });
    } catch (error) {
      sendError(response, traceId, error);
    }
  };

  const mutate = (
    request: Request,
    response: Response,
    context: RouteContext,
    scope: string,
    requestValue: unknown,
    status: number,
    operation: () => unknown,
    authorityMode?: RunMutationAuthorityMode,
  ): void => {
    // Authorization is checked before the replay lookup so an idempotency
    // receipt can never become a mutation-authority cache.
    const authority = authorityMode === undefined
      ? undefined
      : mutationAuthority.authorize({
          runId: context.runId!,
          actorId: context.actor.id,
          mode: authorityMode,
          ...(dependencies.assertRunMutationLease
            ? { assertLease: dependencies.assertRunMutationLease }
            : {}),
        });
    if (authority && authority.scope.missionId !== context.missionId) {
      throw new RunIntelligenceError("run_mission_mismatch", "Mutation run does not belong to the supplied mission");
    }
    const result = idempotency.execute(
      scope,
      requiredIdempotencyKey(request.get("Idempotency-Key")),
      context.actor,
      requestValue,
      () => {
        authority?.assertCurrent();
        return operation();
      },
    );
    response.setHeader("Idempotency-Replayed", result.replayed ? "true" : "false");
    response.status(status).json(result.response);
  };

  router.get(`${prefix}/runs/:runId/intelligence/metrics/snapshots`, runRoute(
    "read_metrics",
    "metrics",
    (request, response, context) => {
      const items = metrics.list(context.runId!, queryLimit(request.query.limit));
      response.json({
        schemaVersion: SCHEMA_VERSION,
        items,
        latestSnapshotId: items[0]?.id ?? null,
      });
    },
  ));

  router.get(`${prefix}/runs/:runId/intelligence/metrics/snapshots/:snapshotId`, runRoute(
    "read_metrics",
    "metrics",
    (request, response, context) => {
      const snapshot = metrics.get(stableIdentifier(request.params.snapshotId, "snapshotId"));
      assertRunResource(snapshot.runId, context.runId!, "metrics_snapshot");
      response.json({ schemaVersion: SCHEMA_VERSION, snapshot });
    },
  ));

  router.post(`${prefix}/runs/:runId/intelligence/metrics/recompute`, runRoute(
    "recompute_metrics",
    "metrics",
    (request, response, context) => {
      const body = emptyMutationBody(request.body);
      mutate(
        request,
        response,
        context,
        `metrics.recompute:${context.runId!}`,
        { runId: context.runId, body },
        200,
        () => ({ schemaVersion: SCHEMA_VERSION, snapshot: metrics.recomputeAndStore(context.runId!) }),
        "ownership",
      );
    },
  ));

  router.get(`${prefix}/runs/:runId/intelligence/attack-attempts`, runRoute(
    "read_attack_attempts",
    "attack_attempts",
    (_request, response, context) => {
      response.json({ schemaVersion: SCHEMA_VERSION, items: attempts.listForRun(context.runId!) });
    },
  ));

  router.get(`${prefix}/runs/:runId/intelligence/attack-attempts/:attemptId`, runRoute(
    "read_attack_attempts",
    "attack_attempts",
    (request, response, context) => {
      const attempt = attempts.get(stableIdentifier(request.params.attemptId, "attemptId"));
      assertRunResource(attempt.runId, context.runId!, "attack_attempt");
      response.json({ schemaVersion: SCHEMA_VERSION, attempt });
    },
  ));

  router.post(`${prefix}/runs/:runId/intelligence/attack-attempts`, runRoute(
    "manage_attack_attempts",
    "attack_attempts",
    (request, response, context) => {
      const input = createAttackAttemptInput(context.missionId, context.runId!, request.body);
      mutate(
        request,
        response,
        context,
        `attack_attempt.create:${context.runId!}`,
        input,
        201,
        () => ({ schemaVersion: SCHEMA_VERSION, attempt: attempts.create(input) }),
        "lease",
      );
    },
  ));

  router.post(`${prefix}/runs/:runId/intelligence/attack-attempts/:attemptId/transition`, runRoute(
    "manage_attack_attempts",
    "attack_attempts",
    (request, response, context) => {
      const attemptId = stableIdentifier(request.params.attemptId, "attemptId");
      const current = attempts.get(attemptId);
      assertRunResource(current.runId, context.runId!, "attack_attempt");
      const body = attackAttemptTransitionBody(request.body);
      mutate(
        request,
        response,
        context,
        `attack_attempt.transition:${context.runId!}:${attemptId}`,
        { attemptId, body },
        200,
        () => ({
          schemaVersion: SCHEMA_VERSION,
          attempt: body.kind === "state"
            ? attempts.transition({
                attemptId,
                expectedVersion: body.expectedVersion,
                status: body.status,
                ...(body.reason ? { reason: body.reason } : {}),
                ...(body.at ? { at: body.at } : {}),
                actorId: context.actor.id,
                actorType: context.actor.type === "reviewer" || context.actor.type === "admin"
                  ? "operator"
                  : context.actor.type,
              })
            : attempts.complete({
                attemptId,
                expectedVersion: body.expectedVersion,
                outcome: body.outcome,
                outcomeSummary: body.outcomeSummary,
                ...(body.failureCategory ? { failureCategory: body.failureCategory } : {}),
                ...(body.failureDiagnosisId ? { failureDiagnosisId: body.failureDiagnosisId } : {}),
                ...(body.evidence ? { evidence: body.evidence } : {}),
                ...(body.endedAt ? { endedAt: body.endedAt } : {}),
              }),
        }),
        "lease",
      );
    },
  ));

  router.get(`${prefix}/missions/:missionId/intelligence/topology`, missionRoute(
    "read_topology",
    "topology",
    (_request, response, context) => {
      response.json({ schemaVersion: SCHEMA_VERSION, digitalTwin: topology.getGraph(context.missionId, context.runId) });
    },
  ));

  router.get(`${prefix}/missions/:missionId/intelligence/topology/nodes`, missionRoute(
    "read_topology",
    "topology",
    (_request, response, context) => {
      const graph = topology.getGraph(context.missionId, context.runId);
      response.json({ schemaVersion: SCHEMA_VERSION, items: graph.nodes });
    },
  ));

  router.post(`${prefix}/missions/:missionId/intelligence/topology/nodes`, missionRoute(
    "manage_topology",
    "topology",
    (request, response, context) => {
      const input = createTopologyNodeInput(context.missionId, request.body);
      const mutationContext = canonicalMutationContext(
        dependencies.database,
        context,
        input.runId,
        "Topology node",
      );
      mutate(
        request,
        response,
        mutationContext,
        `topology.node.create:${context.missionId}`,
        input,
        201,
        () => ({ schemaVersion: SCHEMA_VERSION, node: topology.createNode(input) }),
        "lease",
      );
    },
  ));

  router.get(`${prefix}/missions/:missionId/intelligence/topology/nodes/:nodeId`, missionRoute(
    "read_topology",
    "topology",
    (request, response, context) => {
      const node = topology.repository.getNode(stableIdentifier(request.params.nodeId, "nodeId"));
      assertMissionResource(node.missionId, context.missionId, "topology_node");
      response.json({ schemaVersion: SCHEMA_VERSION, node });
    },
  ));

  router.get(`${prefix}/missions/:missionId/intelligence/topology/edges`, missionRoute(
    "read_topology",
    "topology",
    (_request, response, context) => {
      const graph = topology.getGraph(context.missionId, context.runId);
      response.json({ schemaVersion: SCHEMA_VERSION, items: graph.edges });
    },
  ));

  router.post(`${prefix}/missions/:missionId/intelligence/topology/edges`, missionRoute(
    "manage_topology",
    "topology",
    (request, response, context) => {
      const input = createTopologyEdgeInput(context.missionId, request.body);
      const source = topology.repository.getNode(input.sourceNodeId);
      const target = topology.repository.getNode(input.targetNodeId);
      assertMissionResource(source.missionId, context.missionId, "topology_source_node");
      assertMissionResource(target.missionId, context.missionId, "topology_target_node");
      if (source.runId && target.runId && source.runId !== target.runId) {
        throw new RunIntelligenceError("topology_edge_run_mismatch", "Topology edge endpoints cannot cross run boundaries");
      }
      if (!source.runId || !target.runId) {
        throw new ControlPlaneLeaseError(
          "control_plane_mismatch",
          "Topology edge endpoints are not both linked to one canonical run and remain read-only in Ti-Scale",
        );
      }
      const mutationContext = canonicalMutationContext(
        dependencies.database,
        context,
        source.runId,
        "Topology edge",
      );
      mutate(
        request,
        response,
        mutationContext,
        `topology.edge.create:${context.missionId}`,
        input,
        201,
        () => ({ schemaVersion: SCHEMA_VERSION, edge: topology.createEdge(input) }),
        "lease",
      );
    },
  ));

  router.get(`${prefix}/missions/:missionId/intelligence/topology/edges/:edgeId`, missionRoute(
    "read_topology",
    "topology",
    (request, response, context) => {
      const edge = topology.repository.getEdge(stableIdentifier(request.params.edgeId, "edgeId"));
      assertMissionResource(edge.missionId, context.missionId, "topology_edge");
      response.json({ schemaVersion: SCHEMA_VERSION, edge });
    },
  ));

  router.get(`${prefix}/missions/:missionId/intelligence/topology/assets/:assetNodeId/osi`, missionRoute(
    "read_topology",
    "osi",
    (request, response, context) => {
      const assetNodeId = stableIdentifier(request.params.assetNodeId, "assetNodeId");
      const asset = topology.repository.getNode(assetNodeId);
      assertMissionResource(asset.missionId, context.missionId, "topology_asset");
      response.json({ schemaVersion: SCHEMA_VERSION, stack: topology.getOsiStack(assetNodeId) });
    },
  ));

  router.post(`${prefix}/missions/:missionId/intelligence/topology/assets/:assetNodeId/osi`, missionRoute(
    "manage_topology",
    "osi",
    (request, response, context) => {
      const assetNodeId = stableIdentifier(request.params.assetNodeId, "assetNodeId");
      const asset = topology.repository.getNode(assetNodeId);
      assertMissionResource(asset.missionId, context.missionId, "topology_asset");
      const input = recordOsiObservationInput(assetNodeId, request.body);
      const mutationContext = canonicalMutationContext(
        dependencies.database,
        context,
        asset.runId,
        "Topology asset",
      );
      mutate(
        request,
        response,
        mutationContext,
        `topology.osi.create:${context.missionId}:${assetNodeId}`,
        input,
        201,
        () => ({
          schemaVersion: SCHEMA_VERSION,
          observation: topology.recordOsiObservation(input),
          stack: topology.getOsiStack(assetNodeId),
        }),
        "lease",
      );
    },
  ));

  return router;
}

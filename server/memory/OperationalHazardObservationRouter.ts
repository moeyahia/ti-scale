import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import type { OperationalActor } from "../intelligence-v24/types";
import { ActionRepository } from "../orchestration";
import {
  OperationalHazardObservationError,
  OperationalHazardObservationService,
  OperationalHazardLocalResetEvaluator,
  OperationalHazardRuntimeRecoveryProducer,
} from "./OperationalHazardObservationService";

const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;

export type OperationalHazardObservationCapability =
  | "read_reset_totals"
  | "record_completed_reset"
  | "report_aggregate_reset_minimum";

export interface OperationalHazardObservationRouterDependencies {
  readonly database: SqliteDatabase;
  readonly hmacKey: string | Buffer;
  readonly resolveActor: (request: Request) => OperationalActor | undefined;
  readonly authorize: (
    request: Request,
    actor: OperationalActor,
    authorization: {
      readonly capability: OperationalHazardObservationCapability;
      readonly missionId: string;
      readonly runId: string;
      readonly actionId?: string;
    },
  ) => boolean;
  readonly clock?: () => Date;
}

function errorStatus(error: OperationalHazardObservationError): number {
  if (error.category === "not_found") return 404;
  if (error.category === "scope_conflict" || error.category === "conflict") return 409;
  if (error.category === "evidence_insufficient") return 422;
  if (error.category === "policy_denied") return 403;
  return 400;
}

function sendError(response: Response, traceId: string, error: unknown): void {
  if (error instanceof OperationalHazardObservationError) {
    sendV2Error(response, traceId, {
      status: errorStatus(error),
      code: error.code,
      message: error.message,
      humanMessage: error.message,
      retryable: false,
      category: error.category,
      remediation: error.category === "evidence_insufficient"
        ? "Retain one typed local reset proof for the exact completed reset action, then retry without changing its canonical IDs."
        : "Refresh canonical mission state and retry only against the same Ti-Scale-controlled run.",
    });
    return;
  }
  sendV2Error(response, traceId, {
    status: 500,
    code: "operational_hazard_observation_internal_error",
    message: "Operational-hazard observation failed",
    humanMessage: "Ti-Scale stopped before changing attack memory because the reset record could not be validated.",
    retryable: false,
    category: "internal",
    remediation: "Inspect the redacted request trace and canonical database integrity before retrying.",
  });
}

function actor(dependencies: OperationalHazardObservationRouterDependencies, request: Request): OperationalActor {
  const resolved = dependencies.resolveActor(request);
  if (!resolved) {
    throw new OperationalHazardObservationError(
      "hazard_observation_authentication_required",
      "An authenticated Ti-Scale identity is required",
      "policy_denied",
    );
  }
  return resolved;
}

function requireIdempotencyKey(request: Request): string {
  const value = request.get("Idempotency-Key")?.trim() ?? "";
  if (!IDEMPOTENCY_KEY.test(value)) {
    throw new OperationalHazardObservationError(
      "hazard_observation_idempotency_required",
      "A valid Idempotency-Key header is required",
    );
  }
  return value;
}

function exactBody(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new OperationalHazardObservationError("hazard_observation_invalid", "Request body must be a JSON object");
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !keys.includes(key))) {
    throw new OperationalHazardObservationError("hazard_observation_invalid", "Request body contains unsupported fields");
  }
  return record;
}

function assertOwnedScope(database: SqliteDatabase, missionId: string, runId: string): void {
  const row = database.prepare(`
    SELECT mission.control_plane AS mission_control_plane,
      run.control_plane AS run_control_plane, run.mission_id
    FROM runs run JOIN missions mission ON mission.id = run.mission_id
    WHERE run.id = ?
  `).get(runId) as {
    readonly mission_control_plane: string;
    readonly run_control_plane: string;
    readonly mission_id: string;
  } | undefined;
  if (!row) {
    throw new OperationalHazardObservationError("hazard_observation_run_not_found", "Run was not found", "not_found");
  }
  if (
    row.mission_id !== missionId
    || row.mission_control_plane !== "ti_scale"
    || row.run_control_plane !== "ti_scale"
  ) {
    throw new OperationalHazardObservationError(
      "hazard_observation_control_plane_denied",
      "Reset knowledge can be changed only for a Ti-Scale-controlled mission and run",
      "scope_conflict",
    );
  }
}

function completedAction(database: SqliteDatabase, actionId: string) {
  const exists = database.prepare("SELECT 1 FROM actions WHERE id = ?").get(actionId);
  if (!exists) {
    throw new OperationalHazardObservationError(
      "hazard_recovery_action_not_found",
      "Reset action was not found",
      "not_found",
    );
  }
  return new ActionRepository(database).get(actionId);
}

function authorize(
  dependencies: OperationalHazardObservationRouterDependencies,
  request: Request,
  currentActor: OperationalActor,
  authorization: Parameters<OperationalHazardObservationRouterDependencies["authorize"]>[2],
): void {
  if (!dependencies.authorize(request, currentActor, authorization)) {
    throw new OperationalHazardObservationError(
      "hazard_observation_authorization_denied",
      "This identity may not perform the requested operational-hazard memory action",
      "policy_denied",
    );
  }
}

/** Authenticated canonical reset ingestion; it accepts no target labels or raw output. */
export function createOperationalHazardObservationRouter(
  dependencies: OperationalHazardObservationRouterDependencies,
): Router {
  const router = Router();
  const service = new OperationalHazardObservationService(dependencies.database, {
    hmacKey: dependencies.hmacKey,
    ...(dependencies.clock ? { clock: dependencies.clock } : {}),
  });
  const producer = new OperationalHazardRuntimeRecoveryProducer(dependencies.database);
  const evaluator = new OperationalHazardLocalResetEvaluator(dependencies.database);

  router.post(
    "/api/v2/missions/:missionId/runs/:runId/actions/:actionId/operational-hazard-reset",
    (request, response) => {
      const traceId = attachV2RequestId(request, response);
      response.setHeader("Cache-Control", "no-store");
      try {
        exactBody(request.body ?? {}, []);
        const currentActor = actor(dependencies, request);
        const missionId = request.params.missionId ?? "";
        const runId = request.params.runId ?? "";
        const actionId = request.params.actionId ?? "";
        const idempotencyKey = requireIdempotencyKey(request);
        assertOwnedScope(dependencies.database, missionId, runId);
        authorize(dependencies, request, currentActor, {
          capability: "record_completed_reset", missionId, runId, actionId,
        });
        const result = inImmediateTransaction(dependencies.database, () => {
          const action = completedAction(dependencies.database, actionId);
          if (action.missionId !== missionId || action.runId !== runId) {
            throw new OperationalHazardObservationError(
              "hazard_observation_scope_mismatch",
              "Reset action does not belong to the supplied mission and run",
              "scope_conflict",
            );
          }
          evaluator.evaluateCompletedAction(action);
          const produced = producer.recordCompletedAction(action, currentActor);
          if (!produced) {
            throw new OperationalHazardObservationError(
              "hazard_recovery_action_invalid",
              "Only a completed target or environment reset action can be recorded",
              "evidence_insufficient",
            );
          }
          const staged = service.recordCanonicalReset({
            recoveryEventId: produced.recoveryEventId,
            actor: currentActor,
            idempotencyKey,
          });
          const completedAt = dependencies.clock?.().toISOString() ?? new Date().toISOString();
          dependencies.database.prepare(`
            UPDATE operational_hazard_observation_jobs
            SET status = 'completed', occurrence_id = ?, completed_at = ?,
              lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
            WHERE event_id = ? AND status IN ('pending', 'processing')
          `).run(staged.occurrence.id, completedAt, completedAt, produced.recoveryEventId);
          return staged;
        });
        response.status(result.replayed ? 200 : 201).json(result);
      } catch (error) {
        sendError(response, traceId, error);
      }
    },
  );

  router.post(
    "/api/v2/missions/:missionId/runs/:runId/operational-hazards/reset-minimum-observations",
    (request, response) => {
      const traceId = attachV2RequestId(request, response);
      response.setHeader("Cache-Control", "no-store");
      try {
        const currentActor = actor(dependencies, request);
        const missionId = request.params.missionId ?? "";
        const runId = request.params.runId ?? "";
        const idempotencyKey = requireIdempotencyKey(request);
        const body = exactBody(request.body, ["reportedMinimum"]);
        assertOwnedScope(dependencies.database, missionId, runId);
        authorize(dependencies, request, currentActor, {
          capability: "report_aggregate_reset_minimum", missionId, runId,
        });
        const result = service.reportAggregateResetMinimum({
          missionId,
          runId,
          reportedMinimum: Number(body.reportedMinimum),
          actor: currentActor,
          idempotencyKey,
        });
        response.status(result.replayed ? 200 : 201).json(result);
      } catch (error) {
        sendError(response, traceId, error);
      }
    },
  );

  router.get(
    "/api/v2/missions/:missionId/runs/:runId/operational-hazards/reset-totals",
    (request, response) => {
      const traceId = attachV2RequestId(request, response);
      response.setHeader("Cache-Control", "no-store");
      try {
        const currentActor = actor(dependencies, request);
        const missionId = request.params.missionId ?? "";
        const runId = request.params.runId ?? "";
        assertOwnedScope(dependencies.database, missionId, runId);
        authorize(dependencies, request, currentActor, {
          capability: "read_reset_totals", missionId, runId,
        });
        response.status(200).json(service.totals(missionId, runId));
      } catch (error) {
        sendError(response, traceId, error);
      }
    },
  );

  return router;
}

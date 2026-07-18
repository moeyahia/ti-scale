import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import type { SqliteDatabase } from "../db";
import { ScriptArtifactIdempotencyStore } from "./ScriptArtifactIdempotencyStore";
import { ScriptArtifactService } from "./ScriptArtifactService";
import type { ScriptSourceStore } from "./ScriptSourceStore";
import type { ScriptArtifactActor } from "./types";
import { ScriptArtifactError } from "./types";
import {
  parseCreateScriptArtifactInput,
  parseCreateScriptVersionInput,
  requiredScriptIdempotencyKey,
  scriptArtifactListFilter,
  scriptIdentifier,
} from "./validation";

const SCHEMA_VERSION = "2.4" as const;

export type ScriptArtifactCapability = "read_script_artifacts" | "manage_script_artifacts";

export interface ScriptArtifactAuthorizationRequest {
  readonly missionId: string;
  readonly runId?: string;
  readonly scriptArtifactId?: string;
  readonly capability: ScriptArtifactCapability;
}

export interface ScriptArtifactRouterDependencies {
  readonly database: SqliteDatabase;
  readonly sourceStore: ScriptSourceStore;
  readonly resolveActor: (request: Request) => ScriptArtifactActor | undefined;
  readonly authorize: (
    request: Request,
    actor: ScriptArtifactActor,
    authorization: ScriptArtifactAuthorizationRequest,
  ) => boolean;
  readonly clock?: () => Date;
  readonly basePath?: string;
}

function validatedBasePath(value: string | undefined): string {
  const result = value ?? "/api/v2";
  if (!result.startsWith("/") || result.endsWith("/") || /[?#]/u.test(result)) {
    throw new Error("ScriptArtifactRouter basePath must be absolute without a trailing slash");
  }
  return result;
}

function authenticatedActor(value: ScriptArtifactActor | undefined): ScriptArtifactActor {
  if (!value || !["operator", "agent", "worker", "system"].includes(value.type)) {
    throw new ScriptArtifactError(
      "script_artifact_authentication_required",
      "An authenticated Ti-Scale identity is required",
      "authentication_missing",
      401,
      "Sign in again before accessing canonical script records.",
    );
  }
  return { id: scriptIdentifier(value.id, "actor.id"), type: value.type };
}

function sendError(response: Response, traceId: string, error: unknown): void {
  if (error instanceof ScriptArtifactError) {
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
    code: "script_artifact_internal_error",
    message: "Script artifact service could not complete the request",
    humanMessage: "The immutable script-artifact service encountered an internal error.",
    retryable: false,
    category: "internal",
    remediation: "Use the request ID to inspect redacted V2 logs before retrying.",
  });
}

function withoutSource<T extends { readonly source: string }>(record: T): Omit<T, "source"> {
  const { source: _source, ...summary } = record;
  return summary;
}

/** Authenticated, policy-authorized routes for source documentation and immutable versions only. */
export function createScriptArtifactRouter(dependencies: ScriptArtifactRouterDependencies): Router {
  const router = Router();
  const prefix = validatedBasePath(dependencies.basePath);
  const service = new ScriptArtifactService(dependencies.database, dependencies.sourceStore, dependencies.clock);
  const idempotency = new ScriptArtifactIdempotencyStore(dependencies.database, dependencies.clock);

  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  router.get(`${prefix}/missions/:missionId/script-artifacts`, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = authenticatedActor(dependencies.resolveActor(request));
      const missionId = scriptIdentifier(request.params.missionId, "missionId");
      const filter = scriptArtifactListFilter(missionId, request.query as Record<string, unknown>);
      if (!dependencies.authorize(request, actor, {
        missionId,
        ...(filter.runId ? { runId: filter.runId } : {}),
        capability: "read_script_artifacts",
      })) {
        throw new ScriptArtifactError("script_artifact_policy_denied", "This identity cannot read script artifacts for the mission", "policy_denied", 403, "Use an identity with explicit mission script-read access.");
      }
      response.json({ schemaVersion: SCHEMA_VERSION, items: service.list(filter) });
    } catch (error) { sendError(response, traceId, error); }
  });

  router.get(`${prefix}/missions/:missionId/script-artifacts/:scriptArtifactId`, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = authenticatedActor(dependencies.resolveActor(request));
      const missionId = scriptIdentifier(request.params.missionId, "missionId");
      const scriptArtifactId = scriptIdentifier(request.params.scriptArtifactId, "scriptArtifactId");
      const summary = service.repository.get(scriptArtifactId);
      if (summary.missionId !== missionId) {
        throw new ScriptArtifactError("script_artifact_not_found", "Script artifact was not found in this mission", "not_found", 404);
      }
      if (!dependencies.authorize(request, actor, {
        missionId,
        ...(summary.runId ? { runId: summary.runId } : {}),
        scriptArtifactId,
        capability: "read_script_artifacts",
      })) {
        throw new ScriptArtifactError("script_artifact_policy_denied", "This identity cannot read the requested script artifact", "policy_denied", 403, "Use an identity with explicit mission script-read access.");
      }
      const record = service.get(scriptArtifactId);
      response.json({ schemaVersion: SCHEMA_VERSION, record });
    } catch (error) { sendError(response, traceId, error); }
  });

  router.post(`${prefix}/missions/:missionId/script-artifacts`, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = authenticatedActor(dependencies.resolveActor(request));
      const missionId = scriptIdentifier(request.params.missionId, "missionId");
      const input = parseCreateScriptArtifactInput(missionId, request.body);
      if (!dependencies.authorize(request, actor, {
        missionId,
        ...(input.runId ? { runId: input.runId } : {}),
        capability: "manage_script_artifacts",
      })) {
        throw new ScriptArtifactError("script_artifact_policy_denied", "This identity cannot create script artifacts for the mission", "policy_denied", 403, "Use an identity with explicit mission script-management access.");
      }
      const result = idempotency.execute(
        `script_artifact.create:${missionId}`,
        requiredScriptIdempotencyKey(request.get("Idempotency-Key")),
        actor,
        input,
        () => ({ schemaVersion: SCHEMA_VERSION, record: withoutSource(service.create(input, actor)) }),
      );
      response.setHeader("Idempotency-Replayed", result.replayed ? "true" : "false");
      response.status(201).json(result.response);
    } catch (error) { sendError(response, traceId, error); }
  });

  router.post(`${prefix}/missions/:missionId/script-artifacts/:scriptArtifactId/versions`, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = authenticatedActor(dependencies.resolveActor(request));
      const missionId = scriptIdentifier(request.params.missionId, "missionId");
      const scriptArtifactId = scriptIdentifier(request.params.scriptArtifactId, "scriptArtifactId");
      const previous = service.repository.get(scriptArtifactId);
      if (previous.missionId !== missionId) {
        throw new ScriptArtifactError("script_artifact_not_found", "Script artifact was not found in this mission", "not_found", 404);
      }
      if (!dependencies.authorize(request, actor, {
        missionId,
        ...(previous.runId ? { runId: previous.runId } : {}),
        scriptArtifactId,
        capability: "manage_script_artifacts",
      })) {
        throw new ScriptArtifactError("script_artifact_policy_denied", "This identity cannot version the requested script artifact", "policy_denied", 403, "Use an identity with explicit mission script-management access.");
      }
      const input = parseCreateScriptVersionInput(scriptArtifactId, request.body);
      const result = idempotency.execute(
        `script_artifact.version:${missionId}:${scriptArtifactId}`,
        requiredScriptIdempotencyKey(request.get("Idempotency-Key")),
        actor,
        input,
        () => ({ schemaVersion: SCHEMA_VERSION, record: withoutSource(service.createVersion(input, actor)) }),
      );
      response.setHeader("Idempotency-Replayed", result.replayed ? "true" : "false");
      response.status(201).json(result.response);
    } catch (error) { sendError(response, traceId, error); }
  });

  return router;
}

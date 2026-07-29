import { Router, type Request, type Response } from "express";
import {
  attachV2RequestId,
  sendV2Error,
} from "../contracts/ApiErrorContract";
import type { RuntimeSourceManifests } from "../domain";
import {
  OperationalTruthError,
  RouterIdempotencyStore,
} from "../intelligence-v24";
import type { SqliteDatabase } from "../db";
import { ModelConfigurationError } from "./ModelConfigurationError";
import { ModelConfigurationRepository } from "./ModelConfigurationRepository";
import { ModelConfigurationService } from "./ModelConfigurationService";
import {
  MODEL_CONFIGURATION_SCHEMA_VERSION,
  modelAssignmentSemantics,
} from "./types";
import {
  modelAssignmentPurpose,
  modelConfigurationIdentifier,
  optionalResolutionIdentifier,
  parseModelPreferenceFilters,
  parsePutModelPreference,
  requiredModelConfigurationIdempotencyKey,
} from "./validation";

export interface ModelConfigurationRouterDependencies {
  readonly database: SqliteDatabase;
  readonly readRuntimeManifests: () => RuntimeSourceManifests;
  readonly resolveActor: (request: Request) => string | undefined;
  readonly service?: ModelConfigurationService;
  readonly clock?: () => Date;
  readonly basePath?: string;
}

function normalizedBasePath(value: string | undefined): string {
  const path = value ?? "/api/v2";
  if (!path.startsWith("/") || path.endsWith("/") || /[?#]/u.test(path)) {
    throw new Error(
      "ModelConfigurationRouter basePath must be absolute without a trailing slash",
    );
  }
  return path;
}

function authenticatedActor(
  dependencies: ModelConfigurationRouterDependencies,
  request: Request,
): string {
  const value = dependencies.resolveActor(request)?.trim();
  if (!value) {
    throw new ModelConfigurationError(
      "model_configuration_authentication_required",
      "Authenticated operator identity is required",
      401,
      "policy_denied",
      "Sign in to the isolated Ti-Scale control plane.",
    );
  }
  return modelConfigurationIdentifier(value, "actorId");
}

function errorResponse(
  response: Response,
  traceId: string,
  error: unknown,
): void {
  if (error instanceof ModelConfigurationError) {
    sendV2Error(response, traceId, {
      status: error.status,
      code: error.code,
      message: error.message,
      humanMessage: error.message,
      retryable: error.retryable,
      category: error.category,
      remediation: error.remediation,
    });
    return;
  }
  if (error instanceof OperationalTruthError) {
    sendV2Error(response, traceId, {
      status: error.category === "state_conflict" ? 409 : 400,
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
    code: "model_configuration_internal_error",
    message: "Model configuration service could not complete the request",
    humanMessage: "The model-configuration control plane encountered an internal error.",
    retryable: false,
    category: "internal",
    remediation: "Use the request ID to inspect redacted V2 logs before retrying.",
  });
}

function configurationIds(value: unknown): readonly string[] | undefined {
  if (value === undefined || value === "") return undefined;
  if (typeof value !== "string") {
    throw new ModelConfigurationError(
      "invalid_model_configuration_ids",
      "ids must occur exactly once",
      400,
      "invalid_input",
      "Supply a comma-separated list of stable configuration IDs.",
    );
  }
  const ids = [...new Set(value.split(",").map((item) =>
    modelConfigurationIdentifier(item, "configurationId")))];
  if (ids.length > 100) {
    throw new ModelConfigurationError(
      "model_configuration_ids_limit_exceeded",
      "At most 100 model configuration IDs may be requested",
      400,
      "invalid_input",
      "Request a smaller bounded configuration set.",
    );
  }
  return ids;
}

export function createModelConfigurationRouter(
  dependencies: ModelConfigurationRouterDependencies,
): Router {
  const router = Router();
  const prefix = normalizedBasePath(dependencies.basePath);
  const service = dependencies.service ?? new ModelConfigurationService(
    new ModelConfigurationRepository(
      dependencies.database,
      dependencies.clock,
    ),
    {
      readRuntimeManifests: dependencies.readRuntimeManifests,
      ...(dependencies.clock ? { clock: dependencies.clock } : {}),
    },
  );
  const idempotency = new RouterIdempotencyStore(
    dependencies.database,
    dependencies.clock,
  );

  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  router.get(`${prefix}/model-catalog`, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      authenticatedActor(dependencies, request);
      const catalog = service.catalog();
      response.json({
        schemaVersion: MODEL_CONFIGURATION_SCHEMA_VERSION,
        observedAt: catalog.observedAt,
        items: catalog.items,
      });
    } catch (error) {
      errorResponse(response, traceId, error);
    }
  });

  router.get(`${prefix}/model-configurations`, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      authenticatedActor(dependencies, request);
      response.json({
        schemaVersion: MODEL_CONFIGURATION_SCHEMA_VERSION,
        items: service.listConfigurations(configurationIds(request.query.ids)),
      });
    } catch (error) {
      errorResponse(response, traceId, error);
    }
  });

  router.get(`${prefix}/model-preferences`, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      authenticatedActor(dependencies, request);
      response.json({
        schemaVersion: MODEL_CONFIGURATION_SCHEMA_VERSION,
        items: service.listPreferences(parseModelPreferenceFilters(request.query)),
      });
    } catch (error) {
      errorResponse(response, traceId, error);
    }
  });

  router.get(
    `${prefix}/runs/:runId/model-assignments`,
    (request, response) => {
      const traceId = attachV2RequestId(request, response);
      try {
        authenticatedActor(dependencies, request);
        const runId = modelConfigurationIdentifier(
          request.params.runId,
          "runId",
        );
        response.json({
          schemaVersion: MODEL_CONFIGURATION_SCHEMA_VERSION,
          activeRunPinning: "immutable",
          items: service.listPinnedAssignmentsForRun(runId),
        });
      } catch (error) {
        errorResponse(response, traceId, error);
      }
    },
  );

  router.put(
    `${prefix}/model-preferences/:scopeType/:scopeId`,
    (request, response) => {
      const traceId = attachV2RequestId(request, response);
      try {
        const actorId = authenticatedActor(dependencies, request);
        const input = parsePutModelPreference(
          request.params.scopeType,
          request.params.scopeId,
          request.body,
        );
        const result = idempotency.execute(
          `model_preference.put:${input.purpose}:${input.scopeType}:${input.scopeId}:${input.agentId ?? "global"}`,
          requiredModelConfigurationIdempotencyKey(
            request.get("Idempotency-Key"),
          ),
          { id: actorId, type: "operator" },
          input,
          () => ({
            schemaVersion: MODEL_CONFIGURATION_SCHEMA_VERSION,
            preference: service.putPreference(input, actorId),
          }),
        );
        response.setHeader(
          "Idempotency-Replayed",
          result.replayed ? "true" : "false",
        );
        response.status(input.expectedVersion === 0 ? 201 : 200)
          .json(result.response);
      } catch (error) {
        errorResponse(response, traceId, error);
      }
    },
  );

  router.get(`${prefix}/model-resolution`, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      authenticatedActor(dependencies, request);
      const agentId = optionalResolutionIdentifier(
        request.query.agentId,
        "agentId",
      );
      if (!agentId) {
        throw new ModelConfigurationError(
          "model_resolution_agent_required",
          "agentId is required to resolve a model configuration",
          400,
          "invalid_input",
          "Supply one stable agentId from the live fleet.",
        );
      }
      const missionId = optionalResolutionIdentifier(
        request.query.missionId,
        "missionId",
      );
      const runId = optionalResolutionIdentifier(request.query.runId, "runId");
      const stepId = optionalResolutionIdentifier(
        request.query.stepId,
        "stepId",
      );
      const purpose = modelAssignmentPurpose(request.query.purpose);
      const resolution = service.resolveOptional({
        agentId,
        purpose,
        ...(missionId ? { missionId } : {}),
        ...(runId ? { runId } : {}),
        ...(stepId ? { stepId } : {}),
      });
      response.json({
        schemaVersion: MODEL_CONFIGURATION_SCHEMA_VERSION,
        assignmentSemantics: modelAssignmentSemantics(purpose),
        resolution,
        availability: resolution
          ? {
              status: "configured",
              agentId,
              humanMessage:
                purpose === "planning"
                  ? "This agent has a separate reasoning-advisor assignment for the requested scope."
                  : "This agent has an execution-model assignment for the requested scope.",
              remediation: null,
            }
          : {
              status: "unconfigured",
              agentId,
              humanMessage:
                purpose === "planning"
                  ? "This agent has no optional reasoning advisor for the requested scope; its execution assignment is unchanged."
                  : "This agent does not have an execution-model assignment for the requested scope.",
              remediation:
                purpose === "planning"
                  ? "Optionally connect and attest an advisor-only provider, then choose it on the agent profile."
                  : "Choose a compatible provider and model on the agent profile, or configure a global default.",
            },
      });
    } catch (error) {
      errorResponse(response, traceId, error);
    }
  });

  return router;
}

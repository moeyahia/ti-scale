import { Router, type Request, type Response } from "express";
import { z } from "zod";
import {
  attachV2RequestId,
  sendV2Error,
} from "../../contracts/ApiErrorContract";
import { OpenRouterConnectionError } from "./OpenRouterConnectionError";
import { OpenRouterConnectionService } from "./OpenRouterConnectionService";
import type { PutOpenRouterConnectionInput } from "./OpenRouterConnectionTypes";

const model = z.string().trim()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$/u);
const credential = z.discriminatedUnion("action", [
  z.object({ action: z.literal("keep") }).strict(),
  z.object({
    action: z.literal("replace"),
    value: z.string().min(20).max(4_096)
      .refine((value) => !/[\s\u0000-\u001F\u007F]/u.test(value)),
  }).strict(),
  z.object({ action: z.literal("remove") }).strict(),
]);
const putConnection = z.object({
  enabled: z.boolean(),
  model,
  credential,
  expectedVersion: z.number().int().nonnegative(),
}).strict();
const refreshAttestation = z.object({
  expectedVersion: z.number().int().positive(),
}).strict();
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;

export interface OpenRouterConnectionRouterOptions {
  readonly service: OpenRouterConnectionService;
  readonly resolveActor: (request: Request) => string | undefined;
}

function actor(options: OpenRouterConnectionRouterOptions, request: Request): string {
  const value = options.resolveActor(request)?.trim();
  if (!value) {
    throw new OpenRouterConnectionError(
      "openrouter_connection_authentication_required",
      "Authenticated operator identity is required.",
      401,
      "authentication_required",
      "Sign in to the isolated Ti-Scale control plane.",
    );
  }
  return value;
}

function idempotencyKey(request: Request): string {
  const value = request.get("Idempotency-Key")?.trim();
  if (!value || !IDEMPOTENCY_KEY.test(value)) {
    throw new OpenRouterConnectionError(
      "openrouter_connection_idempotency_key_invalid",
      "A valid Idempotency-Key header containing 8-200 safe characters is required.",
      400,
      "invalid_input",
      "Supply a unique Idempotency-Key and reuse it only for the same request.",
    );
  }
  return value;
}

function invalidRequest(): OpenRouterConnectionError {
  return new OpenRouterConnectionError(
    "openrouter_connection_request_invalid",
    "The OpenRouter connection request failed strict validation.",
    400,
    "invalid_input",
    "Review the enabled state, exact model ID, credential action, and current version.",
  );
}

function sendError(
  response: Response,
  traceId: string,
  error: unknown,
): void {
  if (error instanceof OpenRouterConnectionError) {
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
  sendV2Error(response, traceId, {
    status: 500,
    code: "openrouter_connection_internal_error",
    message: "The OpenRouter connection control plane could not complete the request.",
    humanMessage: "Ti-Scale could not safely update the OpenRouter connection.",
    retryable: false,
    category: "internal",
    remediation: "Use the request ID to inspect redacted server diagnostics.",
  });
}

export function createOpenRouterConnectionRouter(
  options: OpenRouterConnectionRouterOptions,
): Router {
  const router = Router();
  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  router.get("/api/v2/provider-connections/openrouter", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      actor(options, request);
      response.json(options.service.status());
    } catch (error) {
      sendError(response, traceId, error);
    }
  });

  router.put("/api/v2/provider-connections/openrouter", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actorId = actor(options, request);
      const parsed = putConnection.safeParse(request.body);
      if (!parsed.success) throw invalidRequest();
      const result = options.service.put(
        parsed.data as PutOpenRouterConnectionInput,
        actorId,
        idempotencyKey(request),
      );
      response.setHeader("Idempotency-Replayed", String(result.replayed));
      response.status(
        !result.replayed && result.configuration.version === 1 ? 201 : 200,
      ).json({
        ...options.service.status(),
        mutation: {
          savedVersion: result.configuration.version,
          replayed: result.replayed,
        },
      });
    } catch (error) {
      sendError(response, traceId, error);
    }
  });

  router.put("/api/v2/provider-connections/openrouter/attestation", async (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actorId = actor(options, request);
      const parsed = refreshAttestation.safeParse(request.body);
      if (!parsed.success) throw invalidRequest();
      const result = await options.service.refreshAttestation(
        parsed.data.expectedVersion,
        actorId,
        idempotencyKey(request),
      );
      response.setHeader("Idempotency-Replayed", String(result.replayed));
      response.json(result);
    } catch (error) {
      sendError(response, traceId, error);
    }
  });

  return router;
}

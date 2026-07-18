import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import { OperationsApiError } from "../operations/errors";
import { validateAccessPolicy } from "../operations/scope";
import {
  boundedLimit,
  identifier,
  requiredIdempotencyKey,
} from "../operations/validation";
import type { OperationsActor } from "../operations/types";
import { NotificationApiError } from "./NotificationApiError";
import { NotificationRepository } from "./NotificationRepository";
import {
  canMutateNotificationReadState,
  type NotificationRouterDependencies,
} from "./types";

const ACTOR_TYPES = new Set(["operator", "reviewer", "admin", "agent", "system"] as const);

function actor(request: Request, dependencies: NotificationRouterDependencies): OperationsActor {
  const value = dependencies.resolveActor(request);
  if (!value || !ACTOR_TYPES.has(value.type) || !value.id?.trim()) {
    throw new NotificationApiError(
      401,
      "notification_identity_required",
      "An authenticated notification identity is required",
      "Sign in again before accessing in-app notifications.",
      "authentication_missing",
    );
  }
  return { id: identifier(value.id, "Actor ID"), type: value.type };
}

function state(request: Request): "all" | "unread" | "read" {
  const value = request.query.state;
  if (value === undefined || value === "all" || value === "unread" || value === "read") {
    return value ?? "all";
  }
  throw new NotificationApiError(
    400,
    "invalid_notification_state",
    "Notification state filter is invalid",
    "Notification state must be all, unread, or read.",
    "invalid_input",
  );
}

function humanMutationActor(value: OperationsActor): OperationsActor {
  if (canMutateNotificationReadState(value)) return value;
  throw new NotificationApiError(
    403,
    "notification_read_state_forbidden",
    "Only a human reviewer may update notification read state",
    "Only an operator, reviewer, or administrator can mark notifications as read.",
    "policy_denied",
    "Use an authenticated human review identity for this mutation.",
  );
}

function queryText(request: Request, name: string): string | undefined {
  const value = request.query[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw new NotificationApiError(400, "invalid_notification_query", `${name} must occur once`, `The ${name} query value is invalid.`, "invalid_input");
  }
  return value;
}

function sendError(response: Response, error: unknown, traceId: string): void {
  if (error instanceof NotificationApiError) {
    sendV2Error(response, traceId, {
      status: error.status,
      code: error.code,
      message: error.message,
      humanMessage: error.humanMessage,
      retryable: false,
      category: error.category,
      ...(error.remediation ? { remediation: error.remediation } : {}),
    });
    return;
  }
  if (error instanceof OperationsApiError) {
    sendV2Error(response, traceId, {
      status: error.status,
      code: error.code,
      message: error.message,
      humanMessage: error.options.humanMessage ?? error.message,
      retryable: error.options.retryable ?? false,
      category: error.options.category ?? "invalid_input",
      ...(error.options.details === undefined ? {} : { details: error.options.details }),
      ...(error.options.remediation ? { remediation: error.options.remediation } : {}),
    });
    return;
  }
  sendV2Error(response, traceId, {
    status: 500,
    code: "notification_internal_error",
    message: "In-app notifications could not complete the request",
    humanMessage: "The in-app notification service encountered an internal error.",
    retryable: false,
    category: "internal",
    remediation: "Use the request ID to inspect redacted structured logs before retrying.",
  });
}

function handle(
  dependencies: NotificationRouterDependencies,
  operation: (
    request: Request,
    response: Response,
    context: { readonly actor: OperationsActor; readonly access: ReturnType<NotificationRouterDependencies["resolveAccess"]> },
  ) => void,
) {
  return (request: Request, response: Response): void => {
    const traceId = attachV2RequestId(request, response);
    try {
      const resolvedActor = actor(request, dependencies);
      const access = dependencies.resolveAccess(request, resolvedActor);
      validateAccessPolicy(access);
      operation(request, response, { actor: resolvedActor, access });
    } catch (error) {
      sendError(response, error, traceId);
    }
  };
}

export function createNotificationRouter(dependencies: NotificationRouterDependencies): Router {
  const repository = new NotificationRepository(dependencies.database, dependencies.clock);
  const router = Router();
  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  router.get("/api/v2/notifications", handle(dependencies, (request, response, { actor: resolvedActor, access }) => {
    response.json(repository.list(access, resolvedActor, {
      limit: boundedLimit(queryText(request, "limit"), 20),
      cursor: queryText(request, "cursor"),
      state: state(request),
    }));
  }));

  router.get("/api/v2/notifications/unread-count", handle(dependencies, (_request, response, { actor: resolvedActor, access }) => {
    response.json(repository.unreadCount(access, resolvedActor));
  }));

  router.post("/api/v2/notifications/:notificationId/read", handle(dependencies, (request, response, context) => {
    humanMutationActor(context.actor);
    response.json(repository.markRead(
      identifier(request.params.notificationId, "Notification ID"),
      context.access,
      context.actor,
      requiredIdempotencyKey(request.get("Idempotency-Key")),
    ));
  }));

  router.post("/api/v2/notifications/read-all", handle(dependencies, (request, response, context) => {
    humanMutationActor(context.actor);
    response.json(repository.markAllRead(
      context.access,
      context.actor,
      requiredIdempotencyKey(request.get("Idempotency-Key")),
    ));
  }));

  return router;
}

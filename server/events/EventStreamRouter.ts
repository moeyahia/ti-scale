import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import {
  EventStreamService,
  type OperationalEventEnvelope,
} from "./EventStreamService";
import type { EventSensitivity } from "./types";

const IDENTIFIER = /^[A-Za-z0-9._:@/-]{1,200}$/u;

interface ReplayCursor {
  readonly version: 1;
  readonly runId: string;
  readonly afterSequence: number;
}

export interface EventStreamRouterDependencies {
  readonly service: EventStreamService;
  readonly resolveSensitivity?: (request: Request) => EventSensitivity;
  readonly heartbeatIntervalMs?: number;
  readonly maxClientQueueSize?: number;
}

class EventStreamRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EventStreamRequestError";
  }
}

function sendError(
  response: Response,
  error: unknown,
  traceId: string,
  invalidCode: string,
  invalidRemediation: string,
): void {
  const invalid = error instanceof EventStreamRequestError;
  sendV2Error(response, traceId, invalid
    ? {
        status: 400,
        code: invalidCode,
        message: error.message,
        humanMessage: error.message,
        retryable: false,
        category: "invalid_input",
        remediation: invalidRemediation,
      }
    : {
        status: 500,
        code: "event_stream_internal_error",
        message: "Event stream request failed",
        humanMessage: "The event stream could not safely complete this request.",
        retryable: false,
        category: "internal",
        remediation: "Use the trace ID to inspect redacted event-stream logs before reconnecting.",
      });
}

function boundedInteger(
  value: unknown,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || !/^\d+$/u.test(value)) {
    throw new EventStreamRequestError(`${label} must be an integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new EventStreamRequestError(`${label} must be between ${minimum} and ${maximum}`);
  }
  return parsed;
}

function validatedRunId(value: unknown, required: boolean): string | undefined {
  if (value === undefined && !required) return undefined;
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new EventStreamRequestError("runId is invalid");
  }
  return value;
}

function encodeCursor(cursor: ReplayCursor): string {
  return Buffer.from(JSON.stringify(cursor), "utf8").toString("base64url");
}

function decodeCursor(value: string): ReplayCursor {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  } catch {
    throw new EventStreamRequestError("cursor is invalid");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new EventStreamRequestError("cursor is invalid");
  }
  const record = parsed as Record<string, unknown>;
  if (
    record.version !== 1 ||
    typeof record.runId !== "string" ||
    !IDENTIFIER.test(record.runId) ||
    !Number.isSafeInteger(record.afterSequence) ||
    (record.afterSequence as number) < 0
  ) {
    throw new EventStreamRequestError("cursor is invalid");
  }
  return record as unknown as ReplayCursor;
}

/** SSE IDs are encoded so even imported IDs cannot inject protocol fields. */
export function encodeSseEventId(eventId: string): string {
  return `v2.${Buffer.from(eventId, "utf8").toString("base64url")}`;
}

export function decodeSseEventId(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) throw new EventStreamRequestError("Last-Event-ID is empty");
  if (!trimmed.startsWith("v2.")) {
    if (/[\x00\r\n]/u.test(trimmed)) throw new EventStreamRequestError("Last-Event-ID is invalid");
    return trimmed;
  }
  try {
    const decoded = Buffer.from(trimmed.slice(3), "base64url").toString("utf8");
    if (!decoded || /[\x00\r\n]/u.test(decoded)) throw new Error("invalid");
    return decoded;
  } catch {
    throw new EventStreamRequestError("Last-Event-ID is invalid");
  }
}

function sseFrame(event: OperationalEventEnvelope): string {
  return `id: ${encodeSseEventId(event.id)}\ndata: ${JSON.stringify(event)}\n\n`;
}

function sensitivityFor(
  request: Request,
  resolver: ((request: Request) => EventSensitivity) | undefined,
): EventSensitivity {
  const sensitivity = resolver?.(request) ?? "internal";
  if (!["public", "internal", "private", "restricted"].includes(sensitivity)) {
    throw new Error("Invalid event sensitivity policy");
  }
  return sensitivity;
}

/** Mount at the application root; all route paths are already /api/v2-prefixed. */
export function createEventStreamRouter(
  dependencies: EventStreamRouterDependencies,
): Router {
  const router = Router();
  const heartbeatIntervalMs = dependencies.heartbeatIntervalMs ?? 20_000;
  if (!Number.isSafeInteger(heartbeatIntervalMs) || heartbeatIntervalMs < 10 || heartbeatIntervalMs > 120_000) {
    throw new RangeError("heartbeatIntervalMs must be between 10 and 120000");
  }
  if (
    dependencies.maxClientQueueSize !== undefined &&
    (!Number.isSafeInteger(dependencies.maxClientQueueSize) ||
      dependencies.maxClientQueueSize < 1 ||
      dependencies.maxClientQueueSize > 10_000)
  ) {
    throw new RangeError("maxClientQueueSize must be between 1 and 10000");
  }

  const replayHandler = (request: Request, response: Response): void => {
    const traceId = attachV2RequestId(request, response);
    response.setHeader("Cache-Control", "no-store");
    try {
      const decoded = typeof request.query.cursor === "string"
        ? decodeCursor(request.query.cursor)
        : undefined;
      const queryRunId = validatedRunId(request.query.runId, !decoded);
      if (decoded && queryRunId && queryRunId !== decoded.runId) {
        throw new EventStreamRequestError("cursor does not belong to runId");
      }
      const runId = decoded?.runId ?? queryRunId!;
      const afterSequence = decoded?.afterSequence ?? boundedInteger(
        request.query.afterSequence,
        0,
        0,
        Number.MAX_SAFE_INTEGER,
        "afterSequence",
      );
      const limit = boundedInteger(request.query.limit, 250, 1, 500, "limit");
      const sensitivity = sensitivityFor(request, dependencies.resolveSensitivity);
      const page = dependencies.service.replayRun(runId, afterSequence, limit + 1, sensitivity);
      const events = page.slice(0, limit);
      const nextSequence = events.at(-1)?.sequence ?? afterSequence;
      response.json({
        events,
        runId,
        afterSequence: nextSequence,
        nextCursor: encodeCursor({ version: 1, runId, afterSequence: nextSequence }),
        hasMore: page.length > limit,
      });
    } catch (error) {
      sendError(response, error, traceId, "invalid_event_replay_request",
        "Use a valid run ID, non-negative sequence, and cursor returned by this endpoint.");
    }
  };

  router.get("/api/v2/events/replay", replayHandler);
  router.get("/api/v2/events/gap", replayHandler);

  router.get("/api/v2/events/stream", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    let runId: string | undefined;
    let afterSequence = 0;
    let afterEventId: string | undefined;
    let sensitivity: EventSensitivity;
    try {
      runId = validatedRunId(request.query.runId, false);
      afterSequence = boundedInteger(
        request.query.afterSequence,
        0,
        0,
        Number.MAX_SAFE_INTEGER,
        "afterSequence",
      );
      const suppliedLastId = request.get("Last-Event-ID") ?? (
        typeof request.query.lastEventId === "string" ? request.query.lastEventId : undefined
      );
      if (!runId && afterSequence > 0) throw new EventStreamRequestError("afterSequence requires runId");
      if (suppliedLastId) {
        const decodedId = decodeSseEventId(suppliedLastId);
        if (runId) {
          afterSequence = Math.max(
            afterSequence,
            dependencies.service.resolveRunSequence(runId, decodedId),
          );
        } else {
          if (!dependencies.service.eventExists(decodedId)) throw new EventStreamRequestError("Last-Event-ID was not found");
          afterEventId = decodedId;
        }
      }
      sensitivity = sensitivityFor(request, dependencies.resolveSensitivity);
    } catch (error) {
      sendError(response, error, traceId, "invalid_event_stream_request",
        "Reconnect with a valid run ID and the most recent event ID or sequence.");
      return;
    }

    response.status(200);
    response.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    response.setHeader("Cache-Control", "no-cache, no-transform");
    response.setHeader("Connection", "keep-alive");
    response.setHeader("X-Accel-Buffering", "no");
    response.flushHeaders?.();
    response.write(`retry: 1000\n: connected ${new Date().toISOString()}\n\n`);

    let drainListener: (() => void) | null = null;
    let cleaned = false;
    let heartbeat: ReturnType<typeof setInterval> | null = null;
    let subscription: ReturnType<EventStreamService["subscribe"]> | null = null;
    const cleanup = (): void => {
      if (cleaned) return;
      cleaned = true;
      if (heartbeat) clearInterval(heartbeat);
      drainListener?.();
      drainListener = null;
      subscription?.close();
    };

    subscription = dependencies.service.subscribe({
      runId,
      afterSequence,
      afterEventId,
      sensitivity,
      maxQueueSize: dependencies.maxClientQueueSize,
      sink: {
        write: (event) => response.write(sseFrame(event)),
        onDrain: (listener) => {
          const wrapped = (): void => {
            drainListener = null;
            listener();
          };
          response.once("drain", wrapped);
          drainListener = () => response.off("drain", wrapped);
          return drainListener;
        },
        close: (reason) => {
          if (!response.writableEnded) {
            response.write(`: stream closed ${reason}\n\n`);
            response.end();
          }
          cleanup();
        },
      },
    });

    heartbeat = setInterval(() => {
      if (!cleaned && !response.writableEnded && !subscription?.backpressured) {
        try {
          response.write(`: heartbeat ${new Date().toISOString()}\n\n`);
        } catch {
          cleanup();
        }
      }
    }, heartbeatIntervalMs);
    heartbeat.unref?.();

    request.once("close", cleanup);
    response.once("close", cleanup);
    response.once("error", cleanup);
  });

  return router;
}

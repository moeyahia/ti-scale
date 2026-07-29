import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

const REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/u;

export interface V2ErrorDescriptor {
  readonly status: number;
  readonly code: string;
  readonly message: string;
  readonly humanMessage: string;
  readonly retryable: boolean;
  readonly category: string;
  readonly details?: unknown;
  readonly remediation?: string;
}

function validRequestId(value: unknown): value is string {
  return typeof value === "string" && REQUEST_ID.test(value);
}

/**
 * Resolve one correlation ID for the whole V2 request. A previously attached
 * response ID wins so nested mounted routers cannot silently replace it.
 */
export function v2RequestId(request: Request, response?: Response): string {
  const attached = response?.getHeader("X-Request-ID");
  if (validRequestId(attached)) return attached;
  const supplied = request.get("X-Request-ID")?.trim();
  return validRequestId(supplied) ? supplied : randomUUID();
}

export function attachV2RequestId(request: Request, response: Response): string {
  const traceId = v2RequestId(request, response);
  response.setHeader("X-Request-ID", traceId);
  return traceId;
}

/** Emit the one checked JSON error shape used by every canonical V2 domain. */
export function sendV2Error(
  response: Response,
  traceId: string,
  descriptor: V2ErrorDescriptor,
): void {
  response.setHeader("X-Request-ID", traceId);
  response.status(descriptor.status).json({
    error: {
      code: descriptor.code,
      message: descriptor.message,
      humanMessage: descriptor.humanMessage,
      retryable: descriptor.retryable,
      category: descriptor.category,
      ...(descriptor.details === undefined ? {} : { details: descriptor.details }),
      traceId,
      ...(descriptor.remediation ? { remediation: descriptor.remediation } : {}),
      timestamp: new Date().toISOString(),
    },
  });
}

function isV2Request(request: Request): boolean {
  return request.path === "/api/v2" || request.path.startsWith("/api/v2/");
}

/** Attach correlation before body parsing so parser failures remain traceable. */
export function v2RequestContext(
  request: Request,
  response: Response,
  next: NextFunction,
): void {
  if (isV2Request(request)) attachV2RequestId(request, response);
  next();
}

/** Convert only recognized JSON parser failures; unrelated errors keep flowing. */
export function v2JsonBodyError(
  error: unknown,
  request: Request,
  response: Response,
  next: NextFunction,
): void {
  if (!isV2Request(request)) {
    next(error);
    return;
  }
  const record = error && typeof error === "object" ? error as Record<string, unknown> : {};
  const type = typeof record.type === "string" ? record.type : "";
  const status = typeof record.status === "number" ? record.status : 0;
  const parseFailure = type === "entity.parse.failed" || (error instanceof SyntaxError && status === 400);
  const tooLarge = type === "entity.too.large" || status === 413;
  const unsupported = type === "encoding.unsupported" || type === "charset.unsupported";
  if (!parseFailure && !tooLarge && !unsupported) {
    next(error);
    return;
  }
  const traceId = attachV2RequestId(request, response);
  sendV2Error(response, traceId, tooLarge
    ? {
        status: 413,
        code: "request_body_too_large",
        message: "Ti-Scale request body exceeds the configured limit",
        humanMessage: "The submitted request is too large.",
        retryable: false,
        category: "invalid_input",
        remediation: "Submit only the bounded fields accepted by this endpoint.",
      }
    : unsupported
      ? {
          status: 415,
          code: "unsupported_request_encoding",
          message: "Ti-Scale request encoding is unsupported",
          humanMessage: "Send JSON using UTF-8 encoding.",
          retryable: false,
          category: "invalid_input",
          remediation: "Set Content-Type to application/json; charset=utf-8.",
        }
      : {
          status: 400,
          code: "invalid_json_body",
          message: "Ti-Scale request body is not valid JSON",
          humanMessage: "Correct the malformed JSON and submit the request again.",
          retryable: false,
          category: "invalid_input",
          remediation: "Validate the JSON syntax before retrying.",
        });
}

/** Final canonical 404 boundary; prevents unknown V2 paths from becoming SPA HTML. */
export function v2NotFound(
  request: Request,
  response: Response,
  next: NextFunction,
): void {
  if (!isV2Request(request)) {
    next();
    return;
  }
  const traceId = attachV2RequestId(request, response);
  sendV2Error(response, traceId, {
    status: 404,
    code: "ti_scale_route_not_found",
    message: "Ti-Scale route was not found",
    humanMessage: "The requested Ti-Scale endpoint does not exist.",
    retryable: false,
    category: "not_found",
    remediation: "Use an endpoint published by /api/v2/openapi.json.",
  });
}

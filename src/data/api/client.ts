import type { ApiErrorEnvelope } from "../../domain/types/commandOs";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly humanMessage?: string;
  readonly retryable: boolean;
  readonly remediation?: string;
  readonly traceId?: string;

  constructor(status: number, envelope: ApiErrorEnvelope) {
    super(envelope.message);
    this.name = "ApiError";
    this.status = status;
    this.code = envelope.code;
    this.humanMessage = envelope.humanMessage;
    this.retryable = envelope.retryable === true;
    this.remediation = envelope.remediation;
    this.traceId = envelope.traceId;
  }
}

async function responseBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    const body = await response.text();
    if (!response.ok) {
      throw new ApiError(response.status, {
        code: "unexpected_response",
        message: body || `Request failed with HTTP ${response.status}`,
        humanMessage: "The Ti-Scale service returned an unexpected response.",
        retryable: false,
        category: "protocol",
        traceId: response.headers.get("x-request-id") ?? "missing-request-id",
        timestamp: new Date().toISOString(),
      });
    }
    throw new Error("Expected a JSON response from the Ti-Scale service");
  }
  return response.json() as Promise<unknown>;
}

function errorEnvelope(payload: unknown, status: number, requestId: string | null): ApiErrorEnvelope {
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    const root = payload as Record<string, unknown>;
    const candidate = root.error && typeof root.error === "object"
      ? root.error as Record<string, unknown> : root;
    return {
      code: typeof candidate.code === "string" ? candidate.code : `http_${status}`,
      message: typeof candidate.message === "string" ? candidate.message : `Request failed with HTTP ${status}`,
      humanMessage: typeof candidate.humanMessage === "string"
        ? candidate.humanMessage
        : "The Ti-Scale request could not be completed.",
      retryable: candidate.retryable === true,
      category: typeof candidate.category === "string" ? candidate.category : "protocol",
      remediation: typeof candidate.remediation === "string" ? candidate.remediation : undefined,
      traceId: typeof candidate.traceId === "string" ? candidate.traceId : requestId ?? "missing-request-id",
      timestamp: typeof candidate.timestamp === "string" ? candidate.timestamp : new Date().toISOString(),
    };
  }
  return {
    code: `http_${status}`,
    message: `Request failed with HTTP ${status}`,
    humanMessage: "The Ti-Scale request could not be completed.",
    retryable: false,
    category: "protocol",
    traceId: requestId ?? "missing-request-id",
    timestamp: new Date().toISOString(),
  };
}

function csrfTokenFromCookie(): string | undefined {
  if (typeof document === "undefined") return undefined;
  const raw = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("ti_scale_csrf="))
    ?.slice("ti_scale_csrf=".length);
  if (!raw) return undefined;
  try {
    return decodeURIComponent(raw);
  } catch {
    return undefined;
  }
}

export async function apiRequest<T>(
  path: string,
  options: RequestInit & { parse: (payload: unknown) => T },
): Promise<T> {
  const { parse, ...request } = options;
  const method = (request.method ?? "GET").toUpperCase();
  const csrfToken = method === "GET" || method === "HEAD" || method === "OPTIONS"
    ? undefined
    : csrfTokenFromCookie();
  const response = await fetch(path, {
    credentials: "same-origin",
    cache: request.method === "GET" || !request.method ? "no-store" : undefined,
    ...request,
    headers: {
      Accept: "application/json",
      ...(request.body ? { "Content-Type": "application/json" } : {}),
      ...(csrfToken ? { "X-Ti-Scale-CSRF": csrfToken } : {}),
      ...request.headers,
    },
  }).catch((error: unknown) => {
    // Attach a rejection handler directly to the native fetch promise. Mobile
    // WebKit can otherwise report a reload-cancelled same-origin request as a
    // global access-control page error before the QueryCache's downstream
    // handler runs. Preserve every operational failure; normalize only a
    // request whose AbortSignal was explicitly cancelled by our lifecycle.
    if (request.signal?.aborted) {
      throw new DOMException("Ti-Scale request was cancelled", "AbortError");
    }
    throw error;
  });
  const payload = await responseBody(response);
  if (!response.ok) {
    throw new ApiError(
      response.status,
      errorEnvelope(payload, response.status, response.headers.get("x-request-id")),
    );
  }
  try {
    return parse(payload);
  } catch (error) {
    throw new ApiError(response.status, {
      code: "invalid_response_schema",
      message: error instanceof Error ? error.message : "Response failed schema validation",
      humanMessage: "Ti-Scale received data it could not safely interpret.",
      retryable: false,
      category: "protocol",
      traceId: response.headers.get("x-request-id") ?? "missing-request-id",
      remediation: "Check that the web client and server are running compatible versions.",
      timestamp: new Date().toISOString(),
    });
  }
}

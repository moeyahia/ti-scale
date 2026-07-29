import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  MessageExtraInfo,
  JSONRPCMessage,
} from "@modelcontextprotocol/sdk/types.js";
import type {
  Transport,
  TransportSendOptions,
} from "@modelcontextprotocol/sdk/shared/transport.js";
import { parseMcpServerConnectionConfig } from "./config";
import type {
  McpAttestationTransportFactory,
  McpServerConnectionConfig,
} from "./types";
import {
  SystemdCredentialStore,
  systemdCredentialStoreFromEnvironment,
} from "./SystemdCredentialStore";

const ALLOWED_METHODS = new Set(["GET", "POST", "DELETE"]);

export class McpTransportBoundaryError extends Error {
  constructor(
    readonly code:
      | "TRANSPORT_ABORTED"
      | "TRANSPORT_CONFIG_INVALID"
      | "TRANSPORT_ENDPOINT_CHANGED"
      | "TRANSPORT_METHOD_DENIED"
      | "TRANSPORT_REDIRECT_DENIED"
      | "TRANSPORT_REQUEST_TOO_LARGE"
      | "TRANSPORT_RESPONSE_TOO_LARGE",
    message: string,
  ) {
    super(message);
    this.name = "McpTransportBoundaryError";
  }
}

type FetchImplementation = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export interface BoundedStreamableHttpTransportFactoryOptions {
  readonly environment?: NodeJS.ProcessEnv;
  readonly fetch?: FetchImplementation;
  readonly credentialStore?: SystemdCredentialStore;
}

function requestUrl(input: Parameters<FetchImplementation>[0]): URL {
  if (input instanceof Request) return new URL(input.url);
  return new URL(input.toString());
}

function requestMethod(
  input: Parameters<FetchImplementation>[0],
  init: Parameters<FetchImplementation>[1],
): string {
  return (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
}

function bodyByteLength(body: BodyInit | null | undefined): number {
  if (body === undefined || body === null) return 0;
  if (typeof body !== "string") {
    throw new McpTransportBoundaryError(
      "TRANSPORT_CONFIG_INVALID",
      "The bounded MCP client permits only an explicitly serialized request body",
    );
  }
  return new TextEncoder().encode(body).byteLength;
}

function boundedResponse(response: Response, maxBytes: number): Response {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsed = Number(declaredLength);
    if (Number.isFinite(parsed) && parsed > maxBytes) {
      void response.body?.cancel().catch(() => undefined);
      throw new McpTransportBoundaryError(
        "TRANSPORT_RESPONSE_TOO_LARGE",
        "The MCP response exceeded the configured byte limit",
      );
    }
  }
  if (!response.body) return response;

  let received = 0;
  const limited = response.body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      received += chunk.byteLength;
      if (received > maxBytes) {
        controller.error(new McpTransportBoundaryError(
          "TRANSPORT_RESPONSE_TOO_LARGE",
          "The MCP response exceeded the configured byte limit",
        ));
        return;
      }
      controller.enqueue(chunk);
    },
  }));
  return new Response(limited, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

function configuredHeaders(
  config: Extract<McpServerConnectionConfig, { transport: "streamable-http" }>,
  environment: NodeJS.ProcessEnv,
  credentialStore: SystemdCredentialStore | undefined,
): Headers {
  const headers = new Headers();
  for (const [headerName, environmentName] of Object.entries(config.headerEnvironment ?? {})) {
    const value = environment[environmentName];
    if (!value?.trim()) {
      throw new McpTransportBoundaryError(
        "TRANSPORT_CONFIG_INVALID",
        `The MCP credential reference ${environmentName} is unavailable`,
      );
    }
    headers.set(headerName, value);
  }
  for (const [headerName, reference] of Object.entries(config.headerCredentials ?? {})) {
    if (!credentialStore) {
      throw new McpTransportBoundaryError(
        "TRANSPORT_CONFIG_INVALID",
        `The MCP systemd credential ${reference.id} is unavailable`,
      );
    }
    const credential = credentialStore.read(reference.id);
    try {
      const value = Buffer.from(credential).toString("utf8");
      headers.set(headerName, reference.scheme ? `${reference.scheme} ${value}` : value);
    } finally {
      credential.fill(0);
    }
  }
  return headers;
}

function boundedFetch(input: {
  readonly endpoint: URL;
  readonly maxBytes: number;
  readonly fetchImplementation: FetchImplementation;
}): FetchImplementation {
  return (async (request, init) => {
    const url = requestUrl(request);
    if (url.href !== input.endpoint.href) {
      throw new McpTransportBoundaryError(
        "TRANSPORT_ENDPOINT_CHANGED",
        "The MCP transport attempted to contact an endpoint outside its pinned connection",
      );
    }
    const method = requestMethod(request, init);
    if (!ALLOWED_METHODS.has(method)) {
      throw new McpTransportBoundaryError(
        "TRANSPORT_METHOD_DENIED",
        `The MCP transport denied HTTP method ${method}`,
      );
    }
    if (bodyByteLength(init?.body) > input.maxBytes) {
      throw new McpTransportBoundaryError(
        "TRANSPORT_REQUEST_TOO_LARGE",
        "The MCP request exceeded the configured byte limit",
      );
    }
    const response = await input.fetchImplementation(request, {
      ...init,
      redirect: "manual",
    });
    if (response.status >= 300 && response.status < 400) {
      void response.body?.cancel().catch(() => undefined);
      throw new McpTransportBoundaryError(
        "TRANSPORT_REDIRECT_DENIED",
        "The MCP endpoint returned a redirect, which is not allowed for a pinned connection",
      );
    }
    return boundedResponse(response, input.maxBytes);
  }) as FetchImplementation;
}

class AbortBoundTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void;
  private started = false;
  private closed = false;

  constructor(
    private readonly transport: StreamableHTTPClientTransport,
    private readonly signal: AbortSignal,
  ) {}

  get sessionId(): string | undefined {
    return this.transport.sessionId;
  }

  private readonly abort = (): void => {
    void this.close().catch(() => undefined);
  };

  async start(): Promise<void> {
    if (this.signal.aborted) {
      throw new McpTransportBoundaryError("TRANSPORT_ABORTED", "The MCP transport was cancelled before start");
    }
    this.transport.onclose = () => this.onclose?.();
    this.transport.onerror = (error) => this.onerror?.(error);
    this.transport.onmessage = (message) => this.onmessage?.(message);
    this.signal.addEventListener("abort", this.abort, { once: true });
    await this.transport.start();
    this.started = true;
  }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    if (this.signal.aborted) {
      throw new McpTransportBoundaryError("TRANSPORT_ABORTED", "The MCP transport request was cancelled");
    }
    await this.transport.send(message, options);
  }

  setProtocolVersion(version: string): void {
    this.transport.setProtocolVersion(version);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.signal.removeEventListener("abort", this.abort);
    if (this.started) await this.transport.close();
  }
}

/**
 * Creates only a bounded protocol transport. Capability attestation and exact
 * tool invocation authorization remain separate, fail-closed decisions.
 */
export class BoundedStreamableHttpTransportFactory implements McpAttestationTransportFactory {
  private readonly environment: NodeJS.ProcessEnv;
  private readonly fetchImplementation: FetchImplementation;
  private readonly credentialStore: SystemdCredentialStore | undefined;

  constructor(options: BoundedStreamableHttpTransportFactoryOptions = {}) {
    this.environment = options.environment ?? process.env;
    this.fetchImplementation = options.fetch ?? fetch;
    // An explicit `credentialStore: undefined` is a fail-closed production
    // signal: discovery was attempted and the private systemd mount was not
    // valid. Do not retry discovery here and turn a dependency/readiness
    // problem into an application-startup exception.
    this.credentialStore = Object.prototype.hasOwnProperty.call(options, "credentialStore")
      ? options.credentialStore
      : systemdCredentialStoreFromEnvironment(this.environment);
  }

  async create(
    input: McpServerConnectionConfig,
    context: Readonly<{ signal: AbortSignal; maxInboundMessageBytes: number }>,
  ): Promise<Transport> {
    const config = parseMcpServerConnectionConfig(input);
    if (config.transport !== "streamable-http") {
      throw new McpTransportBoundaryError(
        "TRANSPORT_CONFIG_INVALID",
        "This transport factory accepts only streamable HTTP MCP connections",
      );
    }
    const endpoint = new URL(config.endpoint);
    const transport = new StreamableHTTPClientTransport(endpoint, {
      fetch: boundedFetch({
        endpoint,
        maxBytes: context.maxInboundMessageBytes,
        fetchImplementation: this.fetchImplementation,
      }),
      requestInit: {
        headers: configuredHeaders(config, this.environment, this.credentialStore),
        redirect: "manual",
      },
      reconnectionOptions: {
        initialReconnectionDelay: 500,
        maxReconnectionDelay: 2_000,
        reconnectionDelayGrowFactor: 2,
        maxRetries: 0,
      },
    });
    return new AbortBoundTransport(transport, context.signal);
  }
}

import { timingSafeEqual } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import {
  createServer,
  type IncomingMessage,
  type Server as NodeHttpServer,
  type ServerResponse,
} from "node:http";
import { isAbsolute, resolve } from "node:path";
import type { Socket } from "node:net";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createPublicNvdMcpServer } from "./PublicNvdMcpServer";
import type { PublicNvdLookupPort } from "./types";

export const PUBLIC_NVD_MCP_BIND = "127.0.0.1";
export const PUBLIC_NVD_MCP_PATH = "/mcp";
export const PUBLIC_NVD_MCP_DEFAULT_PORT = 43_142;
export const PUBLIC_NVD_MCP_DEFAULT_TOKEN_FILE =
  "/run/credentials/ti-scale-mcp-nvd.service/mcp-token";
export const PUBLIC_NVD_MCP_DEFAULT_MAX_REQUEST_BYTES = 256 * 1024;

const MINIMUM_TOKEN_BYTES = 32;
const MAXIMUM_TOKEN_BYTES = 512;
const MAXIMUM_HEADER_BYTES = 16 * 1024;

class HttpRequestError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "HttpRequestError";
  }
}

export interface PublicNvdHttpSidecarOptions {
  readonly tokenFilePath: string;
  readonly port?: number;
  readonly maxRequestBytes?: number;
  readonly lookupPort?: PublicNvdLookupPort;
}

interface ActiveMcpRequest {
  readonly server: McpServer;
  readonly transport: StreamableHTTPServerTransport;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new RangeError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return resolved;
}

function secureCredentialPath(path: string, serviceUid: number): string {
  if (!isAbsolute(path)) throw new Error("The public NVD MCP token file path must be absolute");
  const normalized = resolve(path);
  const metadata = lstatSync(normalized);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("The public NVD MCP token credential must be a regular, non-symlink file");
  }
  if (realpathSync(normalized) !== normalized) {
    throw new Error("The public NVD MCP token credential path must not traverse symlinks");
  }
  if (metadata.uid !== 0 && metadata.uid !== serviceUid) {
    throw new Error("The public NVD MCP token credential must be owned by root or the sidecar service user");
  }
  const systemdCredential = normalized.startsWith("/run/credentials/");
  const unsafeMode = systemdCredential
    ? (metadata.mode & 0o007) !== 0
    : (metadata.mode & 0o077) !== 0;
  if (unsafeMode) {
    throw new Error("The public NVD MCP token credential must not be accessible to group or other users");
  }
  if (metadata.size < MINIMUM_TOKEN_BYTES || metadata.size > MAXIMUM_TOKEN_BYTES + 1) {
    throw new Error("The public NVD MCP token credential has an invalid size");
  }
  return normalized;
}

export function loadPublicNvdBearerToken(
  path: string,
  serviceUid = process.geteuid?.() ?? process.getuid?.() ?? -1,
): Uint8Array {
  const credentialPath = secureCredentialPath(path, serviceUid);
  const raw = readFileSync(credentialPath);
  if (raw.includes(0)) throw new Error("The public NVD MCP token credential contains invalid bytes");
  const text = raw.toString("utf8");
  const withoutTrailingNewline = text.endsWith("\r\n")
    ? text.slice(0, -2)
    : text.endsWith("\n")
      ? text.slice(0, -1)
      : text;
  if (withoutTrailingNewline.length < MINIMUM_TOKEN_BYTES
      || Buffer.byteLength(withoutTrailingNewline, "utf8") > MAXIMUM_TOKEN_BYTES
      || /\s/u.test(withoutTrailingNewline)
      || !/^[A-Za-z0-9._~-]+$/u.test(withoutTrailingNewline)) {
    throw new Error("The public NVD MCP token credential is not a valid single-line bearer token");
  }
  return new Uint8Array(Buffer.from(withoutTrailingNewline, "utf8"));
}

function constantTimeTokenMatch(expected: Uint8Array, authorization: string | undefined): boolean {
  if (!authorization?.startsWith("Bearer ")) return false;
  const candidateText = authorization.slice("Bearer ".length);
  if (!candidateText || /\s/u.test(candidateText)) return false;
  const candidate = Buffer.from(candidateText, "utf8");
  if (candidate.byteLength !== expected.byteLength) return false;
  return timingSafeEqual(candidate, expected);
}

function commonHeaders(response: ServerResponse): void {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
}

function jsonResponse(
  response: ServerResponse,
  status: number,
  code: string,
  humanMessage: string,
  extraHeaders: Readonly<Record<string, string>> = {},
): void {
  if (response.headersSent) return;
  commonHeaders(response);
  for (const [name, value] of Object.entries(extraHeaders)) response.setHeader(name, value);
  const body = JSON.stringify({
    error: { code, humanMessage },
    targetInteraction: false,
  });
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", Buffer.byteLength(body));
  response.end(body);
}

async function readBoundedJson(request: IncomingMessage, maximumBytes: number): Promise<unknown> {
  const declared = request.headers["content-length"];
  if (declared !== undefined) {
    if (Array.isArray(declared) || !/^\d+$/u.test(declared)) {
      throw new HttpRequestError(400, "The request Content-Length is invalid.");
    }
    if (Number(declared) > maximumBytes) {
      throw new HttpRequestError(413, "The MCP request exceeds the permitted size.");
    }
  }
  return await new Promise<unknown>((resolveBody, rejectBody) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      request.removeListener("data", onData);
      request.removeListener("end", onEnd);
      request.removeListener("error", onError);
      request.removeListener("aborted", onAborted);
      callback();
    };
    const onData = (chunk: Buffer | string) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += bytes.byteLength;
      if (total > maximumBytes) {
        request.resume();
        finish(() => rejectBody(new HttpRequestError(413, "The MCP request exceeds the permitted size.")));
        return;
      }
      chunks.push(bytes);
    };
    const onEnd = () => finish(() => {
      if (total === 0) {
        rejectBody(new HttpRequestError(400, "The MCP request body is required."));
        return;
      }
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
        resolveBody(JSON.parse(text));
      } catch {
        rejectBody(new HttpRequestError(400, "The MCP request body must be valid UTF-8 JSON."));
      }
    });
    const onError = () => finish(() => rejectBody(new HttpRequestError(400, "The MCP request could not be read.")));
    const onAborted = () => finish(() => rejectBody(new HttpRequestError(400, "The MCP request was interrupted.")));
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("error", onError);
    request.once("aborted", onAborted);
  });
}

export class PublicNvdHttpSidecar {
  private readonly expectedToken: Uint8Array;
  private readonly configuredPort: number;
  private readonly maxRequestBytes: number;
  private readonly lookupPort?: PublicNvdLookupPort;
  private readonly httpServer: NodeHttpServer;
  private readonly sockets = new Set<Socket>();
  private readonly activeMcp = new Set<ActiveMcpRequest>();
  private listeningPort: number | undefined;
  private stopping = false;

  constructor(options: PublicNvdHttpSidecarOptions) {
    this.expectedToken = loadPublicNvdBearerToken(options.tokenFilePath);
    this.configuredPort = boundedInteger(options.port, PUBLIC_NVD_MCP_DEFAULT_PORT, 0, 65_535, "port");
    this.maxRequestBytes = boundedInteger(
      options.maxRequestBytes,
      PUBLIC_NVD_MCP_DEFAULT_MAX_REQUEST_BYTES,
      1_024,
      1024 * 1024,
      "maxRequestBytes",
    );
    this.lookupPort = options.lookupPort;
    this.httpServer = createServer({
      maxHeaderSize: MAXIMUM_HEADER_BYTES,
      requireHostHeader: true,
    }, (request, response) => {
      void this.handle(request, response).catch(() => {
        jsonResponse(
          response,
          500,
          "internal_error",
          "The public NVD MCP sidecar failed safely without contacting an assessed target.",
        );
      });
    });
    this.httpServer.requestTimeout = 15_000;
    this.httpServer.headersTimeout = 5_000;
    this.httpServer.keepAliveTimeout = 5_000;
    this.httpServer.maxRequestsPerSocket = 100;
    this.httpServer.on("connection", (socket) => {
      this.sockets.add(socket);
      socket.once("close", () => this.sockets.delete(socket));
    });
    this.httpServer.on("clientError", (_error, socket) => {
      if (socket.writable) {
        socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
      }
    });
  }

  get port(): number {
    if (this.listeningPort === undefined) throw new Error("The public NVD MCP sidecar is not listening");
    return this.listeningPort;
  }

  get endpoint(): URL {
    return new URL(`http://${PUBLIC_NVD_MCP_BIND}:${this.port}${PUBLIC_NVD_MCP_PATH}`);
  }

  async start(): Promise<void> {
    if (this.listeningPort !== undefined) throw new Error("The public NVD MCP sidecar is already listening");
    this.stopping = false;
    await new Promise<void>((resolveStart, rejectStart) => {
      const onError = (error: Error) => {
        this.httpServer.removeListener("listening", onListening);
        rejectStart(error);
      };
      const onListening = () => {
        this.httpServer.removeListener("error", onError);
        resolveStart();
      };
      this.httpServer.once("error", onError);
      this.httpServer.once("listening", onListening);
      this.httpServer.listen(this.configuredPort, PUBLIC_NVD_MCP_BIND);
    });
    const address = this.httpServer.address();
    if (!address || typeof address === "string" || address.address !== PUBLIC_NVD_MCP_BIND) {
      await this.stop();
      throw new Error("The public NVD MCP sidecar did not bind to the required loopback address");
    }
    this.listeningPort = address.port;
  }

  async stop(): Promise<void> {
    if (this.stopping) return;
    this.stopping = true;
    const closeHttp = this.httpServer.listening
      ? new Promise<void>((resolveClose) => this.httpServer.close(() => resolveClose()))
      : Promise.resolve();
    const active = [...this.activeMcp];
    await Promise.allSettled(active.flatMap(({ server, transport }) => [
      transport.close(),
      server.close(),
    ]));
    this.httpServer.closeIdleConnections?.();
    for (const socket of this.sockets) socket.destroy();
    await closeHttp;
    this.activeMcp.clear();
    this.sockets.clear();
    this.listeningPort = undefined;
    this.expectedToken.fill(0);
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    commonHeaders(response);
    if (request.url !== PUBLIC_NVD_MCP_PATH) {
      jsonResponse(response, 404, "not_found", "This sidecar exposes only the fixed /mcp endpoint.");
      return;
    }
    if (this.stopping) {
      jsonResponse(response, 503, "shutting_down", "The public NVD MCP sidecar is shutting down.");
      return;
    }
    if (!this.isLoopbackRequest(request)) {
      jsonResponse(response, 403, "loopback_required", "The public NVD MCP endpoint accepts loopback requests only.");
      return;
    }
    if (!constantTimeTokenMatch(this.expectedToken, request.headers.authorization)) {
      jsonResponse(
        response,
        401,
        "authentication_required",
        "A valid sidecar bearer credential is required.",
        { "WWW-Authenticate": 'Bearer realm="ti-scale-public-nvd"' },
      );
      return;
    }
    if (request.method !== "POST") {
      jsonResponse(response, 405, "method_not_allowed", "Use POST for this MCP endpoint.", { Allow: "POST" });
      return;
    }
    const contentType = request.headers["content-type"];
    if (typeof contentType !== "string" || contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
      jsonResponse(response, 415, "unsupported_media_type", "MCP requests must use application/json.");
      return;
    }

    let parsedBody: unknown;
    try {
      parsedBody = await readBoundedJson(request, this.maxRequestBytes);
    } catch (error) {
      if (error instanceof HttpRequestError) {
        response.shouldKeepAlive = false;
        jsonResponse(
          response,
          error.status,
          error.status === 413 ? "request_too_large" : "invalid_request_body",
          error.message,
          { Connection: "close" },
        );
        return;
      }
      throw error;
    }

    const server = createPublicNvdMcpServer(
      this.lookupPort ? { client: this.lookupPort } : {},
    );
    const expectedHost = `${PUBLIC_NVD_MCP_BIND}:${this.port}`;
    const expectedOrigin = `http://${expectedHost}`;
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
      enableDnsRebindingProtection: true,
      allowedHosts: [expectedHost],
      allowedOrigins: [expectedOrigin],
    });
    const active = { server, transport };
    this.activeMcp.add(active);
    try {
      await server.connect(transport);
      await transport.handleRequest(request, response, parsedBody);
    } finally {
      this.activeMcp.delete(active);
      await Promise.allSettled([transport.close(), server.close()]);
    }
  }

  private isLoopbackRequest(request: IncomingMessage): boolean {
    const expectedHost = `${PUBLIC_NVD_MCP_BIND}:${this.port}`;
    if (request.headers.host !== expectedHost) return false;
    const origin = request.headers.origin;
    if (origin !== undefined && origin !== `http://${expectedHost}`) return false;
    const remote = request.socket.remoteAddress;
    return remote === PUBLIC_NVD_MCP_BIND || remote === `::ffff:${PUBLIC_NVD_MCP_BIND}`;
  }
}

export function resolvePublicNvdHttpPort(value: string | undefined): number {
  if (!value) return PUBLIC_NVD_MCP_DEFAULT_PORT;
  if (!/^\d+$/u.test(value)) throw new Error("TI_SCALE_PUBLIC_NVD_MCP_PORT must be a decimal port number");
  return boundedInteger(Number(value), PUBLIC_NVD_MCP_DEFAULT_PORT, 1, 65_535, "TI_SCALE_PUBLIC_NVD_MCP_PORT");
}

export function resolvePublicNvdTokenFilePath(value: string | undefined): string {
  return value?.trim() || PUBLIC_NVD_MCP_DEFAULT_TOKEN_FILE;
}

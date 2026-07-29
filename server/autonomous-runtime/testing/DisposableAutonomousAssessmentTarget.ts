import { createServer, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";

export const DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST = "127.0.0.2" as const;
export const DISPOSABLE_AUTONOMOUS_ASSESSMENT_PORT = 8_080 as const;
export const DISPOSABLE_AUTONOMOUS_ASSESSMENT_SERVER =
  "Apache/2.4.58" as const;

export interface DisposableAutonomousAssessmentRequest {
  readonly sequence: number;
  readonly method: string;
  readonly path: string;
  readonly outcome: "served" | "transient_reset";
}

export interface DisposableAutonomousAssessmentFailureReceipt {
  readonly enabled: boolean;
  readonly injectedFailureCount: number;
  readonly recoveredCurlHeadCount: number;
}

export interface DisposableAutonomousAssessmentTargetOptions {
  /**
   * Proof-only transport fault. The first exact curl HEAD request to `/` is
   * reset before any HTTP response; every later request is served normally.
   */
  readonly recoverableHttpMetadataFailureOnce?: boolean;
}

export interface DisposableAutonomousAssessmentTarget {
  readonly host: typeof DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST;
  readonly port: number;
  readonly origin: string;
  readonly requests: () => readonly DisposableAutonomousAssessmentRequest[];
  readonly failureReceipt: () => DisposableAutonomousAssessmentFailureReceipt;
  readonly close: () => Promise<void>;
}

function requestPath(raw: string | undefined): string {
  try {
    return new URL(raw ?? "/", "http://127.0.0.2").pathname;
  } catch {
    return "/invalid";
  }
}

function responseBody(path: string): Readonly<{
  status: number;
  contentType: string;
  body: string;
}> {
  if (path === "/robots.txt") {
    return {
      status: 200,
      contentType: "text/plain; charset=utf-8",
      body: "User-agent: *\nDisallow: /admin\n",
    };
  }
  if (path === "/" || path === "/health") {
    return {
      status: 200,
      contentType: "text/html; charset=utf-8",
      body: [
        "<!doctype html><html><head>",
        "<title>Ti-Scale disposable assessment fixture</title>",
        "</head><body><main>",
        "Reviewed local Autonomous assessment target",
        "</main></body></html>",
      ].join(""),
    };
  }
  if (path === "/admin") {
    return {
      status: 403,
      contentType: "text/plain; charset=utf-8",
      body: "Access denied\n",
    };
  }
  return {
    status: 404,
    contentType: "text/plain; charset=utf-8",
    body: "Not found\n",
  };
}

function send(
  response: ServerResponse,
  method: string,
  path: string,
): void {
  if (method === "OPTIONS") {
    response.writeHead(204, {
      Allow: "GET, HEAD, OPTIONS",
      "Cache-Control": "no-store",
      Connection: "close",
      Server: DISPOSABLE_AUTONOMOUS_ASSESSMENT_SERVER,
    });
    response.end();
    return;
  }
  if (!["GET", "HEAD"].includes(method)) {
    const body = "Method not allowed\n";
    response.writeHead(405, {
      Allow: "GET, HEAD, OPTIONS",
      "Cache-Control": "no-store",
      Connection: "close",
      "Content-Length": String(Buffer.byteLength(body)),
      "Content-Type": "text/plain; charset=utf-8",
      Server: DISPOSABLE_AUTONOMOUS_ASSESSMENT_SERVER,
    });
    response.end(method === "HEAD" ? undefined : body);
    return;
  }
  const result = responseBody(path);
  response.writeHead(result.status, {
    "Cache-Control": "no-store",
    Connection: "close",
    "Content-Length": String(Buffer.byteLength(result.body)),
    "Content-Type": result.contentType,
    Server: DISPOSABLE_AUTONOMOUS_ASSESSMENT_SERVER,
  });
  response.end(method === "HEAD" ? undefined : result.body);
}

/**
 * Starts one harmless HTTP target on a loopback address that is distinct from
 * the Ti-Scale control plane and the legacy application. The target never
 * redirects, executes caller input, reads host files, or changes host state.
 */
export async function startDisposableAutonomousAssessmentTarget(
  options: DisposableAutonomousAssessmentTargetOptions = {},
):
Promise<DisposableAutonomousAssessmentTarget> {
  const observed: DisposableAutonomousAssessmentRequest[] = [];
  const sockets = new Set<Socket>();
  let sequence = 0;
  let injectedFailureCount = 0;
  let recoveredCurlHeadCount = 0;
  const injectRecoverableFailure =
    options.recoverableHttpMetadataFailureOnce === true;
  const server: Server = createServer((request, response) => {
    sequence += 1;
    const method = request.method ?? "UNKNOWN";
    const path = requestPath(request.url);
    const userAgent = typeof request.headers["user-agent"] === "string"
      ? request.headers["user-agent"]
      : "";
    const exactCurlHead = method === "HEAD"
      && path === "/"
      && /^curl\/[0-9]/u.test(userAgent);
    if (
      injectRecoverableFailure
      && exactCurlHead
      && injectedFailureCount === 0
    ) {
      injectedFailureCount = 1;
      observed.push(Object.freeze({
        sequence,
        method,
        path,
        outcome: "transient_reset",
      }));
      request.socket.destroy();
      return;
    }
    if (injectRecoverableFailure && exactCurlHead && injectedFailureCount === 1) {
      recoveredCurlHeadCount += 1;
    }
    observed.push(Object.freeze({ sequence, method, path, outcome: "served" }));
    send(response, method, path);
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(
      DISPOSABLE_AUTONOMOUS_ASSESSMENT_PORT,
      DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST,
    );
  });
  const address = server.address();
  if (!address || typeof address === "string"
    || (address as AddressInfo).address !== DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST
    || (address as AddressInfo).port !== DISPOSABLE_AUTONOMOUS_ASSESSMENT_PORT) {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error("Disposable Autonomous assessment target bound to the wrong address or port");
  }
  const port = (address as AddressInfo).port;
  let closed = false;
  return Object.freeze({
    host: DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST,
    port,
    origin: `http://${DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST}:${port}`,
    requests: () => Object.freeze(observed.map((item) => Object.freeze({ ...item }))),
    failureReceipt: () => Object.freeze({
      enabled: injectRecoverableFailure,
      injectedFailureCount,
      recoveredCurlHeadCount,
    }),
    close: async () => {
      if (closed) return;
      closed = true;
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    },
  });
}

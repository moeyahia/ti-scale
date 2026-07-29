import { createHash } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { digestCanonicalJson } from "../../mcp/canonicalJson";
import {
  LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
  LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
  LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
  LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
} from "../CandidateLinuxPrivilegeContinuation";
import {
  LOOPBACK_EXPLOIT_FIXTURE_CVE,
  LOOPBACK_EXPLOIT_FIXTURE_IMPACT_MARKER,
  LOOPBACK_EXPLOIT_FIXTURE_PATH,
  LOOPBACK_EXPLOIT_FIXTURE_PRODUCT,
  LOOPBACK_EXPLOIT_FIXTURE_VERSION,
} from "./LoopbackExploitFixture";

export const DISPOSABLE_COMPLETE_AUTONOMOUS_HOST = "127.0.0.2" as const;
export const DISPOSABLE_COMPLETE_AUTONOMOUS_PORT = 8_080 as const;
export const DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT =
  LOOPBACK_EXPLOIT_FIXTURE_PRODUCT;
export const DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION =
  LOOPBACK_EXPLOIT_FIXTURE_VERSION;
export const DISPOSABLE_COMPLETE_AUTONOMOUS_CVE =
  LOOPBACK_EXPLOIT_FIXTURE_CVE;
export const DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH =
  LOOPBACK_EXPLOIT_FIXTURE_PATH;
export const DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_ROUTED_PATH =
  new URL(
    DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH,
    "http://disposable.invalid",
  ).pathname;
export const DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER =
  LOOPBACK_EXPLOIT_FIXTURE_IMPACT_MARKER;
export const DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER_HEADER =
  "X-Ti-Scale-Fixture-Marker" as const;
export const DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER =
  "reviewed-complete-autonomous-fixture-v1" as const;
export const DISPOSABLE_COMPLETE_AUTONOMOUS_SERVER_HEADER =
  `${DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT}/${DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION}` as const;

const MAXIMUM_REQUEST_BYTES = 32 * 1_024;
const DIGEST_LIMITS = Object.freeze({
  maxBytes: 32 * 1_024,
  maxDepth: 12,
});

type SessionStage = "open" | "privileged" | "closed";

export type DisposableCompleteAutonomousTracePhase =
  | "recon"
  | "exploit_validation"
  | "session";

export interface DisposableCompleteAutonomousTrace {
  readonly sequence: number;
  readonly method: string;
  readonly path: string;
  readonly phase: DisposableCompleteAutonomousTracePhase;
  readonly actionId: string | null;
  readonly fixtureMarker: string | null;
  readonly result:
    | "recon_response"
    | "fixed_impact_triggered"
    | "fixed_impact_disclosed"
    | "session_opened"
    | "user_identity_observed"
    | "user_hash_proved"
    | "privilege_continued"
    | "root_identity_observed"
    | "root_hash_proved"
    | "session_closed"
    | "rejected"
    | "not_found";
}

export interface DisposableCompleteAutonomousTarget {
  readonly schemaVersion:
    "ti-scale.disposable-complete-autonomous-target.v1";
  readonly host: typeof DISPOSABLE_COMPLETE_AUTONOMOUS_HOST;
  readonly port: number;
  readonly origin: string;
  readonly fixtureOnly: true;
  readonly disposableSimulationOnly: true;
  readonly realTargetSupport: false;
  readonly arbitraryExternalTargetSupport: false;
  readonly hostFileReads: false;
  readonly commandExecution: false;
  readonly traces: () => readonly DisposableCompleteAutonomousTrace[];
  readonly openSessionCount: () => number;
  readonly close: () => Promise<void>;
}

function rawPath(request: IncomingMessage): string {
  const raw = request.url ?? "/";
  const query = raw.indexOf("?");
  return query < 0 ? raw : raw.slice(0, query);
}

function actionId(request: IncomingMessage): string | null {
  const value = request.headers["x-ti-scale-action"];
  return typeof value === "string" && value.trim()
    ? value.trim().slice(0, 200)
    : null;
}

function fixtureMarker(request: IncomingMessage): string | null {
  const value = request.headers[
    DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER_HEADER
      .toLocaleLowerCase("en-US")
  ];
  return typeof value === "string" && value.trim()
    ? value.trim().slice(0, 200)
    : null;
}

export function isDisposableCompleteAutonomousImpactPath(
  path: string,
): boolean {
  const normalized = path.toLocaleLowerCase("en-US");
  return normalized
      === DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH
        .toLocaleLowerCase("en-US")
    || normalized
      === DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_ROUTED_PATH
        .toLocaleLowerCase("en-US");
}

function responseHeaders(length: number, contentType: string) {
  return {
    "Cache-Control": "no-store",
    Connection: "close",
    "Content-Length": String(length),
    "Content-Type": contentType,
    Server: DISPOSABLE_COMPLETE_AUTONOMOUS_SERVER_HEADER,
    "X-Ti-Scale-Fixture": "disposable-complete-autonomous-v1",
  };
}

function sendBytes(
  response: ServerResponse,
  status: number,
  bytes: Buffer,
  contentType: string,
  head = false,
): void {
  response.writeHead(status, responseHeaders(bytes.byteLength, contentType));
  response.end(head ? undefined : bytes);
}

function sendText(
  response: ServerResponse,
  status: number,
  body: string,
  contentType: string,
  head = false,
): void {
  sendBytes(response, status, Buffer.from(body, "utf8"), contentType, head);
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: Readonly<Record<string, unknown>>,
): void {
  sendText(
    response,
    status,
    `${JSON.stringify(body)}\n`,
    "application/json; charset=utf-8",
  );
}

function signed(
  body: Readonly<Record<string, unknown>>,
  hashField: string,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    ...body,
    [hashField]: digestCanonicalJson(body, DIGEST_LIMITS).sha256,
  });
}

async function boundedJson(
  request: IncomingMessage,
): Promise<Readonly<Record<string, unknown>>> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += value.byteLength;
    if (bytes > MAXIMUM_REQUEST_BYTES) {
      throw new RangeError(
        `Disposable target request exceeded ${MAXIMUM_REQUEST_BYTES} bytes`,
      );
    }
    chunks.push(value);
  }
  const value = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Disposable target request must be one JSON object");
  }
  return value as Readonly<Record<string, unknown>>;
}

function reconBody(path: string): Readonly<{
  status: number;
  contentType: string;
  body: string;
}> {
  if (path === "/robots.txt") {
    return Object.freeze({
      status: 200,
      contentType: "text/plain; charset=utf-8",
      body: "User-agent: *\nDisallow: /admin\n",
    });
  }
  if (path === "/" || path === "/health") {
    return Object.freeze({
      status: 200,
      contentType: "text/html; charset=utf-8",
      body: [
        "<!doctype html><html><head>",
        "<title>Ti-Scale disposable complete Autonomous fixture</title>",
        "</head><body><main>",
        "<h1>Authorized disposable loopback lab</h1>",
        "<p>Fixture-only Apache HTTP Server 2.4.49 evidence surface.</p>",
        "</main></body></html>",
      ].join(""),
    });
  }
  if (path === "/admin") {
    return Object.freeze({
      status: 403,
      contentType: "text/plain; charset=utf-8",
      body: "Access denied\n",
    });
  }
  return Object.freeze({
    status: 404,
    contentType: "text/plain; charset=utf-8",
    body: "Not found\n",
  });
}

/**
 * Starts a single harmless service on 127.0.0.2.
 *
 * The fixture is intentionally not an arbitrary-target adapter. Its exploit
 * path returns one fixed marker, and its session endpoints mutate only an
 * in-memory state machine. It never reads a host file, executes a command,
 * accepts credentials, returns flag content, or contacts another service.
 */
export async function startDisposableCompleteAutonomousTarget(
  port: number = DISPOSABLE_COMPLETE_AUTONOMOUS_PORT,
): Promise<DisposableCompleteAutonomousTarget> {
  if (
    !Number.isSafeInteger(port)
    || port < 0
    || port > 65_535
  ) {
    throw new RangeError("Disposable complete target port is invalid");
  }

  const traces: DisposableCompleteAutonomousTrace[] = [];
  const sessions = new Map<string, SessionStage>();
  const sockets = new Set<Socket>();
  let sequence = 0;
  let closed = false;
  let impactTriggered = false;

  const trace = (
    request: IncomingMessage,
    phase: DisposableCompleteAutonomousTracePhase,
    result: DisposableCompleteAutonomousTrace["result"],
  ): void => {
    sequence += 1;
    traces.push(Object.freeze({
      sequence,
      method: request.method ?? "UNKNOWN",
      path: rawPath(request),
      phase,
      actionId: actionId(request),
      fixtureMarker: fixtureMarker(request),
      result,
    }));
  };

  const reject = (
    request: IncomingMessage,
    response: ServerResponse,
    error: string,
  ): void => {
    trace(request, "session", "rejected");
    sendJson(response, 409, {
      schemaVersion: "ti-scale.disposable-target-error.v1",
      fixtureOnly: true,
      error,
    });
  };

  const server: Server = createServer((request, response) => {
    const method = request.method ?? "UNKNOWN";
    const path = rawPath(request);
    const url = new URL(request.url ?? "/", "http://127.0.0.2");

    if (method === "POST" && path === "/ti-scale/session/open") {
      void boundedJson(request).then((body) => {
        if (
          body.exactTarget !== DISPOSABLE_COMPLETE_AUTONOMOUS_HOST
          || typeof body.sessionArtifactId !== "string"
          || !body.sessionArtifactId.trim()
          || sessions.has(body.sessionArtifactId)
        ) {
          reject(request, response, "invalid_session_open");
          return;
        }
        sessions.set(body.sessionArtifactId, "open");
        trace(request, "session", "session_opened");
        sendJson(response, 200, {
          schemaVersion: "ti-scale.disposable-session-open.v1",
          fixtureOnly: true,
          accepted: true,
          sessionArtifactId: body.sessionArtifactId,
        });
      }).catch(() => reject(request, response, "invalid_session_open"));
      return;
    }

    if (method === "GET" && path === "/ti-scale/session/identity") {
      const sessionArtifactId =
        url.searchParams.get("sessionArtifactId") ?? "";
      if (
        url.searchParams.get("exactTarget")
          !== DISPOSABLE_COMPLETE_AUTONOMOUS_HOST
        || sessions.get(sessionArtifactId) !== "open"
      ) {
        reject(request, response, "session_not_open");
        return;
      }
      trace(request, "session", "user_identity_observed");
      sendJson(response, 200, {
        schemaVersion: "ti-scale.disposable-session-identity.v1",
        fixtureOnly: true,
        sessionArtifactId,
        principal: "fixtureuser",
        uid: 1_000,
        gid: 1_000,
        groups: ["fixtureuser"],
      });
      return;
    }

    if (
      method === "POST"
      && path === "/ti-scale/session/user-flag-proof"
    ) {
      void boundedJson(request).then((body) => {
        if (
          body.exactTarget !== DISPOSABLE_COMPLETE_AUTONOMOUS_HOST
          || typeof body.sessionArtifactId !== "string"
          || sessions.get(body.sessionArtifactId) !== "open"
          || body.declaredPath !== "/home/fixtureuser/user.txt"
          || body.returnContent === true
        ) {
          reject(request, response, "user_proof_unavailable");
          return;
        }
        const syntheticProof = Buffer.alloc(32, 0x55);
        trace(request, "session", "user_hash_proved");
        sendJson(response, 200, {
          schemaVersion: "ti-scale.disposable-user-hash-proof.v1",
          fixtureOnly: true,
          sessionArtifactId: body.sessionArtifactId,
          declaredPath: body.declaredPath,
          sha256: createHash("sha256").update(syntheticProof).digest("hex"),
          byteSize: syntheticProof.byteLength,
          contentReturned: false,
        });
      }).catch(() => reject(request, response, "invalid_user_proof"));
      return;
    }

    if (
      method === "POST"
      && path === "/ti-scale/session/privilege-escalation"
    ) {
      void boundedJson(request).then((body) => {
        if (
          typeof body.sessionArtifactId !== "string"
          || sessions.get(body.sessionArtifactId) !== "open"
          || body.operation !== "privilege_escalation"
        ) {
          reject(request, response, "privilege_unavailable");
          return;
        }
        sessions.set(body.sessionArtifactId, "privileged");
        trace(request, "session", "privilege_continued");
        sendJson(response, 200, signed({
          schemaVersion: LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
          fixtureOnly: true,
          sessionArtifactId: body.sessionArtifactId,
          accepted: true,
          observedAt: new Date().toISOString(),
        }, "receiptSha256"));
      }).catch(() => reject(request, response, "invalid_privilege_request"));
      return;
    }

    if (
      method === "GET"
      && path === "/ti-scale/session/root-identity"
    ) {
      const sessionArtifactId =
        url.searchParams.get("sessionArtifactId") ?? "";
      if (sessions.get(sessionArtifactId) !== "privileged") {
        reject(request, response, "root_identity_unavailable");
        return;
      }
      trace(request, "session", "root_identity_observed");
      sendJson(response, 200, signed({
        schemaVersion: LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
        fixtureOnly: true,
        sessionArtifactId,
        principal: "root",
        uid: 0,
        gid: 0,
        groups: ["root"],
        observedAt: new Date().toISOString(),
      }, "observationSha256"));
      return;
    }

    if (
      method === "POST"
      && path === "/ti-scale/session/root-flag-proof"
    ) {
      void boundedJson(request).then((body) => {
        if (
          typeof body.sessionArtifactId !== "string"
          || sessions.get(body.sessionArtifactId) !== "privileged"
          || body.operation !== "root_flag_hash_proof"
          || body.declaredPath !== "/root/root.txt"
          || body.returnContent !== false
        ) {
          reject(request, response, "root_proof_unavailable");
          return;
        }
        const syntheticProof = Buffer.alloc(32, 0x52);
        trace(request, "session", "root_hash_proved");
        sendJson(response, 200, signed({
          schemaVersion: LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
          fixtureOnly: true,
          sessionArtifactId: body.sessionArtifactId,
          declaredPath: "/root/root.txt",
          contentSha256: createHash("sha256")
            .update(syntheticProof)
            .digest("hex"),
          byteSize: syntheticProof.byteLength,
          contentReturned: false,
          observedAt: new Date().toISOString(),
        }, "proofSha256"));
      }).catch(() => reject(request, response, "invalid_root_proof"));
      return;
    }

    if (method === "POST" && path === "/ti-scale/session/cleanup") {
      void boundedJson(request).then((body) => {
        if (
          typeof body.sessionArtifactId !== "string"
          || !sessions.has(body.sessionArtifactId)
          || body.operation !== "cleanup"
        ) {
          reject(request, response, "session_unknown");
          return;
        }
        sessions.set(body.sessionArtifactId, "closed");
        trace(request, "session", "session_closed");
        sendJson(response, 200, signed({
          schemaVersion: LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
          fixtureOnly: true,
          sessionArtifactId: body.sessionArtifactId,
          closed: true,
          observedAt: new Date().toISOString(),
        }, "receiptSha256"));
      }).catch(() => reject(request, response, "invalid_cleanup"));
      return;
    }

    if (
      method === "GET"
      && isDisposableCompleteAutonomousImpactPath(path)
    ) {
      const reviewedTrigger =
        fixtureMarker(request)
          === DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER;
      const independentObservation =
        impactTriggered
        && fixtureMarker(request) === null
        && actionId(request) === null;
      if (!reviewedTrigger && !independentObservation) {
        trace(request, "exploit_validation", "rejected");
        sendJson(response, 404, {
          schemaVersion: "ti-scale.disposable-target-impact.v1",
          fixtureOnly: true,
          realTargetSupport: false,
          error: "fixed_impact_not_triggered",
        });
        return;
      }
      if (reviewedTrigger) impactTriggered = true;
      trace(
        request,
        "exploit_validation",
        reviewedTrigger
          ? "fixed_impact_triggered"
          : "fixed_impact_disclosed",
      );
      sendJson(response, 200, {
        schemaVersion: "ti-scale.disposable-target-impact.v1",
        fixtureOnly: true,
        realTargetSupport: false,
        impact: "read_only_marker_disclosed",
        marker: DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER,
        actionId: actionId(request),
        observationRole: reviewedTrigger
          ? "reviewed_fixture_trigger"
          : "independent_outcome_observation",
      });
      return;
    }

    if (method === "GET" && path === "/version") {
      trace(request, "recon", "recon_response");
      sendJson(response, 200, {
        schemaVersion: "ti-scale.disposable-target-version.v1",
        fixtureOnly: true,
        product: DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT,
        version: DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
        cveFixture: DISPOSABLE_COMPLETE_AUTONOMOUS_CVE,
      });
      return;
    }

    if (method === "OPTIONS") {
      trace(request, "recon", "recon_response");
      response.writeHead(204, {
        ...responseHeaders(0, "text/plain; charset=utf-8"),
        Allow: "GET, HEAD, OPTIONS",
      });
      response.end();
      return;
    }

    if (method === "GET" || method === "HEAD") {
      const result = reconBody(path);
      trace(
        request,
        "recon",
        result.status === 404 ? "not_found" : "recon_response",
      );
      sendText(
        response,
        result.status,
        result.body,
        result.contentType,
        method === "HEAD",
      );
      return;
    }

    trace(request, "recon", "rejected");
    sendText(
      response,
      405,
      "Method not allowed\n",
      "text/plain; charset=utf-8",
    );
  });

  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, DISPOSABLE_COMPLETE_AUTONOMOUS_HOST);
  });

  const address = server.address();
  if (
    !address
    || typeof address === "string"
    || (address as AddressInfo).address
      !== DISPOSABLE_COMPLETE_AUTONOMOUS_HOST
    || (port !== 0 && (address as AddressInfo).port !== port)
  ) {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error(
      "Disposable complete Autonomous target bound to the wrong address or port",
    );
  }

  return Object.freeze({
    schemaVersion: "ti-scale.disposable-complete-autonomous-target.v1",
    host: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
    port: (address as AddressInfo).port,
    origin:
      `http://${DISPOSABLE_COMPLETE_AUTONOMOUS_HOST}:${(address as AddressInfo).port}`,
    fixtureOnly: true,
    disposableSimulationOnly: true,
    realTargetSupport: false,
    arbitraryExternalTargetSupport: false,
    hostFileReads: false,
    commandExecution: false,
    traces: () => Object.freeze(
      traces.map((item) => Object.freeze({ ...item })),
    ),
    openSessionCount: () => [...sessions.values()]
      .filter((stage) => stage !== "closed").length,
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

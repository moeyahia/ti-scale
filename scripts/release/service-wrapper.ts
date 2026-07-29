#!/usr/bin/env bun
import { createServer, type Server } from "node:http";
import { isAbsolute, join, resolve } from "node:path";
import {
  RELEASE_STARTUP_MUTATION_BARRIER_PATH,
  releaseStartupMutationBarrierExists,
} from "./ReleaseStartupMutationBarrier";
import {
  assertReleaseServiceStartAdmissionInstallationCommitted,
} from "./ReleaseServiceStartAdmissionInstallation";

export const RELEASE_SERVICE_WRAPPER_PROTOCOL =
  "ti-scale.release-service-wrapper.v2" as const;
export const RELEASE_GUARDED_HEALTH_PROTOCOL =
  "ti-scale.release-journal-guarded-health.v1" as const;
export const RELEASE_SERVICE_WRAPPER_APPLICATION_PATH = "/opt/ti-scale";
export const RELEASE_SERVICE_WRAPPER_BUN_PATH = "/usr/local/bin/bun";
export const RELEASE_SERVICE_WRAPPER_DEFAULT_PORT = 3132;
export const RELEASE_SERVICE_WRAPPER_APPLICATION_ENTRYPOINT =
  "/opt/ti-scale/server/index.ts";

const SYSTEMD_INVOCATION_ID = /^[a-f0-9]{32}$/u;
const GUARDED_PATHS = new Set([
  "/api/v2/health",
  "/api/v2/system/readiness",
]);

export interface ReleaseGuardedServer {
  readonly port: number;
  close(): Promise<void>;
}

export interface ReleaseServiceWrapperOptions {
  readonly invocationId: string;
  readonly host?: string;
  readonly port?: number;
  readonly pollIntervalMs?: number;
  readonly barrierExists?: () => boolean;
  readonly createGuardedServer?: (
    invocationId: string,
    host: string,
    port: number,
  ) => Promise<ReleaseGuardedServer>;
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly execApplication?: () => never;
  /** Injectable only for process-boundary integration tests. The installed
   * CLI never reads an application path from its environment or arguments. */
  readonly applicationPath?: string;
  readonly bunPath?: string;
}

export interface ReleaseServiceApplicationExecSpec {
  readonly executable: string;
  readonly argv: readonly string[];
  readonly cwd: string;
  readonly environment: Readonly<Record<string, string>>;
}

function exactPort(value: unknown): number {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error("TI_SCALE_PORT must be an integer between 1 and 65535");
  }
  return port;
}

function exactInvocationId(value: string): string {
  const invocationId = value.trim().toLowerCase();
  if (!SYSTEMD_INVOCATION_ID.test(invocationId)) {
    throw new Error("The stable Ti-Scale service wrapper requires a systemd invocation identity");
  }
  return invocationId;
}

function responseBytes(value: Readonly<Record<string, unknown>>): Buffer {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function sendJson(
  response: import("node:http").ServerResponse,
  statusCode: number,
  value: Readonly<Record<string, unknown>>,
  headOnly = false,
): void {
  const bytes = responseBytes(value);
  response.statusCode = statusCode;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", String(bytes.byteLength));
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Connection", "close");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.end(headOnly ? undefined : bytes);
}

function guardedPayload(invocationId: string): Readonly<Record<string, unknown>> {
  return Object.freeze({
    schemaVersion: RELEASE_GUARDED_HEALTH_PROTOCOL,
    status: "journal_guarded",
    mode: "release_startup_mutation_fence",
    mutationFenced: true,
    invocationId,
  });
}

function fencedPayload(): Readonly<Record<string, unknown>> {
  return Object.freeze({
    schemaVersion: RELEASE_GUARDED_HEALTH_PROTOCOL,
    status: "release_startup_fenced",
    code: "RELEASE_STARTUP_MUTATION_FENCED",
    humanMessage: "Ti-Scale is completing a durable release recovery. Operational requests are temporarily fenced.",
    retryable: true,
  });
}

export async function createReleaseGuardedServer(
  invocationIdValue: string,
  host = "127.0.0.1",
  portValue = RELEASE_SERVICE_WRAPPER_DEFAULT_PORT,
): Promise<ReleaseGuardedServer> {
  const invocationId = exactInvocationId(invocationIdValue);
  if (host !== "127.0.0.1") {
    throw new Error("The release-guarded listener may bind only to 127.0.0.1");
  }
  const port = exactPort(portValue);
  const server: Server = createServer((request, response) => {
    const method = request.method ?? "";
    const exactHealthRequest = (method === "GET" || method === "HEAD") &&
      typeof request.url === "string" && GUARDED_PATHS.has(request.url);
    request.resume();
    if (exactHealthRequest) {
      sendJson(response, 200, guardedPayload(invocationId), method === "HEAD");
      return;
    }
    sendJson(response, 503, fencedPayload(), method === "HEAD");
  });
  server.headersTimeout = 2_000;
  server.requestTimeout = 2_000;
  server.keepAliveTimeout = 1;
  server.maxHeadersCount = 64;
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => reject(error);
    server.once("error", onError);
    server.listen(port, host, () => {
      server.off("error", onError);
      resolve();
    });
  });
  let closed = false;
  return Object.freeze({
    port,
    close: async () => {
      if (closed) return;
      closed = true;
      const completed = new Promise<void>((resolve, reject) => {
        try { server.close(() => resolve()); }
        catch (error) { reject(error); }
      });
      server.closeIdleConnections?.();
      server.closeAllConnections?.();
      await completed;
    },
  });
}

export function releaseServiceWrapperSelfReport(): Readonly<Record<string, string>> {
  return Object.freeze({
    schemaVersion: RELEASE_SERVICE_WRAPPER_PROTOCOL,
    guardedHealthSchema: RELEASE_GUARDED_HEALTH_PROTOCOL,
    applicationEntrypoint: RELEASE_SERVICE_WRAPPER_APPLICATION_ENTRYPOINT,
    applicationExecMode: "atomic_direct_entrypoint",
  });
}

export function releaseServiceApplicationExecSpec(options: {
  readonly applicationPath?: string;
  readonly bunPath?: string;
  readonly environment?: NodeJS.ProcessEnv;
} = {}): ReleaseServiceApplicationExecSpec {
  const applicationPathValue = options.applicationPath ?? RELEASE_SERVICE_WRAPPER_APPLICATION_PATH;
  const bunPathValue = options.bunPath ?? RELEASE_SERVICE_WRAPPER_BUN_PATH;
  if (!isAbsolute(applicationPathValue) || !isAbsolute(bunPathValue)) {
    throw new Error("Ti-Scale service execution paths must be absolute");
  }
  const applicationPath = resolve(applicationPathValue);
  const bunPath = resolve(bunPathValue);
  const source = options.environment ?? process.env;
  const environment: Record<string, string> = {};
  for (const [name, value] of Object.entries(source)) {
    if (typeof value === "string") environment[name] = value;
  }
  environment.TI_SCALE_PORT = String(exactPort(
    source.TI_SCALE_PORT?.trim() || RELEASE_SERVICE_WRAPPER_DEFAULT_PORT,
  ));
  // The former package script set this unconditionally. Preserve that
  // production contract while removing the package-script parent process.
  environment.TI_SCALE_SERVE_STATIC = "true";
  const entrypoint = join(applicationPath, "server/index.ts");
  return Object.freeze({
    executable: bunPath,
    argv: Object.freeze([bunPath, entrypoint]),
    cwd: applicationPath,
    environment: Object.freeze(environment),
  });
}

function execTiScaleApplication(options: {
  readonly applicationPath?: string;
  readonly bunPath?: string;
} = {}): never {
  const specification = releaseServiceApplicationExecSpec(options);
  process.chdir(specification.cwd);
  const execve = process.execve;
  if (typeof execve !== "function") {
    throw new Error("The installed Bun runtime does not support atomic process replacement");
  }
  execve(
    specification.executable,
    [...specification.argv],
    { ...specification.environment },
  );
  throw new Error("Ti-Scale application exec unexpectedly returned");
}

/**
 * A stable, root-installed systemd entrypoint. It never loads code from the
 * swappable application tree while a nonterminal release owns the startup
 * fence. After the root reconciler durably commits the exact source runtime
 * (or reaches an appropriate terminal boundary) and removes that fence, the
 * wrapper closes every guarded connection and execs the real app.
 */
export async function runReleaseServiceWrapper(
  options: ReleaseServiceWrapperOptions,
): Promise<never> {
  const invocationId = exactInvocationId(options.invocationId);
  const host = options.host ?? "127.0.0.1";
  const port = exactPort(options.port ?? RELEASE_SERVICE_WRAPPER_DEFAULT_PORT);
  const pollIntervalMs = options.pollIntervalMs ?? 100;
  if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 10 || pollIntervalMs > 5_000) {
    throw new Error("Release service wrapper poll interval is outside its safe bounds");
  }
  const barrierExists = options.barrierExists ?? (() =>
    releaseStartupMutationBarrierExists(RELEASE_STARTUP_MUTATION_BARRIER_PATH));
  const createGuardedServer = options.createGuardedServer ?? createReleaseGuardedServer;
  const sleep = options.sleep ?? Bun.sleep;
  const execApplication = options.execApplication ?? (() => execTiScaleApplication({
    applicationPath: options.applicationPath,
    bunPath: options.bunPath,
  }));

  if (!barrierExists()) return execApplication();
  const guarded = await createGuardedServer(invocationId, host, port);
  try {
    while (barrierExists()) await sleep(pollIntervalMs);
  } catch (error) {
    await guarded.close();
    throw error;
  }
  await guarded.close();
  return execApplication();
}

if (import.meta.main) {
  if (process.argv.length === 3 && process.argv[2] === "--self-report") {
    process.stdout.write(`${JSON.stringify(releaseServiceWrapperSelfReport())}\n`);
  } else if (process.argv.length !== 2) {
    throw new Error("The stable Ti-Scale service wrapper accepts only --self-report");
  } else {
    assertReleaseServiceStartAdmissionInstallationCommitted();
    await runReleaseServiceWrapper({
      invocationId: process.env.INVOCATION_ID ?? "",
      host: process.env.TI_SCALE_HOST ?? "127.0.0.1",
      port: exactPort(process.env.TI_SCALE_PORT ?? RELEASE_SERVICE_WRAPPER_DEFAULT_PORT),
    });
  }
}

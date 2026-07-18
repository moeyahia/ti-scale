import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { basename, isAbsolute, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import {
  createLocalSessionRouter,
  authenticateRequest,
  LocalSessionAuth,
  parseCookieHeader,
  V2_CSRF_HEADER,
  V2_SESSION_COOKIE,
} from "./auth";
import { resolveOperatorToken } from "./auth/OperatorTokenConfiguration";
import {
  createCommandOsApplication,
  createRuntimeReadinessProviders,
  resolveV2ScriptSourceRoot,
  type RuntimeReadinessSnapshot,
} from "./app";
import {
  attachV2RequestId,
  sendV2Error,
  v2JsonBodyError,
  v2NotFound,
  v2RequestContext,
} from "./contracts";
import { createSecondBrainRouter } from "./memory/SecondBrainRouter";
import type { ReadinessCheckProvider } from "./missions";
import { createNotificationRouter } from "./notifications";
import {
  createOperationsRouter,
  type OperationsAccessPolicy,
  type OperationsActor,
} from "./operations";
import { VaultPathPolicy } from "./vault";
import { FileScriptSourceStore } from "./script-artifacts";
import { SPA_DOCUMENT_ROUTE, V2_API_TREE_ROUTE } from "./http/expressRoutePatterns";
import { createUnavailableExecutionRouter } from "./routes/UnavailableExecutionRouter";
import { createMissionRunControlV2Router } from "./routes/missionRuntimeV2Routes";
import {
  CommandRuntimeError,
  createMissionRuntime,
  type MissionRuntimeEngine,
  type ResultAwareExecutionPort,
} from "./command-runtime";
import { assertTestRunMutationAuthority } from "./control-plane/TestRunMutationAuthority";
import { StaticArtifactReleaseStore } from "./static-release";

const API_VERSION = "2.4" as const;
const DEFAULT_BIND = "127.0.0.1";
const DEFAULT_PORT = 3_132;
const DEFAULT_DATABASE_PATH = "./data/ti-scale.sqlite";
const DEFAULT_UI_ORIGIN = "http://127.0.0.1:3132";
const MAX_JSON_BODY = "1mb";
const OPERATOR_ID = /^[A-Za-z0-9._:@/-]{1,128}$/u;

function enabled(name: string, fallback = false): boolean {
  const value = process.env[name];
  if (value === undefined) return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be true or false`);
}

function port(): number {
  const value = process.env.TI_SCALE_PORT ?? String(DEFAULT_PORT);
  if (!/^\d+$/u.test(value)) throw new Error("TI_SCALE_PORT must be an integer");
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 1_024 || result > 65_535) {
    throw new Error("TI_SCALE_PORT must be between 1024 and 65535");
  }
  return result;
}

function projectionIntervalMs(): number | undefined {
  const value = process.env.TI_SCALE_PROJECTION_INTERVAL_MS?.trim();
  if (!value) return undefined;
  if (!/^\d+$/u.test(value)) {
    throw new Error("TI_SCALE_PROJECTION_INTERVAL_MS must be an integer");
  }
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 1_000 || result > 300_000) {
    throw new Error("TI_SCALE_PROJECTION_INTERVAL_MS must be between 1000 and 300000");
  }
  return result;
}

function databasePath(): string {
  const configured = process.env.TI_SCALE_DATABASE_PATH?.trim()
    || DEFAULT_DATABASE_PATH;
  if (configured === ":memory:" || configured.startsWith("file::memory:")) {
    throw new Error("The Ti-Scale server requires a durable database file");
  }
  const result = resolve(configured);
  const lower = result.toLocaleLowerCase("en-US");
  const segments = lower.split(sep);
  const file = basename(lower);
  if (
    segments.includes("external-import")
    || ["kanban.sqlite", "missions.sqlite", "sessions.sqlite"].includes(file)
  ) {
    throw new Error("TI_SCALE_DATABASE_PATH must not reference an external import source");
  }
  return result;
}

function testRunControlRuntimeEnabled(canonicalDatabasePath: string): boolean {
  if (!enabled("TI_SCALE_TEST_RUN_CONTROL_RUNTIME")) return false;
  const runId = process.env.TI_SCALE_E2E_RUN_ID?.trim();
  const testRoot = resolve("/tmp/ti-scale-e2e-data");
  if (!runId || (!canonicalDatabasePath.startsWith(`${testRoot}${sep}`) && canonicalDatabasePath !== testRoot)) {
    throw new Error(
      "TI_SCALE_TEST_RUN_CONTROL_RUNTIME is test-only and requires an isolated Playwright database",
    );
  }
  return true;
}

function testRunControlSchedulerEnabled(runtimeEnabled: boolean): boolean {
  const schedulerEnabled = enabled("TI_SCALE_TEST_RUN_CONTROL_SCHEDULER");
  if (schedulerEnabled && !runtimeEnabled) {
    throw new Error(
      "TI_SCALE_TEST_RUN_CONTROL_SCHEDULER requires TI_SCALE_TEST_RUN_CONTROL_RUNTIME=true",
    );
  }
  return schedulerEnabled;
}

function createTestRunControlRuntime(
  database: Parameters<typeof createMissionRuntime>[0]["database"],
): MissionRuntimeEngine {
  const unavailable = () => new CommandRuntimeError(
    503,
    "test_run_control_execution_unavailable",
    "The test-only run-control boundary cannot plan or execute work",
    {
      humanMessage: "This isolated test boundary can only pause, resume an existing Guided decision, or cancel disposable fixture work.",
      category: "dependency_missing",
    },
  );
  const execution: ResultAwareExecutionPort = {
    async dispatch() { throw unavailable(); },
    async resume() { throw unavailable(); },
    // Playwright fixtures have no operating-system child process. Resolving
    // here attests that there is nothing outside canonical fixture state to
    // terminate; DurableRunCoordinator still closes every durable child.
    async cancelRun() {},
  };
  return createMissionRuntime({
    database,
    planner: { async plan() { throw unavailable(); } },
    outcomeEvaluator: { async evaluate() { throw unavailable(); } },
    execution,
    workerId: `ti-scale-e2e-run-control-${process.pid}`,
  });
}

function publicApiPath(path: string): boolean {
  return path === "/api/v2/health"
    || path === "/api/v2/system/readiness"
    || path === "/api/v2/openapi.json"
    || path === "/api/v2/contracts/events"
    || path === "/api/v2/auth/session";
}

function isSafeMethod(method: string): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

function securityHeaders(_request: Request, response: Response, next: NextFunction): void {
  response.setHeader("Content-Security-Policy", [
    "default-src 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "object-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self' http://127.0.0.1:43141",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
  ].join("; "));
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-site");
  response.setHeader("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  next();
}

function cors(allowedOrigin: string) {
  return (request: Request, response: Response, next: NextFunction): void => {
    const origin = request.get("Origin");
    if (origin === allowedOrigin) {
      response.setHeader("Access-Control-Allow-Origin", allowedOrigin);
      response.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
      response.setHeader(
        "Access-Control-Allow-Headers",
        "Authorization,Content-Type,Idempotency-Key,Last-Event-ID,X-Ti-Scale-CSRF,X-Request-ID",
      );
      response.setHeader(
        "Access-Control-Expose-Headers",
        "X-Request-ID,Content-Disposition,Idempotency-Replayed",
      );
      response.setHeader("Vary", "Origin");
    }
    if (request.method === "OPTIONS") {
      response.status(origin === allowedOrigin ? 204 : 403).end();
      return;
    }
    next();
  };
}

function unavailableRuntime(): RuntimeReadinessSnapshot {
  return {
    actionBoundaryActive: false,
    delegationEnforced: false,
    noHandsCommanderEnforced: false,
    directCommanderToolsDenied: true,
    specialistAssignmentRequired: true,
    specialistsConfigured: 0,
    providers: [],
    mcp: {
      enabled: false,
      executionMode: "disabled",
      startPermitted: false,
      configuredServers: 0,
      runnableServers: 0,
      missingDependencies: 0,
      missingSecrets: 0,
    },
    eventStream: "healthy",
    secondBrain: "unknown",
    legacyExecutionEnabled: false,
  };
}

function authenticationReadiness(configured: boolean): ReadinessCheckProvider {
  return {
    id: "local_operator_authentication",
    label: "Local operator authentication",
    journeys: ["autonomous", "guided"],
    evaluate: () => configured
      ? {
          id: "local_operator_authentication",
          label: "Local operator authentication",
          status: "pass",
          journeys: ["autonomous", "guided"],
          impact: "The Ti-Scale API has a configured local operator token.",
        }
      : {
          id: "local_operator_authentication",
          label: "Local operator authentication",
          status: "fail",
          journeys: ["autonomous", "guided"],
          impact: "Operational routes are unavailable because no local operator token is configured.",
          remediation: "Set TI_SCALE_OPERATOR_TOKEN to a private value of at least 24 bytes and restart Ti-Scale.",
        },
  };
}

function authenticatedActor(): OperationsActor {
  return { id: process.env.TI_SCALE_OPERATOR_ID || "local-operator", type: "operator" };
}

function fullLocalAccess(): OperationsAccessPolicy {
  return {
    maximumSensitivity: "restricted",
    allEngagements: true,
    allowUnscopedSystemData: true,
    allowGlobalKnowledge: true,
    canReviewFindings: true,
    canOverrideEvidenceGate: false,
    canReviewLessons: true,
    // The standalone identity is an operator, not an independent reviewer.
    // Keep administrative records visible but fail closed until a host maps a
    // distinct reviewer/admin identity and grants this capability.
    canReviewAdministrativeApprovals: false,
    canManageRecovery: true,
    canDownloadArtifactContent: true,
    canExportEvidenceBundles: true,
    canExportAuditRecords: true,
  };
}

function killSwitchServer(bind: string, listenPort: number): void {
  const app = express();
  app.disable("x-powered-by");
  app.use(securityHeaders);
  app.all(V2_API_TREE_ROUTE, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    sendV2Error(response, traceId, {
      status: 503,
      code: "ti_scale_killed",
      message: "Ti-Scale is disabled by its kill switch",
      humanMessage: "Ti-Scale is deliberately disabled by its administrative kill switch.",
      retryable: false,
      category: "service_disabled",
      remediation: "An administrator must clear TI_SCALE_KILL_SWITCH and restart Ti-Scale.",
    });
  });
  const server = createServer(app);
  server.listen(listenPort, bind, () => {
    process.stdout.write(`Ti-Scale kill switch active on http://${bind}:${listenPort}\n`);
  });
  const stop = () => server.close(() => process.exit(0));
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

async function main(): Promise<void> {
  const bind = process.env.TI_SCALE_HOST?.trim() || DEFAULT_BIND;
  const listenPort = port();
  if (enabled("TI_SCALE_KILL_SWITCH")) {
    killSwitchServer(bind, listenPort);
    return;
  }

  const token = resolveOperatorToken();
  const actorId = process.env.TI_SCALE_OPERATOR_ID?.trim() || "local-operator";
  if (!OPERATOR_ID.test(actorId)) throw new Error("TI_SCALE_OPERATOR_ID is invalid");
  const sessionAuth = token ? new LocalSessionAuth({ operatorToken: token, actorId }) : undefined;
  const runtime = unavailableRuntime();
  const canonicalDatabasePath = databasePath();
  const scriptSourceStore = new FileScriptSourceStore(resolveV2ScriptSourceRoot(
    canonicalDatabasePath,
    process.env.TI_SCALE_SCRIPT_SOURCE_ROOT,
  ));
  const testRunControlEnabled = testRunControlRuntimeEnabled(canonicalDatabasePath);
  const testRunControlScheduler = testRunControlSchedulerEnabled(testRunControlEnabled);
  let testAuthorityDatabase: Parameters<typeof assertTestRunMutationAuthority>[0] | undefined;
  const application = createCommandOsApplication({
    databasePath: canonicalDatabasePath,
    readinessProviders: () => [
      ...createRuntimeReadinessProviders(() => runtime),
      authenticationReadiness(Boolean(token)),
    ],
    runtimeProjection: () => ({ readiness: runtime, agents: [], mcpServers: [] }),
    projectionIntervalMs: projectionIntervalMs(),
    resolveActor: () => actorId,
    resolveEventSensitivity: () => "restricted",
    resolvePageCaptureActor: () => ({ id: actorId, type: "operator" }),
    authorizePageCaptures: (_request, actor) => actor.type === "operator" && actor.id === actorId,
    scriptSourceStore,
    resolveScriptArtifactActor: () => ({ id: actorId, type: "operator" }),
    authorizeScriptArtifacts: (_request, actor) => actor.type === "operator" && actor.id === actorId,
    ...(testRunControlEnabled ? {
      assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
        if (!testAuthorityDatabase) return undefined;
        return assertTestRunMutationAuthority(testAuthorityDatabase, runId);
      },
    } : {}),
  });
  testAuthorityDatabase = application.database;
  const testRunControlRuntime = testRunControlEnabled
    ? createTestRunControlRuntime(application.database)
    : undefined;

  const web = express();
  web.disable("x-powered-by");
  web.set("trust proxy", false);
  web.use(securityHeaders);
  web.use(cors(process.env.TI_SCALE_UI_ORIGIN?.trim() || DEFAULT_UI_ORIGIN));
  web.use(v2RequestContext);
  web.use(express.json({ limit: MAX_JSON_BODY, strict: true, type: "application/json" }));
  web.use(v2JsonBodyError);
  web.use("/api/v2/auth/session", (request, response, next) => {
    if (request.method !== "DELETE" || !sessionAuth) {
      next();
      return;
    }
    const cookies = parseCookieHeader(request.get("Cookie"));
    const session = cookies[V2_SESSION_COOKIE];
    const authorization = request.get("Authorization");
    if (!session && !authorization) {
      next();
      return;
    }
    const authentication = authenticateRequest({
      auth: sessionAuth,
      authorization,
      cookie: request.get("Cookie"),
      csrfHeader: request.get(V2_CSRF_HEADER),
      unsafeMethod: true,
    });
    if (authentication.authenticated) {
      next();
      return;
    }
    const traceId = attachV2RequestId(request, response);
    sendV2Error(response, traceId, {
      status: 403,
      code: "ti_scale_csrf_invalid",
      message: "The local session CSRF proof is missing or invalid",
      humanMessage: "The sign-out request could not be verified as coming from this Ti-Scale session.",
      retryable: false,
      category: "policy_denied",
      remediation: "Refresh Ti-Scale, then sign out again.",
    });
  });
  web.use(createLocalSessionRouter({
    auth: sessionAuth,
    secureCookies: enabled(
      "TI_SCALE_SECURE_COOKIES",
      !["127.0.0.1", "::1", "localhost"].includes(bind),
    ),
  }));
  web.use("/api/v2", (request, response, next) => {
    if (publicApiPath(request.originalUrl.split("?", 1)[0] ?? request.path)) {
      next();
      return;
    }
    const traceId = attachV2RequestId(request, response);
    if (!token) {
      sendV2Error(response, traceId, {
        status: 503,
        code: "ti_scale_authentication_unconfigured",
        message: "Ti-Scale operator authentication is not configured",
        humanMessage: "Operational Ti-Scale routes are unavailable until local authentication is configured.",
        retryable: false,
        category: "authentication_missing",
        remediation: "Set TI_SCALE_OPERATOR_TOKEN to a private value of at least 24 bytes and restart Ti-Scale.",
      });
      return;
    }
    const authorization = request.get("Authorization") ?? "";
    const authentication = authenticateRequest({
      auth: sessionAuth!,
      ...(authorization ? { authorization } : {}),
      cookie: request.get("Cookie"),
      csrfHeader: request.get(V2_CSRF_HEADER),
      unsafeMethod: !isSafeMethod(request.method),
    });
    if (!authentication.authenticated) {
      const csrfFailure = authentication.failure === "csrf_missing"
        || authentication.failure === "csrf_invalid";
      response.setHeader("WWW-Authenticate", "Bearer realm=\"ti-scale\"");
      sendV2Error(response, traceId, {
        status: csrfFailure ? 403 : 401,
        code: csrfFailure
          ? "ti_scale_csrf_invalid"
          : "ti_scale_authentication_required",
        message: csrfFailure
          ? "The local session CSRF proof is missing or invalid"
          : "A valid Ti-Scale bearer token or signed local session is required",
        humanMessage: csrfFailure
          ? "This change could not be verified as coming from your current Ti-Scale session."
          : "Sign in to Ti-Scale.",
        retryable: false,
        category: csrfFailure ? "policy_denied" : "authentication_missing",
        ...(csrfFailure
          ? { remediation: "Refresh Ti-Scale and retry the change." }
          : {}),
      });
      return;
    }
    next();
  });

  const vaultRoot = process.env.TI_SCALE_VAULT_ROOT?.trim();
  if (vaultRoot && !isAbsolute(vaultRoot)) {
    throw new Error("TI_SCALE_VAULT_ROOT must be an absolute path");
  }
  const vaultPathPolicy = vaultRoot ? new VaultPathPolicy(vaultRoot) : undefined;
  const resolveActor = () => authenticatedActor();
  const resolveAccess = () => fullLocalAccess();

  web.use(application.router);
  if (testRunControlRuntime) {
    web.use(createMissionRunControlV2Router({
      runtime: testRunControlRuntime,
      resolveActor: () => actorId,
    }));
  }
  web.use(createOperationsRouter({
    database: application.database,
    resolveActor,
    resolveAccess,
    providerRouteIds: [],
    ...(vaultPathPolicy ? { vaultPathPolicy } : {}),
    ...(testRunControlEnabled ? {
      assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
        if (!testAuthorityDatabase) return undefined;
        return assertTestRunMutationAuthority(testAuthorityDatabase, runId);
      },
      notifyRecoveryContinuation: ({ runId }: { readonly runId: string }) => {
        testRunControlRuntime?.notifyContinuationAvailable(runId, ["resume_recovery_pending"]);
      },
    } : {}),
  }));
  web.use(createNotificationRouter({
    database: application.database,
    resolveActor,
    resolveAccess,
  }));
  web.use(createSecondBrainRouter({
    database: application.database,
    resolveActor: () => actorId,
    resolveAccess: () => ({
      maximumSensitivity: "restricted",
      allowGlobal: true,
      allEngagements: true,
    }),
    ...(vaultRoot ? { vaultAllowedRoot: vaultRoot } : {}),
  }));
  // This standalone preview deliberately has no provider/MCP executor. Keep
  // documented mutation routes explicit and diagnosable instead of allowing
  // them to fall through as generated 404s.
  web.use(createUnavailableExecutionRouter());
  web.use(v2NotFound);

  const serveStatic = enabled("TI_SCALE_SERVE_STATIC");
  const previewEnabled = enabled("TI_SCALE_PREVIEW", true);
  const mutableDevelopmentDist = fileURLToPath(new URL("../dist/", import.meta.url));
  const staticReleaseRoot = process.env.TI_SCALE_STATIC_RELEASE_ROOT?.trim();
  if (staticReleaseRoot && !isAbsolute(staticReleaseRoot)) {
    throw new Error("TI_SCALE_STATIC_RELEASE_ROOT must be an absolute Ti-Scale path");
  }
  // A configured preview/release pins one verified immutable directory exactly
  // once at process startup. Pointer changes cannot alter files served by an
  // already-running process. Local development and Playwright may continue to
  // use the mutable build output when no release root is configured.
  const pinnedStaticRelease = serveStatic && staticReleaseRoot
    ? new StaticArtifactReleaseStore({ releaseRoot: staticReleaseRoot }).pinActiveRelease()
    : undefined;
  const dist = pinnedStaticRelease?.releaseDirectory ?? mutableDevelopmentDist;
  if (pinnedStaticRelease) {
    process.stdout.write(
      `Ti-Scale pinned static release ${pinnedStaticRelease.releaseId} `
      + `(${pinnedStaticRelease.manifestSha256})\n`,
    );
  }
  if (serveStatic && previewEnabled && existsSync(resolve(dist, "index.html"))) {
    web.use(express.static(dist, {
      fallthrough: true,
      index: false,
      immutable: false,
      setHeaders(response, filePath) {
        response.setHeader("Cache-Control", filePath.endsWith("index.html")
          ? "no-store"
          : "public, max-age=3600, must-revalidate");
      },
    }));
    web.get(SPA_DOCUMENT_ROUTE, (request, response, next) => {
      if (request.method !== "GET" || request.path.startsWith("/api/")) {
        next();
        return;
      }
      response.setHeader("Cache-Control", "no-store");
      response.sendFile(resolve(dist, "index.html"));
    });
  }

  web.use((error: unknown, request: Request, response: Response, _next: NextFunction) => {
    if (response.headersSent) return;
    const traceId = attachV2RequestId(request, response);
    sendV2Error(response, traceId, {
      status: 500,
      code: "ti_scale_internal_error",
      message: "Ti-Scale request failed",
      humanMessage: "Ti-Scale could not complete the request.",
      retryable: false,
      category: "internal",
      remediation: "Use the request ID to inspect redacted Ti-Scale logs before retrying.",
    });
    if (error instanceof Error) {
      process.stderr.write(`Ti-Scale request error [${traceId}]: ${error.name}\n`);
    }
  });

  const server = createServer(web);
  server.requestTimeout = 120_000;
  server.headersTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 100;
  application.start();
  // Most browser fixtures need only the fail-closed pause/resume/cancel HTTP
  // adapter. Running its deliberately unavailable planner would claim normal
  // intake and portfolio fixture runs, then rewrite them to `blocked`. The
  // scheduler is therefore a separate test-only opt-in used by the process-
  // boundary recovery fixture, where the real startup recovery pass is the
  // behavior under test. Both switches remain unreachable for normal preview
  // databases because testRunControlRuntimeEnabled() requires the isolated
  // /tmp Playwright data root and an explicit fixture run ID.
  if (testRunControlScheduler) await testRunControlRuntime?.start();

  let stopping = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    process.stdout.write(`Ti-Scale received ${signal}; draining isolated resources\n`);
    const timeout = setTimeout(() => {
      process.stderr.write("Ti-Scale graceful shutdown timed out\n");
      process.exitCode = 1;
      server.closeAllConnections?.();
    }, 10_000);
    timeout.unref();
    try {
      await testRunControlRuntime?.stop();
      await application.stop();
      await new Promise<void>((resolveClose, rejectClose) => {
        server.close((error) => error ? rejectClose(error) : resolveClose());
        server.closeIdleConnections?.();
      });
    } finally {
      clearTimeout(timeout);
    }
  };
  process.once("SIGINT", () => void shutdown("SIGINT"));
  process.once("SIGTERM", () => void shutdown("SIGTERM"));

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(listenPort, bind, () => {
      server.off("error", rejectListen);
      process.stdout.write(
        `Ti-Scale API ${API_VERSION} listening on http://${bind}:${listenPort} (provider and MCP execution adapters unavailable)\n`,
      );
      resolveListen();
    });
  });
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown startup failure";
  process.stderr.write(`Ti-Scale failed to start: ${message}\n`);
  process.exitCode = 1;
});

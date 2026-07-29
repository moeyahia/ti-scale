import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";
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
  createAutonomousProviderAdvisoryComposition,
  loadProductionRuntimeManifest,
  projectOpenRouterRuntime,
  projectConfiguredRuntimeManifest,
  projectPublicNvdMcpRuntime,
  createRuntimeReadinessProviders,
  inspectAutonomousRuntimeComposition,
  applyLocalGuidedToolRuntimeProjection,
  loadProductionLocalGuidedToolConfiguration,
  loadProductionAutonomousDnsConfiguration,
  AutonomousDnsRuntimeLifecycle,
  createProductionObsidianVaultWatcher,
  GracefulShutdownCoordinator,
  LocalGuidedToolActivationCoordinator,
  projectLocalGuidedToolRuntime,
  resolveV2ScriptSourceRoot,
  type RuntimeProjectionInput,
  type RuntimeReadinessSnapshot,
  type GracefulShutdownComponent,
  type GracefulShutdownFinalizer,
  activateWindowsIdentityRuntime,
  applyWindowsIdentityRuntimeProjection,
  drainWindowsIdentityReadinessResources,
  projectWindowsIdentityRuntime,
  activateLocalExploitIntelligenceRuntime,
  applyLocalExploitIntelligenceRuntimeProjection,
  drainLocalExploitIntelligenceReadinessResources,
  projectLocalExploitIntelligenceRuntime,
  StartupDatabaseIntegrityVerifier,
} from "./app";
import { createProductionPublicNvdMcpBoundary } from "./mcp";
import {
  MissionScopedNvdCandidateEnrichmentPort,
  MissionScopedNvdDetailAdapter,
} from "./cve-intelligence";
import {
  ExperimentRunner,
  IntegrityAuthority,
  loadProductionPrivateResearchHoldoutConfiguration,
  loadProductionResearchReadinessProbeConfiguration,
  ResearchExecutionBoundary,
  resolveResearchIntegrityKey,
} from "./research";
import {
  attachV2RequestId,
  sendV2Error,
  v2JsonBodyError,
  v2NotFound,
  v2RequestContext,
} from "./contracts";
import { createSecondBrainRouter } from "./memory/SecondBrainRouter";
import {
  createOperationalHazardObservationRouter,
  OperationalHazardObservationWorker,
  resolveOperationalHazardObservationKey,
} from "./memory";
import { createAttackKnowledgePromotionRouter } from "./migration";
import { createDatabaseConnection, type IntegrityResult } from "./db";
import { CanonicalDatabaseLeaseService } from "./maintenance";
import {
  createGuidedCommanderRouter,
  createLocalDeterministicGuidedCommanderPort,
  createLocalGuidedManualInterpreterRouter,
  createOpenRouterGuidedCommanderPort,
} from "./guided-commander";
import {
  AgentRuntimeBindingService,
  createGuidedAgentRuntimeResolver,
} from "./agent-runtime";
import type { ReadinessCheckProvider } from "./missions";
import { hashCanonical } from "./missions/canonical";
import { createNotificationRouter } from "./notifications";
import {
  createOperationsRouter,
  type OperationsAccessPolicy,
  type OperationsActor,
} from "./operations";
import {
  ConnectedVaultMemoryProjector,
  ObsidianVaultBridge,
  VaultPathPolicy,
} from "./vault";
import { RuntimeCapabilityMemoryProjector } from "./agent-tool-memory";
import { FileScriptSourceStore } from "./script-artifacts";
import { AutonomousRecoveryPolicyProjector } from "./recovery-memory";
import {
  CandidateSpecificIndependentExploitOutcomeVerifier,
  ConnectedVaultExploitSyncAdapter,
} from "./autonomous-runtime";
import { SPA_DOCUMENT_ROUTE, V2_API_TREE_ROUTE } from "./http/expressRoutePatterns";
import { ServiceDrainAdmission } from "./http/ServiceDrainAdmission";
import { createStaticApplicationCompression } from "./http/StaticApplicationCompression";
import { createUnavailableExecutionRouter } from "./routes/UnavailableExecutionRouter";
import { createModelCandidateReviewRouter } from "./model-review";
import {
  createMissionRunControlV2Router,
  createMissionRuntimeV2Router,
} from "./routes/missionRuntimeV2Routes";
import {
  CommandRuntimeError,
  createProductionGuidedLocalToolRuntime,
  createProductionGuidedCompositeRuntime,
  createProductionGuidedManualRuntime,
  createMissionRuntime,
  localGuidedManualAgentProjection,
  type MissionRuntimeEngine,
  type ResultAwareExecutionPort,
  CompositeGuidedExecutionPort,
  FailClosedManualExecutionPort,
  LocalExploitIntelligenceGuidedPlanner,
  LocalGuidedToolPlanner,
  LocalGuidedManualPlanner,
  WindowsIdentityGuidedPlanner,
  createProductionGuidedLocalExploitIntelligenceRuntime,
} from "./command-runtime";
import { assertTestRunMutationAuthority } from "./control-plane/TestRunMutationAuthority";
import {
  resolveManagedE2EStaticBuild,
  StaticArtifactReleaseStore,
} from "./static-release";
import {
  applicationConnectSourceDirective,
  applicationStyleSourceDirective,
} from "./security/ContentSecurityPolicy";
import {
  createOpenRouterPlanningClient,
  createOpenRouterProviderRequestAuditor,
  createOpenRouterDurableReadinessVerifier,
  createProductionOpenRouterReadinessRuntime,
  captureOpenRouterCredential,
  createOpenRouterConnectionRouter,
  OpenRouterConnectionService,
  loadOpenRouterConnectionConfiguration,
  OpenRouterPlanningError,
  type OpenRouterCompletionVerifier,
} from "./providers/openrouter";
import { emptyRuntimeSourceManifests } from "./domain";
import {
  DirectProcessLocalToolInvocationAdapter,
  BubblewrapToolProbeEnvironment,
  OperationalTruthLocalToolOutputRecorder,
  ReviewedLocalToolExecutionPort,
} from "./local-tools";
import {
  createProductionToolBindingReadiness,
  EngagementWorkspaceResolver,
  ToolBindingReadinessRunner,
  ToolExecutionPreflightService,
} from "./system-capabilities";
import {
  DirectWindowsIdentityProcessAdapter,
  SystemdWindowsIdentityCredentialResolver,
  WindowsIdentityCapabilityRegistry,
  WindowsIdentityGuidedExecutionPort,
} from "./windows-identity-tools";
import {
  DirectSearchSploitProcessAdapter,
  SearchSploitActivationService,
  SearchSploitGuidedExecutionPort,
  SearchSploitToolPack,
} from "./local-exploit-intelligence";
import type { PlanChangeAffectedWorkStopReceipt } from "./plan-changes";
import { ProcessWriterLeaseHeartbeat } from "./app/ProcessWriterLeaseHeartbeat";

const API_VERSION = "2.4" as const;
const DEFAULT_BIND = "127.0.0.1";
const DEFAULT_PORT = 3_132;
const DEFAULT_DATABASE_PATH = "./data/ti-scale.sqlite";
const DEFAULT_UI_ORIGIN = "http://127.0.0.1:3132";
const MAX_JSON_BODY = "1mb";
const GRACEFUL_SHUTDOWN_DEADLINE_MS = 24_000;
const HTTP_FORCE_DRAIN_AFTER_MS = 12_000;
const PROCESS_WRITER_LEASE_TTL_MS = 60 * 60_000;
const PROCESS_WRITER_LEASE_HEARTBEAT_MS = 5 * 60_000;
const PROCESS_WRITER_LEASE_BUSY_TIMEOUT_MS = 25;
const OPERATOR_ID = /^[A-Za-z0-9._:@/-]{1,128}$/u;

let fatalMainFailureShutdown: (() => void) | undefined;

function enabled(name: string, fallback = false): boolean {
  const value = process.env[name];
  if (value === undefined) return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be true or false`);
}

function writeShutdownSummaryAndExit(
  stream: NodeJS.WriteStream,
  summary: string,
  exitCode: number,
): void {
  let exited = false;
  const exit = (): void => {
    if (exited) return;
    exited = true;
    process.exit(exitCode);
  };
  // Keep this timer referenced intentionally: it is the final bound when a
  // journal/pipe callback never drains. Clear it on the normal callback so it
  // cannot leave a duplicate pending handle during tests or supervised exit.
  const fallback = setTimeout(exit, 500);
  stream.write(summary, () => {
    clearTimeout(fallback);
    exit();
  });
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

function startupShutdownTestHoldMs(canonicalDatabasePath: string): number | undefined {
  const raw = process.env.TI_SCALE_TEST_STARTUP_HOLD_AFTER_LEASE_MS?.trim();
  if (!raw) return undefined;
  const testRoot = resolve(tmpdir());
  const relativeDatabase = relative(testRoot, canonicalDatabasePath);
  const firstSegment = relativeDatabase.split(sep)[0] ?? "";
  if (process.env.NODE_ENV !== "test"
    || process.env.TI_SCALE_PREVIEW !== "true"
    || process.env.TI_SCALE_SERVE_STATIC !== "false"
    || relativeDatabase === ""
    || relativeDatabase === ".."
    || relativeDatabase.startsWith(`..${sep}`)
    || !firstSegment.startsWith("ti-scale-startup-shutdown-")) {
    throw new Error(
      "TI_SCALE_TEST_STARTUP_HOLD_AFTER_LEASE_MS is test-only and requires an isolated temporary startup-shutdown database",
    );
  }
  if (!/^\d+$/u.test(raw)) {
    throw new Error("TI_SCALE_TEST_STARTUP_HOLD_AFTER_LEASE_MS must be an integer");
  }
  const result = Number(raw);
  if (!Number.isSafeInteger(result) || result < 100 || result > 10_000) {
    throw new Error("TI_SCALE_TEST_STARTUP_HOLD_AFTER_LEASE_MS must be between 100 and 10000");
  }
  return result;
}

function useSlowStartupIntegrityFixture(canonicalDatabasePath: string): boolean {
  if (!enabled("TI_SCALE_TEST_SLOW_STARTUP_INTEGRITY")) return false;
  const testRoot = resolve(tmpdir());
  const relativeDatabase = relative(testRoot, canonicalDatabasePath);
  const firstSegment = relativeDatabase.split(sep)[0] ?? "";
  if (
    process.env.NODE_ENV !== "test"
    || process.env.TI_SCALE_PREVIEW !== "true"
    || process.env.TI_SCALE_SERVE_STATIC !== "true"
    || relativeDatabase === ""
    || relativeDatabase === ".."
    || relativeDatabase.startsWith(`..${sep}`)
    || !firstSegment.startsWith("ti-scale-static-server-integration-")
  ) {
    throw new Error(
      "TI_SCALE_TEST_SLOW_STARTUP_INTEGRITY is test-only and requires an isolated static-server integration database",
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

/**
 * The managed Playwright boundary has no operating-system child processes,
 * but its canonical fixture records still need the same exact-set receipt as
 * production cancellation before the plan-change service may close them.
 *
 * This helper is reachable only after testRunControlRuntimeEnabled() has
 * proved the explicit test flag and an isolated /tmp/ti-scale-e2e-data
 * database. It does not mutate records or grant a lease; the router's normal
 * server-side mutation-authority proof remains mandatory.
 */
function attestTestPlanChangeAffectedWorkCancellation(
  database: Parameters<typeof createMissionRuntime>[0]["database"],
  runId: string,
  actionIds: readonly string[],
): PlanChangeAffectedWorkStopReceipt {
  const requested = [...new Set(actionIds)].sort();
  const running = database.prepare(`
    SELECT id, step_id, assignment_id FROM actions
    WHERE run_id = ? AND status = 'running'
    ORDER BY id
  `).all(runId) as Array<{
    readonly id: string;
    readonly step_id: string | null;
    readonly assignment_id: string | null;
  }>;
  const canonical = running.map((row) => row.id);
  if (
    requested.length !== canonical.length
    || requested.some((actionId, index) => actionId !== canonical[index])
  ) {
    throw new Error(
      "The disposable exact-child cancellation receipt does not match every running fixture action",
    );
  }
  const stoppedAssignmentIds = [...new Set(running
    .map((row) => row.assignment_id)
    .filter((value): value is string => value !== null))].sort();
  const stoppedStepIds = [...new Set(running
    .map((row) => row.step_id)
    .filter((value): value is string => value !== null))].sort();
  const stoppedAttackAttemptIds = stoppedStepIds.length === 0
    ? []
    : (database.prepare(`
        SELECT id FROM attack_attempts
        WHERE run_id = ? AND status = 'running'
          AND step_id IN (${stoppedStepIds.map(() => "?").join(", ")})
        ORDER BY id
      `).all(runId, ...stoppedStepIds) as Array<{ readonly id: string }>)
      .map((row) => row.id);
  return {
    stoppedActionIds: requested,
    stoppedAssignmentIds,
    stoppedAttackAttemptIds,
    stoppedStepIds,
  };
}

function publicApiPath(path: string): boolean {
  return path === "/api/v2/health"
    || path === "/api/v2/system/readiness"
    || path === "/api/v2/openapi.json"
    || path === "/api/v2/contracts/events"
    || path === "/api/v2/auth/session";
}

function mountLocalSessionBoundary(
  web: ReturnType<typeof express>,
  sessionAuth: LocalSessionAuth | undefined,
  secureCookies: boolean,
): void {
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
  web.use(createLocalSessionRouter({ auth: sessionAuth, secureCookies }));
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
    applicationStyleSourceDirective(),
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "font-src 'self' data:",
    // Three's GLTFLoader turns validated embedded GLB textures into same-page
    // blob URLs before image decoding. Keep network access same-origin while
    // permitting that local, non-network decode path.
    applicationConnectSourceDirective(),
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

interface StaticApplicationAdmission {
  readonly enabled: boolean;
  readonly dist: string;
  readonly pinnedRelease?: {
    readonly releaseId: string;
    readonly manifestSha256: string;
  };
}

function resolveStaticApplicationAdmission(): StaticApplicationAdmission {
  const serveStatic = enabled("TI_SCALE_SERVE_STATIC");
  const previewEnabled = enabled("TI_SCALE_PREVIEW", true);
  const mutableDevelopmentDist = fileURLToPath(new URL("../dist/", import.meta.url));
  const staticReleaseRoot = process.env.TI_SCALE_STATIC_RELEASE_ROOT?.trim();
  if (staticReleaseRoot && !isAbsolute(staticReleaseRoot)) {
    throw new Error("TI_SCALE_STATIC_RELEASE_ROOT must be an absolute Ti-Scale path");
  }
  // Resolve and verify one immutable release exactly once. Both the startup
  // authentication listener and the operational handler serve this same
  // pinned directory, so pointer changes cannot split one process across UI
  // versions while the canonical database integrity check is in flight.
  const pinned = serveStatic && staticReleaseRoot
    ? new StaticArtifactReleaseStore({ releaseRoot: staticReleaseRoot }).pinActiveRelease()
    : undefined;
  const managedE2EStaticBuild = serveStatic && !pinned
    ? resolveManagedE2EStaticBuild(process.env, { requireBuiltArtifact: true })
    : undefined;
  const dist = pinned?.releaseDirectory
    ?? managedE2EStaticBuild
    ?? mutableDevelopmentDist;
  return {
    // A manifest-pinned immutable release is the production application and
    // must remain available when development preview mode is disabled.
    // Mutable source-tree and Playwright-managed builds continue to require
    // the explicit preview boundary.
    enabled: serveStatic
      && (pinned !== undefined || previewEnabled)
      && existsSync(resolve(dist, "index.html")),
    dist,
    ...(pinned ? {
      pinnedRelease: {
        releaseId: pinned.releaseId,
        manifestSha256: pinned.manifestSha256,
      },
    } : {}),
  };
}

function mountStaticApplication(
  web: ReturnType<typeof express>,
  admission: StaticApplicationAdmission,
): void {
  if (!admission.enabled) return;
  web.use(createStaticApplicationCompression());
  web.use(express.static(admission.dist, {
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
    response.sendFile(resolve(admission.dist, "index.html"));
  });
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
  let stopping = false;
  const stop = (): void => {
    if (stopping) return;
    stopping = true;
    server.close(() => process.exit(0));
  };
  // Keep both handlers installed until process exit. Removing the only
  // listener after the first signal would restore Node's default action, so a
  // duplicate service-manager signal could bypass the in-flight drain.
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

async function main(): Promise<void> {
  const bind = process.env.TI_SCALE_HOST?.trim() || DEFAULT_BIND;
  const listenPort = port();
  if (enabled("TI_SCALE_KILL_SWITCH")) {
    killSwitchServer(bind, listenPort);
    return;
  }

  type ShutdownSignal = "SIGINT" | "SIGTERM";
  const startupPhases = new Map<string, GracefulShutdownComponent[]>();
  const startupFinalizers: GracefulShutdownFinalizer[] = [];
  let startupCloseAdmission = (): void => undefined;
  let runtimeSignalHandler: ((signal: ShutdownSignal) => void) | undefined;
  let startupShutdownStarted = false;
  let exitSignal = "process-exit";
  const registerStartupComponent = (
    phase: string,
    component: GracefulShutdownComponent,
  ): void => {
    if (startupShutdownStarted) {
      component.beginStop?.();
      void Promise.resolve(component.stop()).catch(() => undefined);
      throw new Error("Ti-Scale startup was interrupted by shutdown");
    }
    const components = startupPhases.get(phase) ?? [];
    if (components.some(({ name }) => name === component.name)) return;
    components.push(component);
    startupPhases.set(phase, components);
  };
  const registerStartupFinalizer = (finalizer: GracefulShutdownFinalizer): void => {
    if (startupFinalizers.some(({ name }) => name === finalizer.name)) return;
    startupFinalizers.push(finalizer);
  };
  const assertStartupActive = (): void => {
    if (startupShutdownStarted) throw new Error("Ti-Scale startup was interrupted by shutdown");
  };
  const dispatchProcessSignal = (signal: ShutdownSignal): void => {
    exitSignal = signal;
    if (runtimeSignalHandler) {
      runtimeSignalHandler(signal);
      return;
    }
    if (startupShutdownStarted) return;
    startupShutdownStarted = true;
    process.stdout.write(`Ti-Scale received ${signal} during startup; draining initialized resources\n`);
    const phases = ["runtimes", "readiness", "workers", "transport", "canonical-data"]
      .map((name) => ({ name, components: startupPhases.get(name) ?? [] }))
      .filter(({ components }) => components.length > 0);
    const startupShutdown = new GracefulShutdownCoordinator({
      deadlineMs: GRACEFUL_SHUTDOWN_DEADLINE_MS,
      closeAdmission: startupCloseAdmission,
      phases,
      finalizers: startupFinalizers,
    });
    void startupShutdown.shutdown(signal).then((report) => {
      const exitCode = report.outcome === "completed" && process.exitCode !== 1 ? 0 : 1;
      const detail = report.outcome === "timed_out"
        ? `; pending components: ${report.pendingComponentNames.join(", ") || "none"}`
        : report.outcome === "failed"
          ? `; failed components: ${report.failedComponentNames.join(", ") || "none"}`
          : "";
      process.exitCode = exitCode;
      writeShutdownSummaryAndExit(
        exitCode === 0 ? process.stdout : process.stderr,
        `Ti-Scale startup shutdown ${report.outcome} in ${report.durationMs}ms${detail}\n`,
        exitCode,
      );
    }).catch((error: unknown) => {
      process.exitCode = 1;
      writeShutdownSummaryAndExit(
        process.stderr,
        `Ti-Scale startup shutdown coordinator failed: ${error instanceof Error ? error.name : "UnknownError"}\n`,
        1,
      );
    });
  };
  // Signal admission is a durable fence, not a one-shot listener. A repeated
  // SIGTERM/SIGINT during startup or normal drain must be absorbed by the
  // idempotent dispatcher instead of reverting to immediate process death.
  process.on("SIGINT", () => dispatchProcessSignal("SIGINT"));
  process.on("SIGTERM", () => dispatchProcessSignal("SIGTERM"));
  fatalMainFailureShutdown = () => dispatchProcessSignal("SIGTERM");

  const token = resolveOperatorToken();
  const actorId = process.env.TI_SCALE_OPERATOR_ID?.trim() || "local-operator";
  if (!OPERATOR_ID.test(actorId)) throw new Error("TI_SCALE_OPERATOR_ID is invalid");
  const sessionAuth = token ? new LocalSessionAuth({ operatorToken: token, actorId }) : undefined;
  const secureCookies = enabled(
    "TI_SCALE_SECURE_COOKIES",
    !["127.0.0.1", "::1", "localhost"].includes(bind),
  );
  const serviceDrainAdmission = new ServiceDrainAdmission();
  const staticApplicationAdmission = resolveStaticApplicationAdmission();
  if (staticApplicationAdmission.pinnedRelease) {
    process.stdout.write(
      `Ti-Scale pinned static release ${staticApplicationAdmission.pinnedRelease.releaseId} `
      + `(${staticApplicationAdmission.pinnedRelease.manifestSha256})\n`,
    );
  }
  const startupStartedAt = new Date().toISOString();
  let startupPhase = "authentication_admission";
  const startupWeb = express();
  startupWeb.disable("x-powered-by");
  startupWeb.set("trust proxy", false);
  startupWeb.use(securityHeaders);
  startupWeb.use(cors(process.env.TI_SCALE_UI_ORIGIN?.trim() || DEFAULT_UI_ORIGIN));
  startupWeb.use(v2RequestContext);
  startupWeb.use(serviceDrainAdmission.middleware);
  startupWeb.use(express.json({ limit: MAX_JSON_BODY, strict: true, type: "application/json" }));
  startupWeb.use(v2JsonBodyError);
  mountLocalSessionBoundary(startupWeb, sessionAuth, secureCookies);
  startupWeb.get("/api/v2/health", (_request, response) => {
    response.setHeader("Cache-Control", "no-store");
    response.json({
      schemaVersion: "2.4",
      status: "degraded",
      service: "ti-scale",
      startup: {
        status: "initializing",
        phase: startupPhase,
        startedAt: startupStartedAt,
        executionAdmission: "closed",
      },
      database: { status: "initializing" },
      eventStream: { status: "initializing", subscribers: 0 },
      checkedAt: new Date().toISOString(),
    });
  });
  startupWeb.get("/api/v2/system/readiness", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    sendV2Error(response, traceId, {
      status: 503,
      code: "ti_scale_startup_initializing",
      message: "Ti-Scale runtime readiness is still initializing",
      humanMessage: "Sign-in is available, but mission execution remains locked while Ti-Scale verifies its local runtime and tools.",
      retryable: true,
      category: "dependency_missing",
      details: { phase: startupPhase, executionAdmission: "closed" },
      remediation: "Keep this page open and retry readiness after initialization advances.",
    });
  });
  startupWeb.all(V2_API_TREE_ROUTE, (request, response) => {
    const traceId = attachV2RequestId(request, response);
    sendV2Error(response, traceId, {
      status: 503,
      code: "ti_scale_startup_initializing",
      message: "Ti-Scale operational admission is closed during startup",
      humanMessage: "Ti-Scale is still verifying its runtime. No mission or execution change was accepted.",
      retryable: true,
      category: "dependency_missing",
      details: { phase: startupPhase, executionAdmission: "closed" },
      remediation: "Wait for runtime readiness to complete, then retry the operation once.",
    });
  });
  // The browser shell is intentionally available before the potentially long
  // canonical database integrity check. Its only live dependency at this
  // point is the local session route above; every operational API remains
  // behind the fail-closed startup handler.
  mountStaticApplication(startupWeb, staticApplicationAdmission);

  let activeHttpHandler: ReturnType<typeof express> = startupWeb;
  const server = createServer((request, response) => activeHttpHandler(request, response));
  server.requestTimeout = 120_000;
  server.headersTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 100;
  let startupHttpCloseStarted = false;
  let resolveStartupHttpClosed!: () => void;
  let rejectStartupHttpClosed!: (error: Error) => void;
  const startupHttpClosed = new Promise<void>((resolveClosed, rejectClosed) => {
    resolveStartupHttpClosed = resolveClosed;
    rejectStartupHttpClosed = rejectClosed;
  });
  const closeStartupHttpAdmission = (): void => {
    if (startupHttpCloseStarted) return;
    startupHttpCloseStarted = true;
    serviceDrainAdmission.beginDrain();
    server.close((error) => {
      if (!error || (error as NodeJS.ErrnoException).code === "ERR_SERVER_NOT_RUNNING") {
        resolveStartupHttpClosed();
      } else {
        rejectStartupHttpClosed(error);
      }
    });
    server.closeIdleConnections?.();
    server.closeAllConnections?.();
  };
  startupCloseAdmission = closeStartupHttpAdmission;
  registerStartupComponent("transport", {
    name: "startup-http-server",
    stop: () => startupHttpClosed,
  });
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(listenPort, bind, () => {
      server.off("error", rejectListen);
      process.stdout.write(
        `Ti-Scale authentication admission active at http://${bind}:${listenPort}; operational execution remains locked during startup\n`,
      );
      resolveListen();
    });
  });
  assertStartupActive();

  const canonicalDatabasePath = databasePath();
  let startupDatabaseIntegrity: IntegrityResult | undefined;
  if (existsSync(canonicalDatabasePath)) {
    const slowIntegrityFixture = useSlowStartupIntegrityFixture(canonicalDatabasePath);
    const startupDatabaseIntegrityVerifier = new StartupDatabaseIntegrityVerifier(
      slowIntegrityFixture ? {
        childEntrypoint: fileURLToPath(new URL(
          "./app/__tests__/fixtures/SlowStartupDatabaseIntegrityChild.ts",
          import.meta.url,
        )),
      } : {},
    );
    registerStartupComponent("readiness", {
      name: "startup-database-integrity",
      beginStop: () => startupDatabaseIntegrityVerifier.beginStop(),
      stop: () => startupDatabaseIntegrityVerifier.stop(),
    });
    startupPhase = "database_integrity";
    startupDatabaseIntegrity = await startupDatabaseIntegrityVerifier.verify(canonicalDatabasePath);
    assertStartupActive();
    if (!startupDatabaseIntegrity.ok) {
      throw new Error("The canonical Ti-Scale database failed its isolated startup integrity check");
    }
  }

  startupPhase = "configuration_loading";
  const configuredRuntimeManifest = loadProductionRuntimeManifest();
  const localGuidedToolConfiguration = loadProductionLocalGuidedToolConfiguration();
  const windowsIdentityEnabled = enabled("TI_SCALE_WINDOWS_IDENTITY_ENABLED");
  const localExploitIntelligenceEnabled = enabled(
    "TI_SCALE_LOCAL_EXPLOIT_INTELLIGENCE_ENABLED",
  );
  if (windowsIdentityEnabled && localGuidedToolConfiguration.status !== "loaded") {
    throw new Error(
      "TI_SCALE_WINDOWS_IDENTITY_ENABLED requires the complete deployment-pinned local Guided sandbox and workspace configuration",
    );
  }
  const autonomousDnsProductionConfiguration = loadProductionAutonomousDnsConfiguration();
  let localGuidedToolAdapter: DirectProcessLocalToolInvocationAdapter | undefined;
  let localGuidedToolExecution: ReviewedLocalToolExecutionPort | undefined;
  let windowsIdentityExecution: WindowsIdentityGuidedExecutionPort | undefined;
  let localExploitIntelligenceExecution:
    SearchSploitGuidedExecutionPort | undefined;
  let localExploitIntelligenceMissionRuntimeMounted = false;
  let localGuidedToolActivation: LocalGuidedToolActivationCoordinator | undefined;
  const loadedOpenRouterConnection = loadOpenRouterConnectionConfiguration();
  const openRouterConfiguration = loadedOpenRouterConnection.configuration;
  const openRouterCredentialReader = openRouterConfiguration.state === "configured_unattested"
    ? captureOpenRouterCredential({
        path: openRouterConfiguration.credentialPath,
      })
    : undefined;
  let durableOpenRouterVerifier: OpenRouterCompletionVerifier | undefined;
  const deferredOpenRouterVerifier: OpenRouterCompletionVerifier | undefined =
    openRouterConfiguration.state === "configured_unattested"
      ? {
          verify(configuration, signal) {
            if (!durableOpenRouterVerifier) {
              throw new OpenRouterPlanningError(
                "openrouter_readiness_audit_unavailable",
                "The durable readiness audit boundary is not initialized",
                {
                  status: 503,
                  category: "persistence",
                  retryable: true,
                  remediation: "Restore the canonical V2 database and provider audit services before retrying readiness.",
                },
              );
            }
            return durableOpenRouterVerifier.verify(configuration, signal);
          },
        }
      : undefined;
  const openRouterRuntime = createProductionOpenRouterReadinessRuntime({
    configuration: openRouterConfiguration,
    ...(deferredOpenRouterVerifier
      ? { completionVerifier: deferredOpenRouterVerifier }
      : {}),
    ...(openRouterCredentialReader
      ? { credentialReader: openRouterCredentialReader }
      : {}),
  });
  const baselineRuntimeProjection = (): RuntimeProjectionInput =>
    projectConfiguredRuntimeManifest({
      readiness: {
        ...unavailableRuntime(),
        guidedManualPlanning: {
          status: "ready",
          plannerId: "ti-scale.local-guided-manual-planner",
          executionMode: "manual_only",
          targetInteraction: "operator_only",
          providerContact: false,
          toolDispatch: false,
          reason: "A local deterministic planner can create represented manual Guided steps. It never contacts a provider, target, tool, or MCP server.",
        },
      },
      agents: [localGuidedManualAgentProjection()],
      mcpServers: [],
    }, configuredRuntimeManifest);
  const publicNvdBoundary = createProductionPublicNvdMcpBoundary();
  const publicNvdRuntime = publicNvdBoundary.runtime;
  registerStartupComponent("readiness", {
    name: "startup-openrouter-readiness",
    beginStop: () => openRouterRuntime.beginStop(),
    stop: () => openRouterRuntime.stop(),
  });
  registerStartupComponent("readiness", {
    name: "startup-public-nvd-readiness",
    beginStop: () => publicNvdRuntime.beginStop(),
    stop: () => publicNvdRuntime.stop(),
  });
  const rawRuntimeProjection = () => projectPublicNvdMcpRuntime(
    projectOpenRouterRuntime(baselineRuntimeProjection(), openRouterRuntime.snapshot()),
    publicNvdRuntime.snapshot(),
    { missionReadAdapterAvailable: true },
  );
  const initialRuntimeManifests = rawRuntimeProjection().capabilityManifests
    ?? emptyRuntimeSourceManifests();
  const toolBindingReadiness = createProductionToolBindingReadiness({
    manifests: initialRuntimeManifests,
    ...(process.env.TI_SCALE_TOOL_BINDING_REGISTRY_PATH?.trim()
      ? { registryPath: process.env.TI_SCALE_TOOL_BINDING_REGISTRY_PATH.trim() }
      : {}),
  });
  registerStartupComponent("readiness", {
    name: "startup-tool-binding-readiness",
    beginStop: () => toolBindingReadiness.runner.beginStop(),
    stop: () => toolBindingReadiness.runner.stop().then(() => undefined),
  });
  // Mission intake, action-class policy, and self-tests must never observe an
  // optimistic local-tool manifest before the complete initial receipt wave.
  startupPhase = "tool_binding_readiness";
  const initialToolReadiness = await toolBindingReadiness.runner.startMonitoring();
  assertStartupActive();
  toolBindingReadiness.assertCompleteInitialWave(initialToolReadiness);
  const windowsIdentityRegistry = windowsIdentityEnabled
    ? new WindowsIdentityCapabilityRegistry()
    : undefined;
  const windowsIdentityWorkspaceResolver = windowsIdentityEnabled
    && localGuidedToolConfiguration.status === "loaded"
    ? new EngagementWorkspaceResolver(localGuidedToolConfiguration.workspaceMappings.mappings)
    : undefined;
  const windowsIdentityCredentialRoot = process.env.TI_SCALE_WINDOWS_IDENTITY_CREDENTIAL_ROOT?.trim();
  const windowsIdentityCredentialResolver = windowsIdentityEnabled
    && windowsIdentityCredentialRoot
    ? new SystemdWindowsIdentityCredentialResolver(windowsIdentityCredentialRoot)
    : undefined;
  const windowsIdentityAdapter = windowsIdentityRegistry
    && windowsIdentityWorkspaceResolver
    && localGuidedToolConfiguration.status === "loaded"
    ? new DirectWindowsIdentityProcessAdapter({
        workspaceResolver: windowsIdentityWorkspaceResolver,
        ...(windowsIdentityCredentialResolver
          ? { credentialResolver: windowsIdentityCredentialResolver }
          : {}),
        sandboxExecutable: {
          path: localGuidedToolConfiguration.probeSandbox.executablePath,
          expectedSha256: localGuidedToolConfiguration.probeSandbox.expectedSha256,
        },
      })
    : undefined;
  const windowsIdentityProbeEnvironment = windowsIdentityRegistry
    && localGuidedToolConfiguration.status === "loaded"
    ? new BubblewrapToolProbeEnvironment(localGuidedToolConfiguration.probeSandbox)
    : undefined;
  const windowsIdentityReadinessRunner = windowsIdentityRegistry
    && windowsIdentityProbeEnvironment
    ? new ToolBindingReadinessRunner(
        windowsIdentityRegistry.createToolBindingRegistry(),
        new ToolExecutionPreflightService({
          environment: windowsIdentityProbeEnvironment,
        }),
      )
    : undefined;
  const windowsIdentityStopController = new AbortController();
  const windowsIdentityInitialActivation = windowsIdentityRegistry
    && windowsIdentityAdapter
    && windowsIdentityReadinessRunner
    ? activateWindowsIdentityRuntime({
        registry: windowsIdentityRegistry,
        runner: windowsIdentityReadinessRunner,
        adapter: windowsIdentityAdapter,
        signal: windowsIdentityStopController.signal,
      })
    : undefined;
  let windowsIdentityRefreshInFlight: Promise<void> | undefined;
  let windowsIdentityRefreshTimer: ReturnType<typeof setInterval> | undefined;
  let windowsIdentityReadinessStopped = false;
  const beginStopWindowsIdentityReadiness = (): void => {
    if (windowsIdentityReadinessStopped) return;
    windowsIdentityReadinessStopped = true;
    windowsIdentityStopController.abort("Ti-Scale Windows identity readiness is stopping");
    if (windowsIdentityRefreshTimer) clearInterval(windowsIdentityRefreshTimer);
    windowsIdentityRefreshTimer = undefined;
    windowsIdentityReadinessRunner?.beginStop();
  };
  const stopWindowsIdentityReadiness = async (): Promise<void> => {
    beginStopWindowsIdentityReadiness();
    await drainWindowsIdentityReadinessResources({
      ...(windowsIdentityReadinessRunner ? { runner: windowsIdentityReadinessRunner } : {}),
      ...(windowsIdentityInitialActivation ? { initialActivation: windowsIdentityInitialActivation } : {}),
      ...(windowsIdentityRefreshInFlight ? { refreshInFlight: windowsIdentityRefreshInFlight } : {}),
      ...(windowsIdentityProbeEnvironment ? { probeEnvironment: windowsIdentityProbeEnvironment } : {}),
    });
  };
  if (windowsIdentityReadinessRunner) {
    registerStartupComponent("readiness", {
      name: "startup-windows-identity-readiness",
      beginStop: beginStopWindowsIdentityReadiness,
      stop: stopWindowsIdentityReadiness,
    });
  }
  startupPhase = "windows_identity_readiness";
  let windowsIdentityActivation = await windowsIdentityInitialActivation;
  assertStartupActive();
  windowsIdentityRefreshTimer = windowsIdentityRegistry
    && windowsIdentityAdapter
    && windowsIdentityReadinessRunner
    ? setInterval(() => {
      if (windowsIdentityReadinessStopped
        || startupShutdownStarted
        || windowsIdentityRefreshInFlight) return;
        const refresh = activateWindowsIdentityRuntime({
          registry: windowsIdentityRegistry,
          runner: windowsIdentityReadinessRunner,
          adapter: windowsIdentityAdapter,
          signal: windowsIdentityStopController.signal,
        }).then((snapshot) => {
          if (!windowsIdentityReadinessStopped && !startupShutdownStarted) {
            windowsIdentityActivation = snapshot;
          }
        }).finally(() => {
          if (windowsIdentityRefreshInFlight === refresh) {
            windowsIdentityRefreshInFlight = undefined;
          }
        });
        windowsIdentityRefreshInFlight = refresh;
        void refresh.catch(() => undefined);
      }, 30_000)
    : undefined;
  windowsIdentityRefreshTimer?.unref();
  const localExploitIntelligencePack = localExploitIntelligenceEnabled
    ? new SearchSploitToolPack()
    : undefined;
  const localExploitIntelligenceAdapter = localExploitIntelligencePack
    ? new DirectSearchSploitProcessAdapter({
        pack: localExploitIntelligencePack,
      })
    : undefined;
  const localExploitIntelligenceActivationService = localExploitIntelligencePack
    ? new SearchSploitActivationService({
        pack: localExploitIntelligencePack,
      })
    : undefined;
  const localExploitIntelligenceStopController = new AbortController();
  const localExploitIntelligenceInitialActivation =
    localExploitIntelligencePack
    && localExploitIntelligenceAdapter
    && localExploitIntelligenceActivationService
      ? activateLocalExploitIntelligenceRuntime({
          pack: localExploitIntelligencePack,
          activation: localExploitIntelligenceActivationService,
          adapter: localExploitIntelligenceAdapter,
          signal: localExploitIntelligenceStopController.signal,
        })
      : undefined;
  let localExploitIntelligenceRefreshInFlight: Promise<void> | undefined;
  let localExploitIntelligenceRefreshTimer: ReturnType<typeof setInterval> | undefined;
  let localExploitIntelligenceReadinessStopped = false;
  const beginStopLocalExploitIntelligenceReadiness = (): void => {
    if (localExploitIntelligenceReadinessStopped) return;
    localExploitIntelligenceReadinessStopped = true;
    localExploitIntelligenceStopController.abort(
      "Ti-Scale local exploit intelligence readiness is stopping",
    );
    if (localExploitIntelligenceRefreshTimer) {
      clearInterval(localExploitIntelligenceRefreshTimer);
    }
    localExploitIntelligenceRefreshTimer = undefined;
  };
  const stopLocalExploitIntelligenceReadiness = async (): Promise<void> => {
    beginStopLocalExploitIntelligenceReadiness();
    await drainLocalExploitIntelligenceReadinessResources({
      ...(localExploitIntelligenceInitialActivation
        ? { initialActivation: localExploitIntelligenceInitialActivation }
        : {}),
      ...(localExploitIntelligenceRefreshInFlight
        ? { refreshInFlight: localExploitIntelligenceRefreshInFlight }
        : {}),
    });
  };
  if (localExploitIntelligenceInitialActivation) {
    registerStartupComponent("readiness", {
      name: "startup-local-exploit-intelligence-readiness",
      beginStop: beginStopLocalExploitIntelligenceReadiness,
      stop: stopLocalExploitIntelligenceReadiness,
    });
  }
  startupPhase = "local_exploit_intelligence_readiness";
  let localExploitIntelligenceActivation =
    await localExploitIntelligenceInitialActivation;
  assertStartupActive();
  localExploitIntelligenceRefreshTimer = localExploitIntelligencePack
    && localExploitIntelligenceAdapter
    && localExploitIntelligenceActivationService
    ? setInterval(() => {
        if (localExploitIntelligenceReadinessStopped
          || startupShutdownStarted
          || localExploitIntelligenceRefreshInFlight) return;
        const refresh = activateLocalExploitIntelligenceRuntime({
          pack: localExploitIntelligencePack,
          activation: localExploitIntelligenceActivationService,
          adapter: localExploitIntelligenceAdapter,
          signal: localExploitIntelligenceStopController.signal,
        }).then((snapshot) => {
          if (!localExploitIntelligenceReadinessStopped
            && !startupShutdownStarted) {
            localExploitIntelligenceActivation = snapshot;
          }
        }).finally(() => {
          if (localExploitIntelligenceRefreshInFlight === refresh) {
            localExploitIntelligenceRefreshInFlight = undefined;
          }
        });
        localExploitIntelligenceRefreshInFlight = refresh;
        void refresh.catch(() => undefined);
      }, 30_000)
    : undefined;
  localExploitIntelligenceRefreshTimer?.unref();
  const nonAutonomousRuntimeProjection = (): RuntimeProjectionInput => {
    const raw = rawRuntimeProjection();
    const attested: RuntimeProjectionInput = {
      ...raw,
      capabilityManifests: toolBindingReadiness.projectManifests(
        raw.capabilityManifests ?? emptyRuntimeSourceManifests(),
      ),
    };
    const localProjected = localGuidedToolConfiguration.status === "loaded"
      ? applyLocalGuidedToolRuntimeProjection(attested, projectLocalGuidedToolRuntime({
          baselineManifests: attested.capabilityManifests ?? emptyRuntimeSourceManifests(),
          manifest: localGuidedToolConfiguration.manifest,
          activationReceipts: localGuidedToolActivation?.snapshot().activationReceipts ?? [],
          adapterId: localGuidedToolAdapter?.adapterId ?? null,
        }))
      : attested;
    const identityProjected = windowsIdentityRegistry && windowsIdentityActivation
      ? applyWindowsIdentityRuntimeProjection(localProjected, projectWindowsIdentityRuntime({
          baselineManifests: localProjected.capabilityManifests ?? emptyRuntimeSourceManifests(),
          registry: windowsIdentityRegistry,
          activation: windowsIdentityActivation,
        }))
      : localProjected;
    return localExploitIntelligencePack && localExploitIntelligenceActivation
      ? applyLocalExploitIntelligenceRuntimeProjection(
          identityProjected,
          projectLocalExploitIntelligenceRuntime({
            baselineManifests: identityProjected.capabilityManifests
              ?? emptyRuntimeSourceManifests(),
            pack: localExploitIntelligencePack,
            activation: localExploitIntelligenceActivation,
            missionRuntimeMounted:
              localExploitIntelligenceMissionRuntimeMounted,
          }),
        )
      : identityProjected;
  };
  let autonomousDnsLifecycle: AutonomousDnsRuntimeLifecycle | undefined;
  const runtimeProjection = (): RuntimeProjectionInput => {
    if (autonomousDnsLifecycle) return autonomousDnsLifecycle.projection();
    const projected = nonAutonomousRuntimeProjection();
    return {
      ...projected,
      readiness: {
        ...projected.readiness,
        autonomousRuntime: inspectAutonomousRuntimeComposition({ projection: projected }),
      },
    };
  };
  const vaultRoot = process.env.TI_SCALE_VAULT_ROOT?.trim();
  if (vaultRoot && !isAbsolute(vaultRoot)) {
    throw new Error("TI_SCALE_VAULT_ROOT must be an absolute path");
  }
  const vaultPathPolicy = vaultRoot ? new VaultPathPolicy(vaultRoot) : undefined;
  const scriptSourceStore = new FileScriptSourceStore(resolveV2ScriptSourceRoot(
    canonicalDatabasePath,
    process.env.TI_SCALE_SCRIPT_SOURCE_ROOT,
  ));
  const researchIntegrityKey = resolveResearchIntegrityKey();
  const researchIntegrityAuthority = researchIntegrityKey
    ? new IntegrityAuthority(researchIntegrityKey)
    : undefined;
  const privateResearchHoldoutConfiguration =
    loadProductionPrivateResearchHoldoutConfiguration();
  const privateResearchHoldout =
    privateResearchHoldoutConfiguration.status === "loaded"
      ? privateResearchHoldoutConfiguration.registry
      : undefined;
  const researchReadinessConfiguration =
    loadProductionResearchReadinessProbeConfiguration();
  const researchExecutionBoundary =
    researchReadinessConfiguration.status === "loaded"
    && researchIntegrityKey
      ? new ResearchExecutionBoundary(
          researchReadinessConfiguration.descriptor,
          researchIntegrityKey,
          researchReadinessConfiguration.temporaryRoot,
        )
      : undefined;
  if (researchExecutionBoundary) {
    registerStartupComponent("readiness", {
      name: "startup-research-readiness",
      beginStop: () => researchExecutionBoundary.beginStop(),
      stop: () => researchExecutionBoundary.stop(),
    });
    startupPhase = "research_readiness";
    await researchExecutionBoundary.start();
    assertStartupActive();
  }
  const testRunControlEnabled = testRunControlRuntimeEnabled(canonicalDatabasePath);
  const testRunControlScheduler = testRunControlSchedulerEnabled(testRunControlEnabled);
  let testAuthorityDatabase: Parameters<typeof assertTestRunMutationAuthority>[0] | undefined;
  let productionGuidedRuntime: MissionRuntimeEngine | undefined;
  let productionRuntimeForRun = (_runId: string): MissionRuntimeEngine | undefined =>
    productionGuidedRuntime;
  let assertProductionRunMutationAuthority = (runId: string) =>
    productionGuidedRuntime?.assertControlPlaneMutationAuthority(runId);
  let vaultMemoryProjector: ConnectedVaultMemoryProjector | undefined;
  let runtimeCapabilityMemoryProjector: RuntimeCapabilityMemoryProjector | undefined;
  const projectMemoryNodes = (nodeIds: readonly string[]): void => {
    vaultMemoryProjector?.project(nodeIds);
  };
  const application = createCommandOsApplication({
    databasePath: canonicalDatabasePath,
    ...(startupDatabaseIntegrity ? {
      databaseIntegrityChecker: () => startupDatabaseIntegrity!,
    } : {}),
    // The router is mounted below for both the production Guided runtime and
    // the isolated Playwright authority. It remains explanation-only and
    // every mutation is still fenced to the current exact Guided decision.
    localCommanderGuidanceMounted: true,
    readinessProviders: (_database, readRuntimeProjection) => [
      ...createRuntimeReadinessProviders(() => readRuntimeProjection().readiness),
      authenticationReadiness(Boolean(token)),
    ],
    runtimeProjection,
    projectMemoryNodes,
    readToolExecutionPreflight: (toolId) =>
      autonomousDnsLifecycle?.readToolExecutionPreflight(toolId)
      ?? localGuidedToolActivation?.readToolExecutionPreflight(toolId)
      ?? windowsIdentityReadinessRunner?.readToolExecutionPreflight(toolId)
      ?? toolBindingReadiness.runner.readToolExecutionPreflight(toolId),
    ...(vaultPathPolicy ? {
      resolveExistingVaultPath: (vaultPath: string) =>
        vaultPathPolicy.resolveExistingVault(vaultPath),
    } : {}),
    projectionIntervalMs: projectionIntervalMs(),
    ...(researchIntegrityAuthority
      ? { researchIntegrityAuthority }
      : {}),
    ...(privateResearchHoldout
      ? { privateResearchHoldout }
      : {}),
    researchReadiness: () =>
      researchExecutionBoundary?.readiness()
      ?? {
        disposableLabReady: false,
        isolatedWorkerReady: false,
        integritySigningKeyReady: Boolean(researchIntegrityAuthority),
      },
    ...(researchExecutionBoundary && researchIntegrityAuthority
      ? {
          createResearchExperimentRunner: (database) =>
            new ExperimentRunner({
              database,
              boundary: researchExecutionBoundary,
              integrityAuthority: researchIntegrityAuthority,
              ...(privateResearchHoldout
                ? { privateHoldout: privateResearchHoldout }
                : {}),
            }),
        }
      : {}),
    resolveActor: () => actorId,
    resolveEventSensitivity: () => "restricted",
    resolvePageCaptureActor: () => ({ id: actorId, type: "operator" }),
    authorizePageCaptures: (_request, actor) => actor.type === "operator" && actor.id === actorId,
    publicNvdDetailClient: publicNvdBoundary.client,
    resolvePublicNvdDetailActor: () => ({ id: actorId, type: "operator" }),
    authorizePublicNvdDetail: (_request, actor) =>
      actor.type === "operator" && actor.id === actorId,
    scriptSourceStore,
    resolveScriptArtifactActor: () => ({ id: actorId, type: "operator" }),
    authorizeScriptArtifacts: (_request, actor) => actor.type === "operator" && actor.id === actorId,
    assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
      if (testRunControlEnabled) {
        if (!testAuthorityDatabase) return undefined;
        return assertTestRunMutationAuthority(testAuthorityDatabase, runId);
      }
      return assertProductionRunMutationAuthority(runId);
    },
    cancelPlanChangeAffectedWork: async ({ runId, actionIds, reason }) => {
      if (testRunControlEnabled) {
        if (!testAuthorityDatabase) {
          throw new Error("The disposable run-control database is unavailable");
        }
        return attestTestPlanChangeAffectedWorkCancellation(
          testAuthorityDatabase,
          runId,
          actionIds,
        );
      }
      const runtime = productionRuntimeForRun(runId);
      if (!runtime) {
        throw new Error("The trusted Ti-Scale runtime is unavailable for exact affected-work cancellation");
      }
      return runtime.cancelPlanChangeAffectedWork(runId, actionIds, reason);
    },
  });
  const openRouterPlanningClient =
    openRouterConfiguration.state === "configured_unattested"
      ? createOpenRouterPlanningClient({
          credentialPath: openRouterConfiguration.credentialPath,
          ...(openRouterCredentialReader
            ? { credentialReader: openRouterCredentialReader }
            : {}),
          requestAuditor: createOpenRouterProviderRequestAuditor({
            database: application.database,
          }),
        })
      : undefined;
  const autonomousProviderAdvisory = openRouterPlanningClient
    ? createAutonomousProviderAdvisoryComposition({
        database: application.database,
        providerClient: openRouterPlanningClient,
        readReadiness: () => openRouterRuntime.snapshot(),
        readAttestation: () => openRouterRuntime.attestation(),
        waitForReadiness: () => openRouterRuntime.refreshNow(),
      })
    : undefined;
  const guidedAgentRuntimeResolver = createGuidedAgentRuntimeResolver({
    bindings: new AgentRuntimeBindingService(application.database),
    modelConfigurations: application.modelConfigurations,
    planningPorts: {
      create(configuration) {
        if (
          configuration.providerId === "provider:local-deterministic-safe-recon"
          && configuration.modelId === "policy:local-safe-recon-v2"
        ) {
          return createLocalDeterministicGuidedCommanderPort({
            providerId: configuration.providerId,
            model: configuration.modelId,
            modelConfigurationHash: hashCanonical({
              schemaVersion: "ti-scale.local-guided-model-binding.v1",
              configurationId: configuration.id,
              configurationVersion: configuration.version,
              providerId: configuration.providerId,
              modelId: configuration.modelId,
              reasoningEffort: configuration.reasoningEffort,
              contextPolicy: configuration.contextPolicy,
              capabilities: configuration.capabilities,
              disclosureClass: configuration.disclosureClass,
              enforcementMode: configuration.enforcementMode,
            }),
          });
        }
        if (
          configuration.providerId === "openrouter"
          && openRouterConfiguration.state === "configured_unattested"
          && openRouterPlanningClient
          && configuration.modelId
            === openRouterConfiguration.modelConfiguration.model
        ) {
          const attestation = openRouterRuntime.attestation();
          if (!attestation) return undefined;
          return createOpenRouterGuidedCommanderPort({
            client: openRouterPlanningClient,
            configuration: openRouterConfiguration.modelConfiguration,
            readinessAttestation: attestation,
          });
        }
        return undefined;
      },
    },
  });
  const openRouterConnectionService = new OpenRouterConnectionService({
    database: application.database,
    store: loadedOpenRouterConnection.store,
    activeConfiguration: openRouterConfiguration,
    activeConfigurationSource: loadedOpenRouterConnection.source,
    activeConfigurationVersion:
      loadedOpenRouterConnection.activeConfigurationVersion,
    readRuntime: () => openRouterRuntime.snapshot(),
    refreshRuntime: () => openRouterRuntime.refreshNow(),
    publishRuntimeProjection: () => {
      application.synchronizeRuntimeProjection(runtimeProjection());
    },
  });
  registerStartupComponent("canonical-data", {
    name: "startup-command-os-application",
    beginStop: () => application.beginStop(),
    stop: () => application.stop(),
  });
  // One durable writer lease covers every in-process HTTP route, scheduler,
  // projector, watcher, and repository mutation. Maintenance can begin only
  // after the whole service has drained and released this process lease.
  const processLeaseDatabase = createDatabaseConnection({
    filename: canonicalDatabasePath,
    fileMustExist: true,
    verifyIntegrity: false,
    // Heartbeat renewal runs on the JavaScript thread. A canonical writer
    // collision must return promptly for bounded retry instead of freezing
    // every HTTP request for the normal five-second SQLite busy timeout.
    busyTimeoutMs: PROCESS_WRITER_LEASE_BUSY_TIMEOUT_MS,
  });
  const processLeases = new CanonicalDatabaseLeaseService(processLeaseDatabase);
  const initialProcessLease = processLeases.acquireWriter({
    ownerId: `ti-scale-service:${process.pid}`,
    operation: "standalone-service-runtime",
    ttlMs: PROCESS_WRITER_LEASE_TTL_MS,
  });
  const processLeaseHeartbeat = new ProcessWriterLeaseHeartbeat({
    leases: processLeases,
    initialHandle: initialProcessLease,
    ttlMs: PROCESS_WRITER_LEASE_TTL_MS,
    intervalMs: PROCESS_WRITER_LEASE_HEARTBEAT_MS,
    onTransition: (transition) => {
      if (transition.state === "contended") {
        process.stderr.write(
          `Ti-Scale canonical writer lease renewal met ${transition.sqliteCode}; `
          + `bounded retry remains fail-closed at ${transition.deadlineAt}\n`,
        );
      } else {
        process.stdout.write(
          `Ti-Scale canonical writer lease renewal recovered after `
          + `${transition.attempts} transient contention attempt${transition.attempts === 1 ? "" : "s"}\n`,
        );
      }
    },
    onFailure: (error) => {
      process.stderr.write(
        `Ti-Scale canonical writer lease was lost: ${error.message}\n`,
      );
      process.kill(process.pid, "SIGTERM");
    },
  });
  processLeaseHeartbeat.start();
  let processLeaseReleased = false;
  const releaseProcessLease = (): void => {
    if (processLeaseReleased) return;
    processLeaseReleased = true;
    processLeaseHeartbeat.stop();
    try {
      processLeases.release(
        processLeaseHeartbeat.currentHandle,
        `service-shutdown:${exitSignal}`,
      );
    } finally {
      processLeaseDatabase.close();
    }
  };
  const releaseProcessLeaseAtExit = (): void => {
    try {
      releaseProcessLease();
    } catch (error) {
      process.stderr.write(
        `Ti-Scale could not release the canonical writer lease at process exit: ${error instanceof Error ? error.name : "UnknownError"}\n`,
      );
    }
  };
  // Install the fallback as soon as the writer lease exists. A SIGTERM during
  // later runtime activation therefore cannot leave a live startup lease just
  // because the fully composed shutdown coordinator is not mounted yet.
  process.once("exit", releaseProcessLeaseAtExit);
  registerStartupFinalizer({
    name: "startup-process-writer-lease-heartbeat",
    finalize: () => processLeaseHeartbeat.stop(),
  });
  registerStartupFinalizer({
    name: "startup-canonical-writer-lease",
    runOnTimeout: false,
    finalize: releaseProcessLease,
  });
  const startupTestHoldMs = startupShutdownTestHoldMs(canonicalDatabasePath);
  if (startupTestHoldMs !== undefined) {
    process.stdout.write("Ti-Scale startup shutdown test hold ready after writer lease\n");
    await new Promise<void>((resolveHold) => setTimeout(resolveHold, startupTestHoldMs));
    assertStartupActive();
  }
  const operationalHazardObservationKey = resolveOperationalHazardObservationKey({
    databasePath: canonicalDatabasePath,
  });
  const operationalHazardObservationWorker = new OperationalHazardObservationWorker(
    application.database,
    {
      hmacKey: operationalHazardObservationKey,
      workerId: `ti-scale-operational-hazard-observation-${process.pid}`,
    },
  );
  registerStartupComponent("workers", {
    name: "startup-operational-hazard-worker",
    beginStop: () => operationalHazardObservationWorker.stop(),
    stop: () => operationalHazardObservationWorker.stop(),
  });
  const vaultBridge = vaultPathPolicy
    ? new ObsidianVaultBridge(
        application.database,
        application.secondBrain.repository,
        vaultPathPolicy,
      )
    : undefined;
  const vaultWatcher = createProductionObsidianVaultWatcher({
    database: application.database,
    ...(vaultBridge ? { bridge: vaultBridge } : {}),
  });
  if (vaultWatcher) {
    registerStartupComponent("workers", {
      name: "startup-obsidian-vault-watcher",
      beginStop: () => vaultWatcher.beginStop(),
      stop: () => vaultWatcher.stop(),
    });
  }
  vaultMemoryProjector = vaultBridge
    ? new ConnectedVaultMemoryProjector(application.database, vaultBridge)
    : undefined;
  if (vaultMemoryProjector) {
    runtimeCapabilityMemoryProjector = new RuntimeCapabilityMemoryProjector({
      database: application.database,
      vaultProjector: vaultMemoryProjector,
    });
    new AutonomousRecoveryPolicyProjector(application.database, {
      projectMemoryNodes,
    }).project();
  }
  testAuthorityDatabase = application.database;
  if (openRouterConfiguration.state === "configured_unattested") {
    durableOpenRouterVerifier = createOpenRouterDurableReadinessVerifier({
      database: application.database,
      secondBrain: application.secondBrain,
      brainContext: application.brainContext,
      credentialPath: openRouterConfiguration.credentialPath,
      ...(openRouterCredentialReader
        ? { credentialReader: openRouterCredentialReader }
        : {}),
    });
  }
  const testRunControlRuntime = testRunControlEnabled
    ? createTestRunControlRuntime(application.database)
    : undefined;
  if (testRunControlRuntime) {
    registerStartupComponent("runtimes", {
      name: "startup-test-run-control-runtime",
      beginStop: () => testRunControlRuntime.beginStop(),
      stop: () => testRunControlRuntime.stop(),
    });
  }
  if (!testRunControlEnabled && localGuidedToolConfiguration.status === "loaded") {
    const defaultWorkspace = localGuidedToolConfiguration.workspaceMappings.mappings[0];
    if (!defaultWorkspace) {
      throw new Error("Reviewed local Guided tool configuration has no engagement workspace mapping");
    }
    const workspaceResolver = new EngagementWorkspaceResolver(
      localGuidedToolConfiguration.workspaceMappings.mappings,
    );
    localGuidedToolAdapter = new DirectProcessLocalToolInvocationAdapter({
      manifest: localGuidedToolConfiguration.manifest,
      workspaceResolver,
      sandboxExecutable: {
        path: localGuidedToolConfiguration.probeSandbox.executablePath,
        expectedSha256: localGuidedToolConfiguration.probeSandbox.expectedSha256,
      },
    });
    localGuidedToolExecution = new ReviewedLocalToolExecutionPort({
      database: application.database,
      executionJourney: "guided",
      manifest: localGuidedToolConfiguration.manifest,
      adapter: localGuidedToolAdapter,
      workspaceResolver,
      outputRecorder: new OperationalTruthLocalToolOutputRecorder(
        application.database,
        localGuidedToolConfiguration.manifest,
      ),
      assertControlPlaneAuthority: (runId) => {
        if (!productionGuidedRuntime) {
          throw new Error("Guided local runtime authority is unavailable");
        }
        return productionGuidedRuntime.assertControlPlaneMutationAuthority(runId);
      },
    });
    if (windowsIdentityRegistry && windowsIdentityAdapter && windowsIdentityActivation) {
      windowsIdentityExecution = new WindowsIdentityGuidedExecutionPort({
        database: application.database,
        pack: windowsIdentityRegistry.pack,
        adapter: windowsIdentityAdapter,
        ...(windowsIdentityCredentialResolver
          ? { credentialResolver: windowsIdentityCredentialResolver }
          : {}),
        assertControlPlaneAuthority: (runId) => {
          if (!productionGuidedRuntime) {
            throw new Error("Guided Windows/identity runtime authority is unavailable");
          }
          return productionGuidedRuntime.assertControlPlaneMutationAuthority(runId);
        },
      });
    }
    if (
      localExploitIntelligencePack
      && localExploitIntelligenceAdapter
      && localExploitIntelligenceActivation?.status === "ready"
    ) {
      localExploitIntelligenceExecution =
        new SearchSploitGuidedExecutionPort({
          database: application.database,
          pack: localExploitIntelligencePack,
          adapter: localExploitIntelligenceAdapter,
          assertControlPlaneAuthority: (runId) => {
            if (!productionGuidedRuntime) {
              throw new Error(
                "Guided local ExploitDB runtime authority is unavailable",
              );
            }
            return productionGuidedRuntime
              .assertControlPlaneMutationAuthority(runId);
          },
        });
      const basePlanner = new LocalGuidedToolPlanner({
        manifest: localGuidedToolConfiguration.manifest,
        logicalWorkspace: defaultWorkspace.logicalRoot,
        readReadyToolIds: () =>
          localGuidedToolActivation?.readyToolIds() ?? new Set(),
      });
      const fallbackPlanner = windowsIdentityRegistry
        ? new WindowsIdentityGuidedPlanner({
            pack: windowsIdentityRegistry.pack,
            logicalWorkspace: defaultWorkspace.logicalRoot,
            readReadyToolIds: () =>
              new Set(windowsIdentityActivation?.readyToolIds ?? []),
            fallback: basePlanner,
          })
        : basePlanner;
      productionGuidedRuntime =
        createProductionGuidedLocalExploitIntelligenceRuntime({
          database: application.database,
          operationalHazardHmacKey: operationalHazardObservationKey,
          brainContext: application.brainContext,
          projectMemoryNodes,
          fallbackPlanner,
          pack: localExploitIntelligencePack,
          readReadyToolIds: () =>
            new Set(
              localExploitIntelligenceActivation?.readyToolIds ?? [],
            ),
          execution: new CompositeGuidedExecutionPort(
            localGuidedToolExecution,
            windowsIdentityExecution,
            localExploitIntelligenceExecution,
          ),
          workerId: `ti-scale-guided-local-exploit-${process.pid}`,
        });
      localExploitIntelligenceMissionRuntimeMounted = true;
    } else if (
      windowsIdentityRegistry
      && windowsIdentityExecution
      && windowsIdentityActivation
    ) {
      productionGuidedRuntime = createProductionGuidedCompositeRuntime({
        database: application.database,
        operationalHazardHmacKey: operationalHazardObservationKey,
        brainContext: application.brainContext,
        projectMemoryNodes,
        fallbackPlanner: new LocalGuidedToolPlanner({
          manifest: localGuidedToolConfiguration.manifest,
          logicalWorkspace: defaultWorkspace.logicalRoot,
          readReadyToolIds: () =>
            localGuidedToolActivation?.readyToolIds() ?? new Set(),
        }),
        windowsIdentityPack: windowsIdentityRegistry.pack,
        windowsIdentityLogicalWorkspace: defaultWorkspace.logicalRoot,
        readReadyWindowsIdentityToolIds: () =>
          new Set(windowsIdentityActivation?.readyToolIds ?? []),
        execution: new CompositeGuidedExecutionPort(
          localGuidedToolExecution,
          windowsIdentityExecution,
        ),
        workerId: `ti-scale-guided-composite-${process.pid}`,
      });
    } else {
      productionGuidedRuntime = createProductionGuidedLocalToolRuntime({
        database: application.database,
        operationalHazardHmacKey: operationalHazardObservationKey,
        brainContext: application.brainContext,
        projectMemoryNodes,
        manifest: localGuidedToolConfiguration.manifest,
        logicalWorkspace: defaultWorkspace.logicalRoot,
        readReadyToolIds: () => localGuidedToolActivation?.readyToolIds() ?? new Set(),
        execution: localGuidedToolExecution,
        workerId: `ti-scale-guided-local-${process.pid}`,
      });
    }
    localGuidedToolActivation = new LocalGuidedToolActivationCoordinator({
      configuration: localGuidedToolConfiguration,
      adapter: localGuidedToolAdapter,
      executionPort: localGuidedToolExecution,
      workspaceResolver,
    });
    registerStartupComponent("runtimes", {
      name: "startup-guided-mission-runtime",
      beginStop: () => productionGuidedRuntime?.beginStop(),
      stop: () => productionGuidedRuntime?.stop(),
    });
    registerStartupComponent("readiness", {
      name: "startup-guided-local-tool-readiness",
      beginStop: () => localGuidedToolActivation?.beginStop(),
      stop: () => localGuidedToolActivation?.stop().then(() => undefined),
    });
    startupPhase = "guided_local_tool_readiness";
    await localGuidedToolActivation.start();
    assertStartupActive();
  } else {
    if (
      localExploitIntelligencePack
      && localExploitIntelligenceAdapter
      && localExploitIntelligenceActivation?.status === "ready"
    ) {
      localExploitIntelligenceExecution =
        new SearchSploitGuidedExecutionPort({
          database: application.database,
          pack: localExploitIntelligencePack,
          adapter: localExploitIntelligenceAdapter,
          assertControlPlaneAuthority: (runId) => {
            if (!productionGuidedRuntime) {
              throw new Error(
                "Guided local ExploitDB runtime authority is unavailable",
              );
            }
            return productionGuidedRuntime
              .assertControlPlaneMutationAuthority(runId);
          },
        });
      productionGuidedRuntime =
        createProductionGuidedLocalExploitIntelligenceRuntime({
          database: application.database,
          operationalHazardHmacKey: operationalHazardObservationKey,
          brainContext: application.brainContext,
          projectMemoryNodes,
          fallbackPlanner: new LocalGuidedManualPlanner(),
          pack: localExploitIntelligencePack,
          readReadyToolIds: () =>
            new Set(
              localExploitIntelligenceActivation?.readyToolIds ?? [],
            ),
          execution: new CompositeGuidedExecutionPort(
            new FailClosedManualExecutionPort(),
            undefined,
            localExploitIntelligenceExecution,
          ),
          workerId: `ti-scale-guided-local-exploit-${process.pid}`,
        });
      localExploitIntelligenceMissionRuntimeMounted = true;
    } else {
      productionGuidedRuntime = createProductionGuidedManualRuntime({
        database: application.database,
        operationalHazardHmacKey: operationalHazardObservationKey,
        brainContext: application.brainContext,
        projectMemoryNodes,
        workerId: `ti-scale-guided-manual-${process.pid}`,
      });
    }
    registerStartupComponent("runtimes", {
      name: "startup-guided-mission-runtime",
      beginStop: () => productionGuidedRuntime?.beginStop(),
      stop: () => productionGuidedRuntime?.stop(),
    });
  }

  const autonomousNvdActor = Object.freeze({
    id: "ti-scale.autonomous-cve-enrichment",
    type: "system" as const,
  });
  const autonomousNvdEnrichment =
    autonomousDnsProductionConfiguration.status === "loaded"
    && autonomousDnsProductionConfiguration.runtime.value.cveApplicability
      ?.nvdEnrichment === "top_candidate"
      ? new MissionScopedNvdCandidateEnrichmentPort(
          new MissionScopedNvdDetailAdapter({
            database: application.database,
            client: publicNvdBoundary.client,
            authorize: (actor, authorization) =>
              actor.type === "system"
              && actor.id === autonomousNvdActor.id
              && authorization.capability === "read_public_nvd_detail"
              && authorization.targetInteraction === false
              && authorization.executionAuthority === "none",
          }),
          autonomousNvdActor,
          publicNvdBoundary.readAttestation,
        )
      : undefined;

  autonomousDnsLifecycle = new AutonomousDnsRuntimeLifecycle({
    database: application.database,
    operationalHazardHmacKey: operationalHazardObservationKey,
    brainContext: application.brainContext,
    ...(autonomousProviderAdvisory
      ? {
          providerAdvisory:
            autonomousProviderAdvisory.providerAdvisory,
          providerPlanningContext:
            autonomousProviderAdvisory.providerPlanningContext,
        }
      : {}),
    projectMemoryNodes,
    scriptSourceStore,
    ...(autonomousNvdEnrichment
      ? { cveNvdEnrichment: autonomousNvdEnrichment }
      : {}),
    exploitOutcomeObserver:
      new CandidateSpecificIndependentExploitOutcomeVerifier({
        database: application.database,
      }),
    ...(vaultMemoryProjector
      ? {
          exploitVaultSync: new ConnectedVaultExploitSyncAdapter(
            application.database,
            vaultMemoryProjector,
          ),
        }
      : {}),
    readBaselineProjection: nonAutonomousRuntimeProjection,
    publishProjection: (projection) => {
      application.synchronizeRuntimeProjection(projection);
      const autonomousReady = projection.readiness.autonomousRuntime?.status === "ready";
      if (!runtimeCapabilityMemoryProjector) {
        if (autonomousReady) {
          throw new Error(
            "Autonomous readiness requires the connected Obsidian capability-memory bridge",
          );
        }
        return;
      }
      const report = runtimeCapabilityMemoryProjector.project(projection);
      if (
        autonomousReady
        && (
          report.status !== "ready"
          || report.eligibleToolIds.length === 0
          || report.eligibleAgentIds.length === 0
          || report.currentNodeIds.length !== report.vaultBackedNodeIds.length
          || report.vault.failures > 0
          || report.vault.attentionRequired > 0
          || report.vault.skippedByPolicy > 0
        )
      ) {
        throw new Error(
          "Autonomous readiness requires current agent/tool capability memory synchronized to an active Obsidian Vault",
        );
      }
    },
    readBaselineToolExecutionPreflight: (toolId) =>
      localGuidedToolActivation?.readToolExecutionPreflight(toolId)
      ?? toolBindingReadiness.runner.readToolExecutionPreflight(toolId),
    productionConfiguration: autonomousDnsProductionConfiguration,
    localToolConfiguration: localGuidedToolConfiguration,
    ...(windowsIdentityRegistry
      && windowsIdentityAdapter
      && localGuidedToolConfiguration.status === "loaded"
      && localGuidedToolConfiguration.workspaceMappings.mappings[0]
      ? {
          windowsIdentityAutonomous: {
            registry: windowsIdentityRegistry,
            adapter: windowsIdentityAdapter,
            logicalWorkspace:
              localGuidedToolConfiguration.workspaceMappings.mappings[0]
                .logicalRoot,
            readActivation: () => windowsIdentityActivation,
          },
        }
      : {}),
    workerId: `ti-scale-autonomous-dns-${process.pid}`,
  });
  registerStartupComponent("runtimes", {
    name: "startup-autonomous-dns-runtime",
    beginStop: () => autonomousDnsLifecycle?.beginStop(),
    stop: () => autonomousDnsLifecycle?.stop(),
  });

  productionRuntimeForRun = (runId: string): MissionRuntimeEngine | undefined => {
    const row = application.database.prepare("SELECT journey FROM runs WHERE id = ?")
      .get(runId) as { readonly journey: "autonomous" | "guided" } | undefined;
    if (row?.journey === "autonomous") return autonomousDnsLifecycle?.runtime();
    return productionGuidedRuntime;
  };

  assertProductionRunMutationAuthority = (runId: string) => {
    const selected = productionRuntimeForRun(runId);
    if (selected) return selected.assertControlPlaneMutationAuthority(runId);
    // The mounted Guided runtime provides a typed journey_unsupported or
    // run_not_found denial when Autonomous has no current executable runtime.
    // Never turn missing Autonomous activation into an undefined authority.
    return productionGuidedRuntime?.assertControlPlaneMutationAuthority(runId);
  };

  const web = express();
  web.disable("x-powered-by");
  web.set("trust proxy", false);
  web.use(securityHeaders);
  web.use(cors(process.env.TI_SCALE_UI_ORIGIN?.trim() || DEFAULT_UI_ORIGIN));
  web.use(v2RequestContext);
  web.use(serviceDrainAdmission.middleware);
  web.use(express.json({ limit: MAX_JSON_BODY, strict: true, type: "application/json" }));
  web.use(v2JsonBodyError);
  mountLocalSessionBoundary(web, sessionAuth, secureCookies);
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

  const resolveActor = () => authenticatedActor();
  const resolveAccess = () => fullLocalAccess();

  web.use(application.router);
  web.use(createOpenRouterConnectionRouter({
    service: openRouterConnectionService,
    resolveActor: () => actorId,
  }));
  // Optional, authenticated and read-only. Candidate media stays outside the
  // static bundle and has no approval/promotion mutation on this boundary.
  web.use(createModelCandidateReviewRouter({
    reviewRoot: process.env.TI_SCALE_MOTION_REVIEW_ROOT?.trim() || undefined,
  }));
  let autonomousControlRuntime: MissionRuntimeEngine | undefined;
  let autonomousControlRouter: ReturnType<typeof createMissionRunControlV2Router> | undefined;
  web.use((request, response, next) => {
    if (testRunControlRuntime || request.method !== "POST") {
      next();
      return;
    }
    const match = /^\/api\/v2\/runs\/([^/]+)\/(?:pause|resume|cancel)$/u.exec(request.path);
    if (!match) {
      next();
      return;
    }
    let runId: string;
    try {
      runId = decodeURIComponent(match[1]!);
    } catch {
      next();
      return;
    }
    const row = application.database.prepare("SELECT journey FROM runs WHERE id = ?")
      .get(runId) as { readonly journey: "autonomous" | "guided" } | undefined;
    if (row?.journey !== "autonomous") {
      next();
      return;
    }
    const runtime = autonomousDnsLifecycle?.runtime();
    if (!runtime) {
      next();
      return;
    }
    if (runtime !== autonomousControlRuntime || !autonomousControlRouter) {
      autonomousControlRuntime = runtime;
      autonomousControlRouter = createMissionRunControlV2Router({
        runtime,
        resolveActor: () => actorId,
      });
    }
    autonomousControlRouter(request, response, next);
  });
  if (testRunControlRuntime) {
    web.use(createGuidedCommanderRouter({
      database: application.database,
      resolveRuntimeBinding: guidedAgentRuntimeResolver.resolve,
      resolveActor: () => actorId,
      secondBrain: application.secondBrain,
      brainContext: application.brainContext,
      mountInterpretResult: false,
      assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
        if (!testAuthorityDatabase) return undefined;
        return assertTestRunMutationAuthority(testAuthorityDatabase, runId);
      },
    }));
    web.use(createLocalGuidedManualInterpreterRouter({
      database: application.database,
      brainContext: application.brainContext,
      resolveActor: () => actorId,
      mountGuidanceRoutes: false,
      assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
        if (!testAuthorityDatabase) return undefined;
        return assertTestRunMutationAuthority(testAuthorityDatabase, runId);
      },
    }));
    web.use(createMissionRunControlV2Router({
      runtime: testRunControlRuntime,
      resolveActor: () => actorId,
    }));
    // The isolated Playwright run-control adapter owns pause/resume/cancel,
    // while the deterministic manual Guided runtime owns exact decision
    // mutations. Mounting both against the same temporary database keeps the
    // browser capability projection truthful without granting tool, provider,
    // target, or production authority. The manual runtime scheduler remains
    // disabled below, so it cannot claim unrelated browser fixtures.
    if (productionGuidedRuntime) {
      web.use(createMissionRuntimeV2Router({
        runtime: productionGuidedRuntime,
        resolveActor: () => actorId,
      }));
    }
  } else if (productionGuidedRuntime) {
    web.use(createGuidedCommanderRouter({
      database: application.database,
      resolveRuntimeBinding: guidedAgentRuntimeResolver.resolve,
      resolveActor: () => actorId,
      secondBrain: application.secondBrain,
      brainContext: application.brainContext,
      // Manual result ingestion remains a separate deterministic truth
      // boundary; a planning model cannot promote raw output to evidence.
      mountInterpretResult: false,
      assertRunMutationLease: ({ runId }: { readonly runId: string }) =>
        productionGuidedRuntime?.assertControlPlaneMutationAuthority(runId),
    }));
    web.use(createLocalGuidedManualInterpreterRouter({
      database: application.database,
      brainContext: application.brainContext,
      resolveActor: () => actorId,
      mountGuidanceRoutes: false,
      assertRunMutationLease: ({ runId }: { readonly runId: string }) =>
        productionGuidedRuntime?.assertControlPlaneMutationAuthority(runId),
    }));
    web.use(createMissionRuntimeV2Router({
      runtime: productionGuidedRuntime,
      resolveActor: () => actorId,
    }));
  }
  web.use(createOperationsRouter({
    database: application.database,
    resolveActor,
    resolveAccess,
    providerRouteIds: [],
    ...(vaultPathPolicy ? { vaultPathPolicy } : {}),
    assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
      if (testRunControlEnabled) {
        if (!testAuthorityDatabase) return undefined;
        return assertTestRunMutationAuthority(testAuthorityDatabase, runId);
      }
      return assertProductionRunMutationAuthority(runId);
    },
    notifyRecoveryContinuation: ({ runId }: { readonly runId: string }) => {
      if (testRunControlEnabled) {
        testRunControlRuntime?.notifyContinuationAvailable(runId, ["resume_recovery_pending"]);
        return;
      }
      productionRuntimeForRun(runId)?.notifyContinuationAvailable(runId, ["resume_recovery_pending"]);
    },
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
    ...(vaultPathPolicy ? { vaultPathPolicy } : {}),
    ...(vaultBridge ? { vaultBridge } : {}),
    ...(vaultWatcher ? {
      onVaultConnectionChanged: () => vaultWatcher.refreshConnections(),
    } : {}),
  }));
  web.use(createAttackKnowledgePromotionRouter({
    database: application.database,
    resolveActor: () => ({ id: actorId, type: "operator" }),
    authorize: (_request, actor) => actor.type === "operator" && actor.id === actorId,
    authorizeEvidence: (_request, actor, evidence) =>
      actor.type === "operator"
      && actor.id === actorId
      && new Set(["public", "internal", "private", "restricted"]).has(evidence.sensitivity),
  }));
  web.use(createOperationalHazardObservationRouter({
    database: application.database,
    hmacKey: operationalHazardObservationKey,
    resolveActor: () => ({ id: actorId, type: "operator" }),
    authorize: (_request, actor, authorization) =>
      actor.type === "operator"
      && actor.id === actorId
      && authorization.missionId.length > 0
      && authorization.runId.length > 0,
  }));
  // This standalone process has planning-only provider advice and a read-only
  // Public NVD MCP dependency, but no Autonomous planner/specialist/tool
  // executor composition. Keep uncovered mutation routes explicit and
  // diagnosable instead of allowing them to fall through as generated 404s.
  web.use(createUnavailableExecutionRouter());
  web.use(v2NotFound);

  mountStaticApplication(web, staticApplicationAdmission);

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

  openRouterRuntime.start();
  publicNvdRuntime.start();
  process.stdout.write(
    `Ti-Scale local tool readiness ${initialToolReadiness.accounting.reported}/${initialToolReadiness.accounting.registered} checked; ${initialToolReadiness.accounting.ready} ready, ${initialToolReadiness.accounting.unavailable} unavailable (no execution authority granted)\n`,
  );
  if (configuredRuntimeManifest.status === "loaded") {
    process.stdout.write(
      `Ti-Scale pinned runtime source manifest ${configuredRuntimeManifest.manifestVersion} `
      + `(${configuredRuntimeManifest.receipt.sourceSha256}); definitions are config-only until exact live attestations promote them\n`,
    );
  }
  if (localGuidedToolConfiguration.status === "loaded") {
    const activation = localGuidedToolActivation?.snapshot();
    const ready = localGuidedToolActivation?.readyToolIds().size ?? 0;
    process.stdout.write(
      `Ti-Scale reviewed Guided local runtime ${activation?.status ?? "unavailable"}; `
      + `${ready}/${localGuidedToolConfiguration.manifest.descriptor.enabledToolCount} exact-step tools activated `
      + `(manifest ${localGuidedToolConfiguration.manifest.descriptor.manifestSha256}; no mission authority granted by readiness)\n`,
    );
  } else {
    process.stdout.write(
      `Ti-Scale reviewed Guided local runtime unconfigured; ${localGuidedToolConfiguration.reason}\n`,
    );
  }
  if (windowsIdentityActivation) {
    process.stdout.write(
      `Ti-Scale reviewed Windows/identity runtime ${windowsIdentityActivation.status}; `
      + `${windowsIdentityActivation.readyToolIds.length}/${windowsIdentityActivation.receipts.length} `
      + "exact Guided bindings ready (startup receipts grant no mission authority)\n",
    );
  } else {
    process.stdout.write(
      "Ti-Scale reviewed Windows/identity runtime disabled; set TI_SCALE_WINDOWS_IDENTITY_ENABLED=true with the pinned local sandbox/workspace configuration to opt in\n",
    );
  }
  if (localExploitIntelligenceActivation) {
    process.stdout.write(
      `Ti-Scale local ExploitDB intelligence runtime ${localExploitIntelligenceActivation.status}; `
      + `${localExploitIntelligenceActivation.readyToolIds.length}/1 exact offline binding ready `
      + `(visible under VulnIntel; durable Guided mission selection ${
        localExploitIntelligenceMissionRuntimeMounted
          ? "mounted"
          : "unavailable"
      })\n`,
    );
  } else {
    process.stdout.write(
      "Ti-Scale local ExploitDB intelligence runtime disabled; set TI_SCALE_LOCAL_EXPLOIT_INTELLIGENCE_ENABLED=true to activate the pinned offline SearchSploit binding\n",
    );
  }
  startupPhase = "runtime_recovery";
  application.start();
  operationalHazardObservationWorker.start();
  vaultWatcher?.start();
  const autonomousDnsStartup = autonomousDnsLifecycle.start();
  if (productionGuidedRuntime && !testRunControlEnabled) {
    await productionGuidedRuntime.start();
    assertStartupActive();
  }
  const autonomousDnsStartupSnapshot = await autonomousDnsStartup;
  assertStartupActive();
  process.stdout.write(
    `Ti-Scale Autonomous Safe Recon runtime ${autonomousDnsStartupSnapshot.status}; `
    + `${autonomousDnsStartupSnapshot.runtimeStarted ? "runtime scheduler mounted" : autonomousDnsStartupSnapshot.reason}\n`,
  );
  // Most browser fixtures need only the fail-closed pause/resume/cancel HTTP
  // adapter. Running its deliberately unavailable planner would claim normal
  // intake and portfolio fixture runs, then rewrite them to `blocked`. The
  // scheduler is therefore a separate test-only opt-in used by the process-
  // boundary recovery fixture, where the real startup recovery pass is the
  // behavior under test. Both switches remain unreachable for normal preview
  // databases because testRunControlRuntimeEnabled() requires the isolated
  // /tmp Playwright data root and an explicit fixture run ID.
  if (testRunControlScheduler) {
    await testRunControlRuntime?.start();
    assertStartupActive();
  }

  let httpCloseStarted = false;
  let httpForceDrainTimer: ReturnType<typeof setTimeout> | undefined;
  let resolveHttpClosed!: () => void;
  let rejectHttpClosed!: (error: Error) => void;
  const httpClosed = new Promise<void>((resolveClosed, rejectClosed) => {
    resolveHttpClosed = resolveClosed;
    rejectHttpClosed = rejectClosed;
  });
  void httpClosed.then(
    () => {
      if (httpForceDrainTimer) clearTimeout(httpForceDrainTimer);
      httpForceDrainTimer = undefined;
    },
    () => {
      if (httpForceDrainTimer) clearTimeout(httpForceDrainTimer);
      httpForceDrainTimer = undefined;
    },
  );

  const closeHttpAdmission = (): void => {
    if (httpCloseStarted) return;
    httpCloseStarted = true;
    serviceDrainAdmission.beginDrain();
    server.close((error) => {
      if (!error || (error as NodeJS.ErrnoException).code === "ERR_SERVER_NOT_RUNNING") {
        resolveHttpClosed();
      } else {
        rejectHttpClosed(error);
      }
    });
    server.closeIdleConnections?.();
    // Active requests receive a bounded opportunity to finish. Long-lived or
    // wedged connections are then closed while enough time remains to stop the
    // application/event stream and close the canonical database deliberately.
    httpForceDrainTimer = setTimeout(() => server.closeAllConnections?.(), HTTP_FORCE_DRAIN_AFTER_MS);
    httpForceDrainTimer.unref?.();
  };

  const runtimeComponents = [
    ...(testRunControlRuntime ? [{
      name: "test-run-control-runtime",
      beginStop: () => testRunControlRuntime.beginStop(),
      stop: () => testRunControlRuntime.stop(),
    }] : []),
    ...(autonomousDnsLifecycle ? [{
      name: "autonomous-dns-runtime",
      beginStop: () => autonomousDnsLifecycle.beginStop(),
      stop: () => autonomousDnsLifecycle.stop(),
    }] : []),
    ...(productionGuidedRuntime ? [{
      name: "guided-mission-runtime",
      beginStop: () => productionGuidedRuntime.beginStop(),
      stop: () => productionGuidedRuntime.stop(),
    }] : []),
  ];
  if (runtimeComponents.length < 1) {
    throw new Error("Ti-Scale shutdown has no mounted runtime component to drain");
  }
  const readinessComponents = [
    ...(researchExecutionBoundary ? [{
      name: "research-readiness",
      beginStop: () => researchExecutionBoundary.beginStop(),
      stop: () => researchExecutionBoundary.stop(),
    }] : []),
    ...(localGuidedToolActivation ? [{
      name: "guided-local-tool-readiness",
      beginStop: () => localGuidedToolActivation.beginStop(),
      stop: () => localGuidedToolActivation.stop().then(() => undefined),
    }] : []),
    ...(windowsIdentityReadinessRunner || windowsIdentityRefreshInFlight ? [{
      name: "windows-identity-readiness",
      beginStop: beginStopWindowsIdentityReadiness,
      stop: stopWindowsIdentityReadiness,
    }] : []),
    ...(localExploitIntelligenceInitialActivation
      || localExploitIntelligenceRefreshInFlight ? [{
        name: "local-exploit-intelligence-readiness",
        beginStop: beginStopLocalExploitIntelligenceReadiness,
        stop: stopLocalExploitIntelligenceReadiness,
      }] : []),
    {
      name: "tool-binding-readiness",
      beginStop: () => toolBindingReadiness.runner.beginStop(),
      stop: () => toolBindingReadiness.runner.stop().then(() => undefined),
    },
    {
      name: "openrouter-readiness",
      beginStop: () => openRouterRuntime.beginStop(),
      stop: () => openRouterRuntime.stop(),
    },
    {
      name: "public-nvd-readiness",
      beginStop: () => publicNvdRuntime.beginStop(),
      stop: () => publicNvdRuntime.stop(),
    },
  ];
  const shutdown = new GracefulShutdownCoordinator({
    // systemd TimeoutStopSec is 30s. Retain six seconds for diagnostics,
    // synchronous lease release in the process exit hook, and service-manager
    // accounting instead of relying on systemd's SIGKILL.
    deadlineMs: GRACEFUL_SHUTDOWN_DEADLINE_MS,
    closeAdmission: closeHttpAdmission,
    forceClose: () => server.closeAllConnections?.(),
    phases: [
      { name: "runtimes", components: runtimeComponents },
      { name: "readiness", components: readinessComponents },
      {
        name: "execution-adapters",
        components: [
          {
            name: "guided-local-tool-result-sink",
            stop: () => localGuidedToolExecution?.close(),
          },
          {
            name: "operational-hazard-worker",
            beginStop: () => operationalHazardObservationWorker.stop(),
            stop: () => operationalHazardObservationWorker.stop(),
          },
        ],
      },
      ...(vaultWatcher ? [{
        name: "vault-sync",
        components: [{
          name: "obsidian-vault-watcher",
          beginStop: () => vaultWatcher.beginStop(),
          stop: () => vaultWatcher.stop(),
        }],
      }] : []),
      {
        name: "transport",
        components: [{ name: "http-server", stop: () => httpClosed }],
      },
      {
        name: "canonical-data",
        components: [{
          name: "command-os-application",
          beginStop: () => application.beginStop(),
          stop: () => application.stop(),
        }],
      },
    ],
    finalizers: [{
      name: "process-writer-lease-heartbeat",
      finalize: () => processLeaseHeartbeat.stop(),
    }, {
      name: "canonical-writer-lease",
      runOnTimeout: false,
      finalize: releaseProcessLease,
    }],
  });

  let signalHandled = false;
  const handleSignal = (signal: "SIGINT" | "SIGTERM"): void => {
    if (signalHandled) return;
    signalHandled = true;
    exitSignal = signal;
    process.stdout.write(`Ti-Scale received ${signal}; draining isolated resources\n`);
    void shutdown.shutdown(signal).then((report) => {
      const exitCode = report.outcome === "completed" && process.exitCode !== 1 ? 0 : 1;
      const summary = report.outcome === "timed_out"
        ? `Ti-Scale shutdown timed out after ${report.durationMs}ms; pending components: ${report.pendingComponentNames.join(", ") || "none"}\n`
        : report.outcome === "failed"
          ? `Ti-Scale shutdown failed after ${report.durationMs}ms; failed components: ${report.failedComponentNames.join(", ") || "none"}\n`
          : `Ti-Scale shutdown completed in ${report.durationMs}ms\n`;
      const stream = exitCode === 0 ? process.stdout : process.stderr;
      process.exitCode = exitCode;
      writeShutdownSummaryAndExit(stream, summary, exitCode);
    }).catch((error: unknown) => {
      process.exitCode = 1;
      writeShutdownSummaryAndExit(
        process.stderr,
        `Ti-Scale shutdown coordinator failed: ${error instanceof Error ? error.name : "UnknownError"}\n`,
        1,
      );
    });
  };
  runtimeSignalHandler = handleSignal;
  assertStartupActive();
  startupPhase = "ready";
  activeHttpHandler = web;
  const guidedRuntimeSummary = localGuidedToolConfiguration.status === "loaded"
    && (localGuidedToolActivation?.readyToolIds().size ?? 0) > 0
    ? "Guided exact-step reviewed local runtime ready; manual fallback retained"
    : "Guided represented-manual runtime ready; target/tool dispatch unavailable";
  const autonomousRuntimeSummary = autonomousDnsStartupSnapshot.status === "ready"
    ? "Autonomous Safe Recon reviewed local-process runtime ready; DNS and exact-IP full-TCP execution active; MCP inventory is advisory only"
    : `Autonomous Safe Recon ${autonomousDnsStartupSnapshot.status}`;
  process.stdout.write(
    `Ti-Scale API ${API_VERSION} operational admission ready on http://${bind}:${listenPort} (${guidedRuntimeSummary}; ${autonomousRuntimeSummary}; mission-scoped public NVD read adapter and readiness monitors enabled)\n`,
  );
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown startup failure";
  process.stderr.write(`Ti-Scale failed to start: ${message}\n`);
  if (process.env.TI_SCALE_DEBUG_STARTUP_STACK === "true" && error instanceof Error && error.stack) {
    process.stderr.write(`${error.stack}\n`);
  }
  process.exitCode = 1;
  fatalMainFailureShutdown?.();
});

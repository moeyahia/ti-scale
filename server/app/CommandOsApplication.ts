import { existsSync } from "node:fs";
import { Router, type Request, type Response } from "express";
import {
  createDatabaseConnection,
  getDatabaseHealth,
  migrateDatabase,
  type SqliteDatabase,
} from "../db";
import { EventRepository } from "../events/EventRepository";
import { createEventStreamRouter } from "../events/EventStreamRouter";
import { EventStreamService } from "../events/EventStreamService";
import type { EventSensitivity } from "../events/types";
import {
  createDatabaseReadinessProvider,
  type ReadinessCheckProvider,
} from "../missions";
import { createCommandOsRouter } from "../routes/commandOsRoutes";
import { RuntimeProjectionService, type RuntimeProjectionInput } from "./RuntimeProjectionService";
import { createApiContractRouter } from "../contracts";
import { attachV2RequestId } from "../contracts/ApiErrorContract";
import type { AssertRunMutationLease } from "../control-plane";
import { createResearchLabRouter, type ResearchRuntimeReadiness } from "../research";
import {
  createOperationalTruthRouter,
  type OperationalTruthAuthorizationRequest,
  type OperationalActor,
} from "../intelligence-v24";
import {
  createRunIntelligenceRouter,
  type RunIntelligenceActor,
  type RunIntelligenceAuthorizationRequest,
} from "../run-intelligence";
import { RuntimeRepository } from "../command-runtime";
import { ActionRepository, CheckpointRepository } from "../orchestration";
import {
  createMissionRuntimeReadRouter,
  type RuntimeReadRunScope,
} from "../routes/MissionRuntimeReadRouter";
import {
  createGuidedMemoryCandidateRouter,
  createGuidedTranscriptReadRouter,
  GuidedCommanderRepository,
  type GuidedTranscriptReadScope,
} from "../guided-commander";
import {
  createPlanChangeRouter,
  type PlanChangeActor,
  type PlanChangeAuthorizationRequest,
} from "../plan-changes";
import {
  createCveApplicabilityRouter,
  type CveIntelligenceAuthorizationRequest,
} from "../cve-intelligence";
import {
  createPageCaptureRouter,
  type PageCaptureAuthorizationRequest,
} from "../page-captures";
import {
  createScriptArtifactRouter,
  type ScriptArtifactActor,
  type ScriptArtifactAuthorizationRequest,
  type ScriptSourceStore,
} from "../script-artifacts";
import { BrainContextService } from "../brain-runtime";
import { MemoryRepository, SecondBrainService } from "../memory";

export interface CommandOsApplicationOptions {
  readonly databasePath: string;
  readonly readinessProviders: (database: SqliteDatabase) => readonly ReadinessCheckProvider[];
  readonly runtimeProjection: () => RuntimeProjectionInput;
  readonly resolveActor: (request: Request) => string;
  readonly resolveEventSensitivity?: (request: Request) => EventSensitivity;
  readonly projectionIntervalMs?: number;
  readonly researchReadiness?: () => ResearchRuntimeReadiness;
  readonly resolveOperationalActor?: (request: Request) => OperationalActor | undefined;
  readonly authorizeOperationalTruth?: (
    request: Request,
    actor: OperationalActor,
    authorization: OperationalTruthAuthorizationRequest,
  ) => boolean;
  readonly resolveRunIntelligenceActor?: (request: Request) => RunIntelligenceActor | undefined;
  readonly authorizeRunIntelligence?: (
    request: Request,
    actor: RunIntelligenceActor,
    authorization: RunIntelligenceAuthorizationRequest,
  ) => boolean;
  /** Server-side runtime authority; never resolve this from caller headers. */
  readonly assertRunMutationLease?: AssertRunMutationLease;
  readonly resolveRuntimeReadActor?: (request: Request) => string | undefined;
  readonly authorizeRuntimeMissionRead?: (
    request: Request,
    actorId: string,
    missionId: string,
  ) => boolean;
  readonly authorizeRuntimeRunRead?: (
    request: Request,
    actorId: string,
    scope: RuntimeReadRunScope,
  ) => boolean;
  readonly resolveGuidedTranscriptActor?: (request: Request) => string | undefined;
  readonly authorizeGuidedTranscriptRead?: (
    request: Request,
    actorId: string,
    scope: GuidedTranscriptReadScope,
  ) => boolean;
  readonly resolvePlanChangeActor?: (request: Request) => PlanChangeActor | undefined;
  readonly authorizePlanChanges?: (
    request: Request,
    actor: PlanChangeActor,
    authorization: PlanChangeAuthorizationRequest,
  ) => boolean;
  readonly resolveCveIntelligenceActor?: (request: Request) => OperationalActor | undefined;
  readonly authorizeCveIntelligence?: (
    request: Request,
    actor: OperationalActor,
    authorization: CveIntelligenceAuthorizationRequest,
  ) => boolean;
  readonly resolvePageCaptureActor?: (request: Request) => OperationalActor | undefined;
  readonly authorizePageCaptures?: (
    request: Request,
    actor: OperationalActor,
    authorization: PageCaptureAuthorizationRequest,
  ) => boolean;
  /** Script routes are absent unless an explicit V2-only source store is injected. */
  readonly scriptSourceStore?: ScriptSourceStore;
  readonly resolveScriptArtifactActor?: (request: Request) => ScriptArtifactActor | undefined;
  readonly authorizeScriptArtifacts?: (
    request: Request,
    actor: ScriptArtifactActor,
    authorization: ScriptArtifactAuthorizationRequest,
  ) => boolean;
}

export interface CommandOsApplication {
  readonly database: SqliteDatabase;
  readonly eventStream: EventStreamService;
  readonly router: Router;
  readonly started: boolean;
  start(): void;
  stop(): Promise<void>;
}

interface ControlPlaneScopeRow {
  readonly control_plane: "legacy" | "ti_scale";
}

interface RunControlPlaneScopeRow extends ControlPlaneScopeRow {
  readonly mission_id: string;
}

/**
 * Imported legacy records remain readable, but no injected authorizer can turn
 * this V2 application into a second writer for a legacy-controlled mission or
 * run. The domain services repeat this check where available; this boundary
 * also protects independently supplied ingestion modules.
 */
function v2OwnsMutableScope(
  database: SqliteDatabase,
  missionId: string,
  runId: string | undefined,
): boolean {
  const mission = database.prepare("SELECT control_plane FROM missions WHERE id = ?")
    .get(missionId) as ControlPlaneScopeRow | undefined;
  if (!mission || mission.control_plane !== "ti_scale") return false;
  if (!runId) return true;
  const run = database.prepare("SELECT mission_id, control_plane FROM runs WHERE id = ?")
    .get(runId) as RunControlPlaneScopeRow | undefined;
  return Boolean(
    run
    && run.mission_id === missionId
    && run.control_plane === "ti_scale",
  );
}

/**
 * Owns the Ti-Scale database, durable event stream, runtime projections, and
 * V2 API lifecycle. It can be mounted inside the legacy server during cutover
 * without making long-running work depend on an HTTP request.
 */
export function createCommandOsApplication(
  options: CommandOsApplicationOptions,
): CommandOsApplication {
  // Existing canonical stores must pass SQLite quick_check before migrations,
  // event streams, projections, or mutation routes are constructed. A new
  // preview store is created normally and becomes integrity-checked on every
  // subsequent process start.
  const databaseExists = existsSync(options.databasePath);
  const database = createDatabaseConnection({
    filename: options.databasePath,
    fileMustExist: databaseExists,
  });
  try {
    migrateDatabase(database);
  } catch (error) {
    database.close();
    throw error;
  }

  const eventStream = new EventStreamService({
    repository: new EventRepository(database),
  });
  const secondBrain = new SecondBrainService(new MemoryRepository(database));
  const brainContext = new BrainContextService({
    database,
    secondBrain,
  });
  const projection = new RuntimeProjectionService({
    database,
    read: options.runtimeProjection,
    intervalMs: options.projectionIntervalMs,
  });
  const router = Router();
  const readinessProviders = [
    createDatabaseReadinessProvider(database),
    ...options.readinessProviders(database),
  ];

  router.use((request, response, next) => {
    attachV2RequestId(request, response);
    next();
  });

  router.use(createApiContractRouter());

  router.use(createCommandOsRouter({
    database,
    readinessProviders,
    resolveActor: options.resolveActor,
    readRuntimeManifests: () => options.runtimeProjection().capabilityManifests
      ?? { riskClasses: [], evidenceKinds: [], capabilities: [], tools: [], mcpServers: [], agents: [], providers: [] },
    ...(options.assertRunMutationLease
      ? { assertRunMutationLease: options.assertRunMutationLease }
      : {}),
  }));
  router.use(createResearchLabRouter({
    database,
    resolveActor: options.resolveActor,
    readRuntimeReadiness: options.researchReadiness,
  }));
  router.use(createOperationalTruthRouter({
    database,
    brainContext,
    resolveActor: options.resolveOperationalActor ?? ((request) => {
      const id = options.resolveActor(request).trim();
      return id ? { id, type: "operator" } : undefined;
    }),
    authorize: options.authorizeOperationalTruth ?? ((_request, actor) => actor.type === "operator"),
    ...(options.assertRunMutationLease
      ? { assertRunMutationLease: options.assertRunMutationLease }
      : {}),
  }));
  router.use(createRunIntelligenceRouter({
    database,
    brainContext,
    resolveActor: options.resolveRunIntelligenceActor ?? ((request) => {
      const id = options.resolveActor(request).trim();
      return id ? { id, type: "operator" } : undefined;
    }),
    authorize: options.authorizeRunIntelligence ?? ((_request, actor) =>
      actor.type === "operator" || actor.type === "admin"),
    ...(options.assertRunMutationLease
      ? { assertRunMutationLease: options.assertRunMutationLease }
      : {}),
  }));
  router.use(createCveApplicabilityRouter({
    database,
    resolveActor: options.resolveCveIntelligenceActor
      ?? options.resolveOperationalActor
      ?? ((request) => {
        const id = options.resolveActor(request).trim();
        return id ? { id, type: "operator" } : undefined;
    }),
    authorize: options.authorizeCveIntelligence ?? ((_request, actor) => actor.type === "operator"),
    ...(options.assertRunMutationLease
      ? { assertRunMutationLease: options.assertRunMutationLease }
      : {}),
  }));
  router.use(createPageCaptureRouter({
    database,
    resolveActor: options.resolvePageCaptureActor
      ?? options.resolveOperationalActor
      ?? ((request) => {
        const id = options.resolveActor(request).trim();
        return id ? { id, type: "operator" } : undefined;
      }),
    authorize: (request, actor, authorization) => {
      const actorAuthorized = options.authorizePageCaptures?.(request, actor, authorization)
        ?? actor.type === "operator";
      if (!actorAuthorized) return false;
      return authorization.capability === "read_page_captures"
        || v2OwnsMutableScope(database, authorization.missionId, authorization.runId);
    },
  }));
  if (options.scriptSourceStore) {
    router.use(createScriptArtifactRouter({
      database,
      sourceStore: options.scriptSourceStore,
      resolveActor: options.resolveScriptArtifactActor ?? ((request) => {
        const id = options.resolveActor(request).trim();
        return id ? { id, type: "operator" } : undefined;
      }),
      authorize: (request, actor, authorization) => {
        const actorAuthorized = options.authorizeScriptArtifacts?.(request, actor, authorization)
          ?? actor.type === "operator";
        if (!actorAuthorized) return false;
        return authorization.capability === "read_script_artifacts"
          || v2OwnsMutableScope(database, authorization.missionId, authorization.runId);
      },
    }));
  }
  router.use(createMissionRuntimeReadRouter({
    repository: new RuntimeRepository(database),
    checkpoints: new CheckpointRepository(database, new ActionRepository(database)),
    resolveActor: options.resolveRuntimeReadActor ?? ((request) => options.resolveActor(request)),
    authorizeMission: options.authorizeRuntimeMissionRead ?? (() => true),
    authorizeRun: options.authorizeRuntimeRunRead ?? (() => true),
  }));
  router.use(createGuidedTranscriptReadRouter({
    repository: new GuidedCommanderRepository(database),
    resolveActor: options.resolveGuidedTranscriptActor
      ?? options.resolveRuntimeReadActor
      ?? ((request) => options.resolveActor(request)),
    authorize: options.authorizeGuidedTranscriptRead ?? ((request, actorId, scope) =>
      (options.authorizeRuntimeMissionRead?.(request, actorId, scope.missionId) ?? true)
      && (options.authorizeRuntimeRunRead?.(request, actorId, scope) ?? true)),
  }));
  router.use(createGuidedMemoryCandidateRouter({
    database,
    secondBrain,
    resolveActor: options.resolveActor,
    ...(options.assertRunMutationLease
      ? { assertRunMutationLease: options.assertRunMutationLease }
      : {}),
  }));
  router.use(createPlanChangeRouter({
    database,
    brainContext,
    resolveActor: options.resolvePlanChangeActor ?? ((request) => {
      const id = options.resolveActor(request).trim();
      return id ? { id, type: "operator" } : undefined;
    }),
    authorize: options.authorizePlanChanges ?? ((_request, actor, authorization) =>
      authorization.capability === "apply_plan_changes"
        ? actor.type === "operator" || actor.type === "admin"
        : actor.type === "operator" || actor.type === "admin" || actor.type === "reviewer"),
    ...(options.assertRunMutationLease
      ? { assertRunMutationLease: options.assertRunMutationLease }
      : {}),
  }));
  router.use(createEventStreamRouter({
    service: eventStream,
    resolveSensitivity: options.resolveEventSensitivity,
  }));
  const readinessHealth = (_request: Request, response: Response) => {
    const health = getDatabaseHealth(database);
    const runtime = options.runtimeProjection().readiness;
    const callableProviders = runtime.providers.filter((provider) =>
      provider.health === "healthy" && provider.authenticated && provider.callable);
    const enforcingProviders = callableProviders.filter((provider) =>
      provider.enforcesAutonomousBoundary);
    const guidedProviders = callableProviders.filter((provider) => provider.supportsGuided);
    const probingProviders = runtime.providers.filter((provider) =>
      provider.circuitState === "probing");
    const providersInitializing = callableProviders.length === 0 && probingProviders.length > 0;
    const mcpReady = runtime.mcp.enabled
      && runtime.mcp.executionMode === "enabled"
      && runtime.mcp.startPermitted
      && runtime.mcp.runnableServers > 0;
    const probingMcpServers = runtime.mcp.probingServers ?? 0;
    const sharedBoundaryReady = runtime.delegationEnforced
      && runtime.noHandsCommanderEnforced
      && runtime.directCommanderToolsDenied
      && runtime.specialistAssignmentRequired
      && runtime.specialistsConfigured > 0;
    const autonomousReady = sharedBoundaryReady
      && runtime.actionBoundaryActive
      && enforcingProviders.length > 0
      && mcpReady;
    const guidedReady = sharedBoundaryReady && guidedProviders.length > 0;
    const dependenciesReady = autonomousReady && guidedReady;
    response.setHeader("Cache-Control", "no-store");
    response.json({
      schemaVersion: "2.4",
      status: health.healthy && eventStream.isStarted && dependenciesReady
        ? "healthy"
        : "degraded",
      database: health,
      eventStream: {
        status: eventStream.isStarted ? "healthy" : "unhealthy",
        subscribers: eventStream.subscriptionCount,
      },
      execution: {
        autonomous: autonomousReady ? "ready" : "unavailable",
        guided: guidedReady ? "ready" : "unavailable",
        actionBoundaryActive: runtime.actionBoundaryActive,
        delegationEnforced: runtime.delegationEnforced,
        noHandsCommanderEnforced: runtime.noHandsCommanderEnforced,
      },
      dependencies: {
        providers: {
          status: callableProviders.length > 0 ? "available" : "unavailable",
          initializing: providersInitializing,
          probing: probingProviders.length,
          reason: providersInitializing
            ? "Live provider attestation is in progress; execution remains unavailable until it succeeds."
            : callableProviders.length > 0
              ? "At least one provider has a fresh live execution attestation."
              : runtime.providers.find((provider) => provider.reason)?.reason
                ?? "No provider has completed a fresh live execution attestation.",
          declared: runtime.providers.length,
          callable: callableProviders.length,
          enforcing: enforcingProviders.length,
          guidedCapable: guidedProviders.length,
        },
        mcp: {
          status: mcpReady ? "available" : "unavailable",
          initializing: !mcpReady && probingMcpServers > 0,
          probingServers: probingMcpServers,
          reason: !mcpReady && probingMcpServers > 0
            ? "Live MCP route attestation is in progress; tool execution remains unavailable until a reviewed route succeeds."
            : mcpReady
              ? "At least one enabled MCP route has a fresh live tools/list attestation."
              : "No enabled MCP route has completed a fresh live tools/list attestation.",
          configuredServers: runtime.mcp.configuredServers,
          runnableServers: runtime.mcp.runnableServers,
          executionMode: runtime.mcp.executionMode,
        },
        specialists: {
          status: runtime.specialistsConfigured > 0 ? "available" : "unavailable",
          configured: runtime.specialistsConfigured,
        },
        secondBrain: runtime.secondBrain,
      },
      checkedAt: new Date().toISOString(),
    });
  };
  // Keep the process-level liveness/readiness contract distinct from the
  // paginated canonical component health API at /api/v2/system/health.
  router.get("/api/v2/system/readiness", readinessHealth);
  router.get("/api/v2/health", readinessHealth);

  let started = false;
  let stopped = false;
  return {
    database,
    eventStream,
    router,
    get started(): boolean {
      return started;
    },
    start(): void {
      if (stopped) throw new Error("Ti-Scale application has already stopped");
      if (started) return;
      eventStream.start();
      try {
        projection.start();
        started = true;
      } catch (error) {
        void eventStream.stop();
        throw error;
      }
    },
    async stop(): Promise<void> {
      if (stopped) return;
      stopped = true;
      started = false;
      projection.stop();
      await eventStream.stop();
      database.close();
    },
  };
}

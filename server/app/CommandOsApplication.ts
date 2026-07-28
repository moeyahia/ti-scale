import { existsSync } from "node:fs";
import { Router, type Request, type Response } from "express";
import {
  assertDatabaseIntegrity,
  checkDatabaseIntegrity,
  createDatabaseConnection,
  getDatabaseHealth,
  migrateDatabase,
  type DatabaseIntegrityChecker,
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
import {
  RuntimeProjectionService,
  type RuntimeProjectionInput,
  type RuntimeProjectionResult,
} from "./RuntimeProjectionService";
import { createApiContractRouter } from "../contracts";
import { attachV2RequestId } from "../contracts/ApiErrorContract";
import type { AssertRunMutationLease } from "../control-plane";
import {
  createResearchLabRouter,
  type ExperimentRunner,
  type HumanResearchPromotionAction,
  type IntegrityAuthority,
  type PrivateResearchHoldoutRegistry,
  type ResearchRuntimeReadiness,
} from "../research";
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
  type PlanChangeAffectedWorkStopReceipt,
  type PlanChangeAuthorizationRequest,
} from "../plan-changes";
import {
  createCveApplicabilityRouter,
  createMissionScopedNvdDetailRouter,
  type CveIntelligenceAuthorizationRequest,
  type MissionScopedNvdDetailAuthorization,
} from "../cve-intelligence";
import {
  PublicNvdToolBoundaryError,
  type PublicNvdMcpToolClient,
} from "../mcp";
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
import {
  canonicalSecondBrainHealth,
  getSecondBrainRuntimeHealth,
} from "./SecondBrainRuntimeHealth";
import type { RuntimeReadinessSnapshot } from "./RuntimeReadiness";
import {
  CapabilitySelfTestRepository,
  CapabilitySelfTestService,
  createCapabilitySelfTestRouter,
  type ToolExecutionPreflightResult,
} from "../system-capabilities";
import {
  createReusableExploitProcedureOnboardingRouter,
} from "../autonomous-runtime/ReusableExploitProcedureOnboardingRouter";
import {
  AutonomousActivationReceiptRepository,
  AutonomousActivationReceiptVerifier,
} from "../autonomous-runtime";
import {
  createModelConfigurationRouter,
  ModelConfigurationRepository,
  ModelConfigurationService,
} from "../model-config";

export interface CommandOsApplicationOptions {
  readonly databasePath: string;
  /** Startup-only database verifier; never invoked by an HTTP handler. */
  readonly databaseIntegrityChecker?: DatabaseIntegrityChecker;
  readonly readinessProviders: (
    database: SqliteDatabase,
    readRuntimeProjection: () => RuntimeProjectionInput,
  ) => readonly ReadinessCheckProvider[];
  readonly runtimeProjection: () => RuntimeProjectionInput;
  /**
   * True only when the standalone process mounts the lease-fenced,
   * provider-independent LocalGuidedCommander routes beside this application.
   * This is a capability attestation, not provider or execution authority.
   */
  readonly localCommanderGuidanceMounted?: boolean;
  /** Optional failure-isolated post-commit projection of canonical Brain nodes. */
  readonly projectMemoryNodes?: (nodeIds: readonly string[]) => void;
  /** Fresh cached results from exact target-free local tool startup checks. */
  readonly readToolExecutionPreflight?: (
    toolId: string,
  ) => ToolExecutionPreflightResult | undefined;
  /** Read-only verifier from the configured Vault sandbox; it must not create paths. */
  readonly resolveExistingVaultPath?: (vaultPath: string) => string;
  readonly resolveActor: (request: Request) => string;
  readonly resolveEventSensitivity?: (request: Request) => EventSensitivity;
  readonly projectionIntervalMs?: number;
  readonly researchReadiness?: () => ResearchRuntimeReadiness;
  /** Local-only HMAC authority; never available to a worker or public model. */
  readonly researchIntegrityAuthority?: IntegrityAuthority;
  /** Hash-pinned operator-owned hidden holdout, retained only in trusted local services. */
  readonly privateResearchHoldout?: PrivateResearchHoldoutRegistry;
  /** Creates the durable local-only Research runner against this exact DB. */
  readonly createResearchExperimentRunner?: (
    database: SqliteDatabase,
  ) => ExperimentRunner;
  readonly resolveResearchPromotionActor?: (
    request: Request,
  ) => {
    readonly id: string;
    readonly type: "operator" | "reviewer" | "admin";
  } | undefined;
  readonly authorizeResearchPromotion?: (
    request: Request,
    actor: {
      readonly id: string;
      readonly type: "operator" | "reviewer" | "admin";
    },
    operation: {
      readonly experimentId: string;
      readonly action: HumanResearchPromotionAction;
    },
  ) => boolean;
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
  /** Trusted runtime port for exact plan-amendment child cleanup. */
  readonly cancelPlanChangeAffectedWork?: (input: {
    readonly runId: string;
    readonly actionIds: readonly string[];
    readonly reason: string;
  }) => Promise<PlanChangeAffectedWorkStopReceipt>;
  readonly resolveCveIntelligenceActor?: (request: Request) => OperationalActor | undefined;
  readonly authorizeCveIntelligence?: (
    request: Request,
    actor: OperationalActor,
    authorization: CveIntelligenceAuthorizationRequest,
  ) => boolean;
  /** Exact public-NVD transport; it has no mission authority on its own. */
  readonly publicNvdDetailClient?: Pick<PublicNvdMcpToolClient, "getCveDetails">;
  readonly resolvePublicNvdDetailActor?: (request: Request) => OperationalActor | undefined;
  readonly authorizePublicNvdDetail?: (
    request: Request,
    actor: OperationalActor,
    authorization: MissionScopedNvdDetailAuthorization,
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

/**
 * Process-level Autonomous readiness must follow the mounted composition's
 * exact transport. A reviewed local-process route is complete without MCP;
 * an MCP-backed route still requires current global MCP readiness.
 */
export function autonomousExecutionHealthReady(runtime: RuntimeReadinessSnapshot): boolean {
  const enforcingProviders = runtime.providers.filter((provider) =>
    provider.health === "healthy"
    && provider.authenticated
    && provider.callable
    && provider.enforcesAutonomousBoundary);
  const mcpReady = runtime.mcp.enabled
    && runtime.mcp.executionMode === "enabled"
    && runtime.mcp.startPermitted
    && runtime.mcp.runnableServers > 0;
  const sharedBoundaryReady = runtime.delegationEnforced
    && runtime.noHandsCommanderEnforced
    && runtime.directCommanderToolsDenied
    && runtime.specialistAssignmentRequired
    && runtime.specialistsConfigured > 0;
  const composition = runtime.autonomousRuntime;
  const transportReady = composition?.components.localProcessExecution === true
    || (composition?.components.mcpExecution === true && mcpReady);
  return composition?.status === "ready"
    && composition.readyActionClassIds.length > 0
    && composition.components.enforcingProvider === true
    && composition.components.resultAwareSpecialistExecution === true
    && sharedBoundaryReady
    && runtime.actionBoundaryActive
    && enforcingProviders.length > 0
    && transportReady;
}

export interface CommandOsApplication {
  readonly database: SqliteDatabase;
  readonly eventStream: EventStreamService;
  /** Canonical user-owned Brain services shared by runtime/provider adapters. */
  readonly secondBrain: SecondBrainService;
  readonly brainContext: BrainContextService;
  /** Scoped preferences plus immutable run/step model assignment pinning. */
  readonly modelConfigurations: ModelConfigurationService;
  /** Canonical immutable aggregate activation-proof store. */
  readonly autonomousActivationReceipts: AutonomousActivationReceiptRepository;
  readonly router: Router;
  readonly started: boolean;
  /**
   * Commits the exact immutable runtime generation used by a lifecycle before
   * that lifecycle advertises public readiness. This prevents intake from
   * joining live health to an older materialized specialist inventory.
   */
  synchronizeRuntimeProjection(input: RuntimeProjectionInput): RuntimeProjectionResult;
  start(): void;
  /** Stop periodic producers immediately while preserving DB access for drain. */
  beginStop(): void;
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
    verifyIntegrity: databaseExists,
    ...(options.databaseIntegrityChecker
      ? { integrityChecker: options.databaseIntegrityChecker }
      : {}),
  });
  try {
    migrateDatabase(database);
    if (!databaseExists) {
      // A new image is attested after its schema is committed. Existing images
      // are checked before any migration work so corruption fails closed.
      assertDatabaseIntegrity(
        database,
        options.databaseIntegrityChecker ?? checkDatabaseIntegrity,
        "startup",
      );
    }
  } catch (error) {
    database.close();
    throw error;
  }

  const auxiliaryConnectionsUseCanonicalDatabase = options.databasePath === ":memory:"
    || options.databasePath.startsWith("file::memory:");
  // Outbox delivery is a low-priority scheduler. It must not share the
  // request connection's five-second SQLite busy wait: a different process
  // can legitimately hold BEGIN IMMEDIATE while WAL reads, authentication,
  // and liveness should remain responsive.
  const { eventStreamDatabase, researchDatabase } = (() => {
    let openedEventStreamDatabase = database;
    try {
      openedEventStreamDatabase = auxiliaryConnectionsUseCanonicalDatabase
        ? database
        : createDatabaseConnection({
            filename: options.databasePath,
            fileMustExist: true,
            verifyIntegrity: false,
            busyTimeoutMs: 0,
          });
      // Research mutations and the local experiment runner use BEGIN IMMEDIATE.
      // Keep their synchronous SQLite busy handling off the canonical HTTP
      // connection so a competing writer becomes a bounded retryable Research
      // response instead of pausing unrelated auth, health, or notification
      // work. This is a second connection to the same canonical WAL-backed
      // file, not a second store; in-memory tests reuse the only connection.
      const openedResearchDatabase = auxiliaryConnectionsUseCanonicalDatabase
        ? database
        : createDatabaseConnection({
            filename: options.databasePath,
            fileMustExist: true,
            verifyIntegrity: false,
            busyTimeoutMs: 0,
          });
      return {
        eventStreamDatabase: openedEventStreamDatabase,
        researchDatabase: openedResearchDatabase,
      };
    } catch (error) {
      if (
        openedEventStreamDatabase !== database
        && openedEventStreamDatabase.open
      ) {
        openedEventStreamDatabase.close();
      }
      if (database.open) database.close();
      throw error;
    }
  })();
  const eventStream = new EventStreamService({
    repository: new EventRepository(eventStreamDatabase),
  });
  const secondBrain = new SecondBrainService(new MemoryRepository(database));
  const brainContext = new BrainContextService({
    database,
    secondBrain,
    ...(options.resolveExistingVaultPath
      ? { resolveExistingVaultPath: options.resolveExistingVaultPath }
      : {}),
    vaultAvailability: () => {
      const health = getSecondBrainRuntimeHealth(database, secondBrain, {
        ...(options.resolveExistingVaultPath
          ? { resolveExistingVaultPath: options.resolveExistingVaultPath }
          : {}),
      }).vaultProjection;
      return health.status === "healthy"
        ? { available: true }
        : {
            available: false,
            code: "active_vault_unavailable",
            explanation: health.reason,
          };
    },
  });
  const withCanonicalMemoryHealth = (input: RuntimeProjectionInput): RuntimeProjectionInput => {
    const secondBrainHealth = getSecondBrainRuntimeHealth(database, secondBrain, {
      ...(options.resolveExistingVaultPath
        ? { resolveExistingVaultPath: options.resolveExistingVaultPath }
        : {}),
    });
    return {
      ...input,
      readiness: {
        ...input.readiness,
        // Mission readiness follows the canonical SQLite/policy/FTS path.
        // Optional Obsidian projection health is exposed separately and may
        // never block retained context that remains locally available.
        secondBrain: canonicalSecondBrainHealth(secondBrainHealth),
      },
    };
  };
  const readRuntimeProjection = (): RuntimeProjectionInput =>
    withCanonicalMemoryHealth(options.runtimeProjection());
  const modelConfigurations = new ModelConfigurationService(
    new ModelConfigurationRepository(database),
    {
      readRuntimeManifests: () => readRuntimeProjection().capabilityManifests
        ?? {
          riskClasses: [],
          evidenceKinds: [],
          capabilities: [],
          tools: [],
          mcpServers: [],
          agents: [],
          providers: [],
        },
    },
  );
  const autonomousActivationReceipts =
    new AutonomousActivationReceiptRepository(database);
  const autonomousActivationReceiptVerifier =
    new AutonomousActivationReceiptVerifier(database);
  const projection = new RuntimeProjectionService({
    database,
    read: readRuntimeProjection,
    intervalMs: options.projectionIntervalMs,
  });
  const capabilitySelfTests = new CapabilitySelfTestService({
    repository: new CapabilitySelfTestRepository({
      database,
      eventStream,
      secondBrain,
      ...(options.resolveExistingVaultPath
        ? { resolveExistingVaultPath: options.resolveExistingVaultPath }
        : {}),
    }),
    readRuntimeProjection,
    ...(options.readToolExecutionPreflight
      ? { readToolExecutionPreflight: options.readToolExecutionPreflight }
      : {}),
  });
  let researchExperimentRunner: ExperimentRunner | undefined;
  try {
    researchExperimentRunner =
      options.createResearchExperimentRunner?.(researchDatabase);
  } catch (error) {
    if (
      researchDatabase !== database
      && researchDatabase.open
    ) {
      researchDatabase.close();
    }
    if (
      eventStreamDatabase !== database
      && eventStreamDatabase.open
    ) {
      eventStreamDatabase.close();
    }
    if (database.open) database.close();
    throw error;
  }
  // Captured only after the startup integrity attestation and migrations have
  // completed. Process liveness must never issue SQL, probe dependencies, or
  // invoke SQLite quick_check on the request path.
  const startupDatabaseHealth = Object.freeze(getDatabaseHealth(database));
  let started = false;
  let stopped = false;
  const router = Router();
  const readinessProviders = [
    createDatabaseReadinessProvider(database),
    ...options.readinessProviders(database, readRuntimeProjection),
  ];

  router.use((request, response, next) => {
    attachV2RequestId(request, response);
    next();
  });

  router.use(createApiContractRouter());

  router.use(createModelConfigurationRouter({
    database,
    service: modelConfigurations,
    readRuntimeManifests: () => readRuntimeProjection().capabilityManifests
      ?? {
        riskClasses: [],
        evidenceKinds: [],
        capabilities: [],
        tools: [],
        mcpServers: [],
        agents: [],
        providers: [],
      },
    resolveActor: options.resolveActor,
  }));

  router.use(createCapabilitySelfTestRouter({
    service: capabilitySelfTests,
    resolveActor: options.resolveActor,
  }));

  router.use(createCommandOsRouter({
    database,
    readinessProviders,
    resolveActor: options.resolveActor,
    brainContext,
    modelConfigurations,
    readRuntimeManifests: () => readRuntimeProjection().capabilityManifests
      ?? { riskClasses: [], evidenceKinds: [], capabilities: [], tools: [], mcpServers: [], agents: [], providers: [] },
    ...(options.projectMemoryNodes ? { projectMemoryNodes: options.projectMemoryNodes } : {}),
    ...(options.assertRunMutationLease
      ? { assertRunMutationLease: options.assertRunMutationLease }
      : {}),
  }));
  router.use(createResearchLabRouter({
    database: researchDatabase,
    resolveActor: options.resolveResearchPromotionActor ?? ((request) => {
      const id = options.resolveActor(request).trim();
      return id ? { id, type: "operator" as const } : undefined;
    }),
    authorizePromotion: options.authorizeResearchPromotion
      ?? ((_request, actor) =>
        actor.type === "operator"
        || actor.type === "reviewer"
        || actor.type === "admin"),
    readRuntimeReadiness: options.researchReadiness,
    ...(options.researchIntegrityAuthority
      ? { integrityAuthority: options.researchIntegrityAuthority }
      : {}),
    ...(options.privateResearchHoldout
      ? { privateHoldout: options.privateResearchHoldout }
      : {}),
    ...(researchExperimentRunner ? { experimentRunner: researchExperimentRunner } : {}),
    authorizeExecution: (_request, actor) =>
      actor.type === "operator" || actor.type === "admin",
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
  router.use(createMissionScopedNvdDetailRouter({
    database,
    client: options.publicNvdDetailClient ?? {
      async getCveDetails() {
        throw new PublicNvdToolBoundaryError(
          "NOT_ATTESTED",
          "The public NVD mission-read dependency is not configured",
          true,
        );
      },
    },
    resolveActor: options.resolvePublicNvdDetailActor
      ?? options.resolveCveIntelligenceActor
      ?? options.resolveOperationalActor
      ?? ((request) => {
        const id = options.resolveActor(request).trim();
        return id ? { id, type: "operator" } : undefined;
    }),
    authorize: options.authorizePublicNvdDetail
      ?? ((_request, actor) => actor.type === "operator"),
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
    if (options.projectMemoryNodes) {
      router.use(createReusableExploitProcedureOnboardingRouter({
        database,
        sourceStore: options.scriptSourceStore,
        projectMemoryNodes: options.projectMemoryNodes,
        resolveActor: options.resolveScriptArtifactActor ?? ((request) => {
          const id = options.resolveActor(request).trim();
          return id ? { id, type: "operator" } : undefined;
        }),
        authorize: (request, actor, authorization) => {
          if (actor.type !== "operator") return false;
          const artifactAuthorized = options.authorizeScriptArtifacts?.(
            request,
            actor,
            {
              missionId: authorization.missionId,
              runId: authorization.runId,
              scriptArtifactId: authorization.scriptArtifactId,
              capability: "manage_script_artifacts",
            },
          ) ?? true;
          return artifactAuthorized && v2OwnsMutableScope(
            database,
            authorization.missionId,
            authorization.runId,
          );
        },
      }));
    }
  }
  router.use(createMissionRuntimeReadRouter({
    repository: new RuntimeRepository(database),
    checkpoints: new CheckpointRepository(database, new ActionRepository(database)),
    autonomousActivationReceipts,
    autonomousActivationReceiptVerifier,
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
    ...(options.cancelPlanChangeAffectedWork
      ? { cancelAffectedWork: options.cancelPlanChangeAffectedWork }
      : {}),
  }));
  router.use(createEventStreamRouter({
    service: eventStream,
    resolveSensitivity: options.resolveEventSensitivity,
  }));
  const readinessHealth = (_request: Request, response: Response) => {
    const health = getDatabaseHealth(database);
    const runtimeInput = readRuntimeProjection();
    const runtime = runtimeInput.readiness;
    const secondBrainHealth = getSecondBrainRuntimeHealth(database, secondBrain, {
      ...(options.resolveExistingVaultPath
        ? { resolveExistingVaultPath: options.resolveExistingVaultPath }
        : {}),
    });
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
    const publicNvd = runtime.publicNvd ?? {
      status: "unavailable" as const,
      credentialMounted: false,
      attested: false,
      reason: "The read-only public NVD sidecar is not configured in this process.",
    };
    const declaredSpecialists = runtimeInput.capabilityManifests?.agents.length
      ?? runtimeInput.agents.filter((agent) => agent.configuration.executionMode !== "manual_only").length;
    const guidedManualReady = runtime.guidedManualPlanning?.status === "ready"
      && runtime.guidedManualPlanning.executionMode === "manual_only"
      && runtime.guidedManualPlanning.targetInteraction === "operator_only"
      && runtime.guidedManualPlanning.providerContact === false
      && runtime.guidedManualPlanning.toolDispatch === false;
    const guidedLocalToolReady = runtime.guidedLocalToolExecution?.status === "ready"
      && runtime.guidedLocalToolExecution.executionBinding === "reviewed_local_process"
      && runtime.guidedLocalToolExecution.readyToolIds.length > 0
      && runtime.guidedLocalToolExecution.exactDecisionRequired === true
      && runtime.guidedLocalToolExecution.providerContact === false
      && runtime.guidedLocalToolExecution.mcpTransport === false;
    const sharedBoundaryReady = runtime.delegationEnforced
      && runtime.noHandsCommanderEnforced
      && runtime.directCommanderToolsDenied
      && runtime.specialistAssignmentRequired
      && runtime.specialistsConfigured > 0;
    const autonomousReady = autonomousExecutionHealthReady(runtime);
    const guidedReady = guidedLocalToolReady || (sharedBoundaryReady && guidedProviders.length > 0);
    const guidedToolReady = guidedLocalToolReady || (sharedBoundaryReady && mcpReady);
    const localCommanderGuidanceReady = options.localCommanderGuidanceMounted === true
      && (guidedLocalToolReady || guidedManualReady);
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
        guided: guidedReady ? "ready" : guidedManualReady ? "manual_only" : "unavailable",
        guidedToolExecution: guidedToolReady ? "ready" : "unavailable",
        localCommanderGuidance: localCommanderGuidanceReady ? "ready" : "unavailable",
        actionBoundaryActive: runtime.actionBoundaryActive,
        delegationEnforced: runtime.delegationEnforced,
        noHandsCommanderEnforced: runtime.noHandsCommanderEnforced,
      },
      dependencies: {
        autonomousRuntime: runtime.autonomousRuntime ?? {
          schemaVersion: "ti-scale.autonomous-runtime-composition.v1",
          status: "blocked",
          readyActionClassIds: [],
          components: {
            plannerAdapter: false,
            outcomeEvaluator: false,
            resultAwareSpecialistExecution: false,
            enforcingProvider: false,
            durableActionBoundary: false,
            specialistFleet: false,
            mcpExecution: false,
            localProcessExecution: false,
            exactRuntimeManifest: false,
          },
          blockers: [{
            code: "autonomous_composition_report_missing",
            component: "policy",
            impact: "The runtime projection did not include an exact Autonomous composition proof.",
            remediation: "Mount and inspect all reviewed Autonomous adapters before advertising execution readiness.",
          }],
        },
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
          configured: runtime.providers.filter((provider) => provider.configured !== false).length,
          callable: callableProviders.length,
          enforcing: enforcingProviders.length,
          guidedCapable: guidedProviders.length,
          routes: runtime.providers.map((provider) => ({
            id: provider.id,
            status: provider.health,
            configured: provider.configured ?? true,
            executionBoundary: provider.executionBoundary ?? "public_provider",
            authenticated: provider.authenticated,
            callable: provider.callable,
            supportsGuided: provider.supportsGuided,
            enforcesAutonomousBoundary: provider.enforcesAutonomousBoundary,
            reportsExactTokenUsage: provider.reportsExactTokenUsage,
            reportsExactCostUsage: provider.reportsExactCostUsage,
            requestedModel: provider.requestedModel ?? null,
            returnedModel: provider.returnedModel ?? null,
            modelConfigurationHash: provider.modelConfigurationHash ?? null,
            completionProbeReceiptId: provider.completionProbeReceiptId ?? null,
            attestedAt: provider.attestedAt ?? null,
            expiresAt: provider.expiresAt ?? null,
            reason: provider.reason ?? null,
          })),
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
        publicNvd: {
          status: publicNvd.status,
          initializing: publicNvd.status === "probing",
          credentialMounted: publicNvd.credentialMounted,
          attested: publicNvd.attested,
          executionAuthorized: false,
          reason: publicNvd.reason,
          lastCheckedAt: publicNvd.lastCheckedAt ?? null,
          attestedAt: publicNvd.attestedAt ?? null,
          expiresAt: publicNvd.expiresAt ?? null,
        },
        guidedManualPlanner: {
          status: guidedManualReady ? "ready" : "unavailable",
          plannerId: runtime.guidedManualPlanning?.plannerId ?? null,
          executionMode: runtime.guidedManualPlanning?.executionMode ?? null,
          targetInteraction: runtime.guidedManualPlanning?.targetInteraction ?? null,
          providerContact: false,
          toolDispatch: false,
          reason: runtime.guidedManualPlanning?.reason
            ?? "No local represented-manual Guided planner is configured.",
        },
        guidedLocalToolExecution: {
          status: guidedLocalToolReady ? "ready" : "unavailable",
          specialistId: runtime.guidedLocalToolExecution?.specialistId ?? null,
          executionBinding: runtime.guidedLocalToolExecution?.executionBinding ?? null,
          readyToolIds: runtime.guidedLocalToolExecution?.readyToolIds ?? [],
          exactDecisionRequired: runtime.guidedLocalToolExecution?.exactDecisionRequired ?? true,
          targetInteraction: runtime.guidedLocalToolExecution?.targetInteraction ?? null,
          providerContact: false,
          mcpTransport: false,
          checkedAt: runtime.guidedLocalToolExecution?.checkedAt ?? null,
          expiresAt: runtime.guidedLocalToolExecution?.expiresAt ?? null,
          reason: runtime.guidedLocalToolExecution?.reason
            ?? "No reviewed direct local specialist execution receipt is current.",
        },
        specialists: {
          status: guidedLocalToolReady || runtime.specialistsConfigured > 0 ? "available" : "unavailable",
          declared: declaredSpecialists,
          configured: runtime.specialistsConfigured + (guidedLocalToolReady ? 1 : 0),
          reason: guidedLocalToolReady
            ? "One reviewed local specialist has current direct-process execution receipts. It is not counted as an MCP or provider-backed specialist."
            : runtime.specialistsConfigured > 0
            ? `${runtime.specialistsConfigured} specialist execution route${runtime.specialistsConfigured === 1 ? " has" : "s have"} a fresh provider and MCP attestation.`
            : declaredSpecialists > 0
              ? "Specialist manifests are declared, but none has both a fresh callable provider route and a live-attested MCP execution binding."
              : "No specialist execution adapter is mounted in this Ti-Scale process.",
        },
        secondBrain: {
          // The system endpoint reports aggregate Brain + optional projection
          // health; mission preflight consumes canonical readiness above.
          status: secondBrainHealth.health,
          databaseHealthy: secondBrainHealth.databaseHealthy,
          canonicalStoreAvailable: secondBrainHealth.canonicalStoreAvailable,
          lexicalIndexAvailable: secondBrainHealth.lexicalIndexAvailable,
          lexicalIndexSynchronized: secondBrainHealth.lexicalIndexSynchronized,
          vaultProjection: secondBrainHealth.vaultProjection,
          reason: secondBrainHealth.reason,
        },
      },
      checkedAt: new Date().toISOString(),
    });
  };
  const livenessHealth = (_request: Request, response: Response) => {
    const processLive = started
      && !stopped
      && database.open
      && eventStream.isStarted
      && startupDatabaseHealth.healthy;
    response.setHeader("Cache-Control", "no-store");
    response.json({
      schemaVersion: "2.4",
      status: processLive ? "healthy" : "degraded",
      service: "ti-scale",
      database: startupDatabaseHealth,
      eventStream: {
        status: eventStream.isStarted ? "healthy" : "unhealthy",
        subscribers: eventStream.subscriptionCount,
      },
      checkedAt: new Date().toISOString(),
    });
  };
  // Liveness is constant-time and process-local. Readiness remains the rich,
  // fail-closed dependency projection; neither path performs a full database
  // scan because both consume the connection's startup attestation.
  router.get("/api/v2/system/readiness", readinessHealth);
  router.get("/api/v2/health", livenessHealth);

  return {
    database,
    eventStream,
    secondBrain,
    brainContext,
    modelConfigurations,
    autonomousActivationReceipts,
    router,
    get started(): boolean {
      return started;
    },
    synchronizeRuntimeProjection(input): RuntimeProjectionResult {
      if (stopped) throw new Error("Ti-Scale application has already stopped");
      return projection.projectNow(withCanonicalMemoryHealth(input));
    },
    start(): void {
      if (stopped) throw new Error("Ti-Scale application has already stopped");
      if (started) return;
      eventStream.start();
      try {
        researchExperimentRunner?.start();
        projection.start();
        started = true;
      } catch (error) {
        void eventStream.stop();
        throw error;
      }
    },
    beginStop(): void {
      started = false;
      researchExperimentRunner?.beginStop();
      projection.stop();
    },
    async stop(): Promise<void> {
      if (stopped) return;
      stopped = true;
      this.beginStop();
      await researchExperimentRunner?.stop();
      await eventStream.stop();
      if (
        !auxiliaryConnectionsUseCanonicalDatabase
        && researchDatabase.open
      ) {
        researchDatabase.close();
      }
      if (
        !auxiliaryConnectionsUseCanonicalDatabase
        && eventStreamDatabase.open
      ) {
        eventStreamDatabase.close();
      }
      database.close();
    },
  };
}

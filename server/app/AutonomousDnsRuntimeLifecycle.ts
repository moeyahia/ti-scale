import { isAbsolute, relative, sep } from "node:path";
import type { BrainContextService } from "../brain-runtime";
import type {
  MissionScopedNvdCandidateEnrichmentPort,
} from "../cve-intelligence";
import type {
  AutonomousProviderPlanningContextPort,
  MissionRuntimeEngine,
  MissionRuntimeOptions,
} from "../command-runtime";
import type { ProviderAdvisoryRuntimePort } from "../autonomous-planning";
import type { SqliteDatabase } from "../db";
import {
  AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
  AUTONOMOUS_DNS_LOCAL_PROCESS_EXECUTION_CONTRACT,
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  AUTONOMOUS_HTTP_METADATA_TOOL_ID,
  AUTONOMOUS_WHATWEB_TOOL_ID,
  AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID,
  AUTONOMOUS_GENERAL_SAFE_RECON_EXECUTION_CONTRACT,
  AUTONOMOUS_LOCAL_SAFE_RECON_EXECUTION_CONTRACT,
  AutonomousGeneralSafeReconExecutionFactory,
  AutonomousExploitValidationExecutionFactory,
  AutonomousPostReconExploitExpansionService,
  AutonomousReusableExploitCandidateMaterializer,
  CandidateLinuxPostExploitPlanExtension,
  CurrentRunCandidateLinuxPostExploitSpecRegistrar,
  CandidateLinuxTransportBindingRegistry,
  CanonicalAutonomousExploitValidationPlanningGate,
  CanonicalIndependentExploitOutcomeVerifier,
  LocalReusableExploitSourceValidator,
  AutonomousDnsLocalProcessExecutionFactory,
  AutonomousLocalSafeReconExecutionFactory,
  LocalAutonomousContractPlanner,
  LocalVerifiedEvidenceOutcomeEvaluator,
  autonomousEndpointDiscoveryEnabled,
  type AutonomousExploitOutcomeObserverCompositionPort,
  type AutonomousExploitOutcomeVerifierPort,
  type AutonomousExploitOutcomeVerifierReadinessPort,
  type AutonomousCurrentEvidenceCandidateGenerationPort,
  type AutonomousReusableExploitCandidateMaterializerPort,
  type AutonomousReusableExploitVaultSyncPort,
} from "../autonomous-runtime";
import {
  composeExactTargetExploitSandbox,
  type ExactTargetSandboxAttestation,
} from "../exploit-sandbox";
import {
  DirectProcessLocalToolInvocationAdapter,
  type LocalProcessToolResultSink,
} from "../local-tools";
import {
  EngagementWorkspaceResolver,
  ReviewedWorkspaceProvisioner,
  type ToolExecutionPreflightResult,
} from "../system-capabilities";
import type { ProductionLocalGuidedToolConfiguration } from "./LocalGuidedToolConfiguration";
import {
  ScriptArtifactService,
  type ScriptSourceStore,
} from "../script-artifacts";
import {
  LocalGuidedToolActivationCoordinator,
  type LocalGuidedToolActivationSnapshot,
} from "./LocalGuidedToolActivationCoordinator";
import {
  attestAutonomousDnsSpecialistHeartbeat,
  attestLocalDeterministicAutonomousDnsProvider,
  composeAutonomousDnsActivation,
  createConfiguredAutonomousPlanningPolicy,
} from "./AutonomousDnsActivationCoordinator";
import {
  createProductionAutonomousRuntime,
  inspectAutonomousRuntimeComposition,
  type AutonomousRuntimeCompositionReadiness,
} from "./AutonomousRuntimeComposition";
import type { AutonomousDnsProductionConfiguration } from "./AutonomousDnsProductionConfiguration";
import type { RuntimeProjectionInput } from "./RuntimeProjectionService";

export const AUTONOMOUS_DNS_RUNTIME_LIFECYCLE_SCHEMA_VERSION =
  "ti-scale.autonomous-dns-runtime-lifecycle.v1" as const;

export interface AutonomousDnsRuntimeLifecycleBlocker {
  readonly code: string;
  readonly reason: string;
  readonly remediation: string;
}

export interface AutonomousDnsRuntimeLifecycleSnapshot {
  readonly schemaVersion: typeof AUTONOMOUS_DNS_RUNTIME_LIFECYCLE_SCHEMA_VERSION;
  readonly status: "unconfigured" | "blocked" | "ready" | "stopped";
  readonly checkedAt: string;
  readonly reason: string;
  readonly projection: RuntimeProjectionInput;
  readonly composition: AutonomousRuntimeCompositionReadiness;
  readonly blockers: readonly AutonomousDnsRuntimeLifecycleBlocker[];
  readonly runtimeMounted: boolean;
  readonly runtimeStarted: boolean;
  readonly localActivationStatus: "unconfigured" | LocalGuidedToolActivationSnapshot["status"];
  readonly mcpAttestationStatus: "not_required";
  readonly mcpRejectionCode: string | null;
}

interface TimerEnvironment {
  set(callback: () => void, delayMs: number): unknown;
  clear(timer: unknown): void;
}

function defaultTimers(): TimerEnvironment {
  return {
    set(callback, delayMs) {
      const timer = setTimeout(callback, delayMs);
      timer.unref?.();
      return timer;
    },
    clear(timer) {
      clearTimeout(timer as ReturnType<typeof setTimeout>);
    },
  };
}

function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) freeze(child);
  }
  return value;
}

function lifecycleBlocker(code: string, reason: string, remediation: string): AutonomousDnsRuntimeLifecycleBlocker {
  return Object.freeze({ code, reason, remediation });
}

function workspaceMappingContains(logicalRoot: string, requested: string): boolean {
  if (!isAbsolute(logicalRoot) || !isAbsolute(requested)) return false;
  const path = relative(logicalRoot, requested);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

function baselineWithComposition(input: RuntimeProjectionInput, now: Date): Readonly<{
  projection: RuntimeProjectionInput;
  composition: AutonomousRuntimeCompositionReadiness;
}> {
  const composition = inspectAutonomousRuntimeComposition({ projection: input, now });
  return Object.freeze({
    projection: Object.freeze({
      ...input,
      readiness: Object.freeze({ ...input.readiness, autonomousRuntime: composition }),
    }),
    composition,
  });
}

function guidedActivationIsCurrent(projection: RuntimeProjectionInput, now: Date): boolean {
  const guided = projection.readiness.guidedLocalToolExecution;
  if (guided?.status !== "ready") return true;
  if (!guided.expiresAt) return false;
  const expiresAt = Date.parse(guided.expiresAt);
  return Number.isFinite(expiresAt)
    && new Date(expiresAt).toISOString() === guided.expiresAt
    && expiresAt > now.getTime();
}

export interface AutonomousDnsRuntimeLifecycleOptions {
  readonly database: SqliteDatabase;
  readonly operationalHazardHmacKey?: string | Buffer;
  readonly brainContext?: BrainContextService;
  /**
   * Optional advisor-only planning route. It must be mounted with the narrow
   * provider-safe Brain adapter below; neither port has execution authority.
   */
  readonly providerAdvisory?: ProviderAdvisoryRuntimePort;
  readonly providerPlanningContext?: AutonomousProviderPlanningContextPort;
  /** Optional exact-CVE NVD binding; required only by a runtime that explicitly enables it. */
  readonly cveNvdEnrichment?: MissionScopedNvdCandidateEnrichmentPort;
  readonly projectMemoryNodes?: MissionRuntimeOptions["projectMemoryNodes"];
  /** Canonical content-addressed ScriptArtifact source store. */
  readonly scriptSourceStore?: ScriptSourceStore;
  /** Active connected-Vault projection for the exact reusable candidate graph. */
  readonly exploitVaultSync?: AutonomousReusableExploitVaultSyncPort;
  /**
   * Optional current-evidence candidate source. This port may only assemble a
   * fixed, product-reviewed local-lab template after the canonical
   * materializer has joined the exact current run, target, version evidence,
   * CVE, signed contract, Brain context and active Vault.
   *
   * It grants no execution authority and is intentionally absent unless a
   * deployment or disposable integration fixture supplies an explicit
   * reviewed implementation.
   */
  readonly currentEvidenceCandidateGenerator?:
    AutonomousCurrentEvidenceCandidateGenerationPort;
  /**
   * Candidate-specific independent target-impact observer. Production defaults
   * to the canonical fail-closed verifier, which deliberately advertises
   * exploit validation as unavailable until a real observer is mounted.
   */
  readonly exploitOutcomeObserver?:
    & AutonomousExploitOutcomeObserverCompositionPort
    & AutonomousExploitOutcomeVerifierPort
    & AutonomousExploitOutcomeVerifierReadinessPort;
  readonly readBaselineProjection: () => RuntimeProjectionInput;
  /**
   * Synchronously materializes one immutable lifecycle generation into the
   * canonical intake/read model. Production wires this to the application
   * projection service; readiness is not published until it succeeds.
   */
  readonly publishProjection?: (projection: RuntimeProjectionInput) => void;
  /** Executable receipt paired with the current baseline projection wave. */
  readonly readBaselineToolExecutionPreflight?: (
    toolId: string,
  ) => ToolExecutionPreflightResult | undefined;
  readonly productionConfiguration: AutonomousDnsProductionConfiguration;
  readonly localToolConfiguration: ProductionLocalGuidedToolConfiguration;
  readonly workerId?: string;
  readonly now?: () => Date;
  readonly timers?: TimerEnvironment;
}

/**
 * Production lifecycle for the one reviewed Autonomous DNS slice.
 *
 * Configuration files grant no execution. Each refresh obtains a target-free
 * local executable/sandbox receipt, a content-free local provider receipt, an
 * actual worker/adapter heartbeat. Optional MCP inventory never grants local
 * execution and is not an activation dependency. A missing, stale, mismatched,
 * or unreachable execution input cancels and unmounts the local runtime before
 * another plan or dispatch can use it.
 */
export class AutonomousDnsRuntimeLifecycle {
  private readonly now: () => Date;
  private readonly timers: TimerEnvironment;
  private runtimeValue?: MissionRuntimeEngine;
  /** Candidate visible only to the runtime being started, never public HTTP. */
  private runtimeStartupProjection?: RuntimeProjectionInput;
  private executionFactory?: AutonomousDnsLocalProcessExecutionFactory
    | AutonomousLocalSafeReconExecutionFactory
    | AutonomousGeneralSafeReconExecutionFactory
    | AutonomousExploitValidationExecutionFactory;
  private activation?: LocalGuidedToolActivationCoordinator;
  private projectedPreflights = new Map<string, ToolExecutionPreflightResult>();
  private localProcess?: DirectProcessLocalToolInvocationAdapter;
  private workspaceResolver?: EngagementWorkspaceResolver;
  private candidateLinuxTransport?:
    CandidateLinuxTransportBindingRegistry;
  private readinessSinkUnbind?: () => void;
  private resultSinkBound = false;
  private timer?: unknown;
  private activeRefresh?: Promise<AutonomousDnsRuntimeLifecycleSnapshot>;
  private activeRefreshController?: AbortController;
  private started = false;
  private stopped = false;
  private snapshotValue: AutonomousDnsRuntimeLifecycleSnapshot;

  constructor(private readonly options: AutonomousDnsRuntimeLifecycleOptions) {
    this.now = options.now ?? (() => new Date());
    this.timers = options.timers ?? defaultTimers();
    this.snapshotValue = this.initialSnapshot();
  }

  private initialSnapshot(): AutonomousDnsRuntimeLifecycleSnapshot {
    const now = this.now();
    const baseline = baselineWithComposition(this.options.readBaselineProjection(), now);
    const configured = this.options.productionConfiguration.status === "loaded";
    const localConfigured = this.options.localToolConfiguration.status === "loaded";
    const reason = !configured
      ? this.options.productionConfiguration.reason
      : !localConfigured
        ? this.options.localToolConfiguration.reason
        : "Autonomous DNS has not completed its first live attestation wave.";
    const code = !configured
      ? "autonomous_dns_unconfigured"
      : !localConfigured
        ? "local_tool_runtime_unconfigured"
        : "autonomous_dns_activation_pending";
    return freeze({
      schemaVersion: AUTONOMOUS_DNS_RUNTIME_LIFECYCLE_SCHEMA_VERSION,
      status: configured && localConfigured ? "blocked" : "unconfigured",
      checkedAt: now.toISOString(),
      reason,
      projection: baseline.projection,
      composition: baseline.composition,
      blockers: [lifecycleBlocker(
        code,
        reason,
        configured
          ? "Configure the exact reviewed local tool boundary and complete every current attestation."
          : "Install the complete deployment-pinned Autonomous DNS local runtime configuration receipt.",
      )],
      runtimeMounted: false,
      runtimeStarted: false,
      localActivationStatus: localConfigured ? "unavailable" : "unconfigured",
      mcpAttestationStatus: "not_required",
      mcpRejectionCode: null,
    });
  }

  snapshot(): AutonomousDnsRuntimeLifecycleSnapshot {
    return this.snapshotValue;
  }

  projection(): RuntimeProjectionInput {
    const now = this.now();
    if (this.snapshotValue.status === "ready"
      && guidedActivationIsCurrent(this.snapshotValue.projection, now)) {
      return this.snapshotValue.projection;
    }
    if (this.snapshotValue.status === "stopped") return this.snapshotValue.projection;

    // A blocked or unconfigured Autonomous lifecycle must not freeze the
    // independently refreshed Guided projection at process startup. Re-read
    // the non-Autonomous baseline on every consumer request so expired local
    // activation receipts are removed synchronously, even if the next probe
    // timer has not fired yet. If a ready Autonomous projection ever outlives
    // its embedded Guided receipt, fail closed to the same current baseline.
    return baselineWithComposition(this.options.readBaselineProjection(), now).projection;
  }

  runtime(): MissionRuntimeEngine | undefined {
    return this.snapshotValue.status === "ready"
      && this.snapshotValue.runtimeStarted
      ? this.runtimeValue
      : undefined;
  }

  private executionProjection(): RuntimeProjectionInput {
    return this.runtimeStartupProjection ?? this.projection();
  }

  /**
   * Returns the preflight that produced the activation receipt currently
   * projected for Autonomous DNS. The Guided coordinator runs an independent
   * receipt wave, so its earlier receipt cannot be joined to this lifecycle's
   * later activation timestamps.
   */
  readToolExecutionPreflight(toolId: string): ToolExecutionPreflightResult | undefined {
    const now = this.now();
    if (this.snapshotValue.status !== "ready"
      || !guidedActivationIsCurrent(this.snapshotValue.projection, now)) return undefined;
    return this.projectedPreflights.get(toolId);
  }

  private refreshIntervalMs(): number {
    if (this.options.productionConfiguration.status !== "loaded") return 60_000;
    const config = this.options.productionConfiguration.runtime.value;
    return Math.max(1_000, Math.floor(Math.min(
      config.provider.attestationTtlMs,
      config.specialist.heartbeatTtlMs,
    ) / 2));
  }

  private schedule(): void {
    if (!this.started || this.stopped || this.timer !== undefined) return;
    this.timer = this.timers.set(() => {
      this.timer = undefined;
      void this.refresh().finally(() => this.schedule());
    }, this.refreshIntervalMs());
  }

  private ensureResources(): boolean {
    if (this.options.productionConfiguration.status !== "loaded"
      || this.options.localToolConfiguration.status !== "loaded") return false;
    if (this.localProcess && this.activation && this.workspaceResolver) return true;

    const local = this.options.localToolConfiguration;
    const runtime = this.options.productionConfiguration.runtime.value;
    const requiredWorkspaces = [
      runtime.dns.logicalWorkspace,
      ...(runtime.ipRecon ? [runtime.ipRecon.logicalWorkspace] : []),
      ...(runtime.fullTcpBaseline ? [runtime.fullTcpBaseline.logicalWorkspace] : []),
      ...(runtime.webSurface ? [runtime.webSurface.logicalWorkspace] : []),
      ...(runtime.vulnerabilityAssessment
        ? [runtime.vulnerabilityAssessment.logicalWorkspace] : []),
      ...(runtime.exploitValidation
        ? [runtime.exploitValidation.logicalWorkspace] : []),
    ];
    if (!requiredWorkspaces.every((workspace) =>
      local.workspaceMappings.mappings.some(({ logicalRoot }) =>
        workspaceMappingContains(logicalRoot, workspace)))) {
      throw new Error("A reviewed Autonomous Safe Recon logical workspace has no exact trusted mapping");
    }
    this.workspaceResolver = new EngagementWorkspaceResolver(local.workspaceMappings.mappings);
    this.localProcess = new DirectProcessLocalToolInvocationAdapter({
      adapterId: runtime.localProcess.adapterId,
      manifest: local.manifest,
      workspaceResolver: this.workspaceResolver,
      sandboxExecutable: {
        path: local.probeSandbox.executablePath,
        expectedSha256: local.probeSandbox.expectedSha256,
      },
    });
    const readinessSink: LocalProcessToolResultSink = {
      async acceptLocalProcessToolResult() {
        throw new Error("Readiness-only Autonomous DNS sink cannot accept mission results");
      },
    };
    this.readinessSinkUnbind = this.localProcess.bindResultSink(readinessSink);
    this.resultSinkBound = true;
    const lifecycle = this;
    this.activation = new LocalGuidedToolActivationCoordinator({
      configuration: local,
      adapter: this.localProcess,
      executionPort: {
        get runtimeResultSinkBound() {
          return lifecycle.resultSinkBound;
        },
      },
      workspaceResolver: this.workspaceResolver,
      clock: this.now,
      timers: this.timers,
    });
    return true;
  }

  async start(): Promise<AutonomousDnsRuntimeLifecycleSnapshot> {
    if (this.stopped) return this.snapshot();
    this.started = true;
    if (
      this.options.productionConfiguration.status === "loaded"
      && this.options.localToolConfiguration.status === "loaded"
    ) {
      const runtime = this.options.productionConfiguration.runtime.value;
      const workspaces = [...new Set([
        runtime.dns.logicalWorkspace,
        ...(runtime.ipRecon ? [runtime.ipRecon.logicalWorkspace] : []),
        ...(runtime.fullTcpBaseline ? [runtime.fullTcpBaseline.logicalWorkspace] : []),
        ...(runtime.webSurface ? [runtime.webSurface.logicalWorkspace] : []),
        ...(runtime.vulnerabilityAssessment
          ? [runtime.vulnerabilityAssessment.logicalWorkspace] : []),
        ...(runtime.exploitValidation
          ? [runtime.exploitValidation.logicalWorkspace] : []),
      ])];
      const provisioner = new ReviewedWorkspaceProvisioner(
        this.options.localToolConfiguration.workspaceMappings.mappings,
      );
      for (const workspace of workspaces) {
        if (this.stopped) return this.snapshot();
        const result = await provisioner.provision(workspace);
        // Workspace I/O is asynchronous. A shutdown fence may have arrived
        // while it was pending; never create readiness resources afterward.
        if (this.stopped) return this.snapshot();
        if (result.status === "unavailable") {
          return this.setBlocked(
            this.now(),
            this.options.readBaselineProjection(),
            [{
              code: "autonomous_workspace_unavailable",
              reason: result.explanation,
              remediation: result.remediation
                ?? "Restore the exact reviewed Autonomous workspace before runtime startup.",
            }],
            "unavailable",
          );
        }
      }
    }
    if (this.stopped) return this.snapshot();
    if (!this.ensureResources()) return this.snapshot();
    await this.activation!.start();
    if (this.stopped) return this.snapshot();
    const first = await this.refresh();
    this.schedule();
    return first;
  }

  refresh(): Promise<AutonomousDnsRuntimeLifecycleSnapshot> {
    if (this.activeRefresh) return this.activeRefresh;
    if (this.stopped || !this.started) return Promise.resolve(this.snapshot());
    const controller = new AbortController();
    this.activeRefreshController = controller;
    this.activeRefresh = this.executeRefresh(controller.signal)
      .catch((error: unknown) => this.blockedFromError(error))
      .finally(() => {
        if (this.activeRefreshController === controller) {
          this.activeRefreshController = undefined;
        }
        this.activeRefresh = undefined;
      });
    return this.activeRefresh;
  }

  private async executeRefresh(signal: AbortSignal): Promise<AutonomousDnsRuntimeLifecycleSnapshot> {
    if (this.stopped || signal.aborted) return this.snapshot();
    if (!this.ensureResources()
      || this.options.productionConfiguration.status !== "loaded"
      || this.options.localToolConfiguration.status !== "loaded") return this.snapshot();

    const now = this.now();
    const localActivation = this.activation!.snapshot();
    const runtimeConfig = this.options.productionConfiguration.runtime;
    const manifest = this.options.localToolConfiguration.manifest;
    const candidateLinuxManifest =
      this.options.productionConfiguration.candidateLinuxTransportManifest;
    if (
      runtimeConfig.value.exploitValidation
      && candidateLinuxManifest
    ) {
      try {
        if (!this.candidateLinuxTransport) {
          this.candidateLinuxTransport =
            new CandidateLinuxTransportBindingRegistry({
              database: this.options.database,
              loadedManifest: candidateLinuxManifest,
              now: this.now,
            });
        }
        await this.candidateLinuxTransport.attest(signal);
      } catch {
        // A configured candidate route is required below. Preserve the
        // assessment-only runtime boundary, but fail this activation wave
        // with a specific transport blocker rather than inventing readiness.
        // Retain the same registry instance so a later refresh can re-attest
        // the transport used by the already-mounted execution factory.
      }
    }
    if (this.stopped || signal.aborted) return this.snapshot();
    const candidateLinuxTransportReady =
      this.candidateLinuxTransport?.missionExecutionReady() === true;
    const policy = createConfiguredAutonomousPlanningPolicy(
      runtimeConfig.value,
      manifest,
      candidateLinuxTransportReady,
    );
    const planner = new LocalAutonomousContractPlanner({
      database: this.options.database,
      policy,
      readRuntimeProjection: () => this.projection(),
      now: this.now,
    });
    const evaluator = new LocalVerifiedEvidenceOutcomeEvaluator(this.options.database);
    const providerAttestation = attestLocalDeterministicAutonomousDnsProvider({
      configuration: runtimeConfig,
      planner,
      evaluator,
      candidateLinuxTransportReady,
      now,
    });
    const requiredToolIds = runtimeConfig.value.webSurface
      ? [
          AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
          AUTONOMOUS_IP_LIVENESS_TOOL_ID,
          AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
          AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
          AUTONOMOUS_HTTP_METADATA_TOOL_ID,
          AUTONOMOUS_WHATWEB_TOOL_ID,
          ...(autonomousEndpointDiscoveryEnabled(runtimeConfig.value.webSurface)
            ? [AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID]
            : []),
          ...(runtimeConfig.value.vulnerabilityAssessment
            ? [AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID]
            : []),
        ]
      : runtimeConfig.value.fullTcpBaseline
      ? [
          AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
          AUTONOMOUS_IP_LIVENESS_TOOL_ID,
          AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
          AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
        ]
      : runtimeConfig.value.ipRecon ? [
          AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
          AUTONOMOUS_IP_LIVENESS_TOOL_ID,
          AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
        ]
      : [AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID];
    const activationReceipts = localActivation.status === "ready"
      ? requiredToolIds.map((toolId) => {
          const matches = localActivation.activationReceipts.filter((receipt) => receipt.toolId === toolId);
          return matches.length === 1 ? matches[0] : undefined;
        })
      : [];
    const activationReceipt = activationReceipts[0];
    const completeActivationReceipts = activationReceipts.every(
      (receipt) => receipt !== undefined,
    ) ? activationReceipts as NonNullable<(typeof activationReceipts)[number]>[] : undefined;
    const specialistHeartbeat = activationReceipt && completeActivationReceipts && this.resultSinkBound
      ? attestAutonomousDnsSpecialistHeartbeat({
          configuration: runtimeConfig,
          manifest,
          activationReceipt,
          activationReceipts: completeActivationReceipts,
          adapterContract: runtimeConfig.value.fullTcpBaseline
            ? AUTONOMOUS_GENERAL_SAFE_RECON_EXECUTION_CONTRACT
            : runtimeConfig.value.ipRecon ? AUTONOMOUS_LOCAL_SAFE_RECON_EXECUTION_CONTRACT
            : AUTONOMOUS_DNS_LOCAL_PROCESS_EXECUTION_CONTRACT,
          now,
      })
      : undefined;
    const baseline = this.options.readBaselineProjection();
    const exploitOutcomeObserver = this.options.exploitOutcomeObserver
      ?? new CanonicalIndependentExploitOutcomeVerifier(this.options.database);
    let exploitCandidateMaterializer:
      AutonomousReusableExploitCandidateMaterializerPort | undefined;
    let exploitScripts: ScriptArtifactService | undefined;
    const exploitManifest =
      this.options.productionConfiguration.exploitSandboxManifest;
    if (runtimeConfig.value.exploitValidation
      && exploitManifest
      && this.options.scriptSourceStore
      && this.options.exploitVaultSync
      && this.options.brainContext) {
      exploitScripts = new ScriptArtifactService(
        this.options.database,
        this.options.scriptSourceStore,
        this.now,
      );
      exploitCandidateMaterializer =
        new AutonomousReusableExploitCandidateMaterializer({
          database: this.options.database,
          scriptSourceStore: this.options.scriptSourceStore,
          brain: this.options.brainContext,
          validator: new LocalReusableExploitSourceValidator({
            database: this.options.database,
            interpreterPath: exploitManifest.value.interpreter.executablePath,
            interpreterSha256:
              exploitManifest.value.interpreter.executableSha256,
            now: this.now,
          }),
          vaultSync: this.options.exploitVaultSync,
          ...(this.options.currentEvidenceCandidateGenerator
            ? {
                currentEvidenceGenerator:
                  this.options.currentEvidenceCandidateGenerator,
              }
            : {}),
          now: this.now,
        });
    }
    let exploitSandboxAttestation: ExactTargetSandboxAttestation | undefined;
    let activationObservedAt = now;
    if (runtimeConfig.value.exploitValidation && exploitManifest) {
      try {
        exploitSandboxAttestation = await composeExactTargetExploitSandbox({
          manifest: exploitManifest,
          now: this.now,
        }).attest();
        // The broker attestation is asynchronous. Compare the newly issued
        // receipt with a timestamp observed after that work, not with the
        // activation-wave timestamp captured before the broker probe began.
        activationObservedAt = this.now();
      } catch {
        // Keep the deterministic assessment route alive. The capability
        // projection below records the sandbox dependency as unavailable, so
        // strict exploit-capable contracts remain non-launchable.
        exploitSandboxAttestation = undefined;
      }
    }
    // The lifecycle publishes a frozen composition. Capture the executable
    // receipts that belong to that same generation before any asynchronous
    // work can let either coordinator advance to a new activation wave.
    const projectedPreflights = new Map<string, ToolExecutionPreflightResult>();
    const autonomousToolIds = new Set<string>(requiredToolIds);
    for (const tool of manifest.list()) {
      const preflight = autonomousToolIds.has(tool.toolId)
        ? this.activation!.readToolExecutionPreflight(tool.toolId)
        : this.options.readBaselineToolExecutionPreflight?.(tool.toolId);
      if (preflight) {
        projectedPreflights.set(tool.toolId, freeze(structuredClone(preflight)));
      }
    }
    const activation = composeAutonomousDnsActivation({
      database: this.options.database,
      baselineProjection: baseline,
      manifest,
      localActivation,
      configuration: runtimeConfig,
      providerAttestation,
      ...(specialistHeartbeat ? { specialistHeartbeat } : {}),
      localProcessTransport: this.localProcess!,
      workspaceResolver: this.workspaceResolver!,
      ...(this.options.brainContext ? { brainContext: this.options.brainContext } : {}),
      ...(this.options.productionConfiguration.status === "loaded"
        && this.options.productionConfiguration.cveCandidateCatalog
        ? {
            cveCandidateCatalog:
              this.options.productionConfiguration.cveCandidateCatalog.catalog,
          }
        : {}),
      ...(this.options.cveNvdEnrichment
        ? { cveNvdEnrichment: this.options.cveNvdEnrichment }
        : {}),
      ...(this.options.scriptSourceStore
        ? { scriptSourceStore: this.options.scriptSourceStore }
        : {}),
      ...(exploitCandidateMaterializer
        ? { exploitCandidateMaterializer }
        : {}),
      ...(runtimeConfig.value.exploitValidation
        ? { exploitOutcomeObserver }
        : {}),
      ...(this.options.productionConfiguration.status === "loaded"
        && this.options.productionConfiguration.exploitSandboxManifest
        ? {
            exploitSandboxManifest:
              this.options.productionConfiguration.exploitSandboxManifest,
          }
        : {}),
      ...(exploitSandboxAttestation
        ? { exploitSandboxAttestation }
        : {}),
      ...(this.candidateLinuxTransport
        ? { candidateLinuxTransport: this.candidateLinuxTransport }
        : {}),
      candidateLinuxTransportRequired: candidateLinuxManifest !== undefined,
      readRuntimeProjection: () => this.executionProjection(),
      runtimeClock: this.now,
      now: activationObservedAt,
    });
    if (activation.status === "blocked") {
      return await this.setBlocked(
        now,
        baseline,
        activation.blockers,
        localActivation.status,
      );
    }
    const runtimeAdapters = Object.freeze({
      ...activation.adapters,
      ...(this.options.providerAdvisory
        ? { providerAdvisory: this.options.providerAdvisory }
        : {}),
      ...(this.options.providerPlanningContext
        ? { providerContext: this.options.providerPlanningContext }
        : {}),
    });
    const runtimeComposition = inspectAutonomousRuntimeComposition({
      projection: activation.projection,
      adapters: runtimeAdapters,
      now: activationObservedAt,
    });
    if (runtimeComposition.status === "blocked") {
      return await this.setBlocked(
        now,
        baseline,
        runtimeComposition.blockers.map((blocker) => ({
          code: blocker.code,
          reason: blocker.impact,
          remediation: blocker.remediation,
        })),
        localActivation.status,
      );
    }
    const runtimeProjection: RuntimeProjectionInput = freeze({
      ...activation.projection,
      readiness: {
        ...activation.projection.readiness,
        autonomousRuntime: runtimeComposition,
      },
    });

    // The readiness sink exists only so the target-free adapter boundary can
    // prove callback wiring. Replace it synchronously with the runtime-owned
    // result sink before the first scheduler scan can dispatch mission work.
    // Keep the candidate projection private while runtime.start() performs
    // recovery and its first scheduler scan: public health remains on the
    // previous fail-closed generation until both the scheduler and canonical
    // intake projection have committed this exact generation.
    if (!this.runtimeValue) {
      this.readinessSinkUnbind?.();
      this.readinessSinkUnbind = undefined;
      this.resultSinkBound = false;
      this.projectedPreflights = projectedPreflights;
      this.runtimeStartupProjection = runtimeProjection;
      const exploitConfig = runtimeConfig.value.exploitValidation;
      const postReconPlanExpansion = exploitConfig
        && exploitManifest
        && exploitCandidateMaterializer
        && exploitScripts
        && activation.composition.readyActionClassIds.includes(
          "exploit_validation",
        )
        ? (() => {
            return new AutonomousPostReconExploitExpansionService({
              database: this.options.database,
              materializer: exploitCandidateMaterializer,
              planning: new CanonicalAutonomousExploitValidationPlanningGate({
                database: this.options.database,
                scripts: exploitScripts,
                outcomeVerifierReadiness: exploitOutcomeObserver,
              }),
              binding: {
                phase: "Evidence-matched validation",
                title: "Validate the exact evidence-matched weakness",
                objective:
                  "Run one approved immutable validation procedure against the exact authorized disposable target.",
                explanation:
                  "Ti-Scale found a current-run exact-version/CVE match for a tested reusable procedure in the connected Vault.",
                rationale:
                  "The candidate is byte-identical, locally revalidated, current-run evidence-backed, and bounded by the unchanged mission contract.",
                successCriterion: exploitConfig.successCriterion,
                reversibility:
                  "The candidate is non-persistent and confined to the exact target; stop on any missing independent outcome proof.",
                agentId: exploitConfig.agentId,
              },
              ...(candidateLinuxTransportReady
                ? {
                    postExploitSpecRegistrar:
                      new CurrentRunCandidateLinuxPostExploitSpecRegistrar(
                        this.options.database,
                        this.now,
                      ),
                    postExploit:
                      new CandidateLinuxPostExploitPlanExtension({
                        database: this.options.database,
                        agentId: exploitConfig.agentId,
                      }),
                  }
                : {}),
            });
          })()
        : undefined;
      const runtime = createProductionAutonomousRuntime({
        database: this.options.database,
        ...(this.options.operationalHazardHmacKey
          ? { operationalHazardHmacKey: this.options.operationalHazardHmacKey }
          : {}),
        ...(this.options.brainContext ? { brainContext: this.options.brainContext } : {}),
        ...(this.options.projectMemoryNodes ? { projectMemoryNodes: this.options.projectMemoryNodes } : {}),
        ...(postReconPlanExpansion ? { postReconPlanExpansion } : {}),
        adapters: runtimeAdapters,
        readRuntimeProjection: () => this.executionProjection(),
        workerId: this.options.workerId ?? `ti-scale-autonomous-dns-${process.pid}`,
        now: this.now,
      });
      this.executionFactory = activation.adapters.execution instanceof AutonomousDnsLocalProcessExecutionFactory
        || activation.adapters.execution instanceof AutonomousLocalSafeReconExecutionFactory
        || activation.adapters.execution instanceof AutonomousGeneralSafeReconExecutionFactory
        || activation.adapters.execution instanceof AutonomousExploitValidationExecutionFactory
        ? activation.adapters.execution
        : undefined;
      this.runtimeValue = runtime;
      this.resultSinkBound = true;
      try {
        await runtime.start();
      } catch (error) {
        this.runtimeStartupProjection = undefined;
        throw error;
      }
    }

    // beginStop() is broadcast before ordered shutdown awaits. A refresh that
    // was already awaiting runtime startup must not publish a new executable
    // generation after that fence.
    if (this.stopped || signal.aborted) return this.snapshot();

    const readySnapshot: AutonomousDnsRuntimeLifecycleSnapshot = freeze({
      schemaVersion: AUTONOMOUS_DNS_RUNTIME_LIFECYCLE_SCHEMA_VERSION,
      status: "ready",
      checkedAt: activationObservedAt.toISOString(),
      reason: "The exact local DNS executable, specialist heartbeat, and deterministic local policy receipts are current.",
      projection: runtimeProjection,
      composition: runtimeComposition,
      blockers: [],
      runtimeMounted: true,
      runtimeStarted: true,
      localActivationStatus: localActivation.status,
      mcpAttestationStatus: "not_required",
      mcpRejectionCode: null,
    });
    this.projectedPreflights = projectedPreflights;
    // This callback is deliberately synchronous. The DB read model is updated
    // before the lifecycle swaps the public snapshot, so no request can join
    // ready live health to a specialist/provider inventory from an older wave.
    this.options.publishProjection?.(runtimeProjection);
    this.snapshotValue = readySnapshot;
    this.runtimeStartupProjection = undefined;
    return this.snapshot();
  }

  private async withdrawRuntime(reason: string): Promise<void> {
    if (this.runtimeValue) await this.runtimeValue.stop();
    this.runtimeValue = undefined;
    this.executionFactory?.close();
    this.executionFactory = undefined;
    this.runtimeStartupProjection = undefined;
    this.resultSinkBound = false;
    if (this.localProcess && !this.readinessSinkUnbind) {
      const readinessSink: LocalProcessToolResultSink = {
        async acceptLocalProcessToolResult() {
          throw new Error(`Readiness-only Autonomous DNS sink rejected a mission result after withdrawal: ${reason}`);
        },
      };
      this.readinessSinkUnbind = this.localProcess.bindResultSink(readinessSink);
      this.resultSinkBound = true;
    }
  }

  private async setBlocked(
    now: Date,
    baseline: RuntimeProjectionInput,
    blockers: readonly Readonly<{
      code: string;
      reason: string;
      remediation: string;
    }>[],
    localStatus: LocalGuidedToolActivationSnapshot["status"],
  ): Promise<AutonomousDnsRuntimeLifecycleSnapshot> {
    const blocked = baselineWithComposition(baseline, now);
    const lifecycleBlockers: AutonomousDnsRuntimeLifecycleBlocker[] = blockers.map(
      ({ code, reason, remediation }) => lifecycleBlocker(code, reason, remediation),
    );
    const blockedSnapshot: AutonomousDnsRuntimeLifecycleSnapshot = freeze({
      schemaVersion: AUTONOMOUS_DNS_RUNTIME_LIFECYCLE_SCHEMA_VERSION,
      status: "blocked",
      checkedAt: now.toISOString(),
      reason: lifecycleBlockers[0]?.reason ?? "Autonomous DNS activation is blocked.",
      projection: blocked.projection,
      composition: blocked.composition,
      blockers: lifecycleBlockers,
      runtimeMounted: false,
      runtimeStarted: false,
      localActivationStatus: localStatus,
      mcpAttestationStatus: "not_required",
      mcpRejectionCode: null,
    });
    // Withdraw public readiness before awaiting runtime cleanup. A concurrent
    // request may observe blocked while cleanup drains, but can never observe
    // ready after this activation wave has failed.
    this.snapshotValue = blockedSnapshot;
    this.projectedPreflights = new Map();
    this.runtimeStartupProjection = undefined;
    try {
      this.options.publishProjection?.(blocked.projection);
    } catch {
      // Live readiness is already fail-closed. A later projection wave can
      // repair the read model; never restore the rejected ready generation.
    }
    await this.withdrawRuntime(blockers[0]?.reason ?? "Autonomous DNS readiness was withdrawn");
    return this.snapshot();
  }

  private async blockedFromError(error: unknown): Promise<AutonomousDnsRuntimeLifecycleSnapshot> {
    if (this.stopped) return this.snapshot();
    const now = this.now();
    const baseline = baselineWithComposition(this.options.readBaselineProjection(), now);
    const message = error instanceof Error
      ? error.message
      : "The Autonomous DNS activation wave failed without a typed error.";
    const blockedSnapshot: AutonomousDnsRuntimeLifecycleSnapshot = freeze({
      schemaVersion: AUTONOMOUS_DNS_RUNTIME_LIFECYCLE_SCHEMA_VERSION,
      status: "blocked",
      checkedAt: now.toISOString(),
      reason: message,
      projection: baseline.projection,
      composition: baseline.composition,
      blockers: [lifecycleBlocker(
        "autonomous_dns_activation_failed",
        message,
        "Inspect the exact trusted configuration and local execution receipts; do not retry mission work until activation succeeds.",
      )],
      runtimeMounted: false,
      runtimeStarted: false,
      localActivationStatus: this.activation?.snapshot().status ?? "unconfigured",
      mcpAttestationStatus: "not_required",
      mcpRejectionCode: null,
    });
    this.snapshotValue = blockedSnapshot;
    this.projectedPreflights = new Map();
    this.runtimeStartupProjection = undefined;
    try {
      this.options.publishProjection?.(baseline.projection);
    } catch {
      // The public lifecycle is already blocked; retain fail-closed truth.
    }
    await this.withdrawRuntime("Autonomous DNS activation refresh failed");
    return this.snapshot();
  }

  beginStop(): void {
    if (this.stopped) return;
    this.stopped = true;
    if (this.timer !== undefined) this.timers.clear(this.timer);
    this.timer = undefined;
    this.activeRefreshController?.abort("Ti-Scale Autonomous DNS lifecycle is stopping");
    this.activation?.beginStop();
    this.runtimeValue?.beginStop();
  }

  async stop(): Promise<void> {
    this.beginStop();
    const activeRefresh = this.activeRefresh;
    const activationStop = this.activation?.stop();
    await Promise.allSettled([
      ...(activeRefresh ? [activeRefresh] : []),
      ...(activationStop ? [activationStop] : []),
    ]);
    await this.runtimeValue?.stop();
    this.runtimeValue = undefined;
    this.executionFactory?.close();
    this.executionFactory = undefined;
    this.runtimeStartupProjection = undefined;
    this.projectedPreflights = new Map();
    this.resultSinkBound = false;
    this.readinessSinkUnbind?.();
    this.readinessSinkUnbind = undefined;
    const now = this.now();
    const baseline = baselineWithComposition(this.options.readBaselineProjection(), now);
    this.snapshotValue = freeze({
      schemaVersion: AUTONOMOUS_DNS_RUNTIME_LIFECYCLE_SCHEMA_VERSION,
      status: "stopped",
      checkedAt: now.toISOString(),
      reason: "Autonomous DNS runtime stopped; child work was cancelled and leases were released by the runtime.",
      projection: baseline.projection,
      composition: baseline.composition,
      blockers: [lifecycleBlocker(
        "autonomous_dns_stopped",
        "The Autonomous DNS lifecycle is stopped.",
        "Start a new process and complete a fresh activation wave before mission work.",
      )],
      runtimeMounted: false,
      runtimeStarted: false,
      localActivationStatus: this.activation?.snapshot().status ?? "unconfigured",
      mcpAttestationStatus: "not_required",
      mcpRejectionCode: null,
    });
  }
}

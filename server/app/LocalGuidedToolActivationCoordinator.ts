import { digestCanonicalJson } from "../mcp/canonicalJson";
import {
  BubblewrapToolProbeEnvironment,
  LOCAL_PROCESS_ADAPTER_READINESS_SCHEMA_VERSION,
  LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION,
  LocalToolInstallationPreflight,
  type DirectProcessLocalToolInvocationAdapter,
  type LocalProcessAdapterReadinessReceipt,
  type LocalToolActivationReceipt,
  type LocalToolInstallationReceipt,
  type ReviewedLocalToolExecutionPort,
} from "../local-tools";
import {
  EngagementWorkspaceResolver,
  ToolBindingReadinessRunner,
  ToolBindingRegistry,
  ToolExecutionPreflightService,
  type ToolBindingReadinessReceipt,
  type ToolBindingReadinessSnapshot,
  type ToolExecutionPreflightResult,
} from "../system-capabilities";
import type { LoadedLocalGuidedToolConfiguration } from "./LocalGuidedToolConfiguration";

export const LOCAL_GUIDED_TOOL_ACTIVATION_SNAPSHOT_SCHEMA_VERSION =
  "ti-scale.local-guided-tool-activation-snapshot.v1" as const;

export interface LocalGuidedToolActivationSnapshot {
  readonly schemaVersion: typeof LOCAL_GUIDED_TOOL_ACTIVATION_SNAPSHOT_SCHEMA_VERSION;
  readonly status: "ready" | "unavailable";
  readonly checkedAt: string;
  readonly reason: string;
  readonly activationReceipts: readonly LocalToolActivationReceipt[];
  readonly installationReceipts: readonly LocalToolInstallationReceipt[];
  readonly toolBindingReadiness: ToolBindingReadinessSnapshot;
  readonly adapterReadiness: LocalProcessAdapterReadinessReceipt | null;
  readonly workspaceConfinementReady: boolean;
  readonly runtimeResultSinkReady: boolean;
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

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

function time(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value
    ? parsed
    : null;
}

function adapterReceiptValid(
  receipt: LocalProcessAdapterReadinessReceipt | null,
  configuration: LoadedLocalGuidedToolConfiguration,
  now: Date,
): receipt is LocalProcessAdapterReadinessReceipt {
  if (!receipt) return false;
  const { receiptSha256, ...unsigned } = receipt;
  const observedAt = time(receipt.observedAt);
  const expiresAt = time(receipt.expiresAt);
  const boundary = receipt.boundary;
  return receipt.schemaVersion === LOCAL_PROCESS_ADAPTER_READINESS_SCHEMA_VERSION
    && receipt.manifestSha256 === configuration.manifest.descriptor.manifestSha256
    && receipt.sandboxExecutableSha256 === configuration.probeSandbox.expectedSha256
    && receipt.sandboxExecutableIdentity.sha256 === configuration.probeSandbox.expectedSha256
    && receipt.grantsMissionExecution === false
    && observedAt !== null
    && observedAt <= now.getTime()
    && expiresAt !== null
    && expiresAt > now.getTime()
    && expiresAt > observedAt
    && boundary.platform === "linux"
    && boundary.directArgv === true
    && boundary.shell === false
    && boundary.workspaceResolver === true
    && boundary.filesystemSandbox === "bubblewrap_minimal_read_only_host_workspace_write"
    && boundary.totalOutputBound === true
    && boundary.cooperativeCancellation === true
    && boundary.processGroupCleanup === true
    && boundary.resultSinkBound === true
    && boundary.targetContact === false
    && digestCanonicalJson(unsigned, { maxBytes: 512 * 1_024, maxDepth: 16 }).sha256
      === receiptSha256
    && receipt.tools.length === configuration.manifest.descriptor.enabledToolCount
    && new Set(receipt.tools.map(({ toolId }) => toolId)).size === receipt.tools.length;
}

function installationReady(
  receipt: LocalToolInstallationReceipt | undefined,
  tool: ReturnType<LoadedLocalGuidedToolConfiguration["manifest"]["resolve"]>,
  manifestSha256: string,
): receipt is LocalToolInstallationReceipt {
  return tool !== undefined
    && receipt !== undefined
    && receipt.manifestSha256 === manifestSha256
    && receipt.toolId === tool.toolId
    && receipt.bindingSha256 === tool.bindingSha256
    && receipt.status === "ready"
    && receipt.code === "ready"
    && receipt.expectedExecutableSha256 === tool.executable.expectedSha256
    && receipt.observedExecutableSha256 === tool.executable.expectedSha256
    && receipt.fileCapabilitiesPresent === false
    && receipt.noNewPrivilegesCompatible === true
    && receipt.probeBoundary.toolExecuted === false
    && receipt.probeBoundary.targetArgumentsSupplied === false
    && receipt.probeBoundary.providerArgumentsSupplied === false
    && receipt.probeBoundary.mcpArgumentsSupplied === false
    && receipt.grantsMissionExecution === false;
}

function isolatedProbeReady(
  receipt: ToolBindingReadinessReceipt | undefined,
  registry: ToolBindingRegistry,
  toolId: string,
  expectedExecutableSha256: string,
  now: Date,
): receipt is ToolBindingReadinessReceipt {
  const binding = registry.resolve(toolId);
  const expiresAt = receipt ? time(receipt.expiresAt) : null;
  return binding !== undefined
    && receipt !== undefined
    && receipt.registryVersion === registry.descriptor.registryVersion
    && receipt.registrySha256 === registry.descriptor.registrySha256
    && receipt.runtimeManifestSha256 === registry.descriptor.runtimeManifestSha256
    && receipt.toolId === toolId
    && receipt.registryBindingSha256 === binding.bindingSha256
    && typeof receipt.preflightBindingSha256 === "string"
    && /^[a-f0-9]{64}$/u.test(receipt.preflightBindingSha256)
    && receipt.status === "ready"
    && receipt.code === "ready"
    && expiresAt !== null
    && expiresAt > now.getTime()
    && receipt.probeBoundary.networkIsolationEnforced === true
    && receipt.probeBoundary.filesystemWriteIsolationEnforced === true
    && receipt.probeBoundary.immutableSnapshotExecutionEnforced === true
    && receipt.executableIdentity?.sha256 === expectedExecutableSha256
    && receipt.grantsMissionExecution === false;
}

function emptySnapshot(
  runner: ToolBindingReadinessRunner,
  now: Date,
  reason: string,
): LocalGuidedToolActivationSnapshot {
  return deepFreeze({
    schemaVersion: LOCAL_GUIDED_TOOL_ACTIVATION_SNAPSHOT_SCHEMA_VERSION,
    status: "unavailable",
    checkedAt: now.toISOString(),
    reason,
    activationReceipts: [],
    installationReceipts: [],
    toolBindingReadiness: runner.snapshot(),
    adapterReadiness: null,
    workspaceConfinementReady: false,
    runtimeResultSinkReady: false,
  });
}

/**
 * Runs the bounded activation wave outside request handlers. The synchronous
 * snapshot is the only state consumed by projections and planners.
 */
export class LocalGuidedToolActivationCoordinator {
  readonly workspaceResolver: EngagementWorkspaceResolver;
  readonly registry: ToolBindingRegistry;
  readonly runner: ToolBindingReadinessRunner;
  private readonly probeEnvironment: BubblewrapToolProbeEnvironment;
  private readonly clock: () => Date;
  private readonly timers: TimerEnvironment;
  private snapshotValue: LocalGuidedToolActivationSnapshot;
  private preflightSnapshotValue = new Map<string, ToolExecutionPreflightResult>();
  private activeRefresh?: Promise<LocalGuidedToolActivationSnapshot>;
  private activeRefreshController?: AbortController;
  private timer?: unknown;
  private monitoring = false;
  private stopped = false;

  constructor(private readonly options: Readonly<{
    configuration: LoadedLocalGuidedToolConfiguration;
    adapter: Pick<DirectProcessLocalToolInvocationAdapter, "adapterId" | "readinessReceipt">;
    executionPort: Pick<ReviewedLocalToolExecutionPort, "runtimeResultSinkBound">;
    workspaceResolver?: EngagementWorkspaceResolver;
    clock?: () => Date;
    timers?: TimerEnvironment;
  }>) {
    this.clock = options.clock ?? (() => new Date());
    this.timers = options.timers ?? defaultTimers();
    this.workspaceResolver = options.workspaceResolver
      ?? new EngagementWorkspaceResolver(options.configuration.workspaceMappings.mappings);
    const localDefinitions = options.configuration.manifest.toRuntimeSourceManifests();
    this.registry = new ToolBindingRegistry(
      options.configuration.manifest.toToolBindingRegistryDocument(),
      localDefinitions,
    );
    this.probeEnvironment = new BubblewrapToolProbeEnvironment(
      options.configuration.probeSandbox,
    );
    this.runner = new ToolBindingReadinessRunner(
      this.registry,
      new ToolExecutionPreflightService({
        environment: this.probeEnvironment,
        clock: this.clock,
      }),
      this.clock,
    );
    this.snapshotValue = emptySnapshot(
      this.runner,
      this.clock(),
      "The complete local Guided activation wave has not run.",
    );
  }

  private refreshIntervalMs(): number {
    const ttls = this.options.configuration.manifest.list()
      .filter(({ activation }) => activation === "enabled")
      .map(({ probe }) => probe.ttlMs);
    if (ttls.length === 0) return 60_000;
    return Math.max(1_000, Math.floor(Math.min(...ttls) / 2));
  }

  private schedule(): void {
    if (!this.monitoring || this.stopped || this.timer !== undefined) return;
    this.timer = this.timers.set(() => {
      this.timer = undefined;
      void this.refresh().finally(() => this.schedule());
    }, this.refreshIntervalMs());
  }

  start(): Promise<LocalGuidedToolActivationSnapshot> {
    if (this.stopped) return Promise.resolve(this.snapshot());
    this.monitoring = true;
    const first = this.refresh();
    void first.finally(() => this.schedule());
    return first;
  }

  refresh(): Promise<LocalGuidedToolActivationSnapshot> {
    if (this.activeRefresh) return this.activeRefresh;
    if (this.stopped) return Promise.resolve(this.snapshot());
    const controller = new AbortController();
    this.activeRefreshController = controller;
    this.activeRefresh = this.executeRefresh(controller.signal)
      .catch(() => {
        if (this.stopped || controller.signal.aborted) return this.snapshot();
        const failed = emptySnapshot(
          this.runner,
          this.clock(),
          "The local Guided activation wave failed before complete receipts were produced.",
        );
        this.preflightSnapshotValue = new Map();
        this.snapshotValue = failed;
        return failed;
      })
      .finally(() => {
        if (this.activeRefreshController === controller) {
          this.activeRefreshController = undefined;
        }
        this.activeRefresh = undefined;
      });
    return this.activeRefresh;
  }

  private async executeRefresh(signal: AbortSignal): Promise<LocalGuidedToolActivationSnapshot> {
    if (this.stopped || signal.aborted) return this.snapshot();
    const configuration = this.options.configuration;
    // Bind the coordinator and adapter to one observation timestamp so the
    // adapter's signed installation hashes can be reproduced exactly here.
    // A fresh `now()` per executable would make otherwise identical receipts
    // differ only by milliseconds and would correctly fail the hash join.
    const activationTime = this.clock();
    const installationReceipts = new LocalToolInstallationPreflight({ now: () => activationTime })
      .inspectAllAsync(configuration.manifest, signal);
    const resolvedInstallationReceipts = await installationReceipts;
    if (this.stopped || signal.aborted) return this.snapshot();
    const toolBindingReadiness = await this.runner.runAll();
    if (this.stopped || signal.aborted) return this.snapshot();
    // Capture the executable preflights from the same completed runner wave
    // as toolBindingReadiness. Consumers must never join a completed
    // activation snapshot to mutable receipts from the next refresh wave.
    const preflightSnapshot = new Map<string, ToolExecutionPreflightResult>();
    for (const tool of configuration.manifest.list()) {
      const preflight = this.runner.readToolExecutionPreflight(tool.toolId);
      if (preflight) {
        preflightSnapshot.set(tool.toolId, deepFreeze(structuredClone(preflight)));
      }
    }
    let adapterReadiness: LocalProcessAdapterReadinessReceipt | null = null;
    try {
      adapterReadiness = await this.options.adapter.readinessReceipt(activationTime, 60_000, signal);
    } catch {
      adapterReadiness = null;
    }
    if (this.stopped || signal.aborted) return this.snapshot();
    const now = this.clock();
    const workspaceResults = await Promise.all(
      configuration.workspaceMappings.mappings.map(({ logicalRoot }) =>
        this.workspaceResolver.resolve(logicalRoot)),
    );
    if (this.stopped || signal.aborted) return this.snapshot();
    const workspaceConfinementReady = workspaceResults.length > 0
      && workspaceResults.every(({ status, resolvedPath }) => status === "resolved" && Boolean(resolvedPath));
    const runtimeResultSinkReady = this.options.executionPort.runtimeResultSinkBound;
    const validAdapter = adapterReceiptValid(adapterReadiness, configuration, now);
    const installs = new Map(resolvedInstallationReceipts.map((receipt) => [receipt.toolId, receipt]));
    const probes = new Map(toolBindingReadiness.receipts.map((receipt) => [receipt.toolId, receipt]));
    const adapterTools = new Map(adapterReadiness?.tools.map((tool) => [tool.toolId, tool]) ?? []);
    const activationReceipts = configuration.manifest.list().map((tool): LocalToolActivationReceipt => {
      const installation = installs.get(tool.toolId);
      const probe = probes.get(tool.toolId);
      const adapterTool = adapterTools.get(tool.toolId);
      const installed = installationReady(
        installation,
        tool,
        configuration.manifest.descriptor.manifestSha256,
      );
      const probed = isolatedProbeReady(
        probe,
        this.registry,
        tool.toolId,
        tool.executable.expectedSha256,
        now,
      );
      const adapterToolReady = validAdapter
        && adapterTool?.bindingSha256 === tool.bindingSha256
        && adapterTool.expectedExecutableSha256 === tool.executable.expectedSha256
        && installed
        && adapterTool.installationReceiptSha256 === digestCanonicalJson(
          installation,
          { maxBytes: 64 * 1_024, maxDepth: 16 },
        ).sha256;
      const expiryCandidates = [
        probe ? time(probe.expiresAt) : null,
        adapterReadiness ? time(adapterReadiness.expiresAt) : null,
      ].filter((value): value is number => value !== null);
      const expiresAt = expiryCandidates.length > 0
        ? Math.min(...expiryCandidates)
        : now.getTime();
      return Object.freeze({
        schemaVersion: LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION,
        manifestSha256: configuration.manifest.descriptor.manifestSha256,
        toolId: tool.toolId,
        bindingSha256: tool.bindingSha256,
        preflightBindingSha256: probe?.preflightBindingSha256 ?? null,
        executableSha256: tool.executable.expectedSha256,
        installationReady: installed,
        isolatedProbeReady: probed,
        invocationAdapterReady: adapterToolReady,
        workspaceConfinementReady,
        resultSinkReady: adapterToolReady && runtimeResultSinkReady,
        cancellationReady: adapterToolReady
          && adapterReadiness?.boundary.cooperativeCancellation === true
          && adapterReadiness.boundary.processGroupCleanup === true,
        observedAt: now.toISOString(),
        expiresAt: new Date(Math.max(now.getTime(), expiresAt)).toISOString(),
      });
    });
    const current = configuration.manifest.toRuntimeSourceManifests(activationReceipts, now);
    const readyCount = current.tools.filter(({ available }) => available).length;
    const snapshot = deepFreeze({
      schemaVersion: LOCAL_GUIDED_TOOL_ACTIVATION_SNAPSHOT_SCHEMA_VERSION,
      status: readyCount > 0 ? "ready" : "unavailable",
      checkedAt: now.toISOString(),
      reason: readyCount > 0
        ? `${readyCount} reviewed local tool${readyCount === 1 ? " is" : "s are"} fully activated for exact Guided decisions.`
        : "No local tool passed the complete installation, isolated probe, adapter, workspace, result, and cancellation boundary.",
      activationReceipts: Object.freeze(activationReceipts),
      installationReceipts: Object.freeze([...resolvedInstallationReceipts]),
      toolBindingReadiness,
      adapterReadiness: validAdapter ? adapterReadiness : null,
      workspaceConfinementReady,
      runtimeResultSinkReady,
    } satisfies LocalGuidedToolActivationSnapshot);
    if (this.stopped || signal.aborted) return this.snapshot();
    this.preflightSnapshotValue = preflightSnapshot;
    this.snapshotValue = snapshot;
    return snapshot;
  }

  snapshot(): LocalGuidedToolActivationSnapshot {
    return this.snapshotValue;
  }

  /**
   * Returns only the executable receipt paired with the last fully published
   * activation snapshot. The runner may already be producing the next wave;
   * exposing its mutable map here would create a false readiness failure.
   */
  readToolExecutionPreflight(toolId: string): ToolExecutionPreflightResult | undefined {
    return this.preflightSnapshotValue.get(toolId);
  }

  readyToolIds(now: Date = this.clock()): ReadonlySet<string> {
    const manifests = this.options.configuration.manifest.toRuntimeSourceManifests(
      this.snapshotValue.activationReceipts,
      now,
    );
    return new Set(manifests.tools.filter(({ available }) => available).map(({ id }) => id));
  }

  beginStop(): void {
    this.stopped = true;
    this.monitoring = false;
    if (this.timer !== undefined) {
      this.timers.clear(this.timer);
      this.timer = undefined;
    }
    this.activeRefreshController?.abort("Ti-Scale local Guided activation is stopping");
    this.runner.beginStop();
  }

  async stop(): Promise<LocalGuidedToolActivationSnapshot> {
    this.beginStop();
    const activeRefresh = this.activeRefresh;
    const runnerStop = this.runner.stop();
    await Promise.allSettled([
      ...(activeRefresh ? [activeRefresh] : []),
      runnerStop,
    ]);
    this.probeEnvironment.close();
    return this.snapshot();
  }
}

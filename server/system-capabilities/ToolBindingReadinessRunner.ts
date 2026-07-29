import {
  ToolExecutionPreflightService,
  toolExecutionPreflightBindingSha256,
  type ToolExecutionPreflightCode,
  type ToolExecutionPreflightResult,
  type ToolExecutionPreflightSpec,
} from "./ToolExecutionPreflight";
import {
  ToolBindingRegistry,
  type ReviewedLocalToolBinding,
  type ToolBindingRegistryDescriptor,
} from "./ToolBindingRegistry";

export const TOOL_BINDING_READINESS_RECEIPT_SCHEMA_VERSION =
  "ti-scale.tool-binding-readiness-receipt.v2" as const;
export const TOOL_BINDING_READINESS_SNAPSHOT_SCHEMA_VERSION =
  "ti-scale.tool-binding-readiness-snapshot.v2" as const;

export type ToolBindingReadinessCode =
  | ToolExecutionPreflightCode
  | "readiness_runner_error";

export interface ToolBindingReadinessReceipt {
  readonly schemaVersion: typeof TOOL_BINDING_READINESS_RECEIPT_SCHEMA_VERSION;
  readonly registryVersion: string;
  readonly registrySha256: string;
  readonly runtimeManifestSha256: string;
  readonly toolId: string;
  readonly registryBindingSha256: string;
  /** Null only when the readiness runner failed before the preflight could attest its binding. */
  readonly preflightBindingSha256: string | null;
  readonly status: "ready" | "unavailable";
  readonly code: ToolBindingReadinessCode;
  readonly checkedAt: string;
  readonly expiresAt: string;
  readonly probeBoundary: ToolExecutionPreflightResult["probeBoundary"];
  readonly executableIdentity: ToolExecutionPreflightResult["executableIdentity"];
  readonly grantsMissionExecution: false;
  readonly privilegeBoundary: Readonly<{
    readonly noNewPrivileges: boolean | null;
    /** True only after an observed EPERM/operation-not-permitted conflict under NoNewPrivs. */
    readonly capabilityTransitionConflictObserved: boolean;
  }>;
  readonly explanation: string;
  readonly remediation: string | null;
  readonly execution: Readonly<{
    readonly exitCode: number | null;
    readonly signal: NodeJS.Signals | null;
    readonly spawnErrorCode: string | null;
    readonly outputBytes: number;
    readonly outputSha256: string | null;
  }>;
}

export interface ToolBindingReadinessSnapshot {
  readonly schemaVersion: typeof TOOL_BINDING_READINESS_SNAPSHOT_SCHEMA_VERSION;
  readonly checkedAt: string;
  readonly readOnly: true;
  readonly grantsMissionExecution: false;
  readonly probeBoundary: Readonly<{
    readonly shell: false;
    readonly targetArgumentsSupplied: false;
    readonly providerArgumentsSupplied: false;
    readonly mcpArgumentsSupplied: false;
    readonly networkIsolationEnforced: boolean | null;
    readonly filesystemWriteIsolationEnforced: boolean | null;
    readonly immutableSnapshotExecutionEnforced: boolean | null;
    readonly externalContact: "not_measured" | "not_applicable";
  }>;
  readonly registry: ToolBindingRegistryDescriptor;
  readonly accounting: Readonly<{
    readonly registered: number;
    readonly attempted: number;
    readonly reported: number;
    readonly missing: number;
    readonly unexpected: number;
    readonly ready: number;
    readonly unavailable: number;
    readonly fresh: number;
    readonly stale: number;
    /** Every registered binding has exactly one receipt, regardless of readiness outcome. */
    readonly complete: boolean;
    /** Complete accounting plus unexpired receipts; this still does not grant execution. */
    readonly current: boolean;
  }>;
  readonly receipts: readonly ToolBindingReadinessReceipt[];
}

export interface ToolBindingReadinessTimerEnvironment {
  set(callback: () => void, delayMs: number): unknown;
  clear(timer: unknown): void;
}

function defaultTimerEnvironment(): ToolBindingReadinessTimerEnvironment {
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

function clonePreflight(result: ToolExecutionPreflightResult): ToolExecutionPreflightResult {
  return deepFreeze(structuredClone(result));
}

function validExecutableIdentity(
  identity: ToolExecutionPreflightResult["executableIdentity"],
): boolean {
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  return identity !== null
    && /^[a-f0-9]{64}$/u.test(identity.sha256)
    && /^\d+$/u.test(identity.device)
    && /^\d+$/u.test(identity.inode)
    && Number.isSafeInteger(identity.sizeBytes)
    && identity.sizeBytes > 0
    && identity.sizeBytes <= 256 * 1024 * 1024
    && Number.isSafeInteger(identity.mode)
    && identity.mode >= 0
    && identity.mode <= 0o7777
    && (identity.mode & 0o022) === 0
    && (identity.mode & 0o111) !== 0
    && Number.isSafeInteger(identity.uid)
    && (identity.uid === 0 || identity.uid === currentUid)
    && Number.isSafeInteger(identity.gid);
}

/**
 * The isolated worker is trusted to enforce its sandbox, but its returned
 * receipt is still treated as untrusted structured input. A mismatched tool,
 * binding, timestamp, boundary, or output bound can never be re-labelled by
 * the runner as a registry receipt.
 */
function preflightMatchesBinding(
  result: ToolExecutionPreflightResult,
  binding: ReviewedLocalToolBinding,
  spec: ToolExecutionPreflightSpec,
  now: Date,
): boolean {
  const checkedAt = Date.parse(result.checkedAt);
  const expiresAt = Date.parse(result.expiresAt);
  const ready = result.status === "ready" && result.code === "ready";
  const unavailable = result.status === "unavailable" && result.code !== "ready";
  const boundary = result.probeBoundary;
  return result.schemaVersion === "ti-scale.tool-execution-preflight.v2"
    && result.toolId === binding.toolId
    && result.bindingSha256 === toolExecutionPreflightBindingSha256(spec)
    && Number.isFinite(checkedAt)
    && checkedAt <= now.getTime() + 60_000
    && Number.isFinite(expiresAt)
    && expiresAt === checkedAt + binding.ttlMs
    && (ready || unavailable)
    && boundary.shell === false
    && boundary.targetArgumentsSupplied === false
    && boundary.providerArgumentsSupplied === false
    && boundary.mcpArgumentsSupplied === false
    && boundary.externalContact === "not_measured"
    && Number.isSafeInteger(result.execution.outputBytes)
    && result.execution.outputBytes >= 0
    && (result.execution.outputBytes <= binding.maximumOutputBytes
      || (!ready && result.code === "startup_probe_output_limit"))
    && (!ready || (
      result.execution.exitCode !== null
      && binding.expectedExitCodes.includes(result.execution.exitCode)
      && result.execution.signal === null
      && result.execution.spawnErrorCode === null
      && result.execution.outputBytes > 0
      && typeof result.execution.outputSha256 === "string"
      && /^[a-f0-9]{64}$/u.test(result.execution.outputSha256)
    ))
    && (!ready || (
      boundary.networkIsolationEnforced
      && boundary.filesystemWriteIsolationEnforced
      && boundary.immutableSnapshotExecutionEnforced
      && validExecutableIdentity(result.executableIdentity)
    ));
}

function internalFailure(
  binding: ReviewedLocalToolBinding,
  now: Date,
): ToolExecutionPreflightResult {
  return deepFreeze({
    schemaVersion: "ti-scale.tool-execution-preflight.v2",
    toolId: binding.toolId,
    status: "unavailable",
    code: "startup_probe_failed",
    checkedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + binding.ttlMs).toISOString(),
    bindingSha256: binding.bindingSha256,
    probeBoundary: {
      shell: false,
      targetArgumentsSupplied: false,
      providerArgumentsSupplied: false,
      mcpArgumentsSupplied: false,
      networkIsolationEnforced: false,
      filesystemWriteIsolationEnforced: false,
      immutableSnapshotExecutionEnforced: false,
      externalContact: "not_measured",
    },
    executableIdentity: null,
    noNewPrivileges: null,
    explanation: "The bounded local readiness runner could not complete this reviewed version/help probe. No mission target, provider, or MCP arguments were supplied; external contact was not independently measured.",
    remediation: "Inspect the isolated local readiness worker and repeat the exact reviewed startup probe after the local fault is resolved.",
    execution: {
      exitCode: null,
      signal: null,
      spawnErrorCode: null,
      outputBytes: 0,
      outputSha256: null,
    },
  } satisfies ToolExecutionPreflightResult);
}

function receipt(
  preflight: ToolExecutionPreflightResult,
  binding: ReviewedLocalToolBinding,
  registry: ToolBindingRegistryDescriptor,
  runnerError: boolean,
): ToolBindingReadinessReceipt {
  const spawnErrorCode = preflight.execution.spawnErrorCode;
  const safeSpawnErrorCode = spawnErrorCode && /^[A-Z][A-Z0-9_]{0,63}$/u.test(spawnErrorCode)
    ? spawnErrorCode
    : null;
  return deepFreeze({
    schemaVersion: TOOL_BINDING_READINESS_RECEIPT_SCHEMA_VERSION,
    registryVersion: registry.registryVersion,
    registrySha256: registry.registrySha256,
    runtimeManifestSha256: registry.runtimeManifestSha256,
    toolId: binding.toolId,
    registryBindingSha256: binding.bindingSha256,
    preflightBindingSha256: runnerError ? null : preflight.bindingSha256,
    status: preflight.status,
    code: runnerError ? "readiness_runner_error" : preflight.code,
    checkedAt: preflight.checkedAt,
    expiresAt: preflight.expiresAt,
    probeBoundary: preflight.probeBoundary,
    executableIdentity: preflight.executableIdentity,
    grantsMissionExecution: false,
    privilegeBoundary: {
      noNewPrivileges: preflight.noNewPrivileges,
      capabilityTransitionConflictObserved:
        preflight.code === "no_new_privileges_capability_conflict",
    },
    explanation: preflight.explanation,
    remediation: preflight.remediation,
    execution: { ...preflight.execution, spawnErrorCode: safeSpawnErrorCode },
  });
}

/**
 * Sequential startup runner for the exact local binding registry. Running
 * sequentially bounds process pressure; a single-flight guard prevents two
 * readiness waves from invoking the same reviewed probes concurrently.
 */
export class ToolBindingReadinessRunner {
  private readonly receipts = new Map<string, ToolBindingReadinessReceipt>();
  private readonly preflightResults = new Map<string, ToolExecutionPreflightResult>();
  private readonly attempted = new Set<string>();
  private activeRun: Promise<ToolBindingReadinessSnapshot> | undefined;
  private stopping = false;
  private monitoring = false;
  private refreshTimer: unknown;

  constructor(
    readonly registry: ToolBindingRegistry,
    private readonly preflight: ToolExecutionPreflightService =
      new ToolExecutionPreflightService(),
    private readonly clock: () => Date = () => new Date(),
    private readonly timers: ToolBindingReadinessTimerEnvironment = defaultTimerEnvironment(),
  ) {}

  private refreshIntervalMs(): number | null {
    const ttls = this.registry.list().map(({ ttlMs }) => ttlMs);
    if (ttls.length === 0) return null;
    return Math.max(1_000, Math.floor(Math.min(...ttls) / 2));
  }

  private scheduleRefresh(): void {
    const intervalMs = this.refreshIntervalMs();
    if (!this.monitoring || this.stopping || intervalMs === null) return;
    this.refreshTimer = this.timers.set(() => {
      this.refreshTimer = undefined;
      void this.runAll().then(
        () => this.scheduleRefresh(),
        () => this.scheduleRefresh(),
      );
    }, intervalMs);
  }

  /** Starts one immediate wave and refreshes before the shortest receipt TTL. */
  startMonitoring(): Promise<ToolBindingReadinessSnapshot> {
    if (this.monitoring) return this.activeRun ?? Promise.resolve(this.snapshot());
    if (this.stopping) return Promise.resolve(this.snapshot());
    this.monitoring = true;
    const first = this.runAll();
    void first.then(
      () => this.scheduleRefresh(),
      () => this.scheduleRefresh(),
    );
    return first;
  }

  /** Executes every registered binding once for this wave, including fresh cached bindings. */
  runAll(): Promise<ToolBindingReadinessSnapshot> {
    if (this.activeRun) return this.activeRun;
    if (this.stopping) return Promise.resolve(this.snapshot());
    this.activeRun = this.executeAll().finally(() => {
      this.activeRun = undefined;
    });
    return this.activeRun;
  }

  private async executeAll(): Promise<ToolBindingReadinessSnapshot> {
    this.attempted.clear();
    for (const binding of this.registry.list()) {
      if (this.stopping) break;
      this.attempted.add(binding.toolId);
      const spec = this.registry.toPreflightSpec(binding.toolId);
      if (!spec) throw new Error(`Registry lost binding ${binding.toolId}`);
      let result: ToolExecutionPreflightResult;
      let runnerError = false;
      try {
        result = clonePreflight(await this.preflight.check(spec));
        if (!preflightMatchesBinding(result, binding, spec, this.clock())) {
          runnerError = true;
          result = internalFailure(binding, this.clock());
        }
      } catch {
        runnerError = true;
        result = internalFailure(binding, this.clock());
      }
      this.preflightResults.set(binding.toolId, result);
      this.receipts.set(
        binding.toolId,
        receipt(result, binding, this.registry.descriptor, runnerError),
      );
    }
    return this.snapshot();
  }

  /**
   * Prevents new probes and waits only for the currently bounded probe before
   * ending the wave. It never starts the next binding during shutdown.
   */
  beginStop(): void {
    this.stopping = true;
    this.monitoring = false;
    if (this.refreshTimer !== undefined) {
      this.timers.clear(this.refreshTimer);
      this.refreshTimer = undefined;
    }
  }

  async stop(): Promise<ToolBindingReadinessSnapshot> {
    this.beginStop();
    if (this.activeRun) await this.activeRun;
    return this.snapshot();
  }

  /** Immutable, raw-output-free receipt suitable for diagnostics and audit persistence. */
  readReceipt(toolId: string): ToolBindingReadinessReceipt | undefined {
    return this.receipts.get(toolId);
  }

  /** Direct bridge for CapabilitySelfTestService.readToolExecutionPreflight. */
  readToolExecutionPreflight(toolId: string): ToolExecutionPreflightResult | undefined {
    return this.preflightResults.get(toolId);
  }

  snapshot(): ToolBindingReadinessSnapshot {
    const now = this.clock();
    const registeredIds = new Set(this.registry.list().map(({ toolId }) => toolId));
    const ordered = this.registry.list()
      .map(({ toolId }) => this.receipts.get(toolId))
      .filter((entry): entry is ToolBindingReadinessReceipt => entry !== undefined);
    const unexpected = [...this.receipts.keys()].filter((toolId) => !registeredIds.has(toolId));
    const stale = ordered.filter(({ expiresAt }) => {
      const expiry = Date.parse(expiresAt);
      return !Number.isFinite(expiry) || expiry <= now.getTime();
    }).length;
    const registered = this.registry.descriptor.registeredBindingCount;
    const reported = ordered.length;
    const missing = registered - reported;
    const complete = reported === registered && missing === 0 && unexpected.length === 0;
    const noProbes = ordered.length === 0;
    return deepFreeze({
      schemaVersion: TOOL_BINDING_READINESS_SNAPSHOT_SCHEMA_VERSION,
      checkedAt: now.toISOString(),
      readOnly: true,
      grantsMissionExecution: false,
      probeBoundary: {
        shell: false,
        targetArgumentsSupplied: false,
        providerArgumentsSupplied: false,
        mcpArgumentsSupplied: false,
        networkIsolationEnforced: noProbes
          ? null
          : ordered.every(({ probeBoundary }) => probeBoundary.networkIsolationEnforced),
        filesystemWriteIsolationEnforced: noProbes
          ? null
          : ordered.every(({ probeBoundary }) => probeBoundary.filesystemWriteIsolationEnforced),
        immutableSnapshotExecutionEnforced: noProbes
          ? null
          : ordered.every(({ probeBoundary }) =>
              probeBoundary.immutableSnapshotExecutionEnforced),
        externalContact: noProbes ? "not_applicable" : "not_measured",
      },
      registry: this.registry.descriptor,
      accounting: {
        registered,
        attempted: this.attempted.size,
        reported,
        missing,
        unexpected: unexpected.length,
        ready: ordered.filter(({ status }) => status === "ready").length,
        unavailable: ordered.filter(({ status }) => status === "unavailable").length,
        fresh: ordered.length - stale,
        stale,
        complete,
        current: complete && stale === 0,
      },
      receipts: Object.freeze([...ordered]),
    });
  }
}

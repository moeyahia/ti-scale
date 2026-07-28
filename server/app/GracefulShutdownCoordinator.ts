export type ShutdownComponentState =
  | "pending"
  | "running"
  | "stopped"
  | "failed"
  | "skipped";

export interface GracefulShutdownComponent {
  /** Stable, operator-readable identity used in timeout diagnostics. */
  readonly name: string;
  /** Synchronous producer fence broadcast before any ordered await begins. */
  beginStop?(): void;
  stop(): void | Promise<void>;
}

export interface GracefulShutdownPhase {
  readonly name: string;
  /** Components in one phase are independent and stop concurrently. */
  readonly components: readonly GracefulShutdownComponent[];
}

export interface GracefulShutdownFinalizer {
  readonly name: string;
  /** Defaults to true. Unsafe ownership release can opt out on hard timeout. */
  readonly runOnTimeout?: boolean;
  /**
   * Finalizers must be synchronous and bounded. They are reserved for local
   * handles such as a process-wide writer lease and its dedicated database.
   * They run exactly once even when the normal drain reaches its deadline.
   */
  finalize(): void;
}

export interface GracefulShutdownComponentResult {
  readonly phase: string;
  readonly name: string;
  readonly state: ShutdownComponentState;
  readonly durationMs: number | null;
  readonly failureName: string | null;
}

export interface GracefulShutdownReport {
  readonly signal: string;
  readonly outcome: "completed" | "failed" | "timed_out";
  readonly startedAt: string;
  readonly completedAt: string;
  readonly durationMs: number;
  readonly deadlineMs: number;
  readonly pendingComponentNames: readonly string[];
  readonly failedComponentNames: readonly string[];
  readonly components: readonly GracefulShutdownComponentResult[];
}

interface MutableComponentResult {
  readonly phase: string;
  readonly name: string;
  state: ShutdownComponentState;
  startedAtMs: number | null;
  durationMs: number | null;
  failureName: string | null;
}

export interface GracefulShutdownCoordinatorOptions {
  readonly deadlineMs: number;
  readonly phases: readonly GracefulShutdownPhase[];
  readonly finalizers?: readonly GracefulShutdownFinalizer[];
  /** Synchronous admission fence. No new work may enter after it returns. */
  readonly closeAdmission: () => void;
  /** Synchronous emergency transport cleanup invoked at the hard deadline. */
  readonly forceClose?: (pendingComponentNames: readonly string[]) => void;
  readonly now?: () => Date;
  /** Monotonic clock used for elapsed time and component durations. */
  readonly monotonicNow?: () => number;
}

function errorName(error: unknown): string {
  if (error instanceof Error && error.name.trim()) return error.name.trim();
  return "UnknownShutdownError";
}

function assertName(value: string, kind: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u.test(value)) {
    throw new Error(`${kind} name is invalid`);
  }
}

function immutableReport(
  signal: string,
  startedAt: Date,
  completedAt: Date,
  durationMs: number,
  deadlineMs: number,
  results: readonly MutableComponentResult[],
  timedOut: boolean,
  lifecycleFailures: readonly string[],
): GracefulShutdownReport {
  const components = results.map((result) => Object.freeze({
    phase: result.phase,
    name: result.name,
    state: result.state,
    durationMs: result.durationMs,
    failureName: result.failureName,
  } satisfies GracefulShutdownComponentResult));
  const pendingComponentNames = components
    .filter(({ state }) => state === "pending" || state === "running" || state === "skipped")
    .map(({ name }) => name);
  const failedComponentNames = [
    ...components.filter(({ state }) => state === "failed").map(({ name }) => name),
    ...lifecycleFailures,
  ];
  return Object.freeze({
    signal,
    outcome: timedOut
      ? "timed_out"
      : failedComponentNames.length > 0
        ? "failed"
        : "completed",
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: Math.max(0, Math.round(durationMs)),
    deadlineMs,
    pendingComponentNames: Object.freeze(pendingComponentNames),
    failedComponentNames: Object.freeze(failedComponentNames),
    components: Object.freeze(components),
  });
}

/**
 * A one-shot, phase-ordered shutdown boundary.
 *
 * Admission closes synchronously before any component stop begins. Components
 * inside a phase stop concurrently; later phases begin only after all members
 * of the preceding phase settle. A single monotonic wall-clock deadline covers
 * the entire drain. The returned promise and bounded finalizers are reused for
 * every signal, preventing duplicate lease release and database close.
 */
export class GracefulShutdownCoordinator {
  readonly #options: GracefulShutdownCoordinatorOptions;
  readonly #results: MutableComponentResult[];
  #shutdownPromise?: Promise<GracefulShutdownReport>;

  constructor(options: GracefulShutdownCoordinatorOptions) {
    if (!Number.isSafeInteger(options.deadlineMs)
      || options.deadlineMs < 1
      || options.deadlineMs > 27_000) {
      throw new RangeError("Graceful shutdown deadline must be between 1 and 27000 ms");
    }
    const names = new Set<string>();
    const results: MutableComponentResult[] = [];
    for (const phase of options.phases) {
      assertName(phase.name, "Shutdown phase");
      if (phase.components.length < 1) {
        throw new Error(`Shutdown phase ${phase.name} has no components`);
      }
      for (const component of phase.components) {
        assertName(component.name, "Shutdown component");
        if (names.has(component.name)) {
          throw new Error(`Duplicate shutdown component ${component.name}`);
        }
        names.add(component.name);
        results.push({
          phase: phase.name,
          name: component.name,
          state: "pending",
          startedAtMs: null,
          durationMs: null,
          failureName: null,
        });
      }
    }
    for (const finalizer of options.finalizers ?? []) {
      assertName(finalizer.name, "Shutdown finalizer");
      if (names.has(finalizer.name)) {
        throw new Error(`Duplicate shutdown component ${finalizer.name}`);
      }
      names.add(finalizer.name);
      results.push({
        phase: "finalize",
        name: finalizer.name,
        state: "pending",
        startedAtMs: null,
        durationMs: null,
        failureName: null,
      });
    }
    this.#options = options;
    this.#results = results;
  }

  shutdown(signal: string): Promise<GracefulShutdownReport> {
    if (this.#shutdownPromise) return this.#shutdownPromise;
    this.#shutdownPromise = this.#run(signal);
    return this.#shutdownPromise;
  }

  async #run(signal: string): Promise<GracefulShutdownReport> {
    const now = this.#options.now ?? (() => new Date());
    const monotonicNow = this.#options.monotonicNow ?? (() => performance.now());
    const startedAt = now();
    const startedAtMonotonic = monotonicNow();
    const lifecycleFailures: string[] = [];
    let timedOut = false;
    let deadlineObservedDurationMs: number | undefined;
    let deadlineResolve: (() => void) | undefined;
    const deadline = new Promise<void>((resolve) => { deadlineResolve = resolve; });
    const deadlineTimer = setTimeout(() => {
      timedOut = true;
      deadlineObservedDurationMs = monotonicNow() - startedAtMonotonic;
      deadlineResolve?.();
    }, this.#options.deadlineMs);
    // This timer is the service-manager deadline contract. It must remain a
    // referenced handle: once admission closes, a component can be represented
    // by a never-settling Promise with no OS handle of its own. Unref'ing the
    // only deadline would let the process exit naturally before diagnostics,
    // finalizers, and the explicit non-zero timeout result are produced.

    try {
      try {
        this.#options.closeAdmission();
      } catch (error) {
        lifecycleFailures.push(`admission:${errorName(error)}`);
      }

      // Stop every producer synchronously before waiting for any one phase.
      // This prevents a readiness refresh or scheduler from starting another
      // wave while an earlier runtime happens to be draining.
      for (const phase of this.#options.phases) {
        for (const component of phase.components) {
          try {
            component.beginStop?.();
          } catch (error) {
            lifecycleFailures.push(`begin-stop:${component.name}:${errorName(error)}`);
          }
        }
      }

      for (const phase of this.#options.phases) {
        if (timedOut) break;
        const phaseResults = phase.components.map((component) => {
          const result = this.#results.find(({ name }) => name === component.name)!;
          result.state = "running";
          result.startedAtMs = monotonicNow();
          return Promise.resolve()
            .then(() => component.stop())
            .then(() => { result.state = "stopped"; })
            .catch((error: unknown) => {
              result.state = "failed";
              result.failureName = errorName(error);
            })
            .finally(() => {
              result.durationMs = Math.max(
                0,
                monotonicNow() - (result.startedAtMs ?? monotonicNow()),
              );
            });
        });
        const settled = Promise.all(phaseResults).then(() => "settled" as const);
        const outcome = await Promise.race([
          settled,
          deadline.then(() => "deadline" as const),
        ]);
        if (outcome === "deadline") break;
      }

      if (timedOut) {
        const timedOutAt = monotonicNow();
        for (const result of this.#results) {
          if (result.state === "running" && result.startedAtMs !== null) {
            // The component promise may never settle, so its finally block may
            // never stamp a duration. Freeze the elapsed substage duration at
            // the observed deadline for exact timeout diagnostics.
            result.durationMs = Math.max(0, timedOutAt - result.startedAtMs);
          }
          if (result.phase !== "finalize" && result.state === "pending") {
            result.state = "skipped";
          }
        }
        const pending = this.#results
          .filter(({ phase, state }) => phase !== "finalize"
            && (state === "running" || state === "skipped"))
          .map(({ name }) => name);
        try {
          this.#options.forceClose?.(Object.freeze([...pending]));
        } catch (error) {
          lifecycleFailures.push(`force-close:${errorName(error)}`);
        }
      }
    } finally {
      clearTimeout(deadlineTimer);
      for (const finalizer of this.#options.finalizers ?? []) {
        const result = this.#results.find(({ name }) => name === finalizer.name)!;
        if (timedOut && finalizer.runOnTimeout === false) {
          result.state = "skipped";
          continue;
        }
        result.state = "running";
        result.startedAtMs = monotonicNow();
        try {
          finalizer.finalize();
          result.state = "stopped";
        } catch (error) {
          result.state = "failed";
          result.failureName = errorName(error);
        } finally {
          result.durationMs = Math.max(
            0,
            monotonicNow() - (result.startedAtMs ?? monotonicNow()),
          );
        }
      }
    }

    return immutableReport(
      signal,
      startedAt,
      now(),
      timedOut
        ? deadlineObservedDurationMs ?? monotonicNow() - startedAtMonotonic
        : monotonicNow() - startedAtMonotonic,
      this.#options.deadlineMs,
      this.#results,
      timedOut,
      lifecycleFailures,
    );
  }
}

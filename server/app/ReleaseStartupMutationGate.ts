import {
  RELEASE_STARTUP_MUTATION_BARRIER_PATH,
  releaseStartupMutationBarrierExists,
} from "../../scripts/release/ReleaseStartupMutationBarrier";

export const RELEASE_STARTUP_MUTATION_GATE_SCHEMA =
  "ti-scale.release-startup-mutation-gate.v1" as const;

export type ReleaseStartupMutationGateState =
  | "idle"
  | "deferred"
  | "activating"
  | "active"
  | "failed"
  | "stopped";

export interface ReleaseStartupMutationGateSnapshot {
  readonly schemaVersion: typeof RELEASE_STARTUP_MUTATION_GATE_SCHEMA;
  readonly state: ReleaseStartupMutationGateState;
  readonly barrierPath: string;
  readonly reason: string;
}

export interface ReleaseStartupMutationGateOptions {
  readonly barrierPath?: string;
  readonly pollIntervalMs?: number;
  readonly inspectBarrier?: (path: string) => boolean;
  readonly onDeferred?: (snapshot: ReleaseStartupMutationGateSnapshot) => void;
  readonly onActivated?: (snapshot: ReleaseStartupMutationGateSnapshot) => void;
  readonly onFailure?: (error: Error) => void;
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error("Unknown startup mutation activation failure");
}

/**
 * Keeps unconditional startup writers dormant while a root-owned functional
 * release journal is still nonterminal. The HTTP/application shell may become
 * live for exact release verification; provider probes, runtime reconciliation,
 * and other background mutation begin only after root removes the barrier.
 */
export class ReleaseStartupMutationGate {
  readonly #path: string;
  readonly #pollIntervalMs: number;
  readonly #inspect: (path: string) => boolean;
  readonly #onDeferred?: ReleaseStartupMutationGateOptions["onDeferred"];
  readonly #onActivated?: ReleaseStartupMutationGateOptions["onActivated"];
  readonly #onFailure?: ReleaseStartupMutationGateOptions["onFailure"];
  #state: ReleaseStartupMutationGateState = "idle";
  #reason = "Startup mutation producers have not been evaluated.";
  #timer?: ReturnType<typeof setInterval>;
  #activation?: Promise<void>;
  #activate?: () => void | Promise<void>;

  constructor(options: ReleaseStartupMutationGateOptions = {}) {
    this.#path = options.barrierPath ?? RELEASE_STARTUP_MUTATION_BARRIER_PATH;
    this.#pollIntervalMs = options.pollIntervalMs ?? 250;
    if (
      !Number.isSafeInteger(this.#pollIntervalMs) ||
      this.#pollIntervalMs < 10 || this.#pollIntervalMs > 10_000
    ) throw new RangeError("Release startup mutation poll interval must be between 10ms and 10s");
    this.#inspect = options.inspectBarrier ?? releaseStartupMutationBarrierExists;
    this.#onDeferred = options.onDeferred;
    this.#onActivated = options.onActivated;
    this.#onFailure = options.onFailure;
  }

  snapshot(): ReleaseStartupMutationGateSnapshot {
    return Object.freeze({
      schemaVersion: RELEASE_STARTUP_MUTATION_GATE_SCHEMA,
      state: this.#state,
      barrierPath: this.#path,
      reason: this.#reason,
    });
  }

  async start(activate: () => void | Promise<void>): Promise<ReleaseStartupMutationGateSnapshot> {
    if (this.#state !== "idle") throw new Error("Release startup mutation gate was already started");
    this.#activate = activate;
    let fenced: boolean;
    try { fenced = this.#inspect(this.#path); }
    catch (error) {
      this.#fail(asError(error));
      throw error;
    }
    if (!fenced) {
      await this.#activateOnce();
      return this.snapshot();
    }
    this.#state = "deferred";
    this.#reason = "A journal-owned release start is being verified; background mutation remains fenced.";
    this.#onDeferred?.(this.snapshot());
    this.#timer = setInterval(() => this.#poll(), this.#pollIntervalMs);
    this.#timer.unref?.();
    return this.snapshot();
  }

  beginStop(): void {
    if (this.#state === "stopped") return;
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = undefined;
    this.#state = "stopped";
    this.#reason = "Startup mutation gate is stopped.";
  }

  async stop(): Promise<void> {
    this.beginStop();
    await this.#activation;
  }

  #poll(): void {
    if (this.#state !== "deferred") return;
    try {
      if (this.#inspect(this.#path)) return;
    } catch (error) {
      this.#fail(asError(error));
      return;
    }
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = undefined;
    void this.#activateOnce().catch(() => undefined);
  }

  async #activateOnce(): Promise<void> {
    if (this.#state === "stopped" || this.#state === "active") return;
    if (this.#activation) return this.#activation;
    const activate = this.#activate;
    if (!activate) throw new Error("Release startup mutation gate has no activation callback");
    this.#state = "activating";
    this.#reason = "The release barrier cleared; background mutation producers are starting.";
    const pending = Promise.resolve().then(() => {
      // beginStop may run after activation was scheduled but before this
      // microtask executes. Recheck at the actual side-effect boundary.
      if (this.#state === "stopped") return;
      return activate();
    }).then(() => {
      if (this.#state === "stopped") return;
      this.#state = "active";
      this.#reason = "Background mutation producers are active after release verification.";
      this.#onActivated?.(this.snapshot());
    }).catch((error: unknown) => {
      const failure = asError(error);
      this.#fail(failure);
      throw failure;
    });
    this.#activation = pending;
    try { await pending; }
    finally {
      if (this.#activation === pending) this.#activation = undefined;
    }
  }

  #fail(error: Error): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = undefined;
    if (this.#state === "stopped") return;
    this.#state = "failed";
    this.#reason = `Background mutation remains fenced: ${error.message}`;
    this.#onFailure?.(error);
  }
}

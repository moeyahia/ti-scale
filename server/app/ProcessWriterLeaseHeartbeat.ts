import type {
  CanonicalDatabaseLeaseHandle,
} from "../maintenance";
import { CanonicalDatabaseLeaseLostError } from "../maintenance";

export interface ProcessWriterLeaseRenewalPort {
  renew(
    handle: CanonicalDatabaseLeaseHandle,
    ttlMs: number,
  ): CanonicalDatabaseLeaseHandle;
}

export interface ProcessWriterLeaseHeartbeatTimer {
  cancel(): void;
  unref(): void;
}

export type ProcessWriterLeaseHeartbeatScheduler = (
  callback: () => void,
  delayMs: number,
) => ProcessWriterLeaseHeartbeatTimer;

export type ProcessWriterLeaseHeartbeatTransition =
  | {
      readonly state: "contended";
      readonly sqliteCode: string;
      readonly deadlineAt: string;
    }
  | {
      readonly state: "recovered";
      readonly attempts: number;
    };

export interface ProcessWriterLeaseHeartbeatOptions {
  readonly leases: ProcessWriterLeaseRenewalPort;
  readonly initialHandle: CanonicalDatabaseLeaseHandle;
  readonly ttlMs: number;
  readonly intervalMs: number;
  readonly retryBaseMs?: number;
  readonly retryMaximumMs?: number;
  readonly contentionRetryWindowMs?: number;
  readonly expirySafetyMarginMs?: number;
  readonly clock?: () => Date;
  readonly schedule?: ProcessWriterLeaseHeartbeatScheduler;
  readonly onTransition?: (
    transition: ProcessWriterLeaseHeartbeatTransition,
  ) => void;
  readonly onFailure: (error: Error) => void;
}

const DEFAULT_RETRY_BASE_MS = 100;
const DEFAULT_RETRY_MAXIMUM_MS = 5_000;
const DEFAULT_CONTENTION_RETRY_WINDOW_MS = 30_000;
const DEFAULT_EXPIRY_SAFETY_MARGIN_MS = 60_000;

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${label} must be a positive integer`);
  }
  return value;
}

function defaultSchedule(
  callback: () => void,
  delayMs: number,
): ProcessWriterLeaseHeartbeatTimer {
  const timer = setTimeout(callback, delayMs);
  return {
    cancel: () => clearTimeout(timer),
    unref: () => timer.unref?.(),
  };
}

function sqliteErrorCode(error: unknown): string {
  if (!error || typeof error !== "object") return "";
  const code = (error as { readonly code?: unknown }).code;
  return typeof code === "string" ? code.toUpperCase() : "";
}

/**
 * SQLite writer collisions do not prove that a durable lease was lost.
 * Recognize only SQLite's explicit transient lock result codes; message text
 * and unknown storage failures remain fail-closed.
 */
export function isTransientSqliteLeaseContention(error: unknown): boolean {
  const code = sqliteErrorCode(error);
  return code === "SQLITE_BUSY"
    || code.startsWith("SQLITE_BUSY_")
    || code === "SQLITE_LOCKED"
    || code.startsWith("SQLITE_LOCKED_");
}

export class ProcessWriterLeaseHeartbeatDeadlineError extends Error {
  readonly deadlineAt: string;
  readonly attempts: number;

  constructor(
    handle: CanonicalDatabaseLeaseHandle,
    deadlineAt: string,
    attempts: number,
    cause: unknown,
  ) {
    super(
      `Canonical writer lease ${handle.id} renewal remained busy through its fail-closed deadline ${deadlineAt}`,
      { cause },
    );
    this.name = "ProcessWriterLeaseHeartbeatDeadlineError";
    this.deadlineAt = deadlineAt;
    this.attempts = attempts;
  }
}

/**
 * Renews the standalone service's durable writer lease without allowing an
 * ordinary SQLite writer collision to impersonate lease loss.
 *
 * One timer is owned at a time. SQLITE_BUSY/SQLITE_LOCKED retries use bounded
 * exponential backoff, while a genuine fencing/ownership loss and every
 * unknown storage error fail closed immediately. Retries may never cross the
 * safety deadline before the currently durable lease expires.
 */
export class ProcessWriterLeaseHeartbeat {
  readonly #leases: ProcessWriterLeaseRenewalPort;
  readonly #ttlMs: number;
  readonly #intervalMs: number;
  readonly #retryBaseMs: number;
  readonly #retryMaximumMs: number;
  readonly #contentionRetryWindowMs: number;
  readonly #expirySafetyMarginMs: number;
  readonly #clock: () => Date;
  readonly #schedule: ProcessWriterLeaseHeartbeatScheduler;
  readonly #onTransition: (
    transition: ProcessWriterLeaseHeartbeatTransition,
  ) => void;
  readonly #onFailure: (error: Error) => void;

  #handle: CanonicalDatabaseLeaseHandle;
  #timer: ProcessWriterLeaseHeartbeatTimer | undefined;
  #started = false;
  #failed = false;
  #busyAttempts = 0;
  #lastBusyError: unknown;
  #contentionDeadlineMs: number | undefined;

  constructor(options: ProcessWriterLeaseHeartbeatOptions) {
    this.#leases = options.leases;
    this.#handle = options.initialHandle;
    this.#ttlMs = positiveInteger(options.ttlMs, "ttlMs");
    this.#intervalMs = positiveInteger(options.intervalMs, "intervalMs");
    this.#retryBaseMs = positiveInteger(
      options.retryBaseMs ?? DEFAULT_RETRY_BASE_MS,
      "retryBaseMs",
    );
    this.#retryMaximumMs = positiveInteger(
      options.retryMaximumMs ?? DEFAULT_RETRY_MAXIMUM_MS,
      "retryMaximumMs",
    );
    if (this.#retryMaximumMs < this.#retryBaseMs) {
      throw new RangeError("retryMaximumMs cannot be shorter than retryBaseMs");
    }
    this.#contentionRetryWindowMs = positiveInteger(
      options.contentionRetryWindowMs
        ?? DEFAULT_CONTENTION_RETRY_WINDOW_MS,
      "contentionRetryWindowMs",
    );
    this.#expirySafetyMarginMs = positiveInteger(
      options.expirySafetyMarginMs ?? DEFAULT_EXPIRY_SAFETY_MARGIN_MS,
      "expirySafetyMarginMs",
    );
    this.#clock = options.clock ?? (() => new Date());
    this.#schedule = options.schedule ?? defaultSchedule;
    this.#onTransition = options.onTransition ?? (() => undefined);
    this.#onFailure = options.onFailure;
    this.#assertHandleDeadlineUsable();
  }

  get currentHandle(): CanonicalDatabaseLeaseHandle {
    return this.#handle;
  }

  get isStarted(): boolean {
    return this.#started;
  }

  get hasFailed(): boolean {
    return this.#failed;
  }

  start(): void {
    if (this.#failed) {
      throw new Error("A failed process writer-lease heartbeat cannot be restarted");
    }
    if (this.#started) return;
    this.#started = true;
    this.#scheduleNext(this.#intervalMs);
  }

  stop(): void {
    this.#started = false;
    this.#timer?.cancel();
    this.#timer = undefined;
  }

  #assertHandleDeadlineUsable(): void {
    const expiresAtMs = Date.parse(this.#handle.expiresAt);
    if (!Number.isFinite(expiresAtMs)) {
      throw new TypeError("Canonical writer lease expiry is invalid");
    }
    if (expiresAtMs - this.#expirySafetyMarginMs <= this.#clock().getTime()) {
      throw new RangeError(
        "Canonical writer lease expiry must remain beyond its heartbeat safety margin",
      );
    }
  }

  #renewalDeadlineMs(): number {
    return Date.parse(this.#handle.expiresAt) - this.#expirySafetyMarginMs;
  }

  #activeDeadlineMs(): number {
    return this.#contentionDeadlineMs ?? this.#renewalDeadlineMs();
  }

  #scheduleNext(requestedDelayMs: number): void {
    if (!this.#started || this.#failed) return;
    if (this.#timer) {
      throw new Error("Process writer-lease heartbeat already owns a timer");
    }
    const remainingMs = this.#activeDeadlineMs() - this.#clock().getTime();
    if (remainingMs <= 0) {
      this.#failForBusyDeadline();
      return;
    }
    const delayMs = Math.max(1, Math.min(requestedDelayMs, remainingMs));
    this.#timer = this.#schedule(() => {
      this.#timer = undefined;
      this.#attemptRenewal();
    }, delayMs);
    this.#timer.unref();
  }

  #attemptRenewal(): void {
    if (!this.#started || this.#failed) return;
    if (this.#clock().getTime() >= this.#activeDeadlineMs()) {
      this.#failForBusyDeadline();
      return;
    }
    try {
      this.#handle = this.#leases.renew(this.#handle, this.#ttlMs);
      this.#assertHandleDeadlineUsable();
      const recoveredAttempts = this.#busyAttempts;
      this.#busyAttempts = 0;
      this.#lastBusyError = undefined;
      this.#contentionDeadlineMs = undefined;
      if (recoveredAttempts > 0) {
        this.#emitTransition({
          state: "recovered",
          attempts: recoveredAttempts,
        });
      }
      this.#scheduleNext(this.#intervalMs);
    } catch (error) {
      if (
        error instanceof CanonicalDatabaseLeaseLostError
        || !isTransientSqliteLeaseContention(error)
      ) {
        this.#fail(error instanceof Error ? error : new Error("Canonical writer lease renewal failed"));
        return;
      }
      this.#lastBusyError = error;
      if (this.#busyAttempts === 0) {
        this.#contentionDeadlineMs = Math.min(
          this.#renewalDeadlineMs(),
          this.#clock().getTime() + this.#contentionRetryWindowMs,
        );
      }
      this.#busyAttempts += 1;
      if (this.#busyAttempts === 1) {
        this.#emitTransition({
          state: "contended",
          sqliteCode: sqliteErrorCode(error),
          deadlineAt: new Date(this.#activeDeadlineMs()).toISOString(),
        });
      }
      const exponent = Math.min(this.#busyAttempts - 1, 30);
      const retryDelayMs = Math.min(
        this.#retryMaximumMs,
        this.#retryBaseMs * (2 ** exponent),
      );
      this.#scheduleNext(retryDelayMs);
    }
  }

  #failForBusyDeadline(): void {
    this.#fail(new ProcessWriterLeaseHeartbeatDeadlineError(
      this.#handle,
      new Date(this.#activeDeadlineMs()).toISOString(),
      this.#busyAttempts,
      this.#lastBusyError,
    ));
  }

  #fail(error: Error): void {
    if (this.#failed) return;
    this.#failed = true;
    this.stop();
    this.#onFailure(error);
  }

  #emitTransition(transition: ProcessWriterLeaseHeartbeatTransition): void {
    try {
      this.#onTransition(transition);
    } catch {
      // Diagnostics cannot weaken or interrupt the durable renewal boundary.
    }
  }
}

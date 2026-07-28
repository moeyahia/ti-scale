import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDatabaseConnection,
  migrateDatabase,
} from "../../db";
import {
  CanonicalDatabaseLeaseLostError,
  CanonicalDatabaseLeaseService,
  type CanonicalDatabaseLeaseHandle,
} from "../../maintenance";
import {
  isTransientSqliteLeaseContention,
  ProcessWriterLeaseHeartbeat,
  ProcessWriterLeaseHeartbeatDeadlineError,
  type ProcessWriterLeaseHeartbeatScheduler,
  type ProcessWriterLeaseHeartbeatTransition,
} from "../ProcessWriterLeaseHeartbeat";

interface ManualTimer {
  readonly callback: () => void;
  readonly delayMs: number;
  cancelled: boolean;
  unrefed: boolean;
}

class ManualHeartbeatRuntime {
  readonly #timers: ManualTimer[] = [];
  nowMs: number;

  constructor(now: Date) {
    this.nowMs = now.getTime();
  }

  readonly clock = (): Date => new Date(this.nowMs);

  readonly schedule: ProcessWriterLeaseHeartbeatScheduler = (callback, delayMs) => {
    const timer: ManualTimer = {
      callback,
      delayMs,
      cancelled: false,
      unrefed: false,
    };
    this.#timers.push(timer);
    return {
      cancel: () => {
        timer.cancelled = true;
      },
      unref: () => {
        timer.unrefed = true;
      },
    };
  };

  get pendingDelays(): readonly number[] {
    return this.#timers
      .filter((timer) => !timer.cancelled)
      .map((timer) => timer.delayMs);
  }

  runNext(): void {
    const index = this.#timers.findIndex((timer) => !timer.cancelled);
    if (index < 0) throw new Error("No heartbeat timer is pending");
    const [timer] = this.#timers.splice(index, 1);
    if (!timer) throw new Error("Heartbeat timer disappeared");
    expect(timer.unrefed).toBe(true);
    this.nowMs += timer.delayMs;
    timer.callback();
  }
}

function leaseHandle(
  now: Date,
  lifetimeMs = 10_000,
): CanonicalDatabaseLeaseHandle {
  return Object.freeze({
    id: "canonical_lease_process_test",
    mode: "writer",
    ownerId: "ti-scale-service:test",
    operation: "standalone-service-runtime",
    fencingToken: 7,
    acquiredAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + lifetimeMs).toISOString(),
  });
}

function sqliteContention(code = "SQLITE_BUSY"): Error & { readonly code: string } {
  return Object.assign(new Error("database is locked"), { code });
}

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("ProcessWriterLeaseHeartbeat", () => {
  test("recognizes only explicit SQLite busy and locked result codes as retryable", () => {
    expect(isTransientSqliteLeaseContention(sqliteContention("SQLITE_BUSY"))).toBe(true);
    expect(isTransientSqliteLeaseContention(sqliteContention("SQLITE_BUSY_SNAPSHOT"))).toBe(true);
    expect(isTransientSqliteLeaseContention(sqliteContention("SQLITE_LOCKED"))).toBe(true);
    expect(isTransientSqliteLeaseContention(sqliteContention("SQLITE_LOCKED_SHAREDCACHE"))).toBe(true);
    expect(isTransientSqliteLeaseContention(new Error("database is locked"))).toBe(false);
    expect(isTransientSqliteLeaseContention(
      Object.assign(new Error("disk I/O error"), { code: "SQLITE_IOERR" }),
    )).toBe(false);
  });

  test("retries transient contention with bounded backoff and resumes the normal cadence", () => {
    const startedAt = new Date("2026-07-25T10:00:00.000Z");
    const runtime = new ManualHeartbeatRuntime(startedAt);
    const failures: Error[] = [];
    const transitions: ProcessWriterLeaseHeartbeatTransition[] = [];
    let renewals = 0;
    const heartbeat = new ProcessWriterLeaseHeartbeat({
      leases: {
        renew(handle, ttlMs) {
          renewals += 1;
          if (renewals === 1) throw sqliteContention("SQLITE_BUSY");
          if (renewals === 2) throw sqliteContention("SQLITE_LOCKED");
          return Object.freeze({
            ...handle,
            expiresAt: new Date(runtime.nowMs + ttlMs).toISOString(),
          });
        },
      },
      initialHandle: leaseHandle(startedAt),
      ttlMs: 10_000,
      intervalMs: 100,
      retryBaseMs: 10,
      retryMaximumMs: 20,
      expirySafetyMarginMs: 1_000,
      clock: runtime.clock,
      schedule: runtime.schedule,
      onTransition: (transition) => transitions.push(transition),
      onFailure: (error) => failures.push(error),
    });

    heartbeat.start();
    expect(runtime.pendingDelays).toEqual([100]);
    runtime.runNext();
    expect(runtime.pendingDelays).toEqual([10]);
    runtime.runNext();
    expect(runtime.pendingDelays).toEqual([20]);
    runtime.runNext();

    expect(renewals).toBe(3);
    expect(failures).toEqual([]);
    expect(transitions).toEqual([
      {
        state: "contended",
        sqliteCode: "SQLITE_BUSY",
        deadlineAt: "2026-07-25T10:00:09.000Z",
      },
      {
        state: "recovered",
        attempts: 2,
      },
    ]);
    expect(heartbeat.hasFailed).toBe(false);
    expect(heartbeat.currentHandle.expiresAt).toBe("2026-07-25T10:00:10.130Z");
    expect(runtime.pendingDelays).toEqual([100]);
    heartbeat.stop();
    expect(runtime.pendingDelays).toEqual([]);
  });

  test("fails closed on a bounded contention deadline before lease expiry", () => {
    const startedAt = new Date("2026-07-25T10:00:00.000Z");
    const runtime = new ManualHeartbeatRuntime(startedAt);
    const failures: Error[] = [];
    let renewals = 0;
    const heartbeat = new ProcessWriterLeaseHeartbeat({
      leases: {
        renew() {
          renewals += 1;
          throw sqliteContention();
        },
      },
      initialHandle: leaseHandle(startedAt, 10_000),
      ttlMs: 10_000,
      intervalMs: 300,
      retryBaseMs: 400,
      retryMaximumMs: 800,
      contentionRetryWindowMs: 900,
      expirySafetyMarginMs: 100,
      clock: runtime.clock,
      schedule: runtime.schedule,
      onFailure: (error) => failures.push(error),
    });

    heartbeat.start();
    runtime.runNext();
    expect(runtime.pendingDelays).toEqual([400]);
    runtime.runNext();
    // The requested 800ms backoff is clamped to the remaining 500ms in the
    // bounded contention window, well before the durable lease's expiry.
    expect(runtime.pendingDelays).toEqual([500]);
    runtime.runNext();

    expect(renewals).toBe(2);
    expect(heartbeat.hasFailed).toBe(true);
    expect(heartbeat.isStarted).toBe(false);
    expect(failures).toHaveLength(1);
    expect(failures[0]).toBeInstanceOf(ProcessWriterLeaseHeartbeatDeadlineError);
    expect(failures[0]).toMatchObject({
      attempts: 2,
      deadlineAt: "2026-07-25T10:00:01.200Z",
    });
    expect(runtime.pendingDelays).toEqual([]);
  });

  test("terminates immediately for genuine lease loss and unknown storage faults", () => {
    for (const failure of [
      new CanonicalDatabaseLeaseLostError("fencing token changed"),
      Object.assign(new Error("disk I/O error"), { code: "SQLITE_IOERR" }),
    ]) {
      const startedAt = new Date("2026-07-25T10:00:00.000Z");
      const runtime = new ManualHeartbeatRuntime(startedAt);
      const failures: Error[] = [];
      const heartbeat = new ProcessWriterLeaseHeartbeat({
        leases: {
          renew() {
            throw failure;
          },
        },
        initialHandle: leaseHandle(startedAt),
        ttlMs: 10_000,
        intervalMs: 100,
        expirySafetyMarginMs: 1_000,
        clock: runtime.clock,
        schedule: runtime.schedule,
        onFailure: (error) => failures.push(error),
      });

      heartbeat.start();
      runtime.runNext();
      expect(failures).toEqual([failure]);
      expect(heartbeat.hasFailed).toBe(true);
      expect(runtime.pendingDelays).toEqual([]);
    }
  });

  test("returns promptly under a real external SQLite writer and renews after it clears", () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-process-lease-heartbeat-"));
    temporaryDirectories.push(directory);
    const filename = join(directory, "canonical.sqlite");
    const leaseDatabase = createDatabaseConnection({
      filename,
      busyTimeoutMs: 25,
    });
    migrateDatabase(leaseDatabase);
    const blockerDatabase = createDatabaseConnection({
      filename,
      fileMustExist: true,
      busyTimeoutMs: 0,
      verifyIntegrity: false,
    });
    const startedAt = new Date("2026-07-25T10:00:00.000Z");
    const runtime = new ManualHeartbeatRuntime(startedAt);
    const leases = new CanonicalDatabaseLeaseService(leaseDatabase, {
      clock: runtime.clock,
    });
    const initialHandle = leases.acquireWriter({
      ownerId: "ti-scale-service:test",
      operation: "standalone-service-runtime",
      ttlMs: 10_000,
    });
    const failures: Error[] = [];
    const transitions: ProcessWriterLeaseHeartbeatTransition[] = [];
    const heartbeat = new ProcessWriterLeaseHeartbeat({
      leases,
      initialHandle,
      ttlMs: 10_000,
      intervalMs: 100,
      retryBaseMs: 10,
      retryMaximumMs: 20,
      expirySafetyMarginMs: 1_000,
      clock: runtime.clock,
      schedule: runtime.schedule,
      onTransition: (transition) => transitions.push(transition),
      onFailure: (error) => failures.push(error),
    });

    try {
      blockerDatabase.exec("BEGIN IMMEDIATE");
      heartbeat.start();
      const attemptedAt = performance.now();
      runtime.runNext();
      const elapsedMs = performance.now() - attemptedAt;

      expect(elapsedMs).toBeLessThan(250);
      expect(Number(leaseDatabase.pragma("busy_timeout", { simple: true }))).toBe(25);
      expect(failures).toEqual([]);
      // Bun 1.3.14 exposes the real external-writer collision using the exact
      // stable SQLite result code consumed by the retry classifier.
      expect(transitions).toEqual([{
        state: "contended",
        sqliteCode: "SQLITE_BUSY",
        deadlineAt: "2026-07-25T10:00:09.000Z",
      }]);
      expect(heartbeat.hasFailed).toBe(false);
      expect(runtime.pendingDelays).toEqual([10]);

      blockerDatabase.exec("ROLLBACK");
      runtime.runNext();
      expect(failures).toEqual([]);
      expect(transitions).toEqual([
        {
          state: "contended",
          sqliteCode: "SQLITE_BUSY",
          deadlineAt: "2026-07-25T10:00:09.000Z",
        },
        {
          state: "recovered",
          attempts: 1,
        },
      ]);
      expect(heartbeat.hasFailed).toBe(false);
      expect(heartbeat.currentHandle.expiresAt).toBe("2026-07-25T10:00:10.110Z");
      expect(leases.assertActive(heartbeat.currentHandle).ownerId)
        .toBe("ti-scale-service:test");
    } finally {
      heartbeat.stop();
      if (blockerDatabase.inTransaction) blockerDatabase.exec("ROLLBACK");
      try {
        leases.release(heartbeat.currentHandle, "test-completed");
      } catch {
        // A failing assertion must not hide the primary regression result.
      }
      blockerDatabase.close();
      leaseDatabase.close();
    }
  });
});

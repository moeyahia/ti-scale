import { describe, expect, test } from "bun:test";
import { GracefulShutdownCoordinator } from "../GracefulShutdownCoordinator";

interface Deferred {
  readonly promise: Promise<void>;
  readonly resolve: () => void;
}

function deferred(): Deferred {
  let resolve!: () => void;
  const promise = new Promise<void>((complete) => { resolve = complete; });
  return { promise, resolve };
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

describe("GracefulShutdownCoordinator", () => {
  test("closes admission first, stops independent refreshes concurrently, preserves phase order, and finalizes once", async () => {
    const first = deferred();
    const second = deferred();
    const events: string[] = [];
    let finalized = 0;
    const coordinator = new GracefulShutdownCoordinator({
      deadlineMs: 1_000,
      closeAdmission() { events.push("admission-closed"); },
      phases: [
        {
          name: "readiness",
          components: [
            {
              name: "local-tool-refresh",
              async stop() {
                events.push("local-tool-started");
                await first.promise;
                events.push("local-tool-stopped");
              },
            },
            {
              name: "provider-refresh",
              async stop() {
                events.push("provider-started");
                await second.promise;
                events.push("provider-stopped");
              },
            },
          ],
        },
        {
          name: "canonical-data",
          components: [{
            name: "database",
            stop() { events.push("database-stopped"); },
          }],
        },
      ],
      finalizers: [{
        name: "writer-heartbeat",
        finalize() {
          finalized += 1;
          events.push("finalized");
        },
      }],
    });

    const shutdown = coordinator.shutdown("SIGTERM");
    expect(coordinator.shutdown("SIGINT")).toBe(shutdown);
    await delay(0);
    expect(events).toEqual([
      "admission-closed",
      "local-tool-started",
      "provider-started",
    ]);
    first.resolve();
    await delay(0);
    expect(events).not.toContain("database-stopped");
    second.resolve();

    const report = await shutdown;
    expect(report).toMatchObject({
      signal: "SIGTERM",
      outcome: "completed",
      pendingComponentNames: [],
      failedComponentNames: [],
    });
    expect(events).toEqual([
      "admission-closed",
      "local-tool-started",
      "provider-started",
      "local-tool-stopped",
      "provider-stopped",
      "database-stopped",
      "finalized",
    ]);
    expect(finalized).toBe(1);
    expect(report.components.map(({ name, state }) => [name, state])).toEqual([
      ["local-tool-refresh", "stopped"],
      ["provider-refresh", "stopped"],
      ["database", "stopped"],
      ["writer-heartbeat", "stopped"],
    ]);
  });

  test("multiple active readiness refreshes drain in the maximum individual duration, not their sum", async () => {
    const starts: number[] = [];
    const startedAt = performance.now();
    const coordinator = new GracefulShutdownCoordinator({
      deadlineMs: 500,
      closeAdmission() {},
      phases: [{
        name: "readiness",
        components: [35, 45, 55].map((duration, index) => ({
          name: `refresh-${index + 1}`,
          async stop() {
            starts.push(performance.now());
            await delay(duration);
          },
        })),
      }],
    });

    const report = await coordinator.shutdown("SIGTERM");
    const elapsed = performance.now() - startedAt;
    expect(report.outcome).toBe("completed");
    expect(Math.max(...starts) - Math.min(...starts)).toBeLessThan(20);
    expect(elapsed).toBeLessThan(140);
    expect(report.components.every(({ state }) => state === "stopped")).toBe(true);
  });

  test("hard deadline is fail-closed with exact running and skipped component diagnostics", async () => {
    const never = new Promise<void>(() => undefined);
    const forced: string[][] = [];
    let finalized = 0;
    const coordinator = new GracefulShutdownCoordinator({
      deadlineMs: 30,
      closeAdmission() {},
      forceClose(pending) { forced.push([...pending]); },
      phases: [
        {
          name: "readiness",
          components: [{ name: "stuck-readiness-refresh", stop: () => never }],
        },
        {
          name: "canonical-data",
          components: [{ name: "database", stop() {} }],
        },
      ],
      finalizers: [{
        name: "writer-heartbeat",
        finalize() { finalized += 1; },
      }],
    });

    const report = await coordinator.shutdown("SIGTERM");
    expect(report.outcome).toBe("timed_out");
    expect(report.pendingComponentNames).toEqual([
      "stuck-readiness-refresh",
      "database",
    ]);
    expect(forced).toEqual([[
      "stuck-readiness-refresh",
      "database",
    ]]);
    expect(report.components).toContainEqual(expect.objectContaining({
      phase: "readiness",
      name: "stuck-readiness-refresh",
      state: "running",
    }));
    const stuck = report.components.find(({ name }) => name === "stuck-readiness-refresh");
    expect(stuck?.durationMs).not.toBeNull();
    expect(stuck?.durationMs ?? 0).toBeGreaterThanOrEqual(20);
    expect(report.components).toContainEqual(expect.objectContaining({
      name: "database",
      state: "skipped",
    }));
    expect(report.components).toContainEqual(expect.objectContaining({
      name: "writer-heartbeat",
      state: "stopped",
    }));
    expect(finalized).toBe(1);
  });

  test("component failures remain release-ineligible while later cleanup and the finalizer still run", async () => {
    let databaseStopped = false;
    let finalized = 0;
    const coordinator = new GracefulShutdownCoordinator({
      deadlineMs: 200,
      closeAdmission() {},
      phases: [
        {
          name: "runtime",
          components: [{
            name: "guided-runtime",
            stop() { throw new TypeError("raw sensitive detail is not retained"); },
          }],
        },
        {
          name: "canonical-data",
          components: [{
            name: "database",
            stop() { databaseStopped = true; },
          }],
        },
      ],
      finalizers: [{
        name: "writer-heartbeat",
        finalize() { finalized += 1; },
      }],
    });

    const report = await coordinator.shutdown("SIGTERM");
    expect(report.outcome).toBe("failed");
    expect(report.failedComponentNames).toEqual(["guided-runtime"]);
    expect(report.components).toContainEqual(expect.objectContaining({
      name: "guided-runtime",
      state: "failed",
      failureName: "TypeError",
    }));
    expect(databaseStopped).toBe(true);
    expect(finalized).toBe(1);
  });
});

import { describe, expect, test } from "bun:test";
import { QueryCache } from "../../../src/data/cache/QueryProvider";
import { querySnapshotExpired } from "../../../src/data/cache/querySnapshotFreshness";

describe("QueryCache mutation reconciliation", () => {
  test("waits out a pre-mutation read and then owns the cache with a fresh canonical read", async () => {
    const cache = new QueryCache();
    let releasePreMutation!: () => void;
    const preMutationGate = new Promise<void>((resolve) => {
      releasePreMutation = resolve;
    });
    let readCount = 0;
    const loader = async () => {
      readCount += 1;
      if (readCount === 1) {
        await preMutationGate;
        return { version: 1, source: "pre-mutation" };
      }
      return { version: 2, source: "canonical-reconciliation" };
    };

    const staleRead = cache.fetch("brain-vault", loader, 0, true);
    const reconciliation = cache.reconcile("brain-vault", loader, 0);

    await Promise.resolve();
    expect(readCount).toBe(1);
    releasePreMutation();
    expect(await staleRead).toEqual({ version: 1, source: "pre-mutation" });
    expect(await reconciliation).toEqual({ version: 2, source: "canonical-reconciliation" });
    expect(readCount).toBe(2);
    expect(cache.read<{ version: number; source: string }>("brain-vault")?.data).toEqual({
      version: 2,
      source: "canonical-reconciliation",
    });
  });

  test("blocks lazy loaders after lifecycle suspension and refreshes mounted keys after resume", async () => {
    const cache = new QueryCache();
    let notifications = 0;
    const unsubscribe = cache.subscribe("late-page-captures", () => {
      notifications += 1;
    });
    let loaderCalls = 0;

    cache.suspend();
    let suspendedError: unknown;
    try {
      await cache.fetch("late-page-captures", async () => {
        loaderCalls += 1;
        return { items: ["must-not-load"] };
      }, 0, true);
    } catch (error) {
      suspendedError = error;
    }

    expect(suspendedError).toBeInstanceOf(DOMException);
    expect((suspendedError as DOMException).name).toBe("AbortError");
    expect(loaderCalls).toBe(0);
    expect(notifications).toBe(0);
    expect(cache.read("late-page-captures")?.updatedAt).toBe(0);

    cache.resume();
    expect(notifications).toBe(1);
    expect(await cache.fetch("late-page-captures", async () => {
      loaderCalls += 1;
      return { items: [] };
    }, 0, true)).toEqual({ items: [] });
    expect(loaderCalls).toBe(1);
    unsubscribe();
  });

  test("preserves an in-flight read across a same-key subscriber handoff", async () => {
    const cache = new QueryCache();
    let releaseRead!: () => void;
    const readGate = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    let requestSignal: AbortSignal | undefined;
    const firstSubscriber = cache.subscribe("mission-runtime:mission-1", () => undefined);
    const request = cache.fetch("mission-runtime:mission-1", async (signal) => {
      requestSignal = signal;
      await readGate;
      return { missionId: "mission-1", runs: ["run-successor"] };
    }, 0, true);

    await Promise.resolve();
    expect(requestSignal).toBeDefined();
    firstSubscriber();
    const successorSubscriber = cache.subscribe(
      "mission-runtime:mission-1",
      () => undefined,
    );
    await Promise.resolve();

    expect(requestSignal?.aborted).toBe(false);
    releaseRead();
    expect(await request).toEqual({
      missionId: "mission-1",
      runs: ["run-successor"],
    });
    successorSubscriber();
  });

  test("cancels an in-flight read once its key remains genuinely unused", async () => {
    const cache = new QueryCache();
    let requestSignal: AbortSignal | undefined;
    const unsubscribe = cache.subscribe("mission-runtime:abandoned", () => undefined);
    const request = cache.fetch("mission-runtime:abandoned", (signal) => {
      requestSignal = signal;
      return new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => {
          reject(new DOMException("Unused mission read cancelled", "AbortError"));
        }, { once: true });
      });
    }, 0, true);
    const outcome = request.catch((error: unknown) => error);

    await Promise.resolve();
    unsubscribe();
    await Promise.resolve();
    await Promise.resolve();

    expect(requestSignal?.aborted).toBe(true);
    const error = await outcome;
    expect(error).toBeInstanceOf(DOMException);
    expect((error as DOMException).name).toBe("AbortError");
    expect(cache.read("mission-runtime:abandoned")?.promise).toBeUndefined();
  });

  test("a deferred unused-key cancellation cannot abort a replacement read", async () => {
    const cache = new QueryCache();
    let firstSignal: AbortSignal | undefined;
    const unsubscribe = cache.subscribe("mission-runtime:replacement", () => undefined);
    const firstRequest = cache.fetch("mission-runtime:replacement", (signal) => {
      firstSignal = signal;
      return new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => {
          reject(new DOMException("Superseded mission read cancelled", "AbortError"));
        }, { once: true });
      });
    }, 0, true);
    const firstOutcome = firstRequest.catch((error: unknown) => error);

    await Promise.resolve();
    unsubscribe();
    cache.cancelAll();

    let releaseReplacement!: () => void;
    const replacementGate = new Promise<void>((resolve) => {
      releaseReplacement = resolve;
    });
    let replacementSignal: AbortSignal | undefined;
    const replacement = cache.fetch("mission-runtime:replacement", async (signal) => {
      replacementSignal = signal;
      await replacementGate;
      return { version: 2 };
    }, 0, true);

    await Promise.resolve();
    await Promise.resolve();
    expect(firstSignal?.aborted).toBe(true);
    expect((await firstOutcome as DOMException).name).toBe("AbortError");
    expect(replacementSignal?.aborted).toBe(false);
    releaseReplacement();
    expect(await replacement).toEqual({ version: 2 });
  });

  test("preserves an event invalidation that arrives while a failing canonical read is pending", async () => {
    const cache = new QueryCache();
    let releaseFailedRead!: () => void;
    const failedReadGate = new Promise<void>((resolve) => {
      releaseFailedRead = resolve;
    });
    let readCount = 0;
    const loader = async () => {
      readCount += 1;
      if (readCount === 1) {
        await failedReadGate;
        throw new Error("The first canonical read is unavailable");
      }
      return { version: 2, source: "post-invalidation-recovery" };
    };
    let recovered: Promise<{ version: number; source: string }> | undefined;
    const unsubscribe = cache.subscribe("run-plans:pending-invalidation", () => {
      const current = cache.read("run-plans:pending-invalidation");
      if (current?.updatedAt === 0 && !current.promise) {
        recovered = cache.fetch("run-plans:pending-invalidation", loader, 0, true);
      }
    });

    const failing = cache.fetch("run-plans:pending-invalidation", loader, 0, true);
    await Promise.resolve();
    expect(readCount).toBe(1);
    cache.invalidate("run-plans:pending-invalidation");
    expect(cache.read("run-plans:pending-invalidation")?.promise).toBeDefined();

    releaseFailedRead();
    await expect(failing).rejects.toThrow("The first canonical read is unavailable");
    await Promise.resolve();
    expect(recovered).toBeDefined();
    expect(await recovered).toEqual({ version: 2, source: "post-invalidation-recovery" });
    expect(readCount).toBe(2);
    expect(cache.read<{ version: number; source: string }>("run-plans:pending-invalidation")?.data).toEqual({
      version: 2,
      source: "post-invalidation-recovery",
    });
    unsubscribe();
  });

  test("does not renew a retained snapshot when its refresh fails", async () => {
    const cache = new QueryCache();
    await cache.fetch("model-catalog", async () => ({ items: ["live"] }), 0, true);
    const originalUpdatedAt = cache.read("model-catalog")?.updatedAt;

    await expect(cache.fetch("model-catalog", async () => {
      throw new Error("catalog offline");
    }, 0, true)).rejects.toThrow("catalog offline");

    expect(cache.read("model-catalog")).toMatchObject({
      data: { items: ["live"] },
      error: expect.objectContaining({ message: "catalog offline" }),
      updatedAt: originalUpdatedAt,
    });
  });

  test("clears a prior visible error while its bounded retry is in flight", async () => {
    const cache = new QueryCache();
    await expect(cache.fetch("research-lab", async () => {
      throw new Error("Research snapshot unavailable");
    }, 0, true)).rejects.toThrow("Research snapshot unavailable");
    expect(cache.read("research-lab")?.error?.message).toBe(
      "Research snapshot unavailable",
    );

    let releaseRetry!: () => void;
    const retryGate = new Promise<void>((resolve) => {
      releaseRetry = resolve;
    });
    const retry = cache.fetch("research-lab", async () => {
      await retryGate;
      return { status: "ready" };
    }, 0, true);

    await Promise.resolve();
    const pendingRetry = cache.read("research-lab");
    expect(pendingRetry?.error).toBeUndefined();
    expect(pendingRetry?.promise).toBeDefined();
    expect(pendingRetry?.updatedAt).toBe(0);
    releaseRetry();
    expect(await retry).toEqual({ status: "ready" });
    const recovered = cache.read("research-lab");
    expect(recovered?.data).toEqual({ status: "ready" });
    expect(recovered?.error).toBeUndefined();
  });

  test("treats invalidated and over-age query snapshots as expired", () => {
    expect(querySnapshotExpired(0, 1_000, 10_000)).toBe(true);
    expect(querySnapshotExpired(9_001, 1_000, 10_000)).toBe(false);
    expect(querySnapshotExpired(9_000, 1_000, 10_000)).toBe(true);
    expect(querySnapshotExpired(null, 1_000, 10_000)).toBe(false);
  });
});

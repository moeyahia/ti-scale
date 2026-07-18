import { describe, expect, test } from "bun:test";
import { QueryCache } from "../../../src/data/cache/QueryProvider";

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
});

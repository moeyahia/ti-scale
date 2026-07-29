import { describe, expect, test } from "bun:test";
import {
  classifyLocationChange,
  MECHANICAL_ROUTE_TIMING,
  MechanicalRouteTransitionController,
  shouldInterceptAppLinkClick,
  type MechanicalRouteTransitionRuntime,
  type RouteTransitionPresentation,
  type ViewTransitionHandle,
} from "../../../src/app/router/navigation";

function nativeTransition(update: () => void | Promise<void>): ViewTransitionHandle {
  const updateCallbackDone = Promise.resolve().then(update).then(() => undefined);
  return {
    updateCallbackDone,
    finished: updateCallbackDone.then(() => undefined),
    skipTransition: () => undefined,
  };
}

describe("mechanical route transition controller", () => {
  test("uses the native View Transition API after deterministic disassembly", async () => {
    const presentations: RouteTransitionPresentation[] = [];
    const sleeps: number[] = [];
    const commits: string[] = [];
    let nativeCalls = 0;
    const runtime: MechanicalRouteTransitionRuntime = {
      shouldBypass: () => false,
      sleep: async (milliseconds) => {
        sleeps.push(milliseconds);
        return true;
      },
      publish: (presentation) => presentations.push(presentation),
      startViewTransition: (update) => {
        nativeCalls += 1;
        return nativeTransition(update);
      },
    };

    const outcome = await new MechanicalRouteTransitionController(runtime).transition({
      from: "/",
      to: "/missions",
      commit: (mode) => { commits.push(mode); },
    });

    expect(outcome).toBe("completed");
    expect(nativeCalls).toBe(1);
    expect(sleeps).toEqual([MECHANICAL_ROUTE_TIMING.disassembleMs]);
    expect(commits).toEqual(["native"]);
    expect(presentations.map(({ phase }) => phase)).toEqual([
      "disassembling",
      "committing",
      "assembling",
      "idle",
    ]);
    expect(presentations[0]).toMatchObject({ mode: "native", from: "/", to: "/missions" });
  });

  test("runs the same finite ordering without the native API", async () => {
    const presentations: RouteTransitionPresentation[] = [];
    const sleeps: number[] = [];
    const commits: string[] = [];
    const runtime: MechanicalRouteTransitionRuntime = {
      shouldBypass: () => false,
      sleep: async (milliseconds) => {
        sleeps.push(milliseconds);
        return true;
      },
      publish: (presentation) => presentations.push(presentation),
    };

    const outcome = await new MechanicalRouteTransitionController(runtime).transition({
      from: "/missions",
      to: "/brain",
      commit: (mode) => { commits.push(mode); },
    });

    expect(outcome).toBe("completed");
    expect(commits).toEqual(["fallback"]);
    expect(sleeps).toEqual([
      MECHANICAL_ROUTE_TIMING.disassembleMs,
      MECHANICAL_ROUTE_TIMING.fallbackAssembleMs,
    ]);
    expect(presentations.map(({ phase }) => phase)).toEqual([
      "disassembling",
      "committing",
      "assembling",
      "idle",
    ]);
    expect(MECHANICAL_ROUTE_TIMING.disassembleMs + MECHANICAL_ROUTE_TIMING.fallbackAssembleMs)
      .toBeLessThan(MECHANICAL_ROUTE_TIMING.maximumMs);
    expect(MECHANICAL_ROUTE_TIMING.maximumMs).toBeLessThan(900);
  });

  test("bypasses all presentation work for reduced motion or a hidden document", async () => {
    for (const bypassReason of ["reduced-motion", "hidden-document"] as const) {
      const presentations: RouteTransitionPresentation[] = [];
      const commits: string[] = [];
      let nativeCalls = 0;
      const controller = new MechanicalRouteTransitionController({
        shouldBypass: () => true,
        sleep: async () => { throw new Error("bypassed navigation must not sleep"); },
        publish: (presentation) => presentations.push(presentation),
        startViewTransition: (update) => {
          nativeCalls += 1;
          return nativeTransition(update);
        },
      });

      expect(await controller.transition({
        from: "/",
        to: `/system?reason=${bypassReason}`,
        commit: (mode) => { commits.push(mode); },
      })).toBe("bypassed");
      expect(commits).toEqual(["bypass"]);
      expect(nativeCalls).toBe(0);
      expect(presentations).toEqual([]);
    }
  });

  test("is latest-request-wins under rapid reentrant navigation and always returns idle", async () => {
    const presentations: RouteTransitionPresentation[] = [];
    const waits: Array<{ milliseconds: number; finish: () => void }> = [];
    const commits: string[] = [];
    const runtime: MechanicalRouteTransitionRuntime = {
      shouldBypass: () => false,
      sleep: (milliseconds, signal) => new Promise((resolve) => {
        let settled = false;
        const finish = (value: boolean) => {
          if (settled) return;
          settled = true;
          resolve(value);
        };
        signal.addEventListener("abort", () => finish(false), { once: true });
        waits.push({ milliseconds, finish: () => finish(true) });
      }),
      publish: (presentation) => presentations.push(presentation),
    };
    const controller = new MechanicalRouteTransitionController(runtime);

    const first = controller.transition({
      from: "/",
      to: "/missions",
      commit: () => { commits.push("missions"); },
    });
    const second = controller.transition({
      from: "/",
      to: "/brain",
      commit: () => { commits.push("brain"); },
    });

    expect(waits.map(({ milliseconds }) => milliseconds)).toEqual([
      MECHANICAL_ROUTE_TIMING.disassembleMs,
      MECHANICAL_ROUTE_TIMING.disassembleMs,
    ]);
    waits[1]!.finish();
    await new Promise((resolve) => globalThis.setTimeout(resolve, 0));
    expect(waits[2]?.milliseconds).toBe(MECHANICAL_ROUTE_TIMING.fallbackAssembleMs);
    waits[2]!.finish();

    expect(await first).toBe("cancelled");
    expect(await second).toBe("completed");
    expect(commits).toEqual(["brain"]);
    expect(presentations.at(-1)?.phase).toBe("idle");
    expect(presentations.filter(({ phase }) => phase === "committing")).toHaveLength(1);
  });

  test("consumes native skip rejections before latest-request-wins cancellation", async () => {
    let firstUpdateReject: ((reason?: unknown) => void) | undefined;
    let firstFinishedReject: ((reason?: unknown) => void) | undefined;
    let attachedCatchHandlers = 0;
    let nativeCalls = 0;
    const trackCatch = (promise: Promise<void>): Promise<void> => {
      const originalCatch = promise.catch.bind(promise);
      Object.defineProperty(promise, "catch", {
        configurable: true,
        value: (onRejected: (reason: unknown) => unknown) => {
          attachedCatchHandlers += 1;
          return originalCatch(onRejected);
        },
      });
      return promise;
    };
    const controller = new MechanicalRouteTransitionController({
      shouldBypass: () => false,
      sleep: async () => true,
      publish: () => undefined,
      startViewTransition: (update) => {
        nativeCalls += 1;
        if (nativeCalls > 1) return nativeTransition(update);
        const updateCallbackDone = trackCatch(new Promise<void>((_resolve, reject) => { firstUpdateReject = reject; }));
        const finished = trackCatch(new Promise<void>((_resolve, reject) => { firstFinishedReject = reject; }));
        return {
          updateCallbackDone,
          finished,
          skipTransition: () => {
            const abort = new DOMException("Skipping view transition because skipTransition() was called.", "AbortError");
            firstUpdateReject?.(abort);
            firstFinishedReject?.(abort);
          },
        };
      },
    });

    const first = controller.transition({ from: "/", to: "/missions", commit: () => undefined });
    await new Promise((resolve) => globalThis.setTimeout(resolve, 0));
    const second = controller.transition({ from: "/", to: "/brain", commit: () => undefined });

    expect(await first).toBe("cancelled");
    expect(await second).toBe("completed");
    expect(attachedCatchHandlers).toBeGreaterThanOrEqual(2);
  });

  test("classifies exact, query-only, hash-only, and route changes without ambiguity", () => {
    const current = { pathname: "/brain/graph", search: "?view=mission", hash: "" };
    expect(classifyLocationChange(current, { ...current })).toBe("noop");
    expect(classifyLocationChange(current, { ...current, search: "?view=local" })).toBe("location-only");
    expect(classifyLocationChange(current, { ...current, hash: "#selected" })).toBe("location-only");
    expect(classifyLocationChange(current, { pathname: "/missions", search: "", hash: "" })).toBe("route");
  });

  test("leaves modified, downloaded, external, and new-context anchors to the browser", () => {
    const ordinary = {
      href: "/missions",
      button: 0,
      detail: 1,
      defaultPrevented: false,
      metaKey: false,
      ctrlKey: false,
      shiftKey: false,
      altKey: false,
      hasDownload: false,
    };
    expect(shouldInterceptAppLinkClick(ordinary)).toBe(true);
    expect(shouldInterceptAppLinkClick({ ...ordinary, ctrlKey: true })).toBe(false);
    expect(shouldInterceptAppLinkClick({ ...ordinary, button: 1 })).toBe(false);
    expect(shouldInterceptAppLinkClick({ ...ordinary, target: "_blank" })).toBe(false);
    expect(shouldInterceptAppLinkClick({ ...ordinary, hasDownload: true })).toBe(false);
    expect(shouldInterceptAppLinkClick({ ...ordinary, href: "https://example.invalid/" })).toBe(false);
    expect(shouldInterceptAppLinkClick({ ...ordinary, href: "//example.invalid/" })).toBe(false);
  });
});

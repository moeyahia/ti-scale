import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.mechanical-route-transition";

async function observeTransitionPhases(page: import("@playwright/test").Page): Promise<void> {
  await page.evaluate(() => {
    const phases: Array<{ phase: string; mode?: string; from?: string; to?: string }> = [];
    Object.defineProperty(window, "__tiRouteTransitionPhases", {
      configurable: true,
      value: phases,
    });
    document.addEventListener("ti-scale:route-transition", (event) => {
      const detail = (event as CustomEvent<{ phase?: string; mode?: string; from?: string; to?: string }>).detail;
      if (!detail?.phase) return;
      phases.push({
        phase: detail.phase,
        ...(detail.mode ? { mode: detail.mode } : {}),
        ...(detail.from ? { from: detail.from } : {}),
        ...(detail.to ? { to: detail.to } : {}),
      });
    });
  });
}

async function transitionPhases(page: import("@playwright/test").Page) {
  return page.evaluate(() => (
    (window as Window & { __tiRouteTransitionPhases?: Array<{ phase: string; mode?: string; from?: string; to?: string }> })
      .__tiRouteTransitionPhases ?? []
  ));
}

interface RenderedTransitionFrame {
  phase: string;
  opacity: number;
  maxPlateOpacity: number;
  width: number;
  height: number;
  visible: boolean;
  textLength: number;
  showedRouteFallback: boolean;
}

async function observeRenderedTransitionFrames(page: import("@playwright/test").Page): Promise<void> {
  await page.evaluate(() => {
    const instrumentedWindow = window as Window & { __tiRenderedTransitionFrames?: RenderedTransitionFrame[] };
    instrumentedWindow.__tiRenderedTransitionFrames = [];
    let sampling = false;
    let fallbackTimer: number | undefined;
    const recordFrame = () => {
      const phase = document.documentElement.dataset.routeTransition ?? "idle";
      const surface = document.querySelector<HTMLElement>("[data-route-transition-surface='route']");
      if (surface) {
        const style = getComputedStyle(surface);
        const bounds = surface.getBoundingClientRect();
        const maxPlateOpacity = Math.max(0, ...Array.from(
          document.querySelectorAll<HTMLElement>(".ti-route-mechanism__plate"),
          (plate) => Number.parseFloat(getComputedStyle(plate).opacity) || 0,
        ));
        const surfaceText = surface.textContent?.trim() ?? "";
        instrumentedWindow.__tiRenderedTransitionFrames?.push({
          phase,
          opacity: Number.parseFloat(style.opacity),
          maxPlateOpacity,
          width: bounds.width,
          height: bounds.height,
          visible: style.display !== "none" && style.visibility !== "hidden",
          textLength: surfaceText.length,
          showedRouteFallback: surfaceText.includes("Loading Ti-Scale surface"),
        });
      }
      if (phase === "idle") {
        sampling = false;
        if (fallbackTimer !== undefined) window.clearTimeout(fallbackTimer);
        fallbackTimer = undefined;
      }
    };
    const sampleAnimationFrame = () => {
      if (!sampling) return;
      recordFrame();
      if (sampling) window.requestAnimationFrame(sampleAnimationFrame);
    };
    const sampleWithTimerFallback = () => {
      if (!sampling) return;
      recordFrame();
      if (sampling) fallbackTimer = window.setTimeout(sampleWithTimerFallback, 16);
    };
    document.addEventListener("ti-scale:route-transition", (event) => {
      const phase = (event as CustomEvent<{ phase?: string }>).detail?.phase;
      if (!phase) return;
      if (phase === "idle") {
        recordFrame();
        return;
      }
      if (!sampling) {
        sampling = true;
        recordFrame();
        window.requestAnimationFrame(sampleAnimationFrame);
        fallbackTimer = window.setTimeout(sampleWithTimerFallback, 16);
      } else {
        recordFrame();
      }
    });
  });
}

async function renderedTransitionFrames(page: import("@playwright/test").Page): Promise<RenderedTransitionFrame[]> {
  return page.evaluate(() => (
    (window as Window & { __tiRenderedTransitionFrames?: RenderedTransitionFrame[] }).__tiRenderedTransitionFrames ?? []
  ));
}

async function expectIdle(page: import("@playwright/test").Page): Promise<void> {
  await expect(page.locator("html")).toHaveAttribute("data-route-transition", "idle", { timeout: 2_000 });
  await expect(page.locator(".ti-scale")).toHaveAttribute("data-route-transition", "idle");
  await expect(page.locator("html")).not.toHaveClass(/is-route-transitioning/u);
  await expect(page.locator(".ti-scale")).not.toHaveClass(/is-route-transitioning/u);
}

async function activatePrimaryRoute(
  page: import("@playwright/test").Page,
  accessibleName: "Missions" | "Second Brain",
): Promise<void> {
  const sidebar = page.locator(".os-sidebar");
  const link = sidebar.getByRole("link", { name: accessibleName, exact: true, includeHidden: true });
  const trigger = page.locator("button.os-menu-button[aria-label='Open navigation']");

  // A reduced-motion mobile document can reach `domcontentloaded` before
  // React mounts the shell. Wait for the persistent navigation boundary
  // before deciding whether the responsive drawer trigger is visible.
  await expect(sidebar).toHaveCount(1);
  await expect(trigger).toHaveCount(1);
  const bootBoundary = page.locator("[data-ti-boot-boundary='startup']");
  if (await bootBoundary.count()) {
    await expect(bootBoundary).toHaveAttribute("data-ti-boot-phase", "complete", { timeout: 5_000 });
  }
  const usesNavigationDrawer = await page.evaluate(() => window.matchMedia("(max-width: 820px)").matches);
  if (usesNavigationDrawer) {
    await expect(trigger).toBeVisible();
    if (await trigger.getAttribute("aria-expanded") !== "true") {
      await trigger.click();
    }
    await expect(trigger).toHaveAttribute("aria-expanded", "true");
    await expect(sidebar).toHaveClass(/\bis-open\b/u);
  }
  await expect(link).toBeVisible();
  await link.click();
}

test.describe(`${TEST_ID} navigation lifecycle`, () => {
  test("disassembles, commits, assembles, restores focus, and clears all active state", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
    await observeTransitionPhases(page);

    await page.evaluate(() => window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "instant" }));
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
    await activatePrimaryRoute(page, "Missions");

    await expect(page).toHaveURL(/\/missions$/u);
    await expect(page.getByRole("heading", { level: 1, name: "Missions", exact: true })).toBeVisible();
    await expectIdle(page);
    await expect(page.locator("main#ti-scale-content")).toBeFocused();
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);

    const phases = await transitionPhases(page);
    expect(phases.map(({ phase }) => phase)).toEqual([
      "disassembling",
      "committing",
      "assembling",
      "idle",
    ]);
    expect(phases[0]).toMatchObject({ from: "/", to: "/missions" });
    expect(["native", "fallback"]).toContain(phases[0]?.mode);
    expect(await page.locator(".ti-route-mechanism__plate").count()).toBe(8);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
  });

  test("keeps every rendered route frame covered through the mechanical commit", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
    await observeRenderedTransitionFrames(page);

    await activatePrimaryRoute(page, "Missions");
    await expect(page.getByRole("heading", { level: 1, name: "Missions", exact: true })).toBeVisible();
    await expectIdle(page);

    const frames = await renderedTransitionFrames(page);
    expect(frames.length).toBeGreaterThan(2);
    expect(frames.some(({ phase }) => phase === "disassembling")).toBe(true);
    expect(frames.some(({ phase }) => phase === "assembling")).toBe(true);
    expect(frames.filter(({ visible, width, height, opacity, maxPlateOpacity }) => (
      !visible || width <= 0 || height <= 0 || !Number.isFinite(opacity)
      || (opacity < 0.2 && maxPlateOpacity < 0.2)
    ))).toEqual([]);
    expect(frames.some(({ showedRouteFallback }) => showedRouteFallback)).toBe(false);
    expect(frames.filter(({ textLength }) => textLength === 0)).toEqual([]);
  });

  test("back and forward traverse existing entries through the same finite mechanism", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await activatePrimaryRoute(page, "Missions");
    await expect(page.getByRole("heading", { level: 1, name: "Missions", exact: true })).toBeVisible();
    await expectIdle(page);
    await activatePrimaryRoute(page, "Second Brain");
    await expect(page.getByRole("heading", { level: 1, name: "Second Brain", exact: true })).toBeVisible();
    await expectIdle(page);
    await observeTransitionPhases(page);

    await page.evaluate(() => window.history.back());
    await expect(page).toHaveURL(/\/missions$/u);
    await expect(page.getByRole("heading", { level: 1, name: "Missions", exact: true })).toBeVisible();
    await expectIdle(page);
    await expect(page.locator("main#ti-scale-content")).toBeFocused();

    await page.evaluate(() => window.history.forward());
    await expect(page).toHaveURL(/\/brain$/u);
    await expect(page.getByRole("heading", { level: 1, name: "Second Brain", exact: true })).toBeVisible();
    await expectIdle(page);

    const phases = await transitionPhases(page);
    expect(phases.filter(({ phase }) => phase === "committing")).toHaveLength(2);
    expect(phases.at(-1)?.phase).toBe("idle");
  });

  test("reduced motion commits immediately without phases or native View Transition work", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
    await page.addInitScript(() => {
      const documentWithTransition = document as Document & {
        startViewTransition?: (update: () => void | Promise<void>) => unknown;
      };
      const nativeStart = documentWithTransition.startViewTransition?.bind(documentWithTransition);
      Object.defineProperty(window, "__tiNativeTransitionCalls", { configurable: true, value: 0, writable: true });
      if (nativeStart) {
        documentWithTransition.startViewTransition = (update) => {
          const instrumentedWindow = window as Window & { __tiNativeTransitionCalls?: number };
          instrumentedWindow.__tiNativeTransitionCalls = (instrumentedWindow.__tiNativeTransitionCalls ?? 0) + 1;
          return nativeStart(update);
        };
      }
    });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await observeTransitionPhases(page);
    await activatePrimaryRoute(page, "Missions");

    await expect(page).toHaveURL(/\/missions$/u);
    await expect(page.getByRole("heading", { level: 1, name: "Missions", exact: true })).toBeVisible();
    expect(await transitionPhases(page)).toEqual([]);
    expect(await page.evaluate(() => (
      (window as Window & { __tiNativeTransitionCalls?: number }).__tiNativeTransitionCalls ?? 0
    ))).toBe(0);
    await expect(page.locator(".ti-route-mechanism")).toHaveCSS("display", "none");
  });

  test("rapid double navigation commits only the latest target and leaves no phantom history entry", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
    await expect(page.locator("[data-ti-boot-boundary='startup']"))
      .toHaveAttribute("data-ti-boot-phase", "complete", { timeout: 5_000 });
    await observeTransitionPhases(page);

    await page.evaluate(() => {
      window.dispatchEvent(new CustomEvent("ti-scale:mechanical-navigate", { detail: { path: "/missions" } }));
      window.dispatchEvent(new CustomEvent("ti-scale:mechanical-navigate", { detail: { path: "/brain" } }));
    });

    await expect(page).toHaveURL(/\/brain$/u);
    await expect(page.getByRole("heading", { level: 1, name: "Second Brain", exact: true })).toBeVisible();
    await expectIdle(page);
    const phases = await transitionPhases(page);
    expect(phases.filter(({ phase }) => phase === "committing")).toHaveLength(1);
    expect(phases.find(({ phase }) => phase === "committing")).toMatchObject({ from: "/", to: "/brain" });

    await page.evaluate(() => window.history.back());
    await expect(page).toHaveURL(/\/$/u);
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
    await expectIdle(page);
  });

  test("query-only actuator requests and exact repeats never enter the mechanism", async ({ page }) => {
    await page.goto("/missions", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Missions", exact: true })).toBeVisible();
    await observeTransitionPhases(page);
    const initialHistoryLength = await page.evaluate(() => window.history.length);

    await page.evaluate(() => window.dispatchEvent(new CustomEvent("ti-scale:mechanical-navigate", {
      detail: { path: "/missions?view=board" },
    })));
    await expect(page).toHaveURL(/\/missions\?view=board$/u);
    expect(await transitionPhases(page)).toEqual([]);

    const lengthAfterQuery = await page.evaluate(() => window.history.length);
    expect(lengthAfterQuery).toBe(initialHistoryLength + 1);
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("ti-scale:mechanical-navigate", {
      detail: { path: "/missions?view=board" },
    })));
    await page.waitForTimeout(50);
    expect(await page.evaluate(() => window.history.length)).toBe(lengthAfterQuery);
    expect(await transitionPhases(page)).toEqual([]);
  });
});

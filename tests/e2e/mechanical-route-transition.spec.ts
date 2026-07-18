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

async function expectIdle(page: import("@playwright/test").Page): Promise<void> {
  await expect(page.locator("html")).toHaveAttribute("data-route-transition", "idle", { timeout: 2_000 });
  await expect(page.locator(".ti-scale")).toHaveAttribute("data-route-transition", "idle");
  await expect(page.locator("html")).not.toHaveClass(/is-route-transitioning/u);
  await expect(page.locator(".ti-scale")).not.toHaveClass(/is-route-transitioning/u);
}

test.describe(`${TEST_ID} navigation lifecycle`, () => {
  test("disassembles, commits, assembles, restores focus, and clears all active state", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
    await observeTransitionPhases(page);

    await page.evaluate(() => window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "instant" }));
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
    await page.getByRole("link", { name: "Missions", exact: true }).click();

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

  test("back and forward traverse existing entries through the same finite mechanism", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.getByRole("link", { name: "Missions", exact: true }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Missions", exact: true })).toBeVisible();
    await expectIdle(page);
    await page.getByRole("link", { name: "Second Brain", exact: true }).click();
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
    await page.getByRole("link", { name: "Missions", exact: true }).click();

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
    await expect(page.getByRole("link", { name: "Missions", exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: "Second Brain", exact: true })).toBeVisible();
    await observeTransitionPhases(page);

    await page.evaluate(() => {
      const missions = document.querySelector<HTMLAnchorElement>('a[href="/missions"]');
      const brain = document.querySelector<HTMLAnchorElement>('a[href="/brain"]');
      if (!missions || !brain) throw new Error("Primary navigation links are missing");
      missions.click();
      brain.click();
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

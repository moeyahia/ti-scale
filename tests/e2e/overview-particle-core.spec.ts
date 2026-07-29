import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.overview.particle-core";
const CANVAS_NAME = "Ti-Scale interactive titanium particle core. Move the pointer to displace nearby particles, drag to rotate, or use arrow keys.";
const REDUCED_CANVAS_NAME = "Ti-Scale titanium particle core in its reduced-motion state. Use arrow keys to inspect its orientation.";
const RETIRED_HERO_ASSET = /(?:ti-scale-higgsfield-core|higgsfield-motion|\.glb(?:$|[?#]))/iu;

test.describe(`${TEST_ID} approved Command Center integration`, () => {
  test("lazy-loads one local approved field without the retired raster or GLB paths", async ({ page, browserAudit }, testInfo) => {
    test.setTimeout(60_000);
    const retiredRequests: string[] = [];
    let runtimeRequestSeen = false;
    let releaseRuntime!: () => void;
    const runtimeRelease = new Promise<void>((resolve) => { releaseRuntime = resolve; });

    page.on("request", (request) => {
      if (RETIRED_HERO_ASSET.test(request.url())) retiredRequests.push(request.url());
    });
    await page.route(/ParticleCoreRuntime[^/]*(?:\.tsx|\.js)?(?:\?.*)?$/u, async (route) => {
      runtimeRequestSeen = true;
      await runtimeRelease;
      await route.continue();
    });

    try {
      await page.goto("/", { waitUntil: "domcontentloaded" });
      await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
      const core = page.locator("[data-ti-particle-artwork='operator-approved']");
      await expect(core).toHaveAttribute("data-ti-exploded-model", "approved-particle-core");
      await expect(core).toHaveAttribute("data-ti-particle-status", "loading");
      await expect(core.getByText("Materializing approved particle core", { exact: true })).toBeVisible();
      await expect(page.getByRole("application", { name: CANVAS_NAME, exact: true })).toHaveCount(0);
      await expect.poll(() => runtimeRequestSeen).toBe(true);
    } finally {
      releaseRuntime();
    }

    const core = page.locator("[data-ti-particle-artwork='operator-approved']");
    const canvas = page.getByRole("application", { name: CANVAS_NAME, exact: true });
    await expect(canvas).toBeVisible({ timeout: 20_000 });
    await expect(core).toHaveAttribute("data-ti-particle-status", "active");
    await expect(core.locator("canvas.particle-core-runtime__canvas")).toHaveCount(1);
    await expect.poll(async () => Number(await core.getAttribute("data-ti-point-count"))).toBeGreaterThan(10_000);
    await expect(core).toHaveAttribute("data-ti-draw-calls", "1");
    await expect(page.locator("[data-ti-assembly-root='command-center']")).toHaveAttribute(
      "data-ti-core-transfer-state",
      "particle-core-approved",
    );
    await expect(page.locator("[data-ti-raster-canvas], .ti-scale-core__media, [data-ti-core-transfer-layer]")).toHaveCount(0);
    expect(retiredRequests).toEqual([]);
    const heroScreenshot = testInfo.outputPath("overview-approved-particle-core.png");
    await page.locator(".ti-command-hero").screenshot({ path: heroScreenshot, animations: "disabled" });
    await testInfo.attach("overview-approved-particle-core", { path: heroScreenshot, contentType: "image/png" });
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
  });

  test("activates the local hover field and settles it after pointer leave", async ({ page, browserAudit }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const canvas = page.getByRole("application", { name: CANVAS_NAME, exact: true });
    const runtime = page.locator(".ti-command-particle-core__runtime");
    await expect(canvas).toBeVisible({ timeout: 20_000 });
    await expect(runtime).toHaveAttribute("data-hover-enabled", "true");
    const bounds = await canvas.boundingBox();
    expect(bounds).not.toBeNull();
    if (!bounds) throw new Error("The approved particle canvas has no rendered bounds");

    await page.mouse.move(bounds.x + bounds.width * 0.72, bounds.y + bounds.height * 0.34);
    await expect(runtime).toHaveAttribute("data-hover-active", "true");
    await expect.poll(async () => Number(await runtime.getAttribute("data-hover-strength"))).toBeGreaterThan(0.35);
    await expect.poll(async () => Math.abs(Number(await runtime.getAttribute("data-hover-field-x")))).toBeGreaterThan(0.15);
    await expect.poll(async () => Math.abs(Number(await runtime.getAttribute("data-hover-field-y")))).toBeGreaterThan(0.1);

    await page.mouse.move(1, 1);
    await expect(runtime).toHaveAttribute("data-hover-active", "false");
    await expect.poll(async () => Math.abs(Number(await runtime.getAttribute("data-hover-field-x")))).toBeLessThan(0.02);
    await expect.poll(async () => Math.abs(Number(await runtime.getAttribute("data-hover-field-y")))).toBeLessThan(0.02);
    await expect.poll(async () => Number(await runtime.getAttribute("data-hover-strength"))).toBeLessThan(0.02);
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
  });

  test("keeps the approved field static and disables hover under reduced motion", async ({ page, browserAudit }) => {
    await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const canvas = page.getByRole("application", { name: REDUCED_CANVAS_NAME, exact: true });
    const fallback = page.getByText("Particle field unavailable", { exact: true });
    await expect(canvas.or(fallback)).toBeVisible({ timeout: 20_000 });
    if (await canvas.count() === 1) {
      const runtime = page.locator(".ti-command-particle-core__runtime");
      await expect(runtime).toHaveAttribute("data-reduced-motion", "true");
      await expect(runtime).toHaveAttribute("data-auto-rotate", "false");
      await expect(runtime).toHaveAttribute("data-hover-enabled", "false");
      const bounds = await canvas.boundingBox();
      expect(bounds).not.toBeNull();
      if (!bounds) throw new Error("The reduced-motion particle canvas has no rendered bounds");
      await page.mouse.move(bounds.x + bounds.width * 0.76, bounds.y + bounds.height * 0.28);
      await page.waitForTimeout(120);
      await expect(runtime).toHaveAttribute("data-hover-active", "false");
      await expect(runtime).toHaveAttribute("data-hover-strength", "0.0000");
      await expect(runtime).toHaveAttribute("data-hover-field-x", "0.0000");
      await expect(runtime).toHaveAttribute("data-hover-field-y", "0.0000");
      const before = await canvas.screenshot({ animations: "disabled" });
      await page.waitForTimeout(550);
      const after = await canvas.screenshot({ animations: "disabled" });
      expect(after.equals(before)).toBe(true);
    } else {
      await expect(fallback).toBeVisible();
    }
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
  });
});

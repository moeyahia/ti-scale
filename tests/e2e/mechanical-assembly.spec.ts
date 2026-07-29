import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.mechanical-assembly";

test.describe(`${TEST_ID} Command Center mechanism`, () => {
  test("mounts the approved particle core, deploys modules, and exposes non-vanilla actuators", async ({ page }, testInfo) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();

    const core = page.locator("[data-ti-transformer-core='true']");
    await expect(core).toBeVisible();
    await expect(core).not.toHaveAttribute("style");
    await expect(core).toHaveAttribute("data-ti-exploded-model", "approved-particle-core");
    await expect(core).toHaveAttribute("data-ti-particle-artwork", "operator-approved");
    await expect(core).toHaveAttribute("data-ti-particle-status", "active", { timeout: 20_000 });
    await expect(core.locator("canvas.particle-core-runtime__canvas")).toHaveCount(1);
    await expect(core.locator(".particle-core-runtime")).toHaveAttribute("data-draw-calls", "1");
    await expect.poll(async () => Number(await core.getAttribute("data-ti-point-count"))).toBeGreaterThan(10_000);
    await expect(core.locator("[data-ti-raster-canvas], .ti-scale-core__media, .ti-scale-core__shard")).toHaveCount(0);

    const assembly = page.locator("[data-ti-assembly-root='command-center']");
    await expect(assembly).toHaveAttribute("data-ti-assembly", "active");
    const modules = assembly.locator("[data-ti-module]");
    expect(await modules.count()).toBeGreaterThanOrEqual(8);
    expect(await modules.evaluateAll((items) => items.every((item) => !item.hasAttribute("style")))).toBe(true);
    for (let index = 0; index < await modules.count(); index += 1) {
      const module = modules.nth(index);
      await module.evaluate((element) => element.scrollIntoView({ block: "center", behavior: "instant" }));
      await expect(module, `Module ${index + 1} should lock after entering the viewport`).toHaveAttribute("data-ti-phase", "locked", { timeout: 3_000 });
    }
    await expect(assembly).toHaveAttribute("data-ti-core-transfer-state", "particle-core-approved");
    await expect(assembly).toHaveAttribute("data-ti-transfer-count", "0");
    await expect(page.locator("[data-ti-core-transfer-layer]")).toHaveCount(0);
    expect(await modules.evaluateAll((items) => items.every((item) => !item.hasAttribute("style")))).toBe(true);

    await page.getByRole("heading", { level: 2, name: "Go Autonomous", exact: true }).scrollIntoViewIfNeeded();

    const autonomous = page.getByRole("link", { name: "Compose mission contract", exact: true });
    await expect(autonomous.locator(".os-button__mechanism i")).toHaveCount(3);
    const firstActuatorPlate = autonomous.locator(".os-button__mechanism i").first();
    const beforeHover = await firstActuatorPlate.evaluate((item) => getComputedStyle(item).height);
    await autonomous.hover();
    await expect(firstActuatorPlate).not.toHaveCSS("height", beforeHover);
    await expect(autonomous).toHaveCSS("min-height", "44px");

    // Chromium owns this one visual artifact to avoid redundant raster output.
    // The static CSP browser contract separately executes WebKit's screenshot
    // synchronization path and proves its exact inert style hash is accepted.
    if (testInfo.project.name.startsWith("chromium")) {
      await testInfo.attach(`mechanical-command-center-${testInfo.project.name}.png`, {
        body: await page.screenshot({ fullPage: true }),
        contentType: "image/png",
      });
    }
  });

  test("provides a stable assembled interface when reduced motion is requested", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const assembly = page.locator("[data-ti-assembly-root='command-center']");
    await expect(assembly).toHaveAttribute("data-ti-assembly", "reduced");
    await expect(assembly.locator("[data-ti-module]").first()).toHaveAttribute("data-ti-phase", "locked");
    await expect(assembly).toHaveAttribute("data-ti-core-transfer-state", "static");
    const runtime = page.locator(".ti-command-particle-core__runtime");
    await expect(runtime).toHaveAttribute("data-runtime-ready", "true", { timeout: 20_000 });
    await expect(runtime).toHaveAttribute("data-reduced-motion", "true");
    await expect(runtime).toHaveAttribute("data-auto-rotate", "false");
    await expect(runtime).toHaveAttribute("data-hover-enabled", "false");
    await expect(page.locator("[data-ti-core-transfer-layer]")).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Compose mission contract", exact: true })).toBeVisible();
  });

  test("keeps the approved procedural field local and never invokes retired raster or GLB transfer paths", async ({ page }) => {
    const eventStreamRequests: string[] = [];
    const retiredHeroRequests: string[] = [];
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (request.method() === "GET" && url.pathname === "/api/v2/events/stream") {
        eventStreamRequests.push(url.href);
      }
      if (/(?:ti-scale-higgsfield-core|higgsfield-motion|\.glb(?:$|[?#]))/iu.test(request.url())) {
        retiredHeroRequests.push(request.url());
      }
    });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect.poll(
      () => eventStreamRequests.length,
      { timeout: 3_000, message: "The one retained live stream must start before noncritical media fan-out" },
    ).toBe(1);
    const assembly = page.locator("[data-ti-assembly-root='command-center']");
    const hero = assembly.locator("[data-ti-module='hero']");

    await expect(assembly).toHaveAttribute("data-ti-assembly", "active");
    await expect(hero).toHaveAttribute("data-ti-phase", "locked", { timeout: 3_000 });
    await expect(assembly.locator("[data-ti-transformer-core='true']")).toHaveAttribute("data-ti-particle-status", "active", { timeout: 20_000 });
    await page.evaluate(() => window.scrollTo({ top: Math.min(1_000, document.documentElement.scrollHeight - innerHeight), behavior: "instant" }));
    await expect(assembly).toHaveAttribute("data-ti-core-transfer-state", "particle-core-approved");
    await expect(assembly).toHaveAttribute("data-ti-transfer-count", "0");
    await expect(page.locator("[data-ti-core-transfer-layer]")).toHaveCount(0);
    await expect(assembly.locator("[data-ti-transformer-core='true']")).toHaveAttribute("data-ti-exploded-model", "approved-particle-core");
    await expect(assembly.locator("canvas.particle-core-runtime__canvas")).toHaveCount(1);
    await expect(page.locator("[data-ti-raster-canvas], .ti-scale-core__media")).toHaveCount(0);

    // Returning to the hero cannot reveal a placeholder transfer or replay a
    // retired raster/GLB path through a second visual plane.
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await expect(page.locator("[data-ti-core-transfer-layer]")).toHaveCount(0);
    await expect(hero).toHaveAttribute("data-ti-phase", "locked");
    expect(await assembly.locator("[data-ti-module]").evaluateAll((items) => items.every((item) => !item.hasAttribute("style")))).toBe(true);
    expect(eventStreamRequests).toHaveLength(1);
    expect(retiredHeroRequests).toEqual([]);
  });
});

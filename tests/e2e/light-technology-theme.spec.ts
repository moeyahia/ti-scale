import { expect, test } from "./support/playwright";
import { createBrainGraphFixture } from "./support/brainGraphFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_ID = "e2e.light-technology-theme";

test.describe(`${TEST_ID} production rendering contract`, () => {
  test("Command Center renders the warm editorial titanium system", async ({ page }, testInfo) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { level: 2, name: "Active operations", exact: true })).toBeVisible();
    await expect(page.locator("[data-ti-particle-artwork='operator-approved'] canvas")).toBeVisible({ timeout: 20_000 });

    const presentation = await page.evaluate(() => {
      const application = document.querySelector<HTMLElement>(".ti-scale");
      const topbar = document.querySelector<HTMLElement>(".os-topbar");
      const card = document.querySelector<HTMLElement>(".os-card");
      const cardFace = card?.querySelector<HTMLElement>(".os-card__face");
      const hero = document.querySelector<HTMLElement>(".ti-command-hero");
      const titleLine = document.querySelector<HTMLElement>(".ti-command-hero__title-line > span");
      const particle = document.querySelector<HTMLElement>("[data-ti-particle-artwork='operator-approved']");
      const runtime = particle?.querySelector<HTMLElement>(".particle-core-runtime");
      if (!application || !topbar || !card || !cardFace || !hero || !titleLine || !particle || !runtime) throw new Error("The Command Center theme surfaces are missing");
      const applicationStyle = getComputedStyle(application);
      return {
        documentClass: document.documentElement.className,
        bodyClass: document.body.className,
        bodyBackground: getComputedStyle(document.body).backgroundColor,
        colorScheme: applicationStyle.colorScheme,
        canvas: applicationStyle.getPropertyValue("--os-canvas").trim(),
        info: applicationStyle.getPropertyValue("--os-info").trim(),
        success: applicationStyle.getPropertyValue("--os-success").trim(),
        shellBackgroundImage: applicationStyle.backgroundImage,
        heroBackgroundImage: getComputedStyle(hero).backgroundImage,
        motionState: application.dataset.motionState,
        titleAnimation: getComputedStyle(titleLine).animationName,
        particleArtwork: particle.dataset.tiParticleArtwork,
        particleModel: particle.dataset.tiExplodedModel,
        particleStatus: particle.dataset.tiParticleStatus,
        particlePointCount: Number(particle.dataset.tiPointCount),
        particleDrawCalls: Number(particle.dataset.tiDrawCalls),
        particleCanvasCount: particle.querySelectorAll("canvas").length,
        oldHeroRasterCount: document.querySelectorAll("[data-ti-raster-canvas], .ti-scale-core__media").length,
        oldHeroPlateCount: document.querySelectorAll(".ti-scale-core__plate").length,
        hoverEnabled: runtime.dataset.hoverEnabled,
        surface: getComputedStyle(cardFace).backgroundColor,
        topbar: getComputedStyle(topbar).backgroundColor,
        themeMeta: document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')?.content,
        schemeMeta: document.querySelector<HTMLMetaElement>('meta[name="color-scheme"]')?.content,
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      };
    });

    expect(presentation.particlePointCount).toBeGreaterThan(10_000);
    expect(presentation).toEqual({
      documentClass: "",
      bodyClass: "",
      bodyBackground: "rgb(244, 242, 238)",
      colorScheme: "light",
      canvas: "#f4f2ee",
      info: "#214f80",
      success: "#46525e",
      shellBackgroundImage: "none",
      heroBackgroundImage: "none",
      motionState: "active",
      titleAnimation: "ti-title-materialize",
      particleArtwork: "operator-approved",
      particleModel: "approved-particle-core",
      particleStatus: "active",
      particlePointCount: expect.any(Number),
      particleDrawCalls: 1,
      particleCanvasCount: 1,
      oldHeroRasterCount: 0,
      oldHeroPlateCount: 0,
      hoverEnabled: "true",
      surface: "rgb(255, 254, 250)",
      topbar: "rgb(255, 254, 250)",
      themeMeta: "#fffefa",
      schemeMeta: "light",
      overflow: 0,
    });

    await testInfo.attach(`command-center-light-${testInfo.project.name}.png`, {
      body: await page.screenshot({ fullPage: true, animations: "disabled" }),
      contentType: "image/png",
    });
  });

  test("Second Brain graph uses the light evidence-topology canvas", async ({ page }, testInfo) => {
    const fixture = createBrainGraphFixture(canonicalFixtureNamespace(testInfo, "light-brain-graph"));
    await page.goto(`/brain/graph?engagement=${encodeURIComponent(fixture.engagementId)}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(page.getByRole("heading", { level: 1, name: "Memory Graph", exact: true })).toBeVisible();
    const canvas = page.getByRole("application", { name: /^Memory graph with/u });
    await expect(canvas).toHaveAttribute("aria-busy", "false", { timeout: 20_000 });
    await expect(page.locator(".brain-graph-workspace")).toHaveCSS("background-color", "rgb(248, 247, 243)");

    const theme = await canvas.evaluate((element) => {
      const styles = getComputedStyle(element);
      return {
        canvas: styles.getPropertyValue("--os-graph-canvas").trim(),
        // Browsers may serialize the same CSS alpha as `.07` or `0.07`.
        // Normalize only the omitted leading zero, then keep the exact color
        // contract below.
        grid: styles.getPropertyValue("--os-graph-grid").trim().replace(/,\s*\.(\d+)\)$/u, ", 0.$1)"),
        selection: styles.getPropertyValue("--os-graph-selection").trim(),
      };
    });
    expect(theme).toMatchObject({
      canvas: "#f8f7f3",
      selection: "#34495e",
    });
    // Vite's production minifier may serialize the same alpha as `.07`.
    // Assert the computed color value rather than the source token spelling.
    expect(theme.grid).toMatch(/^rgba\(74,\s*80,\s*86,\s*(?:0?\.07)\)$/u);

    await testInfo.attach(`second-brain-light-${testInfo.project.name}.png`, {
      body: await page.locator(".brain-graph-workspace").screenshot({ animations: "disabled" }),
      contentType: "image/png",
    });
  });
});

test.describe(`${TEST_ID} reduced-motion contract`, () => {
  test("renders the titanium composition statically and keeps controls focusable", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
    await expect(page.locator(".ti-command-particle-core__runtime canvas")).toBeVisible({ timeout: 20_000 });
    const presentation = await page.evaluate(() => {
      const title = document.querySelector<HTMLElement>(".ti-command-hero__title-line > span");
      const runtime = document.querySelector<HTMLElement>(".ti-command-particle-core__runtime");
      const canvas = runtime?.querySelector<HTMLCanvasElement>("canvas");
      if (!title || !runtime || !canvas) throw new Error("Reduced-motion titanium surfaces are missing");
      return {
        titleAnimation: getComputedStyle(title).animationName,
        canvasAnimation: getComputedStyle(canvas).animationName,
        reducedMotion: runtime.dataset.reducedMotion,
        autoRotate: runtime.dataset.autoRotate,
        hoverEnabled: runtime.dataset.hoverEnabled,
      };
    });
    expect(presentation).toEqual({
      titleAnimation: "none",
      canvasAnimation: "none",
      reducedMotion: "true",
      autoRotate: "false",
      hoverEnabled: "false",
    });
    const command = page.getByRole("button", { name: "Search or run a command", exact: true });
    await command.focus();
    await expect(command).toBeFocused();
    await expect(command).toHaveCSS("pointer-events", "auto");
    await expect(command).toHaveCSS("min-height", "44px");
  });

  test("pauses decorative motion when the document becomes hidden", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const application = page.locator(".ti-scale");
    const runtime = page.locator(".ti-command-particle-core__runtime");
    await expect(application).toHaveAttribute("data-motion-state", "active");
    await expect(runtime).toHaveAttribute("data-runtime-ready", "true", { timeout: 20_000 });

    await page.evaluate(() => {
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await expect(application).toHaveAttribute("data-motion-state", "paused");
    await page.waitForTimeout(120);
    const pausedYaw = await runtime.getAttribute("data-camera-yaw");
    await page.waitForTimeout(320);
    await expect(runtime).toHaveAttribute("data-camera-yaw", pausedYaw ?? "");

    await page.evaluate(() => {
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await expect(application).toHaveAttribute("data-motion-state", "active");
    await expect.poll(() => runtime.getAttribute("data-camera-yaw")).not.toBe(pausedYaw);
  });
});

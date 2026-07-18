import { expect, test } from "./support/playwright";
import { createBrainGraphFixture } from "./support/brainGraphFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_ID = "e2e.light-technology-theme";

test.describe(`${TEST_ID} production rendering contract`, () => {
  test("Command Center renders the warm editorial titanium system", async ({ page }, testInfo) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { level: 2, name: "Active operations", exact: true })).toBeVisible();

    const presentation = await page.evaluate(() => {
      const application = document.querySelector<HTMLElement>(".ti-scale");
      const topbar = document.querySelector<HTMLElement>(".os-topbar");
      const card = document.querySelector<HTMLElement>(".os-card");
      const hero = document.querySelector<HTMLElement>(".ti-command-hero");
      const titleLine = document.querySelector<HTMLElement>(".ti-command-hero__title-line > span");
      const plate = document.querySelector<SVGElement>(".ti-scale-core__plate");
      if (!application || !topbar || !card || !hero || !titleLine || !plate) throw new Error("The Command Center theme surfaces are missing");
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
        plateAnimation: getComputedStyle(plate).animationName,
        adaptivePlateCount: document.querySelectorAll(".ti-scale-core__plate").length,
        retiredHudPrimitiveCount: document.querySelectorAll(".ti-scale-core__guide, .ti-scale-core__orbit, .ti-scale-core__node").length,
        surface: getComputedStyle(card).backgroundColor,
        topbar: getComputedStyle(topbar).backgroundColor,
        themeMeta: document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')?.content,
        schemeMeta: document.querySelector<HTMLMetaElement>('meta[name="color-scheme"]')?.content,
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      };
    });

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
      plateAnimation: "ti-plate-arrive-far",
      adaptivePlateCount: 3,
      retiredHudPrimitiveCount: 0,
      surface: "rgb(255, 254, 250)",
      topbar: "rgba(255, 254, 250, 0.97)",
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
        grid: styles.getPropertyValue("--os-graph-grid").trim(),
        selection: styles.getPropertyValue("--os-graph-selection").trim(),
      };
    });
    expect(theme).toEqual({
      canvas: "#f8f7f3",
      grid: "rgba(74, 80, 86, 0.07)",
      selection: "#34495e",
    });

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
    const presentation = await page.evaluate(() => {
      const title = document.querySelector<HTMLElement>(".ti-command-hero__title-line > span");
      const plate = document.querySelector<SVGElement>(".ti-scale-core__plate");
      const sheen = document.querySelector<HTMLElement>(".ti-scale-core__sheen");
      if (!title || !plate || !sheen) throw new Error("Reduced-motion titanium surfaces are missing");
      return {
        titleAnimation: getComputedStyle(title).animationName,
        plateAnimation: getComputedStyle(plate).animationName,
        sheenDisplay: getComputedStyle(sheen).display,
      };
    });
    expect(presentation).toEqual({
      titleAnimation: "none",
      plateAnimation: "none",
      sheenDisplay: "none",
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
    await expect(application).toHaveAttribute("data-motion-state", "active");

    await page.evaluate(() => {
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await expect(application).toHaveAttribute("data-motion-state", "paused");
    await expect(page.locator(".ti-scale-core__plate").first()).toHaveCSS("animation-play-state", "paused");

    await page.evaluate(() => {
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await expect(application).toHaveAttribute("data-motion-state", "active");
  });
});

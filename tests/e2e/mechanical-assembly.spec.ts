import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.mechanical-assembly";

test.describe(`${TEST_ID} Command Center mechanism`, () => {
  test("assembles the core, deploys modules, and exposes non-vanilla actuators", async ({ page }, testInfo) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();

    const core = page.locator("[data-ti-transformer-core='true']");
    await expect(core).toBeVisible();
    await expect(core.locator(".ti-scale-core__shard")).toHaveCount(8);
    await expect(core.locator(".ti-scale-core__shard").first()).toHaveCSS("animation-name", "ti-transformer-shard-lock");

    const assembly = page.locator("[data-ti-assembly-root='command-center']");
    await expect(assembly).toHaveAttribute("data-ti-assembly", "active");
    const modules = assembly.locator("[data-ti-module]");
    expect(await modules.count()).toBeGreaterThanOrEqual(8);
    for (let index = 0; index < await modules.count(); index += 1) {
      const module = modules.nth(index);
      await module.evaluate((element) => element.scrollIntoView({ block: "center", behavior: "instant" }));
      await expect(module, `Module ${index + 1} should lock after entering the viewport`).toHaveAttribute("data-ti-phase", "locked", { timeout: 3_000 });
    }

    await page.getByRole("heading", { level: 2, name: "Go Autonomous", exact: true }).scrollIntoViewIfNeeded();

    const autonomous = page.getByRole("link", { name: "Compose mission contract", exact: true });
    await expect(autonomous.locator(".os-button__mechanism i")).toHaveCount(3);
    const beforeHover = await autonomous.locator(".os-button__mechanism i").first().evaluate((item) => getComputedStyle(item).height);
    await autonomous.hover();
    await expect.poll(async () => autonomous.locator(".os-button__mechanism i").first().evaluate((item) => getComputedStyle(item).height)).not.toBe(beforeHover);
    await expect(autonomous).toHaveCSS("min-height", "44px");

    await testInfo.attach(`mechanical-command-center-${testInfo.project.name}.png`, {
      body: await page.screenshot({ fullPage: true }),
      contentType: "image/png",
    });
  });

  test("provides a stable assembled interface when reduced motion is requested", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const assembly = page.locator("[data-ti-assembly-root='command-center']");
    await expect(assembly).toHaveAttribute("data-ti-assembly", "reduced");
    await expect(assembly.locator("[data-ti-module]").first()).toHaveAttribute("data-ti-phase", "locked");
    await expect(page.locator(".ti-scale-core__shards")).toHaveCSS("display", "none");
    await expect(page.getByRole("link", { name: "Compose mission contract", exact: true })).toBeVisible();
  });
});

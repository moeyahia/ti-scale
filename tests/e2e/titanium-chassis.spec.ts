import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.titanium-chassis";

test.describe(`${TEST_ID} asymmetric operational modules`, () => {
  test("renders deterministic titanium facets and reverses the finite hover mechanism", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();

    const plateValues = await page.locator("[data-ti-plate]").evaluateAll((items) => items.map((item) => item.getAttribute("data-ti-plate")));
    expect(new Set(plateValues)).toEqual(new Set(["keel", "aero", "prism", "truss"]));

    const card = page.locator(".os-dashboard-grid > .os-card[data-ti-plate]").first();
    await card.evaluate((element) => element.scrollIntoView({ block: "center", behavior: "instant" }));
    await expect(card).toHaveAttribute("data-ti-phase", "locked", { timeout: 4_000 });
    await expect(card.locator("[data-ti-chassis='module']")).toHaveCount(1);
    await expect(card.locator(".os-card__chassis")).toHaveCSS("pointer-events", "none");
    await expect(card).toHaveCSS("overflow", "visible");
    expect(await card.locator("[style]").count()).toBe(0);

    const chassis = card.locator(".os-card__chassis");
    const fastener = card.locator(".os-card__fastener");
    const startingChassis = await chassis.evaluate((element) => getComputedStyle(element).transform);
    const startingFastener = await fastener.evaluate((element) => getComputedStyle(element).transform);
    const hoverCapable = await page.evaluate(() => matchMedia("(hover: hover) and (pointer: fine)").matches);

    if (hoverCapable) {
      await card.hover();
      await page.waitForTimeout(380);
      expect(await chassis.evaluate((element) => getComputedStyle(element).transform)).not.toBe(startingChassis);
      expect(await fastener.evaluate((element) => getComputedStyle(element).transform)).not.toBe(startingFastener);
      await expect(card.locator(".os-card__specular-seam")).not.toHaveCSS("opacity", "0");

      await page.mouse.move(1, 1);
      await page.waitForTimeout(380);
      expect(await chassis.evaluate((element) => getComputedStyle(element).transform)).toBe(startingChassis);
      expect(await fastener.evaluate((element) => getComputedStyle(element).transform)).toBe(startingFastener);
    } else {
      await expect(chassis).toHaveCSS("transition-duration", "0s");
      await expect(card.locator(".os-card__specular-seam")).toHaveCSS("opacity", "0");
    }

    const cardAction = card.getByRole("link").first();
    await cardAction.focus();
    await expect(cardAction).toBeFocused();
    await expect(cardAction).toHaveCSS("outline-style", "solid");
  });

  test("keeps the chassis static when reduced motion is requested", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();

    const card = page.locator(".os-dashboard-grid > .os-card[data-ti-plate]").first();
    await card.evaluate((element) => element.scrollIntoView({ block: "center", behavior: "instant" }));
    const chassis = card.locator(".os-card__chassis");
    await expect(chassis).toHaveCSS("transition-duration", "0s");
    const before = await chassis.evaluate((element) => getComputedStyle(element).transform);
    await card.hover();
    expect(await chassis.evaluate((element) => getComputedStyle(element).transform)).toBe(before);
    await expect(card.locator(".os-card__specular-seam")).toHaveCSS("opacity", "0");
  });
});

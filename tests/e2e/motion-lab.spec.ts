import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.motion-lab.review";

test.describe(`${TEST_ID} isolated production review`, () => {
  test("loads real verified keyframes and moves one stage by controls, keyboard, wheel, and restart", async ({ page, browserAudit }) => {
    await page.goto("/motion-lab", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Titanium Core Transformation", exact: true })).toBeVisible();
    await expect(page.getByText("Locked assembly", { exact: true })).toBeVisible();
    const play = page.getByRole("button", { name: "Play motion", exact: true });
    const timeline = page.getByRole("slider", { name: "Motion timeline", exact: true });
    const video = page.locator(".motion-lab__media video");
    await expect(play).toBeEnabled();
    await expect(timeline).toBeEnabled();
    await expect(video).toHaveAttribute("preload", "metadata");
    await expect(video).toHaveJSProperty("readyState", 0);

    const previous = page.getByRole("button", { name: "Previous motion stage", exact: true });
    const next = page.getByRole("button", { name: "Next motion stage", exact: true });
    await expect(previous).toBeDisabled();
    await expect(next).toBeEnabled();
    await next.click();
    await expect(page.getByText("Engineering explosion", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "View stage 2: Engineering explosion", exact: true })).toHaveAttribute("aria-current", "step");
    await expect(next).toBeEnabled();
    await expect(previous).toBeEnabled();

    await next.click();
    await expect(page.getByText("Architectural chassis", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "View stage 3: Architectural chassis", exact: true })).toHaveAttribute("aria-current", "step");
    await expect(next).toBeDisabled();

    const review = page.getByRole("region", { name: "Titanium motion review stage", exact: true });
    await review.focus();
    await page.keyboard.press("Home");
    await expect(page.getByText("Locked assembly", { exact: true })).toBeVisible();
    await page.keyboard.press("End");
    await expect(page.getByText("Architectural chassis", { exact: true })).toBeVisible();
    await review.dispatchEvent("wheel", { deltaY: -120 });
    await expect(page.getByText("Engineering explosion", { exact: true })).toBeVisible();

    await page.getByRole("button", { name: "View stage 2: Engineering explosion", exact: true }).click();
    await page.getByRole("button", { name: "Restart motion", exact: true }).click();
    await expect(page.getByText("Locked assembly", { exact: true })).toBeVisible();
    await expect(page.locator(".motion-lab__media img[alt^='Assembled sculptural Ti-Scale core']")).toBeVisible();
    await browserAudit.waitForPageApiSettlement(page);
  });

  test("uses verified static keyframes when reduced motion is requested", async ({ page, browserAudit }) => {
    await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
    await page.goto("/motion-lab", { waitUntil: "domcontentloaded" });
    const review = page.getByRole("region", { name: "Titanium motion review stage", exact: true });
    await expect(review).toHaveAttribute("data-reduced-motion", "true");
    await expect(page.getByText("Reduced motion is active. Use the stage controls to inspect verified keyframes.", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Play motion", exact: true })).toBeDisabled();
    await expect(page.getByRole("slider", { name: "Motion timeline", exact: true })).toBeDisabled();
    await page.getByRole("button", { name: "View stage 2: Engineering explosion", exact: true }).click();
    await expect(page.getByText("Engineering explosion", { exact: true })).toBeVisible();
    await expect.poll(() => page.locator(".motion-lab__media img").evaluate((image: HTMLImageElement) => image.complete && image.naturalWidth > 0)).toBe(true);
    await browserAudit.waitForPageApiSettlement(page);
  });
});

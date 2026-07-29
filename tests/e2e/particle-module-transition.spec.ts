import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.motion-lab.particle-module-transition";
const CANVAS_NAME = /^Interactive titanium particle transformation\./u;
const REDUCED_CANVAS_NAME = /^Static titanium particle transformation\./u;
const RETIRED_ASSET = /(?:higgsfield-motion|meshy|\.glb(?:$|[?#])|ti-scale-higgsfield-core|architectural-chassis)/iu;

const moduleRoutes = [
  "/", "/missions", "/live", "/guided", "/decisions", "/intelligence/evidence", "/intelligence/findings",
  "/agents", "/brain", "/brain/graph", "/learning", "/observability", "/reports", "/system",
] as const;

// This review route is intentionally awaiting operator approval. Keep a real
// successful browser recording alongside the three deterministic keyframes.
test.use({ video: "on" });

test.describe(`${TEST_ID} review evidence`, () => {
  test("reversibly disassembles the approved field and forms fourteen real module links", async ({ page, browserAudit }, testInfo) => {
    test.setTimeout(90_000);
    await page.goto("/motion-lab", { waitUntil: "domcontentloaded" });
    const reviewLink = page.getByRole("link", { name: "Review particle-to-module transition", exact: true });
    await expect(reviewLink).toBeVisible();

    const retiredRequests: string[] = [];
    page.on("request", (request) => { if (RETIRED_ASSET.test(request.url())) retiredRequests.push(request.url()); });
    await reviewLink.focus();
    await reviewLink.press("Enter");
    await expect.poll(() => new URL(page.url()).pathname).toBe("/motion-lab/particle-module-transition");

    const review = page.locator("main.particle-module-transition");
    await expect(page.getByRole("heading", { level: 1, name: "Particle field to operational modules", exact: true })).toBeVisible();
    await expect(review).toHaveAttribute("data-review-boundary", "review-only");
    await expect(review).toHaveAttribute("data-transition-section", "coherent-core");
    await expect(page.getByText("Review only · not integrated into Overview", { exact: true })).toBeVisible();
    await expect(review.locator("img, video, model-viewer")).toHaveCount(0);

    const canvas = page.getByRole("application", { name: CANVAS_NAME });
    const fallback = page.getByRole("alert");
    await expect(canvas.or(fallback)).toBeVisible({ timeout: 20_000 });
    const runtime = page.locator(".particle-module-transition__runtime");
    const hasWebgl = await canvas.count() === 1;
    if (hasWebgl) {
      await expect(runtime).toHaveAttribute("data-runtime-ready", "true");
      await expect(runtime).toHaveAttribute("data-module-target-count", "14");
      await expect(runtime).toHaveAttribute("data-draw-calls", "1");
      await expect.poll(async () => Number(await runtime.getAttribute("data-point-count"))).toBeGreaterThan(10_000);
    } else {
      await expect(fallback).toContainText(/WebGL 2 is unavailable|renderer could not load/u);
    }

    const assembledPath = testInfo.outputPath("particle-module-01-assembled.png");
    await review.screenshot({ path: assembledPath, animations: "disabled" });
    await testInfo.attach("particle-module-01-assembled", { path: assembledPath, contentType: "image/png" });

    const phaseButtons = page.getByRole("button", { name: /^View transition phase [1-4]: /u });
    await expect(phaseButtons).toHaveCount(4);
    await phaseButtons.nth(1).click();
    await expect(review).toHaveAttribute("data-transition-section", "cluster-release");
    await expect(phaseButtons.nth(1)).toHaveAttribute("aria-current", "step");
    if (hasWebgl) await expect.poll(async () => Number(await runtime.getAttribute("data-progress"))).toBeGreaterThan(0.98);

    await phaseButtons.nth(2).click();
    await expect(review).toHaveAttribute("data-transition-section", "module-alignment");
    if (hasWebgl) {
      await expect.poll(async () => {
        const value = Number(await runtime.getAttribute("data-module-progress"));
        return value > 0.45 && value < 0.56;
      }).toBe(true);
    }
    const alignmentPath = testInfo.outputPath("particle-module-02-alignment.png");
    await review.screenshot({ path: alignmentPath, animations: "disabled" });
    await testInfo.attach("particle-module-02-alignment", { path: alignmentPath, contentType: "image/png" });

    const next = page.getByRole("button", { name: "Next transition phase", exact: true });
    await next.click();
    await expect(review).toHaveAttribute("data-transition-section", "operational-modules");
    await expect(next).toBeDisabled();
    if (hasWebgl) await expect.poll(async () => Number(await runtime.getAttribute("data-module-progress"))).toBeGreaterThan(0.98);

    const moduleLinks = page.getByRole("link", { name: /^Open .+: /u });
    await expect(moduleLinks).toHaveCount(14);
    for (let index = 0; index < moduleRoutes.length; index += 1) {
      await expect(moduleLinks.nth(index)).toHaveAttribute("href", moduleRoutes[index]!);
      await expect(moduleLinks.nth(index)).toBeVisible();
    }
    const modulesPath = testInfo.outputPath("particle-module-03-operational-modules.png");
    await review.screenshot({ path: modulesPath, animations: "disabled" });
    await testInfo.attach("particle-module-03-operational-modules", { path: modulesPath, contentType: "image/png" });

    const previous = page.getByRole("button", { name: "Previous transition phase", exact: true });
    await previous.click();
    await expect(review).toHaveAttribute("data-transition-section", "module-alignment");
    await phaseButtons.nth(1).click();
    await expect(review).toHaveAttribute("data-transition-section", "cluster-release");
    await phaseButtons.nth(0).click();
    await expect(review).toHaveAttribute("data-transition-section", "coherent-core");
    await expect(previous).toBeDisabled();
    if (hasWebgl) {
      await expect.poll(async () => Number(await runtime.getAttribute("data-progress"))).toBeLessThan(0.02);
      await expect.poll(async () => Number(await runtime.getAttribute("data-module-progress"))).toBeLessThan(0.02);
    }

    await review.focus();
    await page.keyboard.press("End");
    await expect(review).toHaveAttribute("data-transition-section", "operational-modules");
    await page.keyboard.press("Home");
    await expect(review).toHaveAttribute("data-transition-section", "coherent-core");
    expect(retiredRequests).toEqual([]);
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });

    await page.getByRole("link", { name: "Return to Motion Lab", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/motion-lab");
  });
});

test.describe(`${TEST_ID} motion and recovery boundaries`, () => {
  test("uses an immediate stable equivalent under reduced motion", async ({ page, browserAudit }, testInfo) => {
    await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
    await page.goto("/motion-lab/particle-module-transition", { waitUntil: "domcontentloaded" });
    const review = page.locator("main.particle-module-transition");
    await expect(review).toHaveAttribute("data-reduced-motion", "true");
    const canvas = page.getByRole("application", { name: REDUCED_CANVAS_NAME });
    const fallback = page.getByRole("alert");
    await expect(canvas.or(fallback)).toBeVisible({ timeout: 20_000 });

    await page.getByRole("button", { name: "View transition phase 4: Operational modules", exact: true }).click();
    await expect(review).toHaveAttribute("data-transition-section", "operational-modules");
    await expect(page.getByRole("link", { name: /^Open .+: /u })).toHaveCount(14);
    if (await canvas.count() === 1) {
      const runtime = page.locator(".particle-module-transition__runtime");
      await expect(runtime).toHaveAttribute("data-reduced-motion", "true");
      await expect(runtime).toHaveAttribute("data-auto-rotate", "false");
      await expect(runtime).toHaveAttribute("data-hover-enabled", "false");
      await expect(runtime).toHaveAttribute("data-animation-state", "settled-reduced-motion");
      const before = await canvas.screenshot({ animations: "disabled" });
      await page.waitForTimeout(650);
      const after = await canvas.screenshot({ animations: "disabled" });
      expect(after.equals(before)).toBe(true);
    }
    const screenshotPath = testInfo.outputPath("particle-module-reduced-motion.png");
    await review.screenshot({ path: screenshotPath, animations: "disabled" });
    await testInfo.attach("particle-module-reduced-motion", { path: screenshotPath, contentType: "image/png" });
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
  });

  test("pauses the procedural animation when the document is hidden and resumes visibly", async ({ page, browserAudit }) => {
    await page.goto("/motion-lab/particle-module-transition", { waitUntil: "domcontentloaded" });
    const canvas = page.getByRole("application", { name: CANVAS_NAME });
    await expect(canvas.or(page.getByRole("alert"))).toBeVisible({ timeout: 20_000 });
    if (await canvas.count() === 0) {
      await expect(page.getByRole("alert")).toContainText(/WebGL 2 is unavailable|renderer could not load/u);
      return;
    }
    const runtime = page.locator(".particle-module-transition__runtime");
    await expect(runtime).toHaveAttribute("data-animation-state", "running");

    await page.evaluate(() => {
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await expect(runtime).toHaveAttribute("data-animation-state", "paused-hidden");
    await expect(page.locator("main.particle-module-transition")).toHaveAttribute("data-motion-state", "paused-hidden");
    const before = await canvas.screenshot({ animations: "disabled" });
    await page.waitForTimeout(500);
    const after = await canvas.screenshot({ animations: "disabled" });
    expect(after.equals(before)).toBe(true);

    await page.evaluate(() => {
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await expect(runtime).toHaveAttribute("data-animation-state", "running");
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
  });

  test("explains a missing WebGL boundary and remounts only after explicit retry", async ({ page, browserAudit }) => {
    await page.addInitScript(() => {
      const originalGetContext = HTMLCanvasElement.prototype.getContext;
      Object.defineProperty(window, "__tiScaleForceTransitionWebglUnavailable", { configurable: true, writable: true, value: true });
      Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
        configurable: true,
        value(this: HTMLCanvasElement, contextId: string, ...args: unknown[]) {
          const state = window as unknown as Record<string, unknown>;
          if (contextId === "webgl2" && state.__tiScaleForceTransitionWebglUnavailable === true) return null;
          return Reflect.apply(originalGetContext, this, [contextId, ...args]);
        },
      });
    });
    await page.goto("/motion-lab/particle-module-transition", { waitUntil: "domcontentloaded" });
    const alert = page.getByRole("alert");
    await expect(alert).toContainText("WebGL 2 is unavailable", { timeout: 20_000 });
    await page.evaluate(() => {
      (window as unknown as Record<string, unknown>).__tiScaleForceTransitionWebglUnavailable = false;
    });
    await page.getByRole("button", { name: "Retry transition renderer", exact: true }).click();
    await expect(page.getByRole("application", { name: CANVAS_NAME }).or(alert)).toBeVisible({ timeout: 20_000 });
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
  });
});

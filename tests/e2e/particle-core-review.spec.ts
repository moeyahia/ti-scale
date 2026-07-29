import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.motion-lab.particle-core";

test.describe(`${TEST_ID} procedural geometry gate`, () => {
  test("renders one local particle field and traverses every review control family", async ({ page, browserAudit }, testInfo) => {
    test.setTimeout(90_000);
    const remoteVisualRequests: string[] = [];
    page.on("request", (request) => {
      if (/playciso|meshy/i.test(request.url())) remoteVisualRequests.push(request.url());
    });

    await page.goto("/motion-lab", { waitUntil: "domcontentloaded" });
    await page.getByRole("link", { name: "Inspect active particle core", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/motion-lab/particle-core");
    await expect(page.getByRole("heading", { level: 1, name: "Titanium singularity", exact: true })).toBeVisible();
    await expect(page.getByText("Operator-approved particle geometry.", { exact: true })).toBeVisible();
    await expect(page.getByText("This deterministic field is now the active Ti-Scale Command Center artwork.", { exact: true })).toBeVisible();

    const canvas = page.getByRole("application", {
      name: "Interactive titanium particle-shell sculpture with fourteen separable clusters",
      exact: true,
    });
    const fallbackAlert = page.getByRole("alert");
    await expect(canvas.or(fallbackAlert)).toBeVisible({ timeout: 20_000 });
    const hasWebgl = await canvas.count() === 1;
    await expect(page.locator("canvas.particle-core-runtime__canvas")).toHaveCount(hasWebgl ? 1 : 0);
    const runtime = page.locator(".particle-core-runtime");
    if (hasWebgl) {
      await expect(runtime).toHaveAttribute("data-runtime-ready", "true");
      await expect(runtime).toHaveAttribute("data-cluster-count", "14");
      await expect.poll(async () => Number(await runtime.getAttribute("data-point-count"))).toBeGreaterThan(10_000);
      await expect(runtime).toHaveAttribute("data-draw-calls", "1");
      expect((await runtime.getAttribute("data-cluster-point-counts"))?.split(",")).toHaveLength(14);
    } else {
      await expect(fallbackAlert).toContainText("WebGL 2 is unavailable");
      await expect(page.getByText("14 deterministic clusters", { exact: true })).toBeVisible();
    }
    const assembledScreenshot = await page.locator(".particle-core-review__stage").screenshot({ animations: "disabled" });
    await testInfo.attach("particle-core-assembled", { body: assembledScreenshot, contentType: "image/png" });

    const clusterButtons = page.getByRole("button", { name: /^Inspect particle cluster \d+: /u });
    await expect(clusterButtons).toHaveCount(14);
    for (let index = 0; index < 14; index += 1) {
      await clusterButtons.nth(index).click();
      await expect(clusterButtons.nth(index)).toHaveAttribute("aria-pressed", "true");
      if (hasWebgl) await expect(runtime).toHaveAttribute("data-selected-cluster", String(index));
    }
    await page.getByRole("button", { name: "All 14", exact: true }).click();
    if (hasWebgl) await expect(runtime).toHaveAttribute("data-selected-cluster", "-1");

    await page.getByRole("button", { name: "Expansion", exact: true }).click();
    await expect(page.getByText("Expansion field · 48%", { exact: true })).toBeVisible();
    if (hasWebgl) {
      await expect.poll(async () => {
        const value = Number(await runtime.getAttribute("data-progress"));
        return value >= 0.475 && value <= 0.485;
      }).toBe(true);
    }
    await page.getByRole("button", { name: "Exploded", exact: true }).click();
    await expect(page.getByText("Fourteen clusters separated", { exact: true })).toBeVisible();
    if (hasWebgl) await expect.poll(async () => Number(await runtime.getAttribute("data-progress"))).toBeGreaterThan(0.995);
    const explodedScreenshot = await page.locator(".particle-core-review__stage").screenshot({ animations: "disabled" });
    await testInfo.attach("particle-core-exploded", { body: explodedScreenshot, contentType: "image/png" });
    await page.getByRole("button", { name: "Assembled", exact: true }).press("Enter");
    if (hasWebgl) await expect.poll(async () => Number(await runtime.getAttribute("data-progress"))).toBeLessThan(0.005);

    const scrubber = page.getByRole("slider", { name: "Particle cluster separation", exact: true });
    await scrubber.fill("720");
    await expect(page.getByText("Expansion field · 72%", { exact: true })).toBeVisible();
    if (hasWebgl) {
      await expect.poll(async () => {
        const value = Number(await runtime.getAttribute("data-progress"));
        return value >= 0.715 && value <= 0.725;
      }).toBe(true);
    }

    for (const name of ["Rotate −", "Rotate +", "Zoom +", "Zoom −", "Reset"]) {
      const control = page.getByRole("button", { name, exact: true });
      if (hasWebgl) {
        await expect(control).toBeEnabled();
        await control.click();
      } else {
        await expect(control).toBeDisabled();
      }
    }
    if (hasWebgl) {
      await canvas.focus();
      const initialYaw = await runtime.getAttribute("data-camera-yaw");
      await page.keyboard.press("ArrowRight");
      await expect.poll(() => runtime.getAttribute("data-camera-yaw")).not.toBe(initialYaw);
      await page.keyboard.press("+");
      await page.keyboard.press("-");
      await page.keyboard.press("Home");

      const canvasBounds = await canvas.boundingBox();
      expect(canvasBounds).not.toBeNull();
      if (canvasBounds) {
        const pointerYaw = await runtime.getAttribute("data-camera-yaw");
        await page.mouse.move(canvasBounds.x + canvasBounds.width * 0.5, canvasBounds.y + canvasBounds.height * 0.5);
        await page.mouse.down();
        await page.mouse.move(canvasBounds.x + canvasBounds.width * 0.62, canvasBounds.y + canvasBounds.height * 0.57, { steps: 4 });
        await page.mouse.up();
        await expect.poll(() => runtime.getAttribute("data-camera-yaw")).not.toBe(pointerYaw);

        const pointerDistance = await runtime.getAttribute("data-camera-distance");
        await canvas.hover();
        await page.mouse.wheel(0, 180);
        await expect.poll(() => runtime.getAttribute("data-camera-distance")).not.toBe(pointerDistance);
      }
    }

    const orbitalDrift = page.getByRole("checkbox", { name: "Orbital drift", exact: true });
    await expect(orbitalDrift).toBeChecked();
    await orbitalDrift.uncheck();
    if (hasWebgl) await expect(page.locator(".particle-core-runtime")).toHaveAttribute("data-auto-rotate", "false");
    const reducedMotion = page.getByRole("checkbox", { name: "Reduced motion", exact: true });
    await reducedMotion.check();
    await expect(page.locator("main.particle-core-review")).toHaveAttribute("data-reduced-motion", "true");
    await expect(orbitalDrift).toBeDisabled();
    await reducedMotion.uncheck();

    const listToggle = page.getByRole("button", { name: /^(?:Show|Hide) field list$/u });
    await listToggle.click();
    const list = page.getByRole("region", { name: "Accessible particle cluster list", exact: true });
    await expect(list).toBeVisible();
    await expect(list.getByRole("listitem")).toHaveCount(14);
    await expect(listToggle).toHaveAccessibleName("Hide field list");
    await listToggle.click();
    await expect(list).toBeHidden();
    await expect(listToggle).toHaveAccessibleName("Show field list");
    await listToggle.click();
    await expect(list).toBeVisible();
    await list.getByRole("button", { name: "Close list", exact: true }).click();
    await expect(list).toBeHidden();

    expect(remoteVisualRequests).toEqual([]);
    const screenshot = await page.locator(".particle-core-review__stage").screenshot({ animations: "disabled" });
    await testInfo.attach("particle-core-review", { body: screenshot, contentType: "image/png" });
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
    await page.getByRole("link", { name: "Return to Motion Lab", exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe("/motion-lab");
    await expect(page.getByRole("heading", { level: 1, name: "Titanium Core Transformation", exact: true })).toBeVisible();
  });

  test("stops continuous field motion for the operating-system reduced-motion preference", async ({ page, browserAudit }) => {
    test.setTimeout(60_000);
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/motion-lab/particle-core", { waitUntil: "domcontentloaded" });
    const reducedMotion = page.getByRole("checkbox", { name: "Reduced motion · system", exact: true });
    await expect(reducedMotion).toBeChecked();
    await expect(reducedMotion).toBeDisabled();
    await expect(page.getByRole("checkbox", { name: "Orbital drift", exact: true })).toBeDisabled();
    const runtime = page.locator(".particle-core-runtime");
    const canvas = page.locator("canvas.particle-core-runtime__canvas");
    await expect(canvas.or(page.getByRole("alert"))).toBeVisible({ timeout: 20_000 });
    if (await canvas.count() === 1) {
      await expect(runtime).toHaveAttribute("data-runtime-ready", "true", { timeout: 20_000 });
      await page.waitForTimeout(300);
      const before = await canvas.screenshot({ animations: "disabled" });
      await page.waitForTimeout(700);
      const after = await canvas.screenshot({ animations: "disabled" });
      expect(after.equals(before)).toBe(true);
    } else {
      await expect(page.getByRole("alert")).toContainText("WebGL 2 is unavailable");
      await expect(page.getByRole("button", { name: "Show field list", exact: true })).toBeEnabled();
    }
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
  });

  test("explains WebGL 2 failure and recovers only after an explicit renderer retry", async ({ page, browserAudit }) => {
    test.setTimeout(60_000);
    await page.addInitScript(() => {
      const originalGetContext = HTMLCanvasElement.prototype.getContext;
      const nativeWebglAvailable = Boolean(document.createElement("canvas").getContext("webgl2"));
      Object.defineProperty(window, "__tiScaleNativeParticleWebglAvailable", {
        configurable: true,
        writable: false,
        value: nativeWebglAvailable,
      });
      Object.defineProperty(window, "__tiScaleForceParticleWebglUnavailable", {
        configurable: true,
        writable: true,
        value: true,
      });
      Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
        configurable: true,
        value(this: HTMLCanvasElement, contextId: string, ...args: unknown[]) {
          const state = window as unknown as Record<string, unknown>;
          if (contextId === "webgl2" && state.__tiScaleForceParticleWebglUnavailable === true) return null;
          return Reflect.apply(originalGetContext, this, [contextId, ...args]);
        },
      });
    });

    await page.goto("/motion-lab/particle-core", { waitUntil: "domcontentloaded" });
    const error = page.getByRole("alert");
    await expect(error).toContainText("WebGL 2 is unavailable", { timeout: 20_000 });
    await expect(error).toContainText("complete 14-cluster description remains available");
    await expect(page.getByRole("application", {
      name: "Interactive titanium particle-shell sculpture with fourteen separable clusters",
      exact: true,
    })).toHaveCount(0);

    await page.evaluate(() => {
      const state = window as unknown as Record<string, unknown>;
      state.__tiScaleForceParticleWebglUnavailable = false;
    });
    await page.getByRole("button", { name: "Retry particle renderer", exact: true }).click();
    const nativeWebglAvailable = await page.evaluate(() =>
      (window as unknown as Record<string, unknown>).__tiScaleNativeParticleWebglAvailable === true
    );
    const canvas = page.getByRole("application", {
      name: "Interactive titanium particle-shell sculpture with fourteen separable clusters",
      exact: true,
    });
    if (nativeWebglAvailable) {
      await expect(canvas).toBeVisible({ timeout: 20_000 });
      await expect(page.locator(".particle-core-runtime")).toHaveAttribute("data-runtime-ready", "true");
      await expect(error).toHaveCount(0);
    } else {
      await expect(canvas).toHaveCount(0);
      await expect(error).toContainText("WebGL 2 is unavailable");
      await expect(page.getByRole("button", { name: "Show field list", exact: true })).toBeEnabled();
    }
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
  });
});

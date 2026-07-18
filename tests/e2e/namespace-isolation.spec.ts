import { createHash } from "node:crypto";
import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.namespace.isolation";
const PREFIX = "ti-scale.";
const LEGACY_LOCAL_KEY = "external-source.missions.saved-views.v1";
const LEGACY_SESSION_KEY = "external-source.brain.graph-root";

test.describe(`${TEST_ID} browser and asset boundary`, () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(({ localKey, sessionKey, prefix }) => {
      localStorage.setItem(localKey, "legacy-local-sentinel");
      sessionStorage.setItem(sessionKey, "legacy-session-sentinel");
      localStorage.setItem(`${prefix}test-sentinel`, "v2-sentinel");
    }, { localKey: LEGACY_LOCAL_KEY, sessionKey: LEGACY_SESSION_KEY, prefix: PREFIX });
  });

  test("does not read, migrate, overwrite, or delete legacy browser keys", async ({ page, browserAudit }) => {
    await page.goto("/brain/graph");
    await expect(page.locator("main#ti-scale-content")).toBeVisible();
    const graphOrEmptyState = page.locator(
      "canvas[role='application'][aria-label^='Memory graph with'], .brain-empty",
    ).first();
    await expect(graphOrEmptyState).toBeVisible();
    const graph = page.getByRole("application", { name: /^Memory graph with /u });
    if (await graph.isVisible()) {
      await expect(graph).toHaveAttribute("aria-busy", "false");
      await expect(page.getByText("Memory graph layout ready", { exact: true })).toBeVisible();
    }
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 1_000 });
    const storage = await page.evaluate(({ localKey, sessionKey }) => ({
      localLegacy: localStorage.getItem(localKey),
      sessionLegacy: sessionStorage.getItem(sessionKey),
      localKeys: Object.keys(localStorage),
      sessionKeys: Object.keys(sessionStorage),
    }), { localKey: LEGACY_LOCAL_KEY, sessionKey: LEGACY_SESSION_KEY });
    expect(storage.localLegacy).toBe("legacy-local-sentinel");
    expect(storage.sessionLegacy).toBe("legacy-session-sentinel");
    expect(storage.localKeys.filter((key) => key !== LEGACY_LOCAL_KEY).every((key) => key.startsWith(PREFIX))).toBe(true);
    expect(storage.sessionKeys.filter((key) => key !== LEGACY_SESSION_KEY).every((key) => key.startsWith(PREFIX))).toBe(true);
  });

  test("keeps cache, service-worker, resource, and Ti-Scale identities isolated", async ({ page, browserAudit }) => {
    await page.goto("/manual");
    const cacheNames = await page.evaluate(() => caches.keys());
    expect(cacheNames.every((name) => name.startsWith(PREFIX))).toBe(true);
    const registrations = await page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).map((registration) => registration.scope));
    expect(registrations.every((scope) => !scope.includes("/webapp/"))).toBe(true);
    const resources = await page.evaluate(() => performance.getEntriesByType("resource").map((entry) => entry.name));
    expect(resources.some((url) => url.includes("/webapp/"))).toBe(false);

    const serviceWorker = await browserAudit.request(page.request, { method: "GET", url: "/sw-v2.js" });
    expect(serviceWorker.status()).toBe(200);
    const serviceWorkerText = await serviceWorker.text();
    expect(serviceWorkerText).toContain("ti-scale.");
    expect(serviceWorkerText).not.toContain("ti-scale-");

    const mark = await browserAudit.request(page.request, { method: "GET", url: "/brand-v2/source/ti-scale-mark.svg" });
    const wordmark = await browserAudit.request(page.request, { method: "GET", url: "/brand-v2/source/ti-scale-wordmark.svg" });
    expect(mark.status()).toBe(200);
    expect(wordmark.status()).toBe(200);
    expect(createHash("sha256").update(await mark.body()).digest("hex")).toBe("2fac133ce565d70d5dc14791934c3dcd76c77ae7d283ca435ad40f8fbd8b6731");
    expect(createHash("sha256").update(await wordmark.body()).digest("hex")).toBe("509eed9f2539fd3f8dba48543dc2b9b0d6bbf9321ba749644dcde213ebf23646");
  });
});

import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.meshy-webgl.retired-alias";

test(`${TEST_ID} preserves the old bookmark without loading the retired candidate runtime`, async ({ page, browserAudit }) => {
  const retiredAssetRequests: string[] = [];
  page.on("request", (request) => {
    const pathname = new URL(request.url()).pathname;
    if (pathname.endsWith(".glb") || pathname.endsWith("/approved-webgl-manifest.json")) {
      retiredAssetRequests.push(request.url());
    }
  });

  await page.goto("/motion-lab/webgl", { waitUntil: "domcontentloaded" });
  await expect.poll(() => new URL(page.url()).pathname).toBe("/motion-lab/particle-core");
  await expect(page.getByRole("heading", { level: 1, name: "Titanium singularity", exact: true })).toBeVisible();
  await expect(page.getByText("Operator-approved particle geometry.", { exact: true })).toBeVisible();
  await expect(page.getByText("This deterministic field is now the active Ti-Scale Command Center artwork.", { exact: true })).toBeVisible();
  expect(retiredAssetRequests).toEqual([]);
  await browserAudit.waitForPageApiSettlement(page);
});

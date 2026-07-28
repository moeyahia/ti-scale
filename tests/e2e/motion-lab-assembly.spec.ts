import { expect, test } from "./support/playwright";

const TEST_ID = "e2e.motion-lab.assembly-review";
const ASSEMBLY_MANIFEST_PATH = "/review-assets/ti-scale-14-elements/v1/assembly-manifest.json";

test(`${TEST_ID} retires the rejected assembly route without requesting its manifest or GLBs`, async ({ page, browserAudit }) => {
  test.setTimeout(60_000);
  const retiredReviewRequests: string[] = [];
  page.on("request", (request) => {
    const pathname = new URL(request.url()).pathname;
    if (pathname === ASSEMBLY_MANIFEST_PATH || (
      pathname.startsWith("/review-assets/ti-scale-14-elements/v1/models/")
      && pathname.endsWith(".glb")
    )) retiredReviewRequests.push(request.url());
  });

  await page.goto("/motion-lab/assembly", { waitUntil: "domcontentloaded" });
  await expect.poll(() => new URL(page.url()).pathname).toBe("/motion-lab/particle-core");
  await expect(page.getByRole("heading", { level: 1, name: "Titanium singularity", exact: true })).toBeVisible();
  await expect(page.getByText("Operator-approved particle geometry.", { exact: true })).toBeVisible();
  await expect(page.getByText("This deterministic field is now the active Ti-Scale Command Center artwork.", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: "Ti-Scale 14-element assembly", exact: true })).toHaveCount(0);
  await expect(page.getByRole("application", {
    name: "Interactive titanium particle-shell sculpture with fourteen separable clusters",
    exact: true,
  }).or(page.getByRole("alert"))).toBeVisible({ timeout: 20_000 });
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  expect(retiredReviewRequests).toEqual([]);
});

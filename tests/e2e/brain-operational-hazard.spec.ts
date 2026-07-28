import { expect, test } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import { createBrainOperationalHazardFixture, type BrainOperationalHazardFixture } from "./support/brainOperationalHazardFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

let fixture: BrainOperationalHazardFixture;

test.beforeAll(({}, testInfo) => {
  fixture = createBrainOperationalHazardFixture(canonicalFixtureNamespace(testInfo, "brain-operational-hazard"));
});

test("e2e.brain-node.operational-hazard renders the exact guardrail without private engagement provenance", async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const detailRead = page.waitForResponse((response) => response.request().method() === "GET"
    && new URL(response.url()).pathname === `/api/v2/brain/nodes/${fixture.nodeId}`
    && response.status() === 200);
  await page.goto(`/brain/nodes/${fixture.nodeId}`, { waitUntil: "domcontentloaded" });
  expect((await detailRead).status()).toBe(200);
  await expect(page.getByRole("heading", { name: fixture.hazardTitle, exact: true }).first()).toBeVisible();

  const panel = page.getByRole("region", { name: "Operational hazard guardrail", exact: true });
  await expect(panel).toBeVisible();
  await expect(panel.getByRole("heading", { name: "Operational hazard", exact: true })).toBeVisible();
  await expect(panel.getByText("A healthy baseline is not permission to repeat the known-bad procedure.", { exact: true })).toBeVisible();
  await expect(panel.getByText(/must also use the recorded safer sequence and parameter exclusions/u)).toBeVisible();
  await expect(panel.getByRole("link", { name: fixture.procedureTitle, exact: true })).toBeVisible();
  await expect(panel.getByText("Exact corroborated hang count", { exact: true })).toBeVisible();
  await expect(panel.locator(".brain-hazard-counts > div").filter({ hasText: "Exact corroborated hang count" }).getByText("2", { exact: true })).toBeVisible();
  await expect(panel.locator(".brain-hazard-counts > div").filter({ hasText: "Exact resets for this procedure" }).getByText("2", { exact: true })).toBeVisible();
  await expect(panel.getByText("Operator-reported overall reset minimum", { exact: true })).toBeVisible();
  await expect(panel.locator(".brain-hazard-counts").getByText("11", { exact: true })).toBeVisible();
  await expect(panel.getByText("Overall minimum not tied to this procedure", { exact: true })).toBeVisible();
  await expect(panel.locator(".brain-hazard-counts").getByText("9", { exact: true })).toBeVisible();
  await expect(panel.getByRole("heading", { name: "Safe health gate", exact: true })).toBeVisible();
  await expect(panel.getByText("A fresh minimal execution health probe returns the expected scalar result", { exact: true })).toBeVisible();
  await expect(panel.getByRole("heading", { name: "Unsafe retry conditions", exact: true })).toBeVisible();
  await expect(panel.getByRole("heading", { name: "Safer sequence", exact: true })).toBeVisible();
  await expect(panel.getByText(/opaque source receipt/u)).toBeVisible();
  await expect(panel.getByRole("textbox")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText(fixture.privateSourcePath);
  await expect(page.locator("body")).not.toContainText(fixture.privateSourceHash);

  const resetReview = page.getByRole("region", { name: "Reset attribution review", exact: true });
  await expect(resetReview.getByText(/never assigns the unresolved remainder to this procedure/u)).toBeVisible();
  const resetReviewToggle = resetReview.getByRole("button", { name: "Review reset attribution", exact: true });
  await expect(resetReviewToggle).toHaveAttribute("id", "brain-node-hazard-reset-review-toggle");
  await expect(resetReviewToggle).toHaveAttribute("data-testid", "brain-node-hazard-reset-review-toggle");
  await resetReviewToggle.click();
  const runSelector = resetReview.getByRole("combobox", { name: "Related mission run", exact: true });
  await expect(runSelector).toHaveAttribute("id", "brain-node-hazard-reset-run");
  await expect(runSelector).toContainText(fixture.runId);
  await expect(resetReview.getByText("Exact attributable resets in this run", { exact: true })).toBeVisible();
  await expect(resetReview.getByText("Still awaiting procedure attribution", { exact: true })).toBeVisible();
  const minimumInput = resetReview.getByRole("spinbutton", { name: "Overall reset episodes (minimum)", exact: true });
  await expect(minimumInput).toHaveAttribute("id", "brain-node-hazard-reset-minimum");
  await expect(minimumInput).toHaveAttribute("data-testid", "brain-node-hazard-reset-minimum");
  await minimumInput.fill("13");
  const aggregateBoundary = resetReview.getByRole("checkbox", {
    name: "Keep this as an overall run minimum only; do not assign it to this procedure.",
    exact: true,
  });
  await expect(aggregateBoundary).toHaveAttribute("id", "brain-node-hazard-reset-boundary");
  await expect(aggregateBoundary).toHaveAttribute("data-testid", "brain-node-hazard-reset-boundary");
  await aggregateBoundary.check();
  const aggregateWrite = page.waitForResponse((response) => response.request().method() === "POST"
    && new URL(response.url()).pathname === `/api/v2/missions/${fixture.missionId}/runs/${fixture.runId}/operational-hazards/reset-minimum-observations`);
  const recordLowerBound = resetReview.getByRole("button", { name: "Record overall lower bound", exact: true });
  await expect(recordLowerBound).toHaveAttribute("id", "brain-node-hazard-reset-record");
  await expect(recordLowerBound).toHaveAttribute("data-testid", "brain-node-hazard-reset-record");
  await recordLowerBound.click();
  expect((await aggregateWrite).status()).toBe(201);
  await expect(resetReview.getByText(/Recorded at least 13 reset episodes for this run/u)).toBeVisible();
  await expect(resetReview.getByText(/Exact procedure attribution was not changed/u)).toBeVisible();
  const runTotals = resetReview.locator(".brain-hazard-reset-totals");
  await expect(runTotals.getByText("0", { exact: true })).toBeVisible();
  await expect(runTotals.getByText("13", { exact: true })).toHaveCount(2);

  await panel.getByRole("link", { name: fixture.procedureTitle, exact: true }).click();
  await expect(page).toHaveURL(`/brain/nodes/${fixture.procedureNodeId}`);
  await expect(page.getByRole("heading", { name: fixture.procedureTitle, exact: true }).first()).toBeVisible();
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(panel).toBeVisible();

  expect(audit.unexpected, "Unexpected browser failures").toEqual([]);
  expect(audit.degradedApi, "Required V2 API requests must not degrade").toEqual([]);
  await audit.assertClean(testInfo);
});

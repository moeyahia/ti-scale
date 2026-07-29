import { expect, test } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createOperatorPreferencesFixture,
  type OperatorPreferencesFixture,
} from "./support/operatorPreferencesFixture";

const TEST_ID = "e2e.brain-preferences.confirmed-profile";
let fixture: OperatorPreferencesFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createOperatorPreferencesFixture(canonicalFixtureNamespace(testInfo, "operator-preferences"));
});

test(`${TEST_ID} exposes only the authenticated operator's confirmed profile and traverses its canonical links`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const response = page.waitForResponse((candidate) => (
    candidate.request().method() === "GET"
    && new URL(candidate.url()).pathname === "/api/v2/brain/preferences"
  ));
  await page.goto("/brain/preferences", { waitUntil: "domcontentloaded" });
  expect((await response).status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1, name: "Operator Preferences", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Preference isolation boundary", exact: true })).toContainText(
    "never authorization",
  );
  // Browser projects intentionally share one invocation-owned database, so a
  // cross-browser run may retain one isolated confirmed profile per project.
  // Prove the authenticated projection is populated, then assert this exact
  // fixture card and its source below instead of coupling the journey to an
  // execution-order-dependent total.
  await expect(page.getByRole("status").filter({ hasText: "confirmed operator preference" }))
    .toHaveText(/^[1-9]\d* confirmed operator preferences?\./u);

  const card = page.locator(".brain-preference-card").filter({
    has: page.getByRole("heading", { level: 2, name: fixture.title, exact: true }),
  });
  await expect(card).toContainText("Explicit operator confirmation");
  await expect(card).toContainText(fixture.sourceId);
  await expect(card.getByRole("region", { name: "Preference applies to", exact: true })).toContainText("Guided explanations");

  const memoryRecord = card.getByRole("link", { name: "Open memory record", exact: true });
  await expect(memoryRecord).toHaveAttribute("href", `/brain/nodes/${fixture.nodeId}`);
  await memoryRecord.click();
  await expect(page).toHaveURL(`/brain/nodes/${fixture.nodeId}`);
  await expect(page.getByRole("heading", { level: 1, name: fixture.title, exact: true })).toBeVisible();
  const operatorPreferences = page.getByRole("link", {
    name: "Operator Preferences",
    exact: true,
  });
  await expect(operatorPreferences).toHaveAttribute("href", "/brain/preferences");
  await operatorPreferences.click();
  await expect(page).toHaveURL("/brain/preferences");
  await expect(page.getByRole("heading", {
    level: 1,
    name: "Operator Preferences",
    exact: true,
  })).toBeVisible();
  await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
  await expect(page).toHaveURL(`/brain/nodes/${fixture.nodeId}`);
  await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
  await expect(page).toHaveURL("/brain/preferences");

  const showInGraph = card.getByRole("link", { name: "Show in Operator graph", exact: true });
  await expect(showInGraph).toHaveAttribute(
    "href",
    `/brain/graph?view=operator&selected=${encodeURIComponent(fixture.nodeId)}`,
  );
  const graphWorkerLoaded = page.waitForResponse((candidate) => {
    const pathname = new URL(candidate.url()).pathname;
    return candidate.request().method() === "GET"
      && (
        /\/assets\/memoryGraphLayout\.worker-[^/]+\.js$/u.test(pathname)
        || pathname === "/src/workers/memoryGraphLayout.worker.ts"
      )
      && candidate.status() === 200;
  });
  await showInGraph.focus();
  await showInGraph.press("Enter");
  await expect(page).toHaveURL(`/brain/graph?view=operator&selected=${encodeURIComponent(fixture.nodeId)}`);
  await expect(page.getByRole("heading", { level: 1, name: "Memory Graph", exact: true })).toBeVisible();
  await graphWorkerLoaded;
  await expect(page.getByRole("status").filter({ hasText: "Attack-knowledge brain layout ready" })).toBeVisible();
  await audit.assertClean(testInfo);
});

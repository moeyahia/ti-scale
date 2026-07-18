import { expect, test, type Locator, type Page, type Response, type TestInfo } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import {
  advanceBrainNodeVersion,
  createBrainNodeLifecycleFixture,
  readBrainNodeLifecycleState,
  type BrainNodeLifecycleFixture,
} from "./support/brainNodeLifecycleFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_IDS = {
  lifecycle: "e2e.brain-node.lifecycle-controls",
  conflictForget: "e2e.brain-node.conflict-forget",
} as const;

let fixture: BrainNodeLifecycleFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createBrainNodeLifecycleFixture(canonicalFixtureNamespace(testInfo, "brain-node-lifecycle"));
});

function mutationResponse(page: Page, operation: string, status = 200): Promise<Response> {
  const path = `/api/v2/brain/nodes/${fixture.nodeId}/${operation}`;
  return page.waitForResponse((response) => response.request().method() === "POST"
    && new URL(response.url()).pathname === path
    && response.status() === status);
}

function nodeRead(page: Page): Promise<Response> {
  return page.waitForResponse((response) => response.request().method() === "GET"
    && new URL(response.url()).pathname === `/api/v2/brain/nodes/${fixture.nodeId}`
    && response.status() === 200);
}

async function activate(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await control.press("Enter");
  } else {
    await control.click();
  }
}

function versionValue(page: Page): Locator {
  return page.locator(".brain-node-banner > div").filter({ hasText: /^Version/u }).locator("strong");
}

async function strictAudit(audit: BrowserAudit, testInfo: TestInfo): Promise<void> {
  expect(audit.unexpected, "Unexpected browser failures").toEqual([]);
  expect(audit.degradedApi, "Required V2 API requests must not degrade").toEqual([]);
  await audit.assertClean(testInfo);
}

test(`${TEST_IDS.lifecycle} versions correction, pinning, retention, dispute, and Context Pack use`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const initialRead = nodeRead(page);
  await page.goto(`/brain/nodes/${fixture.nodeId}`, { waitUntil: "domcontentloaded" });
  expect((await initialRead).status()).toBe(200);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await expect(page.getByRole("heading", { name: fixture.initialTitle, exact: true }).first()).toBeVisible();
  await expect(versionValue(page)).toHaveText("1");

  const contextRead = page.waitForResponse((response) => response.request().method() === "GET"
    && new URL(response.url()).pathname === `/api/v2/brain/context-packs/${fixture.contextPackId}`
    && response.status() === 200);
  await activate(page.getByRole("button", { name: /^Explain why evidence appears before technique detail/u }), "keyboard");
  expect((await contextRead).status()).toBe(200);
  await expect(page.getByRole("heading", { name: "Explain why evidence appears before technique detail", exact: true })).toBeVisible();
  await expect(page.getByText("Attributable evidence is presented before technical attack detail.", { exact: true })).toBeVisible();

  await activate(page.getByRole("button", { name: "Correct memory", exact: true }), "pointer");
  let dialog = page.getByRole("dialog", { name: "Correct memory", exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("textbox", { name: "Title", exact: true })).toBeFocused();
  await activate(dialog.getByRole("button", { name: "Cancel", exact: true }), "pointer");
  await expect(dialog).toHaveCount(0);
  await activate(page.getByRole("button", { name: "Correct memory", exact: true }), "keyboard");
  dialog = page.getByRole("dialog", { name: "Correct memory", exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("textbox", { name: "Title", exact: true })).toBeFocused();
  const correctedTitle = `Evidence-first mission preference ${fixture.namespace}`;
  await dialog.getByRole("textbox", { name: "Title", exact: true }).fill(correctedTitle);
  await dialog.getByRole("textbox", { name: "Summary", exact: true }).fill("Lead with attributable evidence, then explain the bounded technique.");
  await dialog.getByRole("textbox", { name: "Note body", exact: true }).fill("The operator corrected this mission-scoped preference through the versioned browser control.");
  await dialog.getByRole("combobox", { name: "Sensitivity", exact: true }).selectOption("internal");
  await dialog.getByRole("textbox", { name: "Reason for correction", exact: true }).fill("Clarified the confirmed explanation order and mission scope.");
  const correction = mutationResponse(page, "correct");
  await activate(dialog.getByRole("button", { name: "Save correction", exact: true }), "keyboard");
  expect((await correction).status()).toBe(200);
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("heading", { name: correctedTitle, exact: true }).first()).toBeVisible();
  await expect(versionValue(page)).toHaveText("2");
  expect(readBrainNodeLifecycleState(fixture)).toMatchObject({
    title: correctedTitle,
    lifecycleStatus: "confirmed",
    sensitivity: "internal",
    version: 2,
    pinned: false,
    versionCount: 2,
  });

  const pin = mutationResponse(page, "pin");
  await activate(page.getByRole("button", { name: "Pin memory", exact: true }), "pointer");
  expect((await pin).status()).toBe(200);
  await expect(page.getByRole("button", { name: "Unpin memory", exact: true })).toBeVisible();
  await expect(versionValue(page)).toHaveText("3");
  expect(readBrainNodeLifecycleState(fixture).pinned).toBe(true);

  const unpin = mutationResponse(page, "pin");
  await activate(page.getByRole("button", { name: "Unpin memory", exact: true }), "keyboard");
  expect((await unpin).status()).toBe(200);
  await expect(page.getByRole("button", { name: "Pin memory", exact: true })).toBeVisible();
  await expect(versionValue(page)).toHaveText("4");
  expect(readBrainNodeLifecycleState(fixture).pinned).toBe(false);

  const expiryInput = page.getByLabel("Expire on", { exact: true });
  await expiryInput.fill("2100-01-01T00:00");
  const expiry = mutationResponse(page, "expire");
  await activate(page.getByRole("button", { name: "Set expiry", exact: true }), "pointer");
  expect((await expiry).status()).toBe(200);
  await expect(versionValue(page)).toHaveText("5");
  expect(readBrainNodeLifecycleState(fixture)).toMatchObject({
    expiresAt: "2100-01-01T00:00:00.000Z",
    lifecycleStatus: "confirmed",
    version: 5,
  });

  await page.getByRole("textbox", { name: "Dispute reason", exact: true }).fill("A newer operator decision contradicts this retained preference.");
  const dispute = mutationResponse(page, "dispute");
  await activate(page.getByRole("button", { name: "Mark disputed", exact: true }), "keyboard");
  expect((await dispute).status()).toBe(200);
  await expect(versionValue(page)).toHaveText("6");
  await expect(page.locator(".brain-node-banner").getByText("disputed", { exact: true })).toBeVisible();
  const disputedState = readBrainNodeLifecycleState(fixture);
  expect(disputedState).toMatchObject({
    lifecycleStatus: "disputed",
    version: 6,
    sourceCount: 1,
    versionCount: 6,
    edgeCount: 1,
    representedContextItemCount: 1,
    suppressionCount: 0,
  });
  expect(disputedState.contextItemCount).toBeGreaterThanOrEqual(1);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.conflictForget} reconciles a stale mutation and permanently erases reusable memory`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: [{
      id: "brain-node.pin-version-conflict",
      transport: "browser",
      method: "POST",
      pathname: `/api/v2/brain/nodes/${fixture.nodeId}/pin`,
      query: {},
      status: 409,
      occurrences: 1,
      reason: "Prove a stale node version fails closed before refresh and retry.",
    }],
  });
  const initialRead = nodeRead(page);
  await page.goto(`/brain/nodes/${fixture.nodeId}`, { waitUntil: "domcontentloaded" });
  expect((await initialRead).status()).toBe(200);
  await expect(versionValue(page)).toHaveText("6");
  expect(advanceBrainNodeVersion(fixture)).toBe(7);

  const conflict = mutationResponse(page, "pin", 409);
  await activate(page.getByRole("button", { name: "Pin memory", exact: true }), "pointer");
  const conflictResponse = await conflict;
  const error = await conflictResponse.json() as { error: { code: string; remediation: string; traceId: string } };
  expect(error.error).toMatchObject({
    code: "memory_version_conflict",
    remediation: "Refresh the node before applying this change.",
  });
  await expect(page.getByRole("alert")).toContainText("Memory changed after it was loaded");
  await expect(page.getByRole("alert")).toContainText("Refresh the node before applying this change.");
  await expect(page.getByRole("alert")).toContainText(`Trace ${error.error.traceId}`);

  const refreshed = nodeRead(page);
  await activate(page.getByRole("button", { name: "Try again", exact: true }), "keyboard");
  expect((await refreshed).status()).toBe(200);
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(versionValue(page)).toHaveText("7");
  await expect(page.getByRole("button", { name: "Unpin memory", exact: true })).toBeVisible();

  const unpin = mutationResponse(page, "pin");
  await activate(page.getByRole("button", { name: "Unpin memory", exact: true }), "pointer");
  expect((await unpin).status()).toBe(200);
  await expect(versionValue(page)).toHaveText("8");
  await expect(page.getByRole("button", { name: "Pin memory", exact: true })).toBeVisible();

  await page.getByRole("textbox", { name: "Reason", exact: true }).fill("Remove this preference and prevent its reusable content from being retrieved again.");
  await page.getByRole("textbox", { name: "Type FORGET", exact: true }).fill("FORGET");
  const forget = mutationResponse(page, "forget");
  await activate(page.getByRole("button", { name: "Forget permanently", exact: true }), "keyboard");
  const forgetResponse = await forget;
  expect(forgetResponse.status(), await forgetResponse.text()).toBe(200);
  await expect(page).toHaveURL("/brain");
  await expect(page.getByRole("heading", { name: "Second Brain", exact: true }).first()).toBeVisible();

  expect(readBrainNodeLifecycleState(fixture)).toEqual({
    title: "[Forgotten memory]",
    summary: "",
    body: "",
    lifecycleStatus: "forgotten",
    sensitivity: "internal",
    version: 9,
    pinned: false,
    expiresAt: expect.any(String),
    sourceCount: 0,
    versionCount: 0,
    edgeCount: 0,
    contextItemCount: 0,
    representedContextItemCount: 0,
    suppressionCount: 1,
    forgottenAuditCount: 1,
  });
  await strictAudit(audit, testInfo);
});

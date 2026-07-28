import { expect, test, type Locator, type Page, type TestInfo } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import { waitForInteractiveApplication } from "./support/applicationReadiness";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import { createPlanChangeFixture } from "./support/planChangeFixture";

const ZOOM_PROJECT = "chromium-200-percent-zoom";
const MOBILE_NAVIGATION_TEST_ID = "e2e.shell.mobile-navigation";
const CSS_VIEWPORT = { width: 720, height: 450 } as const;
const PHYSICAL_VIEWPORT = { width: 1440, height: 900 } as const;
const VIEWPORT_EDGE_TOLERANCE = 2;

interface LayoutSnapshot {
  readonly label: string;
  readonly viewport: { readonly width: number; readonly height: number };
  readonly document: { readonly clientWidth: number; readonly scrollWidth: number };
  readonly body: { readonly clientWidth: number; readonly scrollWidth: number };
  readonly main: { readonly clientWidth: number; readonly scrollWidth: number } | null;
}

async function assertZoomRenderingContract(page: Page, testInfo: TestInfo): Promise<void> {
  if (testInfo.project.name !== ZOOM_PROJECT) return;

  const metrics = await page.evaluate(() => ({
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
    screenWidth: window.screen.width,
    screenHeight: window.screen.height,
    devicePixelRatio: window.devicePixelRatio,
    visualViewportScale: window.visualViewport?.scale ?? null,
    documentClientWidth: document.documentElement.clientWidth,
  }));
  expect(metrics).toEqual({
    innerWidth: CSS_VIEWPORT.width,
    innerHeight: CSS_VIEWPORT.height,
    screenWidth: PHYSICAL_VIEWPORT.width,
    screenHeight: PHYSICAL_VIEWPORT.height,
    devicePixelRatio: 2,
    visualViewportScale: 1,
    documentClientWidth: CSS_VIEWPORT.width,
  });

  const screenshot = await page.screenshot({ animations: "disabled" });
  expect(screenshot.subarray(12, 16).toString("ascii"), "Screenshot must use a PNG IHDR header").toBe("IHDR");
  const raster = { width: screenshot.readUInt32BE(16), height: screenshot.readUInt32BE(20) };
  expect(raster).toEqual(PHYSICAL_VIEWPORT);
  await testInfo.attach("zoom-rendering-contract.json", {
    body: Buffer.from(JSON.stringify({
      emulation: "200% browser-zoom rendering geometry",
      nativeBrowserChromeZoom: false,
      cssViewport: CSS_VIEWPORT,
      physicalViewport: PHYSICAL_VIEWPORT,
      metrics,
      raster,
      limitation: "Headless Chromium does not expose a reliable browser-chrome page-zoom command; native headed assistive-technology review remains a separate manual gate.",
    }, null, 2)),
    contentType: "application/json",
  });
  await testInfo.attach("zoom-overview-viewport.png", { body: screenshot, contentType: "image/png" });
}

async function assertNoPageOverflow(page: Page, testInfo: TestInfo, label: string): Promise<void> {
  const snapshot = await page.evaluate((snapshotLabel): LayoutSnapshot => {
    const root = document.documentElement;
    const body = document.body;
    const main = document.querySelector<HTMLElement>("main#ti-scale-content");
    return {
      label: snapshotLabel,
      viewport: { width: window.innerWidth, height: window.innerHeight },
      document: { clientWidth: root.clientWidth, scrollWidth: root.scrollWidth },
      body: { clientWidth: body.clientWidth, scrollWidth: body.scrollWidth },
      main: main ? { clientWidth: main.clientWidth, scrollWidth: main.scrollWidth } : null,
    };
  }, label);
  await testInfo.attach(`zoom-layout-${label}.json`, {
    body: Buffer.from(JSON.stringify(snapshot, null, 2)),
    contentType: "application/json",
  });
  expect(snapshot.document.scrollWidth, `${label}: document must not overflow horizontally`).toBeLessThanOrEqual(snapshot.document.clientWidth + 1);
  expect(snapshot.body.scrollWidth, `${label}: body must not overflow horizontally`).toBeLessThanOrEqual(snapshot.body.clientWidth + 1);
  expect(snapshot.main, `${label}: Ti-Scale main landmark must exist`).not.toBeNull();
  expect(snapshot.main!.scrollWidth, `${label}: main content must contain its horizontal layout`).toBeLessThanOrEqual(snapshot.main!.clientWidth + 1);
}

async function assertKeyboardAndPointerReachable(locator: Locator, label: string): Promise<void> {
  await locator.scrollIntoViewIfNeeded();
  await expect(locator, `${label}: control must be visible`).toBeVisible();
  await expect(locator, `${label}: control must intersect the zoomed viewport`).toBeInViewport();
  await locator.focus();
  await expect(locator, `${label}: programmatic keyboard focus must remain on the control`).toBeFocused();
  const state = await locator.evaluate((element) => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return {
      focusVisible: element.matches(":focus-visible"),
      hasIndicator: style.outlineStyle !== "none" && Number.parseFloat(style.outlineWidth) > 0
        || style.boxShadow !== "none",
      clippedText: element.scrollWidth > element.clientWidth + 1 || element.scrollHeight > element.clientHeight + 1,
      rect: { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom, width: rect.width, height: rect.height },
      viewport: { width: window.innerWidth, height: window.innerHeight },
      disabled: element instanceof HTMLButtonElement || element instanceof HTMLInputElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement
        ? element.disabled
        : false,
    };
  });
  expect(state.focusVisible, `${label}: keyboard focus must use the visible focus treatment`).toBe(true);
  expect(state.hasIndicator, `${label}: focus styling must draw an outline or focus shadow`).toBe(true);
  expect(state.rect.width, `${label}: control width must be non-zero`).toBeGreaterThan(0);
  expect(state.rect.height, `${label}: control height must be non-zero`).toBeGreaterThan(0);
  // Fractional layout coordinates can round by one physical pixel at DPR 2.
  // Keep the allowance below one CSS focus-ring width and still require the
  // actionability trial below to prove that no overlay intercepts the control.
  expect(state.rect.left, `${label}: control must not be clipped on the left`).toBeGreaterThanOrEqual(-VIEWPORT_EDGE_TOLERANCE);
  expect(state.rect.right, `${label}: control must not be clipped on the right`).toBeLessThanOrEqual(state.viewport.width + VIEWPORT_EDGE_TOLERANCE);
  expect(state.rect.top, `${label}: control must not be hidden above the viewport`).toBeGreaterThanOrEqual(-VIEWPORT_EDGE_TOLERANCE);
  expect(state.rect.bottom, `${label}: control must not be hidden below the viewport`).toBeLessThanOrEqual(state.viewport.height + VIEWPORT_EDGE_TOLERANCE);
  expect(state.clippedText, `${label}: the control's accessible text must not be clipped`).toBe(false);
  if (!state.disabled) await locator.click({ trial: true });
}

test.describe("e2e.zoom-accessibility 200% rendering-geometry and reflow gate", () => {
  test(`${MOBILE_NAVIGATION_TEST_ID} overview preserves reflow, primary actions, navigation, and skip-link focus`, async ({ page }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
    await waitForInteractiveApplication(page);
    await assertZoomRenderingContract(page, testInfo);
    await assertNoPageOverflow(page, testInfo, "overview");

    await page.evaluate(() => window.scrollTo(0, 0));
    await page.evaluate(() => {
      if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    });
    await page.keyboard.press("Tab");
    const skip = page.getByRole("link", { name: "Skip to content", exact: true });
    await expect(skip).toBeFocused();
    await expect(skip).toBeVisible();
    await page.keyboard.press("Enter");
    await expect(page.locator("main#ti-scale-content")).toBeFocused();

    await assertKeyboardAndPointerReachable(page.getByRole("link", { name: "Compose mission contract", exact: true }), "Autonomous intake action");
    await assertKeyboardAndPointerReachable(page.getByRole("link", { name: "Create guided mission", exact: true }), "Guided intake action");
    await assertKeyboardAndPointerReachable(page.getByRole("button", { name: "Search or run a command", exact: true }), "Command palette trigger");

    const navigation = page.getByRole("complementary", { name: "Primary navigation", exact: true });
    const menu = page.getByRole("button", { name: "Open navigation", exact: true });
    if (await menu.isVisible()) {
      await assertKeyboardAndPointerReachable(menu, "Off-canvas navigation trigger");
      await menu.click();
      await expect(navigation).toBeVisible();
      await assertKeyboardAndPointerReachable(page.getByRole("link", { name: "Missions", exact: true }), "Missions navigation item");
      const close = page.getByRole("button", { name: "Close navigation", exact: true }).last();
      await assertKeyboardAndPointerReachable(close, "Off-canvas navigation close control");
      await close.click();
      await expect(menu).toHaveAttribute("aria-expanded", "false");
      await expect(navigation).toBeHidden();
      await expect(page.getByRole("link", { name: "Missions", exact: true })).toBeHidden();
    } else {
      await expect(navigation).toBeVisible();
      await assertKeyboardAndPointerReachable(page.getByRole("link", { name: "Missions", exact: true }), "Persistent desktop Missions navigation item");
      await expect(page.getByRole("button", { name: "Close navigation", exact: true })).toBeHidden();
    }
    await assertNoPageOverflow(page, testInfo, "overview-navigation-closed");
    await audit.assertClean(testInfo);
  });

  test("Autonomous intake keeps required fields and step controls reachable without horizontal loss", async ({ page }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    await page.goto("/missions/new/autonomous", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("group", { name: "Authorization and exact scope", exact: true })).toBeVisible();
    await waitForInteractiveApplication(page);
    await assertNoPageOverflow(page, testInfo, "intake-scope");

    const target = page.getByLabel("Authorized targets or environment references", { exact: false });
    const authorization = page.getByRole("checkbox", { name: /I confirm these targets and the selected action policy are authorized/u });
    const continueButton = page.getByRole("button", { name: "Continue", exact: true });
    await assertKeyboardAndPointerReachable(target, "Authorized target field");
    await target.fill(`lab:zoom-accessibility-${testInfo.project.name}`);
    await assertKeyboardAndPointerReachable(authorization, "Authorization acknowledgement");
    await authorization.check();
    await assertKeyboardAndPointerReachable(continueButton, "Scope continue action");

    const resolved = page.waitForResponse((response) => response.url().endsWith("/api/v2/registries/intake/resolve") && response.request().method() === "POST");
    await continueButton.focus();
    await page.keyboard.press("Enter");
    expect((await resolved).status()).toBe(200);
    await expect(page.getByRole("group", { name: "Outcome and collaboration", exact: true })).toBeVisible();
    await assertNoPageOverflow(page, testInfo, "intake-outcome");
    await assertKeyboardAndPointerReachable(page.getByLabel("Mission title", { exact: false }), "Optional mission title");
    await assertKeyboardAndPointerReachable(page.getByLabel("Authorized objective", { exact: false }), "Optional authorized objective");
    await assertKeyboardAndPointerReachable(page.getByRole("button", { name: "Back", exact: true }), "Intake back action");
    await assertKeyboardAndPointerReachable(page.getByRole("button", { name: "Continue", exact: true }), "Outcome continue action");
    await audit.assertClean(testInfo);
  });

  test("run workspace exposes status, tabs, intervention controls, and plan amendment at zoom", async ({ page }, testInfo) => {
    const fixture = createPlanChangeFixture(
      "queued_apply",
      canonicalFixtureNamespace(testInfo, "zoom-accessibility-run-workspace"),
    );
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    await page.goto(`/missions/${encodeURIComponent(fixture.missionId)}/runs/${encodeURIComponent(fixture.runId)}?tab=plan`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: fixture.missionName, exact: true })).toBeVisible();
    await waitForInteractiveApplication(page);
    await expect(page.getByRole("region", { name: "Selected run status", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { level: 2, name: "Plan change requests", exact: true })).toBeVisible();
    await assertNoPageOverflow(page, testInfo, "run-plan");

    const reason = page.getByLabel("Operator reason (audited)", { exact: true });
    await assertKeyboardAndPointerReachable(reason, "Audited intervention reason");
    await reason.fill("Verify that zoomed run controls remain reachable without issuing an intervention.");
    await assertKeyboardAndPointerReachable(page.getByRole("button", { name: "Pause run", exact: true }), "Pause run control");
    await assertKeyboardAndPointerReachable(page.getByRole("button", { name: "Cancel run", exact: true }), "Cancel run control");

    const tabs = page.getByRole("navigation", { name: "Section views", exact: true });
    await assertKeyboardAndPointerReachable(tabs.getByRole("button", { name: "Summary", exact: true }), "First mission workspace tab");
    await assertKeyboardAndPointerReachable(tabs.getByRole("button", { name: "Settings", exact: true }), "Last mission workspace tab");
    await assertKeyboardAndPointerReachable(tabs.getByRole("button", { name: "Plan", exact: true }), "Current Plan tab");

    const request = page.getByLabel(/Why should the plan change/u);
    const strategy = page.getByLabel(/Revised strategy summary/u);
    await assertKeyboardAndPointerReachable(request, "Plan amendment rationale");
    await request.fill("Preserve the represented scope while proving the zoomed proposal form remains usable.");
    await assertKeyboardAndPointerReachable(strategy, "Plan strategy summary");
    await strategy.fill(`${fixture.strategySummary}; preserve explicit zoom-accessibility evidence`);
    const review = page.getByRole("button", { name: "Create reviewable proposal", exact: true });
    await expect(review).toBeEnabled();
    await assertKeyboardAndPointerReachable(review, "Plan amendment review action");
    await assertNoPageOverflow(page, testInfo, "run-plan-controls");
    await audit.assertClean(testInfo);
  });
});

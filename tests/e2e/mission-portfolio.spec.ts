import {
  expect,
  test,
  type Locator,
  type Page,
  type Response,
  type TestInfo,
} from "./support/playwright";
import { createHash } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { BrowserAudit } from "./support/browserAudit";
import { E2E_RUN_ID } from "./support/environment";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createMissionPortfolioFixture,
  readMissionPortfolioFixtureState,
  type MissionPortfolioFixture,
} from "./support/missionPortfolioFixture";

const TEST_IDS = {
  overviewShortcuts: "e2e.overview.portfolio-shortcuts",
  overviewMissionRows: "e2e.overview.mission-row-links",
  journeyRows: "e2e.journey-portfolios.row-links",
  filtersAndSavedView: "e2e.mission-portfolio.filters-saved-view",
  paginationAndDeepLinks: "e2e.mission-portfolio.pagination-deep-links",
  bulkActions: "e2e.mission-portfolio.bulk-actions",
  retry: "e2e.mission-portfolio.retry",
} as const;

const JOURNEY_OPTIONS = ["All", "Autonomous", "Guided"];
const STATUS_OPTIONS = [
  "All", "queued", "planning", "awaiting contract confirmation", "running",
  "waiting guided decision", "blocked", "recovering", "completed", "failed", "cancelled",
];
const SEVERITY_OPTIONS = ["All", "informational", "low", "medium", "high", "critical"];
const DECISION_OPTIONS = [
  "All", "pending", "approved", "manual", "alternative", "rejected", "expired", "cancelled",
];

let fixture: MissionPortfolioFixture;

function missionLinkName(title: string, missionId: string): string {
  return `Open mission ${title} (${missionId})`;
}

function missionSelectionName(title: string, missionId: string): string {
  return `Select mission ${title} (${missionId})`;
}

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createMissionPortfolioFixture(canonicalFixtureNamespace(testInfo, "mission-portfolio"));
});

function pathname(response: Response): string {
  return new URL(response.url()).pathname;
}

function missionListResponse(
  page: Page,
  predicate: (url: URL) => boolean = () => true,
): Promise<Response> {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET"
      && url.pathname === "/api/v2/missions"
      && predicate(url);
  });
}

async function assertMissionListResponse(
  response: Response,
  expectedMissionId?: string,
): Promise<{ readonly items: readonly { readonly id: string; readonly title: string }[]; readonly nextCursor: string | null }> {
  expect(response.status(), await response.text()).toBe(200);
  const payload = await response.json() as {
    readonly items: readonly { readonly id: string; readonly title: string }[];
    readonly nextCursor: string | null;
  };
  if (expectedMissionId) {
    expect(payload.items.map((mission) => mission.id)).toContain(expectedMissionId);
  }
  return payload;
}

async function strictAudit(audit: BrowserAudit, testInfo: TestInfo): Promise<void> {
  expect(audit.unexpected, "Unexpected browser, console, network, or server failures").toEqual([]);
  expect(audit.degradedApi, "Every portfolio fixture requires the real V2 API").toEqual([]);
  await audit.assertClean(testInfo);
}

async function activate(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await control.press("Enter");
  } else {
    await control.click();
  }
}

async function toggleCheckbox(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await control.press("Space");
  } else {
    await control.click();
  }
}

async function expectHeading(page: Page, name: string): Promise<void> {
  await expect(page.getByRole("heading", { level: 1, name, exact: true })).toBeVisible();
  await expect(page.getByText("Command surface not found", { exact: true })).toHaveCount(0);
}

async function settleLocalReads(page: Page): Promise<void> {
  // A heading intentionally renders before its secondary local projections.
  // Give those bounded reads a quiet window before a test leaves the route so
  // a legitimate late request is never mistaken for navigation teardown.
  await page.waitForTimeout(500);
}

async function optionLabels(control: Locator): Promise<string[]> {
  await expect(control).toBeVisible();
  await expect(control.locator("option").first()).toBeAttached();
  return control.locator("option").allTextContents();
}

interface SelectExerciseOptions {
  readonly omittedValue?: string;
  readonly apiCarriesParameter?: boolean;
}

async function selectOptionAndVerify(
  page: Page,
  control: Locator,
  parameter: string,
  value: string,
  options: SelectExerciseOptions = {},
): Promise<void> {
  const omittedValue = options.omittedValue ?? "";
  const apiCarriesParameter = options.apiCarriesParameter ?? true;
  const expectedValue = value === omittedValue ? null : value;
  const responsePromise = missionListResponse(page, (url) => (
    url.searchParams.get("query") === fixture.primaryQuery
    && (apiCarriesParameter
      ? url.searchParams.get(parameter) === expectedValue
      : !url.searchParams.has(parameter))
  ));
  await control.selectOption(value);
  const response = await responsePromise;
  await assertMissionListResponse(response);
  const responseUrl = new URL(response.url());
  expect(responseUrl.searchParams.get("query")).toBe(fixture.primaryQuery);
  expect(responseUrl.searchParams.get(parameter)).toBe(apiCarriesParameter ? expectedValue : null);
  await expect(control).toHaveValue(value);
  await expect.poll(() => new URL(page.url()).searchParams.get(parameter)).toBe(expectedValue);
}

async function exerciseSelectOptions(
  page: Page,
  control: Locator,
  parameter: string,
  options: SelectExerciseOptions = {},
): Promise<void> {
  const initialValue = await control.inputValue();
  const optionValues = await control.locator("option").evaluateAll((elements) => elements.map((element) => (
    (element as HTMLOptionElement).value
  )));
  for (const value of optionValues.filter((optionValue) => optionValue !== initialValue)) {
    await selectOptionAndVerify(page, control, parameter, value, options);
  }

  // The page's primary-query response already proves the initial option's API
  // projection. Returning to that fresh QueryCache key is intentionally local,
  // so assert the real control, URL, and restored fixture rendering without
  // waiting for a duplicate network request that the client correctly omits.
  const omittedValue = options.omittedValue ?? "";
  const expectedValue = initialValue === omittedValue ? null : initialValue;
  await control.selectOption(initialValue);
  await expect(control).toHaveValue(initialValue);
  await expect.poll(() => new URL(page.url()).searchParams.get(parameter)).toBe(expectedValue);
  await expect(page.getByRole("link", { name: missionLinkName(fixture.primaryTitle, fixture.primaryMissionId), exact: true })).toBeVisible();
}

async function setImmediateFilter(
  page: Page,
  control: Locator,
  value: string,
  parameter: string,
  kind: "input" | "select",
): Promise<void> {
  if (kind === "select") {
    // Every individual select projection is proven above. Re-applying those
    // values to compose the saved view may be served entirely by QueryCache,
    // so synchronize on the canonical URL and rendered result instead of
    // requiring a redundant network response.
    await control.selectOption(value);
    await expect(control).toHaveValue(value);
    await expect.poll(() => new URL(page.url()).searchParams.get(parameter)).toBe(value);
    await expect(page.getByRole("link", { name: missionLinkName(fixture.primaryTitle, fixture.primaryMissionId), exact: true })).toBeVisible();
    return;
  }

  const responsePromise = missionListResponse(page, (url) => url.searchParams.get(parameter) === value);
  await control.fill(value);
  const response = await responsePromise;
  await assertMissionListResponse(response, fixture.primaryMissionId);
  await expect.poll(() => new URL(page.url()).searchParams.get(parameter)).toBe(value);
}

function missionRowLink(page: Page, title: string): Locator {
  return page.getByRole("link").filter({ hasText: title }).first();
}

async function waitForOperatorPortfolioLock(): Promise<() => void> {
  const safeRunId = E2E_RUN_ID.replaceAll(/[^A-Za-z0-9._-]+/gu, "-").slice(0, 100) || "unnamed";
  const lockPath = resolve("/tmp", `ti-scale-portfolio-actor-${safeRunId}.lock`);
  for (let attempt = 0; attempt < 1_200; attempt += 1) {
    try {
      mkdirSync(lockPath);
      return () => rmSync(lockPath, { recursive: true, force: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      await new Promise((resolveWait) => setTimeout(resolveWait, 50));
    }
  }
  throw new Error("Timed out waiting for the shared operator saved-view lock");
}

test(`${TEST_IDS.overviewShortcuts} and ${TEST_IDS.overviewMissionRows} traverse canonical shortcuts and both journey links`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const overviewResponse = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === "/api/v2/overview");
  await page.goto("/", { waitUntil: "domcontentloaded" });
  const overview = await overviewResponse;
  expect(overview.status(), await overview.text()).toBe(200);
  const snapshot = await overview.json() as {
    readonly missions: readonly { readonly id: string; readonly journey: string }[];
  };
  expect(snapshot.missions).toContainEqual(expect.objectContaining({
    id: fixture.primaryMissionId,
    journey: "guided",
  }));
  expect(snapshot.missions).toContainEqual(expect.objectContaining({
    id: fixture.autonomousMissionId,
    journey: "autonomous",
  }));
  await expectHeading(page, "Command Center");

  const shortcuts = [
    { name: "View portfolio", path: "/missions", heading: "Missions", input: "pointer" as const },
    { name: "Inspect fleet", path: "/agents", heading: "Agents", input: "keyboard" as const },
    { name: "Open Brain", path: "/brain", heading: "Second Brain", input: "pointer" as const },
    { name: "Connections", path: "/system/connections", heading: "System", input: "keyboard" as const },
  ];
  for (const shortcut of shortcuts) {
    const link = page.getByRole("link", { name: shortcut.name, exact: true });
    await expect(link).toHaveAttribute("href", shortcut.path);
    await activate(link, shortcut.input);
    await expect.poll(() => new URL(page.url()).pathname).toBe(shortcut.path);
    await expectHeading(page, shortcut.heading);
    await settleLocalReads(page);
    await page.goBack({ waitUntil: "domcontentloaded" });
    await expectHeading(page, "Command Center");
  }

  const guidedLink = missionRowLink(page, fixture.primaryTitle);
  const overviewUrl = page.url();
  await expect(guidedLink).toHaveAttribute("href", `/guided/${fixture.primaryMissionId}`);
  const guidedRuntime = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/missions/${fixture.primaryMissionId}/runtime`);
  await activate(guidedLink, "keyboard");
  expect((await guidedRuntime).status()).toBe(200);
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/guided/${fixture.primaryMissionId}`);
  await expectHeading(page, fixture.primaryTitle);
  await settleLocalReads(page);
  const guidedReload = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/missions/${fixture.primaryMissionId}/runtime`);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await guidedReload).status()).toBe(200);
  await expectHeading(page, fixture.primaryTitle);
  await settleLocalReads(page);
  let guidedBackSteps = 0;
  while (page.url() !== overviewUrl && guidedBackSteps < 2) {
    await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
    guidedBackSteps += 1;
  }
  expect(guidedBackSteps).toBeGreaterThanOrEqual(1);
  expect(guidedBackSteps).toBeLessThanOrEqual(2);
  await expect(page).toHaveURL(overviewUrl);
  await expectHeading(page, "Command Center");

  const autonomousLink = missionRowLink(page, fixture.autonomousTitle);
  await expect(autonomousLink).toHaveAttribute("href", `/missions/${fixture.autonomousMissionId}`);
  const autonomousRuntime = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/missions/${fixture.autonomousMissionId}/runtime`);
  await activate(autonomousLink, "pointer");
  expect((await autonomousRuntime).status()).toBe(200);
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/missions/${fixture.autonomousMissionId}`);
  await expectHeading(page, fixture.autonomousTitle);
  await settleLocalReads(page);
  const autonomousReload = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/missions/${fixture.autonomousMissionId}/runtime`);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await autonomousReload).status()).toBe(200);
  await expectHeading(page, fixture.autonomousTitle);
  await settleLocalReads(page);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.journeyRows} traverses the Guided mission and Autonomous run families`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });

  const guidedProjection = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/missions/${fixture.primaryMissionId}/runtime`);
  await page.goto("/guided", { waitUntil: "domcontentloaded" });
  expect((await guidedProjection).status()).toBe(200);
  await expectHeading(page, "Guided Workspace");
  const guidedLink = page.getByRole("link", {
    name: `Open Guided mission ${fixture.primaryTitle} (${fixture.primaryMissionId})`,
    exact: true,
  });
  await expect(guidedLink).toHaveAttribute("href", `/guided/${fixture.primaryMissionId}`);
  const guidedDetail = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/missions/${fixture.primaryMissionId}/runtime`);
  await activate(guidedLink, "keyboard");
  expect((await guidedDetail).status()).toBe(200);
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/guided/${fixture.primaryMissionId}`);
  await expectHeading(page, fixture.primaryTitle);
  await settleLocalReads(page);

  const liveProjection = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/missions/${fixture.autonomousMissionId}/runtime`);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto("/live", { waitUntil: "domcontentloaded" }));
  expect((await liveProjection).status()).toBe(200);
  await expectHeading(page, "Live Operations");
  const autonomousLink = page.getByRole("link", {
    name: `Open Autonomous run ${fixture.autonomousTitle} (${fixture.autonomousRunId})`,
    exact: true,
  });
  await expect(autonomousLink).toHaveAttribute("href", `/live/${fixture.autonomousRunId}`);
  const autonomousDetail = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/runs/${fixture.autonomousRunId}`);
  await activate(autonomousLink, "pointer");
  expect((await autonomousDetail).status()).toBe(200);
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/live/${fixture.autonomousRunId}`);
  await expectHeading(page, fixture.autonomousTitle);
  await settleLocalReads(page);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.filtersAndSavedView} exercises every portfolio filter, board control, saved view, and empty-state entry`, async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const initialResponse = missionListResponse(page);
  await page.goto("/missions", { waitUntil: "domcontentloaded" });
  await assertMissionListResponse(await initialResponse);
  await expectHeading(page, "Missions");

  const newMission = page.getByRole("link", { name: "New mission", exact: true });
  await expect(newMission).toHaveAttribute("href", "/missions/new");
  await activate(newMission, "keyboard");
  await expectHeading(page, "Choose how you want to work");
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expectHeading(page, "Missions");

  const search = page.getByLabel("Mission, phase, run, or next action", { exact: true });
  await search.fill(fixture.primaryQuery);
  const searchResponse = missionListResponse(page, (url) => url.searchParams.get("query") === fixture.primaryQuery);
  await activate(page.getByRole("button", { name: "Apply filters", exact: true }), "keyboard");
  const searched = await assertMissionListResponse(await searchResponse, fixture.primaryMissionId);
  expect(searched.items.map((item) => item.id)).toEqual([fixture.primaryMissionId]);

  const journey = page.getByRole("combobox", { name: "Journey", exact: true });
  const status = page.getByRole("combobox", { name: "Run state", exact: true });
  const view = page.getByRole("combobox", { name: "View", exact: true });
  expect(await optionLabels(journey)).toEqual(JOURNEY_OPTIONS);
  expect(await optionLabels(status)).toEqual(STATUS_OPTIONS);
  expect(await optionLabels(view)).toEqual(["Table", "Compact board"]);

  const advanced = page.locator("details.mission-advanced-filters");
  await activate(advanced.locator("summary"), "keyboard");
  await expect(advanced).toHaveJSProperty("open", true);

  const risk = page.getByRole("combobox", { name: "Current risk", exact: true });
  const evidence = page.getByRole("combobox", { name: "Evidence", exact: true });
  const finding = page.getByRole("combobox", { name: "Finding severity", exact: true });
  const decision = page.getByRole("combobox", { name: "Decision state", exact: true });
  const recovery = page.getByRole("combobox", { name: "Recovery state", exact: true });
  expect(await optionLabels(risk)).toEqual(SEVERITY_OPTIONS);
  expect(await optionLabels(evidence)).toEqual(["All", "Has evidence", "No evidence"]);
  expect(await optionLabels(finding)).toEqual(SEVERITY_OPTIONS);
  expect(await optionLabels(decision)).toEqual(DECISION_OPTIONS);
  expect(await optionLabels(recovery)).toEqual(["All", "Recovering", "Blocked", "No recovery state"]);

  await exerciseSelectOptions(page, journey, "journey");
  await exerciseSelectOptions(page, status, "status");
  await exerciseSelectOptions(page, view, "view", { omittedValue: "table", apiCarriesParameter: false });
  await exerciseSelectOptions(page, risk, "risk");
  await exerciseSelectOptions(page, evidence, "evidence");
  await exerciseSelectOptions(page, finding, "findingSeverity");
  await exerciseSelectOptions(page, decision, "decisionState");
  await exerciseSelectOptions(page, recovery, "recoveryState");

  await setImmediateFilter(page, journey, "guided", "journey", "select");
  await setImmediateFilter(page, status, "recovering", "status", "select");
  await setImmediateFilter(page, page.getByLabel("Engagement", { exact: true }), fixture.engagementId, "engagement", "input");
  await setImmediateFilter(page, page.getByLabel("Target", { exact: true }), fixture.target, "target", "input");
  await setImmediateFilter(page, page.getByLabel("Agent / owner ID", { exact: true }), fixture.agentId, "agent", "input");
  await setImmediateFilter(page, page.getByLabel("Provider", { exact: true }), fixture.provider, "provider", "input");
  await setImmediateFilter(page, page.getByLabel("Updated from", { exact: true }), fixture.fixtureDate, "updatedFrom", "input");
  await setImmediateFilter(page, page.getByLabel("Updated to", { exact: true }), fixture.fixtureDate, "updatedTo", "input");
  await setImmediateFilter(page, risk, "high", "risk", "select");
  await setImmediateFilter(page, evidence, "present", "evidence", "select");
  await setImmediateFilter(page, finding, "critical", "findingSeverity", "select");
  await setImmediateFilter(page, decision, "pending", "decisionState", "select");
  await setImmediateFilter(page, recovery, "recovering", "recoveryState", "select");

  const boardResponse = missionListResponse(page);
  await view.selectOption("board");
  await assertMissionListResponse(await boardResponse, fixture.primaryMissionId);
  await expect(page.getByLabel("Mission board", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: fixture.primaryTitle, exact: true })).toBeVisible();
  const boardCheckbox = page.getByRole("checkbox", { name: missionSelectionName(fixture.primaryTitle, fixture.primaryMissionId), exact: true });
  await toggleCheckbox(boardCheckbox, "pointer");
  await expect(boardCheckbox).toBeChecked();
  await toggleCheckbox(boardCheckbox, "keyboard");
  await expect(boardCheckbox).not.toBeChecked();

  const viewName = `Canonical saved portfolio ${fixture.namespace}`;
  const savedName = page.getByPlaceholder("Name current filters", { exact: true });
  const saveButton = page.getByRole("button", { name: "Save view", exact: true });
  await expect(saveButton).toBeDisabled();
  await savedName.fill(viewName);
  await expect(saveButton).toBeEnabled();

  const releaseLock = await waitForOperatorPortfolioLock();
  try {
    const savedResponse = page.waitForResponse((response) => response.request().method() === "POST"
      && pathname(response) === "/api/v2/missions/saved-views");
    await savedName.focus();
    await savedName.press("Enter");
    const savedResult = await savedResponse;
    expect(savedResult.status(), await savedResult.text()).toBe(200);
    const savedRequest = savedResult.request().postDataJSON() as {
      readonly name: string;
      readonly state: Record<string, string>;
    };
    expect(savedRequest).toMatchObject({
      name: viewName,
      state: {
        query: fixture.primaryQuery,
        journey: "guided",
        status: "recovering",
        engagement: fixture.engagementId,
        target: fixture.target,
        agent: fixture.agentId,
        provider: fixture.provider,
        updatedFrom: fixture.fixtureDate,
        updatedTo: fixture.fixtureDate,
        risk: "high",
        evidence: "present",
        findingSeverity: "critical",
        decisionState: "pending",
        recoveryState: "recovering",
        view: "board",
      },
    });
    await expect(page.getByRole("button", { name: viewName, exact: true })).toBeVisible();

    const reloadResponse = missionListResponse(page, (url) => url.searchParams.get("query") === fixture.primaryQuery);
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
    await assertMissionListResponse(await reloadResponse, fixture.primaryMissionId);
    await expect(page.getByRole("combobox", { name: "View", exact: true })).toHaveValue("board");
    await expect(page.getByLabel("Mission board", { exact: true })).toBeVisible();

    const resetResponse = missionListResponse(page, (url) => url.searchParams.size === 1 && url.searchParams.get("limit") === "50");
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto("/missions", { waitUntil: "domcontentloaded" }));
    await assertMissionListResponse(await resetResponse);
    const applySaved = page.getByRole("button", { name: viewName, exact: true });
    const appliedResponse = missionListResponse(page, (url) => url.searchParams.get("query") === fixture.primaryQuery
      && url.searchParams.get("recoveryState") === "recovering");
    await activate(applySaved, "pointer");
    await assertMissionListResponse(await appliedResponse, fixture.primaryMissionId);
    await expect(page.getByRole("combobox", { name: "View", exact: true })).toHaveValue("board");
    await expect(page.getByLabel("Mission board", { exact: true })).toBeVisible();

    const boardLink = page.getByLabel("Mission board", { exact: true })
      .getByRole("link", { name: missionLinkName(fixture.primaryTitle, fixture.primaryMissionId), exact: true });
    await expect(boardLink).toHaveAttribute("href", `/guided/${fixture.primaryMissionId}`);
    const guidedRuntime = page.waitForResponse((response) => response.request().method() === "GET"
      && pathname(response) === `/api/v2/missions/${fixture.primaryMissionId}/runtime`);
    await activate(boardLink, "keyboard");
    expect((await guidedRuntime).status()).toBe(200);
    await expectHeading(page, fixture.primaryTitle);
    await settleLocalReads(page);
    await page.goBack({ waitUntil: "domcontentloaded" });
    await expectHeading(page, "Missions");
    await expect(page.getByLabel("Mission board", { exact: true })).toBeVisible();

    const deleteResponse = page.waitForResponse((response) => response.request().method() === "DELETE"
      && new URL(response.url()).pathname.startsWith("/api/v2/missions/saved-views/"));
    await activate(page.getByRole("button", { name: `Delete saved view ${viewName}`, exact: true }), "keyboard");
    const deleted = await deleteResponse;
    expect(deleted.status(), await deleted.text()).toBe(200);
    await expect(page.getByRole("button", { name: viewName, exact: true })).toHaveCount(0);
  } finally {
    releaseLock();
  }

  const emptyQuery = `no-match-${fixture.namespace}`;
  const emptyResponse = missionListResponse(page, (url) => url.searchParams.get("query") === emptyQuery);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    `/missions?query=${encodeURIComponent(emptyQuery)}`,
    { waitUntil: "domcontentloaded" },
  ));
  const empty = await assertMissionListResponse(await emptyResponse);
  expect(empty.items).toEqual([]);
  await expect(page.getByText("No missions match this view", { exact: true })).toBeVisible();
  const createMission = page.getByRole("link", { name: "Create mission", exact: true });
  await expect(createMission).toHaveAttribute("href", "/missions/new");
  await activate(createMission, "pointer");
  await expectHeading(page, "Choose how you want to work");
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.paginationAndDeepLinks} preserves signed cursor navigation, selection state, deep links, and refresh`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const firstResponse = missionListResponse(page, (url) => url.searchParams.get("query") === fixture.sharedQuery
    && !url.searchParams.has("cursor"));
  await page.goto(`/missions?query=${encodeURIComponent(fixture.sharedQuery)}`, { waitUntil: "domcontentloaded" });
  const first = await assertMissionListResponse(await firstResponse, fixture.primaryMissionId);
  expect(first.items).toHaveLength(50);
  expect(first.nextCursor).not.toBeNull();
  const firstPage = page.getByRole("button", { name: "First page", exact: true });
  const nextPage = page.getByRole("button", { name: "Next page", exact: true });
  await expect(firstPage).toBeDisabled();
  await expect(nextPage).toBeEnabled();

  const selectAll = page.getByRole("checkbox", { name: "Select all 50 visible missions", exact: true });
  await toggleCheckbox(selectAll, "keyboard");
  await expect(selectAll).toBeChecked();
  await expect(page.getByText("50 selected", { exact: true })).toBeVisible();
  await toggleCheckbox(selectAll, "pointer");
  await expect(selectAll).not.toBeChecked();
  await expect(page.getByText("0 selected", { exact: true })).toBeVisible();

  const primaryLink = missionRowLink(page, fixture.primaryTitle);
  await expect(primaryLink).toHaveAttribute("href", `/guided/${fixture.primaryMissionId}`);
  const runtimeResponse = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/missions/${fixture.primaryMissionId}/runtime`);
  await activate(primaryLink, "pointer");
  expect((await runtimeResponse).status()).toBe(200);
  await expectHeading(page, fixture.primaryTitle);
  await settleLocalReads(page);
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expectHeading(page, "Missions");

  const secondResponse = missionListResponse(page, (url) => url.searchParams.get("query") === fixture.sharedQuery
    && url.searchParams.has("cursor"));
  await activate(page.getByRole("button", { name: "Next page", exact: true }), "keyboard");
  const second = await assertMissionListResponse(await secondResponse);
  expect(second.items).toHaveLength(fixture.totalMissionCount - 50);
  expect(second.nextCursor).toBeNull();
  const cursor = new URL(page.url()).searchParams.get("cursor");
  expect(cursor).toBeTruthy();
  await expect(page.getByRole("button", { name: "First page", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Next page", exact: true })).toBeDisabled();

  const reloadResponse = missionListResponse(page, (url) => url.searchParams.get("cursor") === cursor);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  const reloaded = await assertMissionListResponse(await reloadResponse);
  expect(reloaded.items.map((item) => item.id)).toEqual(second.items.map((item) => item.id));
  expect(new URL(page.url()).searchParams.get("cursor")).toBe(cursor);

  const returnResponse = missionListResponse(page, (url) => url.searchParams.get("query") === fixture.sharedQuery
    && !url.searchParams.has("cursor"));
  await activate(page.getByRole("button", { name: "First page", exact: true }), "pointer");
  await assertMissionListResponse(await returnResponse, fixture.primaryMissionId);
  await expect.poll(() => new URL(page.url()).searchParams.has("cursor")).toBe(false);
  await expect(page.getByRole("button", { name: "First page", exact: true })).toBeDisabled();
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.bulkActions} exports and archives only the selected disposable terminal mission`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  expect(readMissionPortfolioFixtureState(fixture)).toMatchObject({
    visibleFixtureMissions: fixture.totalMissionCount,
    terminalMissionStatus: "completed",
    terminalRunStatus: "completed",
    terminalArchiveAuditCount: 0,
    terminalExportAuditCount: 0,
  });
  const listResponse = missionListResponse(page, (url) => url.searchParams.get("query") === fixture.terminalMissionId);
  await page.goto(`/missions?query=${encodeURIComponent(fixture.terminalMissionId)}`, { waitUntil: "domcontentloaded" });
  const terminalOnly = await assertMissionListResponse(await listResponse, fixture.terminalMissionId);
  expect(terminalOnly.items.map((item) => item.id)).toEqual([fixture.terminalMissionId]);

  const exportButton = page.getByRole("button", { name: "Export redacted metadata", exact: true });
  const archiveButton = page.getByRole("button", { name: "Archive terminal missions", exact: true });
  await expect(exportButton).toBeDisabled();
  await expect(archiveButton).toBeDisabled();
  const selectAll = page.getByRole("checkbox", { name: "Select all 1 visible missions", exact: true });
  await toggleCheckbox(selectAll, "keyboard");
  await expect(exportButton).toBeEnabled();
  await expect(archiveButton).toBeEnabled();
  await toggleCheckbox(selectAll, "pointer");
  await expect(exportButton).toBeDisabled();
  await expect(archiveButton).toBeDisabled();

  const rowSelection = page.getByRole("checkbox", { name: missionSelectionName(fixture.terminalTitle, fixture.terminalMissionId), exact: true });
  await toggleCheckbox(rowSelection, "pointer");
  await expect(rowSelection).toBeChecked();
  await expect(exportButton).toBeEnabled();
  await expect(archiveButton).toBeEnabled();

  await activate(exportButton, "pointer");
  let dialog = page.getByRole("dialog", { name: "Confirm redacted metadata export", exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(exportButton).toBeFocused();

  await activate(exportButton, "keyboard");
  dialog = page.getByRole("dialog", { name: "Confirm redacted metadata export", exact: true });
  await expect(dialog).toBeVisible();
  await activate(dialog.getByRole("button", { name: "Cancel", exact: true }), "pointer");
  await expect(dialog).toBeHidden();

  await activate(exportButton, "pointer");
  dialog = page.getByRole("dialog", { name: "Confirm redacted metadata export", exact: true });
  const expectedSelectionHash = createHash("sha256")
    .update(JSON.stringify([fixture.terminalMissionId]), "utf8")
    .digest("hex");
  const expectedExportFilename = `ti-scale-mission-metadata-${expectedSelectionHash.slice(0, 12)}.json`;
  audit.expectGeneratedDownload(expectedExportFilename);
  const exportResponse = page.waitForResponse((response) => response.request().method() === "POST"
    && pathname(response) === "/api/v2/missions/bulk/export");
  const downloadPromise = page.waitForEvent("download");
  await activate(dialog.getByRole("button", { name: "Confirm export", exact: true }), "keyboard");
  const exported = await exportResponse;
  expect(exported.status(), await exported.text()).toBe(200);
  expect(exported.request().postDataJSON()).toEqual({
    missionIds: [fixture.terminalMissionId],
    confirm: true,
  });
  const exportedPayload = await exported.json() as {
    readonly selectionHash: string;
    readonly outcomes: readonly { readonly missionId: string; readonly status: string }[];
    readonly policy: { readonly evidenceBlobsIncluded: boolean; readonly confidentialPayloadsIncluded: boolean };
  };
  expect(exportedPayload.outcomes).toEqual([{
    missionId: fixture.terminalMissionId,
    status: "exported",
    reason: "Redacted bounded metadata exported.",
  }]);
  expect(exportedPayload.policy).toEqual(expect.objectContaining({
    evidenceBlobsIncluded: false,
    confidentialPayloadsIncluded: false,
  }));
  const download = await downloadPromise;
  expect(exportedPayload.selectionHash).toBe(expectedSelectionHash);
  await audit.verifyGeneratedDownload(download, expectedExportFilename);
  expect(download.suggestedFilename()).toBe(expectedExportFilename);
  await expect(page.getByText("Bulk operation recorded", { exact: true })).toBeVisible();
  expect(readMissionPortfolioFixtureState(fixture).terminalExportAuditCount).toBe(1);

  await activate(archiveButton, "keyboard");
  dialog = page.getByRole("dialog", { name: "Confirm terminal mission archive", exact: true });
  await expect(dialog).toBeVisible();
  await activate(dialog.getByRole("button", { name: "Cancel", exact: true }), "pointer");
  await expect(dialog).toBeHidden();
  await activate(archiveButton, "pointer");
  dialog = page.getByRole("dialog", { name: "Confirm terminal mission archive", exact: true });
  const archiveResponse = page.waitForResponse((response) => response.request().method() === "POST"
    && pathname(response) === "/api/v2/missions/bulk/archive");
  await activate(dialog.getByRole("button", { name: "Confirm archive", exact: true }), "keyboard");
  const archived = await archiveResponse;
  expect(archived.status(), await archived.text()).toBe(200);
  expect(archived.request().postDataJSON()).toEqual({
    missionIds: [fixture.terminalMissionId],
    confirm: true,
  });
  const archivedPayload = await archived.json() as {
    readonly archivedCount: number;
    readonly outcomes: readonly { readonly missionId: string; readonly status: string; readonly reason: string }[];
  };
  expect(archivedPayload).toMatchObject({
    archivedCount: 1,
    outcomes: [{
      missionId: fixture.terminalMissionId,
      status: "archived",
      reason: "Durably terminal mission archived.",
    }],
  });
  // Archiving the only mission in this exact query correctly transitions the
  // portfolio to its empty result state. Bulk controls are scoped to a
  // rendered selection set, so they unmount instead of lingering as inert
  // controls after the canonical refresh removes the archived mission.
  await expect(page.getByText("No missions match this view", { exact: true })).toBeVisible();
  await expect(exportButton).toHaveCount(0);
  await expect(archiveButton).toHaveCount(0);
  const outcomes = page.getByText("Per-mission outcomes", { exact: true }).locator("xpath=..");
  await activate(outcomes.locator("summary"), "pointer");
  await expect(outcomes).toContainText(fixture.terminalMissionId);
  await expect(outcomes).toContainText("archived");
  expect(readMissionPortfolioFixtureState(fixture)).toMatchObject({
    visibleFixtureMissions: fixture.totalMissionCount - 1,
    terminalMissionStatus: "archived",
    terminalRunStatus: "completed",
    terminalArchiveAuditCount: 1,
    terminalExportAuditCount: 1,
  });
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.retry} renders a precise initial failure and retries the canonical portfolio read`, async ({ page, browserAudit }, testInfo) => {
  test.setTimeout(60_000);
  browserAudit.expectHttpResponse(page, {
    id: "mission-portfolio.filtered-read.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: "/api/v2/missions",
    query: { limit: "50", query: fixture.primaryQuery },
    status: 503,
    occurrences: 1,
    reason: "Exercise the exact filtered mission-portfolio retry state once.",
  });
  let failed = false;
  const matcher = (url: URL): boolean => url.pathname === "/api/v2/missions"
    && url.searchParams.get("query") === fixture.primaryQuery;
  await page.route("**/api/v2/missions?**", async (route) => {
    const url = new URL(route.request().url());
    if (!failed && route.request().method() === "GET" && matcher(url)) {
      failed = true;
      await route.fulfill({
        status: 503,
        contentType: "application/json; charset=utf-8",
        body: JSON.stringify({
          error: {
            code: "portfolio_fixture_temporarily_unavailable",
            message: "The canonical mission portfolio is temporarily unavailable",
            humanMessage: "The mission portfolio could not read its isolated local projection.",
            retryable: true,
            category: "dependency",
            remediation: "Retry after the local portfolio projection recovers.",
            traceId: `trace-portfolio-${fixture.namespace}`,
            timestamp: "2099-07-16T23:59:59.000Z",
          },
        }),
      });
      return;
    }
    await route.fallback();
  });
  await page.goto(`/missions?query=${encodeURIComponent(fixture.primaryQuery)}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("alert")).toContainText("The mission portfolio could not read its isolated local projection.");
  await expect(page.getByRole("alert")).toContainText("Retry after the local portfolio projection recovers.");
  await page.unroute("**/api/v2/missions?**");

  // The deliberate fault belongs to the fixture setup. Audit the real retry
  // and the resulting page from this point forward.
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const retryResponse = missionListResponse(page, (url) => url.searchParams.get("query") === fixture.primaryQuery);
  await activate(page.getByRole("button", { name: "Try again", exact: true }), "pointer");
  const retried = await assertMissionListResponse(await retryResponse, fixture.primaryMissionId);
  expect(retried.items.map((item) => item.id)).toEqual([fixture.primaryMissionId]);
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.getByRole("link", { name: missionLinkName(fixture.primaryTitle, fixture.primaryMissionId), exact: true })).toBeVisible();
  await strictAudit(audit, testInfo);
});

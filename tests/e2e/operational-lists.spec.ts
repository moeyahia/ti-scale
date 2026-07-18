import { expect, test, type Locator, type Page, type Response, type TestInfo } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createOperationalListsFixture,
  type OperationalListsFixture,
} from "./support/operationalListsFixture";

const TEST_IDS = {
  agents: "e2e.operational-lists.agents-pagination-detail",
  traces: "e2e.operational-lists.trace-pagination-detail",
  reports: "e2e.operational-lists.reports-pagination-detail",
} as const;

let fixture: OperationalListsFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createOperationalListsFixture(canonicalFixtureNamespace(testInfo, "operational-lists"));
});

function pathname(response: Response): string {
  return new URL(response.url()).pathname;
}

function apiResponse(page: Page, path: string, predicate: (url: URL) => boolean = () => true): Promise<Response> {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET" && url.pathname === path && predicate(url);
  });
}

async function expectPage(response: Response, count: number, hasNext: boolean): Promise<void> {
  expect(response.status(), await response.text()).toBe(200);
  const payload = await response.json() as { readonly items: readonly unknown[]; readonly nextCursor: string | null };
  expect(payload.items).toHaveLength(count);
  expect(Boolean(payload.nextCursor)).toBe(hasNext);
}

async function activate(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await control.press("Enter");
  } else {
    await control.click();
  }
}

async function strictAudit(audit: BrowserAudit, testInfo: TestInfo): Promise<void> {
  expect(audit.unexpected, "Unexpected browser, console, network, or server failures").toEqual([]);
  expect(audit.degradedApi, "Operational-list fixtures require the real V2 API").toEqual([]);
  await audit.assertClean(testInfo);
}

async function returnThroughHistory(page: Page, audit: BrowserAudit, expectedUrl: string): Promise<void> {
  let steps = 0;
  while (page.url() !== expectedUrl && steps < 3) {
    await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
    steps += 1;
  }
  expect(steps).toBeGreaterThanOrEqual(1);
  expect(steps).toBeLessThanOrEqual(3);
  await expect(page).toHaveURL(expectedUrl);
}

test(`${TEST_IDS.agents} traverses canonical agent pages and a stable profile link`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const firstResponse = apiResponse(page, "/api/v2/agents", (url) => url.searchParams.get("query") === fixture.token
    && url.searchParams.get("limit") === "25" && !url.searchParams.has("cursor"));
  await page.goto(`/agents?query=${fixture.token}&limit=25`, { waitUntil: "domcontentloaded" });
  await expectPage(await firstResponse, 25, true);
  await expect(page.getByRole("heading", { level: 1, name: "Agents", exact: true })).toBeVisible();

  const agentSection = page.getByRole("region", { name: "Agent fleet", exact: true });
  const firstLink = agentSection.getByRole("link", {
    name: `Open agent ${fixture.agentNames[0]} (${fixture.agentIds[0]})`,
    exact: true,
  });
  await expect(firstLink).toHaveAttribute("href", `/agents/${fixture.agentIds[0]}`);
  await expect(agentSection.getByRole("link", { name: /^Open agent operationallist[a-f0-9]{12} agent [0-9]{2} \(agent-operationallist[a-f0-9]{12}-[0-9]{2}\)$/ })).toHaveCount(25);

  const secondResponse = apiResponse(page, "/api/v2/agents", (url) => url.searchParams.get("query") === fixture.token
    && url.searchParams.get("limit") === "25" && url.searchParams.has("cursor"));
  await activate(agentSection.getByRole("button", { name: "Next page of agents", exact: true }), "pointer");
  await expectPage(await secondResponse, 2, false);
  await expect(agentSection.getByRole("link", { name: /^Open agent operationallist/ })).toHaveCount(2);
  await expect(agentSection.getByRole("button", { name: "First page of agents", exact: true })).toBeEnabled();
  await expect(agentSection.getByRole("button", { name: "Next page of agents", exact: true })).toBeDisabled();

  await activate(agentSection.getByRole("button", { name: "First page of agents", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.get("cursor")).toBeNull();
  await expect(agentSection.getByRole("link", { name: /^Open agent operationallist/ })).toHaveCount(25);

  const detailResponse = apiResponse(page, `/api/v2/agents/${fixture.agentIds[0]}`);
  const agentListUrl = page.url();
  await activate(firstLink, "keyboard");
  expect((await detailResponse).status()).toBe(200);
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/agents/${fixture.agentIds[0]}`);
  await expect(page.getByRole("heading", { level: 2, name: fixture.agentNames[0], exact: true })).toBeVisible();
  const reloadedDetail = apiResponse(page, `/api/v2/agents/${fixture.agentIds[0]}`);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await reloadedDetail).status()).toBe(200);
  await expect(page.getByRole("heading", { level: 2, name: fixture.agentNames[0], exact: true })).toBeVisible();
  await returnThroughHistory(page, audit, agentListUrl);
  await expect(page.getByRole("link", {
    name: `Open agent ${fixture.agentNames[0]} (${fixture.agentIds[0]})`,
    exact: true,
  })).toBeVisible();
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.traces} traverses canonical trace pages and opens one correlated waterfall`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const firstResponse = apiResponse(page, "/api/v2/observability/traces", (url) => url.searchParams.get("query") === fixture.token
    && url.searchParams.get("limit") === "50" && !url.searchParams.has("cursor"));
  await page.goto(`/observability?view=traces&query=${fixture.token}&limit=50`, { waitUntil: "domcontentloaded" });
  await expectPage(await firstResponse, 50, true);
  const traceSection = page.getByRole("region", { name: "Trace results", exact: true });
  await expect(traceSection.getByRole("button", { name: /^Inspect trace operationallist[a-f0-9]{12} correlated trace [0-9]{2} \(trace-operationallist[a-f0-9]{12}-[0-9]{2}\)$/ })).toHaveCount(50);

  const secondResponse = apiResponse(page, "/api/v2/observability/traces", (url) => url.searchParams.get("query") === fixture.token
    && url.searchParams.get("limit") === "50" && url.searchParams.has("cursor"));
  await activate(traceSection.getByRole("button", { name: "Next page of traces", exact: true }), "keyboard");
  await expectPage(await secondResponse, 2, false);
  await expect(traceSection.getByRole("button", { name: /^Inspect trace operationallist/ })).toHaveCount(2);

  await activate(traceSection.getByRole("button", { name: "First page of traces", exact: true }), "pointer");
  await expect.poll(() => new URL(page.url()).searchParams.get("cursor")).toBeNull();
  await expect(traceSection.getByRole("button", { name: /^Inspect trace operationallist/ })).toHaveCount(50);

  const traceButton = traceSection.getByRole("button", {
    name: `Inspect trace ${fixture.traceSummaries[0]} (${fixture.traceIds[0]})`,
    exact: true,
  });
  const traceListUrl = page.url();
  const detailResponse = apiResponse(page, `/api/v2/observability/traces/${fixture.traceIds[0]}`);
  await activate(traceButton, "pointer");
  expect((await detailResponse).status()).toBe(200);
  await expect.poll(() => new URL(page.url()).searchParams.get("traceId")).toBe(fixture.traceIds[0]);
  await expect(page.getByRole("heading", { level: 2, name: fixture.traceSummaries[0], exact: true })).toBeVisible();
  await expect(page.getByLabel("Selected trace detail", { exact: true })).toContainText(fixture.traceIds[0]);
  const reloadedDetail = apiResponse(page, `/api/v2/observability/traces/${fixture.traceIds[0]}`);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await reloadedDetail).status()).toBe(200);
  await expect(page.getByRole("heading", { level: 2, name: fixture.traceSummaries[0], exact: true })).toBeVisible();
  await returnThroughHistory(page, audit, traceListUrl);
  await expect(page.getByLabel("Selected trace detail", { exact: true })).toContainText("Select a trace");
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.reports} traverses canonical report pages and a stable detail link`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const firstResponse = apiResponse(page, "/api/v2/reports", (url) => url.searchParams.get("missionId") === fixture.missionId
    && url.searchParams.get("limit") === "25" && !url.searchParams.has("cursor"));
  await page.goto(`/reports?missionId=${fixture.missionId}&limit=25`, { waitUntil: "domcontentloaded" });
  await expectPage(await firstResponse, 25, true);
  const reportSection = page.getByRole("region", { name: "Report records", exact: true });
  await expect(reportSection.getByRole("link", { name: /^Open report operationallist[a-f0-9]{12}_report_[0-9]{2} \(artifact-operationallist[a-f0-9]{12}-report-[0-9]{2}\)$/ })).toHaveCount(25);

  const secondResponse = apiResponse(page, "/api/v2/reports", (url) => url.searchParams.get("missionId") === fixture.missionId
    && url.searchParams.get("limit") === "25" && url.searchParams.has("cursor"));
  await activate(reportSection.getByRole("button", { name: "Next page of reports", exact: true }), "pointer");
  await expectPage(await secondResponse, 2, false);
  await expect(reportSection.getByRole("link", { name: /^Open report operationallist/ })).toHaveCount(2);

  await activate(reportSection.getByRole("button", { name: "First page of reports", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.get("cursor")).toBeNull();
  await expect(reportSection.getByRole("link", { name: /^Open report operationallist/ })).toHaveCount(25);

  const reportLink = reportSection.getByRole("link", {
    name: `Open report ${fixture.reportTypes[0]} (${fixture.reportIds[0]})`,
    exact: true,
  });
  await expect(reportLink).toHaveAttribute("href", `/reports/${fixture.reportIds[0]}`);
  const reportListUrl = page.url();
  const detailResponse = apiResponse(page, `/api/v2/reports/${fixture.reportIds[0]}`);
  await activate(reportLink, "keyboard");
  expect((await detailResponse).status()).toBe(200);
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/reports/${fixture.reportIds[0]}`);
  await expect(page.getByRole("heading", { level: 2, name: fixture.reportTypes[0], exact: true })).toBeVisible();
  await expect(page.getByText(/Direct download requires a separate authorized artifact-delivery contract\.$/u)).toBeVisible();
  const reloadedDetail = apiResponse(page, `/api/v2/reports/${fixture.reportIds[0]}`);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await reloadedDetail).status()).toBe(200);
  await expect(page.getByRole("heading", { level: 2, name: fixture.reportTypes[0], exact: true })).toBeVisible();
  await returnThroughHistory(page, audit, reportListUrl);
  await expect(page.getByRole("link", {
    name: `Open report ${fixture.reportTypes[0]} (${fixture.reportIds[0]})`,
    exact: true,
  })).toBeVisible();
  await strictAudit(audit, testInfo);
});

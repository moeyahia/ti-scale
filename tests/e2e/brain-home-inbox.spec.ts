import {
  expect,
  test,
  type Locator,
  type Page,
  type Request,
  type Response,
  type TestInfo,
} from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import {
  createBrainHomeInboxFixture,
  readBrainHomeInboxSnapshot,
  type BrainHomeInboxFixture,
} from "./support/brainHomeInboxFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import { readTitaniumOptions, selectTitaniumOption } from "./support/titaniumSelect";
import { MEMORY_NODE_TYPES, type MemoryNodeType } from "../../src/domain/types/brain";

const TEST_IDS = {
  homeNavigation: "e2e.brain-home.navigation-and-populated",
  homeSearch: "e2e.brain-home.search-filters-node",
  homeEmpty: "e2e.brain-home.empty",
  homeSummaryRetry: "e2e.brain-home.summary-retry",
  homeNodesRetry: "e2e.brain-home.nodes-retry",
  homePagination: "e2e.brain-home.pagination",
  inboxConfirm: "e2e.brain-inbox.confirm",
  inboxEdit: "e2e.brain-inbox.edit-scope-confirm",
  inboxReject: "e2e.brain-inbox.reject",
  inboxSuppress: "e2e.brain-inbox.reject-do-not-relearn",
  inboxEmptyRetry: "e2e.brain-inbox.empty-navigation-retry",
  inboxPagination: "e2e.brain-inbox.pagination",
} as const;

const BRAIN_TABS = [
  { name: "Home", href: "/brain", heading: "Second Brain" },
  { name: "Graph", href: "/brain/graph", heading: "Memory Graph" },
  { name: "Memory Inbox", href: "/brain/inbox", heading: "Memory Inbox" },
  { name: "Controls", href: "/brain/control", heading: "Memory Control Center" },
  { name: "Obsidian Vault", href: "/brain/vault", heading: "Obsidian Vault" },
] as const;
const LIFECYCLES = ["candidate", "confirmed", "verified", "disputed", "stale", "superseded"] as const;
const SENSITIVITIES = ["public", "internal", "private", "restricted"] as const;

function nodeTypeLabel(type: MemoryNodeType): string {
  return type.replaceAll("_", " ");
}

let fixture: BrainHomeInboxFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createBrainHomeInboxFixture(canonicalFixtureNamespace(testInfo, "brain-home-inbox"));
});

function pathname(response: Response): string {
  return new URL(response.url()).pathname;
}

function inboxRoute(missionId = fixture.missionId, runId = fixture.runId): string {
  return `/brain/inbox?missionId=${encodeURIComponent(missionId)}&runId=${encodeURIComponent(runId)}`;
}

function brainRead(
  page: Page,
  endpoint: "/api/v2/brain/summary" | "/api/v2/brain/nodes" | "/api/v2/brain/candidates",
  predicate: (url: URL) => boolean = () => true,
): Promise<Response> {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET" && url.pathname === endpoint && predicate(url);
  });
}

function candidateMutation(
  page: Page,
  candidateId: string,
  action: "confirm" | "reject",
): Promise<Response> {
  const endpoint = `/api/v2/brain/candidates/${candidateId}/${action}`;
  return page.waitForResponse((response) => response.request().method() === "POST" && pathname(response) === endpoint);
}

function candidateRequest(
  page: Page,
  candidateId: string,
  action: "confirm" | "reject",
): Promise<Request> {
  const endpoint = `/api/v2/brain/candidates/${candidateId}/${action}`;
  return page.waitForRequest((request) => request.method() === "POST" && new URL(request.url()).pathname === endpoint);
}

async function strictAudit(audit: BrowserAudit, testInfo: TestInfo): Promise<void> {
  expect(audit.unexpected, "Second Brain controls emitted an unexpected browser, console, network, or server failure").toEqual([]);
  expect(audit.degradedApi, "Second Brain source coverage requires the mounted V2 API").toEqual([]);
  await audit.assertClean(testInfo);
}

async function expectSelectedTitaniumValue(control: Locator, value: string): Promise<void> {
  const selected = (await readTitaniumOptions(control)).filter((option) => option.selected);
  expect(selected).toHaveLength(1);
  expect(selected[0]?.value).toBe(value);
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

async function traverseHistoryTo(
  page: Page,
  audit: BrowserAudit,
  targetUrl: string,
  direction: "back" | "forward",
): Promise<number> {
  let steps = 0;
  while (page.url() !== targetUrl && steps < 2) {
    if (direction === "back") {
      await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
    } else {
      await audit.withExpectedHistoryTraversal(page, () => page.goForward({ waitUntil: "domcontentloaded" }));
    }
    steps += 1;
  }
  expect(steps).toBeGreaterThanOrEqual(1);
  expect(steps).toBeLessThanOrEqual(2);
  await expect(page).toHaveURL(targetUrl);
  return steps;
}

async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 350));
}

function candidateCard(page: Page, title: string): Locator {
  return page.locator("article.brain-candidate").filter({
    has: page.getByRole("heading", { level: 2, name: title, exact: true }),
  });
}

async function gotoInbox(
  page: Page,
  missionId = fixture.missionId,
  runId = fixture.runId,
): Promise<void> {
  const response = brainRead(page, "/api/v2/brain/candidates", (url) =>
    url.searchParams.get("missionId") === missionId
    && url.searchParams.get("runId") === runId);
  await page.goto(inboxRoute(missionId, runId), { waitUntil: "domcontentloaded" });
  expect((await response).status()).toBe(200);
  await expectHeading(page, "Memory Inbox");
  await expect(page.getByText(`Only candidates whose canonical provenance resolves to run ${runId}`, { exact: false })).toBeVisible();
}

function fixtureError(humanMessage: string, remediation: string, traceId: string) {
  return {
    error: {
      code: "brain_fixture_temporarily_unavailable",
      message: "Second Brain fixture temporarily unavailable",
      humanMessage,
      retryable: true,
      category: "dependency",
      remediation,
      traceId,
      timestamp: "2099-07-16T18:30:00.000Z",
    },
  };
}

test(`${TEST_IDS.homeNavigation} traverses every Second Brain home link against canonical data`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const summary = brainRead(page, "/api/v2/brain/summary");
  const nodes = brainRead(page, "/api/v2/brain/nodes");
  await page.goto("/brain", { waitUntil: "domcontentloaded" });
  const [summaryResponse, nodesResponse] = await Promise.all([summary, nodes]);
  expect(summaryResponse.status()).toBe(200);
  expect(nodesResponse.status()).toBe(200);
  const summaryPayload = await summaryResponse.json() as {
    counts: {
      confirmed: number;
      verified: number;
      candidateNodes: number;
      pendingReviews: number;
      candidates: number;
      edges: number;
    };
    health: { database: string; fts: string };
  };
  expect(summaryPayload.counts.confirmed).toBeGreaterThanOrEqual(1);
  expect(summaryPayload.counts.verified).toBeGreaterThanOrEqual(1);
  expect(summaryPayload.counts.candidateNodes).toBeGreaterThanOrEqual(1);
  expect(summaryPayload.counts.pendingReviews).toBeGreaterThanOrEqual(4);
  expect(summaryPayload.counts.candidates).toBe(summaryPayload.counts.pendingReviews);
  expect(summaryPayload.counts.edges).toBeGreaterThanOrEqual(1);
  expect(summaryPayload.health).toEqual({ database: "healthy", fts: "healthy" });
  await expectHeading(page, "Second Brain");
  await expect(page.getByRole("region", { name: "Memory health", exact: true })).toContainText("Confirmed");
  await expect(page.getByRole("region", { name: "Memory health", exact: true })).toContainText("Verified");
  await expect(page.getByRole("region", { name: "Memory health", exact: true })).toContainText("Candidate nodes");
  await expect(page.getByRole("region", { name: "Memory health", exact: true })).toContainText("Inbox reviews");
  await expect(page.getByRole("heading", { name: "Canonical memory health", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Obsidian vault", exact: true })).toBeVisible();

  for (const tab of BRAIN_TABS) {
    await expect(page.getByRole("navigation", { name: "Second Brain", exact: true })
      .getByRole("link", { name: tab.name, exact: true })).toHaveAttribute("href", tab.href);
  }

  const currentHome = page.getByRole("navigation", { name: "Second Brain", exact: true })
    .getByRole("link", { name: "Home", exact: true });
  await activate(currentHome, "keyboard");
  await expectHeading(page, "Second Brain");

  for (const [index, tab] of BRAIN_TABS.slice(1).entries()) {
    const link = page.getByRole("navigation", { name: "Second Brain", exact: true })
      .getByRole("link", { name: tab.name, exact: true });
    await activate(link, index % 2 === 0 ? "pointer" : "keyboard");
    await expect.poll(() => new URL(page.url()).pathname).toBe(tab.href);
    await expectHeading(page, tab.heading);
    await settle();
    await page.goBack({ waitUntil: "domcontentloaded" });
    await expectHeading(page, "Second Brain");
  }

  const openGraph = page.getByRole("link", { name: "Open graph", exact: true });
  await expect(openGraph).toHaveAttribute("href", "/brain/graph");
  await activate(openGraph, "keyboard");
  await expectHeading(page, "Memory Graph");
  await settle();
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expectHeading(page, "Second Brain");

  const manage = page.getByRole("link", { name: "Manage", exact: true });
  await expect(manage).toHaveAttribute("href", "/brain/vault");
  await activate(manage, "pointer");
  await expectHeading(page, "Obsidian Vault");
  await settle();
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expectHeading(page, "Second Brain");

  const review = page.getByRole("link", { name: "Review candidates", exact: true });
  await expect(review).toHaveAttribute("href", "/brain/inbox");
  await activate(review, "keyboard");
  await expectHeading(page, "Memory Inbox");
  await settle();
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expectHeading(page, "Second Brain");
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.homeSearch} exercises every home search option and a stable node deep link`, async ({ page }, testInfo) => {
  // This is an exhaustive registry audit rather than a representative sample:
  // every canonical memory-node type must complete a real filtered API read
  // through alternating pointer and keyboard input.
  test.slow();
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const initialNodes = brainRead(page, "/api/v2/brain/nodes");
  await page.goto("/brain", { waitUntil: "domcontentloaded" });
  expect((await initialNodes).status()).toBe(200);
  await expectHeading(page, "Second Brain");

  const search = page.getByLabel("Search title, summary, and note text", { exact: true });
  const searchResponse = brainRead(page, "/api/v2/brain/nodes", (url) => url.searchParams.get("query") === fixture.searchToken);
  await search.fill(fixture.searchToken);
  await activate(page.getByRole("button", { name: "Search", exact: true }), "pointer");
  const searched = await searchResponse;
  expect(searched.status(), await searched.text()).toBe(200);
  const searchedPayload = await searched.json() as { items: readonly { id: string }[] };
  expect(searchedPayload.items.map((item) => item.id).sort()).toEqual([...fixture.nodeIds].sort());
  await expect(page.getByRole("link", { name: `Open memory ${fixture.primaryNodeTitle} (${fixture.primaryNodeId})`, exact: true })).toBeVisible();

  const nodeType = page.getByRole("combobox", { name: "Node type", exact: true });
  expect((await readTitaniumOptions(nodeType)).map(({ value, label, disabled }) => ({ value, label, disabled }))).toEqual([
    { value: "", label: "All types", disabled: false },
    ...MEMORY_NODE_TYPES.map((type) => ({ value: type, label: nodeTypeLabel(type), disabled: false })),
  ]);
  for (const [index, type] of MEMORY_NODE_TYPES.entries()) {
    const response = brainRead(page, "/api/v2/brain/nodes", (url) => url.searchParams.get("nodeType") === type);
    await selectTitaniumOption(nodeType, type, index % 2 === 0 ? "pointer" : "keyboard");
    expect((await response).status()).toBe(200);
    await expectSelectedTitaniumValue(nodeType, type);
  }
  await selectTitaniumOption(nodeType, "", "keyboard");

  const lifecycle = page.getByRole("combobox", { name: "Lifecycle", exact: true });
  expect((await readTitaniumOptions(lifecycle)).map(({ value, label, disabled }) => ({ value, label, disabled }))).toEqual([
    { value: "", label: "All active states", disabled: false },
    ...LIFECYCLES.map((status) => ({ value: status, label: status, disabled: false })),
  ]);
  for (const [index, status] of LIFECYCLES.entries()) {
    const response = brainRead(page, "/api/v2/brain/nodes", (url) => url.searchParams.get("status") === status);
    await selectTitaniumOption(lifecycle, status, index % 2 === 0 ? "keyboard" : "pointer");
    expect((await response).status()).toBe(200);
  }
  await selectTitaniumOption(lifecycle, "", "pointer");

  const sensitivity = page.getByRole("combobox", { name: "Sensitivity", exact: true });
  expect((await readTitaniumOptions(sensitivity)).map(({ value, label, disabled }) => ({ value, label, disabled }))).toEqual([
    { value: "", label: "Permitted levels", disabled: false },
    ...SENSITIVITIES.map((level) => ({ value: level, label: level, disabled: false })),
  ]);
  for (const [index, level] of SENSITIVITIES.entries()) {
    const response = brainRead(page, "/api/v2/brain/nodes", (url) => url.searchParams.get("sensitivity") === level);
    await selectTitaniumOption(sensitivity, level, index % 2 === 0 ? "pointer" : "keyboard");
    expect((await response).status()).toBe(200);
  }
  await selectTitaniumOption(sensitivity, "", "keyboard");
  await expect(page.getByRole("link", { name: `Open memory ${fixture.primaryNodeTitle} (${fixture.primaryNodeId})`, exact: true })).toBeVisible();

  const detailResponse = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/brain/nodes/${fixture.primaryNodeId}`);
  const historyBeforeDetail = await page.evaluate(() => history.length);
  await activate(page.getByRole("link", { name: `Open memory ${fixture.primaryNodeTitle} (${fixture.primaryNodeId})`, exact: true }), "keyboard");
  expect((await detailResponse).status()).toBe(200);
  await expect.poll(() => page.evaluate(() => history.length)).toBe(historyBeforeDetail + 1);
  await expectHeading(page, fixture.primaryNodeTitle);
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/brain/nodes/${fixture.primaryNodeId}`);
  const reloadDetail = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/brain/nodes/${fixture.primaryNodeId}`);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await reloadDetail).status()).toBe(200);
  expect([historyBeforeDetail + 1, historyBeforeDetail + 2]).toContain(await page.evaluate(() => history.length));
  await expectHeading(page, fixture.primaryNodeTitle);
  for (let attempt = 0; attempt < 2 && new URL(page.url()).pathname !== "/brain"; attempt += 1) {
    await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
  }
  await expect.poll(() => new URL(page.url()).pathname).toBe("/brain");
  await expectHeading(page, "Second Brain");
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.homePagination} preserves home filters through cursor, reload, back, forward, and first-page navigation`, async ({ page }, testInfo) => {
  const firstRead = brainRead(page, "/api/v2/brain/nodes", (url) =>
    url.searchParams.get("query") === fixture.paginationToken
    && url.searchParams.get("sensitivity") === "internal"
    && !url.searchParams.has("cursor"));
  await page.goto(`/brain?${new URLSearchParams({ query: fixture.paginationToken, sensitivity: "internal" })}`, { waitUntil: "domcontentloaded" });
  const firstResponse = await firstRead;
  expect(firstResponse.status()).toBe(200);
  const firstPayload = await firstResponse.json() as { items: unknown[]; nextCursor: string | null };
  expect(firstPayload.items).toHaveLength(50);
  expect(firstPayload.nextCursor).toBeTruthy();
  await expectHeading(page, "Second Brain");
  const firstUrl = page.url();
  const firstPage = page.getByRole("button", { name: "First page", exact: true });
  const nextPage = page.getByRole("button", { name: "Next page", exact: true });
  await expect(firstPage).toBeDisabled();
  await expect(nextPage).toBeEnabled();
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });

  const secondRead = brainRead(page, "/api/v2/brain/nodes", (url) =>
    url.searchParams.get("query") === fixture.paginationToken
    && url.searchParams.get("sensitivity") === "internal"
    && Boolean(url.searchParams.get("cursor")));
  await activate(nextPage, "pointer");
  const secondResponse = await secondRead;
  expect(secondResponse.status()).toBe(200);
  const secondPayload = await secondResponse.json() as { items: unknown[]; nextCursor: string | null };
  expect(secondPayload.items).toHaveLength(5);
  expect(secondPayload.nextCursor).toBeNull();
  const secondUrl = page.url();
  expect(new URL(secondUrl).searchParams.get("query")).toBe(fixture.paginationToken);
  expect(new URL(secondUrl).searchParams.get("sensitivity")).toBe("internal");
  expect(new URL(secondUrl).searchParams.get("cursor")).toBeTruthy();
  await expect(page.getByRole("button", { name: "Next page", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "First page", exact: true })).toBeEnabled();

  const reloadRead = brainRead(page, "/api/v2/brain/nodes", (url) => url.searchParams.get("cursor") === new URL(secondUrl).searchParams.get("cursor"));
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await reloadRead).status()).toBe(200);
  await expectHeading(page, "Second Brain");
  await traverseHistoryTo(page, audit, firstUrl, "back");
  await expect(page.getByLabel("Search title, summary, and note text", { exact: true })).toHaveValue(fixture.paginationToken);
  await expectSelectedTitaniumValue(
    page.getByRole("combobox", { name: "Sensitivity", exact: true }),
    "internal",
  );
  await traverseHistoryTo(page, audit, secondUrl, "forward");
  await activate(page.getByRole("button", { name: "First page", exact: true }), "keyboard");
  await expect(page).toHaveURL(firstUrl);
  await strictAudit(audit, testInfo);
  // Returning to the first page can trigger the shell's final notification
  // refresh just after the route assertion becomes quiet. Keep teardown
  // bounded, but do not close the page while those required reads are still
  // in flight; a genuinely hung request still fails with the audit's precise
  // settlement diagnosis.
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
});

test(`${TEST_IDS.homeEmpty} exposes a useful no-match state and keyboard form submission`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const initialNodes = brainRead(page, "/api/v2/brain/nodes");
  await page.goto("/brain", { waitUntil: "domcontentloaded" });
  expect((await initialNodes).status()).toBe(200);
  const emptyQuery = `${fixture.searchToken}nomatch`;
  const emptyResponse = brainRead(page, "/api/v2/brain/nodes", (url) => url.searchParams.get("query") === emptyQuery);
  const search = page.getByLabel("Search title, summary, and note text", { exact: true });
  await search.fill(emptyQuery);
  await search.press("Enter");
  const response = await emptyResponse;
  expect(response.status()).toBe(200);
  expect((await response.json() as { items: unknown[] }).items).toEqual([]);
  await expect(page.getByText("No matching memory", { exact: true })).toBeVisible();
  const openInbox = page.getByRole("link", { name: "Open Memory Inbox", exact: true });
  await expect(openInbox).toHaveAttribute("href", "/brain/inbox");
  await activate(openInbox, "pointer");
  await expectHeading(page, "Memory Inbox");
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.homeSummaryRetry} explains and retries one summary read failure`, async ({ page, browserAudit }, testInfo) => {
  browserAudit.expectHttpResponse(page, {
    id: "brain.summary.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: "/api/v2/brain/summary",
    query: {},
    status: 503,
    occurrences: 1,
    reason: "Exercise the canonical memory-health retry state once.",
  });
  let failed = false;
  await page.route("**/api/v2/brain/summary", async (route) => {
    if (!failed) {
      failed = true;
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify(fixtureError(
          "Canonical memory health could not read the isolated database snapshot.",
          "Retry after the local Second Brain database is available.",
          "trace-brain-summary-retry",
        )),
      });
      return;
    }
    await route.continue();
  });
  await page.goto("/brain", { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Canonical memory health could not read the isolated database snapshot.", { exact: true })).toBeVisible();
  await expect(page.getByText("Retry after the local Second Brain database is available.", { exact: true })).toBeVisible();
  await expect(page.getByText("Trace trace-brain-summary-retry", { exact: true })).toBeVisible();

  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const recovered = brainRead(page, "/api/v2/brain/summary");
  await activate(page.getByRole("button", { name: "Try again", exact: true }), "keyboard");
  expect((await recovered).status()).toBe(200);
  await expect(page.getByRole("region", { name: "Memory health", exact: true })).toBeVisible();
  await page.unroute("**/api/v2/brain/summary");
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.homeNodesRetry} explains and retries one memory-node read failure`, async ({ page, browserAudit }, testInfo) => {
  browserAudit.expectHttpResponse(page, {
    id: "brain.nodes.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: "/api/v2/brain/nodes",
    query: { limit: "50" },
    status: 503,
    occurrences: 1,
    reason: "Exercise the canonical memory-node retry state once.",
  });
  let failed = false;
  await page.route("**/api/v2/brain/nodes?*", async (route) => {
    if (!failed) {
      failed = true;
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify(fixtureError(
          "Memory search could not read its canonical lexical projection.",
          "Retry after the local memory index is available.",
          "trace-brain-nodes-retry",
        )),
      });
      return;
    }
    await route.continue();
  });
  await page.goto("/brain", { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Memory search could not read its canonical lexical projection.", { exact: true })).toBeVisible();
  await expect(page.getByText("Retry after the local memory index is available.", { exact: true })).toBeVisible();
  await expect(page.getByText("Trace trace-brain-nodes-retry", { exact: true })).toBeVisible();

  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const recovered = brainRead(page, "/api/v2/brain/nodes");
  await activate(page.getByRole("button", { name: "Try again", exact: true }), "pointer");
  expect((await recovered).status()).toBe(200);
  await expect(page.getByRole("link", { name: `Open memory ${fixture.primaryNodeTitle} (${fixture.primaryNodeId})`, exact: true })).toBeVisible();
  await page.unroute("**/api/v2/brain/nodes?*");
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.inboxPagination} preserves exact mission/run scope through cursor and browser history`, async ({ page }, testInfo) => {
  const firstRead = brainRead(page, "/api/v2/brain/candidates", (url) =>
    url.searchParams.get("missionId") === fixture.missionId
    && url.searchParams.get("runId") === fixture.runId
    && !url.searchParams.has("cursor"));
  await page.goto(inboxRoute(), { waitUntil: "domcontentloaded" });
  const firstResponse = await firstRead;
  expect(firstResponse.status()).toBe(200);
  const firstPayload = await firstResponse.json() as { items: unknown[]; nextCursor: string | null };
  expect(firstPayload.items).toHaveLength(50);
  expect(firstPayload.nextCursor).toBeTruthy();
  await expectHeading(page, "Memory Inbox");
  const firstUrl = page.url();
  await expect(page.getByRole("button", { name: "First page", exact: true })).toBeDisabled();
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });

  const secondRead = brainRead(page, "/api/v2/brain/candidates", (url) =>
    url.searchParams.get("missionId") === fixture.missionId
    && url.searchParams.get("runId") === fixture.runId
    && Boolean(url.searchParams.get("cursor")));
  await activate(page.getByRole("button", { name: "Next page", exact: true }), "keyboard");
  const secondResponse = await secondRead;
  expect(secondResponse.status()).toBe(200);
  const secondPayload = await secondResponse.json() as { items: unknown[]; nextCursor: string | null };
  expect(secondPayload.items).toHaveLength(9);
  expect(secondPayload.nextCursor).toBeNull();
  const secondUrl = page.url();
  const secondSearch = new URL(secondUrl).searchParams;
  expect(secondSearch.get("missionId")).toBe(fixture.missionId);
  expect(secondSearch.get("runId")).toBe(fixture.runId);
  expect(secondSearch.get("cursor")).toBeTruthy();
  await expect(page.getByRole("button", { name: "Next page", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "First page", exact: true })).toBeEnabled();

  const reloadRead = brainRead(page, "/api/v2/brain/candidates", (url) => url.searchParams.get("cursor") === secondSearch.get("cursor"));
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await reloadRead).status()).toBe(200);
  await expectHeading(page, "Memory Inbox");
  await traverseHistoryTo(page, audit, firstUrl, "back");
  await expect(page.getByText(`Only candidates whose canonical provenance resolves to run ${fixture.runId}`, { exact: false })).toBeVisible();
  await traverseHistoryTo(page, audit, secondUrl, "forward");
  await activate(page.getByRole("button", { name: "First page", exact: true }), "pointer");
  await expect(page).toHaveURL(firstUrl);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.inboxConfirm} confirms one unchanged candidate through the mounted API`, async ({ page, browserAudit }, testInfo) => {
  browserAudit.expectHttpResponse(page, {
    id: "brain.candidate.confirm.initial-unavailable",
    transport: "browser",
    method: "POST",
    pathname: `/api/v2/brain/candidates/${fixture.directCandidateId}/confirm`,
    query: {},
    status: 503,
    occurrences: 1,
    reason: "Exercise the exact candidate-confirmation recovery boundary once.",
  });
  let failed = false;
  const confirmationPath = `**/api/v2/brain/candidates/${fixture.directCandidateId}/confirm`;
  await page.route(confirmationPath, async (route) => {
    if (!failed) {
      failed = true;
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify(fixtureError(
          "The represented memory candidate could not be confirmed against its canonical state.",
          "Refresh the candidate state and retry this exact confirmation.",
          "trace-brain-candidate-confirm",
        )),
      });
      return;
    }
    await route.continue();
  });
  await gotoInbox(page);
  const card = candidateCard(page, fixture.directCandidateTitle);
  await expect(card).toBeVisible();
  await expect(card).toContainText("Why it was proposed");
  await expect(card).toContainText(fixture.runId);

  await activate(card.getByRole("button", { name: "Confirm memory", exact: true }), "pointer");
  await expect(card.getByRole("alert")).toContainText("The represented memory candidate could not be confirmed against its canonical state.");
  await expect(card.getByRole("alert")).toContainText("Refresh the candidate state and retry this exact confirmation.");
  await expect(card.getByRole("alert")).toContainText("Trace trace-brain-candidate-confirm");
  expect(readBrainHomeInboxSnapshot(fixture).candidates.find((item) => item.id === fixture.directCandidateId)?.status)
    .toBe("pending");
  await page.unroute(confirmationPath);

  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });

  const mutation = candidateMutation(page, fixture.directCandidateId, "confirm");
  const refresh = brainRead(page, "/api/v2/brain/candidates", (url) => url.searchParams.get("runId") === fixture.runId);
  await activate(card.getByRole("button", { name: "Confirm memory", exact: true }), "keyboard");
  const response = await mutation;
  expect(response.status(), await response.text()).toBe(201);
  const payload = await response.json() as { node: { title: string; lifecycleStatus: string; confirmationState: string } };
  expect(payload.node).toMatchObject({
    title: fixture.directCandidateTitle,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
  });
  expect((await refresh).status()).toBe(200);
  await expect(card).toHaveCount(0);

  const snapshot = readBrainHomeInboxSnapshot(fixture);
  expect(snapshot.candidates.find((item) => item.id === fixture.directCandidateId)).toMatchObject({
    status: "confirmed",
    reviewedBy: "e2e-local-operator",
  });
  expect(snapshot.confirmedNodes.find((item) => item.candidateId === fixture.directCandidateId)).toMatchObject({
    title: fixture.directCandidateTitle,
    scope: "global",
    versionCount: 1,
    sourceCount: 1,
  });

  const reload = brainRead(page, "/api/v2/brain/candidates", (url) => url.searchParams.get("runId") === fixture.runId);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await reload).status()).toBe(200);
  await expect(page.getByText(fixture.directCandidateTitle, { exact: true })).toHaveCount(0);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.inboxEdit} discards transient edits then confirms a scoped, sensitive correction`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await gotoInbox(page);
  const card = candidateCard(page, fixture.editedCandidateTitle);
  await activate(card.getByRole("button", { name: "Edit then confirm", exact: true }), "keyboard");
  const title = card.getByRole("textbox", { name: "Title", exact: true });
  await title.fill("This value must be discarded");
  await card.getByRole("textbox", { name: "Summary", exact: true }).fill("This summary must be discarded");
  await activate(card.getByRole("button", { name: "Discard edits", exact: true }), "pointer");
  await expect(card.getByRole("textbox", { name: "Title", exact: true })).toHaveCount(0);
  await activate(card.getByRole("button", { name: "Edit then confirm", exact: true }), "pointer");
  await expect(card.getByRole("textbox", { name: "Title", exact: true })).toHaveValue(fixture.editedCandidateTitle);
  await expect(card.getByRole("textbox", { name: "Summary", exact: true })).toHaveValue("Reviewable edited memory candidate with exact-run provenance.");

  const sensitivity = card.getByRole("combobox", { name: "Sensitivity", exact: true });
  expect((await readTitaniumOptions(sensitivity)).map((option) => option.label)).toEqual([...SENSITIVITIES]);
  for (const [index, level] of SENSITIVITIES.entries()) {
    await selectTitaniumOption(sensitivity, level, index % 2 === 0 ? "pointer" : "keyboard");
  }

  const scope = card.getByRole("combobox", { name: "Scope", exact: true });
  expect((await readTitaniumOptions(scope)).map((option) => option.label)).toEqual(["Global", "Engagement", "Mission"]);
  await selectTitaniumOption(scope, "global", "keyboard");
  await expect(card.getByRole("textbox", { name: "Engagement ID", exact: true })).toHaveCount(0);
  await expect(card.getByRole("textbox", { name: "Mission ID", exact: true })).toHaveCount(0);
  await selectTitaniumOption(scope, "engagement", "pointer");
  await card.getByRole("textbox", { name: "Engagement ID", exact: true }).fill(fixture.engagementId);
  await expect(card.getByRole("textbox", { name: "Mission ID", exact: true })).toHaveCount(0);
  await selectTitaniumOption(scope, "mission", "keyboard");
  await card.getByRole("textbox", { name: "Engagement ID", exact: true }).fill(fixture.engagementId);
  await card.getByRole("textbox", { name: "Mission ID", exact: true }).fill(fixture.missionId);

  const editedTitle = `${fixture.editedCandidateTitle} confirmed`;
  const editedSummary = "Operator-confirmed mission-scoped explanation preference with canonical provenance.";
  const editedBody = "Use the confirmed explanation preference only inside this mission and retain its source link.";
  await card.getByRole("textbox", { name: "Title", exact: true }).fill(editedTitle);
  await card.getByRole("textbox", { name: "Summary", exact: true }).fill(editedSummary);
  await card.getByRole("textbox", { name: "Note body", exact: true }).fill(editedBody);
  await selectTitaniumOption(sensitivity, "restricted", "keyboard");

  const requestPromise = candidateRequest(page, fixture.editedCandidateId, "confirm");
  const mutation = candidateMutation(page, fixture.editedCandidateId, "confirm");
  const refresh = brainRead(page, "/api/v2/brain/candidates", (url) => url.searchParams.get("runId") === fixture.runId);
  await activate(card.getByRole("button", { name: "Confirm edited memory", exact: true }), "pointer");
  const request = await requestPromise;
  expect(request.postDataJSON()).toEqual({
    edits: {
      title: editedTitle,
      summary: editedSummary,
      body: editedBody,
      sensitivity: "restricted",
      scope: { kind: "mission", engagementId: fixture.engagementId, missionId: fixture.missionId },
    },
  });
  const response = await mutation;
  expect(response.status(), await response.text()).toBe(201);
  expect((await refresh).status()).toBe(200);
  await expect(card).toHaveCount(0);

  const snapshot = readBrainHomeInboxSnapshot(fixture);
  expect(snapshot.candidates.find((item) => item.id === fixture.editedCandidateId)).toMatchObject({
    status: "edited_confirmed",
    reviewedBy: "e2e-local-operator",
  });
  expect(snapshot.confirmedNodes.find((item) => item.candidateId === fixture.editedCandidateId)).toMatchObject({
    title: editedTitle,
    sensitivity: "restricted",
    scope: "mission",
    engagementId: fixture.engagementId,
    missionId: fixture.missionId,
    versionCount: 1,
    sourceCount: 1,
  });
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.inboxReject} validates, cancels, and records ordinary rejection without suppression`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await gotoInbox(page);
  const card = candidateCard(page, fixture.plainRejectCandidateTitle);
  await activate(card.getByRole("button", { name: "Reject", exact: true }), "pointer");
  await expect(card.getByRole("group", { name: "Reject candidate", exact: true })).toBeVisible();
  await activate(card.getByRole("button", { name: "Cancel rejection", exact: true }), "keyboard");
  await expect(card.getByRole("group", { name: "Reject candidate", exact: true })).toHaveCount(0);
  await activate(card.getByRole("button", { name: "Reject", exact: true }), "keyboard");

  const confirm = card.getByRole("button", { name: "Confirm rejection", exact: true });
  await activate(confirm, "pointer");
  await expect(card.getByRole("alert")).toHaveText("Record a reason before rejecting this candidate");
  const suppress = card.getByRole("checkbox", { name: /^Do not relearn this memory/u });
  await expect(suppress).toBeChecked();
  await toggleCheckbox(suppress, "keyboard");
  await expect(suppress).not.toBeChecked();
  const reason = "The represented procedure is incorrect, but a future evidence-backed correction may be proposed.";
  await card.getByRole("textbox", { name: "Reason", exact: true }).fill(reason);

  const requestPromise = candidateRequest(page, fixture.plainRejectCandidateId, "reject");
  const mutation = candidateMutation(page, fixture.plainRejectCandidateId, "reject");
  const refresh = brainRead(page, "/api/v2/brain/candidates", (url) => url.searchParams.get("runId") === fixture.runId);
  await activate(confirm, "keyboard");
  expect((await requestPromise).postDataJSON()).toEqual({ reason, doNotRelearn: false });
  const response = await mutation;
  expect(response.status(), await response.text()).toBe(200);
  expect(await response.json()).toMatchObject({ candidateId: fixture.plainRejectCandidateId, status: "rejected" });
  expect((await refresh).status()).toBe(200);
  await expect(card).toHaveCount(0);

  const snapshot = readBrainHomeInboxSnapshot(fixture);
  expect(snapshot.candidates.find((item) => item.id === fixture.plainRejectCandidateId)).toMatchObject({
    status: "rejected",
    title: fixture.plainRejectCandidateTitle,
    reviewedBy: "e2e-local-operator",
  });
  expect(snapshot.suppressionCount).toBe(0);
  expect(snapshot.audits).toContainEqual(expect.objectContaining({
    action: "memory_candidate.rejected",
    resourceId: fixture.plainRejectCandidateId,
    reason,
    details: expect.objectContaining({ doNotRelearn: false }),
    recordHash: expect.stringMatching(/^[a-f0-9]{64}$/u),
  }));
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.inboxSuppress} rejects, erases, and suppresses one candidate from relearning`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await gotoInbox(page);
  const card = candidateCard(page, fixture.suppressCandidateTitle);
  await activate(card.getByRole("button", { name: "Reject", exact: true }), "keyboard");
  const suppress = card.getByRole("checkbox", { name: /^Do not relearn this memory/u });
  await expect(suppress).toBeChecked();
  await toggleCheckbox(suppress, "pointer");
  await expect(suppress).not.toBeChecked();
  await toggleCheckbox(suppress, "pointer");
  await expect(suppress).toBeChecked();
  const reason = "This reusable procedure is unsafe for retention and must not be proposed again from identical content.";
  await card.getByRole("textbox", { name: "Reason", exact: true }).fill(reason);

  const requestPromise = candidateRequest(page, fixture.suppressCandidateId, "reject");
  const mutation = candidateMutation(page, fixture.suppressCandidateId, "reject");
  const refresh = brainRead(page, "/api/v2/brain/candidates", (url) => url.searchParams.get("runId") === fixture.runId);
  await activate(card.getByRole("button", { name: "Confirm rejection", exact: true }), "pointer");
  expect((await requestPromise).postDataJSON()).toEqual({ reason, doNotRelearn: true });
  const response = await mutation;
  expect(response.status(), await response.text()).toBe(200);
  const payload = await response.json() as { candidateId: string; status: string; suppressionId?: string };
  expect(payload).toMatchObject({ candidateId: fixture.suppressCandidateId, status: "suppressed" });
  expect(payload.suppressionId).toBeTruthy();
  expect((await refresh).status()).toBe(200);
  await expect(card).toHaveCount(0);

  const snapshot = readBrainHomeInboxSnapshot(fixture);
  expect(snapshot.candidates.find((item) => item.id === fixture.suppressCandidateId)).toMatchObject({
    status: "suppressed",
    title: "[Suppressed candidate]",
    summary: "",
    body: "",
    reviewedBy: "e2e-local-operator",
  });
  expect(snapshot.suppressionCount).toBe(1);
  expect(snapshot.audits).toContainEqual(expect.objectContaining({
    action: "memory_candidate.suppressed",
    resourceId: fixture.suppressCandidateId,
    reason,
    details: expect.objectContaining({ doNotRelearn: true }),
    recordHash: expect.stringMatching(/^[a-f0-9]{64}$/u),
  }));
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.inboxEmptyRetry} traverses empty inbox navigation and retries a precise read failure`, async ({ page, browserAudit }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await gotoInbox(page, fixture.emptyMissionId, fixture.emptyRunId);
  await expect(page.getByText("No memories awaiting review", { exact: true })).toBeVisible();
  const navigation = page.getByRole("navigation", { name: "Second Brain", exact: true });
  for (const tab of BRAIN_TABS) {
    await expect(navigation.getByRole("link", { name: tab.name, exact: true })).toHaveAttribute("href", tab.href);
  }

  for (const [index, tab] of BRAIN_TABS.entries()) {
    const link = navigation.getByRole("link", { name: tab.name, exact: true });
    await activate(link, index % 2 === 0 ? "keyboard" : "pointer");
    await expect.poll(() => new URL(page.url()).pathname).toBe(tab.href);
    await expectHeading(page, tab.heading);
    await settle();
    await page.goBack({ waitUntil: "domcontentloaded" });
    await expectHeading(page, "Memory Inbox");
    await expect.poll(() => new URL(page.url()).searchParams.get("runId")).toBe(fixture.emptyRunId);
  }
  await strictAudit(audit, testInfo);

  browserAudit.expectHttpResponse(page, {
    id: "brain.inbox.empty-scope.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: "/api/v2/brain/candidates",
    query: { missionId: fixture.emptyMissionId, runId: fixture.emptyRunId, limit: "50" },
    status: 503,
    occurrences: 1,
    reason: "Exercise the exact-run empty Memory Inbox retry state once.",
  });
  let failed = false;
  await page.route("**/api/v2/brain/candidates?*", async (route) => {
    if (!failed) {
      failed = true;
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify(fixtureError(
          "Memory Inbox could not read its exact-run candidate projection.",
          "Retry after the local candidate projection is available.",
          "trace-brain-inbox-retry",
        )),
      });
      return;
    }
    await route.continue();
  });
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByText("Memory Inbox could not read its exact-run candidate projection.", { exact: true })).toBeVisible();
  await expect(page.getByText("Retry after the local candidate projection is available.", { exact: true })).toBeVisible();
  await expect(page.getByText("Trace trace-brain-inbox-retry", { exact: true })).toBeVisible();

  const retryAudit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const recovered = brainRead(page, "/api/v2/brain/candidates", (url) => url.searchParams.get("runId") === fixture.emptyRunId);
  await activate(page.getByRole("button", { name: "Try again", exact: true }), "keyboard");
  expect((await recovered).status()).toBe(200);
  await expect(page.getByText("No memories awaiting review", { exact: true })).toBeVisible();
  await page.unroute("**/api/v2/brain/candidates?*");
  await strictAudit(retryAudit, testInfo);
});

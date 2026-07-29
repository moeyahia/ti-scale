import { expect, test, type Locator, type Page, type TestInfo } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import {
  createBrainSourceCustodyFixture,
  type BrainSourceCustodyFixture,
} from "./support/brainSourceCustodyFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const NODE_TEST_ID = "e2e.brain-node.private-source-custody";
const GRAPH_TEST_ID = "e2e.brain-graph.private-source-custody";
const PAGINATION_TEST_ID = "e2e.brain-node.provenance-pagination";
let fixture: BrainSourceCustodyFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createBrainSourceCustodyFixture(canonicalFixtureNamespace(testInfo, "brain-source-custody"));
});

async function activate(link: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await link.focus();
    await expect(link).toBeFocused();
    await link.press("Enter");
  } else {
    await link.click();
  }
}

async function returnToSourceNode(page: Page, audit: BrowserAudit): Promise<void> {
  await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
  await expect(page).toHaveURL(`/brain/nodes/${fixture.nodeId}`);
  await expect(page.getByRole("region", { name: "Private source custody", exact: true })).toBeVisible();
}

function sourceGraphUrl(): string {
  return `/brain/graph?${new URLSearchParams({
    view: "local",
    root: fixture.nodeId,
    table: "1",
  }).toString()}`;
}

async function expectSelectedSourceGraph(page: Page): Promise<void> {
  await expect(page).toHaveURL(/\/brain\/graph\?/u);
  const url = new URL(page.url());
  expect(url.pathname).toBe("/brain/graph");
  expect(url.searchParams.get("view")).toBe("local");
  expect(url.searchParams.get("root")).toBe(fixture.nodeId);
  expect(url.searchParams.get("table")).toBe("1");
  expect(url.searchParams.get("selected")).toBe(fixture.nodeId);

  const inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
  await expect(inspector.getByRole("heading", { level: 2, name: fixture.nodeTitle, exact: true })).toBeVisible();
  const relationships = inspector.getByRole("region", {
    name: "Reusable relationships and private custody",
    exact: true,
  });
  await expect(relationships).toContainText("0 backlinks · 0 outgoing · 1 loaded exact private custody binding");
  await expect(relationships).toContainText("No reusable graph edges are recorded.");
  const custody = inspector.getByRole("region", { name: "Private source custody", exact: true });
  await expect(custody).toContainText(fixture.engagementId);
  await expect(custody).toContainText(fixture.privateSourceReference);
  await expect(custody).toContainText("never copied into reusable attack content");
}

async function returnToSourceGraph(page: Page, audit: BrowserAudit): Promise<void> {
  await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
  await expectSelectedSourceGraph(page);
}

async function traverse(
  page: Page,
  audit: BrowserAudit,
  testInfo: TestInfo,
  input: "keyboard" | "pointer",
  name: string,
  href: string,
  assertDestination: () => Promise<void>,
): Promise<void> {
  const custody = page.getByRole("region", { name: "Private source custody", exact: true });
  const link = custody.getByRole("link", { name, exact: true });
  await expect(link).toHaveAttribute("href", href);
  await activate(link, input);
  await expect(page).toHaveURL(href);
  await assertDestination();
  await returnToSourceNode(page, audit);
  expect(audit.unexpected, `${input} traversal produced unexpected browser failures`).toEqual([]);
  expect(audit.degradedApi, `${input} traversal degraded a required V2 API`).toEqual([]);
  await audit.assertClean(testInfo);
}

async function traverseFromGraph(
  page: Page,
  audit: BrowserAudit,
  testInfo: TestInfo,
  input: "keyboard" | "pointer",
  name: string,
  href: string,
  assertDestination: () => Promise<void>,
): Promise<void> {
  const inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
  const custody = inspector.getByRole("region", { name: "Private source custody", exact: true });
  const link = custody.getByRole("link", { name, exact: true });
  await expect(link).toHaveAttribute("href", href);
  await activate(link, input);
  await expect(page).toHaveURL(href);
  await assertDestination();
  await returnToSourceGraph(page, audit);
  expect(audit.unexpected, `${input} graph-inspector traversal produced unexpected browser failures`).toEqual([]);
  expect(audit.degradedApi, `${input} graph-inspector traversal degraded a required V2 API`).toEqual([]);
  await audit.assertClean(testInfo);
}

test(`${NODE_TEST_ID} keeps private custody attributable and traverses every canonical relation`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const detailRead = page.waitForResponse((response) => response.request().method() === "GET"
    && new URL(response.url()).pathname === `/api/v2/brain/nodes/${fixture.nodeId}`
    && response.status() === 200);
  await page.goto(`/brain/nodes/${fixture.nodeId}`, { waitUntil: "domcontentloaded" });
  expect((await detailRead).status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1, name: fixture.nodeTitle, exact: true })).toBeVisible();
  const custody = page.getByRole("region", { name: "Private source custody", exact: true });
  await expect(custody).toContainText(fixture.engagementId);
  await expect(custody).toContainText(fixture.privateSourceReference);
  await expect(custody).toContainText("never copied into reusable attack content");

  for (const input of ["pointer", "keyboard"] as const) {
    await traverse(
      page,
      audit,
      testInfo,
      input,
      fixture.missionName,
      `/missions/${fixture.missionId}`,
      async () => {
        await expect(page.getByRole("heading", { level: 1, name: fixture.missionName, exact: true })).toBeVisible();
      },
    );
    await traverse(
      page,
      audit,
      testInfo,
      input,
      fixture.runId,
      `/missions/${fixture.missionId}/runs/${fixture.runId}`,
      async () => {
        await expect(page.getByRole("heading", { level: 1, name: fixture.missionName, exact: true })).toBeVisible();
      },
    );
    await traverse(
      page,
      audit,
      testInfo,
      input,
      fixture.artifactId,
      `/intelligence/artifacts/${fixture.artifactId}`,
      async () => {
        await expect(page.getByRole("heading", { level: 1, name: "Evidence, findings, and artifacts", exact: true })).toBeVisible();
        await expect(page.getByText(fixture.artifactId, { exact: true })).toBeVisible();
      },
    );
    await traverse(
      page,
      audit,
      testInfo,
      input,
      fixture.evidenceId,
      `/intelligence/evidence/${fixture.evidenceId}`,
      async () => {
        await expect(page.getByRole("heading", { level: 1, name: "Evidence, findings, and artifacts", exact: true })).toBeVisible();
        await expect(page.getByRole("heading", { level: 2, name: fixture.evidenceSummary, exact: true })).toBeVisible();
      },
    );
    await traverse(
      page,
      audit,
      testInfo,
      input,
      fixture.privateSourceReference,
      `/intelligence/artifacts/${fixture.artifactId}`,
      async () => {
        await expect(page.getByRole("heading", { level: 1, name: "Evidence, findings, and artifacts", exact: true })).toBeVisible();
        await expect(page.getByText(fixture.artifactId, { exact: true })).toBeVisible();
      },
    );
  }
  await audit.assertClean(testInfo);
});

test(`${PAGINATION_TEST_ID} loads bounded provenance and private custody with pointer and keyboard`, async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });

  for (const input of ["pointer", "keyboard"] as const) {
    const detailRead = page.waitForResponse((response) => response.request().method() === "GET"
      && new URL(response.url()).pathname === `/api/v2/brain/nodes/${fixture.paginationNodeId}`
      && response.status() === 200);
    await page.goto(`/brain/nodes/${fixture.paginationNodeId}`, { waitUntil: "domcontentloaded" });
    const detailResponse = await detailRead;
    const detail = await detailResponse.json() as {
      sources: Array<{ sourceRecordId: string; origins?: unknown[]; originCount: number }>;
      sourcesNextCursor: string;
      node: { sourceCount: number };
    };
    expect(detail.node.sourceCount).toBe(fixture.paginationSourceCount);
    expect(detail.sources).toHaveLength(25);
    expect(detail.sources[0]?.origins).toHaveLength(50);
    expect(detail.sources[0]?.originCount).toBe(fixture.paginationOriginCount);
    expect(detail.sourcesNextCursor).toBeTruthy();

    await expect(page.getByRole("heading", {
      level: 1,
      name: fixture.paginationNodeTitle,
      exact: true,
    })).toBeVisible();
    await expect(page.getByText(
      `Showing 25 of ${fixture.paginationSourceCount} canonical source records.`,
      { exact: true },
    )).toBeVisible();

    const firstSource = page.locator(".brain-provenance-list > li").first();
    await expect(firstSource.getByRole("region", { name: "Private source custody", exact: true }))
      .toContainText(`50 of ${fixture.paginationOriginCount} exact bindings`);

    const sourcePagePath = `/api/v2/brain/nodes/${fixture.paginationNodeId}/sources`;
    let releaseSource!: () => void;
    const sourceHold = new Promise<void>((resolve) => { releaseSource = resolve; });
    await page.route(`**${sourcePagePath}?*`, async (route) => {
      const upstream = await route.fetch();
      await sourceHold;
      await route.fulfill({ response: upstream });
    }, { times: 1 });
    const sourcePageRead = page.waitForResponse((response) => response.request().method() === "GET"
      && new URL(response.url()).pathname === sourcePagePath
      && response.status() === 200);
    const sourceButton = page.getByRole("button", { name: "Load more provenance", exact: true });
    await activate(sourceButton, input);
    await expect(page.getByRole("button", { name: "Loading more provenance…", exact: true })).toBeDisabled();
    releaseSource();
    const sourcePage = await (await sourcePageRead).json() as { items: unknown[]; nextCursor: null };
    expect(sourcePage.items).toHaveLength(fixture.paginationSourceCount - 25);
    expect(sourcePage.nextCursor).toBeNull();
    await expect(page.getByText(
      `Showing ${fixture.paginationSourceCount} of ${fixture.paginationSourceCount} canonical source records.`,
      { exact: true },
    )).toBeVisible();
    await expect(page.getByRole("button", { name: "Load more provenance", exact: true })).toHaveCount(0);

    const sourceRecordId = detail.sources[0]!.sourceRecordId;
    const originPagePath = `/api/v2/brain/nodes/${fixture.paginationNodeId}/sources/${sourceRecordId}/origins`;
    let releaseOrigins!: () => void;
    const originHold = new Promise<void>((resolve) => { releaseOrigins = resolve; });
    await page.route(`**${originPagePath}?*`, async (route) => {
      const upstream = await route.fetch();
      await originHold;
      await route.fulfill({ response: upstream });
    }, { times: 1 });
    const originPageRead = page.waitForResponse((response) => response.request().method() === "GET"
      && new URL(response.url()).pathname === originPagePath
      && response.status() === 200);
    const originButton = firstSource.getByRole("button", {
      name: `Load more private custody (50 of ${fixture.paginationOriginCount})`,
      exact: true,
    });
    await activate(originButton, input);
    await expect(firstSource.getByRole("button", { name: "Loading custody…", exact: true })).toBeDisabled();
    releaseOrigins();
    const originPage = await (await originPageRead).json() as { items: unknown[]; nextCursor: null };
    expect(originPage.items).toHaveLength(fixture.paginationOriginCount - 50);
    expect(originPage.nextCursor).toBeNull();
    await expect(firstSource.getByRole("region", { name: "Private source custody", exact: true }))
      .toContainText(`Private source custody · ${fixture.paginationOriginCount} exact bindings`);
    await expect(firstSource.getByRole("button", { name: /Load more private custody/u })).toHaveCount(0);
  }

  await audit.waitForPageApiSettlement(page, { quietMs: 750 });
  expect(audit.unexpected).toEqual([]);
  expect(audit.degradedApi).toEqual([]);
  await audit.assertClean(testInfo);
});

test(`${PAGINATION_TEST_ID} preserves loaded provenance after a precise retryable page error`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const detailRead = page.waitForResponse((response) => response.request().method() === "GET"
    && new URL(response.url()).pathname === `/api/v2/brain/nodes/${fixture.paginationNodeId}`
    && response.status() === 200);
  await page.goto(`/brain/nodes/${fixture.paginationNodeId}`, { waitUntil: "domcontentloaded" });
  const detail = await (await detailRead).json() as { sourcesNextCursor: string };
  expect(detail.sourcesNextCursor).toBeTruthy();

  const sourcePagePath = `/api/v2/brain/nodes/${fixture.paginationNodeId}/sources`;
  audit.expectHttpResponse({
    id: "brain-node-provenance-page-temporary-failure",
    transport: "browser",
    method: "GET",
    pathname: sourcePagePath,
    query: { cursor: detail.sourcesNextCursor, limit: "25" },
    status: 503,
    occurrences: 1,
    reason: "Prove a bounded provenance read failure preserves the loaded first page and remains retryable.",
  });
  await page.route(`**${sourcePagePath}?*`, async (route) => {
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "brain_provenance_temporarily_unavailable",
          message: "Additional provenance is temporarily unavailable. Retry the same bounded provenance page.",
          humanMessage: "Additional provenance is temporarily unavailable.",
          retryable: true,
          category: "dependency_unavailable",
          details: {},
          traceId: "trace-brain-provenance-page",
          remediation: "Retry the same bounded provenance page.",
          timestamp: "2099-07-21T12:35:00.000Z",
        },
      }),
    });
  }, { times: 1 });

  const failedRead = page.waitForResponse((response) => response.request().method() === "GET"
    && new URL(response.url()).pathname === sourcePagePath
    && response.status() === 503);
  await activate(page.getByRole("button", { name: "Load more provenance", exact: true }), "pointer");
  expect((await failedRead).status()).toBe(503);
  await expect(page.getByRole("alert")).toContainText("Additional provenance is temporarily unavailable.");
  await expect(page.getByText(
    `Showing 25 of ${fixture.paginationSourceCount} canonical source records.`,
    { exact: true },
  )).toBeVisible();

  const retryRead = page.waitForResponse((response) => response.request().method() === "GET"
    && new URL(response.url()).pathname === sourcePagePath
    && response.status() === 200);
  await activate(page.getByRole("button", { name: "Load more provenance", exact: true }), "keyboard");
  expect((await retryRead).status()).toBe(200);
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.getByText(
    `Showing ${fixture.paginationSourceCount} of ${fixture.paginationSourceCount} canonical source records.`,
    { exact: true },
  )).toBeVisible();

  await audit.waitForPageApiSettlement(page, { quietMs: 750 });
  await audit.assertClean(testInfo);
});

test(`${GRAPH_TEST_ID} selects the source node and traverses every private custody relation from the graph inspector`, async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });

  for (const input of ["pointer", "keyboard"] as const) {
    const graphRead = page.waitForResponse((response) => {
      if (response.request().method() !== "GET" || response.status() !== 200) return false;
      const url = new URL(response.url());
      return url.pathname === "/api/v2/brain/graph"
        && url.searchParams.get("view") === "local"
        && url.searchParams.get("nodeId") === fixture.nodeId;
    });
    await page.goto(sourceGraphUrl(), { waitUntil: "domcontentloaded" });
    expect((await graphRead).status()).toBe(200);

    const table = page.getByRole("table", { name: "Accessible memory graph node list", exact: true });
    const sourceRow = table.getByRole("row").filter({ hasText: fixture.nodeTitle });
    await expect(sourceRow).toHaveCount(1);
    await activate(sourceRow.getByRole("button", { name: "Inspect", exact: true }), input);
    await expectSelectedSourceGraph(page);

    await traverseFromGraph(
      page,
      audit,
      testInfo,
      input,
      fixture.missionName,
      `/missions/${fixture.missionId}`,
      async () => {
        await expect(page.getByRole("heading", { level: 1, name: fixture.missionName, exact: true })).toBeVisible();
      },
    );
    await traverseFromGraph(
      page,
      audit,
      testInfo,
      input,
      fixture.runId,
      `/missions/${fixture.missionId}/runs/${fixture.runId}`,
      async () => {
        await expect(page.getByRole("heading", { level: 1, name: fixture.missionName, exact: true })).toBeVisible();
      },
    );
    await traverseFromGraph(
      page,
      audit,
      testInfo,
      input,
      fixture.artifactId,
      `/intelligence/artifacts/${fixture.artifactId}`,
      async () => {
        await expect(page.getByRole("heading", { level: 1, name: "Evidence, findings, and artifacts", exact: true })).toBeVisible();
        await expect(page.getByText(fixture.artifactId, { exact: true })).toBeVisible();
      },
    );
    await traverseFromGraph(
      page,
      audit,
      testInfo,
      input,
      fixture.evidenceId,
      `/intelligence/evidence/${fixture.evidenceId}`,
      async () => {
        await expect(page.getByRole("heading", { level: 1, name: "Evidence, findings, and artifacts", exact: true })).toBeVisible();
        await expect(page.getByRole("heading", { level: 2, name: fixture.evidenceSummary, exact: true })).toBeVisible();
      },
    );
    await traverseFromGraph(
      page,
      audit,
      testInfo,
      input,
      fixture.privateSourceReference,
      `/intelligence/artifacts/${fixture.artifactId}`,
      async () => {
        await expect(page.getByRole("heading", { level: 1, name: "Evidence, findings, and artifacts", exact: true })).toBeVisible();
        await expect(page.getByText(fixture.artifactId, { exact: true })).toBeVisible();
      },
    );
  }

  await audit.assertClean(testInfo);
});

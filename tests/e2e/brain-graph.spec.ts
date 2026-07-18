import {
  expect,
  test,
  type Locator,
  type Page,
  type Response,
  type Route,
  type TestInfo,
} from "./support/playwright";
import {
  MEMORY_EDGE_TYPES,
  MEMORY_LIFECYCLE_STATES,
  MEMORY_NODE_TYPES,
  MEMORY_SENSITIVITIES,
  type MemoryGraph,
} from "../../src/domain/types/brain";
import { collapseGraphClusters, layoutGraph } from "../../src/features/brain/graphUtils";
import { BROWSER_STORAGE_KEYS } from "../../src/lib/browserNamespaces";
import { BrowserAudit } from "./support/browserAudit";
import {
  BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT,
  createBrainGraphFixture,
  readBrainGraphFixtureState,
  type BrainGraphFixture,
} from "./support/brainGraphFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_IDS = {
  globalEmptyInbox: "e2e.brain-graph.global-empty-inbox",
  disconnectedTruth: "e2e.brain-graph.disconnected-truth",
  errorEmptyRetry: "e2e.brain-graph.error-empty-retry",
  controlsFiltersViews: "e2e.brain-graph.controls-filters-views",
  canvasTableInspector: "e2e.brain-graph.canvas-table-inspector",
  visualCanvasTable: "e2e.brain-graph.visual-canvas-table",
  deepLinksHistory: "e2e.brain-graph.deep-links-history",
} as const;
const GRAPH_API_PATH = "/api/v2/brain/graph";
const FIXTURE_DAY = "2099-07-16";
const VISUAL_PROJECT = "chromium-1440";
const GRAPH_VISUALS = {
  canvas: {
    id: "visual.second-brain.graph-canvas.chromium-1440",
    snapshot: "second-brain-graph-canvas.png",
  },
  table: {
    id: "visual.second-brain.graph-table.chromium-1440",
    snapshot: "second-brain-graph-table.png",
  },
} as const;

let fixture: BrainGraphFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createBrainGraphFixture(canonicalFixtureNamespace(testInfo, "brain-graph"));
});

function graphRoute(parameters: Record<string, string | undefined> = {}): string {
  const query = new URLSearchParams({ engagement: fixture.engagementId, ...Object.fromEntries(
    Object.entries(parameters).filter((entry): entry is [string, string] => entry[1] !== undefined),
  ) });
  return `/brain/graph?${query.toString()}`;
}

function pathname(response: Response): string {
  return new URL(response.url()).pathname;
}

function graphResponse(
  page: Page,
  predicate: (url: URL) => boolean = () => true,
): Promise<Response> {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET"
      && url.pathname === GRAPH_API_PATH
      && response.status() === 200
      && predicate(url);
  });
}

async function graphPayload(response: Response): Promise<MemoryGraph> {
  expect(response.status(), await response.text()).toBe(200);
  const payload = await response.json() as MemoryGraph | { readonly data: MemoryGraph };
  return "data" in payload ? payload.data : payload;
}

async function activate(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await control.press("Enter");
  } else {
    await control.click();
  }
}

async function openAdvanced(page: Page, input: "keyboard" | "pointer" = "pointer"): Promise<Locator> {
  const details = page.locator("details.brain-graph-advanced");
  if (!await details.evaluate((node) => (node as HTMLDetailsElement).open)) {
    await activate(details.locator("summary"), input);
  }
  await expect(details).toHaveJSProperty("open", true);
  return details;
}

async function waitForCanvas(page: Page): Promise<Locator> {
  const canvas = page.getByRole("application", { name: /^Memory graph with/u });
  await expect(canvas).toBeVisible();
  await expect(canvas).toHaveAttribute("aria-busy", "false", { timeout: 15_000 });
  await expect.poll(() => canvas.evaluate((element) => {
    const target = element as HTMLCanvasElement;
    const rect = target.getBoundingClientRect();
    const ratio = Math.min(2, window.devicePixelRatio || 1);
    return Math.abs(target.width / ratio - rect.width) < 2
      && Math.abs(target.height / ratio - rect.height) < 2;
  })).toBe(true);
  return canvas;
}

async function expectApprovedGraphVisual(
  locator: Locator,
  testInfo: TestInfo,
  baseline: (typeof GRAPH_VISUALS)[keyof typeof GRAPH_VISUALS],
): Promise<void> {
  if (testInfo.project.name !== VISUAL_PROJECT) return;
  await locator.page().evaluate(async () => { await document.fonts.ready; });
  await expect(locator).toHaveScreenshot(baseline.snapshot, {
    animations: "disabled",
    caret: "hide",
    maxDiffPixels: 0,
    threshold: 0.15,
  });
}

async function strictAudit(audit: BrowserAudit, testInfo: TestInfo): Promise<void> {
  expect(audit.unexpected, "Unexpected browser failures").toEqual([]);
  expect(audit.degradedApi, "Required V2 API requests must not degrade").toEqual([]);
  await audit.assertClean(testInfo);
}

async function optionValues(control: Locator): Promise<string[]> {
  await expect(control).toBeVisible();
  await expect(control.locator("option").first()).toBeAttached();
  return control.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value));
}

async function selectAndAssertGraphFilter(
  page: Page,
  control: Locator,
  option: string,
  apiParameter: string,
  apiValue: string,
  assertion: (payload: MemoryGraph) => void,
): Promise<void> {
  const filtered = graphResponse(page, (url) => url.searchParams.get(apiParameter) === apiValue);
  await control.selectOption(option);
  assertion(await graphPayload(await filtered));
  await control.selectOption("");
  await expect(control).toHaveValue("");
  await expect(page.getByRole("heading", { name: "Memory Graph", exact: true })).toBeVisible();
}

async function selectPreferenceInTable(page: Page, input: "keyboard" | "pointer"): Promise<void> {
  if (await page.getByRole("button", { name: "Accessible table", exact: true }).count()) {
    await activate(page.getByRole("button", { name: "Accessible table", exact: true }), input);
  }
  const table = page.getByRole("table", { name: "Accessible memory graph node list", exact: true });
  await expect(table).toBeVisible();
  const row = table.getByRole("row").filter({ hasText: fixture.preferenceTitle });
  await activate(row.getByRole("button", { name: "Inspect", exact: true }), input);
  await expect.poll(() => new URL(page.url()).searchParams.get("selected")).toBe(fixture.preferenceNodeId);
  await expect(page.getByRole("complementary", { name: "Selected memory details", exact: true })
    .getByRole("heading", { name: fixture.preferenceTitle, exact: true })).toBeVisible();
}

async function expectedError(route: Route): Promise<void> {
  await route.fulfill({
    status: 503,
    contentType: "application/json",
    body: JSON.stringify({
      error: {
        code: "brain_graph_fixture_temporarily_unavailable",
        message: "brain graph fixture temporarily unavailable",
        humanMessage: "The bounded memory graph could not be read from the canonical fixture store.",
        retryable: true,
        category: "dependency",
        remediation: "Retry this exact graph view after the local store is available; no memory content was inferred.",
        traceId: "trace-brain-graph-fixture",
        timestamp: "2099-07-16T12:00:00.000Z",
      },
    }),
  });
}

test(`${TEST_IDS.globalEmptyInbox} renders the canonical empty graph and opens the Memory Inbox`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const emptyGraph = {
    schemaVersion: "2.4",
    view: "global",
    nodes: [],
    edges: [],
    availableNodeCount: 0,
    truncated: false,
  } satisfies MemoryGraph;
  const emptyGraphFixture = async (route: Route): Promise<void> => {
    await route.fulfill({
      status: 200,
      contentType: "application/json; charset=utf-8",
      body: JSON.stringify(emptyGraph),
    });
  };
  await page.route("**/api/v2/brain/graph?*", emptyGraphFixture);
  try {
    const graphRead = graphResponse(page, (url) => url.searchParams.get("view") === "global");
    await page.goto("/brain/graph", { waitUntil: "domcontentloaded" });
    expect(await graphPayload(await graphRead)).toEqual(emptyGraph);
    await expect(page.getByText("The Second Brain is empty", { exact: true })).toBeVisible();
    const inbox = page.getByRole("link", { name: "Open Memory Inbox", exact: true });
    await expect(inbox).toHaveAttribute("href", "/brain/inbox");
    await activate(inbox, "keyboard");
    await expect(page).toHaveURL("/brain/inbox");
    await expect(page.getByRole("heading", { level: 1, name: "Memory Inbox", exact: true })).toBeVisible();
    await strictAudit(audit, testInfo);
  } finally {
    await page.unroute("**/api/v2/brain/graph?*", emptyGraphFixture);
  }
});

test(`${TEST_IDS.disconnectedTruth} explains isolated canonical nodes instead of implying a rendered relationship`, async ({ page }, testInfo) => {
  const disconnectedFixture = async (route: Route): Promise<void> => {
    const response = await route.fetch();
    const payload = await response.json() as MemoryGraph | { readonly data: MemoryGraph };
    const graph = "data" in payload ? payload.data : payload;
    const disconnected = { ...graph, edges: [] } satisfies MemoryGraph;
    await route.fulfill({
      response,
      contentType: "application/json; charset=utf-8",
      body: JSON.stringify("data" in payload ? { ...payload, data: disconnected } : disconnected),
    });
  };
  await page.route("**/api/v2/brain/graph?*", disconnectedFixture);
  try {
    const graphRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId
      && url.searchParams.get("limit") === "500");
    await page.goto(graphRoute({ limit: "500" }), { waitUntil: "domcontentloaded" });
    const graph = await graphPayload(await graphRead);
    expect(graph.nodes.length).toBeGreaterThan(1);
    expect(graph.edges).toEqual([]);
    await expect(page.getByText("0 visible relationships", { exact: true })).toBeVisible();
    await expect(page.getByRole("status").filter({ hasText: "These memories are currently isolated" })).toContainText(
      "Ti-Scale will keep them separate until an import, mission event, or operator-reviewed link provides real provenance.",
    );
    await strictAudit(new BrowserAudit(page, { allowEventStreamNavigationAbort: true }), testInfo);
  } finally {
    await page.unroute("**/api/v2/brain/graph?*", disconnectedFixture);
  }
});

test(`${TEST_IDS.errorEmptyRetry} explains a failed canonical read, retries it, and recovers an empty filtered graph`, async ({ page, browserAudit }, testInfo) => {
  browserAudit.expectHttpResponse(page, {
    id: "brain.graph.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: GRAPH_API_PATH,
    query: { view: "global", depth: "2", limit: String(BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT), engagementId: fixture.engagementId },
    status: 503,
    occurrences: 1,
    reason: "Exercise the exact bounded-graph retry state once.",
  });
  let firstRead = true;
  await page.route("**/api/v2/brain/graph?*", async (route) => {
    if (firstRead) {
      firstRead = false;
      await expectedError(route);
      return;
    }
    await route.continue();
  });

  await page.goto(graphRoute(), { waitUntil: "domcontentloaded" });
  const alert = page.getByRole("alert").filter({ hasText: "Live data is unavailable" });
  await expect(alert).toContainText("The bounded memory graph could not be read from the canonical fixture store.");
  await expect(alert).toContainText("Retry this exact graph view after the local store is available; no memory content was inferred.");

  const recovered = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId);
  await activate(alert.getByRole("button", { name: "Try again", exact: true }), "keyboard");
  const recoveredPayload = await graphPayload(await recovered);
  expect(recoveredPayload.nodes).toHaveLength(BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT);
  expect(recoveredPayload.truncated).toBe(true);
  await expect(page.getByText(`${BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT} visible of ${BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const advanced = await openAdvanced(page);
  const absentEngagement = `${fixture.engagementId}-absent`;
  const emptyRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === absentEngagement);
  await advanced.getByLabel("Engagement ID", { exact: true }).fill(absentEngagement);
  expect((await graphPayload(await emptyRead)).nodes).toEqual([]);
  await expect(page.getByText("No memories match this graph view", { exact: true })).toBeVisible();
  await expect(page.getByText(/No accessible canonical memory nodes match these filters/u)).toBeVisible();

  const unfilteredRead = graphResponse(page, (url) => !url.searchParams.has("engagementId"));
  await activate(page.locator(".brain-empty").getByRole("button", { name: "Reset graph view", exact: true }), "pointer");
  expect((await graphPayload(await unfilteredRead)).nodes.length).toBeGreaterThan(0);
  await waitForCanvas(page);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.controlsFiltersViews} exercises progressive loading, every graph view, filter, cluster, display control, and named view`, async ({ page, context }, testInfo) => {
  test.setTimeout(180_000);
  const initialRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId
    && url.searchParams.get("limit") === String(BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT));
  await page.goto(graphRoute(), { waitUntil: "domcontentloaded" });
  const initial = await graphPayload(await initialRead);
  expect(initial.nodes).toHaveLength(BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT);
  expect(initial.truncated).toBe(true);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });

  const local = page.getByRole("button", { name: "Local", exact: true });
  await expect(local).toBeDisabled();
  const expandedRead = graphResponse(page, (url) => url.searchParams.get("limit") === "500"
    && url.searchParams.get("engagementId") === fixture.engagementId);
  await activate(page.getByRole("button", { name: "Load another bounded segment", exact: true }), "pointer");
  const expanded = await graphPayload(await expandedRead);
  expect(expanded.nodes).toHaveLength(fixture.nodeCount);
  expect(expanded.truncated).toBe(false);
  await expect(page.getByRole("button", { name: "Load another bounded segment", exact: true })).toHaveCount(0);

  const missionButton = page.getByRole("button", { name: "Mission", exact: true });
  await activate(missionButton, "keyboard");
  await expect(page.getByText("Enter a mission ID to load its isolated cluster.", { exact: false })).toBeVisible();
  const missionRead = graphResponse(page, (url) => url.searchParams.get("view") === "mission"
    && url.searchParams.get("missionId") === fixture.missionId);
  await page.getByLabel("Mission ID", { exact: true }).fill(fixture.missionId);
  const missionGraph = await graphPayload(await missionRead);
  expect(missionGraph.view).toBe("mission");
  expect(missionGraph.nodes.some((node) => node.id === fixture.missionId)).toBe(true);

  await activate(page.getByRole("button", { name: "Global", exact: true }), "pointer");
  await expect(page.getByRole("button", { name: "Global", exact: true })).toHaveClass(/is-active/u);
  await expect(page.getByText(`${fixture.nodeCount} visible of ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

  const operatorRead = graphResponse(page, (url) => url.searchParams.get("view") === "operator");
  await activate(page.getByRole("button", { name: "Operator profile", exact: true }), "keyboard");
  const operatorGraph = await graphPayload(await operatorRead);
  expect(operatorGraph.nodes.map((node) => node.nodeType).sort()).toEqual(["operator", "preference"]);

  const attackRead = graphResponse(page, (url) => url.searchParams.get("preset") === "attack_path");
  await activate(page.getByRole("button", { name: "Attack path", exact: true }), "pointer");
  const attackGraph = await graphPayload(await attackRead);
  expect(attackGraph.nodes.some((node) => node.nodeType === "technique")).toBe(true);
  expect(attackGraph.nodes.every((node) => node.nodeType !== "preference")).toBe(true);

  const lessonsRead = graphResponse(page, (url) => url.searchParams.get("preset") === "lessons_failures");
  await activate(page.getByRole("button", { name: "Lessons & failures", exact: true }), "keyboard");
  const lessonsGraph = await graphPayload(await lessonsRead);
  expect(lessonsGraph.nodes.some((node) => node.nodeType === "lesson")).toBe(true);
  expect(lessonsGraph.nodes.some((node) => node.nodeType === "failure")).toBe(true);

  await activate(page.getByRole("button", { name: "Global", exact: true }), "pointer");
  await expect.poll(() => new URL(page.url()).searchParams.get("preset")).toBeNull();
  await expect(page.getByText(`${fixture.nodeCount} visible of ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

  const search = page.getByLabel("Search visible graph", { exact: true });
  await search.fill(fixture.operatorTitle);
  await expect(page.getByText(`1 visible of ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();
  await search.fill("");
  await expect(page.getByText(`${fixture.nodeCount} visible of ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

  expect(await optionValues(page.getByRole("combobox", { name: "Edge type", exact: true }))).toEqual(["", ...MEMORY_EDGE_TYPES]);
  await selectAndAssertGraphFilter(
    page,
    page.getByRole("combobox", { name: "Edge type", exact: true }),
    "supports",
    "edgeType",
    "supports",
    (payload) => {
      expect(payload.nodes.length).toBeGreaterThan(0);
      expect(payload.edges.every((edge) => edge.edgeType === "supports")).toBe(true);
    },
  );

  const advanced = await openAdvanced(page, "keyboard");
  expect(await optionValues(advanced.getByRole("combobox", { name: "Node type", exact: true }))).toEqual(["", ...MEMORY_NODE_TYPES]);
  expect(await optionValues(advanced.getByRole("combobox", { name: "Scope", exact: true }))).toEqual(["", "global", "engagement", "mission"]);
  expect(await optionValues(advanced.getByRole("combobox", { name: "Lifecycle", exact: true }))).toEqual([
    "",
    ...MEMORY_LIFECYCLE_STATES.filter((state) => state !== "forgotten"),
  ]);
  expect(await optionValues(advanced.getByRole("combobox", { name: "Sensitivity", exact: true }))).toEqual(["", ...MEMORY_SENSITIVITIES]);
  expect(await optionValues(advanced.getByRole("combobox", { name: "Minimum confidence", exact: true }))).toEqual(["", "0.25", "0.5", "0.75", "0.9"]);
  expect(await optionValues(advanced.getByRole("combobox", { name: "Label density", exact: true }))).toEqual(["minimal", "balanced", "all"]);
  await selectAndAssertGraphFilter(page, advanced.getByRole("combobox", { name: "Node type", exact: true }), "failure", "nodeType", "failure", (payload) => {
    expect(payload.nodes.length).toBeGreaterThan(0);
    expect(payload.nodes.every((node) => node.nodeType === "failure")).toBe(true);
  });
  await selectAndAssertGraphFilter(page, advanced.getByRole("combobox", { name: "Scope", exact: true }), "mission", "scope", "mission", (payload) => {
    expect(payload.nodes.length).toBeGreaterThan(0);
    expect(payload.nodes.every((node) => node.scope.kind === "mission")).toBe(true);
  });
  await selectAndAssertGraphFilter(page, advanced.getByRole("combobox", { name: "Lifecycle", exact: true }), "disputed", "status", "disputed", (payload) => {
    expect(payload.nodes.length).toBeGreaterThan(0);
    expect(payload.nodes.every((node) => node.lifecycleStatus === "disputed")).toBe(true);
  });
  await selectAndAssertGraphFilter(page, advanced.getByRole("combobox", { name: "Sensitivity", exact: true }), "restricted", "sensitivity", "restricted", (payload) => {
    expect(payload.nodes.length).toBeGreaterThan(0);
    expect(payload.nodes.every((node) => node.sensitivity === "restricted")).toBe(true);
  });
  await selectAndAssertGraphFilter(page, advanced.getByRole("combobox", { name: "Minimum confidence", exact: true }), "0.9", "minConfidence", "0.9", (payload) => {
    expect(payload.nodes.length).toBeGreaterThan(0);
    expect(payload.nodes.every((node) => node.confidence >= 0.9)).toBe(true);
  });

  const fromRead = graphResponse(page, (url) => url.searchParams.get("updatedAfter") === `${FIXTURE_DAY}T00:00:00.000Z`);
  await advanced.getByLabel("Updated from", { exact: true }).fill(FIXTURE_DAY);
  expect((await graphPayload(await fromRead)).nodes.length).toBe(fixture.nodeCount);
  const throughRead = graphResponse(page, (url) => url.searchParams.get("updatedBefore") === `${FIXTURE_DAY}T23:59:59.999Z`);
  await advanced.getByLabel("Updated through", { exact: true }).fill(FIXTURE_DAY);
  expect((await graphPayload(await throughRead)).nodes.length).toBe(fixture.nodeCount);
  const clearFrom = graphResponse(page, (url) => !url.searchParams.has("updatedAfter") && url.searchParams.has("updatedBefore"));
  await advanced.getByLabel("Updated from", { exact: true }).fill("");
  await graphPayload(await clearFrom);
  await advanced.getByLabel("Updated through", { exact: true }).fill("");
  await expect(advanced.getByLabel("Updated through", { exact: true })).toHaveValue("");
  await expect(page.getByText(`${fixture.nodeCount} visible of ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

  const engagementInput = advanced.getByLabel("Engagement ID", { exact: true });
  const missingEngagement = `${fixture.engagementId}-missing`;
  const missingRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === missingEngagement);
  await engagementInput.fill(missingEngagement);
  expect((await graphPayload(await missingRead)).nodes).toEqual([]);
  await engagementInput.fill(fixture.engagementId);
  await expect(page.getByText(`${fixture.nodeCount} visible of ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

  const labels = advanced.getByRole("combobox", { name: "Label density", exact: true });
  await labels.selectOption("minimal");
  await expect(page.getByText("minimal labels", { exact: true })).toBeVisible();
  await labels.selectOption("all");
  await expect(page.getByText("all labels", { exact: true })).toBeVisible();
  await labels.selectOption("balanced");
  await expect(page.getByText("balanced labels", { exact: true })).toBeVisible();

  const layout = page.getByRole("button", { name: "Layout: clusters", exact: true });
  await activate(layout, "keyboard");
  await expect(page.getByRole("button", { name: "Layout: compact", exact: true })).toBeVisible();
  await activate(page.getByRole("button", { name: "Layout: compact", exact: true }), "pointer");
  await expect(page.getByRole("button", { name: "Layout: clusters", exact: true })).toBeVisible();
  const physics = page.getByRole("button", { name: "Physics: fixed clusters", exact: true });
  await activate(physics, "pointer");
  await expect(page.getByRole("button", { name: "Physics: relationship weighted", exact: true })).toHaveAttribute("aria-pressed", "true");
  await waitForCanvas(page);
  await activate(page.getByRole("button", { name: "Physics: relationship weighted", exact: true }), "keyboard");
  await expect(page.getByRole("button", { name: "Physics: fixed clusters", exact: true })).toHaveAttribute("aria-pressed", "false");

  for (const [index, cluster] of ["Operator", "Mission", "Attack", "Tool", "Evidence", "Agent", "Failure", "Lesson"].entries()) {
    const collapse = page.getByRole("button", { name: new RegExp(`^Collapse ${cluster} \\(`, "u") });
    await activate(collapse, index % 2 === 0 ? "pointer" : "keyboard");
    const expand = page.getByRole("button", { name: new RegExp(`^Expand ${cluster} \\(`, "u") });
    await expect(expand).toHaveAttribute("aria-pressed", "true");
    if (cluster === "Operator") {
      const canvas = await waitForCanvas(page);
      const box = await canvas.boundingBox();
      if (!box) throw new Error("The collapsed graph canvas has no measurable bounds");
      const projection = collapseGraphClusters(expanded.nodes, expanded.edges, new Set(["operator"]));
      const point = layoutGraph(projection.nodes, Math.floor(box.width), Math.floor(box.height))
        .find((item) => item.id === "cluster:operator");
      if (!point) throw new Error("The collapsed operator cluster was not projected to the canvas");
      await canvas.click({ position: { x: point.x, y: point.y }, force: true });
    } else {
      await activate(expand, index % 2 === 0 ? "keyboard" : "pointer");
    }
    await expect(page.getByRole("button", { name: new RegExp(`^Collapse ${cluster} \\(`, "u") })).toHaveAttribute("aria-pressed", "false");
  }

  try {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  } catch {
    // WebKit may decline an explicit clipboard permission grant. The product
    // exposes a truthful denied-state message and remains usable.
  }
  await activate(page.getByRole("button", { name: "Copy shareable link", exact: true }), "pointer");
  await expect(page.getByRole("status").filter({ hasText: /Shareable graph link copied|Clipboard access was denied/u })).toBeVisible();

  await search.fill(fixture.operatorTitle);
  await labels.selectOption("all");
  const name = `Evidence-first graph ${fixture.namespace}`;
  const viewName = page.getByLabel("View name", { exact: true });
  await viewName.fill(name);
  await activate(page.getByRole("button", { name: "Save current", exact: true }), "keyboard");
  await expect(page.locator(".brain-graph-notice")).toContainText(`Saved “${name}” in this browser.`);
  await expect(page.getByRole("button", { name, exact: true })).toBeVisible();

  const resetRead = graphResponse(page, (url) => !url.searchParams.has("engagementId") && url.searchParams.get("limit") === String(BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT));
  await activate(page.getByRole("button", { name: "Reset graph view", exact: true }), "keyboard");
  await graphPayload(await resetRead);
  await activate(page.getByRole("button", { name, exact: true }), "pointer");
  await expect.poll(() => {
    const url = new URL(page.url());
    return [url.searchParams.get("search"), url.searchParams.get("labels"), url.searchParams.get("engagement")];
  }).toEqual([fixture.operatorTitle, "all", fixture.engagementId]);

  const reloadRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await graphPayload(await reloadRead);
  await expect(page.getByRole("button", { name, exact: true })).toBeVisible();
  // The graph worker and its route chunk are part of the required surface.
  // Wait for the post-reload canvas before ending the audit so a fast test
  // teardown cannot abort still-loading Vite modules and hide a real failure.
  await waitForCanvas(page);
  await activate(page.getByRole("button", { name: `Delete saved view ${name}`, exact: true }), "keyboard");
  await expect(page.getByRole("button", { name, exact: true })).toHaveCount(0);
  await expect(page.locator(".brain-graph-notice")).toContainText(`Removed “${name}” from this browser.`);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.canvasTableInspector} exercises pointer and keyboard canvas input, list parity, Context Pack transparency, paths, and pin state`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const initialRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId
    && url.searchParams.get("limit") === "500");
  await page.goto(graphRoute({ limit: "500" }), { waitUntil: "domcontentloaded" });
  const graph = await graphPayload(await initialRead);
  expect(graph.nodes).toHaveLength(fixture.nodeCount);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const canvas = await waitForCanvas(page);

  await canvas.focus();
  await canvas.press("ArrowRight");
  await expect.poll(() => new URL(page.url()).searchParams.get("selected")).not.toBeNull();
  await expect(page.getByRole("complementary", { name: "Selected memory details", exact: true })).toBeVisible();
  await canvas.press("Escape");
  await expect.poll(() => new URL(page.url()).searchParams.get("selected")).toBeNull();
  await expect(page.getByRole("heading", { name: "Select a memory", exact: true })).toBeVisible();

  const box = await canvas.boundingBox();
  if (!box) throw new Error("The graph canvas has no measurable bounds");
  const points = layoutGraph(graph.nodes, Math.floor(box.width), Math.floor(box.height));
  const controlBox = await page.getByLabel("Graph viewport controls", { exact: true }).boundingBox();
  const candidate = [...points].reverse().find((point) => (
    point.x > 32
      && point.x < box.width - 32
      && point.y > Math.max(90, (controlBox?.height ?? 0) + 20)
      && point.y < box.height - 48
  ));
  if (!candidate) throw new Error("The deterministic graph layout has no pointer-safe node");
  const expectedPoint = [...points].reverse().find((point) => (
    Math.hypot(candidate.x - point.x, candidate.y - point.y) <= Math.max(12, point.radius + 4)
  ));
  if (!expectedPoint) throw new Error("The deterministic graph pointer target did not resolve");
  await canvas.click({ position: { x: candidate.x, y: candidate.y } });
  await expect.poll(() => new URL(page.url()).searchParams.get("selected")).toBe(expectedPoint.id);

  // Selecting a node opens the inspector and can resize the canvas column.
  // Recompute the deterministic point after that real layout transition so
  // the drag continues to target the selected node rather than stale pixels.
  await waitForCanvas(page);
  const dragBox = await canvas.boundingBox();
  if (!dragBox) throw new Error("The selected graph canvas has no measurable bounds");
  const dragPoint = layoutGraph(graph.nodes, Math.floor(dragBox.width), Math.floor(dragBox.height))
    .find((point) => point.id === expectedPoint.id);
  if (!dragPoint) throw new Error("The selected graph node is absent from the resized deterministic layout");
  await canvas.dragTo(canvas, {
    sourcePosition: { x: dragPoint.x, y: dragPoint.y },
    targetPosition: { x: dragPoint.x + 34, y: dragPoint.y + 24 },
  });
  await expect.poll(() => page.evaluate(([key, nodeId]) => {
    const value = localStorage.getItem(key);
    return value ? Boolean((JSON.parse(value) as Record<string, unknown>)[nodeId]) : false;
  }, [BROWSER_STORAGE_KEYS.brainPinnedPositions, expectedPoint.id] as const)).toBe(true);
  await expect(page.getByText("1 positioned nodes", { exact: true })).toBeVisible();

  const viewportStatus = page.locator("p[role='status']").filter({ hasText: /^Graph viewport zoom/u });
  await expect(viewportStatus).toContainText("100 percent");
  await activate(page.getByRole("button", { name: "Zoom in", exact: true }), "pointer");
  await expect(viewportStatus).toContainText("120 percent");
  await activate(page.getByRole("button", { name: "Fit", exact: true }), "keyboard");
  await expect(viewportStatus).toContainText("100 percent");
  await activate(page.getByRole("button", { name: "Zoom out", exact: true }), "pointer");
  await expect(viewportStatus).toContainText("83 percent");
  await canvas.dispatchEvent("wheel", { deltaY: -100 });
  await expect(viewportStatus).toContainText("92 percent");
  await activate(page.getByRole("button", { name: "Fit", exact: true }), "pointer");
  await expect(viewportStatus).toContainText("100 percent");

  await activate(page.getByRole("button", { name: "Reset layout", exact: true }), "keyboard");
  await expect.poll(() => page.evaluate(([key, nodeId]) => {
    const value = localStorage.getItem(key);
    return value ? Boolean((JSON.parse(value) as Record<string, unknown>)[nodeId]) : false;
  }, [BROWSER_STORAGE_KEYS.brainPinnedPositions, expectedPoint.id] as const)).toBe(false);
  await expect(page.getByText("0 positioned nodes", { exact: true })).toBeVisible();

  await selectPreferenceInTable(page, "pointer");
  const table = page.getByRole("table", { name: "Accessible memory graph node list", exact: true });
  await expect(table.getByRole("row")).toHaveCount(fixture.nodeCount + 1);
  const inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
  await expect(inspector).toContainText("The isolated browser fixture created this preference node through the canonical memory repository.");
  await expect(inspector).toContainText("1 backlinks");
  await expect(inspector).toContainText("2 outgoing");

  const contextRead = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/brain/context-packs/${fixture.contextPackId}`
    && response.status() === 200);
  const contextControl = inspector.getByRole("button", {
    name: /Adapt the represented Guided explanation to the confirmed evidence-first preference/u,
  });
  await activate(contextControl, "keyboard");
  expect((await contextRead).status()).toBe(200);
  await expect(inspector.getByRole("heading", {
    name: "Adapt the represented Guided explanation to the confirmed evidence-first preference",
    exact: true,
  })).toBeVisible();
  await expect(inspector).toContainText("The Guided explanation presents attributable evidence before technique detail.");
  const showPath = inspector.getByRole("link", { name: "Show memory path", exact: true });
  await expect(showPath).toHaveAttribute("href", `/brain/graph?view=local&root=${fixture.preferenceNodeId}&selected=${fixture.preferenceNodeId}`);

  const pinResponse = page.waitForResponse((response) => response.request().method() === "POST"
    && pathname(response) === `/api/v2/brain/nodes/${fixture.preferenceNodeId}/pin`
    && response.status() === 200);
  await activate(inspector.getByRole("button", { name: "Pin", exact: true }), "pointer");
  expect((await pinResponse).status()).toBe(200);
  await expect(inspector.getByRole("button", { name: "Unpin", exact: true })).toBeVisible();
  expect(readBrainGraphFixtureState(fixture).preferencePinned).toBe(true);
  const unpinResponse = page.waitForResponse((response) => response.request().method() === "POST"
    && pathname(response) === `/api/v2/brain/nodes/${fixture.preferenceNodeId}/pin`
    && response.status() === 200);
  await activate(inspector.getByRole("button", { name: "Unpin", exact: true }), "keyboard");
  expect((await unpinResponse).status()).toBe(200);
  await expect(inspector.getByRole("button", { name: "Pin", exact: true })).toBeVisible();
  expect(readBrainGraphFixtureState(fixture)).toMatchObject({
    nodeCount: fixture.nodeCount,
    edgeCount: fixture.edgeCount,
    preferencePinned: false,
    contextPackUsedItems: 1,
  });

  await activate(inspector.getByRole("button", { name: "Set as path start", exact: true }), "pointer");
  await expect.poll(() => new URL(page.url()).searchParams.get("pathFrom")).toBe(fixture.preferenceNodeId);
  await activate(inspector.getByRole("button", { name: "Clear path start", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.get("pathFrom")).toBeNull();
  await activate(inspector.getByRole("button", { name: "Set as path start", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.get("pathFrom")).toBe(fixture.preferenceNodeId);
  const evidenceRow = table.getByRole("row").filter({ hasText: fixture.secondaryTitle });
  await activate(evidenceRow.getByRole("button", { name: "Inspect", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.get("selected")).toBe(fixture.secondaryNodeId);
  await expect(page.getByRole("complementary", { name: "Selected memory details", exact: true })
    .getByRole("heading", { name: fixture.secondaryTitle, exact: true })).toBeVisible();
  await expect(page.locator(".brain-active-filter").filter({ hasText: "Shortest path from" })).toContainText(fixture.preferenceNodeId);
  await activate(page.getByRole("button", { name: "Canvas view", exact: true }), "pointer");
  await waitForCanvas(page);
  await expect(page.locator(".os-visually-hidden").filter({ hasText: /^Shortest memory path contains/u })).toBeAttached();

  const pathFilter = page.locator(".brain-active-filter").filter({ hasText: "Shortest path from" });
  await activate(pathFilter.getByRole("button", { name: "Clear", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.get("pathFrom")).toBeNull();

  const localRead = graphResponse(page, (url) => url.searchParams.get("view") === "local"
    && url.searchParams.get("nodeId") === fixture.secondaryNodeId);
  await activate(page.getByRole("complementary", { name: "Selected memory details", exact: true })
    .getByRole("button", { name: "Open local graph", exact: true }), "pointer");
  const localGraph = await graphPayload(await localRead);
  expect(localGraph.view).toBe("local");
  expect(localGraph.rootNodeId).toBe(fixture.secondaryNodeId);
  await expect(page.getByRole("button", { name: "Local", exact: true })).toBeEnabled();
  await expect(page.locator(".brain-active-filter").filter({ hasText: "Local neighborhood" })).toContainText(fixture.secondaryNodeId);
  const operatorFromLocal = graphResponse(page, (url) => url.searchParams.get("view") === "operator");
  await activate(page.getByRole("button", { name: "Operator profile", exact: true }), "pointer");
  await graphPayload(await operatorFromLocal);
  await activate(page.getByRole("button", { name: "Local", exact: true }), "keyboard");
  await expect.poll(() => {
    const url = new URL(page.url());
    return [url.searchParams.get("view"), url.searchParams.get("root")];
  }).toEqual(["local", fixture.secondaryNodeId]);
  await activate(page.locator(".brain-active-filter").filter({ hasText: "Local neighborhood" })
    .getByRole("button", { name: "Clear", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.get("view")).toBeNull();
  await expect(page.getByText(`${fixture.nodeCount} visible of ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.visualCanvasTable} preserves deterministic canvas and accessible-table projections of the same canonical Brain graph`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const normalizeGraphResponse = async (route: Route): Promise<void> => {
    const response = await route.fetch();
    const payload = await response.json() as MemoryGraph | { readonly data: MemoryGraph };
    const graph = "data" in payload ? payload.data : payload;
    const orderedNodes = graph.nodes.map((node) => ({
      ...node,
      title: node.title.replaceAll(fixture.namespace, "approved-visual"),
      summary: node.summary.replaceAll(fixture.namespace, "approved-visual"),
      scope: {
        ...node.scope,
        ...(node.scope.kind !== "global" ? { engagementId: "engagement-approved-visual" } : {}),
        ...(node.scope.kind === "mission" ? { missionId: "mission-approved-visual" } : {}),
      } as typeof node.scope,
    })).sort((left, right) => `${left.nodeType}:${left.title}`.localeCompare(`${right.nodeType}:${right.title}`, "en"));
    const normalizedIds = new Map(orderedNodes.map((node, index) => [
      node.id,
      `memory-approved-visual-${String(index + 1).padStart(3, "0")}-${node.nodeType}`,
    ]));
    const normalizedGraph: MemoryGraph = {
      ...graph,
      nodes: orderedNodes.map((node) => ({
        ...node,
        id: normalizedIds.get(node.id)!,
      })),
      edges: graph.edges.map((edge, index) => ({
        ...edge,
        id: `edge-approved-visual-${String(index + 1).padStart(3, "0")}`,
        sourceNodeId: normalizedIds.get(edge.sourceNodeId)!,
        targetNodeId: normalizedIds.get(edge.targetNodeId)!,
      })),
      ...(graph.rootNodeId ? { rootNodeId: normalizedIds.get(graph.rootNodeId) } : {}),
    };
    await route.fulfill({
      response,
      contentType: "application/json; charset=utf-8",
      body: JSON.stringify("data" in payload ? { ...payload, data: normalizedGraph } : normalizedGraph),
    });
  };
  await page.route("**/api/v2/brain/graph?*", normalizeGraphResponse);
  try {
    const initialRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId
      && url.searchParams.get("limit") === "500");
    await page.goto(graphRoute({ limit: "500" }), { waitUntil: "domcontentloaded" });
    expect((await graphPayload(await initialRead)).nodes).toHaveLength(fixture.nodeCount);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    await waitForCanvas(page);
    await expectApprovedGraphVisual(page.locator(".brain-graph-workspace"), testInfo, GRAPH_VISUALS.canvas);

    await activate(page.getByRole("button", { name: "Accessible table", exact: true }), "keyboard");
    const table = page.getByRole("table", { name: "Accessible memory graph node list", exact: true });
    await expect(table).toBeVisible();
    await expect(table.getByRole("row")).toHaveCount(fixture.nodeCount + 1);
    await expectApprovedGraphVisual(page.locator(".brain-graph-table"), testInfo, GRAPH_VISUALS.table);
    await strictAudit(audit, testInfo);
  } finally {
    await page.unroute("**/api/v2/brain/graph?*", normalizeGraphResponse);
  }
});

test(`${TEST_IDS.deepLinksHistory} preserves graph state through node, Context Pack, Brain navigation, reload, back, and forward`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const initialRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId
    && url.searchParams.get("limit") === "500");
  await page.goto(graphRoute({ limit: "500" }), { waitUntil: "domcontentloaded" });
  await graphPayload(await initialRead);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await selectPreferenceInTable(page, "keyboard");
  let inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });

  const contextRead = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/brain/context-packs/${fixture.contextPackId}`
    && response.status() === 200);
  await activate(inspector.getByRole("button", {
    name: /Adapt the represented Guided explanation to the confirmed evidence-first preference/u,
  }), "pointer");
  expect((await contextRead).status()).toBe(200);
  const contextNodeLink = inspector.getByRole("link", { name: fixture.preferenceTitle, exact: true });
  await expect(contextNodeLink).toHaveAttribute("href", `/brain/nodes/${fixture.preferenceNodeId}`);
  const contextPathRead = graphResponse(page, (url) => url.searchParams.get("view") === "local"
    && url.searchParams.get("nodeId") === fixture.preferenceNodeId);
  await activate(inspector.getByRole("link", { name: "Show memory path", exact: true }), "keyboard");
  expect((await graphPayload(await contextPathRead)).rootNodeId).toBe(fixture.preferenceNodeId);
  await expect(page).toHaveURL((url) => url.pathname === "/brain/graph"
    && url.searchParams.get("root") === fixture.preferenceNodeId
    && url.searchParams.get("selected") === fixture.preferenceNodeId);

  await selectPreferenceInTable(page, "pointer");
  inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });

  const fullRecord = inspector.getByRole("link", { name: "Full memory record", exact: true });
  await expect(fullRecord).toHaveAttribute("href", `/brain/nodes/${fixture.preferenceNodeId}`);
  const previousGraphUrl = page.url();
  await activate(fullRecord, "pointer");
  await expect(page).toHaveURL(`/brain/nodes/${fixture.preferenceNodeId}`);
  await expect(page.getByRole("heading", { name: fixture.preferenceTitle, exact: true }).first()).toBeVisible();
  const nodeUrl = page.url();
  const nodeReload = page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/brain/nodes/${fixture.preferenceNodeId}`
    && response.status() === 200);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await nodeReload).status()).toBe(200);
  await expect(page.getByRole("heading", { name: fixture.preferenceTitle, exact: true }).first()).toBeVisible();

  let backSteps = 0;
  while (page.url() !== previousGraphUrl && backSteps < 2) {
    await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
    backSteps += 1;
  }
  expect(backSteps).toBeGreaterThanOrEqual(1);
  expect(backSteps).toBeLessThanOrEqual(2);
  await expect(page).toHaveURL(previousGraphUrl);
  await expect(page).toHaveURL((url) => url.pathname === "/brain/graph"
    && url.searchParams.get("selected") === fixture.preferenceNodeId);
  await expect(page.getByRole("heading", { name: "Memory Graph", exact: true })).toBeVisible();

  let forwardSteps = 0;
  while (page.url() !== nodeUrl && forwardSteps < 2) {
    await audit.withExpectedHistoryTraversal(page, () => page.goForward({ waitUntil: "domcontentloaded" }));
    forwardSteps += 1;
  }
  expect(forwardSteps).toBeGreaterThanOrEqual(1);
  expect(forwardSteps).toBeLessThanOrEqual(2);
  await expect(page).toHaveURL(nodeUrl);
  await expect(page).toHaveURL(`/brain/nodes/${fixture.preferenceNodeId}`);
  await expect(page.getByRole("heading", { name: fixture.preferenceTitle, exact: true }).first()).toBeVisible();

  await activate(page.getByRole("button", { name: "Show in graph", exact: true }), "keyboard");
  await expect(page).toHaveURL((url) => url.pathname === "/brain/graph"
    && url.searchParams.get("view") === "local"
    && url.searchParams.get("root") === fixture.preferenceNodeId
    && url.searchParams.get("selected") === fixture.preferenceNodeId);
  await expect(page.locator(".brain-active-filter").filter({ hasText: "Local neighborhood" })).toContainText(fixture.preferenceNodeId);

  const reviewCandidates = page.getByRole("link", { name: "Review candidates", exact: true });
  await expect(reviewCandidates).toHaveAttribute("href", "/brain/inbox");
  await activate(reviewCandidates, "pointer");
  await expect(page.getByRole("heading", { name: "Memory Inbox", exact: true })).toBeVisible();
  await page.waitForTimeout(500);
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Memory Graph", exact: true })).toBeVisible();

  const destinations = [
    { label: "Home", href: "/brain", heading: "Second Brain", input: "keyboard" as const },
    { label: "Memory Inbox", href: "/brain/inbox", heading: "Memory Inbox", input: "pointer" as const },
    { label: "Controls", href: "/brain/control", heading: "Memory Control Center", input: "keyboard" as const },
    { label: "Obsidian Vault", href: "/brain/vault", heading: "Obsidian Vault", input: "pointer" as const },
  ];
  for (const destination of destinations) {
    const nav = page.getByRole("navigation", { name: "Second Brain", exact: true });
    const link = nav.getByRole("link", { name: destination.label, exact: true });
    await expect(link).toHaveAttribute("href", destination.href);
    await activate(link, destination.input);
    await expect(page).toHaveURL(destination.href);
    await expect(page.getByRole("heading", { name: destination.heading, exact: true }).first()).toBeVisible();
    await page.waitForTimeout(500);
    await page.goBack({ waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Memory Graph", exact: true })).toBeVisible();
  }
  const graphNav = page.getByRole("navigation", { name: "Second Brain", exact: true })
    .getByRole("link", { name: "Graph", exact: true });
  await expect(graphNav).toHaveAttribute("href", "/brain/graph");
  await expect(graphNav).toHaveAttribute("aria-current", "page");
  await page.evaluate((staleRoot) => {
    sessionStorage.setItem("ti-scale.brain.graph-root", staleRoot);
  }, fixture.secondaryNodeId);
  const graphHomeRead = graphResponse(page, (url) => url.searchParams.get("view") === "global"
    && !url.searchParams.has("nodeId"));
  await activate(graphNav, "keyboard");
  await graphPayload(await graphHomeRead);
  await expect(page).toHaveURL("/brain/graph");
  await expect(page.locator(".brain-active-filter").filter({ hasText: "Local neighborhood" })).toHaveCount(0);
  await strictAudit(audit, testInfo);
});

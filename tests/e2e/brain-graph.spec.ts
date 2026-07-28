import {
  expect,
  test,
  type Locator,
  type Page,
  type Response,
  type Route,
  type TestInfo,
} from "./support/playwright";
import { readFileSync } from "node:fs";
import {
  MEMORY_EDGE_TYPES,
  MEMORY_LIFECYCLE_STATES,
  MEMORY_NODE_TYPES,
  MEMORY_SENSITIVITIES,
  type MemoryGraph,
} from "../../src/domain/types/brain";
import {
  brainAtlasProjection,
  graphPointToBrainAtlasPosition,
  projectBrainAtlasPoint,
} from "../../src/features/brain/brainAtlasGeometry";
import {
  collapseGraphClusters,
  GRAPH_CLUSTER_LABELS,
  layoutGraph,
  nodeCluster,
  shortestMemoryPath,
  type GraphCluster,
} from "../../src/features/brain/graphUtils";
import { nearestBrainNodeHit } from "../../src/features/brain/brainVisualLanguage";
import { BROWSER_STORAGE_KEYS } from "../../src/lib/browserNamespaces";
import { BrowserAudit } from "./support/browserAudit";
import {
  BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT,
  createBrainGraphFixture,
  readBrainGraphFixtureState,
  type BrainGraphFixture,
} from "./support/brainGraphFixtureController";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
} from "./support/interactionActivationFixture";
import { readTitaniumOptions, selectTitaniumOption } from "./support/titaniumSelect";
import { validateInteractionManifest } from "../interaction-manifest/schema";

const TEST_IDS = {
  globalEmptyInbox: "e2e.brain-graph.global-empty-inbox",
  globalReviewedBoundary: "e2e.brain-graph.global-reviewed-boundary",
  disconnectedTruth: "e2e.brain-graph.disconnected-truth",
  errorEmptyRetry: "e2e.brain-graph.error-empty-retry",
  controlsFiltersViews: "e2e.brain-graph.controls-filters-views",
  outcomeTags: "e2e.brain-graph.outcome-tags",
  canvasTableInspector: "e2e.brain-graph.canvas-table-inspector",
  motionAndSignals: "e2e.brain-graph.motion-and-signals",
  atlasRenderer: "e2e.brain-graph.atlas-renderer",
  atlasFallback: "e2e.brain-graph.atlas-fallback",
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
const interactionManifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

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

function activationReceipt(
  manifestEntryId: string,
  option: string,
  modality: "keyboard" | "pointer",
  testId: string,
): InteractionActivationInput {
  const entry = interactionManifest.entries.find((candidate) => candidate.id === manifestEntryId);
  if (!entry) throw new Error(`Brain graph manifest entry ${manifestEntryId} is missing`);
  if (!entry.options.includes(option)) {
    throw new Error(`Brain graph manifest entry ${manifestEntryId} does not declare ${option}`);
  }
  if (!entry.testIds.includes(testId)) {
    throw new Error(`Brain graph manifest entry ${manifestEntryId} is not bound to ${testId}`);
  }
  return {
    manifestEntryId,
    controlId: entry.controlId,
    option,
    materialState: entry.requiredState,
    modality,
    testId,
  };
}

async function recordGraphActivation<T>(
  recorder: InteractionActivationRecorder,
  manifestEntryId: string,
  option: string,
  modality: "keyboard" | "pointer",
  testId: string,
  action: () => Promise<T>,
): Promise<T> {
  return recorder.activate(
    activationReceipt(manifestEntryId, option, modality, testId),
    action,
  );
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

function projectedFixtureGraphPoints(graph: MemoryGraph, width: number, height: number) {
  const safeWidth = Math.floor(width);
  const safeHeight = Math.floor(height);
  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  const projection = brainAtlasProjection(safeWidth, safeHeight, 1, { x: -0.08, y: 0 });
  return layoutGraph(graph.nodes, safeWidth, safeHeight).flatMap((point) => {
    const node = nodesById.get(point.id);
    if (!node) return [];
    const projected = projectBrainAtlasPoint(
      projection,
      graphPointToBrainAtlasPosition(point, node, safeWidth, safeHeight),
    );
    return [{
      ...projected,
      id: point.id,
      radius: point.radius * projected.scale,
    }];
  });
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
  return (await readTitaniumOptions(control)).map((option) => option.value);
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
  await selectTitaniumOption(control, option, "pointer");
  assertion(await graphPayload(await filtered));
  await selectTitaniumOption(control, "", "keyboard");
  await expect(page.getByRole("heading", { name: "Memory Graph", exact: true })).toBeVisible();
}

async function selectPreferenceInTable(page: Page, input: "keyboard" | "pointer"): Promise<void> {
  const table = page.getByRole("table", { name: "Accessible memory graph node list", exact: true });
  const tableToggle = page.getByRole("button", { name: "Accessible table", exact: true });
  if (!await table.isVisible()) {
    await expect(tableToggle).toBeVisible();
    await activate(tableToggle, input);
    await expect.poll(() => new URL(page.url()).searchParams.get("table")).toBe("1");
  }
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
    await expect(page.getByText("No confirmed or verified reusable knowledge yet", { exact: true })).toBeVisible();
    await expect(page.locator(".brain-empty").getByText(/source provenance/u)).toBeVisible();
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

test(`${TEST_IDS.globalReviewedBoundary} shows confirmed and verified reusable memories with truthful population counts`, async ({ page }, testInfo) => {
  const graphRead = graphResponse(page, (url) => url.searchParams.get("view") === "global"
    && url.searchParams.get("scope") === "global"
    && !url.searchParams.has("status"));
  await page.goto("/brain/graph", { waitUntil: "domcontentloaded" });
  const graph = await graphPayload(await graphRead);
  const lifecycles = new Set(graph.nodes.map((node) => node.lifecycleStatus));
  expect(lifecycles.has("confirmed")).toBe(true);
  expect(lifecycles.has("verified")).toBe(true);
  expect([...lifecycles].every((lifecycle) => lifecycle === "confirmed" || lifecycle === "verified")).toBe(true);
  expect(graph.availableNodeCount).toBeGreaterThanOrEqual(graph.nodes.length);
  expect(graph.truncated).toBe(graph.availableNodeCount > graph.nodes.length);

  await expect(page.getByRole("status").filter({ hasText: "Showing confirmed and verified reusable global knowledge by default" })).toBeVisible();
  await expect(page.getByText(`${graph.nodes.length} loaded · ${new Intl.NumberFormat("en-US").format(graph.availableNodeCount)} accessible in this view`, { exact: false })).toBeVisible();
  await expect(page.getByRole("link", { name: "Operator Preferences", exact: true })).toHaveAttribute("href", "/brain/preferences");
  await strictAudit(new BrowserAudit(page, { allowEventStreamNavigationAbort: true }), testInfo);
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
    await expect(page.getByText("0 displayed from 0 matching relationships", { exact: true })).toBeVisible();
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
  await expect(page.getByText(`${BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT} displayed from ${BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT} matching · ${BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

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
  await expect(page.getByText(`${fixture.nodeCount} displayed from ${fixture.nodeCount} matching · ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

  const operatorRead = graphResponse(page, (url) => url.searchParams.get("view") === "operator");
  await activate(page.getByRole("button", { name: "Operator Preferences / Profile", exact: true }), "keyboard");
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
  await expect(page.getByText(`${fixture.nodeCount} displayed from ${fixture.nodeCount} matching · ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

  const search = page.getByLabel("Search visible graph", { exact: true });
  await search.fill(fixture.operatorTitle);
  await expect(page.getByText(`1 displayed from 1 matching · ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();
  await search.fill("");
  await expect(page.getByText(`${fixture.nodeCount} displayed from ${fixture.nodeCount} matching · ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

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
  expect(await optionValues(advanced.getByRole("combobox", { name: "Scope", exact: true }))).toEqual(["", "all", "global", "engagement", "mission"]);
  expect(await optionValues(advanced.getByRole("combobox", { name: "Lifecycle", exact: true }))).toEqual([
    "",
    ...MEMORY_LIFECYCLE_STATES.filter((state) => state !== "forgotten"),
  ]);
  expect(await optionValues(advanced.getByRole("combobox", { name: "Sensitivity", exact: true }))).toEqual(["", ...MEMORY_SENSITIVITIES]);
  expect(await optionValues(advanced.getByRole("combobox", { name: "Minimum confidence", exact: true }))).toEqual(["", "0.25", "0.5", "0.75", "0.9"]);
  expect(await optionValues(advanced.getByRole("combobox", { name: "Label density", exact: true }))).toEqual(["minimal", "balanced", "all"]);
  const provenanceRead = graphResponse(page, (url) => url.searchParams.get("view") === "global"
    && !url.searchParams.has("scope")
    && !url.searchParams.has("status")
    && !url.searchParams.has("engagementId"));
  await selectTitaniumOption(advanced.getByRole("combobox", { name: "Scope", exact: true }), "all", "keyboard");
  expect((await graphPayload(await provenanceRead)).nodes.length).toBeGreaterThan(0);
  await expect.poll(() => new URL(page.url()).searchParams.get("provenance")).toBe("1");
  await expect(page.getByRole("status").filter({ hasText: "Source provenance is visible" })).toBeVisible();
  const restoredFixture = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId
    && url.searchParams.get("limit") === "500");
  await page.goto(graphRoute({ limit: "500" }), { waitUntil: "domcontentloaded" });
  expect((await graphPayload(await restoredFixture)).nodes).toHaveLength(fixture.nodeCount);
  await openAdvanced(page);
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
  await expect(page.getByText(`${fixture.nodeCount} displayed from ${fixture.nodeCount} matching · ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

  const engagementInput = advanced.getByLabel("Engagement ID", { exact: true });
  const missingEngagement = `${fixture.engagementId}-missing`;
  const missingRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === missingEngagement);
  await engagementInput.fill(missingEngagement);
  expect((await graphPayload(await missingRead)).nodes).toEqual([]);
  await engagementInput.fill(fixture.engagementId);
  await expect(page.getByText(`${fixture.nodeCount} displayed from ${fixture.nodeCount} matching · ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();

  const labels = advanced.getByRole("combobox", { name: "Label density", exact: true });
  await selectTitaniumOption(labels, "minimal", "pointer");
  await expect(page.getByText("minimal labels", { exact: true })).toBeVisible();
  await selectTitaniumOption(labels, "all", "keyboard");
  await expect(page.getByText("all labels", { exact: true })).toBeVisible();
  await selectTitaniumOption(labels, "balanced", "pointer");
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

  const visibleClusters = new Set(expanded.nodes.map(nodeCluster));
  const anatomyClusters = (Object.entries(GRAPH_CLUSTER_LABELS) as Array<[GraphCluster, string]>)
    .filter(([cluster]) => visibleClusters.has(cluster));
  for (const [index, [cluster, clusterLabel]] of anatomyClusters.entries()) {
    const collapse = page.getByRole("button", { name: new RegExp(`^Collapse ${clusterLabel} \\(`, "u") });
    await activate(collapse, index % 2 === 0 ? "pointer" : "keyboard");
    const expand = page.getByRole("button", { name: new RegExp(`^Expand ${clusterLabel} \\(`, "u") });
    await expect(expand).toHaveAttribute("aria-pressed", "true");
    if (cluster === "operator") {
      const canvas = await waitForCanvas(page);
      const box = await canvas.boundingBox();
      if (!box) throw new Error("The collapsed graph canvas has no measurable bounds");
      const projection = collapseGraphClusters(expanded.nodes, expanded.edges, new Set([cluster]));
      await expect(advanced.locator("summary")).toContainText("1 collapsed cluster");
      await expect(page.getByRole("status").filter({ hasText: "aggregate cluster nodes" })).toContainText(
        "not missing memories",
      );
      await expect(page.getByText(`${projection.nodes.length} displayed from ${expanded.nodes.length} matching · ${expanded.nodes.length} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();
      await expect(page.getByText(`${projection.edges.length} displayed from ${expanded.edges.length} matching relationships`, { exact: true })).toBeVisible();
      const point = layoutGraph(projection.nodes, Math.floor(box.width), Math.floor(box.height))
        .find((item) => item.id === "cluster:operator");
      if (!point) throw new Error("The collapsed operator cluster was not projected to the canvas");
      await canvas.click({ position: { x: point.x, y: point.y }, force: true });
    } else {
      await activate(expand, index % 2 === 0 ? "keyboard" : "pointer");
    }
    await expect(page.getByRole("button", { name: new RegExp(`^Collapse ${clusterLabel} \\(`, "u") })).toHaveAttribute("aria-pressed", "false");
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
  await selectTitaniumOption(labels, "all", "keyboard");
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

test(`${TEST_IDS.outcomeTags} filters independent evidence-linked outcomes without classifying supporting knowledge`, async ({ page }, testInfo) => {
  const taggedNodeIds = new Map<string, readonly ("success" | "failed")[]>([
    [fixture.operatorNodeId, ["success"]],
    [fixture.secondaryNodeId, ["success", "failed"]],
  ]);
  const graphFixture = async (route: Route): Promise<void> => {
    const requestedUrl = new URL(route.request().url());
    const requestedOutcome = requestedUrl.searchParams.get("outcome");
    const upstreamUrl = new URL(requestedUrl);
    upstreamUrl.searchParams.delete("outcome");
    const response = await route.fetch({ url: upstreamUrl.toString() });
    const payload = await response.json() as MemoryGraph | { readonly data: MemoryGraph };
    const graph = "data" in payload ? payload.data : payload;
    const taggedNodes = graph.nodes.map((node) => ({
      ...node,
      ...(taggedNodeIds.has(node.id) ? { outcomeTags: taggedNodeIds.get(node.id) } : {}),
    }));
    const nodes = requestedOutcome
      ? taggedNodes.filter((node) => requestedOutcome === "unclassified"
        ? !node.outcomeTags?.length
        : node.outcomeTags?.includes(requestedOutcome as "success" | "failed"))
      : taggedNodes;
    const nodeIds = new Set(nodes.map((node) => node.id));
    const tagged = {
      ...graph,
      nodes,
      edges: graph.edges.filter((edge) => nodeIds.has(edge.sourceNodeId) && nodeIds.has(edge.targetNodeId)),
      availableNodeCount: nodes.length,
      truncated: false,
    } as MemoryGraph;
    await route.fulfill({
      response,
      contentType: "application/json; charset=utf-8",
      body: JSON.stringify("data" in payload ? { ...payload, data: tagged } : tagged),
    });
  };
  const detailFixture = async (route: Route): Promise<void> => {
    if (route.request().method() !== "GET") {
      await route.continue();
      return;
    }
    const response = await route.fetch();
    const payload = await response.json() as Record<string, unknown>;
    const wrapped = payload.data && typeof payload.data === "object"
      ? payload.data as Record<string, unknown>
      : payload;
    const node = wrapped.node as Record<string, unknown>;
    const outcomeTags = taggedNodeIds.get(String(node.id));
    const tagged = {
      ...wrapped,
      node: { ...node, ...(outcomeTags ? { outcomeTags } : {}) },
    };
    await route.fulfill({
      response,
      contentType: "application/json; charset=utf-8",
      body: JSON.stringify(payload.data ? { ...payload, data: tagged } : tagged),
    });
  };
  await page.route("**/api/v2/brain/graph?*", graphFixture);
  await page.route("**/api/v2/brain/nodes/*", detailFixture);
  try {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const initialRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId
      && url.searchParams.get("limit") === "500");
    await page.goto(graphRoute({ limit: "500" }), { waitUntil: "domcontentloaded" });
    expect((await graphPayload(await initialRead)).nodes).toHaveLength(fixture.nodeCount);

    const outcome = page.getByRole("combobox", { name: "Verified outcome", exact: true });
    expect(await optionValues(outcome)).toEqual(["", "success", "failed", "unclassified"]);
    await expect(page.getByLabel("Verified outcome evidence: Success, 2", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Verified outcome evidence: Failed, 1", { exact: true })).toBeVisible();
    await expect(page.getByLabel(`Verified outcome evidence: Supporting or unclassified, ${fixture.nodeCount - 2}`, { exact: true })).toBeVisible();

    const successRead = graphResponse(page, (url) => url.searchParams.get("outcome") === "success");
    await selectTitaniumOption(outcome, "success", "pointer");
    await expect.poll(() => new URL(page.url()).searchParams.get("outcome")).toBe("success");
    expect((await graphPayload(await successRead)).nodes).toHaveLength(2);
    await expect(page.getByText("2 displayed from 2 matching · 2 loaded · 2 accessible in this view", { exact: true })).toBeVisible();
    const failedRead = graphResponse(page, (url) => url.searchParams.get("outcome") === "failed");
    await selectTitaniumOption(outcome, "failed", "keyboard");
    await expect.poll(() => new URL(page.url()).searchParams.get("outcome")).toBe("failed");
    expect((await graphPayload(await failedRead)).nodes).toHaveLength(1);
    await expect(page.getByText("1 displayed from 1 matching · 1 loaded · 1 accessible in this view", { exact: true })).toBeVisible();

    await activate(page.getByRole("button", { name: "Accessible table", exact: true }), "pointer");
    const table = page.getByRole("table", { name: "Accessible memory graph node list", exact: true });
    const bothRow = table.getByRole("row").filter({ hasText: fixture.secondaryTitle });
    await expect(bothRow.getByLabel("Verified outcome evidence: Success and Failed", { exact: true })).toBeVisible();
    await activate(bothRow.getByRole("button", { name: "Inspect", exact: true }), "keyboard");
    const inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
    await expect(inspector.getByLabel("Verified outcome evidence: Success and Failed", { exact: true })).toBeVisible();
    await expect(inspector).toContainText("Success and Failed");

    const unclassifiedRead = graphResponse(page, (url) => url.searchParams.get("outcome") === "unclassified");
    await selectTitaniumOption(outcome, "unclassified", "pointer");
    await expect.poll(() => new URL(page.url()).searchParams.get("outcome")).toBe("unclassified");
    expect((await graphPayload(await unclassifiedRead)).nodes).toHaveLength(fixture.nodeCount - 2);
    await expect(page.getByText(`${fixture.nodeCount - 2} displayed from ${fixture.nodeCount - 2} matching · ${fixture.nodeCount - 2} loaded · ${fixture.nodeCount - 2} accessible in this view`, { exact: true })).toBeVisible();
    const supporting = table.getByRole("row").filter({ hasText: fixture.preferenceTitle });
    await expect(supporting.getByLabel("Verified outcome evidence: Supporting or unclassified", { exact: true })).toBeVisible();
    await strictAudit(audit, testInfo);
  } finally {
    await page.unroute("**/api/v2/brain/graph?*", graphFixture);
    await page.unroute("**/api/v2/brain/nodes/*", detailFixture);
  }
});

test(`${TEST_IDS.canvasTableInspector} exercises pointer and keyboard canvas input, list parity, Context Pack transparency, paths, and pin state`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  await page.emulateMedia({ reducedMotion: "reduce" });
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
  const points = projectedFixtureGraphPoints(graph, box.width, box.height);
  const controlBox = await page.getByLabel("Graph viewport controls", { exact: true }).boundingBox();
  const candidate = points.find((point) => (
    point.visible
      && point.x > 96
      && point.x < box.width - 96
      && point.y > Math.max(90, (controlBox?.height ?? 0) + 20)
      && point.y < box.height - 96
  ));
  if (!candidate) throw new Error("The deterministic projected graph has no pointer-safe node");
  const expectedPointId = nearestBrainNodeHit(points, candidate);
  if (!expectedPointId) throw new Error("The deterministic projected graph pointer target did not resolve");
  await canvas.click({ position: { x: candidate.x, y: candidate.y } });
  await expect.poll(() => new URL(page.url()).searchParams.get("selected")).toBe(expectedPointId);

  // Selecting a node opens the inspector and can resize the canvas column.
  // Recompute the deterministic point after that real layout transition so
  // the drag continues to target the selected node rather than stale pixels.
  await waitForCanvas(page);
  const dragBox = await canvas.boundingBox();
  if (!dragBox) throw new Error("The selected graph canvas has no measurable bounds");
  const dragPoint = projectedFixtureGraphPoints(graph, dragBox.width, dragBox.height)
    .find((point) => point.id === expectedPointId);
  if (!dragPoint) throw new Error("The selected graph node is absent from the resized deterministic layout");
  await canvas.dragTo(canvas, {
    sourcePosition: { x: dragPoint.x, y: dragPoint.y },
    targetPosition: { x: dragPoint.x + 34, y: dragPoint.y + 24 },
  });
  await expect.poll(() => page.evaluate(([key, nodeId]) => {
    const value = localStorage.getItem(key);
    return value ? Boolean((JSON.parse(value) as Record<string, unknown>)[nodeId]) : false;
  }, [BROWSER_STORAGE_KEYS.brainPinnedPositions, expectedPointId] as const)).toBe(true);
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
  }, [BROWSER_STORAGE_KEYS.brainPinnedPositions, expectedPointId] as const)).toBe(false);
  await expect(page.getByText("0 positioned nodes", { exact: true })).toBeVisible();

  await selectPreferenceInTable(page, "pointer");
  const table = page.getByRole("table", { name: "Accessible memory graph node list", exact: true });
  await expect(table.getByRole("row")).toHaveCount(fixture.nodeCount + 1);
  const inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
  await expect(inspector).toContainText("The isolated browser fixture created this preference node through the canonical memory repository.");
  await expect(inspector).toContainText("1 backlinks");
  await expect(inspector).toContainText("2 outgoing");

  const inspectorActions = [
    inspector.getByRole("link", { name: "Full memory record", exact: true }),
    inspector.getByRole("button", { name: "Open local graph", exact: true }),
    inspector.getByRole("button", { name: "Set as path start", exact: true }),
  ];
  for (const action of inspectorActions) {
    await expect(action).toBeVisible();
    const defaultStyle = await action.evaluate((element) => {
      const style = getComputedStyle(element);
      const face = getComputedStyle(element, "::before");
      return { color: style.color, face: face.backgroundImage };
    });
    expect(defaultStyle.color).toBe("rgb(243, 247, 249)");
    expect(defaultStyle.face).toContain("rgb(27, 36, 45)");
    await action.focus();
    await page.keyboard.press("Tab");
    await page.keyboard.press("Shift+Tab");
    await expect(action).toBeFocused();
    const focusStyle = await action.evaluate((element) => {
      const style = getComputedStyle(element);
      return { outlineColor: style.outlineColor, outlineStyle: style.outlineStyle, outlineWidth: style.outlineWidth };
    });
    expect(focusStyle).toEqual({ outlineColor: "rgb(184, 215, 240)", outlineStyle: "solid", outlineWidth: "3px" });
  }

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
  await activate(page.getByRole("button", { name: "Operator Preferences / Profile", exact: true }), "pointer");
  await graphPayload(await operatorFromLocal);
  await activate(page.getByRole("button", { name: "Local", exact: true }), "keyboard");
  await expect.poll(() => {
    const url = new URL(page.url());
    return [url.searchParams.get("view"), url.searchParams.get("root")];
  }).toEqual(["local", fixture.secondaryNodeId]);
  await activate(page.locator(".brain-active-filter").filter({ hasText: "Local neighborhood" })
    .getByRole("button", { name: "Clear", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.get("view")).toBeNull();
  await expect(page.getByText(`${fixture.nodeCount} displayed from ${fixture.nodeCount} matching · ${fixture.nodeCount} loaded · ${fixture.nodeCount} accessible in this view`, { exact: true })).toBeVisible();
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.motionAndSignals} renders an attack-knowledge brain, illuminates only canonical paths, and honors reduced motion`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  await page.emulateMedia({ reducedMotion: "reduce" });
  const initialRead = graphResponse(page, (url) => url.searchParams.get("scope") === "global"
    && url.searchParams.get("limit") === "500"
    && !url.searchParams.has("engagementId"));
  await page.goto("/brain/graph?scope=global&limit=500", { waitUntil: "domcontentloaded" });
  const graph = await graphPayload(await initialRead);
  const attack = graph.nodes.find((node) => node.id === fixture.attackTacticNodeId);
  const technology = graph.nodes.find((node) => node.id === fixture.technologyProductNodeId);
  if (!attack || !technology) throw new Error("The canonical Brain fixture is missing reusable attack/technology nodes");
  expect(attack.title).toBe(fixture.attackTacticTitle);
  expect(technology.title).toBe(fixture.technologyProductTitle);
  const canonicalPath = shortestMemoryPath(graph.edges, attack.id, technology.id);
  expect(canonicalPath.length, "The canonical fixture tactic/product pair must retain an evidence-backed path").toBeGreaterThan(1);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const initialCanvas = await waitForCanvas(page);
  const host = page.locator(".brain-canvas-host");
  await expect(host).toHaveAttribute("data-brain-anatomy", "particle-cloud-3d");
  await expect(host).toHaveAttribute("data-region-taxonomy", "attack-knowledge");
  await expect(host).toHaveAttribute("data-background-grid", "removed");
  await expect(host).toHaveAttribute("data-background-artwork", "removed");
  await expect(host).toHaveAttribute("data-anatomy-silhouette", "removed");
  await expect(host).toHaveAttribute("data-spinal-silhouette", "removed");
  await expect(host).toHaveAttribute("data-visual-theme", "dark-titanium");
  await expect(host).toHaveAttribute("data-node-language", "unified-titanium-dots");
  await expect(host).toHaveAttribute("data-node-visual-scale", "0.82");
  await expect(host).toHaveAttribute("data-node-hit-target-diameter-px", "44");
  await expect(host).toHaveAttribute("data-ambient-particle-contrast", "bright-titanium");
  await expect(host).toHaveAttribute("data-category-color-legend", "removed");
  await expect(host).toHaveAttribute("data-motion", "reduced");
  await expect(host).toHaveAttribute("data-motion-character", "anatomical-orbit");
  await expect(host).toHaveAttribute("data-auto-rotate", "disabled");
  await expect(host).toHaveAttribute("data-orbit-period-ms", "18000");
  await expect(host).toHaveAttribute("data-idle-yaw-amplitude", "0.2");
  await expect(host).toHaveAttribute("data-label-collision-policy", "selected-hovered-priority");
  await expect(host).toHaveAttribute("data-baseline-edge-detail", "restrained-visible");
  await expect(host).toHaveAttribute("data-edge-direction", "source-to-target-arrowheads");
  await expect.poll(async () => Number(await host.getAttribute("data-ambient-signal-count"))).toBeGreaterThan(0);
  await expect(host).toHaveAttribute("data-neuron-signal-count", "0");
  await expect(initialCanvas).toHaveAccessibleName(/six-region three-dimensional attack-knowledge particle cloud/u);
  await expect(page.getByLabel("Graph relationship signal legend", { exact: true })).toContainText("Knowledge path");
  await expect(page.getByLabel("Graph relationship signal legend", { exact: true })).toContainText("Failure or hazard");
  await expect(page.getByLabel("Graph relationship signal legend", { exact: true })).toContainText("Recovery path");
  await expect(page.getByLabel("Brain semantic anatomy legend", { exact: true })).toHaveCount(0);
  const regionControls = page.getByLabel("Brain region controls", { exact: true });
  for (const region of ["Frontal", "Parietal", "Temporal", "Occipital", "Cerebellum", "Brain stem"] as const) {
    await expect(regionControls.getByRole("button", { name: `Toggle ${region} region`, exact: true })).toHaveAttribute("aria-pressed", "true");
  }
  const attackKnowledgeControls = await openAdvanced(page, "keyboard");
  await expect(attackKnowledgeControls.getByRole("button", { name: /^Collapse Technology stack \(/u })).toBeVisible();
  await expect(attackKnowledgeControls.getByRole("button", { name: /^Collapse Attack vectors \(/u })).toBeVisible();

  await activate(page.getByRole("button", { name: "Accessible table", exact: true }), "keyboard");
  const table = page.getByRole("table", { name: "Accessible memory graph node list", exact: true });
  await activate(table.getByRole("row").filter({ hasText: attack.title }).getByRole("button", { name: "Inspect", exact: true }), "pointer");
  const inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
  await expect(inspector.getByRole("heading", { name: attack.title, exact: true })).toBeVisible();
  await activate(inspector.getByRole("button", { name: "Set as path start", exact: true }), "keyboard");
  await activate(table.getByRole("row").filter({ hasText: technology.title }).getByRole("button", { name: "Inspect", exact: true }), "pointer");
  await expect(inspector.getByRole("heading", { name: technology.title, exact: true })).toBeVisible();
  await activate(page.getByRole("button", { name: "Canvas view", exact: true }), "pointer");
  await waitForCanvas(page);
  await expect.poll(async () => Number(await host.getAttribute("data-neuron-signal-count"))).toBeGreaterThan(0);
  await expect.poll(async () => Number(await host.getAttribute("data-hazard-signal-count"))).toBeGreaterThan(0);
  await expect.poll(async () => Number(await host.getAttribute("data-recovery-signal-count"))).toBeGreaterThan(0);
  await expect.poll(async () => Number(await host.getAttribute("data-selected-path-edges"))).toBe(canonicalPath.length - 1);
  await expect(page.locator(".os-visually-hidden").filter({ hasText: /evidence-backed relationship paths illuminated/u })).toBeAttached();
  await expect(host).toHaveAttribute("data-motion", "reduced");
  await testInfo.attach("brain-attack-knowledge-visual-review", {
    body: await page.locator(".brain-graph-workspace").screenshot({ animations: "disabled" }),
    contentType: "image/png",
  });

  await page.emulateMedia({ reducedMotion: "no-preference" });
  await expect(host).toHaveAttribute("data-motion", "orbital");
  await expect(host).toHaveAttribute("data-auto-rotate", "enabled");
  await page.waitForTimeout(1_500);
  const orbitFrameA = await page.getByRole("application", { name: /^Memory graph with/u }).evaluate((element) => (element as HTMLCanvasElement).toDataURL());
  await page.waitForTimeout(600);
  const orbitFrameB = await page.getByRole("application", { name: /^Memory graph with/u }).evaluate((element) => (element as HTMLCanvasElement).toDataURL());
  expect(orbitFrameB, "Idle orbital parallax must produce a perceptible canvas frame change").not.toBe(orbitFrameA);

  await page.emulateMedia({ reducedMotion: "reduce" });
  await expect(host).toHaveAttribute("data-motion", "reduced");
  await page.waitForTimeout(100);
  const reducedFrameA = await page.getByRole("application", { name: /^Memory graph with/u }).evaluate((element) => (element as HTMLCanvasElement).toDataURL());
  await page.waitForTimeout(450);
  const reducedFrameB = await page.getByRole("application", { name: /^Memory graph with/u }).evaluate((element) => (element as HTMLCanvasElement).toDataURL());
  expect(reducedFrameB, "Reduced motion must freeze orbital and traveling-pulse frames").toBe(reducedFrameA);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.atlasRenderer} @brain-renderer uses WebGL2 and exercises the six-region camera and tool rail`, async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  const initialRead = graphResponse(page, (url) => url.searchParams.get("scope") === "global"
    && url.searchParams.get("limit") === "500");
  await page.goto("/brain/graph?scope=global&limit=500", { waitUntil: "domcontentloaded" });
  await graphPayload(await initialRead);
  const canvas = await waitForCanvas(page);
  const host = page.locator(".brain-canvas-host");
  await expect(host).toHaveAttribute("data-renderer", "webgl2");
  await expect(page.locator("#brain-atlas-renderer-status")).toHaveText("WebGL 2 particle renderer active");
  expect(await canvas.evaluate((element) => {
    const context = (element as HTMLCanvasElement).getContext("webgl2");
    return context?.getParameter(context.VERSION) ?? null;
  })).toContain("WebGL");

  await canvas.scrollIntoViewIfNeeded();
  const bounds = await canvas.boundingBox();
  if (!bounds) throw new Error("The WebGL canvas has no measurable bounds");
  const initialRotation = await host.getAttribute("data-camera-rotation-y");
  await page.mouse.move(bounds.x + 18, bounds.y + bounds.height * 0.52);
  await page.mouse.down();
  await page.mouse.move(bounds.x + 94, bounds.y + bounds.height * 0.52, { steps: 8 });
  await page.mouse.up();
  await expect.poll(() => host.getAttribute("data-camera-rotation-y")).not.toBe(initialRotation);

  const viewportStatus = page.locator("p[role='status']").filter({ hasText: /^Graph viewport zoom/u });
  await canvas.hover({ position: { x: 18, y: Math.floor(bounds.height * 0.52) } });
  await page.mouse.wheel(0, -100);
  await expect(viewportStatus).toContainText("110 percent");

  const temporal = page.getByRole("button", { name: "Toggle Temporal region", exact: true });
  await activate(temporal, "keyboard");
  await expect(temporal).toHaveAttribute("aria-pressed", "false");
  await expect(host).not.toHaveAttribute("data-visible-regions", /temporal/u);
  await activate(page.getByRole("button", { name: "Hide all brain regions", exact: true }), "pointer");
  await expect(host).toHaveAttribute("data-visible-regions", "");
  await activate(page.getByRole("button", { name: "Show all brain regions", exact: true }), "keyboard");
  await expect(host).toHaveAttribute("data-visible-regions", "frontal,parietal,temporal,occipital,cerebellum,stem");

  const labels = page.getByRole("button", { name: "Toggle graph labels", exact: true });
  await activate(labels, "pointer");
  await expect(labels).toHaveAttribute("aria-pressed", "false");
  await activate(page.getByRole("button", { name: "Fit", exact: true }), "keyboard");
  await expect(host).toHaveAttribute("data-camera-rotation-x", "-0.080");
  await expect(host).toHaveAttribute("data-camera-rotation-y", "0.000");
  await expect(viewportStatus).toContainText("100 percent");
});

test(`${TEST_IDS.atlasFallback} @brain-renderer preserves the same six-region interactions when WebGL2 is unavailable`, async ({ page }) => {
  await page.addInitScript(() => {
    const original = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function getContext(this: HTMLCanvasElement, contextId: string, ...argumentsList: unknown[]) {
      if (contextId === "webgl2") return null;
      return Reflect.apply(original, this, [contextId, ...argumentsList]);
    } as typeof HTMLCanvasElement.prototype.getContext;
  });
  const initialRead = graphResponse(page, (url) => url.searchParams.get("scope") === "global"
    && url.searchParams.get("limit") === "500");
  await page.goto("/brain/graph?scope=global&limit=500", { waitUntil: "domcontentloaded" });
  await graphPayload(await initialRead);
  const canvas = await waitForCanvas(page);
  const host = page.locator(".brain-canvas-host");
  await expect(host).toHaveAttribute("data-renderer", "canvas2d");
  await expect(page.locator("#brain-atlas-renderer-status")).toContainText("Canvas 2D particle renderer active");
  expect(await canvas.evaluate((element) => Boolean((element as HTMLCanvasElement).getContext("2d")))).toBe(true);
  const frontal = page.getByRole("button", { name: "Toggle Frontal region", exact: true });
  await activate(frontal, "pointer");
  await expect(frontal).toHaveAttribute("aria-pressed", "false");
  await activate(page.getByRole("button", { name: "Show all brain regions", exact: true }), "pointer");
  await expect(frontal).toHaveAttribute("aria-pressed", "true");
});

test("renders a visibly changing 1,000-node bounded brain without dropping below the browser motion gate", async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.route(`**${GRAPH_API_PATH}?**`, async (route) => {
    const response = await route.fetch();
    const payload = await response.json() as MemoryGraph | { readonly data: MemoryGraph };
    const graph = "data" in payload ? payload.data : payload;
    const baseNode = graph.nodes[0];
    if (!baseNode) throw new Error("The canonical graph fixture must contain a node template");
    const nodeTypes = [
      "technology_product", "exact_version_fingerprint", "discovery_pattern",
      "attack_vector", "cve", "script_artifact", "operational_hazard",
      "recovery_pattern", "lesson",
    ] as const;
    const nodes = Array.from({ length: 1_000 }, (_, index) => ({
      ...baseNode,
      id: `perf-node-${String(index).padStart(4, "0")}`,
      nodeType: nodeTypes[index % nodeTypes.length],
      title: `Bounded graph performance node ${index + 1}`,
      summary: "Sanitized browser-only rendering fixture",
      scope: { kind: "global" as const },
      sensitivity: "internal" as const,
      lifecycleStatus: "verified" as const,
      confirmationState: "confirmed" as const,
      edgeCount: index === 0 || index === 999 ? 1 : 2,
      sourceCount: 1,
    }));
    const edges = Array.from({ length: 999 }, (_, index) => ({
      id: `perf-edge-${String(index).padStart(4, "0")}`,
      sourceNodeId: nodes[index]!.id,
      targetNodeId: nodes[index + 1]!.id,
      edgeType: "supports" as const,
      title: "supports",
      summary: "Browser-only bounded rendering relationship",
      confidence: 1,
      lifecycleStatus: "verified" as const,
      explanation: "This relationship exists only in the isolated browser rendering fixture.",
    }));
    const largeGraph: MemoryGraph = {
      ...graph,
      nodes,
      edges,
      availableNodeCount: nodes.length,
      truncated: false,
    };
    await route.fulfill({
      response,
      json: "data" in payload ? { ...payload, data: largeGraph } : largeGraph,
    });
  });

  await page.goto("/brain/graph?scope=global&limit=1000", { waitUntil: "domcontentloaded" });
  const canvas = await waitForCanvas(page);
  const host = page.locator(".brain-canvas-host");
  await expect(host).toHaveAttribute("data-motion", "orbital");
  await expect(canvas).toHaveAccessibleName(/Memory graph with 1000 nodes and 999 typed, directed relationships/u);
  await page.waitForTimeout(1_500);

  const result = await canvas.evaluate(async (element) => {
    const target = element as HTMLCanvasElement;
    const signature = () => target.toDataURL("image/png").slice(-2_000);
    return await new Promise<{ distinctFrames: number; p95FrameMs: number }>((resolve) => {
      const signatures = new Set<string>();
      const intervals: number[] = [];
      const started = performance.now();
      let previous = started;
      const sample = (now: number) => {
        signatures.add(signature());
        intervals.push(now - previous);
        previous = now;
        if (now - started < 1_200) {
          requestAnimationFrame(sample);
          return;
        }
        const ordered = intervals.slice(1).sort((left, right) => left - right);
        resolve({
          distinctFrames: signatures.size,
          p95FrameMs: ordered[Math.min(ordered.length - 1, Math.floor(ordered.length * 0.95))] ?? Number.POSITIVE_INFINITY,
        });
      };
      requestAnimationFrame(sample);
    });
  });
  await testInfo.attach("brain-graph-1000-node-motion-metrics", {
    body: Buffer.from(JSON.stringify(result, null, 2)),
    contentType: "application/json",
  });
  expect(result.distinctFrames, "The 1,000-node canvas must visibly advance during the orbit").toBeGreaterThanOrEqual(18);
  expect(result.p95FrameMs, "Browser animation p95 must remain interactive at the 1,000-node limit").toBeLessThan(50);
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
    await page.emulateMedia({ reducedMotion: "reduce" });
    const initialRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId
      && url.searchParams.get("limit") === "500");
    await page.goto(graphRoute({ limit: "500" }), { waitUntil: "domcontentloaded" });
    expect((await graphPayload(await initialRead)).nodes).toHaveLength(fixture.nodeCount);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    await waitForCanvas(page);
    await page.mouse.move(0, 0);
    await expectApprovedGraphVisual(page.locator(".brain-graph-workspace"), testInfo, GRAPH_VISUALS.canvas);

    await activate(page.getByRole("button", { name: "Accessible table", exact: true }), "keyboard");
    const table = page.getByRole("table", { name: "Accessible memory graph node list", exact: true });
    await expect(table).toBeVisible();
    await expect(table.getByRole("row")).toHaveCount(fixture.nodeCount + 1);
    await page.mouse.move(0, 0);
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

test(`${TEST_IDS.deepLinksHistory} and ${TEST_IDS.canvasTableInspector} record both modalities for Context Pack and inspector navigation`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(180_000);
  await page.emulateMedia({ reducedMotion: "reduce" });

  for (const modality of ["pointer", "keyboard"] as const) {
    const destination = graphRoute({ limit: "500" });
    const initialRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId
      && url.searchParams.get("limit") === "500");
    if (page.url() === "about:blank") {
      await page.goto(destination, { waitUntil: "domcontentloaded" });
    } else {
      await browserAudit.withExpectedDocumentNavigationTeardown(
        page,
        () => page.goto(destination, { waitUntil: "domcontentloaded" }),
      );
    }
    expect((await graphPayload(await initialRead)).nodes).toHaveLength(fixture.nodeCount);
    await selectPreferenceInTable(page, modality);
    let inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
    let contextControl = inspector.getByRole("button", {
      name: /Adapt the represented Guided explanation to the confirmed evidence-first preference/u,
    });

    const contextRead = page.waitForResponse((response) => response.request().method() === "GET"
      && pathname(response) === `/api/v2/brain/context-packs/${fixture.contextPackId}`
      && response.status() === 200);
    await recordGraphActivation(
      interactionActivation,
      "brain.graph.context.toggle",
      "Open Context Pack",
      modality,
      TEST_IDS.deepLinksHistory,
      async () => {
        await activate(contextControl, modality);
        expect((await contextRead).status()).toBe(200);
        await expect(inspector.getByRole("heading", {
          name: "Adapt the represented Guided explanation to the confirmed evidence-first preference",
          exact: true,
        })).toBeVisible();
      },
    );
    await recordGraphActivation(
      interactionActivation,
      "brain.graph.context.toggle",
      "Close Context Pack",
      modality,
      TEST_IDS.deepLinksHistory,
      async () => {
        await activate(contextControl, modality);
        await expect(inspector.getByRole("heading", {
          name: "Adapt the represented Guided explanation to the confirmed evidence-first preference",
          exact: true,
        })).toHaveCount(0);
      },
    );

    // Reopen the already fetched pack so its two stable deep links can be
    // exercised independently without manufacturing another memory record.
    await activate(contextControl, modality);
    await expect(inspector.getByRole("heading", {
      name: "Adapt the represented Guided explanation to the confirmed evidence-first preference",
      exact: true,
    })).toBeVisible();
    const graphBeforeNode = page.url();
    const contextNodeRead = page.waitForResponse((response) => response.request().method() === "GET"
      && pathname(response) === `/api/v2/brain/nodes/${fixture.preferenceNodeId}`
      && response.status() === 200);
    await recordGraphActivation(
      interactionActivation,
      "brain.graph.context.node-link",
      "Open the exact Context Pack memory node",
      modality,
      TEST_IDS.deepLinksHistory,
      async () => {
        await activate(inspector.getByRole("link", { name: fixture.preferenceTitle, exact: true }), modality);
        expect((await contextNodeRead).status()).toBe(200);
        await expect(page).toHaveURL(`/brain/nodes/${fixture.preferenceNodeId}`);
        await expect(page.getByRole("heading", { name: fixture.preferenceTitle, exact: true }).first()).toBeVisible();
      },
    );
    await browserAudit.withExpectedHistoryTraversal(
      page,
      () => page.goBack({ waitUntil: "domcontentloaded" }),
    );
    await expect(page).toHaveURL(graphBeforeNode);
    await expect(page.getByRole("heading", { name: "Memory Graph", exact: true })).toBeVisible();
    await selectPreferenceInTable(page, modality);
    inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
    contextControl = inspector.getByRole("button", {
      name: /Adapt the represented Guided explanation to the confirmed evidence-first preference/u,
    });
    await activate(contextControl, modality);
    await expect(inspector.getByRole("link", { name: "Show memory path", exact: true })).toBeVisible();

    const contextPathRead = graphResponse(page, (url) => url.searchParams.get("view") === "local"
      && url.searchParams.get("nodeId") === fixture.preferenceNodeId);
    await recordGraphActivation(
      interactionActivation,
      "brain.graph.context.path-link",
      "Open local graph rooted at the first used memory and select the last used memory",
      modality,
      TEST_IDS.deepLinksHistory,
      async () => {
        await activate(inspector.getByRole("link", { name: "Show memory path", exact: true }), modality);
        const localGraph = await graphPayload(await contextPathRead);
        expect(localGraph.rootNodeId).toBe(fixture.preferenceNodeId);
        await expect(page).toHaveURL((url) => url.pathname === "/brain/graph"
          && url.searchParams.get("root") === fixture.preferenceNodeId
          && url.searchParams.get("selected") === fixture.preferenceNodeId);
      },
    );

    inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
    const fullRecordRead = page.waitForResponse((response) => response.request().method() === "GET"
      && pathname(response) === `/api/v2/brain/nodes/${fixture.preferenceNodeId}`
      && response.status() === 200);
    await recordGraphActivation(
      interactionActivation,
      "brain.graph.inspector.full-record",
      "Open canonical memory node detail",
      modality,
      TEST_IDS.deepLinksHistory,
      async () => {
        await activate(inspector.getByRole("link", { name: "Full memory record", exact: true }), modality);
        expect((await fullRecordRead).status()).toBe(200);
        await expect(page).toHaveURL(`/brain/nodes/${fixture.preferenceNodeId}`);
      },
    );

    await recordGraphActivation(
      interactionActivation,
      "brain.node.show-in-graph",
      "Open local graph rooted at this exact node",
      modality,
      TEST_IDS.deepLinksHistory,
      async () => {
        await activate(page.getByRole("button", { name: "Show in graph", exact: true }), modality);
        await expect(page).toHaveURL((url) => url.pathname === "/brain/graph"
          && url.searchParams.get("root") === fixture.preferenceNodeId
          && url.searchParams.get("selected") === fixture.preferenceNodeId);
        await expect(page.locator(".brain-active-filter").filter({ hasText: "Local neighborhood" }))
          .toContainText(fixture.preferenceNodeId);
      },
    );

    inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
    await recordGraphActivation(
      interactionActivation,
      "brain.graph.inspector.path-start",
      "Set selected node as path start",
      modality,
      TEST_IDS.canvasTableInspector,
      async () => {
        await activate(inspector.getByRole("button", { name: "Set as path start", exact: true }), modality);
        await expect.poll(() => new URL(page.url()).searchParams.get("pathFrom")).toBe(fixture.preferenceNodeId);
      },
    );
    await recordGraphActivation(
      interactionActivation,
      "brain.graph.inspector.path-start",
      "Clear path start",
      modality,
      TEST_IDS.canvasTableInspector,
      async () => {
        await activate(inspector.getByRole("button", { name: "Clear path start", exact: true }), modality);
        await expect.poll(() => new URL(page.url()).searchParams.get("pathFrom")).toBeNull();
      },
    );

    const globalDestination = graphRoute({ limit: "500" });
    const globalRead = graphResponse(page, (url) => url.searchParams.get("engagementId") === fixture.engagementId
      && url.searchParams.get("limit") === "500"
      && !url.searchParams.has("nodeId"));
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.goto(globalDestination, { waitUntil: "domcontentloaded" }),
    );
    await graphPayload(await globalRead);
    await selectPreferenceInTable(page, modality);
    inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
    const openLocalRead = graphResponse(page, (url) => url.searchParams.get("view") === "local"
      && url.searchParams.get("nodeId") === fixture.preferenceNodeId);
    await recordGraphActivation(
      interactionActivation,
      "brain.graph.inspector.open-local",
      "Use selected node as the local graph root",
      modality,
      TEST_IDS.canvasTableInspector,
      async () => {
        await activate(inspector.getByRole("button", { name: "Open local graph", exact: true }), modality);
        expect((await graphPayload(await openLocalRead)).rootNodeId).toBe(fixture.preferenceNodeId);
        await expect(page.locator(".brain-active-filter").filter({ hasText: "Local neighborhood" }))
          .toContainText(fixture.preferenceNodeId);
      },
    );
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

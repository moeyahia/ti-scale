import {
  parseAttackKnowledgeVaultPresetPreview,
  parseMemoryGraph,
  parseBrainSummary,
  parseVaultSnapshot,
} from "../../src/domain/schemas/brain";
import { parseMissionPage, parseOverview } from "../../src/domain/schemas/commandOs";
import { parseRunPage } from "../../src/domain/schemas/runtimeV2";
import type { MemoryGraph, MemoryNodeSummary } from "../../src/domain/types/brain";
import { layoutGraph, nodeCluster, type GraphCluster } from "../../src/features/brain/graphUtils";
import { journeyModeLabel, projectJourneyReadiness } from "../../src/features/overview/journeyReadiness";
import type { BrowserAuditController } from "./support/browserAudit";
import { expect, test, type Page } from "./support/playwright";

const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const LEFT_HEMISPHERE_CLUSTERS = new Set<GraphCluster>(["other", "evidence"]);
const RIGHT_HEMISPHERE_CLUSTERS = new Set<GraphCluster>(["attack", "tool"]);

function crossLobePath(graph: MemoryGraph): MemoryNodeSummary[] {
  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  const titleCounts = graph.nodes.reduce((counts, node) => {
    counts.set(node.title, (counts.get(node.title) ?? 0) + 1);
    return counts;
  }, new Map<string, number>());
  const selectableLeft = graph.nodes.filter((node) => (
    LEFT_HEMISPHERE_CLUSTERS.has(nodeCluster(node))
    && titleCounts.get(node.title) === 1
  ));
  const selectableRight = new Set(graph.nodes.filter((node) => (
    RIGHT_HEMISPHERE_CLUSTERS.has(nodeCluster(node))
    && titleCounts.get(node.title) === 1
  )).map((node) => node.id));
  const adjacency = new Map<string, string[]>();
  graph.edges.forEach((edge) => {
    if (!nodesById.has(edge.sourceNodeId) || !nodesById.has(edge.targetNodeId)) return;
    adjacency.set(edge.sourceNodeId, [...(adjacency.get(edge.sourceNodeId) ?? []), edge.targetNodeId]);
    adjacency.set(edge.targetNodeId, [...(adjacency.get(edge.targetNodeId) ?? []), edge.sourceNodeId]);
  });
  const queue = selectableLeft.map((node) => node.id);
  const previous = new Map<string, string | null>(queue.map((id) => [id, null]));
  let destination: string | undefined;
  while (queue.length > 0 && !destination) {
    const current = queue.shift()!;
    for (const neighbor of adjacency.get(current) ?? []) {
      if (previous.has(neighbor)) continue;
      previous.set(neighbor, current);
      if (selectableRight.has(neighbor)) {
        destination = neighbor;
        break;
      }
      queue.push(neighbor);
    }
  }
  if (!destination) {
    throw new Error("No canonical relationship path connects a uniquely selectable technology/discovery memory to an attack/execution memory");
  }
  const ids = [destination];
  let cursor = previous.get(destination) ?? null;
  while (cursor) {
    ids.push(cursor);
    cursor = previous.get(cursor) ?? null;
  }
  return ids.reverse().map((id) => nodesById.get(id)!);
}

function average(values: readonly number[]): number {
  if (values.length === 0) throw new Error("Cannot calculate an empty hemisphere centroid");
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

async function readJson(page: Page, browserAudit: BrowserAuditController, path: string): Promise<unknown> {
  const response = await browserAudit.request(page.request, {
    method: "GET",
    url: path,
    options: { headers: { Accept: "application/json" } },
  });
  expect(response.status(), `Read-only live endpoint must resolve: ${path}`).toBe(200);
  return response.json() as Promise<unknown>;
}

test("authenticates and proves the promoted particle Brain, Attack Knowledge Vault, and durable mission links without mutation", async ({ page, browserAudit }, testInfo) => {
  const mutationAttempts: string[] = [];
  await page.route("**/api/v2/**", async (route) => {
    const method = route.request().method().toUpperCase();
    if (READ_METHODS.has(method)) {
      await route.continue();
      return;
    }
    mutationAttempts.push(`${method} ${new URL(route.request().url()).pathname}`);
    await route.abort("blockedbyclient");
  });

  const documentResponse = await page.goto("/", { waitUntil: "domcontentloaded" });
  expect(documentResponse?.status()).toBe(200);
  await expect(page.locator("main#ti-scale-content")).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Enter Ti-Scale", exact: true })).toHaveCount(0);

  const session = await readJson(page, browserAudit, "/api/v2/auth/session") as Record<string, unknown>;
  expect(session.authenticated).toBe(true);
  expect(typeof session.actorId).toBe("string");

  const overview = parseOverview(await readJson(page, browserAudit, "/api/v2/overview"));
  expect(overview.readiness.checks.length).toBeGreaterThan(0);
  const journeys = projectJourneyReadiness(overview.readiness.checks);
  const readinessBand = page.locator(".os-readiness-band");
  await expect(readinessBand).toBeVisible();
  await expect(readinessBand).toContainText(`Autonomous: ${journeyModeLabel(journeys.autonomous.mode)}`);
  await expect(readinessBand).toContainText(`Guided: ${journeyModeLabel(journeys.guided.mode)}`);

  const vault = parseVaultSnapshot(await readJson(page, browserAudit, "/api/v2/brain/vault"));
  const attackVaults = vault.connections.filter((connection) => (
    connection.displayName === "Ti-Scale Attack Knowledge Vault"
    && connection.vaultPath === "Attack-Knowledge-Vault"
  ));
  const healthyAttackVaults = attackVaults.filter((connection) => (
    connection.status === "connected"
    && connection.pathAvailable !== false
    && connection.healthChecks?.write === true
    && connection.healthChecks.read === true
    && connection.healthChecks.rename === true
    && connection.healthChecks.delete === true
  ));
  const genericVaults = vault.connections.filter((connection) => (
    connection.displayName === "Ti-Scale-Brain"
    || connection.vaultPath === "Ti-Scale-Brain"
  ));
  expect(vault.enabled).toBe(true);
  expect(attackVaults).toHaveLength(1);
  expect(healthyAttackVaults).toHaveLength(1);
  expect(genericVaults.length).toBeGreaterThanOrEqual(1);
  expect(genericVaults.every((connection) => connection.status === "disconnected")).toBe(true);
  const attackVault = healthyAttackVaults[0]!;
  const configuredLifecycleStatuses = Array.isArray(attackVault.syncScope.lifecycleStatuses)
    ? attackVault.syncScope.lifecycleStatuses.filter((value): value is string => typeof value === "string")
    : [];
  const configuredNodeTypes = Array.isArray(attackVault.syncScope.nodeTypes)
    ? attackVault.syncScope.nodeTypes.filter((value): value is string => typeof value === "string")
    : [];
  const configuredOperatorIds = Array.isArray(attackVault.syncScope.operatorIds)
    ? attackVault.syncScope.operatorIds.filter((value): value is string => typeof value === "string")
    : [];
  const includeConfirmed = configuredLifecycleStatuses.includes("confirmed");
  const includeOperatorProfile = includeConfirmed
    && configuredNodeTypes.includes("operator")
    && configuredNodeTypes.includes("preference")
    && configuredOperatorIds.length === 1;
  const preset = parseAttackKnowledgeVaultPresetPreview(await readJson(
    page,
    browserAudit,
    `/api/v2/brain/vault/attack-knowledge-preset?includeConfirmed=${includeConfirmed ? "true" : "false"}&includeOperatorProfile=${includeOperatorProfile ? "true" : "false"}`,
  ));
  expect(preset.enabled).toBe(true);
  expect(preset.alreadyActiveConnectionId).toBe(attackVault.id);
  expect(preset.activePreset).toMatchObject({
    connectionId: attackVault.id,
    includeConfirmed,
    includeOperatorProfile,
  });
  expect(preset.projection.operatorProfileIncluded).toBe(includeOperatorProfile);
  expect(preset.projection.policyEligibleNodeCount).toBeGreaterThan(3);
  expect(attackVault.trackedNoteCount ?? 0).toBeGreaterThanOrEqual(preset.projection.policyEligibleNodeCount);
  expect(attackVault.needsReviewCount).toBe(0);
  expect(attackVault.syncScope).toMatchObject({
    nodeTypes: preset.projection.nodeTypes,
    scopeKinds: ["global"],
    lifecycleStatuses: preset.projection.lifecycleStatuses,
    sensitivities: preset.projection.sensitivities,
  });
  expect(preset.projection.sensitivities).not.toContain("restricted");
  expect(vault.conflicts.filter((conflict) => (
    conflict.connectionId === attackVault.id && conflict.status === "open"
  ))).toEqual([]);
  const attackVaultSyncStates = vault.syncStates.filter((item) => item.connectionId === attackVault.id);
  expect(attackVaultSyncStates.length).toBeGreaterThan(0);
  expect(attackVaultSyncStates.filter((item) => (
    ["conflict", "quarantined", "error"].includes(item.status)
  ))).toEqual([]);

  const vaultDocument = await page.goto("/brain/vault", { waitUntil: "domcontentloaded" });
  expect(vaultDocument?.status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1, name: "Obsidian Vault", exact: true })).toBeVisible();
  const activeVaults = page.getByRole("region", { name: "Active Obsidian Vaults", exact: true });
  await expect(activeVaults).toBeVisible();
  await expect(activeVaults.getByRole("heading", { level: 2, name: attackVault.vaultPath, exact: true })).toBeVisible();
  const retiredVaults = page.getByRole("region", { name: "Retired Vault connections", exact: true });
  await expect(retiredVaults).toBeVisible();
  await expect(retiredVaults.getByRole("heading", { level: 2, name: "Ti-Scale-Brain", exact: true })).toBeVisible();
  await expect(page.getByText("Attack Knowledge Vault is active", { exact: true })).toBeVisible();

  const brain = parseBrainSummary(await readJson(page, browserAudit, "/api/v2/brain/summary"));
  const graph = parseMemoryGraph(await readJson(
    page,
    browserAudit,
    "/api/v2/brain/graph?view=global&scope=global&status=verified&limit=1000",
  ));
  expect(graph.availableNodeCount).toBeGreaterThan(3);
  expect(graph.edges.length).toBeGreaterThan(0);
  expect(brain.counts.edges).toBeGreaterThan(0);
  const leftNodes = graph.nodes.filter((node) => LEFT_HEMISPHERE_CLUSTERS.has(nodeCluster(node)));
  const rightNodes = graph.nodes.filter((node) => RIGHT_HEMISPHERE_CLUSTERS.has(nodeCluster(node)));
  expect(leftNodes.length, "The technology/discovery hemisphere must be populated").toBeGreaterThan(1);
  expect(rightNodes.length, "The attack/execution hemisphere must be populated").toBeGreaterThan(1);
  const semanticPath = crossLobePath(graph);
  expect(LEFT_HEMISPHERE_CLUSTERS.has(nodeCluster(semanticPath[0]!))).toBe(true);
  expect(RIGHT_HEMISPHERE_CLUSTERS.has(nodeCluster(semanticPath.at(-1)!))).toBe(true);
  expect(semanticPath.length).toBeGreaterThan(1);

  const graphDocument = await page.goto("/brain/graph?scope=global&lifecycle=verified&limit=1000", { waitUntil: "domcontentloaded" });
  expect(graphDocument?.status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1, name: "Memory Graph", exact: true })).toBeVisible();
  await expect(page.locator(".brain-graph-meta")).toContainText(
    `${new Intl.NumberFormat("en-US").format(graph.availableNodeCount)} accessible in this view`,
  );
  const graphHost = page.locator(".brain-canvas-host");
  const graphCanvas = page.getByRole("application", { name: /^Memory graph with/u });
  await expect(graphHost).toHaveAttribute("data-brain-anatomy", "particle-cloud-3d");
  await expect(graphHost).toHaveAttribute("data-region-taxonomy", "attack-knowledge");
  await expect(graphHost).toHaveAttribute("data-background-grid", "removed");
  await expect(graphHost).toHaveAttribute("data-background-artwork", "removed");
  await expect(graphHost).toHaveAttribute("data-anatomy-silhouette", "removed");
  await expect(graphHost).toHaveAttribute("data-spinal-silhouette", "removed");
  await expect(graphHost).toHaveAttribute("data-visual-theme", "dark-titanium");
  await expect(graphHost).toHaveAttribute("data-node-language", "unified-titanium-dots");
  await expect(graphHost).toHaveAttribute("data-motion", "orbital");
  await expect(graphHost).toHaveAttribute("data-orbit-period-ms", "18000");
  await expect(graphCanvas).toHaveAttribute("aria-busy", "false");
  await expect(graphCanvas).toHaveAccessibleName(/six-region three-dimensional attack-knowledge particle cloud/u);
  const regionControls = page.getByLabel("Brain region controls", { exact: true });
  for (const region of ["Frontal", "Parietal", "Temporal", "Occipital", "Cerebellum", "Brain stem"] as const) {
    await expect(regionControls.getByRole("button", { name: `Toggle ${region} region`, exact: true }))
      .toHaveAttribute("aria-pressed", "true");
  }
  const hostBox = await graphHost.boundingBox();
  if (!hostBox) throw new Error("The particle graph host has no rendered bounds");
  const semanticLayout = layoutGraph(graph.nodes, Math.floor(hostBox.width), Math.floor(hostBox.height));
  const leftCentroid = average(semanticLayout.filter((point) => (
    LEFT_HEMISPHERE_CLUSTERS.has(point.cluster)
  )).map((point) => point.x));
  const rightCentroid = average(semanticLayout.filter((point) => (
    RIGHT_HEMISPHERE_CLUSTERS.has(point.cluster)
  )).map((point) => point.x));
  expect(leftCentroid, "Technology/discovery must occupy the left semantic hemisphere").toBeLessThan(hostBox.width * 0.48);
  expect(rightCentroid, "Attack/execution must occupy the right semantic hemisphere").toBeGreaterThan(hostBox.width * 0.52);
  expect(rightCentroid - leftCentroid, "The two semantic lobes must remain visibly separated").toBeGreaterThan(hostBox.width * 0.15);
  await page.waitForTimeout(1_500);
  const orbitFrameA = await graphCanvas.evaluate((element) => (element as HTMLCanvasElement).toDataURL());
  await page.waitForTimeout(600);
  const orbitFrameB = await graphCanvas.evaluate((element) => (element as HTMLCanvasElement).toDataURL());
  expect(orbitFrameB, "The deployed bilateral graph must visibly advance while idle").not.toBe(orbitFrameA);

  const pathStart = semanticPath[0]!;
  const pathEnd = semanticPath.at(-1)!;
  await page.getByRole("button", { name: "Accessible table", exact: true }).click();
  const graphTable = page.getByRole("table", { name: "Accessible memory graph node list", exact: true });
  const pathStartRow = graphTable
    .getByRole("row")
    .filter({ hasText: pathStart.title })
    .first();
  await pathStartRow.getByRole("button", { name: "Inspect", exact: true }).click();
  await expect.poll(() => new URL(page.url()).searchParams.get("selected")).toBe(pathStart.id);
  const inspector = page.getByRole("complementary", { name: "Selected memory details", exact: true });
  await expect(inspector.getByRole("heading", { name: pathStart.title, exact: true })).toBeVisible();
  await inspector.getByRole("button", { name: "Set as path start", exact: true }).click();
  await expect.poll(() => new URL(page.url()).searchParams.get("pathFrom")).toBe(pathStart.id);
  const pathEndRow = graphTable
    .getByRole("row")
    .filter({ hasText: pathEnd.title })
    .first();
  await pathEndRow.getByRole("button", { name: "Inspect", exact: true }).click();
  await expect.poll(() => new URL(page.url()).searchParams.get("selected")).toBe(pathEnd.id);
  await expect(inspector.getByRole("heading", { name: pathEnd.title, exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Canvas view", exact: true }).click();
  await expect.poll(async () => Number(await graphHost.getAttribute("data-neuron-signal-count"))).toBeGreaterThan(0);
  await expect.poll(async () => Number(await graphHost.getAttribute("data-selected-path-edges"))).toBe(semanticPath.length - 1);
  await expect(page.locator(".os-visually-hidden").filter({
    hasText: `Shortest memory path contains ${semanticPath.length} nodes`,
  })).toBeAttached();
  await testInfo.attach("live-particle-second-brain", {
    body: await page.screenshot({ fullPage: true, animations: "allow" }),
    contentType: "image/png",
  });

  const runs = parseRunPage(await readJson(page, browserAudit, "/api/v2/runs?limit=50"));
  expect(runs.items.length).toBeGreaterThan(0);
  const run = runs.items[0]!;
  const missions = parseMissionPage(await readJson(
    page,
    browserAudit,
    `/api/v2/missions?query=${encodeURIComponent(run.missionId)}&limit=50`,
  ));
  expect(missions.items.some((mission) => mission.id === run.missionId)).toBe(true);
  const missionRuntime = await browserAudit.request(page.request, {
    method: "GET",
    url: `/api/v2/missions/${encodeURIComponent(run.missionId)}/runtime`,
  });
  expect(missionRuntime.status()).toBe(200);
  const runRuntime = await browserAudit.request(page.request, {
    method: "GET",
    url: `/api/v2/runs/${encodeURIComponent(run.id)}`,
  });
  expect(runRuntime.status()).toBe(200);

  const deepLink = `/missions/${encodeURIComponent(run.missionId)}/runs/${encodeURIComponent(run.id)}`;
  const runDocument = await page.goto(deepLink, { waitUntil: "domcontentloaded" });
  expect(runDocument?.status()).toBe(200);
  await expect(page).toHaveURL((url) => url.pathname === deepLink);
  await expect(page.getByRole("heading", { level: 1, name: run.missionName, exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Selected run status", exact: true })).toBeVisible();

  expect(mutationAttempts).toEqual([]);
});

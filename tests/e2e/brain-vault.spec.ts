import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { expect, test, type Locator, type Page, type TestInfo } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import {
  correctBrainVaultCanonicalNode,
  createBrainVaultFixture,
  createBrainVaultOperationsFixture,
  damageBrainVaultForRecovery,
  editBrainVaultProjection,
  markBrainVaultConnectionDegraded,
  readBrainVaultFixture,
  readBrainVaultOperationsState,
  restoreBrainVaultOnline,
  scopeBrainVaultConnection,
  takeBrainVaultOffline,
  type BrainVaultFixture,
} from "./support/brainVaultFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_IDS = {
  roundTrip: "e2e.brain-vault.round-trip-connect-reload",
  pathRetry: "e2e.brain-vault.path-denial-retry",
  projectionLifecycle: "e2e.brain-vault.sync-import-export-portable",
  conflicts: "e2e.brain-vault.conflict-resolution",
  degradedRecovery: "e2e.brain-vault.degraded-recovery",
  recovery: "e2e.brain-vault.repair-reindex-recovery",
} as const;

const VISUAL_PROJECT = "chromium-1440";
const VISUAL_BASELINES = {
  connected: {
    id: "visual.brain-vault.connected.chromium-1440",
    snapshot: "brain-vault-connected-card.png",
  },
  pathDenied: {
    id: "visual.brain-vault.path-denied.chromium-1440",
    snapshot: "brain-vault-path-denied.png",
  },
  conflicts: {
    id: "visual.brain-vault.conflicts-open.chromium-1440",
    snapshot: "brain-vault-conflicts-open.png",
  },
  repair: {
    id: "visual.brain-vault.repair-receipt.chromium-1440",
    snapshot: "brain-vault-repair-receipt.png",
  },
  reindex: {
    id: "visual.brain-vault.reindex-receipt.chromium-1440",
    snapshot: "brain-vault-reindex-receipt.png",
  },
  recovered: {
    id: "visual.brain-vault.recovered.chromium-1440",
    snapshot: "brain-vault-recovered-card.png",
  },
} as const;

async function expectApprovedVisual(
  locator: Locator,
  testInfo: TestInfo,
  baseline: (typeof VISUAL_BASELINES)[keyof typeof VISUAL_BASELINES],
) {
  if (testInfo.project.name !== VISUAL_PROJECT) return;
  await locator.page().evaluate(async () => { await document.fonts.ready; });
  await expect(locator).toHaveScreenshot(baseline.snapshot, {
    animations: "disabled",
    caret: "hide",
    maxDiffPixels: 0,
    threshold: 0.15,
  });
}

async function normalizeConnectionCardVisual(connectionCard: Locator) {
  await connectionCard.evaluate((node) => {
    for (const sibling of node.parentElement?.children ?? []) {
      if (sibling !== node) (sibling as HTMLElement).style.display = "none";
    }
  });
  await connectionCard.locator("header .os-eyebrow").evaluate((node) => {
    node.textContent = "Disposable Vault approved visual fixture";
  });
  await connectionCard.locator("header h2").evaluate((node) => {
    node.textContent = "Disposable-Vault-approved-visual-fixture";
  });
  const values = connectionCard.locator("dl dd");
  await values.nth(0).evaluate((node) => { node.textContent = "Jul 16, 2099, 10:00 PM UTC"; });
  await values.nth(1).evaluate((node) => { node.textContent = "Jul 16, 2099, 10:00 PM UTC"; });
  await values.nth(2).evaluate((node) => { node.textContent = "Not synchronized yet"; });
}

async function stableConnectionCardVisual(page: Page, vaultPath: string): Promise<Locator> {
  const cards = page.locator(".brain-vault-connections > .os-card");
  const index = await cards.evaluateAll((nodes, expectedPath) => nodes.findIndex((node) => (
    node.querySelector("header h2")?.textContent === expectedPath
  )), vaultPath);
  if (index < 0) throw new Error(`Unable to locate connected Vault card for approved visual: ${vaultPath}`);
  return cards.nth(index);
}

async function normalizePathDeniedVisual(alert: Locator): Promise<() => Promise<void>> {
  const trace = alert.getByText(/^Trace /u);
  const originalTrace = await trace.count() === 1 ? await trace.innerText() : undefined;
  if (await trace.count() === 1) {
    await trace.evaluate((node) => { node.textContent = "Trace visual-baseline-receipt"; });
  }
  const activeVaults = alert.page().locator(".brain-vault-active");
  const restoreContext = await hideVisualContext(activeVaults);
  return async () => {
    if (originalTrace !== undefined && await trace.count() === 1) {
      await trace.evaluate((node, text) => { node.textContent = text; }, originalTrace);
    }
    await restoreContext();
  };
}

async function hideOperationToastForVisual(page: Page) {
  const toast = page.locator(".brain-operation-toast");
  if (await toast.count() === 1) {
    await toast.evaluate((node) => { (node as HTMLElement).style.visibility = "hidden"; });
  }
}

async function hideVisualContext(elements: Locator): Promise<() => Promise<void>> {
  const displays = await elements.evaluateAll((nodes) => nodes.map((node) => (node as HTMLElement).style.display));
  await elements.evaluateAll((nodes) => {
    for (const node of nodes) (node as HTMLElement).style.display = "none";
  });
  return async () => {
    await elements.evaluateAll((nodes, priorDisplays) => {
      nodes.forEach((node, index) => { (node as HTMLElement).style.display = priorDisplays[index] ?? ""; });
    }, displays);
  };
}

async function normalizeConflictVisual(conflictsCard: Locator): Promise<() => Promise<void>> {
  const articles = conflictsCard.locator("article");
  const articleCount = await articles.count();
  const originals: Array<{ path: string; detected: string; database?: string; vault?: string }> = [];
  for (let index = 0; index < articleCount; index += 1) {
    const article = articles.nth(index);
    const previews = article.locator("pre");
    const previewCount = await previews.count();
    originals.push({
      path: await article.locator("header strong").innerText(),
      detected: await article.locator("header small").innerText(),
      ...(previewCount > 0 ? { database: await previews.nth(0).innerText() } : {}),
      ...(previewCount > 1 ? { vault: await previews.nth(1).innerText() } : {}),
    });
    await article.locator("header strong").evaluate((node, position) => {
      node.textContent = `40 Attack Plans/visual-conflict-${Number(position) + 1}.md`;
    }, index);
    await article.locator("header small").evaluate((node) => {
      node.textContent = "Detected Jul 16, 2099, 10:00 PM UTC";
    });
    if (previewCount > 0) {
      await previews.nth(0).evaluate((node, position) => {
        node.textContent = `Canonical version ${Number(position) + 1} retained for operator review.`;
      }, index);
    }
    if (previewCount > 1) {
      await previews.nth(1).evaluate((node, position) => {
        node.textContent = `Obsidian version ${Number(position) + 1} retained for operator review.`;
      }, index);
    }
  }
  return async () => {
    for (let index = 0; index < originals.length; index += 1) {
      const article = articles.nth(index);
      const original = originals[index]!;
      await article.locator("header strong").evaluate((node, text) => { node.textContent = text; }, original.path);
      await article.locator("header small").evaluate((node, text) => { node.textContent = text; }, original.detected);
      if (original.database !== undefined) {
        await article.locator("pre").nth(0).evaluate((node, text) => { node.textContent = text; }, original.database);
      }
      if (original.vault !== undefined) {
        await article.locator("pre").nth(1).evaluate((node, text) => { node.textContent = text; }, original.vault);
      }
    }
  };
}

// The Vault snapshot intentionally lists every connection in the isolated
// database. Keep this file serial within each browser project so one test's
// connection lifecycle cannot become another test's pre-mutation read.
test.describe.configure({ mode: "serial" });
test.setTimeout(60_000);

async function connectFixture(page: Page, fixture: BrainVaultFixture) {
  await page.goto("/brain/vault");
  await expect(page.getByRole("heading", { level: 1, name: "Obsidian Vault" })).toBeVisible();
  await page.getByLabel("Display name").fill(fixture.displayName);
  await page.getByLabel("Path inside the allowed root").fill(fixture.relativePath);
  await page.getByLabel("Grant explicit filesystem permission").check();
  await page.getByRole("button", { name: "Test write, read, rename, and delete" }).click();
  await expect(page.getByText("Round-trip verified", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Connect verified vault" }).click();
  await expect(page.getByRole("heading", { level: 2, name: "Active Obsidian Vaults" })).toBeVisible();
  const heading = page.getByRole("heading", { level: 2, name: fixture.relativePath });
  await expect(heading).toBeVisible();
  return page.locator("section").filter({ has: heading });
}

test("connects only after a real round-trip and preserves canonical health on reload", async ({ page }, testInfo) => {
  testInfo.annotations.push({ type: "interaction-test-id", description: TEST_IDS.roundTrip });
  const fixture = createBrainVaultFixture(canonicalFixtureNamespace(testInfo, "brain-vault-round-trip"));
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await page.goto("/brain/vault");
  await expect(page.getByRole("heading", { level: 1, name: "Obsidian Vault" })).toBeVisible();
  await page.getByLabel("Display name").fill(fixture.displayName);
  await page.getByLabel("Path inside the allowed root").fill(fixture.relativePath);
  await page.getByLabel("Grant explicit filesystem permission").check();
  await expect(page.getByRole("button", { name: "Connect verified vault" })).toBeDisabled();

  await page.getByRole("button", { name: "Test write, read, rename, and delete" }).click();
  await expect(page.getByText("Round-trip verified", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Connect verified vault" }).click();
  const activeHeading = page.getByRole("heading", { level: 2, name: "Active Obsidian Vaults" });
  const connectAnotherHeading = page.getByRole("heading", { level: 2, name: "Connect another local vault" });
  await expect(activeHeading).toBeVisible();
  await expect(connectAnotherHeading).toBeVisible();
  const activeBox = await activeHeading.boundingBox();
  const connectBox = await connectAnotherHeading.boundingBox();
  expect(activeBox).not.toBeNull();
  expect(connectBox).not.toBeNull();
  expect(activeBox!.y).toBeLessThan(connectBox!.y);
  const connectionHeading = page.getByRole("heading", { level: 2, name: fixture.relativePath });
  await expect(connectionHeading).toBeVisible();
  const connectionCard = page.locator("section").filter({ has: connectionHeading });
  await expect(connectionCard.getByText("Last round-trip health check", { exact: true })).toBeVisible();

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload());
  await expect(page.getByRole("heading", { level: 2, name: fixture.relativePath })).toBeVisible();
  const connectedVisual = await stableConnectionCardVisual(page, fixture.relativePath);
  await normalizeConnectionCardVisual(connectedVisual);
  await expectApprovedVisual(connectedVisual, testInfo, VISUAL_BASELINES.connected);
  const persisted = readBrainVaultFixture(fixture);
  expect(persisted.connection?.status).toBe("connected");
  expect(persisted.temporaryHealthEntries).toEqual([]);
  expect(persisted.audits.map((item) => item.action)).toEqual([
    "vault.health.verified",
    "vault.health.verified",
    "vault.connection.connected",
  ]);
  expect(JSON.stringify(persisted.audits)).not.toContain(persisted.vaultDirectory);
  expect(audit.unexpected).toEqual([]);
  expect(audit.degradedApi).toEqual([]);
  await audit.assertClean(testInfo);
});

test("shows a bounded path denial and succeeds only after a deliberate safe retry", async ({ page, browserAudit }, testInfo) => {
  testInfo.annotations.push({ type: "interaction-test-id", description: TEST_IDS.pathRetry });
  const fixture = createBrainVaultFixture(canonicalFixtureNamespace(testInfo, "brain-vault-path-retry"));
  browserAudit.expectHttpResponse(page, {
    id: "brain.vault.health-check.path-denied",
    transport: "browser",
    method: "POST",
    pathname: "/api/v2/brain/vault/health-check",
    query: {},
    status: 403,
    occurrences: 1,
    reason: "Prove traversal outside the authorized Vault root fails closed.",
  });
  await page.goto("/brain/vault");
  await page.getByLabel("Path inside the allowed root").fill(`../../${fixture.relativePath}`);
  await page.getByLabel("Grant explicit filesystem permission").check();
  const denialPromise = page.waitForResponse((response) => (
    response.request().method() === "POST"
    && new URL(response.url()).pathname === "/api/v2/brain/vault/health-check"
    && response.status() === 403
  ));
  await page.getByRole("button", { name: "Test write, read, rename, and delete" }).click();
  const denial = await denialPromise;
  const denialBody = await denial.text();
  expect(denialBody).not.toContain(fixture.relativePath);
  expect(denialBody).not.toContain("/tmp/");
  expect(JSON.parse(denialBody)).toMatchObject({
    error: {
      category: "policy_denied",
      retryable: false,
    },
  });
  await expect(page.getByRole("alert")).toContainText("outside the authorized scope");
  await expect(page.getByRole("alert")).not.toContainText("/tmp/");
  const pathDeniedAlert = page.getByRole("alert");
  const restorePathDeniedVisual = await normalizePathDeniedVisual(pathDeniedAlert);
  await expectApprovedVisual(pathDeniedAlert, testInfo, VISUAL_BASELINES.pathDenied);
  await restorePathDeniedVisual();

  // The 403 above is the deliberately exercised safety boundary. Begin the
  // strict recovery audit only after that fully asserted response.
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  page.on("console", (message) => { if (message.type() === "error") runtimeErrors.push(message.text()); });
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await page.getByLabel("Path inside the allowed root").fill(fixture.relativePath);
  await page.getByRole("button", { name: "Test write, read, rename, and delete" }).click();
  await expect(page.getByText("Round-trip verified", { exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
  expect(runtimeErrors).toEqual([]);
  expect(audit.unexpected).toEqual([]);
  expect(audit.degradedApi).toEqual([]);
  await audit.assertClean(testInfo);
});

test("exports, imports, synchronizes, downloads, and reloads one isolated Vault projection", async ({ page, browserAudit }, testInfo) => {
  testInfo.annotations.push({ type: "interaction-test-id", description: TEST_IDS.projectionLifecycle });
  const fixture = createBrainVaultOperationsFixture(canonicalFixtureNamespace(testInfo, "brain-vault-projection-lifecycle"));
  const connectionCard = await connectFixture(page, fixture);
  const connectionId = scopeBrainVaultConnection(fixture);

  await connectionCard.getByRole("button", { name: "Export canonical notes" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Exported 3 accessible canonical notes" })).toBeVisible();
  let state = readBrainVaultOperationsState(fixture);
  expect(state.nodes).toHaveLength(3);
  expect(state.nodes.every((node) => node.syncStatus === "synced" && Boolean(node.relativePath))).toBe(true);
  expect(state.nodes.find((node) => node.id === fixture.importNodeId)?.projectedBody).toBe(fixture.importInitialBody);

  editBrainVaultProjection(fixture, fixture.importNodeId, fixture.importInitialBody, fixture.importVaultBody);
  await connectionCard.getByRole("button", { name: "Import operator edits" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Processed 3 vault notes" })).toBeVisible();
  state = readBrainVaultOperationsState(fixture);
  const imported = state.nodes.find((node) => node.id === fixture.importNodeId);
  expect(imported).toMatchObject({ body: fixture.importVaultBody, projectedBody: fixture.importVaultBody, syncStatus: "synced" });
  expect(imported?.version).toBe(2);

  expect(correctBrainVaultCanonicalNode(fixture, fixture.importNodeId, fixture.importCanonicalBody)).toBe(3);
  await connectionCard.getByRole("button", { name: "Synchronize" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Synchronized 3 tracked notes" })).toBeVisible();
  state = readBrainVaultOperationsState(fixture);
  expect(state.nodes.find((node) => node.id === fixture.importNodeId)).toMatchObject({
    body: fixture.importCanonicalBody,
    projectedBody: fixture.importCanonicalBody,
    syncStatus: "synced",
    version: 3,
  });

  await connectionCard.getByRole("button", { name: "Create portable ZIP" }).click();
  const downloadLink = page.getByRole("link", { name: "Download portable ZIP" });
  await expect(downloadLink).toBeVisible();
  const downloadUrl = new URL(await downloadLink.getAttribute("href") ?? "", page.url());
  const downloadPathname = `${downloadUrl.pathname}${downloadUrl.search}`;
  expect(downloadPathname).toMatch(new RegExp(`^/api/v2/brain/vault/portable-exports/${connectionId}/ti-scale-brain-[A-Za-z0-9._-]+\\.zip$`, "u"));
  browserAudit.expectVerifiedDownload(page, downloadPathname);
  const downloadPromise = page.waitForEvent("download");
  await downloadLink.click();
  const download = await downloadPromise;
  await browserAudit.verifyDownload(page, download, downloadPathname);
  const downloadedPath = await download.path();
  expect(downloadedPath).not.toBeNull();
  const bytes = readFileSync(downloadedPath!);
  expect(bytes.subarray(0, 2).toString("utf8")).toBe("PK");
  state = readBrainVaultOperationsState(fixture);
  expect(state.portableExports).toHaveLength(1);
  expect(state.portableExports[0]).toMatchObject({
    archiveName: download.suggestedFilename(),
    byteSize: bytes.byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });

  await connectionCard.getByText("Note synchronization state", { exact: true }).click();
  const noteLinks = connectionCard.locator(".brain-sync-list").getByRole("link", { name: /^Open .+ in Obsidian$/u });
  await expect(noteLinks).toHaveCount(3);
  for (const link of await noteLinks.all()) {
    expect(await link.getAttribute("href")).toMatch(/^obsidian:\/\/open\?/u);
  }
  await expect(connectionCard.getByRole("link", { name: "Open vault in Obsidian" })).toHaveAttribute("href", /^obsidian:\/\/open\?/u);

  await browserAudit.withExpectedDocumentNavigationTeardown(page, () => page.reload());
  const reloadedHeading = page.getByRole("heading", { level: 2, name: fixture.relativePath });
  await expect(reloadedHeading).toBeVisible();
  const reloadedCard = page.locator("section").filter({ has: reloadedHeading });
  await expect(reloadedCard.getByText("3", { exact: true })).toBeVisible();
  expect(readBrainVaultOperationsState(fixture).nodes.every((node) => node.syncStatus === "synced")).toBe(true);
});

test("surfaces two concurrent edits and persists both deliberate conflict resolutions", async ({ page, browserAudit }, testInfo) => {
  testInfo.annotations.push({ type: "interaction-test-id", description: TEST_IDS.conflicts });
  const fixture = createBrainVaultOperationsFixture(canonicalFixtureNamespace(testInfo, "brain-vault-conflict-resolution"));
  const connectionCard = await connectFixture(page, fixture);
  scopeBrainVaultConnection(fixture);
  await connectionCard.getByRole("button", { name: "Export canonical notes" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Exported 3 accessible canonical notes" })).toBeVisible();

  const databasePath = editBrainVaultProjection(
    fixture,
    fixture.databaseResolutionNodeId,
    fixture.databaseInitialBody,
    fixture.databaseVaultBody,
  );
  const vaultPath = editBrainVaultProjection(
    fixture,
    fixture.vaultResolutionNodeId,
    fixture.vaultInitialBody,
    fixture.vaultVaultBody,
  );
  correctBrainVaultCanonicalNode(fixture, fixture.databaseResolutionNodeId, fixture.databaseCanonicalBody);
  correctBrainVaultCanonicalNode(fixture, fixture.vaultResolutionNodeId, fixture.vaultCanonicalBody);

  await connectionCard.getByRole("button", { name: "Synchronize" }).click();
  const databaseConflict = page.locator("article").filter({ hasText: databasePath });
  const vaultConflict = page.locator("article").filter({ hasText: vaultPath });
  await expect(databaseConflict).toBeVisible();
  await expect(vaultConflict).toBeVisible();
  await expect(databaseConflict.getByRole("button", { name: "Keep database version" })).toBeVisible();
  await expect(vaultConflict.getByRole("button", { name: "Keep vault version" })).toBeVisible();
  const conflictsCard = page.locator(".brain-conflicts");
  const restoreConflictVisual = await normalizeConflictVisual(conflictsCard);
  const restoreConflictContext = await hideVisualContext(page.locator(".brain-vault-active, .brain-vault-connect"));
  try {
    await hideOperationToastForVisual(page);
    await expectApprovedVisual(conflictsCard, testInfo, VISUAL_BASELINES.conflicts);
  } finally {
    await restoreConflictContext();
    await restoreConflictVisual();
  }

  await databaseConflict.getByRole("button", { name: "Keep database version" }).click();
  await expect(databaseConflict).toHaveCount(0);
  let state = readBrainVaultOperationsState(fixture);
  expect(state.nodes.find((node) => node.id === fixture.databaseResolutionNodeId)).toMatchObject({
    body: fixture.databaseCanonicalBody,
    projectedBody: fixture.databaseCanonicalBody,
    syncStatus: "synced",
  });
  expect(state.conflicts.find((item) => item.nodeId === fixture.databaseResolutionNodeId)?.status).toBe("resolved_database");

  await vaultConflict.getByRole("button", { name: "Keep vault version" }).click();
  await expect(vaultConflict).toHaveCount(0);
  state = readBrainVaultOperationsState(fixture);
  expect(state.nodes.find((node) => node.id === fixture.vaultResolutionNodeId)).toMatchObject({
    body: fixture.vaultVaultBody,
    projectedBody: fixture.vaultVaultBody,
    syncStatus: "synced",
  });
  expect(state.conflicts.find((item) => item.nodeId === fixture.vaultResolutionNodeId)?.status).toBe("resolved_vault");

  await browserAudit.withExpectedDocumentNavigationTeardown(page, () => page.reload());
  await expect(page.locator("article").filter({ hasText: databasePath })).toHaveCount(0);
  await expect(page.locator("article").filter({ hasText: vaultPath })).toHaveCount(0);
  expect(readBrainVaultOperationsState(fixture).conflicts.filter((item) => item.status === "open")).toHaveLength(0);
  // The reload can subscribe just before the final Vault query fans out. Do
  // not end the audit while that required authoritative refresh is in flight;
  // a genuinely hung request now fails with the bounded settlement diagnosis.
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 1_000 });
});

test("repairs, reindexes, preserves conflicts, rejects symlinks, and fails closed offline", async ({ page, browserAudit }, testInfo) => {
  testInfo.annotations.push({ type: "interaction-test-id", description: TEST_IDS.recovery });
  const fixture = createBrainVaultOperationsFixture(canonicalFixtureNamespace(testInfo, "brain-vault-repair-reindex"));
  const connectionCard = await connectFixture(page, fixture);
  scopeBrainVaultConnection(fixture);
  await connectionCard.getByRole("button", { name: "Export canonical notes" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Exported 3 accessible canonical notes" })).toBeVisible();

  const conflictPath = editBrainVaultProjection(
    fixture,
    fixture.vaultResolutionNodeId,
    fixture.vaultInitialBody,
    fixture.vaultVaultBody,
  );
  correctBrainVaultCanonicalNode(fixture, fixture.vaultResolutionNodeId, fixture.vaultCanonicalBody);
  await connectionCard.getByRole("button", { name: "Synchronize" }).click();
  await expect(page.locator("article").filter({ hasText: conflictPath })).toBeVisible();

  const damage = damageBrainVaultForRecovery(fixture);
  await connectionCard.getByRole("button", { name: "Repair vault" }).click();
  const repairReceipt = page.locator(".brain-vault-recovery-result").filter({
    has: page.getByRole("heading", { level: 2, name: "Vault repair" }),
  });
  await expect(repairReceipt).toBeVisible();
  await expect(repairReceipt).toContainText("no operator edits were overwritten");
  await expect(repairReceipt).toContainText("Conflicts preserved");
  await expect(repairReceipt).toContainText("Quarantined");
  await expect(repairReceipt).toContainText("Missing");
  const restoreRepairContext = await hideVisualContext(page.locator(".brain-vault-active, .brain-vault-connect, .brain-conflicts"));
  try {
    await hideOperationToastForVisual(page);
    await expectApprovedVisual(repairReceipt, testInfo, VISUAL_BASELINES.repair);
  } finally {
    await restoreRepairContext();
  }
  expect(readFileSync(damage.outsideTargetPath, "utf8")).toBe("outside symlink target must remain unchanged");
  expect(existsSync(damage.symlinkPath)).toBe(true);

  let state = readBrainVaultOperationsState(fixture);
  expect(state.connection.status).toBe("degraded");
  const canonicalMalformedSource = state.nodes.find((item) => item.id === fixture.importNodeId);
  expect(canonicalMalformedSource).toMatchObject({
    body: fixture.importInitialBody,
    version: 1,
  });
  expect(canonicalMalformedSource?.syncStatus).toBeUndefined();
  const detachedQuarantine = state.quarantines.find((item) => (
    item.sourceRelativePath === damage.malformedRelativePath
  ));
  expect(detachedQuarantine).toMatchObject({
    nodeId: null,
    status: "quarantined",
    intentStatus: "committed",
    sourceExists: true,
    copyExists: true,
    receiptExists: true,
  });
  expect(detachedQuarantine?.sourceHash).toBe(detachedQuarantine?.sourceContentHash);
  expect(detachedQuarantine?.copyHash).toBe(detachedQuarantine?.sourceContentHash);
  expect(detachedQuarantine?.receipt).toEqual({
    intentId: detachedQuarantine?.intentId,
    sourceContentHash: detachedQuarantine?.sourceContentHash,
    quarantineRelative: detachedQuarantine?.quarantineRelative,
  });
  expect(readFileSync(damage.malformedSourcePath, "utf8")).toBe(damage.malformedSourceText);
  await connectionCard.getByText("Note synchronization state", { exact: true }).click();
  const detachedQuarantineRow = connectionCard.locator(".brain-sync-list li").filter({
    hasText: damage.malformedRelativePath,
  });
  await expect(detachedQuarantineRow).toContainText("quarantined");
  expect(state.nodes.find((item) => item.id === fixture.databaseResolutionNodeId)?.syncStatus).toBe("database_ahead");
  expect(state.conflicts.filter((item) => item.status === "open")).toHaveLength(1);

  await connectionCard.getByRole("button", { name: "Reindex vault" }).click();
  const reindexReceipt = page.locator(".brain-vault-recovery-result").filter({
    has: page.getByRole("heading", { level: 2, name: "Vault reindex" }),
  });
  await expect(reindexReceipt).toBeVisible();
  await expect(reindexReceipt).toContainText("SQLite remained authoritative");
  const restoreReindexContext = await hideVisualContext(page.locator(".brain-vault-active, .brain-vault-connect, .brain-conflicts"));
  try {
    await hideOperationToastForVisual(page);
    await expectApprovedVisual(reindexReceipt, testInfo, VISUAL_BASELINES.reindex);
  } finally {
    await restoreReindexContext();
  }
  state = readBrainVaultOperationsState(fixture);
  expect(state.conflicts.filter((item) => item.status === "open")).toHaveLength(1);
  expect(readFileSync(damage.outsideTargetPath, "utf8")).toBe("outside symlink target must remain unchanged");

  const offline = takeBrainVaultOffline(fixture);
  try {
    browserAudit.expectHttpResponse(page, {
      id: "brain.vault.repair.offline",
      transport: "browser",
      method: "POST",
      pathname: "/api/v2/brain/vault/repair",
      query: {},
      status: 503,
      occurrences: 1,
      reason: "Prove repair refuses to recreate a configured Vault that is offline.",
    });
    await connectionCard.getByRole("button", { name: "Repair vault" }).click();
    await expect(page.getByRole("alert")).toContainText("offline or missing");
    await expect(page.getByText("Vault repair stopped safely", { exact: true })).toBeVisible();
    expect(existsSync(offline.vaultPath)).toBe(false);
    expect(existsSync(offline.backupPath)).toBe(true);
  } finally {
    restoreBrainVaultOnline(offline);
  }
});

test("recovers a persisted degraded connection through a real filesystem health proof", async ({ page, browserAudit }, testInfo) => {
  testInfo.annotations.push({ type: "interaction-test-id", description: TEST_IDS.degradedRecovery });
  const fixture = createBrainVaultOperationsFixture(canonicalFixtureNamespace(testInfo, "brain-vault-degraded-recovery"));
  await connectFixture(page, fixture);
  scopeBrainVaultConnection(fixture);
  markBrainVaultConnectionDegraded(fixture);

  await browserAudit.withExpectedDocumentNavigationTeardown(page, () => page.reload());
  const heading = page.getByRole("heading", { level: 2, name: fixture.relativePath });
  const connectionCard = page.locator("section").filter({ has: heading });
  await expect(connectionCard.getByText("degraded", { exact: true })).toBeVisible();
  await connectionCard.getByRole("button", { name: "Test connection" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Vault path completed the write, read, rename, and delete round-trip." })).toBeVisible();
  await expect(connectionCard.getByText("connected", { exact: true })).toBeVisible();
  expect(readBrainVaultOperationsState(fixture).connection.status).toBe("connected");

  await browserAudit.withExpectedDocumentNavigationTeardown(page, () => page.reload());
  const reloadedHeading = page.getByRole("heading", { level: 2, name: fixture.relativePath });
  const reloadedCard = page.locator("section").filter({ has: reloadedHeading });
  await expect(reloadedCard.getByText("connected", { exact: true })).toBeVisible();
  const recoveredVisual = await stableConnectionCardVisual(page, fixture.relativePath);
  await normalizeConnectionCardVisual(recoveredVisual);
  await expectApprovedVisual(recoveredVisual, testInfo, VISUAL_BASELINES.recovered);
  expect(readBrainVaultOperationsState(fixture).connection.status).toBe("connected");
});

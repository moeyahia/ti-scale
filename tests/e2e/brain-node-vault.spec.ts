import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parseObsidianNote } from "../../server/vault";
import { expect, test, type Locator, type Page, type TestInfo } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import {
  createBrainVaultOperationsFixture,
  readBrainVaultOperationsState,
  scopeBrainVaultConnection,
  type BrainVaultOperationsFixture,
} from "./support/brainVaultFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_ID = "e2e.brain-node.vault-export-deep-link";
const VISUAL_PROJECT = "chromium-1440";
const VAULT_PROJECTION_VISUAL = {
  id: "visual.brain-node.vault-exported.chromium-1440",
  snapshot: "brain-node-vault-exported.png",
} as const;

async function expectApprovedVisual(locator: Locator, testInfo: TestInfo): Promise<void> {
  if (testInfo.project.name !== VISUAL_PROJECT) return;
  await locator.page().evaluate(async () => { await document.fonts.ready; });
  await expect(locator).toHaveScreenshot(VAULT_PROJECTION_VISUAL.snapshot, {
    animations: "disabled",
    caret: "hide",
    maxDiffPixels: 0,
    threshold: 0.15,
  });
}

async function normalizeVaultProjectionVisual(projectionPanel: Locator): Promise<void> {
  await projectionPanel.getByRole("combobox", { name: "Vault", exact: true }).evaluate((node) => {
    const selected = (node as HTMLSelectElement).selectedOptions[0];
    if (selected) selected.textContent = "Verified Vault visual fixture";
  });
}

async function connectVerifiedVault(page: Page, fixture: BrainVaultOperationsFixture): Promise<void> {
  await page.goto("/brain/vault", { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { level: 1, name: "Obsidian Vault", exact: true })).toBeVisible();
  await page.getByLabel("Display name", { exact: true }).fill(fixture.displayName);
  await page.getByLabel("Path inside the allowed root", { exact: true }).fill(fixture.relativePath);
  await page.getByLabel("Grant explicit filesystem permission", { exact: true }).check();
  await page.getByRole("button", { name: "Test write, read, rename, and delete", exact: true }).click();
  await expect(page.getByText("Round-trip verified", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Connect verified vault", exact: true }).click();
  await expect(page.getByRole("heading", { level: 2, name: fixture.relativePath, exact: true })).toBeVisible();
}

function projectedNode(fixture: BrainVaultOperationsFixture) {
  const state = readBrainVaultOperationsState(fixture);
  const node = state.nodes.find((item) => item.id === fixture.importNodeId);
  if (!node) throw new Error(`Projected node ${fixture.importNodeId} is missing from the canonical Vault state`);
  return { state, node };
}

test(`${TEST_ID} projects one stable note and exposes only a sanitized native deep link`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const fixture = createBrainVaultOperationsFixture(canonicalFixtureNamespace(testInfo, "brain-node-vault"));
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });

  await connectVerifiedVault(page, fixture);
  const connectionId = scopeBrainVaultConnection(fixture);

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    `/brain/nodes/${fixture.importNodeId}`,
    { waitUntil: "domcontentloaded" },
  ));
  await expect(page.getByRole("heading", { name: `Operator import ${fixture.namespace}`, exact: true }).first()).toBeVisible();

  const vaultSelect = page.getByRole("combobox", { name: "Vault", exact: true });
  await expect(vaultSelect).toBeVisible();
  await vaultSelect.selectOption({ label: fixture.displayName });
  await expect(vaultSelect).toHaveValue(connectionId);

  const exportResponse = page.waitForResponse((response) => response.request().method() === "POST"
    && new URL(response.url()).pathname === "/api/v2/brain/vault/export"
    && response.status() === 200);
  const exportButton = page.getByRole("button", { name: "Export this memory", exact: true });
  await exportButton.focus();
  await exportButton.press("Enter");
  expect((await exportResponse).status()).toBe(200);
  await expect(page.getByRole("status").filter({
    hasText: "This memory was exported as a versioned Obsidian note.",
  })).toBeVisible();

  const projected = projectedNode(fixture);
  expect(projected.state.connection).toMatchObject({ id: connectionId, status: "connected" });
  expect(projected.node).toMatchObject({
    id: fixture.importNodeId,
    syncStatus: "synced",
    projectedBody: fixture.importInitialBody,
  });
  expect(projected.node.relativePath).toBeTruthy();
  const relativePath = projected.node.relativePath!;
  const notePath = join(projected.state.connection.vaultPath, relativePath);
  expect(existsSync(notePath), "The targeted export must create a real Markdown projection").toBe(true);
  const markdown = readFileSync(notePath, "utf8");
  expect(markdown.startsWith("---\n"), "The projection must begin with YAML frontmatter").toBe(true);
  const note = parseObsidianNote(markdown);
  expect(note).toMatchObject({
    id: fixture.importNodeId,
    lifecycleStatus: "confirmed",
    body: fixture.importInitialBody,
  });
  expect(note.aliases).toContain(fixture.importNodeId);

  const deepLink = page.getByRole("link", { name: "Open this note in Obsidian", exact: true });
  await expect(deepLink).toBeVisible();
  // Browser automation proves the generated native target without launching an
  // installed desktop protocol handler, which is outside the browser contract.
  await deepLink.focus();
  await expect(deepLink).toBeFocused();
  const href = await deepLink.getAttribute("href");
  expect(href).toBeTruthy();
  const nativeTarget = new URL(href!);
  expect(nativeTarget.protocol).toBe("obsidian:");
  expect(nativeTarget.hostname).toBe("open");
  expect(nativeTarget.searchParams.get("vault")).toBe(fixture.relativePath);
  expect(nativeTarget.searchParams.get("file")).toBe(relativePath.replace(/\.md$/iu, ""));
  expect(href).not.toContain(projected.state.connection.vaultPath);
  expect(nativeTarget.searchParams.get("file")).not.toContain("..");
  expect(nativeTarget.searchParams.get("file")).not.toContain("\\");
  expect(nativeTarget.searchParams.get("file")?.startsWith("/")).toBe(false);

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByRole("heading", { name: `Operator import ${fixture.namespace}`, exact: true }).first()).toBeVisible();
  await page.getByRole("combobox", { name: "Vault", exact: true }).selectOption(connectionId);
  const persistedLink = page.getByRole("link", { name: "Open this note in Obsidian", exact: true });
  await expect(persistedLink).toHaveAttribute("href", href!);

  const projectionPanel = page.locator(".brain-control-card").filter({
    has: page.getByRole("heading", { level: 2, name: "Obsidian note", exact: true }),
  });
  await expect(projectionPanel).toHaveCount(1);
  await expect(projectionPanel).toBeVisible();
  await normalizeVaultProjectionVisual(projectionPanel);
  await expectApprovedVisual(projectionPanel, testInfo);

  const persisted = projectedNode(fixture);
  expect(persisted.node).toMatchObject({
    relativePath,
    syncStatus: "synced",
    projectedBody: fixture.importInitialBody,
  });
  expect(parseObsidianNote(readFileSync(notePath, "utf8")).id).toBe(fixture.importNodeId);
  expect(audit.unexpected, "Unexpected browser failures").toEqual([]);
  expect(audit.degradedApi, "Required V2 API requests must not degrade").toEqual([]);
  await audit.assertClean(testInfo);
});

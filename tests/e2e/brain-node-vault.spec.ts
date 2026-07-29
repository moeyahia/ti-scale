import { readFileSync } from "node:fs";
import { expect, test, type Locator, type Page, type TestInfo } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import {
  createBrainVaultOperationsFixture,
  readBrainVaultProjection,
  readBrainVaultOperationsState,
  scopeBrainVaultConnection,
  type BrainVaultOperationsFixture,
} from "./support/brainVaultFixtureController";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
} from "./support/interactionActivationFixture";
import { selectTitaniumOption } from "./support/titaniumSelect";
import { validateInteractionManifest } from "../interaction-manifest/schema";

const TEST_ID = "e2e.brain-node.vault-export-deep-link";
const VISUAL_PROJECT = "chromium-1440";
const VAULT_PROJECTION_VISUAL = {
  id: "visual.brain-node.vault-exported.chromium-1440",
  snapshot: "brain-node-vault-exported.png",
} as const;
const interactionManifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

function receipt(
  manifestEntryId: string,
  option: string,
  modality: "pointer" | "keyboard",
): InteractionActivationInput {
  const entry = interactionManifest.entries.find((candidate) => candidate.id === manifestEntryId);
  if (!entry) throw new Error(`Brain node Vault manifest entry ${manifestEntryId} is missing`);
  if (!entry.options.includes(option)) {
    throw new Error(`Brain node Vault manifest entry ${manifestEntryId} does not declare ${option}`);
  }
  if (!entry.testIds.includes(TEST_ID)) {
    throw new Error(`Brain node Vault manifest entry ${manifestEntryId} is not bound to ${TEST_ID}`);
  }
  return {
    manifestEntryId,
    controlId: entry.controlId,
    option,
    materialState: entry.requiredState,
    modality,
    testId: TEST_ID,
  };
}

async function recordEffects<T>(
  recorder: InteractionActivationRecorder,
  manifestEntryId: string,
  options: readonly string[],
  modality: "pointer" | "keyboard",
  action: () => Promise<T>,
): Promise<T> {
  const nested = options.reduceRight<() => Promise<T>>(
    (next, option) => () => recorder.activate(receipt(manifestEntryId, option, modality), next),
    action,
  );
  return nested();
}

async function activate(control: Locator, modality: "pointer" | "keyboard"): Promise<void> {
  if (modality === "pointer") await control.click();
  else {
    await control.focus();
    await control.press("Enter");
  }
}

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
  await projectionPanel.getByRole("combobox", { name: "Vault", exact: true })
    .locator(".os-titanium-select__value")
    .evaluate((node) => { node.textContent = "Verified Vault visual fixture"; });
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
  expect(await selectTitaniumOption(vaultSelect, { label: fixture.displayName }, "pointer")).toBe(connectionId);
  await expect(vaultSelect).toBeFocused();

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
  const projection = readBrainVaultProjection(fixture, fixture.importNodeId);
  expect(projection.relativePath).toBe(relativePath);
  expect(projection.markdown.startsWith("---\n"), "The projection must begin with YAML frontmatter").toBe(true);
  expect(projection.note).toMatchObject({
    id: fixture.importNodeId,
    lifecycleStatus: "confirmed",
    body: fixture.importInitialBody,
  });
  expect(projection.note.aliases).toContain(fixture.importNodeId);

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
  await selectTitaniumOption(
    page.getByRole("combobox", { name: "Vault", exact: true }),
    connectionId,
    "keyboard",
  );
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
  expect(readBrainVaultProjection(fixture, fixture.importNodeId).note.id).toBe(fixture.importNodeId);
  expect(audit.unexpected, "Unexpected browser failures").toEqual([]);
  expect(audit.degradedApi, "Required V2 API requests must not degrade").toEqual([]);
  await audit.assertClean(testInfo);
});

test(`${TEST_ID} records both modalities for targeted projection and portable deep-link handoff`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(180_000);
  let sequence = 0;

  for (const modality of ["pointer", "keyboard"] as const) {
    const fixture = createBrainVaultOperationsFixture(
      canonicalFixtureNamespace(testInfo, `${modality}-brain-node-vault-receipts-${++sequence}`),
    );
    if (page.url() === "about:blank") {
      await connectVerifiedVault(page, fixture);
    } else {
      await browserAudit.withExpectedDocumentNavigationTeardown(
        page,
        () => connectVerifiedVault(page, fixture),
      );
    }
    const connectionId = scopeBrainVaultConnection(fixture);

    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.goto(`/brain/nodes/${fixture.importNodeId}`, { waitUntil: "domcontentloaded" }),
    );
    await expect(page.getByRole("heading", {
      name: `Operator import ${fixture.namespace}`,
      exact: true,
    }).first()).toBeVisible();
    const vaultSelect = page.getByRole("combobox", { name: "Vault", exact: true });
    await interactionActivation.activate(
      receipt(
        "brain.node.vault-selection",
        "Select an explicitly connected and scope-compatible Vault",
        modality,
      ),
      async () => {
        expect(await selectTitaniumOption(vaultSelect, { label: fixture.displayName }, modality))
          .toBe(connectionId);
        await expect(vaultSelect).toBeFocused();
      },
    );

    const exportResponse = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/export"
      && response.status() === 200);
    await recordEffects(
      interactionActivation,
      "brain.node.vault-export",
      [
        "Export only this exact memory node",
        "Persist a stable YAML identity and canonical sync state",
      ],
      modality,
      async () => {
        await activate(page.getByRole("button", { name: "Export this memory", exact: true }), modality);
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
        const projection = readBrainVaultProjection(fixture, fixture.importNodeId);
        expect(projection.markdown.startsWith("---\n")).toBe(true);
        expect(projection.note).toMatchObject({
          id: fixture.importNodeId,
          lifecycleStatus: "confirmed",
          body: fixture.importInitialBody,
        });
        expect(projection.note.aliases).toContain(fixture.importNodeId);
        expect(projection.relativePath).toBe(projected.node.relativePath);
      },
    );

    const deepLink = page.getByRole("link", { name: "Open this note in Obsidian", exact: true });
    await expect(deepLink).toBeVisible();
    const href = await deepLink.getAttribute("href");
    expect(href).toBeTruthy();
    const projection = readBrainVaultProjection(fixture, fixture.importNodeId);
    await interactionActivation.activate(
      receipt(
        "brain.node.vault-open",
        "Open the exact projected note through a portable obsidian:// target",
        modality,
      ),
      async () => {
        if (modality === "pointer") {
          await page.evaluate(() => {
            const state = window as Window & { __tiScaleObsidianActivation?: string };
            delete state.__tiScaleObsidianActivation;
            document.addEventListener("click", (event) => {
              const link = (event.target as Element | null)?.closest<HTMLAnchorElement>('a[href^="obsidian:"]');
              if (!link) return;
              event.preventDefault();
              state.__tiScaleObsidianActivation = link.href;
            }, { capture: true, once: true });
          });
          await deepLink.click();
          expect(await page.evaluate(() => (
            window as Window & { __tiScaleObsidianActivation?: string }
          ).__tiScaleObsidianActivation)).toBe(href);
        } else {
          await deepLink.focus();
          await expect(deepLink).toBeFocused();
        }

        const nativeTarget = new URL(href!);
        expect(nativeTarget.protocol).toBe("obsidian:");
        expect(nativeTarget.hostname).toBe("open");
        expect(nativeTarget.searchParams.get("vault")).toBe(fixture.relativePath);
        expect(nativeTarget.searchParams.get("file"))
          .toBe(projection.relativePath.replace(/\.md$/iu, ""));
        expect(href).not.toContain(projectedNode(fixture).state.connection.vaultPath);
        expect(nativeTarget.searchParams.get("file")).not.toContain("..");
        expect(nativeTarget.searchParams.get("file")).not.toContain("\\");
        expect(nativeTarget.searchParams.get("file")?.startsWith("/")).toBe(false);
      },
    );
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

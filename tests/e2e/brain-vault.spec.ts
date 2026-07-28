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
  markBrainVaultRecoveryRequired,
  readBrainVaultFixture,
  readBrainVaultOperationsState,
  restoreBrainVaultOnline,
  scopeBrainVaultConnection,
  takeBrainVaultOffline,
  type BrainVaultFixture,
} from "./support/brainVaultFixtureController";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
} from "./support/interactionActivationFixture";

const TEST_IDS = {
  roundTrip: "e2e.brain-vault.round-trip-connect-reload",
  pathRetry: "e2e.brain-vault.path-denial-retry",
  projectionLifecycle: "e2e.brain-vault.sync-import-export-portable",
  conflicts: "e2e.brain-vault.conflict-resolution",
  degradedRecovery: "e2e.brain-vault.degraded-recovery",
  recovery: "e2e.brain-vault.repair-reindex-recovery",
} as const;
const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

function activation(
  manifestEntryId: string,
  option: string,
  modality: "pointer" | "keyboard",
  testId: string,
): InteractionActivationInput {
  const entry = manifest.entries.find((candidate) => candidate.id === manifestEntryId);
  if (!entry) throw new Error(`Brain Vault manifest entry ${manifestEntryId} is missing`);
  if (!entry.options.includes(option)) throw new Error(`Brain Vault manifest entry ${manifestEntryId} does not declare ${option}`);
  if (!entry.testIds.includes(testId)) throw new Error(`Brain Vault manifest entry ${manifestEntryId} does not declare ${testId}`);
  return {
    manifestEntryId,
    controlId: entry.controlId,
    option,
    materialState: entry.requiredState,
    modality,
    testId,
  };
}

async function recordActivation<T>(
  recorder: InteractionActivationRecorder,
  manifestEntryId: string,
  option: string,
  modality: "pointer" | "keyboard",
  testId: string,
  action: () => Promise<T>,
): Promise<T> {
  return recorder.activate(activation(manifestEntryId, option, modality, testId), action);
}

async function recordActivationEffects<T>(
  recorder: InteractionActivationRecorder,
  manifestEntryId: string,
  options: readonly string[],
  modality: "pointer" | "keyboard",
  testId: string,
  action: () => Promise<T>,
): Promise<T> {
  const nested = options.reduceRight<() => Promise<T>>(
    (next, option) => () => recordActivation(
      recorder,
      manifestEntryId,
      option,
      modality,
      testId,
      next,
    ),
    action,
  );
  return nested();
}

async function enterText(control: Locator, value: string, modality: "pointer" | "keyboard"): Promise<void> {
  if (modality === "pointer") {
    await control.click();
    await control.fill(value);
  } else {
    await control.focus();
    await control.press("ControlOrMeta+A");
    await control.pressSequentially(value);
  }
  await expect(control).toHaveValue(value);
}

async function toggleCheckbox(control: Locator, modality: "pointer" | "keyboard"): Promise<void> {
  if (modality === "pointer") await control.click();
  else {
    await control.focus();
    await control.press("Space");
  }
  await expect(control).toBeChecked();
}

async function activateButton(control: Locator, modality: "pointer" | "keyboard"): Promise<void> {
  if (modality === "pointer") await control.click();
  else {
    await control.focus();
    await control.press("Enter");
  }
}

const VISUAL_PROJECT = "chromium-1440";
const VISUAL_BASELINES = {
  connected: {
    id: "visual.brain-vault.connected.chromium-1440",
    snapshot: "brain-vault-connected-card.png",
    pixelWidth: 551,
    pixelHeight: 675,
  },
  pathDenied: {
    id: "visual.brain-vault.path-denied.chromium-1440",
    snapshot: "brain-vault-path-denied.png",
    pixelWidth: 1122,
    pixelHeight: 183,
    comparisonThreshold: 0.25,
    // Chromium can quantize the three semi-transparent actuator bars by one
    // alpha level after a long serial fixture sequence. Keep the allowance
    // below 0.02% of this crop so text, spacing, color, and remediation drift
    // still fail while the known 27-pixel compositor variance does not.
    maxDiffPixels: 40,
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
  const page = locator.page();
  const viewport = page.viewportSize();
  if (viewport) await page.mouse.move(viewport.width - 1, viewport.height - 1);
  await page.evaluate(async () => { await document.fonts.ready; });
  await locator.locator(".os-status").evaluateAll((nodes) => {
    for (const node of nodes) {
      const status = node as HTMLElement;
      for (const animation of status.getAnimations()) animation.cancel();
      status.style.setProperty("animation", "none", "important");
      status.style.setProperty("transform", "none", "important");
      status.style.setProperty("opacity", "1", "important");
      status.style.setProperty("filter", "none", "important");
      status.style.setProperty("will-change", "auto", "important");
    }
  });
  await page.evaluate(() => new Promise<void>((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  }));
  await expect(locator).toHaveScreenshot(baseline.snapshot, {
    animations: "disabled",
    caret: "hide",
    maxDiffPixels: "maxDiffPixels" in baseline ? baseline.maxDiffPixels : 0,
    threshold: "comparisonThreshold" in baseline ? baseline.comparisonThreshold : 0.15,
  });
}

async function normalizeConnectionCardVisual(
  connectionCard: Locator,
  baseline: typeof VISUAL_BASELINES.connected,
): Promise<() => Promise<void>> {
  await connectionCard.evaluate((node) => {
    node.setAttribute("data-ti-plate", "aero");
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
  const originalGeometry = await connectionCard.evaluate((node, expected) => {
    const element = node as HTMLElement;
    const rect = element.getBoundingClientRect();
    if (
      Math.abs(rect.width - expected.pixelWidth) > 1
      || Math.abs(rect.height - expected.pixelHeight) > 1
    ) {
      throw new Error(
        `Approved connected-Vault geometry changed from ${expected.pixelWidth}x${expected.pixelHeight} `
          + `to ${rect.width}x${rect.height}`,
      );
    }
    const previous = {
      width: element.style.width,
      height: element.style.height,
      transform: element.style.transform,
      transformOrigin: element.style.transformOrigin,
    };
    // Earlier Vault fixtures can leave the selected card at a fractional
    // document-space origin even after its siblings are hidden. Element
    // screenshots normalize the crop size but not that subpixel paint phase.
    // Reject substantive natural geometry drift, then align only the approved
    // crop origin so a full-suite run and an isolated carrier render the same
    // zero-diff material state.
    element.style.width = `${expected.pixelWidth}px`;
    element.style.height = `${expected.pixelHeight}px`;
    const normalizedRect = element.getBoundingClientRect();
    const xOffset = Math.round(normalizedRect.left) - normalizedRect.left;
    const yOffset = Math.round(normalizedRect.top) - normalizedRect.top;
    element.style.transformOrigin = "top left";
    element.style.transform = `translate(${xOffset}px, ${yOffset}px)`;
    return previous;
  }, baseline);
  return async () => {
    await connectionCard.evaluate((node, previous) => {
      const element = node as HTMLElement;
      element.style.width = previous.width;
      element.style.height = previous.height;
      element.style.transform = previous.transform;
      element.style.transformOrigin = previous.transformOrigin;
    }, originalGeometry);
  };
}

async function stableConnectionCardVisual(page: Page, vaultPath: string): Promise<Locator> {
  const cards = page.locator(".brain-vault-connections > .os-card");
  const index = await cards.evaluateAll((nodes, expectedPath) => nodes.findIndex((node) => (
    node.querySelector("header h2")?.textContent === expectedPath
  )), vaultPath);
  if (index < 0) throw new Error(`Unable to locate connected Vault card for approved visual: ${vaultPath}`);
  return cards.nth(index);
}

async function normalizePathDeniedVisual(
  alert: Locator,
  baseline: typeof VISUAL_BASELINES.pathDenied,
): Promise<() => Promise<void>> {
  const trace = alert.getByText(/^Trace /u);
  const originalTrace = await trace.count() === 1 ? await trace.innerText() : undefined;
  if (await trace.count() === 1) {
    await trace.evaluate((node) => { node.textContent = "Trace visual-baseline-receipt"; });
  }
  const activeVaults = alert.page().locator(".brain-vault-active");
  const restoreContext = await hideVisualContext(activeVaults);
  const originalGeometry = await alert.evaluate((node, expected) => {
    const element = node as HTMLElement;
    const rect = element.getBoundingClientRect();
    if (
      Math.abs(rect.width - expected.pixelWidth) > 1 ||
      Math.abs(rect.height - expected.pixelHeight) > 1
    ) {
      throw new Error(
        `Approved path-denial geometry changed from ${expected.pixelWidth}x${expected.pixelHeight} `
          + `to ${rect.width}x${rect.height}`,
      );
    }
    const previous = {
      width: element.style.width,
      height: element.style.height,
      transform: element.style.transform,
      transformOrigin: element.style.transformOrigin,
    };
    // Element screenshots clip fractional CSS boxes differently depending on
    // the page's prior scroll position. Align the approved material-state crop
    // to the approved whole-pixel crop after rejecting a substantive natural
    // geometry change. This removes only the browser's ±1px fractional clip
    // jitter; content, color, typography, spacing, and larger layout changes
    // remain under the zero-diff assertion.
    element.style.width = `${expected.pixelWidth}px`;
    element.style.height = `${expected.pixelHeight}px`;
    const normalizedRect = element.getBoundingClientRect();
    const xOffset = Math.round(normalizedRect.left) - normalizedRect.left;
    const yOffset = Math.round(normalizedRect.top) - normalizedRect.top;
    element.style.transformOrigin = "top left";
    element.style.transform = `translate(${xOffset}px, ${yOffset}px)`;
    const children = [
      element.querySelector<HTMLElement>(".os-state-symbol"),
      element.querySelector<HTMLElement>(".os-button__mechanism"),
    ].filter((child): child is HTMLElement => child !== null).map((child) => {
      const childPrevious = {
        transform: child.style.transform,
        transformOrigin: child.style.transformOrigin,
      };
      const childRect = child.getBoundingClientRect();
      child.style.transformOrigin = "top left";
      child.style.transform = `translate(${Math.round(childRect.left) - childRect.left}px, ${Math.round(childRect.top) - childRect.top}px)`;
      return childPrevious;
    });
    return { element: previous, children };
  }, baseline);
  return async () => {
    if (originalTrace !== undefined && await trace.count() === 1) {
      await trace.evaluate((node, text) => { node.textContent = text; }, originalTrace);
    }
    await alert.evaluate((node, previous) => {
      const element = node as HTMLElement;
      element.style.width = previous.element.width;
      element.style.height = previous.element.height;
      element.style.transform = previous.element.transform;
      element.style.transformOrigin = previous.element.transformOrigin;
      const children = [
        element.querySelector<HTMLElement>(".os-state-symbol"),
        element.querySelector<HTMLElement>(".os-button__mechanism"),
      ].filter((child): child is HTMLElement => child !== null);
      children.forEach((child, index) => {
        const childPrevious = previous.children[index];
        if (!childPrevious) return;
        child.style.transform = childPrevious.transform;
        child.style.transformOrigin = childPrevious.transformOrigin;
      });
    }, originalGeometry);
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

async function normalizeConflictVisual(
  conflictsCard: Locator,
  includedPaths?: readonly string[],
): Promise<() => Promise<void>> {
  const articles = conflictsCard.locator("article");
  const articleCount = await articles.count();
  const included = includedPaths ? new Set(includedPaths) : undefined;
  const count = conflictsCard.locator(".os-count");
  const originalCount = await count.innerText();
  const originals: Array<{
    index: number;
    path: string;
    detected: string;
    display: string;
    included: boolean;
    database?: string;
    vault?: string;
  }> = [];
  let normalizedIndex = 0;
  for (let index = 0; index < articleCount; index += 1) {
    const article = articles.nth(index);
    const previews = article.locator("pre");
    const previewCount = await previews.count();
    const path = await article.locator("header strong").innerText();
    const include = !included || included.has(path);
    originals.push({
      index,
      path,
      detected: await article.locator("header small").innerText(),
      display: await article.evaluate((node) => (node as HTMLElement).style.display),
      included: include,
      ...(previewCount > 0 ? { database: await previews.nth(0).innerText() } : {}),
      ...(previewCount > 1 ? { vault: await previews.nth(1).innerText() } : {}),
    });
    if (!include) {
      await article.evaluate((node) => { (node as HTMLElement).style.display = "none"; });
      continue;
    }
    await article.locator("header strong").evaluate((node, position) => {
      node.textContent = `40 Attack Plans/visual-conflict-${Number(position) + 1}.md`;
    }, normalizedIndex);
    await article.locator("header small").evaluate((node) => {
      node.textContent = "Detected Jul 16, 2099, 10:00 PM UTC";
    });
    if (previewCount > 0) {
      await previews.nth(0).evaluate((node, position) => {
        node.textContent = `Canonical version ${Number(position) + 1} retained for operator review.`;
      }, normalizedIndex);
    }
    if (previewCount > 1) {
      await previews.nth(1).evaluate((node, position) => {
        node.textContent = `Obsidian version ${Number(position) + 1} retained for operator review.`;
      }, normalizedIndex);
    }
    normalizedIndex += 1;
  }
  await count.evaluate((node, value) => { node.textContent = String(value); }, normalizedIndex);
  return async () => {
    await count.evaluate((node, text) => { node.textContent = text; }, originalCount);
    for (const original of originals) {
      const article = articles.nth(original.index);
      await article.evaluate((node, display) => {
        (node as HTMLElement).style.display = display;
      }, original.display);
      if (!original.included) continue;
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

test(`${TEST_IDS.roundTrip} records both modalities for every connection readiness gate`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(180_000);
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: [{
      id: "brain.vault.connection-receipts.path-denied",
      transport: "browser",
      method: "POST",
      pathname: "/api/v2/brain/vault/health-check",
      query: {},
      status: 403,
      occurrences: 2,
      reason: "Prove both pointer and keyboard traversal attempts fail closed before connection.",
    }],
  });

  for (const modality of ["pointer", "keyboard"] as const) {
    const fixture = createBrainVaultFixture(
      canonicalFixtureNamespace(testInfo, `brain-vault-connect-receipts-${modality}`),
    );
    if (page.url() === "about:blank") {
      await page.goto("/brain/vault", { waitUntil: "domcontentloaded" });
    } else {
      await browserAudit.withExpectedDocumentNavigationTeardown(
        page,
        () => page.goto("/brain/vault", { waitUntil: "domcontentloaded" }),
      );
    }
    await expect(page.getByRole("heading", { level: 1, name: "Obsidian Vault", exact: true })).toBeVisible();

    const displayName = page.getByLabel("Display name", { exact: true });
    const relativePath = page.getByLabel("Path inside the allowed root", { exact: true });
    const permission = page.getByLabel("Grant explicit filesystem permission", { exact: true });
    const health = page.getByRole("button", { name: "Test write, read, rename, and delete", exact: true });
    const connect = page.getByRole("button", { name: "Connect verified vault", exact: true });

    await recordActivation(
      interactionActivation,
      "brain.vault.display-name",
      "Disposable fixture display name",
      modality,
      TEST_IDS.roundTrip,
      () => enterText(displayName, fixture.displayName, modality),
    );
    await recordActivation(
      interactionActivation,
      "brain.vault.relative-path",
      "Valid relative path",
      modality,
      TEST_IDS.roundTrip,
      () => enterText(relativePath, fixture.relativePath, modality),
    );
    await recordActivation(
      interactionActivation,
      "brain.vault.connect-verified",
      "Disabled before matching round-trip proof",
      modality,
      TEST_IDS.roundTrip,
      async () => {
        await expect(connect).toBeDisabled();
        expect(readBrainVaultFixture(fixture).connection).toBeNull();
      },
    );
    await recordActivation(
      interactionActivation,
      "brain.vault.relative-path",
      "Traversal path rejected",
      modality,
      TEST_IDS.roundTrip,
      () => enterText(relativePath, `../../${fixture.relativePath}`, modality),
    );
    await recordActivation(
      interactionActivation,
      "brain.vault.filesystem-permission",
      "Grant explicit permission for the selected Vault candidate",
      modality,
      TEST_IDS.roundTrip,
      () => toggleCheckbox(permission, modality),
    );

    const denied = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/health-check"
      && response.status() === 403);
    await recordActivation(
      interactionActivation,
      "brain.vault.round-trip-health",
      "Reject traversal without disclosing absolute paths",
      modality,
      TEST_IDS.roundTrip,
      async () => {
        await activateButton(health, modality);
        const response = await denied;
        const body = await response.text();
        expect(body).not.toContain(fixture.relativePath);
        expect(body).not.toContain("/tmp/");
        expect(JSON.parse(body)).toMatchObject({ error: { category: "policy_denied", retryable: false } });
        await expect(page.getByRole("alert")).toContainText("outside the authorized scope");
      },
    );
    await recordActivation(
      interactionActivation,
      "brain.vault.relative-path",
      "Corrected valid relative path",
      modality,
      TEST_IDS.roundTrip,
      () => enterText(relativePath, fixture.relativePath, modality),
    );

    const retryHealth = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/health-check"
      && response.status() === 200);
    await recordActivation(
      interactionActivation,
      "brain.vault.round-trip-health",
      "Retry after deliberate safe path correction",
      modality,
      TEST_IDS.roundTrip,
      async () => {
        await activateButton(health, modality);
        expect((await retryHealth).status()).toBe(200);
        await expect(page.getByText("Round-trip verified", { exact: true })).toBeVisible();
      },
    );

    const verifiedHealth = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/health-check"
      && response.status() === 200);
    await recordActivation(
      interactionActivation,
      "brain.vault.round-trip-health",
      "Verify valid relative path",
      modality,
      TEST_IDS.roundTrip,
      async () => {
        await activateButton(health, modality);
        expect((await verifiedHealth).status()).toBe(200);
        expect(readBrainVaultFixture(fixture).temporaryHealthEntries).toEqual([]);
      },
    );

    await expect(connect).toBeEnabled();
    const connected = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/connect"
      && response.status() === 201);
    await recordActivation(
      interactionActivation,
      "brain.vault.connect-verified",
      "Connect after matching round-trip proof",
      modality,
      TEST_IDS.roundTrip,
      async () => {
        await activateButton(connect, modality);
        expect((await connected).status()).toBe(201);
        await expect(page.getByRole("heading", { level: 2, name: fixture.relativePath, exact: true })).toBeVisible();
        const state = readBrainVaultFixture(fixture);
        expect(state.connection?.status).toBe("connected");
        expect(state.temporaryHealthEntries).toEqual([]);
        const actions = state.audits.map((item) => item.action);
        expect(actions.filter((action) => action === "vault.connection.connected")).toHaveLength(1);
        expect(actions.filter((action) => action === "vault.health.verified").length).toBeGreaterThanOrEqual(1);
        expect(actions.every((action) => (
          action === "vault.health.verified" || action === "vault.connection.connected"
        ))).toBe(true);
        const connectedAt = actions.indexOf("vault.connection.connected");
        expect(connectedAt).toBeGreaterThan(0);
        expect(actions.slice(0, connectedAt)).toContain("vault.health.verified");
        // A duplicate explicit proof can be idempotently replayed, while the
        // low-priority watcher may append a connection-scoped refresh after
        // connect. Assert the required proof and lifecycle ordering rather
        // than scheduler-dependent duplicate audit counts.
      },
    );
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
  expect(audit.unexpected).toEqual([]);
  expect(audit.degradedApi).toEqual([]);
  await audit.assertClean(testInfo);
});

test(`${TEST_IDS.conflicts} records both modalities for each persisted conflict decision`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(180_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });

  for (const modality of ["pointer", "keyboard"] as const) {
    const fixture = createBrainVaultOperationsFixture(
      canonicalFixtureNamespace(testInfo, `${modality}-brain-vault-conflict-receipts`),
    );
    const connectionCard = await connectFixture(page, fixture);
    scopeBrainVaultConnection(fixture);
    const exported = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/export"
      && response.status() === 200);
    await connectionCard.getByRole("button", { name: "Export canonical notes", exact: true }).click();
    const exportPayload = await (await exported).json() as {
      readonly result: { readonly status: string; readonly message: string };
    };
    expect(exportPayload.result).toMatchObject({
      status: "synced",
      message: "Exported 3 accessible canonical notes.",
    });
    await expect(page.getByRole("status").filter({ hasText: "Exported 3 accessible canonical notes" })).toBeVisible();

    expect(correctBrainVaultCanonicalNode(
      fixture,
      fixture.databaseResolutionNodeId,
      fixture.databaseCanonicalBody,
    )).toBe(2);
    expect(correctBrainVaultCanonicalNode(
      fixture,
      fixture.vaultResolutionNodeId,
      fixture.vaultCanonicalBody,
    )).toBe(2);
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

    const synchronized = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/sync"
      && response.status() === 200);
    await recordActivation(
      interactionActivation,
      "brain.vault.synchronize",
      "Create a visible conflict for concurrent edits",
      modality,
      TEST_IDS.conflicts,
      async () => {
        await activateButton(connectionCard.getByRole("button", { name: "Synchronize", exact: true }), modality);
        expect((await synchronized).status()).toBe(200);
      },
    );
    const databaseConflict = page.locator("article").filter({ hasText: databasePath });
    const vaultConflict = page.locator("article").filter({ hasText: vaultPath });
    await expect(databaseConflict).toBeVisible();
    await expect(vaultConflict).toBeVisible();

    const databaseResolution = page.waitForResponse((response) => response.request().method() === "POST"
      && /\/api\/v2\/brain\/vault\/conflicts\/[^/]+\/resolve$/u.test(new URL(response.url()).pathname)
      && response.status() === 200);
    await recordActivation(
      interactionActivation,
      "brain.vault.conflict-keep-database",
      "Select the represented canonical database version",
      modality,
      TEST_IDS.conflicts,
      async () => {
        await activateButton(databaseConflict.getByRole("button", { name: "Keep database version", exact: true }), modality);
        const response = await databaseResolution;
        expect(response.request().postDataJSON()).toMatchObject({ resolution: "database" });
        await expect(databaseConflict).toHaveCount(0);
        const state = readBrainVaultOperationsState(fixture);
        expect(state.nodes.find((node) => node.id === fixture.databaseResolutionNodeId)).toMatchObject({
          body: fixture.databaseCanonicalBody,
          projectedBody: fixture.databaseCanonicalBody,
          syncStatus: "synced",
        });
        expect(state.conflicts.find((item) => item.nodeId === fixture.databaseResolutionNodeId)?.status)
          .toBe("resolved_database");
      },
    );

    const vaultResolution = page.waitForResponse((response) => response.request().method() === "POST"
      && /\/api\/v2\/brain\/vault\/conflicts\/[^/]+\/resolve$/u.test(new URL(response.url()).pathname)
      && response.status() === 200);
    await recordActivation(
      interactionActivation,
      "brain.vault.conflict-keep-vault",
      "Select the represented operator Vault version",
      modality,
      TEST_IDS.conflicts,
      async () => {
        await activateButton(vaultConflict.getByRole("button", { name: "Keep vault version", exact: true }), modality);
        const response = await vaultResolution;
        expect(response.request().postDataJSON()).toMatchObject({ resolution: "vault" });
        await expect(vaultConflict).toHaveCount(0);
        const state = readBrainVaultOperationsState(fixture);
        expect(state.nodes.find((node) => node.id === fixture.vaultResolutionNodeId)).toMatchObject({
          body: fixture.vaultVaultBody,
          projectedBody: fixture.vaultVaultBody,
          syncStatus: "synced",
        });
        expect(state.conflicts.find((item) => item.nodeId === fixture.vaultResolutionNodeId)?.status)
          .toBe("resolved_vault");
      },
    );
    expect(readBrainVaultOperationsState(fixture).conflicts.filter((item) => item.status === "open")).toHaveLength(0);
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
  expect(audit.unexpected).toEqual([]);
  expect(audit.degradedApi).toEqual([]);
  await audit.assertClean(testInfo);
});

test(`${TEST_IDS.recovery} and ${TEST_IDS.degradedRecovery} record both modalities for bounded repair and reindex`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(240_000);
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: [{
      id: "brain.vault.recovery-receipts.offline",
      transport: "browser",
      method: "POST",
      pathname: "/api/v2/brain/vault/repair",
      query: {},
      status: 503,
      occurrences: 2,
      reason: "Prove repair fails closed for both modalities when the configured Vault path is offline.",
    }],
  });
  const repairEffects = [
    "Reconcile valid managed records",
    "Quarantine malformed notes",
    "Preserve canonical memory for missing projections",
    "Preserve open conflicts",
    "Reject symlinks",
  ] as const;
  const reindexEffects = [
    "Parse bounded current managed notes",
    "Refresh represented canonical search rows",
    "Preserve open conflicts and SQLite source-of-truth",
  ] as const;

  for (const modality of ["pointer", "keyboard"] as const) {
    const fixture = createBrainVaultOperationsFixture(
      canonicalFixtureNamespace(testInfo, `${modality}-brain-vault-repair-reindex-receipts`),
    );
    const connectionCard = await connectFixture(page, fixture);
    scopeBrainVaultConnection(fixture);
    await connectionCard.getByRole("button", { name: "Export canonical notes", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "Exported 3 accessible canonical notes" })).toBeVisible();

    const rechecked = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/health-check"
      && response.status() === 200);
    await recordActivation(
      interactionActivation,
      "brain.vault.connection-health",
      "Recheck a connected Vault",
      modality,
      TEST_IDS.degradedRecovery,
      async () => {
        await activateButton(connectionCard.getByRole("button", { name: "Test connection", exact: true }), modality);
        expect((await rechecked).status()).toBe(200);
        await expect(page.getByRole("status").filter({
          hasText: "Vault path completed the write, read, rename, and delete round-trip.",
        })).toBeVisible();
        expect(readBrainVaultOperationsState(fixture).connection.status).toBe("connected");
      },
    );

    expect(correctBrainVaultCanonicalNode(
      fixture,
      fixture.vaultResolutionNodeId,
      fixture.vaultCanonicalBody,
    )).toBe(2);
    const conflictPath = editBrainVaultProjection(
      fixture,
      fixture.vaultResolutionNodeId,
      fixture.vaultInitialBody,
      fixture.vaultVaultBody,
    );
    await connectionCard.getByRole("button", { name: "Synchronize", exact: true }).click();
    await expect(page.locator("article").filter({ hasText: conflictPath })).toBeVisible();

    const damage = damageBrainVaultForRecovery(fixture);
    const repaired = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/repair"
      && response.status() === 200);
    await recordActivationEffects(
      interactionActivation,
      "brain.vault.repair",
      repairEffects,
      modality,
      TEST_IDS.recovery,
      async () => {
        await activateButton(connectionCard.getByRole("button", { name: "Repair vault", exact: true }), modality);
        expect((await repaired).status()).toBe(200);
      },
    );
    const repairReceipt = page.locator(".brain-vault-recovery-result").filter({
      has: page.getByRole("heading", { level: 2, name: "Vault repair", exact: true }),
    });
    await expect(repairReceipt).toBeVisible();
    await expect(repairReceipt).toContainText("no operator edits were overwritten");
    await expect(repairReceipt).toContainText("Conflicts preserved");
    await expect(repairReceipt).toContainText("Quarantined");
    await expect(repairReceipt).toContainText("Missing");
    let state = readBrainVaultOperationsState(fixture);
    expect(state.connection.status).toBe("degraded");
    expect(state.conflicts.filter((item) => item.status === "open")).toHaveLength(1);
    const preservedMissingProjection = state.nodes.find(
      (item) => item.id === fixture.databaseResolutionNodeId,
    );
    expect(preservedMissingProjection).toMatchObject({
      body: fixture.databaseInitialBody,
      version: 1,
    });
    expect(["database_ahead", "synced"]).toContain(preservedMissingProjection?.syncStatus);
    const quarantine = state.quarantines.find((item) => item.sourceRelativePath === damage.malformedRelativePath);
    expect(quarantine).toMatchObject({
      status: "quarantined",
      intentStatus: "committed",
      originalProjectionExists: false,
      quarantinedArtifactExists: true,
      receiptExists: true,
    });
    expect(quarantine?.quarantinedArtifactHash).toBe(quarantine?.sourceContentHash);
    expect(existsSync(damage.symlinkPath)).toBe(true);
    expect(readFileSync(damage.outsideTargetPath, "utf8")).toBe("outside symlink target must remain unchanged");

    const reindexed = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/reindex"
      && response.status() === 200);
    await recordActivationEffects(
      interactionActivation,
      "brain.vault.reindex",
      reindexEffects,
      modality,
      TEST_IDS.recovery,
      async () => {
        await activateButton(connectionCard.getByRole("button", { name: "Reindex vault", exact: true }), modality);
        expect((await reindexed).status()).toBe(200);
      },
    );
    const reindexReceipt = page.locator(".brain-vault-recovery-result").filter({
      has: page.getByRole("heading", { level: 2, name: "Vault reindex", exact: true }),
    });
    await expect(reindexReceipt).toBeVisible();
    await expect(reindexReceipt).toContainText("SQLite remained authoritative");
    state = readBrainVaultOperationsState(fixture);
    expect(state.conflicts.filter((item) => item.status === "open")).toHaveLength(1);
    expect(readFileSync(damage.outsideTargetPath, "utf8")).toBe("outside symlink target must remain unchanged");

    const recovered = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/health-check"
      && response.status() === 200);
    await recordActivation(
      interactionActivation,
      "brain.vault.connection-health",
      "Recover a degraded connection after a successful proof",
      modality,
      TEST_IDS.degradedRecovery,
      async () => {
        await activateButton(connectionCard.getByRole("button", { name: "Test connection", exact: true }), modality);
        expect((await recovered).status()).toBe(200);
        await expect(connectionCard.getByText("connected", { exact: true })).toBeVisible();
        expect(readBrainVaultOperationsState(fixture).connection.status).toBe("connected");
      },
    );

    const offline = takeBrainVaultOffline(fixture);
    try {
      const rejected = page.waitForResponse((response) => response.request().method() === "POST"
        && new URL(response.url()).pathname === "/api/v2/brain/vault/repair"
        && response.status() === 503);
      await recordActivation(
        interactionActivation,
        "brain.vault.repair",
        "Fail closed while offline",
        modality,
        TEST_IDS.recovery,
        async () => {
          await activateButton(connectionCard.getByRole("button", { name: "Repair vault", exact: true }), modality);
          const response = await rejected;
          const body = await response.json() as { error: { code: string; category: string } };
          expect(body.error).toMatchObject({ category: "dependency_unavailable" });
          await expect(page.getByText("Vault repair stopped safely", { exact: true })).toBeVisible();
          expect(existsSync(offline.vaultPath)).toBe(false);
          expect(existsSync(offline.detachedPath)).toBe(true);
        },
      );
    } finally {
      restoreBrainVaultOnline(offline);
    }
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
  expect(audit.unexpected).toEqual([]);
  expect(audit.degradedApi).toEqual([]);
  await audit.assertClean(testInfo);
});

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
  const connectAnotherHeading = page.getByRole("heading", { level: 2, name: "Connect another custom vault" });
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
  const restoreConnectedVisual = await normalizeConnectionCardVisual(
    connectedVisual,
    VISUAL_BASELINES.connected,
  );
  await expectApprovedVisual(connectedVisual, testInfo, VISUAL_BASELINES.connected);
  await restoreConnectedVisual();
  const persisted = readBrainVaultFixture(fixture);
  expect(persisted.connection?.status).toBe("connected");
  expect(persisted.temporaryHealthEntries).toEqual([]);
  expect(persisted.audits.map((item) => [item.action, item.resource_type])).toEqual([
    ["vault.health.verified", "vault_path_candidate"],
    ["vault.health.verified", "vault_connection"],
    ["vault.connection.connected", "vault_connection"],
    ["vault.health.verified", "vault_connection"],
  ]);
  const auditRowIds = persisted.audits.map((item) => item.rowid);
  expect(auditRowIds.every((rowId) => Number.isInteger(rowId))).toBe(true);
  expect(auditRowIds).toEqual(
    [...auditRowIds].sort((left, right) => Number(left) - Number(right)),
  );
  for (let index = 1; index < persisted.audits.length; index += 1) {
    expect(persisted.audits[index]?.previous_hash)
      .toBe(persisted.audits[index - 1]?.record_hash);
  }
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
  const candidatePath = page.getByLabel("Path inside the allowed root");
  await candidatePath.fill(`../../${fixture.relativePath}`);
  // Startup's native disabled gate must hold this action until the titanium
  // boot boundary is complete; an inert-only boundary can silently swallow a
  // programmatic fill while reporting the action as successful.
  await expect(candidatePath).toHaveValue(`../../${fixture.relativePath}`);
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
  const restorePathDeniedVisual = await normalizePathDeniedVisual(
    pathDeniedAlert,
    VISUAL_BASELINES.pathDenied,
  );
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

test("exports, imports, synchronizes, enforces no-backup policy, and reloads one isolated Vault projection", async ({ page, browserAudit }, testInfo) => {
  testInfo.annotations.push({ type: "interaction-test-id", description: TEST_IDS.projectionLifecycle });
  const fixture = createBrainVaultOperationsFixture(canonicalFixtureNamespace(testInfo, "brain-vault-projection-lifecycle"));
  const connectionCard = await connectFixture(page, fixture);
  scopeBrainVaultConnection(fixture);

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

  const portableDisabled = connectionCard.getByRole("button", { name: "Portable ZIP disabled" });
  await expect(portableDisabled).toBeDisabled();
  await expect(connectionCard).toContainText("operator no-backup policy");
  state = readBrainVaultOperationsState(fixture);
  expect(state.portableExports).toHaveLength(0);

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

  correctBrainVaultCanonicalNode(fixture, fixture.databaseResolutionNodeId, fixture.databaseCanonicalBody);
  correctBrainVaultCanonicalNode(fixture, fixture.vaultResolutionNodeId, fixture.vaultCanonicalBody);
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

  await connectionCard.getByRole("button", { name: "Synchronize" }).click();
  const databaseConflict = page.locator("article").filter({ hasText: databasePath });
  const vaultConflict = page.locator("article").filter({ hasText: vaultPath });
  await expect(databaseConflict).toBeVisible();
  await expect(vaultConflict).toBeVisible();
  await expect(databaseConflict.getByRole("button", { name: "Keep database version" })).toBeVisible();
  await expect(vaultConflict.getByRole("button", { name: "Keep vault version" })).toBeVisible();
  const conflictsCard = page.locator(".brain-conflicts");
  const restoreConflictVisual = await normalizeConflictVisual(
    conflictsCard,
    [databasePath, vaultPath],
  );
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

  correctBrainVaultCanonicalNode(fixture, fixture.vaultResolutionNodeId, fixture.vaultCanonicalBody);
  const conflictPath = editBrainVaultProjection(
    fixture,
    fixture.vaultResolutionNodeId,
    fixture.vaultInitialBody,
    fixture.vaultVaultBody,
  );
  await connectionCard.getByRole("button", { name: "Synchronize" }).click();
  await expect(page.locator("article").filter({ hasText: conflictPath })).toBeVisible();

  const recoveryRequired = markBrainVaultRecoveryRequired(fixture);
  await browserAudit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.reload({ waitUntil: "domcontentloaded" }),
  );
  const recoveryHeading = page.getByRole("heading", { level: 2, name: fixture.relativePath });
  const recoveryCard = page.locator("section").filter({ has: recoveryHeading });
  await expect(recoveryCard.getByText("error", { exact: true })).toBeVisible();
  expect(readBrainVaultOperationsState(fixture).connection.status).toBe("error");

  const damage = damageBrainVaultForRecovery(fixture);
  const repaired = page.waitForResponse((response) => response.request().method() === "POST"
    && new URL(response.url()).pathname === "/api/v2/brain/vault/repair"
    && response.status() === 200);
  await recoveryCard.getByRole("button", { name: "Repair vault" }).click();
  expect((await repaired).request().postDataJSON()).toMatchObject({
    expectedUpdatedAt: recoveryRequired.updatedAt,
  });
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
    originalProjectionExists: false,
    quarantinedArtifactExists: true,
    receiptExists: true,
  });
  expect(detachedQuarantine?.quarantinedArtifactHash).toBe(
    detachedQuarantine?.sourceContentHash,
  );
  expect(detachedQuarantine?.receipt).toEqual({
    intentId: detachedQuarantine?.intentId,
    sourceContentHash: detachedQuarantine?.sourceContentHash,
    quarantineRelative: detachedQuarantine?.quarantineRelative,
  });
  expect(existsSync(damage.malformedSourcePath)).toBe(false);
  await connectionCard.getByText("Note synchronization state", { exact: true }).click();
  const detachedQuarantineRow = connectionCard.locator(".brain-sync-list li").filter({
    hasText: damage.malformedRelativePath,
  });
  await expect(detachedQuarantineRow).toContainText("quarantined");
  const preservedMissingProjection = state.nodes.find(
    (item) => item.id === fixture.databaseResolutionNodeId,
  );
  expect(preservedMissingProjection).toMatchObject({
    body: fixture.databaseInitialBody,
    version: 1,
  });
  expect(["database_ahead", "synced"]).toContain(preservedMissingProjection?.syncStatus);
  expect(state.conflicts.filter((item) => item.status === "open")).toHaveLength(1);

  const reindexed = page.waitForResponse((response) => response.request().method() === "POST"
    && new URL(response.url()).pathname === "/api/v2/brain/vault/reindex"
    && response.status() === 200);
  await connectionCard.getByRole("button", { name: "Reindex vault" }).click();
  const reindexResponse = await reindexed;
  const reindexPayload = await reindexResponse.json() as {
    readonly result: {
      readonly message: string;
      readonly progress: { readonly discovered: number; readonly processed: number };
      readonly counts: {
        readonly indexed: number;
        readonly conflictsPreserved: number;
        readonly quarantined: number;
        readonly missing: number;
        readonly errors: number;
      };
    };
  };
  expect(reindexPayload.result).toMatchObject({
    progress: { discovered: 1, processed: 3 },
    counts: {
      indexed: 2,
      conflictsPreserved: 1,
      quarantined: 0,
      missing: 1,
      errors: 1,
    },
  });
  expect(reindexPayload.result.message).toContain(
    "Reindexed 2 canonical notes from 1 managed projections; SQLite remained authoritative and 3 records need review.",
  );
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
  const quarantinesAfterReindex = state.quarantines.filter((item) => (
    item.sourceRelativePath === damage.malformedRelativePath
  ));
  expect(quarantinesAfterReindex).toHaveLength(1);
  expect(quarantinesAfterReindex[0]).toMatchObject({
    status: "quarantined",
    intentStatus: "committed",
    originalProjectionExists: false,
    quarantinedArtifactExists: true,
    receiptExists: true,
  });
  expect(existsSync(damage.malformedSourcePath)).toBe(false);
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
    expect(existsSync(offline.detachedPath)).toBe(true);
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
  const restoreRecoveredVisual = await normalizeConnectionCardVisual(
    recoveredVisual,
    VISUAL_BASELINES.connected,
  );
  await expectApprovedVisual(recoveredVisual, testInfo, VISUAL_BASELINES.recovered);
  await restoreRecoveredVisual();
  expect(readBrainVaultOperationsState(fixture).connection.status).toBe("connected");
});

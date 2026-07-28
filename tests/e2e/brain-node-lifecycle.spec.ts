import { expect, test, type Locator, type Page, type Response, type TestInfo } from "./support/playwright";
import { readFileSync } from "node:fs";
import { BrowserAudit } from "./support/browserAudit";
import {
  advanceBrainNodeVersion,
  createBrainNodeLifecycleFixture,
  readBrainNodeLifecycleState,
  type BrainNodeLifecycleFixture,
} from "./support/brainNodeLifecycleFixtureController";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import { selectTitaniumOption } from "./support/titaniumSelect";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
} from "./support/interactionActivationFixture";

const TEST_IDS = {
  lifecycle: "e2e.brain-node.lifecycle-controls",
  conflictForget: "e2e.brain-node.conflict-forget",
} as const;
const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

let fixture: BrainNodeLifecycleFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createBrainNodeLifecycleFixture(canonicalFixtureNamespace(testInfo, "brain-node-lifecycle"));
});

function mutationResponse(
  page: Page,
  operation: string,
  status = 200,
  targetFixture: BrainNodeLifecycleFixture = fixture,
): Promise<Response> {
  const path = `/api/v2/brain/nodes/${targetFixture.nodeId}/${operation}`;
  return page.waitForResponse((response) => response.request().method() === "POST"
    && new URL(response.url()).pathname === path
    && response.status() === status);
}

function nodeRead(page: Page, targetFixture: BrainNodeLifecycleFixture = fixture): Promise<Response> {
  return page.waitForResponse((response) => response.request().method() === "GET"
    && new URL(response.url()).pathname === `/api/v2/brain/nodes/${targetFixture.nodeId}`
    && response.status() === 200);
}

function receipt(
  manifestEntryId: string,
  option: string,
  modality: "pointer" | "keyboard",
  testId: string = TEST_IDS.conflictForget,
): InteractionActivationInput {
  const entry = manifest.entries.find((candidate) => candidate.id === manifestEntryId);
  if (!entry) throw new Error(`Brain lifecycle manifest entry ${manifestEntryId} is missing`);
  if (!entry.options.includes(option)) throw new Error(`Brain lifecycle manifest entry ${manifestEntryId} does not declare ${option}`);
  if (!entry.testIds.includes(testId)) {
    throw new Error(`Brain lifecycle manifest entry ${manifestEntryId} is not bound to ${testId}`);
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

async function replaceWithModality(
  control: Locator,
  value: string,
  modality: "pointer" | "keyboard",
): Promise<void> {
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

async function fillDateTimeWithModality(
  control: Locator,
  value: string,
  modality: "pointer" | "keyboard",
): Promise<void> {
  if (modality === "pointer") {
    await control.click();
  } else {
    await control.focus();
    await control.press("ControlOrMeta+A");
  }
  // Chromium exposes datetime-local as segmented native fields; Playwright's
  // standards-aware fill is the deterministic equivalent of entering every
  // represented segment after the modality-specific focus action above.
  await control.fill(value);
  await expect(control).toHaveValue(value);
}

async function enterWithModality(
  control: Locator,
  value: string,
  modality: "pointer" | "keyboard",
): Promise<void> {
  if (modality === "pointer") {
    await control.click();
    await control.fill(value);
  } else {
    await control.focus();
    await control.pressSequentially(value);
  }
  await expect(control).toHaveValue(value);
}

async function recordFieldActivation(
  recorder: InteractionActivationRecorder,
  manifestEntryId: string,
  option: string,
  control: Locator,
  value: string,
  modality: "pointer" | "keyboard",
): Promise<void> {
  await recorder.activate(receipt(manifestEntryId, option, modality), async () => {
    await enterWithModality(control, value, modality);
  });
}

async function activate(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await control.press("Enter");
  } else {
    await control.click();
  }
}

function versionValue(page: Page): Locator {
  return page.locator(".brain-node-banner > div").filter({ hasText: /^Version/u }).locator("strong");
}

async function strictAudit(audit: BrowserAudit, testInfo: TestInfo): Promise<void> {
  expect(audit.unexpected, "Unexpected browser failures").toEqual([]);
  expect(audit.degradedApi, "Required V2 API requests must not degrade").toEqual([]);
  await audit.assertClean(testInfo);
}

test(`${TEST_IDS.lifecycle} versions correction, pinning, retention, dispute, and Context Pack use`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const initialRead = nodeRead(page);
  await page.goto(`/brain/nodes/${fixture.nodeId}`, { waitUntil: "domcontentloaded" });
  expect((await initialRead).status()).toBe(200);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await expect(page.getByRole("heading", { name: fixture.initialTitle, exact: true }).first()).toBeVisible();
  await expect(versionValue(page)).toHaveText("1");

  const contextRead = page.waitForResponse((response) => response.request().method() === "GET"
    && new URL(response.url()).pathname === `/api/v2/brain/context-packs/${fixture.contextPackId}`
    && response.status() === 200);
  await activate(page.getByRole("button", { name: /^Explain why evidence appears before technique detail/u }), "keyboard");
  expect((await contextRead).status()).toBe(200);
  await expect(page.getByRole("heading", { name: "Explain why evidence appears before technique detail", exact: true })).toBeVisible();
  await expect(page.getByText("Attributable evidence is presented before technical attack detail.", { exact: true })).toBeVisible();

  await activate(page.getByRole("button", { name: "Correct memory", exact: true }), "pointer");
  let dialog = page.getByRole("dialog", { name: "Correct memory", exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("textbox", { name: "Title", exact: true })).toBeFocused();
  await activate(dialog.getByRole("button", { name: "Cancel", exact: true }), "pointer");
  await expect(dialog).toHaveCount(0);
  await activate(page.getByRole("button", { name: "Correct memory", exact: true }), "keyboard");
  dialog = page.getByRole("dialog", { name: "Correct memory", exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("textbox", { name: "Title", exact: true })).toBeFocused();
  const correctedTitle = `Evidence-first mission preference ${fixture.namespace}`;
  await dialog.getByRole("textbox", { name: "Title", exact: true }).fill(correctedTitle);
  await dialog.getByRole("textbox", { name: "Summary", exact: true }).fill("Lead with attributable evidence, then explain the bounded technique.");
  await dialog.getByRole("textbox", { name: "Note body", exact: true }).fill("The operator corrected this mission-scoped preference through the versioned browser control.");
  await selectTitaniumOption(
    dialog.getByRole("combobox", { name: "Sensitivity", exact: true }),
    "internal",
    "keyboard",
  );
  await dialog.getByRole("textbox", { name: "Reason for correction", exact: true }).fill("Clarified the confirmed explanation order and mission scope.");
  const correction = mutationResponse(page, "correct");
  await activate(dialog.getByRole("button", { name: "Save correction", exact: true }), "keyboard");
  expect((await correction).status()).toBe(200);
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("heading", { name: correctedTitle, exact: true }).first()).toBeVisible();
  await expect(versionValue(page)).toHaveText("2");
  expect(readBrainNodeLifecycleState(fixture)).toMatchObject({
    title: correctedTitle,
    lifecycleStatus: "confirmed",
    sensitivity: "internal",
    version: 2,
    pinned: false,
    versionCount: 2,
  });

  const pin = mutationResponse(page, "pin");
  await activate(page.getByRole("button", { name: "Pin memory", exact: true }), "pointer");
  expect((await pin).status()).toBe(200);
  await expect(page.getByRole("button", { name: "Unpin memory", exact: true })).toBeVisible();
  await expect(versionValue(page)).toHaveText("3");
  expect(readBrainNodeLifecycleState(fixture).pinned).toBe(true);

  const unpin = mutationResponse(page, "pin");
  await activate(page.getByRole("button", { name: "Unpin memory", exact: true }), "keyboard");
  expect((await unpin).status()).toBe(200);
  await expect(page.getByRole("button", { name: "Pin memory", exact: true })).toBeVisible();
  await expect(versionValue(page)).toHaveText("4");
  expect(readBrainNodeLifecycleState(fixture).pinned).toBe(false);

  const expiryInput = page.getByLabel("Expire on", { exact: true });
  await expiryInput.fill("2100-01-01T00:00");
  const expiry = mutationResponse(page, "expire");
  await activate(page.getByRole("button", { name: "Set expiry", exact: true }), "pointer");
  expect((await expiry).status()).toBe(200);
  await expect(versionValue(page)).toHaveText("5");
  expect(readBrainNodeLifecycleState(fixture)).toMatchObject({
    expiresAt: "2100-01-01T00:00:00.000Z",
    lifecycleStatus: "confirmed",
    version: 5,
  });

  await page.getByRole("textbox", { name: "Dispute reason", exact: true }).fill("A newer operator decision contradicts this retained preference.");
  const dispute = mutationResponse(page, "dispute");
  await activate(page.getByRole("button", { name: "Mark disputed", exact: true }), "keyboard");
  expect((await dispute).status()).toBe(200);
  await expect(versionValue(page)).toHaveText("6");
  await expect(page.locator(".brain-node-banner").getByText("disputed", { exact: true })).toBeVisible();
  const disputedState = readBrainNodeLifecycleState(fixture);
  expect(disputedState).toMatchObject({
    lifecycleStatus: "disputed",
    version: 6,
    sourceCount: 1,
    versionCount: 6,
    edgeCount: 1,
    representedContextItemCount: 1,
    suppressionCount: 0,
  });
  expect(disputedState.contextItemCount).toBeGreaterThanOrEqual(1);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.lifecycle} records both modalities for versioned correction and dispute`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(180_000);
  let sequence = 0;

  for (const modality of ["pointer", "keyboard"] as const) {
    const targetFixture = createBrainNodeLifecycleFixture(
      canonicalFixtureNamespace(testInfo, `brain-node-correction-dispute-${modality}-${++sequence}`),
    );
    const read = nodeRead(page, targetFixture);
    const destination = `/brain/nodes/${targetFixture.nodeId}`;
    if (page.url() === "about:blank") {
      await page.goto(destination, { waitUntil: "domcontentloaded" });
    } else {
      await browserAudit.withExpectedDocumentNavigationTeardown(
        page,
        () => page.goto(destination, { waitUntil: "domcontentloaded" }),
      );
    }
    expect((await read).status()).toBe(200);
    await expect(page.getByRole("heading", { name: targetFixture.initialTitle, exact: true }).first()).toBeVisible();
    await expect(versionValue(page)).toHaveText("1");

    const correctMemory = page.getByRole("button", { name: "Correct memory", exact: true });
    await interactionActivation.activate(
      receipt(
        "brain.node.correct.open",
        "Open correction dialog with canonical values",
        modality,
        TEST_IDS.lifecycle,
      ),
      async () => {
        await activate(correctMemory, modality);
        const dialog = page.getByRole("dialog", { name: "Correct memory", exact: true });
        await expect(dialog).toBeVisible();
        await expect(dialog.getByRole("textbox", { name: "Title", exact: true }))
          .toHaveValue(targetFixture.initialTitle);
        await expect(dialog.getByRole("textbox", { name: "Title", exact: true })).toBeFocused();
      },
    );

    let dialog = page.getByRole("dialog", { name: "Correct memory", exact: true });
    await interactionActivation.activate(
      receipt("brain.node.correct.cancel", "Close without mutation", modality, TEST_IDS.lifecycle),
      async () => {
        await activate(dialog.getByRole("button", { name: "Cancel", exact: true }), modality);
        await expect(dialog).toHaveCount(0);
        expect(readBrainNodeLifecycleState(targetFixture)).toMatchObject({
          title: targetFixture.initialTitle,
          version: 1,
          lifecycleStatus: "confirmed",
        });
      },
    );

    await interactionActivation.activate(
      receipt("brain.node.correct.open", "Reopen after cancel", modality, TEST_IDS.lifecycle),
      async () => {
        await activate(correctMemory, modality);
        dialog = page.getByRole("dialog", { name: "Correct memory", exact: true });
        await expect(dialog).toBeVisible();
        await expect(dialog.getByRole("textbox", { name: "Title", exact: true }))
          .toHaveValue(targetFixture.initialTitle);
      },
    );

    const corrected = {
      title: `Versioned ${modality} memory correction ${targetFixture.namespace}`,
      summary: `Attributable ${modality} evidence remains ahead of bounded technique detail.`,
      body: `The operator applied this disposable ${modality} correction through the canonical versioned control.`,
      reason: `Clarified the confirmed explanation order through the ${modality} interaction path.`,
    } as const;
    const fields = [
      { option: "Title", label: "Title", value: corrected.title },
      { option: "Summary", label: "Summary", value: corrected.summary },
      { option: "Note body", label: "Note body", value: corrected.body },
      { option: "Reason for correction", label: "Reason for correction", value: corrected.reason },
    ] as const;
    for (const field of fields) {
      await interactionActivation.activate(
        receipt("brain.node.correct.fields", field.option, modality, TEST_IDS.lifecycle),
        async () => {
          await replaceWithModality(
            dialog.getByRole("textbox", { name: field.label, exact: true }),
            field.value,
            modality,
          );
        },
      );
    }

    const sensitivity = dialog.getByRole("combobox", { name: "Sensitivity", exact: true });
    for (const option of ["public", "internal", "private", "restricted"] as const) {
      await interactionActivation.activate(
        receipt("brain.node.correct.sensitivity", option, modality, TEST_IDS.lifecycle),
        async () => {
          await selectTitaniumOption(sensitivity, option, modality);
        },
      );
    }

    const correction = mutationResponse(page, "correct", 200, targetFixture);
    await interactionActivation.activate(
      receipt("brain.node.correct.save", "Persist one versioned correction", modality, TEST_IDS.lifecycle),
      async () => {
        await activate(dialog.getByRole("button", { name: "Save correction", exact: true }), modality);
        expect((await correction).status()).toBe(200);
        await expect(dialog).toHaveCount(0);
        await expect(page.getByRole("heading", { name: corrected.title, exact: true }).first()).toBeVisible();
        await expect(versionValue(page)).toHaveText("2");
        expect(readBrainNodeLifecycleState(targetFixture)).toMatchObject({
          title: corrected.title,
          summary: corrected.summary,
          body: corrected.body,
          sensitivity: "restricted",
          lifecycleStatus: "confirmed",
          version: 2,
          versionCount: 2,
          sourceCount: 1,
          edgeCount: 1,
          representedContextItemCount: 1,
        });
      },
    );

    const disputeReason = `A newer ${modality} operator decision contradicts this retained preference.`;
    const disputeReasonControl = page.getByRole("textbox", { name: "Dispute reason", exact: true });
    await interactionActivation.activate(
      receipt("brain.node.dispute-reason", "Describe contradiction or uncertainty", modality, TEST_IDS.lifecycle),
      async () => {
        await replaceWithModality(disputeReasonControl, disputeReason, modality);
      },
    );
    const dispute = mutationResponse(page, "dispute", 200, targetFixture);
    await interactionActivation.activate(
      receipt("brain.node.dispute", "Mark disputed while preserving prior versions", modality, TEST_IDS.lifecycle),
      async () => {
        await activate(page.getByRole("button", { name: "Mark disputed", exact: true }), modality);
        expect((await dispute).status()).toBe(200);
        await expect(versionValue(page)).toHaveText("3");
        await expect(page.locator(".brain-node-banner").getByText("disputed", { exact: true })).toBeVisible();
        const state = readBrainNodeLifecycleState(targetFixture);
        expect(state).toMatchObject({
          title: corrected.title,
          summary: corrected.summary,
          body: corrected.body,
          sensitivity: "restricted",
          lifecycleStatus: "disputed",
          version: 3,
          versionCount: 3,
          sourceCount: 1,
          edgeCount: 1,
          representedContextItemCount: 1,
          suppressionCount: 0,
        });
        expect(state.contextItemCount).toBeGreaterThanOrEqual(1);
      },
    );
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

test(`${TEST_IDS.lifecycle} and ${TEST_IDS.conflictForget} record both modalities for context, retention, and optimistic pinning`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(180_000);
  let sequence = 0;

  for (const modality of ["pointer", "keyboard"] as const) {
    const targetFixture = createBrainNodeLifecycleFixture(
      canonicalFixtureNamespace(testInfo, `brain-node-context-retention-${modality}-${++sequence}`),
    );
    const initialRead = nodeRead(page, targetFixture);
    const destination = `/brain/nodes/${targetFixture.nodeId}`;
    if (page.url() === "about:blank") {
      await page.goto(destination, { waitUntil: "domcontentloaded" });
    } else {
      await browserAudit.withExpectedDocumentNavigationTeardown(
        page,
        () => page.goto(destination, { waitUntil: "domcontentloaded" }),
      );
    }
    expect((await initialRead).status()).toBe(200);
    await expect(page.getByRole("heading", { name: targetFixture.initialTitle, exact: true }).first()).toBeVisible();
    await expect(versionValue(page)).toHaveText("1");

    const contextControl = page.getByRole("button", {
      name: /^Explain why evidence appears before technique detail .+ used$/u,
    });
    const contextRead = page.waitForResponse((response) => response.request().method() === "GET"
      && new URL(response.url()).pathname === `/api/v2/brain/context-packs/${targetFixture.contextPackId}`
      && response.status() === 200);
    await interactionActivation.activate(
      receipt("brain.node.context-use", "Expand exact Context Pack use", modality, TEST_IDS.lifecycle),
      async () => {
        await activate(contextControl, modality);
        expect((await contextRead).status()).toBe(200);
        await expect(page.getByRole("heading", {
          name: "Explain why evidence appears before technique detail",
          exact: true,
        })).toBeVisible();
        await expect(page.getByText(
          "Attributable evidence is presented before technical attack detail.",
          { exact: true },
        )).toBeVisible();
      },
    );
    await interactionActivation.activate(
      receipt("brain.node.context-use", "Collapse exact Context Pack use", modality, TEST_IDS.lifecycle),
      async () => {
        await activate(contextControl, modality);
        await expect(page.getByRole("heading", {
          name: "Explain why evidence appears before technique detail",
          exact: true,
        })).toHaveCount(0);
      },
    );

    const pin = mutationResponse(page, "pin", 200, targetFixture);
    await interactionActivation.activate(
      receipt("brain.node.pin", "Pin memory", modality, TEST_IDS.lifecycle),
      async () => {
        await activate(page.getByRole("button", { name: "Pin memory", exact: true }), modality);
        expect((await pin).status()).toBe(200);
        await expect(page.getByRole("button", { name: "Unpin memory", exact: true })).toBeVisible();
        await expect(versionValue(page)).toHaveText("2");
        expect(readBrainNodeLifecycleState(targetFixture)).toMatchObject({ pinned: true, version: 2 });
      },
    );
    const unpin = mutationResponse(page, "pin", 200, targetFixture);
    await interactionActivation.activate(
      receipt("brain.node.pin", "Unpin memory", modality, TEST_IDS.lifecycle),
      async () => {
        await activate(page.getByRole("button", { name: "Unpin memory", exact: true }), modality);
        expect((await unpin).status()).toBe(200);
        await expect(page.getByRole("button", { name: "Pin memory", exact: true })).toBeVisible();
        await expect(versionValue(page)).toHaveText("3");
        expect(readBrainNodeLifecycleState(targetFixture)).toMatchObject({ pinned: false, version: 3 });
      },
    );

    const expiryValue = modality === "pointer" ? "2100-01-01T00:00" : "2100-02-02T01:30";
    const expiryControl = page.getByLabel("Expire on", { exact: true });
    await interactionActivation.activate(
      receipt("brain.node.expiry-input", "Future UTC-normalized expiry", modality, TEST_IDS.lifecycle),
      async () => {
        await fillDateTimeWithModality(expiryControl, expiryValue, modality);
        expect(readBrainNodeLifecycleState(targetFixture)).toMatchObject({ version: 3, expiresAt: null });
      },
    );
    const expiry = mutationResponse(page, "expire", 200, targetFixture);
    await interactionActivation.activate(
      receipt("brain.node.expiry-set", "Persist future expiry", modality, TEST_IDS.lifecycle),
      async () => {
        await activate(page.getByRole("button", { name: "Set expiry", exact: true }), modality);
        expect((await expiry).status()).toBe(200);
        await expect(versionValue(page)).toHaveText("4");
        expect(readBrainNodeLifecycleState(targetFixture)).toMatchObject({
          pinned: false,
          version: 4,
          expiresAt: `${expiryValue}:00.000Z`,
          sourceCount: 1,
          edgeCount: 1,
          representedContextItemCount: 1,
        });
      },
    );

    const conflictFixture = createBrainNodeLifecycleFixture(
      canonicalFixtureNamespace(testInfo, `brain-node-pin-conflict-${modality}-${++sequence}`),
    );
    const conflictRead = nodeRead(page, conflictFixture);
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.goto(`/brain/nodes/${conflictFixture.nodeId}`, { waitUntil: "domcontentloaded" }),
    );
    expect((await conflictRead).status()).toBe(200);
    await expect(versionValue(page)).toHaveText("1");
    expect(advanceBrainNodeVersion(conflictFixture)).toBe(2);
    browserAudit.expectHttpResponse(page, {
      id: `brain-node-pin-version-conflict-${modality}`,
      transport: "browser",
      method: "POST",
      pathname: `/api/v2/brain/nodes/${conflictFixture.nodeId}/pin`,
      query: {},
      status: 409,
      occurrences: 1,
      reason: `Prove the ${modality} stale pin path fails closed before canonical refresh.`,
    });
    const conflict = mutationResponse(page, "pin", 409, conflictFixture);
    await interactionActivation.activate(
      receipt("brain.node.pin", "Reject stale version", modality, TEST_IDS.conflictForget),
      async () => {
        await activate(page.getByRole("button", { name: "Pin memory", exact: true }), modality);
        const response = await conflict;
        const body = await response.json() as { error: { code: string; remediation: string } };
        expect(body.error).toMatchObject({
          code: "memory_version_conflict",
          remediation: "Refresh the node before applying this change.",
        });
        await expect(page.getByRole("alert")).toContainText("Memory changed after it was loaded");
        expect(readBrainNodeLifecycleState(conflictFixture)).toMatchObject({ pinned: true, version: 2 });
      },
    );

    await interactionActivation.activate(
      receipt("brain.node.pin", "Refresh and retry current version", modality, TEST_IDS.conflictForget),
      async () => {
        const refreshed = nodeRead(page, conflictFixture);
        await activate(page.getByRole("button", { name: "Try again", exact: true }), modality);
        expect((await refreshed).status()).toBe(200);
        await expect(page.getByRole("alert")).toHaveCount(0);
        await expect(versionValue(page)).toHaveText("2");
        await expect(page.getByRole("button", { name: "Unpin memory", exact: true })).toBeVisible();

        const retried = mutationResponse(page, "pin", 200, conflictFixture);
        await activate(page.getByRole("button", { name: "Unpin memory", exact: true }), modality);
        expect((await retried).status()).toBe(200);
        await expect(versionValue(page)).toHaveText("3");
        expect(readBrainNodeLifecycleState(conflictFixture)).toMatchObject({ pinned: false, version: 3 });
      },
    );
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

test(`${TEST_IDS.conflictForget} reconciles a stale mutation and permanently erases reusable memory`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: [{
      id: "brain-node.pin-version-conflict",
      transport: "browser",
      method: "POST",
      pathname: `/api/v2/brain/nodes/${fixture.nodeId}/pin`,
      query: {},
      status: 409,
      occurrences: 1,
      reason: "Prove a stale node version fails closed before refresh and retry.",
    }],
  });
  const initialRead = nodeRead(page);
  await page.goto(`/brain/nodes/${fixture.nodeId}`, { waitUntil: "domcontentloaded" });
  expect((await initialRead).status()).toBe(200);
  await expect(versionValue(page)).toHaveText("6");
  expect(advanceBrainNodeVersion(fixture)).toBe(7);

  const conflict = mutationResponse(page, "pin", 409);
  await activate(page.getByRole("button", { name: "Pin memory", exact: true }), "pointer");
  const conflictResponse = await conflict;
  const error = await conflictResponse.json() as { error: { code: string; remediation: string; traceId: string } };
  expect(error.error).toMatchObject({
    code: "memory_version_conflict",
    remediation: "Refresh the node before applying this change.",
  });
  await expect(page.getByRole("alert")).toContainText("Memory changed after it was loaded");
  await expect(page.getByRole("alert")).toContainText("Refresh the node before applying this change.");
  await expect(page.getByRole("alert")).toContainText(`Trace ${error.error.traceId}`);

  const refreshed = nodeRead(page);
  await activate(page.getByRole("button", { name: "Try again", exact: true }), "keyboard");
  expect((await refreshed).status()).toBe(200);
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(versionValue(page)).toHaveText("7");
  await expect(page.getByRole("button", { name: "Unpin memory", exact: true })).toBeVisible();

  const unpin = mutationResponse(page, "pin");
  await activate(page.getByRole("button", { name: "Unpin memory", exact: true }), "pointer");
  expect((await unpin).status()).toBe(200);
  await expect(versionValue(page)).toHaveText("8");
  await expect(page.getByRole("button", { name: "Pin memory", exact: true })).toBeVisible();

  await page.getByRole("textbox", { name: "Reason", exact: true }).fill("Remove this preference and prevent its reusable content from being retrieved again.");
  await page.getByRole("textbox", { name: "Type FORGET", exact: true }).fill("FORGET");
  const forget = mutationResponse(page, "forget");
  await activate(page.getByRole("button", { name: "Forget permanently", exact: true }), "keyboard");
  const forgetResponse = await forget;
  expect(forgetResponse.status(), await forgetResponse.text()).toBe(200);
  await expect(page).toHaveURL("/brain");
  await expect(page.getByRole("heading", { name: "Second Brain", exact: true }).first()).toBeVisible();

  expect(readBrainNodeLifecycleState(fixture)).toEqual({
    title: "[Forgotten memory]",
    summary: "",
    body: "",
    lifecycleStatus: "forgotten",
    sensitivity: "internal",
    version: 9,
    pinned: false,
    expiresAt: expect.any(String),
    sourceCount: 0,
    versionCount: 0,
    edgeCount: 0,
    contextItemCount: 0,
    representedContextItemCount: 0,
    suppressionCount: 1,
    forgottenAuditCount: 1,
  });
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.conflictForget} records both modalities for every transactional erasure effect`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(180_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const effects = [
    "Erase reusable content",
    "Remove sources, versions, embeddings, derived edges, Context Pack links, and projections",
    "Create content-free suppression and audit",
    "Redirect to Brain home",
  ] as const;
  let sequence = 0;

  for (const modality of ["pointer", "keyboard"] as const) {
    for (const effect of effects) {
      const targetFixture = createBrainNodeLifecycleFixture(
        canonicalFixtureNamespace(testInfo, `brain-node-forget-${modality}-${++sequence}`),
      );
      const read = nodeRead(page, targetFixture);
      const destination = `/brain/nodes/${targetFixture.nodeId}`;
      if (page.url() === "about:blank") {
        await page.goto(destination, { waitUntil: "domcontentloaded" });
      } else {
        await browserAudit.withExpectedDocumentNavigationTeardown(
          page,
          () => page.goto(destination, { waitUntil: "domcontentloaded" }),
        );
      }
      expect((await read).status()).toBe(200);
      await expect(page.getByRole("heading", { name: targetFixture.initialTitle, exact: true }).first()).toBeVisible();

      const reason = page.getByRole("textbox", { name: "Reason", exact: true });
      const confirmation = page.getByRole("textbox", { name: "Type FORGET", exact: true });
      const forgetButton = page.getByRole("button", { name: "Forget permanently", exact: true });
      await expect(forgetButton).toBeDisabled();
      const reasonText = `Erase this disposable ${modality} fixture and prevent identical reusable retrieval.`;
      if (effect === effects[0]) {
        await recordFieldActivation(
          interactionActivation,
          "brain.node.forget-reason",
          "Explain operator-requested erasure",
          reason,
          reasonText,
          modality,
        );
        await recordFieldActivation(
          interactionActivation,
          "brain.node.forget-confirmation",
          "Exact FORGET confirmation",
          confirmation,
          "FORGET",
          modality,
        );
      } else {
        await enterWithModality(reason, reasonText, modality);
        await enterWithModality(confirmation, "FORGET", modality);
      }
      await expect(forgetButton).toBeEnabled();

      const forgotten = mutationResponse(page, "forget", 200, targetFixture);
      await interactionActivation.activate(receipt("brain.node.forget", effect, modality), async () => {
        await activate(forgetButton, modality);
        const response = await forgotten;
        expect(response.status(), await response.text()).toBe(200);
        await expect(page).toHaveURL("/brain");
        await expect(page.getByRole("heading", { name: "Second Brain", exact: true }).first()).toBeVisible();
        const state = readBrainNodeLifecycleState(targetFixture);
        expect(state).toMatchObject({
          lifecycleStatus: "forgotten",
          version: 2,
          pinned: false,
          suppressionCount: 1,
          forgottenAuditCount: 1,
        });
        if (effect === "Erase reusable content") {
          expect(state).toMatchObject({ title: "[Forgotten memory]", summary: "", body: "" });
        } else if (effect === "Remove sources, versions, embeddings, derived edges, Context Pack links, and projections") {
          expect(state).toMatchObject({
            sourceCount: 0,
            versionCount: 0,
            edgeCount: 0,
            contextItemCount: 0,
            representedContextItemCount: 0,
          });
        } else if (effect === "Create content-free suppression and audit") {
          expect(state.suppressionCount).toBe(1);
          expect(state.forgottenAuditCount).toBe(1);
        } else {
          expect(new URL(page.url()).pathname).toBe("/brain");
        }
      });
    }
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
  await strictAudit(audit, testInfo);
});

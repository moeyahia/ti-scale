import { readFileSync } from "node:fs";
import { MissionIntakeService } from "../../server/intake";
import { autonomousContractHash } from "../../server/missions/canonical";
import type { AutonomousMissionRequest } from "../../server/missions/types";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { expect, test, type Locator, type Page, type TestInfo } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import { createAutonomousBranchFixture, type AutonomousBranchFixture } from "./support/autonomousBranchFixture";
import {
  createIntakeRequestLedger,
  installIntakeApiProxy,
} from "./support/autonomousIntake";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import { startReadyAutonomousIntakeBackend } from "./support/readyAutonomousIntakeBackendController";
import { readTitaniumOptions, selectTitaniumOption } from "./support/titaniumSelect";

const TEST_ID = "e2e.autonomous-branch.contract-registry";
const ACTION_POLICY_OPTIONS = [
  { value: "pre_authorized", label: "Pre-authorized" },
  { value: "guided_only", label: "Guided only / not autonomous" },
  { value: "prohibited", label: "Prohibited" },
  { value: "inherited_default", label: "Inherited default" },
] as const;
const ACTION_POLICY_VALUES = ACTION_POLICY_OPTIONS.map(({ value }) => value);
const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);
const expectedRegistry = new MissionIntakeService().snapshot("autonomous", "custom");
let fixture: AutonomousBranchFixture;

test.describe.configure({ mode: "parallel" });
test.beforeAll(({}, testInfo) => {
  fixture = createAutonomousBranchFixture(canonicalFixtureNamespace(testInfo, "autonomous-branch-contract"));
});

function route(target: AutonomousBranchFixture = fixture): string {
  return `/missions/${encodeURIComponent(target.missionId)}/runs/${encodeURIComponent(target.runId)}?tab=settings`;
}

async function openDetails(page: Page, prefix: string): Promise<Locator> {
  const summary = page.locator("summary").filter({ hasText: prefix }).first();
  await expect(summary).toBeVisible();
  await summary.click();
  const details = summary.locator("xpath=..");
  await expect(details).toHaveAttribute("open", "");
  return details;
}

async function toggleCheckboxRange(
  details: Locator,
  start: number,
  end: number,
): Promise<void> {
  const controls = details.getByRole("checkbox");
  expect(end).toBeGreaterThan(start);
  expect(await controls.count()).toBeGreaterThanOrEqual(end);
  for (let index = start; index < end; index += 1) {
    const checkbox = controls.nth(index);
    const initial = await checkbox.isChecked();
    await checkbox.click();
    await expect(checkbox).toBeChecked({ checked: !initial });
    await checkbox.press("Space");
    await expect(checkbox).toBeChecked({ checked: initial });
  }
}

async function openBranchEditor(
  page: Page,
  target: AutonomousBranchFixture = fixture,
): Promise<void> {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto(route(target));
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Autonomous branch contract");
  await expect(page.getByRole("heading", { name: "Create a separate Autonomous execution attempt", exact: true })).toBeVisible();
  const viewportMetrics = await page.evaluate(() => ({
    innerWidth: window.innerWidth,
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
    visualWidth: window.visualViewport?.width,
    visualScale: window.visualViewport?.scale,
    overflow: [...document.querySelectorAll<HTMLElement>("body *")]
      .map((element) => {
        const bounds = element.getBoundingClientRect();
        return {
          tag: element.tagName.toLowerCase(),
          className: element.className,
          left: bounds.left,
          right: bounds.right,
          width: bounds.width,
          scrollWidth: element.scrollWidth,
          clientWidth: element.clientWidth,
        };
      })
      .filter(({ left, right }) => (
        left < -1 || right > document.documentElement.clientWidth + 1
      ))
      .sort((left, right) => (
        Math.max(right.right, right.scrollWidth)
        - Math.max(left.right, left.scrollWidth)
      ))
      .slice(0, 20),
  }));
  const viewportEvidence = JSON.stringify(viewportMetrics);
  expect(viewportMetrics.innerWidth, viewportEvidence)
    .toBeCloseTo(viewportMetrics.clientWidth, 0);
  expect(viewportMetrics.scrollWidth, viewportEvidence)
    .toBeLessThanOrEqual(viewportMetrics.clientWidth + 1);
  expect(viewportMetrics.visualWidth, viewportEvidence)
    .toBeCloseTo(viewportMetrics.clientWidth, 0);
  expect(viewportMetrics.visualScale, viewportEvidence).toBe(1);

  const amendmentMode = page.getByRole("radio", {
    name: /Versioned contract amendment/u,
  });
  await amendmentMode.click();
  await expect(amendmentMode).toBeChecked();
  await expect(page.getByRole("heading", { name: "Amend explicit authority", exact: true })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: /runtime registry/iu }).last()).toBeVisible();
  await expect(page.getByLabel("Allowed action classes · one per line", { exact: false })).toHaveCount(0);
  await expect(page.getByLabel("Evidence requirements · one per line", { exact: false })).toHaveCount(0);
  await expect(page.getByLabel("Safe-stop conditions · one per line", { exact: false })).toHaveCount(0);
  await expect(page.getByLabel("Final deliverables · one per line", { exact: false })).toHaveCount(0);
}

async function exerciseActionPolicyMatrix(policy: Locator, actionIndex: number): Promise<void> {
  const trigger = policy.and(policy.page().locator('[role="combobox"]'));
  const proxy = trigger.locator("xpath=..").locator("select.os-titanium-select__form-proxy");
  const options = await proxy.locator("option").evaluateAll((elements) => elements.map((element) => ({
    value: (element as HTMLOptionElement).value,
    label: element.textContent?.trim() ?? "",
  })));
  expect(options).toEqual(ACTION_POLICY_OPTIONS);
  const initial = await proxy.inputValue();
  expect(ACTION_POLICY_VALUES).toContain(initial);
  const listboxId = await trigger.getAttribute("aria-controls");
  expect(listboxId, "Every action-class selector must own an application listbox").toBeTruthy();
  const listbox = policy.page().locator(`[role="listbox"][id=${JSON.stringify(listboxId)}]`);

  for (const [stateIndex, state] of ACTION_POLICY_VALUES.entries()) {
    const modality = (actionIndex + stateIndex) % 2 === 0 ? "pointer" : "keyboard";
    if (modality === "pointer") {
      await trigger.click();
      await listbox.locator(`[role="option"][data-select-value=${JSON.stringify(state)}]`).click();
    } else {
      await trigger.focus();
      await trigger.press("Enter");
      await trigger.press("Home");
      for (let offset = 0; offset < stateIndex; offset += 1) {
        await trigger.press("ArrowDown");
      }
      await trigger.press("Enter");
    }
    await expect(proxy).toHaveValue(state);
    await expect(trigger).toHaveAttribute("aria-expanded", "false");
  }
}

async function finishAudit(page: Page, audit: BrowserAudit, testInfo: TestInfo): Promise<void> {
  await audit.waitForPageApiSettlement(page);
  await audit.assertClean(testInfo);
}

test(`${TEST_ID} exposes the structured successor-contract boundary and destructive policy`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await openBranchEditor(page);
  const destructivePolicy = page.getByLabel("Destructive-action policy", { exact: false });
  expect((await readTitaniumOptions(destructivePolicy)).map((option) => option.label)).toEqual([
    "Prohibited",
    "Validate the path without executing",
    "Named disposable lab targets only",
  ]);
  await selectTitaniumOption(destructivePolicy, "validate_without_executing", "pointer");
  await selectTitaniumOption(destructivePolicy, "bounded_lab_only", "keyboard");
  const boundedTargets = page.getByRole("group", { name: "Named bounded destructive targets", exact: true });
  await expect(boundedTargets).toBeVisible();
  const boundedTarget = boundedTargets.getByRole("checkbox");
  await boundedTarget.check();
  await expect(boundedTarget).toBeChecked();
  await boundedTarget.press("Space");
  await expect(boundedTarget).not.toBeChecked();
  await selectTitaniumOption(destructivePolicy, "prohibited", "pointer");
  await finishAudit(page, audit, testInfo);
});

test(`${TEST_ID} pins exact primary and fallback models in a successor contract`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const backend = await startReadyAutonomousIntakeBackend(
    canonicalFixtureNamespace(testInfo, "autonomous-branch-model-submit"),
  );
  const proxy = await installIntakeApiProxy(page, backend.baseUrl);
  const ledger = createIntakeRequestLedger(page);
  const modelFixture = backend.branchFixture;
  const missionRuntimePattern =
    `**/api/v2/missions/${encodeURIComponent(modelFixture.missionId)}/runtime`;
  let delayNextMissionRuntime = false;
  let delayedMissionRuntimeCount = 0;
  let markMissionRuntimeStarted!: () => void;
  const missionRuntimeStarted = new Promise<void>((resolve) => {
    markMissionRuntimeStarted = resolve;
  });
  let releaseMissionRuntime!: () => void;
  const missionRuntimeGate = new Promise<void>((resolve) => {
    releaseMissionRuntime = resolve;
  });
  const missionRuntimeHandler = async (
    requestRoute: import("@playwright/test").Route,
  ): Promise<void> => {
    if (
      requestRoute.request().method() !== "GET"
      || !delayNextMissionRuntime
    ) {
      await requestRoute.fallback();
      return;
    }
    delayNextMissionRuntime = false;
    delayedMissionRuntimeCount += 1;
    markMissionRuntimeStarted();
    await missionRuntimeGate;
    await requestRoute.fallback();
  };
  await page.route(missionRuntimePattern, missionRuntimeHandler);
  try {
    await openBranchEditor(page, modelFixture);
  const editor = page.locator(".mission-model-assignment").first();
  await expect(editor).toBeVisible();
  const editedAgentId = await editor.getAttribute("data-agent-id");
  expect(editedAgentId).toBeTruthy();
  await expect(editor).toContainText("Source signed contract");
  const controls = editor.getByRole("combobox");
  await expect(controls).toHaveCount(6);

  const primaryProvider = controls.nth(0);
  const primaryModel = controls.nth(1);
  const primaryReasoning = controls.nth(2);
  const fallbackProvider = controls.nth(3);
  const fallbackModel = controls.nth(4);
  const fallbackReasoning = controls.nth(5);

  const primaryProviderOptions = await readTitaniumOptions(primaryProvider);
  const primaryProviderValue = primaryProviderOptions.find(({ disabled, value }) =>
    !disabled && value.length > 0)?.value;
  expect(primaryProviderValue).toBeTruthy();
  await selectTitaniumOption(primaryProvider, primaryProviderValue!, "pointer");

  const primaryModelOptions = await readTitaniumOptions(primaryModel);
  const primaryModelValue = primaryModelOptions.find(({ disabled, value }) =>
    !disabled && value.length > 0)?.value;
  expect(primaryModelValue).toBeTruthy();
  await selectTitaniumOption(primaryModel, primaryModelValue!, "keyboard");

  const primaryReasoningOptions = await readTitaniumOptions(primaryReasoning);
  const currentPrimary = await primaryReasoning
    .locator("xpath=..")
    .locator("select.os-titanium-select__form-proxy")
    .inputValue();
  const changedPrimary = primaryReasoningOptions.find(({ disabled, value }) =>
    !disabled && value !== currentPrimary)?.value;
  expect(changedPrimary).toBeTruthy();
  await selectTitaniumOption(primaryReasoning, changedPrimary!, "pointer");

  const fallbackProviderOptions = await readTitaniumOptions(fallbackProvider);
  const fallbackProviderValue = fallbackProviderOptions.find(({ disabled, value }) =>
    !disabled && value.length > 0)?.value;
  expect(fallbackProviderValue).toBeTruthy();
  await selectTitaniumOption(fallbackProvider, fallbackProviderValue!, "keyboard");

  const fallbackModelOptions = await readTitaniumOptions(fallbackModel);
  const fallbackModelValue = fallbackModelOptions.find(({ disabled, value }) =>
    !disabled && value.length > 0)?.value;
  expect(fallbackModelValue).toBeTruthy();
  await selectTitaniumOption(fallbackModel, fallbackModelValue!, "pointer");

  const fallbackReasoningOptions = await readTitaniumOptions(fallbackReasoning);
  const fallbackReasoningValue = fallbackReasoningOptions.find(({ disabled, value }) =>
    !disabled && value.length > 0)?.value;
  expect(fallbackReasoningValue).toBeTruthy();
  await selectTitaniumOption(fallbackReasoning, fallbackReasoningValue!, "keyboard");
  await expect(editor).toContainText("Branch amendment pending review");

  const restore = page.getByRole("button", {
    name: "Restore signed models",
    exact: true,
  });
  await expect(restore).toHaveAttribute(
    "data-control-id",
    "autonomous-branch-model-restore-signed",
  );
  await expect(restore).toBeEnabled();
  await restore.click();
  await expect(restore).toBeDisabled();
  await expect(editor).toContainText("Source signed contract");
  const restoredPrimaryOptions = await readTitaniumOptions(primaryReasoning);
  const restoredPrimary = await primaryReasoning
    .locator("xpath=..")
    .locator("select.os-titanium-select__form-proxy")
    .inputValue();
  const amendedPrimary = restoredPrimaryOptions.find(({ disabled, value }) =>
    !disabled && value !== restoredPrimary)?.value;
  expect(amendedPrimary).toBeTruthy();
  await selectTitaniumOption(primaryReasoning, amendedPrimary!, "keyboard");
  const amendedPrimaryProvider = await primaryProvider
    .locator("xpath=..")
    .locator("select.os-titanium-select__form-proxy")
    .inputValue();
  const amendedFallbackProvider = (await readTitaniumOptions(fallbackProvider))
    .find(({ disabled, value }) =>
      !disabled && value.length > 0 && value !== amendedPrimaryProvider)?.value;
  expect(amendedFallbackProvider).toBeTruthy();
  await selectTitaniumOption(fallbackProvider, amendedFallbackProvider!, "pointer");
  const amendedFallbackModel = (await readTitaniumOptions(fallbackModel))
    .find(({ disabled, value }) => !disabled && value.length > 0)?.value;
  expect(amendedFallbackModel).toBeTruthy();
  await selectTitaniumOption(fallbackModel, amendedFallbackModel!, "keyboard");
  const finalPrimaryConfigurationId = await primaryReasoning
    .locator("xpath=..")
    .locator("select.os-titanium-select__form-proxy")
    .inputValue();
  const amendedFallbackReasoning = (await readTitaniumOptions(fallbackReasoning))
    .find(({ disabled, value }) =>
      !disabled && value.length > 0 && value !== finalPrimaryConfigurationId)?.value;
  expect(amendedFallbackReasoning).toBeTruthy();
  await selectTitaniumOption(fallbackReasoning, amendedFallbackReasoning!, "pointer");
  const finalFallbackConfigurationId = await fallbackReasoning
    .locator("xpath=..")
    .locator("select.os-titanium-select__form-proxy")
    .inputValue();
  expect(finalFallbackConfigurationId).not.toBe("");
  expect(finalFallbackConfigurationId).not.toBe(finalPrimaryConfigurationId);
  await expect(editor).toContainText("Branch amendment pending review");

  await page.getByLabel("Branch or amendment reason (audited)", {
    exact: true,
  }).fill("Use a reviewed exact model route for this separate bounded run.");
  const preflightPath =
    `/api/v2/missions/${encodeURIComponent(modelFixture.missionId)}/autonomous-branches/preflight`;
  const preflightResponse = page.waitForResponse((response) =>
    response.request().method() === "POST"
    && new URL(response.url()).pathname === preflightPath);
  await page.getByRole("button", {
    name: "Draft and review amended contract",
    exact: true,
  }).click();
  const reviewedResponse = await preflightResponse;
  expect(reviewedResponse.status()).toBe(201);
  const submitted = reviewedResponse.request().postDataJSON() as {
    readonly request: AutonomousMissionRequest;
  };
  expect(submitted.request.authorization).toEqual(backend.branchFixture.authorization);
  expect(submitted.request.authorization.environmentClassification).toBe("htb");
  expect(submitted.request.contract.agentModelAssignments.find(
    ({ agentId }) => agentId === editedAgentId,
  )).toMatchObject({
    agentId: editedAgentId,
    primaryConfigurationId: finalPrimaryConfigurationId,
    fallbackConfigurationId: finalFallbackConfigurationId,
  });
  const reviewed = await reviewedResponse.json() as {
    readonly contract: {
      readonly version: number;
      readonly hash: string;
    };
    readonly request: AutonomousMissionRequest;
  };
  expect(reviewed.request.authorization).toEqual(backend.branchFixture.authorization);
  expect(reviewed.request.contract.agentModelAssignments).toEqual(
    submitted.request.contract.agentModelAssignments,
  );
  expect(reviewed.contract.hash).toBe(autonomousContractHash(reviewed.request));
  await expect(page.getByRole("heading", {
    name: `Contract v${reviewed.contract.version}`,
    exact: true,
  })).toBeVisible();
  await expect(page.getByText(`SHA-256 ${reviewed.contract.hash}`, {
    exact: true,
  })).toBeVisible();

  await page.getByRole("checkbox", {
    name: /I reviewed contract v/u,
  }).check();
  const createPath =
    `/api/v2/missions/${encodeURIComponent(modelFixture.missionId)}/autonomous-branches`;
  const createResponse = page.waitForResponse((response) =>
    response.request().method() === "POST"
    && new URL(response.url()).pathname === createPath);
  delayNextMissionRuntime = true;
  await page.getByRole("button", {
    name: `Confirm contract v${reviewed.contract.version} and create run`,
    exact: true,
  }).click();
  const createdResponse = await createResponse;
  expect(createdResponse.status()).toBe(201);
  await missionRuntimeStarted;
  expect(delayedMissionRuntimeCount).toBe(1);
  expect(ledger.count("POST", createPath)).toBe(1);
  const createRequest = createdResponse.request().postDataJSON() as {
    readonly review: { readonly version: number; readonly hash: string };
  };
  expect(createRequest.review).toEqual({
    version: reviewed.contract.version,
    hash: reviewed.contract.hash,
  });
  const created = await createdResponse.json() as {
    readonly run: { readonly id: string };
    readonly contract: { readonly hash: string };
  };
  expect(created.contract.hash).toBe(reviewed.contract.hash);
  releaseMissionRuntime();
  await expect.poll(() => page.url()).toContain(
    `/missions/${encodeURIComponent(modelFixture.missionId)}/runs/${encodeURIComponent(created.run.id)}`,
  );
    const successor = await page.evaluate(async ({ missionId, runId }) => {
      const response = await fetch(
        `/api/v2/missions/${encodeURIComponent(missionId)}/autonomous-branches/context?sourceRunId=${encodeURIComponent(runId)}`,
        { headers: { accept: "application/json" } },
      );
      if (!response.ok) {
        throw new Error(`Successor branch context returned ${response.status}`);
      }
      return response.json() as Promise<{
        readonly contract: { readonly hash: string };
        readonly request: AutonomousMissionRequest;
      }>;
    }, { missionId: modelFixture.missionId, runId: created.run.id });
    expect(successor.contract.hash).toBe(reviewed.contract.hash);
    expect(successor.request.authorization).toEqual(backend.branchFixture.authorization);
    expect(successor.request.contract.agentModelAssignments).toEqual(
      reviewed.request.contract.agentModelAssignments,
    );
    expect(ledger.count("POST", createPath)).toBe(1);
    await finishAudit(page, audit, testInfo);
  } finally {
    releaseMissionRuntime();
    ledger.dispose();
    if (!page.isClosed()) {
      await page.unroute(missionRuntimePattern, missionRuntimeHandler);
    }
    await proxy.dispose();
    await backend.stop();
  }
});

test(`${TEST_ID} keeps successor model selectors retired until catalog recovery`, async ({
  page,
}, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const backend = await startReadyAutonomousIntakeBackend(
    canonicalFixtureNamespace(testInfo, "autonomous-branch-catalog-recovery"),
  );
  const proxy = await installIntakeApiProxy(page, backend.baseUrl);
  let catalogAvailable = false;
  await page.route("**/api/v2/model-catalog", async (requestRoute) => {
    if (catalogAvailable) {
      await requestRoute.fallback();
      return;
    }
    await requestRoute.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "model_catalog_unavailable",
          message: "The successor model catalog could not be refreshed.",
          humanMessage: "The successor model catalog could not be refreshed.",
          retryable: true,
          category: "dependency",
          remediation: "Restore the provider catalog service, then try again.",
          traceId: "trace-autonomous-branch-model-catalog",
          timestamp: "2026-07-27T00:00:00.000Z",
        },
      }),
    });
  });
  audit.expectHttpResponse({
    id: "autonomous-branch-model-catalog-unavailable",
    transport: "browser",
    method: "GET",
    pathname: "/api/v2/model-catalog",
    query: {},
    status: 503,
    occurrences: 2,
    reason: "Prove one failed retry cannot revive successor-contract model selectors.",
  });
  try {
    await openBranchEditor(page, backend.branchFixture);
    const failure = page.getByRole("alert").filter({
      hasText: "Mission model catalog is unavailable",
    });
    await expect(failure).toContainText(
      "The successor model catalog could not be refreshed.",
    );
    await expect(page.getByRole("combobox", {
      name: / primary provider$/u,
    })).toHaveCount(0);

    let retry = failure.getByRole("button", { name: "Try again", exact: true });
    await expect(retry).toHaveAttribute(
      "data-control-id",
      "autonomous-branch-model-catalog-retry",
    );
    const failedRetry = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/model-catalog"
      && response.status() === 503);
    await retry.click();
    await failedRetry;
    await expect(page.getByRole("combobox", {
      name: / primary provider$/u,
    })).toHaveCount(0);

    catalogAvailable = true;
    retry = failure.getByRole("button", { name: "Try again", exact: true });
    await expect(retry).toHaveAttribute(
      "data-control-id",
      "autonomous-branch-model-catalog-retry",
    );
    await retry.focus();
    const recovered = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/v2/model-catalog"
      && response.status() === 200);
    await page.keyboard.press("Enter");
    await recovered;
    await expect(failure).toHaveCount(0);
    await expect(page.getByRole("combobox", {
      name: / primary provider$/u,
    }).first()).toBeVisible();
    await finishAudit(page, audit, testInfo);
  } finally {
    await proxy.dispose();
    await backend.stop();
  }
});

const actionClassEntries = Object.values(expectedRegistry.actionClasses.classes);
for (const [actionIndex, action] of actionClassEntries.entries()) {
  test(`${TEST_ID} action-class ${String(actionIndex + 1).padStart(2, "0")} ${action.label}`, async ({ page }, testInfo) => {
    test.setTimeout(180_000);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    await openBranchEditor(page);
    const actionMatrix = await openDetails(page, "Action-class policy matrix");
    expect(await actionMatrix.locator("article.os-policy-row > div > strong").allTextContents()).toEqual(
      actionClassEntries.map(({ label }) => label),
    );
    const actionPolicies = actionMatrix.getByRole("combobox", { name: / branch policy$/u });
    await expect(actionPolicies).toHaveCount(actionClassEntries.length);
    const policy = actionPolicies.nth(actionIndex);
    await exerciseActionPolicyMatrix(policy, actionIndex);
    await finishAudit(page, audit, testInfo);
  });
}

function checklistShards(total: number, size: number): Array<readonly [number, number]> {
  const shards: Array<readonly [number, number]> = [];
  for (let start = 0; start < total; start += size) {
    shards.push([start, Math.min(start + size, total)]);
  }
  return shards;
}

const deliverableLabels = Object.values(expectedRegistry.deliverables.deliverables).map(({ label }) => label);
for (const [shardIndex, [start, end]] of checklistShards(deliverableLabels.length, 5).entries()) {
  test(`${TEST_ID} deliverables shard ${shardIndex + 1}`, async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    await openBranchEditor(page);
    const deliverables = await openDetails(page, "Final deliverables");
    expect(await deliverables.locator("label.os-check-field strong").allTextContents()).toEqual(deliverableLabels);
    await toggleCheckboxRange(deliverables, start, end);
    await finishAudit(page, audit, testInfo);
  });
}

const evidenceLabels = Object.values(expectedRegistry.evidenceTypes.types).map(({ label }) => label);
for (const [shardIndex, [start, end]] of checklistShards(evidenceLabels.length, 5).entries()) {
  test(`${TEST_ID} evidence shard ${shardIndex + 1}`, async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    await openBranchEditor(page);
    const evidence = await openDetails(page, "Evidence requirements");
    expect(await evidence.locator("label.os-check-field strong").allTextContents()).toEqual(evidenceLabels);
    await toggleCheckboxRange(evidence, start, end);
    await finishAudit(page, audit, testInfo);
  });
}

const safeStopLabels = expectedRegistry.safeStops.optional.map(({ label }) => label);
for (const [shardIndex, [start, end]] of checklistShards(safeStopLabels.length, 5).entries()) {
  test(`${TEST_ID} safe-stops shard ${shardIndex + 1}`, async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    await openBranchEditor(page);
    const safeStops = await openDetails(page, "Safe-stop behavior");
    expect(await safeStops.locator("label.os-check-field strong").allTextContents()).toEqual(safeStopLabels);
    await toggleCheckboxRange(safeStops, start, end);
    await expect(safeStops.locator(".os-mandatory-stop")).toHaveCount(expectedRegistry.safeStops.mandatory.length);
    await expect(safeStops.locator(".os-mandatory-stop input")).toHaveCount(0);
    await expect(safeStops).toContainText("Mandatory platform stops are always enforced and cannot be removed.");
    await finishAudit(page, audit, testInfo);
  });
}

test(`${TEST_ID} retains complete interaction-manifest accounting`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await openBranchEditor(page);
  const actionMatrix = await openDetails(page, "Action-class policy matrix");
  expect(await actionMatrix.locator("article.os-policy-row > div > strong").allTextContents()).toEqual(
    actionClassEntries.map(({ label }) => label),
  );
  const actionPolicies = actionMatrix.getByRole("combobox", { name: / branch policy$/u });
  await expect(actionPolicies).toHaveCount(actionClassEntries.length);
  const requiredManifestEntries = [
    "autonomous-branch.contract.destructive-policy",
    "autonomous-branch.contract.bounded-targets",
    "autonomous-branch.contract.registry-disclosures",
    "autonomous-branch.contract.action-classes",
    "autonomous-branch.contract.deliverables",
    "autonomous-branch.contract.evidence",
    "autonomous-branch.contract.safe-stops",
    "autonomous-branch.contract.model-primary-provider",
    "autonomous-branch.contract.model-primary-model",
    "autonomous-branch.contract.model-primary-reasoning",
    "autonomous-branch.contract.model-fallback-provider",
    "autonomous-branch.contract.model-fallback-model",
    "autonomous-branch.contract.model-fallback-reasoning",
    "autonomous-branch.contract.model-restore",
  ];
  for (const id of requiredManifestEntries) {
    expect(manifest.entries.some((entry) => entry.id === id), `Missing interaction manifest entry ${id}`).toBe(true);
  }
  await finishAudit(page, audit, testInfo);
});

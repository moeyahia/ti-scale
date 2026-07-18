import { readFileSync } from "node:fs";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import {
  createCommandPaletteFixture,
  readCommandPaletteCandidateSnapshot,
  refreshCommandPaletteMemoryCandidateAuthority,
  type CommandPaletteFixture,
} from "./support/commandPaletteFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import { expect, test, type Locator, type Page, type Request, type Response } from "./support/playwright";
import { readRunInterventionRecoverySnapshot } from "./support/runInterventionRecoveryFixture";

const TEST_SEARCH = "e2e.command-palette.search-record-families";
const TEST_RUN_CONTROL = "e2e.command-palette.run-control";
const TEST_MEMORY = "e2e.command-palette.memory-candidate";
const TEST_DEGRADED = "e2e.command-palette.partial-data";
const MANIFEST_IDS = [
  "command-palette.search",
  "command-palette.results",
  "command-palette.journey-results",
  "command-palette.navigation-results",
  "command-palette.mission-results",
  "command-palette.run-results",
  "command-palette.decision-results",
  "command-palette.agent-results",
  "command-palette.memory-results",
  "command-palette.run-commands",
  "command-palette.editor-back",
  "command-palette.run-reason",
  "command-palette.cancel-confirmation",
  "command-palette.run-confirm",
  "command-palette.memory-command",
  "command-palette.memory-type",
  "command-palette.memory-scope",
  "command-palette.memory-sensitivity",
  "command-palette.memory-title",
  "command-palette.memory-summary",
  "command-palette.memory-create",
  "command-palette.memory-inbox",
] as const;
const manifest = validateInteractionManifest(JSON.parse(
  readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8"),
) as unknown);

let fixture: CommandPaletteFixture;

test.beforeEach(({}, testInfo) => {
  // Fully-parallel Playwright may execute more than one file-scoped hook in
  // the same worker process. Include the current test identity so each hook
  // owns distinct canonical rows instead of re-inserting a prior fixture.
  fixture = createCommandPaletteFixture(canonicalFixtureNamespace(
    testInfo,
    `command-palette-${testInfo.testId}`,
  ));
});

interface RemoteQueryExpectation {
  readonly pathname: string;
  readonly limit: number;
  readonly itemId: string;
  readonly optionNameFromItem?: (item: Readonly<Record<string, unknown>>) => RegExp;
}

const AGENT_PALETTE_STATUSES = ["available", "busy", "degraded", "offline", "quarantined"] as const;

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function pathname(request: Request): string {
  return new URL(request.url()).pathname;
}

function manifestEntry(id: typeof MANIFEST_IDS[number]) {
  const entry = manifest.entries.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`Command palette manifest entry ${id} is missing`);
  return entry;
}

function waitForPaletteSearch(dialog: Locator): Promise<void> {
  return expect(dialog.locator("[role='status'][aria-live='polite']"))
    .toHaveText(/\d+ commands? available/u, { timeout: 15_000 });
}

async function openPalette(page: Page): Promise<Locator> {
  const trigger = page.getByRole("button", { name: "Search or run a command", exact: true });
  await expect(trigger).toBeVisible();
  const initialCollections = ["/api/v2/missions", "/api/v2/runs", "/api/v2/decisions", "/api/v2/agents"];
  const initialResponses = initialCollections.map((path) => page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET" &&
      url.pathname === path &&
      url.searchParams.get("limit") === "100" &&
      !url.searchParams.has("query");
  }));
  await trigger.click();
  const dialog = page.getByRole("dialog", { name: "Command palette", exact: true });
  await expect(dialog).toBeVisible();
  const search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  await expect(search).toBeFocused();
  await expect(search).toHaveAttribute("aria-controls", "command-palette-results");
  await expect(dialog.getByRole("listbox", { name: "Command results", exact: true })).toBeVisible();
  for (const response of await Promise.all(initialResponses)) expect(response.status()).toBe(200);
  await waitForPaletteSearch(dialog);
  return dialog;
}

async function chooseResult(input: {
  page: Page;
  audit: BrowserAudit;
  query: string;
  name: RegExp;
  expectedPath: string;
  keyboard?: boolean;
  remote?: RemoteQueryExpectation;
  assertDestination?: (page: Page) => Promise<void>;
}): Promise<void> {
  await input.audit.withExpectedDocumentNavigationTeardown(input.page, () =>
    input.page.goto("/manual", { waitUntil: "domcontentloaded" }));
  const dialog = await openPalette(input.page);
  const search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  const remoteResponse = input.remote
    ? input.page.waitForResponse((response) => {
        const url = new URL(response.url());
        return response.request().method() === "GET" &&
          url.pathname === input.remote!.pathname &&
          url.searchParams.get("query") === input.query &&
          url.searchParams.get("limit") === String(input.remote!.limit);
      })
    : undefined;
  await search.fill(input.query);
  let optionName = input.name;
  if (remoteResponse && input.remote) {
    const response = await remoteResponse;
    expect(response.status()).toBe(200);
    const payload = await response.json() as { items?: Array<Record<string, unknown>> };
    const item = payload.items?.find((candidate) => candidate.id === input.remote!.itemId);
    expect(item, `Remote ${input.remote.pathname} must return the exact requested record`).toBeDefined();
    if (item && input.remote.optionNameFromItem) optionName = input.remote.optionNameFromItem(item);
  }
  await waitForPaletteSearch(dialog);
  const option = dialog.getByRole("option", { name: optionName }).first();
  await expect(option).toBeVisible();
  // The manual route keeps required notification reads active while the
  // palette is open. Settle those reads before activating a client-side
  // navigation so the destination cannot abort a required request. This is
  // a product boundary: palette navigation must be as clean as a direct link.
  await input.audit.waitForPageApiSettlement(input.page, { quietMs: 1_000 });
  if (input.keyboard) {
    for (let index = 0; index < 20 && await option.getAttribute("aria-selected") !== "true"; index += 1) {
      await search.press("ArrowDown");
    }
    await expect(option).toHaveAttribute("aria-selected", "true");
    await expect(search).toHaveAttribute("aria-activedescendant", await option.getAttribute("id") ?? "");
    await search.press("Enter");
  } else {
    await option.click();
  }
  await expect(input.page).toHaveURL((url) => url.pathname === input.expectedPath);
  const routeSurface = input.page.locator("main#ti-scale-content");
  await expect(routeSurface).toBeVisible();
  await expect(routeSurface.locator("h1:visible, [role='status']:visible").first()).toBeVisible();
  // A route heading can render after its first canonical read while nested
  // mission surfaces are still starting their own required queries. Keep the
  // command activation boundary open until every same-page V2 read has a
  // normal completion receipt; the next palette navigation must never make
  // legitimate plan, evidence, or topology reads look like teardown noise.
  await input.audit.waitForPageApiSettlement(input.page, { quietMs: 1_000 });
  await input.assertDestination?.(input.page);
}

async function assertGuidedSearchDestination(page: Page): Promise<void> {
  await expect(page.getByRole("heading", { name: fixture.missionLabel, exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Exact step decision", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Commander conversation", exact: true })).toBeVisible();
  await expect(page.getByLabel("Current Guided step").getByRole("heading", {
    name: "Collect bounded observation",
    exact: true,
  })).toBeVisible();
  await expect(page.getByLabel("Selected run status")).toContainText("waiting guided decision");
  await expect(page.getByRole("region", { name: "Recon digital twin", exact: true })).toBeVisible();
  await expect(page.locator("main#ti-scale-content .os-state-panel")).toHaveCount(0);
}

function mutationResponse(page: Page, path: string, action: () => Promise<void>) {
  const pending = page.waitForResponse((response) =>
    pathname(response.request()) === path && response.request().method() === "POST");
  return action().then(() => pending);
}

interface RunWorkspaceSettleExpectation {
  readonly runId: string;
  readonly runStatus: string;
  readonly planStatus: string;
  readonly stepStatus: string;
  readonly eventType: string | null;
  readonly eventSummaryIncludes?: string;
  readonly recoveryRequired?: boolean;
}

function waitForRunWorkspaceSettle(
  page: Page,
  expectation: RunWorkspaceSettleExpectation,
): Promise<readonly Response[]> {
  const runId = expectation.runId;
  const matchingGet = (response: Response, expectedPath: string): boolean =>
    response.request().method() === "GET" &&
    new URL(response.url()).pathname === expectedPath &&
    response.status() === 200;
  const run = page.waitForResponse(async (response) => {
    if (!matchingGet(response, `/api/v2/runs/${runId}`)) return false;
    const payload = await response.json() as { run?: { id?: unknown; status?: unknown } };
    return payload.run?.id === runId && payload.run.status === expectation.runStatus;
  });
  const plans = page.waitForResponse(async (response) => {
    if (!matchingGet(response, `/api/v2/runs/${runId}/plans`)) return false;
    const payload = await response.json() as {
      items?: Array<{ runId?: unknown; status?: unknown; steps?: Array<{ status?: unknown }> }>;
    };
    return payload.items?.some((plan) =>
      plan.runId === runId &&
      plan.status === expectation.planStatus &&
      plan.steps?.every((step) => step.status === expectation.stepStatus)) === true;
  });
  const recovery = expectation.recoveryRequired === undefined
    ? undefined
    : page.waitForResponse(async (response) => {
        if (!matchingGet(response, `/api/v2/operations/runs/${runId}/recovery`)) return false;
        const payload = await response.json() as {
          recoveryRequired?: unknown;
          run?: { id?: unknown; status?: unknown };
        };
        return payload.run?.id === runId &&
          payload.run.status === expectation.runStatus &&
          payload.recoveryRequired === expectation.recoveryRequired;
      });
  const events = page.waitForResponse(async (response) => {
    const url = new URL(response.url());
    if (
      !matchingGet(response, "/api/v2/observability/events") ||
      url.searchParams.get("runId") !== runId ||
      url.searchParams.get("limit") !== "30"
    ) return false;
    const payload = await response.json() as {
      items?: Array<{ runId?: unknown; eventType?: unknown; summary?: unknown }>;
    };
    if (expectation.eventType === null) return payload.items?.length === 0;
    return payload.items?.some((event) =>
      event.runId === runId &&
      event.eventType === expectation.eventType &&
      (expectation.eventSummaryIncludes === undefined ||
        (typeof event.summary === "string" && event.summary.includes(expectation.eventSummaryIncludes)))) === true;
  });
  return Promise.all([run, plans, ...(recovery ? [recovery] : []), events]);
}

test(`${TEST_SEARCH} searches real permitted records and activates every result family`, async ({ page }, testInfo) => {
  test.setTimeout(90_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  for (const id of MANIFEST_IDS.slice(0, 9)) manifestEntry(id);

  await page.goto("/manual", { waitUntil: "domcontentloaded" });
  let dialog = await openPalette(page);
  let search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  await search.fill("Mission");
  await expect(dialog.locator("[role='status'][aria-live='polite']"))
    .toHaveText(/\d+ commands? available/u, { timeout: 15_000 });
  const firstActive = await search.getAttribute("aria-activedescendant");
  expect(firstActive).toBeTruthy();
  await search.press("ArrowDown");
  const secondActive = await search.getAttribute("aria-activedescendant");
  expect(secondActive).toBeTruthy();
  expect(secondActive).not.toBe(firstActive);
  await search.press("ArrowUp");
  await expect(search).toHaveAttribute("aria-activedescendant", firstActive!);
  await search.fill("");
  await expect(search).toHaveValue("");
  await expect(dialog.locator("[role='status'][aria-live='polite']"))
    .toHaveText(/\d+ commands? available/u, { timeout: 15_000 });

  await chooseResult({
    page,
    audit,
    query: "Go Autonomous",
    name: /^Go Autonomous.*Compose and validate an authorized mission contract$/u,
    expectedPath: "/missions/new/autonomous",
    keyboard: true,
  });
  await chooseResult({
    page,
    audit,
    query: "Start Guided Mission",
    name: /^Start Guided Mission.*Create a collaborative, deliberate step-by-step mission$/u,
    expectedPath: "/missions/new/guided",
  });
  await chooseResult({
    page,
    audit,
    query: "Observability",
    name: /^Observability.*Navigate to Observability$/u,
    expectedPath: "/observability",
  });
  await chooseResult({
    page,
    audit,
    query: fixture.missionToken,
    name: new RegExp(`^${escapeRegex(fixture.missionLabel)}.*Guided mission.*waiting guided decision$`, "u"),
    expectedPath: `/guided/${fixture.search.missionId}`,
    remote: { pathname: "/api/v2/missions", limit: 100, itemId: fixture.search.missionId },
    assertDestination: assertGuidedSearchDestination,
  });
  await chooseResult({
    page,
    audit,
    query: fixture.search.runId,
    name: new RegExp(`^${escapeRegex(fixture.missionLabel)}.*Guided run.*${escapeRegex(fixture.search.runId)}$`, "u"),
    expectedPath: `/guided/${fixture.search.missionId}`,
    keyboard: true,
    remote: { pathname: "/api/v2/runs", limit: 100, itemId: fixture.search.runId },
    assertDestination: assertGuidedSearchDestination,
  });
  await chooseResult({
    page,
    audit,
    query: fixture.decisionToken,
    name: new RegExp(`^${escapeRegex(fixture.decisionLabel)}.*pending.*low risk`, "u"),
    expectedPath: "/decisions",
    keyboard: true,
    remote: { pathname: "/api/v2/decisions", limit: 100, itemId: fixture.search.decisionId! },
  });
  await chooseResult({
    page,
    audit,
    query: fixture.agentToken,
    name: new RegExp(`^${escapeRegex(fixture.agentLabel)}.*recon-specialist.*available`, "u"),
    expectedPath: `/agents/${fixture.search.agentId}`,
    remote: {
      pathname: "/api/v2/agents",
      limit: 100,
      itemId: fixture.search.agentId,
      optionNameFromItem: (item) => {
        if (item.displayName !== fixture.agentLabel || item.role !== "recon-specialist") {
          throw new Error("The canonical agent search returned an unexpected identity or specialist role");
        }
        if (typeof item.status !== "string" ||
          !AGENT_PALETTE_STATUSES.includes(item.status as typeof AGENT_PALETTE_STATUSES[number])) {
          throw new Error(`The canonical agent search returned unsupported status ${String(item.status)}`);
        }
        const assignmentHealth = item.assignmentHealth;
        if (!assignmentHealth || typeof assignmentHealth !== "object" ||
          !("queueDepth" in assignmentHealth) ||
          !Number.isSafeInteger(assignmentHealth.queueDepth) ||
          Number(assignmentHealth.queueDepth) < 0) {
          throw new Error("The canonical agent search returned an invalid queue depth");
        }
        return new RegExp(
          `^${escapeRegex(fixture.agentLabel)}.*recon-specialist.*${escapeRegex(item.status)}.*queue ${String(assignmentHealth.queueDepth)}$`,
          "u",
        );
      },
    },
  });
  await chooseResult({
    page,
    audit,
    query: fixture.memoryToken,
    name: new RegExp(`^${escapeRegex(fixture.memoryLabel)}.*preference.*confirmed`, "u"),
    expectedPath: `/brain/nodes/${fixture.memoryNodeId}`,
    remote: { pathname: "/api/v2/brain/nodes", limit: 30, itemId: fixture.memoryNodeId },
  });
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  await audit.assertClean(testInfo);
});

test(`${TEST_RUN_CONTROL} pauses, exactly resumes, and cancels disposable runs through reviewed editors`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const idempotencyKeys: string[] = [];
  for (const id of MANIFEST_IDS.slice(9, 14)) manifestEntry(id);
  const pausePath = `/api/v2/runs/${fixture.pauseResume.runId}/pause`;
  const resumePath = `/api/v2/runs/${fixture.pauseResume.runId}/resume`;
  let pauseMutationCount = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && pathname(request) === pausePath) pauseMutationCount += 1;
  });

  await page.goto(`/live/${fixture.pauseResume.runId}`, { waitUntil: "domcontentloaded" });
  let dialog = await openPalette(page);
  let search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  await search.fill("Pause current run");
  await waitForPaletteSearch(dialog);
  const pauseOption = dialog.getByRole("option", { name: /^Pause current run/u });
  await pauseOption.click();
  await expect(dialog.getByRole("heading", { name: /^Pause /u })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(search).toBeFocused();

  await pauseOption.click();
  await dialog.getByRole("button", { name: "Back to command results", exact: true }).click();
  await expect(search).toBeFocused();
  expect(pauseMutationCount).toBe(0);

  await pauseOption.click();
  const reason = dialog.getByRole("textbox", { name: "Audited reason", exact: true });
  const confirmPause = dialog.getByRole("button", { name: "Confirm pause", exact: true });
  await expect(confirmPause).toBeDisabled();
  const pauseReason = "Pause through the reviewed global command boundary.";
  await reason.fill(pauseReason);
  const paused = await mutationResponse(page, pausePath, () => confirmPause.click());
  expect(paused.status()).toBe(200);
  expect(pauseMutationCount).toBe(1);
  expect(paused.request().postDataJSON()).toEqual({ reason: pauseReason });
  const pauseKey = paused.request().headers()["idempotency-key"];
  expect(pauseKey).toMatch(/^palette-run-pause-/u);
  idempotencyKeys.push(pauseKey!);
  expect(await paused.json()).toMatchObject({ run: { id: fixture.pauseResume.runId, status: "blocked" } });
  const afterPause = readRunInterventionRecoverySnapshot(fixture.pauseResume);
  expect(afterPause.run.status).toBe("blocked");
  expect(afterPause.checkpoints.at(-1)).toMatchObject({ stateHashVerified: true, inFlightCount: 0 });
  expect(afterPause.audits.at(-1)).toEqual({
    action: "run.paused",
    reason: "Pause through the reviewed global command boundary.",
  });

  search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  await search.fill("Resume current run");
  await waitForPaletteSearch(dialog);
  await dialog.getByRole("option", { name: /^Resume current run/u }).click();
  const resumeReason = "Resume only the exact verified zero-in-flight checkpoint.";
  await dialog.getByRole("textbox", { name: "Audited reason", exact: true }).fill(resumeReason);
  const resumedExpectation = {
    runId: fixture.pauseResume.runId,
    runStatus: "waiting_guided_decision",
    planStatus: "active",
    stepStatus: "waiting_guided_decision",
    recoveryRequired: false,
    eventType: "run.state_changed",
    eventSummaryIncludes: "blocked -> waiting_guided_decision",
  } satisfies RunWorkspaceSettleExpectation;
  const postResumeReconciliation = waitForRunWorkspaceSettle(page, resumedExpectation);
  const resumed = await mutationResponse(page, resumePath, () =>
    dialog.getByRole("button", { name: "Confirm resume", exact: true }).click());
  expect(resumed.status()).toBe(200);
  const resumeBody = resumed.request().postDataJSON() as Record<string, unknown>;
  expect(resumeBody).toEqual({
    reason: resumeReason,
    expectedRunVersion: afterPause.run.version,
    expectedRunStatus: "blocked",
    expectedCheckpointId: afterPause.checkpoints.at(-1)?.id,
    expectedCheckpointStateHash: afterPause.checkpoints.at(-1)?.stateHash,
    expectedCheckpointEventSequence: afterPause.checkpoints.at(-1)?.eventSequence,
  });
  const resumeKey = resumed.request().headers()["idempotency-key"];
  expect(resumeKey).toMatch(/^palette-run-resume-/u);
  idempotencyKeys.push(resumeKey!);
  expect(await resumed.json()).toMatchObject({
    run: { id: fixture.pauseResume.runId, status: "waiting_guided_decision" },
  });
  expect((await postResumeReconciliation).map((response) => response.status()))
    .toEqual([200, 200, 200, 200]);
  const resumedWorkspace = waitForRunWorkspaceSettle(page, resumedExpectation);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await resumedWorkspace).map((response) => response.status())).toEqual([200, 200, 200, 200]);
  await expect(page.getByLabel("Selected run status"))
    .toContainText("waiting guided decision", { timeout: 15_000 });

  const cancelPath = `/api/v2/runs/${fixture.cancel.runId}/cancel`;
  const initialCancelWorkspace = waitForRunWorkspaceSettle(page, {
    runId: fixture.cancel.runId,
    runStatus: "running",
    planStatus: "active",
    stepStatus: "running",
    eventType: null,
  });
  await audit.withExpectedDocumentNavigationTeardown(page, () =>
    page.goto(`/live/${fixture.cancel.runId}`, { waitUntil: "domcontentloaded" }));
  expect((await initialCancelWorkspace).map((response) => response.status())).toEqual([200, 200, 200]);
  dialog = await openPalette(page);
  search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  await search.fill("Cancel current run");
  await waitForPaletteSearch(dialog);
  await dialog.getByRole("option", { name: /^Cancel current run/u }).click();
  const cancelReason = "Terminate the disposable palette fixture and all durable child work.";
  await dialog.getByRole("textbox", { name: "Audited reason", exact: true }).fill(cancelReason);
  const confirmCancel = dialog.getByRole("button", { name: "Confirm cancel", exact: true });
  await expect(confirmCancel).toBeDisabled();
  const cancelAttestation = dialog.getByRole("checkbox", {
    name: "I understand this ends the current run and does not expand authorization.",
    exact: true,
  });
  await cancelAttestation.focus();
  await cancelAttestation.press("Space");
  await expect(cancelAttestation).toBeChecked();
  // Register before the mutation so no fast WebKit response can escape the
  // synchronization boundary. Each predicate requires terminal canonical
  // content, so an earlier event-driven refresh cannot satisfy it.
  const postCancelReconciliation = waitForRunWorkspaceSettle(page, {
    runId: fixture.cancel.runId,
    runStatus: "cancelled",
    planStatus: "abandoned",
    stepStatus: "cancelled",
    eventType: "run.cancelled",
  });
  const cancelled = await mutationResponse(page, cancelPath, () => confirmCancel.press("Enter"));
  expect(cancelled.status()).toBe(200);
  expect(cancelled.request().postDataJSON()).toEqual({ reason: cancelReason });
  const cancelKey = cancelled.request().headers()["idempotency-key"];
  expect(cancelKey).toMatch(/^palette-run-cancel-/u);
  idempotencyKeys.push(cancelKey!);
  expect(new Set(idempotencyKeys).size).toBe(3);
  expect(await cancelled.json()).toMatchObject({ run: { id: fixture.cancel.runId, status: "cancelled" } });
  const afterCancel = readRunInterventionRecoverySnapshot(fixture.cancel);
  expect(afterCancel.run.status).toBe("cancelled");
  expect(afterCancel.executingChildCount).toBe(0);
  expect(afterCancel.activeChildCount).toBe(0);
  expect(afterCancel.durableRunLeaseActive).toBe(false);
  expect(afterCancel.activeControlPlaneLeaseCount).toBe(0);
  const cancellationAudits = afterCancel.audits.filter((record) => record.action === "run.cancelled");
  expect(cancellationAudits).toEqual([{
    action: "run.cancelled",
    reason: "Terminate the disposable palette fixture and all durable child work.",
  }]);
  const cancellationAuditIndex = afterCancel.audits.findIndex((record) => record.action === "run.cancelled");
  const terminalBrainHookIndex = afterCancel.audits.findIndex((record, index) =>
    index > cancellationAuditIndex && record.action === "brain.context_hook.invoked");
  expect(cancellationAuditIndex).toBeGreaterThanOrEqual(0);
  expect(terminalBrainHookIndex).toBeGreaterThan(cancellationAuditIndex);
  const reconciledResponses = await postCancelReconciliation;
  expect(reconciledResponses.map((response) => response.status())).toEqual([200, 200, 200]);
  await expect(page.getByLabel("Selected run status"))
    .toContainText("cancelled", { timeout: 15_000 });
  const cancelledWorkspace = waitForRunWorkspaceSettle(page, {
    runId: fixture.cancel.runId,
    runStatus: "cancelled",
    planStatus: "abandoned",
    stepStatus: "cancelled",
    eventType: "run.cancelled",
  });
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await cancelledWorkspace).map((response) => response.status())).toEqual([200, 200, 200]);
  dialog = await openPalette(page);
  await dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  }).fill("Cancel current run");
  await waitForPaletteSearch(dialog);
  await expect(dialog.getByText("No matching permitted commands or records.", { exact: true })).toBeVisible();
  await audit.assertClean(testInfo);
});

test(`${TEST_MEMORY} creates only a reviewable Guided memory candidate with audited provenance`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  manifestEntry("command-palette.editor-back");
  for (const id of MANIFEST_IDS.slice(14)) manifestEntry(id);
  await page.goto(`/guided/${fixture.memoryCandidate.missionId}`, { waitUntil: "domcontentloaded" });
  const rememberPath = `/api/v2/guided/${fixture.memoryCandidate.missionId}/commander/remember`;
  let rememberMutationCount = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && pathname(request) === rememberPath) rememberMutationCount += 1;
  });
  const dialog = await openPalette(page);
  const search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  await search.fill("Create memory candidate");
  await waitForPaletteSearch(dialog);
  const command = dialog.getByRole("option", {
    name: /^Create memory candidate from latest Guided insight/u,
  });
  await expect(command).toBeVisible();
  await expect(command).toHaveAttribute("aria-selected", "true");
  await expect(search).toHaveAttribute("aria-activedescendant", await command.getAttribute("id") ?? "");
  await search.press("Enter");
  await expect(dialog.getByRole("heading", { name: "Create a reviewable memory candidate", exact: true })).toBeVisible();
  await dialog.getByRole("button", { name: "Back to command results", exact: true }).click();
  await expect(search).toBeFocused();
  await command.click();
  await page.keyboard.press("Escape");
  await expect(search).toBeFocused();
  expect(rememberMutationCount).toBe(0);
  await command.click();
  await expect(dialog.getByRole("heading", { name: "Create a reviewable memory candidate", exact: true })).toBeVisible();

  const type = dialog.getByRole("combobox", { name: "Type", exact: true });
  const scope = dialog.getByRole("combobox", { name: "Scope", exact: true });
  const sensitivity = dialog.getByRole("combobox", { name: "Sensitivity", exact: true });
  await type.selectOption("preference");
  await scope.selectOption("global");
  await type.selectOption("source");
  await expect(scope).toHaveValue("mission");
  await expect(scope.locator('option[value="global"]')).toHaveCount(0);
  for (const value of ["procedure", "tool", "tactic", "technique"] as const) {
    await type.selectOption(value);
    await expect(type).toHaveValue(value);
  }
  await type.selectOption("preference");
  for (const value of ["mission", "engagement", "global"] as const) {
    await scope.selectOption(value);
    await expect(scope).toHaveValue(value);
  }
  for (const value of ["private", "restricted", "internal"] as const) {
    await sensitivity.selectOption(value);
    await expect(sensitivity).toHaveValue(value);
  }
  await dialog.getByRole("textbox", { name: "Title", exact: true })
    .fill(fixture.candidateTitle);
  const candidateSummary = "Keep Guided explanations concise and evidence-led when this candidate is later confirmed.";
  await dialog.getByRole("textbox", { name: "Summary", exact: true }).fill(candidateSummary);
  refreshCommandPaletteMemoryCandidateAuthority(fixture);
  const created = await mutationResponse(page, rememberPath, () =>
    dialog.getByRole("button", { name: "Create candidate", exact: true }).click());
  expect(created.status()).toBe(201);
  expect(rememberMutationCount).toBe(1);
  const memoryKey = created.request().headers()["idempotency-key"];
  expect(memoryKey).toMatch(/^palette-memory-candidate-/u);
  expect(created.request().postDataJSON()).toEqual({
    runId: fixture.memoryCandidate.runId,
    stepId: fixture.memoryCandidate.stepId,
    expectedFingerprint: fixture.expectedFingerprint,
    sourceMessageId: fixture.sourceMessageId,
    nodeType: "preference",
    title: fixture.candidateTitle,
    summary: candidateSummary,
    scope: "global",
    sensitivity: "internal",
  });
  const createdPayload = await created.json() as {
    result: { candidateId: string; status: string; sourceMessageId: string };
  };
  expect(createdPayload).toMatchObject({ result: { status: "pending", sourceMessageId: fixture.sourceMessageId } });
  await expect(dialog.getByRole("status").filter({ hasText: "It is not confirmed memory until you approve it" }))
    .toBeVisible();
  const snapshot = readCommandPaletteCandidateSnapshot(fixture);
  expect(snapshot.candidates).toHaveLength(1);
  expect(snapshot.candidates[0]).toMatchObject({
    type: "preference",
    title: fixture.candidateTitle,
    scope: "global",
    sensitivity: "internal",
    status: "pending",
    proposedBy: "e2e-local-operator",
  });
  expect(snapshot.candidates[0]?.id).toBe(createdPayload.result.candidateId);
  expect(snapshot.candidates[0]?.missionId).toBeNull();
  expect(JSON.stringify(snapshot.candidates[0]?.source)).toContain(fixture.sourceMessageId);
  expect(snapshot.confirmedNodeCount).toBe(0);
  expect(snapshot.audits).toEqual([{
    action: "memory.candidate_created",
    missionId: fixture.memoryCandidate.missionId,
    runId: fixture.memoryCandidate.runId,
    resourceId: createdPayload.result.candidateId,
  }]);
  expect(snapshot.events).toEqual([{
    eventType: "memory.candidate_created",
    missionId: fixture.memoryCandidate.missionId,
    runId: fixture.memoryCandidate.runId,
    candidateId: createdPayload.result.candidateId,
  }]);
  const exactInboxRead = page.waitForResponse(async (response) => {
    const url = new URL(response.url());
    if (
      response.request().method() !== "GET" ||
      url.pathname !== "/api/v2/brain/candidates" ||
      url.searchParams.get("missionId") !== fixture.memoryCandidate.missionId ||
      url.searchParams.get("runId") !== fixture.memoryCandidate.runId ||
      url.searchParams.get("limit") !== "50" ||
      response.status() !== 200
    ) return false;
    const payload = await response.json() as { items?: Array<{ id?: unknown }> };
    return payload.items?.some((candidate) => candidate.id === createdPayload.result.candidateId) === true;
  });
  // Creating a candidate refreshes notifications on the Guided route. Do not
  // let the subsequent palette navigation cancel those required reads.
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  await dialog.getByRole("button", { name: "Open Memory Inbox", exact: true }).click();
  await expect(page).toHaveURL((url) =>
    url.pathname === "/brain/inbox" &&
    url.searchParams.get("missionId") === fixture.memoryCandidate.missionId &&
    url.searchParams.get("runId") === fixture.memoryCandidate.runId);
  expect((await exactInboxRead).status()).toBe(200);
  await expect(page.getByText(fixture.candidateTitle, { exact: true })).toBeVisible();
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByText(fixture.candidateTitle, { exact: true })).toBeVisible();
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  await audit.assertClean(testInfo);
});

test(`${TEST_DEGRADED} names a partial endpoint failure while retaining authoritative local navigation`, async ({ page }, testInfo) => {
  const agentPath = "/api/v2/agents";
  const brainPath = "/api/v2/brain/nodes";
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: [
      {
        id: "command-palette.agents-query-partial",
        transport: "browser",
        method: "GET",
        pathname: agentPath,
        query: { query: fixture.agentToken, limit: "100" },
        status: 503,
        occurrences: 1,
        reason: "Prove a failed agent query omits stale agent rows without hiding authoritative local commands.",
      },
      {
        id: "command-palette.brain-query-partial",
        transport: "browser",
        method: "GET",
        pathname: brainPath,
        query: { query: fixture.memoryToken, limit: "30" },
        status: 503,
        occurrences: 1,
        reason: "Prove failed permitted-memory search never invents or reuses a stale Brain result.",
      },
    ],
  });
  await page.route((url) =>
    url.pathname === agentPath &&
    url.searchParams.get("query") === fixture.agentToken &&
    url.searchParams.get("limit") === "100", (route) =>
    route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "fixture_agent_catalog_unavailable",
          message: "Agent catalog unavailable",
          humanMessage: "Agent search is temporarily unavailable.",
          retryable: true,
          category: "provider_unavailable",
          details: {},
          traceId: "trace-command-palette-partial",
          remediation: "Retry after agent health recovers.",
          timestamp: new Date().toISOString(),
        },
      }),
    }));
  await page.route((url) =>
    url.pathname === brainPath &&
    url.searchParams.get("query") === fixture.memoryToken &&
    url.searchParams.get("limit") === "30", (route) =>
    route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "fixture_brain_search_unavailable",
          message: "Second Brain search unavailable",
          humanMessage: "Permitted Second Brain search is temporarily unavailable.",
          retryable: true,
          category: "dependency_unavailable",
          details: {},
          traceId: "trace-command-palette-brain-partial",
          remediation: "Retry after the local Brain index recovers.",
          timestamp: new Date().toISOString(),
        },
      }),
    }));
  await page.goto("/manual", { waitUntil: "domcontentloaded" });
  const trigger = page.getByRole("button", { name: "Search or run a command", exact: true });
  const dialog = await openPalette(page);
  const search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  await search.fill(fixture.agentToken);
  await expect(dialog.locator("[role='status'][aria-live='polite']"))
    .toHaveText(/\d+ commands? available/u, { timeout: 15_000 });
  await expect(dialog.getByRole("status").filter({ hasText: "Search results are unavailable for: agents" }))
    .toBeVisible();
  await expect(dialog.getByRole("option", { name: new RegExp(escapeRegex(fixture.agentLabel), "u") }))
    .toHaveCount(0);

  await search.fill(fixture.memoryToken);
  await expect(dialog.locator("[role='status'][aria-live='polite']"))
    .toHaveText(/\d+ commands? available/u, { timeout: 15_000 });
  await expect(dialog.getByRole("status").filter({ hasText: "Search results are unavailable for: Second Brain" }))
    .toBeVisible();
  await expect(dialog.getByRole("option", { name: new RegExp(escapeRegex(fixture.memoryLabel), "u") }))
    .toHaveCount(0);

  await search.fill("Reports");
  await expect(dialog.locator("[role='status'][aria-live='polite']"))
    .toHaveText(/\d+ commands? available/u, { timeout: 15_000 });
  const reportsResponse = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET" &&
      url.pathname === "/api/v2/reports" &&
      url.searchParams.get("limit") === "25";
  });
  await dialog.getByRole("option", { name: /^Reports.*Navigate to Reports$/u }).click();
  await expect(page).toHaveURL((url) => url.pathname === "/reports");
  expect((await reportsResponse).status()).toBe(200);
  await audit.waitForPageApiSettlement(page);
  await expect(page.getByRole("dialog", { name: "Command palette", exact: true })).toHaveCount(0);
  await expect(trigger).toBeVisible();
  await audit.assertClean(testInfo);
});

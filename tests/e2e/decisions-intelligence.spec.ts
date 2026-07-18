import { expect, test, type Download, type Locator, type Page, type Response, type TestInfo } from "./support/playwright";
import { readFileSync } from "node:fs";
import { BrowserAudit } from "./support/browserAudit";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createDecisionsIntelligenceFixture,
  readDecisionsIntelligenceFixtureSnapshot,
  type DecisionsIntelligenceFixture,
} from "./support/decisionsIntelligenceFixture";

const TEST_IDS = {
  decisionFilters: "e2e.decisions.read-filter-pagination",
  decisionCards: "e2e.decisions.cards-controls-deep-links",
  decisionAliasRetry: "e2e.decisions.alias-empty-retry",
  evidence: "e2e.intelligence.evidence-list-detail-export",
  findings: "e2e.intelligence.findings-list-detail-controls",
  artifacts: "e2e.intelligence.artifacts-list-detail-controls",
  intelligenceRetry: "e2e.intelligence.empty-error-retry",
} as const;

const DECISION_KINDS = [
  "autonomous_exception",
  "administrative_approval",
  "guided_decision",
  "autonomous_contract",
] as const;
const DECISION_STATUSES = [
  "pending", "attention", "post_run", "draft", "confirmed", "superseded", "revoked",
  "approved", "manual", "alternative", "rejected", "expired", "cancelled",
] as const;
const EVIDENCE_STATES = ["unverified", "verified", "disputed", "rejected"] as const;
const FINDING_SEVERITIES = ["informational", "low", "medium", "high", "critical"] as const;
const FINDING_REVIEWS = ["draft", "under_review", "verified", "rejected", "accepted_risk"] as const;

let fixture: DecisionsIntelligenceFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createDecisionsIntelligenceFixture(canonicalFixtureNamespace(testInfo, "decisions-intelligence"));
});

function pathname(response: Response): string {
  return new URL(response.url()).pathname;
}

function apiResponse(
  page: Page,
  path: string,
  predicate: (url: URL) => boolean = () => true,
): Promise<Response> {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET" && url.pathname === path && predicate(url);
  });
}

async function pagePayload(response: Response): Promise<{
  readonly items: readonly Record<string, unknown>[];
  readonly nextCursor: string | null;
}> {
  expect(response.status()).toBe(200);
  const payload = await response.json() as {
    readonly items: readonly Record<string, unknown>[];
    readonly nextCursor: string | null;
  };
  expect(Array.isArray(payload.items)).toBe(true);
  return payload;
}

async function strictAudit(audit: BrowserAudit, testInfo: TestInfo): Promise<void> {
  expect(audit.unexpected, "Unexpected browser, console, network, or server failures").toEqual([]);
  expect(audit.degradedApi, "This source slice requires the real mounted V2 API").toEqual([]);
  await audit.assertClean(testInfo);
}

async function activate(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await control.press("Enter");
  } else {
    await control.click();
  }
}

async function toggle(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await control.press("Space");
  } else {
    await control.click();
  }
}

async function optionLabels(control: Locator): Promise<string[]> {
  await expect(control).toBeVisible();
  await expect(control.locator("option").first()).toBeAttached();
  return control.locator("option").allTextContents();
}

async function expectHeading(page: Page, name: string): Promise<void> {
  await expect(page.getByRole("heading", { level: 1, name, exact: true })).toBeVisible();
  await expect(page.getByText("Command surface not found", { exact: true })).toHaveCount(0);
}

async function setSelectFilter(
  page: Page,
  path: string,
  control: Locator,
  parameter: string,
  value: string,
): Promise<readonly Record<string, unknown>[]> {
  const response = apiResponse(page, path, (url) => url.searchParams.get(parameter) === value);
  await control.selectOption(value);
  const payload = await pagePayload(await response);
  await expect.poll(() => new URL(page.url()).searchParams.get(parameter)).toBe(value);
  return payload.items;
}

async function clearSelectFilter(page: Page, _path: string, control: Locator, parameter: string): Promise<void> {
  await control.selectOption("");
  await expect(control).toHaveValue("");
  await expect.poll(() => new URL(page.url()).searchParams.has(parameter)).toBe(false);
}

function fixtureSnapshot() {
  return readDecisionsIntelligenceFixtureSnapshot(fixture);
}

function decisionUrl(parameters: Record<string, string> = {}): string {
  const query = new URLSearchParams({ query: fixture.searchToken, ...parameters });
  return `/decisions?${query.toString()}`;
}

function intelligenceUrl(
  view: "evidence" | "findings" | "artifacts",
  parameters: Record<string, string> = {},
): string {
  const query = new URLSearchParams({ missionId: fixture.intelligenceMissionId, ...parameters });
  return `/intelligence/${view}?${query.toString()}`;
}

test(`${TEST_IDS.decisionFilters} reads every canonical kind/state filter and traverses the stable cursor`, async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const initial = apiResponse(page, "/api/v2/decision-inbox", (url) => url.searchParams.get("query") === fixture.searchToken);
  await page.goto(decisionUrl(), { waitUntil: "domcontentloaded" });
  const first = await pagePayload(await initial);
  await expectHeading(page, "Decisions");
  expect(first.items).toHaveLength(50);
  expect(first.nextCursor).toEqual(expect.any(String));
  expect(fixture.decisionInboxCount).toBeGreaterThan(50);

  const kind = page.getByRole("combobox", { name: "Record type", exact: true });
  const state = page.getByRole("combobox", { name: "State", exact: true });
  expect(await optionLabels(kind)).toEqual([
    "All",
    "Autonomous safe stops and exceptions",
    "Administrative approvals",
    "Guided exact-step decisions",
    "Autonomous mission contracts",
  ]);
  expect(await optionLabels(state)).toEqual(["All", ...DECISION_STATUSES.map((value) => value.replaceAll("_", " "))]);

  const next = page.getByRole("button", { name: "Next page", exact: true });
  const firstPage = page.getByRole("button", { name: "First page", exact: true });
  await expect(firstPage).toBeDisabled();
  await expect(next).toBeEnabled();
  const nextResponse = apiResponse(page, "/api/v2/decision-inbox", (url) => Boolean(url.searchParams.get("cursor")));
  await activate(next, "pointer");
  const second = await pagePayload(await nextResponse);
  expect(second.items.length).toBe(fixture.decisionInboxCount - 50);
  await expect(firstPage).toBeEnabled();
  const firstResponse = apiResponse(page, "/api/v2/decision-inbox", (url) => !url.searchParams.has("cursor"));
  await activate(firstPage, "keyboard");
  await pagePayload(await firstResponse);

  for (const value of DECISION_KINDS) {
    const items = await setSelectFilter(page, "/api/v2/decision-inbox", kind, "kind", value);
    expect(items.every((item) => item.kind === value)).toBe(true);
  }
  await clearSelectFilter(page, "/api/v2/decision-inbox", kind, "kind");

  for (const value of DECISION_STATUSES) {
    const items = await setSelectFilter(page, "/api/v2/decision-inbox", state, "status", value);
    expect(items.every((item) => item.status === value)).toBe(true);
  }
  await clearSelectFilter(page, "/api/v2/decision-inbox", state, "status");

  const missionInput = page.getByLabel("Mission ID", { exact: true });
  const missionResponse = apiResponse(page, "/api/v2/decision-inbox", (url) => url.searchParams.get("missionId") === fixture.toolMissionId);
  await missionInput.fill(fixture.toolMissionId);
  const missionItems = (await pagePayload(await missionResponse)).items;
  expect(missionItems).toEqual([expect.objectContaining({ id: fixture.toolDecisionId, kind: "guided_decision" })]);
  const clearMission = apiResponse(page, "/api/v2/decision-inbox", (url) => !url.searchParams.has("missionId"));
  await missionInput.fill("");
  await pagePayload(await clearMission);

  const runInput = page.getByLabel("Run ID", { exact: true });
  const runResponse = apiResponse(page, "/api/v2/decision-inbox", (url) => url.searchParams.get("runId") === fixture.autonomousTerminalRunId);
  await runInput.fill(fixture.autonomousTerminalRunId);
  const runItems = (await pagePayload(await runResponse)).items;
  expect(runItems.some((item) => item.id === fixture.terminalExceptionId)).toBe(true);
  expect(runItems.some((item) => item.id === fixture.terminalApprovalId)).toBe(true);
  const clearRun = apiResponse(page, "/api/v2/decision-inbox", (url) => !url.searchParams.has("runId"));
  await runInput.fill("");
  await pagePayload(await clearRun);

  const search = page.getByLabel("Mission, run, record, or event", { exact: true });
  await search.fill(fixture.terminalApprovalId);
  const searchedResponse = apiResponse(page, "/api/v2/decision-inbox", (url) => url.searchParams.get("query") === fixture.terminalApprovalId);
  await activate(page.getByRole("button", { name: "Apply filters", exact: true }), "keyboard");
  const searched = await pagePayload(await searchedResponse);
  expect(searched.items).toEqual([expect.objectContaining({ id: fixture.terminalApprovalId })]);

  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.decisionCards} exercises every rendered card control without invoking the fail-closed execution routes`, async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const before = fixtureSnapshot();
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });

  const guidedResponse = apiResponse(page, "/api/v2/decision-inbox", (url) => url.searchParams.get("kind") === "guided_decision");
  await page.goto(decisionUrl({ kind: "guided_decision" }), { waitUntil: "domcontentloaded" });
  await pagePayload(await guidedResponse);
  const toolCard = page.locator(".os-guided-decision-card").filter({
    has: page.getByRole("heading", { name: "Inspect the exact approved endpoint with the bounded read-only specialist.", exact: true }),
  });
  const manualCard = page.locator(".os-guided-decision-card").filter({
    has: page.getByRole("heading", { name: "Review the exact retained response manually before interpretation.", exact: true }),
  });
  await expect(toolCard).toBeVisible();
  await expect(manualCard).toBeVisible();
  await expect(page.getByText(
    "Exact Guided runtime controls are read-only because this V2 process has no callable Guided provider/runtime boundary. Connect and attest that boundary before executing a represented step.",
    { exact: true },
  )).toBeVisible();
  const toolParameters = toolCard.locator("details").filter({ hasText: "Exact normalized parameters" });
  await activate(toolParameters.locator("summary"), "keyboard");
  await expect(toolParameters).toHaveJSProperty("open", true);
  const manualParameters = manualCard.locator("details").filter({ hasText: "Exact normalized parameters" });
  await activate(manualParameters.locator("summary"), "pointer");
  await expect(manualParameters).toHaveJSProperty("open", true);
  expect(await page.locator("body").innerText()).not.toContain("fixture-secret-must-redact");
  await expect(toolParameters).toContainText("[REDACTED]");

  await toolCard.getByLabel("Optional authorization note", { exact: true }).fill("Bounded read-only execution only");
  await expect(toolCard.getByRole("button", { name: "Run this exact step", exact: true })).toBeDisabled();
  await expect(manualCard.getByRole("button", { name: "Run this exact step", exact: true })).toHaveCount(0);
  await expect(manualCard.getByText("This operator-run step cannot be dispatched through MCP.", { exact: false })).toBeVisible();

  const rejection = toolCard.getByLabel("Required rejection reason", { exact: true });
  const reject = toolCard.getByRole("button", { name: "Reject and replan", exact: true });
  await expect(reject).toBeDisabled();
  await rejection.fill("Use a different bounded observation source");
  await expect(reject).toBeDisabled();
  const skipReason = toolCard.getByLabel("Required skip reason", { exact: true });
  const skip = toolCard.getByRole("button", { name: "Skip exact step", exact: true });
  await expect(skip).toBeDisabled();
  await skipReason.fill("The bounded observation is not required for this fixture review");
  await expect(skip).toBeDisabled();
  const stopReason = toolCard.getByLabel("Required stop reason", { exact: true });
  const stopConfirmation = toolCard.getByRole("checkbox", { name: "I understand this stops the entire mission, not only this step.", exact: true });
  const stop = toolCard.getByRole("button", { name: "Stop mission", exact: true });
  await stopReason.fill("Stop after verifying the read-only decision projection");
  await expect(stop).toBeDisabled();
  await toggle(stopConfirmation, "keyboard");
  await expect(stopConfirmation).toBeChecked();
  await expect(stop).toBeDisabled();
  await toggle(stopConfirmation, "pointer");
  await expect(stopConfirmation).not.toBeChecked();

  const guidedLink = toolCard.getByRole("link", { name: "Open Guided result review", exact: true });
  await expect(guidedLink).toHaveAttribute("href", `/guided/${fixture.toolMissionId}`);
  const guidedRead = apiResponse(page, `/api/v2/missions/${fixture.toolMissionId}/runtime`);
  await activate(guidedLink, "pointer");
  expect((await guidedRead).status()).toBe(200);
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/guided/${fixture.toolMissionId}`);
  await expectHeading(page, `${fixture.searchToken} Guided exact tool decision`);
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  const guidedReturnRead = apiResponse(page, "/api/v2/decision-inbox", (url) => (
    url.searchParams.get("kind") === "guided_decision"
    && url.searchParams.get("query") === fixture.searchToken
  ));
  await page.goBack({ waitUntil: "domcontentloaded" });
  await pagePayload(await guidedReturnRead);
  await expectHeading(page, "Decisions");

  const contractResponse = apiResponse(page, "/api/v2/decision-inbox", (url) => url.searchParams.get("kind") === "autonomous_contract");
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    decisionUrl({ kind: "autonomous_contract", missionId: fixture.autonomousTerminalMissionId }),
    { waitUntil: "domcontentloaded" },
  ));
  await pagePayload(await contractResponse);
  const contractLink = page.locator(`a[href="/missions/${fixture.autonomousTerminalMissionId}?tab=settings"]`).filter({ hasText: "Open contract settings" }).first();
  await expect(contractLink).toBeVisible();
  await activate(contractLink, "keyboard");
  await expect.poll(() => `${new URL(page.url()).pathname}${new URL(page.url()).search}`).toBe(`/missions/${fixture.autonomousTerminalMissionId}?tab=settings`);
  await expectHeading(page, `${fixture.searchToken} Autonomous terminal exception`);
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  const contractReturnRead = apiResponse(page, "/api/v2/decision-inbox", (url) => (
    url.searchParams.get("kind") === "autonomous_contract"
    && url.searchParams.get("missionId") === fixture.autonomousTerminalMissionId
    && url.searchParams.get("query") === fixture.searchToken
  ));
  await page.goBack({ waitUntil: "domcontentloaded" });
  await pagePayload(await contractReturnRead);

  const exceptionResponse = apiResponse(page, "/api/v2/decision-inbox", (url) => url.searchParams.get("kind") === "autonomous_exception");
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    decisionUrl({ kind: "autonomous_exception" }),
    { waitUntil: "domcontentloaded" },
  ));
  await pagePayload(await exceptionResponse);
  const terminalException = page.locator(".os-card").filter({ hasText: `${fixture.searchToken} no in-contract path remained after bounded recovery` });
  const exceptionDetails = terminalException.locator("details").filter({ hasText: "Redacted exception detail" });
  await activate(exceptionDetails.locator("summary"), "pointer");
  await expect(exceptionDetails).toContainText("outside_contract");
  expect(await exceptionDetails.innerText()).not.toContain("fixture-secret-must-redact");
  const recoveryLink = terminalException.getByRole("link", { name: "Open run recovery", exact: true });
  await expect(recoveryLink).toHaveAttribute("href", `/missions/${fixture.autonomousTerminalMissionId}/runs/${fixture.autonomousTerminalRunId}`);
  const recoveryRunRead = apiResponse(page, `/api/v2/runs/${fixture.autonomousTerminalRunId}`);
  const recoveryActionsRead = apiResponse(
    page,
    "/api/v2/operations/actions",
    (url) => url.searchParams.get("runId") === fixture.autonomousTerminalRunId,
  );
  await activate(recoveryLink, "pointer");
  const [recoveryRunResponse, recoveryActionsResponse] = await Promise.all([
    recoveryRunRead,
    recoveryActionsRead,
  ]);
  expect(recoveryRunResponse.status()).toBe(200);
  expect(recoveryActionsResponse.status()).toBe(200);
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/missions/${fixture.autonomousTerminalMissionId}/runs/${fixture.autonomousTerminalRunId}`);
  await expectHeading(page, `${fixture.searchToken} Autonomous terminal exception`);
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  const exceptionReturnRead = apiResponse(page, "/api/v2/decision-inbox", (url) => (
    url.searchParams.get("kind") === "autonomous_exception"
    && url.searchParams.get("query") === fixture.searchToken
  ));
  await page.goBack({ waitUntil: "domcontentloaded" });
  await pagePayload(await exceptionReturnRead);

  const approvalsResponse = apiResponse(page, "/api/v2/decision-inbox", (url) => url.searchParams.get("kind") === "administrative_approval");
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    decisionUrl({ kind: "administrative_approval" }),
    { waitUntil: "domcontentloaded" },
  ));
  await pagePayload(await approvalsResponse);
  const terminalApproval = page.locator(".os-card").filter({ hasText: `${fixture.searchToken} review a future-only policy change` });
  const terminalRequest = terminalApproval.locator("details").filter({ hasText: "Redacted administrative request" });
  await activate(terminalRequest.locator("summary"), "keyboard");
  await expect(terminalRequest).toContainText("future-only");
  expect(await terminalRequest.innerText()).not.toContain("fixture-secret-must-redact");
  await expect(terminalApproval.getByText(
    "This identity does not have administrative review permission.",
    { exact: true },
  )).toBeVisible();
  await expect(terminalApproval.getByLabel("Required administrative decision reason", { exact: true })).toHaveCount(0);
  await expect(terminalApproval.getByRole("button", { name: "Approve for future/admin effect", exact: true })).toHaveCount(0);
  await expect(terminalApproval.getByRole("button", { name: "Reject", exact: true })).toHaveCount(0);
  const related = terminalApproval.getByRole("link", { name: "Open related context", exact: true });
  await expect(related).toHaveAttribute("href", `/missions/${fixture.autonomousTerminalMissionId}/runs/${fixture.autonomousTerminalRunId}`);

  const activeApproval = page.locator(".os-card").filter({ hasText: `${fixture.searchToken} must never unblock active Autonomous work` });
  await expect(activeApproval.getByText("This identity does not have administrative review permission.", { exact: true })).toBeVisible();
  await expect(activeApproval.getByLabel("Required administrative decision reason", { exact: true })).toHaveCount(0);
  const systemApproval = page.locator(".os-card").filter({ hasText: `${fixture.searchToken} system retention review` });
  const systemPolicyLink = systemApproval.getByRole("link", { name: "Open related context", exact: true });
  await expect(systemPolicyLink).toHaveAttribute("href", "/system/policies");
  await activate(systemPolicyLink, "keyboard");
  await expect.poll(() => new URL(page.url()).pathname).toBe("/system/policies");
  await expectHeading(page, "System");
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  const approvalReturnRead = apiResponse(page, "/api/v2/decision-inbox", (url) => (
    url.searchParams.get("kind") === "administrative_approval"
    && url.searchParams.get("query") === fixture.searchToken
  ));
  await page.goBack({ waitUntil: "domcontentloaded" });
  await pagePayload(await approvalReturnRead);
  await expectHeading(page, "Decisions");

  expect(fixtureSnapshot()).toEqual(before);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.decisionAliasRetry} verifies the compatibility alias, browser history, empty state, and a precise retry`, async ({ page, browserAudit }, testInfo) => {
  await page.goto("/approvals", { waitUntil: "domcontentloaded" });
  await expect.poll(() => new URL(page.url()).pathname).toBe("/decisions");
  await expectHeading(page, "Decisions");
  await browserAudit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expectHeading(page, "Decisions");

  const emptyResponse = apiResponse(page, "/api/v2/decision-inbox", (url) => url.searchParams.get("query") === fixture.absentToken);
  await browserAudit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    `/decisions?query=${fixture.absentToken}`,
    { waitUntil: "domcontentloaded" },
  ));
  expect((await pagePayload(await emptyResponse)).items).toEqual([]);
  await expect(page.getByText("No canonical decision records match", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "First page", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Next page", exact: true })).toBeDisabled();
  await browserAudit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
  await expectHeading(page, "Decisions");
  await browserAudit.withExpectedHistoryTraversal(page, () => page.goForward({ waitUntil: "domcontentloaded" }));
  await expect(page.getByText("No canonical decision records match", { exact: true })).toBeVisible();

  browserAudit.expectHttpResponse(page, {
    id: "decisions.guided-filter.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: "/api/v2/decision-inbox",
    query: { query: fixture.searchToken, kind: "guided_decision", limit: "50" },
    status: 503,
    occurrences: 1,
    reason: "Exercise the exact Guided-decision retry state once.",
  });
  let failed = false;
  await page.route("**/api/v2/decision-inbox?*", async (route) => {
    if (failed) {
      await route.continue();
      return;
    }
    failed = true;
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "decision_fixture_temporarily_unavailable",
          message: "Decision fixture temporarily unavailable",
          humanMessage: "Canonical decision records could not be read from the isolated fixture store.",
          retryable: true,
          category: "dependency",
          remediation: "Retry the canonical read after the local store recovers.",
          traceId: "trace-decision-retry",
          timestamp: "2099-07-16T23:59:59.000Z",
        },
      }),
    });
  });
  await browserAudit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    decisionUrl({ kind: "guided_decision" }),
    { waitUntil: "domcontentloaded" },
  ));
  await expect(page.getByText("Canonical decision records could not be read from the isolated fixture store.", { exact: true })).toBeVisible();
  await expect(page.getByText("Retry the canonical read after the local store recovers.", { exact: true })).toBeVisible();
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const recovered = apiResponse(page, "/api/v2/decision-inbox", (url) => url.searchParams.get("kind") === "guided_decision");
  await activate(page.getByRole("button", { name: "Try again", exact: true }), "keyboard");
  expect((await pagePayload(await recovered)).items.map((item) => item.id)).toEqual(expect.arrayContaining([fixture.toolDecisionId, fixture.manualDecisionId]));
  await expect(page.getByRole("heading", { name: "Guided exact-step decisions", exact: true })).toBeVisible();
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.evidence} exercises evidence tabs, filters, cursor, provenance, history, reload, and bounded export`, async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const evidenceExportPath = `/api/v2/intelligence/evidence/runs/${fixture.intelligenceRunId}/export`;
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    verifiedDownloadPaths: [evidenceExportPath],
  });
  const initial = apiResponse(page, "/api/v2/intelligence/evidence", (url) => url.searchParams.get("missionId") === fixture.intelligenceMissionId);
  await page.goto(intelligenceUrl("evidence", { runId: fixture.intelligenceRunId }), { waitUntil: "domcontentloaded" });
  const first = await pagePayload(await initial);
  await expectHeading(page, "Evidence, findings, and artifacts");
  expect(first.items).toHaveLength(25);
  expect(first.nextCursor).toEqual(expect.any(String));
  expect(first.items.every((item) => item.recordClass === "evidence")).toBe(true);
  expect(first.items.map((item) => item.id)).not.toContain(fixture.operationalLogEvidenceId);
  const recordClass = page.getByRole("combobox", { name: "Record class", exact: true });
  const verification = page.getByRole("combobox", { name: "Verification", exact: true });
  expect(await optionLabels(recordClass)).toEqual([
    "Evidence only",
    "Imported operational logs",
    "Evidence and operational logs",
  ]);
  await expect(verification).toBeVisible({ timeout: 30_000 });
  expect(await optionLabels(verification)).toEqual(["All", ...EVIDENCE_STATES]);
  await expect(page.getByRole("link", { name: "Evidence", exact: true })).toHaveAttribute("href", "/intelligence/evidence");
  await expect(page.getByRole("link", { name: "Findings", exact: true })).toHaveAttribute("href", "/intelligence/findings");
  await expect(page.getByRole("link", { name: "Artifacts", exact: true })).toHaveAttribute("href", "/intelligence/artifacts");

  const operationalRows = await setSelectFilter(
    page,
    "/api/v2/intelligence/evidence",
    recordClass,
    "recordClass",
    "operational_log",
  );
  expect(operationalRows).toEqual([
    expect.objectContaining({
      id: fixture.operationalLogEvidenceId,
      evidenceType: "command_output",
      recordClass: "operational_log",
    }),
  ]);
  const operationalLink = page.getByRole("link", { name: fixture.operationalLogEvidenceSummary, exact: true });
  await expect(operationalLink).toHaveAttribute(
    "href",
    `/intelligence/evidence/${fixture.operationalLogEvidenceId}`,
  );
  const operationalDetailResponse = apiResponse(
    page,
    `/api/v2/intelligence/evidence/${fixture.operationalLogEvidenceId}`,
  );
  await activate(operationalLink, "keyboard");
  expect((await operationalDetailResponse).status()).toBe(200);
  await expect(page.getByRole("note")).toContainText("Historical operational log — not verified evidence.");
  await page.goBack({ waitUntil: "domcontentloaded" });
  const allRecords = await setSelectFilter(
    page,
    "/api/v2/intelligence/evidence",
    recordClass,
    "recordClass",
    "all",
  );
  expect(allRecords.map((item) => item.id)).toContain(fixture.operationalLogEvidenceId);
  expect(allRecords.some((item) => item.recordClass === "evidence")).toBe(true);
  await clearSelectFilter(page, "/api/v2/intelligence/evidence", recordClass, "recordClass");
  await expect(page.getByText("Raw command output is hidden by default because a technical log is not proof.", { exact: false })).toBeVisible();

  const search = page.getByLabel("Search", { exact: true });
  await search.fill(fixture.searchToken);
  const searchedResponse = apiResponse(page, "/api/v2/intelligence/evidence", (url) => url.searchParams.get("query") === fixture.searchToken);
  await activate(page.getByRole("button", { name: "Apply filters", exact: true }), "pointer");
  const searched = await pagePayload(await searchedResponse);
  expect(searched.items).toHaveLength(25);
  await search.fill("");
  await activate(page.getByRole("button", { name: "Apply filters", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.has("query")).toBe(false);

  for (const value of EVIDENCE_STATES) {
    const items = await setSelectFilter(page, "/api/v2/intelligence/evidence", verification, "verificationState", value);
    expect(items.length).toBeGreaterThan(0);
    expect(items.every((item) => item.verificationState === value)).toBe(true);
  }
  await clearSelectFilter(page, "/api/v2/intelligence/evidence", verification, "verificationState");

  const nextResponse = apiResponse(page, "/api/v2/intelligence/evidence", (url) => Boolean(url.searchParams.get("cursor")));
  await activate(page.getByRole("button", { name: "Next page", exact: true }), "pointer");
  expect((await pagePayload(await nextResponse)).items).toHaveLength(fixture.evidenceCount - 25);
  await activate(page.getByRole("button", { name: "First page", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.has("cursor")).toBe(false);
  await expect(page.getByRole("link", { name: fixture.primaryEvidenceSummary, exact: true })).toBeVisible();

  const primaryLink = page.getByRole("link", { name: fixture.primaryEvidenceSummary, exact: true });
  await expect(primaryLink).toHaveAttribute("href", `/intelligence/evidence/${fixture.primaryEvidenceId}`);
  const detailResponse = apiResponse(page, `/api/v2/intelligence/evidence/${fixture.primaryEvidenceId}`);
  await activate(primaryLink, "keyboard");
  expect((await detailResponse).status()).toBe(200);
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/intelligence/evidence/${fixture.primaryEvidenceId}`);
  await expect(page.getByRole("heading", { name: fixture.primaryEvidenceSummary, exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Chain of custody", exact: true })).toBeVisible();
  const evidenceDetail = page.locator(".os-detail-panel");
  const evidenceMission = evidenceDetail.getByRole("link", { name: fixture.intelligenceMissionTitle, exact: true });
  const evidenceRun = evidenceDetail.getByRole("link", { name: fixture.intelligenceRunId, exact: true });
  const evidenceArtifact = evidenceDetail.getByRole("link", { name: fixture.primaryArtifactType, exact: true });
  await expect(evidenceMission).toHaveAttribute("href", `/missions/${fixture.intelligenceMissionId}`);
  await expect(evidenceRun).toHaveAttribute("href", `/missions/${fixture.intelligenceMissionId}/runs/${fixture.intelligenceRunId}`);
  await expect(evidenceArtifact).toHaveAttribute("href", `/intelligence/artifacts/${fixture.primaryArtifactId}`);
  await activate(evidenceRun, "pointer");
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/missions/${fixture.intelligenceMissionId}/runs/${fixture.intelligenceRunId}`);
  await expectHeading(page, fixture.intelligenceMissionTitle);
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: fixture.primaryEvidenceSummary, exact: true })).toBeVisible();
  await activate(page.locator(".os-detail-panel").getByRole("link", { name: fixture.primaryArtifactType, exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/intelligence/artifacts/${fixture.primaryArtifactId}`);
  await expect(page.getByRole("heading", { name: fixture.primaryArtifactType, exact: true })).toBeVisible();
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: fixture.primaryEvidenceSummary, exact: true })).toBeVisible();
  const provenance = page.locator("details").filter({ hasText: "Provenance" });
  await activate(provenance.locator("summary"), "pointer");
  await expect(provenance).toContainText("isolated_fixture");
  const custodyDetails = page.locator("ol.os-timeline details");
  await expect(custodyDetails).toHaveCount(2);
  await activate(custodyDetails.nth(0).locator("summary"), "keyboard");
  await activate(custodyDetails.nth(1).locator("summary"), "pointer");
  await expect(custodyDetails.nth(1)).toContainText("immutable finding evidence gate");

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByRole("heading", { name: fixture.primaryEvidenceSummary, exact: true })).toBeVisible();
  await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
  await expect(page.getByRole("link", { name: fixture.primaryEvidenceSummary, exact: true })).toBeVisible();
  await audit.withExpectedHistoryTraversal(page, () => page.goForward({ waitUntil: "domcontentloaded" }));
  await expect(page.getByRole("heading", { name: fixture.primaryEvidenceSummary, exact: true })).toBeVisible();

  const unavailableEvidenceResponse = apiResponse(page, `/api/v2/intelligence/evidence/${fixture.missingRunEvidenceId}`);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    `/intelligence/evidence/${fixture.missingRunEvidenceId}`,
    { waitUntil: "domcontentloaded" },
  ));
  expect((await unavailableEvidenceResponse).status()).toBe(200);
  await expect(page.getByRole("heading", { name: fixture.missingRunEvidenceSummary, exact: true })).toBeVisible();
  const unavailableEvidence = page.locator(".os-detail-panel");
  await expect(unavailableEvidence.getByRole("link", { name: fixture.relationlessMissionTitle, exact: true }))
    .toHaveAttribute("href", `/missions/${fixture.relationlessMissionId}`);
  await expect(unavailableEvidence.getByText("No run relation was retained.", { exact: true })).toBeVisible();
  await expect(unavailableEvidence.getByText(
    "Referenced artifact is unavailable or outside the current scope.",
    { exact: true },
  )).toBeVisible();
  await expect(unavailableEvidence.getByRole("link", { name: /artifact-no-longer-present/u })).toHaveCount(0);
  await expect(unavailableEvidence.getByRole("link", { name: fixture.intelligenceRunId, exact: true })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Export evidence metadata", exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Evidence export reconciliation", { exact: true })).toContainText(
    "No canonical run relation was retained for this evidence. Reconcile it to an authorized run in the same mission before exporting run-scoped metadata.",
  );
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByRole("heading", { name: fixture.missingRunEvidenceSummary, exact: true })).toBeVisible();

  const crossMissionListResponse = apiResponse(page, "/api/v2/intelligence/evidence", (url) => (
    url.searchParams.get("missionId") === fixture.relationlessMissionId
    && url.searchParams.get("runId") === fixture.intelligenceRunId
  ));
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(`/intelligence/evidence?${new URLSearchParams({
    missionId: fixture.relationlessMissionId,
    runId: fixture.intelligenceRunId,
  }).toString()}`, { waitUntil: "domcontentloaded" }));
  const crossMissionList = await pagePayload(await crossMissionListResponse);
  expect(crossMissionList.items).toEqual([
    expect.objectContaining({
      id: fixture.crossMissionRunEvidenceId,
      runId: fixture.intelligenceRunId,
      run: null,
    }),
  ]);
  await expect(page.getByRole("link", { name: fixture.crossMissionRunEvidenceSummary, exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Export evidence metadata", exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Evidence export reconciliation", { exact: true })).toContainText(
    "The retained run reference is unavailable or belongs to another mission. It is shown only for reconciliation and is never used to construct a run or export link.",
  );

  const crossMissionDetailResponse = apiResponse(page, `/api/v2/intelligence/evidence/${fixture.crossMissionRunEvidenceId}`);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    `/intelligence/evidence/${fixture.crossMissionRunEvidenceId}`,
    { waitUntil: "domcontentloaded" },
  ));
  const crossMissionDetail = await crossMissionDetailResponse;
  expect(crossMissionDetail.status()).toBe(200);
  expect(await crossMissionDetail.json()).toEqual(expect.objectContaining({
    id: fixture.crossMissionRunEvidenceId,
    runId: fixture.intelligenceRunId,
    run: null,
  }));
  await expect(page.getByRole("heading", { name: fixture.crossMissionRunEvidenceSummary, exact: true })).toBeVisible();
  const crossMissionEvidence = page.locator(".os-detail-panel");
  await expect(crossMissionEvidence.getByText(
    "Referenced run is unavailable or belongs to another mission.",
    { exact: true },
  )).toBeVisible();
  await expect(crossMissionEvidence.getByRole("link", { name: fixture.intelligenceRunId, exact: true })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Export evidence metadata", exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Evidence export reconciliation", { exact: true })).toContainText(
    "The retained run reference is unavailable or belongs to another mission.",
  );

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    intelligenceUrl("evidence", { runId: fixture.intelligenceRunId }),
    { waitUntil: "domcontentloaded" },
  ));
  const exportLink = page.getByRole("link", { name: "Export evidence metadata", exact: true });
  await expect(exportLink).toHaveAttribute("href", evidenceExportPath);
  await expect(exportLink).toHaveAttribute("download", "");
  const downloadPromise = page.waitForEvent("download");
  await activate(exportLink, "pointer");
  const download: Download = await downloadPromise;
  await audit.verifyDownload(download, evidenceExportPath);
  expect(await download.failure()).toBeNull();
  const boundedRunFilename = fixture.intelligenceRunId.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 96);
  expect(download.suggestedFilename()).toBe(`ti-scale-${boundedRunFilename}-evidence.json`);
  const downloadPath = await download.path();
  expect(downloadPath).not.toBeNull();
  const exported = JSON.parse(readFileSync(downloadPath!, "utf8")) as {
    readonly exportKind: string;
    readonly run: { readonly id: string };
    readonly evidence: readonly { readonly id: string }[];
  };
  expect(exported.exportKind).toBe("run_evidence_metadata");
  expect(exported.run.id).toBe(fixture.intelligenceRunId);
  expect(exported.evidence).toHaveLength(fixture.evidenceCount);
  expect(exported.evidence.map((item) => item.id)).toContain(fixture.primaryEvidenceId);
  expect(fixtureSnapshot().evidenceCount).toBe(fixture.evidenceCount);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.findings} exercises every finding filter and review-form control without submitting a mutation`, async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const before = fixtureSnapshot();
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const initial = apiResponse(page, "/api/v2/intelligence/findings", (url) => url.searchParams.get("missionId") === fixture.intelligenceMissionId);
  await page.goto(intelligenceUrl("findings"), { waitUntil: "domcontentloaded" });
  const first = await pagePayload(await initial);
  expect(first.items).toHaveLength(25);
  expect(first.nextCursor).toEqual(expect.any(String));
  const severity = page.getByRole("combobox", { name: "Severity", exact: true });
  const review = page.getByRole("combobox", { name: "Review", exact: true });
  await expect(severity).toBeVisible({ timeout: 30_000 });
  await expect(review).toBeVisible({ timeout: 30_000 });
  expect(await optionLabels(severity)).toEqual(["All", ...FINDING_SEVERITIES]);
  expect(await optionLabels(review)).toEqual(["All", ...FINDING_REVIEWS]);
  for (const value of FINDING_SEVERITIES) {
    const items = await setSelectFilter(page, "/api/v2/intelligence/findings", severity, "severity", value);
    expect(items.length).toBeGreaterThan(0);
    expect(items.every((item) => item.severity === value)).toBe(true);
  }
  await clearSelectFilter(page, "/api/v2/intelligence/findings", severity, "severity");
  for (const value of FINDING_REVIEWS) {
    const items = await setSelectFilter(page, "/api/v2/intelligence/findings", review, "reviewStatus", value);
    expect(items.length).toBeGreaterThan(0);
    expect(items.every((item) => item.reviewStatus === value)).toBe(true);
  }
  await clearSelectFilter(page, "/api/v2/intelligence/findings", review, "reviewStatus");

  const search = page.getByLabel("Search", { exact: true });
  await search.fill(fixture.searchToken);
  const searchResponse = apiResponse(page, "/api/v2/intelligence/findings", (url) => url.searchParams.get("query") === fixture.searchToken);
  await activate(page.getByRole("button", { name: "Apply filters", exact: true }), "keyboard");
  expect((await pagePayload(await searchResponse)).items).toHaveLength(25);
  await search.fill("");
  await activate(page.getByRole("button", { name: "Apply filters", exact: true }), "pointer");
  await expect.poll(() => new URL(page.url()).searchParams.has("query")).toBe(false);

  const nextResponse = apiResponse(page, "/api/v2/intelligence/findings", (url) => Boolean(url.searchParams.get("cursor")));
  await activate(page.getByRole("button", { name: "Next page", exact: true }), "keyboard");
  expect((await pagePayload(await nextResponse)).items).toHaveLength(fixture.findingCount - 25);
  await activate(page.getByRole("button", { name: "First page", exact: true }), "pointer");
  await expect.poll(() => new URL(page.url()).searchParams.has("cursor")).toBe(false);
  await expect(page.getByRole("link", { name: fixture.primaryFindingTitle, exact: true })).toBeVisible();

  const primaryLink = page.getByRole("link", { name: fixture.primaryFindingTitle, exact: true });
  await expect(primaryLink).toHaveAttribute("href", `/intelligence/findings/${fixture.primaryFindingId}`);
  const detailResponse = apiResponse(page, `/api/v2/intelligence/findings/${fixture.primaryFindingId}`);
  await activate(primaryLink, "pointer");
  expect((await detailResponse).status()).toBe(200);
  await expect(page.getByRole("heading", { name: fixture.primaryFindingTitle, exact: true })).toBeVisible();
  const findingDetail = page.locator(".os-detail-panel");
  const findingMission = findingDetail.getByRole("link", { name: fixture.intelligenceMissionTitle, exact: true });
  const findingRun = findingDetail.getByRole("link", { name: fixture.intelligenceRunId, exact: true });
  const findingEvidence = findingDetail.getByRole("link", { name: fixture.primaryEvidenceSummary, exact: true });
  await expect(findingMission).toHaveAttribute("href", `/missions/${fixture.intelligenceMissionId}`);
  await expect(findingRun).toHaveAttribute("href", `/missions/${fixture.intelligenceMissionId}/runs/${fixture.intelligenceRunId}`);
  await expect(findingEvidence).toHaveAttribute("href", `/intelligence/evidence/${fixture.primaryEvidenceId}`);
  await activate(findingEvidence, "keyboard");
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/intelligence/evidence/${fixture.primaryEvidenceId}`);
  await expect(page.getByRole("heading", { name: fixture.primaryEvidenceSummary, exact: true })).toBeVisible();
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: fixture.primaryFindingTitle, exact: true })).toBeVisible();
  const reviewStatus = page.getByRole("combobox", { name: "Status", exact: true });
  await expect(reviewStatus).toBeVisible();
  expect(await optionLabels(reviewStatus)).toEqual(["under_review", "verified", "rejected", "accepted_risk"]);
  for (const value of ["verified", "rejected", "accepted_risk", "under_review"]) {
    await reviewStatus.selectOption(value);
    await expect(reviewStatus).toHaveValue(value);
  }
  const reason = page.getByLabel("Reason", { exact: true });
  const override = page.getByRole("checkbox", { name: "Explicit evidence-gate override (audited)", exact: true });
  const record = page.getByRole("button", { name: "Record decision", exact: true });
  await expect(record).toBeDisabled();
  await reason.fill("Retain the current evidence-gated review state");
  await expect(record).toBeEnabled();
  await toggle(override, "pointer");
  await expect(override).toBeChecked();
  await toggle(override, "keyboard");
  await expect(override).not.toBeChecked();
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByRole("heading", { name: fixture.primaryFindingTitle, exact: true })).toBeVisible();

  const relationlessFindingResponse = apiResponse(page, `/api/v2/intelligence/findings/${fixture.relationlessFindingId}`);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    `/intelligence/findings/${fixture.relationlessFindingId}`,
    { waitUntil: "domcontentloaded" },
  ));
  expect((await relationlessFindingResponse).status()).toBe(200);
  await expect(page.getByRole("heading", { name: fixture.relationlessFindingTitle, exact: true })).toBeVisible();
  const relationlessFinding = page.locator(".os-detail-panel");
  await expect(relationlessFinding.getByText("No run relation was retained.", { exact: true })).toBeVisible();
  await expect(relationlessFinding.getByText(
    "No evidence links were returned. Verification remains evidence-gated.",
    { exact: true },
  )).toBeVisible();
  await expect(relationlessFinding.getByRole("link", { name: /evidence/u })).toHaveCount(0);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByRole("heading", { name: fixture.relationlessFindingTitle, exact: true })).toBeVisible();

  const artifactTab = page.getByRole("link", { name: "Artifacts", exact: true });
  const artifactListResponse = apiResponse(page, "/api/v2/intelligence/artifacts");
  await activate(artifactTab, "keyboard");
  expect((await artifactListResponse).status()).toBe(200);
  await expect.poll(() => new URL(page.url()).pathname).toBe("/intelligence/artifacts");
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: fixture.relationlessFindingTitle, exact: true })).toBeVisible();
  expect(fixtureSnapshot()).toEqual(before);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.artifacts} exercises artifact tabs, exact-type filter, cursor, metadata detail, history, and reload`, async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const initial = apiResponse(page, "/api/v2/intelligence/artifacts", (url) => url.searchParams.get("missionId") === fixture.intelligenceMissionId);
  await page.goto(intelligenceUrl("artifacts"), { waitUntil: "domcontentloaded" });
  const first = await pagePayload(await initial);
  expect(first.items).toHaveLength(25);
  expect(first.nextCursor).toEqual(expect.any(String));
  const artifactType = page.getByRole("textbox", { name: "Artifact type", exact: true });
  await expect(artifactType).toBeVisible({ timeout: 30_000 });
  await artifactType.fill(fixture.primaryArtifactType);
  const filteredResponse = apiResponse(page, "/api/v2/intelligence/artifacts", (url) => url.searchParams.get("artifactType") === fixture.primaryArtifactType);
  await activate(page.getByRole("button", { name: "Apply filters", exact: true }), "keyboard");
  const filtered = await pagePayload(await filteredResponse);
  expect(filtered.items).toEqual([expect.objectContaining({ id: fixture.primaryArtifactId, artifactType: fixture.primaryArtifactType })]);
  await artifactType.fill("");
  await activate(page.getByRole("button", { name: "Apply filters", exact: true }), "pointer");
  await expect.poll(() => new URL(page.url()).searchParams.has("artifactType")).toBe(false);

  const nextResponse = apiResponse(page, "/api/v2/intelligence/artifacts", (url) => Boolean(url.searchParams.get("cursor")));
  await activate(page.getByRole("button", { name: "Next page", exact: true }), "pointer");
  expect((await pagePayload(await nextResponse)).items).toHaveLength(fixture.artifactCount - 25);
  await activate(page.getByRole("button", { name: "First page", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.has("cursor")).toBe(false);
  await expect(page.getByRole("link", { name: fixture.primaryArtifactType, exact: true })).toBeVisible();

  const primaryLink = page.getByRole("link", { name: fixture.primaryArtifactType, exact: true });
  await expect(primaryLink).toHaveAttribute("href", `/intelligence/artifacts/${fixture.primaryArtifactId}`);
  const detailResponse = apiResponse(page, `/api/v2/intelligence/artifacts/${fixture.primaryArtifactId}`);
  await activate(primaryLink, "keyboard");
  expect((await detailResponse).status()).toBe(200);
  await expect(page.getByRole("heading", { name: fixture.primaryArtifactType, exact: true })).toBeVisible();
  const artifactDetail = page.locator(".os-detail-panel");
  const artifactMission = artifactDetail.getByRole("link", { name: fixture.intelligenceMissionTitle, exact: true });
  const artifactRun = artifactDetail.getByRole("link", { name: fixture.intelligenceRunId, exact: true });
  const artifactEvidence = artifactDetail.getByRole("link", { name: fixture.primaryEvidenceSummary, exact: true });
  await expect(artifactMission).toHaveAttribute("href", `/missions/${fixture.intelligenceMissionId}`);
  await expect(artifactRun).toHaveAttribute("href", `/missions/${fixture.intelligenceMissionId}/runs/${fixture.intelligenceRunId}`);
  await expect(artifactEvidence).toHaveAttribute("href", `/intelligence/evidence/${fixture.primaryEvidenceId}`);
  await activate(artifactEvidence, "pointer");
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/intelligence/evidence/${fixture.primaryEvidenceId}`);
  await expect(page.getByRole("heading", { name: fixture.primaryEvidenceSummary, exact: true })).toBeVisible();
  await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
  await expect(page.getByRole("heading", { name: fixture.primaryArtifactType, exact: true })).toBeVisible();
  const metadata = page.locator("details").filter({ hasText: "Artifact metadata" });
  await activate(metadata.locator("summary"), "pointer");
  await expect(metadata).toContainText("isolated_fixture");
  await expect(page.getByText("Metadata only", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Download verified content", exact: true })).toHaveCount(0);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByRole("heading", { name: fixture.primaryArtifactType, exact: true })).toBeVisible();

  const relationlessArtifactResponse = apiResponse(page, `/api/v2/intelligence/artifacts/${fixture.relationlessArtifactId}`);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    `/intelligence/artifacts/${fixture.relationlessArtifactId}`,
    { waitUntil: "domcontentloaded" },
  ));
  expect((await relationlessArtifactResponse).status()).toBe(200);
  await expect(page.getByRole("heading", { name: fixture.relationlessArtifactType, exact: true })).toBeVisible();
  const relationlessArtifact = page.locator(".os-detail-panel");
  await expect(relationlessArtifact.getByText("No run relation was retained.", { exact: true })).toBeVisible();
  await expect(relationlessArtifact.getByText("No evidence records reference this artifact.", { exact: true })).toBeVisible();
  await expect(relationlessArtifact.getByRole("link", { name: /evidence/u })).toHaveCount(0);
  await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
  await expect(page).toHaveURL(new RegExp(`/intelligence/artifacts/${fixture.primaryArtifactId}$`, "u"));
  await expect(page.getByRole("heading", { name: fixture.primaryArtifactType, exact: true })).toBeVisible();
  await audit.withExpectedHistoryTraversal(page, () => page.goForward({ waitUntil: "domcontentloaded" }));
  await expect(page).toHaveURL(new RegExp(`/intelligence/artifacts/${fixture.relationlessArtifactId}$`, "u"));
  await expect(page.getByRole("heading", { name: fixture.relationlessArtifactType, exact: true })).toBeVisible();
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page).toHaveURL(new RegExp(`/intelligence/artifacts/${fixture.relationlessArtifactId}$`, "u"));
  await expect(page.getByRole("heading", { name: fixture.relationlessArtifactType, exact: true })).toBeVisible();
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    `/intelligence/artifacts/${fixture.primaryArtifactId}`,
    { waitUntil: "domcontentloaded" },
  ));
  await expect(page).toHaveURL(new RegExp(`/intelligence/artifacts/${fixture.primaryArtifactId}$`, "u"));
  await expect(page.getByRole("heading", { name: fixture.primaryArtifactType, exact: true })).toBeVisible();
  const evidenceTab = page.getByRole("link", { name: "Evidence", exact: true });
  const evidenceListResponse = apiResponse(page, "/api/v2/intelligence/evidence");
  await activate(evidenceTab, "pointer");
  expect((await evidenceListResponse).status()).toBe(200);
  await expect.poll(() => new URL(page.url()).pathname).toBe("/intelligence/evidence");
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect.poll(() => new URL(page.url()).pathname).toBe(`/intelligence/artifacts/${fixture.primaryArtifactId}`);
  await expect(page.getByRole("heading", { name: fixture.primaryArtifactType, exact: true })).toBeVisible();
  expect(fixtureSnapshot().artifactCount).toBe(fixture.artifactCount);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.intelligenceRetry} proves precise empty and retry states for all three canonical list endpoints`, async ({ page, browserAudit }, testInfo) => {
  test.setTimeout(120_000);
  const surfaces: ReadonlyArray<{
    readonly view: "evidence" | "findings" | "artifacts";
    readonly api: string;
    readonly filter: Readonly<Record<string, string>>;
    readonly empty: string;
    readonly human: string;
  }> = [
    {
      view: "evidence" as const,
      api: "/api/v2/intelligence/evidence",
      filter: { query: fixture.absentToken },
      empty: "No evidence retained",
      human: "Canonical evidence records could not be read from the isolated fixture store.",
    },
    {
      view: "findings" as const,
      api: "/api/v2/intelligence/findings",
      filter: { query: fixture.absentToken },
      empty: "No findings recorded",
      human: "Canonical finding records could not be read from the isolated fixture store.",
    },
    {
      view: "artifacts" as const,
      api: "/api/v2/intelligence/artifacts",
      filter: { artifactType: fixture.absentToken },
      empty: "No artifacts produced",
      human: "Canonical artifact records could not be read from the isolated fixture store.",
    },
  ];

  for (const surface of surfaces) {
    browserAudit.expectHttpResponse(page, {
      id: `intelligence.${surface.view}.empty-filter.initial-unavailable`,
      transport: "browser",
      method: "GET",
      pathname: surface.api,
      query: { missionId: fixture.intelligenceMissionId, ...surface.filter, limit: "25" },
      status: 503,
      occurrences: 1,
      reason: `Exercise the exact ${surface.view} list retry state once.`,
    });
    let failed = false;
    const routePattern = `**${surface.api}?*`;
    await page.route(routePattern, async (route) => {
      if (failed) {
        await route.continue();
        return;
      }
      failed = true;
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({
          error: {
            code: `${surface.view}_fixture_temporarily_unavailable`,
            message: `${surface.view} fixture temporarily unavailable`,
            humanMessage: surface.human,
            retryable: true,
            category: "dependency",
            remediation: "Retry the canonical read after the local store recovers.",
            traceId: `trace-${surface.view}-retry`,
            timestamp: "2099-07-16T23:59:59.000Z",
          },
        }),
      });
    });
    await browserAudit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
      intelligenceUrl(surface.view, surface.filter),
      { waitUntil: "domcontentloaded" },
    ));
    await expect(page.getByText(surface.human, { exact: true })).toBeVisible();
    await expect(page.getByText("Retry the canonical read after the local store recovers.", { exact: true })).toBeVisible();
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const recovered = apiResponse(page, surface.api, (url) => Object.entries(surface.filter).every(([key, value]) => url.searchParams.get(key) === value));
    await activate(page.getByRole("button", { name: "Try again", exact: true }), surface.view === "findings" ? "keyboard" : "pointer");
    expect((await pagePayload(await recovered)).items).toEqual([]);
    await expect(page.getByText(surface.empty, { exact: true })).toBeVisible();
    await strictAudit(audit, testInfo);
    await page.unroute(routePattern);
  }
});

// Literal identifiers keep source-to-manifest assignment auditable.
void Object.values(TEST_IDS);

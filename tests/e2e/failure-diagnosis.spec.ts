import { expect, test, type Page, type Response, type Route } from "./support/playwright";
import { readFileSync } from "node:fs";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import {
  createFailureDiagnosisFixture,
  proveFailureResolutionAuditImmutable,
  readFailureDiagnosisFixtureSnapshot,
  type FailureDiagnosisFixture,
} from "./support/failureDiagnosisFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_EMPTY_AND_RETRY = "e2e.failure-diagnosis.empty-and-retry";
const TEST_MASTER_DETAIL = "e2e.failure-diagnosis.master-detail";
const TEST_DECLARED_RESOLUTION = "e2e.failure-diagnosis.declared-resolution";
const TEST_IMMUTABLE_RESOLUTION = "e2e.failure-diagnosis.immutable-resolution";
const FIXTURE_TIME = "2026-07-16T20:00:00.000Z";
const TIMEOUT_REASON = "The provider exceeded the bounded response deadline twice without returning a usable result.";
const VERIFIED_OUTCOME = "Provider readiness succeeded and the bounded retry returned an attributable result.";
const EXPECTED_RESOLUTION = `Declared recovery action: retry_bounded — Retry once. Operator-verified outcome: ${VERIFIED_OUTCOME}`;
const EXPECTED_RESOLUTION_REQUEST = {
  actionKind: "retry_bounded",
  verifiedOutcome: VERIFIED_OUTCOME,
  confirmed: true,
} as const;
const MANIFEST_IDS = [
  "failure-diagnosis.retry",
  "failure-diagnosis.check-again",
  "failure-diagnosis.refresh",
  "failure-diagnosis.select",
  "failure-diagnosis.record-disclosures",
  "failure-diagnosis.declared-actions",
  "failure-diagnosis.verified-outcome",
  "failure-diagnosis.confirm-resolution",
  "failure-diagnosis.record-resolution",
] as const;
const manifest = validateInteractionManifest(JSON.parse(
  readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8"),
) as unknown);

let emptyFixture: FailureDiagnosisFixture;
let recordsFixture: FailureDiagnosisFixture;
let resolutionFixture: FailureDiagnosisFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  emptyFixture = createFailureDiagnosisFixture(
    "empty",
    canonicalFixtureNamespace(testInfo, "failure-diagnosis-empty"),
  );
  recordsFixture = createFailureDiagnosisFixture(
    "records",
    canonicalFixtureNamespace(testInfo, "failure-diagnosis-records"),
  );
  resolutionFixture = createFailureDiagnosisFixture(
    "resolution",
    canonicalFixtureNamespace(testInfo, "failure-diagnosis-resolution"),
  );
});

function liveRoute(fixture: FailureDiagnosisFixture): string {
  return `/live/${encodeURIComponent(fixture.runId)}`;
}

function listPath(fixture: FailureDiagnosisFixture): string {
  return `/api/v2/operational-truth/missions/${fixture.missionId}/runs/${fixture.runId}/failure-diagnoses`;
}

function detailPath(fixture: FailureDiagnosisFixture, diagnosisId: string): string {
  return `${listPath(fixture)}/${diagnosisId}`;
}

function resolvePath(fixture: FailureDiagnosisFixture, diagnosisId: string): string {
  return `${detailPath(fixture, diagnosisId)}/resolve`;
}

function pathname(response: Response): string {
  return new URL(response.url()).pathname;
}

function errorEnvelope(code: string, humanMessage: string, remediation: string) {
  return {
    error: {
      code,
      message: code.replaceAll("_", " "),
      humanMessage,
      retryable: true,
      category: "dependency",
      remediation,
      traceId: `trace-${code}`,
      timestamp: FIXTURE_TIME,
    },
  };
}

async function assertManifestControl(page: Page, id: typeof MANIFEST_IDS[number]): Promise<void> {
  const entry = manifest.entries.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`Failure-diagnosis manifest entry ${id} is missing`);
  if (entry.accessible.locator === "native-summary") {
    const name = entry.accessible.match === "regex" ? new RegExp(entry.accessible.name) : entry.accessible.name;
    await expect(page.locator("summary").filter({ hasText: name }).first()).toBeVisible();
    return;
  }
  if (!entry.accessible.role) throw new Error(`Failure-diagnosis manifest entry ${id} is not role-addressable`);
  const name = entry.accessible.match === "regex" ? new RegExp(entry.accessible.name) : entry.accessible.name;
  await expect(page.getByRole(entry.accessible.role, {
    name,
    exact: entry.accessible.match === "exact",
  }).first()).toBeVisible();
}

async function fulfillExpectedError(
  route: Route,
  code: string,
  humanMessage: string,
  remediation: string,
): Promise<void> {
  await route.fulfill({
    status: 503,
    contentType: "application/json",
    body: JSON.stringify(errorEnvelope(code, humanMessage, remediation)),
  });
}

test(`${TEST_EMPTY_AND_RETRY} retries only the failed canonical list and truthfully rechecks an empty diagnosis state`, async ({ page, browserAudit }, testInfo) => {
  const canonicalPath = listPath(emptyFixture);
  browserAudit.expectHttpResponse(page, {
    id: "failure-diagnosis.list.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: canonicalPath,
    query: { states: "active,terminal,resolved,superseded", limit: "100" },
    status: 503,
    occurrences: 1,
    reason: "Exercise the exact run diagnosis-list retry state once.",
  });
  let firstRead = true;
  await page.route(`**${canonicalPath}?*`, async (route) => {
    if (firstRead) {
      firstRead = false;
      await fulfillExpectedError(
        route,
        "failure_diagnosis_fixture_unavailable",
        "Structured failure diagnoses could not be read from the canonical fixture store.",
        "Retry this diagnosis projection after the local store is available; do not infer a cause from the run badge.",
      );
      return;
    }
    await route.continue();
  });

  await page.goto(liveRoute(emptyFixture), { waitUntil: "domcontentloaded" });
  const alert = page.getByRole("alert").filter({ hasText: "Failure diagnosis is unavailable" });
  await expect(alert).toContainText("Structured failure diagnoses could not be read from the canonical fixture store.");
  await expect(alert).toContainText("Retry this diagnosis projection after the local store is available; do not infer a cause from the run badge.");
  await assertManifestControl(page, "failure-diagnosis.retry");

  const recovered = page.waitForResponse((response) =>
    pathname(response) === canonicalPath
      && response.request().method() === "GET"
      && response.status() === 200);
  const retry = alert.getByRole("button", { name: "Try again", exact: true });
  await retry.focus();
  await page.keyboard.press("Enter");
  const recoveredResponse = await recovered;
  const recoveredUrl = new URL(recoveredResponse.url());
  expect(recoveredUrl.searchParams.get("states")).toBe("active,terminal,resolved,superseded");
  expect(recoveredUrl.searchParams.get("limit")).toBe("100");

  await expect(page.getByText("No structured failure diagnosis", { exact: true })).toBeVisible();
  await expect(page.getByText(/Do not infer a cause from a generic status badge/u)).toBeVisible();
  await assertManifestControl(page, "failure-diagnosis.check-again");
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const checked = page.waitForResponse((response) =>
    pathname(response) === canonicalPath
      && response.request().method() === "GET"
      && response.status() === 200);
  await page.getByRole("button", { name: "Check again", exact: true }).click();
  expect((await checked).status()).toBe(200);
  await expect(page.getByText("No structured failure diagnosis", { exact: true })).toBeVisible();
  expect(readFailureDiagnosisFixtureSnapshot(emptyFixture)).toMatchObject({
    runStatus: "blocked",
    diagnoses: [],
    audits: [],
  });
  await audit.assertClean(testInfo);
});

test(`${TEST_MASTER_DETAIL} selects a canonical record by keyboard and retries only its failed detail`, async ({ page, browserAudit }, testInfo) => {
  const diagnosisId = recordsFixture.timeoutDiagnosisId;
  if (!diagnosisId) throw new Error("The records fixture has no timeout diagnosis");
  const canonicalDetailPath = detailPath(recordsFixture, diagnosisId);
  browserAudit.expectHttpResponse(page, {
    id: "failure-diagnosis.detail.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: canonicalDetailPath,
    query: {},
    status: 503,
    occurrences: 1,
    reason: "Exercise the exact selected-diagnosis retry state once.",
  });
  let firstTimeoutDetail = true;
  await page.route(`**${canonicalDetailPath}`, async (route) => {
    if (firstTimeoutDetail) {
      firstTimeoutDetail = false;
      await fulfillExpectedError(
        route,
        "failure_detail_fixture_unavailable",
        "The selected canonical failure detail could not be loaded.",
        "Retry only this selected detail; the validated diagnosis list remains authoritative.",
      );
      return;
    }
    await route.continue();
  });

  await page.goto(liveRoute(recordsFixture), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", {
    name: "The primary provider remained unavailable after its readiness circuit opened.",
    exact: true,
  })).toBeVisible();
  await assertManifestControl(page, "failure-diagnosis.select");
  const timeoutRecord = page.getByRole("button", { name: /^timeout · provider_deadline_exceeded/u });
  const failedDetail = page.waitForResponse((response) =>
    pathname(response) === canonicalDetailPath && response.status() === 503);
  await timeoutRecord.focus();
  await page.keyboard.press("Enter");
  await failedDetail;
  await expect(timeoutRecord).toHaveAttribute("aria-current", "true");
  const alert = page.getByRole("alert").filter({ hasText: "Failure detail is unavailable" });
  await expect(alert).toContainText("The selected canonical failure detail could not be loaded.");
  await expect(alert).toContainText("Retry only this selected detail; the validated diagnosis list remains authoritative.");
  await assertManifestControl(page, "failure-diagnosis.retry");

  const recovered = page.waitForResponse((response) =>
    pathname(response) === canonicalDetailPath
      && response.request().method() === "GET"
      && response.status() === 200);
  await alert.getByRole("button", { name: "Try again", exact: true }).click();
  expect((await recovered).status()).toBe(200);
  await expect(page.getByRole("heading", { name: TIMEOUT_REASON, exact: true })).toBeVisible();
  await expect(page.getByText(recordsFixture.lastSuccessEventId!, { exact: true }).first()).toBeVisible();
  await expect(page.getByText(recordsFixture.rawErrorLogId!, { exact: true }).first()).toBeVisible();
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const recoveryDetails = page.locator("details").filter({
    has: page.locator("summary").filter({ hasText: "Automatic recovery record" }),
  });
  await recoveryDetails.locator("summary").click();
  await expect(recoveryDetails).toHaveJSProperty("open", true);
  await expect(recoveryDetails).toContainText(/bounded_backoff/u);
  await audit.assertClean(testInfo);
});

test(`${TEST_DECLARED_RESOLUTION} refreshes complete records, exposes exact troubleshooting data, and gates all undeclared or incomplete resolutions`, async ({ page }, testInfo) => {
  const diagnosisId = recordsFixture.timeoutDiagnosisId;
  if (!diagnosisId) throw new Error("The records fixture has no timeout diagnosis");
  const canonicalListPath = listPath(recordsFixture);
  const canonicalDetailPath = detailPath(recordsFixture, diagnosisId);
  const canonicalResolvePath = resolvePath(recordsFixture, diagnosisId);
  let resolutionRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === canonicalResolvePath && request.method() === "POST") resolutionRequests += 1;
  });
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });

  await page.goto(liveRoute(recordsFixture), { waitUntil: "domcontentloaded" });
  const selectedDetail = page.locator('section[aria-label="Selected failure diagnosis"]');
  const timeoutRecord = page.getByRole("button", { name: /^timeout · provider_deadline_exceeded/u });
  const selected = page.waitForResponse((response) => pathname(response) === canonicalDetailPath && response.status() === 200);
  await timeoutRecord.click();
  await selected;
  await expect(page.getByRole("heading", { name: TIMEOUT_REASON, exact: true })).toBeVisible();

  await assertManifestControl(page, "failure-diagnosis.refresh");
  const listRefresh = page.waitForResponse((response) =>
    pathname(response) === canonicalListPath
      && response.request().method() === "GET"
      && response.status() === 200);
  const detailRefresh = page.waitForResponse((response) =>
    pathname(response) === canonicalDetailPath
      && response.request().method() === "GET"
      && response.status() === 200);
  const refresh = page.getByRole("button", { name: "Refresh diagnoses", exact: true });
  await refresh.focus();
  await page.keyboard.press("Space");
  await expect(page.getByRole("heading", { name: TIMEOUT_REASON, exact: true })).toBeVisible();
  expect((await listRefresh).status()).toBe(200);
  expect((await detailRefresh).status()).toBe(200);

  await assertManifestControl(page, "failure-diagnosis.record-disclosures");
  const automaticRecovery = selectedDetail.locator("summary").filter({ hasText: "Automatic recovery record" });
  await automaticRecovery.focus();
  await page.keyboard.press("Enter");
  await expect(automaticRecovery.locator("..")).toHaveAttribute("open", "");
  await expect(selectedDetail.getByText(/bounded_backoff/u)).toBeVisible();
  const retryHistory = selectedDetail.locator("summary").filter({ hasText: "Retry history" });
  await retryHistory.click();
  await expect(retryHistory.locator("..")).toHaveAttribute("open", "");
  await expect(selectedDetail.getByText(/"attempt": 2/u)).toBeVisible();
  const preservedProgress = selectedDetail.locator("summary").filter({ hasText: "Progress preserved before failure" });
  await preservedProgress.focus();
  await page.keyboard.press("Space");
  await expect(preservedProgress.locator("..")).toHaveAttribute("open", "");
  await expect(selectedDetail.getByText(/"checkpointPreserved": true/u)).toBeVisible();

  await assertManifestControl(page, "failure-diagnosis.declared-actions");
  const declaredActions = selectedDetail.getByRole("radio");
  await expect(declaredActions).toHaveCount(2);
  const connectionCheck = selectedDetail.getByRole("radio", { name: /^Test provider connection/u });
  const boundedRetry = selectedDetail.getByRole("radio", { name: /^Retry once/u });
  await expect(connectionCheck).toHaveValue("test_connection");
  await expect(boundedRetry).toHaveValue("retry_bounded");
  await expect(selectedDetail.getByRole("radio", { name: /fallback|resume|terminate/iu })).toHaveCount(0);
  await connectionCheck.click();
  await expect(connectionCheck).toBeChecked();
  await connectionCheck.focus();
  await page.keyboard.press("ArrowDown");
  await expect(boundedRetry).toBeChecked();
  await expect(connectionCheck).not.toBeChecked();

  await assertManifestControl(page, "failure-diagnosis.verified-outcome");
  await assertManifestControl(page, "failure-diagnosis.confirm-resolution");
  await assertManifestControl(page, "failure-diagnosis.record-resolution");
  const outcome = selectedDetail.getByRole("textbox", { name: "Verified resolution outcome", exact: true });
  const confirmation = selectedDetail.getByRole("checkbox", {
    name: /^I confirm the selected declared action was completed and its outcome was verified\./u,
  });
  const record = selectedDetail.getByRole("button", { name: "Record audited resolution", exact: true });
  await expect(record).toBeDisabled();
  await outcome.click();
  await page.keyboard.type("Too short");
  await expect(record).toBeDisabled();
  await outcome.fill(VERIFIED_OUTCOME);
  await expect(record).toBeDisabled();
  await confirmation.focus();
  await page.keyboard.press("Space");
  await expect(confirmation).toBeChecked();
  await expect(record).toBeEnabled();
  await confirmation.click();
  await expect(confirmation).not.toBeChecked();
  await expect(record).toBeDisabled();
  expect(resolutionRequests).toBe(0);

  const snapshot = readFailureDiagnosisFixtureSnapshot(recordsFixture);
  expect(snapshot.diagnoses).toHaveLength(2);
  expect(snapshot.diagnoses.every((diagnosis) => diagnosis.state === "active")).toBe(true);
  expect(snapshot.audits.map((auditRecord) => auditRecord.action)).toEqual([
    "failure_diagnosis.created",
    "failure_diagnosis.created",
  ]);
  await audit.assertClean(testInfo);
});

test(`${TEST_IMMUTABLE_RESOLUTION} records one exact declared-action resolution and proves refresh-persistent immutable audit state`, async ({ page, browserAudit }, testInfo) => {
  const diagnosisId = resolutionFixture.timeoutDiagnosisId;
  if (!diagnosisId) throw new Error("The resolution fixture has no timeout diagnosis");
  const canonicalResolvePath = resolvePath(resolutionFixture, diagnosisId);
  browserAudit.expectHttpResponse(page, {
    id: "failure-diagnosis.resolution.version-conflict",
    transport: "browser",
    method: "POST",
    pathname: canonicalResolvePath,
    query: {},
    status: 409,
    occurrences: 1,
    reason: "Prove a stale diagnosis resolution fails before immutable commit.",
  });
  const submitted: Array<{ readonly body: unknown; readonly idempotencyKey: string | undefined }> = [];
  let rejectFirstResolution = true;
  await page.route(`**${canonicalResolvePath}`, async (route) => {
    submitted.push({
      body: route.request().postDataJSON(),
      idempotencyKey: route.request().headers()["idempotency-key"],
    });
    if (rejectFirstResolution) {
      rejectFirstResolution = false;
      await route.fulfill({
        status: 409,
        contentType: "application/json",
        body: JSON.stringify(errorEnvelope(
          "failure_resolution_version_conflict",
          "The operator resolution could not be committed because the canonical record changed.",
          "Refresh the diagnosis, verify the declared action and outcome again, then resubmit once.",
        )),
      });
      return;
    }
    await route.continue();
  });

  await page.goto(liveRoute(resolutionFixture), { waitUntil: "domcontentloaded" });
  const selectedDetail = page.locator('section[aria-label="Selected failure diagnosis"]');
  await expect(page.getByRole("heading", { name: TIMEOUT_REASON, exact: true })).toBeVisible();
  const boundedRetry = selectedDetail.getByRole("radio", { name: /^Retry once/u });
  const outcome = selectedDetail.getByRole("textbox", { name: "Verified resolution outcome", exact: true });
  const confirmation = selectedDetail.getByRole("checkbox", {
    name: /^I confirm the selected declared action was completed and its outcome was verified\./u,
  });
  const record = selectedDetail.getByRole("button", { name: "Record audited resolution", exact: true });
  await boundedRetry.click();
  await outcome.fill(VERIFIED_OUTCOME);
  await confirmation.check();
  await record.focus();
  await page.keyboard.press("Enter");

  const mutationAlert = page.getByRole("alert").filter({ hasText: "Diagnosis resolution was not accepted" });
  await expect(mutationAlert).toContainText("The operator resolution could not be committed because the canonical record changed.");
  await expect(mutationAlert).toContainText("Refresh the diagnosis, verify the declared action and outcome again, then resubmit once.");
  expect(submitted).toHaveLength(1);
  expect(submitted[0]?.body).toEqual(EXPECTED_RESOLUTION_REQUEST);
  expect(submitted[0]?.idempotencyKey).toMatch(/^failure-resolution-[0-9a-f-]{36}$/u);
  const rejectedSnapshot = readFailureDiagnosisFixtureSnapshot(resolutionFixture);
  expect(rejectedSnapshot.diagnoses).toEqual([
    expect.objectContaining({ id: diagnosisId, state: "active", resolvedAt: null }),
  ]);
  expect(rejectedSnapshot.audits.map((auditRecord) => auditRecord.action)).toEqual(["failure_diagnosis.created"]);

  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const accepted = page.waitForResponse((response) =>
    pathname(response) === canonicalResolvePath
      && response.request().method() === "POST"
      && response.status() === 200);
  await record.click();
  const acceptedResponse = await accepted;
  expect(await acceptedResponse.json()).toMatchObject({
    schemaVersion: "2.4",
    diagnosis: { id: diagnosisId, state: "resolved" },
  });
  expect(submitted).toHaveLength(2);
  expect(submitted[1]?.body).toEqual(EXPECTED_RESOLUTION_REQUEST);
  expect(submitted[1]?.idempotencyKey).toMatch(/^failure-resolution-[0-9a-f-]{36}$/u);
  expect(submitted[1]?.idempotencyKey).not.toBe(submitted[0]?.idempotencyKey);

  await expect(selectedDetail.getByText("This diagnosis is resolved. Its original declared actions remain visible for audit, but it cannot be resolved again.", { exact: true })).toBeVisible();
  await expect(selectedDetail.getByRole("radio")).toHaveCount(2);
  await expect(selectedDetail.getByRole("radio").first()).toBeDisabled();
  await expect(selectedDetail.getByRole("radio").last()).toBeDisabled();
  await expect(selectedDetail.getByRole("textbox", { name: "Verified resolution outcome", exact: true })).toHaveCount(0);
  await expect(selectedDetail.getByRole("button", { name: "Record audited resolution", exact: true })).toHaveCount(0);

  const resolvedSnapshot = readFailureDiagnosisFixtureSnapshot(resolutionFixture);
  expect(resolvedSnapshot.diagnoses).toEqual([
    {
      id: diagnosisId,
      state: "resolved",
      resolvedAt: expect.any(String),
      operatorActions: [
        {
          kind: "test_connection",
          label: "Test provider connection",
          consequence: "Runs a non-executing readiness probe without resuming the failed action.",
          requiresConfirmation: false,
        },
        {
          kind: "retry_bounded",
          label: "Retry once",
          consequence: "Uses one bounded retry only after the provider readiness probe succeeds.",
          requiresConfirmation: true,
        },
      ],
    },
  ]);
  expect(resolvedSnapshot.audits).toHaveLength(2);
  expect(resolvedSnapshot.audits[1]).toMatchObject({
    action: "failure_diagnosis.resolved",
    actorId: "e2e-local-operator",
    reason: EXPECTED_RESOLUTION,
    details: {
      from: "active",
      to: "resolved",
      category: "timeout",
      code: "provider_deadline_exceeded",
      actionKind: "retry_bounded",
      actionLabel: "Retry once",
      actionRequiresConfirmation: true,
      verifiedOutcome: VERIFIED_OUTCOME,
      confirmed: true,
    },
  });
  expect(resolvedSnapshot.audits[1]?.previousHash).toMatch(/^[0-9a-f]{64}$/u);
  expect(resolvedSnapshot.audits[1]?.recordHash).toMatch(/^[0-9a-f]{64}$/u);
  const immutable = proveFailureResolutionAuditImmutable(resolutionFixture);
  expect(immutable).toMatchObject({
    updateRejected: true,
    deleteRejected: true,
    retainedReason: EXPECTED_RESOLUTION,
    retainedRecordHash: resolvedSnapshot.audits[1]?.recordHash,
  });
  expect(immutable.updateError).toContain("audit records are immutable");
  expect(immutable.deleteError).toContain("audit records are immutable");

  const persistedDetail = page.waitForResponse((response) =>
    pathname(response) === detailPath(resolutionFixture, diagnosisId)
      && response.request().method() === "GET"
      && response.status() === 200);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await persistedDetail;
  await expect(page.getByRole("heading", { name: TIMEOUT_REASON, exact: true })).toBeVisible();
  await expect(page.getByText("This diagnosis is resolved. Its original declared actions remain visible for audit, but it cannot be resolved again.", { exact: true })).toBeVisible();
  await expect(page.getByRole("radio", { name: /^Test provider connection/u })).toBeDisabled();
  await expect(page.getByRole("radio", { name: /^Retry once/u })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Record audited resolution", exact: true })).toHaveCount(0);
  expect(readFailureDiagnosisFixtureSnapshot(resolutionFixture).audits).toHaveLength(2);
  await audit.assertClean(testInfo);
});

// Literal identifiers keep future manifest reassignment and static coverage auditable.
void [
  TEST_EMPTY_AND_RETRY,
  TEST_MASTER_DETAIL,
  TEST_DECLARED_RESOLUTION,
  TEST_IMMUTABLE_RESOLUTION,
  ...MANIFEST_IDS,
];

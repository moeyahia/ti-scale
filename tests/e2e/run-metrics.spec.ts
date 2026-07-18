import { readFileSync } from "node:fs";
import {
  expect,
  test,
  type Locator,
  type Page,
  type Response,
  type Route,
  type TestInfo,
} from "./support/playwright";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createRunMetricsFixture,
  readRunMetricsFixtureState,
  type RunMetricsFixture,
} from "./support/runMetricsFixture";

const TEST_ID = "e2e.run-intelligence.metrics.controls";
const RETRY_POINTER_TEST_ID = "e2e.run-intelligence.metrics.retry.pointer";
const RETRY_KEYBOARD_TEST_ID = "e2e.run-intelligence.metrics.retry.keyboard";
const MANIFEST_ENTRIES = [
  "run-intelligence.metrics.refresh",
  "run-intelligence.metrics.retry",
  "run-intelligence.metrics.drill-down-disclosures",
  "run-intelligence.metrics.filtered-record-links",
  "run-intelligence.metrics.attempt-evidence-disclosures",
  "run-intelligence.metrics.evidence-links",
] as const;
const METRIC_CATEGORIES = [
  ["objective", "Objective and plan"],
  ["orchestration", "Agent orchestration"],
  ["attempts", "Attack attempts"],
  ["discovery", "Discovery and topology"],
  ["evidence", "Evidence quality"],
  ["reliability", "Reliability"],
  ["resources", "Resources"],
  ["learning", "Brain and learning"],
] as const;
const FIXTURE_TIME = "2026-07-16T20:00:00.000Z";
const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

let fixture: RunMetricsFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createRunMetricsFixture(canonicalFixtureNamespace(testInfo, "run-metrics"));
});

function missionRoute(): string {
  return `/missions/${encodeURIComponent(fixture.missionId)}/runs/${encodeURIComponent(fixture.runId)}`;
}

function pathname(response: Response): string {
  return new URL(response.url()).pathname;
}

function metricSnapshotsPath(): string {
  return `/api/v2/runs/${fixture.runId}/intelligence/metrics/snapshots`;
}

function attackAttemptsPath(): string {
  return `/api/v2/runs/${fixture.runId}/intelligence/attack-attempts`;
}

function metricSnapshotsResponse(page: Page): Promise<Response> {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET"
      && url.pathname === metricSnapshotsPath()
      && url.searchParams.get("limit") === "20";
  });
}

function attackAttemptsResponse(page: Page): Promise<Response> {
  return page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === attackAttemptsPath());
}

async function assertMetricsResponse(response: Response): Promise<void> {
  expect(response.status()).toBe(200);
  const payload = await response.json() as {
    readonly latestSnapshotId?: string | null;
    readonly items?: readonly { readonly id?: string }[];
  };
  expect(payload.latestSnapshotId).toBe(fixture.snapshotId);
  expect(payload.items?.some((item) => item.id === fixture.snapshotId)).toBe(true);
}

async function assertAttemptsResponse(response: Response): Promise<void> {
  expect(response.status()).toBe(200);
  const payload = await response.json() as {
    readonly items?: readonly {
      readonly id?: string;
      readonly evidence?: readonly { readonly evidenceId?: string }[];
    }[];
  };
  const attempt = payload.items?.find((item) => item.id === fixture.attackAttemptId);
  expect(attempt).toBeDefined();
  expect(attempt?.evidence?.some((item) => item.evidenceId === fixture.evidenceId)).toBe(true);
}

async function assertManifestControl(page: Page, id: (typeof MANIFEST_ENTRIES)[number]): Promise<Locator> {
  const entry = manifest.entries.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`Run-metrics interaction-manifest entry ${id} is missing`);
  const name = entry.accessible.match === "regex"
    ? new RegExp(entry.accessible.name)
    : entry.accessible.name;
  if (entry.accessible.locator === "native-summary") {
    const control = page.locator("summary").filter({ hasText: name }).first();
    await expect(control).toBeVisible();
    return control;
  }
  if (!entry.accessible.role) throw new Error(`Run-metrics interaction-manifest entry ${id} is not role-addressable`);
  const control = page.getByRole(entry.accessible.role, {
    name,
    exact: entry.accessible.match === "exact",
  }).first();
  await expect(control).toBeVisible();
  return control;
}

async function assertStrictlyClean(audit: BrowserAudit, testInfo: TestInfo): Promise<void> {
  expect(audit.unexpected, "Unexpected browser failures").toEqual([]);
  expect(audit.degradedApi, "Required V2 API requests must not degrade").toEqual([]);
  expect(audit.optionalMedia, "Optional operational media must not fail").toEqual([]);
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

async function ensureOpen(details: Locator, input: "keyboard" | "pointer" = "pointer"): Promise<void> {
  if (await details.evaluate((node) => (node as HTMLDetailsElement).open)) return;
  await activate(details.locator("summary"), input);
  await expect(details).toHaveJSProperty("open", true);
}

async function refreshCanonicalRecords(page: Page, input: "keyboard" | "pointer"): Promise<void> {
  const metrics = metricSnapshotsResponse(page);
  const attempts = attackAttemptsResponse(page);
  await activate(page.getByRole("button", { name: "Refresh records", exact: true }), input);
  await expect(page.getByText(fixture.snapshotId, { exact: true }), "Refresh must retain the last validated snapshot").toBeVisible();
  await Promise.all([
    assertMetricsResponse(await metrics),
    assertAttemptsResponse(await attempts),
  ]);
  await expect(page.getByText(fixture.snapshotId, { exact: true })).toBeVisible();
}

async function openFilteredEvidence(
  page: Page,
  input: "keyboard" | "pointer",
  expectCanonicalRead = true,
): Promise<void> {
  const surface = page.getByLabel("Reproducible run metrics", { exact: true });
  const metricRow = surface
    .locator('section[aria-labelledby="run-metrics-evidence"] tbody tr')
    .filter({ hasText: "Verified evidence" })
    .first();
  const details = metricRow.locator("details");
  await ensureOpen(details, input);
  const link = details.getByRole("link", { name: "Open filtered canonical records", exact: true });
  const expectedHref = `/intelligence/evidence?runId=${encodeURIComponent(fixture.runId)}`;
  await expect(link).toHaveAttribute("href", expectedHref);
  await assertManifestControl(page, "run-intelligence.metrics.filtered-record-links");

  const listResponse = expectCanonicalRead ? page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET"
      && url.pathname === "/api/v2/intelligence/evidence"
      && url.searchParams.get("runId") === fixture.runId;
  }) : undefined;
  await activate(link, input);
  if (listResponse) {
    const response = await listResponse;
    expect(response.status()).toBe(200);
    const payload = await response.json() as {
      readonly items?: readonly { readonly id?: string; readonly summary?: string }[];
    };
    expect(payload.items?.some((item) => item.id === fixture.evidenceId && item.summary === fixture.evidenceSummary)).toBe(true);
  }
  await expect(page).toHaveURL((url) => url.pathname === "/intelligence/evidence"
    && url.searchParams.get("runId") === fixture.runId);
  await expect(page.getByRole("heading", { name: "Evidence, findings, and artifacts", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: fixture.evidenceSummary, exact: true })).toBeVisible();
  await expect(page.getByText("Command surface not found", { exact: true })).toHaveCount(0);
}

async function openAttemptEvidenceDetail(
  page: Page,
  input: "keyboard" | "pointer",
  expectCanonicalRead = true,
): Promise<void> {
  const surface = page.getByLabel("Reproducible run metrics", { exact: true });
  const attemptRow = surface.locator("tbody tr").filter({ hasText: fixture.techniqueName }).first();
  const details = attemptRow.locator("details");
  await ensureOpen(details, input);
  await expect(details).toContainText("outcome");
  await expect(details).toContainText("verified");
  await expect(details).toContainText("99%");
  await assertManifestControl(page, "run-intelligence.metrics.attempt-evidence-disclosures");
  const link = details.getByRole("link", { name: fixture.evidenceId, exact: true });
  await expect(link).toHaveAttribute("href", `/intelligence/evidence/${encodeURIComponent(fixture.evidenceId)}`);
  await assertManifestControl(page, "run-intelligence.metrics.evidence-links");

  const detailResponse = expectCanonicalRead ? page.waitForResponse((response) => response.request().method() === "GET"
    && pathname(response) === `/api/v2/intelligence/evidence/${fixture.evidenceId}`) : undefined;
  await activate(link, input);
  if (detailResponse) expect((await detailResponse).status()).toBe(200);
  await expect(page).toHaveURL(`/intelligence/evidence/${fixture.evidenceId}`);
  await expect(page.getByRole("heading", { name: fixture.evidenceSummary, exact: true })).toBeVisible();
  await expect(page.getByText(fixture.evidenceHash, { exact: true })).toBeVisible();
  await expect(page.getByText("Command surface not found", { exact: true })).toHaveCount(0);
}

test(`${TEST_ID} traverses immutable metrics, canonical drill-downs, attempt evidence, and valid record routes`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const initialState = readRunMetricsFixtureState(fixture);
  expect(initialState).toEqual({
    snapshotCount: 1,
    snapshotId: fixture.snapshotId,
    recomputationHash: fixture.recomputationHash,
    attackAttemptCount: 1,
    attemptEvidenceCount: 1,
    evidenceCount: 1,
    evidenceHash: fixture.evidenceHash,
  });
  await testInfo.attach("canonical-run-metrics-fixture.json", {
    body: Buffer.from(JSON.stringify({ manifestEntries: MANIFEST_ENTRIES, ...fixture, state: initialState }, null, 2)),
    contentType: "application/json",
  });

  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const initialMetrics = metricSnapshotsResponse(page);
  const initialAttempts = attackAttemptsResponse(page);
  await page.goto(missionRoute(), { waitUntil: "domcontentloaded" });
  await Promise.all([
    assertMetricsResponse(await initialMetrics),
    assertAttemptsResponse(await initialAttempts),
  ]);
  await expect(page).toHaveURL(missionRoute());
  await expect(page.getByRole("heading", { name: "Recomputed run intelligence", exact: true })).toBeVisible();
  await expect(page.getByText(fixture.snapshotId, { exact: true })).toBeVisible();
  await expect(page.getByText(fixture.recomputationHash, { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Classified attack attempts", exact: true })).toBeVisible();
  await expect(page.getByLabel("Reproducible run metrics", { exact: true })
    .locator('th[scope="row"]')
    .filter({ hasText: fixture.techniqueName })).toBeVisible();
  await assertManifestControl(page, "run-intelligence.metrics.refresh");
  await assertManifestControl(page, "run-intelligence.metrics.drill-down-disclosures");

  await refreshCanonicalRecords(page, "keyboard");
  await refreshCanonicalRecords(page, "pointer");
  expect(readRunMetricsFixtureState(fixture), "Read-only refreshes must not alter canonical state").toEqual(initialState);

  const surface = page.getByLabel("Reproducible run metrics", { exact: true });
  for (const [category, label] of METRIC_CATEGORIES) {
    const section = surface.locator(`section[aria-labelledby="run-metrics-${category}"]`);
    await expect(section.getByRole("heading", { name: label, exact: true })).toBeVisible();
    const details = section.locator("details").first();
    const summary = details.locator("summary");
    await activate(summary, "keyboard");
    await expect(details).toHaveJSProperty("open", true);
    await expect(surface.locator('section[aria-labelledby^="run-metrics-"] details[open]')).toHaveCount(1);
    await expect(details).toContainText(`run_id eq ${fixture.runId}`);
    await expect(details).toContainText(fixture.missionId);
    await expect(details).toContainText(fixture.runId);
    await activate(summary, "pointer");
    await expect(details).toHaveJSProperty("open", false);
  }

  await openFilteredEvidence(page, "pointer");
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(missionRoute());
  await expect(page.getByText(fixture.snapshotId, { exact: true })).toBeVisible();
  await openFilteredEvidence(page, "keyboard", false);
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(missionRoute());

  const attemptDetails = page.getByLabel("Reproducible run metrics", { exact: true })
    .locator("tbody tr")
    .filter({ hasText: fixture.techniqueName })
    .first()
    .locator("details");
  await ensureOpen(attemptDetails, "keyboard");
  await activate(attemptDetails.locator("summary"), "pointer");
  await expect(attemptDetails).toHaveJSProperty("open", false);
  await openAttemptEvidenceDetail(page, "pointer");
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(missionRoute());
  await openAttemptEvidenceDetail(page, "keyboard", false);
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(missionRoute());

  const reloadMetrics = metricSnapshotsResponse(page);
  const reloadAttempts = attackAttemptsResponse(page);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await Promise.all([
    assertMetricsResponse(await reloadMetrics),
    assertAttemptsResponse(await reloadAttempts),
  ]);
  await expect(page.getByText(fixture.snapshotId, { exact: true })).toBeVisible();
  await expect(page.getByLabel("Reproducible run metrics", { exact: true })
    .locator('th[scope="row"]')
    .filter({ hasText: fixture.techniqueName })).toBeVisible();
  expect(readRunMetricsFixtureState(fixture), "Navigation and browser refresh must preserve immutable records").toEqual(initialState);
  await assertStrictlyClean(audit, testInfo);
});

async function exerciseInitialMetricsRetry(
  page: Page,
  testInfo: TestInfo,
  input: "keyboard" | "pointer",
): Promise<void> {
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: [{
      id: `run-metrics.${input}.initial-unavailable`,
      transport: "browser",
      method: "GET",
      pathname: metricSnapshotsPath(),
      query: { limit: "20" },
      status: 503,
      occurrences: 1,
      reason: `Exercise the exact ${input} run-metrics retry state once.`,
    }],
  });
  const expectedError = {
    error: {
      code: "run_metrics_projection_unavailable",
      message: "The canonical run-metrics projection is temporarily unavailable",
      humanMessage: "Reproducible run metrics could not be read from the isolated local projection.",
      retryable: true,
      category: "dependency",
      remediation: "Retry the canonical read after the local metrics projection recovers.",
      traceId: `trace-run-metrics-retry-${input}-${fixture.runId}`,
      timestamp: FIXTURE_TIME,
    },
  };
  const metricsMatcher = (url: URL): boolean => url.pathname === metricSnapshotsPath()
    && url.searchParams.get("limit") === "20";
  let failedOnce = false;
  const failInitialMetrics = async (intercepted: Route): Promise<void> => {
    const url = new URL(intercepted.request().url());
    if (!failedOnce && intercepted.request().method() === "GET" && metricsMatcher(url)) {
      failedOnce = true;
      await intercepted.fulfill({
        status: 503,
        contentType: "application/json; charset=utf-8",
        headers: { "X-Request-Id": expectedError.error.traceId },
        body: JSON.stringify(expectedError),
      });
      return;
    }
    await intercepted.continue();
  };
  await page.route(metricsMatcher, failInitialMetrics);
  const failedResponse = metricSnapshotsResponse(page);
  await page.goto(missionRoute(), { waitUntil: "domcontentloaded" });
  expect((await failedResponse).status()).toBe(503);
  const alert = page.getByRole("alert").filter({ hasText: "Run metrics are unavailable" });
  await expect(alert).toContainText(expectedError.error.humanMessage);
  await expect(alert).toContainText(expectedError.error.remediation);
  await expect(alert).toContainText(expectedError.error.traceId);
  const retry = await assertManifestControl(page, "run-intelligence.metrics.retry");
  await expect(page.getByText(fixture.snapshotId, { exact: true })).toHaveCount(0);

  await page.unroute(metricsMatcher, failInitialMetrics);
  const recovered = metricSnapshotsResponse(page);
  await activate(retry, input);
  await assertMetricsResponse(await recovered);
  await expect(page.getByRole("heading", { name: "Recomputed run intelligence", exact: true })).toBeVisible();
  await expect(page.getByText(fixture.snapshotId, { exact: true })).toBeVisible();
  expect(readRunMetricsFixtureState(fixture)).toEqual({
    snapshotCount: 1,
    snapshotId: fixture.snapshotId,
    recomputationHash: fixture.recomputationHash,
    attackAttemptCount: 1,
    attemptEvidenceCount: 1,
    evidenceCount: 1,
    evidenceHash: fixture.evidenceHash,
  });
  await assertStrictlyClean(audit, testInfo);
}

test(`${RETRY_POINTER_TEST_ID} presents a precise initial failure and retries with pointer activation`, async ({ page }, testInfo) => {
  test.setTimeout(60_000);
  await exerciseInitialMetricsRetry(page, testInfo, "pointer");
});

test(`${RETRY_KEYBOARD_TEST_ID} presents a precise initial failure and retries with keyboard activation`, async ({ page }, testInfo) => {
  test.setTimeout(60_000);
  await exerciseInitialMetricsRetry(page, testInfo, "keyboard");
});

// Literal IDs keep interaction-manifest and release-evidence coverage auditable without mutating the manifest here.
void [TEST_ID, RETRY_POINTER_TEST_ID, RETRY_KEYBOARD_TEST_ID, ...MANIFEST_ENTRIES];

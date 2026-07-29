import { expect, test, type Locator, type Page, type Response, type TestInfo } from "./support/playwright";
import { readFileSync } from "node:fs";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createOperationalTruthFixture,
  OPERATIONAL_TRUTH_ADDITIONAL_REQUIREMENT,
  OPERATIONAL_TRUTH_MAIN_LABEL,
  OPERATIONAL_TRUTH_MAIN_SUMMARY,
  OPERATIONAL_TRUTH_REDACTED_SECRET,
  OPERATIONAL_TRUTH_REJECT_LABEL,
  readOperationalTruthSnapshot,
  type OperationalTruthFixture,
} from "./support/operationalTruthFixture";

const STAGES_TEST_ID = "e2e.operational-truth.stages-and-pagination";
const RETRY_TEST_ID = "e2e.operational-truth.retry";
const REJECT_TEST_ID = "e2e.operational-truth.reject";
const VERIFY_TEST_ID = "e2e.operational-truth.verify-demote";
const VISUAL_PROJECT = "chromium-1440";
const EVIDENCE_VERIFICATION_VISUAL = {
  id: "visual.operational-truth.evidence-verification.chromium-1440",
  snapshot: "operational-truth-evidence-verification.png",
} as const;

const OPERATIONAL_TRUTH_MANIFEST_IDS = [
  "operational-truth.stage-tabs",
  "operational-truth.retry",
  "operational-truth.pagination",
  "operational-truth.log-payload-disclosures",
  "operational-truth.observation-payload-disclosures",
  "operational-truth.candidate-select",
  "operational-truth.decision-reason",
  "operational-truth.begin-validation",
  "operational-truth.reject-candidate",
  "operational-truth.demote-evidence",
  "operational-truth.verify.reason",
  "operational-truth.verify.source",
  "operational-truth.verify.target",
  "operational-truth.verify.acquired-at",
  "operational-truth.verify.confidence",
  "operational-truth.verify.method",
  "operational-truth.verify.explanation",
  "operational-truth.verify.custody-actor",
  "operational-truth.verify.custody-time",
  "operational-truth.verify.additional-requirements",
  "operational-truth.verify.confirmation",
  "operational-truth.verify.submit",
  "operational-truth.verified-select",
  "operational-truth.provenance-disclosure",
  "operational-truth.custody-disclosures",
] as const;

const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);
const PROMOTE_REASON = "The normalized service record is attributable and ready for independent validation.";
const REJECT_REASON = "A single response header does not independently establish the claimed application product.";
const VERIFY_REASON = "I independently checked the normalized target, source attribution, and retained acquisition record.";
const DEMOTE_REASON = "A later review requires the evidence to leave promoted status while its immutable history is retained.";
const SOURCE_DESCRIPTION = "Local normalized reconnaissance result";
const NORMALIZED_TARGET = "operational-truth.example.test:443/tcp";
const ACQUIRED_AT_LOCAL = "2026-07-16T13:20";
const CUSTODY_AT_LOCAL = "2026-07-16T13:21";
const PROVENANCE_METHOD = "Independent review of a normalized structured observation";
const PROVENANCE_EXPLANATION = "The canonical observation and retained source log agree on the authorized target, port, and transport.";
const CUSTODY_ACTOR = "e2e-acquisition-reviewer";

let fixture: OperationalTruthFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createOperationalTruthFixture(canonicalFixtureNamespace(testInfo, "operational-truth"));
});

function missionRoute(): string {
  return `/missions/${encodeURIComponent(fixture.missionId)}/runs/${encodeURIComponent(fixture.runId)}?tab=evidence`;
}

function apiRoot(): string {
  return `/api/v2/operational-truth/missions/${fixture.missionId}`;
}

function pathname(response: Response): string {
  return new URL(response.url()).pathname;
}

function nativeDisclosure(page: Page, label: string | RegExp): Locator {
  // Chromium and Firefox expose native <details>/<summary> as a named group
  // rather than a button. Target the real keyboard-operable summary while the
  // interaction manifest keeps its cross-control disclosure normalization.
  return page.locator("summary").filter({ hasText: label });
}

async function expectEvidenceVerificationVisual(form: Locator, testInfo: TestInfo): Promise<void> {
  if (testInfo.project.name !== VISUAL_PROJECT) return;
  await form.page().evaluate(async () => { await document.fonts.ready; });
  const topbar = form.page().locator(".os-topbar");
  if (await topbar.count() === 1) {
    await topbar.evaluate((node) => { (node as HTMLElement).style.visibility = "hidden"; });
  }
  const sourceIds = form.locator(".os-compact-list small");
  await expect(sourceIds).toHaveCount(2);
  await sourceIds.nth(0).evaluate((node) => { node.textContent = "obs_visual_fixture"; });
  await sourceIds.nth(1).evaluate((node) => { node.textContent = "log_visual_fixture"; });
  await expect(form).toHaveScreenshot(EVIDENCE_VERIFICATION_VISUAL.snapshot, {
    animations: "disabled",
    caret: "hide",
    maxDiffPixels: 0,
    threshold: 0.15,
  });
}

async function assertManifestControl(page: Page, id: typeof OPERATIONAL_TRUTH_MANIFEST_IDS[number]): Promise<void> {
  const entry = manifest.entries.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`Operational-truth manifest entry ${id} is missing`);
  if (entry.accessible.locator === "native-summary") {
    const name = entry.accessible.match === "regex" ? new RegExp(entry.accessible.name) : entry.accessible.name;
    await expect(nativeDisclosure(page, name).first()).toBeVisible();
    return;
  }
  if (entry.accessible.locator === "native-date-input") {
    const label = entry.accessible.match === "regex" ? new RegExp(entry.accessible.name) : entry.accessible.name;
    await expect(page.getByLabel(label, { exact: entry.accessible.match === "exact" })).toBeVisible();
    return;
  }
  if (!entry.accessible.role) throw new Error(`Operational-truth manifest entry ${id} has no supported locator`);
  const name = entry.accessible.match === "regex" ? new RegExp(entry.accessible.name) : entry.accessible.name;
  await expect(page.getByRole(entry.accessible.role, {
    name,
    exact: entry.accessible.match === "exact",
  }).first()).toBeVisible();
}

async function selectStage(page: Page, label: "Logs" | "Observations" | "Candidates" | "Verified evidence"): Promise<void> {
  const tab = page.getByRole("tab", { name: label, exact: true });
  await tab.click();
  await expect(tab).toHaveAttribute("aria-selected", "true");
}

async function exerciseNextAndPrevious(page: Page, collectionPath: string): Promise<void> {
  const nextResponse = page.waitForResponse((response) =>
    pathname(response) === collectionPath
    && response.request().method() === "GET"
    && new URL(response.url()).searchParams.has("cursor"));
  await page.getByRole("button", { name: "Next page", exact: true }).click();
  expect((await nextResponse).status()).toBe(200);
  await expect(page.getByText("Page 2", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "First page", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Previous page", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Next page", exact: true })).toBeDisabled();

  const previous = page.getByRole("button", { name: "Previous page", exact: true });
  await previous.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Page 1", { exact: true })).toBeVisible();
}

async function gotoCandidateStage(page: Page): Promise<void> {
  const candidates = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/evidence-candidates`
    && response.request().method() === "GET");
  await page.goto(missionRoute(), { waitUntil: "domcontentloaded" });
  await selectStage(page, "Candidates");
  expect((await candidates).status()).toBe(200);
}

test(`${STAGES_TEST_ID} traverses every truth stage, disclosure, and opaque cursor`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const logs = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/logs` && response.request().method() === "GET");
  await page.goto(missionRoute(), { waitUntil: "domcontentloaded" });
  expect((await logs).status()).toBe(200);

  await assertManifestControl(page, "operational-truth.stage-tabs");
  await assertManifestControl(page, "operational-truth.pagination");
  await assertManifestControl(page, "operational-truth.log-payload-disclosures");
  await expect(page.getByText("Chronological technical records. Raw output is not evidence.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "First page", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Previous page", exact: true })).toBeDisabled();

  const logDisclosure = nativeDisclosure(page, "View redacted technical payload").first();
  await logDisclosure.focus();
  await page.keyboard.press("Enter");
  const redactedPayload = page.locator("pre").filter({ hasText: "apiToken" });
  await expect(redactedPayload).toContainText("[REDACTED]");
  await expect(page.locator("body")).not.toContainText(OPERATIONAL_TRUTH_REDACTED_SECRET);
  await page.keyboard.press("Enter");
  await expect(redactedPayload).toBeHidden();

  await exerciseNextAndPrevious(page, `${apiRoot()}/logs`);
  await page.getByRole("button", { name: "Next page", exact: true }).click();
  await expect(page.getByText("Page 2", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "First page", exact: true }).click();
  await expect(page.getByText("Page 1", { exact: true })).toBeVisible();

  const observations = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/observations` && response.request().method() === "GET");
  const logsTab = page.getByRole("tab", { name: "Logs", exact: true });
  await logsTab.focus();
  await page.keyboard.press("ArrowRight");
  expect((await observations).status()).toBe(200);
  await expect(page.getByRole("tab", { name: "Observations", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByText("Parsed, attributable statements that can remain uncertain or conflicting.", { exact: true })).toBeVisible();
  await assertManifestControl(page, "operational-truth.observation-payload-disclosures");
  const observationDisclosure = nativeDisclosure(page, "Normalized observation").first();
  await observationDisclosure.click();
  await expect(page.locator("pre").filter({ hasText: "operational-truth.example.test:443/tcp" })).toContainText("443");
  await observationDisclosure.focus();
  await page.keyboard.press("Enter");
  await exerciseNextAndPrevious(page, `${apiRoot()}/observations`);

  await selectStage(page, "Candidates");
  await assertManifestControl(page, "operational-truth.candidate-select");
  await exerciseNextAndPrevious(page, `${apiRoot()}/evidence-candidates`);

  const verifiedTab = page.getByRole("tab", { name: "Candidates", exact: true });
  await verifiedTab.focus();
  const verified = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/verified-evidence` && response.request().method() === "GET");
  await page.keyboard.press("End");
  expect((await verified).status()).toBe(200);
  await expect(page.getByRole("tab", { name: "Verified evidence", exact: true })).toHaveAttribute("aria-selected", "true");
  await exerciseNextAndPrevious(page, `${apiRoot()}/verified-evidence`);

  await page.getByRole("tab", { name: "Verified evidence", exact: true }).focus();
  await page.keyboard.press("Home");
  await expect(page.getByRole("tab", { name: "Logs", exact: true })).toHaveAttribute("aria-selected", "true");
  await audit.assertClean(testInfo);
});

test(`${RETRY_TEST_ID} explains and recovers one precise stage-read failure`, async ({ page, browserAudit }, testInfo) => {
  browserAudit.expectHttpResponse(page, {
    id: "operational-truth.logs.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: `${apiRoot()}/logs`,
    query: { runId: fixture.runId, limit: "25" },
    status: 503,
    occurrences: 1,
    reason: "Exercise the exact run-scoped engagement-log retry state once.",
  });
  let failedOnce = false;
  await page.route(`**${apiRoot()}/logs?*`, async (route) => {
    if (!failedOnce) {
      failedOnce = true;
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({
          error: {
            code: "operational_truth_fixture_unavailable",
            message: "Operational-truth fixture temporarily unavailable",
            humanMessage: "The engagement-log projection could not read its isolated local records.",
            retryable: true,
            category: "dependency",
            remediation: "Retry this read after the isolated local projection is available.",
            traceId: "trace-operational-truth-retry",
            timestamp: "2026-07-16T13:30:00.000Z",
          },
        }),
      });
      return;
    }
    await route.continue();
  });
  await page.goto(missionRoute(), { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Loading engagement logs failed", { exact: true })).toBeVisible();
  await expect(page.getByText("The engagement-log projection could not read its isolated local records.", { exact: true })).toBeVisible();
  await expect(page.getByText("Retry this read after the isolated local projection is available.", { exact: true })).toBeVisible();
  await expect(page.getByText("Trace trace-operational-truth-retry", { exact: true })).toBeVisible();
  await assertManifestControl(page, "operational-truth.retry");

  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const recovered = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/logs`
    && response.request().method() === "GET"
    && response.status() === 200);
  const retry = page.getByRole("button", { name: "Try again", exact: true });
  await retry.focus();
  await page.keyboard.press("Enter");
  expect((await recovered).status()).toBe(200);
  await expect(page.getByText("Authorized reconnaissance observed HTTPS on TCP port 443; this remains a technical log until reviewed.", { exact: true })).toBeVisible();
  await page.unroute(`**${apiRoot()}/logs?*`);
  await audit.assertClean(testInfo);
});

test(`${REJECT_TEST_ID} rejects one candidate with an audited durable reason`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await gotoCandidateStage(page);
  const selector = page.getByRole("button", { name: OPERATIONAL_TRUTH_REJECT_LABEL, exact: true });
  await selector.focus();
  await page.keyboard.press("Enter");
  await expect(selector).toHaveAttribute("aria-pressed", "true");
  await assertManifestControl(page, "operational-truth.decision-reason");
  await assertManifestControl(page, "operational-truth.reject-candidate");

  const reason = page.getByRole("textbox", { name: "Decision reason", exact: true });
  await reason.fill("too short");
  await expect(page.getByRole("button", { name: "Reject candidate", exact: true })).toBeDisabled();
  await reason.fill(REJECT_REASON);
  const requestPromise = page.waitForRequest((request) =>
    request.url().endsWith(`/evidence-candidates/${fixture.rejectCandidateId}/reject`)
    && request.method() === "POST");
  const responsePromise = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/evidence-candidates/${fixture.rejectCandidateId}/reject`
    && response.request().method() === "POST");
  await page.getByRole("button", { name: "Reject candidate", exact: true }).click();
  const [request, response] = await Promise.all([requestPromise, responsePromise]);
  expect(response.status()).toBe(200);
  expect(request.headers()["idempotency-key"]).toMatch(/^candidate-reject-/u);
  expect(request.postDataJSON()).toEqual({ reason: REJECT_REASON });

  let snapshot = readOperationalTruthSnapshot(fixture);
  expect(snapshot.rejectCandidate).toMatchObject({
    state: "rejected",
    reviewedBy: "e2e-local-operator",
    reviewReason: REJECT_REASON,
    promotedEvidenceId: null,
  });
  expect(snapshot.totalEvidenceCount).toBe(fixture.seededVerifiedEvidenceCount);
  expect(snapshot.audits).toContainEqual(expect.objectContaining({
    action: "evidence_candidate.rejected",
    resourceId: fixture.rejectCandidateId,
    actorId: "e2e-local-operator",
    reason: REJECT_REASON,
  }));
  expect(snapshot.audits.find((record) => record.action === "evidence_candidate.rejected")?.recordHash)
    .toMatch(/^[a-f0-9]{64}$/u);

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await selectStage(page, "Candidates");
  await page.getByRole("button", { name: OPERATIONAL_TRUTH_REJECT_LABEL, exact: true }).click();
  await expect(page.getByText("This rejected candidate is retained for audit. It has no valid review mutation from its current state.", { exact: true })).toBeVisible();
  await expect(page.getByText(REJECT_REASON, { exact: false })).toBeVisible();
  snapshot = readOperationalTruthSnapshot(fixture);
  expect(snapshot.rejectCandidate.state).toBe("rejected");
  await audit.assertClean(testInfo);
});

test(`${VERIFY_TEST_ID} validates, independently verifies, inspects, and demotes canonical evidence`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await gotoCandidateStage(page);
  const mainSelector = page.getByRole("button", { name: OPERATIONAL_TRUTH_MAIN_LABEL, exact: true });
  await mainSelector.click();
  await expect(mainSelector).toHaveAttribute("aria-pressed", "true");
  await assertManifestControl(page, "operational-truth.candidate-select");
  await assertManifestControl(page, "operational-truth.begin-validation");

  const decisionReason = page.getByRole("textbox", { name: "Decision reason", exact: true });
  await decisionReason.fill("too short");
  await expect(page.getByRole("button", { name: "Begin validation", exact: true })).toBeDisabled();
  await decisionReason.fill(PROMOTE_REASON);
  const promoteRequest = page.waitForRequest((request) =>
    request.url().endsWith(`/evidence-candidates/${fixture.mainCandidateId}/promote`)
    && request.method() === "POST");
  const promoteResponse = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/evidence-candidates/${fixture.mainCandidateId}/promote`
    && response.request().method() === "POST");
  const promotedObservation = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/observations/${fixture.mainObservationId}`
    && response.request().method() === "GET");
  const beginValidation = page.getByRole("button", { name: "Begin validation", exact: true });
  await beginValidation.focus();
  await page.keyboard.press("Enter");
  const [promoteHttpRequest, promoteHttpResponse] = await Promise.all([promoteRequest, promoteResponse]);
  expect(promoteHttpResponse.status()).toBe(200);
  expect(promoteHttpRequest.headers()["idempotency-key"]).toMatch(/^candidate-promote-/u);
  expect(promoteHttpRequest.postDataJSON()).toEqual({ reason: PROMOTE_REASON });
  // Moving into validation mounts the canonical observation resolver. Let
  // that required read settle before the deliberate persistence reload so a
  // controlled component teardown cannot race the browser network audit.
  expect((await promotedObservation).status()).toBe(200);

  let snapshot = readOperationalTruthSnapshot(fixture);
  expect(snapshot.mainCandidate).toMatchObject({
    state: "validating",
    reviewedBy: "e2e-local-operator",
    reviewReason: PROMOTE_REASON,
    promotedEvidenceId: null,
  });
  expect(snapshot.totalEvidenceCount).toBe(fixture.seededVerifiedEvidenceCount);
  expect(snapshot.audits).toContainEqual(expect.objectContaining({
    action: "evidence_candidate.promoted_for_validation",
    resourceId: fixture.mainCandidateId,
    actorId: "e2e-local-operator",
    reason: PROMOTE_REASON,
  }));

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  const observationDetail = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/observations/${fixture.mainObservationId}`
    && response.request().method() === "GET");
  await selectStage(page, "Candidates");
  const persistedSelector = page.getByRole("button", { name: OPERATIONAL_TRUTH_MAIN_LABEL, exact: true });
  await persistedSelector.focus();
  await page.keyboard.press("Enter");
  expect((await observationDetail).status()).toBe(200);
  await expect(page.getByRole("heading", { name: "Verify as evidence", exact: true })).toBeVisible();

  for (const id of [
    "operational-truth.verify.reason",
    "operational-truth.verify.source",
    "operational-truth.verify.target",
    "operational-truth.verify.acquired-at",
    "operational-truth.verify.confidence",
    "operational-truth.verify.method",
    "operational-truth.verify.explanation",
    "operational-truth.verify.custody-actor",
    "operational-truth.verify.custody-time",
    "operational-truth.verify.additional-requirements",
    "operational-truth.verify.confirmation",
    "operational-truth.verify.submit",
  ] as const) await assertManifestControl(page, id);

  const verifySubmit = page.getByRole("button", { name: "Verify evidence", exact: true });
  await expect(verifySubmit).toBeDisabled();
  await page.getByRole("textbox", { name: "Independent review reason", exact: true }).fill(VERIFY_REASON);
  const source = page.getByRole("textbox", { name: "Source description", exact: true });
  await source.focus();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+A" : "Control+A");
  await page.keyboard.type(SOURCE_DESCRIPTION);
  await page.getByRole("textbox", { name: "Normalized target", exact: true }).fill(NORMALIZED_TARGET);
  await page.getByLabel("Acquired at", { exact: true }).fill(ACQUIRED_AT_LOCAL);
  const confidence = page.getByRole("slider", { name: /^Confidence \([0-9]+%\)$/u });
  await confidence.focus();
  await page.keyboard.press("End");
  await page.keyboard.press("ArrowLeft");
  await expect(page.getByRole("slider", { name: "Confidence (95%)", exact: true })).toHaveValue("0.95");
  await page.getByRole("textbox", { name: "Provenance method", exact: true }).fill(PROVENANCE_METHOD);
  await page.getByRole("textbox", { name: "Provenance explanation", exact: true }).fill(PROVENANCE_EXPLANATION);
  await page.getByRole("textbox", { name: "Acquisition custody actor", exact: true }).fill(CUSTODY_ACTOR);
  await page.getByLabel("Custody event time", { exact: true }).fill(CUSTODY_AT_LOCAL);
  await expect(verifySubmit).toBeDisabled();

  const additional = page.getByRole("checkbox", { name: "I verified the additional requirement: Second source corroborated", exact: true });
  await additional.click();
  await expect(additional).toBeChecked();
  await expect(verifySubmit).toBeDisabled();
  const attestation = page.getByRole("checkbox", { name: /^I independently reviewed attribution, scope, hash-bound source, acquisition time, and custody\./u });
  await attestation.focus();
  await page.keyboard.press("Space");
  await expect(attestation).toBeChecked();
  await expect(verifySubmit).toBeEnabled();
  const verificationForm = page.locator("form.os-review-form").filter({
    has: page.getByRole("heading", { name: "Verify as evidence", exact: true }),
  });
  await expectEvidenceVerificationVisual(verificationForm, testInfo);

  const verifyRequest = page.waitForRequest((request) =>
    request.url().endsWith(`/evidence-candidates/${fixture.mainCandidateId}/verify`)
    && request.method() === "POST");
  const verifyResponse = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/evidence-candidates/${fixture.mainCandidateId}/verify`
    && response.request().method() === "POST");
  await verifySubmit.focus();
  await page.keyboard.press("Enter");
  const [verifyHttpRequest, verifyHttpResponse] = await Promise.all([verifyRequest, verifyResponse]);
  expect(verifyHttpResponse.status()).toBe(201);
  expect(verifyHttpRequest.headers()["idempotency-key"]).toMatch(/^candidate-verify-/u);
  const verifyBody = verifyHttpRequest.postDataJSON() as {
    readonly reason: string;
    readonly source: string;
    readonly target: string;
    readonly acquiredAt: string;
    readonly confidence: number;
    readonly provenance: { readonly method: string; readonly explanation: string; readonly sources: readonly unknown[] };
    readonly custody: readonly { readonly eventType: string; readonly actor: string; readonly occurredAt: string }[];
    readonly satisfiedAdditionalRequirements: readonly string[];
  };
  expect(verifyBody).toMatchObject({
    reason: VERIFY_REASON,
    source: SOURCE_DESCRIPTION,
    target: NORMALIZED_TARGET,
    acquiredAt: "2026-07-16T13:20:00.000Z",
    confidence: 0.95,
    provenance: {
      method: PROVENANCE_METHOD,
      explanation: PROVENANCE_EXPLANATION,
      sources: [
        { kind: "observation", id: fixture.mainObservationId },
        { kind: "engagement_log", id: fixture.mainLogId },
      ],
    },
    custody: [{ eventType: "acquired", actor: CUSTODY_ACTOR, occurredAt: "2026-07-16T13:21:00.000Z" }],
    satisfiedAdditionalRequirements: [OPERATIONAL_TRUTH_ADDITIONAL_REQUIREMENT],
  });

  snapshot = readOperationalTruthSnapshot(fixture);
  expect(snapshot.mainCandidate).toMatchObject({
    state: "promoted",
    reviewedBy: "e2e-local-operator",
    reviewReason: VERIFY_REASON,
  });
  expect(snapshot.mainCandidate.promotedEvidenceId).toBeTruthy();
  expect(snapshot.totalEvidenceCount).toBe(fixture.seededVerifiedEvidenceCount + 1);
  expect(snapshot.mainEvidence).toMatchObject({
    source: SOURCE_DESCRIPTION,
    target: NORMALIZED_TARGET,
    confidence: 0.95,
    verificationState: "verified",
    summary: OPERATIONAL_TRUTH_MAIN_SUMMARY,
    createdBy: "e2e-local-operator",
  });
  expect(snapshot.mainEvidence?.contentHash).toMatch(/^[a-f0-9]{64}$/u);
  expect(snapshot.mainEvidence?.provenance).toMatchObject({
    candidateId: fixture.mainCandidateId,
    sourceLogIds: [fixture.mainLogId],
    sources: [
      { kind: "observation", id: fixture.mainObservationId },
      { kind: "engagement_log", id: fixture.mainLogId },
    ],
  });
  expect(snapshot.custody.map((event) => [event.eventType, event.actor])).toEqual([
    ["acquired", CUSTODY_ACTOR],
    ["verified", "e2e-local-operator"],
  ]);
  expect(snapshot.custody[0]).toMatchObject({
    occurredAt: "2026-07-16T13:21:00.000Z",
    details: { review: "Canonical source and acquisition were explicitly reviewed by a human operator." },
  });
  expect(snapshot.audits).toContainEqual(expect.objectContaining({
    action: "evidence.verified",
    resourceId: snapshot.mainCandidate.promotedEvidenceId,
    actorId: "e2e-local-operator",
    reason: VERIFY_REASON,
  }));
  expect(snapshot.audits.find((record) => record.action === "evidence.verified")?.recordHash)
    .toMatch(/^[a-f0-9]{64}$/u);

  const evidenceDetail = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/verified-evidence/${snapshot.mainCandidate.promotedEvidenceId}`
    && response.request().method() === "GET");
  await selectStage(page, "Verified evidence");
  expect((await evidenceDetail).status()).toBe(200);
  const verifiedSelector = page.getByRole("button", { name: OPERATIONAL_TRUTH_MAIN_SUMMARY, exact: true });
  await verifiedSelector.focus();
  await page.keyboard.press("Enter");
  await expect(verifiedSelector).toHaveAttribute("aria-pressed", "true");
  await assertManifestControl(page, "operational-truth.verified-select");
  await assertManifestControl(page, "operational-truth.provenance-disclosure");
  await assertManifestControl(page, "operational-truth.custody-disclosures");

  const provenance = nativeDisclosure(page, "Inspect provenance");
  await provenance.focus();
  await page.keyboard.press("Enter");
  const provenancePayload = page.locator("pre").filter({ hasText: fixture.mainObservationId });
  await expect(provenancePayload).toContainText(fixture.mainLogId);
  await expect(provenancePayload).toContainText(PROVENANCE_METHOD);
  await provenance.click();

  const custodyDisclosures = nativeDisclosure(page, "Custody detail");
  await expect(custodyDisclosures).toHaveCount(2);
  await custodyDisclosures.first().click();
  await expect(page.locator("pre").filter({ hasText: "Canonical source and acquisition were explicitly reviewed" })).toBeVisible();
  await custodyDisclosures.first().focus();
  await page.keyboard.press("Enter");

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await selectStage(page, "Verified evidence");
  await expect(page.getByRole("button", { name: OPERATIONAL_TRUTH_MAIN_SUMMARY, exact: true })).toBeVisible();
  await expect(page.getByText(snapshot.mainEvidence!.contentHash, { exact: true })).toBeVisible();

  await selectStage(page, "Candidates");
  await page.getByRole("button", { name: OPERATIONAL_TRUTH_MAIN_LABEL, exact: true }).click();
  await assertManifestControl(page, "operational-truth.demote-evidence");
  const demoteReason = page.getByRole("textbox", { name: "Decision reason", exact: true });
  await demoteReason.fill(DEMOTE_REASON);
  const demoteRequest = page.waitForRequest((request) =>
    request.url().endsWith(`/evidence-candidates/${fixture.mainCandidateId}/demote`)
    && request.method() === "POST");
  const demoteResponse = page.waitForResponse((response) =>
    pathname(response) === `${apiRoot()}/evidence-candidates/${fixture.mainCandidateId}/demote`
    && response.request().method() === "POST");
  await page.getByRole("button", { name: "Demote evidence", exact: true }).click();
  const [demoteHttpRequest, demoteHttpResponse] = await Promise.all([demoteRequest, demoteResponse]);
  expect(demoteHttpResponse.status()).toBe(200);
  expect(demoteHttpRequest.headers()["idempotency-key"]).toMatch(/^candidate-demote-/u);
  expect(demoteHttpRequest.postDataJSON()).toEqual({ reason: DEMOTE_REASON });

  snapshot = readOperationalTruthSnapshot(fixture);
  expect(snapshot.mainCandidate).toMatchObject({
    state: "demoted",
    reviewedBy: "e2e-local-operator",
    reviewReason: DEMOTE_REASON,
  });
  expect(snapshot.totalEvidenceCount).toBe(fixture.seededVerifiedEvidenceCount + 1);
  expect(snapshot.mainEvidence?.verificationState).toBe("verified");
  expect(snapshot.custody.map((event) => event.eventType)).toEqual(["acquired", "verified", "demoted"]);
  expect(snapshot.custody.at(-1)).toMatchObject({ actor: "e2e-local-operator", details: { reason: DEMOTE_REASON } });
  expect(snapshot.audits).toContainEqual(expect.objectContaining({
    action: "evidence.demoted",
    resourceId: snapshot.mainCandidate.promotedEvidenceId,
    actorId: "e2e-local-operator",
    reason: DEMOTE_REASON,
  }));

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await selectStage(page, "Candidates");
  await page.getByRole("button", { name: OPERATIONAL_TRUTH_MAIN_LABEL, exact: true }).click();
  await expect(page.getByText(DEMOTE_REASON, { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: "Demote evidence", exact: true })).toHaveCount(0);
  const revalidationButton = page.getByRole("button", { name: "Begin validation", exact: true });
  await expect(revalidationButton).toBeDisabled();
  await page.getByRole("textbox", { name: "Decision reason", exact: true })
    .fill("Revalidate after reviewing the complete demotion history.");
  await expect(revalidationButton).toBeEnabled();

  await selectStage(page, "Verified evidence");
  await page.getByRole("button", { name: OPERATIONAL_TRUTH_MAIN_SUMMARY, exact: true }).click();
  await expect(page.getByText("Demoted", { exact: true })).toBeVisible();
  await expect(page.getByText(`e2e-local-operator ·`, { exact: false }).last()).toBeVisible();
  await audit.assertClean(testInfo);
});

// Literal identifiers keep dedicated interaction-manifest coverage statically auditable.
void [
  STAGES_TEST_ID,
  RETRY_TEST_ID,
  REJECT_TEST_ID,
  VERIFY_TEST_ID,
  ...OPERATIONAL_TRUTH_MANIFEST_IDS,
];

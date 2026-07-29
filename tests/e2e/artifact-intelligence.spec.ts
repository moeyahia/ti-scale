import { expect, test, type Page, type Response } from "./support/playwright";
import { readFileSync } from "node:fs";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import { createArtifactIntelligenceFixture, type ArtifactIntelligenceFixture } from "./support/artifactIntelligenceFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_ID = "e2e.artifact-intelligence.controls";
const TEST_SCRIPT_ERROR = "e2e.artifact-intelligence.script-retry";
const TEST_CAPTURE_ERROR = "e2e.artifact-intelligence.capture-retry";
const manifest = validateInteractionManifest(JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown);
let fixture: ArtifactIntelligenceFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createArtifactIntelligenceFixture(canonicalFixtureNamespace(testInfo, "artifact-intelligence"));
});

function route(): string { return `/missions/${encodeURIComponent(fixture.missionId)}/runs/${encodeURIComponent(fixture.runId)}?tab=plan`; }
function pathname(response: Response): string { return new URL(response.url()).pathname; }

async function assertManifestControl(page: Page, id: string): Promise<void> {
  const entry = manifest.entries.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`Artifact-intelligence manifest entry ${id} is missing`);
  if (!entry.accessible.role) throw new Error(`Artifact-intelligence manifest entry ${id} is not role-addressable`);
  const name = entry.accessible.match === "regex" ? new RegExp(entry.accessible.name) : entry.accessible.name;
  await expect(page.getByRole(entry.accessible.role, { name, exact: entry.accessible.match === "exact" }).first()).toBeVisible();
}

test(`${TEST_ID} reads immutable scripts and evidence-backed capture metadata without execution`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const scriptList = page.waitForResponse((response) => pathname(response) === `/api/v2/missions/${fixture.missionId}/script-artifacts` && response.request().method() === "GET");
  const captureList = page.waitForResponse((response) => pathname(response) === `/api/v2/missions/${fixture.missionId}/intelligence/page-captures` && response.request().method() === "GET");
  await page.goto(route(), { waitUntil: "domcontentloaded" });
  expect((await scriptList).status()).toBe(200);
  expect((await captureList).status()).toBe(200);

  await expect(page.getByRole("heading", { name: "Generated scripts", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Web-page captures", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: `Inspect script ${fixture.scriptName} version 2`, exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByLabel(`Read-only script ${fixture.scriptName} version 2`, { exact: true })).toContainText("Immutable source version 2");
  await expect(page.getByLabel("Immutable script source", { exact: true })).toContainText("metadata-ready:v2");
  await expect(page.getByText("Document offline-only behavior and make the deterministic marker version-specific.", { exact: true })).toBeVisible();
  await expect(page.getByText("An isolated offline parser test passed; no target action was performed.", { exact: true })).toBeVisible();
  await expect(page.getByText("This workspace is intentionally read only.", { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: /execute|run script/iu })).toHaveCount(0);

  const versionOne = page.getByRole("button", { name: `Inspect script ${fixture.scriptName} version 1`, exact: true });
  await versionOne.focus();
  await page.keyboard.press("Enter");
  await expect(versionOne).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByLabel(`Read-only script ${fixture.scriptName} version 1`, { exact: true })).toContainText("Initial documented script version");

  const versionTwo = page.getByRole("button", { name: `Inspect script ${fixture.scriptName} version 2`, exact: true });
  await versionTwo.click();
  await expect(page.getByLabel(`Read-only script ${fixture.scriptName} version 2`, { exact: true })).toBeVisible();
  const sourceArtifact = page.getByRole("link", { name: `Open source artifact ${fixture.scriptArtifactId}`, exact: true });
  await expect(sourceArtifact).toHaveAttribute("href", `/intelligence/artifacts/${fixture.scriptArtifactId}`);
  await expect(page.getByRole("link", { name: `Open script test artifact ${fixture.scriptTestArtifactId}`, exact: true })).toHaveAttribute("href", `/intelligence/artifacts/${fixture.scriptTestArtifactId}`);

  await expect(page.getByRole("button", { name: `Inspect page capture ${fixture.captureTitle}`, exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByLabel(`Page capture ${fixture.captureTitle}`, { exact: true })).toContainText("HTTP 200");
  await expect(page.getByLabel("Capture preview ready", { exact: true })).toContainText("has not registered an approved inline image-delivery adapter");
  await expect(page.getByText("TLSv1.3", { exact: true })).toBeVisible();
  await expect(page.getByText("fixture-server/2.4", { exact: true })).toBeVisible();
  const previewArtifact = page.getByRole("link", { name: `Open preview artifact ${fixture.screenshotArtifactId}`, exact: true }).first();
  await expect(previewArtifact).toHaveAttribute("href", `/intelligence/artifacts/${fixture.screenshotArtifactId}`);
  await expect(page.getByRole("link", { name: `Open full-page artifact ${fixture.fullPageArtifactId}`, exact: true })).toHaveAttribute("href", `/intelligence/artifacts/${fixture.fullPageArtifactId}`);
  await expect(page.getByRole("link", { name: fixture.evidenceId, exact: true })).toHaveAttribute("href", `/intelligence/evidence/${fixture.evidenceId}`);
  await expect(page.getByRole("link", { name: fixture.findingId, exact: true })).toHaveAttribute("href", `/intelligence/findings/${fixture.findingId}`);

  for (const id of [
    "artifact-intelligence.scripts.refresh", "artifact-intelligence.scripts.select", "artifact-intelligence.scripts.source-artifact",
    "artifact-intelligence.scripts.test-artifact", "artifact-intelligence.scripts.plan", "artifact-intelligence.captures.refresh", "artifact-intelligence.captures.select",
    "artifact-intelligence.captures.preview-artifact", "artifact-intelligence.captures.full-page-artifact", "artifact-intelligence.captures.evidence", "artifact-intelligence.captures.finding",
    "artifact-intelligence.captures.plan",
  ]) await assertManifestControl(page, id);

  const scriptRefresh = page.waitForResponse((response) => pathname(response) === `/api/v2/missions/${fixture.missionId}/script-artifacts` && response.request().method() === "GET");
  await page.getByRole("button", { name: "Refresh script artifacts", exact: true }).click();
  expect((await scriptRefresh).status()).toBe(200);
  const captureRefresh = page.waitForResponse((response) => pathname(response) === `/api/v2/missions/${fixture.missionId}/intelligence/page-captures` && response.request().method() === "GET");
  await page.getByRole("button", { name: "Refresh page captures", exact: true }).click();
  expect((await captureRefresh).status()).toBe(200);

  const evidenceDetail = page.waitForResponse((response) => pathname(response) === `/api/v2/intelligence/evidence/${fixture.evidenceId}` && response.request().method() === "GET");
  await page.getByRole("link", { name: fixture.evidenceId, exact: true }).click();
  expect((await evidenceDetail).status()).toBe(200);
  await expect(page).toHaveURL(`/intelligence/evidence/${fixture.evidenceId}`);
  await expect(page.getByRole("heading", { name: "Evidence, findings, and artifacts", exact: true })).toBeVisible();
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Generated scripts", exact: true })).toBeVisible();
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByLabel(`Read-only script ${fixture.scriptName} version 2`, { exact: true })).toBeVisible();
  await expect(page.getByLabel(`Page capture ${fixture.captureTitle}`, { exact: true })).toBeVisible();
  await audit.assertClean(testInfo);
});

test(`${TEST_SCRIPT_ERROR} retries a precise initial ScriptArtifact failure`, async ({ page, browserAudit }, testInfo) => {
  browserAudit.expectHttpResponse(page, {
    id: "artifact-intelligence.script.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: `/api/v2/missions/${fixture.missionId}/script-artifacts`,
    query: { runId: fixture.runId, limit: "100" },
    status: 503,
    occurrences: 1,
    reason: "Exercise the precise ScriptArtifact retry state once.",
  });
  const url = `**/api/v2/missions/${fixture.missionId}/script-artifacts?*`;
  let failed = false;
  await page.route(url, async (request) => {
    if (!failed) {
      failed = true;
      await request.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: { code: "script_fixture_unavailable", message: "Script fixture temporarily unavailable", humanMessage: "Immutable script records could not be read from the local fixture store.", retryable: true, category: "dependency", remediation: "Retry the canonical read after the local store recovers.", traceId: "trace-script-retry", timestamp: NOW } }) });
      return;
    }
    await request.continue();
  });
  await page.goto(route(), { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Immutable script records could not be read from the local fixture store.", { exact: true })).toBeVisible();
  await assertManifestControl(page, "artifact-intelligence.scripts.retry");
  const recovered = page.waitForResponse((response) => pathname(response) === `/api/v2/missions/${fixture.missionId}/script-artifacts` && response.status() === 200);
  await page.getByRole("button", { name: "Try again", exact: true }).click();
  await recovered;
  await expect(page.getByLabel(`Read-only script ${fixture.scriptName} version 2`, { exact: true })).toBeVisible();
  const audit = new BrowserAudit(page);
  await page.getByRole("button", { name: "Refresh script artifacts", exact: true }).click();
  await audit.assertClean(testInfo);
});

test(`${TEST_CAPTURE_ERROR} retries a precise initial PageCapture failure`, async ({ page, browserAudit }, testInfo) => {
  browserAudit.expectHttpResponse(page, {
    id: "artifact-intelligence.capture.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: `/api/v2/missions/${fixture.missionId}/intelligence/page-captures`,
    query: { runId: fixture.runId, limit: "100" },
    status: 503,
    occurrences: 1,
    reason: "Exercise the precise PageCapture retry state once.",
  });
  const url = `**/api/v2/missions/${fixture.missionId}/intelligence/page-captures?*`;
  let failed = false;
  await page.route(url, async (request) => {
    if (!failed) {
      failed = true;
      await request.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: { code: "capture_fixture_unavailable", message: "Capture fixture temporarily unavailable", humanMessage: "Evidence-backed page captures could not be read from the local fixture store.", retryable: true, category: "dependency", remediation: "Retry the canonical read after the local store recovers.", traceId: "trace-capture-retry", timestamp: NOW } }) });
      return;
    }
    await request.continue();
  });
  await page.goto(route(), { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Evidence-backed page captures could not be read from the local fixture store.", { exact: true })).toBeVisible();
  await assertManifestControl(page, "artifact-intelligence.captures.retry");
  const recovered = page.waitForResponse((response) => pathname(response) === `/api/v2/missions/${fixture.missionId}/intelligence/page-captures` && response.status() === 200);
  await page.getByRole("button", { name: "Try again", exact: true }).click();
  await recovered;
  await expect(page.getByLabel(`Page capture ${fixture.captureTitle}`, { exact: true })).toBeVisible();
  const audit = new BrowserAudit(page);
  await page.getByRole("button", { name: "Refresh page captures", exact: true }).click();
  await audit.assertClean(testInfo);
});

// Literal identifiers keep static interaction-manifest coverage auditable.
void [TEST_ID, TEST_SCRIPT_ERROR, TEST_CAPTURE_ERROR];
const NOW = "2026-07-16T19:00:00.000Z";

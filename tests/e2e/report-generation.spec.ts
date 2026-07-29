import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { BrowserAudit } from "./support/browserAudit";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createReportGenerationFixture,
  type ReportGenerationFixture,
} from "./support/reportGenerationFixture";
import { expect, test, type APIResponse, type Locator, type Page, type TestInfo } from "./support/playwright";

const TEST_ID = "e2e.reports.canonical-generation-delivery";

interface GeneratedArtifact {
  readonly id: string;
  readonly format: "markdown" | "json";
  readonly mediaType: string;
  readonly contentHash: string;
  readonly byteSize: number;
  readonly downloadUrl: string;
}

interface GenerationResponse {
  readonly schemaVersion: "2.4";
  readonly reportSchemaVersion: "2.4-report.1";
  readonly missionId: string;
  readonly runId: string;
  readonly reportVersion: number;
  readonly sourceSnapshotHash: string;
  readonly snapshotThrough: string;
  readonly idempotent: true;
  readonly artifacts: readonly GeneratedArtifact[];
}

let fixture: ReportGenerationFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createReportGenerationFixture(
    canonicalFixtureNamespace(testInfo, "canonical-report-generation"),
  );
});

function digest(body: Buffer): string {
  return createHash("sha256").update(body).digest("hex");
}

function expectedFilename(artifact: GeneratedArtifact): string {
  return `ti-scale-${fixture.runId}-report-v${fixture.reportVersion}.${artifact.format === "markdown" ? "md" : "json"}`;
}

async function assertInertHeaders(response: APIResponse, artifact: GeneratedArtifact): Promise<Buffer> {
  expect(response.status(), await response.text()).toBe(200);
  const headers = response.headers();
  expect(headers["content-type"]).toBe(artifact.mediaType);
  expect(headers["content-disposition"]).toBe(`attachment; filename="${expectedFilename(artifact)}"`);
  expect(headers["content-length"]).toBe(String(artifact.byteSize));
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["cross-origin-resource-policy"]).toBe("same-origin");
  expect(headers["content-security-policy"]).toBe("sandbox");
  expect(headers["cache-control"]).toBe("no-store");
  expect(headers.digest).toBe(`sha-256=${Buffer.from(artifact.contentHash, "hex").toString("base64")}`);
  const body = Buffer.from(await response.body());
  expect(body).toHaveLength(artifact.byteSize);
  expect(digest(body)).toBe(artifact.contentHash);
  expect(body.toString("utf8")).not.toContain(fixture.secretMarker);
  return body;
}

async function downloadThroughLink(
  page: Page,
  audit: BrowserAudit,
  link: Locator,
  artifact: GeneratedArtifact,
  expectedBody: Buffer,
  expectedPageUrl: string | RegExp = new RegExp("/reports(?:\\?|$)", "u"),
): Promise<void> {
  audit.expectVerifiedDownload(artifact.downloadUrl);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    link.click(),
  ]);
  await audit.verifyDownload(download, artifact.downloadUrl);
  expect(download.suggestedFilename()).toBe(expectedFilename(artifact));
  const path = await download.path();
  if (!path) throw new Error(`Playwright did not retain ${artifact.format} report download`);
  const received = readFileSync(path);
  expect(received.equals(expectedBody)).toBe(true);
  expect(digest(received)).toBe(artifact.contentHash);
  await expect(page).toHaveURL(expectedPageUrl);
}

async function attachScreenshot(page: Page, testInfo: TestInfo, name: string): Promise<void> {
  await testInfo.attach(name, {
    body: await page.screenshot({ fullPage: true, animations: "disabled" }),
    contentType: "image/png",
  });
}

test(`${TEST_ID} generates, downloads, and reloads two canonical authenticated artifacts`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await page.goto(`/reports?missionId=${fixture.missionId}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { level: 1, name: "Reports", exact: true })).toBeVisible();

  await page.getByLabel("Run ID", { exact: true }).fill(fixture.runId);
  await expect(page.getByLabel("Report version", { exact: true })).toHaveValue(String(fixture.reportVersion));
  const generationResponse = page.waitForResponse((response) => (
    response.request().method() === "POST"
      && new URL(response.url()).pathname === `/api/v2/reports/runs/${fixture.runId}/generate`
  ));
  await page.getByRole("button", { name: "Generate report", exact: true }).click();
  const generatedHttp = await generationResponse;
  expect(generatedHttp.status(), await generatedHttp.text()).toBe(201);
  const generation = await generatedHttp.json() as GenerationResponse;
  expect(generation).toMatchObject({
    schemaVersion: "2.4",
    reportSchemaVersion: "2.4-report.1",
    missionId: fixture.missionId,
    runId: fixture.runId,
    reportVersion: fixture.reportVersion,
    idempotent: true,
  });
  expect(generation.sourceSnapshotHash).toMatch(/^[a-f0-9]{64}$/u);
  expect(generation.artifacts).toHaveLength(2);
  expect(generation.artifacts.map((artifact) => artifact.id).sort()).toEqual([
    fixture.jsonArtifactId,
    fixture.markdownArtifactId,
  ].sort());
  expect(generation.artifacts.map((artifact) => artifact.format).sort()).toEqual(["json", "markdown"]);

  const generatedStatus = page.getByRole("status").filter({ hasText: "Both files represent the same canonical snapshot" });
  await expect(generatedStatus).toContainText(`Version ${fixture.reportVersion} is ready.`);
  const markdownLink = page.getByRole("link", { name: "Download Markdown", exact: true });
  const jsonLink = page.getByRole("link", { name: "Download JSON", exact: true });
  await expect(markdownLink).toBeVisible();
  await expect(jsonLink).toBeVisible();
  await attachScreenshot(page, testInfo, "canonical-report-generated");

  const downloadedBodies = new Map<string, Buffer>();
  for (const artifact of generation.artifacts) {
    const direct = await audit.request(page.request, {
      method: "GET",
      url: artifact.downloadUrl,
    });
    const body = await assertInertHeaders(direct, artifact);
    downloadedBodies.set(artifact.id, body);
    await downloadThroughLink(
      page,
      audit,
      artifact.format === "markdown" ? markdownLink : jsonLink,
      artifact,
      body,
    );
  }

  const selectedArtifact = generation.artifacts.find((artifact) => artifact.format === "markdown");
  if (!selectedArtifact) throw new Error("Canonical report response omitted its Markdown artifact");
  const detailResponse = page.waitForResponse((response) => (
    response.request().method() === "GET"
      && new URL(response.url()).pathname === `/api/v2/reports/${selectedArtifact.id}`
  ));
  await page.getByRole("link", {
    name: `Open report mission_report_markdown (${selectedArtifact.id})`,
    exact: true,
  }).click();
  expect((await detailResponse).status()).toBe(200);
  await expect(page).toHaveURL(`/reports/${selectedArtifact.id}`);
  await expect(page.getByRole("heading", { level: 2, name: "mission_report_markdown", exact: true })).toBeVisible();
  const detailDownload = page.getByRole("link", {
    name: `Download report v${fixture.reportVersion}`,
    exact: true,
  });
  await expect(detailDownload).toHaveAttribute("href", selectedArtifact.downloadUrl);
  await expect(page.getByText(selectedArtifact.contentHash, { exact: true })).toBeVisible();
  await attachScreenshot(page, testInfo, "canonical-report-detail");

  const reloadedDetail = page.waitForResponse((response) => (
    response.request().method() === "GET"
      && new URL(response.url()).pathname === `/api/v2/reports/${selectedArtifact.id}`
  ));
  await audit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.reload({ waitUntil: "domcontentloaded" }),
  );
  expect((await reloadedDetail).status()).toBe(200);
  await expect(page.getByRole("heading", { level: 2, name: "mission_report_markdown", exact: true })).toBeVisible();
  await expect(page.getByRole("link", {
    name: `Download report v${fixture.reportVersion}`,
    exact: true,
  })).toHaveAttribute("href", selectedArtifact.downloadUrl);
  const selectedBody = downloadedBodies.get(selectedArtifact.id);
  if (!selectedBody) throw new Error("The generated Markdown bytes were not retained for detail verification");
  await downloadThroughLink(
    page,
    audit,
    page.getByRole("link", {
      name: `Download report v${fixture.reportVersion}`,
      exact: true,
    }),
    selectedArtifact,
    selectedBody,
    `/reports/${selectedArtifact.id}`,
  );
  expect(audit.unexpected, "No console, required-network, or browser defects may remain").toEqual([]);
  expect(audit.degradedApi, "The canonical report route must remain fully available").toEqual([]);
  await audit.assertClean(testInfo);
});

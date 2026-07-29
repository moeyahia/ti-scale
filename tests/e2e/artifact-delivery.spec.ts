import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, test, type APIResponse, type Page, type Response } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import { sameUrlWrongPageDownloadCanary } from "./support/browserAuditNegativeCanary";
import {
  createArtifactDeliveryFixture,
  readArtifactDownloadAudits,
  type ArtifactDeliveryFixture,
} from "./support/artifactDeliveryFixture";
import { E2E_VAULT_ROOT } from "./support/environment";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const VERIFIED_DOWNLOAD = "e2e.intelligence.artifact-verified-download";
const DELIVERY_RECONCILIATION = "e2e.intelligence.artifact-delivery-reconciliation";
let fixture: ArtifactDeliveryFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createArtifactDeliveryFixture(canonicalFixtureNamespace(testInfo, "artifact-delivery"));
});

function artifactRoute(artifactId: string): string {
  return `/intelligence/artifacts/${encodeURIComponent(artifactId)}`;
}

function downloadPath(artifactId: string): string {
  return `/api/v2/intelligence/artifacts/${encodeURIComponent(artifactId)}/download`;
}

function pathname(response: Response): string {
  return new URL(response.url()).pathname;
}

async function navigateToArtifact(page: Page, artifactId: string, audit: BrowserAudit): Promise<void> {
  const detail = page.waitForResponse((response) =>
    pathname(response) === `/api/v2/intelligence/artifacts/${artifactId}`
    && response.request().method() === "GET",
  );
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
    artifactRoute(artifactId),
    { waitUntil: "domcontentloaded" },
  ));
  expect((await detail).status()).toBe(200);
  await expect(page.getByRole("heading", { name: "obsidian_attachment", exact: true })).toBeVisible();
}

async function expectDownloadDenied(
  response: APIResponse,
  expectedCode: string,
  expectedCategory: string,
): Promise<void> {
  expect(response.status()).toBe(409);
  expect(response.headers()["content-type"]).toContain("application/json");
  const payload = await response.json() as {
    error: {
      code: string;
      category: string;
      humanMessage: string;
      remediation: string;
      traceId: string;
    };
  };
  expect(payload.error).toMatchObject({
    code: expectedCode,
    category: expectedCategory,
    humanMessage: expect.any(String),
    remediation: expect.any(String),
    traceId: expect.any(String),
  });
  const serialized = JSON.stringify(payload);
  expect(serialized).not.toContain(E2E_VAULT_ROOT);
  expect(serialized).not.toContain("vault-attachment://");
}

test(`${VERIFIED_DOWNLOAD} returns the exact integrity-verified browser attachment and audit`, async ({ page }, testInfo) => {
  const canonicalDownloadPath = downloadPath(fixture.readyArtifactId);
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    verifiedDownloadPaths: [canonicalDownloadPath],
  });
  await navigateToArtifact(page, fixture.readyArtifactId, audit);

  await expect(page.getByText("Verified delivery", { exact: true })).toBeVisible();
  const delivery = page.getByRole("region", { name: "Artifact content delivery", exact: true });
  await expect(delivery).toContainText("Content is eligible for a bounded integrity-verified download.");
  await expect(delivery).toContainText("1 visible verified evidence record supports this delivery boundary.");
  await expect(page.getByText(fixture.contentHash, { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Verified content-addressed local fixture attachment", exact: true })).toHaveAttribute(
    "href",
    `/intelligence/evidence/${fixture.readyEvidenceId}`,
  );

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  const downloadLink = page.getByRole("link", { name: "Download verified content", exact: true });
  await expect(downloadLink).toHaveAttribute("href", canonicalDownloadPath);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    downloadLink.click(),
  ]);
  await audit.verifyDownload(download, canonicalDownloadPath);
  expect(download.suggestedFilename()).toBe(`ti-scale-artifact-${fixture.readyArtifactId}.bin`);
  const retainedPath = await download.path();
  if (!retainedPath) throw new Error("Playwright did not retain the verified fixture attachment");
  const received = readFileSync(retainedPath);
  expect(received.equals(fixture.content)).toBe(true);
  expect(received.length).toBe(fixture.content.length);
  expect(createHash("sha256").update(received).digest("hex")).toBe(fixture.contentHash);
  await expect(page).toHaveURL(artifactRoute(fixture.readyArtifactId));

  const downloadAudits = readArtifactDownloadAudits([fixture.readyArtifactId]);
  expect(downloadAudits).toHaveLength(1);
  expect(downloadAudits[0]).toMatchObject({
    resourceId: fixture.readyArtifactId,
    actorId: "e2e-local-operator",
    reason: "Authorized operator downloaded verified canonical artifact content.",
    details: {
      storageScheme: "vault-attachment",
      contentHash: fixture.contentHash,
      byteSize: fixture.content.length,
      inertAttachment: true,
    },
  });
  expect(downloadAudits[0]?.recordHash).toMatch(/^[a-f0-9]{64}$/u);
  expect(JSON.stringify(downloadAudits)).not.toContain(E2E_VAULT_ROOT);
  await audit.assertClean(testInfo);
});

test("e2e.audit-boundary.wrong-page-download-negative-canary rejects the same successful URL without page-bound authority", async ({
  baseURL,
  browser,
  context,
}) => {
  if (!baseURL) throw new Error("The browser-audit canary requires the configured V2 base URL");
  const messages = await sameUrlWrongPageDownloadCanary(browser, baseURL, {
    attachmentPath: downloadPath(fixture.readyArtifactId),
    storageState: await context.storageState(),
    requireSuccessfulDownload: true,
  });
  expect(messages).toContainEqual(expect.stringContaining("Download was not prospectively declared for this page"));
});

test(`${DELIVERY_RECONCILIATION} fails closed for missing proof, quarantine, changed bytes, and cross-scope proof`, async ({ page, browserAudit }, testInfo) => {
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const deniedArtifacts = [
    { id: fixture.reconciliationArtifactId, receipt: "artifact.download.missing-proof" },
    { id: fixture.quarantinedArtifactId, receipt: "artifact.download.quarantined" },
    { id: fixture.crossScopeArtifactId, receipt: "artifact.download.cross-scope" },
    { id: fixture.hashMismatchArtifactId, receipt: "artifact.download.hash-mismatch" },
  ] as const;
  for (const entry of deniedArtifacts) browserAudit.expectHttpResponse(page, {
    id: entry.receipt,
    transport: "api-request",
    method: "GET",
    pathname: downloadPath(entry.id),
    query: {},
    status: 409,
    occurrences: 1,
    reason: "Prove this artifact delivery boundary fails closed exactly once.",
  });

  await navigateToArtifact(page, fixture.reconciliationArtifactId, audit);
  await expect(page.getByText("Reconciliation required", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Artifact content delivery", exact: true })).toContainText(
    "No visible verified evidence canonically links this artifact to the same mission and run.",
  );
  await expect(page.getByRole("link", { name: "Download verified content", exact: true })).toHaveCount(0);
  await expectDownloadDenied(
    await browserAudit.request(page.request, {
      method: "GET",
      url: downloadPath(fixture.reconciliationArtifactId),
      expectedResponseId: "artifact.download.missing-proof",
    }),
    "artifact_verified_evidence_required",
    "reconciliation_required",
  );

  await navigateToArtifact(page, fixture.quarantinedArtifactId, audit);
  await expect(page.getByText("Quarantined", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Artifact content delivery", exact: true })).toContainText(
    "This artifact is quarantined and cannot be delivered.",
  );
  await expect(page.getByRole("link", { name: "Download verified content", exact: true })).toHaveCount(0);
  await expectDownloadDenied(
    await browserAudit.request(page.request, {
      method: "GET",
      url: downloadPath(fixture.quarantinedArtifactId),
      expectedResponseId: "artifact.download.quarantined",
    }),
    "artifact_content_quarantined",
    "artifact_quarantined",
  );

  await navigateToArtifact(page, fixture.crossScopeArtifactId, audit);
  await expect(page.getByText("Reconciliation required", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Artifact content delivery", exact: true })).toContainText(
    "No visible verified evidence canonically links this artifact to the same mission and run.",
  );
  await expect(page.getByRole("region", { name: "Artifact content delivery", exact: true })).toContainText(
    "0 visible verified evidence records support this delivery boundary.",
  );
  await expect(page.getByRole("link", { name: "Download verified content", exact: true })).toHaveCount(0);
  await expectDownloadDenied(
    await browserAudit.request(page.request, {
      method: "GET",
      url: downloadPath(fixture.crossScopeArtifactId),
      expectedResponseId: "artifact.download.cross-scope",
    }),
    "artifact_verified_evidence_required",
    "reconciliation_required",
  );

  await navigateToArtifact(page, fixture.hashMismatchArtifactId, audit);
  await expect(page.getByText("Verified delivery", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Download verified content", exact: true })).toBeVisible();
  await expectDownloadDenied(
    await browserAudit.request(page.request, {
      method: "GET",
      url: downloadPath(fixture.hashMismatchArtifactId),
      expectedResponseId: "artifact.download.hash-mismatch",
    }),
    "artifact_integrity_reconciliation_required",
    "reconciliation_required",
  );

  const failedArtifactIds = [
    fixture.reconciliationArtifactId,
    fixture.quarantinedArtifactId,
    fixture.crossScopeArtifactId,
    fixture.hashMismatchArtifactId,
  ];
  expect(readArtifactDownloadAudits(failedArtifactIds)).toEqual([]);
  await audit.assertClean(testInfo);
});

// Literal identifiers keep static interaction-manifest coverage auditable.
void [VERIFIED_DOWNLOAD, DELIVERY_RECONCILIATION];

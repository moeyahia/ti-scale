import { expect, test, type Page } from "./support/playwright";
import {
  createAttackKnowledgePromotionFixture,
  readAttackKnowledgePromotionSnapshot,
  type AttackKnowledgePromotionFixture,
} from "./support/attackKnowledgePromotionFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_ID = "e2e.brain-inbox.attack-promotion";
let fixture: AttackKnowledgePromotionFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createAttackKnowledgePromotionFixture(
    canonicalFixtureNamespace(testInfo, "attack-knowledge-promotion"),
  );
});

function shortFingerprint(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-8)}`;
}

function bundleButton(page: Page, fingerprint: string) {
  return page.getByRole("button", {
    name: `Review operational hazard bundle ${shortFingerprint(fingerprint)}`,
    exact: true,
  });
}

test(`${TEST_ID} reviews only compiler-bound evidence and commits one immutable operator receipt`, async ({ page, browserAudit }) => {
  test.setTimeout(120_000);
  await page.goto("/brain/inbox", { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Attack Knowledge Promotion", exact: true })).toBeVisible();
  await expect(page.getByText("Exact resets attributable to this procedure", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Overall operator-reported reset minimum", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("At least 11", { exact: true }).first()).toBeVisible();
  await expect(page.getByText(/Context only\. This overall minimum is not silently assigned to this procedure\./u).first()).toBeVisible();

  const listRead = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET"
      && url.pathname === "/api/v2/brain/attack-knowledge/bundles"
      && url.searchParams.get("status") === "all";
  });
  await page.getByRole("button", { name: "Refresh promotion queue", exact: true }).click();
  const listResponse = await listRead;
  expect(listResponse.status()).toBe(200);
  const safeListPayload = await listResponse.text();
  expect(safeListPayload).not.toContain("ReaperTwo");
  expect(safeListPayload).not.toContain("10.129.39.191");
  expect(safeListPayload).not.toContain("/private/engagements");

  const blockedEvidenceRead = page.waitForResponse((response) =>
    response.request().method() === "GET"
    && new URL(response.url()).pathname.endsWith(`/${fixture.blockedBundleFingerprint}/evidence`));
  await bundleButton(page, fixture.blockedBundleFingerprint).click();
  expect((await blockedEvidenceRead).status()).toBe(200);
  await expect(page.getByText("No canonical evidence is bound to this bundle", { exact: true })).toBeVisible();
  await expect(page.getByText(/this review surface cannot create or repair bindings/u)).toBeVisible();
  const blockedPreviewResponse = page.waitForResponse((response) =>
    response.request().method() === "POST"
    && new URL(response.url()).pathname.endsWith(`/${fixture.blockedBundleFingerprint}/preview`));
  const blockedPreview = page.getByRole("button", { name: "Preview exact promotion", exact: true });
  await blockedPreview.focus();
  await page.keyboard.press("Enter");
  expect((await blockedPreviewResponse).status()).toBe(200);
  await expect(page.getByRole("alert").filter({ hasText: /promotion blocker/u })).toContainText("verification evidence missing");

  const readyEvidenceRead = page.waitForResponse((response) =>
    response.request().method() === "GET"
    && new URL(response.url()).pathname.endsWith(`/${fixture.bundleFingerprint}/evidence`));
  await bundleButton(page, fixture.bundleFingerprint).click();
  const readyEvidenceResponse = await readyEvidenceRead;
  expect(readyEvidenceResponse.status()).toBe(200);
  const privateEvidencePayload = await readyEvidenceResponse.json() as {
    items: Array<Record<string, unknown>>;
  };
  expect(privateEvidencePayload.items.map((item) => item.id)).toEqual([...fixture.evidenceIds]);
  expect(Object.keys(privateEvidencePayload.items[0]!).sort()).toEqual([
    "acquiredAt", "contentHash", "evidenceType", "id", "verificationState",
  ]);

  const evidenceControls = fixture.evidenceIds.map((id) => page.getByRole("checkbox", {
    name: new RegExp(`^Use verified evidence ${id.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}`),
  }));
  await evidenceControls[0]!.check();
  await evidenceControls[1]!.focus();
  await page.keyboard.press("Space");
  await expect(evidenceControls[0]!).toBeChecked();
  await expect(evidenceControls[1]!).toBeChecked();

  const previewRequest = page.waitForRequest((request) =>
    request.method() === "POST"
    && new URL(request.url()).pathname.endsWith(`/${fixture.bundleFingerprint}/preview`));
  const previewResponse = page.waitForResponse((response) =>
    response.request().method() === "POST"
    && new URL(response.url()).pathname.endsWith(`/${fixture.bundleFingerprint}/preview`));
  await page.getByRole("button", { name: "Preview exact promotion", exact: true }).click();
  expect((await previewRequest).postDataJSON()).toEqual({ verificationEvidenceIds: [...fixture.evidenceIds] });
  const preview = await previewResponse;
  expect(preview.status()).toBe(200);
  const previewPayload = await preview.json() as {
    ready: boolean;
    reviewHash: string;
    blockers: unknown[];
    review: { candidates: unknown[]; edges: unknown[]; verification: { evidence: unknown[] } };
  };
  expect(previewPayload.ready).toBe(true);
  expect(previewPayload.blockers).toEqual([]);
  expect(previewPayload.reviewHash).toMatch(/^[a-f0-9]{64}$/u);
  expect(previewPayload.review.candidates).toHaveLength(fixture.candidateCount);
  expect(previewPayload.review.verification.evidence).toHaveLength(2);
  const diff = page.getByRole("region", { name: "Exact promotion diff", exact: true });
  await expect(diff).toContainText(previewPayload.reviewHash);
  await expect(diff).toContainText("Canonical evidence: 2 selected; minimum 2.");

  const commit = page.getByRole("button", { name: "Promote verified attack knowledge", exact: true });
  await expect(commit).toBeDisabled();
  const acknowledgement = page.getByRole("checkbox", { name: /^I reviewed this exact diff and evidence set/u });
  await acknowledgement.focus();
  await page.keyboard.press("Space");
  await expect(acknowledgement).toBeChecked();
  await expect(commit).toBeEnabled();

  const promotionRequest = page.waitForRequest((request) =>
    request.method() === "POST"
    && new URL(request.url()).pathname.endsWith(`/${fixture.bundleFingerprint}/promote`));
  const promotionResponse = page.waitForResponse((response) =>
    response.request().method() === "POST"
    && new URL(response.url()).pathname.endsWith(`/${fixture.bundleFingerprint}/promote`));
  await commit.click();
  const representedRequest = await promotionRequest;
  expect(representedRequest.postDataJSON()).toEqual({
    expectedReviewHash: previewPayload.reviewHash,
    verificationEvidenceIds: [...fixture.evidenceIds],
  });
  expect(representedRequest.headers()["idempotency-key"]).toMatch(/.{8,200}/u);
  expect(representedRequest.headers()["x-ti-scale-csrf"]).toBeTruthy();
  const promoted = await promotionResponse;
  expect(promoted.status()).toBe(200);
  const receipt = await promoted.json() as {
    status: string;
    receiptId: string;
    reviewHash: string;
    auditRecordId: string;
    edgeIds: string[];
  };
  expect(receipt).toMatchObject({ status: "materialized", reviewHash: previewPayload.reviewHash });
  expect(receipt.edgeIds.length).toBeGreaterThan(0);
  const receiptRegion = page.getByRole("status").filter({ hasText: "Immutable operator receipt" });
  await expect(receiptRegion).toContainText(receipt.receiptId);
  await expect(receiptRegion).toContainText(receipt.auditRecordId);

  const arbitraryId = `evidence-unbound-${fixture.namespace}`;
  const expectedUnboundEvidence = browserAudit.expectHttpResponse(page, {
    id: "attack-knowledge-promotion.reject-unbound-evidence",
    transport: "api-request",
    method: "POST",
    pathname: `/api/v2/brain/attack-knowledge/bundles/${fixture.blockedBundleFingerprint}/preview`,
    query: {},
    status: 400,
    occurrences: 1,
    reason: "Prove the authenticated API rejects an evidence ID that was never compiler-bound to the selected bundle.",
  });
  const csrf = (await page.context().cookies()).find(({ name }) => name === "ti_scale_csrf")?.value;
  expect(csrf).toBeTruthy();
  const rejected = await browserAudit.request(page.request, {
    method: "POST",
    url: `/api/v2/brain/attack-knowledge/bundles/${fixture.blockedBundleFingerprint}/preview`,
    expectedResponseId: expectedUnboundEvidence,
    options: {
      headers: { "X-Ti-Scale-CSRF": csrf! },
      data: { verificationEvidenceIds: [arbitraryId] },
    },
  });
  expect(rejected.status()).toBe(400);
  expect(await rejected.json()).toMatchObject({ error: { code: "promotion_evidence_not_bound" } });

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  const snapshot = readAttackKnowledgePromotionSnapshot(fixture);
  expect(snapshot).toMatchObject({
    bundleStatus: "materialized",
    receiptCount: 1,
    promotionAuditCount: 1,
    verifiedNodeCount: fixture.candidateCount,
  });
  expect(snapshot.verifiedEdgeCount).toBeGreaterThan(0);
  expect(snapshot.reusableText).not.toContain("ReaperTwo");
  expect(snapshot.reusableText).not.toContain("10.129.39.191");
  expect(snapshot.reusableText).not.toContain("/private/engagements");

  await browserAudit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.reload({ waitUntil: "domcontentloaded" }),
  );
  const persistedBundle = bundleButton(page, fixture.bundleFingerprint).locator("xpath=..");
  await expect(persistedBundle.getByRole("region", { name: "Immutable promotion receipt summary", exact: true })).toContainText(receipt.receiptId);
  await expect(persistedBundle).toContainText(previewPayload.reviewHash);
});

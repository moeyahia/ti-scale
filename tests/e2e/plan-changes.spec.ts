import { expect, test, type Locator, type Page, type Response } from "./support/playwright";
import { readFileSync } from "node:fs";
import { validateInteractionManifest, type InteractionManifestEntry } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createPlanChangeFixture,
  readPlanChangeFixtureSnapshot,
  refreshPlanChangeFixtureAgents,
  repairPlanChangeHistory,
  type PlanChangeFixture,
} from "./support/planChangeFixture";

const TEST_ID = "e2e.plan-changes";
const CREATE_EDIT_APPLY_TEST_ID = "e2e.plan-changes.create-edit-apply";
const BLOCKED_APPLY_TEST_ID = "e2e.plan-changes.blocked-apply";
const REJECT_TEST_ID = "e2e.plan-changes.reject";
const RETRY_TEST_ID = "e2e.plan-changes.retry";
const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

const PLAN_CHANGE_IDS = [
  "plan-change.create.reason",
  "plan-change.create.strategy",
  "plan-change.create.submit",
  "plan-change.retry",
  "plan-change.impact-disclosures",
  "plan-change.edit.strategy",
  "plan-change.edit.submit",
  "plan-change.apply",
  "plan-change.reject.reason",
  "plan-change.reject.submit",
] as const;

type PlanChangeManifestId = typeof PLAN_CHANGE_IDS[number];
type RoleScope = Pick<Page, "getByRole"> | Pick<Locator, "getByRole">;

interface PlanChangeResponseBody {
  readonly schemaVersion: "2.4";
  readonly request: {
    readonly id: string;
    readonly status: string;
    readonly version: number;
    readonly basePlanId: string;
    readonly structuredDiff: readonly { readonly path: string }[];
    readonly inflightImpact: {
      readonly safeToApply: boolean;
      readonly requiresCheckpoint: boolean;
      readonly requiresCancellation: boolean;
      readonly reasons: readonly string[];
    };
  };
  readonly resultPlanId?: string;
  readonly resultPlanVersion?: number;
}

const COVERAGE = {
  "safe create, review, edit, and apply": [
    "plan-change.create.reason",
    "plan-change.create.strategy",
    "plan-change.create.submit",
    "plan-change.impact-disclosures",
    "plan-change.edit.strategy",
    "plan-change.edit.submit",
    "plan-change.apply",
  ],
  "blocked apply state": ["plan-change.apply", "plan-change.reject.reason"],
  "explicit rejection": ["plan-change.reject.reason", "plan-change.reject.submit"],
  "strict-history retry": ["plan-change.retry"],
} satisfies Record<string, readonly PlanChangeManifestId[]>;

function entry(id: PlanChangeManifestId): InteractionManifestEntry {
  const candidate = manifest.entries.find((item) => item.id === id);
  if (!candidate) throw new Error(`Interaction manifest entry ${id} is missing`);
  return candidate;
}

function control(scope: RoleScope, id: PlanChangeManifestId): Locator {
  const item = entry(id);
  if (!item.accessible.role) throw new Error(`Interaction manifest entry ${id} is not role-addressable`);
  const name = item.accessible.match === "regex"
    ? new RegExp(item.accessible.name)
    : item.accessible.name;
  return scope.getByRole(item.accessible.role, {
    name,
    exact: item.accessible.match === "exact",
  });
}

function route(fixture: PlanChangeFixture): string {
  return `/missions/${encodeURIComponent(fixture.missionId)}/runs/${encodeURIComponent(fixture.runId)}?tab=plan`;
}

function endpoint(fixture: PlanChangeFixture): string {
  return `/api/v2/runs/${encodeURIComponent(fixture.runId)}/plan-changes`;
}

function isResponse(response: Response, pathname: string, method: string): boolean {
  return new URL(response.url()).pathname === pathname && response.request().method() === method;
}

async function responseBody(response: Response, expectedStatus: number): Promise<PlanChangeResponseBody> {
  expect(response.status(), await response.text()).toBe(expectedStatus);
  expect(response.headers()["idempotency-replayed"]).toBe("false");
  return response.json() as Promise<PlanChangeResponseBody>;
}

async function openPlan(page: Page, fixture: PlanChangeFixture): Promise<void> {
  await page.goto(route(fixture), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { level: 1, name: fixture.missionName, exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { level: 2, name: "Plan change requests", exact: true })).toBeVisible();
  await expect(page.locator(".os-plan-change-create")).toBeVisible();
}

async function createProposal(
  page: Page,
  fixture: PlanChangeFixture,
  rationale: string,
  strategySummary: string,
): Promise<PlanChangeResponseBody> {
  const reason = control(page, "plan-change.create.reason");
  const strategy = control(page, "plan-change.create.strategy");
  const submit = control(page, "plan-change.create.submit");
  await expect(reason).toBeVisible();
  await expect(strategy).toHaveValue(fixture.strategySummary);
  await expect(submit).toBeDisabled();

  await reason.focus();
  await expect(reason).toBeFocused();
  await reason.fill(rationale);
  await strategy.focus();
  await expect(strategy).toBeFocused();
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.type(strategySummary);
  await expect(strategy).toHaveValue(strategySummary);
  await expect(submit).toBeEnabled();

  refreshPlanChangeFixtureAgents(fixture);
  const pending = page.waitForResponse((response) => isResponse(response, endpoint(fixture), "POST"));
  await submit.focus();
  await expect(submit).toBeFocused();
  await page.keyboard.press("Enter");
  const response = await pending;
  const body = await responseBody(response, 201);
  expect(response.request().postDataJSON()).toEqual({
    basePlanId: fixture.planId,
    expectedRunVersion: fixture.runVersion,
    expectedPlanVersion: fixture.planVersion,
    requestText: rationale,
    operations: [{ kind: "update_plan", strategySummary }],
  });
  expect(body).toMatchObject({
    schemaVersion: "2.4",
    request: {
      basePlanId: fixture.planId,
      version: 1,
      structuredDiff: [{ path: "strategySummary" }],
    },
  });
  await expect(page.getByRole("region", { name: `Exact diff for ${body.request.id}` })).toBeVisible();
  return body;
}

function proposalCard(page: Page, requestId: string): Locator {
  return page.locator(".os-plan-change-card").filter({ hasText: `Proposal ${requestId}` });
}

test.describe(`${TEST_ID} canonical versioned plan-change browser coverage`, () => {
  test.describe.configure({ mode: "serial" });
  test.setTimeout(90_000);

  test(`${CREATE_EDIT_APPLY_TEST_ID} covers seven manifested controls with a real immutable plan activation`, async ({ page, browserAudit }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const fixture = createPlanChangeFixture(
      "queued_apply",
      canonicalFixtureNamespace(testInfo, CREATE_EDIT_APPLY_TEST_ID),
    );
    await testInfo.attach("plan-change-manifest-coverage.json", {
      body: Buffer.from(JSON.stringify({
        expectedEntryCount: 10,
        entries: PLAN_CHANGE_IDS,
        scenarios: COVERAGE,
      }, null, 2)),
      contentType: "application/json",
    });
    expect(manifest.entries.filter((item) => PLAN_CHANGE_IDS.includes(item.id as PlanChangeManifestId)).map((item) => item.id)).toEqual(PLAN_CHANGE_IDS);

    await openPlan(page, fixture);
    const created = await createProposal(
      page,
      fixture,
      "Prior evidence narrowed the represented scope, so the plan should emphasize attributable HTTPS observations.",
      "Correlate represented scope facts, then validate only attributable HTTPS evidence",
    );
    expect(created.request).toMatchObject({ status: "validated", inflightImpact: { safeToApply: true } });
    const card = proposalCard(page, created.request.id);
    await expect(card).toContainText("Safe pre-execution boundary");
    await expect(card).toContainText("Duration and provider cost are not observed; no estimate is fabricated.");

    // Chromium exposes native <details>/<summary> as a group/generic pair,
    // while the existing manifest audit normalizes <summary> to button. Use
    // the native summary for real keyboard coverage and report that manifest
    // matcher limitation rather than changing product or manifest scope here.
    expect(entry("plan-change.impact-disclosures").accessible).toMatchObject({
      role: "button",
      name: "Structured interpretation and impact",
    });
    const impact = card.locator("summary").filter({ hasText: "Structured interpretation and impact" });
    await impact.focus();
    await expect(impact).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(impact.locator("xpath=..")).toHaveAttribute("open", "");
    await expect(impact.locator("xpath=..")).toContainText('"safeToApply": true');
    await expect(impact.locator("xpath=..")).toContainText('"durationEstimate": "not_observed"');

    const revision = control(card, "plan-change.edit.strategy");
    const save = control(card, "plan-change.edit.submit");
    const revisedSummary = "Validate represented scope facts before preserving attributable HTTPS and DNS evidence";
    await revision.focus();
    await expect(revision).toBeFocused();
    await page.keyboard.press("ControlOrMeta+A");
    await page.keyboard.type(revisedSummary);
    const editPath = `${endpoint(fixture)}/${encodeURIComponent(created.request.id)}`;
    refreshPlanChangeFixtureAgents(fixture);
    const editedPending = page.waitForResponse((response) => isResponse(response, editPath, "PUT"));
    await save.focus();
    await expect(save).toBeFocused();
    await page.keyboard.press("Enter");
    const editedResponse = await editedPending;
    const edited = await responseBody(editedResponse, 200);
    expect(editedResponse.request().postDataJSON()).toMatchObject({
      expectedRequestVersion: 1,
      expectedRunVersion: 1,
      expectedPlanVersion: 1,
      operations: [{ kind: "update_plan", strategySummary: revisedSummary }],
    });
    expect(edited.request).toMatchObject({ status: "validated", version: 2 });
    await expect(proposalCard(page, created.request.id)).toContainText("Proposal version2");

    const refreshedCard = proposalCard(page, created.request.id);
    const apply = control(refreshedCard, "plan-change.apply");
    await expect(apply).toBeEnabled();
    const applyPath = `${editPath}/apply`;
    refreshPlanChangeFixtureAgents(fixture);
    const appliedPending = page.waitForResponse((response) => isResponse(response, applyPath, "POST"));
    await apply.focus();
    await expect(apply).toBeFocused();
    await page.keyboard.press("Enter");
    const appliedResponse = await appliedPending;
    const applied = await responseBody(appliedResponse, 200);
    expect(appliedResponse.request().postDataJSON()).toEqual({
      expectedRequestVersion: 2,
      expectedRunVersion: 1,
      expectedPlanVersion: 1,
    });
    expect(applied).toMatchObject({
      resultPlanVersion: 2,
      request: { status: "applied", version: 3 },
    });
    await expect(proposalCard(page, created.request.id)).toContainText("Applied as plan:");
    await expect(proposalCard(page, created.request.id)).toContainText(applied.resultPlanId!);
    await expect(control(page, "plan-change.create.strategy")).toHaveValue(revisedSummary);
    await expect(control(page, "plan-change.create.submit")).toBeDisabled();

    const persisted = readPlanChangeFixtureSnapshot(fixture);
    expect(persisted.run).toMatchObject({
      status: "queued",
      currentPlanId: applied.resultPlanId,
      version: 2,
      replanCount: 1,
      leaseOwner: null,
    });
    expect(persisted.plans).toEqual([
      expect.objectContaining({ id: fixture.planId, version: 1, status: "superseded" }),
      expect.objectContaining({ id: applied.resultPlanId, version: 2, status: "active", strategySummary: revisedSummary }),
    ]);
    expect(persisted.requests).toEqual([
      expect.objectContaining({ id: created.request.id, status: "applied", version: 3, resultPlanId: applied.resultPlanId }),
    ]);
    expect(persisted.actionCount).toBe(0);
    expect(persisted.assignmentStates).toContain("cancelled");
    expect(persisted.assignmentStates).toContain("queued");
    expect(persisted.assignmentStates).not.toContain("active");

    const plansResponse = await browserAudit.request(page.request, {
      method: "GET",
      url: `/api/v2/runs/${encodeURIComponent(fixture.runId)}/plans`,
    });
    expect(plansResponse.status(), await plansResponse.text()).toBe(200);
    const plansPayload = await plansResponse.json() as { items: Array<{ id: string; version: number; status: string }> };
    expect(plansPayload.items).toContainEqual(expect.objectContaining({ id: applied.resultPlanId, version: 2, status: "active" }));
    await audit.assertClean(testInfo);
  });

  test(`${BLOCKED_APPLY_TEST_ID} explains live-work impact and cannot be keyboard-activated`, async ({ page }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const fixture = createPlanChangeFixture(
      "running",
      canonicalFixtureNamespace(testInfo, BLOCKED_APPLY_TEST_ID),
    );
    await openPlan(page, fixture);
    const created = await createProposal(
      page,
      fixture,
      "Record the proposed refinement without interrupting the represented specialist.",
      "Preserve the active observation, then correlate only attributable service evidence",
    );
    expect(created.request).toMatchObject({
      status: "proposed",
      inflightImpact: {
        safeToApply: false,
        requiresCheckpoint: true,
        requiresCancellation: true,
      },
    });
    expect(created.request.inflightImpact.reasons.join(" ")).toContain(fixture.workerId);

    const card = proposalCard(page, created.request.id);
    await expect(card.getByRole("status")).toContainText("This proposal cannot be applied yet");
    await expect(card.getByRole("status")).toContainText("Run status running is not a safe pre-execution amendment state.");
    await expect(card.getByRole("status")).toContainText("Started work has no durable checkpoint for an amendment boundary.");
    const apply = control(card, "plan-change.apply");
    await expect(apply).toBeDisabled();

    const save = control(card, "plan-change.edit.submit");
    const rejectionReason = control(card, "plan-change.reject.reason");
    await expect(save).toBeDisabled();
    await apply.focus();
    await expect(apply).not.toBeFocused();
    await rejectionReason.focus();
    await expect(rejectionReason).toBeFocused();
    let applyRequests = 0;
    page.on("request", (request) => {
      if (new URL(request.url()).pathname.endsWith(`/${created.request.id}/apply`)) applyRequests += 1;
    });
    await page.keyboard.press("Enter");
    await expect.poll(() => applyRequests).toBe(0);

    const persisted = readPlanChangeFixtureSnapshot(fixture);
    expect(persisted.run).toEqual({
      status: "running",
      currentPlanId: fixture.planId,
      version: 2,
      replanCount: 0,
      leaseOwner: fixture.workerId,
    });
    expect(persisted.plans).toEqual([
      expect.objectContaining({ id: fixture.planId, version: 1, status: "active" }),
    ]);
    expect(persisted.requests).toEqual([
      expect.objectContaining({ id: created.request.id, status: "proposed", version: 1, resultPlanId: null }),
    ]);
    expect(persisted.actionCount).toBe(0);
    expect(persisted.assignmentStates).toEqual(["active"]);
    await audit.assertClean(testInfo);
  });

  test(`${REJECT_TEST_ID} records the operator reason without changing plan or execution`, async ({ page }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const fixture = createPlanChangeFixture(
      "queued_reject",
      canonicalFixtureNamespace(testInfo, REJECT_TEST_ID),
    );
    await openPlan(page, fixture);
    const created = await createProposal(
      page,
      fixture,
      "Evaluate a narrower strategy while preserving the existing represented plan.",
      "Review attributable DNS evidence before considering the narrower service hypothesis",
    );
    const card = proposalCard(page, created.request.id);
    const reason = control(card, "plan-change.reject.reason");
    const reject = control(card, "plan-change.reject.submit");
    await expect(reject).toBeDisabled();
    const rejection = "Keep the original represented strategy until a new verified observation exists.";
    await reason.focus();
    await expect(reason).toBeFocused();
    await reason.fill(rejection);
    await expect(reject).toBeEnabled();

    const rejectPath = `${endpoint(fixture)}/${encodeURIComponent(created.request.id)}/reject`;
    const rejectedPending = page.waitForResponse((response) => isResponse(response, rejectPath, "POST"));
    await reject.focus();
    await expect(reject).toBeFocused();
    await page.keyboard.press("Enter");
    const rejectedResponse = await rejectedPending;
    const rejected = await responseBody(rejectedResponse, 200);
    expect(rejectedResponse.request().postDataJSON()).toEqual({ expectedRequestVersion: 1, reason: rejection });
    expect(rejected.request).toMatchObject({ status: "rejected", version: 2 });
    await expect(proposalCard(page, created.request.id)).toContainText("Rejected: the base plan and execution state were not changed.");

    const persisted = readPlanChangeFixtureSnapshot(fixture);
    expect(persisted.run).toEqual({
      status: "queued",
      currentPlanId: fixture.planId,
      version: 1,
      replanCount: 0,
      leaseOwner: null,
    });
    expect(persisted.plans).toEqual([
      expect.objectContaining({ id: fixture.planId, version: 1, status: "active", strategySummary: fixture.strategySummary }),
    ]);
    expect(persisted.requests).toEqual([
      expect.objectContaining({ id: created.request.id, status: "rejected", version: 2, resultPlanId: null }),
    ]);
    expect(persisted.actionCount).toBe(0);
    expect(persisted.assignmentStates).toEqual(["queued"]);
    await audit.assertClean(testInfo);
  });

  test(`${RETRY_TEST_ID} recovers strict response parsing through the real history endpoint`, async ({ page }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const fixture = createPlanChangeFixture(
      "corrupt_history",
      canonicalFixtureNamespace(testInfo, RETRY_TEST_ID),
    );
    await openPlan(page, fixture);
    const alert = page.getByRole("alert").filter({ hasText: "Plan proposals are unavailable" });
    await expect(alert).toBeVisible();
    await expect(alert).toContainText("Ti-Scale received data it could not safely interpret.");
    await expect(alert).toContainText("Check that the web client and server are running compatible versions.");
    const retry = control(alert, "plan-change.retry");
    await expect(retry).toBeVisible();

    repairPlanChangeHistory(fixture);
    const pending = page.waitForResponse((response) => isResponse(response, endpoint(fixture), "GET"));
    await retry.focus();
    await expect(retry).toBeFocused();
    await page.keyboard.press("Enter");
    const response = await pending;
    expect(response.status(), await response.text()).toBe(200);
    await expect(alert).toBeHidden();
    await expect(proposalCard(page, fixture.corruptRequestId!)).toBeVisible();
    await expect(proposalCard(page, fixture.corruptRequestId!)).toContainText("validated");

    const persisted = readPlanChangeFixtureSnapshot(fixture);
    expect(persisted.requests).toEqual([
      expect.objectContaining({ id: fixture.corruptRequestId, status: "validated", version: 1 }),
    ]);
    expect(persisted.actionCount).toBe(0);
    await audit.assertClean(testInfo);
  });
});

import { expect, test, type Locator, type Page, type Response, type TestInfo } from "./support/playwright";
import { readFileSync } from "node:fs";
import { validateInteractionManifest, type InteractionManifestEntry } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createPlanChangeFixture,
  readPlanChangeFixtureSnapshot,
  refreshPlanChangeFixtureAgents,
  repairPlanChangeHistory,
  settlePlanChangeInflightWork,
  type PlanChangeFixture,
} from "./support/planChangeFixture";
import type { InteractionActivationInput } from "./support/interactionActivationFixture";

const TEST_ID = "e2e.plan-changes";
const CREATE_EDIT_APPLY_TEST_ID = "e2e.plan-changes.create-edit-apply";
const BLOCKED_APPLY_TEST_ID = "e2e.plan-changes.blocked-apply";
const REJECT_TEST_ID = "e2e.plan-changes.reject";
const RETRY_TEST_ID = "e2e.plan-changes.retry";
const RESTORE_TEST_ID = "e2e.plan-changes.version-restore";
const RESTORE_CONFLICT_TEST_ID = "e2e.plan-changes.version-restore-conflict";
const RESTORE_INITIAL_FAILURE_TEST_ID = "e2e.plan-changes.version-history-initial-failure";
const RESTORE_STALE_TEST_ID = "e2e.plan-changes.version-history-stale";
const RESTORE_RESPONSIVE_TEST_ID = "e2e.plan-changes.version-restore-responsive";
const INFLIGHT_RESOLUTION_TEST_ID = "e2e.plan-changes.inflight-resolution";
const VISUAL_PROJECT = "chromium-1440";
const RESTORE_VISUALS = {
  comparison: {
    id: "visual.plan-change.version-comparison.chromium-1440",
    snapshot: "plan-version-comparison.png",
  },
  validatedDiff: {
    id: "visual.plan-change.validated-restore-diff.chromium-1440",
    snapshot: "plan-version-validated-restore-diff.png",
  },
} as const;
const INFLIGHT_VISUALS = {
  decision: {
    id: "visual.plan-change.inflight-decision.chromium-1440",
    snapshot: "plan-change-inflight-decision.png",
  },
  waiting: {
    id: "visual.plan-change.inflight-waiting.chromium-1440",
    snapshot: "plan-change-inflight-waiting.png",
  },
} as const;
const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

const PLAN_CHANGE_IDS = [
  "plan-change.create.reason",
  "plan-change.create.strategy",
  "plan-change.create.submit",
  "plan-change.version-history.select",
  "plan-change.version-history.reason",
  "plan-change.version-history.prepare",
  "plan-change.version-history.retry",
  "plan-change.retry",
  "plan-change.impact-disclosures",
  "plan-change.edit.strategy",
  "plan-change.edit.submit",
  "plan-change.apply",
  "plan-change.reject.reason",
  "plan-change.reject.submit",
  "plan-change.inflight.reason",
  "plan-change.inflight.finish",
  "plan-change.inflight.cancel",
  "plan-change.inflight.refresh",
  "plan-change.inflight.finalize",
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

interface PlanChangeInflightResponseBody {
  readonly schemaVersion: "2.4";
  readonly resolution: {
    readonly id: string;
    readonly status: "waiting_for_terminal_work" | "ready_for_review" | "failed";
    readonly mode: "checkpoint_finish_idempotent_work" | "checkpoint_cancel_affected_work";
    readonly version: number;
    readonly sourceCheckpointId: string;
    readonly freshRequestId: string | null;
  } | null;
  readonly request?: {
    readonly id: string;
    readonly status: string;
    readonly version: number;
  };
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
  "reviewed immutable version rollback": [
    "plan-change.version-history.select",
    "plan-change.version-history.reason",
    "plan-change.version-history.prepare",
    "plan-change.apply",
  ],
  "initial plan-history failure and retry": ["plan-change.version-history.retry"],
  "exact in-flight amendment settlement": [
    "plan-change.inflight.reason",
    "plan-change.inflight.finish",
    "plan-change.inflight.cancel",
    "plan-change.inflight.refresh",
    "plan-change.inflight.finalize",
  ],
} satisfies Record<string, readonly PlanChangeManifestId[]>;

function entry(id: PlanChangeManifestId): InteractionManifestEntry {
  const candidate = manifest.entries.find((item) => item.id === id);
  if (!candidate) throw new Error(`Interaction manifest entry ${id} is missing`);
  return candidate;
}

function activation(
  manifestEntryId: PlanChangeManifestId,
  option: string,
  modality: "pointer" | "keyboard",
): InteractionActivationInput {
  const item = entry(manifestEntryId);
  if (!item.options.includes(option)) {
    throw new Error(`Interaction manifest entry ${manifestEntryId} does not declare ${option}`);
  }
  if (!item.testIds.includes(INFLIGHT_RESOLUTION_TEST_ID)) {
    throw new Error(`Interaction manifest entry ${manifestEntryId} does not declare ${INFLIGHT_RESOLUTION_TEST_ID}`);
  }
  return {
    manifestEntryId,
    controlId: item.controlId,
    option,
    materialState: item.requiredState,
    modality,
    testId: INFLIGHT_RESOLUTION_TEST_ID,
  };
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

function deferred(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

async function expectApprovedRestoreVisual(
  locator: Locator,
  testInfo: TestInfo,
  baseline: (typeof RESTORE_VISUALS)[keyof typeof RESTORE_VISUALS],
): Promise<void> {
  if (testInfo.project.name !== VISUAL_PROJECT) return;
  const page = locator.page();
  await page.evaluate(async () => { await document.fonts.ready; });
  const viewport = page.viewportSize();
  if (viewport) await page.mouse.move(viewport.width - 1, viewport.height - 1);
  await locator.locator(".os-status").evaluateAll((nodes) => {
    for (const node of nodes) {
      const status = node as HTMLElement;
      for (const animation of status.getAnimations()) animation.finish();
      status.style.animation = "none";
      status.style.transform = "none";
    }
  });
  const stickyChrome = page.locator(
    ".os-topbar, .os-mission-workspace > .os-surface-tabs, .os-refresh-note",
  );
  const previousVisibility = await stickyChrome.evaluateAll((nodes) =>
    nodes.map((node) => (node as HTMLElement).style.visibility));
  await stickyChrome.evaluateAll((nodes) => {
    for (const node of nodes) {
      (node as HTMLElement).style.visibility = "hidden";
    }
  });
  try {
    await expect(locator).toHaveScreenshot(baseline.snapshot, {
      animations: "disabled",
      caret: "hide",
      maxDiffPixels: 0,
      threshold: 0.15,
    });
  } finally {
    await stickyChrome.evaluateAll((nodes, visibility) => {
      for (let index = 0; index < nodes.length; index += 1) {
        (nodes[index] as HTMLElement).style.visibility = visibility[index] ?? "";
      }
    }, previousVisibility);
  }
}

async function normalizeRestoreDiffVisual(diff: Locator): Promise<void> {
  await diff.locator("th small, code").evaluateAll((nodes) => {
    for (const node of nodes) {
      node.textContent = (node.textContent ?? "")
        .replace(/(?:mission|run|plan|step|agent|assignment|constraint)-plan-change-e2e-[A-Za-z0-9._-]+/gu, "stable-visual-record")
        .replace(/[a-z0-9][a-z0-9.-]*\.fixture\.test/giu, "approved-visual.fixture.test");
    }
  });
}

async function normalizeInflightVisual(surface: Locator): Promise<void> {
  await surface.evaluate((node) => {
    for (const status of node.querySelectorAll<HTMLElement>(".os-status")) {
      for (const animation of status.getAnimations()) animation.finish();
      status.style.animation = "none";
      status.style.transform = "none";
    }
    for (const detail of node.querySelectorAll<HTMLElement>(".os-plan-change-work-grid span")) {
      detail.textContent = (detail.textContent ?? "")
        .replace(/[a-z0-9][a-z0-9.-]*\.fixture\.test/giu, "approved-visual.fixture.test");
    }
    for (const checkpoint of node.querySelectorAll<HTMLElement>(".os-plan-change-resolution-status .os-mono")) {
      checkpoint.textContent = "checkpoint-approved-visual";
    }
    for (const paragraph of node.querySelectorAll<HTMLElement>(".os-plan-change-resolution-status p")) {
      if (paragraph.textContent?.startsWith("Bounded settlement deadline:")) {
        paragraph.textContent = "Bounded settlement deadline: Jul 24, 2099, 12:10 PM UTC.";
      }
    }
  });
}

async function expectInflightVisual(
  surface: Locator,
  testInfo: TestInfo,
  baseline: (typeof INFLIGHT_VISUALS)[keyof typeof INFLIGHT_VISUALS],
): Promise<void> {
  if (testInfo.project.name !== VISUAL_PROJECT) return;
  const page = surface.page();
  await page.evaluate(async () => { await document.fonts.ready; });
  const viewport = page.viewportSize();
  if (viewport) await page.mouse.move(viewport.width - 1, viewport.height - 1);
  await normalizeInflightVisual(surface);
  const stickyChrome = page.locator(
    ".os-topbar, .os-mission-workspace > .os-surface-tabs, .os-refresh-note",
  );
  const previousVisibility = await stickyChrome.evaluateAll((nodes) =>
    nodes.map((node) => (node as HTMLElement).style.visibility));
  await stickyChrome.evaluateAll((nodes) => {
    for (const node of nodes) {
      (node as HTMLElement).style.visibility = "hidden";
    }
  });
  try {
    await expect(surface).toHaveScreenshot(baseline.snapshot, {
      animations: "disabled",
      caret: "hide",
      maxDiffPixels: 0,
      threshold: 0.15,
    });
  } finally {
    await stickyChrome.evaluateAll((nodes, visibility) => {
      for (let index = 0; index < nodes.length; index += 1) {
        (nodes[index] as HTMLElement).style.visibility = visibility[index] ?? "";
      }
    }, previousVisibility);
  }
}

async function expectNoEssentialHorizontalOverflow(page: Page, surface: Locator): Promise<void> {
  const pageOverflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(pageOverflow).toBeLessThanOrEqual(1);
  const overflow = await surface.evaluate((node) => node.scrollWidth - node.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  const box = await surface.boundingBox();
  const viewport = page.viewportSize();
  expect(box).not.toBeNull();
  expect(viewport).not.toBeNull();
  if (box && viewport) {
    expect(box.x).toBeGreaterThanOrEqual(-1);
    expect(box.x + box.width).toBeLessThanOrEqual(viewport.width + 1);
  }
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
        expectedEntryCount: 19,
        entries: PLAN_CHANGE_IDS,
        scenarios: COVERAGE,
      }, null, 2)),
      contentType: "application/json",
    });
    expect(manifest.entries.filter((item) => PLAN_CHANGE_IDS.includes(item.id as PlanChangeManifestId)).map((item) => item.id)).toEqual(PLAN_CHANGE_IDS);

    await openPlan(page, fixture);
    const currentOnlyHistory = page.locator(".os-plan-version-history");
    await expect(currentOnlyHistory).toContainText("Current only");
    await expect(currentOnlyHistory).toContainText("No earlier plan version");
    await expect(currentOnlyHistory).toContainText("This run has only its current immutable plan.");
    await expect(control(page, "plan-change.version-history.select")).toHaveCount(0);
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

  test(`${RESTORE_TEST_ID} compares history and restores it only as a reviewed new version`, async ({ page }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const fixture = createPlanChangeFixture(
      "version_history",
      canonicalFixtureNamespace(testInfo, RESTORE_TEST_ID),
    );
    if (!fixture.historicalPlanV1Id || !fixture.historicalPlanV2Id) {
      throw new Error("Version-history fixture did not expose both immutable historical plans");
    }
    await openPlan(page, fixture);

    const history = page.locator(".os-plan-version-history");
    const selector = control(page, "plan-change.version-history.select");
    await expect(selector).toBeVisible();
    await expect(selector).toContainText("Plan v2");
    await expect(history).toContainText("History available");
    await expect(history).not.toContainText(fixture.historicalPlanV1Id);
    await expect(history).not.toContainText(fixture.historicalPlanV2Id);

    await selector.click();
    const optionLabels = await page.getByRole("option").evaluateAll((options) => options.map((option) => option.getAttribute("aria-label")));
    expect(optionLabels).toEqual([
      "Plan v2 · Correlate verified service evidence",
      "Plan v1 · Map the approved surface",
    ]);
    await page.keyboard.press("Escape");

    // Keyboard-select the nondefault older version and prove that the visible
    // comparison changes before any request exists.
    await selector.focus();
    await expect(selector).toBeFocused();
    await page.keyboard.press("Enter");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    await expect(selector).toBeFocused();
    await expect(selector).toContainText("Plan v1");
    await expect(page.getByRole("region", { name: "Plan v3 and plan v1 comparison", exact: true })).toContainText("Map the approved surface");

    // Pointer-select the other historical version and use that exact target
    // for the reviewed proposal below.
    await selector.click();
    await page.getByRole("option", { name: "Plan v2 · Correlate verified service evidence", exact: true }).click();
    await expect(selector).toContainText("Plan v2");
    const comparison = page.getByRole("region", { name: "Plan v3 and plan v2 comparison", exact: true });
    await expect(comparison).toContainText("Correlate verified service evidence");

    const reason = control(page, "plan-change.version-history.reason");
    const prepare = control(page, "plan-change.version-history.prepare");
    await expect(prepare).toBeDisabled();
    const rollbackReason = "Verified evidence disproved the current branch, so review the earlier evidence-correlation strategy again.";
    await reason.fill(rollbackReason);
    await expect(prepare).toBeEnabled();
    await expectApprovedRestoreVisual(history, testInfo, RESTORE_VISUALS.comparison);

    refreshPlanChangeFixtureAgents(fixture);
    const observed = deferred();
    const release = deferred();
    const delayedCreate = async (route: import("@playwright/test").Route) => {
      if (route.request().method() !== "POST") {
        await route.fallback();
        return;
      }
      observed.resolve();
      await release.promise;
      await route.continue();
    };
    await page.route(`**${endpoint(fixture)}`, delayedCreate);
    const createdPending = page.waitForResponse((response) => isResponse(response, endpoint(fixture), "POST"));
    const reconciledListPending = page.waitForResponse((response) => isResponse(response, endpoint(fixture), "GET"));
    await prepare.focus();
    await expect(prepare).toBeFocused();
    await page.keyboard.press("Enter");
    await observed.promise;
    const pendingPrepare = page.locator('[data-control-id="plan-version-rollback-prepare"]');
    await expect(pendingPrepare).toHaveText("Preparing reviewed rollback…");
    await expect(pendingPrepare).toBeDisabled();
    await expect(selector).toBeDisabled();
    await expect(selector).toHaveAttribute("aria-busy", "true");
    await expect(reason).toBeDisabled();
    await expect(reason).toHaveValue(rollbackReason);
    release.resolve();
    const createdResponse = await createdPending;
    const created = await responseBody(createdResponse, 201);
    const reconciledListResponse = await reconciledListPending;
    expect(reconciledListResponse.status(), await reconciledListResponse.text()).toBe(200);
    await page.unroute(`**${endpoint(fixture)}`, delayedCreate);
    expect(createdResponse.request().postDataJSON()).toEqual({
      basePlanId: fixture.planId,
      expectedRunVersion: fixture.runVersion,
      expectedPlanVersion: fixture.planVersion,
      requestText: rollbackReason,
      operations: [{ kind: "restore_plan_version", targetPlanId: fixture.historicalPlanV2Id, targetPlanVersion: 2 }],
    });
    expect(created.request).toMatchObject({ status: "validated", basePlanId: fixture.planId });
    const beforeApply = readPlanChangeFixtureSnapshot(fixture);
    expect(beforeApply.run.currentPlanId).toBe(fixture.planId);
    expect(beforeApply.plans).toEqual([
      expect.objectContaining({ id: fixture.historicalPlanV1Id, version: 1, status: "superseded" }),
      expect.objectContaining({ id: fixture.historicalPlanV2Id, version: 2, status: "superseded" }),
      expect.objectContaining({ id: fixture.planId, version: 3, status: "active" }),
    ]);
    expect(beforeApply.actionCount).toBe(0);

    let card = proposalCard(page, created.request.id);
    await expect(card).toContainText("Restore historical plan v2 as a new immutable version");
    await expect(card).toContainText("Historical snapshot:");
    await expect(card.getByRole("button", { name: /Edit structured proposal/u })).toHaveCount(0);
    const validatedDiff = card.locator(".os-plan-diff");
    await normalizeRestoreDiffVisual(validatedDiff);
    await expectApprovedRestoreVisual(validatedDiff, testInfo, RESTORE_VISUALS.validatedDiff);

    await audit.waitForPageApiSettlement(page);
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
    await expect(page.getByRole("heading", { level: 2, name: "Plan change requests", exact: true })).toBeVisible();
    card = proposalCard(page, created.request.id);
    await expect(card).toContainText("Historical snapshot:");
    await audit.waitForPageApiSettlement(page);
    await audit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.goto(route(fixture).replace("tab=plan", "tab=summary"), { waitUntil: "domcontentloaded" }),
    );
    await expect(page.locator(".os-mission-summary-grid")).toBeVisible();
    await audit.waitForPageApiSettlement(page);
    await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
    await expect(page.getByRole("region", { name: "Plan v3 and plan v2 comparison", exact: true })).toBeVisible();
    await audit.waitForPageApiSettlement(page);

    card = proposalCard(page, created.request.id);
    const apply = control(card, "plan-change.apply");
    await expect(apply).toBeEnabled();
    refreshPlanChangeFixtureAgents(fixture);
    const applyPath = `${endpoint(fixture)}/${encodeURIComponent(created.request.id)}/apply`;
    const appliedPending = page.waitForResponse((response) => isResponse(response, applyPath, "POST"));
    await apply.click();
    const appliedResponse = await appliedPending;
    const applied = await responseBody(appliedResponse, 200);
    expect(appliedResponse.request().postDataJSON()).toEqual({
      expectedRequestVersion: 1,
      expectedRunVersion: fixture.runVersion,
      expectedPlanVersion: fixture.planVersion,
    });
    expect(applied).toMatchObject({ resultPlanVersion: 4, request: { status: "applied" } });

    const afterApply = readPlanChangeFixtureSnapshot(fixture);
    expect(afterApply.run).toMatchObject({ currentPlanId: applied.resultPlanId, version: 2, replanCount: 1 });
    expect(afterApply.plans).toEqual([
      expect.objectContaining({ id: fixture.historicalPlanV1Id, version: 1, status: "superseded" }),
      expect.objectContaining({ id: fixture.historicalPlanV2Id, version: 2, status: "superseded" }),
      expect.objectContaining({ id: fixture.planId, version: 3, status: "superseded" }),
      expect.objectContaining({ id: applied.resultPlanId, version: 4, status: "active", strategySummary: "Correlate verified service evidence" }),
    ]);
    expect(afterApply.actionCount).toBe(0);
    await expect(page.locator(".os-plan-summary .os-eyebrow")).toContainText("Plan v4");
    await audit.waitForPageApiSettlement(page);
    await audit.assertClean(testInfo);
  });

  test(`${RESTORE_CONFLICT_TEST_ID} preserves the selected history and reason after one declared creation conflict`, async ({ page, browserAudit }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const fixture = createPlanChangeFixture(
      "version_history",
      canonicalFixtureNamespace(testInfo, RESTORE_CONFLICT_TEST_ID),
    );
    if (!fixture.historicalPlanV1Id) throw new Error("Version-history fixture did not expose plan v1");
    await openPlan(page, fixture);

    const selector = control(page, "plan-change.version-history.select");
    await selector.click();
    await page.getByRole("option", { name: "Plan v1 · Map the approved surface", exact: true }).click();
    const reason = control(page, "plan-change.version-history.reason");
    const prepare = control(page, "plan-change.version-history.prepare");
    const rollbackReason = "The latest interpretation conflicts with verified evidence, so preserve this exact comparison for review.";
    await reason.fill(rollbackReason);

    browserAudit.expectHttpResponse(page, {
      id: "plan-change.version-restore.expected-conflict",
      transport: "browser",
      method: "POST",
      pathname: endpoint(fixture),
      query: {},
      status: 409,
      occurrences: 1,
      reason: "Prove an optimistic rollback conflict preserves the local reviewed draft and execution state.",
    });
    let posted: unknown;
    const conflictRoute = async (route: import("@playwright/test").Route) => {
      if (route.request().method() !== "POST") {
        await route.fallback();
        return;
      }
      posted = route.request().postDataJSON();
      await route.fulfill({
        status: 409,
        contentType: "application/json; charset=utf-8",
        headers: { "X-Request-Id": "trace-plan-restore-conflict" },
        body: JSON.stringify({
          error: {
            code: "plan_change_version_conflict",
            message: "The active plan version changed before proposal creation",
            humanMessage: "The active plan changed before this rollback proposal could be prepared.",
            retryable: false,
            category: "conflict",
            remediation: "Refresh plan history, review the new comparison, and submit again.",
            traceId: "trace-plan-restore-conflict",
            timestamp: "2026-07-16T18:05:00.000Z",
          },
        }),
      });
    };
    await page.route(`**${endpoint(fixture)}`, conflictRoute);
    const failed = page.waitForResponse((response) => isResponse(response, endpoint(fixture), "POST") && response.status() === 409);
    await prepare.click();
    expect((await failed).status()).toBe(409);
    await page.unroute(`**${endpoint(fixture)}`, conflictRoute);

    expect(posted).toEqual({
      basePlanId: fixture.planId,
      expectedRunVersion: fixture.runVersion,
      expectedPlanVersion: fixture.planVersion,
      requestText: rollbackReason,
      operations: [{ kind: "restore_plan_version", targetPlanId: fixture.historicalPlanV1Id, targetPlanVersion: 1 }],
    });
    const alert = page.getByRole("alert").filter({ hasText: "Rollback proposal was not prepared" });
    await expect(alert).toContainText("The active plan changed before this rollback proposal could be prepared.");
    await expect(alert).toContainText("Refresh plan history, review the new comparison, and submit again.");
    await expect(alert).toContainText("Trace trace-plan-restore-conflict");
    await expect(selector).toContainText("Plan v1");
    await expect(reason).toHaveValue(rollbackReason);
    await expect(prepare).toBeEnabled();
    await expect(page.locator(".os-plan-summary .os-eyebrow")).toContainText("Plan v3");

    const persisted = readPlanChangeFixtureSnapshot(fixture);
    expect(persisted.run).toMatchObject({ currentPlanId: fixture.planId, version: fixture.runVersion, replanCount: 0 });
    expect(persisted.plans).toHaveLength(3);
    expect(persisted.plans.at(-1)).toMatchObject({ id: fixture.planId, version: 3, status: "active" });
    expect(persisted.requests).toEqual([]);
    expect(persisted.actionCount).toBe(0);
    await audit.assertClean(testInfo);
  });

  test(`${RESTORE_INITIAL_FAILURE_TEST_ID} explains and retries an initial canonical plan-history failure without rendering rollback controls`, async ({ page, browserAudit }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const fixture = createPlanChangeFixture(
      "version_history",
      canonicalFixtureNamespace(testInfo, RESTORE_INITIAL_FAILURE_TEST_ID),
    );
    const plansPath = `/api/v2/runs/${encodeURIComponent(fixture.runId)}/plans`;
    browserAudit.expectHttpResponse(page, {
      id: "plan-change.version-history.initial-unavailable",
      transport: "browser",
      method: "GET",
      pathname: plansPath,
      query: {},
      status: 503,
      occurrences: 1,
      reason: "Prove an initial canonical plan-history failure exposes precise remediation and no rollback authority.",
    });
    let failedOnce = false;
    const initialFailure = async (route: import("@playwright/test").Route) => {
      if (failedOnce || route.request().method() !== "GET") {
        await route.fallback();
        return;
      }
      failedOnce = true;
      await route.fulfill({
        status: 503,
        contentType: "application/json; charset=utf-8",
        headers: { "X-Request-Id": "trace-plan-history-initial" },
        body: JSON.stringify({
          error: {
            code: "plan_history_initial_unavailable",
            message: "The canonical plan history could not be loaded",
            humanMessage: "The current and historical plan versions could not be confirmed.",
            retryable: true,
            category: "dependency",
            remediation: "Retry the plan-history read before reviewing or preparing a rollback.",
            traceId: "trace-plan-history-initial",
            timestamp: "2026-07-16T18:04:00.000Z",
          },
        }),
      });
    };
    await page.route(`**${plansPath}`, initialFailure);
    await page.goto(route(fixture), { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1, name: fixture.missionName, exact: true })).toBeVisible();
    const alert = page.getByRole("alert").filter({ hasText: "Plan history is unavailable" });
    await expect(alert).toContainText("The current and historical plan versions could not be confirmed.");
    await expect(alert).toContainText("Retry the plan-history read before reviewing or preparing a rollback.");
    await expect(alert).toContainText("Trace trace-plan-history-initial");
    await expect(page.locator(".os-plan-version-history")).toHaveCount(0);
    await expect(control(page, "plan-change.version-history.select")).toHaveCount(0);
    await expect(control(page, "plan-change.version-history.reason")).toHaveCount(0);
    await expect(control(page, "plan-change.version-history.prepare")).toHaveCount(0);

    await page.unroute(`**${plansPath}`, initialFailure);
    const recovered = page.waitForResponse((response) => isResponse(response, plansPath, "GET") && response.status() === 200);
    const retry = control(alert, "plan-change.version-history.retry");
    await retry.focus();
    await expect(retry).toBeFocused();
    await page.keyboard.press("Enter");
    expect((await recovered).status()).toBe(200);
    await expect(alert).toHaveCount(0);
    await expect(page.getByRole("heading", { level: 2, name: "Plan change requests", exact: true })).toBeVisible();
    await expect(page.locator(".os-plan-version-history")).toContainText("History available");
    expect(readPlanChangeFixtureSnapshot(fixture).actionCount).toBe(0);
    await audit.assertClean(testInfo);
  });

  test(`${RESTORE_STALE_TEST_ID} fails closed while cached plan history refreshes and after that refresh fails`, async ({ page, browserAudit }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const fixture = createPlanChangeFixture(
      "version_history",
      canonicalFixtureNamespace(testInfo, RESTORE_STALE_TEST_ID),
    );
    await openPlan(page, fixture);
    await browserAudit.waitForPageApiSettlement(page);

    let history = page.locator(".os-plan-version-history");
    let selector = control(page, "plan-change.version-history.select");
    await expect(history).toContainText("History available");
    await expect(selector).toBeEnabled();
    const created = await createProposal(
      page,
      fixture,
      "Create one reviewed successor so the post-commit plan-history reconciliation boundary can be exercised.",
      "Retain verified service evidence before reviewing the next current hypothesis",
    );
    const apply = control(proposalCard(page, created.request.id), "plan-change.apply");
    await expect(apply).toBeEnabled();

    const plansPath = `/api/v2/runs/${encodeURIComponent(fixture.runId)}/plans`;
    browserAudit.expectHttpResponse(page, {
      id: "plan-change.version-history.cached-refresh-unavailable",
      transport: "browser",
      method: "GET",
      pathname: plansPath,
      query: {},
      status: 503,
      occurrences: 1,
      reason: "Prove cached plan history cannot authorize rollback during or after a failed canonical refresh.",
    });
    const observed = deferred();
    const release = deferred();
    const automaticRecoveryObserved = deferred();
    const releaseAutomaticRecovery = deferred();
    let failureDelivered = false;
    const failedRefresh = async (route: import("@playwright/test").Route) => {
      if (route.request().method() !== "GET") {
        await route.fallback();
        return;
      }
      if (failureDelivered) {
        automaticRecoveryObserved.resolve();
        await releaseAutomaticRecovery.promise;
        await route.continue();
        return;
      }
      observed.resolve();
      await release.promise;
      failureDelivered = true;
      await route.fulfill({
        status: 503,
        contentType: "application/json; charset=utf-8",
        headers: { "X-Request-Id": "trace-plan-history-refresh" },
        body: JSON.stringify({
          error: {
            code: "plan_history_refresh_unavailable",
            message: "The canonical plan projection could not refresh",
            humanMessage: "The latest plan history could not be confirmed.",
            retryable: true,
            category: "dependency",
            remediation: "Retry the plan-history read before preparing a rollback.",
            traceId: "trace-plan-history-refresh",
            timestamp: "2026-07-16T18:06:00.000Z",
          },
        }),
      });
    };
    await page.route(`**${plansPath}`, failedRefresh);
    refreshPlanChangeFixtureAgents(fixture);
    const applyPath = `${endpoint(fixture)}/${encodeURIComponent(created.request.id)}/apply`;
    const applied = page.waitForResponse((response) => isResponse(response, applyPath, "POST") && response.status() === 200);
    await apply.click();
    expect((await applied).status()).toBe(200);
    await observed.promise;

    history = page.locator(".os-plan-version-history");
    selector = control(page, "plan-change.version-history.select");
    await expect(history).toContainText("History stale");
    await expect(history).toContainText("Plan history is not current.");
    await expect(selector).toBeDisabled();
    await expect(control(page, "plan-change.version-history.reason")).toBeDisabled();
    await expect(control(page, "plan-change.version-history.prepare")).toBeDisabled();

    const failed = page.waitForResponse((response) => isResponse(response, plansPath, "GET") && response.status() === 503);
    release.resolve();
    expect((await failed).status()).toBe(503);
    await automaticRecoveryObserved.promise;
    await expect(history).toContainText("History stale");
    await expect(history).toContainText("cached history cannot authorize a restore");
    await expect(selector).toBeDisabled();
    await expect(page.locator(".os-plan-summary .os-eyebrow")).toContainText("Plan v3");
    expect(readPlanChangeFixtureSnapshot(fixture).actionCount).toBe(0);
    const recovered = page.waitForResponse((response) => isResponse(response, plansPath, "GET") && response.status() === 200);
    releaseAutomaticRecovery.resolve();
    expect((await recovered).status()).toBe(200);
    await page.unroute(`**${plansPath}`, failedRefresh);
    await audit.assertClean(testInfo);
  });

  test(`${RESTORE_RESPONSIVE_TEST_ID} keeps comparison, focus, and 44-pixel controls usable at 390px and 200% zoom`, async ({ page }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const fixture = createPlanChangeFixture(
      "version_history",
      canonicalFixtureNamespace(testInfo, RESTORE_RESPONSIVE_TEST_ID),
    );
    await openPlan(page, fixture);

    const history = page.locator(".os-plan-version-history");
    const selector = control(page, "plan-change.version-history.select");
    const selectorBox = await selector.boundingBox();
    expect(selectorBox?.height ?? 0).toBeGreaterThanOrEqual(44);
    if (testInfo.project.name.endsWith("390")) {
      await selector.tap();
      const option = page.getByRole("option", { name: "Plan v1 · Map the approved surface", exact: true });
      const optionBox = await option.boundingBox();
      expect(optionBox?.height ?? 0).toBeGreaterThanOrEqual(44);
      await option.tap();
    } else {
      await selector.focus();
      await expect(selector).toBeFocused();
      await page.keyboard.press("Enter");
      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("Enter");
    }
    await selector.focus();
    await expect(selector).toBeFocused();
    await expect(selector).toContainText("Plan v1");

    const reason = control(page, "plan-change.version-history.reason");
    await reason.fill("Responsive review keeps this exact historical comparison understandable and deliberate.");
    const prepare = control(page, "plan-change.version-history.prepare");
    const prepareBox = await prepare.boundingBox();
    expect(prepareBox?.height ?? 0).toBeGreaterThanOrEqual(44);
    await reason.focus();
    await expect(reason).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(prepare).toBeFocused();
    await expectNoEssentialHorizontalOverflow(page, history);
    await expect(page.getByRole("region", { name: "Plan v3 and plan v1 comparison", exact: true })).toBeVisible();
    await audit.assertClean(testInfo);
  });

  test(`${INFLIGHT_RESOLUTION_TEST_ID} checkpoints exact affected work and prepares only a fresh reviewed proposal`, async ({ page, interactionActivation }, testInfo) => {
    const scenarios = [
      {
        mode: "checkpoint_finish_idempotent_work" as const,
        entryId: "plan-change.inflight.finish" as const,
        option: "Fence dispatch and finish only the represented repeat-safe affected work",
        buttonName: "Checkpoint and finish repeat-safe work",
      },
      {
        mode: "checkpoint_cancel_affected_work" as const,
        entryId: "plan-change.inflight.cancel" as const,
        option: "Fence dispatch and stop only the represented affected work",
        buttonName: "Checkpoint and cancel affected work",
      },
    ];

    for (const [scenarioIndex, scenario] of scenarios.entries()) {
      for (const modality of ["pointer", "keyboard"] as const) {
        const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
        const fixture = createPlanChangeFixture(
          "inflight_resolution",
          canonicalFixtureNamespace(
            testInfo,
            `plan-change-inflight-${scenario.mode}-${modality}`,
          ),
        );
        await openPlan(page, fixture);
        const created = await createProposal(
          page,
          fixture,
          "Checkpoint the represented observation before reviewing the changed strategy.",
          "Correlate the completed observation before preparing any dependent work",
        );
        expect(created.request).toMatchObject({
          status: "proposed",
          inflightImpact: {
            safeToApply: false,
            requiresCheckpoint: true,
            requiresCancellation: true,
          },
        });
        const card = proposalCard(page, created.request.id);
        const surface = card.locator(".os-plan-change-resolution");
        await expect(surface).toContainText("Only work in the changed step and its dependent steps is affected.");
        await expect(surface).toContainText("Collect one attributable observation");
        await expect(surface).toContainText("No unrelated active actions.");

        const reason = control(surface, "plan-change.inflight.reason");
        const resolutionReason = `Use the ${scenario.mode} boundary for the exact represented work.`;
        await interactionActivation.activate(
          activation(
            "plan-change.inflight.reason",
            "Enter an audited reason of at least three characters",
            modality,
          ),
          async () => {
            if (modality === "pointer") await reason.click();
            else {
              await reason.focus();
              await expect(reason).toBeFocused();
            }
            await reason.fill(resolutionReason);
          },
        );

        const finish = control(surface, "plan-change.inflight.finish");
        const cancel = control(surface, "plan-change.inflight.cancel");
        await expect(finish).toBeEnabled();
        await expect(cancel).toBeEnabled();
        if (scenarioIndex === 0 && modality === "pointer") {
          await expectInflightVisual(surface, testInfo, INFLIGHT_VISUALS.decision);
        }

        refreshPlanChangeFixtureAgents(fixture);
        const resolvePath = `${endpoint(fixture)}/${encodeURIComponent(created.request.id)}/resolve-inflight`;
        const resolvedResponse = await interactionActivation.activate(
          activation(scenario.entryId, scenario.option, modality),
          async () => {
            const pending = page.waitForResponse((response) => isResponse(response, resolvePath, "POST"));
            const selected = surface.getByRole("button", { name: scenario.buttonName, exact: true });
            if (modality === "pointer") await selected.click();
            else {
              await selected.focus();
              await expect(selected).toBeFocused();
              await page.keyboard.press("Enter");
            }
            return pending;
          },
        );
        expect(resolvedResponse.status(), await resolvedResponse.text()).toBe(200);
        expect(resolvedResponse.headers()["idempotency-replayed"]).toBe("false");
        const resolved = await resolvedResponse.json() as PlanChangeInflightResponseBody;
        expect(resolved).toMatchObject({
          schemaVersion: "2.4",
          resolution: {
            mode: scenario.mode,
            status: "waiting_for_terminal_work",
          },
        });
        expect(resolvedResponse.request().postDataJSON()).toEqual({
          mode: scenario.mode,
          expectedRequestVersion: 1,
          expectedRunVersion: fixture.runVersion,
          expectedPlanVersion: fixture.planVersion,
          reason: resolutionReason,
        });
        const resolutionVersion = resolved.resolution?.version;
        if (!resolutionVersion) throw new Error("The in-flight resolution version is missing");

        await expect(surface).toContainText("Dispatch is fenced while work settles.");
        const refresh = control(surface, "plan-change.inflight.refresh");
        const finalize = control(surface, "plan-change.inflight.finalize");
        await expect(refresh).toBeEnabled();
        await expect(finalize).toBeEnabled();
        if (scenarioIndex === 0 && modality === "pointer") {
          await expectInflightVisual(surface, testInfo, INFLIGHT_VISUALS.waiting);
        }

        const resolutionPath = `${endpoint(fixture)}/${encodeURIComponent(created.request.id)}/inflight-resolution`;
        const refreshedResponse = await interactionActivation.activate(
          activation(
            "plan-change.inflight.refresh",
            "Read the canonical resolution ledger",
            modality,
          ),
          async () => {
            const pending = page.waitForResponse((response) => isResponse(response, resolutionPath, "GET"));
            if (modality === "pointer") await refresh.click();
            else {
              await refresh.focus();
              await expect(refresh).toBeFocused();
              await page.keyboard.press("Enter");
            }
            return pending;
          },
        );
        expect(refreshedResponse.status(), await refreshedResponse.text()).toBe(200);
        const refreshed = await refreshedResponse.json() as PlanChangeInflightResponseBody;
        expect(refreshed.resolution).toMatchObject({
          id: resolved.resolution?.id,
          status: "waiting_for_terminal_work",
          mode: scenario.mode,
        });
        await audit.waitForPageApiSettlement(page);

        if (scenario.mode === "checkpoint_finish_idempotent_work") {
          settlePlanChangeInflightWork(fixture);
        }
        refreshPlanChangeFixtureAgents(fixture);
        const finalizePath = `${resolutionPath}/finalize`;
        const finalizedResponse = await interactionActivation.activate(
          activation(
            "plan-change.inflight.finalize",
            "Revalidate and create one fresh immutable proposal",
            modality,
          ),
          async () => {
            const pending = page.waitForResponse((response) => isResponse(response, finalizePath, "POST"));
            if (modality === "pointer") await finalize.click();
            else {
              await finalize.focus();
              await expect(finalize).toBeFocused();
              await page.keyboard.press("Enter");
            }
            return pending;
          },
        );
        expect(finalizedResponse.status(), await finalizedResponse.text()).toBe(200);
        expect(finalizedResponse.headers()["idempotency-replayed"]).toBe("false");
        expect(finalizedResponse.request().postDataJSON()).toEqual({
          expectedResolutionVersion: resolutionVersion,
        });
        const finalized = await finalizedResponse.json() as PlanChangeInflightResponseBody;
        expect(finalized).toMatchObject({
          schemaVersion: "2.4",
          resolution: {
            status: "ready_for_review",
            mode: scenario.mode,
          },
          request: {
            status: "validated",
          },
        });
        expect(finalized.resolution?.freshRequestId).toBe(finalized.request?.id);
        const outcome = page.locator(".os-plan-change-inflight-outcome");
        await expect(outcome).toContainText("Fresh review is ready.");
        await expect(outcome).toContainText("It still requires exact review and apply.");
        await expect(outcome).toContainText(created.request.id);
        await expect(outcome).toContainText(finalized.request?.id ?? "");
        if (!finalized.request?.id) throw new Error("The fresh plan-change review ID is missing");
        await expect(proposalCard(page, finalized.request.id)).toContainText("validated");
        await expect(control(proposalCard(page, finalized.request.id), "plan-change.apply")).toBeEnabled();

        const persisted = readPlanChangeFixtureSnapshot(fixture);
        expect(persisted.run).toMatchObject({
          status: "blocked",
          currentPlanId: fixture.planId,
          replanCount: 0,
          leaseOwner: null,
        });
        expect(persisted.plans).toEqual([
          expect.objectContaining({ id: fixture.planId, version: 1, status: "active" }),
        ]);
        expect(persisted.requests).toEqual([
          expect.objectContaining({ id: created.request.id, status: "cancelled", version: 2 }),
          expect.objectContaining({ id: finalized.request.id, status: "validated", version: 1 }),
        ]);
        await audit.assertClean(testInfo);
      }
    }
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

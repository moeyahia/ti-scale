import { expect, test, type Locator, type Page, type Request, type TestInfo } from "./support/playwright";
import { readFileSync } from "node:fs";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import {
  advanceRunInterventionRecoveryVersion,
  createRunInterventionRecoveryFixture,
  readRunInterventionRecoverySnapshot,
  refreshRunInterventionRecoveryAttestations,
  type RunInterventionRecoveryFixture,
} from "./support/runInterventionRecoveryFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_CONTROL_PLANE = "e2e.run-intervention.control-plane-rejection";
const TEST_PAUSE_RESUME = "e2e.run-intervention.pause-resume-replay";
const TEST_CANCEL = "e2e.run-intervention.cancel-no-ghost";
const TEST_REPLAN = "e2e.run-recovery.replan-boundary-replay";
const TEST_REASSIGN_TERMINATE = "e2e.run-recovery.reassign-terminate";
const VISUAL_PROJECT = "chromium-1440";
const RECOVERY_VISUALS = {
  blocked: {
    id: "visual.run-recovery.structured-blocked.chromium-1440",
    snapshot: "run-recovery-structured-blocked.png",
  },
  waitingDecision: {
    id: "visual.guided.waiting-decision.chromium-1440",
    snapshot: "guided-waiting-decision.png",
  },
} as const;
const MANIFEST_IDS = [
  "run-intervention.reason",
  "run-intervention.pause",
  "run-intervention.cancel",
  "run-recovery.reason",
  "run-recovery.resume",
  "run-recovery.strategy",
  "run-recovery.replan",
  "run-recovery.specialist",
  "run-recovery.capability",
  "run-recovery.reassign",
  "run-recovery.change-provider",
  "run-recovery.terminate",
] as const;
const manifest = validateInteractionManifest(JSON.parse(
  readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8"),
) as unknown);

let legacyFixture: RunInterventionRecoveryFixture;
let pauseFixture: RunInterventionRecoveryFixture;
let cancelFixture: RunInterventionRecoveryFixture;
let replanFixture: RunInterventionRecoveryFixture;
let reassignFixture: RunInterventionRecoveryFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  legacyFixture = createRunInterventionRecoveryFixture(
    "legacy_control",
    canonicalFixtureNamespace(testInfo, "run-intervention-legacy-control"),
  );
  pauseFixture = createRunInterventionRecoveryFixture(
    "pause_resume",
    canonicalFixtureNamespace(testInfo, "run-intervention-pause-resume"),
  );
  cancelFixture = createRunInterventionRecoveryFixture(
    "cancel",
    canonicalFixtureNamespace(testInfo, "run-intervention-cancel"),
  );
  replanFixture = createRunInterventionRecoveryFixture(
    "replan",
    canonicalFixtureNamespace(testInfo, "run-recovery-replan"),
  );
  reassignFixture = createRunInterventionRecoveryFixture(
    "reassign",
    canonicalFixtureNamespace(testInfo, "run-recovery-reassign"),
  );
});

function liveRoute(fixture: RunInterventionRecoveryFixture): string {
  return `/live/${encodeURIComponent(fixture.runId)}`;
}

function runControlPath(fixture: RunInterventionRecoveryFixture, command: "pause" | "resume" | "cancel"): string {
  return `/api/v2/runs/${fixture.runId}/${command}`;
}

function recoveryMutationPath(
  fixture: RunInterventionRecoveryFixture,
  command: "replan" | "reassign" | "provider",
): string {
  return `/api/v2/operations/runs/${fixture.runId}/recovery/${command}`;
}

function pathOf(request: Request): string {
  return new URL(request.url()).pathname;
}

function interventionControls(page: Page): Locator {
  return page.locator(".os-run-controls");
}

function recoveryControls(page: Page): Locator {
  return page.locator(".os-recovery-panel");
}

async function normalizeRecoveryVisual(panel: Locator): Promise<void> {
  await panel.evaluate((node) => {
    for (const child of node.children) {
      const element = child as HTMLElement;
      const keep = element.classList.contains("os-card-heading")
        || element.classList.contains("os-recovery-summary")
        || element.classList.contains("os-recovery-proposal");
      if (!keep) element.style.display = "none";
    }
    const replacements: Record<string, string> = {
      "Current owner": "Recon specialist",
      "Current step": "step-approved-visual",
      "Lease expiry": "No active lease",
    };
    for (const row of node.querySelectorAll("dl > div")) {
      const label = row.querySelector("dt")?.textContent?.trim();
      const value = row.querySelector("dd");
      if (label && value && replacements[label]) value.textContent = replacements[label];
    }
    const decisionSummary = node.querySelector(".os-guided-recovery-decision p:last-child");
    if (decisionSummary) decisionSummary.textContent = "low risk · expires Jul 16, 2099, 12:30 PM UTC";
  });
}

async function restoreRecoveryVisual(panel: Locator): Promise<void> {
  await panel.evaluate((node) => {
    for (const child of node.children) (child as HTMLElement).style.removeProperty("display");
  });
}

async function normalizeWaitingDecisionVisual(statusBand: Locator): Promise<void> {
  await statusBand.locator(":scope > div").evaluateAll((items) => {
    const replacements: Record<string, string> = {
      Owner: "Recon specialist",
      Heartbeat: "Jul 16, 2099, 12:00 PM UTC",
    };
    for (const item of items) {
      const label = item.querySelector("span")?.textContent?.trim();
      const value = item.querySelector("strong");
      if (label && value && replacements[label]) value.textContent = replacements[label];
    }
  });
}

async function expectApprovedRecoveryVisual(
  panel: Locator,
  testInfo: TestInfo,
  baseline: (typeof RECOVERY_VISUALS)[keyof typeof RECOVERY_VISUALS],
): Promise<void> {
  if (testInfo.project.name !== VISUAL_PROJECT) return;
  await panel.page().evaluate(async () => { await document.fonts.ready; });
  await expect(panel).toHaveScreenshot(baseline.snapshot, {
    animations: "disabled",
    caret: "hide",
    maxDiffPixels: 0,
    threshold: 0.15,
  });
}

async function assertManifestControl(
  scope: Page | Locator,
  id: typeof MANIFEST_IDS[number],
  visible = true,
): Promise<void> {
  const entry = manifest.entries.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`Run intervention manifest entry ${id} is missing`);
  if (!("role" in entry.accessible) || !entry.accessible.role) {
    throw new Error(`Run intervention manifest entry ${id} is not role-addressable`);
  }
  const name = entry.accessible.match === "regex"
    ? new RegExp(entry.accessible.name)
    : entry.accessible.name;
  const locator = scope.getByRole(entry.accessible.role, {
    name,
    exact: entry.accessible.match === "exact",
  }).first();
  if (visible) await expect(locator).toBeVisible();
  else await expect(locator).toHaveCount(0);
}

async function mutationResponse(
  page: Page,
  pathname: string,
  action: () => Promise<void>,
) {
  const pending = page.waitForResponse((response) =>
    new URL(response.url()).pathname === pathname && response.request().method() === "POST");
  await action();
  return pending;
}

async function replayCapturedMutation(
  page: Page,
  audit: BrowserAudit,
  request: Request,
  expectedResponseId?: string,
): Promise<{
  readonly status: number;
  readonly body: unknown;
}> {
  const capturedUrl = new URL(request.url());
  const requestPath = `${capturedUrl.pathname}${capturedUrl.search}`;
  const headers = request.headers();
  const idempotencyKey = headers["idempotency-key"];
  const capturedCsrf = headers["x-ti-scale-csrf"];
  const contentType = headers["content-type"];
  const body = request.postData();
  expect(idempotencyKey).toBeTruthy();
  expect(capturedCsrf).toBeTruthy();
  expect(contentType).toContain("application/json");
  expect(body).toBeTruthy();
  const csrf = (await page.context().cookies(request.url()))
    .find((cookie) => cookie.name === "ti_scale_csrf");
  if (!csrf || csrf.value !== capturedCsrf) {
    throw new Error("The captured V2 mutation is not bound to the exact authenticated origin CSRF cookie");
  }
  const response = await audit.request(page.request, {
    method: "POST",
    url: requestPath,
    ...(expectedResponseId ? { expectedResponseId } : {}),
    options: {
      data: body,
      headers: {
        Accept: headers.accept ?? "application/json",
        "Content-Type": contentType!,
        "Idempotency-Key": idempotencyKey!,
        "X-Ti-Scale-CSRF": capturedCsrf!,
      },
    },
  });
  return { status: response.status(), body: await response.json() as unknown };
}

test(`${TEST_CONTROL_PLANE} refuses a legacy-owned run without creating V2 lease, event, checkpoint, or audit state`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: [{
      id: "run-control.legacy-owner.pause-denied",
      transport: "browser",
      method: "POST",
      pathname: runControlPath(legacyFixture, "pause"),
      query: {},
      status: 409,
      occurrences: 1,
      reason: "Prove server-enforced single-control-plane ownership.",
    }],
  });
  await page.goto(liveRoute(legacyFixture), { waitUntil: "domcontentloaded" });
  const controls = interventionControls(page);
  await assertManifestControl(controls, "run-intervention.reason");
  await assertManifestControl(controls, "run-intervention.pause");
  await controls.getByRole("textbox", { name: "Operator reason (audited)", exact: true })
    .fill("Verify the owning control plane rejects this intervention.");
  const response = await mutationResponse(page, runControlPath(legacyFixture, "pause"), async () => {
    await controls.getByRole("button", { name: "Pause run", exact: true }).click();
  });
  expect(response.status()).toBe(409);
  expect(await response.json()).toMatchObject({
    error: {
      code: "control_plane_control_plane_mismatch",
      humanMessage: "This run belongs to another control plane and Ti-Scale refused to mutate it.",
      remediation: "Open the run through its owning control plane; do not attempt concurrent control.",
    },
  });
  const alert = controls.getByRole("alert");
  await expect(alert).toContainText("This run belongs to another control plane and Ti-Scale refused to mutate it.");
  await expect(alert).toContainText("Open the run through its owning control plane; do not attempt concurrent control.");
  expect(readRunInterventionRecoverySnapshot(legacyFixture)).toMatchObject({
    run: { status: "running", version: 1, controlPlane: "legacy", leaseOwner: null },
    events: [],
    audits: [],
    checkpoints: [],
    runtimeIdempotencyCount: 0,
  });
  await expect(page.getByLabel("Selected run status")).toContainText("running");
  await audit.assertClean(testInfo);
});

test(`${TEST_PAUSE_RESUME} pauses and resumes from the exact durable checkpoint with idempotent replay and refresh persistence`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
  });
  await page.goto(liveRoute(pauseFixture), { waitUntil: "domcontentloaded" });
  const controls = interventionControls(page);
  await assertManifestControl(controls, "run-intervention.reason");
  await assertManifestControl(controls, "run-intervention.pause");
  const pause = controls.getByRole("button", { name: "Pause run", exact: true });
  await expect(pause).toBeDisabled();
  await controls.getByRole("textbox", { name: "Operator reason (audited)", exact: true })
    .fill("Pause at the next durable operator checkpoint.");
  const pausedResponse = await mutationResponse(page, runControlPath(pauseFixture, "pause"), async () => {
    await pause.focus();
    await page.keyboard.press("Enter");
  });
  expect(pausedResponse.status()).toBe(200);
  const pausedBody = await pausedResponse.json();
  expect(pausedBody).toMatchObject({ run: { id: pauseFixture.runId, status: "blocked" } });
  const afterPause = readRunInterventionRecoverySnapshot(pauseFixture);
  expect(afterPause.run).toMatchObject({ status: "blocked", controlPlane: "ti_scale", leaseOwner: null });
  expect(afterPause.missionStatus).toBe("paused");
  expect(afterPause.stepStatuses).toEqual(["waiting_guided_decision"]);
  expect(afterPause.assignments).toEqual([{
    id: pauseFixture.assignmentId,
    agentId: pauseFixture.agentId,
    status: "blocked",
    leaseOwner: null,
  }]);
  expect(afterPause.decisionStatuses).toEqual(["pending"]);
  expect(afterPause.approvalStatuses).toEqual([]);
  expect(afterPause.executingChildCount).toBe(0);
  expect(afterPause.durableRunLeaseActive).toBe(false);
  expect(afterPause.activeControlPlaneLeaseCount).toBe(0);
  expect(afterPause.events.some((event) => event.type === "run.state_changed")).toBe(true);
  expect(afterPause.audits).toEqual([
    { action: "run.paused", reason: "Pause at the next durable operator checkpoint." },
  ]);
  expect(afterPause.checkpoints.length).toBeGreaterThan(0);
  expect(afterPause.checkpoints.every((checkpoint) => checkpoint.planVersion === 1 && checkpoint.stateHashVerified)).toBe(true);
  expect(afterPause.checkpoints.at(-1)?.inFlightCount).toBe(0);
  expect(afterPause.runtimeIdempotencyCount).toBe(1);

  await audit.waitForPageApiSettlement(page);
  const replay = await replayCapturedMutation(page, audit, pausedResponse.request());
  expect(replay).toEqual({ status: 200, body: pausedBody });
  expect(readRunInterventionRecoverySnapshot(pauseFixture)).toEqual(afterPause);

  const recovery = recoveryControls(page);
  await expect(recovery.getByRole("heading", { name: "Guided recovery needs your decision", exact: true })).toBeVisible();
  await expect(recovery.getByText("Plan version", { exact: true })).toBeVisible();
  await expect(recovery.getByText("In-flight actions", { exact: true })).toBeVisible();
  await assertManifestControl(recovery, "run-recovery.reason");
  await assertManifestControl(recovery, "run-recovery.resume");
  await normalizeRecoveryVisual(recovery);
  await expectApprovedRecoveryVisual(recovery, testInfo, RECOVERY_VISUALS.blocked);
  await restoreRecoveryVisual(recovery);
  await recovery.getByRole("textbox", { name: "Operator reason (audited)", exact: true })
    .fill("Resume only the persisted exact Guided checkpoint.");
  const resumedResponse = await mutationResponse(page, runControlPath(pauseFixture, "resume"), async () => {
    await recovery.getByRole("button", { name: "Resume from checkpoint", exact: true }).click();
  });
  expect(resumedResponse.status()).toBe(200);
  const resumeRequest = resumedResponse.request().postDataJSON() as Record<string, unknown>;
  const sourceCheckpoint = afterPause.checkpoints.at(-1)!;
  expect(resumeRequest).toMatchObject({
    expectedRunVersion: afterPause.run.version,
    expectedRunStatus: "blocked",
    expectedCheckpointId: sourceCheckpoint.id,
    expectedCheckpointStateHash: sourceCheckpoint.stateHash,
    expectedCheckpointEventSequence: sourceCheckpoint.eventSequence,
  });
  const resumedBody = await resumedResponse.json();
  expect(resumedBody).toMatchObject({
    run: { id: pauseFixture.runId, status: "waiting_guided_decision", currentStepId: pauseFixture.stepId },
  });
  await audit.waitForPageApiSettlement(page);
  const resumedReplay = await replayCapturedMutation(page, audit, resumedResponse.request());
  expect(resumedReplay).toEqual({ status: 200, body: resumedBody });
  // Resume invalidates the mounted run, plan, observability, and notification
  // projections. Prove those authoritative reads finish before deliberately
  // replacing the document so the refresh cannot mask a failed reconciliation
  // as an expected navigation cancellation.
  await audit.waitForPageApiSettlement(page);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  const waitingBand = page.getByLabel("Selected run status");
  await expect(waitingBand).toContainText("waiting guided decision");
  await normalizeWaitingDecisionVisual(waitingBand);
  await expectApprovedRecoveryVisual(waitingBand, testInfo, RECOVERY_VISUALS.waitingDecision);
  const afterResume = readRunInterventionRecoverySnapshot(pauseFixture);
  expect(afterResume.run).toMatchObject({ status: "waiting_guided_decision", leaseOwner: null });
  expect(afterResume.missionStatus).toBe("active");
  expect(afterResume.stepStatuses).toEqual(["waiting_guided_decision"]);
  expect(afterResume.assignments).toEqual([{
    id: pauseFixture.assignmentId,
    agentId: pauseFixture.agentId,
    status: "queued",
    leaseOwner: null,
  }]);
  expect(afterResume.decisionStatuses).toEqual(["pending"]);
  expect(afterResume.executingChildCount).toBe(0);
  expect(afterResume.durableRunLeaseActive).toBe(false);
  expect(afterResume.activeControlPlaneLeaseCount).toBe(0);
  expect(afterResume.audits).toEqual([
    { action: "run.paused", reason: "Pause at the next durable operator checkpoint." },
    { action: "run.resumed", reason: "Resume only the persisted exact Guided checkpoint." },
  ]);
  expect(afterResume.checkpoints.length).toBeGreaterThan(afterPause.checkpoints.length);
  expect(afterResume.checkpoints.every((checkpoint) => checkpoint.stateHashVerified)).toBe(true);
  expect(afterResume.runtimeIdempotencyCount).toBe(2);
  await audit.assertClean(testInfo);
});

test(`${TEST_CANCEL} cancels all durable child work, checkpoints zero in-flight work, replays idempotently, and survives refresh`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
  });
  await page.goto(liveRoute(cancelFixture), { waitUntil: "domcontentloaded" });
  const controls = interventionControls(page);
  await assertManifestControl(controls, "run-intervention.cancel");
  const before = readRunInterventionRecoverySnapshot(cancelFixture);
  expect(before.activeChildCount).toBeGreaterThanOrEqual(5);
  await controls.getByRole("textbox", { name: "Operator reason (audited)", exact: true })
    .fill("Terminate the disposable fixture and close every child record.");
  const cancelledResponse = await mutationResponse(page, runControlPath(cancelFixture, "cancel"), async () => {
    await controls.getByRole("button", { name: "Cancel run", exact: true }).click();
  });
  expect(cancelledResponse.status()).toBe(200);
  const cancelledBody = await cancelledResponse.json();
  expect(cancelledBody).toMatchObject({ run: { id: cancelFixture.runId, status: "cancelled" } });
  const afterCancel = readRunInterventionRecoverySnapshot(cancelFixture);
  expect(afterCancel.run).toMatchObject({ status: "cancelled", leaseOwner: null, leaseExpiresAt: null });
  expect(afterCancel.missionStatus).toBe("cancelled");
  expect(afterCancel.planStatuses).toEqual(["abandoned"]);
  expect(afterCancel.stepStatuses).toEqual(["cancelled"]);
  expect(afterCancel.assignments.map((assignment) => assignment.status)).toEqual(["cancelled"]);
  expect(afterCancel.assignments.every((assignment) => assignment.leaseOwner === null)).toBe(true);
  expect(afterCancel.actionStatuses).toEqual(["cancelled"]);
  expect(afterCancel.toolCallStatuses).toEqual(["cancelled"]);
  expect(afterCancel.decisionStatuses).toEqual(["cancelled"]);
  expect(afterCancel.approvalStatuses).toEqual(["cancelled"]);
  expect(afterCancel.providerTurnStatuses).toEqual(["cancelled"]);
  expect(afterCancel.runtimeContinuationStatuses.length).toBeGreaterThanOrEqual(2);
  expect(afterCancel.runtimeContinuationStatuses.every((status) =>
    status === "cancelled" || status === "completed")).toBe(true);
  expect(afterCancel.executingChildCount).toBe(0);
  expect(afterCancel.durableRunLeaseActive).toBe(false);
  expect(afterCancel.activeControlPlaneLeaseCount).toBe(0);
  expect(afterCancel.activeChildCount).toBe(0);
  expect(afterCancel.events.some((event) => event.type === "run.cancellation_requested")).toBe(true);
  expect(afterCancel.events.some((event) => event.type === "run.cancelled")).toBe(true);
  expect(afterCancel.audits).toContainEqual({
    action: "run.cancelled",
    reason: "Terminate the disposable fixture and close every child record.",
  });
  expect(afterCancel.checkpoints.length).toBeGreaterThanOrEqual(2);
  expect(afterCancel.checkpoints.every((checkpoint) => checkpoint.stateHashVerified)).toBe(true);
  expect(afterCancel.checkpoints.at(-1)?.inFlightCount).toBe(0);
  expect(afterCancel.runtimeIdempotencyCount).toBe(1);

  await audit.waitForPageApiSettlement(page);
  const replay = await replayCapturedMutation(page, audit, cancelledResponse.request());
  expect(replay).toEqual({ status: 200, body: cancelledBody });
  expect(readRunInterventionRecoverySnapshot(cancelFixture)).toEqual(afterCancel);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByLabel("Selected run status")).toContainText("cancelled");
  await expect(page.getByText("Mission completion review", { exact: true })).toBeVisible();
  expect(readRunInterventionRecoverySnapshot(cancelFixture).activeChildCount).toBe(0);
  await audit.assertClean(testInfo);
});

test(`${TEST_REPLAN} rejects a stale boundary, persists one bounded replan, then rejects replay after fail-closed progression`, async ({ page }, testInfo) => {
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: [
      {
        id: "run-recovery.replan-stale-boundary",
        transport: "browser",
        method: "POST",
        pathname: recoveryMutationPath(replanFixture, "replan"),
        query: {},
        status: 409,
        occurrences: 1,
        reason: "Prove a stale exact recovery boundary fails closed in the represented browser interaction.",
      },
      {
        id: "run-recovery.replan-progressed-replay",
        transport: "api-request",
        method: "POST",
        pathname: recoveryMutationPath(replanFixture, "replan"),
        query: {},
        status: 409,
        occurrences: 1,
        reason: "Prove the exact idempotency key cannot replay after fail-closed runtime progression.",
      },
    ],
  });
  await page.goto(liveRoute(replanFixture), { waitUntil: "domcontentloaded" });
  const recovery = recoveryControls(page);
  await assertManifestControl(recovery, "run-recovery.strategy");
  await assertManifestControl(recovery, "run-recovery.replan");
  const staleCheckpoint = readRunInterventionRecoverySnapshot(replanFixture).checkpoints.at(-1)!;
  const staleVersion = advanceRunInterventionRecoveryVersion(replanFixture);
  expect(staleVersion).toBe(2);
  const advancedCheckpoint = readRunInterventionRecoverySnapshot(replanFixture).checkpoints.at(-1)!;
  expect(advancedCheckpoint.id).not.toBe(staleCheckpoint.id);
  expect(advancedCheckpoint.stateHash).not.toBe(staleCheckpoint.stateHash);
  expect(advancedCheckpoint.stateHashVerified).toBe(true);
  await recovery.getByRole("textbox", { name: "Materially different in-scope strategy", exact: true })
    .fill("Correlate the retained timeout with a different passive source before any retry.");
  const staleResponse = await mutationResponse(page, recoveryMutationPath(replanFixture, "replan"), async () => {
    await recovery.getByRole("button", { name: "Request bounded replan", exact: true }).click();
  });
  expect(staleResponse.status()).toBe(409);
  expect(await staleResponse.json()).toMatchObject({
    error: {
      humanMessage: "The run, plan, step, or assignment changed before the recovery mutation could be applied.",
      remediation: "Refresh the Recovery Panel and retry only against the current exact work boundary.",
    },
  });
  const alert = recovery.getByRole("alert");
  await expect(alert).toContainText("The run, plan, step, or assignment changed before the recovery mutation could be applied.");
  await expect(alert).toContainText("Refresh the Recovery Panel and retry only against the current exact work boundary.");
  expect(readRunInterventionRecoverySnapshot(replanFixture)).toMatchObject({
    run: { status: "blocked", version: 2 },
    audits: [],
    recoveryIdempotencyCount: 0,
  });

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  const refreshedRecovery = recoveryControls(page);
  const strategy = "Correlate the retained timeout with an independent passive source before any retry.";
  await refreshedRecovery.getByRole("textbox", { name: "Materially different in-scope strategy", exact: true })
    .fill(strategy);
  const acceptedResponse = await mutationResponse(page, recoveryMutationPath(replanFixture, "replan"), async () => {
    await refreshedRecovery.getByRole("button", { name: "Request bounded replan", exact: true }).click();
  });
  expect(acceptedResponse.status()).toBe(200);
  const acceptedBody = await acceptedResponse.json();
  expect(acceptedBody).toMatchObject({
    mutation: { kind: "replan", checkpointId: expect.any(String), continuationId: expect.any(String) },
    run: {
      id: replanFixture.runId,
      status: "recovering",
      planId: replanFixture.planId,
      planVersion: 1,
      stepId: replanFixture.stepId,
      assignmentId: replanFixture.assignmentId,
    },
  });
  // The response is the immutable projection of the committed recovery
  // boundary. A targeted continuation wake may advance canonical state before
  // this test process can observe the transient `recovering` row, so prove the
  // boundary through its returned version, event, and hash-verified checkpoint
  // rather than requiring a scheduler-dependent intermediate snapshot.
  expect(acceptedBody.run.version).toBeGreaterThan(staleVersion);

  // The managed release server wakes only this run's durable continuation; it
  // does not re-enable the ambient runnable-run scanner. Its deliberately
  // unavailable fixture planner must consume the persisted replan once and
  // fail closed.
  await expect.poll(() => {
    const snapshot = readRunInterventionRecoverySnapshot(replanFixture);
    return {
      runStatus: snapshot.run.status,
      stepStatuses: snapshot.stepStatuses,
      assignmentStatuses: snapshot.assignments.map((assignment) => assignment.status),
      replanStarted: snapshot.events.some((event) => event.type === "run.replan_started"),
      guidedBlocked: snapshot.events.some((event) => event.type === "run.guided_blocked"),
    };
  }, { timeout: 7_500 }).toEqual({
    runStatus: "blocked",
    stepStatuses: ["failed"],
    assignmentStatuses: ["failed"],
    replanStarted: true,
    guidedBlocked: true,
  });
  const afterUnavailablePlanner = readRunInterventionRecoverySnapshot(replanFixture);
  expect(afterUnavailablePlanner.run.statusReason).toContain("isolated test boundary");
  expect(afterUnavailablePlanner.run.version).toBeGreaterThan(acceptedBody.run.version);
  expect(afterUnavailablePlanner.stepStatuses).toEqual(["failed"]);
  expect(afterUnavailablePlanner.assignments.map((assignment) => assignment.status)).toEqual(["failed"]);
  expect(afterUnavailablePlanner.actionStatuses).toEqual(["timed_out"]);
  expect(afterUnavailablePlanner.events.some((event) => event.type === "run.replan_started")).toBe(true);
  expect(afterUnavailablePlanner.events.some((event) => event.type === "run.guided_blocked")).toBe(true);
  expect(afterUnavailablePlanner.audits).toContainEqual({ action: "run.replan_requested", reason: strategy });
  expect(afterUnavailablePlanner.events.some((event) => event.type === "run.operator_replan_requested")).toBe(true);
  expect(afterUnavailablePlanner.checkpoints).toContainEqual(expect.objectContaining({
    id: acceptedBody.mutation.checkpointId,
    planVersion: 1,
    stateHashVerified: true,
    inFlightCount: 0,
  }));
  expect(afterUnavailablePlanner.recoveryIdempotencyCount).toBe(1);
  await audit.waitForPageApiSettlement(page);
  const progressedReplay = await replayCapturedMutation(
    page,
    audit,
    acceptedResponse.request(),
    "run-recovery.replan-progressed-replay",
  );
  expect(progressedReplay).toMatchObject({
    status: 409,
    body: { error: { code: "recovery_idempotent_replay_stale", retryable: false } },
  });
  expect(readRunInterventionRecoverySnapshot(replanFixture)).toEqual(afterUnavailablePlanner);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByLabel("Selected run status")).toContainText("blocked");
  await audit.assertClean(testInfo);
});

test(`${TEST_REASSIGN_TERMINATE} reassigns only the exact stopped assignment, declares provider routing unavailable, then terminates with no ghost-active state`, async ({ page }, testInfo) => {
  refreshRunInterventionRecoveryAttestations(reassignFixture);
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
  });
  await page.goto(liveRoute(reassignFixture), { waitUntil: "domcontentloaded" });
  const recovery = recoveryControls(page);
  await assertManifestControl(recovery, "run-recovery.reason");
  await assertManifestControl(recovery, "run-recovery.specialist");
  await assertManifestControl(recovery, "run-recovery.capability");
  await assertManifestControl(recovery, "run-recovery.reassign");
  await assertManifestControl(recovery, "run-recovery.change-provider");
  const provider = recovery.getByRole("button", { name: "Change provider", exact: true });
  await expect(provider).toBeDisabled();
  await expect(provider.locator("xpath=ancestor::li[1]")).toContainText("No healthy callable provider satisfies the journey and budget enforcement boundary.");
  await assertManifestControl(recovery, "run-recovery.terminate");

  await recovery.getByRole("textbox", { name: "Operator reason (audited)", exact: true })
    .fill("Move only the exact stopped step to the attested alternate specialist.");
  await recovery.getByRole("combobox", { name: "Healthy capable specialist", exact: true })
    .selectOption(reassignFixture.candidateAgentId!);
  await recovery.getByRole("combobox", { name: "Declared shared capability", exact: true })
    .selectOption("network.recon");
  const reassignedResponse = await mutationResponse(page, recoveryMutationPath(reassignFixture, "reassign"), async () => {
    await recovery.getByRole("button", { name: "Reassign specialist", exact: true }).click();
  });
  expect(reassignedResponse.status()).toBe(200);
  const reassignedBody = await reassignedResponse.json();
  expect(reassignedBody).toMatchObject({
    mutation: {
      kind: "reassign",
      agentId: reassignFixture.candidateAgentId,
      assignmentId: expect.any(String),
      checkpointId: expect.any(String),
    },
    run: {
      id: reassignFixture.runId,
      status: "blocked",
      planId: reassignFixture.planId,
      planVersion: 1,
      stepId: reassignFixture.stepId,
    },
  });
  const afterReassign = readRunInterventionRecoverySnapshot(reassignFixture);
  expect(afterReassign.run).toMatchObject({ status: "blocked", leaseOwner: null });
  expect(afterReassign.assignments).toHaveLength(2);
  expect(afterReassign.assignments[0]).toMatchObject({
    id: reassignFixture.assignmentId,
    agentId: reassignFixture.agentId,
    status: "cancelled",
  });
  expect(afterReassign.assignments[1]).toMatchObject({
    agentId: reassignFixture.candidateAgentId,
    status: "queued",
  });
  expect(afterReassign.decisionStatuses).toEqual(["cancelled", "pending"]);
  expect(afterReassign.events.some((event) => event.type === "run.specialist_reassigned")).toBe(true);
  expect(afterReassign.audits).toContainEqual({
    action: "run.specialist_reassigned",
    reason: "Move only the exact stopped step to the attested alternate specialist.",
  });
  expect(afterReassign.checkpoints.at(-1)).toMatchObject({ planVersion: 1, stateHashVerified: true, inFlightCount: 0 });
  expect(afterReassign.recoveryIdempotencyCount).toBe(1);
  await audit.waitForPageApiSettlement(page);
  const replay = await replayCapturedMutation(page, audit, reassignedResponse.request());
  expect(replay).toEqual({ status: 200, body: reassignedBody });
  expect(readRunInterventionRecoverySnapshot(reassignFixture)).toEqual(afterReassign);

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await audit.waitForPageApiSettlement(page);
  const terminateRecovery = recoveryControls(page);
  await terminateRecovery.getByRole("textbox", { name: "Operator reason (audited)", exact: true })
    .fill("No further in-scope recovery remains; close the disposable run cleanly.");
  const terminatedResponse = await mutationResponse(page, runControlPath(reassignFixture, "cancel"), async () => {
    await terminateRecovery.getByRole("button", { name: "Terminate gracefully", exact: true }).click();
  });
  expect(terminatedResponse.status()).toBe(200);
  expect(await terminatedResponse.json()).toMatchObject({ run: { id: reassignFixture.runId, status: "cancelled" } });
  const terminated = readRunInterventionRecoverySnapshot(reassignFixture);
  expect(terminated.run).toMatchObject({ status: "cancelled", leaseOwner: null, leaseExpiresAt: null });
  expect(terminated.providerTurnStatuses.every((status) => status === "cancelled")).toBe(true);
  expect(terminated.runtimeContinuationStatuses.every((status) =>
    status === "cancelled" || status === "completed")).toBe(true);
  expect(terminated.executingChildCount).toBe(0);
  expect(terminated.durableRunLeaseActive).toBe(false);
  expect(terminated.activeControlPlaneLeaseCount).toBe(0);
  expect(terminated.activeChildCount).toBe(0);
  expect(terminated.assignments.every((assignment) => assignment.status === "cancelled" && assignment.leaseOwner === null)).toBe(true);
  expect(terminated.decisionStatuses.every((status) => status === "cancelled")).toBe(true);
  expect(terminated.checkpoints.at(-1)).toMatchObject({ planVersion: 1, stateHashVerified: true, inFlightCount: 0 });
  expect(terminated.audits).toContainEqual({
    action: "run.cancelled",
    reason: "No further in-scope recovery remains; close the disposable run cleanly.",
  });
  await audit.waitForPageApiSettlement(page);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expect(page.getByLabel("Selected run status")).toContainText("cancelled");
  expect(readRunInterventionRecoverySnapshot(reassignFixture).activeChildCount).toBe(0);
  await audit.assertClean(testInfo);
});

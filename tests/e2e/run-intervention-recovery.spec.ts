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
import { selectTitaniumOption } from "./support/titaniumSelect";
import type { InteractionActivationInput } from "./support/interactionActivationFixture";
import { BROWSER_STORAGE_KEYS } from "../../src/lib/browserNamespaces";

const TEST_CONTROL_PLANE = "e2e.run-intervention.control-plane-rejection";
const TEST_PAUSE_RESUME = "e2e.run-intervention.pause-resume-replay";
const TEST_CANCEL = "e2e.run-intervention.cancel-no-ghost";
const TEST_REPLAN = "e2e.run-recovery.replan-boundary-replay";
const TEST_REASSIGN_TERMINATE = "e2e.run-recovery.reassign-terminate";
const TEST_RECOVERY_RETRY = "e2e.run-recovery.exact-mutation-retry-reconcile";
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
  exactAttempt: {
    id: "visual.run-recovery.exact-attempt.chromium-1440",
    snapshot: "run-recovery-exact-attempt.png",
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
  "run-recovery.exact-attempt",
  "run-recovery.discard-attempt",
] as const;
const manifest = validateInteractionManifest(JSON.parse(
  readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8"),
) as unknown);

function activation(
  manifestEntryId: typeof MANIFEST_IDS[number],
  option: string,
  modality: "pointer" | "keyboard",
  testId: string,
): InteractionActivationInput {
  const entry = manifest.entries.find((candidate) => candidate.id === manifestEntryId);
  if (!entry) throw new Error(`Run intervention manifest entry ${manifestEntryId} is missing`);
  if (!entry.options.includes(option)) throw new Error(`Run intervention manifest entry ${manifestEntryId} does not declare ${option}`);
  if (!entry.testIds.includes(testId)) throw new Error(`Run intervention manifest entry ${manifestEntryId} does not declare ${testId}`);
  return {
    manifestEntryId,
    controlId: entry.controlId,
    option,
    materialState: entry.requiredState,
    modality,
    testId,
  };
}

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
      "Next runtime action": "Wait for the exact represented decision",
    };
    for (const row of node.querySelectorAll("dl > div")) {
      const label = row.querySelector("dt")?.textContent?.trim();
      const value = row.querySelector("dd");
      if (label && value && replacements[label]) value.textContent = replacements[label];
    }
    const decisionSummary = node.querySelector(".os-guided-recovery-decision p:last-child");
    if (decisionSummary) decisionSummary.textContent = "low risk · expires Jul 16, 2099, 12:30 PM UTC";
    // Status pills normally use a finite arrival transform. The screenshot
    // represents the settled recovery state, so remove the compositor layer
    // explicitly instead of allowing a query refresh to restart that transform
    // between Playwright's stability probes.
    for (const status of node.querySelectorAll<HTMLElement>(".os-status")) {
      status.style.animation = "none";
      status.style.transform = "none";
    }
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
      Next: "Wait for the exact represented decision",
    };
    for (const item of items) {
      const label = item.querySelector("span")?.textContent?.trim();
      const value = item.querySelector("strong");
      if (label && value && replacements[label]) value.textContent = replacements[label];
    }
  });
  await statusBand.locator(".os-status").evaluateAll((statuses) => {
    for (const status of statuses) {
      status.style.animation = "none";
      status.style.transform = "none";
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

async function normalizeExactRecoveryAttemptVisual(attempt: Locator): Promise<void> {
  await attempt.evaluate((node) => {
    for (const status of node.querySelectorAll<HTMLElement>(".os-status")) {
      for (const animation of status.getAnimations()) animation.finish();
      status.style.animation = "none";
      status.style.transform = "none";
    }
    const integrity = node.querySelector<HTMLElement>(".os-mono");
    if (integrity) {
      integrity.textContent = "Body SHA-256 a1b2c3d4e5f60708… · expires Jul 24, 2099, 12:10 PM UTC";
    }
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

async function prepareExactReassignment(
  page: Page,
  fixture: RunInterventionRecoveryFixture,
  reasonText: string,
  modality: "pointer" | "keyboard",
): Promise<void> {
  const recovery = recoveryControls(page);
  const reason = recovery.getByRole("textbox", { name: "Operator reason (audited)", exact: true });
  if (modality === "pointer") {
    await reason.click();
    await reason.fill(reasonText);
  } else {
    await reason.focus();
    await page.keyboard.insertText(reasonText);
  }
  await selectTitaniumOption(
    recovery.getByRole("combobox", { name: "Healthy capable specialist", exact: true }),
    fixture.candidateAgentId!,
    modality,
  );
  await selectTitaniumOption(
    recovery.getByRole("combobox", { name: "Declared shared capability", exact: true }),
    "network.recon",
    modality,
  );
  await expect(recovery.getByRole("button", { name: "Reassign specialist", exact: true })).toBeEnabled();
}

async function activateExactAttempt(
  page: Page,
  modality: "pointer" | "keyboard",
  accessibleName: "Retry exact recovery action" | "Reconcile exact recovery attempt",
): Promise<void> {
  const button = recoveryControls(page).getByRole("button", { name: accessibleName, exact: true });
  if (modality === "pointer") {
    await button.click();
    return;
  }
  await button.focus();
  await expect(button).toBeFocused();
  await page.keyboard.press("Enter");
}

type InvalidStoredRecoveryAttempt =
  | "malformed"
  | "expired"
  | "hash_mutated"
  | "cross_actor"
  | "secret_bearing";

async function installInvalidStoredRecoveryAttempt(
  page: Page,
  key: string,
  baseRaw: string,
  variant: InvalidStoredRecoveryAttempt,
): Promise<void> {
  await page.evaluate(async ({ storageKey, raw, invalidVariant }) => {
    if (invalidVariant === "malformed") {
      sessionStorage.setItem(storageKey, "{");
      return;
    }
    const attempt = JSON.parse(raw) as Record<string, unknown>;
    if (invalidVariant === "expired") {
      attempt.createdAt = "2000-01-01T00:00:00.000Z";
      attempt.expiresAt = "2000-01-01T00:10:00.000Z";
    } else if (invalidVariant === "hash_mutated") {
      attempt.bodySha256 = "0".repeat(64);
    } else if (invalidVariant === "cross_actor") {
      attempt.actorId = `${String(attempt.actorId)}-different`;
    } else {
      const body = JSON.parse(String(attempt.serializedBody)) as Record<string, unknown>;
      body.reason = "authorization=synthetic-secret-value";
      const serializedBody = JSON.stringify(body);
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(serializedBody),
      );
      attempt.serializedBody = serializedBody;
      attempt.bodySha256 = [...new Uint8Array(digest)]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
    }
    sessionStorage.setItem(storageKey, JSON.stringify(attempt));
  }, { storageKey: key, raw: baseRaw, invalidVariant: variant });
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

async function mutateCapturedWithFreshIdempotencyKey(
  page: Page,
  audit: BrowserAudit,
  request: Request,
  expectedResponseId: string,
  idempotencyKey: string,
): Promise<{
  readonly status: number;
  readonly body: unknown;
}> {
  const capturedUrl = new URL(request.url());
  const requestPath = `${capturedUrl.pathname}${capturedUrl.search}`;
  const headers = request.headers();
  const capturedCsrf = headers["x-ti-scale-csrf"];
  const contentType = headers["content-type"];
  const body = request.postData();
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
    expectedResponseId,
    options: {
      data: body,
      headers: {
        Accept: headers.accept ?? "application/json",
        "Content-Type": contentType!,
        "Idempotency-Key": idempotencyKey,
        "X-Ti-Scale-CSRF": capturedCsrf!,
      },
    },
  });
  return { status: response.status(), body: await response.json() as unknown };
}

test(`${TEST_CONTROL_PLANE} refuses a legacy-owned run without creating V2 lease, event, checkpoint, or audit state`, async ({ page, interactionActivation }, testInfo) => {
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
  const reason = controls.getByRole("textbox", { name: "Operator reason (audited)", exact: true });
  await interactionActivation.activate(activation(
    "run-intervention.reason",
    "Legacy ownership rejection reason",
    "pointer",
    TEST_CONTROL_PLANE,
  ), async () => {
    await reason.click();
    await reason.fill("Verify the owning control plane rejects this intervention.");
    await expect(reason).toHaveValue("Verify the owning control plane rejects this intervention.");
  });
  await interactionActivation.activate(activation(
    "run-intervention.pause",
    "Reject legacy-owned run",
    "pointer",
    TEST_CONTROL_PLANE,
  ), async () => {
    const response = await mutationResponse(page, runControlPath(legacyFixture, "pause"), async () => {
      await controls.getByRole("button", { name: "Pause run", exact: true }).click();
    });
    expect(response.status()).toBe(409);
    expect(await response.json()).toMatchObject({
      error: {
        code: "control_plane_mismatch",
        humanMessage: "This mission and run are controlled elsewhere, so Ti-Scale made no changes.",
        remediation: "Open this run through its owning control plane; imported legacy runs remain read-only in Ti-Scale.",
      },
    });
    const alert = controls.getByRole("alert");
    await expect(alert).toContainText("This mission and run are controlled elsewhere, so Ti-Scale made no changes.");
    await expect(alert).toContainText("Open this run through its owning control plane; imported legacy runs remain read-only in Ti-Scale.");
    expect(readRunInterventionRecoverySnapshot(legacyFixture)).toMatchObject({
      run: { status: "running", version: 1, controlPlane: "legacy", leaseOwner: null },
      events: [],
      audits: [],
      checkpoints: [],
      runtimeIdempotencyCount: 0,
    });
    await expect(page.getByLabel("Selected run status")).toContainText("running");
  });
  await audit.assertClean(testInfo);
});

test(`${TEST_PAUSE_RESUME} pauses and resumes from the exact durable checkpoint with idempotent replay and refresh persistence`, async ({ page, interactionActivation }, testInfo) => {
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
  });
  await page.goto(liveRoute(pauseFixture), { waitUntil: "domcontentloaded" });
  const controls = interventionControls(page);
  await assertManifestControl(controls, "run-intervention.reason");
  await assertManifestControl(controls, "run-intervention.pause");
  const pause = controls.getByRole("button", { name: "Pause run", exact: true });
  await expect(pause).toBeDisabled();
  const pauseReason = controls.getByRole("textbox", { name: "Operator reason (audited)", exact: true });
  await interactionActivation.activate(activation(
    "run-intervention.reason",
    "Pause reason",
    "keyboard",
    TEST_PAUSE_RESUME,
  ), async () => {
    await pauseReason.focus();
    await page.keyboard.insertText("Pause at the next durable operator checkpoint.");
    await expect(pauseReason).toHaveValue("Pause at the next durable operator checkpoint.");
  });
  const pauseProof = await interactionActivation.activate(activation(
    "run-intervention.pause",
    "Idempotently replay exact accepted request",
    "keyboard",
    TEST_PAUSE_RESUME,
  ), async () => {
    const proof = await interactionActivation.activate(activation(
      "run-intervention.pause",
      "Pause V2-owned run at durable boundary",
      "keyboard",
      TEST_PAUSE_RESUME,
    ), async () => {
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
      return { pausedResponse, pausedBody, afterPause };
    });
    await audit.waitForPageApiSettlement(page);
    const replay = await replayCapturedMutation(page, audit, proof.pausedResponse.request());
    expect(replay).toEqual({ status: 200, body: proof.pausedBody });
    expect(readRunInterventionRecoverySnapshot(pauseFixture)).toEqual(proof.afterPause);
    return proof;
  });
  const { afterPause } = pauseProof;

  const recovery = recoveryControls(page);
  await expect(recovery.getByRole("heading", { name: "Guided recovery needs your decision", exact: true })).toBeVisible();
  await expect(recovery.getByText("Plan version", { exact: true })).toBeVisible();
  await expect(recovery.getByText("In-flight actions", { exact: true })).toBeVisible();
  await assertManifestControl(recovery, "run-recovery.reason");
  await assertManifestControl(recovery, "run-recovery.resume");
  await normalizeRecoveryVisual(recovery);
  await expectApprovedRecoveryVisual(recovery, testInfo, RECOVERY_VISUALS.blocked);
  await restoreRecoveryVisual(recovery);
  const resumeReason = recovery.getByRole("textbox", { name: "Operator reason (audited)", exact: true });
  await interactionActivation.activate(activation(
    "run-recovery.reason",
    "Resume reason",
    "pointer",
    TEST_PAUSE_RESUME,
  ), async () => {
    await resumeReason.click();
    await resumeReason.fill("Resume only the persisted exact Guided checkpoint.");
    await expect(resumeReason).toHaveValue("Resume only the persisted exact Guided checkpoint.");
  });
  await interactionActivation.activate(activation(
    "run-recovery.resume",
    "Resume exact paused checkpoint",
    "pointer",
    TEST_PAUSE_RESUME,
  ), async () => {
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
    // A waiting Guided decision retains one fenced mutation-authority lease so
    // another controller cannot take over its exact boundary. That passive
    // authority is not an executing child or a durable run lease.
    expect(afterResume.activeControlPlaneLeaseCount).toBe(1);
    expect(afterResume.audits).toEqual([
      { action: "run.paused", reason: "Pause at the next durable operator checkpoint." },
      { action: "run.resumed", reason: "Resume only the persisted exact Guided checkpoint." },
    ]);
    expect(afterResume.checkpoints.length).toBeGreaterThan(afterPause.checkpoints.length);
    expect(afterResume.checkpoints.every((checkpoint) => checkpoint.stateHashVerified)).toBe(true);
    expect(afterResume.runtimeIdempotencyCount).toBe(2);
  });
  await audit.assertClean(testInfo);
});

test(`${TEST_CANCEL} cancels all durable child work, checkpoints zero in-flight work, replays idempotently, and survives refresh`, async ({ page, interactionActivation }, testInfo) => {
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
  });
  await page.goto(liveRoute(cancelFixture), { waitUntil: "domcontentloaded" });
  const controls = interventionControls(page);
  await assertManifestControl(controls, "run-intervention.cancel");
  const before = readRunInterventionRecoverySnapshot(cancelFixture);
  expect(before.activeChildCount).toBeGreaterThanOrEqual(5);
  const cancelReason = controls.getByRole("textbox", { name: "Operator reason (audited)", exact: true });
  await interactionActivation.activate(activation(
    "run-intervention.reason",
    "Cancellation reason",
    "pointer",
    TEST_CANCEL,
  ), async () => {
    await cancelReason.click();
    await cancelReason.fill("Terminate the disposable fixture and close every child record.");
    await expect(cancelReason).toHaveValue("Terminate the disposable fixture and close every child record.");
  });
  await interactionActivation.activate(activation(
    "run-intervention.cancel",
    "Idempotently replay exact accepted request",
    "pointer",
    TEST_CANCEL,
  ), async () => {
    const proof = await interactionActivation.activate(activation(
      "run-intervention.cancel",
      "Cancel run and every durable child",
      "pointer",
      TEST_CANCEL,
    ), async () => {
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
      return { cancelledResponse, cancelledBody, afterCancel };
    });
    await audit.waitForPageApiSettlement(page);
    const replay = await replayCapturedMutation(page, audit, proof.cancelledResponse.request());
    expect(replay).toEqual({ status: 200, body: proof.cancelledBody });
    expect(readRunInterventionRecoverySnapshot(cancelFixture)).toEqual(proof.afterCancel);
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
    await expect(page.getByLabel("Selected run status")).toContainText("cancelled");
    await expect(page.getByText("Mission completion review", { exact: true })).toBeVisible();
    expect(readRunInterventionRecoverySnapshot(cancelFixture).activeChildCount).toBe(0);
  });
  await audit.assertClean(testInfo);
});

test(`${TEST_REPLAN} rejects a stale boundary, persists one bounded replan, then rejects replay after fail-closed progression`, async ({ page, interactionActivation }, testInfo) => {
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
  const initialStrategy = recovery.getByRole("textbox", { name: "Materially different in-scope strategy", exact: true });
  await interactionActivation.activate(activation(
    "run-recovery.strategy",
    "At least 12 normalized characters",
    "pointer",
    TEST_REPLAN,
  ), async () => {
    await initialStrategy.click();
    await initialStrategy.fill("Correlate the retained timeout with a different passive source before any retry.");
    await expect(initialStrategy).toHaveValue("Correlate the retained timeout with a different passive source before any retry.");
  });
  await interactionActivation.activate(activation(
    "run-recovery.replan",
    "Reject stale boundary with remediation",
    "pointer",
    TEST_REPLAN,
  ), async () => {
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
  });

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  const refreshedRecovery = recoveryControls(page);
  const strategy = "Correlate the retained timeout with an independent passive source before any retry.";
  const refreshedStrategy = refreshedRecovery.getByRole("textbox", { name: "Materially different in-scope strategy", exact: true });
  await interactionActivation.activate(activation(
    "run-recovery.strategy",
    "Stale-boundary retry after refresh",
    "keyboard",
    TEST_REPLAN,
  ), async () => {
    await interactionActivation.activate(activation(
      "run-recovery.strategy",
      "Materially different strategy",
      "keyboard",
      TEST_REPLAN,
    ), async () => {
      await refreshedStrategy.focus();
      await page.keyboard.insertText(strategy);
      await expect(refreshedStrategy).toHaveValue(strategy);
    });
  });
  await interactionActivation.activate(activation(
    "run-recovery.replan",
    "Idempotently replay exact accepted request",
    "pointer",
    TEST_REPLAN,
  ), async () => {
    const proof = await interactionActivation.activate(activation(
      "run-recovery.replan",
      "Persist one bounded replan",
      "pointer",
      TEST_REPLAN,
    ), async () => {
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
      // boundary through its returned version, event, and hash-verified checkpoint.
      expect(acceptedBody.run.version).toBeGreaterThan(staleVersion);
      return { acceptedResponse, acceptedBody };
    });

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
        runtimeContinuationStatuses: snapshot.runtimeContinuationStatuses,
        executingChildCount: snapshot.executingChildCount,
        activeChildCount: snapshot.activeChildCount,
        failureDiagnosed: snapshot.audits.some((auditRecord) => auditRecord.action === "failure_diagnosis.created"),
      };
    }, { timeout: 7_500 }).toEqual({
      runStatus: "blocked",
      stepStatuses: ["failed"],
      assignmentStatuses: ["failed"],
      replanStarted: true,
      guidedBlocked: true,
      runtimeContinuationStatuses: ["completed"],
      executingChildCount: 0,
      activeChildCount: 1,
      failureDiagnosed: true,
    });
    const afterUnavailablePlanner = readRunInterventionRecoverySnapshot(replanFixture);
    expect(afterUnavailablePlanner.run.statusReason).toContain("isolated test boundary");
    expect(afterUnavailablePlanner.run.version).toBeGreaterThan(proof.acceptedBody.run.version);
    expect(afterUnavailablePlanner.stepStatuses).toEqual(["failed"]);
    expect(afterUnavailablePlanner.assignments.map((assignment) => assignment.status)).toEqual(["failed"]);
    expect(afterUnavailablePlanner.actionStatuses).toEqual(["timed_out"]);
    expect(afterUnavailablePlanner.events.some((event) => event.type === "run.replan_started")).toBe(true);
    expect(afterUnavailablePlanner.events.some((event) => event.type === "run.guided_blocked")).toBe(true);
    expect(afterUnavailablePlanner.audits).toContainEqual({ action: "run.replan_requested", reason: strategy });
    expect(afterUnavailablePlanner.events.some((event) => event.type === "run.operator_replan_requested")).toBe(true);
    expect(afterUnavailablePlanner.checkpoints).toContainEqual(expect.objectContaining({
      id: proof.acceptedBody.mutation.checkpointId,
      planVersion: 1,
      stateHashVerified: true,
      inFlightCount: 0,
    }));
    expect(afterUnavailablePlanner.recoveryIdempotencyCount).toBe(1);
    await audit.waitForPageApiSettlement(page);
    const progressedReplay = await replayCapturedMutation(
      page,
      audit,
      proof.acceptedResponse.request(),
      "run-recovery.replan-progressed-replay",
    );
    expect(progressedReplay).toMatchObject({
      status: 409,
      body: { error: { code: "recovery_idempotent_replay_stale", retryable: false } },
    });
    expect(readRunInterventionRecoverySnapshot(replanFixture)).toEqual(afterUnavailablePlanner);
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
    await expect(page.getByLabel("Selected run status")).toContainText("blocked");
  });
  await audit.assertClean(testInfo);
});

test(`${TEST_REASSIGN_TERMINATE} reassigns only the exact stopped assignment, declares provider routing unavailable, then terminates with no ghost-active state`, async ({ page, interactionActivation }, testInfo) => {
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
  await interactionActivation.activate(activation(
    "run-recovery.change-provider",
    "Unavailable without compatible callable provider",
    "pointer",
    TEST_REASSIGN_TERMINATE,
  ), async () => {
    await provider.hover();
    await expect(provider).toBeDisabled();
    await expect(provider.locator("xpath=ancestor::li[1]")).toContainText("No healthy callable provider satisfies the journey and budget enforcement boundary.");
    expect(readRunInterventionRecoverySnapshot(reassignFixture)).toMatchObject({
      run: { status: "blocked" },
      recoveryIdempotencyCount: 0,
    });
  });
  await assertManifestControl(recovery, "run-recovery.terminate");

  const reassignmentReason = recovery.getByRole("textbox", { name: "Operator reason (audited)", exact: true });
  await interactionActivation.activate(activation(
    "run-recovery.reason",
    "Reassignment reason",
    "pointer",
    TEST_REASSIGN_TERMINATE,
  ), async () => {
    await reassignmentReason.click();
    await reassignmentReason.fill("Move only the exact stopped step to the attested alternate specialist.");
    await expect(reassignmentReason).toHaveValue("Move only the exact stopped step to the attested alternate specialist.");
  });
  const specialist = recovery.getByRole("combobox", { name: "Healthy capable specialist", exact: true });
  await interactionActivation.activate(activation(
    "run-recovery.specialist",
    "Alternate recon specialist",
    "pointer",
    TEST_REASSIGN_TERMINATE,
  ), async () => {
    await selectTitaniumOption(specialist, reassignFixture.candidateAgentId!, "pointer");
    await expect(specialist.locator("xpath=..").locator("select.os-titanium-select__form-proxy"))
      .toHaveValue(reassignFixture.candidateAgentId!);
    await expect(specialist).toBeFocused();
  });
  const capability = recovery.getByRole("combobox", { name: "Declared shared capability", exact: true });
  await interactionActivation.activate(activation(
    "run-recovery.capability",
    "network.recon",
    "keyboard",
    TEST_REASSIGN_TERMINATE,
  ), async () => {
    await selectTitaniumOption(capability, "network.recon", "keyboard");
    await expect(capability.locator("xpath=..").locator("select.os-titanium-select__form-proxy"))
      .toHaveValue("network.recon");
    await expect(capability).toBeFocused();
  });
  await interactionActivation.activate(activation(
    "run-recovery.reassign",
    "Idempotently replay exact accepted request",
    "pointer",
    TEST_REASSIGN_TERMINATE,
  ), async () => {
    const proof = await interactionActivation.activate(activation(
      "run-recovery.reassign",
      "Supersede exact Guided decision",
      "pointer",
      TEST_REASSIGN_TERMINATE,
    ), async () => interactionActivation.activate(activation(
      "run-recovery.reassign",
      "Replace only exact stopped assignment",
      "pointer",
      TEST_REASSIGN_TERMINATE,
    ), async () => {
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
      return { reassignedResponse, reassignedBody, afterReassign };
    }));
    await audit.waitForPageApiSettlement(page);
    const replay = await replayCapturedMutation(page, audit, proof.reassignedResponse.request());
    expect(replay).toEqual({ status: 200, body: proof.reassignedBody });
    expect(readRunInterventionRecoverySnapshot(reassignFixture)).toEqual(proof.afterReassign);
  });

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await audit.waitForPageApiSettlement(page);
  const terminateRecovery = recoveryControls(page);
  const terminationReason = terminateRecovery.getByRole("textbox", { name: "Operator reason (audited)", exact: true });
  await interactionActivation.activate(activation(
    "run-recovery.reason",
    "Graceful termination reason",
    "keyboard",
    TEST_REASSIGN_TERMINATE,
  ), async () => {
    await terminationReason.focus();
    await page.keyboard.insertText("No further in-scope recovery remains; close the disposable run cleanly.");
    await expect(terminationReason).toHaveValue("No further in-scope recovery remains; close the disposable run cleanly.");
  });
  await interactionActivation.activate(activation(
    "run-recovery.terminate",
    "Close every remaining durable child",
    "pointer",
    TEST_REASSIGN_TERMINATE,
  ), async () => interactionActivation.activate(activation(
    "run-recovery.terminate",
    "Terminate after reassignment",
    "pointer",
    TEST_REASSIGN_TERMINATE,
  ), async () => {
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
  }));
  await audit.assertClean(testInfo);
});

test(`${TEST_CANCEL} records both modalities for durable cancellation, exact replay, and no-ghost refresh`, async ({ page, interactionActivation }, testInfo) => {
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
  });

  for (const modality of ["pointer", "keyboard"] as const) {
    const fixture = createRunInterventionRecoveryFixture(
      "cancel",
      canonicalFixtureNamespace(testInfo, `run-intervention-cancel-receipt-${modality}`),
    );
    const route = liveRoute(fixture);
    if (page.url() === "about:blank") {
      await page.goto(route, { waitUntil: "domcontentloaded" });
    } else {
      await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(route, { waitUntil: "domcontentloaded" }));
    }

    const controls = interventionControls(page);
    await assertManifestControl(controls, "run-intervention.reason");
    await assertManifestControl(controls, "run-intervention.cancel");
    const before = readRunInterventionRecoverySnapshot(fixture);
    expect(before.run).toMatchObject({ status: "running", controlPlane: "ti_scale" });
    expect(before.activeChildCount).toBeGreaterThanOrEqual(5);

    const reasonText = `Cancel the ${modality} disposable run and close every durable child record.`;
    const reason = controls.getByRole("textbox", { name: "Operator reason (audited)", exact: true });
    await interactionActivation.activate(activation(
      "run-intervention.reason",
      "Cancellation reason",
      modality,
      TEST_CANCEL,
    ), async () => {
      if (modality === "pointer") {
        await reason.click();
        await reason.fill(reasonText);
      } else {
        await reason.focus();
        await page.keyboard.insertText(reasonText);
      }
      await expect(reason).toHaveValue(reasonText);
    });

    await interactionActivation.activate(activation(
      "run-intervention.cancel",
      "Idempotently replay exact accepted request",
      modality,
      TEST_CANCEL,
    ), async () => {
      const proof = await interactionActivation.activate(activation(
        "run-intervention.cancel",
        "Cancel run and every durable child",
        modality,
        TEST_CANCEL,
      ), async () => {
        const cancel = controls.getByRole("button", { name: "Cancel run", exact: true });
        const cancelledResponse = await mutationResponse(page, runControlPath(fixture, "cancel"), async () => {
          if (modality === "pointer") {
            await cancel.click();
          } else {
            await cancel.focus();
            await page.keyboard.press("Enter");
          }
        });
        expect(cancelledResponse.status()).toBe(200);
        const cancelledBody = await cancelledResponse.json();
        expect(cancelledBody).toMatchObject({ run: { id: fixture.runId, status: "cancelled" } });

        const afterCancel = readRunInterventionRecoverySnapshot(fixture);
        expect(afterCancel.run).toMatchObject({
          status: "cancelled",
          leaseOwner: null,
          leaseExpiresAt: null,
        });
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
        expect(afterCancel.audits).toContainEqual({ action: "run.cancelled", reason: reasonText });
        expect(afterCancel.checkpoints.length).toBeGreaterThanOrEqual(2);
        expect(afterCancel.checkpoints.every((checkpoint) => checkpoint.stateHashVerified)).toBe(true);
        expect(afterCancel.checkpoints.at(-1)?.inFlightCount).toBe(0);
        expect(afterCancel.runtimeIdempotencyCount).toBe(1);
        return { cancelledResponse, cancelledBody, afterCancel };
      });

      await audit.waitForPageApiSettlement(page);
      const replay = await replayCapturedMutation(page, audit, proof.cancelledResponse.request());
      expect(replay).toEqual({ status: 200, body: proof.cancelledBody });
      expect(readRunInterventionRecoverySnapshot(fixture)).toEqual(proof.afterCancel);
    });

    await audit.waitForPageApiSettlement(page);
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
    await expect(page.getByLabel("Selected run status")).toContainText("cancelled");
    await expect(page.getByText("Mission completion review", { exact: true })).toBeVisible();
    expect(readRunInterventionRecoverySnapshot(fixture).activeChildCount).toBe(0);
  }

  await audit.assertClean(testInfo);
});

test(`${TEST_PAUSE_RESUME} records both modalities for durable pause, exact checkpoint resume, and idempotent replay`, async ({ page, interactionActivation }, testInfo) => {
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
  });

  for (const modality of ["pointer", "keyboard"] as const) {
    const fixture = createRunInterventionRecoveryFixture(
      "pause_resume",
      canonicalFixtureNamespace(testInfo, `run-intervention-pause-resume-receipt-${modality}`),
    );
    const route = liveRoute(fixture);
    if (page.url() === "about:blank") {
      await page.goto(route, { waitUntil: "domcontentloaded" });
    } else {
      await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(route, { waitUntil: "domcontentloaded" }));
    }

    const controls = interventionControls(page);
    await assertManifestControl(controls, "run-intervention.reason");
    await assertManifestControl(controls, "run-intervention.pause");
    const pauseButton = controls.getByRole("button", { name: "Pause run", exact: true });
    await expect(pauseButton).toBeDisabled();

    const pauseReasonText = `Pause the ${modality} fixture at its exact durable Guided boundary.`;
    const pauseReason = controls.getByRole("textbox", { name: "Operator reason (audited)", exact: true });
    await interactionActivation.activate(activation(
      "run-intervention.reason",
      "Pause reason",
      modality,
      TEST_PAUSE_RESUME,
    ), async () => {
      if (modality === "pointer") {
        await pauseReason.click();
        await pauseReason.fill(pauseReasonText);
      } else {
        await pauseReason.focus();
        await page.keyboard.insertText(pauseReasonText);
      }
      await expect(pauseReason).toHaveValue(pauseReasonText);
      await expect(pauseButton).toBeEnabled();
    });

    const pauseProof = await interactionActivation.activate(activation(
      "run-intervention.pause",
      "Idempotently replay exact accepted request",
      modality,
      TEST_PAUSE_RESUME,
    ), async () => {
      const proof = await interactionActivation.activate(activation(
        "run-intervention.pause",
        "Pause V2-owned run at durable boundary",
        modality,
        TEST_PAUSE_RESUME,
      ), async () => {
        const pausedResponse = await mutationResponse(page, runControlPath(fixture, "pause"), async () => {
          if (modality === "pointer") {
            await pauseButton.click();
          } else {
            await pauseButton.focus();
            await page.keyboard.press("Enter");
          }
        });
        expect(pausedResponse.status()).toBe(200);
        const pausedBody = await pausedResponse.json();
        expect(pausedBody).toMatchObject({ run: { id: fixture.runId, status: "blocked" } });

        const afterPause = readRunInterventionRecoverySnapshot(fixture);
        expect(afterPause.run).toMatchObject({
          status: "blocked",
          controlPlane: "ti_scale",
          leaseOwner: null,
          leaseExpiresAt: null,
        });
        expect(afterPause.missionStatus).toBe("paused");
        expect(afterPause.stepStatuses).toEqual(["waiting_guided_decision"]);
        expect(afterPause.assignments).toEqual([{
          id: fixture.assignmentId,
          agentId: fixture.agentId,
          status: "blocked",
          leaseOwner: null,
        }]);
        expect(afterPause.decisionStatuses).toEqual(["pending"]);
        expect(afterPause.executingChildCount).toBe(0);
        expect(afterPause.durableRunLeaseActive).toBe(false);
        expect(afterPause.activeControlPlaneLeaseCount).toBe(0);
        expect(afterPause.events.some((event) => event.type === "run.state_changed")).toBe(true);
        expect(afterPause.audits).toEqual([{ action: "run.paused", reason: pauseReasonText }]);
        expect(afterPause.checkpoints.length).toBeGreaterThan(0);
        expect(afterPause.checkpoints.every((checkpoint) => checkpoint.stateHashVerified)).toBe(true);
        expect(afterPause.checkpoints.at(-1)?.inFlightCount).toBe(0);
        expect(afterPause.runtimeIdempotencyCount).toBe(1);
        return { pausedResponse, pausedBody, afterPause };
      });

      await audit.waitForPageApiSettlement(page);
      const replay = await replayCapturedMutation(page, audit, proof.pausedResponse.request());
      expect(replay).toEqual({ status: 200, body: proof.pausedBody });
      expect(readRunInterventionRecoverySnapshot(fixture)).toEqual(proof.afterPause);
      return proof;
    });

    const recovery = recoveryControls(page);
    await expect(recovery.getByRole("heading", { name: "Guided recovery needs your decision", exact: true })).toBeVisible();
    await assertManifestControl(recovery, "run-recovery.reason");
    await assertManifestControl(recovery, "run-recovery.resume");
    const resumeButton = recovery.getByRole("button", { name: "Resume from checkpoint", exact: true });
    await expect(resumeButton).toBeDisabled();

    const resumeReasonText = `Resume the ${modality} fixture only from its persisted exact checkpoint.`;
    const resumeReason = recovery.getByRole("textbox", { name: "Operator reason (audited)", exact: true });
    await interactionActivation.activate(activation(
      "run-recovery.reason",
      "Resume reason",
      modality,
      TEST_PAUSE_RESUME,
    ), async () => {
      if (modality === "pointer") {
        await resumeReason.click();
        await resumeReason.fill(resumeReasonText);
      } else {
        await resumeReason.focus();
        await page.keyboard.insertText(resumeReasonText);
      }
      await expect(resumeReason).toHaveValue(resumeReasonText);
      await expect(resumeButton).toBeEnabled();
    });

    await interactionActivation.activate(activation(
      "run-recovery.resume",
      "Resume exact paused checkpoint",
      modality,
      TEST_PAUSE_RESUME,
    ), async () => {
      const resumedResponse = await mutationResponse(page, runControlPath(fixture, "resume"), async () => {
        if (modality === "pointer") {
          await resumeButton.click();
        } else {
          await resumeButton.focus();
          await page.keyboard.press("Enter");
        }
      });
      expect(resumedResponse.status()).toBe(200);
      const sourceCheckpoint = pauseProof.afterPause.checkpoints.at(-1)!;
      expect(resumedResponse.request().postDataJSON()).toMatchObject({
        expectedRunVersion: pauseProof.afterPause.run.version,
        expectedRunStatus: "blocked",
        expectedCheckpointId: sourceCheckpoint.id,
        expectedCheckpointStateHash: sourceCheckpoint.stateHash,
        expectedCheckpointEventSequence: sourceCheckpoint.eventSequence,
      });
      const resumedBody = await resumedResponse.json();
      expect(resumedBody).toMatchObject({
        run: {
          id: fixture.runId,
          status: "waiting_guided_decision",
          currentStepId: fixture.stepId,
        },
      });
      await audit.waitForPageApiSettlement(page);
      const replay = await replayCapturedMutation(page, audit, resumedResponse.request());
      expect(replay).toEqual({ status: 200, body: resumedBody });

      const afterResume = readRunInterventionRecoverySnapshot(fixture);
      expect(afterResume.run).toMatchObject({ status: "waiting_guided_decision", leaseOwner: null });
      expect(afterResume.missionStatus).toBe("active");
      expect(afterResume.stepStatuses).toEqual(["waiting_guided_decision"]);
      expect(afterResume.assignments).toEqual([{
        id: fixture.assignmentId,
        agentId: fixture.agentId,
        status: "queued",
        leaseOwner: null,
      }]);
      expect(afterResume.decisionStatuses).toEqual(["pending"]);
      expect(afterResume.executingChildCount).toBe(0);
      expect(afterResume.durableRunLeaseActive).toBe(false);
      expect(afterResume.activeControlPlaneLeaseCount).toBe(1);
      expect(afterResume.audits).toEqual([
        { action: "run.paused", reason: pauseReasonText },
        { action: "run.resumed", reason: resumeReasonText },
      ]);
      expect(afterResume.checkpoints.length).toBeGreaterThan(pauseProof.afterPause.checkpoints.length);
      expect(afterResume.checkpoints.every((checkpoint) => checkpoint.stateHashVerified)).toBe(true);
      expect(afterResume.runtimeIdempotencyCount).toBe(2);
    });

    await audit.waitForPageApiSettlement(page);
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
    await expect(page.getByLabel("Selected run status")).toContainText("waiting guided decision");
    expect(readRunInterventionRecoverySnapshot(fixture).executingChildCount).toBe(0);
  }

  await audit.assertClean(testInfo);
});

test(`${TEST_REPLAN} records both modalities for stale-boundary rejection, bounded replan, and fail-closed progression`, async ({ page, interactionActivation }, testInfo) => {
  const fixtures = (["pointer", "keyboard"] as const).map((modality) => ({
    modality,
    fixture: createRunInterventionRecoveryFixture(
      "replan",
      canonicalFixtureNamespace(testInfo, `run-recovery-replan-receipt-${modality}`),
    ),
  }));
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: fixtures.flatMap(({ modality, fixture }) => [
      {
        id: `run-recovery.replan-stale-boundary.${modality}`,
        transport: "browser" as const,
        method: "POST",
        pathname: recoveryMutationPath(fixture, "replan"),
        query: {},
        status: 409,
        occurrences: 1,
        reason: `Prove the ${modality} stale recovery boundary fails closed before mutation.`,
      },
      {
        id: `run-recovery.replan-progressed-replay.${modality}`,
        transport: "api-request" as const,
        method: "POST",
        pathname: recoveryMutationPath(fixture, "replan"),
        query: {},
        status: 409,
        occurrences: 1,
        reason: `Prove the ${modality} request cannot replay after fail-closed runtime progression.`,
      },
    ]),
  });

  for (const { modality, fixture } of fixtures) {
    const route = liveRoute(fixture);
    if (page.url() === "about:blank") {
      await page.goto(route, { waitUntil: "domcontentloaded" });
    } else {
      await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(route, { waitUntil: "domcontentloaded" }));
    }

    const recovery = recoveryControls(page);
    await assertManifestControl(recovery, "run-recovery.strategy");
    await assertManifestControl(recovery, "run-recovery.replan");
    const staleCheckpoint = readRunInterventionRecoverySnapshot(fixture).checkpoints.at(-1)!;
    const staleVersion = advanceRunInterventionRecoveryVersion(fixture);
    expect(staleVersion).toBe(2);
    const advancedCheckpoint = readRunInterventionRecoverySnapshot(fixture).checkpoints.at(-1)!;
    expect(advancedCheckpoint.id).not.toBe(staleCheckpoint.id);
    expect(advancedCheckpoint.stateHash).not.toBe(staleCheckpoint.stateHash);
    expect(advancedCheckpoint.stateHashVerified).toBe(true);

    const initialStrategyText = `Use a different ${modality} passive source before considering another retry.`;
    const initialStrategy = recovery.getByRole("textbox", { name: "Materially different in-scope strategy", exact: true });
    await interactionActivation.activate(activation(
      "run-recovery.strategy",
      "At least 12 normalized characters",
      modality,
      TEST_REPLAN,
    ), async () => {
      if (modality === "pointer") {
        await initialStrategy.click();
        await initialStrategy.fill(initialStrategyText);
      } else {
        await initialStrategy.focus();
        await page.keyboard.insertText(initialStrategyText);
      }
      await expect(initialStrategy).toHaveValue(initialStrategyText);
    });

    await interactionActivation.activate(activation(
      "run-recovery.replan",
      "Reject stale boundary with remediation",
      modality,
      TEST_REPLAN,
    ), async () => {
      const replan = recovery.getByRole("button", { name: "Request bounded replan", exact: true });
      const staleResponse = await mutationResponse(page, recoveryMutationPath(fixture, "replan"), async () => {
        if (modality === "pointer") {
          await replan.click();
        } else {
          await replan.focus();
          await page.keyboard.press("Enter");
        }
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
      expect(readRunInterventionRecoverySnapshot(fixture)).toMatchObject({
        run: { status: "blocked", version: 2 },
        audits: [],
        recoveryIdempotencyCount: 0,
      });
    });

    await audit.waitForPageApiSettlement(page);
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
    const refreshedRecovery = recoveryControls(page);
    const strategyText = `Correlate the ${modality} timeout with an independent passive source before any retry.`;
    const refreshedStrategy = refreshedRecovery.getByRole("textbox", { name: "Materially different in-scope strategy", exact: true });
    await interactionActivation.activate(activation(
      "run-recovery.strategy",
      "Stale-boundary retry after refresh",
      modality,
      TEST_REPLAN,
    ), async () => interactionActivation.activate(activation(
      "run-recovery.strategy",
      "Materially different strategy",
      modality,
      TEST_REPLAN,
    ), async () => {
      if (modality === "pointer") {
        await refreshedStrategy.click();
        await refreshedStrategy.fill(strategyText);
      } else {
        await refreshedStrategy.focus();
        await page.keyboard.insertText(strategyText);
      }
      await expect(refreshedStrategy).toHaveValue(strategyText);
    }));

    await interactionActivation.activate(activation(
      "run-recovery.replan",
      "Idempotently replay exact accepted request",
      modality,
      TEST_REPLAN,
    ), async () => {
      const proof = await interactionActivation.activate(activation(
        "run-recovery.replan",
        "Persist one bounded replan",
        modality,
        TEST_REPLAN,
      ), async () => {
        const replan = refreshedRecovery.getByRole("button", { name: "Request bounded replan", exact: true });
        const acceptedResponse = await mutationResponse(page, recoveryMutationPath(fixture, "replan"), async () => {
          if (modality === "pointer") {
            await replan.click();
          } else {
            await replan.focus();
            await page.keyboard.press("Enter");
          }
        });
        expect(acceptedResponse.status()).toBe(200);
        const acceptedBody = await acceptedResponse.json();
        expect(acceptedBody).toMatchObject({
          mutation: { kind: "replan", checkpointId: expect.any(String), continuationId: expect.any(String) },
          run: {
            id: fixture.runId,
            status: "recovering",
            planId: fixture.planId,
            planVersion: 1,
            stepId: fixture.stepId,
            assignmentId: fixture.assignmentId,
          },
        });
        expect(acceptedBody.run.version).toBeGreaterThan(staleVersion);
        return { acceptedResponse, acceptedBody };
      });

      await expect.poll(() => {
        const snapshot = readRunInterventionRecoverySnapshot(fixture);
        return {
          runStatus: snapshot.run.status,
          stepStatuses: snapshot.stepStatuses,
          assignmentStatuses: snapshot.assignments.map((assignment) => assignment.status),
          replanStarted: snapshot.events.some((event) => event.type === "run.replan_started"),
          guidedBlocked: snapshot.events.some((event) => event.type === "run.guided_blocked"),
          runtimeContinuationStatuses: snapshot.runtimeContinuationStatuses,
          executingChildCount: snapshot.executingChildCount,
          activeChildCount: snapshot.activeChildCount,
          failureDiagnosed: snapshot.audits.some((auditRecord) => auditRecord.action === "failure_diagnosis.created"),
        };
      }, { timeout: 7_500 }).toEqual({
        runStatus: "blocked",
        stepStatuses: ["failed"],
        assignmentStatuses: ["failed"],
        replanStarted: true,
        guidedBlocked: true,
        runtimeContinuationStatuses: ["completed"],
        executingChildCount: 0,
        activeChildCount: 1,
        failureDiagnosed: true,
      });

      const progressed = readRunInterventionRecoverySnapshot(fixture);
      expect(progressed.run.statusReason).toContain("isolated test boundary");
      expect(progressed.run.version).toBeGreaterThan(proof.acceptedBody.run.version);
      expect(progressed.events.some((event) => event.type === "run.replan_started")).toBe(true);
      expect(progressed.events.some((event) => event.type === "run.guided_blocked")).toBe(true);
      expect(progressed.audits).toContainEqual({ action: "run.replan_requested", reason: strategyText });
      expect(progressed.audits.some((auditRecord) => auditRecord.action === "failure_diagnosis.created")).toBe(true);
      expect(progressed.checkpoints).toContainEqual(expect.objectContaining({
        id: proof.acceptedBody.mutation.checkpointId,
        planVersion: 1,
        stateHashVerified: true,
        inFlightCount: 0,
      }));
      expect(progressed.recoveryIdempotencyCount).toBe(1);

      await audit.waitForPageApiSettlement(page);
      const replay = await replayCapturedMutation(
        page,
        audit,
        proof.acceptedResponse.request(),
        `run-recovery.replan-progressed-replay.${modality}`,
      );
      expect(replay).toMatchObject({
        status: 409,
        body: { error: { code: "recovery_idempotent_replay_stale", retryable: false } },
      });
      expect(readRunInterventionRecoverySnapshot(fixture)).toEqual(progressed);
    });

    await audit.waitForPageApiSettlement(page);
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
    await expect(page.getByLabel("Selected run status")).toContainText("blocked");
    expect(readRunInterventionRecoverySnapshot(fixture).executingChildCount).toBe(0);
  }

  await audit.assertClean(testInfo);
});

test(`${TEST_REASSIGN_TERMINATE} records both modalities for exact specialist reassignment and unavailable provider recovery`, async ({ page, interactionActivation }, testInfo) => {
  const fixtures = (["pointer", "keyboard"] as const).map((modality) => {
    const fixture = createRunInterventionRecoveryFixture(
      "reassign",
      canonicalFixtureNamespace(testInfo, `run-recovery-reassign-receipt-${modality}`),
    );
    refreshRunInterventionRecoveryAttestations(fixture);
    return { modality, fixture };
  });
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: fixtures.map(({ modality, fixture }) => ({
      id: `run-recovery.reassign-stale-version.${modality}`,
      transport: "api-request" as const,
      method: "POST",
      pathname: recoveryMutationPath(fixture, "reassign"),
      query: {},
      status: 409,
      occurrences: 1,
      reason: `Prove a fresh-key ${modality} replay cannot bypass the exact run-version boundary.`,
    })),
  });

  for (const { modality, fixture } of fixtures) {
    const route = liveRoute(fixture);
    if (page.url() === "about:blank") {
      await page.goto(route, { waitUntil: "domcontentloaded" });
    } else {
      await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(route, { waitUntil: "domcontentloaded" }));
    }

    const recovery = recoveryControls(page);
    await assertManifestControl(recovery, "run-recovery.reason");
    await assertManifestControl(recovery, "run-recovery.specialist");
    await assertManifestControl(recovery, "run-recovery.capability");
    await assertManifestControl(recovery, "run-recovery.reassign");
    await assertManifestControl(recovery, "run-recovery.change-provider");
    const before = readRunInterventionRecoverySnapshot(fixture);
    expect(before.run).toMatchObject({ status: "blocked", version: 1, controlPlane: "ti_scale" });
    const sourceCheckpoint = before.checkpoints.at(-1)!;
    expect(sourceCheckpoint.stateHashVerified).toBe(true);
    expect(sourceCheckpoint.inFlightCount).toBe(0);

    const reasonText = `Move the ${modality} fixture's exact stopped step to the attested alternate specialist.`;
    const reason = recovery.getByRole("textbox", { name: "Operator reason (audited)", exact: true });
    await interactionActivation.activate(activation(
      "run-recovery.reason",
      "Reassignment reason",
      modality,
      TEST_REASSIGN_TERMINATE,
    ), async () => {
      if (modality === "pointer") {
        await reason.click();
        await reason.fill(reasonText);
      } else {
        await reason.focus();
        await page.keyboard.insertText(reasonText);
      }
      await expect(reason).toHaveValue(reasonText);
    });

    const specialist = recovery.getByRole("combobox", { name: "Healthy capable specialist", exact: true });
    await interactionActivation.activate(activation(
      "run-recovery.specialist",
      "Choose a specialist",
      modality,
      TEST_REASSIGN_TERMINATE,
    ), async () => {
      await selectTitaniumOption(specialist, "", modality);
      await expect(specialist.locator("xpath=..").locator("select.os-titanium-select__form-proxy")).toHaveValue("");
    });
    await interactionActivation.activate(activation(
      "run-recovery.specialist",
      "Alternate recon specialist",
      modality,
      TEST_REASSIGN_TERMINATE,
    ), async () => {
      await selectTitaniumOption(specialist, fixture.candidateAgentId!, modality);
      await expect(specialist.locator("xpath=..").locator("select.os-titanium-select__form-proxy"))
        .toHaveValue(fixture.candidateAgentId!);
      await expect(specialist).toBeFocused();
    });

    const capability = recovery.getByRole("combobox", { name: "Declared shared capability", exact: true });
    await interactionActivation.activate(activation(
      "run-recovery.capability",
      "Choose a capability",
      modality,
      TEST_REASSIGN_TERMINATE,
    ), async () => {
      await selectTitaniumOption(capability, "", modality);
      await expect(capability.locator("xpath=..").locator("select.os-titanium-select__form-proxy")).toHaveValue("");
      await expect(capability).toBeFocused();
    });
    await interactionActivation.activate(activation(
      "run-recovery.capability",
      "network.recon",
      modality,
      TEST_REASSIGN_TERMINATE,
    ), async () => {
      await selectTitaniumOption(capability, "network.recon", modality);
      await expect(capability.locator("xpath=..").locator("select.os-titanium-select__form-proxy"))
        .toHaveValue("network.recon");
      await expect(capability).toBeFocused();
    });

    const provider = recovery.getByRole("button", { name: "Change provider", exact: true });
    await interactionActivation.activate(activation(
      "run-recovery.change-provider",
      "Unavailable without compatible callable provider",
      modality,
      TEST_REASSIGN_TERMINATE,
    ), async () => {
      await expect(provider).toBeDisabled();
      const providerRow = provider.locator("xpath=ancestor::li[1]");
      await expect(providerRow).toContainText("No healthy callable provider satisfies the journey and budget enforcement boundary.");
      if (modality === "pointer") {
        await provider.hover();
      } else {
        const reassign = recovery.getByRole("button", { name: "Reassign specialist", exact: true });
        await expect(reassign).toBeEnabled();
        await reassign.focus();
        await page.keyboard.press("Tab");
        await expect(provider).not.toBeFocused();
        await expect(recovery.getByRole("button", { name: "Terminate gracefully", exact: true })).toBeFocused();
      }
      expect(readRunInterventionRecoverySnapshot(fixture)).toEqual(before);
    });

    await interactionActivation.activate(activation(
      "run-recovery.reassign",
      "Idempotently replay exact accepted request",
      modality,
      TEST_REASSIGN_TERMINATE,
    ), async () => {
      const proof = await interactionActivation.activate(activation(
        "run-recovery.reassign",
        "Supersede exact Guided decision",
        modality,
        TEST_REASSIGN_TERMINATE,
      ), async () => interactionActivation.activate(activation(
        "run-recovery.reassign",
        "Replace only exact stopped assignment",
        modality,
        TEST_REASSIGN_TERMINATE,
      ), async () => {
        const reassign = recovery.getByRole("button", { name: "Reassign specialist", exact: true });
        const reassignedResponse = await mutationResponse(page, recoveryMutationPath(fixture, "reassign"), async () => {
          if (modality === "pointer") {
            await reassign.click();
          } else {
            await reassign.focus();
            await page.keyboard.press("Enter");
          }
        });
        expect(reassignedResponse.status()).toBe(200);
        const requestBody = reassignedResponse.request().postDataJSON() as Record<string, unknown>;
        expect(requestBody).toMatchObject({
          expectedRunVersion: before.run.version,
          expectedPlanId: fixture.planId,
          expectedPlanVersion: 1,
          expectedStepId: fixture.stepId,
          expectedAssignmentId: fixture.assignmentId,
          expectedCheckpointId: sourceCheckpoint.id,
          expectedCheckpointStateHash: sourceCheckpoint.stateHash,
          expectedCheckpointEventSequence: sourceCheckpoint.eventSequence,
          targetAgentId: fixture.candidateAgentId,
          capability: "network.recon",
          reason: reasonText,
          guidedDecisionId: fixture.decisionId,
          expectedDecisionFingerprint: expect.stringMatching(/^[a-f0-9]{64}$/u),
        });
        const reassignedBody = await reassignedResponse.json();
        expect(reassignedBody).toMatchObject({
          mutation: {
            kind: "reassign",
            agentId: fixture.candidateAgentId,
            assignmentId: expect.any(String),
            checkpointId: expect.any(String),
          },
          run: {
            id: fixture.runId,
            status: "blocked",
            planId: fixture.planId,
            planVersion: 1,
            stepId: fixture.stepId,
          },
        });

        const afterReassign = readRunInterventionRecoverySnapshot(fixture);
        expect(afterReassign.run).toMatchObject({ status: "blocked", controlPlane: "ti_scale", leaseOwner: null });
        expect(afterReassign.run.version).toBeGreaterThan(before.run.version);
        expect(afterReassign.assignments).toHaveLength(2);
        expect(afterReassign.assignments[0]).toMatchObject({
          id: fixture.assignmentId,
          agentId: fixture.agentId,
          status: "cancelled",
          leaseOwner: null,
        });
        expect(afterReassign.assignments[1]).toMatchObject({
          agentId: fixture.candidateAgentId,
          status: "queued",
          leaseOwner: null,
        });
        expect(afterReassign.decisionStatuses).toEqual(["cancelled", "pending"]);
        expect(afterReassign.executingChildCount).toBe(0);
        expect(afterReassign.events.some((event) => event.type === "run.specialist_reassigned")).toBe(true);
        expect(afterReassign.audits).toContainEqual({ action: "run.specialist_reassigned", reason: reasonText });
        expect(afterReassign.checkpoints.at(-1)).toMatchObject({
          planVersion: 1,
          stateHashVerified: true,
          inFlightCount: 0,
        });
        expect(afterReassign.recoveryIdempotencyCount).toBe(1);
        return { reassignedResponse, reassignedBody, afterReassign };
      }));

      await audit.waitForPageApiSettlement(page);
      const replay = await replayCapturedMutation(page, audit, proof.reassignedResponse.request());
      expect(replay).toEqual({ status: 200, body: proof.reassignedBody });
      expect(readRunInterventionRecoverySnapshot(fixture)).toEqual(proof.afterReassign);

      const stale = await mutateCapturedWithFreshIdempotencyKey(
        page,
        audit,
        proof.reassignedResponse.request(),
        `run-recovery.reassign-stale-version.${modality}`,
        `reassign-stale-${modality}-${fixture.runId}`,
      );
      expect(stale).toMatchObject({
        status: 409,
        body: {
          error: {
            code: "operations_state_conflict",
            humanMessage: "The run, plan, step, or assignment changed before the recovery mutation could be applied.",
            remediation: "Refresh the Recovery Panel and retry only against the current exact work boundary.",
          },
        },
      });
      expect(readRunInterventionRecoverySnapshot(fixture)).toEqual(proof.afterReassign);
    });

    await audit.waitForPageApiSettlement(page);
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
    await expect(page.getByLabel("Selected run status")).toContainText("blocked");
    await expect(recoveryControls(page).getByText(fixture.candidateAgentId!, { exact: true }).first()).toBeVisible();
    expect(readRunInterventionRecoverySnapshot(fixture).executingChildCount).toBe(0);
  }

  await audit.assertClean(testInfo);
});

test(`${TEST_RECOVERY_RETRY} preserves exact recovery intent across retryable errors, response loss, route reopen, material edits, and stale projection`, async ({ page, browserAudit, interactionActivation }, testInfo) => {
  test.setTimeout(240_000);
  const waitForDocumentSettlement = async (): Promise<void> => {
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 500 });
    const wordmark = page.locator('img[src$="/brand-v2/source/ti-scale-wordmark.svg"]').first();
    await expect(wordmark).toHaveJSProperty("complete", true);
    await expect.poll(
      () => wordmark.evaluate((image: HTMLImageElement) => image.naturalWidth),
    ).toBeGreaterThan(0);
  };
  const openDocument = async (url: string): Promise<void> => {
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.goto(url, { waitUntil: "domcontentloaded" }),
    );
    await waitForDocumentSettlement();
  };
  const reloadDocument = async (): Promise<void> => {
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.reload({ waitUntil: "domcontentloaded" }),
    );
    await waitForDocumentSettlement();
  };
  const retryableEnvelope = JSON.stringify({
    error: {
      code: "recovery_dependency_temporarily_unavailable",
      message: "The recovery dependency was temporarily unavailable",
      humanMessage: "The recovery service did not accept this exact request yet.",
      retryable: true,
      category: "dependency_unavailable",
      remediation: "Retry only the unchanged represented request after refreshing canonical state.",
      traceId: "trace-recovery-retry-fixture",
      timestamp: "2026-07-24T12:00:00.000Z",
    },
  });

  for (const modality of ["pointer", "keyboard"] as const) {
    const fixture = createRunInterventionRecoveryFixture(
      "reassign",
      canonicalFixtureNamespace(testInfo, `run-recovery-exact-retry-${modality}`),
    );
    refreshRunInterventionRecoveryAttestations(fixture);
    await openDocument(liveRoute(fixture));
    const reason = `Retry the ${modality} fixture's exact assignment without changing represented intent.`;
    await prepareExactReassignment(page, fixture, reason, modality);
    const pathname = recoveryMutationPath(fixture, "reassign");
    const captured: Array<{ readonly body: string | null; readonly key: string | undefined }> = [];
    const matcher = (url: URL) => url.pathname === pathname;
    await page.route(matcher, async (route) => {
      captured.push({
        body: route.request().postData(),
        key: route.request().headers()["idempotency-key"],
      });
      if (captured.length === 1) {
        await route.fulfill({ status: 503, contentType: "application/json", body: retryableEnvelope });
        return;
      }
      await route.continue();
    });
    browserAudit.expectHttpResponse(page, {
      id: `run-recovery.retryable-exact-reassignment.${modality}`,
      transport: "browser",
      method: "POST",
      pathname,
      query: {},
      status: 503,
      occurrences: 1,
      reason: "Prove one unchanged represented recovery request can be retried after a declared transient dependency failure.",
    });

    const before = readRunInterventionRecoverySnapshot(fixture);
    const rejected = await mutationResponse(page, pathname, async () => {
      await recoveryControls(page).getByRole("button", { name: "Reassign specialist", exact: true }).click();
    });
    expect(rejected.status()).toBe(503);
    expect(readRunInterventionRecoverySnapshot(fixture)).toEqual(before);
    await expect(recoveryControls(page).getByRole("alert")).toContainText(
      "The recovery service did not accept this exact request yet.",
    );
    await assertManifestControl(recoveryControls(page), "run-recovery.exact-attempt");
    await assertManifestControl(recoveryControls(page), "run-recovery.discard-attempt");
    if (modality === "pointer") {
      const exactAttempt = recoveryControls(page).locator(".os-recovery-mutation-attempt");
      await normalizeExactRecoveryAttemptVisual(exactAttempt);
      await expectApprovedRecoveryVisual(
        exactAttempt,
        testInfo,
        RECOVERY_VISUALS.exactAttempt,
      );
    }

    const accepted = await interactionActivation.activate(activation(
      "run-recovery.exact-attempt",
      "Retry canonical retryable response with exact body and key",
      modality,
      TEST_RECOVERY_RETRY,
    ), async () => mutationResponse(page, pathname, async () => {
      await activateExactAttempt(page, modality, "Retry exact recovery action");
    }));
    expect(accepted.status()).toBe(200);
    expect(captured).toHaveLength(2);
    expect(captured[1]).toEqual(captured[0]);
    const after = readRunInterventionRecoverySnapshot(fixture);
    expect(after.events.filter((event) => event.type === "run.specialist_reassigned")).toHaveLength(1);
    expect(after.audits.filter((audit) => audit.action === "run.specialist_reassigned")).toEqual([
      { action: "run.specialist_reassigned", reason },
    ]);
    expect(after.checkpoints).toHaveLength(before.checkpoints.length + 1);
    expect(after.eventOutboxCount).toBe(after.events.length);
    expect(after.recoveryIdempotencyCount).toBe(1);
    await expect(recoveryControls(page).getByRole("button", { name: "Retry exact recovery action", exact: true })).toHaveCount(0);
    await waitForDocumentSettlement();
    await page.unroute(matcher);
  }

  for (const modality of ["pointer", "keyboard"] as const) {
    const fixture = createRunInterventionRecoveryFixture(
      "reassign",
      canonicalFixtureNamespace(testInfo, `run-recovery-response-loss-${modality}`),
    );
    refreshRunInterventionRecoveryAttestations(fixture);
    await openDocument(liveRoute(fixture));
    const uncommittedReason = recoveryControls(page).getByRole("textbox", { name: "Operator reason (audited)", exact: true });
    await uncommittedReason.fill("This unsubmitted draft must not survive a route reopen.");
    await openDocument("/");
    await openDocument(liveRoute(fixture));
    await expect(recoveryControls(page).getByRole("textbox", { name: "Operator reason (audited)", exact: true })).toHaveValue("");
    expect(await page.evaluate(() => Object.keys(sessionStorage)
      .filter((key) => key.startsWith("ti-scale.recovery.mutation-intent.v1.")).length)).toBe(0);

    const reason = `Reconcile the committed ${modality} reassignment after its response is lost.`;
    await prepareExactReassignment(page, fixture, reason, modality);
    const pathname = recoveryMutationPath(fixture, "reassign");
    const captured: Array<{ readonly body: string | null; readonly key: string | undefined }> = [];
    let committedReceipt: unknown;
    const matcher = (url: URL) => url.pathname === pathname;
    await page.route(matcher, async (route) => {
      captured.push({
        body: route.request().postData(),
        key: route.request().headers()["idempotency-key"],
      });
      if (captured.length === 1) {
        const upstream = await route.fetch();
        committedReceipt = await upstream.json();
        await route.fulfill({ status: 200, contentType: "application/json", body: "{" });
        return;
      }
      await route.continue();
    });

    const lost = await mutationResponse(page, pathname, async () => {
      await recoveryControls(page).getByRole("button", { name: "Reassign specialist", exact: true }).click();
    });
    expect(lost.status()).toBe(200);
    await expect(recoveryControls(page).getByRole("button", {
      name: "Reconcile exact recovery attempt",
      exact: true,
    })).toBeVisible();
    const committed = readRunInterventionRecoverySnapshot(fixture);
    expect(committed.recoveryIdempotencyCount).toBe(1);
    expect(committed.audits.filter((audit) => audit.action === "run.specialist_reassigned")).toHaveLength(1);

    await waitForDocumentSettlement();
    await openDocument("/");
    await openDocument(liveRoute(fixture));
    await assertManifestControl(recoveryControls(page), "run-recovery.exact-attempt");
    const reconciled = await interactionActivation.activate(activation(
      "run-recovery.exact-attempt",
      "Reconcile committed response loss after route reopen",
      modality,
      TEST_RECOVERY_RETRY,
    ), async () => mutationResponse(page, pathname, async () => {
      await activateExactAttempt(page, modality, "Reconcile exact recovery attempt");
    }));
    expect(reconciled.status()).toBe(200);
    expect(await reconciled.json()).toEqual(committedReceipt);
    expect(captured).toHaveLength(2);
    expect(captured[1]).toEqual(captured[0]);
    const afterReplay = readRunInterventionRecoverySnapshot(fixture);
    expect(afterReplay.events).toEqual(committed.events);
    expect(afterReplay.audits).toEqual(committed.audits);
    expect(afterReplay.checkpoints).toEqual(committed.checkpoints);
    expect(afterReplay.eventOutboxCount).toBe(committed.eventOutboxCount);
    expect(afterReplay.recoveryIdempotencyCount).toBe(1);
    expect(await page.evaluate(() => Object.keys(sessionStorage)
      .filter((key) => key.startsWith("ti-scale.recovery.mutation-intent.v1.")).length)).toBe(0);
    await waitForDocumentSettlement();
    await page.unroute(matcher);
  }

  for (const modality of ["pointer", "keyboard"] as const) {
    const fixture = createRunInterventionRecoveryFixture(
      "reassign",
      canonicalFixtureNamespace(testInfo, `run-recovery-material-edit-${modality}`),
    );
    refreshRunInterventionRecoveryAttestations(fixture);
    await openDocument(liveRoute(fixture));
    await prepareExactReassignment(
      page,
      fixture,
      `Represent the first ${modality} reassignment request.`,
      modality,
    );
    const pathname = recoveryMutationPath(fixture, "reassign");
    const captured: Array<{ readonly body: string | null; readonly key: string | undefined }> = [];
    const matcher = (url: URL) => url.pathname === pathname;
    await page.route(matcher, async (route) => {
      captured.push({
        body: route.request().postData(),
        key: route.request().headers()["idempotency-key"],
      });
      if (captured.length === 1) {
        await route.fulfill({ status: 503, contentType: "application/json", body: retryableEnvelope });
        return;
      }
      await route.continue();
    });
    browserAudit.expectHttpResponse(page, {
      id: `run-recovery.retryable-material-edit.${modality}`,
      transport: "browser",
      method: "POST",
      pathname,
      query: {},
      status: 503,
      occurrences: 1,
      reason: "Prove a failed represented recovery attempt must be discarded before a materially changed request is submitted.",
    });
    await mutationResponse(page, pathname, async () => {
      await recoveryControls(page).getByRole("button", { name: "Reassign specialist", exact: true }).click();
    });
    const discard = recoveryControls(page).getByRole("button", {
      name: "Discard attempt and review current state",
      exact: true,
    });
    await interactionActivation.activate(activation(
      "run-recovery.discard-attempt",
      "Discard exact attempt before material edit",
      modality,
      TEST_RECOVERY_RETRY,
    ), async () => {
      if (modality === "pointer") await discard.click();
      else {
        await discard.focus();
        await page.keyboard.press("Enter");
      }
    });
    const changedReason = `Represent a materially changed ${modality} reassignment after fresh review.`;
    await recoveryControls(page).getByRole("textbox", {
      name: "Operator reason (audited)",
      exact: true,
    }).fill(changedReason);
    const accepted = await mutationResponse(page, pathname, async () => {
      await recoveryControls(page).getByRole("button", { name: "Reassign specialist", exact: true }).click();
    });
    expect(accepted.status()).toBe(200);
    expect(captured).toHaveLength(2);
    expect(captured[1]?.key).not.toBe(captured[0]?.key);
    expect(captured[1]?.body).not.toBe(captured[0]?.body);
    expect(JSON.parse(captured[1]!.body!).reason).toBe(changedReason);
    expect(readRunInterventionRecoverySnapshot(fixture).recoveryIdempotencyCount).toBe(1);
    await waitForDocumentSettlement();
    await page.unroute(matcher);
  }

  const staleFixture = createRunInterventionRecoveryFixture(
    "reassign",
    canonicalFixtureNamespace(testInfo, "run-recovery-stale-retry"),
  );
  refreshRunInterventionRecoveryAttestations(staleFixture);
  await openDocument(liveRoute(staleFixture));
  await prepareExactReassignment(page, staleFixture, "Retain this retry only for the exact current boundary.", "pointer");
  const stalePath = recoveryMutationPath(staleFixture, "reassign");
  let stalePosts = 0;
  const staleMatcher = (url: URL) => url.pathname === stalePath;
  await page.route(staleMatcher, async (route) => {
    stalePosts += 1;
    await route.fulfill({ status: 503, contentType: "application/json", body: retryableEnvelope });
  });
  browserAudit.expectHttpResponse(page, {
    id: "run-recovery.retryable-stale-projection",
    transport: "browser",
    method: "POST",
    pathname: stalePath,
    query: {},
    status: 503,
    occurrences: 1,
    reason: "Prove a retained recovery attempt is removed when the canonical run version advances.",
  });
  await mutationResponse(page, stalePath, async () => {
    await recoveryControls(page).getByRole("button", { name: "Reassign specialist", exact: true }).click();
  });
  advanceRunInterventionRecoveryVersion(staleFixture);
  await reloadDocument();
  await expect(recoveryControls(page).getByText("Fresh review required.", { exact: false })).toBeVisible();
  await expect(recoveryControls(page).getByRole("button", { name: "Retry exact recovery action", exact: true })).toHaveCount(0);
  expect(stalePosts).toBe(1);
  expect(await page.evaluate(() => Object.keys(sessionStorage)
    .filter((key) => key.startsWith("ti-scale.recovery.mutation-intent.v1.")).length)).toBe(0);
  await page.unroute(staleMatcher);

  const storedRecordFixture = createRunInterventionRecoveryFixture(
    "reassign",
    canonicalFixtureNamespace(testInfo, "run-recovery-invalid-stored-records"),
  );
  refreshRunInterventionRecoveryAttestations(storedRecordFixture);
  await openDocument(liveRoute(storedRecordFixture));
  await prepareExactReassignment(
    page,
    storedRecordFixture,
    "Retain one exact attempt only to verify hostile session records are discarded.",
    "pointer",
  );
  const storedRecordPath = recoveryMutationPath(storedRecordFixture, "reassign");
  let storedRecordPosts = 0;
  const storedRecordMatcher = (url: URL) => url.pathname === storedRecordPath;
  await page.route(storedRecordMatcher, async (route) => {
    storedRecordPosts += 1;
    await route.fulfill({ status: 503, contentType: "application/json", body: retryableEnvelope });
  });
  browserAudit.expectHttpResponse(page, {
    id: "run-recovery.retryable-invalid-stored-record",
    transport: "browser",
    method: "POST",
    pathname: storedRecordPath,
    query: {},
    status: 503,
    occurrences: 1,
    reason: "Prove hostile or stale stored recovery records cannot replay an earlier transiently failed request.",
  });
  await mutationResponse(page, storedRecordPath, async () => {
    await recoveryControls(page).getByRole("button", { name: "Reassign specialist", exact: true }).click();
  });
  await expect(recoveryControls(page).getByRole("button", {
    name: "Retry exact recovery action",
    exact: true,
  })).toBeVisible();
  await waitForDocumentSettlement();
  const storedRecord = await page.evaluate((prefix) => {
    const key = Object.keys(sessionStorage).find((candidate) => candidate.startsWith(prefix));
    if (!key) throw new Error("The exact recovery attempt was not persisted");
    const raw = sessionStorage.getItem(key);
    if (!raw) throw new Error("The exact recovery attempt payload is missing");
    return { key, raw };
  }, `${BROWSER_STORAGE_KEYS.recoveryMutationIntentPrefix}.`);

  for (const variant of [
    "malformed",
    "expired",
    "hash_mutated",
    "cross_actor",
    "secret_bearing",
  ] as const) {
    await installInvalidStoredRecoveryAttempt(page, storedRecord.key, storedRecord.raw, variant);
    await reloadDocument();
    await expect.poll(() => page.evaluate(
      (storageKey) => sessionStorage.getItem(storageKey),
      storedRecord.key,
    )).toBeNull();
    await expect(recoveryControls(page).getByRole("button", {
      name: /^(?:Retry exact recovery action|Reconcile exact recovery attempt)$/u,
    })).toHaveCount(0);
    await expect(recoveryControls(page).getByRole("textbox", {
      name: "Operator reason (audited)",
      exact: true,
    })).toBeEnabled();
  }
  expect(storedRecordPosts).toBe(1);
  await page.unroute(storedRecordMatcher);
});

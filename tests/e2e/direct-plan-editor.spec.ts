import { expect, test, type Locator, type Page, type Response } from "./support/playwright";
import { readFileSync } from "node:fs";
import { MissionIntakeService } from "../../server/intake";
import type { RuntimeSourceManifests } from "../../server/domain/source-manifest-adapters";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createPlanChangeFixture,
  readPlanChangeFixtureSnapshot,
  refreshPlanChangeFixtureAgents,
  type PlanChangeFixture,
} from "./support/planChangeFixture";

const TEST_ID = "e2e.plan-direct.proposals";
const DIRECT_EDIT_TEST_ID = "e2e.plan-direct.edit-revalidate";
const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

interface ProposalResponse {
  readonly schemaVersion: "2.4";
  readonly request: {
    readonly id: string;
    readonly status: string;
    readonly version?: number;
    readonly normalizedChange: { readonly operations: readonly unknown[] };
    readonly structuredDiff?: readonly { readonly path: string; readonly after: unknown }[];
  };
}

function directControl(page: Page, controlId: string): Locator {
  return page.locator(`[data-control-id="${controlId}"]`);
}

async function activateVisiblePointerTarget(control: Locator): Promise<void> {
  await control.evaluate((element) => element.scrollIntoView({ block: "center", inline: "nearest", behavior: "auto" }));
  await expect(control).toBeInViewport();
  await expect.poll(
    () => control.evaluate((element) => {
      const bounds = element.getBoundingClientRect();
      const x = Math.max(0, Math.min(window.innerWidth - 1, bounds.left + (bounds.width / 2)));
      const y = Math.max(0, Math.min(window.innerHeight - 1, bounds.top + (bounds.height / 2)));
      const hit = document.elementFromPoint(x, y);
      return hit === element || (hit !== null && element.contains(hit));
    }),
    { message: "The represented pointer target must not be covered by sticky shell or form content", timeout: 3_000 },
  ).toBe(true);
  const bounds = await control.boundingBox();
  expect(bounds, "The represented pointer target must retain concrete viewport geometry").not.toBeNull();
  if (!bounds) return;
  // Locator.click() performs another scrollIntoViewIfNeeded after the verified
  // hit test, which can relocate a fully reachable control beneath a sticky
  // shell in compact Chromium. Dispatch a normal pointer at the already
  // verified center so the test exercises the same visible hit target a human
  // would, without force-clicking or bypassing document hit testing.
  await control.page().mouse.click(bounds.x + (bounds.width / 2), bounds.y + (bounds.height / 2));
}

async function assertManifestControls(page: Page, ids: readonly string[]): Promise<void> {
  for (const id of ids) {
    const entry = manifest.entries.find((candidate) => candidate.id === id);
    if (!entry) throw new Error(`Direct editor manifest entry ${id} is missing`);
    if (!entry.accessible.role) throw new Error(`Direct editor manifest entry ${id} is not role-addressable`);
    const name = entry.accessible.match === "regex"
      ? new RegExp(entry.accessible.name)
      : entry.accessible.name;
    const controls = page.getByRole(entry.accessible.role, {
      name,
      exact: entry.accessible.match === "exact",
    });
    const count = await controls.count();
    expect(count, `${id} must resolve through its declared accessible role and name`).toBeGreaterThan(0);
    for (let index = 0; index < count; index += 1) await expect(controls.nth(index), id).toBeVisible();
  }
}

function route(fixture: PlanChangeFixture): string {
  return `/missions/${encodeURIComponent(fixture.missionId)}/runs/${encodeURIComponent(fixture.runId)}?tab=plan`;
}

function endpoint(fixture: PlanChangeFixture): string {
  return `/api/v2/runs/${encodeURIComponent(fixture.runId)}/plan-changes`;
}

function isCreateResponse(response: Response, fixture: PlanChangeFixture): boolean {
  return new URL(response.url()).pathname === endpoint(fixture)
    && response.request().method() === "POST";
}

function runtimeManifests(fixture: PlanChangeFixture): RuntimeSourceManifests {
  if (!fixture.alternateAgentId) throw new Error("The direct editor fixture requires its alternate specialist");
  const actionClassIds = [
    "passive_intelligence_osint",
    "dns_domain_certificate_discovery",
    "web_crawling_page_capture",
  ] as const;
  return {
    riskClasses: [{ id: "read-only", label: "Read only", actionClassIds }],
    evidenceKinds: [],
    capabilities: [],
    tools: actionClassIds.map((actionClassId) => ({
      id: `fixture-tool-${actionClassId}`,
      label: `Fixture ${actionClassId}`,
      available: true,
      locallyPolicyEnforced: true,
      requiresModel: false,
      actionClassIds: [actionClassId],
      evidenceTypeIds: actionClassId === "dns_domain_certificate_discovery"
        ? ["dns_certificate_record"]
        : actionClassId === "web_crawling_page_capture"
          ? ["web_page_capture"]
          : ["asset_discovery_proof"],
      riskClassIds: ["read-only"],
    })),
    mcpServers: [],
    agents: [
      {
        id: fixture.agentId,
        label: "Recon specialist",
        available: true,
        capabilityIds: [],
        actionClassIds: ["passive_intelligence_osint", "dns_domain_certificate_discovery"],
        toolIds: [
          "fixture-tool-passive_intelligence_osint",
          "fixture-tool-dns_domain_certificate_discovery",
        ],
        modelRefs: [],
      },
      {
        id: fixture.alternateAgentId,
        label: "Web assessment specialist",
        available: true,
        capabilityIds: [],
        actionClassIds: ["web_crawling_page_capture", "dns_domain_certificate_discovery"],
        toolIds: [
          "fixture-tool-web_crawling_page_capture",
          "fixture-tool-dns_domain_certificate_discovery",
        ],
        modelRefs: [],
      },
    ],
    providers: [],
  };
}

async function installCanonicalRegistry(page: Page, fixture: PlanChangeFixture): Promise<void> {
  const intake = new MissionIntakeService({ readRuntimeManifests: () => runtimeManifests(fixture) });
  const snapshot = intake.snapshot("guided", "custom");
  expect(snapshot.source.status).toBe("live");
  expect(snapshot.actionClasses.classes.passive_intelligence_osint.capability.availability).toBe("supported");
  await page.route("**/api/v2/registries/intake?*", async (requestRoute) => {
    expect(requestRoute.request().method()).toBe("GET");
    const url = new URL(requestRoute.request().url());
    expect(url.searchParams.get("journey")).toBe("guided");
    expect(url.searchParams.get("templateId")).toBe("custom");
    await requestRoute.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(snapshot) });
  });
}

async function setReason(page: Page, value: string): Promise<void> {
  const reason = directControl(page, "plan-direct-change-reason");
  await reason.focus();
  await expect(reason).toBeFocused();
  await reason.fill(value);
}

async function selectMode(page: Page, mode: string): Promise<void> {
  const control = directControl(page, "plan-direct-editor-mode");
  await control.focus();
  await expect(control).toBeFocused();
  await control.selectOption(mode);
}

async function createProposal(
  page: Page,
  fixture: PlanChangeFixture,
  submitControlId: string,
  expectedBody: unknown,
): Promise<ProposalResponse> {
  const submit = directControl(page, submitControlId);
  await expect(submit).toBeEnabled();
  refreshPlanChangeFixtureAgents(fixture);
  const pending = page.waitForResponse((response) => isCreateResponse(response, fixture));
  await submit.focus();
  await expect(submit).toBeFocused();
  await page.keyboard.press("Enter");
  const response = await pending;
  expect(response.status(), await response.text()).toBe(201);
  expect(response.headers()["idempotency-replayed"]).toBe("false");
  expect(response.request().postDataJSON()).toEqual(expectedBody);
  const body = await response.json() as ProposalResponse;
  expect(body.schemaVersion).toBe("2.4");
  expect(body.request.normalizedChange.operations).toEqual(
    (expectedBody as { operations: readonly unknown[] }).operations,
  );
  await expect(page.getByRole("status").filter({ hasText: "Review proposal created." })).toContainText(body.request.id);
  return body;
}

test(`${TEST_ID} creates six exact graph proposals through the real service without applying or executing`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const fixture = createPlanChangeFixture(
    "direct_editor",
    canonicalFixtureNamespace(testInfo, TEST_ID),
  );
  if (!fixture.stepThreeId || !fixture.alternateAgentId) throw new Error("Direct editor fixture did not create its third step and specialist");
  await installCanonicalRegistry(page, fixture);

  const directEntries = manifest.entries.filter((entry) => entry.id.startsWith("plan-direct."));
  expect(directEntries).toHaveLength(46);
  expect(new Set(directEntries.flatMap((entry) => entry.testIds))).toEqual(new Set([TEST_ID]));
  await testInfo.attach("direct-plan-editor-manifest-coverage.json", {
    body: Buffer.from(JSON.stringify({ entries: directEntries.map((entry) => entry.id) }, null, 2)),
    contentType: "application/json",
  });

  let applyRequests = 0;
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (request.method() === "POST" && url.pathname.endsWith("/apply")) applyRequests += 1;
  });

  await page.goto(route(fixture), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { level: 1, name: fixture.missionName, exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { level: 3, name: "Edit the plan graph without executing it", exact: true })).toBeVisible();
  await expect(page.getByText("Live ActionClassRegistry", { exact: true })).toBeVisible();
  await assertManifestControls(page, [
    "plan-direct.mode",
    "plan-direct.reason",
    ...directEntries.filter((entry) => entry.id.startsWith("plan-direct.add.")).map((entry) => entry.id),
  ]);

  const target = fixture.target;
  const commonBody = {
    basePlanId: fixture.planId,
    expectedRunVersion: fixture.runVersion,
    expectedPlanVersion: fixture.planVersion,
  } as const;
  const createdIds: string[] = [];

  await setReason(page, "Add one attributable application discovery step after the represented recon sequence.");
  await directControl(page, "plan-direct-add-id").fill("draft-http-metadata");
  await directControl(page, "plan-direct-add-after").selectOption(fixture.stepThreeId);
  await directControl(page, "plan-direct-add-phase").fill("Application discovery");
  await directControl(page, "plan-direct-add-title").fill("Collect bounded HTTP metadata");
  await directControl(page, "plan-direct-add-objective").fill("Collect attributable response metadata from the exact authorized target.");
  await directControl(page, "plan-direct-add-criteria").fill("Response metadata is attributable\nNo target state is changed");
  await directControl(page, "plan-direct-add-action-class").selectOption("passive_intelligence_osint");
  await directControl(page, "plan-direct-add-agent").selectOption(fixture.agentId);
  for (const stepId of [fixture.stepOneId, fixture.stepTwoId]) {
    const dependency = directControl(page, `plan-direct-add-dependency-${stepId}`);
    await dependency.focus();
    await expect(dependency).toBeFocused();
    await page.keyboard.press("Space");
    await expect(dependency).toBeChecked();
  }
  const defaultDependency = directControl(page, `plan-direct-add-dependency-${fixture.stepThreeId}`);
  await expect(defaultDependency).toBeChecked();
  await defaultDependency.uncheck();
  await defaultDependency.focus();
  await page.keyboard.press("Space");
  await expect(defaultDependency).toBeChecked();
  await directControl(page, "plan-direct-add-action-action-type").fill("http_metadata_collection");
  await directControl(page, "plan-direct-add-action-kind").selectOption("tool");
  await directControl(page, "plan-direct-add-action-target").fill(target);
  await directControl(page, "plan-direct-add-action-arguments").fill('{"timeoutSeconds":15,"path":"/"}');
  await directControl(page, "plan-direct-add-action-intent").fill("Collect bounded response metadata from the authorized application.");
  await directControl(page, "plan-direct-add-action-idempotent").check();
  await directControl(page, "plan-direct-add-action-explanation").fill("Read the approved application response metadata once.");
  await directControl(page, "plan-direct-add-action-rationale").fill("Observed HTTP metadata reduces uncertainty without changing target state.");
  await directControl(page, "plan-direct-add-action-reversibility").fill("Read-only request; stop on instability.");
  const addOperation = {
    kind: "add_step",
    clientStepId: "draft-http-metadata",
    afterStepId: fixture.stepThreeId,
    phase: "Application discovery",
    title: "Collect bounded HTTP metadata",
    objective: "Collect attributable response metadata from the exact authorized target.",
    successCriteria: ["Response metadata is attributable", "No target state is changed"],
    dependencyStepIds: [fixture.stepOneId, fixture.stepTwoId, fixture.stepThreeId],
    actionClass: "passive_intelligence_osint",
    riskClass: "low",
    assignedAgentId: fixture.agentId,
    representation: {
      action: {
        actionType: "http_metadata_collection",
        target,
        arguments: { timeoutSeconds: 15, path: "/" },
        intentSummary: "Collect bounded response metadata from the authorized application.",
        kind: "tool",
        idempotent: true,
        destructive: false,
      },
      explanation: "Read the approved application response metadata once.",
      rationale: "Observed HTTP metadata reduces uncertainty without changing target state.",
      reversibility: "Read-only request; stop on instability.",
    },
  } as const;
  createdIds.push((await createProposal(page, fixture, "plan-direct-add-submit", {
    ...commonBody,
    requestText: "Add one attributable application discovery step after the represented recon sequence.",
    operations: [addOperation],
  })).request.id);

  await selectMode(page, "update");
  await assertManifestControls(page, [
    "plan-direct.step",
    ...directEntries.filter((entry) => entry.id.startsWith("plan-direct.update.")).map((entry) => entry.id),
  ]);
  await setReason(page, "Refine the DNS step wording and assign the specialist best suited to the verified application context.");
  await directControl(page, "plan-direct-step").selectOption(fixture.stepTwoId);
  await directControl(page, "plan-direct-update-phase").fill("Correlated discovery");
  await directControl(page, "plan-direct-update-title").fill("Correlate approved DNS records");
  await directControl(page, "plan-direct-update-objective").fill("Correlate only names attributable to the exact approved target.");
  await directControl(page, "plan-direct-update-criteria").fill("Approved names are attributable\nConflicts remain visible");
  await directControl(page, "plan-direct-update-action-class").selectOption("web_crawling_page_capture");
  await directControl(page, "plan-direct-update-action-class").selectOption("dns_domain_certificate_discovery");
  await directControl(page, "plan-direct-update-agent").selectOption(fixture.alternateAgentId);
  const updateOperation = {
    kind: "update_step",
    stepId: fixture.stepTwoId,
    phase: "Correlated discovery",
    title: "Correlate approved DNS records",
    objective: "Correlate only names attributable to the exact approved target.",
    successCriteria: ["Approved names are attributable", "Conflicts remain visible"],
    assignedAgentId: fixture.alternateAgentId,
  } as const;
  createdIds.push((await createProposal(page, fixture, "plan-direct-update-submit", {
    ...commonBody,
    requestText: "Refine the DNS step wording and assign the specialist best suited to the verified application context.",
    operations: [updateOperation],
  })).request.id);

  await selectMode(page, "dependencies");
  await assertManifestControls(page, directEntries
    .filter((entry) => entry.id === "plan-direct.step" || entry.id.startsWith("plan-direct.dependencies."))
    .map((entry) => entry.id));
  await setReason(page, "Make target identity an explicit prerequisite for the independent application metadata step.");
  await directControl(page, "plan-direct-step").selectOption(fixture.stepThreeId);
  const firstDependency = directControl(page, `plan-direct-dependency-${fixture.stepOneId}`);
  const secondDependency = directControl(page, `plan-direct-dependency-${fixture.stepTwoId}`);
  await secondDependency.focus();
  await page.keyboard.press("Space");
  await firstDependency.focus();
  await page.keyboard.press("Space");
  await expect(firstDependency).toBeChecked();
  await expect(secondDependency).toBeChecked();
  await firstDependency.uncheck();
  await firstDependency.check();
  const dependencyOperation = { kind: "set_dependencies", stepId: fixture.stepThreeId, dependencyStepIds: [fixture.stepOneId, fixture.stepTwoId] } as const;
  createdIds.push((await createProposal(page, fixture, "plan-direct-dependencies-submit", {
    ...commonBody,
    requestText: "Make target identity an explicit prerequisite for the independent application metadata step.",
    operations: [dependencyOperation],
  })).request.id);

  await selectMode(page, "reorder");
  await assertManifestControls(page, directEntries
    .filter((entry) => entry.id.startsWith("plan-direct.reorder."))
    .map((entry) => entry.id));
  await setReason(page, "Place independent application metadata before DNS correlation while retaining every dependency boundary.");
  const reorderButtons = page.locator('[data-control-id^="plan-direct-reorder-up-"], [data-control-id^="plan-direct-reorder-down-"]');
  await expect(reorderButtons).toHaveCount(6);
  await expect(directControl(page, `plan-direct-reorder-down-${fixture.stepTwoId}`)).toBeEnabled();
  await activateVisiblePointerTarget(directControl(page, `plan-direct-reorder-down-${fixture.stepTwoId}`));
  await expect(directControl(page, "plan-direct-reorder-reset")).toBeEnabled();
  await directControl(page, "plan-direct-reorder-reset").focus();
  await page.keyboard.press("Enter");
  await expect(directControl(page, "plan-direct-reorder-reset")).toBeDisabled();
  await directControl(page, `plan-direct-reorder-up-${fixture.stepThreeId}`).focus();
  await page.keyboard.press("Enter");
  const reorderOperation = {
    kind: "reorder_steps",
    orderedStepIds: [fixture.stepOneId, fixture.stepThreeId, fixture.stepTwoId],
  } as const;
  createdIds.push((await createProposal(page, fixture, "plan-direct-reorder-submit", {
    ...commonBody,
    requestText: "Place independent application metadata before DNS correlation while retaining every dependency boundary.",
    operations: [reorderOperation],
  })).request.id);

  await selectMode(page, "remove");
  await assertManifestControls(page, directEntries
    .filter((entry) => entry.id === "plan-direct.step" || entry.id.startsWith("plan-direct.remove."))
    .map((entry) => entry.id));
  await setReason(page, "Remove the independent application metadata hypothesis because current evidence makes it unnecessary.");
  await directControl(page, "plan-direct-step").selectOption(fixture.stepThreeId);
  await directControl(page, "plan-direct-remove-reason").fill("The represented step is independent and no longer reduces uncertainty.");
  const removeOperation = {
    kind: "remove_step",
    stepId: fixture.stepThreeId,
    reason: "The represented step is independent and no longer reduces uncertainty.",
  } as const;
  createdIds.push((await createProposal(page, fixture, "plan-direct-remove-submit", {
    ...commonBody,
    requestText: "Remove the independent application metadata hypothesis because current evidence makes it unnecessary.",
    operations: [removeOperation],
  })).request.id);

  await selectMode(page, "represented_action");
  await assertManifestControls(page, directEntries
    .filter((entry) => entry.id === "plan-direct.step" || entry.id.startsWith("plan-direct.action."))
    .map((entry) => entry.id));
  await setReason(page, "Make the first step's exact represented action and rollback language match the bounded observation method.");
  await directControl(page, "plan-direct-step").selectOption(fixture.stepOneId);
  await directControl(page, "plan-direct-existing-action-action-type").fill("passive_scope_revalidation");
  await directControl(page, "plan-direct-existing-action-kind").selectOption("tool");
  await directControl(page, "plan-direct-existing-action-target").fill(target);
  await directControl(page, "plan-direct-existing-action-arguments").fill('{"sources":["registry","scope"]}');
  await directControl(page, "plan-direct-existing-action-intent").fill("Revalidate attributable target identity using bounded local sources.");
  await directControl(page, "plan-direct-existing-action-idempotent").uncheck();
  await directControl(page, "plan-direct-existing-action-explanation").fill("Recheck which approved identity belongs to the target.");
  await directControl(page, "plan-direct-existing-action-rationale").fill("A fresh attributable identity check prevents later work from drifting outside scope.");
  await directControl(page, "plan-direct-existing-action-reversibility").fill("Read-only lookup; retain the prior represented action until review.");
  const actionOperation = {
    kind: "set_represented_action",
    stepId: fixture.stepOneId,
    representation: {
      action: {
        actionType: "passive_scope_revalidation",
        target,
        arguments: { sources: ["registry", "scope"] },
        intentSummary: "Revalidate attributable target identity using bounded local sources.",
        kind: "tool",
        idempotent: false,
        destructive: false,
      },
      explanation: "Recheck which approved identity belongs to the target.",
      rationale: "A fresh attributable identity check prevents later work from drifting outside scope.",
      reversibility: "Read-only lookup; retain the prior represented action until review.",
    },
  } as const;
  createdIds.push((await createProposal(page, fixture, "plan-direct-action-submit", {
    ...commonBody,
    requestText: "Make the first step's exact represented action and rollback language match the bounded observation method.",
    operations: [actionOperation],
  })).request.id);

  expect(createdIds).toHaveLength(6);
  expect(new Set(createdIds).size).toBe(6);
  expect(applyRequests).toBe(0);
  const beforeRefresh = readPlanChangeFixtureSnapshot(fixture);
  expect(beforeRefresh).toMatchObject({
    run: { status: "queued", currentPlanId: fixture.planId, version: 1, replanCount: 0, leaseOwner: null },
    actionCount: 0,
  });
  expect(beforeRefresh.plans).toEqual([expect.objectContaining({ id: fixture.planId, status: "active", version: 1 })]);
  expect(beforeRefresh.requests).toHaveLength(6);
  expect(beforeRefresh.requests.every((request) => request.status === "validated" && request.resultPlanId === null)).toBe(true);

  // Assert the settled state before the deliberate full-page refresh. The
  // shared context audit remains authoritative across the reload; only the
  // exact navigation teardown window is prospectively bounded.
  await audit.assertClean(testInfo);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  const refreshAudit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await expect(page.getByRole("heading", { level: 3, name: "Edit the plan graph without executing it", exact: true })).toBeVisible();
  for (const requestId of createdIds) {
    await expect(page.locator(".os-plan-change-card").filter({ hasText: `Proposal ${requestId}` })).toBeVisible();
  }
  expect(readPlanChangeFixtureSnapshot(fixture).actionCount).toBe(0);
  expect(applyRequests).toBe(0);
  await refreshAudit.assertClean(testInfo);
});

test(`${DIRECT_EDIT_TEST_ID} revises and revalidates one exact direct proposal without applying or executing`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const fixture = createPlanChangeFixture(
    "direct_edit",
    canonicalFixtureNamespace(testInfo, DIRECT_EDIT_TEST_ID),
  );
  if (!fixture.alternateAgentId) throw new Error("Direct proposal edit fixture did not create its alternate specialist");
  await installCanonicalRegistry(page, fixture);

  const editManifestIds = [
    "plan-change.direct-edit.open",
    "plan-change.direct-edit.cancel",
    "plan-change.direct-edit.submit",
  ] as const;
  for (const id of editManifestIds) {
    const entry = manifest.entries.find((candidate) => candidate.id === id);
    expect(entry, `${id} must be registered`).toBeDefined();
    expect(entry?.testIds).toContain(DIRECT_EDIT_TEST_ID);
  }
  await testInfo.attach("direct-proposal-edit-manifest-coverage.json", {
    body: Buffer.from(JSON.stringify({ entries: editManifestIds }, null, 2)),
    contentType: "application/json",
  });

  let applyRequests = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && new URL(request.url()).pathname.endsWith("/apply")) applyRequests += 1;
  });

  await page.goto(route(fixture), { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { level: 3, name: "Edit the plan graph without executing it", exact: true })).toBeVisible();
  const target = fixture.target;
  const reason = "Represent the exact bounded identity check before any plan version can be activated.";
  await selectMode(page, "represented_action");
  await setReason(page, reason);
  await directControl(page, "plan-direct-step").selectOption(fixture.stepOneId);
  await directControl(page, "plan-direct-existing-action-action-type").fill("passive_scope_revalidation");
  await directControl(page, "plan-direct-existing-action-kind").selectOption("tool");
  await directControl(page, "plan-direct-existing-action-target").fill(target);
  await directControl(page, "plan-direct-existing-action-arguments").fill('{"sources":["registry","scope"]}');
  await directControl(page, "plan-direct-existing-action-intent").fill("Revalidate attributable target identity using bounded local sources.");
  await directControl(page, "plan-direct-existing-action-idempotent").uncheck();
  await directControl(page, "plan-direct-existing-action-explanation").fill("Recheck which approved identity belongs to the target.");
  await directControl(page, "plan-direct-existing-action-rationale").fill("A fresh identity check prevents later work from drifting outside scope.");
  await directControl(page, "plan-direct-existing-action-reversibility").fill("Read-only lookup; retain the prior representation until review.");
  const originalOperation = {
    kind: "set_represented_action",
    stepId: fixture.stepOneId,
    representation: {
      action: {
        actionType: "passive_scope_revalidation",
        target,
        arguments: { sources: ["registry", "scope"] },
        intentSummary: "Revalidate attributable target identity using bounded local sources.",
        kind: "tool",
        idempotent: false,
        destructive: false,
      },
      explanation: "Recheck which approved identity belongs to the target.",
      rationale: "A fresh identity check prevents later work from drifting outside scope.",
      reversibility: "Read-only lookup; retain the prior representation until review.",
    },
  } as const;
  const created = await createProposal(page, fixture, "plan-direct-action-submit", {
    basePlanId: fixture.planId,
    expectedRunVersion: fixture.runVersion,
    expectedPlanVersion: fixture.planVersion,
    requestText: reason,
    operations: [originalOperation],
  });
  const requestId = created.request.id;
  const card = page.locator(".os-plan-change-card").filter({ hasText: `Proposal ${requestId}` });
  await expect(card).toBeVisible();
  await expect(card.getByRole("textbox", { name: `Revised strategy summary for ${requestId}`, exact: true })).toHaveCount(0);

  const openEdit = card.getByRole("button", { name: `Edit exact represented action in ${requestId}`, exact: true });
  await openEdit.focus();
  await expect(openEdit).toBeFocused();
  await page.keyboard.press("Enter");
  const editHeading = page.getByRole("heading", { level: 3, name: "Revise this structured proposal without applying it", exact: true });
  await expect(editHeading).toBeVisible();
  await expect(editHeading).toBeFocused();
  await expect(directControl(page, "plan-direct-existing-action-action-type")).toHaveValue("passive_scope_revalidation");
  await expect(directControl(page, "plan-direct-existing-action-target")).toHaveValue(target);
  await expect(directControl(page, "plan-direct-existing-action-arguments")).toHaveValue(JSON.stringify({ sources: ["registry", "scope"] }, null, 2));
  await expect(directControl(page, "plan-change-direct-edit-submit")).toBeDisabled();

  const cancel = page.getByRole("button", { name: `Cancel structured edit for ${requestId}`, exact: true });
  await cancel.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 3, name: "Edit the plan graph without executing it", exact: true })).toBeVisible();
  await expect(openEdit).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(editHeading).toBeFocused();

  const revisedOperation = {
    ...originalOperation,
    representation: {
      ...originalOperation.representation,
      action: {
        ...originalOperation.representation.action,
        actionType: "passive_scope_revalidation_v2",
        arguments: { sources: ["registry", "scope"], maxRecords: 25 },
        intentSummary: "Revalidate attributable target identity with an explicit local record bound.",
      },
      explanation: "Recheck the approved identity with an explicit maximum of 25 local records.",
    },
  } as const;
  await directControl(page, "plan-direct-existing-action-action-type").fill(revisedOperation.representation.action.actionType);
  await directControl(page, "plan-direct-existing-action-arguments").fill(JSON.stringify(revisedOperation.representation.action.arguments));
  await directControl(page, "plan-direct-existing-action-intent").fill(revisedOperation.representation.action.intentSummary);
  await directControl(page, "plan-direct-existing-action-explanation").fill(revisedOperation.representation.explanation);
  const save = directControl(page, "plan-change-direct-edit-submit");
  await expect(save).toBeEnabled();

  refreshPlanChangeFixtureAgents(fixture);
  const editPath = `${endpoint(fixture)}/${encodeURIComponent(requestId)}`;
  const pending = page.waitForResponse((response) => new URL(response.url()).pathname === editPath && response.request().method() === "PUT");
  await directControl(page, "plan-direct-existing-action-reversibility").focus();
  await page.keyboard.press("Tab");
  await expect(save).toBeFocused();
  await page.keyboard.press("Enter");
  const response = await pending;
  expect(response.status(), await response.text()).toBe(200);
  expect(response.headers()["idempotency-replayed"]).toBe("false");
  expect(response.request().postDataJSON()).toEqual({
    expectedRequestVersion: 1,
    expectedRunVersion: fixture.runVersion,
    expectedPlanVersion: fixture.planVersion,
    requestText: reason,
    operations: [revisedOperation],
  });
  const edited = await response.json() as ProposalResponse;
  expect(edited.request).toMatchObject({ id: requestId, status: "validated", version: 2 });
  expect(edited.request.normalizedChange.operations).toEqual([revisedOperation]);
  expect(edited.request.structuredDiff).toEqual(expect.arrayContaining([
    expect.objectContaining({
      path: `steps[${fixture.stepOneId}].representation`,
      after: expect.objectContaining({
        action: expect.objectContaining({ actionType: "passive_scope_revalidation_v2" }),
      }),
    }),
  ]));
  await expect(page.locator(".os-plan-change-card").filter({ hasText: `Proposal ${requestId}` })).toContainText("Proposal version2");
  await expect(page.getByRole("region", { name: `Exact diff for ${requestId}` })).toContainText("passive_scope_revalidation_v2");
  await expect(page.getByRole("heading", { level: 3, name: "Edit the plan graph without executing it", exact: true })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "Structured revision saved." })).toContainText(`Proposal ${requestId} was saved as version 2`);
  await expect(openEdit).toBeFocused();

  const persistedBeforeRefresh = readPlanChangeFixtureSnapshot(fixture);
  expect(persistedBeforeRefresh).toMatchObject({
    run: { status: "queued", currentPlanId: fixture.planId, version: fixture.runVersion, replanCount: 0, leaseOwner: null },
    actionCount: 0,
  });
  expect(persistedBeforeRefresh.requests).toEqual([
    expect.objectContaining({ id: requestId, status: "validated", version: 2, resultPlanId: null }),
  ]);
  expect(persistedBeforeRefresh.plans).toEqual([
    expect.objectContaining({ id: fixture.planId, status: "active", version: fixture.planVersion }),
  ]);
  expect(applyRequests).toBe(0);

  await audit.assertClean(testInfo);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  const refreshAudit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const refreshedCard = page.locator(".os-plan-change-card").filter({ hasText: `Proposal ${requestId}` });
  await expect(refreshedCard).toContainText("Proposal version2");
  await refreshedCard.getByRole("button", { name: `Edit exact represented action in ${requestId}`, exact: true }).click();
  await expect(directControl(page, "plan-direct-existing-action-action-type")).toHaveValue("passive_scope_revalidation_v2");
  await expect(directControl(page, "plan-direct-existing-action-arguments")).toHaveValue(JSON.stringify({ sources: ["registry", "scope"], maxRecords: 25 }, null, 2));
  expect(readPlanChangeFixtureSnapshot(fixture).actionCount).toBe(0);
  expect(applyRequests).toBe(0);
  await refreshAudit.assertClean(testInfo);
});

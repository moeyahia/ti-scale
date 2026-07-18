import { expect, test, type Locator, type Page, type Response, type TestInfo } from "./support/playwright";
import { readFileSync } from "node:fs";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import {
  createMissionIntakeDynamicFixture,
  type MissionIntakeDynamicFixture,
} from "./support/missionIntakeDynamicFixture";

const TEST_ID = "e2e.mission-intake";
const VISUAL_PROJECT = "chromium-1440";
const AUTONOMOUS_MINIMAL_VISUAL = {
  id: "visual.autonomous-intake.minimal-review.chromium-1440",
  snapshot: "autonomous-intake-minimal-review.png",
} as const;
const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

type IntakeJourney = "autonomous" | "guided";

const ACTION_POLICY_VALUES = ["pre_authorized", "guided_only", "prohibited", "inherited_default"] as const;

function manifestOptions(id: string): readonly string[] {
  const entry = manifest.entries.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`Interaction manifest entry ${id} is missing`);
  return entry.options;
}

function route(journey: IntakeJourney): string {
  return `/missions/new/${journey}`;
}

function prefix(journey: IntakeJourney): string {
  return `${journey}-intake`;
}

function group(page: Page, name: string): Locator {
  return page.getByRole("group", { name, exact: true });
}

async function expectApprovedVisual(locator: Locator, testInfo: TestInfo): Promise<void> {
  if (testInfo.project.name !== VISUAL_PROJECT) return;
  await locator.page().evaluate(async () => { await document.fonts.ready; });
  await expect(locator).toHaveScreenshot(AUTONOMOUS_MINIMAL_VISUAL.snapshot, {
    animations: "disabled",
    caret: "hide",
    maxDiffPixels: 0,
    threshold: 0.15,
  });
}

async function normalizeAutonomousReviewVisual(card: Locator): Promise<void> {
  // Locator screenshots taller than the viewport are captured in tiles. The
  // sticky shell header can otherwise be painted over a different tile seam
  // depending on the page's prior scroll position, obscuring the fieldset
  // legend or one readiness row without any product-state change.
  for (const selector of [".os-topbar", ".os-refresh-note"]) {
    const shellOverlay = card.page().locator(selector);
    if (await shellOverlay.count() === 1) {
      await shellOverlay.evaluate((node) => { (node as HTMLElement).style.display = "none"; });
    }
  }
  await card.locator(".os-review-grid > div").evaluateAll((rows) => {
    const replacements: Record<string, string> = {
      Mission: "Safe Recon — approved visual fixture",
      Objective: "Map the authorized disposable lab target and retain attributable evidence without changing target state.",
      Targets: "lab:autonomous-intake-approved-visual",
      "Contract SHA-256": "0000000000000000000000000000000000000000000000000000000000000000",
      "Compatible providers": "1",
    };
    for (const row of rows) {
      const label = row.querySelector("dt")?.textContent?.trim();
      const value = row.querySelector("dd");
      if (label && value && replacements[label]) value.textContent = replacements[label];
    }
  });
  await card.locator(".os-review-list > li").evaluateAll((rows) => {
    for (const row of rows) {
      if (row.querySelector("strong")?.textContent?.trim() !== "Inspected enforcing provider paths") continue;
      const detail = row.querySelector("small");
      if (detail) {
        detail.textContent = "1 projected authenticated provider path is compatible with the Autonomous boundary; live readiness is also rechecked at launch.";
      }
    }
  });
}

async function openDetails(page: Page, label: string): Promise<Locator> {
  const summary = page.locator("summary").filter({ hasText: label }).first();
  await expect(summary).toBeVisible();
  const details = summary.locator("xpath=..");
  if (!(await details.getAttribute("open"))) await summary.click();
  await expect(details).toHaveAttribute("open", "");
  return details;
}

async function expectSuccessfulResolve(response: Response): Promise<void> {
  expect(response.status(), await response.text()).toBe(200);
  expect(response.request().method()).toBe("POST");
}

async function clickContinue(
  page: Page,
  nextGroup: string,
  options: { readonly autonomousPreflight?: boolean } = {},
): Promise<void> {
  const resolved = page.waitForResponse((response) => response.url().endsWith("/api/v2/registries/intake/resolve") && response.request().method() === "POST");
  const preflight = options.autonomousPreflight
    ? page.waitForResponse((response) => response.url().endsWith("/api/v2/missions/autonomous/preflight") && response.request().method() === "POST")
    : undefined;
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expectSuccessfulResolve(await resolved);
  if (preflight) expect((await preflight).status()).toBe(200);
  await expect(group(page, nextGroup)).toBeVisible();
}

async function exerciseMinimalScope(page: Page, journey: IntakeJourney, target: string): Promise<void> {
  await page.goto(route(journey));
  await expect(group(page, "Authorization and exact scope")).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: /Runtime registry unavailable|Live runtime registry/u }).first()).toBeVisible();

  await page.getByRole("button", { name: "Continue", exact: true }).click();
  const validation = page.getByRole("alert").filter({ hasText: "Resolve before continuing" });
  await expect(validation).toContainText("Add at least one authorized target or environment reference.");
  await expect(validation).toContainText("Confirm that you are authorized to assess the supplied target scope.");

  const template = page.getByLabel("Mission template", { exact: false });
  const templateLabels = await template.locator("option").allTextContents();
  expect(templateLabels).toEqual(manifestOptions(`${prefix(journey)}.scope.template`));
  const templateValues = await template.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value));
  for (const value of templateValues) {
    await page.getByLabel("Mission template", { exact: false }).selectOption(value);
    await expect(page.getByLabel("Mission template", { exact: false })).toHaveValue(value);
  }
  await page.getByLabel("Mission template", { exact: false }).selectOption("safe_recon");
  await expect(page.getByLabel("Mission template", { exact: false })).toHaveValue("safe_recon");

  const targetField = page.getByLabel("Authorized targets or environment references", { exact: false });
  await expect(targetField).toHaveAttribute("placeholder", "https://portal.example.test\n10.10.10.0/24");
  const targetHelp = page.locator("details.os-field-help").first();
  await targetHelp.locator("summary").click();
  await expect(targetHelp).toContainText("Defines the exact host, network, URL, domain, account, scope file, engagement, or lab boundary.");
  await expect(targetHelp).toContainText("Example: https://portal.example.test or 10.10.10.0/24");

  const boundary = await openDetails(page, "Excluded targets and engagement boundary");
  const excluded = boundary.getByLabel("Explicitly excluded targets", { exact: false });
  const engagement = boundary.getByLabel("Existing engagement ID", { exact: false });
  await expect(excluded).toHaveAttribute("placeholder", "admin.portal.example.test");
  await expect(engagement).toHaveAttribute("placeholder", "eng_customer-portal_q3");
  await excluded.fill("excluded.example.test");
  await excluded.clear();
  await engagement.fill("eng_e2e_intake");
  await engagement.clear();
  const engagementHelp = boundary.locator("details.os-field-help");
  await engagementHelp.locator("summary").click();
  await expect(engagementHelp).toContainText("Scopes retained knowledge and links the mission to an existing authorized engagement.");

  await targetField.fill(target);
  const authorization = page.getByRole("checkbox", { name: /I confirm these targets and the selected action policy are authorized/u });
  await authorization.check();
  await expect(authorization).toBeChecked();
  await expect(page.getByLabel("Current mission contract summary")).toContainText("Authorized targets1");
}

async function exerciseOutcome(page: Page, journey: IntakeJourney): Promise<void> {
  const title = page.getByLabel("Mission title", { exact: false });
  const objective = page.getByLabel("Authorized objective", { exact: false });
  await expect(title).toHaveAttribute("placeholder", "Q3 External Web Assessment — Customer Portal");
  await expect(objective).not.toHaveAttribute("placeholder", "");
  await title.fill("Temporary E2E title");
  await title.clear();
  await objective.fill("Temporary authorized objective that remains inside the supplied target.");
  await objective.clear();

  const helpers = page.locator("details.os-field-help");
  await expect(helpers).toHaveCount(2);
  for (const helper of await helpers.all()) {
    await helper.locator("summary").click();
    await expect(helper).toContainText("Example:");
  }

  const success = page.locator("fieldset.os-registry-checklist").first();
  const successControls = success.getByRole("checkbox");
  await expect(successControls).toHaveCount(3);
  for (const checkbox of await successControls.all()) {
    const initial = await checkbox.isChecked();
    await checkbox.click();
    await expect(checkbox).toBeChecked({ checked: !initial });
    await checkbox.click();
    await expect(checkbox).toBeChecked({ checked: initial });
  }
  const additional = page.getByLabel("Additional success criteria", { exact: false });
  await additional.fill("A safe alternative is documented when execution prerequisites are unavailable.");
  await additional.clear();

  if (journey === "guided") {
    const depth = page.getByLabel("Explanation depth", { exact: false });
    expect(await depth.locator("option").allTextContents()).toEqual(manifestOptions("guided-intake.outcome.explanation-depth"));
    for (const value of ["concise", "deep", "balanced"]) {
      await depth.selectOption(value);
      await expect(depth).toHaveValue(value);
    }
    const manual = page.getByRole("radio", { name: /I run commands manually/u });
    const singleStep = page.getByRole("radio", { name: /Allow one represented agent step/u });
    await singleStep.check();
    await expect(singleStep).toBeChecked();
    await manual.check();
    await expect(manual).toBeChecked();
  }
}

async function toggleCollection(details: Locator, expectedLabels: readonly string[]): Promise<void> {
  const labels = await details.locator("label.os-check-field strong").allTextContents();
  expect(labels).toEqual(expectedLabels);
  const controls = details.getByRole("checkbox");
  await expect(controls).toHaveCount(expectedLabels.length);
  for (const checkbox of await controls.all()) {
    const initial = await checkbox.isChecked();
    await checkbox.click();
    await expect(checkbox).toBeChecked({ checked: !initial });
    await checkbox.click();
    await expect(checkbox).toBeChecked({ checked: initial });
  }
}

async function exerciseContract(page: Page, journey: IntakeJourney): Promise<void> {
  const budget = page.getByLabel("Budget preset", { exact: false });
  expect(await budget.locator("option").allTextContents()).toEqual(manifestOptions(`${prefix(journey)}.contract.budget`));
  for (const value of ["quick", "deep", "standard"]) {
    await budget.selectOption(value);
    await expect(budget).toHaveValue(value);
  }

  const destructive = page.getByLabel("Destructive-action policy", { exact: false });
  expect(await destructive.locator("option").allTextContents()).toEqual(manifestOptions(`${prefix(journey)}.contract.destructive-policy`));
  await destructive.selectOption("bounded_lab_only");
  const bounded = group(page, "Named disposable lab targets");
  await expect(bounded).toBeVisible();
  const boundedTarget = bounded.getByRole("checkbox");
  await expect(boundedTarget).toHaveCount(1);
  await boundedTarget.check();
  await expect(boundedTarget).toBeChecked();
  await boundedTarget.uncheck();
  await expect(boundedTarget).not.toBeChecked();
  await destructive.selectOption("validate_without_executing");
  await expect(bounded).toBeHidden();
  await destructive.selectOption("prohibited");
  await expect(destructive).toHaveValue("prohibited");

  const actionMatrix = await openDetails(page, "Action-class policy matrix");
  const actionLabels = await actionMatrix.locator("article.os-policy-row > div > strong").allTextContents();
  expect(actionLabels).toEqual(manifestOptions(`${prefix(journey)}.contract.action-classes`));
  const actionControls = actionMatrix.getByRole("combobox", { name: / policy$/u });
  await expect(actionControls).toHaveCount(actionLabels.length);
  for (const control of await actionControls.all()) {
    expect(await control.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value))).toEqual(ACTION_POLICY_VALUES);
    const initial = await control.inputValue();
    for (const value of ACTION_POLICY_VALUES) {
      await control.selectOption(value);
      await expect(control).toHaveValue(value);
    }
    await control.selectOption(initial);
  }

  const deliverables = await openDetails(page, "Final deliverables");
  await toggleCollection(deliverables, manifestOptions(`${prefix(journey)}.contract.deliverables`));
  const evidence = await openDetails(page, "Evidence requirements");
  await expect(evidence.locator(".os-policy-note")).toContainText(
    "mission preferences never weaken the immutable evidence required to verify a finding",
  );
  for (const label of ["OS, kernel, or platform fingerprint", "DNS or certificate record"]) {
    const row = evidence.locator("label.os-check-field").filter({ hasText: label });
    await expect(row).toHaveCount(1);
    await expect(row.getByRole("checkbox")).not.toBeChecked();
    await expect(row).toContainText("not selected by recommended defaults");
  }
  await toggleCollection(evidence, manifestOptions(`${prefix(journey)}.contract.evidence`));
  const stops = await openDetails(page, "Safe-stop behavior");
  await toggleCollection(stops, manifestOptions(`${prefix(journey)}.contract.safe-stops`));
  await expect(stops.getByText("Always enforced", { exact: true })).toBeVisible();
  await expect(stops.locator(".os-mandatory-stop")).toHaveCount(8);
}

async function exerciseAutonomousTeam(page: Page, fixture: MissionIntakeDynamicFixture): Promise<void> {
  await expect(page.getByText("Specialist team and execution readiness", { exact: true })).toBeVisible();
  const recommended = page.getByRole("button", { name: "Use recommended team", exact: true });
  await expect(recommended).toBeVisible();
  const team = group(page, "Specialist team and execution readiness");
  const candidate = team.getByRole("checkbox", { name: new RegExp(fixture.agentName, "u") });
  await expect(candidate).toBeEnabled();
  const initial = await candidate.isChecked();
  await candidate.click();
  await expect(candidate).toBeChecked({ checked: !initial });
  await candidate.click();
  await expect(candidate).toBeChecked({ checked: initial });
  await recommended.click();
  await expect(candidate).toBeChecked();
  const selectedSummary = team.locator(":scope > .os-inline-actions > span");
  const recommendedCount = await team.locator('input[type="checkbox"]:checked').count();
  expect(recommendedCount, "The live recommended team must contain at least the attested fixture specialist").toBeGreaterThan(0);
  await expect(selectedSummary).toHaveText(`${recommendedCount} selected`);

  // Other suites legitimately add specialists to the same canonical browser
  // database. Exercise the live recommendation as returned, then create one
  // explicit, deterministic operator selection for this mission instead of
  // allowing unrelated fixture agents to change the signed contract visual.
  // This proves both the dynamic count and the exact selected-team boundary.
  const specialistRows = team.locator("label.os-check-field");
  for (let index = 0; index < await specialistRows.count(); index += 1) {
    const row = specialistRows.nth(index);
    const checkbox = row.getByRole("checkbox");
    const isFixtureSpecialist = (await row.textContent())?.includes(fixture.agentName) === true;
    if (await checkbox.isDisabled()) {
      await expect(checkbox).not.toBeChecked();
    } else if (isFixtureSpecialist) {
      await checkbox.check();
    } else {
      await checkbox.uncheck();
    }
  }
  await expect(team.locator('input[type="checkbox"]:checked')).toHaveCount(1);
  await expect(selectedSummary).toHaveText("1 selected");
  await expect(page.getByText("Provider enforcement paths", { exact: true })).toBeVisible();
}

async function exerciseAutonomousContext(page: Page, fixture: MissionIntakeDynamicFixture): Promise<void> {
  const context = group(page, "Second Brain context");
  await expect(context).toContainText("smallest useful set");
  const scopes = group(page, "Memory scopes allowed for this mission");
  await expect(scopes.getByRole("checkbox", { name: /Confirmed operator preferences/u })).toBeChecked();
  await expect(scopes.getByRole("checkbox", { name: /Verified operational lessons/u })).toBeChecked();
  await expect(scopes.getByRole("checkbox", { name: /Engagement-isolated knowledge/u })).toBeDisabled();
  const candidate = context.getByRole("checkbox", { name: new RegExp(fixture.memoryTitle, "u") });
  await expect(candidate).not.toBeChecked();
  await candidate.check();
  await expect(candidate).toBeChecked();
  await context.getByRole("button", { name: "Use no retained context", exact: true }).click();
  await expect(candidate).not.toBeChecked();
  await expect(scopes.getByRole("checkbox", { name: /Confirmed operator preferences/u })).toBeChecked();
  await expect(context).toContainText(/never expand authorization/u);
}

test.describe(`${TEST_ID} registry-driven journey-specific intake`, () => {
  test.setTimeout(120_000);

  test("e2e.mission-intake.autonomous-minimal resolves defaults and remains fail-closed", async ({ page }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const dynamicFixture = createMissionIntakeDynamicFixture(testInfo.testId);
    const target = "lab:autonomous-intake-approved-visual";
    await exerciseMinimalScope(page, "autonomous", target);
    await clickContinue(page, "Outcome and collaboration");
    await exerciseOutcome(page, "autonomous");

    await page.getByRole("button", { name: "Back", exact: true }).click();
    await expect(group(page, "Authorization and exact scope")).toBeVisible();
    await expect(page.getByLabel("Authorized targets or environment references", { exact: false })).toHaveValue(target);
    await expect(page.getByRole("checkbox", { name: /I confirm these targets/u })).toBeChecked();
    await clickContinue(page, "Outcome and collaboration");
    await clickContinue(page, "Autonomous operating contract");
    await exerciseContract(page, "autonomous");
    await clickContinue(page, "Specialist team and execution readiness", { autonomousPreflight: true });
    await exerciseAutonomousTeam(page, dynamicFixture);
    await clickContinue(page, "Second Brain context", { autonomousPreflight: true });
    await exerciseAutonomousContext(page, dynamicFixture);
    await clickContinue(page, "Review the resolved mission", { autonomousPreflight: true });

    const review = group(page, "Review the resolved mission");
    await expect(review).toContainText("Autonomous");
    await expect(review).toContainText(target);
    await expect(review).toContainText("Inferred by recommended defaults");
    await expect(review).toContainText("title, objective");
    await expect(review).toContainText("No attested runtime capability manifest is connected");
    const readiness = review.locator(".os-readiness-summary");
    await expect(readiness).toContainText("blocked");
    await expect(readiness).toContainText("launch blockers");
    await expect(review.getByText("Signed specialists", { exact: true }).locator("xpath=..").locator("dd")).toHaveText("1");
    const launch = page.getByRole("button", { name: "Launch Autonomous Mission", exact: true });
    await expect(launch).toBeDisabled();
    const visual = page.locator(".os-contract-form > .os-card");
    await normalizeAutonomousReviewVisual(visual);
    await expectApprovedVisual(visual, testInfo);
    await audit.assertClean(testInfo);
  });

  test("e2e.mission-intake.guided-minimal creates and reopens a real durable Guided mission", async ({ page, browserAudit }, testInfo) => {
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const target = `lab:guided-intake-${Date.now()}`;
    await exerciseMinimalScope(page, "guided", target);
    await clickContinue(page, "Outcome and collaboration");
    await exerciseOutcome(page, "guided");
    await clickContinue(page, "Guided proposal boundaries");
    await exerciseContract(page, "guided");
    await clickContinue(page, "Review the resolved mission");

    const review = group(page, "Review the resolved mission");
    await expect(review).toContainText("Guided");
    await expect(review).toContainText(target);
    await expect(review).toContainText("Explain → recommend → choose → observe → interpret → record → advance");
    await audit.assertClean(testInfo);
    const createdPromise = page.waitForResponse((response) => response.url().endsWith("/api/v2/missions") && response.request().method() === "POST");
    const runtimePromise = page.waitForResponse((response) => /\/api\/v2\/missions\/[^/]+\/runtime$/u.test(new URL(response.url()).pathname));
    await page.getByRole("button", { name: "Start Guided Mission", exact: true }).click();
    const createdResponse = await createdPromise;
    expect(createdResponse.status(), await createdResponse.text()).toBe(201);
    const created = await createdResponse.json() as { mission: { id: string; title: string; journey: string }; nextUrl: string };
    expect(createdResponse.request().postDataJSON()).toMatchObject({
      journey: "guided",
      authorizationConfirmed: true,
      target,
      explanationDepth: "balanced",
      executionPreference: "manual",
    });
    await expect.poll(() => new URL(page.url()).pathname).toBe(`/guided/${created.mission.id}`);
    expect(created.nextUrl).toBe(`/guided/${created.mission.id}`);
    expect(created.mission.journey).toBe("guided");
    const runtimeResponse = await runtimePromise;
    expect(runtimeResponse.status(), await runtimeResponse.text()).toBe(200);
    const runtime = await runtimeResponse.json() as {
      schemaVersion: string;
      mission: { id: string; journey: string };
      runs: Array<{
        id: string;
        missionId: string;
        journey: string;
        status: string;
        statusReason: string;
        nextAction: string;
      }>;
    };
    expect(runtime).toMatchObject({
      schemaVersion: "2.4",
      mission: { id: created.mission.id, journey: "guided" },
      runs: [expect.objectContaining({
        missionId: created.mission.id,
        journey: "guided",
        status: "planning",
        statusReason: "Guided mission created; an explained first step must precede any consequential action.",
        nextAction: "Explain the assessment path and recommend the first bounded step",
      })],
    });
    await expect(page.getByRole("region", { name: "Selected run status" })).toContainText("planning");
    await expect(page.getByText("Planning has not produced a represented step", { exact: true })).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);

    const persistedResponse = await browserAudit.request(page.request, {
      method: "GET",
      url: `/api/v2/missions?query=${encodeURIComponent(created.mission.id)}`,
    });
    expect(persistedResponse.status(), await persistedResponse.text()).toBe(200);
    const persisted = await persistedResponse.json() as { items: Array<{ id: string; title: string; journey: string }> };
    expect(persisted.items).toContainEqual(expect.objectContaining({
      id: created.mission.id,
      title: created.mission.title,
      journey: "guided",
    }));
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload());
    await expect(page.getByRole("region", { name: "Selected run status" })).toContainText("planning");
    await expect(page.getByText("Planning has not produced a represented step", { exact: true })).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
    await audit.assertClean(testInfo);
  });
});

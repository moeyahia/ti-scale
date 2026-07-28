import { expect, test, type Locator, type Page, type Response, type TestInfo } from "./support/playwright";
import { readFileSync } from "node:fs";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import {
  createMissionIntakeDynamicFixture,
  type MissionIntakeDynamicFixture,
} from "./support/missionIntakeDynamicFixture";
import {
  openTitaniumSelect,
  readTitaniumOptions,
  selectTitaniumOption,
} from "./support/titaniumSelect";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
} from "./support/interactionActivationFixture";
import type {
  AutonomousMissionPreflight,
  ReadinessCheck,
} from "../../src/domain/types/commandOs";
import type { RuntimeReadinessSnapshot } from "../../src/domain/types/runtimeReadiness";
import { DELIVERABLE_DEFINITIONS } from "../../server/domain/deliverable-registry";
import { EVIDENCE_TYPE_DEFINITIONS } from "../../server/domain/evidence-type-registry";
import { OPTIONAL_MISSION_SAFE_STOPS } from "../../server/domain/safe-stop-registry";
import type { ResolvedMissionIntake } from "../../server/intake/types";
import { startReadyAutonomousIntakeBackend } from "./support/readyAutonomousIntakeBackendController";
import { assertAutonomousIntakeGuard } from "./support/autonomousIntake";

const TEST_ID = "e2e.mission-intake";
const TEST_AUTONOMOUS_MINIMAL = "e2e.mission-intake.autonomous-minimal";
const TEST_GUIDED_MINIMAL = "e2e.mission-intake.guided-minimal";
const TEST_GUIDED_WINDOWS_IDENTITY = "e2e.mission-intake.guided-windows-identity";
const TEST_GUIDED_LOCAL_EXPLOIT_INTELLIGENCE =
  "e2e.mission-intake.guided-local-exploit-intelligence";
const INTERACTION_ACTIVATION_SENTINEL = "__control_activation__" as const;
const VISUAL_PROJECT = "chromium-1440";
const AUTONOMOUS_MINIMAL_VISUAL = {
  id: "visual.autonomous-intake.minimal-review.chromium-1440",
  snapshot: "autonomous-intake-minimal-review.png",
} as const;
const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

type IntakeJourney = "autonomous" | "guided";

interface ExpectedContractChecklist {
  readonly deliverables: readonly string[];
  readonly evidence: readonly string[];
  readonly optionalSafeStops: readonly string[];
}

const ACTION_POLICY_VALUES = ["pre_authorized", "guided_only", "prohibited", "inherited_default"] as const;
const ACTION_POLICY_OPTIONS = [
  { value: "pre_authorized", label: "Pre-authorized" },
  { value: "guided_only", label: "Guided only / not autonomous" },
  { value: "prohibited", label: "Prohibited" },
  { value: "inherited_default", label: "Inherited default" },
] as const;
const STALE_AUTONOMOUS_CHECKS: readonly ReadinessCheck[] = [
  ["execution_boundary_autonomous", "Autonomous execution boundary"],
  ["contract_action_boundary", "Executable action boundary"],
  ["provider_execution_autonomous", "Autonomous provider enforcement"],
  ["contract_provider_inventory", "Inspected enforcing provider paths"],
  ["contract_specialist_selection", "Signed specialist pool"],
  ["mcp_execution_autonomous", "Autonomous MCP execution"],
  ["contract_evidence_capability", "Required evidence capability"],
  ["provider_token_accounting_autonomous", "Exact token accounting"],
  ["provider_cost_accounting_autonomous", "Exact cost accounting"],
].map(([id, label]) => ({
  id,
  label,
  status: "fail" as const,
  journeys: ["autonomous" as const],
  impact: `${label} is not currently satisfied for unattended execution.`,
  remediation: `Repair ${label.toLocaleLowerCase("en-US")} and rerun preflight.`,
}));

function manifestOptions(id: string): readonly string[] {
  const entry = manifest.entries.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`Interaction manifest entry ${id} is missing`);
  return entry.options;
}

function contractCollectionOptions(
  journey: IntakeJourney,
  autonomousCollectionId: string,
  guidedCollectionId: string,
): readonly string[] {
  return manifestOptions(
    journey === "autonomous"
      ? `autonomous-intake.contract.${autonomousCollectionId}`
      : `guided-intake.contract.${guidedCollectionId}`,
  );
}

interface IntakeReceiptContext {
  readonly recorder: InteractionActivationRecorder;
  readonly testId: string;
}

function activation(
  manifestEntryId: string,
  option: string,
  modality: "pointer" | "keyboard",
  testId: string,
): InteractionActivationInput {
  const entry = manifest.entries.find((candidate) => candidate.id === manifestEntryId);
  if (!entry) throw new Error(`Mission intake manifest entry ${manifestEntryId} is missing`);
  const options = entry.options.length > 0 ? entry.options : [INTERACTION_ACTIVATION_SENTINEL];
  if (!options.includes(option)) throw new Error(`Mission intake manifest entry ${manifestEntryId} does not declare ${option}`);
  if (!entry.testIds.includes(testId)) throw new Error(`Mission intake manifest entry ${manifestEntryId} does not declare ${testId}`);
  return {
    manifestEntryId,
    controlId: entry.controlId,
    option,
    materialState: entry.requiredState,
    modality,
    testId,
  };
}

async function activateIf<T>(
  context: IntakeReceiptContext | undefined,
  manifestEntryId: string,
  option: string,
  modality: "pointer" | "keyboard",
  action: () => Promise<T>,
): Promise<T> {
  if (!context) return action();
  return context.recorder.activate(
    activation(manifestEntryId, option, modality, context.testId),
    action,
  );
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

function titaniumSelect(root: Page | Locator, name: string | RegExp): Locator {
  return root.getByRole("combobox", { name, exact: typeof name === "string" });
}

function titaniumFormProxy(control: Locator): Locator {
  return control.locator("xpath=..").locator("select.os-titanium-select__form-proxy");
}

async function titaniumOptions(control: Locator) {
  const options = await readTitaniumOptions(control);
  expect(options.length, "A titanium selector must expose at least one visible option").toBeGreaterThan(0);
  expect(options.every((option) => option.label.length > 0 && option.value.length > 0)).toBe(true);
  return options;
}

async function chooseTitaniumOption(
  control: Locator,
  value: string,
  modality: "pointer" | "keyboard" = "keyboard",
): Promise<void> {
  await selectTitaniumOption(control, value, modality);
  await expect(control).toBeFocused();
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
  await card.locator(".mission-model-assignment__facts dl > div").evaluateAll((rows) => {
    const replacements: Record<string, string> = {
      Configuration: "configuration-approved-visual-00000000000000000000000000000000",
      "Catalog observed": "Jul 28, 2026, 12:00 PM",
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
  if ((await details.getAttribute("open")) === null) await summary.click();
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
): Promise<Response> {
  const resolved = page.waitForResponse((response) => response.url().endsWith("/api/v2/registries/intake/resolve") && response.request().method() === "POST");
  const preflight = options.autonomousPreflight
    ? page.waitForResponse((response) => response.url().endsWith("/api/v2/missions/autonomous/preflight") && response.request().method() === "POST")
    : undefined;
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  const resolvedResponse = await resolved;
  await expectSuccessfulResolve(resolvedResponse);
  if (preflight) expect((await preflight).status()).toBe(200);
  await expect(group(page, nextGroup)).toBeVisible();
  return resolvedResponse;
}

async function proxyV2ApiTo(page: Page, baseUrl: string): Promise<void> {
  await page.route("**/api/v2/**", async (requestRoute) => {
    const original = new URL(requestRoute.request().url());
    if (
      original.pathname.startsWith("/api/v2/auth/")
      || original.pathname.startsWith("/api/v2/notifications")
      || original.pathname === "/api/v2/events/stream"
    ) {
      await requestRoute.continue();
      return;
    }
    const target = new URL(`${original.pathname}${original.search}`, baseUrl);
    const response = await requestRoute.fetch({ url: target.href, timeout: 30_000 });
    await requestRoute.fulfill({ response });
  });
}

function expectRecommendedContractFieldsOmitted(response: Response): void {
  const body = response.request().postDataJSON() as Record<string, unknown>;
  for (const field of [
    "deliverableIds",
    "evidenceTypeIds",
    "optionalSafeStopIds",
    "budgetPresetId",
  ]) {
    expect(
      Object.hasOwn(body, field),
      `${field} must be omitted so the server, not a duplicated browser value, resolves its registry default`,
    ).toBe(false);
  }
}

async function exerciseJourneyRoundTrip(
  page: Page,
  journey: IntakeJourney,
  receiptContext: IntakeReceiptContext | undefined,
): Promise<void> {
  if (!receiptContext) return;
  const entryId = `${prefix(journey)}.navigation.change-journey`;
  const journeyLinkName = journey === "autonomous" ? "Go Autonomous" : "Start Guided Mission";
  for (const modality of ["pointer", "keyboard"] as const) {
    const changeJourney = page.getByRole("link", { name: "Change journey", exact: true });
    await activateIf(
      receiptContext,
      entryId,
      "Return to two-journey selection",
      modality,
      async () => {
        if (modality === "pointer") {
          await changeJourney.click();
        } else {
          await changeJourney.focus();
          await page.keyboard.press("Enter");
        }
        await expect.poll(() => new URL(page.url()).pathname).toBe("/missions/new");
        await expect(page.getByRole("link", { name: "Go Autonomous", exact: true })).toBeVisible();
        await expect(page.getByRole("link", { name: "Start Guided Mission", exact: true })).toBeVisible();
      },
    );
    await page.getByRole("link", { name: journeyLinkName, exact: true }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe(route(journey));
    await expect(group(page, "Authorization and exact scope")).toBeVisible();
  }
}

async function exerciseMinimalScope(
  page: Page,
  journey: IntakeJourney,
  target: string,
  receiptContext?: IntakeReceiptContext,
): Promise<void> {
  await page.goto(route(journey));
  await expect(group(page, "Authorization and exact scope")).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: /Runtime registry unavailable|Live runtime registry/u }).first()).toBeVisible();
  await exerciseJourneyRoundTrip(page, journey, receiptContext);

  await page.getByRole("button", { name: "Continue", exact: true }).click();
  const validation = page.getByRole("alert").filter({ hasText: "Resolve before continuing" });
  await expect(validation).toContainText("Add at least one authorized target or environment reference.");
  await expect(validation).toContainText("Confirm that you are authorized to assess the supplied target scope.");

  const template = titaniumSelect(page, /Mission template/u);
  const templateOptions = await titaniumOptions(template);
  expect(templateOptions.map((option) => option.label)).toEqual(manifestOptions(`${prefix(journey)}.scope.template`));
  for (const option of templateOptions) await chooseTitaniumOption(template, option.value);
  await chooseTitaniumOption(template, "safe_recon");

  if (journey === "autonomous") {
    const environment = titaniumSelect(page, /Environment classification/u);
    const environmentOptions = await titaniumOptions(environment);
    expect(environmentOptions.map((option) => option.label)).toEqual(
      manifestOptions("autonomous-intake.scope.environment-classification"),
    );
    for (const option of environmentOptions) {
      await activateIf(
        receiptContext,
        "autonomous-intake.scope.environment-classification",
        option.label,
        "keyboard",
        async () => {
          await chooseTitaniumOption(environment, option.value, "keyboard");
          await expect(titaniumFormProxy(environment)).toHaveValue(option.value);
        },
      );
    }
    await chooseTitaniumOption(environment, "htb");
  }

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

  const targetsEntryId = `${prefix(journey)}.scope.targets`;
  if (receiptContext) {
    await activateIf(
      receiptContext,
      targetsEntryId,
      INTERACTION_ACTIVATION_SENTINEL,
      "pointer",
      async () => {
        await targetField.click();
        await targetField.fill(target);
        await expect(targetField).toHaveValue(target);
        await expect(page.getByLabel("Current mission contract summary")).toContainText("Authorized targets1");
      },
    );
    await targetField.clear();
    await activateIf(
      receiptContext,
      targetsEntryId,
      INTERACTION_ACTIVATION_SENTINEL,
      "keyboard",
      async () => {
        await targetField.focus();
        await page.keyboard.insertText(target);
        await expect(targetField).toHaveValue(target);
        await expect(page.getByLabel("Current mission contract summary")).toContainText("Authorized targets1");
      },
    );
  } else {
    await targetField.fill(target);
  }
  const authorization = page.getByRole("checkbox", { name: /I confirm these targets and the selected action policy are authorized/u });
  const authorizationEntryId = `${prefix(journey)}.scope.authorization`;
  if (receiptContext) {
    await activateIf(receiptContext, authorizationEntryId, "Confirmed", "pointer", async () => {
      await authorization.click();
      await expect(authorization).toBeChecked();
    });
    await activateIf(receiptContext, authorizationEntryId, "Not confirmed", "keyboard", async () => {
      await authorization.focus();
      await page.keyboard.press("Space");
      await expect(authorization).not.toBeChecked();
    });
    await activateIf(receiptContext, authorizationEntryId, "Confirmed", "keyboard", async () => {
      await authorization.focus();
      await page.keyboard.press("Space");
      await expect(authorization).toBeChecked();
    });
    await activateIf(receiptContext, authorizationEntryId, "Not confirmed", "pointer", async () => {
      await authorization.click();
      await expect(authorization).not.toBeChecked();
    });
  }
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
    const depth = titaniumSelect(page, /Explanation depth/u);
    expect((await titaniumOptions(depth)).map((option) => option.label)).toEqual(manifestOptions("guided-intake.outcome.explanation-depth"));
    for (const value of ["concise", "deep", "balanced"]) {
      await chooseTitaniumOption(depth, value);
    }
    const manual = page.getByRole("radio", { name: /I run commands manually/u });
    const singleStep = page.getByRole("radio", { name: /Allow one represented agent step/u });
    await singleStep.check();
    await expect(singleStep).toBeChecked();
    await manual.check();
    await expect(manual).toBeChecked();
  }
}

async function toggleCollection(
  details: Locator,
  expectedLabels: readonly string[],
  receiptContext?: IntakeReceiptContext,
  manifestEntryId?: string,
): Promise<void> {
  const labels = await details.locator("label.os-check-field strong").allTextContents();
  expect(labels).toEqual(expectedLabels);
  const controls = details.getByRole("checkbox");
  await expect(controls).toHaveCount(expectedLabels.length);
  for (let index = 0; index < expectedLabels.length; index += 1) {
    const checkbox = controls.nth(index);
    const option = expectedLabels[index]!;
    const initial = await checkbox.isChecked();
    if (receiptContext && manifestEntryId) {
      await activateIf(receiptContext, manifestEntryId, option, "pointer", async () => {
        await checkbox.click();
        await expect(checkbox).toBeChecked({ checked: !initial });
      });
      await activateIf(receiptContext, manifestEntryId, option, "keyboard", async () => {
        await checkbox.focus();
        await checkbox.press("Space");
        await expect(checkbox).toBeChecked({ checked: initial });
      });
    } else {
      await checkbox.click();
      await expect(checkbox).toBeChecked({ checked: !initial });
      await checkbox.click();
      await expect(checkbox).toBeChecked({ checked: initial });
    }
  }
}

async function checkedChecklistLabels(details: Locator): Promise<string[]> {
  const rows = details.locator("label.os-check-field");
  const selected: string[] = [];
  for (let index = 0; index < await rows.count(); index += 1) {
    const row = rows.nth(index);
    if (await row.getByRole("checkbox").isChecked()) {
      selected.push((await row.locator("strong").first().innerText()).trim());
    }
  }
  return selected;
}

async function exerciseContract(
  page: Page,
  journey: IntakeJourney,
  receiptContext?: IntakeReceiptContext,
): Promise<ExpectedContractChecklist> {
  const checklistOverview = page.getByRole("region", { name: "Operating contract checklists", exact: true });
  await expect(checklistOverview).toBeVisible();
  await expect(checklistOverview).toContainText("Four registry-backed checklists");
  await expect(checklistOverview).toContainText("Action classes");
  await expect(checklistOverview).toContainText("Final deliverables");
  await expect(checklistOverview).toContainText("Evidence requirements");
  await expect(checklistOverview).toContainText("Safe stops");
  const defaults = checklistOverview.getByRole("button", { name: "Use recommended defaults", exact: true });
  await expect(defaults).toHaveAttribute(
    "data-control-id",
    `${journey}-intake-contract-recommended-defaults`,
  );
  await expect(defaults).toBeDisabled();

  const budget = titaniumSelect(page, /Budget preset/u);
  expect((await titaniumOptions(budget)).map((option) => option.label)).toEqual(manifestOptions(`${prefix(journey)}.contract.budget`));
  for (const value of ["quick", "deep", "standard"]) {
    await chooseTitaniumOption(budget, value);
  }

  const destructive = titaniumSelect(page, /Destructive-action policy/u);
  expect((await titaniumOptions(destructive)).map((option) => option.label)).toEqual(manifestOptions(`${prefix(journey)}.contract.destructive-policy`));
  await chooseTitaniumOption(destructive, "bounded_lab_only");
  const bounded = group(page, "Named disposable lab targets");
  await expect(bounded).toBeVisible();
  const boundedTarget = bounded.getByRole("checkbox");
  await expect(boundedTarget).toHaveCount(1);
  await boundedTarget.check();
  await expect(boundedTarget).toBeChecked();
  await boundedTarget.uncheck();
  await expect(boundedTarget).not.toBeChecked();
  await chooseTitaniumOption(destructive, "validate_without_executing");
  await expect(bounded).toBeHidden();
  await chooseTitaniumOption(destructive, "prohibited");

  const actionMatrix = await openDetails(page, "Action-class policy matrix");
  const actionLabels = await actionMatrix.locator("article.os-policy-row > div > strong").allTextContents();
  expect(actionLabels).toEqual(
    contractCollectionOptions(journey, "action-class-controls", "action-classes"),
  );
  const actionControls = actionMatrix.getByRole("combobox", { name: / policy$/u });
  await expect(actionControls).toHaveCount(actionLabels.length);
  const actionPolicyEntryId = `${prefix(journey)}.contract.action-policy-state`;
  const actionControlList = await actionControls.all();
  for (let index = 0; index < actionControlList.length; index += 1) {
    const control = actionControlList[index]!;
    const options = await titaniumOptions(control);
    expect(options.map((option) => option.value)).toEqual(ACTION_POLICY_VALUES);
    const initial = options.find((option) => option.selected)?.value;
    expect(initial, "Each action-class titanium selector must expose its canonical selected option").toBeTruthy();
    for (const policy of ACTION_POLICY_OPTIONS) {
      if (receiptContext && index === 0) {
        const alternate = ACTION_POLICY_VALUES.find((value) => value !== policy.value)!;
        await chooseTitaniumOption(control, alternate, "keyboard");
        await activateIf(receiptContext, actionPolicyEntryId, policy.label, "pointer", async () => {
          await chooseTitaniumOption(control, policy.value, "pointer");
          await expect(titaniumFormProxy(control)).toHaveValue(policy.value);
        });
        await chooseTitaniumOption(control, alternate, "pointer");
        await activateIf(receiptContext, actionPolicyEntryId, policy.label, "keyboard", async () => {
          await chooseTitaniumOption(control, policy.value, "keyboard");
          await expect(titaniumFormProxy(control)).toHaveValue(policy.value);
        });
      } else {
        await chooseTitaniumOption(control, policy.value);
      }
    }
    await chooseTitaniumOption(control, initial!);
  }

  const deliverables = await openDetails(page, "Final deliverables");
  const recommendedDeliverableLabels = await checkedChecklistLabels(deliverables);
  await toggleCollection(
    deliverables,
    contractCollectionOptions(journey, "deliverable-controls", "deliverables"),
  );
  const evidence = await openDetails(page, "Evidence requirements");
  await expect(evidence.locator(".os-policy-note")).toContainText(
    "mission preferences never weaken the immutable evidence required to verify a finding",
  );
  const evidenceLabels = contractCollectionOptions(
    journey,
    "evidence-controls",
    "evidence",
  );
  const recommendedEvidenceLabels = await checkedChecklistLabels(evidence);
  expect(
    recommendedEvidenceLabels.length,
    "Action-class-driven evidence defaults must select at least one attributable evidence type",
  ).toBeGreaterThan(0);
  expect(
    recommendedEvidenceLabels.length,
    "Recommended evidence defaults must retain at least one genuinely unselected registry item",
  ).toBeLessThan(evidenceLabels.length);
  const nonRecommendedEvidenceLabels = evidenceLabels.filter(
    (label) => !recommendedEvidenceLabels.includes(label),
  );
  expect(nonRecommendedEvidenceLabels.length).toBeGreaterThan(0);
  for (const label of nonRecommendedEvidenceLabels) {
    const row = evidence.locator("label.os-check-field").filter({ hasText: label });
    await expect(row).toHaveCount(1);
    await expect(row.getByRole("checkbox")).not.toBeChecked();
  }
  await toggleCollection(
    evidence,
    evidenceLabels,
    receiptContext,
    `${prefix(journey)}.contract.evidence-controls`,
  );
  const stops = await openDetails(page, "Safe-stop behavior");
  const recommendedSafeStopLabels = await checkedChecklistLabels(stops);
  await toggleCollection(
    stops,
    contractCollectionOptions(journey, "safe-stop-controls", "safe-stops"),
    receiptContext,
    `${prefix(journey)}.contract.safe-stop-controls`,
  );
  await expect(stops.getByText("Always enforced", { exact: true })).toBeVisible();
  await expect(stops.locator(".os-mandatory-stop")).toHaveCount(8);

  // Traversing every selector above intentionally creates explicit draft
  // values even when the final visible value matches the template. Prove the
  // product has a real one-click recommended-default path and that it restores
  // the exact registry-derived checklist, not a UI-only counter.
  await expect(defaults).toBeEnabled();
  await defaults.click();
  await expect(defaults).toBeDisabled();
  expect((await readTitaniumOptions(budget)).find((option) => option.selected)?.value).toBe("standard");
  expect((await readTitaniumOptions(destructive)).find((option) => option.selected)?.value).toBe("prohibited");
  await expect(checklistOverview).toContainText("recommended values");
  await expect.poll(() => checkedChecklistLabels(deliverables)).toEqual(
    recommendedDeliverableLabels,
  );
  await expect.poll(() => checkedChecklistLabels(evidence)).toEqual(
    recommendedEvidenceLabels,
  );
  await expect.poll(() => checkedChecklistLabels(stops)).toEqual(
    recommendedSafeStopLabels,
  );

  return {
    deliverables: await checkedChecklistLabels(deliverables),
    evidence: await checkedChecklistLabels(evidence),
    optionalSafeStops: await checkedChecklistLabels(stops),
  };
}

async function expectResolvedContractChecklist(
  page: Page,
  resolved: ResolvedMissionIntake,
): Promise<void> {
  const checklist = page.getByRole("region", { name: "Resolved operating contract checklist", exact: true });
  await expect(checklist).toBeVisible();
  await expect(checklist).toContainText("These are the server-normalized values—not draft counts.");
  await expect(checklist.getByText("Recommended default", { exact: true })).not.toHaveCount(0);
  await expect(checklist.getByText("Always enforced", { exact: true })).toHaveCount(1);
  for (const heading of [
    "Action classes",
    "Final deliverables",
    "Evidence requirements",
    "Mission-specific safe stops",
    "Operational budget",
  ]) {
    const block = checklist.locator(".os-contract-review-block").filter({ hasText: heading });
    await expect(block, `${heading} must retain server-resolved default provenance`).toHaveCount(1);
    await expect(block.getByText("Recommended default", { exact: true })).toHaveCount(1);
  }
  const labelsById = new Map([
    ...DELIVERABLE_DEFINITIONS,
    ...EVIDENCE_TYPE_DEFINITIONS,
    ...OPTIONAL_MISSION_SAFE_STOPS,
  ].map(({ id, label }) => [id, label] as const));
  const resolvedIds = [
    ...resolved.deliverableIds,
    ...resolved.evidenceTypeIds,
    ...resolved.optionalSafeStopIds,
  ];
  for (const id of resolvedIds) {
    const label = labelsById.get(id);
    if (!label) throw new Error(`The canonical registry does not label resolved contract item ${id}`);
    await expect(checklist.getByText(label, { exact: true })).toBeVisible();
  }
  await expect(checklist.locator(".os-contract-review-block").filter({ hasText: "Final deliverables" }).getByRole("listitem"))
    .toHaveCount(resolved.deliverableIds.length);
  await expect(checklist.locator(".os-contract-review-block").filter({ hasText: "Evidence requirements" }).getByRole("listitem"))
    .toHaveCount(resolved.evidenceTypeIds.length);
  const resolvedEvidenceLabels = resolved.evidenceTypeIds.map((id) => {
    const label = labelsById.get(id);
    if (!label) throw new Error(`The canonical evidence registry does not label ${id}`);
    return label;
  });
  expect(
    await checklist
      .locator(".os-contract-review-block")
      .filter({ hasText: "Evidence requirements" })
      .getByRole("listitem")
      .allTextContents(),
  ).toEqual(resolvedEvidenceLabels);
  await expect(checklist.locator(".os-contract-review-block").filter({ hasText: "Mission-specific safe stops" }).getByRole("listitem"))
    .toHaveCount(resolved.optionalSafeStopIds.length);
  await expect(checklist.locator(".os-contract-review-block").filter({ hasText: "Mandatory platform stops" }).getByRole("listitem")).toHaveCount(8);
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
  await expect(context).toContainText("smallest relevant set");
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

  test("e2e.mission-intake.titanium-selector replaces the operating-system menu", async ({ page }) => {
    await page.goto(route("guided"));
    await expect(group(page, "Authorization and exact scope")).toBeVisible();
    const selector = titaniumSelect(page, /Mission template/u);
    const formProxy = titaniumFormProxy(selector);

    await expect(selector).toHaveJSProperty("tagName", "BUTTON");
    await expect(formProxy).toHaveAttribute("aria-hidden", "true");
    await expect(formProxy).toHaveAttribute("tabindex", "-1");

    // Implicit and htmlFor labels must activate the visible application-owned
    // button, never the hidden canonical form proxy.
    await selector.locator("xpath=ancestor::label[1]").click({ position: { x: 8, y: 8 } });
    await expect(selector).toBeFocused();
    await expect(selector).toHaveAttribute("aria-expanded", "true");
    await selector.press("Escape");

    await selector.click();
    const listbox = page.getByRole("listbox", { name: /Mission template.*options/u });
    await expect(listbox).toBeVisible();
    await expect(selector).toHaveAttribute("aria-expanded", "true");
    const expectedTemplateLabels = manifestOptions("guided-intake.scope.template");
    await expect(listbox.getByRole("option")).toHaveCount(expectedTemplateLabels.length);
    expect(await listbox.getByRole("option").evaluateAll((options) => (
      options.map((option) => option.getAttribute("aria-label"))
    ))).toEqual(expectedTemplateLabels);
    const externalWeb = listbox.locator('[role="option"][data-select-value="external_web_assessment"]');
    await expect(externalWeb).toContainText("External Web Assessment");
    await expect(externalWeb).toHaveAttribute("data-select-value", "external_web_assessment");
    await externalWeb.click();
    expect((await readTitaniumOptions(selector)).find((option) => option.selected)?.value)
      .toBe("external_web_assessment");
    await expect(selector).toContainText("External Web Assessment");
    await expect(selector).toBeFocused();
    await expect(listbox).toBeHidden();

    await selector.press("ArrowDown");
    await expect(listbox).toBeVisible();
    await selector.press("End");
    await expect(listbox.getByRole("option").last()).toHaveClass(/is-active/u);
    await selector.press("Enter");
    expect((await readTitaniumOptions(selector)).find((option) => option.selected)?.value).toBe("custom");
    await expect(selector).toContainText("Custom");
    await expect(listbox).toBeHidden();

    await selector.press("Home");
    await expect(listbox).toBeVisible();
    await selector.press("Escape");
    await expect(listbox).toBeHidden();
    await expect(selector).toBeFocused();
  });

  test("e2e.mission-intake.autonomous-exact-htb-host produces a bounded exploit-ready contract without changing the IP target type", async ({ page }, testInfo) => {
    test.setTimeout(150_000);
    const backend = await startReadyAutonomousIntakeBackend(testInfo.testId);
    try {
      await proxyV2ApiTo(page, backend.baseUrl);
      await page.goto(route("autonomous"));
      const environment = titaniumSelect(page, /Environment classification/u);
      await chooseTitaniumOption(environment, "htb");
      await page.getByLabel("Authorized targets or environment references", { exact: false })
        .fill("10.129.39.191");
      await page.getByRole("checkbox", {
        name: /I confirm these targets and the selected action policy are authorized/u,
      }).check();

      const scopeResolve = await clickContinue(page, "Outcome and collaboration");
      const scopeRequest = scopeResolve.request().postDataJSON() as Record<string, unknown>;
      expect(scopeRequest).toMatchObject({
        environmentClassification: "htb",
        targets: [{ value: "10.129.39.191" }],
      });
      expect((scopeRequest.targets as Array<Record<string, unknown>>)[0]).not.toHaveProperty("type");
      const scopeResolved = await scopeResolve.json() as ResolvedMissionIntake;
      expect(scopeResolved.normalizedTargets[0]).toMatchObject({
        value: "10.129.39.191",
        type: "host",
      });
      expect(scopeResolved.request.journey === "autonomous"
        && scopeResolved.request.authorization.environmentClassification).toBe("htb");

      await clickContinue(page, "Autonomous operating contract");
      const destructive = titaniumSelect(page, /Destructive-action policy/u);
      await chooseTitaniumOption(destructive, "bounded_lab_only");
      const bounded = group(page, "Named disposable lab targets");
      const exactHost = bounded.getByRole("checkbox", { name: /10\.129\.39\.191.*Exact authorized host/u });
      await expect(exactHost).toBeVisible();
      await exactHost.check();

      const actionMatrix = await openDetails(page, "Action-class policy matrix");
      const exploitRow = actionMatrix.locator("article.os-policy-row").filter({ hasText: "Exploit validation" });
      await expect(exploitRow).toHaveCount(1);
      await chooseTitaniumOption(exploitRow.getByRole("combobox", { name: /Exploit validation policy/u }), "pre_authorized");

      const contractResolve = await clickContinue(page, "Specialist team and execution readiness", {
        autonomousPreflight: true,
      });
      const resolved = await contractResolve.json() as ResolvedMissionIntake;
      expect(resolved.request.journey).toBe("autonomous");
      if (resolved.request.journey !== "autonomous") throw new Error("Expected Autonomous request");
      expect(resolved.normalizedTargets[0]?.type).toBe("host");
      expect(resolved.request.authorization.environmentClassification).toBe("htb");
      expect(resolved.request.contract.destructivePolicy).toBe("bounded_lab_only");
      expect(resolved.request.contract.boundedDestructiveTargets).toEqual(["10.129.39.191"]);
      expect(resolved.request.contract.allowedActionClasses).toContain("exploit_validation");
      expect(resolved.request.contract.memoryScopes).toContain("verified_attack_knowledge");

      await page.goto(route("autonomous"));
      await chooseTitaniumOption(titaniumSelect(page, /Environment classification/u), "internal");
      await page.getByLabel("Authorized targets or environment references", { exact: false })
        .fill("10.129.39.191");
      await page.getByRole("checkbox", {
        name: /I confirm these targets and the selected action policy are authorized/u,
      }).check();
      await clickContinue(page, "Outcome and collaboration");
      await clickContinue(page, "Autonomous operating contract");
      await chooseTitaniumOption(titaniumSelect(page, /Destructive-action policy/u), "bounded_lab_only");
      const nonDisposable = group(page, "Named disposable lab targets");
      await expect(nonDisposable.getByRole("checkbox")).toHaveCount(0);
      await expect(nonDisposable).toContainText(
        "this mission is classified as a non-disposable environment",
      );
    } finally {
      await backend.stop();
    }
  });

  test("e2e.mission-intake.autonomous-readiness-refresh retires a stale blocker snapshot", async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    createMissionIntakeDynamicFixture(testInfo.testId);
    let runtimeReady = false;
    let preflightCalls = 0;

    await page.route("**/api/v2/system/readiness", async (route) => {
      const response = await route.fetch();
      const body = await response.json() as RuntimeReadinessSnapshot;
      const simulated: RuntimeReadinessSnapshot = {
        ...body,
        status: runtimeReady ? "healthy" : "degraded",
        execution: {
          ...body.execution,
          autonomous: runtimeReady ? "ready" : "unavailable",
          actionBoundaryActive: runtimeReady,
          delegationEnforced: runtimeReady,
          noHandsCommanderEnforced: runtimeReady,
        },
        dependencies: {
          ...body.dependencies,
          providers: runtimeReady ? body.dependencies.providers : {
            ...body.dependencies.providers,
            status: "unavailable",
            reason: "The enforcing provider path has not finished its current attestation.",
            callable: 0,
            enforcing: 0,
          },
          mcp: runtimeReady ? body.dependencies.mcp : {
            ...body.dependencies.mcp,
            status: "unavailable",
            reason: "No reviewed Autonomous MCP path is currently attested.",
            runnableServers: 0,
            executionMode: "disabled",
          },
        },
        checkedAt: new Date().toISOString(),
      };
      await route.fulfill({ response, json: simulated });
    });

    await page.route("**/api/v2/missions/autonomous/preflight", async (route) => {
      preflightCalls += 1;
      const response = await route.fetch();
      const body = await response.json() as AutonomousMissionPreflight;
      if (runtimeReady) await new Promise((resolve) => setTimeout(resolve, 750));
      const simulated: AutonomousMissionPreflight = {
        ...body,
        readiness: runtimeReady ? {
          status: "ready",
          score: 100,
          checks: body.readiness.checks.map((check) => ({
            ...check,
            status: "pass",
            remediation: undefined,
          })),
        } : {
          status: "blocked",
          score: 51,
          checks: [...STALE_AUTONOMOUS_CHECKS],
        },
      };
      await route.fulfill({ response, json: simulated });
    });

    await page.goto(route("autonomous"));
    await page.getByLabel("Authorized targets or environment references", { exact: false })
      .fill("lab:stale-readiness-refresh");
    await page.getByRole("checkbox", { name: /I confirm these targets/u }).check();
    await clickContinue(page, "Outcome and collaboration");
    await clickContinue(page, "Autonomous operating contract");
    await clickContinue(page, "Specialist team and execution readiness", { autonomousPreflight: true });
    await clickContinue(page, "Second Brain context", { autonomousPreflight: true });
    await clickContinue(page, "Review the resolved mission", { autonomousPreflight: true });

    const review = page.locator(".os-autonomous-readiness");
    await expect(review.getByLabel("Autonomous readiness score 51 out of 100")).toBeVisible();
    await expect(review).toContainText("9 failing checks prevent unattended execution");
    const callsBeforeRecovery = preflightCalls;

    runtimeReady = true;
    await expect(review).toHaveAttribute("data-readiness-review-state", "refreshing", { timeout: 15_000 });
    await expect(review).toContainText("retired the old score and blockers");
    await expect(review).not.toContainText("51/100");
    await expect(review).not.toContainText("9 failing checks prevent unattended execution");

    await expect(review.getByLabel("Autonomous readiness score 100 out of 100"))
      .toBeVisible({ timeout: 15_000 });
    expect(preflightCalls).toBeGreaterThan(callsBeforeRecovery);
    await expect(review).toContainText("Autonomous launch is ready");
    await expect(review).not.toContainText("51/100");
    await expect(review).not.toContainText("9 failing checks prevent unattended execution");
  });

  test("e2e.mission-intake.autonomous-launch-keyboard creates a durable ready mission", async ({ page, browserAudit }, testInfo) => {
    test.setTimeout(180_000);
    const backend = await startReadyAutonomousIntakeBackend(testInfo.testId);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    // The success-path fixture must use a concrete target kind accepted by a
    // reviewed Autonomous executor. An opaque lab reference is valid intake
    // data, but it cannot truthfully produce an executable plan until a
    // deployment-specific environment resolver maps it to exact targets.
    const target = "127.0.0.1";
    try {
      await proxyV2ApiTo(page, backend.baseUrl);
      await exerciseMinimalScope(page, "autonomous", target);
      await chooseTitaniumOption(
        titaniumSelect(page, /Environment classification/u),
        "local_disposable_lab",
      );
      await clickContinue(page, "Outcome and collaboration");
      await clickContinue(page, "Autonomous operating contract");
      const contractResolve = await clickContinue(page, "Specialist team and execution readiness", {
        autonomousPreflight: true,
      });
      expectRecommendedContractFieldsOmitted(contractResolve);
      const resolvedContract = await contractResolve.json() as ResolvedMissionIntake;

      const team = group(page, "Specialist team and execution readiness");
      const specialistRows = team.locator("label.os-check-field");
      await expect(specialistRows).toHaveCount(backend.productAgents.length);
      expect(backend.productAgents).toHaveLength(12);
      expect(
        await specialistRows.locator("strong").allTextContents(),
      ).toEqual(
        backend.productAgents
          .map(({ displayName }) => displayName)
          .sort((left, right) => left.localeCompare(right)),
      );
      for (const agent of backend.productAgents) {
        const specialist = team.getByRole("checkbox", {
          name: new RegExp(
            `^${agent.displayName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")} ${agent.role.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}`,
            "u",
          ),
        });
        await expect(specialist).toBeEnabled();
      }
      await expect(team.getByText("Isolated full-contract runtime adapter", { exact: false }))
        .toHaveCount(0);
      await page.getByRole("button", { name: "Use recommended team", exact: true }).click();
      await expect(team.locator('input[type="checkbox"]:checked'))
        .toHaveCount(backend.productAgents.length);

      await clickContinue(page, "Second Brain context", { autonomousPreflight: true });
      const context = group(page, "Second Brain context");
      for (const node of backend.memoryNodes) {
        const selection = context.getByRole("checkbox", {
          name: new RegExp(node.title.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"),
        });
        await expect(selection).toBeEnabled();
        await selection.check();
        await expect(selection).toBeChecked();
      }
      const reviewPreflightPromise = page.waitForResponse((response) =>
        response.url().endsWith("/api/v2/missions/autonomous/preflight")
        && response.request().method() === "POST");
      await clickContinue(page, "Review the resolved mission", { autonomousPreflight: true });
      const reviewPreflightResponse = await reviewPreflightPromise;
      expect(reviewPreflightResponse.status(), await reviewPreflightResponse.text()).toBe(200);
      const reviewPreflight = await reviewPreflightResponse.json() as AutonomousMissionPreflight;
      expect(reviewPreflight.readiness.status).toBe("ready");
      expect(reviewPreflight.readiness.checks.filter(({ status }) => status === "fail")).toEqual([]);
      expect(reviewPreflight.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_agent_model_assignments",
        status: "pass",
      }));
      expect(reviewPreflight.execution.team.effectiveAgentIds).toEqual(
        backend.productAgents.map(({ id }) => id),
      );
      expect(reviewPreflight.context.selectedNodeIds).toEqual(
        expect.arrayContaining(backend.memoryNodes.map(({ id }) => id)),
      );
      expect(reviewPreflight.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_attack_memory_vault",
        status: "pass",
      }));
      await expectResolvedContractChecklist(page, resolvedContract);

      const review = group(page, "Review the resolved mission");
      const readiness = review.locator(".os-readiness-summary");
      await expect(readiness).toContainText("ready");
      await expect(readiness).toContainText("no Autonomous launch blocker is reported");
      const launch = page.getByRole("button", { name: "Launch Autonomous Assessment", exact: true });
      await expect(launch).toBeEnabled();
      const createdPromise = page.waitForResponse((response) =>
        response.url().endsWith("/api/v2/missions")
        && response.request().method() === "POST");
      await launch.focus();
      await page.keyboard.press("Enter");
      const createdResponse = await createdPromise;
      expect(createdResponse.status(), await createdResponse.text()).toBe(201);
      const createBody = createdResponse.request().postDataJSON() as {
        journey: string;
        launch: boolean;
        authorization: {
          authorizationConfirmed: boolean;
          allowedTargets: string[];
        };
        contract: { specialistAgentIds: string[] };
        contractReview?: { version: number; hash: string };
      };
      expect(createBody).toMatchObject({
        journey: "autonomous",
        launch: true,
        authorization: {
          authorizationConfirmed: true,
          allowedTargets: [target],
        },
        contract: {
          specialistAgentIds: backend.productAgents.map(({ id }) => id),
        },
        contractReview: {
          version: reviewPreflight.contract.version,
          hash: reviewPreflight.contract.hash,
        },
      });
      const created = await createdResponse.json() as {
        mission: { id: string; title: string; journey: string };
        run: { id: string; status: string; journey: string };
        nextUrl: string;
      };
      expect(created).toMatchObject({
        mission: { journey: "autonomous" },
        run: { status: "planning", journey: "autonomous" },
      });
      expect(created.nextUrl).toBe(`/missions/${created.mission.id}`);
      await expect.poll(() => new URL(page.url()).pathname).toBe(created.nextUrl);

      const persistedResponse = await page.evaluate(async (path) => {
        const response = await fetch(path, { headers: { accept: "application/json" } });
        return { status: response.status, body: await response.text() };
      }, `/api/v2/missions?query=${encodeURIComponent(created.mission.id)}`);
      expect(persistedResponse.status, persistedResponse.body).toBe(200);
      const persisted = JSON.parse(persistedResponse.body) as {
        items: Array<{ id: string; title: string; journey: string }>;
      };
      expect(persisted.items).toContainEqual(expect.objectContaining({
        id: created.mission.id,
        title: created.mission.title,
        journey: "autonomous",
      }));
      await expect(page.getByRole("region", { name: "Selected run status" })).toContainText("Planning autonomously");
      await expect(page.getByRole("region", { name: "Mission workspace" })).toBeVisible();
      await expect(page.getByRole("alert")).toHaveCount(0);
      await audit.assertClean(testInfo);
    } finally {
      try {
        if (!page.isClosed()) {
          await browserAudit.closePageBeforeDependencyShutdown(page);
        }
      } finally {
        await backend.stop();
      }
    }
  });

  test("e2e.mission-intake.autonomous-minimal resolves defaults and remains fail-closed", async ({ page, browserAudit, interactionActivation }, testInfo) => {
    // The minimal journey deliberately activates every rendered template,
    // budget, destructive-policy, and per-action-class option. Mobile WebKit
    // therefore performs more than one hundred audited interactions.
    test.setTimeout(300_000);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    // Specialist/model resolution is sourced only from the signed runtime
    // manifest. Database health rows seeded by createMissionIntakeDynamicFixture
    // cannot legally manufacture that source-of-truth binding. Use the
    // disposable exact-runtime backend already shared by the ready launch
    // carrier, then keep this opaque target fail-closed at outcome readiness.
    const backend = await startReadyAutonomousIntakeBackend(testInfo.testId);
    const reconScout = backend.productAgents.find(({ id }) => id === "ReconScout");
    const contextMemory = backend.memoryNodes[0];
    if (!reconScout || !contextMemory) {
      await backend.stop();
      throw new Error("The exact-runtime intake fixture is missing ReconScout or its confirmed context node");
    }
    const dynamicFixture: MissionIntakeDynamicFixture = {
      agentId: reconScout.id,
      agentName: reconScout.displayName,
      memoryNodeId: contextMemory.id,
      memoryTitle: contextMemory.title,
    };
    const receiptContext: IntakeReceiptContext = {
      recorder: interactionActivation,
      testId: TEST_AUTONOMOUS_MINIMAL,
    };
    const target = "lab:autonomous-intake-approved-visual";
    try {
      await proxyV2ApiTo(page, backend.baseUrl);
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
    const contractResolve = await clickContinue(page, "Specialist team and execution readiness", { autonomousPreflight: true });
    expectRecommendedContractFieldsOmitted(contractResolve);
    const resolvedContract = await contractResolve.json() as ResolvedMissionIntake;
    await exerciseAutonomousTeam(page, dynamicFixture);
    await clickContinue(page, "Second Brain context", { autonomousPreflight: true });
    await exerciseAutonomousContext(page, dynamicFixture);
    const reviewPreflightPromise = page.waitForResponse((response) =>
      response.url().endsWith("/api/v2/missions/autonomous/preflight")
      && response.request().method() === "POST");
    await clickContinue(page, "Review the resolved mission", { autonomousPreflight: true });
    const reviewPreflightResponse = await reviewPreflightPromise;
    expect(reviewPreflightResponse.status(), await reviewPreflightResponse.text()).toBe(200);
    const reviewPreflight = await reviewPreflightResponse.json() as AutonomousMissionPreflight;
    expect(reviewPreflight.readiness.status).toBe("blocked");
    expect(reviewPreflight.execution.team.effectiveAgentIds).toEqual([dynamicFixture.agentId]);
    const launchBlockerCount = reviewPreflight.readiness.checks.filter(({ status }) => status === "fail").length;
    expect(launchBlockerCount).toBeGreaterThan(0);
    const launchBlockerCopy = launchBlockerCount === 1
      ? "1 failing check prevents unattended execution"
      : `${launchBlockerCount} failing checks prevent unattended execution`;

    const review = group(page, "Review the resolved mission");
    await expect(review).toContainText("Autonomous");
    await expect(review).toContainText(target);
    await expect(review).toContainText("Inferred by recommended defaults");
    await expect(review).toContainText("Mission title, Authorized objective");
    await expectResolvedContractChecklist(page, resolvedContract);
    await expect(review).toContainText(
      "No target-compatible reviewed outcome producer is mounted for the supplied target type.",
    );
    const readiness = review.locator(".os-readiness-summary");
    await expect(readiness).toContainText("blocked");
    await expect(readiness).toContainText(launchBlockerCopy);
    await expect(review.getByText("Signed Autonomous specialists", { exact: true }).locator("xpath=..").locator("dd"))
      .toHaveText(String(reviewPreflight.execution.team.effectiveAgentIds.length));
    const launch = page.getByRole("button", { name: "Launch Autonomous Assessment", exact: true });
    let missionCreateRequests = 0;
    const recordMissionCreateRequest = (request: { method(): string; url(): string }) => {
      const url = new URL(request.url());
      if (request.method() === "POST" && url.pathname === "/api/v2/missions") {
        missionCreateRequests += 1;
      }
    };
    page.on("request", recordMissionCreateRequest);
    await assertAutonomousIntakeGuard(
      receiptContext,
      "autonomous-intake.review.launch-blocked-guard",
      "Blocked launch remains disabled and sends no mission request",
      async () => {
        await expect(launch).toBeDisabled();
        await expect(readiness).toContainText("blocked");
        await expect(readiness).toContainText(launchBlockerCopy);
        expect(missionCreateRequests).toBe(0);
      },
    );
    page.off("request", recordMissionCreateRequest);
    const visual = page.locator(".os-contract-form > .os-card");
    await normalizeAutonomousReviewVisual(visual);
    await expectApprovedVisual(visual, testInfo);
      await audit.assertClean(testInfo);
    } finally {
      if (!page.isClosed()) {
        await browserAudit.closePageBeforeDependencyShutdown(page);
      }
      await backend.stop();
    }
  });

  test("e2e.mission-intake.guided-minimal creates and reopens a real durable Guided mission", async ({ page, browserAudit, interactionActivation }, testInfo) => {
    test.setTimeout(300_000);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const receiptContext: IntakeReceiptContext = {
      recorder: interactionActivation,
      testId: TEST_GUIDED_MINIMAL,
    };
    const target = `lab:guided-intake-${Date.now()}`;
    await exerciseMinimalScope(page, "guided", target, receiptContext);
    await clickContinue(page, "Outcome and collaboration");
    await exerciseOutcome(page, "guided");
    await clickContinue(page, "Guided proposal boundaries");
    await exerciseContract(page, "guided", receiptContext);
    const contractResolve = await clickContinue(page, "Review the resolved mission");
    expectRecommendedContractFieldsOmitted(contractResolve);
    const resolvedContract = await contractResolve.json() as ResolvedMissionIntake;

    const review = group(page, "Review the resolved mission");
    await expect(review).toContainText("Guided");
    await expect(review).toContainText(target);
    await expect(review).toContainText("Explain → recommend → choose → observe → interpret → record → advance");
    await expectResolvedContractChecklist(page, resolvedContract);
    await audit.assertClean(testInfo);
    await activateIf(
      receiptContext,
      "guided-intake.review.launch",
      "Create durable Guided mission",
      "keyboard",
      async () => {
        const createdPromise = page.waitForResponse((response) => response.url().endsWith("/api/v2/missions") && response.request().method() === "POST");
        const runtimePromise = page.waitForResponse((response) => /\/api\/v2\/missions\/[^/]+\/runtime$/u.test(new URL(response.url()).pathname));
        const launch = page.getByRole("button", { name: "Start Guided Mission", exact: true });
        await launch.focus();
        await page.keyboard.press("Enter");
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
      },
    );
    await audit.assertClean(testInfo);
  });

  test("e2e.mission-intake.guided-launch-pointer creates a durable represented mission", async ({ page, browserAudit, interactionActivation }, testInfo) => {
    test.setTimeout(180_000);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const receiptContext: IntakeReceiptContext = {
      recorder: interactionActivation,
      testId: TEST_GUIDED_MINIMAL,
    };
    const target = `lab:guided-pointer-launch-${Date.now()}`;
    await exerciseMinimalScope(page, "guided", target);
    await clickContinue(page, "Outcome and collaboration");
    await clickContinue(page, "Guided proposal boundaries");
    const contractResolve = await clickContinue(page, "Review the resolved mission");
    expectRecommendedContractFieldsOmitted(contractResolve);
    const resolvedContract = await contractResolve.json() as ResolvedMissionIntake;
    await expectResolvedContractChecklist(page, resolvedContract);

    await activateIf(
      receiptContext,
      "guided-intake.review.launch",
      "Create durable Guided mission",
      "pointer",
      async () => {
        const createdPromise = page.waitForResponse((response) =>
          response.url().endsWith("/api/v2/missions")
          && response.request().method() === "POST");
        const runtimePromise = page.waitForResponse((response) =>
          /\/api\/v2\/missions\/[^/]+\/runtime$/u.test(new URL(response.url()).pathname));
        await page.getByRole("button", { name: "Start Guided Mission", exact: true }).click();
        const createdResponse = await createdPromise;
        expect(createdResponse.status(), await createdResponse.text()).toBe(201);
        expect(createdResponse.request().postDataJSON()).toMatchObject({
          journey: "guided",
          authorizationConfirmed: true,
          target,
          explanationDepth: "balanced",
          executionPreference: "manual",
        });
        const created = await createdResponse.json() as {
          mission: { id: string; title: string; journey: string };
          run: { id: string; status: string; journey: string };
          nextUrl: string;
        };
        expect(created).toMatchObject({
          mission: { journey: "guided" },
          run: { status: "planning", journey: "guided" },
        });
        expect(created.nextUrl).toBe(`/guided/${created.mission.id}`);
        await expect.poll(() => new URL(page.url()).pathname).toBe(created.nextUrl);
        const runtimeResponse = await runtimePromise;
        expect(runtimeResponse.status(), await runtimeResponse.text()).toBe(200);
        const runtime = await runtimeResponse.json() as {
          mission: { id: string; journey: string };
          runs: Array<{ missionId: string; journey: string; status: string; nextAction: string }>;
        };
        expect(runtime).toMatchObject({
          mission: { id: created.mission.id, journey: "guided" },
          runs: [expect.objectContaining({
            missionId: created.mission.id,
            journey: "guided",
            status: "planning",
            nextAction: "Explain the assessment path and recommend the first bounded step",
          })],
        });
        const persistedResponse = await browserAudit.request(page.request, {
          method: "GET",
          url: `/api/v2/missions?query=${encodeURIComponent(created.mission.id)}`,
        });
        expect(persistedResponse.status(), await persistedResponse.text()).toBe(200);
        const persisted = await persistedResponse.json() as {
          items: Array<{ id: string; title: string; journey: string }>;
        };
        expect(persisted.items).toContainEqual(expect.objectContaining({
          id: created.mission.id,
          title: created.mission.title,
          journey: "guided",
        }));
        await expect(page.getByRole("region", { name: "Selected run status" })).toContainText("planning");
        await expect(page.getByRole("alert")).toHaveCount(0);
      },
    );
    await audit.assertClean(testInfo);
  });

  test("e2e.mission-intake.guided-nmap-operator-flow persists exact ports and an unavailable manual fallback", async ({ page }, testInfo) => {
    test.setTimeout(180_000);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const target = "10.10.10.20";
    await exerciseMinimalScope(page, "guided", target);
    await clickContinue(page, "Outcome and collaboration");

    const recommended = page.getByRole("radio", { name: /^Use recommended target-based behavior/u });
    const liveness = page.getByRole("radio", { name: /^Check host reachability/u });
    const tcp = page.getByRole("radio", { name: /^Scan selected TCP services/u });
    await expect(recommended).toBeChecked();
    await expect(liveness).toBeEnabled();
    await expect(tcp).toBeEnabled();
    await liveness.check();
    await expect(liveness).toBeChecked();
    await tcp.check();
    await expect(tcp).toBeChecked();
    await expect(group(page, "Outcome and collaboration")).toContainText("Guided can still launch with a represented manual step");

    const portSelection = titaniumSelect(page, /^TCP port selection/u);
    const presetOptions = await titaniumOptions(portSelection);
    expect(presetOptions.map(({ value }) => value)).toEqual([
      "focused_services",
      "web_services",
      "remote_management",
      "custom",
    ]);
    await chooseTitaniumOption(portSelection, "custom");
    const customPorts = page.getByRole("textbox", { name: /^Custom TCP ports/u });
    await customPorts.fill("22-25");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await expect(page.getByRole("alert").filter({ hasText: "Resolve before continuing" }))
      .toContainText("Use comma-separated individual port numbers only, such as 22, 80, 443");
    await customPorts.fill("8443, 22, 443, 22");
    const outcomeResolve = await clickContinue(page, "Guided proposal boundaries");
    expect(outcomeResolve.request().postDataJSON()).toMatchObject({
      journey: "guided",
      executionPreference: "manual",
      guidedReconnaissance: {
        mode: "tcp_service_scan",
        portSelection: { source: "custom", ports: [22, 443, 8443] },
      },
    });

    await page.getByRole("button", { name: "Back", exact: true }).click();
    await expect(group(page, "Outcome and collaboration")).toBeVisible();
    await expect(tcp).toBeChecked();
    await expect(customPorts).toHaveValue("8443, 22, 443, 22");
    await clickContinue(page, "Guided proposal boundaries");
    await clickContinue(page, "Review the resolved mission");
    const review = group(page, "Review the resolved mission");
    await expect(review).toContainText("Selected TCP service scan");
    await expect(review).toContainText("Custom operator list");
    await expect(review).toContainText("22,443,8443");
    await expect(review).toContainText("Launching now preserves this selection as the represented manual fallback");

    const createdPromise = page.waitForResponse((response) => response.url().endsWith("/api/v2/missions") && response.request().method() === "POST");
    await page.getByRole("button", { name: "Start Guided Mission", exact: true }).click();
    const createdResponse = await createdPromise;
    expect(createdResponse.status(), await createdResponse.text()).toBe(201);
    expect(createdResponse.request().postDataJSON()).toMatchObject({
      journey: "guided",
      target,
      guidedReconnaissance: {
        mode: "tcp_service_scan",
        portSelection: { source: "custom", ports: [22, 443, 8443] },
      },
    });
    const created = await createdResponse.json() as { mission: { id: string } };
    await expect.poll(() => new URL(page.url()).pathname).toBe(`/guided/${created.mission.id}`);
    await audit.waitForPageApiSettlement(page, { quietMs: 750 });
    await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload());
    await expect(page.getByRole("region", { name: "Selected run status" })).toContainText("planning");
    await expect(page.getByRole("alert")).toHaveCount(0);
    await audit.assertClean(testInfo);
  });

  test(`${TEST_GUIDED_WINDOWS_IDENTITY} enforces ready, exclusive, exact-step Windows identity intake`, async ({
    page,
    browserAudit,
    interactionActivation,
  }, testInfo) => {
    test.setTimeout(240_000);
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const backend = await startReadyAutonomousIntakeBackend(
      testInfo.testId,
      { profile: "guided_windows_identity" },
    );
    const receiptContext: IntakeReceiptContext = {
      recorder: interactionActivation,
      testId: TEST_GUIDED_WINDOWS_IDENTITY,
    };
    const target = "10.10.10.44";
    const credentialReference = "systemd/windows/lab-reader";
    const selectRadio = async (
      manifestEntryId: string,
      option: string,
      radio: Locator,
      modality: "pointer" | "keyboard",
    ) => activateIf(
      receiptContext,
      manifestEntryId,
      option,
      modality,
      async () => {
        if (modality === "pointer") {
          await radio.click();
        } else {
          await radio.focus();
          await radio.press("Space");
        }
        await expect(radio).toBeChecked();
      },
    );

    try {
      await proxyV2ApiTo(page, backend.baseUrl);
      for (const modality of ["pointer", "keyboard"] as const) {
        await exerciseMinimalScope(page, "guided", target);
        await clickContinue(page, "Outcome and collaboration");

        const outcome = group(page, "Outcome and collaboration");
        const manual = outcome.getByRole("radio", {
          name: /^I run commands manually/u,
        });
        const singleStep = outcome.getByRole("radio", {
          name: /^Allow one represented agent step/u,
        });
        const recommendedRecon = outcome.getByRole("radio", {
          name: /^Use recommended target-based behavior/u,
        });
        const tcpRecon = outcome.getByRole("radio", {
          name: /^Scan selected TCP services/u,
        });
        const noIdentity = outcome.getByRole("radio", {
          name: /^No Windows or identity override/u,
        });
        const smbShares = outcome.getByRole("radio", {
          name: /^List the SMB shares the approved host exposes/u,
        });
        const smbSummary = outcome.getByRole("radio", {
          name: /^Read the approved host’s SMB identity summary/u,
        });
        const ldapRoot = outcome.getByRole("radio", {
          name: /^Read the LDAP directory’s public root metadata/u,
        });
        const rpcDomain = outcome.getByRole("radio", {
          name: /^Read the approved host’s RPC domain summary/u,
        });

        await expect(manual).toBeChecked();
        await expect(noIdentity).toBeChecked();
        await expect(smbShares).toBeEnabled();
        await expect(smbSummary).toBeEnabled();
        await expect(ldapRoot).toBeEnabled();
        if (modality === "pointer") {
          const rpcEntry = manifest.entries.find(
            ({ id }) => id === "guided-intake.outcome.identity-rpc-domain-info",
          );
          if (!rpcEntry) throw new Error("RPC identity guard is missing from the interaction manifest");
          await interactionActivation.assertGuard({
            manifestEntryId: rpcEntry.id,
            controlId: rpcEntry.controlId,
            option: "Unavailable operation remains disabled",
            materialState: rpcEntry.requiredState,
            testId: TEST_GUIDED_WINDOWS_IDENTITY,
          }, async () => {
            await expect(rpcDomain).toBeDisabled();
            await expect(rpcDomain).not.toBeChecked();
          });
        }

        await tcpRecon.check();
        await expect(tcpRecon).toBeChecked();
        await selectRadio(
          "guided-intake.outcome.identity-smb-share-list",
          "Select bounded SMB share listing",
          smbShares,
          modality,
        );
        await expect(tcpRecon).not.toBeChecked();
        await expect(recommendedRecon).not.toBeChecked();
        await expect(singleStep).toBeChecked();
        await expect(manual).toBeDisabled();

        await selectRadio(
          "guided-intake.outcome.identity-smb-summary",
          "Select credentialed SMB identity summary",
          smbSummary,
          modality,
        );
        await expect(outcome.getByRole("textbox", {
          name: /^Credential bundle reference/u,
        })).toBeVisible();
        await selectRadio(
          "guided-intake.outcome.identity-ldap-root-dse",
          "Select anonymous LDAP root metadata",
          ldapRoot,
          modality,
        );
        await expect(outcome.getByRole("textbox", {
          name: /^Credential bundle reference/u,
        })).toHaveCount(0);

        await selectRadio(
          "guided-intake.outcome.identity-none",
          "Remove Windows or identity override",
          noIdentity,
          modality,
        );
        await expect(manual).toBeEnabled();
        await selectRadio(
          "guided-intake.outcome.identity-smb-share-list",
          "Select bounded SMB share listing",
          smbShares,
          modality,
        );

        const authentication = titaniumSelect(
          outcome,
          /^Authentication mode/u,
        );
        expect((await titaniumOptions(authentication)).map(({ value }) => value))
          .toEqual(["anonymous", "credential_reference"]);
        await activateIf(
          receiptContext,
          "guided-intake.outcome.identity-authentication-mode",
          "Private credential reference",
          modality,
          () => chooseTitaniumOption(authentication, "credential_reference", modality),
        );
        await activateIf(
          receiptContext,
          "guided-intake.outcome.identity-authentication-mode",
          "Anonymous metadata read",
          modality,
          () => chooseTitaniumOption(authentication, "anonymous", modality),
        );
        await activateIf(
          receiptContext,
          "guided-intake.outcome.identity-authentication-mode",
          "Private credential reference",
          modality,
          () => chooseTitaniumOption(authentication, "credential_reference", modality),
        );
        const credential = outcome.getByRole("textbox", {
          name: /^Credential bundle reference/u,
        });
        await activateIf(
          receiptContext,
          "guided-intake.outcome.identity-credential-reference",
          "Enter opaque systemd credential bundle reference",
          modality,
          async () => {
            if (modality === "pointer") {
              await credential.click();
              await credential.fill(credentialReference);
            } else {
              await credential.focus();
              await credential.pressSequentially(credentialReference);
            }
            await expect(credential).toHaveValue(credentialReference);
          },
        );

        const identityResolve = await clickContinue(
          page,
          "Guided proposal boundaries",
        );
        const identityRequest = identityResolve.request().postDataJSON() as Record<string, unknown>;
        expect(identityRequest).toMatchObject({
          journey: "guided",
          executionPreference: "single_step_agent",
          guidedWindowsIdentity: {
            operation: "smb_share_list",
            authenticationMode: "credential_reference",
            credentialReference: {
              kind: "systemd_credential_bundle",
              id: credentialReference,
            },
          },
        });
        expect(identityRequest).not.toHaveProperty("guidedReconnaissance");
        const identityResolved = await identityResolve.json() as ResolvedMissionIntake;
        expect(identityResolved.request).toMatchObject({
          journey: "guided",
          guidedWindowsIdentity: {
            operation: "smb_share_list",
            authenticationMode: "credential_reference",
            credentialReference: {
              kind: "systemd_credential_bundle",
              id: credentialReference,
            },
          },
        });

        await page.getByRole("button", { name: "Back", exact: true }).click();
        await expect(outcome).toBeVisible();
        await tcpRecon.check();
        await expect(noIdentity).toBeChecked();
        await expect(smbShares).not.toBeChecked();
        await expect(manual).toBeEnabled();
        await manual.check();
        const reconResolve = await clickContinue(
          page,
          "Guided proposal boundaries",
        );
        const reconRequest = reconResolve.request().postDataJSON() as Record<string, unknown>;
        expect(reconRequest).toMatchObject({
          journey: "guided",
          executionPreference: "manual",
          guidedReconnaissance: {
            mode: "tcp_service_scan",
          },
        });
        expect(reconRequest).not.toHaveProperty("guidedWindowsIdentity");
      }
      await audit.assertClean(testInfo);
    } finally {
      if (!page.isClosed()) {
        await browserAudit.closePageBeforeDependencyShutdown(page);
      }
      await backend.stop();
    }
  });

  test(`${TEST_GUIDED_LOCAL_EXPLOIT_INTELLIGENCE} submits one local-only CVE or technology lookup by pointer and keyboard`, async ({
    page,
    browserAudit,
    interactionActivation,
  }, testInfo) => {
    test.setTimeout(240_000);
    const audit = new BrowserAudit(page, {
      allowEventStreamNavigationAbort: true,
    });
    const backend = await startReadyAutonomousIntakeBackend(
      testInfo.testId,
      { profile: "guided_local_exploit_intelligence" },
    );
    const receiptContext: IntakeReceiptContext = {
      recorder: interactionActivation,
      testId: TEST_GUIDED_LOCAL_EXPLOIT_INTELLIGENCE,
    };
    const target = "web01.lab.test";

    const selectRadio = async (
      manifestEntryId: string,
      option: string,
      radio: Locator,
      modality: "pointer" | "keyboard",
    ) => activateIf(
      receiptContext,
      manifestEntryId,
      option,
      modality,
      async () => {
        if (modality === "pointer") {
          await radio.click();
        } else {
          await radio.focus();
          await radio.press("Space");
        }
        await expect(radio).toBeChecked();
      },
    );

    const replaceInput = async (
      manifestEntryId: string,
      option: string,
      input: Locator,
      value: string,
      modality: "pointer" | "keyboard",
    ) => activateIf(
      receiptContext,
      manifestEntryId,
      option,
      modality,
      async () => {
        if (modality === "pointer") {
          await input.click();
          await input.fill(value);
        } else {
          await input.focus();
          await input.press("ControlOrMeta+A");
          await input.pressSequentially(value);
        }
        await expect(input).toHaveValue(value);
      },
    );

    try {
      await proxyV2ApiTo(page, backend.baseUrl);
      for (const modality of ["pointer", "keyboard"] as const) {
        await exerciseMinimalScope(page, "guided", target);
        await clickContinue(page, "Outcome and collaboration");

        const outcome = group(page, "Outcome and collaboration");
        const manual = outcome.getByRole("radio", {
          name: /^I run commands manually/u,
        });
        const singleStep = outcome.getByRole("radio", {
          name: /^Allow one represented agent step/u,
        });
        const tcpRecon = outcome.getByRole("radio", {
          name: /^Scan selected TCP services/u,
        });
        const smbShares = outcome.getByRole("radio", {
          name: /^List the SMB shares the approved host exposes/u,
        });
        const noLocalLookup = outcome.getByRole("radio", {
          name: /^No local ExploitDB override/u,
        });
        const cveLookup = outcome.getByRole("radio", {
          name: /^Look up a CVE in the local catalog/u,
        });
        const technologyLookup = outcome.getByRole("radio", {
          name: /^Look up a product and version locally/u,
        });

        await expect(noLocalLookup).toBeChecked();
        await expect(cveLookup).toBeEnabled();
        await expect(technologyLookup).toBeEnabled();
        await tcpRecon.check();
        await smbShares.check();
        await expect(tcpRecon).not.toBeChecked();
        await selectRadio(
          "guided-intake.outcome.local-exploit-cve",
          "Select local CVE lookup",
          cveLookup,
          modality,
        );
        await expect(smbShares).not.toBeChecked();
        await expect(tcpRecon).not.toBeChecked();
        await expect(singleStep).toBeChecked();
        await expect(manual).toBeDisabled();

        const cveId = outcome.getByRole("textbox", {
          name: /^CVE ID/u,
        });
        const maximumMatches = outcome.getByRole("spinbutton", {
          name: /^Maximum catalog matches/u,
        });
        await replaceInput(
          "guided-intake.outcome.local-exploit-cve-id",
          "Enter canonical CVE identifier",
          cveId,
          "cve-2021-44228",
          modality,
        );
        await replaceInput(
          "guided-intake.outcome.local-exploit-maximum-results",
          "Set bounded result limit",
          maximumMatches,
          "12",
          modality,
        );

        const cveResolve = await clickContinue(
          page,
          "Guided proposal boundaries",
        );
        expect(cveResolve.request().postDataJSON()).toMatchObject({
          journey: "guided",
          executionPreference: "single_step_agent",
          guidedLocalExploitIntelligence: {
            query: {
              kind: "cve",
              cveId: "CVE-2021-44228",
              maximumResults: 12,
            },
          },
        });
        const cveRequest =
          cveResolve.request().postDataJSON() as Record<string, unknown>;
        expect(cveRequest).not.toHaveProperty("guidedReconnaissance");
        expect(cveRequest).not.toHaveProperty("guidedWindowsIdentity");

        await page.getByRole("button", {
          name: "Back",
          exact: true,
        }).click();
        await expect(outcome).toBeVisible();
        await selectRadio(
          "guided-intake.outcome.local-exploit-none",
          "Remove local ExploitDB override",
          noLocalLookup,
          modality,
        );
        await smbShares.check();
        await expect(noLocalLookup).toBeChecked();
        await expect(cveLookup).not.toBeChecked();
        await tcpRecon.check();
        await expect(noLocalLookup).toBeChecked();
        await expect(cveLookup).not.toBeChecked();
        await expect(smbShares).not.toBeChecked();
        await expect(manual).toBeEnabled();

        await selectRadio(
          "guided-intake.outcome.local-exploit-technology",
          "Select local technology lookup",
          technologyLookup,
          modality,
        );
        await expect(tcpRecon).not.toBeChecked();
        await expect(singleStep).toBeChecked();
        const product = outcome.getByRole("textbox", {
          name: /^Product/u,
        });
        const version = outcome.getByRole("textbox", {
          name: /^Version/u,
        });
        const platform = outcome.getByRole("textbox", {
          name: /^Platform/u,
        });
        await replaceInput(
          "guided-intake.outcome.local-exploit-product",
          "Enter observed product",
          product,
          "Apache HTTP Server",
          modality,
        );
        await replaceInput(
          "guided-intake.outcome.local-exploit-version",
          "Enter optional observed version",
          version,
          "2.4.49",
          modality,
        );
        await replaceInput(
          "guided-intake.outcome.local-exploit-platform",
          "Enter optional observed platform",
          platform,
          "linux",
          modality,
        );
        if (modality === "pointer") {
          await maximumMatches.click();
          await maximumMatches.fill("7");
        } else {
          await maximumMatches.focus();
          await maximumMatches.press("ControlOrMeta+A");
          await maximumMatches.pressSequentially("7");
        }
        await expect(maximumMatches).toHaveValue("7");

        const technologyResolve = await clickContinue(
          page,
          "Guided proposal boundaries",
        );
        expect(technologyResolve.request().postDataJSON()).toMatchObject({
          journey: "guided",
          executionPreference: "single_step_agent",
          guidedLocalExploitIntelligence: {
            query: {
              kind: "technology",
              product: "Apache HTTP Server",
              version: "2.4.49",
              platform: "linux",
              maximumResults: 7,
            },
          },
        });
        const technologyRequest =
          technologyResolve.request().postDataJSON() as Record<string, unknown>;
        expect(technologyRequest).not.toHaveProperty("guidedReconnaissance");
        expect(technologyRequest).not.toHaveProperty(
          "guidedWindowsIdentity",
        );

        await clickContinue(page, "Review the resolved mission");
        const review = group(page, "Review the resolved mission");
        await expect(review).toContainText(
          "Look up a product and version locally",
        );
        await expect(review).toContainText(
          "Apache HTTP Server · 2.4.49 · linux",
        );
        await expect(review).toContainText("kali:searchsploit-local");
        await expect(review).toContainText(
          "contacts neither the approved target nor a public provider",
        );
        await expect(review).toContainText(
          "parsed matches remain unverified observations",
        );
      }
      await audit.assertClean(testInfo);
    } finally {
      if (!page.isClosed()) {
        await browserAudit.closePageBeforeDependencyShutdown(page);
      }
      await backend.stop();
    }
  });
});

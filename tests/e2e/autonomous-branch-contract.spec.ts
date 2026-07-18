import { readFileSync } from "node:fs";
import { MissionIntakeService } from "../../server/intake";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { expect, test, type Locator, type Page } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import { createAutonomousBranchFixture, type AutonomousBranchFixture } from "./support/autonomousBranchFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_ID = "e2e.autonomous-branch.contract-registry";
const ACTION_POLICY_VALUES = ["pre_authorized", "guided_only", "prohibited", "inherited_default"] as const;
const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);
const expectedRegistry = new MissionIntakeService().snapshot("autonomous", "custom");
let fixture: AutonomousBranchFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createAutonomousBranchFixture(canonicalFixtureNamespace(testInfo, "autonomous-branch-contract"));
});

function route(): string {
  return `/missions/${encodeURIComponent(fixture.missionId)}/runs/${encodeURIComponent(fixture.runId)}?tab=settings`;
}

async function openDetails(page: Page, prefix: string): Promise<Locator> {
  const summary = page.locator("summary").filter({ hasText: prefix }).first();
  await expect(summary).toBeVisible();
  await summary.click();
  const details = summary.locator("xpath=..");
  await expect(details).toHaveAttribute("open", "");
  return details;
}

async function toggleEveryCheckbox(details: Locator): Promise<void> {
  const controls = details.getByRole("checkbox");
  expect(await controls.count()).toBeGreaterThan(0);
  for (const checkbox of await controls.all()) {
    const initial = await checkbox.isChecked();
    await checkbox.click();
    await expect(checkbox).toBeChecked({ checked: !initial });
    await checkbox.press("Space");
    await expect(checkbox).toBeChecked({ checked: initial });
  }
}

test(`${TEST_ID} exposes and exercises every structured successor-contract option`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  await page.goto(route());
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Autonomous branch contract");
  await expect(page.getByRole("heading", { name: "Create a separate Autonomous execution attempt", exact: true })).toBeVisible();

  await page.getByRole("radio", { name: /Versioned contract amendment/u }).check();
  await expect(page.getByRole("heading", { name: "Amend explicit authority", exact: true })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: /runtime registry/iu }).last()).toBeVisible();
  await expect(page.getByLabel("Allowed action classes · one per line", { exact: false })).toHaveCount(0);
  await expect(page.getByLabel("Evidence requirements · one per line", { exact: false })).toHaveCount(0);
  await expect(page.getByLabel("Safe-stop conditions · one per line", { exact: false })).toHaveCount(0);
  await expect(page.getByLabel("Final deliverables · one per line", { exact: false })).toHaveCount(0);

  const destructivePolicy = page.getByLabel("Destructive-action policy", { exact: false });
  expect(await destructivePolicy.locator("option").allTextContents()).toEqual([
    "Prohibited",
    "Validate the path without executing",
    "Named disposable lab targets only",
  ]);
  await destructivePolicy.selectOption("validate_without_executing");
  await expect(destructivePolicy).toHaveValue("validate_without_executing");
  await destructivePolicy.selectOption("bounded_lab_only");
  const boundedTargets = page.getByRole("group", { name: "Named bounded destructive targets", exact: true });
  await expect(boundedTargets).toBeVisible();
  const boundedTarget = boundedTargets.getByRole("checkbox");
  await boundedTarget.check();
  await expect(boundedTarget).toBeChecked();
  await boundedTarget.press("Space");
  await expect(boundedTarget).not.toBeChecked();
  await destructivePolicy.selectOption("prohibited");

  const actionMatrix = await openDetails(page, "Action-class policy matrix");
  expect(await actionMatrix.locator("article.os-policy-row > div > strong").allTextContents()).toEqual(
    Object.values(expectedRegistry.actionClasses.classes).map(({ label }) => label),
  );
  const actionPolicies = actionMatrix.getByRole("combobox", { name: / branch policy$/u });
  await expect(actionPolicies).toHaveCount(Object.keys(expectedRegistry.actionClasses.classes).length);
  for (const policy of await actionPolicies.all()) {
    expect(await policy.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value))).toEqual(ACTION_POLICY_VALUES);
    const initial = await policy.inputValue();
    for (const state of ACTION_POLICY_VALUES) {
      await policy.selectOption(state);
      await expect(policy).toHaveValue(state);
    }
    await policy.selectOption(initial);
  }

  const deliverables = await openDetails(page, "Final deliverables");
  expect(await deliverables.locator("label.os-check-field strong").allTextContents()).toEqual(
    Object.values(expectedRegistry.deliverables.deliverables).map(({ label }) => label),
  );
  await toggleEveryCheckbox(deliverables);

  const evidence = await openDetails(page, "Evidence requirements");
  expect(await evidence.locator("label.os-check-field strong").allTextContents()).toEqual(
    Object.values(expectedRegistry.evidenceTypes.types).map(({ label }) => label),
  );
  await toggleEveryCheckbox(evidence);

  const safeStops = await openDetails(page, "Safe-stop behavior");
  expect(await safeStops.locator("label.os-check-field strong").allTextContents()).toEqual(
    expectedRegistry.safeStops.optional.map(({ label }) => label),
  );
  await toggleEveryCheckbox(safeStops);
  await expect(safeStops.locator(".os-mandatory-stop")).toHaveCount(expectedRegistry.safeStops.mandatory.length);
  await expect(safeStops.locator(".os-mandatory-stop input")).toHaveCount(0);
  await expect(safeStops).toContainText("Mandatory platform stops are always enforced and cannot be removed.");

  const requiredManifestEntries = [
    "autonomous-branch.contract.destructive-policy",
    "autonomous-branch.contract.bounded-targets",
    "autonomous-branch.contract.registry-disclosures",
    "autonomous-branch.contract.action-classes",
    "autonomous-branch.contract.deliverables",
    "autonomous-branch.contract.evidence",
    "autonomous-branch.contract.safe-stops",
  ];
  for (const id of requiredManifestEntries) {
    expect(manifest.entries.some((entry) => entry.id === id), `Missing interaction manifest entry ${id}`).toBe(true);
  }
  await audit.waitForPageApiSettlement(page);
  await audit.assertClean(testInfo);
});

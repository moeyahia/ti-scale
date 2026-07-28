import {
  ACTION_CLASS_DEFINITIONS,
} from "../../server/domain/action-class-registry";
import { ACTION_CLASS_IDS } from "../../server/domain/catalog-ids";
import {
  DELIVERABLE_DEFINITIONS,
} from "../../server/domain/deliverable-registry";
import {
  EVIDENCE_TYPE_DEFINITIONS,
} from "../../server/domain/evidence-type-registry";
import {
  OPTIONAL_MISSION_SAFE_STOPS,
} from "../../server/domain/safe-stop-registry";
import type { ActionPolicyState } from "../../server/domain/action-class-registry";
import type { ResolvedMissionIntake } from "../../server/intake/types";
import {
  expect,
  test,
  type Locator,
  type Page,
} from "./support/playwright";
import {
  activateAutonomousIntake,
  advanceAutonomousIntake,
  autonomousIntakeGroup,
  autonomousIntakeManifestOptions,
  autonomousTitaniumOptions,
  chooseAutonomousTitaniumOption,
  createIntakeRequestLedger,
  installIntakeApiProxy,
  type IntakeActivationModality,
  type IntakeReceiptContext,
} from "./support/autonomousIntake";
import {
  startReadyAutonomousIntakeBackend,
} from "./support/readyAutonomousIntakeBackendController";

const TEST_ID = "e2e.autonomous-intake.contract-normalization";
const TARGET = "127.0.0.1";
const POLICY_OPTIONS: Readonly<Record<string, ActionPolicyState>> = {
  "Pre-authorized": "pre_authorized",
  "Guided only / not autonomous": "guided_only",
  Prohibited: "prohibited",
  "Inherited default": "inherited_default",
};
const CUSTOM_DELIVERABLE_IDS = DELIVERABLE_DEFINITIONS.slice(0, 3).map(({ id }) => id);
const CUSTOM_EVIDENCE_IDS = EVIDENCE_TYPE_DEFINITIONS.slice(0, 4).map(({ id }) => id);
const CUSTOM_SAFE_STOP_IDS = OPTIONAL_MISSION_SAFE_STOPS.slice(0, 2).map(({ id }) => id);
const EXPECTED_RESOLVED_POLICY = {
  passive_intelligence_osint: { state: "prohibited", source: "platform_default" },
  dns_domain_certificate_discovery: { state: "prohibited", source: "platform_default" },
  active_host_discovery: { state: "pre_authorized", source: "operator_override" },
  port_service_enumeration: { state: "pre_authorized", source: "preset" },
  os_technology_fingerprinting: { state: "pre_authorized", source: "preset" },
  web_crawling_page_capture: { state: "pre_authorized", source: "preset" },
  web_content_endpoint_discovery_fuzzing: { state: "pre_authorized", source: "preset" },
  vulnerability_configuration_assessment: { state: "guided_only", source: "platform_default" },
  cve_intelligence_applicability_validation: { state: "pre_authorized", source: "preset" },
  credential_password_hash_assessment: { state: "prohibited", source: "platform_default" },
  authentication_testing: { state: "prohibited", source: "platform_default" },
  exploit_validation: { state: "guided_only", source: "platform_default" },
  command_session_execution: { state: "guided_only", source: "platform_default" },
  target_file_write: { state: "prohibited", source: "platform_default" },
  privilege_escalation: { state: "guided_only", source: "platform_default" },
  lateral_movement_pivoting: { state: "prohibited", source: "platform_default" },
  active_directory_identity_operations: { state: "prohibited", source: "platform_default" },
  cloud_container_kubernetes_assessment: { state: "prohibited", source: "platform_default" },
  reverse_engineering_binary_analysis: { state: "prohibited", source: "platform_default" },
  fuzzing_crash_discovery: { state: "prohibited", source: "platform_default" },
  data_access_impact_validation: { state: "guided_only", source: "platform_default" },
  persistence: { state: "prohibited", source: "platform_default" },
  cleanup_restoration: { state: "guided_only", source: "platform_default" },
  denial_of_service_disruption: { state: "prohibited", source: "platform_default" },
  destructive_modification: { state: "prohibited", source: "operator_override" },
  local_report_artifact_generation: { state: "prohibited", source: "platform_default" },
} as const;

function activateElement(
  locator: Locator,
  modality: IntakeActivationModality,
): Promise<void> {
  if (modality === "pointer") return locator.click();
  return locator.focus().then(() => locator.press("Enter"));
}

async function openDisclosureWithoutReceipt(details: Locator): Promise<void> {
  if ((await details.getAttribute("open")) === null) {
    await details.locator(":scope > summary").click();
  }
  await expect(details).toHaveAttribute("open", "");
}

async function exerciseDisclosure(
  details: Locator,
  entryId: string,
  modality: IntakeActivationModality,
  context: IntakeReceiptContext,
): Promise<void> {
  const summary = details.locator(":scope > summary");
  if ((await details.getAttribute("open")) !== null) {
    await activateElement(summary, modality);
    await expect(details).not.toHaveAttribute("open", "");
  }
  await activateAutonomousIntake(context, entryId, "Open", modality, async () => {
    await activateElement(summary, modality);
    await expect(details).toHaveAttribute("open", "");
  });
  await activateAutonomousIntake(context, entryId, "Close", modality, async () => {
    await activateElement(summary, modality);
    await expect(details).not.toHaveAttribute("open", "");
  });
}

async function exerciseSelectOptions(
  control: Locator,
  entryId: string,
  modality: IntakeActivationModality,
  context: IntakeReceiptContext,
): Promise<void> {
  const options = await autonomousTitaniumOptions(control);
  expect(options.map(({ label }) => label)).toEqual(
    autonomousIntakeManifestOptions(entryId),
  );
  for (let index = 0; index < options.length; index += 1) {
    const option = options[index]!;
    const alternate = options[(index + 1) % options.length]!;
    await chooseAutonomousTitaniumOption(control, alternate.value, modality);
    await activateAutonomousIntake(
      context,
      entryId,
      option.label,
      modality,
      async () => {
        await chooseAutonomousTitaniumOption(control, option.value, modality);
      },
    );
  }
}

async function setCheckboxWithModality(
  checkbox: Locator,
  checked: boolean,
  modality: IntakeActivationModality,
): Promise<void> {
  if (await checkbox.isChecked() === checked) return;
  if (modality === "pointer") {
    await checkbox.click();
  } else {
    await checkbox.focus();
    await checkbox.press("Space");
  }
  await expect(checkbox).toBeChecked({ checked });
}

async function exerciseChecklist(
  details: Locator,
  entryId: string,
  labels: readonly string[],
  modality: IntakeActivationModality,
  context: IntakeReceiptContext,
): Promise<void> {
  await openDisclosureWithoutReceipt(details);
  const rows = details.locator("label.os-check-field");
  await expect(rows).toHaveCount(labels.length);
  for (const label of labels) {
    const row = rows.filter({ hasText: label });
    await expect(row).toHaveCount(1);
    const checkbox = row.getByRole("checkbox");
    const initial = await checkbox.isChecked();
    await activateAutonomousIntake(
      context,
      entryId,
      label,
      modality,
      async () => {
        await setCheckboxWithModality(checkbox, !initial, modality);
      },
    );
  }
}

async function setExactChecklist(
  details: Locator,
  definitions: readonly { readonly id: string; readonly label: string }[],
  selectedIds: readonly string[],
): Promise<void> {
  await openDisclosureWithoutReceipt(details);
  for (const definition of definitions) {
    const row = details.locator("label.os-check-field").filter({
      hasText: definition.label,
    });
    await expect(row).toHaveCount(1);
    await row.getByRole("checkbox").setChecked(false);
  }
  for (const selectedId of selectedIds) {
    const definition = definitions.find(({ id }) => id === selectedId);
    if (!definition) throw new Error(`Checklist selection ${selectedId} is not registered`);
    const row = details.locator("label.os-check-field").filter({
      hasText: definition.label,
    });
    await row.getByRole("checkbox").setChecked(true);
  }
}

async function prepareContract(page: Page): Promise<string> {
  await page.goto("/missions/new/autonomous");
  const environment = page.getByRole("combobox", {
    name: /Environment classification/u,
  });
  await chooseAutonomousTitaniumOption(
    environment,
    "local_disposable_lab",
    "keyboard",
  );
  await page
    .getByLabel("Authorized targets or environment references", { exact: false })
    .fill(TARGET);
  await page
    .getByRole("checkbox", {
      name: /I confirm these targets and the selected action policy are authorized/u,
    })
    .check();
  const scopeResolution = await advanceAutonomousIntake(
    page,
    "Outcome and collaboration",
  );
  const resolvedScope = await scopeResolution.resolved.json() as ResolvedMissionIntake;
  expect(resolvedScope.normalizedTargets).toHaveLength(1);
  expect(resolvedScope.normalizedTargets[0]).toEqual({
    id: expect.stringMatching(/^target_[a-f0-9]+$/u),
    type: "host",
    value: TARGET,
  });
  const boundedTargetId = resolvedScope.normalizedTargets[0]!.id;
  await advanceAutonomousIntake(page, "Autonomous operating contract");
  return boundedTargetId;
}

async function customizeThenRestoreDefaults(
  page: Page,
  context: IntakeReceiptContext,
  modality: IntakeActivationModality,
  budget: Locator,
  destructive: Locator,
  actionMatrix: Locator,
  evidence: Locator,
): Promise<void> {
  const defaults = page.getByRole("button", {
    name: "Use recommended defaults",
    exact: true,
  });
  const firstPolicy = actionMatrix.getByRole("combobox", {
    name: `${ACTION_CLASS_DEFINITIONS[0]!.label} policy`,
    exact: true,
  });
  await chooseAutonomousTitaniumOption(firstPolicy, "guided_only", modality);
  await expect(defaults).toBeEnabled();
  await activateAutonomousIntake(
    context,
    "autonomous-intake.contract.recommended-defaults",
    "Restore action-class policy from the selected template and runtime registry",
    modality,
    async () => {
      await activateElement(defaults, modality);
      await expect(page.getByLabel("Current mission contract summary"))
        .toContainText("Action policyRecommended defaults");
    },
  );

  await chooseAutonomousTitaniumOption(budget, "deep", modality);
  await chooseAutonomousTitaniumOption(
    destructive,
    "validate_without_executing",
    modality,
  );
  await openDisclosureWithoutReceipt(evidence);
  const firstEvidence = evidence.getByRole("checkbox").first();
  await firstEvidence.setChecked(!(await firstEvidence.isChecked()));
  await expect(defaults).toBeEnabled();
  await activateAutonomousIntake(
    context,
    "autonomous-intake.contract.recommended-defaults",
    "Restore deliverable, evidence, safe-stop, destructive-policy, and budget defaults",
    modality,
    async () => {
      await activateElement(defaults, modality);
      await expect(defaults).toBeDisabled();
      expect(
        (await autonomousTitaniumOptions(budget)).find(({ selected }) => selected)
          ?.value,
      ).toBe("standard");
      expect(
        (await autonomousTitaniumOptions(destructive)).find(
          ({ selected }) => selected,
        )?.value,
      ).toBe("prohibited");
    },
  );
}

async function runContractTraversal(
  page: Page,
  context: IntakeReceiptContext,
  modality: IntakeActivationModality,
): Promise<void> {
  const budget = page.getByRole("combobox", { name: /Budget preset/u });
  const destructive = page.getByRole("combobox", {
    name: /Destructive-action policy/u,
  });
  await exerciseSelectOptions(
    budget,
    "autonomous-intake.contract.budget",
    modality,
    context,
  );
  await exerciseSelectOptions(
    destructive,
    "autonomous-intake.contract.destructive-policy",
    modality,
    context,
  );

  await chooseAutonomousTitaniumOption(
    destructive,
    "bounded_lab_only",
    modality,
  );
  const boundedTarget = autonomousIntakeGroup(
    page,
    "Named disposable lab targets",
  ).getByRole("checkbox", { name: new RegExp(TARGET.replaceAll(".", "\\."), "u") });
  await expect(boundedTarget).toBeVisible();
  await boundedTarget.uncheck();
  await activateAutonomousIntake(
    context,
    "autonomous-intake.contract.bounded-lab-target",
    "Exact normalized disposable lab target",
    modality,
    async () => {
      await setCheckboxWithModality(boundedTarget, true, modality);
    },
  );

  const actionMatrix = page.locator("details.os-advanced-section").filter({
    has: page.locator("summary").filter({ hasText: "Action-class policy matrix" }),
  });
  await exerciseDisclosure(
    actionMatrix,
    "autonomous-intake.contract.action-classes",
    modality,
    context,
  );
  await openDisclosureWithoutReceipt(actionMatrix);
  const policyRows = actionMatrix.locator("article.os-policy-row");
  await expect(policyRows).toHaveCount(ACTION_CLASS_IDS.length);
  for (const definition of ACTION_CLASS_DEFINITIONS) {
    const row = policyRows.filter({ hasText: definition.label });
    await expect(row).toHaveCount(1);
    const control = row.getByRole("combobox", {
      name: `${definition.label} policy`,
      exact: true,
    });
    const entryId = `autonomous-intake.contract.action-policy-state.${definition.id}`;
    expect(autonomousIntakeManifestOptions(entryId)).toEqual(
      Object.keys(POLICY_OPTIONS),
    );
    for (const [label, value] of Object.entries(POLICY_OPTIONS)) {
      const alternate = value === "pre_authorized" ? "prohibited" : "pre_authorized";
      await chooseAutonomousTitaniumOption(control, alternate, modality);
      await activateAutonomousIntake(
        context,
        entryId,
        label,
        modality,
        async () => {
          await chooseAutonomousTitaniumOption(control, value, modality);
        },
      );
    }
  }

  const deliverables = page.locator("details.os-advanced-section").filter({
    has: page.locator("summary").filter({ hasText: "Final deliverables" }),
  });
  const evidence = page.locator("details.os-advanced-section").filter({
    has: page.locator("summary").filter({ hasText: "Evidence requirements" }),
  });
  const safeStops = page.locator("details.os-advanced-section").filter({
    has: page.locator("summary").filter({ hasText: "Safe-stop behavior" }),
  });
  for (const [details, entryId] of [
    [deliverables, "autonomous-intake.contract.deliverables"],
    [evidence, "autonomous-intake.contract.evidence"],
    [safeStops, "autonomous-intake.contract.safe-stops"],
  ] as const) {
    await exerciseDisclosure(details, entryId, modality, context);
  }
  await exerciseChecklist(
    deliverables,
    "autonomous-intake.contract.deliverable-controls",
    DELIVERABLE_DEFINITIONS.map(({ label }) => label),
    modality,
    context,
  );
  await exerciseChecklist(
    evidence,
    "autonomous-intake.contract.evidence-controls",
    EVIDENCE_TYPE_DEFINITIONS.map(({ label }) => label),
    modality,
    context,
  );
  await exerciseChecklist(
    safeStops,
    "autonomous-intake.contract.safe-stop-controls",
    OPTIONAL_MISSION_SAFE_STOPS.map(({ label }) => label),
    modality,
    context,
  );

  await customizeThenRestoreDefaults(
    page,
    context,
    modality,
    budget,
    destructive,
    actionMatrix,
    evidence,
  );

  await chooseAutonomousTitaniumOption(budget, "deep", modality);
  await chooseAutonomousTitaniumOption(
    destructive,
    "bounded_lab_only",
    modality,
  );
  await boundedTarget.check();
  for (const definition of ACTION_CLASS_DEFINITIONS) {
    const row = policyRows.filter({ hasText: definition.label });
    const value: ActionPolicyState = definition.id === "active_host_discovery"
      ? "pre_authorized"
      : definition.id === "destructive_modification"
        ? "prohibited"
        : "inherited_default";
    const control = row.getByRole("combobox", {
      name: `${definition.label} policy`,
      exact: true,
    });
    const selectedValue = (await autonomousTitaniumOptions(control))
      .find(({ selected }) => selected)?.value;
    if (selectedValue === value) {
      await chooseAutonomousTitaniumOption(
        control,
        value === "pre_authorized" ? "prohibited" : "pre_authorized",
        modality,
      );
    }
    await chooseAutonomousTitaniumOption(control, value, modality);
  }
  await setExactChecklist(
    deliverables,
    DELIVERABLE_DEFINITIONS,
    CUSTOM_DELIVERABLE_IDS,
  );
  await setExactChecklist(
    evidence,
    EVIDENCE_TYPE_DEFINITIONS,
    CUSTOM_EVIDENCE_IDS,
  );
  await setExactChecklist(
    safeStops,
    OPTIONAL_MISSION_SAFE_STOPS,
    CUSTOM_SAFE_STOP_IDS,
  );
}

test.describe(`${TEST_ID} registry normalization`, () => {
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
  });
  test.setTimeout(420_000);

  for (const modality of ["pointer", "keyboard"] as const) {
    test(`${TEST_ID}.${modality}`, async ({
      page,
      browserAudit,
      interactionActivation,
    }, testInfo) => {
      const backend = await startReadyAutonomousIntakeBackend(testInfo.testId);
      const proxy = await installIntakeApiProxy(page, backend.baseUrl);
      const ledger = createIntakeRequestLedger(page);
      const context: IntakeReceiptContext = {
        recorder: interactionActivation,
        testId: TEST_ID,
      };
      try {
        const boundedTargetId = await prepareContract(page);
        const resolveCountAtContract = ledger.count(
          "POST",
          "/api/v2/registries/intake/resolve",
        );
        await runContractTraversal(page, context, modality);
        expect(
          ledger.count("POST", "/api/v2/registries/intake/resolve"),
          "Contract draft controls must not mutate the server before Continue",
        ).toBe(resolveCountAtContract);

        const result = await advanceAutonomousIntake(
          page,
          "Specialist team and execution readiness",
          { expectPreflight: true },
        );
        const body = result.resolved.request().postDataJSON() as Record<string, unknown>;
        const expectedPolicyOverrides = Object.fromEntries(
          ACTION_CLASS_IDS.map((id) => [
            id,
            id === "active_host_discovery"
              ? "pre_authorized"
              : id === "destructive_modification"
                ? "prohibited"
                : "inherited_default",
          ]),
        );
        expect(body).toEqual({
          journey: "autonomous",
          authorizationAcknowledged: true,
          targets: [{ value: TARGET }],
          templateId: "safe_recon",
          environmentClassification: "local_disposable_lab",
          budgetPresetId: "deep",
          destructivePolicy: "bounded_lab_only",
          actionPolicyOverrides: expectedPolicyOverrides,
          deliverableIds: CUSTOM_DELIVERABLE_IDS,
          evidenceTypeIds: CUSTOM_EVIDENCE_IDS,
          optionalSafeStopIds: CUSTOM_SAFE_STOP_IDS,
          boundedDestructiveTargetIds: [boundedTargetId],
        });

        const resolved = await result.resolved.json() as ResolvedMissionIntake;
        expect(resolved.request.journey).toBe("autonomous");
        if (resolved.request.journey !== "autonomous") {
          throw new Error("Expected a resolved Autonomous contract");
        }
        expect(resolved.request.contract.destructivePolicy).toBe(
          "bounded_lab_only",
        );
        expect(resolved.request.contract.boundedDestructiveTargets).toEqual([
          TARGET,
        ]);
        expect(resolved.deliverableIds).toEqual(CUSTOM_DELIVERABLE_IDS);
        expect(resolved.evidenceTypeIds).toEqual(CUSTOM_EVIDENCE_IDS);
        expect(resolved.optionalSafeStopIds).toEqual(CUSTOM_SAFE_STOP_IDS);
        expect(resolved.budget.id).toBe("deep");
        expect(resolved.request.contract.deliverables).toEqual(
          CUSTOM_DELIVERABLE_IDS,
        );
        expect(resolved.request.contract.evidenceRequirements).toEqual(
          CUSTOM_EVIDENCE_IDS,
        );
        expect(resolved.request.contract.safeStopConditions).toEqual(
          CUSTOM_SAFE_STOP_IDS,
        );
        expect(Object.keys(resolved.policyMatrix.classes)).toEqual(
          ACTION_CLASS_IDS,
        );
        expect(Object.fromEntries(ACTION_CLASS_IDS.map((id) => [
          id,
          {
            state: resolved.policyMatrix.classes[id].policyState,
            source: resolved.policyMatrix.classes[id].policySource,
          },
        ]))).toEqual(EXPECTED_RESOLVED_POLICY);
        await expect(
          autonomousIntakeGroup(
            page,
            "Specialist team and execution readiness",
          ),
        ).toBeVisible();
      } finally {
        ledger.dispose();
        if (!page.isClosed()) {
          await browserAudit.closePageBeforeDependencyShutdown(page);
        }
        await proxy.dispose().catch(() => undefined);
        await backend.stop();
      }
    });
  }
});

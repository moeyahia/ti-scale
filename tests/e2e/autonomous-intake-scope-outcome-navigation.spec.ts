import {
  expect,
  test,
  type Locator,
  type Page,
  type Response,
} from "./support/playwright";
import { startReadyAutonomousIntakeBackend } from "./support/readyAutonomousIntakeBackendController";
import {
  AUTONOMOUS_INTAKE_ROUTE,
  activateAutonomousIntake,
  activateIntakeStepper,
  advanceAutonomousIntake,
  autonomousIntakeGroup,
  autonomousIntakeManifestOptions,
  autonomousTitaniumFormProxy,
  autonomousTitaniumOptions,
  autonomousTitaniumSelect,
  chooseAutonomousTitaniumOption,
  createIntakeRequestLedger,
  exerciseNativeDisclosure,
  fillAutonomousIntakeText,
  installIntakeApiProxy,
  returnAutonomousIntake,
  setAutonomousIntakeCheckbox,
  type IntakeActivationModality,
  type IntakeReceiptContext,
} from "./support/autonomousIntake";
import type { TitaniumOptionEntry } from "./support/titaniumSelect";

const TEST_ID = "e2e.autonomous-intake.scope-outcome-navigation";
const TARGET = "10.129.39.191";
const EXCLUDED_TARGET = "admin.restricted.example";
const ENGAGEMENT_ID = "eng_autonomous_scope_e2e";
const TITLE = "Current-IP service assessment";
const OBJECTIVE =
  "Map the authorized target, verify exposed services, and retain attributable evidence.";
const ADDITIONAL_SUCCESS =
  "Document a safe alternative when an execution prerequisite is unavailable.";

interface ExpectedScopeRequest {
  readonly journey: "autonomous";
  readonly authorizationAcknowledged: true;
  readonly targets: readonly [
    { readonly value: string },
    { readonly value: string; readonly excluded: true },
  ];
  readonly templateId: "safe_recon";
  readonly engagementId: string;
  readonly environmentClassification: "htb";
  readonly destructivePolicy: "prohibited";
  readonly boundedDestructiveTargetIds: readonly [];
  readonly actionPolicyOverrides: Readonly<Record<string, never>>;
}

const EXPECTED_SCOPE_REQUEST = {
  journey: "autonomous",
  authorizationAcknowledged: true,
  targets: [
    { value: TARGET },
    { value: EXCLUDED_TARGET, excluded: true },
  ] as const,
  templateId: "safe_recon",
  engagementId: ENGAGEMENT_ID,
  environmentClassification: "htb",
  destructivePolicy: "prohibited",
  boundedDestructiveTargetIds: [] as const,
  actionPolicyOverrides: {},
} satisfies ExpectedScopeRequest;

async function activateLink(
  page: Page,
  context: IntakeReceiptContext,
  manifestEntryId: string,
  option: string,
  name: string,
  modality: IntakeActivationModality,
): Promise<void> {
  const link = page.getByRole("link", { name, exact: true });
  await activateAutonomousIntake(
    context,
    manifestEntryId,
    option,
    modality,
    async () => {
      if (modality === "pointer") await link.click();
      else {
        await link.focus();
        await link.press("Enter");
      }
      await expect.poll(() => new URL(page.url()).pathname).toBe("/missions/new");
      await expect(
        page.getByRole("link", { name: "Go Autonomous", exact: true }),
      ).toBeVisible();
    },
  );
  await page.getByRole("link", { name: "Go Autonomous", exact: true }).click();
  await expect.poll(() => new URL(page.url()).pathname).toBe(
    AUTONOMOUS_INTAKE_ROUTE,
  );
  await expect(
    autonomousIntakeGroup(page, "Authorization and exact scope"),
  ).toBeVisible();
}

async function exerciseJourneyLinks(
  page: Page,
  context: IntakeReceiptContext,
): Promise<void> {
  for (const modality of ["pointer", "keyboard"] as const) {
    await activateLink(
      page,
      context,
      "autonomous-intake.navigation.change-journey",
      "Return to two-journey selection",
      "Change journey",
      modality,
    );
  }
  for (const modality of ["pointer", "keyboard"] as const) {
    await activateLink(
      page,
      context,
      "autonomous-intake.navigation.back-link",
      "Return to journey selection",
      "Back",
      modality,
    );
  }
}

async function exerciseTitaniumOptions(
  control: Locator,
  context: IntakeReceiptContext,
  manifestEntryId: string,
): Promise<readonly TitaniumOptionEntry[]> {
  const options = await autonomousTitaniumOptions(control);
  expect(options.map(({ label }) => label)).toEqual(
    autonomousIntakeManifestOptions(manifestEntryId),
  );
  for (const modality of ["pointer", "keyboard"] as const) {
    for (const option of options) {
      await activateAutonomousIntake(
        context,
        manifestEntryId,
        option.label,
        modality,
        async () => {
          await chooseAutonomousTitaniumOption(
            control,
            option.value,
            modality,
          );
          await expect(autonomousTitaniumFormProxy(control)).toHaveValue(
            option.value,
          );
        },
      );
    }
  }
  return options;
}

async function expectScopeRequest(response: Response): Promise<void> {
  expect(response.request().postDataJSON()).toEqual(EXPECTED_SCOPE_REQUEST);
}

async function expectOutcomeRequest(response: Response): Promise<void> {
  expect(response.request().postDataJSON()).toEqual({
    ...EXPECTED_SCOPE_REQUEST,
    title: TITLE,
    objective: OBJECTIVE,
    successCriteria: [
      ...autonomousIntakeManifestOptions(
        "autonomous-intake.outcome.success-criteria",
      ),
      ADDITIONAL_SUCCESS,
    ],
  });
}

async function expectResolvedOutcomeFields(response: Response): Promise<void> {
  expect(response.request().postDataJSON()).toMatchObject({
    ...EXPECTED_SCOPE_REQUEST,
    title: TITLE,
    objective: OBJECTIVE,
    successCriteria: [
      ...autonomousIntakeManifestOptions(
        "autonomous-intake.outcome.success-criteria",
      ),
      ADDITIONAL_SUCCESS,
    ],
  });
}

async function exerciseTransition(
  page: Page,
  context: IntakeReceiptContext,
  input: {
    readonly nextGroup: string;
    readonly previousGroup: string;
    readonly continueOption: string;
    readonly backOption: string;
    readonly expectPreflight?: boolean;
    readonly expectRequest?: (response: Response) => Promise<void>;
  },
): Promise<void> {
  for (const modality of ["pointer", "keyboard"] as const) {
    const advanced = await advanceAutonomousIntake(page, input.nextGroup, {
      context,
      manifestOption: input.continueOption,
      modality,
      expectPreflight: input.expectPreflight,
    });
    if (input.expectRequest) await input.expectRequest(advanced.resolved);
    await returnAutonomousIntake(
      page,
      input.previousGroup,
      context,
      input.backOption,
      modality,
    );
  }
  const advanced = await advanceAutonomousIntake(page, input.nextGroup, {
    expectPreflight: input.expectPreflight,
  });
  if (input.expectRequest) await input.expectRequest(advanced.resolved);
}

async function exerciseHelp(
  details: Locator,
  context: IntakeReceiptContext,
  manifestEntryId: string,
  expectedText: RegExp,
): Promise<void> {
  await exerciseNativeDisclosure(details, context, manifestEntryId);
  await details.locator(":scope > summary").click();
  await expect(details).toHaveAttribute("open", "");
  await expect(details).toContainText(expectedText);
  await details.locator(":scope > summary").click();
}

test(TEST_ID, async (
  { page, browserAudit, interactionActivation },
  testInfo,
) => {
  test.setTimeout(360_000);
  await page.emulateMedia({ reducedMotion: "reduce" });
  const backend = await startReadyAutonomousIntakeBackend(testInfo.testId);
  const proxy = await installIntakeApiProxy(page, backend.baseUrl);
  const ledger = createIntakeRequestLedger(page);
  const context: IntakeReceiptContext = {
    recorder: interactionActivation,
    testId: TEST_ID,
  };

  try {
    await page.goto(AUTONOMOUS_INTAKE_ROUTE);
    const scope = autonomousIntakeGroup(
      page,
      "Authorization and exact scope",
    );
    await expect(scope).toBeVisible();
    await exerciseJourneyLinks(page, context);
    await activateIntakeStepper(page, 1, "Scope", context);

    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await expect(
      page.getByRole("alert").filter({ hasText: "Resolve before continuing" }),
    ).toContainText(
      "Add at least one authorized target or environment reference.",
    );
    expect(ledger.count("POST", "/api/v2/registries/intake/resolve")).toBe(0);
    expect(ledger.count("POST", "/api/v2/missions")).toBe(0);

    const template = autonomousTitaniumSelect(page, /Mission template/u);
    const templateOptions = await exerciseTitaniumOptions(
      template,
      context,
      "autonomous-intake.scope.template",
    );
    await chooseAutonomousTitaniumOption(template, "safe_recon", "pointer");

    const environment = autonomousTitaniumSelect(
      page,
      /Environment classification/u,
    );
    await exerciseTitaniumOptions(
      environment,
      context,
      "autonomous-intake.scope.environment-classification",
    );
    await chooseAutonomousTitaniumOption(environment, "htb", "pointer");

    const targetHelp = scope.locator("details.os-field-help").first();
    await exerciseHelp(
      targetHelp,
      context,
      "autonomous-intake.scope.target-field-help",
      /exact host, network, URL, domain, account, scope file, engagement, or lab boundary/u,
    );

    const boundary = scope
      .locator("details.os-advanced-section")
      .filter({ hasText: "Excluded targets and engagement boundary" });
    await exerciseNativeDisclosure(
      boundary,
      context,
      "autonomous-intake.scope.boundary-disclosure",
    );
    await boundary.locator(":scope > summary").click();
    await expect(boundary).toHaveAttribute("open", "");

    const engagementHelp = boundary.locator("details.os-field-help");
    await exerciseHelp(
      engagementHelp,
      context,
      "autonomous-intake.scope.engagement-field-help",
      /Scopes retained knowledge and links the mission/u,
    );

    await fillAutonomousIntakeText(
      page.getByLabel("Authorized targets or environment references", {
        exact: false,
      }),
      TARGET,
      context,
      "autonomous-intake.scope.targets",
    );
    await fillAutonomousIntakeText(
      boundary.getByLabel("Explicitly excluded targets", { exact: false }),
      EXCLUDED_TARGET,
      context,
      "autonomous-intake.scope.excluded-targets",
    );
    await fillAutonomousIntakeText(
      boundary.getByLabel("Existing engagement ID", { exact: false }),
      ENGAGEMENT_ID,
      context,
      "autonomous-intake.scope.engagement",
    );

    const authorization = page.getByRole("checkbox", {
      name: /I confirm these targets and the selected action policy are authorized/u,
    });
    await setAutonomousIntakeCheckbox(
      authorization,
      true,
      context,
      "autonomous-intake.scope.authorization",
      "Confirmed",
      "pointer",
    );
    await setAutonomousIntakeCheckbox(
      authorization,
      false,
      context,
      "autonomous-intake.scope.authorization",
      "Not confirmed",
      "pointer",
    );
    await setAutonomousIntakeCheckbox(
      authorization,
      true,
      context,
      "autonomous-intake.scope.authorization",
      "Confirmed",
      "keyboard",
    );
    await setAutonomousIntakeCheckbox(
      authorization,
      false,
      context,
      "autonomous-intake.scope.authorization",
      "Not confirmed",
      "keyboard",
    );
    await authorization.check();
    await expect(authorization).toBeChecked();

    await exerciseTransition(page, context, {
      previousGroup: "Authorization and exact scope",
      nextGroup: "Outcome and collaboration",
      continueOption: "Scope → Outcome",
      backOption: "Outcome → Scope",
      expectRequest: expectScopeRequest,
    });
    await activateIntakeStepper(page, 2, "Outcome", context);

    const outcome = autonomousIntakeGroup(page, "Outcome and collaboration");
    const outcomeHelp = outcome.locator("details.os-field-help");
    await expect(outcomeHelp).toHaveCount(2);
    await exerciseHelp(
      outcomeHelp.nth(0),
      context,
      "autonomous-intake.outcome.title-field-help",
      /human-readable name for dashboards, reports/u,
    );
    await exerciseHelp(
      outcomeHelp.nth(1),
      context,
      "autonomous-intake.outcome.objective-field-help",
      /outcome Ti-Scale is permitted to establish/u,
    );

    await fillAutonomousIntakeText(
      outcome.getByLabel("Mission title", { exact: false }),
      TITLE,
      context,
      "autonomous-intake.outcome.title",
    );
    await fillAutonomousIntakeText(
      outcome.getByLabel("Authorized objective", { exact: false }),
      OBJECTIVE,
      context,
      "autonomous-intake.outcome.objective",
    );

    const successLabels = autonomousIntakeManifestOptions(
      "autonomous-intake.outcome.success-criteria",
    );
    for (const label of successLabels) {
      const checkbox = outcome.getByRole("checkbox", {
        name: new RegExp(
          `^${label.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}`,
          "u",
        ),
      });
      const initial = await checkbox.isChecked();
      await activateAutonomousIntake(
        context,
        "autonomous-intake.outcome.success-criteria",
        label,
        "pointer",
        async () => {
          await checkbox.click();
          await expect(checkbox).toBeChecked({ checked: !initial });
        },
      );
      await activateAutonomousIntake(
        context,
        "autonomous-intake.outcome.success-criteria",
        label,
        "keyboard",
        async () => {
          await checkbox.focus();
          await checkbox.press("Space");
          await expect(checkbox).toBeChecked({ checked: initial });
        },
      );
    }
    await fillAutonomousIntakeText(
      outcome.getByLabel("Additional success criteria", { exact: false }),
      ADDITIONAL_SUCCESS,
      context,
      "autonomous-intake.outcome.additional-success",
    );

    await exerciseTransition(page, context, {
      previousGroup: "Outcome and collaboration",
      nextGroup: "Autonomous operating contract",
      continueOption: "Outcome → Contract",
      backOption: "Contract → Outcome",
      expectRequest: expectOutcomeRequest,
    });
    await activateIntakeStepper(page, 3, "Contract", context);

    await exerciseTransition(page, context, {
      previousGroup: "Autonomous operating contract",
      nextGroup: "Specialist team and execution readiness",
      continueOption: "Contract → Team",
      backOption: "Team → Contract",
      expectPreflight: true,
      expectRequest: expectResolvedOutcomeFields,
    });
    await activateIntakeStepper(page, 4, "Team", context);

    await exerciseTransition(page, context, {
      previousGroup: "Specialist team and execution readiness",
      nextGroup: "Second Brain context",
      continueOption: "Team → Context",
      backOption: "Context → Team",
      expectPreflight: true,
    });
    await activateIntakeStepper(page, 5, "Context", context);

    await exerciseTransition(page, context, {
      previousGroup: "Second Brain context",
      nextGroup: "Review the resolved mission",
      continueOption: "Context → Review",
      backOption: "Review → Context",
      expectPreflight: true,
    });
    await activateIntakeStepper(page, 6, "Review", context);

    const templateRequests = ledger.records
      .filter(
        ({ method, pathname }) =>
          method === "GET" && pathname === "/api/v2/registries/intake",
      )
      .map(({ search }) => new URLSearchParams(search).get("templateId"));
    for (const option of templateOptions) {
      expect(templateRequests).toContain(option.value);
    }
    expect(ledger.count("POST", "/api/v2/missions")).toBe(0);
    await expect(
      page.getByRole("button", {
        name: /Launch (?:Complete )?Autonomous (?:Assessment|Engagement)/u,
      }),
    ).toBeEnabled();
  } finally {
    ledger.dispose();
    await proxy.dispose();
    if (!page.isClosed()) {
      await browserAudit.closePageBeforeDependencyShutdown(page);
    }
    await backend.stop();
  }
});

import type { AutonomousPlanningSelection } from "../../src/domain/types/commandOs";
import type {
  ModelCatalog,
  ModelCatalogItem,
} from "../../src/domain/types/modelConfiguration";
import {
  activateAutonomousIntake,
  advanceAutonomousIntake,
  assertAutonomousIntakeGuard,
  autonomousTitaniumSelect,
  chooseAutonomousTitaniumOption,
  createIntakeRequestLedger,
  installIntakeApiProxy,
  type IntakeReceiptContext,
} from "./support/autonomousIntake";
import {
  expect,
  test,
  type Locator,
  type Page,
} from "./support/playwright";
import {
  startReadyAutonomousIntakeBackend,
} from "./support/readyAutonomousIntakeBackendController";

const TEST_ID = "e2e.autonomous-planning-selection";

const option = {
  local: "Use local deterministic planning",
  provider: "Use provider-advisory planning",
  agent: "Select the planning agent",
  primaryProvider: "Select an advisor-only primary provider",
  primaryModel: "Select an exact advisor-only primary model",
  primaryReasoning: "Select exact primary planning reasoning",
  fallbackProvider: "Select a planning fallback provider",
  noFallback: "Remove the planning fallback",
  fallbackModel: "Select an exact planning fallback model",
  fallbackReasoning: "Select exact fallback planning reasoning",
  unavailable: "Inspect unavailable planning paths",
} as const;

async function fetchCatalog(page: Page): Promise<ModelCatalog> {
  return page.evaluate(async () => {
    const response = await fetch("/api/v2/model-catalog", {
      headers: { accept: "application/json" },
    });
    if (!response.ok) throw new Error(`Model catalog returned ${response.status}`);
    return response.json() as Promise<ModelCatalog>;
  });
}

function advisorConfigurations(catalog: ModelCatalog): readonly ModelCatalogItem[] {
  const items = catalog.items.filter((item) =>
    item.selectable
    && item.enforcementMode === "advisor_only"
    && item.executionBoundary === "provider_tool_calling"
    && item.authState === "authenticated"
    && item.healthState === "healthy"
    && item.capabilities.structuredOutput);
  expect(items.length).toBeGreaterThanOrEqual(2);
  return items;
}

async function openIntakeTeam(page: Page): Promise<void> {
  await page.goto("/missions/new/autonomous");
  await chooseAutonomousTitaniumOption(
    autonomousTitaniumSelect(page, /Environment classification/u),
    "local_disposable_lab",
    "keyboard",
  );
  await page
    .getByLabel("Authorized targets or environment references", { exact: false })
    .fill("127.0.0.1");
  await page
    .getByRole("checkbox", {
      name: /I confirm these targets and the selected action policy are authorized/u,
    })
    .check();
  await advanceAutonomousIntake(page, "Outcome and collaboration");
  await advanceAutonomousIntake(page, "Autonomous operating contract");
  await advanceAutonomousIntake(
    page,
    "Specialist team and execution readiness",
    { expectPreflight: true },
  );
}

async function activateRadio(
  receipts: IntakeReceiptContext,
  manifestEntryId: string,
  declaredOption: string,
  radio: Locator,
  modality: "pointer" | "keyboard",
): Promise<void> {
  await activateAutonomousIntake(
    receipts,
    manifestEntryId,
    declaredOption,
    modality,
    async () => {
      if (modality === "pointer") await radio.click();
      else {
        await radio.focus();
        await radio.press("Space");
      }
      await expect(radio).toBeChecked();
    },
  );
}

async function activateSelect(
  receipts: IntakeReceiptContext,
  manifestEntryId: string,
  declaredOption: string,
  control: Locator,
  value: string,
  modality: "pointer" | "keyboard",
): Promise<void> {
  await activateAutonomousIntake(
    receipts,
    manifestEntryId,
    declaredOption,
    modality,
    () => chooseAutonomousTitaniumOption(control, value, modality),
  );
}

async function configureProviderPlanning(
  page: Page,
  receipts: IntakeReceiptContext,
  prefix: "autonomous-intake.team" | "autonomous-branch.contract",
): Promise<AutonomousPlanningSelection> {
  const idPrefix = prefix === "autonomous-intake.team"
    ? "autonomous-intake-team"
    : "autonomous-branch";
  const catalog = await fetchCatalog(page);
  const advisor = advisorConfigurations(catalog);
  const low = advisor.find(({ reasoningEffort }) => reasoningEffort === "low")
    ?? advisor[0]!;
  const high = advisor.find(({ reasoningEffort }) => reasoningEffort === "high")
    ?? advisor.find(({ configurationId }) => configurationId !== low.configurationId)!;
  expect(high.configurationId).not.toBe(low.configurationId);

  const providerRoute = page.getByRole("radio", {
    name: "Provider-advisory planner",
    exact: true,
  });
  await expect(providerRoute).toBeEnabled();
  await activateRadio(
    receipts,
    `${prefix}.planning-route-provider`,
    prefix === "autonomous-intake.team"
      ? option.provider
      : "Use provider advisory planning",
    providerRoute,
    "pointer",
  );
  const localRoute = page.getByRole("radio", {
    name: "Local deterministic planner",
    exact: true,
  });
  await activateRadio(
    receipts,
    `${prefix}.planning-route-local`,
    prefix === "autonomous-intake.team"
      ? option.local
      : "Use local deterministic planning",
    localRoute,
    "keyboard",
  );
  await activateRadio(
    receipts,
    `${prefix}.planning-route-provider`,
    prefix === "autonomous-intake.team"
      ? option.provider
      : "Use provider advisory planning",
    providerRoute,
    "keyboard",
  );

  const agent = autonomousTitaniumSelect(page, "Autonomous planning agent");
  const agentValue = await agent
    .locator("xpath=..")
    .locator("select.os-titanium-select__form-proxy")
    .inputValue();
  await activateSelect(
    receipts,
    `${prefix}.planning-agent`,
    prefix === "autonomous-intake.team"
      ? option.agent
      : "Every compatible planning specialist from the live catalog",
    agent,
    agentValue,
    "pointer",
  );
  await activateSelect(
    receipts,
    `${prefix}.planning-primary-provider`,
    prefix === "autonomous-intake.team"
      ? option.primaryProvider
      : "Every compatible advisor-only provider",
    autonomousTitaniumSelect(page, "Autonomous planning primary provider"),
    high.providerId,
    "keyboard",
  );
  await activateSelect(
    receipts,
    `${prefix}.planning-primary-model`,
    prefix === "autonomous-intake.team"
      ? option.primaryModel
      : "Every compatible advisor-only exact model",
    autonomousTitaniumSelect(page, "Autonomous planning primary model"),
    high.modelId,
    "pointer",
  );
  await activateSelect(
    receipts,
    `${prefix}.planning-primary-reasoning`,
    prefix === "autonomous-intake.team"
      ? option.primaryReasoning
      : "Every supported reasoning effort",
    autonomousTitaniumSelect(
      page,
      "Autonomous planning primary reasoning effort",
    ),
    high.configurationId,
    "keyboard",
  );

  const fallbackProvider = autonomousTitaniumSelect(
    page,
    "Autonomous planning fallback provider",
  );
  await activateSelect(
    receipts,
    `${prefix}.planning-fallback-provider`,
    prefix === "autonomous-intake.team"
      ? option.fallbackProvider
      : "Every compatible advisor-only provider",
    fallbackProvider,
    low.providerId,
    "pointer",
  );
  await activateSelect(
    receipts,
    `${prefix}.planning-fallback-model`,
    prefix === "autonomous-intake.team"
      ? option.fallbackModel
      : "Every compatible advisor-only fallback model",
    autonomousTitaniumSelect(page, "Autonomous planning fallback model"),
    low.modelId,
    "keyboard",
  );
  await activateSelect(
    receipts,
    `${prefix}.planning-fallback-reasoning`,
    prefix === "autonomous-intake.team"
      ? option.fallbackReasoning
      : "Every supported fallback reasoning effort",
    autonomousTitaniumSelect(
      page,
      "Autonomous planning fallback reasoning effort",
    ),
    low.configurationId,
    "pointer",
  );
  if (prefix === "autonomous-intake.team") {
    await activateSelect(
      receipts,
      `${prefix}.planning-fallback-provider`,
      option.noFallback,
      fallbackProvider,
      "",
      "keyboard",
    );
    await activateSelect(
      receipts,
      `${prefix}.planning-fallback-provider`,
      option.fallbackProvider,
      fallbackProvider,
      low.providerId,
      "pointer",
    );
  }

  const unavailable = page.getByRole("region", {
    name: "Unavailable planning model paths",
    exact: true,
  });
  await assertAutonomousIntakeGuard(
    receipts,
    `${prefix}.planning-unavailable-paths`,
    prefix === "autonomous-intake.team"
      ? option.unavailable
      : "Inspect why a model cannot construct a provider-advisory plan",
    async () => {
      await expect(unavailable).toBeVisible();
      await expect(unavailable).toContainText("not an advisor-only planning path");
    },
  );
  await expect(
    page.locator(
      `[data-control-id="${idPrefix}-planning-primary-reasoning"]`,
    ),
  ).toHaveAttribute("aria-expanded", "false");

  const selectedPrimaryId = await autonomousTitaniumSelect(
    page,
    "Autonomous planning primary reasoning effort",
  ).locator("xpath=..").locator("select.os-titanium-select__form-proxy").inputValue();
  const selectedFallbackId = await autonomousTitaniumSelect(
    page,
    "Autonomous planning fallback reasoning effort",
  ).locator("xpath=..").locator("select.os-titanium-select__form-proxy").inputValue();
  const selectedPrimary = catalog.items.find(
    ({ configurationId }) => configurationId === selectedPrimaryId,
  );
  if (!selectedPrimary) {
    throw new Error(`Selected primary planning configuration ${selectedPrimaryId} is absent`);
  }
  return {
    route: "provider_advisory",
    agentId: agentValue,
    primaryConfigurationId: selectedPrimaryId,
    fallbackConfigurationId: selectedFallbackId || null,
    enforcementMode: "advisor_only",
    disclosureClass: selectedPrimary.disclosureClass === "public_only"
      ? "public_only"
      : "sanitized_internal",
    executionAuthority: "none",
  };
}

test(`${TEST_ID} preserves one exact advisor-only planning selection through intake review`, async ({
  page,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(240_000);
  await page.emulateMedia({ reducedMotion: "reduce" });
  const backend = await startReadyAutonomousIntakeBackend(testInfo.testId);
  const proxy = await installIntakeApiProxy(page, backend.baseUrl);
  const ledger = createIntakeRequestLedger(page);
  const receipts = { recorder: interactionActivation, testId: TEST_ID };
  try {
    await openIntakeTeam(page);
    const expected = await configureProviderPlanning(
      page,
      receipts,
      "autonomous-intake.team",
    );
    const advanced = await advanceAutonomousIntake(
      page,
      "Second Brain context",
      { expectPreflight: true },
    );
    const submitted = advanced.preflight?.request().postDataJSON() as {
      readonly contract: {
        readonly planningSelection?: AutonomousPlanningSelection;
      };
    };
    expect(submitted.contract.planningSelection).toEqual(expected);
    await advanceAutonomousIntake(
      page,
      "Review the resolved mission",
      { expectPreflight: true },
    );
    const review = page.getByRole("region", {
      name: "Signed planning route",
      exact: true,
    });
    await expect(review).toContainText("Provider advisory");
    await expect(review).toContainText("Advisor only");
    await expect(review).toContainText("Execution authority");
    await expect(review).toContainText("None");
    expect(ledger.count("POST", "/api/v2/registries/intake/resolve"))
      .toBeGreaterThan(0);
  } finally {
    ledger.dispose();
    await proxy.dispose();
    await backend.stop();
  }
});

test(`${TEST_ID} branches only after a deliberate planning-route change`, async ({
  page,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(240_000);
  await page.emulateMedia({ reducedMotion: "reduce" });
  const backend = await startReadyAutonomousIntakeBackend(testInfo.testId);
  const proxy = await installIntakeApiProxy(page, backend.baseUrl);
  const ledger = createIntakeRequestLedger(page);
  const receipts = { recorder: interactionActivation, testId: TEST_ID };
  const branchPath =
    `/api/v2/missions/${backend.branchFixture.missionId}/autonomous-branches/preflight`;
  try {
    await page.goto(
      `/missions/${backend.branchFixture.missionId}/runs/${backend.branchFixture.runId}?tab=settings`,
    );
    await page.getByRole("radio", {
      name: /Versioned contract amendment/u,
    }).click();
    await expect(page.getByRole("heading", {
      name: "Amend explicit authority",
      exact: true,
    })).toBeVisible();
    await configureProviderPlanning(
      page,
      receipts,
      "autonomous-branch.contract",
    );

    const restore = page.getByRole("button", {
      name: "Restore signed planning route",
      exact: true,
    });
    await expect(restore).toBeEnabled();
    await activateAutonomousIntake(
      receipts,
      "autonomous-branch.contract.planning-restore",
      "Restore the source contract selection",
      "pointer",
      async () => {
        await restore.click();
        await expect(page.getByRole("radio", {
          name: "Local deterministic planner",
          exact: true,
        })).toBeChecked();
      },
    );
    const expected = await configureProviderPlanning(
      page,
      receipts,
      "autonomous-branch.contract",
    );
    await page.getByLabel(
      "Branch or amendment reason (audited)",
      { exact: true },
    ).fill("Use the reviewed advisor-only plan construction route.");
    const responsePromise = page.waitForResponse((response) =>
      response.request().method() === "POST"
      && new URL(response.url()).pathname === branchPath);
    await page.getByRole("button", {
      name: "Draft and review amended contract",
      exact: true,
    }).click();
    const response = await responsePromise;
    expect(response.status(), await response.text()).toBe(201);
    const record = ledger.matching("POST", branchPath).at(-1);
    expect(record).toBeDefined();
    const submitted = record?.body as {
      readonly request?: {
        readonly contract: {
          readonly planningSelection?: AutonomousPlanningSelection;
        };
      };
    };
    expect(submitted.request?.contract.planningSelection).toEqual(expected);
    const review = page.getByRole("region", {
      name: "Signed planning route",
      exact: true,
    });
    await expect(review).toContainText("Provider advisory");
    await expect(review).toContainText("Execution authority");
    await expect(review).toContainText("None");
  } finally {
    ledger.dispose();
    await proxy.dispose();
    await backend.stop();
  }
});

import type {
  AutonomousAgentModelAssignment,
  AutonomousMissionPreflight,
} from "../../src/domain/types/commandOs";
import type {
  ResolvedMissionIntake,
} from "../../src/domain/types/intake";
import type {
  ModelCatalog,
  ModelCatalogItem,
} from "../../src/domain/types/modelConfiguration";
import {
  expect,
  test,
  type Locator,
  type Page,
} from "./support/playwright";
import {
  AUTONOMOUS_INTAKE_ROUTE,
  activateAutonomousIntake,
  advanceAutonomousIntake,
  assertAutonomousIntakeGuard,
  autonomousIntakeGroup,
  autonomousTitaniumSelect,
  chooseAutonomousTitaniumOption,
  createIntakeRequestLedger,
  installIntakeApiProxy,
  type IntakeReceiptContext,
} from "./support/autonomousIntake";
import {
  startReadyAutonomousIntakeBackend,
} from "./support/readyAutonomousIntakeBackendController";
import {
  verifyTitaniumOptionDisabled,
} from "./support/titaniumSelect";

const TEST_ID = "e2e.autonomous-intake.agent-model-assignments";
const PRIMARY_PROVIDER_OPTION = "Select a compatible provider for this mission";
const UNAVAILABLE_PROVIDER_OPTION = "Inspect unavailable provider paths and keep them disabled";
const PRIMARY_MODEL_OPTION = "Select a compatible exact primary model";
const OBSERVE_ONLY_MODEL_OPTION = "Inspect an observe-only model and keep it unavailable for Autonomous execution";
const PRIMARY_REASONING_OPTION = "Select an exact primary reasoning effort";
const FALLBACK_PROVIDER_OPTION = "Select a compatible fallback provider";
const NO_FALLBACK_OPTION = "Remove the automatic fallback";
const FALLBACK_MODEL_OPTION = "Select a compatible exact fallback model";
const FALLBACK_REASONING_OPTION = "Select an exact fallback reasoning effort";
const RESTORE_OPTION = "Restore runtime-recommended or inherited assignments";
const CATALOG_RETRY_OPTION =
  "Retry the authoritative catalog read without reviving failed or expired selector choices";

const PRIMARY_PROVIDER_ID = "e2e-ready-autonomous-provider";
const PRIMARY_MODEL_ID = "e2e-ready-autonomous-model";
const ALTERNATE_MODEL_ID = "e2e-ready-autonomous-model-alternate";
const OBSERVE_ONLY_MODEL_ID = "e2e-ready-autonomous-model-observe-only";
const SECONDARY_PROVIDER_ID = "e2e-ready-autonomous-provider-secondary";
const SECONDARY_MODEL_ID = "e2e-ready-autonomous-model-secondary";
const UNAVAILABLE_PROVIDER_ID = "e2e-unavailable-autonomous-provider";

interface AgentChoice {
  readonly id: string;
  readonly displayName: string;
}

function modelControl(
  page: Page,
  agent: AgentChoice,
  suffix:
    | "primary provider"
    | "primary model"
    | "reasoning effort"
    | "fallback provider"
    | "fallback model"
    | "fallback reasoning effort",
): Locator {
  return autonomousTitaniumSelect(page, `${agent.displayName} ${suffix}`);
}

async function fetchCatalog(page: Page): Promise<ModelCatalog> {
  return page.evaluate(async () => {
    const response = await fetch("/api/v2/model-catalog", {
      headers: { accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error(`Model catalog returned ${response.status}`);
    }
    return response.json() as Promise<ModelCatalog>;
  });
}

function exactConfiguration(
  catalog: ModelCatalog,
  input: {
    readonly providerId: string;
    readonly modelId: string;
    readonly reasoningEffort: string;
  },
): ModelCatalogItem {
  const item = catalog.items.find((candidate) =>
    candidate.providerId === input.providerId
    && candidate.modelId === input.modelId
    && candidate.reasoningEffort === input.reasoningEffort);
  if (!item) {
    throw new Error(
      `Live catalog is missing ${input.providerId}/${input.modelId}/${input.reasoningEffort}`,
    );
  }
  return item;
}

async function openTeam(
  page: Page,
): Promise<AutonomousMissionPreflight> {
  await page.goto(AUTONOMOUS_INTAKE_ROUTE);
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
  const advanced = await advanceAutonomousIntake(
    page,
    "Specialist team and execution readiness",
    { expectPreflight: true },
  );
  if (!advanced.preflight) {
    throw new Error("Specialist team did not receive an Autonomous preflight");
  }
  const preflight = await advanced.preflight.json() as AutonomousMissionPreflight;
  await page
    .getByRole("button", { name: "Use recommended team", exact: true })
    .click();
  return preflight;
}

async function activateSelect(
  receipts: IntakeReceiptContext,
  manifestEntryId: string,
  option: string,
  control: Locator,
  value: string,
  modality: "pointer" | "keyboard",
): Promise<void> {
  await activateAutonomousIntake(
    receipts,
    manifestEntryId,
    option,
    modality,
    () => chooseAutonomousTitaniumOption(control, value, modality),
  );
}

test(TEST_ID, async ({ page, browserAudit, interactionActivation }, testInfo) => {
  test.setTimeout(300_000);
  await page.emulateMedia({ reducedMotion: "reduce" });
  const backend = await startReadyAutonomousIntakeBackend(testInfo.testId);
  const proxy = await installIntakeApiProxy(page, backend.baseUrl);
  const ledger = createIntakeRequestLedger(page);
  const receipts: IntakeReceiptContext = {
    recorder: interactionActivation,
    testId: TEST_ID,
  };
  try {
    const firstPreflight = await openTeam(page);
    expect(firstPreflight.readiness.status).toBe("ready");
    const effectiveAgentIds = firstPreflight.execution.team.effectiveAgentIds;
    const selectedAgentIds = firstPreflight.execution.team.recommendedAgentIds;
    expect(effectiveAgentIds.length).toBeGreaterThan(0);
    expect(selectedAgentIds.length).toBeGreaterThan(0);
    expect(firstPreflight.execution.team.modelAssignments).toHaveLength(
      effectiveAgentIds.length,
    );
    const agent = backend.productAgents.find(({ id }) => id === effectiveAgentIds[0]);
    if (!agent) {
      throw new Error("The effective specialist is absent from the canonical product roster");
    }
    const initialReceipt = firstPreflight.execution.team.modelAssignments
      .find((assignment) => assignment.agentId === agent.id);
    expect(initialReceipt).toBeDefined();
    expect(initialReceipt?.ready).toBe(true);
    expect(initialReceipt?.primary.providerId).toBe(PRIMARY_PROVIDER_ID);

    const editor = page
      .locator(".mission-model-assignment")
      .filter({ hasText: agent.displayName });
    await expect(editor).toHaveCount(1);
    await expect(editor).toContainText(initialReceipt!.primary.configurationId);
    await expect(editor).toContainText(
      initialReceipt!.source === "recommended"
        ? "Runtime recommendation"
        : initialReceipt!.source === "inherited"
          ? "Inherited model preference"
          : "Mission operator override",
    );
    await expect(editor).toContainText("Enforced Executor");
    await expect(editor).toContainText("Authenticated");
    await expect(editor).toContainText("Healthy");

    const catalog = await fetchCatalog(page);
    const secondaryHigh = exactConfiguration(catalog, {
      providerId: SECONDARY_PROVIDER_ID,
      modelId: SECONDARY_MODEL_ID,
      reasoningEffort: "high",
    });
    const alternateHigh = exactConfiguration(catalog, {
      providerId: PRIMARY_PROVIDER_ID,
      modelId: ALTERNATE_MODEL_ID,
      reasoningEffort: "high",
    });

    const primaryProvider = modelControl(page, agent, "primary provider");
    await assertAutonomousIntakeGuard(
      receipts,
      "autonomous-intake.team.model-unavailable-paths",
      UNAVAILABLE_PROVIDER_OPTION,
      async () => {
        await verifyTitaniumOptionDisabled(
          primaryProvider,
          UNAVAILABLE_PROVIDER_ID,
          "pointer",
        );
        await verifyTitaniumOptionDisabled(
          primaryProvider,
          UNAVAILABLE_PROVIDER_ID,
          "keyboard",
        );
        await expect(
          editor.getByRole("region", {
            name: `${agent.displayName} unavailable model paths`,
          }),
        ).toContainText("Provider authentication is unavailable");
      },
    );

    await activateSelect(
      receipts,
      "autonomous-intake.team.model-primary-provider",
      PRIMARY_PROVIDER_OPTION,
      primaryProvider,
      SECONDARY_PROVIDER_ID,
      "pointer",
    );
    await activateSelect(
      receipts,
      "autonomous-intake.team.model-primary-provider",
      PRIMARY_PROVIDER_OPTION,
      primaryProvider,
      PRIMARY_PROVIDER_ID,
      "keyboard",
    );

    const primaryModel = modelControl(page, agent, "primary model");
    await assertAutonomousIntakeGuard(
      receipts,
      "autonomous-intake.team.model-unavailable-paths",
      OBSERVE_ONLY_MODEL_OPTION,
      async () => {
        await verifyTitaniumOptionDisabled(
          primaryModel,
          OBSERVE_ONLY_MODEL_ID,
          "pointer",
        );
        await verifyTitaniumOptionDisabled(
          primaryModel,
          OBSERVE_ONLY_MODEL_ID,
          "keyboard",
        );
        await expect(editor).toContainText("Observe Only Executor");
      },
    );
    await activateSelect(
      receipts,
      "autonomous-intake.team.model-primary-model",
      PRIMARY_MODEL_OPTION,
      primaryModel,
      ALTERNATE_MODEL_ID,
      "pointer",
    );
    await activateSelect(
      receipts,
      "autonomous-intake.team.model-primary-reasoning",
      PRIMARY_REASONING_OPTION,
      modelControl(page, agent, "reasoning effort"),
      alternateHigh.configurationId,
      "keyboard",
    );

    await activateSelect(
      receipts,
      "autonomous-intake.team.model-primary-provider",
      PRIMARY_PROVIDER_OPTION,
      primaryProvider,
      SECONDARY_PROVIDER_ID,
      "keyboard",
    );
    await activateSelect(
      receipts,
      "autonomous-intake.team.model-primary-reasoning",
      PRIMARY_REASONING_OPTION,
      modelControl(page, agent, "reasoning effort"),
      secondaryHigh.configurationId,
      "pointer",
    );

    const fallbackProvider = modelControl(page, agent, "fallback provider");
    await activateSelect(
      receipts,
      "autonomous-intake.team.model-fallback-provider",
      FALLBACK_PROVIDER_OPTION,
      fallbackProvider,
      PRIMARY_PROVIDER_ID,
      "pointer",
    );
    await activateSelect(
      receipts,
      "autonomous-intake.team.model-fallback-model",
      FALLBACK_MODEL_OPTION,
      modelControl(page, agent, "fallback model"),
      ALTERNATE_MODEL_ID,
      "keyboard",
    );
    await activateSelect(
      receipts,
      "autonomous-intake.team.model-fallback-reasoning",
      FALLBACK_REASONING_OPTION,
      modelControl(page, agent, "fallback reasoning effort"),
      alternateHigh.configurationId,
      "pointer",
    );
    await activateSelect(
      receipts,
      "autonomous-intake.team.model-fallback-provider",
      NO_FALLBACK_OPTION,
      fallbackProvider,
      "",
      "pointer",
    );
    await activateSelect(
      receipts,
      "autonomous-intake.team.model-fallback-provider",
      FALLBACK_PROVIDER_OPTION,
      fallbackProvider,
      PRIMARY_PROVIDER_ID,
      "keyboard",
    );
    await activateSelect(
      receipts,
      "autonomous-intake.team.model-fallback-model",
      FALLBACK_MODEL_OPTION,
      modelControl(page, agent, "fallback model"),
      ALTERNATE_MODEL_ID,
      "pointer",
    );
    await activateSelect(
      receipts,
      "autonomous-intake.team.model-fallback-reasoning",
      FALLBACK_REASONING_OPTION,
      modelControl(page, agent, "fallback reasoning effort"),
      alternateHigh.configurationId,
      "keyboard",
    );
    await expect(editor).toContainText("Mission override pending review");
    await expect(editor).toContainText(
      "The mission changed after the last review. Run readiness again before launch.",
    );

    const expectedOverride: AutonomousAgentModelAssignment = {
      agentId: agent.id,
      primaryConfigurationId: secondaryHigh.configurationId,
      fallbackConfigurationId: alternateHigh.configurationId,
    };
    const contextAdvance = await advanceAutonomousIntake(
      page,
      "Second Brain context",
      { expectPreflight: true },
    );
    if (!contextAdvance.preflight) {
      throw new Error("Model assignment did not receive a fresh preflight");
    }
    const submitted = contextAdvance.preflight.request().postDataJSON() as {
      readonly contract: {
        readonly agentModelAssignments?: readonly AutonomousAgentModelAssignment[];
      };
    };
    expect(submitted.contract.agentModelAssignments).toHaveLength(
      selectedAgentIds.length,
    );
    expect(
      submitted.contract.agentModelAssignments
        ?.map(({ agentId }) => agentId)
        .sort(),
    ).toEqual([...selectedAgentIds].sort());
    expect(submitted.contract.agentModelAssignments).toContainEqual(expectedOverride);
    const checked = await contextAdvance.preflight.json() as AutonomousMissionPreflight;
    const checkedReceipt = checked.execution.team.modelAssignments
      .find((assignment) => assignment.agentId === agent.id);
    expect(checkedReceipt).toMatchObject({
      agentId: agent.id,
      source: "operator_override",
      ready: true,
      primary: {
        configurationId: secondaryHigh.configurationId,
        providerId: SECONDARY_PROVIDER_ID,
        modelId: SECONDARY_MODEL_ID,
        reasoningEffort: "high",
      },
      fallback: {
        configurationId: alternateHigh.configurationId,
        providerId: PRIMARY_PROVIDER_ID,
        modelId: ALTERNATE_MODEL_ID,
        reasoningEffort: "high",
      },
    });

    const reviewAdvance = await advanceAutonomousIntake(
      page,
      "Review the resolved mission",
      { expectPreflight: true },
    );
    const resolution = await reviewAdvance.resolved.json() as ResolvedMissionIntake;
    expect(resolution.request.journey).toBe("autonomous");
    if (resolution.request.journey !== "autonomous") {
      throw new Error("Expected an Autonomous resolution");
    }
    expect(resolution.request.contract.agentModelAssignments).toHaveLength(
      selectedAgentIds.length,
    );
    const resolvedOverride = resolution.request.contract.agentModelAssignments.find(
      ({ agentId }) => agentId === expectedOverride.agentId,
    );
    expect(resolvedOverride).toBeDefined();
    expect(resolvedOverride && {
      agentId: resolvedOverride.agentId,
      primaryConfigurationId: resolvedOverride.primaryConfigurationId,
      fallbackConfigurationId: resolvedOverride.fallbackConfigurationId,
    }).toEqual(expectedOverride);
    const signedReview = page.getByRole("region", {
      name: "Exact signed specialist models",
    });
    await expect(signedReview).toBeVisible();
    await expect(signedReview.locator(".mission-model-review__item")).toHaveCount(
      selectedAgentIds.length,
    );
    const signedAgent = signedReview
      .locator(".mission-model-review__item")
      .filter({ hasText: agent.displayName });
    await expect(signedAgent).toContainText("Mission operator override");
    await expect(signedAgent).toContainText(secondaryHigh.configurationId);
    await expect(signedAgent).toContainText(alternateHigh.configurationId);
    await expect(signedAgent).toContainText("High");

    await page
      .getByRole("list", { name: "Autonomous intake steps", exact: true })
      .getByRole("button", { name: /Team$/u })
      .click();
    await expect(page.getByRole("group", {
      name: "Specialist team and execution readiness",
      exact: true,
    })).toBeVisible();
    const restore = page.getByRole("button", {
      name: "Restore recommended models",
      exact: true,
    });
    await expect(restore).toHaveAttribute(
      "data-control-id",
      "autonomous-intake-team-model-restore-recommended",
    );
    await expect(restore).toBeEnabled();
    await activateAutonomousIntake(
      receipts,
      "autonomous-intake.team.model-restore",
      RESTORE_OPTION,
      "pointer",
      async () => {
        await restore.click();
        await expect(restore).toBeDisabled();
        await expect(editor).toContainText(
          "The mission changed after the last review. Run readiness again before launch.",
        );
      },
    );

    await activateSelect(
      receipts,
      "autonomous-intake.team.model-primary-provider",
      PRIMARY_PROVIDER_OPTION,
      primaryProvider,
      PRIMARY_PROVIDER_ID,
      "keyboard",
    );
    await expect(restore).toBeEnabled();
    await activateAutonomousIntake(
      receipts,
      "autonomous-intake.team.model-restore",
      RESTORE_OPTION,
      "keyboard",
      async () => {
        await restore.focus();
        await restore.press("Enter");
        await expect(restore).toBeDisabled();
      },
    );

    const recommendedAdvance = await advanceAutonomousIntake(
      page,
      "Second Brain context",
      { expectPreflight: true },
    );
    if (!recommendedAdvance.preflight) {
      throw new Error("Restored model assignments did not receive preflight");
    }
    const restoredIntakeRequest =
      recommendedAdvance.resolved.request().postDataJSON() as Record<string, unknown>;
    expect("agentModelAssignments" in restoredIntakeRequest).toBe(false);
    const restored = await recommendedAdvance.preflight.json() as AutonomousMissionPreflight;
    expect(restored.execution.team.modelAssignments).toHaveLength(
      selectedAgentIds.length,
    );
    expect(
      restored.execution.team.modelAssignments.every((assignment) =>
        assignment.source === "recommended" || assignment.source === "inherited"),
    ).toBe(true);
    expect(ledger.count("POST", "/api/v2/missions")).toBe(0);
    expect(ledger.count("GET", "/api/v2/model-catalog")).toBeGreaterThan(0);
  } finally {
    ledger.dispose();
    await proxy.dispose();
    if (!page.isClosed()) {
      await browserAudit.closePageBeforeDependencyShutdown(page);
    }
    await backend.stop();
  }
});

test(`${TEST_ID} keeps mission selectors retired across a failed catalog retry`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(180_000);
  await page.emulateMedia({ reducedMotion: "reduce" });
  const backend = await startReadyAutonomousIntakeBackend(
    `${testInfo.testId}-catalog-recovery`,
  );
  const proxy = await installIntakeApiProxy(page, backend.baseUrl);
  let catalogAvailable = false;
  await page.route("**/api/v2/model-catalog", async (route) => {
    if (catalogAvailable) {
      await route.fallback();
      return;
    }
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "model_catalog_unavailable",
          message: "The live model catalog could not be refreshed.",
          humanMessage: "The live model catalog could not be refreshed.",
          retryable: true,
          category: "dependency",
          remediation: "Restore the provider catalog service, then try again.",
          traceId: "trace-autonomous-intake-model-catalog",
          timestamp: "2026-07-27T00:00:00.000Z",
        },
      }),
    });
  });
  browserAudit.expectHttpResponse(page, {
    id: "autonomous-intake-model-catalog-unavailable",
    transport: "browser",
    method: "GET",
    pathname: "/api/v2/model-catalog",
    query: {},
    status: 503,
    occurrences: 2,
    reason: "Prove one failed retry cannot revive Autonomous selector choices.",
  });
  const receipts: IntakeReceiptContext = {
    recorder: interactionActivation,
    testId: TEST_ID,
  };
  try {
    await openTeam(page);
    const failure = page.getByRole("alert").filter({
      hasText: "Mission model catalog is unavailable",
    });
    await expect(failure).toContainText(
      "The live model catalog could not be refreshed.",
    );
    await expect(page.getByRole("combobox", {
      name: / primary provider$/u,
    })).toHaveCount(0);

    let retry = failure.getByRole("button", { name: "Try again", exact: true });
    await expect(retry).toHaveAttribute(
      "data-control-id",
      "autonomous-intake-team-model-catalog-retry",
    );
    await activateAutonomousIntake(
      receipts,
      "autonomous-intake.team.model-catalog-retry",
      CATALOG_RETRY_OPTION,
      "pointer",
      async () => {
        const failedRefresh = page.waitForResponse((response) =>
          new URL(response.url()).pathname === "/api/v2/model-catalog"
          && response.status() === 503);
        await retry.click();
        await failedRefresh;
      },
    );
    await expect(page.getByRole("combobox", {
      name: / primary provider$/u,
    })).toHaveCount(0);

    catalogAvailable = true;
    retry = failure.getByRole("button", { name: "Try again", exact: true });
    await expect(retry).toHaveAttribute(
      "data-control-id",
      "autonomous-intake-team-model-catalog-retry",
    );
    await retry.focus();
    await activateAutonomousIntake(
      receipts,
      "autonomous-intake.team.model-catalog-retry",
      CATALOG_RETRY_OPTION,
      "keyboard",
      async () => {
        const recovered = page.waitForResponse((response) =>
          new URL(response.url()).pathname === "/api/v2/model-catalog"
          && response.status() === 200);
        await page.keyboard.press("Enter");
        await recovered;
      },
    );
    await expect(failure).toHaveCount(0);
    await expect(page.getByRole("combobox", {
      name: / primary provider$/u,
    }).first()).toBeVisible();
    await browserAudit.waitForPageApiSettlement(page);
  } finally {
    await proxy.dispose();
    if (!page.isClosed()) {
      await browserAudit.closePageBeforeDependencyShutdown(page);
    }
    await backend.stop();
  }
});

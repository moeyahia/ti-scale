import { expect, test, type Page } from "./support/playwright";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createDecisionsIntelligenceFixture,
  readGuidedRuntimeBindingReceipts,
  type DecisionsIntelligenceFixture,
} from "./support/decisionsIntelligenceFixture";

let fixture: DecisionsIntelligenceFixture;

test.beforeAll(({}, testInfo) => {
  fixture = createDecisionsIntelligenceFixture(
    canonicalFixtureNamespace(testInfo, "guided-provider-free-capabilities"),
  );
});

async function attestProviderFreeLocalGuidedRuntime(page: Page): Promise<void> {
  await page.route("**/api/v2/system/readiness", async (route) => {
    const response = await route.fetch();
    const payload = await response.json() as {
      execution: Record<string, unknown>;
      dependencies: {
        providers: Record<string, unknown>;
        secondBrain?: Record<string, unknown>;
      };
    };
    await route.fulfill({
      response,
      contentType: "application/json",
      body: JSON.stringify({
        ...payload,
        execution: {
          ...payload.execution,
          guided: "ready",
          guidedToolExecution: "ready",
          localCommanderGuidance: "ready",
        },
        dependencies: {
          ...payload.dependencies,
          providers: {
            ...payload.dependencies.providers,
            status: "unavailable",
            declared: 0,
            callable: 0,
            enforcing: 0,
            guidedCapable: 0,
          },
          secondBrain: {
            ...payload.dependencies.secondBrain,
            status: "healthy",
            canonicalStoreAvailable: true,
            reason: "The isolated canonical Second Brain is available.",
          },
        },
      }),
    });
  });
}

test("e2e.guided-provider-free-capabilities enables local explanations without provider, tool, target, or plan authority", async ({ page, browserAudit }) => {
  await attestProviderFreeLocalGuidedRuntime(page);
  const modelConfigurationId = fixture.guidedModelConfigurationId;
  await page.goto(`/guided/${fixture.toolMissionId}`, { waitUntil: "domcontentloaded" });

  await expect(page.getByRole("heading", {
    level: 1,
    name: `${fixture.searchToken} Guided exact tool decision`,
    exact: true,
  })).toBeVisible();
  await expect(page.getByText("Reviewed local Guided execution is active.", { exact: true })).toBeVisible();
  await expect(page.getByText(
    "The local Commander can explain the current exact step and how to request another approach without contacting a provider, tool, or target.",
    { exact: false },
  )).toBeVisible();
  await expect(page.getByText(
    "Provider-backed semantic interpretation remains unavailable.",
    { exact: false },
  )).toBeVisible();

  const exactGuidance = {
    mode: "local_deterministic",
    productAgentId: "ReconScout",
    modelConfigurationId,
    providerId: "provider:local-deterministic-safe-recon",
    modelId: "policy:local-safe-recon-v2",
    usedFallbackModel: false,
    providerContacted: false,
    toolDispatched: false,
    targetContacted: false,
    planMutated: false,
    exactDecisionRequired: true,
  };
  const guidanceControls = [
    { name: "Explain more", path: "explain-more" },
    { name: "Show next step", path: "show-next-step" },
    { name: "Use another approach", path: "use-another-approach" },
  ] as const;

  for (const control of guidanceControls) {
    const button = page.getByRole("button", { name: control.name, exact: true });
    await expect(button).toBeEnabled();
    const responsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return response.request().method() === "POST"
        && url.pathname === `/api/v2/guided/${fixture.toolMissionId}/commander/${control.path}`;
    });
    await button.click();
    const response = await responsePromise;
    expect(response.status()).toBe(200);
    const payload = await response.json() as {
      guidance: typeof exactGuidance & {
        readonly modelAssignmentId: string;
      };
      result: {
        action: string;
        contextPackId: string;
        assistantMessage: {
          body: string;
          structuredContent: Record<string, unknown>;
        };
      };
    };
    expect(payload.guidance).toMatchObject(exactGuidance);
    expect(payload.guidance.modelAssignmentId).toEqual(expect.any(String));
    expect(payload.result.contextPackId).toBeTruthy();
    expect(payload.result.assistantMessage.body).toContain(
      "Control boundary — This response explains one represented step",
    );
    expect(payload.result.assistantMessage.structuredContent).toMatchObject({
      productAgentId: "ReconScout",
      modelConfigurationId,
      modelAssignmentId: payload.guidance.modelAssignmentId,
      executionPerformed: false,
      planMutated: false,
      nextConsequentialActionRequiresDecision: true,
    });
    await expect(page.getByRole("button", { name: "Run this exact step", exact: true })).toBeEnabled();
  }

  await expect(page.getByText(
    "Control boundary — This response explains one represented step",
    { exact: false },
  ).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Run this exact step", exact: true })).toBeEnabled();

  await browserAudit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.reload({ waitUntil: "domcontentloaded" }),
  );
  await expect(page.getByText(
    "Control boundary — This response explains one represented step",
    { exact: false },
  ).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Run this exact step", exact: true })).toBeEnabled();

  const result = page.getByLabel("Result text", { exact: true });
  await expect(result).toBeEnabled();
  await result.fill("One bounded operator-observed line.");
  await expect(page.getByRole("button", {
    name: "Retain and attest ingestion — keep step paused",
    exact: true,
  })).toBeEnabled();
  await expect(page.getByRole("button", {
    name: "Accept interpreted evidence and advance exact step",
    exact: true,
  })).toHaveCount(0);

  const receipts = readGuidedRuntimeBindingReceipts(fixture);
  expect(receipts).toHaveLength(guidanceControls.length);
  expect(new Set(receipts.map(({ modelAssignmentId }) => modelAssignmentId)).size).toBe(1);
  for (const receipt of receipts) {
    expect(receipt).toMatchObject({
      provider: "provider:local-deterministic-safe-recon",
      model: "policy:local-safe-recon-v2",
      status: "completed",
      agentId: "ReconScout",
      modelConfigurationId,
    });
    expect(receipt.modelAssignmentId).toEqual(expect.any(String));
    expect(receipt.promptTemplateHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(receipt.contextPackId).toEqual(expect.any(String));
  }
});

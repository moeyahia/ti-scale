import {
  expect,
  test,
  type Page,
  type Route,
} from "./support/playwright";
import {
  startAgentModelSettingsRealBackend,
  type AgentModelSettingsRealBackend,
} from "./support/agentModelSettingsRealBackend";
import {
  readTitaniumOptions,
  selectTitaniumOption,
} from "./support/titaniumSelect";

const TEST_ID =
  "e2e.agent-model-settings.real-backend-persistence";
const EXPECTED_PRODUCT_AGENT_IDS = [
  "ADAttackMapper",
  "CloudSentinel",
  "CredSmith",
  "FuzzSmith",
  "OSINTSeeker",
  "ReconScout",
  "ReportSmith",
  "ReverseSage",
  "SecretHunter",
  "SessionRunner",
  "VulnIntel",
  "WebBreaker",
] as const;

let backend: AgentModelSettingsRealBackend;

test.describe.configure({ mode: "serial" });
test.beforeAll(async () => {
  backend = await startAgentModelSettingsRealBackend();
});
test.afterAll(async () => {
  await backend.close();
});

async function forwardToRealBackend(
  route: Route,
  baseUrl: string,
): Promise<void> {
  const incoming = new URL(route.request().url());
  const target = new URL(`${incoming.pathname}${incoming.search}`, baseUrl);
  const response = await route.fetch({ url: target.toString() });
  await route.fulfill({ response });
}

async function useRealModelBackend(
  page: Page,
  fixture: AgentModelSettingsRealBackend,
): Promise<void> {
  const forward = (route: Route) =>
    forwardToRealBackend(route, fixture.url);
  await page.route("**/api/v2/agents**", forward);
  await page.route("**/api/v2/model-**", forward);
}

test(`${TEST_ID} exposes only the canonical roster and persists one exact execution assignment across refresh`, async ({
  page,
  browserAudit,
}) => {
  test.setTimeout(90_000);
  await useRealModelBackend(page, backend);

  const rosterResponse = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === "/api/v2/agents"
      && url.searchParams.get("limit") === "100";
  });
  await page.goto("/agents/ReconScout#agent-model-configuration", {
    waitUntil: "domcontentloaded",
  });
  const rosterBody = await (await rosterResponse).json() as {
    readonly items: readonly { readonly id: string }[];
  };
  expect(rosterBody.items.map(({ id }) => id).sort())
    .toEqual([...EXPECTED_PRODUCT_AGENT_IDS]);
  expect(rosterBody.items.some(({ id }) => id === backend.internalAdapterId))
    .toBe(false);

  const editor = page.getByLabel(
    "ReconScout model configuration",
    { exact: true },
  );
  await expect(editor).toBeVisible();
  const semantics = editor.getByLabel(
    "ReconScout model assignment semantics",
    { exact: true },
  );
  await expect(semantics).toContainText("Specialist execution");
  await expect(semantics).toContainText("Workspace → agent → mission → run → step");
  await expect(semantics).toContainText("Immutable pinned receipt");
  await expect(semantics).toContainText("Reviewed in the mission contract");

  const provider = editor.getByRole("combobox", {
    name: "ReconScout provider",
    exact: true,
  });
  const model = editor.getByRole("combobox", {
    name: "ReconScout primary model",
    exact: true,
  });
  const reasoning = editor.getByRole("combobox", {
    name: "ReconScout reasoning effort",
    exact: true,
  });
  const fallback = editor.getByRole("combobox", {
    name: "ReconScout fallback model",
    exact: true,
  });
  await selectTitaniumOption(provider, "titanium-primary", "pointer");
  await selectTitaniumOption(model, "ti-reasoner", "pointer");
  const highOption = (await readTitaniumOptions(reasoning))
    .find(({ label }) => label === "High")?.value ?? null;
  expect(highOption).not.toBeNull();
  await selectTitaniumOption(reasoning, highOption!, "pointer");
  const fallbackOption = (await readTitaniumOptions(fallback))
    .find(({ label }) => label.includes("titanium-fallback"))?.value ?? null;
  expect(fallbackOption).not.toBeNull();
  await selectTitaniumOption(fallback, fallbackOption!, "pointer");

  const reason =
    "Pin this exact high-reasoning execution route for future ReconScout runs.";
  await editor.getByRole("textbox", {
    name: "Reason for this assignment",
    exact: true,
  }).fill(reason);
  const writeResponse = page.waitForResponse((response) =>
    response.request().method() === "PUT"
    && new URL(response.url()).pathname
      === "/api/v2/model-preferences/agent/ReconScout");
  await editor.getByRole("button", {
    name: "Save agent assignment",
    exact: true,
  }).click();
  expect((await writeResponse).status()).toBe(201);
  await expect(editor.getByRole("status"))
    .toContainText("Model assignment version 1 saved");

  await browserAudit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.reload({ waitUntil: "domcontentloaded" }),
  );
  await expect(editor).toBeVisible();
  await expect(editor).toContainText("ReconScout override");
  await expect(editor).toContainText(reason);
  const formValue = (control: typeof provider) =>
    control.locator("xpath=..")
      .locator("select.os-titanium-select__form-proxy");
  await expect(formValue(provider)).toHaveValue("titanium-primary");
  await expect(formValue(model)).toHaveValue("ti-reasoner");
  await expect(formValue(reasoning)).toHaveValue(highOption!);
  await expect(formValue(fallback)).toHaveValue(fallbackOption!);
  await expect(editor).toContainText("Enforced Executor");
  await expect(editor).toContainText("Public Only");
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

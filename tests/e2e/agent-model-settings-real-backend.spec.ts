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
  "Commander",
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
  await expect(editor.locator('[data-model-catalog-refresh="staged"]'))
    .toHaveCount(0);
  await expect(editor.locator('[data-model-catalog-refresh="unresolved"]'))
    .toHaveCount(0);

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

test(`${TEST_ID} refreshes an older immutable provider attestation through one explicit real preference mutation`, async ({
  page,
  browserAudit,
}) => {
  test.setTimeout(90_000);
  backend.renewCatalogAttestation("2099-07-28T12:00:02.000Z");
  await useRealModelBackend(page, backend);
  await page.goto("/agents/ReconScout#agent-model-configuration", {
    waitUntil: "domcontentloaded",
  });

  const editor = page.getByLabel(
    "ReconScout model configuration",
    { exact: true },
  );
  await expect(editor).toBeVisible();
  await expect(editor.locator('[data-model-catalog-refresh="staged"]'))
    .toContainText("older provider-attestation receipt");
  await expect(editor).toContainText("Saved primary receipt:");
  await expect(editor).toContainText(
    "titanium-primary · Titanium Reasoner (ti-reasoner)",
  );
  await expect(editor).toContainText("Saved fallback receipt:");

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
  const formValue = (control: typeof provider) =>
    control.locator("xpath=..")
      .locator("select.os-titanium-select__form-proxy");
  await expect(formValue(provider)).toHaveValue("titanium-primary");
  await expect(formValue(model)).toHaveValue("ti-reasoner");
  await expect(reasoning).toContainText("High");
  await expect(fallback).toContainText("titanium-fallback");
  const refreshedPrimaryId = await formValue(reasoning).inputValue();
  const refreshedFallbackId = await formValue(fallback).inputValue();
  const refreshedMediumId = (await readTitaniumOptions(reasoning))
    .find(({ label }) => label === "Medium")?.value ?? null;
  expect(refreshedMediumId).not.toBeNull();
  await selectTitaniumOption(reasoning, refreshedMediumId!, "pointer");
  await expect(editor.locator(
    '[data-model-catalog-refresh="staged-alternative"]',
  )).toContainText("this draft now selects a different route");
  await selectTitaniumOption(reasoning, refreshedPrimaryId, "pointer");
  await expect(editor.locator('[data-model-catalog-refresh="staged"]'))
    .toContainText("staged the single matching live provider");

  const reason =
    "Refresh ReconScout to the current live provider attestation without changing active run pins.";
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
  const response = await writeResponse;
  expect(response.status()).toBe(200);
  const requestBody = response.request().postDataJSON() as {
    readonly primaryConfigurationId: string;
    readonly fallbackConfigurationId: string | null;
    readonly expectedVersion: number;
  };
  expect(requestBody).toMatchObject({
    primaryConfigurationId: refreshedPrimaryId,
    fallbackConfigurationId: refreshedFallbackId,
    expectedVersion: 1,
  });
  await expect(editor.getByText(
    "Model assignment version 2 saved. New runs will pin this exact configuration.",
    { exact: true },
  )).toBeVisible();

  await browserAudit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.reload({ waitUntil: "domcontentloaded" }),
  );
  await expect(editor).toBeVisible();
  await expect(editor.locator('[data-model-catalog-refresh="staged"]'))
    .toHaveCount(0);
  await expect(editor).toContainText(reason);
  await expect(formValue(reasoning)).toHaveValue(refreshedPrimaryId);
  await expect(formValue(fallback)).toHaveValue(refreshedFallbackId);
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

test(`${TEST_ID} reconciles a stale workspace default from immutable receipts and mutates it only after review`, async ({
  page,
  browserAudit,
}) => {
  test.setTimeout(90_000);
  backend.renewCatalogAttestation("2099-07-28T12:00:03.000Z");
  await useRealModelBackend(page, backend);
  const globalWrites: string[] = [];
  page.on("request", (request) => {
    if (
      request.method() === "PUT"
      && new URL(request.url()).pathname
        === "/api/v2/model-preferences/global/global"
    ) {
      globalWrites.push(request.postData() ?? "");
    }
  });
  await page.goto("/system/settings", { waitUntil: "domcontentloaded" });

  const editor = page.getByLabel(
    "Workspace default model configuration",
    { exact: true },
  );
  await expect(editor).toBeVisible();
  const provider = editor.getByRole("combobox", {
    name: "Workspace default provider",
    exact: true,
  });
  const model = editor.getByRole("combobox", {
    name: "Workspace default primary model",
    exact: true,
  });
  const reasoning = editor.getByRole("combobox", {
    name: "Workspace default reasoning effort",
    exact: true,
  });
  const fallback = editor.getByRole("combobox", {
    name: "Workspace default fallback model",
    exact: true,
  });
  const formValue = (control: typeof provider) =>
    control.locator("xpath=..")
      .locator("select.os-titanium-select__form-proxy");

  await selectTitaniumOption(provider, "titanium-primary", "pointer");
  await selectTitaniumOption(model, "ti-reasoner", "pointer");
  const highConfigurationId = (await readTitaniumOptions(reasoning))
    .find(({ label }) => label === "High")?.value ?? null;
  expect(highConfigurationId).not.toBeNull();
  await selectTitaniumOption(
    reasoning,
    highConfigurationId!,
    "pointer",
  );
  const fallbackConfigurationId = (await readTitaniumOptions(fallback))
    .find(({ label }) => label.includes("titanium-fallback"))?.value ?? null;
  expect(fallbackConfigurationId).not.toBeNull();
  await selectTitaniumOption(
    fallback,
    fallbackConfigurationId!,
    "pointer",
  );
  await editor.getByRole("textbox", {
    name: "Reason for this assignment",
    exact: true,
  }).fill("Establish the reviewed real workspace execution default.");
  const createResponse = page.waitForResponse((response) =>
    response.request().method() === "PUT"
    && new URL(response.url()).pathname
      === "/api/v2/model-preferences/global/global");
  await editor.getByRole("button", {
    name: "Save workspace default",
    exact: true,
  }).click();
  expect((await createResponse).status()).toBe(201);
  await expect(editor).toContainText("Preference version 1");

  const mediumConfigurationId = (await readTitaniumOptions(reasoning))
    .find(({ label }) => label === "Medium")?.value ?? null;
  expect(mediumConfigurationId).not.toBeNull();
  await selectTitaniumOption(
    reasoning,
    mediumConfigurationId!,
    "pointer",
  );
  await expect(editor.locator('[data-model-catalog-refresh="staged"]'))
    .toHaveCount(0);
  await expect(editor.locator('[data-model-catalog-refresh="unresolved"]'))
    .toHaveCount(0);
  expect(globalWrites).toHaveLength(1);

  backend.renewCatalogAttestation("2099-07-28T12:00:04.000Z");
  const immutableReceipts = page.waitForResponse((response) =>
    response.request().method() === "GET"
    && new URL(response.url()).pathname === "/api/v2/model-configurations");
  await browserAudit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.reload({ waitUntil: "domcontentloaded" }),
  );
  const receiptResponse = await immutableReceipts;
  expect(receiptResponse.status()).toBe(200);
  const receiptIds = new URL(receiptResponse.url())
    .searchParams.get("ids")?.split(",") ?? [];
  expect(receiptIds).toEqual(expect.arrayContaining([
    highConfigurationId!,
    fallbackConfigurationId!,
  ]));

  await expect(editor).toBeVisible();
  await expect(editor.locator('[data-model-catalog-refresh="staged"]'))
    .toContainText("older provider-attestation receipt");
  await expect(editor).toContainText("Saved primary receipt:");
  await expect(editor).toContainText(highConfigurationId!);
  await expect(editor).toContainText("Saved fallback receipt:");
  await expect(editor).toContainText(fallbackConfigurationId!);
  await expect(formValue(provider)).toHaveValue("titanium-primary");
  await expect(formValue(model)).toHaveValue("ti-reasoner");
  const refreshedPrimaryId = await formValue(reasoning).inputValue();
  const refreshedFallbackId = await formValue(fallback).inputValue();
  expect(refreshedPrimaryId).not.toBe(highConfigurationId);
  expect(refreshedFallbackId).not.toBe(fallbackConfigurationId);
  expect(globalWrites).toHaveLength(1);

  const refreshReason =
    "Refresh the workspace default receipt for future runs without rewriting active run pins.";
  await editor.getByRole("textbox", {
    name: "Reason for this assignment",
    exact: true,
  }).fill(refreshReason);
  const updateResponse = page.waitForResponse((response) =>
    response.request().method() === "PUT"
    && new URL(response.url()).pathname
      === "/api/v2/model-preferences/global/global");
  await editor.getByRole("button", {
    name: "Save workspace default",
    exact: true,
  }).click();
  const response = await updateResponse;
  expect(response.status()).toBe(200);
  expect(response.request().postDataJSON()).toMatchObject({
    agentId: null,
    primaryConfigurationId: refreshedPrimaryId,
    fallbackConfigurationId: refreshedFallbackId,
    expectedVersion: 1,
    reason: refreshReason,
  });
  await expect(editor).toContainText("Preference version 2");
  await expect(editor.locator('[data-model-catalog-refresh="staged"]'))
    .toHaveCount(0);
  expect(globalWrites).toHaveLength(2);
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

test(`${TEST_ID} requires a deliberate live selection when a saved execution receipt changed materially`, async ({
  page,
  browserAudit,
}) => {
  test.setTimeout(90_000);
  backend.renewCatalogAttestation(
    "2099-07-28T12:00:05.000Z",
    { primaryContextLimit: 262_144 },
  );
  await useRealModelBackend(page, backend);
  const writes: string[] = [];
  page.on("request", (request) => {
    if (
      request.method() === "PUT"
      && new URL(request.url()).pathname
        === "/api/v2/model-preferences/agent/ReconScout"
    ) {
      writes.push(request.postData() ?? "");
    }
  });
  await page.goto("/agents/ReconScout#agent-model-configuration", {
    waitUntil: "domcontentloaded",
  });

  const editor = page.getByLabel(
    "ReconScout model configuration",
    { exact: true },
  );
  await expect(editor).toBeVisible();
  await expect(editor.locator('[data-model-catalog-refresh="unresolved"]'))
    .toContainText("no single equivalent route could be proven");
  const save = editor.getByRole("button", {
    name: "Save agent assignment",
    exact: true,
  });
  await expect(save).toBeDisabled();
  expect(writes).toHaveLength(0);

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
  const formValue = (control: typeof provider) =>
    control.locator("xpath=..")
      .locator("select.os-titanium-select__form-proxy");

  await selectTitaniumOption(provider, "titanium-primary", "pointer");
  await selectTitaniumOption(model, "ti-reasoner", "pointer");
  const highConfigurationId = (await readTitaniumOptions(reasoning))
    .find(({ label }) => label === "High")?.value ?? null;
  expect(highConfigurationId).not.toBeNull();
  await selectTitaniumOption(
    reasoning,
    highConfigurationId!,
    "pointer",
  );
  await editor.getByRole("textbox", {
    name: "Reason for this assignment",
    exact: true,
  }).fill(
    "Accept the reviewed larger-context provider receipt for future ReconScout runs.",
  );
  await expect(save).toBeEnabled();

  const writeResponse = page.waitForResponse((response) =>
    response.request().method() === "PUT"
    && new URL(response.url()).pathname
      === "/api/v2/model-preferences/agent/ReconScout");
  await save.click();
  const response = await writeResponse;
  expect(response.status()).toBe(200);
  expect(response.request().postDataJSON()).toMatchObject({
    primaryConfigurationId: highConfigurationId,
    expectedVersion: 2,
  });
  expect(writes).toHaveLength(1);
  await expect(editor).toContainText("Preference version 3");
  await expect(editor.locator('[data-model-catalog-refresh="unresolved"]'))
    .toHaveCount(0);
  await expect(formValue(reasoning)).toHaveValue(highConfigurationId!);
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

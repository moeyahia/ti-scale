import { readFileSync } from "node:fs";
import { expect, test, type Locator, type Page, type Response, type TestInfo } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
} from "./support/interactionActivationFixture";
import { readTitaniumOptions, selectTitaniumOption } from "./support/titaniumSelect";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import {
  createSystemFixture,
  readSystemFixtureSnapshot,
  SYSTEM_FIXTURE_SECRET,
  SYSTEM_HEALTH_COMPONENT,
  SYSTEM_MCP_FIRST_PAGE,
  SYSTEM_MCP_SECOND_PAGE,
  SYSTEM_POLICY_SETTING,
  SYSTEM_PROVIDER_FIRST_PAGE,
  SYSTEM_PROVIDER_SECOND_PAGE,
  type SystemFixture,
} from "./support/systemFixture";

const TEST_IDS = {
  routesAndTabs: "e2e.system.routes-and-tabs",
  connections: "e2e.system.connections-controls",
  retry: "e2e.system.connections-retry",
  policies: "e2e.system.policies-controls",
  settings: "e2e.system.settings-controls",
} as const;

const SYSTEM_TABS = [
  { name: "Connections", href: "/system/connections" },
  { name: "Policies", href: "/system/policies" },
  { name: "Settings status", href: "/system/settings" },
] as const;
const MCP_STATUS_OPTIONS = ["All", "unknown", "healthy", "degraded", "offline", "quarantined"];
const interactionManifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

function settingsReceipt(
  manifestEntryId: "system.settings.openapi-contract" | "system.settings.event-contract" | "system.settings.metrics",
  option: string,
  modality: "pointer" | "keyboard",
): InteractionActivationInput {
  const entry = interactionManifest.entries.find((candidate) => candidate.id === manifestEntryId);
  if (!entry) throw new Error(`System Settings manifest entry ${manifestEntryId} is missing`);
  if (!entry.options.includes(option)) {
    throw new Error(`System Settings manifest entry ${manifestEntryId} does not declare ${option}`);
  }
  if (!entry.testIds.includes(TEST_IDS.settings)) {
    throw new Error(`System Settings manifest entry ${manifestEntryId} is not bound to ${TEST_IDS.settings}`);
  }
  return {
    manifestEntryId,
    controlId: entry.controlId,
    option,
    materialState: entry.requiredState,
    modality,
    testId: TEST_IDS.settings,
  };
}

function systemRetryReceipt(
  option: string,
  modality: "pointer" | "keyboard",
): InteractionActivationInput {
  const entry = interactionManifest.entries.find((candidate) => candidate.id === "system.query.retry");
  if (!entry) throw new Error("System query retry manifest entry is missing");
  if (!entry.options.includes(option)) {
    throw new Error(`System query retry manifest entry does not declare ${option}`);
  }
  if (!entry.testIds.includes(TEST_IDS.retry)) {
    throw new Error(`System query retry manifest entry is not bound to ${TEST_IDS.retry}`);
  }
  return {
    manifestEntryId: entry.id,
    controlId: entry.controlId,
    option,
    materialState: entry.requiredState,
    modality,
    testId: TEST_IDS.retry,
  };
}

let fixture: SystemFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(({}, testInfo) => {
  fixture = createSystemFixture(canonicalFixtureNamespace(testInfo, "system"));
});

function systemResponse(
  page: Page,
  endpoint: "/api/v2/system/providers" | "/api/v2/system/mcp" | "/api/v2/system/policies" | "/api/v2/system/health",
  predicate: (url: URL) => boolean = () => true,
): Promise<Response> {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET" && url.pathname === endpoint && predicate(url);
  });
}

function capabilitySelfTestResponse(page: Page): Promise<Response> {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET"
      && url.pathname === "/api/v2/system/capability-self-tests";
  });
}

async function assertCapabilitySnapshot(response: Response): Promise<{
  readonly total: number;
  readonly results: readonly Record<string, unknown>[];
}> {
  expect(response.status(), await response.text()).toBe(200);
  const payload = await response.json() as {
    readonly schemaVersion: string;
    readonly readOnly: boolean;
    readonly grantsMissionExecution: boolean;
    readonly accounting: {
      readonly complete: boolean;
      readonly registered: Record<string, number>;
      readonly reported: Record<string, number>;
    };
    readonly summary: { readonly total: number };
    readonly results: readonly Record<string, unknown>[];
  };
  expect(payload.schemaVersion).toBe("2.4");
  expect(payload.readOnly).toBe(true);
  expect(payload.grantsMissionExecution).toBe(false);
  expect(payload.accounting.complete).toBe(true);
  expect(payload.summary.total).toBe(payload.results.length);
  expect(payload.results.length).toBeGreaterThan(0);
  expect(payload.results.every((item) => {
    const authorization = item.executionAuthorization as Record<string, unknown> | undefined;
    return authorization?.state === "not_granted" && authorization.grantsMissionExecution === false;
  })).toBe(true);
  return { total: payload.summary.total, results: payload.results };
}

async function strictAudit(audit: BrowserAudit, testInfo: TestInfo): Promise<void> {
  expect(audit.unexpected, "System controls emitted an unexpected browser, console, network, or server failure").toEqual([]);
  expect(audit.degradedApi, "System controls require the mounted V2 API for every canonical read").toEqual([]);
  await audit.assertClean(testInfo);
}

async function activate(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await control.press("Enter");
  } else {
    await control.click();
  }
}

async function titaniumOptionLabels(control: Locator): Promise<readonly string[]> {
  return (await readTitaniumOptions(control)).map((option) => option.label);
}

async function expectSystemHeading(page: Page): Promise<void> {
  await expect(page.getByRole("heading", { level: 1, name: "System", exact: true })).toBeVisible();
  await expect(page.getByText("Command surface not found", { exact: true })).toHaveCount(0);
}

function section(page: Page, name: string): Locator {
  return page.locator("section").filter({ has: page.getByRole("heading", { name, exact: true }) }).first();
}

function disclosure(scope: Page | Locator, name: string): Locator {
  return scope.locator("summary").filter({ hasText: name });
}

async function toggleEveryDisclosure(disclosures: Locator, expectedMinimum: number): Promise<void> {
  const count = await disclosures.count();
  expect(count).toBeGreaterThanOrEqual(expectedMinimum);
  for (let index = 0; index < count; index += 1) {
    const disclosure = disclosures.nth(index);
    await activate(disclosure, index === 0 ? "keyboard" : "pointer");
    await expect(disclosure.locator("xpath=..")).toHaveJSProperty("open", true);
  }
}

async function assertPagePayload(response: Response, minimumItems = 1): Promise<{
  readonly items: readonly Record<string, unknown>[];
  readonly nextCursor: string | null;
}> {
  expect(response.status(), await response.text()).toBe(200);
  const payload = await response.json() as {
    readonly schemaVersion: string;
    readonly items: readonly Record<string, unknown>[];
    readonly nextCursor: string | null;
  };
  expect(payload.schemaVersion).toBe("2.4");
  expect(payload.items.length).toBeGreaterThanOrEqual(minimumItems);
  return payload;
}

test(`${TEST_IDS.routesAndTabs} traverses the alias, canonical tabs, history, and direct refresh`, async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const aliasCapabilities = capabilitySelfTestResponse(page);
  const aliasProviders = systemResponse(page, "/api/v2/system/providers");
  const aliasMcp = systemResponse(page, "/api/v2/system/mcp");
  await page.goto("/system", { waitUntil: "domcontentloaded" });
  await assertCapabilitySnapshot(await aliasCapabilities);
  await assertPagePayload(await aliasProviders);
  await assertPagePayload(await aliasMcp);
  await expectSystemHeading(page);
  await expect.poll(() => new URL(page.url()).pathname).toBe("/system");

  for (const tab of SYSTEM_TABS) {
    await expect(page.getByRole("link", { name: tab.name, exact: true })).toHaveAttribute("href", tab.href);
  }

  const aliasMcpSection = section(page, "MCP servers");
  const aliasStatus = aliasMcpSection.getByRole("combobox", { name: "Status", exact: true });
  await expect(aliasStatus).toBeVisible();
  const aliasHealthy = systemResponse(page, "/api/v2/system/mcp", (url) => url.searchParams.get("status") === "healthy");
  await selectTitaniumOption(aliasStatus, "healthy", "keyboard");
  await assertPagePayload(await aliasHealthy);
  await expect(aliasStatus).toBeFocused();
  await expect.poll(() => new URL(page.url()).searchParams.get("status")).toBe("healthy");
  await selectTitaniumOption(aliasStatus, "", "pointer");
  await expect.poll(() => new URL(page.url()).searchParams.has("status")).toBe(false);

  const aliasProviderSection = section(page, "Providers");
  const aliasProviderNext = systemResponse(page, "/api/v2/system/providers", (url) => url.searchParams.has("cursor"));
  await activate(aliasProviderSection.getByRole("button", { name: "Next page", exact: true }), "pointer");
  await assertPagePayload(await aliasProviderNext);
  await activate(aliasProviderSection.getByRole("button", { name: "First page", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.has("providerCursor")).toBe(false);
  await expect(aliasProviderSection.getByText(SYSTEM_PROVIDER_FIRST_PAGE, { exact: true })).toBeVisible();
  await expect(aliasProviderSection.getByRole("button", { name: "First page", exact: true })).toBeDisabled();

  const aliasMcpNext = systemResponse(page, "/api/v2/system/mcp", (url) => url.searchParams.has("cursor"));
  await activate(aliasMcpSection.getByRole("button", { name: "Next page", exact: true }), "keyboard");
  await assertPagePayload(await aliasMcpNext);
  await toggleEveryDisclosure(disclosure(aliasMcpSection, "Capabilities and policy"), 1);
  await activate(aliasMcpSection.getByRole("button", { name: "First page", exact: true }), "pointer");
  await expect.poll(() => new URL(page.url()).searchParams.has("mcpCursor")).toBe(false);
  await expect(aliasMcpSection.getByRole("rowheader", { name: SYSTEM_MCP_FIRST_PAGE })).toBeVisible();
  await expect(aliasMcpSection.getByRole("button", { name: "First page", exact: true })).toBeDisabled();
  await toggleEveryDisclosure(disclosure(aliasMcpSection, "Capabilities and policy"), 1);

  const policies = systemResponse(page, "/api/v2/system/policies");
  await activate(page.getByRole("link", { name: "Policies", exact: true }), "keyboard");
  await assertPagePayload(await policies);
  await expect.poll(() => new URL(page.url()).pathname).toBe("/system/policies");
  await expect(page.getByRole("link", { name: "Policies", exact: true })).toHaveClass(/is-current/u);

  const health = systemResponse(page, "/api/v2/system/health");
  const settingsPolicies = systemResponse(page, "/api/v2/system/policies", (url) => url.searchParams.get("limit") === "100");
  await activate(page.getByRole("link", { name: "Settings status", exact: true }), "pointer");
  await assertPagePayload(await health);
  await assertPagePayload(await settingsPolicies);
  await expect.poll(() => new URL(page.url()).pathname).toBe("/system/settings");

  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect.poll(() => new URL(page.url()).pathname).toBe("/system/policies");
  await expectSystemHeading(page);
  await page.goForward({ waitUntil: "domcontentloaded" });
  await expect.poll(() => new URL(page.url()).pathname).toBe("/system/settings");
  await expectSystemHeading(page);

  await activate(page.getByRole("link", { name: "Connections", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).pathname).toBe("/system/connections");
  await expect(page.getByText(SYSTEM_PROVIDER_FIRST_PAGE, { exact: true })).toBeVisible();
  await expect(page.getByRole("rowheader", { name: SYSTEM_MCP_FIRST_PAGE })).toBeVisible();
  const reloadProviders = systemResponse(page, "/api/v2/system/providers");
  const reloadMcp = systemResponse(page, "/api/v2/system/mcp");
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await assertPagePayload(await reloadProviders);
  await assertPagePayload(await reloadMcp);
  await expectSystemHeading(page);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.connections} exercises provider and MCP pagination, every status option, and every visible policy disclosure`, async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const capabilitiesResponse = capabilitySelfTestResponse(page);
  const providersResponse = systemResponse(page, "/api/v2/system/providers");
  const mcpResponse = systemResponse(page, "/api/v2/system/mcp");
  await page.goto("/system/connections", { waitUntil: "domcontentloaded" });
  const capabilityPayload = await assertCapabilitySnapshot(await capabilitiesResponse);
  const providersPayload = await assertPagePayload(await providersResponse, 25);
  const mcpPayload = await assertPagePayload(await mcpResponse, 25);
  expect(providersPayload.nextCursor).not.toBeNull();
  expect(mcpPayload.nextCursor).not.toBeNull();
  await expectSystemHeading(page);
  await expect(page.getByText(SYSTEM_PROVIDER_FIRST_PAGE, { exact: true })).toBeVisible();
  await expect(page.getByRole("rowheader", { name: SYSTEM_MCP_FIRST_PAGE })).toBeVisible();

  const capabilitySection = section(page, "Capability readiness");
  await expect(capabilitySection).toContainText("never contacts a mission target");
  await expect(capabilitySection).toContainText("Not granted by these checks");
  await expect(capabilitySection.locator("tbody tr")).toHaveCount(capabilityPayload.total);
  const authorizationDetails = disclosure(capabilitySection, "Read-only authorization detail");
  await toggleEveryDisclosure(authorizationDetails, capabilityPayload.total);
  await expect(capabilitySection.locator("pre").first()).toContainText('"grantsMissionExecution": false');

  const refreshedCapabilities = capabilitySelfTestResponse(page);
  await activate(capabilitySection.getByRole("button", { name: "Refresh readiness records", exact: true }), "keyboard");
  const refreshedPayload = await assertCapabilitySnapshot(await refreshedCapabilities);
  await expect(capabilitySection.locator("tbody tr")).toHaveCount(refreshedPayload.total);

  const providersSection = section(page, "Providers");
  const providerNextResponse = systemResponse(page, "/api/v2/system/providers", (url) => url.searchParams.has("cursor"));
  await activate(providersSection.getByRole("button", { name: "Next page", exact: true }), "keyboard");
  await assertPagePayload(await providerNextResponse);
  await expect.poll(() => new URL(page.url()).searchParams.has("providerCursor")).toBe(true);
  await expect(providersSection.getByText(SYSTEM_PROVIDER_SECOND_PAGE, { exact: true })).toBeVisible();
  await expect(providersSection.getByRole("button", { name: "First page", exact: true })).toBeEnabled();
  await activate(providersSection.getByRole("button", { name: "First page", exact: true }), "pointer");
  await expect.poll(() => new URL(page.url()).searchParams.has("providerCursor")).toBe(false);
  await expect(providersSection.getByText(SYSTEM_PROVIDER_FIRST_PAGE, { exact: true })).toBeVisible();
  await expect(providersSection.getByRole("button", { name: "First page", exact: true })).toBeDisabled();

  const mcpSection = section(page, "MCP servers");
  const status = mcpSection.getByRole("combobox", { name: "Status", exact: true });
  await expect(status).toBeVisible();
  expect(await titaniumOptionLabels(status)).toEqual(MCP_STATUS_OPTIONS);
  for (const option of MCP_STATUS_OPTIONS.slice(1, -1)) {
    const filtered = systemResponse(page, "/api/v2/system/mcp", (url) => url.searchParams.get("status") === option);
    await selectTitaniumOption(status, option, option === "healthy" ? "keyboard" : "pointer");
    const payload = await assertPagePayload(await filtered);
    expect(payload.items.every((item) => item.status === option)).toBe(true);
    await expect.poll(() => new URL(page.url()).searchParams.get("status")).toBe(option);
    await expect(mcpSection.getByRole("button", { name: "Next page", exact: true })).toBeDisabled();
  }
  await selectTitaniumOption(status, "", "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.has("status")).toBe(false);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expectSystemHeading(page);
  expect((await readTitaniumOptions(
    page.getByRole("combobox", { name: "Status", exact: true }),
  )).find((option) => option.selected)?.value).toBe("");

  const reloadedMcpSection = section(page, "MCP servers");
  const mcpNextResponse = systemResponse(page, "/api/v2/system/mcp", (url) => url.searchParams.has("cursor"));
  await activate(reloadedMcpSection.getByRole("button", { name: "Next page", exact: true }), "pointer");
  await assertPagePayload(await mcpNextResponse);
  await expect.poll(() => new URL(page.url()).searchParams.has("mcpCursor")).toBe(true);
  await expect(reloadedMcpSection.getByRole("rowheader", { name: SYSTEM_MCP_SECOND_PAGE })).toBeVisible();
  await toggleEveryDisclosure(disclosure(reloadedMcpSection, "Capabilities and policy"), 1);
  await activate(reloadedMcpSection.getByRole("button", { name: "First page", exact: true }), "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.has("mcpCursor")).toBe(false);
  await expect(reloadedMcpSection.getByRole("rowheader", { name: SYSTEM_MCP_FIRST_PAGE })).toBeVisible();
  await expect(reloadedMcpSection.getByRole("button", { name: "First page", exact: true })).toBeDisabled();
  await activate(reloadedMcpSection.getByRole("button", { name: "Next page", exact: true }), "pointer");
  await expect.poll(() => new URL(page.url()).searchParams.has("mcpCursor")).toBe(true);
  const resetStaleCursor = systemResponse(page, "/api/v2/system/mcp", (url) =>
    url.searchParams.get("status") === "quarantined" && !url.searchParams.has("cursor"));
  await selectTitaniumOption(page.getByRole("combobox", { name: "Status", exact: true }), "quarantined", "pointer");
  const quarantined = await assertPagePayload(await resetStaleCursor);
  expect(quarantined.items.every((item) => item.status === "quarantined")).toBe(true);
  await expect.poll(() => new URL(page.url()).searchParams.has("mcpCursor")).toBe(false);
  await expect(reloadedMcpSection.getByRole("button", { name: "Next page", exact: true })).toBeDisabled();
  await selectTitaniumOption(page.getByRole("combobox", { name: "Status", exact: true }), "", "keyboard");
  await expect.poll(() => new URL(page.url()).searchParams.has("status")).toBe(false);
  await expect(reloadedMcpSection.getByRole("rowheader", { name: SYSTEM_MCP_FIRST_PAGE })).toBeVisible();

  const disclosures = disclosure(reloadedMcpSection, "Capabilities and policy");
  await toggleEveryDisclosure(disclosures, 25);
  await expect(reloadedMcpSection.locator("pre").first()).toContainText("[REDACTED]");
  await expect(page.locator("body")).not.toContainText(SYSTEM_FIXTURE_SECRET);

  const snapshot = readSystemFixtureSnapshot(fixture);
  expect(snapshot).toMatchObject({
    providerTurnCount: fixture.providerGroupCount,
    mcpServerCount: fixture.mcpServerCount,
    healthSnapshotCount: fixture.healthSnapshotCount,
  });
  expect(JSON.stringify(snapshot.policySetting)).toContain(SYSTEM_FIXTURE_SECRET);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.retry} explains and retries every canonical System read boundary`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(300_000);
  const retryCases = [
    {
      id: "capability",
      route: "/system/connections",
      endpoint: "/api/v2/system/capability-self-tests",
      query: undefined,
      sectionName: "Capability readiness",
      option: "Retry the failed capability readiness query",
      subject: "capability readiness snapshot",
      waitForRecovery: () => capabilitySelfTestResponse(page),
      assertRecovery: async (response: Response) => {
        const payload = await assertCapabilitySnapshot(response);
        await expect(section(page, "Capability readiness").locator("tbody tr")).toHaveCount(payload.total);
      },
    },
    {
      id: "providers",
      route: "/system/connections",
      endpoint: "/api/v2/system/providers",
      query: { limit: "25" },
      sectionName: "Providers",
      option: "Retry the failed provider history query",
      subject: "provider history projection",
      waitForRecovery: () => systemResponse(page, "/api/v2/system/providers"),
      assertRecovery: async (response: Response) => {
        await assertPagePayload(response, 25);
        await expect(section(page, "Providers").getByText(SYSTEM_PROVIDER_FIRST_PAGE, { exact: true })).toBeVisible();
      },
    },
    {
      id: "mcp",
      route: "/system/connections",
      endpoint: "/api/v2/system/mcp",
      query: { limit: "25" },
      sectionName: "MCP servers",
      option: "Retry the failed MCP registry query",
      subject: "MCP connection registry",
      waitForRecovery: () => systemResponse(page, "/api/v2/system/mcp"),
      assertRecovery: async (response: Response) => {
        await assertPagePayload(response, 25);
        await expect(section(page, "MCP servers").getByRole("rowheader", { name: SYSTEM_MCP_FIRST_PAGE })).toBeVisible();
      },
    },
    {
      id: "policies",
      route: "/system/policies",
      endpoint: "/api/v2/system/policies",
      query: { limit: "25" },
      sectionName: undefined,
      option: "Retry the failed policy projection query",
      subject: "policy projection",
      waitForRecovery: () => systemResponse(page, "/api/v2/system/policies"),
      assertRecovery: async (response: Response) => {
        await assertPagePayload(response, 25);
        await expect(disclosure(page, "Redacted policy document").first()).toBeVisible();
      },
    },
    {
      id: "health",
      route: "/system/settings",
      endpoint: "/api/v2/system/health",
      query: { limit: "50" },
      sectionName: "System health",
      option: "Retry the failed system health query",
      subject: "system health projection",
      waitForRecovery: () => systemResponse(page, "/api/v2/system/health"),
      assertRecovery: async (response: Response) => {
        await assertPagePayload(response, fixture.healthSnapshotCount);
        await expect(section(page, "System health").getByText(SYSTEM_HEALTH_COMPONENT, { exact: true })).toBeVisible();
      },
    },
    {
      id: "settings-policies",
      route: "/system/settings",
      endpoint: "/api/v2/system/policies",
      query: { limit: "100" },
      sectionName: "Policy projection inventory",
      option: "Retry the failed settings policy inventory query",
      subject: "settings policy inventory",
      waitForRecovery: () => systemResponse(page, "/api/v2/system/policies", (url) => url.searchParams.get("limit") === "100"),
      assertRecovery: async (response: Response) => {
        const payload = await assertPagePayload(response);
        await expect(section(page, "Policy projection inventory").getByText(
          `${payload.items.length} policy projections are currently visible to this operator.`,
          { exact: true },
        )).toBeVisible();
      },
    },
  ] as const;

  let navigationCount = 0;
  for (const retryCase of retryCases) {
    browserAudit.expectHttpResponse(page, {
      id: `system.${retryCase.id}.initial-unavailable`,
      transport: "browser",
      method: "GET",
      pathname: retryCase.endpoint,
      query: { ...(retryCase.query ?? {}) },
      status: 503,
      occurrences: 2,
      reason: `Exercise the exact ${retryCase.subject} retry boundary once with pointer input and once with keyboard input.`,
    });
    for (const modality of ["pointer", "keyboard"] as const) {
      const traceId = `trace-system-${retryCase.id}-${modality}`;
      const humanMessage = `The ${retryCase.subject} could not read its isolated canonical state.`;
      const remediation = `Retry after the local ${retryCase.subject} is available.`;
      let failedOnce = false;
      const routePattern = `**${retryCase.endpoint}*`;
      await page.route(routePattern, async (route) => {
        if (!failedOnce) {
          failedOnce = true;
          await route.fulfill({
            status: 503,
            contentType: "application/json",
            body: JSON.stringify({
              error: {
                code: `system_fixture_${retryCase.id.replaceAll("-", "_")}_unavailable`,
                message: `System fixture ${retryCase.subject} unavailable`,
                humanMessage,
                retryable: true,
                category: "dependency",
                remediation,
                traceId,
                timestamp: "2199-07-16T12:30:00.000Z",
              },
            }),
          });
          return;
        }
        await route.continue();
      });
      try {
        const navigate = () => page.goto(retryCase.route, { waitUntil: "domcontentloaded" });
        if (navigationCount === 0) await navigate();
        else await browserAudit.withExpectedDocumentNavigationTeardown(page, navigate);
        navigationCount += 1;
        const scope = retryCase.sectionName ? section(page, retryCase.sectionName) : page;
        await expect(scope.getByText("Live data is unavailable", { exact: true })).toBeVisible();
        await expect(scope.getByText(humanMessage, { exact: true })).toBeVisible();
        await expect(scope.getByText(remediation, { exact: true })).toBeVisible();
        await expect(scope.getByText(`Trace ${traceId}`, { exact: true })).toBeVisible();

        const recovered = retryCase.waitForRecovery();
        const retry = scope.getByRole("button", { name: "Try again", exact: true });
        await interactionActivation.activate(
          systemRetryReceipt(retryCase.option, modality),
          () => activate(retry, modality),
        );
        await retryCase.assertRecovery(await recovered);
        await expect(scope.getByText("Live data is unavailable", { exact: true })).toHaveCount(0);
      } finally {
        await page.unroute(routePattern);
      }
    }
  }
});

test(`${TEST_IDS.policies} exercises every visible policy disclosure and both cursor controls`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const policiesResponse = systemResponse(page, "/api/v2/system/policies");
  await page.goto("/system/policies", { waitUntil: "domcontentloaded" });
  let payload = await assertPagePayload(await policiesResponse, 25);
  expect(payload.nextCursor).not.toBeNull();
  await expectSystemHeading(page);
  const firstPageLabel = payload.items[0]?.label;
  expect(typeof firstPageLabel).toBe("string");

  const requiredFixtureLabels = new Set([SYSTEM_MCP_SECOND_PAGE, SYSTEM_POLICY_SETTING]);
  const observedFixtureLabels = new Set<string>();
  const inspectCurrentPage = async (): Promise<void> => {
    const labels = payload.items.flatMap((item) => typeof item.label === "string" ? [item.label] : []);
    for (const label of labels) {
      if (!requiredFixtureLabels.has(label)) continue;
      observedFixtureLabels.add(label);
      await expect(page.getByRole("heading", { name: label, exact: true })).toBeVisible();
    }
    await toggleEveryDisclosure(disclosure(page, "Redacted policy document"), payload.items.length);
    if (labels.includes(SYSTEM_POLICY_SETTING)) {
      const redactedSetting = page.getByRole("heading", { name: SYSTEM_POLICY_SETTING, exact: true })
        .locator("xpath=ancestor::section[contains(concat(' ', normalize-space(@class), ' '), ' os-card ')][1]");
      await expect(redactedSetting.locator("pre")).toContainText("[REDACTED]");
      await expect(redactedSetting).not.toContainText(SYSTEM_FIXTURE_SECRET);
    }
    if (labels.includes(SYSTEM_MCP_SECOND_PAGE)) {
      const redactedMcp = page.getByRole("heading", { name: SYSTEM_MCP_SECOND_PAGE, exact: true })
        .locator("xpath=ancestor::section[contains(concat(' ', normalize-space(@class), ' '), ' os-card ')][1]");
      await expect(redactedMcp.locator("pre")).toContainText("apiToken");
      await expect(redactedMcp.locator("pre")).toContainText("[REDACTED]");
      await expect(redactedMcp).not.toContainText(SYSTEM_FIXTURE_SECRET);
    }
  };

  await inspectCurrentPage();
  await expect(page.locator("body")).not.toContainText(SYSTEM_FIXTURE_SECRET);

  // Policy rows are a shared canonical projection of agents, MCP servers, and
  // settings. Accumulated release fixtures and runtime projection timestamps
  // may legitimately move a fixture across cursor pages, so traverse the real
  // cursor chain instead of assuming both records are always on page two.
  for (let pageNumber = 2; observedFixtureLabels.size < requiredFixtureLabels.size; pageNumber += 1) {
    expect(payload.nextCursor, `Policy fixture records were not found by page ${pageNumber - 1}`).not.toBeNull();
    expect(pageNumber, "Policy cursor traversal exceeded its bounded fixture allowance").toBeLessThanOrEqual(12);
    const next = systemResponse(page, "/api/v2/system/policies", (url) => url.searchParams.has("cursor"));
    await activate(page.getByRole("button", { name: "Next page", exact: true }), pageNumber === 2 ? "keyboard" : "pointer");
    payload = await assertPagePayload(await next);
    await expect.poll(() => new URL(page.url()).searchParams.has("cursor")).toBe(true);
    await expect(page.getByRole("button", { name: "First page", exact: true })).toBeEnabled();
    await inspectCurrentPage();
  }
  expect([...observedFixtureLabels].sort()).toEqual([...requiredFixtureLabels].sort());
  await activate(page.getByRole("button", { name: "First page", exact: true }), "pointer");
  await expect.poll(() => new URL(page.url()).searchParams.has("cursor")).toBe(false);
  await expect(page.getByRole("button", { name: "First page", exact: true })).toBeDisabled();
  await expect(page.getByRole("heading", { name: firstPageLabel as string, exact: true })).toBeVisible();
  await strictAudit(audit, testInfo);
});

async function openContractDocument(
  page: Page,
  audit: BrowserAudit,
  interactionActivation: InteractionActivationRecorder,
  manifestEntryId: "system.settings.openapi-contract" | "system.settings.event-contract",
  option: string,
  linkName: "Open API contract" | "Open event contract",
  expectedPath: "/api/v2/openapi.json" | "/api/v2/contracts/events",
  input: "keyboard" | "pointer",
): Promise<void> {
  const link = page.getByRole("link", { name: linkName, exact: true });
  await expect(link).toHaveAttribute("href", expectedPath);
  await expect(link).toHaveAttribute("target", "_blank");
  const response = await audit.request(page.request, { method: "GET", url: expectedPath });
  const contractBody = await response.text();
  expect(response.status(), contractBody).toBe(200);
  expect(response.headers()["content-type"]).toContain("application/json");
  await page.context().route(`**${expectedPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/plain; charset=utf-8",
    body: contractBody,
  }));
  try {
    audit.expectPopup(expectedPath);
    const popupPromise = page.waitForEvent("popup");
    await interactionActivation.activate(
      settingsReceipt(manifestEntryId, option, input),
      () => activate(link, input),
    );
    const popup = await popupPromise;
    await popup.waitForLoadState("domcontentloaded");
    expect(new URL(popup.url()).pathname).toBe(expectedPath);
    await expect(popup.locator("body")).not.toBeEmpty();
    await popup.close();
  } finally {
    await page.context().unroute(`**${expectedPath}`);
  }
}

test(`${TEST_IDS.settings} opens both live contracts and exercises every visible health-metric disclosure`, async ({
  page,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const healthResponse = systemResponse(page, "/api/v2/system/health");
  const policiesResponse = systemResponse(page, "/api/v2/system/policies", (url) => url.searchParams.get("limit") === "100");
  await page.goto("/system/settings", { waitUntil: "domcontentloaded" });
  const health = await assertPagePayload(await healthResponse, fixture.healthSnapshotCount);
  await assertPagePayload(await policiesResponse);
  expect(health.items).toContainEqual(expect.objectContaining({ componentId: SYSTEM_HEALTH_COMPONENT, status: "degraded" }));
  await expectSystemHeading(page);
  await expect(page.getByRole("heading", {
    name: "Versioned configuration boundaries",
    exact: true,
  })).toBeVisible();

  for (const modality of ["pointer", "keyboard"] as const) {
    await openContractDocument(
      page,
      audit,
      interactionActivation,
      "system.settings.openapi-contract",
      "Open /api/v2/openapi.json",
      "Open API contract",
      "/api/v2/openapi.json",
      modality,
    );
    await openContractDocument(
      page,
      audit,
      interactionActivation,
      "system.settings.event-contract",
      "Open /api/v2/contracts/events",
      "Open event contract",
      "/api/v2/contracts/events",
      modality,
    );
  }

  const metrics = disclosure(page, "Metrics");
  const firstMetric = metrics.first();
  const firstMetricDetails = firstMetric.locator("xpath=..");
  for (const modality of ["pointer", "keyboard"] as const) {
    expect(await firstMetricDetails.evaluate((element) => (element as HTMLDetailsElement).open)).toBe(false);
    await interactionActivation.activate(
      settingsReceipt("system.settings.metrics", "Open metrics", modality),
      () => activate(firstMetric, modality),
    );
    await expect(firstMetricDetails).toHaveJSProperty("open", true);
    await interactionActivation.activate(
      settingsReceipt("system.settings.metrics", "Close metrics", modality),
      () => activate(firstMetric, modality),
    );
    await expect(firstMetricDetails).toHaveJSProperty("open", false);
  }
  await toggleEveryDisclosure(metrics, fixture.healthSnapshotCount);
  await expect(page.locator("pre").filter({ hasText: "connectedSubscribers" }).first()).toContainText("[REDACTED]");
  await expect(page.locator("body")).not.toContainText(SYSTEM_FIXTURE_SECRET);
  await expect(page.getByText(/policy projections are currently visible to this operator\./u)).toBeVisible();
  await strictAudit(audit, testInfo);
});

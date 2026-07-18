import { expect, test, type Locator, type Page, type Response, type TestInfo } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
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
  const aliasProviders = systemResponse(page, "/api/v2/system/providers");
  const aliasMcp = systemResponse(page, "/api/v2/system/mcp");
  await page.goto("/system", { waitUntil: "domcontentloaded" });
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
  await aliasStatus.selectOption("healthy");
  await assertPagePayload(await aliasHealthy);
  await aliasStatus.selectOption("");
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
  const providersResponse = systemResponse(page, "/api/v2/system/providers");
  const mcpResponse = systemResponse(page, "/api/v2/system/mcp");
  await page.goto("/system/connections", { waitUntil: "domcontentloaded" });
  const providersPayload = await assertPagePayload(await providersResponse, 25);
  const mcpPayload = await assertPagePayload(await mcpResponse, 25);
  expect(providersPayload.nextCursor).not.toBeNull();
  expect(mcpPayload.nextCursor).not.toBeNull();
  await expectSystemHeading(page);
  await expect(page.getByText(SYSTEM_PROVIDER_FIRST_PAGE, { exact: true })).toBeVisible();
  await expect(page.getByRole("rowheader", { name: SYSTEM_MCP_FIRST_PAGE })).toBeVisible();

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
  expect(await status.locator("option").allTextContents()).toEqual(MCP_STATUS_OPTIONS);
  for (const option of MCP_STATUS_OPTIONS.slice(1, -1)) {
    const filtered = systemResponse(page, "/api/v2/system/mcp", (url) => url.searchParams.get("status") === option);
    await status.selectOption(option);
    const payload = await assertPagePayload(await filtered);
    expect(payload.items.every((item) => item.status === option)).toBe(true);
    await expect.poll(() => new URL(page.url()).searchParams.get("status")).toBe(option);
    await expect(mcpSection.getByRole("button", { name: "Next page", exact: true })).toBeDisabled();
  }
  await status.selectOption("");
  await expect.poll(() => new URL(page.url()).searchParams.has("status")).toBe(false);
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  await expectSystemHeading(page);
  await expect(page.getByRole("combobox", { name: "Status", exact: true })).toHaveValue("");

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
  await page.getByRole("combobox", { name: "Status", exact: true }).selectOption("quarantined");
  const quarantined = await assertPagePayload(await resetStaleCursor);
  expect(quarantined.items.every((item) => item.status === "quarantined")).toBe(true);
  await expect.poll(() => new URL(page.url()).searchParams.has("mcpCursor")).toBe(false);
  await expect(reloadedMcpSection.getByRole("button", { name: "Next page", exact: true })).toBeDisabled();
  await page.getByRole("combobox", { name: "Status", exact: true }).selectOption("");
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

test(`${TEST_IDS.retry} explains one MCP read failure and retries the mounted endpoint`, async ({ page, browserAudit }, testInfo) => {
  test.setTimeout(60_000);
  browserAudit.expectHttpResponse(page, {
    id: "system.mcp.initial-unavailable",
    transport: "browser",
    method: "GET",
    pathname: "/api/v2/system/mcp",
    query: { limit: "25" },
    status: 503,
    occurrences: 1,
    reason: "Exercise the exact MCP-registry retry state once.",
  });
  let failedOnce = false;
  await page.route("**/api/v2/system/mcp?*", async (route) => {
    if (!failedOnce) {
      failedOnce = true;
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({
          error: {
            code: "system_fixture_mcp_unavailable",
            message: "System fixture MCP projection unavailable",
            humanMessage: "The MCP connection registry could not read its isolated canonical state.",
            retryable: true,
            category: "dependency",
            remediation: "Retry after the local MCP registry projection is available.",
            traceId: "trace-system-mcp-retry",
            timestamp: "2199-07-16T12:30:00.000Z",
          },
        }),
      });
      return;
    }
    await route.continue();
  });
  await page.goto("/system/connections", { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Live data is unavailable", { exact: true })).toBeVisible();
  await expect(page.getByText("The MCP connection registry could not read its isolated canonical state.", { exact: true })).toBeVisible();
  await expect(page.getByText("Retry after the local MCP registry projection is available.", { exact: true })).toBeVisible();
  await expect(page.getByText("Trace trace-system-mcp-retry", { exact: true })).toBeVisible();

  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const recovered = systemResponse(page, "/api/v2/system/mcp");
  await activate(page.getByRole("button", { name: "Try again", exact: true }), "keyboard");
  await assertPagePayload(await recovered, 25);
  await expect(page.getByRole("rowheader", { name: SYSTEM_MCP_FIRST_PAGE })).toBeVisible();
  await page.unroute("**/api/v2/system/mcp?*");
  await strictAudit(audit, testInfo);
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
    await activate(link, input);
    const popup = await popupPromise;
    await popup.waitForLoadState("domcontentloaded");
    expect(new URL(popup.url()).pathname).toBe(expectedPath);
    await expect(popup.locator("body")).not.toBeEmpty();
    await popup.close();
  } finally {
    await page.context().unroute(`**${expectedPath}`);
  }
}

test(`${TEST_IDS.settings} opens both live contracts and exercises every visible health-metric disclosure`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const healthResponse = systemResponse(page, "/api/v2/system/health");
  const policiesResponse = systemResponse(page, "/api/v2/system/policies", (url) => url.searchParams.get("limit") === "100");
  await page.goto("/system/settings", { waitUntil: "domcontentloaded" });
  const health = await assertPagePayload(await healthResponse, fixture.healthSnapshotCount);
  await assertPagePayload(await policiesResponse);
  expect(health.items).toContainEqual(expect.objectContaining({ componentId: SYSTEM_HEALTH_COMPONENT, status: "degraded" }));
  await expectSystemHeading(page);
  await expect(page.getByText("Configuration is read-only in this API contract", { exact: true })).toBeVisible();

  await openContractDocument(page, audit, "Open API contract", "/api/v2/openapi.json", "keyboard");
  await openContractDocument(page, audit, "Open event contract", "/api/v2/contracts/events", "pointer");

  const metrics = disclosure(page, "Metrics");
  await toggleEveryDisclosure(metrics, fixture.healthSnapshotCount);
  await expect(page.locator("pre").filter({ hasText: "connectedSubscribers" }).first()).toContainText("[REDACTED]");
  await expect(page.locator("body")).not.toContainText(SYSTEM_FIXTURE_SECRET);
  await expect(page.getByText(/policy projections are currently visible to this operator\./u)).toBeVisible();
  await strictAudit(audit, testInfo);
});

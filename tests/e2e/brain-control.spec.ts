import {
  expect,
  test,
  type ConsoleMessage,
  type Locator,
  type Page,
  type Request,
  type Response,
  type TestInfo,
} from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import {
  acquireBrainControlFixtureLock,
  BRAIN_CONTROL_FIXTURE_SECRET,
  BRAIN_CONTROL_START_POLICY,
  createBrainControlFixture,
  readBrainControlFixtureSnapshot,
  releaseBrainControlFixtureLock,
  type BrainControlFixture,
} from "./support/brainControlFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_IDS = {
  controls: "e2e.brain-control.all-controls-save-reload",
  conflict: "e2e.brain-control.version-conflict-retry",
  invariants: "e2e.brain-control.locked-invariants",
} as const;

const CONTROL_PATH = "/api/v2/brain/control";
const BRAIN_TABS = [
  { name: "Home", href: "/brain", heading: "Second Brain" },
  { name: "Graph", href: "/brain/graph", heading: "Memory Graph" },
  { name: "Memory Inbox", href: "/brain/inbox", heading: "Memory Inbox" },
  { name: "Controls", href: "/brain/control", heading: "Memory Control Center" },
  { name: "Obsidian Vault", href: "/brain/vault", heading: "Obsidian Vault" },
] as const;
const PREFERENCE_OPTIONS = [
  "Candidate only — always review",
  "Disabled",
] as const;
const RETENTION_OPTIONS = ["30 days", "90 days", "1 year", "3 years", "No automatic expiry"] as const;
const SYNC_OPTIONS = ["Disabled", "Confirmed nodes", "Confirmed and verified nodes"] as const;

interface EditableControlPolicy {
  readonly enabled: boolean;
  readonly personalPreferencePolicy: "candidate_only" | "disabled";
  readonly operationalMemoryEnabled: boolean;
  readonly engagementIsolation: boolean;
  readonly defaultRetentionDays: number | null;
  readonly autonomousUse: boolean;
  readonly guidedUse: boolean;
  readonly obsidianSyncScope: "disabled" | "confirmed" | "confirmed_and_verified";
  readonly secretsNeverRetained: boolean;
}

interface ControlPolicy extends EditableControlPolicy {
  readonly version: number;
  readonly updatedBy: string;
  readonly updatedAt: string;
}

interface ControlPayload {
  readonly schemaVersion: string;
  readonly policy: ControlPolicy;
}

interface ErrorPayload {
  readonly error: {
    readonly code: string;
    readonly message: string;
    readonly humanMessage: string;
    readonly retryable: boolean;
    readonly category: string;
    readonly remediation?: string;
    readonly traceId: string;
    readonly timestamp: string;
  };
}

interface BrowserPutResult {
  readonly status: number;
  readonly body: ControlPayload | ErrorPayload;
  readonly rawBody: string;
}

let lockDirectory = "";
let fixture: BrainControlFixture;

test.describe.configure({ mode: "serial" });
test.beforeAll(async ({}, testInfo) => {
  testInfo.setTimeout(330_000);
  lockDirectory = await acquireBrainControlFixtureLock();
});
test.beforeEach(({}, testInfo) => {
  fixture = createBrainControlFixture(
    canonicalFixtureNamespace(testInfo, `brain-control-${testInfo.title}`),
    lockDirectory,
  );
});
test.afterAll(async () => {
  if (lockDirectory) await releaseBrainControlFixtureLock(lockDirectory);
});

function pathname(url: string): string {
  return new URL(url).pathname;
}

function controlResponse(page: Page, method: "GET" | "PUT", status = 200): Promise<Response> {
  return page.waitForResponse((response) => (
    response.request().method() === method
    && pathname(response.url()) === CONTROL_PATH
    && response.status() === status
  ));
}

function controlRequest(page: Page, expectedVersion?: number): Promise<Request> {
  return page.waitForRequest((request) => {
    if (request.method() !== "PUT" || pathname(request.url()) !== CONTROL_PATH) return false;
    if (expectedVersion === undefined) return true;
    try {
      return (request.postDataJSON() as { expectedVersion?: unknown }).expectedVersion === expectedVersion;
    } catch {
      return false;
    }
  });
}

function brainTabReads(page: Page, href: string): Promise<Response>[] {
  const paths = href === "/brain"
    ? ["/api/v2/brain/summary", "/api/v2/brain/nodes"]
    : href === "/brain/graph"
      ? ["/api/v2/brain/graph"]
      : href === "/brain/inbox"
        ? ["/api/v2/brain/candidates"]
        : href === "/brain/vault"
          ? ["/api/v2/brain/vault"]
          : [];
  return paths.map((path) => page.waitForResponse((response) => (
    response.request().method() === "GET"
    && new URL(response.url()).pathname === path
  )));
}

async function settleBrainTab(page: Page, href: string): Promise<void> {
  if (href !== "/brain/graph") return;
  const canvas = page.getByRole("application", { name: /^Memory graph with /u });
  // The canonical response may legitimately produce either an empty state or
  // a worker-backed canvas. Wait for that branch to render before deciding;
  // checking count immediately can race the lazy route commit.
  await expect(page.locator("canvas[role='application'][aria-label^='Memory graph with'], .brain-empty").first())
    .toBeVisible();
  if (!await canvas.isVisible()) return;
  // aria-busy becomes false only after the lazy layout worker returns its
  // first computed projection (or the explicit local fallback completes).
  // This state boundary works for populated and clustered graphs without
  // assuming a development-only worker URL.
  await expect(canvas).toHaveAttribute("aria-busy", "false");
  await expect(page.getByText("Memory graph layout ready", { exact: true })).toBeVisible();
}

function editablePolicy(policy: ControlPolicy): EditableControlPolicy {
  return {
    enabled: policy.enabled,
    personalPreferencePolicy: policy.personalPreferencePolicy,
    operationalMemoryEnabled: policy.operationalMemoryEnabled,
    engagementIsolation: policy.engagementIsolation,
    defaultRetentionDays: policy.defaultRetentionDays,
    autonomousUse: policy.autonomousUse,
    guidedUse: policy.guidedUse,
    obsidianSyncScope: policy.obsidianSyncScope,
    secretsNeverRetained: policy.secretsNeverRetained,
  };
}

async function payload(response: Response): Promise<ControlPayload> {
  const rawBody = await response.text();
  expect(response.status(), rawBody).toBe(200);
  const result = JSON.parse(rawBody) as ControlPayload;
  expect(result.schemaVersion).toBe("2.4");
  expect(JSON.stringify(result)).not.toContain(BRAIN_CONTROL_FIXTURE_SECRET);
  return result;
}

async function activate(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await control.press("Enter");
  } else {
    await control.click();
  }
}

async function toggle(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await control.press("Space");
  } else {
    await control.click();
  }
}

async function expectHeading(page: Page, name: string): Promise<void> {
  await expect(page.getByRole("heading", { level: 1, name, exact: true })).toBeVisible();
  await expect(page.getByText("Command surface not found", { exact: true })).toHaveCount(0);
}

async function strictAudit(audit: BrowserAudit, testInfo: TestInfo): Promise<void> {
  expect(audit.unexpected, "Brain Control emitted an unexpected browser, console, network, or server failure").toEqual([]);
  expect(audit.degradedApi, "Brain Control requires the mounted V2 API for all canonical reads and writes").toEqual([]);
  await audit.assertClean(testInfo);
}

function captureRuntimeErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  page.on("console", (message: ConsoleMessage) => {
    if (message.type() === "error") errors.push(`console: ${message.text()}`);
  });
  return errors;
}

async function browserPutControl(
  page: Page,
  expectedVersion: number,
  policy: EditableControlPolicy,
  idempotencyKey: string,
): Promise<BrowserPutResult> {
  return page.evaluate(async (input) => {
    const encoded = document.cookie
      .split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith("ti_scale_csrf="))
      ?.slice("ti_scale_csrf=".length);
    if (!encoded) throw new Error("The authenticated browser context has no V2 CSRF token");
    const response = await fetch("/api/v2/brain/control", {
      method: "PUT",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": input.idempotencyKey,
        "X-Ti-Scale-CSRF": decodeURIComponent(encoded),
      },
      body: JSON.stringify({ expectedVersion: input.expectedVersion, policy: input.policy }),
    });
    const rawBody = await response.text();
    return {
      status: response.status,
      body: JSON.parse(rawBody) as ControlPayload | ErrorPayload,
      rawBody,
    };
  }, { expectedVersion, policy, idempotencyKey });
}

function assertCanonicalStoredKeys(value: Record<string, unknown>): void {
  expect(Object.keys(value).sort()).toEqual(Object.keys(BRAIN_CONTROL_START_POLICY).sort());
  expect(JSON.stringify(value)).not.toContain(BRAIN_CONTROL_FIXTURE_SECRET);
}

async function expectNoFixtureSecretLeakage(page: Page): Promise<void> {
  await expect(page.locator("body")).not.toContainText(BRAIN_CONTROL_FIXTURE_SECRET);
  const browserProjection = await page.evaluate(() => ({
    html: document.documentElement.outerHTML,
    cookie: document.cookie,
    localStorage: Object.fromEntries(Object.entries(localStorage)),
    sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
  }));
  expect(JSON.stringify(browserProjection)).not.toContain(BRAIN_CONTROL_FIXTURE_SECRET);
}

test(`${TEST_IDS.controls} reads, navigates, exercises every option, saves, and reloads canonical controls`, async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const seeded = readBrainControlFixtureSnapshot(fixture);
  expect(seeded.version).toBe(fixture.seededVersion);
  expect(seeded.storedValue.fixtureAuthenticationToken).toBe(BRAIN_CONTROL_FIXTURE_SECRET);

  const initialResponse = controlResponse(page, "GET");
  await page.goto("/brain/control", { waitUntil: "domcontentloaded" });
  const initial = await payload(await initialResponse);
  expect(initial.policy).toMatchObject({ ...BRAIN_CONTROL_START_POLICY, version: fixture.seededVersion });
  await expectHeading(page, "Memory Control Center");
  await expectNoFixtureSecretLeakage(page);

  const navigation = page.getByRole("navigation", { name: "Second Brain", exact: true });
  for (const tab of BRAIN_TABS) {
    await expect(navigation.getByRole("link", { name: tab.name, exact: true })).toHaveAttribute("href", tab.href);
  }
  await expect(navigation.getByRole("link", { name: "Controls", exact: true })).toHaveClass(/is-active/u);
  for (const [index, tab] of BRAIN_TABS.filter((tab) => tab.name !== "Controls").entries()) {
    const canonicalReads = brainTabReads(page, tab.href);
    await activate(navigation.getByRole("link", { name: tab.name, exact: true }), index % 2 === 0 ? "pointer" : "keyboard");
    for (const canonicalRead of canonicalReads) expect((await canonicalRead).status()).toBe(200);
    await expect.poll(() => new URL(page.url()).pathname).toBe(tab.href);
    await expectHeading(page, tab.heading);
    await settleBrainTab(page, tab.href);
    await page.goBack({ waitUntil: "domcontentloaded" });
    await expectHeading(page, "Memory Control Center");
  }
  const exportLink = page.getByRole("link", { name: "Export or sync", exact: true });
  await expect(exportLink).toHaveAttribute("href", "/brain/vault");
  const exportVaultRead = page.waitForResponse((response) => response.request().method() === "GET"
    && new URL(response.url()).pathname === "/api/v2/brain/vault");
  await activate(exportLink, "pointer");
  expect((await exportVaultRead).status()).toBe(200);
  await expectHeading(page, "Obsidian Vault");
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expectHeading(page, "Memory Control Center");

  const enabled = page.getByRole("checkbox", { name: "Enable memory retention and retrieval", exact: true });
  const operational = page.getByRole("checkbox", { name: "Retain evidence-backed operational knowledge", exact: true });
  const autonomous = page.getByRole("checkbox", { name: "Allow permitted confirmed memory in Autonomous runs", exact: true });
  const guided = page.getByRole("checkbox", { name: "Allow confirmed preferences and knowledge in Guided missions", exact: true });
  const nestedControls = [
    page.getByRole("combobox", { name: "Personal preference learning", exact: true }),
    operational,
    page.getByRole("combobox", { name: "Default retention", exact: true }),
    autonomous,
    guided,
    page.getByRole("combobox", { name: "Synchronization scope", exact: true }),
  ];
  await toggle(enabled, "keyboard");
  await expect(enabled).not.toBeChecked();
  await expect(page.getByRole("heading", { level: 2, name: "Second Brain is disabled", exact: true })).toBeVisible();
  for (const control of nestedControls) await expect(control).toBeDisabled();
  await toggle(enabled, "pointer");
  await expect(enabled).toBeChecked();
  for (const control of nestedControls) await expect(control).toBeEnabled();

  await toggle(operational, "pointer");
  await expect(operational).not.toBeChecked();
  await toggle(operational, "keyboard");
  await expect(operational).toBeChecked();
  await toggle(autonomous, "keyboard");
  await expect(autonomous).not.toBeChecked();
  await toggle(autonomous, "pointer");
  await expect(autonomous).toBeChecked();
  await toggle(guided, "pointer");
  await expect(guided).not.toBeChecked();
  await toggle(guided, "keyboard");
  await expect(guided).toBeChecked();

  const preference = page.getByRole("combobox", { name: "Personal preference learning", exact: true });
  expect(await preference.locator("option").allTextContents()).toEqual(PREFERENCE_OPTIONS);
  await preference.selectOption("disabled");
  await expect(preference).toHaveValue("disabled");
  await preference.selectOption("candidate_only");
  await expect(preference).toHaveValue("candidate_only");

  const retention = page.getByRole("combobox", { name: "Default retention", exact: true });
  expect(await retention.locator("option").allTextContents()).toEqual(RETENTION_OPTIONS);
  for (const value of ["30", "90", "365", "1095", "never"] as const) {
    await retention.selectOption(value);
    await expect(retention).toHaveValue(value);
  }
  await retention.selectOption("90");

  const sync = page.getByRole("combobox", { name: "Synchronization scope", exact: true });
  expect(await sync.locator("option").allTextContents()).toEqual(SYNC_OPTIONS);
  for (const value of ["disabled", "confirmed", "confirmed_and_verified"] as const) {
    await sync.selectOption(value);
    await expect(sync).toHaveValue(value);
  }
  await sync.selectOption("confirmed");

  const strictIsolation = page.getByRole("checkbox", { name: "Strict engagement isolation", exact: true });
  const secretExclusion = page.getByRole("checkbox", {
    name: "Never retain credentials, tokens, private keys, or authentication material",
    exact: true,
  });
  await expect(strictIsolation).toBeChecked();
  await expect(strictIsolation).toBeDisabled();
  await expect(secretExclusion).toBeChecked();
  await expect(secretExclusion).toBeDisabled();

  const saveRequestPromise = controlRequest(page);
  const saveResponsePromise = controlResponse(page, "PUT");
  await activate(page.getByRole("button", { name: "Save memory controls", exact: true }), "keyboard");
  const saveRequest = await saveRequestPromise;
  const requestBody = saveRequest.postDataJSON() as { expectedVersion: number; policy: EditableControlPolicy };
  expect(requestBody).toEqual({
    expectedVersion: fixture.seededVersion,
    policy: {
      ...BRAIN_CONTROL_START_POLICY,
      defaultRetentionDays: 90,
      obsidianSyncScope: "confirmed",
    },
  });
  expect(saveRequest.headers()["idempotency-key"]).toBeTruthy();
  expect(saveRequest.headers()["x-ti-scale-csrf"]).toBeTruthy();
  expect(JSON.stringify(requestBody)).not.toContain(BRAIN_CONTROL_FIXTURE_SECRET);
  const saved = await payload(await saveResponsePromise);
  expect(saved.policy).toMatchObject({
    version: fixture.seededVersion + 1,
    defaultRetentionDays: 90,
    obsidianSyncScope: "confirmed",
    engagementIsolation: true,
    secretsNeverRetained: true,
  });
  await expect(page.getByText("Controls saved", { exact: true })).toBeVisible();
  await expect(page.getByText(`Policy version ${saved.policy.version}`, { exact: true })).toBeVisible();

  const snapshot = readBrainControlFixtureSnapshot(fixture);
  expect(snapshot.version).toBe(saved.policy.version);
  expect(snapshot.updatedBy).toBe("e2e-local-operator");
  assertCanonicalStoredKeys(snapshot.storedValue);
  expect(snapshot.storedValue).toEqual(editablePolicy(saved.policy));
  expect(snapshot.audits).toHaveLength(1);
  expect(snapshot.audits[0]).toMatchObject({
    action: "memory.control.updated",
    actorId: "e2e-local-operator",
    details: {
      previousVersion: fixture.seededVersion,
      version: saved.policy.version,
      changedFields: ["defaultRetentionDays", "obsidianSyncScope"],
    },
  });
  expect(snapshot.audits[0]!.recordHash).toMatch(/^[a-f0-9]{64}$/u);

  const reloadResponse = controlResponse(page, "GET");
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  const reloaded = await payload(await reloadResponse);
  expect(reloaded.policy).toEqual(saved.policy);
  await expect(retention).toHaveValue("90");
  await expect(sync).toHaveValue("confirmed");
  await expect(strictIsolation).toBeChecked();
  await expect(secretExclusion).toBeChecked();
  await expectNoFixtureSecretLeakage(page);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.conflict} explains a real version conflict and retries against the refreshed canonical policy`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: [{
      id: "brain-control.version-conflict",
      transport: "browser",
      method: "PUT",
      pathname: "/api/v2/brain/control",
      query: {},
      status: 409,
      occurrences: 1,
      reason: "Prove a stale policy version fails closed before the represented retry.",
    }],
  });
  const initialResponse = controlResponse(page, "GET");
  await page.goto("/brain/control", { waitUntil: "domcontentloaded" });
  const initial = await payload(await initialResponse);
  await expectHeading(page, "Memory Control Center");
  await page.getByRole("combobox", { name: "Default retention", exact: true }).selectOption("30");

  const concurrent = await browserPutControl(
    page,
    initial.policy.version,
    { ...editablePolicy(initial.policy), defaultRetentionDays: 90 },
    `brain-control-concurrent-${fixture.namespace}`,
  );
  expect(concurrent.status, concurrent.rawBody).toBe(200);
  expect(concurrent.rawBody).not.toContain(BRAIN_CONTROL_FIXTURE_SECRET);
  const concurrentPayload = concurrent.body as ControlPayload;
  expect(concurrentPayload.policy).toMatchObject({
    version: initial.policy.version + 1,
    defaultRetentionDays: 90,
  });

  const conflictResponsePromise = controlResponse(page, "PUT", 409);
  await activate(page.getByRole("button", { name: "Save memory controls", exact: true }), "pointer");
  const conflictResponse = await conflictResponsePromise;
  const conflictRaw = await conflictResponse.text();
  expect(conflictRaw).not.toContain(BRAIN_CONTROL_FIXTURE_SECRET);
  const conflict = JSON.parse(conflictRaw) as ErrorPayload;
  expect(conflict.error).toMatchObject({
    code: "brain_state_conflict",
    message: "The Second Brain resource changed or is no longer actionable",
    humanMessage: "The Second Brain resource changed or is no longer actionable",
    retryable: false,
    category: "conflict",
    remediation: "Refresh the record and retry against its current version.",
  });
  expect(conflict.error.traceId).toBeTruthy();
  await expect(page.getByRole("alert")).toContainText("Memory controls were not saved");
  await expect(page.getByRole("alert")).toContainText("The Second Brain resource changed or is no longer actionable");
  await expect(page.getByRole("alert")).toContainText("Refresh the record and retry against its current version.");
  await expect(page.getByRole("alert")).toContainText(`Trace ${conflict.error.traceId}`);

  const runtimeErrors = captureRuntimeErrors(page);
  const refreshPromise = controlResponse(page, "GET");
  const retryRequestPromise = controlRequest(page, concurrentPayload.policy.version);
  const retryResponsePromise = controlResponse(page, "PUT");
  await activate(page.getByRole("button", { name: "Try again", exact: true }), "keyboard");
  const refreshed = await payload(await refreshPromise);
  expect(refreshed.policy.version).toBe(concurrentPayload.policy.version);
  const retryRequest = await retryRequestPromise;
  expect(retryRequest.postDataJSON()).toEqual({
    expectedVersion: concurrentPayload.policy.version,
    policy: { ...BRAIN_CONTROL_START_POLICY, defaultRetentionDays: 30 },
  });
  const retried = await payload(await retryResponsePromise);
  expect(retried.policy).toMatchObject({
    version: concurrentPayload.policy.version + 1,
    defaultRetentionDays: 30,
  });
  await expect(page.getByText("Controls saved", { exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);

  const snapshot = readBrainControlFixtureSnapshot(fixture);
  expect(snapshot.version).toBe(retried.policy.version);
  assertCanonicalStoredKeys(snapshot.storedValue);
  expect(snapshot.audits).toHaveLength(2);
  expect(snapshot.audits.map((entry) => entry.details.changedFields)).toEqual([
    ["defaultRetentionDays"],
    ["defaultRetentionDays"],
  ]);
  expect(runtimeErrors).toEqual([]);
  await expectNoFixtureSecretLeakage(page);
  await strictAudit(audit, testInfo);
});

test(`${TEST_IDS.invariants} keeps safety invariants locked in the UI and rejects attempts to weaken them`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: [{
      id: "brain-control.safety-invariant-denials",
      transport: "browser",
      method: "PUT",
      pathname: "/api/v2/brain/control",
      query: {},
      status: 400,
      occurrences: 2,
      reason: "Prove both immutable memory safety invariants reject attempted weakening.",
    }],
  });
  const initialResponse = controlResponse(page, "GET");
  await page.goto("/brain/control", { waitUntil: "domcontentloaded" });
  const initial = await payload(await initialResponse);
  const strictIsolation = page.getByRole("checkbox", { name: "Strict engagement isolation", exact: true });
  const secretExclusion = page.getByRole("checkbox", {
    name: "Never retain credentials, tokens, private keys, or authentication material",
    exact: true,
  });
  await expect(strictIsolation).toBeChecked();
  await expect(strictIsolation).toBeDisabled();
  await expect(secretExclusion).toBeChecked();
  await expect(secretExclusion).toBeDisabled();

  const isolationAttempt = await browserPutControl(
    page,
    initial.policy.version,
    { ...editablePolicy(initial.policy), engagementIsolation: false },
    `brain-control-weaken-isolation-${fixture.namespace}`,
  );
  expect(isolationAttempt.status, isolationAttempt.rawBody).toBe(400);
  expect(isolationAttempt.rawBody).not.toContain(BRAIN_CONTROL_FIXTURE_SECRET);
  expect((isolationAttempt.body as ErrorPayload).error).toMatchObject({
    code: "invalid_brain_request",
    humanMessage: "The Second Brain request is invalid",
    retryable: false,
    category: "invalid_input",
  });

  const secretAttempt = await browserPutControl(
    page,
    initial.policy.version,
    { ...editablePolicy(initial.policy), secretsNeverRetained: false },
    `brain-control-weaken-secret-exclusion-${fixture.namespace}`,
  );
  expect(secretAttempt.status, secretAttempt.rawBody).toBe(400);
  expect(secretAttempt.rawBody).not.toContain(BRAIN_CONTROL_FIXTURE_SECRET);
  expect((secretAttempt.body as ErrorPayload).error).toMatchObject({
    code: "invalid_brain_request",
    humanMessage: "The Second Brain request is invalid",
    retryable: false,
    category: "invalid_input",
  });

  const rejected = readBrainControlFixtureSnapshot(fixture);
  expect(rejected.version).toBe(fixture.seededVersion);
  expect(rejected.audits).toEqual([]);
  expect(rejected.storedValue.fixtureAuthenticationToken).toBe(BRAIN_CONTROL_FIXTURE_SECRET);

  const runtimeErrors = captureRuntimeErrors(page);
  const saveRequestPromise = controlRequest(page);
  const saveResponsePromise = controlResponse(page, "PUT");
  await activate(page.getByRole("button", { name: "Save memory controls", exact: true }), "pointer");
  const saveRequest = await saveRequestPromise;
  expect(saveRequest.postDataJSON()).toEqual({
    expectedVersion: initial.policy.version,
    policy: BRAIN_CONTROL_START_POLICY,
  });
  const saved = await payload(await saveResponsePromise);
  expect(saved.policy).toMatchObject({
    version: initial.policy.version + 1,
    engagementIsolation: true,
    secretsNeverRetained: true,
  });
  const snapshot = readBrainControlFixtureSnapshot(fixture);
  assertCanonicalStoredKeys(snapshot.storedValue);
  expect(snapshot.audits).toHaveLength(1);
  expect(snapshot.audits[0]!.details.changedFields).toEqual([]);
  await expect(strictIsolation).toBeChecked();
  await expect(strictIsolation).toBeDisabled();
  await expect(secretExclusion).toBeChecked();
  await expect(secretExclusion).toBeDisabled();
  await expectNoFixtureSecretLeakage(page);
  expect(runtimeErrors).toEqual([]);
  await strictAudit(audit, testInfo);
});

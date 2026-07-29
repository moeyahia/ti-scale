import {
  expect,
  test,
  type Locator,
  type Page,
  type Route,
} from "./support/playwright";
import { readFileSync } from "node:fs";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { waitForInteractiveApplication } from "./support/applicationReadiness";
import type { BrowserAuditController } from "./support/browserAudit";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
} from "./support/interactionActivationFixture";

const TEST_ID = "e2e.brain.read-retry-accessibility";
const manifest = validateInteractionManifest(
  JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown,
);

function readFailure(humanMessage: string, remediation: string, traceId: string) {
  return {
    error: {
      code: "brain_read_fixture_temporarily_unavailable",
      message: "Second Brain fixture temporarily unavailable",
      humanMessage,
      retryable: true,
      category: "dependency",
      remediation,
      traceId,
      timestamp: "2099-07-16T12:00:00.000Z",
    },
  };
}

async function failOnce(
  page: Page,
  pattern: string,
  error: ReturnType<typeof readFailure>,
): Promise<void> {
  let failed = false;
  await page.route(pattern, async (route: Route) => {
    if (!failed) {
      failed = true;
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify(error),
      });
      return;
    }
    await route.continue();
  });
}

function receipt(
  manifestEntryId: string,
  option: string,
  modality: "pointer" | "keyboard",
): InteractionActivationInput {
  const entry = manifest.entries.find((candidate) => candidate.id === manifestEntryId);
  if (!entry) throw new Error(`Brain retry manifest entry ${manifestEntryId} is missing`);
  if (!entry.options.includes(option)) {
    throw new Error(`Brain retry manifest entry ${manifestEntryId} does not declare ${option}`);
  }
  if (!entry.testIds.includes(TEST_ID)) {
    throw new Error(`Brain retry manifest entry ${manifestEntryId} is not bound to ${TEST_ID}`);
  }
  return {
    manifestEntryId,
    controlId: entry.controlId,
    option,
    materialState: entry.requiredState,
    modality,
    testId: TEST_ID,
  };
}

async function activate(control: Locator, modality: "pointer" | "keyboard"): Promise<void> {
  if (modality === "keyboard") {
    await control.focus();
    await control.press("Enter");
  } else {
    await control.click();
  }
}

async function navigate(
  page: Page,
  browserAudit: BrowserAuditController,
  destination: string,
): Promise<void> {
  if (page.url() === "about:blank") {
    await page.goto(destination, { waitUntil: "domcontentloaded" });
  } else {
    await browserAudit.withExpectedDocumentNavigationTeardown(
      page,
      () => page.goto(destination, { waitUntil: "domcontentloaded" }),
    );
  }
  await waitForInteractiveApplication(page);
}

test(`${TEST_ID} gives each initial Brain read its own accessible recovery action`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  const expectedFailures: ReadonlyArray<{
    readonly id: string;
    readonly pathname: string;
    readonly query: Readonly<Record<string, string>>;
    readonly reason: string;
  }> = [
    {
      id: "brain.preferences.initial-unavailable",
      pathname: "/api/v2/brain/preferences",
      query: {},
      reason: "Exercise the Operator Preferences read retry.",
    },
    {
      id: "brain.control.initial-unavailable",
      pathname: "/api/v2/brain/control",
      query: {},
      reason: "Exercise the Memory Control Center read retry.",
    },
    {
      id: "brain.vault.snapshot.initial-unavailable",
      pathname: "/api/v2/brain/vault",
      query: {},
      reason: "Exercise the canonical Vault snapshot retry.",
    },
    {
      id: "brain.vault.preset.initial-unavailable",
      pathname: "/api/v2/brain/vault/attack-knowledge-preset",
      query: { includeConfirmed: "false", includeOperatorProfile: "false" },
      reason: "Exercise the Attack Knowledge Vault preview retry independently.",
    },
  ];
  for (const expectation of expectedFailures) {
    browserAudit.expectHttpResponse(page, {
      ...expectation,
      transport: "browser",
      method: "GET",
      status: 503,
      occurrences: 2,
    });
  }

  for (const modality of ["pointer", "keyboard"] as const) {
    await failOnce(
      page,
      "**/api/v2/brain/preferences",
      readFailure(
        "Confirmed Operator Preferences could not be read.",
        "Retry only the authenticated preference projection.",
        "trace-brain-preferences-retry",
      ),
    );
    await navigate(page, browserAudit, "/brain/preferences");
    const preferencesRetry = page.getByRole("button", { name: "Retry Operator Preferences", exact: true });
    await expect(preferencesRetry).toHaveAttribute("id", "brain-preferences-read-retry");
    await expect(preferencesRetry).toHaveAttribute("data-testid", "brain-preferences-read-retry");
    const preferencesRecovered = page.waitForResponse((response) => response.request().method() === "GET"
      && new URL(response.url()).pathname === "/api/v2/brain/preferences"
      && response.status() === 200);
    await interactionActivation.activate(
      receipt(
        "brain.preferences.retry.read",
        "Retry the authenticated operator's confirmed preferences",
        modality,
      ),
      () => activate(preferencesRetry, modality),
    );
    expect((await preferencesRecovered).status()).toBe(200);
    await expect(preferencesRetry).toHaveCount(0);
    await page.unroute("**/api/v2/brain/preferences");
  }

  for (const modality of ["pointer", "keyboard"] as const) {
    await failOnce(
      page,
      "**/api/v2/brain/control",
      readFailure(
        "Memory controls could not be read.",
        "Retry only the canonical memory-control policy read.",
        "trace-brain-control-read-retry",
      ),
    );
    await navigate(page, browserAudit, "/brain/control");
    const controlRetry = page.getByRole("button", { name: "Retry memory controls", exact: true });
    await expect(controlRetry).toHaveAttribute("id", "brain-control-read-retry");
    await expect(controlRetry).toHaveAttribute("data-control-id", "brain-control-read-retry");
    const controlRecovered = page.waitForResponse((response) => response.request().method() === "GET"
      && new URL(response.url()).pathname === "/api/v2/brain/control"
      && response.status() === 200);
    await interactionActivation.activate(
      receipt("brain.control.retry.read", "Retry only the canonical memory controls", modality),
      () => activate(controlRetry, modality),
    );
    expect((await controlRecovered).status()).toBe(200);
    await expect(page.getByRole("button", { name: "Save memory controls", exact: true })).toBeVisible();
    await page.unroute("**/api/v2/brain/control");
  }

  for (const modality of ["pointer", "keyboard"] as const) {
    await failOnce(
      page,
      "**/api/v2/brain/vault",
      readFailure(
        "The canonical Vault snapshot could not be read.",
        "Retry only the Vault snapshot.",
        "trace-brain-vault-snapshot-retry",
      ),
    );
    await failOnce(
      page,
      "**/api/v2/brain/vault/attack-knowledge-preset?*",
      readFailure(
        "The Attack Knowledge Vault preview could not be prepared.",
        "Retry only the fixed policy preview.",
        "trace-brain-vault-preset-retry",
      ),
    );
    await navigate(page, browserAudit, "/brain/vault");
    const snapshotRetry = page.getByRole("button", { name: "Retry Vault snapshot", exact: true });
    const presetRetry = page.getByRole("button", {
      name: "Retry Attack Knowledge Vault preview",
      exact: true,
    });
    await expect(snapshotRetry).toHaveAttribute("id", "brain-vault-snapshot-retry");
    await expect(presetRetry).toHaveAttribute("id", "brain-vault-preset-preview-retry");
    const snapshotRecovered = page.waitForResponse((response) => response.request().method() === "GET"
      && new URL(response.url()).pathname === "/api/v2/brain/vault"
      && response.status() === 200);
    await interactionActivation.activate(
      receipt("brain.vault.retry.snapshot", "Retry only the canonical Vault snapshot", modality),
      () => activate(snapshotRetry, modality),
    );
    expect((await snapshotRecovered).status()).toBe(200);
    const presetRecovered = page.waitForResponse((response) => response.request().method() === "GET"
      && new URL(response.url()).pathname === "/api/v2/brain/vault/attack-knowledge-preset"
      && response.status() === 200);
    await interactionActivation.activate(
      receipt("brain.vault.retry.preset-preview", "Retry only the registry-owned preset preview", modality),
      () => activate(presetRetry, modality),
    );
    expect((await presetRecovered).status()).toBe(200);
    await expect(page.locator(".brain-attack-vault-preset")).toBeVisible();

    await page.unroute("**/api/v2/brain/vault");
    await page.unroute("**/api/v2/brain/vault/attack-knowledge-preset?*");
  }
});

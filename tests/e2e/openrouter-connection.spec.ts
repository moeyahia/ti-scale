import {
  expect,
  test,
  type Route,
} from "./support/playwright";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
} from "./support/interactionActivationFixture";
import { selectTitaniumOption } from "./support/titaniumSelect";

const TEST_ID = "e2e.system.openrouter-connection";
const NOW = "2026-07-24T13:00:00.000Z";
const PRIVATE_KEY = "sk-or-v1-browser-private-value-never-persisted";
const AGENTS = [
  "ReconScout",
  "WebBreaker",
  "CredSmith",
  "ADAttackMapper",
  "CloudSentinel",
  "ReverseSage",
  "FuzzSmith",
  "OSINTSeeker",
  "SecretHunter",
  "SessionRunner",
  "ReportSmith",
  "VulnIntel",
] as const;

const INTERACTIONS = {
  "system.openrouter.state": {
    controlId: "openrouter-connection-state",
    materialState: "Fixture required: the authenticated OpenRouter connection record is loaded",
  },
  "system.openrouter.model": {
    controlId: "openrouter-model-id",
    materialState: "Fixture required: the authenticated OpenRouter connection record is loaded",
  },
  "system.openrouter.credential": {
    controlId: "openrouter-credential",
    materialState: "Fixture required: OpenRouter is staged as enabled",
  },
  "system.openrouter.save": {
    controlId: "openrouter-save-connection",
    materialState: "Fixture required: the staged connection differs from the canonical record and has a valid exact model plus required credential action",
  },
  "system.openrouter.attestation": {
    controlId: "openrouter-refresh-attestation",
    materialState: "Fixture required: the enabled canonical configuration version is loaded by the running process and no save is pending",
  },
} as const;

type InteractionId = keyof typeof INTERACTIONS;

function activation(
  manifestEntryId: InteractionId,
  option: string,
  modality: InteractionActivationInput["modality"],
): InteractionActivationInput {
  return {
    manifestEntryId,
    controlId: INTERACTIONS[manifestEntryId].controlId,
    option,
    materialState: INTERACTIONS[manifestEntryId].materialState,
    modality,
    testId: TEST_ID,
  };
}

function connection(
  state: "unconfigured" | "restart_required" | "active" | "disabled_restart",
  model = "openai/gpt-5.2",
) {
  const version = state === "unconfigured" ? 0 : state === "disabled_restart" ? 2 : 1;
  const enabled = state !== "unconfigured" && state !== "disabled_restart";
  const active = state === "active";
  return {
    schemaVersion: "ti-scale.openrouter-connection.v1",
    providerId: "openrouter",
    configuration: {
      source: state === "unconfigured" ? "none" : "canonical_provider_config",
      version,
      enabled,
      model,
      credentialConfigured: enabled,
      updatedAt: version ? NOW : null,
      updatedBy: version ? "operator:test" : null,
      storage: "service_owned_mode_0600",
      browserStorage: false,
    },
    activation: {
      activeConfigurationVersion: active ? 1 : state === "disabled_restart" ? 1 : null,
      configuredVersion: version,
      restartRequired: state === "restart_required" || state === "disabled_restart",
      status: state === "unconfigured"
        ? "not_configured"
        : state === "active"
          ? "active"
          : "restart_required",
      humanMessage: state === "unconfigured"
        ? "OpenRouter is not configured."
        : state === "active"
          ? "OpenRouter is active for sanitized Guided planning and advisory work."
          : "The private connection record is saved. Restart Ti-Scale to load this exact version and run the audited provider check.",
    },
    runtime: {
      status: active ? "ready" : "disabled",
      configured: active,
      authenticated: active,
      callable: active,
      supportsGuided: active,
      enforcesAutonomousBoundary: false,
      reportsExactTokenUsage: active,
      reportsExactCostUsage: active,
      requestedModel: active ? model : null,
      returnedModel: active ? model : null,
      lastCheckedAt: NOW,
      attestedAt: active ? NOW : null,
      expiresAt: active ? "2026-07-24T13:05:00.000Z" : null,
      failureCode: null,
      remediation: null,
      reason: active
        ? "The exact provider and model passed the bounded fixture attestation."
        : "No provider version is loaded by this fixture process.",
    },
    planningCompatibility: {
      enforcementMode: "advisor_only",
      compatibleAgentIds: [...AGENTS],
      localExecutionAuthorityUnchanged: true,
      explanation: "OpenRouter may plan, explain, critique, and summarize for every canonical specialist after attestation. Local policy-gated adapters retain all tool and Autonomous execution authority.",
    },
  };
}

async function clickRecorded(
  recorder: InteractionActivationRecorder,
  input: InteractionActivationInput,
  action: () => Promise<void>,
): Promise<void> {
  await recorder.activate(input, action);
}

test(`${TEST_ID} configures, activates, and disables the private advisory connection`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(180_000);
  let current = connection("unconfigured");
  const mutations: Array<{
    readonly path: string;
    readonly body: Record<string, unknown>;
    readonly idempotencyKey: string | null;
    readonly csrf: string | null;
  }> = [];

  await page.route("**/api/v2/provider-connections/openrouter**", async (route: Route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(current),
      });
      return;
    }
    const body = request.postDataJSON() as Record<string, unknown>;
    mutations.push({
      path,
      body,
      idempotencyKey: await request.headerValue("idempotency-key"),
      csrf: await request.headerValue("x-ti-scale-csrf"),
    });
    if (path.endsWith("/attestation")) {
      current = connection("active", current.configuration.model);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          schemaVersion: "ti-scale.openrouter-connection.v1",
          providerId: "openrouter",
          replayed: false,
          connection: current,
        }),
      });
      return;
    }
    const enabled = body.enabled === true;
    const model = String(body.model);
    current = connection(
      enabled ? "restart_required" : "disabled_restart",
      model,
    );
    await route.fulfill({
      status: enabled ? 201 : 200,
      contentType: "application/json",
      body: JSON.stringify({
        ...current,
        mutation: {
          savedVersion: current.configuration.version,
          replayed: false,
        },
      }),
    });
  });

  await page.goto("/system/connections", { waitUntil: "domcontentloaded" });
  const panel = page.getByRole("region", { name: "OpenRouter provider connection" });
  await expect(panel).toBeVisible();
  await expect(panel).toContainText("12 canonical agents · advisor only");
  await expect(panel).toContainText("Remains with local policy-gated adapters");

  const state = panel.getByRole("combobox", {
    name: "OpenRouter connection state",
    exact: true,
  });
  await clickRecorded(
    interactionActivation,
    activation(
      "system.openrouter.state",
      "Enabled for advisory planning",
      "pointer",
    ),
    async () => {
      await selectTitaniumOption(state, "enabled", "pointer");
    },
  );

  const model = panel.getByRole("textbox", {
    name: "Exact OpenRouter model",
    exact: true,
  });
  await clickRecorded(
    interactionActivation,
    activation(
      "system.openrouter.model",
      "Enter one exact provider/model identifier",
      "keyboard",
    ),
    async () => {
      await model.fill("anthropic/claude-3.7-sonnet");
    },
  );

  const credential = panel.getByRole("textbox", {
    name: "OpenRouter credential",
    exact: true,
  });
  await expect(credential).toHaveAttribute("type", "password");
  await expect(credential).toHaveAttribute("autocomplete", "off");
  await clickRecorded(
    interactionActivation,
    activation(
      "system.openrouter.credential",
      "Paste one private OpenRouter completion key",
      "keyboard",
    ),
    async () => {
      await credential.fill(PRIVATE_KEY);
    },
  );

  const save = panel.getByRole("button", { name: "Save connection", exact: true });
  await clickRecorded(
    interactionActivation,
    activation(
      "system.openrouter.save",
      "Save enabled advisory connection",
      "pointer",
    ),
    async () => {
      await save.click();
    },
  );
  await expect(panel.getByRole("status").filter({ hasText: "Restart required" }))
    .toBeVisible();
  await expect(panel.getByRole("textbox", {
    name: "Replace OpenRouter credential",
    exact: true,
  })).toHaveValue("");
  await expect(page.locator("body")).not.toContainText(PRIVATE_KEY);
  const browserStorage = await page.evaluate(() => ({
    local: Object.values(localStorage),
    session: Object.values(sessionStorage),
  }));
  expect([...browserStorage.local, ...browserStorage.session].join("\n"))
    .not.toContain(PRIVATE_KEY);
  expect(mutations[0]).toMatchObject({
    path: "/api/v2/provider-connections/openrouter",
    body: {
      enabled: true,
      model: "anthropic/claude-3.7-sonnet",
      credential: { action: "replace", value: PRIVATE_KEY },
      expectedVersion: 0,
    },
  });
  expect(mutations[0]?.idempotencyKey).toBeTruthy();
  expect(mutations[0]?.csrf).toBeTruthy();

  current = connection("active", "anthropic/claude-3.7-sonnet");
  await browserAudit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.reload({ waitUntil: "domcontentloaded" }),
  );
  const activePanel = page.getByRole("region", {
    name: "OpenRouter provider connection",
  });
  await expect(activePanel).toContainText(
    "OpenRouter is active for sanitized Guided planning and advisory work.",
  );
  const verify = activePanel.getByRole("button", {
    name: "Verify connection & refresh catalog",
    exact: true,
  });
  await clickRecorded(
    interactionActivation,
    activation(
      "system.openrouter.attestation",
      "Run one bounded credential, exact-model, completion, token, and cost attestation and republish the resulting catalog projection",
      "keyboard",
    ),
    async () => {
      await verify.focus();
      await verify.press("Enter");
    },
  );
  await expect(activePanel).toContainText(
    "OpenRouter is active for sanitized Guided planning and advisory work.",
  );
  expect(mutations[1]).toMatchObject({
    path: "/api/v2/provider-connections/openrouter/attestation",
    body: { expectedVersion: 1 },
  });

  const activeState = activePanel.getByRole("combobox", {
    name: "OpenRouter connection state",
    exact: true,
  });
  await clickRecorded(
    interactionActivation,
    activation(
      "system.openrouter.state",
      "Disabled and remove credential",
      "keyboard",
    ),
    async () => {
      await selectTitaniumOption(activeState, "disabled", "keyboard");
    },
  );
  await clickRecorded(
    interactionActivation,
    activation(
      "system.openrouter.save",
      "Save disabled connection and remove credential",
      "keyboard",
    ),
    async () => {
      const disable = activePanel.getByRole("button", {
        name: "Save connection",
        exact: true,
      });
      await disable.focus();
      await disable.press("Enter");
    },
  );
  await expect(activePanel).toContainText("Disabled and remove credential");
  expect(mutations[2]).toMatchObject({
    path: "/api/v2/provider-connections/openrouter",
    body: {
      enabled: false,
      model: "anthropic/claude-3.7-sonnet",
      credential: { action: "remove" },
      expectedVersion: 1,
    },
  });
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 500 });
  await testInfo.attach("openrouter-connection-mutations.json", {
    body: Buffer.from(JSON.stringify(mutations.map((mutation) => ({
      ...mutation,
      body: {
        ...mutation.body,
        credential: mutation.body.credential
          ? { action: (mutation.body.credential as Record<string, unknown>).action }
          : undefined,
      },
    })))),
    contentType: "application/json",
  });
});

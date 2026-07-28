import { expect, test, type Locator, type Page, type Route } from "./support/playwright";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
} from "./support/interactionActivationFixture";
import {
  readTitaniumOptions,
  selectTitaniumOption,
  verifyTitaniumOptionDisabled,
} from "./support/titaniumSelect";

const TEST_CONFIGURATION = "e2e.agent-model-settings.configuration";
const TEST_FAIL_CLOSED = "e2e.agent-model-settings.fail-closed";
const TEST_GLOBAL_DEFAULT = "e2e.agent-model-settings.global-default";
const TEST_CANONICAL_ROSTER = "e2e.agent-model-settings.canonical-roster";
const NOW = "2026-07-23T13:00:00.000Z";
const AGENT_ID = "ReconScout";
const AGENT_NAME = "ReconScout";
const ASSIGNMENT_SEMANTICS = {
  purpose: "execution",
  preferenceResolutionOrder:
    "global_then_agent_then_mission_then_run_then_step",
  saveEffect: "future_resolutions_only",
  activeRunPinning: "immutable",
  planningRoute: "autonomous_mission_contract",
} as const;

const CANONICAL_AGENTS = [
  { id: "ReconScout", role: "Reconnaissance and asset intelligence" },
  { id: "WebBreaker", role: "Web application assessment" },
  { id: "CredSmith", role: "Credential and authentication assessment" },
  { id: "ADAttackMapper", role: "Active Directory and identity path analysis" },
  { id: "CloudSentinel", role: "Cloud, container, and Kubernetes assessment" },
  { id: "ReverseSage", role: "Reverse engineering and binary analysis" },
  { id: "FuzzSmith", role: "Fuzzing and crash discovery" },
  { id: "OSINTSeeker", role: "Passive intelligence and OSINT" },
  { id: "SecretHunter", role: "Secrets and source-code analysis" },
  { id: "SessionRunner", role: "Controlled exploitation and session execution" },
  { id: "ReportSmith", role: "Evidence-backed reporting and memory" },
  { id: "VulnIntel", role: "Vulnerability and CVE intelligence" },
] as const;

const RUNTIME_BOUND_AGENT_IDS = new Set<string>([
  "ReconScout",
  "WebBreaker",
  "SessionRunner",
  "ReportSmith",
  "VulnIntel",
]);

const MODEL_INTERACTIONS = {
  "agents.model.configure-links": {
    controlId: "agents-model-configure",
    materialState: "Fixture required: all twelve canonical specialists are represented in the fleet and their current executable-binding coverage is summarized separately from internal runtime adapters",
    option: "Open ReconScout LLM settings",
  },
  "agents.model.provider": {
    controlId: "agents-model-provider",
    materialState: "Fixture required: the live model catalog and the selected specialist's inherited or unconfigured resolution are loaded",
    option: "Every catalog provider compatible with this specialist",
  },
  "agents.model.primary": {
    controlId: "agents-model-primary",
    materialState: "Fixture required: a compatible provider is selected for the specialist",
    option: "Every exact live-catalog model for the selected provider",
  },
  "agents.model.reasoning": {
    controlId: "agents-model-reasoning",
    materialState: "Fixture required: an exact specialist model with one or more reported reasoning efforts is selected",
    option: "Every reasoning effort reported by the selected provider/model configuration",
  },
  "agents.model.fallback": {
    controlId: "agents-model-fallback",
    materialState: "Fixture required: the specialist model editor and live catalog are loaded",
    option: "Every other exact compatible and selectable configuration",
  },
  "agents.model.reason": {
    controlId: "agents-model-reason",
    materialState: "Fixture required: the operator changed the specialist's primary or fallback configuration",
    option: "Enter a reviewable reason of at least three characters",
  },
  "agents.model.save": {
    controlId: "agents-model-save",
    materialState: "Fixture required: the specialist has a changed, compatible exact assignment and a valid rationale",
    option: "Save one exact per-agent override with optimistic concurrency and idempotency",
  },
  "agents.model.conflict-retry": {
    controlId: "agents-model-conflict-retry",
    materialState: "Fixture required: saving the specialist assignment returned a structured version conflict",
    option: "Refresh the authoritative scoped preference and model resolution",
  },
  "agents.model.open-workspace-default": {
    controlId: "agent-model-open-workspace-default",
    materialState: "Fixture required: the specialist has neither an exact override nor an inherited workspace assignment",
    option: "Open the workspace default model configuration",
  },
  "agents.model.load-retry": {
    controlId: "agents-model-load-retry",
    materialState: "Fixture required: the specialist model catalog, preference, or inherited resolution read failed or the catalog exceeded its 15-minute trust window",
    option: "Retry the authoritative model reads without reviving failed or expired catalog choices",
  },
  "system.model.provider": {
    controlId: "system-model-provider",
    materialState: "Fixture required: the live model catalog and workspace model preference are loaded",
    option: "Every globally selectable live-catalog provider",
  },
  "system.model.primary": {
    controlId: "system-model-primary",
    materialState: "Fixture required: a globally selectable provider is selected",
    option: "Every exact live-catalog model for the selected provider",
  },
  "system.model.reasoning": {
    controlId: "system-model-reasoning",
    materialState: "Fixture required: an exact workspace model with reported reasoning efforts is selected",
    option: "Every reasoning effort reported for the selected exact model",
  },
  "system.model.fallback": {
    controlId: "system-model-fallback",
    materialState: "Fixture required: the workspace model editor and live catalog are loaded",
    option: "Every other exact globally selectable configuration",
  },
  "system.model.reason": {
    controlId: "system-model-reason",
    materialState: "Fixture required: the workspace primary or fallback model differs from its authoritative baseline",
    option: "Enter a reviewable reason of at least three characters",
  },
  "system.model.save": {
    controlId: "system-model-save",
    materialState: "Fixture required: the workspace default has a changed, globally selectable exact assignment and valid rationale",
    option: "Save one exact global default with optimistic concurrency and idempotency",
  },
  "system.model.load-retry": {
    controlId: "system-model-load-retry",
    materialState: "Fixture required: the workspace model catalog or preference read failed or the catalog exceeded its 15-minute trust window",
    option: "Retry authoritative workspace model reads without reviving failed or expired catalog choices",
  },
} as const;

type ModelInteractionId = keyof typeof MODEL_INTERACTIONS;

function activation(
  manifestEntryId: ModelInteractionId,
  modality: InteractionActivationInput["modality"],
  testId: string,
  option?: string,
): InteractionActivationInput {
  const interaction = MODEL_INTERACTIONS[manifestEntryId];
  return {
    manifestEntryId,
    controlId: interaction.controlId,
    option: option ?? interaction.option,
    materialState: interaction.materialState,
    modality,
    testId,
  };
}

const catalogItems = [
  catalogItem({
    configurationId: "configuration-local-high",
    providerId: "local-runtime",
    modelId: "local-reasoner",
    displayName: "Local Reasoner",
    executionBoundary: "local_deterministic_policy",
    reasoningEffort: "high",
    supportedReasoningEfforts: ["high"],
    disclosureClass: "local_only",
    capabilities: {
      toolCalling: false,
      structuredOutput: true,
      compatibleActionClassIds: [
        "active_host_discovery",
        "port_service_enumeration",
      ],
      localDeterministicActionClassIdsByAgent: {
        [AGENT_ID]: [
          "active_host_discovery",
          "port_service_enumeration",
        ],
      },
    },
  }),
  catalogItem({
    configurationId: "configuration-openai-medium",
    providerId: "openai",
    modelId: "gpt-5.6",
    displayName: "GPT-5.6",
    reasoningEffort: "medium",
    supportedReasoningEfforts: ["medium", "high"],
  }),
  catalogItem({
    configurationId: "configuration-openai-high",
    providerId: "openai",
    modelId: "gpt-5.6",
    displayName: "GPT-5.6",
    reasoningEffort: "high",
    supportedReasoningEfforts: ["medium", "high"],
  }),
  catalogItem({
    configurationId: "configuration-openai-unavailable",
    providerId: "openai",
    modelId: "gpt-unavailable",
    displayName: "Unavailable Test Model",
    reasoningEffort: "high",
    supportedReasoningEfforts: ["high"],
    enforcementMode: "unavailable",
    healthState: "unavailable",
    selectable: false,
    unavailableReasons: ["This exact catalog model is unavailable in the current runtime."],
  }),
  catalogItem({
    configurationId: "configuration-openrouter-medium",
    providerId: "openrouter",
    modelId: "anthropic/claude-4.5-sonnet",
    displayName: "Claude 4.5 Sonnet",
    reasoningEffort: "medium",
    supportedReasoningEfforts: ["medium", "high"],
    enforcementMode: "advisor_only",
  }),
  catalogItem({
    configurationId: "configuration-openrouter-high-unavailable",
    providerId: "openrouter",
    modelId: "anthropic/claude-4.5-sonnet",
    displayName: "Claude 4.5 Sonnet",
    reasoningEffort: "high",
    supportedReasoningEfforts: ["medium", "high"],
    enforcementMode: "unavailable",
    healthState: "unavailable",
    selectable: false,
    unavailableReasons: [
      "High reasoning is unavailable for this exact provider and model path.",
    ],
  }),
  catalogItem({
    configurationId: "configuration-gemini-observe",
    providerId: "gemini",
    modelId: "gemini-3-pro",
    displayName: "Gemini 3 Pro",
    reasoningEffort: null,
    supportedReasoningEfforts: [],
    enforcementMode: "observe_only_executor",
  }),
  catalogItem({
    configurationId: "configuration-xai-unavailable",
    providerId: "xai",
    modelId: "grok-4",
    displayName: "Grok 4",
    reasoningEffort: null,
    supportedReasoningEfforts: [],
    enforcementMode: "unavailable",
    authState: "unconfigured",
    healthState: "unavailable",
    selectable: false,
    unavailableReasons: ["Provider authentication is not configured."],
  }),
  catalogItem({
    configurationId: "configuration-anthropic-other-agent",
    providerId: "anthropic",
    modelId: "claude-4.5-opus",
    displayName: "Claude 4.5 Opus",
    reasoningEffort: "high",
    supportedReasoningEfforts: ["high"],
    compatibleAgentIds: ["WebBreaker"],
  }),
] as const;

function catalogItem(overrides: Record<string, unknown>) {
  return {
    configurationId: "configuration-default",
    providerId: "provider",
    modelId: "model",
    displayName: "Model",
    executionBoundary: "provider_tool_calling",
    reasoningEffort: null,
    supportedReasoningEfforts: [],
    contextLimit: 400_000,
    costClass: "premium",
    latencyClass: "deliberate",
    disclosureClass: "public_provider_sanitized",
    enforcementMode: "enforced_executor",
    authState: "authenticated",
    healthState: "healthy",
    catalogSource: "runtime_source_manifest",
    catalogRetrievedAt: NOW,
    capabilities: {
      toolCalling: true,
      structuredOutput: true,
      compatibleActionClassIds: [
        "active_host_discovery",
        "port_service_enumeration",
      ],
      localDeterministicActionClassIdsByAgent: {},
    },
    compatibleAgentIds: [AGENT_ID],
    selectable: true,
    unavailableReasons: [],
    ...overrides,
  };
}

function configuration(configurationId: string) {
  const catalog = catalogItems.find((item) => item.configurationId === configurationId);
  if (!catalog) throw new Error(`Unknown model configuration fixture ${configurationId}`);
  return {
    id: catalog.configurationId,
    providerId: catalog.providerId,
    modelId: catalog.modelId,
    displayName: catalog.displayName,
    executionBoundary: catalog.executionBoundary,
    reasoningEffort: catalog.reasoningEffort,
    contextPolicy: { maximumContextTokens: 120_000 },
    capabilities: catalog.capabilities,
    contextLimit: catalog.contextLimit,
    costClass: catalog.costClass,
    latencyClass: catalog.latencyClass,
    disclosureClass: catalog.disclosureClass,
    enforcementMode: catalog.enforcementMode,
    authState: catalog.authState,
    healthState: catalog.healthState,
    catalogSource: catalog.catalogSource,
    catalogRetrievedAt: catalog.catalogRetrievedAt,
    configurationSource: "manual",
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function modelPreference(input: {
  readonly scopeType: "global" | "agent";
  readonly scopeId: string;
  readonly agentId: string | null;
  readonly primaryConfigurationId: string;
  readonly fallbackConfigurationId: string | null;
  readonly resolutionReason: string;
  readonly version: number;
}) {
  return {
    id: `model-preference-${input.scopeType}-${input.scopeId}`,
    ...input,
    createdBy: "e2e-local-operator",
    createdAt: NOW,
    updatedBy: "e2e-local-operator",
    updatedAt: NOW,
  };
}

function agentRecord(input: (typeof CANONICAL_AGENTS)[number]) {
  const runtimeBound = RUNTIME_BOUND_AGENT_IDS.has(input.id);
  const runtimeBindingId = `runtime:${input.id.toLocaleLowerCase()}`;
  const runtimeBindings = runtimeBound
    ? [{ id: runtimeBindingId, version: "runtime-v1" }]
    : [];
  return {
    id: input.id,
    role: input.role,
    displayName: input.id,
    status: runtimeBound ? "available" : "offline",
    version: "2.4.0",
    lastHeartbeatAt: runtimeBound ? NOW : null,
    updatedAt: NOW,
    providerPolicy: {
      source: "runtime",
      runtimeBindings: runtimeBound
        ? [{
            agentId: runtimeBindingId,
            policy: { source: "current-runtime-manifest" },
          }]
        : [],
    },
    toolPolicy: {
      actionClasses: runtimeBound ? ["active_host_discovery"] : [],
    },
    configuration: {
      source: "standalone_specialist_registry",
      schemaVersion: "ti-scale.product-agent-roster.v1",
      description: runtimeBound
        ? `${input.id} is bound to its current runtime specialist adapter.`
        : `${input.id} is a stable product role with no current executable runtime binding.`,
      runtimeBindingCount: runtimeBindings.length,
      runtimeBindingsVersioned: true,
      runtimeBindings,
    },
    assignmentHealth: {
      queueDepth: 0,
      active: 0,
      completed: runtimeBound ? 3 : 0,
      failed: 0,
      successRate: runtimeBound ? 1 : null,
      meanCompletionSeconds: runtimeBound ? 12 : null,
      lastAssignmentAt: runtimeBound ? NOW : null,
    },
    health: null,
    capabilities: [{
      name: `product.${input.id.toLocaleLowerCase()}`,
      source: "standalone_specialist_registry",
      enabled: runtimeBound,
      metadata: {
        runtimeBound,
      },
    }],
  };
}

const agents = CANONICAL_AGENTS.map(agentRecord);
const agent = agents.find(({ id }) => id === AGENT_ID);
if (!agent) throw new Error("The canonical ReconScout fixture is missing");

async function json(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

function errorEnvelope(input: {
  readonly code: string;
  readonly humanMessage: string;
  readonly remediation: string;
  readonly traceId: string;
}) {
  return {
    error: {
      ...input,
      message: input.humanMessage,
      retryable: false,
      category: "conflict",
      timestamp: NOW,
    },
  };
}

async function installAgentRoutes(page: Page): Promise<void> {
  await page.route("**/api/v2/agents**", async (route) => {
    const url = new URL(route.request().url());
    const assignmentsMatch = /^\/api\/v2\/agents\/([^/]+)\/assignments$/u.exec(url.pathname);
    if (assignmentsMatch && agents.some(({ id }) => id === decodeURIComponent(assignmentsMatch[1]!))) {
      await json(route, { schemaVersion: "2.4", items: [], nextCursor: null });
      return;
    }
    const detailMatch = /^\/api\/v2\/agents\/([^/]+)$/u.exec(url.pathname);
    const requestedAgent = detailMatch
      ? agents.find(({ id }) => id === decodeURIComponent(detailMatch[1]!))
      : undefined;
    if (requestedAgent) {
      await json(route, requestedAgent);
      return;
    }
    if (url.pathname === "/api/v2/agents") {
      await json(route, { schemaVersion: "2.4", items: agents, nextCursor: null });
      return;
    }
    await route.continue();
  });
}

interface CapturedPreferenceWrite {
  readonly headers: Record<string, string>;
  readonly body: Record<string, unknown>;
}

async function installModelRoutes(page: Page, input: {
  readonly scope: "agent" | "global";
  readonly resolution: "inherited" | "missing";
  readonly mutation: "success" | "conflict";
  readonly canonicalRuntimeCompatibility?: boolean;
  readonly catalogInitiallyAvailable?: boolean;
}): Promise<{
  readonly writes: CapturedPreferenceWrite[];
  readonly reads: {
    catalog: number;
    preferences: number;
    resolution: number;
  };
  readonly setCatalogAvailable: (available: boolean) => void;
}> {
  const writes: CapturedPreferenceWrite[] = [];
  const reads = {
    catalog: 0,
    preferences: 0,
    resolution: 0,
  };
  let catalogAvailable = input.catalogInitiallyAvailable ?? true;
  let storedPreference: ReturnType<typeof modelPreference> | undefined;
  await page.route("**/api/v2/model-**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/v2/model-catalog") {
      reads.catalog += 1;
      if (!catalogAvailable) {
        await json(route, errorEnvelope({
          code: "model_catalog_unavailable",
          humanMessage: "The live model catalog could not be refreshed.",
          remediation: "Restore the provider catalog service, then try again.",
          traceId: "trace-model-catalog-unavailable",
        }), 503);
        return;
      }
      const items = input.canonicalRuntimeCompatibility
        ? catalogItems.map((item) => (
          item.selectable && item.compatibleAgentIds.includes(AGENT_ID)
          ? {
              ...item,
              compatibleAgentIds: [...RUNTIME_BOUND_AGENT_IDS],
            }
          : item))
        : catalogItems;
      await json(route, { schemaVersion: "2.4", observedAt: NOW, items });
      return;
    }
    if (url.pathname === "/api/v2/model-preferences" && request.method() === "GET") {
      reads.preferences += 1;
      const requestedScope = url.searchParams.get("scopeType");
      const requestedAgent = url.searchParams.get("agentId");
      const matches = storedPreference
        && requestedScope === storedPreference.scopeType
        && (requestedAgent ?? null) === storedPreference.agentId;
      await json(route, {
        schemaVersion: "2.4",
        items: matches ? [storedPreference] : [],
      });
      return;
    }
    if (url.pathname === "/api/v2/model-resolution" && request.method() === "GET") {
      reads.resolution += 1;
      const requestedAgentId = url.searchParams.get("agentId") ?? AGENT_ID;
      if (input.resolution === "missing") {
        await json(route, {
          schemaVersion: "2.4",
          assignmentSemantics: ASSIGNMENT_SEMANTICS,
          resolution: null,
          availability: {
            status: "unconfigured",
            agentId: requestedAgentId,
            humanMessage: "No model preference is configured for this specialist.",
            remediation: "Configure the workspace default or this specialist directly.",
          },
        });
        return;
      }
      await json(route, {
        schemaVersion: "2.4",
        assignmentSemantics: ASSIGNMENT_SEMANTICS,
        availability: {
          status: "configured",
          agentId: requestedAgentId,
          humanMessage: "This agent has a model assignment for the requested scope.",
          remediation: null,
        },
        resolution: {
          agentId: requestedAgentId,
          context: { missionId: null, runId: null, stepId: null },
          source: {
            scopeType: "global",
            scopeId: "global",
            preferenceId: "model-preference-global",
            preferenceVersion: 7,
          },
          primaryConfiguration: configuration("configuration-local-high"),
          fallbackConfiguration: null,
          resolvedAt: NOW,
        },
      });
      return;
    }
    if (url.pathname === `/api/v2/model-preferences/${input.scope}/${input.scope === "global" ? "global" : AGENT_ID}`
      && request.method() === "PUT") {
      const body = request.postDataJSON() as Record<string, unknown>;
      writes.push({ headers: request.headers(), body });
      if (input.mutation === "conflict") {
        await json(route, errorEnvelope({
          code: "model_preference_version_conflict",
          humanMessage: "This model assignment changed after the page loaded.",
          remediation: "Refresh the assignment, review the current model receipt, and save again.",
          traceId: "trace-model-preference-conflict",
        }), 409);
        return;
      }
      const nextVersion = (storedPreference?.version ?? 0) + 1;
      storedPreference = modelPreference({
        scopeType: input.scope,
        scopeId: input.scope === "global" ? "global" : AGENT_ID,
        agentId: input.scope === "global" ? null : AGENT_ID,
        primaryConfigurationId: String(body.primaryConfigurationId),
        fallbackConfigurationId: typeof body.fallbackConfigurationId === "string"
          ? body.fallbackConfigurationId
          : null,
        resolutionReason: String(body.reason),
        version: nextVersion,
      });
      await json(route, { schemaVersion: "2.4", preference: storedPreference });
      return;
    }
    await route.continue();
  });
  return {
    writes,
    reads,
    setCatalogAvailable: (available) => {
      catalogAvailable = available;
    },
  };
}

async function selectReviewedAssignment(
  page: Page,
  label: string,
  agentScoped: boolean,
  interactionActivation: InteractionActivationRecorder,
  testId: string,
  modalities: readonly InteractionActivationInput["modality"][],
): Promise<void> {
  const provider = page.getByRole("combobox", { name: `${label} provider`, exact: true });
  const primary = page.getByRole("combobox", { name: `${label} primary model`, exact: true });
  const reasoning = page.getByRole("combobox", { name: `${label} reasoning effort`, exact: true });
  const fallback = page.getByRole("combobox", { name: `${label} fallback model`, exact: true });
  const interactionPrefix = agentScoped ? "agents.model" : "system.model";
  const controlPrefix = agentScoped ? "agents" : "system";
  await expect(provider).toHaveAttribute(
    "data-control-id",
    `${controlPrefix}-model-provider`,
  );
  await expect(primary).toHaveAttribute(
    "data-control-id",
    `${controlPrefix}-model-primary`,
  );
  await expect(reasoning).toHaveAttribute(
    "data-control-id",
    `${controlPrefix}-model-reasoning`,
  );
  await expect(fallback).toHaveAttribute(
    "data-control-id",
    `${controlPrefix}-model-fallback`,
  );

  for (const modality of modalities) {
    const providers = await readTitaniumOptions(provider);
    const selectableProviders = providers.filter(({ disabled, value }) => !disabled && value);
    const unavailableProviders = providers.filter(({ disabled, value }) => disabled && value);
    expect(unavailableProviders.find((item) => item.value === "xai")).toMatchObject({
      label: "xai — unavailable",
      disabled: true,
    });
    expect(providers.find((item) => item.value === "anthropic")).toMatchObject({
      label: agentScoped ? "anthropic — unavailable" : "anthropic",
      disabled: agentScoped,
    });
    await interactionActivation.activate(
      activation(`${interactionPrefix}.provider`, modality, testId),
      async () => {
        for (const option of selectableProviders) {
          await selectTitaniumOption(provider, option.value, modality);
        }
        await selectTitaniumOption(provider, "openai", modality);
      },
    );
    await interactionActivation.activate(
      activation(
        `${interactionPrefix}.provider`,
        modality,
        testId,
        agentScoped
          ? "Unavailable and agent-incompatible providers remain represented but disabled"
          : "Unavailable providers remain represented but disabled",
      ),
      async () => {
        for (const option of unavailableProviders) {
          await verifyTitaniumOptionDisabled(provider, option.value, modality);
        }
      },
    );

    await interactionActivation.activate(
      activation(`${interactionPrefix}.primary`, modality, testId),
      async () => {
        for (const providerOption of selectableProviders) {
          await selectTitaniumOption(provider, providerOption.value, modality);
          const modelOptions = await readTitaniumOptions(primary);
          for (const modelOption of modelOptions.filter(({ disabled, value }) => !disabled && value)) {
            await selectTitaniumOption(primary, modelOption.value, modality);
          }
        }
        await selectTitaniumOption(provider, "openai", modality);
        await selectTitaniumOption(primary, "gpt-5.6", modality);
      },
    );
    await interactionActivation.activate(
      activation(
        `${interactionPrefix}.primary`,
        modality,
        testId,
        "Unavailable models remain represented but disabled",
      ),
      async () => {
        let disabledModelCount = 0;
        for (const providerOption of selectableProviders) {
          await selectTitaniumOption(provider, providerOption.value, modality);
          const unavailableModels = (await readTitaniumOptions(primary))
            .filter(({ disabled, value }) => disabled && value);
          disabledModelCount += unavailableModels.length;
          for (const modelOption of unavailableModels) {
            await verifyTitaniumOptionDisabled(primary, modelOption.value, modality);
          }
        }
        expect(disabledModelCount).toBeGreaterThan(0);
        await selectTitaniumOption(provider, "openai", modality);
        const unavailableOpenAiModel = (await readTitaniumOptions(primary))
          .find((item) => item.value === "gpt-unavailable");
        expect(unavailableOpenAiModel).toMatchObject({
          label: "Unavailable Test Model · gpt-unavailable — unavailable",
          disabled: true,
        });
        await selectTitaniumOption(primary, "gpt-5.6", modality);
      },
    );

    await interactionActivation.activate(
      activation(`${interactionPrefix}.reasoning`, modality, testId),
      async () => {
        for (const providerOption of selectableProviders) {
          await selectTitaniumOption(provider, providerOption.value, modality);
          const modelOptions = (await readTitaniumOptions(primary))
            .filter(({ disabled, value }) => !disabled && value);
          for (const modelOption of modelOptions) {
            await selectTitaniumOption(primary, modelOption.value, modality);
            const reasoningOptions = (await readTitaniumOptions(reasoning))
              .filter(({ disabled, value }) => !disabled && value);
            for (const reasoningOption of reasoningOptions) {
              await selectTitaniumOption(reasoning, reasoningOption.value, modality);
            }
          }
        }
        await selectTitaniumOption(provider, "openai", modality);
        await selectTitaniumOption(primary, "gpt-5.6", modality);
        await selectTitaniumOption(reasoning, "configuration-openai-high", modality);
      },
    );
    await interactionActivation.activate(
      activation(
        `${interactionPrefix}.reasoning`,
        modality,
        testId,
        "Unavailable reasoning efforts remain represented but disabled",
      ),
      async () => {
        let disabledReasoningCount = 0;
        for (const providerOption of selectableProviders) {
          await selectTitaniumOption(provider, providerOption.value, modality);
          const modelOptions = (await readTitaniumOptions(primary))
            .filter(({ disabled, value }) => !disabled && value);
          for (const modelOption of modelOptions) {
            await selectTitaniumOption(primary, modelOption.value, modality);
            const unavailableReasoning = (await readTitaniumOptions(reasoning))
              .filter(({ disabled, value }) => disabled && value);
            disabledReasoningCount += unavailableReasoning.length;
            for (const reasoningOption of unavailableReasoning) {
              await verifyTitaniumOptionDisabled(reasoning, reasoningOption.value, modality);
            }
          }
        }
        expect(disabledReasoningCount).toBeGreaterThan(0);
        await selectTitaniumOption(provider, "openrouter", modality);
        await selectTitaniumOption(
          primary,
          "anthropic/claude-4.5-sonnet",
          modality,
        );
        expect((await readTitaniumOptions(reasoning))
          .find(({ value }) => value === "configuration-openrouter-high-unavailable"))
          .toMatchObject({ disabled: true });
        await selectTitaniumOption(provider, "openai", modality);
        await selectTitaniumOption(primary, "gpt-5.6", modality);
        await selectTitaniumOption(reasoning, "configuration-openai-high", modality);
      },
    );

    await interactionActivation.activate(
      activation(
        `${interactionPrefix}.fallback`,
        modality,
        testId,
        "No automatic fallback",
      ),
      () => selectTitaniumOption(fallback, "", modality),
    );
    const selectableConfigurationIds = catalogItems
      .filter((item) => item.selectable && (
        !agentScoped || item.compatibleAgentIds.includes(AGENT_ID)
      ))
      .map(({ configurationId }) => configurationId);
    await interactionActivation.activate(
      activation(`${interactionPrefix}.fallback`, modality, testId),
      async () => {
        for (const configurationId of selectableConfigurationIds) {
          if (configurationId === "configuration-openai-high") {
            await selectTitaniumOption(provider, "local-runtime", modality);
            await selectTitaniumOption(primary, "local-reasoner", modality);
          } else {
            await selectTitaniumOption(provider, "openai", modality);
            await selectTitaniumOption(primary, "gpt-5.6", modality);
            await selectTitaniumOption(
              reasoning,
              "configuration-openai-high",
              modality,
            );
          }
          expect((await readTitaniumOptions(fallback))
            .find(({ value }) => value === configurationId))
            .toMatchObject({ disabled: false });
          await selectTitaniumOption(fallback, configurationId, modality);
        }
        await selectTitaniumOption(provider, "openai", modality);
        await selectTitaniumOption(primary, "gpt-5.6", modality);
        await selectTitaniumOption(reasoning, "configuration-openai-high", modality);
        await selectTitaniumOption(fallback, "configuration-openrouter-medium", modality);
      },
    );
    await interactionActivation.activate(
      activation(
        `${interactionPrefix}.fallback`,
        modality,
        testId,
        agentScoped
          ? "Unavailable, incompatible, and current-primary configurations remain represented but disabled"
          : "Unavailable and current-primary configurations remain represented but disabled",
      ),
      async () => {
        const unavailableFallbacks = (await readTitaniumOptions(fallback))
          .filter(({ disabled, value }) => disabled && value);
        expect(unavailableFallbacks.length).toBeGreaterThan(0);
        for (const option of unavailableFallbacks) {
          await verifyTitaniumOptionDisabled(fallback, option.value, modality);
        }
        expect((await readTitaniumOptions(fallback))
          .find(({ value }) => value === "configuration-openai-high"))
          .toMatchObject({ disabled: true });
        expect((await readTitaniumOptions(fallback))
          .find(({ value }) => value === "configuration-openrouter-high-unavailable"))
          .toMatchObject({ disabled: true });
      },
    );
  }
}

async function enterAssignmentReason(
  reason: Locator,
  value: string,
  modality: InteractionActivationInput["modality"],
): Promise<void> {
  if (modality === "pointer") {
    await reason.click();
    await reason.fill(value);
  } else {
    await reason.focus();
    await reason.press(process.platform === "darwin" ? "Meta+A" : "Control+A");
    await reason.pressSequentially(value);
  }
  await expect(reason).toHaveValue(value);
}

async function expectFragmentFocusedInViewport(editor: Locator): Promise<void> {
  await expect(editor).toBeFocused();
  await expect.poll(
    () => editor.evaluate((element) => {
      const rect = element.getBoundingClientRect();
      return rect.top >= 0 && rect.top < window.innerHeight && rect.bottom > 0;
    }),
    { message: "The linked model editor must be placed inside the visible viewport" },
  ).toBe(true);
}

test(`${TEST_CONFIGURATION} exposes inherited truth and saves one exact per-agent override`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(120_000);
  await installAgentRoutes(page);
  const model = await installModelRoutes(page, {
    scope: "agent",
    resolution: "inherited",
    mutation: "success",
  });

  await page.goto(`/agents/${AGENT_ID}#agent-model-configuration`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page).toHaveURL(
    new RegExp(`/agents/${AGENT_ID}#agent-model-configuration$`, "u"),
  );
  const editor = page.getByLabel(`${AGENT_NAME} model configuration`, { exact: true });
  await expect(editor).toBeVisible();
  await expectFragmentFocusedInViewport(editor);
  const semantics = editor.getByLabel(
    `${AGENT_NAME} model assignment semantics`,
    { exact: true },
  );
  await expect(semantics).toContainText("Specialist execution");
  await expect(semantics).toContainText("Immutable pinned receipt");
  await expect(semantics).toContainText("Reviewed in the mission contract");
  await expect(editor).toContainText("Inherited from Global");
  await expect(editor.getByText("Enforced executor", { exact: true })).toBeVisible();
  await expect(editor.getByRole("combobox", { name: `${AGENT_NAME} provider`, exact: true }))
    .toContainText("local-runtime");
  const runtimeBindings = page.getByLabel(`${AGENT_NAME} runtime bindings`, { exact: true });
  await expect(runtimeBindings).toContainText("runtime:reconscout");
  await expect(runtimeBindings).toContainText("Runtime version runtime-v1");
  const readiness = editor.getByLabel(`${AGENT_NAME} live model readiness`, { exact: true });
  await expect(readiness).toContainText("Enforced Executor");
  await expect(readiness).toContainText("Observe Only Executor");
  await expect(readiness).toContainText("Advisor Only");
  await expect(readiness).toContainText("Unavailable");
  await expect(readiness).toContainText("Locally enforced deterministic policy");
  await expect(readiness).toContainText("Provider tool-calling");
  await expect(editor.getByText("Execution boundary", { exact: true }).first())
    .toBeVisible();
  await expect(editor).toContainText("Locally enforced deterministic policy");
  await selectReviewedAssignment(
    page,
    AGENT_NAME,
    true,
    interactionActivation,
    TEST_CONFIGURATION,
    ["keyboard"],
  );
  await expect(editor.getByText("Enforced executor", { exact: true })).toBeVisible();
  await expect(editor).toContainText("Provider tool-calling");
  await expect(
    editor.getByText("Fallback enforcement", { exact: true }).locator(".."),
  ).toContainText("Advisor Only");
  await expect(
    editor.getByText("Fallback provider health", { exact: true }).locator(".."),
  ).toContainText("Healthy");
  await expect(
    editor.getByText("Fallback data disclosure", { exact: true }).locator(".."),
  ).toContainText("Public Provider Sanitized");

  const reason = editor.getByRole("textbox", { name: "Reason for this assignment", exact: true });
  await expect(reason).toHaveAttribute("data-control-id", "agents-model-reason");
  await interactionActivation.activate(
    activation("agents.model.reason", "keyboard", TEST_CONFIGURATION),
    () => enterAssignmentReason(
      reason,
      "Use the attested tool-capable model for reconnaissance.",
      "keyboard",
    ),
  );
  const save = editor.getByRole("button", { name: "Save agent assignment", exact: true });
  await expect(save).toHaveAttribute("data-control-id", "agents-model-save");
  await expect(save).toBeEnabled();
  const mutation = page.waitForResponse((response) =>
    new URL(response.url()).pathname === `/api/v2/model-preferences/agent/${AGENT_ID}`
    && response.request().method() === "PUT");
  await save.focus();
  await interactionActivation.activate(
    activation("agents.model.save", "keyboard", TEST_CONFIGURATION),
    () => page.keyboard.press("Enter"),
  );
  expect((await mutation).status()).toBe(200);
  await expect(editor).toContainText(`${AGENT_NAME} override`);
  await expect(editor).toContainText(
    "Saved rationale: Use the attested tool-capable model for reconnaissance.",
  );
  await browserAudit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.reload({ waitUntil: "domcontentloaded" }),
  );
  const reloadedEditor = page.getByLabel(
    `${AGENT_NAME} model configuration`,
    { exact: true },
  );
  await expect(reloadedEditor).toContainText(`${AGENT_NAME} override`);
  await expect(reloadedEditor).toContainText(
    "Saved rationale: Use the attested tool-capable model for reconnaissance.",
  );

  expect(model.writes).toHaveLength(1);
  expect(model.writes[0]?.body).toEqual({
    agentId: AGENT_ID,
    primaryConfigurationId: "configuration-openai-high",
    fallbackConfigurationId: "configuration-openrouter-medium",
    expectedVersion: 0,
    reason: "Use the attested tool-capable model for reconnaissance.",
  });
  expect(model.writes[0]?.headers["idempotency-key"]).toMatch(
    /^(?:[0-9a-f-]{20,}|model-preference-)/u,
  );
  await browserAudit.waitForPageApiSettlement(page);
});

test(`${TEST_CANONICAL_ROSTER} traverses every canonical specialist's LLM settings route`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(120_000);
  await installAgentRoutes(page);
  const model = await installModelRoutes(page, {
    scope: "agent",
    resolution: "inherited",
    mutation: "success",
    canonicalRuntimeCompatibility: true,
  });

  await page.goto("/agents", { waitUntil: "domcontentloaded" });
  const rosterSummary = page.getByRole("region", {
    name: "Canonical specialist roster status",
    exact: true,
  });
  await expect(rosterSummary).toContainText("Canonical specialist roles");
  await expect(rosterSummary).toContainText(String(CANONICAL_AGENTS.length));
  await expect(rosterSummary).toContainText("Roles with execution");
  await expect(rosterSummary).toContainText(String(RUNTIME_BOUND_AGENT_IDS.size));
  await expect(rosterSummary).toContainText("Roles awaiting runtime");
  await expect(rosterSummary).toContainText(
    String(CANONICAL_AGENTS.length - RUNTIME_BOUND_AGENT_IDS.size),
  );
  await expect(rosterSummary).toContainText("Internal adapters remain separate from agents");
  const settingsLinks = page.getByRole("link", { name: /^LLM settings for /u });
  await expect(settingsLinks).toHaveCount(CANONICAL_AGENTS.length);

  for (const modality of ["pointer", "keyboard"] as const) {
    if (modality === "keyboard") {
      await page.goto("/agents", { waitUntil: "domcontentloaded" });
    }
    for (const specialist of CANONICAL_AGENTS) {
      const link = page.getByRole("link", {
        name: `LLM settings for ${specialist.id}`,
        exact: true,
      });
      await expect(link).toBeVisible();
      await expect(link).toContainText("LLM settings");
      await expect(link).toContainText("Provider · model · reasoning");
      await interactionActivation.activate(
        activation(
          "agents.model.configure-links",
          modality,
          TEST_CANONICAL_ROSTER,
          `Open ${specialist.id} LLM settings`,
        ),
        async () => {
          if (modality === "pointer") {
            await link.click();
            return;
          }
          await link.focus();
          await page.keyboard.press("Enter");
        },
      );
      await expect(page).toHaveURL(
        new RegExp(`/agents/${specialist.id}#agent-model-configuration$`, "u"),
      );
      const editor = page.getByLabel(
        `${specialist.id} model configuration`,
        { exact: true },
      );
      await expect(editor).toBeVisible();
      await expect(editor).toContainText(
        "Model choice controls reasoning and provider routing.",
      );
      await expect(editor).toContainText(
        "It does not create a missing specialist tool binding or grant execution authority.",
      );
      await expectFragmentFocusedInViewport(editor);
      const binding = page.getByLabel(`${specialist.id} runtime bindings`, { exact: true });
      await expect(editor).toContainText("Inherited from Global");
      await expect(editor.getByRole("heading", { name: "Provider and model", exact: true }))
        .toBeVisible();
      const provider = editor.getByRole("combobox", {
        name: `${specialist.id} provider`,
        exact: true,
      });
      await expect(provider).toBeVisible();
      const openAi = (await readTitaniumOptions(provider))
        .find(({ value }) => value === "openai");
      const runtimeBound = RUNTIME_BOUND_AGENT_IDS.has(specialist.id);
      if (runtimeBound) {
        await expect(binding).toContainText(`runtime:${specialist.id.toLocaleLowerCase()}`);
        await expect(binding).toContainText("Runtime version runtime-v1");
        expect(openAi, `${specialist.id} must expose a selectable provider override`)
          .toMatchObject({ label: "openai", disabled: false });
      } else {
        await expect(binding).toContainText(
          "No current runtime manifest maps an executable adapter to this role.",
        );
        await expect(binding).toContainText("Executable bindings");
        await expect(binding).toContainText("0");
        expect(openAi, `${specialist.id} must not appear executable without a runtime binding`)
          .toMatchObject({ label: "openai — unavailable", disabled: true });
        expect((await readTitaniumOptions(provider))
          .filter(({ disabled, value }) => value && !disabled)).toHaveLength(0);
        await expect(editor.getByRole("textbox", {
          name: "Reason for this assignment",
          exact: true,
        })).toBeDisabled();
        await expect(editor.getByRole("button", {
          name: "Save agent assignment",
          exact: true,
        })).toBeDisabled();
      }
      if (modality === "pointer" && runtimeBound) {
        await selectTitaniumOption(provider, "openai", "pointer");
        const primary = editor.getByRole("combobox", {
          name: `${specialist.id} primary model`,
          exact: true,
        });
        expect((await readTitaniumOptions(primary))
          .find(({ value }) => value === "gpt-5.6")).toMatchObject({
          label: "GPT-5.6 · gpt-5.6",
          disabled: false,
        });
        await selectTitaniumOption(primary, "gpt-5.6", "pointer");
        const reasoning = editor.getByRole("combobox", {
          name: `${specialist.id} reasoning effort`,
          exact: true,
        });
        expect((await readTitaniumOptions(reasoning))
          .find(({ value }) => value === "configuration-openai-high"))
          .toMatchObject({ label: "High", disabled: false });
        await expect(editor.getByRole("textbox", {
          name: "Reason for this assignment",
          exact: true,
        })).toBeEnabled();
      }
    }
  }

  expect(model.writes).toHaveLength(0);
  await browserAudit.waitForPageApiSettlement(page);
});

test(`${TEST_FAIL_CLOSED} invents no default, disables unavailable options, and explains an optimistic conflict`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(120_000);
  await installAgentRoutes(page);
  const model = await installModelRoutes(page, {
    scope: "agent",
    resolution: "missing",
    mutation: "conflict",
  });
  browserAudit.expectHttpResponse(page, {
    id: "agent-model-settings.version-conflict",
    transport: "browser",
    method: "PUT",
    pathname: `/api/v2/model-preferences/agent/${AGENT_ID}`,
    query: {},
    status: 409,
    occurrences: 1,
    reason: "Prove a stale model preference never overwrites the newer canonical assignment.",
  });

  await page.goto(`/agents/${AGENT_ID}`, { waitUntil: "domcontentloaded" });
  const editor = page.getByLabel(`${AGENT_NAME} model configuration`, { exact: true });
  await expect(editor).toContainText("No model preference configured");
  await expect(editor.getByText("Loading live model catalog and assignment", { exact: true }))
    .toHaveCount(0);
  await expect(editor).toContainText("Not configured");
  for (const modality of ["pointer", "keyboard"] as const) {
    const workspaceSettings = editor.getByRole("link", {
      name: "Open workspace model settings",
      exact: true,
    });
    await expect(workspaceSettings).toHaveAttribute(
      "data-control-id",
      "agent-model-open-workspace-default",
    );
    await interactionActivation.activate(
      activation(
        "agents.model.open-workspace-default",
        modality,
        TEST_FAIL_CLOSED,
      ),
      async () => {
        if (modality === "pointer") {
          await workspaceSettings.click();
        } else {
          await workspaceSettings.focus();
          await page.keyboard.press("Enter");
        }
        await expect(page).toHaveURL(/\/system\/settings$/u);
        await expect(page.getByLabel(
          "Workspace default model configuration",
          { exact: true },
        )).toBeVisible();
      },
    );
    await page.goto(`/agents/${AGENT_ID}`, { waitUntil: "domcontentloaded" });
    await expect(editor).toContainText("No model preference configured");
  }
  const provider = editor.getByRole("combobox", { name: `${AGENT_NAME} provider`, exact: true });
  const primary = editor.getByRole("combobox", { name: `${AGENT_NAME} primary model`, exact: true });
  await expect(provider).toContainText("Choose an authenticated provider");
  await expect(primary).toBeDisabled();
  await selectReviewedAssignment(
    page,
    AGENT_NAME,
    true,
    interactionActivation,
    TEST_FAIL_CLOSED,
    ["pointer"],
  );

  await interactionActivation.activate(
    activation("agents.model.reason", "pointer", TEST_FAIL_CLOSED),
    () => enterAssignmentReason(
      editor.getByRole("textbox", { name: "Reason for this assignment", exact: true }),
      "Use the reviewed high-reasoning configuration for this specialist.",
      "pointer",
    ),
  );
  const response = page.waitForResponse((candidate) =>
    new URL(candidate.url()).pathname === `/api/v2/model-preferences/agent/${AGENT_ID}`
    && candidate.status() === 409);
  await interactionActivation.activate(
    activation("agents.model.save", "pointer", TEST_FAIL_CLOSED),
    () => editor.getByRole("button", { name: "Save agent assignment", exact: true }).click(),
  );
  expect((await response).status()).toBe(409);
  const alert = editor.getByRole("alert");
  await expect(alert).toContainText("Model assignment was not saved");
  await expect(alert).toContainText("This model assignment changed after the page loaded.");
  await expect(alert).toContainText("Refresh the assignment, review the current model receipt, and save again.");
  await expect(alert).toContainText("trace-model-preference-conflict");
  const tryAgain = alert.getByRole("button", { name: "Try again", exact: true });
  await expect(tryAgain).toBeVisible();
  await expect(tryAgain).toHaveAttribute(
    "data-control-id",
    "agents-model-conflict-retry",
  );
  expect(model.writes[0]?.body).toEqual({
    agentId: AGENT_ID,
    primaryConfigurationId: "configuration-openai-high",
    fallbackConfigurationId: "configuration-openrouter-medium",
    expectedVersion: 0,
    reason: "Use the reviewed high-reasoning configuration for this specialist.",
  });
  expect(model.writes[0]?.headers["idempotency-key"]).toMatch(
    /^(?:[0-9a-f-]{20,}|model-preference-)/u,
  );
  const preferenceReadsBeforeRetry = model.reads.preferences;
  const resolutionReadsBeforeRetry = model.reads.resolution;
  await interactionActivation.activate(
    activation("agents.model.conflict-retry", "pointer", TEST_FAIL_CLOSED),
    async () => {
      const preferenceRefresh = page.waitForResponse((candidate) =>
        new URL(candidate.url()).pathname === "/api/v2/model-preferences"
        && candidate.request().method() === "GET");
      const resolutionRefresh = page.waitForResponse((candidate) =>
        new URL(candidate.url()).pathname === "/api/v2/model-resolution"
        && candidate.request().method() === "GET");
      await tryAgain.click();
      expect((await preferenceRefresh).status()).toBe(200);
      expect((await resolutionRefresh).status()).toBe(200);
    },
  );
  expect(model.reads.preferences).toBe(preferenceReadsBeforeRetry + 1);
  expect(model.reads.resolution).toBe(resolutionReadsBeforeRetry + 1);
  await expect(tryAgain).toBeVisible();
  await tryAgain.focus();
  await interactionActivation.activate(
    activation("agents.model.conflict-retry", "keyboard", TEST_FAIL_CLOSED),
    async () => {
      const preferenceRefresh = page.waitForResponse((candidate) =>
        new URL(candidate.url()).pathname === "/api/v2/model-preferences"
        && candidate.request().method() === "GET");
      const resolutionRefresh = page.waitForResponse((candidate) =>
        new URL(candidate.url()).pathname === "/api/v2/model-resolution"
        && candidate.request().method() === "GET");
      await page.keyboard.press("Enter");
      expect((await preferenceRefresh).status()).toBe(200);
      expect((await resolutionRefresh).status()).toBe(200);
    },
  );
  expect(model.reads.preferences).toBe(preferenceReadsBeforeRetry + 2);
  expect(model.reads.resolution).toBe(resolutionReadsBeforeRetry + 2);
  await expect(editor).toContainText("No model preference configured");
  expect(model.writes).toHaveLength(1);
  await browserAudit.waitForPageApiSettlement(page);
});

test(`${TEST_FAIL_CLOSED} keeps failed catalog choices retired until an authoritative retry succeeds`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(120_000);
  await installAgentRoutes(page);
  const model = await installModelRoutes(page, {
    scope: "agent",
    resolution: "missing",
    mutation: "success",
    catalogInitiallyAvailable: false,
  });
  browserAudit.expectHttpResponse(page, {
    id: "agent-model-settings.catalog-unavailable",
    transport: "browser",
    method: "GET",
    pathname: "/api/v2/model-catalog",
    query: {},
    status: 503,
    occurrences: 2,
    reason: "Prove an unavailable catalog and one failed retry cannot revive retained model choices.",
  });

  await page.goto(`/agents/${AGENT_ID}`, { waitUntil: "domcontentloaded" });
  const editor = page.getByLabel(`${AGENT_NAME} model configuration`, { exact: true });
  await expect(editor.getByRole("alert")).toContainText(
    "The live model catalog could not be refreshed.",
  );
  await expect(editor.getByRole("combobox")).toHaveCount(0);
  await expect(editor.getByRole("button", {
    name: "Save agent assignment",
    exact: true,
  })).toHaveCount(0);

  let retry = editor.getByRole("button", { name: "Try again", exact: true });
  await expect(retry).toHaveAttribute(
    "data-control-id",
    "agents-model-load-retry",
  );
  await interactionActivation.activate(
    activation("agents.model.load-retry", "pointer", TEST_FAIL_CLOSED),
    async () => {
      const failedRefresh = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/api/v2/model-catalog"
        && response.status() === 503);
      await retry.click();
      await failedRefresh;
    },
  );
  await expect(editor.getByRole("combobox")).toHaveCount(0);
  await expect(editor.getByRole("alert")).toContainText(
    "Restore the provider catalog service, then try again.",
  );

  model.setCatalogAvailable(true);
  retry = editor.getByRole("button", { name: "Try again", exact: true });
  await retry.focus();
  await interactionActivation.activate(
    activation("agents.model.load-retry", "keyboard", TEST_FAIL_CLOSED),
    async () => {
      const recovered = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/api/v2/model-catalog"
        && response.status() === 200);
      await page.keyboard.press("Enter");
      await recovered;
    },
  );
  await expect(editor.getByRole("alert")).toHaveCount(0);
  await expect(editor.getByRole("combobox", {
    name: `${AGENT_NAME} provider`,
    exact: true,
  })).toBeVisible();
  await expect(editor.getByRole("button", {
    name: "Save agent assignment",
    exact: true,
  })).toBeDisabled();
  expect(model.writes).toHaveLength(0);
  await browserAudit.waitForPageApiSettlement(page);
});

test(`${TEST_GLOBAL_DEFAULT} uses the same application-owned selectors for the workspace default`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(240_000);
  const model = await installModelRoutes(page, {
    scope: "global",
    resolution: "missing",
    mutation: "success",
  });
  await page.goto("/system/settings", { waitUntil: "domcontentloaded" });
  const editor = page.getByLabel("Workspace default model configuration", { exact: true });
  await expect(editor).toContainText("No model preference configured");
  await selectReviewedAssignment(
    page,
    "Workspace default",
    false,
    interactionActivation,
    TEST_GLOBAL_DEFAULT,
    ["pointer", "keyboard"],
  );
  const reason = editor.getByRole("textbox", { name: "Reason for this assignment", exact: true });
  await expect(reason).toHaveAttribute("data-control-id", "system-model-reason");
  await interactionActivation.activate(
    activation("system.model.reason", "pointer", TEST_GLOBAL_DEFAULT),
    () => enterAssignmentReason(
      reason,
      "Review the attested workspace default.",
      "pointer",
    ),
  );
  await interactionActivation.activate(
    activation("system.model.reason", "keyboard", TEST_GLOBAL_DEFAULT),
    () => enterAssignmentReason(
      reason,
      "Use this attested model as the fail-closed workspace default.",
      "keyboard",
    ),
  );
  const response = page.waitForResponse((candidate) =>
    new URL(candidate.url()).pathname === "/api/v2/model-preferences/global/global"
    && candidate.request().method() === "PUT");
  await interactionActivation.activate(
    activation("system.model.save", "pointer", TEST_GLOBAL_DEFAULT),
    () => editor.getByRole("button", { name: "Save workspace default", exact: true }).click(),
  );
  expect((await response).status()).toBe(200);
  await expect(editor).toContainText("Preference version 1");
  await expect(editor).toContainText(
    "Saved rationale: Use this attested model as the fail-closed workspace default.",
  );

  const reasoning = editor.getByRole("combobox", {
    name: "Workspace default reasoning effort",
    exact: true,
  });
  await selectTitaniumOption(reasoning, "configuration-openai-medium", "pointer");
  await enterAssignmentReason(
    reason,
    "Use the medium reasoning profile for the second audited save path.",
    "pointer",
  );
  const keyboardResponse = page.waitForResponse((candidate) =>
    new URL(candidate.url()).pathname === "/api/v2/model-preferences/global/global"
    && candidate.request().method() === "PUT");
  const save = editor.getByRole("button", { name: "Save workspace default", exact: true });
  await expect(save).toHaveAttribute("data-control-id", "system-model-save");
  await save.focus();
  await interactionActivation.activate(
    activation("system.model.save", "keyboard", TEST_GLOBAL_DEFAULT),
    () => page.keyboard.press("Enter"),
  );
  expect((await keyboardResponse).status()).toBe(200);
  await expect(editor).toContainText("Preference version 2");
  await expect(editor).toContainText(
    "Saved rationale: Use the medium reasoning profile for the second audited save path.",
  );

  expect(model.writes).toHaveLength(2);
  expect(model.writes[0]?.body).toEqual({
    agentId: null,
    primaryConfigurationId: "configuration-openai-high",
    fallbackConfigurationId: "configuration-openrouter-medium",
    expectedVersion: 0,
    reason: "Use this attested model as the fail-closed workspace default.",
  });
  expect(model.writes[1]?.body).toEqual({
    agentId: null,
    primaryConfigurationId: "configuration-openai-medium",
    fallbackConfigurationId: "configuration-openrouter-medium",
    expectedVersion: 1,
    reason: "Use the medium reasoning profile for the second audited save path.",
  });
  const firstIdempotencyKey = model.writes[0]?.headers["idempotency-key"];
  const secondIdempotencyKey = model.writes[1]?.headers["idempotency-key"];
  expect(firstIdempotencyKey).toMatch(/^(?:[0-9a-f-]{20,}|model-preference-)/u);
  expect(secondIdempotencyKey).toMatch(/^(?:[0-9a-f-]{20,}|model-preference-)/u);
  expect(secondIdempotencyKey).not.toBe(firstIdempotencyKey);
  await browserAudit.waitForPageApiSettlement(page);
});

test(`${TEST_GLOBAL_DEFAULT} recovers the workspace editor only after a fresh catalog succeeds`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(120_000);
  const model = await installModelRoutes(page, {
    scope: "global",
    resolution: "missing",
    mutation: "success",
    catalogInitiallyAvailable: false,
  });
  browserAudit.expectHttpResponse(page, {
    id: "workspace-model-settings.catalog-unavailable",
    transport: "browser",
    method: "GET",
    pathname: "/api/v2/model-catalog",
    query: {},
    status: 503,
    occurrences: 2,
    reason: "Prove the workspace default cannot use retained model choices while catalog refresh fails.",
  });

  await page.goto("/system/settings", { waitUntil: "domcontentloaded" });
  const editor = page.getByLabel(
    "Workspace default model configuration",
    { exact: true },
  );
  await expect(editor.getByRole("combobox")).toHaveCount(0);
  let retry = editor.getByRole("button", { name: "Try again", exact: true });
  await expect(retry).toHaveAttribute(
    "data-control-id",
    "system-model-load-retry",
  );
  await interactionActivation.activate(
    activation("system.model.load-retry", "pointer", TEST_GLOBAL_DEFAULT),
    async () => {
      const failedRefresh = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/api/v2/model-catalog"
        && response.status() === 503);
      await retry.click();
      await failedRefresh;
    },
  );
  await expect(editor.getByRole("combobox")).toHaveCount(0);

  model.setCatalogAvailable(true);
  retry = editor.getByRole("button", { name: "Try again", exact: true });
  await retry.focus();
  await interactionActivation.activate(
    activation("system.model.load-retry", "keyboard", TEST_GLOBAL_DEFAULT),
    async () => {
      const recovered = page.waitForResponse((response) =>
        new URL(response.url()).pathname === "/api/v2/model-catalog"
        && response.status() === 200);
      await page.keyboard.press("Enter");
      await recovered;
    },
  );
  await expect(editor.getByRole("alert")).toHaveCount(0);
  await expect(editor.getByRole("combobox", {
    name: "Workspace default provider",
    exact: true,
  })).toBeVisible();
  await expect(editor.getByRole("button", {
    name: "Save workspace default",
    exact: true,
  })).toBeDisabled();
  expect(model.writes).toHaveLength(0);
  await browserAudit.waitForPageApiSettlement(page);
});

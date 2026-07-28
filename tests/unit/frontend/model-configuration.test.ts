/// <reference lib="dom" />

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  fetchModelCatalog,
  fetchModelConfigurations,
  fetchModelPreferences,
  fetchModelResolution,
  updateModelPreference,
} from "../../../src/data/api/modelConfiguration";
import {
  parseModelCatalog,
  parseModelConfigurations,
  parseModelPreferenceMutation,
  parseModelPreferences,
  parseModelResolution,
} from "../../../src/domain/schemas/modelConfiguration";

const NOW = "2026-07-23T13:00:00.000Z";

function catalogItem(overrides: Record<string, unknown> = {}) {
  return {
    configurationId: "configuration-openai-high",
    providerId: "openai",
    modelId: "gpt-5.6",
    displayName: "GPT-5.6",
    executionBoundary: "provider_tool_calling",
    reasoningEffort: "high",
    supportedReasoningEfforts: ["low", "medium", "high"],
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
      compatibleActionClassIds: ["active_host_discovery", "port_service_enumeration"],
      localDeterministicActionClassIdsByAgent: {},
    },
    compatibleAgentIds: ["recon-scout"],
    selectable: true,
    unavailableReasons: [],
    ...overrides,
  };
}

function configuration(overrides: Record<string, unknown> = {}) {
  return {
    id: "configuration-openai-high",
    providerId: "openai",
    modelId: "gpt-5.6",
    displayName: "GPT-5.6",
    executionBoundary: "provider_tool_calling",
    reasoningEffort: "high",
    contextPolicy: { maximumContextTokens: 120_000 },
    capabilities: { toolCalling: true, structuredOutput: true },
    contextLimit: 400_000,
    costClass: "premium",
    latencyClass: "deliberate",
    disclosureClass: "public_provider_sanitized",
    enforcementMode: "enforced_executor",
    authState: "authenticated",
    healthState: "healthy",
    catalogSource: "runtime_source_manifest",
    catalogRetrievedAt: NOW,
    configurationSource: "manual",
    version: 3,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

function preference(overrides: Record<string, unknown> = {}) {
  return {
    id: "model-preference-recon",
    scopeType: "agent",
    scopeId: "recon-scout",
    agentId: "recon-scout",
    primaryConfigurationId: "configuration-openai-high",
    fallbackConfigurationId: null,
    resolutionReason: "Use the attested model for reconnaissance.",
    version: 4,
    createdBy: "operator-one",
    createdAt: NOW,
    updatedBy: "operator-one",
    updatedAt: NOW,
    ...overrides,
  };
}

function resolution(overrides: Record<string, unknown> = {}) {
  return {
    agentId: "recon-scout",
    context: { missionId: null, runId: null, stepId: null },
    source: {
      scopeType: "global",
      scopeId: "global",
      preferenceId: "model-preference-global",
      preferenceVersion: 2,
    },
    primaryConfiguration: configuration(),
    fallbackConfiguration: null,
    resolvedAt: NOW,
    ...overrides,
  };
}

function availability(status: "configured" | "unconfigured" = "configured") {
  return {
    status,
    agentId: "recon-scout",
    humanMessage: status === "configured"
      ? "This agent has a model assignment for the requested scope."
      : "This agent does not have a model assignment for the requested scope.",
    remediation: status === "configured"
      ? null
      : "Choose a compatible provider and model on the agent profile, or configure a global default.",
  };
}

function assignmentSemantics() {
  return {
    purpose: "execution",
    preferenceResolutionOrder:
      "global_then_agent_then_mission_then_run_then_step",
    saveEffect: "future_resolutions_only",
    activeRunPinning: "immutable",
    planningRoute: "autonomous_mission_contract",
  };
}

interface FetchCall {
  readonly path: string;
  readonly init?: RequestInit;
}

let originalFetch: typeof globalThis.fetch;
let originalDocument: PropertyDescriptor | undefined;
let calls: FetchCall[];
let responses: unknown[];

beforeEach(() => {
  originalFetch = globalThis.fetch;
  originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  calls = [];
  responses = [];
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: { cookie: "ti_scale_csrf=csrf-model-settings" },
  });
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ path: typeof input === "string" ? input : input.toString(), init });
    const payload = responses.shift();
    if (payload === undefined) throw new Error("No mocked model-configuration response remains");
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "X-Request-Id": "request-model-settings",
      },
    });
  }) as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalDocument) Object.defineProperty(globalThis, "document", originalDocument);
  else Reflect.deleteProperty(globalThis, "document");
});

describe("model configuration schema boundary", () => {
  test("accepts the exact catalog, preference, configuration, and inherited-resolution contract", () => {
    expect(parseModelCatalog({
      schemaVersion: "2.4",
      observedAt: NOW,
      items: [catalogItem()],
    }).items[0]).toMatchObject({
      configurationId: "configuration-openai-high",
      executionBoundary: "provider_tool_calling",
      enforcementMode: "enforced_executor",
      selectable: true,
    });
    expect(parseModelConfigurations({
      schemaVersion: "2.4",
      items: [configuration()],
    }).items[0]?.version).toBe(3);
    expect(parseModelPreferences({
      schemaVersion: "2.4",
      items: [preference()],
    }).items[0]).toMatchObject({
      scopeType: "agent",
      scopeId: "recon-scout",
      version: 4,
    });
    expect(parseModelPreferenceMutation({
      schemaVersion: "2.4",
      preference: preference({ version: 5 }),
    }).preference.version).toBe(5);
    expect(parseModelResolution({
      schemaVersion: "2.4",
      assignmentSemantics: assignmentSemantics(),
      resolution: resolution(),
      availability: availability(),
    }).resolution).toMatchObject({
      agentId: "recon-scout",
      source: { scopeType: "global", scopeId: "global", preferenceVersion: 2 },
      primaryConfiguration: { id: "configuration-openai-high" },
    });
    expect(parseModelResolution({
      schemaVersion: "2.4",
      assignmentSemantics: assignmentSemantics(),
      resolution: null,
      availability: availability("unconfigured"),
    })).toMatchObject({
      resolution: null,
      availability: {
        status: "unconfigured",
        agentId: "recon-scout",
      },
    });
  });

  test("rejects unsupported enum values, malformed versions, and invalid live catalog fields", () => {
    expect(() => parseModelCatalog({
      schemaVersion: "2.4",
      observedAt: NOW,
      items: [catalogItem({ enforcementMode: "pretend_executor" })],
    })).toThrow("model enforcementMode is invalid");
    expect(() => parseModelCatalog({
      schemaVersion: "2.4",
      observedAt: NOW,
      items: [catalogItem({ authState: "logged_in_maybe" })],
    })).toThrow("model authState is invalid");
    expect(() => parseModelCatalog({
      schemaVersion: "2.4",
      observedAt: NOW,
      items: [catalogItem({ healthState: "green" })],
    })).toThrow("model healthState is invalid");
    expect(() => parseModelCatalog({
      schemaVersion: "2.4",
      observedAt: NOW,
      items: [catalogItem({ executionBoundary: "imaginary_boundary" })],
    })).toThrow("model executionBoundary is invalid");
    expect(() => parseModelCatalog({
      schemaVersion: "2.4",
      observedAt: NOW,
      items: [catalogItem({
        capabilities: {
          toolCalling: false,
          structuredOutput: true,
          compatibleActionClassIds: ["active_host_discovery"],
          localDeterministicActionClassIdsByAgent: {
            "recon-scout": "active_host_discovery",
          },
        },
      })],
    })).toThrow("localDeterministicActionClassIdsByAgent.recon-scout must be an array");
    expect(() => parseModelCatalog({
      schemaVersion: "2.4",
      observedAt: NOW,
      items: [catalogItem({ contextLimit: 0 })],
    })).toThrow("contextLimit must be a positive whole number or null");
    expect(() => parseModelCatalog({
      schemaVersion: "2.4",
      observedAt: NOW,
      items: [catalogItem({ compatibleAgentIds: "recon-scout" })],
    })).toThrow("compatibleAgentIds must be an array");
    expect(() => parseModelConfigurations({
      schemaVersion: "2.4",
      items: [configuration({ version: 1.5 })],
    })).toThrow("version must be a positive whole number");
    expect(() => parseModelPreferences({
      schemaVersion: "2.4",
      items: [preference({ scopeType: "workspace-ish" })],
    })).toThrow("model preference scopeType is invalid");
    expect(() => parseModelResolution({
      schemaVersion: "2.4",
      assignmentSemantics: assignmentSemantics(),
      resolution: resolution({
        source: {
          scopeType: "global",
          scopeId: "global",
          preferenceId: "model-preference-global",
          preferenceVersion: 0,
        },
      }),
      availability: availability(),
    })).toThrow("preferenceVersion must be positive");
    expect(() => parseModelResolution({
      schemaVersion: "2.4",
      assignmentSemantics: assignmentSemantics(),
      resolution: null,
      availability: availability(),
    })).toThrow("availability must be unconfigured");
    expect(() => parseModelResolution({
      schemaVersion: "2.4",
      assignmentSemantics: {
        ...assignmentSemantics(),
        purpose: "planning",
      },
      resolution: resolution(),
      availability: availability(),
    })).toThrow("assignment purpose is invalid");
    expect(() => parseModelResolution({
      schemaVersion: "2.4",
      resolution: resolution(),
      availability: availability(),
    })).toThrow("assignmentSemantics");
    expect(() => parseModelCatalog({
      schemaVersion: "2.3",
      observedAt: NOW,
      items: [],
    })).toThrow("unsupported Ti-Scale schema version");
  });
});

describe("model configuration API client", () => {
  test("reads the live catalog, exact configurations, scoped preferences, and inherited resolution", async () => {
    responses.push(
      { schemaVersion: "2.4", observedAt: NOW, items: [catalogItem()] },
      { schemaVersion: "2.4", items: [configuration()] },
      { schemaVersion: "2.4", items: [preference()] },
      {
        schemaVersion: "2.4",
        assignmentSemantics: assignmentSemantics(),
        resolution: resolution(),
        availability: availability(),
      },
    );
    const signal = new AbortController().signal;

    expect((await fetchModelCatalog(signal)).items[0]?.modelId).toBe("gpt-5.6");
    expect((await fetchModelConfigurations(
      ["configuration/openai high", "fallback:local"],
      signal,
    )).items[0]?.id).toBe("configuration-openai-high");
    expect((await fetchModelPreferences({
      scopeType: "agent",
      scopeId: "recon/scout",
      agentId: "recon-scout",
    }, signal)).items[0]?.scopeType).toBe("agent");
    expect((await fetchModelResolution({
      agentId: "recon/scout",
      missionId: "mission one",
      runId: "run/one",
      stepId: "step:one",
    }, signal)).resolution?.source.scopeType).toBe("global");

    expect(calls.map((call) => call.path)).toEqual([
      "/api/v2/model-catalog",
      "/api/v2/model-configurations?ids=configuration%2Fopenai+high%2Cfallback%3Alocal",
      "/api/v2/model-preferences?scopeType=agent&scopeId=recon%2Fscout&agentId=recon-scout",
      "/api/v2/model-resolution?agentId=recon%2Fscout&missionId=mission+one&runId=run%2Fone&stepId=step%3Aone",
    ]);
    expect(calls.every((call) => call.init?.method === "GET")).toBe(true);
    expect(calls.every((call) => call.init?.signal === signal)).toBe(true);
  });

  test("writes one exact scoped preference with optimistic version and caller-owned idempotency", async () => {
    responses.push({
      schemaVersion: "2.4",
      preference: preference({ version: 5 }),
    });

    const result = await updateModelPreference(
      "agent",
      "recon/scout",
      {
        agentId: "recon-scout",
        primaryConfigurationId: "configuration-openai-high",
        fallbackConfigurationId: "configuration-local-safe",
        expectedVersion: 4,
        reason: "Use the attested tool-capable model for reconnaissance.",
      },
      undefined,
      "model-preference-agent-recon-0001",
    );

    expect(result.preference.version).toBe(5);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.path).toBe("/api/v2/model-preferences/agent/recon%2Fscout");
    expect(calls[0]?.init?.method).toBe("PUT");
    const headers = new Headers(calls[0]?.init?.headers);
    expect(headers.get("Idempotency-Key")).toBe("model-preference-agent-recon-0001");
    expect(headers.get("X-Ti-Scale-CSRF")).toBe("csrf-model-settings");
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual({
      agentId: "recon-scout",
      primaryConfigurationId: "configuration-openai-high",
      fallbackConfigurationId: "configuration-local-safe",
      expectedVersion: 4,
      reason: "Use the attested tool-capable model for reconnaissance.",
    });
  });
});

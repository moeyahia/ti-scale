/// <reference lib="dom" />

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  fetchOpenRouterConnection,
  refreshOpenRouterAttestation,
  updateOpenRouterConnection,
} from "../../../src/data/api/providerConnections";
import {
  parseOpenRouterAttestationRefresh,
  parseOpenRouterConnection,
} from "../../../src/domain/schemas/providerConnections";

const NOW = "2026-07-24T12:00:00.000Z";
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

function connection(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "ti-scale.openrouter-connection.v1",
    providerId: "openrouter",
    configuration: {
      source: "canonical_provider_config",
      version: 2,
      enabled: true,
      model: "openai/gpt-5.2",
      credentialConfigured: true,
      updatedAt: NOW,
      updatedBy: "operator:test",
      storage: "service_owned_mode_0600",
      browserStorage: false,
    },
    activation: {
      activeConfigurationVersion: 1,
      configuredVersion: 2,
      restartRequired: true,
      status: "restart_required",
      humanMessage: "Restart Ti-Scale to load this exact version.",
    },
    runtime: {
      status: "degraded",
      configured: true,
      authenticated: false,
      callable: false,
      supportsGuided: false,
      enforcesAutonomousBoundary: false,
      reportsExactTokenUsage: false,
      reportsExactCostUsage: false,
      requestedModel: "openai/gpt-5.2",
      returnedModel: null,
      lastCheckedAt: NOW,
      attestedAt: null,
      expiresAt: null,
      failureCode: null,
      remediation: null,
      reason: "The saved version is not loaded by this process.",
    },
    planningCompatibility: {
      enforcementMode: "advisor_only",
      compatibleAgentIds: [...AGENTS],
      localExecutionAuthorityUnchanged: true,
      explanation: "OpenRouter advises while local adapters retain execution authority.",
    },
    ...overrides,
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
    value: { cookie: "ti_scale_csrf=csrf-openrouter" },
  });
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({
      path: typeof input === "string" ? input : input.toString(),
      init,
    });
    const payload = responses.shift();
    if (payload === undefined) throw new Error("No mocked OpenRouter response remains");
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "X-Request-Id": "request-openrouter",
      },
    });
  }) as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalDocument) Object.defineProperty(globalThis, "document", originalDocument);
  else Reflect.deleteProperty(globalThis, "document");
});

describe("OpenRouter connection frontend boundary", () => {
  test("accepts only the secret-free advisor-only connection contract", () => {
    const parsed = parseOpenRouterConnection(connection());
    expect(parsed.configuration).toMatchObject({
      storage: "service_owned_mode_0600",
      browserStorage: false,
      credentialConfigured: true,
    });
    expect(parsed.planningCompatibility).toMatchObject({
      enforcementMode: "advisor_only",
      compatibleAgentIds: [...AGENTS],
      localExecutionAuthorityUnchanged: true,
    });

    expect(() => parseOpenRouterConnection(connection({
      configuration: {
        ...(connection().configuration as Record<string, unknown>),
        browserStorage: true,
      },
    }))).toThrow("must never use browser storage");
    expect(() => parseOpenRouterConnection(connection({
      planningCompatibility: {
        ...(connection().planningCompatibility as Record<string, unknown>),
        localExecutionAuthorityUnchanged: false,
      },
    }))).toThrow("must not inherit local execution authority");
    expect(() => parseOpenRouterConnection(connection({
      runtime: {
        ...(connection().runtime as Record<string, unknown>),
        enforcesAutonomousBoundary: true,
      },
    }))).toThrow("must remain outside the Autonomous execution boundary");
  });

  test("uses authenticated same-origin GET/PUT contracts without browser persistence", async () => {
    const privateKey = "sk-or-v1-private-frontend-test-value";
    responses.push(
      connection(),
      connection(),
      {
        schemaVersion: "ti-scale.openrouter-connection.v1",
        providerId: "openrouter",
        replayed: false,
        connection: connection(),
      },
    );

    await fetchOpenRouterConnection(new AbortController().signal);
    await updateOpenRouterConnection({
      enabled: true,
      model: "openai/gpt-5.2",
      credential: { action: "replace", value: privateKey },
      expectedVersion: 2,
    }, undefined, "openrouter-ui-save-0001");
    await refreshOpenRouterAttestation(
      2,
      undefined,
      "openrouter-ui-attest-0001",
    );

    expect(calls.map(({ path }) => path)).toEqual([
      "/api/v2/provider-connections/openrouter",
      "/api/v2/provider-connections/openrouter",
      "/api/v2/provider-connections/openrouter/attestation",
    ]);
    expect(calls[0]?.init).toMatchObject({
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
    });
    expect(calls[1]?.init).toMatchObject({
      method: "PUT",
      credentials: "same-origin",
      headers: expect.objectContaining({
        "Idempotency-Key": "openrouter-ui-save-0001",
        "X-Ti-Scale-CSRF": "csrf-openrouter",
      }),
    });
    expect(JSON.parse(String(calls[1]?.init?.body))).toEqual({
      enabled: true,
      model: "openai/gpt-5.2",
      credential: { action: "replace", value: privateKey },
      expectedVersion: 2,
    });
    expect(calls[2]?.init).toMatchObject({
      method: "PUT",
      headers: expect.objectContaining({
        "Idempotency-Key": "openrouter-ui-attest-0001",
        "X-Ti-Scale-CSRF": "csrf-openrouter",
      }),
    });
    expect(JSON.parse(String(calls[2]?.init?.body))).toEqual({
      expectedVersion: 2,
    });
    expect(parseOpenRouterAttestationRefresh({
      schemaVersion: "ti-scale.openrouter-connection.v1",
      providerId: "openrouter",
      replayed: false,
      connection: connection(),
    }).connection.configuration).not.toHaveProperty("credential");
  });
});

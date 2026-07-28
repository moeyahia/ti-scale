import { describe, expect, test } from "bun:test";
import {
  createProductionOpenRouterReadinessRuntime,
  OpenRouterPlanningError,
  OpenRouterReadinessRuntime,
  resolveOpenRouterGuidedStandaloneConfiguration,
  type OpenRouterModelAttestation,
} from "../../../../server/providers/openrouter";

function configuration() {
  const result = resolveOpenRouterGuidedStandaloneConfiguration({
    TI_SCALE_OPENROUTER_GUIDED_ENABLED: "true",
    TI_SCALE_OPENROUTER_CREDENTIAL_PATH: "/run/credentials/ti-scale/openrouter-api-key",
    TI_SCALE_OPENROUTER_MODEL: "openai/gpt-5.2",
  });
  if (result.state !== "configured_unattested") throw new Error("fixture configuration failed");
  return result;
}

function attestation(callable: boolean): OpenRouterModelAttestation {
  const config = configuration();
  return {
    schemaVersion: "ti-scale.openrouter-model-attestation.v2",
    providerId: "openrouter",
    model: config.modelConfiguration.model,
    modelConfigurationHash: config.modelConfiguration.configurationHash,
    authenticated: true,
    keyEligibility: "verified_completion_key",
    metadataSupportsGuided: true,
    callable,
    callabilityVerification: callable ? "audited_content_free_completion" : "unverified",
    supportsGuided: callable,
    enforcesAutonomousBoundary: false,
    reportsExactTokenUsage: callable,
    reportsExactCostUsage: callable,
    contextLength: 400_000,
    supportedParameters: ["response_format", "structured_outputs", "tool_choice", "tools"],
    pricing: {
      promptUsdPerToken: "0.00000175",
      completionUsdPerToken: "0.000014",
      provenance: "advertised_model_metadata",
    },
    ...(callable ? {
      completionProbeReceiptId: "provider-request-readiness",
      completionReturnedModel: "openai/gpt-5.2-20260718",
    } : {}),
    attestedAt: "2026-07-18T19:00:00.000Z",
    expiresAt: "2026-07-18T19:05:00.000Z",
    latencyMs: 12,
  };
}

describe("OpenRouter readiness runtime", () => {
  test("uses the already-resolved canonical connection configuration instead of rereading process environment", async () => {
    const runtime = createProductionOpenRouterReadinessRuntime({
      configuration: configuration(),
      credentialReader: () => "test-key-not-read-without-refresh",
      now: () => new Date("2026-07-18T18:59:00.000Z"),
    });
    expect(runtime.snapshot()).toMatchObject({
      status: "degraded",
      configured: true,
      authenticated: false,
      callable: false,
      requestedModel: "openai/gpt-5.2",
    });
    expect(() => createProductionOpenRouterReadinessRuntime({
      configuration: configuration(),
      environment: {},
    })).toThrow("either a resolved configuration or an environment");
    await runtime.stop();
  });

  test("timestamps the local provider-registry observation even when OpenRouter is disabled", async () => {
    const runtime = new OpenRouterReadinessRuntime({
      configuration: resolveOpenRouterGuidedStandaloneConfiguration({}),
      now: () => new Date("2026-07-18T18:59:00.000Z"),
    });
    expect(runtime.snapshot()).toMatchObject({
      status: "disabled",
      configured: false,
      authenticated: false,
      callable: false,
      lastCheckedAt: "2026-07-18T18:59:00.000Z",
    });
    await runtime.stop();
  });

  test("retains authenticated exact-model metadata but stays non-callable without a durable completion receipt", async () => {
    const runtime = new OpenRouterReadinessRuntime({
      configuration: configuration(),
      probe: { async attest() { return attestation(false); } },
      now: () => new Date("2026-07-18T19:00:01.000Z"),
    });
    expect(await runtime.refreshNow()).toMatchObject({
      status: "degraded",
      configured: true,
      authenticated: true,
      callable: false,
      supportsGuided: false,
      requestedModel: "openai/gpt-5.2",
      modelConfigurationHash: expect.stringMatching(/^[a-f0-9]{64}$/u),
      contextLength: 400_000,
    });
    expect(runtime.snapshot().completionProbeReceiptId).toBeUndefined();
    await runtime.stop();
  });

  test("becomes Guided-callable only with exact returned model, receipt, and usage truth", async () => {
    const runtime = new OpenRouterReadinessRuntime({
      configuration: configuration(),
      probe: { async attest() { return attestation(true); } },
      now: () => new Date("2026-07-18T19:00:01.000Z"),
    });
    expect(await runtime.refreshNow()).toMatchObject({
      status: "ready",
      authenticated: true,
      callable: true,
      supportsGuided: true,
      enforcesAutonomousBoundary: false,
      requestedModel: "openai/gpt-5.2",
      returnedModel: "openai/gpt-5.2-20260718",
      completionProbeReceiptId: "provider-request-readiness",
      reportsExactTokenUsage: true,
      reportsExactCostUsage: true,
    });
    await runtime.stop();
  });

  test("redacts provider failures and expires attestation fail-closed", async () => {
    let now = new Date("2026-07-18T19:00:01.000Z");
    const runtime = new OpenRouterReadinessRuntime({
      configuration: configuration(),
      probe: { async attest() { return attestation(true); } },
      now: () => now,
    });
    await runtime.refreshNow();
    now = new Date("2026-07-18T19:06:00.000Z");
    const expired = runtime.snapshot();
    expect(expired).toMatchObject({
      status: "degraded",
      authenticated: false,
      callable: false,
      failureCode: "openrouter_attestation_expired",
      failureCategory: "provider_unavailable",
      failureRetryable: true,
      failureHttpStatus: 503,
    });
    expect(expired.completionProbeReceiptId).toBeUndefined();
    await runtime.stop();

    const secret = "sk-or-v1-secret-must-not-escape";
    const failed = new OpenRouterReadinessRuntime({
      configuration: configuration(),
      probe: {
        async attest() {
          throw new OpenRouterPlanningError("openrouter_authentication_failed", secret, {
            status: 503,
            category: "authentication_failed",
            retryable: false,
          });
        },
      },
    });
    const snapshot = await failed.refreshNow();
    expect(snapshot).toMatchObject({
      status: "degraded",
      authenticated: false,
      failureCode: "openrouter_authentication_failed",
      failureCategory: "authentication_failed",
      failureRetryable: false,
      failureHttpStatus: 503,
    });
    expect(JSON.stringify(snapshot)).not.toContain(secret);
    await failed.stop();
  });
});

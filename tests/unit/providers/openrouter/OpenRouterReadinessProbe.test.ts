import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  OPENROUTER_CURRENT_KEY_ENDPOINT,
  OpenRouterPlanningError,
  OpenRouterReadinessProbe,
} from "../../../../server/providers/openrouter";

const SECRET = "sk-or-v1-test-secret-value-that-must-never-escape";
const MODEL_ENDPOINT = "https://openrouter.ai/api/v1/model/openai/gpt-5.2";
const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function credential(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-openrouter-readiness-"));
  directories.push(directory);
  chmodSync(directory, 0o700);
  const path = join(directory, "key");
  writeFileSync(path, SECRET, { mode: 0o600 });
  return path;
}

function json(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function model(parameters = ["tools", "tool_choice", "response_format", "structured_outputs"]) {
  return {
    data: {
      id: "openai/gpt-5.2",
      canonical_slug: "openai/gpt-5.2",
      context_length: 400_000,
      supported_parameters: parameters,
      pricing: { prompt: "0.00000175", completion: "0.000014" },
    },
  };
}

function key(overrides: Record<string, unknown> = {}) {
  return {
    data: {
      is_management_key: false,
      is_provisioning_key: false,
      limit_remaining: 25,
      expires_at: null,
      ...overrides,
    },
  };
}

async function planningError(promise: Promise<unknown>): Promise<OpenRouterPlanningError> {
  try {
    await promise;
  } catch (failure) {
    expect(failure).toBeInstanceOf(OpenRouterPlanningError);
    return failure as OpenRouterPlanningError;
  }
  throw new Error("Expected OpenRouter readiness rejection");
}

describe("OpenRouter metadata-only readiness probe", () => {
  test("authenticates the key and pins one Guided-capable model without sending mission data", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const probe = new OpenRouterReadinessProbe({
      credentialPath: credential(),
      now: () => new Date("2026-07-18T19:00:00.000Z"),
      fetch: async (input, init) => {
        calls.push({ url: input.toString(), init: init ?? {} });
        return input.toString() === OPENROUTER_CURRENT_KEY_ENDPOINT
          ? json(key())
          : json(model());
      },
    });
    const result = await probe.attest();
    expect(calls.map((call) => call.url)).toEqual([
      OPENROUTER_CURRENT_KEY_ENDPOINT,
      MODEL_ENDPOINT,
    ]);
    for (const call of calls) {
      expect(call.init).toMatchObject({ method: "GET", redirect: "error" });
      expect(new Headers(call.init.headers).get("authorization")).toBe(`Bearer ${SECRET}`);
      expect(call.init.body).toBeUndefined();
    }
    expect(result).toMatchObject({
      providerId: "openrouter",
      model: "openai/gpt-5.2",
      authenticated: true,
      callable: false,
      callabilityVerification: "unverified",
      supportsGuided: false,
      enforcesAutonomousBoundary: false,
      reportsExactTokenUsage: false,
      reportsExactCostUsage: false,
      contextLength: 400_000,
      pricing: {
        promptUsdPerToken: "0.00000175",
        completionUsdPerToken: "0.000014",
      },
      attestedAt: "2026-07-18T19:00:00.000Z",
      expiresAt: "2026-07-18T19:05:00.000Z",
    });
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });

  test("fails closed when structured output or explicit tool denial support disappears", async () => {
    const probe = new OpenRouterReadinessProbe({
      credentialPath: credential(),
      fetch: async (input) => input.toString() === OPENROUTER_CURRENT_KEY_ENDPOINT
        ? json(key())
        : json(model(["response_format", "structured_outputs"])),
    });
    const failure = await planningError(probe.attest());
    expect(failure).toMatchObject({
      code: "openrouter_model_parameters_unavailable",
      retryable: false,
    });
    expect(JSON.stringify(failure)).not.toContain(SECRET);
  });

  test("maps authentication, rate-limit, redirect, oversize, and cancellation failures safely", async () => {
    const failures: ReadonlyArray<readonly [Response, string]> = [
      [json({ error: SECRET }, 401), "openrouter_authentication_failed"],
      [json({ error: SECRET }, 429), "openrouter_rate_limited"],
      [new Response(null, { status: 302, headers: { location: "https://evil.invalid" } }), "openrouter_readiness_redirect_denied"],
      [new Response("{}", {
        status: 200,
        headers: { "content-type": "application/json", "content-length": "999999" },
      }), "openrouter_readiness_response_too_large"],
    ];
    for (const [response, code] of failures) {
      const probe = new OpenRouterReadinessProbe({
        credentialPath: credential(),
        maximumResponseBytes: 4_096,
        fetch: async () => response,
      });
      const failure = await planningError(probe.attest());
      expect(failure.code).toBe(code);
      expect(JSON.stringify(failure)).not.toContain(SECRET);
    }

    const abort = new AbortController();
    abort.abort();
    const cancelled = await planningError(new OpenRouterReadinessProbe({
      credentialPath: credential(),
      fetch: async () => { throw new Error("must not fetch"); },
    }).attest(abort.signal));
    expect(cancelled.category).toBe("cancelled");
  });

  test("rejects management, provisioning, expired, exhausted, and incomplete keys", async () => {
    const now = () => new Date("2026-07-18T19:00:00.000Z");
    const cases: ReadonlyArray<readonly [unknown, string]> = [
      [key({ is_management_key: true }), "openrouter_key_not_completion_capable"],
      [key({ is_provisioning_key: true }), "openrouter_key_not_completion_capable"],
      [key({ expires_at: "2026-07-18T18:59:59.000Z" }), "openrouter_key_expired"],
      [key({ limit_remaining: 0 }), "openrouter_key_limit_exhausted"],
      [{ data: { is_management_key: false } }, "openrouter_key_contract_invalid"],
    ];
    for (const [contract, code] of cases) {
      let calls = 0;
      const probe = new OpenRouterReadinessProbe({
        credentialPath: credential(),
        now,
        fetch: async () => {
          calls += 1;
          return json(contract);
        },
      });
      expect((await planningError(probe.attest())).code).toBe(code);
      expect(calls).toBe(1);
    }
  });

  test("only marks callability and exact usage after a matching audited content-free completion", async () => {
    const probe = new OpenRouterReadinessProbe({
      credentialPath: credential(),
      now: () => new Date("2026-07-18T19:00:00.000Z"),
      fetch: async (input) => input.toString() === OPENROUTER_CURRENT_KEY_ENDPOINT
        ? json(key())
        : json(model()),
      completionVerifier: {
        async verify(configuration) {
          return {
            requestedModel: configuration.model,
            returnedModel: `${configuration.model}-20260718`,
            modelConfigurationHash: configuration.configurationHash,
            strictSchemaVerified: true,
            toolFreeVerified: true,
            exactTokenUsage: true,
            exactCostUsage: true,
            requestAuditReceiptId: "exposure-readiness-probe",
          };
        },
      },
    });
    expect(await probe.attest()).toMatchObject({
      callable: true,
      supportsGuided: true,
      callabilityVerification: "audited_content_free_completion",
      reportsExactTokenUsage: true,
      reportsExactCostUsage: true,
      enforcesAutonomousBoundary: false,
      completionProbeReceiptId: "exposure-readiness-probe",
      completionReturnedModel: "openai/gpt-5.2-20260718",
    });
  });

  test("enforces a hard deadline even when fetch ignores AbortSignal and distinguishes caller cancellation", async () => {
    const timeout = new OpenRouterReadinessProbe({
      credentialPath: credential(),
      timeoutMs: 100,
      fetch: async () => new Promise<Response>(() => undefined),
    });
    expect(await planningError(timeout.attest())).toMatchObject({
      code: "openrouter_readiness_timeout",
      category: "timeout",
      status: 503,
    });

    const controller = new AbortController();
    const cancelledProbe = new OpenRouterReadinessProbe({
      credentialPath: credential(),
      timeoutMs: 5_000,
      fetch: async () => new Promise<Response>(() => undefined),
    });
    const pending = cancelledProbe.attest(controller.signal);
    controller.abort();
    expect(await planningError(pending)).toMatchObject({
      code: "openrouter_readiness_cancelled",
      category: "cancelled",
      status: 499,
    });
  });

  test("honors Retry-After and cancels non-200 response bodies", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new TextEncoder().encode("unsafe")); },
      cancel() { cancelled = true; },
    });
    const probe = new OpenRouterReadinessProbe({
      credentialPath: credential(),
      fetch: async () => new Response(body, {
        status: 429,
        headers: { "content-type": "application/json", "retry-after": "2.5" },
      }),
    });
    const error = await planningError(probe.attest());
    expect(error).toMatchObject({ code: "openrouter_rate_limited", retryAfterMs: 2_500 });
    expect(cancelled).toBe(true);
  });
});

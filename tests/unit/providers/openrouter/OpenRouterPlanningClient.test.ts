import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  OPENROUTER_CHAT_COMPLETIONS_ENDPOINT,
  OpenRouterPlanningClient,
  OpenRouterPlanningError,
  resolveOpenRouterModelConfiguration,
  type ProviderRequestAuditor,
  type ProviderRequestAuthorizationInput,
  type StructuredJsonCall,
} from "../../../../server/providers/openrouter";

const roots: string[] = [];
const KEY = "sk-or-v1-never-leak-this-unit-test-key";
const CONFIGURATION = resolveOpenRouterModelConfiguration({ model: "openai/gpt-5.4-mini" });

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function credential(): string {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-openrouter-client-"));
  roots.push(root);
  chmodSync(root, 0o700);
  const path = join(root, "api-key");
  writeFileSync(path, KEY, { encoding: "utf8", mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

interface Answer {
  readonly summary: string;
}

function call(overrides: Partial<StructuredJsonCall<Answer>> = {}): StructuredJsonCall<Answer> {
  return {
    model: "openai/gpt-5.4-mini",
    messages: [
      { role: "system", content: "Return one bounded planning answer." },
      { role: "user", content: "Explain the represented step without executing it." },
    ],
    response: {
      name: "guided_answer",
      description: "One bounded Guided explanation",
      schema: {
        type: "object",
        properties: { summary: { type: "string" } },
        required: ["summary"],
        additionalProperties: false,
      },
      validate(value): Answer {
        if (
          !value || typeof value !== "object" || Array.isArray(value) ||
          typeof (value as Record<string, unknown>).summary !== "string"
        ) {
          throw new TypeError("Invalid answer");
        }
        return { summary: (value as { summary: string }).summary };
      },
    },
    exposure: {
      exposureReceiptId: "exposure-unit-test",
      contextPackId: "context-pack-unit-test",
      modelConfigurationHash: CONFIGURATION.configurationHash,
    },
    ...overrides,
  };
}

function approvingAuditor(
  inspect?: (input: ProviderRequestAuthorizationInput) => void,
): ProviderRequestAuditor {
  return {
    async authorize(input) {
      inspect?.(input);
      return {
        authorized: true,
        exposureReceiptId: input.exposure.exposureReceiptId,
        contextPackId: input.exposure.contextPackId,
        providerTurnId: "provider-turn-unit-test",
        requestedModel: input.requestedModel,
        modelConfigurationHash: input.exposure.modelConfigurationHash,
        requestBodyHash: input.requestBodyHash,
        committedAt: "2026-07-18T12:00:00.000Z",
      };
    },
  };
}

function providerPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "generation-unit-test",
    model: "openai/gpt-5.4-mini-20260701",
    choices: [{
      finish_reason: "stop",
      message: { role: "assistant", content: JSON.stringify({ summary: "Review the evidence first." }) },
    }],
    usage: {
      prompt_tokens: 20,
      completion_tokens: 8,
      total_tokens: 28,
      cost: 0.00042,
    },
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("content-type", "application/json");
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: responseHeaders,
  });
}

function fetcher(
  implementation: (url: string, init: RequestInit) => Response | Promise<Response>,
): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) =>
    implementation(String(input), init ?? {})) as typeof fetch;
}

async function failure(promise: Promise<unknown>): Promise<OpenRouterPlanningError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(OpenRouterPlanningError);
    return error as OpenRouterPlanningError;
  }
  throw new Error("Expected OpenRouterPlanningError");
}

describe("OpenRouterPlanningClient structured JSON boundary", () => {
  test("posts a strict tool-free schema request and returns locally validated exact usage", async () => {
    let capturedUrl = "";
    let capturedInit: RequestInit | undefined;
    let audited: ProviderRequestAuthorizationInput | undefined;
    const order: string[] = [];
    const client = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor((input) => {
        audited = input;
        order.push("audit-committed");
      }),
      fetch: fetcher((url, init) => {
        order.push("fetch");
        capturedUrl = url;
        capturedInit = init;
        return jsonResponse(providerPayload());
      }),
    });

    const result = await client.callStructuredJson(call());
    expect(result).toEqual({
      value: { summary: "Review the evidence first." },
      providerId: "openrouter",
      requestedModel: "openai/gpt-5.4-mini",
      returnedModel: "openai/gpt-5.4-mini-20260701",
      usage: {
        inputTokens: 20,
        outputTokens: 8,
        providerTokens: 28,
        billedCostUsd: 0.00042,
        exactTokenUsage: true,
        exactCostUsage: true,
      },
      exposure: {
        exposureReceiptId: "exposure-unit-test",
        contextPackId: "context-pack-unit-test",
        modelConfigurationHash: CONFIGURATION.configurationHash,
      },
    });
    expect(capturedUrl).toBe(OPENROUTER_CHAT_COMPLETIONS_ENDPOINT);
    expect(capturedInit?.method).toBe("POST");
    expect(capturedInit?.redirect).toBe("error");
    expect(new Headers(capturedInit?.headers).get("authorization")).toBe(`Bearer ${KEY}`);
    const exactBody = String(capturedInit?.body);
    const body = JSON.parse(exactBody);
    expect(body).toMatchObject({
      model: "openai/gpt-5.4-mini",
      stream: false,
      tools: [],
      tool_choice: "none",
      provider: { require_parameters: true },
      usage: { include: true },
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "guided_answer",
          strict: true,
          schema: { type: "object", additionalProperties: false },
        },
      },
    });
    expect(JSON.stringify(body)).not.toContain("exposure-unit-test");
    expect(JSON.stringify(body)).not.toContain("context-pack-unit-test");
    expect(order).toEqual(["audit-committed", "fetch"]);
    expect(audited).toMatchObject({
      requestedModel: "openai/gpt-5.4-mini",
      requestBodyBytes: Buffer.byteLength(exactBody, "utf8"),
      requestBodyHash: createHash("sha256").update(exactBody, "utf8").digest("hex"),
    });
    expect(audited?.exposure.modelConfigurationHash).toBe(CONFIGURATION.configurationHash);
    expect(exactBody).not.toContain(KEY);
  });

  test("replaces thrown transport details with a typed error that cannot leak the bearer token", async () => {
    const client = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      fetch: fetcher((_url, init) => {
        const authorization = new Headers(init.headers).get("authorization");
        throw new Error(`transport included ${authorization}`);
      }),
    });
    const error = await failure(client.callStructuredJson(call()));
    expect(error).toMatchObject({
      code: "openrouter_network_unavailable",
      category: "provider_unavailable",
      retryable: true,
    });
    expect(JSON.stringify(error)).not.toContain(KEY);
    expect(error.stack).not.toContain(KEY);
  });

  test("fails closed on malformed outer JSON, malformed structured content, and oversized responses", async () => {
    const malformedOuter = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      fetch: fetcher(() => jsonResponse("{")),
    });
    expect((await failure(malformedOuter.callStructuredJson(call()))).code)
      .toBe("openrouter_response_json_invalid");

    const malformedContent = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      fetch: fetcher(() => jsonResponse(providerPayload({
        choices: [{ finish_reason: "stop", message: { content: "not-json" } }],
      }))),
    });
    expect((await failure(malformedContent.callStructuredJson(call()))).code)
      .toBe("openrouter_structured_json_invalid");

    const oversized = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      maximumResponseBytes: 4_096,
      fetch: fetcher(() => jsonResponse("x".repeat(5_000), 200, { "content-length": "5000" })),
    });
    expect((await failure(oversized.callStructuredJson(call()))).code)
      .toBe("openrouter_response_too_large");
  });

  test("maps 401, 429 with Retry-After, and 5xx without retaining provider bodies", async () => {
    const cases = [
      { status: 401, code: "openrouter_authentication_failed", category: "authentication_failed", retryable: false },
      { status: 429, code: "openrouter_rate_limited", category: "rate_limit", retryable: true },
      { status: 503, code: "openrouter_unavailable", category: "provider_unavailable", retryable: true },
    ] as const;
    for (const item of cases) {
      const client = new OpenRouterPlanningClient({
        credentialPath: credential(),
        requestAuditor: approvingAuditor(),
        fetch: fetcher(() => jsonResponse({ error: { message: `unsafe ${KEY}` } }, item.status, {
          "retry-after": item.status === 429 ? "2.5" : "",
        })),
      });
      const error = await failure(client.callStructuredJson(call()));
      expect(error).toMatchObject({
        code: item.code,
        category: item.category,
        retryable: item.retryable,
      });
      if (item.status === 429) expect(error.retryAfterMs).toBe(2_500);
      expect(JSON.stringify(error)).not.toContain(KEY);
    }

    const datedRetry = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      now: () => new Date("2026-07-18T12:00:00.000Z"),
      fetch: fetcher(() => jsonResponse({}, 429, {
        "retry-after": "Sat, 18 Jul 2026 12:00:03 GMT",
      })),
    });
    expect((await failure(datedRetry.callStructuredJson(call()))).retryAfterMs).toBe(3_000);
  });

  test("cancels rejected response bodies and never dispatches when durable authorization fails", async () => {
    let cancelled = false;
    const rejectedBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("unsafe provider body"));
      },
      cancel() {
        cancelled = true;
      },
    });
    const rejected = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      fetch: fetcher(() => new Response(rejectedBody, {
        status: 429,
        headers: { "content-type": "application/json", "retry-after": "1" },
      })),
    });
    expect((await failure(rejected.callStructuredJson(call()))).code).toBe("openrouter_rate_limited");
    expect(cancelled).toBe(true);

    let fetchCalls = 0;
    const auditFailure = new OpenRouterPlanningClient({
      // If credential access occurs before audit, this test fails with authentication_missing.
      credentialPath: "/definitely/missing/openrouter-key",
      requestAuditor: {
        async authorize() {
          throw new Error("database transaction failed with secret=never-surface");
        },
      },
      fetch: fetcher(() => {
        fetchCalls += 1;
        return jsonResponse(providerPayload());
      }),
    });
    const failed = await failure(auditFailure.callStructuredJson(call()));
    expect(failed).toMatchObject({
      code: "openrouter_request_audit_failed",
      category: "persistence",
    });
    expect(JSON.stringify(failed)).not.toContain("never-surface");
    expect(fetchCalls).toBe(0);

    const mismatch = new OpenRouterPlanningClient({
      credentialPath: "/definitely/missing/openrouter-key",
      requestAuditor: {
        async authorize(input) {
          return {
            authorized: true,
            exposureReceiptId: input.exposure.exposureReceiptId,
            contextPackId: input.exposure.contextPackId,
            providerTurnId: "provider-turn-unit-test",
            requestedModel: input.requestedModel,
            modelConfigurationHash: input.exposure.modelConfigurationHash,
            requestBodyHash: "0".repeat(64),
            committedAt: "2026-07-18T12:00:00.000Z",
          };
        },
      },
      fetch: fetcher(() => {
        fetchCalls += 1;
        return jsonResponse(providerPayload());
      }),
    });
    expect((await failure(mismatch.callStructuredJson(call()))).code)
      .toBe("openrouter_request_audit_mismatch");
    expect(fetchCalls).toBe(0);
  });

  test("distinguishes a hard timeout from caller cancellation and forwards AbortSignal", async () => {
    const waitForAbort = fetcher((_url, init) => new Promise<Response>((_resolve, reject) => {
      const signal = init.signal;
      if (!signal) throw new Error("Expected signal");
      if (signal.aborted) {
        reject(new DOMException("Aborted", "AbortError"));
        return;
      }
      signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    }));
    const timeoutClient = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      timeoutMs: 100,
      fetch: waitForAbort,
    });
    const timeout = await failure(timeoutClient.callStructuredJson(call()));
    expect(timeout).toMatchObject({ code: "openrouter_timeout", category: "timeout" });

    const ignoresAbort = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      timeoutMs: 100,
      fetch: fetcher(() => new Promise<Response>(() => undefined)),
    });
    expect(await failure(ignoresAbort.callStructuredJson(call())))
      .toMatchObject({ code: "openrouter_timeout", category: "timeout" });

    const cancellationClient = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      timeoutMs: 5_000,
      fetch: waitForAbort,
    });
    const controller = new AbortController();
    const pending = cancellationClient.callStructuredJson(call({ signal: controller.signal }));
    controller.abort();
    const cancelled = await failure(pending);
    expect(cancelled).toMatchObject({ code: "openrouter_cancelled", category: "cancelled" });
  });

  test("denies redirects even when an injected fetch returns the redirect response", async () => {
    const client = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      fetch: fetcher(() => jsonResponse({}, 302, { location: "https://evil.example" })),
    });
    const error = await failure(client.callStructuredJson(call()));
    expect(error).toMatchObject({
      code: "openrouter_redirect_denied",
      category: "provider_protocol",
      retryable: false,
    });
  });

  test("requires exact tokens and billed cost by default and reports explicit non-exact telemetry only when allowed", async () => {
    const missingTokens = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      fetch: fetcher(() => jsonResponse(providerPayload({ usage: { cost: 0.1 } }))),
    });
    expect((await failure(missingTokens.callStructuredJson(call()))).code)
      .toBe("openrouter_exact_token_usage_missing");

    const missingCost = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      fetch: fetcher(() => jsonResponse(providerPayload({
        usage: { prompt_tokens: 2, completion_tokens: 3, total_tokens: 5 },
      }))),
    });
    expect((await failure(missingCost.callStructuredJson(call()))).code)
      .toBe("openrouter_exact_cost_usage_missing");

    const allowed = await missingTokens.callStructuredJson(call({
      requireExactUsage: { tokens: false, cost: false },
    }));
    expect(allowed.usage).toEqual({
      billedCostUsd: 0.1,
      exactTokenUsage: false,
      exactCostUsage: true,
    });
  });

  test("rejects invalid models, non-opaque exposure references, non-strict schemas, and oversized prompts before fetch", async () => {
    let calls = 0;
    const client = new OpenRouterPlanningClient({
      credentialPath: credential(),
      requestAuditor: approvingAuditor(),
      fetch: fetcher(() => {
        calls += 1;
        return jsonResponse(providerPayload());
      }),
    });
    expect((await failure(client.callStructuredJson(call({ model: "https://evil.example/model" })))).code)
      .toBe("openrouter_model_invalid");
    expect((await failure(client.callStructuredJson(call({
      exposure: {
        exposureReceiptId: "not opaque!",
        contextPackId: "context-pack",
        modelConfigurationHash: CONFIGURATION.configurationHash,
      },
    })))).code).toBe("openrouter_exposure_reference_invalid");
    expect((await failure(client.callStructuredJson(call({
      exposure: {
        ...call().exposure,
        modelConfigurationHash: "0".repeat(64),
      },
    })))).code).toBe("openrouter_model_configuration_invalid");
    expect((await failure(client.callStructuredJson(call({
      response: {
        ...call().response,
        schema: {
          type: "object",
          properties: { summary: { type: "string" } },
          required: ["summary"],
        },
      },
    })))).code).toBe("openrouter_schema_not_strict");
    expect((await failure(client.callStructuredJson(call({
      messages: [{ role: "user", content: "x".repeat(33 * 1024) }],
    })))).code).toBe("openrouter_message_too_large");
    expect(calls).toBe(0);
  });
});

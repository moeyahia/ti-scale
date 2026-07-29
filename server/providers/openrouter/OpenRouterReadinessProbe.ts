import { performance } from "node:perf_hooks";
import {
  readOpenRouterCredential,
  type OpenRouterCredentialReader,
} from "./OpenRouterCredential";
import {
  resolveOpenRouterModelConfiguration,
  type ResolvedOpenRouterModelConfiguration,
} from "./OpenRouterModelConfiguration";
import { OpenRouterPlanningError } from "./types";

export const OPENROUTER_CURRENT_KEY_ENDPOINT = "https://openrouter.ai/api/v1/key";
export const OPENROUTER_DEFAULT_MODEL = "openai/gpt-5.2";

const REQUIRED_GUIDED_PARAMETERS = Object.freeze([
  "response_format",
  "structured_outputs",
  "tool_choice",
  "tools",
] as const);
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAXIMUM_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_TTL_MS = 5 * 60_000;
const MAXIMUM_RETRY_AFTER_MS = 7 * 24 * 60 * 60_000;
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,239}$/u;
const RETURNED_MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,239}$/u;

type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface OpenRouterCompletionProbeResult {
  readonly requestedModel: string;
  readonly returnedModel: string;
  readonly modelConfigurationHash: string;
  readonly strictSchemaVerified: true;
  readonly toolFreeVerified: true;
  readonly exactTokenUsage: boolean;
  readonly exactCostUsage: boolean;
  readonly inputTokens?: number;
  readonly outputTokens?: number;
  readonly totalTokens?: number;
  readonly billedCostUsd?: number;
  readonly latencyMs?: number;
  /** Proves that the content-free POST used the same durable request audit boundary. */
  readonly requestAuditReceiptId: string;
}

export interface OpenRouterCompletionVerifier {
  verify(
    configuration: ResolvedOpenRouterModelConfiguration,
    signal: AbortSignal,
  ): Promise<OpenRouterCompletionProbeResult>;
}

export interface OpenRouterReadinessProbeOptions {
  readonly credentialPath: string;
  /** Optional process-local startup credential snapshot. */
  readonly credentialReader?: OpenRouterCredentialReader;
  readonly serviceUid?: number;
  readonly model?: string;
  readonly fetch?: Fetch;
  readonly timeoutMs?: number;
  readonly maximumResponseBytes?: number;
  readonly ttlMs?: number;
  readonly now?: () => Date;
  /** Optional audited, content-free strict-schema completion verification. */
  readonly completionVerifier?: OpenRouterCompletionVerifier;
}

export interface OpenRouterModelAttestation {
  readonly schemaVersion: "ti-scale.openrouter-model-attestation.v2";
  readonly providerId: "openrouter";
  readonly model: string;
  readonly modelConfigurationHash: string;
  readonly authenticated: true;
  readonly keyEligibility: "verified_completion_key";
  readonly metadataSupportsGuided: true;
  /** False until an audited content-free strict-schema POST proves callability. */
  readonly callable: boolean;
  readonly callabilityVerification: "unverified" | "audited_content_free_completion";
  readonly supportsGuided: boolean;
  /** OpenRouter remains planning/advisory only for Autonomous execution. */
  readonly enforcesAutonomousBoundary: false;
  readonly reportsExactTokenUsage: boolean;
  readonly reportsExactCostUsage: boolean;
  readonly contextLength: number;
  readonly supportedParameters: readonly string[];
  readonly pricing: Readonly<{
    promptUsdPerToken: string;
    completionUsdPerToken: string;
    provenance: "advertised_model_metadata";
  }>;
  readonly completionProbeReceiptId?: string;
  /** Present only when the audited completion returned an exact provider model identifier. */
  readonly completionReturnedModel?: string;
  readonly attestedAt: string;
  readonly expiresAt: string;
  readonly latencyMs: number;
}

interface Configuration {
  readonly credentialPath: string;
  readonly credentialReader: OpenRouterCredentialReader;
  readonly serviceUid?: number;
  readonly resolvedModel: ResolvedOpenRouterModelConfiguration;
  readonly fetch: Fetch;
  readonly timeoutMs: number;
  readonly maximumResponseBytes: number;
  readonly ttlMs: number;
  readonly now: () => Date;
  readonly completionVerifier?: OpenRouterCompletionVerifier;
}

function readinessError(
  code: string,
  message: string,
  options: ConstructorParameters<typeof OpenRouterPlanningError>[2],
): OpenRouterPlanningError {
  return new OpenRouterPlanningError(code, message, options);
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < minimum || result > maximum) {
    throw readinessError("openrouter_readiness_configuration_invalid", `${label} is outside its safe bound`, {
      status: 500,
      category: "invalid_configuration",
      retryable: false,
    });
  }
  return result;
}

function configure(options: OpenRouterReadinessProbeOptions): Configuration {
  if (typeof options.credentialPath !== "string" || !options.credentialPath.trim()) {
    throw readinessError("openrouter_credential_path_required", "An OpenRouter credential path is required", {
      status: 500,
      category: "invalid_configuration",
      retryable: false,
    });
  }
  if (options.completionVerifier && typeof options.completionVerifier.verify !== "function") {
    throw readinessError("openrouter_completion_verifier_invalid", "The completion verifier is invalid", {
      status: 500,
      category: "invalid_configuration",
      retryable: false,
    });
  }
  return {
    credentialPath: options.credentialPath,
    credentialReader: options.credentialReader ?? (() => readOpenRouterCredential({
      path: options.credentialPath,
      ...(options.serviceUid === undefined ? {} : { serviceUid: options.serviceUid }),
    })),
    ...(options.serviceUid === undefined ? {} : { serviceUid: options.serviceUid }),
    resolvedModel: resolveOpenRouterModelConfiguration({
      model: options.model?.trim() || OPENROUTER_DEFAULT_MODEL,
    }),
    fetch: options.fetch ?? globalThis.fetch,
    timeoutMs: boundedInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS, 100, 120_000, "Readiness timeout"),
    maximumResponseBytes: boundedInteger(
      options.maximumResponseBytes,
      DEFAULT_MAXIMUM_RESPONSE_BYTES,
      4 * 1024,
      2 * 1024 * 1024,
      "Readiness response byte limit",
    ),
    ttlMs: boundedInteger(options.ttlMs, DEFAULT_TTL_MS, 10_000, 60 * 60_000, "Readiness TTL"),
    now: options.now ?? (() => new Date()),
    ...(options.completionVerifier ? { completionVerifier: options.completionVerifier } : {}),
  };
}

function modelEndpoint(model: string): string {
  const [author, slug] = model.split("/", 2) as [string, string];
  return `https://openrouter.ai/api/v1/model/${encodeURIComponent(author)}/${encodeURIComponent(slug)}`;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function retryAfter(value: string | null, now: Date): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value.trim());
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(MAXIMUM_RETRY_AFTER_MS, Math.ceil(seconds * 1_000));
  }
  const date = Date.parse(value);
  if (!Number.isFinite(date)) return undefined;
  return Math.min(MAXIMUM_RETRY_AFTER_MS, Math.max(0, date - now.getTime()));
}

async function boundedJson(
  response: Response,
  maximumBytes: number,
  signal: AbortSignal,
): Promise<unknown> {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) {
    await response.body?.cancel().catch(() => undefined);
    throw readinessError("openrouter_readiness_content_type_invalid", "OpenRouter readiness returned a non-JSON response", {
      status: 502, category: "provider_protocol", retryable: true,
    });
  }
  const declared = response.headers.get("content-length");
  if (declared && /^\d+$/u.test(declared) && Number(declared) > maximumBytes) {
    await response.body?.cancel().catch(() => undefined);
    throw readinessError("openrouter_readiness_response_too_large", "OpenRouter readiness exceeded its response byte limit", {
      status: 502, category: "provider_protocol", retryable: true,
    });
  }
  if (!response.body) {
    throw readinessError("openrouter_readiness_response_invalid", "OpenRouter readiness returned an empty response", {
      status: 502, category: "provider_protocol", retryable: true,
    });
  }
  const reader = response.body.getReader();
  const cancelReader = () => { void reader.cancel().catch(() => undefined); };
  signal.addEventListener("abort", cancelReader, { once: true });
  if (signal.aborted) cancelReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel().catch(() => undefined);
        throw readinessError("openrouter_readiness_response_too_large", "OpenRouter readiness exceeded its response byte limit", {
          status: 502, category: "provider_protocol", retryable: true,
        });
      }
      chunks.push(part.value);
    }
  } finally {
    signal.removeEventListener("abort", cancelReader);
    reader.releaseLock();
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(joined)) as unknown;
  } catch {
    throw readinessError("openrouter_readiness_response_invalid", "OpenRouter readiness returned malformed JSON", {
      status: 502, category: "provider_protocol", retryable: true,
    });
  }
}

function statusError(response: Response, now: Date): OpenRouterPlanningError {
  const retryAfterMs = retryAfter(response.headers.get("retry-after"), now);
  if (response.status === 401 || response.status === 403) {
    return readinessError("openrouter_authentication_failed", "OpenRouter rejected the configured credential", {
      status: 503, category: "authentication_failed", retryable: false,
      remediation: "Replace the service-owned OpenRouter credential and rerun provider readiness.",
    });
  }
  if (response.status === 429) {
    return readinessError("openrouter_rate_limited", "OpenRouter temporarily limited the readiness request", {
      status: 429, category: "rate_limit", retryable: true,
      ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    });
  }
  if (response.status === 408 || response.status === 504) {
    return readinessError("openrouter_readiness_upstream_timeout", "OpenRouter readiness did not respond in time", {
      status: 503, category: "timeout", retryable: true,
      ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    });
  }
  if (response.status >= 500) {
    return readinessError("openrouter_unavailable", "OpenRouter readiness is temporarily unavailable", {
      status: 503, category: "provider_unavailable", retryable: true,
      ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    });
  }
  return readinessError("openrouter_readiness_rejected", "OpenRouter rejected the bounded readiness request", {
    status: 502, category: "provider_protocol", retryable: false,
  });
}

function parseKeyContract(value: unknown, now: Date): void {
  const data = record(record(value)?.data);
  if (
    !data ||
    typeof data.is_management_key !== "boolean" ||
    typeof data.is_provisioning_key !== "boolean" ||
    !(data.limit_remaining === null || typeof data.limit_remaining === "number") ||
    !(data.expires_at === null || typeof data.expires_at === "string")
  ) {
    throw readinessError("openrouter_key_contract_invalid", "OpenRouter returned an incomplete credential-status contract", {
      status: 502, category: "provider_protocol", retryable: true,
    });
  }
  if (data.is_management_key || data.is_provisioning_key) {
    throw readinessError("openrouter_key_not_completion_capable", "The configured OpenRouter key cannot call completions", {
      status: 503, category: "authentication_failed", retryable: false,
      remediation: "Configure a non-management, non-provisioning OpenRouter completion key.",
    });
  }
  if (data.limit_remaining !== null && (
    !Number.isFinite(data.limit_remaining) || (data.limit_remaining as number) <= 0
  )) {
    throw readinessError("openrouter_key_limit_exhausted", "The configured OpenRouter key has no remaining limit", {
      status: 503, category: "rate_limit", retryable: false,
      remediation: "Increase the key limit or configure another eligible completion key.",
    });
  }
  if (data.expires_at !== null) {
    const expiresAt = Date.parse(data.expires_at as string);
    if (!Number.isFinite(expiresAt)) {
      throw readinessError("openrouter_key_contract_invalid", "OpenRouter returned an invalid key expiry", {
        status: 502, category: "provider_protocol", retryable: true,
      });
    }
    if (expiresAt <= now.getTime()) {
      throw readinessError("openrouter_key_expired", "The configured OpenRouter key is expired", {
        status: 503, category: "authentication_failed", retryable: false,
        remediation: "Replace the expired service-owned OpenRouter key.",
      });
    }
  }
}

function decimal(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d*)(?:\.\d+)?$/u.test(value)) {
    throw readinessError("openrouter_model_contract_invalid", `${label} is missing from the model contract`, {
      status: 502, category: "provider_protocol", retryable: true,
    });
  }
  return value;
}

function parseModelContract(value: unknown, expectedModel: string): {
  readonly contextLength: number;
  readonly supportedParameters: readonly string[];
  readonly pricing: OpenRouterModelAttestation["pricing"];
} {
  const data = record(record(value)?.data);
  const contextLength = data?.context_length;
  const supported = data?.supported_parameters;
  const pricing = record(data?.pricing);
  if (
    data?.id !== expectedModel || !Number.isSafeInteger(contextLength) || (contextLength as number) <= 0 ||
    !Array.isArray(supported) || supported.length > 256 ||
    !supported.every((item) => typeof item === "string" && item.length > 0 && item.length <= 128)
  ) {
    throw readinessError("openrouter_model_contract_invalid", "The configured OpenRouter model contract is invalid", {
      status: 502, category: "provider_protocol", retryable: true,
    });
  }
  const supportedParameters = Object.freeze([...new Set(supported as string[])].sort());
  if (REQUIRED_GUIDED_PARAMETERS.some((parameter) => !supportedParameters.includes(parameter))) {
    throw readinessError("openrouter_model_parameters_unavailable", "The configured OpenRouter model lacks a required planning parameter", {
      status: 503, category: "provider_protocol", retryable: false,
      remediation: "Select a model that supports strict structured outputs and explicit tool denial.",
    });
  }
  return {
    contextLength: contextLength as number,
    supportedParameters,
    pricing: Object.freeze({
      promptUsdPerToken: decimal(pricing?.prompt, "Prompt pricing"),
      completionUsdPerToken: decimal(pricing?.completion, "Completion pricing"),
      provenance: "advertised_model_metadata",
    }),
  };
}

function cancellationError(timedOut: boolean): OpenRouterPlanningError {
  return timedOut
    ? readinessError("openrouter_readiness_timeout", "OpenRouter readiness timed out", {
        status: 503, category: "timeout", retryable: true,
      })
    : readinessError("openrouter_readiness_cancelled", "OpenRouter readiness was cancelled", {
        status: 499, category: "cancelled", retryable: true,
      });
}

export class OpenRouterReadinessProbe {
  readonly #configuration: Configuration;

  constructor(options: OpenRouterReadinessProbeOptions) {
    this.#configuration = configure(options);
  }

  get resolvedConfiguration(): ResolvedOpenRouterModelConfiguration {
    return this.#configuration.resolvedModel;
  }

  async attest(signal?: AbortSignal): Promise<OpenRouterModelAttestation> {
    if (signal?.aborted) throw cancellationError(false);
    const key = this.#configuration.credentialReader();
    const controller = new AbortController();
    let timedOut = false;
    const cancel = () => controller.abort(signal?.reason);
    signal?.addEventListener("abort", cancel, { once: true });
    let rejectDeadline: (() => void) | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      rejectDeadline = () => reject(cancellationError(timedOut));
      controller.signal.addEventListener("abort", rejectDeadline, { once: true });
    });
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort("readiness timeout");
    }, this.#configuration.timeoutMs);
    timer.unref?.();
    if (signal?.aborted) controller.abort(signal.reason);
    const started = performance.now();

    const request = async (endpoint: string): Promise<unknown> => {
      let response: Response | undefined;
      try {
        response = await Promise.race([
          this.#configuration.fetch(endpoint, {
            method: "GET",
            headers: { Accept: "application/json", Authorization: `Bearer ${key}` },
            redirect: "error",
            signal: controller.signal,
          }),
          deadline,
        ]);
        if (response.redirected || response.status >= 300 && response.status < 400) {
          await response.body?.cancel().catch(() => undefined);
          throw readinessError("openrouter_readiness_redirect_denied", "OpenRouter readiness attempted an unapproved redirect", {
            status: 502, category: "provider_protocol", retryable: false,
          });
        }
        if (response.status !== 200) {
          await response.body?.cancel().catch(() => undefined);
          throw statusError(response, this.#configuration.now());
        }
        return await Promise.race([
          boundedJson(response, this.#configuration.maximumResponseBytes, controller.signal),
          deadline,
        ]);
      } catch (failure) {
        if (controller.signal.aborted) {
          await response?.body?.cancel().catch(() => undefined);
          throw cancellationError(timedOut);
        }
        if (failure instanceof OpenRouterPlanningError) throw failure;
        throw readinessError("openrouter_readiness_unavailable", "OpenRouter readiness could not reach the provider", {
          status: 503, category: "provider_unavailable", retryable: true,
        });
      }
    };

    try {
      const keyContract = await request(OPENROUTER_CURRENT_KEY_ENDPOINT);
      parseKeyContract(keyContract, this.#configuration.now());
      const contract = parseModelContract(
        await request(modelEndpoint(this.#configuration.resolvedModel.model)),
        this.#configuration.resolvedModel.model,
      );
      let completion: OpenRouterCompletionProbeResult | undefined;
      if (this.#configuration.completionVerifier) {
        completion = await Promise.race([
          this.#configuration.completionVerifier.verify(this.#configuration.resolvedModel, controller.signal),
          deadline,
        ]);
        if (
          completion.requestedModel !== this.#configuration.resolvedModel.model ||
          completion.modelConfigurationHash !== this.#configuration.resolvedModel.configurationHash ||
          completion.strictSchemaVerified !== true || completion.toolFreeVerified !== true ||
          !OPAQUE_ID.test(completion.requestAuditReceiptId) ||
          !RETURNED_MODEL_ID.test(completion.returnedModel)
        ) {
          throw readinessError("openrouter_completion_probe_mismatch", "The completion probe did not match the pinned model configuration", {
            status: 503, category: "policy_denied", retryable: false,
          });
        }
      }
      const attestedAt = this.#configuration.now();
      return Object.freeze({
        schemaVersion: "ti-scale.openrouter-model-attestation.v2",
        providerId: "openrouter",
        model: this.#configuration.resolvedModel.model,
        modelConfigurationHash: this.#configuration.resolvedModel.configurationHash,
        authenticated: true,
        keyEligibility: "verified_completion_key",
        metadataSupportsGuided: true,
        callable: Boolean(completion),
        callabilityVerification: completion ? "audited_content_free_completion" : "unverified",
        supportsGuided: Boolean(completion),
        enforcesAutonomousBoundary: false,
        reportsExactTokenUsage: completion?.exactTokenUsage === true,
        reportsExactCostUsage: completion?.exactCostUsage === true,
        contextLength: contract.contextLength,
        supportedParameters: contract.supportedParameters,
        pricing: contract.pricing,
        ...(completion ? { completionProbeReceiptId: completion.requestAuditReceiptId } : {}),
        ...(completion ? { completionReturnedModel: completion.returnedModel } : {}),
        attestedAt: attestedAt.toISOString(),
        expiresAt: new Date(attestedAt.getTime() + this.#configuration.ttlMs).toISOString(),
        latencyMs: Math.max(0, Math.round(performance.now() - started)),
      });
    } catch (error) {
      if (controller.signal.aborted) throw cancellationError(timedOut);
      if (error instanceof OpenRouterPlanningError) throw error;
      throw readinessError("openrouter_readiness_failed", "OpenRouter readiness failed safely", {
        status: 503, category: "provider_unavailable", retryable: true,
      });
    } finally {
      clearTimeout(timer);
      if (rejectDeadline) controller.signal.removeEventListener("abort", rejectDeadline);
      signal?.removeEventListener("abort", cancel);
    }
  }
}

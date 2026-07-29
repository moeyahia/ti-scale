import {
  readOpenRouterCredential,
  type OpenRouterCredentialReader,
} from "./OpenRouterCredential";
import { canonicalJson, sha256 } from "../../missions/canonical";
import {
  assertOpenRouterConfigurationHash,
  OPENROUTER_CHAT_COMPLETIONS_ENDPOINT,
  resolveOpenRouterModelConfiguration,
  validateOpenRouterEndpoint,
} from "./OpenRouterModelConfiguration";
import {
  OpenRouterPlanningError,
  type OpenRouterExactUsage,
  type OpenRouterStructuredMessage,
  type ProviderExposureReferences,
  type ProviderRequestAuditor,
  type StructuredJsonCall,
  type StructuredJsonProviderClient,
  type StructuredJsonResult,
} from "./types";

// OpenRouter models are namespaced `provider/model` identifiers, never URLs.
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$/u;
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,239}$/u;
const SCHEMA_NAME = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/u;
const MESSAGE_ROLES = new Set(["system", "user", "assistant"] as const);
const MAXIMUM_MESSAGES = 64;
const MAXIMUM_MESSAGE_BYTES = 32 * 1024;
const MAXIMUM_PROMPT_BYTES = 128 * 1024;
const MAXIMUM_SCHEMA_BYTES = 64 * 1024;
const DEFAULT_REQUEST_BYTES = 256 * 1024;
const DEFAULT_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 120_000;
const MAXIMUM_TIMEOUT_MS = 5 * 60_000;
const MAXIMUM_RETRY_AFTER_MS = 7 * 24 * 60 * 60_000;

/** Callable subset used by the client; avoids coupling injected test/edge fetches to Bun statics. */
type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface OpenRouterPlanningClientOptions {
  readonly credentialPath: string;
  /**
   * Optional process-local startup snapshot. Production composition supplies
   * this so a newly saved provider key cannot hot-activate before restart.
   */
  readonly credentialReader?: OpenRouterCredentialReader;
  /** Required durable request-hash authorization. There is no unaudited mode. */
  readonly requestAuditor: ProviderRequestAuditor;
  readonly serviceUid?: number;
  readonly endpoint?: string;
  readonly fetch?: Fetch;
  readonly timeoutMs?: number;
  readonly maximumRequestBytes?: number;
  readonly maximumResponseBytes?: number;
  readonly now?: () => Date;
}

interface NormalizedConfiguration {
  readonly credentialPath: string;
  readonly credentialReader: OpenRouterCredentialReader;
  readonly serviceUid?: number;
  readonly endpoint: string;
  readonly fetch: Fetch;
  readonly timeoutMs: number;
  readonly maximumRequestBytes: number;
  readonly maximumResponseBytes: number;
  readonly now: () => Date;
  readonly requestAuditor: ProviderRequestAuditor;
}

interface ProviderResponse {
  readonly model: string;
  readonly choices: readonly {
    readonly finish_reason?: unknown;
    readonly message?: {
      readonly content?: unknown;
      readonly tool_calls?: unknown;
    };
  }[];
  readonly usage?: {
    readonly prompt_tokens?: unknown;
    readonly completion_tokens?: unknown;
    readonly total_tokens?: unknown;
    readonly cost?: unknown;
  };
}

function planningError(
  code: string,
  message: string,
  options: ConstructorParameters<typeof OpenRouterPlanningError>[2],
): OpenRouterPlanningError {
  return new OpenRouterPlanningError(code, message, options);
}

function configurationError(code: string, message: string): OpenRouterPlanningError {
  return planningError(code, message, {
    status: 500,
    category: "invalid_configuration",
    retryable: false,
  });
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  label: string,
  minimum: number,
  maximum: number,
): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < minimum || result > maximum) {
    throw configurationError("openrouter_configuration_invalid", `${label} is outside its safe bound`);
  }
  return result;
}

function normalizeConfiguration(options: OpenRouterPlanningClientOptions): NormalizedConfiguration {
  if (typeof options.credentialPath !== "string" || !options.credentialPath.trim()) {
    throw configurationError("openrouter_credential_path_required", "An OpenRouter credential path is required");
  }
  if (!options.requestAuditor || typeof options.requestAuditor.authorize !== "function") {
    throw configurationError(
      "openrouter_request_auditor_required",
      "A durable OpenRouter request auditor is required",
    );
  }
  return {
    credentialPath: options.credentialPath,
    credentialReader: options.credentialReader ?? (() => readOpenRouterCredential({
      path: options.credentialPath,
      ...(options.serviceUid === undefined ? {} : { serviceUid: options.serviceUid }),
    })),
    ...(options.serviceUid === undefined ? {} : { serviceUid: options.serviceUid }),
    endpoint: validateOpenRouterEndpoint(options.endpoint),
    fetch: options.fetch ?? globalThis.fetch,
    timeoutMs: boundedInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS, "OpenRouter timeout", 100, MAXIMUM_TIMEOUT_MS),
    maximumRequestBytes: boundedInteger(
      options.maximumRequestBytes,
      DEFAULT_REQUEST_BYTES,
      "OpenRouter request byte limit",
      4 * 1024,
      2 * 1024 * 1024,
    ),
    maximumResponseBytes: boundedInteger(
      options.maximumResponseBytes,
      DEFAULT_RESPONSE_BYTES,
      "OpenRouter response byte limit",
      4 * 1024,
      2 * 1024 * 1024,
    ),
    now: options.now ?? (() => new Date()),
    requestAuditor: options.requestAuditor,
  };
}

function invalidInput(code: string, message: string): OpenRouterPlanningError {
  return planningError(code, message, {
    status: 400,
    category: "invalid_input",
    retryable: false,
  });
}

function opaqueId(value: string, label: string): string {
  if (typeof value !== "string" || !OPAQUE_ID.test(value.trim())) {
    throw invalidInput("openrouter_exposure_reference_invalid", `${label} must be an opaque canonical identifier`);
  }
  return value.trim();
}

function exposureReferences(value: ProviderExposureReferences): ProviderExposureReferences {
  if (!value || typeof value !== "object") {
    throw invalidInput("openrouter_exposure_reference_required", "Provider exposure references are required");
  }
  const hasPlanningMode = value.planningDisclosureMode !== undefined;
  const hasAdvisoryIdentity = value.advisoryIdentityHash !== undefined;
  if (
    hasPlanningMode !== hasAdvisoryIdentity
    || (
      hasPlanningMode
      && value.planningDisclosureMode !== "public_only"
      && value.planningDisclosureMode !== "sanitized_internal"
    )
    || (
      hasAdvisoryIdentity
      && (
        typeof value.advisoryIdentityHash !== "string"
        || !/^[a-f0-9]{64}$/u.test(value.advisoryIdentityHash)
      )
    )
  ) {
    throw invalidInput(
      "openrouter_advisory_disclosure_identity_invalid",
      "Advisory planning exposure references require one exact disclosure mode and identity hash.",
    );
  }
  return {
    exposureReceiptId: opaqueId(value.exposureReceiptId, "Exposure receipt ID"),
    contextPackId: opaqueId(value.contextPackId, "Context Pack ID"),
    modelConfigurationHash: typeof value.modelConfigurationHash === "string"
      ? value.modelConfigurationHash.trim()
      : "",
    ...(hasPlanningMode && hasAdvisoryIdentity
      ? {
          planningDisclosureMode: value.planningDisclosureMode,
          advisoryIdentityHash: value.advisoryIdentityHash,
        }
      : {}),
  };
}

function messages(values: readonly OpenRouterStructuredMessage[]): readonly OpenRouterStructuredMessage[] {
  if (!Array.isArray(values) || values.length < 1 || values.length > MAXIMUM_MESSAGES) {
    throw invalidInput("openrouter_messages_invalid", `OpenRouter requires 1 through ${MAXIMUM_MESSAGES} messages`);
  }
  let total = 0;
  return values.map((value) => {
    if (!value || typeof value !== "object" || !MESSAGE_ROLES.has(value.role)) {
      throw invalidInput("openrouter_message_role_invalid", "An OpenRouter message role is invalid");
    }
    if (typeof value.content !== "string" || !value.content.trim()) {
      throw invalidInput("openrouter_message_content_required", "OpenRouter message content is required");
    }
    const normalized = value.content.normalize("NFKC");
    const size = Buffer.byteLength(normalized, "utf8");
    if (size > MAXIMUM_MESSAGE_BYTES) {
      throw invalidInput("openrouter_message_too_large", "An OpenRouter message exceeds the per-message byte limit");
    }
    total += size;
    if (total > MAXIMUM_PROMPT_BYTES) {
      throw invalidInput("openrouter_prompt_too_large", "The OpenRouter prompt exceeds its total byte limit");
    }
    return { role: value.role, content: normalized };
  });
}

function jsonClone(value: unknown, label: string, maximumBytes: number): unknown {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw invalidInput("openrouter_schema_invalid", `${label} must be finite JSON`);
  }
  if (serialized === undefined || Buffer.byteLength(serialized, "utf8") > maximumBytes) {
    throw invalidInput("openrouter_schema_too_large", `${label} exceeds its byte limit`);
  }
  try {
    return JSON.parse(serialized) as unknown;
  } catch {
    throw invalidInput("openrouter_schema_invalid", `${label} must be valid JSON`);
  }
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value != null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function enforceStrictObjectSchemas(value: unknown, depth = 0, visited = { count: 0 }): void {
  if (depth > 32 || ++visited.count > 2_000) {
    throw invalidInput("openrouter_schema_too_complex", "The response schema exceeds its complexity bound");
  }
  if (Array.isArray(value)) {
    for (const item of value) enforceStrictObjectSchemas(item, depth + 1, visited);
    return;
  }
  const object = record(value);
  if (!object) return;
  if (object.type === "object") {
    const properties = record(object.properties);
    if (!properties || object.additionalProperties !== false) {
      throw invalidInput(
        "openrouter_schema_not_strict",
        "Every object response schema must declare properties and additionalProperties false",
      );
    }
    const required = Array.isArray(object.required) ? object.required : [];
    const propertyNames = Object.keys(properties);
    if (
      required.length !== propertyNames.length ||
      propertyNames.some((name) => !required.includes(name))
    ) {
      throw invalidInput(
        "openrouter_schema_not_strict",
        "Every object response schema property must be explicitly required",
      );
    }
  }
  for (const child of Object.values(object)) enforceStrictObjectSchemas(child, depth + 1, visited);
}

function strictSchema<T>(input: StructuredJsonCall<T>["response"]): {
  readonly name: string;
  readonly description?: string;
  readonly schema: Record<string, unknown>;
  readonly validate: (value: unknown) => T;
} {
  if (!input || typeof input !== "object" || !SCHEMA_NAME.test(input.name)) {
    throw invalidInput("openrouter_schema_name_invalid", "The response schema name is invalid");
  }
  if (typeof input.validate !== "function") {
    throw invalidInput("openrouter_schema_validator_required", "A local response validator is required");
  }
  if (input.description !== undefined && (
    typeof input.description !== "string" ||
    !input.description.trim() ||
    Buffer.byteLength(input.description, "utf8") > 1_024
  )) {
    throw invalidInput("openrouter_schema_description_invalid", "The response schema description is invalid");
  }
  const cloned = jsonClone(input.schema, "Response schema", MAXIMUM_SCHEMA_BYTES);
  const schema = record(cloned);
  if (!schema || schema.type !== "object") {
    throw invalidInput("openrouter_schema_invalid", "The response schema root must be an object schema");
  }
  enforceStrictObjectSchemas(schema);
  return {
    name: input.name,
    ...(input.description ? { description: input.description } : {}),
    schema,
    validate: input.validate,
  };
}

function model(value: string): string {
  if (typeof value !== "string" || !MODEL.test(value.trim())) {
    throw invalidInput("openrouter_model_invalid", "The OpenRouter model identifier is invalid");
  }
  return value.trim();
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

async function readBoundedResponse(
  response: Response,
  maximumBytes: number,
  signal: AbortSignal,
): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared && /^\d+$/u.test(declared) && Number(declared) > maximumBytes) {
    throw planningError("openrouter_response_too_large", "The OpenRouter response exceeded its byte limit", {
      status: 502,
      category: "provider_protocol",
      retryable: true,
    });
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const cancelReader = () => { void reader.cancel().catch(() => undefined); };
  signal.addEventListener("abort", cancelReader, { once: true });
  if (signal.aborted) cancelReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > maximumBytes) {
        await reader.cancel().catch(() => undefined);
        throw planningError("openrouter_response_too_large", "The OpenRouter response exceeded its byte limit", {
          status: 502,
          category: "provider_protocol",
          retryable: true,
        });
      }
      chunks.push(next.value);
    }
  } finally {
    signal.removeEventListener("abort", cancelReader);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw planningError("openrouter_response_encoding_invalid", "The OpenRouter response was not valid UTF-8", {
      status: 502,
      category: "provider_protocol",
      retryable: true,
    });
  }
}

function statusError(response: Response, now: Date): OpenRouterPlanningError {
  const retryAfterMs = retryAfter(response.headers.get("retry-after"), now);
  if (response.status >= 300 && response.status < 400) {
    return planningError("openrouter_redirect_denied", "OpenRouter attempted an unapproved redirect", {
      status: 502,
      category: "provider_protocol",
      retryable: false,
    });
  }
  if (response.status === 401 || response.status === 403) {
    return planningError("openrouter_authentication_failed", "OpenRouter rejected the configured credential", {
      status: 503,
      category: "authentication_failed",
      retryable: false,
      remediation: "Replace the service-owned OpenRouter credential and rerun provider readiness.",
    });
  }
  if (response.status === 429) {
    return planningError("openrouter_rate_limited", "OpenRouter rate-limited the planning request", {
      status: 429,
      category: "rate_limit",
      retryable: true,
      ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    });
  }
  if (response.status === 408 || response.status === 504) {
    return planningError("openrouter_upstream_timeout", "OpenRouter did not complete the planning request in time", {
      status: 503,
      category: "timeout",
      retryable: true,
      ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    });
  }
  if (response.status >= 500) {
    return planningError("openrouter_unavailable", "OpenRouter is temporarily unavailable", {
      status: 503,
      category: "provider_unavailable",
      retryable: true,
      ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    });
  }
  return planningError("openrouter_request_rejected", "OpenRouter rejected the bounded planning request", {
    status: 502,
    category: "provider_protocol",
    retryable: false,
  });
}

function nonNegativeInteger(value: unknown): number | undefined {
  return Number.isSafeInteger(value) && (value as number) >= 0 ? value as number : undefined;
}

function nonNegativeNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
}

function exactUsage(
  response: ProviderResponse,
  requirements: StructuredJsonCall<unknown>["requireExactUsage"],
): OpenRouterExactUsage {
  const inputTokens = nonNegativeInteger(response.usage?.prompt_tokens);
  const outputTokens = nonNegativeInteger(response.usage?.completion_tokens);
  const providerTokens = nonNegativeInteger(response.usage?.total_tokens);
  const billedCostUsd = nonNegativeNumber(response.usage?.cost);
  const exactTokenUsage = inputTokens !== undefined
    && outputTokens !== undefined
    && providerTokens !== undefined
    && providerTokens >= inputTokens + outputTokens;
  const exactCostUsage = billedCostUsd !== undefined;
  if ((requirements?.tokens ?? true) && !exactTokenUsage) {
    throw planningError("openrouter_exact_token_usage_missing", "OpenRouter did not return exact token usage", {
      status: 502,
      category: "provider_protocol",
      retryable: true,
    });
  }
  if ((requirements?.cost ?? true) && !exactCostUsage) {
    throw planningError("openrouter_exact_cost_usage_missing", "OpenRouter did not return exact billed cost", {
      status: 502,
      category: "provider_protocol",
      retryable: true,
    });
  }
  return {
    ...(inputTokens === undefined ? {} : { inputTokens }),
    ...(outputTokens === undefined ? {} : { outputTokens }),
    ...(providerTokens === undefined ? {} : { providerTokens }),
    ...(billedCostUsd === undefined ? {} : { billedCostUsd }),
    exactTokenUsage,
    exactCostUsage,
  };
}

function providerResponse(value: unknown): ProviderResponse {
  const root = record(value);
  if (!root || typeof root.model !== "string" || !MODEL.test(root.model)) {
    throw planningError("openrouter_response_invalid", "OpenRouter returned an invalid response envelope", {
      status: 502,
      category: "provider_protocol",
      retryable: true,
    });
  }
  if (!Array.isArray(root.choices) || root.choices.length !== 1) {
    throw planningError("openrouter_response_invalid", "OpenRouter returned an invalid choice count", {
      status: 502,
      category: "provider_protocol",
      retryable: true,
    });
  }
  return root as unknown as ProviderResponse;
}

function responseValue<T>(response: ProviderResponse, validate: (value: unknown) => T): T {
  const choice = response.choices[0];
  if (
    !choice ||
    choice.finish_reason !== "stop" ||
    !choice.message ||
    typeof choice.message.content !== "string" ||
    !choice.message.content.trim() ||
    (choice.message.tool_calls !== undefined && (
      !Array.isArray(choice.message.tool_calls) || choice.message.tool_calls.length > 0
    ))
  ) {
    throw planningError("openrouter_structured_content_missing", "OpenRouter did not return one completed tool-free JSON response", {
      status: 502,
      category: "provider_protocol",
      retryable: true,
    });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(choice.message.content) as unknown;
  } catch {
    throw planningError("openrouter_structured_json_invalid", "OpenRouter returned malformed structured JSON", {
      status: 502,
      category: "provider_protocol",
      retryable: true,
    });
  }
  try {
    return validate(parsed);
  } catch {
    throw planningError("openrouter_structured_json_rejected", "OpenRouter returned JSON that failed local schema validation", {
      status: 502,
      category: "provider_protocol",
      retryable: true,
    });
  }
}

function abortError(timedOut: boolean): OpenRouterPlanningError {
  return timedOut
    ? planningError("openrouter_timeout", "The OpenRouter planning request timed out", {
        status: 503,
        category: "timeout",
        retryable: true,
      })
    : planningError("openrouter_cancelled", "The OpenRouter planning request was cancelled", {
        status: 499,
        category: "cancelled",
        retryable: true,
      });
}

export class OpenRouterPlanningClient implements StructuredJsonProviderClient {
  readonly providerId = "openrouter" as const;
  readonly #options: NormalizedConfiguration;

  constructor(options: OpenRouterPlanningClientOptions) {
    this.#options = normalizeConfiguration(options);
  }

  async callStructuredJson<T>(input: StructuredJsonCall<T>): Promise<StructuredJsonResult<T>> {
    const requestedModel = model(input.model);
    const normalizedMessages = messages(input.messages);
    const responseContract = strictSchema(input.response);
    const exposure = exposureReferences(input.exposure);
    if (input.signal?.aborted) throw abortError(false);
    const resolvedConfiguration = resolveOpenRouterModelConfiguration({
      model: requestedModel,
      endpoint: this.#options.endpoint,
    });
    assertOpenRouterConfigurationHash(
      exposure.modelConfigurationHash,
      resolvedConfiguration.configurationHash,
    );
    const body = canonicalJson({
      model: requestedModel,
      messages: normalizedMessages,
      stream: false,
      tools: [],
      tool_choice: "none",
      response_format: {
        type: "json_schema",
        json_schema: {
          name: responseContract.name,
          ...(responseContract.description ? { description: responseContract.description } : {}),
          strict: true,
          schema: responseContract.schema,
        },
      },
      provider: { require_parameters: true },
      usage: { include: true },
    });
    const requestBodyBytes = Buffer.byteLength(body, "utf8");
    if (requestBodyBytes > this.#options.maximumRequestBytes) {
      throw invalidInput("openrouter_request_too_large", "The OpenRouter request exceeds its byte limit");
    }

    const requestBodyHash = sha256(body);
    let authorization;
    try {
      authorization = await this.#options.requestAuditor.authorize({
        providerId: "openrouter",
        exposure,
        requestedModel,
        endpoint: this.#options.endpoint,
        requestContractVersion: "ti-scale.openrouter-structured-request.v1",
        requestBodyHash,
        requestBodyBytes,
      });
    } catch (error) {
      if (error instanceof OpenRouterPlanningError) throw error;
      throw planningError(
        "openrouter_request_audit_failed",
        "The exact public-provider request could not be durably authorized",
        {
          status: 503,
          category: "persistence",
          retryable: true,
          remediation: "Restore the V2 provider audit path before retrying.",
        },
      );
    }
    if (
      authorization.authorized !== true ||
      authorization.exposureReceiptId !== exposure.exposureReceiptId ||
      authorization.contextPackId !== exposure.contextPackId ||
      authorization.requestedModel !== requestedModel ||
      authorization.modelConfigurationHash !== exposure.modelConfigurationHash ||
      authorization.requestBodyHash !== requestBodyHash ||
      !OPAQUE_ID.test(authorization.providerTurnId) ||
      !Number.isFinite(Date.parse(authorization.committedAt))
    ) {
      throw planningError(
        "openrouter_request_audit_mismatch",
        "The durable provider request authorization did not match the exact outbound request",
        { status: 503, category: "policy_denied", retryable: false },
      );
    }
    if (input.signal?.aborted) throw abortError(false);

    // Credential access is intentionally last: no key is read until the exact
    // body hash is durably committed and revalidated above.
    const key = this.#options.credentialReader();

    const controller = new AbortController();
    let timedOut = false;
    const cancel = () => controller.abort();
    input.signal?.addEventListener("abort", cancel, { once: true });
    let rejectForAbort: (() => void) | undefined;
    const aborted = new Promise<never>((_resolve, reject) => {
      rejectForAbort = () => reject(abortError(timedOut));
      controller.signal.addEventListener("abort", rejectForAbort, { once: true });
    });
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.#options.timeoutMs);
    timeout.unref?.();
    // Close the narrow race between the initial check and listener registration.
    if (input.signal?.aborted) controller.abort();
    let activeResponse: Response | undefined;
    try {
      let response: Response;
      try {
        response = await Promise.race([
          this.#options.fetch(this.#options.endpoint, {
            method: "POST",
            headers: {
              Accept: "application/json",
              Authorization: `Bearer ${key}`,
              "Content-Type": "application/json",
            },
            body,
            redirect: "error",
            signal: controller.signal,
          }),
          aborted,
        ]);
      } catch (error) {
        if (error instanceof OpenRouterPlanningError) throw error;
        if (controller.signal.aborted) throw abortError(timedOut);
        throw planningError("openrouter_network_unavailable", "The OpenRouter planning request could not reach the provider", {
          status: 503,
          category: "provider_unavailable",
          retryable: true,
        });
      }
      activeResponse = response;
      if (response.redirected || response.status >= 300 && response.status < 400) {
        await response.body?.cancel().catch(() => undefined);
        throw statusError(response, this.#options.now());
      }
      if (response.status !== 200) {
        await response.body?.cancel().catch(() => undefined);
        throw statusError(response, this.#options.now());
      }
      const contentType = response.headers.get("content-type")?.toLocaleLowerCase("en-US") ?? "";
      if (!contentType.includes("application/json")) {
        await response.body?.cancel().catch(() => undefined);
        throw planningError("openrouter_content_type_invalid", "OpenRouter returned a non-JSON response", {
          status: 502,
          category: "provider_protocol",
          retryable: true,
        });
      }
      const text = await Promise.race([
        readBoundedResponse(response, this.#options.maximumResponseBytes, controller.signal),
        aborted,
      ]);
      activeResponse = undefined;
      let decoded: unknown;
      try {
        decoded = JSON.parse(text) as unknown;
      } catch {
        throw planningError("openrouter_response_json_invalid", "OpenRouter returned malformed response JSON", {
          status: 502,
          category: "provider_protocol",
          retryable: true,
        });
      }
      const envelope = providerResponse(decoded);
      const usage = exactUsage(envelope, input.requireExactUsage);
      let value: T;
      try {
        value = responseValue(envelope, responseContract.validate);
      } catch (error) {
        if (error instanceof OpenRouterPlanningError) {
          throw new OpenRouterPlanningError(
            error.code,
            error.message,
            {
              status: error.status,
              category: error.category,
              retryable: error.retryable,
              ...(error.retryAfterMs === undefined
                ? {}
                : { retryAfterMs: error.retryAfterMs }),
              ...(error.remediation
                ? { remediation: error.remediation }
                : {}),
              usage,
              returnedModel: envelope.model,
            },
          );
        }
        throw error;
      }
      return {
        value,
        providerId: "openrouter",
        requestedModel,
        returnedModel: envelope.model,
        usage,
        exposure,
      };
    } catch (error) {
      if (error instanceof OpenRouterPlanningError) throw error;
      if (controller.signal.aborted) throw abortError(timedOut);
      throw planningError("openrouter_response_failed", "The OpenRouter planning response could not be processed", {
        status: 502,
        category: "provider_protocol",
        retryable: true,
      });
    } finally {
      if (controller.signal.aborted) {
        await activeResponse?.body?.cancel().catch(() => undefined);
      }
      clearTimeout(timeout);
      if (rejectForAbort) controller.signal.removeEventListener("abort", rejectForAbort);
      input.signal?.removeEventListener("abort", cancel);
    }
  }
}

export function createOpenRouterPlanningClient(
  options: OpenRouterPlanningClientOptions,
): OpenRouterPlanningClient {
  return new OpenRouterPlanningClient(options);
}

export type OpenRouterMessageRole = "system" | "user" | "assistant";

export interface OpenRouterStructuredMessage {
  readonly role: OpenRouterMessageRole;
  readonly content: string;
}

/**
 * Public-provider context is referenced only by canonical opaque identifiers.
 * The client deliberately has no API for raw memory, evidence, or receipt data.
 */
export interface ProviderExposureReferences {
  readonly exposureReceiptId: string;
  readonly contextPackId: string;
  /** Exact resolved configuration selected before the canonical provider turn starts. */
  readonly modelConfigurationHash: string;
  /**
   * Advisory-only authority fields. They are optional for historical,
   * Guided/Commander and Research Lab receipts, but must appear together for
   * the autonomous planning exposure policy.
   */
  readonly planningDisclosureMode?: "public_only" | "sanitized_internal";
  readonly advisoryIdentityHash?: string;
}

export interface ProviderRequestAuthorizationInput {
  readonly providerId: "openrouter";
  readonly exposure: ProviderExposureReferences;
  readonly requestedModel: string;
  readonly endpoint: string;
  readonly requestContractVersion: "ti-scale.openrouter-structured-request.v1";
  /** SHA-256 of the exact UTF-8 bytes supplied to fetch as `body`. */
  readonly requestBodyHash: string;
  readonly requestBodyBytes: number;
}

export interface ProviderRequestAuthorization {
  readonly authorized: true;
  readonly exposureReceiptId: string;
  readonly contextPackId: string;
  readonly providerTurnId: string;
  readonly requestedModel: string;
  readonly modelConfigurationHash: string;
  readonly planningDisclosureMode?: "public_only" | "sanitized_internal";
  readonly advisoryIdentityHash?: string;
  readonly requestBodyHash: string;
  readonly committedAt: string;
}

/**
 * Local durable authorization boundary. Implementations must commit the exact
 * request hash before returning. A provider client without one fails closed.
 */
export interface ProviderRequestAuditor {
  authorize(input: ProviderRequestAuthorizationInput): Promise<ProviderRequestAuthorization>;
}

export interface StructuredJsonSchema<T> {
  readonly name: string;
  readonly description?: string;
  readonly schema: Readonly<Record<string, unknown>>;
  /** Local validation remains authoritative even when the provider promises strict JSON. */
  readonly validate: (value: unknown) => T;
}

export interface ExactUsageRequirements {
  readonly tokens?: boolean;
  readonly cost?: boolean;
}

export interface StructuredJsonCall<T> {
  readonly model: string;
  readonly messages: readonly OpenRouterStructuredMessage[];
  readonly response: StructuredJsonSchema<T>;
  readonly exposure: ProviderExposureReferences;
  readonly signal?: AbortSignal;
  /** Both are required by default. Disable only when the caller has no finite matching budget. */
  readonly requireExactUsage?: ExactUsageRequirements;
}

export interface OpenRouterExactUsage {
  readonly inputTokens?: number;
  readonly outputTokens?: number;
  readonly providerTokens?: number;
  readonly billedCostUsd?: number;
  readonly exactTokenUsage: boolean;
  readonly exactCostUsage: boolean;
}

export interface StructuredJsonResult<T> {
  readonly value: T;
  readonly providerId: "openrouter";
  readonly requestedModel: string;
  readonly returnedModel: string;
  readonly usage: OpenRouterExactUsage;
  readonly exposure: ProviderExposureReferences;
}

export interface StructuredJsonProviderClient {
  callStructuredJson<T>(input: StructuredJsonCall<T>): Promise<StructuredJsonResult<T>>;
}

export type OpenRouterPlanningErrorCategory =
  | "invalid_configuration"
  | "invalid_input"
  | "authentication_missing"
  | "authentication_failed"
  | "rate_limit"
  | "provider_unavailable"
  | "provider_protocol"
  | "policy_denied"
  | "persistence"
  | "timeout"
  | "cancelled";

export interface OpenRouterPlanningErrorOptions {
  readonly status: number;
  readonly category: OpenRouterPlanningErrorCategory;
  readonly retryable: boolean;
  readonly retryAfterMs?: number;
  readonly remediation?: string;
  /**
   * Exact provider usage already returned in a valid response envelope before
   * a later local structured-response check failed. This is audit telemetry,
   * not a partial result.
   */
  readonly usage?: OpenRouterExactUsage;
  readonly returnedModel?: string;
}

/** A deliberately redacted error contract. It never retains response bodies, headers, keys, or causes. */
export class OpenRouterPlanningError extends Error {
  readonly status: number;
  readonly category: OpenRouterPlanningErrorCategory;
  readonly retryable: boolean;
  readonly retryAfterMs?: number;
  readonly remediation?: string;
  readonly usage?: OpenRouterExactUsage;
  readonly returnedModel?: string;

  constructor(
    readonly code: string,
    message: string,
    options: OpenRouterPlanningErrorOptions,
  ) {
    super(message);
    this.name = "OpenRouterPlanningError";
    this.status = options.status;
    this.category = options.category;
    this.retryable = options.retryable;
    this.retryAfterMs = options.retryAfterMs;
    this.remediation = options.remediation;
    this.usage = options.usage;
    this.returnedModel = options.returnedModel;
  }

  toJSON(): Readonly<Record<string, unknown>> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      status: this.status,
      category: this.category,
      retryable: this.retryable,
      ...(this.retryAfterMs === undefined ? {} : { retryAfterMs: this.retryAfterMs }),
      ...(this.remediation ? { remediation: this.remediation } : {}),
      ...(this.usage ? { usage: this.usage } : {}),
      ...(this.returnedModel ? { returnedModel: this.returnedModel } : {}),
    };
  }
}

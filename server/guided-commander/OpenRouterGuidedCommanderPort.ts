import {
  assertOpenRouterConfigurationHash,
  OpenRouterPlanningError,
  resolveOpenRouterModelConfiguration,
  type ExactUsageRequirements,
  type OpenRouterModelAttestation,
  type ResolvedOpenRouterModelConfiguration,
  type StructuredJsonProviderClient,
} from "../providers/openrouter";
import {
  buildGuidedCommanderProviderMessages,
  GUIDED_COMMANDER_RESPONSE_JSON_SCHEMA,
} from "./GuidedCommanderProviderContract";
import type {
  GuidedCommanderPort,
  GuidedCommanderPortInput,
  GuidedCommanderPortResponse,
} from "./types";
import { GuidedCommanderError, validatePortResponse } from "./validation";

export interface OpenRouterGuidedCommanderPortOptions {
  readonly client: StructuredJsonProviderClient;
  readonly configuration: ResolvedOpenRouterModelConfiguration;
  readonly readinessAttestation: OpenRouterModelAttestation;
  readonly requireExactUsage?: ExactUsageRequirements;
  readonly now?: () => Date;
}

function missingReceipt(): GuidedCommanderError {
  return new GuidedCommanderError(
    503,
    "guided_commander_exposure_receipt_missing",
    "The public-provider exposure receipt is missing",
    {
      humanMessage: "The explanation was not sent because its public-provider disclosure receipt is unavailable.",
      category: "policy_denied",
      retryable: false,
      remediation: "Retry after the canonical Brain context and provider exposure receipt are durably prepared.",
    },
  );
}

function readinessExpired(): GuidedCommanderError {
  return new GuidedCommanderError(
    503,
    "guided_commander_openrouter_readiness_expired",
    "The pinned OpenRouter readiness attestation is no longer fresh",
    {
      humanMessage: "The explanation was not sent because its live provider verification expired.",
      category: "provider_unavailable",
      retryable: true,
      remediation: "Run a new audited content-free readiness probe and mount its matching pinned configuration.",
    },
  );
}

function providerFailure(error: unknown): GuidedCommanderError {
  if (error instanceof GuidedCommanderError) return error;
  if (error instanceof OpenRouterPlanningError) {
    const knownCategories = new Set([
      "invalid_configuration",
      "invalid_input",
      "authentication_missing",
      "authentication_failed",
      "rate_limit",
      "provider_unavailable",
      "provider_protocol",
      "policy_denied",
      "persistence",
      "timeout",
      "cancelled",
    ]);
    const category = knownCategories.has(error.category) ? error.category : "provider_unavailable";
    const status = category === "rate_limit"
      ? 429
      : category === "provider_protocol" ? 502 : 503;
    const humanMessage = category === "rate_limit"
      ? "The explanation provider is temporarily rate-limited. The Guided step remains paused and unchanged."
      : category === "timeout"
        ? "The explanation provider did not respond in time. The Guided step remains paused and unchanged."
        : category === "cancelled"
          ? "The explanation request was cancelled. The Guided step remains paused and unchanged."
          : category === "authentication_missing" || category === "authentication_failed"
            ? "The explanation provider is not authenticated. No mission state changed."
            : category === "policy_denied" || category === "persistence"
              ? "The explanation was not sent because its exact disclosure audit could not be verified and committed."
            : "The explanation provider could not return a safe structured response. No mission state changed.";
    const remediation = category === "authentication_missing" || category === "authentication_failed"
      ? "Restore the service-owned OpenRouter credential and rerun provider readiness."
      : category === "rate_limit"
        ? "Wait for the provider retry window before requesting another explanation."
        : category === "policy_denied" || category === "persistence"
          ? "Create a fresh matching provider turn and disclosure receipt after the V2 audit store is healthy."
        : "Retry after the planning-only provider is healthy.";
    return new GuidedCommanderError(status, "guided_commander_openrouter_failed", "OpenRouter planning-only request failed", {
      humanMessage,
      category,
      retryable: error.retryable,
      remediation,
      ...(Number.isFinite(error.retryAfterMs) && (error.retryAfterMs ?? -1) >= 0
        ? { details: { retryAfterMs: error.retryAfterMs } }
        : {}),
    });
  }
  return new GuidedCommanderError(502, "guided_commander_openrouter_failed", "OpenRouter planning-only request failed", {
    humanMessage: "The explanation provider failed safely. The Guided step remains paused and unchanged.",
    category: "provider_unavailable",
    retryable: true,
    remediation: "Retry after provider health recovers.",
  });
}

/** Public-provider explanation adapter. It has no executor, tool, or plan-mutation surface. */
export class OpenRouterGuidedCommanderPort implements GuidedCommanderPort {
  readonly kind = "planning_only" as const;
  readonly supportsToolExecution = false as const;
  readonly contextBoundary = "public_provider" as const;
  readonly providerId = "openrouter";
  readonly model: string;
  readonly modelConfigurationHash: string;
  readonly #client: StructuredJsonProviderClient;
  readonly #requireExactUsage?: ExactUsageRequirements;
  readonly #attestationExpiresAt: number;
  readonly #now: () => Date;

  constructor(options: OpenRouterGuidedCommanderPortOptions) {
    if (!options.client || typeof options.client.callStructuredJson !== "function") {
      throw new TypeError("OpenRouter structured JSON client is required");
    }
    if (!options.configuration || !options.readinessAttestation) {
      throw new TypeError("OpenRouter Guided configuration and readiness attestation are required");
    }
    const resolved = resolveOpenRouterModelConfiguration({
      model: options.configuration.model,
      endpoint: options.configuration.endpoint,
    });
    assertOpenRouterConfigurationHash(options.configuration.configurationHash, resolved.configurationHash);
    const attestation = options.readinessAttestation;
    if (
      attestation.providerId !== "openrouter" ||
      attestation.model !== resolved.model ||
      attestation.modelConfigurationHash !== resolved.configurationHash
    ) {
      throw new TypeError("OpenRouter Guided readiness does not match the pinned model configuration");
    }
    this.#now = options.now ?? (() => new Date());
    const now = this.#now();
    const attestationExpiresAt = Date.parse(attestation.expiresAt);
    if (
      !Number.isFinite(now.getTime()) ||
      !Number.isFinite(attestationExpiresAt) ||
      attestationExpiresAt <= now.getTime() ||
      attestation.callabilityVerification !== "audited_content_free_completion" ||
      attestation.callable !== true || attestation.supportsGuided !== true
    ) {
      throw new TypeError("OpenRouter Guided readiness is stale or has not proven an audited completion");
    }
    this.#client = options.client;
    this.model = resolved.model;
    this.modelConfigurationHash = resolved.configurationHash;
    this.#attestationExpiresAt = attestationExpiresAt;
    this.#requireExactUsage = options.requireExactUsage;
  }

  async respond(
    input: GuidedCommanderPortInput,
    signal: AbortSignal,
  ): Promise<GuidedCommanderPortResponse> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const now = this.#now();
    if (!Number.isFinite(now.getTime()) || now.getTime() >= this.#attestationExpiresAt) {
      throw readinessExpired();
    }
    const exposureReceiptId = input.brainContext.exposureReceiptId?.trim();
    if (!exposureReceiptId) throw missingReceipt();
    const startedAt = performance.now();
    try {
      const result = await this.#client.callStructuredJson({
        model: this.model,
        messages: buildGuidedCommanderProviderMessages(input),
        response: {
          name: "ti_scale_guided_commander_response",
          description: "One planning-only Guided explanation or interpretation",
          schema: GUIDED_COMMANDER_RESPONSE_JSON_SCHEMA,
          validate: validatePortResponse,
        },
        exposure: {
          exposureReceiptId,
          contextPackId: input.brainContext.contextPackId,
          modelConfigurationHash: this.modelConfigurationHash,
        },
        signal,
        ...(this.#requireExactUsage ? { requireExactUsage: this.#requireExactUsage } : {}),
      });
      return {
        ...validatePortResponse(result.value),
        providerUsage: {
          providerId: result.providerId,
          requestedModel: result.requestedModel,
          returnedModel: result.returnedModel,
          ...(result.usage.inputTokens === undefined ? {} : { inputTokens: result.usage.inputTokens }),
          ...(result.usage.outputTokens === undefined ? {} : { outputTokens: result.usage.outputTokens }),
          ...(result.usage.providerTokens === undefined ? {} : { totalTokens: result.usage.providerTokens }),
          ...(result.usage.billedCostUsd === undefined ? {} : { billedCostUsd: result.usage.billedCostUsd }),
          exactTokenUsage: result.usage.exactTokenUsage,
          exactCostUsage: result.usage.exactCostUsage,
          latencyMs: Math.max(0, Math.round(performance.now() - startedAt)),
        },
      };
    } catch (error) {
      throw providerFailure(error);
    }
  }
}

export function createOpenRouterGuidedCommanderPort(
  options: OpenRouterGuidedCommanderPortOptions,
): OpenRouterGuidedCommanderPort {
  return new OpenRouterGuidedCommanderPort(options);
}

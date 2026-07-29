import type { ResolvedOpenRouterModelConfiguration } from "./OpenRouterModelConfiguration";
import type {
  OpenRouterCompletionProbeResult,
  OpenRouterCompletionVerifier,
} from "./OpenRouterReadinessProbe";
import type { StructuredJsonProviderClient } from "./types";

export interface OpenRouterAuditedCompletionVerifierOptions {
  readonly client: StructuredJsonProviderClient;
  readonly exposureReceiptId: string;
  readonly contextPackId: string;
}

interface ReadinessAcknowledgement {
  readonly ready: true;
}

/**
 * A bounded, content-free readiness completion. It uses the exact same
 * strict-schema, tools-disabled, durably audited client as Guided dispatch and
 * carries no mission, target, transcript, evidence, or memory text.
 */
export class OpenRouterAuditedCompletionVerifier implements OpenRouterCompletionVerifier {
  readonly #client: StructuredJsonProviderClient;
  readonly #exposureReceiptId: string;
  readonly #contextPackId: string;

  constructor(options: OpenRouterAuditedCompletionVerifierOptions) {
    if (!options.client || typeof options.client.callStructuredJson !== "function") {
      throw new TypeError("An audited OpenRouter structured client is required");
    }
    this.#client = options.client;
    this.#exposureReceiptId = options.exposureReceiptId;
    this.#contextPackId = options.contextPackId;
  }

  async verify(
    configuration: ResolvedOpenRouterModelConfiguration,
    signal: AbortSignal,
  ): Promise<OpenRouterCompletionProbeResult> {
    const startedAt = performance.now();
    const result = await this.#client.callStructuredJson<ReadinessAcknowledgement>({
      model: configuration.model,
      messages: [
        {
          role: "system",
          content: "Return the constant readiness acknowledgement. This probe contains no mission data and cannot execute tools.",
        },
        { role: "user", content: "Return {\"ready\":true}." },
      ],
      response: {
        name: "ti_scale_openrouter_readiness",
        description: "Content-free strict-schema provider readiness acknowledgement",
        schema: {
          type: "object",
          properties: { ready: { type: "boolean", enum: [true] } },
          required: ["ready"],
          additionalProperties: false,
        },
        validate(value): ReadinessAcknowledgement {
          if (!value || typeof value !== "object" || Array.isArray(value) ||
            (value as Record<string, unknown>).ready !== true) {
            throw new TypeError("Invalid readiness acknowledgement");
          }
          return { ready: true };
        },
      },
      exposure: {
        exposureReceiptId: this.#exposureReceiptId,
        contextPackId: this.#contextPackId,
        modelConfigurationHash: configuration.configurationHash,
      },
      signal,
      requireExactUsage: { tokens: true, cost: true },
    });
    return {
      requestedModel: result.requestedModel,
      returnedModel: result.returnedModel,
      modelConfigurationHash: configuration.configurationHash,
      strictSchemaVerified: true,
      toolFreeVerified: true,
      exactTokenUsage: result.usage.exactTokenUsage,
      exactCostUsage: result.usage.exactCostUsage,
      ...(result.usage.inputTokens === undefined ? {} : { inputTokens: result.usage.inputTokens }),
      ...(result.usage.outputTokens === undefined ? {} : { outputTokens: result.usage.outputTokens }),
      ...(result.usage.providerTokens === undefined ? {} : { totalTokens: result.usage.providerTokens }),
      ...(result.usage.billedCostUsd === undefined ? {} : { billedCostUsd: result.usage.billedCostUsd }),
      latencyMs: Math.max(0, Math.round(performance.now() - startedAt)),
      requestAuditReceiptId: result.exposure.exposureReceiptId,
    };
  }
}

export function createOpenRouterAuditedCompletionVerifier(
  options: OpenRouterAuditedCompletionVerifierOptions,
): OpenRouterAuditedCompletionVerifier {
  return new OpenRouterAuditedCompletionVerifier(options);
}

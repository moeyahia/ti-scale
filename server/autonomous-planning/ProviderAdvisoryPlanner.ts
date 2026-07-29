import { canonicalJson } from "../missions/canonical";
import {
  compileProviderAdvisorySelection,
  validateProviderAdvisorySelection,
} from "./ProviderAdvisoryCompiler";
import { prepareProviderAdvisoryBrief } from "./ProviderAdvisoryExposure";
import {
  ProviderAdvisoryPlanningError,
  type PreparedProviderAdvisoryBrief,
  type ProviderAdvisoryPlanningInput,
  type ProviderAdvisoryPlanningOutcome,
} from "./ProviderAdvisoryPlanningTypes";
import { reconstructProviderAdvisoryCandidateCatalog } from "./ProviderAdvisoryCandidateCatalog";

const HASH = /^[a-f0-9]{64}$/u;
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$/u;
const INVALID_STRUCTURED_RESPONSE_CODES = new Set([
  "openrouter_structured_json_rejected",
  "openrouter_structured_json_invalid",
  "openrouter_structured_content_missing",
]);

function safeProviderCode(error: unknown): string {
  if (
    error !== null
    && typeof error === "object"
    && "code" in error
    && typeof error.code === "string"
    && /^[a-z0-9_.:-]{1,120}$/u.test(error.code)
  ) return error.code;
  return "provider_advisory_unavailable";
}

function unavailable(message: string): never {
  throw new ProviderAdvisoryPlanningError(
    "provider_advisory_unavailable",
    message,
    "provider_unavailable",
    true,
  );
}

function invalidResponse(code: string, message: string): never {
  throw new ProviderAdvisoryPlanningError(
    code,
    message,
    "invalid_provider_response",
    false,
  );
}

function cancelled(): never {
  throw new ProviderAdvisoryPlanningError(
    "provider_advisory_cancelled",
    "The provider-advisory planning request was cancelled.",
    "cancelled",
    true,
  );
}

function assertExposureBinding(
  prepared: PreparedProviderAdvisoryBrief,
  input: ProviderAdvisoryPlanningInput,
): void {
  if (
    !input.provider
    || input.provider.mode !== "advisor_only"
    || input.provider.executionAuthority !== "none"
  ) invalidResponse(
    "provider_advisory_authority_invalid",
    "The configured planning provider is not an advisory-only boundary.",
  );
  if (
    typeof input.modelId !== "string"
    || !OPAQUE_ID.test(input.modelId)
    || !input.exposure
    || input.exposure.exposureReceiptId !==
      prepared.exposureReceipt.id
    || input.exposure.contextPackId !== input.catalog.contextPackId
    || !HASH.test(input.exposure.modelConfigurationHash)
  ) invalidResponse(
    "provider_advisory_exposure_binding_invalid",
    "The provider model, Context Pack or exposure receipt binding is incomplete.",
  );
}

/**
 * Fail-closed provider-advisory orchestration boundary. This class cannot
 * execute a tool, create candidate materialization, or silently replace the
 * signed provider route with a local route.
 */
export class ProviderAdvisoryAutonomousPlanner {
  prepare(
    input: Pick<
      ProviderAdvisoryPlanningInput,
      "catalog" | "provider" | "modelId" | "createdAt" | "contextItems"
    >,
  ): PreparedProviderAdvisoryBrief {
    if (!input.provider || !input.modelId) {
      unavailable("A provider and exact model are required to prepare public advice.");
    }
    if (
      input.provider.mode !== "advisor_only"
      || input.provider.executionAuthority !== "none"
    ) invalidResponse(
      "provider_advisory_authority_invalid",
      "The configured planning provider is not advisory-only.",
    );
    return prepareProviderAdvisoryBrief({
      catalog: input.catalog,
      providerId: input.provider.providerId,
      modelId: input.modelId,
      createdAt: input.createdAt,
      contextItems: input.contextItems,
    });
  }

  async plan(
    rawInput: ProviderAdvisoryPlanningInput,
    signal: AbortSignal,
  ): Promise<ProviderAdvisoryPlanningOutcome> {
    if (signal.aborted) cancelled();
    const catalog = reconstructProviderAdvisoryCandidateCatalog(
      JSON.parse(canonicalJson(rawInput.catalog)) as unknown,
    );
    const input: ProviderAdvisoryPlanningInput = {
      ...rawInput,
      catalog,
    };
    if (!input.provider) {
      unavailable(
        "The signed advisory provider is not configured; no local fallback was applied.",
      );
    }
    if (!input.modelId || !input.exposure) invalidResponse(
      "provider_advisory_exposure_binding_missing",
      "Provider advice requires an exact model and persisted exposure binding.",
    );
    const prepared = this.prepare(input);
    assertExposureBinding(prepared, input);

    let providerResult;
    try {
      providerResult = await input.provider.advise({
        modelId: input.modelId,
        brief: prepared.brief,
        exposure: input.exposure,
        signal,
      });
    } catch (error) {
      if (signal.aborted) cancelled();
      const code = safeProviderCode(error);
      if (INVALID_STRUCTURED_RESPONSE_CODES.has(code)) invalidResponse(
        "provider_advisory_structured_response_rejected",
        "The provider returned content outside the strict advisory response schema.",
      );
      unavailable(
        `The signed advisory provider did not return a usable response (${code}); no local fallback was applied.`,
      );
    }
    if (
      providerResult.providerId !== input.provider.providerId
      || providerResult.requestedModel !== input.modelId
      || typeof providerResult.returnedModel !== "string"
      || !providerResult.returnedModel.trim()
      || providerResult.usage.exactTokenUsage !== true
      || providerResult.usage.exactCostUsage !== true
    ) invalidResponse(
      "provider_advisory_result_binding_mismatch",
      "The provider result does not match its exact advisory model and usage contract.",
    );
    const selection = validateProviderAdvisorySelection(
      providerResult.value,
      catalog,
    );
    const compiled = compileProviderAdvisorySelection({
      catalog,
      selection,
      expectedContractHash: input.expectedContractHash,
      expectedPolicyHash: input.expectedPolicyHash,
      expectedContextPackId: input.expectedContextPackId,
      source: "provider_advisory",
      providerResult,
      briefHash: prepared.briefHash,
      exposureReceiptId: prepared.exposureReceipt.id,
    });
    return {
      ...compiled,
      preparedBrief: prepared,
    };
  }
}

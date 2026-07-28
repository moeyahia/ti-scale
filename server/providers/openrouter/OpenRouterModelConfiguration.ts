import { canonicalJson, sha256 } from "../../missions/canonical";
import { OpenRouterPlanningError } from "./types";

const MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$/u;
export const OPENROUTER_CHAT_COMPLETIONS_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions";

export interface ResolvedOpenRouterModelConfiguration {
  readonly schemaVersion: "ti-scale.openrouter-model-configuration.v1";
  readonly providerId: "openrouter";
  readonly model: string;
  readonly endpoint: string;
  readonly responseContract: "strict_json_schema";
  readonly toolPolicy: "tools_explicitly_disabled";
  readonly usagePolicy: "provider_usage_required";
  readonly configurationHash: string;
}

function invalidConfiguration(message: string): never {
  throw new OpenRouterPlanningError("openrouter_model_configuration_invalid", message, {
    status: 500,
    category: "invalid_configuration",
    retryable: false,
  });
}

/** The endpoint can never leave OpenRouter's official HTTPS completion route. */
export function validateOpenRouterEndpoint(value = OPENROUTER_CHAT_COMPLETIONS_ENDPOINT): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return invalidConfiguration("The OpenRouter endpoint is invalid");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.origin !== "https://openrouter.ai" ||
    parsed.pathname !== "/api/v1/chat/completions" ||
    parsed.username || parsed.password || parsed.search || parsed.hash
  ) {
    return invalidConfiguration("The OpenRouter endpoint must use the allowlisted official HTTPS completion route");
  }
  return parsed.toString();
}

/**
 * Resolve the one immutable configuration used by readiness, the Guided
 * adapter, request authorization, and dispatch. The hash deliberately binds
 * behavior-affecting request controls, not only the human-readable model ID.
 */
export function resolveOpenRouterModelConfiguration(input: {
  readonly model: string;
  readonly endpoint?: string;
}): ResolvedOpenRouterModelConfiguration {
  const model = input.model?.trim();
  if (!model || !MODEL_PATTERN.test(model)) {
    return invalidConfiguration("The pinned OpenRouter model identifier is invalid");
  }
  const seed = {
    schemaVersion: "ti-scale.openrouter-model-configuration.v1" as const,
    providerId: "openrouter" as const,
    model,
    endpoint: validateOpenRouterEndpoint(input.endpoint ?? OPENROUTER_CHAT_COMPLETIONS_ENDPOINT),
    responseContract: "strict_json_schema" as const,
    toolPolicy: "tools_explicitly_disabled" as const,
    usagePolicy: "provider_usage_required" as const,
  };
  return Object.freeze({
    ...seed,
    configurationHash: sha256(canonicalJson(seed)),
  });
}

export function assertOpenRouterConfigurationHash(value: string, expected: string): void {
  if (!/^[a-f0-9]{64}$/u.test(value) || value !== expected) {
    invalidConfiguration("The OpenRouter model configuration does not match its pinned readiness binding");
  }
}

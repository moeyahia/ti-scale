import { OpenRouterConnectionError } from "./OpenRouterConnectionError";
import {
  OpenRouterConnectionStore,
  resolveProviderConfigurationRoot,
} from "./OpenRouterConnectionStore";
import type { OpenRouterConfigurationSource } from "./OpenRouterConnectionTypes";
import {
  resolveOpenRouterGuidedStandaloneConfiguration,
  type OpenRouterGuidedStandaloneConfiguration,
} from "./OpenRouterStandaloneConfiguration";

export interface LoadedOpenRouterConnectionConfiguration {
  readonly store: OpenRouterConnectionStore;
  readonly configuration: OpenRouterGuidedStandaloneConfiguration;
  readonly source: OpenRouterConfigurationSource;
  readonly activeConfigurationVersion: number | null;
}

export interface LoadOpenRouterConnectionConfigurationOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly serviceUid?: number;
  readonly clock?: () => Date;
}

function blockedFromStore(
  error: OpenRouterConnectionError,
): OpenRouterGuidedStandaloneConfiguration {
  return {
    state: "blocked",
    reasonCode: "provider_config_store_invalid",
    reason: error.message,
    remediation: error.remediation,
  };
}

/**
 * Load the canonical provider-config record before falling back to the
 * backwards-compatible non-secret environment path.
 *
 * A present-but-invalid canonical record wins and fails closed: Ti-Scale must
 * never silently bypass a damaged service-owned credential boundary by
 * falling through to unrelated environment configuration.
 */
export function loadOpenRouterConnectionConfiguration(
  options: LoadOpenRouterConnectionConfigurationOptions = {},
): LoadedOpenRouterConnectionConfiguration {
  const environment = options.environment ?? process.env;
  const store = new OpenRouterConnectionStore({
    root: resolveProviderConfigurationRoot(environment),
    ...(options.serviceUid === undefined ? {} : { serviceUid: options.serviceUid }),
    ...(options.clock ? { clock: options.clock } : {}),
  });
  let stored;
  try {
    stored = store.read();
  } catch (error) {
    if (!(error instanceof OpenRouterConnectionError)) throw error;
    return {
      store,
      configuration: blockedFromStore(error),
      source: "canonical_provider_config",
      activeConfigurationVersion: null,
    };
  }
  if (stored) {
    return {
      store,
      configuration: resolveOpenRouterGuidedStandaloneConfiguration({
        TI_SCALE_OPENROUTER_GUIDED_ENABLED: String(stored.enabled),
        ...(stored.enabled
          ? {
              TI_SCALE_OPENROUTER_CREDENTIAL_PATH: store.credentialPath,
              TI_SCALE_OPENROUTER_MODEL: stored.model,
            }
          : {}),
      }),
      source: "canonical_provider_config",
      activeConfigurationVersion: stored.version,
    };
  }
  const configuration = resolveOpenRouterGuidedStandaloneConfiguration(environment);
  return {
    store,
    configuration,
    source: configuration.state === "disabled"
      && configuration.reasonCode === "not_configured"
      ? "none"
      : "legacy_environment",
    activeConfigurationVersion: null,
  };
}

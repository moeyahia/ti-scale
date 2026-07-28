import { isAbsolute } from "node:path";
import {
  OPENROUTER_DEFAULT_MODEL,
} from "./OpenRouterReadinessProbe";
import {
  resolveOpenRouterModelConfiguration,
  type ResolvedOpenRouterModelConfiguration,
} from "./OpenRouterModelConfiguration";

export type OpenRouterGuidedStandaloneConfiguration =
  | {
      readonly state: "disabled";
      readonly reasonCode: "not_configured" | "explicitly_disabled";
      readonly reason: string;
      readonly remediation?: string;
    }
  | {
      readonly state: "blocked";
      readonly reasonCode:
        | "raw_environment_credential_unsupported"
        | "credential_path_missing"
        | "credential_path_not_absolute"
        | "enabled_flag_invalid"
        | "provider_config_store_invalid";
      readonly reason: string;
      readonly remediation: string;
    }
  | {
      readonly state: "configured_unattested";
      readonly credentialPath: string;
      readonly modelConfiguration: ResolvedOpenRouterModelConfiguration;
      readonly reason: string;
      readonly remediation: string;
    };

function configuredFlag(value: string | undefined): true | false | "invalid" | undefined {
  if (value === undefined || !value.trim()) return undefined;
  if (value === "true") return true;
  if (value === "false") return false;
  return "invalid";
}

/**
 * Resolve only non-secret standalone configuration. Raw environment keys are
 * intentionally detected but never read or copied: production dispatch uses
 * the service-owned private-file credential boundary exclusively.
 */
export function resolveOpenRouterGuidedStandaloneConfiguration(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): OpenRouterGuidedStandaloneConfiguration {
  const enabled = configuredFlag(environment.TI_SCALE_OPENROUTER_GUIDED_ENABLED);
  if (enabled === "invalid") {
    return {
      state: "blocked",
      reasonCode: "enabled_flag_invalid",
      reason: "The OpenRouter Guided enable flag is invalid.",
      remediation: "Set TI_SCALE_OPENROUTER_GUIDED_ENABLED to true or false.",
    };
  }
  if (enabled === false) {
    return {
      state: "disabled",
      reasonCode: "explicitly_disabled",
      reason: "The OpenRouter Guided provider is explicitly disabled.",
    };
  }

  const credentialPath = environment.TI_SCALE_OPENROUTER_CREDENTIAL_PATH?.trim();
  if (!credentialPath) {
    if (environment.OPENROUTER_API_KEY !== undefined) {
      return {
        state: "blocked",
        reasonCode: "raw_environment_credential_unsupported",
        reason: "A raw OpenRouter environment credential is present, but Ti-Scale does not accept provider keys from environment variables.",
        remediation: "Place the provider key in a root- or service-owned mode-0600 file and set TI_SCALE_OPENROUTER_CREDENTIAL_PATH to its absolute path.",
      };
    }
    return enabled === true
      ? {
          state: "blocked",
          reasonCode: "credential_path_missing",
          reason: "OpenRouter Guided is enabled without a service-owned credential file path.",
          remediation: "Set TI_SCALE_OPENROUTER_CREDENTIAL_PATH to an absolute private credential file.",
        }
      : {
          state: "disabled",
          reasonCode: "not_configured",
          reason: "No service-owned OpenRouter credential file is configured.",
          remediation: "Configure a private credential file only when Guided public-provider explanations are required.",
        };
  }
  if (!isAbsolute(credentialPath)) {
    return {
      state: "blocked",
      reasonCode: "credential_path_not_absolute",
      reason: "The OpenRouter credential path is not absolute.",
      remediation: "Use an absolute root- or service-owned mode-0600 credential file path.",
    };
  }

  return {
    state: "configured_unattested",
    credentialPath,
    modelConfiguration: resolveOpenRouterModelConfiguration({
      model: environment.TI_SCALE_OPENROUTER_MODEL?.trim() || OPENROUTER_DEFAULT_MODEL,
    }),
    reason: "OpenRouter has non-secret configuration, but no fresh audited strict-schema completion attestation is mounted in this process.",
    remediation: "Create a fresh readiness provider turn and empty Context Pack, durably authorize the content-free probe, then mount the matching Guided port and runtime lease resolver.",
  };
}

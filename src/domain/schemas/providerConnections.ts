import type {
  OpenRouterAttestationRefresh,
  OpenRouterConnection,
  OpenRouterRuntimeStatus,
} from "../types/providerConnections";
import {
  boolean,
  nullableNumber,
  nullableString,
  nonEmpty,
  number,
  object,
  stringList,
} from "./common";

const SCHEMA_VERSION = "ti-scale.openrouter-connection.v1" as const;

function oneOf<T extends string>(
  value: unknown,
  values: readonly T[],
  label: string,
): T {
  const result = nonEmpty(value, label);
  if (!values.includes(result as T)) throw new Error(`${label} is invalid`);
  return result as T;
}

function nonNegativeInteger(value: unknown, label: string): number {
  const result = number(value, label);
  if (!Number.isSafeInteger(result) || result < 0) {
    throw new Error(`${label} must be a non-negative whole number`);
  }
  return result;
}

function parseRuntime(value: unknown): OpenRouterConnection["runtime"] {
  const runtime = object(value, "OpenRouter connection runtime");
  const autonomousEnforcement = boolean(
    runtime.enforcesAutonomousBoundary,
    "OpenRouter runtime Autonomous enforcement",
  );
  if (autonomousEnforcement) {
    throw new Error("OpenRouter must remain outside the Autonomous execution boundary");
  }
  return {
    status: oneOf(
      runtime.status,
      ["disabled", "blocked", "probing", "degraded", "ready", "stopped"] as const,
      "OpenRouter runtime status",
    ) as OpenRouterRuntimeStatus,
    configured: boolean(runtime.configured, "OpenRouter runtime configured"),
    authenticated: boolean(runtime.authenticated, "OpenRouter runtime authenticated"),
    callable: boolean(runtime.callable, "OpenRouter runtime callable"),
    supportsGuided: boolean(runtime.supportsGuided, "OpenRouter runtime supportsGuided"),
    enforcesAutonomousBoundary: false,
    reportsExactTokenUsage: boolean(
      runtime.reportsExactTokenUsage,
      "OpenRouter runtime reportsExactTokenUsage",
    ),
    reportsExactCostUsage: boolean(
      runtime.reportsExactCostUsage,
      "OpenRouter runtime reportsExactCostUsage",
    ),
    requestedModel: nullableString(runtime.requestedModel, "OpenRouter requested model"),
    returnedModel: nullableString(runtime.returnedModel, "OpenRouter returned model"),
    lastCheckedAt: nullableString(runtime.lastCheckedAt, "OpenRouter last checked time"),
    attestedAt: nullableString(runtime.attestedAt, "OpenRouter attested time"),
    expiresAt: nullableString(runtime.expiresAt, "OpenRouter attestation expiry"),
    failureCode: nullableString(runtime.failureCode, "OpenRouter failure code"),
    remediation: nullableString(runtime.remediation, "OpenRouter remediation"),
    reason: nonEmpty(runtime.reason, "OpenRouter runtime reason"),
  };
}

export function parseOpenRouterConnection(payload: unknown): OpenRouterConnection {
  const root = object(payload, "OpenRouter connection");
  if (root.schemaVersion !== SCHEMA_VERSION || root.providerId !== "openrouter") {
    throw new Error("Unsupported OpenRouter connection contract");
  }
  const configuration = object(root.configuration, "OpenRouter connection configuration");
  const activation = object(root.activation, "OpenRouter connection activation");
  const compatibility = object(
    root.planningCompatibility,
    "OpenRouter planning compatibility",
  );
  const activeVersion = nullableNumber(
    activation.activeConfigurationVersion,
    "OpenRouter active configuration version",
  );
  if (activeVersion !== null && (!Number.isSafeInteger(activeVersion) || activeVersion < 1)) {
    throw new Error("OpenRouter active configuration version is invalid");
  }
  if (configuration.browserStorage !== false) {
    throw new Error("OpenRouter connection must never use browser storage");
  }
  if (compatibility.localExecutionAuthorityUnchanged !== true) {
    throw new Error("OpenRouter must not inherit local execution authority");
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    providerId: "openrouter",
    configuration: {
      source: oneOf(
        configuration.source,
        ["canonical_provider_config", "legacy_environment", "none"] as const,
        "OpenRouter configuration source",
      ),
      version: nonNegativeInteger(configuration.version, "OpenRouter configuration version"),
      enabled: boolean(configuration.enabled, "OpenRouter configuration enabled"),
      model: nonEmpty(configuration.model, "OpenRouter exact model"),
      credentialConfigured: boolean(
        configuration.credentialConfigured,
        "OpenRouter credentialConfigured",
      ),
      updatedAt: nullableString(configuration.updatedAt, "OpenRouter updatedAt"),
      updatedBy: nullableString(configuration.updatedBy, "OpenRouter updatedBy"),
      storage: oneOf(
        configuration.storage,
        ["service_owned_mode_0600"] as const,
        "OpenRouter storage boundary",
      ),
      browserStorage: false,
    },
    activation: {
      activeConfigurationVersion: activeVersion,
      configuredVersion: nonNegativeInteger(
        activation.configuredVersion,
        "OpenRouter configured version",
      ),
      restartRequired: boolean(
        activation.restartRequired,
        "OpenRouter restartRequired",
      ),
      status: oneOf(
        activation.status,
        ["not_configured", "disabled", "restart_required", "active", "degraded"] as const,
        "OpenRouter activation status",
      ),
      humanMessage: nonEmpty(activation.humanMessage, "OpenRouter activation message"),
    },
    runtime: parseRuntime(root.runtime),
    planningCompatibility: {
      enforcementMode: oneOf(
        compatibility.enforcementMode,
        ["advisor_only"] as const,
        "OpenRouter enforcement mode",
      ),
      compatibleAgentIds: stringList(
        compatibility.compatibleAgentIds,
        "OpenRouter compatible agents",
      ),
      localExecutionAuthorityUnchanged: true,
      explanation: nonEmpty(
        compatibility.explanation,
        "OpenRouter compatibility explanation",
      ),
    },
  };
}

export function parseOpenRouterAttestationRefresh(
  payload: unknown,
): OpenRouterAttestationRefresh {
  const root = object(payload, "OpenRouter attestation refresh");
  if (root.schemaVersion !== SCHEMA_VERSION || root.providerId !== "openrouter") {
    throw new Error("Unsupported OpenRouter attestation contract");
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    providerId: "openrouter",
    replayed: boolean(root.replayed, "OpenRouter attestation replayed"),
    connection: parseOpenRouterConnection(root.connection),
  };
}

import type { OpenRouterReadinessRuntimeSnapshot } from "./OpenRouterReadinessRuntime";

export const OPENROUTER_CONNECTION_SCHEMA_VERSION =
  "ti-scale.openrouter-connection.v1" as const;

export type OpenRouterCredentialMutation =
  | {
      readonly action: "keep";
    }
  | {
      readonly action: "replace";
      readonly value: string;
    }
  | {
      readonly action: "remove";
    };

export interface PutOpenRouterConnectionInput {
  readonly enabled: boolean;
  readonly model: string;
  readonly credential: OpenRouterCredentialMutation;
  readonly expectedVersion: number;
}

export interface StoredOpenRouterConnectionConfiguration {
  readonly schemaVersion: typeof OPENROUTER_CONNECTION_SCHEMA_VERSION;
  readonly providerId: "openrouter";
  readonly enabled: boolean;
  readonly model: string;
  readonly credentialSha256: string | null;
  readonly version: number;
  readonly updatedBy: string;
  readonly updatedAt: string;
}

export interface OpenRouterConnectionMutationResult {
  readonly configuration: StoredOpenRouterConnectionConfiguration;
  readonly replayed: boolean;
}

export type OpenRouterConfigurationSource =
  | "canonical_provider_config"
  | "legacy_environment"
  | "none";

export interface OpenRouterConnectionStatus {
  readonly schemaVersion: typeof OPENROUTER_CONNECTION_SCHEMA_VERSION;
  readonly providerId: "openrouter";
  readonly configuration: {
    readonly source: OpenRouterConfigurationSource;
    readonly version: number;
    readonly enabled: boolean;
    readonly model: string;
    readonly credentialConfigured: boolean;
    readonly updatedAt: string | null;
    readonly updatedBy: string | null;
    readonly storage: "service_owned_mode_0600";
    readonly browserStorage: false;
  };
  readonly activation: {
    readonly activeConfigurationVersion: number | null;
    readonly configuredVersion: number;
    readonly restartRequired: boolean;
    readonly status:
      | "not_configured"
      | "disabled"
      | "restart_required"
      | "active"
      | "degraded";
    readonly humanMessage: string;
  };
  readonly runtime: OpenRouterReadinessRuntimeSnapshot;
  readonly planningCompatibility: {
    readonly enforcementMode: "advisor_only";
    readonly compatibleAgentIds: readonly string[];
    readonly localExecutionAuthorityUnchanged: true;
    readonly explanation: string;
  };
}

export interface OpenRouterAttestationRefreshResult {
  readonly schemaVersion: typeof OPENROUTER_CONNECTION_SCHEMA_VERSION;
  readonly providerId: "openrouter";
  readonly replayed: boolean;
  readonly connection: OpenRouterConnectionStatus;
}

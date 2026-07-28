export type OpenRouterRuntimeStatus =
  | "disabled"
  | "blocked"
  | "probing"
  | "degraded"
  | "ready"
  | "stopped";

export interface OpenRouterConnection {
  readonly schemaVersion: "ti-scale.openrouter-connection.v1";
  readonly providerId: "openrouter";
  readonly configuration: {
    readonly source:
      | "canonical_provider_config"
      | "legacy_environment"
      | "none";
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
  readonly runtime: {
    readonly status: OpenRouterRuntimeStatus;
    readonly configured: boolean;
    readonly authenticated: boolean;
    readonly callable: boolean;
    readonly supportsGuided: boolean;
    readonly enforcesAutonomousBoundary: false;
    readonly reportsExactTokenUsage: boolean;
    readonly reportsExactCostUsage: boolean;
    readonly requestedModel: string | null;
    readonly returnedModel: string | null;
    readonly lastCheckedAt: string | null;
    readonly attestedAt: string | null;
    readonly expiresAt: string | null;
    readonly failureCode: string | null;
    readonly remediation: string | null;
    readonly reason: string;
  };
  readonly planningCompatibility: {
    readonly enforcementMode: "advisor_only";
    readonly compatibleAgentIds: readonly string[];
    readonly localExecutionAuthorityUnchanged: true;
    readonly explanation: string;
  };
}

export type UpdateOpenRouterConnectionInput =
  | {
      readonly enabled: true;
      readonly model: string;
      readonly credential:
        | { readonly action: "keep" }
        | { readonly action: "replace"; readonly value: string };
      readonly expectedVersion: number;
    }
  | {
      readonly enabled: false;
      readonly model: string;
      readonly credential: { readonly action: "remove" };
      readonly expectedVersion: number;
    };

export interface OpenRouterAttestationRefresh {
  readonly schemaVersion: "ti-scale.openrouter-connection.v1";
  readonly providerId: "openrouter";
  readonly replayed: boolean;
  readonly connection: OpenRouterConnection;
}

export type CapabilitySelfTestComponentKind =
  | "registry"
  | "database"
  | "event_stream"
  | "second_brain"
  | "obsidian_vault"
  | "provider"
  | "mcp_server"
  | "tool"
  | "tool_dependency";

export type CapabilitySelfTestKind =
  | "manifest_integrity"
  | "local_integrity"
  | "service_state"
  | "canonical_read"
  | "vault_round_trip_receipt"
  | "runtime_attestation"
  | "local_executable_attestation"
  | "manifest_dependency";

export type CapabilitySelfTestStatus = "pass" | "degraded" | "fail";
export type CapabilityAvailability = "available" | "degraded" | "unavailable" | "unsupported";
export type CapabilityFreshnessState = "fresh" | "stale" | "unknown";

export interface CapabilitySelfTestResult {
  readonly id: string;
  readonly component: {
    readonly kind: CapabilitySelfTestComponentKind;
    readonly id: string;
    readonly label: string;
  };
  readonly testKind: CapabilitySelfTestKind;
  readonly status: CapabilitySelfTestStatus;
  readonly availability: CapabilityAvailability;
  readonly checkedAt: string;
  readonly freshness: {
    readonly state: CapabilityFreshnessState;
    readonly observedAt: string | null;
    readonly expiresAt: string | null;
    readonly maximumAgeMs: number | null;
  };
  readonly explanation: string;
  readonly remediation: string | null;
  readonly executionAuthorization: {
    readonly state: "not_granted";
    readonly grantsMissionExecution: false;
    readonly explanation: string;
  };
}

export interface CapabilitySelfTestSnapshot {
  readonly schemaVersion: "2.4";
  readonly checkedAt: string;
  readonly readOnly: true;
  readonly grantsMissionExecution: false;
  readonly accounting: {
    readonly runtimeRegistryRead: boolean;
    readonly manifestValid: boolean;
    readonly complete: boolean;
    readonly registered: {
      readonly providers: number;
      readonly mcpServers: number;
      readonly tools: number;
      readonly toolDependencies: number;
    };
    readonly reported: {
      readonly providers: number;
      readonly mcpServers: number;
      readonly tools: number;
      readonly toolDependencies: number;
    };
  };
  readonly summary: {
    readonly total: number;
    readonly pass: number;
    readonly degraded: number;
    readonly fail: number;
    readonly available: number;
    readonly degradedAvailability: number;
    readonly unavailable: number;
    readonly unsupported: number;
  };
  readonly results: readonly CapabilitySelfTestResult[];
}

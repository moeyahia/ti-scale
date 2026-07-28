export const CAPABILITY_SELF_TEST_COMPONENT_KINDS = [
  "registry",
  "database",
  "event_stream",
  "second_brain",
  "obsidian_vault",
  "provider",
  "mcp_server",
  "tool",
  "tool_dependency",
] as const;

export type CapabilitySelfTestComponentKind =
  (typeof CAPABILITY_SELF_TEST_COMPONENT_KINDS)[number];

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

export type CapabilityAvailability =
  | "available"
  | "degraded"
  | "unavailable"
  | "unsupported";

export type CapabilityFreshnessState = "fresh" | "stale" | "unknown";

export interface CapabilitySelfTestFreshness {
  readonly state: CapabilityFreshnessState;
  /** Time recorded by the dependency, or by this request only for a check performed locally now. */
  readonly observedAt: string | null;
  readonly expiresAt: string | null;
  readonly maximumAgeMs: number | null;
}

export interface CapabilityExecutionAuthorization {
  readonly state: "not_granted";
  readonly grantsMissionExecution: false;
  readonly explanation: string;
}

export interface CapabilitySelfTestResult {
  readonly id: string;
  readonly component: {
    readonly kind: CapabilitySelfTestComponentKind;
    /** Registry identifier or a non-reversible placeholder when the source id is unsafe. */
    readonly id: string;
    readonly label: string;
  };
  readonly testKind: CapabilitySelfTestKind;
  readonly status: CapabilitySelfTestStatus;
  readonly availability: CapabilityAvailability;
  readonly checkedAt: string;
  readonly freshness: CapabilitySelfTestFreshness;
  readonly explanation: string;
  readonly remediation: string | null;
  readonly executionAuthorization: CapabilityExecutionAuthorization;
}

export interface CapabilitySelfTestAccounting {
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
}

export interface CapabilitySelfTestSnapshot {
  readonly schemaVersion: "2.4";
  readonly checkedAt: string;
  readonly readOnly: true;
  readonly grantsMissionExecution: false;
  readonly accounting: CapabilitySelfTestAccounting;
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

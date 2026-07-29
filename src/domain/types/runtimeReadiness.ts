export type ExecutionReadiness = "ready" | "unavailable";
export type GuidedExecutionReadiness = ExecutionReadiness | "manual_only";
export type RuntimeComponentHealth = "healthy" | "degraded" | "unhealthy" | "unknown";

/**
 * Process-level capability attestation. This is deliberately separate from
 * historical provider/MCP health records: controls may mutate runtime state
 * only when the current process says the matching execution boundary exists.
 */
export interface RuntimeReadinessSnapshot {
  readonly schemaVersion: "2.4";
  readonly status: "healthy" | "degraded";
  readonly execution: {
    readonly autonomous: ExecutionReadiness;
    readonly guided: GuidedExecutionReadiness;
    /** Exact-step Guided tool dispatch; manual Guided work may still be available when this is not. */
    readonly guidedToolExecution: ExecutionReadiness;
    /**
     * Provider-independent, explanation-only Commander boundary. `ready`
     * attests the local deterministic route; it grants no provider, tool,
     * target-contact, plan-mutation, or decision authority.
     */
    readonly localCommanderGuidance: ExecutionReadiness;
    readonly actionBoundaryActive: boolean;
    readonly delegationEnforced: boolean;
    readonly noHandsCommanderEnforced: boolean;
  };
  readonly dependencies: {
    readonly providers: {
      readonly status: "available" | "unavailable";
      readonly initializing: boolean;
      readonly probing: number;
      readonly reason: string | null;
      readonly declared: number;
      readonly callable: number;
      readonly enforcing: number;
      readonly guidedCapable: number;
    };
    readonly mcp: {
      readonly status: "available" | "unavailable";
      readonly initializing: boolean;
      readonly probingServers: number;
      readonly reason: string | null;
      readonly configuredServers: number;
      readonly runnableServers: number;
      readonly executionMode: "disabled" | "dry-run" | "enabled";
    };
    /** Canonical SQLite/policy memory path; Obsidian projection health is separate. */
    readonly secondBrain: {
      readonly status: RuntimeComponentHealth;
      readonly canonicalStoreAvailable: boolean;
      readonly reason: string | null;
    };
  };
  readonly checkedAt: string;
}

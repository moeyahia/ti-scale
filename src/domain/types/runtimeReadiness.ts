export type ExecutionReadiness = "ready" | "unavailable";

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
    readonly guided: ExecutionReadiness;
    /** Exact-step Guided tool dispatch; manual Guided work may still be available when this is not. */
    readonly guidedToolExecution: ExecutionReadiness;
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
  };
  readonly checkedAt: string;
}

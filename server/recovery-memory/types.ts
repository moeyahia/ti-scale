import type { FailureCategory } from "../supervisor";

export const AUTONOMOUS_RECOVERY_MEMORY_SCHEMA_VERSION = "1" as const;
export const AUTONOMOUS_RECOVERY_MEMORY_COMPILER_VERSION = "1" as const;

export type AutonomousRecoveryMemoryHook = "failure" | "replan";

export type RecoveryMemoryIgnoredReason =
  | "context_boundary_mismatch"
  | "node_type_not_allowed"
  | "node_not_confirmed_or_verified"
  | "lesson_not_verified"
  | "autonomous_use_not_permitted"
  | "scope_mismatch"
  | "typed_policy_missing_or_invalid"
  | "failure_category_mismatch"
  | "action_type_mismatch"
  | "action_class_mismatch";

export interface CompiledRecoveryMemoryCandidate {
  readonly nodeId: string;
  readonly denyRetry: boolean;
  readonly minimumBackoffMs?: number;
  readonly alternativeStepId?: string;
}

/**
 * A deterministic, local-only recovery overlay. It contains constraints and
 * references only: never a target, tool, command, action class, or action
 * payload. An alternative step must be resolved from the already-active plan
 * and re-authorized against the unchanged signed contract by the coordinator.
 */
export interface CompiledAutonomousRecoveryMemory {
  readonly schemaVersion: typeof AUTONOMOUS_RECOVERY_MEMORY_SCHEMA_VERSION;
  readonly compilerVersion: typeof AUTONOMOUS_RECOVERY_MEMORY_COMPILER_VERSION;
  readonly hook: AutonomousRecoveryMemoryHook;
  readonly contextPackId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly stepId?: string;
  readonly actionId?: string;
  readonly failureCategory: FailureCategory;
  readonly candidates: readonly CompiledRecoveryMemoryCandidate[];
  readonly ignored: Readonly<Record<string, RecoveryMemoryIgnoredReason>>;
}

export type RecoveryMemoryAppliedEffect =
  | "retry_denied"
  | "bounded_backoff_raised"
  | "bounded_alternative_selected";

export interface RecoveryMemoryDecisionSnapshot {
  readonly retryEligible: boolean;
  readonly retryDelayMs: number | null;
  readonly recoveryKind: string;
  readonly alternativeStepId: string | null;
}

export interface RecoveryMemoryDecisionReceipt {
  readonly id: string;
  readonly schemaVersion: typeof AUTONOMOUS_RECOVERY_MEMORY_SCHEMA_VERSION;
  readonly compilerVersion: typeof AUTONOMOUS_RECOVERY_MEMORY_COMPILER_VERSION;
  readonly hook: AutonomousRecoveryMemoryHook;
  readonly missionId: string;
  readonly runId: string;
  readonly actionId: string;
  readonly stepId: string;
  readonly contextPackId: string;
  readonly failureCategory: FailureCategory;
  readonly baseline: RecoveryMemoryDecisionSnapshot;
  readonly resolved: RecoveryMemoryDecisionSnapshot;
  readonly effects: readonly RecoveryMemoryAppliedEffect[];
  readonly candidateNodeIds: readonly string[];
  readonly appliedNodeIds: readonly string[];
  readonly ignoredNodeIds: readonly string[];
  readonly ignoredReasons: Readonly<Record<string, string>>;
  readonly receiptHash: string;
  readonly createdAt: string;
}

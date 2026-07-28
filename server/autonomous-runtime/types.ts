import type { ActionClassId, EvidenceTypeId } from "../domain";

export const LOCAL_AUTONOMOUS_PLANNING_POLICY_SCHEMA_VERSION =
  "ti-scale.local-autonomous-planning-policy.v1" as const;
export const LOCAL_AUTONOMOUS_PLANNER_BOUNDARY_SCHEMA_VERSION =
  "ti-scale.local-autonomous-planner-boundary.v1" as const;

export const LOCAL_AUTONOMOUS_TARGET_KINDS = [
  "url",
  "domain",
  "ip",
  "cidr",
  "cloud",
  "environment",
] as const;

export type LocalAutonomousTargetKind = (typeof LOCAL_AUTONOMOUS_TARGET_KINDS)[number];

/**
 * One reviewed, declarative route from a signed action class to an exact
 * specialist MCP binding. The planner never synthesizes a command or guesses
 * a tool schema. Only the named target property is populated dynamically.
 */
interface LocalAutonomousActionBindingBase {
  readonly bindingId: string;
  readonly actionClassId: ActionClassId;
  readonly targetKinds: readonly LocalAutonomousTargetKind[];
  readonly phase: string;
  readonly title: string;
  readonly objective: string;
  readonly explanation: string;
  readonly rationale: string;
  readonly successCriteria: readonly string[];
  readonly reversibility: string;
  readonly riskClass: "low" | "medium" | "high" | "critical";
  readonly idempotent: boolean;
  readonly destructive: boolean;
  readonly agentId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  readonly targetParameter: string;
  readonly staticParameters: Readonly<Record<string, unknown>>;
  readonly capabilityIds: readonly string[];
  readonly requiredEvidenceTypeIds: readonly EvidenceTypeId[];
}

/** Existing exact MCP execution route. */
export interface LocalAutonomousMcpActionBinding extends LocalAutonomousActionBindingBase {
  readonly mcpServerId: string;
  readonly toolName: string;
}

/** Truthful direct-argv route; it carries no MCP server identity. */
export interface LocalAutonomousProcessActionBinding extends LocalAutonomousActionBindingBase {
  readonly executionBinding: "reviewed_local_process";
  readonly toolId: string;
}

export type LocalAutonomousActionBinding =
  | LocalAutonomousMcpActionBinding
  | LocalAutonomousProcessActionBinding;

export interface LocalAutonomousPlanningPolicy {
  readonly schemaVersion: typeof LOCAL_AUTONOMOUS_PLANNING_POLICY_SCHEMA_VERSION;
  readonly policyId: string;
  readonly maximumSteps: number;
  readonly bindings: readonly LocalAutonomousActionBinding[];
}

interface LocalAutonomousPlannerBindingReceiptBase {
  readonly bindingId: string;
  readonly actionClassId: ActionClassId;
  readonly agentId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
}

export interface LocalAutonomousMcpPlannerBindingReceipt extends LocalAutonomousPlannerBindingReceiptBase {
  readonly mcpServerId: string;
  readonly toolName: string;
}

export interface LocalAutonomousProcessPlannerBindingReceipt extends LocalAutonomousPlannerBindingReceiptBase {
  readonly executionBinding: "reviewed_local_process";
  readonly toolId: string;
}

export type LocalAutonomousPlannerBindingReceipt =
  | LocalAutonomousMcpPlannerBindingReceipt
  | LocalAutonomousProcessPlannerBindingReceipt;

/** Exact object inspected by the production composition readiness gate. */
export interface LocalAutonomousPlannerBoundary {
  readonly schemaVersion: typeof LOCAL_AUTONOMOUS_PLANNER_BOUNDARY_SCHEMA_VERSION;
  readonly kind: "local_deterministic";
  readonly providerContact: false;
  readonly canonicalContractRequired: true;
  readonly runtimeManifestRequired: true;
  readonly heuristicToolArguments: false;
  readonly policyId: string;
  readonly policyHash: string;
  readonly bindings: readonly LocalAutonomousPlannerBindingReceipt[];
}

export type AutonomousCriterionOutcome =
  | "achieved"
  | "not_achieved"
  | "not_applicable";

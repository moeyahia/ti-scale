import type { AutonomousPlanningSelection } from "../model-config";

export const AUTONOMOUS_ACTIVATION_RECEIPT_SCHEMA_VERSION = "2.4" as const;

export const AUTONOMOUS_ACTIVATION_BINDING_TYPES = [
  "launch",
  "planning",
  "plan_version",
  "dispatch",
  "resume",
  "restart_recovery",
] as const;

export type AutonomousActivationBindingType =
  (typeof AUTONOMOUS_ACTIVATION_BINDING_TYPES)[number];

export type AutonomousToolBindingKind = "local" | "mcp";

type LocalAutonomousPlanningSelection = Extract<
  AutonomousPlanningSelection,
  { readonly route: "local_deterministic" }
>;

type ProviderAutonomousPlanningSelection = Extract<
  AutonomousPlanningSelection,
  { readonly route: "provider_advisory" }
>;

/**
 * Planning is one run-level authority selection, independent of specialist
 * execution routes. Local deterministic planning has no provider assignment;
 * provider advisory planning binds one exact purpose=planning run pin.
 */
export type AutonomousActivationPlanningInput =
  | {
      readonly selection: LocalAutonomousPlanningSelection;
      readonly modelAssignmentId?: never;
    }
  | {
      readonly selection: ProviderAutonomousPlanningSelection;
      readonly modelAssignmentId: string;
    };

export type AutonomousActivationPlanningSnapshot =
  | {
      readonly route: "local_deterministic";
      readonly selection: LocalAutonomousPlanningSelection;
      readonly selectionHash: string;
      readonly plannerId: LocalAutonomousPlanningSelection["plannerId"];
      readonly modelAssignmentId: null;
      readonly primaryConfigurationId: null;
      readonly fallbackConfigurationId: null;
      readonly primaryConfigurationHash: null;
      readonly fallbackConfigurationHash: null;
    }
  | {
      readonly route: "provider_advisory";
      readonly selection: ProviderAutonomousPlanningSelection;
      readonly selectionHash: string;
      readonly plannerId: string;
      readonly modelAssignmentId: string;
      readonly primaryConfigurationId: string;
      readonly fallbackConfigurationId: string | null;
      readonly primaryConfigurationHash: string;
      readonly fallbackConfigurationHash: string | null;
    };

export interface AutonomousActivationRouteInput {
  readonly actionClassId: string;
  readonly agentId: string;
  readonly executionModelAssignmentId: string;
  readonly toolId: string;
  readonly toolBindingKind: AutonomousToolBindingKind;
  readonly mcpServerId: string | null;
  readonly toolActivationReceiptId: string;
  readonly toolActivationReceiptHash: string;
  readonly toolManifestHash: string;
  readonly evidenceTypeIds: readonly string[];
  readonly evidenceProducerIds: readonly string[];
  /**
   * The route may remain healthy longer than the aggregate receipt, but never
   * for less time. The aggregate issuer uses the earliest dependency expiry.
   */
  readonly routeExpiresAt: string;
}

export interface IssueAutonomousActivationReceiptInput {
  readonly id?: string;
  readonly missionId: string;
  readonly runId: string;
  readonly contractId: string;
  readonly contractVersion: number;
  readonly contractHash: string;
  readonly generation: number;
  readonly runtimeGenerationHash: string;
  readonly evidencePolicyHash: string;
  readonly brainContextPackId: string;
  readonly planning: AutonomousActivationPlanningInput;
  readonly routes: readonly AutonomousActivationRouteInput[];
  readonly issuedBy: string;
  readonly issuedAt?: string;
  readonly expiresAt: string;
}

export interface AutonomousActivationModelAssignmentSnapshot {
  readonly id: string;
  readonly purpose: "execution" | "planning";
  readonly agentId: string;
  readonly primaryConfigurationId: string;
  readonly fallbackConfigurationId: string | null;
  readonly primaryConfigurationHash: string;
  readonly fallbackConfigurationHash: string | null;
}

export interface AutonomousActivationReceiptItem {
  readonly actionClassId: string;
  readonly agentId: string;
  readonly executionModelAssignmentId: string;
  readonly executionPrimaryConfigurationId: string;
  readonly executionFallbackConfigurationId: string | null;
  readonly toolId: string;
  readonly toolBindingKind: AutonomousToolBindingKind;
  readonly mcpServerId: string | null;
  readonly toolActivationReceiptId: string;
  readonly toolActivationReceiptHash: string;
  readonly toolManifestHash: string;
  readonly evidenceTypeIds: readonly string[];
  readonly evidenceProducerIds: readonly string[];
  readonly routeExpiresAt: string;
  readonly routeHash: string;
  readonly createdAt: string;
}

export interface AutonomousActivationBinding {
  readonly id: string;
  readonly receiptId: string;
  readonly sequence: number;
  readonly bindingType: AutonomousActivationBindingType;
  readonly subjectId: string;
  readonly subjectDigest: string;
  readonly runtimeGenerationHash: string;
  readonly planId: string | null;
  readonly stepId: string | null;
  readonly actionId: string | null;
  readonly contextPackId: string | null;
  readonly providerTurnId: string | null;
  readonly previousBindingHash: string | null;
  readonly boundBy: string;
  readonly boundAt: string;
  readonly bindingHash: string;
}

export interface AutonomousActivationReceipt {
  readonly id: string;
  readonly schemaVersion: typeof AUTONOMOUS_ACTIVATION_RECEIPT_SCHEMA_VERSION;
  readonly missionId: string;
  readonly runId: string;
  readonly contractId: string;
  readonly generation: number;
  readonly contractVersion: number;
  readonly contractHash: string;
  readonly runtimeGenerationHash: string;
  readonly modelAssignmentSetHash: string;
  readonly evidencePolicyHash: string;
  readonly brainContextPackId: string;
  readonly brainContextPackHash: string;
  readonly planning: AutonomousActivationPlanningSnapshot;
  readonly selectedActionClassIds: readonly string[];
  readonly selectedActionClassCount: number;
  readonly activatedActionClassCount: number;
  readonly routeSetHash: string;
  readonly issuedBy: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly receiptHash: string;
  readonly items: readonly AutonomousActivationReceiptItem[];
  readonly bindings: readonly AutonomousActivationBinding[];
}

export interface AppendAutonomousActivationBindingInput {
  readonly id?: string;
  readonly receiptId: string;
  readonly bindingType: AutonomousActivationBindingType;
  readonly subjectId: string;
  readonly subjectDigest: string;
  readonly planId?: string | null;
  readonly stepId?: string | null;
  readonly actionId?: string | null;
  readonly contextPackId?: string | null;
  readonly providerTurnId?: string | null;
  readonly boundBy: string;
  readonly boundAt?: string;
}

export interface AutonomousActivationReceiptExpectations {
  readonly missionId?: string;
  readonly runId?: string;
  readonly contractId?: string;
  readonly contractVersion?: number;
  readonly contractHash?: string;
  readonly runtimeGenerationHash?: string;
  readonly evidencePolicyHash?: string;
  readonly brainContextPackId?: string;
  readonly planningSelectionHash?: string;
  readonly selectedActionClassIds?: readonly string[];
  readonly receiptHash?: string;
  readonly allowExpired?: boolean;
}

export interface AutonomousActivationReceiptVerification {
  readonly valid: true;
  readonly receipt: AutonomousActivationReceipt;
  readonly verifiedAt: string;
}

export type AutonomousActivationReceiptIntegrityCode =
  | "activation_receipt_not_found"
  | "activation_receipt_invalid_input"
  | "activation_receipt_lineage_mismatch"
  | "activation_receipt_contract_mismatch"
  | "activation_receipt_class_coverage_mismatch"
  | "activation_receipt_model_assignment_mismatch"
  | "activation_receipt_brain_context_mismatch"
  | "activation_receipt_runtime_generation_drift"
  | "activation_receipt_expired"
  | "activation_receipt_tampered"
  | "activation_binding_chain_invalid";

export class AutonomousActivationReceiptIntegrityError extends Error {
  constructor(
    readonly code: AutonomousActivationReceiptIntegrityCode,
    message: string,
  ) {
    super(message);
    this.name = "AutonomousActivationReceiptIntegrityError";
  }
}

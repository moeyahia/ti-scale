import type {
  MissionPlanDraft,
  PlannedStep,
} from "../command-runtime/types";
import type { ActionClassId, EvidenceTypeId } from "../domain";
import type {
  ProviderExposureReceipt,
  ResearchSourceItem,
  UntrustedContentEnvelope,
} from "../research/LlmExposurePolicy";
import type { ProviderExposureReferences } from "../providers/openrouter/types";

export const PROVIDER_ADVISORY_CATALOG_SCHEMA_VERSION =
  "ti-scale.autonomous-provider-advisory-catalog.v1" as const;
export const PROVIDER_ADVISORY_BRIEF_SCHEMA_VERSION =
  "ti-scale.autonomous-provider-advisory-brief.v1" as const;
export const PROVIDER_ADVISORY_SELECTION_SCHEMA_VERSION =
  "ti-scale.autonomous-provider-advisory-selection.v1" as const;
export const PROVIDER_ADVISORY_COMPILATION_SCHEMA_VERSION =
  "ti-scale.autonomous-provider-advisory-compilation.v1" as const;

export type ProviderAdvisoryRiskClass =
  | "low"
  | "medium"
  | "high"
  | "critical";

export interface ProviderAdvisoryCandidateInput {
  /**
   * This text is the only candidate-specific prose eligible for disclosure.
   * Exact target, tool, arguments, specialist and evidence IDs remain local.
   */
  readonly publicSummary: {
    readonly phase: string;
    readonly purpose: string;
  };
  readonly step: PlannedStep;
  readonly requiredEvidenceTypeIds: readonly EvidenceTypeId[];
}

export interface BuildProviderAdvisoryCatalogInput {
  readonly planningRequestId: string;
  readonly contractHash: string;
  readonly policyHash: string;
  readonly contextPackId: string;
  readonly allowedTargets: readonly string[];
  readonly allowedActionClassIds: readonly ActionClassId[];
  readonly prohibitedActionClassIds: readonly ActionClassId[];
  readonly allowedAgentIds: readonly string[];
  readonly maximumSteps: number;
  readonly candidates: readonly ProviderAdvisoryCandidateInput[];
}

export interface ProviderAdvisoryLocalCandidate {
  readonly candidateId: string;
  readonly candidateHash: string;
  readonly publicSummary: {
    readonly phase: string;
    readonly purpose: string;
    readonly riskClass: ProviderAdvisoryRiskClass;
    readonly prerequisiteCandidateIds: readonly string[];
    readonly requiredEvidenceCount: number;
  };
  /** Exact local materialization. This object is never placed in a provider brief. */
  readonly step: Omit<PlannedStep, "dependencyOrdinals">;
  readonly dependencyCandidateIds: readonly string[];
  readonly requiredEvidenceTypeIds: readonly EvidenceTypeId[];
}

export interface ProviderAdvisoryCandidateCatalog {
  readonly schemaVersion: typeof PROVIDER_ADVISORY_CATALOG_SCHEMA_VERSION;
  readonly planningRequestId: string;
  readonly contractHash: string;
  readonly policyHash: string;
  readonly contextPackId: string;
  readonly actionRegistryHash: string;
  readonly allowedTargets: readonly string[];
  readonly allowedActionClassIds: readonly ActionClassId[];
  readonly prohibitedActionClassIds: readonly ActionClassId[];
  readonly allowedAgentIds: readonly string[];
  readonly maximumSteps: number;
  readonly candidates: readonly ProviderAdvisoryLocalCandidate[];
  readonly catalogHash: string;
}

export interface ProviderAdvisoryPublicCandidateSummary {
  readonly candidateId: string;
  readonly phase: string;
  readonly purpose: string;
  readonly riskClass: ProviderAdvisoryRiskClass;
  readonly prerequisiteCandidateIds: readonly string[];
  readonly requiredEvidenceCount: number;
}

export interface ProviderAdvisoryBrief {
  readonly schemaVersion: typeof PROVIDER_ADVISORY_BRIEF_SCHEMA_VERSION;
  readonly planningRequestId: string;
  readonly catalogHash: string;
  readonly exposurePayloadHash: string;
  readonly systemContract: {
    readonly advisoryOnly: true;
    readonly executionAuthority: "none";
    readonly mayExecuteTools: false;
    readonly mayEmitTargets: false;
    readonly mayEmitToolArguments: false;
    readonly mayChangePolicy: false;
    readonly mustReturnEveryCandidateExactlyOnce: true;
    readonly allowedOutput: "candidate_id_order_and_concise_rationale";
  };
  readonly candidates: readonly ProviderAdvisoryPublicCandidateSummary[];
  readonly observations: readonly UntrustedContentEnvelope[];
}

export interface PrepareProviderAdvisoryBriefInput {
  readonly catalog: ProviderAdvisoryCandidateCatalog;
  readonly providerId: string;
  readonly modelId: string;
  readonly createdAt: string;
  readonly contextItems?: readonly ResearchSourceItem[];
}

export interface PreparedProviderAdvisoryBrief {
  readonly brief: ProviderAdvisoryBrief;
  readonly briefHash: string;
  readonly exposureReceipt: ProviderExposureReceipt;
}

export interface ProviderAdvisorySelection {
  readonly schemaVersion: typeof PROVIDER_ADVISORY_SELECTION_SCHEMA_VERSION;
  readonly catalogHash: string;
  readonly advisoryOnly: true;
  readonly executionRequested: false;
  readonly orderedCandidateIds: readonly string[];
  readonly rationale: string;
}

export interface ProviderAdvisoryProviderResult {
  readonly value: unknown;
  readonly providerId: string;
  readonly requestedModel: string;
  readonly returnedModel: string;
  readonly usage: {
    readonly inputTokens?: number;
    readonly outputTokens?: number;
    readonly providerTokens?: number;
    readonly billedCostUsd?: number;
    readonly exactTokenUsage: boolean;
    readonly exactCostUsage: boolean;
  };
}

export interface ProviderAdvisoryProviderPort {
  readonly mode: "advisor_only";
  readonly executionAuthority: "none";
  readonly providerId: string;
  advise(input: {
    readonly modelId: string;
    readonly brief: ProviderAdvisoryBrief;
    readonly exposure: ProviderExposureReferences;
    readonly signal: AbortSignal;
  }): Promise<ProviderAdvisoryProviderResult>;
}

export interface CompileProviderAdvisorySelectionInput {
  readonly catalog: ProviderAdvisoryCandidateCatalog;
  readonly selection: ProviderAdvisorySelection;
  readonly expectedContractHash: string;
  readonly expectedPolicyHash: string;
  readonly expectedContextPackId: string;
  readonly source: "provider_advisory" | "local_deterministic_fallback";
  readonly providerResult?: ProviderAdvisoryProviderResult;
  readonly briefHash?: string;
  readonly exposureReceiptId?: string;
  readonly fallbackReasonCode?: string;
}

export interface ProviderAdvisoryCompilationReceipt {
  readonly schemaVersion: typeof PROVIDER_ADVISORY_COMPILATION_SCHEMA_VERSION;
  readonly planningRequestId: string;
  readonly catalogHash: string;
  readonly contractHash: string;
  readonly policyHash: string;
  readonly contextPackId: string;
  readonly source: "provider_advisory" | "local_deterministic_fallback";
  readonly executionAuthority: "none";
  readonly orderedCandidateIds: readonly string[];
  readonly candidateHashes: readonly string[];
  readonly evidenceRequirements: readonly {
    readonly candidateId: string;
    readonly evidenceTypeIds: readonly EvidenceTypeId[];
  }[];
  readonly briefHash?: string;
  readonly exposureReceiptId?: string;
  readonly fallbackReasonCode?: string;
  readonly planHash: string;
  readonly receiptHash: string;
}

export interface CompiledProviderAdvisoryPlan {
  readonly plan: MissionPlanDraft;
  readonly receipt: ProviderAdvisoryCompilationReceipt;
}

export interface ProviderAdvisoryPlanningInput {
  readonly catalog: ProviderAdvisoryCandidateCatalog;
  readonly expectedContractHash: string;
  readonly expectedPolicyHash: string;
  readonly expectedContextPackId: string;
  readonly provider?: ProviderAdvisoryProviderPort;
  readonly modelId?: string;
  readonly exposure?: ProviderExposureReferences;
  readonly createdAt: string;
  readonly contextItems?: readonly ResearchSourceItem[];
}

export interface ProviderAdvisoryPlanningOutcome
  extends CompiledProviderAdvisoryPlan {
  readonly preparedBrief?: PreparedProviderAdvisoryBrief;
}

export type ProviderAdvisoryErrorCategory =
  | "invalid_catalog"
  | "invalid_provider_response"
  | "disclosure_denied"
  | "policy_drift"
  | "provider_unavailable"
  | "cancelled";

/** Redacted error surface: raw provider/context payloads are never retained. */
export class ProviderAdvisoryPlanningError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly category: ProviderAdvisoryErrorCategory,
    readonly retryable: boolean,
  ) {
    super(message);
    this.name = "ProviderAdvisoryPlanningError";
  }

  toJSON(): Readonly<Record<string, unknown>> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      category: this.category,
      retryable: this.retryable,
    };
  }
}

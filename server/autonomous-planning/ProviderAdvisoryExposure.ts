import { canonicalJson, hashCanonical } from "../missions/canonical";
import {
  LlmExposurePolicy,
  validateProviderExposureReceipt,
  type ResearchSourceItem,
} from "../research/LlmExposurePolicy";
import {
  PROVIDER_ADVISORY_BRIEF_SCHEMA_VERSION,
  ProviderAdvisoryPlanningError,
  type PrepareProviderAdvisoryBriefInput,
  type PreparedProviderAdvisoryBrief,
  type ProviderAdvisoryBrief,
  type ProviderAdvisoryCandidateCatalog,
} from "./ProviderAdvisoryPlanningTypes";
import { reconstructProviderAdvisoryCandidateCatalog } from "./ProviderAdvisoryCandidateCatalog";

const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$/u;
export const PROVIDER_ADVISORY_EXPOSURE_POLICY_VERSION =
  "autonomous-planning-exposure-v1" as const;
export const PROVIDER_ADVISORY_DIMENSION_ID =
  "autonomous_plan_candidate_ordering" as const;
const MAXIMUM_CONTEXT_ITEMS = 8;

function disclosureError(code: string, message: string): never {
  throw new ProviderAdvisoryPlanningError(
    code,
    message,
    "disclosure_denied",
    false,
  );
}

function opaqueId(value: unknown, label: string): string {
  if (typeof value !== "string" || !OPAQUE_ID.test(value.trim())) {
    disclosureError(
      "provider_advisory_exposure_binding_invalid",
      `${label} is not an opaque canonical identifier.`,
    );
  }
  return value.trim();
}

function candidateSourceItems(
  catalog: ProviderAdvisoryCandidateCatalog,
): readonly ResearchSourceItem[] {
  return catalog.candidates.map((candidate): ResearchSourceItem => ({
    id: candidate.candidateId,
    kind: "strategy_summary",
    classification: "public",
    disclosureClass: "public",
    content: canonicalJson({
      candidateId: candidate.candidateId,
      ...candidate.publicSummary,
    }),
    verified: true,
  }));
}

function localBindingTokens(
  catalog: ProviderAdvisoryCandidateCatalog,
): readonly string[] {
  const result = new Set<string>(catalog.allowedTargets);
  for (const { step } of catalog.candidates) {
    result.add(step.action.target);
    result.add(step.action.actionType);
    result.add(step.assignedAgentId);
    const modelBinding = step.runtimeModelBinding;
    if (modelBinding) {
      result.add(modelBinding.agentId);
      result.add(modelBinding.modelAssignmentId);
      result.add(modelBinding.modelConfigurationId);
      result.add(modelBinding.providerId);
      result.add(modelBinding.modelId);
    }
    const argumentsRecord = step.action.arguments;
    for (const key of [
      "toolId",
      "toolName",
      "mcpServer",
      "mcpServerId",
      "agentId",
      "providerId",
      "modelId",
    ]) {
      const value = argumentsRecord[key];
      if (typeof value === "string" && value.length >= 3) result.add(value);
    }
  }
  return [...result].filter((value) => value.length >= 3);
}

function assertNoLocalBindingDisclosure(
  catalog: ProviderAdvisoryCandidateCatalog,
  brief: ProviderAdvisoryBrief,
): void {
  const serialized = canonicalJson(brief).toLocaleLowerCase("en-US");
  const leaked = localBindingTokens(catalog).find((value) =>
    serialized.includes(value.toLocaleLowerCase("en-US")));
  if (leaked) disclosureError(
    "provider_advisory_local_binding_disclosure_denied",
    "The sanitized planning brief still contains an exact local target or tool binding.",
  );
}

/**
 * Produces the only public-provider payload accepted by the advisory planner.
 * Candidate materialization remains in the local catalog; the public brief
 * carries opaque IDs, bounded summaries and exposure-policy envelopes only.
 */
export function prepareProviderAdvisoryBrief(
  input: PrepareProviderAdvisoryBriefInput,
): PreparedProviderAdvisoryBrief {
  const catalog = reconstructProviderAdvisoryCandidateCatalog(
    JSON.parse(canonicalJson(input.catalog)) as unknown,
  );
  const providerId = opaqueId(input.providerId, "Provider ID");
  const modelId = opaqueId(input.modelId, "Model ID");
  if (!Number.isFinite(Date.parse(input.createdAt))) disclosureError(
    "provider_advisory_exposure_time_invalid",
    "The provider exposure timestamp is invalid.",
  );
  const contextItems = input.contextItems ?? [];
  if (!Array.isArray(contextItems) || contextItems.length > MAXIMUM_CONTEXT_ITEMS) {
    disclosureError(
      "provider_advisory_context_bound_exceeded",
      `Provider advisory context is limited to ${MAXIMUM_CONTEXT_ITEMS} items.`,
    );
  }
  const policy = new LlmExposurePolicy(
    PROVIDER_ADVISORY_EXPOSURE_POLICY_VERSION,
  );
  const decision = policy.buildResearchBrief({
    campaignId: catalog.planningRequestId,
    dimensionId: PROVIDER_ADVISORY_DIMENSION_ID,
    objective:
      "Order every opaque candidate exactly once while preserving all stated prerequisites. Return advice only and request no execution.",
    providerId,
    modelId,
    createdAt: input.createdAt,
    items: [
      ...candidateSourceItems(catalog),
      ...contextItems,
    ],
  });
  const receiptErrors = validateProviderExposureReceipt(decision.receipt, {
    campaignId: catalog.planningRequestId,
    dimensionId: PROVIDER_ADVISORY_DIMENSION_ID,
  });
  if (
    !decision.brief
    || decision.receipt.blocked
    || receiptErrors.length > 0
  ) disclosureError(
    "provider_advisory_exposure_blocked",
    "The local disclosure policy did not produce an admissible planning brief.",
  );
  if (decision.receipt.rejectedContext.length > 0) disclosureError(
    "provider_advisory_context_rejected",
    "At least one requested context item violated the public-provider disclosure boundary.",
  );
  const brief: ProviderAdvisoryBrief = Object.freeze({
    schemaVersion: PROVIDER_ADVISORY_BRIEF_SCHEMA_VERSION,
    planningRequestId: catalog.planningRequestId,
    catalogHash: catalog.catalogHash,
    exposurePayloadHash: decision.receipt.exposedPayloadHash,
    systemContract: Object.freeze({
      advisoryOnly: true as const,
      executionAuthority: "none" as const,
      mayExecuteTools: false as const,
      mayEmitTargets: false as const,
      mayEmitToolArguments: false as const,
      mayChangePolicy: false as const,
      mustReturnEveryCandidateExactlyOnce: true as const,
      allowedOutput: "candidate_id_order_and_concise_rationale" as const,
    }),
    candidates: Object.freeze(catalog.candidates.map((candidate) =>
      Object.freeze({
        candidateId: candidate.candidateId,
        phase: candidate.publicSummary.phase,
        purpose: candidate.publicSummary.purpose,
        riskClass: candidate.publicSummary.riskClass,
        prerequisiteCandidateIds:
          Object.freeze([...candidate.dependencyCandidateIds]),
        requiredEvidenceCount: candidate.requiredEvidenceTypeIds.length,
      }))),
    observations: Object.freeze([...decision.brief.observations]),
  });
  assertNoLocalBindingDisclosure(catalog, brief);
  return Object.freeze({
    brief,
    briefHash: hashCanonical(brief),
    exposureReceipt: decision.receipt,
  });
}

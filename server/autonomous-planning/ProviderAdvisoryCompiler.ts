import { canonicalJson, hashCanonical } from "../missions/canonical";
import {
  assessPromptInjection,
  sanitizeResearchText,
} from "../research/LlmExposurePolicy";
import { deepFreeze } from "../research/canonical";
import {
  PROVIDER_ADVISORY_COMPILATION_SCHEMA_VERSION,
  PROVIDER_ADVISORY_SELECTION_SCHEMA_VERSION,
  ProviderAdvisoryPlanningError,
  type CompileProviderAdvisorySelectionInput,
  type CompiledProviderAdvisoryPlan,
  type ProviderAdvisoryCandidateCatalog,
  type ProviderAdvisoryCompilationReceipt,
  type ProviderAdvisorySelection,
} from "./ProviderAdvisoryPlanningTypes";
import { reconstructProviderAdvisoryCandidateCatalog } from "./ProviderAdvisoryCandidateCatalog";

const HASH = /^[a-f0-9]{64}$/u;
const CANDIDATE_ID = /^candidate_[a-f0-9]{24}$/u;

function responseError(code: string, message: string): never {
  throw new ProviderAdvisoryPlanningError(
    code,
    message,
    "invalid_provider_response",
    false,
  );
}

function driftError(code: string, message: string): never {
  throw new ProviderAdvisoryPlanningError(
    code,
    message,
    "policy_drift",
    false,
  );
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function exactHash(value: unknown, label: string): string {
  if (typeof value !== "string" || !HASH.test(value)) driftError(
    "provider_advisory_policy_binding_invalid",
    `${label} must be a SHA-256 hash.`,
  );
  return value;
}

function conciseRationale(value: unknown): string {
  if (typeof value !== "string") responseError(
    "provider_advisory_rationale_invalid",
    "The provider rationale must be concise text.",
  );
  const normalized = value.normalize("NFKC").trim();
  if (!normalized || normalized.length > 500) responseError(
    "provider_advisory_rationale_invalid",
    "The provider rationale is empty or exceeds 500 characters.",
  );
  if (assessPromptInjection(normalized).quarantined) responseError(
    "provider_advisory_rationale_prompt_injection",
    "The provider rationale contains instruction-like content.",
  );
  const sanitized = sanitizeResearchText(normalized, 500);
  if (!sanitized.sanitized || sanitized.actions.length > 0) responseError(
    "provider_advisory_rationale_disclosure_violation",
    "The provider rationale contains content outside the advisory disclosure contract.",
  );
  return sanitized.sanitized;
}

function assertDependencyOrder(
  catalog: ProviderAdvisoryCandidateCatalog,
  orderedCandidateIds: readonly string[],
): void {
  const positions = new Map(
    orderedCandidateIds.map((candidateId, index) => [candidateId, index]),
  );
  for (const candidate of catalog.candidates) {
    const position = positions.get(candidate.candidateId)!;
    if (candidate.dependencyCandidateIds.some((dependency) =>
      positions.get(dependency)! >= position)) {
      responseError(
        "provider_advisory_dependency_order_invalid",
        "The provider ordering violates a pre-materialized prerequisite.",
      );
    }
  }
}

export function validateProviderAdvisorySelection(
  value: unknown,
  catalog: ProviderAdvisoryCandidateCatalog,
): ProviderAdvisorySelection {
  if (!plainRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "catalogHash",
    "advisoryOnly",
    "executionRequested",
    "orderedCandidateIds",
    "rationale",
  ])) responseError(
    "provider_advisory_selection_schema_invalid",
    "The provider response has missing or unexpected fields.",
  );
  if (value.schemaVersion !== PROVIDER_ADVISORY_SELECTION_SCHEMA_VERSION) {
    responseError(
      "provider_advisory_selection_version_unsupported",
      "The provider response schema version is unsupported.",
    );
  }
  if (value.advisoryOnly !== true || value.executionRequested !== false) {
    responseError(
      "provider_advisory_execution_request_denied",
      "The provider attempted to claim execution authority.",
    );
  }
  if (value.catalogHash !== catalog.catalogHash) responseError(
    "provider_advisory_catalog_binding_mismatch",
    "The provider response does not bind the exact candidate catalog.",
  );
  if (!Array.isArray(value.orderedCandidateIds)) responseError(
    "provider_advisory_candidate_ids_invalid",
    "The provider response must contain an ordered candidate-ID list.",
  );
  const orderedCandidateIds = value.orderedCandidateIds.map((item) => {
    if (typeof item !== "string" || !CANDIDATE_ID.test(item)) responseError(
      "provider_advisory_candidate_id_invalid",
      "The provider response contains a malformed candidate ID.",
    );
    return item;
  });
  if (new Set(orderedCandidateIds).size !== orderedCandidateIds.length) {
    responseError(
      "provider_advisory_candidate_id_duplicate",
      "The provider response repeats a candidate ID.",
    );
  }
  const expected = new Set(catalog.candidates.map(({ candidateId }) =>
    candidateId));
  if (orderedCandidateIds.some((candidateId) => !expected.has(candidateId))) {
    responseError(
      "provider_advisory_candidate_id_unknown",
      "The provider response contains an unknown candidate ID.",
    );
  }
  if (orderedCandidateIds.length !== expected.size
    || [...expected].some((candidateId) =>
      !orderedCandidateIds.includes(candidateId))) {
    responseError(
      "provider_advisory_candidate_id_missing",
      "The provider response must include every candidate exactly once.",
    );
  }
  assertDependencyOrder(catalog, orderedCandidateIds);
  return deepFreeze({
    schemaVersion: PROVIDER_ADVISORY_SELECTION_SCHEMA_VERSION,
    catalogHash: catalog.catalogHash,
    advisoryOnly: true,
    executionRequested: false,
    orderedCandidateIds,
    rationale: conciseRationale(value.rationale),
  });
}

export function deterministicFallbackSelection(
  catalog: ProviderAdvisoryCandidateCatalog,
): ProviderAdvisorySelection {
  const remaining = new Map(
    catalog.candidates.map((candidate, ordinal) => [
      candidate.candidateId,
      { candidate, ordinal },
    ]),
  );
  const ordered: string[] = [];
  while (remaining.size > 0) {
    const ready = [...remaining.values()]
      .filter(({ candidate }) => candidate.dependencyCandidateIds.every(
        (dependency) => ordered.includes(dependency),
      ))
      .sort((left, right) => left.ordinal - right.ordinal)[0];
    if (!ready) driftError(
      "provider_advisory_fallback_dependency_cycle",
      "The local fallback cannot topologically order the candidate catalog.",
    );
    ordered.push(ready.candidate.candidateId);
    remaining.delete(ready.candidate.candidateId);
  }
  return deepFreeze({
    schemaVersion: PROVIDER_ADVISORY_SELECTION_SCHEMA_VERSION,
    catalogHash: catalog.catalogHash,
    advisoryOnly: true,
    executionRequested: false,
    orderedCandidateIds: ordered,
    rationale:
      "The public advisor was unavailable, so local policy preserved the original dependency-valid candidate order.",
  });
}

export function compileProviderAdvisorySelection(
  input: CompileProviderAdvisorySelectionInput,
): CompiledProviderAdvisoryPlan {
  const catalog = reconstructProviderAdvisoryCandidateCatalog(
    JSON.parse(canonicalJson(input.catalog)) as unknown,
  );
  const expectedContractHash = exactHash(
    input.expectedContractHash,
    "Expected contract hash",
  );
  const expectedPolicyHash = exactHash(
    input.expectedPolicyHash,
    "Expected policy hash",
  );
  if (
    catalog.contractHash !== expectedContractHash
    || catalog.policyHash !== expectedPolicyHash
    || catalog.contextPackId !== input.expectedContextPackId
  ) driftError(
    "provider_advisory_policy_drift",
    "The signed contract, action policy or Context Pack changed after candidate construction.",
  );
  if (
    input.source !== "provider_advisory"
    && input.source !== "local_deterministic_fallback"
  ) driftError(
    "provider_advisory_source_invalid",
    "The planning source is not recognized.",
  );
  const selection = validateProviderAdvisorySelection(
    input.selection,
    catalog,
  );
  if (input.source === "provider_advisory") {
    if (
      !input.providerResult
      || input.providerResult.providerId.trim().length === 0
      || input.providerResult.requestedModel.trim().length === 0
      || input.providerResult.returnedModel.trim().length === 0
      || !input.briefHash
      || !HASH.test(input.briefHash)
      || !input.exposureReceiptId
    ) driftError(
      "provider_advisory_provider_receipt_missing",
      "Provider advice lacks its exact model, brief or exposure binding.",
    );
  }
  const byId = new Map(catalog.candidates.map((candidate) => [
    candidate.candidateId,
    candidate,
  ]));
  const outputPositions = new Map(
    selection.orderedCandidateIds.map((candidateId, ordinal) => [
      candidateId,
      ordinal,
    ]),
  );
  const steps = selection.orderedCandidateIds.map((candidateId) => {
    const candidate = byId.get(candidateId)!;
    return deepFreeze({
      ...candidate.step,
      dependencyOrdinals: candidate.dependencyCandidateIds
        .map((dependency) => outputPositions.get(dependency)!)
        .sort((left, right) => left - right),
    });
  });
  const providerUsage = input.providerResult === undefined
    ? undefined
    : {
        providerId: input.providerResult.providerId,
        requestedModel: input.providerResult.requestedModel,
        returnedModel: input.providerResult.returnedModel,
        ...(input.providerResult.usage.inputTokens === undefined
          ? {}
          : { inputTokens: input.providerResult.usage.inputTokens }),
        ...(input.providerResult.usage.outputTokens === undefined
          ? {}
          : { outputTokens: input.providerResult.usage.outputTokens }),
        ...(input.providerResult.usage.providerTokens === undefined
          ? {}
          : {
              totalTokens: input.providerResult.usage.providerTokens,
              providerTokens: input.providerResult.usage.providerTokens,
            }),
        ...(input.providerResult.usage.billedCostUsd === undefined
          ? {}
          : {
              billedCostUsd: input.providerResult.usage.billedCostUsd,
              estimatedCost: input.providerResult.usage.billedCostUsd,
            }),
        exactTokenUsage: input.providerResult.usage.exactTokenUsage,
        exactCostUsage: input.providerResult.usage.exactCostUsage,
      };
  const plan = deepFreeze({
    strategySummary:
      `Use ${steps.length} locally materialized, policy-bound candidate ${steps.length === 1 ? "step" : "steps"} in dependency-valid order.`,
    rationaleSummary:
      `${selection.rationale} The provider selected opaque IDs only; local code retained every target, tool argument, evidence requirement and execution binding unchanged.`,
    steps,
    ...(providerUsage === undefined ? {} : { providerUsage }),
  });
  const withoutReceiptHash:
    Omit<ProviderAdvisoryCompilationReceipt, "receiptHash"> = {
      schemaVersion: PROVIDER_ADVISORY_COMPILATION_SCHEMA_VERSION,
      planningRequestId: catalog.planningRequestId,
      catalogHash: catalog.catalogHash,
      contractHash: catalog.contractHash,
      policyHash: catalog.policyHash,
      contextPackId: catalog.contextPackId,
      source: input.source,
      executionAuthority: "none",
      orderedCandidateIds: Object.freeze([
        ...selection.orderedCandidateIds,
      ]),
      candidateHashes: Object.freeze(selection.orderedCandidateIds.map(
        (candidateId) => byId.get(candidateId)!.candidateHash,
      )),
      evidenceRequirements: Object.freeze(
        selection.orderedCandidateIds.map((candidateId) => {
          const candidate = byId.get(candidateId)!;
          return Object.freeze({
            candidateId,
            evidenceTypeIds: Object.freeze([
              ...candidate.requiredEvidenceTypeIds,
            ]),
          });
        }),
      ),
      ...(input.briefHash ? { briefHash: input.briefHash } : {}),
      ...(input.exposureReceiptId
        ? { exposureReceiptId: input.exposureReceiptId }
        : {}),
      ...(input.fallbackReasonCode
        ? { fallbackReasonCode: input.fallbackReasonCode }
        : {}),
      planHash: hashCanonical(plan),
    };
  return deepFreeze({
    plan,
    receipt: {
      ...withoutReceiptHash,
      receiptHash: hashCanonical(withoutReceiptHash),
    },
  });
}

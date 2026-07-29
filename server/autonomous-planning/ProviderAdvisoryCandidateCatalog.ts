import {
  ACTION_CLASS_DEFINITIONS,
  isActionClassId,
  isEvidenceTypeId,
  type ActionClassDefinition,
  type ActionClassId,
  type EvidenceTypeId,
} from "../domain";
import type { RuntimeModelBindingReceipt } from "../command-runtime/types";
import { canonicalJson, hashCanonical } from "../missions/canonical";
import {
  assessPromptInjection,
  sanitizeResearchText,
} from "../research/LlmExposurePolicy";
import { deepFreeze } from "../research/canonical";
import {
  PROVIDER_ADVISORY_CATALOG_SCHEMA_VERSION,
  ProviderAdvisoryPlanningError,
  type BuildProviderAdvisoryCatalogInput,
  type ProviderAdvisoryCandidateInput,
  type ProviderAdvisoryCandidateCatalog,
  type ProviderAdvisoryLocalCandidate,
  type ProviderAdvisoryRiskClass,
} from "./ProviderAdvisoryPlanningTypes";

const HASH = /^[a-f0-9]{64}$/u;
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,239}$/u;
const MAXIMUM_CANDIDATES = 24;
const MAXIMUM_JSON_BYTES = 256 * 1_024;
const SECRET_KEY =
  /(?:^|[_-])(?:api[_-]?key|auth|authorization|bearer|cookie|credential|password|private[_-]?key|secret|session|token)(?:$|[_-])/iu;
const DEFINITIONS = new Map<ActionClassId, ActionClassDefinition>(
  ACTION_CLASS_DEFINITIONS.map((definition) => [definition.id, definition]),
);

function catalogError(code: string, message: string): never {
  throw new ProviderAdvisoryPlanningError(
    code,
    message,
    "invalid_catalog",
    false,
  );
}

function exactKeys(
  value: Readonly<Record<string, unknown>>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  return required.every((key) => keys.includes(key))
    && keys.every((key) => allowed.has(key));
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function boundedText(
  value: unknown,
  label: string,
  maximum = 2_000,
): string {
  if (typeof value !== "string") catalogError(
    "provider_advisory_catalog_text_invalid",
    `${label} must be text.`,
  );
  const normalized = value.normalize("NFKC").trim();
  if (!normalized || normalized.length > maximum) catalogError(
    "provider_advisory_catalog_text_invalid",
    `${label} is empty or exceeds its bound.`,
  );
  return normalized;
}

function opaqueId(value: unknown, label: string): string {
  const normalized = boundedText(value, label, 240);
  if (!OPAQUE_ID.test(normalized)) catalogError(
    "provider_advisory_catalog_id_invalid",
    `${label} is not an opaque canonical identifier.`,
  );
  return normalized;
}

function exactHash(value: unknown, label: string): string {
  if (typeof value !== "string" || !HASH.test(value)) catalogError(
    "provider_advisory_catalog_hash_invalid",
    `${label} must be a SHA-256 hash.`,
  );
  return value;
}

function uniqueTexts(
  value: unknown,
  label: string,
  options: { readonly allowEmpty?: boolean; readonly maximum?: number } = {},
): readonly string[] {
  if (!Array.isArray(value)) catalogError(
    "provider_advisory_catalog_list_invalid",
    `${label} must be a list.`,
  );
  const maximum = options.maximum ?? 128;
  if (value.length > maximum || (!options.allowEmpty && value.length === 0)) {
    catalogError(
      "provider_advisory_catalog_list_invalid",
      `${label} is outside its item bound.`,
    );
  }
  const normalized = value.map((item, index) =>
    boundedText(item, `${label}[${index}]`, 1_000));
  if (new Set(normalized).size !== normalized.length) catalogError(
    "provider_advisory_catalog_list_duplicate",
    `${label} contains duplicate values.`,
  );
  return Object.freeze(normalized);
}

function assertJsonSafe(value: unknown, path: string, depth = 0): void {
  if (depth > 16) catalogError(
    "provider_advisory_catalog_json_too_deep",
    `${path} exceeds the JSON depth bound.`,
  );
  if (
    value === null
    || typeof value === "string"
    || typeof value === "boolean"
  ) return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) catalogError(
      "provider_advisory_catalog_json_invalid",
      `${path} contains a non-finite number.`,
    );
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 500) catalogError(
      "provider_advisory_catalog_json_too_large",
      `${path} contains too many values.`,
    );
    value.forEach((item, index) =>
      assertJsonSafe(item, `${path}[${index}]`, depth + 1));
    return;
  }
  if (!plainRecord(value)) catalogError(
    "provider_advisory_catalog_json_invalid",
    `${path} is not plain JSON.`,
  );
  for (const [key, item] of Object.entries(value)) {
    if (SECRET_KEY.test(key)) catalogError(
      "provider_advisory_catalog_secret_field",
      `${path} contains a secret-bearing field.`,
    );
    assertJsonSafe(item, `${path}.${key}`, depth + 1);
  }
}

function frozenJson<T>(value: T, path: string): T {
  assertJsonSafe(value, path);
  const serialized = canonicalJson(value);
  if (Buffer.byteLength(serialized, "utf8") > MAXIMUM_JSON_BYTES) catalogError(
    "provider_advisory_catalog_json_too_large",
    `${path} exceeds its byte bound.`,
  );
  return deepFreeze(JSON.parse(serialized) as T);
}

function expectedRisk(definition: ActionClassDefinition): ProviderAdvisoryRiskClass {
  return definition.riskBand === "moderate" ? "medium" : definition.riskBand;
}

function publicSummary(
  value: unknown,
  label: string,
  forbiddenExactValues: readonly string[],
): string {
  const raw = boundedText(value, label, 500);
  const injection = assessPromptInjection(raw);
  if (injection.quarantined) catalogError(
    "provider_advisory_candidate_prompt_injection",
    `${label} contains quarantined instruction-like content.`,
  );
  const lower = raw.toLocaleLowerCase("en-US");
  if (forbiddenExactValues.some((item) =>
    item.length >= 3 && lower.includes(item.toLocaleLowerCase("en-US")))) {
    catalogError(
      "provider_advisory_candidate_summary_discloses_local_binding",
      `${label} contains an exact target or tool binding.`,
    );
  }
  const sanitized = sanitizeResearchText(raw, 500);
  if (!sanitized.sanitized) catalogError(
    "provider_advisory_candidate_summary_empty",
    `${label} is empty after provider sanitization.`,
  );
  return sanitized.sanitized;
}

function runtimeBinding(
  value: unknown,
  path: string,
): RuntimeModelBindingReceipt {
  if (!plainRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "agentId",
    "modelAssignmentId",
    "modelConfigurationId",
    "modelConfigurationHash",
    "providerConfigurationHash",
    "providerId",
    "modelId",
    "reasoningEffort",
  ])) catalogError(
    "provider_advisory_runtime_model_binding_invalid",
    `${path} is not an exact runtime model binding.`,
  );
  exactHash(value.modelConfigurationHash, `${path}.modelConfigurationHash`);
  exactHash(value.providerConfigurationHash, `${path}.providerConfigurationHash`);
  for (const key of [
    "schemaVersion", "agentId", "modelAssignmentId", "modelConfigurationId",
    "providerId", "modelId",
  ]) boundedText(value[key], `${path}.${key}`, 240);
  if (value.reasoningEffort !== null && typeof value.reasoningEffort !== "string") {
    catalogError(
      "provider_advisory_runtime_model_binding_invalid",
      `${path}.reasoningEffort is invalid.`,
    );
  }
  if (value.schemaVersion !== "ti-scale.runtime-model-binding.v1") {
    catalogError(
      "provider_advisory_runtime_model_binding_invalid",
      `${path}.schemaVersion is unsupported.`,
    );
  }
  return value as unknown as RuntimeModelBindingReceipt;
}

function stepCore(
  value: unknown,
  index: number,
  allowedTargets: ReadonlySet<string>,
  allowedActionClasses: ReadonlySet<string>,
  prohibitedActionClasses: ReadonlySet<string>,
  allowedAgentIds: ReadonlySet<string>,
): Omit<ProviderAdvisoryLocalCandidate["step"], never> {
  const path = `candidates[${index}].step`;
  if (!plainRecord(value) || !exactKeys(value, [
    "phase",
    "title",
    "objective",
    "explanation",
    "rationale",
    "successCriteria",
    "assignedAgentId",
    "riskClass",
    "reversibility",
    "action",
  ], ["dependencyOrdinals", "runtimeModelBinding"])) catalogError(
    "provider_advisory_step_schema_invalid",
    `${path} contains missing or unexpected fields.`,
  );
  const assignedAgentId = opaqueId(value.assignedAgentId, `${path}.assignedAgentId`);
  if (!allowedAgentIds.has(assignedAgentId)) catalogError(
    "provider_advisory_step_agent_outside_policy",
    `${path} uses a specialist outside the signed policy.`,
  );
  if (!plainRecord(value.action) || !exactKeys(value.action, [
    "actionType",
    "actionClass",
    "target",
    "arguments",
    "intentSummary",
    "kind",
    "idempotent",
    "destructive",
  ])) catalogError(
    "provider_advisory_action_schema_invalid",
    `${path}.action contains missing or unexpected fields.`,
  );
  const actionClass = boundedText(
    value.action.actionClass,
    `${path}.action.actionClass`,
    120,
  );
  if (!isActionClassId(actionClass)
    || !allowedActionClasses.has(actionClass)
    || prohibitedActionClasses.has(actionClass)) {
    catalogError(
      "provider_advisory_action_outside_policy",
      `${path}.action is not pre-authorized by the exact policy.`,
    );
  }
  const definition = DEFINITIONS.get(actionClass)!;
  const target = boundedText(value.action.target, `${path}.action.target`, 1_000);
  if (!allowedTargets.has(target)) catalogError(
    "provider_advisory_target_outside_scope",
    `${path}.action target is outside exact normalized scope.`,
  );
  if (value.riskClass !== expectedRisk(definition)) catalogError(
    "provider_advisory_risk_mismatch",
    `${path} risk does not match the Action Class Registry.`,
  );
  if (value.action.destructive !== definition.destructiveOrDisruptive) catalogError(
    "provider_advisory_destructive_mismatch",
    `${path} destructive state does not match the Action Class Registry.`,
  );
  if (value.action.kind !== "tool") catalogError(
    "provider_advisory_non_tool_action",
    `${path} is not a finite pre-materialized tool action.`,
  );
  if (typeof value.action.idempotent !== "boolean"
    || typeof value.action.destructive !== "boolean") {
    catalogError(
      "provider_advisory_action_boolean_invalid",
      `${path}.action has an invalid execution property.`,
    );
  }
  const successCriteria = uniqueTexts(
    value.successCriteria,
    `${path}.successCriteria`,
    { maximum: 64 },
  );
  if (!plainRecord(value.action.arguments)) catalogError(
    "provider_advisory_action_arguments_invalid",
    `${path}.action.arguments must be an exact JSON object.`,
  );
  const actionArguments = frozenJson(
    value.action.arguments,
    `${path}.action.arguments`,
  );
  const runtimeModelBindingValue = value.runtimeModelBinding === undefined
    ? undefined
    : runtimeBinding(
        value.runtimeModelBinding,
        `${path}.runtimeModelBinding`,
      );
  const core: ProviderAdvisoryLocalCandidate["step"] = {
    phase: boundedText(value.phase, `${path}.phase`, 240),
    title: boundedText(value.title, `${path}.title`, 500),
    objective: boundedText(value.objective, `${path}.objective`, 2_000),
    explanation: boundedText(value.explanation, `${path}.explanation`, 4_000),
    rationale: boundedText(value.rationale, `${path}.rationale`, 4_000),
    successCriteria,
    assignedAgentId,
    riskClass: value.riskClass as ProviderAdvisoryRiskClass,
    reversibility: boundedText(value.reversibility, `${path}.reversibility`, 2_000),
    action: {
      actionType: opaqueId(value.action.actionType, `${path}.action.actionType`),
      actionClass,
      target,
      arguments: actionArguments,
      intentSummary: boundedText(
        value.action.intentSummary,
        `${path}.action.intentSummary`,
        2_000,
      ),
      kind: "tool" as const,
      idempotent: value.action.idempotent,
      destructive: value.action.destructive,
    },
    ...(runtimeModelBindingValue === undefined
      ? {}
      : { runtimeModelBinding: runtimeModelBindingValue }),
  };
  return frozenJson(core, path);
}

function dependencyOrdinals(
  value: unknown,
  index: number,
  candidateCount: number,
): readonly number[] {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value)) catalogError(
    "provider_advisory_dependencies_invalid",
    `candidates[${index}].step.dependencyOrdinals must be a list.`,
  );
  const ordinals = value.map((item) => {
    if (!Number.isSafeInteger(item) || (item as number) < 0
      || (item as number) >= candidateCount || item === index) {
      catalogError(
        "provider_advisory_dependency_outside_catalog",
        `candidates[${index}] has an invalid dependency ordinal.`,
      );
    }
    return item as number;
  });
  if (new Set(ordinals).size !== ordinals.length) catalogError(
    "provider_advisory_dependency_duplicate",
    `candidates[${index}] repeats a dependency.`,
  );
  return Object.freeze(ordinals);
}

function assertAcyclic(dependencies: readonly (readonly number[])[]): void {
  const state = new Array<number>(dependencies.length).fill(0);
  const visit = (index: number): void => {
    if (state[index] === 1) catalogError(
      "provider_advisory_dependency_cycle",
      "Candidate dependencies contain a cycle.",
    );
    if (state[index] === 2) return;
    state[index] = 1;
    for (const dependency of dependencies[index]!) visit(dependency);
    state[index] = 2;
  };
  for (let index = 0; index < dependencies.length; index += 1) visit(index);
}

function evidenceTypes(
  value: unknown,
  index: number,
  definition: ActionClassDefinition,
): readonly EvidenceTypeId[] {
  const items = uniqueTexts(
    value,
    `candidates[${index}].requiredEvidenceTypeIds`,
    { maximum: 32 },
  );
  if (items.some((item) => !isEvidenceTypeId(item))) catalogError(
    "provider_advisory_evidence_type_invalid",
    `candidates[${index}] contains an unregistered evidence type.`,
  );
  const evidence = items as readonly EvidenceTypeId[];
  if (definition.defaultEvidenceTypeIds.some((item) => !evidence.includes(item))) {
    catalogError(
      "provider_advisory_evidence_policy_incomplete",
      `candidates[${index}] omits required Action Class Registry evidence.`,
    );
  }
  return Object.freeze([...evidence]);
}

function registryHash(actionClassIds: readonly ActionClassId[]): string {
  return hashCanonical(
    [...actionClassIds]
      .sort((left, right) => left.localeCompare(right))
      .map((id) => DEFINITIONS.get(id)!),
  );
}

function catalogPayload(
  catalog: Omit<ProviderAdvisoryCandidateCatalog, "catalogHash">,
): unknown {
  return catalog;
}

function candidatePayload(
  candidate: Omit<ProviderAdvisoryLocalCandidate, "candidateHash">,
): unknown {
  return candidate;
}

export function buildProviderAdvisoryCandidateCatalog(
  input: BuildProviderAdvisoryCatalogInput,
): ProviderAdvisoryCandidateCatalog {
  if (!plainRecord(input)) catalogError(
    "provider_advisory_catalog_input_invalid",
    "Provider-advisory catalog input must be an object.",
  );
  const planningRequestId = opaqueId(
    input.planningRequestId,
    "planningRequestId",
  );
  const contractHash = exactHash(input.contractHash, "contractHash");
  const policyHash = exactHash(input.policyHash, "policyHash");
  const contextPackId = opaqueId(input.contextPackId, "contextPackId");
  const allowedTargets = uniqueTexts(
    input.allowedTargets,
    "allowedTargets",
    { maximum: 128 },
  );
  const actionClasses = uniqueTexts(
    input.allowedActionClassIds,
    "allowedActionClassIds",
    { maximum: 64 },
  );
  const prohibited = uniqueTexts(
    input.prohibitedActionClassIds,
    "prohibitedActionClassIds",
    { allowEmpty: true, maximum: 64 },
  );
  if (actionClasses.some((item) => !isActionClassId(item))
    || prohibited.some((item) => !isActionClassId(item))) {
    catalogError(
      "provider_advisory_action_class_invalid",
      "The candidate catalog contains an unregistered action class.",
    );
  }
  if (actionClasses.some((item) => prohibited.includes(item))) catalogError(
    "provider_advisory_action_policy_conflict",
    "An action class cannot be both allowed and prohibited.",
  );
  const allowedActionClassIds = actionClasses as readonly ActionClassId[];
  const prohibitedActionClassIds = prohibited as readonly ActionClassId[];
  const allowedAgentIds = uniqueTexts(
    input.allowedAgentIds,
    "allowedAgentIds",
    { maximum: 64 },
  ).map((item, index) => opaqueId(item, `allowedAgentIds[${index}]`));
  if (!Number.isSafeInteger(input.maximumSteps)
    || input.maximumSteps < 1
    || input.maximumSteps > MAXIMUM_CANDIDATES) {
    catalogError(
      "provider_advisory_maximum_steps_invalid",
      `maximumSteps must be 1 through ${MAXIMUM_CANDIDATES}.`,
    );
  }
  if (!Array.isArray(input.candidates)
    || input.candidates.length < 1
    || input.candidates.length > input.maximumSteps) {
    catalogError(
      "provider_advisory_candidate_count_invalid",
      "The finite candidate count is empty or exceeds the exact policy bound.",
    );
  }

  const allowedTargetSet = new Set(allowedTargets);
  const allowedClassSet = new Set(allowedActionClassIds);
  const prohibitedClassSet = new Set(prohibitedActionClassIds);
  const allowedAgentSet = new Set(allowedAgentIds);
  const cores = input.candidates.map((candidate, index) => stepCore(
    candidate.step,
    index,
    allowedTargetSet,
    allowedClassSet,
    prohibitedClassSet,
    allowedAgentSet,
  ));
  const dependencies = input.candidates.map((candidate, index) =>
    dependencyOrdinals(
      candidate.step.dependencyOrdinals,
      index,
      input.candidates.length,
    ));
  assertAcyclic(dependencies);
  const evidence = input.candidates.map((candidate, index) => {
    const definition = DEFINITIONS.get(
      cores[index]!.action.actionClass as ActionClassId,
    )!;
    return evidenceTypes(candidate.requiredEvidenceTypeIds, index, definition);
  });
  const candidateIds = cores.map((step, ordinal) =>
    `candidate_${hashCanonical({
      planningRequestId,
      contractHash,
      policyHash,
      ordinal,
      step,
      requiredEvidenceTypeIds: evidence[ordinal],
    }).slice(0, 24)}`);

  const candidates = input.candidates.map((candidate, index) => {
    const step = cores[index]!;
    const dependencyCandidateIds = dependencies[index]!
      .map((ordinal) => candidateIds[ordinal]!);
    const forbiddenValues = [
      step.action.target,
      step.action.actionType,
    ];
    const withoutHash: Omit<ProviderAdvisoryLocalCandidate, "candidateHash"> = {
      candidateId: candidateIds[index]!,
      publicSummary: {
        phase: publicSummary(
          candidate.publicSummary.phase,
          `candidates[${index}].publicSummary.phase`,
          forbiddenValues,
        ),
        purpose: publicSummary(
          candidate.publicSummary.purpose,
          `candidates[${index}].publicSummary.purpose`,
          forbiddenValues,
        ),
        riskClass: step.riskClass,
        prerequisiteCandidateIds: Object.freeze(dependencyCandidateIds),
        requiredEvidenceCount: evidence[index]!.length,
      },
      step,
      dependencyCandidateIds: Object.freeze(dependencyCandidateIds),
      requiredEvidenceTypeIds: evidence[index]!,
    };
    return deepFreeze({
      ...withoutHash,
      candidateHash: hashCanonical(candidatePayload(withoutHash)),
    });
  });
  const withoutHash: Omit<ProviderAdvisoryCandidateCatalog, "catalogHash"> = {
    schemaVersion: PROVIDER_ADVISORY_CATALOG_SCHEMA_VERSION,
    planningRequestId,
    contractHash,
    policyHash,
    contextPackId,
    actionRegistryHash: registryHash(allowedActionClassIds),
    allowedTargets,
    allowedActionClassIds: Object.freeze([...allowedActionClassIds]),
    prohibitedActionClassIds: Object.freeze([...prohibitedActionClassIds]),
    allowedAgentIds: Object.freeze([...allowedAgentIds]),
    maximumSteps: input.maximumSteps,
    candidates: Object.freeze(candidates),
  };
  return deepFreeze({
    ...withoutHash,
    catalogHash: hashCanonical(catalogPayload(withoutHash)),
  });
}

/**
 * Restart-safe reconstruction. It validates every local-only field and all
 * hashes; it never trusts a serialized catalog simply because its JSON parses.
 */
export function reconstructProviderAdvisoryCandidateCatalog(
  value: unknown,
): ProviderAdvisoryCandidateCatalog {
  if (!plainRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "planningRequestId",
    "contractHash",
    "policyHash",
    "contextPackId",
    "actionRegistryHash",
    "allowedTargets",
    "allowedActionClassIds",
    "prohibitedActionClassIds",
    "allowedAgentIds",
    "maximumSteps",
    "candidates",
    "catalogHash",
  ])) catalogError(
    "provider_advisory_catalog_schema_invalid",
    "The serialized candidate catalog has missing or unexpected fields.",
  );
  if (value.schemaVersion !== PROVIDER_ADVISORY_CATALOG_SCHEMA_VERSION) {
    catalogError(
      "provider_advisory_catalog_version_unsupported",
      "The serialized candidate catalog version is unsupported.",
    );
  }
  if (!Array.isArray(value.candidates)) catalogError(
    "provider_advisory_candidate_count_invalid",
    "The serialized candidate catalog has no finite candidate list.",
  );
  const serializedCandidates = value.candidates as unknown[];
  const candidateIds = serializedCandidates.map((candidate, index) => {
    if (!plainRecord(candidate) || !exactKeys(candidate, [
      "candidateId",
      "candidateHash",
      "publicSummary",
      "step",
      "dependencyCandidateIds",
      "requiredEvidenceTypeIds",
    ])) catalogError(
      "provider_advisory_candidate_schema_invalid",
      `Serialized candidate ${index} has missing or unexpected fields.`,
    );
    return opaqueId(candidate.candidateId, `candidates[${index}].candidateId`);
  });
  const dependencyOrdinalsByCandidate = serializedCandidates.map(
    (candidate, index) => {
      const record = candidate as Record<string, unknown>;
      if (!Array.isArray(record.dependencyCandidateIds)) catalogError(
        "provider_advisory_dependencies_invalid",
        `Serialized candidate ${index} has invalid dependencies.`,
      );
      return record.dependencyCandidateIds.map((dependency) => {
        const id = opaqueId(
          dependency,
          `candidates[${index}].dependencyCandidateIds`,
        );
        const ordinal = candidateIds.indexOf(id);
        if (ordinal < 0) catalogError(
          "provider_advisory_dependency_outside_catalog",
          `Serialized candidate ${index} references an unknown dependency.`,
        );
        return ordinal;
      });
    },
  );
  const rebuilt = buildProviderAdvisoryCandidateCatalog({
    planningRequestId: opaqueId(value.planningRequestId, "planningRequestId"),
    contractHash: exactHash(value.contractHash, "contractHash"),
    policyHash: exactHash(value.policyHash, "policyHash"),
    contextPackId: opaqueId(value.contextPackId, "contextPackId"),
    allowedTargets: value.allowedTargets as readonly string[],
    allowedActionClassIds: value.allowedActionClassIds as readonly ActionClassId[],
    prohibitedActionClassIds: value.prohibitedActionClassIds as readonly ActionClassId[],
    allowedAgentIds: value.allowedAgentIds as readonly string[],
    maximumSteps: value.maximumSteps as number,
    candidates: serializedCandidates.map((candidate, index) => {
      const record = candidate as Record<string, unknown>;
      const summary = record.publicSummary;
      if (!plainRecord(summary)) catalogError(
        "provider_advisory_candidate_summary_invalid",
        `Serialized candidate ${index} has an invalid public summary.`,
      );
      return {
        publicSummary: {
          phase: summary.phase as string,
          purpose: summary.purpose as string,
        },
        step: {
          ...(record.step as object),
          dependencyOrdinals: dependencyOrdinalsByCandidate[index],
        } as unknown as ProviderAdvisoryCandidateInput["step"],
        requiredEvidenceTypeIds:
          record.requiredEvidenceTypeIds as readonly EvidenceTypeId[],
      };
    }),
  });
  if (
    rebuilt.catalogHash !== exactHash(value.catalogHash, "catalogHash")
    || rebuilt.actionRegistryHash !== exactHash(
      value.actionRegistryHash,
      "actionRegistryHash",
    )
    || rebuilt.candidates.some((candidate, index) => {
      const record = serializedCandidates[index] as Record<string, unknown>;
      return candidate.candidateId !== record.candidateId
        || candidate.candidateHash !== record.candidateHash;
    })
  ) catalogError(
    "provider_advisory_catalog_integrity_failed",
    "The serialized candidate catalog does not match its canonical hashes.",
  );
  return rebuilt;
}

export function currentProviderAdvisoryRegistryHash(
  actionClassIds: readonly ActionClassId[],
): string {
  return registryHash(actionClassIds);
}

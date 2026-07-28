import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { canonicalJson, hashJson } from "../orchestration/serialization";
import {
  attackKnowledgeOperationalLocatorCategories,
} from "./AttackKnowledgeTaxonomy";
import {
  assertReusableMemoryText,
  assertReusableMemoryUnknown,
  REUSABLE_MEMORY_LIMITS,
} from "./ReusableMemorySafety";
import type { MemoryLifecycle, MemoryNodeType } from "./types";

type Primitive = string | number | boolean;

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const MAX_NODE_IDS = 128;
const MAX_LIST_ITEMS = 128;
const MAX_TEXT_BYTES = 4_000;

const VERSION_TYPES: ReadonlySet<MemoryNodeType> = new Set([
  "exact_version_fingerprint",
  "version_range_fingerprint",
]);
const STACK_TYPES: ReadonlySet<MemoryNodeType> = new Set([
  "operating_system",
  "kernel",
  "framework",
  "runtime",
  "database",
  "firewall",
  "waf",
  "proxy",
  "security_control",
  "topology_pattern",
  "topology_role",
]);
const OBSERVED_STATE_TYPES: ReadonlySet<MemoryNodeType> = new Set([
  "target_state_transition",
  "health_check",
  "attribute",
]);

interface NodeRow {
  readonly id: string;
  readonly node_type: MemoryNodeType;
  readonly scope: string;
  readonly lifecycle_status: MemoryLifecycle;
}

interface ProfileRow {
  readonly node_id: string;
  readonly procedure_node_id: string;
  readonly procedure_version_node_id: string | null;
  readonly product_node_ids_json: string;
  readonly version_node_ids_json: string;
  readonly stack_node_ids_json: string;
  readonly prerequisite_node_ids_json: string;
  readonly observed_state_node_ids_json: string;
  readonly ordered_steps_json: string;
  readonly normalized_parameters_json: string;
  readonly load_min: number | null;
  readonly concurrency_min: number | null;
  readonly timing_window_ms: number | null;
  readonly observed_symptom: string;
  readonly affected_component: string;
  readonly state_before: string;
  readonly state_after: string;
  readonly state_transition_node_id: string | null;
  readonly reproducibility_count: number;
  readonly receipt_backed_occurrence_count: number;
  readonly attempt_count: number;
  readonly recovery_pattern_node_id: string | null;
  readonly recovery_action_summary: string;
  readonly recovery_cost_json: string;
  readonly unsafe_retry_conditions_json: string;
  readonly safe_retry_gate_json: string;
  readonly alternative_sequence_json: string;
  readonly alternative_procedure_node_id: string | null;
  readonly applicability_constraints_json: string;
  readonly reviewed_retry_contract_json: string | null;
  readonly confidence: number;
  readonly observed_at: string;
  readonly fresh_until: string | null;
  readonly version: number;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface OperationalHazardProfileInput {
  readonly hazardNodeId: string;
  readonly procedureNodeId: string;
  readonly procedureVersionNodeId?: string;
  readonly productNodeIds: readonly string[];
  readonly versionNodeIds: readonly string[];
  readonly stackNodeIds: readonly string[];
  readonly prerequisiteNodeIds: readonly string[];
  readonly observedStateNodeIds?: readonly string[];
  readonly orderedSteps: readonly string[];
  readonly normalizedParameters: Readonly<Record<string, Primitive>>;
  readonly loadMinimum?: number;
  readonly concurrencyMinimum?: number;
  readonly timingWindowMs?: number;
  readonly observedSymptom: string;
  readonly affectedComponent: string;
  readonly stateBefore: string;
  readonly stateAfter: string;
  readonly stateTransitionNodeId?: string;
  readonly reproducibilityCount: number;
  readonly attemptCount: number;
  readonly recoveryPatternNodeId?: string;
  readonly recoveryActionSummary: string;
  readonly recoveryCost?: OperationalHazardRecoveryCost;
  readonly unsafeRetryConditions: readonly string[];
  readonly safeRetryGate: readonly string[];
  readonly alternativeSequence?: readonly string[];
  readonly alternativeProcedureNodeId?: string;
  readonly applicabilityConstraints?: OperationalHazardApplicabilityConstraints;
  /**
   * Exact, operator-reviewed retry boundary. A display-only safeRetryGate is
   * never execution authority: the health gate requires this structured
   * contract and locally verified proof for each named condition.
   */
  readonly reviewedRetryContract?: OperationalHazardReviewedRetryContract;
  readonly confidence: number;
  readonly observedAt: string;
  readonly freshUntil?: string;
}

/** Numeric/boolean recovery facts deliberately exclude target-identifying text. */
export interface OperationalHazardRecoveryCost {
  readonly resetCount?: number;
  readonly operatorReportedResetCountMinimum?: number;
  readonly serviceRecycleCount?: number;
  readonly downtimeMs?: number;
  readonly operatorMinutes?: number;
  readonly requiresDisposableTargetReset?: boolean;
}

/** Matching rules are typed so a caller cannot smuggle a target label into them. */
export interface OperationalHazardApplicabilityConstraints {
  readonly requireExactProcedureVersion?: boolean;
  readonly requireVerifiedVersionRelationship?: boolean;
  readonly requireAllStackNodes?: boolean;
  readonly requireAllPrerequisites?: boolean;
  readonly requireObservedState?: boolean;
}

export interface OperationalHazardReviewedAttemptBinding {
  readonly procedureNodeId: string;
  readonly procedureVersionNodeId: string;
  readonly normalizedParameters: Readonly<Record<string, Primitive>>;
  readonly load: number | null;
  readonly concurrency: number | null;
  readonly timingWindowMs: number | null;
}

export interface OperationalHazardRetryValidCondition {
  /** Stable, non-semantic identifier selected during review. */
  readonly id: string;
  /** Must exactly correspond to one safeRetryGate statement. */
  readonly statement: string;
  /** Boolean result key emitted by the pinned trusted local evaluator. */
  readonly evidenceKey: string;
}

export interface OperationalHazardReviewedRetryContract {
  readonly schema: "ti_scale.operational_hazard_retry_contract/v1";
  readonly alternativeKind: "explicit_alternative" | "structured_delta";
  readonly source: OperationalHazardReviewedAttemptBinding;
  readonly alternative: OperationalHazardReviewedAttemptBinding;
  readonly retryValidConditions: readonly OperationalHazardRetryValidCondition[];
}

export function operationalHazardReviewedBindingFingerprint(
  binding: OperationalHazardReviewedAttemptBinding,
): string {
  return hashJson(binding);
}

export function operationalHazardRetryContractHash(
  contract: OperationalHazardReviewedRetryContract,
): string {
  return hashJson(contract);
}

export interface OperationalHazardProfile extends OperationalHazardProfileInput {
  /** Recomputed from immutable local reset/occurrence receipts; never caller supplied. */
  readonly receiptBackedOccurrenceCount: number;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export class OperationalHazardProfileError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "OperationalHazardProfileError";
  }
}

function parseJson<T>(value: string, label: string): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    throw new OperationalHazardProfileError("hazard_profile_malformed", `${label} is malformed`);
  }
}

function assertId(value: string, label: string): string {
  const normalized = value.trim();
  if (!ID_PATTERN.test(normalized)) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", `${label} is invalid`);
  }
  return normalized;
}

function normalizeIds(values: readonly string[], label: string): readonly string[] {
  if (!Array.isArray(values) || values.length > MAX_NODE_IDS) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", `${label} exceeds the bounded selection`);
  }
  return [...new Set(values.map((value) => assertId(value, label)))].sort();
}

function normalizeText(value: string, label: string): string {
  const normalized = value.trim().normalize("NFKC");
  if (!normalized) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", `${label} is required`);
  }
  assertReusableMemoryText([{ field: label, value: normalized, maximumBytes: MAX_TEXT_BYTES }]);
  const locators = attackKnowledgeOperationalLocatorCategories(normalized);
  if (locators.length > 0) {
    throw new OperationalHazardProfileError(
      "hazard_profile_contains_operational_locator",
      `${label} contains private operational locators: ${locators.join(", ")}`,
    );
  }
  return normalized;
}

function normalizeTextList(
  values: readonly string[],
  label: string,
  options: { readonly allowEmpty?: boolean } = {},
): readonly string[] {
  if (!Array.isArray(values) || values.length > MAX_LIST_ITEMS || (!options.allowEmpty && values.length === 0)) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", `${label} is invalid`);
  }
  return [...new Set(values.map((value, index) => normalizeText(value, `${label}[${index}]`)))];
}

function assertFiniteJson(value: unknown, field: string): void {
  assertReusableMemoryUnknown(value, field, REUSABLE_MEMORY_LIMITS.contextMetadata);
  const visit = (item: unknown): void => {
    if (typeof item === "number" && !Number.isFinite(item)) {
      throw new OperationalHazardProfileError("hazard_profile_invalid", `${field} contains a non-finite number`);
    }
    if (typeof item === "string") normalizeText(item, field);
    else if (Array.isArray(item)) item.forEach(visit);
    else if (item && typeof item === "object") Object.entries(item as Record<string, unknown>).forEach(([key, nested]) => {
      normalizeText(key, `${field}.key`);
      visit(nested);
    });
  };
  visit(value);
}

function normalizeRecoveryCost(value: OperationalHazardRecoveryCost): OperationalHazardRecoveryCost {
  const allowed = new Set([
    "resetCount",
    "operatorReportedResetCountMinimum",
    "serviceRecycleCount",
    "downtimeMs",
    "operatorMinutes",
    "requiresDisposableTargetReset",
  ]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new OperationalHazardProfileError("hazard_profile_invalid", "Recovery cost contains an unsupported field");
    }
  }
  const result: Record<string, number | boolean> = {};
  for (const key of [
    "resetCount",
    "operatorReportedResetCountMinimum",
    "serviceRecycleCount",
    "downtimeMs",
    "operatorMinutes",
  ] as const) {
    const item = value[key];
    if (item === undefined) continue;
    if (!Number.isSafeInteger(item) || item < 0) {
      throw new OperationalHazardProfileError("hazard_profile_invalid", `Recovery cost ${key} is invalid`);
    }
    result[key] = item;
  }
  if (value.requiresDisposableTargetReset !== undefined) {
    if (typeof value.requiresDisposableTargetReset !== "boolean") {
      throw new OperationalHazardProfileError("hazard_profile_invalid", "Recovery reset requirement is invalid");
    }
    result.requiresDisposableTargetReset = value.requiresDisposableTargetReset;
  }
  if (
    typeof result.resetCount === "number"
    && typeof result.operatorReportedResetCountMinimum === "number"
    && result.operatorReportedResetCountMinimum < result.resetCount
  ) {
    throw new OperationalHazardProfileError(
      "hazard_profile_invalid",
      "Operator-reported aggregate reset minimum cannot be lower than the exact-procedure reset count",
    );
  }
  return result;
}

function normalizeApplicabilityConstraints(
  value: OperationalHazardApplicabilityConstraints,
): OperationalHazardApplicabilityConstraints {
  const allowed = new Set([
    "requireExactProcedureVersion",
    "requireVerifiedVersionRelationship",
    "requireAllStackNodes",
    "requireAllPrerequisites",
    "requireObservedState",
  ]);
  const result: Record<string, boolean> = {};
  for (const [key, item] of Object.entries(value)) {
    if (!allowed.has(key) || typeof item !== "boolean") {
      throw new OperationalHazardProfileError(
        "hazard_profile_invalid",
        "Applicability constraints contain an unsupported field",
      );
    }
    result[key] = item;
  }
  return result;
}

function normalizeParameters(
  parameters: Readonly<Record<string, Primitive>>,
): Readonly<Record<string, Primitive>> {
  if (!parameters || typeof parameters !== "object" || Array.isArray(parameters)) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", "Normalized parameters must be an object");
  }
  const result: Record<string, Primitive> = {};
  const entries = Object.entries(parameters);
  if (entries.length > 64) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", "Normalized parameters exceed the field limit");
  }
  for (const [rawKey, rawValue] of entries.sort(([left], [right]) => left.localeCompare(right))) {
    const key = rawKey.trim().normalize("NFKC");
    if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(key)) {
      throw new OperationalHazardProfileError("hazard_profile_invalid", "Normalized parameter name is invalid");
    }
    if (typeof rawValue === "number" && !Number.isFinite(rawValue)) {
      throw new OperationalHazardProfileError("hazard_profile_invalid", "Normalized parameter value is invalid");
    }
    result[key] = typeof rawValue === "string"
      ? normalizeText(rawValue, `normalizedParameters.${key}`)
      : rawValue;
  }
  return result;
}

const RETRY_CONTRACT_SCHEMA = "ti_scale.operational_hazard_retry_contract/v1" as const;
const RETRY_CONDITION_KEY = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u;

function normalizeReviewedAttemptBinding(
  binding: OperationalHazardReviewedAttemptBinding,
  label: string,
): OperationalHazardReviewedAttemptBinding {
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", `${label} is invalid`);
  }
  const nullableNumber = (
    value: number | null,
    field: string,
    options: { readonly integer?: boolean } = {},
  ): number | null => {
    if (value === null) return null;
    if (!Number.isFinite(value) || value < 0 || (options.integer && (!Number.isSafeInteger(value) || value < 1))) {
      throw new OperationalHazardProfileError("hazard_profile_invalid", `${field} is invalid`);
    }
    return value;
  };
  return {
    procedureNodeId: assertId(binding.procedureNodeId, `${label} procedure node ID`),
    procedureVersionNodeId: assertId(binding.procedureVersionNodeId, `${label} procedure-version node ID`),
    normalizedParameters: normalizeParameters(binding.normalizedParameters),
    load: nullableNumber(binding.load, `${label} load`),
    concurrency: nullableNumber(binding.concurrency, `${label} concurrency`, { integer: true }),
    timingWindowMs: nullableNumber(binding.timingWindowMs, `${label} timing window`),
  };
}

function normalizeReviewedRetryContract(
  contract: OperationalHazardReviewedRetryContract,
  profile: {
    readonly procedureNodeId: string;
    readonly procedureVersionNodeId?: string;
    readonly normalizedParameters: Readonly<Record<string, Primitive>>;
    readonly loadMinimum?: number;
    readonly concurrencyMinimum?: number;
    readonly timingWindowMs?: number;
    readonly safeRetryGate: readonly string[];
    readonly alternativeProcedureNodeId?: string;
  },
): OperationalHazardReviewedRetryContract {
  if (!contract || typeof contract !== "object" || Array.isArray(contract)) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", "Reviewed retry contract is invalid");
  }
  if (contract.schema !== RETRY_CONTRACT_SCHEMA) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", "Reviewed retry contract schema is unsupported");
  }
  if (!(["explicit_alternative", "structured_delta"] as const).includes(contract.alternativeKind)) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", "Reviewed retry alternative kind is unsupported");
  }
  if (!profile.procedureVersionNodeId) {
    throw new OperationalHazardProfileError(
      "hazard_profile_invalid",
      "A reviewed retry contract requires an exact known-bad procedure version",
    );
  }
  const source = normalizeReviewedAttemptBinding(contract.source, "Reviewed source binding");
  const alternative = normalizeReviewedAttemptBinding(contract.alternative, "Reviewed alternative binding");
  const parametersApplicable = Object.entries(profile.normalizedParameters)
    .every(([key, value]) => Object.hasOwn(source.normalizedParameters, key)
      && source.normalizedParameters[key] === value);
  const loadApplicable = profile.loadMinimum === undefined
    || (source.load !== null && source.load >= profile.loadMinimum);
  const concurrencyApplicable = profile.concurrencyMinimum === undefined
    || (source.concurrency !== null && source.concurrency >= profile.concurrencyMinimum);
  const timingApplicable = profile.timingWindowMs === undefined
    || (source.timingWindowMs !== null && source.timingWindowMs <= profile.timingWindowMs);
  if (
    source.procedureNodeId !== profile.procedureNodeId
    || source.procedureVersionNodeId !== profile.procedureVersionNodeId
    || !parametersApplicable
    || !loadApplicable
    || !concurrencyApplicable
    || !timingApplicable
  ) {
    throw new OperationalHazardProfileError(
      "hazard_profile_retry_source_mismatch",
      "Reviewed retry contract source must be an exact observed binding inside the known-bad profile applicability boundary",
    );
  }
  if (contract.alternativeKind === "explicit_alternative") {
    if (
      !profile.alternativeProcedureNodeId
      || alternative.procedureNodeId !== profile.alternativeProcedureNodeId
      || alternative.procedureNodeId === source.procedureNodeId
    ) {
      throw new OperationalHazardProfileError(
        "hazard_profile_retry_alternative_mismatch",
        "Explicit safer alternative must exactly use the profile's different reviewed alternative procedure",
      );
    }
  } else if (
    alternative.procedureNodeId !== source.procedureNodeId
    || operationalHazardReviewedBindingFingerprint(alternative)
      === operationalHazardReviewedBindingFingerprint(source)
  ) {
    throw new OperationalHazardProfileError(
      "hazard_profile_retry_delta_invalid",
      "Structured safer delta must keep the reviewed procedure and change its exact version or execution parameters",
    );
  }
  if (!Array.isArray(contract.retryValidConditions)
    || contract.retryValidConditions.length !== profile.safeRetryGate.length
    || contract.retryValidConditions.length === 0) {
    throw new OperationalHazardProfileError(
      "hazard_profile_retry_conditions_mismatch",
      "Every safe-retry statement needs exactly one typed local-evidence condition",
    );
  }
  const conditionIds = new Set<string>();
  const evidenceKeys = new Set<string>();
  const retryValidConditions = contract.retryValidConditions.map((condition, index) => {
    if (!condition || typeof condition !== "object" || Array.isArray(condition)) {
      throw new OperationalHazardProfileError("hazard_profile_invalid", `Retry condition ${index} is invalid`);
    }
    const id = String(condition.id ?? "").trim();
    const evidenceKey = String(condition.evidenceKey ?? "").trim();
    const statement = normalizeText(String(condition.statement ?? ""), `retryValidConditions[${index}].statement`);
    if (!RETRY_CONDITION_KEY.test(id) || !RETRY_CONDITION_KEY.test(evidenceKey)) {
      throw new OperationalHazardProfileError(
        "hazard_profile_invalid",
        `Retry condition ${index} has an invalid ID or evidence key`,
      );
    }
    if (conditionIds.has(id) || evidenceKeys.has(evidenceKey)) {
      throw new OperationalHazardProfileError(
        "hazard_profile_invalid",
        "Retry condition IDs and evidence keys must be unique",
      );
    }
    if (statement !== profile.safeRetryGate[index]) {
      throw new OperationalHazardProfileError(
        "hazard_profile_retry_conditions_mismatch",
        "Typed retry conditions must exactly preserve the reviewed safe-retry statements and order",
      );
    }
    conditionIds.add(id);
    evidenceKeys.add(evidenceKey);
    return { id, statement, evidenceKey };
  });
  const normalized: OperationalHazardReviewedRetryContract = {
    schema: RETRY_CONTRACT_SCHEMA,
    alternativeKind: contract.alternativeKind,
    source,
    alternative,
    retryValidConditions,
  };
  assertFiniteJson(normalized, "reviewedRetryContract");
  return normalized;
}

function assertTimestamp(value: string, label: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", `${label} must be an ISO timestamp`);
  }
  return new Date(parsed).toISOString();
}

function optionalNumber(value: number | undefined, label: string, minimum: number): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isFinite(value) || value < minimum) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", `${label} is invalid`);
  }
  return value;
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", `${label} must be a positive integer`);
  }
  return value;
}

function normalizeProfile(input: OperationalHazardProfileInput): OperationalHazardProfileInput {
  const reproducibilityCount = positiveInteger(input.reproducibilityCount, "Reproducibility count");
  const attemptCount = positiveInteger(input.attemptCount, "Attempt count");
  if (attemptCount < reproducibilityCount) {
    throw new OperationalHazardProfileError(
      "hazard_profile_invalid",
      "Attempt count cannot be lower than reproducibility count",
    );
  }
  if (!Number.isFinite(input.confidence) || input.confidence < 0 || input.confidence > 1) {
    throw new OperationalHazardProfileError("hazard_profile_invalid", "Confidence must be between zero and one");
  }
  const recoveryCost = normalizeRecoveryCost(input.recoveryCost ?? {});
  const applicabilityConstraints = normalizeApplicabilityConstraints(input.applicabilityConstraints ?? {});
  assertFiniteJson(recoveryCost, "recoveryCost");
  assertFiniteJson(applicabilityConstraints, "applicabilityConstraints");
  const orderedSteps = normalizeTextList(input.orderedSteps, "orderedSteps");
  const normalizedParameters = normalizeParameters(input.normalizedParameters);
  const unsafeRetryConditions = normalizeTextList(input.unsafeRetryConditions, "unsafeRetryConditions");
  const safeRetryGate = normalizeTextList(input.safeRetryGate, "safeRetryGate");
  const alternativeSequence = normalizeTextList(
    input.alternativeSequence ?? [],
    "alternativeSequence",
    { allowEmpty: true },
  );
  assertReusableMemoryUnknown({
    orderedSteps,
    normalizedParameters,
    recoveryCost,
    unsafeRetryConditions,
    safeRetryGate,
    alternativeSequence,
    applicabilityConstraints,
  }, "operationalHazardProfile", REUSABLE_MEMORY_LIMITS.body);
  const procedureNodeId = assertId(input.procedureNodeId, "Procedure node ID");
  const procedureVersionNodeId = input.procedureVersionNodeId
    ? assertId(input.procedureVersionNodeId, "Procedure-version node ID")
    : undefined;
  const alternativeProcedureNodeId = input.alternativeProcedureNodeId
    ? assertId(input.alternativeProcedureNodeId, "Alternative-procedure node ID")
    : undefined;
  const reviewedRetryContract = input.reviewedRetryContract
    ? normalizeReviewedRetryContract(input.reviewedRetryContract, {
      procedureNodeId,
      ...(procedureVersionNodeId ? { procedureVersionNodeId } : {}),
      normalizedParameters,
      ...(input.loadMinimum === undefined ? {} : { loadMinimum: input.loadMinimum }),
      ...(input.concurrencyMinimum === undefined ? {} : { concurrencyMinimum: input.concurrencyMinimum }),
      ...(input.timingWindowMs === undefined ? {} : { timingWindowMs: input.timingWindowMs }),
      safeRetryGate,
      ...(alternativeProcedureNodeId ? { alternativeProcedureNodeId } : {}),
    })
    : undefined;
  return {
    hazardNodeId: assertId(input.hazardNodeId, "Hazard node ID"),
    procedureNodeId,
    ...(procedureVersionNodeId ? { procedureVersionNodeId } : {}),
    productNodeIds: normalizeIds(input.productNodeIds, "Product node ID"),
    versionNodeIds: normalizeIds(input.versionNodeIds, "Version node ID"),
    stackNodeIds: normalizeIds(input.stackNodeIds, "Stack node ID"),
    prerequisiteNodeIds: normalizeIds(input.prerequisiteNodeIds, "Prerequisite node ID"),
    observedStateNodeIds: normalizeIds(input.observedStateNodeIds ?? [], "Observed-state node ID"),
    orderedSteps,
    normalizedParameters,
    ...(optionalNumber(input.loadMinimum, "Load minimum", 0) === undefined
      ? {}
      : { loadMinimum: input.loadMinimum }),
    ...(input.concurrencyMinimum === undefined
      ? {}
      : { concurrencyMinimum: positiveInteger(input.concurrencyMinimum, "Concurrency minimum") }),
    ...(optionalNumber(input.timingWindowMs, "Timing window", 0) === undefined
      ? {}
      : { timingWindowMs: input.timingWindowMs }),
    observedSymptom: normalizeText(input.observedSymptom, "observedSymptom"),
    affectedComponent: normalizeText(input.affectedComponent, "affectedComponent"),
    stateBefore: normalizeText(input.stateBefore, "stateBefore"),
    stateAfter: normalizeText(input.stateAfter, "stateAfter"),
    ...(input.stateTransitionNodeId
      ? { stateTransitionNodeId: assertId(input.stateTransitionNodeId, "State-transition node ID") }
      : {}),
    reproducibilityCount,
    attemptCount,
    ...(input.recoveryPatternNodeId
      ? { recoveryPatternNodeId: assertId(input.recoveryPatternNodeId, "Recovery-pattern node ID") }
      : {}),
    recoveryActionSummary: normalizeText(input.recoveryActionSummary, "recoveryActionSummary"),
    recoveryCost,
    unsafeRetryConditions,
    safeRetryGate,
    alternativeSequence,
    ...(alternativeProcedureNodeId ? { alternativeProcedureNodeId } : {}),
    applicabilityConstraints,
    ...(reviewedRetryContract ? { reviewedRetryContract } : {}),
    confidence: input.confidence,
    observedAt: assertTimestamp(input.observedAt, "Observed time"),
    ...(input.freshUntil ? { freshUntil: assertTimestamp(input.freshUntil, "Fresh-until time") } : {}),
  };
}

function rowToProfile(row: ProfileRow): OperationalHazardProfile {
  return {
    hazardNodeId: row.node_id,
    procedureNodeId: row.procedure_node_id,
    ...(row.procedure_version_node_id ? { procedureVersionNodeId: row.procedure_version_node_id } : {}),
    productNodeIds: parseJson<readonly string[]>(row.product_node_ids_json, "Stored product node IDs"),
    versionNodeIds: parseJson<readonly string[]>(row.version_node_ids_json, "Stored version node IDs"),
    stackNodeIds: parseJson<readonly string[]>(row.stack_node_ids_json, "Stored stack node IDs"),
    prerequisiteNodeIds: parseJson<readonly string[]>(row.prerequisite_node_ids_json, "Stored prerequisite node IDs"),
    observedStateNodeIds: parseJson<readonly string[]>(row.observed_state_node_ids_json, "Stored state node IDs"),
    orderedSteps: parseJson<readonly string[]>(row.ordered_steps_json, "Stored ordered steps"),
    normalizedParameters: parseJson<Readonly<Record<string, Primitive>>>(row.normalized_parameters_json, "Stored normalized parameters"),
    ...(row.load_min === null ? {} : { loadMinimum: row.load_min }),
    ...(row.concurrency_min === null ? {} : { concurrencyMinimum: row.concurrency_min }),
    ...(row.timing_window_ms === null ? {} : { timingWindowMs: row.timing_window_ms }),
    observedSymptom: row.observed_symptom,
    affectedComponent: row.affected_component,
    stateBefore: row.state_before,
    stateAfter: row.state_after,
    ...(row.state_transition_node_id ? { stateTransitionNodeId: row.state_transition_node_id } : {}),
    reproducibilityCount: row.reproducibility_count,
    receiptBackedOccurrenceCount: row.receipt_backed_occurrence_count,
    attemptCount: row.attempt_count,
    ...(row.recovery_pattern_node_id ? { recoveryPatternNodeId: row.recovery_pattern_node_id } : {}),
    recoveryActionSummary: row.recovery_action_summary,
    recoveryCost: parseJson<OperationalHazardRecoveryCost>(row.recovery_cost_json, "Stored recovery cost"),
    unsafeRetryConditions: parseJson<readonly string[]>(row.unsafe_retry_conditions_json, "Stored unsafe conditions"),
    safeRetryGate: parseJson<readonly string[]>(row.safe_retry_gate_json, "Stored safe retry gate"),
    alternativeSequence: parseJson<readonly string[]>(row.alternative_sequence_json, "Stored alternative sequence"),
    ...(row.alternative_procedure_node_id ? { alternativeProcedureNodeId: row.alternative_procedure_node_id } : {}),
    applicabilityConstraints: parseJson<OperationalHazardApplicabilityConstraints>(row.applicability_constraints_json, "Stored applicability constraints"),
    ...(row.reviewed_retry_contract_json
      ? {
        reviewedRetryContract: parseJson<OperationalHazardReviewedRetryContract>(
          row.reviewed_retry_contract_json,
          "Stored reviewed retry contract",
        ),
      }
      : {}),
    confidence: row.confidence,
    observedAt: row.observed_at,
    ...(row.fresh_until ? { freshUntil: row.fresh_until } : {}),
    version: row.version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Persists generalized operational-hazard profiles. It accepts only global
 * attack-knowledge node IDs and sanitized execution characteristics; mission,
 * target, address, credential, raw-log, and raw-evidence fields do not exist
 * on this boundary.
 */
export class OperationalHazardProfileRepository {
  readonly #clock: () => Date;

  constructor(
    private readonly database: SqliteDatabase,
    options: { readonly clock?: () => Date } = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
  }

  get(hazardNodeId: string): OperationalHazardProfile | undefined {
    const row = this.database.prepare(
      "SELECT * FROM operational_hazard_profiles WHERE node_id = ?",
    ).get(assertId(hazardNodeId, "Hazard node ID")) as ProfileRow | undefined;
    return row ? rowToProfile(row) : undefined;
  }

  require(hazardNodeId: string): OperationalHazardProfile {
    const profile = this.get(hazardNodeId);
    if (!profile) {
      throw new OperationalHazardProfileError("hazard_profile_not_found", "Operational hazard profile was not found");
    }
    return profile;
  }

  create(rawInput: OperationalHazardProfileInput): OperationalHazardProfile {
    const input = normalizeProfile(rawInput);
    this.#assertReferences(input);
    const now = this.#clock().toISOString();
    const receiptBackedOccurrenceCount = this.#receiptBackedOccurrenceCount(input.hazardNodeId);
    try {
      this.database.prepare(`
        INSERT INTO operational_hazard_profiles (
          node_id, procedure_node_id, procedure_version_node_id,
          product_node_ids_json, version_node_ids_json, stack_node_ids_json,
          prerequisite_node_ids_json, observed_state_node_ids_json,
          ordered_steps_json, normalized_parameters_json, load_min,
          concurrency_min, timing_window_ms, observed_symptom,
          affected_component, state_before, state_after, state_transition_node_id,
          reproducibility_count, attempt_count, recovery_pattern_node_id,
          recovery_action_summary, recovery_cost_json,
          unsafe_retry_conditions_json, safe_retry_gate_json,
          alternative_sequence_json, alternative_procedure_node_id,
          applicability_constraints_json, reviewed_retry_contract_json,
          confidence, observed_at, fresh_until,
          receipt_backed_occurrence_count, version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
      `).run(...this.#parameters(input), receiptBackedOccurrenceCount, now, now);
    } catch (error) {
      if (error instanceof Error && /UNIQUE constraint failed/u.test(error.message)) {
        throw new OperationalHazardProfileError(
          "hazard_profile_exists",
          "An operational hazard profile already exists for this hazard node",
        );
      }
      throw error;
    }
    return this.require(input.hazardNodeId);
  }

  update(
    rawInput: OperationalHazardProfileInput,
    expectedVersion: number,
  ): OperationalHazardProfile {
    const input = normalizeProfile(rawInput);
    positiveInteger(expectedVersion, "Expected version");
    this.#assertReferences(input);
    const receiptBackedOccurrenceCount = this.#receiptBackedOccurrenceCount(input.hazardNodeId);
    const result = inImmediateTransaction(this.database, () => this.database.prepare(`
      UPDATE operational_hazard_profiles SET
        procedure_node_id = ?, procedure_version_node_id = ?,
        product_node_ids_json = ?, version_node_ids_json = ?,
        stack_node_ids_json = ?, prerequisite_node_ids_json = ?,
        observed_state_node_ids_json = ?, ordered_steps_json = ?,
        normalized_parameters_json = ?, load_min = ?, concurrency_min = ?,
        timing_window_ms = ?, observed_symptom = ?, affected_component = ?,
        state_before = ?, state_after = ?, state_transition_node_id = ?,
        reproducibility_count = ?, attempt_count = ?, recovery_pattern_node_id = ?,
        recovery_action_summary = ?, recovery_cost_json = ?,
        unsafe_retry_conditions_json = ?, safe_retry_gate_json = ?,
        alternative_sequence_json = ?, alternative_procedure_node_id = ?,
        applicability_constraints_json = ?, reviewed_retry_contract_json = ?,
        confidence = ?, observed_at = ?,
        fresh_until = ?, receipt_backed_occurrence_count = ?,
        version = version + 1, updated_at = ?
      WHERE node_id = ? AND version = ?
    `).run(
      ...this.#parameters(input).slice(1),
      receiptBackedOccurrenceCount,
      this.#clock().toISOString(),
      input.hazardNodeId,
      expectedVersion,
    ));
    if (result.changes !== 1) {
      throw new OperationalHazardProfileError(
        "hazard_profile_version_conflict",
        "Operational hazard profile changed; reload before updating it",
      );
    }
    return this.require(input.hazardNodeId);
  }

  #parameters(input: OperationalHazardProfileInput): readonly unknown[] {
    return [
      input.hazardNodeId,
      input.procedureNodeId,
      input.procedureVersionNodeId ?? null,
      canonicalJson(input.productNodeIds),
      canonicalJson(input.versionNodeIds),
      canonicalJson(input.stackNodeIds),
      canonicalJson(input.prerequisiteNodeIds),
      canonicalJson(input.observedStateNodeIds ?? []),
      canonicalJson(input.orderedSteps),
      canonicalJson(input.normalizedParameters),
      input.loadMinimum ?? null,
      input.concurrencyMinimum ?? null,
      input.timingWindowMs ?? null,
      input.observedSymptom,
      input.affectedComponent,
      input.stateBefore,
      input.stateAfter,
      input.stateTransitionNodeId ?? null,
      input.reproducibilityCount,
      input.attemptCount,
      input.recoveryPatternNodeId ?? null,
      input.recoveryActionSummary,
      canonicalJson(input.recoveryCost ?? {}),
      canonicalJson(input.unsafeRetryConditions),
      canonicalJson(input.safeRetryGate),
      canonicalJson(input.alternativeSequence ?? []),
      input.alternativeProcedureNodeId ?? null,
      canonicalJson(input.applicabilityConstraints ?? {}),
      input.reviewedRetryContract ? canonicalJson(input.reviewedRetryContract) : null,
      input.confidence,
      input.observedAt,
      input.freshUntil ?? null,
    ];
  }

  #receiptBackedOccurrenceCount(hazardNodeId: string): number {
    const row = this.database.prepare(`
      SELECT receipt_backed_occurrence_count
      FROM operational_hazard_receipt_backed_counts
      WHERE hazard_node_id = ?
    `).get(assertId(hazardNodeId, "Hazard node ID")) as {
      readonly receipt_backed_occurrence_count: number;
    } | undefined;
    const count = row?.receipt_backed_occurrence_count ?? 0;
    if (!Number.isSafeInteger(count) || count < 0) {
      throw new OperationalHazardProfileError(
        "hazard_profile_receipt_count_invalid",
        "The canonical receipt-backed hazard occurrence count is invalid",
      );
    }
    return count;
  }

  #assertReferences(input: OperationalHazardProfileInput): void {
    this.#assertNode(input.hazardNodeId, new Set(["operational_hazard"]), "hazard");
    this.#assertNode(input.procedureNodeId, new Set(["attack_procedure"]), "procedure");
    if (input.procedureVersionNodeId) {
      this.#assertNode(input.procedureVersionNodeId, new Set(["procedure_version"]), "procedure version");
    }
    input.productNodeIds.forEach((id) => this.#assertNode(id, new Set(["technology_product"]), "product"));
    input.versionNodeIds.forEach((id) => this.#assertNode(id, VERSION_TYPES, "version"));
    input.stackNodeIds.forEach((id) => this.#assertNode(id, STACK_TYPES, "stack"));
    input.prerequisiteNodeIds.forEach((id) => this.#assertNode(id, new Set(["prerequisite"]), "prerequisite"));
    (input.observedStateNodeIds ?? []).forEach((id) => this.#assertNode(id, OBSERVED_STATE_TYPES, "observed state"));
    if (input.stateTransitionNodeId) {
      this.#assertNode(input.stateTransitionNodeId, new Set(["target_state_transition"]), "state transition");
    }
    if (input.recoveryPatternNodeId) {
      this.#assertNode(input.recoveryPatternNodeId, new Set(["recovery_pattern"]), "recovery pattern");
    }
    if (input.alternativeProcedureNodeId) {
      this.#assertNode(input.alternativeProcedureNodeId, new Set(["attack_procedure"]), "alternative procedure");
    }
    if (input.reviewedRetryContract) {
      this.#assertNode(
        input.reviewedRetryContract.source.procedureNodeId,
        new Set(["attack_procedure"]),
        "reviewed retry source procedure",
      );
      this.#assertNode(
        input.reviewedRetryContract.source.procedureVersionNodeId,
        new Set(["procedure_version"]),
        "reviewed retry source procedure version",
      );
      this.#assertNode(
        input.reviewedRetryContract.alternative.procedureNodeId,
        new Set(["attack_procedure"]),
        "reviewed retry alternative procedure",
      );
      this.#assertNode(
        input.reviewedRetryContract.alternative.procedureVersionNodeId,
        new Set(["procedure_version"]),
        "reviewed retry alternative procedure version",
      );
    }
  }

  #assertNode(id: string, allowedTypes: ReadonlySet<MemoryNodeType>, label: string): NodeRow {
    const row = this.database.prepare(`
      SELECT id, node_type, scope, lifecycle_status FROM memory_nodes WHERE id = ?
    `).get(id) as NodeRow | undefined;
    if (
      !row
      || !allowedTypes.has(row.node_type)
      || row.scope !== "global"
      || !(["confirmed", "verified"] as readonly MemoryLifecycle[]).includes(row.lifecycle_status)
    ) {
      throw new OperationalHazardProfileError(
        "hazard_profile_reference_invalid",
        `Operational hazard ${label} must reference reviewed global attack-knowledge`,
      );
    }
    return row;
  }
}

import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { canonicalJson } from "../orchestration/serialization";
import { attackKnowledgeOperationalLocatorCategories } from "./AttackKnowledgeTaxonomy";
import type {
  MemoryLifecycle,
  MemoryNode,
  MemoryNodeType,
  OperationalHazardAssessment,
  OperationalHazardContext,
} from "./types";

const DEFAULT_BLOCK_CONFIDENCE = 0.85;
const DEFAULT_REPRODUCIBILITY_COUNT = 2;
const MAX_CONTEXT_NODE_IDS = 128;
const MAX_NORMALIZED_PARAMETERS = 64;
const MAX_PARAMETER_TEXT_BYTES = 512;

const STACK_NODE_TYPES: ReadonlySet<MemoryNodeType> = new Set([
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
const OBSERVED_STATE_NODE_TYPES: ReadonlySet<MemoryNodeType> = new Set([
  "target_state_transition",
  "health_check",
  "attribute",
]);

type Primitive = string | number | boolean;
type MatchKind = "exact" | "partial" | "mismatch";

const APPLICABILITY_CONSTRAINT_KEYS = [
  "requireExactProcedureVersion",
  "requireVerifiedVersionRelationship",
  "requireAllStackNodes",
  "requireAllPrerequisites",
  "requireObservedState",
] as const;

type ApplicabilityConstraintKey = typeof APPLICABILITY_CONSTRAINT_KEYS[number];
type ApplicabilityConstraints = Readonly<Partial<Record<ApplicabilityConstraintKey, boolean>>>;

interface MemoryNodeRow {
  readonly id: string;
  readonly node_type: MemoryNodeType;
  readonly scope: string;
  readonly confidence: number;
  readonly lifecycle_status: MemoryLifecycle;
  readonly expires_at: string | null;
}

interface VersionEdgeRow {
  readonly source_node_id: string;
  readonly target_node_id: string;
  readonly scope: string;
  readonly confidence: number;
  readonly lifecycle_status: MemoryLifecycle;
  readonly expires_at: string | null;
}

interface HazardRow {
  readonly node_id: string;
  readonly procedure_node_id: string;
  readonly procedure_version_node_id: string | null;
  readonly product_node_ids_json: string;
  readonly version_node_ids_json: string;
  readonly stack_node_ids_json: string;
  readonly prerequisite_node_ids_json: string;
  readonly observed_state_node_ids_json: string;
  readonly normalized_parameters_json: string;
  readonly load_min: number | null;
  readonly concurrency_min: number | null;
  readonly timing_window_ms: number | null;
  readonly unsafe_retry_conditions_json: string;
  readonly safe_retry_gate_json: string;
  readonly alternative_sequence_json: string;
  readonly applicability_constraints_json: string;
  readonly confidence: number;
  readonly reproducibility_count: number;
  readonly receipt_backed_occurrence_count: number;
  readonly attempt_count: number;
  readonly recovery_cost_json: string;
  readonly fresh_until: string | null;
  readonly hazard_node_type: MemoryNodeType;
  readonly hazard_scope: string;
  readonly hazard_confidence: number;
  readonly hazard_lifecycle_status: MemoryLifecycle;
  readonly hazard_confirmation_state: string;
  readonly hazard_expires_at: string | null;
  readonly procedure_node_type: MemoryNodeType;
  readonly procedure_scope: string;
  readonly procedure_confidence: number;
  readonly procedure_lifecycle_status: MemoryLifecycle;
  readonly procedure_expires_at: string | null;
  readonly procedure_version_node_type: MemoryNodeType | null;
  readonly procedure_version_scope: string | null;
  readonly procedure_version_confidence: number | null;
  readonly procedure_version_lifecycle_status: MemoryLifecycle | null;
  readonly procedure_version_expires_at: string | null;
}

interface KnowledgeContextRow {
  readonly attack_attempt_id: string;
  readonly procedure_node_id: string;
  readonly procedure_version_node_id: string | null;
  readonly product_node_ids_json: string;
  readonly version_node_ids_json: string;
  readonly stack_node_ids_json: string;
  readonly prerequisite_node_ids_json: string;
  readonly observed_state_node_ids_json: string;
  readonly normalized_parameters_json: string;
  readonly load: number | null;
  readonly concurrency: number | null;
  readonly timing_window_ms: number | null;
  readonly context_pack_id: string | null;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface AttackAttemptKnowledgeContext extends OperationalHazardContext {
  readonly attackAttemptId: string;
  readonly contextPackId?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface BindAttackAttemptKnowledgeContextInput extends OperationalHazardContext {
  readonly attackAttemptId: string;
}

export interface OperationalHazardMatcherOptions {
  readonly clock?: () => Date;
  readonly blockConfidence?: number;
  readonly minimumReproducibilityCount?: number;
}

export class OperationalHazardMatcherError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "OperationalHazardMatcherError";
  }
}

function parseJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new OperationalHazardMatcherError("hazard_profile_malformed", `${label} is malformed`);
  }
}

function parseStringArray(value: string, label: string): readonly string[] {
  const parsed = parseJson(value, label);
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string" || !item.trim())) {
    throw new OperationalHazardMatcherError("hazard_profile_malformed", `${label} must contain non-empty string IDs`);
  }
  return [...new Set(parsed.map((item) => (item as string).trim()))].sort();
}

function parseTextArray(value: string, label: string): readonly string[] {
  const parsed = parseJson(value, label);
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string" || !item.trim())) {
    throw new OperationalHazardMatcherError("hazard_profile_malformed", `${label} must contain non-empty text entries`);
  }
  const normalized = [...new Set(parsed.map((item) => (item as string).trim()))].sort();
  const unsafe = normalized.flatMap(attackKnowledgeOperationalLocatorCategories);
  if (unsafe.length > 0) {
    throw new OperationalHazardMatcherError(
      "hazard_profile_contains_operational_locator",
      `${label} contains private operational locators: ${[...new Set(unsafe)].sort().join(", ")}`,
    );
  }
  return normalized;
}

function parsePrimitiveRecord(value: string, label: string): Readonly<Record<string, Primitive>> {
  const parsed = parseJson(value, label);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new OperationalHazardMatcherError("hazard_profile_malformed", `${label} must be an object`);
  }
  const entries = Object.entries(parsed as Record<string, unknown>);
  if (entries.some(([key, item]) => !key.trim() || !["string", "number", "boolean"].includes(typeof item))) {
    throw new OperationalHazardMatcherError("hazard_profile_malformed", `${label} contains unsupported values`);
  }
  return Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right))) as Record<string, Primitive>;
}

function parseObject(value: string, label: string): Readonly<Record<string, unknown>> {
  const parsed = parseJson(value, label);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new OperationalHazardMatcherError("hazard_profile_malformed", `${label} must be an object`);
  }
  return parsed as Readonly<Record<string, unknown>>;
}

function parseApplicabilityConstraints(
  value: string,
  label: string,
): { readonly constraints: ApplicabilityConstraints; readonly hasUnsupportedConstraint: boolean } {
  const parsed = parseObject(value, label);
  const allowed = new Set<string>(APPLICABILITY_CONSTRAINT_KEYS);
  const constraints: Partial<Record<ApplicabilityConstraintKey, boolean>> = {};
  let hasUnsupportedConstraint = false;
  for (const [key, item] of Object.entries(parsed).sort(([left], [right]) => left.localeCompare(right))) {
    if (!allowed.has(key) || typeof item !== "boolean") {
      // Imported or older rows may contain constraints unknown to this matcher.
      // They can inform a warning, but can never be treated as an exact match.
      hasUnsupportedConstraint = true;
      continue;
    }
    constraints[key as ApplicabilityConstraintKey] = item;
  }
  return { constraints, hasUnsupportedConstraint };
}

function assertId(value: string, label: string): string {
  const normalized = value.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(normalized)) {
    throw new OperationalHazardMatcherError("attack_knowledge_context_invalid", `${label} is invalid`);
  }
  return normalized;
}

function normalizeNodeIds(values: readonly string[], label: string): readonly string[] {
  if (!Array.isArray(values) || values.length > MAX_CONTEXT_NODE_IDS) {
    throw new OperationalHazardMatcherError(
      "attack_knowledge_context_invalid",
      `${label} exceeds the bounded node selection`,
    );
  }
  return [...new Set(values.map((value) => assertId(value, label)))].sort();
}

function normalizeParameters(
  value: Readonly<Record<string, Primitive>>,
): Readonly<Record<string, Primitive>> {
  const entries = Object.entries(value);
  if (entries.length > MAX_NORMALIZED_PARAMETERS) {
    throw new OperationalHazardMatcherError(
      "attack_knowledge_context_invalid",
      "Normalized parameters exceed the bounded field count",
    );
  }
  const normalized: Record<string, Primitive> = {};
  for (const [rawKey, rawValue] of entries.sort(([left], [right]) => left.localeCompare(right))) {
    const key = rawKey.trim().normalize("NFKC");
    if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(key)) {
      throw new OperationalHazardMatcherError("attack_knowledge_context_invalid", "Normalized parameter name is invalid");
    }
    if (typeof rawValue === "number" && !Number.isFinite(rawValue)) {
      throw new OperationalHazardMatcherError("attack_knowledge_context_invalid", "Normalized parameter number is invalid");
    }
    const value = typeof rawValue === "string" ? rawValue.trim().normalize("NFKC") : rawValue;
    if (typeof value === "string") {
      if (!value || Buffer.byteLength(value, "utf8") > MAX_PARAMETER_TEXT_BYTES) {
        throw new OperationalHazardMatcherError("attack_knowledge_context_invalid", "Normalized parameter text is invalid");
      }
      const locators = attackKnowledgeOperationalLocatorCategories(`${key} ${value}`);
      if (locators.length > 0) {
        throw new OperationalHazardMatcherError(
          "attack_knowledge_context_contains_operational_locator",
          `Reusable attack context contains private operational locators: ${locators.join(", ")}`,
        );
      }
    }
    normalized[key] = value;
  }
  return normalized;
}

function optionalNumber(value: number | undefined, label: string, minimum: number): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isFinite(value) || value < minimum) {
    throw new OperationalHazardMatcherError("attack_knowledge_context_invalid", `${label} is invalid`);
  }
  return value;
}

function optionalInteger(value: number | undefined, label: string, minimum: number): number | undefined {
  const normalized = optionalNumber(value, label, minimum);
  if (normalized !== undefined && !Number.isSafeInteger(normalized)) {
    throw new OperationalHazardMatcherError("attack_knowledge_context_invalid", `${label} must be an integer`);
  }
  return normalized;
}

function setMatch(required: readonly string[], actual: readonly string[]): MatchKind {
  if (required.length === 0) return "exact";
  if (actual.length === 0) return "partial";
  const actualSet = new Set(actual);
  if (required.every((id) => actualSet.has(id))) return "exact";
  if (required.some((id) => actualSet.has(id))) return "partial";
  return "mismatch";
}

function parameterMatch(
  required: Readonly<Record<string, Primitive>>,
  actual: Readonly<Record<string, Primitive>>,
): MatchKind {
  let partial = false;
  for (const [key, value] of Object.entries(required)) {
    if (!(key in actual)) {
      partial = true;
      continue;
    }
    if (actual[key] !== value) return "mismatch";
  }
  return partial ? "partial" : "exact";
}

function thresholdMatch(
  required: number | null,
  actual: number | undefined,
  direction: "minimum" | "maximum",
): MatchKind {
  if (required === null) return "exact";
  if (actual === undefined) return "partial";
  return direction === "minimum"
    ? (actual >= required ? "exact" : "mismatch")
    : (actual <= required ? "exact" : "mismatch");
}

function isFresh(timestamp: string | null, now: Date): boolean {
  if (!timestamp) return true;
  const parsed = Date.parse(timestamp);
  return Number.isFinite(parsed) && parsed > now.getTime();
}

function isVerifiedReusableNode(input: {
  readonly nodeType: MemoryNodeType | null;
  readonly expectedType: MemoryNodeType;
  readonly scope: string | null;
  readonly lifecycle: MemoryLifecycle | null;
  readonly confidence: number | null;
  readonly expiresAt: string | null;
}, now: Date, minimumConfidence: number): boolean {
  return input.nodeType === input.expectedType
    && input.scope === "global"
    && input.lifecycle === "verified"
    && (input.confidence ?? 0) >= minimumConfidence
    && isFresh(input.expiresAt, now);
}

function mergeMatch(left: MatchKind, right: MatchKind): MatchKind {
  if (left === "mismatch" || right === "mismatch") return "mismatch";
  if (left === "partial" || right === "partial") return "partial";
  return "exact";
}

function normalizedContext(input: OperationalHazardContext): OperationalHazardContext {
  return {
    procedureNodeId: assertId(input.procedureNodeId, "Procedure node ID"),
    ...(input.procedureVersionNodeId
      ? { procedureVersionNodeId: assertId(input.procedureVersionNodeId, "Procedure-version node ID") }
      : {}),
    productNodeIds: normalizeNodeIds(input.productNodeIds, "Product node ID"),
    versionNodeIds: normalizeNodeIds(input.versionNodeIds, "Version node ID"),
    stackNodeIds: normalizeNodeIds(input.stackNodeIds, "Stack node ID"),
    prerequisiteNodeIds: normalizeNodeIds(input.prerequisiteNodeIds, "Prerequisite node ID"),
    observedStateNodeIds: normalizeNodeIds(input.observedStateNodeIds ?? [], "Observed-state node ID"),
    normalizedParameters: normalizeParameters(input.normalizedParameters),
    ...(optionalNumber(input.load, "Load", 0) === undefined ? {} : { load: input.load }),
    ...(optionalInteger(input.concurrency, "Concurrency", 1) === undefined ? {} : { concurrency: input.concurrency }),
    ...(optionalInteger(input.timingWindowMs, "Timing window", 0) === undefined
      ? {}
      : { timingWindowMs: input.timingWindowMs }),
  };
}

function rowContext(row: KnowledgeContextRow): AttackAttemptKnowledgeContext {
  return {
    attackAttemptId: row.attack_attempt_id,
    procedureNodeId: row.procedure_node_id,
    ...(row.procedure_version_node_id ? { procedureVersionNodeId: row.procedure_version_node_id } : {}),
    productNodeIds: parseStringArray(row.product_node_ids_json, "Stored product context"),
    versionNodeIds: parseStringArray(row.version_node_ids_json, "Stored version context"),
    stackNodeIds: parseStringArray(row.stack_node_ids_json, "Stored stack context"),
    prerequisiteNodeIds: parseStringArray(row.prerequisite_node_ids_json, "Stored prerequisite context"),
    observedStateNodeIds: parseStringArray(row.observed_state_node_ids_json, "Stored observed-state context"),
    normalizedParameters: parsePrimitiveRecord(row.normalized_parameters_json, "Stored normalized parameters"),
    ...(row.load === null ? {} : { load: row.load }),
    ...(row.concurrency === null ? {} : { concurrency: row.concurrency }),
    ...(row.timing_window_ms === null ? {} : { timingWindowMs: row.timing_window_ms }),
    ...(row.context_pack_id ? { contextPackId: row.context_pack_id } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Trusted local matcher for reusable operational hazards. It does not invoke
 * a provider, infer procedure identity from a target/name, or broaden scope.
 */
export class OperationalHazardMatcher {
  readonly #clock: () => Date;
  readonly #blockConfidence: number;
  readonly #minimumReproducibilityCount: number;

  constructor(
    private readonly database: SqliteDatabase,
    options: OperationalHazardMatcherOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#blockConfidence = options.blockConfidence ?? DEFAULT_BLOCK_CONFIDENCE;
    this.#minimumReproducibilityCount = options.minimumReproducibilityCount ?? DEFAULT_REPRODUCIBILITY_COUNT;
    if (this.#blockConfidence < 0 || this.#blockConfidence > 1) {
      throw new RangeError("Operational-hazard block confidence must be between zero and one");
    }
    if (!Number.isSafeInteger(this.#minimumReproducibilityCount) || this.#minimumReproducibilityCount < 2) {
      throw new RangeError("Operational-hazard reproducibility threshold must be at least two");
    }
  }

  bindAttackAttempt(input: BindAttackAttemptKnowledgeContextInput): AttackAttemptKnowledgeContext {
    const attackAttemptId = assertId(input.attackAttemptId, "Attack-attempt ID");
    const context = normalizedContext(input);
    this.#assertAttemptExists(attackAttemptId);
    this.#assertNodeType(context.procedureNodeId, new Set(["attack_procedure"]), "procedure");
    if (context.procedureVersionNodeId) {
      this.#assertNodeType(context.procedureVersionNodeId, new Set(["procedure_version"]), "procedure version");
    }
    this.#assertNodeList(context.productNodeIds, new Set(["technology_product"]), "product");
    this.#assertNodeList(context.versionNodeIds, new Set(["exact_version_fingerprint"]), "version");
    this.#assertNodeList(context.stackNodeIds, STACK_NODE_TYPES, "stack");
    this.#assertNodeList(context.prerequisiteNodeIds, new Set(["prerequisite"]), "prerequisite");
    this.#assertNodeList(context.observedStateNodeIds ?? [], OBSERVED_STATE_NODE_TYPES, "observed state");
    const now = this.#clock().toISOString();
    inImmediateTransaction(this.database, () => {
      const desired = {
        procedure_node_id: context.procedureNodeId,
        procedure_version_node_id: context.procedureVersionNodeId ?? null,
        product_node_ids_json: canonicalJson(context.productNodeIds),
        version_node_ids_json: canonicalJson(context.versionNodeIds),
        stack_node_ids_json: canonicalJson(context.stackNodeIds),
        prerequisite_node_ids_json: canonicalJson(context.prerequisiteNodeIds),
        observed_state_node_ids_json: canonicalJson(context.observedStateNodeIds ?? []),
        normalized_parameters_json: canonicalJson(context.normalizedParameters),
        load: context.load ?? null,
        concurrency: context.concurrency ?? null,
        timing_window_ms: context.timingWindowMs ?? null,
      };
      const existing = this.database.prepare(`
        SELECT procedure_node_id, procedure_version_node_id,
          product_node_ids_json, version_node_ids_json, stack_node_ids_json,
          prerequisite_node_ids_json, observed_state_node_ids_json,
          normalized_parameters_json, load, concurrency, timing_window_ms
        FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = ?
      `).get(attackAttemptId) as typeof desired | undefined;
      if (existing) {
        if (canonicalJson(existing) !== canonicalJson(desired)) {
          throw new OperationalHazardMatcherError(
            "attack_knowledge_binding_immutable",
            "Attack-attempt knowledge is immutable; create a new represented attempt for a different procedure, version, or parameter set",
          );
        }
        return;
      }
      this.database.prepare(`
        INSERT INTO attack_attempt_knowledge_contexts (
          attack_attempt_id, procedure_node_id, procedure_version_node_id,
          product_node_ids_json, version_node_ids_json, stack_node_ids_json,
          prerequisite_node_ids_json, observed_state_node_ids_json,
          normalized_parameters_json, load, concurrency, timing_window_ms,
          context_pack_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
      `).run(
        attackAttemptId,
        desired.procedure_node_id,
        desired.procedure_version_node_id,
        desired.product_node_ids_json,
        desired.version_node_ids_json,
        desired.stack_node_ids_json,
        desired.prerequisite_node_ids_json,
        desired.observed_state_node_ids_json,
        desired.normalized_parameters_json,
        desired.load,
        desired.concurrency,
        desired.timing_window_ms,
        now,
        now,
      );
    });
    return this.requireAttackAttemptContext(attackAttemptId);
  }

  getAttackAttemptContext(attackAttemptId: string): AttackAttemptKnowledgeContext | undefined {
    const row = this.database.prepare(`
      SELECT * FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = ?
    `).get(assertId(attackAttemptId, "Attack-attempt ID")) as KnowledgeContextRow | undefined;
    return row ? rowContext(row) : undefined;
  }

  requireAttackAttemptContext(attackAttemptId: string): AttackAttemptKnowledgeContext {
    const context = this.getAttackAttemptContext(attackAttemptId);
    if (!context) {
      throw new OperationalHazardMatcherError(
        "attack_procedure_knowledge_required",
        "The first-class attack attempt has no exact reusable procedure binding",
      );
    }
    return context;
  }

  attachContextPack(attackAttemptId: string, contextPackId: string): AttackAttemptKnowledgeContext {
    const result = this.database.prepare(`
      UPDATE attack_attempt_knowledge_contexts
      SET context_pack_id = ?, updated_at = ?
      WHERE attack_attempt_id = ?
    `).run(
      assertId(contextPackId, "Context Pack ID"),
      this.#clock().toISOString(),
      assertId(attackAttemptId, "Attack-attempt ID"),
    );
    if (result.changes !== 1) {
      throw new OperationalHazardMatcherError(
        "attack_procedure_knowledge_required",
        "The first-class attack attempt has no exact reusable procedure binding",
      );
    }
    return this.requireAttackAttemptContext(attackAttemptId);
  }

  assessAttackAttempt(attackAttemptId: string): OperationalHazardAssessment | undefined {
    const context = this.getAttackAttemptContext(attackAttemptId);
    return context ? this.assess(context) : undefined;
  }

  assess(rawContext: OperationalHazardContext): OperationalHazardAssessment {
    const context = normalizedContext(rawContext);
    const now = this.#clock();
    const rows = this.database.prepare(`
      SELECT
        hp.*,
        hazard.node_type AS hazard_node_type,
        hazard.scope AS hazard_scope,
        hazard.confidence AS hazard_confidence,
        hazard.lifecycle_status AS hazard_lifecycle_status,
        hazard.confirmation_state AS hazard_confirmation_state,
        hazard.expires_at AS hazard_expires_at,
        procedure.node_type AS procedure_node_type,
        procedure.scope AS procedure_scope,
        procedure.confidence AS procedure_confidence,
        procedure.lifecycle_status AS procedure_lifecycle_status,
        procedure.expires_at AS procedure_expires_at,
        procedure_version.node_type AS procedure_version_node_type,
        procedure_version.scope AS procedure_version_scope,
        procedure_version.confidence AS procedure_version_confidence,
        procedure_version.lifecycle_status AS procedure_version_lifecycle_status,
        procedure_version.expires_at AS procedure_version_expires_at
      FROM operational_hazard_profiles hp
      JOIN memory_nodes hazard ON hazard.id = hp.node_id
      JOIN memory_nodes procedure ON procedure.id = hp.procedure_node_id
      LEFT JOIN memory_nodes procedure_version ON procedure_version.id = hp.procedure_version_node_id
      WHERE hp.procedure_node_id = ?
      ORDER BY hp.node_id
    `).all(context.procedureNodeId) as HazardRow[];

    const candidates: Array<{
      readonly row: HazardRow;
      readonly match: Exclude<MatchKind, "mismatch">;
      readonly verifiedForBlock: boolean;
    }> = [];
    for (const row of rows) {
      let match: MatchKind = "exact";
      if (row.procedure_version_node_id) {
        match = !context.procedureVersionNodeId
          ? "partial"
          : context.procedureVersionNodeId === row.procedure_version_node_id
            ? match
            : "mismatch";
      }
      const productNodeIds = parseStringArray(row.product_node_ids_json, `Hazard ${row.node_id} products`);
      const versionNodeIds = parseStringArray(row.version_node_ids_json, `Hazard ${row.node_id} versions`);
      const stackNodeIds = parseStringArray(row.stack_node_ids_json, `Hazard ${row.node_id} stack`);
      const prerequisiteNodeIds = parseStringArray(
        row.prerequisite_node_ids_json,
        `Hazard ${row.node_id} prerequisites`,
      );
      const observedStateNodeIds = parseStringArray(
        row.observed_state_node_ids_json,
        `Hazard ${row.node_id} observed states`,
      );
      const productMatch = setMatch(productNodeIds, context.productNodeIds);
      match = mergeMatch(match, productMatch);
      const versionMatch = this.#versionMatch(versionNodeIds, context.versionNodeIds, now);
      match = mergeMatch(match, versionMatch.match);
      const stackMatch = setMatch(stackNodeIds, context.stackNodeIds);
      const prerequisiteMatch = setMatch(prerequisiteNodeIds, context.prerequisiteNodeIds);
      const observedStateMatch = setMatch(observedStateNodeIds, context.observedStateNodeIds ?? []);
      match = mergeMatch(match, stackMatch);
      match = mergeMatch(match, prerequisiteMatch);
      match = mergeMatch(match, observedStateMatch);
      match = mergeMatch(match, parameterMatch(
        normalizeParameters(parsePrimitiveRecord(
          row.normalized_parameters_json,
          `Hazard ${row.node_id} normalized parameters`,
        )),
        context.normalizedParameters,
      ));
      match = mergeMatch(match, thresholdMatch(row.load_min, context.load, "minimum"));
      match = mergeMatch(match, thresholdMatch(row.concurrency_min, context.concurrency, "minimum"));
      match = mergeMatch(match, thresholdMatch(row.timing_window_ms, context.timingWindowMs, "maximum"));
      const applicability = parseApplicabilityConstraints(
        row.applicability_constraints_json,
        `Hazard ${row.node_id} applicability constraints`,
      );
      if (applicability.hasUnsupportedConstraint) {
        match = mergeMatch(match, "partial");
      }
      const constraints = applicability.constraints;
      if (constraints.requireExactProcedureVersion) {
        match = mergeMatch(
          match,
          row.procedure_version_node_id && context.procedureVersionNodeId
            ? "exact"
            : "partial",
        );
      }
      if (constraints.requireVerifiedVersionRelationship) {
        match = mergeMatch(
          match,
          versionNodeIds.length > 0 && context.versionNodeIds.length > 0 && versionMatch.verifiedForBlock
            ? "exact"
            : "partial",
        );
      }
      if (constraints.requireAllStackNodes) {
        match = mergeMatch(match, stackNodeIds.length > 0 ? stackMatch : "partial");
      }
      if (constraints.requireAllPrerequisites) {
        match = mergeMatch(match, prerequisiteNodeIds.length > 0 ? prerequisiteMatch : "partial");
      }
      if (constraints.requireObservedState) {
        match = mergeMatch(match, observedStateNodeIds.length > 0 ? observedStateMatch : "partial");
      }
      if (match === "mismatch") continue;

      const verifiedForBlock = match === "exact"
        && isVerifiedReusableNode({
          nodeType: row.hazard_node_type,
          expectedType: "operational_hazard",
          scope: row.hazard_scope,
          lifecycle: row.hazard_lifecycle_status,
          confidence: row.hazard_confidence,
          expiresAt: row.hazard_expires_at,
        }, now, this.#blockConfidence)
        && isVerifiedReusableNode({
          nodeType: row.procedure_node_type,
          expectedType: "attack_procedure",
          scope: row.procedure_scope,
          lifecycle: row.procedure_lifecycle_status,
          confidence: row.procedure_confidence,
          expiresAt: row.procedure_expires_at,
        }, now, this.#blockConfidence)
        && (!row.procedure_version_node_id || isVerifiedReusableNode({
          nodeType: row.procedure_version_node_type,
          expectedType: "procedure_version",
          scope: row.procedure_version_scope,
          lifecycle: row.procedure_version_lifecycle_status,
          confidence: row.procedure_version_confidence,
          expiresAt: row.procedure_version_expires_at,
        }, now, this.#blockConfidence))
        && row.confidence >= this.#blockConfidence
        // Recovery-cost metadata is descriptive knowledge, not proof that a
        // physical reset occurred. One locally attested reset occurrence is
        // authoritative; otherwise the ordinary repeated-outcome threshold
        // remains mandatory. Never infer this from caller-supplied resetCount.
        && (
          row.receipt_backed_occurrence_count >= 1
          || row.reproducibility_count >= this.#minimumReproducibilityCount
        )
        && isFresh(row.fresh_until, now)
        && this.#nodesVerified(productNodeIds, new Set(["technology_product"]), now)
        && versionMatch.verifiedForBlock
        && this.#nodesVerified(
          versionNodeIds,
          new Set(["exact_version_fingerprint", "version_range_fingerprint"]),
          now,
        )
        && this.#nodesVerified(context.versionNodeIds, new Set(["exact_version_fingerprint"]), now)
        && this.#nodesVerified(stackNodeIds, STACK_NODE_TYPES, now)
        && this.#nodesVerified(prerequisiteNodeIds, new Set(["prerequisite"]), now)
        && this.#nodesVerified(observedStateNodeIds, OBSERVED_STATE_NODE_TYPES, now);
      candidates.push({ row, match, verifiedForBlock });
    }

    candidates.sort((left, right) => {
      const leftRank = left.verifiedForBlock ? 0 : left.match === "exact" ? 1 : 2;
      const rightRank = right.verifiedForBlock ? 0 : right.match === "exact" ? 1 : 2;
      return leftRank - rightRank
        || right.row.confidence - left.row.confidence
        || right.row.reproducibility_count - left.row.reproducibility_count
        || left.row.node_id.localeCompare(right.row.node_id);
    });
    const blocking = candidates.filter((candidate) => candidate.verifiedForBlock);
    const values = (column: "unsafe_retry_conditions_json" | "safe_retry_gate_json" | "alternative_sequence_json") =>
      [...new Set(candidates.flatMap(({ row }) => parseTextArray(
        row[column],
        `Hazard ${row.node_id} ${column}`,
      )))];
    const unsafeRetryConditions = values("unsafe_retry_conditions_json");
    const safeRetryGate = values("safe_retry_gate_json");
    const saferKnownSequence = values("alternative_sequence_json");
    const decision: OperationalHazardAssessment["decision"] = blocking.length > 0
      ? "block"
      : candidates.length > 0
        ? "warn"
        : "allow";
    const warning = decision === "block"
      ? "A verified, fresh hazard with repeated reproduction matches this procedure and execution context. Automatic execution and blind retry are stopped until the represented health gate is satisfied."
      : decision === "warn"
        ? "Related failure knowledge exists, but its applicability is incomplete, stale, unverified, insufficiently reproduced, or below the configured confidence threshold. Review it without treating it as proof."
        : undefined;
    return {
      decision,
      matchedHazardNodeIds: candidates.map((candidate) => candidate.row.node_id),
      blockedProcedureNodeIds: [...new Set(blocking.map((candidate) => candidate.row.procedure_node_id))],
      ...(warning ? { warning } : {}),
      checklist: safeRetryGate,
      saferKnownSequence,
      unsafeRetryConditions,
      healthGate: safeRetryGate,
      safeRetryGate,
    };
  }

  #assertAttemptExists(id: string): void {
    if (!this.database.prepare("SELECT id FROM attack_attempts WHERE id = ?").get(id)) {
      throw new OperationalHazardMatcherError("attack_attempt_not_found", `Attack attempt not found: ${id}`);
    }
  }

  #assertNodeList(ids: readonly string[], allowed: ReadonlySet<MemoryNodeType>, label: string): void {
    for (const id of ids) this.#assertNodeType(id, allowed, label);
  }

  #nodesVerified(ids: readonly string[], allowed: ReadonlySet<MemoryNodeType>, now: Date): boolean {
    for (const id of ids) {
      const row = this.database.prepare(`
        SELECT id, node_type, scope, confidence, lifecycle_status, expires_at
        FROM memory_nodes WHERE id = ?
      `).get(id) as MemoryNodeRow | undefined;
      if (
        !row
        || !allowed.has(row.node_type)
        || row.scope !== "global"
        || row.lifecycle_status !== "verified"
        || row.confidence < this.#blockConfidence
        || !isFresh(row.expires_at, now)
      ) return false;
    }
    return true;
  }

  #versionMatch(
    required: readonly string[],
    observedExactVersions: readonly string[],
    now: Date,
  ): { readonly match: MatchKind; readonly verifiedForBlock: boolean } {
    if (required.length === 0) return { match: "exact", verifiedForBlock: true };
    if (observedExactVersions.length === 0) return { match: "partial", verifiedForBlock: false };
    let match: MatchKind = "exact";
    let verifiedForBlock = true;
    for (const requiredId of required) {
      const node = this.database.prepare(`
        SELECT id, node_type, scope, confidence, lifecycle_status, expires_at
        FROM memory_nodes WHERE id = ?
      `).get(requiredId) as MemoryNodeRow | undefined;
      if (!node || !["exact_version_fingerprint", "version_range_fingerprint"].includes(node.node_type)) {
        throw new OperationalHazardMatcherError(
          "hazard_profile_malformed",
          `Hazard version reference ${requiredId} is not an exact or range fingerprint`,
        );
      }
      if (node.node_type === "exact_version_fingerprint") {
        if (!observedExactVersions.includes(requiredId)) {
          return { match: "mismatch", verifiedForBlock: false };
        }
        continue;
      }
      const placeholders = observedExactVersions.map(() => "?").join(",");
      const edges = this.database.prepare(`
        SELECT source_node_id, target_node_id, scope, confidence,
          lifecycle_status, expires_at
        FROM memory_edges_safe
        WHERE edge_type = 'version_in_range'
          AND target_node_id = ?
          AND source_node_id IN (${placeholders})
        ORDER BY confidence DESC, source_node_id, target_node_id
      `).all(requiredId, ...observedExactVersions) as VersionEdgeRow[];
      const verified = edges.some((edge) => edge.scope === "global"
        && edge.lifecycle_status === "verified"
        && edge.confidence >= this.#blockConfidence
        && isFresh(edge.expires_at, now));
      if (!verified) {
        // A range title or body is never parsed to guess applicability. The
        // absence of a verified version_in_range edge leaves only a visible
        // uncertainty warning and can never authorize a block or action.
        match = mergeMatch(match, "partial");
        verifiedForBlock = false;
      }
    }
    return { match, verifiedForBlock };
  }

  #assertNodeType(id: string, allowed: ReadonlySet<MemoryNodeType>, label: string): MemoryNodeRow {
    const row = this.database.prepare(`
      SELECT id, node_type, scope, confidence, lifecycle_status, expires_at
      FROM memory_nodes WHERE id = ?
    `).get(id) as MemoryNodeRow | undefined;
    if (!row || !allowed.has(row.node_type) || row.scope !== "global" || row.lifecycle_status === "forgotten") {
      throw new OperationalHazardMatcherError(
        "attack_knowledge_context_type_invalid",
        `Attack-attempt ${label} binding must reference an active global attack-centric memory node`,
      );
    }
    return row;
  }
}

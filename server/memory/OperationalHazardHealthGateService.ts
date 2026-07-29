import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import type { OperationalActor } from "../intelligence-v24/types";
import type { DurableAction } from "../orchestration";
import { canonicalJson, hashJson } from "../orchestration/serialization";
import { OperationalHazardMatcher } from "./OperationalHazardMatcher";
import {
  operationalHazardReviewedBindingFingerprint,
  operationalHazardRetryContractHash,
  type OperationalHazardReviewedAttemptBinding,
  type OperationalHazardReviewedRetryContract,
} from "./OperationalHazardProfileRepository";

const SHA256 = /^[a-f0-9]{64}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const HEALTH_ACTION_TYPE = "operational_hazard_health_check";
const DEFAULT_ASSESSMENT_TTL_MS = 15 * 60_000;
const DEFAULT_AUTHORIZATION_TTL_MS = 10 * 60_000;
const MAX_TTL_MS = 60 * 60_000;
const LOCAL_EVALUATOR_VERSION = "operational-hazard-health/v2";
const LOCAL_EVALUATOR_HASH = "a5deb63c76404c368d0fd360cf7240786031399416329467e6daf9d10447af14";
const LOCAL_HEALTH_EVIDENCE_SCHEMA = "ti_scale.operational_health/v2";

type Primitive = string | number | boolean;
type HealthResult = "pass" | "fail";
type AuthorizationBasis = "distinct_procedure_version" | "distinct_parameters" | "explicit_alternative";

interface HazardProfileRow {
  readonly node_id: string;
  readonly procedure_node_id: string;
  readonly procedure_version_node_id: string | null;
  readonly alternative_procedure_node_id: string | null;
  readonly safe_retry_gate_json: string;
  readonly reviewed_retry_contract_json: string | null;
  readonly reproducibility_count: number;
  readonly attempt_count: number;
  readonly recovery_cost_json: string;
  readonly version: number;
  readonly confidence: number;
  readonly fresh_until: string | null;
}

interface AttemptScopeRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly step_id: string | null;
  readonly target_asset_id: string | null;
  readonly target_service_id: string | null;
  readonly recovery_source_attack_attempt_id: string | null;
  readonly action_class: string;
  readonly status: string;
  readonly engagement_id: string | null;
  readonly scope_json: string;
}

interface KnowledgeRow {
  readonly attack_attempt_id: string;
  readonly procedure_node_id: string;
  readonly procedure_version_node_id: string | null;
  readonly normalized_parameters_json: string;
  readonly load: number | null;
  readonly concurrency: number | null;
  readonly timing_window_ms: number | null;
}

interface ActionBindingRow {
  readonly attack_attempt_id: string;
  readonly action_type: string;
  readonly action_class: string;
  readonly normalized_arguments_json: string;
  readonly scoped_target: string;
  readonly binding_hash: string;
}

interface HealthAssessmentRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly hazard_node_id: string;
  readonly hazard_profile_version: number;
  readonly blocked_attack_attempt_id: string;
  readonly procedure_node_id: string;
  readonly procedure_version_node_id: string;
  readonly source_target_asset_id: string | null;
  readonly source_target_service_id: string | null;
  readonly target_context_fingerprint: string;
  readonly represented_health_check_action_id: string;
  readonly verified_evidence_id: string;
  readonly verified_evidence_hash: string;
  readonly evaluator_version: string;
  readonly evaluator_hash: string;
  readonly context_pack_id: string;
  readonly result: HealthResult;
  readonly exact_procedure_attempt_count: number;
  readonly exact_procedure_reproducibility_count: number;
  readonly exact_procedure_reset_count: number;
  readonly operator_reported_reset_count_minimum: number | null;
  readonly recovery_cost_json: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly assessment_hash: string;
  readonly retry_contract_hash: string | null;
  readonly reviewed_alternative_hash: string | null;
  readonly retry_condition_proofs_json: string | null;
  readonly retry_condition_proofs_hash: string | null;
  readonly audit_record_id: string;
  readonly audit_record_hash: string;
}

interface RetryAuthorizationRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly health_assessment_id: string;
  readonly hazard_node_id: string;
  readonly hazard_profile_version: number;
  readonly source_attack_attempt_id: string;
  readonly authorized_attack_attempt_id: string;
  readonly source_procedure_node_id: string;
  readonly source_procedure_version_node_id: string;
  readonly source_parameter_fingerprint: string;
  readonly authorized_procedure_node_id: string;
  readonly authorized_procedure_version_node_id: string;
  readonly authorized_parameter_fingerprint: string;
  readonly authorized_action_binding_hash: string;
  readonly authorization_basis: AuthorizationBasis;
  readonly target_context_fingerprint: string;
  readonly max_attempts: number;
  readonly automatic_retry: number;
  readonly context_pack_id: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly authorization_hash: string;
  readonly health_assessment_hash: string | null;
  readonly retry_contract_hash: string | null;
  readonly reviewed_alternative_hash: string | null;
  readonly retry_condition_proofs_hash: string | null;
  readonly audit_record_id: string;
  readonly audit_record_hash: string;
}

interface ConsumptionRow {
  readonly authorization_id: string;
  readonly attack_attempt_id: string;
  readonly action_id: string;
  readonly context_pack_id: string;
  readonly consumed_at: string;
  readonly consumption_hash: string;
  readonly audit_record_id: string;
  readonly audit_record_hash: string;
}

export interface OperationalHazardRetryConditionProof {
  readonly conditionId: string;
  readonly evidenceKey: string;
  readonly satisfied: boolean;
  readonly verifiedEvidenceId: string;
  readonly verifiedEvidenceHash: string;
  readonly evaluatorVersion: string;
  readonly evaluatorHash: string;
}

export interface OperationalHazardHealthAssessment {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly hazardNodeId: string;
  readonly hazardProfileVersion: number;
  readonly blockedAttackAttemptId: string;
  readonly procedureNodeId: string;
  readonly procedureVersionNodeId: string;
  readonly targetContextFingerprint: string;
  readonly representedHealthCheckActionId: string;
  readonly verifiedEvidenceId: string;
  readonly verifiedEvidenceHash: string;
  readonly evaluatorVersion: string;
  readonly evaluatorHash: string;
  readonly contextPackId: string;
  readonly result: HealthResult;
  /** Counts corroborated for this exact procedure only. */
  readonly exactProcedureAttemptCount: number;
  readonly exactProcedureReproducibilityCount: number;
  readonly exactProcedureResetCount: number;
  /** Separately attributed aggregate from the operator; never treated as exact-procedure evidence. */
  readonly operatorReportedResetCountMinimum?: number;
  readonly recoveryCost: Readonly<Record<string, unknown>>;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly assessmentHash: string;
  /** Missing only on pre-v28 historical records, which cannot authorize recovery. */
  readonly retryContractHash?: string;
  readonly reviewedAlternativeHash?: string;
  readonly retryConditionProofs?: readonly OperationalHazardRetryConditionProof[];
  readonly retryConditionProofsHash?: string;
  readonly auditRecordId: string;
  readonly auditRecordHash: string;
}

export interface OperationalHazardRetryAuthorization {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly healthAssessmentId: string;
  readonly hazardNodeId: string;
  readonly hazardProfileVersion: number;
  readonly sourceAttackAttemptId: string;
  readonly authorizedAttackAttemptId: string;
  readonly sourceProcedureNodeId: string;
  readonly sourceProcedureVersionNodeId: string;
  readonly sourceParameterFingerprint: string;
  readonly authorizedProcedureNodeId: string;
  readonly authorizedProcedureVersionNodeId: string;
  readonly authorizedParameterFingerprint: string;
  readonly authorizedActionBindingHash: string;
  readonly authorizationBasis: AuthorizationBasis;
  readonly targetContextFingerprint: string;
  readonly maxAttempts: 1;
  readonly automaticRetry: false;
  readonly contextPackId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly authorizationHash: string;
  /** Missing only on pre-v28 historical records, which fail closed at reservation. */
  readonly healthAssessmentHash?: string;
  readonly retryContractHash?: string;
  readonly reviewedAlternativeHash?: string;
  readonly retryConditionProofsHash?: string;
  readonly auditRecordId: string;
  readonly auditRecordHash: string;
}

export interface OperationalHazardRetryConsumption {
  readonly authorizationId: string;
  readonly attackAttemptId: string;
  readonly actionId: string;
  readonly contextPackId: string;
  readonly consumedAt: string;
  readonly consumptionHash: string;
  readonly auditRecordId: string;
  readonly auditRecordHash: string;
  readonly duplicate: boolean;
}

export class OperationalHazardHealthGateError extends Error {
  readonly retryable = false;
  readonly category: "evidence_insufficient" | "policy_denied" | "scope_conflict" | "conflict";

  constructor(
    readonly code: string,
    message: string,
    category: OperationalHazardHealthGateError["category"] = "policy_denied",
  ) {
    super(message);
    this.name = "OperationalHazardHealthGateError";
    this.category = category;
  }
}

function assertId(value: string, label: string): string {
  const normalized = value.trim();
  if (!ID.test(normalized)) throw new OperationalHazardHealthGateError("hazard_health_gate_invalid", `${label} is invalid`);
  return normalized;
}

function assertHash(value: string, label: string): string {
  const normalized = value.trim().toLowerCase();
  if (!SHA256.test(normalized)) throw new OperationalHazardHealthGateError("hazard_health_gate_invalid", `${label} must be a SHA-256 digest`);
  return normalized;
}

function ttl(value: number | undefined, fallback: number): number {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1_000 || selected > MAX_TTL_MS) {
    throw new OperationalHazardHealthGateError("hazard_health_gate_invalid", "Health-gate expiry must be between one second and one hour");
  }
  return selected;
}

function parseObject(value: string, label: string): Readonly<Record<string, unknown>> {
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { parsed = null; }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new OperationalHazardHealthGateError("hazard_health_gate_integrity_failed", `${label} is malformed`, "evidence_insufficient");
  }
  return parsed as Readonly<Record<string, unknown>>;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function parseRetryConditionProofs(
  value: string,
  label: string,
): readonly OperationalHazardRetryConditionProof[] {
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { parsed = null; }
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > 128) {
    throw new OperationalHazardHealthGateError(
      "hazard_retry_condition_proof_integrity_failed",
      `${label} is malformed`,
      "evidence_insufficient",
    );
  }
  const ids = new Set<string>();
  const keys = new Set<string>();
  return parsed.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_condition_proof_integrity_failed",
        `${label} item ${index} is malformed`,
        "evidence_insufficient",
      );
    }
    const row = item as Record<string, unknown>;
    const conditionId = assertId(String(row.conditionId ?? ""), `${label} condition ID`);
    const evidenceKey = assertId(String(row.evidenceKey ?? ""), `${label} evidence key`);
    const verifiedEvidenceId = assertId(String(row.verifiedEvidenceId ?? ""), `${label} evidence ID`);
    const verifiedEvidenceHash = assertHash(String(row.verifiedEvidenceHash ?? ""), `${label} evidence hash`);
    const evaluatorVersion = String(row.evaluatorVersion ?? "");
    const evaluatorHash = assertHash(String(row.evaluatorHash ?? ""), `${label} evaluator hash`);
    if (
      typeof row.satisfied !== "boolean"
      || evaluatorVersion !== LOCAL_EVALUATOR_VERSION
      || evaluatorHash !== LOCAL_EVALUATOR_HASH
      || ids.has(conditionId)
      || keys.has(evidenceKey)
    ) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_condition_proof_integrity_failed",
        `${label} contains an invalid or duplicate proof`,
        "evidence_insufficient",
      );
    }
    ids.add(conditionId);
    keys.add(evidenceKey);
    return {
      conditionId,
      evidenceKey,
      satisfied: row.satisfied,
      verifiedEvidenceId,
      verifiedEvidenceHash,
      evaluatorVersion,
      evaluatorHash,
    };
  });
}

function mapAssessment(row: HealthAssessmentRow): OperationalHazardHealthAssessment {
  return {
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    hazardNodeId: row.hazard_node_id,
    hazardProfileVersion: row.hazard_profile_version,
    blockedAttackAttemptId: row.blocked_attack_attempt_id,
    procedureNodeId: row.procedure_node_id,
    procedureVersionNodeId: row.procedure_version_node_id,
    targetContextFingerprint: row.target_context_fingerprint,
    representedHealthCheckActionId: row.represented_health_check_action_id,
    verifiedEvidenceId: row.verified_evidence_id,
    verifiedEvidenceHash: row.verified_evidence_hash,
    evaluatorVersion: row.evaluator_version,
    evaluatorHash: row.evaluator_hash,
    contextPackId: row.context_pack_id,
    result: row.result,
    exactProcedureAttemptCount: row.exact_procedure_attempt_count,
    exactProcedureReproducibilityCount: row.exact_procedure_reproducibility_count,
    exactProcedureResetCount: row.exact_procedure_reset_count,
    ...(row.operator_reported_reset_count_minimum === null
      ? {}
      : { operatorReportedResetCountMinimum: row.operator_reported_reset_count_minimum }),
    recoveryCost: parseObject(row.recovery_cost_json, "Stored recovery cost"),
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    assessmentHash: row.assessment_hash,
    ...(row.retry_contract_hash ? { retryContractHash: row.retry_contract_hash } : {}),
    ...(row.reviewed_alternative_hash ? { reviewedAlternativeHash: row.reviewed_alternative_hash } : {}),
    ...(row.retry_condition_proofs_json
      ? { retryConditionProofs: parseRetryConditionProofs(row.retry_condition_proofs_json, "Stored retry-condition proofs") }
      : {}),
    ...(row.retry_condition_proofs_hash
      ? { retryConditionProofsHash: row.retry_condition_proofs_hash }
      : {}),
    auditRecordId: row.audit_record_id,
    auditRecordHash: row.audit_record_hash,
  };
}

function mapAuthorization(row: RetryAuthorizationRow): OperationalHazardRetryAuthorization {
  return {
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    healthAssessmentId: row.health_assessment_id,
    hazardNodeId: row.hazard_node_id,
    hazardProfileVersion: row.hazard_profile_version,
    sourceAttackAttemptId: row.source_attack_attempt_id,
    authorizedAttackAttemptId: row.authorized_attack_attempt_id,
    sourceProcedureNodeId: row.source_procedure_node_id,
    sourceProcedureVersionNodeId: row.source_procedure_version_node_id,
    sourceParameterFingerprint: row.source_parameter_fingerprint,
    authorizedProcedureNodeId: row.authorized_procedure_node_id,
    authorizedProcedureVersionNodeId: row.authorized_procedure_version_node_id,
    authorizedParameterFingerprint: row.authorized_parameter_fingerprint,
    authorizedActionBindingHash: row.authorized_action_binding_hash,
    authorizationBasis: row.authorization_basis,
    targetContextFingerprint: row.target_context_fingerprint,
    maxAttempts: 1,
    automaticRetry: false,
    contextPackId: row.context_pack_id,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    authorizationHash: row.authorization_hash,
    ...(row.health_assessment_hash ? { healthAssessmentHash: row.health_assessment_hash } : {}),
    ...(row.retry_contract_hash ? { retryContractHash: row.retry_contract_hash } : {}),
    ...(row.reviewed_alternative_hash ? { reviewedAlternativeHash: row.reviewed_alternative_hash } : {}),
    ...(row.retry_condition_proofs_hash
      ? { retryConditionProofsHash: row.retry_condition_proofs_hash }
      : {}),
    auditRecordId: row.audit_record_id,
    auditRecordHash: row.audit_record_hash,
  };
}

function mapConsumption(row: ConsumptionRow, duplicate: boolean): OperationalHazardRetryConsumption {
  return {
    authorizationId: row.authorization_id,
    attackAttemptId: row.attack_attempt_id,
    actionId: row.action_id,
    contextPackId: row.context_pack_id,
    consumedAt: row.consumed_at,
    consumptionHash: row.consumption_hash,
    auditRecordId: row.audit_record_id,
    auditRecordHash: row.audit_record_hash,
    duplicate,
  };
}

function containsPublicModelAttribution(value: unknown): boolean {
  if (typeof value === "string") {
    return /(?:public[_ -]?model|public[_ -]?llm|provider[_ -]?turn|model[_ -]?self[_ -]?report|openai|anthropic|openrouter|gemini|grok|xai)/iu.test(value);
  }
  if (Array.isArray(value)) return value.some(containsPublicModelAttribution);
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).some(([key, item]) =>
      containsPublicModelAttribution(key) || containsPublicModelAttribution(item));
  }
  return false;
}

function parseReviewedAttemptBinding(
  value: unknown,
  label: string,
): OperationalHazardReviewedAttemptBinding {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new OperationalHazardHealthGateError(
      "hazard_retry_contract_invalid",
      `${label} is malformed`,
      "evidence_insufficient",
    );
  }
  const row = value as Record<string, unknown>;
  const expectedKeys = new Set([
    "procedureNodeId", "procedureVersionNodeId", "normalizedParameters",
    "load", "concurrency", "timingWindowMs",
  ]);
  if (Object.keys(row).some((key) => !expectedKeys.has(key)) || Object.keys(row).length !== expectedKeys.size) {
    throw new OperationalHazardHealthGateError(
      "hazard_retry_contract_invalid",
      `${label} contains unsupported or missing fields`,
      "evidence_insufficient",
    );
  }
  if (!row.normalizedParameters || typeof row.normalizedParameters !== "object" || Array.isArray(row.normalizedParameters)) {
    throw new OperationalHazardHealthGateError("hazard_retry_contract_invalid", `${label} parameters are malformed`, "evidence_insufficient");
  }
  const normalizedParameters: Record<string, Primitive> = {};
  const parameters = Object.entries(row.normalizedParameters as Record<string, unknown>);
  if (parameters.length > 64) {
    throw new OperationalHazardHealthGateError("hazard_retry_contract_invalid", `${label} parameters exceed the limit`, "evidence_insufficient");
  }
  for (const [key, item] of parameters.sort(([left], [right]) => left.localeCompare(right))) {
    if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(key)
      || !(["string", "number", "boolean"] as const).includes(typeof item as "string" | "number" | "boolean")
      || (typeof item === "number" && !Number.isFinite(item))) {
      throw new OperationalHazardHealthGateError("hazard_retry_contract_invalid", `${label} parameters are malformed`, "evidence_insufficient");
    }
    normalizedParameters[key] = item as Primitive;
  }
  const nullableNumber = (item: unknown, field: string, integer = false): number | null => {
    if (item === null) return null;
    if (typeof item !== "number" || !Number.isFinite(item) || item < 0
      || (integer && (!Number.isSafeInteger(item) || item < 1))) {
      throw new OperationalHazardHealthGateError("hazard_retry_contract_invalid", `${field} is malformed`, "evidence_insufficient");
    }
    return item;
  };
  return {
    procedureNodeId: assertId(String(row.procedureNodeId ?? ""), `${label} procedure node ID`),
    procedureVersionNodeId: assertId(String(row.procedureVersionNodeId ?? ""), `${label} procedure-version node ID`),
    normalizedParameters,
    load: nullableNumber(row.load, `${label} load`),
    concurrency: nullableNumber(row.concurrency, `${label} concurrency`, true),
    timingWindowMs: nullableNumber(row.timingWindowMs, `${label} timing window`),
  };
}

function parseReviewedRetryContract(profile: HazardProfileRow): OperationalHazardReviewedRetryContract {
  if (!profile.reviewed_retry_contract_json) {
    throw new OperationalHazardHealthGateError(
      "hazard_retry_contract_required",
      "This hazard has no exact operator-reviewed safer alternative and cannot authorize recovery",
      "evidence_insufficient",
    );
  }
  const parsed = parseObject(profile.reviewed_retry_contract_json, "Reviewed retry contract");
  const allowedKeys = new Set(["schema", "alternativeKind", "source", "alternative", "retryValidConditions"]);
  if (Object.keys(parsed).some((key) => !allowedKeys.has(key)) || Object.keys(parsed).length !== allowedKeys.size
    || parsed.schema !== "ti_scale.operational_hazard_retry_contract/v1"
    || !(["explicit_alternative", "structured_delta"] as const).includes(
      parsed.alternativeKind as "explicit_alternative" | "structured_delta",
    )) {
    throw new OperationalHazardHealthGateError("hazard_retry_contract_invalid", "Reviewed retry contract is malformed", "evidence_insufficient");
  }
  const safeRetryGate = (() => {
    let value: unknown;
    try { value = JSON.parse(profile.safe_retry_gate_json) as unknown; } catch { value = null; }
    if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string" || !item.trim())) {
      throw new OperationalHazardHealthGateError("hazard_retry_contract_invalid", "Safe-retry conditions are malformed", "evidence_insufficient");
    }
    return value as string[];
  })();
  if (!Array.isArray(parsed.retryValidConditions)
    || parsed.retryValidConditions.length !== safeRetryGate.length
    || parsed.retryValidConditions.length === 0) {
    throw new OperationalHazardHealthGateError(
      "hazard_retry_contract_invalid",
      "Reviewed retry contract does not type every safe-retry condition",
      "evidence_insufficient",
    );
  }
  const ids = new Set<string>();
  const evidenceKeys = new Set<string>();
  const retryValidConditions = parsed.retryValidConditions.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new OperationalHazardHealthGateError("hazard_retry_contract_invalid", "Reviewed retry condition is malformed", "evidence_insufficient");
    }
    const condition = item as Record<string, unknown>;
    const id = assertId(String(condition.id ?? ""), "Retry condition ID");
    const evidenceKey = assertId(String(condition.evidenceKey ?? ""), "Retry condition evidence key");
    const statement = String(condition.statement ?? "");
    if (Object.keys(condition).length !== 3
      || !Object.hasOwn(condition, "id")
      || !Object.hasOwn(condition, "statement")
      || !Object.hasOwn(condition, "evidenceKey")
      || statement !== safeRetryGate[index]
      || ids.has(id)
      || evidenceKeys.has(evidenceKey)) {
      throw new OperationalHazardHealthGateError("hazard_retry_contract_invalid", "Reviewed retry conditions are ambiguous or out of sync", "evidence_insufficient");
    }
    ids.add(id);
    evidenceKeys.add(evidenceKey);
    return { id, statement, evidenceKey };
  });
  const contract: OperationalHazardReviewedRetryContract = {
    schema: "ti_scale.operational_hazard_retry_contract/v1",
    alternativeKind: parsed.alternativeKind as "explicit_alternative" | "structured_delta",
    source: parseReviewedAttemptBinding(parsed.source, "Reviewed source binding"),
    alternative: parseReviewedAttemptBinding(parsed.alternative, "Reviewed alternative binding"),
    retryValidConditions,
  };
  if (
    contract.source.procedureNodeId !== profile.procedure_node_id
    || contract.source.procedureVersionNodeId !== profile.procedure_version_node_id
  ) {
    throw new OperationalHazardHealthGateError("hazard_retry_contract_source_mismatch", "Reviewed retry source no longer matches the hazard profile", "evidence_insufficient");
  }
  if (contract.alternativeKind === "explicit_alternative") {
    if (!profile.alternative_procedure_node_id
      || contract.alternative.procedureNodeId !== profile.alternative_procedure_node_id
      || contract.alternative.procedureNodeId === contract.source.procedureNodeId) {
      throw new OperationalHazardHealthGateError("hazard_retry_contract_alternative_mismatch", "Reviewed explicit alternative no longer matches the hazard profile", "evidence_insufficient");
    }
  } else if (
    contract.alternative.procedureNodeId !== contract.source.procedureNodeId
    || operationalHazardReviewedBindingFingerprint(contract.alternative)
      === operationalHazardReviewedBindingFingerprint(contract.source)
  ) {
    throw new OperationalHazardHealthGateError("hazard_retry_contract_delta_invalid", "Reviewed structured delta is not a material exact change", "evidence_insufficient");
  }
  return contract;
}

/** Trusted local service. No HTTP or provider-facing mutation surface is exposed. */
export class OperationalHazardHealthGateService {
  readonly #clock: () => Date;
  readonly #events: EventRepository;
  readonly #audit: AuditTrailWriter;

  constructor(
    private readonly database: SqliteDatabase,
    options: { readonly clock?: () => Date } = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#events = new EventRepository(database);
    this.#audit = new AuditTrailWriter(database);
  }

  getAssessment(id: string): OperationalHazardHealthAssessment | undefined {
    const row = this.database.prepare("SELECT * FROM operational_hazard_health_assessments WHERE id = ?")
      .get(assertId(id, "Health assessment ID")) as HealthAssessmentRow | undefined;
    return row ? mapAssessment(row) : undefined;
  }

  getAuthorization(id: string): OperationalHazardRetryAuthorization | undefined {
    const row = this.database.prepare("SELECT * FROM operational_hazard_retry_authorizations WHERE id = ?")
      .get(assertId(id, "Retry authorization ID")) as RetryAuthorizationRow | undefined;
    return row ? mapAuthorization(row) : undefined;
  }

  /**
   * Trusted runtime completion seam. The represented action names only the
   * immutable hazard/source/Context Pack; evidence and evaluator outcome are
   * discovered and derived locally after the action reaches succeeded.
   */
  recordAssessmentForCompletedAction(
    action: DurableAction,
    actor: OperationalActor,
  ): OperationalHazardHealthAssessment | undefined {
    if (action.actionType !== HEALTH_ACTION_TYPE) return undefined;
    if (action.status !== "succeeded") {
      throw new OperationalHazardHealthGateError(
        "hazard_health_action_not_verified",
        "Operational health assessment can run only after the represented action succeeds",
        "evidence_insufficient",
      );
    }
    const hazardNodeId = typeof action.arguments.hazardNodeId === "string"
      ? action.arguments.hazardNodeId
      : "";
    const blockedAttackAttemptId = typeof action.arguments.blockedAttackAttemptId === "string"
      ? action.arguments.blockedAttackAttemptId
      : "";
    const contextPackId = typeof action.arguments.contextPackId === "string"
      ? action.arguments.contextPackId
      : "";
    const hazardProfileVersion = action.arguments.hazardProfileVersion;
    if (typeof hazardProfileVersion !== "number" || !Number.isSafeInteger(hazardProfileVersion) || hazardProfileVersion < 1) {
      throw new OperationalHazardHealthGateError(
        "hazard_health_action_contract_invalid",
        "Represented health action does not name an exact hazard profile version",
        "evidence_insufficient",
      );
    }
    const evidence = this.database.prepare(`
      SELECT id, content_hash FROM evidence
      WHERE mission_id = ? AND run_id = ? AND action_id = ?
        AND evidence_type = 'health_check_result'
        AND verification_state = 'verified'
      ORDER BY acquired_at, id
    `).all(action.missionId, action.runId, action.id) as Array<{
      readonly id: string;
      readonly content_hash: string;
    }>;
    if (evidence.length !== 1) {
      throw new OperationalHazardHealthGateError(
        "hazard_health_evidence_cardinality_invalid",
        "The completed health action must produce exactly one verified typed health-check result",
        "evidence_insufficient",
      );
    }
    return this.recordAssessment({
      hazardNodeId,
      hazardProfileVersion,
      blockedAttackAttemptId,
      representedHealthCheckActionId: action.id,
      verifiedEvidenceId: evidence[0]!.id,
      verifiedEvidenceHash: evidence[0]!.content_hash,
      contextPackId,
      actor,
    });
  }

  authorizationForAttempt(attackAttemptId: string): OperationalHazardRetryAuthorization | undefined {
    const rows = this.database.prepare(`
      SELECT * FROM operational_hazard_retry_authorizations
      WHERE authorized_attack_attempt_id = ? ORDER BY issued_at, id LIMIT 2
    `).all(assertId(attackAttemptId, "Attack-attempt ID")) as RetryAuthorizationRow[];
    if (rows.length > 1) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_authorization_ambiguous",
        "More than one safer-retry authorization names this attack attempt",
        "conflict",
      );
    }
    return rows[0] ? mapAuthorization(rows[0]) : undefined;
  }

  /** Fail closed only for an explicitly recovery-linked attempt. */
  assertReservationAuthorized(attackAttemptId: string): OperationalHazardRetryAuthorization | undefined {
    const candidate = this.#requireAttempt(assertId(attackAttemptId, "Attack-attempt ID"));
    const authorization = this.authorizationForAttempt(candidate.id);
    const unresolvedSources = this.#unresolvedRelevantHazardSources(candidate);
    if (!candidate.recovery_source_attack_attempt_id) {
      if (authorization) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_lineage_mismatch",
          "A safer-attempt authorization cannot exist without immutable recovery lineage",
          "conflict",
        );
      }
      if (unresolvedSources.length > 0) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_lineage_required",
          "This typed procedure is a version or explicit alternative of an unresolved hazard on the same canonical target; create it as an explicit recovery attempt",
          "evidence_insufficient",
        );
      }
      return undefined;
    }
    if (!authorization) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_authorization_required",
        "This explicitly linked recovery attempt requires a current passing health assessment and a single-use safer-attempt authorization",
        "evidence_insufficient",
      );
    }
    if (authorization.sourceAttackAttemptId !== candidate.recovery_source_attack_attempt_id) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_lineage_mismatch",
        "The authorization does not match the attempt's immutable recovery source",
        "conflict",
      );
    }
    const source = this.#requireAttempt(candidate.recovery_source_attack_attempt_id);
    if (!unresolvedSources.includes(source.id)) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_source_not_active",
        "The immutable recovery source is not a current exact hazard for this typed procedure and canonical target",
        "conflict",
      );
    }
    if (!['waiting_conditions', 'blocked'].includes(source.status)) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_source_not_active",
        "The immutable recovery source is no longer in its preserved blocked state",
        "conflict",
      );
    }
    const now = this.#clock();
    if (Date.parse(authorization.expiresAt) <= now.getTime()) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_authorization_expired",
        "The safer-attempt authorization expired before action reservation",
        "evidence_insufficient",
      );
    }
    const assessment = this.getAssessment(authorization.healthAssessmentId);
    if (!assessment || assessment.result !== "pass" || Date.parse(assessment.expiresAt) <= now.getTime()) {
      throw new OperationalHazardHealthGateError(
        "hazard_health_assessment_expired",
        "A current passing health assessment is required before action reservation",
        "evidence_insufficient",
      );
    }
    const consumed = this.database.prepare(`
      SELECT action_id FROM operational_hazard_retry_consumptions WHERE authorization_id = ?
    `).get(authorization.id) as { readonly action_id: string } | undefined;
    if (consumed) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_authorization_replayed",
        "This single-use safer-attempt authorization was already consumed",
        "conflict",
      );
    }
    return authorization;
  }

  /** Called from the fenced action-reservation transaction. */
  consumeRequiredForAction(input: {
    readonly attackAttemptId: string;
    readonly action: DurableAction;
    readonly actorId: string;
  }): OperationalHazardRetryConsumption | undefined {
    const authorization = this.assertReservationAuthorized(input.attackAttemptId);
    if (!authorization) return undefined;
    return this.consumeForAction({
      authorizationId: authorization.id,
      attackAttemptId: input.attackAttemptId,
      action: input.action,
      actorId: input.actorId,
    });
  }

  recordAssessment(input: {
    readonly hazardNodeId: string;
    readonly hazardProfileVersion: number;
    readonly blockedAttackAttemptId: string;
    readonly representedHealthCheckActionId: string;
    readonly verifiedEvidenceId: string;
    readonly verifiedEvidenceHash: string;
    readonly contextPackId: string;
    readonly actor: OperationalActor;
    readonly ttlMs?: number;
  }): OperationalHazardHealthAssessment {
    const hazardNodeId = assertId(input.hazardNodeId, "Hazard node ID");
    const blockedAttackAttemptId = assertId(input.blockedAttackAttemptId, "Blocked attack-attempt ID");
    const healthActionId = assertId(input.representedHealthCheckActionId, "Health-check action ID");
    const evidenceId = assertId(input.verifiedEvidenceId, "Verified evidence ID");
    const evidenceHash = assertHash(input.verifiedEvidenceHash, "Verified evidence hash");
    const contextPackId = assertId(input.contextPackId, "Context Pack ID");
    const evaluatorVersion = LOCAL_EVALUATOR_VERSION;
    const evaluatorHash = LOCAL_EVALUATOR_HASH;
    const now = this.#clock();
    const issuedAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + ttl(input.ttlMs, DEFAULT_ASSESSMENT_TTL_MS)).toISOString();

    return inImmediateTransaction(this.database, () => {
      const profile = this.#requireVerifiedHazard(hazardNodeId, input.hazardProfileVersion, now);
      if (!profile.procedure_version_node_id) {
        throw new OperationalHazardHealthGateError("hazard_exact_procedure_version_required", "Health assessment requires an exact known-bad procedure version", "evidence_insufficient");
      }
      const attempt = this.#requireAttempt(blockedAttackAttemptId);
      if (!['waiting_conditions', 'blocked'].includes(attempt.status)) {
        throw new OperationalHazardHealthGateError("hazard_source_attempt_not_blocked", "Health assessment requires the preserved blocked attempt", "conflict");
      }
      const binding = this.#requireKnowledge(blockedAttackAttemptId);
      if (binding.procedure_node_id !== profile.procedure_node_id || binding.procedure_version_node_id !== profile.procedure_version_node_id) {
        throw new OperationalHazardHealthGateError("hazard_source_binding_mismatch", "Blocked attempt does not match the exact hazard procedure and version", "scope_conflict");
      }
      const retryContract = parseReviewedRetryContract(profile);
      this.#assertReviewedRetryContractNodes(retryContract, now);
      if (operationalHazardReviewedBindingFingerprint(this.#reviewedBinding(binding))
        !== operationalHazardReviewedBindingFingerprint(retryContract.source)) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_contract_source_mismatch",
          "Blocked attempt does not exactly match the reviewed retry contract source binding",
          "scope_conflict",
        );
      }
      const retryContractHash = operationalHazardRetryContractHash(retryContract);
      const reviewedAlternativeHash = operationalHazardReviewedBindingFingerprint(retryContract.alternative);
      const hazardAssessment = new OperationalHazardMatcher(this.database, { clock: this.#clock })
        .assessAttackAttempt(blockedAttackAttemptId);
      if (hazardAssessment?.decision !== "block" || !hazardAssessment.matchedHazardNodeIds.includes(hazardNodeId)) {
        throw new OperationalHazardHealthGateError("verified_operational_hazard_required", "Candidate or non-applicable hazard memory cannot authorize a health gate", "evidence_insufficient");
      }
      const healthAction = this.#requireHealthAction(attempt, healthActionId);
      this.#requireRegisteredLocalEvaluator();
      const evaluation = this.#evaluateVerifiedLocalEvidence(
        attempt,
        healthAction,
        evidenceId,
        evidenceHash,
        retryContract,
        retryContractHash,
      );
      const result = evaluation.result;
      const retryConditionProofs = evaluation.retryConditionProofs;
      const retryConditionProofsHash = hashJson(retryConditionProofs);
      const retryConditionProofsPayload = retryConditionProofs.map((proof) => ({
        conditionId: proof.conditionId,
        evidenceKey: proof.evidenceKey,
        satisfied: proof.satisfied,
        verifiedEvidenceId: proof.verifiedEvidenceId,
        verifiedEvidenceHash: proof.verifiedEvidenceHash,
        evaluatorVersion: proof.evaluatorVersion,
        evaluatorHash: proof.evaluatorHash,
      }));
      this.#assertContextPack(attempt, contextPackId, healthActionId, [
        hazardNodeId,
        profile.procedure_node_id,
        profile.procedure_version_node_id,
      ]);
      const targetContextFingerprint = this.#targetContextFingerprint(attempt);
      const recoveryCost = parseObject(profile.recovery_cost_json, "Hazard recovery cost");
      const exactResetCount = Number.isSafeInteger(recoveryCost.resetCount) && Number(recoveryCost.resetCount) >= 0
        ? Number(recoveryCost.resetCount)
        : 0;
      const operatorReported = Number.isSafeInteger(recoveryCost.operatorReportedResetCountMinimum)
        && Number(recoveryCost.operatorReportedResetCountMinimum) >= exactResetCount
        ? Number(recoveryCost.operatorReportedResetCountMinimum)
        : undefined;
      const assessmentBody = {
        missionId: attempt.mission_id,
        runId: attempt.run_id,
        hazardNodeId,
        hazardProfileVersion: profile.version,
        blockedAttackAttemptId,
        procedureNodeId: profile.procedure_node_id,
        procedureVersionNodeId: profile.procedure_version_node_id,
        sourceTargetAssetId: attempt.target_asset_id,
        sourceTargetServiceId: attempt.target_service_id,
        targetContextFingerprint,
        representedHealthCheckActionId: healthActionId,
        verifiedEvidenceId: evidenceId,
        verifiedEvidenceHash: evidenceHash,
        evaluatorKind: "local_evaluator",
        evaluatorVersion,
        evaluatorHash,
        contextPackId,
        result,
        exactProcedureAttemptCount: profile.attempt_count,
        exactProcedureReproducibilityCount: profile.reproducibility_count,
        exactProcedureResetCount: exactResetCount,
        operatorReportedResetCountMinimum: operatorReported ?? null,
        recoveryCost,
        retryContractHash,
        reviewedAlternativeHash,
        retryConditionProofs,
        retryConditionProofsHash,
        issuedAt,
        expiresAt,
      };
      const assessmentHash = hashJson(assessmentBody);
      const prior = this.database.prepare("SELECT * FROM operational_hazard_health_assessments WHERE assessment_hash = ?")
        .get(assessmentHash) as HealthAssessmentRow | undefined;
      if (prior) return mapAssessment(prior);
      const id = `hazard_health_${randomUUID()}`;
      const auditId = this.#audit.append({
        missionId: attempt.mission_id,
        runId: attempt.run_id,
        actor: input.actor,
        action: "operational_hazard.health_assessed",
        resourceType: "operational_hazard_health_assessment",
        resourceId: id,
        reason: result === "pass"
          ? "Trusted local evidence restored the target baseline; no retry was authorized"
          : "Trusted local evidence showed the target baseline is not restored",
        details: {
          assessmentHash,
          hazardNodeId,
          blockedAttackAttemptId,
          healthActionId,
          evidenceId,
          evidenceHash,
          evaluatorVersion,
          evaluatorHash,
          contextPackId,
          result,
          exactProcedureAttemptCount: profile.attempt_count,
          exactProcedureReproducibilityCount: profile.reproducibility_count,
          exactProcedureResetCount: exactResetCount,
          operatorReportedResetCountMinimum: operatorReported ?? null,
          retryContractHash,
          reviewedAlternativeHash,
          retryConditionProofs: retryConditionProofsPayload,
          retryConditionProofsHash,
          identicalKnownBadProcedureAuthorized: false,
        },
        occurredAt: issuedAt,
      });
      const audit = this.database.prepare("SELECT record_hash FROM audit_records WHERE id = ?")
        .get(auditId) as { record_hash: string };
      this.database.prepare(`
        INSERT INTO operational_hazard_health_assessments (
          id, mission_id, run_id, hazard_node_id, hazard_profile_version,
          blocked_attack_attempt_id, procedure_node_id, procedure_version_node_id,
          source_target_asset_id, source_target_service_id,
          target_context_fingerprint, represented_health_check_action_id,
          verified_evidence_id, verified_evidence_hash, evaluator_kind,
          evaluator_version, evaluator_hash, context_pack_id, result,
          exact_procedure_attempt_count, exact_procedure_reproducibility_count,
          exact_procedure_reset_count, operator_reported_reset_count_minimum,
          recovery_cost_json, issued_at, expires_at, assessment_hash,
          retry_contract_hash, reviewed_alternative_hash,
          retry_condition_proofs_json, retry_condition_proofs_hash,
          audit_record_id, audit_record_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'local_evaluator', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, attempt.mission_id, attempt.run_id, hazardNodeId, profile.version,
        blockedAttackAttemptId, profile.procedure_node_id, profile.procedure_version_node_id,
        attempt.target_asset_id, attempt.target_service_id,
        targetContextFingerprint, healthActionId, evidenceId, evidenceHash,
        evaluatorVersion, evaluatorHash, contextPackId, result,
        profile.attempt_count, profile.reproducibility_count, exactResetCount,
        operatorReported ?? null, canonicalJson(recoveryCost), issuedAt, expiresAt,
        assessmentHash, retryContractHash, reviewedAlternativeHash,
        canonicalJson(retryConditionProofs), retryConditionProofsHash,
        auditId, audit.record_hash,
      );
      this.#events.append({
        missionId: attempt.mission_id,
        runId: attempt.run_id,
        eventType: "operational_hazard.health_assessed",
        actorType: "system",
        actorId: "local-operational-hazard-evaluator",
        summary: result === "pass"
          ? "The represented health check restored the baseline; the known-bad procedure remains blocked."
          : "The represented health check did not restore the baseline; no retry can be authorized.",
        payload: {
          assessmentId: id,
          hazardNodeId,
          blockedAttackAttemptId,
          healthActionId,
          evidenceId,
          evidenceHash,
          result,
          expiresAt,
          exactProcedureAttemptCount: profile.attempt_count,
          exactProcedureReproducibilityCount: profile.reproducibility_count,
          exactProcedureResetCount: exactResetCount,
          operatorReportedResetCountMinimum: operatorReported ?? null,
          retryContractHash,
          reviewedAlternativeHash,
          retryConditionProofsHash,
          identicalKnownBadProcedureAuthorized: false,
        },
        contextPackId,
        sensitivity: "private",
        redaction: { targetContext: "sha256_fingerprint_only", rawEvidence: "excluded" },
      });
      return this.getAssessment(id)!;
    });
  }

  authorizeSaferAttempt(input: {
    readonly healthAssessmentId: string;
    readonly attackAttemptId: string;
    readonly actor: OperationalActor;
    readonly maxAttempts?: 1;
    readonly ttlMs?: number;
  }): OperationalHazardRetryAuthorization {
    if (input.maxAttempts !== undefined && input.maxAttempts !== 1) {
      throw new OperationalHazardHealthGateError("hazard_retry_attempt_bound_invalid", "Operational-hazard recovery permits one represented attempt only");
    }
    const assessment = this.getAssessment(assertId(input.healthAssessmentId, "Health assessment ID"));
    if (!assessment) throw new OperationalHazardHealthGateError("hazard_health_assessment_not_found", "Health assessment was not found", "conflict");
    const attackAttemptId = assertId(input.attackAttemptId, "Safer attack-attempt ID");
    const now = this.#clock();
    const issuedAt = now.toISOString();
    if (assessment.result !== "pass") {
      throw new OperationalHazardHealthGateError("hazard_health_gate_failed", "A failed health assessment cannot authorize a retry", "evidence_insufficient");
    }
    if (Date.parse(assessment.expiresAt) <= now.getTime()) {
      throw new OperationalHazardHealthGateError("hazard_health_assessment_expired", "The passing health assessment expired", "evidence_insufficient");
    }

    return inImmediateTransaction(this.database, () => {
      const profile = this.#requireVerifiedHazard(assessment.hazardNodeId, assessment.hazardProfileVersion, now);
      const retryContract = parseReviewedRetryContract(profile);
      this.#assertReviewedRetryContractNodes(retryContract, now);
      const retryContractHash = operationalHazardRetryContractHash(retryContract);
      const reviewedAlternativeHash = operationalHazardReviewedBindingFingerprint(retryContract.alternative);
      if (
        assessment.retryContractHash !== retryContractHash
        || assessment.reviewedAlternativeHash !== reviewedAlternativeHash
        || !assessment.retryConditionProofs
        || !assessment.retryConditionProofsHash
      ) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_assessment_contract_mismatch",
          "Passing health assessment is not bound to the current exact reviewed retry contract",
          "evidence_insufficient",
        );
      }
      this.#assertConditionProofs(
        retryContract,
        assessment.retryConditionProofs,
        assessment.verifiedEvidenceId,
        assessment.verifiedEvidenceHash,
      );
      if (hashJson(assessment.retryConditionProofs) !== assessment.retryConditionProofsHash
        || assessment.retryConditionProofs.some((proof) => !proof.satisfied)) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_conditions_not_satisfied",
          "Every reviewed retry-valid condition must have current passing local evidence",
          "evidence_insufficient",
        );
      }
      const source = this.#requireAttempt(assessment.blockedAttackAttemptId);
      const candidate = this.#requireAttempt(attackAttemptId);
      if (candidate.status !== "ready") {
        throw new OperationalHazardHealthGateError("hazard_retry_attempt_not_ready", "The safer attempt must be represented and ready", "conflict");
      }
      if (candidate.mission_id !== assessment.missionId || candidate.run_id !== assessment.runId) {
        throw new OperationalHazardHealthGateError("hazard_retry_cross_run_denied", "Health recovery authorization cannot cross mission or run", "scope_conflict");
      }
      if (candidate.recovery_source_attack_attempt_id !== source.id) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_lineage_mismatch",
          "The safer attempt was not created with this exact immutable recovery source",
          "scope_conflict",
        );
      }
      const candidateTarget = this.#targetContextFingerprint(candidate);
      if (candidateTarget !== assessment.targetContextFingerprint || this.#targetContextFingerprint(source) !== candidateTarget) {
        throw new OperationalHazardHealthGateError("hazard_retry_cross_target_denied", "Health recovery authorization cannot cross target or environment", "scope_conflict");
      }
      const sourceBinding = this.#requireKnowledge(source.id);
      const candidateBinding = this.#requireKnowledge(candidate.id);
      const candidateActionBinding = this.#requireActionBinding(candidate.id);
      if (!sourceBinding.procedure_version_node_id || !candidateBinding.procedure_version_node_id) {
        throw new OperationalHazardHealthGateError("hazard_exact_procedure_version_required", "Both source and safer attempt need exact procedure versions", "evidence_insufficient");
      }
      const sourceParameterFingerprint = this.#parameterFingerprint(sourceBinding);
      const authorizedParameterFingerprint = this.#parameterFingerprint(candidateBinding);
      const actualSourceBinding = this.#reviewedBinding(sourceBinding);
      const actualCandidateBinding = this.#reviewedBinding(candidateBinding);
      if (operationalHazardReviewedBindingFingerprint(actualSourceBinding)
        !== operationalHazardReviewedBindingFingerprint(retryContract.source)) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_contract_source_mismatch",
          "Recovery source does not exactly match the reviewed known-bad binding",
          "scope_conflict",
        );
      }
      if (operationalHazardReviewedBindingFingerprint(actualCandidateBinding)
        === operationalHazardReviewedBindingFingerprint(actualSourceBinding)) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_identical_known_bad_denied",
          "A passing health check never authorizes the identical known-bad procedure and parameters",
          "policy_denied",
        );
      }
      if (operationalHazardReviewedBindingFingerprint(actualCandidateBinding) !== reviewedAlternativeHash) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_alternative_not_reviewed",
          "A merely different version or parameter set is not safer; the represented attempt must exactly match the reviewed alternative binding",
          "policy_denied",
        );
      }
      const authorizationBasis: AuthorizationBasis = retryContract.alternativeKind === "explicit_alternative"
        ? "explicit_alternative"
        : candidateBinding.procedure_version_node_id !== sourceBinding.procedure_version_node_id
          ? "distinct_procedure_version"
          : "distinct_parameters";
      const requestedExpiry = new Date(now.getTime() + ttl(input.ttlMs, DEFAULT_AUTHORIZATION_TTL_MS)).getTime();
      const expiresAt = new Date(Math.min(requestedExpiry, Date.parse(assessment.expiresAt))).toISOString();
      if (Date.parse(expiresAt) <= now.getTime()) {
        throw new OperationalHazardHealthGateError("hazard_retry_authorization_expired", "The safer-attempt authorization has no remaining valid window", "evidence_insufficient");
      }
      const body = {
        missionId: assessment.missionId,
        runId: assessment.runId,
        healthAssessmentId: assessment.id,
        hazardNodeId: assessment.hazardNodeId,
        hazardProfileVersion: assessment.hazardProfileVersion,
        sourceAttackAttemptId: source.id,
        authorizedAttackAttemptId: candidate.id,
        sourceProcedureNodeId: sourceBinding.procedure_node_id,
        sourceProcedureVersionNodeId: sourceBinding.procedure_version_node_id,
        sourceParameterFingerprint,
        authorizedProcedureNodeId: candidateBinding.procedure_node_id,
        authorizedProcedureVersionNodeId: candidateBinding.procedure_version_node_id,
        authorizedParameterFingerprint,
        authorizedActionBindingHash: candidateActionBinding.binding_hash,
        authorizationBasis,
        targetContextFingerprint: candidateTarget,
        maxAttempts: 1,
        automaticRetry: false,
        contextPackId: assessment.contextPackId,
        healthAssessmentHash: assessment.assessmentHash,
        retryContractHash,
        reviewedAlternativeHash,
        retryConditionProofsHash: assessment.retryConditionProofsHash,
        issuedAt,
        expiresAt,
      };
      const authorizationHash = hashJson(body);
      const existing = this.database.prepare("SELECT * FROM operational_hazard_retry_authorizations WHERE authorization_hash = ? OR authorized_attack_attempt_id = ?")
        .get(authorizationHash, candidate.id) as RetryAuthorizationRow | undefined;
      if (existing) {
        if (existing.authorization_hash !== authorizationHash) {
          throw new OperationalHazardHealthGateError("hazard_retry_authorization_conflict", "This safer attempt already has a different immutable authorization", "conflict");
        }
        return mapAuthorization(existing);
      }
      const id = `hazard_retry_${randomUUID()}`;
      const auditId = this.#audit.append({
        missionId: assessment.missionId,
        runId: assessment.runId,
        actor: input.actor,
        action: "operational_hazard.safer_attempt_authorized",
        resourceType: "operational_hazard_retry_authorization",
        resourceId: id,
        reason: "Authorized one represented safer attempt after a passing local health gate",
        details: {
          authorizationHash,
          healthAssessmentId: assessment.id,
          hazardNodeId: assessment.hazardNodeId,
          sourceAttackAttemptId: source.id,
          authorizedAttackAttemptId: candidate.id,
          authorizationBasis,
          sourceParameterFingerprint,
          authorizedParameterFingerprint,
          authorizedActionBindingHash: candidateActionBinding.binding_hash,
          healthAssessmentHash: assessment.assessmentHash,
          retryContractHash,
          reviewedAlternativeHash,
          retryConditionProofsHash: assessment.retryConditionProofsHash,
          maxAttempts: 1,
          automaticRetry: false,
          expiresAt,
        },
        occurredAt: issuedAt,
      });
      const audit = this.database.prepare("SELECT record_hash FROM audit_records WHERE id = ?")
        .get(auditId) as { record_hash: string };
      this.database.prepare(`
        INSERT INTO operational_hazard_retry_authorizations (
          id, mission_id, run_id, health_assessment_id, hazard_node_id,
          hazard_profile_version, source_attack_attempt_id,
          authorized_attack_attempt_id, source_procedure_node_id,
          source_procedure_version_node_id, source_parameter_fingerprint,
          authorized_procedure_node_id, authorized_procedure_version_node_id,
          authorized_parameter_fingerprint, authorized_action_binding_hash,
          authorization_basis,
          target_context_fingerprint, max_attempts, automatic_retry,
          context_pack_id, issued_at, expires_at, authorization_hash,
          health_assessment_hash, retry_contract_hash,
          reviewed_alternative_hash, retry_condition_proofs_hash,
          audit_record_id, audit_record_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, assessment.missionId, assessment.runId, assessment.id,
        assessment.hazardNodeId, assessment.hazardProfileVersion, source.id,
        candidate.id, sourceBinding.procedure_node_id,
        sourceBinding.procedure_version_node_id, sourceParameterFingerprint,
        candidateBinding.procedure_node_id, candidateBinding.procedure_version_node_id,
        authorizedParameterFingerprint, candidateActionBinding.binding_hash,
        authorizationBasis, candidateTarget,
        assessment.contextPackId, issuedAt, expiresAt, authorizationHash,
        assessment.assessmentHash, retryContractHash, reviewedAlternativeHash,
        assessment.retryConditionProofsHash,
        auditId, audit.record_hash,
      );
      this.#events.append({
        missionId: assessment.missionId,
        runId: assessment.runId,
        eventType: "operational_hazard.safer_attempt_authorized",
        actorType: "operator",
        actorId: input.actor.id,
        summary: "One distinct safer attempt is authorized after the passing health gate; automatic retry remains disabled.",
        payload: {
          authorizationId: id,
          healthAssessmentId: assessment.id,
          hazardNodeId: assessment.hazardNodeId,
          sourceAttackAttemptId: source.id,
          authorizedAttackAttemptId: candidate.id,
          authorizationBasis,
          retryContractHash,
          reviewedAlternativeHash,
          retryConditionProofsHash: assessment.retryConditionProofsHash,
          maxAttempts: 1,
          automaticRetry: false,
          expiresAt,
        },
        contextPackId: assessment.contextPackId,
        sensitivity: "private",
        redaction: { targetContext: "sha256_fingerprint_only" },
      });
      return this.getAuthorization(id)!;
    });
  }

  consumeForAction(input: {
    readonly authorizationId: string;
    readonly attackAttemptId: string;
    readonly action: DurableAction;
    readonly actorId: string;
  }): OperationalHazardRetryConsumption {
    const authorizationId = assertId(input.authorizationId, "Retry authorization ID");
    const attackAttemptId = assertId(input.attackAttemptId, "Attack-attempt ID");
    const actorId = assertId(input.actorId, "Runtime actor ID");
    return inImmediateTransaction(this.database, () => {
      const existing = this.database.prepare("SELECT * FROM operational_hazard_retry_consumptions WHERE authorization_id = ?")
        .get(authorizationId) as ConsumptionRow | undefined;
      if (existing) {
        if (existing.attack_attempt_id === attackAttemptId && existing.action_id === input.action.id) {
          return mapConsumption(existing, true);
        }
        throw new OperationalHazardHealthGateError("hazard_retry_authorization_replayed", "This single-use safer-attempt authorization was already consumed", "conflict");
      }
      const authorization = this.getAuthorization(authorizationId);
      if (!authorization || authorization.authorizedAttackAttemptId !== attackAttemptId) {
        throw new OperationalHazardHealthGateError("hazard_retry_authorization_mismatch", "Retry authorization does not name this exact attack attempt", "scope_conflict");
      }
      const now = this.#clock();
      const consumedAt = now.toISOString();
      if (Date.parse(authorization.expiresAt) <= now.getTime()) {
        throw new OperationalHazardHealthGateError("hazard_retry_authorization_expired", "The safer-attempt authorization expired before action reservation", "evidence_insufficient");
      }
      const assessment = this.getAssessment(authorization.healthAssessmentId);
      if (!assessment || assessment.result !== "pass" || Date.parse(assessment.expiresAt) <= now.getTime()) {
        throw new OperationalHazardHealthGateError("hazard_health_assessment_expired", "A current passing health assessment is required at dispatch", "evidence_insufficient");
      }
      const profile = this.#requireVerifiedHazard(authorization.hazardNodeId, authorization.hazardProfileVersion, now);
      const retryContract = parseReviewedRetryContract(profile);
      this.#assertReviewedRetryContractNodes(retryContract, now);
      const retryContractHash = operationalHazardRetryContractHash(retryContract);
      const reviewedAlternativeHash = operationalHazardReviewedBindingFingerprint(retryContract.alternative);
      if (
        authorization.healthAssessmentHash !== assessment.assessmentHash
        || authorization.retryContractHash !== retryContractHash
        || authorization.reviewedAlternativeHash !== reviewedAlternativeHash
        || authorization.retryConditionProofsHash !== assessment.retryConditionProofsHash
        || assessment.retryContractHash !== retryContractHash
        || assessment.reviewedAlternativeHash !== reviewedAlternativeHash
        || !assessment.retryConditionProofs
        || !assessment.retryConditionProofsHash
        || hashJson(assessment.retryConditionProofs) !== assessment.retryConditionProofsHash
        || assessment.retryConditionProofs.some((proof) => !proof.satisfied)
      ) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_contract_changed",
          "Reviewed retry contract or its locally verified condition proofs changed after authorization",
          "conflict",
        );
      }
      this.#assertConditionProofs(
        retryContract,
        assessment.retryConditionProofs,
        assessment.verifiedEvidenceId,
        assessment.verifiedEvidenceHash,
      );
      const source = this.#requireAttempt(authorization.sourceAttackAttemptId);
      if (!['waiting_conditions', 'blocked'].includes(source.status)) {
        throw new OperationalHazardHealthGateError("hazard_retry_source_not_active", "The source hazard is no longer in its preserved blocked state", "conflict");
      }
      const attempt = this.#requireAttempt(attackAttemptId);
      if (attempt.status !== "ready") {
        throw new OperationalHazardHealthGateError("hazard_retry_attempt_not_ready", "The authorized safer attempt is no longer ready", "conflict");
      }
      if (this.#targetContextFingerprint(attempt) !== authorization.targetContextFingerprint) {
        throw new OperationalHazardHealthGateError("hazard_retry_cross_target_denied", "Target or environment changed after authorization", "scope_conflict");
      }
      if (attempt.recovery_source_attack_attempt_id !== source.id) {
        throw new OperationalHazardHealthGateError("hazard_retry_lineage_mismatch", "Recovery lineage changed or does not match this authorization", "scope_conflict");
      }
      const sourceBinding = this.#requireKnowledge(source.id);
      const candidateBinding = this.#requireKnowledge(attempt.id);
      if (
        operationalHazardReviewedBindingFingerprint(this.#reviewedBinding(sourceBinding))
          !== operationalHazardReviewedBindingFingerprint(retryContract.source)
        || operationalHazardReviewedBindingFingerprint(this.#reviewedBinding(candidateBinding))
          !== reviewedAlternativeHash
      ) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_binding_changed",
          "Source or safer procedure no longer matches the exact reviewed retry contract",
          "conflict",
        );
      }
      if (
        sourceBinding.procedure_node_id !== authorization.sourceProcedureNodeId
        || sourceBinding.procedure_version_node_id !== authorization.sourceProcedureVersionNodeId
        || this.#parameterFingerprint(sourceBinding) !== authorization.sourceParameterFingerprint
        || candidateBinding.procedure_node_id !== authorization.authorizedProcedureNodeId
        || candidateBinding.procedure_version_node_id !== authorization.authorizedProcedureVersionNodeId
        || this.#parameterFingerprint(candidateBinding) !== authorization.authorizedParameterFingerprint
      ) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_binding_changed",
          "Source or safer procedure knowledge no longer matches the immutable authorization",
          "conflict",
        );
      }
      const actionBinding = this.#requireActionBinding(attempt.id);
      if (
        actionBinding.binding_hash !== authorization.authorizedActionBindingHash
        || this.#actionBindingHash(input.action) !== authorization.authorizedActionBindingHash
      ) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_action_binding_mismatch",
          "The action being reserved does not exactly match the safer action arguments authorized after the health gate",
          "scope_conflict",
        );
      }
      if (
        input.action.missionId !== authorization.missionId
        || input.action.runId !== authorization.runId
        || input.action.stepId !== attempt.step_id
        || input.action.actionClass !== attempt.action_class
        || input.action.status !== "running"
      ) {
        throw new OperationalHazardHealthGateError("hazard_retry_action_mismatch", "Reserved action does not match the authorized safer attempt", "scope_conflict");
      }
      this.#assertActionTarget(attempt, input.action.target);
      const consumptionBody = {
        authorizationId,
        attackAttemptId,
        actionId: input.action.id,
        actionFingerprint: input.action.fingerprint,
        contextPackId: authorization.contextPackId,
        consumedAt,
      };
      const consumptionHash = hashJson(consumptionBody);
      const auditId = this.#audit.append({
        missionId: authorization.missionId,
        runId: authorization.runId,
        actor: { id: actorId, type: "worker" },
        action: "operational_hazard.safer_attempt_consumed",
        resourceType: "operational_hazard_retry_authorization",
        resourceId: authorizationId,
        reason: "Consumed the single-use authorization in the same transaction as the represented action reservation",
        details: {
          authorizationId,
          attackAttemptId,
          actionId: input.action.id,
          actionFingerprint: input.action.fingerprint,
          consumptionHash,
          maxAttempts: 1,
          automaticRetry: false,
        },
        occurredAt: consumedAt,
      });
      const audit = this.database.prepare("SELECT record_hash FROM audit_records WHERE id = ?")
        .get(auditId) as { record_hash: string };
      this.database.prepare(`
        INSERT INTO operational_hazard_retry_consumptions (
          authorization_id, attack_attempt_id, action_id, context_pack_id,
          consumed_at, consumption_hash, audit_record_id, audit_record_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        authorizationId, attackAttemptId, input.action.id,
        authorization.contextPackId, consumedAt, consumptionHash,
        auditId, audit.record_hash,
      );
      this.#events.append({
        missionId: authorization.missionId,
        runId: authorization.runId,
        eventType: "operational_hazard.safer_attempt_consumed",
        actorType: "worker",
        actorId,
        summary: "The single-use safer-attempt authorization was consumed with this exact action; no automatic retry remains.",
        payload: {
          authorizationId,
          attackAttemptId,
          actionId: input.action.id,
          actionFingerprint: input.action.fingerprint,
          maxAttempts: 1,
          automaticRetry: false,
        },
        contextPackId: authorization.contextPackId,
        sensitivity: "private",
        redaction: { targetContext: "sha256_fingerprint_only" },
      });
      return mapConsumption(this.database.prepare("SELECT * FROM operational_hazard_retry_consumptions WHERE authorization_id = ?")
        .get(authorizationId) as ConsumptionRow, false);
    });
  }

  #requireVerifiedHazard(hazardNodeId: string, expectedVersion: number, now: Date): HazardProfileRow {
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) {
      throw new OperationalHazardHealthGateError("hazard_profile_version_invalid", "Hazard profile version is invalid");
    }
    const row = this.database.prepare(`
      SELECT hp.* FROM operational_hazard_profiles hp
      JOIN memory_nodes hazard ON hazard.id = hp.node_id
      JOIN memory_nodes procedure ON procedure.id = hp.procedure_node_id
      LEFT JOIN memory_nodes procedure_version ON procedure_version.id = hp.procedure_version_node_id
      WHERE hp.node_id = ? AND hp.version = ?
        AND hazard.node_type = 'operational_hazard'
        AND hazard.scope = 'global' AND hazard.lifecycle_status = 'verified'
        AND (hazard.expires_at IS NULL OR hazard.expires_at > ?)
        AND procedure.node_type = 'attack_procedure'
        AND procedure.scope = 'global' AND procedure.lifecycle_status = 'verified'
        AND (procedure.expires_at IS NULL OR procedure.expires_at > ?)
        AND procedure_version.node_type = 'procedure_version'
        AND procedure_version.scope = 'global' AND procedure_version.lifecycle_status = 'verified'
        AND (procedure_version.expires_at IS NULL OR procedure_version.expires_at > ?)
    `).get(hazardNodeId, expectedVersion, now.toISOString(), now.toISOString(), now.toISOString()) as HazardProfileRow | undefined;
    if (!row || row.confidence < 0.85 || (row.fresh_until && Date.parse(row.fresh_until) <= now.getTime())) {
      throw new OperationalHazardHealthGateError("verified_operational_hazard_required", "Hazard memory is missing, stale, candidate, or no longer verified", "evidence_insufficient");
    }
    return row;
  }

  #requireAttempt(id: string): AttemptScopeRow {
    const row = this.database.prepare(`
      SELECT aa.*, m.engagement_id, m.scope_json
      FROM attack_attempts aa JOIN missions m ON m.id = aa.mission_id
      WHERE aa.id = ?
    `).get(id) as AttemptScopeRow | undefined;
    if (!row) throw new OperationalHazardHealthGateError("attack_attempt_not_found", "Attack attempt was not found", "conflict");
    return row;
  }

  #requireKnowledge(attemptId: string): KnowledgeRow {
    const row = this.database.prepare("SELECT * FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = ?")
      .get(attemptId) as KnowledgeRow | undefined;
    if (!row) throw new OperationalHazardHealthGateError("attack_procedure_knowledge_required", "Exact reusable procedure knowledge is required", "evidence_insufficient");
    return row;
  }

  #requireActionBinding(attemptId: string): ActionBindingRow {
    const row = this.database.prepare(`
      SELECT * FROM attack_attempt_action_bindings WHERE attack_attempt_id = ?
    `).get(attemptId) as ActionBindingRow | undefined;
    if (!row) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_action_binding_required",
        "A recovery attempt requires an immutable represented-action binding",
        "evidence_insufficient",
      );
    }
    return row;
  }

  #actionBindingHash(action: DurableAction): string {
    return hashJson({
      missionId: action.missionId,
      runId: action.runId,
      stepId: action.stepId,
      actionType: action.actionType,
      actionClass: action.actionClass,
      normalizedArguments: action.arguments,
      scopedTarget: action.target,
    });
  }

  #unresolvedRelevantHazardSources(candidate: AttemptScopeRow): readonly string[] {
    const candidateBinding = this.database.prepare(`
      SELECT procedure_node_id FROM attack_attempt_knowledge_contexts
      WHERE attack_attempt_id = ?
    `).get(candidate.id) as { readonly procedure_node_id: string } | undefined;
    if (!candidateBinding) return [];
    const now = this.#clock().toISOString();
    const rows = this.database.prepare(`
      SELECT DISTINCT source.id
      FROM attack_attempts source
      JOIN attack_attempt_knowledge_contexts source_binding
        ON source_binding.attack_attempt_id = source.id
      JOIN operational_hazard_profiles profile
        ON profile.procedure_node_id = source_binding.procedure_node_id
       AND profile.procedure_version_node_id IS source_binding.procedure_version_node_id
      JOIN memory_nodes hazard ON hazard.id = profile.node_id
      WHERE source.id <> ?
        AND source.mission_id = ? AND source.run_id = ?
        AND source.status IN ('waiting_conditions', 'blocked')
        AND source.target_asset_id IS ?
        AND source.target_service_id IS ?
        AND (? = source_binding.procedure_node_id
          OR ? = profile.alternative_procedure_node_id)
        AND hazard.node_type = 'operational_hazard'
        AND hazard.scope = 'global' AND hazard.lifecycle_status = 'verified'
        AND (hazard.expires_at IS NULL OR hazard.expires_at > ?)
        AND profile.confidence >= 0.85
        AND (profile.fresh_until IS NULL OR profile.fresh_until > ?)
      ORDER BY source.created_at, source.id
    `).all(
      candidate.id,
      candidate.mission_id,
      candidate.run_id,
      candidate.target_asset_id,
      candidate.target_service_id,
      candidateBinding.procedure_node_id,
      candidateBinding.procedure_node_id,
      now,
      now,
    ) as Array<{ readonly id: string }>;
    const matcher = new OperationalHazardMatcher(this.database, { clock: this.#clock });
    return rows
      .filter(({ id }) => matcher.assessAttackAttempt(id)?.decision === "block")
      .map(({ id }) => id);
  }

  #requireHealthAction(attempt: AttemptScopeRow, actionId: string): DurableAction {
    const row = this.database.prepare(`
      SELECT id, mission_id, run_id, step_id, action_type, action_class,
        fingerprint, normalized_arguments_json, scoped_target, status,
        intent_summary, guided_decision_id, contract_id, context_pack_id,
        result_summary, error_category, retry_count, progress_signature,
        created_at, started_at, ended_at
      FROM actions WHERE id = ?
    `).get(actionId) as Record<string, unknown> | undefined;
    if (!row || row.mission_id !== attempt.mission_id || row.run_id !== attempt.run_id) {
      throw new OperationalHazardHealthGateError("hazard_health_action_scope_mismatch", "Health-check action belongs to another mission or run", "scope_conflict");
    }
    if (row.action_type !== HEALTH_ACTION_TYPE || row.status !== "succeeded") {
      throw new OperationalHazardHealthGateError("hazard_health_action_not_verified", "A succeeded represented operational health-check action is required", "evidence_insufficient");
    }
    const stored = parseObject(String(row.normalized_arguments_json), "Health action arguments");
    const orchestration = stored.orchestration && typeof stored.orchestration === "object" && !Array.isArray(stored.orchestration)
      ? stored.orchestration as Record<string, unknown>
      : {};
    if (orchestration.destructive === true) {
      throw new OperationalHazardHealthGateError("hazard_health_action_destructive", "A destructive action cannot establish the safe baseline", "policy_denied");
    }
    this.#assertActionTarget(attempt, String(row.scoped_target ?? ""));
    return {
      id: String(row.id), missionId: String(row.mission_id), runId: String(row.run_id),
      stepId: String(row.step_id ?? ""), actionType: String(row.action_type),
      actionClass: String(row.action_class), fingerprint: String(row.fingerprint),
      arguments: stored.input && typeof stored.input === "object" && !Array.isArray(stored.input)
        ? stored.input as Record<string, unknown> : {},
      target: String(row.scoped_target ?? ""), kind: "tool",
      intentSummary: String(row.intent_summary), status: "succeeded",
      idempotent: orchestration.idempotent === true, destructive: false,
      guidedDecisionId: row.guided_decision_id ? String(row.guided_decision_id) : null,
      contractId: row.contract_id ? String(row.contract_id) : null,
      contextPackId: row.context_pack_id ? String(row.context_pack_id) : null,
      resultSummary: row.result_summary ? String(row.result_summary) : null,
      errorCategory: null, retryCount: Number(row.retry_count),
      progressSignature: row.progress_signature ? String(row.progress_signature) : null,
      createdAt: String(row.created_at), startedAt: row.started_at ? String(row.started_at) : null,
      endedAt: row.ended_at ? String(row.ended_at) : null,
    };
  }

  #requireRegisteredLocalEvaluator(): void {
    const row = this.database.prepare(`
      SELECT evaluator_hash, enabled FROM operational_hazard_local_evaluators
      WHERE evaluator_version = ?
    `).get(LOCAL_EVALUATOR_VERSION) as {
      readonly evaluator_hash: string;
      readonly enabled: number;
    } | undefined;
    if (!row || row.enabled !== 1 || row.evaluator_hash !== LOCAL_EVALUATOR_HASH) {
      throw new OperationalHazardHealthGateError(
        "hazard_health_evaluator_integrity_failed",
        "The pinned trusted local health evaluator is missing, disabled, or changed",
        "evidence_insufficient",
      );
    }
  }

  #evaluateVerifiedLocalEvidence(
    attempt: AttemptScopeRow,
    action: DurableAction,
    evidenceId: string,
    expectedHash: string,
    retryContract: OperationalHazardReviewedRetryContract,
    retryContractHash: string,
  ): {
    readonly result: HealthResult;
    readonly retryConditionProofs: readonly OperationalHazardRetryConditionProof[];
  } {
    const row = this.database.prepare(`
      SELECT mission_id, run_id, action_id, evidence_type, content_hash,
        provenance_json, verification_state, source, created_by
      FROM evidence WHERE id = ?
    `).get(evidenceId) as {
      mission_id: string; run_id: string | null; action_id: string | null;
      evidence_type: string; content_hash: string; provenance_json: string;
      verification_state: string; source: string; created_by: string;
    } | undefined;
    if (!row || row.mission_id !== attempt.mission_id || row.run_id !== attempt.run_id || row.action_id !== action.id) {
      throw new OperationalHazardHealthGateError("hazard_health_evidence_scope_mismatch", "Health evidence does not belong to the represented health-check action", "scope_conflict");
    }
    const provenance = parseObject(row.provenance_json, "Health evidence provenance");
    const forbiddenType = ["operator_supplied", "guided_text_result", "guided_manual_result"].includes(row.evidence_type);
    if (
      row.verification_state !== "verified"
      || row.content_hash !== expectedHash
      || forbiddenType
      || containsPublicModelAttribution(row.source)
      || containsPublicModelAttribution(row.created_by)
      || containsPublicModelAttribution(provenance)
    ) {
      throw new OperationalHazardHealthGateError("hazard_health_verified_local_evidence_required", "Unverified, operator-acknowledged, or public-model evidence cannot satisfy the health gate", "evidence_insufficient");
    }
    const verified = this.database.prepare(`
      SELECT 1 FROM evidence_chain_events
      WHERE evidence_id = ? AND event_type = 'verified' LIMIT 1
    `).get(evidenceId);
    if (!verified) {
      throw new OperationalHazardHealthGateError("hazard_health_evidence_custody_required", "Health evidence has no immutable verification custody event", "evidence_insufficient");
    }
    const health = provenance.healthAssessment;
    if (!health || typeof health !== "object" || Array.isArray(health)) {
      throw new OperationalHazardHealthGateError(
        "hazard_health_evidence_schema_invalid",
        "Verified health evidence does not contain the typed local baseline assessment",
        "evidence_insufficient",
      );
    }
    const typed = health as Record<string, unknown>;
    if (
      typed.schema !== LOCAL_HEALTH_EVIDENCE_SCHEMA
      || typeof typed.baselineRestored !== "boolean"
      || typed.retryContractHash !== retryContractHash
      || !typed.retryConditionResults
      || typeof typed.retryConditionResults !== "object"
      || Array.isArray(typed.retryConditionResults)
    ) {
      throw new OperationalHazardHealthGateError(
        "hazard_health_evidence_schema_invalid",
        "Verified health evidence has an unsupported schema, contract hash, baseline, or retry-condition result set",
        "evidence_insufficient",
      );
    }
    const results = typed.retryConditionResults as Record<string, unknown>;
    const expectedKeys = retryContract.retryValidConditions.map((condition) => condition.evidenceKey).sort();
    const actualKeys = Object.keys(results).sort();
    if (
      canonicalJson(actualKeys) !== canonicalJson(expectedKeys)
      || actualKeys.some((key) => typeof results[key] !== "boolean")
    ) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_condition_proof_incomplete",
        "Verified local evidence must prove every reviewed retry-valid condition exactly once and may not add unreviewed conditions",
        "evidence_insufficient",
      );
    }
    const retryConditionProofs = retryContract.retryValidConditions.map((condition) => ({
      conditionId: condition.id,
      evidenceKey: condition.evidenceKey,
      satisfied: results[condition.evidenceKey] === true,
      verifiedEvidenceId: evidenceId,
      verifiedEvidenceHash: expectedHash,
      evaluatorVersion: LOCAL_EVALUATOR_VERSION,
      evaluatorHash: LOCAL_EVALUATOR_HASH,
    }));
    return {
      result: typed.baselineRestored === true && retryConditionProofs.every((proof) => proof.satisfied)
        ? "pass"
        : "fail",
      retryConditionProofs,
    };
  }

  #assertContextPack(attempt: AttemptScopeRow, packId: string, actionId: string, requiredNodes: readonly string[]): void {
    const pack = this.database.prepare(`
      SELECT mission_id, run_id, action_id FROM memory_context_packs WHERE id = ?
    `).get(packId) as { mission_id: string | null; run_id: string | null; action_id: string | null } | undefined;
    if (!pack || pack.mission_id !== attempt.mission_id || pack.run_id !== attempt.run_id || (pack.action_id && pack.action_id !== actionId)) {
      throw new OperationalHazardHealthGateError("hazard_health_context_pack_scope_mismatch", "Health-gate Context Pack belongs to another scope", "scope_conflict");
    }
    const rows = this.database.prepare(`
      SELECT node_id, used FROM memory_context_items WHERE context_pack_id = ?
    `).all(packId) as Array<{ node_id: string; used: number }>;
    const used = new Set(rows.filter((row) => row.used === 1).map((row) => row.node_id));
    if (requiredNodes.some((nodeId) => !used.has(nodeId))) {
      throw new OperationalHazardHealthGateError("hazard_health_context_pack_incomplete", "Context Pack did not use the exact hazard, procedure, and procedure version", "evidence_insufficient");
    }
  }

  #targetContextFingerprint(attempt: AttemptScopeRow): string {
    const topology = (id: string | null): Readonly<Record<string, unknown>> | null => {
      if (!id) return null;
      const row = this.database.prepare(`
        SELECT id, mission_id, run_id, node_type, normalized_identity,
          scope_status, properties_json FROM topology_nodes WHERE id = ?
      `).get(id) as {
        id: string; mission_id: string; run_id: string | null; node_type: string;
        normalized_identity: string; scope_status: string; properties_json: string;
      } | undefined;
      if (!row || row.mission_id !== attempt.mission_id || (row.run_id && row.run_id !== attempt.run_id)) {
        throw new OperationalHazardHealthGateError("hazard_target_context_missing", "Canonical target context is unavailable for the attack attempt", "scope_conflict");
      }
      return {
        id: row.id,
        nodeType: row.node_type,
        normalizedIdentityHash: sha256(row.normalized_identity.normalize("NFKC").trim().toLowerCase()),
        scopeStatus: row.scope_status,
        propertiesHash: hashJson(parseObject(row.properties_json, "Topology properties")),
      };
    };
    const missionTargets = (this.database.prepare(`
      SELECT target_type, disposition, normalized_target FROM mission_targets
      WHERE mission_id = ? ORDER BY target_type, disposition, normalized_target
    `).all(attempt.mission_id) as Array<{ target_type: string; disposition: string; normalized_target: string }>).map((row) => ({
      targetType: row.target_type,
      disposition: row.disposition,
      normalizedTargetHash: sha256(row.normalized_target.normalize("NFKC").trim().toLowerCase()),
    }));
    return hashJson({
      missionId: attempt.mission_id,
      runId: attempt.run_id,
      engagementFingerprint: sha256(attempt.engagement_id ?? "no-engagement"),
      scopeHash: hashJson(parseObject(attempt.scope_json, "Mission scope")),
      missionTargets,
      targetAsset: topology(attempt.target_asset_id),
      targetService: topology(attempt.target_service_id),
    });
  }

  #assertActionTarget(attempt: AttemptScopeRow, actionTarget: string): void {
    const normalized = actionTarget.normalize("NFKC").trim().toLowerCase();
    if (!normalized) throw new OperationalHazardHealthGateError("hazard_action_target_required", "Represented health/retry action needs an exact target", "scope_conflict");
    const candidates = new Set<string>();
    for (const target of this.database.prepare(`
      SELECT target, normalized_target FROM mission_targets WHERE mission_id = ? AND disposition = 'allowed'
    `).all(attempt.mission_id) as Array<{ target: string; normalized_target: string }>) {
      candidates.add(target.target.normalize("NFKC").trim().toLowerCase());
      candidates.add(target.normalized_target.normalize("NFKC").trim().toLowerCase());
    }
    for (const id of [attempt.target_asset_id, attempt.target_service_id]) {
      if (!id) continue;
      const row = this.database.prepare("SELECT primary_label, normalized_identity FROM topology_nodes WHERE id = ? AND mission_id = ?")
        .get(id, attempt.mission_id) as { primary_label: string; normalized_identity: string } | undefined;
      if (row) {
        candidates.add(row.primary_label.normalize("NFKC").trim().toLowerCase());
        candidates.add(row.normalized_identity.normalize("NFKC").trim().toLowerCase());
      }
    }
    if (!candidates.has(normalized)) {
      throw new OperationalHazardHealthGateError("hazard_action_target_mismatch", "Represented action target does not match the canonical private target context", "scope_conflict");
    }
  }

  #parameterFingerprint(binding: KnowledgeRow): string {
    return hashJson({
      procedureNodeId: binding.procedure_node_id,
      procedureVersionNodeId: binding.procedure_version_node_id,
      normalizedParameters: parseObject(binding.normalized_parameters_json, "Attack parameters"),
      load: binding.load,
      concurrency: binding.concurrency,
      timingWindowMs: binding.timing_window_ms,
    });
  }

  #reviewedBinding(binding: KnowledgeRow): OperationalHazardReviewedAttemptBinding {
    if (!binding.procedure_version_node_id) {
      throw new OperationalHazardHealthGateError(
        "hazard_exact_procedure_version_required",
        "Reviewed retry binding requires an exact procedure version",
        "evidence_insufficient",
      );
    }
    return {
      procedureNodeId: binding.procedure_node_id,
      procedureVersionNodeId: binding.procedure_version_node_id,
      normalizedParameters: parseObject(binding.normalized_parameters_json, "Attack parameters") as Readonly<Record<string, Primitive>>,
      load: binding.load,
      concurrency: binding.concurrency,
      timingWindowMs: binding.timing_window_ms,
    };
  }

  #assertReviewedRetryContractNodes(
    contract: OperationalHazardReviewedRetryContract,
    now: Date,
  ): void {
    const assertNode = (id: string, expectedType: "attack_procedure" | "procedure_version"): void => {
      const row = this.database.prepare(`
        SELECT node_type, scope, lifecycle_status, confidence, expires_at
        FROM memory_nodes WHERE id = ?
      `).get(id) as {
        readonly node_type: string;
        readonly scope: string;
        readonly lifecycle_status: string;
        readonly confidence: number;
        readonly expires_at: string | null;
      } | undefined;
      if (
        !row
        || row.node_type !== expectedType
        || row.scope !== "global"
        || row.lifecycle_status !== "verified"
        || row.confidence < 0.85
        || (row.expires_at && Date.parse(row.expires_at) <= now.getTime())
      ) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_contract_reference_unverified",
          "Reviewed retry contract references missing, stale, or unverified attack knowledge",
          "evidence_insufficient",
        );
      }
    };
    assertNode(contract.source.procedureNodeId, "attack_procedure");
    assertNode(contract.source.procedureVersionNodeId, "procedure_version");
    assertNode(contract.alternative.procedureNodeId, "attack_procedure");
    assertNode(contract.alternative.procedureVersionNodeId, "procedure_version");
  }

  #assertConditionProofs(
    contract: OperationalHazardReviewedRetryContract,
    proofs: readonly OperationalHazardRetryConditionProof[],
    evidenceId: string,
    evidenceHash: string,
  ): void {
    if (proofs.length !== contract.retryValidConditions.length) {
      throw new OperationalHazardHealthGateError(
        "hazard_retry_condition_proof_incomplete",
        "Retry-condition proof count does not match the reviewed contract",
        "evidence_insufficient",
      );
    }
    for (let index = 0; index < contract.retryValidConditions.length; index += 1) {
      const condition = contract.retryValidConditions[index]!;
      const proof = proofs[index]!;
      if (
        proof.conditionId !== condition.id
        || proof.evidenceKey !== condition.evidenceKey
        || proof.verifiedEvidenceId !== evidenceId
        || proof.verifiedEvidenceHash !== evidenceHash
        || proof.evaluatorVersion !== LOCAL_EVALUATOR_VERSION
        || proof.evaluatorHash !== LOCAL_EVALUATOR_HASH
      ) {
        throw new OperationalHazardHealthGateError(
          "hazard_retry_condition_proof_mismatch",
          "Retry-condition proof does not exactly match the reviewed condition, evidence, and pinned evaluator",
          "evidence_insufficient",
        );
      }
    }
  }

}

export const OPERATIONAL_HAZARD_HEALTH_ACTION_TYPE = HEALTH_ACTION_TYPE;

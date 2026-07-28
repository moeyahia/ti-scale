import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db/transaction";
import {
  resolveAutonomousRunMemoryPolicy,
} from "../brain-runtime/AutonomousRunMemoryPolicy";
import {
  getMemoryControlPolicy,
  memoryUseAllowed,
} from "../memory/MemoryControlPolicy";
import {
  isAttackCentricReusableNodeType,
  type MemoryNodeType,
} from "../memory/types";
import { canonicalJson, hashCanonical } from "../missions/canonical";
import type {
  ResearchDataClassification,
  ResearchDisclosureClass,
  ResearchSourceItem,
} from "../research/LlmExposurePolicy";
import {
  assessPromptInjection,
  sanitizeResearchText,
} from "../research/LlmExposurePolicy";

export const PROVIDER_ADVISORY_BRAIN_CONTEXT_POLICY_VERSION =
  "ti-scale.provider-advisory-brain-context.v2" as const;
export const PROVIDER_ADVISORY_BRAIN_CONTEXT_RESULT_SCHEMA_VERSION =
  "ti-scale.provider-advisory-brain-context-result.v2" as const;

export type ProviderAdvisoryBrainDisclosureClass =
  | "public_only"
  | "sanitized_internal";

export type ProviderAdvisoryBrainContextRejectionReason =
  | "confirmation_rejected"
  | "confirmation_not_approved"
  | "lifecycle_not_disclosable"
  | "stale"
  | "expired"
  | "forgotten"
  | "cross_engagement_scope"
  | "provider_disclosure_not_approved"
  | "autonomous_use_not_approved"
  | "operational_memory_disabled"
  | "contract_memory_excluded"
  | "internal_not_allowed"
  | "sensitivity_not_disclosable"
  | "raw_operational_record_forbidden"
  | "credential_or_secret_content"
  | "raw_payload_content"
  | "prompt_injection_quarantined"
  | "empty_after_sanitization"
  | "item_budget_exceeded"
  | "byte_budget_exceeded";

export interface ProviderAdvisoryBrainContextSelectedDisposition {
  readonly nodeId: string;
  readonly sourceItemId: string;
  readonly reasonCode:
    | "public_disclosure_approved"
    | "sanitized_internal_disclosure_approved";
  readonly classification: "public" | "internal";
  readonly disclosureClass: "public" | "internal_sanitized";
  readonly contentHash: string;
  readonly contentBytes: number;
  readonly sanitizationActions: readonly string[];
}

export interface ProviderAdvisoryBrainContextRejectedDisposition {
  readonly nodeId: string;
  readonly reasonCode: ProviderAdvisoryBrainContextRejectionReason;
  readonly promptInjectionRuleIds: readonly string[];
}

export interface ProviderAdvisoryBrainContextTelemetry {
  readonly auditRecordId: string;
  readonly reused: boolean;
  readonly policyVersion: typeof PROVIDER_ADVISORY_BRAIN_CONTEXT_POLICY_VERSION;
  readonly inputFingerprint: string;
  readonly outputHash: string;
  readonly maximumItems: number;
  readonly maximumBytes: number;
  readonly selected: readonly ProviderAdvisoryBrainContextSelectedDisposition[];
  readonly rejected: readonly ProviderAdvisoryBrainContextRejectedDisposition[];
  readonly selectedBytes: number;
  readonly consumerBinding: ProviderAdvisoryBrainContextConsumerBinding;
}

export interface ProviderAdvisoryBrainContextConsumerBinding {
  readonly schemaVersion:
    "ti-scale.provider-advisory-context-consumer-binding.v1";
  readonly bindingType:
    | "direct_context_consumer"
    | "signed_provider_advisor_delegation";
  readonly retrievedByActorId: string;
  readonly consumerActorId: string;
  readonly contractId: string;
  readonly contractVersion: number;
  readonly contractHash: string;
  readonly planningSelectionHash: string;
  readonly bindingHash: string;
}

export interface ProviderAdvisoryBrainContextResult {
  readonly schemaVersion:
    typeof PROVIDER_ADVISORY_BRAIN_CONTEXT_RESULT_SCHEMA_VERSION;
  readonly contextPackId: string;
  readonly disclosureClass: ProviderAdvisoryBrainDisclosureClass;
  readonly consumerBinding: ProviderAdvisoryBrainContextConsumerBinding;
  readonly items: readonly ResearchSourceItem[];
  readonly telemetry: ProviderAdvisoryBrainContextTelemetry;
}

export interface PrepareProviderAdvisoryBrainContextInput {
  readonly missionId: string;
  readonly runId: string;
  readonly contextPackId: string;
  /** Exact actor that retrieved and persisted the canonical Context Pack. */
  readonly retrievedByActorId: string;
  /** Exact signed provider-advisor consumer of the disclosed projection. */
  readonly actorId: string;
  readonly disclosureClass: ProviderAdvisoryBrainDisclosureClass;
  /**
   * Exact local target/tool/MCP bindings from the candidate catalog. They are
   * used only as local redaction terms and are persisted solely as one hash.
   */
  readonly opaqueTerms?: readonly string[];
  readonly maximumItems?: number;
  readonly maximumBytes?: number;
}

export interface ProviderAdvisoryBrainContextAdapterOptions {
  readonly database: SqliteDatabase;
  readonly clock?: () => Date;
}

interface MissionRow {
  readonly journey: string;
  readonly control_plane: string;
  readonly engagement_id: string | null;
}

interface RunRow {
  readonly mission_id: string;
  readonly journey: string;
  readonly control_plane: string;
}

interface ContextPackRow {
  readonly mission_id: string | null;
  readonly run_id: string | null;
  readonly journey: string;
  readonly scope_policy_json: string;
  readonly release_data_class: string;
  readonly created_by: string;
}

interface ConsumerContractRow {
  readonly contract_id: string | null;
  readonly contract_version_bound: number | null;
  readonly contract_hash_bound: string | null;
  readonly version: number;
  readonly state: string;
  readonly contract_hash: string;
  readonly action_policy_json: string;
}

interface ContextNodeRow {
  readonly node_id: string;
  readonly rank: number;
  readonly relevance_reason: string;
  readonly node_type: string;
  readonly title: string;
  readonly summary: string;
  readonly scope: string;
  readonly engagement_id: string | null;
  readonly mission_id: string | null;
  readonly sensitivity: string;
  readonly lifecycle_status: string;
  readonly confirmation_state: string;
  readonly provenance_json: string;
  readonly retention_policy_json: string;
  readonly expires_at: string | null;
  readonly version: number;
}

interface ExistingAuditRow {
  readonly mission_id: string | null;
  readonly run_id: string | null;
  readonly journey: string | null;
  readonly actor_id: string | null;
  readonly action: string;
  readonly resource_type: string;
  readonly resource_id: string | null;
  readonly details_json: string;
  readonly occurred_at: string;
}

interface AuditDetails {
  readonly schemaVersion:
    typeof PROVIDER_ADVISORY_BRAIN_CONTEXT_RESULT_SCHEMA_VERSION;
  readonly policyVersion:
    typeof PROVIDER_ADVISORY_BRAIN_CONTEXT_POLICY_VERSION;
  readonly inputFingerprint: string;
  readonly outputHash: string;
  readonly actorId: string;
  readonly retrievedByActorId: string;
  readonly contextPackId: string;
  readonly disclosureClass: ProviderAdvisoryBrainDisclosureClass;
  readonly opaqueTermsHash: string;
  readonly maximumItems: number;
  readonly maximumBytes: number;
  readonly selectedBytes: number;
  readonly memoryControlPolicyVersion: number;
  readonly memoryControlPolicyHash: string;
  readonly contractMemoryPolicyHash: string;
  readonly consumerBinding:
    ProviderAdvisoryBrainContextConsumerBinding;
  readonly selected: readonly ProviderAdvisoryBrainContextSelectedDisposition[];
  readonly rejected: readonly ProviderAdvisoryBrainContextRejectedDisposition[];
}

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,255}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const DEFAULT_MAXIMUM_ITEMS = 6;
const MAXIMUM_ITEMS = 8;
const DEFAULT_MAXIMUM_BYTES = 4_000;
const MAXIMUM_BYTES = 8_000;
const MAXIMUM_OPAQUE_TERMS = 128;
const MAXIMUM_OPAQUE_TERM_BYTES = 512;

const RAW_OPERATIONAL_NODE_TYPES = new Set([
  "mission",
  "run",
  "plan",
  "phase",
  "step",
  "target",
  "asset",
  "entity",
  "decision",
  "evidence",
  "finding",
  "artifact",
  "report",
  "source",
  "tool",
  "mcp_capability",
  "script_artifact",
  "tool_artifact",
]);

/**
 * Evidence-backed objective facts may use `not_required` confirmation only
 * after reaching the verified lifecycle. Personal preferences, procedures,
 * tactics, lessons and other reusable judgments always require explicit
 * confirmed consent.
 */
const OBJECTIVE_NOT_REQUIRED_NODE_TYPES = new Set([
  "technology_product",
  "exact_version_fingerprint",
  "version_range_fingerprint",
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
  "cve",
  "advisory",
  "cwe",
  "misconfiguration",
  "discovery_pattern",
  "fingerprint_pattern",
  "outcome",
  "evidence_pattern",
  "validation_pattern",
  "detection",
  "remediation",
  "target_state_transition",
  "health_check",
]);

const SECRET_SANITIZATION_ACTIONS = new Set([
  "private_key_redacted",
  "authorization_redacted",
  "named_secret_redacted",
  "jwt_redacted",
  "provider_token_redacted",
]);

const RAW_PAYLOAD_PATTERN =
  /(?:```|<script\b|(?:^|\s)(?:curl|wget|nmap|masscan|naabu|sqlmap|ffuf|gobuster|feroxbuster|bash|sh|powershell|cmd(?:\.exe)?)\s+(?:--?|\$|\/)|(?:^|\s)(?:GET|POST|PUT|PATCH|DELETE)\s+\/\S+\s+HTTP\/\d)/iu;

export class ProviderAdvisoryBrainContextPolicyError extends Error {
  readonly name = "ProviderAdvisoryBrainContextPolicyError";

  constructor(
    readonly code:
      | "provider_advisory_memory_control_disabled"
      | "provider_advisory_autonomous_memory_use_revoked"
      | "provider_advisory_context_retriever_mismatch"
      | "provider_advisory_context_consumer_not_authorized"
      | "provider_advisory_contract_memory_policy_invalid",
    message: string,
  ) {
    super(message);
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function assertId(value: string, label: string): void {
  if (!SAFE_ID.test(value)) throw new TypeError(`${label} is invalid`);
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  maximum: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (
    !Number.isSafeInteger(resolved)
    || resolved < 1
    || resolved > maximum
  ) {
    throw new RangeError(`${label} must be an integer from 1 through ${maximum}`);
  }
  return resolved;
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseRecord(value: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(value) as unknown;
    return plainRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function canonicalOpaqueTerms(
  input: readonly string[] | undefined,
): readonly string[] {
  if (input !== undefined && !Array.isArray(input)) {
    throw new TypeError("Provider advisory opaque terms must be a string list");
  }
  const result = [...new Set((input ?? []).map((value) => {
    if (typeof value !== "string") {
      throw new TypeError("Provider advisory opaque terms must contain strings");
    }
    const normalized = value.normalize("NFKC").trim();
    if (Buffer.byteLength(normalized, "utf8") > MAXIMUM_OPAQUE_TERM_BYTES) {
      throw new RangeError("Provider advisory opaque term exceeds its bounded size");
    }
    return normalized;
  }).filter((value) => value.length >= 3))];
  if (result.length > MAXIMUM_OPAQUE_TERMS) {
    throw new RangeError(
      `Provider advisory context accepts at most ${MAXIMUM_OPAQUE_TERMS} opaque terms`,
    );
  }
  return Object.freeze(result.sort((left, right) =>
    right.length - left.length || left.localeCompare(right)));
}

function redactOpaqueTerms(
  value: string,
  opaqueTerms: readonly string[],
): string {
  let redacted = value;
  for (const term of opaqueTerms) {
    redacted = redacted.replace(
      new RegExp(escapeRegExp(term), "giu"),
      "[OPAQUE_BINDING]",
    );
  }
  return redacted
    .replace(/(?<![\w.])(?:\/(?:root|home|tmp|var|opt|etc)\/[^\s,;]+)/giu, "[REDACTED_PATH]")
    .replace(/\b[A-Z]:\\[^\s,;]+/giu, "[REDACTED_PATH]");
}

function containsOpaqueTerm(
  value: string,
  opaqueTerms: readonly string[],
): boolean {
  const normalized = value.toLocaleLowerCase("en-US");
  return opaqueTerms.some((term) =>
    normalized.includes(term.toLocaleLowerCase("en-US")));
}

function sourceItemId(contextPackId: string, nodeId: string): string {
  return `brain_context_${sha256(`${contextPackId}\0${nodeId}`).slice(0, 24)}`;
}

function lifecycleRejection(
  lifecycle: string,
): ProviderAdvisoryBrainContextRejectionReason | undefined {
  if (lifecycle === "stale") return "stale";
  if (lifecycle === "forgotten") return "forgotten";
  if (lifecycle !== "confirmed" && lifecycle !== "verified") {
    return "lifecycle_not_disclosable";
  }
  return undefined;
}

function objectiveNotRequiredConfirmationEligible(
  row: ContextNodeRow,
): boolean {
  if (
    row.lifecycle_status !== "verified"
    || row.confirmation_state !== "not_required"
    || !OBJECTIVE_NOT_REQUIRED_NODE_TYPES.has(row.node_type)
  ) return false;
  const provenance = parseRecord(row.provenance_json);
  return (
    provenance?.method === "evidence"
    || provenance?.method === "observation"
  ) && Array.isArray(provenance.sources) && provenance.sources.length > 0;
}

function scopeMatches(
  row: ContextNodeRow,
  missionId: string,
  engagementId: string | null,
  allowGlobal: boolean,
): boolean {
  if (row.scope === "global") {
    return allowGlobal
      && row.engagement_id === null
      && row.mission_id === null;
  }
  if (row.scope === "engagement") {
    return engagementId !== null
      && row.engagement_id === engagementId
      && row.mission_id === null;
  }
  if (row.scope === "mission") {
    return row.mission_id === missionId
      && (
        row.engagement_id === null
        || row.engagement_id === engagementId
      );
  }
  return false;
}

function resolveConsumerBinding(input: {
  readonly database: SqliteDatabase;
  readonly missionId: string;
  readonly runId: string;
  readonly contextPackId: string;
  readonly contextPackCreatedBy: string;
  readonly retrievedByActorId: string;
  readonly consumerActorId: string;
}): ProviderAdvisoryBrainContextConsumerBinding {
  if (input.contextPackCreatedBy !== input.retrievedByActorId) {
    throw new ProviderAdvisoryBrainContextPolicyError(
      "provider_advisory_context_retriever_mismatch",
      "Provider advisory disclosure was rejected because the declared retriever did not create the canonical Context Pack",
    );
  }
  const row = input.database.prepare(`
    SELECT
      run.contract_id,
      run.contract_version_bound,
      run.contract_hash_bound,
      contract.version,
      contract.state,
      contract.contract_hash,
      contract.action_policy_json
    FROM runs AS run
    JOIN mission_contracts AS contract
      ON contract.id = run.contract_id
      AND contract.mission_id = run.mission_id
    WHERE run.id = ? AND run.mission_id = ?
  `).get(input.runId, input.missionId) as ConsumerContractRow | undefined;
  if (
    !row
    || row.contract_id === null
    || row.state !== "confirmed"
    || row.contract_version_bound !== row.version
    || row.contract_hash_bound !== row.contract_hash
  ) {
    throw new ProviderAdvisoryBrainContextPolicyError(
      "provider_advisory_context_consumer_not_authorized",
      "Provider advisory disclosure was rejected because the run is not bound to one unchanged confirmed contract",
    );
  }
  const actionPolicy = parseRecord(row.action_policy_json);
  const planningSelection = actionPolicy
    ? actionPolicy.planningSelection
    : undefined;
  if (
    !plainRecord(planningSelection)
    || planningSelection.route !== "provider_advisory"
    || planningSelection.agentId !== input.consumerActorId
    || planningSelection.enforcementMode !== "advisor_only"
    || planningSelection.executionAuthority !== "none"
  ) {
    throw new ProviderAdvisoryBrainContextPolicyError(
      "provider_advisory_context_consumer_not_authorized",
      "Provider advisory disclosure was rejected because its consumer is not the exact advisor signed into the current contract",
    );
  }
  const bindingType = input.contextPackCreatedBy === input.consumerActorId
    ? "direct_context_consumer" as const
    : "signed_provider_advisor_delegation" as const;
  const planningSelectionHash = hashCanonical(planningSelection);
  const bindingMaterial = {
    schemaVersion:
      "ti-scale.provider-advisory-context-consumer-binding.v1" as const,
    bindingType,
    missionId: input.missionId,
    runId: input.runId,
    contextPackId: input.contextPackId,
    retrievedByActorId: input.retrievedByActorId,
    consumerActorId: input.consumerActorId,
    contractId: row.contract_id,
    contractVersion: row.version,
    contractHash: row.contract_hash,
    planningSelectionHash,
  };
  return Object.freeze({
    schemaVersion:
      "ti-scale.provider-advisory-context-consumer-binding.v1",
    bindingType,
    retrievedByActorId: input.retrievedByActorId,
    consumerActorId: input.consumerActorId,
    contractId: row.contract_id,
    contractVersion: row.version,
    contractHash: row.contract_hash,
    planningSelectionHash,
    bindingHash: hashCanonical(bindingMaterial),
  });
}

function contractAllowsNode(
  row: ContextNodeRow,
  policy: {
    readonly allowedScopes: readonly string[];
    readonly exactContextNodeIds: readonly string[];
  },
): boolean {
  if (
    policy.exactContextNodeIds.length > 0
    && !policy.exactContextNodeIds.includes(row.node_id)
  ) return false;
  const allowed = new Set(policy.allowedScopes);
  if (row.node_type === "preference") {
    return allowed.has("confirmed_preferences");
  }
  if (row.node_type === "lesson") {
    return row.lifecycle_status === "verified"
      && allowed.has("verified_lessons");
  }
  if (
    isAttackCentricReusableNodeType(row.node_type as MemoryNodeType)
  ) {
    return row.lifecycle_status === "verified"
      ? allowed.has("verified_attack_knowledge")
        || allowed.has("confirmed_attack_knowledge")
      : allowed.has("confirmed_attack_knowledge");
  }
  // Operational memory can remain mission/engagement scoped, but it never
  // gains global authority merely because global retrieval was enabled.
  return row.scope !== "global" && allowed.has("engagement_memory");
}

function frozenResearchItem(
  input: {
    readonly id: string;
    readonly classification: ResearchDataClassification;
    readonly disclosureClass: ResearchDisclosureClass;
    readonly content: string;
    readonly verified: boolean;
  },
): ResearchSourceItem {
  return Object.freeze({
    id: input.id,
    kind: input.verified
      ? "verified_memory_summary"
      : "sanitized_observation",
    classification: input.classification,
    disclosureClass: input.disclosureClass,
    content: input.content,
    verified: input.verified,
  });
}

/**
 * Converts one already-persisted, scope-checked Autonomous Context Pack into
 * bounded provider-advisory source items. It never creates a provider exposure
 * receipt or a provider envelope; ProviderAdvisoryRuntimeService remains the
 * sole owner of that pre-network authorization boundary.
 */
export class ProviderAdvisoryBrainContextAdapter {
  readonly #database: SqliteDatabase;
  readonly #clock: () => Date;

  constructor(options: ProviderAdvisoryBrainContextAdapterOptions) {
    this.#database = options.database;
    this.#clock = options.clock ?? (() => new Date());
  }

  prepare(
    input: PrepareProviderAdvisoryBrainContextInput,
  ): ProviderAdvisoryBrainContextResult {
    assertId(input.missionId, "Provider advisory mission ID");
    assertId(input.runId, "Provider advisory run ID");
    assertId(input.contextPackId, "Provider advisory Context Pack ID");
    assertId(
      input.retrievedByActorId,
      "Provider advisory Context Pack retriever ID",
    );
    assertId(input.actorId, "Provider advisory context actor ID");
    if (
      input.disclosureClass !== "public_only"
      && input.disclosureClass !== "sanitized_internal"
    ) {
      throw new TypeError("Provider advisory disclosure class is invalid");
    }
    const maximumItems = boundedInteger(
      input.maximumItems,
      DEFAULT_MAXIMUM_ITEMS,
      MAXIMUM_ITEMS,
      "Provider advisory Brain item budget",
    );
    const maximumBytes = boundedInteger(
      input.maximumBytes,
      DEFAULT_MAXIMUM_BYTES,
      MAXIMUM_BYTES,
      "Provider advisory Brain byte budget",
    );
    const suppliedOpaqueTerms = canonicalOpaqueTerms(input.opaqueTerms);
    const now = this.#clock();
    if (!Number.isFinite(now.getTime())) {
      throw new TypeError("Provider advisory context clock is invalid");
    }

    const mission = this.#database.prepare(`
      SELECT journey, control_plane, engagement_id
      FROM missions WHERE id = ?
    `).get(input.missionId) as MissionRow | undefined;
    const run = this.#database.prepare(`
      SELECT mission_id, journey, control_plane
      FROM runs WHERE id = ?
    `).get(input.runId) as RunRow | undefined;
    const pack = this.#database.prepare(`
      SELECT mission_id, run_id, journey, scope_policy_json,
        release_data_class, created_by
      FROM memory_context_packs WHERE id = ?
    `).get(input.contextPackId) as ContextPackRow | undefined;
    if (
      !mission
      || mission.journey !== "autonomous"
      || mission.control_plane !== "ti_scale"
      || !run
      || run.mission_id !== input.missionId
      || run.journey !== "autonomous"
      || run.control_plane !== "ti_scale"
      || !pack
      || pack.mission_id !== input.missionId
      || pack.run_id !== input.runId
      || pack.journey !== "autonomous"
      || pack.release_data_class !== "canonical"
    ) {
      throw new Error(
        "Provider advisory Context Pack does not belong to the exact canonical Autonomous mission and run",
      );
    }
    const scopePolicy = parseRecord(pack.scope_policy_json);
    if (!scopePolicy || (
      scopePolicy.journey !== undefined
      && scopePolicy.journey !== "autonomous"
    ) || (
      scopePolicy.missionId !== undefined
      && scopePolicy.missionId !== input.missionId
    ) || (
      scopePolicy.engagementId !== undefined
      && scopePolicy.engagementId !== mission.engagement_id
    )) {
      throw new Error(
        "Provider advisory Context Pack has a non-canonical retrieval scope",
      );
    }
    const memoryControlPolicy = getMemoryControlPolicy(this.#database);
    if (!memoryControlPolicy.enabled) {
      throw new ProviderAdvisoryBrainContextPolicyError(
        "provider_advisory_memory_control_disabled",
        "Provider advisory disclosure was rejected because the operator disabled the Second Brain after this Context Pack was retrieved",
      );
    }
    if (!memoryUseAllowed(memoryControlPolicy, "autonomous")) {
      throw new ProviderAdvisoryBrainContextPolicyError(
        "provider_advisory_autonomous_memory_use_revoked",
        "Provider advisory disclosure was rejected because the operator revoked Autonomous Brain use after this Context Pack was retrieved",
      );
    }
    const consumerBinding = resolveConsumerBinding({
      database: this.#database,
      missionId: input.missionId,
      runId: input.runId,
      contextPackId: input.contextPackId,
      contextPackCreatedBy: pack.created_by,
      retrievedByActorId: input.retrievedByActorId,
      consumerActorId: input.actorId,
    });
    let contractMemoryPolicy: ReturnType<
      typeof resolveAutonomousRunMemoryPolicy
    >;
    try {
      contractMemoryPolicy = resolveAutonomousRunMemoryPolicy({
        database: this.#database,
        missionId: input.missionId,
        runId: input.runId,
      });
    } catch (error) {
      throw new ProviderAdvisoryBrainContextPolicyError(
        "provider_advisory_contract_memory_policy_invalid",
        `Provider advisory disclosure was rejected because the current signed memory policy is unavailable: ${
          error instanceof Error ? error.message : "unknown policy error"
        }`,
      );
    }
    const allowGlobal = scopePolicy.allowGlobal === true;

    const persistedOpaqueTerms = this.#database.prepare(`
      SELECT target AS value
      FROM mission_targets
      WHERE mission_id = ?
      UNION
      SELECT normalized_target AS value
      FROM mission_targets
      WHERE mission_id = ?
      UNION
      SELECT scoped_target AS value
      FROM actions
      WHERE run_id = ? AND scoped_target IS NOT NULL
      UNION
      SELECT action_type AS value
      FROM actions
      WHERE run_id = ?
      UNION
      SELECT call.tool_name AS value
      FROM tool_calls call
      JOIN actions action ON action.id = call.action_id
      WHERE action.run_id = ?
      UNION
      SELECT call.mcp_server_id AS value
      FROM tool_calls call
      JOIN actions action ON action.id = call.action_id
      WHERE action.run_id = ? AND call.mcp_server_id IS NOT NULL
    `).all(
      input.missionId,
      input.missionId,
      input.runId,
      input.runId,
      input.runId,
      input.runId,
    ) as Array<{ value: string | null }>;
    const opaqueTerms = canonicalOpaqueTerms([
      ...suppliedOpaqueTerms,
      ...persistedOpaqueTerms.flatMap(({ value }) => value ? [value] : []),
    ]);
    const opaqueTermsHash = sha256(canonicalJson(opaqueTerms));

    const rows = this.#database.prepare(`
      SELECT
        item.node_id, item.rank, item.relevance_reason,
        node.node_type, node.title, node.summary, node.scope,
        node.engagement_id, node.mission_id, node.sensitivity,
        node.lifecycle_status, node.confirmation_state, node.provenance_json,
        node.retention_policy_json, node.expires_at, node.version
      FROM memory_context_items item
      JOIN memory_nodes node ON node.id = item.node_id
      WHERE item.context_pack_id = ?
      ORDER BY item.rank, item.node_id
    `).all(input.contextPackId) as ContextNodeRow[];

    const selected: ProviderAdvisoryBrainContextSelectedDisposition[] = [];
    const rejected: ProviderAdvisoryBrainContextRejectedDisposition[] = [];
    const items: ResearchSourceItem[] = [];
    let selectedBytes = 0;
    const reject = (
      row: ContextNodeRow,
      reasonCode: ProviderAdvisoryBrainContextRejectionReason,
      promptInjectionRuleIds: readonly string[] = [],
    ): void => {
      rejected.push(Object.freeze({
        nodeId: row.node_id,
        reasonCode,
        promptInjectionRuleIds: Object.freeze([...promptInjectionRuleIds]),
      }));
    };

    for (const row of rows) {
      if (row.confirmation_state === "rejected") {
        reject(row, "confirmation_rejected");
        continue;
      }
      const lifecycleReason = lifecycleRejection(row.lifecycle_status);
      if (lifecycleReason) {
        reject(row, lifecycleReason);
        continue;
      }
      if (
        row.confirmation_state !== "confirmed"
        && !objectiveNotRequiredConfirmationEligible(row)
      ) {
        reject(row, "confirmation_not_approved");
        continue;
      }
      if (
        row.expires_at !== null
        && (
          !Number.isFinite(Date.parse(row.expires_at))
          || Date.parse(row.expires_at) <= now.getTime()
        )
      ) {
        reject(row, "expired");
        continue;
      }
      if (!scopeMatches(
        row,
        input.missionId,
        mission.engagement_id,
        allowGlobal,
      )) {
        reject(row, "cross_engagement_scope");
        continue;
      }
      if (!contractAllowsNode(row, contractMemoryPolicy)) {
        reject(row, "contract_memory_excluded");
        continue;
      }
      const retention = parseRecord(row.retention_policy_json);
      if (
        retention?.allowAutonomous === false
        || (
          Array.isArray(retention?.journeys)
          && !retention.journeys.includes("autonomous")
        )
      ) {
        reject(row, "autonomous_use_not_approved");
        continue;
      }
      if (
        !memoryControlPolicy.operationalMemoryEnabled
        && row.node_type !== "preference"
      ) {
        reject(row, "operational_memory_disabled");
        continue;
      }
      if (retention?.publicProviderDisclosure !== "sanitized") {
        reject(row, "provider_disclosure_not_approved");
        continue;
      }
      if (
        row.sensitivity === "private"
        || row.sensitivity === "restricted"
        || (
          row.sensitivity !== "public"
          && row.sensitivity !== "internal"
        )
      ) {
        reject(row, "sensitivity_not_disclosable");
        continue;
      }
      if (
        input.disclosureClass === "public_only"
        && row.sensitivity === "internal"
      ) {
        reject(row, "internal_not_allowed");
        continue;
      }
      if (RAW_OPERATIONAL_NODE_TYPES.has(row.node_type)) {
        reject(row, "raw_operational_record_forbidden");
        continue;
      }

      const source = `${row.title}\n${row.summary}\n${row.relevance_reason}`;
      const injection = assessPromptInjection(source);
      if (injection.quarantined) {
        reject(row, "prompt_injection_quarantined", injection.ruleIds);
        continue;
      }
      if (RAW_PAYLOAD_PATTERN.test(source)) {
        reject(row, "raw_payload_content");
        continue;
      }
      const title = sanitizeResearchText(
        redactOpaqueTerms(row.title, opaqueTerms),
        180,
      );
      const summary = sanitizeResearchText(
        redactOpaqueTerms(row.summary, opaqueTerms),
        700,
      );
      const combinedActions = [...new Set([
        ...title.actions,
        ...summary.actions,
      ])].sort();
      if (
        combinedActions.some((action) =>
          SECRET_SANITIZATION_ACTIONS.has(action))
      ) {
        reject(row, "credential_or_secret_content");
        continue;
      }
      if (!title.sanitized || !summary.sanitized) {
        reject(row, "empty_after_sanitization");
        continue;
      }
      const content = canonicalJson({
        memoryType: row.node_type,
        title: title.sanitized,
        summary: summary.sanitized,
      });
      if (containsOpaqueTerm(content, opaqueTerms)) {
        reject(row, "raw_payload_content");
        continue;
      }
      if (items.length >= maximumItems) {
        reject(row, "item_budget_exceeded");
        continue;
      }
      const contentBytes = Buffer.byteLength(content, "utf8");
      if (selectedBytes + contentBytes > maximumBytes) {
        reject(row, "byte_budget_exceeded");
        continue;
      }
      const classification = row.sensitivity as "public" | "internal";
      const disclosureClass = classification === "public"
        ? "public" as const
        : "internal_sanitized" as const;
      const id = sourceItemId(input.contextPackId, row.node_id);
      const verified = row.lifecycle_status === "verified";
      items.push(frozenResearchItem({
        id,
        classification,
        disclosureClass,
        content,
        verified,
      }));
      selectedBytes += contentBytes;
      selected.push(Object.freeze({
        nodeId: row.node_id,
        sourceItemId: id,
        reasonCode: classification === "public"
          ? "public_disclosure_approved"
          : "sanitized_internal_disclosure_approved",
        classification,
        disclosureClass,
        contentHash: sha256(content),
        contentBytes,
        sanitizationActions: Object.freeze(combinedActions),
      }));
    }

    const snapshotHash = hashCanonical(rows.map((row) => ({
      nodeId: row.node_id,
      rank: row.rank,
      relevanceReasonHash: sha256(row.relevance_reason),
      nodeType: row.node_type,
      titleHash: sha256(row.title),
      summaryHash: sha256(row.summary),
      scope: row.scope,
      engagementId: row.engagement_id,
      missionId: row.mission_id,
      sensitivity: row.sensitivity,
      lifecycleStatus: row.lifecycle_status,
      confirmationState: row.confirmation_state,
      provenanceHash: sha256(row.provenance_json),
      retentionPolicyHash: sha256(row.retention_policy_json),
      expiresAt: row.expires_at,
      version: row.version,
    })));
    const inputFingerprint = hashCanonical({
      policyVersion: PROVIDER_ADVISORY_BRAIN_CONTEXT_POLICY_VERSION,
      missionId: input.missionId,
      runId: input.runId,
      contextPackId: input.contextPackId,
      actorId: input.actorId,
      retrievedByActorId: input.retrievedByActorId,
      disclosureClass: input.disclosureClass,
      maximumItems,
      maximumBytes,
      opaqueTermsHash,
      snapshotHash,
      memoryControlPolicyVersion: memoryControlPolicy.version,
      memoryControlPolicyHash: hashCanonical(memoryControlPolicy),
      contractMemoryPolicyHash: hashCanonical(contractMemoryPolicy),
      consumerBindingHash: consumerBinding.bindingHash,
    });
    const outputHash = hashCanonical({
      items,
      selected,
      rejected,
      selectedBytes,
    });
    if (!SHA256.test(inputFingerprint) || !SHA256.test(outputHash)) {
      throw new Error("Provider advisory context hashing failed");
    }
    const details: AuditDetails = Object.freeze({
      schemaVersion: PROVIDER_ADVISORY_BRAIN_CONTEXT_RESULT_SCHEMA_VERSION,
      policyVersion: PROVIDER_ADVISORY_BRAIN_CONTEXT_POLICY_VERSION,
      inputFingerprint,
      outputHash,
      actorId: input.actorId,
      retrievedByActorId: input.retrievedByActorId,
      contextPackId: input.contextPackId,
      disclosureClass: input.disclosureClass,
      opaqueTermsHash,
      maximumItems,
      maximumBytes,
      selectedBytes,
      memoryControlPolicyVersion: memoryControlPolicy.version,
      memoryControlPolicyHash: hashCanonical(memoryControlPolicy),
      contractMemoryPolicyHash: hashCanonical(contractMemoryPolicy),
      consumerBinding,
      selected: Object.freeze(selected),
      rejected: Object.freeze(rejected),
    });
    const auditRecordId =
      `audit-provider-brain-${inputFingerprint.slice(0, 32)}`;
    let reused = false;
    inImmediateTransaction(this.#database, () => {
      const existing = this.#database.prepare(`
        SELECT mission_id, run_id, journey, actor_id, action, resource_type,
          resource_id, details_json, occurred_at
        FROM audit_records WHERE id = ?
      `).get(auditRecordId) as ExistingAuditRow | undefined;
      if (existing) {
        if (
          existing.mission_id !== input.missionId
          || existing.run_id !== input.runId
          || existing.journey !== "autonomous"
          || existing.actor_id !== input.actorId
          || existing.action !== "provider_advisory.brain_context.prepared"
          || existing.resource_type !== "memory_context_pack"
          || existing.resource_id !== input.contextPackId
          || existing.details_json !== canonicalJson(details)
        ) {
          throw new Error(
            "Provider advisory Brain context telemetry conflicts with its deterministic audit identity",
          );
        }
        reused = true;
        return;
      }
      const occurredAt = now.toISOString();
      const previous = this.#database.prepare(`
        SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1
      `).get() as { record_hash: string } | undefined;
      const previousHash = previous?.record_hash ?? null;
      const reason =
        "Prepared bounded, reason-coded Brain context for an advisor-only provider route.";
      const recordHash = hashCanonical({
        id: auditRecordId,
        missionId: input.missionId,
        runId: input.runId,
        journey: "autonomous",
        actorType: "agent",
        actorId: input.actorId,
        action: "provider_advisory.brain_context.prepared",
        resourceType: "memory_context_pack",
        resourceId: input.contextPackId,
        reason,
        details,
        previousHash,
        occurredAt,
      });
      this.#database.prepare(`
        INSERT INTO audit_records (
          id, mission_id, run_id, journey, actor_type, actor_id, action,
          resource_type, resource_id, reason, details_json, previous_hash,
          record_hash, occurred_at
        ) VALUES (?, ?, ?, 'autonomous', 'agent', ?,
          'provider_advisory.brain_context.prepared',
          'memory_context_pack', ?, ?, ?, ?, ?, ?)
      `).run(
        auditRecordId,
        input.missionId,
        input.runId,
        input.actorId,
        input.contextPackId,
        reason,
        canonicalJson(details),
        previousHash,
        recordHash,
        occurredAt,
      );
    });

    return Object.freeze({
      schemaVersion: PROVIDER_ADVISORY_BRAIN_CONTEXT_RESULT_SCHEMA_VERSION,
      contextPackId: input.contextPackId,
      disclosureClass: input.disclosureClass,
      consumerBinding,
      items: Object.freeze(items),
      telemetry: Object.freeze({
        auditRecordId,
        reused,
        policyVersion: PROVIDER_ADVISORY_BRAIN_CONTEXT_POLICY_VERSION,
        inputFingerprint,
        outputHash,
        maximumItems,
        maximumBytes,
        selected: Object.freeze(selected),
        rejected: Object.freeze(rejected),
        selectedBytes,
        consumerBinding,
      }),
    });
  }
}

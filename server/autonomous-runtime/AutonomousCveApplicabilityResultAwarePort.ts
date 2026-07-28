import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { canonicalProductOwnerBindsRuntimeAgent } from "../agents";
import {
  retrieveMissionBrainContext,
  type BrainContextService,
  type BrainContextResult,
} from "../brain-runtime";
import type {
  ExecutionResult,
  ExecutionResultReceipt,
  ExecutionResultSink,
  ResultAwareExecutionPort,
} from "../command-runtime";
import type { ControlPlaneLease } from "../control-plane";
import {
  AutonomousCveCandidateService,
  CveApplicabilityService,
  type AutonomousCveCandidateEnrichmentPort,
  type AutonomousCveCandidateRecord,
  type CveApplicabilityRecord,
  type MissionScopedNvdDetailResult,
  type VerifiedServiceProductVersionEvidence,
} from "../cve-intelligence";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { digestCanonicalJson } from "../mcp";
import {
  ActionRepository,
  ExecutionBoundaryError,
  RunRepository,
  reviewedLocalToolActionEnvelope,
  type DurableAction,
} from "../orchestration";
import type { FailureCategory } from "../supervisor";
import {
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
  AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE,
  type AuthoritativeCveCandidateCatalogPort,
  type AuthoritativeCveCatalogQueryReceipt,
  type AutonomousCveApplicabilityConfiguration,
  validateAutonomousCveApplicabilityConfiguration,
} from "./AutonomousCveApplicability";
import { AutonomousCveVersionEvidenceResolver } from "./AutonomousCveVersionEvidenceResolver";
import {
  AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
  autonomousSuccessCriterionId,
} from "./LocalVerifiedEvidenceOutcomeEvaluator";

export const AUTONOMOUS_CVE_APPLICABILITY_RESULT_SCHEMA_VERSION =
  "ti-scale.autonomous-cve-applicability-result.v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const TERMINAL_ATTEMPT_LIMIT = 3;

interface CanonicalContext {
  readonly action: DurableAction;
  readonly lease: ControlPlaneLease;
  readonly memoryPolicy: Readonly<Record<string, unknown>>;
}

interface TerminalPayload {
  readonly schemaVersion: typeof AUTONOMOUS_CVE_APPLICABILITY_RESULT_SCHEMA_VERSION;
  readonly contextPackId: string | null;
  readonly sourceEvidenceIds: readonly string[];
  readonly applicabilityRecordIds: readonly string[];
  readonly evidenceIds: readonly string[];
  readonly catalogQueryReceiptIds: readonly string[];
  readonly catalogQueryReceipts: readonly Readonly<{
    readonly queryReceiptId: string;
    readonly queryReceiptSha256: string;
  }>[];
  readonly nvdEnrichmentReceiptIds: readonly string[];
  /**
   * Immutable analysis receipt bound to the verified evidence content hash.
   * Delivery bookkeeping may change, but this digest may not.
   */
  readonly immutableResultReceiptSha256: string | null;
  readonly deliveryResult: ExecutionResult;
  readonly resultAccepted: boolean;
  readonly deliveryAttemptCount: number;
  readonly deliveryLastAttemptAt: string | null;
  readonly deliveryLastError: string | null;
}

interface PendingRow {
  readonly id: string;
  readonly redacted_payload_json: string;
}

export class AutonomousCveApplicabilityExecutionError extends ExecutionBoundaryError {
  constructor(
    code: string,
    category: FailureCategory,
    message: string,
  ) {
    super(code, category, message);
    this.name = "AutonomousCveApplicabilityExecutionError";
  }
}

export function autonomousCveApplicabilityToolCallId(actionId: string): string {
  return `cve_composite_${createHash("sha256").update(actionId).digest("hex").slice(0, 40)}`;
}

function canonicalIp(value: string): string {
  if (value !== value.trim() || isIP(value) === 0) {
    throw new AutonomousCveApplicabilityExecutionError(
      "autonomous_cve_ip_required",
      "scope_conflict",
      "CVE applicability accepts only the exact canonical IP bound to the verified service evidence.",
    );
  }
  const host = new URL(`http://${isIP(value) === 6 ? `[${value}]` : value}/`).hostname;
  const normalized = host.startsWith("[") ? host.slice(1, -1) : host;
  if (normalized !== value.toLowerCase()) {
    throw new AutonomousCveApplicabilityExecutionError(
      "autonomous_cve_ip_not_canonical",
      "scope_conflict",
      "CVE applicability requires the canonical mission IP spelling.",
    );
  }
  return normalized;
}

function jsonObject(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown> : {};
  } catch { return {}; }
}

function jsonArray(value: string): unknown[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}

function failureCode(error: unknown): string {
  const value = typeof (error as { readonly code?: unknown })?.code === "string"
    ? (error as { readonly code: string }).code : "autonomous_cve_applicability_failed";
  return /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$/u.test(value)
    ? value : "autonomous_cve_applicability_failed";
}

function failureCategory(error: unknown, code: string): FailureCategory {
  if (error instanceof ExecutionBoundaryError) return error.failureCategory;
  if (/cancel/iu.test(code)) return "operator_rejection";
  if (/scope|target/iu.test(code)) return "scope_conflict";
  if (/authorization/iu.test(code)) return "authorization_denied";
  if (/brain|context|catalog|nvd|dependency/iu.test(code)) return "dependency_missing";
  if (/evidence|version|candidate|receipt|integrity/iu.test(code)) return "evidence_insufficient";
  if (/contract|policy|binding|canonical/iu.test(code)) return "policy_denied";
  return "deterministic_tool_error";
}

function failureResult(action: DurableAction, error: unknown, wallClockMs: number): ExecutionResult {
  const code = failureCode(error);
  const detail = (error instanceof Error ? error.message : "CVE applicability failed.")
    .replace(/[\u0000-\u001F\u007F]/gu, " ").trim().replace(/\s+/gu, " ").slice(0, 700);
  return Object.freeze({
    actionId: action.id,
    runId: action.runId,
    actionFingerprint: action.fingerprint,
    success: false,
    summary: `CVE applicability failed safely. ${detail} No applicability outcome was claimed.`,
    progress: Object.freeze({}),
    failure: Object.freeze({ source: "tool" as const, code, message: detail }),
    failureCategory: failureCategory(error, code),
    circuitKey: "autonomous-cve:reviewed-local-catalog",
    usage: Object.freeze({ wallClockMs: Math.max(0, Math.round(wallClockMs)) }),
  });
}

function affectedRangeSummary(record: AutonomousCveCandidateRecord): string {
  return record.affectedRanges.map((range) => {
    const lower = range.lower ? `${range.lower.inclusive ? "[" : "("}${range.lower.version}` : "(-inf";
    const upper = range.upper ? `${range.upper.version}${range.upper.inclusive ? "]" : ")"}` : "+inf)";
    const exact = range.exactVersions?.length ? ` exact=${range.exactVersions.join(",")}` : "";
    const excluded = range.excludedVersions?.length ? ` excluded=${range.excludedVersions.join(",")}` : "";
    return `${range.id}:${range.scheme}:${lower},${upper}${exact}${excluded}`;
  }).join("; ").slice(0, 1_000);
}

function receiptBody(receipt: AuthoritativeCveCatalogQueryReceipt): Readonly<Record<string, unknown>> {
  const { queryReceiptSha256: _queryReceiptSha256, ...body } = receipt;
  return body;
}

function assertCatalogReceipt(
  receipt: AuthoritativeCveCatalogQueryReceipt,
  evidence: VerifiedServiceProductVersionEvidence,
  configuration: AutonomousCveApplicabilityConfiguration,
): void {
  const queriedAt = Date.parse(receipt.queriedAt);
  if (receipt.schemaVersion !== "ti-scale.authoritative-cve-catalog-query.v1"
    || receipt.catalogId !== configuration.catalogId
    || receipt.catalogSnapshotSha256 !== configuration.catalogSnapshotSha256
    || receipt.evidenceId !== evidence.evidenceId
    || receipt.targetInteraction !== false
    || receipt.executionAuthority !== "none"
    || !Array.isArray(receipt.candidates)
    || receipt.candidates.length > configuration.maximumCandidatesPerProduct
    || !Number.isFinite(queriedAt)
    || !SHA256.test(receipt.queryReceiptSha256)
    || digestCanonicalJson(receiptBody(receipt), { maxBytes: 8 * 1024 * 1024, maxDepth: 64 }).sha256
      !== receipt.queryReceiptSha256) {
    throw new AutonomousCveApplicabilityExecutionError(
      "autonomous_cve_catalog_receipt_invalid",
      "evidence_insufficient",
      "The reviewed local CVE catalogue returned an invalid, drifting, or over-budget query receipt.",
    );
  }
}

function parsePayload(value: string): TerminalPayload | undefined {
  try {
    const item = JSON.parse(value) as Partial<TerminalPayload>;
    if (!item || typeof item !== "object" || Array.isArray(item)
      || item.schemaVersion !== AUTONOMOUS_CVE_APPLICABILITY_RESULT_SCHEMA_VERSION
      || !item.deliveryResult || typeof item.deliveryResult !== "object"
      || typeof item.resultAccepted !== "boolean"
      || (item.immutableResultReceiptSha256 !== null
        && (typeof item.immutableResultReceiptSha256 !== "string"
          || !SHA256.test(item.immutableResultReceiptSha256)))
      || !Array.isArray(item.catalogQueryReceipts)
      || item.catalogQueryReceipts.some((receipt) =>
        !receipt || typeof receipt !== "object" || Array.isArray(receipt)
        || typeof receipt.queryReceiptId !== "string"
        || typeof receipt.queryReceiptSha256 !== "string"
        || !SHA256.test(receipt.queryReceiptSha256))
      || !Number.isSafeInteger(item.deliveryAttemptCount)
      || (item.deliveryAttemptCount ?? -1) < 0
      || (item.deliveryAttemptCount ?? 0) > TERMINAL_ATTEMPT_LIMIT) return undefined;
    return item as TerminalPayload;
  } catch { return undefined; }
}

export class AutonomousCveApplicabilityResultAwarePort implements ResultAwareExecutionPort {
  readonly #configuration: AutonomousCveApplicabilityConfiguration;
  readonly #actions: ActionRepository;
  readonly #runs: RunRepository;
  readonly #events: EventRepository;
  readonly #resolver: AutonomousCveVersionEvidenceResolver;
  readonly #candidates: AutonomousCveCandidateService;
  readonly #applicability: CveApplicabilityService;
  readonly #now: () => Date;
  readonly #controllers = new Map<string, AbortController>();
  #sink?: ExecutionResultSink;

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    configuration: AutonomousCveApplicabilityConfiguration;
    catalog: AuthoritativeCveCandidateCatalogPort;
    brainContext: BrainContextService;
    enrichment?: AutonomousCveCandidateEnrichmentPort<MissionScopedNvdDetailResult>;
    assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
    now?: () => Date;
  }>) {
    this.#configuration = validateAutonomousCveApplicabilityConfiguration(options.configuration);
    this.#actions = new ActionRepository(options.database);
    this.#runs = new RunRepository(options.database);
    this.#events = new EventRepository(options.database);
    this.#resolver = new AutonomousCveVersionEvidenceResolver(options.database);
    this.#now = options.now ?? (() => new Date());
    this.#candidates = new AutonomousCveCandidateService({ clock: this.#now });
    this.#applicability = new CveApplicabilityService(options.database, this.#now);
    if (this.#configuration.nvdEnrichment === "top_candidate" && !options.enrichment) {
      throw new AutonomousCveApplicabilityExecutionError(
        "autonomous_cve_nvd_binding_missing",
        "dependency_missing",
        "Top-candidate NVD enrichment requires the reviewed opaque mission-scoped NVD binding.",
      );
    }
  }

  bindResultSink(sink: ExecutionResultSink): () => void {
    if (this.#sink) throw new Error("Autonomous CVE result sink is already bound");
    this.#sink = sink;
    return () => { if (this.#sink === sink) this.#sink = undefined; };
  }

  private canonical(input: DurableAction): CanonicalContext {
    const action = this.#actions.get(input.id);
    if (digestCanonicalJson(action, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      !== digestCanonicalJson(input, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      || action.status !== "running"
      || action.actionType !== AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE
      || action.actionClass !== AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS) {
      throw new AutonomousCveApplicabilityExecutionError(
        "autonomous_cve_action_not_canonical",
        "policy_denied",
        "Only the exact canonical running CVE applicability action may execute.",
      );
    }
    const target = canonicalIp(action.target);
    const envelope = reviewedLocalToolActionEnvelope(action.arguments);
    const keys = envelope ? Object.keys(envelope.parameters).sort().join("\u0000") : "";
    if (!envelope || envelope.toolId !== AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE
      || keys !== "catalogId\u0000catalogSnapshotSha256\u0000target"
      || envelope.parameters.target !== target
      || envelope.parameters.catalogId !== this.#configuration.catalogId
      || envelope.parameters.catalogSnapshotSha256 !== this.#configuration.catalogSnapshotSha256) {
      throw new AutonomousCveApplicabilityExecutionError(
        "autonomous_cve_binding_invalid",
        "policy_denied",
        "The action does not carry the exact reviewed catalogue snapshot and target envelope.",
      );
    }
    const lease = this.options.assertControlPlaneAuthority(action.runId);
    const authorized = this.#runs.authorizePersistedLocalTool(
      this.#runs.get(action.runId), action, action.actionType,
    );
    if (!authorized.allowed) {
      throw new AutonomousCveApplicabilityExecutionError(
        authorized.code, "policy_denied", authorized.humanMessage,
      );
    }
    const row = this.options.database.prepare(`
      SELECT mc.contract_hash, mc.state, mc.version, mc.action_policy_json,
        mc.memory_scopes_json, r.contract_hash_bound, r.contract_version_bound,
        r.contract_id, m.success_criteria_json, m.memory_policy_json,
        ps.assigned_agent_id, ass.agent_id AS assignment_agent_id
      FROM actions a
      JOIN runs r ON r.id = a.run_id AND r.mission_id = a.mission_id
      JOIN missions m ON m.id = r.mission_id
      JOIN mission_contracts mc ON mc.id = r.contract_id AND mc.mission_id = r.mission_id
      JOIN plan_steps ps ON ps.id = a.step_id AND ps.run_id = r.id
      JOIN assignments ass ON ass.id = a.assignment_id
        AND ass.run_id = r.id AND ass.step_id = ps.id
      WHERE a.id = ? AND r.id = ? AND r.mission_id = ?
        AND r.journey = 'autonomous'
        AND r.control_plane = 'ti_scale' AND m.control_plane = 'ti_scale'
        AND m.authorization_status = 'verified'
        AND ps.assigned_agent_id = ass.agent_id AND ass.status = 'active'
    `).get(action.id, action.runId, action.missionId) as {
      readonly contract_hash: string; readonly state: string; readonly version: number;
      readonly action_policy_json: string; readonly memory_scopes_json: string;
      readonly contract_hash_bound: string | null; readonly contract_version_bound: number | null;
      readonly contract_id: string | null; readonly success_criteria_json: string;
      readonly memory_policy_json: string;
      readonly assigned_agent_id: string | null;
      readonly assignment_agent_id: string;
    } | undefined;
    const scope = this.options.database.prepare(`
      SELECT disposition, normalized_target FROM mission_targets
      WHERE mission_id = ? ORDER BY created_at, id
    `).all(action.missionId) as Array<{ readonly disposition: string; readonly normalized_target: string }>;
    const policy = jsonObject(row?.action_policy_json ?? "null");
    const missionMemoryPolicy = jsonObject(row?.memory_policy_json ?? "null");
    const memoryScopes = jsonArray(row?.memory_scopes_json ?? "null")
      .filter((item): item is string => typeof item === "string" && Boolean(item.trim()));
    const criteria = jsonArray(row?.success_criteria_json ?? "null");
    const allowedClasses = Array.isArray(policy.allowedActionClasses) ? policy.allowedActionClasses : [];
    const prohibitedClasses = Array.isArray(policy.prohibitedActionClasses) ? policy.prohibitedActionClasses : [];
    const specialists = Array.isArray(policy.specialistAgentIds) ? policy.specialistAgentIds : [];
    const allowedTargets = scope.filter(({ disposition }) => disposition === "allowed");
    if (!row || row.state !== "confirmed" || row.contract_id !== action.contractId
      || row.contract_hash !== row.contract_hash_bound || row.version !== row.contract_version_bound
      || allowedTargets.length !== 1 || canonicalIp(allowedTargets[0]!.normalized_target) !== target
      || scope.some(({ disposition, normalized_target }) => disposition === "prohibited" && normalized_target === target)
      || !allowedClasses.includes(AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS)
      || prohibitedClasses.includes(AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS)
      || !canonicalProductOwnerBindsRuntimeAgent(
        this.options.database,
        {
          actionClassId: action.actionClass,
          planAgentId: row.assigned_agent_id,
          assignmentAgentId: row.assignment_agent_id,
          signedSpecialistAgentIds: specialists,
          runtimeAgentId: this.#configuration.agentId,
        },
      )
      || !criteria.includes(this.#configuration.successCriterion)
      || !Array.isArray(missionMemoryPolicy.exactContextNodeIds)
      || !Array.isArray(missionMemoryPolicy.allowedScopes)) {
      throw new AutonomousCveApplicabilityExecutionError(
        "autonomous_cve_scope_or_contract_changed",
        "policy_denied",
        "The confirmed contract, exact IP scope, specialist, or CVE criterion changed before execution.",
      );
    }
    const selections = this.options.database.prepare(`
      SELECT node_id, selection_type FROM run_context_selections
      WHERE run_id = ? ORDER BY selected_at, id
    `).all(action.runId) as Array<{ readonly node_id: string; readonly selection_type: string }>;
    if (selections.some(({ selection_type }) => selection_type !== "verified_lesson")
      || (selections.length > 0 && !memoryScopes.includes("verified_lessons"))) {
      throw new AutonomousCveApplicabilityExecutionError(
        "autonomous_cve_memory_selection_invalid",
        "policy_denied",
        "The immutable run memory selection is outside the signed Autonomous memory policy.",
      );
    }
    return Object.freeze({
      action,
      lease,
      memoryPolicy: Object.freeze({
        ...missionMemoryPolicy,
        allowedScopes: Object.freeze(memoryScopes),
        exactContextNodeIds: Object.freeze(selections.length
          ? selections.map(({ node_id }) => node_id)
          : (missionMemoryPolicy.exactContextNodeIds as unknown[])
              .filter((item): item is string => typeof item === "string" && Boolean(item.trim()))),
      }),
    });
  }

  private context(canonical: CanonicalContext, evidenceIds: readonly string[]): BrainContextResult {
    const result = retrieveMissionBrainContext({
      brainContext: this.options.brainContext,
      hook: "finding_validation",
      journey: "autonomous",
      missionId: canonical.action.missionId,
      runId: canonical.action.runId,
      stepId: canonical.action.stepId,
      actionId: canonical.action.id,
      actorId: this.#configuration.agentId,
      actorType: "agent",
      query: `Validate CVE candidates for verified service-version evidence ${evidenceIds.join(", ")}. Retrieve only relevant confirmed technology, advisory, contradiction, failure, and verified lesson memory.`,
      queryRedacted: "Validate authoritative CVE candidates against verified product/version evidence and relevant confirmed memory.",
      memoryPolicy: canonical.memoryPolicy,
      maximumSensitivity: "private",
      contextBudget: 4_000,
      limit: 12,
    });
    this.options.brainContext.recordUnusedContext(
      result,
      "The mandatory Context Pack was inspected for contradictions and prior evidence, but deterministic product/range matching and authoritative source records remained the only applicability authority.",
    );
    return result;
  }

  private persistCandidate(record: AutonomousCveCandidateRecord): CveApplicabilityRecord {
    const previous = this.#applicability.repository.findCanonical(record);
    const sourceVersions = [...new Set(record.provenance.candidateSources.map(({ sourceVersion }) => sourceVersion))];
    return this.#applicability.upsert({
      missionId: record.missionId,
      runId: record.runId,
      assetNodeId: record.assetNodeId,
      serviceNodeId: record.serviceNodeId,
      cveId: record.cveId,
      title: record.title,
      description: `A reviewed authoritative candidate was compared locally with verified ${record.component} version evidence. External descriptive text was not promoted into trusted mission evidence.`,
      component: record.component,
      ...(record.detectedVersion ? { detectedVersion: record.detectedVersion } : {}),
      affectedRange: affectedRangeSummary(record),
      cpeOrPackage: {
        productIdentityMatch: record.productIdentityMatch,
        versionMatch: record.versionMatch,
        candidateInputSha256: record.provenance.candidateInputSha256,
      },
      applicability: record.applicability,
      confidence: record.confidence,
      reasoningSummary: record.reasoningSummary,
      sourceLinks: record.sourceLinks,
      sourceRetrievedAt: record.sourceRetrievedAt,
      sourceVersion: sourceVersions.join(", ").slice(0, 1_000),
      discoveryAgentId: this.#configuration.agentId,
      versionEvidenceId: record.versionEvidenceId,
      ...(previous ? { expectedUpdatedAt: previous.updatedAt } : {}),
    }, { id: this.#configuration.agentId, type: "agent" });
  }

  private enrich(
    record: CveApplicabilityRecord,
    detail: MissionScopedNvdDetailResult,
  ): CveApplicabilityRecord {
    if (detail.context.reviewedCveRef !== record.id || detail.detail.cveId !== record.cveId) {
      throw new AutonomousCveApplicabilityExecutionError(
        "autonomous_cve_nvd_receipt_mismatch",
        "evidence_insufficient",
        "The reviewed NVD detail receipt does not match the exact persisted candidate.",
      );
    }
    return this.#applicability.upsert({
      missionId: record.missionId,
      ...(record.runId ? { runId: record.runId } : {}),
      ...(record.assetNodeId ? { assetNodeId: record.assetNodeId } : {}),
      ...(record.serviceNodeId ? { serviceNodeId: record.serviceNodeId } : {}),
      cveId: record.cveId,
      title: record.title,
      description: record.description,
      component: record.component,
      ...(record.detectedVersion ? { detectedVersion: record.detectedVersion } : {}),
      ...(record.affectedRange ? { affectedRange: record.affectedRange } : {}),
      cpeOrPackage: record.cpeOrPackage,
      applicability: record.applicability,
      confidence: record.confidence,
      reasoningSummary: record.reasoningSummary,
      cvss: detail.detail.strongestCvss ?? {},
      cwe: detail.detail.weaknesses,
      sourceLinks: record.sourceLinks,
      sourceRetrievedAt: detail.provenance.retrievedAt,
      ...(record.sourceVersion ? { sourceVersion: record.sourceVersion } : {}),
      ...(record.discoveryAgentId ? { discoveryAgentId: record.discoveryAgentId } : {}),
      ...(record.versionEvidenceId ? { versionEvidenceId: record.versionEvidenceId } : {}),
      ...(detail.detail.publishedAt ? { publishedAt: detail.detail.publishedAt } : {}),
      ...(detail.detail.lastModifiedAt ? { modifiedAt: detail.detail.lastModifiedAt } : {}),
      expectedUpdatedAt: record.updatedAt,
    }, { id: this.#configuration.agentId, type: "agent" });
  }

  private commitSuccess(input: Readonly<{
    canonical: CanonicalContext;
    contextPackId: string;
    sourceEvidenceIds: readonly string[];
    records: readonly CveApplicabilityRecord[];
    catalogReceipts: readonly AuthoritativeCveCatalogQueryReceipt[];
    nvdDetails: readonly MissionScopedNvdDetailResult[];
    startedAt: Date;
    invocationId: string;
  }>): TerminalPayload {
    return inImmediateTransaction(this.options.database, () => {
      const current = this.canonical(input.canonical.action);
      if (current.lease.leaseOwner !== input.canonical.lease.leaseOwner) {
        throw new AutonomousCveApplicabilityExecutionError(
          "autonomous_cve_owner_fence_changed", "worker_lost",
          "The control-plane owner changed before CVE applicability evidence commit.",
        );
      }
      const now = this.#now().toISOString();
      const criterionId = autonomousSuccessCriterionId(this.#configuration.successCriterion);
      const content = digestCanonicalJson({
        schemaVersion: AUTONOMOUS_CVE_APPLICABILITY_RESULT_SCHEMA_VERSION,
        catalogId: this.#configuration.catalogId,
        catalogSnapshotSha256: this.#configuration.catalogSnapshotSha256,
        sourceEvidenceIds: input.sourceEvidenceIds,
        applicabilityRecords: input.records.map((record) => ({
          id: record.id, cveId: record.cveId, applicability: record.applicability,
          confidence: record.confidence, versionEvidenceId: record.versionEvidenceId,
        })),
        catalogQueryReceipts: input.catalogReceipts.map(({
          queryReceiptId,
          queryReceiptSha256,
        }) => ({ queryReceiptId, queryReceiptSha256 })),
        nvdEnrichmentReceipts: input.nvdDetails.map(({ context, provenance }) => ({
          reviewedCveRef: context.reviewedCveRef,
          invocationId: provenance.invocationId,
          resultSha256: provenance.resultSha256,
          auditRecordId: provenance.auditRecordId,
        })),
        contextPackId: input.contextPackId,
        targetInteraction: false,
        rawBannerConfirmedApplicability: false,
      }, { maxBytes: 8 * 1024 * 1024, maxDepth: 64 });
      const evidenceId = `evidence_cve_${createHash("sha256")
        .update(`${current.action.id}\u0000${content.sha256}`).digest("hex").slice(0, 40)}`;
      const summary = input.records.length === 0
        ? `The reviewed catalogue returned no exact CVE candidate for ${input.sourceEvidenceIds.length} verified product/version observation${input.sourceEvidenceIds.length === 1 ? "" : "s"}. No CVE was invented.`
        : `Ti-Scale retained ${input.records.length} conservative CVE applicability assessment${input.records.length === 1 ? "" : "s"}; banner-derived matches remain possible or insufficient, never confirmed.`;
      const provenance = digestCanonicalJson({
        method: "verified_version_authoritative_catalog_range_match",
        actionId: current.action.id,
        actionFingerprint: current.action.fingerprint,
        sourceEvidenceIds: input.sourceEvidenceIds,
        catalogId: this.#configuration.catalogId,
        catalogSnapshotSha256: this.#configuration.catalogSnapshotSha256,
        catalogQueryReceipts: input.catalogReceipts.map(({
          queryReceiptId,
          queryReceiptSha256,
        }) => ({ queryReceiptId, queryReceiptSha256 })),
        applicabilityRecordIds: input.records.map(({ id }) => id),
        contextPackId: input.contextPackId,
        nvdInvocationIds: input.nvdDetails.map(({ provenance: detail }) => detail.invocationId),
        rawOutputPromoted: false,
        bannerOnlyConfirmationPermitted: false,
        targetInteraction: false,
        successCriterionReferences: [{
          schemaVersion: AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
          criterionId,
          outcome: "achieved",
        }],
      }, { maxBytes: 8 * 1024 * 1024, maxDepth: 64 });
      this.options.database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, step_id, action_id, source, acquired_at,
          target, evidence_type, content_hash, provenance_json, confidence,
          sensitivity, verification_state, summary, extracted_text,
          artifact_id, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'private', 'verified', ?, ?, NULL, ?, ?)
      `).run(
        evidenceId, current.action.missionId, current.action.runId, current.action.stepId,
        current.action.id, `specialist:${this.#configuration.agentId}`, now,
        current.action.target, AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE,
        content.sha256, provenance.canonicalJson,
        input.records.length ? Math.min(...input.records.map(({ confidence }) => confidence)) : 0.8,
        summary, content.canonicalJson, "autonomous-cve-applicability-verifier", now,
      );
      this.options.database.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES (?, ?, 'acquired', ?, ?, ?), (?, ?, 'verified', ?, ?, ?)
      `).run(
        `custody_${createHash("sha256").update(`${evidenceId}\u0000acquired`).digest("hex").slice(0, 40)}`,
        evidenceId, this.#configuration.agentId,
        JSON.stringify({ sourceEvidenceIds: input.sourceEvidenceIds, contentHash: content.sha256 }), now,
        `custody_${createHash("sha256").update(`${evidenceId}\u0000verified`).digest("hex").slice(0, 40)}`,
        evidenceId, "autonomous-cve-applicability-verifier",
        JSON.stringify({ method: "authoritative_catalog_and_local_range_match", criterionId }), now,
      );
      this.#events.append({
        id: `event_cve_${createHash("sha256").update(current.action.id).digest("hex").slice(0, 40)}`,
        missionId: current.action.missionId,
        runId: current.action.runId,
        journey: "autonomous",
        eventType: "autonomous_cve_applicability_completed",
        occurredAt: now,
        actorType: "agent",
        actorId: this.#configuration.agentId,
        summary,
        payload: {
          evidenceId,
          applicabilityRecordIds: input.records.map(({ id }) => id),
          catalogQueryReceipts: input.catalogReceipts.map(({
            queryReceiptId,
            queryReceiptSha256,
          }) => ({ queryReceiptId, queryReceiptSha256 })),
          immutableResultReceiptSha256: content.sha256,
          criterionId,
        },
        sensitivity: "private",
        contextPackId: input.contextPackId,
      });
      const result: ExecutionResult = Object.freeze({
        actionId: current.action.id,
        runId: current.action.runId,
        actionFingerprint: current.action.fingerprint,
        success: true,
        summary: `${summary} The result is linked to verified service/version evidence and exact authoritative source receipts.`,
        progress: Object.freeze({
          stepStates: Object.freeze({ [current.action.stepId]: "completed" as const }),
          evidenceIds: Object.freeze([evidenceId]),
          successCriteria: Object.freeze({ [criterionId]: 1 }),
        }),
        usage: Object.freeze({ wallClockMs: this.#now().getTime() - input.startedAt.getTime() }),
      });
      const payload: TerminalPayload = Object.freeze({
        schemaVersion: AUTONOMOUS_CVE_APPLICABILITY_RESULT_SCHEMA_VERSION,
        contextPackId: input.contextPackId,
        sourceEvidenceIds: Object.freeze([...input.sourceEvidenceIds]),
        applicabilityRecordIds: Object.freeze(input.records.map(({ id }) => id)),
        evidenceIds: Object.freeze([evidenceId]),
        catalogQueryReceiptIds: Object.freeze(input.catalogReceipts.map(({ queryReceiptId }) => queryReceiptId)),
        catalogQueryReceipts: Object.freeze(input.catalogReceipts.map(({
          queryReceiptId,
          queryReceiptSha256,
        }) => Object.freeze({ queryReceiptId, queryReceiptSha256 }))),
        nvdEnrichmentReceiptIds: Object.freeze(input.nvdDetails.map(({ provenance }) => provenance.invocationId)),
        immutableResultReceiptSha256: content.sha256,
        deliveryResult: result,
        resultAccepted: false,
        deliveryAttemptCount: 0,
        deliveryLastAttemptAt: null,
        deliveryLastError: null,
      });
      const changed = this.options.database.prepare(`
        UPDATE tool_calls SET status = 'succeeded', error_category = NULL,
          latency_ms = ?, output_summary = ?, redacted_payload_json = ?, ended_at = ?
        WHERE id = ? AND status = 'running'
      `).run(
        Math.max(0, this.#now().getTime() - input.startedAt.getTime()), result.summary,
        JSON.stringify(payload), now, input.invocationId,
      ).changes;
      if (changed !== 1) throw new Error("The CVE tool-call terminal receipt changed before commit");
      return payload;
    });
  }

  async dispatch(input: DurableAction, signal: AbortSignal): Promise<void> {
    if (!this.#sink) throw new AutonomousCveApplicabilityExecutionError(
      "result_sink_unbound", "dependency_missing",
      "Mission runtime result delivery must be bound before CVE applicability execution.",
    );
    const canonical = this.canonical(input);
    const invocationId = autonomousCveApplicabilityToolCallId(canonical.action.id);
    const startedAt = this.#now();
    const controller = new AbortController();
    this.#controllers.set(canonical.action.runId, controller);
    const effectiveSignal = AbortSignal.any([signal, controller.signal]);
    this.options.database.prepare(`
      INSERT INTO tool_calls (
        id, action_id, provider, tool_name, mcp_server_id,
        normalized_arguments_json, status, started_at, created_at
      ) VALUES (?, ?, 'reviewed-local-intelligence', ?, NULL, ?, 'running', ?, ?)
    `).run(
      invocationId, canonical.action.id, AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
      JSON.stringify({
        catalogId: this.#configuration.catalogId,
        catalogSnapshotSha256: this.#configuration.catalogSnapshotSha256,
        target: canonical.action.target,
        targetInteraction: false,
      }), startedAt.toISOString(), startedAt.toISOString(),
    );
    let contextPackId: string | null = null;
    try {
      const evidence = this.#resolver.resolve({
        missionId: canonical.action.missionId,
        runId: canonical.action.runId,
        stepId: canonical.action.stepId,
        target: canonical.action.target,
        fallbackAgentId: this.#configuration.agentId,
      });
      if (evidence.length === 0) {
        throw new AutonomousCveApplicabilityExecutionError(
          "autonomous_cve_verified_version_evidence_missing",
          "evidence_insufficient",
          "No verified evidence-backed service product/version observation is eligible for CVE matching.",
        );
      }
      const context = this.context(canonical, evidence.map(({ evidenceId }) => evidenceId));
      contextPackId = context.contextPack.id;
      const receipts: AuthoritativeCveCatalogQueryReceipt[] = [];
      const generated: AutonomousCveCandidateRecord[] = [];
      for (const source of evidence) {
        const receipt = await this.options.catalog.lookup(source, effectiveSignal);
        assertCatalogReceipt(receipt, source, this.#configuration);
        receipts.push(receipt);
        if (receipt.candidates.length) {
          generated.push(...this.#candidates.create({ evidence: source, candidates: receipt.candidates }));
        }
      }
      // Recheck exact authority after asynchronous local catalogue reads.
      const current = this.canonical(canonical.action);
      if (current.lease.leaseOwner !== canonical.lease.leaseOwner) {
        throw new AutonomousCveApplicabilityExecutionError(
          "autonomous_cve_owner_fence_changed", "worker_lost",
          "The control-plane owner changed while the reviewed catalogue was queried.",
        );
      }
      let persisted = generated.map((record) => this.persistCandidate(record));
      const nvdDetails: MissionScopedNvdDetailResult[] = [];
      if (this.#configuration.nvdEnrichment === "top_candidate" && persisted.length > 0) {
        const rank = new Map(["confirmed", "likely", "possible", "insufficient_evidence", "not_applicable"]
          .map((value, index) => [value, index]));
        const top = [...persisted].sort((left, right) =>
          (rank.get(left.applicability) ?? 99) - (rank.get(right.applicability) ?? 99)
          || right.confidence - left.confidence || left.cveId.localeCompare(right.cveId))[0]!;
        if (top.applicability !== "not_applicable" && top.applicability !== "insufficient_evidence") {
          const detail = await this.options.enrichment!.lookupExactCandidate({
            missionId: top.missionId,
            runId: top.runId!,
            stepId: canonical.action.stepId,
            reviewedCveRef: top.id,
          }, effectiveSignal);
          nvdDetails.push(detail);
          const enriched = this.enrich(top, detail);
          persisted = persisted.map((record) => record.id === enriched.id ? enriched : record);
        }
      }
      this.commitSuccess({
        canonical,
        contextPackId,
        sourceEvidenceIds: [...new Set(evidence.map(({ evidenceId }) => evidenceId))],
        records: persisted,
        catalogReceipts: receipts,
        nvdDetails,
        startedAt,
        invocationId,
      });
      await this.deliver(invocationId);
    } catch (error) {
      const terminal = failureResult(canonical.action, error, this.#now().getTime() - startedAt.getTime());
      const payload: TerminalPayload = {
        schemaVersion: AUTONOMOUS_CVE_APPLICABILITY_RESULT_SCHEMA_VERSION,
        contextPackId, sourceEvidenceIds: [], applicabilityRecordIds: [], evidenceIds: [],
        catalogQueryReceiptIds: [], catalogQueryReceipts: [], nvdEnrichmentReceiptIds: [],
        immutableResultReceiptSha256: null,
        deliveryResult: terminal, resultAccepted: false, deliveryAttemptCount: 0,
        deliveryLastAttemptAt: null, deliveryLastError: null,
      };
      this.options.database.prepare(`
        UPDATE tool_calls SET status = 'failed', error_category = ?, latency_ms = ?,
          output_summary = ?, redacted_payload_json = ?, ended_at = ?
        WHERE id = ? AND status = 'running'
      `).run(
        terminal.failureCategory ?? "unknown", terminal.usage?.wallClockMs ?? 0,
        terminal.summary, JSON.stringify(payload), this.#now().toISOString(), invocationId,
      );
      await this.deliver(invocationId);
    } finally {
      this.#controllers.delete(canonical.action.runId);
    }
  }

  resume(action: DurableAction, _signal: AbortSignal): Promise<void> {
    const row = this.options.database.prepare(
      "SELECT id FROM tool_calls WHERE id = ? AND status IN ('succeeded','failed')",
    ).get(autonomousCveApplicabilityToolCallId(action.id));
    return row ? this.deliver(autonomousCveApplicabilityToolCallId(action.id)).then(() => undefined)
      : Promise.reject(new AutonomousCveApplicabilityExecutionError(
          "autonomous_cve_resume_receipt_missing", "process_crash",
          "The idempotent CVE action has no durable terminal receipt to resume.",
        ));
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    this.#controllers.get(runId)?.abort(new Error(reason));
  }

  private async deliver(invocationId: string): Promise<boolean> {
    if (!this.#sink) return false;
    const row = this.options.database.prepare(
      "SELECT id, redacted_payload_json FROM tool_calls WHERE id = ? AND status IN ('succeeded','failed')",
    ).get(invocationId) as PendingRow | undefined;
    if (!row) return false;
    const payload = parsePayload(row.redacted_payload_json);
    if (!payload || payload.resultAccepted || payload.deliveryAttemptCount >= TERMINAL_ATTEMPT_LIMIT) return false;
    const attemptedAt = this.#now().toISOString();
    try {
      const receipt: ExecutionResultReceipt = await this.#sink.acceptExecutionResult(payload.deliveryResult);
      if (!receipt.accepted || receipt.actionId !== payload.deliveryResult.actionId
        || receipt.runId !== payload.deliveryResult.runId) throw new Error("Runtime rejected the correlated result");
      this.options.database.prepare(
        "UPDATE tool_calls SET redacted_payload_json = ? WHERE id = ?",
      ).run(JSON.stringify({
        ...payload, resultAccepted: true,
        deliveryAttemptCount: payload.deliveryAttemptCount + 1,
        deliveryLastAttemptAt: attemptedAt, deliveryLastError: null,
      }), invocationId);
      return true;
    } catch (error) {
      this.options.database.prepare(
        "UPDATE tool_calls SET redacted_payload_json = ? WHERE id = ?",
      ).run(JSON.stringify({
        ...payload, resultAccepted: false,
        deliveryAttemptCount: payload.deliveryAttemptCount + 1,
        deliveryLastAttemptAt: attemptedAt,
        deliveryLastError: (error instanceof Error ? error.message : "delivery failed").slice(0, 500),
      }), invocationId);
      return false;
    }
  }

  async replayPendingResults(limit = 100): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) throw new RangeError("limit must be 1 through 1000");
    const rows = this.options.database.prepare(`
      SELECT tc.id, tc.redacted_payload_json FROM tool_calls tc
      JOIN actions a ON a.id = tc.action_id
      WHERE tc.tool_name = ? AND tc.status IN ('succeeded','failed')
      ORDER BY tc.ended_at, tc.id LIMIT ?
    `).all(AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE, limit) as PendingRow[];
    let accepted = 0;
    for (const row of rows) {
      const payload = parsePayload(row.redacted_payload_json);
      if (payload && !payload.resultAccepted && await this.deliver(row.id)) accepted += 1;
    }
    return accepted;
  }
}

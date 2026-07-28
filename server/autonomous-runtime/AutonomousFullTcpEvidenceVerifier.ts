import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { isIP } from "node:net";
import { isAbsolute, join, relative, sep } from "node:path";
import type { ExecutionResult } from "../command-runtime";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { agentAssignmentBindsRuntimeAgent } from "../agents";
import { OperationalTruthService } from "../intelligence-v24";
import type { EngagementWorkspaceResolver } from "../system-capabilities";
import { ReviewedNmapTopologyMaterializer } from "../local-tools";
import { digestCanonicalJson } from "../mcp";
import { ActionRepository, reviewedLocalToolActionEnvelope } from "../orchestration";
import {
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_MAX_TOTAL_OUTPUT_BYTES,
  AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE,
  AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
  createAutonomousFullTcpBaselinePolicy,
  type AutonomousFullTcpBaselinePolicy,
} from "./AutonomousFullTcpBaseline";
import {
  AUTONOMOUS_FULL_TCP_BASELINE_RESULT_SCHEMA_VERSION,
  AUTONOMOUS_FULL_TCP_NORMALIZER_VERSION,
  type AutonomousFullTcpArtifact,
  type AutonomousFullTcpBaselineResult,
} from "./AutonomousFullTcpBaselineExecution";
import type { AutonomousFullTcpPlanningConfiguration } from "./AutonomousGeneralSafeRecon";
import {
  AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
  autonomousSuccessCriterionId,
} from "./LocalVerifiedEvidenceOutcomeEvaluator";
import type { LocalToolCapabilityManifest } from "../local-tools";

export const AUTONOMOUS_FULL_TCP_EVIDENCE_VERIFIER_SCHEMA_VERSION =
  "ti-scale.autonomous-full-tcp-evidence-verifier.v1" as const;
export const AUTONOMOUS_FULL_TCP_RESULT_DELIVERY_SCHEMA_VERSION =
  "ti-scale.autonomous-full-tcp-result-delivery.v1" as const;

const RECEIPT_PREFIX = "idempotency.autonomous-full-tcp-evidence.";
const SHA256 = /^[a-f0-9]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,511}$/u;

export function autonomousFullTcpCompositeToolCallId(actionId: string): string {
  return `full_tcp_composite_${createHash("sha256").update(actionId, "utf8").digest("hex").slice(0, 40)}`;
}

interface CanonicalBoundaryRow {
  readonly journey: string;
  readonly run_control_plane: string;
  readonly mission_control_plane: string;
  readonly authorization_status: string;
  readonly mission_success_criteria_json: string;
  readonly run_contract_id: string | null;
  readonly contract_version_bound: number | null;
  readonly contract_hash_bound: string | null;
  readonly contract_version: number | null;
  readonly contract_hash: string | null;
  readonly contract_state: string | null;
  readonly action_policy_json: string | null;
  readonly assigned_agent_id: string | null;
  readonly assignment_lease_owner: string | null;
  readonly control_lease_owner: string | null;
  readonly control_lease_expires_at: string | null;
  readonly control_lease_released_at: string | null;
  readonly plan_id: string;
  readonly tool_call_started_at: string | null;
  readonly tool_call_status: string | null;
  readonly mission_target_id: string | null;
}

interface PromotionReceipt {
  readonly schemaVersion: typeof AUTONOMOUS_FULL_TCP_EVIDENCE_VERIFIER_SCHEMA_VERSION;
  readonly actionId: string;
  readonly actionFingerprint: string;
  readonly resultSha256: string;
  readonly logRecordId: string;
  readonly observationId: string;
  readonly evidenceIds: readonly [string, string];
  readonly executionResult: ExecutionResult;
}

export interface AutonomousFullTcpEvidencePromotionResult {
  readonly executionResult: ExecutionResult;
  readonly logRecordId: string;
  readonly observationId: string;
  readonly evidenceIds: readonly [string, string];
  readonly duplicate: boolean;
}

export interface AutonomousFullTcpEvidenceVerifierOptions {
  readonly database: SqliteDatabase;
  readonly manifest: LocalToolCapabilityManifest;
  readonly configuration: AutonomousFullTcpPlanningConfiguration;
  readonly workspaceResolver: EngagementWorkspaceResolver;
  readonly now?: () => Date;
}

export class AutonomousFullTcpEvidenceVerificationError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "AutonomousFullTcpEvidenceVerificationError";
  }
}

function plain(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseObject(value: string | null, label: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(value ?? "null") as unknown;
    if (!plain(parsed)) throw new Error("not an object");
    return parsed;
  } catch {
    throw new AutonomousFullTcpEvidenceVerificationError(
      "full_tcp_contract_malformed",
      `The canonical ${label} is malformed.`,
    );
  }
}

function parseStringArray(value: string, label: string): readonly string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)
      || parsed.some((item) => typeof item !== "string" || !item.trim())) throw new Error("invalid");
    return parsed as string[];
  } catch {
    throw new AutonomousFullTcpEvidenceVerificationError(
      "full_tcp_contract_malformed",
      `The canonical ${label} is malformed.`,
    );
  }
}

function exactKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function canonicalIp(value: string): string {
  if (value !== value.trim() || isIP(value) === 0) {
    throw new AutonomousFullTcpEvidenceVerificationError(
      "full_tcp_ip_literal_required",
      "Full-TCP evidence requires the exact authorized canonical IP literal; hostnames are not accepted.",
    );
  }
  // URL canonicalization provides a stable compressed spelling for IPv6 while
  // leaving IPv4 unchanged. Strip brackets introduced for IPv6 host syntax.
  const hostname = new URL(`http://${isIP(value) === 6 ? `[${value}]` : value}/`).hostname;
  const normalized = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
  if (normalized !== value.toLowerCase()) {
    throw new AutonomousFullTcpEvidenceVerificationError(
      "full_tcp_ip_not_canonical",
      "Full-TCP evidence requires the same canonical IP spelling used by the signed mission scope.",
    );
  }
  return normalized;
}

function inside(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

function unsignedResult(result: AutonomousFullTcpBaselineResult): Readonly<Record<string, unknown>> {
  const { resultSha256: _resultSha256, artifacts, ...body } = result;
  return {
    ...body,
    artifacts: artifacts.filter(({ kind }) => kind !== "structured_result"),
  };
}

function validateResultStructure(
  result: AutonomousFullTcpBaselineResult,
  policy: AutonomousFullTcpBaselinePolicy,
  manifestSha256: string,
): void {
  const target = canonicalIp(result.target);
  const ports = result.ports;
  const discoveryPorts = result.discovery.normalized.openPorts;
  const requestedPorts = result.serviceVersionBatches.flatMap(({ normalized }) =>
    normalized.requestedPorts);
  if (result.schemaVersion !== AUTONOMOUS_FULL_TCP_BASELINE_RESULT_SCHEMA_VERSION
    || result.status !== "completed"
    || !SHA256.test(result.resultSha256)
    || digestCanonicalJson(unsignedResult(result), {
      maxBytes: 2 * 1024 * 1024,
      maxDepth: 24,
    }).sha256 !== result.resultSha256
    || result.policyId !== policy.policyId
    || result.bindingId !== policy.bindingId
    || result.manifestSha256 !== manifestSha256
    || result.discovery.normalized.normalizerVersion !== AUTONOMOUS_FULL_TCP_NORMALIZER_VERSION
    || result.discovery.normalized.target !== target
    || result.discovery.normalized.scannedPortRange !== "1-65535"
    || result.discovery.normalized.hostReportedUp !== true
    || result.discovery.normalized.scanCompleted !== true
    || result.verification.state !== "verified"
    || result.verification.verifierVersion !== AUTONOMOUS_FULL_TCP_NORMALIZER_VERSION
    || result.verification.exactTargetMatched !== true
    || result.verification.fullRangeDiscoveryCompleted !== true
    || result.verification.discoveredPortCoverageComplete !== true
    || result.verification.processResultsComplete !== true
    || result.verification.outputWithinBound !== true
    || result.evidence.eligibleForExplicitPromotion !== true
    || result.evidence.automaticallyPromoted !== false
    || result.evidence.evidenceIds.length !== 0
    || discoveryPorts.length !== result.discoveredOpenPortCount
    || new Set(discoveryPorts).size !== discoveryPorts.length
    || discoveryPorts.some((port, index) => !Number.isSafeInteger(port) || port < 1 || port > 65_535
      || (index > 0 && port <= discoveryPorts[index - 1]!))
    || requestedPorts.length !== discoveryPorts.length
    || requestedPorts.some((port, index) => port !== discoveryPorts[index])
    || ports.length !== discoveryPorts.length
    || ports.some((port, index) => port.port !== discoveryPorts[index]
      || port.transport !== "tcp" || port.state !== "open"
      || !(port.service === null || typeof port.service === "string")
      || !(port.version === null || typeof port.version === "string"))) {
    throw new AutonomousFullTcpEvidenceVerificationError(
      "full_tcp_result_integrity_invalid",
      "The composite result no longer matches its deterministic full-range and discovered-port coverage proof.",
    );
  }
}

function receipt(value: string): PromotionReceipt {
  const parsed = JSON.parse(value) as unknown;
  if (!plain(parsed)
    || parsed.schemaVersion !== AUTONOMOUS_FULL_TCP_EVIDENCE_VERIFIER_SCHEMA_VERSION
    || typeof parsed.actionId !== "string"
    || typeof parsed.actionFingerprint !== "string"
    || typeof parsed.resultSha256 !== "string"
    || typeof parsed.logRecordId !== "string"
    || typeof parsed.observationId !== "string"
    || !Array.isArray(parsed.evidenceIds) || parsed.evidenceIds.length !== 2
    || parsed.evidenceIds.some((id) => typeof id !== "string")
    || !plain(parsed.executionResult)) {
    throw new Error("Stored Full-TCP evidence receipt is invalid");
  }
  return parsed as unknown as PromotionReceipt;
}

export class AutonomousFullTcpEvidenceVerifier {
  readonly #policy: AutonomousFullTcpBaselinePolicy;
  readonly #now: () => Date;
  readonly #actions: ActionRepository;

  constructor(private readonly options: AutonomousFullTcpEvidenceVerifierOptions) {
    this.#policy = createAutonomousFullTcpBaselinePolicy(options.configuration, options.manifest);
    this.#now = options.now ?? (() => new Date());
    this.#actions = new ActionRepository(options.database);
  }

  private receiptKey(actionId: string): string {
    return `${RECEIPT_PREFIX}${createHash("sha256").update(actionId, "utf8").digest("hex")}`;
  }

  private canonicalBoundary(result: AutonomousFullTcpBaselineResult): CanonicalBoundaryRow {
    const action = this.#actions.get(result.actionId);
    const envelope = reviewedLocalToolActionEnvelope(action.arguments);
    if (action.fingerprint !== result.actionFingerprint
      || action.missionId !== result.missionId || action.runId !== result.runId
      || action.contractId !== result.contractId
      || action.actionType !== AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE
      || action.actionClass !== AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS
      || action.kind !== "tool" || action.status !== "running"
      || action.destructive || !action.idempotent
      || action.guidedDecisionId !== null
      || action.target !== result.target
      || !envelope || envelope.toolId !== AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE
      || !exactKeys(envelope.parameters, ["target", "workspace"])
      || envelope.parameters.target !== result.target
      || envelope.parameters.workspace !== this.#policy.logicalWorkspace) {
      throw new AutonomousFullTcpEvidenceVerificationError(
        "full_tcp_action_binding_changed",
        "The Full-TCP result differs from the exact canonical running action and reviewed local envelope.",
      );
    }
    const toolCallId = autonomousFullTcpCompositeToolCallId(action.id);
    const row = this.options.database.prepare(`
      SELECT r.journey, r.control_plane AS run_control_plane,
        m.control_plane AS mission_control_plane, m.authorization_status,
        m.success_criteria_json AS mission_success_criteria_json,
        r.contract_id AS run_contract_id, r.contract_version_bound,
        r.contract_hash_bound, mc.version AS contract_version,
        mc.contract_hash, mc.state AS contract_state, mc.action_policy_json,
        ps.assigned_agent_id, ps.plan_id,
        assn.lease_owner AS assignment_lease_owner,
        cpl.lease_owner AS control_lease_owner,
        cpl.expires_at AS control_lease_expires_at,
        cpl.released_at AS control_lease_released_at,
        tc.started_at AS tool_call_started_at, tc.status AS tool_call_status,
        mt.id AS mission_target_id
      FROM actions a
      JOIN runs r ON r.id = a.run_id AND r.mission_id = a.mission_id
      JOIN missions m ON m.id = r.mission_id
      JOIN plan_steps ps ON ps.id = a.step_id AND ps.run_id = r.id
      JOIN assignments assn ON assn.id = a.assignment_id AND assn.step_id = ps.id
      LEFT JOIN mission_contracts mc ON mc.id = r.contract_id AND mc.mission_id = m.id
      LEFT JOIN control_plane_leases cpl ON cpl.run_id = r.id
      LEFT JOIN tool_calls tc ON tc.id = ? AND tc.action_id = a.id
      LEFT JOIN mission_targets mt ON mt.mission_id = m.id
        AND mt.disposition = 'allowed'
        AND (mt.target = a.scoped_target COLLATE NOCASE
          OR mt.normalized_target = a.scoped_target COLLATE NOCASE)
      WHERE a.id = ? AND a.status = 'running' AND assn.status = 'active'
    `).get(toolCallId, action.id) as CanonicalBoundaryRow | undefined;
    const now = this.#now().getTime();
    if (!row || row.journey !== "autonomous"
      || row.run_control_plane !== "ti_scale" || row.mission_control_plane !== "ti_scale"
      || row.authorization_status !== "verified" || row.contract_state !== "confirmed"
      || row.run_contract_id !== result.contractId
      || row.contract_hash !== result.contractHash
      || row.contract_hash_bound !== result.contractHash
      || row.contract_version_bound !== row.contract_version
      || !agentAssignmentBindsRuntimeAgent(
        this.options.database,
        row.assigned_agent_id,
        this.#policy.agentId,
      )
      || !row.assignment_lease_owner
      || row.assignment_lease_owner !== row.control_lease_owner
      || row.control_lease_released_at !== null
      || !row.control_lease_expires_at || Date.parse(row.control_lease_expires_at) <= now
      || row.tool_call_status !== "running" || !row.tool_call_started_at
      || !row.mission_target_id) {
      throw new AutonomousFullTcpEvidenceVerificationError(
        "full_tcp_owner_fence_invalid",
        "Authorization, contract binding, exact scope, specialist assignment, or the run owner fence changed before Full-TCP evidence promotion.",
      );
    }
    const scopeRows = this.options.database.prepare(`
      SELECT disposition, target, normalized_target FROM mission_targets WHERE mission_id = ?
    `).all(result.missionId) as Array<{
      readonly disposition: string;
      readonly target: string;
      readonly normalized_target: string;
    }>;
    const allowed = scopeRows.filter(({ disposition }) => disposition === "allowed");
    if (allowed.length !== 1
      || canonicalIp(allowed[0]!.normalized_target) !== result.target
      || scopeRows.some(({ disposition, normalized_target }) =>
        disposition === "prohibited" && (() => {
          try { return canonicalIp(normalized_target) === result.target; } catch { return false; }
        })())) {
      throw new AutonomousFullTcpEvidenceVerificationError(
        "full_tcp_target_outside_scope",
        "The Full-TCP result target is not the one exact canonical IP allowed by the signed mission.",
      );
    }
    const policy = parseObject(row.action_policy_json, "action policy");
    const allowedClasses = Array.isArray(policy.allowedActionClasses)
      ? policy.allowedActionClasses.filter((value): value is string => typeof value === "string") : [];
    const prohibitedClasses = Array.isArray(policy.prohibitedActionClasses)
      ? policy.prohibitedActionClasses.filter((value): value is string => typeof value === "string") : [];
    const specialists = Array.isArray(policy.specialistAgentIds)
      ? policy.specialistAgentIds.filter((value): value is string => typeof value === "string") : [];
    if (!allowedClasses.includes(AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS)
      || prohibitedClasses.includes(AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS)
      || !row.assigned_agent_id
      || !specialists.includes(row.assigned_agent_id)
      || !parseStringArray(row.mission_success_criteria_json, "success criteria")
        .includes(this.options.configuration.successCriterion)) {
      throw new AutonomousFullTcpEvidenceVerificationError(
        "full_tcp_contract_policy_denied",
        "The signed contract does not pre-authorize this exact Full-TCP class, specialist, and success criterion.",
      );
    }
    const startedAt = Date.parse(result.startedAt);
    const endedAt = Date.parse(result.endedAt);
    if (!Number.isFinite(startedAt) || !Number.isFinite(endedAt)
      || startedAt < Date.parse(row.tool_call_started_at)
      || endedAt < startedAt || endedAt > now + 60_000) {
      throw new AutonomousFullTcpEvidenceVerificationError(
        "full_tcp_result_timestamp_invalid",
        "The Full-TCP result is outside the canonical tool-call and current owner-fence interval.",
      );
    }
    return row;
  }

  private async verifyArtifacts(result: AutonomousFullTcpBaselineResult): Promise<void> {
    const workspace = await this.options.workspaceResolver.resolve(this.#policy.logicalWorkspace);
    if (workspace.status !== "resolved" || !workspace.resolvedPath) {
      throw new AutonomousFullTcpEvidenceVerificationError(
        `full_tcp_workspace_${workspace.code}`,
        workspace.explanation,
      );
    }
    const root = await realpath(workspace.resolvedPath);
    if (root !== workspace.resolvedPath || result.artifacts.length < 3
      || result.artifacts.filter(({ kind }) => kind === "structured_result").length !== 1) {
      throw new AutonomousFullTcpEvidenceVerificationError(
        "full_tcp_artifact_set_invalid",
        "The Full-TCP artifact set or resolved workspace identity is incomplete.",
      );
    }
    let total = 0;
    let structuredBytes: Buffer | undefined;
    for (const artifact of result.artifacts) {
      const bytes = await this.verifyArtifact(root, artifact);
      if (artifact.kind === "structured_result") structuredBytes = bytes;
      total += artifact.sizeBytes;
    }
    if (total > AUTONOMOUS_FULL_TCP_MAX_TOTAL_OUTPUT_BYTES + 2 * 1024 * 1024) {
      throw new AutonomousFullTcpEvidenceVerificationError(
        "full_tcp_artifact_bound_exceeded",
        "The Full-TCP artifact set exceeds its reviewed aggregate bound.",
      );
    }
    const structured = result.artifacts.find(({ kind }) => kind === "structured_result")!;
    if (!structuredBytes) throw new Error(`Verified bytes are missing for ${structured.relativePath}`);
    const stored = JSON.parse(structuredBytes.toString("utf8")) as unknown;
    if (!plain(stored) || stored.resultSha256 !== result.resultSha256
      || digestCanonicalJson(stored, { maxBytes: 2 * 1024 * 1024, maxDepth: 24 }).canonicalJson
        !== digestCanonicalJson({ ...unsignedResult(result), resultSha256: result.resultSha256 }, {
          maxBytes: 2 * 1024 * 1024,
          maxDepth: 24,
        }).canonicalJson) {
      throw new AutonomousFullTcpEvidenceVerificationError(
        "full_tcp_structured_artifact_invalid",
        "The stored structured Full-TCP artifact differs from the deterministic result receipt.",
      );
    }
  }

  private async verifyArtifact(root: string, artifact: AutonomousFullTcpArtifact): Promise<Buffer> {
    if (!artifact.relativePath || isAbsolute(artifact.relativePath)
      || artifact.relativePath.startsWith(`..${sep}`) || artifact.relativePath === ".."
      || !SHA256.test(artifact.sha256) || !Number.isSafeInteger(artifact.sizeBytes)
      || artifact.sizeBytes < 0
      || artifact.logicalPath !== join(this.#policy.logicalWorkspace, artifact.relativePath)) {
      throw new AutonomousFullTcpEvidenceVerificationError(
        "full_tcp_artifact_receipt_invalid",
        "A Full-TCP artifact receipt is malformed or outside the reviewed logical workspace.",
      );
    }
    const path = join(root, artifact.relativePath);
    const canonical = await realpath(path);
    const pathMetadata = await lstat(path);
    if (!inside(root, canonical) || canonical !== path || pathMetadata.isSymbolicLink()
      || !pathMetadata.isFile() || pathMetadata.size !== artifact.sizeBytes) {
      throw new AutonomousFullTcpEvidenceVerificationError(
        "full_tcp_artifact_identity_changed",
        "A Full-TCP artifact changed identity or escaped the reviewed workspace.",
      );
    }
    const handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    try {
      const before = await handle.stat();
      if (!before.isFile() || before.size !== artifact.sizeBytes
        || before.dev !== pathMetadata.dev || before.ino !== pathMetadata.ino) {
        throw new AutonomousFullTcpEvidenceVerificationError(
          "full_tcp_artifact_identity_changed",
          "A Full-TCP artifact changed identity while its immutable receipt was checked.",
        );
      }
      const bytes = await handle.readFile();
      const after = await handle.stat();
      if (after.dev !== before.dev || after.ino !== before.ino
        || after.size !== before.size || after.mtimeMs !== before.mtimeMs
        || createHash("sha256").update(bytes).digest("hex") !== artifact.sha256) {
        throw new AutonomousFullTcpEvidenceVerificationError(
          "full_tcp_artifact_hash_changed",
          "A Full-TCP artifact no longer matches its immutable SHA-256 receipt.",
        );
      }
      return bytes;
    } finally {
      await handle.close();
    }
  }

  private insertEvidence(input: Readonly<{
    result: AutonomousFullTcpBaselineResult;
    observationId: string;
    logRecordId: string;
    evidenceType: typeof AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE
      | typeof AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE;
    summary: string;
    normalized: Readonly<Record<string, unknown>>;
    confidence: number;
  }>): string {
    const content = digestCanonicalJson(input.normalized, { maxBytes: 2 * 1024 * 1024, maxDepth: 32 });
    const criterionId = autonomousSuccessCriterionId(this.options.configuration.successCriterion);
    const evidenceId = `evidence_full_tcp_${createHash("sha256")
      .update(`${input.result.actionId}\u0000${input.evidenceType}\u0000${content.sha256}`, "utf8")
      .digest("hex").slice(0, 40)}`;
    const provenance = digestCanonicalJson({
      schemaVersion: AUTONOMOUS_FULL_TCP_EVIDENCE_VERIFIER_SCHEMA_VERSION,
      method: "deterministic_full_tcp_artifact_and_coverage_validation",
      actionId: input.result.actionId,
      actionFingerprint: input.result.actionFingerprint,
      toolCallId: autonomousFullTcpCompositeToolCallId(input.result.actionId),
      observationId: input.observationId,
      logRecordId: input.logRecordId,
      specialistAgentId: this.#policy.agentId,
      executionBinding: "reviewed_local_process",
      compositeToolId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
      phaseToolIds: this.#policy.phases.map(({ toolId }) => toolId),
      manifestSha256: this.options.manifest.descriptor.manifestSha256,
      resultSha256: input.result.resultSha256,
      artifactSha256s: input.result.artifacts.map(({ sha256 }) => sha256),
      rawProcessOutputPromoted: false,
      cveClaimsCreated: false,
      successCriterionReferences: [{
        schemaVersion: AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
        criterionId,
        outcome: "achieved" as const,
      }],
    }, { maxBytes: 2 * 1024 * 1024, maxDepth: 32 });
    const createdAt = this.#now().toISOString();
    this.options.database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, step_id, action_id, source, acquired_at,
        target, evidence_type, content_hash, provenance_json, confidence,
        sensitivity, verification_state, summary, extracted_text,
        artifact_id, created_by, created_at
      ) SELECT ?, mission_id, run_id, step_id, id, ?, ?, scoped_target, ?, ?, ?, ?,
        'private', 'verified', ?, ?, NULL, 'autonomous-full-tcp-evidence-verifier', ?
      FROM actions WHERE id = ?
    `).run(
      evidenceId,
      `specialist:${this.#policy.agentId}`,
      input.result.endedAt,
      input.evidenceType,
      content.sha256,
      provenance.canonicalJson,
      input.confidence,
      input.summary,
      content.canonicalJson,
      createdAt,
      input.result.actionId,
    );
    const acquiredId = `custody_${createHash("sha256").update(`${evidenceId}\u0000acquired`).digest("hex").slice(0, 40)}`;
    const verifiedId = `custody_${createHash("sha256").update(`${evidenceId}\u0000verified`).digest("hex").slice(0, 40)}`;
    this.options.database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'acquired', ?, ?, ?), (?, ?, 'verified', ?, ?, ?)
    `).run(
      acquiredId,
      evidenceId,
      this.#policy.agentId,
      digestCanonicalJson({
        observationId: input.observationId,
        logRecordId: input.logRecordId,
        resultSha256: input.result.resultSha256,
        contentHash: content.sha256,
      }, { maxBytes: 32 * 1_024, maxDepth: 8 }).canonicalJson,
      input.result.endedAt,
      verifiedId,
      evidenceId,
      "autonomous-full-tcp-evidence-verifier",
      digestCanonicalJson({
        method: "deterministic_full_tcp_artifact_and_coverage_validation",
        criterionId,
        rawProcessOutputPromoted: false,
        cveClaimsCreated: false,
      }, { maxBytes: 32 * 1_024, maxDepth: 8 }).canonicalJson,
      createdAt,
    );
    return evidenceId;
  }

  async process(result: AutonomousFullTcpBaselineResult): Promise<AutonomousFullTcpEvidencePromotionResult> {
    const key = this.receiptKey(result.actionId);
    const stored = this.options.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(key) as { readonly value_json: string } | undefined;
    if (stored) {
      const parsed = receipt(stored.value_json);
      if (parsed.actionId !== result.actionId
        || parsed.actionFingerprint !== result.actionFingerprint
        || parsed.resultSha256 !== result.resultSha256) {
        throw new Error("Stored Full-TCP evidence receipt conflicts with this result");
      }
      return { ...parsed, duplicate: true };
    }

    validateResultStructure(
      result,
      this.#policy,
      this.options.manifest.descriptor.manifestSha256,
    );
    const boundary = this.canonicalBoundary(result);
    await this.verifyArtifacts(result);

    return inImmediateTransaction(this.options.database, () => {
      const concurrent = this.options.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(key) as { readonly value_json: string } | undefined;
      if (concurrent) {
        const parsed = receipt(concurrent.value_json);
        if (parsed.actionId !== result.actionId
          || parsed.actionFingerprint !== result.actionFingerprint
          || parsed.resultSha256 !== result.resultSha256) {
          throw new Error("Stored Full-TCP evidence receipt conflicts with this result");
        }
        return { ...parsed, duplicate: true };
      }
      // Recheck the canonical owner fence after asynchronous artifact reads.
      const currentBoundary = this.canonicalBoundary(result);
      if (currentBoundary.control_lease_owner !== boundary.control_lease_owner
        || currentBoundary.contract_hash !== boundary.contract_hash) {
        throw new AutonomousFullTcpEvidenceVerificationError(
          "full_tcp_owner_fence_changed",
          "The Full-TCP authority fence changed while artifacts were being verified.",
        );
      }
      const statement = result.ports.length === 0
        ? `The complete reviewed TCP-connect discovery checked ports 1-65535 on ${result.target} and found no listening TCP service.`
        : `The complete reviewed TCP-connect discovery checked ports 1-65535 on ${result.target}, found ${result.ports.length} listening TCP service${result.ports.length === 1 ? "" : "s"}, and versioned the exact discovered set.`;
      const truth = new OperationalTruthService(this.options.database, { clock: this.#now });
      const log = truth.appendEngagementLog({
        missionId: result.missionId,
        runId: result.runId,
        planId: boundary.plan_id,
        stepId: this.#actions.get(result.actionId).stepId,
        actionId: result.actionId,
        agentId: this.#policy.agentId,
        toolCallId: autonomousFullTcpCompositeToolCallId(result.actionId),
        severity: "notice",
        domain: "autonomous_full_tcp_baseline",
        recordType: "verified_composite_artifact_receipt",
        humanSummary: statement,
        technicalPayload: {
          resultSha256: result.resultSha256,
          target: result.target,
          scannedPortRange: "1-65535",
          discoveredOpenPortCount: result.discoveredOpenPortCount,
          versionedOpenPortCount: result.versionedOpenPortCount,
          portsNoLongerOpenAtVersionScan: result.portsNoLongerOpenAtVersionScan,
          artifacts: result.artifacts,
          rawProcessOutputPromoted: false,
          cveClaimsCreated: false,
        },
        sensitivity: "private",
        occurredAt: result.endedAt,
      });
      const observation = truth.createObservation({
        missionId: result.missionId,
        runId: result.runId,
        stepId: this.#actions.get(result.actionId).stepId,
        observationType: "tcp_service_scan",
        statement,
        normalizedValue: {
          schemaVersion: AUTONOMOUS_FULL_TCP_EVIDENCE_VERIFIER_SCHEMA_VERSION,
          missionId: result.missionId,
          runId: result.runId,
          missionTargetId: boundary.mission_target_id,
          toolId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
          actionId: result.actionId,
          toolCallId: autonomousFullTcpCompositeToolCallId(result.actionId),
          resultSha256: result.resultSha256,
          result: {
            host: result.target,
            hostReportedUp: true,
            scanCompleted: true,
            scannedPortRange: "1-65535",
            openPorts: result.ports,
          },
          rawProcessOutputPromoted: false,
          cveClaimsCreated: false,
        },
        confidence: 0.98,
        verificationState: "corroborated",
        sourceAgentId: this.#policy.agentId,
        sourceTool: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
        firstSeenAt: result.startedAt,
        lastSeenAt: result.endedAt,
        sensitivity: "private",
        sources: [{
          logRecordId: log.id,
          parserId: "ti-scale.autonomous-full-tcp-deterministic-verifier",
          parserVersion: "1.0.0",
        }],
      });
      const scanEvidenceId = this.insertEvidence({
        result,
        observationId: observation.id,
        logRecordId: log.id,
        evidenceType: AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE,
        summary: statement,
        normalized: {
          target: result.target,
          transport: "tcp",
          scanTechnique: "tcp_connect",
          completePortRange: "1-65535",
          openPorts: result.discovery.normalized.openPorts,
          resultSha256: result.resultSha256,
          observationId: observation.id,
          logRecordId: log.id,
        },
        confidence: 0.98,
      });
      const versionEvidenceId = this.insertEvidence({
        result,
        observationId: observation.id,
        logRecordId: log.id,
        evidenceType: AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
        summary: `The reviewed light version phase covered the exact ${result.discoveredOpenPortCount}-port discovery set on ${result.target}.`,
        normalized: {
          target: result.target,
          requestedPorts: result.discovery.normalized.openPorts,
          fingerprints: result.ports,
          portsNoLongerOpenAtVersionScan: result.portsNoLongerOpenAtVersionScan,
          identificationStrength: "nmap_version_light",
          discoveredPortCoverageComplete: true,
          cveApplicability: "not_evaluated",
          resultSha256: result.resultSha256,
          observationId: observation.id,
          logRecordId: log.id,
        },
        confidence: 0.95,
      });
      const evidenceIds = Object.freeze([scanEvidenceId, versionEvidenceId]) as readonly [string, string];
      for (const evidenceId of evidenceIds) {
        truth.repository.audit.append({
          missionId: result.missionId,
          runId: result.runId,
          actor: { id: "autonomous-full-tcp-evidence-verifier", type: "system" },
          action: "evidence.verified_deterministically",
          resourceType: "evidence",
          resourceId: evidenceId,
          reason: "The exact canonical IP, owner fence, full-range discovery, discovered-port coverage, immutable artifacts, and criterion binding passed deterministic checks.",
          details: {
            observationId: observation.id,
            logRecordId: log.id,
            resultSha256: result.resultSha256,
            rawProcessOutputPromoted: false,
            cveClaimsCreated: false,
          },
          occurredAt: this.#now().toISOString(),
        });
      }
      new ReviewedNmapTopologyMaterializer(this.options.database).materialize(
        observation,
        { verifiedEvidenceIds: evidenceIds },
      );
      const criterionId = autonomousSuccessCriterionId(this.options.configuration.successCriterion);
      const action = this.#actions.get(result.actionId);
      const executionResult: ExecutionResult = {
        actionId: action.id,
        runId: action.runId,
        actionFingerprint: action.fingerprint,
        success: true,
        summary: `${statement} Two verified evidence items and evidence-linked topology were retained with chain of custody.`,
        progress: {
          stepStates: { [action.stepId]: "completed" },
          evidenceIds,
          successCriteria: { [criterionId]: 1 },
        },
        usage: { wallClockMs: result.wallClockMs },
      };
      const persisted: PromotionReceipt = {
        schemaVersion: AUTONOMOUS_FULL_TCP_EVIDENCE_VERIFIER_SCHEMA_VERSION,
        actionId: action.id,
        actionFingerprint: action.fingerprint,
        resultSha256: result.resultSha256,
        logRecordId: log.id,
        observationId: observation.id,
        evidenceIds,
        executionResult,
      };
      this.options.database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'private', 1, 'autonomous-full-tcp-evidence-verifier', ?)
      `).run(
        key,
        digestCanonicalJson(persisted, { maxBytes: 2 * 1024 * 1024, maxDepth: 64 }).canonicalJson,
        this.#now().toISOString(),
      );
      return { ...persisted, duplicate: false };
    });
  }
}

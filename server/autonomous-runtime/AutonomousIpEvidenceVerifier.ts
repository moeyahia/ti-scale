import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { agentAssignmentBindsRuntimeAgent } from "../agents";
import type { ExecutionResult } from "../command-runtime";
import {
  FailureDiagnosisService,
  OperationalTruthService,
  type FailureCategory as DiagnosisFailureCategory,
} from "../intelligence-v24";
import {
  classifyReviewedLocalToolResult,
  type LocalProcessToolResult,
  type LocalToolCapabilityManifest,
} from "../local-tools";
import { digestCanonicalJson } from "../mcp";
import { ActionRepository, reviewedLocalToolActionEnvelope } from "../orchestration";
import type { FailureCategory as RuntimeFailureCategory } from "../supervisor";
import {
  AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
  autonomousSuccessCriterionId,
} from "./LocalVerifiedEvidenceOutcomeEvaluator";
import { deterministicFindingPolicyReferencesForServiceFingerprints } from "./AutonomousDeterministicFindingPolicy";
import {
  AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  AUTONOMOUS_IP_LIVENESS_EVIDENCE_TYPE,
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
  AUTONOMOUS_IP_SERVICE_SCAN_EVIDENCE_TYPE,
  AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
  AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE,
  normalizeAutonomousIpHost,
  validateAutonomousIpSafeReconConfiguration,
  type AutonomousIpSafeReconConfiguration,
} from "./AutonomousIpSafeRecon";

export const AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION =
  "ti-scale.autonomous-ip-evidence-verifier.v1" as const;

const RECEIPT_PREFIX = "idempotency.autonomous-ip-evidence.";
const SHA256 = /^[a-f0-9]{64}$/u;

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
}

interface ParsedPing {
  readonly kind: "liveness";
  readonly host: string;
  readonly responded: boolean;
  readonly transmitted: number;
  readonly received: number;
  readonly packetLossPercent: number;
  readonly timingMs: Readonly<{
    readonly minimum: number;
    readonly average: number;
    readonly maximum: number;
    readonly deviation: number;
  }> | null;
}

interface ParsedPort {
  readonly port: number;
  readonly transport: "tcp";
  readonly state: "open";
  readonly service: string;
  readonly version: string | null;
}

interface ParsedScan {
  readonly kind: "service_scan";
  readonly host: string;
  readonly requestedPorts: readonly number[];
  readonly hostReportedUp: true;
  readonly scanCompleted: true;
  readonly openPorts: readonly ParsedPort[];
}

type ParsedFact = ParsedPing | ParsedScan;

interface ProcessingReceipt {
  readonly schemaVersion: typeof AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION;
  readonly actionId: string;
  readonly actionFingerprint: string;
  readonly invocationId: string;
  readonly outputSha256: string;
  readonly executionResult: ExecutionResult;
  readonly logRecordId: string;
  readonly observationId: string | null;
  readonly evidenceIds: readonly string[];
  readonly diagnosisId: string | null;
}

export interface AutonomousIpEvidenceProcessingResult {
  readonly executionResult: ExecutionResult;
  readonly logRecordId: string;
  readonly observationId?: string;
  readonly evidenceIds: readonly string[];
  readonly diagnosisId?: string;
  readonly duplicate: boolean;
}

export interface AutonomousIpEvidenceVerifierOptions {
  readonly database: SqliteDatabase;
  readonly manifest: LocalToolCapabilityManifest;
  readonly configuration: AutonomousIpSafeReconConfiguration;
  readonly now?: () => Date;
}

class IpVerificationFailure extends Error {
  constructor(
    readonly code: string,
    readonly category: RuntimeFailureCategory,
    message: string,
    readonly remediation: string,
    readonly retryable = false,
  ) {
    super(message);
    this.name = "IpVerificationFailure";
  }
}

function diagnosisCategory(category: RuntimeFailureCategory): DiagnosisFailureCategory {
  if (category === "scope_conflict" || category === "authorization_denied") return "scope_denied";
  if (category === "transient_network") return "target_unreachable";
  if (category === "process_crash") return "deterministic_tool_error";
  if (category === "operator_rejection") return "policy_denied";
  return category;
}

function plainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function parseRecord(value: string | null, label: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(value ?? "null") as unknown;
    if (!plainRecord(parsed)) throw new Error("not an object");
    return parsed;
  } catch {
    throw new IpVerificationFailure(
      "autonomous_ip_contract_malformed",
      "policy_denied",
      `The canonical ${label} is malformed, so the IP reconnaissance result cannot be trusted.`,
      "Repair the versioned contract record and start a new run.",
    );
  }
}

function parseStringArray(value: string, label: string): readonly string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string" || !item.trim())) {
      throw new Error("invalid array");
    }
    return parsed as string[];
  } catch {
    throw new IpVerificationFailure(
      "autonomous_ip_contract_malformed",
      "policy_denied",
      `The canonical ${label} is malformed, so the IP reconnaissance result cannot be trusted.`,
      "Repair the versioned mission record and start a new run.",
    );
  }
}

function bounded(value: string, maximum = 1_000): string {
  const normalized = value.trim().replace(/\s+/gu, " ");
  return normalized.length <= maximum ? normalized : `${normalized.slice(0, maximum - 1)}…`;
}

function outputSha256(result: LocalProcessToolResult): string {
  return createHash("sha256")
    .update(result.stdout, "utf8")
    .update("\u0000", "utf8")
    .update(result.stderr, "utf8")
    .digest("hex");
}

function expectedInvocationId(actionId: string): string {
  return `local_tool_${createHash("sha256").update(actionId, "utf8").digest("hex").slice(0, 40)}`;
}

function parseReceipt(value: string): ProcessingReceipt {
  const parsed = JSON.parse(value) as unknown;
  if (!plainRecord(parsed)
    || parsed.schemaVersion !== AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION
    || typeof parsed.actionId !== "string"
    || typeof parsed.actionFingerprint !== "string"
    || typeof parsed.invocationId !== "string"
    || typeof parsed.outputSha256 !== "string"
    || !plainRecord(parsed.executionResult)
    || typeof parsed.logRecordId !== "string"
    || !(parsed.observationId === null || typeof parsed.observationId === "string")
    || !Array.isArray(parsed.evidenceIds)
    || parsed.evidenceIds.some((id) => typeof id !== "string")
    || !(parsed.diagnosisId === null || typeof parsed.diagnosisId === "string")) {
    throw new Error("Stored Autonomous IP evidence receipt is invalid");
  }
  return parsed as unknown as ProcessingReceipt;
}

function toolBoundary(toolId: string) {
  if (toolId === AUTONOMOUS_IP_LIVENESS_TOOL_ID) {
    return {
      actionClass: AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
      criterionKey: "livenessSuccessCriterion" as const,
    };
  }
  if (toolId === AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID) {
    return {
      actionClass: AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
      criterionKey: "serviceScanSuccessCriterion" as const,
    };
  }
  throw new IpVerificationFailure(
    "autonomous_ip_tool_unreviewed",
    "policy_denied",
    "The process result does not belong to either reviewed Autonomous IP tool.",
    "Discard it and create a new action from the reviewed Safe IP Recon policy.",
  );
}

function parsePorts(value: string): readonly number[] {
  if (!/^\d{1,5}(?:,\d{1,5}){0,63}$/u.test(value)) {
    throw new IpVerificationFailure(
      "autonomous_ip_port_set_malformed",
      "policy_denied",
      "The persisted TCP port set is not the exact reviewed canonical list.",
      "Create a new action from the reviewed Safe IP Recon policy.",
    );
  }
  const ports = value.split(",").map(Number);
  if (ports.some((port) => !Number.isSafeInteger(port) || port < 1 || port > 65_535)
    || new Set(ports).size !== ports.length
    || ports.some((port, index) => index > 0 && port <= ports[index - 1]!)) {
    throw new IpVerificationFailure(
      "autonomous_ip_port_set_malformed",
      "policy_denied",
      "The persisted TCP port set is not unique, sorted, and bounded.",
      "Create a new action from the reviewed Safe IP Recon policy.",
    );
  }
  return ports;
}

function parsePing(result: LocalProcessToolResult, expectedHost: string): ParsedPing {
  const text = `${result.stdout}\n${result.stderr}`.replaceAll("\r\n", "\n");
  const firstLine = text.split("\n").find((line) => line.trim())?.trim() ?? "";
  const reported = firstLine.match(/^PING\s+(\S+)(?:\s+\([^)]*\))?/u)?.[1];
  const summaryMatches = [...text.matchAll(
    /(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received(?:,\s*\+?\d+\s+errors?)?,\s*([\d.]+)%\s+packet loss/giu,
  )];
  if (!reported || normalizeAutonomousIpHost(reported) !== expectedHost
    || summaryMatches.length !== 1) {
    throw new IpVerificationFailure(
      "autonomous_ip_liveness_output_malformed",
      "evidence_insufficient",
      "The liveness output did not contain one attributable packet summary for the exact target.",
      "Keep the raw log, update only a reviewed tested parser if the installed format changed, and use a new bounded action.",
    );
  }
  const summary = summaryMatches[0]!;
  const transmitted = Number(summary[1]);
  const received = Number(summary[2]);
  const packetLossPercent = Number(summary[3]);
  const responded = received > 0;
  const expectedLoss = ((transmitted - received) / transmitted) * 100;
  if (transmitted !== 2 || received < 0 || received > transmitted
    || !Number.isFinite(packetLossPercent)
    || Math.abs(packetLossPercent - expectedLoss) > 0.1
    || (result.exitCode === 0) !== responded
    || (result.exitCode !== 0 && result.exitCode !== 1)) {
    throw new IpVerificationFailure(
      "autonomous_ip_liveness_output_conflict",
      "evidence_insufficient",
      "The liveness exit result and packet counts conflict, so no fact was promoted.",
      "Inspect the retained log and run a new bounded check only after the conflict is understood.",
    );
  }
  const timingMatches = [...text.matchAll(
    /(?:round-trip|rtt)\s+min\/avg\/max\/(?:mdev|stddev)\s*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)\s*ms/giu,
  )];
  if (timingMatches.length > 1 || (responded && timingMatches.length !== 1)) {
    throw new IpVerificationFailure(
      "autonomous_ip_liveness_timing_malformed",
      "evidence_insufficient",
      "The liveness timing section was missing or ambiguous.",
      "Inspect the retained log and update only a reviewed parser format before retrying.",
    );
  }
  const timing = timingMatches[0];
  return Object.freeze({
    kind: "liveness",
    host: expectedHost,
    responded,
    transmitted,
    received,
    packetLossPercent,
    timingMs: timing ? Object.freeze({
      minimum: Number(timing[1]),
      average: Number(timing[2]),
      maximum: Number(timing[3]),
      deviation: Number(timing[4]),
    }) : null,
  });
}

function parseOpenPort(line: string): ParsedPort | undefined {
  const match = line.trim().match(
    /^(\d{1,5})\/tcp\s+open\s+([A-Za-z0-9?._/-]{1,80})(?:\s+([^\u0000-\u001F\u007F]{1,300}))?$/u,
  );
  if (!match?.[1] || !match[2]) return undefined;
  const port = Number(match[1]);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) return undefined;
  return Object.freeze({
    port,
    transport: "tcp" as const,
    state: "open" as const,
    service: bounded(match[2], 80),
    version: match[3] ? bounded(match[3], 300) : null,
  });
}

function parseScan(
  result: LocalProcessToolResult,
  expectedHost: string,
  requestedPorts: readonly number[],
): ParsedScan {
  const text = `${result.stdout}\n${result.stderr}`.replaceAll("\r\n", "\n");
  const reports = [...text.matchAll(/^Nmap scan report for\s+(.+)$/gimu)];
  const completions = [...text.matchAll(
    /^Nmap done:\s+1 IP address \(1 host up\) scanned in\s+[\d.]+\s+seconds$/gimu,
  )];
  const report = reports[0]?.[1]?.trim() ?? "";
  const reportHost = report.match(/^([^\s()]+)(?:\s+\(([^)]+)\))?$/u);
  const attributable = reportHost
    ? [reportHost[1], reportHost[2]].filter((value): value is string => Boolean(value))
      .some((value) => {
        try { return normalizeAutonomousIpHost(value) === expectedHost; } catch { return false; }
      })
    : false;
  const hostUpCount = (text.match(/^Host is up(?:\s|\.)/gimu) ?? []).length;
  const openPorts = text.split("\n")
    .map(parseOpenPort)
    .filter((port): port is ParsedPort => port !== undefined)
    .sort((left, right) => left.port - right.port);
  if (reports.length !== 1 || completions.length !== 1 || hostUpCount !== 1 || !attributable
    || result.exitCode !== 0 || new Set(openPorts.map(({ port }) => port)).size !== openPorts.length
    || openPorts.some(({ port }) => !requestedPorts.includes(port))) {
    throw new IpVerificationFailure(
      "autonomous_ip_service_scan_output_malformed",
      "evidence_insufficient",
      "The service scan was incomplete, ambiguous, or reported a port outside the reviewed set.",
      "Retain the raw log, verify the installed Nmap output format, and create a new bounded action without widening the port set.",
    );
  }
  return Object.freeze({
    kind: "service_scan",
    host: expectedHost,
    requestedPorts: Object.freeze([...requestedPorts]),
    hostReportedUp: true,
    scanCompleted: true,
    openPorts: Object.freeze(openPorts),
  });
}

export class AutonomousIpEvidenceVerifier {
  readonly #configuration: AutonomousIpSafeReconConfiguration;
  readonly #now: () => Date;
  readonly #actions: ActionRepository;

  constructor(private readonly options: AutonomousIpEvidenceVerifierOptions) {
    this.#configuration = validateAutonomousIpSafeReconConfiguration(
      options.configuration,
      options.manifest,
    );
    this.#now = options.now ?? (() => new Date());
    this.#actions = new ActionRepository(options.database);
  }

  private receiptKey(invocationId: string): string {
    return `${RECEIPT_PREFIX}${createHash("sha256").update(invocationId, "utf8").digest("hex")}`;
  }

  private canonicalBoundary(result: LocalProcessToolResult): CanonicalBoundaryRow {
    const canonical = this.#actions.get(result.action.id);
    if (digestCanonicalJson(canonical, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      !== digestCanonicalJson(result.action, { maxBytes: 1_048_576, maxDepth: 64 }).sha256) {
      throw new IpVerificationFailure(
        "autonomous_ip_action_binding_changed",
        "policy_denied",
        "The IP reconnaissance result action differs from the exact canonical running action.",
        "Discard the result and recover from the latest durable checkpoint.",
      );
    }
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
        tc.started_at AS tool_call_started_at, tc.status AS tool_call_status
      FROM actions a
      JOIN runs r ON r.id = a.run_id AND r.mission_id = a.mission_id
      JOIN missions m ON m.id = r.mission_id
      JOIN plan_steps ps ON ps.id = a.step_id AND ps.run_id = r.id
      JOIN assignments assn ON assn.id = a.assignment_id AND assn.step_id = ps.id
      LEFT JOIN mission_contracts mc ON mc.id = r.contract_id AND mc.mission_id = m.id
      LEFT JOIN control_plane_leases cpl ON cpl.run_id = r.id
      LEFT JOIN tool_calls tc ON tc.id = ? AND tc.action_id = a.id
      WHERE a.id = ? AND a.status = 'running' AND assn.status = 'active'
    `).get(result.invocationId, canonical.id) as CanonicalBoundaryRow | undefined;
    const envelope = reviewedLocalToolActionEnvelope(canonical.arguments);
    const expected = toolBoundary(result.toolId);
    if (!row || row.journey !== "autonomous"
      || row.run_control_plane !== "ti_scale" || row.mission_control_plane !== "ti_scale"
      || canonical.kind !== "tool" || canonical.actionType !== result.toolId
      || canonical.actionClass !== expected.actionClass
      || canonical.guidedDecisionId !== null || canonical.contractId === null
      || canonical.contractId !== row.run_contract_id
      || envelope?.toolId !== result.toolId) {
      throw new IpVerificationFailure(
        "autonomous_ip_execution_boundary_invalid",
        "policy_denied",
        "The result is not inside the exact Autonomous Ti-Scale local specialist boundary.",
        "Use a new Autonomous run bound to the reviewed Safe IP Recon contract.",
      );
    }
    const nowMs = this.#now().getTime();
    if (row.authorization_status !== "verified" || row.contract_state !== "confirmed"
      || row.contract_version_bound !== row.contract_version
      || row.contract_hash_bound !== row.contract_hash
      || !agentAssignmentBindsRuntimeAgent(
        this.options.database,
        row.assigned_agent_id,
        this.#configuration.agentId,
      )
      || !row.assignment_lease_owner
      || row.assignment_lease_owner !== row.control_lease_owner
      || row.control_lease_released_at !== null
      || !row.control_lease_expires_at
      || Date.parse(row.control_lease_expires_at) <= nowMs
      || row.tool_call_status !== "running"
      || !row.tool_call_started_at) {
      throw new IpVerificationFailure(
        "autonomous_ip_owner_fence_invalid",
        "policy_denied",
        "Authorization, contract binding, specialist assignment, or the run owner fence changed before result validation.",
        "Restore one current Ti-Scale control-plane owner and create a new bounded attempt.",
      );
    }
    return row;
  }

  private assertPolicyScopeAndResult(
    result: LocalProcessToolResult,
    row: CanonicalBoundaryRow,
  ): Readonly<{ parameters: Readonly<Record<string, unknown>>; host: string; criterion: string }> {
    const envelope = reviewedLocalToolActionEnvelope(result.action.arguments);
    if (!envelope || envelope.toolId !== result.toolId) {
      throw new IpVerificationFailure(
        "autonomous_ip_local_binding_invalid",
        "policy_denied",
        "The IP result is not bound to the reviewed local process envelope.",
        "Discard it and create a new action through the reviewed local planner.",
      );
    }
    const expected = toolBoundary(result.toolId);
    const parameters = envelope.parameters;
    const expectedKeys = result.toolId === AUTONOMOUS_IP_LIVENESS_TOOL_ID
      ? ["target", "workspace"]
      : ["ports", "target", "workspace"];
    const host = normalizeAutonomousIpHost(result.action.target);
    if (!exactKeys(parameters, expectedKeys)
      || parameters.workspace !== this.#configuration.logicalWorkspace
      || typeof parameters.target !== "string"
      || normalizeAutonomousIpHost(parameters.target) !== host
      || (result.toolId === AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID
        && parameters.ports !== this.#configuration.ports.join(","))) {
      throw new IpVerificationFailure(
        "autonomous_ip_exact_binding_invalid",
        "policy_denied",
        "The IP tool, exact target, workspace, or reviewed port set differs from the persisted action.",
        "Discard the result and create a new exact action from the reviewed planning policy.",
      );
    }
    this.options.manifest.compileInvocation(result.toolId, parameters);
    const targets = this.options.database.prepare(`
      SELECT disposition, normalized_target FROM mission_targets WHERE mission_id = ?
    `).all(result.action.missionId) as Array<{
      readonly disposition: "allowed" | "prohibited";
      readonly normalized_target: string;
    }>;
    const allowed = targets.filter(({ disposition }) => disposition === "allowed");
    const prohibited = targets.filter(({ disposition }) => disposition === "prohibited");
    if (allowed.length !== 1
      || normalizeAutonomousIpHost(allowed[0]!.normalized_target) !== host
      || prohibited.some(({ normalized_target }) => {
        try { return normalizeAutonomousIpHost(normalized_target) === host; } catch { return false; }
      })) {
      throw new IpVerificationFailure(
        "autonomous_ip_target_outside_scope",
        "scope_conflict",
        `The IP target ${result.action.target} is not the one unambiguously allowed mission host.`,
        "Create one separately signed run per exact normalized host.",
      );
    }
    const policy = parseRecord(row.action_policy_json, "action policy");
    const allowedClasses = Array.isArray(policy.allowedActionClasses)
      ? policy.allowedActionClasses.filter((value): value is string => typeof value === "string")
      : [];
    const prohibitedClasses = Array.isArray(policy.prohibitedActionClasses)
      ? policy.prohibitedActionClasses.filter((value): value is string => typeof value === "string")
      : [];
    const specialists = Array.isArray(policy.specialistAgentIds)
      ? policy.specialistAgentIds.filter((value): value is string => typeof value === "string")
      : [];
    if (!allowedClasses.includes(AUTONOMOUS_IP_LIVENESS_ACTION_CLASS)
      || !allowedClasses.includes(AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS)
      || prohibitedClasses.includes(expected.actionClass)
      || !row.assigned_agent_id
      || !specialists.includes(row.assigned_agent_id)) {
      throw new IpVerificationFailure(
        "autonomous_ip_contract_policy_denied",
        "policy_denied",
        "The signed action policy does not pre-authorize the complete exact Safe IP Recon route.",
        "Amend the registry-backed contract; never infer authority from a process result.",
      );
    }
    const criterion = this.#configuration[expected.criterionKey];
    if (!parseStringArray(row.mission_success_criteria_json, "success criteria").includes(criterion)) {
      throw new IpVerificationFailure(
        "autonomous_ip_success_criterion_unbound",
        "evidence_insufficient",
        "The reviewed IP evidence criterion is not an exact canonical mission criterion.",
        "Add the criterion through a versioned contract and start a new run.",
      );
    }
    const tool = this.options.manifest.resolve(result.toolId)!;
    const startedAt = Date.parse(result.startedAt);
    const endedAt = Date.parse(result.endedAt);
    if (result.invocationId !== expectedInvocationId(result.action.id)
      || result.outputTruncated || !SHA256.test(result.outputSha256)
      || outputSha256(result) !== result.outputSha256
      || result.executable.sourcePath !== tool.executable.path
      || result.executable.sourceSha256 !== tool.executable.expectedSha256
      || result.executable.snapshotSha256 !== tool.executable.expectedSha256
      || result.sandbox.shell !== false
      || !Number.isFinite(startedAt) || !Number.isFinite(endedAt)
      || startedAt < Date.parse(row.tool_call_started_at!)
      || endedAt < startedAt || endedAt > this.#now().getTime() + 60_000) {
      throw new IpVerificationFailure(
        "autonomous_ip_result_integrity_invalid",
        "policy_denied",
        "The IP process result failed exact invocation, executable, output, owner, timestamp, or truncation checks.",
        "Quarantine the result, re-attest the executable and sandbox, and recover from a durable checkpoint.",
      );
    }
    return { parameters, host, criterion };
  }

  private appendLog(
    result: LocalProcessToolResult,
    input: Readonly<{ severity: "notice" | "error"; summary: string }>,
  ) {
    const truth = new OperationalTruthService(this.options.database, { clock: this.#now });
    const row = this.options.database.prepare("SELECT plan_id FROM plan_steps WHERE id = ?")
      .get(result.action.stepId) as { readonly plan_id: string };
    return truth.appendEngagementLog({
      missionId: result.action.missionId,
      runId: result.action.runId,
      planId: row.plan_id,
      stepId: result.action.stepId,
      actionId: result.action.id,
      agentId: this.#configuration.agentId,
      toolCallId: result.invocationId,
      severity: input.severity,
      domain: "autonomous_ip_safe_recon",
      recordType: "bounded_ip_process_output",
      humanSummary: input.summary,
      technicalPayload: {
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.exitCode,
        signal: result.signal,
        termination: result.termination,
        outputSha256: result.outputSha256,
        outputTruncated: result.outputTruncated,
        sourceExecutableSha256: result.executable.sourceSha256,
        sandboxExecutableSha256: result.sandbox.executableSha256,
        shell: false,
      },
      sensitivity: "private",
      occurredAt: result.endedAt,
    });
  }

  private failure(
    result: LocalProcessToolResult,
    failure: IpVerificationFailure,
    logRecordId: string,
  ): AutonomousIpEvidenceProcessingResult {
    const diagnosis = new FailureDiagnosisService(this.options.database, { clock: this.#now }).create({
      missionId: result.action.missionId,
      runId: result.action.runId,
      stepId: result.action.stepId,
      actionId: result.action.id,
      subjectType: "action",
      subjectId: result.action.id,
      humanReason: `Failed safely: ${failure.message}`,
      category: diagnosisCategory(failure.category),
      code: failure.code,
      originatingComponent: "autonomous-ip-evidence-verifier",
      failedComponentRef: `reviewed-local-process/${result.toolId}`,
      targetSummary: `Exact authorized host ${result.action.target}; no verified evidence was created.`,
      policyOrDependency: "The signed contract, single-host scope, owner fence, exact tool arguments, executable hash, complete output, deterministic parser, and canonical success criterion must all match.",
      rawErrorLogId: logRecordId,
      retryHistory: [],
      progressBeforeFailure: { verifiedEvidenceCreated: false },
      preservedReferences: [{
        kind: "log",
        id: logRecordId,
        meaning: "Redacted bounded IP process output retained for diagnosis",
      }],
      retryable: failure.retryable,
      automaticRecovery: {
        safeStopped: !failure.retryable,
        automaticRetryPermitted: failure.retryable,
        repeatedUnchangedActionPermitted: false,
      },
      remediation: failure.remediation,
      operatorActions: failure.retryable ? [{
        kind: "retry_bounded",
        label: "Retry this exact step once",
        consequence: "Creates one new bounded attempt only after current policy, scope, owner, and dependency checks pass again.",
        requiresConfirmation: false,
      }, {
        kind: "terminate_gracefully",
        label: "End the run safely",
        consequence: "Preserves the log and diagnosis without claiming evidence or success.",
        requiresConfirmation: false,
      }] : [{
        kind: "amend_plan",
        label: "Correct the Safe IP Recon boundary",
        consequence: "Creates a new plan version and action; it never reinterprets this rejected result.",
        requiresConfirmation: true,
      }, {
        kind: "terminate_gracefully",
        label: "End the run safely",
        consequence: "Preserves the log and diagnosis without claiming evidence or success.",
        requiresConfirmation: false,
      }],
      objectiveImpact: "The current criterion remains unsupported; prior mission evidence is preserved.",
      terminal: !failure.retryable,
      actor: { id: "autonomous-ip-evidence-verifier", type: "system" },
    });
    return {
      executionResult: {
        actionId: result.action.id,
        runId: result.action.runId,
        actionFingerprint: result.action.fingerprint,
        success: false,
        summary: `Failed safely: ${failure.message}`,
        progress: {},
        failure: { source: "tool", code: failure.code, message: failure.message },
        failureCategory: failure.category,
        circuitKey: `autonomous-ip:${result.toolId}`,
        usage: { wallClockMs: result.wallClockMs },
      },
      logRecordId,
      evidenceIds: [],
      diagnosisId: diagnosis.id,
      duplicate: false,
    };
  }

  private insertEvidence(input: Readonly<{
    result: LocalProcessToolResult;
    observationId: string;
    logRecordId: string;
    evidenceType: typeof AUTONOMOUS_IP_LIVENESS_EVIDENCE_TYPE
      | typeof AUTONOMOUS_IP_SERVICE_SCAN_EVIDENCE_TYPE
      | typeof AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE;
    summary: string;
    normalized: Readonly<Record<string, unknown>>;
    criterion: string;
    confidence: number;
  }>): string {
    const content = digestCanonicalJson(input.normalized, { maxBytes: 256 * 1_024, maxDepth: 32 });
    const criterionId = autonomousSuccessCriterionId(input.criterion);
    const evidenceId = `evidence_ip_${createHash("sha256")
      .update(`${input.result.action.id}\u0000${input.evidenceType}\u0000${content.sha256}`, "utf8")
      .digest("hex").slice(0, 40)}`;
    const findingPolicyReferences = input.evidenceType === AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE
      ? deterministicFindingPolicyReferencesForServiceFingerprints(input.normalized.fingerprints)
      : [];
    const provenance = digestCanonicalJson({
      schemaVersion: AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION,
      method: "deterministic_reviewed_ip_result_validation",
      actionId: input.result.action.id,
      actionFingerprint: input.result.action.fingerprint,
      toolCallId: input.result.invocationId,
      observationId: input.observationId,
      logRecordId: input.logRecordId,
      specialistAgentId: this.#configuration.agentId,
      executionBinding: "reviewed_local_process",
      toolId: input.result.toolId,
      manifestSha256: this.options.manifest.descriptor.manifestSha256,
      toolBindingSha256: this.options.manifest.resolve(input.result.toolId)!.bindingSha256,
      executableSha256: input.result.executable.sourceSha256,
      outputSha256: input.result.outputSha256,
      rawOutputPromoted: false,
      cveClaimsCreated: false,
      ...(findingPolicyReferences.length > 0
        ? { deterministicFindingPolicyReferences: findingPolicyReferences }
        : {}),
      successCriterionReferences: [{
        schemaVersion: AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
        criterionId,
        outcome: "achieved" as const,
      }],
    }, { maxBytes: 256 * 1_024, maxDepth: 32 });
    const createdAt = this.#now().toISOString();
    this.options.database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, step_id, action_id, source, acquired_at,
        target, evidence_type, content_hash, provenance_json, confidence,
        sensitivity, verification_state, summary, extracted_text,
        artifact_id, created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'private', 'verified', ?, ?, NULL, ?, ?)
    `).run(
      evidenceId,
      input.result.action.missionId,
      input.result.action.runId,
      input.result.action.stepId,
      input.result.action.id,
      `specialist:${this.#configuration.agentId}`,
      input.result.endedAt,
      input.result.action.target,
      input.evidenceType,
      content.sha256,
      provenance.canonicalJson,
      input.confidence,
      input.summary,
      content.canonicalJson,
      "autonomous-ip-evidence-verifier",
      createdAt,
    );
    const acquiredCustodyId = `custody_${createHash("sha256").update(`${evidenceId}\u0000acquired`).digest("hex").slice(0, 40)}`;
    const verifiedCustodyId = `custody_${createHash("sha256").update(`${evidenceId}\u0000verified`).digest("hex").slice(0, 40)}`;
    this.options.database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'acquired', ?, ?, ?), (?, ?, 'verified', ?, ?, ?)
    `).run(
      acquiredCustodyId,
      evidenceId,
      this.#configuration.agentId,
      digestCanonicalJson({
        observationId: input.observationId,
        logRecordId: input.logRecordId,
        contentHash: content.sha256,
      }, { maxBytes: 16 * 1_024, maxDepth: 8 }).canonicalJson,
      input.result.endedAt,
      verifiedCustodyId,
      evidenceId,
      "autonomous-ip-evidence-verifier",
      digestCanonicalJson({
        method: "deterministic_reviewed_ip_result_validation",
        criterionId,
        rawOutputPromoted: false,
        cveClaimsCreated: false,
      }, { maxBytes: 16 * 1_024, maxDepth: 8 }).canonicalJson,
      createdAt,
    );
    return evidenceId;
  }

  processLocalResult(result: LocalProcessToolResult): AutonomousIpEvidenceProcessingResult {
    return inImmediateTransaction(this.options.database, () => {
      const key = this.receiptKey(result.invocationId);
      const stored = this.options.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(key) as { readonly value_json: string } | undefined;
      if (stored) {
        const receipt = parseReceipt(stored.value_json);
        if (receipt.actionId !== result.action.id
          || receipt.actionFingerprint !== result.action.fingerprint
          || receipt.invocationId !== result.invocationId
          || receipt.outputSha256 !== result.outputSha256) {
          throw new Error("Autonomous IP evidence receipt conflicts with this result");
        }
        return {
          executionResult: receipt.executionResult,
          logRecordId: receipt.logRecordId,
          ...(receipt.observationId ? { observationId: receipt.observationId } : {}),
          evidenceIds: receipt.evidenceIds,
          ...(receipt.diagnosisId ? { diagnosisId: receipt.diagnosisId } : {}),
          duplicate: true,
        };
      }

      let boundary: CanonicalBoundaryRow;
      let binding: Readonly<{
        parameters: Readonly<Record<string, unknown>>;
        host: string;
        criterion: string;
      }>;
      try {
        boundary = this.canonicalBoundary(result);
        binding = this.assertPolicyScopeAndResult(result, boundary);
      } catch (error) {
        const failure = error instanceof IpVerificationFailure ? error : new IpVerificationFailure(
          "autonomous_ip_boundary_validation_failed",
          "policy_denied",
          error instanceof Error ? error.message : "The IP result boundary could not be validated.",
          "Inspect the action, contract, scope, owner fence, manifest, and executable before a new run.",
        );
        const log = this.appendLog(result, { severity: "error", summary: `Failed safely: ${failure.message}` });
        const outcome = this.failure(result, failure, log.id);
        this.saveReceipt(key, result, outcome);
        return outcome;
      }

      const classification = classifyReviewedLocalToolResult(result);
      if (!classification.success) {
        const networkFailure = /\b(?:network is unreachable|no route to host)\b/iu.test(
          `${result.stdout}\n${result.stderr}`,
        );
        const failure = new IpVerificationFailure(
          networkFailure ? "autonomous_ip_target_unreachable" : classification.code ?? "autonomous_ip_tool_failed",
          networkFailure ? "transient_network" : classification.category ?? "deterministic_tool_error",
          networkFailure ? "The exact host was unreachable from the reviewed local network boundary." : classification.summary,
          networkFailure || classification.category === "timeout"
            ? "Re-check route availability and allow at most one bounded automatic retry."
            : "Inspect the retained log and repair the deterministic tool or dependency before a new action.",
          networkFailure || classification.category === "timeout",
        );
        const log = this.appendLog(result, { severity: "error", summary: `Failed safely: ${failure.message}` });
        const outcome = this.failure(result, failure, log.id);
        this.saveReceipt(key, result, outcome);
        return outcome;
      }

      let fact: ParsedFact;
      try {
        fact = result.toolId === AUTONOMOUS_IP_LIVENESS_TOOL_ID
          ? parsePing(result, binding.host)
          : parseScan(result, binding.host, parsePorts(String(binding.parameters.ports)));
      } catch (error) {
        const failure = error instanceof IpVerificationFailure ? error : new IpVerificationFailure(
          "autonomous_ip_parser_failed",
          "evidence_insufficient",
          "The IP reconnaissance output could not be normalized deterministically.",
          "Inspect the retained log and add a tested parser format before a new action.",
        );
        const log = this.appendLog(result, { severity: "error", summary: `Failed safely: ${failure.message}` });
        const outcome = this.failure(result, failure, log.id);
        this.saveReceipt(key, result, outcome);
        return outcome;
      }

      const statement = fact.kind === "liveness"
        ? fact.responded
          ? `The exact approved host ${binding.host} replied to the bounded liveness check.`
          : `The exact approved host ${binding.host} did not reply to the bounded liveness check; this does not prove it is offline.`
        : fact.openPorts.length === 0
          ? `The complete reviewed TCP scan checked ${fact.requestedPorts.length} ports on ${binding.host} and found no open service in that set.`
          : `The complete reviewed TCP scan checked ${fact.requestedPorts.length} ports on ${binding.host} and found ${fact.openPorts.length} open service${fact.openPorts.length === 1 ? "" : "s"}.`;
      const log = this.appendLog(result, { severity: "notice", summary: statement });
      const truth = new OperationalTruthService(this.options.database, { clock: this.#now });
      const observation = truth.createObservation({
        missionId: result.action.missionId,
        runId: result.action.runId,
        stepId: result.action.stepId,
        observationType: fact.kind === "liveness" ? "host_liveness" : "tcp_service_scan",
        statement,
        normalizedValue: {
          schemaVersion: AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION,
          semanticOutcome: "positive_observation",
          missionId: result.action.missionId,
          runId: result.action.runId,
          stepId: result.action.stepId,
          target: result.action.target,
          result: fact,
          ...fact,
          actionId: result.action.id,
          toolCallId: result.invocationId,
          toolId: result.toolId,
          outputSha256: result.outputSha256,
          rawOutputPromoted: false,
          cveClaimsCreated: false,
        },
        confidence: fact.kind === "liveness" ? fact.responded ? 0.95 : 0.8 : 0.95,
        verificationState: "corroborated",
        sourceAgentId: this.#configuration.agentId,
        sourceTool: result.toolId,
        firstSeenAt: result.startedAt,
        lastSeenAt: result.endedAt,
        sensitivity: "private",
        sources: [{
          logRecordId: log.id,
          parserId: "ti-scale.autonomous-ip-deterministic-parser",
          parserVersion: "1.0.0",
        }],
      });
      const evidenceIds: string[] = [];
      if (fact.kind === "liveness") {
        evidenceIds.push(this.insertEvidence({
          result,
          observationId: observation.id,
          logRecordId: log.id,
          evidenceType: AUTONOMOUS_IP_LIVENESS_EVIDENCE_TYPE,
          summary: statement,
          normalized: {
            host: fact.host,
            responded: fact.responded,
            transmitted: fact.transmitted,
            received: fact.received,
            packetLossPercent: fact.packetLossPercent,
            timingMs: fact.timingMs,
            interpretation: fact.responded
              ? "current_reply_observed"
              : "no_reply_observed_offline_not_established",
            observationId: observation.id,
            logRecordId: log.id,
            outputSha256: result.outputSha256,
          },
          criterion: binding.criterion,
          confidence: fact.responded ? 0.95 : 0.8,
        }));
      } else {
        evidenceIds.push(this.insertEvidence({
          result,
          observationId: observation.id,
          logRecordId: log.id,
          evidenceType: AUTONOMOUS_IP_SERVICE_SCAN_EVIDENCE_TYPE,
          summary: statement,
          normalized: {
            host: fact.host,
            transport: "tcp",
            scanTechnique: "tcp_connect",
            requestedPorts: fact.requestedPorts,
            openPorts: fact.openPorts,
            versionDetection: "light",
            scriptsExecuted: false,
            osDetectionRequested: false,
            rawSocketRequired: false,
            observationId: observation.id,
            logRecordId: log.id,
            outputSha256: result.outputSha256,
          },
          criterion: binding.criterion,
          confidence: 0.95,
        }));
        if (fact.openPorts.length > 0) {
          evidenceIds.push(this.insertEvidence({
            result,
            observationId: observation.id,
            logRecordId: log.id,
            evidenceType: AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE,
            summary: `The complete reviewed scan retained ${fact.openPorts.length} attributable service fingerprint${fact.openPorts.length === 1 ? "" : "s"} for ${binding.host}.`,
            normalized: {
              host: fact.host,
              fingerprints: fact.openPorts,
              identificationStrength: "nmap_version_light",
              cveApplicability: "not_evaluated",
              observationId: observation.id,
              logRecordId: log.id,
              outputSha256: result.outputSha256,
            },
            criterion: binding.criterion,
            confidence: 0.9,
          }));
        }
      }
      for (const evidenceId of evidenceIds) {
        truth.repository.audit.append({
          missionId: result.action.missionId,
          runId: result.action.runId,
          actor: { id: "autonomous-ip-evidence-verifier", type: "system" },
          action: "evidence.verified_deterministically",
          resourceType: "evidence",
          resourceId: evidenceId,
          reason: "The exact reviewed IP result passed scope, owner, binding, executable, output, parser, and criterion checks.",
          details: {
            observationId: observation.id,
            logRecordId: log.id,
            rawOutputPromoted: false,
            cveClaimsCreated: false,
          },
          occurredAt: this.#now().toISOString(),
        });
      }
      const criterionId = autonomousSuccessCriterionId(binding.criterion);
      const executionResult: ExecutionResult = {
        actionId: result.action.id,
        runId: result.action.runId,
        actionFingerprint: result.action.fingerprint,
        success: true,
        summary: `${statement} ${evidenceIds.length} verified evidence item${evidenceIds.length === 1 ? " was" : "s were"} retained with chain of custody.`,
        progress: {
          stepStates: { [result.action.stepId]: "completed" },
          evidenceIds,
          successCriteria: { [criterionId]: 1 },
        },
        usage: { wallClockMs: result.wallClockMs },
      };
      const outcome: AutonomousIpEvidenceProcessingResult = {
        executionResult,
        logRecordId: log.id,
        observationId: observation.id,
        evidenceIds: Object.freeze(evidenceIds),
        duplicate: false,
      };
      this.saveReceipt(key, result, outcome);
      return outcome;
    });
  }

  private saveReceipt(
    key: string,
    result: LocalProcessToolResult,
    outcome: AutonomousIpEvidenceProcessingResult,
  ): void {
    const receipt: ProcessingReceipt = {
      schemaVersion: AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION,
      actionId: result.action.id,
      actionFingerprint: result.action.fingerprint,
      invocationId: result.invocationId,
      outputSha256: result.outputSha256,
      executionResult: outcome.executionResult,
      logRecordId: outcome.logRecordId,
      observationId: outcome.observationId ?? null,
      evidenceIds: outcome.evidenceIds,
      diagnosisId: outcome.diagnosisId ?? null,
    };
    this.options.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', 1, 'autonomous-ip-evidence-verifier', ?)
    `).run(
      key,
      digestCanonicalJson(receipt, { maxBytes: 512 * 1_024, maxDepth: 64 }).canonicalJson,
      this.#now().toISOString(),
    );
  }
}

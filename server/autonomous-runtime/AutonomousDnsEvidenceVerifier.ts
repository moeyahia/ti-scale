import { createHash } from "node:crypto";
import { isIP } from "node:net";
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
import { ActionRepository } from "../orchestration";
import { reviewedLocalToolActionEnvelope } from "../orchestration";
import type { SpecialistToolInvocation } from "../specialist-runtime";
import type { FailureCategory as RuntimeFailureCategory } from "../supervisor";
import {
  AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
  autonomousSuccessCriterionId,
} from "./LocalVerifiedEvidenceOutcomeEvaluator";
import {
  AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
  AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE,
  AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
  validateAutonomousDnsSafeReconConfiguration,
  type AutonomousDnsRecordType,
  type AutonomousDnsSafeReconConfiguration,
} from "./AutonomousDnsSafeRecon";

export const AUTONOMOUS_DNS_EVIDENCE_VERIFIER_SCHEMA_VERSION =
  "ti-scale.autonomous-dns-evidence-verifier.v1" as const;

const RECEIPT_PREFIX = "idempotency.autonomous-dns-evidence.";
const SHA256 = /^[a-f0-9]{64}$/u;

interface DnsAnswer {
  readonly kind:
    | "address"
    | "ipv6_address"
    | "alias"
    | "mail_exchange"
    | "name_server"
    | "soa"
    | "text";
  readonly value: string;
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
  readonly plan_id: string;
}

interface ProcessingReceipt {
  readonly schemaVersion: typeof AUTONOMOUS_DNS_EVIDENCE_VERIFIER_SCHEMA_VERSION;
  readonly actionId: string;
  readonly actionFingerprint: string;
  readonly invocationId: string;
  readonly outputSha256: string;
  readonly executionResult: ExecutionResult;
  readonly logRecordId: string;
  readonly observationId: string | null;
  readonly evidenceId: string | null;
  readonly diagnosisId: string | null;
}

interface AutonomousDnsBoundInvocation {
  readonly invocationId: string;
  readonly action: SpecialistToolInvocation["action"];
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly inputSha256: string;
  readonly route:
    | Readonly<{ readonly kind: "mcp"; readonly serverId: string; readonly toolName: string }>
    | Readonly<{ readonly kind: "reviewed_local_process"; readonly toolId: string }>;
}

export interface AutonomousDnsEvidenceProcessingResult {
  readonly executionResult: ExecutionResult;
  readonly logRecordId: string;
  readonly observationId?: string;
  readonly evidenceId?: string;
  readonly diagnosisId?: string;
  readonly duplicate: boolean;
}

export interface AutonomousDnsEvidenceVerifierOptions {
  readonly database: SqliteDatabase;
  readonly manifest: LocalToolCapabilityManifest;
  readonly configuration: AutonomousDnsSafeReconConfiguration;
  readonly now?: () => Date;
}

class DnsVerificationFailure extends Error {
  constructor(
    readonly code: string,
    readonly category: RuntimeFailureCategory,
    message: string,
    readonly remediation: string,
    readonly retryable = false,
  ) {
    super(message);
    this.name = "DnsVerificationFailure";
  }
}

function diagnosisCategory(category: RuntimeFailureCategory): DiagnosisFailureCategory {
  if (category === "scope_conflict" || category === "authorization_denied") return "scope_denied";
  if (category === "transient_network") return "target_unreachable";
  if (category === "process_crash") return "deterministic_tool_error";
  if (category === "operator_rejection") return "policy_denied";
  return category;
}

function normalizeDomain(value: string): string {
  const normalized = value.endsWith(".") ? value.slice(0, -1) : value;
  return normalized.normalize("NFKC").toLocaleLowerCase("en-US");
}

function exactKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function plainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function parseJsonRecord(value: string | null, label: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(value ?? "null") as unknown;
    if (!plainRecord(parsed)) throw new Error("not an object");
    return parsed;
  } catch {
    throw new DnsVerificationFailure(
      "autonomous_dns_contract_malformed",
      "policy_denied",
      `The canonical ${label} is malformed, so the DNS result cannot be trusted.`,
      "Repair the versioned contract record and start a new run; do not reinterpret malformed policy.",
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
    throw new DnsVerificationFailure(
      "autonomous_dns_contract_malformed",
      "policy_denied",
      `The canonical ${label} is malformed, so the DNS result cannot be trusted.`,
      "Repair the versioned mission record and start a new run.",
    );
  }
}

function bounded(value: string, maximum = 1_000): string {
  const normalized = value.trim().replace(/\s+/gu, " ");
  return normalized.length <= maximum ? normalized : `${normalized.slice(0, maximum - 1)}…`;
}

function dnsAnswer(line: string): DnsAnswer | undefined {
  const patterns: readonly [DnsAnswer["kind"], RegExp][] = [
    ["address", /\shas address\s+(.+)$/iu],
    ["ipv6_address", /\shas IPv6 address\s+(.+)$/iu],
    ["alias", /\sis an alias for\s+(.+)$/iu],
    ["mail_exchange", /\smail is handled by\s+(.+)$/iu],
    ["name_server", /\sname server\s+(.+)$/iu],
    ["soa", /\shas SOA record\s+(.+)$/iu],
    ["text", /\sdescriptive text\s+(.+)$/iu],
  ];
  for (const [kind, pattern] of patterns) {
    const match = line.match(pattern);
    if (match?.[1]) return { kind, value: bounded(match[1], 500) };
  }
  return undefined;
}

function allowedAnswerKinds(recordType: AutonomousDnsRecordType): ReadonlySet<DnsAnswer["kind"]> {
  switch (recordType) {
    case "A": return new Set(["address", "alias"]);
    case "AAAA": return new Set(["ipv6_address", "alias"]);
    case "CNAME": return new Set(["alias"]);
    case "MX": return new Set(["mail_exchange"]);
    case "NS": return new Set(["name_server"]);
    case "SOA": return new Set(["soa"]);
    case "TXT": return new Set(["text"]);
  }
}

function answerValueValid(answer: DnsAnswer): boolean {
  if (answer.kind === "address") return isIP(answer.value) === 4;
  if (answer.kind === "ipv6_address") return isIP(answer.value) === 6;
  if (answer.kind === "alias" || answer.kind === "name_server") {
    const domain = answer.value.endsWith(".") ? answer.value.slice(0, -1) : answer.value;
    return domain.length <= 253
      && domain.split(".").every((label) =>
        /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(label));
  }
  if (answer.kind === "mail_exchange") {
    return /^\d{1,5}\s+[A-Za-z0-9.-]+\.?$/u.test(answer.value);
  }
  return answer.value.length > 0 && answer.value.length <= 500
    && !/[\u0000-\u001F\u007F]/u.test(answer.value);
}

function outputSha256(result: LocalProcessToolResult): string {
  return createHash("sha256")
    .update(result.stdout, "utf8")
    .update("\u0000", "utf8")
    .update(result.stderr, "utf8")
    .digest("hex");
}

function parseReceipt(value: string): ProcessingReceipt {
  const parsed = JSON.parse(value) as unknown;
  if (
    !plainRecord(parsed)
    || parsed.schemaVersion !== AUTONOMOUS_DNS_EVIDENCE_VERIFIER_SCHEMA_VERSION
    || typeof parsed.actionId !== "string"
    || typeof parsed.actionFingerprint !== "string"
    || typeof parsed.invocationId !== "string"
    || typeof parsed.outputSha256 !== "string"
    || !plainRecord(parsed.executionResult)
    || typeof parsed.logRecordId !== "string"
    || !(parsed.observationId === null || typeof parsed.observationId === "string")
    || !(parsed.evidenceId === null || typeof parsed.evidenceId === "string")
    || !(parsed.diagnosisId === null || typeof parsed.diagnosisId === "string")
  ) throw new Error("Stored Autonomous DNS evidence receipt is invalid");
  return parsed as unknown as ProcessingReceipt;
}

/**
 * Deterministic result authority for the one reviewed DNS binding. Raw output
 * is always retained as an Engagement Log. Verified Evidence is created only
 * from a schema-checked normalized DNS fact that remains bound to the exact
 * signed action, target, tool, executable hash, and mission criterion.
 */
export class AutonomousDnsEvidenceVerifier {
  readonly #configuration: AutonomousDnsSafeReconConfiguration;
  readonly #now: () => Date;
  readonly #tool: NonNullable<ReturnType<LocalToolCapabilityManifest["resolve"]>>;
  readonly #actions: ActionRepository;

  constructor(private readonly options: AutonomousDnsEvidenceVerifierOptions) {
    this.#configuration = validateAutonomousDnsSafeReconConfiguration(
      options.configuration,
      options.manifest,
    );
    this.#tool = options.manifest.resolve(AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID)!;
    this.#now = options.now ?? (() => new Date());
    this.#actions = new ActionRepository(options.database);
  }

  private receiptKey(invocationId: string): string {
    return `${RECEIPT_PREFIX}${createHash("sha256").update(invocationId, "utf8").digest("hex")}`;
  }

  private specialistInvocation(invocation: SpecialistToolInvocation): AutonomousDnsBoundInvocation {
    return {
      invocationId: invocation.invocationId,
      action: invocation.action,
      arguments: invocation.arguments,
      inputSha256: invocation.inputSha256,
      route: {
        kind: "mcp",
        serverId: invocation.binding.serverId,
        toolName: invocation.binding.toolName,
      },
    };
  }

  private localInvocation(result: LocalProcessToolResult): AutonomousDnsBoundInvocation {
    const envelope = reviewedLocalToolActionEnvelope(result.action.arguments);
    if (!envelope || envelope.toolId !== AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID) {
      throw new DnsVerificationFailure(
        "autonomous_dns_local_binding_invalid",
        "policy_denied",
        "The DNS result is not bound to the reviewed local process envelope.",
        "Discard the result and create a new action through the reviewed local DNS planner.",
      );
    }
    return {
      invocationId: result.invocationId,
      action: result.action,
      arguments: envelope.parameters,
      inputSha256: digestCanonicalJson(
        envelope.parameters,
        { maxBytes: 64 * 1_024, maxDepth: 16 },
      ).sha256,
      route: { kind: "reviewed_local_process", toolId: envelope.toolId },
    };
  }

  /** Read-only crash-window replay of an already committed terminal result. */
  replay(invocation: SpecialistToolInvocation): AutonomousDnsEvidenceProcessingResult | undefined {
    const stored = this.options.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(this.receiptKey(invocation.invocationId)) as { readonly value_json: string } | undefined;
    if (!stored) return undefined;
    const receipt = parseReceipt(stored.value_json);
    if (
      receipt.actionId !== invocation.action.id
      || receipt.actionFingerprint !== invocation.action.fingerprint
      || receipt.invocationId !== invocation.invocationId
    ) throw new Error("Autonomous DNS evidence replay receipt conflicts with the canonical invocation");
    return {
      executionResult: receipt.executionResult,
      logRecordId: receipt.logRecordId,
      ...(receipt.observationId ? { observationId: receipt.observationId } : {}),
      ...(receipt.evidenceId ? { evidenceId: receipt.evidenceId } : {}),
      ...(receipt.diagnosisId ? { diagnosisId: receipt.diagnosisId } : {}),
      duplicate: true,
    };
  }

  /**
   * Fail-closed read-only gate used immediately before the process transport is
   * allowed to make target contact. Result verification repeats these checks so
   * a contract or scope change during execution cannot be accepted afterward.
   */
  assertPreDispatch(invocation: SpecialistToolInvocation): void {
    const bound = this.specialistInvocation(invocation);
    const boundary = this.canonicalBoundary(bound);
    this.assertPolicyAndScope(bound, boundary);
  }

  private canonicalBoundary(invocation: AutonomousDnsBoundInvocation): CanonicalBoundaryRow {
    const canonical = this.#actions.get(invocation.action.id);
    if (digestCanonicalJson(canonical, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      !== digestCanonicalJson(invocation.action, { maxBytes: 1_048_576, maxDepth: 64 }).sha256) {
      throw new DnsVerificationFailure(
        "autonomous_dns_action_binding_changed",
        "policy_denied",
        "The DNS result action differs from the exact canonical running action.",
        "Discard the mismatched result and recover from the latest durable checkpoint.",
      );
    }
    const row = this.options.database.prepare(`
      SELECT r.journey, r.control_plane AS run_control_plane,
        m.control_plane AS mission_control_plane, m.authorization_status,
        m.success_criteria_json AS mission_success_criteria_json,
        r.contract_id AS run_contract_id, r.contract_version_bound,
        r.contract_hash_bound, mc.version AS contract_version,
        mc.contract_hash, mc.state AS contract_state, mc.action_policy_json,
        ps.assigned_agent_id, ps.plan_id
      FROM actions a
      JOIN runs r ON r.id = a.run_id AND r.mission_id = a.mission_id
      JOIN missions m ON m.id = r.mission_id
      JOIN plan_steps ps ON ps.id = a.step_id AND ps.run_id = r.id
      LEFT JOIN mission_contracts mc ON mc.id = r.contract_id AND mc.mission_id = m.id
      WHERE a.id = ? AND a.status = 'running'
    `).get(canonical.id) as CanonicalBoundaryRow | undefined;
    if (!row) {
      throw new DnsVerificationFailure(
        "autonomous_dns_action_not_running",
        "policy_denied",
        "The DNS result no longer belongs to one exact running action.",
        "Reconcile the durable action and tool-call receipt before accepting another result.",
      );
    }
    if (
      row.journey !== "autonomous"
      || row.run_control_plane !== "ti_scale"
      || row.mission_control_plane !== "ti_scale"
      || canonical.kind !== "tool"
      || canonical.actionType !== (invocation.route.kind === "reviewed_local_process"
        ? AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID
        : AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS)
      || canonical.actionClass !== AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS
      || canonical.guidedDecisionId !== null
      || canonical.contractId === null
      || canonical.contractId !== row.run_contract_id
    ) {
      throw new DnsVerificationFailure(
        "autonomous_dns_execution_boundary_invalid",
        "policy_denied",
        "The result is not inside the exact Autonomous Ti-Scale specialist action boundary.",
        "Use a new Autonomous run bound to the reviewed DNS specialist contract.",
      );
    }
    if (
      row.authorization_status !== "verified"
      || row.contract_state !== "confirmed"
      || row.contract_version_bound !== row.contract_version
      || row.contract_hash_bound !== row.contract_hash
    ) {
      throw new DnsVerificationFailure(
        "autonomous_dns_contract_binding_invalid",
        "scope_conflict",
        "Authorization or the signed Autonomous contract changed before DNS evidence validation.",
        "Restore explicit authorization and start a new run from an unchanged confirmed contract.",
      );
    }
    if (!agentAssignmentBindsRuntimeAgent(
      this.options.database,
      row.assigned_agent_id,
      this.#configuration.agentId,
    )) {
      throw new DnsVerificationFailure(
        "autonomous_dns_specialist_binding_changed",
        "policy_denied",
        "The plan step is no longer assigned to the reviewed DNS specialist.",
        "Reassign through a versioned plan change and start a newly bound action.",
      );
    }
    return row;
  }

  private assertPolicyAndScope(
    invocation: AutonomousDnsBoundInvocation,
    row: CanonicalBoundaryRow,
  ): void {
    const action = invocation.action;
    const descriptor = action.arguments;
    const localEnvelope = reviewedLocalToolActionEnvelope(descriptor);
    const parameters = invocation.arguments;
    const routeEnvelopeValid = invocation.route.kind === "mcp"
      ? exactKeys(descriptor, ["mcpServer", "parameters", "toolName"])
        && descriptor.mcpServer === this.#configuration.mcpServerId
        && descriptor.toolName === AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID
        && plainRecord(descriptor.parameters)
        && digestCanonicalJson(descriptor.parameters, { maxBytes: 64 * 1_024, maxDepth: 16 }).sha256
          === digestCanonicalJson(parameters, { maxBytes: 64 * 1_024, maxDepth: 16 }).sha256
      : localEnvelope?.toolId === AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID
        && digestCanonicalJson(localEnvelope.parameters, { maxBytes: 64 * 1_024, maxDepth: 16 }).sha256
          === digestCanonicalJson(parameters, { maxBytes: 64 * 1_024, maxDepth: 16 }).sha256;
    if (
      !routeEnvelopeValid
      || !exactKeys(parameters, ["name", "recordType", "workspace"])
      || parameters.workspace !== this.#configuration.logicalWorkspace
      || parameters.recordType !== this.#configuration.recordType
      || typeof parameters.name !== "string"
      || normalizeDomain(parameters.name) !== normalizeDomain(action.target)
      || (invocation.route.kind === "mcp"
        ? invocation.route.serverId !== this.#configuration.mcpServerId
          || invocation.route.toolName !== AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID
        : invocation.route.toolId !== AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID)
      || digestCanonicalJson(parameters, { maxBytes: 64 * 1_024, maxDepth: 16 }).sha256
        !== invocation.inputSha256
      || digestCanonicalJson(parameters, { maxBytes: 64 * 1_024, maxDepth: 16 }).sha256
        !== digestCanonicalJson(invocation.arguments, { maxBytes: 64 * 1_024, maxDepth: 16 }).sha256
    ) {
      throw new DnsVerificationFailure(
        "autonomous_dns_exact_binding_invalid",
        "policy_denied",
        "The DNS execution route, tool, target, workspace, record type, or input hash differs from the reviewed action.",
        "Discard the result and create a new exact action from the reviewed planning policy.",
      );
    }
    this.options.manifest.compileInvocation(AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID, parameters);

    const targets = this.options.database.prepare(`
      SELECT disposition, normalized_target FROM mission_targets
      WHERE mission_id = ?
    `).all(action.missionId) as Array<{
      readonly disposition: "allowed" | "prohibited";
      readonly normalized_target: string;
    }>;
    const target = normalizeDomain(action.target);
    const allowed = targets.some((candidate) =>
      candidate.disposition === "allowed" && normalizeDomain(candidate.normalized_target) === target);
    const prohibited = targets.some((candidate) =>
      candidate.disposition === "prohibited" && normalizeDomain(candidate.normalized_target) === target);
    if (!allowed || prohibited) {
      throw new DnsVerificationFailure(
        "autonomous_dns_target_outside_scope",
        "scope_conflict",
        `The DNS target ${action.target} is not one unambiguously allowed mission target.`,
        "Correct the normalized allowed/prohibited target set in a new signed contract.",
      );
    }

    const policy = parseJsonRecord(row.action_policy_json, "action policy");
    const allowedClasses = Array.isArray(policy.allowedActionClasses)
      ? policy.allowedActionClasses.filter((value): value is string => typeof value === "string")
      : [];
    const prohibitedClasses = Array.isArray(policy.prohibitedActionClasses)
      ? policy.prohibitedActionClasses.filter((value): value is string => typeof value === "string")
      : [];
    const specialists = Array.isArray(policy.specialistAgentIds)
      ? policy.specialistAgentIds.filter((value): value is string => typeof value === "string")
      : [];
    if (
      !allowedClasses.includes(AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS)
      || prohibitedClasses.includes(AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS)
      || !row.assigned_agent_id
      || !specialists.includes(row.assigned_agent_id)
    ) {
      throw new DnsVerificationFailure(
        "autonomous_dns_contract_policy_denied",
        "policy_denied",
        "The signed action policy does not pre-authorize this exact DNS specialist route.",
        "Amend the registry-backed contract; never infer authority from the tool result.",
      );
    }
    const criteria = parseStringArray(row.mission_success_criteria_json, "success criteria");
    if (!criteria.includes(this.#configuration.successCriterion)) {
      throw new DnsVerificationFailure(
        "autonomous_dns_success_criterion_unbound",
        "evidence_insufficient",
        "The reviewed DNS evidence criterion is not an exact canonical mission criterion.",
        "Add the criterion through a versioned contract and start a new run.",
      );
    }
  }

  private assertResultBinding(
    invocation: AutonomousDnsBoundInvocation,
    result: LocalProcessToolResult,
  ): void {
    if (
      result.invocationId !== invocation.invocationId
      || result.toolId !== AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID
      || digestCanonicalJson(result.action, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
        !== digestCanonicalJson(invocation.action, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      || result.outputTruncated
      || !SHA256.test(result.outputSha256)
      || outputSha256(result) !== result.outputSha256
      || result.executable.sourcePath !== this.#tool.executable.path
      || result.executable.sourceSha256 !== this.#tool.executable.expectedSha256
      || result.executable.snapshotSha256 !== this.#tool.executable.expectedSha256
      || result.sandbox.shell !== false
      || Date.parse(result.endedAt) < Date.parse(result.startedAt)
      || Date.parse(result.endedAt) > this.#now().getTime() + 60_000
    ) {
      throw new DnsVerificationFailure(
        "autonomous_dns_result_integrity_invalid",
        "policy_denied",
        "The DNS process result failed exact invocation, executable, output, timestamp, or truncation checks.",
        "Quarantine the result, re-attest the executable and sandbox, and resume only from a durable checkpoint.",
      );
    }
  }

  private parsedAnswers(result: LocalProcessToolResult): readonly DnsAnswer[] {
    const allowedKinds = allowedAnswerKinds(this.#configuration.recordType);
    const answers = `${result.stdout}\n${result.stderr}`.replaceAll("\r\n", "\n")
      .split("\n")
      .map((line) => dnsAnswer(line.trim()))
      .filter((answer): answer is DnsAnswer => answer !== undefined);
    const unique = [...new Map(answers.map((answer) => [`${answer.kind}\u0000${answer.value}`, answer])).values()]
      .sort((left, right) => `${left.kind}\u0000${left.value}`.localeCompare(`${right.kind}\u0000${right.value}`));
    if (unique.length > 100 || unique.some((answer) => !allowedKinds.has(answer.kind) || !answerValueValid(answer))) {
      throw new DnsVerificationFailure(
        "autonomous_dns_answer_schema_invalid",
        "evidence_insufficient",
        "The DNS output contained an unsupported or malformed answer and was not promoted to evidence.",
        "Inspect the Engagement Log, update the reviewed parser only with a tested format, then run a new exact action.",
      );
    }
    return unique;
  }

  private appendLog(
    invocation: AutonomousDnsBoundInvocation,
    result: LocalProcessToolResult,
    input: Readonly<{ severity: "notice" | "error"; summary: string }>,
  ) {
    const truth = new OperationalTruthService(this.options.database, { clock: this.#now });
    const row = this.options.database.prepare("SELECT plan_id FROM plan_steps WHERE id = ?")
      .get(invocation.action.stepId) as { readonly plan_id: string };
    return truth.appendEngagementLog({
      missionId: invocation.action.missionId,
      runId: invocation.action.runId,
      planId: row.plan_id,
      stepId: invocation.action.stepId,
      actionId: invocation.action.id,
      agentId: this.#configuration.agentId,
      toolCallId: invocation.invocationId,
      severity: input.severity,
      domain: "autonomous_dns_safe_recon",
      recordType: "bounded_dns_process_output",
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
    invocation: AutonomousDnsBoundInvocation,
    result: LocalProcessToolResult,
    failure: DnsVerificationFailure,
    logRecordId: string,
  ): AutonomousDnsEvidenceProcessingResult {
    const diagnosis = new FailureDiagnosisService(this.options.database, { clock: this.#now }).create({
      missionId: invocation.action.missionId,
      runId: invocation.action.runId,
      stepId: invocation.action.stepId,
      actionId: invocation.action.id,
      subjectType: "action",
      subjectId: invocation.action.id,
      humanReason: `Failed safely: ${failure.message}`,
      category: diagnosisCategory(failure.category),
      code: failure.code,
      originatingComponent: "autonomous-dns-evidence-verifier",
      failedComponentRef: invocation.route.kind === "reviewed_local_process"
        ? `reviewed-local-process/${invocation.route.toolId}`
        : `${invocation.route.serverId}/${invocation.route.toolName}`,
      targetSummary: `Exact authorized DNS target ${invocation.action.target}; no verified evidence was created.`,
      policyOrDependency: "The signed contract, normalized target, exact specialist/execution/tool binding, executable hash, complete output, deterministic parser, and canonical success criterion must all match.",
      rawErrorLogId: logRecordId,
      retryHistory: [],
      progressBeforeFailure: { verifiedEvidenceCreated: false },
      preservedReferences: [{
        kind: "log",
        id: logRecordId,
        meaning: "Redacted bounded DNS process output retained for diagnosis",
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
        label: "Retry this exact DNS step once",
        consequence: "Creates a new bounded attempt only after current policy, scope, and dependency checks pass again.",
        requiresConfirmation: true,
      }, {
        kind: "terminate_gracefully",
        label: "End the run safely",
        consequence: "Preserves the log and diagnosis without claiming DNS evidence or mission success.",
        requiresConfirmation: true,
      }] : [{
        kind: "amend_plan",
        label: "Correct the DNS action boundary",
        consequence: "Creates a new plan version and action; it does not reinterpret or replay this rejected result.",
        requiresConfirmation: true,
      }, {
        kind: "terminate_gracefully",
        label: "End the run safely",
        consequence: "Preserves the log and diagnosis without claiming DNS evidence or mission success.",
        requiresConfirmation: true,
      }],
      objectiveImpact: "The requested DNS criterion remains unsupported. Existing mission state and prior evidence are preserved.",
      terminal: !failure.retryable,
      actor: { id: "autonomous-dns-evidence-verifier", type: "system" },
    });
    return {
      executionResult: {
        actionId: invocation.action.id,
        runId: invocation.action.runId,
        actionFingerprint: invocation.action.fingerprint,
        success: false,
        summary: `Failed safely: ${failure.message}`,
        progress: {},
        failure: {
          source: "tool",
          code: failure.code,
          message: failure.message,
        },
        failureCategory: failure.category,
        circuitKey: `autonomous-dns:${AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID}`,
        usage: { wallClockMs: result.wallClockMs },
      },
      logRecordId,
      diagnosisId: diagnosis.id,
      duplicate: false,
    };
  }

  process(
    invocation: SpecialistToolInvocation,
    result: LocalProcessToolResult,
  ): AutonomousDnsEvidenceProcessingResult {
    return this.processBound(this.specialistInvocation(invocation), result);
  }

  processLocalResult(result: LocalProcessToolResult): AutonomousDnsEvidenceProcessingResult {
    return this.processBound(this.localInvocation(result), result);
  }

  private processBound(
    invocation: AutonomousDnsBoundInvocation,
    result: LocalProcessToolResult,
  ): AutonomousDnsEvidenceProcessingResult {
    return inImmediateTransaction(this.options.database, () => {
      const key = this.receiptKey(invocation.invocationId);
      const stored = this.options.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(key) as { readonly value_json: string } | undefined;
      if (stored) {
        const receipt = parseReceipt(stored.value_json);
        if (
          receipt.actionId !== invocation.action.id
          || receipt.actionFingerprint !== invocation.action.fingerprint
          || receipt.invocationId !== invocation.invocationId
          || receipt.outputSha256 !== result.outputSha256
        ) throw new Error("Autonomous DNS evidence receipt conflicts with this result");
        return {
          executionResult: receipt.executionResult,
          logRecordId: receipt.logRecordId,
          ...(receipt.observationId ? { observationId: receipt.observationId } : {}),
          ...(receipt.evidenceId ? { evidenceId: receipt.evidenceId } : {}),
          ...(receipt.diagnosisId ? { diagnosisId: receipt.diagnosisId } : {}),
          duplicate: true,
        };
      }

      let boundary: CanonicalBoundaryRow;
      try {
        boundary = this.canonicalBoundary(invocation);
        this.assertPolicyAndScope(invocation, boundary);
        this.assertResultBinding(invocation, result);
      } catch (error) {
        const failure = error instanceof DnsVerificationFailure ? error : new DnsVerificationFailure(
          "autonomous_dns_boundary_validation_failed",
          "policy_denied",
          error instanceof Error ? error.message : "The DNS result boundary could not be validated.",
          "Inspect the exact action, contract, scope, manifest, and executable bindings before a new run.",
        );
        const log = this.appendLog(invocation, result, { severity: "error", summary: `Failed safely: ${failure.message}` });
        const outcome = this.failure(invocation, result, failure, log.id);
        this.saveReceipt(key, invocation, result, outcome);
        return outcome;
      }

      const classification = classifyReviewedLocalToolResult(result);
      if (!classification.success) {
        const failure = new DnsVerificationFailure(
          classification.code ?? "autonomous_dns_tool_failed",
          classification.category ?? "deterministic_tool_error",
          classification.summary,
          classification.category === "timeout"
            ? "Verify resolver reachability, then use only the bounded retry control."
            : "Inspect the retained log and repair the deterministic tool or dependency before a new action.",
          classification.category === "timeout",
        );
        const log = this.appendLog(invocation, result, { severity: "error", summary: `Failed safely: ${failure.message}` });
        const outcome = this.failure(invocation, result, failure, log.id);
        this.saveReceipt(key, invocation, result, outcome);
        return outcome;
      }

      let answers: readonly DnsAnswer[];
      try {
        answers = this.parsedAnswers(result);
        if (classification.outcome === "positive_observation" && answers.length === 0) {
          throw new DnsVerificationFailure(
            "autonomous_dns_answer_missing",
            "evidence_insufficient",
            "The DNS process exited successfully but produced no supported answer, so no evidence was created.",
            "Inspect the log and update the reviewed parser or use a new bounded query only when justified.",
          );
        }
        if (classification.outcome === "negative_observation" && answers.length > 0) {
          throw new DnsVerificationFailure(
            "autonomous_dns_outcome_conflict",
            "evidence_insufficient",
            "The DNS result simultaneously looked negative and contained parsed answers.",
            "Review the conflicting output and do not promote it automatically.",
          );
        }
      } catch (error) {
        const failure = error instanceof DnsVerificationFailure ? error : new DnsVerificationFailure(
          "autonomous_dns_parser_failed",
          "evidence_insufficient",
          "The DNS output could not be normalized deterministically.",
          "Inspect the retained log and add a tested parser format before a new action.",
        );
        const log = this.appendLog(invocation, result, { severity: "error", summary: `Failed safely: ${failure.message}` });
        const outcome = this.failure(invocation, result, failure, log.id);
        this.saveReceipt(key, invocation, result, outcome);
        return outcome;
      }

      const noRecord = classification.outcome === "negative_observation";
      const statement = noRecord
        ? `The exact DNS ${this.#configuration.recordType} query for ${invocation.action.target} completed with an attributable no-record result.`
        : `The exact DNS ${this.#configuration.recordType} query for ${invocation.action.target} returned ${answers.length} validated ${answers.length === 1 ? "answer" : "answers"}.`;
      const log = this.appendLog(invocation, result, { severity: "notice", summary: statement });
      const truth = new OperationalTruthService(this.options.database, { clock: this.#now });
      const observation = truth.createObservation({
        missionId: invocation.action.missionId,
        runId: invocation.action.runId,
        stepId: invocation.action.stepId,
        observationType: "dns_record_query",
        statement,
        normalizedValue: {
          schemaVersion: AUTONOMOUS_DNS_EVIDENCE_VERIFIER_SCHEMA_VERSION,
          queryName: normalizeDomain(invocation.action.target),
          recordType: this.#configuration.recordType,
          noRecord,
          answerCount: answers.length,
          answers,
          actionId: invocation.action.id,
          toolCallId: invocation.invocationId,
          toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
          outputSha256: result.outputSha256,
        },
        confidence: noRecord ? 0.9 : 0.95,
        verificationState: "corroborated",
        sourceAgentId: this.#configuration.agentId,
        sourceTool: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
        firstSeenAt: result.startedAt,
        lastSeenAt: result.endedAt,
        sensitivity: "private",
        sources: [{
          logRecordId: log.id,
          parserId: "ti-scale.autonomous-dns-deterministic-parser",
          parserVersion: "1.0.0",
        }],
      });
      const normalizedEvidence = {
        queryName: normalizeDomain(invocation.action.target),
        recordType: this.#configuration.recordType,
        noRecord,
        answers,
        observationId: observation.id,
        logRecordId: log.id,
        outputSha256: result.outputSha256,
      };
      const content = digestCanonicalJson(normalizedEvidence, { maxBytes: 256 * 1_024, maxDepth: 32 });
      const criterionId = autonomousSuccessCriterionId(this.#configuration.successCriterion);
      const evidenceId = `evidence_dns_${createHash("sha256")
        .update(`${invocation.action.id}\u0000${invocation.invocationId}\u0000${content.sha256}`, "utf8")
        .digest("hex").slice(0, 40)}`;
      const acquiredAt = result.endedAt;
      const createdAt = this.#now().toISOString();
      const provenance = digestCanonicalJson({
        schemaVersion: AUTONOMOUS_DNS_EVIDENCE_VERIFIER_SCHEMA_VERSION,
        method: "deterministic_reviewed_dns_result_validation",
        actionId: invocation.action.id,
        actionFingerprint: invocation.action.fingerprint,
        toolCallId: invocation.invocationId,
        observationId: observation.id,
        logRecordId: log.id,
        specialistAgentId: this.#configuration.agentId,
        executionRoute: invocation.route,
        ...(this.#configuration.mcpServerId
          ? { advisoryMcpInventoryId: this.#configuration.mcpServerId }
          : {}),
        advisoryMcpGrantedExecution: false,
        toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
        manifestSha256: this.options.manifest.descriptor.manifestSha256,
        toolBindingSha256: this.#tool.bindingSha256,
        executableSha256: result.executable.sourceSha256,
        outputSha256: result.outputSha256,
        rawOutputPromoted: false,
        successCriterionReferences: [{
          schemaVersion: AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
          criterionId,
          outcome: "achieved",
        }],
      }, { maxBytes: 256 * 1_024, maxDepth: 32 });
      this.options.database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, step_id, action_id, source, acquired_at,
          target, evidence_type, content_hash, provenance_json, confidence,
          sensitivity, verification_state, summary, extracted_text,
          artifact_id, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'private', 'verified', ?, ?, NULL, ?, ?)
      `).run(
        evidenceId,
        invocation.action.missionId,
        invocation.action.runId,
        invocation.action.stepId,
        invocation.action.id,
        `specialist:${this.#configuration.agentId}`,
        acquiredAt,
        invocation.action.target,
        AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE,
        content.sha256,
        provenance.canonicalJson,
        noRecord ? 0.9 : 0.95,
        statement,
        content.canonicalJson,
        "autonomous-dns-evidence-verifier",
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
        digestCanonicalJson({ observationId: observation.id, logRecordId: log.id, contentHash: content.sha256 }, { maxBytes: 16 * 1_024, maxDepth: 8 }).canonicalJson,
        acquiredAt,
        verifiedCustodyId,
        evidenceId,
        "autonomous-dns-evidence-verifier",
        digestCanonicalJson({ method: "deterministic_reviewed_dns_result_validation", criterionId, rawOutputPromoted: false }, { maxBytes: 16 * 1_024, maxDepth: 8 }).canonicalJson,
        createdAt,
      );
      truth.repository.audit.append({
        missionId: invocation.action.missionId,
        runId: invocation.action.runId,
        actor: { id: "autonomous-dns-evidence-verifier", type: "system" },
        action: "evidence.verified_deterministically",
        resourceType: "evidence",
        resourceId: evidenceId,
        reason: "The exact reviewed DNS result passed scope, policy, binding, executable, output, parser, and criterion checks.",
        details: { observationId: observation.id, logRecordId: log.id, criterionId, rawOutputPromoted: false },
        occurredAt: createdAt,
      });
      const executionResult: ExecutionResult = {
        actionId: invocation.action.id,
        runId: invocation.action.runId,
        actionFingerprint: invocation.action.fingerprint,
        success: true,
        summary: `${statement} Verified evidence ${evidenceId} was retained with chain of custody.`,
        progress: {
          stepStates: { [invocation.action.stepId]: "completed" },
          evidenceIds: [evidenceId],
          successCriteria: { [criterionId]: 1 },
        },
        usage: {
          wallClockMs: result.wallClockMs,
          evidenceBytes: content.bytes + provenance.bytes,
        },
      };
      const outcome: AutonomousDnsEvidenceProcessingResult = {
        executionResult,
        logRecordId: log.id,
        observationId: observation.id,
        evidenceId,
        duplicate: false,
      };
      this.saveReceipt(key, invocation, result, outcome);
      return outcome;
    });
  }

  private saveReceipt(
    key: string,
    invocation: AutonomousDnsBoundInvocation,
    result: LocalProcessToolResult,
    outcome: AutonomousDnsEvidenceProcessingResult,
  ): void {
    const receipt: ProcessingReceipt = {
      schemaVersion: AUTONOMOUS_DNS_EVIDENCE_VERIFIER_SCHEMA_VERSION,
      actionId: invocation.action.id,
      actionFingerprint: invocation.action.fingerprint,
      invocationId: invocation.invocationId,
      outputSha256: result.outputSha256,
      executionResult: outcome.executionResult,
      logRecordId: outcome.logRecordId,
      observationId: outcome.observationId ?? null,
      evidenceId: outcome.evidenceId ?? null,
      diagnosisId: outcome.diagnosisId ?? null,
    };
    this.options.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', 1, 'autonomous-dns-evidence-verifier', ?)
    `).run(key, digestCanonicalJson(receipt, { maxBytes: 512 * 1_024, maxDepth: 64 }).canonicalJson, this.#now().toISOString());
  }
}

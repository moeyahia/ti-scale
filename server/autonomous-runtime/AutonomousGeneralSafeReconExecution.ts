import { createHash } from "node:crypto";
import { isIP } from "node:net";
import type { BrainContextService } from "../brain-runtime";
import type { ControlPlaneLease } from "../control-plane";
import type {
  ExecutionResult,
  ExecutionResultReceipt,
  ExecutionResultSink,
  ResultAwareExecutionPort,
} from "../command-runtime";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  LocalProcessToolExecutionError,
  type LocalProcessAdapterReadinessReceipt,
  type LocalProcessToolInvocation,
  type LocalProcessToolResult,
  type LocalProcessToolResultSink,
  type LocalToolCapabilityManifest,
  type ReviewedLocalProcessInvocationAdapter,
} from "../local-tools";
import { digestCanonicalJson } from "../mcp";
import {
  ActionRepository,
  ExecutionBoundaryError,
  RunRepository,
  reviewedLocalToolActionEnvelope,
  type DurableAction,
} from "../orchestration";
import type { FailureCategory } from "../supervisor";
import type { EngagementWorkspaceResolver } from "../system-capabilities";
import type {
  AutonomousCveCandidateEnrichmentPort,
  MissionScopedNvdDetailResult,
} from "../cve-intelligence";
import {
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
} from "./AutonomousFullTcpBaseline";
import {
  AutonomousFullTcpBaselineError,
  AutonomousFullTcpBaselineExecution,
  createAutonomousFullTcpAuthorizationReceipt,
  type ReviewedFullTcpBaselineInvocationAdapter,
} from "./AutonomousFullTcpBaselineExecution";
import {
  AUTONOMOUS_FULL_TCP_RESULT_DELIVERY_SCHEMA_VERSION,
  AutonomousFullTcpEvidenceVerifier,
  AutonomousFullTcpEvidenceVerificationError,
  autonomousFullTcpCompositeToolCallId,
} from "./AutonomousFullTcpEvidenceVerifier";
import {
  AUTONOMOUS_GENERAL_SAFE_RECON_EXECUTION_CONTRACT,
  type AutonomousFullTcpPlanningConfiguration,
} from "./AutonomousGeneralSafeRecon";
import type { AutonomousDnsSafeReconConfiguration } from "./AutonomousDnsSafeRecon";
import {
  AutonomousLocalSafeReconExecutionFactory,
} from "./AutonomousIpLocalProcessExecution";
import type { AutonomousIpSafeReconConfiguration } from "./AutonomousIpSafeRecon";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
  AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
  AUTONOMOUS_HTTP_METADATA_TOOL_ID,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
  AUTONOMOUS_WHATWEB_TOOL_ID,
  type AutonomousWebSurfacePlanningConfiguration,
} from "./AutonomousWebSurfaceBaseline";
import type { ReviewedAutonomousWebSurfaceInvocationAdapter } from "./AutonomousWebSurfaceExecution";
import { AutonomousWebSurfaceResultAwarePort } from "./AutonomousWebSurfaceResultAwarePort";
import {
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
  type AuthoritativeCveCandidateCatalogPort,
  type AutonomousCveApplicabilityConfiguration,
} from "./AutonomousCveApplicability";
import { AutonomousCveApplicabilityResultAwarePort } from "./AutonomousCveApplicabilityResultAwarePort";
import {
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID,
  type AutonomousVulnerabilityAssessmentConfiguration,
} from "./AutonomousVulnerabilityAssessment";
import type {
  ReviewedAutonomousVulnerabilityInvocationAdapter,
} from "./AutonomousVulnerabilityExecution";
import {
  AutonomousVulnerabilityResultAwarePort,
} from "./AutonomousVulnerabilityResultAwarePort";

interface ReadinessCapableAdapter extends ReviewedLocalProcessInvocationAdapter {
  readinessReceipt(now?: Date, ttlMs?: number): Promise<LocalProcessAdapterReadinessReceipt>;
}

function readinessCapable(
  adapter: ReviewedLocalProcessInvocationAdapter,
): adapter is ReadinessCapableAdapter {
  return typeof (adapter as Partial<ReadinessCapableAdapter>).readinessReceipt === "function";
}

function canonicalIp(value: string): string {
  if (value !== value.trim() || isIP(value) === 0) {
    throw new LocalProcessToolExecutionError(
      "full_tcp_ip_literal_required",
      "The reviewed Full-TCP route accepts only one exact canonical IP literal.",
    );
  }
  const hostname = new URL(`http://${isIP(value) === 6 ? `[${value}]` : value}/`).hostname;
  const normalized = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
  if (normalized !== value.toLowerCase()) {
    throw new LocalProcessToolExecutionError(
      "full_tcp_ip_not_canonical",
      "The reviewed Full-TCP route requires the canonical IP spelling persisted in mission scope.",
    );
  }
  return normalized;
}

/**
 * The process adapter deliberately supports one result sink. This router owns
 * that sink and gives the ordinary one-process port and the composite
 * Full-TCP executor disjoint tool channels. Neither channel can consume the
 * other's result or dispatch an unreviewed tool.
 */
class GeneralSafeReconProcessRouter {
  private standardSink?: LocalProcessToolResultSink;
  private fullTcpSink?: LocalProcessToolResultSink;
  private webSink?: LocalProcessToolResultSink;
  private vulnerabilitySink?: LocalProcessToolResultSink;
  private readonly unbind: () => void;
  readonly standard: ReviewedLocalProcessInvocationAdapter;
  readonly fullTcp: ReviewedFullTcpBaselineInvocationAdapter;
  readonly web: ReviewedAutonomousWebSurfaceInvocationAdapter;
  readonly vulnerability: ReviewedAutonomousVulnerabilityInvocationAdapter;

  constructor(private readonly adapter: ReviewedLocalProcessInvocationAdapter) {
    const unbind = adapter.bindResultSink({
      acceptLocalProcessToolResult: (result) => this.accept(result),
    });
    this.unbind = typeof unbind === "function" ? unbind : () => undefined;
    this.standard = Object.freeze({
      bindResultSink: (sink: LocalProcessToolResultSink) => this.bind("standard", sink),
      dispatch: (invocation: LocalProcessToolInvocation, signal: AbortSignal): Promise<void> => {
        if (invocation.toolId === AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID
          || invocation.toolId === AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID
          || invocation.toolId === AUTONOMOUS_HTTP_METADATA_TOOL_ID
          || invocation.toolId === AUTONOMOUS_WHATWEB_TOOL_ID
          || invocation.toolId === AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID
          || invocation.toolId === AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID) {
          throw new LocalProcessToolExecutionError(
            "composite_phase_wrong_channel",
            "A composite phase invocation reached the ordinary Safe Recon channel.",
          );
        }
        return adapter.dispatch(invocation, signal);
      },
      cancelRun: (runId: string, reason: string): Promise<void> =>
        adapter.cancelRun(runId, reason),
    });
    this.fullTcp = Object.freeze({
      bindResultSink: (sink: LocalProcessToolResultSink) => this.bind("full_tcp", sink),
      dispatch: (invocation: LocalProcessToolInvocation, signal: AbortSignal): Promise<void> => {
        if (invocation.toolId !== AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID
          && invocation.toolId !== AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID) {
          throw new LocalProcessToolExecutionError(
            "standard_tool_wrong_channel",
            "A non-composite invocation reached the Full-TCP phase channel.",
          );
        }
        return adapter.dispatch(invocation, signal);
      },
      cancelRun: (runId: string, reason: string): Promise<void> =>
        adapter.cancelRun(runId, reason),
      readinessReceipt: async (now?: Date, ttlMs?: number) => {
        if (!readinessCapable(adapter)) {
          throw new LocalProcessToolExecutionError(
            "full_tcp_readiness_unavailable",
            "The process adapter cannot produce a current target-free readiness receipt.",
          );
        }
        const current = await adapter.readinessReceipt(now, ttlMs);
        const tools = current.tools.filter(({ toolId }) =>
          toolId === AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID
          || toolId === AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID);
        if (tools.length !== 2) {
          throw new LocalProcessToolExecutionError(
            "full_tcp_readiness_incomplete",
            "The process adapter did not attest both exact Full-TCP phase tools.",
          );
        }
        const { receiptSha256: _receiptSha256, tools: _tools, ...rest } = current;
        const unsigned = { ...rest, tools };
        return Object.freeze({
          ...unsigned,
          receiptSha256: digestCanonicalJson(unsigned, {
            maxBytes: 512 * 1_024,
            maxDepth: 16,
          }).sha256,
        });
      },
    });
    this.web = Object.freeze({
      bindResultSink: (sink: LocalProcessToolResultSink) => this.bind("web", sink),
      dispatch: (invocation: LocalProcessToolInvocation, signal: AbortSignal): Promise<void> => {
        if (invocation.toolId !== AUTONOMOUS_HTTP_METADATA_TOOL_ID
          && invocation.toolId !== AUTONOMOUS_WHATWEB_TOOL_ID
          && invocation.toolId !== AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID) {
          throw new LocalProcessToolExecutionError(
            "non_web_tool_wrong_channel",
            "A non-web invocation reached the derived-origin web phase channel.",
          );
        }
        return adapter.dispatch(invocation, signal);
      },
      cancelRun: (runId: string, reason: string): Promise<void> =>
        adapter.cancelRun(runId, reason),
    });
    this.vulnerability = Object.freeze({
      bindResultSink: (sink: LocalProcessToolResultSink) =>
        this.bind("vulnerability", sink),
      dispatch: (invocation: LocalProcessToolInvocation, signal: AbortSignal): Promise<void> => {
        if (invocation.toolId !== AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID) {
          throw new LocalProcessToolExecutionError(
            "non_vulnerability_tool_wrong_channel",
            "A non-vulnerability tool reached the bounded assessment channel.",
          );
        }
        return adapter.dispatch(invocation, signal);
      },
      cancelRun: (runId: string, reason: string): Promise<void> =>
        adapter.cancelRun(runId, reason),
    });
  }

  private bind(
    channel: "standard" | "full_tcp" | "web" | "vulnerability",
    sink: LocalProcessToolResultSink,
  ): () => void {
    if (channel === "standard") {
      if (this.standardSink) throw new Error("Standard Safe Recon result sink is already bound");
      this.standardSink = sink;
      return () => { if (this.standardSink === sink) this.standardSink = undefined; };
    }
    if (channel === "full_tcp") {
      if (this.fullTcpSink) throw new Error("Full-TCP result sink is already bound");
      this.fullTcpSink = sink;
      return () => { if (this.fullTcpSink === sink) this.fullTcpSink = undefined; };
    }
    if (channel === "web") {
      if (this.webSink) throw new Error("Web-surface result sink is already bound");
      this.webSink = sink;
      return () => { if (this.webSink === sink) this.webSink = undefined; };
    }
    if (this.vulnerabilitySink) {
      throw new Error("Vulnerability-assessment result sink is already bound");
    }
    this.vulnerabilitySink = sink;
    return () => {
      if (this.vulnerabilitySink === sink) this.vulnerabilitySink = undefined;
    };
  }

  private async accept(result: LocalProcessToolResult): Promise<void> {
    const fullTcp = result.toolId === AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID
      || result.toolId === AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID;
    const web = result.toolId === AUTONOMOUS_HTTP_METADATA_TOOL_ID
      || result.toolId === AUTONOMOUS_WHATWEB_TOOL_ID
      || result.toolId === AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID;
    const vulnerability =
      result.toolId === AUTONOMOUS_VULNERABILITY_ASSESSMENT_TOOL_ID;
    const sink = fullTcp ? this.fullTcpSink
      : web ? this.webSink
        : vulnerability ? this.vulnerabilitySink : this.standardSink;
    if (!sink) {
      throw new LocalProcessToolExecutionError(
        "general_safe_recon_result_sink_unbound",
        "The exact Safe Recon result channel is not bound.",
      );
    }
    await sink.acceptLocalProcessToolResult(result);
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    await this.adapter.cancelRun(runId, reason);
  }

  close(): void {
    if (this.standardSink || this.fullTcpSink || this.webSink
      || this.vulnerabilitySink) {
      throw new Error("Cannot close the general Safe Recon router while child result sinks remain bound");
    }
    this.unbind();
  }
}

interface CompositeTerminalPayload {
  readonly schemaVersion: typeof AUTONOMOUS_FULL_TCP_RESULT_DELIVERY_SCHEMA_VERSION;
  readonly resultSha256: string | null;
  readonly logRecordId: string | null;
  readonly observationId: string | null;
  readonly evidenceIds: readonly string[];
  readonly deliveryResult: ExecutionResult;
  readonly resultAccepted: boolean;
  readonly duplicateResult: boolean;
  readonly deliveryAttemptCount: number;
  readonly deliveryLastAttemptAt: string | null;
  readonly deliveryLastError: string | null;
}

interface PendingCompositeRow {
  readonly invocation_id: string;
  readonly tool_status: "succeeded" | "failed" | "timed_out";
  readonly redacted_payload_json: string;
  readonly action_id: string;
  readonly run_id: string;
  readonly action_fingerprint: string;
}

function parsePayload(value: string): CompositeTerminalPayload | undefined {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    const item = parsed as Partial<CompositeTerminalPayload>;
    if (item.schemaVersion !== AUTONOMOUS_FULL_TCP_RESULT_DELIVERY_SCHEMA_VERSION
      || !item.deliveryResult || typeof item.deliveryResult !== "object"
      || (item.resultSha256 !== null && typeof item.resultSha256 !== "string")
      || (item.logRecordId !== null && typeof item.logRecordId !== "string")
      || (item.observationId !== null && typeof item.observationId !== "string")
      || !Array.isArray(item.evidenceIds)
      || item.evidenceIds.some((id) => typeof id !== "string")
      || typeof item.resultAccepted !== "boolean" || typeof item.duplicateResult !== "boolean"
      || typeof item.deliveryAttemptCount !== "number") return undefined;
    const delivery = item.deliveryResult as Partial<ExecutionResult>;
    if (typeof delivery.actionId !== "string" || typeof delivery.runId !== "string"
      || typeof delivery.actionFingerprint !== "string" || typeof delivery.success !== "boolean"
      || typeof delivery.summary !== "string" || !delivery.progress
      || typeof delivery.progress !== "object" || Array.isArray(delivery.progress)) return undefined;
    return item as CompositeTerminalPayload;
  } catch {
    return undefined;
  }
}

function redactedFailureDetail(error: unknown): string {
  const message = error instanceof Error ? error.message : "Full-TCP composite execution failed.";
  const normalized = message.replace(/[\u0000-\u001F\u007F]/gu, " ").trim().replace(/\s+/gu, " ");
  return (normalized || "Full-TCP composite execution failed.").slice(0, 700);
}

function fullTcpFailureCode(error: unknown): string {
  const code = typeof (error as { readonly code?: unknown })?.code === "string"
    ? (error as { readonly code: string }).code
    : "full_tcp_composite_failed";
  return /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$/u.test(code)
    ? code
    : "full_tcp_composite_failed";
}

function fullTcpFailureCategory(error: unknown, code: string): FailureCategory {
  if (error instanceof ExecutionBoundaryError) return error.failureCategory;
  if (/owner_fence|lease|heartbeat/iu.test(code)) return "worker_lost";
  if (/cancel/iu.test(code)) return "operator_rejection";
  if (/wall_clock|timeout|timed_out/iu.test(code)) return "timeout";
  if (/target|scope/iu.test(code)) return "scope_conflict";
  if (/authorization/iu.test(code)) return "authorization_denied";
  if (/contract|binding|canonical|compiler|policy/iu.test(code)) return "policy_denied";
  if (/output|verification|evidence|coverage/iu.test(code)
    || error instanceof AutonomousFullTcpEvidenceVerificationError) return "evidence_insufficient";
  if (error instanceof AutonomousFullTcpBaselineError) {
    if (error.phase === "discovery" || error.phase === "service_version") {
      return "deterministic_tool_error";
    }
    if (error.phase === "verification") return "evidence_insufficient";
    return "dependency_missing";
  }
  if (/workspace|readiness|artifact|executable|spawn|dependency|sink/iu.test(code)) {
    return "dependency_missing";
  }
  return "unknown";
}

function failedExecutionResult(input: Readonly<{
  action: DurableAction;
  error: unknown;
  wallClockMs: number;
}>): ExecutionResult {
  const code = fullTcpFailureCode(input.error);
  const detail = redactedFailureDetail(input.error);
  const category = fullTcpFailureCategory(input.error, code);
  return Object.freeze({
    actionId: input.action.id,
    runId: input.action.runId,
    actionFingerprint: input.action.fingerprint,
    success: false,
    summary: `Full TCP baseline failed safely. ${detail} The action was closed without claiming mission success.`,
    progress: Object.freeze({}),
    failure: Object.freeze({ source: "tool" as const, code, message: detail }),
    failureCategory: category,
    circuitKey: `autonomous-full-tcp:${AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE}`,
    usage: Object.freeze({ wallClockMs: Math.max(0, Math.round(input.wallClockMs)) }),
  });
}

class AutonomousFullTcpResultAwarePort implements ResultAwareExecutionPort {
  private readonly actions: ActionRepository;
  private readonly runs: RunRepository;
  private readonly executor: AutonomousFullTcpBaselineExecution;
  private readonly verifier: AutonomousFullTcpEvidenceVerifier;
  private readonly now: () => Date;
  private resultSink?: ExecutionResultSink;

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    manifest: LocalToolCapabilityManifest;
    configuration: AutonomousFullTcpPlanningConfiguration;
    adapter: ReviewedFullTcpBaselineInvocationAdapter;
    workspaceResolver: EngagementWorkspaceResolver;
    assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
    now?: () => Date;
  }>) {
    this.actions = new ActionRepository(options.database);
    this.runs = new RunRepository(options.database);
    this.now = options.now ?? (() => new Date());
    this.executor = new AutonomousFullTcpBaselineExecution({
      manifest: options.manifest,
      configuration: options.configuration,
      adapter: options.adapter,
      workspaceResolver: options.workspaceResolver,
      ...(options.now ? { now: options.now } : {}),
    });
    this.verifier = new AutonomousFullTcpEvidenceVerifier({
      database: options.database,
      manifest: options.manifest,
      configuration: options.configuration,
      workspaceResolver: options.workspaceResolver,
      ...(options.now ? { now: options.now } : {}),
    });
  }

  bindResultSink(sink: ExecutionResultSink): () => void {
    if (this.resultSink) throw new Error("Full-TCP runtime result sink is already bound");
    this.resultSink = sink;
    return () => { if (this.resultSink === sink) this.resultSink = undefined; };
  }

  private canonical(input: DurableAction): Readonly<{
    action: DurableAction;
    lease: ControlPlaneLease;
    contractHash: string;
    prohibitedTargets: readonly string[];
  }> {
    const action = this.actions.get(input.id);
    if (digestCanonicalJson(action, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      !== digestCanonicalJson(input, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      || action.status !== "running") {
      throw new LocalProcessToolExecutionError(
        "full_tcp_action_not_canonical",
        "Only the exact canonical running Full-TCP action may enter composite execution.",
      );
    }
    const target = canonicalIp(action.target);
    const envelope = reviewedLocalToolActionEnvelope(action.arguments);
    if (!envelope || envelope.toolId !== AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE
      || action.actionType !== AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE
      || action.actionClass !== AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS
      || Object.keys(envelope.parameters).sort().join("\u0000") !== "target\u0000workspace"
      || envelope.parameters.target !== target
      || envelope.parameters.workspace !== this.options.configuration.logicalWorkspace) {
      throw new LocalProcessToolExecutionError(
        "full_tcp_action_binding_invalid",
        "The canonical action does not carry the exact reviewed Full-TCP composite envelope.",
      );
    }
    const lease = this.options.assertControlPlaneAuthority(action.runId);
    const authorized = this.runs.authorizePersistedLocalTool(
      this.runs.get(action.runId),
      action,
      AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
    );
    if (!authorized.allowed) {
      throw new LocalProcessToolExecutionError(authorized.code, authorized.humanMessage);
    }
    const contract = this.options.database.prepare(`
      SELECT mc.contract_hash, mc.state, r.contract_hash_bound, r.contract_version_bound,
        mc.version, r.contract_id
      FROM runs r JOIN mission_contracts mc
        ON mc.id = r.contract_id AND mc.mission_id = r.mission_id
      WHERE r.id = ? AND r.mission_id = ?
    `).get(action.runId, action.missionId) as {
      readonly contract_hash: string;
      readonly state: string;
      readonly contract_hash_bound: string | null;
      readonly contract_version_bound: number | null;
      readonly version: number;
      readonly contract_id: string | null;
    } | undefined;
    const scope = this.options.database.prepare(`
      SELECT disposition, normalized_target FROM mission_targets
      WHERE mission_id = ? ORDER BY created_at, id
    `).all(action.missionId) as Array<{
      readonly disposition: "allowed" | "prohibited";
      readonly normalized_target: string;
    }>;
    const allowed = scope.filter(({ disposition }) => disposition === "allowed");
    if (!contract || contract.state !== "confirmed" || !action.contractId
      || contract.contract_id !== action.contractId
      || contract.contract_hash !== contract.contract_hash_bound
      || contract.version !== contract.contract_version_bound
      || allowed.length !== 1 || canonicalIp(allowed[0]!.normalized_target) !== target
      || scope.some(({ disposition, normalized_target }) =>
        disposition === "prohibited" && (() => {
          try { return canonicalIp(normalized_target) === target; } catch { return false; }
        })())) {
      throw new LocalProcessToolExecutionError(
        "full_tcp_scope_or_contract_changed",
        "The confirmed contract or exact single-IP mission scope changed before Full-TCP dispatch.",
      );
    }
    return {
      action,
      lease,
      contractHash: contract.contract_hash,
      prohibitedTargets: Object.freeze(scope
        .filter(({ disposition }) => disposition === "prohibited")
        .map(({ normalized_target }) => normalized_target)),
    };
  }

  async dispatch(input: DurableAction, signal: AbortSignal): Promise<void> {
    if (!this.resultSink) {
      throw new LocalProcessToolExecutionError(
        "result_sink_unbound",
        "Mission runtime result delivery must be bound before Full-TCP execution.",
      );
    }
    const canonical = this.canonical(input);
    const invocationId = autonomousFullTcpCompositeToolCallId(canonical.action.id);
    const now = this.now();
    const existing = this.options.database.prepare("SELECT status FROM tool_calls WHERE id = ?")
      .get(invocationId) as { readonly status: string } | undefined;
    if (existing) {
      throw new LocalProcessToolExecutionError(
        "duplicate_invocation",
        "This exact Full-TCP composite action already has a durable tool-call receipt.",
      );
    }
    this.options.database.prepare(`
      INSERT INTO tool_calls (
        id, action_id, provider, tool_name, mcp_server_id,
        normalized_arguments_json, status, started_at, created_at
      ) VALUES (?, ?, 'reviewed-local-process', ?, NULL, ?, 'running', ?, ?)
    `).run(
      invocationId,
      canonical.action.id,
      AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
      digestCanonicalJson({
        schemaVersion: "ti-scale.autonomous-full-tcp-composite-invocation.v1",
        target: canonical.action.target,
        logicalWorkspace: this.options.configuration.logicalWorkspace,
        manifestSha256: this.options.manifest.descriptor.manifestSha256,
        phaseToolIds: [
          AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
          AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
        ],
      }, { maxBytes: 128 * 1_024, maxDepth: 16 }).canonicalJson,
      now.toISOString(),
      now.toISOString(),
    );
    try {
      await this.executor.readiness(now);
      // The target-free readiness read may await filesystem inspection; re-run
      // the complete canonical query and owner fence at the last pre-contact boundary.
      const current = this.canonical(canonical.action);
      const authorization = createAutonomousFullTcpAuthorizationReceipt({
        missionId: current.action.missionId,
        runId: current.action.runId,
        contractId: current.action.contractId!,
        contractHash: current.contractHash,
        exactAllowedTargets: [current.action.target],
        prohibitedTargets: current.prohibitedTargets,
        issuedAt: this.now().toISOString(),
        expiresAt: current.lease.expiresAt,
      });
      const result = await this.executor.execute({ action: current.action, authorization }, signal);
      const promotion = await this.verifier.process(result);
      const payload: CompositeTerminalPayload = {
        schemaVersion: AUTONOMOUS_FULL_TCP_RESULT_DELIVERY_SCHEMA_VERSION,
        resultSha256: result.resultSha256,
        logRecordId: promotion.logRecordId,
        observationId: promotion.observationId,
        evidenceIds: promotion.evidenceIds,
        deliveryResult: promotion.executionResult,
        resultAccepted: false,
        duplicateResult: false,
        deliveryAttemptCount: 0,
        deliveryLastAttemptAt: null,
        deliveryLastError: null,
      };
      const changed = this.options.database.prepare(`
        UPDATE tool_calls SET status = 'succeeded', error_category = NULL,
          latency_ms = ?, output_summary = ?, redacted_payload_json = ?, ended_at = ?
        WHERE id = ? AND status = 'running'
      `).run(
        result.wallClockMs,
        promotion.executionResult.summary,
        JSON.stringify(payload),
        this.now().toISOString(),
        invocationId,
      ).changes;
      if (changed !== 1) {
        throw new LocalProcessToolExecutionError(
          "full_tcp_terminal_receipt_conflict",
          "The Full-TCP tool-call receipt changed before terminal evidence delivery.",
        );
      }
      await this.deliver(invocationId);
    } catch (error) {
      const boundaryError = error instanceof LocalProcessToolExecutionError
        ? error
        : new LocalProcessToolExecutionError(
            typeof (error as { readonly code?: unknown })?.code === "string"
              ? (error as { readonly code: string }).code
              : "full_tcp_composite_failed",
            error instanceof Error ? error.message : "Full-TCP composite execution failed.",
          );
      const terminal = failedExecutionResult({
        action: canonical.action,
        // Preserve the more precise composite/verifier error for category and
        // diagnosis, while retaining the normalized boundary error code when
        // an untyped exception crossed this adapter.
        error: error instanceof Error ? error : boundaryError,
        wallClockMs: this.now().getTime() - now.getTime(),
      });
      const payload: CompositeTerminalPayload = {
        schemaVersion: AUTONOMOUS_FULL_TCP_RESULT_DELIVERY_SCHEMA_VERSION,
        resultSha256: null,
        logRecordId: null,
        observationId: null,
        evidenceIds: [],
        deliveryResult: terminal,
        resultAccepted: false,
        duplicateResult: false,
        deliveryAttemptCount: 0,
        deliveryLastAttemptAt: null,
        deliveryLastError: null,
      };
      const toolStatus = terminal.failureCategory === "timeout" ? "timed_out" : "failed";
      const changed = this.options.database.prepare(`
        UPDATE tool_calls SET status = ?, error_category = ?, latency_ms = ?,
          output_summary = ?, redacted_payload_json = ?, ended_at = ?
        WHERE id = ? AND status = 'running'
      `).run(
        toolStatus,
        terminal.failureCategory ?? "unknown",
        terminal.usage?.wallClockMs ?? 0,
        terminal.summary,
        JSON.stringify(payload),
        this.now().toISOString(),
        invocationId,
      ).changes;
      if (changed === 1) {
        // Failure delivery uses the same durable acknowledgement/replay path
        // as success. A lost acknowledgement can no longer erase terminal
        // tool truth or strand the action behind a running receipt.
        await this.deliver(invocationId);
        return;
      }
      const concurrent = this.options.database.prepare(
        "SELECT status FROM tool_calls WHERE id = ?",
      ).get(invocationId) as { readonly status: string } | undefined;
      if (concurrent && ["cancelled", "failed", "timed_out", "succeeded"].includes(concurrent.status)) {
        return;
      }
      throw boundaryError;
    }
  }

  async resume(_action: DurableAction, _signal: AbortSignal): Promise<void> {
    throw new LocalProcessToolExecutionError(
      "full_tcp_resume_requires_new_attempt",
      "A recovered Full-TCP process phase requires a new bounded action; target contact is never replayed.",
    );
  }

  async cancelRunPersisted(runId: string, reason: string): Promise<void> {
    this.options.database.prepare(`
      UPDATE tool_calls SET status = 'cancelled', error_category = NULL,
        output_summary = ?, ended_at = ?
      WHERE status = 'running' AND provider = 'reviewed-local-process'
        AND tool_name = ? AND action_id IN (SELECT id FROM actions WHERE run_id = ?)
    `).run(
      reason.slice(0, 1_000),
      this.now().toISOString(),
      AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
      runId,
    );
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    await this.executor.cancelRun(runId, reason);
    await this.cancelRunPersisted(runId, reason);
  }

  private pending(invocationId: string): PendingCompositeRow | undefined {
    return this.options.database.prepare(`
      SELECT tc.id AS invocation_id, tc.status AS tool_status, tc.redacted_payload_json,
        a.id AS action_id, a.run_id, a.fingerprint AS action_fingerprint
      FROM tool_calls tc JOIN actions a ON a.id = tc.action_id
      JOIN runs r ON r.id = a.run_id JOIN missions m ON m.id = r.mission_id
      WHERE tc.id = ? AND tc.provider = 'reviewed-local-process'
        AND tc.tool_name = ? AND tc.status IN ('succeeded', 'failed', 'timed_out')
        AND r.journey = 'autonomous' AND r.control_plane = 'ti_scale'
        AND m.control_plane = 'ti_scale' AND tc.redacted_payload_json IS NOT NULL
    `).get(invocationId, AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE) as PendingCompositeRow | undefined;
  }

  private recordDelivery(
    row: PendingCompositeRow,
    _payload: CompositeTerminalPayload,
    outcome: Readonly<{ accepted: boolean; duplicate: boolean; error: string | null }>,
  ): void {
    inImmediateTransaction(this.options.database, () => {
      const current = this.pending(row.invocation_id);
      const payload = current ? parsePayload(current.redacted_payload_json) : undefined;
      if (!payload || payload.resultAccepted) return;
      this.options.database.prepare(`
        UPDATE tool_calls SET redacted_payload_json = ?
        WHERE id = ? AND status IN ('succeeded', 'failed', 'timed_out') AND tool_name = ?
      `).run(JSON.stringify({
        ...payload,
        resultAccepted: outcome.accepted,
        duplicateResult: outcome.accepted ? outcome.duplicate : false,
        deliveryAttemptCount: payload.deliveryAttemptCount + 1,
        deliveryLastAttemptAt: this.now().toISOString(),
        deliveryLastError: outcome.error,
      }), row.invocation_id, AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE);
    });
  }

  private async deliver(invocationId: string): Promise<boolean> {
    const row = this.pending(invocationId);
    if (!row) return false;
    const payload = parsePayload(row.redacted_payload_json);
    if (!payload || payload.resultAccepted) return payload?.resultAccepted ?? false;
    const result = payload.deliveryResult;
    const terminalStatusMatches = result.success
      ? row.tool_status === "succeeded"
      : row.tool_status === "failed" || row.tool_status === "timed_out";
    if (result.actionId !== row.action_id || result.runId !== row.run_id
      || result.actionFingerprint !== row.action_fingerprint || !terminalStatusMatches
      || (result.success && (payload.resultSha256 === null
        || payload.logRecordId === null || payload.observationId === null))) {
      return false;
    }
    const sink = this.resultSink;
    if (!sink) return false;
    try {
      const resultReceipt: ExecutionResultReceipt = await sink.acceptExecutionResult(result);
      const accepted = resultReceipt.accepted
        && resultReceipt.actionId === row.action_id && resultReceipt.runId === row.run_id;
      this.recordDelivery(row, payload, {
        accepted,
        duplicate: accepted && resultReceipt.duplicate,
        error: accepted ? null : "runtime_result_receipt_rejected",
      });
      return accepted;
    } catch {
      this.recordDelivery(row, payload, {
        accepted: false,
        duplicate: false,
        error: "runtime_result_delivery_failed",
      });
      return false;
    }
  }

  async replayPendingResults(limit = 100): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new RangeError("Pending Full-TCP result replay limit must be 1 through 1000");
    }
    if (!this.resultSink) return 0;
    const rows = this.options.database.prepare(`
      SELECT tc.id AS invocation_id FROM tool_calls tc
      JOIN actions a ON a.id = tc.action_id JOIN runs r ON r.id = a.run_id
      JOIN missions m ON m.id = r.mission_id
      WHERE tc.provider = 'reviewed-local-process' AND tc.tool_name = ?
        AND tc.status IN ('succeeded', 'failed', 'timed_out') AND r.journey = 'autonomous'
        AND r.control_plane = 'ti_scale' AND m.control_plane = 'ti_scale'
        AND COALESCE(json_extract(tc.redacted_payload_json, '$.resultAccepted'), 0) = 0
      ORDER BY tc.ended_at, tc.id LIMIT ?
    `).all(AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE, limit) as Array<{
      readonly invocation_id: string;
    }>;
    let acknowledged = 0;
    for (const row of rows) if (await this.deliver(row.invocation_id)) acknowledged += 1;
    return acknowledged;
  }

  close(): void {
    this.executor.close();
  }
}

class AutonomousGeneralSafeReconExecutionPort implements ResultAwareExecutionPort {
  private standardUnbind?: () => void;
  private fullTcpUnbind?: () => void;
  private webUnbind?: () => void;
  private cveUnbind?: () => void;
  private vulnerabilityUnbind?: () => void;

  constructor(
    private readonly standard: ResultAwareExecutionPort,
    private readonly fullTcp: AutonomousFullTcpResultAwarePort,
    private readonly web: AutonomousWebSurfaceResultAwarePort | undefined,
    private readonly cve: AutonomousCveApplicabilityResultAwarePort | undefined,
    private readonly vulnerability: AutonomousVulnerabilityResultAwarePort | undefined,
    private readonly router: GeneralSafeReconProcessRouter,
  ) {}

  bindResultSink(sink: ExecutionResultSink): () => void {
    this.standardUnbind = this.standard.bindResultSink?.(sink) as (() => void) | undefined;
    this.fullTcpUnbind = this.fullTcp.bindResultSink(sink);
    this.webUnbind = this.web?.bindResultSink(sink);
    this.cveUnbind = this.cve?.bindResultSink(sink);
    this.vulnerabilityUnbind = this.vulnerability?.bindResultSink(sink);
    return () => {
      this.standardUnbind?.();
      this.standardUnbind = undefined;
      this.fullTcpUnbind?.();
      this.fullTcpUnbind = undefined;
      this.webUnbind?.();
      this.webUnbind = undefined;
      this.cveUnbind?.();
      this.cveUnbind = undefined;
      this.vulnerabilityUnbind?.();
      this.vulnerabilityUnbind = undefined;
    };
  }

  dispatch(action: DurableAction, signal: AbortSignal): Promise<void> {
    if (action.actionType === AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE) {
      return this.fullTcp.dispatch(action, signal);
    }
    if (action.actionType === AUTONOMOUS_HTTP_METADATA_ACTION_TYPE
      || action.actionType === AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE
      || action.actionType === AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE) {
      if (!this.web) {
        throw new LocalProcessToolExecutionError(
          "autonomous_web_runtime_not_configured",
          "This run did not activate the reviewed Autonomous web continuation.",
        );
      }
      return this.web.dispatch(action, signal);
    }
    if (action.actionType === AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE) {
      if (!this.cve) throw new LocalProcessToolExecutionError(
        "autonomous_cve_runtime_not_configured",
        "This run did not activate the reviewed Autonomous CVE applicability continuation.",
      );
      return this.cve.dispatch(action, signal);
    }
    if (action.actionType === AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE) {
      if (!this.vulnerability) throw new LocalProcessToolExecutionError(
        "autonomous_vulnerability_runtime_not_configured",
        "This run did not activate the reviewed bounded vulnerability assessment.",
      );
      return this.vulnerability.dispatch(action, signal);
    }
    return this.standard.dispatch(action, signal);
  }

  resume(action: DurableAction, signal: AbortSignal): Promise<void> {
    if (action.actionType === AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE) {
      return this.fullTcp.resume(action, signal);
    }
    if (action.actionType === AUTONOMOUS_HTTP_METADATA_ACTION_TYPE
      || action.actionType === AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE
      || action.actionType === AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE) {
      if (!this.web) {
        throw new LocalProcessToolExecutionError(
          "autonomous_web_runtime_not_configured",
          "This run did not activate the reviewed Autonomous web continuation.",
        );
      }
      return this.web.resume(action, signal);
    }
    if (action.actionType === AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE) {
      if (!this.cve) throw new LocalProcessToolExecutionError(
        "autonomous_cve_runtime_not_configured",
        "This run did not activate the reviewed Autonomous CVE applicability continuation.",
      );
      return this.cve.resume(action, signal);
    }
    if (action.actionType === AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE) {
      if (!this.vulnerability) throw new LocalProcessToolExecutionError(
        "autonomous_vulnerability_runtime_not_configured",
        "This run did not activate the reviewed bounded vulnerability assessment.",
      );
      return this.vulnerability.resume(action, signal);
    }
    return this.standard.resume(action, signal);
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    // One raw-adapter cancellation drains every channel. Persist each channel's
    // own canonical cancellation receipts without sending duplicate signals.
    await this.standard.cancelRun(runId, reason);
    await this.fullTcp.cancelRunPersisted(runId, reason);
    await this.web?.cancelRunPersisted(runId, reason);
    await this.cve?.cancelRun(runId, reason);
    await this.vulnerability?.cancelRunPersisted(runId, reason);
  }

  async replayPendingResults(limit = 100): Promise<number> {
    const [standard, fullTcp, web, cve, vulnerability] = await Promise.all([
      this.standard.replayPendingResults?.(limit) ?? 0,
      this.fullTcp.replayPendingResults(limit),
      this.web?.replayPendingResults(limit) ?? 0,
      this.cve?.replayPendingResults(limit) ?? 0,
      this.vulnerability?.replayPendingResults(limit) ?? 0,
    ]);
    return standard + fullTcp + web + cve + vulnerability;
  }

  close(): void {
    this.standardUnbind?.();
    this.fullTcpUnbind?.();
    this.webUnbind?.();
    this.cveUnbind?.();
    this.vulnerabilityUnbind?.();
    this.standardUnbind = undefined;
    this.fullTcpUnbind = undefined;
    this.webUnbind = undefined;
    this.cveUnbind = undefined;
    this.vulnerabilityUnbind = undefined;
    (this.standard as { close?: () => void }).close?.();
    this.fullTcp.close();
    this.web?.close();
    this.vulnerability?.close();
    this.router.close();
  }
}

export interface AutonomousGeneralSafeReconExecutionFactoryOptions {
  readonly manifest: LocalToolCapabilityManifest;
  readonly dnsConfiguration: AutonomousDnsSafeReconConfiguration;
  readonly ipConfiguration: AutonomousIpSafeReconConfiguration;
  readonly fullTcpConfiguration: AutonomousFullTcpPlanningConfiguration;
  readonly webSurfaceConfiguration?: AutonomousWebSurfacePlanningConfiguration;
  readonly cveApplicabilityConfiguration?: AutonomousCveApplicabilityConfiguration;
  readonly vulnerabilityAssessmentConfiguration?: AutonomousVulnerabilityAssessmentConfiguration;
  readonly cveCandidateCatalog?: AuthoritativeCveCandidateCatalogPort;
  readonly cveNvdEnrichment?: AutonomousCveCandidateEnrichmentPort<MissionScopedNvdDetailResult>;
  readonly brainContext?: BrainContextService;
  readonly adapter: ReviewedLocalProcessInvocationAdapter;
  readonly workspaceResolver: EngagementWorkspaceResolver;
  readonly now?: () => Date;
}

export class AutonomousGeneralSafeReconExecutionFactory {
  readonly localProcessContract = AUTONOMOUS_GENERAL_SAFE_RECON_EXECUTION_CONTRACT;
  #created = false;
  #port?: AutonomousGeneralSafeReconExecutionPort;

  constructor(private readonly options: AutonomousGeneralSafeReconExecutionFactoryOptions) {}

  create(input: Readonly<{
    database: SqliteDatabase;
    assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
  }>): ResultAwareExecutionPort {
    if (this.#created) throw new Error("Autonomous general Safe Recon execution factory is single-use");
    if (this.options.webSurfaceConfiguration && !this.options.brainContext) {
      throw new LocalProcessToolExecutionError(
        "autonomous_web_brain_context_required",
        "The reviewed Autonomous web continuation requires the core Brain Context service.",
      );
    }
    if (this.options.cveApplicabilityConfiguration
      && (!this.options.brainContext || !this.options.cveCandidateCatalog)) {
      throw new LocalProcessToolExecutionError(
        "autonomous_cve_dependencies_required",
        "The reviewed Autonomous CVE continuation requires the core Brain Context service and a pinned authoritative local candidate catalogue.",
      );
    }
    if (this.options.vulnerabilityAssessmentConfiguration
      && (!this.options.brainContext || !this.options.webSurfaceConfiguration)) {
      throw new LocalProcessToolExecutionError(
        "autonomous_vulnerability_dependencies_required",
        "The bounded vulnerability assessment requires the core Brain Context service and verified web continuation.",
      );
    }
    const router = new GeneralSafeReconProcessRouter(this.options.adapter);
    const standardFactory = new AutonomousLocalSafeReconExecutionFactory({
      manifest: this.options.manifest,
      dnsConfiguration: this.options.dnsConfiguration,
      ipConfiguration: this.options.ipConfiguration,
      adapter: router.standard,
      workspaceResolver: this.options.workspaceResolver,
      ...(this.options.now ? { now: this.options.now } : {}),
    });
    const standard = standardFactory.create(input);
    const fullTcp = new AutonomousFullTcpResultAwarePort({
      database: input.database,
      manifest: this.options.manifest,
      configuration: this.options.fullTcpConfiguration,
      adapter: router.fullTcp,
      workspaceResolver: this.options.workspaceResolver,
      assertControlPlaneAuthority: input.assertControlPlaneAuthority,
      ...(this.options.now ? { now: this.options.now } : {}),
    });
    const web = this.options.webSurfaceConfiguration && this.options.brainContext
      ? new AutonomousWebSurfaceResultAwarePort({
          database: input.database,
          manifest: this.options.manifest,
          configuration: this.options.webSurfaceConfiguration,
          adapter: router.web,
          workspaceResolver: this.options.workspaceResolver,
          brainContext: this.options.brainContext,
          assertControlPlaneAuthority: input.assertControlPlaneAuthority,
          ...(this.options.now ? { now: this.options.now } : {}),
        })
      : undefined;
    const cve = this.options.cveApplicabilityConfiguration
      && this.options.brainContext && this.options.cveCandidateCatalog
      ? new AutonomousCveApplicabilityResultAwarePort({
          database: input.database,
          configuration: this.options.cveApplicabilityConfiguration,
          catalog: this.options.cveCandidateCatalog,
          brainContext: this.options.brainContext,
          ...(this.options.cveNvdEnrichment
            ? { enrichment: this.options.cveNvdEnrichment } : {}),
          assertControlPlaneAuthority: input.assertControlPlaneAuthority,
          ...(this.options.now ? { now: this.options.now } : {}),
        })
      : undefined;
    const vulnerability = this.options.vulnerabilityAssessmentConfiguration
      && this.options.webSurfaceConfiguration && this.options.brainContext
      ? new AutonomousVulnerabilityResultAwarePort({
          database: input.database,
          manifest: this.options.manifest,
          webConfiguration: this.options.webSurfaceConfiguration,
          configuration: this.options.vulnerabilityAssessmentConfiguration,
          adapter: router.vulnerability,
          workspaceResolver: this.options.workspaceResolver,
          brainContext: this.options.brainContext,
          assertControlPlaneAuthority: input.assertControlPlaneAuthority,
          ...(this.options.now ? { now: this.options.now } : {}),
        })
      : undefined;
    this.#port = new AutonomousGeneralSafeReconExecutionPort(
      standard,
      fullTcp,
      web,
      cve,
      vulnerability,
      router,
    );
    this.#created = true;
    return this.#port;
  }

  close(): void {
    this.#port?.close();
    this.#port = undefined;
  }
}

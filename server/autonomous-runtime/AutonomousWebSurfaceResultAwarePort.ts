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
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  LocalProcessToolExecutionError,
  type LocalToolCapabilityManifest,
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
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS,
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  AUTONOMOUS_HTTP_METADATA_ACTION_CLASS,
  AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
  AUTONOMOUS_WHATWEB_ACTION_CLASS,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
  type AutonomousWebSurfacePlanningConfiguration,
} from "./AutonomousWebSurfaceBaseline";
import {
  AUTONOMOUS_WEB_RESULT_DELIVERY_SCHEMA_VERSION,
  AutonomousWebEvidenceVerifier,
  AutonomousWebEvidenceVerificationError,
} from "./AutonomousWebEvidenceVerifier";
import {
  AutonomousWebSurfaceExecution,
  type AutonomousWebSurfacePhase,
  type ReviewedAutonomousWebSurfaceInvocationAdapter,
} from "./AutonomousWebSurfaceExecution";
import { authorizeAutonomousDerivedWebOrigins } from "./AutonomousWebOriginAuthorization";
import {
  compileAutonomousWebPhaseMemoryGuard,
  inspectAutonomousWebPhaseMemoryEvidence,
} from "./AutonomousWebPhaseMemoryGuard";

interface TerminalPayload {
  readonly schemaVersion: typeof AUTONOMOUS_WEB_RESULT_DELIVERY_SCHEMA_VERSION;
  readonly resultSha256: string | null;
  readonly contextPackId: string | null;
  readonly memoryGuardReceiptId?: string | null;
  readonly memoryInfluenceAuditId?: string | null;
  readonly logRecordId: string | null;
  readonly observationId: string | null;
  readonly evidenceIds: readonly string[];
  readonly deliveryResult: ExecutionResult;
  readonly deliveryState: "pending" | "accepted" | "quarantined";
  readonly resultAccepted: boolean;
  readonly duplicateResult: boolean;
  readonly deliveryAttemptCount: number;
  readonly deliveryLastAttemptAt: string | null;
  readonly deliveryLastError: string | null;
  readonly deliveryQuarantineReason: string | null;
}

interface QuarantinedDeliveryPayload {
  readonly schemaVersion: typeof AUTONOMOUS_WEB_RESULT_DELIVERY_SCHEMA_VERSION;
  readonly deliveryState: "quarantined";
  readonly resultAccepted: false;
  readonly duplicateResult: false;
  readonly deliveryAttemptCount: number;
  readonly deliveryLastAttemptAt: string;
  readonly deliveryLastError: string;
  readonly deliveryQuarantineReason: string;
  readonly originalPayloadSha256: string;
}

const AUTONOMOUS_WEB_DELIVERY_ATTEMPT_LIMIT = 3;

interface PendingRow {
  readonly invocation_id: string;
  readonly tool_status: "succeeded" | "failed" | "timed_out";
  readonly redacted_payload_json: string;
  readonly action_id: string;
  readonly run_id: string;
  readonly action_fingerprint: string;
  readonly mission_id: string;
  readonly step_id: string | null;
}

function canonicalIp(value: string): string {
  if (value !== value.trim() || isIP(value) === 0) {
    throw new LocalProcessToolExecutionError(
      "autonomous_web_ip_required",
      "The Autonomous web continuation accepts only one exact canonical IP parent target.",
    );
  }
  const hostname = new URL(`http://${isIP(value) === 6 ? `[${value}]` : value}/`).hostname;
  const normalized = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
  if (normalized !== value.toLowerCase()) {
    throw new LocalProcessToolExecutionError(
      "autonomous_web_ip_not_canonical",
      "The Autonomous web continuation requires the canonical mission IP spelling.",
    );
  }
  return normalized;
}

export function autonomousWebCompositeToolCallId(actionId: string): string {
  return `web_composite_${createHash("sha256").update(actionId).digest("hex").slice(0, 40)}`;
}

function phaseFor(action: DurableAction): AutonomousWebSurfacePhase {
  if (action.actionType === AUTONOMOUS_HTTP_METADATA_ACTION_TYPE
    && action.actionClass === AUTONOMOUS_HTTP_METADATA_ACTION_CLASS) return "http_metadata";
  if (action.actionType === AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE
    && action.actionClass === AUTONOMOUS_WHATWEB_ACTION_CLASS) return "whatweb_fingerprint";
  if (action.actionType === AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE
    && action.actionClass === AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS) {
    return "endpoint_discovery";
  }
  throw new LocalProcessToolExecutionError(
    "autonomous_web_action_type_invalid",
    "The action is not one of the reviewed Autonomous web-surface phases.",
  );
}

function parsePayload(value: string): TerminalPayload | undefined {
  try {
    const item = JSON.parse(value) as Partial<TerminalPayload>;
    if (!item || typeof item !== "object" || Array.isArray(item)
      || item.schemaVersion !== AUTONOMOUS_WEB_RESULT_DELIVERY_SCHEMA_VERSION
      || !item.deliveryResult || typeof item.deliveryResult !== "object"
      || !Array.isArray(item.evidenceIds)
      || !["pending", "accepted", "quarantined"].includes(item.deliveryState ?? "")
      || typeof item.resultAccepted !== "boolean"
      || typeof item.duplicateResult !== "boolean"
      || !Number.isSafeInteger(item.deliveryAttemptCount)
      || (item.deliveryAttemptCount ?? -1) < 0
      || (item.deliveryAttemptCount ?? 0) > AUTONOMOUS_WEB_DELIVERY_ATTEMPT_LIMIT
      || (item.deliveryState === "accepted" && item.resultAccepted !== true)
      || (item.deliveryState !== "accepted" && item.resultAccepted !== false)
      || (item.deliveryState === "quarantined"
        && typeof item.deliveryQuarantineReason !== "string")) return undefined;
    return item as TerminalPayload;
  } catch {
    return undefined;
  }
}

function failureCode(error: unknown): string {
  const code = typeof (error as { readonly code?: unknown })?.code === "string"
    ? (error as { readonly code: string }).code : "autonomous_web_phase_failed";
  return /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$/u.test(code)
    ? code : "autonomous_web_phase_failed";
}

function failureCategory(error: unknown, code: string): FailureCategory {
  if (error instanceof ExecutionBoundaryError) return error.failureCategory;
  if (/cancel/iu.test(code)) return "operator_rejection";
  if (/timeout|timed_out/iu.test(code)) return "timeout";
  if (/transient[_-]?network/iu.test(code)) return "transient_network";
  if (/scope|origin|target/iu.test(code)) return "scope_conflict";
  if (/authorization/iu.test(code)) return "authorization_denied";
  if (/hazard|unsafe/iu.test(code)) return "policy_denied";
  if (/context|brain|memory|workspace|dependency|executable|sink/iu.test(code)) return "dependency_missing";
  if (/evidence|source|proof|parse|integrity|fingerprint|status/iu.test(code)
    || error instanceof AutonomousWebEvidenceVerificationError) return "evidence_insufficient";
  if (/contract|policy|binding|canonical/iu.test(code)) return "policy_denied";
  return "deterministic_tool_error";
}

function failedResult(action: DurableAction, error: unknown, wallClockMs: number): ExecutionResult {
  const code = failureCode(error);
  const category = failureCategory(error, code);
  const detail = (error instanceof Error ? error.message : "The Autonomous web phase failed.")
    .replace(/[\u0000-\u001F\u007F]/gu, " ").trim().replace(/\s+/gu, " ").slice(0, 700);
  return Object.freeze({
    actionId: action.id,
    runId: action.runId,
    actionFingerprint: action.fingerprint,
    success: false,
    summary: `The web continuation failed safely. ${detail} No web outcome was claimed.`,
    progress: Object.freeze({}),
    failure: Object.freeze({ source: "tool" as const, code, message: detail }),
    failureCategory: category,
    circuitKey: `autonomous-web:${action.actionType}`,
    usage: Object.freeze({ wallClockMs: Math.max(0, Math.round(wallClockMs)) }),
  });
}

export class AutonomousWebSurfaceResultAwarePort implements ResultAwareExecutionPort {
  private readonly actions: ActionRepository;
  private readonly runs: RunRepository;
  private readonly executor: AutonomousWebSurfaceExecution;
  private readonly verifier: AutonomousWebEvidenceVerifier;
  private readonly now: () => Date;
  private resultSink?: ExecutionResultSink;

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    manifest: LocalToolCapabilityManifest;
    configuration: AutonomousWebSurfacePlanningConfiguration;
    adapter: ReviewedAutonomousWebSurfaceInvocationAdapter;
    workspaceResolver: EngagementWorkspaceResolver;
    brainContext: BrainContextService;
    assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
    now?: () => Date;
  }>) {
    this.actions = new ActionRepository(options.database);
    this.runs = new RunRepository(options.database);
    this.now = options.now ?? (() => new Date());
    this.executor = new AutonomousWebSurfaceExecution({
      database: options.database,
      manifest: options.manifest,
      configuration: options.configuration,
      adapter: options.adapter,
      workspaceResolver: options.workspaceResolver,
      assertOriginAuthority: ({ action, authorization, origin, originIndex }) => {
        const current = this.canonical(action);
        const proof = authorizeAutonomousDerivedWebOrigins(
          options.database,
          current.action,
          options.configuration,
          current.phase,
        );
        if (proof.authorizationSha256 !== authorization.authorizationSha256
          || proof.origins[originIndex] !== origin) {
          throw new LocalProcessToolExecutionError(
            "autonomous_web_origin_authority_changed",
            "The canonical lease, contract, source evidence, or derived origin changed before contact.",
          );
        }
        return proof;
      },
      ...(options.now ? { now: options.now } : {}),
    });
    this.verifier = new AutonomousWebEvidenceVerifier({
      database: options.database,
      manifest: options.manifest,
      configuration: options.configuration,
      assertCanonicalAuthority: (action) => { void this.canonical(action); },
      ...(options.now ? { now: options.now } : {}),
    });
  }

  bindResultSink(sink: ExecutionResultSink): () => void {
    if (this.resultSink) throw new Error("Autonomous web result sink is already bound");
    this.resultSink = sink;
    return () => { if (this.resultSink === sink) this.resultSink = undefined; };
  }

  private canonical(input: DurableAction): Readonly<{
    action: DurableAction;
    phase: AutonomousWebSurfacePhase;
    lease: ControlPlaneLease;
    memoryPolicy: Readonly<Record<string, unknown>>;
  }> {
    const action = this.actions.get(input.id);
    if (digestCanonicalJson(action, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      !== digestCanonicalJson(input, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      || action.status !== "running") {
      throw new LocalProcessToolExecutionError(
        "autonomous_web_action_not_canonical",
        "Only the exact canonical running web action may enter derived-origin execution.",
      );
    }
    const phase = phaseFor(action);
    const target = canonicalIp(action.target);
    const envelope = reviewedLocalToolActionEnvelope(action.arguments);
    if (!envelope || envelope.toolId !== action.actionType
      || Object.keys(envelope.parameters).sort().join("\u0000") !== "target\u0000workspace"
      || envelope.parameters.target !== target
      || envelope.parameters.workspace !== this.options.configuration.logicalWorkspace) {
      throw new LocalProcessToolExecutionError(
        "autonomous_web_action_binding_invalid",
        "The parent action does not carry the exact reviewed derived-origin envelope.",
      );
    }
    const lease = this.options.assertControlPlaneAuthority(action.runId);
    const authorized = this.runs.authorizePersistedLocalTool(
      this.runs.get(action.runId), action, action.actionType,
    );
    if (!authorized.allowed) {
      throw new LocalProcessToolExecutionError(authorized.code, authorized.humanMessage);
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
      readonly contract_hash: string;
      readonly state: string;
      readonly version: number;
      readonly action_policy_json: string;
      readonly memory_scopes_json: string;
      readonly contract_hash_bound: string | null;
      readonly contract_version_bound: number | null;
      readonly contract_id: string | null;
      readonly success_criteria_json: string;
      readonly memory_policy_json: string;
      readonly assigned_agent_id: string | null;
      readonly assignment_agent_id: string;
    } | undefined;
    const scope = this.options.database.prepare(`
      SELECT disposition, normalized_target FROM mission_targets
      WHERE mission_id = ? ORDER BY created_at, id
    `).all(action.missionId) as Array<{
      readonly disposition: "allowed" | "prohibited";
      readonly normalized_target: string;
    }>;
    const allowed = scope.filter(({ disposition }) => disposition === "allowed");
    let policy: Record<string, unknown> = {};
    let criteria: unknown[] = [];
    let memoryScopes: unknown[] = [];
    let missionMemoryPolicy: Record<string, unknown> = {};
    try {
      policy = JSON.parse(row?.action_policy_json ?? "null") as Record<string, unknown>;
      criteria = JSON.parse(row?.success_criteria_json ?? "null") as unknown[];
      memoryScopes = JSON.parse(row?.memory_scopes_json ?? "null") as unknown[];
      missionMemoryPolicy = JSON.parse(row?.memory_policy_json ?? "null") as Record<string, unknown>;
    } catch {
      // The exact checks below fail closed.
    }
    const expectedCriterion = phase === "http_metadata"
      ? this.options.configuration.httpMetadataSuccessCriterion
      : phase === "whatweb_fingerprint"
        ? this.options.configuration.whatwebSuccessCriterion
        : this.options.configuration.endpointDiscoverySuccessCriterion;
    const allowedClasses = Array.isArray(policy.allowedActionClasses)
      ? policy.allowedActionClasses : [];
    const prohibitedClasses = Array.isArray(policy.prohibitedActionClasses)
      ? policy.prohibitedActionClasses : [];
    const specialists = Array.isArray(policy.specialistAgentIds)
      ? policy.specialistAgentIds : [];
    if (!row || row.state !== "confirmed" || row.contract_id !== action.contractId
      || row.contract_hash !== row.contract_hash_bound
      || row.version !== row.contract_version_bound
      || allowed.length !== 1 || canonicalIp(allowed[0]!.normalized_target) !== target
      || scope.some(({ disposition, normalized_target }) => disposition === "prohibited"
        && normalized_target === target)
      || !allowedClasses.includes(action.actionClass)
      || prohibitedClasses.includes(action.actionClass)
      || !canonicalProductOwnerBindsRuntimeAgent(
        this.options.database,
        {
          actionClassId: action.actionClass,
          planAgentId: row.assigned_agent_id,
          assignmentAgentId: row.assignment_agent_id,
          signedSpecialistAgentIds: specialists,
          runtimeAgentId: this.options.configuration.agentId,
        },
      )
      || typeof expectedCriterion !== "string"
      || !criteria.includes(expectedCriterion)
      || !missionMemoryPolicy || typeof missionMemoryPolicy !== "object"
      || Array.isArray(missionMemoryPolicy)
      || !Array.isArray(missionMemoryPolicy.exactContextNodeIds)
      || !Array.isArray(missionMemoryPolicy.allowedScopes)
      || !Array.isArray(memoryScopes)) {
      throw new LocalProcessToolExecutionError(
        "autonomous_web_scope_or_contract_changed",
        "The confirmed contract, exact IP scope, action class, specialist, or measurable web criterion changed before dispatch.",
      );
    }
    const selections = this.options.database.prepare(`
      SELECT node_id, selection_type FROM run_context_selections
      WHERE run_id = ? ORDER BY selected_at, id
    `).all(action.runId) as Array<{
      readonly node_id: string;
      readonly selection_type: string;
    }>;
    if (selections.some(({ selection_type }) => selection_type !== "verified_lesson")) {
      throw new LocalProcessToolExecutionError(
        "autonomous_web_memory_selection_invalid",
        "The run contains an unsupported immutable memory selection type.",
      );
    }
    const allowedScopes = Object.freeze(memoryScopes.filter(
      (value): value is string => typeof value === "string" && value.trim().length > 0,
    ));
    if (selections.length > 0 && !allowedScopes.includes("verified_lessons")) {
      throw new LocalProcessToolExecutionError(
        "autonomous_web_memory_selection_outside_contract",
        "The immutable verified-lesson selection is outside the signed contract memory scopes.",
      );
    }
    return {
      action,
      phase,
      lease,
      memoryPolicy: Object.freeze({
        ...missionMemoryPolicy,
        allowedScopes,
        exactContextNodeIds: Object.freeze(selections.length > 0
          ? selections.map(({ node_id }) => node_id)
          : (missionMemoryPolicy.exactContextNodeIds as unknown[]).filter(
              (value): value is string => typeof value === "string" && value.trim().length > 0,
            )),
      }),
    };
  }

  private webContext(
    action: DurableAction,
    phase: AutonomousWebSurfacePhase,
    sourceEvidenceIds: readonly string[],
    technologySignals: readonly string[],
    memoryPolicy: Readonly<Record<string, unknown>>,
  ): BrainContextResult {
    const context = retrieveMissionBrainContext({
      brainContext: this.options.brainContext,
      hook: "phase_transition",
      journey: "autonomous",
      missionId: action.missionId,
      runId: action.runId,
      stepId: action.stepId,
      actionId: action.id,
      actorId: this.options.configuration.agentId,
      actorType: "agent",
      query: `Prepare the ${phase} phase for exact in-scope target ${action.target}. Use verified source evidence ${sourceEvidenceIds.join(", ") || "none"} and detected technology/version signals ${technologySignals.join(" | ") || "none"} to retrieve only relevant confirmed technology, failure, operational-hazard, recovery, and lesson memory.`,
      queryRedacted: "Prepare an evidence-derived read-only web phase using relevant confirmed technology and failure/recovery memory.",
      memoryPolicy,
      maximumSensitivity: "private",
      contextBudget: 4_000,
      limit: 12,
    });
    return context;
  }

  async dispatch(input: DurableAction, signal: AbortSignal): Promise<void> {
    if (!this.resultSink) {
      throw new LocalProcessToolExecutionError(
        "result_sink_unbound",
        "Mission runtime result delivery must be bound before Autonomous web execution.",
      );
    }
    const canonical = this.canonical(input);
    const invocationId = autonomousWebCompositeToolCallId(canonical.action.id);
    const started = this.now();
    const existing = this.options.database.prepare("SELECT status FROM tool_calls WHERE id = ?")
      .get(invocationId) as { readonly status: string } | undefined;
    if (existing) {
      throw new LocalProcessToolExecutionError(
        "duplicate_invocation",
        "This exact Autonomous web action already has a durable composite receipt.",
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
      canonical.action.actionType,
      digestCanonicalJson({
        schemaVersion: "ti-scale.autonomous-web-composite-invocation.v1",
        phase: canonical.phase,
        parentTarget: canonical.action.target,
        logicalWorkspace: this.options.configuration.logicalWorkspace,
        manifestSha256: this.options.manifest.descriptor.manifestSha256,
      }, { maxBytes: 64 * 1_024, maxDepth: 12 }).canonicalJson,
      started.toISOString(),
      started.toISOString(),
    );
    let contextPackId: string | null = null;
    let memoryGuardReceiptId: string | null = null;
    let memoryInfluenceAuditId: string | null = null;
    try {
      // Inspect only the preceding immutable fingerprint. No origin is
      // derived or authorized until the typed memory guard has completed.
      const memoryEvidence = inspectAutonomousWebPhaseMemoryEvidence(
        this.options.database,
        canonical.action,
        canonical.phase,
      );
      const context = this.webContext(
        canonical.action,
        canonical.phase,
        memoryEvidence.sourceEvidenceIds,
        memoryEvidence.technologySignals,
        canonical.memoryPolicy,
      );
      contextPackId = context.contextPack.id;
      const memoryGuard = compileAutonomousWebPhaseMemoryGuard({
        database: this.options.database,
        action: canonical.action,
        phase: canonical.phase,
        context,
        evidence: memoryEvidence,
        now: this.now(),
      });
      memoryGuardReceiptId = memoryGuard.receiptId;
      memoryInfluenceAuditId = memoryGuard.influenceAuditRecordId;
      if (memoryGuard.usedNodeIds.length > 0) {
        this.options.brainContext.recordContextUse(
          context,
          memoryGuard.usedNodeIds,
          "Verified technology/version and operational-hazard memory stopped bounded endpoint discovery before origin authorization.",
          "The retrieved item was not part of the exact verified technology/hazard match used by this phase.",
        );
      } else {
        this.options.brainContext.recordUnusedContext(
          context,
          memoryGuard.reasonCode === "no_relevant_memory"
            ? "No relevant eligible memory was available, so the phase retained its fixed conservative behavior."
            : "Retrieved memory did not form an exact verified technology/version hang-or-crash hazard match and did not influence the phase.",
        );
      }
      if (memoryGuard.decision === "block_endpoint_discovery") {
        throw new ExecutionBoundaryError(
          "autonomous_endpoint_discovery_blocked_by_verified_hazard",
          "policy_denied",
          "Endpoint discovery was stopped before target contact because verified memory links this exact detected technology and version to a reproducible hang or crash hazard. Review the linked recovery memory or amend the plan; no FFUF process was dispatched.",
        );
      }
      // Brain retrieval may perform local indexed reads. Recheck the complete
      // authority and evidence derivation immediately before target contact.
      const current = this.canonical(canonical.action);
      if (current.lease.leaseOwner !== canonical.lease.leaseOwner) {
        throw new LocalProcessToolExecutionError(
          "autonomous_web_owner_fence_changed",
          "The run owner changed before the derived web origin was contacted.",
        );
      }
      const authorization = authorizeAutonomousDerivedWebOrigins(
        this.options.database,
        current.action,
        this.options.configuration,
        current.phase,
      );
      const result = await this.executor.execute({
        action: current.action,
        authorization,
        contextPackId,
      }, signal);
      this.verifier.process(result, (committed) => {
        const payload: TerminalPayload = {
          schemaVersion: AUTONOMOUS_WEB_RESULT_DELIVERY_SCHEMA_VERSION,
          resultSha256: result.resultSha256,
          contextPackId,
          memoryGuardReceiptId,
          memoryInfluenceAuditId,
          logRecordId: committed.logRecordId,
          observationId: committed.observationId,
          evidenceIds: committed.evidenceIds,
          deliveryResult: committed.executionResult,
          deliveryState: "pending",
          resultAccepted: false,
          duplicateResult: false,
          deliveryAttemptCount: 0,
          deliveryLastAttemptAt: null,
          deliveryLastError: null,
          deliveryQuarantineReason: null,
        };
        const changed = this.options.database.prepare(`
          UPDATE tool_calls SET status = 'succeeded', error_category = NULL,
            latency_ms = ?, output_summary = ?, redacted_payload_json = ?, ended_at = ?
          WHERE id = ? AND status = 'running'
        `).run(
          result.wallClockMs,
          committed.executionResult.summary,
          JSON.stringify(payload),
          this.now().toISOString(),
          invocationId,
        ).changes;
        if (changed !== 1) {
          throw new LocalProcessToolExecutionError(
            "autonomous_web_terminal_receipt_conflict",
            "The web tool-call receipt changed before the atomic evidence commit.",
          );
        }
      });
      await this.deliver(invocationId);
    } catch (error) {
      const terminal = failedResult(
        canonical.action,
        error,
        this.now().getTime() - started.getTime(),
      );
      const payload: TerminalPayload = {
        schemaVersion: AUTONOMOUS_WEB_RESULT_DELIVERY_SCHEMA_VERSION,
        resultSha256: null,
        contextPackId,
        memoryGuardReceiptId,
        memoryInfluenceAuditId,
        logRecordId: null,
        observationId: null,
        evidenceIds: [],
        deliveryResult: terminal,
        deliveryState: "pending",
        resultAccepted: false,
        duplicateResult: false,
        deliveryAttemptCount: 0,
        deliveryLastAttemptAt: null,
        deliveryLastError: null,
        deliveryQuarantineReason: null,
      };
      const changed = this.options.database.prepare(`
        UPDATE tool_calls SET status = ?, error_category = ?, latency_ms = ?,
          output_summary = ?, redacted_payload_json = ?, ended_at = ?
        WHERE id = ? AND status = 'running'
      `).run(
        terminal.failureCategory === "timeout" ? "timed_out" : "failed",
        terminal.failureCategory ?? "unknown",
        terminal.usage?.wallClockMs ?? 0,
        terminal.summary,
        JSON.stringify(payload),
        this.now().toISOString(),
        invocationId,
      ).changes;
      if (changed === 1) {
        await this.deliver(invocationId);
        return;
      }
      const current = this.options.database.prepare("SELECT status FROM tool_calls WHERE id = ?")
        .get(invocationId) as { readonly status: string } | undefined;
      if (current && ["cancelled", "failed", "timed_out", "succeeded"].includes(current.status)) return;
      throw error;
    }
  }

  async resume(_action: DurableAction, _signal: AbortSignal): Promise<void> {
    throw new LocalProcessToolExecutionError(
      "autonomous_web_resume_requires_new_attempt",
      "A recovered web process phase requires a new bounded action; target contact is never replayed.",
    );
  }

  async cancelRunPersisted(runId: string, reason: string): Promise<void> {
    this.options.database.prepare(`
      UPDATE tool_calls SET status = 'cancelled', error_category = NULL,
        output_summary = ?, ended_at = ?
      WHERE status = 'running' AND provider = 'reviewed-local-process'
        AND tool_name IN (?, ?, ?) AND action_id IN (SELECT id FROM actions WHERE run_id = ?)
    `).run(
      reason.slice(0, 1_000), this.now().toISOString(),
      AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
      AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
      AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
      runId,
    );
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    await this.executor.cancelRun(runId, reason);
    await this.cancelRunPersisted(runId, reason);
  }

  private pending(invocationId: string): PendingRow | undefined {
    return this.options.database.prepare(`
      SELECT tc.id AS invocation_id, tc.status AS tool_status, tc.redacted_payload_json,
        a.id AS action_id, a.run_id, a.mission_id, a.step_id,
        a.fingerprint AS action_fingerprint
      FROM tool_calls tc JOIN actions a ON a.id = tc.action_id
      JOIN runs r ON r.id = a.run_id JOIN missions m ON m.id = r.mission_id
      WHERE tc.id = ? AND tc.provider = 'reviewed-local-process'
        AND tc.tool_name IN (?, ?, ?) AND tc.status IN ('succeeded', 'failed', 'timed_out')
        AND r.journey = 'autonomous' AND r.control_plane = 'ti_scale'
        AND m.control_plane = 'ti_scale' AND tc.redacted_payload_json IS NOT NULL
    `).get(
      invocationId,
      AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
      AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
      AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
    ) as PendingRow | undefined;
  }

  private recordDelivery(row: PendingRow, outcome: Readonly<{
    accepted: boolean;
    duplicate: boolean;
    error: string | null;
    terminal?: boolean;
  }>): void {
    inImmediateTransaction(this.options.database, () => {
      const current = this.pending(row.invocation_id);
      const payload = current ? parsePayload(current.redacted_payload_json) : undefined;
      if (!payload || payload.deliveryState !== "pending") return;
      const deliveryAttemptCount = payload.deliveryAttemptCount + 1;
      const quarantined = !outcome.accepted
        && (outcome.terminal === true
          || deliveryAttemptCount >= AUTONOMOUS_WEB_DELIVERY_ATTEMPT_LIMIT);
      this.options.database.prepare(`
        UPDATE tool_calls SET redacted_payload_json = ? WHERE id = ?
          AND status IN ('succeeded', 'failed', 'timed_out')
      `).run(JSON.stringify({
        ...payload,
        deliveryState: outcome.accepted ? "accepted" : quarantined ? "quarantined" : "pending",
        resultAccepted: outcome.accepted,
        duplicateResult: outcome.accepted ? outcome.duplicate : false,
        deliveryAttemptCount,
        deliveryLastAttemptAt: this.now().toISOString(),
        deliveryLastError: outcome.error,
        deliveryQuarantineReason: quarantined ? outcome.error : null,
      }), row.invocation_id);
      if (quarantined) this.recordDeliveryDiagnosis(row, outcome.error ?? "unknown_delivery_failure", deliveryAttemptCount);
    });
  }

  private recordDeliveryDiagnosis(row: PendingRow, reason: string, attempts: number): void {
    const id = `failure_web_delivery_${createHash("sha256")
      .update(row.invocation_id).digest("hex").slice(0, 40)}`;
    this.options.database.prepare(`
      INSERT OR IGNORE INTO failure_diagnoses (
        id, mission_id, run_id, step_id, assignment_id, action_id,
        attack_attempt_id, subject_type, subject_id, human_reason, category,
        code, originating_component, last_success_event_id, failed_component_ref,
        target_summary, policy_or_dependency, raw_error_log_id, retry_history_json,
        progress_before_failure_json, preserved_refs_json, retryable,
        automatic_recovery_json, remediation, operator_actions_json,
        objective_impact, state, created_at, resolved_at
      ) VALUES (?, ?, ?, ?, NULL, ?, NULL, 'action', ?, ?,
        'restart_recovery_required', 'autonomous_web_result_delivery_quarantined',
        'AutonomousWebSurfaceResultAwarePort', NULL, ?, NULL,
        'bounded durable result delivery', NULL, ?, '{}', '[]', 0, '[]', ?,
        ?, ?, 'terminal', ?, NULL)
    `).run(
      id,
      row.mission_id,
      row.run_id,
      row.step_id,
      row.action_id,
      row.action_id,
      `The runtime could not safely acknowledge this durable web-phase result after ${attempts} delivery attempt${attempts === 1 ? "" : "s"}. The receipt was quarantined instead of replaying forever.`,
      row.invocation_id,
      JSON.stringify([{ attempt: attempts, reason }]),
      "Inspect the durable tool-call receipt and runtime result sink, then start a new bounded run or reconcile the action explicitly.",
      JSON.stringify([{ kind: "start_new_run", label: "Start a new bounded run" }]),
      "The web phase cannot advance from this action until its terminal result is reconciled.",
      this.now().toISOString(),
    );
  }

  private quarantineMalformedDelivery(row: PendingRow, reason: string): void {
    const now = this.now().toISOString();
    const payload: QuarantinedDeliveryPayload = {
      schemaVersion: AUTONOMOUS_WEB_RESULT_DELIVERY_SCHEMA_VERSION,
      deliveryState: "quarantined",
      resultAccepted: false,
      duplicateResult: false,
      deliveryAttemptCount: 1,
      deliveryLastAttemptAt: now,
      deliveryLastError: reason,
      deliveryQuarantineReason: reason,
      originalPayloadSha256: createHash("sha256")
        .update(row.redacted_payload_json, "utf8").digest("hex"),
    };
    inImmediateTransaction(this.options.database, () => {
      this.options.database.prepare(`
        UPDATE tool_calls SET redacted_payload_json = ? WHERE id = ?
          AND status IN ('succeeded', 'failed', 'timed_out')
      `).run(JSON.stringify(payload), row.invocation_id);
      this.recordDeliveryDiagnosis(row, reason, 1);
    });
  }

  private async deliver(invocationId: string): Promise<boolean> {
    const row = this.pending(invocationId);
    if (!row) return false;
    const payload = parsePayload(row.redacted_payload_json);
    if (!payload) {
      this.quarantineMalformedDelivery(row, "runtime_result_payload_malformed");
      return false;
    }
    if (payload.deliveryState === "accepted") return true;
    if (payload.deliveryState === "quarantined") return false;
    const result = payload.deliveryResult;
    const statusMatches = result.success
      ? row.tool_status === "succeeded"
      : row.tool_status === "failed" || row.tool_status === "timed_out";
    if (result.actionId !== row.action_id || result.runId !== row.run_id
      || result.actionFingerprint !== row.action_fingerprint || !statusMatches
      || (result.success && (payload.resultSha256 === null || payload.contextPackId === null
        || payload.evidenceIds.length < 1
        || ((payload.logRecordId === null) !== (payload.observationId === null))))) {
      this.recordDelivery(row, {
        accepted: false,
        duplicate: false,
        error: "runtime_result_payload_binding_invalid",
        terminal: true,
      });
      return false;
    }
    if (!this.resultSink) return false;
    try {
      const receipt: ExecutionResultReceipt = await this.resultSink.acceptExecutionResult(result);
      const accepted = receipt.accepted
        && receipt.actionId === row.action_id && receipt.runId === row.run_id;
      this.recordDelivery(row, {
        accepted,
        duplicate: accepted && receipt.duplicate,
        error: accepted ? null : "runtime_result_receipt_rejected",
      });
      return accepted;
    } catch {
      this.recordDelivery(row, {
        accepted: false,
        duplicate: false,
        error: "runtime_result_delivery_failed",
      });
      return false;
    }
  }

  async replayPendingResults(limit = 100): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new RangeError("Pending Autonomous web result replay limit must be 1 through 1000");
    }
    if (!this.resultSink) return 0;
    const rows = this.options.database.prepare(`
      SELECT tc.id AS invocation_id FROM tool_calls tc
      JOIN actions a ON a.id = tc.action_id JOIN runs r ON r.id = a.run_id
      JOIN missions m ON m.id = r.mission_id
      WHERE tc.provider = 'reviewed-local-process' AND tc.tool_name IN (?, ?, ?)
        AND tc.status IN ('succeeded', 'failed', 'timed_out')
        AND r.journey = 'autonomous' AND r.control_plane = 'ti_scale'
        AND m.control_plane = 'ti_scale'
        AND COALESCE(json_extract(tc.redacted_payload_json, '$.deliveryState'), 'pending') = 'pending'
        AND COALESCE(json_extract(tc.redacted_payload_json, '$.deliveryAttemptCount'), 0) < ?
      ORDER BY tc.ended_at, tc.id LIMIT ?
    `).all(
      AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
      AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
      AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
      AUTONOMOUS_WEB_DELIVERY_ATTEMPT_LIMIT,
      limit,
    ) as Array<{ readonly invocation_id: string }>;
    let accepted = 0;
    for (const row of rows) if (await this.deliver(row.invocation_id)) accepted += 1;
    return accepted;
  }

  close(): void {
    this.executor.close();
  }
}

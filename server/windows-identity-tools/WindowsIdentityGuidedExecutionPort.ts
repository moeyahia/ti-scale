import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import {
  ActionRepository,
  RunRepository,
  type DurableAction,
} from "../orchestration";
import type {
  ExecutionResult,
  ExecutionResultReceipt,
  ExecutionResultSink,
  ResultAwareExecutionPort,
} from "../command-runtime";
import type { ControlPlaneLeaseService } from "../control-plane";
import { ControlPlaneLeaseError } from "../control-plane";
import { REVIEWED_WINDOWS_IDENTITY_EXECUTION_BINDING } from "../command-runtime/WindowsIdentityGuidedRuntime";
import { normalizeWindowsIdentityResult } from "./WindowsIdentityResultNormalizer";
import { WindowsIdentityToolPack } from "./WindowsIdentityToolPack";
import {
  WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION,
  WindowsIdentityBoundaryError,
  type WindowsIdentityActionRequest,
  type WindowsIdentityCredentialMaterialResolver,
  type WindowsIdentityCredentialView,
  type WindowsIdentityExecutionAdapter,
  type WindowsIdentityNormalizedResult,
  type WindowsIdentityOperation,
  type WindowsIdentityToolId,
} from "./types";

const PROVIDER = "reviewed-windows-identity-process" as const;
const DELIVERY_SCHEMA = "ti-scale.windows-identity-result-delivery.v1" as const;

interface CanonicalIdentityAction {
  readonly action: DurableAction;
  readonly operation: WindowsIdentityOperation;
  readonly toolId: WindowsIdentityToolId;
  readonly authenticationMode: "anonymous" | "credential_reference";
  readonly credentialReference: WindowsIdentityActionRequest["credentialReference"];
  readonly logicalWorkspace: string;
  readonly planId: string;
  readonly planVersion: number;
  readonly agentId: string;
}

interface PersistedDeliveryPayload {
  readonly schemaVersion: typeof DELIVERY_SCHEMA;
  readonly executionResult: ExecutionResult;
  readonly logRecordId: string;
  readonly observationIds: readonly string[];
  readonly evidenceCandidateIds: readonly [];
  readonly resultAccepted: boolean;
  readonly duplicateResult: boolean;
  readonly deliveryAttemptCount: number;
  readonly deliveryLastAttemptAt: string | null;
  readonly deliveryLastError: string | null;
}

export interface WindowsIdentityGuidedExecutionPortOptions {
  readonly database: SqliteDatabase;
  readonly pack: WindowsIdentityToolPack;
  readonly adapter: WindowsIdentityExecutionAdapter;
  readonly credentialResolver?: WindowsIdentityCredentialMaterialResolver;
  readonly assertControlPlaneAuthority: (
    runId: string,
  ) => ReturnType<ControlPlaneLeaseService["assertMutationAuthority"]>;
  readonly now?: () => Date;
}

function exactKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function requiredViews(operation: WindowsIdentityOperation): readonly WindowsIdentityCredentialView[] {
  if (operation === "smb_identity_summary") return ["username_file", "password_file"];
  if (operation === "smb_share_list" || operation === "rpc_domain_info") return ["samba_auth_file"];
  return ["ldap_bind_identity"];
}

function resultStatus(normalized: WindowsIdentityNormalizedResult): "succeeded" | "failed" | "timed_out" | "cancelled" {
  if (normalized.status === "completed") return "succeeded";
  if (normalized.status === "cancelled") return "cancelled";
  return normalized.failure?.category === "timeout" ? "timed_out" : "failed";
}

function parseDelivery(value: string | null): PersistedDeliveryPayload | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<PersistedDeliveryPayload>;
    if (parsed.schemaVersion !== DELIVERY_SCHEMA
      || !parsed.executionResult
      || typeof parsed.executionResult.actionId !== "string"
      || typeof parsed.executionResult.runId !== "string"
      || typeof parsed.executionResult.actionFingerprint !== "string"
      || typeof parsed.resultAccepted !== "boolean") return null;
    return parsed as PersistedDeliveryPayload;
  } catch {
    return null;
  }
}

/**
 * The single runtime's direct-process Windows/identity execution boundary.
 * It accepts only one canonical running action with one exact approved
 * Guided decision, then persists log/observation truth before acknowledging
 * the result. Evidence promotion is deliberately impossible on this port.
 */
export class WindowsIdentityGuidedExecutionPort implements ResultAwareExecutionPort {
  private readonly actions: ActionRepository;
  private readonly runs: RunRepository;
  private readonly clock: () => Date;
  private resultSink?: ExecutionResultSink;
  private readonly terminalInProgress = new Set<string>();

  constructor(private readonly options: WindowsIdentityGuidedExecutionPortOptions) {
    this.actions = new ActionRepository(options.database);
    this.runs = new RunRepository(options.database);
    this.clock = options.now ?? (() => new Date());
  }

  bindResultSink(sink: ExecutionResultSink): () => void {
    if (this.resultSink) throw new Error("Windows/identity result sink is already bound");
    this.resultSink = sink;
    return () => {
      if (this.resultSink === sink) this.resultSink = undefined;
    };
  }

  private assertAuthority(runId: string): void {
    try {
      this.options.assertControlPlaneAuthority(runId);
    } catch (error) {
      if (error instanceof ControlPlaneLeaseError) {
        throw new WindowsIdentityBoundaryError(
          "windows_identity_guided_decision_required",
          "policy_denied",
          "Ti-Scale no longer holds the run's control-plane authority at the Windows/identity execution boundary.",
          false,
        );
      }
      throw error;
    }
  }

  private canonical(input: DurableAction): CanonicalIdentityAction {
    const action = this.actions.get(input.id);
    if (digestCanonicalJson(action, { maxBytes: 1_024 * 1_024, maxDepth: 64 }).sha256
      !== digestCanonicalJson(input, { maxBytes: 1_024 * 1_024, maxDepth: 64 }).sha256
      || action.status !== "running" || action.kind !== "tool") {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_guided_action_changed",
        "policy_denied",
        "Only the exact running canonical Guided action may enter Windows/identity execution.",
      );
    }
    const args = action.arguments;
    if (!exactKeys(args, [
      "authenticationMode", "credentialReference", "executionBinding", "logicalWorkspace",
      "operation", "schemaVersion", "toolId",
    ])
      || args.schemaVersion !== WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION
      || args.executionBinding !== REVIEWED_WINDOWS_IDENTITY_EXECUTION_BINDING
      || typeof args.operation !== "string"
      || typeof args.toolId !== "string"
      || typeof args.logicalWorkspace !== "string"
      || (args.authenticationMode !== "anonymous" && args.authenticationMode !== "credential_reference")) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_request_invalid",
        "invalid_input",
        "The persisted Windows/identity action envelope is not canonical.",
      );
    }
    const definition = this.options.pack.resolveOperation(args.operation as WindowsIdentityOperation);
    if (!definition || definition.toolId !== args.toolId || action.actionType !== definition.toolId
      || action.actionClass !== definition.actionClassId) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_tool_identity_changed",
        "dependency_missing",
        "The persisted action no longer matches the reviewed Windows/identity tool definition.",
      );
    }
    this.assertAuthority(action.runId);
    const allowed = this.runs.authorizePersistedReviewedProcessTool(
      this.runs.get(action.runId),
      action,
      definition.toolId,
      REVIEWED_WINDOWS_IDENTITY_EXECUTION_BINDING,
    );
    if (!allowed.allowed) {
      throw new WindowsIdentityBoundaryError(
        allowed.code === "guided_decision_no_longer_authorized"
          ? "windows_identity_guided_decision_required"
          : "windows_identity_guided_action_changed",
        "policy_denied",
        allowed.humanMessage,
      );
    }
    const relation = this.options.database.prepare(`
      SELECT p.id AS plan_id, p.version AS plan_version, ass.agent_id
      FROM plan_steps ps
      JOIN plans p ON p.id = ps.plan_id AND p.run_id = ps.run_id
      JOIN assignments ass ON ass.step_id = ps.id AND ass.run_id = ps.run_id
      WHERE ps.id = ? AND ps.run_id = ? AND p.status = 'active'
        AND ass.status = 'active' AND ass.agent_id = ps.assigned_agent_id
      LIMIT 1
    `).get(action.stepId, action.runId) as {
      plan_id: string;
      plan_version: number;
      agent_id: string;
    } | undefined;
    if (!relation) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_guided_action_changed",
        "policy_denied",
        "The current plan, step, and specialist assignment no longer match this action.",
      );
    }
    return {
      action,
      operation: definition.operation,
      toolId: definition.toolId,
      authenticationMode: args.authenticationMode,
      credentialReference: args.credentialReference as WindowsIdentityActionRequest["credentialReference"],
      logicalWorkspace: args.logicalWorkspace,
      planId: relation.plan_id,
      planVersion: relation.plan_version,
      agentId: relation.agent_id,
    };
  }

  private async compile(input: DurableAction) {
    const canonical = this.canonical(input);
    const now = this.clock();
    const decision = this.options.database.prepare(`
      SELECT id, mission_id, run_id, step_id, requested_action_fingerprint,
        status, decided_at, expires_at
      FROM guided_decisions WHERE id = ?
    `).get(canonical.action.guidedDecisionId) as {
      id: string;
      mission_id: string;
      run_id: string;
      step_id: string;
      requested_action_fingerprint: string;
      status: string;
      decided_at: string | null;
      expires_at: string;
    } | undefined;
    if (!decision || decision.status !== "approved"
      || decision.mission_id !== canonical.action.missionId
      || decision.run_id !== canonical.action.runId
      || decision.step_id !== canonical.action.stepId
      || decision.requested_action_fingerprint !== canonical.action.fingerprint
      || Date.parse(decision.expires_at) <= now.getTime()) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_guided_decision_required",
        "policy_denied",
        "The exact Guided decision is missing, expired, rejected, or belongs to a different action.",
      );
    }
    const request: WindowsIdentityActionRequest = {
      schemaVersion: WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION,
      missionId: canonical.action.missionId,
      runId: canonical.action.runId,
      stepId: canonical.action.stepId,
      planVersion: canonical.planVersion,
      journey: "guided",
      operation: canonical.operation,
      target: canonical.action.target,
      logicalWorkspace: canonical.logicalWorkspace,
      authenticationMode: canonical.authenticationMode,
      credentialReference: canonical.credentialReference,
    };
    let credentialBindingReceipt = null;
    if (request.credentialReference) {
      if (!this.options.credentialResolver) {
        throw new WindowsIdentityBoundaryError(
          "windows_identity_credential_binding_missing",
          "authentication_missing",
          "The opaque credential reference has no configured private resolver.",
        );
      }
      const material = await this.options.credentialResolver.resolve({
        reference: request.credentialReference,
        runId: request.runId,
        actionFingerprint: canonical.action.fingerprint,
        requiredViews: requiredViews(request.operation),
      });
      credentialBindingReceipt = material.receipt;
    }
    const targets = this.options.database.prepare(`
      SELECT target, disposition FROM mission_targets WHERE mission_id = ? ORDER BY id
    `).all(canonical.action.missionId) as Array<{
      target: string;
      disposition: "allowed" | "prohibited";
    }>;
    const mission = this.options.database.prepare(`
      SELECT authorization_status FROM missions WHERE id = ?
    `).get(canonical.action.missionId) as { authorization_status: string } | undefined;
    const invocation = this.options.pack.compile({
      request,
      missionBoundary: {
        authorizationVerified: mission?.authorization_status === "verified",
        allowedTargets: targets.filter(({ disposition }) => disposition === "allowed").map(({ target }) => target),
        prohibitedTargets: targets.filter(({ disposition }) => disposition === "prohibited").map(({ target }) => target),
        allowedActionClassIds: [canonical.action.actionClass],
        prohibitedActionClassIds: [],
        // The decision is persisted as approved. RunRepository already proved
        // that exactly one action consumed it; pack compilation rechecks the
        // same fingerprint without creating or consuming a second decision.
        guidedDecision: {
          id: decision.id,
          missionId: decision.mission_id,
          runId: decision.run_id,
          stepId: decision.step_id,
          journey: "guided",
          actionFingerprint: decision.requested_action_fingerprint,
          status: "authorized",
          ...(decision.decided_at ? { authorizedAt: decision.decided_at } : {}),
          expiresAt: decision.expires_at,
          version: 1,
        },
      },
      credentialBindingReceipt,
      now,
    });
    if (invocation.actionFingerprint !== canonical.action.fingerprint) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_guided_action_changed",
        "policy_denied",
        "The compiled Windows/identity action differs from the exact approved persisted action.",
      );
    }
    return { canonical, invocation };
  }

  async dispatch(action: DurableAction, signal: AbortSignal): Promise<void> {
    if (!this.resultSink) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_adapter_not_bounded",
        "policy_denied",
        "The mission runtime result sink is not bound.",
      );
    }
    const prepared = await this.compile(action);
    const invocationId = `windows_identity_${createHash("sha256").update(action.id).digest("hex").slice(0, 40)}`;
    const startedAt = this.clock().toISOString();
    const inserted = this.options.database.prepare(`
      INSERT INTO tool_calls (
        id, action_id, provider, tool_name, mcp_server_id,
        normalized_arguments_json, status, started_at, created_at
      ) VALUES (?, ?, ?, ?, NULL, ?, 'running', ?, ?)
      ON CONFLICT(id) DO NOTHING
    `).run(
      invocationId,
      action.id,
      PROVIDER,
      prepared.canonical.toolId,
      JSON.stringify({
        schemaVersion: WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION,
        executionBinding: REVIEWED_WINDOWS_IDENTITY_EXECUTION_BINDING,
        operation: prepared.canonical.operation,
        logicalWorkspace: prepared.canonical.logicalWorkspace,
        authenticationMode: prepared.canonical.authenticationMode,
        credentialReferenceId: prepared.canonical.credentialReference?.id ?? null,
        actionFingerprint: prepared.invocation.actionFingerprint,
      }),
      startedAt,
      startedAt,
    ).changes;
    if (inserted !== 1) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_guided_action_changed",
        "policy_denied",
        "This exact Windows/identity action already has a durable tool-call receipt.",
      );
    }
    // Acceptance is distinct from completion. Long-running identity reads are
    // owned by the runtime lease and may finish after this scheduler turn.
    // Any post-acceptance adapter failure is converted into a correlated
    // terminal result rather than becoming an unhandled rejection.
    void this.options.adapter.execute(prepared.invocation, signal).then(
      (raw) => this.acceptResult(
        invocationId,
        prepared.canonical,
        normalizeWindowsIdentityResult(raw),
      ),
      (error) => this.acceptAdapterFailure(invocationId, prepared.canonical, error),
    );
  }

  async resume(): Promise<void> {
    throw new WindowsIdentityBoundaryError(
      "windows_identity_guided_action_changed",
      "policy_denied",
      "A recovered identity read requires a new bounded action and exact Guided decision; the old process is never replayed.",
    );
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    await this.options.adapter.cancelRun(runId, reason);
    this.options.database.prepare(`
      UPDATE tool_calls SET status = 'cancelled', error_category = NULL,
        output_summary = ?, ended_at = ?
      WHERE provider = ? AND status = 'running' AND action_id IN (
        SELECT id FROM actions WHERE run_id = ?
      )
    `).run(
      "Run cancellation terminated the reviewed Windows/identity process before a result was accepted.",
      this.clock().toISOString(),
      PROVIDER,
      runId,
    );
  }

  private async acceptResult(
    invocationId: string,
    canonical: CanonicalIdentityAction,
    normalized: WindowsIdentityNormalizedResult,
  ): Promise<void> {
    if (this.terminalInProgress.has(invocationId)) return;
    this.terminalInProgress.add(invocationId);
    try {
      const now = this.clock().toISOString();
      const logRecordId = `log_${randomUUID()}`;
      const observationIds = normalized.observations.map(() => `observation_${randomUUID()}`);
      const success = normalized.status === "completed";
      const executionResult: ExecutionResult = {
        actionId: canonical.action.id,
        runId: canonical.action.runId,
        actionFingerprint: canonical.action.fingerprint,
        success,
        summary: normalized.summary,
        progress: { verifiedWorkerResultIds: [invocationId] },
        ...(!success ? {
          failure: {
            source: "tool" as const,
            ...(normalized.failure ? { code: normalized.failure.code } : {}),
            message: normalized.summary,
          },
          ...(normalized.failure ? { failureCategory: normalized.failure.category } : {}),
          circuitKey: `windows-identity:${canonical.toolId}`,
        } : {}),
      };
      const payload: PersistedDeliveryPayload = {
        schemaVersion: DELIVERY_SCHEMA,
        executionResult,
        logRecordId,
        observationIds,
        evidenceCandidateIds: [],
        resultAccepted: false,
        duplicateResult: false,
        deliveryAttemptCount: 0,
        deliveryLastAttemptAt: null,
        deliveryLastError: null,
      };
      const committed = inImmediateTransaction(this.options.database, () => {
        const current = this.options.database.prepare(`
          SELECT status FROM tool_calls WHERE id = ? AND provider = ?
        `).get(invocationId, PROVIDER) as { status: string } | undefined;
        if (current?.status !== "running") return false;
        const technicalPayload = JSON.stringify({
          schemaVersion: normalized.schemaVersion,
          stdout: normalized.engagementLog.stdout,
          stderr: normalized.engagementLog.stderr,
          outputSha256: normalized.engagementLog.outputSha256,
          outputTruncated: normalized.engagementLog.outputTruncated,
          evidencePromotion: "none",
        });
        this.options.database.prepare(`
          INSERT INTO engagement_log_records (
            id, mission_id, run_id, plan_id, step_id, action_id,
            agent_id, tool_call_id, severity, domain, record_type,
            human_summary, technical_payload_json, content_hash,
            sensitivity, occurred_at, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'windows_identity',
            'tool_result', ?, ?, ?, 'restricted', ?, ?)
        `).run(
          logRecordId,
          canonical.action.missionId,
          canonical.action.runId,
          canonical.planId,
          canonical.action.stepId,
          canonical.action.id,
          canonical.agentId,
          invocationId,
          success ? "notice" : "error",
          normalized.summary,
          technicalPayload,
          createHash("sha256").update(technicalPayload).digest("hex"),
          now,
          now,
        );
        normalized.observations.forEach((observation, index) => {
          const observationId = observationIds[index]!;
          this.options.database.prepare(`
            INSERT INTO observations (
              id, mission_id, run_id, step_id, observation_type, statement,
              normalized_value_json, confidence, verification_state,
              source_agent_id, source_tool, first_seen_at, last_seen_at,
              sensitivity, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unverified', ?, ?, ?, ?, 'restricted', ?)
          `).run(
            observationId,
            canonical.action.missionId,
            canonical.action.runId,
            canonical.action.stepId,
            observation.type,
            observation.statement,
            JSON.stringify(observation.normalizedValue),
            observation.confidence,
            canonical.agentId,
            observation.sourceToolId,
            now,
            now,
            now,
          );
          this.options.database.prepare(`
            INSERT INTO observation_log_sources (
              observation_id, log_record_id, parser_id, parser_version, created_at
            ) VALUES (?, ?, 'ti-scale.windows-identity-normalizer', ?, ?)
          `).run(observationId, logRecordId, normalized.schemaVersion, now);
        });
        this.options.database.prepare(`
          UPDATE tool_calls SET status = ?, error_category = ?, output_summary = ?,
            redacted_payload_json = ?, ended_at = ?
          WHERE id = ? AND provider = ? AND status = 'running'
        `).run(
          resultStatus(normalized),
          normalized.failure?.category ?? null,
          normalized.summary,
          JSON.stringify(payload),
          now,
          invocationId,
          PROVIDER,
        );
        return true;
      });
      if (committed) await this.deliver(invocationId, payload);
    } finally {
      this.terminalInProgress.delete(invocationId);
    }
  }

  private async acceptAdapterFailure(
    invocationId: string,
    canonical: CanonicalIdentityAction,
    error: unknown,
  ): Promise<void> {
    const failure = error instanceof WindowsIdentityBoundaryError
      ? error
      : new WindowsIdentityBoundaryError(
          "windows_identity_tool_deterministic_error",
          "deterministic_tool_error",
          "The reviewed Windows/identity adapter failed after accepting the exact action.",
        );
    const now = this.clock().toISOString();
    const executionResult: ExecutionResult = {
      actionId: canonical.action.id,
      runId: canonical.action.runId,
      actionFingerprint: canonical.action.fingerprint,
      success: false,
      summary: failure.message,
      progress: {},
      failure: { source: "tool", code: failure.code, message: failure.message },
      failureCategory: failure.category,
      circuitKey: `windows-identity:${canonical.toolId}`,
    };
    const payload: PersistedDeliveryPayload = {
      schemaVersion: DELIVERY_SCHEMA,
      executionResult,
      logRecordId: "",
      observationIds: [],
      evidenceCandidateIds: [],
      resultAccepted: false,
      duplicateResult: false,
      deliveryAttemptCount: 0,
      deliveryLastAttemptAt: null,
      deliveryLastError: null,
    };
    const changed = this.options.database.prepare(`
      UPDATE tool_calls SET status = 'failed', error_category = ?, output_summary = ?,
        redacted_payload_json = ?, ended_at = ?
      WHERE id = ? AND provider = ? AND status = 'running'
    `).run(
      failure.category,
      failure.message,
      JSON.stringify(payload),
      now,
      invocationId,
      PROVIDER,
    ).changes;
    if (changed === 1) await this.deliver(invocationId, payload);
  }

  private updateDelivery(invocationId: string, payload: PersistedDeliveryPayload): void {
    this.options.database.prepare(`
      UPDATE tool_calls SET redacted_payload_json = ?
      WHERE id = ? AND provider = ? AND status IN ('succeeded', 'failed', 'timed_out', 'cancelled')
    `).run(JSON.stringify(payload), invocationId, PROVIDER);
  }

  private async deliver(invocationId: string, payload: PersistedDeliveryPayload): Promise<boolean> {
    if (payload.resultAccepted) return true;
    const sink = this.resultSink;
    if (!sink) return false;
    try {
      const receipt: ExecutionResultReceipt = await sink.acceptExecutionResult(payload.executionResult);
      const accepted = receipt.accepted
        && receipt.actionId === payload.executionResult.actionId
        && receipt.runId === payload.executionResult.runId;
      this.updateDelivery(invocationId, {
        ...payload,
        resultAccepted: accepted,
        duplicateResult: accepted ? receipt.duplicate : false,
        deliveryAttemptCount: payload.deliveryAttemptCount + 1,
        deliveryLastAttemptAt: this.clock().toISOString(),
        deliveryLastError: accepted ? null : "runtime_result_receipt_rejected",
      });
      return accepted;
    } catch {
      this.updateDelivery(invocationId, {
        ...payload,
        deliveryAttemptCount: payload.deliveryAttemptCount + 1,
        deliveryLastAttemptAt: this.clock().toISOString(),
        deliveryLastError: "runtime_result_delivery_failed",
      });
      return false;
    }
  }

  async replayPendingResults(limit = 100): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new RangeError("Pending Windows/identity result replay limit must be 1-1000");
    }
    if (!this.resultSink) return 0;
    const rows = this.options.database.prepare(`
      SELECT id, redacted_payload_json FROM tool_calls
      WHERE provider = ? AND status IN ('succeeded', 'failed', 'timed_out')
        AND COALESCE(json_extract(redacted_payload_json, '$.resultAccepted'), 0) = 0
      ORDER BY ended_at, id LIMIT ?
    `).all(PROVIDER, limit) as Array<{ id: string; redacted_payload_json: string | null }>;
    let delivered = 0;
    for (const row of rows) {
      const payload = parseDelivery(row.redacted_payload_json);
      if (payload && await this.deliver(row.id, payload)) delivered += 1;
    }
    return delivered;
  }
}

import { createHash } from "node:crypto";
import type {
  ExecutionResult,
  ExecutionResultReceipt,
  ExecutionResultSink,
  ResultAwareExecutionPort,
} from "../command-runtime";
import type { SqliteDatabase } from "../db";
import { digestCanonicalJson } from "../mcp";
import {
  ActionRepository,
  ExecutionBoundaryError,
  type DurableAction,
} from "../orchestration";
import type { FailureCategory } from "../supervisor";
import {
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
  AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
  AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
  parseAutonomousLinuxPrivilegeActionArguments,
} from "./CandidateLinuxPrivilegeContinuation";
import {
  AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION,
  CandidateLinuxPrivilegeContinuationRuntime,
  type CandidateLinuxPrivilegeRuntimeResult,
} from "./CandidateLinuxPrivilegeContinuationRuntime";

export const AUTONOMOUS_LINUX_PRIVILEGE_DELIVERY_SCHEMA_VERSION =
  "ti-scale.autonomous-linux-privilege-delivery.v1" as const;

const DELIVERY_ATTEMPT_LIMIT = 8;
const CANCELLATION_SETTLEMENT_TIMEOUT_MS = 10_000;

interface TerminalPayload {
  readonly schemaVersion:
    typeof AUTONOMOUS_LINUX_PRIVILEGE_DELIVERY_SCHEMA_VERSION;
  readonly runtimeResult: CandidateLinuxPrivilegeRuntimeResult | null;
  readonly deliveryResult: ExecutionResult;
  readonly resultAccepted: boolean;
  readonly duplicateResult: boolean;
  readonly deliveryAttemptCount: number;
  readonly deliveryLastAttemptAt: string | null;
  readonly deliveryLastError: string | null;
}

interface PendingRow {
  readonly invocation_id: string;
  readonly tool_status: "succeeded" | "failed" | "timed_out" | "cancelled";
  readonly redacted_payload_json: string;
  readonly action_id: string;
  readonly run_id: string;
  readonly action_fingerprint: string;
}

function toolCallId(actionId: string): string {
  return `linux_post_exploit_${createHash("sha256")
    .update(actionId, "utf8").digest("hex").slice(0, 40)}`;
}

function knownActionType(value: string): boolean {
  const types: readonly string[] = [
    AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
    AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
    AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
  ];
  return types.includes(value);
}

function normalizedError(error: unknown): Readonly<{
  code: string;
  message: string;
  category: FailureCategory;
}> {
  const rawCode = typeof (error as { readonly code?: unknown })?.code === "string"
    ? (error as { readonly code: string }).code
    : "autonomous_linux_privilege_continuation_failed";
  const code = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$/u.test(rawCode)
    ? rawCode
    : "autonomous_linux_privilege_continuation_failed";
  const message = (error instanceof Error
    ? error.message
    : "The candidate-bound Linux continuation failed.")
    .replace(/[\u0000-\u001F\u007F]/gu, " ")
    .trim().replace(/\s+/gu, " ").slice(0, 700);
  let category: FailureCategory = "deterministic_tool_error";
  if (error instanceof ExecutionBoundaryError) category = error.failureCategory;
  else if (/cancel|abort/iu.test(code)) category = "operator_rejection";
  else if (/timeout|timed_out/iu.test(code)) category = "timeout";
  else if (/scope|target|path/iu.test(code)) category = "scope_conflict";
  else if (/authorization|control_plane/iu.test(code)) {
    category = "authorization_denied";
  } else if (/brain|context|dependency|origin|connection|lease_busy/iu.test(code)) {
    category = "dependency_missing";
  } else if (/identity|evidence|proof|hash|correlation|integrity/iu.test(code)) {
    category = "evidence_insufficient";
  } else if (/contract|policy|binding|canonical|lease_fence/iu.test(code)) {
    category = "policy_denied";
  }
  return Object.freeze({ code, message, category });
}

function failureResult(
  action: DurableAction,
  error: unknown,
  wallClockMs: number,
): ExecutionResult {
  const failure = normalizedError(error);
  return Object.freeze({
    actionId: action.id,
    runId: action.runId,
    actionFingerprint: action.fingerprint,
    success: false,
    summary:
      `The candidate-bound Linux continuation failed safely. ${failure.message} `
      + "No root access or flag outcome was inferred.",
    progress: Object.freeze({}),
    failure: Object.freeze({
      source: "tool" as const,
      code: failure.code,
      message: failure.message,
    }),
    failureCategory: failure.category,
    circuitKey: "autonomous-linux-post-exploit:candidate-session",
    usage: Object.freeze({ wallClockMs: Math.max(0, Math.round(wallClockMs)) }),
  });
}

function successfulResult(
  action: DurableAction,
  result: CandidateLinuxPrivilegeRuntimeResult,
  wallClockMs: number,
): ExecutionResult {
  return Object.freeze({
    actionId: action.id,
    runId: action.runId,
    actionFingerprint: action.fingerprint,
    success: true,
    summary: result.summary,
    progress: Object.freeze({
      stepStates: Object.freeze({ [action.stepId]: "completed" as const }),
      evidenceIds: result.evidenceIds,
      verifiedWorkerResultIds: Object.freeze([result.resultSha256]),
    }),
    usage: Object.freeze({
      wallClockMs: Math.max(0, Math.round(wallClockMs)),
      evidenceBytes: result.evidenceIds.length * 64,
    }),
  });
}

function materialRuntimeResult(
  input: Omit<CandidateLinuxPrivilegeRuntimeResult, "resultSha256">,
): CandidateLinuxPrivilegeRuntimeResult {
  return Object.freeze({
    ...input,
    resultSha256: digestCanonicalJson(
      input,
      { maxBytes: 128 * 1_024, maxDepth: 16 },
    ).sha256,
  });
}

function runtimeResultIntegrityValid(
  result: CandidateLinuxPrivilegeRuntimeResult,
): boolean {
  const { resultSha256, ...unsigned } = result;
  return /^[a-f0-9]{64}$/u.test(resultSha256)
    && digestCanonicalJson(
      unsigned,
      { maxBytes: 128 * 1_024, maxDepth: 16 },
    ).sha256 === resultSha256;
}

function provenance(value: string): Readonly<Record<string, unknown>> | undefined {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed !== null
      && typeof parsed === "object"
      && !Array.isArray(parsed)
      ? parsed as Readonly<Record<string, unknown>>
      : undefined;
  } catch {
    return undefined;
  }
}

function parsePayload(value: string): TerminalPayload | undefined {
  try {
    const parsed = JSON.parse(value) as Partial<TerminalPayload>;
    if (!parsed
      || typeof parsed !== "object"
      || Array.isArray(parsed)
      || parsed.schemaVersion
        !== AUTONOMOUS_LINUX_PRIVILEGE_DELIVERY_SCHEMA_VERSION
      || !parsed.deliveryResult
      || typeof parsed.deliveryResult !== "object"
      || typeof parsed.resultAccepted !== "boolean"
      || typeof parsed.duplicateResult !== "boolean"
      || !Number.isSafeInteger(parsed.deliveryAttemptCount)
      || (parsed.deliveryAttemptCount ?? -1) < 0
      || (parsed.deliveryAttemptCount ?? 0) > DELIVERY_ATTEMPT_LIMIT
      || (parsed.runtimeResult !== null
        && (
          !parsed.runtimeResult
          || parsed.runtimeResult.schemaVersion
            !== AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION
          || typeof parsed.runtimeResult.resultSha256 !== "string"
          || !runtimeResultIntegrityValid(
            parsed.runtimeResult as CandidateLinuxPrivilegeRuntimeResult,
          )
        ))) {
      return undefined;
    }
    return parsed as TerminalPayload;
  } catch {
    return undefined;
  }
}

function withinCancellationSettlementBound(
  operation: Promise<void>,
  code: string,
  message: string,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new ExecutionBoundaryError(
      code,
      "worker_lost",
      message,
    )), CANCELLATION_SETTLEMENT_TIMEOUT_MS);
    timer.unref?.();
    operation.then(
      () => {
        clearTimeout(timer);
        resolve();
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

/**
 * Durable MissionRuntime bridge for the fixed candidate privilege, root-proof,
 * and cleanup operations. Restart/resume may only redeliver a terminal
 * receipt; it can never repeat escalation or reread the root proof.
 */
export class AutonomousLinuxPrivilegeContinuationResultAwarePort
implements ResultAwareExecutionPort {
  readonly #actions: ActionRepository;
  readonly #now: () => Date;
  readonly #controllers = new Map<string, Readonly<{
    action: DurableAction;
    controller: AbortController;
    settled: Promise<void>;
  }>>();
  #sink?: ExecutionResultSink;

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    runtime: CandidateLinuxPrivilegeContinuationRuntime;
    now?: () => Date;
  }>) {
    this.#actions = new ActionRepository(options.database);
    this.#now = options.now ?? (() => new Date());
  }

  bindResultSink(sink: ExecutionResultSink): () => void {
    if (this.#sink) {
      throw new Error("Candidate Linux continuation result sink is already bound");
    }
    this.#sink = sink;
    return () => {
      if (this.#sink === sink) this.#sink = undefined;
    };
  }

  private canonical(input: DurableAction): DurableAction {
    const action = this.#actions.get(input.id);
    if (digestCanonicalJson(action, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      !== digestCanonicalJson(input, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      || action.status !== "running"
      || !knownActionType(action.actionType)) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_privilege_delivery_action_not_canonical",
        "policy_denied",
        "Only an exact running candidate Linux continuation action may cross the durable delivery boundary.",
      );
    }
    return action;
  }

  async dispatch(input: DurableAction, signal: AbortSignal): Promise<void> {
    if (!this.#sink) {
      throw new ExecutionBoundaryError(
        "result_sink_unbound",
        "dependency_missing",
        "Mission result delivery must be bound before candidate Linux continuation.",
      );
    }
    const action = this.canonical(input);
    const invocationId = toolCallId(action.id);
    if (this.pending(invocationId)) {
      await this.deliver(invocationId);
      return;
    }
    const existing = this.options.database.prepare(
      "SELECT status FROM tool_calls WHERE id = ?",
    ).get(invocationId) as { readonly status: string } | undefined;
    if (existing) {
      if (existing.status !== "running") {
        throw new ExecutionBoundaryError(
          "autonomous_linux_privilege_invocation_conflict",
          "policy_denied",
          "This candidate Linux action already has a conflicting invocation record.",
        );
      }
      if (this.#controllers.has(action.id)) {
        throw new ExecutionBoundaryError(
          "autonomous_linux_privilege_invocation_in_flight",
          "worker_lost",
          "This candidate Linux action is already executing in the current worker.",
        );
      }
      this.settleInterruptedInvocation(action, invocationId);
      await this.deliver(invocationId);
      return;
    }
    const started = this.#now();
    this.options.database.prepare(`
      INSERT INTO tool_calls (
        id, action_id, provider, tool_name, mcp_server_id,
        normalized_arguments_json, status, started_at, created_at
      ) VALUES (?, ?, 'candidate-linux-session', ?, NULL, ?,
        'running', ?, ?)
    `).run(
      invocationId,
      action.id,
      action.actionType,
      digestCanonicalJson({
        schemaVersion: "ti-scale.autonomous-linux-session-invocation.v1",
        actionId: action.id,
        actionFingerprint: action.fingerprint,
        actionType: action.actionType,
        actionClass: action.actionClass,
        target: action.target,
        argumentsSha256: digestCanonicalJson(
          action.arguments,
          { maxBytes: 64 * 1_024, maxDepth: 12 },
        ).sha256,
        publicProvider: false,
        shell: false,
        arbitraryCommand: false,
      }, { maxBytes: 128 * 1_024, maxDepth: 16 }).canonicalJson,
      started.toISOString(),
      started.toISOString(),
    );

    const controller = new AbortController();
    let markSettled!: () => void;
    const settled = new Promise<void>((resolve) => {
      markSettled = resolve;
    });
    this.#controllers.set(action.id, Object.freeze({
      action,
      controller,
      settled,
    }));
    const effectiveSignal = AbortSignal.any([signal, controller.signal]);
    try {
      const runtimeResult = await this.options.runtime.execute(
        action,
        effectiveSignal,
      );
      const deliveryResult = successfulResult(
        action,
        runtimeResult,
        this.#now().getTime() - started.getTime(),
      );
      this.commitTerminal(
        invocationId,
        "succeeded",
        runtimeResult,
        deliveryResult,
        this.#now().getTime() - started.getTime(),
      );
      if (!effectiveSignal.aborted) await this.deliver(invocationId);
    } catch (error) {
      const current = this.options.database.prepare(
        "SELECT status FROM tool_calls WHERE id = ?",
      ).get(invocationId) as { readonly status: string } | undefined;
      if (current?.status !== "running") throw error;
      const deliveryResult = failureResult(
        action,
        error,
        this.#now().getTime() - started.getTime(),
      );
      const status = deliveryResult.failureCategory === "timeout"
        ? "timed_out"
        : deliveryResult.failureCategory === "operator_rejection"
          ? "cancelled"
          : "failed";
      this.commitTerminal(
        invocationId,
        status,
        null,
        deliveryResult,
        this.#now().getTime() - started.getTime(),
      );
      if (!effectiveSignal.aborted) await this.deliver(invocationId);
    } finally {
      this.#controllers.delete(action.id);
      markSettled();
    }
  }

  private commitTerminal(
    invocationId: string,
    status: "succeeded" | "failed" | "timed_out" | "cancelled",
    runtimeResult: CandidateLinuxPrivilegeRuntimeResult | null,
    deliveryResult: ExecutionResult,
    wallClockMs: number,
  ): void {
    const now = this.#now().toISOString();
    const payload: TerminalPayload = Object.freeze({
      schemaVersion: AUTONOMOUS_LINUX_PRIVILEGE_DELIVERY_SCHEMA_VERSION,
      runtimeResult,
      deliveryResult,
      resultAccepted: false,
      duplicateResult: false,
      deliveryAttemptCount: 0,
      deliveryLastAttemptAt: null,
      deliveryLastError: null,
    });
    const changed = this.options.database.prepare(`
      UPDATE tool_calls
      SET status = ?, error_category = ?, latency_ms = ?,
        output_summary = ?, redacted_payload_json = ?, ended_at = ?
      WHERE id = ? AND status = 'running'
    `).run(
      status,
      deliveryResult.failureCategory ?? null,
      Math.max(0, Math.round(wallClockMs)),
      deliveryResult.summary,
      JSON.stringify(payload),
      now,
      invocationId,
    ).changes;
    if (changed !== 1) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_privilege_terminal_conflict",
        "worker_lost",
        "The candidate Linux invocation changed before its terminal result committed.",
      );
    }
  }

  private settleInterruptedInvocation(
    action: DurableAction,
    invocationId: string,
  ): void {
    const recovered = this.recoverCommittedRuntimeResult(action);
    if (recovered) {
      this.commitTerminal(
        invocationId,
        "succeeded",
        recovered,
        successfulResult(action, recovered, 0),
        0,
      );
      return;
    }
    this.releaseInterruptedLease(action);
    const result = failureResult(
      action,
      new ExecutionBoundaryError(
        "autonomous_linux_privilege_restart_review_required",
        "worker_lost",
        "The worker restarted before a complete canonical privilege, root-proof, or cleanup result committed. The target operation was not repeated and its local lease was released.",
      ),
      0,
    );
    this.commitTerminal(invocationId, "failed", null, result, 0);
  }

  private releaseInterruptedLease(action: DurableAction): void {
    const actionType = knownActionType(action.actionType)
      ? action.actionType as
        | typeof AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE
        | typeof AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE
        | typeof AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE
      : undefined;
    if (!actionType) return;
    let sessionArtifactId: string;
    try {
      sessionArtifactId = parseAutonomousLinuxPrivilegeActionArguments(
        actionType,
        action.arguments,
      ).sessionArtifactId;
    } catch {
      return;
    }
    this.options.database.prepare(`
      UPDATE session_artifact_leases
      SET released_at = ?, release_reason =
        'worker_lost_without_durable_operation_result'
      WHERE session_artifact_id = ? AND released_at IS NULL
    `).run(this.#now().toISOString(), sessionArtifactId);
  }

  private recoverCommittedRuntimeResult(
    action: DurableAction,
  ): CandidateLinuxPrivilegeRuntimeResult | undefined {
    if (action.actionType === AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE) {
      const row = this.options.database.prepare(`
        SELECT observation.session_artifact_id, observation.observation_hash,
          observation.evidence_id, evidence.provenance_json,
          session.status AS session_status, session.access_level
        FROM session_identity_observations observation
        JOIN evidence ON evidence.id = observation.evidence_id
          AND evidence.action_id = observation.action_id
          AND evidence.verification_state = 'verified'
          AND evidence.evidence_type = 'privilege_access_proof'
        JOIN session_artifacts session
          ON session.id = observation.session_artifact_id
        WHERE observation.action_id = ?
          AND observation.observer_kind = 'root_identity'
          AND observation.principal = 'root'
          AND observation.uid = 0 AND observation.gid = 0
          AND session.status = 'privileged'
          AND session.access_level = 'root'
      `).get(action.id) as {
        readonly session_artifact_id: string;
        readonly observation_hash: string;
        readonly evidence_id: string;
        readonly provenance_json: string;
        readonly session_status: string;
        readonly access_level: string;
      } | undefined;
      const details = row ? provenance(row.provenance_json) : undefined;
      if (!row || !details
        || typeof details.contextPackId !== "string"
        || typeof details.privilegeReceiptSha256 !== "string"
        || typeof details.observationSha256 !== "string"
        || details.observationSha256 !== row.observation_hash
        || !/^[a-f0-9]{64}$/u.test(details.privilegeReceiptSha256)
        || !/^[a-f0-9]{64}$/u.test(row.observation_hash)) {
        return undefined;
      }
      return materialRuntimeResult({
        schemaVersion:
          AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION,
        actionId: action.id,
        actionType: AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
        sessionArtifactId: row.session_artifact_id,
        contextPackId: details.contextPackId,
        evidenceIds: Object.freeze([row.evidence_id]),
        privilegeReceiptSha256: details.privilegeReceiptSha256,
        rootIdentityObservationSha256: row.observation_hash,
        cleanupCompleted: false,
        summary:
          "Recovered the committed independent root-identity proof after worker restart without repeating privilege escalation.",
      });
    }
    if (action.actionType === AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE) {
      const row = this.options.database.prepare(`
        SELECT proof.session_artifact_id, proof.content_sha256,
          proof.evidence_id, evidence.provenance_json,
          session.status AS session_status, session.access_level
        FROM session_flag_proofs proof
        JOIN evidence ON evidence.id = proof.evidence_id
          AND evidence.action_id = proof.action_id
          AND evidence.verification_state = 'verified'
          AND evidence.evidence_type = 'privilege_access_proof'
        JOIN session_artifacts session
          ON session.id = proof.session_artifact_id
        WHERE proof.action_id = ? AND proof.proof_kind = 'root_flag'
          AND proof.declared_path = '/root/root.txt'
          AND session.status = 'privileged'
          AND session.access_level = 'root'
      `).get(action.id) as {
        readonly session_artifact_id: string;
        readonly content_sha256: string;
        readonly evidence_id: string;
        readonly provenance_json: string;
        readonly session_status: string;
        readonly access_level: string;
      } | undefined;
      const details = row ? provenance(row.provenance_json) : undefined;
      if (!row || !details
        || typeof details.contextPackId !== "string"
        || typeof details.proofSha256 !== "string"
        || typeof details.contentSha256 !== "string"
        || details.contentSha256 !== row.content_sha256
        || !/^[a-f0-9]{64}$/u.test(details.proofSha256)
        || !/^[a-f0-9]{64}$/u.test(row.content_sha256)) {
        return undefined;
      }
      return materialRuntimeResult({
        schemaVersion:
          AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION,
        actionId: action.id,
        actionType: AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
        sessionArtifactId: row.session_artifact_id,
        contextPackId: details.contextPackId,
        evidenceIds: Object.freeze([row.evidence_id]),
        rootFlagProofSha256: details.proofSha256,
        rootFlagContentSha256: row.content_sha256,
        cleanupCompleted: false,
        summary:
          "Recovered the committed hash-only root proof after worker restart without rereading the target file.",
      });
    }
    if (action.actionType === AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE) {
      const row = this.options.database.prepare(`
        SELECT evidence.id AS evidence_id, evidence.provenance_json
        FROM evidence
        WHERE evidence.action_id = ?
          AND evidence.verification_state = 'verified'
          AND evidence.evidence_type = 'session_command_outcome'
          AND evidence.source = 'candidate_bound_session_cleanup'
      `).get(action.id) as {
        readonly evidence_id: string;
        readonly provenance_json: string;
      } | undefined;
      const details = row ? provenance(row.provenance_json) : undefined;
      if (!row || !details
        || typeof details.sessionArtifactId !== "string"
        || typeof details.contextPackId !== "string"
        || typeof details.cleanupReceiptSha256 !== "string"
        || !/^[a-f0-9]{64}$/u.test(details.cleanupReceiptSha256)) {
        return undefined;
      }
      const closed = this.options.database.prepare(`
        SELECT 1
        FROM session_artifacts session
        WHERE session.id = ? AND session.status = 'closed'
          AND session.closed_at IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM session_artifact_leases lease
            WHERE lease.session_artifact_id = session.id
              AND lease.released_at IS NULL
          )
      `).get(details.sessionArtifactId);
      if (!closed) return undefined;
      return materialRuntimeResult({
        schemaVersion:
          AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION,
        actionId: action.id,
        actionType: AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
        sessionArtifactId: details.sessionArtifactId,
        contextPackId: details.contextPackId,
        evidenceIds: Object.freeze([row.evidence_id]),
        cleanupReceiptSha256: details.cleanupReceiptSha256,
        cleanupCompleted: true,
        summary:
          "Recovered the committed session-cleanup proof after worker restart without repeating cleanup.",
      });
    }
    return undefined;
  }

  private pending(invocationId: string): PendingRow | undefined {
    return this.options.database.prepare(`
      SELECT call.id AS invocation_id, call.status AS tool_status,
        call.redacted_payload_json, action.id AS action_id, action.run_id,
        action.fingerprint AS action_fingerprint
      FROM tool_calls call
      JOIN actions action ON action.id = call.action_id
      JOIN runs run ON run.id = action.run_id
      JOIN missions mission ON mission.id = run.mission_id
      WHERE call.id = ?
        AND call.provider IN (
          'candidate-linux-session',
          'candidate-loopback-linux-session'
        )
        AND call.tool_name IN (?, ?, ?)
        AND call.status IN ('succeeded', 'failed', 'timed_out', 'cancelled')
        AND call.redacted_payload_json IS NOT NULL
        AND run.journey = 'autonomous'
        AND run.control_plane = 'ti_scale'
        AND mission.control_plane = 'ti_scale'
    `).get(
      invocationId,
      AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
      AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
      AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
    ) as PendingRow | undefined;
  }

  private async deliver(invocationId: string): Promise<boolean> {
    if (!this.#sink) return false;
    const row = this.pending(invocationId);
    if (!row) return false;
    const payload = parsePayload(row.redacted_payload_json);
    if (!payload
      || payload.resultAccepted
      || payload.deliveryAttemptCount >= DELIVERY_ATTEMPT_LIMIT) {
      return false;
    }
    const expectedSuccess = row.tool_status === "succeeded";
    if (payload.deliveryResult.actionId !== row.action_id
      || payload.deliveryResult.runId !== row.run_id
      || payload.deliveryResult.actionFingerprint !== row.action_fingerprint
      || payload.deliveryResult.success !== expectedSuccess
      || (
        expectedSuccess
        && (
          payload.runtimeResult === null
          || payload.runtimeResult.actionId !== row.action_id
          || !knownActionType(payload.runtimeResult.actionType)
          || digestCanonicalJson(
            successfulResult(
              this.#actions.get(row.action_id),
              payload.runtimeResult,
              payload.deliveryResult.usage?.wallClockMs ?? 0,
            ),
            { maxBytes: 256 * 1_024, maxDepth: 32 },
          ).sha256 !== digestCanonicalJson(
            payload.deliveryResult,
            { maxBytes: 256 * 1_024, maxDepth: 32 },
          ).sha256
        )
      )
      || (!expectedSuccess && payload.runtimeResult !== null)) {
      return false;
    }
    const attemptedAt = this.#now().toISOString();
    try {
      const receipt: ExecutionResultReceipt =
        await this.#sink.acceptExecutionResult(payload.deliveryResult);
      if (!receipt.accepted
        || receipt.actionId !== row.action_id
        || receipt.runId !== row.run_id) {
        throw new Error("Mission runtime rejected the correlated result");
      }
      this.options.database.prepare(
        "UPDATE tool_calls SET redacted_payload_json = ? WHERE id = ?",
      ).run(JSON.stringify({
        ...payload,
        resultAccepted: true,
        duplicateResult: receipt.duplicate,
        deliveryAttemptCount: payload.deliveryAttemptCount + 1,
        deliveryLastAttemptAt: attemptedAt,
        deliveryLastError: null,
      }), invocationId);
      return true;
    } catch (error) {
      this.options.database.prepare(
        "UPDATE tool_calls SET redacted_payload_json = ? WHERE id = ?",
      ).run(JSON.stringify({
        ...payload,
        resultAccepted: false,
        duplicateResult: false,
        deliveryAttemptCount: payload.deliveryAttemptCount + 1,
        deliveryLastAttemptAt: attemptedAt,
        deliveryLastError: (error instanceof Error
          ? error.message
          : "Mission result delivery failed").slice(0, 500),
      }), invocationId);
      return false;
    }
  }

  async resume(action: DurableAction, _signal: AbortSignal): Promise<void> {
    const canonical = this.canonical(action);
    const invocationId = toolCallId(canonical.id);
    if (!this.pending(invocationId)) {
      const running = this.options.database.prepare(`
        SELECT 1 AS present FROM tool_calls
        WHERE id = ? AND status = 'running'
      `).get(invocationId) as { readonly present: number } | undefined;
      if (!running) {
        throw new ExecutionBoundaryError(
          "autonomous_linux_privilege_resume_forbidden",
          "policy_denied",
          "Restart may only redeliver or reconstruct durable candidate-session state; it cannot repeat the target operation.",
        );
      }
      this.settleInterruptedInvocation(canonical, invocationId);
    }
    await this.deliver(invocationId);
  }

  async replayPendingResults(limit = 100): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new RangeError(
        "Pending candidate-session replay limit must be 1 through 1000",
      );
    }
    if (!this.#sink) return 0;
    const running = this.options.database.prepare(`
      SELECT call.id AS invocation_id, action.id AS action_id
      FROM tool_calls call
      JOIN actions action ON action.id = call.action_id
      JOIN runs run ON run.id = action.run_id
      JOIN missions mission ON mission.id = run.mission_id
      WHERE call.provider IN (
          'candidate-linux-session',
          'candidate-loopback-linux-session'
        )
        AND call.tool_name IN (?, ?, ?)
        AND call.status = 'running'
        AND run.journey = 'autonomous'
        AND run.control_plane = 'ti_scale'
        AND mission.control_plane = 'ti_scale'
      ORDER BY call.started_at, call.id LIMIT ?
    `).all(
      AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
      AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
      AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
      limit,
    ) as Array<{
      readonly invocation_id: string;
      readonly action_id: string;
    }>;
    let accepted = 0;
    for (const row of running) {
      this.settleInterruptedInvocation(
        this.#actions.get(row.action_id),
        row.invocation_id,
      );
      if (await this.deliver(row.invocation_id)) accepted += 1;
    }
    const rows = this.options.database.prepare(`
      SELECT call.id AS invocation_id
      FROM tool_calls call
      JOIN actions action ON action.id = call.action_id
      JOIN runs run ON run.id = action.run_id
      JOIN missions mission ON mission.id = run.mission_id
      WHERE call.provider IN (
          'candidate-linux-session',
          'candidate-loopback-linux-session'
        )
        AND call.tool_name IN (?, ?, ?)
        AND call.status IN ('succeeded', 'failed', 'timed_out', 'cancelled')
        AND call.redacted_payload_json IS NOT NULL
        AND run.journey = 'autonomous'
        AND run.control_plane = 'ti_scale'
        AND mission.control_plane = 'ti_scale'
        AND COALESCE(
          json_extract(call.redacted_payload_json, '$.resultAccepted'),
          0
        ) = 0
        AND COALESCE(
          json_extract(call.redacted_payload_json, '$.deliveryAttemptCount'),
          0
        ) < ?
      ORDER BY call.ended_at, call.id LIMIT ?
    `).all(
      AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
      AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
      AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
      DELIVERY_ATTEMPT_LIMIT,
      Math.max(0, limit - running.length),
    ) as Array<{ readonly invocation_id: string }>;
    for (const row of rows) {
      if (await this.deliver(row.invocation_id)) accepted += 1;
    }
    return accepted;
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    const active = [...this.#controllers.values()]
      .filter(({ action }) => action.runId === runId);
    for (const { controller } of active) {
      controller.abort(new Error(reason));
    }
    const settlements = await Promise.allSettled(active.map(({ settled }) =>
      withinCancellationSettlementBound(
        settled,
        "autonomous_linux_privilege_cancellation_settlement_timeout",
        "The candidate session operation did not durably settle after cancellation.",
      )));
    const failed = settlements.find(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );
    if (failed) throw failed.reason;
    const cleanupSignal = AbortSignal.timeout(
      CANCELLATION_SETTLEMENT_TIMEOUT_MS,
    );
    await this.options.runtime.cleanupRun(runId, reason, cleanupSignal);
  }

  close(): void {
    for (const { controller } of this.#controllers.values()) {
      controller.abort(new Error("Candidate Linux continuation port closed"));
    }
    this.#controllers.clear();
    this.#sink = undefined;
  }
}

export const autonomousLinuxPrivilegeContinuationToolCallId = toolCallId;

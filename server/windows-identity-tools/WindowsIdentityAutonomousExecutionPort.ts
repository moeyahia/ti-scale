import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import {
  ActionRepository,
  RunRepository,
  reviewedLocalToolActionEnvelope,
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
import type {
  LocalAutonomousPlanningPolicy,
  LocalAutonomousProcessActionBinding,
} from "../autonomous-runtime/types";
import { validateLocalAutonomousPlanningPolicy } from "../autonomous-runtime";
import type {
  ProductionAutonomousLocalProcessExecutionFactory,
} from "../app/AutonomousRuntimeComposition";
import { normalizeWindowsIdentityResult } from "./WindowsIdentityResultNormalizer";
import {
  WindowsIdentityToolPack,
} from "./WindowsIdentityToolPack";
import {
  WindowsIdentityBoundaryError,
  type WindowsIdentityExecutionAdapter,
  type WindowsIdentityNormalizedResult,
} from "./types";

export const AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID =
  "kali:nxc-smb-summary" as const;
export const AUTONOMOUS_NXC_SMB_SUMMARY_BINDING_ID =
  "ti-scale:autonomous-nxc-smb-summary" as const;
export const AUTONOMOUS_WINDOWS_IDENTITY_RUNTIME_AGENT_ID =
  "specialist:windows-identity" as const;
export const AUTONOMOUS_WINDOWS_IDENTITY_PRODUCT_AGENT_ID =
  "ADAttackMapper" as const;
export const AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS =
  "active_directory_identity_operations" as const;
export const AUTONOMOUS_NXC_SMB_SUMMARY_EVIDENCE_TYPE =
  "identity_ad_graph" as const;

export const AUTONOMOUS_WINDOWS_IDENTITY_EXECUTION_CONTRACT = Object.freeze({
  schemaVersion: "ti-scale.autonomous-local-process-execution.v1" as const,
  adapterId: "ti-scale:autonomous-windows-identity-composite" as const,
  executionBinding: "reviewed_local_process" as const,
  directArgv: true as const,
  shell: false as const,
  resultDelivery: "bound_execution_result_sink" as const,
  cancellation: "run_scoped_cooperative" as const,
  publicProviderToolExecution: false as const,
});

const PROVIDER = "reviewed-autonomous-windows-identity-process" as const;
const DELIVERY_SCHEMA =
  "ti-scale.autonomous-windows-identity-result-delivery.v1" as const;
const DELIVERY_ATTEMPT_LIMIT = 8;
const LOCAL_PROCESS_ADAPTER_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const LOCAL_PROCESS_CONTRACT_KEYS = Object.freeze([
  "adapterId",
  "cancellation",
  "directArgv",
  "executionBinding",
  "publicProviderToolExecution",
  "resultDelivery",
  "schemaVersion",
  "shell",
] as const);

interface CanonicalAutonomousIdentityAction {
  readonly action: DurableAction;
  readonly planId: string;
  readonly planVersion: number;
  readonly agentId: string;
  readonly logicalWorkspace: string;
}

interface PersistedDeliveryPayload {
  readonly schemaVersion: typeof DELIVERY_SCHEMA;
  readonly executionResult: ExecutionResult;
  readonly logRecordId: string;
  readonly observationIds: readonly string[];
  readonly evidenceCandidateIds: readonly [];
  readonly deliveryState: "pending" | "accepted" | "retry_exhausted";
  readonly resultAccepted: boolean;
  readonly duplicateResult: boolean;
  readonly deliveryAttemptCount: number;
  readonly deliveryLastAttemptAt: string | null;
  readonly deliveryLastError: string | null;
  readonly deliveryTerminalMessage: string | null;
}

function exactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function assertDelegatedLocalProcessFactory(
  factory: ProductionAutonomousLocalProcessExecutionFactory,
): Readonly<
  ProductionAutonomousLocalProcessExecutionFactory["localProcessContract"]
> {
  const candidate = factory as unknown as Readonly<{
    create?: unknown;
    localProcessContract?: unknown;
  }>;
  const contract = candidate?.localProcessContract;
  if (
    typeof candidate !== "object"
    || candidate === null
    || typeof candidate.create !== "function"
    || typeof contract !== "object"
    || contract === null
    || Array.isArray(contract)
    || !Object.isFrozen(contract)
    || !exactKeys(
      contract as Readonly<Record<string, unknown>>,
      LOCAL_PROCESS_CONTRACT_KEYS,
    )
  ) {
    throw new TypeError(
      "Autonomous Windows/identity composition requires one exact immutable delegated local-process execution contract",
    );
  }
  const typed = contract as Readonly<
    ProductionAutonomousLocalProcessExecutionFactory["localProcessContract"]
  >;
  if (
    typed.schemaVersion
      !== "ti-scale.autonomous-local-process-execution.v1"
    || !LOCAL_PROCESS_ADAPTER_ID.test(typed.adapterId)
    || typed.adapterId
      === AUTONOMOUS_WINDOWS_IDENTITY_EXECUTION_CONTRACT.adapterId
    || typed.executionBinding !== "reviewed_local_process"
    || typed.directArgv !== true
    || typed.shell !== false
    || typed.resultDelivery !== "bound_execution_result_sink"
    || typed.cancellation !== "run_scoped_cooperative"
    || typed.publicProviderToolExecution !== false
  ) {
    throw new TypeError(
      "Autonomous Windows/identity composition rejected the delegated local-process execution contract",
    );
  }
  return typed;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? [...new Set(value
        .filter((item): item is string => typeof item === "string")
        .map((item) => item.trim())
        .filter(Boolean))]
    : [];
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
      || !["pending", "accepted", "retry_exhausted"].includes(
        parsed.deliveryState ?? "",
      )
      || typeof parsed.resultAccepted !== "boolean"
      || typeof parsed.duplicateResult !== "boolean"
      || !Number.isSafeInteger(parsed.deliveryAttemptCount)
      || (parsed.deliveryAttemptCount ?? -1) < 0
      || (parsed.deliveryAttemptCount ?? 0) > DELIVERY_ATTEMPT_LIMIT
      || (parsed.deliveryState === "accepted" && !parsed.resultAccepted)
      || (parsed.deliveryState !== "accepted" && parsed.resultAccepted)
      || (
        parsed.deliveryState === "pending"
        && parsed.deliveryAttemptCount === DELIVERY_ATTEMPT_LIMIT
      )
      || (
        parsed.deliveryState === "retry_exhausted"
        && (
          parsed.deliveryAttemptCount !== DELIVERY_ATTEMPT_LIMIT
          || typeof parsed.deliveryTerminalMessage !== "string"
        )
      )
      || !Array.isArray(parsed.observationIds)
      || !Array.isArray(parsed.evidenceCandidateIds)
      || parsed.evidenceCandidateIds.length !== 0) return null;
    return parsed as PersistedDeliveryPayload;
  } catch {
    return null;
  }
}

function resultStatus(
  normalized: WindowsIdentityNormalizedResult,
): "succeeded" | "failed" | "timed_out" | "cancelled" {
  if (normalized.status === "completed") return "succeeded";
  if (normalized.status === "cancelled") return "cancelled";
  return normalized.failure?.category === "timeout" ? "timed_out" : "failed";
}

function adapterCancellation(error: unknown): boolean {
  const candidate = error as {
    readonly name?: unknown;
    readonly code?: unknown;
  } | null;
  return candidate?.name === "AbortError"
    || candidate?.code === "ABORT_ERR"
    || candidate?.code === "windows_identity_cancelled";
}

function deliveryRetryExhaustedMessage(): string {
  return "Mission result delivery stopped after 8 unsuccessful attempts. "
    + "The committed Windows/identity result remains stored for operator "
    + "reconciliation, and Ti-Scale will not contact the target again for "
    + "this action.";
}

/**
 * Adds the one reviewed anonymous SMB identity summary to an existing local
 * Autonomous policy. The action remains absent unless the signed contract
 * explicitly authorizes the identity action class.
 */
export function withAutonomousNxcSmbSummaryPlanning(
  policy: LocalAutonomousPlanningPolicy,
  input: Readonly<{
    logicalWorkspace: string;
    providerId: string;
    modelId: string;
    modelConfigurationHash: string;
  }>,
): LocalAutonomousPlanningPolicy {
  if (policy.bindings.some(({ bindingId }) =>
    bindingId === AUTONOMOUS_NXC_SMB_SUMMARY_BINDING_ID)) {
    throw new Error("The Autonomous NetExec binding is already present");
  }
  const binding: LocalAutonomousProcessActionBinding = Object.freeze({
    bindingId: AUTONOMOUS_NXC_SMB_SUMMARY_BINDING_ID,
    actionClassId: AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
    targetKinds: Object.freeze(["ip"] as const),
    phase: "anonymous_smb_identity_summary",
    title: "Read the approved host's SMB identity",
    objective:
      "Confirm the Windows host, domain, SMB protocol, signing, and anonymously visible share metadata reported by the exact approved IP.",
    explanation:
      "Ti-Scale asks the approved host for a small read-only SMB identity summary without a username, password, password spray, administrator test, share write, or command execution.",
    rationale:
      "This records the identity and SMB security settings needed to decide whether later Windows or directory analysis is relevant, while keeping authentication and evidence promotion out of this step.",
    successCriteria: Object.freeze([
      "The approved host returns attributable SMB identity metadata, or Ti-Scale records a precise connection, policy, timeout, or anonymous-access result.",
    ]),
    reversibility:
      "The action is one bounded read-only SMB query. It sends no reusable credential, writes nothing to the target, and can be cancelled as one run-scoped process group.",
    riskClass: "high",
    idempotent: true,
    destructive: false,
    agentId: AUTONOMOUS_WINDOWS_IDENTITY_RUNTIME_AGENT_ID,
    providerId: input.providerId,
    modelId: input.modelId,
    modelConfigurationHash: input.modelConfigurationHash,
    executionBinding: "reviewed_local_process",
    toolId: AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
    targetParameter: "target",
    staticParameters: Object.freeze({
      authenticationMode: "anonymous",
      operation: "smb_identity_summary",
      workspace: input.logicalWorkspace,
    }),
    capabilityIds: Object.freeze([
      `capability:${AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID}`,
    ]),
    requiredEvidenceTypeIds: Object.freeze([
      AUTONOMOUS_NXC_SMB_SUMMARY_EVIDENCE_TYPE,
    ]),
  });
  return validateLocalAutonomousPlanningPolicy({
    ...policy,
    maximumSteps: policy.maximumSteps + 1,
    bindings: Object.freeze([...policy.bindings, binding]),
  });
}

export interface WindowsIdentityAutonomousExecutionPortOptions {
  readonly database: SqliteDatabase;
  readonly pack: WindowsIdentityToolPack;
  readonly adapter: WindowsIdentityExecutionAdapter;
  readonly assertControlPlaneAuthority: (
    runId: string,
  ) => ReturnType<ControlPlaneLeaseService["assertMutationAuthority"]>;
  readonly now?: () => Date;
}

/**
 * Autonomous result-aware boundary for exactly one anonymous NetExec SMB
 * summary. It re-reads the canonical action, signed contract, current scope,
 * assignment, and tool policy immediately before spawn. Raw output becomes an
 * Engagement Log record and parsed statements remain unverified observations;
 * this port has no evidence-promotion path.
 */
export class WindowsIdentityAutonomousExecutionPort
  implements ResultAwareExecutionPort {
  private readonly actions: ActionRepository;
  private readonly runs: RunRepository;
  private readonly clock: () => Date;
  private resultSink?: ExecutionResultSink;
  private readonly terminalInProgress = new Set<string>();
  private readonly activeInvocations = new Map<string, Readonly<{
    runId: string;
    controller: AbortController;
  }>>();

  constructor(private readonly options: WindowsIdentityAutonomousExecutionPortOptions) {
    this.actions = new ActionRepository(options.database);
    this.runs = new RunRepository(options.database);
    this.clock = options.now ?? (() => new Date());
  }

  bindResultSink(sink: ExecutionResultSink): () => void {
    if (this.resultSink) {
      throw new Error("Autonomous Windows/identity result sink is already bound");
    }
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
          "windows_identity_autonomous_not_approved",
          "policy_denied",
          "Ti-Scale no longer holds this Autonomous run's control-plane authority.",
          false,
        );
      }
      throw error;
    }
  }

  private canonical(input: DurableAction): CanonicalAutonomousIdentityAction {
    const action = this.actions.get(input.id);
    if (digestCanonicalJson(action, {
      maxBytes: 1_024 * 1_024,
      maxDepth: 64,
    }).sha256 !== digestCanonicalJson(input, {
      maxBytes: 1_024 * 1_024,
      maxDepth: 64,
    }).sha256
      || action.status !== "running"
      || action.kind !== "tool"
      || action.actionType !== AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID
      || action.actionClass !== AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_tool_identity_changed",
        "policy_denied",
        "Only the exact running canonical anonymous NetExec action may enter Autonomous execution.",
      );
    }
    const envelope = reviewedLocalToolActionEnvelope(action.arguments);
    if (!envelope
      || envelope.toolId !== AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID
      || !exactKeys(envelope.parameters, [
        "authenticationMode",
        "operation",
        "target",
        "workspace",
      ])
      || envelope.parameters.authenticationMode !== "anonymous"
      || envelope.parameters.operation !== "smb_identity_summary"
      || envelope.parameters.target !== action.target
      || typeof envelope.parameters.workspace !== "string") {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_request_invalid",
        "invalid_input",
        "The persisted Autonomous NetExec action envelope is not canonical.",
      );
    }
    this.assertAuthority(action.runId);
    const allowed = this.runs.authorizePersistedLocalTool(
      this.runs.get(action.runId),
      action,
      AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
    );
    if (!allowed.allowed) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_autonomous_not_approved",
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
    if (!relation
      || relation.agent_id !== AUTONOMOUS_WINDOWS_IDENTITY_PRODUCT_AGENT_ID) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_autonomous_not_approved",
        "policy_denied",
        "The active plan no longer assigns this identity action to ADAttackMapper.",
      );
    }
    return {
      action,
      planId: relation.plan_id,
      planVersion: relation.plan_version,
      agentId: relation.agent_id,
      logicalWorkspace: envelope.parameters.workspace,
    };
  }

  private compile(input: DurableAction) {
    const canonical = this.canonical(input);
    const run = this.runs.get(canonical.action.runId);
    if (!run.contractId || canonical.action.contractId !== run.contractId) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_autonomous_not_approved",
        "policy_denied",
        "The action is not bound to the run's current signed Autonomous contract.",
      );
    }
    const contract = this.options.database.prepare(`
      SELECT version, state, action_policy_json
      FROM mission_contracts WHERE id = ?
    `).get(run.contractId) as {
      version: number;
      state: string;
      action_policy_json: string;
    } | undefined;
    if (!contract || contract.state !== "confirmed"
      || contract.version !== run.run.contractVersion) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_autonomous_not_approved",
        "policy_denied",
        "The current Autonomous contract is missing, unconfirmed, or version-mismatched.",
      );
    }
    let policy: Readonly<Record<string, unknown>>;
    try {
      const parsed = JSON.parse(contract.action_policy_json) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("not an object");
      }
      policy = parsed as Readonly<Record<string, unknown>>;
    } catch {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_autonomous_not_approved",
        "policy_denied",
        "The signed Autonomous action policy is malformed.",
      );
    }
    const targets = this.options.database.prepare(`
      SELECT target, disposition FROM mission_targets
      WHERE mission_id = ? ORDER BY id
    `).all(canonical.action.missionId) as Array<{
      target: string;
      disposition: "allowed" | "prohibited";
    }>;
    const mission = this.options.database.prepare(`
      SELECT authorization_status FROM missions WHERE id = ?
    `).get(canonical.action.missionId) as {
      authorization_status: string;
    } | undefined;
    const allowedActionClasses = stringArray(policy.allowedActionClasses);
    const prohibitedActionClasses = stringArray(policy.prohibitedActionClasses);
    const persistedAction = {
      missionId: canonical.action.missionId,
      runId: canonical.action.runId,
      stepId: canonical.action.stepId,
      planVersion: canonical.planVersion,
      actionType: canonical.action.actionType,
      actionClass: canonical.action.actionClass,
      target: canonical.action.target,
      arguments: canonical.action.arguments,
    };
    const invocation = this.options.pack.compile({
      request: {
        schemaVersion: "ti-scale.windows-identity-action.v1",
        missionId: canonical.action.missionId,
        runId: canonical.action.runId,
        stepId: canonical.action.stepId,
        planVersion: canonical.planVersion,
        journey: "autonomous",
        operation: "smb_identity_summary",
        target: canonical.action.target,
        logicalWorkspace: canonical.logicalWorkspace,
        authenticationMode: "anonymous",
        credentialReference: null,
      },
      persistedAction,
      missionBoundary: {
        authorizationVerified: mission?.authorization_status === "verified",
        allowedTargets: targets
          .filter(({ disposition }) => disposition === "allowed")
          .map(({ target }) => target),
        prohibitedTargets: targets
          .filter(({ disposition }) => disposition === "prohibited")
          .map(({ target }) => target),
        allowedActionClassIds: allowedActionClasses,
        prohibitedActionClassIds: prohibitedActionClasses,
        guidedDecision: null,
        autonomousContract: {
          runId: canonical.action.runId,
          version: contract.version,
          status: "signed",
          allowedActionTypes: allowedActionClasses,
          prohibitedActionTypes: prohibitedActionClasses,
          allowedTargets: targets
            .filter(({ disposition }) => disposition === "allowed")
            .map(({ target }) => target),
        },
      },
      credentialBindingReceipt: null,
      now: this.clock(),
    });
    if (invocation.actionFingerprint !== canonical.action.fingerprint) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_tool_identity_changed",
        "policy_denied",
        "The compiled anonymous NetExec invocation differs from the exact persisted action.",
      );
    }
    return { canonical, invocation };
  }

  async dispatch(action: DurableAction, signal: AbortSignal): Promise<void> {
    await this.start(action, signal, false);
  }

  async resume(action: DurableAction, signal: AbortSignal): Promise<void> {
    if (!action.idempotent || action.destructive) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_autonomous_not_approved",
        "policy_denied",
        "Only the idempotent, non-destructive anonymous SMB summary may resume.",
      );
    }
    // Resume is not a weaker entry point. Re-read the canonical action,
    // contract, scope, assignment, and current specialist policy before
    // replaying or replacing any prior terminal delivery.
    this.canonical(action);
    const pending = this.options.database.prepare(`
      SELECT id, status, redacted_payload_json FROM tool_calls
      WHERE action_id = ? AND provider = ?
        AND status IN ('succeeded', 'failed', 'timed_out', 'cancelled')
      ORDER BY ended_at DESC, id DESC LIMIT 1
    `).get(action.id, PROVIDER) as {
      id: string;
      status: "succeeded" | "failed" | "timed_out" | "cancelled";
      redacted_payload_json: string | null;
    } | undefined;
    const payload = parseDelivery(pending?.redacted_payload_json ?? null);
    if (pending?.status === "cancelled") return;
    if (pending) {
      if (!payload) {
        throw new WindowsIdentityBoundaryError(
          "windows_identity_tool_identity_changed",
          "policy_denied",
          "The committed Windows/identity terminal result is malformed; "
            + "operator reconciliation is required and the target will not "
            + "be contacted again for this action.",
        );
      }
      if (!payload.resultAccepted) await this.deliver(pending.id, payload);
      return;
    }
    this.options.database.prepare(`
      UPDATE tool_calls SET status = 'cancelled', output_summary = ?,
        ended_at = ?
      WHERE action_id = ? AND provider = ? AND status = 'running'
    `).run(
      "The previous worker ended before accepting a result; the bounded idempotent read is being resumed.",
      this.clock().toISOString(),
      action.id,
      PROVIDER,
    );
    await this.start(action, signal, true);
  }

  private async start(
    action: DurableAction,
    signal: AbortSignal,
    resumed: boolean,
  ): Promise<void> {
    if (!this.resultSink) {
      throw new WindowsIdentityBoundaryError(
        "windows_identity_adapter_not_bounded",
        "policy_denied",
        "The Autonomous mission result sink is not bound.",
      );
    }
    const prepared = this.compile(action);
    const invocationId =
      `autonomous_windows_identity_${randomUUID()}`;
    const startedAt = this.clock().toISOString();
    this.options.database.prepare(`
      INSERT INTO tool_calls (
        id, action_id, provider, tool_name, mcp_server_id,
        normalized_arguments_json, status, started_at, created_at
      ) VALUES (?, ?, ?, ?, NULL, ?, 'running', ?, ?)
    `).run(
      invocationId,
      action.id,
      PROVIDER,
      AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
      JSON.stringify({
        schemaVersion: "ti-scale.reviewed-local-tool-action.v1",
        executionBinding: "reviewed_local_process",
        toolId: AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
        parameters: {
          authenticationMode: "anonymous",
          operation: "smb_identity_summary",
          target: prepared.canonical.action.target,
          workspace: prepared.canonical.logicalWorkspace,
        },
        actionFingerprint: prepared.invocation.actionFingerprint,
        resumed,
      }),
      startedAt,
      startedAt,
    );
    const controller = new AbortController();
    const effectiveSignal = AbortSignal.any([signal, controller.signal]);
    if (effectiveSignal.aborted) {
      this.acceptCancellation(
        invocationId,
        "The reviewed anonymous NetExec process was cancelled before target contact.",
      );
      return;
    }
    const active = Object.freeze({
      runId: action.runId,
      controller,
    });
    this.activeInvocations.set(invocationId, active);
    void this.options.adapter.execute(prepared.invocation, effectiveSignal).then(
      (raw) => this.acceptResult(
        invocationId,
        prepared.canonical,
        normalizeWindowsIdentityResult(raw),
        effectiveSignal,
      ),
      (error) => this.acceptAdapterFailure(
        invocationId,
        prepared.canonical,
        error,
        effectiveSignal,
      ),
    ).finally(() => {
      if (this.activeInvocations.get(invocationId) === active) {
        this.activeInvocations.delete(invocationId);
      }
    });
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    for (const active of this.activeInvocations.values()) {
      if (active.runId === runId) active.controller.abort(new Error(reason));
    }
    await this.options.adapter.cancelRun(runId, reason);
    this.options.database.prepare(`
      UPDATE tool_calls SET status = 'cancelled', error_category = NULL,
        output_summary = ?, ended_at = ?
      WHERE provider = ? AND status = 'running' AND action_id IN (
        SELECT id FROM actions WHERE run_id = ?
      )
    `).run(
      "Run cancellation terminated the reviewed anonymous NetExec process before a result was accepted.",
      this.clock().toISOString(),
      PROVIDER,
      runId,
    );
  }

  private acceptCancellation(invocationId: string, summary: string): void {
    if (this.terminalInProgress.has(invocationId)) return;
    this.terminalInProgress.add(invocationId);
    try {
      this.options.database.prepare(`
        UPDATE tool_calls SET status = 'cancelled', error_category = NULL,
          output_summary = ?, redacted_payload_json = NULL, ended_at = ?
        WHERE id = ? AND provider = ? AND status = 'running'
      `).run(
        summary.slice(0, 1_000),
        this.clock().toISOString(),
        invocationId,
        PROVIDER,
      );
    } finally {
      this.terminalInProgress.delete(invocationId);
    }
  }

  private async acceptResult(
    invocationId: string,
    canonical: CanonicalAutonomousIdentityAction,
    normalized: WindowsIdentityNormalizedResult,
    signal: AbortSignal,
  ): Promise<void> {
    if (signal.aborted || normalized.status === "cancelled") {
      this.acceptCancellation(invocationId, normalized.summary);
      return;
    }
    if (
      normalized.toolId !== AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID
      || normalized.actionFingerprint !== canonical.action.fingerprint
    ) {
      await this.acceptAdapterFailure(
        invocationId,
        canonical,
        new WindowsIdentityBoundaryError(
          "windows_identity_tool_identity_changed",
          "policy_denied",
          "The NetExec result did not match the exact persisted Autonomous action.",
        ),
        signal,
      );
      return;
    }
    if (this.terminalInProgress.has(invocationId)) return;
    this.terminalInProgress.add(invocationId);
    try {
      const now = this.clock().toISOString();
      const logRecordId = `log_${randomUUID()}`;
      const observationIds =
        normalized.observations.map(() => `observation_${randomUUID()}`);
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
          ...(normalized.failure
            ? { failureCategory: normalized.failure.category }
            : {}),
          circuitKey: `windows-identity:${AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID}`,
        } : {}),
      };
      const payload: PersistedDeliveryPayload = {
        schemaVersion: DELIVERY_SCHEMA,
        executionResult,
        logRecordId,
        observationIds,
        evidenceCandidateIds: [],
        deliveryState: "pending",
        resultAccepted: false,
        duplicateResult: false,
        deliveryAttemptCount: 0,
        deliveryLastAttemptAt: null,
        deliveryLastError: null,
        deliveryTerminalMessage: null,
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
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unverified', ?, ?, ?, ?,
              'restricted', ?)
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
              observation_id, log_record_id, parser_id, parser_version,
              created_at
            ) VALUES (?, ?, 'ti-scale.windows-identity-normalizer', ?, ?)
          `).run(
            observationId,
            logRecordId,
            normalized.schemaVersion,
            now,
          );
        });
        this.options.database.prepare(`
          UPDATE tool_calls SET status = ?, error_category = ?,
            output_summary = ?, redacted_payload_json = ?, ended_at = ?
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
      if (committed && !signal.aborted) {
        await this.deliver(invocationId, payload);
      }
    } finally {
      this.terminalInProgress.delete(invocationId);
    }
  }

  private async acceptAdapterFailure(
    invocationId: string,
    canonical: CanonicalAutonomousIdentityAction,
    error: unknown,
    signal: AbortSignal,
  ): Promise<void> {
    if (signal.aborted || adapterCancellation(error)) {
      this.acceptCancellation(
        invocationId,
        "The reviewed anonymous NetExec process was cancelled before a result was accepted.",
      );
      return;
    }
    if (this.terminalInProgress.has(invocationId)) return;
    this.terminalInProgress.add(invocationId);
    try {
    const failure = error instanceof WindowsIdentityBoundaryError
      ? error
      : new WindowsIdentityBoundaryError(
          "windows_identity_tool_deterministic_error",
          "deterministic_tool_error",
          "The reviewed anonymous NetExec adapter failed after accepting the exact action.",
        );
    const now = this.clock().toISOString();
    const logRecordId = `log_${randomUUID()}`;
    const executionResult: ExecutionResult = {
      actionId: canonical.action.id,
      runId: canonical.action.runId,
      actionFingerprint: canonical.action.fingerprint,
      success: false,
      summary: failure.message,
      progress: {},
      failure: {
        source: "tool",
        code: failure.code,
        message: failure.message,
      },
      failureCategory: failure.category,
      circuitKey: `windows-identity:${AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID}`,
    };
    const payload: PersistedDeliveryPayload = {
      schemaVersion: DELIVERY_SCHEMA,
      executionResult,
      logRecordId,
      observationIds: [],
      evidenceCandidateIds: [],
      deliveryState: "pending",
      resultAccepted: false,
      duplicateResult: false,
      deliveryAttemptCount: 0,
      deliveryLastAttemptAt: null,
      deliveryLastError: null,
      deliveryTerminalMessage: null,
    };
    const technicalPayload = JSON.stringify({
      schemaVersion: "ti-scale.windows-identity-adapter-failure.v1",
      code: failure.code,
      category: failure.category,
      retryable: failure.retryable,
      evidencePromotion: "none",
    });
    const committed = inImmediateTransaction(this.options.database, () => {
      const current = this.options.database.prepare(`
        SELECT status FROM tool_calls WHERE id = ? AND provider = ?
      `).get(invocationId, PROVIDER) as { status: string } | undefined;
      if (current?.status !== "running") return false;
      this.options.database.prepare(`
        INSERT INTO engagement_log_records (
          id, mission_id, run_id, plan_id, step_id, action_id,
          agent_id, tool_call_id, severity, domain, record_type,
          human_summary, technical_payload_json, content_hash,
          sensitivity, occurred_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'error', 'windows_identity',
          'tool_failure', ?, ?, ?, 'restricted', ?, ?)
      `).run(
        logRecordId,
        canonical.action.missionId,
        canonical.action.runId,
        canonical.planId,
        canonical.action.stepId,
        canonical.action.id,
        canonical.agentId,
        invocationId,
        failure.message,
        technicalPayload,
        createHash("sha256").update(technicalPayload).digest("hex"),
        now,
        now,
      );
      this.options.database.prepare(`
        UPDATE tool_calls SET status = ?, error_category = ?,
          output_summary = ?, redacted_payload_json = ?, ended_at = ?
        WHERE id = ? AND provider = ? AND status = 'running'
      `).run(
        failure.category === "timeout" ? "timed_out" : "failed",
        failure.category,
        failure.message,
        JSON.stringify(payload),
        now,
        invocationId,
        PROVIDER,
      );
      return true;
    });
    if (committed && !signal.aborted) {
      await this.deliver(invocationId, payload);
    }
    } finally {
      this.terminalInProgress.delete(invocationId);
    }
  }

  private updateDelivery(
    invocationId: string,
    payload: PersistedDeliveryPayload,
  ): void {
    if (payload.deliveryState === "retry_exhausted"
      && payload.deliveryTerminalMessage) {
      this.options.database.prepare(`
        UPDATE tool_calls SET redacted_payload_json = ?, output_summary = ?
        WHERE id = ? AND provider = ?
          AND status IN ('succeeded', 'failed', 'timed_out')
      `).run(
        JSON.stringify(payload),
        `${payload.executionResult.summary} ${payload.deliveryTerminalMessage}`,
        invocationId,
        PROVIDER,
      );
      return;
    }
    this.options.database.prepare(`
      UPDATE tool_calls SET redacted_payload_json = ?
      WHERE id = ? AND provider = ?
        AND status IN ('succeeded', 'failed', 'timed_out')
    `).run(JSON.stringify(payload), invocationId, PROVIDER);
  }

  private async deliver(
    invocationId: string,
    payload: PersistedDeliveryPayload,
  ): Promise<boolean> {
    if (payload.resultAccepted || payload.deliveryState !== "pending"
      || payload.deliveryAttemptCount >= DELIVERY_ATTEMPT_LIMIT) {
      return payload.resultAccepted;
    }
    const sink = this.resultSink;
    if (!sink) return false;
    const attemptedAt = this.clock().toISOString();
    try {
      const receipt: ExecutionResultReceipt =
        await sink.acceptExecutionResult(payload.executionResult);
      const accepted = receipt.accepted
        && receipt.actionId === payload.executionResult.actionId
        && receipt.runId === payload.executionResult.runId;
      const deliveryAttemptCount = payload.deliveryAttemptCount + 1;
      const retryExhausted =
        !accepted && deliveryAttemptCount >= DELIVERY_ATTEMPT_LIMIT;
      this.updateDelivery(invocationId, {
        ...payload,
        deliveryState: accepted
          ? "accepted"
          : retryExhausted
            ? "retry_exhausted"
            : "pending",
        resultAccepted: accepted,
        duplicateResult: accepted ? receipt.duplicate : false,
        deliveryAttemptCount,
        deliveryLastAttemptAt: attemptedAt,
        deliveryLastError:
          accepted ? null : "runtime_result_receipt_rejected",
        deliveryTerminalMessage:
          retryExhausted ? deliveryRetryExhaustedMessage() : null,
      });
      return accepted;
    } catch {
      const deliveryAttemptCount = payload.deliveryAttemptCount + 1;
      const retryExhausted =
        deliveryAttemptCount >= DELIVERY_ATTEMPT_LIMIT;
      this.updateDelivery(invocationId, {
        ...payload,
        deliveryState: retryExhausted ? "retry_exhausted" : "pending",
        resultAccepted: false,
        duplicateResult: false,
        deliveryAttemptCount,
        deliveryLastAttemptAt: attemptedAt,
        deliveryLastError: "runtime_result_delivery_failed",
        deliveryTerminalMessage:
          retryExhausted ? deliveryRetryExhaustedMessage() : null,
      });
      return false;
    }
  }

  async replayPendingResults(limit = 100): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new RangeError(
        "Pending Autonomous Windows/identity result replay limit must be 1-1000",
      );
    }
    if (!this.resultSink) return 0;
    const rows = this.options.database.prepare(`
      SELECT id, redacted_payload_json FROM tool_calls
      WHERE provider = ? AND status IN ('succeeded', 'failed', 'timed_out')
        AND COALESCE(
          json_extract(redacted_payload_json, '$.resultAccepted'), 0
        ) = 0
        AND COALESCE(
          json_extract(redacted_payload_json, '$.deliveryState'), 'pending'
        ) = 'pending'
        AND COALESCE(
          json_extract(redacted_payload_json, '$.deliveryAttemptCount'), 0
        ) < ?
      ORDER BY ended_at, id LIMIT ?
    `).all(PROVIDER, DELIVERY_ATTEMPT_LIMIT, limit) as Array<{
      id: string;
      redacted_payload_json: string | null;
    }>;
    let delivered = 0;
    for (const row of rows) {
      const payload = parseDelivery(row.redacted_payload_json);
      if (payload && await this.deliver(row.id, payload)) delivered += 1;
    }
    return delivered;
  }
}

class AutonomousWindowsIdentityCompositeExecutionPort
  implements ResultAwareExecutionPort {
  private baseUnbind?: () => void;
  private identityUnbind?: () => void;

  constructor(
    private readonly base: ResultAwareExecutionPort,
    private readonly identity: WindowsIdentityAutonomousExecutionPort,
  ) {}

  bindResultSink(sink: ExecutionResultSink): () => void {
    this.baseUnbind = this.base.bindResultSink?.(sink) as (() => void) | undefined;
    try {
      this.identityUnbind = this.identity.bindResultSink(sink);
    } catch (error) {
      this.baseUnbind?.();
      this.baseUnbind = undefined;
      throw error;
    }
    return () => {
      this.baseUnbind?.();
      this.identityUnbind?.();
      this.baseUnbind = undefined;
      this.identityUnbind = undefined;
    };
  }

  dispatch(action: DurableAction, signal: AbortSignal): Promise<void> {
    return action.actionType === AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID
      ? this.identity.dispatch(action, signal)
      : this.base.dispatch(action, signal);
  }

  resume(action: DurableAction, signal: AbortSignal): Promise<void> {
    return action.actionType === AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID
      ? this.identity.resume(action, signal)
      : this.base.resume(action, signal);
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    await Promise.all([
      this.base.cancelRun(runId, reason),
      this.identity.cancelRun(runId, reason),
    ]);
  }

  async replayPendingResults(limit = 100): Promise<number> {
    const [base, identity] = await Promise.all([
      this.base.replayPendingResults?.(limit) ?? 0,
      this.identity.replayPendingResults(limit),
    ]);
    return base + identity;
  }
}

export class AutonomousWindowsIdentityExecutionFactory
  implements ProductionAutonomousLocalProcessExecutionFactory {
  readonly localProcessContract =
    AUTONOMOUS_WINDOWS_IDENTITY_EXECUTION_CONTRACT;
  #created = false;
  readonly #delegatedContract:
    ProductionAutonomousLocalProcessExecutionFactory["localProcessContract"];

  constructor(
    private readonly baseFactory: ProductionAutonomousLocalProcessExecutionFactory,
    private readonly options: Readonly<{
      pack: WindowsIdentityToolPack;
      adapter: WindowsIdentityExecutionAdapter;
      now?: () => Date;
    }>,
  ) {
    this.#delegatedContract =
      assertDelegatedLocalProcessFactory(baseFactory);
  }

  create(input: Readonly<{
    database: SqliteDatabase;
    assertControlPlaneAuthority: (
      runId: string,
    ) => ReturnType<ControlPlaneLeaseService["assertMutationAuthority"]>;
  }>): ResultAwareExecutionPort {
    if (this.#created) {
      throw new Error(
        "Autonomous Windows/identity execution factory is single-use",
      );
    }
    if (
      assertDelegatedLocalProcessFactory(this.baseFactory)
        !== this.#delegatedContract
    ) {
      throw new TypeError(
        "Autonomous Windows/identity composition rejected a changed delegated local-process execution contract",
      );
    }
    const base = this.baseFactory.create(input);
    const identity = new WindowsIdentityAutonomousExecutionPort({
      database: input.database,
      pack: this.options.pack,
      adapter: this.options.adapter,
      assertControlPlaneAuthority: input.assertControlPlaneAuthority,
      ...(this.options.now ? { now: this.options.now } : {}),
    });
    this.#created = true;
    return new AutonomousWindowsIdentityCompositeExecutionPort(base, identity);
  }

  close(): void {
    (this.baseFactory as { close?: () => void }).close?.();
  }
}

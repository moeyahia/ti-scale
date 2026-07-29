import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
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
} from "../command-runtime/types";
import {
  ControlPlaneLeaseService,
  type ControlPlaneLease,
} from "../control-plane";
import {
  digestCanonicalJson,
  isMcpAttestationIntegrityValid,
  type McpCapabilityAttestation,
} from "../mcp";
import {
  FailureDiagnosisService,
  type CreateFailureDiagnosisInput,
  type FailureDiagnosis,
  type FailureOperatorAction,
} from "../intelligence-v24";
import {
  EngagementWorkspaceResolver,
  ToolExecutionPreflightService,
  mcpToolFailureDiagnosisInput,
  preflightMcpToolInvocation,
  toolPreflightFailureDiagnosisInput,
  type McpToolFailureSignal,
  type McpToolInvocationPreflightResult,
  type ToolExecutionPreflightSpec,
} from "../system-capabilities";

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const SETTING_PREFIX = "idempotency.specialist-tool-dispatch.";

export interface SpecialistLocalToolBinding {
  /** Trusted executable binding; workingDirectory is always resolved per action. */
  readonly preflight: Omit<ToolExecutionPreflightSpec, "workingDirectory">;
  /** Exact top-level MCP parameter containing the stable logical workspace path. */
  readonly logicalWorkspaceParameter: string;
}

export interface SpecialistMcpToolBinding {
  readonly serverId: string;
  readonly toolName: string;
  readonly attestation: McpCapabilityAttestation;
  readonly localTool?: SpecialistLocalToolBinding;
}

export interface SpecialistToolInvocation {
  readonly invocationId: string;
  readonly action: DurableAction;
  readonly binding: SpecialistMcpToolBinding;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly inputSha256: string;
  readonly resolvedWorkspacePath?: string;
}

export const SPECIALIST_TOOL_ADAPTER_CONTRACT_SCHEMA_VERSION =
  "ti-scale.specialist-tool-invocation-adapter.v1" as const;

/**
 * Code-reviewed transport contract. These declarations do not grant runtime
 * authority; SpecialistToolDispatchService still revalidates the canonical
 * action, lease, assignment, policy, MCP inventory, schema, and local tool
 * preflight immediately before dispatch.
 */
export interface SpecialistToolInvocationAdapterContract {
  readonly schemaVersion: typeof SPECIALIST_TOOL_ADAPTER_CONTRACT_SCHEMA_VERSION;
  readonly adapterId: string;
  readonly toolSelection: "exact_persisted_binding_only";
  readonly resultDelivery: "bound_execution_result_sink";
  readonly cancellation: "run_scoped_cooperative";
  readonly shellInterpolation: false;
  readonly publicProviderToolExecution: false;
}

export interface SpecialistToolInvocationResult {
  readonly invocationId: string;
  readonly result: ExecutionResult;
}

export interface SpecialistToolInvocationResultSink {
  acceptSpecialistToolResult(
    result: SpecialistToolInvocationResult,
  ): Promise<ExecutionResultReceipt>;
}

/**
 * The adapter owns transport only. It receives no authority to select another
 * target, server, tool, schema, executable, or workspace.
 */
export interface SpecialistToolInvocationAdapter {
  readonly contract: SpecialistToolInvocationAdapterContract;
  /** Required terminal callback; accepted dispatch without result delivery is not executable. */
  bindResultSink(
    sink: SpecialistToolInvocationResultSink,
  ): void | (() => void);
  dispatch(invocation: SpecialistToolInvocation, signal: AbortSignal): Promise<void>;
  resume?(invocation: SpecialistToolInvocation, signal: AbortSignal): Promise<void>;
  cancelRun(runId: string, reason: string): Promise<void>;
}

export class SpecialistToolAdapterError extends Error {
  constructor(
    message: string,
    readonly failure: McpToolFailureSignal,
  ) {
    super(message);
    this.name = "SpecialistToolAdapterError";
  }
}

export type SpecialistToolDispatchErrorCode =
  | "action_not_canonical"
  | "action_not_running"
  | "action_binding_invalid"
  | "binding_unavailable"
  | "binding_attestation_invalid"
  | "control_plane_authority_invalid"
  | "specialist_tool_policy_denied"
  | "dispatch_rejected"
  | "dispatch_already_in_progress"
  | "unchanged_request_suppressed"
  | "resume_not_safe"
  | "result_sink_unbound"
  | "result_binding_invalid";

export class SpecialistToolDispatchError extends Error {
  constructor(
    readonly code: SpecialistToolDispatchErrorCode,
    message: string,
    readonly options: Readonly<{
      retryable: boolean;
      diagnosisId?: string;
      toolCallId?: string;
    }> = { retryable: false },
  ) {
    super(message);
    this.name = "SpecialistToolDispatchError";
  }
}

interface DispatchRecord {
  readonly schemaVersion: "ti-scale.specialist-tool-dispatch-record.v1";
  readonly state: "reserved" | "accepted" | "failed_deterministic" | "failed_transient";
  readonly requestSha256: string;
  readonly actionId: string;
  readonly toolCallId: string;
  readonly diagnosisId: string | null;
  readonly updatedAt: string;
}

interface PreparedInvocation {
  readonly action: DurableAction;
  readonly binding: SpecialistMcpToolBinding;
  readonly preflight: McpToolInvocationPreflightResult;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly resolvedWorkspacePath?: string;
  readonly suppressionKey: string;
  readonly requestSha256: string;
  readonly toolCallId: string;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function plainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function assertSpecialistToolInvocationAdapterContract(
  contract: SpecialistToolInvocationAdapterContract,
): void {
  if (!plainRecord(contract)) throw new Error("Specialist adapter contract must be a plain object");
  const keys = Object.keys(contract).sort();
  const expected = [
    "adapterId",
    "cancellation",
    "publicProviderToolExecution",
    "resultDelivery",
    "schemaVersion",
    "shellInterpolation",
    "toolSelection",
  ].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error(`Specialist adapter contract must contain exactly: ${expected.join(", ")}`);
  }
  if (
    contract.schemaVersion !== SPECIALIST_TOOL_ADAPTER_CONTRACT_SCHEMA_VERSION
    || !PUBLIC_ID.test(contract.adapterId)
    || contract.toolSelection !== "exact_persisted_binding_only"
    || contract.resultDelivery !== "bound_execution_result_sink"
    || contract.cancellation !== "run_scoped_cooperative"
    || contract.shellInterpolation !== false
    || contract.publicProviderToolExecution !== false
  ) {
    throw new Error("Specialist adapter contract does not satisfy the exact production boundary");
  }
}

function parseDispatchRecord(value: string): DispatchRecord {
  const parsed = JSON.parse(value) as unknown;
  if (
    !plainRecord(parsed)
    || parsed.schemaVersion !== "ti-scale.specialist-tool-dispatch-record.v1"
    || !["reserved", "accepted", "failed_deterministic", "failed_transient"].includes(String(parsed.state))
    || typeof parsed.requestSha256 !== "string"
    || typeof parsed.actionId !== "string"
    || typeof parsed.toolCallId !== "string"
    || !(parsed.diagnosisId === null || typeof parsed.diagnosisId === "string")
    || typeof parsed.updatedAt !== "string"
  ) throw new Error("Stored specialist dispatch record is invalid");
  return parsed as unknown as DispatchRecord;
}

function correctionActions(): readonly FailureOperatorAction[] {
  return [
    {
      kind: "configure_dependency",
      label: "Restore the exact specialist binding",
      consequence: "Re-attests the existing MCP server, tool schema, local executable, and workspace without broadening mission scope.",
      requiresConfirmation: true,
    },
    {
      kind: "use_compatible_fallback",
      label: "Use a reviewed compatible specialist tool",
      consequence: "Changes the binding only after the alternative passes current policy, schema, executable, and workspace checks.",
      requiresConfirmation: true,
    },
    {
      kind: "amend_plan",
      label: "Amend the affected step",
      consequence: "Creates a new versioned action with materially corrected parameters.",
      requiresConfirmation: true,
    },
  ];
}

function boundaryFailure(input: {
  readonly action: DurableAction;
  readonly code: string;
  readonly humanReason: string;
  readonly category: "dependency_missing" | "invalid_input" | "policy_denied" | "restart_recovery_required";
  readonly failedComponentRef: string;
  readonly remediation: string;
  readonly actorId: string;
}): CreateFailureDiagnosisInput {
  return {
    missionId: input.action.missionId,
    runId: input.action.runId,
    stepId: input.action.stepId,
    actionId: input.action.id,
    subjectType: "action",
    subjectId: input.action.id,
    humanReason: input.humanReason,
    category: input.category,
    code: input.code,
    originatingComponent: "specialist-tool-dispatch",
    failedComponentRef: input.failedComponentRef,
    targetSummary: `Authorized target ${input.action.target}; no accepted tool result was recorded.`,
    policyOrDependency: "Current V2 control-plane authority, specialist assignment, target policy, exact MCP attestation, and local tool readiness are all mandatory.",
    retryHistory: [],
    progressBeforeFailure: { targetContact: false, acceptedToolResult: false },
    preservedReferences: [],
    retryable: false,
    automaticRecovery: {
      attempted: false,
      repeatedUnchangedDispatchSuppressed: true,
    },
    remediation: input.remediation,
    operatorActions: correctionActions(),
    objectiveImpact: "The affected action did not receive a valid result. Prior mission state, evidence, and artifacts remain preserved.",
    actor: { id: input.actorId, type: "system" },
  };
}

function exactAction(left: DurableAction, right: DurableAction): boolean {
  return left.id === right.id
    && left.missionId === right.missionId
    && left.runId === right.runId
    && left.stepId === right.stepId
    && left.fingerprint === right.fingerprint
    && left.actionType === right.actionType
    && left.actionClass === right.actionClass
    && left.target === right.target
    && left.kind === right.kind
    && left.status === right.status
    && left.guidedDecisionId === right.guidedDecisionId
    && left.contractId === right.contractId
    && digestCanonicalJson(
      left.runtimeModelBinding,
      { maxBytes: 16_384, maxDepth: 16 },
    ).sha256 === digestCanonicalJson(
      right.runtimeModelBinding,
      { maxBytes: 16_384, maxDepth: 16 },
    ).sha256
    && digestCanonicalJson(left.arguments, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      === digestCanonicalJson(right.arguments, { maxBytes: 1_048_576, maxDepth: 64 }).sha256;
}

export interface SpecialistToolDispatchServiceOptions {
  readonly database: SqliteDatabase;
  /** Trusted callback owned by MissionRuntimeEngine; raw lease tokens never enter this service. */
  readonly assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
  readonly resolveBinding: (
    serverId: string,
    toolName: string,
  ) => SpecialistMcpToolBinding | undefined;
  readonly adapter: SpecialistToolInvocationAdapter;
  readonly workspaceResolver: EngagementWorkspaceResolver;
  readonly toolPreflight?: ToolExecutionPreflightService;
  readonly actorId?: string;
  readonly now?: () => Date;
}

/**
 * Fail-closed ExecutionPort for specialist MCP tools. This service is additive
 * and intentionally unmounted until production supplies a real specialist
 * transport and a MissionRuntimeEngine-owned control-plane proof callback.
 */
export class SpecialistToolDispatchService implements ResultAwareExecutionPort {
  private readonly actions: ActionRepository;
  private readonly runs: RunRepository;
  private readonly leases: ControlPlaneLeaseService;
  private readonly failures: FailureDiagnosisService;
  private readonly toolPreflight: ToolExecutionPreflightService;
  private readonly now: () => Date;
  private readonly actorId: string;
  private resultSink?: ExecutionResultSink;
  private unbindAdapterResultSink?: () => void;

  constructor(private readonly options: SpecialistToolDispatchServiceOptions) {
    this.actions = new ActionRepository(options.database);
    this.runs = new RunRepository(options.database);
    this.leases = new ControlPlaneLeaseService(options.database);
    this.failures = new FailureDiagnosisService(options.database);
    this.toolPreflight = options.toolPreflight ?? new ToolExecutionPreflightService();
    this.now = options.now ?? (() => new Date());
    this.actorId = options.actorId?.trim() || "specialist-tool-dispatch";
    if (!PUBLIC_ID.test(this.actorId)) throw new Error("Specialist dispatch actor ID is invalid");
    assertSpecialistToolInvocationAdapterContract(options.adapter.contract);
  }

  private timestamp(): string {
    return this.now().toISOString();
  }

  private canonicalAction(input: DurableAction): DurableAction {
    const action = this.actions.get(input.id);
    if (!exactAction(action, input)) {
      throw new SpecialistToolDispatchError(
        "action_not_canonical",
        "The dispatch payload differs from the current canonical action.",
      );
    }
    if (action.status !== "running") {
      throw new SpecialistToolDispatchError(
        "action_not_running",
        "Only the exact currently running action may enter specialist dispatch.",
      );
    }
    return action;
  }

  private assertControlPlaneAuthority(runId: string): void {
    let proof: ControlPlaneLease;
    try {
      proof = this.options.assertControlPlaneAuthority(runId);
      const current = this.leases.assertCurrentLeaseProof(proof, this.now());
      if (current.runId !== runId || current.controlPlane !== "ti_scale") {
        throw new Error("wrong control plane");
      }
    } catch {
      throw new SpecialistToolDispatchError(
        "control_plane_authority_invalid",
        "The active Ti-Scale runtime could not prove current fenced control-plane authority for this run.",
      );
    }
  }

  private assertBaseAuthority(action: DurableAction): void {
    this.assertControlPlaneAuthority(action.runId);
    const authorization = this.runs.authorizePersistedAction(this.runs.get(action.runId), action);
    if (!authorization.allowed) {
      throw new SpecialistToolDispatchError(
        "specialist_tool_policy_denied",
        authorization.humanMessage,
      );
    }
  }

  private descriptor(action: DurableAction): Readonly<{
    serverId: string;
    toolName: string;
    arguments: Readonly<Record<string, unknown>>;
  }> {
    const keys = Object.keys(action.arguments).sort();
    const serverId = action.arguments.mcpServer;
    const toolName = action.arguments.toolName;
    const parameters = action.arguments.parameters;
    if (
      keys.length !== 3 || keys[0] !== "mcpServer" || keys[1] !== "parameters" || keys[2] !== "toolName"
      || typeof serverId !== "string" || !PUBLIC_ID.test(serverId)
      || typeof toolName !== "string" || !PUBLIC_ID.test(toolName)
      || !plainRecord(parameters)
    ) {
      throw new SpecialistToolDispatchError(
        "action_binding_invalid",
        "The tool action must contain only one exact MCP server, tool name, and parameter object.",
      );
    }
    return { serverId, toolName, arguments: parameters };
  }

  private binding(serverId: string, toolName: string): SpecialistMcpToolBinding {
    const binding = this.options.resolveBinding(serverId, toolName);
    if (!binding || binding.serverId !== serverId || binding.toolName !== toolName) {
      throw new SpecialistToolDispatchError(
        "binding_unavailable",
        "No reviewed specialist binding exists for the exact persisted MCP server and tool.",
      );
    }
    const attestation = binding.attestation;
    const matchingTools = attestation.tools.filter(({ name }) => name === toolName);
    const attestedAt = Date.parse(attestation.attestedAt);
    const expiresAt = Date.parse(attestation.expiresAt);
    const now = this.now().getTime();
    if (
      attestation.connectionId !== serverId
      || attestation.executionAuthorization !== "none"
      || !Number.isFinite(attestedAt)
      || !Number.isFinite(expiresAt)
      || attestedAt > now
      || expiresAt <= now
      || expiresAt <= attestedAt
      || !/^[a-f0-9]{64}$/u.test(attestation.configurationSha256)
      || !isMcpAttestationIntegrityValid(attestation)
      || matchingTools.length !== 1
    ) {
      throw new SpecialistToolDispatchError(
        "binding_attestation_invalid",
        "The exact MCP server/tool binding is missing a fresh, immutable capability attestation.",
      );
    }
    return binding;
  }

  private assertSpecialistPolicy(action: DurableAction, binding: SpecialistMcpToolBinding): void {
    const result = this.runs.authorizePersistedSpecialistTool(
      this.runs.get(action.runId),
      action,
      binding.serverId,
      binding.toolName,
    );
    if (!result.allowed) {
      throw new SpecialistToolDispatchError(
        "specialist_tool_policy_denied",
        result.humanMessage,
      );
    }
  }

  private suppression(input: {
    action: DurableAction;
    binding: SpecialistMcpToolBinding;
    preflight: McpToolInvocationPreflightResult;
  }): Readonly<{ key: string; requestSha256: string; toolCallId: string }> {
    const requestSha256 = sha256([
      input.action.runId,
      input.action.fingerprint,
      input.binding.attestation.configurationSha256,
      input.binding.attestation.manifestSha256,
      input.preflight.inputSchemaSha256,
      input.preflight.inputSha256 ?? input.preflight.code,
    ].join("\u0000"));
    return {
      key: `${SETTING_PREFIX}${requestSha256}`,
      requestSha256,
      toolCallId: `tool_call_${sha256(input.action.id).slice(0, 40)}`,
    };
  }

  private stored(key: string): DispatchRecord | undefined {
    const row = this.options.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(key) as { value_json: string } | undefined;
    return row ? parseDispatchRecord(row.value_json) : undefined;
  }

  private save(key: string, record: DispatchRecord): void {
    this.options.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', 1, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        value_json = excluded.value_json,
        version = settings.version + 1,
        updated_by = excluded.updated_by,
        updated_at = excluded.updated_at
    `).run(key, JSON.stringify(record), this.actorId, record.updatedAt);
  }

  private ensureToolCall(
    prepared: Pick<PreparedInvocation, "action" | "binding" | "preflight" | "toolCallId">,
    status: "queued" | "running" | "failed" | "denied",
    category?: string,
    summary?: string,
  ): void {
    const now = this.timestamp();
    const receipt = JSON.stringify({
      inputSha256: prepared.preflight.inputSha256,
      inputSchemaSha256: prepared.preflight.inputSchemaSha256,
      configurationSha256: prepared.binding.attestation.configurationSha256,
      manifestSha256: prepared.binding.attestation.manifestSha256,
    });
    this.options.database.prepare(`
      INSERT INTO tool_calls (
        id, action_id, provider, tool_name, mcp_server_id,
        normalized_arguments_json, status, error_category, output_summary,
        started_at, ended_at, created_at
      ) VALUES (?, ?, 'specialist-mcp', ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        status = excluded.status,
        error_category = excluded.error_category,
        output_summary = excluded.output_summary,
        started_at = coalesce(tool_calls.started_at, excluded.started_at),
        ended_at = excluded.ended_at
    `).run(
      prepared.toolCallId,
      prepared.action.id,
      prepared.binding.toolName,
      prepared.binding.serverId,
      receipt,
      status,
      category ?? null,
      summary ?? null,
      status === "queued" ? null : now,
      status === "failed" || status === "denied" ? now : null,
      now,
    );
  }

  private existingTerminalFailure(record: DispatchRecord): never {
    throw new SpecialistToolDispatchError(
      "unchanged_request_suppressed",
      "This unchanged tool request already has a deterministic failure diagnosis and will not be dispatched again.",
      {
        retryable: false,
        ...(record.diagnosisId ? { diagnosisId: record.diagnosisId } : {}),
        toolCallId: record.toolCallId,
      },
    );
  }

  private persistFailure(
    prepared: PreparedInvocation,
    input: CreateFailureDiagnosisInput,
    deterministic: boolean,
  ): FailureDiagnosis {
    return inImmediateTransaction(this.options.database, () => {
      this.assertBaseAuthority(prepared.action);
      const existing = this.stored(prepared.suppressionKey);
      if (existing?.state === "failed_deterministic") this.existingTerminalFailure(existing);
      const diagnosis = this.failures.create(input);
      this.ensureToolCall(
        prepared,
        input.category === "invalid_input" || input.category === "policy_denied" || input.category === "dependency_missing"
          ? "denied"
          : "failed",
        input.category,
        input.humanReason,
      );
      this.save(prepared.suppressionKey, {
        schemaVersion: "ti-scale.specialist-tool-dispatch-record.v1",
        state: deterministic ? "failed_deterministic" : "failed_transient",
        requestSha256: prepared.requestSha256,
        actionId: prepared.action.id,
        toolCallId: prepared.toolCallId,
        diagnosisId: diagnosis.id,
        updatedAt: this.timestamp(),
      });
      return diagnosis;
    });
  }

  private throwDiagnosis(diagnosis: FailureDiagnosis): never {
    throw new SpecialistToolDispatchError(
      "dispatch_rejected",
      diagnosis.humanReason,
      {
        retryable: diagnosis.retryable,
        diagnosisId: diagnosis.id,
        toolCallId: (this.options.database.prepare(`
          SELECT id FROM tool_calls WHERE action_id = ? ORDER BY created_at DESC, id DESC LIMIT 1
        `).get(diagnosis.actionId ?? "") as { id: string } | undefined)?.id,
      },
    );
  }

  private async prepare(input: DurableAction): Promise<PreparedInvocation> {
    const action = this.canonicalAction(input);
    this.assertBaseAuthority(action);
    const descriptor = this.descriptor(action);
    const binding = this.binding(descriptor.serverId, descriptor.toolName);
    this.assertSpecialistPolicy(action, binding);
    const preflight = preflightMcpToolInvocation({
      serverId: descriptor.serverId,
      requestedToolName: descriptor.toolName,
      attestedTool: binding.attestation.tools.find(({ name }) => name === descriptor.toolName)!,
      arguments: descriptor.arguments,
    });
    const suppression = this.suppression({ action, binding, preflight });
    const preparedBase = {
      action,
      binding,
      preflight,
      arguments: descriptor.arguments,
      suppressionKey: suppression.key,
      requestSha256: suppression.requestSha256,
      toolCallId: suppression.toolCallId,
    };
    if (preflight.status !== "ready") {
      const diagnosis = this.persistFailure(preparedBase, mcpToolFailureDiagnosisInput(
        preflight,
        { attemptCount: 1 },
        {
          missionId: action.missionId,
          runId: action.runId,
          stepId: action.stepId,
          actionId: action.id,
          actor: { id: this.actorId, type: "system" },
        },
      ), true);
      this.throwDiagnosis(diagnosis);
    }

    let resolvedWorkspacePath: string | undefined;
    if (binding.localTool) {
      const logicalWorkspace = descriptor.arguments[binding.localTool.logicalWorkspaceParameter];
      if (typeof logicalWorkspace !== "string") {
        const diagnosis = this.persistFailure(preparedBase, boundaryFailure({
          action,
          code: "logical_workspace_parameter_missing",
          humanReason: `The exact “${binding.localTool.logicalWorkspaceParameter}” workspace parameter is missing or invalid.`,
          category: "invalid_input",
          failedComponentRef: `${binding.serverId}/${binding.toolName}`,
          remediation: "Amend the represented action with one logical engagement path under a configured workspace mapping.",
          actorId: this.actorId,
        }), true);
        this.throwDiagnosis(diagnosis);
      }
      const workspace = await this.options.workspaceResolver.resolve(logicalWorkspace);
      if (workspace.status !== "resolved" || !workspace.resolvedPath) {
        const diagnosis = this.persistFailure(preparedBase, boundaryFailure({
          action,
          code: `workspace_${workspace.code}`,
          humanReason: workspace.explanation,
          category: "dependency_missing",
          failedComponentRef: binding.localTool.preflight.toolId,
          remediation: workspace.remediation ?? "Restore the reviewed engagement workspace before dispatch.",
          actorId: this.actorId,
        }), true);
        this.throwDiagnosis(diagnosis);
      }
      resolvedWorkspacePath = workspace.resolvedPath;
      const localPreflight = await this.toolPreflight.check({
        ...binding.localTool.preflight,
        workingDirectory: resolvedWorkspacePath,
      });
      if (localPreflight.status !== "ready") {
        const diagnosis = this.persistFailure(preparedBase, toolPreflightFailureDiagnosisInput(
          localPreflight,
          {
            missionId: action.missionId,
            runId: action.runId,
            stepId: action.stepId,
            actionId: action.id,
            actor: { id: this.actorId, type: "system" },
          },
        ), true);
        this.throwDiagnosis(diagnosis);
      }
    }
    return { ...preparedBase, ...(resolvedWorkspacePath ? { resolvedWorkspacePath } : {}) };
  }

  private reserve(prepared: PreparedInvocation): "reserved" | "replayed" {
    return inImmediateTransaction(this.options.database, () => {
      this.assertBaseAuthority(prepared.action);
      this.assertSpecialistPolicy(prepared.action, prepared.binding);
      const existing = this.stored(prepared.suppressionKey);
      if (existing) {
        if (existing.requestSha256 !== prepared.requestSha256) {
          throw new SpecialistToolDispatchError("dispatch_rejected", "The durable dispatch receipt conflicts with this request.");
        }
        if (existing.state === "failed_deterministic") this.existingTerminalFailure(existing);
        if (existing.state === "accepted" && existing.actionId === prepared.action.id) return "replayed";
        if (existing.state === "reserved") {
          throw new SpecialistToolDispatchError(
            "dispatch_already_in_progress",
            "The exact specialist tool request is already reserved; restart recovery must classify it before another dispatch.",
            { retryable: false, toolCallId: existing.toolCallId },
          );
        }
        if (existing.state === "accepted") {
          throw new SpecialistToolDispatchError(
            "unchanged_request_suppressed",
            "An equivalent action was already accepted and cannot be dispatched as a second side effect.",
            { retryable: false, toolCallId: existing.toolCallId },
          );
        }
        if (existing.state === "failed_transient" && existing.actionId === prepared.action.id) {
          throw new SpecialistToolDispatchError(
            "dispatch_already_in_progress",
            "This action already has a transient failure receipt. Recovery must create a bounded retry action or resume from its checkpoint; the same action will not be dispatched again.",
            {
              retryable: false,
              ...(existing.diagnosisId ? { diagnosisId: existing.diagnosisId } : {}),
              toolCallId: existing.toolCallId,
            },
          );
        }
      }
      this.ensureToolCall(prepared, "running");
      this.save(prepared.suppressionKey, {
        schemaVersion: "ti-scale.specialist-tool-dispatch-record.v1",
        state: "reserved",
        requestSha256: prepared.requestSha256,
        actionId: prepared.action.id,
        toolCallId: prepared.toolCallId,
        diagnosisId: null,
        updatedAt: this.timestamp(),
      });
      return "reserved";
    });
  }

  private accepted(prepared: PreparedInvocation): void {
    inImmediateTransaction(this.options.database, () => {
      this.assertBaseAuthority(prepared.action);
      const current = this.stored(prepared.suppressionKey);
      if (!current || current.state !== "reserved" || current.actionId !== prepared.action.id) {
        throw new SpecialistToolDispatchError("dispatch_rejected", "The durable dispatch reservation changed before acceptance.");
      }
      this.save(prepared.suppressionKey, {
        ...current,
        state: "accepted",
        updatedAt: this.timestamp(),
      });
    });
  }

  /**
   * Re-check the fence and exact specialist policy after the durable
   * reservation and immediately before handing control to a transport.
   */
  private assertReservedDispatchAuthority(prepared: PreparedInvocation): void {
    inImmediateTransaction(this.options.database, () => {
      this.assertBaseAuthority(prepared.action);
      this.assertSpecialistPolicy(prepared.action, prepared.binding);
      const current = this.stored(prepared.suppressionKey);
      if (
        !current
        || current.state !== "reserved"
        || current.actionId !== prepared.action.id
        || current.requestSha256 !== prepared.requestSha256
      ) {
        throw new SpecialistToolDispatchError(
          "dispatch_rejected",
          "The durable specialist dispatch reservation is no longer current.",
        );
      }
    });
  }

  private invocation(prepared: PreparedInvocation): SpecialistToolInvocation {
    return {
      invocationId: prepared.toolCallId,
      action: prepared.action,
      binding: prepared.binding,
      arguments: prepared.arguments,
      inputSha256: prepared.preflight.inputSha256!,
      ...(prepared.resolvedWorkspacePath
        ? { resolvedWorkspacePath: prepared.resolvedWorkspacePath }
        : {}),
    };
  }

  bindResultSink(sink: ExecutionResultSink): () => void {
    if (this.resultSink) throw new Error("Specialist execution result sink is already bound");
    this.resultSink = sink;
    const unbind = this.options.adapter.bindResultSink({
      acceptSpecialistToolResult: (result) => this.acceptSpecialistToolResult(result),
    });
    if (typeof unbind === "function") this.unbindAdapterResultSink = unbind;
    return () => {
      if (this.resultSink !== sink) return;
      this.unbindAdapterResultSink?.();
      this.unbindAdapterResultSink = undefined;
      this.resultSink = undefined;
    };
  }

  private acceptedDispatchRecord(invocationId: string, actionId: string): DispatchRecord {
    const rows = this.options.database.prepare(`
      SELECT value_json FROM settings
      WHERE key LIKE ?
        AND json_extract(value_json, '$.toolCallId') = ?
        AND json_extract(value_json, '$.actionId') = ?
      LIMIT 2
    `).all(`${SETTING_PREFIX}%`, invocationId, actionId) as Array<{ value_json: string }>;
    if (rows.length !== 1) {
      throw new SpecialistToolDispatchError(
        "result_binding_invalid",
        "The specialist result does not identify one exact durable dispatch receipt.",
      );
    }
    const record = parseDispatchRecord(rows[0]!.value_json);
    if (record.state !== "accepted" || record.toolCallId !== invocationId || record.actionId !== actionId) {
      throw new SpecialistToolDispatchError(
        "result_binding_invalid",
        "The specialist result arrived before its exact dispatch was durably accepted.",
      );
    }
    return record;
  }

  private async acceptSpecialistToolResult(
    input: SpecialistToolInvocationResult,
  ): Promise<ExecutionResultReceipt> {
    const sink = this.resultSink;
    if (!sink) {
      throw new SpecialistToolDispatchError(
        "result_sink_unbound",
        "The specialist adapter has no bound MissionRuntimeEngine result sink.",
      );
    }
    if (!PUBLIC_ID.test(input.invocationId)) {
      throw new SpecialistToolDispatchError(
        "result_binding_invalid",
        "The specialist result invocation ID is invalid.",
      );
    }
    const action = this.actions.get(input.result.actionId);
    if (
      action.runId !== input.result.runId
      || action.fingerprint !== input.result.actionFingerprint
      || action.kind !== "tool"
    ) {
      throw new SpecialistToolDispatchError(
        "result_binding_invalid",
        "The specialist result does not match the exact persisted tool action.",
      );
    }
    const toolCall = this.options.database.prepare(`
      SELECT action_id, status FROM tool_calls
      WHERE id = ? AND provider = 'specialist-mcp'
    `).get(input.invocationId) as { action_id: string; status: string } | undefined;
    if (!toolCall || toolCall.action_id !== action.id || toolCall.status !== "running") {
      throw new SpecialistToolDispatchError(
        "result_binding_invalid",
        "The specialist result does not match one running canonical tool call.",
      );
    }
    this.acceptedDispatchRecord(input.invocationId, action.id);
    this.assertBaseAuthority(action);
    return sink.acceptExecutionResult(input.result);
  }

  private adapterFailure(prepared: PreparedInvocation, error: unknown): never {
    const signal = error instanceof SpecialistToolAdapterError
      ? error.failure
      : { transportCode: error instanceof Error ? error.name : "unknown" };
    const input = mcpToolFailureDiagnosisInput(
      prepared.preflight,
      signal,
      {
        missionId: prepared.action.missionId,
        runId: prepared.action.runId,
        stepId: prepared.action.stepId,
        actionId: prepared.action.id,
        targetSummary: `Exact specialist action against authorized target ${prepared.action.target}.`,
        actor: { id: this.actorId, type: "system" },
      },
    );
    const diagnosis = this.persistFailure(prepared, input, !input.retryable);
    this.throwDiagnosis(diagnosis);
  }

  async dispatch(action: DurableAction, signal: AbortSignal): Promise<void> {
    if (!this.resultSink) {
      throw new SpecialistToolDispatchError(
        "result_sink_unbound",
        "Specialist dispatch is unavailable until MissionRuntimeEngine binds terminal result delivery.",
      );
    }
    const prepared = await this.prepare(action);
    const reservation = this.reserve(prepared);
    if (reservation === "replayed") return;
    this.assertReservedDispatchAuthority(prepared);
    try {
      await this.options.adapter.dispatch(this.invocation(prepared), signal);
      this.accepted(prepared);
    } catch (error) {
      this.adapterFailure(prepared, error);
    }
  }

  async resume(action: DurableAction, signal: AbortSignal): Promise<void> {
    if (!this.resultSink) {
      throw new SpecialistToolDispatchError(
        "result_sink_unbound",
        "Specialist resume is unavailable until MissionRuntimeEngine binds terminal result delivery.",
      );
    }
    const prepared = await this.prepare(action);
    if (!prepared.action.idempotent || !this.options.adapter.resume) {
      throw new SpecialistToolDispatchError(
        "resume_not_safe",
        "This specialist action has no reviewed idempotent resume adapter.",
      );
    }
    const record = this.stored(prepared.suppressionKey);
    if (!record || record.state !== "reserved" || record.actionId !== prepared.action.id) {
      throw new SpecialistToolDispatchError(
        "resume_not_safe",
        "No matching durable in-flight reservation is available for safe resume.",
      );
    }
    this.assertReservedDispatchAuthority(prepared);
    try {
      await this.options.adapter.resume(this.invocation(prepared), signal);
      this.accepted(prepared);
    } catch (error) {
      this.adapterFailure(prepared, error);
    }
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    if (!PUBLIC_ID.test(runId) || !reason.trim()) {
      throw new SpecialistToolDispatchError("dispatch_rejected", "Cancellation requires an exact run and reason.");
    }
    this.assertControlPlaneAuthority(runId);
    await this.options.adapter.cancelRun(runId, reason.trim());
  }
}

export function specialistDispatchRecordPrefix(): string {
  return SETTING_PREFIX;
}

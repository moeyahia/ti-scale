import {
  LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION,
  LocalProcessToolExecutionError,
  type LocalToolCapabilityManifest,
  type LocalProcessToolInvocation,
  type LocalProcessToolResultSink,
} from "../local-tools";
import type { ControlPlaneLease } from "../control-plane";
import type { SqliteDatabase } from "../db";
import { digestCanonicalJson } from "../mcp";
import {
  SPECIALIST_TOOL_ADAPTER_CONTRACT_SCHEMA_VERSION,
  SpecialistToolDispatchService,
  SpecialistToolAdapterError,
  type SpecialistMcpToolBinding,
  type SpecialistToolInvocation,
  type SpecialistToolInvocationAdapter,
  type SpecialistToolInvocationResultSink,
} from "../specialist-runtime";
import type {
  EngagementWorkspaceResolver,
  ToolExecutionPreflightService,
} from "../system-capabilities";
import {
  AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
  AUTONOMOUS_DNS_SAFE_RECON_ADAPTER_ID,
  AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
  validateAutonomousDnsSafeReconConfiguration,
  type AutonomousDnsSafeReconConfiguration,
} from "./AutonomousDnsSafeRecon";
import { AutonomousDnsEvidenceVerifier } from "./AutonomousDnsEvidenceVerifier";

export interface AutonomousDnsLocalProcessTransport {
  bindResultSink(sink: LocalProcessToolResultSink): void | (() => void);
  dispatch(invocation: LocalProcessToolInvocation, signal: AbortSignal): Promise<void>;
  cancelRun(runId: string, reason: string): Promise<void>;
}

export interface AutonomousDnsSpecialistAdapterOptions {
  readonly localProcessTransport: AutonomousDnsLocalProcessTransport;
  readonly evidenceVerifier: AutonomousDnsEvidenceVerifier;
  readonly mcpServerId: string;
}

export const AUTONOMOUS_DNS_SPECIALIST_ADAPTER_CONTRACT = Object.freeze({
  schemaVersion: SPECIALIST_TOOL_ADAPTER_CONTRACT_SCHEMA_VERSION,
  adapterId: AUTONOMOUS_DNS_SAFE_RECON_ADAPTER_ID,
  toolSelection: "exact_persisted_binding_only",
  resultDelivery: "bound_execution_result_sink",
  cancellation: "run_scoped_cooperative",
  shellInterpolation: false,
  publicProviderToolExecution: false,
} as const);

function plainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function transportFailure(error: unknown): SpecialistToolAdapterError {
  const code = error instanceof LocalProcessToolExecutionError
    ? error.code
    : error instanceof Error
      ? error.name
      : "autonomous_dns_transport_failed";
  return new SpecialistToolAdapterError(
    error instanceof Error ? error.message : "The bounded DNS process transport failed.",
    { transportCode: code },
  );
}

/**
 * Autonomous-only specialist transport for one reviewed DNS operation. It
 * translates an already authorized specialist invocation into the existing
 * sandboxed direct-argv runner. It cannot select another tool or target.
 */
export class AutonomousDnsSpecialistAdapter implements SpecialistToolInvocationAdapter {
  readonly contract = AUTONOMOUS_DNS_SPECIALIST_ADAPTER_CONTRACT;

  readonly #active = new Map<string, SpecialistToolInvocation>();
  readonly #unbindLocal: (() => void) | undefined;
  #sink?: SpecialistToolInvocationResultSink;

  constructor(private readonly options: AutonomousDnsSpecialistAdapterOptions) {
    const unbind = options.localProcessTransport.bindResultSink({
      acceptLocalProcessToolResult: async (result) => {
        const invocation = this.#active.get(result.invocationId);
        if (!invocation) {
          throw transportFailure(new Error("The DNS process result has no active specialist invocation."));
        }
        const sink = this.#sink;
        if (!sink) {
          throw transportFailure(new Error("The DNS specialist result sink is not bound."));
        }
        const outcome = this.options.evidenceVerifier.process(invocation, result);
        try {
          await sink.acceptSpecialistToolResult({
            invocationId: invocation.invocationId,
            result: outcome.executionResult,
          });
        } finally {
          this.#active.delete(invocation.invocationId);
        }
      },
    });
    this.#unbindLocal = typeof unbind === "function" ? unbind : undefined;
  }

  bindResultSink(sink: SpecialistToolInvocationResultSink): () => void {
    if (this.#sink) throw new Error("Autonomous DNS specialist result sink is already bound");
    this.#sink = sink;
    return () => {
      if (this.#sink !== sink || this.#active.size > 0) return;
      this.#sink = undefined;
      this.#unbindLocal?.();
    };
  }

  private localInvocation(invocation: SpecialistToolInvocation): LocalProcessToolInvocation {
    const parameters = invocation.arguments;
    const actionArguments = invocation.action.arguments;
    if (
      !this.#sink
      || this.#active.has(invocation.invocationId)
      || invocation.action.kind !== "tool"
      || invocation.action.actionType !== AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS
      || invocation.action.actionClass !== AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS
      || invocation.action.guidedDecisionId !== null
      || invocation.action.contractId === null
      || invocation.binding.serverId !== this.options.mcpServerId
      || invocation.binding.toolName !== AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID
      || !plainRecord(parameters)
      || !exactKeys(parameters, ["name", "recordType", "workspace"])
      || !plainRecord(actionArguments.parameters)
      || actionArguments.mcpServer !== this.options.mcpServerId
      || actionArguments.toolName !== AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID
      || digestCanonicalJson(actionArguments.parameters, { maxBytes: 64 * 1_024, maxDepth: 16 }).sha256
        !== invocation.inputSha256
      || digestCanonicalJson(parameters, { maxBytes: 64 * 1_024, maxDepth: 16 }).sha256
        !== invocation.inputSha256
      || typeof invocation.resolvedWorkspacePath !== "string"
    ) {
      throw new SpecialistToolAdapterError(
        "The Autonomous DNS invocation differs from its exact persisted specialist binding.",
        { transportCode: "autonomous_dns_invocation_binding_invalid" },
      );
    }
    try {
      this.options.evidenceVerifier.assertPreDispatch(invocation);
    } catch (error) {
      throw new SpecialistToolAdapterError(
        error instanceof Error
          ? error.message
          : "The Autonomous DNS scope and policy boundary could not be verified before dispatch.",
        { transportCode: "autonomous_dns_pre_dispatch_denied" },
      );
    }
    return {
      schemaVersion: LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION,
      invocationId: invocation.invocationId,
      action: invocation.action,
      toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
      parameters,
      inputSha256: invocation.inputSha256,
      resolvedWorkspacePath: invocation.resolvedWorkspacePath,
    };
  }

  async dispatch(invocation: SpecialistToolInvocation, signal: AbortSignal): Promise<void> {
    const local = this.localInvocation(invocation);
    if (signal.aborted) {
      throw new SpecialistToolAdapterError(
        "The Autonomous DNS action was cancelled before target contact.",
        { transportCode: "autonomous_dns_cancelled_before_dispatch" },
      );
    }
    this.#active.set(invocation.invocationId, invocation);
    try {
      await this.options.localProcessTransport.dispatch(local, signal);
    } catch (error) {
      this.#active.delete(invocation.invocationId);
      throw transportFailure(error);
    }
  }

  async resume(invocation: SpecialistToolInvocation, signal: AbortSignal): Promise<void> {
    if (signal.aborted) {
      throw new SpecialistToolAdapterError(
        "The Autonomous DNS recovery was cancelled before result replay.",
        { transportCode: "autonomous_dns_replay_cancelled" },
      );
    }
    const sink = this.#sink;
    if (!sink) {
      throw new SpecialistToolAdapterError(
        "The Autonomous DNS specialist result sink is not bound.",
        { transportCode: "autonomous_dns_result_sink_unbound" },
      );
    }
    const replay = this.options.evidenceVerifier.replay(invocation);
    if (!replay) {
      throw new SpecialistToolAdapterError(
        "No committed Autonomous DNS result exists; the previous process will not be replayed blindly.",
        { transportCode: "autonomous_dns_resume_requires_new_attempt" },
      );
    }
    await sink.acceptSpecialistToolResult({
      invocationId: invocation.invocationId,
      result: replay.executionResult,
    });
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    await this.options.localProcessTransport.cancelRun(runId, reason);
    for (const [invocationId, invocation] of this.#active) {
      if (invocation.action.runId === runId) this.#active.delete(invocationId);
    }
  }
}

export interface AutonomousDnsSpecialistExecutionFactoryOptions {
  readonly manifest: LocalToolCapabilityManifest;
  readonly configuration: AutonomousDnsSafeReconConfiguration;
  readonly localProcessTransport: AutonomousDnsLocalProcessTransport;
  readonly resolveBinding: (
    serverId: string,
    toolName: string,
  ) => SpecialistMcpToolBinding | undefined;
  readonly workspaceResolver: EngagementWorkspaceResolver;
  readonly toolPreflight?: ToolExecutionPreflightService;
  readonly actorId?: string;
  readonly now?: () => Date;
}

/**
 * Genuine production composition boundary for the reviewed DNS adapter. It
 * deliberately does not provide provider, MCP, executable, or readiness
 * attestations; those remain live inputs to the composition inspector and the
 * dispatch service's re-checkable preflight.
 */
export class AutonomousDnsSpecialistExecutionFactory {
  readonly adapterContract = AUTONOMOUS_DNS_SPECIALIST_ADAPTER_CONTRACT;
  readonly #configuration: AutonomousDnsSafeReconConfiguration;
  #created = false;

  constructor(private readonly options: AutonomousDnsSpecialistExecutionFactoryOptions) {
    this.#configuration = validateAutonomousDnsSafeReconConfiguration(
      options.configuration,
      options.manifest,
    );
  }

  create(input: Readonly<{
    database: SqliteDatabase;
    assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
  }>): SpecialistToolDispatchService {
    if (this.#created) {
      throw new Error("Autonomous DNS specialist execution factory is single-use");
    }
    const mcpServerId = this.#configuration.mcpServerId;
    if (!mcpServerId) {
      throw new Error("The compatibility MCP specialist factory requires an exact MCP server ID; use the reviewed local-process factory for direct execution");
    }
    const verifier = new AutonomousDnsEvidenceVerifier({
      database: input.database,
      manifest: this.options.manifest,
      configuration: this.#configuration,
      ...(this.options.now ? { now: this.options.now } : {}),
    });
    const adapter = new AutonomousDnsSpecialistAdapter({
      localProcessTransport: this.options.localProcessTransport,
      evidenceVerifier: verifier,
      mcpServerId,
    });
    const service = new SpecialistToolDispatchService({
      database: input.database,
      assertControlPlaneAuthority: input.assertControlPlaneAuthority,
      resolveBinding: this.options.resolveBinding,
      adapter,
      workspaceResolver: this.options.workspaceResolver,
      ...(this.options.toolPreflight ? { toolPreflight: this.options.toolPreflight } : {}),
      ...(this.options.actorId ? { actorId: this.options.actorId } : {}),
      ...(this.options.now ? { now: this.options.now } : {}),
    });
    this.#created = true;
    return service;
  }
}

import type { SqliteDatabase } from "../db";
import {
  WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION,
  WindowsIdentityBoundaryError,
  WindowsIdentityToolPack,
  canonicalWindowsIdentityTarget,
  type WindowsIdentityOperation,
  type WindowsIdentityToolId,
} from "../windows-identity-tools";
import type { BrainContextService } from "../brain-runtime";
import { MissionRuntimeEngine } from "./MissionRuntimeEngine";
import { DeterministicGuidedPreferenceOutcomeEvaluator } from "./LocalGuidedToolRuntime";
import { LocalGuidedManualPlanner } from "./LocalGuidedManualRuntime";
import type {
  ExecutionResultSink,
  MissionPlanDraft,
  MissionPlannerInput,
  MissionPlannerPort,
  ResultAwareExecutionPort,
} from "./types";
import type { DurableAction } from "../orchestration";
import { CommandRuntimeError } from "./types";

export const REVIEWED_WINDOWS_IDENTITY_EXECUTION_BINDING =
  "reviewed_windows_identity_process" as const;

const PRESENTATION: Readonly<Record<WindowsIdentityOperation, Readonly<{
  title: string;
  objective(target: string): string;
  explanation: string;
  expected: string;
}>>> = Object.freeze({
  smb_share_list: {
    title: "List the SMB shares the approved host exposes",
    objective: (target) => `Ask ${target} for its advertised SMB share names and types.`,
    explanation: "Ti-Scale will make one read-only SMB listing request to the exact approved host. Anonymous mode sends no credential; credential mode uses only the selected opaque private reference. It will not open files, write to a share, try passwords, or contact another host.",
    expected: "A bounded list of advertised shares, an access-denied response, or a precise connection, policy, dependency, or timeout failure.",
  },
  smb_identity_summary: {
    title: "Read the approved host’s SMB identity summary",
    objective: (target) => `Confirm the SMB host, domain, signing, and protocol details reported by ${target}.`,
    explanation: "Ti-Scale will use one operator-selected opaque credential reference for a bounded SMB metadata and share check. The credential files stay private to the sandbox. It will not spray passwords, test local-admin access, write to shares, or execute commands.",
    expected: "Attributable host and domain metadata with SMB security settings, or a precise authentication, connection, policy, dependency, or timeout failure.",
  },
  ldap_root_dse: {
    title: "Read the LDAP directory’s public root metadata",
    objective: (target) => `Ask ${target} for the small public metadata record that identifies its LDAP directory namespaces and supported protocols.`,
    explanation: "Ti-Scale will make one anonymous, read-only LDAP base query to the exact approved host. It asks only for a fixed set of root-directory metadata and will not enumerate users, groups, computers, or neighboring systems.",
    expected: "Directory namespace and protocol metadata, an access-denied response, or a precise connection, policy, dependency, or timeout failure.",
  },
  rpc_domain_info: {
    title: "Read the approved host’s RPC domain summary",
    objective: (target) => `Ask ${target} for its bounded Windows domain summary over RPC.`,
    explanation: "Ti-Scale will make one read-only RPC domain-information request to the exact approved host. Anonymous mode sends no credential; credential mode uses only the selected opaque private reference. It will not enumerate accounts, change domain objects, or execute commands.",
    expected: "A bounded domain-role and object-count summary, an access-denied response, or a precise connection, policy, dependency, or timeout failure.",
  },
});

export interface WindowsIdentityGuidedPlannerOptions {
  readonly pack: WindowsIdentityToolPack;
  readonly logicalWorkspace: string;
  readonly readReadyToolIds: () => ReadonlySet<string>;
  readonly fallback: MissionPlannerPort;
}

/** Selects identity tooling only when intake persisted one explicit intent. */
export class WindowsIdentityGuidedPlanner implements MissionPlannerPort {
  constructor(private readonly options: WindowsIdentityGuidedPlannerOptions) {}

  async plan(input: MissionPlannerInput, signal: AbortSignal): Promise<MissionPlanDraft> {
    const selection = input.mission.guidedWindowsIdentity;
    if (!selection) {
      const fallback = await this.options.fallback.plan(input, signal);
      return "plan" in fallback ? fallback.plan : fallback;
    }
    if (input.mission.journey !== "guided" || input.run.journey !== "guided") {
      throw new CommandRuntimeError(409, "windows_identity_autonomous_not_approved", "Windows/identity direct-process execution is Guided-only", {
        category: "policy_denied",
        humanMessage: "This reviewed Windows and identity tool pack is available only as one represented Guided action.",
        remediation: "Create a Guided mission and approve the exact represented step.",
      });
    }
    if (input.mission.guidedReconnaissance) {
      throw new CommandRuntimeError(409, "guided_first_step_ambiguous", "Two first-step Guided intents were persisted", {
        category: "data_integrity",
        humanMessage: "The mission contains both a reconnaissance selection and a Windows/identity selection. Ti-Scale did not choose one silently.",
        remediation: "Create a new Guided mission with exactly one first-step selection.",
      });
    }
    const targetValue = input.mission.allowedTargets[0];
    let target: string;
    try {
      target = canonicalWindowsIdentityTarget(targetValue);
    } catch (error) {
      if (error instanceof WindowsIdentityBoundaryError) {
        throw new CommandRuntimeError(409, error.code, error.message, {
          category: error.category,
          humanMessage: "The Windows/identity step requires one canonical approved IP address or hostname. Ti-Scale did not alter the target.",
          remediation: "Create a new Guided mission with one exact host target.",
        });
      }
      throw error;
    }
    const definition = this.options.pack.resolveOperation(selection.operation);
    if (!definition
      || !definition.authenticationModes.includes(selection.authenticationMode)
      || !this.options.readReadyToolIds().has(definition.toolId)) {
      throw new CommandRuntimeError(503, "windows_identity_tool_unavailable", "The exact reviewed Windows/identity binding is unavailable", {
        category: "dependency_missing",
        retryable: true,
        humanMessage: "The selected Windows/identity read has no complete, current executable and sandbox receipt. Nothing was sent to the target.",
        remediation: "Restore the exact reviewed tool binding, repeat startup readiness, then create a new run.",
      });
    }
    if (input.mission.executionPreference !== "single_step_agent") {
      throw new CommandRuntimeError(409, "windows_identity_single_step_execution_required", "The identity selection requires single-step agent execution", {
        category: "policy_denied",
        humanMessage: "This mission is configured for operator-run commands, so Ti-Scale will not start the selected identity tool.",
        remediation: "Use the manual Guided workflow or create a new mission that permits one exact agent-run step.",
      });
    }
    if (signal.aborted) throw new DOMException("Guided planning was cancelled", "AbortError");
    const content = PRESENTATION[selection.operation];
    return {
      strategySummary: `Use one operator-approved Windows/identity metadata read against ${target}; do not expand into enumeration, credential attacks, file access, or command execution.`,
      rationaleSummary: "The exact executable, target, authentication mode, workspace, timeout, output cap, and cancellation boundary have current local receipts. The operator must still approve this one represented action.",
      steps: [{
        phase: "Windows and identity baseline",
        title: content.title,
        objective: content.objective(target),
        explanation: content.explanation,
        rationale: `${content.expected} Raw output is retained as an Engagement Log record; parsed statements remain unverified Observations and no evidence is created automatically.`,
        successCriteria: [
          "Only the exact approved host is contacted",
          "The represented read returns a bounded attributable result or precise failure",
          "No raw output or parsed statement is promoted to evidence automatically",
        ],
        dependencyOrdinals: [],
        assignedAgentId: "specialist:windows-identity",
        riskClass: "medium",
        reversibility: "This is a target-read-only metadata request. Stop terminates the child process group; it makes no target or identity change.",
        action: {
          actionType: definition.toolId,
          actionClass: definition.actionClassId,
          target,
          arguments: {
            schemaVersion: WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION,
            executionBinding: REVIEWED_WINDOWS_IDENTITY_EXECUTION_BINDING,
            operation: selection.operation,
            toolId: definition.toolId,
            authenticationMode: selection.authenticationMode,
            credentialReference: selection.credentialReference,
            logicalWorkspace: this.options.logicalWorkspace,
          },
          intentSummary: `${definition.label} for the exact approved host ${target}`,
          kind: "tool",
          idempotent: true,
          destructive: false,
        },
      }],
      planningAttribution: {
        contextPackIds: [input.brainContext.contextPackId],
        citations: [],
      },
    };
  }
}

function identityBinding(action: DurableAction): boolean {
  return action.arguments.executionBinding === REVIEWED_WINDOWS_IDENTITY_EXECUTION_BINDING;
}

/** One runtime-facing port that delegates only by a closed execution binding. */
export class CompositeGuidedExecutionPort implements ResultAwareExecutionPort {
  private resultSink?: ExecutionResultSink;

  constructor(
    private readonly baseline: ResultAwareExecutionPort,
    private readonly identity: ResultAwareExecutionPort,
  ) {}

  bindResultSink(sink: ExecutionResultSink): () => void {
    if (this.resultSink) throw new Error("Composite Guided result sink is already bound");
    this.resultSink = sink;
    const unbindBaseline = this.baseline.bindResultSink?.(sink);
    const unbindIdentity = this.identity.bindResultSink?.(sink);
    return () => {
      unbindIdentity?.();
      unbindBaseline?.();
      if (this.resultSink === sink) this.resultSink = undefined;
    };
  }

  dispatch(action: DurableAction, signal: AbortSignal): Promise<void> {
    return identityBinding(action)
      ? this.identity.dispatch(action, signal)
      : this.baseline.dispatch(action, signal);
  }

  resume(action: DurableAction, signal: AbortSignal): Promise<void> {
    return identityBinding(action)
      ? this.identity.resume(action, signal)
      : this.baseline.resume(action, signal);
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    await Promise.allSettled([
      this.identity.cancelRun(runId, reason),
      this.baseline.cancelRun(runId, reason),
    ]);
  }

  async replayPendingResults(limit = 100): Promise<number> {
    const [identity, baseline] = await Promise.all([
      this.identity.replayPendingResults?.(limit) ?? 0,
      this.baseline.replayPendingResults?.(limit) ?? 0,
    ]);
    return identity + baseline;
  }
}

export function createProductionGuidedCompositeRuntime(options: Readonly<{
  database: SqliteDatabase;
  operationalHazardHmacKey?: string | Buffer;
  brainContext: BrainContextService;
  projectMemoryNodes?: (nodeIds: readonly string[]) => void;
  fallbackPlanner: MissionPlannerPort;
  windowsIdentityPack: WindowsIdentityToolPack;
  windowsIdentityLogicalWorkspace: string;
  readReadyWindowsIdentityToolIds: () => ReadonlySet<string>;
  execution: ResultAwareExecutionPort;
  workerId?: string;
}>): MissionRuntimeEngine {
  return new MissionRuntimeEngine({
    database: options.database,
    ...(options.operationalHazardHmacKey
      ? { operationalHazardHmacKey: options.operationalHazardHmacKey }
      : {}),
    planner: new WindowsIdentityGuidedPlanner({
      pack: options.windowsIdentityPack,
      logicalWorkspace: options.windowsIdentityLogicalWorkspace,
      readReadyToolIds: options.readReadyWindowsIdentityToolIds,
      fallback: options.fallbackPlanner,
    }),
    outcomeEvaluator: new DeterministicGuidedPreferenceOutcomeEvaluator(options.database),
    execution: options.execution,
    brainContext: options.brainContext,
    ...(options.projectMemoryNodes ? { projectMemoryNodes: options.projectMemoryNodes } : {}),
    supportedJourneys: ["guided"],
    ...(options.workerId ? { workerId: options.workerId } : {}),
  });
}

export function windowsIdentityActionToolId(action: DurableAction): WindowsIdentityToolId | null {
  if (!identityBinding(action) || typeof action.arguments.toolId !== "string") return null;
  return action.arguments.toolId as WindowsIdentityToolId;
}

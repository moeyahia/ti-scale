import { brainLifecycleHookDefinition } from "./BrainLifecycleHookRegistry";
import type {
  BrainContextService,
  LifecyclePreferenceNodeIds,
} from "./BrainContextService";
import type {
  BrainContextRequest,
  BrainContextResult,
  BrainLifecycleHook,
} from "./types";
import type { Journey } from "../memory";
import {
  AUTONOMOUS_MEMORY_SCOPE_CLASSES,
  RUNTIME_CAPABILITY_MEMORY_SCOPE_CLASS,
  type AutonomousMemoryScopeClass,
  type MemorySensitivity,
} from "../memory";

function strings(value: unknown): readonly string[] {
  return Array.isArray(value)
    ? [...new Set(value.filter((item): item is string => typeof item === "string" && item.trim().length > 0))]
    : [];
}

export function parseMissionMemoryPolicy(value: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Readonly<Record<string, unknown>>
      : {};
  } catch {
    return {};
  }
}

/**
 * One policy compiler for every mission/run Brain hook. It preserves the
 * Autonomous contract's exact selection (including an explicitly empty
 * selection), never enables global memory for step hooks that forbid it, and
 * keeps required-vs-degraded behavior consistent across runtime services.
 */
export function retrieveMissionBrainContext(input: {
  readonly brainContext: BrainContextService;
  readonly hook: BrainLifecycleHook;
  readonly journey: Journey;
  readonly missionId: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly actionId?: string;
  readonly actorId: string;
  readonly actorType: "operator" | "agent" | "worker" | "system";
  readonly query: string;
  readonly queryRedacted: string;
  readonly memoryPolicy: Readonly<Record<string, unknown>>;
  readonly maximumSensitivity?: Exclude<MemorySensitivity, "restricted">;
  readonly contextBudget?: number;
  readonly limit?: number;
  /**
   * Stable current-mission graph anchors selected by the trusted local
   * runtime. Guided may include these because they are canonical mission
   * facts, not cross-mission reusable suggestions. Autonomous remains bound
   * exclusively to its signed exact selection.
   */
  readonly canonicalContextNodeIds?: readonly string[];
  /**
   * Exact current runtime-capability nodes selected by the trusted local
   * dispatch boundary. They are additive execution facts, not operator
   * preference/lesson authority, and MemoryScopePolicy revalidates their
   * system author, typed schema, lifecycle, and current status.
   */
  readonly trustedRuntimeCapabilityNodeIds?: readonly string[];
  /**
   * Opaque exact preference anchors resolved by BrainContextService for this
   * mission creator and lifecycle hook. A nonempty signed Autonomous exact
   * whitelist always takes precedence, so these IDs can never broaden it.
   */
  readonly lifecyclePreferenceNodeIds?: LifecyclePreferenceNodeIds;
  /** Terminal cleanup must remain durable even when optional memory is down. */
  readonly terminalSafe?: boolean;
}): BrainContextResult {
  const definition = brainLifecycleHookDefinition(input.hook);
  if (definition.requiresRun && !input.runId) {
    throw new TypeError(`${definition.label} requires a canonical run`);
  }
  if (definition.requiresStep && !input.stepId) {
    throw new TypeError(`${definition.label} requires a canonical plan step`);
  }
  const exactNodeIds = strings(input.memoryPolicy.exactContextNodeIds);
  const canonicalContextNodeIds = strings(input.canonicalContextNodeIds);
  const runtimeCapabilityNodeIds = strings(input.trustedRuntimeCapabilityNodeIds);
  const requestedLifecyclePreferenceNodeIds = strings(input.lifecyclePreferenceNodeIds);
  const allowedScopes = strings(input.memoryPolicy.allowedScopes);
  if (input.journey === "autonomous") {
    if (!Array.isArray(input.memoryPolicy.exactContextNodeIds) || !Array.isArray(input.memoryPolicy.allowedScopes)) {
      throw new TypeError("Autonomous mission memory policy is missing its signed scope or exact-node selection");
    }
    const allowed = new Set<string>(AUTONOMOUS_MEMORY_SCOPE_CLASSES);
    if (allowedScopes.some((scope) => !allowed.has(scope))) {
      throw new TypeError("Autonomous mission memory policy contains an unsupported scope class");
    }
  }
  const autonomousMemoryRequired = input.journey === "autonomous"
    && (exactNodeIds.length > 0 || allowedScopes.length > 0);
  const allowGlobal = definition.allowGlobalWhenExplicit
    && (
      input.journey === "guided" ||
      allowedScopes.includes("confirmed_preferences") ||
      allowedScopes.includes("verified_lessons") ||
      allowedScopes.includes("confirmed_attack_knowledge") ||
      allowedScopes.includes("verified_attack_knowledge")
      || runtimeCapabilityNodeIds.length > 0
      || requestedLifecyclePreferenceNodeIds.length > 0
    );
  const lifecyclePreferenceNodeIds = (
    definition.allowedNodeTypes.includes("preference")
    && exactNodeIds.length === 0
    && (
      input.journey === "guided"
      || allowedScopes.includes("confirmed_preferences")
    )
  )
    ? requestedLifecyclePreferenceNodeIds
    : [];
  const selectedNodeIds = [...new Set([
    ...exactNodeIds,
    ...runtimeCapabilityNodeIds,
    ...lifecyclePreferenceNodeIds,
  ])];
  const effectiveAllowedScopes = [...new Set([
    ...allowedScopes,
    ...(runtimeCapabilityNodeIds.length > 0
      ? [RUNTIME_CAPABILITY_MEMORY_SCOPE_CLASS]
      : []),
  ])] as readonly AutonomousMemoryScopeClass[];

  return input.brainContext.retrieve({
    hook: input.hook,
    journey: input.journey,
    missionId: input.missionId,
    ...(input.runId ? { runId: input.runId } : {}),
    ...(input.stepId ? { stepId: input.stepId } : {}),
    ...(input.actionId ? { actionId: input.actionId } : {}),
    actorId: input.actorId,
    actorType: input.actorType,
    availabilityPolicy: input.terminalSafe || input.journey === "guided" || !autonomousMemoryRequired
      ? "degraded_allowed"
      : "required",
    query: input.query,
    queryRedacted: input.queryRedacted,
    allowGlobal,
    maximumSensitivity: input.maximumSensitivity ?? "private",
    ...(input.contextBudget === undefined ? {} : { contextBudget: input.contextBudget }),
    ...(input.limit === undefined ? {} : { limit: input.limit }),
    ...(input.journey === "autonomous"
      ? {
          exactNodeIds: selectedNodeIds,
          // A nonempty launch-time selection is an immutable whitelist.
          // Explicitly empty selections may still use the separately signed
          // scope classes for bounded dynamic retrieval. Lifecycle preference
          // anchors alone therefore seed deterministic profiles without
          // converting an empty signed selection into a hidden whitelist.
          ...(exactNodeIds.length > 0 || runtimeCapabilityNodeIds.length > 0
            ? { exactNodeIdsOnly: true }
            : {}),
          allowedScopeClasses: effectiveAllowedScopes,
          requireApplicableExactNodeIds: selectedNodeIds.length > 0,
        }
      : {
          ...(
            canonicalContextNodeIds.length
              || runtimeCapabilityNodeIds.length
              || lifecyclePreferenceNodeIds.length
              ? {
                  exactNodeIds: [...new Set([
                    ...canonicalContextNodeIds,
                    ...runtimeCapabilityNodeIds,
                    ...lifecyclePreferenceNodeIds,
                  ])],
                }
              : {}
          ),
          allowedScopeClasses: runtimeCapabilityNodeIds.length > 0
            ? [
                ...AUTONOMOUS_MEMORY_SCOPE_CLASSES,
                RUNTIME_CAPABILITY_MEMORY_SCOPE_CLASS,
              ]
            : AUTONOMOUS_MEMORY_SCOPE_CLASSES,
        }),
  } as BrainContextRequest);
}

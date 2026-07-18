import { brainLifecycleHookDefinition } from "./BrainLifecycleHookRegistry";
import type { BrainContextService } from "./BrainContextService";
import type {
  BrainContextRequest,
  BrainContextResult,
  BrainLifecycleHook,
} from "./types";
import type { Journey } from "../memory";
import {
  AUTONOMOUS_MEMORY_SCOPE_CLASSES,
  type AutonomousMemoryScopeClass,
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
      allowedScopes.includes("verified_lessons")
    );

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
    maximumSensitivity: "private",
    ...(input.journey === "autonomous"
      ? {
          exactNodeIds,
          allowedScopeClasses: allowedScopes as readonly AutonomousMemoryScopeClass[],
          requireApplicableExactNodeIds: exactNodeIds.length > 0,
        }
      : { allowedScopeClasses: AUTONOMOUS_MEMORY_SCOPE_CLASSES }),
  } as BrainContextRequest);
}

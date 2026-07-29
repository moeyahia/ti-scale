import type { BrainContextResult } from "../brain-runtime";
import type { MemoryNode } from "../memory";
import { FAILURE_CATEGORIES, type FailureCategory } from "../supervisor";
import {
  AUTONOMOUS_RECOVERY_MEMORY_COMPILER_VERSION,
  AUTONOMOUS_RECOVERY_MEMORY_SCHEMA_VERSION,
  type AutonomousRecoveryMemoryHook,
  type CompiledAutonomousRecoveryMemory,
  type CompiledRecoveryMemoryCandidate,
  type RecoveryMemoryIgnoredReason,
} from "./types";

const POLICY_KEY = "autonomousRecovery";
const MAXIMUM_MEMORY_BACKOFF_MS = 30_000;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const ALLOWED_NODE_TYPES = new Set([
  "failure_mode",
  "operational_hazard",
  "recovery_pattern",
  "health_check",
  "alternative",
  "lesson",
  "attack_lesson",
]);
const VERIFIED_LESSON_TYPES = new Set(["lesson", "attack_lesson"]);
const FAILURE_CATEGORY_SET = new Set<string>(FAILURE_CATEGORIES);

interface TypedRecoveryPolicy {
  readonly failureCategories?: readonly FailureCategory[];
  readonly actionTypes?: readonly string[];
  readonly actionClasses?: readonly string[];
  readonly denyRetry: boolean;
  readonly minimumBackoffMs?: number;
  readonly alternativeStepId?: string;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const set = new Set(allowed);
  return Object.keys(value).every((key) => set.has(key));
}

function stringList(value: unknown, validator?: (value: string) => boolean): readonly string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) return undefined;
  const normalized = value.map((item) => typeof item === "string" ? item.trim().toLowerCase() : "");
  if (normalized.some((item) => !item || item.length > 128 || (validator && !validator(item)))) return undefined;
  return [...new Set(normalized)].sort();
}

function parsePolicy(node: MemoryNode): TypedRecoveryPolicy | undefined {
  const policy = object(node.retentionPolicy[POLICY_KEY]);
  if (!policy || !exactKeys(policy, ["schemaVersion", "match", "effects"])) return undefined;
  if (policy.schemaVersion !== AUTONOMOUS_RECOVERY_MEMORY_SCHEMA_VERSION) return undefined;
  const match = object(policy.match);
  const effects = object(policy.effects);
  if (!match || !effects) return undefined;
  if (!exactKeys(match, ["failureCategories", "actionTypes", "actionClasses"])) return undefined;
  if (!exactKeys(effects, ["denyRetry", "minimumBackoffMs", "alternativeStepId"])) return undefined;

  const failureCategories = stringList(
    match.failureCategories,
    (value) => FAILURE_CATEGORY_SET.has(value),
  ) as readonly FailureCategory[] | undefined;
  const actionTypes = stringList(match.actionTypes);
  const actionClasses = stringList(match.actionClasses);
  if (match.failureCategories !== undefined && !failureCategories) return undefined;
  if (match.actionTypes !== undefined && !actionTypes) return undefined;
  if (match.actionClasses !== undefined && !actionClasses) return undefined;

  const denyRetry = effects.denyRetry === true;
  if (effects.denyRetry !== undefined && effects.denyRetry !== true) return undefined;
  const minimumBackoffMs = effects.minimumBackoffMs;
  if (
    minimumBackoffMs !== undefined &&
    (typeof minimumBackoffMs !== "number" || !Number.isSafeInteger(minimumBackoffMs)
      || minimumBackoffMs < 0 || minimumBackoffMs > MAXIMUM_MEMORY_BACKOFF_MS)
  ) return undefined;
  const alternativeStepId = effects.alternativeStepId;
  if (
    alternativeStepId !== undefined &&
    (typeof alternativeStepId !== "string" || !SAFE_ID.test(alternativeStepId))
  ) return undefined;
  if (!denyRetry && minimumBackoffMs === undefined && alternativeStepId === undefined) return undefined;
  return {
    ...(failureCategories ? { failureCategories } : {}),
    ...(actionTypes ? { actionTypes } : {}),
    ...(actionClasses ? { actionClasses } : {}),
    denyRetry,
    ...(minimumBackoffMs === undefined ? {} : { minimumBackoffMs }),
    ...(alternativeStepId === undefined ? {} : { alternativeStepId }),
  };
}

function scopeMatches(node: MemoryNode, missionId: string, engagementId: string | null): boolean {
  if (node.scope.kind === "global") return true;
  if (node.scope.kind === "mission") return node.scope.missionId === missionId;
  return Boolean(engagementId && node.scope.engagementId === engagementId);
}

function eligibilityReason(
  node: MemoryNode,
  missionId: string,
  engagementId: string | null,
): RecoveryMemoryIgnoredReason | undefined {
  if (!ALLOWED_NODE_TYPES.has(node.nodeType)) return "node_type_not_allowed";
  if (node.lifecycleStatus !== "confirmed" && node.lifecycleStatus !== "verified") {
    return "node_not_confirmed_or_verified";
  }
  if (VERIFIED_LESSON_TYPES.has(node.nodeType) && node.lifecycleStatus !== "verified") {
    return "lesson_not_verified";
  }
  if (
    node.retentionPolicy.allowAutonomous === false ||
    (node.retentionPolicy.journeys && !node.retentionPolicy.journeys.includes("autonomous"))
  ) return "autonomous_use_not_permitted";
  if (!scopeMatches(node, missionId, engagementId)) return "scope_mismatch";
  return undefined;
}

export interface CompileAutonomousRecoveryMemoryInput {
  readonly hook: AutonomousRecoveryMemoryHook;
  readonly context: BrainContextResult;
  readonly missionId: string;
  readonly engagementId: string | null;
  readonly runId: string;
  readonly stepId?: string;
  readonly actionId?: string;
  readonly failureCategory: FailureCategory;
  readonly actionType: string;
  readonly actionClass: string;
}

/**
 * Compile only schema-valid local recovery constraints. No prose is parsed,
 * and no field in this result can introduce a target, tool, or new action.
 */
export function compileAutonomousRecoveryMemory(
  input: CompileAutonomousRecoveryMemoryInput,
): CompiledAutonomousRecoveryMemory {
  const ignored: Record<string, RecoveryMemoryIgnoredReason> = {};
  const candidates: CompiledRecoveryMemoryCandidate[] = [];
  const pack = input.context.contextPack;
  const boundaryMatches = input.context.hook === input.hook && pack.journey === "autonomous"
    && pack.missionId === input.missionId && pack.runId === input.runId
    && pack.scopePolicy.missionId === input.missionId
    && (pack.scopePolicy.engagementId ?? null) === input.engagementId
    && (!input.stepId || pack.stepId === input.stepId)
    && (!input.actionId || pack.actionId === input.actionId);
  const actionType = input.actionType.trim().toLowerCase();
  const actionClass = input.actionClass.trim().toLowerCase();

  for (const item of input.context.items) {
    const node = item.node;
    if (!boundaryMatches) {
      ignored[node.id] = "context_boundary_mismatch";
      continue;
    }
    const nodeReason = eligibilityReason(node, input.missionId, input.engagementId);
    if (nodeReason) {
      ignored[node.id] = nodeReason;
      continue;
    }
    const policy = parsePolicy(node);
    if (!policy) {
      ignored[node.id] = "typed_policy_missing_or_invalid";
      continue;
    }
    if (policy.failureCategories && !policy.failureCategories.includes(input.failureCategory)) {
      ignored[node.id] = "failure_category_mismatch";
      continue;
    }
    if (policy.actionTypes && !policy.actionTypes.includes(actionType)) {
      ignored[node.id] = "action_type_mismatch";
      continue;
    }
    if (policy.actionClasses && !policy.actionClasses.includes(actionClass)) {
      ignored[node.id] = "action_class_mismatch";
      continue;
    }
    candidates.push({
      nodeId: node.id,
      denyRetry: policy.denyRetry,
      ...(policy.minimumBackoffMs === undefined ? {} : { minimumBackoffMs: policy.minimumBackoffMs }),
      ...(policy.alternativeStepId ? { alternativeStepId: policy.alternativeStepId } : {}),
    });
  }

  candidates.sort((left, right) => left.nodeId.localeCompare(right.nodeId));
  return {
    schemaVersion: AUTONOMOUS_RECOVERY_MEMORY_SCHEMA_VERSION,
    compilerVersion: AUTONOMOUS_RECOVERY_MEMORY_COMPILER_VERSION,
    hook: input.hook,
    contextPackId: pack.id,
    missionId: input.missionId,
    runId: input.runId,
    ...(input.stepId ? { stepId: input.stepId } : {}),
    ...(input.actionId ? { actionId: input.actionId } : {}),
    failureCategory: input.failureCategory,
    candidates,
    ignored,
  };
}

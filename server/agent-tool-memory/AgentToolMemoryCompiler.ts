import type { BrainContextResult } from "../brain-runtime";
import type { Journey, MemoryNode } from "../memory";
import {
  AGENT_TOOL_MEMORY_COMPILER_VERSION,
  AGENT_TOOL_MEMORY_SCHEMA_VERSION,
  type AgentToolMemoryCandidate,
  type AgentToolMemoryHook,
  type AgentToolMemoryIgnoredReason,
  type AgentToolMemoryVerdict,
  type AgentToolRepresentedSelection,
  type CompiledAgentToolMemoryDecision,
} from "./types";

const POLICY_KEY = "agentToolDecision";
const SAFE_CODE = /^[a-z][a-z0-9._:-]{0,127}$/u;
const ALLOWED_NODE_TYPES = new Set([
  "agent",
  "tool",
  "mcp_capability",
  "prerequisite",
  "failure_mode",
  "operational_hazard",
  "recovery_pattern",
  "lesson",
  "attack_lesson",
]);
const VERIFIED_LESSON_TYPES = new Set(["lesson", "attack_lesson"]);
const VERDICTS = new Set<AgentToolMemoryVerdict>([
  "compatible",
  "incompatible",
  "missing_dependency",
]);

interface TypedAgentToolPolicy {
  readonly hooks: readonly AgentToolMemoryHook[];
  readonly agentIds?: readonly string[];
  readonly actionTypes?: readonly string[];
  readonly actionClasses?: readonly string[];
  readonly verdict: AgentToolMemoryVerdict;
  readonly reasonCode: string;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const permitted = new Set(allowed);
  return Object.keys(value).every((key) => permitted.has(key));
}

function strings(
  value: unknown,
  maximumItems = 32,
  validator: (value: string) => boolean = (item) => item.length <= 160,
): readonly string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length === 0 || value.length > maximumItems) return undefined;
  const normalized = value.map((item) =>
    typeof item === "string" ? item.trim().toLocaleLowerCase("en-US") : "");
  if (normalized.some((item) => !item || !validator(item))) return undefined;
  return [...new Set(normalized)].sort();
}

function parsePolicy(node: MemoryNode): TypedAgentToolPolicy | undefined {
  const policy = object(node.retentionPolicy[POLICY_KEY]);
  if (!policy || !exactKeys(policy, ["schemaVersion", "match", "effect"])) return undefined;
  if (policy.schemaVersion !== AGENT_TOOL_MEMORY_SCHEMA_VERSION) return undefined;
  const match = object(policy.match);
  const effect = object(policy.effect);
  if (!match || !effect) return undefined;
  if (!exactKeys(match, ["hooks", "agentIds", "actionTypes", "actionClasses"])) return undefined;
  if (!exactKeys(effect, ["verdict", "reasonCode"])) return undefined;
  const hooks = strings(match.hooks, 2, (item) =>
    item === "assignment_acceptance" || item === "tool_selection") as
    readonly AgentToolMemoryHook[] | undefined;
  if (!hooks) return undefined;
  const agentIds = strings(match.agentIds);
  const actionTypes = strings(match.actionTypes);
  const actionClasses = strings(match.actionClasses);
  if (match.agentIds !== undefined && !agentIds) return undefined;
  if (match.actionTypes !== undefined && !actionTypes) return undefined;
  if (match.actionClasses !== undefined && !actionClasses) return undefined;
  if (typeof effect.verdict !== "string" || !VERDICTS.has(effect.verdict as AgentToolMemoryVerdict)) {
    return undefined;
  }
  if (typeof effect.reasonCode !== "string" || !SAFE_CODE.test(effect.reasonCode)) return undefined;
  return {
    hooks,
    ...(agentIds ? { agentIds } : {}),
    ...(actionTypes ? { actionTypes } : {}),
    ...(actionClasses ? { actionClasses } : {}),
    verdict: effect.verdict as AgentToolMemoryVerdict,
    reasonCode: effect.reasonCode,
  };
}

function scopeMatches(node: MemoryNode, missionId: string, engagementId: string | null): boolean {
  if (node.scope.kind === "global") return true;
  if (node.scope.kind === "mission") return node.scope.missionId === missionId;
  return Boolean(engagementId && node.scope.engagementId === engagementId);
}

function eligibilityReason(input: {
  readonly node: MemoryNode;
  readonly journey: Journey;
  readonly missionId: string;
  readonly engagementId: string | null;
  readonly activeVaultBackedNodeIds: ReadonlySet<string>;
}): AgentToolMemoryIgnoredReason | undefined {
  const { node } = input;
  if (!input.activeVaultBackedNodeIds.has(node.id)) return "node_not_active_vault_backed";
  if (!ALLOWED_NODE_TYPES.has(node.nodeType)) return "node_type_not_allowed";
  if (node.lifecycleStatus !== "confirmed" && node.lifecycleStatus !== "verified") {
    return "node_not_confirmed_or_verified";
  }
  if (VERIFIED_LESSON_TYPES.has(node.nodeType) && node.lifecycleStatus !== "verified") {
    return "lesson_not_verified";
  }
  if (
    (input.journey === "autonomous" && node.retentionPolicy.allowAutonomous === false) ||
    (input.journey === "guided" && node.retentionPolicy.allowGuided === false) ||
    (node.retentionPolicy.journeys && !node.retentionPolicy.journeys.includes(input.journey))
  ) return "journey_use_not_permitted";
  if (!scopeMatches(node, input.missionId, input.engagementId)) return "scope_mismatch";
  return undefined;
}

function resolvedVerdict(candidates: readonly AgentToolMemoryCandidate[]): AgentToolMemoryVerdict | undefined {
  if (candidates.some((candidate) => candidate.verdict === "missing_dependency")) {
    return "missing_dependency";
  }
  if (candidates.some((candidate) => candidate.verdict === "incompatible")) return "incompatible";
  if (candidates.some((candidate) => candidate.verdict === "compatible")) return "compatible";
  return undefined;
}

export interface CompileAgentToolMemoryInput {
  readonly hook: AgentToolMemoryHook;
  readonly context: BrainContextResult;
  readonly journey: Journey;
  readonly missionId: string;
  readonly engagementId: string | null;
  readonly runId: string;
  readonly stepId: string;
  readonly selection: AgentToolRepresentedSelection;
  readonly activeVaultBackedNodeIds: ReadonlySet<string>;
}

/**
 * Compile a local constraint or attestation over an already represented
 * selection. Retained prose is never parsed and the result contains no field
 * capable of introducing or changing a target, tool, action class, argument,
 * authorization, or provider disclosure.
 */
export function compileAgentToolMemoryDecision(
  input: CompileAgentToolMemoryInput,
): CompiledAgentToolMemoryDecision {
  const ignored: Record<string, AgentToolMemoryIgnoredReason> = {};
  const candidates: AgentToolMemoryCandidate[] = [];
  const pack = input.context.contextPack;
  const boundaryMatches = input.context.hook === input.hook
    && pack.journey === input.journey
    && pack.missionId === input.missionId
    && pack.runId === input.runId
    && pack.stepId === input.stepId
    && !pack.actionId;
  const agentId = input.selection.representedAgentId?.trim().toLocaleLowerCase("en-US");
  const actionType = input.selection.representedActionType.trim().toLocaleLowerCase("en-US");
  const actionClass = input.selection.representedActionClass.trim().toLocaleLowerCase("en-US");

  for (const item of input.context.items) {
    const node = item.node;
    if (!boundaryMatches) {
      ignored[node.id] = "context_boundary_mismatch";
      continue;
    }
    const reason = eligibilityReason({
      node,
      journey: input.journey,
      missionId: input.missionId,
      engagementId: input.engagementId,
      activeVaultBackedNodeIds: input.activeVaultBackedNodeIds,
    });
    if (reason) {
      ignored[node.id] = reason;
      continue;
    }
    const policy = parsePolicy(node);
    if (!policy) {
      ignored[node.id] = "typed_policy_missing_or_invalid";
      continue;
    }
    if (!policy.hooks.includes(input.hook)) {
      ignored[node.id] = "hook_mismatch";
      continue;
    }
    if (input.hook === "assignment_acceptance" && !policy.agentIds) {
      ignored[node.id] = "required_represented_agent_match_missing";
      continue;
    }
    if (input.hook === "tool_selection" && !policy.actionTypes) {
      ignored[node.id] = "required_represented_action_match_missing";
      continue;
    }
    if (policy.agentIds && (!agentId || !policy.agentIds.includes(agentId))) {
      ignored[node.id] = "represented_agent_mismatch";
      continue;
    }
    if (policy.actionTypes && !policy.actionTypes.includes(actionType)) {
      ignored[node.id] = "represented_action_type_mismatch";
      continue;
    }
    if (policy.actionClasses && !policy.actionClasses.includes(actionClass)) {
      ignored[node.id] = "represented_action_class_mismatch";
      continue;
    }
    candidates.push({
      nodeId: node.id,
      verdict: policy.verdict,
      reasonCode: policy.reasonCode,
    });
  }

  candidates.sort((left, right) => left.nodeId.localeCompare(right.nodeId));
  const verdict = resolvedVerdict(candidates);
  const appliedNodeIds = verdict
    ? candidates.filter((candidate) => candidate.verdict === verdict).map((candidate) => candidate.nodeId)
    : [];
  return {
    schemaVersion: AGENT_TOOL_MEMORY_SCHEMA_VERSION,
    compilerVersion: AGENT_TOOL_MEMORY_COMPILER_VERSION,
    hook: input.hook,
    journey: input.journey,
    contextPackId: pack.id,
    brainAuditRecordId: input.context.auditRecordId,
    missionId: input.missionId,
    engagementId: input.engagementId,
    runId: input.runId,
    stepId: input.stepId,
    selection: input.selection,
    decision: verdict === "missing_dependency"
      ? "veto_missing_dependency"
      : verdict === "incompatible"
        ? "veto_incompatible"
        : verdict === "compatible"
          ? "attest_compatible"
          : "no_applicable_memory",
    candidates,
    appliedNodeIds,
    ignored,
  };
}

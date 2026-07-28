import type { SqliteDatabase } from "../db/types";
import type {
  Journey,
  MemoryNode,
  MemoryScope,
  MemorySensitivity,
  RetrievalPolicy,
} from "./types";
import { isAttackCentricReusableNodeType } from "./types";
import { autonomousMemoryConfirmationEligible } from "./AutonomousMemoryInfluence";

const SENSITIVITY_RANK: Record<MemorySensitivity, number> = {
  public: 0,
  internal: 1,
  private: 2,
  restricted: 3,
};

interface CanonicalMissionScope {
  readonly engagementId: string | null;
  readonly journey: Journey;
}

function isCurrentRuntimeCapability(node: MemoryNode): boolean {
  if (!["agent", "tool", "mcp_capability"].includes(node.nodeType)) return false;
  const projection = node.retentionPolicy.runtimeCapabilityProjection;
  const decision = node.retentionPolicy.agentToolDecision;
  return node.authorType === "system"
    && node.authorId === "system:runtime-capability-memory-projector"
    && node.lifecycleStatus === "verified"
    && projection !== null
    && typeof projection === "object"
    && !Array.isArray(projection)
    && (projection as Record<string, unknown>).schemaVersion
      === "ti-scale.runtime-capability-memory-projection.v1"
    && (projection as Record<string, unknown>).status === "current"
    && decision !== null
    && typeof decision === "object"
    && !Array.isArray(decision)
    && (decision as Record<string, unknown>).schemaVersion === "1";
}

export function requireCanonicalMissionScope(
  database: SqliteDatabase,
  missionId: string,
): CanonicalMissionScope {
  const row = database.prepare(`
    SELECT engagement_id, journey FROM missions WHERE id = ?
  `).get(missionId) as { engagement_id: string | null; journey: Journey } | undefined;
  if (!row) throw new Error("Mission-scoped memory requires its canonical mission");
  return { engagementId: row.engagement_id, journey: row.journey };
}

/** Reject contradictory mission/engagement labels before reusable memory is stored. */
export function assertCanonicalMemoryScope(
  database: SqliteDatabase,
  scope: MemoryScope,
): void {
  if (scope.kind !== "mission" || !scope.missionId) return;
  const canonical = requireCanonicalMissionScope(database, scope.missionId);
  if (scope.engagementId && scope.engagementId !== canonical.engagementId) {
    throw new Error("Mission memory engagement does not match its canonical mission");
  }
}

export function memoryScopeMatchesPolicy(
  database: SqliteDatabase,
  node: MemoryNode,
  policy: RetrievalPolicy,
): boolean {
  const scopeClasses = policy.allowedScopeClasses;
  const attackKnowledge = isAttackCentricReusableNodeType(node.nodeType);
  const currentRuntimeCapability = isCurrentRuntimeCapability(node);
  if (scopeClasses) {
    const allowed = new Set(scopeClasses);
    const confirmedAttackKnowledgeAllowed = allowed.has("confirmed_attack_knowledge");
    const verifiedAttackKnowledgeAllowed = allowed.has("verified_attack_knowledge");
    const typeAllowed = node.nodeType === "preference"
      ? allowed.has("confirmed_preferences")
      : node.nodeType === "lesson"
        ? allowed.has("verified_lessons")
        : attackKnowledge
          ? node.lifecycleStatus === "verified"
            ? verifiedAttackKnowledgeAllowed || confirmedAttackKnowledgeAllowed
            : node.lifecycleStatus === "confirmed" && confirmedAttackKnowledgeAllowed
        : currentRuntimeCapability
          ? allowed.has("current_runtime_capabilities")
        : true;
    if (!typeAllowed) return false;
    if (node.scope.kind === "global") {
      // Only explicitly reviewable global classes may cross mission
      // boundaries. Operational mission/target/evidence records never become
      // retrieval authority merely because global retrieval is enabled.
      if (
        node.nodeType !== "preference"
        && node.nodeType !== "lesson"
        && !attackKnowledge
        && !currentRuntimeCapability
      ) return false;
      return policy.allowGlobal === true;
    }
    // A signed preference/lesson class permits that reviewed node type inside
    // the canonical current mission or engagement enforced below. The broader
    // engagement-memory authority is still required for every other
    // operational node type; it never becomes implicit through lesson use.
    if (
      node.nodeType !== "preference"
      && node.nodeType !== "lesson"
      && !attackKnowledge
      && !currentRuntimeCapability
      &&
      !allowed.has("engagement_memory")
    ) return false;
  }
  if (node.scope.kind === "global") return policy.allowGlobal !== false;
  if (node.scope.kind === "engagement") {
    return Boolean(policy.engagementId && node.scope.engagementId === policy.engagementId);
  }
  if (!node.scope.missionId || !policy.missionId || node.scope.missionId !== policy.missionId) {
    return false;
  }
  let canonical: CanonicalMissionScope;
  try {
    canonical = requireCanonicalMissionScope(database, node.scope.missionId);
  } catch {
    return false;
  }
  if (policy.engagementId && policy.engagementId !== canonical.engagementId) return false;
  if (node.scope.engagementId && node.scope.engagementId !== canonical.engagementId) return false;
  return true;
}

export function memoryNodeMatchesPolicy(
  database: SqliteDatabase,
  node: MemoryNode,
  policy: RetrievalPolicy,
  now: string,
): boolean {
  const statuses = policy.allowedStatuses ?? ["confirmed", "verified"];
  if (!statuses.includes(node.lifecycleStatus as "confirmed" | "verified")) return false;
  if (
    policy.journey === "autonomous"
    && !autonomousMemoryConfirmationEligible(node)
  ) return false;
  if (node.expiresAt && Date.parse(node.expiresAt) <= Date.parse(now)) return false;
  if (SENSITIVITY_RANK[node.sensitivity] > SENSITIVITY_RANK[policy.maximumSensitivity]) return false;
  if (policy.allowedNodeTypes && !policy.allowedNodeTypes.includes(node.nodeType)) return false;
  if (!memoryScopeMatchesPolicy(database, node, policy)) return false;
  const retention = node.retentionPolicy;
  if (retention.journeys && !retention.journeys.includes(policy.journey)) return false;
  if (policy.journey === "autonomous" && retention.allowAutonomous === false) return false;
  if (policy.journey === "guided" && retention.allowGuided === false) return false;
  return true;
}

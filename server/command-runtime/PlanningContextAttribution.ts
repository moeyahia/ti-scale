import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { MemoryRepository, SecondBrainService } from "../memory";
import type {
  ContextPack,
  MemoryNode,
  PlanningContextAttribution,
} from "../memory";
import { canonicalLessonMemoryNodeId } from "../learning/AttackChainLessonRepository";
import type { Journey } from "../supervisor";

function parseObject(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

export function verifiedPlanningLesson(
  database: SqliteDatabase,
  pack: ContextPack,
  node: MemoryNode,
  now: string,
): { readonly id: string } | undefined {
  if (!pack.missionId || !pack.runId || node.nodeType !== "lesson" || node.lifecycleStatus !== "verified") {
    return undefined;
  }
  if (node.sensitivity === "restricted" || (node.expiresAt && node.expiresAt <= now)) return undefined;
  if (node.retentionPolicy.journeys && !node.retentionPolicy.journeys.includes(pack.journey)) return undefined;
  if (pack.journey === "autonomous" && node.retentionPolicy.allowAutonomous !== true) return undefined;
  if (pack.journey === "guided" && node.retentionPolicy.allowGuided !== true) return undefined;
  const packRow = database.prepare(`
    SELECT mcp.mission_id, mcp.run_id, mcp.journey, mcp.scope_policy_json,
      r.mission_id AS run_mission_id, r.journey AS run_journey,
      m.engagement_id
    FROM memory_context_packs mcp
    JOIN runs r ON r.id = mcp.run_id
    JOIN missions m ON m.id = mcp.mission_id
    WHERE mcp.id = ?
  `).get(pack.id) as {
    mission_id: string;
    run_id: string;
    journey: Journey;
    scope_policy_json: string;
    run_mission_id: string;
    run_journey: Journey;
    engagement_id: string | null;
  } | undefined;
  if (
    !packRow ||
    packRow.mission_id !== pack.missionId ||
    packRow.run_id !== pack.runId ||
    packRow.run_mission_id !== pack.missionId ||
    packRow.journey !== pack.journey ||
    packRow.run_journey !== pack.journey
  ) return undefined;
  const scopePolicy = parseObject(packRow.scope_policy_json);
  if (typeof scopePolicy.missionId === "string" && scopePolicy.missionId !== pack.missionId) return undefined;
  if (typeof scopePolicy.engagementId === "string" && scopePolicy.engagementId !== packRow.engagement_id) return undefined;
  const lessonSource = node.provenance.sources.find((source) =>
    source.sourceType === "lesson" && canonicalLessonMemoryNodeId(source.sourceId) === node.id);
  if (!lessonSource || node.id !== canonicalLessonMemoryNodeId(lessonSource.sourceId)) return undefined;
  const lesson = database.prepare(`
    SELECT id, engagement_id, mission_id FROM lessons
    WHERE id = ? AND status = 'verified' AND (expires_at IS NULL OR expires_at > ?)
  `).get(lessonSource.sourceId, now) as {
    id: string;
    engagement_id: string | null;
    mission_id: string | null;
  } | undefined;
  if (!lesson) return undefined;
  if (lesson.engagement_id && lesson.engagement_id !== packRow.engagement_id) return undefined;
  if (lesson.mission_id && lesson.mission_id !== pack.missionId) return undefined;
  if (lesson.engagement_id) {
    if (node.scope.kind !== "engagement" || node.scope.engagementId !== lesson.engagement_id) return undefined;
  } else if (lesson.mission_id) {
    if (node.scope.kind !== "mission" || node.scope.missionId !== lesson.mission_id) return undefined;
  } else if (node.scope.kind !== "global") {
    return undefined;
  }
  return { id: lesson.id };
}

export function commitPlanningContextAttribution(
  database: SqliteDatabase,
  attribution: PlanningContextAttribution | undefined,
  expected: {
    readonly missionId: string;
    readonly runId: string;
    readonly journey: Journey;
    readonly usedAt: string;
  },
): void {
  if (!attribution || attribution.contextPackIds.length === 0) return;
  const repository = new MemoryRepository(database);
  const brain = new SecondBrainService(repository);
  const events = new EventRepository(database);
  const used = new Map(attribution.citations.map((citation) => [citation.nodeId, citation.influence]));

  inImmediateTransaction(database, () => {
    for (const packId of [...new Set(attribution.contextPackIds)]) {
      const pack = repository.requireContextPack(packId);
      if (
        pack.missionId !== expected.missionId ||
        pack.runId !== expected.runId ||
        pack.journey !== expected.journey
      ) {
        throw new Error("Planning context attribution crosses its canonical mission, run, or journey");
      }
      for (const item of pack.items) {
        const influence = used.get(item.nodeId);
        const node = repository.getNode(item.nodeId);
        const lesson = node?.nodeType === "lesson"
          ? verifiedPlanningLesson(database, pack, node, expected.usedAt)
          : undefined;
        if (node?.nodeType === "lesson" && !lesson) {
          brain.recordContextUse(pack.id, {
            nodeId: item.nodeId,
            used: false,
            relevanceReason: item.relevanceReason,
            ignoredReason: "The lesson failed canonical identity, scope, retention, or journey revalidation.",
          });
          continue;
        }
        brain.recordContextUse(pack.id, influence
          ? {
              nodeId: item.nodeId,
              used: true,
              relevanceReason: item.relevanceReason,
              influenceSummary: influence,
            }
          : {
              nodeId: item.nodeId,
              used: false,
              relevanceReason: item.relevanceReason,
              ignoredReason: "The planner did not cite this memory as influencing the bounded plan.",
            });
        if (!influence || !pack.runId || !pack.missionId || node?.nodeType !== "lesson" || !lesson) continue;
        const usageId = `usage_${createHash("sha256")
          .update(`${pack.id}\n${lesson.id}`, "utf8").digest("hex").slice(0, 32)}`;
        const inserted = database.prepare(`
          INSERT OR IGNORE INTO lesson_usage (
            id, lesson_id, mission_id, run_id, context_pack_id,
            influence_summary, measured_impact_json, used_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          usageId,
          lesson.id,
          pack.missionId,
          pack.runId,
          pack.id,
          influence,
          JSON.stringify({ attribution: "planner_citation", selectedFrom: "verified_context_pack" }),
          expected.usedAt,
        );
        if (inserted.changes === 1) {
          events.append({
            missionId: pack.missionId,
            runId: pack.runId,
            journey: pack.journey,
            eventType: "learning.lesson_reused",
            actorType: "agent",
            actorId: "grok-acp-planner",
            summary: "A verified lesson materially influenced the bounded plan",
            payload: {
              lessonId: lesson.id,
              memoryNodeId: node.id,
              contextPackId: pack.id,
              influenceSummary: influence,
            },
            occurredAt: expected.usedAt,
            contextPackId: pack.id,
            sensitivity: "private",
          });
        }
      }
    }
  });
}

import { createDatabaseConnection } from "../../../server/db";
import { MemoryRepository } from "../../../server/memory/MemoryRepository";
import {
  MEMORY_EDGE_TYPES,
  MEMORY_NODE_TYPES,
  type MemoryEdgeType,
  type MemoryLifecycle,
  type MemoryNodeType,
  type MemoryScope,
  type MemorySensitivity,
} from "../../../server/memory/types";
import { hashCanonical } from "../../../server/missions/canonical";
import { MissionRepository } from "../../../server/missions/MissionRepository";
import { validateMissionCreateRequest } from "../../../server/missions/validation";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_TIME = "2099-07-16T12:00:00.000Z";
export const BRAIN_GRAPH_FIXTURE_NODE_COUNT = 276;
export const BRAIN_GRAPH_FIXTURE_INITIAL_LIMIT = 250;

const FILLER_NODE_TYPES = [
  "entity",
  "asset",
  "technique",
  "tool",
  "evidence",
  "agent",
  "failure",
  "lesson",
  "source",
] as const satisfies readonly MemoryNodeType[];

type GraphCluster = "operator" | "mission" | "attack" | "tool" | "evidence" | "agent" | "failure" | "lesson" | "other";

export interface BrainGraphFixture {
  readonly namespace: string;
  readonly engagementId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly operatorNodeId: string;
  readonly operatorTitle: string;
  readonly preferenceNodeId: string;
  readonly preferenceTitle: string;
  readonly secondaryNodeId: string;
  readonly secondaryTitle: string;
  readonly contextPackId: string;
  readonly nodeCount: number;
  readonly edgeCount: number;
}

export interface BrainGraphFixtureState {
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly preferencePinned: boolean;
  readonly contextPackUsedItems: number;
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Brain-graph E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

function clusterFor(nodeType: MemoryNodeType): GraphCluster {
  if (nodeType === "operator" || nodeType === "preference") return "operator";
  if (["mission", "run", "plan", "phase", "step", "target", "asset", "entity", "decision"].includes(nodeType)) return "mission";
  if (["tactic", "technique", "procedure"].includes(nodeType)) return "attack";
  if (nodeType === "tool" || nodeType === "mcp_capability") return "tool";
  if (["evidence", "finding", "artifact", "report", "source"].includes(nodeType)) return "evidence";
  if (nodeType === "agent") return "agent";
  if (nodeType === "failure" || nodeType === "recovery") return "failure";
  if (nodeType === "lesson" || nodeType === "evaluation") return "lesson";
  return "other";
}

function titleFor(nodeType: MemoryNodeType, namespace: string): string {
  if (nodeType === "operator") return `Graph fixture operator ${namespace}`;
  if (nodeType === "preference") return `Evidence-first explanations ${namespace}`;
  if (nodeType === "mission") return `Canonical graph mission ${namespace}`;
  if (nodeType === "failure") return `Bounded provider failure ${namespace}`;
  if (nodeType === "recovery") return `Verified fallback recovery ${namespace}`;
  if (nodeType === "lesson") return `Avoid repeated no-progress actions ${namespace}`;
  return `${nodeType.replaceAll("_", " ")} memory ${namespace}`;
}

function lifecycleFor(nodeType: MemoryNodeType): MemoryLifecycle {
  if (nodeType === "operator" || nodeType === "preference") return "confirmed";
  if (nodeType === "failure") return "disputed";
  if (nodeType === "evaluation") return "stale";
  return "verified";
}

function sensitivityFor(nodeType: MemoryNodeType): MemorySensitivity {
  if (nodeType === "operator" || nodeType === "preference") return "private";
  if (nodeType === "source") return "restricted";
  if (nodeType === "tool") return "public";
  return "internal";
}

function coreNodeId(
  nodeType: MemoryNodeType,
  namespace: string,
  missionId: string,
  runId: string,
): string {
  if (nodeType === "mission") return missionId;
  if (nodeType === "run") return runId;
  return `mem-brain-graph-${namespace}-${nodeType}`;
}

function sourceScope(
  nodeType: MemoryNodeType,
  engagementId: string,
  missionId: string,
): MemoryScope {
  return nodeType === "operator" || nodeType === "preference"
    ? { kind: "engagement", engagementId }
    : { kind: "mission", engagementId, missionId };
}

/**
 * Seeds a progressive, canonical memory graph through production repositories.
 *
 * The 276 nodes deliberately cross the UI's 250-node initial segment. Every
 * canonical node type, every edge type, all nine visual clusters, provenance,
 * version history, every reachable typed visual cluster, and a used Context
 * Pack are represented without fixtures in the production response path.
 */
export function createBrainGraphFixture(instanceId: string): BrainGraphFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const engagementId = `eng-brain-graph-${namespace}`;
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const request = validateMissionCreateRequest({
      journey: "guided",
      launch: true,
      authorizationConfirmed: true,
      title: `Canonical Brain graph browser fixture ${namespace}`,
      objective: "Inspect a bounded, attributed memory graph without exposing unrelated engagement knowledge.",
      target: "https://brain-graph-fixture.example.test",
      engagementId,
      explanationDepth: "balanced",
      executionPreference: "manual",
      evidenceExpectations: ["Every graph relationship retains attributable canonical provenance"],
    });
    const created = new MissionRepository(database).create({
      request,
      requestHash: hashCanonical(request),
      idempotencyKey: `brain-graph-e2e-${namespace}`,
      actorId: "e2e-local-operator",
    });

    let generatedId = 0;
    const repository = new MemoryRepository(database, {
      clock: () => new Date(FIXTURE_TIME),
      createId: (prefix) => `${prefix}_brain_graph_${namespace}_${++generatedId}`,
    });
    const coreIds = new Map<MemoryNodeType, string>();
    for (const nodeType of MEMORY_NODE_TYPES) {
      const id = coreNodeId(nodeType, namespace, created.mission.id, created.run.id);
      coreIds.set(nodeType, id);
      const lifecycleStatus = lifecycleFor(nodeType);
      repository.createNode({
        id,
        nodeType,
        title: titleFor(nodeType, namespace),
        summary: `Canonical ${nodeType.replaceAll("_", " ")} knowledge retained for deterministic graph traversal.`,
        body: `This sanitized fixture note represents ${nodeType.replaceAll("_", " ")} knowledge and contains no credentials or client payloads.`,
        scope: sourceScope(nodeType, engagementId, created.mission.id),
        sensitivity: sensitivityFor(nodeType),
        confidence: nodeType === "evaluation" ? 0.55 : nodeType === "failure" ? 0.72 : 0.96,
        lifecycleStatus,
        confirmationState: lifecycleStatus === "confirmed" ? "confirmed" : "not_required",
        provenance: {
          method: nodeType === "operator" || nodeType === "preference" ? "operator_statement" : "evidence",
          explanation: `The isolated browser fixture created this ${nodeType.replaceAll("_", " ")} node through the canonical memory repository.`,
          sources: [{
            sourceType: "e2e_fixture",
            sourceId: `brain-graph-source-${namespace}-${nodeType}`,
            acquiredAt: FIXTURE_TIME,
            excerptRedacted: `Sanitized ${nodeType.replaceAll("_", " ")} fixture source.`,
          }],
        },
        authorType: nodeType === "operator" || nodeType === "preference" ? "operator" : "agent",
        authorId: nodeType === "operator" || nodeType === "preference" ? "e2e-local-operator" : "brain-graph-fixture-agent",
        retentionPolicy: { allowGuided: true, allowAutonomous: nodeType !== "failure", journeys: ["guided"] },
      });
    }

    const fillerCount = BRAIN_GRAPH_FIXTURE_NODE_COUNT - MEMORY_NODE_TYPES.length;
    const fillerNodes: Array<{ readonly id: string; readonly nodeType: MemoryNodeType }> = [];
    for (let index = 0; index < fillerCount; index += 1) {
      const nodeType = FILLER_NODE_TYPES[index % FILLER_NODE_TYPES.length]!;
      const id = `mem-brain-graph-${namespace}-filler-${String(index + 1).padStart(3, "0")}`;
      fillerNodes.push({ id, nodeType });
      repository.createNode({
        id,
        nodeType,
        title: `Progressive ${nodeType.replaceAll("_", " ")} ${String(index + 1).padStart(3, "0")} ${namespace}`,
        summary: "A deterministic progressive-loading fixture node with attributable local provenance.",
        body: "This bounded fixture node exists to exercise clustering, progressive detail, and worker layout at realistic local scale.",
        scope: { kind: "mission", engagementId, missionId: created.mission.id },
        sensitivity: index % 11 === 0 ? "private" : "internal",
        confidence: 0.9 + (index % 10) / 100,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: {
          method: "derived",
          explanation: "Generated deterministically from the canonical browser graph fixture definition.",
          sources: [{
            sourceType: "e2e_fixture",
            sourceId: `brain-graph-filler-source-${namespace}-${index + 1}`,
            acquiredAt: FIXTURE_TIME,
          }],
        },
        authorType: "system",
        authorId: "brain-graph-fixture",
        retentionPolicy: { allowGuided: true, journeys: ["guided"] },
      });
    }

    let edgeCount = 0;
    const createEdge = (sourceNodeId: string, targetNodeId: string, edgeType: MemoryEdgeType, purpose: string) => {
      edgeCount += 1;
      repository.createEdge({
        id: `medge-brain-graph-${namespace}-${String(edgeCount).padStart(4, "0")}`,
        sourceNodeId,
        targetNodeId,
        edgeType,
        title: `${edgeType.replaceAll("_", " ")} relationship`,
        summary: purpose,
        scope: { kind: "mission", engagementId, missionId: created.mission.id },
        sensitivity: "internal",
        confidence: 0.95,
        lifecycleStatus: "verified",
        provenance: {
          method: "derived",
          explanation: "The canonical graph fixture records the reason for this typed relationship.",
          sources: [{
            sourceType: "e2e_fixture",
            sourceId: `brain-graph-edge-source-${namespace}-${edgeCount}`,
            acquiredAt: FIXTURE_TIME,
          }],
        },
        explanation: purpose,
        authorType: "system",
        authorId: "brain-graph-fixture",
      });
    };

    const coreEntries = MEMORY_NODE_TYPES.map((nodeType) => ({ nodeType, id: coreIds.get(nodeType)! }));
    for (let index = 1; index < coreEntries.length; index += 1) {
      createEdge(
        coreEntries[index - 1]!.id,
        coreEntries[index]!.id,
        MEMORY_EDGE_TYPES[(index - 1) % MEMORY_EDGE_TYPES.length]!,
        `The fixture preserves a typed ${MEMORY_EDGE_TYPES[(index - 1) % MEMORY_EDGE_TYPES.length]!.replaceAll("_", " ")} explanation between adjacent canonical domains.`,
      );
    }
    const missionNodeId = coreIds.get("mission")!;
    for (const entry of coreEntries) {
      if (entry.id === missionNodeId) continue;
      createEdge(entry.id, missionNodeId, "belongs_to", "This canonical memory belongs to the represented mission cluster.");
    }

    const clusterAnchors: Record<GraphCluster, string> = {
      operator: coreIds.get("operator")!,
      mission: coreIds.get("mission")!,
      attack: coreIds.get("technique")!,
      tool: coreIds.get("tool")!,
      evidence: coreIds.get("evidence")!,
      agent: coreIds.get("agent")!,
      failure: coreIds.get("failure")!,
      lesson: coreIds.get("lesson")!,
      other: coreIds.get("entity")!,
    };
    for (const filler of fillerNodes) {
      createEdge(
        filler.id,
        clusterAnchors[clusterFor(filler.nodeType)],
        "belongs_to",
        "This progressive fixture node belongs to its semantic graph cluster.",
      );
    }

    const preferenceNode = repository.requireNode(coreIds.get("preference")!);
    const contextPackId = `ctx-brain-graph-${namespace}`;
    repository.persistContextPack({
      id: contextPackId,
      missionId: created.mission.id,
      runId: created.run.id,
      journey: "guided",
      purpose: "Adapt the represented Guided explanation to the confirmed evidence-first preference",
      queryRedacted: "confirmed explanation preference for the current engagement",
      scopePolicy: {
        engagementId,
        missionId: created.mission.id,
        allowGlobal: false,
        journey: "guided",
        maximumSensitivity: "private",
        allowedNodeTypes: ["preference"],
        allowedStatuses: ["confirmed"],
        contextBudget: 1_024,
        limit: 1,
        graphDepth: 0,
        exactNodeIds: [preferenceNode.id],
        exactNodeIdsOnly: true,
      },
      contextBudget: 1_024,
      retrievalMetrics: { durationMs: 1, retrievedCount: 1, signals: ["exact"] },
      createdBy: "brain-graph-fixture-agent",
      items: [{
        node: preferenceNode,
        score: 0.99,
        relevanceReason: "The operator explicitly confirmed evidence-first explanations for this engagement.",
        signals: ["exact"],
      }],
    });
    repository.setContextItemDisposition(contextPackId, {
      nodeId: preferenceNode.id,
      used: true,
      relevanceReason: "The preference is confirmed, current, scope-matched, and directly relevant.",
      influenceSummary: "The Guided explanation presents attributable evidence before technique detail.",
    });

    return {
      namespace,
      engagementId,
      missionId: created.mission.id,
      runId: created.run.id,
      operatorNodeId: coreIds.get("operator")!,
      operatorTitle: titleFor("operator", namespace),
      preferenceNodeId: preferenceNode.id,
      preferenceTitle: titleFor("preference", namespace),
      secondaryNodeId: coreIds.get("evidence")!,
      secondaryTitle: titleFor("evidence", namespace),
      contextPackId,
      nodeCount: BRAIN_GRAPH_FIXTURE_NODE_COUNT,
      edgeCount,
    };
  } finally {
    database.close();
  }
}

export function readBrainGraphFixtureState(fixture: BrainGraphFixture): BrainGraphFixtureState {
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const nodeCount = database.prepare(`
      SELECT COUNT(*) AS count FROM memory_nodes
      WHERE engagement_id = ? AND lifecycle_status != 'forgotten'
    `).get(fixture.engagementId) as { readonly count: number };
    const edgeCount = database.prepare(`
      SELECT COUNT(*) AS count FROM memory_edges WHERE id LIKE ?
    `).get(`medge-brain-graph-${fixture.namespace}-%`) as { readonly count: number };
    const preference = database.prepare(`
      SELECT pinned FROM memory_nodes WHERE id = ?
    `).get(fixture.preferenceNodeId) as { readonly pinned: number } | undefined;
    const used = database.prepare(`
      SELECT COUNT(*) AS count FROM memory_context_items WHERE context_pack_id = ? AND used = 1
    `).get(fixture.contextPackId) as { readonly count: number };
    if (!preference) throw new Error("The canonical Brain graph preference fixture is missing");
    return {
      nodeCount: Number(nodeCount.count),
      edgeCount: Number(edgeCount.count),
      preferencePinned: preference.pinned === 1,
      contextPackUsedItems: Number(used.count),
    };
  } finally {
    database.close();
  }
}

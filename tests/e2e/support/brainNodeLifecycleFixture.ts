import { createDatabaseConnection } from "../../../server/db";
import { MemoryRepository } from "../../../server/memory/MemoryRepository";
import { hashCanonical } from "../../../server/missions/canonical";
import { MissionRepository } from "../../../server/missions/MissionRepository";
import { validateMissionCreateRequest } from "../../../server/missions/validation";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_TIME = "2099-07-16T12:00:00.000Z";

export interface BrainNodeLifecycleFixture {
  readonly namespace: string;
  readonly engagementId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly nodeId: string;
  readonly relatedNodeId: string;
  readonly contextPackId: string;
  readonly initialTitle: string;
}

export interface BrainNodeLifecycleState {
  readonly title: string;
  readonly summary: string;
  readonly body: string;
  readonly lifecycleStatus: string;
  readonly sensitivity: string;
  readonly version: number;
  readonly pinned: boolean;
  readonly expiresAt: string | null;
  readonly sourceCount: number;
  readonly versionCount: number;
  readonly edgeCount: number;
  readonly contextItemCount: number;
  readonly representedContextItemCount: number;
  readonly suppressionCount: number;
  readonly forgottenAuditCount: number;
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Brain-node lifecycle E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

export function createBrainNodeLifecycleFixture(instanceId: string): BrainNodeLifecycleFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const engagementId = `eng-brain-node-${namespace}`;
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
      title: `Memory lifecycle browser fixture ${namespace}`,
      objective: "Verify operator-controlled memory correction, retention, dispute, and privacy erasure.",
      target: "https://brain-node-lifecycle.example.test",
      engagementId,
      explanationDepth: "balanced",
      executionPreference: "manual",
      evidenceExpectations: ["Every memory mutation is versioned and auditable"],
    });
    const created = new MissionRepository(database).create({
      request,
      requestHash: hashCanonical(request),
      idempotencyKey: `brain-node-lifecycle-e2e-${namespace}`,
      actorId: "e2e-local-operator",
    });
    let generatedId = 0;
    const repository = new MemoryRepository(database, {
      clock: () => new Date(FIXTURE_TIME),
      createId: (prefix) => `${prefix}_brain_node_${namespace}_${++generatedId}`,
    });
    const nodeId = `mem-brain-node-${namespace}`;
    const relatedNodeId = `mem-brain-node-related-${namespace}`;
    const initialTitle = `Evidence review preference ${namespace}`;
    const scope = { kind: "mission" as const, engagementId, missionId: created.mission.id };
    repository.createNode({
      id: nodeId,
      nodeType: "preference",
      title: initialTitle,
      summary: "Show attributable evidence before detailed technique discussion.",
      body: "The operator explicitly confirmed an evidence-first explanation order for this mission.",
      scope,
      sensitivity: "private",
      confidence: 1,
      lifecycleStatus: "confirmed",
      confirmationState: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "The isolated browser fixture records an explicit operator-confirmed preference.",
        sources: [{
          sourceType: "e2e_fixture",
          sourceId: `brain-node-source-${namespace}`,
          acquiredAt: FIXTURE_TIME,
          excerptRedacted: "Use evidence-first explanations for this mission.",
        }],
      },
      authorType: "operator",
      authorId: "e2e-local-operator",
      retentionPolicy: { allowGuided: true, allowAutonomous: false, journeys: ["guided"] },
    });
    repository.createNode({
      id: relatedNodeId,
      nodeType: "evidence",
      title: `Attributable evidence ${namespace}`,
      summary: "Sanitized evidence relationship used to prove edge erasure.",
      body: "This record contains no client payload or credential material.",
      scope,
      sensitivity: "internal",
      confidence: 0.98,
      lifecycleStatus: "verified",
      confirmationState: "not_required",
      provenance: {
        method: "evidence",
        explanation: "Created by the isolated canonical lifecycle fixture.",
        sources: [{ sourceType: "e2e_fixture", sourceId: `brain-node-related-source-${namespace}`, acquiredAt: FIXTURE_TIME }],
      },
      authorType: "system",
      authorId: "brain-node-lifecycle-fixture",
      retentionPolicy: { allowGuided: true, journeys: ["guided"] },
    });
    repository.createEdge({
      id: `medge-brain-node-${namespace}`,
      sourceNodeId: nodeId,
      targetNodeId: relatedNodeId,
      edgeType: "influenced",
      title: "Influenced evidence presentation",
      summary: "The confirmed preference changed how evidence was presented.",
      scope,
      sensitivity: "private",
      confidence: 1,
      lifecycleStatus: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "The operator-confirmed preference was applied to the represented explanation.",
        sources: [{ sourceType: "e2e_fixture", sourceId: `brain-node-edge-source-${namespace}`, acquiredAt: FIXTURE_TIME }],
      },
      explanation: "The represented explanation led with attributable evidence because of this confirmed preference.",
      authorType: "system",
      authorId: "brain-node-lifecycle-fixture",
    });
    const contextPackId = `ctx-brain-node-${namespace}`;
    const node = repository.requireNode(nodeId);
    repository.persistContextPack({
      id: contextPackId,
      missionId: created.mission.id,
      runId: created.run.id,
      journey: "guided",
      purpose: "Explain why evidence appears before technique detail",
      queryRedacted: "confirmed evidence presentation preference",
      scopePolicy: {
        engagementId,
        missionId: created.mission.id,
        allowGlobal: false,
        journey: "guided",
        maximumSensitivity: "private",
        allowedNodeTypes: ["preference"],
        allowedStatuses: ["confirmed"],
        contextBudget: 512,
        limit: 1,
        graphDepth: 0,
        exactNodeIds: [nodeId],
        exactNodeIdsOnly: true,
      },
      contextBudget: 512,
      retrievalMetrics: { durationMs: 1, retrievedCount: 1, signals: ["exact"] },
      createdBy: "brain-node-lifecycle-fixture",
      items: [{
        node,
        score: 1,
        relevanceReason: "The confirmed mission preference directly controls explanation order.",
        signals: ["exact"],
      }],
    });
    repository.setContextItemDisposition(contextPackId, {
      nodeId,
      used: true,
      relevanceReason: "The preference is confirmed, current, and mission scoped.",
      influenceSummary: "Attributable evidence is presented before technical attack detail.",
    });
    return {
      namespace,
      engagementId,
      missionId: created.mission.id,
      runId: created.run.id,
      nodeId,
      relatedNodeId,
      contextPackId,
      initialTitle,
    };
  } finally {
    database.close();
  }
}

export function readBrainNodeLifecycleState(fixture: BrainNodeLifecycleFixture): BrainNodeLifecycleState {
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const node = database.prepare(`
      SELECT title, summary, body, lifecycle_status, sensitivity, version, pinned, expires_at
      FROM memory_nodes WHERE id = ?
    `).get(fixture.nodeId) as {
      title: string; summary: string; body: string; lifecycle_status: string; sensitivity: string;
      version: number; pinned: number; expires_at: string | null;
    } | undefined;
    if (!node) throw new Error("The canonical Brain-node lifecycle fixture is missing");
    const count = (sql: string, ...parameters: unknown[]) => Number((database.prepare(sql).get(...parameters) as { count: number }).count);
    return {
      title: node.title,
      summary: node.summary,
      body: node.body,
      lifecycleStatus: node.lifecycle_status,
      sensitivity: node.sensitivity,
      version: Number(node.version),
      pinned: Number(node.pinned) === 1,
      expiresAt: node.expires_at,
      sourceCount: count("SELECT COUNT(*) AS count FROM memory_sources WHERE node_id = ?", fixture.nodeId),
      versionCount: count("SELECT COUNT(*) AS count FROM memory_versions WHERE node_id = ?", fixture.nodeId),
      edgeCount: count("SELECT COUNT(*) AS count FROM memory_edges WHERE source_node_id = ? OR target_node_id = ?", fixture.nodeId, fixture.nodeId),
      contextItemCount: count("SELECT COUNT(*) AS count FROM memory_context_items WHERE node_id = ?", fixture.nodeId),
      representedContextItemCount: count(
        "SELECT COUNT(*) AS count FROM memory_context_items WHERE context_pack_id = ? AND node_id = ?",
        fixture.contextPackId,
        fixture.nodeId,
      ),
      suppressionCount: count("SELECT COUNT(*) AS count FROM memory_suppressions WHERE engagement_id = ? AND category = 'preference'", fixture.engagementId),
      forgottenAuditCount: count("SELECT COUNT(*) AS count FROM audit_records WHERE action = 'memory.forgotten' AND resource_id = ?", fixture.nodeId),
    };
  } finally {
    database.close();
  }
}

export function advanceBrainNodeVersion(fixture: BrainNodeLifecycleFixture): number {
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    return new MemoryRepository(database, {
      clock: () => new Date("2099-07-16T12:01:00.000Z"),
      createId: (prefix) => `${prefix}_brain_node_external_${fixture.namespace}`,
    }).correctNode(fixture.nodeId, {
      pinned: true,
      authorType: "operator",
      authorId: "e2e-local-operator",
      changeReason: "Concurrent canonical mutation used to prove optimistic reconciliation",
    }).version;
  } finally {
    database.close();
  }
}

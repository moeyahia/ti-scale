import { createHash } from "node:crypto";
import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { MemoryRepository } from "../../../server/memory/MemoryRepository";
import type {
  MemoryCandidate,
  MemoryLifecycle,
  MemoryNodeType,
  MemoryScope,
  MemorySensitivity,
} from "../../../server/memory/types";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_TIME = "2099-07-16T18:00:00.000Z";

interface CandidateState {
  readonly id: string;
  readonly status: MemoryCandidate["status"];
  readonly title: string;
  readonly summary: string;
  readonly body: string;
  readonly proposedNodeId: string | null;
  readonly reviewedBy: string | null;
}

export interface BrainHomeInboxFixture {
  readonly namespace: string;
  readonly searchToken: string;
  readonly paginationToken: string;
  readonly missionId: string;
  readonly runId: string;
  readonly emptyMissionId: string;
  readonly emptyRunId: string;
  readonly engagementId: string;
  readonly nodeIds: readonly string[];
  readonly primaryNodeId: string;
  readonly primaryNodeTitle: string;
  readonly directCandidateId: string;
  readonly directCandidateTitle: string;
  readonly editedCandidateId: string;
  readonly editedCandidateTitle: string;
  readonly plainRejectCandidateId: string;
  readonly plainRejectCandidateTitle: string;
  readonly suppressCandidateId: string;
  readonly suppressCandidateTitle: string;
}

export interface BrainHomeInboxSnapshot {
  readonly candidates: readonly CandidateState[];
  readonly suppressionCount: number;
  readonly audits: readonly {
    readonly action: string;
    readonly resourceId: string;
    readonly reason: string | null;
    readonly details: Record<string, unknown>;
    readonly recordHash: string;
  }[];
  readonly confirmedNodes: readonly {
    readonly candidateId: string;
    readonly nodeId: string | null;
    readonly title: string | null;
    readonly sensitivity: string | null;
    readonly scope: string | null;
    readonly engagementId: string | null;
    readonly missionId: string | null;
    readonly versionCount: number;
    readonly sourceCount: number;
  }[];
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Second Brain home/inbox E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function scopeFor(
  kind: "global" | "engagement" | "mission",
  engagementId: string,
  missionId: string,
): MemoryScope {
  if (kind === "global") return { kind };
  if (kind === "engagement") return { kind, engagementId };
  return { kind, engagementId, missionId };
}

export function createBrainHomeInboxFixture(instanceId: string): BrainHomeInboxFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const searchToken = `brainfixture${digest(namespace).slice(0, 12)}`;
  const paginationToken = `brainpage${digest(`page:${namespace}`).slice(0, 12)}`;
  const missionId = `mission-brain-${namespace}`;
  const runId = `run-brain-${namespace}`;
  const emptyMissionId = `mission-brain-empty-${namespace}`;
  const emptyRunId = `run-brain-empty-${namespace}`;
  const engagementId = `engagement-brain-${namespace}`;
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  let sequence = 0;
  const repository = new MemoryRepository(database, {
    clock: () => new Date(FIXTURE_TIME),
    createId: (prefix) => `${prefix}_brain_e2e_${namespace}_${++sequence}`,
  });
  const provenance = (sourceId: string) => ({
    method: "operator_statement" as const,
    explanation: "A deterministic isolated browser fixture supplied this reviewable memory record.",
    sources: [{
      sourceType: sourceId.startsWith("candidate-") ? "run" : "source",
      sourceId: sourceId.startsWith("candidate-") ? runId : sourceId,
      sourceHash: digest(`${namespace}:${sourceId}`),
      excerptRedacted: "Sanitized canonical Second Brain browser fixture source.",
      acquiredAt: FIXTURE_TIME,
    }],
  });

  try {
    inImmediateTransaction(database, () => {
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status, engagement_id,
          scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
          created_by, version, created_at, updated_at
        ) VALUES (?, ?, ?, 'guided', 'active', 'verified', ?, ?, '[]', '{}', '{}',
          'e2e-local-operator', 1, ?, ?)
      `).run(
        missionId,
        `Second Brain browser fixture ${searchToken}`,
        "Review canonical memory without crossing the isolated fixture scope.",
        engagementId,
        JSON.stringify({ allowedTargets: [`${searchToken}.example.test`] }),
        FIXTURE_TIME,
        FIXTURE_TIME,
      );
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, status_reason,
          next_action_summary, created_at, updated_at, version
        ) VALUES (?, ?, 'guided', 'waiting_guided_decision', 0.5,
          'Memory candidates await deliberate operator review.',
          'Review one represented memory candidate', ?, ?, 1)
      `).run(runId, missionId, FIXTURE_TIME, FIXTURE_TIME);
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status, engagement_id,
          scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
          created_by, version, created_at, updated_at
        ) VALUES (?, ?, ?, 'guided', 'active', 'verified', ?, ?, '[]', '{}', '{}',
          'e2e-local-operator', 1, ?, ?)
      `).run(
        emptyMissionId,
        `Empty Second Brain review fixture ${searchToken}`,
        "Verify the canonical empty Memory Inbox state without changing populated pagination records.",
        engagementId,
        JSON.stringify({ allowedTargets: [`empty-${searchToken}.example.test`] }),
        FIXTURE_TIME,
        FIXTURE_TIME,
      );
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, status_reason,
          next_action_summary, created_at, updated_at, version
        ) VALUES (?, ?, 'guided', 'waiting_guided_decision', 0,
          'No memory candidates exist for this isolated empty-state run.',
          'Create a reviewable candidate when new attributable knowledge exists', ?, ?, 1)
      `).run(emptyRunId, emptyMissionId, FIXTURE_TIME, FIXTURE_TIME);
    });

    const nodeDefinitions: readonly {
      suffix: string;
      nodeType: MemoryNodeType;
      lifecycleStatus: Exclude<MemoryLifecycle, "forgotten">;
      confirmationState: "pending" | "confirmed" | "not_required";
      sensitivity: MemorySensitivity;
      scope: MemoryScope;
    }[] = [
      { suffix: "confirmed", nodeType: "preference", lifecycleStatus: "confirmed", confirmationState: "confirmed", sensitivity: "private", scope: { kind: "global" } },
      { suffix: "verified", nodeType: "technique", lifecycleStatus: "verified", confirmationState: "not_required", sensitivity: "internal", scope: { kind: "engagement", engagementId } },
      { suffix: "disputed", nodeType: "failure", lifecycleStatus: "disputed", confirmationState: "not_required", sensitivity: "restricted", scope: { kind: "mission", engagementId, missionId } },
      { suffix: "stale", nodeType: "lesson", lifecycleStatus: "stale", confirmationState: "not_required", sensitivity: "public", scope: { kind: "global" } },
      { suffix: "candidate", nodeType: "source", lifecycleStatus: "candidate", confirmationState: "pending", sensitivity: "internal", scope: { kind: "engagement", engagementId } },
      { suffix: "superseded", nodeType: "report", lifecycleStatus: "superseded", confirmationState: "not_required", sensitivity: "private", scope: { kind: "mission", engagementId, missionId } },
    ];
    const nodeIds = nodeDefinitions.map((definition, index) => {
      const id = `mem-brain-${definition.suffix}-${namespace}`;
      repository.createNode({
        id,
        nodeType: definition.nodeType,
        title: `${searchToken} ${definition.suffix} memory`,
        summary: `Canonical ${definition.lifecycleStatus} memory for the isolated Second Brain browser fixture.`,
        body: `Inspectable ${definition.nodeType} note body ${index + 1}.`,
        scope: definition.scope,
        sensitivity: definition.sensitivity,
        confidence: 0.95 - index * 0.05,
        lifecycleStatus: definition.lifecycleStatus,
        confirmationState: definition.confirmationState,
        provenance: provenance(`node-${definition.suffix}-${namespace}`),
        authorType: definition.nodeType === "preference" ? "operator" : "system",
        authorId: `e2e-brain-${namespace}`,
      });
      return id;
    });
    repository.createEdge({
      id: `edge-brain-${namespace}`,
      sourceNodeId: nodeIds[1]!,
      targetNodeId: nodeIds[2]!,
      edgeType: "failed_in",
      title: "Technique failed in the represented fixture",
      summary: "The typed relationship is backed by deterministic fixture provenance.",
      scope: { kind: "engagement", engagementId },
      sensitivity: "internal",
      confidence: 0.9,
      lifecycleStatus: "verified",
      provenance: provenance(`edge-${namespace}`),
      explanation: "The fixture links an attributable technique to its represented failure.",
      authorType: "system",
      authorId: `e2e-brain-${namespace}`,
    });

    // Keep the first page anchored by the named records above, then add enough
    // same-query nodes to prove opaque cursor traversal without synthetic API
    // responses. IDs sort after the named fixture records deterministically.
    for (let index = 0; index < 55; index += 1) {
      const suffix = String(index + 1).padStart(2, "0");
      repository.createNode({
        id: `aa-mem-brain-page-${suffix}-${namespace}`,
        nodeType: "source",
        title: `${paginationToken} paginated memory ${suffix}`,
        summary: "Canonical paginated memory retained in the exact fixture mission.",
        body: `Inspectable pagination note ${suffix}.`,
        scope: { kind: "mission", engagementId, missionId },
        sensitivity: "internal",
        confidence: 0.8,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: provenance(`node-page-${suffix}-${namespace}`),
        authorType: "system",
        authorId: `e2e-brain-${namespace}`,
      });
    }

    const candidates = [
      { key: "direct", title: `${searchToken} confirm unchanged`, scope: scopeFor("global", engagementId, missionId), sensitivity: "private" as const },
      { key: "edited", title: `${searchToken} edit before confirm`, scope: scopeFor("global", engagementId, missionId), sensitivity: "internal" as const },
      { key: "reject", title: `${searchToken} reject without suppression`, scope: scopeFor("engagement", engagementId, missionId), sensitivity: "private" as const },
      { key: "suppress", title: `${searchToken} reject and suppress`, scope: scopeFor("mission", engagementId, missionId), sensitivity: "restricted" as const },
    ] as const;
    for (const candidate of candidates) {
      repository.createCandidate({
        id: `candidate-brain-${candidate.key}-${namespace}`,
        nodeType: candidate.key === "direct" || candidate.key === "edited" ? "preference" : "procedure",
        title: candidate.title,
        summary: `Reviewable ${candidate.key} memory candidate with exact-run provenance.`,
        body: `Candidate ${candidate.key} body retained only according to the selected review action.`,
        scope: candidate.scope,
        sensitivity: candidate.sensitivity,
        confidence: 0.82,
        provenance: provenance(`candidate-${candidate.key}-${namespace}`),
        proposedBy: `agent-brain-${namespace}`,
      });
    }
    for (let index = 0; index < 55; index += 1) {
      const suffix = String(index + 1).padStart(2, "0");
      repository.createCandidate({
        id: `aa-candidate-brain-page-${suffix}-${namespace}`,
        nodeType: "procedure",
        title: `${paginationToken} paginated candidate ${suffix}`,
        summary: "Reviewable paginated candidate with exact-run provenance.",
        body: `Candidate pagination body ${suffix}.`,
        scope: { kind: "mission", engagementId, missionId },
        sensitivity: "internal",
        confidence: 0.75,
        provenance: provenance(`candidate-page-${suffix}-${namespace}`),
        proposedBy: `agent-brain-${namespace}`,
      });
    }

    return {
      namespace,
      searchToken,
      paginationToken,
      missionId,
      runId,
      emptyMissionId,
      emptyRunId,
      engagementId,
      nodeIds,
      primaryNodeId: nodeIds[0]!,
      primaryNodeTitle: `${searchToken} confirmed memory`,
      directCandidateId: `candidate-brain-direct-${namespace}`,
      directCandidateTitle: `${searchToken} confirm unchanged`,
      editedCandidateId: `candidate-brain-edited-${namespace}`,
      editedCandidateTitle: `${searchToken} edit before confirm`,
      plainRejectCandidateId: `candidate-brain-reject-${namespace}`,
      plainRejectCandidateTitle: `${searchToken} reject without suppression`,
      suppressCandidateId: `candidate-brain-suppress-${namespace}`,
      suppressCandidateTitle: `${searchToken} reject and suppress`,
    };
  } finally {
    database.close();
  }
}

export function readBrainHomeInboxSnapshot(fixture: BrainHomeInboxFixture): BrainHomeInboxSnapshot {
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const candidateIds = [
      fixture.directCandidateId,
      fixture.editedCandidateId,
      fixture.plainRejectCandidateId,
      fixture.suppressCandidateId,
    ];
    const candidates = database.prepare(`
      SELECT id, status, title, summary, body, proposed_node_id, reviewed_by
      FROM memory_candidates
      WHERE id IN (${candidateIds.map(() => "?").join(",")})
      ORDER BY id
    `).all(...candidateIds) as Array<{
      id: string;
      status: MemoryCandidate["status"];
      title: string;
      summary: string;
      body: string;
      proposed_node_id: string | null;
      reviewed_by: string | null;
    }>;
    const confirmedNodes = candidates.map((candidate) => {
      const node = candidate.proposed_node_id
        ? database.prepare(`
            SELECT id, title, sensitivity, scope, engagement_id, mission_id
            FROM memory_nodes WHERE id = ?
          `).get(candidate.proposed_node_id) as {
            id: string;
            title: string;
            sensitivity: string;
            scope: string;
            engagement_id: string | null;
            mission_id: string | null;
          } | undefined
        : undefined;
      const versionCount = candidate.proposed_node_id
        ? (database.prepare("SELECT COUNT(*) AS count FROM memory_versions WHERE node_id = ?")
            .get(candidate.proposed_node_id) as { count: number }).count
        : 0;
      const sourceCount = candidate.proposed_node_id
        ? (database.prepare("SELECT COUNT(*) AS count FROM memory_sources WHERE node_id = ?")
            .get(candidate.proposed_node_id) as { count: number }).count
        : 0;
      return {
        candidateId: candidate.id,
        nodeId: node?.id ?? null,
        title: node?.title ?? null,
        sensitivity: node?.sensitivity ?? null,
        scope: node?.scope ?? null,
        engagementId: node?.engagement_id ?? null,
        missionId: node?.mission_id ?? null,
        versionCount,
        sourceCount,
      };
    });
    const suppressionCount = (database.prepare(`
      SELECT COUNT(*) AS count
      FROM memory_suppressions
      WHERE engagement_id = ?
        AND category = 'procedure'
        AND created_by = 'e2e-local-operator'
    `).get(fixture.engagementId) as { count: number }).count;
    const audits = database.prepare(`
      SELECT action, resource_id, reason, details_json, record_hash
      FROM audit_records
      WHERE resource_type = 'memory_candidate'
        AND resource_id IN (${candidateIds.map(() => "?").join(",")})
      ORDER BY occurred_at, id
    `).all(...candidateIds) as Array<{
      action: string;
      resource_id: string;
      reason: string | null;
      details_json: string;
      record_hash: string;
    }>;
    return {
      candidates: candidates.map((candidate) => ({
        id: candidate.id,
        status: candidate.status,
        title: candidate.title,
        summary: candidate.summary,
        body: candidate.body,
        proposedNodeId: candidate.proposed_node_id,
        reviewedBy: candidate.reviewed_by,
      })),
      suppressionCount,
      audits: audits.map((audit) => ({
        action: audit.action,
        resourceId: audit.resource_id,
        reason: audit.reason,
        details: JSON.parse(audit.details_json) as Record<string, unknown>,
        recordHash: audit.record_hash,
      })),
      confirmedNodes,
    };
  } finally {
    database.close();
  }
}

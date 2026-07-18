import { createHash } from "node:crypto";
import { acquireTestRunMutationAuthority } from "../../../server/control-plane/TestRunMutationAuthority";
import { createDatabaseConnection, inImmediateTransaction, type SqliteDatabase } from "../../../server/db";
import { MemoryRepository } from "../../../server/memory";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";
import {
  createRunInterventionRecoveryFixture,
  type RunInterventionRecoveryFixture,
} from "./runInterventionRecoveryFixture";

export interface CommandPaletteFixture {
  readonly namespace: string;
  readonly search: RunInterventionRecoveryFixture;
  readonly pauseResume: RunInterventionRecoveryFixture;
  readonly cancel: RunInterventionRecoveryFixture;
  readonly memoryCandidate: RunInterventionRecoveryFixture;
  readonly missionLabel: string;
  readonly missionToken: string;
  readonly decisionLabel: string;
  readonly decisionToken: string;
  readonly agentLabel: string;
  readonly agentToken: string;
  readonly memoryNodeId: string;
  readonly memoryLabel: string;
  readonly memoryToken: string;
  readonly candidateTitle: string;
  readonly conversationId: string;
  readonly sourceMessageId: string;
  readonly expectedFingerprint: string;
}

export interface CommandPaletteCandidateSnapshot {
  readonly candidates: readonly {
    readonly id: string;
    readonly type: string;
    readonly title: string;
    readonly summary: string;
    readonly scope: string;
    readonly sensitivity: string;
    readonly status: string;
    readonly proposedBy: string;
    readonly missionId: string | null;
    readonly source: Readonly<Record<string, unknown>>;
  }[];
  readonly confirmedNodeCount: number;
  readonly audits: readonly {
    readonly action: string;
    readonly missionId: string;
    readonly runId: string;
    readonly resourceId: string;
  }[];
  readonly events: readonly {
    readonly eventType: string;
    readonly missionId: string;
    readonly runId: string;
    readonly candidateId: string;
  }[];
}

function database(): SqliteDatabase {
  if (!E2E_DATABASE_PATH) throw new Error("The isolated Playwright database path was not configured");
  return createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
}

function token(namespace: string, purpose: string): string {
  return `palette${purpose}${createHash("sha256").update(`${namespace}:${purpose}`, "utf8").digest("hex").slice(0, 12)}`;
}

export function createCommandPaletteFixture(instanceId: string): CommandPaletteFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const search = createRunInterventionRecoveryFixture("pause_resume", `${namespace}-search`);
  const pauseResume = createRunInterventionRecoveryFixture("pause_resume", `${namespace}-pause-resume`);
  const cancel = createRunInterventionRecoveryFixture("cancel", `${namespace}-cancel`);
  const memoryCandidate = createRunInterventionRecoveryFixture("pause_resume", `${namespace}-memory-candidate`);
  const missionToken = token(namespace, "mission");
  const decisionToken = token(namespace, "decision");
  const agentToken = token(namespace, "agent");
  const memoryToken = token(namespace, "memory");
  const missionLabel = `Palette mission beacon ${missionToken}`;
  const decisionLabel = `Review palette decision beacon ${decisionToken}`;
  const agentLabel = `Palette agent beacon ${agentToken}`;
  const memoryLabel = `Palette memory beacon ${memoryToken}`;
  const candidateTitle = `Palette candidate ${token(namespace, "candidate")}`;
  const memoryNodeId = `memory-palette-search-${namespace}`;
  const conversationId = `conversation-palette-${namespace}`;
  const sourceMessageId = `message-palette-assistant-${namespace}`;
  const now = new Date().toISOString();
  const connection = database();
  let expectedFingerprint = "";

  try {
    inImmediateTransaction(connection, () => {
      connection.prepare(`
        UPDATE missions SET name = ?, objective = ?, updated_at = ? WHERE id = ?
      `).run(
        missionLabel,
        `Exercise bounded command-palette discovery for ${missionToken} without changing authorization.`,
        now,
        search.missionId,
      );
      connection.prepare(`
        UPDATE guided_decisions SET rationale = ? WHERE id = ?
      `).run(decisionLabel, search.decisionId!);
      connection.prepare(`
        UPDATE agents SET display_name = ?, updated_at = ? WHERE id = ?
      `).run(agentLabel, now, search.agentId);

      const decision = connection.prepare(`
        SELECT requested_action_fingerprint AS fingerprint
        FROM guided_decisions WHERE id = ?
      `).get(memoryCandidate.decisionId!) as { fingerprint: string } | undefined;
      if (!decision) throw new Error("The Guided palette memory fixture has no represented decision");
      expectedFingerprint = decision.fingerprint;
      connection.prepare(`
        INSERT INTO conversations (
          id, mission_id, run_id, step_id, conversation_type, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'guided', ?, ?)
      `).run(
        conversationId,
        memoryCandidate.missionId,
        memoryCandidate.runId,
        memoryCandidate.stepId,
        now,
        now,
      );
      connection.prepare(`
        INSERT INTO messages (
          id, conversation_id, role, body, structured_content_json, created_at
        ) VALUES (?, ?, 'assistant', ?, ?, ?)
      `).run(
        sourceMessageId,
        conversationId,
        "Prefer a concise evidence-led explanation before the next represented Guided action.",
        JSON.stringify({
          kind: "guided_step",
          stepId: memoryCandidate.stepId,
          actionFingerprint: decision.fingerprint,
        }),
        now,
      );
    });

    new MemoryRepository(connection).createNode({
      id: memoryNodeId,
      nodeType: "preference",
      title: memoryLabel,
      summary: `Confirmed searchable operator preference ${memoryToken}`,
      body: "Keep bounded operational explanations concise and evidence-led.",
      scope: { kind: "global" },
      sensitivity: "private",
      confidence: 1,
      lifecycleStatus: "confirmed",
      confirmationState: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "Deterministic non-sensitive command-palette fixture confirmed by the test operator",
        sources: [{
          sourceType: "operator_note",
          sourceId: `operator-note-palette-${namespace}`,
          acquiredAt: now,
        }],
      },
      authorType: "operator",
      authorId: "e2e-local-operator",
      retentionPolicy: { allowGuided: true, allowAutonomous: true },
    });
  } finally {
    connection.close();
  }
  if (!expectedFingerprint) throw new Error("The Guided palette memory fixture has no action fingerprint");

  return {
    namespace,
    search,
    pauseResume,
    cancel,
    memoryCandidate,
    missionLabel,
    missionToken,
    decisionLabel,
    decisionToken,
    agentLabel,
    agentToken,
    memoryNodeId,
    memoryLabel,
    memoryToken,
    candidateTitle,
    conversationId,
    sourceMessageId,
    expectedFingerprint,
  };
}

export function readCommandPaletteCandidateSnapshot(
  fixture: CommandPaletteFixture,
): CommandPaletteCandidateSnapshot {
  const connection = database();
  try {
    const candidates = connection.prepare(`
      SELECT candidate.id, candidate.candidate_type AS type, candidate.title,
        candidate.summary, candidate.proposed_scope AS scope, candidate.sensitivity,
        candidate.status, candidate.proposed_by AS proposedBy,
        candidate.mission_id AS missionId, candidate.source_json AS sourceJson
      FROM memory_candidates candidate
      WHERE candidate.title = ?
        AND candidate.proposed_by = 'e2e-local-operator'
        AND EXISTS (
          SELECT 1 FROM json_each(candidate.source_json, '$.sources') source
          WHERE json_extract(source.value, '$.sourceType') = 'message'
            AND json_extract(source.value, '$.sourceId') = ?
        )
      ORDER BY candidate.created_at, candidate.id
    `).all(
      fixture.candidateTitle,
      fixture.sourceMessageId,
    ) as Array<{
      id: string;
      type: string;
      title: string;
      summary: string;
      scope: string;
      sensitivity: string;
      status: string;
      proposedBy: string;
      missionId: string | null;
      sourceJson: string;
    }>;
    const nodeCount = connection.prepare(`
      SELECT COUNT(*) AS count FROM memory_nodes
      WHERE title = ? AND lifecycle_status IN ('confirmed', 'verified')
    `).get(fixture.candidateTitle) as { count: number };
    const audits = connection.prepare(`
      SELECT audit.action, audit.mission_id AS missionId, audit.run_id AS runId,
        audit.resource_id AS resourceId
      FROM audit_records audit
      JOIN memory_candidates candidate ON candidate.id = audit.resource_id
      WHERE audit.mission_id = ? AND audit.run_id = ?
        AND audit.action = 'memory.candidate_created'
        AND candidate.title = ?
        AND EXISTS (
          SELECT 1 FROM json_each(candidate.source_json, '$.sources') source
          WHERE json_extract(source.value, '$.sourceType') = 'message'
            AND json_extract(source.value, '$.sourceId') = ?
        )
      ORDER BY audit.occurred_at, audit.rowid
    `).all(
      fixture.memoryCandidate.missionId,
      fixture.memoryCandidate.runId,
      fixture.candidateTitle,
      fixture.sourceMessageId,
    ) as Array<{ action: string; missionId: string; runId: string; resourceId: string }>;
    const events = connection.prepare(`
      SELECT event.event_type AS eventType, event.mission_id AS missionId,
        event.run_id AS runId,
        json_extract(event.payload_json, '$.candidateId') AS candidateId
      FROM events event
      JOIN memory_candidates candidate
        ON candidate.id = json_extract(event.payload_json, '$.candidateId')
      WHERE event.mission_id = ? AND event.run_id = ?
        AND event.event_type = 'memory.candidate_created'
        AND candidate.title = ?
        AND EXISTS (
          SELECT 1 FROM json_each(candidate.source_json, '$.sources') source
          WHERE json_extract(source.value, '$.sourceType') = 'message'
            AND json_extract(source.value, '$.sourceId') = ?
        )
      ORDER BY event.sequence, event.id
    `).all(
      fixture.memoryCandidate.missionId,
      fixture.memoryCandidate.runId,
      fixture.candidateTitle,
      fixture.sourceMessageId,
    ) as Array<{ eventType: string; missionId: string; runId: string; candidateId: string }>;
    return {
      candidates: candidates.map((candidate) => ({
        id: candidate.id,
        type: candidate.type,
        title: candidate.title,
        summary: candidate.summary,
        scope: candidate.scope,
        sensitivity: candidate.sensitivity,
        status: candidate.status,
        proposedBy: candidate.proposedBy,
        missionId: candidate.missionId,
        source: JSON.parse(candidate.sourceJson) as Readonly<Record<string, unknown>>,
      })),
      confirmedNodeCount: Number(nodeCount.count),
      audits,
      events,
    };
  } finally {
    connection.close();
  }
}

/**
 * Refreshes the disposable runtime-owned lease immediately before the real
 * Guided memory mutation. The production boundary correctly fails closed
 * without this server-side authority; browser fixtures must not bypass it.
 */
export function refreshCommandPaletteMemoryCandidateAuthority(
  fixture: CommandPaletteFixture,
): void {
  const connection = database();
  try {
    acquireTestRunMutationAuthority(connection, fixture.memoryCandidate.runId);
  } finally {
    connection.close();
  }
}

import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import { inImmediateTransaction } from "../db";
import { missing, scopeConflict, stateConflict } from "./errors";
import type {
  EngagementLogRecord,
  EvidenceCustodyEvent,
  EvidenceCandidate,
  EvidenceCandidateState,
  FindingVerificationReadiness,
  JsonValue,
  Observation,
  ObservationSource,
  OperationalActor,
  OperationalTruthPage,
  OperationalTruthPageCursor,
  VerifiedEvidence,
} from "./types";
import { canonicalJson, parseJson, sha256 } from "./validation";
import { AuditTrailWriter } from "./AuditTrailWriter";

interface LogRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly plan_id: string | null;
  readonly step_id: string | null;
  readonly action_id: string | null;
  readonly attack_attempt_id: string | null;
  readonly asset_id: string | null;
  readonly agent_id: string | null;
  readonly provider_turn_id: string | null;
  readonly tool_call_id: string | null;
  readonly severity: EngagementLogRecord["severity"];
  readonly domain: string;
  readonly record_type: string;
  readonly human_summary: string;
  readonly technical_payload_json: string;
  readonly content_hash: string;
  readonly sensitivity: EngagementLogRecord["sensitivity"];
  readonly trace_id: string | null;
  readonly span_id: string | null;
  readonly occurred_at: string;
  readonly created_at: string;
}

interface ObservationRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly asset_id: string | null;
  readonly observation_type: string;
  readonly statement: string;
  readonly normalized_value_json: string;
  readonly confidence: number;
  readonly verification_state: Observation["verificationState"];
  readonly source_agent_id: string | null;
  readonly source_tool: string | null;
  readonly first_seen_at: string;
  readonly last_seen_at: string;
  readonly sensitivity: Observation["sensitivity"];
  readonly created_at: string;
}

interface ObservationSourceRow {
  readonly log_record_id: string;
  readonly parser_id: string;
  readonly parser_version: string;
}

interface CandidateRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly observation_id: string | null;
  readonly artifact_id: string | null;
  readonly evidence_type: string;
  readonly label: string;
  readonly meaning: string;
  readonly promotion_reason: string;
  readonly validation_requirements_json: string;
  readonly state: EvidenceCandidateState;
  readonly sensitivity: EvidenceCandidate["sensitivity"];
  readonly proposed_by: string;
  readonly reviewed_by: string | null;
  readonly review_reason: string | null;
  readonly promoted_evidence_id: string | null;
  readonly created_at: string;
  readonly reviewed_at: string | null;
}

interface EvidenceRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly source: string;
  readonly acquired_at: string;
  readonly target: string | null;
  readonly evidence_type: string;
  readonly content_hash: string;
  readonly provenance_json: string;
  readonly confidence: number;
  readonly sensitivity: VerifiedEvidence["sensitivity"];
  readonly verification_state: string;
  readonly summary: string;
  readonly artifact_id: string | null;
  readonly created_by: string;
  readonly created_at: string;
}

interface ScopeRow {
  readonly mission_id?: string;
  readonly run_id?: string;
  readonly plan_id?: string;
  readonly step_id?: string;
  readonly action_id?: string;
  readonly status?: string;
  readonly journey?: string;
  readonly content_hash?: string;
  readonly artifact_id?: string | null;
  readonly observation_id?: string | null;
}

interface FindingRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly review_status: string;
  readonly version: number;
}

interface FindingEvidenceRow extends EvidenceRow {
  readonly relationship: "supports" | "contradicts" | "context";
  readonly candidate_state: EvidenceCandidateState | null;
  readonly acquired_count: number;
  readonly verified_count: number;
}

function mapLog(row: LogRow): EngagementLogRecord {
  return {
    id: row.id,
    missionId: row.mission_id,
    ...(row.run_id ? { runId: row.run_id } : {}),
    ...(row.plan_id ? { planId: row.plan_id } : {}),
    ...(row.step_id ? { stepId: row.step_id } : {}),
    ...(row.action_id ? { actionId: row.action_id } : {}),
    ...(row.attack_attempt_id ? { attackAttemptId: row.attack_attempt_id } : {}),
    ...(row.asset_id ? { assetId: row.asset_id } : {}),
    ...(row.agent_id ? { agentId: row.agent_id } : {}),
    ...(row.provider_turn_id ? { providerTurnId: row.provider_turn_id } : {}),
    ...(row.tool_call_id ? { toolCallId: row.tool_call_id } : {}),
    severity: row.severity,
    domain: row.domain,
    recordType: row.record_type,
    humanSummary: row.human_summary,
    technicalPayload: parseJson(row.technical_payload_json),
    contentHash: row.content_hash,
    sensitivity: row.sensitivity,
    ...(row.trace_id ? { traceId: row.trace_id } : {}),
    ...(row.span_id ? { spanId: row.span_id } : {}),
    occurredAt: row.occurred_at,
    createdAt: row.created_at,
  };
}

function mapCandidate(row: CandidateRow): EvidenceCandidate {
  return {
    id: row.id,
    missionId: row.mission_id,
    ...(row.run_id ? { runId: row.run_id } : {}),
    ...(row.step_id ? { stepId: row.step_id } : {}),
    ...(row.observation_id ? { observationId: row.observation_id } : {}),
    ...(row.artifact_id ? { artifactId: row.artifact_id } : {}),
    evidenceType: row.evidence_type,
    label: row.label,
    meaning: row.meaning,
    promotionReason: row.promotion_reason,
    validationRequirements: parseJson(row.validation_requirements_json) as readonly string[],
    state: row.state,
    sensitivity: row.sensitivity,
    proposedBy: row.proposed_by,
    ...(row.reviewed_by ? { reviewedBy: row.reviewed_by } : {}),
    ...(row.review_reason ? { reviewReason: row.review_reason } : {}),
    ...(row.promoted_evidence_id ? { promotedEvidenceId: row.promoted_evidence_id } : {}),
    createdAt: row.created_at,
    ...(row.reviewed_at ? { reviewedAt: row.reviewed_at } : {}),
  };
}

function mapEvidence(row: EvidenceRow): VerifiedEvidence {
  if (row.verification_state !== "verified" || !row.target) {
    throw stateConflict("Evidence is not a verified operational-truth record");
  }
  return {
    id: row.id,
    missionId: row.mission_id,
    ...(row.run_id ? { runId: row.run_id } : {}),
    ...(row.step_id ? { stepId: row.step_id } : {}),
    source: row.source,
    acquiredAt: row.acquired_at,
    target: row.target,
    evidenceType: row.evidence_type,
    contentHash: row.content_hash,
    provenance: parseJson(row.provenance_json),
    confidence: row.confidence,
    sensitivity: row.sensitivity,
    verificationState: "verified",
    summary: row.summary,
    ...(row.artifact_id ? { artifactId: row.artifact_id } : {}),
    createdBy: row.created_by,
    createdAt: row.created_at,
  };
}

function page<T extends { readonly id: string; readonly createdAt: string }>(
  items: readonly T[],
  limit: number,
): OperationalTruthPage<T> {
  const visible = items.slice(0, limit);
  const last = visible.at(-1);
  return {
    items: visible,
    ...(items.length > limit && last
      ? { nextCursor: { createdAt: last.createdAt, id: last.id } }
      : {}),
  };
}

export interface RepositoryOptions {
  readonly clock?: () => Date;
  readonly idFactory?: (prefix: string) => string;
}

/** SQL boundary for the V2.4 operational-truth state machine. */
export class OperationalTruthRepository {
  readonly clock: () => Date;
  readonly idFactory: (prefix: string) => string;
  readonly audit: AuditTrailWriter;

  constructor(readonly database: SqliteDatabase, options: RepositoryOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.idFactory = options.idFactory ?? ((prefix) => `${prefix}_${randomUUID()}`);
    this.audit = new AuditTrailWriter(database, this.idFactory);
  }

  transaction<T>(operation: () => T): T {
    return inImmediateTransaction(this.database, operation);
  }

  nextId(prefix: string): string {
    return this.idFactory(prefix);
  }

  now(): string {
    return this.clock().toISOString();
  }

  assertCanonicalScope(input: {
    missionId: string;
    runId?: string;
    planId?: string;
    stepId?: string;
    actionId?: string;
    attackAttemptId?: string;
    agentId?: string;
    providerTurnId?: string;
    toolCallId?: string;
  }): void {
    const mission = this.database.prepare("SELECT journey FROM missions WHERE id = ?")
      .get(input.missionId) as ScopeRow | undefined;
    if (!mission) throw missing("mission");
    if (input.runId) {
      const run = this.database.prepare("SELECT mission_id, journey FROM runs WHERE id = ?")
        .get(input.runId) as ScopeRow | undefined;
      if (!run || run.mission_id !== input.missionId || run.journey !== mission.journey) {
        throw scopeConflict("Run does not belong to the mission and journey");
      }
    }
    if (input.planId) {
      const plan = this.database.prepare(`
        SELECT r.mission_id, p.run_id FROM plans p JOIN runs r ON r.id = p.run_id WHERE p.id = ?
      `).get(input.planId) as ScopeRow | undefined;
      if (!plan || plan.mission_id !== input.missionId || (input.runId && plan.run_id !== input.runId)) {
        throw scopeConflict("Plan does not belong to the mission and run");
      }
    }
    if (input.stepId) {
      const step = this.database.prepare(`
        SELECT r.mission_id, ps.run_id, ps.plan_id FROM plan_steps ps
        JOIN runs r ON r.id = ps.run_id WHERE ps.id = ?
      `).get(input.stepId) as ScopeRow | undefined;
      if (
        !step || step.mission_id !== input.missionId ||
        (input.runId && step.run_id !== input.runId) ||
        (input.planId && step.plan_id !== input.planId)
      ) throw scopeConflict("Step does not belong to the mission, run, and plan");
    }
    if (input.actionId) {
      const action = this.database.prepare("SELECT mission_id, run_id, step_id FROM actions WHERE id = ?")
        .get(input.actionId) as ScopeRow | undefined;
      if (
        !action || action.mission_id !== input.missionId ||
        (input.runId && action.run_id !== input.runId) ||
        (input.stepId && action.step_id !== input.stepId)
      ) throw scopeConflict("Action does not belong to the mission, run, and step");
    }
    if (input.attackAttemptId) {
      const attempt = this.database.prepare("SELECT mission_id, run_id, step_id FROM attack_attempts WHERE id = ?")
        .get(input.attackAttemptId) as ScopeRow | undefined;
      if (
        !attempt || attempt.mission_id !== input.missionId ||
        (input.runId && attempt.run_id !== input.runId) ||
        (input.stepId && attempt.step_id !== input.stepId)
      ) throw scopeConflict("Attack attempt does not belong to the mission, run, and step");
    }
    if (input.agentId && !this.database.prepare("SELECT 1 FROM agents WHERE id = ?").get(input.agentId)) {
      throw missing("agent");
    }
    if (input.providerTurnId) {
      const turn = this.database.prepare("SELECT run_id FROM provider_turns WHERE id = ?")
        .get(input.providerTurnId) as ScopeRow | undefined;
      if (!turn || (input.runId && turn.run_id !== input.runId)) throw scopeConflict("Provider turn does not belong to the run");
    }
    if (input.toolCallId) {
      const call = this.database.prepare(`
        SELECT a.mission_id, a.run_id, a.step_id FROM tool_calls tc
        JOIN actions a ON a.id = tc.action_id WHERE tc.id = ?
      `).get(input.toolCallId) as ScopeRow | undefined;
      if (
        !call || call.mission_id !== input.missionId ||
        (input.runId && call.run_id !== input.runId) ||
        (input.stepId && call.step_id !== input.stepId)
      ) throw scopeConflict("Tool call does not belong to the mission, run, and step");
    }
  }

  insertLog(row: LogRow): EngagementLogRecord {
    this.database.prepare(`
      INSERT INTO engagement_log_records (
        id, mission_id, run_id, plan_id, step_id, action_id, attack_attempt_id,
        asset_id, agent_id, provider_turn_id, tool_call_id, severity, domain,
        record_type, human_summary, technical_payload_json, content_hash,
        sensitivity, trace_id, span_id, occurred_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      row.id, row.mission_id, row.run_id, row.plan_id, row.step_id, row.action_id,
      row.attack_attempt_id, row.asset_id, row.agent_id, row.provider_turn_id,
      row.tool_call_id, row.severity, row.domain, row.record_type, row.human_summary,
      row.technical_payload_json, row.content_hash, row.sensitivity, row.trace_id,
      row.span_id, row.occurred_at, row.created_at,
    );
    return mapLog(row);
  }

  getLog(id: string): EngagementLogRecord {
    const row = this.database.prepare("SELECT * FROM engagement_log_records WHERE id = ?")
      .get(id) as LogRow | undefined;
    if (!row) throw missing("engagement_log_record");
    return mapLog(row);
  }

  listLogs(input: {
    readonly missionId: string;
    readonly runId?: string;
    readonly stepId?: string;
    readonly limit: number;
    readonly cursor?: OperationalTruthPageCursor;
  }): OperationalTruthPage<EngagementLogRecord> {
    this.assertCanonicalScope({
      missionId: input.missionId,
      ...(input.runId ? { runId: input.runId } : {}),
      ...(input.stepId ? { stepId: input.stepId } : {}),
    });
    const rows = this.database.prepare(`
      SELECT * FROM engagement_log_records
      WHERE mission_id = ?
        AND (? IS NULL OR run_id = ?)
        AND (? IS NULL OR step_id = ?)
        AND (? IS NULL OR created_at < ? OR (created_at = ? AND id < ?))
      ORDER BY created_at DESC, id DESC LIMIT ?
    `).all(
      input.missionId,
      input.runId ?? null, input.runId ?? null,
      input.stepId ?? null, input.stepId ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.id ?? null,
      input.limit + 1,
    ) as LogRow[];
    return page(rows.map(mapLog), input.limit);
  }

  insertObservation(row: ObservationRow, sources: readonly ObservationSource[]): Observation {
    this.database.prepare(`
      INSERT INTO observations (
        id, mission_id, run_id, step_id, asset_id, observation_type, statement,
        normalized_value_json, confidence, verification_state, source_agent_id,
        source_tool, first_seen_at, last_seen_at, sensitivity, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      row.id, row.mission_id, row.run_id, row.step_id, row.asset_id,
      row.observation_type, row.statement, row.normalized_value_json, row.confidence,
      row.verification_state, row.source_agent_id, row.source_tool, row.first_seen_at,
      row.last_seen_at, row.sensitivity, row.created_at,
    );
    const insertSource = this.database.prepare(`
      INSERT INTO observation_log_sources (
        observation_id, log_record_id, parser_id, parser_version, created_at
      ) VALUES (?, ?, ?, ?, ?)
    `);
    for (const source of sources) {
      insertSource.run(row.id, source.logRecordId, source.parserId, source.parserVersion, row.created_at);
    }
    return {
      id: row.id,
      missionId: row.mission_id,
      ...(row.run_id ? { runId: row.run_id } : {}),
      ...(row.step_id ? { stepId: row.step_id } : {}),
      ...(row.asset_id ? { assetId: row.asset_id } : {}),
      observationType: row.observation_type,
      statement: row.statement,
      normalizedValue: parseJson(row.normalized_value_json),
      confidence: row.confidence,
      verificationState: row.verification_state,
      ...(row.source_agent_id ? { sourceAgentId: row.source_agent_id } : {}),
      ...(row.source_tool ? { sourceTool: row.source_tool } : {}),
      firstSeenAt: row.first_seen_at,
      lastSeenAt: row.last_seen_at,
      sensitivity: row.sensitivity,
      sources,
      createdAt: row.created_at,
    };
  }

  getObservation(id: string): Observation {
    const row = this.database.prepare("SELECT * FROM observations WHERE id = ?")
      .get(id) as ObservationRow | undefined;
    if (!row) throw missing("observation");
    const sources = this.database.prepare(`
      SELECT log_record_id, parser_id, parser_version FROM observation_log_sources
      WHERE observation_id = ? ORDER BY log_record_id
    `).all(id) as ObservationSourceRow[];
    return {
      id: row.id,
      missionId: row.mission_id,
      ...(row.run_id ? { runId: row.run_id } : {}),
      ...(row.step_id ? { stepId: row.step_id } : {}),
      ...(row.asset_id ? { assetId: row.asset_id } : {}),
      observationType: row.observation_type,
      statement: row.statement,
      normalizedValue: parseJson(row.normalized_value_json),
      confidence: row.confidence,
      verificationState: row.verification_state,
      ...(row.source_agent_id ? { sourceAgentId: row.source_agent_id } : {}),
      ...(row.source_tool ? { sourceTool: row.source_tool } : {}),
      firstSeenAt: row.first_seen_at,
      lastSeenAt: row.last_seen_at,
      sensitivity: row.sensitivity,
      sources: sources.map((source) => ({
        logRecordId: source.log_record_id,
        parserId: source.parser_id,
        parserVersion: source.parser_version,
      })),
      createdAt: row.created_at,
    };
  }

  listObservations(input: {
    readonly missionId: string;
    readonly runId?: string;
    readonly stepId?: string;
    readonly limit: number;
    readonly cursor?: OperationalTruthPageCursor;
  }): OperationalTruthPage<Observation> {
    this.assertCanonicalScope({
      missionId: input.missionId,
      ...(input.runId ? { runId: input.runId } : {}),
      ...(input.stepId ? { stepId: input.stepId } : {}),
    });
    const rows = this.database.prepare(`
      SELECT id, created_at FROM observations
      WHERE mission_id = ?
        AND (? IS NULL OR run_id = ?)
        AND (? IS NULL OR step_id = ?)
        AND (? IS NULL OR created_at < ? OR (created_at = ? AND id < ?))
      ORDER BY created_at DESC, id DESC LIMIT ?
    `).all(
      input.missionId,
      input.runId ?? null, input.runId ?? null,
      input.stepId ?? null, input.stepId ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.id ?? null,
      input.limit + 1,
    ) as Array<{ readonly id: string; readonly created_at: string }>;
    return page(rows.map((row) => this.getObservation(row.id)), input.limit);
  }

  insertCandidate(row: CandidateRow): EvidenceCandidate {
    this.database.prepare(`
      INSERT INTO evidence_candidates (
        id, mission_id, run_id, step_id, observation_id, artifact_id,
        evidence_type, label, meaning, promotion_reason,
        validation_requirements_json, state, sensitivity, proposed_by,
        reviewed_by, review_reason, promoted_evidence_id, created_at, reviewed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      row.id, row.mission_id, row.run_id, row.step_id, row.observation_id,
      row.artifact_id, row.evidence_type, row.label, row.meaning,
      row.promotion_reason, row.validation_requirements_json, row.state,
      row.sensitivity, row.proposed_by, row.reviewed_by, row.review_reason,
      row.promoted_evidence_id, row.created_at, row.reviewed_at,
    );
    return mapCandidate(row);
  }

  getCandidate(id: string): EvidenceCandidate {
    const row = this.candidateRow(id);
    return mapCandidate(row);
  }

  listCandidates(input: {
    readonly missionId: string;
    readonly runId?: string;
    readonly stepId?: string;
    readonly state?: EvidenceCandidateState;
    readonly limit: number;
    readonly cursor?: OperationalTruthPageCursor;
  }): OperationalTruthPage<EvidenceCandidate> {
    this.assertCanonicalScope({
      missionId: input.missionId,
      ...(input.runId ? { runId: input.runId } : {}),
      ...(input.stepId ? { stepId: input.stepId } : {}),
    });
    const rows = this.database.prepare(`
      SELECT * FROM evidence_candidates
      WHERE mission_id = ?
        AND (? IS NULL OR run_id = ?)
        AND (? IS NULL OR step_id = ?)
        AND (? IS NULL OR state = ?)
        AND (? IS NULL OR created_at < ? OR (created_at = ? AND id < ?))
      ORDER BY created_at DESC, id DESC LIMIT ?
    `).all(
      input.missionId,
      input.runId ?? null, input.runId ?? null,
      input.stepId ?? null, input.stepId ?? null,
      input.state ?? null, input.state ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.id ?? null,
      input.limit + 1,
    ) as CandidateRow[];
    return page(rows.map(mapCandidate), input.limit);
  }

  candidateRow(id: string): CandidateRow {
    const row = this.database.prepare("SELECT * FROM evidence_candidates WHERE id = ?")
      .get(id) as CandidateRow | undefined;
    if (!row) throw missing("evidence_candidate");
    return row;
  }

  transitionCandidate(
    id: string,
    fromStates: readonly EvidenceCandidateState[],
    toState: EvidenceCandidateState,
    actor: string,
    reason: string,
    reviewedAt: string,
    promotedEvidenceId?: string,
  ): EvidenceCandidate {
    const placeholders = fromStates.map(() => "?").join(", ");
    this.database.prepare(`
      UPDATE evidence_candidates SET state = ?, reviewed_by = ?, review_reason = ?,
        reviewed_at = ?, promoted_evidence_id = COALESCE(?, promoted_evidence_id)
      WHERE id = ? AND state IN (${placeholders})
    `).run(toState, actor, reason, reviewedAt, promotedEvidenceId ?? null, id, ...fromStates);
    // Bun's compatibility driver's RunResult.changes includes trigger work for
    // some FTS-backed transactions. SQLite changes() is the authoritative count
    // for the immediately preceding conditional update.
    const changed = this.database.prepare("SELECT changes() AS count").get() as { readonly count: number };
    if (Number(changed.count) !== 1) {
      const row = this.candidateRow(id);
      throw stateConflict(
        `Evidence candidate cannot transition from ${row.state} to ${toState}`,
        "Refresh the candidate and choose an action valid for its current state.",
      );
    }
    return this.getCandidate(id);
  }

  artifactScope(id: string): ScopeRow {
    const row = this.database.prepare(`
      SELECT mission_id, run_id, step_id, content_hash FROM artifacts WHERE id = ?
    `).get(id) as ScopeRow | undefined;
    if (!row) throw missing("artifact");
    return row;
  }

  observationManifest(id: string): { readonly hash: string; readonly sourceLogIds: readonly string[] } {
    const observation = this.getObservation(id);
    const logs = observation.sources.map((source) => this.getLog(source.logRecordId));
    return {
      hash: sha256(canonicalJson({
        observationId: observation.id,
        missionId: observation.missionId,
        runId: observation.runId ?? null,
        statement: observation.statement,
        normalizedValue: observation.normalizedValue,
        confidence: observation.confidence,
        sources: logs.map((log) => ({ id: log.id, contentHash: log.contentHash })),
      })),
      sourceLogIds: logs.map((log) => log.id),
    };
  }

  insertVerifiedEvidence(input: {
    row: EvidenceRow;
    custody: readonly { id: string; eventType: string; actor: string; details: JsonValue; occurredAt: string }[];
  }): VerifiedEvidence {
    const row = input.row;
    this.database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
        evidence_type, content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, extracted_text, artifact_id, created_by, created_at
      ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', ?, NULL, ?, ?, ?)
    `).run(
      row.id, row.mission_id, row.run_id, row.step_id, row.source,
      row.acquired_at, row.target, row.evidence_type, row.content_hash,
      row.provenance_json, row.confidence, row.sensitivity, row.summary,
      row.artifact_id, row.created_by, row.created_at,
    );
    const insert = this.database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);
    for (const event of input.custody) {
      insert.run(event.id, row.id, event.eventType, event.actor, canonicalJson(event.details), event.occurredAt);
    }
    return mapEvidence(row);
  }

  getVerifiedEvidence(id: string): VerifiedEvidence {
    const row = this.database.prepare("SELECT * FROM evidence WHERE id = ?")
      .get(id) as EvidenceRow | undefined;
    if (!row) throw missing("evidence");
    return mapEvidence(row);
  }

  listEvidenceCustody(evidenceId: string): readonly EvidenceCustodyEvent[] {
    this.getVerifiedEvidence(evidenceId);
    const rows = this.database.prepare(`
      SELECT id, evidence_id, event_type, actor, details_json, occurred_at
      FROM evidence_chain_events WHERE evidence_id = ?
      ORDER BY occurred_at, rowid
    `).all(evidenceId) as Array<{
      readonly id: string;
      readonly evidence_id: string;
      readonly event_type: string;
      readonly actor: string;
      readonly details_json: string;
      readonly occurred_at: string;
    }>;
    return rows.map((row) => ({
      id: row.id,
      evidenceId: row.evidence_id,
      eventType: row.event_type,
      actor: row.actor,
      details: parseJson(row.details_json),
      occurredAt: row.occurred_at,
    }));
  }

  listVerifiedEvidence(input: {
    readonly missionId: string;
    readonly runId?: string;
    readonly stepId?: string;
    readonly limit: number;
    readonly cursor?: OperationalTruthPageCursor;
  }): OperationalTruthPage<VerifiedEvidence> {
    this.assertCanonicalScope({
      missionId: input.missionId,
      ...(input.runId ? { runId: input.runId } : {}),
      ...(input.stepId ? { stepId: input.stepId } : {}),
    });
    const rows = this.database.prepare(`
      SELECT * FROM evidence
      WHERE mission_id = ? AND ${verifiedEvidenceSql("evidence")} AND target IS NOT NULL
        AND (? IS NULL OR run_id = ?)
        AND (? IS NULL OR step_id = ?)
        AND (? IS NULL OR created_at < ? OR (created_at = ? AND id < ?))
      ORDER BY created_at DESC, id DESC LIMIT ?
    `).all(
      input.missionId,
      input.runId ?? null, input.runId ?? null,
      input.stepId ?? null, input.stepId ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.createdAt ?? null,
      input.cursor?.id ?? null,
      input.limit + 1,
    ) as EvidenceRow[];
    return page(rows.map(mapEvidence), input.limit);
  }

  appendCustodyEvent(input: {
    id: string;
    evidenceId: string;
    eventType: string;
    actor: string;
    details: JsonValue;
    occurredAt: string;
  }): void {
    this.database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(input.id, input.evidenceId, input.eventType, input.actor, canonicalJson(input.details), input.occurredAt);
  }

  verifiedFindingDependents(evidenceId: string): number {
    const row = this.database.prepare(`
      SELECT COUNT(*) AS count FROM finding_evidence fe
      JOIN findings f ON f.id = fe.finding_id
      WHERE fe.evidence_id = ? AND fe.relationship = 'supports' AND f.review_status = 'verified'
    `).get(evidenceId) as { count: number };
    return Number(row.count);
  }

  linkFindingEvidence(input: {
    findingId: string;
    evidenceId: string;
    relationship: "supports" | "contradicts" | "context";
    addedAt: string;
  }): void {
    const finding = this.findingRow(input.findingId);
    const evidence = this.database.prepare("SELECT mission_id, run_id FROM evidence WHERE id = ?")
      .get(input.evidenceId) as ScopeRow | undefined;
    if (!evidence) throw missing("evidence");
    if (
      evidence.mission_id !== finding.mission_id ||
      (finding.run_id && evidence.run_id !== finding.run_id)
    ) throw scopeConflict("Evidence does not belong to the finding mission and run");
    this.database.prepare(`
      INSERT INTO finding_evidence (finding_id, evidence_id, relationship, added_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(finding_id, evidence_id, relationship) DO NOTHING
    `).run(input.findingId, input.evidenceId, input.relationship, input.addedAt);
  }

  findingRow(id: string): FindingRow {
    const row = this.database.prepare(`
      SELECT id, mission_id, run_id, review_status, version FROM findings WHERE id = ?
    `).get(id) as FindingRow | undefined;
    if (!row) throw missing("finding");
    return row;
  }

  assertFindingMission(id: string, missionId: string): void {
    if (this.findingRow(id).mission_id !== missionId) throw missing("finding");
  }

  findingReadiness(id: string): FindingVerificationReadiness {
    const finding = this.findingRow(id);
    const rows = this.database.prepare(`
      SELECT e.*, fe.relationship,
        (SELECT ec.state FROM evidence_candidates ec
          WHERE ec.promoted_evidence_id = e.id ORDER BY ec.reviewed_at DESC LIMIT 1) AS candidate_state,
        (SELECT COUNT(*) FROM evidence_chain_events ce
          WHERE ce.evidence_id = e.id AND ce.event_type = 'acquired') AS acquired_count,
        (SELECT COUNT(*) FROM evidence_chain_events ce
          WHERE ce.evidence_id = e.id AND ce.event_type = 'verified') AS verified_count
      FROM finding_evidence fe JOIN evidence e ON e.id = fe.evidence_id
      WHERE fe.finding_id = ? AND e.mission_id = ?
        AND (? IS NULL OR e.run_id = ?)
      ORDER BY e.created_at, e.id
    `).all(id, finding.mission_id, finding.run_id, finding.run_id) as FindingEvidenceRow[];
    const supporting: string[] = [];
    const rejected: string[] = [];
    const contradictory: string[] = [];
    for (const row of rows) {
      if (row.relationship === "contradicts" && row.verification_state === "verified") {
        contradictory.push(row.id);
        continue;
      }
      if (row.relationship !== "supports") continue;
      const provenance = parseJson(row.provenance_json);
      const valid = row.verification_state === "verified"
        && row.evidence_type.trim().toLowerCase() !== "command_output"
        && /^[a-f0-9]{64}$/u.test(row.content_hash)
        && Boolean(row.target?.trim())
        && Number.isFinite(Date.parse(row.acquired_at))
        && Boolean(provenance && typeof provenance === "object" && !Array.isArray(provenance))
        && row.acquired_count > 0
        && row.verified_count > 0
        && (row.candidate_state === null || row.candidate_state === "promoted");
      (valid ? supporting : rejected).push(row.id);
    }
    const reasons: string[] = [];
    if (supporting.length === 0) reasons.push("No linked supporting item satisfies the verified-evidence integrity gate.");
    if (contradictory.length > 0) reasons.push("Verified contradictory evidence must be resolved before finding verification.");
    return {
      findingId: id,
      sufficient: supporting.length > 0 && contradictory.length === 0,
      supportingEvidenceIds: supporting,
      rejectedEvidenceIds: rejected,
      contradictoryEvidenceIds: contradictory,
      reasons,
    };
  }

  markFindingVerified(id: string, expectedVersion: number, updatedAt: string): FindingRow {
    const current = this.findingRow(id);
    if (current.review_status !== "under_review" || current.version !== expectedVersion) {
      throw stateConflict(
        "Finding must still be under review at the expected version",
        "Refresh the finding and review its current evidence before verifying it.",
      );
    }
    this.database.prepare(`
      UPDATE findings SET review_status = 'verified', operator_override = 0,
        version = version + 1, updated_at = ?
      WHERE id = ? AND review_status = 'under_review' AND version = ?
    `).run(updatedAt, id, expectedVersion);
    const changed = this.database.prepare("SELECT changes() AS count").get() as { readonly count: number };
    if (Number(changed.count) !== 1) throw stateConflict("Finding changed during verification");
    return this.findingRow(id);
  }
}

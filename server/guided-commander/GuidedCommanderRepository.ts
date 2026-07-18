import { randomUUID, timingSafeEqual } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository, type JsonValue } from "../events";
import { canonicalJson, hashCanonical, sha256 } from "../missions/canonical";
import type {
  GuidedMessage,
  GuidedMissionContext,
  GuidedRepresentedStep,
  GuidedReviewedObservation,
  GuidedRunContext,
  GuidedTextResult,
  GuidedTranscriptPage,
} from "./types";
import { GuidedCommanderError } from "./validation";

interface RepositoryOptions {
  readonly clock?: () => Date;
  readonly createId?: (prefix: string) => string;
}

interface ScopeRow {
  readonly mission_id: string;
  readonly mission_name: string;
  readonly objective: string;
  readonly engagement_id: string | null;
  readonly authorization_status: string;
  readonly scope_json: string;
  readonly run_id: string;
  readonly run_status: string;
  readonly current_step_id: string | null;
  readonly progress: number;
  readonly step_id: string;
  readonly plan_id: string;
  readonly plan_version: number;
  readonly phase: string;
  readonly step_title: string;
  readonly step_objective: string;
  readonly step_status: string;
  readonly assigned_agent_id: string | null;
  readonly risk_class: string | null;
  readonly success_criteria_json: string;
  readonly representation_json: string;
}

interface DecisionRow {
  readonly id: string;
  readonly requested_action_fingerprint: string;
  readonly requested_parameters_json: string;
  readonly status: string;
}

interface MessageRow {
  readonly id: string;
  readonly conversation_id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly step_id: string | null;
  readonly role: GuidedMessage["role"];
  readonly body: string;
  readonly structured_content_json: string;
  readonly context_pack_id: string | null;
  readonly created_at: string;
}

interface CursorValue {
  readonly createdAt: string;
  readonly id: string;
}

interface StoredCompletedIdempotency {
  readonly state?: "completed";
  readonly requestHash: string;
  readonly response: JsonValue;
}

interface StoredProviderReservation {
  readonly state: "in_progress";
  readonly requestHash: string;
  readonly ownerToken: string;
  readonly expiresAt: string;
}

type StoredIdempotency = StoredCompletedIdempotency | StoredProviderReservation;

export type ProviderMutationReservationResult =
  | { readonly status: "reserved"; readonly ownerToken: string; readonly expiresAt: string }
  | { readonly status: "in_progress"; readonly expiresAt: string }
  | { readonly status: "replay"; readonly response: JsonValue };

interface Representation {
  readonly action: Readonly<Record<string, unknown>>;
  readonly explanation: string;
  readonly rationale: string;
  readonly reversibility: string;
}

export interface GuidedScope {
  readonly mission: GuidedMissionContext;
  readonly run: GuidedRunContext;
  readonly step: GuidedRepresentedStep;
}

export interface EvidenceReceipt {
  readonly id: string;
  readonly contentHash: string;
  readonly byteSize: number;
  readonly redactionCount: number;
  readonly deduplicated: boolean;
}

function parseObject(source: string, label: string): Record<string, unknown> {
  try {
    const value = JSON.parse(source) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("not an object");
    return value as Record<string, unknown>;
  } catch {
    throw new Error(`Stored ${label} is malformed`);
  }
}

function parseJsonValue(source: string, label: string): JsonValue {
  try {
    return JSON.parse(source) as JsonValue;
  } catch {
    throw new Error(`Stored ${label} is malformed`);
  }
}

function parseStringArray(source: string, label: string): readonly string[] {
  try {
    const value = JSON.parse(source) as unknown;
    if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
      throw new Error("not a string array");
    }
    return value;
  } catch {
    throw new Error(`Stored ${label} is malformed`);
  }
}

function parseRepresentation(source: string): Representation {
  const value = parseObject(source, "represented Guided action");
  if (!value.action || typeof value.action !== "object" || Array.isArray(value.action)) {
    throw new Error("Stored represented Guided action has no action object");
  }
  const explanation = value.explanation;
  const rationale = value.rationale;
  const reversibility = value.reversibility;
  if (typeof explanation !== "string") throw new Error("Stored represented Guided action has no explanation");
  if (typeof rationale !== "string") throw new Error("Stored represented Guided action has no rationale");
  if (typeof reversibility !== "string") throw new Error("Stored represented Guided action has no reversibility");
  return {
    action: value.action as Readonly<Record<string, unknown>>,
    explanation,
    rationale,
    reversibility,
  };
}

function safeFingerprintEqual(expected: string, actual: string): boolean {
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(Buffer.from(expected, "utf8"), Buffer.from(actual, "utf8"));
}

function messageFromRow(row: MessageRow): GuidedMessage {
  return {
    id: row.id,
    conversationId: row.conversation_id,
    missionId: row.mission_id,
    runId: row.run_id,
    stepId: row.step_id,
    role: row.role,
    body: row.body,
    structuredContent: parseJsonValue(row.structured_content_json, "message structured content"),
    contextPackId: row.context_pack_id,
    createdAt: row.created_at,
  };
}

function decodeCursor(value: string | undefined): CursorValue | undefined {
  if (!value) return undefined;
  try {
    const decoded = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as unknown;
    if (!decoded || typeof decoded !== "object") throw new Error("invalid");
    const cursor = decoded as Record<string, unknown>;
    if (
      typeof cursor.createdAt !== "string" ||
      Number.isNaN(Date.parse(cursor.createdAt)) ||
      typeof cursor.id !== "string" ||
      !cursor.id
    ) {
      throw new Error("invalid");
    }
    return { createdAt: cursor.createdAt, id: cursor.id };
  } catch {
    throw new GuidedCommanderError(400, "invalid_transcript_cursor", "Transcript cursor is invalid", {
      category: "invalid_input",
      remediation: "Restart transcript pagination without a cursor.",
    });
  }
}

function encodeCursor(row: MessageRow): string {
  return Buffer.from(canonicalJson({ createdAt: row.created_at, id: row.id }), "utf8").toString("base64url");
}

function idempotencySettingKey(scope: string, key: string): string {
  return `idempotency.guided-commander.${sha256(`${scope}:${key}`)}`;
}

function parseStoredIdempotency(source: string): StoredIdempotency {
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error("Stored Guided Commander idempotency record is corrupt");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Stored Guided Commander idempotency record is corrupt");
  }
  const stored = value as Record<string, unknown>;
  if (typeof stored.requestHash !== "string" || !stored.requestHash) {
    throw new Error("Stored Guided Commander idempotency record is corrupt");
  }
  if (stored.state === "in_progress") {
    if (
      typeof stored.ownerToken !== "string" || !stored.ownerToken ||
      typeof stored.expiresAt !== "string" || Number.isNaN(Date.parse(stored.expiresAt))
    ) {
      throw new Error("Stored Guided Commander provider reservation is corrupt");
    }
    return {
      state: "in_progress",
      requestHash: stored.requestHash,
      ownerToken: stored.ownerToken,
      expiresAt: stored.expiresAt,
    };
  }
  // Records written before durable reservations had no explicit state. Keep
  // them replayable as completed records during the compatibility window.
  if ((stored.state === undefined || stored.state === "completed") && "response" in stored) {
    return {
      state: "completed",
      requestHash: stored.requestHash,
      response: stored.response as JsonValue,
    };
  }
  throw new Error("Stored Guided Commander idempotency record is corrupt");
}

function asJsonValue<T>(value: T): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

/** Canonical SQLite persistence for Guided Commander conversations and evidence. */
export class GuidedCommanderRepository {
  readonly database: SqliteDatabase;
  readonly events: EventRepository;
  readonly #clock: () => Date;
  readonly #createId: (prefix: string) => string;

  constructor(database: SqliteDatabase, options: RepositoryOptions = {}) {
    this.database = database;
    this.events = new EventRepository(database);
    this.#clock = options.clock ?? (() => new Date());
    this.#createId = options.createId ?? ((prefix) => `${prefix}_${randomUUID()}`);
  }

  now(): string {
    return this.#clock().toISOString();
  }

  createId(prefix: string): string {
    return this.#createId(prefix);
  }

  transaction<T>(operation: () => T): T {
    return inImmediateTransaction(this.database, operation);
  }

  private scopeRow(missionId: string, runId: string, stepId: string): ScopeRow {
    const row = this.database.prepare(`
      SELECT
        m.id AS mission_id, m.name AS mission_name, m.objective,
        m.engagement_id, m.authorization_status, m.scope_json,
        r.id AS run_id, r.status AS run_status, r.current_step_id, r.progress,
        ps.id AS step_id, ps.plan_id, p.version AS plan_version, ps.phase,
        ps.title AS step_title, ps.objective AS step_objective,
        ps.status AS step_status, ps.assigned_agent_id, ps.risk_class,
        ps.success_criteria_json, mc.value_json AS representation_json
      FROM missions m
      JOIN runs r ON r.mission_id = m.id
      JOIN plan_steps ps ON ps.run_id = r.id
      JOIN plans p ON p.id = ps.plan_id
      JOIN mission_constraints mc
        ON mc.source = ps.id AND mc.constraint_type = 'represented_action'
      WHERE m.id = ? AND r.id = ? AND ps.id = ?
        AND m.journey = 'guided' AND r.journey = 'guided'
        AND r.current_plan_id = p.id
    `).get(missionId, runId, stepId) as ScopeRow | undefined;
    if (!row) {
      throw new GuidedCommanderError(404, "guided_scope_not_found", "Guided mission, run, or represented step was not found", {
        humanMessage: "The Guided step is unavailable or does not belong to this mission.",
        category: "not_found",
      });
    }
    return row;
  }

  requireScope(
    missionId: string,
    runId: string,
    stepId: string,
    expectedFingerprint?: string,
  ): GuidedScope {
    const row = this.scopeRow(missionId, runId, stepId);
    if (row.current_step_id !== row.step_id) {
      throw new GuidedCommanderError(409, "guided_step_stale", "The requested step is no longer current", {
        humanMessage: "This Guided step changed. Review the current step before continuing.",
        category: "conflict",
      });
    }
    const decision = this.database.prepare(`
      SELECT id, requested_action_fingerprint, requested_parameters_json, status
      FROM guided_decisions
      WHERE mission_id = ? AND run_id = ? AND step_id = ?
      ORDER BY created_at DESC, id DESC LIMIT 1
    `).get(missionId, runId, stepId) as DecisionRow | undefined;
    if (!decision) {
      throw new GuidedCommanderError(409, "guided_decision_not_represented", "The current step has no exact represented decision", {
        humanMessage: "The runtime has not produced an exact Guided action card yet.",
        category: "conflict",
        remediation: "Wait for planning to produce the next represented step.",
      });
    }
    if (expectedFingerprint && !safeFingerprintEqual(expectedFingerprint, decision.requested_action_fingerprint)) {
      throw new GuidedCommanderError(409, "guided_action_changed", "Expected action fingerprint does not match", {
        humanMessage: "The Guided action card changed or became stale. Review the current exact step.",
        category: "conflict",
      });
    }
    const represented = parseRepresentation(row.representation_json);
    return {
      mission: {
        id: row.mission_id,
        name: row.mission_name,
        objective: row.objective,
        engagementId: row.engagement_id,
        authorizationStatus: row.authorization_status,
        scope: parseObject(row.scope_json, "mission scope"),
      },
      run: {
        id: row.run_id,
        status: row.run_status,
        currentStepId: row.current_step_id,
        progress: row.progress,
      },
      step: {
        id: row.step_id,
        planId: row.plan_id,
        planVersion: row.plan_version,
        phase: row.phase,
        title: row.step_title,
        objective: row.step_objective,
        status: row.step_status,
        assignedAgentId: row.assigned_agent_id,
        riskClass: row.risk_class,
        successCriteria: parseStringArray(row.success_criteria_json, "step success criteria"),
        explanation: represented.explanation,
        rationale: represented.rationale,
        reversibility: represented.reversibility,
        representedAction: represented.action,
        decisionParameters: parseJsonValue(
          decision.requested_parameters_json,
          "Guided decision parameters",
        ),
        actionFingerprint: decision.requested_action_fingerprint,
        guidedDecisionId: decision.id,
        guidedDecisionStatus: decision.status,
      },
    };
  }

  requireRun(missionId: string, runId: string): { mission: GuidedMissionContext; run: GuidedRunContext } {
    const row = this.database.prepare(`
      SELECT m.id AS mission_id, m.name AS mission_name, m.objective,
        m.engagement_id, m.authorization_status, m.scope_json,
        r.id AS run_id, r.status AS run_status, r.current_step_id, r.progress
      FROM missions m JOIN runs r ON r.mission_id = m.id
      WHERE m.id = ? AND r.id = ? AND m.journey = 'guided' AND r.journey = 'guided'
    `).get(missionId, runId) as Omit<ScopeRow,
      "step_id" | "plan_id" | "plan_version" | "phase" | "step_title" |
      "step_objective" | "step_status" | "assigned_agent_id" | "risk_class" |
      "success_criteria_json" | "representation_json"
    > | undefined;
    if (!row) {
      throw new GuidedCommanderError(404, "guided_run_not_found", "Guided mission or run was not found", {
        category: "not_found",
      });
    }
    return {
      mission: {
        id: row.mission_id,
        name: row.mission_name,
        objective: row.objective,
        engagementId: row.engagement_id,
        authorizationStatus: row.authorization_status,
        scope: parseObject(row.scope_json, "mission scope"),
      },
      run: {
        id: row.run_id,
        status: row.run_status,
        currentStepId: row.current_step_id,
        progress: row.progress,
      },
    };
  }

  transcript(input: {
    missionId: string;
    runId: string;
    stepId?: string;
    cursor?: string;
    limit: number;
  }): GuidedTranscriptPage {
    const base = this.requireRun(input.missionId, input.runId);
    if (input.stepId) this.scopeRow(input.missionId, input.runId, input.stepId);
    const cursor = decodeCursor(input.cursor);
    const rows = this.database.prepare(`
      SELECT msg.id, msg.conversation_id, c.mission_id, c.run_id, c.step_id,
        msg.role, msg.body, msg.structured_content_json, msg.context_pack_id, msg.created_at
      FROM messages msg JOIN conversations c ON c.id = msg.conversation_id
      WHERE c.mission_id = ? AND c.run_id = ? AND c.conversation_type = 'guided'
        AND (
          ? IS NULL OR c.step_id = ? OR
          json_extract(msg.structured_content_json, '$.stepId') = ?
        )
        AND (
          ? IS NULL OR msg.created_at > ? OR (msg.created_at = ? AND msg.id > ?)
        )
      ORDER BY msg.created_at ASC, msg.id ASC
      LIMIT ?
    `).all(
      input.missionId,
      input.runId,
      input.stepId ?? null,
      input.stepId ?? null,
      input.stepId ?? null,
      cursor?.createdAt ?? null,
      cursor?.createdAt ?? null,
      cursor?.createdAt ?? null,
      cursor?.id ?? null,
      input.limit + 1,
    ) as MessageRow[];
    const hasMore = rows.length > input.limit;
    const page = rows.slice(0, input.limit);
    let currentStep: GuidedRepresentedStep | null = null;
    let currentObservation: GuidedReviewedObservation | null = null;
    if (base.run.currentStepId) {
      try {
        currentStep = this.requireScope(input.missionId, input.runId, base.run.currentStepId).step;
        currentObservation = this.reviewedObservation(
          input.missionId,
          input.runId,
          base.run.currentStepId,
          currentStep.actionFingerprint,
        );
      } catch (error) {
        if (!(error instanceof GuidedCommanderError) || error.code !== "guided_decision_not_represented") throw error;
      }
    }
    return {
      ...base,
      currentStep,
      currentObservation,
      items: page.map(messageFromRow),
      nextCursor: hasMore && page.length ? encodeCursor(page[page.length - 1]!) : null,
    };
  }

  reviewedObservation(
    missionId: string,
    runId: string,
    stepId: string,
    actionFingerprint: string,
  ): GuidedReviewedObservation | null {
    const row = this.database.prepare(`
      SELECT e.id, e.content_hash, e.provenance_json, e.verification_state,
        e.acquired_at, interpreted.details_json AS interpretation_json
      FROM evidence e
      JOIN evidence_chain_events interpreted
        ON interpreted.evidence_id = e.id AND interpreted.event_type = 'interpreted'
      WHERE e.mission_id = ? AND e.run_id = ? AND e.step_id = ?
        AND e.evidence_type = 'guided_text_result'
      ORDER BY interpreted.occurred_at DESC, interpreted.id DESC LIMIT 1
    `).get(missionId, runId, stepId) as {
      id: string;
      content_hash: string;
      provenance_json: string;
      verification_state: GuidedReviewedObservation["verificationState"];
      interpretation_json: string;
      acquired_at: string;
    } | undefined;
    if (!row) return null;
    const provenance = parseObject(row.provenance_json, "Guided evidence provenance");
    const interpretation = parseObject(row.interpretation_json, "Guided evidence interpretation");
    if (provenance.representedActionFingerprint !== actionFingerprint) return null;
    const source = provenance.source;
    if (source !== "paste" && source !== "text_upload") return null;
    return {
      evidenceId: row.id,
      contentHash: row.content_hash,
      source,
      mediaType: typeof provenance.mediaType === "string" ? provenance.mediaType : "text/plain",
      fileName: typeof provenance.fileName === "string" ? provenance.fileName : null,
      byteSize: Number(provenance.byteSize ?? 0),
      redactionCount: Number(provenance.redactionCount ?? 0),
      interpretationSummary: typeof interpretation.summary === "string"
        ? interpretation.summary
        : "The Guided observation was interpreted.",
      verificationState: row.verification_state,
      acquiredAt: row.acquired_at,
    };
  }

  recentTranscript(missionId: string, runId: string, limit: number): readonly GuidedMessage[] {
    const rows = this.database.prepare(`
      SELECT * FROM (
        SELECT msg.id, msg.conversation_id, c.mission_id, c.run_id, c.step_id,
          msg.role, msg.body, msg.structured_content_json, msg.context_pack_id, msg.created_at
        FROM messages msg JOIN conversations c ON c.id = msg.conversation_id
        WHERE c.mission_id = ? AND c.run_id = ? AND c.conversation_type = 'guided'
        ORDER BY msg.created_at DESC, msg.id DESC LIMIT ?
      ) ORDER BY created_at ASC, id ASC
    `).all(missionId, runId, limit) as MessageRow[];
    return rows.map(messageFromRow);
  }

  requireMessageForStep(
    messageId: string,
    missionId: string,
    runId: string,
    stepId: string,
  ): GuidedMessage {
    const row = this.database.prepare(`
      SELECT msg.id, msg.conversation_id, c.mission_id, c.run_id, c.step_id,
        msg.role, msg.body, msg.structured_content_json, msg.context_pack_id, msg.created_at
      FROM messages msg JOIN conversations c ON c.id = msg.conversation_id
      WHERE msg.id = ? AND c.mission_id = ? AND c.run_id = ? AND c.conversation_type = 'guided'
    `).get(messageId, missionId, runId) as MessageRow | undefined;
    if (!row) {
      throw new GuidedCommanderError(404, "guided_source_message_not_found", "Source message was not found in this Guided run", {
        category: "not_found",
      });
    }
    const message = messageFromRow(row);
    const structured = message.structuredContent;
    const structuredStep = structured && typeof structured === "object" && !Array.isArray(structured)
      ? structured.stepId
      : undefined;
    if (message.stepId !== stepId && structuredStep !== stepId) {
      throw new GuidedCommanderError(409, "guided_source_message_scope_conflict", "Source message belongs to another step", {
        humanMessage: "Select a message from the current represented step.",
        category: "scope_conflict",
      });
    }
    return message;
  }

  private getOrCreateConversation(scope: GuidedScope, now: string): string {
    const existing = this.database.prepare(`
      SELECT id FROM conversations
      WHERE mission_id = ? AND run_id = ? AND step_id = ? AND conversation_type = 'guided'
      ORDER BY created_at, id LIMIT 1
    `).get(scope.mission.id, scope.run.id, scope.step.id) as { id: string } | undefined;
    if (existing) return existing.id;
    const conversationId = this.createId("conversation");
    this.database.prepare(`
      INSERT INTO conversations (
        id, mission_id, run_id, step_id, conversation_type, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'guided', ?, ?)
    `).run(conversationId, scope.mission.id, scope.run.id, scope.step.id, now, now);
    return conversationId;
  }

  /**
   * Conversation cursors use (created_at, id), so timestamps must advance even
   * when a deterministic test clock or a coarse host clock returns the same
   * instant for two exchanges. Keeping this invariant in the repository also
   * prevents a newly inserted operator message from sorting ahead of the
   * represented step that preceded it.
   */
  private nextConversationTimestamp(conversationId: string, candidate: string): string {
    const latest = this.database.prepare(`
      SELECT created_at FROM messages
      WHERE conversation_id = ?
      ORDER BY created_at DESC, id DESC LIMIT 1
    `).get(conversationId) as { created_at: string } | undefined;
    if (!latest) return candidate;
    const candidateMs = Date.parse(candidate);
    const latestMs = Date.parse(latest.created_at);
    if (!Number.isFinite(latestMs) || candidateMs > latestMs) return candidate;
    return new Date(latestMs + 1).toISOString();
  }

  insertExchange(input: {
    scope: GuidedScope;
    actorId: string;
    action: string;
    operatorBody: string;
    operatorStructured: JsonValue;
    assistantBody: string;
    assistantStructured: JsonValue;
    contextPackId?: string;
    providerTurnId?: string;
    evidenceId?: string;
  }): { operatorMessage: GuidedMessage; assistantMessage: GuidedMessage } {
    const requestedAt = this.now();
    const conversationId = this.getOrCreateConversation(input.scope, requestedAt);
    const now = this.nextConversationTimestamp(conversationId, requestedAt);
    const assistantAt = new Date(Date.parse(now) + 1).toISOString();
    const operatorId = this.createId("message");
    const assistantId = this.createId("message");
    const insert = this.database.prepare(`
      INSERT INTO messages (
        id, conversation_id, role, body, structured_content_json, context_pack_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    insert.run(
      operatorId,
      conversationId,
      "operator",
      input.operatorBody,
      canonicalJson(input.operatorStructured),
      null,
      now,
    );
    insert.run(
      assistantId,
      conversationId,
      "assistant",
      input.assistantBody,
      canonicalJson(input.assistantStructured),
      input.contextPackId ?? null,
      assistantAt,
    );
    this.database.prepare("UPDATE conversations SET updated_at = ? WHERE id = ?")
      .run(assistantAt, conversationId);
    if (input.contextPackId) {
      this.database.prepare(`
        UPDATE memory_context_packs SET message_id = ?
        WHERE id = ? AND mission_id = ? AND run_id = ? AND journey = 'guided'
      `).run(assistantId, input.contextPackId, input.scope.mission.id, input.scope.run.id);
    }
    if (input.providerTurnId) {
      this.database.prepare(`
        UPDATE provider_turns
        SET conversation_id = ?, message_id = ?
        WHERE id = ? AND run_id = ?
      `).run(conversationId, assistantId, input.providerTurnId, input.scope.run.id);
    }
    const operatorMessage = this.getMessage(operatorId);
    const assistantMessage = this.getMessage(assistantId);
    this.events.append({
      missionId: input.scope.mission.id,
      runId: input.scope.run.id,
      journey: "guided",
      eventType: `guided.commander.${input.action}`,
      actorType: "agent",
      actorId: "guided-commander",
      summary: input.action === "interpret_result"
        ? "Guided Commander interpreted the retained text evidence"
        : "Guided Commander added a bounded explanation without advancing execution",
      payload: {
        stepId: input.scope.step.id,
        actionFingerprint: input.scope.step.actionFingerprint,
        operatorMessageId: operatorMessage.id,
        assistantMessageId: assistantMessage.id,
        evidenceId: input.evidenceId ?? null,
      },
      contextPackId: input.contextPackId ?? null,
      sensitivity: "private",
    });
    this.appendAudit({
      scope: input.scope,
      actorId: input.actorId,
      action: `guided.commander.${input.action}`,
      resourceType: "message",
      resourceId: assistantId,
      reason: "Operator requested a bounded Guided Commander action",
      details: {
        stepId: input.scope.step.id,
        actionFingerprint: input.scope.step.actionFingerprint,
        evidenceId: input.evidenceId ?? null,
      },
      now,
    });
    return { operatorMessage, assistantMessage };
  }

  getMessage(messageId: string): GuidedMessage {
    const row = this.database.prepare(`
      SELECT msg.id, msg.conversation_id, c.mission_id, c.run_id, c.step_id,
        msg.role, msg.body, msg.structured_content_json, msg.context_pack_id, msg.created_at
      FROM messages msg JOIN conversations c ON c.id = msg.conversation_id
      WHERE msg.id = ?
    `).get(messageId) as MessageRow | undefined;
    if (!row) throw new Error(`Message not found: ${messageId}`);
    return messageFromRow(row);
  }

  acquireTextEvidence(
    scope: GuidedScope,
    actorId: string,
    result: GuidedTextResult,
    assertMutationAuthority: () => void,
  ): EvidenceReceipt {
    return this.transaction(() => {
      assertMutationAuthority();
      const existing = this.database.prepare(`
        SELECT id, provenance_json FROM evidence
        WHERE mission_id = ? AND run_id = ? AND step_id = ?
          AND evidence_type = 'guided_text_result' AND content_hash = ?
        ORDER BY created_at, id LIMIT 1
      `).get(scope.mission.id, scope.run.id, scope.step.id, result.contentHash) as {
        id: string;
        provenance_json: string;
      } | undefined;
      if (existing) {
        const provenance = parseObject(existing.provenance_json, "evidence provenance");
        return {
          id: existing.id,
          contentHash: result.contentHash,
          byteSize: Number(provenance.byteSize ?? result.byteSize),
          redactionCount: Number(provenance.redactionCount ?? result.redactionCount),
          deduplicated: true,
        };
      }
      const now = this.now();
      const evidenceId = this.createId("evidence");
      const target = typeof scope.step.representedAction.target === "string"
        ? scope.step.representedAction.target
        : null;
      const provenance = {
        method: "operator_supplied_text",
        source: result.source,
        mediaType: result.mediaType,
        fileName: result.fileName ?? null,
        byteSize: result.byteSize,
        redactionCount: result.redactionCount,
        rawContentRetained: false,
        contentAddressedBy: "sha256",
        representedActionFingerprint: scope.step.actionFingerprint,
      };
      this.database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, step_id, action_id, source, acquired_at,
          target, evidence_type, content_hash, provenance_json, confidence,
          sensitivity, verification_state, summary, extracted_text,
          artifact_id, created_by, created_at
        ) VALUES (?, ?, ?, ?, NULL, 'guided.operator_text', ?, ?,
          'guided_text_result', ?, ?, 0.5, 'private', 'unverified', ?, ?, NULL, ?, ?)
      `).run(
        evidenceId,
        scope.mission.id,
        scope.run.id,
        scope.step.id,
        now,
        target,
        result.contentHash,
        canonicalJson(provenance),
        "Operator supplied a bounded text result for Guided interpretation",
        result.redactedText,
        actorId,
        now,
      );
      this.database.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES (?, ?, 'acquired', ?, ?, ?)
      `).run(
        this.createId("evidence-chain"),
        evidenceId,
        actorId,
        canonicalJson({
          source: result.source,
          contentHash: result.contentHash,
          byteSize: result.byteSize,
          rawContentRetained: false,
          redactionCount: result.redactionCount,
        }),
        now,
      );
      this.events.append({
        missionId: scope.mission.id,
        runId: scope.run.id,
        journey: "guided",
        eventType: "evidence.guided_text_acquired",
        actorType: "operator",
        actorId,
        summary: "Operator supplied bounded text evidence for Guided interpretation",
        payload: {
          evidenceId,
          stepId: scope.step.id,
          contentHash: result.contentHash,
          byteSize: result.byteSize,
          redactionCount: result.redactionCount,
          rawContentRetained: false,
        },
        sensitivity: "private",
        redaction: { authenticationMaterial: result.redactionCount },
      });
      return {
        id: evidenceId,
        contentHash: result.contentHash,
        byteSize: result.byteSize,
        redactionCount: result.redactionCount,
        deduplicated: false,
      };
    });
  }

  recordTextEvidenceInterpretation(input: {
    scope: GuidedScope;
    evidenceId: string;
    assistantMessageId: string;
    contextPackId: string;
    summary: string;
    confidence: number;
  }): void {
    const row = this.database.prepare(`
      SELECT provenance_json FROM evidence
      WHERE id = ? AND mission_id = ? AND run_id = ? AND step_id = ?
        AND evidence_type = 'guided_text_result' AND action_id IS NULL
    `).get(
      input.evidenceId,
      input.scope.mission.id,
      input.scope.run.id,
      input.scope.step.id,
    ) as { provenance_json: string } | undefined;
    if (!row) {
      throw new GuidedCommanderError(409, "guided_evidence_scope_conflict", "Evidence is not available for this exact Guided step", {
        humanMessage: "The observed result no longer belongs to the current represented step.",
        category: "scope_conflict",
      });
    }
    const provenance = parseObject(row.provenance_json, "Guided evidence provenance");
    if (provenance.representedActionFingerprint !== input.scope.step.actionFingerprint) {
      throw new GuidedCommanderError(409, "guided_evidence_fingerprint_conflict", "Evidence action fingerprint changed", {
        humanMessage: "The observed result was captured for a different exact action.",
        category: "conflict",
      });
    }
    const now = this.now();
    this.database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'interpreted', 'guided-commander', ?, ?)
    `).run(
      this.createId("evidence-chain"),
      input.evidenceId,
      canonicalJson({
        assistantMessageId: input.assistantMessageId,
        contextPackId: input.contextPackId,
        actionFingerprint: input.scope.step.actionFingerprint,
        confidence: input.confidence,
        summary: input.summary,
      }),
      now,
    );
    this.events.append({
      missionId: input.scope.mission.id,
      runId: input.scope.run.id,
      journey: "guided",
      eventType: "evidence.guided_text_interpreted",
      actorType: "agent",
      actorId: "guided-commander",
      summary: "Guided Commander interpreted the bounded observation without advancing the step",
      payload: {
        evidenceId: input.evidenceId,
        stepId: input.scope.step.id,
        assistantMessageId: input.assistantMessageId,
        actionFingerprint: input.scope.step.actionFingerprint,
      },
      contextPackId: input.contextPackId,
      sensitivity: "private",
    });
  }

  startProviderTurn(scope: GuidedScope, provider: string, model?: string): { id: string; startedAt: number } {
    const id = this.createId("provider-turn");
    const now = this.now();
    this.database.prepare(`
      INSERT INTO provider_turns (
        id, run_id, provider, model, status, started_at
      ) VALUES (?, ?, ?, ?, 'started', ?)
    `).run(id, scope.run.id, provider, model ?? null, now);
    return { id, startedAt: performance.now() };
  }

  finishProviderTurn(
    id: string,
    status: "completed" | "failed" | "cancelled",
    startedAt: number,
    errorCategory?: string,
  ): void {
    this.database.prepare(`
      UPDATE provider_turns SET status = ?, latency_ms = ?, error_category = ?, ended_at = ?
      WHERE id = ? AND status = 'started'
    `).run(
      status,
      Math.max(0, Math.round(performance.now() - startedAt)),
      errorCategory ?? null,
      this.now(),
      id,
    );
  }

  findIdempotent(scope: string, key: string, requestHash: string): JsonValue | undefined {
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(idempotencySettingKey(scope, key)) as { value_json: string } | undefined;
    if (!row) return undefined;
    const stored = parseStoredIdempotency(row.value_json);
    if (stored.requestHash !== requestHash) {
      throw new GuidedCommanderError(409, "idempotency_key_conflict", "Idempotency key was reused with another request", {
        humanMessage: "This action key already belongs to another Guided command.",
        category: "conflict",
      });
    }
    return stored.state === "in_progress" ? undefined : stored.response;
  }

  findIdempotentAuthorized(input: {
    scope: string;
    key: string;
    requestHash: string;
    assertMutationAuthority: () => void;
  }): JsonValue | undefined {
    return this.transaction(() => {
      // Replay data is protected mission state. Check the current controller
      // in the same BEGIN IMMEDIATE transaction as the replay read.
      input.assertMutationAuthority();
      return this.findIdempotent(input.scope, input.key, input.requestHash);
    });
  }

  reserveProviderMutation(input: {
    scope: string;
    key: string;
    requestHash: string;
    actorId: string;
    leaseMs: number;
    assertMutationAuthority: () => void;
  }): ProviderMutationReservationResult {
    if (!Number.isSafeInteger(input.leaseMs) || input.leaseMs < 1_000 || input.leaseMs > 15 * 60_000) {
      throw new RangeError("Guided provider reservation lease must be 1,000 through 900,000 milliseconds");
    }
    return this.transaction(() => {
      // Fence the durable reservation in the same BEGIN IMMEDIATE transaction
      // that makes it visible to other V2 workers.
      input.assertMutationAuthority();
      const settingKey = idempotencySettingKey(input.scope, input.key);
      const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(settingKey) as { value_json: string } | undefined;
      const now = this.now();
      if (row) {
        const stored = parseStoredIdempotency(row.value_json);
        if (stored.requestHash !== input.requestHash) {
          throw new GuidedCommanderError(409, "idempotency_key_conflict", "Idempotency key was reused with another request", {
            humanMessage: "This action key already belongs to another Guided command.",
            category: "conflict",
          });
        }
        if (stored.state !== "in_progress") {
          return { status: "replay", response: stored.response };
        }
        if (Date.parse(stored.expiresAt) > Date.parse(now)) {
          return { status: "in_progress", expiresAt: stored.expiresAt };
        }
      }

      const ownerToken = this.createId("guided-provider-owner");
      const expiresAt = new Date(Date.parse(now) + input.leaseMs).toISOString();
      const value = canonicalJson({
        state: "in_progress",
        requestHash: input.requestHash,
        ownerToken,
        expiresAt,
      });
      if (row) {
        this.database.prepare(`
          UPDATE settings SET value_json = ?, version = version + 1,
            updated_by = ?, updated_at = ? WHERE key = ?
        `).run(value, input.actorId, now, settingKey);
      } else {
        this.database.prepare(`
          INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
          VALUES (?, ?, 'private', 1, ?, ?)
        `).run(settingKey, value, input.actorId, now);
      }
      return { status: "reserved", ownerToken, expiresAt };
    });
  }

  renewProviderMutationReservation(input: {
    scope: string;
    key: string;
    requestHash: string;
    ownerToken: string;
    leaseMs: number;
  }): boolean {
    return this.transaction(() => {
      const settingKey = idempotencySettingKey(input.scope, input.key);
      const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(settingKey) as { value_json: string } | undefined;
      if (!row) return false;
      const stored = parseStoredIdempotency(row.value_json);
      if (
        stored.state !== "in_progress" ||
        stored.requestHash !== input.requestHash ||
        stored.ownerToken !== input.ownerToken
      ) return false;
      const now = this.now();
      const expiresAt = new Date(Date.parse(now) + input.leaseMs).toISOString();
      this.database.prepare(`
        UPDATE settings SET value_json = ?, version = version + 1, updated_at = ?
        WHERE key = ?
      `).run(canonicalJson({ ...stored, expiresAt }), now, settingKey);
      return true;
    });
  }

  releaseProviderMutationReservation(input: {
    scope: string;
    key: string;
    requestHash: string;
    ownerToken: string;
  }): boolean {
    return this.transaction(() => {
      const settingKey = idempotencySettingKey(input.scope, input.key);
      const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(settingKey) as { value_json: string } | undefined;
      if (!row) return false;
      const stored = parseStoredIdempotency(row.value_json);
      if (
        stored.state !== "in_progress" ||
        stored.requestHash !== input.requestHash ||
        stored.ownerToken !== input.ownerToken
      ) return false;
      return this.database.prepare("DELETE FROM settings WHERE key = ?").run(settingKey).changes === 1;
    });
  }

  completeProviderMutationReservation<T>(input: {
    scope: string;
    key: string;
    requestHash: string;
    ownerToken: string;
    actorId: string;
    assertMutationAuthority: () => void;
    operation: () => T;
  }): { value: T; replayed: boolean } {
    return this.transaction(() => {
      // A response finishing after lease loss cannot commit through an older
      // provider reservation, even if the idempotency key is otherwise valid.
      input.assertMutationAuthority();
      const settingKey = idempotencySettingKey(input.scope, input.key);
      const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(settingKey) as { value_json: string } | undefined;
      if (!row) {
        throw new GuidedCommanderError(409, "guided_commander_reservation_lost", "Provider reservation no longer exists", {
          category: "conflict",
          retryable: true,
          remediation: "Retry with the same Idempotency-Key to obtain the stored response or a new reservation.",
        });
      }
      const stored = parseStoredIdempotency(row.value_json);
      if (stored.requestHash !== input.requestHash) {
        throw new GuidedCommanderError(409, "idempotency_key_conflict", "Idempotency key was reused with another request", {
          category: "conflict",
        });
      }
      if (stored.state !== "in_progress") {
        return { value: stored.response as T, replayed: true };
      }
      if (stored.ownerToken !== input.ownerToken) {
        throw new GuidedCommanderError(409, "guided_commander_reservation_lost", "Another worker owns the provider reservation", {
          category: "conflict",
          retryable: true,
          remediation: "Retry with the same Idempotency-Key after the active owner completes.",
        });
      }
      const value = input.operation();
      const response = asJsonValue(value);
      this.database.prepare(`
        UPDATE settings SET value_json = ?, version = version + 1,
          updated_by = ?, updated_at = ? WHERE key = ?
      `).run(
        canonicalJson({ state: "completed", requestHash: input.requestHash, response }),
        input.actorId,
        this.now(),
        settingKey,
      );
      return { value, replayed: false };
    });
  }

  commitIdempotent<T>(input: {
    scope: string;
    key: string;
    requestHash: string;
    actorId: string;
    assertMutationAuthority: () => void;
    operation: () => T;
  }): { value: T; replayed: boolean } {
    return this.transaction(() => {
      // A concurrent writer may complete after the fast replay lookup. Recheck
      // before both the transactional replay branch and a new write.
      input.assertMutationAuthority();
      const replay = this.findIdempotent(input.scope, input.key, input.requestHash);
      if (replay !== undefined) return { value: replay as T, replayed: true };
      const value = input.operation();
      const response = asJsonValue(value);
      this.database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'private', 1, ?, ?)
      `).run(
        idempotencySettingKey(input.scope, input.key),
        canonicalJson({ state: "completed", requestHash: input.requestHash, response }),
        input.actorId,
        this.now(),
      );
      return { value, replayed: false };
    });
  }

  candidateScope(candidateId: string): {
    status: string;
    nodeType: string;
    scope: string;
    engagementId: string | null;
    missionId: string | null;
  } | null {
    const row = this.database.prepare(`
      SELECT status, candidate_type, proposed_scope, engagement_id, mission_id
      FROM memory_candidates WHERE id = ?
    `).get(candidateId) as {
      status: string;
      candidate_type: string;
      proposed_scope: string;
      engagement_id: string | null;
      mission_id: string | null;
    } | undefined;
    return row ? {
      status: row.status,
      nodeType: row.candidate_type,
      scope: row.proposed_scope,
      engagementId: row.engagement_id,
      missionId: row.mission_id,
    } : null;
  }

  appendMemoryEvent(input: {
    scope: GuidedScope;
    actorId: string;
    action: "candidate_created" | "candidate_suppressed";
    candidateId: string;
    resourceId: string;
  }): void {
    const now = this.now();
    this.events.append({
      missionId: input.scope.mission.id,
      runId: input.scope.run.id,
      journey: "guided",
      eventType: `memory.${input.action}`,
      actorType: "operator",
      actorId: input.actorId,
      summary: input.action === "candidate_created"
        ? "Operator proposed a reviewable memory candidate"
        : "Operator suppressed a memory candidate and prevented relearning",
      payload: {
        candidateId: input.candidateId,
        stepId: input.scope.step.id,
        resourceId: input.resourceId,
      },
      sensitivity: "private",
    });
    this.appendAudit({
      scope: input.scope,
      actorId: input.actorId,
      action: `memory.${input.action}`,
      resourceType: "memory_candidate",
      resourceId: input.candidateId,
      reason: input.action === "candidate_created"
        ? "Operator requested reviewable retention"
        : "Operator requested do-not-relearn suppression",
      details: { stepId: input.scope.step.id, resourceId: input.resourceId },
      now,
    });
  }

  private appendAudit(input: {
    scope: GuidedScope;
    actorId: string;
    action: string;
    resourceType: string;
    resourceId: string;
    reason: string;
    details: JsonValue;
    now: string;
  }): void {
    const previous = this.database.prepare(`
      SELECT record_hash FROM audit_records ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get() as { record_hash: string } | undefined;
    const auditId = this.createId("audit");
    const recordHash = hashCanonical({
      id: auditId,
      previousHash: previous?.record_hash ?? null,
      missionId: input.scope.mission.id,
      runId: input.scope.run.id,
      journey: "guided",
      actorId: input.actorId,
      action: input.action,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      reason: input.reason,
      details: input.details,
      occurredAt: input.now,
    });
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action, resource_type,
        resource_id, reason, details_json, previous_hash, record_hash, occurred_at
      ) VALUES (?, ?, ?, 'guided', 'operator', ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      auditId,
      input.scope.mission.id,
      input.scope.run.id,
      input.actorId,
      input.action,
      input.resourceType,
      input.resourceId,
      input.reason,
      canonicalJson(input.details),
      previous?.record_hash ?? null,
      recordHash,
      input.now,
    );
  }
}

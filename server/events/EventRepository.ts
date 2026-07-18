import { randomUUID } from "node:crypto";
import { inImmediateTransaction } from "../db/transaction";
import type { SqliteDatabase } from "../db/types";
import type {
  AppendRunEventInput,
  JsonValue,
  OutboxRecord,
  RunEvent,
} from "./types";
import { NotificationProjector } from "../notifications/NotificationProjector";

interface RunIdentityRow {
  readonly mission_id: string;
  readonly journey: "autonomous" | "guided";
}

interface SequenceRow {
  readonly last_sequence: number;
}

interface EventRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly sequence: number;
  readonly event_type: string;
  readonly occurred_at: string;
  readonly actor_type: RunEvent["actorType"];
  readonly actor_id: string | null;
  readonly summary: string;
  readonly payload_json: string;
  readonly schema_version: number;
  readonly journey: RunEvent["journey"];
  readonly trace_id: string | null;
  readonly span_id: string | null;
  readonly sensitivity: RunEvent["sensitivity"];
  readonly redaction_json: string;
  readonly context_pack_id: string | null;
  readonly created_at: string;
}

interface EventIdRow {
  readonly id: string;
}

interface OutboxRow {
  readonly id: string;
  readonly event_id: string;
  readonly topic: string;
  readonly payload_json: string;
  readonly status: OutboxRecord["status"];
  readonly attempt_count: number;
  readonly available_at: string;
  readonly claimed_by: string | null;
  readonly claimed_at: string | null;
  readonly delivered_at: string | null;
  readonly last_error: string | null;
  readonly created_at: string;
}

function serializeJson(value: JsonValue): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new TypeError("Event value is not JSON serializable");
  return serialized;
}

function parseJson(serialized: string): JsonValue {
  return JSON.parse(serialized) as JsonValue;
}

function mapEvent(row: EventRow): RunEvent {
  return {
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    sequence: row.sequence,
    eventType: row.event_type,
    occurredAt: row.occurred_at,
    actorType: row.actor_type,
    actorId: row.actor_id,
    summary: row.summary,
    payload: parseJson(row.payload_json),
    schemaVersion: row.schema_version,
    journey: row.journey,
    traceId: row.trace_id,
    spanId: row.span_id,
    sensitivity: row.sensitivity,
    redaction: parseJson(row.redaction_json),
    contextPackId: row.context_pack_id,
    createdAt: row.created_at,
  };
}

function mapOutbox(row: OutboxRow): OutboxRecord {
  return {
    id: row.id,
    eventId: row.event_id,
    topic: row.topic,
    payload: parseJson(row.payload_json),
    status: row.status,
    attemptCount: row.attempt_count,
    availableAt: row.available_at,
    claimedBy: row.claimed_by,
    claimedAt: row.claimed_at,
    deliveredAt: row.delivered_at,
    lastError: row.last_error,
    createdAt: row.created_at,
  };
}

function boundedLimit(limit: number, maximum: number): number {
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new RangeError("limit must be a positive integer");
  }
  return Math.min(limit, maximum);
}

/** Durable append-only event log paired with a transactional delivery outbox. */
export class EventRepository {
  private readonly notifications;
  private readonly findRun;
  private readonly allocateSequence;
  private readonly insertEvent;
  private readonly insertOutbox;
  private readonly listEventsAfter;
  private readonly findEventById;
  private readonly listGlobalEventsAfter;
  private readonly listGlobalEventsFromStart;
  private readonly findLatestEvent;
  private readonly selectOutbox;
  private readonly markClaimed;
  private readonly markDeliveredStatement;
  private readonly markFailedStatement;
  private readonly releaseStaleClaimsStatement;

  constructor(private readonly database: SqliteDatabase) {
    this.notifications = new NotificationProjector(database);
    this.findRun = database.prepare(
      "SELECT mission_id, journey FROM runs WHERE id = ?",
    );
    this.allocateSequence = database.prepare(`
      INSERT INTO run_event_sequences (run_id, last_sequence)
      VALUES (
        ?,
        COALESCE((SELECT MAX(sequence) + 1 FROM events WHERE run_id = ?), 1)
      )
      ON CONFLICT(run_id) DO UPDATE SET last_sequence = last_sequence + 1
      RETURNING last_sequence
    `);
    this.insertEvent = database.prepare(`
      INSERT INTO events (
        id, mission_id, run_id, sequence, event_type, occurred_at,
        actor_type, actor_id, summary, payload_json, schema_version, journey,
        trace_id, span_id, sensitivity, redaction_json, context_pack_id, created_at
      ) VALUES (
        @id, @missionId, @runId, @sequence, @eventType, @occurredAt,
        @actorType, @actorId, @summary, @payloadJson, @schemaVersion, @journey,
        @traceId, @spanId, @sensitivity, @redactionJson, @contextPackId, @createdAt
      )
    `);
    this.insertOutbox = database.prepare(`
      INSERT INTO event_outbox (
        id, event_id, topic, payload_json, status, attempt_count,
        available_at, created_at
      ) VALUES (?, ?, ?, ?, 'pending', 0, ?, ?)
    `);
    this.listEventsAfter = database.prepare(`
      SELECT * FROM events
      WHERE run_id = ? AND sequence > ?
      ORDER BY sequence ASC
      LIMIT ?
    `);
    this.findEventById = database.prepare("SELECT * FROM events WHERE id = ?");
    this.listGlobalEventsAfter = database.prepare(`
      SELECT * FROM events
      WHERE rowid > COALESCE((SELECT rowid FROM events WHERE id = ?), -1)
      ORDER BY rowid ASC
      LIMIT ?
    `);
    this.listGlobalEventsFromStart = database.prepare(`
      SELECT * FROM events
      ORDER BY rowid ASC
      LIMIT ?
    `);
    this.findLatestEvent = database.prepare(`
      SELECT id FROM events ORDER BY rowid DESC LIMIT 1
    `);
    this.selectOutbox = database.prepare(`
      SELECT * FROM event_outbox
      WHERE status IN ('pending', 'failed') AND available_at <= ?
      ORDER BY available_at ASC, created_at ASC
      LIMIT ?
    `);
    this.markClaimed = database.prepare(`
      UPDATE event_outbox
      SET status = 'delivering', claimed_by = ?, claimed_at = ?,
          attempt_count = attempt_count + 1, last_error = NULL
      WHERE id = ? AND status IN ('pending', 'failed')
    `);
    this.markDeliveredStatement = database.prepare(`
      UPDATE event_outbox
      SET status = 'delivered', delivered_at = ?, claimed_by = NULL,
          claimed_at = NULL, last_error = NULL
      WHERE id = ? AND status = 'delivering'
    `);
    this.markFailedStatement = database.prepare(`
      UPDATE event_outbox
      SET status = 'failed', available_at = ?, last_error = ?,
          claimed_by = NULL, claimed_at = NULL
      WHERE id = ? AND status = 'delivering'
    `);
    this.releaseStaleClaimsStatement = database.prepare(`
      UPDATE event_outbox
      SET status = 'failed', available_at = ?, last_error = ?,
          claimed_by = NULL, claimed_at = NULL
      WHERE status = 'delivering' AND claimed_at IS NOT NULL AND claimed_at < ?
    `);
  }

  append(input: AppendRunEventInput): RunEvent {
    const summary = input.summary.trim();
    const eventType = input.eventType.trim();
    if (!summary) throw new Error("Event summary is required");
    if (!eventType) throw new Error("Event type is required");
    if (!input.runId.trim()) throw new Error("Run ID is required");
    const schemaVersion = input.schemaVersion ?? 1;
    if (!Number.isSafeInteger(schemaVersion) || schemaVersion < 1) {
      throw new RangeError("schemaVersion must be a positive integer");
    }

    return inImmediateTransaction(this.database, () => {
      const run = this.findRun.get(input.runId) as RunIdentityRow | undefined;
      if (!run) throw new Error(`Run not found: ${input.runId}`);
      if (input.missionId && input.missionId !== run.mission_id) {
        throw new Error("Event mission does not match its run");
      }
      if (input.journey && input.journey !== run.journey) {
        throw new Error("Event journey does not match its run");
      }

      const allocated = this.allocateSequence.get(
        input.runId,
        input.runId,
      ) as SequenceRow | undefined;
      if (!allocated) throw new Error("Unable to allocate an event sequence");

      const occurredAt = input.occurredAt ?? new Date().toISOString();
      const createdAt = new Date().toISOString();
      const payload = input.payload ?? {};
      const redaction = input.redaction ?? {};
      const event: RunEvent = {
        id: input.id ?? randomUUID(),
        missionId: run.mission_id,
        runId: input.runId,
        sequence: allocated.last_sequence,
        eventType,
        occurredAt,
        actorType: input.actorType,
        actorId: input.actorId ?? null,
        summary,
        payload,
        schemaVersion,
        journey: run.journey,
        traceId: input.traceId ?? null,
        spanId: input.spanId ?? null,
        sensitivity: input.sensitivity ?? "internal",
        redaction,
        contextPackId: input.contextPackId ?? null,
        createdAt,
      };

      this.insertEvent.run({
        ...event,
        payloadJson: serializeJson(payload),
        redactionJson: serializeJson(redaction),
      });
      this.insertOutbox.run(
        `outbox:${event.id}`,
        event.id,
        input.outboxTopic?.trim() || "run.events",
        serializeJson(event as unknown as JsonValue),
        createdAt,
        createdAt,
      );
      this.notifications.project(event);
      return event;
    });
  }

  listAfter(runId: string, afterSequence = 0, limit = 250): RunEvent[] {
    if (!Number.isSafeInteger(afterSequence) || afterSequence < 0) {
      throw new RangeError("afterSequence must be a non-negative integer");
    }
    const rows = this.listEventsAfter.all(
      runId,
      afterSequence,
      boundedLimit(limit, 1_000),
    ) as EventRow[];
    return rows.map(mapEvent);
  }

  /** Resolve a stable public event ID for Last-Event-ID resume handling. */
  getById(eventId: string): RunEvent | null {
    if (!eventId.trim()) return null;
    const row = this.findEventById.get(eventId) as EventRow | undefined;
    return row ? mapEvent(row) : null;
  }

  /**
   * Replay the append-only global event stream after a stable event ID.
   *
   * Global ordering uses SQLite's append rowid. Run-scoped consumers should
   * prefer listAfter(), whose monotonic sequence is part of the public API.
   */
  listGlobalAfter(eventId: string | null, limit = 250): RunEvent[] {
    const bounded = boundedLimit(limit, 1_000);
    if (eventId === null) {
      return (this.listGlobalEventsFromStart.all(bounded) as EventRow[]).map(mapEvent);
    }
    if (!eventId.trim()) throw new Error("Event ID is required");
    if (!this.getById(eventId)) throw new Error(`Event not found: ${eventId}`);
    return (this.listGlobalEventsAfter.all(eventId, bounded) as EventRow[]).map(mapEvent);
  }

  getLatestEventId(): string | null {
    const row = this.findLatestEvent.get() as EventIdRow | undefined;
    return row?.id ?? null;
  }

  claimOutbox(
    workerId: string,
    now = new Date().toISOString(),
    limit = 100,
  ): OutboxRecord[] {
    if (!workerId.trim()) throw new Error("workerId is required");
    return inImmediateTransaction(this.database, () => {
      const candidates = this.selectOutbox.all(
        now,
        boundedLimit(limit, 500),
      ) as OutboxRow[];
      const claimed: OutboxRecord[] = [];
      for (const candidate of candidates) {
        const result = this.markClaimed.run(workerId, now, candidate.id);
        if (result.changes !== 1) continue;
        claimed.push(
          mapOutbox({
            ...candidate,
            status: "delivering",
            attempt_count: candidate.attempt_count + 1,
            claimed_by: workerId,
            claimed_at: now,
            last_error: null,
          }),
        );
      }
      return claimed;
    });
  }

  markDelivered(outboxId: string, deliveredAt = new Date().toISOString()): boolean {
    return this.markDeliveredStatement.run(deliveredAt, outboxId).changes === 1;
  }

  markFailed(
    outboxId: string,
    error: string,
    availableAt: string,
  ): boolean {
    return this.markFailedStatement.run(availableAt, error.slice(0, 2_000), outboxId)
      .changes === 1;
  }

  /** Return abandoned delivery leases to the retryable outbox. */
  releaseStaleClaims(
    claimedBefore: string,
    availableAt = new Date().toISOString(),
    reason = "Outbox delivery lease expired",
  ): number {
    return this.releaseStaleClaimsStatement.run(
      availableAt,
      reason.slice(0, 2_000),
      claimedBefore,
    ).changes;
  }
}

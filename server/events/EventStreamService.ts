import { randomUUID } from "node:crypto";
import { EventRepository } from "./EventRepository";
import type {
  EventSensitivity,
  JsonValue,
  RunEvent,
} from "./types";

const SENSITIVITY_RANK: Readonly<Record<EventSensitivity, number>> = {
  public: 0,
  internal: 1,
  private: 2,
  restricted: 3,
};

const SECRET_KEY = /(?:^|_)(?:api_?key|authorization|cookie|credential|pass(?:word)?|private_?key|secret|session_?token|token)(?:$|_)/iu;

export interface OperationalEventEnvelope {
  readonly id: string;
  readonly sequence: number;
  readonly type: string;
  readonly timestamp: string;
  readonly missionId: string;
  readonly runId: string;
  readonly journey: RunEvent["journey"];
  readonly summary: string;
  readonly actor: {
    readonly type: RunEvent["actorType"];
    readonly id: string | null;
  };
  readonly payload: JsonValue;
  readonly schemaVersion: number;
  readonly traceId: string | null;
  readonly spanId: string | null;
  readonly sensitivity: EventSensitivity;
  readonly redaction: JsonValue;
  readonly contextPackId: string | null;
}

export interface EventStreamSink {
  /** A false result means the data was accepted but the transport is backpressured. */
  write(event: OperationalEventEnvelope): boolean;
  onDrain(listener: () => void): () => void;
  close?(reason: "service_stopped" | "queue_overflow" | "transport_error"): void;
}

export interface EventStreamSubscriptionOptions {
  readonly runId?: string;
  readonly afterSequence?: number;
  readonly afterEventId?: string;
  readonly sensitivity?: EventSensitivity;
  readonly maxQueueSize?: number;
  readonly sink: EventStreamSink;
}

export interface EventStreamSubscription {
  readonly id: string;
  readonly ready: Promise<void>;
  readonly closed: boolean;
  readonly backpressured: boolean;
  readonly lastSequence: number;
  close(): void;
}

export interface OutboxPumpResult {
  readonly claimed: number;
  readonly delivered: number;
  readonly failed: number;
}

export interface EventStreamServiceOptions {
  readonly repository: EventRepository;
  readonly workerId?: string;
  readonly pollIntervalMs?: number;
  readonly outboxBatchSize?: number;
  readonly replayBatchSize?: number;
  readonly maxQueueSize?: number;
  readonly staleClaimMs?: number;
  readonly retryBaseDelayMs?: number;
  readonly retryMaxDelayMs?: number;
  readonly retryJitterRatio?: number;
  readonly clock?: () => Date;
  readonly random?: () => number;
  /** Optional durable transport hook. Throwing retains the outbox row for retry. */
  readonly beforeBroadcast?: (event: RunEvent) => void | Promise<void>;
}

interface StreamClient {
  readonly id: string;
  readonly runId?: string;
  readonly sensitivity: EventSensitivity;
  readonly maxQueueSize: number;
  readonly sink: EventStreamSink;
  readonly queue: OperationalEventEnvelope[];
  readonly readyPromise: Promise<void>;
  resolveReady: () => void;
  cursorSequence: number;
  cursorEventId: string | null;
  catchingUp: boolean;
  catchUpScheduled: boolean;
  paused: boolean;
  closed: boolean;
  removeDrainListener: (() => void) | null;
}

function isRecord(value: JsonValue): value is { readonly [key: string]: JsonValue } {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function redactionPaths(value: JsonValue): string[] {
  if (!isRecord(value)) return [];
  const configured = value.paths ?? value.fields;
  if (!Array.isArray(configured)) return [];
  return configured.filter((entry): entry is string => typeof entry === "string" && entry.length > 0);
}

function redactKnownSecrets(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(redactKnownSecrets);
  if (!isRecord(value)) return value;
  const redacted: Record<string, JsonValue> = {};
  for (const [key, child] of Object.entries(value)) {
    redacted[key] = SECRET_KEY.test(key) ? "[REDACTED]" : redactKnownSecrets(child);
  }
  return redacted;
}

function redactPath(value: JsonValue, path: readonly string[]): JsonValue {
  if (path.length === 0 || !isRecord(value)) return value;
  const [head, ...tail] = path;
  if (!head || !(head in value)) return value;
  return {
    ...value,
    [head]: tail.length === 0 ? "[REDACTED]" : redactPath(value[head]!, tail),
  };
}

function redactPayload(payload: JsonValue, metadata: JsonValue): JsonValue {
  let result = redactKnownSecrets(payload);
  for (const path of redactionPaths(metadata)) {
    result = redactPath(result, path.split(".").filter(Boolean));
  }
  return result;
}

/** Convert the durable event record to the stable frontend V2 envelope. */
export function toOperationalEventEnvelope(
  event: RunEvent,
  allowedSensitivity: EventSensitivity = "internal",
): OperationalEventEnvelope {
  const sensitivityDenied =
    SENSITIVITY_RANK[event.sensitivity] > SENSITIVITY_RANK[allowedSensitivity];
  return {
    id: event.id,
    sequence: event.sequence,
    type: event.eventType,
    timestamp: event.occurredAt,
    missionId: event.missionId,
    runId: event.runId,
    journey: event.journey,
    summary: sensitivityDenied ? "Sensitive event details redacted" : event.summary,
    actor: {
      type: event.actorType,
      id: sensitivityDenied ? null : event.actorId,
    },
    payload: sensitivityDenied
      ? { redacted: true, reason: "sensitivity_policy" }
      : redactPayload(event.payload, event.redaction),
    schemaVersion: event.schemaVersion,
    traceId: sensitivityDenied ? null : event.traceId,
    spanId: sensitivityDenied ? null : event.spanId,
    sensitivity: event.sensitivity,
    redaction: sensitivityDenied
      ? { applied: true, reason: "sensitivity_policy" }
      : event.redaction,
    contextPackId: sensitivityDenied ? null : event.contextPackId,
  };
}

function positiveInteger(
  value: number | undefined,
  fallback: number,
  maximum: number,
  label: string,
): number {
  const normalized = value ?? fallback;
  if (!Number.isSafeInteger(normalized) || normalized < 1 || normalized > maximum) {
    throw new RangeError(`${label} must be an integer between 1 and ${maximum}`);
  }
  return normalized;
}

function nonNegativeInteger(value: number | undefined, fallback: number, label: string): number {
  const normalized = value ?? fallback;
  if (!Number.isSafeInteger(normalized) || normalized < 0) {
    throw new RangeError(`${label} must be a non-negative integer`);
  }
  return normalized;
}

/** Durable outbox publisher plus replay-aware, bounded in-process fanout. */
export class EventStreamService {
  private readonly repository: EventRepository;
  private readonly workerId: string;
  private readonly pollIntervalMs: number;
  private readonly outboxBatchSize: number;
  private readonly replayBatchSize: number;
  private readonly defaultMaxQueueSize: number;
  private readonly staleClaimMs: number;
  private readonly retryBaseDelayMs: number;
  private readonly retryMaxDelayMs: number;
  private readonly retryJitterRatio: number;
  private readonly clock: () => Date;
  private readonly random: () => number;
  private readonly beforeBroadcast?: (event: RunEvent) => void | Promise<void>;
  private readonly clients = new Map<string, StreamClient>();
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private activePump: Promise<OutboxPumpResult> | null = null;
  private started = false;

  constructor(options: EventStreamServiceOptions) {
    this.repository = options.repository;
    this.workerId = options.workerId?.trim() || `event-stream:${process.pid}:${randomUUID()}`;
    this.pollIntervalMs = positiveInteger(options.pollIntervalMs, 100, 500, "pollIntervalMs");
    this.outboxBatchSize = positiveInteger(options.outboxBatchSize, 100, 500, "outboxBatchSize");
    this.replayBatchSize = positiveInteger(options.replayBatchSize, 250, 1_000, "replayBatchSize");
    this.defaultMaxQueueSize = positiveInteger(options.maxQueueSize, 500, 10_000, "maxQueueSize");
    this.staleClaimMs = positiveInteger(options.staleClaimMs, 30_000, 3_600_000, "staleClaimMs");
    this.retryBaseDelayMs = positiveInteger(options.retryBaseDelayMs, 250, 60_000, "retryBaseDelayMs");
    this.retryMaxDelayMs = positiveInteger(options.retryMaxDelayMs, 30_000, 3_600_000, "retryMaxDelayMs");
    if (this.retryMaxDelayMs < this.retryBaseDelayMs) {
      throw new RangeError("retryMaxDelayMs cannot be less than retryBaseDelayMs");
    }
    this.retryJitterRatio = options.retryJitterRatio ?? 0.2;
    if (!Number.isFinite(this.retryJitterRatio) || this.retryJitterRatio < 0 || this.retryJitterRatio > 1) {
      throw new RangeError("retryJitterRatio must be between 0 and 1");
    }
    this.clock = options.clock ?? (() => new Date());
    this.random = options.random ?? Math.random;
    this.beforeBroadcast = options.beforeBroadcast;
  }

  get isStarted(): boolean {
    return this.started;
  }

  get subscriptionCount(): number {
    return this.clients.size;
  }

  start(): void {
    if (this.started) return;
    this.started = true;
    const now = this.clock();
    this.repository.releaseStaleClaims(
      new Date(now.getTime() - this.staleClaimMs).toISOString(),
      now.toISOString(),
    );
    this.pollTimer = setInterval(() => {
      void this.pumpOnce();
    }, this.pollIntervalMs);
    this.pollTimer.unref?.();
    void this.pumpOnce();
  }

  async stop(): Promise<void> {
    this.started = false;
    if (this.pollTimer) clearInterval(this.pollTimer);
    this.pollTimer = null;
    if (this.activePump) await this.activePump;
    for (const client of [...this.clients.values()]) {
      this.closeClient(client, "service_stopped");
    }
  }

  /** Resolve and verify a browser Last-Event-ID against a run boundary. */
  resolveRunSequence(runId: string, eventId: string): number {
    const event = this.repository.getById(eventId);
    if (!event) throw new Error(`Event not found: ${eventId}`);
    if (event.runId !== runId) throw new Error("Last-Event-ID belongs to a different run");
    return event.sequence;
  }

  eventExists(eventId: string): boolean {
    return this.repository.getById(eventId) !== null;
  }

  replayRun(
    runId: string,
    afterSequence = 0,
    limit = 250,
    sensitivity: EventSensitivity = "internal",
  ): OperationalEventEnvelope[] {
    return this.repository
      .listAfter(runId, afterSequence, limit)
      .map((event) => toOperationalEventEnvelope(event, sensitivity));
  }

  subscribe(options: EventStreamSubscriptionOptions): EventStreamSubscription {
    const runId = options.runId?.trim() || undefined;
    const afterSequence = nonNegativeInteger(options.afterSequence, 0, "afterSequence");
    if (!runId && afterSequence !== 0) {
      throw new Error("afterSequence requires a runId");
    }
    if (runId && options.afterEventId) {
      throw new Error("Use afterSequence or Last-Event-ID for a run stream, not afterEventId");
    }
    if (!runId && options.afterEventId && !this.eventExists(options.afterEventId)) {
      throw new Error(`Event not found: ${options.afterEventId}`);
    }

    let resolveReady = (): void => undefined;
    const readyPromise = new Promise<void>((resolve) => {
      resolveReady = resolve;
    });
    const id = randomUUID();
    const client: StreamClient = {
      id,
      runId,
      sensitivity: options.sensitivity ?? "internal",
      maxQueueSize: positiveInteger(
        options.maxQueueSize,
        this.defaultMaxQueueSize,
        10_000,
        "maxQueueSize",
      ),
      sink: options.sink,
      queue: [],
      readyPromise,
      resolveReady,
      cursorSequence: afterSequence,
      cursorEventId: options.afterEventId ?? null,
      catchingUp: Boolean(runId || options.afterEventId),
      catchUpScheduled: false,
      paused: false,
      closed: false,
      removeDrainListener: null,
    };
    this.clients.set(id, client);

    if (client.catchingUp) this.scheduleCatchUp(client);
    else client.resolveReady();

    const service = this;
    return {
      id,
      ready: readyPromise,
      get closed(): boolean {
        return client.closed;
      },
      get backpressured(): boolean {
        return client.paused;
      },
      get lastSequence(): number {
        return client.cursorSequence;
      },
      close(): void {
        service.closeClient(client);
      },
    };
  }

  pumpOnce(): Promise<OutboxPumpResult> {
    if (this.activePump) return this.activePump;
    const operation = this.runPump().finally(() => {
      if (this.activePump === operation) this.activePump = null;
    });
    this.activePump = operation;
    return operation;
  }

  private async runPump(): Promise<OutboxPumpResult> {
    const claimed = this.repository.claimOutbox(
      this.workerId,
      this.clock().toISOString(),
      this.outboxBatchSize,
    );
    let delivered = 0;
    let failed = 0;
    for (const record of claimed) {
      try {
        const event = this.repository.getById(record.eventId);
        if (!event) throw new Error(`Outbox references missing event: ${record.eventId}`);
        await this.beforeBroadcast?.(event);
        this.broadcast(event);
        if (!this.repository.markDelivered(record.id, this.clock().toISOString())) {
          throw new Error(`Outbox claim was lost before delivery: ${record.id}`);
        }
        delivered += 1;
      } catch (error) {
        const retryAt = new Date(this.clock().getTime() + this.retryDelay(record.attemptCount));
        this.repository.markFailed(
          record.id,
          error instanceof Error ? error.message : String(error),
          retryAt.toISOString(),
        );
        failed += 1;
      }
    }
    return { claimed: claimed.length, delivered, failed };
  }

  private retryDelay(attempt: number): number {
    const exponent = Math.max(0, Math.min(20, attempt - 1));
    const base = Math.min(this.retryMaxDelayMs, this.retryBaseDelayMs * 2 ** exponent);
    const jitter = base * this.retryJitterRatio * (this.random() * 2 - 1);
    return Math.max(0, Math.round(base + jitter));
  }

  private broadcast(event: RunEvent): void {
    for (const client of this.clients.values()) {
      if (client.closed || (client.runId && client.runId !== event.runId)) continue;
      if (client.catchingUp) {
        this.scheduleCatchUp(client);
        continue;
      }
      if (client.runId && event.sequence <= client.cursorSequence) continue;
      if (!client.runId && event.id === client.cursorEventId) continue;
      this.enqueue(client, toOperationalEventEnvelope(event, client.sensitivity));
    }
  }

  private scheduleCatchUp(client: StreamClient): void {
    if (client.closed || client.paused || client.catchUpScheduled) return;
    client.catchUpScheduled = true;
    queueMicrotask(() => {
      client.catchUpScheduled = false;
      this.catchUp(client);
    });
  }

  private catchUp(client: StreamClient): void {
    if (client.closed || client.paused || !client.catchingUp) return;
    try {
      const events = client.runId
        ? this.repository.listAfter(client.runId, client.cursorSequence, this.replayBatchSize)
        : this.repository.listGlobalAfter(client.cursorEventId, this.replayBatchSize);

      for (const event of events) {
        if (client.closed || client.paused) break;
        this.enqueue(client, toOperationalEventEnvelope(event, client.sensitivity));
      }
      if (client.closed || client.paused) return;
      if (events.length < this.replayBatchSize) {
        client.catchingUp = false;
        client.resolveReady();
        return;
      }
      this.scheduleCatchUp(client);
    } catch {
      this.closeClient(client, "transport_error");
    }
  }

  private enqueue(client: StreamClient, event: OperationalEventEnvelope): void {
    if (client.closed) return;
    if (client.runId && event.sequence <= client.cursorSequence) return;
    if (!client.runId && event.id === client.cursorEventId) return;
    if (client.queue.length >= client.maxQueueSize) {
      this.closeClient(client, "queue_overflow");
      return;
    }
    client.queue.push(event);
    this.flush(client);
  }

  private flush(client: StreamClient): void {
    if (client.closed || client.paused) return;
    while (client.queue.length > 0 && !client.paused && !client.closed) {
      const event = client.queue.shift()!;
      try {
        const writable = client.sink.write(event);
        client.cursorSequence = client.runId ? event.sequence : client.cursorSequence;
        client.cursorEventId = event.id;
        if (!writable) {
          client.paused = true;
          client.removeDrainListener = client.sink.onDrain(() => {
            client.removeDrainListener = null;
            client.paused = false;
            this.flush(client);
            if (client.catchingUp) this.scheduleCatchUp(client);
          });
        }
      } catch {
        this.closeClient(client, "transport_error");
      }
    }
    if (!client.paused && client.catchingUp) this.scheduleCatchUp(client);
  }

  private closeClient(
    client: StreamClient,
    reason?: "service_stopped" | "queue_overflow" | "transport_error",
  ): void {
    if (client.closed) return;
    client.closed = true;
    client.removeDrainListener?.();
    client.removeDrainListener = null;
    client.queue.length = 0;
    this.clients.delete(client.id);
    client.resolveReady();
    if (reason) {
      try {
        client.sink.close?.(reason);
      } catch {
        // The transport is already unusable; durable replay remains available.
      }
    }
  }
}

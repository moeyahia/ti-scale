export type Journey = "autonomous" | "guided";

export type EventActorType =
  | "operator"
  | "agent"
  | "worker"
  | "provider"
  | "tool"
  | "system";

export type EventSensitivity = "public" | "internal" | "private" | "restricted";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { readonly [key: string]: JsonValue };

export interface RunEvent {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly sequence: number;
  readonly eventType: string;
  readonly occurredAt: string;
  readonly actorType: EventActorType;
  readonly actorId: string | null;
  readonly summary: string;
  readonly payload: JsonValue;
  readonly schemaVersion: number;
  readonly journey: Journey;
  readonly traceId: string | null;
  readonly spanId: string | null;
  readonly sensitivity: EventSensitivity;
  readonly redaction: JsonValue;
  readonly contextPackId: string | null;
  readonly createdAt: string;
}

export interface AppendRunEventInput {
  readonly id?: string;
  readonly missionId?: string;
  readonly runId: string;
  readonly eventType: string;
  readonly occurredAt?: string;
  readonly actorType: EventActorType;
  readonly actorId?: string | null;
  readonly summary: string;
  readonly payload?: JsonValue;
  readonly schemaVersion?: number;
  readonly journey?: Journey;
  readonly traceId?: string | null;
  readonly spanId?: string | null;
  readonly sensitivity?: EventSensitivity;
  readonly redaction?: JsonValue;
  readonly contextPackId?: string | null;
  readonly outboxTopic?: string;
}

export interface OutboxRecord {
  readonly id: string;
  readonly eventId: string;
  readonly topic: string;
  readonly payload: JsonValue;
  readonly status: "pending" | "delivering" | "delivered" | "failed";
  readonly attemptCount: number;
  readonly availableAt: string;
  readonly claimedBy: string | null;
  readonly claimedAt: string | null;
  readonly deliveredAt: string | null;
  readonly lastError: string | null;
  readonly createdAt: string;
}

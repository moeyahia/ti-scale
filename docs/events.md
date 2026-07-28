# Event model

Ti-Scale uses durable events for operational state and Server-Sent Events for live delivery.

## Event envelope

Every delivered event contains:

```ts
interface OperationalEvent {
  id: string;
  sequence: number;
  type: string;
  timestamp: string;
  missionId: string;
  runId: string;
  journey: "autonomous" | "guided";
  summary: string;
  actor: { type: string; id: string | null };
  payload: unknown;
  schemaVersion: number;
  traceId: string | null;
  spanId: string | null;
  sensitivity: "public" | "internal" | "private" | "restricted";
  redaction: unknown;
  contextPackId: string | null;
}
```

Sequences are monotonic per run. Event IDs are stable and opaque. The schema version allows clients to reject unsupported payload changes explicitly.

## Subscribe

```http
GET /api/v2/events/stream
Accept: text/event-stream
```

Optional query parameters:

- `runId` — limit the stream to one run.
- `afterSequence` — resume after a per-run sequence; requires `runId`.
- `lastEventId` — query equivalent of the standard `Last-Event-ID` header.

The server sends an initial retry hint and heartbeat comments. Heartbeats confirm transport liveness; they are not mission progress.

## Replay and gap repair

```text
GET /api/v2/events/replay?runId=<run>&afterSequence=<n>&limit=<1..500>
GET /api/v2/events/gap?runId=<run>&afterSequence=<n>&limit=<1..500>
```

Both endpoints return bounded events, the next sequence, an opaque next cursor, and `hasMore`. A cursor is bound to one run and must not be reused with another run ID.

## Reconnect algorithm

1. Retain the latest applied event ID and per-run sequence.
2. Reconnect with exponential backoff and jitter.
3. Send `Last-Event-ID`, or `runId` plus `afterSequence`.
4. Deduplicate by event ID.
5. Reject or repair sequence gaps before applying later run events.
6. Reconcile the affected resource from the API after reconnect.
7. Show the operator whether the client is live, reconnecting, or using fallback reads.

Do not treat an SSE reconnect as a failed mission.

## Delivery semantics

The database event record is canonical. An outbox bridges durable changes to live fanout. Delivery is at-least-once at the transport boundary, so clients must deduplicate.

Temporary SQLite writer contention does not discard or claim an event and does not terminate the event-stream service. The outbox pump defers the claim with capped exponential backoff and jitter, avoids touching SQLite again during that cooldown, and resumes from the unchanged durable row when the writer lock clears. Non-contention database errors still fail visibly; they are not reclassified as routine load.

Subscriber queues are bounded. When a slow consumer exceeds the queue boundary, the server closes that subscriber instead of allowing unbounded memory growth. The client then replays from its last durable cursor.

## Redaction and sensitivity

The stream applies two safeguards:

- known secret-like keys are redacted recursively;
- events above the caller's permitted sensitivity are replaced with a redacted summary and payload.

Redaction metadata is part of the event envelope. A missing payload after sensitivity filtering is not evidence that the underlying action produced no result.

## Semantic event guidance

Event summaries should state what changed and why it matters. Exact commands, terminal output, provider payloads, and large technical objects belong in linked logs or artifacts, subject to sensitivity policy.

Tool output by itself is not meaningful progress. A progress event should correspond to a state transition, new attributable evidence, a resolved dependency, reduced uncertainty, a produced artifact, or an advanced success criterion.

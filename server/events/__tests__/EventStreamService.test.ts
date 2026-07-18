import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createServer, type Server } from "node:http";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import type { SqliteDatabase } from "../../db";
import { EventRepository } from "../EventRepository";
import {
  EventStreamService,
  type EventStreamSink,
  type OperationalEventEnvelope,
} from "../EventStreamService";
import {
  createEventStreamRouter,
  decodeSseEventId,
  encodeSseEventId,
} from "../EventStreamRouter";

const databases: SqliteDatabase[] = [];
const servers: Server[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  for (const database of databases.splice(0)) database.close();
});

function setup(): { database: SqliteDatabase; repository: EventRepository } {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  return { database, repository: new EventRepository(database) };
}

function seedRun(
  database: SqliteDatabase,
  runId: string,
  journey: "autonomous" | "guided" = "autonomous",
): void {
  const now = new Date().toISOString();
  const missionId = `mission:${runId}`;
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, created_by, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'operator', ?, ?)
  `).run(missionId, `Mission ${runId}`, "Collect authorized evidence", journey, now, now);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, created_at, updated_at
    ) VALUES (?, ?, ?, 'running', ?, ?)
  `).run(runId, missionId, journey, now, now);
}

function collectingSink(
  target: OperationalEventEnvelope[],
  options: { writable?: () => boolean; closed?: (reason: string) => void } = {},
): EventStreamSink {
  return {
    write(event) {
      target.push(event);
      return options.writable?.() ?? true;
    },
    onDrain() {
      return () => undefined;
    },
    close(reason) {
      options.closed?.(reason);
    },
  };
}

async function listen(app: express.Express): Promise<{ server: Server; origin: string }> {
  const server = createServer(app);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Server did not bind a TCP port");
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

async function waitUntil(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("Timed out waiting for condition");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe("EventStreamService", () => {
  test("replays a run after its acknowledged sequence in monotonic order", async () => {
    const { database, repository } = setup();
    seedRun(database, "run-a");
    for (let sequence = 1; sequence <= 4; sequence += 1) {
      repository.append({
        id: `event-${sequence}`,
        runId: "run-a",
        eventType: "test.progress",
        actorType: "worker",
        summary: `Progress ${sequence}`,
      });
    }

    const received: OperationalEventEnvelope[] = [];
    const service = new EventStreamService({ repository, replayBatchSize: 2 });
    const subscription = service.subscribe({
      runId: "run-a",
      afterSequence: 1,
      sink: collectingSink(received),
    });
    await subscription.ready;

    expect(received.map((event) => event.sequence)).toEqual([2, 3, 4]);
    expect(received.map((event) => event.type)).toEqual([
      "test.progress",
      "test.progress",
      "test.progress",
    ]);
    expect(received[0]?.timestamp).toBeString();
    subscription.close();
  });

  test("delivers live outbox events in order and isolates run-scoped subscribers", async () => {
    const { database, repository } = setup();
    seedRun(database, "run-a");
    seedRun(database, "run-b", "guided");
    const received: OperationalEventEnvelope[] = [];
    const service = new EventStreamService({ repository });
    const subscription = service.subscribe({
      runId: "run-a",
      sink: collectingSink(received),
    });
    await subscription.ready;

    repository.append({
      id: "a-1",
      runId: "run-a",
      eventType: "run.progressed",
      actorType: "agent",
      summary: "Run A advanced",
    });
    repository.append({
      id: "b-1",
      runId: "run-b",
      eventType: "guided.explained",
      actorType: "agent",
      summary: "Run B explained its step",
    });
    repository.append({
      id: "a-2",
      runId: "run-a",
      eventType: "evidence.added",
      actorType: "agent",
      summary: "Run A added evidence",
    });

    expect(await service.pumpOnce()).toEqual({ claimed: 3, delivered: 3, failed: 0 });
    expect(received.map((event) => event.id)).toEqual(["a-1", "a-2"]);
    expect(received.map((event) => event.sequence)).toEqual([1, 2]);
    subscription.close();
  });

  test("resumes the global overview stream after a stable event ID across runs", async () => {
    const { database, repository } = setup();
    seedRun(database, "run-a");
    seedRun(database, "run-b", "guided");
    repository.append({
      id: "global-1",
      runId: "run-a",
      eventType: "run.started",
      actorType: "system",
      summary: "Run A started",
    });
    repository.append({
      id: "global-2",
      runId: "run-b",
      eventType: "guided.waiting",
      actorType: "system",
      summary: "Run B awaits one decision",
    });
    repository.append({
      id: "global-3",
      runId: "run-a",
      eventType: "evidence.added",
      actorType: "agent",
      summary: "Run A added evidence",
    });
    const received: OperationalEventEnvelope[] = [];
    const service = new EventStreamService({ repository, replayBatchSize: 1 });
    const subscription = service.subscribe({
      afterEventId: "global-1",
      sink: collectingSink(received),
    });
    await subscription.ready;

    expect(received.map((event) => event.id)).toEqual(["global-2", "global-3"]);
    subscription.close();
  });

  test("bounds backpressured client queues and removes disconnected clients", async () => {
    const { database, repository } = setup();
    seedRun(database, "run-a");
    const received: OperationalEventEnvelope[] = [];
    let closeReason = "";
    const service = new EventStreamService({ repository, maxQueueSize: 2 });
    const subscription = service.subscribe({
      runId: "run-a",
      sink: collectingSink(received, {
        writable: () => false,
        closed: (reason) => {
          closeReason = reason;
        },
      }),
    });
    await subscription.ready;
    for (let index = 1; index <= 4; index += 1) {
      repository.append({
        id: `event-${index}`,
        runId: "run-a",
        eventType: "test.backpressure",
        actorType: "system",
        summary: `Backpressure event ${index}`,
      });
    }
    await service.pumpOnce();

    expect(received).toHaveLength(1);
    expect(subscription.closed).toBe(true);
    expect(closeReason).toBe("queue_overflow");
    expect(service.subscriptionCount).toBe(0);
  });

  test("retains a failed delivery in the durable outbox with retry backoff", async () => {
    const { database, repository } = setup();
    seedRun(database, "run-a");
    repository.append({
      id: "event-failed",
      runId: "run-a",
      eventType: "provider.failed",
      actorType: "provider",
      summary: "Provider delivery failed",
    });
    const now = new Date(Date.now() + 1_000);
    const service = new EventStreamService({
      repository,
      clock: () => now,
      retryBaseDelayMs: 250,
      retryMaxDelayMs: 1_000,
      retryJitterRatio: 0,
      beforeBroadcast: () => {
        throw new Error("temporary publisher outage");
      },
    });

    expect(await service.pumpOnce()).toEqual({ claimed: 1, delivered: 0, failed: 1 });
    const row = database.prepare(`
      SELECT status, attempt_count, available_at, last_error
      FROM event_outbox WHERE event_id = ?
    `).get("event-failed") as {
      status: string;
      attempt_count: number;
      available_at: string;
      last_error: string;
    };
    expect(row.status).toBe("failed");
    expect(row.attempt_count).toBe(1);
    expect(row.last_error).toContain("temporary publisher outage");
    expect(Date.parse(row.available_at)).toBe(now.getTime() + 250);
  });

  test("recovers stale outbox claims and supports graceful start/stop", async () => {
    const { database, repository } = setup();
    seedRun(database, "run-a");
    repository.append({
      id: "event-stale",
      runId: "run-a",
      eventType: "worker.recovered",
      actorType: "worker",
      summary: "Recovered after publisher restart",
    });
    const staleAt = new Date(Date.now() - 60_000).toISOString();
    expect(repository.claimOutbox("crashed-publisher", new Date().toISOString(), 1)).toHaveLength(1);
    database.prepare(
      "UPDATE event_outbox SET claimed_at = ? WHERE event_id = ?",
    ).run(staleAt, "event-stale");

    const service = new EventStreamService({
      repository,
      pollIntervalMs: 10,
      staleClaimMs: 1_000,
    });
    service.start();
    await waitUntil(() => {
      const row = database.prepare(
        "SELECT status FROM event_outbox WHERE event_id = ?",
      ).get("event-stale") as { status: string };
      return row.status === "delivered";
    });
    expect(service.isStarted).toBe(true);
    await service.stop();
    expect(service.isStarted).toBe(false);
  });

  test("redacts configured and secret fields before transport", async () => {
    const { database, repository } = setup();
    seedRun(database, "run-a");
    repository.append({
      id: "private-event",
      runId: "run-a",
      eventType: "tool.completed",
      actorType: "tool",
      actorId: "tool-1",
      summary: "Private tool result",
      sensitivity: "private",
      payload: {
        result: { host: "allowed", password: "must-not-stream" },
        exact: "remove-me",
      },
      redaction: { paths: ["exact"] },
    });
    const service = new EventStreamService({ repository });

    const internal = service.replayRun("run-a", 0, 10, "internal")[0]!;
    expect(internal.summary).toBe("Sensitive event details redacted");
    expect(internal.payload).toEqual({ redacted: true, reason: "sensitivity_policy" });

    const privateView = service.replayRun("run-a", 0, 10, "private")[0]!;
    expect(privateView.payload).toEqual({
      result: { host: "allowed", password: "[REDACTED]" },
      exact: "[REDACTED]",
    });
  });
});

describe("EventStreamRouter", () => {
  test("rejects protocol-control bytes in legacy and encoded Last-Event-ID values", () => {
    expect(decodeSseEventId("legacy-safe-id")).toBe("legacy-safe-id");
    expect(() => decodeSseEventId("legacy\u0000injected")).toThrow("Last-Event-ID is invalid");
    expect(() => decodeSseEventId(`v2.${Buffer.from("encoded\r\ninjected", "utf8").toString("base64url")}`))
      .toThrow("Last-Event-ID is invalid");
  });

  test("resumes SSE from Last-Event-ID and maps eventType/occurredAt to type/timestamp", async () => {
    const { database, repository } = setup();
    seedRun(database, "run-a");
    const first = repository.append({
      id: "event-1",
      runId: "run-a",
      eventType: "run.started",
      actorType: "system",
      summary: "Run started",
    });
    const second = repository.append({
      id: "event-2",
      runId: "run-a",
      eventType: "evidence.added",
      actorType: "agent",
      summary: "Evidence added",
    });
    const service = new EventStreamService({ repository });
    const app = express();
    app.use(createEventStreamRouter({ service, heartbeatIntervalMs: 50 }));
    const { origin } = await listen(app);
    const controller = new AbortController();
    const response = await fetch(`${origin}/api/v2/events/stream?runId=run-a`, {
      headers: { "Last-Event-ID": encodeSseEventId(first.id) },
      signal: controller.signal,
    });
    expect(response.status).toBe(200);
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let body = "";
    while (!body.includes(`\"id\":\"${second.id}\"`)) {
      const chunk = await reader.read();
      if (chunk.done) break;
      body += decoder.decode(chunk.value, { stream: true });
    }
    controller.abort();
    await waitUntil(() => service.subscriptionCount === 0);

    expect(body).not.toContain(`\"id\":\"${first.id}\"`);
    expect(body).toContain(`\"type\":\"evidence.added\"`);
    expect(body).toContain(`\"timestamp\":\"${second.occurredAt}\"`);
  });

  test("replay/gap endpoint returns an opaque cursor without crossing runs", async () => {
    const { database, repository } = setup();
    seedRun(database, "run-a");
    seedRun(database, "run-b");
    for (let index = 1; index <= 3; index += 1) {
      repository.append({
        id: `a-${index}`,
        runId: "run-a",
        eventType: "test.a",
        actorType: "system",
        summary: `A ${index}`,
      });
    }
    repository.append({
      id: "b-1",
      runId: "run-b",
      eventType: "test.b",
      actorType: "system",
      summary: "B 1",
    });
    const service = new EventStreamService({ repository });
    const app = express();
    app.use(createEventStreamRouter({ service }));
    const { origin } = await listen(app);

    const firstResponse = await fetch(`${origin}/api/v2/events/gap?runId=run-a&limit=2`);
    const firstPage = await firstResponse.json() as {
      events: OperationalEventEnvelope[];
      nextCursor: string;
      hasMore: boolean;
    };
    expect(firstPage.events.map((event) => event.id)).toEqual(["a-1", "a-2"]);
    expect(firstPage.hasMore).toBe(true);

    const secondResponse = await fetch(
      `${origin}/api/v2/events/replay?cursor=${encodeURIComponent(firstPage.nextCursor)}`,
    );
    const secondPage = await secondResponse.json() as {
      events: OperationalEventEnvelope[];
      hasMore: boolean;
    };
    expect(secondPage.events.map((event) => event.id)).toEqual(["a-3"]);
    expect(secondPage.hasMore).toBe(false);
  });

  test("emits heartbeats and cleans up the subscription on disconnect", async () => {
    const { repository } = setup();
    const service = new EventStreamService({ repository });
    const app = express();
    app.use(createEventStreamRouter({ service, heartbeatIntervalMs: 15 }));
    const { origin } = await listen(app);
    const controller = new AbortController();
    const response = await fetch(`${origin}/api/v2/events/stream`, {
      signal: controller.signal,
    });
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let body = "";
    while (!body.includes(": heartbeat ")) {
      const chunk = await reader.read();
      if (chunk.done) break;
      body += decoder.decode(chunk.value, { stream: true });
    }
    expect(body).toContain(": heartbeat ");
    expect(service.subscriptionCount).toBe(1);
    controller.abort();
    await waitUntil(() => service.subscriptionCount === 0);
  });
});

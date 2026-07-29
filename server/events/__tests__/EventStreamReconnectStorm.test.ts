import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { EventRepository } from "../EventRepository";
import {
  EventStreamService,
  type OperationalEventEnvelope,
} from "../EventStreamService";

describe("EventStreamService reconnect storm", () => {
  test("replays bounded concurrent reconnects without gaps, duplicates, or retained clients", async () => {
    const database = createDatabaseConnection({ filename: ":memory:", verifyIntegrity: false });
    try {
      migrateDatabase(database);
      const now = "2026-07-15T00:00:00.000Z";
      database.prepare(`
        INSERT INTO missions (id, name, objective, journey, created_by, created_at, updated_at)
        VALUES ('mission-reconnect', 'Reconnect fixture', 'Verify event replay',
          'autonomous', 'test', ?, ?)
      `).run(now, now);
      database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES ('run-reconnect', 'mission-reconnect', 'autonomous', 'running', ?, ?)
      `).run(now, now);
      const repository = new EventRepository(database);
      for (let sequence = 1; sequence <= 500; sequence += 1) {
        repository.append({
          id: `reconnect-event-${sequence}`,
          runId: "run-reconnect",
          eventType: "benchmark.progress",
          actorType: "system",
          summary: `Progress ${sequence}`,
        });
      }

      const service = new EventStreamService({
        repository,
        replayBatchSize: 37,
        maxQueueSize: 600,
      });
      const reconnects = Array.from({ length: 64 }, (_, index) => {
        const afterSequence = (index * 7) % 450;
        const received: OperationalEventEnvelope[] = [];
        const subscription = service.subscribe({
          runId: "run-reconnect",
          afterSequence,
          sink: {
            write(event) {
              received.push(event);
              return true;
            },
            onDrain() {
              return () => undefined;
            },
          },
        });
        return { afterSequence, received, subscription };
      });

      await Promise.all(reconnects.map(({ subscription }) => subscription.ready));
      expect(service.subscriptionCount).toBe(64);
      for (const reconnect of reconnects) {
        const expected = Array.from(
          { length: 500 - reconnect.afterSequence },
          (_, index) => reconnect.afterSequence + index + 1,
        );
        const sequences = reconnect.received.map((event) => event.sequence);
        expect(sequences).toEqual(expected);
        expect(new Set(sequences).size).toBe(sequences.length);
        expect(reconnect.subscription.lastSequence).toBe(500);
        reconnect.subscription.close();
      }
      expect(service.subscriptionCount).toBe(0);
    } finally {
      database.close();
    }
  }, 10_000);
});

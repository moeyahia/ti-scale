import { describe, expect, test } from "bun:test";
import { performance } from "node:perf_hooks";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import type { OperationsAccessPolicy } from "../../operations/types";
import { TraceRepository } from "../TraceRepository";

const access: OperationsAccessPolicy = {
  maximumSensitivity: "internal",
  engagementIds: ["eng-scale"],
  missionIds: ["mission-scale"],
  allowUnscopedSystemData: false,
};

describe("trace scale projection", () => {
  test("keeps 100,000-event trace retrieval cursor-bounded", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const startedAt = "2026-07-15T00:00:00.000Z";
      database.prepare(`
        INSERT INTO missions (id, name, objective, journey, engagement_id, created_by, created_at, updated_at)
        VALUES ('mission-scale', 'Scale mission', 'Prove bounded trace access', 'autonomous', 'eng-scale', 'operator', ?, ?)
      `).run(startedAt, startedAt);
      database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, progress, created_at, updated_at)
        VALUES ('run-scale', 'mission-scale', 'autonomous', 'running', 0.5, ?, ?)
      `).run(startedAt, startedAt);
      const insert = database.prepare(`
        INSERT INTO events (
          id, mission_id, run_id, sequence, event_type, occurred_at, actor_type,
          summary, payload_json, journey, trace_id, sensitivity, created_at
        ) VALUES (?, 'mission-scale', 'run-scale', ?, 'scale.progress', ?, 'worker',
          'Meaningful scale progress', '{}', 'autonomous', 'trace-scale-100k', 'internal', ?)
      `);
      database.transaction(() => {
        const base = Date.parse(startedAt);
        for (let index = 1; index <= 100_000; index += 1) {
          const occurredAt = new Date(base + index).toISOString();
          insert.run(`event-scale-${String(index).padStart(6, "0")}`, index, occurredAt, occurredAt);
        }
      })();

      const repository = new TraceRepository(database);
      const firstStarted = performance.now();
      const first = repository.getTrace("trace-scale-100k", access, { limit: 50 });
      const firstElapsedMs = performance.now() - firstStarted;
      expect(first.trace.counts.events).toBe(100_000);
      expect(first.records.items).toHaveLength(50);
      expect(first.records.nextCursor).toEqual(expect.any(String));
      expect(JSON.stringify(first).length).toBeLessThan(100_000);

      const secondStarted = performance.now();
      const second = repository.getTrace("trace-scale-100k", access, { limit: 50, cursor: first.records.nextCursor! });
      const secondElapsedMs = performance.now() - secondStarted;
      expect(second.records.items).toHaveLength(50);
      expect(new Set([...first.records.items, ...second.records.items].map((item) => item.id)).size).toBe(100);
      // Wide enough for shared CI while still catching an accidental unbounded response/materialization path.
      expect(firstElapsedMs).toBeLessThan(2_000);
      expect(secondElapsedMs).toBeLessThan(2_000);
      console.info(`[observability-scale] 100000 events: first=${firstElapsedMs.toFixed(1)}ms second=${secondElapsedMs.toFixed(1)}ms response=${JSON.stringify(first).length}B`);
    } finally {
      database.close();
    }
  }, 20_000);
});

import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { EventRepository } from "../EventRepository";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-events-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function seedRun(
  database: ReturnType<typeof createDatabaseConnection>,
  missionId = "mission-1",
  runId = "run-1",
): void {
  const now = new Date().toISOString();
  database
    .prepare(`
      INSERT INTO missions (
        id, name, objective, journey, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, 'autonomous', 'operator', ?, ?)
    `)
    .run(missionId, "Authorized mission", "Collect evidence", now, now);
  database
    .prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, created_at, updated_at
      ) VALUES (?, ?, 'autonomous', 'running', ?, ?)
    `)
    .run(runId, missionId, now, now);
}

describe("EventRepository", () => {
  test("allocates monotonic per-run sequences and writes a durable outbox atomically", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      seedRun(database);
      const repository = new EventRepository(database);

      const first = repository.append({
        id: "event-1",
        runId: "run-1",
        eventType: "run.started",
        actorType: "system",
        summary: "Autonomous execution started",
        payload: { phase: "recon" },
      });
      const second = repository.append({
        id: "event-2",
        runId: "run-1",
        eventType: "evidence.added",
        actorType: "agent",
        actorId: "reconscout",
        summary: "Recon specialist added unique service evidence",
        payload: { evidenceDelta: 1 },
      });

      expect(first.sequence).toBe(1);
      expect(second.sequence).toBe(2);
      expect(repository.listAfter("run-1", 1).map((event) => event.id)).toEqual([
        "event-2",
      ]);

      const claimed = repository.claimOutbox("publisher-1");
      expect(claimed).toHaveLength(2);
      expect(claimed[0]?.attemptCount).toBe(1);
      expect(claimed[0]?.payload).toMatchObject({
        runId: "run-1",
        sequence: 1,
        journey: "autonomous",
      });
      expect(repository.markDelivered(claimed[0]!.id)).toBe(true);
      expect(
        repository.markFailed(
          claimed[1]!.id,
          "temporary stream outage",
          new Date(Date.now() + 1_000).toISOString(),
        ),
      ).toBe(true);
    } finally {
      database.close();
    }
  });

  test("rolls back the event and sequence when the outbox write fails", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      seedRun(database);
      const repository = new EventRepository(database);
      database.exec(`
        CREATE TRIGGER reject_test_outbox
        BEFORE INSERT ON event_outbox BEGIN
          SELECT RAISE(ABORT, 'test outbox failure');
        END;
      `);

      expect(() =>
        repository.append({
          runId: "run-1",
          eventType: "test.failed",
          actorType: "system",
          summary: "This transaction must roll back",
        }),
      ).toThrow("test outbox failure");
      expect(
        (database.prepare("SELECT COUNT(*) AS count FROM events").get() as { count: number })
          .count,
      ).toBe(0);
      expect(
        (
          database
            .prepare("SELECT COUNT(*) AS count FROM run_event_sequences")
            .get() as { count: number }
        ).count,
      ).toBe(0);

      database.exec("DROP TRIGGER reject_test_outbox");
      const persisted = repository.append({
        runId: "run-1",
        eventType: "test.recovered",
        actorType: "system",
        summary: "Outbox recovered",
      });
      expect(persisted.sequence).toBe(1);
    } finally {
      database.close();
    }
  });

  test("coordinates sequences across independent WAL connections", () => {
    const path = join(temporaryDirectory(), "events.sqlite");
    const firstDatabase = createDatabaseConnection({ filename: path });
    migrateDatabase(firstDatabase);
    seedRun(firstDatabase);
    const secondDatabase = createDatabaseConnection({
      filename: path,
      fileMustExist: true,
    });
    try {
      const firstRepository = new EventRepository(firstDatabase);
      const secondRepository = new EventRepository(secondDatabase);
      const sequences: number[] = [];
      for (let index = 0; index < 20; index += 1) {
        const repository = index % 2 === 0 ? firstRepository : secondRepository;
        sequences.push(
          repository.append({
            id: `event-${index}`,
            runId: "run-1",
            eventType: "test.sequence",
            actorType: "worker",
            actorId: `worker-${index % 2}`,
            summary: `Allocated sequence ${index + 1}`,
          }).sequence,
        );
      }
      expect(sequences).toEqual(Array.from({ length: 20 }, (_, index) => index + 1));
    } finally {
      secondDatabase.close();
      firstDatabase.close();
    }
  });

  test("rejects mission and journey mismatches before persisting", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      seedRun(database);
      const repository = new EventRepository(database);
      expect(() =>
        repository.append({
          runId: "run-1",
          missionId: "another-mission",
          eventType: "invalid.mission",
          actorType: "system",
          summary: "Invalid mission",
        }),
      ).toThrow("does not match");
      expect(() =>
        repository.append({
          runId: "run-1",
          journey: "guided",
          eventType: "invalid.journey",
          actorType: "system",
          summary: "Invalid journey",
        }),
      ).toThrow("does not match");
    } finally {
      database.close();
    }
  });
});

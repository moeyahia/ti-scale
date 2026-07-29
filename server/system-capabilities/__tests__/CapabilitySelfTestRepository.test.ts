import { describe, expect, test } from "bun:test";
import { MemoryRepository, SecondBrainService } from "../../memory";
import { EventRepository, EventStreamService } from "../../events";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { CapabilitySelfTestRepository } from "../CapabilitySelfTestRepository";

interface ChangeCountRow {
  readonly count: number;
}

function changeCount(database: ReturnType<typeof createDatabaseConnection>): number {
  return (database.prepare("SELECT total_changes() AS count").get() as ChangeCountRow).count;
}

describe("CapabilitySelfTestRepository", () => {
  test("reads canonical local health without persisting a self-test result", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const eventStream = new EventStreamService({ repository: new EventRepository(database) });
      const secondBrain = new SecondBrainService(new MemoryRepository(database));
      const repository = new CapabilitySelfTestRepository({
        database,
        eventStream,
        secondBrain,
        clock: () => new Date("2026-07-18T20:00:00.000Z"),
      });
      const before = changeCount(database);
      const snapshot = repository.read();
      const after = changeCount(database);

      expect(snapshot.checkedAt).toBe("2026-07-18T20:00:00.000Z");
      expect(snapshot.database.healthy).toBe(true);
      expect(snapshot.eventStream).toEqual({ started: false, subscribers: 0 });
      expect(snapshot.secondBrain).toMatchObject({
        health: "healthy",
        canonicalStoreAvailable: true,
        vaultProjection: {
          status: "not_configured",
          configuredConnections: 0,
        },
      });
      expect(after).toBe(before);
    } finally {
      database.close();
    }
  });
});

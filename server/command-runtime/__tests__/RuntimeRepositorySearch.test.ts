import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { RuntimeRepository } from "../RuntimeRepository";

function seed(database: ReturnType<typeof createDatabaseConnection>): void {
  const now = "2026-07-15T00:00:00.000Z";
  for (const fixture of [
    { missionId: "mission-alpha", runId: "run-alpha", name: "Credential audit", objective: "Validate the authorized identity", journey: "guided", owner: "CredSmith" },
    { missionId: "mission-beta", runId: "run-beta", name: "Network inventory", objective: "Map approved services", journey: "autonomous", owner: "ReconScout" },
  ] as const) {
    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, status, authorization_status,
        success_criteria_json, memory_policy_json, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'active', 'verified', '[]', '{}', 'operator', ?, ?)
    `).run(fixture.missionId, fixture.name, fixture.objective, fixture.journey, now, now);
    database.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, progress, budget_json, budget_usage_json,
        status_reason, next_action_summary, current_owner_id, started_at,
        created_at, updated_at, version
      ) VALUES (?, ?, ?, 'running', 0.25, '{}', '{}', 'Fixture run',
        'Collect unique evidence', ?, ?, ?, ?, 1)
    `).run(fixture.runId, fixture.missionId, fixture.journey, fixture.owner, now, now, now);
  }
}

describe("RuntimeRepository command search", () => {
  test("returns bounded real run projections using mission, objective, owner, and journey filters", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      seed(database);
      const repository = new RuntimeRepository(database);
      expect(repository.listRunProjections({ query: "credential", limit: 10 }).map((run) => run.id)).toEqual(["run-alpha"]);
      expect(repository.listRunProjections({ query: "ReconScout", limit: 10 }).map((run) => run.id)).toEqual(["run-beta"]);
      expect(repository.listRunProjections({ journey: "guided", limit: 10 })).toHaveLength(1);
      expect(repository.listRunProjections({ status: "completed", limit: 10 })).toEqual([]);
      expect(() => repository.listRunProjections({ limit: 101 })).toThrow("between 1 and 100");
    } finally {
      database.close();
    }
  });
});

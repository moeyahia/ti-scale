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

  test("applies journey and operational-state predicates before the bounded page", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      seed(database);
      database.prepare("UPDATE runs SET updated_at = '2026-07-14T00:00:00.000Z' WHERE id = 'run-beta'")
        .run();
      for (let index = 0; index < 24; index += 1) {
        const suffix = String(index).padStart(2, "0");
        const missionId = `mission-newer-guided-${suffix}`;
        const runId = `run-newer-guided-${suffix}`;
        const updatedAt = `2026-07-16T00:${suffix}:00.000Z`;
        database.prepare(`
          INSERT INTO missions (
            id, name, objective, journey, status, authorization_status,
            success_criteria_json, memory_policy_json, created_by, created_at, updated_at
          ) VALUES (?, ?, 'Exercise the newer Guided projection', 'guided', 'active',
            'verified', '[]', '{}', 'operator', ?, ?)
        `).run(missionId, `Newer Guided ${suffix}`, updatedAt, updatedAt);
        database.prepare(`
          INSERT INTO runs (
            id, mission_id, journey, status, progress, budget_json, budget_usage_json,
            status_reason, next_action_summary, current_owner_id, started_at,
            created_at, updated_at, version
          ) VALUES (?, ?, 'guided', 'running', 0.25, '{}', '{}', 'Fixture run',
            'Collect unique evidence', 'GuidedCommander', ?, ?, ?, 1)
        `).run(runId, missionId, updatedAt, updatedAt, updatedAt);
      }

      const repository = new RuntimeRepository(database);
      expect(repository.listRunProjectionPage({
        journey: "autonomous",
        statuses: ["queued", "planning", "awaiting_contract_confirmation", "running", "blocked", "recovering"],
        limit: 1,
      })).toEqual({
        items: [expect.objectContaining({ id: "run-beta", journey: "autonomous", status: "running" })],
        nextCursor: null,
      });

      database.prepare("UPDATE runs SET status = 'completed' WHERE id = 'run-beta'").run();
      expect(repository.listRunProjectionPage({
        journey: "autonomous",
        statuses: ["queued", "planning", "awaiting_contract_confirmation", "running", "blocked", "recovering"],
        limit: 1,
      })).toEqual({ items: [], nextCursor: null });
      expect(repository.listRunProjectionPage({
        journey: "autonomous",
        status: "completed",
        limit: 1,
      }).items.map((run) => run.id)).toEqual(["run-beta"]);
    } finally {
      database.close();
    }
  });
});

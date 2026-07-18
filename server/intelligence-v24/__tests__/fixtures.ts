import type { SqliteDatabase } from "../../db";
import { createDatabaseConnection, migrateDatabase } from "../../db";

export const NOW = "2026-07-16T10:00:00.000Z";

export function testDatabase(): SqliteDatabase {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  seedScope(database, "mission-one", "run-one", "guided", "engagement-one");
  seedScope(database, "mission-two", "run-two", "autonomous", "engagement-two");
  return database;
}

function seedScope(
  database: SqliteDatabase,
  missionId: string,
  runId: string,
  journey: "autonomous" | "guided",
  engagementId: string,
): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      engagement_id, created_by, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'active', 'verified', ?, 'operator', ?, ?)
  `).run(missionId, `${missionId} name`, `Authorized objective for ${missionId}`, journey, engagementId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, created_at, updated_at
    ) VALUES (?, ?, ?, 'running', 0.2, ?, ?)
  `).run(runId, missionId, journey, NOW, NOW);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Bounded evidence plan', ?, 'planner', ?, ?)
  `).run(`plan-${runId}`, runId, "a".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'reconnaissance', 'Observe service', 'Collect attributable output', 'running', ?, ?)
  `).run(`step-${runId}`, `plan-${runId}`, runId, NOW, NOW);
}

export function seedAgent(database: SqliteDatabase, id = "ReconScout"): void {
  database.prepare(`
    INSERT INTO agents (id, role, display_name, status, version, created_at, updated_at)
    VALUES (?, 'reconnaissance', ?, 'available', '1', ?, ?)
  `).run(id, id, NOW, NOW);
}

export function seedFinding(database: SqliteDatabase, id: string, missionId = "mission-one", runId = "run-one"): void {
  database.prepare(`
    INSERT INTO findings (
      id, mission_id, run_id, title, severity, confidence, affected_scope,
      description, impact, remediation, review_status, version, created_at, updated_at
    ) VALUES (?, ?, ?, 'Exposed service', 'medium', 0.8, 'authorized target',
      'A service exposure requires evidence.', 'Potential unauthorized access.',
      'Restrict service access.', 'under_review', 1, ?, ?)
  `).run(id, missionId, runId, NOW, NOW);
}

export function deterministicOptions() {
  let sequence = 0;
  return {
    clock: () => new Date(NOW),
    idFactory: (prefix: string) => `${prefix}_${String(++sequence).padStart(4, "0")}`,
  };
}

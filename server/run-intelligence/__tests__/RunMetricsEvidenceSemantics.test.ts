import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { RunMetricsService } from "../RunMetricsService";

describe("RunMetricsService evidence semantics", () => {
  test("successful tool output does not change mission evidence counts or time-to-evidence", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const started = "2026-07-18T07:55:00.000Z";
      const ended = "2026-07-18T08:00:00.000Z";
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          success_criteria_json, memory_policy_json, created_by, created_at, updated_at
        ) VALUES ('mission-metrics', 'Metric semantics', 'Measure canonical evidence',
          'autonomous', 'completed', 'verified', '[]', '{}', 'operator', ?, ?)
      `).run(started, ended);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, budget_json, budget_usage_json,
          started_at, ended_at, created_at, updated_at, version
        ) VALUES ('run-metrics', 'mission-metrics', 'autonomous', 'completed', '{}', '{}',
          ?, ?, ?, ?, 1)
      `).run(started, ended, started, ended);
      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity,
          verification_state, summary, created_by, created_at
        ) VALUES ('raw-success', 'mission-metrics', 'run-metrics', 'mcp:scanner.run',
          '2026-07-18T07:56:00.000Z', '127.0.0.1', 'command_output', ?,
          '{"processSucceeded":true}', 0.95, 'private', 'verified',
          'The scanner process succeeded', 'runtime', '2026-07-18T07:56:00.000Z')
      `).run("a".repeat(64));

      const snapshot = new RunMetricsService(database, () => new Date(ended)).compute("run-metrics");
      const metric = (key: string) => snapshot.metrics.find((item) => item.key === key);
      expect(snapshot.sourceCounts.evidence).toBe(0);
      expect(metric("verified_evidence")?.value).toBe(0);
      expect(metric("time_to_first_evidence_ms")).toMatchObject({
        value: null,
        measurement: "not_observed",
      });
    } finally {
      database.close();
    }
  });
});

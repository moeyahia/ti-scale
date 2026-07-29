import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { evidenceRecordSql, verifiedEvidenceSql } from "../evidence-semantics";

describe("canonical evidence semantics", () => {
  test("excludes raw and unreviewed MCP output while preserving reviewed and direct evidence", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const now = "2026-07-18T08:00:00.000Z";
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          success_criteria_json, memory_policy_json, created_by, created_at, updated_at
        ) VALUES ('mission-evidence', 'Evidence semantics', 'Prove the evidence boundary',
          'autonomous', 'active', 'verified', '[]', '{}', 'operator', ?, ?)
      `).run(now, now);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, budget_json, budget_usage_json,
          created_at, updated_at, version
        ) VALUES ('run-evidence', 'mission-evidence', 'autonomous', 'running', '{}', '{}', ?, ?, 1)
      `).run(now, now);
      const insert = database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity,
          verification_state, summary, created_by, created_at
        ) VALUES (?, 'mission-evidence', 'run-evidence', ?, ?, '127.0.0.1', ?, ?, '{}',
          1, 'private', 'verified', ?, 'fixture', ?)
      `);
      insert.run("evidence-command", "mcp:scanner.run", now, "command_output", "a".repeat(64), "Raw stdout", now);
      insert.run("evidence-legacy-tool", "mcp:scanner.run", now, "tool_result", "b".repeat(64), "Successful process output", now);
      insert.run("evidence-direct", "operator-upload", now, "http_response", "c".repeat(64), "Direct verified evidence", now);
      insert.run("evidence-reviewed-tool", "mcp:scanner.run", now, "tool_result", "d".repeat(64), "Independently reviewed tool evidence", now);
      database.prepare(`
        INSERT INTO evidence_chain_events (id, evidence_id, event_type, actor, details_json, occurred_at)
        VALUES ('chain-reviewed', 'evidence-reviewed-tool', 'verified', 'reviewer', '{}', ?)
      `).run(now);

      expect(database.prepare(`
        SELECT id FROM evidence WHERE ${evidenceRecordSql("evidence")} ORDER BY id
      `).all()).toEqual([
        { id: "evidence-direct" },
        { id: "evidence-reviewed-tool" },
      ]);
      expect(database.prepare(`
        SELECT id FROM evidence WHERE ${verifiedEvidenceSql("evidence")} ORDER BY id
      `).all()).toEqual([
        { id: "evidence-direct" },
        { id: "evidence-reviewed-tool" },
      ]);
      expect(() => verifiedEvidenceSql("evidence; DROP TABLE evidence"))
        .toThrow("Invalid evidence SQL alias");
    } finally {
      database.close();
    }
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { AttackKnowledgeCompiler } from "../AttackKnowledgeCompiler";
import {
  historicalHangKnowledgeInputs,
  historicalHangReconciliation,
} from "../fixtures/HistoricalHangKnowledgeFixtures";

const HMAC_KEY = "historical-hang-fixture-hmac-key-32-bytes-minimum";
const databases: SqliteDatabase[] = [];
const directories: string[] = [];

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function setup() {
  const directory = mkdtempSync(join(tmpdir(), "historical-hang-fixture-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  databases.push(database);
  migrateDatabase(database);
  return {
    database,
    compiler: new AttackKnowledgeCompiler(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date("2026-07-20T16:00:00.000Z"),
    }),
  };
}

describe("sanitized historical hang knowledge", () => {
  test("dry-run is deterministic and preserves only opaque provenance receipts", () => {
    const { compiler } = setup();

    for (const input of historicalHangKnowledgeInputs) {
      const first = compiler.compile(input, { dryRun: true });
      const second = compiler.compile(input, { dryRun: true });

      expect(first).toEqual(second);
      expect(first.status).toBe("dry_run");
      expect(first.provenanceReceiptId).toMatch(/^akpr_[a-f0-9]{64}$/u);
      expect(first.bundleId).toMatch(/^akb_[a-f0-9]{64}$/u);
      expect(first.candidateIds).toEqual([]);
      expect(first.reconciliation.bundleCount).toBe(0);
    }
  });

  test("stages three distinct candidate-only hazards and does not materialize memory", () => {
    const { database, compiler } = setup();
    const results = historicalHangKnowledgeInputs.map((input) => compiler.compile(input));

    expect(results.every(({ status }) => status === "staged")).toBe(true);
    expect(new Set(results.map(({ bundleId }) => bundleId)).size).toBe(3);
    expect(results.every(({ provenanceReceiptId }) => /^akpr_[a-f0-9]{64}$/u.test(provenanceReceiptId ?? ""))).toBe(true);

    const candidateStatuses = database.prepare(`
      SELECT status, COUNT(*) AS count FROM memory_candidates GROUP BY status
    `).all() as Array<{ status: string; count: number }>;
    expect(candidateStatuses).toEqual([{
      status: "pending",
      count: results.reduce((total, result) => total + result.candidatesCreated, 0),
    }]);
    expect((database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get() as { count: number }).count).toBe(0);
    expect((database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get() as { count: number }).count).toBe(0);
    expect((database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_profiles").get() as { count: number }).count).toBe(0);
  });

  test("keeps exact reset evidence separate from the operator-reported engagement minimum", () => {
    const { database, compiler } = setup();
    historicalHangKnowledgeInputs.forEach((input) => compiler.compile(input));

    const counts = database.prepare(`
      SELECT SUM(exact_procedure_reset_count) AS exact_resets,
             MAX(operator_reported_reset_count_minimum) AS operator_minimum
      FROM attack_knowledge_bundles
    `).get() as { exact_resets: number; operator_minimum: number };
    expect(counts).toEqual({
      exact_resets: historicalHangReconciliation.exactEvidencedResetMinimum,
      operator_minimum: historicalHangReconciliation.operatorReportedAggregateResetMinimum,
    });
    expect(historicalHangReconciliation.minimumUnattributedResets).toBe(9);

    const procedureRows = database.prepare(`
      SELECT sanitized_bundle_json FROM attack_knowledge_bundles ORDER BY id
    `).all() as Array<{ sanitized_bundle_json: string }>;
    expect(procedureRows).toHaveLength(3);
    expect(procedureRows.filter(({ sanitized_bundle_json }) => sanitized_bundle_json.includes("DebugPrint"))).toHaveLength(1);
    expect(procedureRows.filter(({ sanitized_bundle_json }) => sanitized_bundle_json.includes("Path B"))).toHaveLength(2);
  });

  test("does not leak engagement names, addresses, or private filesystem paths into reusable content", () => {
    const { database, compiler } = setup();
    historicalHangKnowledgeInputs.forEach((input) => compiler.compile(input));

    const reusableText = JSON.stringify({
      bundles: database.prepare("SELECT sanitized_bundle_json FROM attack_knowledge_bundles ORDER BY id").all(),
      candidates: database.prepare("SELECT title, summary, body FROM memory_candidates ORDER BY id").all(),
      edges: database.prepare("SELECT source_role, target_role, edge_type FROM attack_knowledge_bundle_edges ORDER BY bundle_id, edge_key").all(),
    });

    expect(reusableText).not.toMatch(/ReaperTwo|10\.129\.|\/root\/|\/var\/lib\/|private:\/\//u);
    expect(reusableText).not.toMatch(/(?:https?|tcp):\/\//u);
    expect(reusableText).not.toContain("192.0.2.44");
    expect(reusableText).toContain("ASP.NET");
    expect(reusableText).toContain("10.0.20348.4163");
  });
});

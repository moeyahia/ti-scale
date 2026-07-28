import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../index";

const NOW = "2026-07-22T00:00:00.000Z";
const READINESS_SCOPE = JSON.stringify({
  allowGlobal: false,
  allowedStatuses: ["confirmed", "verified"],
  contextBudget: 0,
  exactNodeIds: [],
  exactNodeIdsOnly: true,
  graphDepth: 0,
  journey: "guided",
  maximumSensitivity: "public",
});
const READINESS_METRICS = JSON.stringify({
  retrievedCount: 0,
  source: "openrouter-content-free-readiness",
});

function insertContextPack(
  database: ReturnType<typeof createDatabaseConnection>,
  id: string,
  releaseDataClass: "canonical" | "startup_readiness",
  overrides: { readonly purpose?: string; readonly metrics?: string } = {},
): void {
  database.prepare(`
    INSERT INTO memory_context_packs (
      id, journey, purpose, query_redacted, scope_policy_json, context_budget,
      retrieval_metrics_json, created_by, created_at, release_data_class
    ) VALUES (?, 'guided', ?, 'content-free readiness acknowledgement', ?, 0, ?,
      'openrouter-readiness-monitor', ?, ?)
  `).run(
    id,
    overrides.purpose ?? "Content-free public-provider readiness audit",
    READINESS_SCOPE,
    overrides.metrics ?? READINESS_METRICS,
    NOW,
    releaseDataClass,
  );
}

function insertExposureReceipt(
  database: ReturnType<typeof createDatabaseConnection>,
  input: {
    readonly id: string;
    readonly turnId: string;
    readonly packId: string;
    readonly releaseDataClass: "canonical" | "startup_readiness";
    readonly selectedIds?: string;
  },
): void {
  database.prepare(`
    INSERT INTO provider_exposure_receipts (
      id, provider_id, model_id, provider_turn_id, context_pack_id,
      disclosure_policy_version, input_classification,
      selected_context_ids_json, rejected_context_ids_json,
      sanitization_actions_json, untrusted_content_envelope_hash,
      exposed_payload_hash, blocked, block_reason, created_at, release_data_class
    ) VALUES (?, 'openrouter', 'openai/gpt-5.2', ?, ?,
      'brain-provider-context-v1', 'public', ?, '[]', '[]', ?, ?, 0, NULL, ?, ?)
  `).run(
    input.id,
    input.turnId,
    input.packId,
    input.selectedIds ?? "[]",
    "a".repeat(64),
    "a".repeat(64),
    NOW,
    input.releaseDataClass,
  );
}

describe("startup readiness audit classification migration", () => {
  test("defaults all ordinary audit records to canonical release data", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      const migration = migrateDatabase(database);
      expect(migration.currentVersion).toBe(60);
      database.prepare(`
        INSERT INTO provider_turns (id, provider, status, started_at)
        VALUES ('turn-canonical', 'openrouter', 'started', ?)
      `).run(NOW);
      insertContextPack(database, "pack-canonical", "canonical", {
        purpose: "Operational Guided context",
        metrics: "{}",
      });
      insertExposureReceipt(database, {
        id: "receipt-canonical",
        turnId: "turn-canonical",
        packId: "pack-canonical",
        releaseDataClass: "canonical",
      });
      expect(database.prepare(`
        SELECT
          (SELECT release_data_class FROM provider_turns WHERE id = 'turn-canonical') AS turnClass,
          (SELECT release_data_class FROM memory_context_packs WHERE id = 'pack-canonical') AS packClass,
          (SELECT release_data_class FROM provider_exposure_receipts WHERE id = 'receipt-canonical') AS receiptClass
      `).get()).toEqual({
        turnClass: "canonical",
        packClass: "canonical",
        receiptClass: "canonical",
      });
    } finally {
      database.close();
    }
  });

  test("accepts only the exact content-free readiness lineage and keeps it immutable", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      database.prepare(`
        INSERT INTO provider_turns (
          id, provider, model, status, started_at, release_data_class
        ) VALUES ('provider-readiness-valid', 'openrouter', 'openai/gpt-5.2',
          'started', ?, 'startup_readiness')
      `).run(NOW);
      insertContextPack(database, "pack-readiness-valid", "startup_readiness");
      insertExposureReceipt(database, {
        id: "receipt-readiness-valid",
        turnId: "provider-readiness-valid",
        packId: "pack-readiness-valid",
        releaseDataClass: "startup_readiness",
      });

      expect(() => database.prepare(`
        UPDATE provider_turns SET provider = 'other'
        WHERE id = 'provider-readiness-valid'
      `).run()).toThrow("startup readiness provider turn classification is invalid");
      expect(() => database.prepare(`
        UPDATE memory_context_packs SET purpose = 'mission content'
        WHERE id = 'pack-readiness-valid'
      `).run()).toThrow("startup readiness context pack classification is invalid");
      expect(() => database.prepare(`
        UPDATE provider_exposure_receipts SET selected_context_ids_json = '[\"memory-secret\"]'
        WHERE id = 'receipt-readiness-valid'
      `).run()).toThrow("startup readiness exposure receipt classification is invalid");
      expect(() => database.prepare(`
        INSERT INTO memory_context_items (
          context_pack_id, node_id, rank, retrieval_score, relevance_reason
        ) VALUES ('pack-readiness-valid', 'memory-secret', 0, 1, 'must remain hidden')
      `).run()).toThrow("startup readiness context packs cannot contain memory items");
    } finally {
      database.close();
    }
  });

  test("rejects forged or mixed startup-readiness classifications", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      expect(() => database.prepare(`
        INSERT INTO provider_turns (
          id, provider, status, started_at, release_data_class
        ) VALUES ('ordinary-turn', 'openrouter', 'started', ?, 'startup_readiness')
      `).run(NOW)).toThrow("startup readiness provider turn classification is invalid");
      expect(() => insertContextPack(
        database,
        "pack-readiness-forged",
        "startup_readiness",
        { metrics: '{"retrievedCount":0,"source":"openrouter-content-free-readiness","mission":"secret"}' },
      )).toThrow("startup readiness context pack classification is invalid");

      database.prepare(`
        INSERT INTO provider_turns (id, provider, status, started_at)
        VALUES ('turn-canonical', 'openrouter', 'started', ?)
      `).run(NOW);
      insertContextPack(database, "pack-canonical", "canonical", {
        purpose: "Operational context",
        metrics: "{}",
      });
      expect(() => insertExposureReceipt(database, {
        id: "receipt-readiness-forged",
        turnId: "turn-canonical",
        packId: "pack-canonical",
        releaseDataClass: "startup_readiness",
      })).toThrow("startup readiness exposure receipt classification is invalid");
      expect(() => database.prepare(`
        UPDATE provider_turns SET release_data_class = 'startup_readiness'
        WHERE id = 'turn-canonical'
      `).run()).toThrow("release data classification is immutable");
    } finally {
      database.close();
    }
  });
});

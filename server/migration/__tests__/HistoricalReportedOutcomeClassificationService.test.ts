import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { HistoricalReportedOutcomeService, MemoryRepository } from "../../memory";
import { canonicalJson } from "../../orchestration/serialization";
import { ObsidianVaultBridge, VaultPathPolicy, parseObsidianNote } from "../../vault";
import {
  HistoricalReportedOutcomeClassificationError,
  HistoricalReportedOutcomeClassificationService,
} from "../HistoricalReportedOutcomeClassificationService";
import { runHistoricalReportedOutcomeCli } from "../historical-reported-outcome-cli";

const NOW = "2026-07-22T15:00:00.000Z";
const temporaryDirectories: string[] = [];

afterEach(() => {
  temporaryDirectories.splice(0).forEach((directory) => {
    rmSync(directory, { recursive: true, force: true });
  });
});

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function setup(options: {
  readonly omitSourceObject?: boolean;
  readonly omitInventoryReceipt?: boolean;
  readonly candidateSensitivity?: "internal" | "private";
} = {}): {
  readonly database: SqliteDatabase;
  readonly directory: string;
  readonly nodeId: string;
} {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-reported-outcome-"));
  temporaryDirectories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "test.sqlite") });
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
      created_by, created_at, updated_at
    ) VALUES ('mission-history-claims', 'Internal history claims',
      'Preserve private historical source custody only.', 'guided', 'archived',
      'unverified', '{}', '[]', '{}', '{}',
      'system:historical-attack-knowledge-import', ?, ?)
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, started_at, ended_at, created_at, updated_at
    ) VALUES ('run-history-claims', 'mission-history-claims', 'guided', 'completed', ?, ?, ?, ?)
  `).run(NOW, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO legacy_migration_runs (
      id, status, source_roots_json, database_path, output_directory,
      source_retention, source_retention_acknowledged_at, brain_projection_mode,
      brain_projection_acknowledged_at, started_at, completed_at
    ) VALUES ('migration-history-claims', 'completed', '[]', '/private/database',
      '/private/output', 'verified-reference', ?, 'attack-knowledge-only', ?, ?, ?)
  `).run(NOW, NOW, NOW, NOW);
  if (!options.omitInventoryReceipt) {
    database.prepare(`
      INSERT INTO legacy_migration_inventory_receipts (
        migration_id, receipt_hash, object_count, byte_count, created_at
      ) VALUES ('migration-history-claims', ?, 1, 128, ?)
    `).run(sha256("inventory"), NOW);
  }
  database.prepare(`
    INSERT INTO historical_attack_knowledge_import_contexts (
      migration_id, mission_id, run_id, created_at
    ) VALUES ('migration-history-claims', 'mission-history-claims', 'run-history-claims', ?)
  `).run(NOW);
  database.prepare(`
    INSERT INTO legacy_migration_sources (
      id, migration_id, source_path, relative_path, source_type, source_identity,
      source_sha256, byte_size, modified_at, source_reference, source_retention,
      source_device, source_inode, verified_at, status, discovered_at, completed_at
    ) VALUES ('legacy-source-claims', 'migration-history-claims', '/private/source',
      'opaque-source', 'event_jsonl', 'opaque-identity', ?, 128, ?,
      'legacy-private-source://source-claims', 'verified-reference', 1, 2, ?,
      'completed', ?, ?)
  `).run(sha256("source"), NOW, NOW, NOW, NOW);
  if (!options.omitSourceObject) {
    database.prepare(`
      INSERT INTO legacy_migration_source_objects (
        id, migration_id, source_id, object_key, source_reference, source_path,
        object_kind, classification, source_sha256, byte_size, modified_at,
        source_device, source_inode, verification_status, verified_at
      ) VALUES ('source-object-claims', 'migration-history-claims', 'legacy-source-claims',
        'source', 'legacy-private-source://source-claims', '/private/source',
        'source', 'event_jsonl', ?, 128, ?, 1, 2, 'verified_reference', ?)
    `).run(sha256("source"), NOW, NOW);
  }
  database.prepare(`
    INSERT INTO evidence_candidates (
      id, mission_id, run_id, evidence_type, label, meaning, promotion_reason,
      validation_requirements_json, state, sensitivity, proposed_by, created_at
    ) VALUES ('candidate-source-claims', 'mission-history-claims', 'run-history-claims',
      'historical_attack_source_record', 'Historical source',
      'Opaque source claim custody.', 'Review only as a reported claim.', '[]',
      'candidate', 'private', 'system:historical-attack-knowledge-extractor', ?)
  `).run(NOW);
  database.prepare(`
    INSERT INTO historical_attack_knowledge_source_candidates (
      candidate_id, source_hash, byte_size, created_at
    ) VALUES ('candidate-source-claims', ?, 128, ?)
  `).run(sha256("source"), NOW);
  database.prepare(`
    INSERT INTO historical_attack_knowledge_source_occurrences (
      candidate_id, migration_id, source_reference, source_hash, modified_at, observed_at
    ) VALUES ('candidate-source-claims', 'migration-history-claims',
      'legacy-private-source://source-claims', ?, ?, ?)
  `).run(sha256("source"), NOW, NOW);

  const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
  const node = memory.createNode({
    id: `mem_${sha256("reported-outcome-technique")}`,
    nodeType: "attack_technique",
    title: "Reusable bounded validation",
    summary: "A technique-centric historical procedure.",
    body: "Validate this procedure against a matching technology stack before reuse.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.8,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "Generalized from an opaque historical source claim.",
      sources: [{ sourceType: "review_receipt", sourceId: "source-claims", acquiredAt: NOW }],
    },
    authorType: "operator",
    authorId: "operator-test",
  });
  database.prepare(`
    INSERT INTO memory_candidates (
      id, proposed_node_id, candidate_type, title, summary, body, proposed_scope,
      sensitivity, confidence, source_json, status, proposed_by, reviewed_by,
      reviewed_at, created_at
    ) VALUES ('candidate-technique-claims', ?, 'attack_technique',
      'Reusable bounded validation', 'A technique-centric historical procedure.',
      'Validate against a matching technology stack.', 'global', 'internal', 0.8,
      '{}', 'confirmed', 'attack-knowledge-compiler', 'operator-test', ?, ?)
  `).run(node.id, NOW, NOW);
  const contentFingerprint = sha256("candidate-technique-claims");
  database.prepare(`
    INSERT INTO attack_knowledge_candidate_registry (
      content_fingerprint, candidate_id, node_type, created_at
    ) VALUES (?, 'candidate-technique-claims', 'attack_technique', ?)
  `).run(contentFingerprint, NOW);

  const bundles = [
    ["success", { reportedOutcome: "reported_success", verification: "source_reported_unverified" }, false],
    ["failure", { reportedOutcome: "reported_failure", verification: "source_reported_unverified" }, false],
    ["mixed", { reportedOutcome: "mixed", verification: "source_reported_unverified" }, false],
    ["unknown", null, false],
    ["unsafe", { reportedOutcome: "reported_success", verification: "source_reported_unverified" }, true],
  ] as const;
  for (const [ordinal, [label, reported, unsafe]] of bundles.entries()) {
    const facts: Array<Record<string, unknown>> = [{
      role: "technique",
      nodeType: "attack_technique",
      title: "Reusable bounded validation",
      summary: "Technique-centric historical knowledge.",
    }];
    if (reported) {
      facts.push({
        role: "outcome",
        nodeType: "outcome",
        title: "Historical reported outcome",
        summary: "Reported by a historical source; not independently verified.",
        body: canonicalJson({ ...reported, ...(unsafe ? { password: "must-not-cross" } : {}) }),
      });
    }
    const sanitized = canonicalJson({
      schemaVersion: 1,
      knowledge: {
        kind: "reusable_bundle",
        facts,
        edges: reported
          ? [{ sourceRole: "technique", edgeType: "produces_outcome", targetRole: "outcome" }]
          : [],
      },
    });
    const fingerprint = sha256(sanitized);
    const bundleId = `akb_${fingerprint}`;
    const receiptId = `receipt-${label}`;
    database.prepare(`
      INSERT INTO attack_knowledge_bundles (
        id, semantic_fingerprint, sanitized_bundle_json, status,
        first_observed_at, last_observed_at, created_at, updated_at
      ) VALUES (?, ?, ?, 'materialized', ?, ?, ?, ?)
    `).run(bundleId, fingerprint, sanitized, NOW, NOW, NOW, NOW);
    database.prepare(`
      INSERT INTO attack_knowledge_provenance_receipts (
        id, source_class, source_hash, evidence_count, observed_at, created_at
      ) VALUES (?, 'historical', ?, 1, ?, ?)
    `).run(receiptId, sha256(`sanitized-segment-${label}`), NOW, NOW);
    database.prepare(`
      INSERT INTO attack_knowledge_bundle_receipts (bundle_id, receipt_id, linked_at)
      VALUES (?, ?, ?)
    `).run(bundleId, receiptId, NOW);
    database.prepare(`
      INSERT INTO historical_attack_knowledge_bundle_sources (
        bundle_id, receipt_id, candidate_id, source_hash, binding_hash, linked_at
      ) VALUES (?, ?, 'candidate-source-claims', ?, ?, ?)
    `).run(bundleId, receiptId, sha256("source"), sha256(`binding-${label}`), NOW);
    database.prepare(`
      INSERT INTO attack_knowledge_bundle_candidates (
        bundle_id, role, content_fingerprint, required, ordinal, linked_at
      ) VALUES (?, 'technique', ?, 1, ?, ?)
    `).run(bundleId, contentFingerprint, ordinal, NOW);
  }
  if (options.candidateSensitivity && options.candidateSensitivity !== "private") {
    database.prepare(`
      UPDATE evidence_candidates SET sensitivity = ?
      WHERE id = 'candidate-source-claims'
    `).run(options.candidateSensitivity);
  }
  return { database, directory, nodeId: node.id };
}

describe("HistoricalReportedOutcomeClassificationService", () => {
  test("uses the node-first covering index for Vault outcome projection", () => {
    const fixture = setup();
    try {
      const index = fixture.database.prepare(`
        SELECT name, sql FROM sqlite_master
        WHERE type = 'index' AND name = 'idx_memory_candidates_proposed_node_id'
      `).get() as { readonly name: string; readonly sql: string } | undefined;
      expect(index).toEqual({
        name: "idx_memory_candidates_proposed_node_id",
        sql: expect.stringContaining("memory_candidates(proposed_node_id, id)"),
      });

      const plan = fixture.database.prepare(`
        EXPLAIN QUERY PLAN
        SELECT classification, COUNT(DISTINCT claim_id) AS claim_count,
          COUNT(DISTINCT source_hash) AS source_count,
          MAX(classification_confidence) AS maximum_confidence
        FROM historical_reported_outcome_node_claims
        WHERE memory_node_id = ? AND policy_version = ?
        GROUP BY classification
        ORDER BY classification
      `).all(fixture.nodeId, "historical-reported-outcome/v1") as Array<{
        readonly detail: string;
      }>;
      const details = plan.map(({ detail }) => detail);
      expect(details).toContainEqual(expect.stringContaining(
        "SEARCH candidate USING COVERING INDEX idx_memory_candidates_proposed_node_id (proposed_node_id=?)",
      ));
      expect(details).not.toContainEqual(expect.stringMatching(/^SCAN claim\b/u));
    } finally {
      fixture.database.close();
    }
  });

  test("keeps the CLI preview query-only", () => {
    const fixture = setup();
    try {
      const preview = runHistoricalReportedOutcomeCli([
        "preview",
        "--dry-run",
        "--db",
        join(fixture.directory, "test.sqlite"),
        "--max-records",
        "2",
      ]) as { readonly reviewedCount: number; readonly dryRun: boolean };
      expect(preview).toMatchObject({ reviewedCount: 2, dryRun: true });
      expect(fixture.database.prepare(
        "SELECT COUNT(*) AS count FROM historical_reported_outcome_claims",
      ).get()).toEqual({ count: 0 });
      expect(() => runHistoricalReportedOutcomeCli([
        "preview", "--db", join(fixture.directory, "test.sqlite"),
      ])).toThrow("--dry-run");
    } finally {
      fixture.database.close();
    }
  });

  test("classifies sanitized source claims separately, pages deterministically, and never creates canonical outcomes", () => {
    const fixture = setup();
    try {
      const service = new HistoricalReportedOutcomeClassificationService(
        fixture.database,
        () => new Date(NOW),
      );
      const first = service.preview({ maxRecords: 2 });
      expect(first).toMatchObject({
        dryRun: true,
        reviewedCount: 2,
        eligibleCount: 2,
        rejectedCount: 0,
        hasMore: true,
      });
      expect(first.nextCursor).toBeString();
      const second = service.preview({ afterCursor: first.nextCursor!, maxRecords: 3 });
      expect(second).toMatchObject({ reviewedCount: 3, eligibleCount: 2, rejectedCount: 1, hasMore: false });
      const classifications = [...first.entries, ...second.entries]
        .filter(({ disposition }) => disposition === "eligible")
        .map(({ classification }) => classification).sort();
      expect(classifications).toEqual([
        "mixed", "reported_failure", "reported_success", "unknown",
      ]);
      expect(JSON.stringify([first, second])).not.toContain("/private/");

      const applied = service.apply({
        maxRecords: 2,
        expectedPreviewHash: first.previewHash,
        acknowledgeReportedOnly: true,
        actorId: "operator-test",
        reason: "Classify this bounded page as source-reported history only.",
      });
      expect(applied).toMatchObject({ insertedCount: 2, reusedCount: 0 });
      const replay = service.apply({
        maxRecords: 2,
        expectedPreviewHash: first.previewHash,
        acknowledgeReportedOnly: true,
        actorId: "operator-test",
        reason: "Classify this bounded page as source-reported history only.",
      });
      expect(replay).toMatchObject({ insertedCount: 0, reusedCount: 2 });
      expect(fixture.database.prepare(
        "SELECT COUNT(*) AS count FROM historical_reported_outcome_claims",
      ).get()).toEqual({ count: 2 });
      expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM attack_attempts").get())
        .toEqual({ count: 0 });
      expect(fixture.database.prepare(
        "SELECT COUNT(*) AS count FROM reusable_knowledge_outcome_links",
      ).get()).toEqual({ count: 0 });
      expect(() => fixture.database.prepare(`
        UPDATE historical_reported_outcome_claims SET classification = 'unknown'
      `).run()).toThrow("immutable");
    } finally {
      fixture.database.close();
    }
  });

  test("accepts distinct sanitized-receipt and raw-source hashes only through strict verified-reference custody", () => {
    const fixture = setup();
    try {
      const hashes = fixture.database.prepare(`
        SELECT receipt.source_hash AS receipt_hash, source.source_hash AS raw_source_hash
        FROM historical_attack_knowledge_bundle_sources source
        JOIN attack_knowledge_provenance_receipts receipt ON receipt.id = source.receipt_id
        ORDER BY source.receipt_id LIMIT 1
      `).get() as { readonly receipt_hash: string; readonly raw_source_hash: string };
      expect(hashes.receipt_hash).not.toBe(hashes.raw_source_hash);

      const service = new HistoricalReportedOutcomeClassificationService(
        fixture.database,
        () => new Date(NOW),
      );
      const preview = service.preview({ maxRecords: 5 });
      expect(preview).toMatchObject({ reviewedCount: 5, eligibleCount: 4, rejectedCount: 1 });
      const result = service.apply({
        maxRecords: 5,
        expectedPreviewHash: preview.previewHash,
        acknowledgeReportedOnly: true,
        actorId: "operator-test",
        reason: "Classify source-reported history under exact two-hash custody.",
      });
      expect(result).toMatchObject({ insertedCount: 4, reusedCount: 0 });
      expect(fixture.database.prepare(
        "SELECT COUNT(*) AS count FROM historical_reported_outcome_claims",
      ).get()).toEqual({ count: 4 });
    } finally {
      fixture.database.close();
    }
  });

  test("fails closed when raw-source inventory custody or candidate privacy is invalid", () => {
    const invalidators: ReadonlyArray<{
      readonly label: string;
      readonly options: Parameters<typeof setup>[0];
    }> = [
      {
        label: "missing verified source object",
        options: { omitSourceObject: true },
      },
      {
        label: "missing completed inventory receipt",
        options: { omitInventoryReceipt: true },
      },
      {
        label: "non-private source candidate",
        options: { candidateSensitivity: "internal" },
      },
    ];

    for (const invalidator of invalidators) {
      const fixture = setup(invalidator.options);
      try {
        const service = new HistoricalReportedOutcomeClassificationService(
          fixture.database,
          () => new Date(NOW),
        );
        const preview = service.preview({ maxRecords: 5 });
        expect(preview.reviewedCount, invalidator.label).toBe(0);
        expect(preview.eligibleCount, invalidator.label).toBe(0);
        expect(fixture.database.prepare(
          "SELECT COUNT(*) AS count FROM historical_reported_outcome_claims",
        ).get()).toEqual({ count: 0 });
      } finally {
        fixture.database.close();
      }
    }
  });

  test("requires the exact reviewed hash and projects a filterable reported-only Vault tag", () => {
    const fixture = setup();
    try {
      const service = new HistoricalReportedOutcomeClassificationService(
        fixture.database,
        () => new Date(NOW),
      );
      const preview = service.preview({ maxRecords: 5 });
      expect(() => service.apply({
        maxRecords: 5,
        expectedPreviewHash: "f".repeat(64),
        acknowledgeReportedOnly: true,
        actorId: "operator-test",
        reason: "Classify reported history only.",
      })).toThrow(HistoricalReportedOutcomeClassificationError);
      service.apply({
        maxRecords: 5,
        expectedPreviewHash: preview.previewHash,
        acknowledgeReportedOnly: true,
        actorId: "operator-test",
        reason: "Classify reported history only.",
      });
      const summary = new HistoricalReportedOutcomeService(fixture.database)
        .summary(fixture.nodeId);
      expect(summary).toEqual({
        classification: "mixed",
        classificationConfidence: 0.75,
        claimCount: 4,
        sourceCount: 1,
        policyVersion: "historical-reported-outcome/v1",
      });

      const policy = new VaultPathPolicy(join(fixture.directory, "vaults"));
      const bridge = new ObsidianVaultBridge(
        fixture.database,
        new MemoryRepository(fixture.database),
        policy,
      );
      const connection = bridge.connect({
        id: "vault-reported-outcomes",
        vaultPath: "Attack-Knowledge",
        displayName: "Attack Knowledge",
        syncScope: {},
        permissionGranted: true,
      });
      const exported = bridge.exportNode(connection.id, fixture.nodeId);
      const text = readFileSync(join(connection.vaultPath, exported.relativePath), "utf8");
      expect(text).toContain('reported_outcome: "mixed"');
      expect(text).toContain('  - "ti-scale/reported-outcome/mixed"');
      expect(text).not.toContain("outcome_tags:");
      expect(parseObsidianNote(text).reportedOutcome).toEqual(summary);
    } finally {
      fixture.database.close();
    }
  });
});

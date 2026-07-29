import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import {
  GenericHistoricalAttackKnowledgeIngestionService,
} from "../GenericHistoricalAttackKnowledgeIngestionService";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";
import type { LegacySource, LegacySourceType } from "../types";

const HMAC_KEY = "generic-historical-ingestion-test-key-longer-than-thirty-two-bytes";
const RECEIPT = "b".repeat(64);
const directories: string[] = [];
const databases: SqliteDatabase[] = [];

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function setup(): {
  readonly root: string;
  readonly database: SqliteDatabase;
  readonly metadata: MigrationMetadataRepository;
  readonly migrationId: string;
  readonly service: GenericHistoricalAttackKnowledgeIngestionService;
} {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-generic-history-"));
  directories.push(root);
  const database = createDatabaseConnection({ filename: join(root, "ti-scale.sqlite") });
  databases.push(database);
  migrateDatabase(database);
  const metadata = new MigrationMetadataRepository(database, () => new Date("2026-07-20T10:00:00.000Z"));
  const migration = metadata.createRun({
    sourceRoots: [join(root, "history")],
    databasePath: join(root, "ti-scale.sqlite"),
    outputDirectory: join(root, "output"),
    sourceRetention: "verified-reference",
    verifiedReferenceAcknowledged: true,
    brainProjectionMode: "attack-knowledge-only",
    attackKnowledgeOnlyAcknowledged: true,
  });
  database.prepare(`
    INSERT INTO legacy_migration_inventory_receipts (
      migration_id, receipt_hash, object_count, byte_count, created_at
    ) VALUES (?, ?, 1, 1, '2026-07-20T10:00:00.000Z')
  `).run(migration.id, RECEIPT);
  return {
    root,
    database,
    metadata,
    migrationId: migration.id,
    service: new GenericHistoricalAttackKnowledgeIngestionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date("2026-07-20T10:00:00.000Z"),
    }),
  };
}

function registerSource(
  fixture: ReturnType<typeof setup>,
  relativePath: string,
  type: LegacySourceType,
  content: string | Uint8Array,
): LegacySource {
  const root = join(fixture.root, "history");
  const path = join(root, relativePath);
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, content, { mode: 0o600 });
  const bytes = typeof content === "string" ? Buffer.from(content) : Buffer.from(content);
  const state = statSync(path);
  const source: LegacySource = {
    absolutePath: path,
    relativePath,
    root,
    type,
    sha256: sha256(bytes),
    byteSize: bytes.byteLength,
    modifiedAt: state.mtime.toISOString(),
  };
  const sourceId = fixture.metadata.registerSource(fixture.migrationId, source, undefined, {
    retentionMode: "verified-reference",
    device: state.dev,
    inode: state.ino,
  });
  fixture.metadata.registerSourceObject({
    migrationId: fixture.migrationId,
    sourceId,
    objectKey: "source",
    sourcePath: path,
    objectKind: "source",
    classification: type,
    sourceSha256: source.sha256,
    byteSize: source.byteSize,
    modifiedAt: source.modifiedAt,
    sourceDevice: state.dev,
    sourceInode: state.ino,
  });
  return source;
}

function ingest(
  fixture: ReturnType<typeof setup>,
  sources: readonly LegacySource[],
  overrides: Partial<Parameters<typeof fixture.service.ingest>[0]> = {},
) {
  return fixture.service.ingest({
    migrationId: fixture.migrationId,
    inventoryReceiptHash: RECEIPT,
    sources,
    ...overrides,
  });
}

function candidateText(database: SqliteDatabase): string {
  return JSON.stringify(database.prepare(`
    SELECT candidate_type, title, summary, body, source_json, proposed_scope
    FROM memory_candidates ORDER BY candidate_type, title
  `).all());
}

describe("GenericHistoricalAttackKnowledgeIngestionService", () => {
  test("preserves mixed historical source claims without promoting them to canonical outcomes", () => {
    const fixture = setup();
    const source = registerSource(
      fixture,
      "runtime/mixed-result.json",
      "run_json",
      JSON.stringify({
        result: "Apache HTTP Server/2.4.49 path traversal worked once, then failed and timed out with nmap",
      }),
    );

    const result = ingest(fixture, [source]);
    expect(result.compilerBundlesStaged).toBe(1);
    const outcome = fixture.database.prepare(`
      SELECT body FROM memory_candidates
      WHERE candidate_type = 'outcome' ORDER BY id LIMIT 1
    `).get() as { readonly body: string };
    expect(JSON.parse(outcome.body)).toEqual({
      reportedOutcome: "mixed",
      reportedStatus: "mixed",
      verification: "source_reported_unverified",
    });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM attack_attempts").get())
      .toEqual({ count: 0 });
    expect(fixture.database.prepare(
      "SELECT COUNT(*) AS count FROM reusable_knowledge_outcome_links",
    ).get()).toEqual({ count: 0 });
  });

  test("stages generalized candidates only from structured operational records", () => {
    const fixture = setup();
    const sources = [
      registerSource(fixture, "runtime/runs/run.json", "run_json", JSON.stringify({
        timestamp: "2026-01-01T00:00:00Z",
        result: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 worked with nmap",
      })),
      registerSource(fixture, "state/sessions/session.json", "session_json", JSON.stringify({
        messages: [{ content: "nginx 1.24.0 remote code execution failed with timeout" }],
      })),
      registerSource(fixture, "runtime/events.jsonl", "event_jsonl", `${JSON.stringify({ summary: "PHP 8.2.1 command injection validated" })}\n`),
      registerSource(fixture, "session-logs/raw.jsonl", "raw_llm_jsonl", `${JSON.stringify({ message: "OpenSSH_9.2p1 authentication bypass failed" })}\n`),
      registerSource(fixture, "logs/dashboard.log", "dashboard_log", "Linux kernel 6.1.0 privilege escalation failed; reset before retry\n"),
      registerSource(fixture, "runtime/memory/items.json", "memory_json", JSON.stringify({
        memories: [{ summary: "MySQL 8.0.35 SQL injection was confirmed" }],
      })),
      registerSource(fixture, "runtime/training/lessons.json", "training_json", JSON.stringify({
        lessons: [{ summary: "ASP.NET 4.8 remote code execution timed out; recycle then verify health" }],
      })),
    ];

    const result = ingest(fixture, sources);
    expect(result.status).toBe("completed");
    expect(result.filesDiscovered).toBe(7);
    expect(result.filesParsed).toBe(4);
    expect(result.filesSkipped).toBe(3);
    expect(result.compilerBundlesStaged).toBe(4);
    expect(result.compilerReconciliationPasses).toBe(1);
    expect(result.compilerRunsReconciled).toBe(result.compilerBundlesStaged);
    expect(result.compilerReconciliation).toMatchObject({
      bundleCount: result.compilerBundlesStaged,
      receiptCount: result.compilerBundlesStaged,
      orphanedCandidateLinks: 0,
    });
    const compilerRunReconciliations = fixture.database.prepare(`
      SELECT reconciliation_json FROM attack_knowledge_compiler_runs ORDER BY id
    `).all() as Array<{ readonly reconciliation_json: string }>;
    expect(compilerRunReconciliations.map(({ reconciliation_json }) => JSON.parse(reconciliation_json)))
      .toEqual(Array.from(
        { length: result.compilerRunsReconciled },
        () => result.compilerReconciliation,
      ));
    expect(result.sourceEvidenceCandidatesCreated).toBe(4);
    expect(result.sourceBundleLinks).toBe(4);
    expect(result.recordsProcessed).toBe(7);
    expect(result.recordsQuarantined).toBe(0);
    expect(candidateText(fixture.database)).toContain("Apache HTTP Server");
    expect(candidateText(fixture.database)).toContain("CVE-2021-41773");
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM evidence_candidates
      WHERE state = 'candidate' AND sensitivity = 'private'
    `).get()).toEqual({ count: 4 });
  });

  test("resumes after interruption from the durable item ledger and is idempotent", () => {
    const fixture = setup();
    const source = registerSource(fixture, "runtime/events.jsonl", "event_jsonl", [
      JSON.stringify({ summary: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 worked" }),
      JSON.stringify({ summary: "nginx 1.24.0 remote code execution failed with timeout" }),
    ].join("\n"));

    const interrupted = ingest(fixture, [source], { interruptAfterNewRecords: 1 });
    expect(interrupted.status).toBe("partial");
    expect(interrupted.recordsProcessed).toBe(1);
    expect(interrupted.nextResumeAfterRecordKey).toBeDefined();

    const resumed = ingest(fixture, [source]);
    expect(resumed.status).toBe("completed");
    expect(resumed.recordsDeduplicated).toBe(1);
    expect(resumed.recordsProcessed).toBe(1);

    const replay = ingest(fixture, [source]);
    expect(replay.status).toBe("completed");
    expect(replay.recordsProcessed).toBe(0);
    expect(replay.recordsDeduplicated).toBe(0);
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_provenance_receipts").get()).toEqual({ count: 2 });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM historical_attack_knowledge_bundle_sources").get()).toEqual({ count: 2 });
  });

  test("pages a dry preview past its record budget with opaque source and record cursors", () => {
    const fixture = setup();
    const source = registerSource(fixture, "runtime/paged-events.jsonl", "event_jsonl", [
      JSON.stringify({ summary: "Apache HTTP Server/2.4.49 path traversal worked" }),
      JSON.stringify({ summary: "nginx 1.24.0 remote code execution failed" }),
      JSON.stringify({ summary: "PHP 8.2.1 command injection validated" }),
    ].join("\n"));

    const first = ingest(fixture, [source], { dryRun: true, maxRecordsThisRun: 1 });
    expect(first).toMatchObject({ status: "partial", recordsProcessed: 1, sourcesCompleted: 0 });
    expect(first.nextResumeAfterSourceKey).toMatch(/^[a-f0-9]{64}$/u);
    expect(first.nextResumeAfterRecordKey).toMatch(/^[a-f0-9]{64}$/u);

    const second = ingest(fixture, [source], {
      dryRun: true,
      maxRecordsThisRun: 1,
      resumeAfterSourceKey: first.nextResumeAfterSourceKey,
      resumeAfterRecordKey: first.nextResumeAfterRecordKey,
    });
    expect(second).toMatchObject({ status: "partial", recordsProcessed: 1, sourcesCompleted: 0 });

    const third = ingest(fixture, [source], {
      dryRun: true,
      maxRecordsThisRun: 1,
      resumeAfterSourceKey: second.nextResumeAfterSourceKey,
      resumeAfterRecordKey: second.nextResumeAfterRecordKey,
    });
    expect(third).toMatchObject({ status: "completed", recordsProcessed: 1, sourcesCompleted: 1 });
    expect([first, second, third].reduce((total, page) => total + page.recordsProcessed, 0)).toBe(3);
    expect(new Set([first, second, third].flatMap((page) => page.sourceEvidenceCandidateIds))).toHaveProperty("size", 1);
    expect([first, second, third].reduce(
      (total, page) => total + Object.values(page.nodeTypeCounts).reduce((sum, count) => sum + count, 0),
      0,
    )).toBeGreaterThanOrEqual(6);
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get()).toEqual({ count: 0 });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get()).toEqual({ count: 0 });
  });

  test("never reports completion when record or bundle budgets leave work unprocessed", () => {
    const fixture = setup();
    const source = registerSource(fixture, "runtime/events.jsonl", "event_jsonl", [
      JSON.stringify({ summary: "Apache HTTP Server/2.4.49 path traversal worked" }),
      JSON.stringify({ summary: "nginx 1.24.0 remote code execution failed" }),
    ].join("\n"));

    const recordLimited = ingest(fixture, [source], { maxRecordsThisRun: 1 });
    expect(recordLimited.status).toBe("partial");
    expect(recordLimited.issues.some((issue) => issue.reason === "record_budget_exceeded")).toBeTrue();

    const fixtureTwo = setup();
    const second = registerSource(fixtureTwo, "runtime/events.jsonl", "event_jsonl", [
      JSON.stringify({ summary: "Apache HTTP Server/2.4.49 path traversal worked" }),
      JSON.stringify({ summary: "nginx 1.24.0 remote code execution failed" }),
    ].join("\n"));
    const bundleLimited = ingest(fixtureTwo, [second], { maxBundlesThisRun: 1 });
    expect(bundleLimited.status).toBe("partial");
    expect(bundleLimited.issues.some((issue) => issue.reason === "bundle_budget_exceeded")).toBeTrue();
  });

  test("fails closed on inventory receipt mismatch and quarantines path replacement", () => {
    const fixture = setup();
    const source = registerSource(fixture, "runtime/runs/run.json", "run_json", JSON.stringify({
      result: "Apache HTTP Server/2.4.49 path traversal worked",
    }));
    expect(() => fixture.service.ingest({
      migrationId: fixture.migrationId,
      inventoryReceiptHash: "c".repeat(64),
      sources: [source],
    })).toThrow("immutable migration inventory receipt");

    const replaced = `${source.absolutePath}.replaced`;
    renameSync(source.absolutePath, replaced);
    writeFileSync(source.absolutePath, JSON.stringify({ result: "nginx 1.24.0 remote code execution" }), { mode: 0o600 });
    const result = ingest(fixture, [source]);
    expect(result.status).toBe("completed");
    expect(result.filesQuarantined).toBe(1);
    expect(result.issues).toContainEqual(expect.objectContaining({ reason: "source_changed" }));
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get()).toEqual({ count: 0 });
  });

  test("quarantines malformed and secret-bearing records without retaining payloads", () => {
    const fixture = setup();
    const secret = "operator_api_token=shh-this-must-not-be-retained";
    const source = registerSource(fixture, "runtime/events.jsonl", "event_jsonl", [
      JSON.stringify({ summary: `Apache HTTP Server/2.4.49 ${secret}` }),
      "{malformed-json",
      JSON.stringify({ summary: "nginx 1.24.0 path traversal worked" }),
    ].join("\n"));
    const result = ingest(fixture, [source]);
    expect(result.status).toBe("completed");
    expect(result.recordsQuarantined).toBe(2);
    expect(result.compilerBundlesStaged).toBe(1);
    const persisted = JSON.stringify(fixture.database.prepare(`
      SELECT category, reason, redacted_excerpt FROM legacy_migration_quarantine ORDER BY category
    `).all());
    expect(persisted).not.toContain(secret);
    expect(persisted).not.toContain("malformed-json");
    expect(candidateText(fixture.database)).not.toContain(secret);
  });

  test("deduplicates reusable semantics across private operational locators without cross-engagement leakage", () => {
    const fixture = setup();
    const first = registerSource(fixture, "sessions/one.json", "session_json", JSON.stringify({
      target: "10.20.30.40",
      mission: "private-alpha",
      result: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 worked",
    }));
    const second = registerSource(fixture, "sessions/two.json", "session_json", JSON.stringify({
      target: "192.0.2.55",
      mission: "private-bravo",
      result: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 worked",
    }));
    const firstResult = ingest(fixture, [first]);
    const candidateCount = (fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get() as { count: number }).count;
    const secondResult = ingest(fixture, [second]);
    expect(firstResult.candidatesCreated).toBeGreaterThan(0);
    expect(secondResult.candidatesCreated).toBe(0);
    expect(secondResult.candidatesReused).toBeGreaterThan(0);
    expect((fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get() as { count: number }).count).toBe(candidateCount);
    const retained = candidateText(fixture.database);
    expect(retained).not.toContain("10.20.30.40");
    expect(retained).not.toContain("192.0.2.55");
    expect(retained).not.toContain("private-alpha");
    expect(retained).not.toContain("private-bravo");
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM historical_attack_knowledge_source_occurrences").get()).toEqual({ count: 2 });
  });

  test("accepts completed provider tool results but rejects model prose and prompts", () => {
    const fixture = setup();
    const secret = "operator_api_token=never-retain-this-value";
    const sources = [
      registerSource(
        fixture,
        "provider/session.jsonl",
        "provider_session_jsonl",
        `${JSON.stringify({
          type: "response_item",
          payload: {
            type: "function_call_output",
            output: "nginx 1.24.0 path traversal failed, then restart and verify health",
          },
        })}\n`,
      ),
      registerSource(
        fixture,
        "hermes/conversations/valid.md",
        "conversation_markdown",
        "# Assessment note\n\nPostgreSQL 15.4 authentication bypass was confirmed.\n",
      ),
      registerSource(
        fixture,
        "hermes/conversations/secret.md",
        "conversation_markdown",
        `# Private note\n\nApache HTTP Server 2.4.58 ${secret}\n`,
      ),
    ];

    const result = ingest(fixture, sources);
    expect(result.status).toBe("completed");
    expect(result.recordsQuarantined).toBe(1);
    expect(result.compilerBundlesStaged).toBe(1);
    expect(result.issues).toContainEqual(expect.objectContaining({
      disposition: "skipped",
      reason: "non_evidentiary_narrative",
    }));
    const retained = candidateText(fixture.database);
    expect(retained).toContain("nginx");
    expect(retained).not.toContain("PostgreSQL");
    expect(retained).not.toContain(secret);
    expect(JSON.stringify(fixture.database.prepare(`
      SELECT category, reason, redacted_excerpt FROM legacy_migration_quarantine
    `).all())).not.toContain(secret);
  });

  test("rejects bare statuses, provider stream fragments, and system prompt examples", () => {
    const fixture = setup();
    const sources = [
      registerSource(fixture, "runtime/status.json", "run_json", JSON.stringify({
        status: "failed",
        recovery: "restart successful",
      })),
      registerSource(fixture, "provider/stream.jsonl", "provider_session_jsonl", [
        JSON.stringify({
          type: "stream_event",
          event: {
            type: "text_delta",
            delta: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 failed",
          },
        }),
        JSON.stringify({
          type: "response_item",
          payload: {
            type: "message",
            role: "developer",
            content: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 worked",
          },
        }),
      ].join("\n")),
    ];

    const result = ingest(fixture, sources);
    expect(result.status).toBe("completed");
    expect(result.compilerBundlesStaged).toBe(0);
    expect(result.semanticFactsParsed).toBe(0);
    expect(result.issues).toContainEqual(expect.objectContaining({
      reason: "insufficient_technical_context",
    }));
    expect(result.issues.filter(({ reason }) => reason === "provider_prompt_or_stream")).toHaveLength(2);
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get()).toEqual({ count: 0 });
  });

  test("keeps an evidence-bearing tool fingerprint without inventing an outcome", () => {
    const fixture = setup();
    const source = registerSource(
      fixture,
      "provider/tool-output.jsonl",
      "provider_session_jsonl",
      `${JSON.stringify({
        type: "response_item",
        payload: {
          type: "function_call_output",
          output: "80/tcp open http Apache httpd 2.4.49; service version detected from scan output",
        },
      })}\n`,
    );

    const result = ingest(fixture, [source]);
    expect(result.compilerBundlesStaged).toBe(1);
    expect(result.nodeTypeCounts).toMatchObject({
      technology_product: 1,
      exact_version_fingerprint: 1,
    });
    expect(result.nodeTypeCounts.outcome ?? 0).toBe(0);
    expect(result.nodeTypeCounts.failure_mode ?? 0).toBe(0);
    expect(result.nodeTypeCounts.recovery_pattern ?? 0).toBe(0);
  });

  test("reads allowlisted historical SQLite state in bounded query-only mode", () => {
    const fixture = setup();
    const root = join(fixture.root, "history");
    const path = join(root, "kanban.db");
    mkdirSync(root, { recursive: true });
    const sqlite = createDatabaseConnection({ filename: path });
    sqlite.exec("CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT, details TEXT)");
    sqlite.prepare("INSERT INTO tasks (id, title, details) VALUES (?, ?, ?)").run(
      "task-1",
      "Historical result",
      "Microsoft-IIS/10.0 remote code execution failed with timeout; restart service before retry",
    );
    sqlite.pragma("wal_checkpoint(TRUNCATE)");
    sqlite.close();
    const file = readFileSync(path);
    const source = registerExistingSqlite(fixture, path, "kanban_sqlite", file);

    const result = ingest(fixture, [source]);
    expect(result.status).toBe("completed");
    expect(result.filesParsed).toBe(1);
    expect(result.compilerBundlesStaged).toBe(1);
    expect(candidateText(fixture.database)).toContain("Microsoft IIS");
    expect(candidateText(fixture.database)).toContain("Execution timeout");
  });
});

function registerExistingSqlite(
  fixture: ReturnType<typeof setup>,
  path: string,
  type: "kanban_sqlite" | "conversation_state_sqlite",
  bytes: Uint8Array,
): LegacySource {
  const root = join(fixture.root, "history");
  const state = statSync(path);
  const source: LegacySource = {
    absolutePath: path,
    relativePath: basename(path),
    root,
    type,
    sha256: sha256(bytes),
    byteSize: bytes.byteLength,
    modifiedAt: state.mtime.toISOString(),
  };
  const sourceId = fixture.metadata.registerSource(fixture.migrationId, source, undefined, {
    retentionMode: "verified-reference",
    device: state.dev,
    inode: state.ino,
  });
  fixture.metadata.registerSourceObject({
    migrationId: fixture.migrationId,
    sourceId,
    objectKey: "source",
    sourcePath: path,
    objectKind: "source",
    classification: type,
    sourceSha256: source.sha256,
    byteSize: source.byteSize,
    modifiedAt: source.modifiedAt,
    sourceDevice: state.dev,
    sourceInode: state.ino,
  });
  return source;
}

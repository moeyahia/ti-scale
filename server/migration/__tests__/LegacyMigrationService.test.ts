import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdtempSync } from "node:fs";
import {
  createDatabaseConnection,
  migrateDatabase,
} from "../../db";
import { LegacyMigrationService, restoreMigrationBackup } from "../LegacyMigrationService";
import { discoverLegacySources } from "../SourceDiscovery";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const path = mkdtempSync(join(tmpdir(), "ti-scale-import-migration-"));
  temporaryDirectories.push(path);
  return path;
}

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) rmSync(path, { recursive: true, force: true });
});

function writeJson(path: string, value: unknown): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function createCanonicalDatabase(path: string): void {
  const database = createDatabaseConnection({ filename: path });
  try { migrateDatabase(database); }
  finally { database.close(); }
}

function createKanban(path: string): void {
  const database = createDatabaseConnection({ filename: path });
  try {
    database.exec(`
      CREATE TABLE tasks (
        id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT, assignee TEXT,
        status TEXT NOT NULL, created_at INTEGER NOT NULL, started_at INTEGER,
        completed_at INTEGER, engagement TEXT, result TEXT, last_failure_error TEXT,
        agent_provider TEXT
      );
    `);
    database.prepare(`
      INSERT INTO tasks (
        id, title, body, status, created_at, completed_at, engagement,
        result, agent_provider
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      "task-1",
      "Review authorized service",
      "Preserve a historical board objective",
      "done",
      1_700_000_000,
      1_700_000_100,
      "lab-a",
      "complete",
      "grok",
    );
    database.pragma("wal_checkpoint(TRUNCATE)");
  } finally { database.close(); }
}

function createConversationState(path: string): void {
  const database = createDatabaseConnection({ filename: path });
  try {
    database.exec(`
      CREATE TABLE sessions (
        id TEXT PRIMARY KEY, source TEXT NOT NULL, model TEXT,
        system_prompt TEXT, started_at REAL NOT NULL, ended_at REAL,
        end_reason TEXT, input_tokens INTEGER, output_tokens INTEGER,
        estimated_cost_usd REAL, title TEXT
      );
      CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
        role TEXT NOT NULL, content TEXT, tool_name TEXT, timestamp REAL NOT NULL,
        token_count INTEGER, finish_reason TEXT
      );
    `);
    database.prepare("INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
      "conversation-session",
      "cli",
      "provider-model",
      "system token=must-not-import",
      1_700_000_000,
      1_700_000_100,
      "completed",
      10,
      20,
      0,
      "Historical session",
    );
    database.prepare("INSERT INTO messages (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)").run(
      "conversation-session",
      "user",
      "password=conversation-secret",
      1_700_000_001,
    );
    // The production importer deliberately rejects live SQLite sources with
    // uncheckpointed WAL state. Make this fixture represent a quiescent Conversation
    // database instead of weakening that safety boundary for the test.
    database.pragma("wal_checkpoint(TRUNCATE)");
  } finally { database.close(); }
}

function createLegacyFixture(root: string): void {
  writeJson(join(root, "runtime/runs/run-1.json"), {
    run: {
      id: "run-1",
      objective: "Assess the authorized example service",
      status: "completed",
      engagement: "lab-a",
      providerKind: "grok",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:10:00.000Z",
      endedAt: "2026-01-01T00:10:00.000Z",
    },
    steps: [{
      id: "step-1",
      index: 0,
      title: "Passive fingerprint",
      purpose: "Collect service metadata",
      successCriteria: "Unique service metadata captured",
      dependencies: [],
      riskLevel: "read-only",
      status: "completed",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:05:00.000Z",
    }],
    evidence: [{
      id: "evidence-1",
      kind: "finding",
      label: "Service metadata",
      content: "password=should-never-enter-canonical",
      createdAt: "2026-01-01T00:05:00.000Z",
    }],
  });
  writeJson(join(root, "sessions/session-1.json"), {
    id: "session-1",
    createdAt: "2026-01-01T00:00:00.000Z",
    messages: [
      { id: "m1", role: "user", content: "Use password=super-secret-value", timestamp: "2026-01-01T00:00:00.000Z" },
      { id: "m2", role: "assistant", content: "Proceed only in authorized scope", timestamp: "2026-01-01T00:01:00.000Z" },
    ],
  });
  mkdirSync(join(root, "llm-logs"), { recursive: true });
  writeFileSync(join(root, "llm-logs/raw.jsonl"), [
    JSON.stringify({ type: "model_text", role: "assistant", provider: "grok", model: "grok", content: "token=raw-provider-secret", timestamp: "2026-01-01T00:03:00.000Z" }),
    JSON.stringify({ type: "model_thinking", role: "assistant", provider: "grok", reasoning: "private internal reasoning", timestamp: "2026-01-01T00:03:01.000Z" }),
  ].join("\n"));
  mkdirSync(join(root, "logs"), { recursive: true });
  writeFileSync(join(root, "logs/dashboard.log"), "2026-01-01 info password=dashboard-secret\n", { mode: 0o600 });
  mkdirSync(join(root, "runtime"), { recursive: true });
  writeFileSync(join(root, "runtime/events.jsonl"), [
    JSON.stringify({ id: "event-1", type: "step_completed", agentRunId: "run-1", timestamp: "2026-01-01T00:05:00.000Z", data: { password: "hidden" } }),
    "{malformed",
  ].join("\n"));
  writeJson(join(root, "runtime/memory/items.json"), [
    { id: "preference-1", type: "user_preference", content: "Prefer concise evidence summaries", confidence: 0.8, timestamp: "2026-01-01T00:00:00.000Z" },
    { id: "target-fact", type: "engagement_fact", content: "Target-specific fact must remain isolated", confidence: 0.9 },
    { id: "secret-memory", type: "tool_observation", content: "FLAG{do-not-store}" },
  ]);
  writeJson(join(root, "runtime/training/lessons.json"), [
    {
      id: "lesson-1",
      category: "verified_attack_lesson",
      kind: "attack_chain",
      title: "Validate service identity before deeper testing",
      techniqueName: "Service identity validation",
      techniqueCategory: "recon",
      summary: "Correlate two independent read-only fingerprints before selecting a technique.",
      prerequisites: ["Authorized target scope"],
      observedSignals: ["Two matching service identifiers"],
      stepsThatWorked: ["Collect metadata", "Compare independent fingerprints"],
      toolsUsed: ["nmap"],
      references: ["https://nmap.org/book/man-version-detection.html"],
      evidenceIds: [],
      sourceStepIds: [],
      verificationMethod: "Independent metadata agrees",
      outcome: "Reduced service-identification uncertainty",
      confidence: 0.8,
      reuseGuidance: "Use before version-specific validation",
      antiReuseWarnings: ["Do not treat one banner as proof"],
      failedAttempts: ["If fingerprints disagree, collect a second protocol-safe observation before retrying"],
      scope: "global",
      status: "verified",
      createdAt: "2026-01-01T00:00:00.000Z",
    },
    {
      id: "lesson-box",
      title: "HTB box shortcut",
      techniqueName: "Target shortcut",
      techniqueCategory: "recon",
      summary: "Follow a walkthrough for 10.10.10.10",
    },
    {
      id: "lesson-literal-command",
      kind: "attack_chain",
      title: "Literal command must be rejected",
      techniqueName: "Service validation",
      techniqueCategory: "recon",
      summary: "Collect a bounded service response.",
      prerequisites: ["Confirmed authorization"],
      observedSignals: ["A service response is available"],
      stepsThatWorked: ["nmap -sV victim"],
      toolsUsed: ["nmap"],
      references: ["https://nmap.org/book/man-version-detection.html"],
      verificationMethod: "Confirm a verified response artifact",
      failedAttempts: ["Change conditions before a bounded retry"],
      confidence: 0.6,
      scope: "global",
    },
    {
      id: "lesson-walkthrough-url",
      kind: "attack_chain",
      title: "Walkthrough reference must be rejected",
      techniqueName: "Service validation",
      techniqueCategory: "recon",
      summary: "Collect a bounded service response.",
      prerequisites: ["Confirmed authorization"],
      observedSignals: ["A service response is available"],
      stepsThatWorked: ["Use nmap against <TARGET_HOST>"],
      toolsUsed: ["nmap"],
      references: ["https://example.org/lab-walkthrough-solution"],
      verificationMethod: "Confirm a verified response artifact",
      failedAttempts: ["Change conditions before a bounded retry"],
      confidence: 0.6,
      scope: "global",
    },
  ]);
  mkdirSync(join(root, "artifacts"), { recursive: true });
  writeFileSync(join(root, "artifacts/report.txt"), "historical artifact body", { mode: 0o600 });
  writeFileSync(join(root, "artifacts/id_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\nnever-copy\n", { mode: 0o600 });
  createKanban(join(root, "kanban.db"));
  writeJson(join(root, "auth.json"), { token: "must-not-copy" });
  writeJson(join(root, "sessions/request_dump_unsafe.json"), { authorization: "must-not-copy" });
}

describe("legacy source discovery", () => {
  test("allowlists supported sources and excludes secret/request dump files", async () => {
    const root = temporaryDirectory();
    createLegacyFixture(root);
    const inventory = await discoverLegacySources([root]);
    const paths = inventory.included.map((item) => item.relativePath);
    expect(paths).toContain("runtime/runs/run-1.json");
    expect(paths).toContain("runtime/training/lessons.json");
    expect(paths).toContain("kanban.db");
    expect(paths).not.toContain("auth.json");
    expect(paths).not.toContain("sessions/request_dump_unsafe.json");
    expect(paths).not.toContain("artifacts/id_ed25519");
    expect(inventory.included.every((item) => item.sha256.length === 64)).toBe(true);
  });
});

describe("LegacyMigrationService", () => {
  test("dry run hashes inventory and writes a report without touching canonical state", async () => {
    const root = temporaryDirectory();
    const legacy = join(root, "legacy");
    const output = join(root, "migration-output");
    const databasePath = join(root, "ti-scale.sqlite");
    createLegacyFixture(legacy);
    createCanonicalDatabase(databasePath);

    const before = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    const beforeCounts = {
      migrations: (before.prepare("SELECT COUNT(*) AS count FROM legacy_migration_runs").get() as { count: number }).count,
      memoryCandidates: (before.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get() as { count: number }).count,
      attackBundles: (before.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_bundles").get() as { count: number }).count,
    };
    before.close();

    const result = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy],
      outputDirectory: output,
      dryRun: true,
    }).run();

    expect(result.report.dryRun).toBe(true);
    expect(result.report.counts.sources).toBeGreaterThanOrEqual(7);
    expect(result.report.databaseBackup).toBeUndefined();
    const database = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect((database.prepare("SELECT COUNT(*) AS count FROM legacy_migration_runs").get() as { count: number }).count)
        .toBe(beforeCounts.migrations);
      expect((database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get() as { count: number }).count)
        .toBe(beforeCounts.memoryCandidates);
      expect((database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_bundles").get() as { count: number }).count)
        .toBe(beforeCounts.attackBundles);
    } finally { database.close(); }
  });

  test("supports an explicit forward-only import without database or source copies", async () => {
    const root = temporaryDirectory();
    const legacy = join(root, "legacy");
    const output = join(root, "migration-output");
    const databasePath = join(root, "ti-scale.sqlite");
    mkdirSync(join(legacy, "logs"), { recursive: true });
    writeFileSync(
      join(legacy, "logs", "dashboard.log"),
      "2026-07-24 info reusable service fingerprint recorded\n",
      { mode: 0o600 },
    );
    createCanonicalDatabase(databasePath);

    const result = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy],
      outputDirectory: output,
      databaseBackupMode: "disabled",
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
    }).run();

    expect(result.report.databaseBackup).toBeUndefined();
    expect(result.report.sourceBackup).toBeUndefined();
    expect(result.report.sourceRetention).toMatchObject({
      mode: "verified-reference",
      protectedSourceCopyCreated: false,
    });
    expect(existsSync(join(output, "database-backups"))).toBe(false);
    expect(existsSync(join(output, result.migrationId, "sources"))).toBe(false);
  });

  test("imports dashboard logs across transaction-batch boundaries and remains idempotent", async () => {
    const root = temporaryDirectory();
    const legacy = join(root, "legacy");
    const output = join(root, "migration-output");
    const databasePath = join(root, "ti-scale.sqlite");
    const logPath = join(legacy, "logs", "dashboard.log");
    mkdirSync(join(legacy, "logs"), { recursive: true });
    writeFileSync(logPath, `${Array.from({ length: 2_105 }, (_, index) => JSON.stringify({
      level: "info",
      message: `Synthetic migration record ${index + 1}`,
      timestamp: "2026-07-15T00:00:00.000Z",
    })).join("\n")}\n`, { mode: 0o600 });
    createCanonicalDatabase(databasePath);

    const first = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy],
      outputDirectory: output,
    }).run();
    expect(first.report.counts.imported).toBe(2_105);
    const database = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect((database.prepare("SELECT COUNT(*) AS count FROM structured_logs").get() as { count: number }).count)
        .toBe(2_105);
    } finally { database.close(); }

    const second = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy],
      outputDirectory: output,
    }).run();
    expect(second.report.counts.imported).toBe(0);
    expect(second.report.counts.deduplicated).toBe(2_105);
  });

  test("imports conservatively without retained copies, quarantines malformed/unsafe records, and deduplicates", async () => {
    const root = temporaryDirectory();
    const legacy = join(root, "legacy");
    const output = join(root, "migration-output");
    const databasePath = join(root, "ti-scale.sqlite");
    createLegacyFixture(legacy);
    createCanonicalDatabase(databasePath);
    const originalRun = readFileSync(join(legacy, "runtime/runs/run-1.json"));

    const first = await new LegacyMigrationService({ databasePath, sourceRoots: [legacy], outputDirectory: output }).run();
    expect(first.report.dryRun).toBe(false);
    expect(first.report.counts.imported).toBeGreaterThan(5);
    expect(first.report.counts.quarantined).toBeGreaterThanOrEqual(3);
    expect(first.report.databaseBackup).toBeUndefined();
    expect(first.report.rollback).toBeUndefined();
    expect(first.report.sourceBackup).toBeUndefined();
    expect(first.report.sourceReferences?.sourceBytesCopied).toBe(false);
    expect(existsSync(join(output, "database-backups"))).toBe(false);
    expect(existsSync(join(output, first.migrationId, "sources"))).toBe(false);
    expect(readFileSync(join(legacy, "runtime/runs/run-1.json")).equals(originalRun)).toBe(true);

    const database = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect((database.prepare("SELECT COUNT(*) AS count FROM missions").get() as { count: number }).count).toBeGreaterThanOrEqual(2);
      expect((database.prepare("SELECT COUNT(*) AS count FROM runs").get() as { count: number }).count).toBe(2);
      expect(database.prepare("SELECT DISTINCT control_plane FROM missions").all())
        .toEqual([{ control_plane: "legacy" }]);
      expect(database.prepare("SELECT DISTINCT control_plane FROM runs").all())
        .toEqual([{ control_plane: "legacy" }]);
      expect((database.prepare("SELECT COUNT(*) AS count FROM plan_steps").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM evidence").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM evidence_chain_events").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM conversations").get() as { count: number }).count).toBe(2);
      expect((database.prepare("SELECT COUNT(*) AS count FROM messages").get() as { count: number }).count).toBe(4);
      expect((database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM lessons WHERE status='proposed'").get() as { count: number }).count)
        .toBeGreaterThanOrEqual(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM lesson_attack_chain_details").get() as { count: number }).count).toBe(1);
      const importedChain = database.prepare(`
        SELECT item_type, ordinal, content FROM lesson_attack_chain_items
        ORDER BY item_type, ordinal
      `).all() as Array<{ item_type: string; ordinal: number; content: string }>;
      expect(importedChain.filter((item) => item.item_type === "ordered_step").map((item) => item.content))
        .toEqual(["Collect metadata", "Compare independent fingerprints"]);
      expect(importedChain.some((item) => item.item_type === "tool" && item.content === "nmap")).toBe(true);
      expect(importedChain.some((item) => item.item_type === "public_reference" && item.content.includes("nmap.org"))).toBe(true);
      expect(importedChain.some((item) => item.item_type === "validation_checkpoint")).toBe(true);
      expect(importedChain.some((item) => item.item_type === "failure_recovery")).toBe(true);
      const rejectedChains = database.prepare(`
        SELECT item_key, reason FROM legacy_migration_quarantine
        WHERE item_key IN ('lesson:lesson-box', 'lesson:lesson-literal-command', 'lesson:lesson-walkthrough-url')
        ORDER BY item_key
      `).all() as Array<{ item_key: string; reason: string }>;
      expect(rejectedChains.map((item) => item.item_key)).toEqual([
        "lesson:lesson-box",
        "lesson:lesson-literal-command",
        "lesson:lesson-walkthrough-url",
      ]);
      expect((database.prepare("SELECT COUNT(*) AS count FROM artifacts").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM events").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM event_outbox WHERE status='delivered'").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE action='legacy_migration_completed'").get() as { count: number }).count).toBe(1);
      const canonicalText = [
        ...(database.prepare("SELECT body AS text FROM messages").all() as Array<{ text: string }>),
        ...(database.prepare("SELECT extracted_text AS text FROM evidence").all() as Array<{ text: string }>),
        ...(database.prepare("SELECT body AS text FROM memory_candidates").all() as Array<{ text: string }>),
        ...(database.prepare("SELECT statement AS text FROM lessons").all() as Array<{ text: string }>),
        ...(database.prepare("SELECT message AS text FROM structured_logs").all() as Array<{ text: string }>),
      ].map((row) => row.text ?? "").join("\n");
      expect(canonicalText).not.toContain("super-secret-value");
      expect(canonicalText).not.toContain("should-never-enter-canonical");
      expect(canonicalText).not.toContain("FLAG{do-not-store}");
      expect(canonicalText).not.toContain("raw-provider-secret");
      expect(canonicalText).not.toContain("private internal reasoning");
      expect(canonicalText).not.toContain("dashboard-secret");
      const states = database.prepare("SELECT DISTINCT authorization_status FROM missions").all() as Array<{ authorization_status: string }>;
      expect(states.map((row) => row.authorization_status)).toEqual(["unverified"]);
    } finally { database.close(); }

    const second = await new LegacyMigrationService({ databasePath, sourceRoots: [legacy], outputDirectory: output }).run();
    expect(second.report.counts.deduplicated).toBeGreaterThan(5);
    expect(second.report.counts.imported).toBe(0);
    expect(second.report.counts.quarantined).toBe(0);
    expect(second.report.targets.messages).toBe(4);
    expect(second.report.targets.missions).toBeGreaterThanOrEqual(1);

    writeJson(join(legacy, "sessions/session-1.json"), {
      id: "session-1",
      createdAt: "2026-01-01T00:00:00.000Z",
      messages: [
        { id: "m1", role: "user", content: "Use password=super-secret-value", timestamp: "2026-01-01T00:00:00.000Z" },
        { id: "m2", role: "assistant", content: "Proceed only in authorized scope", timestamp: "2026-01-01T00:01:00.000Z" },
        { id: "m3", role: "assistant", content: "New append-only message", timestamp: "2026-01-01T00:02:00.000Z" },
      ],
    });
    const incremental = await new LegacyMigrationService({ databasePath, sourceRoots: [legacy], outputDirectory: output }).run();
    expect(incremental.report.counts.imported).toBe(1);
    const incrementedDatabase = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect((incrementedDatabase.prepare("SELECT COUNT(*) AS count FROM messages").get() as { count: number }).count).toBe(5);
    } finally { incrementedDatabase.close(); }

    const writable = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      writable.prepare("UPDATE legacy_migration_runs SET status='failed' WHERE id=?").run(first.migrationId);
    } finally { writable.close(); }
    await expect(new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy],
      outputDirectory: output,
      resumeMigrationId: first.migrationId,
    }).run()).rejects.toThrow(/inventory.*receipt/u);
  });

  test("rejects protected copies, database backups, and restore before filesystem mutation", async () => {
    const root = temporaryDirectory();
    const legacy = join(root, "legacy");
    const output = join(root, "migration-output");
    const databasePath = join(root, "ti-scale.sqlite");
    mkdirSync(legacy, { recursive: true });
    createCanonicalDatabase(databasePath);
    const databaseBefore = readFileSync(databasePath);

    await expect(new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy],
      outputDirectory: output,
      sourceRetention: "protected-copy",
    }).run()).rejects.toThrow("Protected-copy legacy migration is disabled");
    await expect(new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy],
      outputDirectory: output,
      databaseBackupMode: "verified",
    }).run()).rejects.toThrow("Database backup creation is disabled");

    const nonexistentBackup = join(root, "must-not-be-opened.sqlite");
    await expect(restoreMigrationBackup({
      databasePath,
      backupPath: nonexistentBackup,
      expectedSha256: "0".repeat(64),
      serviceStopped: true,
    })).rejects.toThrow("restore is disabled by operator policy");

    expect(readFileSync(databasePath).equals(databaseBefore)).toBe(true);
    expect(existsSync(nonexistentBackup)).toBe(false);
    expect(existsSync(output)).toBe(false);
    expect(readdirSync(root).some((entry) =>
      entry.includes("backup") || entry.includes("rollback") || entry.endsWith(".restore")
    )).toBe(false);
  });

  test("refuses an active SQLite source with uncheckpointed WAL state", async () => {
    const root = temporaryDirectory();
    const legacy = join(root, "legacy");
    const output = join(root, "migration-output");
    const databasePath = join(root, "ti-scale.sqlite");
    mkdirSync(legacy, { recursive: true });
    createCanonicalDatabase(databasePath);
    const kanban = createDatabaseConnection({ filename: join(legacy, "kanban.db") });
    try {
      kanban.exec("CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT, status TEXT, created_at INTEGER)");
      kanban.prepare("INSERT INTO tasks VALUES (?, ?, ?, ?)").run("active", "Active writer", "running", 1_700_000_000);
      await expect(new LegacyMigrationService({
        databasePath,
        sourceRoots: [legacy],
        outputDirectory: output,
      }).run()).rejects.toThrow("non-empty WAL");
    } finally { kanban.close(); }
  });

  test("imports the Conversation session index without system prompts or secrets", async () => {
    const root = temporaryDirectory();
    const legacy = join(root, "legacy");
    const output = join(root, "migration-output");
    const databasePath = join(root, "ti-scale.sqlite");
    mkdirSync(legacy, { recursive: true });
    createCanonicalDatabase(databasePath);
    createConversationState(join(legacy, "state.db"));

    await new LegacyMigrationService({ databasePath, sourceRoots: [legacy], outputDirectory: output }).run();
    const database = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect((database.prepare("SELECT COUNT(*) AS count FROM conversations").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM messages").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM provider_turns").get() as { count: number }).count).toBe(1);
      const body = (database.prepare("SELECT body FROM messages").get() as { body: string }).body;
      expect(body).not.toContain("conversation-secret");
      expect(body).not.toContain("system token");
    } finally { database.close(); }
  });
});

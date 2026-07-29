import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection } from "../../db";
import {
  discoverLegacyHistoricalSources,
  parseLegacyHistoricalSource,
  type LegacyHistoricalSource,
} from "../LegacyHistoricalSourceAdapter";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-history-adapter-"));
  temporaryDirectories.push(directory);
  return directory;
}

function write(path: string, value: string): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, value, { encoding: "utf8", mode: 0o600 });
}

function sqlite(path: string, statements: readonly string[]): void {
  mkdirSync(join(path, ".."), { recursive: true });
  const database = createDatabaseConnection({ filename: path, verifyIntegrity: false });
  try {
    statements.forEach((statement) => database.exec(statement));
    database.pragma("wal_checkpoint(TRUNCATE)");
    database.pragma("journal_mode = DELETE");
  } finally { database.close(); }
}

interface Fixture {
  readonly root: string;
  readonly alias: string;
  readonly duplicateRoot: string;
  readonly vault: string;
  readonly currentDatabase: string;
}

function fixture(): Fixture {
  const base = temporaryDirectory();
  const root = join(base, "history");
  const alias = join(base, "history-alias");
  const duplicateRoot = join(base, "stale-copy");
  const vault = join(base, "Old ChillsPwn Brain");
  const currentDatabase = join(root, "active", "ti-scale.sqlite");
  mkdirSync(root, { recursive: true });
  symlinkSync(root, alias);

  write(join(root, ".claude", "projects", "client-a", "session.jsonl"), [
    JSON.stringify({ type: "assistant", message: "Identified a reusable worker-health precondition", timestamp: "2026-07-14T01:00:00Z" }),
    "{malformed",
  ].join("\n"));
  write(join(root, ".grok", "sessions", "nested", "session.json"), JSON.stringify({
    sessions: [{ id: "grok-1", messages: [{ role: "assistant", content: "Use a bounded health probe" }] }],
  }));
  write(join(root, "sessions", "archive", "archived.json"), JSON.stringify({
    messages: [{ role: "operator", content: "The execution worker hung after the second stage" }],
  }));
  write(join(root, "session-logs", "session-1.system.txt"), "Supervisor detected a no-progress loop\nRecovery required a worker recycle\n");
  write(join(root, ".codex", "logs", "client.log"), "safe client event\nHTB{must_be_quarantined}\n");
  write(join(root, "exports", "command-os-v2-export.json"), JSON.stringify({
    schemaVersion: "2.4",
    missions: [{ id: "private-history-only", target: "10.129.39.191", result: "worker hang" }],
  }));
  write(join(duplicateRoot, "session-logs", "session-copy.system.txt"), "Supervisor detected a no-progress loop\nRecovery required a worker recycle\n");

  mkdirSync(join(vault, ".obsidian"), { recursive: true });
  write(join(vault, "Attack Patterns", "Worker Hang.md"), [
    "---",
    "type: failure",
    "status: candidate",
    "---",
    "A staged diagnostic can wedge the worker. Link [[Worker recycle]] and [[Health probe]].",
  ].join("\n"));

  sqlite(join(root, "mission-board.db"), [
    "CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT, status TEXT)",
    "INSERT INTO tasks VALUES ('task-1', 'Review the worker hang', 'blocked')",
  ]);
  sqlite(join(root, ".codex", "state.sqlite"), [
    "CREATE TABLE threads (id TEXT PRIMARY KEY, title TEXT, updated_at TEXT)",
    "INSERT INTO threads VALUES ('thread-1', 'Historical analysis', '2026-07-14T02:00:00Z')",
  ]);
  sqlite(join(root, "exports", "command-os-v2.sqlite"), [
    "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)",
    "CREATE TABLE missions (id TEXT PRIMARY KEY, name TEXT)",
    "CREATE TABLE runs (id TEXT PRIMARY KEY, mission_id TEXT, status TEXT)",
    "INSERT INTO schema_migrations VALUES (14)",
    "INSERT INTO missions VALUES ('legacy-mission', 'Private historical mission')",
    "INSERT INTO runs VALUES ('legacy-run', 'legacy-mission', 'failed')",
  ]);
  sqlite(currentDatabase, [
    "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)",
    "CREATE TABLE missions (id TEXT PRIMARY KEY, name TEXT)",
    "CREATE TABLE runs (id TEXT PRIMARY KEY, mission_id TEXT, status TEXT)",
    "INSERT INTO schema_migrations VALUES (28)",
  ]);
  return { root, alias, duplicateRoot, vault, currentDatabase };
}

describe("LegacyHistoricalSourceAdapter", () => {
  test("discovers missed sources as one hash-bound manifest while excluding aliases, stale copies, and the active DB", async () => {
    const input = fixture();
    const first = await discoverLegacyHistoricalSources({
      roots: [input.root, input.alias, input.duplicateRoot, input.vault],
      canonicalDatabasePaths: [input.currentDatabase],
    });
    const second = await discoverLegacyHistoricalSources({
      roots: [input.root, input.alias, input.duplicateRoot, input.vault],
      canonicalDatabasePaths: [input.currentDatabase],
    });

    expect(first.schemaVersion).toBe("ti_scale.legacy_historical_manifest/v1");
    expect(first.verificationState).toBe("verified");
    expect(first.manifestHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(second.manifestHash).toBe(first.manifestHash);
    expect(second.sources.map(({ id }) => id)).toEqual(first.sources.map(({ id }) => id));
    expect(new Set(first.sources.map(({ kind }) => kind))).toEqual(new Set([
      "grok_nested_session",
      "claude_project_jsonl",
      "session_archive",
      "session_system_text",
      "root_client_log",
      "mission_board_sqlite",
      "codex_sqlite",
      "obsidian_note",
      "prior_v2_export",
      "prior_v2_sqlite",
    ]));
    expect(first.rootAliases).toHaveLength(1);
    expect(first.excluded.some(({ category }) => category === "canonical_database")).toBe(true);
    expect(first.excluded.some(({ category }) => category === "duplicate_content")).toBe(true);
    expect(first.sources.some(({ canonicalPath }) => canonicalPath === input.currentDatabase)).toBe(false);
  });

  test("parses only bounded private/local candidates, quarantines malformed and secret records, and is idempotent", async () => {
    const input = fixture();
    const discovery = await discoverLegacyHistoricalSources({
      roots: [input.root, input.vault],
      canonicalDatabasePaths: [input.currentDatabase],
    });
    const first = discovery.sources.map((source) => parseLegacyHistoricalSource(source, { maximumRecords: 20 }));
    const second = discovery.sources.map((source) => parseLegacyHistoricalSource(source, { maximumRecords: 20 }));
    const candidates = first.flatMap(({ candidates: items }) => items);
    const quarantined = first.flatMap(({ quarantined: items }) => items);

    expect(candidates.length).toBeGreaterThanOrEqual(11);
    expect(candidates.every((item) => item.sensitivity === "private")).toBe(true);
    expect(candidates.every((item) => item.disclosure === "local_only")).toBe(true);
    expect(candidates.every((item) => item.lifecycle === "candidate")).toBe(true);
    expect(candidates.every((item) => item.reusableMemoryEligible === false)).toBe(true);
    expect(candidates.every((item) => item.projectionPolicy.mode === "attack_knowledge_only")).toBe(true);
    expect(candidates.every((item) => item.projectionPolicy.forbiddenReusableFields.includes("target"))).toBe(true);
    expect(candidates.every((item) => !item.title.includes("10.129.39.191"))).toBe(true);
    expect(candidates.every((item) => !item.summary.includes(input.root))).toBe(true);
    expect(JSON.stringify(candidates)).not.toContain("HTB{must_be_quarantined}");
    expect(quarantined.some(({ category }) => category === "malformed")).toBe(true);
    expect(quarantined.some(({ category }) => category === "secret_bearing")).toBe(true);
    expect(second.map(({ candidates: items }) => items.map(({ id }) => id)))
      .toEqual(first.map(({ candidates: items }) => items.map(({ id }) => id)));
    const note = candidates.find(({ sourceKind }) => sourceKind === "obsidian_note");
    expect(note?.privatePayload).toMatchObject({ wikilinks: ["Worker recycle", "Health probe"] });
  });

  test("fails closed without the canonical DB exclusion and bounds records, SQLite WALs, size, and post-discovery changes", async () => {
    const input = fixture();
    await expect(discoverLegacyHistoricalSources({ roots: [input.root], canonicalDatabasePaths: [] })).rejects.toThrow(
      "canonical Ti-Scale database path",
    );

    const oversized = join(input.root, "session-logs", "oversized.system.txt");
    write(oversized, "x".repeat(1_024));
    const unsafeBoard = join(input.root, "unsafe", "mission-board.db");
    sqlite(unsafeBoard, ["CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT)"]);
    writeFileSync(`${unsafeBoard}-wal`, "active-wal", { mode: 0o600 });
    const bounded = await discoverLegacyHistoricalSources({
      roots: [input.root],
      canonicalDatabasePaths: [input.currentDatabase],
      maximumTextBytes: 512,
    });
    expect(bounded.excluded.some(({ category }) => category === "oversized")).toBe(true);
    expect(bounded.excluded.some(({ category, reason }) => category === "unsafe_sqlite" && reason.includes("WAL"))).toBe(true);

    const system = bounded.sources.find(({ kind }) => kind === "session_system_text") as LegacyHistoricalSource;
    const one = parseLegacyHistoricalSource(system, { maximumRecords: 1 });
    expect(one.candidates).toHaveLength(1);
    expect(one.quarantined.some(({ category }) => category === "record_limit")).toBe(true);
    write(system.canonicalPath, "changed after discovery\n");
    const changed = parseLegacyHistoricalSource(system);
    expect(changed.candidates).toHaveLength(0);
    expect(changed.quarantined).toEqual([
      expect.objectContaining({ category: "changed" }),
    ]);
  });
});

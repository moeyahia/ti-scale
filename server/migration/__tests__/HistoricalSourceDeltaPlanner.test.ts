import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
  type HistoricalSourceRootConfiguration,
} from "../HistoricalSourceRootConfiguration";
import { HistoricalSourceDeltaPlanner } from "../HistoricalSourceDeltaPlanner";
import {
  loadTrustedHistoricalSourceDeltaExecutionPlan,
  sealHistoricalSourceDeltaExecutionPlan,
} from "../HistoricalSourceDeltaExecutionPlan";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-delta-planner-"));
  roots.push(root);
  const engagement = join(root, "engagement");
  mkdirSync(join(engagement, "notes"), { recursive: true });
  mkdirSync(join(engagement, "logs"), { recursive: true });
  mkdirSync(join(engagement, "creds"), { recursive: true });
  const changed = join(engagement, "notes", "changed.md");
  const added = join(engagement, "notes", "new.md");
  const rawLog = join(engagement, "logs", "stream.log");
  const quarantined = join(engagement, "creds", "password.txt");
  writeFileSync(changed, "current safe technical note\n");
  writeFileSync(added, "new safe technical note\n");
  writeFileSync(rawLog, "raw operational line\n");
  writeFileSync(quarantined, "redacted fixture\n");
  const databasePath = join(root, "canonical.sqlite");
  const database = createDatabaseConnection({ filename: databasePath });
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO legacy_migration_runs (
      id, status, source_roots_json, database_path, output_directory,
      source_retention, source_retention_acknowledged_at,
      brain_projection_mode, brain_projection_acknowledged_at,
      started_at, completed_at
    ) VALUES (?, 'completed', '[]', ?, ?, 'verified-reference', ?,
      'attack-knowledge-only', ?, ?, ?)
  `).run(
    "migration_baseline",
    databasePath,
    join(root, "output"),
    "2026-01-01T00:00:00.000Z",
    "2026-01-01T00:00:00.000Z",
    "2026-01-01T00:00:00.000Z",
    "2026-01-01T00:01:00.000Z",
  );
  database.prepare(`
    INSERT INTO legacy_migration_inventory_receipts (
      migration_id, receipt_hash, object_count, byte_count, created_at
    ) VALUES (?, ?, 1, 1, ?)
  `).run("migration_baseline", "a".repeat(64), "2026-01-01T00:01:00.000Z");
  database.prepare(`
    INSERT INTO legacy_migration_sources (
      id, migration_id, source_path, relative_path, source_type,
      source_identity, source_sha256, byte_size, modified_at,
      source_reference, source_retention, source_device, source_inode,
      verified_at, status, discovered_at, completed_at
    ) VALUES (?, ?, ?, ?, 'engagement_manifest', ?, ?, 1, ?, ?,
      'verified-reference', 1, 1, ?, 'completed', ?, ?)
  `).run(
    "source_baseline",
    "migration_baseline",
    engagement,
    "engagement",
    "identity",
    "b".repeat(64),
    "2026-01-01T00:00:00.000Z",
    "legacy-private-source://baseline",
    "2026-01-01T00:00:00.000Z",
    "2026-01-01T00:00:00.000Z",
    "2026-01-01T00:01:00.000Z",
  );
  database.prepare(`
    INSERT INTO legacy_migration_source_objects (
      id, migration_id, source_id, object_key, source_reference, source_path,
      object_kind, classification, source_sha256, byte_size, modified_at,
      source_device, source_inode, verification_status, verified_at
    ) VALUES (?, ?, ?, 'changed.md', ?, ?, 'accepted', 'note', ?, 1, ?,
      1, 2, 'verified_reference', ?)
  `).run(
    "object_baseline",
    "migration_baseline",
    "source_baseline",
    "legacy-private-source://changed",
    changed,
    sha256("old safe technical note\n"),
    "2026-01-01T00:00:00.000Z",
    "2026-01-01T00:00:00.000Z",
  );
  const configuration: HistoricalSourceRootConfiguration = {
    schemaVersion: HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
    configurationVersion: "delta-test-v1",
    roots: [{ id: "reviewed-root", path: engagement, mode: "engagement-root", required: true }],
  };
  return { root, engagement, database, configuration };
}

describe("HistoricalSourceDeltaPlanner", () => {
  test("reports only aggregate changed/new/parser/sensitivity classes and never paths or content", async () => {
    const { root, engagement, database, configuration } = fixture();
    try {
      const result = await new HistoricalSourceDeltaPlanner(database).plan({
        configuration,
        configurationSha256: "c".repeat(64),
        settleSeconds: 60,
        now: new Date(Date.now() + 120_000),
      });
      expect(result.status).toBe("ready");
      expect(result.delta.files).toBe(4);
      expect(result.delta.newFiles).toBe(3);
      expect(result.delta.changedFiles).toBe(1);
      expect(result.delta.semanticParserEligibleFiles).toBe(2);
      expect(result.delta.custodyOnlyFiles).toBe(1);
      expect(result.delta.quarantinedFiles).toBe(1);
      expect(result.roots[0]?.rootId).toBe("reviewed-root");
      const publicReceipt = JSON.stringify(result);
      expect(publicReceipt).not.toContain(root);
      expect(publicReceipt).not.toContain(engagement);
      expect(publicReceipt).not.toContain("changed.md");
      expect(publicReceipt).not.toContain("current safe technical note");
      expect(result.safety).toEqual({
        sourcePathsExposed: false,
        sourceContentExposed: false,
        canonicalDatabaseOpenedReadOnly: true,
        canonicalDatabaseWrites: false,
        vaultWrites: false,
        sourceWrites: false,
        unchangedSourcesRequireReingestion: false,
      });
    } finally {
      database.close();
    }
  });

  test("marks an engagement root blocked when a non-empty SQLite WAL is present without hiding the other delta", async () => {
    const { engagement, database, configuration } = fixture();
    const sqlite = join(engagement, "session.sqlite");
    const wal = join(engagement, "session.sqlite-wal");
    writeFileSync(sqlite, "not parsed");
    writeFileSync(wal, "non-empty stale wal");
    const before = [sqlite, wal].map((path) => ({
      path,
      hash: sha256(readFileSync(path, "utf8")),
      modifiedAt: statSync(path).mtimeMs,
      size: statSync(path).size,
    }));
    try {
      const result = await new HistoricalSourceDeltaPlanner(database).plan({
        configuration,
        configurationSha256: "d".repeat(64),
        settleSeconds: 60,
        now: new Date(Date.now() + 120_000),
      });
      expect(result.status).toBe("blocked_active_sqlite");
      expect(result.current.activeSqliteFiles).toBe(1);
      expect(result.roots[0]?.status).toBe("blocked_active_sqlite");
      expect(result.delta.files).toBe(4);
      expect([sqlite, wal].map((path) => ({
        path,
        hash: sha256(readFileSync(path, "utf8")),
        modifiedAt: statSync(path).mtimeMs,
        size: statSync(path).size,
      }))).toEqual(before);
    } finally {
      database.close();
    }
  });

  test("seals exact private admissions at mode 0600 while the public plan remains path-free", async () => {
    const { root, engagement, database, configuration } = fixture();
    const privatePlanPath = join(root, "reviewed-delta.private.json");
    try {
      const planned = await new HistoricalSourceDeltaPlanner(database).planForExecution({
        configuration,
        configurationSha256: "e".repeat(64),
        settleSeconds: 60,
        now: new Date(Date.now() + 120_000),
      });
      const sealed = sealHistoricalSourceDeltaExecutionPlan({
        path: privatePlanPath,
        plan: planned.executionPlan,
        sourceRoots: [engagement],
      });
      expect(sealed.mode).toBe("0600");
      expect(statSync(privatePlanPath).mode & 0o777).toBe(0o600);
      expect(sealed.sourceSha256).toBe(sha256(readFileSync(privatePlanPath, "utf8")));
      const loaded = loadTrustedHistoricalSourceDeltaExecutionPlan({
        path: privatePlanPath,
        trustRoot: root,
        expectedSha256: sealed.sourceSha256,
        allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
      });
      expect(loaded.value.planHash).toBe(planned.executionPlan.planHash);
      expect(loaded.value.admissions).toHaveLength(4);
      expect(loaded.value.admissions.every(({ path }) => path.startsWith(engagement))).toBe(true);
      expect(JSON.stringify(planned.publicPlan)).not.toContain(engagement);
    } finally {
      database.close();
    }
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { discoverLegacyEngagements } from "../LegacyEngagementDiscovery";
import { LegacyEngagementImporter } from "../LegacyEngagementImporter";
import { LegacyMigrationService } from "../LegacyMigrationService";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";
import { ProtectedBackupStore } from "../ProtectedBackupStore";
import type { AttackKnowledgeExtractionBatchReport } from "../types";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-reference-migration-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function write(path: string, body: string): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, body, { mode: 0o600 });
}

function createDatabase(path: string): void {
  const database = createDatabaseConnection({ filename: path });
  try { migrateDatabase(database); }
  finally { database.close(); }
}

function count(database: ReturnType<typeof createDatabaseConnection>, table: string): number {
  return (database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count;
}

function files(root: string): string[] {
  if (!existsSync(root)) return [];
  const result: string[] = [];
  const pending = [root];
  while (pending.length) {
    const directory = pending.pop()!;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile()) result.push(path);
    }
  }
  return result.sort();
}

async function runCli(args: readonly string[]): Promise<{
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}> {
  const child = Bun.spawn([
    globalThis.process.execPath,
    "run",
    "server/migration/cli.ts",
    ...args,
  ], {
    cwd: globalThis.process.cwd(),
    env: globalThis.process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { exitCode, stdout, stderr };
}

function fixture(root: string): { sourceRoot: string; engagement: string; outsideSentinel: string } {
  const sourceRoot = join(root, "history");
  const engagement = join(sourceRoot, "historical-assessment");
  write(join(engagement, "notes", "summary.md"), "Reusable assessment notes without credentials.\n");
  write(join(engagement, "scans", "service.nmap"), [
    "Nmap scan report for 192.0.2.10",
    "Host is up.",
    "443/tcp open https nginx 1.24",
    "",
  ].join("\n"));
  write(join(engagement, "notes", "operator.txt"), "access_token=quarantined-reference-only\n");
  const outsideSentinel = "SYMLINK-TARGET-BYTES-MUST-NEVER-BE-READ";
  const outside = join(root, "outside.txt");
  write(outside, `${outsideSentinel}\n`);
  symlinkSync(outside, join(engagement, "notes", "linked.md"));
  write(join(sourceRoot, "runtime", "runs", "run-1.json"), JSON.stringify({
    run: { id: "run-1", objective: "Historical objective", status: "completed" },
  }));
  return { sourceRoot, engagement, outsideSentinel };
}

describe("verified-reference attack-knowledge-only migration", () => {
  test("inventories all source objects without copying bytes or creating target-centric domain and Brain rows", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "ti-scale.sqlite");
    const output = join(root, "migration-output");
    const source = fixture(root);
    createDatabase(databasePath);
    let handled = 0;
    let handlerSawWriteTransaction = true;

    const first = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [source.sourceRoot],
      outputDirectory: output,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
      attackKnowledgeManifestHandler: (_manifest, database) => {
        handled += 1;
        handlerSawWriteTransaction = database.inTransaction;
        const batch = (status: "completed" | "partial", filesParsed: number): AttackKnowledgeExtractionBatchReport => ({
          status,
          dryRun: false,
          manifestFingerprint: "f".repeat(64),
          filesDiscovered: 2,
          filesParsed,
          filesSkipped: 0,
          filesQuarantined: 0,
          bytesParsed: filesParsed * 10,
          semanticFactsParsed: filesParsed,
          ambiguousFragments: 0,
          compilerBundlesStaged: filesParsed,
          candidatesCreated: filesParsed,
          candidatesReused: 0,
          sourceEvidenceCandidatesCreated: filesParsed,
          sourceEvidenceCandidatesReused: 0,
          sourceBundleLinks: filesParsed,
          issues: [],
        });
        return [batch("partial", 1), batch("completed", 1)];
      },
    }).run();

    expect(handled).toBe(1);
    expect(handlerSawWriteTransaction).toBeFalse();
    expect(first.report.sourceBackup).toBeUndefined();
    expect(first.report.sourceRetention).toMatchObject({
      mode: "verified-reference",
      protectedSourceCopyCreated: false,
      referenceOnly: { acceptedObjects: 3, quarantinedObjects: 2, symbolicLinks: 1 },
    });
    expect(first.report.brainProjection).toEqual({
      mode: "attack-knowledge-only",
      legacyMissionRunAssetArtifactNodesCreated: false,
      acknowledgementRequired: true,
    });
    expect(first.report.attackKnowledgeExtraction).toMatchObject({
      semanticPreview: false,
      manifestsParsed: 1,
      batchesProcessed: 2,
      filesDiscovered: 2,
      filesParsed: 2,
      semanticFactsParsed: 2,
    });
    expect(first.report.sourceReferences?.sourceBytesCopied).toBe(false);
    expect(existsSync(join(output, first.migrationId, "sources"))).toBe(false);
    const outputText = files(join(output, first.migrationId)).map((path) => readFileSync(path, "utf8")).join("\n");
    expect(outputText).not.toContain(source.outsideSentinel);

    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      for (const table of ["missions", "runs", "artifacts", "memory_nodes", "memory_edges"]) {
        expect(count(database, table)).toBe(0);
      }
      expect(count(database, "legacy_migration_source_objects")).toBe(5);
      const receipt = database.prepare(`
        SELECT object_count, byte_count
        FROM legacy_migration_inventory_receipts WHERE migration_id = ?
      `).get(first.migrationId) as { object_count: number; byte_count: number };
      const custody = database.prepare(`
        SELECT COUNT(*) AS object_count, COALESCE(SUM(byte_size), 0) AS byte_count
        FROM legacy_migration_source_objects WHERE migration_id = ?
      `).get(first.migrationId) as { object_count: number; byte_count: number };
      expect(receipt).toEqual(custody);
      const persisted = database.prepare(`
        SELECT report_json FROM legacy_migration_reconciliation WHERE migration_id = ?
      `).get(first.migrationId) as { report_json: string };
      expect(JSON.parse(persisted.report_json)).toMatchObject({
        attackKnowledgeExtraction: {
          manifestsParsed: 1,
          batchesProcessed: 2,
          filesDiscovered: 2,
        },
      });
      expect((database.prepare(`
        SELECT COUNT(*) AS count FROM legacy_migration_source_objects
        WHERE verification_status = 'verified_reference'
          AND source_reference LIKE 'legacy-private-source://%'
      `).get() as { count: number }).count).toBe(5);
      expect((database.prepare(`
        SELECT COUNT(*) AS count FROM legacy_migration_sources
        WHERE source_retention = 'verified-reference' AND backup_relative_path IS NULL
          AND source_device IS NOT NULL AND source_inode IS NOT NULL
      `).get() as { count: number }).count).toBe(2);
      expect((database.prepare(`
        SELECT COUNT(*) AS count FROM legacy_migration_quarantine
        WHERE retention_mode = 'verified-reference' AND source_reference IS NOT NULL
          AND protected_backup_ref IS NULL AND protected_backup_sha256 IS NULL AND backup_mode IS NULL
      `).get() as { count: number }).count).toBe(2);
      expect(() => database.prepare(`
        UPDATE legacy_migration_source_objects SET classification = 'tampered'
        WHERE migration_id = ?
      `).run(first.migrationId)).toThrow("completed legacy migration source-object custody is immutable");
      expect(() => database.prepare(`
        DELETE FROM legacy_migration_source_objects WHERE migration_id = ?
      `).run(first.migrationId)).toThrow("completed legacy migration source-object custody is retained");
    } finally { database.close(); }

    const second = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [source.sourceRoot],
      outputDirectory: output,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
    }).run();
    expect(second.report.counts.imported).toBe(0);
    expect(second.report.counts.deduplicated).toBe(5);
    const afterReplay = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect(count(afterReplay, "missions")).toBe(0);
      expect(count(afterReplay, "legacy_migration_source_objects")).toBe(10);
      expect(count(afterReplay, "legacy_migration_quarantine")).toBe(2);
    } finally { afterReplay.close(); }
  });

  test("reference-backed compatibility artifacts never claim immutable copied storage", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "ti-scale.sqlite");
    const output = join(root, "migration-output");
    const source = fixture(root);
    createDatabase(databasePath);

    const migration = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [source.sourceRoot],
      outputDirectory: output,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
    }).run();
    expect(migration.report.sourceBackup).toBeUndefined();
    expect(migration.report.sourceReferences?.sourceBytesCopied).toBe(false);
    const database = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      const artifacts = database.prepare(`
        SELECT storage_uri, metadata_json FROM artifacts ORDER BY id
      `).all() as Array<{ storage_uri: string; metadata_json: string }>;
      expect(artifacts.length).toBeGreaterThan(0);
      for (const artifact of artifacts) {
        const metadata = JSON.parse(artifact.metadata_json) as {
          sourceRetention?: string;
          immutableCopiedStorage?: boolean;
          availabilityDependsOnOperatorSourceTree?: boolean;
        };
        expect(artifact.storage_uri).toMatch(/^legacy-private-(?:manifest-reference|source):\/\//u);
        expect(metadata.sourceRetention).toBe("verified-reference");
        expect(metadata.immutableCopiedStorage).toBe(false);
        expect(metadata.availabilityDependsOnOperatorSourceTree).toBe(true);
      }
    } finally { database.close(); }
  });

  test("rolls back inventory and extractor writes when a source races after preflight", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "ti-scale.sqlite");
    const source = fixture(root);
    createDatabase(databasePath);
    const discovery = await discoverLegacyEngagements([source.sourceRoot]);
    const manifest = discovery.manifests[0]!;
    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      const metadata = new MigrationMetadataRepository(database);
      metadata.ensureSchema();
      const migration = metadata.createRun({
        sourceRoots: [source.sourceRoot],
        databasePath,
        outputDirectory: join(root, "output"),
        sourceRetention: "verified-reference",
        verifiedReferenceAcknowledged: true,
        brainProjectionMode: "attack-knowledge-only",
        attackKnowledgeOnlyAcknowledged: true,
      });
      const importer = new LegacyEngagementImporter(
        database,
        metadata,
        migration.id,
        join(root, "unused-sources"),
        () => new Date("2026-07-20T00:00:00.000Z"),
        (backupRoot) => new ProtectedBackupStore(backupRoot),
        {
          sourceRetention: "verified-reference",
          verifiedReferenceAcknowledged: true,
          brainProjectionMode: "attack-knowledge-only",
          attackKnowledgeOnlyAcknowledged: true,
          testHooks: {
            afterVerifiedReferencePreflight: () => {
              writeFileSync(join(source.engagement, "notes", "summary.md"), "Changed during migration.\n", { mode: 0o600 });
            },
          },
        },
      );
      await expect(importer.importManifest(manifest)).rejects.toThrow(/changed|provenance/u);
      expect(count(database, "legacy_migration_source_objects")).toBe(0);
      expect(count(database, "legacy_migration_quarantine")).toBe(0);
      expect(count(database, "missions")).toBe(0);
    } finally { database.close(); }
    expect(existsSync(join(root, "unused-sources"))).toBe(false);
  });

  test("resumes an interrupted inventory idempotently with the same acknowledged modes", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "ti-scale.sqlite");
    const output = join(root, "migration-output");
    const source = fixture(root);
    createDatabase(databasePath);
    await expect(new LegacyMigrationService({
      databasePath,
      sourceRoots: [source.sourceRoot],
      outputDirectory: output,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
      attackKnowledgeManifestHandler: () => { throw new Error("simulated extractor interruption"); },
    }).run()).rejects.toThrow("simulated extractor interruption");

    const failed = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    let migrationId: string;
    try {
      const row = failed.prepare(`
        SELECT id, status FROM legacy_migration_runs ORDER BY started_at DESC LIMIT 1
      `).get() as { id: string; status: string };
      expect(row.status).toBe("failed");
      migrationId = row.id;
      // Private hash/inode inventory is a resumable staging record. It is
      // retained when semantic extraction stops, without creating target data.
      expect(count(failed, "legacy_migration_source_objects")).toBe(4);
    } finally { failed.close(); }

    const resumed = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [source.sourceRoot],
      outputDirectory: output,
      resumeMigrationId: migrationId!,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
    }).run();
    expect(resumed.migrationId).toBe(migrationId!);
    const verified = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect((verified.prepare("SELECT status FROM legacy_migration_runs WHERE id = ?").get(migrationId!) as { status: string }).status).toBe("completed");
      expect(count(verified, "missions")).toBe(0);
      expect(count(verified, "legacy_migration_source_objects")).toBe(5);
    } finally { verified.close(); }
  });

  test("rejects resume when the hash/size/mtime source inventory no longer matches", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "ti-scale.sqlite");
    const output = join(root, "migration-output");
    const source = fixture(root);
    createDatabase(databasePath);
    await expect(new LegacyMigrationService({
      databasePath,
      sourceRoots: [source.sourceRoot],
      outputDirectory: output,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
      attackKnowledgeManifestHandler: () => { throw new Error("stop after immutable inventory binding"); },
    }).run()).rejects.toThrow("stop after immutable inventory binding");
    const database = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    const migrationId = (database.prepare(`
      SELECT id FROM legacy_migration_runs ORDER BY started_at DESC LIMIT 1
    `).get() as { id: string }).id;
    database.close();
    write(join(source.engagement, "notes", "new-history.md"), "nginx 1.25 was newly added after the failed job.\n");

    await expect(new LegacyMigrationService({
      databasePath,
      sourceRoots: [source.sourceRoot],
      outputDirectory: output,
      resumeMigrationId: migrationId,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
    }).run()).rejects.toThrow(/inventory.*receipt/u);
  });

  test("uses the global no-copy policy by default and fails closed on explicit rejection or missing projection acknowledgement", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "ti-scale.sqlite");
    const source = fixture(root);
    createDatabase(databasePath);
    await expect(new LegacyMigrationService({
      databasePath,
      sourceRoots: [source.sourceRoot],
      outputDirectory: join(root, "output-a"),
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: false,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
    }).run()).rejects.toThrow("explicitly rejected");
    await expect(new LegacyMigrationService({
      databasePath,
      sourceRoots: [source.sourceRoot],
      outputDirectory: join(root, "output-b"),
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
    }).run()).rejects.toThrow("acknowledge-attack-knowledge-only");
    const database = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect((database.prepare(`
        SELECT COUNT(*) AS count FROM legacy_migration_runs
      `).get() as { count: number }).count).toBe(0);
    }
    finally { database.close(); }
  });

  test("CLI requires both acknowledgements and reports the zero-copy dry-run contract", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "ti-scale.sqlite");
    const source = fixture(root);
    const output = join(root, "migration-output");

    const missingReferenceAcknowledgement = await runCli([
      "migrate", "--db", databasePath, "--source", source.sourceRoot, "--output", output,
      "--source-retention", "verified-reference",
      "--brain-projection", "attack-knowledge-only",
      "--acknowledge-attack-knowledge-only",
      "--dry-run",
    ]);
    expect(missingReferenceAcknowledgement.exitCode).toBe(1);
    expect(missingReferenceAcknowledgement.stderr).toContain("--acknowledge-verified-reference");

    const missingProjectionAcknowledgement = await runCli([
      "migrate", "--db", databasePath, "--source", source.sourceRoot, "--output", output,
      "--source-retention", "verified-reference",
      "--acknowledge-verified-reference",
      "--brain-projection", "attack-knowledge-only",
      "--dry-run",
    ]);
    expect(missingProjectionAcknowledgement.exitCode).toBe(1);
    expect(missingProjectionAcknowledgement.stderr).toContain("--acknowledge-attack-knowledge-only");

    const accepted = await runCli([
      "migrate", "--db", databasePath, "--source", source.sourceRoot, "--output", output,
      "--source-retention", "verified-reference",
      "--acknowledge-verified-reference",
      "--brain-projection", "attack-knowledge-only",
      "--acknowledge-attack-knowledge-only",
      "--dry-run",
    ]);
    expect(accepted.exitCode).toBe(0);
    const result = JSON.parse(accepted.stdout) as { reportPath: string };
    const report = JSON.parse(readFileSync(result.reportPath, "utf8")) as {
      sourceRetention: {
        mode: string;
        protectedSourceCopyCreated: boolean;
        acknowledgementRequired: boolean;
        referenceOnly?: unknown;
      };
      brainProjection: {
        mode: string;
        legacyMissionRunAssetArtifactNodesCreated: boolean;
        acknowledgementRequired: boolean;
      };
      attackKnowledgeExtraction?: {
        semanticPreview: boolean;
        manifestsParsed: number;
        batchesProcessed: number;
        filesDiscovered: number;
        filesParsed: number;
        semanticFactsParsed: number;
        evidenceAutomaticallyVerified: number;
        reusableMemoryAutomaticallyPromoted: number;
      };
    };
    expect(report.sourceRetention).toEqual({
      mode: "verified-reference",
      protectedSourceCopyCreated: false,
      acknowledgementRequired: true,
      referenceOnly: expect.any(Object),
    });
    expect(report.brainProjection).toEqual({
      mode: "attack-knowledge-only",
      legacyMissionRunAssetArtifactNodesCreated: false,
      acknowledgementRequired: true,
    });
    expect(report.attackKnowledgeExtraction).toMatchObject({
      semanticPreview: true,
      manifestsParsed: 2,
      batchesProcessed: 2,
      filesDiscovered: 3,
      filesParsed: 1,
      evidenceAutomaticallyVerified: 0,
      reusableMemoryAutomaticallyPromoted: 0,
    });
    expect(report.attackKnowledgeExtraction!.semanticFactsParsed).toBeGreaterThan(0);
    expect(existsSync(databasePath)).toBe(false);
  });
});

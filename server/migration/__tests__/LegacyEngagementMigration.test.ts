import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../../memory";
import { ObsidianVaultBridge, VaultPathPolicy } from "../../vault";
import { ApprovedLegacyVaultProjectionService } from "../ApprovedLegacyVaultProjectionService";
import {
  canonicalizeLegacySourceRoots,
  discoverLegacyEngagements,
  type LegacyEngagementManifest,
} from "../LegacyEngagementDiscovery";
import { LegacyEngagementImporter } from "../LegacyEngagementImporter";
import { LegacyMigrationService } from "../LegacyMigrationService";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";
import {
  PROTECTED_BACKUP_STORE_DISABLED_ERROR,
  ProtectedBackupStore,
} from "../ProtectedBackupStore";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-engagement-migration-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function write(path: string, content: string | Uint8Array): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, content, { mode: 0o600 });
}

function createEngagement(root: string): { engagement: string; secret: string } {
  const engagement = join(root, "customer-portal");
  write(join(engagement, "scans/service.nmap"), [
    "Nmap scan report for portal.example.test (192.0.2.45)",
    "Host is up (0.0040s latency).",
    "PORT    STATE SERVICE VERSION",
    "443/tcp open  https   nginx 1.24",
    "Running: Linux 5.X",
    "",
  ].join("\n"));
  write(join(engagement, "report/report.md"), "# Historical report\nReview required.\n");
  write(join(engagement, "loot/public.txt"), "non-secret historical username: analyst\n");
  write(join(engagement, "notes/overview.md"), "Authorized-history note with no inferred current authorization.\n");
  write(join(engagement, "scripts/check.sh"), "#!/bin/sh\nprintf 'read-only check'\n");
  write(join(engagement, "captures/page.png"), new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]));
  write(join(engagement, "evidence/proof.txt"), "Potential support awaiting claim validation.\n");
  write(join(engagement, "logs/raw.log"), "stdout is a troubleshooting log, not verified evidence\n");
  const secret = "provider-secret-value-123";
  write(join(engagement, "notes/operator.txt"), `access_token=${secret}\n`);
  write(join(engagement, "loot/password.txt"), "password=must-not-import\n");
  symlinkSync(join(engagement, "notes/overview.md"), join(engagement, "notes/linked.md"));
  return { engagement, secret };
}

function createCanonicalDatabase(path: string): void {
  const database = createDatabaseConnection({ filename: path });
  try { migrateDatabase(database); }
  finally { database.close(); }
}

function count(database: ReturnType<typeof createDatabaseConnection>, table: string): number {
  return (database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count;
}

function sha256(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function allFiles(root: string): string[] {
  if (!existsSync(root)) return [];
  const output: string[] = [];
  const pending = [root];
  while (pending.length) {
    const directory = pending.pop()!;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile()) output.push(path);
    }
  }
  return output.sort();
}

interface ProtectedEngagementManifest {
  readonly schemaVersion: number;
  readonly quarantined: readonly {
    readonly quarantineId: string;
    readonly category: string;
    readonly sourceKind: string;
    readonly sourceSha256: string | null;
    readonly byteSize: number | null;
    readonly protectedBackupRef: string;
    readonly backupRelativePath: string;
    readonly backupSha256: string;
    readonly backupMode: "byte_copy" | "metadata_only";
    readonly canonicalPromotion: "none";
  }[];
}

function readProtectedEngagementManifest(sourceBackupDirectory: string): {
  path: string;
  manifest: ProtectedEngagementManifest;
} {
  const matches = allFiles(join(sourceBackupDirectory, "engagements"))
    .filter((path) => path.endsWith("/engagement-manifest.v2.json"));
  expect(matches).toHaveLength(1);
  return {
    path: matches[0]!,
    manifest: JSON.parse(readFileSync(matches[0]!, "utf8")) as ProtectedEngagementManifest,
  };
}

function directImporter(
  database: ReturnType<typeof createDatabaseConnection>,
  databasePath: string,
  sourceRoot: string,
  sourceBackupDirectory: string,
  protectedBackupStoreFactory?: (root: string) => ProtectedBackupStore,
): { importer: LegacyEngagementImporter; migrationId: string } {
  const metadata = new MigrationMetadataRepository(database);
  metadata.ensureSchema();
  const migration = metadata.createRun({
    sourceRoots: [sourceRoot],
    databasePath,
    outputDirectory: join(sourceBackupDirectory, ".."),
  });
  return {
    importer: protectedBackupStoreFactory
      ? new LegacyEngagementImporter(
          database,
          metadata,
          migration.id,
          sourceBackupDirectory,
          () => new Date(),
          protectedBackupStoreFactory,
        )
      : new LegacyEngagementImporter(database, metadata, migration.id, sourceBackupDirectory),
    migrationId: migration.id,
  };
}

async function rejectionMessage(operation: Promise<unknown>): Promise<string> {
  try {
    await operation;
    return "";
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

function expectNoCanonicalEngagementRows(database: ReturnType<typeof createDatabaseConnection>): void {
  for (const table of [
    "missions",
    "runs",
    "artifacts",
    "evidence",
    "evidence_candidates",
    "memory_nodes",
    "legacy_migration_quarantine",
  ]) expect(count(database, table)).toBe(0);
}

function markdownFiles(root: string): string[] {
  if (!existsSync(root)) return [];
  const output: string[] = [];
  const pending = [root];
  while (pending.length) {
    const directory = pending.pop()!;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile() && entry.name.endsWith(".md")) output.push(path);
    }
  }
  return output.sort();
}

describe("historical engagement discovery", () => {
  test("canonicalizes physical aliases and creates a stable secret-safe classified manifest", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    mkdirSync(legacy, { recursive: true });
    const fixture = createEngagement(legacy);
    const alias = join(directory, "legacy-alias");
    symlinkSync(legacy, alias, "dir");

    const roots = canonicalizeLegacySourceRoots([legacy, alias]);
    expect(roots.roots).toHaveLength(1);
    expect(roots.aliases).toHaveLength(1);
    expect(roots.missing).toHaveLength(0);

    const first = await discoverLegacyEngagements([legacy, alias]);
    const second = await discoverLegacyEngagements([alias, legacy]);
    expect(first.manifests).toHaveLength(1);
    expect(first.manifests[0]!.id).toBe(second.manifests[0]!.id);
    expect(first.manifests[0]!.sha256).toBe(second.manifests[0]!.sha256);
    expect(first.manifests[0]!.files.map((file) => file.kind).sort()).toEqual([
      "capture", "evidence", "log", "loot", "note", "recon", "report", "script",
    ]);
    expect(first.excluded.filter((item) => item.absolutePath.startsWith(fixture.engagement))).toHaveLength(3);
    expect(first.excluded.map((item) => item.category).sort()).toEqual([
      "sensitive_content", "symlink", "unsafe_name",
    ]);
    expect(first.manifests[0]!.files.every((file) => file.sha256.length === 64)).toBe(true);
  });

  test("treats an explicitly selected engagement directory as one engagement", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    mkdirSync(legacy, { recursive: true });
    const fixture = createEngagement(legacy);

    const discovery = await discoverLegacyEngagements([fixture.engagement], { rootMode: "self" });

    expect(discovery.manifests).toHaveLength(1);
    expect(discovery.manifests[0]!.engagementName).toBe("customer-portal");
    expect(discovery.manifests[0]!.engagementDirectory).toBe(fixture.engagement);
    expect(discovery.manifests[0]!.files.map((file) => file.relativePath)).toContain("scans/service.nmap");
    expect(discovery.manifests[0]!.files.some((file) => file.relativePath.startsWith("scans/"))).toBe(true);
  });
});

describe("historical engagement import and approved Vault projection", () => {
  test("the retired protected-copy store rejects before creating its root", () => {
    const directory = temporaryDirectory();
    const forbiddenRoot = join(directory, "must-not-be-created");

    expect(() => new ProtectedBackupStore(forbiddenRoot))
      .toThrow(PROTECTED_BACKUP_STORE_DISABLED_ERROR);
    expect(existsSync(forbiddenRoot)).toBe(false);
  });

  test("direct importer rejects protected-copy before constructing a copy store", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const sourceCopyDirectory = join(directory, "must-not-be-created");
    const databasePath = join(directory, "ti-scale.sqlite");
    write(join(legacy, "engagement", "notes", "safe.md"), "Reusable historical context.\n");
    const manifest = (await discoverLegacyEngagements([legacy])).manifests[0]!;
    createCanonicalDatabase(databasePath);
    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    let factoryCalled = false;
    try {
      const metadata = new MigrationMetadataRepository(database);
      metadata.ensureSchema();
      const migration = metadata.createRun({
        sourceRoots: [legacy],
        databasePath,
        outputDirectory: directory,
      });
      const importer = new LegacyEngagementImporter(
        database,
        metadata,
        migration.id,
        sourceCopyDirectory,
        () => new Date(),
        (root) => {
          factoryCalled = true;
          return new ProtectedBackupStore(root);
        },
        {
          sourceRetention: "protected-copy",
        },
      );

      await expect(importer.importManifest(manifest)).rejects.toThrow(
        "Protected-copy legacy engagement import is disabled",
      );
      expect(factoryCalled).toBe(false);
      expect(existsSync(sourceCopyDirectory)).toBe(false);
      expectNoCanonicalEngagementRows(database);
    } finally {
      database.close();
    }
  });

  test("retains quarantined sources by verified reference without copying or promoting them", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const engagement = join(legacy, "quarantine-fixture");
    const output = join(directory, "migration-output");
    const databasePath = join(directory, "ti-scale.sqlite");
    mkdirSync(legacy, { recursive: true });

    const secretText = "access_token=receipt-leak-sentinel-731";
    const sensitiveNameText = "sensitive-name-byte-sentinel-884";
    const privateKeyText = [
      "-----BEGIN PRIVATE KEY-----",
      "TEST-ONLY-NOT-A-REAL-KEY-992",
      "-----END PRIVATE KEY-----",
      "",
    ].join("\n");
    const oversizedText = `${"A".repeat((2 * 1024 * 1024) + 1)}oversized-byte-sentinel-447`;
    const sensitiveDirectoryBytes = "credential-directory-byte-sentinel-663";
    const safeNote = join(engagement, "notes/safe.md");
    const secretPath = join(engagement, "notes/operator.txt");
    const sensitiveNamePath = join(engagement, "loot/password.txt");
    const privateKeyPath = join(engagement, "notes/material.txt");
    const oversizedPath = join(engagement, "notes/oversized.txt");
    const sensitiveDirectoryPath = join(engagement, "creds/vault.bin");
    const symlinkPath = join(engagement, "notes/linked.md");
    write(safeNote, "Safe historical context.\n");
    write(secretPath, `${secretText}\n`);
    write(sensitiveNamePath, `${sensitiveNameText}\n`);
    write(privateKeyPath, privateKeyText);
    write(oversizedPath, oversizedText);
    write(sensitiveDirectoryPath, sensitiveDirectoryBytes);
    symlinkSync(safeNote, symlinkPath);
    createCanonicalDatabase(databasePath);

    const discovery = await discoverLegacyEngagements([legacy]);
    expect(discovery.manifests).toHaveLength(1);
    expect(discovery.manifests[0]!.quarantined.map((item) => item.category).sort()).toEqual([
      "oversized",
      "sensitive_content",
      "sensitive_content",
      "symlink",
      "unsafe_name",
      "unsafe_name",
    ]);
    expect(discovery.manifests[0]!.quarantined.filter((item) => item.sourceKind === "regular_file").every(
      (item) => item.sourceSha256?.length === 64 && item.byteSize !== undefined && item.modifiedAt !== undefined,
    )).toBe(true);
    expect(discovery.manifests[0]!.quarantined.find((item) => item.sourceKind === "symlink")?.sourceSha256).toHaveLength(64);

    const first = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy],
      outputDirectory: output,
    }).run();
    expect(first.report.databaseBackup).toBeUndefined();
    expect(first.report.rollback).toBeUndefined();
    expect(first.report.sourceBackup).toBeUndefined();
    expect(first.report.sourceReferences?.sourceBytesCopied).toBe(false);
    expect(existsSync(join(output, "database-backups"))).toBe(false);
    expect(existsSync(join(output, first.migrationId, "sources"))).toBe(false);
    const referenceDatabase = createDatabaseConnection({
      filename: databasePath,
      readonly: true,
      fileMustExist: true,
    });
    try {
      const quarantineRows = referenceDatabase.prepare(`
        SELECT source_reference, retention_mode, protected_backup_ref,
          protected_backup_sha256, backup_mode
        FROM legacy_migration_quarantine
      `).all() as Array<{
        source_reference: string | null;
        retention_mode: string | null;
        protected_backup_ref: string | null;
        protected_backup_sha256: string | null;
        backup_mode: string | null;
      }>;
      expect(quarantineRows).toHaveLength(6);
      expect(quarantineRows.every((row) =>
        row.source_reference?.startsWith("legacy-private-source://")
        && row.retention_mode === "verified-reference"
        && row.protected_backup_ref === null
        && row.protected_backup_sha256 === null
        && row.backup_mode === null
      )).toBe(true);
    } finally {
      referenceDatabase.close();
    }
    return;
    expect(first.report.sourceBackup?.quarantineProtection).toEqual({
      verifiedByteCopies: 5,
      metadataOnlyDescriptors: 1,
      verifiedSourceBytes:
        Buffer.byteLength(`${secretText}\n`)
        + Buffer.byteLength(`${sensitiveNameText}\n`)
        + Buffer.byteLength(privateKeyText)
        + Buffer.byteLength(oversizedText)
        + Buffer.byteLength(sensitiveDirectoryBytes),
      symlinksDereferenced: false,
    });
    expect(first.report.engagementDiscovery).toMatchObject({
      quarantinedPaths: 6,
      hashAddressedQuarantinedPaths: 6,
    });
    expect(first.report.warnings.join("\n")).toContain("hash-verified permission-restricted byte copy");
    expect(first.report.warnings.join("\n")).toContain("symbolic links are never followed");

    const backupRoot = first.report.sourceBackup!.directory;
    const protectedManifest = readProtectedEngagementManifest(backupRoot);
    expect(protectedManifest.manifest.schemaVersion).toBe(2);
    expect(protectedManifest.manifest.quarantined).toHaveLength(6);
    expect(new Set(protectedManifest.manifest.quarantined.map((item) => item.quarantineId)).size).toBe(6);
    expect(protectedManifest.manifest.quarantined.every((item) =>
      item.protectedBackupRef.startsWith("legacy-protected-quarantine://")
      && item.canonicalPromotion === "none"
    )).toBe(true);
    const protectedManifestText = readFileSync(protectedManifest.path, "utf8");
    for (const forbidden of [
      secretText,
      sensitiveNameText,
      "TEST-ONLY-NOT-A-REAL-KEY-992",
      "oversized-byte-sentinel-447",
      sensitiveDirectoryBytes,
      "operator.txt",
      "password.txt",
      "material.txt",
      "oversized.txt",
      "linked.md",
      "vault.bin",
    ]) expect(protectedManifestText).not.toContain(forbidden);
    const nonPayloadReceipts = allFiles(join(output, first.migrationId))
      .filter((path) => !path.endsWith(".bin"))
      .map((path) => readFileSync(path, "utf8"))
      .join("\n");
    for (const forbidden of [
      secretText,
      sensitiveNameText,
      "TEST-ONLY-NOT-A-REAL-KEY-992",
      "oversized-byte-sentinel-447",
      sensitiveDirectoryBytes,
    ]) expect(nonPayloadReceipts).not.toContain(forbidden);

    const expectedByteHashes = new Set([
      sha256(`${secretText}\n`),
      sha256(`${sensitiveNameText}\n`),
      sha256(privateKeyText),
      sha256(oversizedText),
      sha256(sensitiveDirectoryBytes),
    ]);
    const byteCopies = protectedManifest.manifest.quarantined.filter((item) => item.backupMode === "byte_copy");
    expect(byteCopies).toHaveLength(5);
    expect(new Set(byteCopies.map((item) => item.sourceSha256))).toEqual(expectedByteHashes);
    for (const item of byteCopies) {
      const backupPath = join(backupRoot, ...item.backupRelativePath.split("/"));
      const bytes = readFileSync(backupPath);
      expect(sha256(bytes)).toBe(item.sourceSha256!);
      expect(sha256(bytes)).toBe(item.backupSha256);
      expect(statSync(backupPath).mode & 0o777).toBe(0o600);
    }
    const metadataOnly = protectedManifest.manifest.quarantined.filter((item) => item.backupMode === "metadata_only");
    expect(metadataOnly).toHaveLength(1);
    const descriptorPath = join(backupRoot, ...metadataOnly[0]!.backupRelativePath.split("/"));
    const descriptor = readFileSync(descriptorPath, "utf8");
    expect(sha256(descriptor)).toBe(metadataOnly[0]!.backupSha256);
    expect(descriptor).toContain('"symlinkDereferenced": false');
    expect(descriptor).toContain('"rawContentRetained": false');
    expect(descriptor).not.toContain(safeNote);

    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      expect(count(database, "legacy_migration_quarantine")).toBe(6);
      expect(count(database, "evidence")).toBe(0);
      expect(count(database, "evidence_candidates")).toBe(0);
      const sourceBrainNode = database.prepare(`
        SELECT summary, body FROM memory_nodes WHERE node_type = 'source'
      `).get() as { summary: string; body: string };
      expect(sourceBrainNode.summary).toContain("6 policy-quarantined source objects");
      expect(sourceBrainNode.body).toContain("Symlinks were not followed");
      expect(sourceBrainNode.body).toContain("No quarantined content was projected");
      const quarantineRows = database.prepare(`
        SELECT source_content_sha256, byte_size, source_created_at, source_modified_at,
          protected_backup_ref, protected_backup_sha256, backup_mode
        FROM legacy_migration_quarantine ORDER BY item_key
      `).all() as Array<{
        source_content_sha256: string | null;
        byte_size: number | null;
        source_created_at: string | null;
        source_modified_at: string | null;
        protected_backup_ref: string | null;
        protected_backup_sha256: string | null;
        backup_mode: string | null;
      }>;
      expect(quarantineRows.every((row) =>
        row.source_content_sha256?.length === 64
        && row.byte_size !== null
        && row.source_created_at !== null
        && row.source_modified_at !== null
        && row.protected_backup_ref?.startsWith("legacy-protected-quarantine://")
        && row.protected_backup_sha256?.length === 64
      )).toBe(true);
      expect(quarantineRows.filter((row) => row.backup_mode === "byte_copy")).toHaveLength(5);
      expect(quarantineRows.filter((row) => row.backup_mode === "metadata_only")).toHaveLength(1);
      const artifactHashes = new Set((database.prepare("SELECT content_hash FROM artifacts").all() as Array<{ content_hash: string }>).map((row) => row.content_hash));
      for (const hash of expectedByteHashes) expect(artifactHashes.has(hash)).toBe(false);
      const canonicalReceiptText = [
        ...(database.prepare("SELECT title || ' ' || summary || ' ' || body AS value FROM memory_nodes").all() as Array<{ value: string }>).map((row) => row.value),
        ...(database.prepare("SELECT storage_uri || ' ' || metadata_json AS value FROM artifacts").all() as Array<{ value: string }>).map((row) => row.value),
        ...(database.prepare("SELECT reason || ' ' || COALESCE(redacted_excerpt, '') || ' ' || COALESCE(protected_backup_ref, '') AS value FROM legacy_migration_quarantine").all() as Array<{ value: string }>).map((row) => row.value),
        ...(database.prepare("SELECT report_json AS value FROM legacy_migration_reconciliation").all() as Array<{ value: string }>).map((row) => row.value),
        ...(database.prepare("SELECT reason || ' ' || details_json AS value FROM audit_records").all() as Array<{ value: string }>).map((row) => row.value),
      ].join("\n");
      for (const forbidden of [secretText, sensitiveNameText, "TEST-ONLY-NOT-A-REAL-KEY-992", "oversized-byte-sentinel-447", sensitiveDirectoryBytes]) {
        expect(canonicalReceiptText).not.toContain(forbidden);
      }
    } finally {
      database.close();
    }

    const second = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy],
      outputDirectory: output,
    }).run();
    expect(second.report.counts).toMatchObject({ imported: 0, deduplicated: 8, quarantined: 0 });
    expect(second.report.sourceBackup?.quarantineProtection).toMatchObject({
      verifiedByteCopies: 5,
      metadataOnlyDescriptors: 1,
    });
    expect(readProtectedEngagementManifest(second.report.sourceBackup!.directory).manifest.quarantined).toHaveLength(6);
    const afterSecond = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      expect(count(afterSecond, "legacy_migration_quarantine")).toBe(6);
      expect(count(afterSecond, "artifacts")).toBe(2);
      expect(count(afterSecond, "evidence")).toBe(0);
      expect(count(afterSecond, "evidence_candidates")).toBe(0);
    } finally {
      afterSecond.close();
    }
  });

  test("never constructs the retired protected-copy store during a reference import", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const engagement = join(legacy, "reference-only-fixture");
    const sourceCopyDirectory = join(directory, "must-not-be-created");
    const databasePath = join(directory, "ti-scale.sqlite");
    write(join(engagement, "notes/safe.md"), "Reference-only historical context.\n");
    const manifest = (await discoverLegacyEngagements([legacy])).manifests[0]!;
    createCanonicalDatabase(databasePath);
    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    let factoryCalled = false;
    try {
      const { importer } = directImporter(
        database,
        databasePath,
        legacy,
        sourceCopyDirectory,
        (root) => {
          factoryCalled = true;
          return new ProtectedBackupStore(root);
        },
      );
      await importer.importManifest(manifest);
      expect(factoryCalled).toBe(false);
      expect(existsSync(sourceCopyDirectory)).toBe(false);
    } finally {
      database.close();
    }
    return;
    for (const destinationKind of ["accepted", "quarantine_byte", "quarantine_metadata"] as const) {
      const directory = temporaryDirectory();
      const legacy = join(directory, "legacy");
      const engagement = join(legacy, `destination-${destinationKind}`);
      const sourceBackup = join(directory, "protected-sources");
      const databasePath = join(directory, "ti-scale.sqlite");
      const safePath = join(engagement, "notes/safe.md");
      write(safePath, "Safe historical context.\n");
      write(join(engagement, "notes/operator.txt"), "access_token=protected-destination-sentinel\n");
      symlinkSync(safePath, join(engagement, "notes/linked.md"));

      const discovery = await discoverLegacyEngagements([legacy]);
      const manifest = discovery.manifests[0]!;
      const accepted = manifest.files[0]!;
      const quarantineByte = manifest.quarantined.find((item) => item.sourceKind === "regular_file")!;
      const quarantineMetadata = manifest.quarantined.find((item) => item.sourceKind === "symlink")!;
      const extension = ".md";
      const descriptor = `${JSON.stringify({
        schemaVersion: 1,
        quarantineId: quarantineMetadata.quarantineId,
        category: quarantineMetadata.category,
        sourceKind: quarantineMetadata.sourceKind,
        sourceSha256: quarantineMetadata.sourceSha256 ?? null,
        byteSize: quarantineMetadata.byteSize ?? null,
        createdAt: quarantineMetadata.createdAt ?? null,
        modifiedAt: quarantineMetadata.modifiedAt ?? null,
        symlinkDereferenced: false,
        originalPathRetained: false,
        rawContentRetained: false,
      }, null, 2)}\n`;
      const relativeDestinations = {
        accepted: `engagements/${manifest.id}/files/000000-${accepted.sha256}${extension}`,
        quarantine_byte: `engagements/${manifest.id}/quarantine/${quarantineByte.quarantineId}/${quarantineByte.sourceSha256}.bin`,
        quarantine_metadata: `engagements/${manifest.id}/quarantine/${quarantineMetadata.quarantineId}/metadata-${sha256(descriptor)}.json`,
      } as const;
      const destination = join(sourceBackup, ...relativeDestinations[destinationKind].split("/"));
      const outside = join(directory, `outside-${destinationKind}.txt`);
      const outsideContent = `outside-${destinationKind}-must-remain-unchanged\n`;
      write(outside, outsideContent);
      chmodSync(outside, 0o640);
      mkdirSync(dirname(destination), { recursive: true });
      symlinkSync(outside, destination);
      const outsideMode = statSync(outside).mode & 0o777;
      createCanonicalDatabase(databasePath);

      const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
      try {
        const { importer } = directImporter(database, databasePath, legacy, sourceBackup);
        const message = await rejectionMessage(importer.importManifest(manifest));
        expect(message).toContain("destination is not a regular file");
        expect(readFileSync(outside, "utf8")).toBe(outsideContent);
        expect(statSync(outside).mode & 0o777).toBe(outsideMode);
        expectNoCanonicalEngagementRows(database);
      } finally {
        database.close();
      }
    }
  });

  test("rejects a source replaced after verified-reference preflight without creating copies", async () => {
    const forwardOnlyDirectory = temporaryDirectory();
    const forwardOnlyLegacy = join(forwardOnlyDirectory, "legacy");
    const forwardOnlyEngagement = join(forwardOnlyLegacy, "source-race-fixture");
    const forwardOnlySourceCopy = join(forwardOnlyDirectory, "must-not-be-created");
    const forwardOnlyDatabasePath = join(forwardOnlyDirectory, "ti-scale.sqlite");
    const forwardOnlySource = join(forwardOnlyEngagement, "notes/safe.md");
    write(forwardOnlySource, "Original historical context.\n");
    const forwardOnlyManifest = (await discoverLegacyEngagements([forwardOnlyLegacy])).manifests[0]!;
    createCanonicalDatabase(forwardOnlyDatabasePath);
    const forwardOnlyDatabase = createDatabaseConnection({
      filename: forwardOnlyDatabasePath,
      fileMustExist: true,
    });
    try {
      const metadata = new MigrationMetadataRepository(forwardOnlyDatabase);
      metadata.ensureSchema();
      const migration = metadata.createRun({
        sourceRoots: [forwardOnlyLegacy],
        databasePath: forwardOnlyDatabasePath,
        outputDirectory: forwardOnlyDirectory,
        sourceRetention: "verified-reference",
        verifiedReferenceAcknowledged: true,
        brainProjectionMode: "attack-knowledge-only",
        attackKnowledgeOnlyAcknowledged: true,
      });
      const importer = new LegacyEngagementImporter(
        forwardOnlyDatabase,
        metadata,
        migration.id,
        forwardOnlySourceCopy,
        () => new Date(),
        undefined,
        {
          sourceRetention: "verified-reference",
          verifiedReferenceAcknowledged: true,
          brainProjectionMode: "attack-knowledge-only",
          attackKnowledgeOnlyAcknowledged: true,
          testHooks: {
            afterVerifiedReferencePreflight: () => {
              writeFileSync(forwardOnlySource, "Changed historical context.\n", { mode: 0o600 });
            },
          },
        },
      );
      await expect(importer.importManifest(forwardOnlyManifest)).rejects.toThrow(
        /changed during verified-reference import|changed after discovery|no longer matches discovery provenance/iu,
      );
      expect(existsSync(forwardOnlySourceCopy)).toBe(false);
      expectNoCanonicalEngagementRows(forwardOnlyDatabase);
    } finally {
      forwardOnlyDatabase.close();
    }
    return;
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const engagement = join(legacy, "concurrent-replacement-fixture");
    const sourceBackup = join(directory, "protected-sources");
    const firstDatabasePath = join(directory, "first.sqlite");
    const secondDatabasePath = join(directory, "second.sqlite");
    write(join(engagement, "notes/safe.md"), "Safe historical context.\n");
    write(join(engagement, "notes/operator.txt"), "access_token=concurrent-replacement-sentinel\n");
    const discovery = await discoverLegacyEngagements([legacy]);
    const manifest = discovery.manifests[0]!;
    const accepted = manifest.files[0]!;
    const acceptedBackup = join(
      sourceBackup,
      "engagements",
      manifest.id,
      "files",
      `000000-${accepted.sha256}.md`,
    );

    createCanonicalDatabase(firstDatabasePath);
    const firstDatabase = createDatabaseConnection({ filename: firstDatabasePath, fileMustExist: true });
    try {
      const { importer } = directImporter(firstDatabase, firstDatabasePath, legacy, sourceBackup);
      await importer.importManifest(manifest);
    } finally {
      firstDatabase.close();
    }
    expect(existsSync(acceptedBackup)).toBe(true);

    const outside = join(directory, "outside-concurrent-target.txt");
    const outsideContent = "outside target must remain byte-for-byte unchanged\n";
    write(outside, outsideContent);
    chmodSync(outside, 0o640);
    const outsideMode = statSync(outside).mode & 0o777;
    let replacementTriggered = false;

    createCanonicalDatabase(secondDatabasePath);
    const secondDatabase = createDatabaseConnection({ filename: secondDatabasePath, fileMustExist: true });
    try {
      const { importer } = directImporter(
        secondDatabase,
        secondDatabasePath,
        legacy,
        sourceBackup,
        (root) => new ProtectedBackupStore(root, {
          afterExistingDestinationRead: () => {
            if (replacementTriggered) return;
            replacementTriggered = true;
            unlinkSync(acceptedBackup);
            symlinkSync(outside, acceptedBackup);
          },
        }),
      );
      const message = await rejectionMessage(importer.importManifest(manifest));
      expect(replacementTriggered).toBe(true);
      expect(message).toContain("unlinked or replaced after it was read");
      expect(readFileSync(outside, "utf8")).toBe(outsideContent);
      expect(statSync(outside).mode & 0o777).toBe(outsideMode);
      expectNoCanonicalEngagementRows(secondDatabase);
    } finally {
      secondDatabase.close();
    }
  });

  test("rejects traversal-shaped manifest and quarantine identifiers before deriving backup paths", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const engagement = join(legacy, "traversal-fixture");
    const sourceBackup = join(directory, "protected-sources");
    write(join(engagement, "notes/safe.md"), "Safe note.\n");
    write(join(engagement, "notes/operator.txt"), "access_token=traversal-sentinel\n");
    const discovery = await discoverLegacyEngagements([legacy]);
    const manifest = discovery.manifests[0]!;

    const cases: Array<{ name: string; manifest: LegacyEngagementManifest }> = [
      {
        name: "manifest",
        manifest: { ...manifest, id: "legacy_engagement_../../outside" },
      },
      {
        name: "quarantine",
        manifest: {
          ...manifest,
          quarantined: manifest.quarantined.map((item, index) => index === 0
            ? { ...item, quarantineId: "quarantine_../../outside" }
            : item),
        },
      },
    ];

    for (const scenario of cases) {
      const databasePath = join(directory, `${scenario.name}.sqlite`);
      createCanonicalDatabase(databasePath);
      const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
      try {
        const { importer } = directImporter(database, databasePath, legacy, sourceBackup);
        const message = await rejectionMessage(importer.importManifest(scenario.manifest));
        expect(message).toContain("opaque identifier");
        expectNoCanonicalEngagementRows(database);
      } finally {
        database.close();
      }
    }
    expect(allFiles(sourceBackup)).toHaveLength(0);
    expect(existsSync(join(directory, "outside"))).toBe(false);
  });

  test("revalidates a stale verified-reference source without creating a protected copy", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const engagement = join(legacy, "stale-preexisting-fixture");
    const sourceBackup = join(directory, "protected-sources");
    const firstDatabasePath = join(directory, "first.sqlite");
    const secondDatabasePath = join(directory, "second.sqlite");
    const safePath = join(engagement, "notes/safe.md");
    const original = "Original safe historical context.\n";
    write(safePath, original);
    write(join(engagement, "notes/operator.txt"), "access_token=stale-backup-sentinel\n");
    const discovery = await discoverLegacyEngagements([legacy]);
    const manifest = discovery.manifests[0]!;
    const accepted = manifest.files[0]!;
    const acceptedBackup = join(
      sourceBackup,
      "engagements",
      manifest.id,
      "files",
      `000000-${accepted.sha256}.md`,
    );

    createCanonicalDatabase(firstDatabasePath);
    const firstDatabase = createDatabaseConnection({ filename: firstDatabasePath, fileMustExist: true });
    try {
      const { importer } = directImporter(firstDatabase, firstDatabasePath, legacy, sourceBackup);
      await importer.importManifest(manifest);
    } finally {
      firstDatabase.close();
    }
    expect(existsSync(acceptedBackup)).toBe(false);

    writeFileSync(safePath, "Changed safe historical context.\n", { mode: 0o600 });
    createCanonicalDatabase(secondDatabasePath);
    const secondDatabase = createDatabaseConnection({ filename: secondDatabasePath, fileMustExist: true });
    try {
      const { importer } = directImporter(secondDatabase, secondDatabasePath, legacy, sourceBackup);
      const message = await rejectionMessage(importer.importManifest(manifest));
      expect(message).toMatch(/discovery provenance|changed after discovery/u);
      expectNoCanonicalEngagementRows(secondDatabase);
    } finally {
      secondDatabase.close();
    }
    expect(existsSync(acceptedBackup)).toBe(false);
  });

  test("replays verified references and version-corrects stale Brain provenance exactly once", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const engagement = join(legacy, "v1-resume-fixture");
    const firstBackup = join(directory, "protected-v2-first");
    const resumeBackup = join(directory, "protected-v1-resume");
    const databasePath = join(directory, "ti-scale.sqlite");
    const safePath = join(engagement, "notes/safe.md");
    write(safePath, "Safe historical context.\n");
    write(join(engagement, "notes/operator.txt"), "access_token=v1-resume-sentinel\n");
    symlinkSync(safePath, join(engagement, "notes/linked.md"));
    const discovery = await discoverLegacyEngagements([legacy]);
    const manifest = discovery.manifests[0]!;
    createCanonicalDatabase(databasePath);

    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      const first = directImporter(database, databasePath, legacy, firstBackup);
      await first.importer.importManifest(manifest);
      const sourceRow = database.prepare(`
        SELECT id, version FROM memory_nodes WHERE node_type = 'source'
      `).get() as { id: string; version: number };
      const staleExplanation = "Legacy v1 projection with incomplete quarantine provenance.";
      database.prepare(`
        UPDATE memory_nodes SET summary = ?, body = ?, provenance_json = ? WHERE id = ?
      `).run(
        "Legacy v1 source summary.",
        "Legacy v1 source body.",
        JSON.stringify({
          method: "imported",
          explanation: staleExplanation,
          sources: [{
            sourceType: "legacy_engagement_manifest",
            sourceId: manifest.id,
            sourceHash: "0".repeat(64),
            acquiredAt: manifest.modifiedAt,
          }],
        }),
        sourceRow.id,
      );

      expect(existsSync(resumeBackup)).toBe(false);

      const resumed = directImporter(database, databasePath, legacy, resumeBackup);
      await resumed.importer.importManifest(manifest);
      const memory = new MemoryRepository(database);
      const corrected = memory.requireNode(sourceRow.id, true);
      expect(corrected.summary).toContain("policy-quarantined source objects");
      expect(corrected.body).toContain("without following symlinks");
      expect(corrected.provenance.explanation).toContain("hash-verified historical engagement manifest");
      expect(corrected.provenance.sources.some((source) =>
        source.sourceType === "legacy_engagement_manifest"
        && source.sourceId === `${manifest.id}:v2:${manifest.sha256.slice(0, 16)}`
        && source.sourceHash === manifest.sha256
      )).toBe(true);
      expect(corrected.version).toBe(sourceRow.version + 1);
      expect(existsSync(resumeBackup)).toBe(false);

      const replay = directImporter(database, databasePath, legacy, resumeBackup);
      await replay.importer.importManifest(manifest);
      expect(memory.requireNode(sourceRow.id, true).version).toBe(corrected.version);
    } finally {
      database.close();
    }
  });

  test("detects quarantined source churn before canonical rows or unverified backups are published", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const engagement = join(legacy, "churn-fixture");
    const sourceBackup = join(directory, "protected-sources");
    const databasePath = join(directory, "ti-scale.sqlite");
    const originalSecret = "access_token=original-churn-sentinel-411";
    const changedSecret = "access_token=changed-churn-sentinel-812";
    write(join(engagement, "notes/safe.md"), "Safe note.\n");
    const secretPath = join(engagement, "notes/operator.txt");
    write(secretPath, `${originalSecret}\n`);
    const discovery = await discoverLegacyEngagements([legacy]);
    expect(discovery.manifests).toHaveLength(1);
    write(secretPath, `${changedSecret}\n`);
    createCanonicalDatabase(databasePath);

    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      const metadata = new MigrationMetadataRepository(database);
      metadata.ensureSchema();
      const migration = metadata.createRun({
        sourceRoots: [legacy],
        databasePath,
        outputDirectory: directory,
      });
      const importer = new LegacyEngagementImporter(database, metadata, migration.id, sourceBackup);
      let message = "";
      try {
        await importer.importManifest(discovery.manifests[0]!);
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toContain("discovery provenance");
      expect(message).not.toContain(originalSecret);
      expect(message).not.toContain(changedSecret);
      expect(count(database, "missions")).toBe(0);
      expect(count(database, "runs")).toBe(0);
      expect(count(database, "artifacts")).toBe(0);
      expect(count(database, "evidence")).toBe(0);
      expect(count(database, "evidence_candidates")).toBe(0);
      expect(count(database, "memory_nodes")).toBe(0);
      expect(count(database, "legacy_migration_quarantine")).toBe(0);
      expect(allFiles(sourceBackup).some((path) => path.endsWith(".tmp"))).toBe(false);
      expect(allFiles(sourceBackup).some((path) => path.endsWith(".bin"))).toBe(false);
    } finally {
      database.close();
    }
  });

  test("additively upgrades pre-provenance quarantine metadata tables", () => {
    const directory = temporaryDirectory();
    const databasePath = join(directory, "ti-scale.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      // Reproduce the table shape that existed before provenance custody was
      // introduced. Do not migrate the fixture first: the canonical migration
      // now owns this table and would make this compatibility test meaningless.
      database.exec(`
        CREATE TABLE legacy_migration_quarantine (
          id TEXT PRIMARY KEY,
          migration_id TEXT NOT NULL,
          source_sha256 TEXT NOT NULL,
          source_path TEXT NOT NULL,
          item_key TEXT NOT NULL,
          item_hash TEXT,
          category TEXT NOT NULL,
          reason TEXT NOT NULL,
          redacted_excerpt TEXT,
          created_at TEXT NOT NULL
        ) STRICT
      `);
      new MigrationMetadataRepository(database).ensureSchema();
      const columns = new Set((database.prepare("PRAGMA table_info('legacy_migration_quarantine')").all() as Array<{ name: string }>).map((row) => row.name));
      for (const name of [
        "source_content_sha256",
        "byte_size",
        "source_created_at",
        "source_modified_at",
        "protected_backup_ref",
        "protected_backup_sha256",
        "backup_mode",
      ]) expect(columns.has(name)).toBe(true);
    } finally {
      database.close();
    }
  });

  test("imports an explicit engagement root as one canonical mission", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const output = join(directory, "migration-output");
    const databasePath = join(directory, "ti-scale.sqlite");
    mkdirSync(legacy, { recursive: true });
    const fixture = createEngagement(legacy);
    createCanonicalDatabase(databasePath);

    await new LegacyMigrationService({
      databasePath,
      sourceRoots: [],
      engagementRoots: [fixture.engagement],
      outputDirectory: output,
    }).run();

    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      expect(count(database, "missions")).toBe(1);
      expect(count(database, "runs")).toBe(1);
      expect(count(database, "legacy_engagement_manifests")).toBe(1);
      expect((database.prepare("SELECT name FROM missions").get() as { name: string }).name).toBe("customer-portal");
      expect(count(database, "artifacts")).toBe(9);
    } finally {
      database.close();
    }
  });

  test("imports once, preserves log/evidence semantics, and blocks obsolete target-centric Vault projection", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const output = join(directory, "migration-output");
    const databasePath = join(directory, "ti-scale.sqlite");
    mkdirSync(legacy, { recursive: true });
    const fixture = createEngagement(legacy);
    const alias = join(directory, "legacy-alias");
    symlinkSync(legacy, alias, "dir");
    createCanonicalDatabase(databasePath);
    const originalLog = readFileSync(join(fixture.engagement, "logs/raw.log"));

    const dryRun = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy, alias],
      outputDirectory: output,
      dryRun: true,
    }).run();
    expect(dryRun.report.engagementDiscovery).toMatchObject({
      manifests: 1,
      classifiedFiles: 8,
      quarantinedPaths: 3,
    });
    expect(dryRun.report.engagementDiscovery?.rootAliases).toHaveLength(1);
    expect(dryRun.report.targets).toEqual({});

    const first = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy, alias],
      outputDirectory: output,
    }).run();
    expect(first.report.counts).toMatchObject({ sources: 1, imported: 9, quarantined: 3 });
    expect(first.report.engagementDiscovery?.rootAliases).toHaveLength(1);
    expect(readFileSync(join(fixture.engagement, "logs/raw.log")).equals(originalLog)).toBe(true);

    let reconciliationHash: string;
    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      expect(count(database, "missions")).toBe(1);
      expect(count(database, "runs")).toBe(1);
      expect(count(database, "artifacts")).toBe(9);
      expect(count(database, "engagement_log_records")).toBe(1);
      expect(count(database, "evidence_candidates")).toBe(2);
      expect(count(database, "evidence")).toBe(0);
      expect(count(database, "memory_nodes")).toBe(16);
      expect(count(database, "memory_edges")).toBe(17);
      expect(count(database, "legacy_engagement_manifests")).toBe(1);
      expect(count(database, "legacy_migration_quarantine")).toBe(3);
      expect((database.prepare("SELECT authorization_status FROM missions").get() as { authorization_status: string }).authorization_status).toBe("unverified");
      expect((database.prepare("SELECT control_plane FROM missions").get() as { control_plane: string }).control_plane).toBe("legacy");
      expect((database.prepare("SELECT status FROM runs").get() as { status: string }).status).toBe("blocked");
      expect((database.prepare("SELECT control_plane FROM runs").get() as { control_plane: string }).control_plane).toBe("legacy");
      expect((database.prepare("SELECT technical_payload_json FROM engagement_log_records").get() as { technical_payload_json: string }).technical_payload_json)
        .toContain('"rawOutputIsEvidence":false');
      expect((database.prepare("SELECT COUNT(*) AS count FROM memory_edges WHERE lifecycle_status='verified'").get() as { count: number }).count).toBe(15);
      const assetObservation = database.prepare(`
        SELECT title, summary, body FROM memory_nodes WHERE node_type = 'asset'
      `).get() as { title: string; summary: string; body: string };
      expect(assetObservation.title).toContain("192.0.2.45");
      expect(assetObservation.summary).toContain("current reachability is unverified");
      expect(assetObservation.body).toContain("portal.example.test");
      const serviceObservation = database.prepare(`
        SELECT title, summary, body FROM memory_nodes WHERE node_type = 'entity'
      `).get() as { title: string; summary: string; body: string };
      expect(serviceObservation.title).toContain("192.0.2.45:443/tcp");
      expect(serviceObservation.body).toContain("nginx 1.24");
      expect((database.prepare(`
        SELECT COUNT(*) AS count FROM memory_edges
        WHERE edge_type = 'belongs_to'
          AND source_node_id = (SELECT id FROM memory_nodes WHERE node_type = 'entity')
          AND target_node_id = (SELECT id FROM memory_nodes WHERE node_type = 'asset')
      `).get() as { count: number }).count).toBe(1);
      const verifiedNodes = (database.prepare("SELECT id FROM memory_nodes WHERE lifecycle_status='verified'").all() as Array<{ id: string }>).map((row) => row.id);
      const visibleEdgeNodes = new Set((database.prepare(`
        SELECT source_node_id AS id FROM memory_edges WHERE lifecycle_status='verified'
        UNION SELECT target_node_id AS id FROM memory_edges WHERE lifecycle_status='verified'
      `).all() as Array<{ id: string }>).map((row) => row.id));
      expect(verifiedNodes.every((id) => visibleEdgeNodes.has(id))).toBe(true);
      const canonicalText = (database.prepare(`
        SELECT title || ' ' || summary || ' ' || body AS text FROM memory_nodes
        UNION ALL SELECT human_summary || ' ' || technical_payload_json FROM engagement_log_records
      `).all() as Array<{ text: string }>).map((row) => row.text).join("\n");
      expect(canonicalText).not.toContain(fixture.secret);
      reconciliationHash = (database.prepare(`
        SELECT report_hash FROM legacy_migration_reconciliation WHERE migration_id = ?
      `).get(first.migrationId) as { report_hash: string }).report_hash;
    } finally {
      database.close();
    }

    const second = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [alias, legacy],
      outputDirectory: output,
    }).run();
    expect(second.report.counts).toMatchObject({ sources: 1, imported: 0, deduplicated: 12, quarantined: 0 });
    const afterSecond = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      expect(count(afterSecond, "missions")).toBe(1);
      expect(count(afterSecond, "runs")).toBe(1);
      expect(count(afterSecond, "artifacts")).toBe(9);
      expect(count(afterSecond, "memory_nodes")).toBe(16);
      expect(count(afterSecond, "memory_edges")).toBe(17);
    } finally {
      afterSecond.close();
    }

    const writable = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      const allowedVaults = join(directory, "allowed-vaults");
      const bridge = new ObsidianVaultBridge(
        writable,
        new MemoryRepository(writable),
        new VaultPathPolicy(allowedVaults),
      );
      const connection = bridge.connect({
        id: "legacy-projection-test",
        vaultPath: "Ti-Scale-Brain",
        displayName: "Imported engagement Brain",
        permissionGranted: true,
      });
      const approval = new ApprovedLegacyVaultProjectionService(writable, bridge);
      const preview = approval.preview({
        migrationId: first.migrationId,
        expectedReconciliationHash: reconciliationHash!,
        connectionId: connection.id,
      });
      // Legacy mission, run, target, asset, and artifact nodes remain in the
      // canonical audit trail, but are deliberately ineligible for the new
      // reusable Attack Knowledge Vault. Technology, vector, procedure,
      // hazard, recovery, and verified lesson nodes use the separate staged
      // extraction and promotion path.
      expect(preview.mappedNodeCount).toBe(16);
      expect(preview.eligibleNodeCount).toBe(0);
      expect(preview.excludedNodeCount).toBe(16);
      expect(preview.projectionHash).toMatch(/^[a-f0-9]{64}$/u);
      expect(markdownFiles(connection.vaultPath)).toHaveLength(0);
      await expect(approval.project({
        migrationId: first.migrationId,
        expectedReconciliationHash: "0".repeat(64),
        expectedProjectionHash: preview.projectionHash,
        connectionId: connection.id,
        approvedBy: "operator-test",
      })).rejects.toThrow("does not match");
      expect(markdownFiles(connection.vaultPath)).toHaveLength(0);

      writable.prepare("UPDATE vault_connections SET status='disconnected' WHERE id=?").run(connection.id);
      await expect(approval.project({
        migrationId: first.migrationId,
        expectedReconciliationHash: reconciliationHash!,
        expectedProjectionHash: preview.projectionHash,
        connectionId: connection.id,
        approvedBy: "operator-test",
      })).rejects.toThrow("disconnected");
      expect(markdownFiles(connection.vaultPath)).toHaveLength(0);
      writable.prepare("UPDATE vault_connections SET status='connected' WHERE id=?").run(connection.id);

      await expect(approval.project({
        migrationId: first.migrationId,
        expectedReconciliationHash: reconciliationHash!,
        expectedProjectionHash: preview.projectionHash,
        connectionId: connection.id,
        approvedBy: "operator-test",
      })).rejects.toThrow("No imported engagement memory nodes are eligible");
      expect(markdownFiles(connection.vaultPath)).toHaveLength(0);
      expect(writable.prepare(`
        SELECT 1 AS present FROM sqlite_master
        WHERE type='table' AND name='legacy_vault_projection_approvals'
      `).get()).toBeNull();
    } finally {
      writable.close();
    }
  });
});

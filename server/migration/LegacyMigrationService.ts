import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  createReadStream,
  existsSync,
  mkdirSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import {
  assertDatabaseIntegrity,
  checkDatabaseIntegrity,
  createDatabaseConnection,
  createTimestampedBackup,
  migrateDatabase,
  type SqliteDatabase,
} from "../db";
import { LegacyImporter } from "./LegacyImporter";
import { LegacyEngagementImporter } from "./LegacyEngagementImporter";
import {
  canonicalizeLegacySourceRoots,
  discoverLegacyEngagements,
  type CanonicalLegacyRoots,
  type LegacyEngagementDiscovery,
} from "./LegacyEngagementDiscovery";
import { MigrationMetadataRepository, type MigrationRunRecord } from "./MigrationMetadataRepository";
import { sha256Text } from "./SecretSafety";
import { discoverLegacySources } from "./SourceDiscovery";
import type {
  LegacyMigrationOptions,
  LegacyMigrationResult,
  LegacySource,
  MigrationCounts,
  ReconciliationReport,
  SourceMigrationResult,
} from "./types";

async function hashFile(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

function atomicWrite(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  try {
    writeFileSync(temporary, content, { encoding: "utf8", mode: 0o600, flag: "wx" });
    renameSync(temporary, path);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}

function backupRelativePath(source: LegacySource): string {
  const rootTag = sha256Text(source.root).slice(0, 12);
  return join(rootTag, source.sha256.slice(0, 12), ...source.relativePath.split("/"));
}

function copySource(source: LegacySource, destinationRoot: string): string {
  const relativePath = backupRelativePath(source);
  const destination = resolve(destinationRoot, relativePath);
  const expectedRoot = resolve(destinationRoot);
  const relation = relative(expectedRoot, destination);
  if (relation === ".." || relation.startsWith(`..${sep}`)) throw new Error("Backup path escaped destination");
  mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
  const temporary = `${destination}.${process.pid}.${Date.now()}.tmp`;
  try {
    copyFileSync(source.absolutePath, temporary);
    chmodSync(temporary, 0o600);
    const modified = new Date(source.modifiedAt);
    utimesSync(temporary, modified, modified);
    renameSync(temporary, destination);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
  return relativePath.split(sep).join("/");
}

/** Capture only a quiescent file. A writer racing the copy causes a bounded retry then failure. */
async function captureStableSource(source: LegacySource, destinationRoot: string): Promise<LegacySource> {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (
      (source.type === "kanban_sqlite" || source.type === "conversation_state_sqlite")
      && existsSync(`${source.absolutePath}-wal`)
      && statSync(`${source.absolutePath}-wal`).size > 0
    ) {
      throw new Error(`SQLite source has a non-empty WAL; quiesce and checkpoint it before migration: ${source.absolutePath}`);
    }
    const beforeStat = statSync(source.absolutePath);
    const beforeHash = await hashFile(source.absolutePath);
    const effective: LegacySource = {
      ...source,
      sha256: beforeHash,
      byteSize: beforeStat.size,
      modifiedAt: beforeStat.mtime.toISOString(),
    };
    const backupRel = copySource(effective, destinationRoot);
    const destination = join(destinationRoot, ...backupRel.split("/"));
    const afterStat = statSync(source.absolutePath);
    const [afterHash, copiedHash] = await Promise.all([hashFile(source.absolutePath), hashFile(destination)]);
    if (
      beforeHash === afterHash
      && copiedHash === afterHash
      && beforeStat.size === afterStat.size
      && statSync(destination).size === afterStat.size
    ) return { ...effective, modifiedAt: afterStat.mtime.toISOString() };
  }
  throw new Error(`Source remained active while backup was attempted: ${source.absolutePath}`);
}

function sumCounts(results: readonly SourceMigrationResult[]): MigrationCounts {
  return results.reduce<MigrationCounts>((total, result) => ({
    sources: total.sources + 1,
    imported: total.imported + result.imported,
    deduplicated: total.deduplicated + result.deduplicated,
    quarantined: total.quarantined + result.quarantined,
    skipped: total.skipped + result.skipped,
  }), { sources: 0, imported: 0, deduplicated: 0, quarantined: 0, skipped: 0 });
}

function sumTargets(results: readonly SourceMigrationResult[]): Record<string, number> {
  const totals: Record<string, number> = {};
  for (const result of results) {
    for (const [target, count] of Object.entries(result.targetCounts)) {
      totals[target] = (totals[target] ?? 0) + count;
    }
  }
  return totals;
}

function pathInside(directory: string, candidate: string): boolean {
  const value = relative(resolve(directory), resolve(candidate));
  return value === "" || (value !== ".." && !value.startsWith(`..${sep}`));
}

function engagementDiscoverySummary(
  discovery: LegacyEngagementDiscovery,
  resolvedRoots: CanonicalLegacyRoots,
): NonNullable<ReconciliationReport["engagementDiscovery"]> {
  return {
    manifests: discovery.manifests.length,
    classifiedFiles: discovery.manifests.reduce((total, manifest) => total + manifest.files.length, 0),
    classifiedBytes: discovery.manifests.reduce(
      (total, manifest) => total + manifest.files.reduce((subtotal, file) => subtotal + file.byteSize, 0),
      0,
    ),
    quarantinedPaths: discovery.excluded.length,
    rootAliases: resolvedRoots.aliases.map((alias) => ({
      requestedPath: alias.requestedPath,
      canonicalPath: alias.canonicalPath,
      duplicateOf: alias.duplicateOf,
    })),
  };
}

interface ForeignKeyViolation { readonly table: string; readonly rowid: number; }

function databaseValidation(database: SqliteDatabase): ReconciliationReport["integrity"] {
  const integrity = checkDatabaseIntegrity(database);
  const violations = database.pragma("foreign_key_check") as ForeignKeyViolation[];
  return { quickCheck: integrity.messages, foreignKeyViolations: violations.length };
}

/** Backup-first, resumable and hash-addressed migration coordinator. */
export class LegacyMigrationService {
  private readonly clock: () => Date;

  constructor(private readonly options: LegacyMigrationOptions) {
    this.clock = options.clock ?? (() => new Date());
  }

  async run(): Promise<LegacyMigrationResult> {
    const databasePath = resolve(this.options.databasePath);
    const outputDirectory = resolve(this.options.outputDirectory);
    const configuredEngagementRoots = this.options.engagementRoots ?? [];
    if (!this.options.sourceRoots.length && !configuredEngagementRoots.length) {
      throw new Error("At least one legacy source root or explicit engagement root is required");
    }
    const parentRootResolution = canonicalizeLegacySourceRoots(this.options.sourceRoots);
    const engagementRootResolution = canonicalizeLegacySourceRoots(configuredEngagementRoots);
    const parentRootIdentities = new Set(parentRootResolution.roots.map((root) => root.physicalIdentity));
    const ambiguousRoot = engagementRootResolution.roots.find((root) => parentRootIdentities.has(root.physicalIdentity));
    if (ambiguousRoot) {
      throw new Error(`A legacy path cannot be both a parent source root and an explicit engagement root: ${ambiguousRoot.canonicalPath}`);
    }
    const rootResolution: CanonicalLegacyRoots = {
      roots: [...parentRootResolution.roots, ...engagementRootResolution.roots],
      aliases: [...parentRootResolution.aliases, ...engagementRootResolution.aliases],
      missing: [...parentRootResolution.missing, ...engagementRootResolution.missing],
    };
    const parentSourceRoots = parentRootResolution.roots.map((root) => root.canonicalPath);
    const explicitEngagementRoots = engagementRootResolution.roots.map((root) => root.canonicalPath);
    const sourceRoots = [...parentSourceRoots, ...explicitEngagementRoots].sort();
    if (!sourceRoots.length && !this.options.dryRun) {
      throw new Error("No configured legacy source root exists; migration made no changes");
    }
    for (const root of sourceRoots) {
      if (!existsSync(root) || !statSync(root).isDirectory()) continue;
      const outputRelation = relative(root, outputDirectory);
      if (outputRelation === "" || (!outputRelation.startsWith(`..${sep}`) && outputRelation !== "..")) {
        throw new Error("Migration output directory must be outside every source root");
      }
    }
    const startedAt = this.clock().toISOString();
    const [childDiscovery, explicitDiscovery] = await Promise.all([
      discoverLegacyEngagements(parentSourceRoots),
      discoverLegacyEngagements(explicitEngagementRoots, { rootMode: "self" }),
    ]);
    const engagementDiscovery: LegacyEngagementDiscovery = {
      roots: rootResolution,
      manifests: [...childDiscovery.manifests, ...explicitDiscovery.manifests]
        .sort((left, right) => left.engagementKey.localeCompare(right.engagementKey)),
      excluded: [...childDiscovery.excluded, ...explicitDiscovery.excluded],
    };
    const discoveredInventory = await discoverLegacySources(sourceRoots);
    const engagementDirectories = engagementDiscovery.manifests.map((manifest) => manifest.engagementDirectory);
    const inventory = {
      included: discoveredInventory.included.filter((source) =>
        !engagementDirectories.some((directory) => pathInside(directory, source.absolutePath))),
      excluded: [
        ...discoveredInventory.excluded,
        ...rootResolution.missing.map((absolutePath) => ({ absolutePath, reason: "source root does not exist" })),
        ...engagementDiscovery.excluded.map((item) => ({ absolutePath: item.absolutePath, reason: `${item.category}: ${item.reason}` })),
      ],
    };
    if (inventory.included.some((source) => source.absolutePath === databasePath)) {
      throw new Error("Canonical database path must not be one of the legacy source files");
    }
    const sqliteWalWarnings = inventory.included
      .filter((source) => source.type === "kanban_sqlite" || source.type === "conversation_state_sqlite")
      .filter((source) => existsSync(`${source.absolutePath}-wal`) && statSync(`${source.absolutePath}-wal`).size > 0)
      .map((source) => `SQLite source has a non-empty WAL and must be quiesced/checkpointed: ${source.absolutePath}`);

    if (this.options.dryRun) {
      const migrationId = `dry_run_${randomUUID()}`;
      const reportDirectory = join(outputDirectory, migrationId);
      const reportPath = join(reportDirectory, "reconciliation.json");
      const report: ReconciliationReport = {
        migrationId,
        dryRun: true,
        startedAt,
        completedAt: this.clock().toISOString(),
        databasePath,
        sourceRoots,
        counts: { sources: inventory.included.length + engagementDiscovery.manifests.length, imported: 0, deduplicated: 0, quarantined: 0, skipped: 0 },
        targets: {},
        sources: [...inventory.included, ...engagementDiscovery.manifests.map<LegacySource>((manifest) => ({
          absolutePath: manifest.engagementDirectory,
          relativePath: manifest.engagementName,
          root: manifest.root,
          type: "engagement_manifest",
          sha256: manifest.sha256,
          byteSize: manifest.byteSize,
          modifiedAt: manifest.modifiedAt,
        }))].map((source) => ({
          path: source.absolutePath,
          type: source.type,
          sha256: source.sha256,
          bytes: source.byteSize,
          imported: 0,
          deduplicated: 0,
          quarantined: 0,
          skipped: 0,
        })),
        excluded: inventory.excluded,
        integrity: existsSync(databasePath)
          ? this.validateReadOnlyDatabase(databasePath)
          : { quickCheck: ["database does not exist; no canonical writes performed"], foreignKeyViolations: 0 },
        warnings: [
          "Dry run performed discovery and hashing only; no source backup or canonical import was created.",
          "Legacy nonterminal runs will be imported blocked and will never resume automatically.",
          ...sqliteWalWarnings,
        ],
        engagementDiscovery: engagementDiscoverySummary(engagementDiscovery, rootResolution),
      };
      atomicWrite(reportPath, `${JSON.stringify(report, null, 2)}\n`);
      return { migrationId, report, reportPath };
    }

    const database = createDatabaseConnection({ filename: databasePath, verifyIntegrity: existsSync(databasePath) });
    let migration: MigrationRunRecord | undefined;
    const metadata = new MigrationMetadataRepository(database, this.clock);
    try {
      migrateDatabase(database);
      metadata.ensureSchema();
      if (this.options.resumeMigrationId) {
        migration = metadata.getRun(this.options.resumeMigrationId);
        if (!migration) throw new Error(`Unknown migration run: ${this.options.resumeMigrationId}`);
        if (migration.status === "completed" || migration.status === "rolled_back") {
          throw new Error(`Migration ${migration.id} cannot resume from status ${migration.status}`);
        }
        if (resolve(migration.databasePath) !== databasePath) throw new Error("Resume database path does not match migration metadata");
        if (resolve(migration.outputDirectory) !== outputDirectory) throw new Error("Resume output directory does not match migration metadata");
        const recordedRoots = [...migration.sourceRoots].map((root) => resolve(root)).sort();
        const requestedRoots = [...sourceRoots].sort();
        if (JSON.stringify(recordedRoots) !== JSON.stringify(requestedRoots)) {
          throw new Error("Resume source roots do not match migration metadata");
        }
        const discoveredPaths = new Set([
          ...inventory.included.map((source) => source.absolutePath),
          ...engagementDiscovery.manifests.map((manifest) => manifest.engagementDirectory),
        ]);
        const missingRegistered = metadata.registeredSourcePaths(migration.id).filter((path) => !discoveredPaths.has(path));
        if (missingRegistered.length) {
          throw new Error(`Resume source inventory is incomplete; ${missingRegistered.length} previously registered source(s) are missing`);
        }
      } else {
        const backup = await createTimestampedBackup(database, join(outputDirectory, "database-backups"), "pre-legacy-import");
        const backupHash = await hashFile(backup.destination);
        migration = metadata.createRun({ sourceRoots, databasePath, outputDirectory });
        metadata.setBackup(migration.id, backup.destination, backupHash, {
          databaseBackupPath: backup.destination,
          databaseBackupSha256: backupHash,
          destinationDatabasePath: databasePath,
          requiresServiceStop: true,
        });
        migration = metadata.getRun(migration.id)!;
      }

      const migrationDirectory = join(outputDirectory, migration.id);
      const sourceBackupDirectory = join(migrationDirectory, "sources");
      mkdirSync(sourceBackupDirectory, { recursive: true, mode: 0o700 });
      const backupRows: string[] = ["source_sha256\tbyte_size\tmodified_at\toriginal_absolute_path\tbackup_relative_path"];
      const results: SourceMigrationResult[] = [];

      const priority: Record<LegacySource["type"], number> = {
        run_json: 0,
        kanban_sqlite: 0,
        session_json: 1,
        conversation_state_sqlite: 1,
        event_jsonl: 2,
        raw_llm_jsonl: 3,
        dashboard_log: 4,
        memory_json: 5,
        training_json: 6,
        artifact: 7,
        engagement_manifest: 8,
      };
      const orderedSources = [...inventory.included].sort((left, right) =>
        priority[left.type] - priority[right.type] || left.absolutePath.localeCompare(right.absolutePath));
      const capturedSources: Array<{
        source: LegacySource;
        backupRel: string;
        destination: string;
      }> = [];
      for (const discoveredSource of orderedSources) {
        const initialBackupRel = backupRelativePath(discoveredSource).split(sep).join("/");
        const initialDestination = join(sourceBackupDirectory, ...initialBackupRel.split("/"));
        let source: LegacySource;
        if (existsSync(initialDestination)) {
          source = discoveredSource;
        } else {
          source = await captureStableSource(discoveredSource, sourceBackupDirectory);
        }
        const backupRel = backupRelativePath(source).split(sep).join("/");
        const destination = join(sourceBackupDirectory, ...backupRel.split("/"));
        if (!existsSync(destination)) throw new Error(`Verified source backup is missing: ${source.absolutePath}`);
        const copiedHash = await hashFile(destination);
        if (copiedHash !== source.sha256 || statSync(destination).size !== source.byteSize) {
          throw new Error(`Source backup verification failed: ${source.absolutePath}`);
        }
        backupRows.push([
          source.sha256,
          source.byteSize,
          source.modifiedAt,
          source.absolutePath.replaceAll("\t", " "),
          backupRel,
        ].join("\t"));
        capturedSources.push({ source, backupRel, destination });
      }

      // Publish the verified source manifest before the first domain-row import.
      const sourceManifestPath = join(migrationDirectory, "source-manifest.tsv");
      atomicWrite(sourceManifestPath, `${backupRows.join("\n")}\n`);

      const engagementImporter = new LegacyEngagementImporter(
        database,
        metadata,
        migration.id,
        sourceBackupDirectory,
        this.clock,
      );
      for (const manifest of engagementDiscovery.manifests) {
        const manifestBackupRel = join("engagements", manifest.id, "engagement-manifest.json").split(sep).join("/");
        const result = await engagementImporter.importManifest(manifest, engagementDiscovery.excluded);
        results.push(result);
        backupRows.push([
          manifest.sha256,
          manifest.byteSize,
          manifest.modifiedAt,
          manifest.engagementDirectory.replaceAll("\t", " "),
          manifestBackupRel,
        ].join("\t"));
      }
      // Each engagement importer creates and verifies its protected source
      // backup before writing canonical rows. Publish those manifests alongside
      // the already-verified legacy file inventory after the bounded batch.
      atomicWrite(sourceManifestPath, `${backupRows.join("\n")}\n`);

      for (const { source, backupRel, destination } of capturedSources) {
        const sourceId = metadata.registerSource(migration.id, source, backupRel);
        metadata.markSource(sourceId, "importing");
        try {
          const result = await new LegacyImporter(
            database,
            metadata,
            migration.id,
            sourceId,
            source,
            this.clock,
            destination,
          ).import();
          results.push(result);
          metadata.markSource(sourceId, "completed");
        } catch (error) {
          metadata.markSource(sourceId, "failed", error instanceof Error ? error.message : String(error));
          throw error;
        }
      }
      assertDatabaseIntegrity(database);
      const integrity = databaseValidation(database);
      if (integrity.foreignKeyViolations) throw new Error(`Foreign-key reconciliation found ${integrity.foreignKeyViolations} violation(s)`);
      const reportPath = join(migrationDirectory, "reconciliation.json");
      const report: ReconciliationReport = {
        migrationId: migration.id,
        dryRun: false,
        startedAt: migration.startedAt,
        completedAt: this.clock().toISOString(),
        databasePath,
        sourceRoots,
        counts: sumCounts(results),
        targets: sumTargets(results),
        sources: results.map((result) => ({
          path: result.source.absolutePath,
          type: result.source.type,
          sha256: result.source.sha256,
          bytes: result.source.byteSize,
          imported: result.imported,
          deduplicated: result.deduplicated,
          quarantined: result.quarantined,
          skipped: result.skipped,
        })),
        excluded: inventory.excluded,
        ...(migration.databaseBackupPath && migration.databaseBackupSha256 ? {
          databaseBackup: { path: migration.databaseBackupPath, sha256: migration.databaseBackupSha256 },
          rollback: {
            databaseBackupPath: migration.databaseBackupPath,
            databaseBackupSha256: migration.databaseBackupSha256,
            destinationDatabasePath: databasePath,
            requiresServiceStop: true as const,
          },
        } : {}),
        sourceBackup: { directory: sourceBackupDirectory, manifestPath: sourceManifestPath },
        integrity,
        warnings: [
          "Original legacy files were not modified or deleted.",
          "Imported missions remain authorization-unverified and legacy nonterminal runs are blocked.",
          "Memory and lessons remain candidates/proposed until operator review.",
          "Raw confidential content remains in the protected backup and is not canonical reusable memory.",
          "Obsidian projection is not automatic; an exact reconciliation hash and explicit approval are required.",
        ],
        engagementDiscovery: engagementDiscoverySummary(engagementDiscovery, rootResolution),
      };
      atomicWrite(reportPath, `${JSON.stringify(report, null, 2)}\n`);
      metadata.completeRun(migration.id, report, reportPath);
      return { migrationId: migration.id, report, reportPath };
    } catch (error) {
      if (migration) metadata.failRun(migration.id, error instanceof Error ? error.message : String(error));
      throw error;
    } finally {
      database.close();
    }
  }

  private validateReadOnlyDatabase(path: string): ReconciliationReport["integrity"] {
    const database = createDatabaseConnection({ filename: path, readonly: true, fileMustExist: true });
    try { return databaseValidation(database); }
    finally { database.close(); }
  }
}

export interface RollbackOptions {
  readonly databasePath: string;
  readonly backupPath: string;
  readonly expectedSha256: string;
  readonly serviceStopped: boolean;
}

/** Restore a pre-import database atomically; refuses to run while service-stop is unconfirmed. */
export async function restoreMigrationBackup(options: RollbackOptions): Promise<void> {
  if (!options.serviceStopped) throw new Error("Rollback requires an explicit confirmation that the Ti-Scale service is stopped");
  const databasePath = resolve(options.databasePath);
  const backupPath = resolve(options.backupPath);
  if (!existsSync(backupPath)) throw new Error(`Backup does not exist: ${backupPath}`);
  const actualHash = await hashFile(backupPath);
  if (actualHash !== options.expectedSha256) throw new Error("Backup checksum does not match rollback metadata");
  const verification = createDatabaseConnection({ filename: backupPath, readonly: true, fileMustExist: true });
  try { assertDatabaseIntegrity(verification); }
  finally { verification.close(); }
  mkdirSync(dirname(databasePath), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(databasePath), `.${basename(databasePath)}.${process.pid}.${Date.now()}.restore`);
  try {
    // Preserve the current database and any SQLite sidecars before replacement.
    // This is a last-resort rollback-of-the-rollback copy, not a canonical source.
    if (existsSync(databasePath)) {
      const safety = `${databasePath}.pre-rollback-${new Date().toISOString().replace(/[:.]/gu, "-")}`;
      copyFileSync(databasePath, safety);
      chmodSync(safety, 0o600);
      for (const suffix of ["-wal", "-shm"] as const) {
        const sidecar = `${databasePath}${suffix}`;
        if (existsSync(sidecar)) {
          copyFileSync(sidecar, `${safety}${suffix}`);
          chmodSync(`${safety}${suffix}`, 0o600);
        }
      }
    }
    copyFileSync(backupPath, temporary);
    chmodSync(temporary, 0o600);
    // A WAL from the post-import database must never be replayed over the restored image.
    rmSync(`${databasePath}-wal`, { force: true });
    rmSync(`${databasePath}-shm`, { force: true });
    renameSync(temporary, databasePath);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}

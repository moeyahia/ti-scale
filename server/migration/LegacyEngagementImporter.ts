import { createHash } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import { extname, join, relative, resolve, sep } from "node:path";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { LegacyEngagementBrainProjector, type LegacyEngagementProjectionArtifact } from "./LegacyEngagementBrainProjector";
import type { LegacyEngagementExclusion, LegacyEngagementFile, LegacyEngagementManifest } from "./LegacyEngagementDiscovery";
import { MigrationMetadataRepository } from "./MigrationMetadataRepository";
import {
  assertSafeOpaqueId,
  assertSha256,
  ProtectedBackupStore,
  verifyDiscoveredRegularSource,
  verifyDiscoveredSymlinkSource,
  type DiscoveredRegularSource,
  type DiscoveredSymlinkSource,
  type VerifiedSourceIdentity,
} from "./ProtectedBackupStore";
import { redactLegacyText, safeJson, sha256Text } from "./SecretSafety";
import type {
  AttackKnowledgeExtractionBatchReport,
  LegacyBrainProjectionMode,
  LegacySource,
  LegacySourceRetentionMode,
  SourceMigrationResult,
} from "./types";

export interface LegacyEngagementImporterOptions {
  readonly sourceRetention?: LegacySourceRetentionMode;
  readonly verifiedReferenceAcknowledged?: boolean;
  readonly brainProjectionMode?: LegacyBrainProjectionMode;
  readonly attackKnowledgeOnlyAcknowledged?: boolean;
  readonly attackKnowledgeManifestHandler?: (
    manifest: LegacyEngagementManifest,
    database: SqliteDatabase,
    context: { readonly dryRun: boolean },
  ) => readonly AttackKnowledgeExtractionBatchReport[] | undefined | void;
  readonly testHooks?: {
    readonly afterVerifiedReferencePreflight?: (manifest: LegacyEngagementManifest) => void;
  };
}

interface VerifiedManifestSnapshot {
  readonly root: VerifiedSourceIdentity;
  readonly files: ReadonlyMap<string, VerifiedSourceIdentity>;
  readonly quarantined: ReadonlyMap<string, VerifiedSourceIdentity>;
}

function stableId(prefix: string, ...parts: string[]): string {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part).update("\0");
  return `${prefix}_legacy_${hash.digest("hex").slice(0, 40)}`;
}

function inside(root: string, candidate: string): boolean {
  const value = relative(resolve(root), resolve(candidate));
  return value === "" || (value !== ".." && !value.startsWith(`..${sep}`));
}

function assertTimestamp(value: string | undefined, label: string): asserts value is string {
  if (!value || !Number.isFinite(Date.parse(value))) throw new Error(`${label} is not a valid timestamp`);
}

function regularSource(
  source: Pick<LegacyEngagementFile, "absolutePath" | "sha256" | "byteSize" | "modifiedAt"> | LegacyEngagementExclusion,
  engagementDirectory: string,
): DiscoveredRegularSource {
  const sha256 = "sha256" in source ? source.sha256 : source.sourceSha256;
  if (!sha256) throw new Error("Regular source SHA-256 provenance is missing");
  const byteSize = source.byteSize;
  assertSha256(sha256, "regular source hash");
  if (!Number.isSafeInteger(byteSize) || byteSize === undefined || byteSize < 0) {
    throw new Error("Regular source byte-size provenance is invalid");
  }
  assertTimestamp(source.modifiedAt, "regular source modified time");
  return {
    absolutePath: source.absolutePath,
    containmentRoot: engagementDirectory,
    sha256,
    byteSize,
    modifiedAt: source.modifiedAt,
  };
}

function symlinkSource(
  source: LegacyEngagementExclusion,
  engagementDirectory: string,
): DiscoveredSymlinkSource {
  if (!source.sourceSha256) throw new Error("Symlink source SHA-256 provenance is missing");
  assertSha256(source.sourceSha256, "symlink source hash");
  if (!Number.isSafeInteger(source.byteSize) || source.byteSize === undefined || source.byteSize < 0) {
    throw new Error("Symlink source byte-size provenance is invalid");
  }
  assertTimestamp(source.modifiedAt, "symlink source modified time");
  return {
    absolutePath: source.absolutePath,
    containmentRoot: engagementDirectory,
    sha256: source.sourceSha256,
    byteSize: source.byteSize,
    modifiedAt: source.modifiedAt,
  };
}

function sameIdentity(left: VerifiedSourceIdentity, right: VerifiedSourceIdentity): boolean {
  return left.device === right.device
    && left.inode === right.inode
    && left.byteSize === right.byteSize
    && left.modifiedAt === right.modifiedAt
    && left.sha256 === right.sha256;
}

function assertForwardOnlySourceRetention(sourceRetention: LegacySourceRetentionMode): void {
  if (sourceRetention !== "verified-reference") {
    throw new Error(
      "Protected-copy legacy engagement import is disabled by operator policy; only forward-only verified-reference import is available",
    );
  }
}

function validateAndRevalidateManifest(
  manifest: LegacyEngagementManifest,
  expected?: VerifiedManifestSnapshot,
): VerifiedManifestSnapshot {
  assertSha256(manifest.engagementKey, "engagement key");
  assertSha256(manifest.sha256, "engagement manifest hash");
  assertSafeOpaqueId(manifest.id, "engagement manifest ID", "legacy_engagement_");
  if (manifest.id !== `legacy_engagement_${manifest.engagementKey.slice(0, 40)}`) {
    throw new Error("Engagement manifest ID does not match its engagement key");
  }
  if (!inside(manifest.root, manifest.engagementDirectory)) {
    throw new Error("Engagement manifest escaped its canonical source root");
  }
  const filePaths = new Set<string>();
  for (const file of manifest.files) {
    assertSha256(file.sha256, "engagement file hash");
    const normalized = relative(manifest.engagementDirectory, file.absolutePath).split(sep).join("/");
    if (!inside(manifest.engagementDirectory, file.absolutePath) || normalized !== file.relativePath) {
      throw new Error("Engagement file path does not match its manifest-relative path");
    }
    if (filePaths.has(file.relativePath)) throw new Error("Engagement manifest contains a duplicate file path");
    filePaths.add(file.relativePath);
  }
  const quarantineIds = new Set<string>();
  for (const exclusion of manifest.quarantined) {
    assertSafeOpaqueId(exclusion.quarantineId, "quarantine ID", "quarantine_");
    if (quarantineIds.has(exclusion.quarantineId)) throw new Error("Engagement manifest contains a duplicate quarantine ID");
    quarantineIds.add(exclusion.quarantineId);
    if (!inside(manifest.engagementDirectory, exclusion.absolutePath)) {
      throw new Error("Quarantined source escaped its manifest directory");
    }
    if (exclusion.engagementDirectory && resolve(exclusion.engagementDirectory) !== resolve(manifest.engagementDirectory)) {
      throw new Error("Quarantined source engagement binding does not match its manifest");
    }
  }

  const rootState = lstatSync(manifest.engagementDirectory);
  if (!rootState.isDirectory() || rootState.isSymbolicLink()) {
    throw new Error("Engagement source root is no longer a stable real directory");
  }
  if (!inside(realpathSync(manifest.root), realpathSync(manifest.engagementDirectory))) {
    throw new Error("Engagement source root escaped its canonical containment root");
  }
  const rootIdentity: VerifiedSourceIdentity = {
    device: rootState.dev,
    inode: rootState.ino,
    byteSize: rootState.size,
    modifiedAt: rootState.mtime.toISOString(),
    sha256: manifest.sha256,
  };
  const fileIdentities = new Map<string, VerifiedSourceIdentity>();
  const quarantineIdentities = new Map<string, VerifiedSourceIdentity>();
  // Complete this full source preflight before any canonical write.
  for (const file of manifest.files) {
    fileIdentities.set(
      file.relativePath,
      verifyDiscoveredRegularSource(regularSource(file, manifest.engagementDirectory)),
    );
  }
  for (const exclusion of manifest.quarantined) {
    if (exclusion.sourceKind === "regular_file") {
      quarantineIdentities.set(
        exclusion.quarantineId,
        verifyDiscoveredRegularSource(regularSource(exclusion, manifest.engagementDirectory)),
      );
    } else if (exclusion.sourceKind === "symlink") {
      quarantineIdentities.set(
        exclusion.quarantineId,
        verifyDiscoveredSymlinkSource(symlinkSource(exclusion, manifest.engagementDirectory)),
      );
    } else {
      throw new Error("Quarantined source lacks revalidatable discovery provenance");
    }
  }
  const current = { root: rootIdentity, files: fileIdentities, quarantined: quarantineIdentities };
  if (expected) {
    if (!sameIdentity(expected.root, current.root)) throw new Error("Engagement source directory changed during verified-reference import");
    for (const [key, identity] of expected.files) {
      const after = current.files.get(key);
      if (!after || !sameIdentity(identity, after)) throw new Error("Accepted source changed during verified-reference import");
    }
    for (const [key, identity] of expected.quarantined) {
      const after = current.quarantined.get(key);
      if (!after || !sameIdentity(identity, after)) throw new Error("Quarantined source changed during verified-reference import");
    }
  }
  return current;
}

function addTarget(targets: Record<string, number>, table: string, count = 1): void {
  targets[table] = (targets[table] ?? 0) + count;
}

interface QuarantineBackup {
  readonly protectedBackupRef: string;
  readonly backupRelativePath: string;
  readonly backupSha256: string;
  readonly backupMode: "byte_copy" | "metadata_only";
}

interface ReferenceOnlyQuarantine {
  readonly sourceReference: string;
  readonly sourceSha256: string;
  readonly device: number;
  readonly inode: number;
}

function manifestJson(
  manifest: LegacyEngagementManifest,
  backups: ReadonlyMap<string, string>,
  quarantineBackups: ReadonlyMap<string, QuarantineBackup>,
): string {
  return `${JSON.stringify({
    schemaVersion: 2,
    id: manifest.id,
    engagementKey: manifest.engagementKey,
    engagementName: manifest.engagementName,
    sourceManifestHash: manifest.sha256,
    modifiedAt: manifest.modifiedAt,
    files: manifest.files.map((file) => ({
      relativePath: file.relativePath,
      kind: file.kind,
      contentClass: file.contentClass,
      mediaType: file.mediaType ?? null,
      sha256: file.sha256,
      byteSize: file.byteSize,
      modifiedAt: file.modifiedAt,
      backupRelativePath: backups.get(file.relativePath),
    })),
    quarantined: manifest.quarantined.map((item) => {
      const backup = quarantineBackups.get(item.quarantineId);
      if (!backup) throw new Error("Quarantined source backup mapping is missing");
      return {
        quarantineId: item.quarantineId,
        category: item.category,
        sourceKind: item.sourceKind,
        sourceSha256: item.sourceSha256 ?? null,
        byteSize: item.byteSize ?? null,
        createdAt: item.createdAt ?? null,
        modifiedAt: item.modifiedAt ?? null,
        dispositionReceiptSha256: item.dispositionReceiptSha256 ?? null,
        normalizedSnapshotSha256: item.normalizedSnapshotSha256 ?? null,
        quarantineMappingId: item.quarantineMappingId ?? null,
        protectedBackupRef: backup.protectedBackupRef,
        backupRelativePath: backup.backupRelativePath,
        backupSha256: backup.backupSha256,
        backupMode: backup.backupMode,
        canonicalPromotion: "none",
      };
    }),
  }, null, 2)}\n`;
}

function backupQuarantinedSource(
  store: ProtectedBackupStore,
  manifest: LegacyEngagementManifest,
  exclusion: LegacyEngagementExclusion,
): QuarantineBackup {
  const protectedBackupRef = `legacy-protected-quarantine://${manifest.id}/${exclusion.quarantineId}`;
  const base = join("engagements", manifest.id, "quarantine", exclusion.quarantineId);
  if (exclusion.sourceKind === "regular_file" && exclusion.sourceSha256) {
    const backupRelativePath = join(base, `${exclusion.sourceSha256}.bin`).split(sep).join("/");
    const captured = store.captureRegularFile(backupRelativePath, regularSource(exclusion, manifest.engagementDirectory));
    const backupSha256 = captured.sha256;
    return { protectedBackupRef, backupRelativePath, backupSha256, backupMode: "byte_copy" };
  }

  if (exclusion.sourceKind !== "symlink" || !exclusion.sourceSha256) {
    throw new Error("Quarantined source lacks revalidatable discovery provenance");
  }
  verifyDiscoveredSymlinkSource(symlinkSource(exclusion, manifest.engagementDirectory));
  const descriptor = `${JSON.stringify({
    schemaVersion: 1,
    quarantineId: exclusion.quarantineId,
    category: exclusion.category,
    sourceKind: exclusion.sourceKind,
    sourceSha256: exclusion.sourceSha256 ?? null,
    byteSize: exclusion.byteSize ?? null,
    createdAt: exclusion.createdAt ?? null,
    modifiedAt: exclusion.modifiedAt ?? null,
    symlinkDereferenced: false,
    originalPathRetained: false,
    rawContentRetained: false,
  }, null, 2)}\n`;
  const backupSha256 = sha256Text(descriptor);
  const backupRelativePath = join(base, `metadata-${backupSha256}.json`).split(sep).join("/");
  const stored = store.ensureText(backupRelativePath, descriptor);
  if (stored.sha256 !== backupSha256) throw new Error("Protected quarantine metadata failed verification");
  return { protectedBackupRef, backupRelativePath, backupSha256, backupMode: "metadata_only" };
}

export function ensureLegacyEngagementSchema(database: SqliteDatabase): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS legacy_engagement_manifests (
      id TEXT PRIMARY KEY,
      engagement_key TEXT NOT NULL UNIQUE,
      root_identity TEXT NOT NULL,
      source_path TEXT NOT NULL,
      engagement_name TEXT NOT NULL,
      manifest_hash TEXT NOT NULL,
      mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
      run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
      latest_migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
      status TEXT NOT NULL CHECK (status IN ('imported', 'reconciled')),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS idx_legacy_engagement_manifest_migration
      ON legacy_engagement_manifests(latest_migration_id, updated_at DESC);
  `);
}

/** Forward-only verified-reference importer for one classified historical engagement manifest. */
export class LegacyEngagementImporter {
  readonly #projector: LegacyEngagementBrainProjector;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly metadata: MigrationMetadataRepository,
    private readonly migrationId: string,
    private readonly sourceBackupDirectory: string,
    private readonly clock: () => Date = () => new Date(),
    private readonly protectedBackupStoreFactory: (root: string) => ProtectedBackupStore =
      (root) => new ProtectedBackupStore(root),
    private readonly options: LegacyEngagementImporterOptions = {},
  ) {
    ensureLegacyEngagementSchema(database);
    this.#projector = new LegacyEngagementBrainProjector(database, clock);
  }

  async importManifest(
    manifest: LegacyEngagementManifest,
  ): Promise<SourceMigrationResult> {
    const sourceRetention = this.options.sourceRetention ?? "verified-reference";
    assertForwardOnlySourceRetention(sourceRetention);
    if (this.options.verifiedReferenceAcknowledged === false) {
      throw new Error("Verified-reference retention was explicitly rejected");
    }
    if (
      (this.options.brainProjectionMode ?? "legacy-engagement") === "attack-knowledge-only"
      && !this.options.attackKnowledgeOnlyAcknowledged
    ) {
      throw new Error("Attack-knowledge-only import requires deliberate acknowledgement");
    }
    if (sourceRetention === "verified-reference" &&
        (this.options.brainProjectionMode ?? "legacy-engagement") === "attack-knowledge-only") {
      return this.importAttackKnowledgeOnlyVerifiedReference(manifest);
    }
    if (sourceRetention === "verified-reference" && !this.database.inTransaction) {
      this.database.exec("BEGIN IMMEDIATE");
      try {
        const result = this.importManifestWithinBoundary(manifest, sourceRetention);
        this.database.exec("COMMIT");
        return result;
      } catch (error) {
        if (this.database.inTransaction) this.database.exec("ROLLBACK");
        throw error;
      }
    }
    return this.importManifestWithinBoundary(manifest, sourceRetention);
  }

  /**
   * Verified-reference attack extraction deliberately keeps filesystem I/O
   * outside the SQLite write reservation. Inventory commits, extraction
   * writes, and terminal source status each use their own bounded transaction.
   */
  private importAttackKnowledgeOnlyVerifiedReference(
    manifest: LegacyEngagementManifest,
  ): SourceMigrationResult {
    const verifiedSnapshot = validateAndRevalidateManifest(manifest);
    this.options.testHooks?.afterVerifiedReferencePreflight?.(manifest);
    // Catch the deterministic preflight race before creating inventory rows.
    validateAndRevalidateManifest(manifest, verifiedSnapshot);
    const source: LegacySource = {
      absolutePath: manifest.engagementDirectory,
      relativePath: manifest.engagementName,
      root: manifest.root,
      type: "engagement_manifest",
      sha256: manifest.sha256,
      byteSize: manifest.byteSize,
      modifiedAt: manifest.modifiedAt,
    };
    let sourceId = "";
    const inventoryResult = inImmediateTransaction(this.database, () => {
      sourceId = this.metadata.registerSource(
        this.migrationId,
        source,
        undefined,
        {
          retentionMode: "verified-reference",
          device: verifiedSnapshot.root.device,
          inode: verifiedSnapshot.root.inode,
        },
      );
      this.metadata.markSource(sourceId, "importing");
      return this.importAttackKnowledgeOnlyManifest(
        manifest,
        source,
        sourceId,
        verifiedSnapshot,
      );
    });
    try {
      // Parsing uses independently pinned file descriptors and bounded DB
      // transactions. No BEGIN IMMEDIATE is held while source bytes are read.
      this.options.attackKnowledgeManifestHandler?.(manifest, this.database, { dryRun: false });
      validateAndRevalidateManifest(manifest, verifiedSnapshot);
      inImmediateTransaction(this.database, () => this.metadata.markSource(sourceId, "completed"));
      return inventoryResult;
    } catch (error) {
      inImmediateTransaction(this.database, () => this.metadata.markSource(
        sourceId,
        "failed",
        error instanceof Error ? error.message : String(error),
      ));
      throw error;
    }
  }

  private importManifestWithinBoundary(
    manifest: LegacyEngagementManifest,
    sourceRetention: LegacySourceRetentionMode,
  ): SourceMigrationResult {
    assertForwardOnlySourceRetention(sourceRetention);
    const verifiedSnapshot = validateAndRevalidateManifest(manifest);
    if (sourceRetention === "verified-reference") {
      this.options.testHooks?.afterVerifiedReferencePreflight?.(manifest);
    }
    const source: LegacySource = {
      absolutePath: manifest.engagementDirectory,
      relativePath: manifest.engagementName,
      root: manifest.root,
      type: "engagement_manifest",
      sha256: manifest.sha256,
      byteSize: manifest.byteSize,
      modifiedAt: manifest.modifiedAt,
    };
    const backupPaths = new Map<string, string>();
    const quarantineBackups = new Map<string, QuarantineBackup>();
    const quarantineReferences = new Map<string, ReferenceOnlyQuarantine>();
    let manifestRelativePath: string | undefined;
    let renderedManifest: string | undefined;
    if (sourceRetention === "protected-copy") {
      const protectedBackups = this.protectedBackupStoreFactory(this.sourceBackupDirectory);
      for (const [index, file] of manifest.files.entries()) {
        const extension = /^[.][A-Za-z0-9]{1,12}$/u.test(extname(file.relativePath)) ? extname(file.relativePath).toLowerCase() : "";
        const relativeBackup = join("engagements", manifest.id, "files", `${String(index).padStart(6, "0")}-${file.sha256}${extension}`).split(sep).join("/");
        protectedBackups.captureRegularFile(relativeBackup, regularSource(file, manifest.engagementDirectory));
        backupPaths.set(file.relativePath, relativeBackup);
      }
      for (const exclusion of manifest.quarantined) {
        if (!inside(manifest.engagementDirectory, exclusion.absolutePath)) throw new Error("Quarantined source escaped its manifest directory");
        quarantineBackups.set(
          exclusion.quarantineId,
          backupQuarantinedSource(protectedBackups, manifest, exclusion),
        );
      }
      manifestRelativePath = join("engagements", manifest.id, "engagement-manifest.v2.json").split(sep).join("/");
      renderedManifest = manifestJson(manifest, backupPaths, quarantineBackups);
      protectedBackups.ensureText(manifestRelativePath, renderedManifest);
    }
    const sourceId = this.metadata.registerSource(
      this.migrationId,
      source,
      manifestRelativePath,
      sourceRetention === "verified-reference" ? {
        retentionMode: sourceRetention,
        device: verifiedSnapshot.root.device,
        inode: verifiedSnapshot.root.inode,
      } : undefined,
    );
    if (sourceRetention === "verified-reference") {
      for (const exclusion of manifest.quarantined) {
        const identity = verifiedSnapshot.quarantined.get(exclusion.quarantineId);
        if (!identity || !exclusion.sourceSha256) throw new Error("Quarantined reference verification is incomplete");
        quarantineReferences.set(exclusion.quarantineId, {
          sourceReference: `legacy-private-source://${sourceId}/quarantine/${exclusion.quarantineId}`,
          sourceSha256: exclusion.sourceSha256,
          device: identity.device,
          inode: identity.inode,
        });
      }
    }
    this.metadata.markSource(sourceId, "importing");

    if ((this.options.brainProjectionMode ?? "legacy-engagement") === "attack-knowledge-only") {
      if (sourceRetention !== "verified-reference") {
        throw new Error("Attack-knowledge-only import requires verified-reference source retention");
      }
      return this.importAttackKnowledgeOnlyManifest(manifest, source, sourceId, verifiedSnapshot);
    }

    try {
    const targets: Record<string, number> = {};
    let imported = 0;
    let deduplicated = 0;
    let quarantined = 0;
    let skipped = 0;
    const sourceIdentity = sha256Text(`engagement_manifest\0${manifest.engagementKey}`);
    const missionId = stableId("mission_engagement", manifest.engagementKey);
    const runId = stableId("run_engagement", manifest.engagementKey);
    const engagementId = `engagement_legacy_${manifest.engagementKey.slice(0, 40)}`;
    const manifestArtifactId = stableId("artifact_manifest", manifest.engagementKey, manifest.sha256);
    const now = this.clock().toISOString();

    const previousManifest = this.metadata.previousItem(sourceIdentity, manifest.sha256, "manifest", manifest.sha256);
    inImmediateTransaction(this.database, () => {
      this.database.prepare(`
        INSERT OR IGNORE INTO missions (
          id, name, objective, journey, status, authorization_status, engagement_id,
          scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
          created_by, version, created_at, updated_at, control_plane
        ) VALUES (?, ?, ?, 'guided', 'paused', 'unverified', ?, ?, '[]', ?, ?,
          'import:legacy-engagement', 1, ?, ?, 'legacy')
      `).run(
        missionId,
        redactLegacyText(manifest.engagementName, 240),
        "Imported historical engagement. Authorization, scope, findings, and outcome require operator reconciliation before any new execution.",
        engagementId,
        safeJson({ legacy: true, executionAuthorized: false, sourceManifestHash: manifest.sha256 }),
        safeJson({ source: "legacy_engagement_import", preserveUntilReviewed: true }),
        safeJson({ reusableRetrieval: false, allowAutonomous: false }),
        manifest.modifiedAt,
        now,
      );
      this.database.prepare(`
        INSERT OR IGNORE INTO runs (
          id, mission_id, journey, status, progress, status_reason, next_action_summary,
          budget_json, budget_usage_json, retry_count, replan_count,
          started_at, ended_at, created_at, updated_at, version, control_plane
        ) VALUES (?, ?, 'guided', 'blocked', 0, ?, ?, '{}', '{}', 0, 0, ?, NULL, ?, ?, 1, 'legacy')
      `).run(
        runId,
        missionId,
        "Imported historical run is blocked from execution until its authorization and canonical relationships are reviewed.",
        "Review imported history or create a new authorized run",
        manifest.modifiedAt,
        manifest.modifiedAt,
        now,
      );
      this.database.prepare(`
        INSERT OR IGNORE INTO artifacts (
          id, mission_id, run_id, journey, artifact_type, storage_uri, content_hash, byte_size,
          media_type, sensitivity, metadata_json, created_at
        ) VALUES (?, ?, ?, 'guided', 'legacy_engagement_manifest', ?, ?, ?, 'application/json', 'restricted', ?, ?)
      `).run(
        manifestArtifactId,
        missionId,
        runId,
        sourceRetention === "protected-copy"
          ? `legacy-migration-manifest://${sourceId}`
          : `legacy-private-manifest-reference://${sourceId}`,
        manifest.sha256,
        renderedManifest ? Buffer.byteLength(renderedManifest, "utf8") : manifest.byteSize,
        safeJson(sourceRetention === "protected-copy" ? {
          backupRelativePath: manifestRelativePath,
          sourceManifestHash: manifest.sha256,
          sourceRetention,
          immutableCopiedStorage: true,
        } : {
          sourceReference: `legacy-private-source://${sourceId}`,
          sourceManifestHash: manifest.sha256,
          sourceRetention,
          immutableCopiedStorage: false,
          availabilityDependsOnOperatorSourceTree: true,
        }),
        manifest.modifiedAt,
      );
      this.database.prepare(`
        INSERT INTO legacy_engagement_manifests (
          id, engagement_key, root_identity, source_path, engagement_name, manifest_hash,
          mission_id, run_id, latest_migration_id, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'imported', ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          manifest_hash = excluded.manifest_hash,
          latest_migration_id = excluded.latest_migration_id,
          status = 'imported',
          updated_at = excluded.updated_at
      `).run(
        manifest.id,
        manifest.engagementKey,
        manifest.rootIdentity,
        manifest.engagementDirectory,
        redactLegacyText(manifest.engagementName, 240),
        manifest.sha256,
        missionId,
        runId,
        this.migrationId,
        now,
        now,
      );
      if (!previousManifest) {
        this.metadata.recordItem({
          migrationId: this.migrationId,
          sourceId,
          sourceIdentity,
          sourceSha256: manifest.sha256,
          itemKey: "manifest",
          itemHash: manifest.sha256,
          status: "imported",
          targetTable: "missions",
          targetId: missionId,
        });
      }
    });
    if (previousManifest) deduplicated += 1;
    else imported += 1;
    addTarget(targets, "missions");
    addTarget(targets, "runs");
    addTarget(targets, "artifacts");

    const projectedArtifacts: LegacyEngagementProjectionArtifact[] = [];
    for (const file of manifest.files) {
      const itemKey = `file:${file.relativePath}`;
      const previous = this.metadata.previousItem(sourceIdentity, manifest.sha256, itemKey, file.sha256);
      const artifactId = stableId("artifact_engagement", manifest.engagementKey, file.relativePath, file.sha256);
      const evidenceCandidateId = ["evidence", "capture"].includes(file.kind)
        ? stableId("evidence_candidate_engagement", artifactId)
        : undefined;
      const backupRelativePath = backupPaths.get(file.relativePath);
      if (sourceRetention === "protected-copy" && !backupRelativePath) {
        throw new Error("Engagement file backup mapping is missing");
      }
      const identity = verifiedSnapshot.files.get(file.relativePath);
      if (!identity) throw new Error("Engagement file reference verification is missing");
      const sourceReference = `legacy-private-source://${sourceId}/accepted/${file.sha256}`;
      inImmediateTransaction(this.database, () => {
        this.database.prepare(`
          INSERT OR IGNORE INTO artifacts (
            id, mission_id, run_id, journey, artifact_type, storage_uri, content_hash, byte_size,
            media_type, sensitivity, metadata_json, created_at
          ) VALUES (?, ?, ?, 'guided', ?, ?, ?, ?, ?, 'restricted', ?, ?)
        `).run(
          artifactId,
          missionId,
          runId,
          `legacy_${file.kind}`,
          sourceRetention === "protected-copy"
            ? `legacy-engagement-source://${sourceId}/${file.sha256}`
            : sourceReference,
          file.sha256,
          file.byteSize,
          file.mediaType ?? null,
          safeJson({
            relativePath: file.relativePath,
            ...(sourceRetention === "protected-copy" ? { backupRelativePath } : { sourceReference }),
            sourceManifestHash: manifest.sha256,
            contentClass: file.contentClass,
            sourceRetention,
            immutableCopiedStorage: sourceRetention === "protected-copy",
            ...(sourceRetention === "verified-reference" ? {
              sourceDevice: identity.device,
              sourceInode: identity.inode,
              sourceModifiedAt: identity.modifiedAt,
              availabilityDependsOnOperatorSourceTree: true,
            } : {}),
            rawContentRetainedAsReusableMemory: false,
          }),
          file.modifiedAt,
        );
        if (file.kind === "log") {
          this.database.prepare(`
            INSERT OR IGNORE INTO engagement_log_records (
              id, mission_id, run_id, severity, domain, record_type, human_summary,
              technical_payload_json, content_hash, sensitivity, occurred_at, created_at
            ) VALUES (?, ?, ?, 'info', 'legacy_import', 'historical_log_artifact', ?, ?, ?, 'restricted', ?, ?)
          `).run(
            stableId("engagement_log", artifactId),
            missionId,
            runId,
            `Imported historical log metadata for ${redactLegacyText(file.relativePath.split("/").at(-1), 240)}`,
            safeJson({ artifactId, rawOutputIsEvidence: false, sourceManifestHash: manifest.sha256 }),
            file.sha256,
            file.modifiedAt,
            now,
          );
        }
        if (evidenceCandidateId) {
          this.database.prepare(`
            INSERT OR IGNORE INTO evidence_candidates (
              id, mission_id, run_id, artifact_id, evidence_type, label, meaning,
              promotion_reason, validation_requirements_json, state, sensitivity,
              proposed_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'candidate', 'restricted', 'import:legacy-engagement', ?)
          `).run(
            evidenceCandidateId,
            missionId,
            runId,
            artifactId,
            file.kind === "capture" ? "page_or_screen_capture" : "operator_supplied_historical_artifact",
            redactLegacyText(file.relativePath.split("/").at(-1), 240),
            "Potential historical support requiring provenance and claim validation before promotion.",
            "The file was located in an explicit evidence or capture class; location alone does not verify a claim.",
            safeJson(["Review content under restricted access", "Link a specific claim", "Verify source and acquisition context"]),
            file.modifiedAt,
          );
        }
        if (!previous) {
          this.metadata.recordItem({
            migrationId: this.migrationId,
            sourceId,
            sourceIdentity,
            sourceSha256: manifest.sha256,
            itemKey,
            itemHash: file.sha256,
            status: "imported",
            targetTable: "artifacts",
            targetId: artifactId,
          });
        }
      });
      if (previous) deduplicated += 1;
      else imported += 1;
      addTarget(targets, "artifacts");
      if (file.kind === "log") addTarget(targets, "engagement_log_records");
      if (evidenceCandidateId) addTarget(targets, "evidence_candidates");
      projectedArtifacts.push({ artifactId, relativePath: file.relativePath, kind: file.kind, contentHash: file.sha256, ...(evidenceCandidateId ? { evidenceCandidateId } : {}) });
    }

    for (const exclusion of manifest.quarantined) {
      const backup = quarantineBackups.get(exclusion.quarantineId);
      const reference = quarantineReferences.get(exclusion.quarantineId);
      if (sourceRetention === "protected-copy" && !backup) throw new Error("Quarantined source backup mapping is missing");
      if (sourceRetention === "verified-reference" && !reference) throw new Error("Quarantined source reference mapping is missing");
      const itemKey = `excluded:${exclusion.quarantineId}`;
      const itemHash = sha256Text([
        exclusion.category,
        exclusion.sourceKind,
        exclusion.sourceSha256 ?? "",
        String(exclusion.byteSize ?? ""),
        exclusion.dispositionReceiptSha256 ?? "",
        exclusion.normalizedSnapshotSha256 ?? "",
        exclusion.quarantineMappingId ?? "",
        sourceRetention,
        backup?.backupSha256 ?? reference?.sourceSha256 ?? "",
      ].join("\0"));
      const previous = this.metadata.previousItem(sourceIdentity, manifest.sha256, itemKey, itemHash);
      if (previous) {
        deduplicated += 1;
        continue;
      }
      this.metadata.quarantine(this.migrationId, {
        sourceSha256: manifest.sha256,
        sourcePath: exclusion.absolutePath,
        itemKey,
        itemHash,
        category: exclusion.category,
        reason: exclusion.reason,
        sourceContentSha256: exclusion.sourceSha256,
        byteSize: exclusion.byteSize,
        sourceCreatedAt: exclusion.createdAt,
        sourceModifiedAt: exclusion.modifiedAt,
        ...(backup ? {
          protectedBackupRef: backup.protectedBackupRef,
          protectedBackupSha256: backup.backupSha256,
          backupMode: backup.backupMode,
          retentionMode: sourceRetention,
        } : {
          sourceReference: reference!.sourceReference,
          retentionMode: sourceRetention,
          sourceDevice: reference!.device,
          sourceInode: reference!.inode,
        }),
      });
      this.metadata.recordItem({
        migrationId: this.migrationId,
        sourceId,
        sourceIdentity,
        sourceSha256: manifest.sha256,
        itemKey,
        itemHash,
        status: "quarantined",
        errorCategory: exclusion.category,
      });
      quarantined += 1;
    }

    const projection = this.#projector.project({
      migrationId: this.migrationId,
      manifest,
      missionId,
      runId,
      manifestArtifactId,
      artifacts: projectedArtifacts,
      sourceRetention,
    });
    addTarget(targets, "memory_nodes", projection.nodeIds.length);
    addTarget(targets, "memory_edges", projection.edgeIds.length);
    this.database.prepare("UPDATE legacy_engagement_manifests SET status='reconciled', updated_at=? WHERE id=?")
      .run(this.clock().toISOString(), manifest.id);
    if (sourceRetention === "verified-reference") {
      validateAndRevalidateManifest(manifest, verifiedSnapshot);
    }
    this.metadata.markSource(sourceId, "completed");
    return { source, imported, deduplicated, quarantined, skipped, targetCounts: targets };
    } catch (error) {
      this.metadata.markSource(sourceId, "failed", error instanceof Error ? error.message : String(error));
      throw error;
    }
  }

  private importAttackKnowledgeOnlyManifest(
    manifest: LegacyEngagementManifest,
    source: LegacySource,
    sourceId: string,
    verifiedSnapshot: VerifiedManifestSnapshot,
  ): SourceMigrationResult {
    const targetCounts: Record<string, number> = {};
    let imported = 0;
    let deduplicated = 0;
    let quarantined = 0;
    const sourceIdentity = sha256Text(`engagement_manifest\0${manifest.engagementKey}`);

    for (const file of manifest.files) {
      const identity = verifiedSnapshot.files.get(file.relativePath);
      if (!identity) throw new Error("Accepted source reference identity is missing");
      this.metadata.registerSourceObject({
        migrationId: this.migrationId,
        sourceId,
        objectKey: `accepted:${file.relativePath}`,
        sourcePath: file.absolutePath,
        objectKind: "accepted",
        classification: file.kind,
        sourceSha256: file.sha256,
        byteSize: file.byteSize,
        modifiedAt: file.modifiedAt,
        sourceDevice: identity.device,
        sourceInode: identity.inode,
      });
      const itemKey = `reference:file:${file.relativePath}`;
      const previous = this.metadata.previousItem(sourceIdentity, manifest.sha256, itemKey, file.sha256);
      if (previous) deduplicated += 1;
      else {
        this.metadata.recordItem({
          migrationId: this.migrationId,
          sourceId,
          sourceIdentity,
          sourceSha256: manifest.sha256,
          itemKey,
          itemHash: file.sha256,
          status: "imported",
          targetTable: "legacy_migration_source_objects",
        });
        imported += 1;
      }
      addTarget(targetCounts, "legacy_migration_source_objects");
    }

    for (const exclusion of manifest.quarantined) {
      const identity = verifiedSnapshot.quarantined.get(exclusion.quarantineId);
      if (!identity || !exclusion.sourceSha256 || exclusion.byteSize === undefined || !exclusion.modifiedAt) {
        throw new Error("Quarantined source reference identity is incomplete");
      }
      const sourceReference = this.metadata.registerSourceObject({
        migrationId: this.migrationId,
        sourceId,
        objectKey: `quarantine:${exclusion.quarantineId}`,
        sourcePath: exclusion.absolutePath,
        objectKind: exclusion.sourceKind === "symlink" ? "symlink" : "quarantined",
        classification: exclusion.category,
        sourceSha256: exclusion.sourceSha256,
        byteSize: exclusion.byteSize,
        modifiedAt: exclusion.modifiedAt,
        sourceDevice: identity.device,
        sourceInode: identity.inode,
      });
      const itemKey = `reference:excluded:${exclusion.quarantineId}`;
      const itemHash = sha256Text([
        exclusion.category,
        exclusion.sourceKind,
        exclusion.sourceSha256,
        String(exclusion.byteSize),
        exclusion.dispositionReceiptSha256 ?? "",
        exclusion.normalizedSnapshotSha256 ?? "",
        exclusion.quarantineMappingId ?? "",
        "verified-reference",
      ].join("\0"));
      const previous = this.metadata.previousItem(sourceIdentity, manifest.sha256, itemKey, itemHash);
      if (previous) deduplicated += 1;
      else {
        this.metadata.quarantine(this.migrationId, {
          sourceSha256: manifest.sha256,
          sourcePath: exclusion.absolutePath,
          itemKey,
          itemHash,
          category: exclusion.category,
          reason: exclusion.reason,
          sourceContentSha256: exclusion.sourceSha256,
          byteSize: exclusion.byteSize,
          sourceCreatedAt: exclusion.createdAt,
          sourceModifiedAt: exclusion.modifiedAt,
          sourceReference,
          retentionMode: "verified-reference",
          sourceDevice: identity.device,
          sourceInode: identity.inode,
        });
        this.metadata.recordItem({
          migrationId: this.migrationId,
          sourceId,
          sourceIdentity,
          sourceSha256: manifest.sha256,
          itemKey,
          itemHash,
          status: "quarantined",
          errorCategory: exclusion.category,
        });
        quarantined += 1;
      }
      addTarget(targetCounts, "legacy_migration_source_objects");
    }

    return {
      source,
      imported,
      deduplicated,
      quarantined,
      skipped: 0,
      targetCounts,
    };
  }
}

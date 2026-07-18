import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  createReadStream,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { LegacyEngagementBrainProjector, type LegacyEngagementProjectionArtifact } from "./LegacyEngagementBrainProjector";
import type { LegacyEngagementDiscovery, LegacyEngagementManifest } from "./LegacyEngagementDiscovery";
import { MigrationMetadataRepository } from "./MigrationMetadataRepository";
import { redactLegacyText, safeJson, sha256Text } from "./SecretSafety";
import type { LegacySource, SourceMigrationResult } from "./types";

function stableId(prefix: string, ...parts: string[]): string {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part).update("\0");
  return `${prefix}_legacy_${hash.digest("hex").slice(0, 40)}`;
}

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

function inside(root: string, candidate: string): boolean {
  const value = relative(resolve(root), resolve(candidate));
  return value === "" || (value !== ".." && !value.startsWith(`..${sep}`));
}

function addTarget(targets: Record<string, number>, table: string, count = 1): void {
  targets[table] = (targets[table] ?? 0) + count;
}

function manifestJson(manifest: LegacyEngagementManifest, backups: ReadonlyMap<string, string>): string {
  return `${JSON.stringify({
    schemaVersion: 1,
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
  }, null, 2)}\n`;
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

/** Backup-first importer for one classified historical engagement manifest. */
export class LegacyEngagementImporter {
  readonly #projector: LegacyEngagementBrainProjector;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly metadata: MigrationMetadataRepository,
    private readonly migrationId: string,
    private readonly sourceBackupDirectory: string,
    private readonly clock: () => Date = () => new Date(),
  ) {
    ensureLegacyEngagementSchema(database);
    this.#projector = new LegacyEngagementBrainProjector(database, clock);
  }

  async importManifest(
    manifest: LegacyEngagementManifest,
    exclusions: LegacyEngagementDiscovery["excluded"] = [],
  ): Promise<SourceMigrationResult> {
    if (!inside(manifest.root, manifest.engagementDirectory)) throw new Error("Engagement manifest escaped its canonical source root");
    const source: LegacySource = {
      absolutePath: manifest.engagementDirectory,
      relativePath: manifest.engagementName,
      root: manifest.root,
      type: "engagement_manifest",
      sha256: manifest.sha256,
      byteSize: manifest.byteSize,
      modifiedAt: manifest.modifiedAt,
    };
    const manifestDirectory = join(this.sourceBackupDirectory, "engagements", manifest.id);
    const fileDirectory = join(manifestDirectory, "files");
    mkdirSync(fileDirectory, { recursive: true, mode: 0o700 });
    const backupPaths = new Map<string, string>();
    for (const [index, file] of manifest.files.entries()) {
      if (!inside(manifest.engagementDirectory, file.absolutePath)) throw new Error("Engagement file escaped its manifest directory");
      const extension = /^[.][A-Za-z0-9]{1,12}$/u.test(extname(file.relativePath)) ? extname(file.relativePath).toLowerCase() : "";
      const relativeBackup = join("engagements", manifest.id, "files", `${String(index).padStart(6, "0")}-${file.sha256}${extension}`).split(sep).join("/");
      const destination = join(this.sourceBackupDirectory, ...relativeBackup.split("/"));
      if (!existsSync(destination)) {
        const temporary = `${destination}.${process.pid}.${Date.now()}.tmp`;
        const before = statSync(file.absolutePath);
        try {
          copyFileSync(file.absolutePath, temporary);
          chmodSync(temporary, 0o600);
          const [originalHash, copiedHash] = await Promise.all([hashFile(file.absolutePath), hashFile(temporary)]);
          const after = statSync(file.absolutePath);
          if (
            originalHash !== file.sha256 || copiedHash !== file.sha256 ||
            before.size !== after.size || before.mtimeMs !== after.mtimeMs
          ) throw new Error("Engagement file changed while its protected backup was created");
          renameSync(temporary, destination);
        } catch (error) {
          rmSync(temporary, { force: true });
          throw error;
        }
      } else if (await hashFile(destination) !== file.sha256) {
        throw new Error("Existing engagement source backup failed hash verification");
      }
      backupPaths.set(file.relativePath, relativeBackup);
    }
    const manifestRelativePath = join("engagements", manifest.id, "engagement-manifest.json").split(sep).join("/");
    const manifestPath = join(this.sourceBackupDirectory, ...manifestRelativePath.split("/"));
    const renderedManifest = manifestJson(manifest, backupPaths);
    if (!existsSync(manifestPath)) atomicWrite(manifestPath, renderedManifest);
    else if (readFileSync(manifestPath, "utf8") !== renderedManifest) {
      throw new Error("Existing engagement manifest backup failed content verification");
    }
    const sourceId = this.metadata.registerSource(this.migrationId, source, manifestRelativePath);
    this.metadata.markSource(sourceId, "importing");

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
        `legacy-migration-manifest://${sourceId}`,
        manifest.sha256,
        Buffer.byteLength(renderedManifest, "utf8"),
        safeJson({ backupRelativePath: manifestRelativePath, sourceManifestHash: manifest.sha256 }),
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
      if (!backupRelativePath) throw new Error("Engagement file backup mapping is missing");
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
          `legacy-engagement-source://${sourceId}/${file.sha256}`,
          file.sha256,
          file.byteSize,
          file.mediaType ?? null,
          safeJson({
            relativePath: file.relativePath,
            backupRelativePath,
            sourceManifestHash: manifest.sha256,
            contentClass: file.contentClass,
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

    for (const exclusion of exclusions.filter((item) => inside(manifest.engagementDirectory, item.absolutePath))) {
      const itemKey = `excluded:${sha256Text(relative(manifest.engagementDirectory, exclusion.absolutePath)).slice(0, 32)}`;
      const itemHash = sha256Text(`${exclusion.category}\0${exclusion.reason}`);
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
    });
    addTarget(targets, "memory_nodes", projection.nodeIds.length);
    addTarget(targets, "memory_edges", projection.edgeIds.length);
    this.database.prepare("UPDATE legacy_engagement_manifests SET status='reconciled', updated_at=? WHERE id=?")
      .run(this.clock().toISOString(), manifest.id);
    this.metadata.markSource(sourceId, "completed");
    return { source, imported, deduplicated, quarantined, skipped, targetCounts: targets };
    } catch (error) {
      this.metadata.markSource(sourceId, "failed", error instanceof Error ? error.message : String(error));
      throw error;
    }
  }
}

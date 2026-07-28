import { createHash, randomUUID } from "node:crypto";
import {
  copyFileSync,
  closeSync,
  constants,
  createReadStream,
  existsSync,
  fchmodSync,
  fchownSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { hashJson } from "../orchestration/serialization";
import {
  assertDatabaseIntegrity,
  checkDatabaseIntegrity,
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../db";
import { LegacyImporter } from "./LegacyImporter";
import { LegacyEngagementImporter } from "./LegacyEngagementImporter";
import {
  canonicalizeLegacySourceRoots,
  discoverLegacyEngagements,
  EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON,
  SETTLED_SOURCE_DEFERRED_REASON,
  type CanonicalLegacyRoots,
  type LegacyEngagementDiscovery,
} from "./LegacyEngagementDiscovery";
import { MigrationMetadataRepository, type MigrationRunRecord } from "./MigrationMetadataRepository";
import { HistoricalAttackKnowledgeExtractionReconciliationService } from "./HistoricalAttackKnowledgeExtractionReconciliationService";
import {
  verifyDiscoveredRegularSource,
  type VerifiedSourceIdentity,
} from "./ProtectedBackupStore";
import { sha256Text } from "./SecretSafety";
import { discoverLegacySources } from "./SourceDiscovery";
import {
  historicalSourceDeltaBaselineBinding,
  quarantineSensitivity,
  semanticEngagementEligibility,
} from "./HistoricalSourceDeltaPlanner";
import {
  historicalDeltaAdmissionInventoryHash,
  type HistoricalSourceDeltaAdmission,
  type HistoricalSourceDeltaExecutionPlan,
} from "./HistoricalSourceDeltaExecutionPlan";
import {
  indexHistoricalSqliteSnapshotQuarantineFiles,
  summarizeHistoricalSqliteSnapshotQuarantineMappings,
} from "./HistoricalSqliteSnapshotQuarantineMapping";
import type {
  AttackKnowledgeExtractionBatchReport,
  AttackKnowledgeExtractionReconciliation,
  DeferredLegacySource,
  LegacyMigrationOptions,
  LegacyMigrationResult,
  LegacySource,
  LegacySourceDiscoveryCoverage,
  MigrationCounts,
  ReconciliationReport,
  SourceMigrationResult,
} from "./types";

export const MIN_SETTLE_SECONDS = 60;
export const MAX_SETTLE_SECONDS = 86_400;

function normalizeSettleSeconds(value: number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || value < MIN_SETTLE_SECONDS || value > MAX_SETTLE_SECONDS) {
    throw new RangeError(
      `settleSeconds must be an integer between ${MIN_SETTLE_SECONDS} and ${MAX_SETTLE_SECONDS}`,
    );
  }
  return value;
}

function settledCutoffAt(startedAt: string, settleSeconds: number): string {
  const started = Date.parse(startedAt);
  if (!Number.isFinite(started)) throw new Error("Migration start timestamp is invalid");
  return new Date(started - settleSeconds * 1_000).toISOString();
}

function deduplicateDeferredSources(
  sources: readonly DeferredLegacySource[],
): readonly DeferredLegacySource[] {
  const byIdentity = new Map<string, DeferredLegacySource>();
  for (const source of [...sources].sort((left, right) => left.absolutePath.localeCompare(right.absolutePath))) {
    const key = `${source.sourceDevice}:${source.sourceInode}`;
    if (!byIdentity.has(key)) byIdentity.set(key, source);
  }
  return [...byIdentity.values()].sort((left, right) => left.absolutePath.localeCompare(right.absolutePath));
}

function loadResumeSettlementBoundary(
  databasePath: string,
  migrationId: string,
  requestedSettleSeconds: number | undefined,
): { readonly startedAt: string; readonly settleSeconds?: number; readonly cutoffAt?: string } {
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const exists = database.prepare(
      "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'legacy_migration_runs'",
    ).get() as { present: number } | undefined;
    if (!exists) throw new Error(`Unknown migration run: ${migrationId}`);
    const columns = new Set((database.prepare("PRAGMA table_info('legacy_migration_runs')").all() as Array<{
      name: string;
    }>).map(({ name }) => name));
    const hasBoundary = columns.has("settle_seconds") && columns.has("settle_cutoff_at");
    const row = database.prepare(`
      SELECT started_at${hasBoundary ? ", settle_seconds, settle_cutoff_at" : ""}
      FROM legacy_migration_runs WHERE id = ?
    `).get(migrationId) as {
      started_at: string;
      settle_seconds?: number | null;
      settle_cutoff_at?: string | null;
    } | undefined;
    if (!row) throw new Error(`Unknown migration run: ${migrationId}`);
    const storedSeconds = row.settle_seconds === null || row.settle_seconds === undefined
      ? undefined
      : Number(row.settle_seconds);
    const storedCutoff = row.settle_cutoff_at ?? undefined;
    if (storedSeconds !== requestedSettleSeconds) {
      throw new Error("Resume settle-seconds does not match the immutable migration boundary");
    }
    if ((storedSeconds === undefined) !== (storedCutoff === undefined)) {
      throw new Error("Resumed migration has an incomplete settled-source boundary");
    }
    if (storedSeconds !== undefined && storedCutoff !== settledCutoffAt(row.started_at, storedSeconds)) {
      throw new Error("Resumed migration settled-source cutoff does not match its start receipt");
    }
    return {
      startedAt: row.started_at,
      ...(storedSeconds !== undefined ? { settleSeconds: storedSeconds, cutoffAt: storedCutoff } : {}),
    };
  } finally {
    database.close();
  }
}

function verifiedRegularSource(source: LegacySource): VerifiedSourceIdentity {
  return verifyDiscoveredRegularSource({
    absolutePath: source.absolutePath,
    containmentRoot: source.root,
    sha256: source.sha256,
    byteSize: source.byteSize,
    modifiedAt: source.modifiedAt,
  });
}

function sameVerifiedIdentity(left: VerifiedSourceIdentity, right: VerifiedSourceIdentity): boolean {
  return left.device === right.device
    && left.inode === right.inode
    && left.byteSize === right.byteSize
    && left.modifiedAt === right.modifiedAt
    && left.sha256 === right.sha256;
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

function addSourceCoverage(
  left: LegacySourceDiscoveryCoverage,
  right: LegacySourceDiscoveryCoverage,
): LegacySourceDiscoveryCoverage {
  return {
    scannedFiles: left.scannedFiles + right.scannedFiles,
    scannedBytes: left.scannedBytes + right.scannedBytes,
    classifiedFiles: left.classifiedFiles + right.classifiedFiles,
    classifiedBytes: left.classifiedBytes + right.classifiedBytes,
    includedFiles: left.includedFiles + right.includedFiles,
    includedBytes: left.includedBytes + right.includedBytes,
    deferredFiles: left.deferredFiles + right.deferredFiles,
    deferredBytes: left.deferredBytes + right.deferredBytes,
    unsupportedFiles: left.unsupportedFiles + right.unsupportedFiles,
    unsupportedBytes: left.unsupportedBytes + right.unsupportedBytes,
    excludedFiles: left.excludedFiles + right.excludedFiles,
    excludedBytes: left.excludedBytes + right.excludedBytes,
    oversizedFiles: left.oversizedFiles + right.oversizedFiles,
    oversizedBytes: left.oversizedBytes + right.oversizedBytes,
    activeSqliteFiles: left.activeSqliteFiles + right.activeSqliteFiles,
    activeSqliteBytes: left.activeSqliteBytes + right.activeSqliteBytes,
    receiptBoundSqliteFiles: left.receiptBoundSqliteFiles + right.receiptBoundSqliteFiles,
    receiptBoundSqliteBytes: left.receiptBoundSqliteBytes + right.receiptBoundSqliteBytes,
    vaultProjectionDirectories: left.vaultProjectionDirectories + right.vaultProjectionDirectories,
    deniedDirectories: left.deniedDirectories + right.deniedDirectories,
  };
}

function pathInside(directory: string, candidate: string): boolean {
  const value = relative(resolve(directory), resolve(candidate));
  return value === "" || (value !== ".." && !value.startsWith(`..${sep}`));
}

interface ExplicitActiveSourceIdentity {
  readonly sourceDevice: number;
  readonly sourceInode: number;
}

/**
 * Return target inode identities currently held by at least one writable Linux
 * file descriptor. The scan never reads target bytes and ignores processes
 * that exit while /proc is traversed.
 */
function openWritableTargetIdentities(
  targets: ReadonlySet<string>,
): ReadonlySet<string> {
  if (targets.size === 0) return new Set();
  if (!existsSync("/proc/self/fd") || !existsSync("/proc/self/fdinfo")) {
    throw new Error("Explicit active-source deferral requires readable Linux /proc file-descriptor metadata");
  }
  const writable = new Set<string>();
  let processEntries: string[];
  try { processEntries = readdirSync("/proc").filter((entry) => /^\d+$/u.test(entry)); }
  catch {
    throw new Error("Explicit active-source deferral could not enumerate Linux /proc");
  }
  for (const processId of processEntries) {
    const descriptorRoot = `/proc/${processId}/fd`;
    let descriptors: string[];
    try { descriptors = readdirSync(descriptorRoot); }
    catch { continue; }
    for (const descriptor of descriptors) {
      let flags: number;
      try {
        const flagsLine = readFileSync(`/proc/${processId}/fdinfo/${descriptor}`, "utf8")
          .split("\n")
          .find((line) => line.startsWith("flags:"));
        if (!flagsLine) continue;
        flags = Number.parseInt(flagsLine.slice("flags:".length).trim(), 8);
      } catch { continue; }
      // Linux O_ACCMODE is the low two bits; 1 and 2 are writable modes.
      if ((flags & 0o3) !== 0o1 && (flags & 0o3) !== 0o2) continue;
      try {
        const state = statSync(`${descriptorRoot}/${descriptor}`);
        const identity = `${state.dev}:${state.ino}`;
        if (targets.has(identity)) writable.add(identity);
      } catch { /* descriptor closed while scanning */ }
      if (writable.size === targets.size) return writable;
    }
  }
  return writable;
}

function validateExplicitActiveSourceDeferrals(input: {
  readonly paths: readonly string[];
  readonly sourceRoots: readonly string[];
  readonly settleCutoffAt?: string;
  readonly resume: boolean;
}): ReadonlyMap<string, ExplicitActiveSourceIdentity> {
  if (input.paths.length === 0) return new Map();
  if (!input.settleCutoffAt) {
    throw new Error("Explicit active-source deferral requires an immutable --settle-seconds boundary");
  }
  const cutoffMs = Date.parse(input.settleCutoffAt);
  const resolved = new Map<string, {
    readonly sourceDevice: number;
    readonly sourceInode: number;
    readonly modifiedAtMs: number;
  }>();
  const identities = new Set<string>();
  for (const requestedPath of input.paths) {
    const lexicalPath = resolve(requestedPath);
    const lexicalState = lstatSync(lexicalPath);
    if (!lexicalState.isFile() || lexicalState.isSymbolicLink()) {
      throw new Error("Explicitly deferred source must be a regular non-link file");
    }
    const canonicalPath = realpathSync(lexicalPath);
    if (!input.sourceRoots.some((root) => pathInside(root, canonicalPath)) ||
        input.sourceRoots.some((root) => resolve(root) === canonicalPath)) {
      throw new Error("Explicitly deferred source must be contained by a configured source root");
    }
    if (resolved.has(canonicalPath)) throw new Error("Explicit active-source deferral contains a duplicate path");
    const identity = `${lexicalState.dev}:${lexicalState.ino}`;
    if (identities.has(identity)) throw new Error("Explicit active-source deferral contains duplicate inode aliases");
    identities.add(identity);
    resolved.set(canonicalPath, {
      sourceDevice: lexicalState.dev,
      sourceInode: lexicalState.ino,
      modifiedAtMs: lexicalState.mtimeMs,
    });
  }
  if (!input.resume) {
    const openForWrite = openWritableTargetIdentities(identities);
    for (const [path, identity] of resolved) {
      const key = `${identity.sourceDevice}:${identity.sourceInode}`;
      if (identity.modifiedAtMs <= cutoffMs && !openForWrite.has(key)) {
        throw new Error(
          `Explicitly deferred source is neither newer than the settled-source cutoff nor open for write: ${path}`,
        );
      }
    }
  }
  return new Map([...resolved].map(([path, identity]) => [path, {
    sourceDevice: identity.sourceDevice,
    sourceInode: identity.sourceInode,
  }]));
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
    hashAddressedQuarantinedPaths: discovery.manifests.reduce(
      (total, manifest) => total + manifest.quarantined.filter((item) => item.sourceSha256 !== undefined).length,
      0,
    ),
    quarantinedSourceBytes: discovery.manifests.reduce(
      (total, manifest) => total + manifest.quarantined.reduce((subtotal, item) => subtotal + (item.byteSize ?? 0), 0),
      0,
    ),
    deferredFiles: discovery.deferred.length,
    deferredBytes: discovery.deferred.reduce((total, item) => total + item.byteSize, 0),
    rootAliases: resolvedRoots.aliases.map((alias) => ({
      requestedPath: alias.requestedPath,
      canonicalPath: alias.canonicalPath,
      duplicateOf: alias.duplicateOf,
    })),
  };
}

function assertReviewedDeltaDiscovery(input: {
  readonly plan: HistoricalSourceDeltaExecutionPlan;
  readonly inventory: { readonly included: readonly LegacySource[] };
  readonly engagements: LegacyEngagementDiscovery;
}): void {
  const rootIdByCanonicalPath = new Map(input.plan.configuration.roots.map(({ id, path }) => [
    realpathSync(path),
    id,
  ]));
  const plannedByPath = new Map(input.plan.admissions.map((admission) => [admission.path, admission]));
  const identity = (path: string) => {
    const state = lstatSync(path);
    return {
      modifiedAt: state.mtime.toISOString(),
      sourceDevice: state.dev,
      sourceInode: state.ino,
    };
  };
  const actual: HistoricalSourceDeltaAdmission[] = [];
  for (const manifest of input.engagements.manifests) {
    const rootId = rootIdByCanonicalPath.get(manifest.root);
    if (!rootId) throw new Error("Reviewed delta manifest resolved outside its configured root binding");
    for (const file of manifest.files) {
      const planned = plannedByPath.get(file.absolutePath);
      if (!planned) throw new Error("Reviewed delta discovery produced an unplanned engagement file");
      actual.push({
        rootId,
        path: file.absolutePath,
        sourceHash: file.sha256,
        byteSize: file.byteSize,
        ...identity(file.absolutePath),
        classification: file.kind,
        objectKind: "accepted",
        parserEligibility: semanticEngagementEligibility(file),
        sensitivity: "locally_screened",
        disposition: planned.disposition,
      });
    }
    for (const item of manifest.quarantined) {
      if (!item.sourceSha256) continue;
      const planned = plannedByPath.get(item.absolutePath);
      if (!planned) throw new Error("Reviewed delta discovery produced an unplanned quarantine object");
      actual.push({
        rootId,
        path: item.absolutePath,
        sourceHash: item.sourceSha256,
        byteSize: item.byteSize ?? 0,
        ...identity(item.absolutePath),
        classification: item.category,
        objectKind: item.category === "symlink" ? "symlink" : "quarantined",
        parserEligibility: "quarantined",
        sensitivity: quarantineSensitivity(item),
        disposition: planned.disposition,
      });
    }
  }
  for (const source of input.inventory.included) {
    const rootId = rootIdByCanonicalPath.get(source.root);
    if (!rootId) throw new Error("Reviewed delta generic source resolved outside its configured root binding");
    const planned = plannedByPath.get(source.absolutePath);
    if (!planned) throw new Error("Reviewed delta discovery produced an unplanned generic source");
    actual.push({
      rootId,
      path: source.absolutePath,
      sourceHash: source.sha256,
      byteSize: source.byteSize,
      ...identity(source.absolutePath),
      classification: source.type,
      objectKind: "source",
      parserEligibility: source.type === "artifact" ? "custody_only" : "semantic_parser_eligible",
      sensitivity: "local_only_record_sanitization_required",
      disposition: planned.disposition,
    });
  }
  actual.sort((left, right) => left.rootId.localeCompare(right.rootId) || left.path.localeCompare(right.path));
  const planned = [...input.plan.admissions].sort((left, right) =>
    left.rootId.localeCompare(right.rootId) || left.path.localeCompare(right.path));
  if (hashJson(actual) !== hashJson(planned)
      || historicalDeltaAdmissionInventoryHash(actual) !== input.plan.delta.inventoryHash) {
    throw new Error("Reviewed delta discovery no longer matches the sealed exact-file admission");
  }
}

function immutableInventoryReceipt(input: {
  readonly roots: CanonicalLegacyRoots;
  readonly inventory: {
    readonly included: readonly LegacySource[];
    readonly excluded: readonly { readonly absolutePath: string; readonly reason: string }[];
    readonly deferred: readonly DeferredLegacySource[];
    readonly coverage: LegacySourceDiscoveryCoverage;
  };
  readonly engagements: LegacyEngagementDiscovery;
  readonly reviewedDeltaPlan?: HistoricalSourceDeltaExecutionPlan;
}): { readonly hash: string; readonly objectCount: number; readonly byteCount: number } {
  const payload = {
    schemaVersion: 1,
    roots: input.roots.roots.map(({ canonicalPath, physicalIdentity }) => ({ canonicalPath, physicalIdentity }))
      .sort((left, right) => left.canonicalPath.localeCompare(right.canonicalPath)),
    sources: input.inventory.included.map(({ absolutePath, type, sha256, byteSize, modifiedAt }) => ({
      absolutePath, type, sha256, byteSize, modifiedAt,
    })).sort((left, right) => left.absolutePath.localeCompare(right.absolutePath)),
    engagements: input.engagements.manifests.map((manifest) => ({
      engagementDirectory: manifest.engagementDirectory,
      engagementKey: manifest.engagementKey,
      manifestHash: manifest.sha256,
      byteSize: manifest.byteSize,
      modifiedAt: manifest.modifiedAt,
      files: manifest.files.map(({ relativePath, kind, sha256, byteSize, modifiedAt }) => ({
        relativePath, kind, sha256, byteSize, modifiedAt,
      })).sort((left, right) => left.relativePath.localeCompare(right.relativePath)),
      quarantined: manifest.quarantined.map((item) => ({
        quarantineId: item.quarantineId,
        category: item.category,
        sourceKind: item.sourceKind,
        sourceSha256: item.sourceSha256 ?? null,
        byteSize: item.byteSize ?? null,
        modifiedAt: item.modifiedAt ?? null,
        dispositionReceiptSha256: item.dispositionReceiptSha256 ?? null,
        normalizedSnapshotSha256: item.normalizedSnapshotSha256 ?? null,
        quarantineMappingId: item.quarantineMappingId ?? null,
      })).sort((left, right) => left.quarantineId.localeCompare(right.quarantineId)),
    })).sort((left, right) => left.engagementKey.localeCompare(right.engagementKey)),
    excluded: input.inventory.excluded.map(({ absolutePath, reason }) => ({ absolutePath, reason }))
      .sort((left, right) => left.absolutePath.localeCompare(right.absolutePath) || left.reason.localeCompare(right.reason)),
    deferred: input.inventory.deferred.map((source) => ({
      absolutePath: source.absolutePath,
      reason: source.reason,
      byteSize: source.byteSize,
      modifiedAt: source.modifiedAt,
      sourceDevice: source.sourceDevice,
      sourceInode: source.sourceInode,
    })).sort((left, right) => left.absolutePath.localeCompare(right.absolutePath)),
    coverage: input.inventory.coverage,
    ...(input.reviewedDeltaPlan ? { reviewedDeltaExecution: {
      executionPlanHash: input.reviewedDeltaPlan.planHash,
      publicPlanHash: input.reviewedDeltaPlan.publicPlanHash,
      configurationSha256: input.reviewedDeltaPlan.configuration.sha256,
      baseline: input.reviewedDeltaPlan.baseline,
      admittedFiles: input.reviewedDeltaPlan.delta.files,
      admittedBytes: input.reviewedDeltaPlan.delta.bytes,
      admittedInventoryHash: input.reviewedDeltaPlan.delta.inventoryHash,
      exactPathAdmission: true,
    } } : {}),
  };
  // Counts describe only durable source-object custody rows. Exclusions remain
  // hash-bound in the receipt payload, but they are not falsely represented as
  // verified source objects with known bytes.
  const objectCount = payload.sources.length + payload.engagements.reduce(
    (total, engagement) => total + engagement.files.length + engagement.quarantined.length,
    0,
  );
  const byteCount = payload.sources.reduce((total, source) => total + source.byteSize, 0) +
    payload.engagements.reduce(
      (total, engagement) => total
        + engagement.files.reduce((subtotal, file) => subtotal + file.byteSize, 0)
        + engagement.quarantined.reduce((subtotal, item) => subtotal + (item.byteSize ?? 0), 0),
      0,
    );
  return { hash: sha256Text(JSON.stringify(payload)), objectCount, byteCount };
}

function attackKnowledgeExtractionSummary(
  perManifest: readonly (readonly AttackKnowledgeExtractionBatchReport[])[],
  semanticPreview: boolean,
): AttackKnowledgeExtractionReconciliation {
  const batches = perManifest.flat();
  const sum = (key: keyof Pick<AttackKnowledgeExtractionBatchReport,
    "filesParsed" | "filesSkipped" | "filesQuarantined" | "bytesParsed" |
    "semanticFactsParsed" | "ambiguousFragments" | "compilerBundlesStaged" |
    "candidatesCreated" | "candidatesReused" | "sourceEvidenceCandidatesCreated" |
    "sourceEvidenceCandidatesReused" | "sourceBundleLinks">): number =>
    batches.reduce((total, batch) => total + Number(batch[key]), 0);
  const issueCounts: Record<string, number> = {};
  for (const issue of batches.flatMap(({ issues }) => issues)) {
    const key = `${issue.disposition}:${issue.reason}`;
    issueCounts[key] = (issueCounts[key] ?? 0) + (issue.count ?? 1);
  }
  const aggregateDistribution = (key: "nodeTypeCounts" | "edgeTypeCounts"): Readonly<Record<string, number>> => {
    const counts: Record<string, number> = {};
    for (const batch of batches) {
      for (const [type, count] of Object.entries(batch[key] ?? {})) {
        counts[type] = (counts[type] ?? 0) + Number(count);
      }
    }
    return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
  };
  const generic = batches as readonly (AttackKnowledgeExtractionBatchReport & {
    readonly sourcesProcessed?: number;
    readonly sourcesCompleted?: number;
    readonly recordsProcessed?: number;
    readonly recordsQuarantined?: number;
    readonly sourceEvidenceCandidateIds?: readonly string[];
  })[];
  const genericScopes = perManifest.filter((results) => results.some((batch) =>
    "sourcesProcessed" in batch || "recordsProcessed" in batch));
  const incomplete = perManifest.flatMap((results) => {
    const latest = results.at(-1);
    return latest?.status === "partial" ? [latest] : [];
  });
  const resumeCursors = incomplete.map((batch) => ({
    manifestFingerprint: batch.manifestFingerprint,
    ...(batch.nextResumeAfterSourceKey
      ? { nextResumeAfterSourceKey: batch.nextResumeAfterSourceKey }
      : {}),
    ...(batch.nextResumeAfterRecordKey
      ? { nextResumeAfterRecordKey: batch.nextResumeAfterRecordKey }
      : {}),
  })).sort((left, right) => left.manifestFingerprint.localeCompare(right.manifestFingerprint));
  const batchesWithSourceCandidateIds = batches.filter((batch) => batch.sourceEvidenceCandidateIds !== undefined);
  const sourceEvidenceCandidateIds = [...new Set(batchesWithSourceCandidateIds.flatMap(
    (batch) => batch.sourceEvidenceCandidateIds ?? [],
  ))].sort();
  const sourceEvidenceCandidatesCreated = batchesWithSourceCandidateIds.length > 0
    ? Math.min(sum("sourceEvidenceCandidatesCreated"), sourceEvidenceCandidateIds.length)
    : sum("sourceEvidenceCandidatesCreated");
  const sourceEvidenceCandidatesReused = batchesWithSourceCandidateIds.length > 0
    ? Math.max(0, sourceEvidenceCandidateIds.length - sourceEvidenceCandidatesCreated)
    : sum("sourceEvidenceCandidatesReused");
  return {
    mode: "attack-knowledge-only",
    semanticPreview,
    status: incomplete.length > 0 ? "partial" : "completed",
    partialScopeCount: incomplete.length,
    resumeCursors,
    manifestsParsed: perManifest.length,
    batchesProcessed: batches.reduce(
      (total, batch) => total + (batch.representedBatchCount ?? 1),
      0,
    ),
    // filesDiscovered describes a manifest universe, so count only the first
    // batch for each manifest rather than multiplying it by cursor pages.
    filesDiscovered: perManifest.reduce((total, results) => total + (results[0]?.filesDiscovered ?? 0), 0),
    filesParsed: sum("filesParsed"),
    filesSkipped: sum("filesSkipped"),
    filesQuarantined: sum("filesQuarantined"),
    bytesParsed: sum("bytesParsed"),
    semanticFactsParsed: sum("semanticFactsParsed"),
    ambiguousFragments: sum("ambiguousFragments"),
    connectedBundlesStaged: sum("compilerBundlesStaged"),
    candidatesCreated: sum("candidatesCreated"),
    candidatesReused: sum("candidatesReused"),
    sourceEvidenceCandidatesCreated,
    sourceEvidenceCandidatesReused,
    sourceBundleLinksCreated: sum("sourceBundleLinks"),
    nodeTypeCounts: aggregateDistribution("nodeTypeCounts"),
    edgeTypeCounts: aggregateDistribution("edgeTypeCounts"),
    genericSourcesDiscovered: genericScopes.reduce(
      (total, results) => total + (results[0]?.filesDiscovered ?? 0),
      0,
    ),
    genericSourcesProcessed: generic.reduce((total, batch) => total + (batch.sourcesProcessed ?? 0), 0),
    genericSourcesCompleted: generic.reduce((total, batch) => total + (batch.sourcesCompleted ?? 0), 0),
    genericRecordsProcessed: generic.reduce((total, batch) => total + (batch.recordsProcessed ?? 0), 0),
    genericRecordsQuarantined: generic.reduce((total, batch) => total + (batch.recordsQuarantined ?? 0), 0),
    sourceEvidenceCandidateIds,
    issueCounts: Object.fromEntries(Object.entries(issueCounts).sort(([left], [right]) => left.localeCompare(right))),
    evidenceAutomaticallyVerified: 0,
    reusableMemoryAutomaticallyPromoted: 0,
  };
}

interface ForeignKeyViolation { readonly table: string; readonly rowid: number; }

function databaseValidation(database: SqliteDatabase): ReconciliationReport["integrity"] {
  const integrity = checkDatabaseIntegrity(database);
  const violations = database.pragma("foreign_key_check") as ForeignKeyViolation[];
  return {
    verificationStatus: "verified",
    quickCheck: integrity.messages,
    foreignKeyViolations: violations.length,
  };
}

/** Resumable, hash-addressed, forward-only migration coordinator. */
export class LegacyMigrationService {
  private readonly clock: () => Date;

  constructor(private readonly options: LegacyMigrationOptions) {
    this.clock = options.clock ?? (() => new Date());
  }

  async run(): Promise<LegacyMigrationResult> {
    const sourceRetention = this.options.sourceRetention ?? "verified-reference";
    if (sourceRetention !== "verified-reference") {
      throw new Error(
        "Protected-copy legacy migration is disabled by operator policy; only forward-only verified-reference migration is available",
      );
    }
    if (this.options.databaseBackupMode === "verified") {
      throw new Error(
        "Database backup creation is disabled by operator policy; legacy migration is forward-only",
      );
    }
    const verifiedReferenceAcknowledged = this.options.verifiedReferenceAcknowledged !== false;
    const brainProjectionMode = this.options.brainProjectionMode ?? "legacy-engagement";
    const requestedSettleSeconds = normalizeSettleSeconds(this.options.settleSeconds);
    const requestedActiveDeferrals = this.options.explicitActiveSourceDeferrals ?? [];
    const requestedSqliteQuarantines = this.options.sqliteSnapshotQuarantineMappings ?? [];
    const reviewedDeltaPlan = this.options.reviewedDeltaExecutionPlan;
    if (!verifiedReferenceAcknowledged) {
      throw new Error("Verified-reference retention was explicitly rejected");
    }
    if (brainProjectionMode === "attack-knowledge-only" && !this.options.attackKnowledgeOnlyAcknowledged) {
      throw new Error("Attack-knowledge-only import requires --acknowledge-attack-knowledge-only or the equivalent explicit service acknowledgement");
    }
    if (brainProjectionMode === "attack-knowledge-only" && sourceRetention !== "verified-reference") {
      throw new Error("Attack-knowledge-only import requires verified-reference source retention");
    }
    if (requestedActiveDeferrals.length > 0 &&
        (sourceRetention !== "verified-reference" || brainProjectionMode !== "attack-knowledge-only")) {
      throw new Error(
        "Explicit active-source deferral is available only to verified-reference attack-knowledge-only imports",
      );
    }
    if (requestedSqliteQuarantines.length > 0
      && (sourceRetention !== "verified-reference" || brainProjectionMode !== "attack-knowledge-only")) {
      throw new Error(
        "Receipt-bound SQLite quarantine is available only to verified-reference attack-knowledge-only imports",
      );
    }
    if (requestedSqliteQuarantines.length > 0 && !this.options.sqliteSnapshotQuarantineAcknowledged) {
      throw new Error("Receipt-bound SQLite quarantine requires explicit acknowledgement");
    }
    if (requestedSqliteQuarantines.length === 0 && this.options.sqliteSnapshotQuarantineAcknowledged) {
      throw new Error("SQLite snapshot quarantine acknowledgement requires a reviewed mapping");
    }
    if (reviewedDeltaPlan
      && (sourceRetention !== "verified-reference" || brainProjectionMode !== "attack-knowledge-only")) {
      throw new Error("Reviewed delta execution requires verified-reference attack-knowledge-only migration");
    }
    if (reviewedDeltaPlan && requestedActiveDeferrals.length > 0) {
      throw new Error("Reviewed delta execution cannot combine a second unsealed active-source deferral list");
    }
    const databasePath = resolve(this.options.databasePath);
    const outputDirectory = resolve(this.options.outputDirectory);
    const invocationStartedAt = this.clock().toISOString();
    const resumeBoundary = this.options.resumeMigrationId && !this.options.dryRun
      ? loadResumeSettlementBoundary(databasePath, this.options.resumeMigrationId, requestedSettleSeconds)
      : undefined;
    const startedAt = resumeBoundary?.startedAt ?? invocationStartedAt;
    const settleSeconds = resumeBoundary?.settleSeconds ?? requestedSettleSeconds;
    const settleCutoffAt = resumeBoundary?.cutoffAt ?? (
      settleSeconds === undefined ? undefined : settledCutoffAt(startedAt, settleSeconds)
    );
    const configuredEngagementRoots = this.options.engagementRoots ?? [];
    const configuredHistoryRoots = this.options.historyRoots ?? [];
    if (!this.options.sourceRoots.length && !configuredEngagementRoots.length && !configuredHistoryRoots.length) {
      throw new Error("At least one legacy source root, explicit engagement root, or history root is required");
    }
    const parentRootResolution = canonicalizeLegacySourceRoots(this.options.sourceRoots);
    const engagementRootResolution = canonicalizeLegacySourceRoots(configuredEngagementRoots);
    const historyRootResolution = canonicalizeLegacySourceRoots(configuredHistoryRoots);
    const rootModes = [
      ...parentRootResolution.roots.map((root) => ({ root, mode: "children" as const })),
      ...engagementRootResolution.roots.map((root) => ({ root, mode: "engagement-root" as const })),
      ...historyRootResolution.roots.map((root) => ({ root, mode: "history-root" as const })),
    ];
    const modeByIdentity = new Map<string, (typeof rootModes)[number]>();
    for (const entry of rootModes) {
      const prior = modeByIdentity.get(entry.root.physicalIdentity);
      if (prior) {
        throw new Error(
          `A legacy path cannot use both ${prior.mode} and ${entry.mode} modes: ${entry.root.canonicalPath}`,
        );
      }
      modeByIdentity.set(entry.root.physicalIdentity, entry);
    }
    for (let left = 0; left < rootModes.length; left += 1) {
      for (let right = left + 1; right < rootModes.length; right += 1) {
        const leftPath = rootModes[left]!.root.canonicalPath;
        const rightPath = rootModes[right]!.root.canonicalPath;
        const relation = relative(leftPath, rightPath);
        const inverse = relative(rightPath, leftPath);
        const overlaps = relation === "" || (
          relation !== ".." && !relation.startsWith(`..${sep}`)
        ) || (
          inverse !== ".." && !inverse.startsWith(`..${sep}`)
        );
        if (overlaps) {
          throw new Error("Historical source roots must not overlap or nest");
        }
      }
    }
    const rootResolution: CanonicalLegacyRoots = {
      roots: [
        ...parentRootResolution.roots,
        ...engagementRootResolution.roots,
        ...historyRootResolution.roots,
      ],
      aliases: [
        ...parentRootResolution.aliases,
        ...engagementRootResolution.aliases,
        ...historyRootResolution.aliases,
      ],
      missing: [
        ...parentRootResolution.missing,
        ...engagementRootResolution.missing,
        ...historyRootResolution.missing,
      ],
    };
    const parentSourceRoots = parentRootResolution.roots.map((root) => root.canonicalPath);
    const explicitEngagementRoots = engagementRootResolution.roots.map((root) => root.canonicalPath);
    const genericHistoryRoots = historyRootResolution.roots.map((root) => root.canonicalPath);
    const sourceRoots = [...parentSourceRoots, ...explicitEngagementRoots, ...genericHistoryRoots].sort();
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
    if (reviewedDeltaPlan) {
      if (requestedSettleSeconds !== reviewedDeltaPlan.boundary.settleSeconds) {
        throw new Error("Reviewed delta execution settle-seconds does not match the sealed plan");
      }
      const requestedModeRoots = [
        ...parentRootResolution.roots.map(({ canonicalPath }) => ({ mode: "children" as const, path: canonicalPath })),
        ...engagementRootResolution.roots.map(({ canonicalPath }) => ({ mode: "engagement-root" as const, path: canonicalPath })),
        ...historyRootResolution.roots.map(({ canonicalPath }) => ({ mode: "history-root" as const, path: canonicalPath })),
      ].sort((left, right) => left.mode.localeCompare(right.mode) || left.path.localeCompare(right.path));
      const plannedModeRoots = reviewedDeltaPlan.configuration.roots.map(({ mode, path }) => ({
        mode,
        path: realpathSync(path),
      })).sort((left, right) => left.mode.localeCompare(right.mode) || left.path.localeCompare(right.path));
      if (JSON.stringify(requestedModeRoots) !== JSON.stringify(plannedModeRoots)) {
        throw new Error("Reviewed delta execution root/mode binding does not match configured source roots");
      }
      const baselineDatabase = createDatabaseConnection({
        filename: databasePath,
        readonly: true,
        fileMustExist: true,
        verifyIntegrity: false,
      });
      try {
        const currentBaseline = historicalSourceDeltaBaselineBinding(baselineDatabase);
        if (JSON.stringify(currentBaseline) !== JSON.stringify(reviewedDeltaPlan.baseline)) {
          throw new Error("Reviewed delta execution baseline drifted after planning");
        }
      } finally {
        baselineDatabase.close();
      }
      const rootsById = new Map(reviewedDeltaPlan.configuration.roots.map((root) => [root.id, realpathSync(root.path)]));
      const admittedIdentities = new Set<string>();
      for (const admission of reviewedDeltaPlan.admissions) {
        const containmentRoot = rootsById.get(admission.rootId);
        if (!containmentRoot) throw new Error("Reviewed delta admission references an unknown configured root");
        const lexicalPath = resolve(admission.path);
        const state = lstatSync(lexicalPath);
        if (!state.isFile() || state.isSymbolicLink() || realpathSync(lexicalPath) !== lexicalPath
            || !pathInside(containmentRoot, lexicalPath) || lexicalPath === containmentRoot) {
          throw new Error("Reviewed delta admission is no longer a contained regular non-link file");
        }
        if (state.dev !== admission.sourceDevice || state.ino !== admission.sourceInode
            || state.size !== admission.byteSize || state.mtime.toISOString() !== admission.modifiedAt) {
          throw new Error("Reviewed delta admission identity drifted after planning");
        }
        admittedIdentities.add(`${state.dev}:${state.ino}`);
      }
      if (admittedIdentities.size !== reviewedDeltaPlan.admissions.length) {
        throw new Error("Reviewed delta admissions contain physical aliases");
      }
      if (openWritableTargetIdentities(admittedIdentities).size > 0) {
        throw new Error("Reviewed delta admission is currently open for write; reseal after it settles");
      }
      if (historicalDeltaAdmissionInventoryHash(reviewedDeltaPlan.admissions)
          !== reviewedDeltaPlan.delta.inventoryHash) {
        throw new Error("Reviewed delta admission inventory does not match the public delta hash");
      }
    }
    const explicitActiveSourceDeferrals = validateExplicitActiveSourceDeferrals({
      paths: requestedActiveDeferrals,
      sourceRoots,
      settleCutoffAt,
      resume: this.options.resumeMigrationId !== undefined,
    });
    const receiptBoundSqliteQuarantines = indexHistoricalSqliteSnapshotQuarantineFiles(
      requestedSqliteQuarantines,
      sourceRoots,
    );
    const sqliteSnapshotQuarantine = requestedSqliteQuarantines.length > 0
      ? summarizeHistoricalSqliteSnapshotQuarantineMappings(requestedSqliteQuarantines)
      : undefined;
    const discoveryOptions = {
      ...(settleCutoffAt ? { settledSourceCutoffAt: settleCutoffAt } : {}),
      ...(explicitActiveSourceDeferrals.size > 0 ? { explicitActiveSourceDeferrals } : {}),
      ...(receiptBoundSqliteQuarantines.size > 0 ? { receiptBoundSqliteQuarantines } : {}),
    };
    const reviewedRootModeById = new Map(
      reviewedDeltaPlan?.configuration.roots.map(({ id, mode }) => [id, mode]) ?? [],
    );
    const reviewedChildEngagementPaths = reviewedDeltaPlan?.admissions.filter((admission) =>
      admission.objectKind !== "source"
      && reviewedRootModeById.get(admission.rootId) === "children").map(({ path }) => path);
    const reviewedExplicitEngagementPaths = reviewedDeltaPlan?.admissions.filter((admission) =>
      admission.objectKind !== "source"
      && reviewedRootModeById.get(admission.rootId) === "engagement-root").map(({ path }) => path);
    const reviewedPrimarySourcePaths = reviewedDeltaPlan?.admissions.filter((admission) =>
      admission.objectKind === "source"
      && reviewedRootModeById.get(admission.rootId) !== "history-root").map(({ path }) => path);
    const reviewedHistorySourcePaths = reviewedDeltaPlan?.admissions.filter((admission) =>
      admission.objectKind === "source"
      && reviewedRootModeById.get(admission.rootId) === "history-root").map(({ path }) => path);
    const [childDiscovery, explicitDiscovery] = await Promise.all([
      discoverLegacyEngagements(parentSourceRoots, {
        ...discoveryOptions,
        ...(reviewedDeltaPlan ? { exactSourcePaths: reviewedChildEngagementPaths ?? [] } : {}),
      }),
      discoverLegacyEngagements(explicitEngagementRoots, {
        rootMode: "self",
        ...discoveryOptions,
        ...(reviewedDeltaPlan ? { exactSourcePaths: reviewedExplicitEngagementPaths ?? [] } : {}),
      }),
    ]);
    const engagementDiscovery: LegacyEngagementDiscovery = {
      roots: rootResolution,
      manifests: [...childDiscovery.manifests, ...explicitDiscovery.manifests]
        .sort((left, right) => left.engagementKey.localeCompare(right.engagementKey)),
      excluded: [...childDiscovery.excluded, ...explicitDiscovery.excluded],
      deferred: [...childDiscovery.deferred, ...explicitDiscovery.deferred],
    };
    const primaryInventory = await discoverLegacySources([
      ...parentSourceRoots,
      ...explicitEngagementRoots,
    ], {
      ...discoveryOptions,
      ...(reviewedDeltaPlan ? { exactSourcePaths: reviewedPrimarySourcePaths ?? [] } : {}),
    });
    const supplementalInventory = await discoverLegacySources(genericHistoryRoots, {
      ...discoveryOptions,
      ...(reviewedDeltaPlan ? { exactSourcePaths: reviewedHistorySourcePaths ?? [] } : {}),
      boundedHistoryRoots: genericHistoryRoots,
      maximumBoundedSourceBytes: 8 * 1024 * 1024,
      maximumBoundedFiles: 100_000,
      maximumBoundedDepth: 24,
    });
    // Parent/engagement roots are expected to represent a coherent historical
    // snapshot. Silently omitting an allowlisted SQLite source with live WAL
    // state would make that snapshot incomplete. Generic history roots retain
    // their existing bounded exclusion behavior because they are intentionally
    // heterogeneous supplemental stores.
    if (primaryInventory.coverage.activeSqliteFiles > 0) {
      throw new Error(
        `Historical source contains ${primaryInventory.coverage.activeSqliteFiles} active SQLite file(s) with a non-empty WAL or journal; import a quiesced checkpoint instead`,
      );
    }
    const discoveredInventory = {
      included: [...primaryInventory.included, ...supplementalInventory.included],
      excluded: [...primaryInventory.excluded, ...supplementalInventory.excluded],
      deferred: [...primaryInventory.deferred, ...supplementalInventory.deferred],
      coverage: addSourceCoverage(primaryInventory.coverage, supplementalInventory.coverage),
    };
    const engagementDirectories = engagementDiscovery.manifests.map((manifest) => manifest.engagementDirectory);
    const deferred = deduplicateDeferredSources([
      ...engagementDiscovery.deferred,
      ...discoveredInventory.deferred,
    ]);
    const inventory = {
      included: discoveredInventory.included.filter((source) =>
        !engagementDirectories.some((directory) => pathInside(directory, source.absolutePath))),
      excluded: [
        ...discoveredInventory.excluded,
        ...rootResolution.missing.map((absolutePath) => ({ absolutePath, reason: "source root does not exist" })),
        ...engagementDiscovery.excluded.map((item) => ({ absolutePath: item.absolutePath, reason: `${item.category}: ${item.reason}` })),
      ],
      deferred,
      coverage: discoveredInventory.coverage,
    };
    if (reviewedDeltaPlan) {
      assertReviewedDeltaDiscovery({
        plan: reviewedDeltaPlan,
        inventory,
        engagements: engagementDiscovery,
      });
    }
    const genericSourceDiscovery = {
      ...supplementalInventory.coverage,
      supplementalHistoryRoots: genericHistoryRoots.length,
    };
    const settledSourceBoundary = settleSeconds === undefined || settleCutoffAt === undefined
      ? undefined
      : {
        settleSeconds,
        migrationStartedAt: startedAt,
        cutoffAt: settleCutoffAt,
        deferredObjects: deferred.length,
        deferredBytes: deferred.reduce((total, item) => total + item.byteSize, 0),
        reason: SETTLED_SOURCE_DEFERRED_REASON,
        deferredReasonCounts: {
          [SETTLED_SOURCE_DEFERRED_REASON]: deferred.filter(
            ({ reason }) => reason === SETTLED_SOURCE_DEFERRED_REASON,
          ).length,
          [EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON]: deferred.filter(
            ({ reason }) => reason === EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON,
          ).length,
        },
      } as const;
    const reportedExclusions = [
      ...inventory.excluded,
      ...deferred.map((item) => ({
        absolutePath: item.absolutePath,
        reason: `deferred_recent: ${item.reason}`,
      })),
    ];
    if (inventory.included.some((source) => source.absolutePath === databasePath)) {
      throw new Error("Canonical database path must not be one of the legacy source files");
    }
    const sqliteWalWarnings = inventory.included
      .filter((source) => source.type === "kanban_sqlite" || source.type === "conversation_state_sqlite")
      .filter((source) => existsSync(`${source.absolutePath}-wal`) && statSync(`${source.absolutePath}-wal`).size > 0)
      .map((source) => `SQLite source has a non-empty WAL and must be quiesced/checkpointed: ${source.absolutePath}`);
    const referenceOnlySummary = {
      acceptedObjects: inventory.included.length + engagementDiscovery.manifests.reduce(
        (total, manifest) => total + manifest.files.length,
        0,
      ),
      acceptedBytes: inventory.included.reduce((total, source) => total + source.byteSize, 0)
        + engagementDiscovery.manifests.reduce(
          (total, manifest) => total + manifest.files.reduce((subtotal, file) => subtotal + file.byteSize, 0),
          0,
        ),
      quarantinedObjects: engagementDiscovery.manifests.reduce(
        (total, manifest) => total + manifest.quarantined.length,
        0,
      ),
      quarantinedBytes: engagementDiscovery.manifests.reduce(
        (total, manifest) => total + manifest.quarantined.reduce((subtotal, item) => subtotal + (item.byteSize ?? 0), 0),
        0,
      ),
      symbolicLinks: engagementDiscovery.manifests.reduce(
        (total, manifest) => total + manifest.quarantined.filter((item) => item.sourceKind === "symlink").length,
        0,
      ),
      referencedObjects: 0,
      referencedBytes: 0,
    };
    referenceOnlySummary.referencedObjects = referenceOnlySummary.acceptedObjects + referenceOnlySummary.quarantinedObjects;
    referenceOnlySummary.referencedBytes = referenceOnlySummary.acceptedBytes + referenceOnlySummary.quarantinedBytes;
    const inventoryReceipt = immutableInventoryReceipt({
      roots: rootResolution,
      inventory,
      engagements: engagementDiscovery,
      ...(reviewedDeltaPlan ? { reviewedDeltaPlan } : {}),
    });

    let attackKnowledgePreview: AttackKnowledgeExtractionReconciliation | undefined;
    if (this.options.dryRun && brainProjectionMode === "attack-knowledge-only" &&
        (this.options.attackKnowledgeManifestHandler || this.options.genericAttackKnowledgeSourceHandler)) {
      const previewDatabase = createDatabaseConnection({ filename: ":memory:" });
      try {
        migrateDatabase(previewDatabase);
        const previewBatches: AttackKnowledgeExtractionBatchReport[][] = [];
        if (this.options.attackKnowledgeManifestHandler) {
          previewBatches.push(...engagementDiscovery.manifests.map((manifest) =>
            [...(this.options.attackKnowledgeManifestHandler!(manifest, previewDatabase, {
              dryRun: true,
              migrationId: `dry_run_preview_${inventoryReceipt.hash.slice(0, 40)}`,
              recordBatch: () => undefined,
            }) ?? [])]));
        }
        if (this.options.genericAttackKnowledgeSourceHandler && inventory.included.length > 0) {
          // Dry preview uses a disposable canonical schema and the same
          // verified-reference custody contract. No row reaches the live DB.
          const previewMetadata = new MigrationMetadataRepository(previewDatabase, this.clock);
          const previewMigration = previewMetadata.createRun({
            sourceRoots,
            databasePath: ":memory:",
            outputDirectory,
            startedAt,
            ...(settleSeconds !== undefined && settleCutoffAt ? { settleSeconds, settleCutoffAt } : {}),
            sourceRetention: "verified-reference",
            verifiedReferenceAcknowledged: true,
            brainProjectionMode: "attack-knowledge-only",
            attackKnowledgeOnlyAcknowledged: true,
          });
          previewDatabase.prepare(`
            INSERT INTO legacy_migration_inventory_receipts (
              migration_id, receipt_hash, object_count, byte_count, created_at
            ) VALUES (?, ?, ?, ?, ?)
          `).run(
            previewMigration.id,
            inventoryReceipt.hash,
            inventoryReceipt.objectCount,
            inventoryReceipt.byteCount,
            this.clock().toISOString(),
          );
          for (const source of inventory.included) {
            const identity = verifiedRegularSource(source);
            const sourceId = previewMetadata.registerSource(previewMigration.id, source, undefined, {
              retentionMode: "verified-reference",
              device: identity.device,
              inode: identity.inode,
            });
            previewMetadata.registerSourceObject({
              migrationId: previewMigration.id,
              sourceId,
              objectKey: "source",
              sourcePath: source.absolutePath,
              objectKind: "source",
              classification: source.type,
              sourceSha256: source.sha256,
              byteSize: source.byteSize,
              modifiedAt: source.modifiedAt,
              sourceDevice: identity.device,
              sourceInode: identity.inode,
            });
          }
          previewBatches.push([...(this.options.genericAttackKnowledgeSourceHandler({
            migrationId: previewMigration.id,
            inventoryReceiptHash: inventoryReceipt.hash,
            sources: inventory.included,
          }, previewDatabase, {
            dryRun: true,
            migrationId: previewMigration.id,
            recordBatch: () => undefined,
          }) ?? [])]);
        }
        attackKnowledgePreview = attackKnowledgeExtractionSummary(previewBatches, true);
      } finally {
        previewDatabase.close();
      }
    }

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
        excluded: reportedExclusions,
        ...(settledSourceBoundary ? { settledSourceBoundary } : {}),
        sourceRetention: {
          mode: sourceRetention,
          protectedSourceCopyCreated: false,
          acknowledgementRequired: sourceRetention === "verified-reference",
          ...(sourceRetention === "verified-reference" ? { referenceOnly: referenceOnlySummary } : {}),
        },
        brainProjection: {
          mode: brainProjectionMode,
          legacyMissionRunAssetArtifactNodesCreated: false,
          acknowledgementRequired: brainProjectionMode === "attack-knowledge-only",
        },
        inventoryReceipt,
        ...(reviewedDeltaPlan ? { reviewedDeltaExecution: {
          executionPlanHash: reviewedDeltaPlan.planHash,
          publicPlanHash: reviewedDeltaPlan.publicPlanHash,
          configurationSha256: reviewedDeltaPlan.configuration.sha256,
          baselineInventoryReceiptSetHash: reviewedDeltaPlan.baseline.inventoryReceiptSetHash,
          admittedFiles: reviewedDeltaPlan.delta.files,
          admittedBytes: reviewedDeltaPlan.delta.bytes,
          exactPathAdmission: true as const,
        } } : {}),
        ...(sqliteSnapshotQuarantine ? { sqliteSnapshotQuarantine } : {}),
        ...(attackKnowledgePreview ? { attackKnowledgeExtraction: attackKnowledgePreview } : {}),
        // A semantic preview must remain bounded by its source-page budgets. A
        // multi-gigabyte canonical quick_check/foreign_key_check is a separate
        // operator verification job and must not run while the preview graph is
        // live in memory. The explicit `verify` CLI remains authoritative.
        integrity: existsSync(databasePath)
          ? {
            verificationStatus: "deferred",
            quickCheck: ["canonical database verification deferred to the explicit verify command"],
            foreignKeyViolations: null,
          }
          : {
            verificationStatus: "not_applicable",
            quickCheck: ["database does not exist; no canonical writes performed"],
            foreignKeyViolations: null,
          },
        warnings: [
          attackKnowledgePreview
            ? "Dry run performed discovery, hashing, and bounded local semantic extraction in a disposable database; no canonical import was created."
            : "Dry run performed discovery and hashing only; no source backup or canonical import was created.",
          ...(existsSync(databasePath) ? [
            "Canonical database integrity verification was deliberately deferred; run the explicit database verify command separately so a multi-gigabyte scan cannot amplify preview memory.",
          ] : []),
          ...(sourceRetention === "verified-reference" ? [
            "Verified-reference was previewed: source bytes would remain only in the read-only operator-owned source tree.",
          ] : []),
          ...(brainProjectionMode === "attack-knowledge-only" ? [
            "Attack-knowledge-only was previewed: legacy mission, run, asset, and artifact Brain nodes would not be created.",
          ] : []),
          ...(settledSourceBoundary ? [
            `The explicit ${settledSourceBoundary.settleSeconds}-second settled-source boundary deferred ${settledSourceBoundary.deferredObjects} source object(s); the reconciliation receipt separates recent writes from explicitly verified active sources.`,
          ] : []),
          ...(sqliteSnapshotQuarantine ? [
            `A sealed SQLite snapshot mapped ${sqliteSnapshotQuarantine.sourceFiles} exact DB/WAL/SHM source file(s) to content-free quarantine; the reviewed normalized snapshot contained zero semantic rows.`,
          ] : []),
          "Legacy nonterminal runs will be imported blocked and will never resume automatically.",
          ...sqliteWalWarnings,
        ],
        engagementDiscovery: engagementDiscoverySummary(engagementDiscovery, rootResolution),
        genericSourceDiscovery,
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
        if (migration.sourceRetention !== sourceRetention) throw new Error("Resume source-retention mode does not match migration metadata");
        if (migration.brainProjectionMode !== brainProjectionMode) throw new Error("Resume Brain-projection mode does not match migration metadata");
        if (sourceRetention === "verified-reference" && !migration.sourceRetentionAcknowledgedAt) {
          throw new Error("Resumed verified-reference migration lacks its recorded acknowledgement");
        }
        if (brainProjectionMode === "attack-knowledge-only" && !migration.brainProjectionAcknowledgedAt) {
          throw new Error("Resumed attack-knowledge-only migration lacks its recorded acknowledgement");
        }
        const recordedRoots = [...migration.sourceRoots].map((root) => resolve(root)).sort();
        const requestedRoots = [...sourceRoots].sort();
        if (JSON.stringify(recordedRoots) !== JSON.stringify(requestedRoots)) {
          throw new Error("Resume source roots do not match migration metadata");
        }
        const recordedInventory = database.prepare(`
          SELECT receipt_hash, object_count, byte_count
          FROM legacy_migration_inventory_receipts WHERE migration_id = ?
        `).get(migration.id) as {
          readonly receipt_hash: string;
          readonly object_count: number;
          readonly byte_count: number;
        } | undefined;
        if (!recordedInventory) {
          throw new Error("Resume migration lacks an immutable source-inventory receipt");
        }
        if (recordedInventory.receipt_hash !== inventoryReceipt.hash ||
            Number(recordedInventory.object_count) !== inventoryReceipt.objectCount ||
            Number(recordedInventory.byte_count) !== inventoryReceipt.byteCount) {
          throw new Error("Resume source inventory hash/size/mtime receipt does not match the original job");
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
        migration = metadata.createRun({
          sourceRoots,
          databasePath,
          outputDirectory,
          startedAt,
          ...(settleSeconds !== undefined && settleCutoffAt ? { settleSeconds, settleCutoffAt } : {}),
          sourceRetention,
          verifiedReferenceAcknowledged,
          brainProjectionMode,
          attackKnowledgeOnlyAcknowledged: this.options.attackKnowledgeOnlyAcknowledged,
        });
        database.prepare(`
          INSERT INTO legacy_migration_inventory_receipts (
            migration_id, receipt_hash, object_count, byte_count, created_at
          ) VALUES (?, ?, ?, ?, ?)
        `).run(
          migration.id,
          inventoryReceipt.hash,
          inventoryReceipt.objectCount,
          inventoryReceipt.byteCount,
          this.clock().toISOString(),
        );
        migration = metadata.getRun(migration.id)!;
      }

      const migrationDirectory = join(outputDirectory, migration.id);
      const retiredSourceCopyDirectory = join(migrationDirectory, "sources");
      const sourceRows: string[] = [
        "source_sha256\tbyte_size\tmodified_at\toriginal_absolute_path\tretention_mode",
      ];
      const results: SourceMigrationResult[] = [];

      const priority: Record<LegacySource["type"], number> = {
        run_json: 0,
        kanban_sqlite: 0,
        session_json: 1,
        conversation_state_sqlite: 1,
        event_jsonl: 2,
        raw_llm_jsonl: 3,
        provider_session_json: 3,
        provider_session_jsonl: 3,
        provider_log: 4,
        conversation_markdown: 4,
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
        verifiedIdentity: VerifiedSourceIdentity;
      }> = [];
      for (const discoveredSource of orderedSources) {
        const verifiedIdentity = verifiedRegularSource(discoveredSource);
        sourceRows.push([
          discoveredSource.sha256,
          discoveredSource.byteSize,
          discoveredSource.modifiedAt,
          discoveredSource.absolutePath.replaceAll("\t", " "),
          "verified-reference",
        ].join("\t"));
        capturedSources.push({
          source: discoveredSource,
          verifiedIdentity,
        });
      }

      // This manifest is private migration metadata. In verified-reference mode
      // it contains no copied source bytes and makes that retention model explicit.
      const sourceManifestPath = join(
        migrationDirectory,
        "source-reference-manifest.tsv",
      );
      atomicWrite(sourceManifestPath, `${sourceRows.join("\n")}\n`);

      const engagementImporter = new LegacyEngagementImporter(
        database,
        metadata,
        migration.id,
        retiredSourceCopyDirectory,
        this.clock,
        undefined,
        {
          sourceRetention,
          verifiedReferenceAcknowledged,
          brainProjectionMode,
          attackKnowledgeOnlyAcknowledged: this.options.attackKnowledgeOnlyAcknowledged,
          ...(this.options.attackKnowledgeManifestHandler ? {
            attackKnowledgeManifestHandler: (manifest, handlerDatabase, context) => {
              const recordBatch = (batch: AttackKnowledgeExtractionBatchReport): void => {
                metadata.recordExtractionBatch({
                  migrationId: migration!.id,
                  extractorKind: "manifest",
                  report: batch,
                });
              };
              const batches = this.options.attackKnowledgeManifestHandler!(manifest, handlerDatabase, {
                dryRun: context.dryRun,
                migrationId: migration!.id,
                recordBatch,
              }) ?? [];
              // Backward-compatible handlers may return pages without calling
              // recordBatch. Re-recording is safe because page keys are stable.
              batches.forEach(recordBatch);
              return batches;
            },
          } : {}),
        },
      );
      for (const manifest of engagementDiscovery.manifests) {
        const result = await engagementImporter.importManifest(manifest);
        results.push(result);
        sourceRows.push([
          manifest.sha256,
          manifest.byteSize,
          manifest.modifiedAt,
          manifest.engagementDirectory.replaceAll("\t", " "),
          "verified-reference",
        ].join("\t"));
      }
      // Publish engagement inventory beside the generic source inventory after
      // the bounded batch. Protected-copy stores bytes; verified-reference
      // stores only private provenance metadata and opaque references.
      atomicWrite(sourceManifestPath, `${sourceRows.join("\n")}\n`);

      for (const { source, verifiedIdentity } of capturedSources) {
        const sourceId = metadata.registerSource(
          migration.id,
          source,
          undefined,
          {
            retentionMode: "verified-reference",
            device: verifiedIdentity.device,
            inode: verifiedIdentity.inode,
          },
        );
        metadata.markSource(sourceId, "importing");
        try {
          let result: SourceMigrationResult;
          database.exec("BEGIN IMMEDIATE");
          let descriptor: number | undefined;
          try {
              const before = verifiedIdentity;
              descriptor = openSync(source.absolutePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
              const opened = fstatSync(descriptor);
              if (opened.dev !== before.device || opened.ino !== before.inode) {
                throw new Error("Historical source inode changed after verified-reference preflight");
              }
              const sourceReference = metadata.registerSourceObject({
                migrationId: migration.id,
                sourceId,
                objectKey: "source",
                sourcePath: source.absolutePath,
                objectKind: "source",
                classification: source.type,
                sourceSha256: source.sha256,
                byteSize: source.byteSize,
                modifiedAt: source.modifiedAt,
                sourceDevice: before.device,
                sourceInode: before.inode,
              });
              if (brainProjectionMode === "attack-knowledge-only") {
                const sourceIdentity = sha256Text(`${source.type}\0${source.absolutePath}`);
                const itemKey = "reference:source";
                const previous = metadata.previousItem(sourceIdentity, source.sha256, itemKey, source.sha256);
                if (!previous) metadata.recordItem({
                  migrationId: migration.id,
                  sourceId,
                  sourceIdentity,
                  sourceSha256: source.sha256,
                  itemKey,
                  itemHash: source.sha256,
                  status: "imported",
                  targetTable: "legacy_migration_source_objects",
                });
                result = {
                  source,
                  imported: previous ? 0 : 1,
                  deduplicated: previous ? 1 : 0,
                  quarantined: 0,
                  skipped: 0,
                  targetCounts: { legacy_migration_source_objects: 1 },
                };
              } else {
                result = await new LegacyImporter(
                  database,
                  metadata,
                  migration.id,
                  sourceId,
                  source,
                  this.clock,
                  `/proc/self/fd/${descriptor}`,
                ).import();
              }
              void sourceReference;
              const after = verifiedRegularSource(source);
              if (!sameVerifiedIdentity(before, after)) throw new Error("Historical source changed during verified-reference import");
              metadata.markSource(sourceId, "completed");
              database.exec("COMMIT");
          } catch (error) {
            if (database.inTransaction) database.exec("ROLLBACK");
            throw error;
          } finally {
            if (descriptor !== undefined) closeSync(descriptor);
          }
          results.push(result);
        } catch (error) {
          metadata.markSource(sourceId, "failed", error instanceof Error ? error.message : String(error));
          throw error;
        }
      }
      if (brainProjectionMode === "attack-knowledge-only" &&
          this.options.genericAttackKnowledgeSourceHandler && inventory.included.length > 0) {
        const recordBatch = (batch: AttackKnowledgeExtractionBatchReport): void => {
          metadata.recordExtractionBatch({
            migrationId: migration!.id,
            extractorKind: "generic",
            report: batch,
          });
        };
        const batches = this.options.genericAttackKnowledgeSourceHandler({
          migrationId: migration.id,
          inventoryReceiptHash: inventoryReceipt.hash,
          sources: inventory.included,
        }, database, {
          dryRun: false,
          migrationId: migration.id,
          recordBatch,
        }) ?? [];
        batches.forEach(recordBatch);
      }
      if (sourceRetention === "verified-reference") {
        // The generic semantic handler runs after per-source custody is
        // registered. Revalidate every referenced object once more so a file
        // that changes during that later phase still aborts the migration.
        for (const { source, verifiedIdentity } of capturedSources) {
          if (!verifiedIdentity) continue;
          const current = verifiedRegularSource(source);
          if (!sameVerifiedIdentity(verifiedIdentity, current)) {
            throw new Error("Historical source changed after verified-reference import");
          }
        }
      }
      assertDatabaseIntegrity(database);
      const integrity = databaseValidation(database);
      if (integrity.foreignKeyViolations) throw new Error(`Foreign-key reconciliation found ${integrity.foreignKeyViolations} violation(s)`);
      const attackKnowledgeExtraction = brainProjectionMode === "attack-knowledge-only" &&
        (this.options.attackKnowledgeManifestHandler || this.options.genericAttackKnowledgeSourceHandler)
        ? new HistoricalAttackKnowledgeExtractionReconciliationService(database)
          .reconcile(migration.id, false)
        : undefined;
      if (attackKnowledgeExtraction?.status === "partial") {
        throw new Error(
          `Historical attack-knowledge extraction is incomplete across ${attackKnowledgeExtraction.partialScopeCount} scope(s); resume from the persisted opaque cursor ledger`,
        );
      }
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
        excluded: reportedExclusions,
        ...(settledSourceBoundary ? { settledSourceBoundary } : {}),
        sourceReferences: {
          manifestPath: sourceManifestPath,
          pathsArePrivateMigrationMetadata: true,
          sourceBytesCopied: false,
        },
        sourceRetention: {
          mode: sourceRetention,
          protectedSourceCopyCreated: false,
          acknowledgementRequired: true,
          referenceOnly: referenceOnlySummary,
        },
        brainProjection: {
          mode: brainProjectionMode,
          legacyMissionRunAssetArtifactNodesCreated: brainProjectionMode === "legacy-engagement",
          acknowledgementRequired: brainProjectionMode === "attack-knowledge-only",
        },
        inventoryReceipt,
        ...(reviewedDeltaPlan ? { reviewedDeltaExecution: {
          executionPlanHash: reviewedDeltaPlan.planHash,
          publicPlanHash: reviewedDeltaPlan.publicPlanHash,
          configurationSha256: reviewedDeltaPlan.configuration.sha256,
          baselineInventoryReceiptSetHash: reviewedDeltaPlan.baseline.inventoryReceiptSetHash,
          admittedFiles: reviewedDeltaPlan.delta.files,
          admittedBytes: reviewedDeltaPlan.delta.bytes,
          exactPathAdmission: true as const,
        } } : {}),
        ...(sqliteSnapshotQuarantine ? { sqliteSnapshotQuarantine } : {}),
        ...(attackKnowledgeExtraction ? { attackKnowledgeExtraction } : {}),
        integrity,
        warnings: [
          "Original legacy files were not modified or deleted.",
          ...(brainProjectionMode === "legacy-engagement" ? [
            "Imported missions remain authorization-unverified and legacy nonterminal runs are blocked.",
            "Memory and lessons remain candidates/proposed until operator review.",
          ] : [
            "Attack-knowledge-only mode created no legacy mission, run, asset, artifact, or per-file Brain nodes; only private source inventory and the configured sanitized semantic extractor are permitted.",
          ]),
          `Verified-reference retained ${referenceOnlySummary.referencedObjects} source objects (${referenceOnlySummary.referencedBytes} bytes) by private reference; zero accepted or quarantined source bytes were copied.`,
          "Reference-only artifacts do not claim immutable copied storage. Source availability remains dependent on the operator-owned historical tree.",
          "Symbolic links were inventoried by link-object fingerprint only and were never followed.",
          ...(settledSourceBoundary ? [
            `The explicit ${settledSourceBoundary.settleSeconds}-second settled-source boundary deferred ${settledSourceBoundary.deferredObjects} source object(s); the reconciliation receipt separates recent writes from explicitly verified active sources, which remain eligible for a later migration after settling.`,
          ] : []),
          "Obsidian projection is not automatic; an exact reconciliation hash and explicit approval are required.",
        ],
        engagementDiscovery: engagementDiscoverySummary(engagementDiscovery, rootResolution),
        genericSourceDiscovery,
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

}

export interface RollbackOptions {
  readonly databasePath: string;
  readonly backupPath: string;
  readonly expectedSha256: string;
  readonly serviceStopped: boolean;
  /** Exact owner required on the restored database. Defaults to the existing database owner. */
  readonly expectedUid?: number;
  /** Exact group required on the restored database. Defaults to the existing database group. */
  readonly expectedGid?: number;
  /** Exact permission bits required on the restored database. Defaults to the existing database mode. */
  readonly expectedMode?: number;
  /** Test/diagnostic seam emitted immediately after the named restore operation. */
  readonly onPhase?: (phase: RestoreMigrationBackupPhase) => void;
}

export type RestoreMigrationBackupPhase =
  | "backup_validated"
  | "safety_copies_synced"
  | "safety_directory_synced"
  | "restore_temporary_synced"
  | "sidecars_unlinked"
  | "sidecar_directory_synced"
  | "database_renamed"
  | "database_directory_synced"
  | "restore_verified";

interface RestoreFileIdentity {
  readonly uid: number;
  readonly gid: number;
  readonly mode: number;
}

const RESTORE_NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const RESTORE_CLOSE_ON_EXEC = (constants as typeof constants & { readonly O_CLOEXEC?: number }).O_CLOEXEC ?? 0;
const RESTORE_DIRECTORY = constants.O_DIRECTORY ?? 0;
const RESTORE_MODE_MASK = 0o7777;

function lstatIfPresent(path: string): Stats | undefined {
  try {
    return lstatSync(path) as Stats;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

function assertExactRegularFile(path: string, label: string): Stats {
  const state = lstatIfPresent(path);
  if (!state) throw new Error(`${label} does not exist: ${path}`);
  if (state.isSymbolicLink() || !state.isFile()) {
    throw new Error(`${label} must be a regular non-symlink file: ${path}`);
  }
  const canonicalPath = realpathSync(path);
  if (canonicalPath !== path) {
    throw new Error(`${label} must resolve to its exact configured path: ${path}`);
  }
  return state;
}

function assertExactDirectory(path: string, label: string): void {
  const state = lstatSync(path);
  if (state.isSymbolicLink() || !state.isDirectory()) {
    throw new Error(`${label} must be a real non-symlink directory: ${path}`);
  }
  if (realpathSync(path) !== path) {
    throw new Error(`${label} must resolve to its exact configured path: ${path}`);
  }
}

function openExactRegularFile(path: string, label: string): number {
  const lexicalState = assertExactRegularFile(path, label);
  const descriptor = openSync(
    path,
    constants.O_RDONLY | RESTORE_NO_FOLLOW | RESTORE_CLOSE_ON_EXEC,
  );
  try {
    const openedState = fstatSync(descriptor);
    if (!openedState.isFile() || openedState.dev !== lexicalState.dev || openedState.ino !== lexicalState.ino) {
      throw new Error(`${label} changed identity while it was opened: ${path}`);
    }
    return descriptor;
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

async function hashExactRegularFile(path: string, label: string): Promise<string> {
  const descriptor = openExactRegularFile(path, label);
  const before = fstatSync(descriptor);
  const hash = createHash("sha256");
  try {
    const stream = createReadStream(path, { fd: descriptor, autoClose: false });
    for await (const chunk of stream) hash.update(chunk as Buffer);
    const after = fstatSync(descriptor);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    ) {
      throw new Error(`${label} changed while it was hashed: ${path}`);
    }
    return hash.digest("hex");
  } finally {
    closeSync(descriptor);
  }
}

function fsyncExactDirectory(path: string, label: string): void {
  assertExactDirectory(path, label);
  const descriptor = openSync(
    path,
    constants.O_RDONLY | RESTORE_DIRECTORY | RESTORE_NO_FOLLOW | RESTORE_CLOSE_ON_EXEC,
  );
  try {
    if (!fstatSync(descriptor).isDirectory()) throw new Error(`${label} changed while it was opened: ${path}`);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function validateIdentityField(value: number, label: string, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new RangeError(`${label} must be a non-negative integer no greater than ${maximum}`);
  }
  return value;
}

function requestedRestoreIdentity(
  options: RollbackOptions,
  current: Stats | undefined,
): RestoreFileIdentity {
  const defaultUid = current?.uid ?? (typeof process.getuid === "function" ? process.getuid() : 0);
  const defaultGid = current?.gid ?? (typeof process.getgid === "function" ? process.getgid() : 0);
  const defaultMode = current ? current.mode & RESTORE_MODE_MASK : 0o600;
  return {
    uid: validateIdentityField(options.expectedUid ?? defaultUid, "expectedUid"),
    gid: validateIdentityField(options.expectedGid ?? defaultGid, "expectedGid"),
    mode: validateIdentityField(options.expectedMode ?? defaultMode, "expectedMode", RESTORE_MODE_MASK),
  };
}

function prepareAndSyncCopiedFile(
  path: string,
  label: string,
  identity: RestoreFileIdentity,
): void {
  const descriptor = openExactRegularFile(path, label);
  try {
    const initial = fstatSync(descriptor);
    if (initial.uid !== identity.uid || initial.gid !== identity.gid) {
      fchownSync(descriptor, identity.uid, identity.gid);
    }
    if ((fstatSync(descriptor).mode & RESTORE_MODE_MASK) !== identity.mode) {
      fchmodSync(descriptor, identity.mode);
    }
    const prepared = fstatSync(descriptor);
    if (
      prepared.uid !== identity.uid ||
      prepared.gid !== identity.gid ||
      (prepared.mode & RESTORE_MODE_MASK) !== identity.mode
    ) {
      throw new Error(`${label} ownership or mode could not be prepared exactly: ${path}`);
    }
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

async function assertRestoredDatabaseExact(
  path: string,
  expectedSha256: string,
  expectedIdentity: RestoreFileIdentity,
): Promise<void> {
  const state = assertExactRegularFile(path, "Restored database");
  if (
    state.uid !== expectedIdentity.uid ||
    state.gid !== expectedIdentity.gid ||
    (state.mode & RESTORE_MODE_MASK) !== expectedIdentity.mode
  ) {
    throw new Error(
      `Restored database ownership/mode mismatch: expected ${expectedIdentity.uid}:${expectedIdentity.gid} ` +
      `${expectedIdentity.mode.toString(8)}, received ${state.uid}:${state.gid} ` +
      `${(state.mode & RESTORE_MODE_MASK).toString(8)}`,
    );
  }
  if (await hashExactRegularFile(path, "Restored database") !== expectedSha256) {
    throw new Error("Restored database checksum does not match rollback metadata");
  }
}

/**
 * Retained only as a source-compatibility trap for callers compiled against the
 * former rollback API. Operator policy is forward-only: this function rejects
 * before resolving, opening, copying, deleting, or renaming any filesystem path.
 */
export async function restoreMigrationBackup(options: RollbackOptions): Promise<void> {
  void options;
  throw new Error(
    "Legacy migration restore is disabled by operator policy; migration is forward-only and retains no restorable database copy",
  );
  /* c8 ignore start -- unreachable legacy implementation kept for source compatibility */
  if (!options.serviceStopped) throw new Error("Rollback requires an explicit confirmation that the Ti-Scale service is stopped");
  const databasePath = resolve(options.databasePath);
  const backupPath = resolve(options.backupPath);
  if (backupPath === databasePath) throw new Error("Backup path must be different from the database path");
  assertExactRegularFile(backupPath, "Backup");
  const actualHash = await hashExactRegularFile(backupPath, "Backup");
  if (actualHash !== options.expectedSha256) throw new Error("Backup checksum does not match rollback metadata");
  options.onPhase?.("backup_validated");

  const databaseDirectory = dirname(databasePath);
  mkdirSync(databaseDirectory, { recursive: true, mode: 0o700 });
  assertExactDirectory(databaseDirectory, "Database parent");
  const currentDatabase = lstatIfPresent(databasePath);
  if (currentDatabase) assertExactRegularFile(databasePath, "Current database");
  const expectedIdentity = requestedRestoreIdentity(options, currentDatabase);
  const temporary = join(
    databaseDirectory,
    `.${basename(databasePath)}.${process.pid}.${Date.now()}.${randomUUID()}.restore`,
  );
  let temporaryCreated = false;
  try {
    // Preserve the current database and any SQLite sidecars before replacement.
    // This is a last-resort rollback-of-the-rollback copy, not a canonical source.
    const safety = `${databasePath}.pre-rollback-${new Date().toISOString().replace(/[:.]/gu, "-")}-${randomUUID()}`;
    const safetySources = [databasePath, `${databasePath}-wal`, `${databasePath}-shm`]
      .filter((path) => lstatIfPresent(path) !== undefined);
    const safetyIdentity: RestoreFileIdentity = {
      uid: process.getuid?.() ?? expectedIdentity.uid,
      gid: process.getgid?.() ?? expectedIdentity.gid,
      mode: 0o600,
    };
    for (const source of safetySources) {
      assertExactRegularFile(source, "Rollback safety source");
      const suffix = source === databasePath ? "" : source.slice(databasePath.length);
      const destination = `${safety}${suffix}`;
      copyFileSync(source, destination, constants.COPYFILE_EXCL);
      prepareAndSyncCopiedFile(destination, "Rollback safety copy", safetyIdentity);
    }
    options.onPhase?.("safety_copies_synced");
    if (safetySources.length > 0) {
      fsyncExactDirectory(databaseDirectory, "Database parent");
      options.onPhase?.("safety_directory_synced");
    }

    copyFileSync(backupPath, temporary, constants.COPYFILE_EXCL);
    temporaryCreated = true;
    prepareAndSyncCopiedFile(temporary, "Prepared restore database", expectedIdentity);
    const preparedVerification = createDatabaseConnection({
      filename: temporary,
      readonly: true,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    try { assertDatabaseIntegrity(preparedVerification); }
    finally { preparedVerification.close(); }
    for (const suffix of ["-wal", "-shm"] as const) {
      const preparedSidecar = `${temporary}${suffix}`;
      if (lstatIfPresent(preparedSidecar)) {
        assertExactRegularFile(preparedSidecar, "Prepared restore SQLite sidecar");
        rmSync(preparedSidecar);
      }
    }
    if (await hashExactRegularFile(temporary, "Prepared restore database") !== options.expectedSha256) {
      throw new Error("Prepared restore database checksum does not match rollback metadata");
    }
    fsyncExactDirectory(databaseDirectory, "Database parent");
    options.onPhase?.("restore_temporary_synced");

    // A WAL from the post-import database must never be replayed over the restored image.
    for (const suffix of ["-wal", "-shm"] as const) {
      const sidecar = `${databasePath}${suffix}`;
      if (lstatIfPresent(sidecar)) {
        assertExactRegularFile(sidecar, "SQLite sidecar");
        rmSync(sidecar);
      }
    }
    options.onPhase?.("sidecars_unlinked");
    fsyncExactDirectory(databaseDirectory, "Database parent");
    options.onPhase?.("sidecar_directory_synced");

    renameSync(temporary, databasePath);
    temporaryCreated = false;
    options.onPhase?.("database_renamed");
    fsyncExactDirectory(databaseDirectory, "Database parent");
    options.onPhase?.("database_directory_synced");

    await assertRestoredDatabaseExact(databasePath, options.expectedSha256, expectedIdentity);
    options.onPhase?.("restore_verified");
  } catch (error) {
    if (temporaryCreated) {
      for (const path of [temporary, `${temporary}-wal`, `${temporary}-shm`]) rmSync(path, { force: true });
      try { fsyncExactDirectory(databaseDirectory, "Database parent"); }
      catch { /* Preserve the primary restore failure; a retry reclaims any orphaned temp entry. */ }
    }
    throw error;
  }
  /* c8 ignore stop */
}

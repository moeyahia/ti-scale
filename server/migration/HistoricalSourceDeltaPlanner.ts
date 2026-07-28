import { createHash } from "node:crypto";
import { lstatSync } from "node:fs";
import { extname, relative, resolve, sep } from "node:path";
import type { SqliteDatabase } from "../db";
import { canonicalJson, hashJson } from "../orchestration/serialization";
import {
  discoverLegacyEngagements,
  type LegacyEngagementFile,
  type LegacyEngagementExclusion,
} from "./LegacyEngagementDiscovery";
import {
  type HistoricalSourceRootConfiguration,
  type HistoricalSourceRootDefinition,
} from "./HistoricalSourceRootConfiguration";
import { discoverLegacySources } from "./SourceDiscovery";
import {
  indexHistoricalSqliteSnapshotQuarantineFiles,
  summarizeHistoricalSqliteSnapshotQuarantineMappings,
  type HistoricalSqliteSnapshotQuarantineMapping,
  type ReceiptBoundSqliteQuarantineFile,
} from "./HistoricalSqliteSnapshotQuarantineMapping";
import {
  HISTORICAL_SOURCE_DELTA_EXECUTION_PLAN_SCHEMA_VERSION,
  createHistoricalSourceDeltaExecutionPlan,
  type HistoricalDeltaDisposition,
  type HistoricalParserEligibility,
  type HistoricalSourceDeltaAdmission,
  type HistoricalSourceDeltaBaselineBinding,
  type HistoricalSourceDeltaExecutionPlan,
  type HistoricalSourceSensitivity,
} from "./HistoricalSourceDeltaExecutionPlan";

export const HISTORICAL_SOURCE_DELTA_PLAN_SCHEMA_VERSION =
  "ti_scale.historical_source_delta_plan/v1" as const;

const MINIMUM_SETTLE_SECONDS = 60;
const MAXIMUM_SETTLE_SECONDS = 86_400;
const MAXIMUM_SEMANTIC_FILE_BYTES = 2 * 1024 * 1024;
const SEMANTIC_ENGAGEMENT_KINDS = new Set([
  "note", "report", "recon", "script", "evidence", "log",
]);
const SEMANTIC_TEXT_EXTENSIONS = new Set([
  ".txt", ".md", ".json", ".jsonl", ".xml", ".csv", ".yaml", ".yml",
  ".html", ".htm", ".nmap", ".gnmap", ".log", ".py", ".sh", ".ps1",
  ".js", ".ts", ".rb", ".go", ".c", ".cpp", ".conf", ".ini",
]);
const SEMANTIC_SUMMARY_LOG_NAME =
  /(?:summary|status|checkpoint|result|timeline|next[-_ ]?actions|blocker|recovery)/iu;

interface PrivateCurrentItem {
  readonly rootId: string;
  readonly path: string;
  readonly sourceHash: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
  readonly sourceDevice: number;
  readonly sourceInode: number;
  readonly classification: string;
  readonly objectKind: "accepted" | "quarantined" | "source" | "symlink";
  readonly parserEligibility: HistoricalParserEligibility;
  readonly sensitivity: HistoricalSourceSensitivity;
}

interface PrivateBaselineItem {
  readonly path: string;
  readonly sourceHash: string;
}

export interface HistoricalSourceDeltaCategory {
  readonly classification: string;
  readonly parserEligibility: HistoricalParserEligibility;
  readonly sensitivity: HistoricalSourceSensitivity;
  readonly newFiles: number;
  readonly changedFiles: number;
  readonly bytes: number;
}

export interface HistoricalSourceDeltaRootSummary {
  readonly rootId: string;
  readonly mode: HistoricalSourceRootDefinition["mode"];
  readonly status: "ready" | "no_delta" | "blocked_active_sqlite";
  readonly stableCurrentFiles: number;
  readonly stableDeltaFiles: number;
  readonly stableDeltaBytes: number;
  readonly deferredRecentFiles: number;
  readonly deferredRecentBytes: number;
  readonly activeSqliteFiles: number;
  readonly receiptBoundSqliteFiles: number;
  readonly receiptBoundSqliteBytes: number;
  readonly policyExcludedFiles: number;
  readonly unsupportedFiles: number;
  readonly oversizedFiles: number;
  readonly vaultProjectionDirectories: number;
  readonly deniedDirectories: number;
  readonly categories: readonly HistoricalSourceDeltaCategory[];
}

export interface HistoricalSourceDeltaPlan {
  readonly schemaVersion: typeof HISTORICAL_SOURCE_DELTA_PLAN_SCHEMA_VERSION;
  readonly dryRun: true;
  readonly status: "ready" | "no_delta" | "blocked_active_sqlite";
  readonly configuration: {
    readonly schemaVersion: HistoricalSourceRootConfiguration["schemaVersion"];
    readonly version: string;
    readonly sha256: string;
    readonly rootCount: number;
  };
  readonly boundary: {
    readonly plannedAt: string;
    readonly settleSeconds: number;
    readonly cutoffAt: string;
  };
  readonly baseline: {
    readonly completedMigrationCount: number;
    readonly sourceObjectCount: number;
    readonly inventoryReceiptCount: number;
    readonly inventoryReceiptSetHash: string;
  };
  readonly current: {
    readonly stableFiles: number;
    readonly stableBytes: number;
    readonly alreadyImportedFiles: number;
    readonly deferredRecentFiles: number;
    readonly deferredRecentBytes: number;
    readonly activeSqliteFiles: number;
    readonly receiptBoundSqliteFiles: number;
    readonly receiptBoundSqliteBytes: number;
    readonly policyExcludedFiles: number;
    readonly unsupportedFiles: number;
    readonly oversizedFiles: number;
    readonly vaultProjectionDirectories: number;
    readonly deniedDirectories: number;
    readonly inventoryHash: string;
  };
  readonly delta: {
    readonly files: number;
    readonly bytes: number;
    readonly newFiles: number;
    readonly changedFiles: number;
    readonly semanticParserEligibleFiles: number;
    readonly custodyOnlyFiles: number;
    readonly quarantinedFiles: number;
    readonly inventoryHash: string;
    readonly categories: readonly HistoricalSourceDeltaCategory[];
  };
  readonly roots: readonly HistoricalSourceDeltaRootSummary[];
  readonly sqliteSnapshotQuarantine?: ReturnType<
    typeof summarizeHistoricalSqliteSnapshotQuarantineMappings
  >;
  readonly safety: {
    readonly sourcePathsExposed: false;
    readonly sourceContentExposed: false;
    readonly canonicalDatabaseOpenedReadOnly: true;
    readonly canonicalDatabaseWrites: false;
    readonly vaultWrites: false;
    readonly sourceWrites: false;
    readonly unchangedSourcesRequireReingestion: false;
  };
  readonly planHash: string;
}

interface CollectedRoot {
  readonly definition: HistoricalSourceRootDefinition;
  readonly items: readonly PrivateCurrentItem[];
  readonly deferredRecentFiles: number;
  readonly deferredRecentBytes: number;
  readonly activeSqliteFiles: number;
  readonly receiptBoundSqliteFiles: number;
  readonly receiptBoundSqliteBytes: number;
  readonly policyExcludedFiles: number;
  readonly unsupportedFiles: number;
  readonly oversizedFiles: number;
  readonly vaultProjectionDirectories: number;
  readonly deniedDirectories: number;
}

interface BaselineInventory {
  readonly items: readonly PrivateBaselineItem[];
  readonly completedMigrationCount: number;
  readonly sourceObjectCount: number;
  readonly inventoryReceiptCount: number;
  readonly inventoryReceiptSetHash: string;
}

export function historicalSourceDeltaBaselineBinding(
  database: SqliteDatabase,
): HistoricalSourceDeltaBaselineBinding {
  const baseline = loadBaseline(database);
  return Object.freeze({
    completedMigrationCount: baseline.completedMigrationCount,
    sourceObjectCount: baseline.sourceObjectCount,
    inventoryReceiptCount: baseline.inventoryReceiptCount,
    inventoryReceiptSetHash: baseline.inventoryReceiptSetHash,
  });
}

interface ClassifiedDeltaItem extends PrivateCurrentItem {
  readonly disposition: HistoricalDeltaDisposition;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isInside(parent: string, candidate: string): boolean {
  const value = relative(parent, candidate);
  return value === "" || (value !== ".." && !value.startsWith(`..${sep}`));
}

export function semanticEngagementEligibility(file: LegacyEngagementFile): HistoricalParserEligibility {
  const extension = extname(file.relativePath).toLowerCase();
  if (
    !SEMANTIC_ENGAGEMENT_KINDS.has(file.kind)
    || !SEMANTIC_TEXT_EXTENSIONS.has(extension)
    || !["text", "structured"].includes(file.contentClass)
    || file.byteSize > MAXIMUM_SEMANTIC_FILE_BYTES
    || (file.kind === "log" && !SEMANTIC_SUMMARY_LOG_NAME.test(file.relativePath))
  ) return "custody_only";
  return "semantic_parser_eligible";
}

export function quarantineSensitivity(
  exclusion: LegacyEngagementExclusion,
): HistoricalSourceSensitivity {
  if (exclusion.category === "oversized") return "quarantined_oversized";
  if (exclusion.category === "unsafe_name") return "quarantined_unsafe_name";
  if (exclusion.category === "symlink") return "non_dereferenced_symlink";
  return "quarantined_sensitive";
}

function sourceIdentity(path: string): {
  readonly modifiedAt: string;
  readonly sourceDevice: number;
  readonly sourceInode: number;
} {
  const state = lstatSync(path);
  return {
    modifiedAt: state.mtime.toISOString(),
    sourceDevice: state.dev,
    sourceInode: state.ino,
  };
}

function aggregateCategories(items: readonly ClassifiedDeltaItem[]): readonly HistoricalSourceDeltaCategory[] {
  const categories = new Map<string, {
    classification: string;
    parserEligibility: HistoricalParserEligibility;
    sensitivity: HistoricalSourceSensitivity;
    newFiles: number;
    changedFiles: number;
    bytes: number;
  }>();
  for (const item of items) {
    const key = canonicalJson([
      item.classification,
      item.parserEligibility,
      item.sensitivity,
    ]);
    const current = categories.get(key) ?? {
      classification: item.classification,
      parserEligibility: item.parserEligibility,
      sensitivity: item.sensitivity,
      newFiles: 0,
      changedFiles: 0,
      bytes: 0,
    };
    current[item.disposition === "new" ? "newFiles" : "changedFiles"] += 1;
    current.bytes += item.byteSize;
    categories.set(key, current);
  }
  return [...categories.values()].sort((left, right) =>
    left.classification.localeCompare(right.classification)
    || left.parserEligibility.localeCompare(right.parserEligibility)
    || left.sensitivity.localeCompare(right.sensitivity));
}

function privateInventoryHash(items: readonly PrivateCurrentItem[]): string {
  return hashJson(items.map((item) => ({
    rootId: item.rootId,
    pathIdentity: sha256(`${item.rootId}\0${item.path}`),
    sourceHash: item.sourceHash,
    byteSize: item.byteSize,
    classification: item.classification,
    objectKind: item.objectKind,
    parserEligibility: item.parserEligibility,
    sensitivity: item.sensitivity,
  })).sort((left, right) =>
    left.rootId.localeCompare(right.rootId)
    || left.pathIdentity.localeCompare(right.pathIdentity)
    || left.sourceHash.localeCompare(right.sourceHash)));
}

function classifyDelta(
  current: readonly PrivateCurrentItem[],
  baseline: readonly PrivateBaselineItem[],
): { readonly unchanged: number; readonly delta: readonly ClassifiedDeltaItem[] } {
  const exact = new Set(baseline.map((item) => `${item.path}\0${item.sourceHash}`));
  const paths = new Set(baseline.map((item) => item.path));
  const delta: ClassifiedDeltaItem[] = [];
  let unchanged = 0;
  for (const item of current) {
    if (exact.has(`${item.path}\0${item.sourceHash}`)) {
      unchanged += 1;
      continue;
    }
    delta.push({ ...item, disposition: paths.has(item.path) ? "changed" : "new" });
  }
  return { unchanged, delta };
}

function loadBaseline(database: SqliteDatabase): BaselineInventory {
  const items = database.prepare(`
    SELECT DISTINCT source_path AS path, source_sha256 AS source_hash
    FROM legacy_migration_source_objects AS source_object
    JOIN legacy_migration_runs AS migration
      ON migration.id = source_object.migration_id
    WHERE migration.status = 'completed'
      AND migration.source_retention = 'verified-reference'
      AND migration.brain_projection_mode = 'attack-knowledge-only'
    ORDER BY source_path, source_sha256
  `).all() as Array<{ path: string; source_hash: string }>;
  const migrations = database.prepare(`
    SELECT migration.id, inventory.receipt_hash
    FROM legacy_migration_runs AS migration
    LEFT JOIN legacy_migration_inventory_receipts AS inventory
      ON inventory.migration_id = migration.id
    WHERE migration.status = 'completed'
      AND migration.source_retention = 'verified-reference'
      AND migration.brain_projection_mode = 'attack-knowledge-only'
    ORDER BY migration.id
  `).all() as Array<{ id: string; receipt_hash: string | null }>;
  const receipts = migrations.flatMap(({ id, receipt_hash }) =>
    receipt_hash ? [{ migrationId: id, receiptHash: receipt_hash }] : []);
  return {
    items: items.map(({ path, source_hash }) => ({ path, sourceHash: source_hash })),
    completedMigrationCount: migrations.length,
    sourceObjectCount: items.length,
    inventoryReceiptCount: receipts.length,
    inventoryReceiptSetHash: hashJson(receipts),
  };
}

function deferredSummary(values: readonly { sourceDevice: number; sourceInode: number; byteSize: number }[]): {
  readonly files: number;
  readonly bytes: number;
} {
  const unique = new Map<string, number>();
  for (const item of values) {
    const identity = `${item.sourceDevice}:${item.sourceInode}`;
    if (!unique.has(identity)) unique.set(identity, item.byteSize);
  }
  return { files: unique.size, bytes: [...unique.values()].reduce((sum, value) => sum + value, 0) };
}

async function collectRoot(
  definition: HistoricalSourceRootDefinition,
  cutoffAt: string,
  receiptBoundSqliteQuarantines: ReadonlyMap<string, ReceiptBoundSqliteQuarantineFile>,
): Promise<CollectedRoot> {
  const path = resolve(definition.path);
  if (definition.mode === "history-root") {
    const inventory = await discoverLegacySources([path], {
      settledSourceCutoffAt: cutoffAt,
      boundedHistoryRoots: [path],
      maximumBoundedSourceBytes: 8 * 1024 * 1024,
      maximumBoundedFiles: 100_000,
      maximumBoundedDepth: 24,
      ...(receiptBoundSqliteQuarantines.size > 0 ? { receiptBoundSqliteQuarantines } : {}),
    });
    const deferred = deferredSummary(inventory.deferred);
    return {
      definition,
      items: inventory.included.map((source) => ({
        rootId: definition.id,
        path: source.absolutePath,
        sourceHash: source.sha256,
        byteSize: source.byteSize,
        ...sourceIdentity(source.absolutePath),
        classification: source.type,
        objectKind: "source" as const,
        parserEligibility: source.type === "artifact"
          ? "custody_only" as const
          : "semantic_parser_eligible" as const,
        sensitivity: "local_only_record_sanitization_required" as const,
      })),
      deferredRecentFiles: deferred.files,
      deferredRecentBytes: deferred.bytes,
      activeSqliteFiles: inventory.coverage.activeSqliteFiles,
      receiptBoundSqliteFiles: inventory.coverage.receiptBoundSqliteFiles,
      receiptBoundSqliteBytes: inventory.coverage.receiptBoundSqliteBytes,
      policyExcludedFiles: new Set(inventory.excluded.map(({ absolutePath }) => absolutePath)).size,
      unsupportedFiles: inventory.coverage.unsupportedFiles,
      oversizedFiles: inventory.coverage.oversizedFiles,
      vaultProjectionDirectories: inventory.coverage.vaultProjectionDirectories,
      deniedDirectories: inventory.coverage.deniedDirectories,
    };
  }

  const rootMode = definition.mode === "engagement-root" ? "self" as const : "children" as const;
  const [engagements, generic] = await Promise.all([
    discoverLegacyEngagements([path], {
      rootMode,
      settledSourceCutoffAt: cutoffAt,
      ...(receiptBoundSqliteQuarantines.size > 0 ? { receiptBoundSqliteQuarantines } : {}),
    }),
    discoverLegacySources([path], {
      settledSourceCutoffAt: cutoffAt,
      ...(receiptBoundSqliteQuarantines.size > 0 ? { receiptBoundSqliteQuarantines } : {}),
    }),
  ]);
  const engagementDirectories = engagements.manifests.map(({ engagementDirectory }) => engagementDirectory);
  const accepted: PrivateCurrentItem[] = engagements.manifests.flatMap(({ files }) =>
    files.map((file) => ({
      rootId: definition.id,
      path: file.absolutePath,
      sourceHash: file.sha256,
      byteSize: file.byteSize,
      ...sourceIdentity(file.absolutePath),
      classification: file.kind,
      objectKind: "accepted" as const,
      parserEligibility: semanticEngagementEligibility(file),
      sensitivity: "locally_screened" as const,
    })));
  const quarantined: PrivateCurrentItem[] = engagements.manifests.flatMap(({ quarantined: values }) =>
    values.flatMap((item) => item.sourceSha256 ? [{
      rootId: definition.id,
      path: item.absolutePath,
      sourceHash: item.sourceSha256,
      byteSize: item.byteSize ?? 0,
      ...sourceIdentity(item.absolutePath),
      classification: item.category,
      objectKind: item.category === "symlink" ? "symlink" as const : "quarantined" as const,
      parserEligibility: "quarantined" as const,
      sensitivity: quarantineSensitivity(item),
    }] : []));
  const rootLevelSources: PrivateCurrentItem[] = generic.included
    .filter((source) => !engagementDirectories.some((directory) => isInside(directory, source.absolutePath)))
    .map((source) => ({
      rootId: definition.id,
      path: source.absolutePath,
      sourceHash: source.sha256,
      byteSize: source.byteSize,
      ...sourceIdentity(source.absolutePath),
      classification: source.type,
      objectKind: "source" as const,
      parserEligibility: source.type === "artifact"
        ? "custody_only" as const
        : "semantic_parser_eligible" as const,
      sensitivity: "local_only_record_sanitization_required" as const,
    }));
  const deferred = deferredSummary([...engagements.deferred, ...generic.deferred]);
  return {
    definition,
    items: [...accepted, ...quarantined, ...rootLevelSources],
    deferredRecentFiles: deferred.files,
    deferredRecentBytes: deferred.bytes,
    activeSqliteFiles: generic.coverage.activeSqliteFiles,
    receiptBoundSqliteFiles: generic.coverage.receiptBoundSqliteFiles,
    receiptBoundSqliteBytes: generic.coverage.receiptBoundSqliteBytes,
    policyExcludedFiles: new Set(generic.excluded.map(({ absolutePath }) => absolutePath)).size,
    unsupportedFiles: generic.coverage.unsupportedFiles,
    oversizedFiles: generic.coverage.oversizedFiles,
    vaultProjectionDirectories: generic.coverage.vaultProjectionDirectories,
    deniedDirectories: generic.coverage.deniedDirectories,
  };
}

export interface HistoricalSourceDeltaPlannerInput {
  readonly configuration: HistoricalSourceRootConfiguration;
  readonly configurationSha256: string;
  readonly settleSeconds: number;
  readonly now?: Date;
  readonly sqliteSnapshotQuarantineMappings?: readonly HistoricalSqliteSnapshotQuarantineMapping[];
}

/**
 * Read-only inventory comparison. Private paths are required to compare the
 * live tree with canonical custody, but they are reduced to aggregate counts
 * and inventory hashes before this method returns.
 */
export class HistoricalSourceDeltaPlanner {
  constructor(private readonly database: SqliteDatabase) {}

  private async prepare(input: HistoricalSourceDeltaPlannerInput): Promise<{
    readonly publicPlan: HistoricalSourceDeltaPlan;
    readonly delta: readonly ClassifiedDeltaItem[];
  }> {
    if (!Number.isSafeInteger(input.settleSeconds)
      || input.settleSeconds < MINIMUM_SETTLE_SECONDS
      || input.settleSeconds > MAXIMUM_SETTLE_SECONDS) {
      throw new RangeError("settleSeconds must be an integer between 60 and 86400");
    }
    if (!/^[a-f0-9]{64}$/u.test(input.configurationSha256)) {
      throw new Error("configurationSha256 must be a lowercase SHA-256");
    }
    const plannedAt = (input.now ?? new Date()).toISOString();
    const cutoffAt = new Date(Date.parse(plannedAt) - input.settleSeconds * 1_000).toISOString();
    const baseline = loadBaseline(this.database);
    const mappings = input.sqliteSnapshotQuarantineMappings ?? [];
    const configuredRoots = input.configuration.roots.map(({ path }) => path);
    const receiptBoundSqliteQuarantines = indexHistoricalSqliteSnapshotQuarantineFiles(
      mappings,
      configuredRoots,
    );
    const sqliteSnapshotQuarantine = mappings.length > 0
      ? summarizeHistoricalSqliteSnapshotQuarantineMappings(mappings)
      : undefined;
    const roots: CollectedRoot[] = [];
    for (const definition of input.configuration.roots) {
      roots.push(await collectRoot(definition, cutoffAt, receiptBoundSqliteQuarantines));
    }
    const currentItems = roots.flatMap(({ items }) => items);
    const comparison = classifyDelta(currentItems, baseline.items);
    const deltaByRoot = new Map<string, ClassifiedDeltaItem[]>();
    for (const item of comparison.delta) {
      deltaByRoot.set(item.rootId, [...(deltaByRoot.get(item.rootId) ?? []), item]);
    }
    const rootSummaries = roots.map((root): HistoricalSourceDeltaRootSummary => {
      const delta = deltaByRoot.get(root.definition.id) ?? [];
      return {
        rootId: root.definition.id,
        mode: root.definition.mode,
        status: root.definition.mode !== "history-root" && root.activeSqliteFiles > 0
          ? "blocked_active_sqlite"
          : delta.length > 0 ? "ready" : "no_delta",
        stableCurrentFiles: root.items.length,
        stableDeltaFiles: delta.length,
        stableDeltaBytes: delta.reduce((sum, item) => sum + item.byteSize, 0),
        deferredRecentFiles: root.deferredRecentFiles,
        deferredRecentBytes: root.deferredRecentBytes,
        activeSqliteFiles: root.activeSqliteFiles,
        receiptBoundSqliteFiles: root.receiptBoundSqliteFiles,
        receiptBoundSqliteBytes: root.receiptBoundSqliteBytes,
        policyExcludedFiles: root.policyExcludedFiles,
        unsupportedFiles: root.unsupportedFiles,
        oversizedFiles: root.oversizedFiles,
        vaultProjectionDirectories: root.vaultProjectionDirectories,
        deniedDirectories: root.deniedDirectories,
        categories: aggregateCategories(delta),
      };
    });
    const activeSqliteFiles = rootSummaries.reduce((sum, root) => sum + root.activeSqliteFiles, 0);
    const blockingActiveSqliteFiles = rootSummaries
      .filter(({ mode }) => mode !== "history-root")
      .reduce((sum, root) => sum + root.activeSqliteFiles, 0);
    const deltaCategories = aggregateCategories(comparison.delta);
    const body = {
      schemaVersion: HISTORICAL_SOURCE_DELTA_PLAN_SCHEMA_VERSION,
      dryRun: true as const,
      status: blockingActiveSqliteFiles > 0
        ? "blocked_active_sqlite" as const
        : comparison.delta.length > 0 ? "ready" as const : "no_delta" as const,
      configuration: {
        schemaVersion: input.configuration.schemaVersion,
        version: input.configuration.configurationVersion,
        sha256: input.configurationSha256,
        rootCount: input.configuration.roots.length,
      },
      boundary: { plannedAt, settleSeconds: input.settleSeconds, cutoffAt },
      baseline: {
        completedMigrationCount: baseline.completedMigrationCount,
        sourceObjectCount: baseline.sourceObjectCount,
        inventoryReceiptCount: baseline.inventoryReceiptCount,
        inventoryReceiptSetHash: baseline.inventoryReceiptSetHash,
      },
      current: {
        stableFiles: currentItems.length,
        stableBytes: currentItems.reduce((sum, item) => sum + item.byteSize, 0),
        alreadyImportedFiles: comparison.unchanged,
        deferredRecentFiles: rootSummaries.reduce((sum, root) => sum + root.deferredRecentFiles, 0),
        deferredRecentBytes: rootSummaries.reduce((sum, root) => sum + root.deferredRecentBytes, 0),
        activeSqliteFiles,
        receiptBoundSqliteFiles: rootSummaries.reduce(
          (sum, root) => sum + root.receiptBoundSqliteFiles,
          0,
        ),
        receiptBoundSqliteBytes: rootSummaries.reduce(
          (sum, root) => sum + root.receiptBoundSqliteBytes,
          0,
        ),
        policyExcludedFiles: rootSummaries.reduce((sum, root) => sum + root.policyExcludedFiles, 0),
        unsupportedFiles: rootSummaries.reduce((sum, root) => sum + root.unsupportedFiles, 0),
        oversizedFiles: rootSummaries.reduce((sum, root) => sum + root.oversizedFiles, 0),
        vaultProjectionDirectories: rootSummaries.reduce(
          (sum, root) => sum + root.vaultProjectionDirectories,
          0,
        ),
        deniedDirectories: rootSummaries.reduce((sum, root) => sum + root.deniedDirectories, 0),
        inventoryHash: privateInventoryHash(currentItems),
      },
      delta: {
        files: comparison.delta.length,
        bytes: comparison.delta.reduce((sum, item) => sum + item.byteSize, 0),
        newFiles: comparison.delta.filter(({ disposition }) => disposition === "new").length,
        changedFiles: comparison.delta.filter(({ disposition }) => disposition === "changed").length,
        semanticParserEligibleFiles: comparison.delta.filter(
          ({ parserEligibility }) => parserEligibility === "semantic_parser_eligible",
        ).length,
        custodyOnlyFiles: comparison.delta.filter(
          ({ parserEligibility }) => parserEligibility === "custody_only",
        ).length,
        quarantinedFiles: comparison.delta.filter(
          ({ parserEligibility }) => parserEligibility === "quarantined",
        ).length,
        inventoryHash: privateInventoryHash(comparison.delta),
        categories: deltaCategories,
      },
      roots: rootSummaries,
      ...(sqliteSnapshotQuarantine ? { sqliteSnapshotQuarantine } : {}),
      safety: {
        sourcePathsExposed: false as const,
        sourceContentExposed: false as const,
        canonicalDatabaseOpenedReadOnly: true as const,
        canonicalDatabaseWrites: false as const,
        vaultWrites: false as const,
        sourceWrites: false as const,
        unchangedSourcesRequireReingestion: false as const,
      },
    };
    return {
      publicPlan: { ...body, planHash: hashJson(body) },
      delta: comparison.delta,
    };
  }

  async plan(input: HistoricalSourceDeltaPlannerInput): Promise<HistoricalSourceDeltaPlan> {
    return (await this.prepare(input)).publicPlan;
  }

  async planForExecution(input: HistoricalSourceDeltaPlannerInput): Promise<{
    readonly publicPlan: HistoricalSourceDeltaPlan;
    readonly executionPlan: HistoricalSourceDeltaExecutionPlan;
  }> {
    const prepared = await this.prepare(input);
    if (prepared.publicPlan.status !== "ready") {
      throw new Error(
        prepared.publicPlan.status === "no_delta"
          ? "No stable historical delta exists to seal"
          : "Historical delta contains a blocking active SQLite source and cannot be sealed",
      );
    }
    const admissions: HistoricalSourceDeltaAdmission[] = prepared.delta.map((item) => ({
      rootId: item.rootId,
      path: item.path,
      sourceHash: item.sourceHash,
      byteSize: item.byteSize,
      modifiedAt: item.modifiedAt,
      sourceDevice: item.sourceDevice,
      sourceInode: item.sourceInode,
      classification: item.classification,
      objectKind: item.objectKind,
      parserEligibility: item.parserEligibility,
      sensitivity: item.sensitivity,
      disposition: item.disposition,
    })).sort((left, right) =>
      left.rootId.localeCompare(right.rootId) || left.path.localeCompare(right.path));
    const executionPlan = createHistoricalSourceDeltaExecutionPlan({
      schemaVersion: HISTORICAL_SOURCE_DELTA_EXECUTION_PLAN_SCHEMA_VERSION,
      publicPlanHash: prepared.publicPlan.planHash,
      configuration: {
        schemaVersion: input.configuration.schemaVersion,
        version: input.configuration.configurationVersion,
        sha256: input.configurationSha256,
        roots: input.configuration.roots.map(({ id, path, mode }) => ({ id, path, mode })),
      },
      boundary: prepared.publicPlan.boundary,
      baseline: prepared.publicPlan.baseline,
      delta: {
        files: prepared.publicPlan.delta.files,
        bytes: prepared.publicPlan.delta.bytes,
        inventoryHash: prepared.publicPlan.delta.inventoryHash,
      },
      admissions,
      safety: {
        disclosure: "private_local_only",
        exactPathAdmissionRequired: true,
        revalidateEverySource: true,
        failOnConfigurationDrift: true,
        failOnBaselineDrift: true,
        failOnSourceDrift: true,
        activeWriterAdmission: false,
      },
    });
    return { publicPlan: prepared.publicPlan, executionPlan };
  }
}

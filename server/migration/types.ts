import type { SqliteDatabase } from "../db";
import type { AttackKnowledgeReconciliation } from "./AttackKnowledgeCompiler";
import type { LegacyEngagementManifest } from "./LegacyEngagementDiscovery";
import type { HistoricalSqliteSnapshotQuarantineMapping } from "./HistoricalSqliteSnapshotQuarantineMapping";
import type { HistoricalSourceDeltaExecutionPlan } from "./HistoricalSourceDeltaExecutionPlan";

export const LEGACY_SOURCE_TYPES = [
  "run_json",
  "session_json",
  "event_jsonl",
  "raw_llm_jsonl",
  "dashboard_log",
  "memory_json",
  "training_json",
  "artifact",
  "kanban_sqlite",
  "conversation_state_sqlite",
  "provider_session_json",
  "provider_session_jsonl",
  "provider_log",
  "conversation_markdown",
  "engagement_manifest",
] as const;

export type LegacySourceType = (typeof LEGACY_SOURCE_TYPES)[number];

/**
 * `protected-copy` remains in persisted-schema unions so historical migration
 * rows can be read. New service calls reject it before filesystem access.
 */
export const LEGACY_SOURCE_RETENTION_MODES = ["protected-copy", "verified-reference"] as const;

export type LegacySourceRetentionMode = (typeof LEGACY_SOURCE_RETENTION_MODES)[number];

export const LEGACY_BRAIN_PROJECTION_MODES = ["legacy-engagement", "attack-knowledge-only"] as const;
export type LegacyBrainProjectionMode = (typeof LEGACY_BRAIN_PROJECTION_MODES)[number];

export interface LegacySource {
  readonly absolutePath: string;
  readonly relativePath: string;
  readonly root: string;
  readonly type: LegacySourceType;
  readonly sha256: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
}

export interface DeferredLegacySource {
  readonly absolutePath: string;
  readonly reason:
    | "source modified after the settled-source cutoff; deferred to a later migration"
    | "source was explicitly verified active and deferred to a later migration";
  readonly byteSize: number;
  readonly modifiedAt: string;
  /** Used only to collapse lexical/bind-mount aliases in the private inventory. */
  readonly sourceDevice: number;
  readonly sourceInode: number;
}

export interface SourceInventory {
  readonly included: readonly LegacySource[];
  readonly excluded: readonly {
    absolutePath: string;
    reason: string;
  }[];
  readonly deferred: readonly DeferredLegacySource[];
  /** Aggregate only: no unsupported private pathname enters summary output. */
  readonly coverage: LegacySourceDiscoveryCoverage;
}

export interface LegacySourceDiscoveryCoverage {
  readonly scannedFiles: number;
  readonly scannedBytes: number;
  readonly classifiedFiles: number;
  readonly classifiedBytes: number;
  readonly includedFiles: number;
  readonly includedBytes: number;
  readonly deferredFiles: number;
  readonly deferredBytes: number;
  readonly unsupportedFiles: number;
  readonly unsupportedBytes: number;
  readonly excludedFiles: number;
  readonly excludedBytes: number;
  readonly oversizedFiles: number;
  readonly oversizedBytes: number;
  readonly activeSqliteFiles: number;
  readonly activeSqliteBytes: number;
  /** Exact DB/WAL/SHM files covered by a sealed, empty-snapshot quarantine receipt. */
  readonly receiptBoundSqliteFiles: number;
  readonly receiptBoundSqliteBytes: number;
  readonly vaultProjectionDirectories: number;
  readonly deniedDirectories: number;
}

export interface MigrationCounts {
  readonly sources: number;
  readonly imported: number;
  readonly deduplicated: number;
  readonly quarantined: number;
  readonly skipped: number;
}

export interface AttackKnowledgeExtractionBatchReport {
  readonly status: "completed" | "partial";
  readonly dryRun: boolean;
  readonly manifestFingerprint: string;
  readonly filesDiscovered: number;
  readonly filesParsed: number;
  readonly filesSkipped: number;
  readonly filesQuarantined: number;
  readonly bytesParsed: number;
  readonly semanticFactsParsed: number;
  readonly ambiguousFragments: number;
  readonly compilerBundlesStaged: number;
  readonly candidatesCreated: number;
  readonly candidatesReused: number;
  readonly sourceEvidenceCandidatesCreated: number;
  readonly sourceEvidenceCandidatesReused: number;
  readonly sourceBundleLinks: number;
  /**
   * A dry-run preview may compact many already-accounted cursor pages into one
   * bounded report. Reconciliation uses this value for the original page count
   * while retaining only aggregate counters and issue buckets in memory.
   */
  readonly representedBatchCount?: number;
  /** Present for compiler-backed importers that use bounded deferred reconciliation. */
  readonly compilerReconciliation?: AttackKnowledgeReconciliation;
  readonly compilerReconciliationPasses?: 1;
  readonly compilerRunsReconciled?: number;
  /** Parsed reusable node occurrences by canonical node type (not a unique-node claim). */
  readonly nodeTypeCounts?: Readonly<Record<string, number>>;
  /** Parsed reusable relationship occurrences by canonical edge type (not a unique-edge claim). */
  readonly edgeTypeCounts?: Readonly<Record<string, number>>;
  /** Opaque resume keys. They never contain a path, target, mission, or engagement label. */
  readonly nextResumeAfterSourceKey?: string;
  readonly nextResumeAfterRecordKey?: string;
  /** Opaque source-evidence candidate IDs used to deduplicate reconciliation totals. */
  readonly sourceEvidenceCandidateIds?: readonly string[];
  readonly issues: readonly {
    readonly disposition: "skipped" | "quarantined" | "ambiguous";
    readonly reason: string;
    readonly count?: number;
  }[];
}

export interface AttackKnowledgeExtractionReconciliation {
  readonly mode: "attack-knowledge-only";
  readonly semanticPreview: boolean;
  /** Completed only when the final page for every extractor scope completed. */
  readonly status: "completed" | "partial";
  readonly partialScopeCount: number;
  readonly resumeCursors: readonly {
    readonly manifestFingerprint: string;
    readonly nextResumeAfterSourceKey?: string;
    readonly nextResumeAfterRecordKey?: string;
  }[];
  readonly manifestsParsed: number;
  readonly batchesProcessed: number;
  readonly filesDiscovered: number;
  readonly filesParsed: number;
  readonly filesSkipped: number;
  readonly filesQuarantined: number;
  readonly bytesParsed: number;
  readonly semanticFactsParsed: number;
  readonly ambiguousFragments: number;
  readonly connectedBundlesStaged: number;
  readonly candidatesCreated: number;
  readonly candidatesReused: number;
  readonly sourceEvidenceCandidatesCreated: number;
  readonly sourceEvidenceCandidatesReused: number;
  readonly sourceBundleLinksCreated: number;
  /** Parsed semantic occurrences, grouped by canonical taxonomy type. */
  readonly nodeTypeCounts: Readonly<Record<string, number>>;
  readonly edgeTypeCounts: Readonly<Record<string, number>>;
  /** Immutable generic-source inventory size represented by the first page of each generic scope. */
  readonly genericSourcesDiscovered: number;
  /** Source-page attempts; a large source may appear in more than one bounded page. */
  readonly genericSourcesProcessed: number;
  /** Sources that reached a terminal imported/skipped/quarantined disposition exactly once. */
  readonly genericSourcesCompleted: number;
  readonly genericRecordsProcessed: number;
  readonly genericRecordsQuarantined: number;
  /** Opaque candidate IDs only; private source paths never enter reconciliation output. */
  readonly sourceEvidenceCandidateIds: readonly string[];
  readonly issueCounts: Readonly<Record<string, number>>;
  readonly evidenceAutomaticallyVerified: 0;
  readonly reusableMemoryAutomaticallyPromoted: 0;
}

export interface AttackKnowledgeExtractionHandlerContext {
  readonly dryRun: boolean;
  /** Present for both initial execution and resumed execution. */
  readonly migrationId: string;
  /**
   * Persist one completed extractor page immediately. Callers that execute
   * more than one page must invoke this after each page so a later process
   * interruption cannot erase already-completed reconciliation work.
   * It is a no-op for disposable dry-run previews.
   */
  readonly recordBatch: (report: AttackKnowledgeExtractionBatchReport) => void;
}

export interface SourceMigrationResult {
  readonly source: LegacySource;
  readonly imported: number;
  readonly deduplicated: number;
  readonly quarantined: number;
  readonly skipped: number;
  readonly targetCounts: Readonly<Record<string, number>>;
}

export interface ReconciliationReport {
  readonly migrationId: string;
  readonly dryRun: boolean;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly databasePath: string;
  readonly sourceRoots: readonly string[];
  readonly counts: MigrationCounts;
  readonly targets: Readonly<Record<string, number>>;
  readonly sources: readonly {
    readonly path: string;
    readonly type: LegacySourceType;
    readonly sha256: string;
    readonly bytes: number;
    readonly imported: number;
    readonly deduplicated: number;
    readonly quarantined: number;
    readonly skipped: number;
  }[];
  readonly excluded: readonly { absolutePath: string; reason: string }[];
  readonly settledSourceBoundary?: {
    readonly settleSeconds: number;
    readonly migrationStartedAt: string;
    readonly cutoffAt: string;
    readonly deferredObjects: number;
    readonly deferredBytes: number;
    readonly reason: DeferredLegacySource["reason"];
    readonly deferredReasonCounts: Readonly<Record<DeferredLegacySource["reason"], number>>;
  };
  /** Historical report compatibility only; new migrations never emit this field. */
  readonly databaseBackup?: {
    readonly path: string;
    readonly sha256: string;
  };
  /** Historical report compatibility only; new migrations never emit this field. */
  readonly sourceBackup?: {
    readonly directory: string;
    readonly manifestPath: string;
    readonly quarantineProtection?: {
      readonly verifiedByteCopies: number;
      readonly metadataOnlyDescriptors: number;
      readonly verifiedSourceBytes: number;
      readonly symlinksDereferenced: false;
    };
  };
  readonly sourceRetention: {
    readonly mode: LegacySourceRetentionMode;
    readonly protectedSourceCopyCreated: boolean;
    readonly acknowledgementRequired: boolean;
    readonly referenceOnly?: {
      readonly acceptedObjects: number;
      readonly acceptedBytes: number;
      readonly quarantinedObjects: number;
      readonly quarantinedBytes: number;
      readonly symbolicLinks: number;
      readonly referencedObjects: number;
      readonly referencedBytes: number;
    };
  };
  readonly sourceReferences?: {
    readonly manifestPath: string;
    readonly pathsArePrivateMigrationMetadata: true;
    readonly sourceBytesCopied: false;
  };
  readonly brainProjection: {
    readonly mode: LegacyBrainProjectionMode;
    readonly legacyMissionRunAssetArtifactNodesCreated: boolean;
    readonly acknowledgementRequired: boolean;
  };
  readonly inventoryReceipt: {
    readonly hash: string;
    /** Number of durable verified source-object custody rows represented. */
    readonly objectCount: number;
    /** Sum of byte_size for those custody rows; excludes manifest serialization and non-custodied exclusions. */
    readonly byteCount: number;
  };
  readonly reviewedDeltaExecution?: {
    readonly executionPlanHash: string;
    readonly publicPlanHash: string;
    readonly configurationSha256: string;
    readonly baselineInventoryReceiptSetHash: string;
    readonly admittedFiles: number;
    readonly admittedBytes: number;
    readonly exactPathAdmission: true;
  };
  /** Historical report compatibility only; restore is disabled for new and old reports. */
  readonly rollback?: {
    readonly databaseBackupPath: string;
    readonly databaseBackupSha256: string;
    readonly destinationDatabasePath: string;
    readonly requiresServiceStop: true;
  };
  readonly integrity: {
    readonly verificationStatus: "verified" | "deferred" | "not_applicable";
    readonly quickCheck: readonly string[];
    readonly foreignKeyViolations: number | null;
  };
  readonly warnings: readonly string[];
  readonly engagementDiscovery?: {
    readonly manifests: number;
    readonly classifiedFiles: number;
    readonly classifiedBytes: number;
    readonly quarantinedPaths: number;
    readonly hashAddressedQuarantinedPaths: number;
    readonly quarantinedSourceBytes: number;
    readonly deferredFiles: number;
    readonly deferredBytes: number;
    readonly rootAliases: readonly {
      readonly requestedPath: string;
      readonly canonicalPath: string;
      readonly duplicateOf: string;
    }[];
  };
  readonly genericSourceDiscovery?: LegacySourceDiscoveryCoverage & {
    readonly supplementalHistoryRoots: number;
  };
  readonly sqliteSnapshotQuarantine?: {
    readonly mappings: number;
    readonly sourceFiles: number;
    readonly sourceBytes: number;
    readonly semanticRows: 0;
    readonly mappingSetHash: string;
    readonly disposition: "quarantined_no_semantic_records";
  };
  readonly attackKnowledgeExtraction?: AttackKnowledgeExtractionReconciliation;
}

export interface LegacyMigrationOptions {
  readonly databasePath: string;
  readonly sourceRoots: readonly string[];
  /** Explicit engagement directories that must each import as one mission. */
  readonly engagementRoots?: readonly string[];
  /**
   * Generic-only runtime/provider roots. These are never interpreted as
   * engagement parents and are subject to the canonical 8 MiB per-source
   * semantic ingestion boundary.
   */
  readonly historyRoots?: readonly string[];
  readonly outputDirectory: string;
  readonly dryRun?: boolean;
  readonly resumeMigrationId?: string;
  /**
   * Historical source compatibility only. `verified` is rejected before
   * database or filesystem mutation; omit this option or pass `disabled`.
   */
  readonly databaseBackupMode?: "verified" | "disabled";
  /**
   * Explicit settled-source window. Sources newer than the single migration
   * cutoff are deferred without being read; accepted sources retain all
   * existing exact revalidation gates. Omit to preserve legacy behavior.
   */
  readonly settleSeconds?: number;
  /**
   * Exact regular files that the operator has identified as currently active.
   * On a new run each path must either be newer than the immutable settle
   * cutoff or have an open writable descriptor. The path list is folded into
   * the immutable source-inventory receipt, so a resume must repeat it exactly.
   * This narrow escape hatch is available only to verified-reference,
   * attack-knowledge-only imports with a settled-source window.
   */
  readonly explicitActiveSourceDeferrals?: readonly string[];
  /**
   * Sealed snapshot mappings for exact SQLite DB/WAL/SHM bundles whose
   * normalized, locally inspected schema contains zero semantic records.
   * Mapped bytes are retained only as immutable quarantine custody.
   */
  readonly sqliteSnapshotQuarantineMappings?: readonly HistoricalSqliteSnapshotQuarantineMapping[];
  readonly sqliteSnapshotQuarantineAcknowledged?: boolean;
  /**
   * Private, byte-hash-pinned exact-file admission produced by the read-only
   * delta planner. When present, discovery must inspect only these reviewed
   * paths and must fail closed on configuration, baseline, source, or writer
   * drift before any migration mutation.
   */
  readonly reviewedDeltaExecutionPlan?: HistoricalSourceDeltaExecutionPlan;
  /**
   * Defaults to `verified-reference`. `protected-copy` remains accepted by the
   * type only to read old configuration/schema values and is rejected by every
   * production importer before filesystem access.
   */
  readonly sourceRetention?: LegacySourceRetentionMode;
  /** Explicit `false` rejects the run; omission accepts the operator's global no-copy policy. */
  readonly verifiedReferenceAcknowledged?: boolean;
  /** Defaults to the historical mission/asset projection for compatibility. */
  readonly brainProjectionMode?: LegacyBrainProjectionMode;
  /** Required when intentionally suppressing target-centric Brain projection. */
  readonly attackKnowledgeOnlyAcknowledged?: boolean;
  /** Synchronous canonical candidate extraction after reference inventory and revalidation. */
  readonly attackKnowledgeManifestHandler?: (
    manifest: LegacyEngagementManifest,
    database: SqliteDatabase,
    context: AttackKnowledgeExtractionHandlerContext,
  ) => readonly AttackKnowledgeExtractionBatchReport[] | undefined | void;
  /**
   * Bounded generic runtime/session/log/memory/lesson/SQLite extraction after
   * verified-reference source custody has been registered. The immutable
   * inventory receipt is the resume authority; raw source bytes remain local.
   */
  readonly genericAttackKnowledgeSourceHandler?: (
    input: {
      readonly migrationId: string;
      readonly inventoryReceiptHash: string;
      readonly sources: readonly LegacySource[];
    },
    database: SqliteDatabase,
    context: AttackKnowledgeExtractionHandlerContext,
  ) => readonly AttackKnowledgeExtractionBatchReport[] | undefined | void;
  readonly clock?: () => Date;
}

export interface LegacyMigrationResult {
  readonly migrationId: string;
  readonly report: ReconciliationReport;
  readonly reportPath: string;
}

export interface QuarantineInput {
  readonly sourceSha256: string;
  readonly sourcePath: string;
  readonly itemKey: string;
  readonly itemHash?: string;
  readonly category: string;
  readonly reason: string;
  readonly redactedExcerpt?: string;
  readonly sourceContentSha256?: string;
  readonly byteSize?: number;
  readonly sourceCreatedAt?: string;
  readonly sourceModifiedAt?: string;
  readonly protectedBackupRef?: string;
  readonly protectedBackupSha256?: string;
  readonly backupMode?: "byte_copy" | "metadata_only";
  readonly sourceReference?: string;
  readonly retentionMode?: LegacySourceRetentionMode;
  readonly sourceDevice?: number;
  readonly sourceInode?: number;
}

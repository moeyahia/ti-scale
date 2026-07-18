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
  "engagement_manifest",
] as const;

export type LegacySourceType = (typeof LEGACY_SOURCE_TYPES)[number];

export interface LegacySource {
  readonly absolutePath: string;
  readonly relativePath: string;
  readonly root: string;
  readonly type: LegacySourceType;
  readonly sha256: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
}

export interface SourceInventory {
  readonly included: readonly LegacySource[];
  readonly excluded: readonly {
    absolutePath: string;
    reason: string;
  }[];
}

export interface MigrationCounts {
  readonly sources: number;
  readonly imported: number;
  readonly deduplicated: number;
  readonly quarantined: number;
  readonly skipped: number;
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
  readonly databaseBackup?: {
    readonly path: string;
    readonly sha256: string;
  };
  readonly sourceBackup?: {
    readonly directory: string;
    readonly manifestPath: string;
  };
  readonly rollback?: {
    readonly databaseBackupPath: string;
    readonly databaseBackupSha256: string;
    readonly destinationDatabasePath: string;
    readonly requiresServiceStop: true;
  };
  readonly integrity: {
    readonly quickCheck: readonly string[];
    readonly foreignKeyViolations: number;
  };
  readonly warnings: readonly string[];
  readonly engagementDiscovery?: {
    readonly manifests: number;
    readonly classifiedFiles: number;
    readonly classifiedBytes: number;
    readonly quarantinedPaths: number;
    readonly rootAliases: readonly {
      readonly requestedPath: string;
      readonly canonicalPath: string;
      readonly duplicateOf: string;
    }[];
  };
}

export interface LegacyMigrationOptions {
  readonly databasePath: string;
  readonly sourceRoots: readonly string[];
  /** Explicit engagement directories that must each import as one mission. */
  readonly engagementRoots?: readonly string[];
  readonly outputDirectory: string;
  readonly dryRun?: boolean;
  readonly resumeMigrationId?: string;
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
}

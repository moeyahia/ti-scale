import type {
  MemoryEdgeType,
  MemoryLifecycle,
  MemoryNodeType,
  MemoryScope,
  MemorySensitivity,
} from "../memory/types";
import type { BrainAtlasRegion } from "./AttackBrainAtlasMappingRegistry";
import type { OperatorProfileBrainAtlasClass } from "../../shared/AttackBrainAtlasMappingRegistry";
import type { ReusableKnowledgeOutcomeTag } from "../domain/reusable-knowledge-outcomes";
import type { HistoricalReportedOutcomeSummary } from "../domain/historical-reported-outcomes";

export interface VaultConnection {
  readonly id: string;
  readonly vaultPath: string;
  readonly displayName: string;
  readonly status: "disconnected" | "connecting" | "connected" | "degraded" | "error";
  readonly syncScope: Record<string, unknown>;
  readonly permissionGrantedAt: string;
  readonly lastSyncAt?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface VaultNoteEdge {
  readonly edgeType: MemoryEdgeType;
  readonly targetNodeId: string;
  readonly targetTitle: string;
  readonly wikilink: string;
}

export interface VaultNoteAttachment {
  readonly relativePath: string;
  readonly artifactId?: string;
  readonly contentHash?: string;
}

/**
 * Bounded, integrity-bearing projection of private source custody.
 *
 * The full set remains canonical in SQLite. Obsidian receives only a bounded
 * list of opaque `memory_sources.id` values plus this summary, so a note never
 * grows in proportion to a high-fanout engagement history.
 */
export interface VaultPrivateProvenanceSummary {
  readonly schema: "ti-scale/private-provenance/v1";
  readonly total: number;
  readonly projected: number;
  readonly sha256: string;
  readonly truncated: boolean;
}

export interface VaultNote {
  readonly id: string;
  readonly nodeType: MemoryNodeType;
  /** Portable anatomical classification for attack knowledge or an explicitly
   * consented Operator Profile projection. */
  readonly brainRegion?: BrainAtlasRegion;
  /** Explicit, consent-bound Atlas class for Operator Profile projections. */
  readonly operatorProfileClass?: OperatorProfileBrainAtlasClass;
  readonly lifecycleStatus: MemoryLifecycle;
  readonly scope: MemoryScope;
  readonly sensitivity: MemorySensitivity;
  readonly confidence: number;
  readonly confirmationState: "not_required" | "pending" | "confirmed" | "rejected";
  readonly title: string;
  readonly summary: string;
  readonly body: string;
  readonly authorType: "operator" | "agent" | "system" | "import";
  readonly authorId?: string;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly expiresAt?: string;
  /** Opaque IDs for canonical `memory_sources` rows. Raw mission, target, and
   * evidence locators remain in SQLite and are never copied into reusable
   * attack-knowledge Markdown. */
  readonly privateProvenanceIds: readonly string[];
  /** Present on current managed projections; absent only for legacy notes
   * written before bounded provenance summaries were introduced. */
  readonly privateProvenanceSummary?: VaultPrivateProvenanceSummary;
  readonly sourceIds: readonly string[];
  readonly aliases: readonly string[];
  readonly tags: readonly string[];
  /**
   * Canonical evidence-linked outcomes projected from SQLite. An imported
   * value is descriptive only and cannot create an outcome classification.
   */
  readonly outcomeTags: readonly ReusableKnowledgeOutcomeTag[];
  /** Descriptive historical source claim. Never equivalent to outcomeTags. */
  readonly reportedOutcome?: HistoricalReportedOutcomeSummary;
  readonly edges: readonly VaultNoteEdge[];
  readonly attachments: readonly VaultNoteAttachment[];
}

export interface VaultSyncResult {
  readonly connectionId: string;
  readonly nodeId: string;
  readonly relativePath: string;
  readonly status: "synced" | "database_ahead" | "vault_ahead" | "conflict" | "quarantined";
  readonly conflictId?: string;
  readonly message: string;
}

export interface VaultBulkExportCounts {
  readonly synced: number;
  readonly skipped: number;
  readonly databaseAhead: number;
  readonly vaultAhead: number;
  readonly conflicts: number;
  readonly quarantined: number;
  readonly failed: number;
}

export interface VaultBulkExportIssue {
  readonly nodeId: string;
  readonly category: "database_ahead" | "vault_ahead" | "conflict" | "quarantined" | "failed";
  readonly message: string;
  readonly relativePath?: string;
  readonly conflictId?: string;
}

export interface VaultBulkExportProgress {
  readonly connectionId: string;
  readonly total: number;
  readonly processed: number;
  readonly remaining: number;
  readonly counts: VaultBulkExportCounts;
  readonly elapsedMs: number;
}

export interface VaultBulkExportResult extends VaultBulkExportProgress {
  readonly startedAt: string;
  readonly completedAt: string;
  /** A bounded diagnostic sample; aggregate counts always cover every item. */
  readonly issues: readonly VaultBulkExportIssue[];
  readonly issueSampleTruncated: boolean;
}

export interface VaultBulkExportOptions {
  /** Number of note writes allowed in flight. Defaults to 8; maximum 32. */
  readonly concurrency?: number;
  readonly signal?: AbortSignal;
  /** Progress cadence by completed notes. Defaults to 100. */
  readonly progressInterval?: number;
  readonly onProgress?: (progress: VaultBulkExportProgress) => void | Promise<void>;
}

export interface VaultImportResult {
  readonly relativePath: string;
  readonly status: "candidate" | "updated" | "unchanged" | "quarantined";
  readonly nodeId?: string;
  readonly candidateId?: string;
  readonly quarantinePath?: string;
}

export interface VaultPortableExport {
  readonly connectionId: string;
  readonly archiveName: string;
  readonly archivePath: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly fileCount: number;
  readonly createdAt: string;
  readonly nodeSnapshots: readonly {
    readonly nodeId: string;
    readonly version: number;
    readonly projectionHash: string;
  }[];
  readonly brainAtlasProfile?: {
    readonly pluginId: "brain-atlas";
    readonly version: string;
    readonly configurationSha256: string;
    readonly assetSha256: Readonly<Record<string, string>>;
    readonly mode: "portable-copy";
  };
}

export interface VaultPortableExportOptions {
  /** Include only the verified pinned Brain Atlas plugin/profile in `.obsidian`. */
  readonly includeBrainAtlasProfile?: boolean;
}

export interface VaultSyncVerificationItem {
  readonly relativePath: string;
  readonly nodeId?: string;
  readonly status: "synced" | "database_ahead" | "vault_ahead" | "conflict" | "missing" | "pending" | "quarantined";
}

export interface VaultSyncVerification {
  readonly connectionId: string;
  readonly healthy: boolean;
  readonly checkedAt: string;
  readonly counts: Readonly<Record<VaultSyncVerificationItem["status"], number>>;
  readonly items: readonly VaultSyncVerificationItem[];
}

export type VaultRecoveryOperation = "repair" | "reindex";

export interface VaultRecoveryCounts {
  readonly synced: number;
  readonly databaseAhead: number;
  readonly vaultAhead: number;
  readonly conflictsPreserved: number;
  readonly quarantined: number;
  readonly missing: number;
  readonly pending: number;
  readonly indexed: number;
  readonly skipped: number;
  readonly errors: number;
}

export interface VaultRecoveryIssue {
  readonly category:
    | "conflict_preserved"
    | "malformed_note"
    | "missing_projection"
    | "pending_candidate"
    | "scope_denied"
    | "unsafe_path"
    | "scan_limit"
    | "duplicate_projection"
    | "permission_denied"
    | "concurrent_change"
    | "quarantine_recovery"
    | "processing_error";
  readonly message: string;
  readonly relativePath?: string;
  readonly nodeId?: string;
}

/**
 * A bounded recovery receipt. `processed` includes discovered files and
 * tracked projections that were found missing. The issue list is sampled;
 * aggregate counts always cover the complete bounded operation.
 */
export interface VaultRecoveryResult {
  readonly operation: VaultRecoveryOperation;
  readonly connectionId: string;
  readonly status: "completed" | "partial";
  readonly startedAt: string;
  readonly completedAt: string;
  readonly elapsedMs: number;
  readonly expectedConnectionVersion: string;
  readonly connectionVersion: string;
  readonly health: {
    readonly checkedAt: string;
    readonly checks: { readonly write: true; readonly read: true; readonly rename: true; readonly delete: true };
  };
  readonly progress: {
    readonly discovered: number;
    readonly processed: number;
    readonly remaining: number;
  };
  readonly counts: VaultRecoveryCounts;
  readonly issues: readonly VaultRecoveryIssue[];
  readonly issueSampleTruncated: boolean;
  readonly message: string;
}

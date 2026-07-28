import { randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { checkDatabaseIntegrity, inImmediateTransaction, type SqliteDatabase } from "../db";
import type {
  CanonicalDatabaseLeaseHandle,
  CanonicalDatabaseLeaseService,
} from "../maintenance";
import { CanonicalDatabaseLeaseService as LeaseService } from "../maintenance";
import { canonicalJson, sha256 } from "../intelligence-v24/validation";
import type { JsonValue } from "../intelligence-v24/types";
import { HistoricalAttackKnowledgeExtractionReconciliationService } from
  "./HistoricalAttackKnowledgeExtractionReconciliationService";
import { detectActiveLegacyMigrationProcessIds } from "./FailedLegacyMigrationReconciliationService";
import type { AttackKnowledgeExtractionReconciliation } from "./types";

export const POST_EXTRACTION_INVENTORY_DRIFT_ERROR =
  "Resume source inventory hash/size/mtime receipt does not match the original job";

interface MigrationRow {
  readonly id: string;
  readonly status: string;
  readonly source_roots_json: string;
  readonly database_path: string;
  readonly output_directory: string;
  readonly reconciliation_path: string | null;
  readonly source_retention: string;
  readonly source_retention_acknowledged_at: string | null;
  readonly brain_projection_mode: string;
  readonly brain_projection_acknowledged_at: string | null;
  readonly error_summary: string | null;
  readonly started_at: string;
  readonly completed_at: string | null;
}

interface ActiveLeaseRow {
  readonly id: string;
  readonly operation: string;
}

interface ExtractionBatchRow {
  readonly extractor_kind: "manifest" | "generic";
  readonly scope_key: string;
  readonly page_key: string;
  readonly sequence: number;
  readonly report_json: string;
  readonly report_hash: string;
}

interface ExtractionBatchDocument {
  readonly status?: unknown;
  readonly dryRun?: unknown;
  readonly manifestFingerprint?: unknown;
  readonly nextResumeAfterSourceKey?: unknown;
  readonly nextResumeAfterRecordKey?: unknown;
}

export interface CompletedHistoricalExtractionSealPreview {
  readonly schemaVersion: "ti_scale.completed_historical_extraction_seal_preview/v1";
  readonly migrationId: string;
  readonly statusBefore: "failed";
  readonly originalFailure: string;
  readonly startedAt: string;
  readonly failedAt: string;
  readonly sourceRoots: readonly string[];
  readonly inventory: {
    readonly receiptHash: string;
    readonly objectCount: number;
    readonly byteCount: number;
    readonly sourceCount: number;
    readonly completedSourceCount: number;
  };
  readonly extraction: AttackKnowledgeExtractionReconciliation;
  readonly integrity: {
    readonly quickCheck: readonly string[];
    readonly foreignKeyViolations: 0;
    readonly extractionBatchCount: number;
    readonly extractionScopeCount: number;
    readonly sourceCandidateReceiptCount: number;
    readonly sourceCandidateOccurrenceCount: number;
    readonly receiptOnlySourceCandidateCount: number;
    readonly occurrenceOnlySourceCandidateCount: number;
    readonly reconciledSourceCandidateCount: number;
    readonly occurrenceLedgerProofRowCount: number;
    readonly occurrenceLedgerProofHash: string;
  };
  readonly reportPath: string;
  readonly semanticKnowledgeChanged: false;
  readonly sourceBytesCopied: false;
  readonly currentSourceInventoryReused: false;
  readonly previewHash: string;
}

export interface CompletedHistoricalExtractionSealResult {
  readonly status: "sealed";
  readonly migrationId: string;
  readonly reportPath: string;
  readonly reportHash: string;
  readonly inventoryReceiptHash: string;
  readonly auditRecordId: string;
  readonly auditRecordHash: string;
  readonly previewHash: string;
  readonly completedAt: string;
}

export interface CompletedHistoricalExtractionSealServiceOptions {
  readonly clock?: () => Date;
  readonly createId?: () => string;
  readonly activeMigrationProcessIds?: () => readonly number[];
}

function boundedText(value: string, label: string, maximum: number): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new TypeError(`${label} must contain 1 to ${maximum} printable characters`);
  }
  return normalized;
}

function identifier(value: string, label: string): string {
  const normalized = boundedText(value, label, 256);
  if (!/^[a-z0-9][a-z0-9_.:-]*$/iu.test(normalized)) {
    throw new TypeError(`${label} contains unsupported characters`);
  }
  return normalized;
}

function isoTimestamp(value: string | null, label: string): string {
  if (!value || !Number.isFinite(Date.parse(value))) throw new Error(`${label} is not a valid timestamp`);
  return new Date(value).toISOString();
}

function sourceRoots(value: string): readonly string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.some((entry) => typeof entry !== "string" || !entry.trim())) {
    throw new Error("Migration source-root receipt is invalid");
  }
  return Object.freeze(parsed.map((entry) => resolve(entry as string)).sort());
}

function migrationLeaseOperation(operation: string): boolean {
  return /(?:historical|legacy).*(?:import|migration)|(?:import|migration).*(?:historical|legacy)/iu.test(operation);
}

function inside(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`) && !path.startsWith(sep));
}

function reportPath(outputDirectory: string, migrationId: string): string {
  const output = resolve(outputDirectory);
  const outputState = lstatSync(output);
  if (!outputState.isDirectory() || outputState.isSymbolicLink()) {
    throw new Error("Migration output directory must be an existing non-link directory");
  }
  const canonicalOutput = realpathSync(output);
  const migrationDirectory = join(canonicalOutput, migrationId);
  const migrationState = lstatSync(migrationDirectory);
  if (!migrationState.isDirectory() || migrationState.isSymbolicLink()) {
    throw new Error("Migration receipt directory must be an existing non-link directory");
  }
  const canonicalMigrationDirectory = realpathSync(migrationDirectory);
  if (!inside(canonicalOutput, canonicalMigrationDirectory) || basename(canonicalMigrationDirectory) !== migrationId) {
    throw new Error("Migration receipt directory escaped its recorded output root");
  }
  return join(canonicalMigrationDirectory, "sealed-extraction-reconciliation.json");
}

function atomicPublish(path: string, content: string): void {
  if (existsSync(path)) {
    const state = lstatSync(path);
    if (state.isSymbolicLink() || !state.isFile() || readFileSync(path, "utf8") !== content) {
      throw new Error("Existing sealed extraction report does not match the reviewed receipt");
    }
    return;
  }
  const directory = dirname(path);
  const temporary = join(directory, `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    writeFileSync(descriptor, content, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    // A hard-link publish is atomic and refuses to replace an unexpected file.
    linkSync(temporary, path);
    unlinkSync(temporary);
    chmodSync(path, 0o600);
    const directoryDescriptor = openSync(directory, constants.O_RDONLY);
    try { fsyncSync(directoryDescriptor); } finally { closeSync(directoryDescriptor); }
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    rmSync(temporary, { force: true });
    throw error;
  }
}

/**
 * Seal an extraction that durably completed before the coordinator's final
 * live-tree rescan detected inventory drift. This operation never reads the
 * current source tree, creates knowledge, changes candidate state, or adopts
 * facts into another migration. It only makes the already receipt-bound run
 * eligible for the existing independent confirmation workflow.
 */
export class CompletedHistoricalExtractionSealService {
  readonly #clock: () => Date;
  readonly #createId: () => string;
  readonly #activeMigrationProcessIds: () => readonly number[];

  constructor(
    readonly database: SqliteDatabase,
    options: CompletedHistoricalExtractionSealServiceOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#createId = options.createId ?? (() => `audit_migration_extraction_seal_${randomUUID()}`);
    this.#activeMigrationProcessIds = options.activeMigrationProcessIds
      ?? (() => detectActiveLegacyMigrationProcessIds());
    if (!LeaseService.schemaAvailable(database)) {
      throw new Error("Completed extraction sealing requires canonical database migration 35");
    }
  }

  preview(input: { readonly migrationId: string }): CompletedHistoricalExtractionSealPreview {
    const active = this.#activeMigrationProcessIds();
    if (active.length > 0) throw new Error(`A legacy migration process is still active (${active.join(", ")})`);
    return this.#preview(identifier(input.migrationId, "Migration ID"), null);
  }

  seal(
    input: {
      readonly migrationId: string;
      readonly expectedPreviewHash: string;
      readonly actorId: string;
      readonly reason: string;
      readonly acknowledged: boolean;
    },
    authority: {
      readonly handle: CanonicalDatabaseLeaseHandle;
      readonly leases: CanonicalDatabaseLeaseService;
    },
  ): CompletedHistoricalExtractionSealResult {
    if (!input.acknowledged) throw new Error("Completed extraction sealing requires explicit acknowledgement");
    if (!/^[a-f0-9]{64}$/u.test(input.expectedPreviewHash)) {
      throw new TypeError("Expected preview hash must be a lowercase SHA-256 digest");
    }
    const migrationId = identifier(input.migrationId, "Migration ID");
    const actorId = identifier(input.actorId, "Actor ID");
    const reason = boundedText(input.reason, "Seal reason", 1_000);
    const active = this.#activeMigrationProcessIds();
    if (active.length > 0) throw new Error(`A legacy migration process is still active (${active.join(", ")})`);

    return inImmediateTransaction(this.database, () => {
      authority.leases.assertActiveInCurrentTransaction(authority.handle);
      if (authority.handle.mode !== "writer") throw new Error("A canonical writer lease is required");
      const preview = this.#preview(migrationId, authority.handle.id);
      if (preview.previewHash !== input.expectedPreviewHash) {
        throw new Error("Completed extraction seal preview changed; review the current proof before retrying");
      }
      const report = {
        schemaVersion: "ti_scale.completed_historical_extraction_seal/v1",
        migrationId,
        disposition: "completed_from_durable_extraction_receipts",
        originalFailure: preview.originalFailure,
        startedAt: preview.startedAt,
        failedAt: preview.failedAt,
        sourceRoots: preview.sourceRoots,
        inventory: preview.inventory,
        extraction: preview.extraction,
        integrity: preview.integrity,
        semanticKnowledgeChanged: false,
        sourceBytesCopied: false,
        currentSourceInventoryReused: false,
        warning: "The live source inventory drifted after extraction. This report seals only the immutable captured receipt; later source changes require a separate catch-up migration.",
      } as const;
      const reportJson = canonicalJson(report as unknown as JsonValue);
      const reportHash = sha256(reportJson);
      atomicPublish(preview.reportPath, `${reportJson}\n`);

      const completedAt = this.#clock().toISOString();
      this.database.prepare(`
        INSERT INTO legacy_migration_reconciliation (
          migration_id, report_json, report_hash, created_at
        ) VALUES (?, ?, ?, ?)
      `).run(migrationId, reportJson, reportHash, completedAt);

      const previous = this.database.prepare(
        "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
      ).get() as { readonly record_hash: string } | undefined;
      const auditRecordId = this.#createId();
      const details = {
        migrationId,
        previewHash: preview.previewHash,
        reconciliationHash: reportHash,
        inventoryReceiptHash: preview.inventory.receiptHash,
        originalFailure: preview.originalFailure,
        originalFailedAt: preview.failedAt,
        sourceCount: preview.inventory.sourceCount,
        sourceObjectCount: preview.inventory.objectCount,
        extractionBatchCount: preview.integrity.extractionBatchCount,
        semanticFactCount: preview.extraction.semanticFactsParsed,
        candidateCount: preview.integrity.reconciledSourceCandidateCount,
        semanticKnowledgeChanged: false,
        sourceBytesCopied: false,
        currentSourceInventoryReused: false,
      } as const;
      const hashBody = {
        id: auditRecordId,
        actorType: "operator",
        actorId,
        action: "legacy_migration.completed_extraction_sealed",
        resourceType: "data_migration",
        resourceId: migrationId,
        reason,
        details,
        previousHash: previous?.record_hash ?? null,
        occurredAt: completedAt,
      } as const;
      const auditRecordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(hashBody)}`);
      this.database.prepare(`
        INSERT INTO audit_records (
          id, actor_type, actor_id, action, resource_type, resource_id,
          reason, details_json, previous_hash, record_hash, occurred_at
        ) VALUES (?, 'operator', ?, 'legacy_migration.completed_extraction_sealed',
          'data_migration', ?, ?, ?, ?, ?, ?)
      `).run(
        auditRecordId,
        actorId,
        migrationId,
        reason,
        canonicalJson(details),
        previous?.record_hash ?? null,
        auditRecordHash,
        completedAt,
      );
      const update = this.database.prepare(`
        UPDATE legacy_migration_runs
        SET status = 'completed', reconciliation_path = ?, completed_at = ?
        WHERE id = ? AND status = 'failed' AND error_summary = ?
      `).run(preview.reportPath, completedAt, migrationId, POST_EXTRACTION_INVENTORY_DRIFT_ERROR);
      if (update.changes !== 1) throw new Error("Failed migration state changed during extraction sealing");
      authority.leases.assertActiveInCurrentTransaction(authority.handle);
      return Object.freeze({
        status: "sealed" as const,
        migrationId,
        reportPath: preview.reportPath,
        reportHash,
        inventoryReceiptHash: preview.inventory.receiptHash,
        auditRecordId,
        auditRecordHash,
        previewHash: preview.previewHash,
        completedAt,
      });
    });
  }

  #preview(migrationId: string, ignoredLeaseId: string | null): CompletedHistoricalExtractionSealPreview {
    this.#assertNoActiveMigrationLease(ignoredLeaseId);
    const migration = this.database.prepare(`
      SELECT id, status, source_roots_json, database_path, output_directory,
        reconciliation_path, source_retention, source_retention_acknowledged_at,
        brain_projection_mode, brain_projection_acknowledged_at, error_summary,
        started_at, completed_at
      FROM legacy_migration_runs WHERE id = ?
    `).get(migrationId) as MigrationRow | undefined;
    if (!migration || migration.status !== "failed") throw new Error("Migration is not terminal failed");
    if (migration.error_summary?.trim() !== POST_EXTRACTION_INVENTORY_DRIFT_ERROR) {
      throw new Error("Failed migration was not terminated by the exact post-extraction inventory-drift guard");
    }
    if (migration.source_retention !== "verified-reference" ||
        migration.brain_projection_mode !== "attack-knowledge-only" ||
        !migration.source_retention_acknowledged_at || !migration.brain_projection_acknowledged_at) {
      throw new Error("Failed migration does not have the acknowledged verified-reference attack-knowledge contract");
    }
    if (migration.reconciliation_path || this.database.prepare(`
      SELECT 1 AS present FROM legacy_migration_reconciliation WHERE migration_id = ?
    `).get(migrationId)) {
      throw new Error("Failed migration already has a reconciliation receipt");
    }
    const startedAt = isoTimestamp(migration.started_at, "Migration start");
    const failedAt = isoTimestamp(migration.completed_at, "Migration failure");
    if (Date.parse(failedAt) < Date.parse(startedAt)) throw new Error("Migration failure predates its start");

    const receipt = this.database.prepare(`
      SELECT receipt_hash, object_count, byte_count
      FROM legacy_migration_inventory_receipts WHERE migration_id = ?
    `).get(migrationId) as {
      readonly receipt_hash: string;
      readonly object_count: number;
      readonly byte_count: number;
    } | undefined;
    if (!receipt || !/^[a-f0-9]{64}$/u.test(receipt.receipt_hash) ||
        !Number.isSafeInteger(Number(receipt.object_count)) || Number(receipt.object_count) < 1 ||
        !Number.isSafeInteger(Number(receipt.byte_count)) || Number(receipt.byte_count) < 0) {
      throw new Error("Failed migration lacks a valid immutable inventory receipt");
    }
    const source = this.database.prepare(`
      SELECT COUNT(*) AS total,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
        SUM(CASE WHEN status != 'completed' THEN 1 ELSE 0 END) AS incomplete
      FROM legacy_migration_sources WHERE migration_id = ?
    `).get(migrationId) as { readonly total: number; readonly completed: number; readonly incomplete: number };
    if (Number(source.total) < 1 || Number(source.completed) !== Number(source.total) || Number(source.incomplete) !== 0) {
      throw new Error("Failed migration has incomplete or failed source-custody rows");
    }
    const objects = this.database.prepare(`
      SELECT COUNT(*) AS total, COALESCE(SUM(byte_size), 0) AS bytes,
        SUM(CASE WHEN verification_status = 'verified_reference'
          AND source_reference GLOB 'legacy-private-source://*' THEN 1 ELSE 0 END) AS verified
      FROM legacy_migration_source_objects WHERE migration_id = ?
    `).get(migrationId) as { readonly total: number; readonly bytes: number; readonly verified: number };
    if (Number(objects.total) !== Number(receipt.object_count) ||
        Number(objects.bytes) !== Number(receipt.byte_count) ||
        Number(objects.verified) !== Number(objects.total)) {
      throw new Error("Failed migration source custody no longer matches its immutable inventory receipt");
    }
    const missingGenericCustody = this.database.prepare(`
      SELECT COUNT(*) AS count
      FROM legacy_migration_sources source
      WHERE source.migration_id = ? AND source.source_type != 'engagement_manifest'
        AND NOT EXISTS (
          SELECT 1 FROM legacy_migration_source_objects object
          WHERE object.migration_id = source.migration_id
            AND object.source_id = source.id
            AND object.object_key = 'source'
            AND object.object_kind = 'source'
            AND object.source_path = source.source_path
            AND object.source_sha256 = source.source_sha256
            AND object.byte_size = source.byte_size
            AND object.modified_at = source.modified_at
            AND object.source_device = source.source_device
            AND object.source_inode = source.source_inode
            AND object.verification_status = 'verified_reference'
        )
    `).get(migrationId) as { readonly count: number };
    const emptyManifestCustody = this.database.prepare(`
      SELECT COUNT(*) AS count
      FROM legacy_migration_sources source
      WHERE source.migration_id = ? AND source.source_type = 'engagement_manifest'
        AND NOT EXISTS (
          SELECT 1 FROM legacy_migration_source_objects object
          WHERE object.migration_id = source.migration_id
            AND object.source_id = source.id
            AND object.verification_status = 'verified_reference'
        )
    `).get(migrationId) as { readonly count: number };
    if (Number(missingGenericCustody.count) !== 0 || Number(emptyManifestCustody.count) !== 0) {
      throw new Error("Failed migration has a source row without its exact verified-reference object custody");
    }
    const context = this.database.prepare(`
      SELECT context.mission_id, context.run_id
      FROM historical_attack_knowledge_import_contexts context
      JOIN missions mission ON mission.id = context.mission_id
      JOIN runs run ON run.id = context.run_id AND run.mission_id = mission.id
      WHERE context.migration_id = ?
    `).all(migrationId) as Array<{ readonly mission_id: string; readonly run_id: string }>;
    if (context.length !== 1) throw new Error("Failed migration lacks one durable attack-knowledge import context");

    const ledger = this.#validateExtractionLedger(migrationId, failedAt);
    const extraction = new HistoricalAttackKnowledgeExtractionReconciliationService(this.database)
      .reconcile(migrationId, false);
    if (extraction.status !== "completed" || extraction.partialScopeCount !== 0 || extraction.resumeCursors.length !== 0) {
      throw new Error("Failed migration extraction is not durably complete");
    }
    const occurrenceIds = (this.database.prepare(`
      SELECT DISTINCT candidate_id AS id
      FROM historical_attack_knowledge_source_occurrences
      WHERE migration_id = ? ORDER BY candidate_id
    `).all(migrationId) as Array<{ readonly id: string }>).map(({ id }) => id);
    const receiptIds = [...extraction.sourceEvidenceCandidateIds].sort();
    const occurrenceSet = new Set(occurrenceIds);
    const receiptSet = new Set(receiptIds);
    const receiptOnlyIds = receiptIds.filter((id) => !occurrenceSet.has(id));
    const occurrenceOnlyIds = occurrenceIds.filter((id) => !receiptSet.has(id));
    const reconciledCandidateIds = [...new Set([...receiptIds, ...occurrenceIds])].sort();
    const registeredReceiptIds = (this.database.prepare(`
      SELECT candidate_id AS id FROM historical_attack_knowledge_source_candidates
      WHERE candidate_id IN (SELECT value FROM json_each(?)) ORDER BY candidate_id
    `).all(JSON.stringify(reconciledCandidateIds)) as Array<{ readonly id: string }>).map(({ id }) => id);
    if (canonicalJson(registeredReceiptIds) !== canonicalJson(reconciledCandidateIds)) {
      throw new Error("Extraction candidate ledger references an unavailable source-candidate registry row");
    }
    const invalidOccurrenceCustody = this.database.prepare(`
      SELECT COUNT(*) AS count
      FROM historical_attack_knowledge_source_occurrences occurrence
      WHERE occurrence.migration_id = ? AND NOT EXISTS (
        SELECT 1 FROM legacy_migration_source_objects object
        WHERE object.migration_id = occurrence.migration_id
          AND object.source_reference = occurrence.source_reference
          AND object.source_sha256 = occurrence.source_hash
          AND object.verification_status = 'verified_reference'
      )
    `).get(migrationId) as { readonly count: number };
    if (Number(invalidOccurrenceCustody.count) !== 0) {
      throw new Error("Extraction source-candidate occurrence lacks exact verified-reference custody");
    }
    const occurrenceLedgerProofRows = occurrenceOnlyIds.length === 0 ? [] : this.database.prepare(`
      SELECT DISTINCT
        occurrence.candidate_id,
        occurrence.source_reference,
        occurrence.source_hash,
        occurrence.modified_at,
        occurrence.observed_at,
        source_candidate.byte_size AS candidate_byte_size,
        source_object.id AS source_object_id,
        source_object.source_id,
        source_object.byte_size AS source_object_byte_size,
        source_object.source_device,
        source_object.source_inode,
        source_binding.bundle_id,
        source_binding.receipt_id,
        source_binding.binding_hash,
        source_binding.linked_at AS binding_linked_at,
        provenance.source_hash AS provenance_source_hash,
        provenance.evidence_count AS provenance_evidence_count,
        provenance.created_at AS provenance_created_at,
        compiler.id AS compiler_run_id,
        compiler.request_fingerprint,
        compiler.status AS compiler_status,
        compiler.checkpoint_ordinal,
        compiler.reconciliation_json,
        compiler.completed_at AS compiler_completed_at,
        migration_item.id AS migration_item_id,
        migration_item.item_key,
        migration_item.item_hash,
        migration_item.status AS migration_item_status,
        migration_item.created_at AS migration_item_created_at
      FROM historical_attack_knowledge_source_occurrences occurrence
      JOIN historical_attack_knowledge_source_candidates source_candidate
        ON source_candidate.candidate_id = occurrence.candidate_id
        AND source_candidate.source_hash = occurrence.source_hash
      JOIN evidence_candidates evidence_candidate
        ON evidence_candidate.id = occurrence.candidate_id
        AND evidence_candidate.state = 'candidate'
        AND evidence_candidate.sensitivity = 'private'
        AND evidence_candidate.proposed_by = 'system:historical-attack-knowledge-extractor'
        AND evidence_candidate.observation_id IS NULL
        AND evidence_candidate.artifact_id IS NULL
      JOIN legacy_migration_source_objects source_object
        ON source_object.migration_id = occurrence.migration_id
        AND source_object.source_reference = occurrence.source_reference
        AND source_object.source_sha256 = occurrence.source_hash
        AND source_object.byte_size = source_candidate.byte_size
        AND source_object.modified_at = occurrence.modified_at
        AND source_object.verification_status = 'verified_reference'
      JOIN historical_attack_knowledge_bundle_sources source_binding
        ON source_binding.candidate_id = occurrence.candidate_id
        AND source_binding.source_hash = occurrence.source_hash
      JOIN attack_knowledge_bundle_receipts bundle_receipt
        ON bundle_receipt.bundle_id = source_binding.bundle_id
        AND bundle_receipt.receipt_id = source_binding.receipt_id
      JOIN attack_knowledge_provenance_receipts provenance
        ON provenance.id = source_binding.receipt_id
        AND provenance.source_class = 'historical'
      JOIN attack_knowledge_compiler_runs compiler
        ON compiler.bundle_id = source_binding.bundle_id
        AND compiler.receipt_id = source_binding.receipt_id
        AND compiler.source_class = 'historical'
        AND compiler.status IN ('staged', 'materialized')
        AND compiler.completed_at IS NOT NULL
      JOIN legacy_migration_items migration_item
        ON migration_item.migration_id = occurrence.migration_id
        AND migration_item.source_id = source_object.source_id
        AND migration_item.source_sha256 = occurrence.source_hash
        AND migration_item.target_table = 'attack_knowledge_bundles'
        AND migration_item.target_id = source_binding.bundle_id
        AND migration_item.status IN ('imported', 'deduplicated')
      WHERE occurrence.migration_id = ?
        AND occurrence.candidate_id IN (SELECT value FROM json_each(?))
        AND julianday(occurrence.observed_at) IS NOT NULL
        AND julianday(occurrence.observed_at) <= julianday(?)
        AND julianday(source_binding.linked_at) IS NOT NULL
        AND julianday(source_binding.linked_at) <= julianday(?)
        AND julianday(provenance.created_at) IS NOT NULL
        AND julianday(provenance.created_at) <= julianday(?)
        AND julianday(compiler.completed_at) IS NOT NULL
        AND julianday(compiler.completed_at) <= julianday(?)
        AND julianday(migration_item.created_at) IS NOT NULL
        AND julianday(migration_item.created_at) <= julianday(?)
      ORDER BY occurrence.candidate_id, source_binding.bundle_id,
        source_binding.receipt_id, compiler.id, migration_item.id
    `).all(
      migrationId,
      JSON.stringify(occurrenceOnlyIds),
      failedAt,
      failedAt,
      failedAt,
      failedAt,
      failedAt,
    ) as Array<Record<string, string | number>>;
    const provenOccurrenceOnlyIds = [...new Set(
      occurrenceLedgerProofRows.map((row) => String(row.candidate_id)),
    )].sort();
    if (canonicalJson(provenOccurrenceOnlyIds) !== canonicalJson(occurrenceOnlyIds)) {
      throw new Error(
        "Extraction occurrence absent from the batch receipt lacks a complete immutable source-and-bundle proof chain",
      );
    }
    const occurrenceLedgerProofHash = sha256(
      canonicalJson(occurrenceLedgerProofRows as unknown as JsonValue),
    );
    const integrityResult = checkDatabaseIntegrity(this.database);
    const foreignKeyViolations = this.database.pragma("foreign_key_check") as unknown[];
    if (!integrityResult.ok || foreignKeyViolations.length !== 0) {
      throw new Error("Canonical database integrity does not permit extraction sealing");
    }
    const unsigned = {
      schemaVersion: "ti_scale.completed_historical_extraction_seal_preview/v1" as const,
      migrationId,
      statusBefore: "failed" as const,
      originalFailure: migration.error_summary.trim(),
      startedAt,
      failedAt,
      sourceRoots: sourceRoots(migration.source_roots_json),
      inventory: {
        receiptHash: receipt.receipt_hash,
        objectCount: Number(receipt.object_count),
        byteCount: Number(receipt.byte_count),
        sourceCount: Number(source.total),
        completedSourceCount: Number(source.completed),
      },
      extraction,
      integrity: {
        quickCheck: Object.freeze([...integrityResult.messages]),
        foreignKeyViolations: 0 as const,
        extractionBatchCount: ledger.batchCount,
        extractionScopeCount: ledger.scopeCount,
        sourceCandidateReceiptCount: receiptIds.length,
        sourceCandidateOccurrenceCount: occurrenceIds.length,
        receiptOnlySourceCandidateCount: receiptOnlyIds.length,
        occurrenceOnlySourceCandidateCount: occurrenceOnlyIds.length,
        reconciledSourceCandidateCount: reconciledCandidateIds.length,
        occurrenceLedgerProofRowCount: occurrenceLedgerProofRows.length,
        occurrenceLedgerProofHash,
      },
      reportPath: reportPath(migration.output_directory, migrationId),
      semanticKnowledgeChanged: false as const,
      sourceBytesCopied: false as const,
      currentSourceInventoryReused: false as const,
    };
    return Object.freeze({
      ...unsigned,
      previewHash: sha256(canonicalJson(unsigned as unknown as JsonValue)),
    });
  }

  #validateExtractionLedger(migrationId: string, failedAt: string): {
    readonly batchCount: number;
    readonly scopeCount: number;
  } {
    const query = this.database.prepare(`
      SELECT extractor_kind, scope_key, page_key, sequence, report_json, report_hash
      FROM legacy_migration_extraction_batches
      WHERE migration_id = ? ORDER BY extractor_kind, scope_key, sequence
    `);
    const expected = new Map<string, number>();
    const latest = new Map<string, "completed" | "partial">();
    let batchCount = 0;
    for (const row of query.iterate(migrationId) as IterableIterator<ExtractionBatchRow>) {
      batchCount += 1;
      if (sha256(row.report_json) !== row.report_hash) throw new Error("Extraction batch report hash mismatch");
      let document: ExtractionBatchDocument;
      try { document = JSON.parse(row.report_json) as ExtractionBatchDocument; }
      catch { throw new Error("Extraction batch report is malformed JSON"); }
      if ((document.status !== "completed" && document.status !== "partial") || document.dryRun !== false ||
          document.manifestFingerprint !== row.scope_key) {
        throw new Error("Extraction batch report violates its immutable scope contract");
      }
      const scope = `${row.extractor_kind}\0${row.scope_key}`;
      const nextSequence = (expected.get(scope) ?? 0) + 1;
      if (Number(row.sequence) !== nextSequence) throw new Error("Extraction batch sequence is not contiguous");
      expected.set(scope, nextSequence);
      const pageIdentity = JSON.stringify({
        status: document.status,
        nextResumeAfterSourceKey: document.nextResumeAfterSourceKey ?? null,
        nextResumeAfterRecordKey: document.nextResumeAfterRecordKey ?? null,
      });
      if (sha256(pageIdentity) !== row.page_key) throw new Error("Extraction batch page identity hash mismatch");
      latest.set(scope, document.status);
    }
    if (batchCount < 1 || latest.size < 1 || [...latest.values()].some((status) => status !== "completed")) {
      throw new Error("Extraction batch ledger has no completed terminal page for every scope");
    }
    const lateBatch = this.database.prepare(`
      SELECT 1 AS present FROM legacy_migration_extraction_batches
      WHERE migration_id = ? AND julianday(created_at) > julianday(?) LIMIT 1
    `).get(migrationId, failedAt);
    if (lateBatch) throw new Error("Extraction receipt was appended after the migration failed");
    return { batchCount, scopeCount: latest.size };
  }

  #assertNoActiveMigrationLease(ignoredLeaseId: string | null): void {
    const now = this.#clock().toISOString();
    const rows = this.database.prepare(`
      SELECT id, operation FROM canonical_database_leases
      WHERE released_at IS NULL AND julianday(expires_at) > julianday(?)
      ORDER BY id
    `).all(now) as ActiveLeaseRow[];
    const conflicting = rows.filter((row) => row.id !== ignoredLeaseId && migrationLeaseOperation(row.operation));
    if (conflicting.length > 0) {
      throw new Error(`An active canonical migration lease remains (${conflicting.map((row) => row.id).join(", ")})`);
    }
  }
}

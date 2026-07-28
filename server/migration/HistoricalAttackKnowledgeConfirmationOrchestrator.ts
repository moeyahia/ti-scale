import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { canonicalJson, hashJson } from "../orchestration/serialization";
import {
  HistoricalAttackKnowledgeConfirmationService,
  normalizeHistoricalCandidateConfirmationInput,
  type HistoricalCandidateConfirmationPreview,
  type HistoricalCandidateConfirmationReconciliation,
  type HistoricalCandidateConfirmationResult,
} from "./HistoricalAttackKnowledgeConfirmationService";

const SHA256 = /^[a-f0-9]{64}$/u;
const DEFAULT_PAGE_SIZE = 500;
const DEFAULT_MAX_PAGES = 100;
const MAX_PAGES_PER_INVOCATION = 1_000;
const LEASE_DURATION_MS = 15 * 60 * 1_000;
const POLICY_VERSION = "historical-safe-candidate-confirmation-all-pages-v1" as const;
const RECEIPT_SCHEMA = "ti_scale.historical_attack_confirmation_all_pages/v1" as const;

interface PersistedReceiptRow {
  readonly value_json: string;
  readonly version: number;
}

export interface HistoricalConfirmationAllPagesTotals {
  readonly selectedCount: number;
  readonly confirmedCount: number;
  readonly alreadyConfirmedCount: number;
  readonly suppressedCount: number;
  readonly preservedOperatorRejectionCount: number;
  readonly edgesCreated: number;
  readonly edgesAlreadyPresent: number;
  readonly edgesDeferred: number;
  readonly provenanceBindingsCreated: number;
  readonly provenanceBindingsAlreadyPresent: number;
  readonly unlinkedCandidateCount: number;
}

export interface HistoricalConfirmationAllPagesLastPage {
  readonly pageNumber: number;
  readonly selectionCursor: string | null;
  readonly previewHash: string;
  readonly auditRecordId: string;
  readonly executionStatus: "completed" | "replayed";
  readonly selectedCount: number;
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string;
}

export interface HistoricalConfirmationAllPagesReceipt {
  readonly schemaVersion: typeof RECEIPT_SCHEMA;
  readonly policyVersion: typeof POLICY_VERSION;
  readonly operationId: string;
  readonly migrationId: string;
  readonly inventoryReceiptHash: string;
  readonly actorId: string;
  readonly reason: string;
  readonly pageSize: number;
  readonly status: "in_progress" | "completed";
  readonly nextSelectionCursor: string | null;
  readonly pagesCompleted: number;
  readonly pageChainHash: string;
  readonly totals: HistoricalConfirmationAllPagesTotals;
  readonly initialReconciliation: HistoricalCandidateConfirmationReconciliation;
  readonly reconciliation: HistoricalCandidateConfirmationReconciliation;
  readonly lastPage: HistoricalConfirmationAllPagesLastPage | null;
  readonly lease: {
    readonly owner: string;
    readonly expiresAt: string;
  } | null;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly completedAt: string | null;
  readonly receiptHash: string;
}

export interface HistoricalConfirmationAllPagesInput {
  readonly migrationId: string;
  readonly actorId: string;
  readonly reason: string;
  readonly pageSize?: number;
  /** A per-invocation bound. Re-running with the same binding resumes safely. */
  readonly maxPages?: number;
}

export interface HistoricalConfirmationAllPagesResult {
  readonly outcome: "completed" | "bounded" | "replayed";
  readonly pagesProcessedThisInvocation: number;
  readonly stateVersion: number;
  readonly receipt: HistoricalConfirmationAllPagesReceipt;
}

export class HistoricalAttackKnowledgeConfirmationOrchestrationError extends Error {
  constructor(
    readonly code:
      | "invalid_request"
      | "orchestration_busy"
      | "operation_binding_mismatch"
      | "receipt_integrity_failed"
      | "concurrent_checkpoint_update"
      | "page_integrity_failed"
      | "completion_reconciliation_failed",
    message: string,
  ) {
    super(message);
    this.name = "HistoricalAttackKnowledgeConfirmationOrchestrationError";
  }
}

type ReceiptBody = Omit<HistoricalConfirmationAllPagesReceipt, "receiptHash">;

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function boundedMaxPages(value: number | undefined): number {
  const resolved = value ?? DEFAULT_MAX_PAGES;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > MAX_PAGES_PER_INVOCATION) {
    throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
      "invalid_request",
      `maxPages must be an integer between 1 and ${MAX_PAGES_PER_INVOCATION}`,
    );
  }
  return resolved;
}

function sealReceipt(body: ReceiptBody): HistoricalConfirmationAllPagesReceipt {
  return { ...body, receiptHash: hashJson(body) };
}

function receiptBody(receipt: HistoricalConfirmationAllPagesReceipt): ReceiptBody {
  const { receiptHash: _receiptHash, ...body } = receipt;
  return body;
}

function numberRecord(value: unknown, keys: readonly string[], label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
      "receipt_integrity_failed", `${label} is malformed`,
    );
  }
  const record = value as Record<string, unknown>;
  for (const key of keys) {
    if (!Number.isSafeInteger(record[key]) || Number(record[key]) < 0) {
      throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
        "receipt_integrity_failed", `${label}.${key} is invalid`,
      );
    }
  }
}

const TOTAL_KEYS = [
  "selectedCount", "confirmedCount", "alreadyConfirmedCount", "suppressedCount",
  "preservedOperatorRejectionCount", "edgesCreated", "edgesAlreadyPresent",
  "edgesDeferred", "provenanceBindingsCreated", "provenanceBindingsAlreadyPresent",
  "unlinkedCandidateCount",
] as const;

const RECONCILIATION_KEYS = [
  "totalMigrationCandidateCount", "eligibleCandidateCount", "pendingEligibleCount",
  "confirmedEligibleCount", "incompatibleEligibleCount", "rejectedOrSuppressedCount",
  "provenanceBindingExpectedCount", "provenanceBindingPresentCount",
  "provenanceBindingMissingCount", "unlinkedEligibleCount", "unlinkedConfirmedCount",
] as const;

function validateReconciliation(
  value: unknown,
  migrationId: string,
  inventoryReceiptHash: string,
  label: string,
): void {
  numberRecord(value, RECONCILIATION_KEYS, label);
  const record = value as Record<string, unknown>;
  if (record.migrationId !== migrationId || record.inventoryReceiptHash !== inventoryReceiptHash) {
    throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
      "receipt_integrity_failed", `${label} is not bound to the receipt migration inventory`,
    );
  }
}

function parseReceipt(valueJson: string): HistoricalConfirmationAllPagesReceipt {
  let value: unknown;
  try { value = JSON.parse(valueJson) as unknown; }
  catch {
    throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
      "receipt_integrity_failed", "The persisted all-page confirmation receipt is malformed JSON",
    );
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
      "receipt_integrity_failed", "The persisted all-page confirmation receipt is malformed",
    );
  }
  const receipt = value as Record<string, unknown>;
  const requiredStrings = [
    "operationId", "migrationId", "inventoryReceiptHash", "actorId", "reason",
    "pageChainHash", "createdAt", "updatedAt", "receiptHash",
  ] as const;
  if (
    receipt.schemaVersion !== RECEIPT_SCHEMA
    || receipt.policyVersion !== POLICY_VERSION
    || !requiredStrings.every((key) => typeof receipt[key] === "string" && receipt[key] !== "")
    || !SHA256.test(String(receipt.inventoryReceiptHash))
    || !SHA256.test(String(receipt.pageChainHash))
    || !SHA256.test(String(receipt.receiptHash))
    || !Number.isSafeInteger(receipt.pageSize) || Number(receipt.pageSize) < 1 || Number(receipt.pageSize) > 1_000
    || !Number.isSafeInteger(receipt.pagesCompleted) || Number(receipt.pagesCompleted) < 0
    || !["in_progress", "completed"].includes(String(receipt.status))
    || !(receipt.nextSelectionCursor === null
      || typeof receipt.nextSelectionCursor === "string" && SHA256.test(receipt.nextSelectionCursor))
    || !(receipt.completedAt === null || typeof receipt.completedAt === "string")
  ) {
    throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
      "receipt_integrity_failed", "The persisted all-page confirmation receipt has invalid fields",
    );
  }
  numberRecord(receipt.totals, TOTAL_KEYS, "receipt.totals");
  validateReconciliation(
    receipt.initialReconciliation,
    String(receipt.migrationId),
    String(receipt.inventoryReceiptHash),
    "receipt.initialReconciliation",
  );
  validateReconciliation(
    receipt.reconciliation,
    String(receipt.migrationId),
    String(receipt.inventoryReceiptHash),
    "receipt.reconciliation",
  );
  if (receipt.lease !== null) {
    if (!receipt.lease || typeof receipt.lease !== "object" || Array.isArray(receipt.lease)) {
      throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
        "receipt_integrity_failed", "The persisted all-page confirmation lease is malformed",
      );
    }
    const lease = receipt.lease as Record<string, unknown>;
    if (typeof lease.owner !== "string" || !lease.owner
      || typeof lease.expiresAt !== "string" || !Number.isFinite(Date.parse(lease.expiresAt))) {
      throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
        "receipt_integrity_failed", "The persisted all-page confirmation lease is invalid",
      );
    }
  }
  if (receipt.lastPage !== null) {
    if (!receipt.lastPage || typeof receipt.lastPage !== "object" || Array.isArray(receipt.lastPage)) {
      throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
        "receipt_integrity_failed", "The persisted last-page receipt is malformed",
      );
    }
    const page = receipt.lastPage as Record<string, unknown>;
    if (!Number.isSafeInteger(page.pageNumber) || Number(page.pageNumber) < 1
      || !(page.selectionCursor === null || typeof page.selectionCursor === "string" && SHA256.test(page.selectionCursor))
      || typeof page.previewHash !== "string" || !SHA256.test(page.previewHash)
      || typeof page.auditRecordId !== "string" || !page.auditRecordId
      || !["completed", "replayed"].includes(String(page.executionStatus))
      || !Number.isSafeInteger(page.selectedCount) || Number(page.selectedCount) < 1
      || typeof page.hasMore !== "boolean"
      || typeof page.nextSelectionCursor !== "string" || !SHA256.test(page.nextSelectionCursor)) {
      throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
        "receipt_integrity_failed", "The persisted last-page receipt is invalid",
      );
    }
  }
  if (receipt.status === "completed" && (receipt.completedAt === null || receipt.lease !== null)) {
    throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
      "receipt_integrity_failed", "A completed all-page receipt must be terminal and lease-free",
    );
  }
  const typed = receipt as unknown as HistoricalConfirmationAllPagesReceipt;
  if (hashJson(receiptBody(typed)) !== typed.receiptHash) {
    throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
      "receipt_integrity_failed", "The persisted all-page confirmation receipt hash does not match",
    );
  }
  return typed;
}

function zeroTotals(): HistoricalConfirmationAllPagesTotals {
  return {
    selectedCount: 0,
    confirmedCount: 0,
    alreadyConfirmedCount: 0,
    suppressedCount: 0,
    preservedOperatorRejectionCount: 0,
    edgesCreated: 0,
    edgesAlreadyPresent: 0,
    edgesDeferred: 0,
    provenanceBindingsCreated: 0,
    provenanceBindingsAlreadyPresent: 0,
    unlinkedCandidateCount: 0,
  };
}

function addResult(
  totals: HistoricalConfirmationAllPagesTotals,
  result: HistoricalCandidateConfirmationResult,
): HistoricalConfirmationAllPagesTotals {
  return {
    selectedCount: totals.selectedCount + result.selectedCount,
    confirmedCount: totals.confirmedCount + result.confirmedCount,
    alreadyConfirmedCount: totals.alreadyConfirmedCount + result.alreadyConfirmedCount,
    suppressedCount: totals.suppressedCount + result.suppressedCount,
    preservedOperatorRejectionCount:
      totals.preservedOperatorRejectionCount + result.preservedOperatorRejectionCount,
    edgesCreated: totals.edgesCreated + result.edgesCreated,
    edgesAlreadyPresent: totals.edgesAlreadyPresent + result.edgesAlreadyPresent,
    edgesDeferred: totals.edgesDeferred + result.edgesDeferred,
    provenanceBindingsCreated:
      totals.provenanceBindingsCreated + result.provenanceBindingsCreated,
    provenanceBindingsAlreadyPresent:
      totals.provenanceBindingsAlreadyPresent + result.provenanceBindingsAlreadyPresent,
    unlinkedCandidateCount: totals.unlinkedCandidateCount + result.unlinkedCandidateCount,
  };
}

function completionIsReconciled(value: HistoricalCandidateConfirmationReconciliation): boolean {
  return value.pendingEligibleCount === 0
    && value.incompatibleEligibleCount === 0
    && value.provenanceBindingMissingCount === 0
    && value.eligibleCandidateCount === value.confirmedEligibleCount
    && value.provenanceBindingExpectedCount === value.provenanceBindingPresentCount;
}

function operationId(input: {
  readonly migrationId: string;
  readonly inventoryReceiptHash: string;
  readonly actorId: string;
  readonly reason: string;
  readonly pageSize: number;
}): string {
  return `hakc_all_${hashJson({ policyVersion: POLICY_VERSION, ...input }).slice(0, 48)}`;
}

export function historicalConfirmationAllPagesStateKey(migrationId: string): string {
  return `historical_attack_knowledge.confirm_all.${sha256(migrationId)}`;
}

class ConfirmationAllPagesReceiptStore {
  constructor(private readonly database: SqliteDatabase) {}

  load(migrationId: string): { readonly receipt: HistoricalConfirmationAllPagesReceipt; readonly version: number } | undefined {
    const row = this.database.prepare(
      "SELECT value_json, version FROM settings WHERE key = ?",
    ).get(historicalConfirmationAllPagesStateKey(migrationId)) as PersistedReceiptRow | undefined;
    if (!row) return undefined;
    if (!Number.isSafeInteger(row.version) || row.version < 1) {
      throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
        "receipt_integrity_failed", "The all-page confirmation checkpoint version is invalid",
      );
    }
    return { receipt: parseReceipt(row.value_json), version: row.version };
  }

  insert(receipt: HistoricalConfirmationAllPagesReceipt): number {
    const changes = this.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', 1, ?, ?)
      ON CONFLICT(key) DO NOTHING
    `).run(
      historicalConfirmationAllPagesStateKey(receipt.migrationId),
      canonicalJson(receipt),
      receipt.actorId,
      receipt.updatedAt,
    ).changes;
    if (changes !== 1) {
      throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
        "concurrent_checkpoint_update",
        "Another all-page confirmation process created the migration checkpoint",
      );
    }
    return 1;
  }

  update(receipt: HistoricalConfirmationAllPagesReceipt, expectedVersion: number): number {
    const changes = this.database.prepare(`
      UPDATE settings SET value_json = ?, version = version + 1,
        updated_by = ?, updated_at = ?, sensitivity = 'private'
      WHERE key = ? AND version = ?
    `).run(
      canonicalJson(receipt),
      receipt.actorId,
      receipt.updatedAt,
      historicalConfirmationAllPagesStateKey(receipt.migrationId),
      expectedVersion,
    ).changes;
    if (changes !== 1) {
      throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
        "concurrent_checkpoint_update",
        "The all-page confirmation checkpoint changed concurrently; reload before continuing",
      );
    }
    return expectedVersion + 1;
  }
}

function validatePage(
  preview: HistoricalCandidateConfirmationPreview,
  input: Required<Pick<HistoricalConfirmationAllPagesInput, "migrationId" | "actorId" | "reason">> & {
    readonly pageSize: number;
  },
  cursor: string | null,
): void {
  const candidates = preview.review.candidates;
  const fingerprints = candidates.map(({ contentFingerprint }) => contentFingerprint);
  const last = fingerprints.at(-1) ?? null;
  if (
    preview.review.migrationId !== input.migrationId
    || preview.review.actorId !== input.actorId
    || preview.review.reason !== input.reason
    || preview.review.selection.afterContentFingerprint !== cursor
    || preview.review.selection.maxCandidates !== input.pageSize
    || preview.candidateCount !== candidates.length
    || preview.candidateCount > input.pageSize
    || preview.nextSelectionCursor !== last
    || fingerprints.some((fingerprint, index) => !SHA256.test(fingerprint)
      || (cursor !== null && fingerprint <= cursor)
      || (index > 0 && fingerprint <= fingerprints[index - 1]!))
    || (preview.hasMore && (preview.candidateCount === 0 || last === null))
  ) {
    throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
      "page_integrity_failed",
      "A fresh confirmation page did not advance only from the persisted selection cursor",
    );
  }
}

function validateExecution(
  preview: HistoricalCandidateConfirmationPreview,
  result: HistoricalCandidateConfirmationResult,
  cursor: string | null,
): void {
  if (
    result.previewHash !== preview.previewHash
    || result.selectedCount !== preview.candidateCount
    || result.hasMore !== preview.hasMore
    || result.nextSelectionCursor !== preview.nextSelectionCursor
    || result.nextSelectionCursor === null
    || !SHA256.test(result.nextSelectionCursor)
    || (cursor !== null && result.nextSelectionCursor <= cursor)
  ) {
    throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
      "page_integrity_failed",
      "The executed confirmation page did not match its fresh hash-bound preview",
    );
  }
}

/**
 * Durable bounded driver for the single-page confirmation gate. It advances
 * only through the page service's returned fingerprint cursor and persists a
 * hash-checked checkpoint after every successful page. A crash between page
 * execution and checkpoint publication is safe because the exact page audit
 * replays idempotently on the next invocation.
 */
export class HistoricalAttackKnowledgeConfirmationOrchestrator {
  readonly #service: HistoricalAttackKnowledgeConfirmationService;
  readonly #store: ConfirmationAllPagesReceiptStore;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
    private readonly invocationIdFactory: () => string = () => `hakc_inv_${randomUUID()}`,
    /** Renew the outer canonical writer lease at durable page boundaries. */
    private readonly canonicalLeaseHeartbeat: () => void = () => {},
  ) {
    this.#service = new HistoricalAttackKnowledgeConfirmationService(database, clock);
    this.#store = new ConfirmationAllPagesReceiptStore(database);
  }

  getReceipt(migrationId: string): HistoricalConfirmationAllPagesReceipt | undefined {
    return this.#store.load(migrationId)?.receipt;
  }

  run(input: HistoricalConfirmationAllPagesInput): HistoricalConfirmationAllPagesResult {
    const normalizedPage = normalizeHistoricalCandidateConfirmationInput({
      migrationId: input.migrationId,
      actorId: input.actorId,
      reason: input.reason,
      maxCandidates: input.pageSize ?? DEFAULT_PAGE_SIZE,
    });
    const maxPages = boundedMaxPages(input.maxPages);
    const currentReconciliation = this.#service.reconcile(normalizedPage.migrationId);
    const binding = {
      migrationId: normalizedPage.migrationId,
      inventoryReceiptHash: currentReconciliation.inventoryReceiptHash,
      actorId: normalizedPage.actorId,
      reason: normalizedPage.reason,
      pageSize: normalizedPage.maxCandidates,
    } as const;
    const expectedOperationId = operationId(binding);
    const now = this.clock();
    const nowIso = now.toISOString();
    const invocationId = this.invocationIdFactory();
    if (!invocationId || Buffer.byteLength(invocationId, "utf8") > 200) {
      throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
        "invalid_request", "The orchestration invocation identifier is invalid",
      );
    }

    let checkpoint = this.#store.load(normalizedPage.migrationId);
    if (checkpoint) {
      const receipt = checkpoint.receipt;
      if (
        receipt.operationId !== expectedOperationId
        || receipt.migrationId !== binding.migrationId
        || receipt.inventoryReceiptHash !== binding.inventoryReceiptHash
        || receipt.actorId !== binding.actorId
        || receipt.reason !== binding.reason
        || receipt.pageSize !== binding.pageSize
      ) {
        throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
          "operation_binding_mismatch",
          "This migration already has an all-page confirmation checkpoint with a different actor, reason, page size, or inventory receipt",
        );
      }
      if (receipt.status === "completed") {
        if (!completionIsReconciled(currentReconciliation)
          || canonicalJson(currentReconciliation) !== canonicalJson(receipt.reconciliation)) {
          throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
            "completion_reconciliation_failed",
            "The completed confirmation receipt no longer matches canonical migration reconciliation",
          );
        }
        return {
          outcome: "replayed",
          pagesProcessedThisInvocation: 0,
          stateVersion: checkpoint.version,
          receipt,
        };
      }
      if (receipt.lease && Date.parse(receipt.lease.expiresAt) > now.getTime()) {
        throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
          "orchestration_busy",
          "Another bounded all-page confirmation invocation holds the unexpired migration lease",
        );
      }
    } else {
      const body: ReceiptBody = {
        schemaVersion: RECEIPT_SCHEMA,
        policyVersion: POLICY_VERSION,
        operationId: expectedOperationId,
        ...binding,
        status: "in_progress",
        nextSelectionCursor: null,
        pagesCompleted: 0,
        pageChainHash: sha256(`${expectedOperationId}\0start`),
        totals: zeroTotals(),
        initialReconciliation: currentReconciliation,
        reconciliation: currentReconciliation,
        lastPage: null,
        lease: null,
        createdAt: nowIso,
        updatedAt: nowIso,
        completedAt: null,
      };
      checkpoint = { receipt: sealReceipt(body), version: 0 };
    }

    const lease = {
      owner: invocationId,
      expiresAt: new Date(now.getTime() + LEASE_DURATION_MS).toISOString(),
    } as const;
    let receipt = sealReceipt({ ...receiptBody(checkpoint.receipt), lease, updatedAt: nowIso });
    let version = checkpoint.version === 0
      ? this.#store.insert(receipt)
      : this.#store.update(receipt, checkpoint.version);
    let pagesProcessed = 0;

    const publish = (next: HistoricalConfirmationAllPagesReceipt): void => {
      version = this.#store.update(next, version);
      receipt = next;
    };
    const release = (): void => {
      if (receipt.lease?.owner !== invocationId) return;
      const releasedAt = this.clock().toISOString();
      publish(sealReceipt({ ...receiptBody(receipt), lease: null, updatedAt: releasedAt }));
    };
    let canonicalLeaseLost = false;
    const heartbeatCanonicalLease = (): void => {
      try { this.canonicalLeaseHeartbeat(); }
      catch (error) {
        canonicalLeaseLost = true;
        throw error;
      }
    };

    try {
      while (pagesProcessed < maxPages) {
        // The page loop is synchronous and can block timer-based heartbeats.
        // Renew before each page so an expired or superseded fence fails before
        // any additional confirmation mutation begins.
        heartbeatCanonicalLease();
        const cursor = receipt.nextSelectionCursor;
        const preview = this.#service.preview({
          migrationId: binding.migrationId,
          actorId: binding.actorId,
          reason: binding.reason,
          maxCandidates: binding.pageSize,
          ...(cursor ? { afterContentFingerprint: cursor } : {}),
        });
        validatePage(preview, binding, cursor);
        if (preview.review.inventoryReceiptHash !== binding.inventoryReceiptHash) {
          throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
            "page_integrity_failed", "The migration inventory receipt changed during confirmation",
          );
        }

        if (preview.candidateCount === 0) {
          const reconciliation = this.#service.reconcile(binding.migrationId);
          if (!completionIsReconciled(reconciliation)) {
            throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
              "completion_reconciliation_failed",
              "No page remained, but eligible candidates or provenance bindings are still unresolved",
            );
          }
          const completedAt = this.clock().toISOString();
          const completed = sealReceipt({
            ...receiptBody(receipt),
            status: "completed",
            reconciliation,
            lease: null,
            updatedAt: completedAt,
            completedAt,
          });
          publish(completed);
          return {
            outcome: "completed",
            pagesProcessedThisInvocation: pagesProcessed,
            stateVersion: version,
            receipt,
          };
        }

        // Previewing is read-only but may be expensive. Never begin its
        // corresponding write page under an ownership window that expired
        // while the review was being assembled.
        heartbeatCanonicalLease();
        const result = this.#service.execute({
          migrationId: binding.migrationId,
          actorId: binding.actorId,
          reason: binding.reason,
          maxCandidates: binding.pageSize,
          ...(cursor ? { afterContentFingerprint: cursor } : {}),
          expectedPreviewHash: preview.previewHash,
          acknowledgeConfirmAllSafe: true,
        });
        // A page may be expensive on a large historical graph. Recheck and
        // renew the same fencing token before reconciliation/checkpoint work.
        heartbeatCanonicalLease();
        validateExecution(preview, result, cursor);
        const reconciliation = this.#service.reconcile(binding.migrationId);
        if (!result.hasMore && !completionIsReconciled(reconciliation)) {
          throw new HistoricalAttackKnowledgeConfirmationOrchestrationError(
            "completion_reconciliation_failed",
            "The terminal confirmation page left eligible candidates or provenance bindings unresolved",
          );
        }
        const pageNumber = receipt.pagesCompleted + 1;
        const lastPage: HistoricalConfirmationAllPagesLastPage = {
          pageNumber,
          selectionCursor: cursor,
          previewHash: preview.previewHash,
          auditRecordId: result.auditRecordId,
          executionStatus: result.status,
          selectedCount: result.selectedCount,
          hasMore: result.hasMore,
          nextSelectionCursor: result.nextSelectionCursor!,
        };
        const updatedAt = this.clock().toISOString();
        const terminal = !result.hasMore;
        const nextLease = terminal ? null : {
          owner: invocationId,
          expiresAt: new Date(this.clock().getTime() + LEASE_DURATION_MS).toISOString(),
        };
        const next = sealReceipt({
          ...receiptBody(receipt),
          status: terminal ? "completed" : "in_progress",
          nextSelectionCursor: result.nextSelectionCursor,
          pagesCompleted: pageNumber,
          pageChainHash: sha256(`${receipt.pageChainHash}\n${canonicalJson(lastPage)}`),
          totals: addResult(receipt.totals, result),
          reconciliation,
          lastPage,
          lease: nextLease,
          updatedAt,
          completedAt: terminal ? updatedAt : null,
        });
        publish(next);
        pagesProcessed += 1;
        if (terminal) {
          return {
            outcome: "completed",
            pagesProcessedThisInvocation: pagesProcessed,
            stateVersion: version,
            receipt,
          };
        }
      }

      release();
      return {
        outcome: "bounded",
        pagesProcessedThisInvocation: pagesProcessed,
        stateVersion: version,
        receipt,
      };
    } catch (error) {
      // Once canonical ownership is uncertain, even releasing the inner
      // orchestration lease would be a stale write. Leave its bounded expiry
      // as the fail-closed recovery point for a later valid writer.
      if (!canonicalLeaseLost) {
        try { release(); } catch { /* The persisted cursor remains the fail-closed recovery point. */ }
      }
      throw error;
    }
  }
}

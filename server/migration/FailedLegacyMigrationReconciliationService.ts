import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync, readlinkSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import type {
  CanonicalDatabaseLeaseHandle,
  CanonicalDatabaseLeaseService,
} from "../maintenance";
import { CanonicalDatabaseLeaseService as LeaseService } from "../maintenance";
import { canonicalJson, sha256 } from "../intelligence-v24/validation";

interface MigrationRunRow {
  readonly id: string;
  readonly status: string;
  readonly source_roots_json: string;
  readonly source_retention: string;
  readonly brain_projection_mode: string;
  readonly error_summary: string | null;
  readonly started_at: string;
  readonly completed_at: string | null;
}

interface MigrationSourceRow {
  readonly id: string;
  readonly migration_id: string;
  readonly source_path: string;
  readonly relative_path: string;
  readonly source_type: string;
  readonly source_identity: string;
  readonly source_sha256: string;
  readonly status: string;
  readonly discovered_at: string;
  readonly completed_at: string | null;
}

interface ReplacementProofRow extends MigrationSourceRow {
  readonly source_object_count: number;
}

interface ActiveLeaseRow {
  readonly id: string;
  readonly operation: string;
  readonly owner_id: string;
}

export interface FailedLegacyMigrationReconciliationPreview {
  readonly failedMigrationId: string;
  readonly replacementMigrationId: string;
  readonly terminalAt: string;
  readonly parentError: string;
  readonly sourceCount: number;
  readonly sources: readonly {
    readonly id: string;
    readonly priorStatus: "pending" | "importing";
    readonly sourceIdentity: string;
    readonly sourcePathHash: string;
    readonly replacementSourceId: string;
    readonly replacementSourceHash: string;
  }[];
  readonly replacement: {
    readonly reconciliationHash: string;
    readonly inventoryReceiptHash: string;
    readonly completedAt: string;
  };
  readonly previewHash: string;
}

export interface ReconcileFailedLegacyMigrationInput {
  readonly failedMigrationId: string;
  readonly replacementMigrationId: string;
  readonly expectedPreviewHash: string;
  readonly actorId: string;
  readonly reason: string;
  readonly acknowledged: boolean;
}

export interface FailedLegacyMigrationReconciliationResult {
  readonly status: "reconciled";
  readonly failedMigrationId: string;
  readonly replacementMigrationId: string;
  readonly reconciledSourceIds: readonly string[];
  readonly terminalAt: string;
  readonly auditRecordId: string;
  readonly auditRecordHash: string;
  readonly previewHash: string;
}

export interface FailedLegacyMigrationReconciliationServiceOptions {
  readonly clock?: () => Date;
  readonly createId?: () => string;
  readonly activeMigrationProcessIds?: () => readonly number[];
}

const MIGRATION_PROCESS_MARKERS = Object.freeze([
  "server/migration/cli.ts\0migrate",
  "configured-historical-cli.ts",
  "history:migrate-configured",
  "db:migrate:historical",
]);

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
  if (!value || !Number.isFinite(Date.parse(value))) throw new Error(`${label} is missing a valid terminal timestamp`);
  return new Date(value).toISOString();
}

function sourceRoots(serialized: string, label: string): readonly string[] {
  const parsed = JSON.parse(serialized) as unknown;
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.some((value) => typeof value !== "string" || !value.trim())) {
    throw new Error(`${label} does not contain a valid source-root receipt`);
  }
  return parsed.map((value) => resolve(value as string));
}

function isInside(root: string, candidate: string): boolean {
  const path = relative(resolve(root), resolve(candidate));
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`) && !path.startsWith(sep));
}

function parentProcessId(procRoot: string, pid: number): number | undefined {
  try {
    const stat = readFileSync(`${procRoot}/${pid}/stat`, "utf8");
    const close = stat.lastIndexOf(")");
    if (close < 0) return undefined;
    const fields = stat.slice(close + 2).split(" ");
    const ppid = Number(fields[1]);
    return Number.isSafeInteger(ppid) && ppid > 0 ? ppid : undefined;
  } catch {
    return undefined;
  }
}

function configuredMigrationDatabasePath(
  procRoot: string,
  pid: number,
  command: string,
): string | undefined {
  const arguments_ = command.split("\0").filter(Boolean);
  const databaseArgument = arguments_.findIndex((argument) => argument === "--db");
  let configured = databaseArgument >= 0 ? arguments_[databaseArgument + 1] : undefined;
  if (!configured) {
    try {
      const environment = readFileSync(`${procRoot}/${pid}/environ`, "utf8").split("\0");
      configured = environment.find((entry) => entry.startsWith("TI_SCALE_DATABASE_PATH="))
        ?.slice("TI_SCALE_DATABASE_PATH=".length);
    } catch {
      // An importer whose canonical database cannot be proven remains active.
      return undefined;
    }
  }
  const normalized = configured?.trim();
  if (!normalized) return undefined;
  if (isAbsolute(normalized)) return resolve(normalized);
  try {
    return resolve(readlinkSync(`${procRoot}/${pid}/cwd`), normalized);
  } catch {
    // Relative paths cannot be correlated safely without the process cwd.
    return undefined;
  }
}

/**
 * Read-only Linux process evidence. Package-script ancestors are excluded so
 * the reconciliation CLI does not mistake its own Bun wrapper for an importer.
 * When a target database is supplied, an importer is ignored only if its
 * explicit CLI/environment configuration proves it belongs to a different
 * canonical database. Missing or unreadable configuration remains fail-closed.
 */
export function detectActiveLegacyMigrationProcessIds(
  procRoot = "/proc",
  currentPid = process.pid,
  targetDatabasePath?: string,
): readonly number[] {
  const target = targetDatabasePath ? resolve(targetDatabasePath) : undefined;
  const ancestors = new Set<number>();
  for (let pid: number | undefined = currentPid; pid && !ancestors.has(pid); pid = parentProcessId(procRoot, pid)) {
    ancestors.add(pid);
  }
  let entries: string[];
  try {
    entries = readdirSync(procRoot);
  } catch {
    throw new Error("Cannot inspect the process table; failed-migration reconciliation fails closed");
  }
  const active: number[] = [];
  for (const entry of entries) {
    if (!/^\d+$/u.test(entry)) continue;
    const pid = Number(entry);
    if (!Number.isSafeInteger(pid) || ancestors.has(pid)) continue;
    let command: string;
    try {
      command = readFileSync(`${procRoot}/${pid}/cmdline`, "utf8");
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ESRCH") continue;
      throw new Error(`Cannot inspect process ${pid}; failed-migration reconciliation fails closed`);
    }
    if (!command || !MIGRATION_PROCESS_MARKERS.some((marker) => command.includes(marker))) continue;
    if (target) {
      const configuredDatabase = configuredMigrationDatabasePath(procRoot, pid, command);
      if (configuredDatabase && configuredDatabase !== target) continue;
    }
    active.push(pid);
  }
  return active.sort((left, right) => left - right);
}

function migrationLeaseOperation(operation: string): boolean {
  return /(?:historical|legacy).*(?:import|migration)|(?:import|migration).*(?:historical|legacy)/iu.test(operation);
}

/**
 * Repairs only terminal metadata left by an interrupted, subsequently
 * superseded legacy import. It never removes source objects, candidates,
 * evidence, or audit history and never infers semantic knowledge.
 */
export class FailedLegacyMigrationReconciliationService {
  readonly #clock: () => Date;
  readonly #createId: () => string;
  readonly #activeMigrationProcessIds: () => readonly number[];

  constructor(
    readonly database: SqliteDatabase,
    options: FailedLegacyMigrationReconciliationServiceOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#createId = options.createId ?? (() => `audit_migration_reconcile_${randomUUID()}`);
    this.#activeMigrationProcessIds = options.activeMigrationProcessIds
      ?? (() => detectActiveLegacyMigrationProcessIds());
    if (!LeaseService.schemaAvailable(database)) {
      throw new Error("Failed-migration reconciliation requires canonical database migration 35");
    }
  }

  preview(input: {
    readonly failedMigrationId: string;
    readonly replacementMigrationId: string;
  }): FailedLegacyMigrationReconciliationPreview {
    const activeProcessIds = this.#activeMigrationProcessIds();
    if (activeProcessIds.length > 0) {
      throw new Error(`A legacy migration process is still active (${activeProcessIds.join(", ")})`);
    }
    return this.#preview(input, null);
  }

  reconcile(
    input: ReconcileFailedLegacyMigrationInput,
    authority: {
      readonly handle: CanonicalDatabaseLeaseHandle;
      readonly leases: CanonicalDatabaseLeaseService;
    },
  ): FailedLegacyMigrationReconciliationResult {
    if (!input.acknowledged) {
      throw new Error("Failed-migration reconciliation requires explicit acknowledgement");
    }
    const actorId = identifier(input.actorId, "Actor ID");
    const reason = boundedText(input.reason, "Reconciliation reason", 1_000);
    if (!/^[a-f0-9]{64}$/u.test(input.expectedPreviewHash)) {
      throw new TypeError("Expected preview hash must be a lowercase SHA-256 digest");
    }
    const activeProcessIds = this.#activeMigrationProcessIds();
    if (activeProcessIds.length > 0) {
      throw new Error(`A legacy migration process is still active (${activeProcessIds.join(", ")})`);
    }

    return inImmediateTransaction(this.database, () => {
      authority.leases.assertActiveInCurrentTransaction(authority.handle);
      if (authority.handle.mode !== "writer") throw new Error("A canonical writer lease is required");
      const preview = this.#preview(input, authority.handle.id);
      if (preview.previewHash !== input.expectedPreviewHash) {
        throw new Error("Failed-migration reconciliation preview changed; review the current proof before retrying");
      }
      const sourceIds = preview.sources.map((source) => source.id);
      const terminalError = [
        `Reconciled after completed replacement ${preview.replacementMigrationId}.`,
        preview.parentError,
      ].join(" ").slice(0, 1_000);
      const update = this.database.prepare(`
        UPDATE legacy_migration_sources
        SET status = 'failed', error_summary = ?, completed_at = ?
        WHERE migration_id = ? AND status IN ('pending', 'importing')
      `).run(terminalError, preview.terminalAt, preview.failedMigrationId);
      if (update.changes !== sourceIds.length) {
        throw new Error("Lingering migration-source state changed during reconciliation");
      }

      const now = this.#clock().toISOString();
      const previous = this.database.prepare(
        "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
      ).get() as { readonly record_hash: string } | undefined;
      const auditRecordId = this.#createId();
      const details = {
        failedMigrationId: preview.failedMigrationId,
        replacementMigrationId: preview.replacementMigrationId,
        previewHash: preview.previewHash,
        disposition: "failed_metadata_quarantine",
        sourceIds,
        sourceIdentityHashes: preview.sources.map((source) => sha256(source.sourceIdentity)),
        sourcePathHashes: preview.sources.map((source) => source.sourcePathHash),
        replacementSourceIds: preview.sources.map((source) => source.replacementSourceId),
        replacementReconciliationHash: preview.replacement.reconciliationHash,
        replacementInventoryReceiptHash: preview.replacement.inventoryReceiptHash,
        terminalAt: preview.terminalAt,
        sourceObjectsPreserved: true,
        semanticKnowledgeChanged: false,
      } as const;
      const hashBody = {
        id: auditRecordId,
        actorType: "operator",
        actorId,
        action: "legacy_migration.failed_children_reconciled",
        resourceType: "data_migration",
        resourceId: preview.failedMigrationId,
        reason,
        details,
        previousHash: previous?.record_hash ?? null,
        occurredAt: now,
      } as const;
      const auditRecordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(hashBody)}`);
      this.database.prepare(`
        INSERT INTO audit_records (
          id, actor_type, actor_id, action, resource_type, resource_id,
          reason, details_json, previous_hash, record_hash, occurred_at
        ) VALUES (?, 'operator', ?, 'legacy_migration.failed_children_reconciled',
          'data_migration', ?, ?, ?, ?, ?, ?)
      `).run(
        auditRecordId,
        actorId,
        preview.failedMigrationId,
        reason,
        canonicalJson(details),
        previous?.record_hash ?? null,
        auditRecordHash,
        now,
      );
      authority.leases.assertActiveInCurrentTransaction(authority.handle);
      return Object.freeze({
        status: "reconciled" as const,
        failedMigrationId: preview.failedMigrationId,
        replacementMigrationId: preview.replacementMigrationId,
        reconciledSourceIds: Object.freeze(sourceIds),
        terminalAt: preview.terminalAt,
        auditRecordId,
        auditRecordHash,
        previewHash: preview.previewHash,
      });
    });
  }

  #preview(
    input: { readonly failedMigrationId: string; readonly replacementMigrationId: string },
    ignoredLeaseId: string | null,
  ): FailedLegacyMigrationReconciliationPreview {
    const failedMigrationId = identifier(input.failedMigrationId, "Failed migration ID");
    const replacementMigrationId = identifier(input.replacementMigrationId, "Replacement migration ID");
    if (failedMigrationId === replacementMigrationId) throw new Error("Replacement migration must be a different run");
    this.#assertNoActiveMigrationLease(ignoredLeaseId);

    const failed = this.#run(failedMigrationId);
    if (!failed || failed.status !== "failed") throw new Error("Parent migration is not terminal failed");
    const terminalAt = isoTimestamp(failed.completed_at, "Failed parent migration");
    const parentError = failed.error_summary?.trim();
    if (!parentError) throw new Error("Failed parent migration has no terminal error summary");
    const lingering = this.database.prepare(`
      SELECT id, migration_id, source_path, relative_path, source_type,
        source_identity, source_sha256, status, discovered_at, completed_at
      FROM legacy_migration_sources
      WHERE migration_id = ? AND status IN ('pending', 'importing')
      ORDER BY id
    `).all(failedMigrationId) as MigrationSourceRow[];
    if (lingering.length === 0) throw new Error("Failed migration has no lingering child sources to reconcile");

    const replacement = this.#run(replacementMigrationId);
    if (!replacement || replacement.status !== "completed") {
      throw new Error("Replacement migration is not completed");
    }
    const replacementCompletedAt = isoTimestamp(replacement.completed_at, "Replacement migration");
    if (Date.parse(replacement.started_at) < Date.parse(terminalAt)
        || Date.parse(replacementCompletedAt) < Date.parse(terminalAt)) {
      throw new Error("Replacement migration does not postdate the failed parent");
    }
    if (replacement.source_retention !== failed.source_retention
        || replacement.brain_projection_mode !== failed.brain_projection_mode) {
      throw new Error("Replacement migration retention or Brain-projection contract differs from the failed parent");
    }
    const replacementRoots = sourceRoots(replacement.source_roots_json, "Replacement migration");
    const failedRoots = sourceRoots(failed.source_roots_json, "Failed parent migration");
    const reconciliation = this.database.prepare(`
      SELECT report_hash FROM legacy_migration_reconciliation WHERE migration_id = ?
    `).get(replacementMigrationId) as { readonly report_hash: string } | undefined;
    const inventory = this.database.prepare(`
      SELECT receipt_hash FROM legacy_migration_inventory_receipts WHERE migration_id = ?
    `).get(replacementMigrationId) as { readonly receipt_hash: string } | undefined;
    if (!reconciliation || !/^[a-f0-9]{64}$/u.test(reconciliation.report_hash)
        || !inventory || !/^[a-f0-9]{64}$/u.test(inventory.receipt_hash)) {
      throw new Error("Replacement migration lacks an immutable inventory and reconciliation receipt");
    }

    const sources = lingering.map((source) => {
      if (!failedRoots.some((root) => isInside(root, source.source_path))) {
        throw new Error(`Lingering source ${source.id} falls outside the failed migration root receipt`);
      }
      if (!replacementRoots.includes(resolve(source.source_path))) {
        throw new Error(`Replacement migration does not declare exact source root for ${source.id}`);
      }
      const candidate = this.database.prepare(`
        SELECT source.id, source.migration_id, source.source_path, source.relative_path,
          source.source_type, source.source_identity, source.source_sha256, source.status,
          source.discovered_at, source.completed_at,
          COUNT(source_object.id) AS source_object_count
        FROM legacy_migration_sources AS source
        LEFT JOIN legacy_migration_source_objects AS source_object
          ON source_object.source_id = source.id
        WHERE source.migration_id = ? AND source.source_path = ?
        GROUP BY source.id
      `).get(replacementMigrationId, source.source_path) as ReplacementProofRow | undefined;
      if (!candidate || candidate.status !== "completed" || !candidate.completed_at
          || candidate.source_object_count < 1
          || candidate.source_identity !== source.source_identity
          || candidate.source_type !== source.source_type
          || candidate.relative_path !== source.relative_path
          || resolve(candidate.source_path) !== resolve(source.source_path)) {
        throw new Error(`Replacement migration does not prove exact source identity for ${source.id}`);
      }
      if (Date.parse(candidate.completed_at) < Date.parse(terminalAt)) {
        throw new Error(`Replacement source coverage predates the failed parent for ${source.id}`);
      }
      return Object.freeze({
        id: source.id,
        priorStatus: source.status as "pending" | "importing",
        sourceIdentity: source.source_identity,
        sourcePathHash: sha256(resolve(source.source_path)),
        replacementSourceId: candidate.id,
        replacementSourceHash: candidate.source_sha256,
      });
    });
    const unsigned = {
      failedMigrationId,
      replacementMigrationId,
      terminalAt,
      parentError,
      sourceCount: sources.length,
      sources,
      replacement: {
        reconciliationHash: reconciliation.report_hash,
        inventoryReceiptHash: inventory.receipt_hash,
        completedAt: replacementCompletedAt,
      },
    } as const;
    return Object.freeze({ ...unsigned, previewHash: sha256(canonicalJson(unsigned)) });
  }

  #run(id: string): MigrationRunRow | undefined {
    return this.database.prepare(`
      SELECT id, status, source_roots_json, source_retention,
        brain_projection_mode, error_summary, started_at, completed_at
      FROM legacy_migration_runs WHERE id = ?
    `).get(id) as MigrationRunRow | undefined;
  }

  #assertNoActiveMigrationLease(ignoredLeaseId: string | null): void {
    const now = this.#clock().toISOString();
    const rows = this.database.prepare(`
      SELECT id, operation, owner_id
      FROM canonical_database_leases
      WHERE released_at IS NULL AND julianday(expires_at) > julianday(?)
      ORDER BY id
    `).all(now) as ActiveLeaseRow[];
    const conflicting = rows.filter((row) => row.id !== ignoredLeaseId && migrationLeaseOperation(row.operation));
    if (conflicting.length > 0) {
      throw new Error(`An active canonical migration lease remains (${conflicting.map((row) => row.id).join(", ")})`);
    }
  }
}

import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db/types";
import { inImmediateTransaction } from "../db/transaction";

export type RecoveryProjectionStatus =
  | "pending"
  | "synced"
  | "database_ahead"
  | "vault_ahead"
  | "conflict"
  | "quarantined"
  | "deleted";

export interface RecoveryConnectionSnapshot {
  readonly id: string;
  readonly vaultPath: string;
  readonly updatedAt: string;
}

export interface RecoverySyncState {
  readonly id: string;
  readonly connectionId: string;
  readonly nodeId?: string;
  readonly relativePath: string;
  readonly databaseVersion?: number;
  readonly vaultContentHash?: string;
  readonly databaseContentHash?: string;
  readonly status: RecoveryProjectionStatus;
  readonly lastScannedAt?: string;
  readonly lastSyncedAt?: string;
  readonly errorMessage?: string;
}

export interface RecoveryProjectionUpdate {
  readonly relativePath: string;
  readonly nodeId?: string;
  readonly databaseVersion?: number;
  readonly vaultContentHash?: string;
  readonly databaseContentHash?: string;
  readonly status: RecoveryProjectionStatus;
  readonly errorMessage?: string;
}

interface ConnectionRow {
  readonly id: string;
  readonly vault_path: string;
  readonly updated_at: string;
}

interface SyncStateRow {
  readonly id: string;
  readonly connection_id: string;
  readonly node_id: string | null;
  readonly relative_path: string;
  readonly database_version: number | null;
  readonly vault_content_hash: string | null;
  readonly database_content_hash: string | null;
  readonly status: RecoveryProjectionStatus;
  readonly last_scanned_at: string | null;
  readonly last_synced_at: string | null;
  readonly error_message: string | null;
}

interface RepositoryOptions {
  readonly clock?: () => Date;
  readonly createId?: (prefix: string) => string;
}

export class VaultSearchIndexIntegrityError extends Error {
  constructor(options?: ErrorOptions) {
    super(
      `Canonical memory search index failed bounded incremental refresh; no global rebuild was attempted${options?.cause instanceof Error ? `: ${options.cause.message}` : ""}`,
      options,
    );
    this.name = "VaultSearchIndexIntegrityError";
  }
}

export class DuplicateVaultProjectionError extends Error {
  constructor() {
    super("A Vault connection cannot retain more than one projection for the same canonical memory node");
    this.name = "DuplicateVaultProjectionError";
  }
}

function stateFromRow(row: SyncStateRow): RecoverySyncState {
  return {
    id: row.id,
    connectionId: row.connection_id,
    ...(row.node_id ? { nodeId: row.node_id } : {}),
    relativePath: row.relative_path,
    ...(row.database_version === null ? {} : { databaseVersion: Number(row.database_version) }),
    ...(row.vault_content_hash ? { vaultContentHash: row.vault_content_hash } : {}),
    ...(row.database_content_hash ? { databaseContentHash: row.database_content_hash } : {}),
    status: row.status,
    ...(row.last_scanned_at ? { lastScannedAt: row.last_scanned_at } : {}),
    ...(row.last_synced_at ? { lastSyncedAt: row.last_synced_at } : {}),
    ...(row.error_message ? { errorMessage: row.error_message } : {}),
  };
}

function nextTimestamp(clock: () => Date, previous: string): string {
  const candidate = clock().toISOString();
  const previousTime = Date.parse(previous);
  return Number.isFinite(previousTime) && Date.parse(candidate) <= previousTime
    ? new Date(previousTime + 1).toISOString()
    : candidate;
}

/** Persistence boundary for the recovery service. Filesystem inspection is
 * performed before this repository atomically refreshes projection metadata,
 * bounded canonical FTS rows, and the optimistic connection version. */
export class VaultRecoveryRepository {
  readonly #database: SqliteDatabase;
  readonly #clock: () => Date;
  readonly #createId: (prefix: string) => string;

  constructor(database: SqliteDatabase, options: RepositoryOptions = {}) {
    this.#database = database;
    this.#clock = options.clock ?? (() => new Date());
    this.#createId = options.createId ?? ((prefix) => `${prefix}_${randomUUID()}`);
  }

  requireConnectionVersion(connectionId: string, expectedUpdatedAt: string): RecoveryConnectionSnapshot {
    const row = this.#database.prepare(`
      SELECT id, vault_path, updated_at FROM vault_connections WHERE id = ?
    `).get(connectionId) as ConnectionRow | undefined;
    if (!row) throw new Error(`Vault connection not found: ${connectionId}`);
    if (row.updated_at !== expectedUpdatedAt) {
      throw new Error("Vault connection version does not match; refresh the connection before recovery");
    }
    return { id: row.id, vaultPath: row.vault_path, updatedAt: row.updated_at };
  }

  listSyncStates(connectionId: string, limit: number): readonly RecoverySyncState[] {
    return (this.#database.prepare(`
      SELECT * FROM vault_sync_state WHERE connection_id = ?
      ORDER BY relative_path LIMIT ?
    `).all(connectionId, limit) as SyncStateRow[]).map(stateFromRow);
  }

  openConflictStateIds(connectionId: string): ReadonlySet<string> {
    const rows = this.#database.prepare(`
      SELECT sync_state_id FROM vault_conflicts
      WHERE connection_id = ? AND status = 'open'
    `).all(connectionId) as Array<{ sync_state_id: string }>;
    return new Set(rows.map((row) => row.sync_state_id));
  }

  /** Quarantine moves are owned by the bridge; this method only records a
   * path-level safety diagnostic when a symlink or non-file could not be moved. */
  recordPathError(connectionId: string, relativePath: string, message: string): void {
    this.#database.prepare(`
      UPDATE vault_sync_state SET error_message = ?, last_scanned_at = ?
      WHERE connection_id = ? AND relative_path = ?
    `).run(message.slice(0, 1_000), this.#clock().toISOString(), connectionId, relativePath);
  }

  complete(input: {
    readonly connectionId: string;
    readonly expectedUpdatedAt: string;
    readonly connectionStatus: "connected" | "degraded" | "error";
    readonly updates: readonly RecoveryProjectionUpdate[];
    readonly indexNodeIds: readonly string[];
  }): string {
    return inImmediateTransaction(this.#database, () => {
      this.requireConnectionVersion(input.connectionId, input.expectedUpdatedAt);
      const scannedAt = this.#clock().toISOString();
      for (const update of input.updates) {
        const existing = this.#database.prepare(`
          SELECT id FROM vault_sync_state WHERE connection_id = ? AND relative_path = ?
        `).get(input.connectionId, update.relativePath) as { id: string } | undefined;
        if (existing) {
          this.#database.prepare(`
            UPDATE vault_sync_state SET node_id = ?, database_version = ?,
              vault_content_hash = ?, database_content_hash = ?, status = ?,
              last_scanned_at = ?, error_message = ? WHERE id = ?
          `).run(
            update.nodeId ?? null,
            update.databaseVersion ?? null,
            update.vaultContentHash ?? null,
            update.databaseContentHash ?? null,
            update.status,
            scannedAt,
            update.errorMessage?.slice(0, 1_000) ?? null,
            existing.id,
          );
        } else {
          this.#database.prepare(`
            INSERT INTO vault_sync_state (
              id, connection_id, node_id, relative_path, database_version,
              vault_content_hash, database_content_hash, status, last_scanned_at, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(
            this.#createId("vsync"),
            input.connectionId,
            update.nodeId ?? null,
            update.relativePath,
            update.databaseVersion ?? null,
            update.vaultContentHash ?? null,
            update.databaseContentHash ?? null,
            update.status,
            scannedAt,
            update.errorMessage?.slice(0, 1_000) ?? null,
          );
        }
      }

      const duplicate = this.#database.prepare(`
        SELECT node_id, COUNT(*) AS projection_count
        FROM vault_sync_state
        WHERE connection_id = ? AND node_id IS NOT NULL AND status != 'deleted'
        GROUP BY node_id HAVING COUNT(*) > 1
        ORDER BY node_id LIMIT 1
      `).get(input.connectionId) as { node_id: string; projection_count: number } | undefined;
      if (duplicate) throw new DuplicateVaultProjectionError();

      // SQLite remains authoritative. Refresh only represented rows through
      // the established external-content trigger. A corrupt FTS structure
      // aborts and rolls back this transaction; recovery never launches an
      // unbounded global rebuild from an operator action.
      const uniqueIndexIds = [...new Set(input.indexNodeIds)];
      if (uniqueIndexIds.length > 0) {
        try {
          const refresh = this.#database.prepare("UPDATE memory_nodes SET title = title WHERE id = ?");
          const canonicalExists = this.#database.prepare("SELECT 1 AS ok FROM memory_nodes WHERE id = ?");
          for (const nodeId of uniqueIndexIds) {
            if (!(canonicalExists.get(nodeId) as { ok: number } | undefined)) {
              throw new Error("Canonical memory row disappeared during bounded search refresh");
            }
            refresh.run(nodeId);
          }
        } catch (error) {
          throw new VaultSearchIndexIntegrityError({ cause: error });
        }
      }

      const completedAt = nextTimestamp(this.#clock, input.expectedUpdatedAt);
      const changed = this.#database.prepare(`
        UPDATE vault_connections SET status = ?, updated_at = ?
        WHERE id = ? AND updated_at = ?
      `).run(
        input.connectionStatus,
        completedAt,
        input.connectionId,
        input.expectedUpdatedAt,
      );
      if (changed.changes !== 1) {
        throw new Error("Vault connection version does not match; refresh the connection before recovery");
      }
      return completedAt;
    });
  }
}

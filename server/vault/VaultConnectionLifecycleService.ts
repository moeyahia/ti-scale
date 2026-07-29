import type { SqliteDatabase } from "../db/types";
import type { ObsidianVaultBridge } from "./ObsidianVaultBridge";
import type { VaultConnection } from "./types";

const ACTIVE_RUN_STATES = [
  "queued",
  "planning",
  "awaiting_contract_confirmation",
  "running",
  "waiting_guided_decision",
  "blocked",
  "recovering",
] as const;

export class VaultConnectionVersionConflictError extends Error {
  constructor() {
    super("Vault connection version does not match; refresh the connection before disconnecting it");
    this.name = "VaultConnectionVersionConflictError";
  }
}

export class VaultConnectionAlreadyDisconnectedError extends Error {
  constructor() {
    super("Vault connection is already disconnected");
    this.name = "VaultConnectionAlreadyDisconnectedError";
  }
}

export class VaultLastHealthyConnectionError extends Error {
  constructor() {
    super("Disconnecting the last healthy Obsidian vault requires an explicit controlled-degraded-state acknowledgement");
    this.name = "VaultLastHealthyConnectionError";
  }
}

export interface VaultDisconnectResult {
  readonly connection: VaultConnection;
  readonly previousStatus: Exclude<VaultConnection["status"], "disconnected">;
  readonly disconnectedAt: string;
  readonly connectionVersion: string;
  readonly projectionState: "healthy" | "degraded";
  readonly replacementConnectionId?: string;
  readonly activeRunCount: number;
  readonly activeRunImpact: "canonical_brain_unaffected";
  readonly syncStopped: true;
  readonly filesDeleted: 0;
  readonly notesRewritten: 0;
}

interface LifecycleOptions {
  readonly clock?: () => Date;
}

function nextVersion(now: string, prior: string): string {
  if (now > prior) return now;
  return new Date(Date.parse(prior) + 1).toISOString();
}

/**
 * Owns the lifecycle boundary for a persisted Obsidian projection. Disconnect
 * is intentionally metadata-only: SQLite remains canonical, while the Vault
 * directory, notes, attachments, sync history, and conflicts remain intact.
 */
export class VaultConnectionLifecycleService {
  readonly #database: SqliteDatabase;
  readonly #bridge: ObsidianVaultBridge;
  readonly #clock: () => Date;

  constructor(
    database: SqliteDatabase,
    bridge: ObsidianVaultBridge,
    options: LifecycleOptions = {},
  ) {
    this.#database = database;
    this.#bridge = bridge;
    this.#clock = options.clock ?? (() => new Date());
  }

  disconnect(input: {
    readonly connectionId: string;
    readonly expectedUpdatedAt: string;
    readonly allowProjectionDegraded: boolean;
  }): VaultDisconnectResult {
    const current = this.#bridge.requireExistingConnection(input.connectionId);
    if (current.updatedAt !== input.expectedUpdatedAt) {
      throw new VaultConnectionVersionConflictError();
    }
    if (current.status === "disconnected") {
      throw new VaultConnectionAlreadyDisconnectedError();
    }

    const replacementConnectionId = this.#healthyReplacementConnectionId(current.id);
    if (!replacementConnectionId && !input.allowProjectionDegraded) {
      throw new VaultLastHealthyConnectionError();
    }

    const disconnectedAt = nextVersion(this.#clock().toISOString(), current.updatedAt);
    const updated = this.#database.prepare(`
      UPDATE vault_connections
      SET status = 'disconnected', updated_at = ?
      WHERE id = ? AND updated_at = ? AND status != 'disconnected'
    `).run(disconnectedAt, current.id, current.updatedAt);
    if (updated.changes !== 1) throw new VaultConnectionVersionConflictError();

    return {
      connection: this.#bridge.requireExistingConnection(current.id),
      previousStatus: current.status,
      disconnectedAt,
      connectionVersion: disconnectedAt,
      projectionState: replacementConnectionId ? "healthy" : "degraded",
      ...(replacementConnectionId ? { replacementConnectionId } : {}),
      activeRunCount: this.#activeRunCount(),
      activeRunImpact: "canonical_brain_unaffected",
      syncStopped: true,
      filesDeleted: 0,
      notesRewritten: 0,
    };
  }

  #healthyReplacementConnectionId(excludedConnectionId: string): string | undefined {
    const rows = this.#database.prepare(`
      SELECT vc.id
      FROM vault_connections vc
      WHERE vc.id != ? AND vc.status = 'connected'
        AND EXISTS (
          SELECT 1 FROM audit_records ar
          WHERE ar.resource_type = 'vault_connection'
            AND ar.resource_id = vc.id
            AND ar.action = 'vault.health.verified'
        )
      ORDER BY vc.updated_at DESC, vc.id
    `).all(excludedConnectionId) as Array<{ id: string }>;
    for (const row of rows) {
      try {
        this.#bridge.requireExistingConnection(row.id);
        return row.id;
      } catch {
        // A recorded health proof is not enough when the path is no longer
        // reachable. Continue looking for a genuinely usable replacement.
      }
    }
    return undefined;
  }

  #activeRunCount(): number {
    const table = this.#database.prepare(`
      SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'runs'
    `).get() as { present: number } | undefined;
    if (!table) return 0;
    const placeholders = ACTIVE_RUN_STATES.map(() => "?").join(",");
    const row = this.#database.prepare(`
      SELECT COUNT(*) AS count FROM runs WHERE status IN (${placeholders})
    `).get(...ACTIVE_RUN_STATES) as { count: number };
    return Number(row.count);
  }
}

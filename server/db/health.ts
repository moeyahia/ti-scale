import { checkDatabaseIntegrity } from "./connection";
import type { SqliteDatabase } from "./types";

export interface DatabaseHealth {
  readonly healthy: boolean;
  readonly integrity: readonly string[];
  readonly journalMode: string;
  readonly foreignKeys: boolean;
  readonly busyTimeoutMs: number;
  readonly currentMigration: number;
  readonly pendingOutbox: number;
  readonly checkedAt: string;
}

export interface DatabaseHealthOptions {
  /** Force a new full SQLite quick-check instead of using this connection's verified result. */
  readonly refreshIntegrity?: boolean;
}

interface CountRow {
  readonly count: number;
}

interface CachedIntegrity {
  readonly ok: boolean;
  readonly messages: readonly string[];
}

// A full quick_check is intentionally connection-scoped and cached. On a
// multi-gigabyte database it is an offline/startup integrity operation, not a
// request-path liveness probe. New connections still verify independently,
// and callers performing an explicit diagnostic may force a refresh.
const integrityByConnection = new WeakMap<SqliteDatabase, CachedIntegrity>();

function tableExists(database: SqliteDatabase, name: string): boolean {
  const row = database
    .prepare("SELECT 1 AS count FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get(name) as CountRow | undefined;
  return row?.count === 1;
}

export function getDatabaseHealth(
  database: SqliteDatabase,
  options: DatabaseHealthOptions = {},
): DatabaseHealth {
  let integrity = options.refreshIntegrity ? undefined : integrityByConnection.get(database);
  if (!integrity) {
    integrity = checkDatabaseIntegrity(database);
    integrityByConnection.set(database, integrity);
  }
  const journalMode = String(database.pragma("journal_mode", { simple: true }));
  const foreignKeys = Number(database.pragma("foreign_keys", { simple: true })) === 1;
  const busyTimeoutMs = Number(database.pragma("busy_timeout", { simple: true }));

  let currentMigration = 0;
  if (tableExists(database, "schema_migrations")) {
    const row = database
      .prepare("SELECT COALESCE(MAX(version), 0) AS count FROM schema_migrations")
      .get() as CountRow;
    currentMigration = row.count;
  }

  let pendingOutbox = 0;
  if (tableExists(database, "event_outbox")) {
    const row = database
      .prepare("SELECT COUNT(*) AS count FROM event_outbox WHERE status IN ('pending', 'failed')")
      .get() as CountRow;
    pendingOutbox = row.count;
  }

  return {
    healthy: integrity.ok && foreignKeys,
    integrity: integrity.messages,
    journalMode,
    foreignKeys,
    busyTimeoutMs,
    currentMigration,
    pendingOutbox,
    checkedAt: new Date().toISOString(),
  };
}

import { getDatabaseIntegrityAttestation } from "./connection";
import type { SqliteDatabase } from "./types";

export interface DatabaseHealth {
  readonly healthy: boolean;
  readonly integrity: readonly string[];
  readonly integrityStatus: "verified" | "unverified";
  readonly integrityCheckedAt: string | null;
  readonly integritySource: "startup" | "diagnostic" | null;
  readonly journalMode: string;
  readonly foreignKeys: boolean;
  readonly busyTimeoutMs: number;
  readonly currentMigration: number;
  readonly pendingOutbox: number;
  readonly checkedAt: string;
}

interface CountRow {
  readonly count: number;
}

const UNVERIFIED_INTEGRITY = Object.freeze([
  "Database integrity has not been attested for this connection.",
]);

function tableExists(database: SqliteDatabase, name: string): boolean {
  const row = database
    .prepare("SELECT 1 AS count FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get(name) as CountRow | undefined;
  return row?.count === 1;
}

export function getDatabaseHealth(
  database: SqliteDatabase,
): DatabaseHealth {
  // This accessor is used by HTTP readiness and Brain health. It must never
  // execute SQLite quick_check: a multi-gigabyte store can take minutes. The
  // connection records its startup attestation before it is published.
  const integrity = getDatabaseIntegrityAttestation(database);
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
    healthy: integrity?.ok === true && foreignKeys,
    integrity: integrity?.messages ?? UNVERIFIED_INTEGRITY,
    integrityStatus: integrity ? "verified" : "unverified",
    integrityCheckedAt: integrity?.checkedAt ?? null,
    integritySource: integrity?.source ?? null,
    journalMode,
    foreignKeys,
    busyTimeoutMs,
    currentMigration,
    pendingOutbox,
    checkedAt: new Date().toISOString(),
  };
}

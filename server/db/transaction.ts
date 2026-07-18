import type { SqliteDatabase } from "./types";

/**
 * Run a synchronous operation under an IMMEDIATE SQLite transaction.
 *
 * IMMEDIATE obtains the write reservation before reading counters or current
 * state, preventing two processes from allocating the same logical sequence.
 * Existing transactions are respected so repositories compose safely.
 */
export function inImmediateTransaction<T>(
  database: SqliteDatabase,
  operation: () => T,
): T {
  if (database.inTransaction) return operation();
  return database.transaction(operation).immediate();
}

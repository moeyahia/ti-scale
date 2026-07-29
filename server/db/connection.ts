import {
  chmodSync,
  existsSync,
  mkdirSync,
  statSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import { DATABASE_BACKUP_DISABLED_ERROR } from "./backup";
import type { SqliteDatabase } from "./types";

export interface DatabaseConnectionOptions {
  readonly filename: string;
  readonly readonly?: boolean;
  readonly fileMustExist?: boolean;
  readonly busyTimeoutMs?: number;
  readonly verifyIntegrity?: boolean;
  /**
   * Startup-only integrity implementation. Production uses SQLite quick_check;
   * the injection point exists so boundary tests can prove slow verification
   * never moves into an HTTP request.
   */
  readonly integrityChecker?: DatabaseIntegrityChecker;
  readonly verbose?: (message?: unknown, ...additionalArgs: unknown[]) => void;
}

export interface IntegrityResult {
  readonly ok: boolean;
  readonly messages: readonly string[];
}

export type DatabaseIntegrityChecker = (database: SqliteDatabase) => IntegrityResult;

export interface DatabaseIntegrityAttestation extends IntegrityResult {
  readonly checkedAt: string;
  readonly source: "startup" | "diagnostic";
}

interface IntegrityRow {
  readonly quick_check: string;
}

const DEFAULT_BUSY_TIMEOUT_MS = 5_000;
const MAX_BUSY_TIMEOUT_MS = 120_000;
const require = createRequire(import.meta.url);
const integrityAttestations = new WeakMap<SqliteDatabase, DatabaseIntegrityAttestation>();

interface BunStatement {
  get(...parameters: unknown[]): unknown;
  all(...parameters: unknown[]): unknown[];
  iterate(...parameters: unknown[]): IterableIterator<unknown>;
  run(...parameters: unknown[]): { changes: number; lastInsertRowid: number | bigint };
  finalize(): void;
}

interface BunTransaction<T extends (...parameters: never[]) => unknown> {
  (...parameters: Parameters<T>): ReturnType<T>;
  immediate(...parameters: Parameters<T>): ReturnType<T>;
  deferred(...parameters: Parameters<T>): ReturnType<T>;
  exclusive(...parameters: Parameters<T>): ReturnType<T>;
}

export interface WeakStatementReference<T extends object> {
  deref(): T | undefined;
}

export type WeakStatementReferenceFactory<T extends object> = (
  statement: T,
) => WeakStatementReference<T>;

/**
 * Tracks live Bun statements without owning their lifetime. The injectable
 * reference factory makes the ownership rule deterministic to test; production
 * always uses native WeakRef and never stores a statement alongside it.
 */
export class WeakStatementRegistry<T extends object> {
  readonly #references = new Set<WeakStatementReference<T>>();
  readonly #collected: FinalizationRegistry<WeakStatementReference<T>>;

  constructor(
    private readonly createReference: WeakStatementReferenceFactory<T> =
      (statement) => new WeakRef(statement),
  ) {
    this.#collected = new FinalizationRegistry((reference) => {
      this.#references.delete(reference);
    });
  }

  track(statement: T): T {
    const reference = this.createReference(statement);
    this.#references.add(reference);
    this.#collected.register(statement, reference, reference);
    return statement;
  }

  visitLive(visitor: (statement: T) => void): void {
    for (const reference of this.#references) {
      const statement = reference.deref();
      if (statement) {
        visitor(statement);
        continue;
      }
      this.#collected.unregister(reference);
      this.#references.delete(reference);
    }
  }

  clear(): void {
    for (const reference of this.#references) {
      this.#collected.unregister(reference);
    }
    this.#references.clear();
  }

  /** Exact count of weak reference records, never a count of retained values. */
  get referenceCount(): number {
    return this.#references.size;
  }
}

interface BunDatabaseInstance {
  readonly filename: string;
  readonly inTransaction: boolean;
  prepare(sql: string): BunStatement;
  exec(sql: string): unknown;
  transaction<T extends (...parameters: never[]) => unknown>(operation: T): BunTransaction<T>;
  serialize(): Buffer;
  close(throwOnError?: boolean): void;
}

interface BunDatabaseConstructor {
  new (
    filename: string,
    options: {
      readonly: boolean;
      create: boolean;
      readwrite: boolean;
      strict: boolean;
    },
  ): BunDatabaseInstance;
}

/**
 * better-sqlite3 is the canonical Node driver, but its native addon is rejected
 * by Bun 1.3. The application runs on Bun, whose native SQLite API is nearly
 * identical; this adapter supplies only the better-sqlite3 surface used by the
 * database layer. It can be removed when Bun supports the addon.
 */
function createBunCompatibilityDatabase(
  filename: string,
  readonly: boolean,
  fileMustExist: boolean,
): SqliteDatabase {
  // Keep the Bun-only protocol out of Playwright's Node-side static module
  // graph. Some fixture modules import the shared database layer before the
  // runtime branch is evaluated; a literal `bun:` specifier makes Node's ESM
  // loader reject the otherwise unreachable adapter.
  const bunSqliteSpecifier = ["bun", "sqlite"].join(":");
  const module = require(bunSqliteSpecifier) as { Database: BunDatabaseConstructor };
  const BunDatabase = module.Database;
  const inner = new BunDatabase(filename, {
    readonly,
    create: !readonly && !fileMustExist,
    readwrite: !readonly,
    strict: true,
  });
  let open = true;
  // Never retain prepared statements strongly. Most repository calls prepare a
  // short-lived statement inline; the previous strong Set kept every Bun
  // native query object alive until process shutdown and grew the JSC heap by
  // gigabytes under repeated health/Brain reads. Weak references still let a
  // graceful close finalize statements that remain live without defeating GC.
  const statements = new WeakStatementRegistry<BunStatement>();
  const prepareTracked = (sql: string): BunStatement => {
    return statements.track(inner.prepare(sql));
  };

  const adapter = {
    memory: isMemoryDatabase(filename),
    readonly,
    name: filename,
    get open(): boolean {
      return open;
    },
    get inTransaction(): boolean {
      return inner.inTransaction;
    },
    prepare(sql: string): BunStatement {
      return prepareTracked(sql);
    },
    transaction<T extends (...parameters: never[]) => unknown>(
      operation: T,
    ): BunTransaction<T> {
      return inner.transaction(operation);
    },
    exec(sql: string): void {
      inner.exec(sql);
    },
    pragma(source: string, options?: { simple?: boolean }): unknown {
      const rows = prepareTracked(`PRAGMA ${source}`).all() as Record<string, unknown>[];
      if (!options?.simple) return rows;
      const first = rows[0];
      return first ? Object.values(first)[0] : undefined;
    },
    async backup(_destinationFile: string): Promise<{
      totalPages: number;
      remainingPages: number;
    }> {
      throw new Error(DATABASE_BACKUP_DISABLED_ERROR);
    },
    serialize(): Buffer {
      return inner.serialize();
    },
    close(): void {
      if (!open) return;
      if (inner.inTransaction) {
        throw new Error("Cannot close the SQLite connection while a transaction is active");
      }
      statements.visitLive((statement) => {
        // Bun documents finalize() as idempotent. Let an unexpected native
        // finalization failure surface and leave the adapter open for recovery.
        statement.finalize();
      });
      // A WeakRef can already be cleared while Bun's native query finalizer is
      // still queued. sqlite3_close() reports SQLITE_BUSY in that safe state;
      // sqlite3_close_v2() instead closes the public database handle and lets
      // only those unreachable native statements finish disposal. Every still-
      // reachable statement was finalized synchronously above.
      inner.close(false);
      statements.clear();
      open = false;
    },
  };
  return adapter as unknown as SqliteDatabase;
}

function normalizeBusyTimeout(value: number | undefined): number {
  const timeout = value ?? DEFAULT_BUSY_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout < 0 || timeout > MAX_BUSY_TIMEOUT_MS) {
    throw new RangeError(
      `busyTimeoutMs must be an integer between 0 and ${MAX_BUSY_TIMEOUT_MS}`,
    );
  }
  return timeout;
}

function isMemoryDatabase(filename: string): boolean {
  return filename === ":memory:" || filename.startsWith("file::memory:");
}

export function checkDatabaseIntegrity(database: SqliteDatabase): IntegrityResult {
  const rows = database.pragma("quick_check") as IntegrityRow[];
  const messages = rows.map((row) => row.quick_check);
  return {
    ok: messages.length === 1 && messages[0]?.toLowerCase() === "ok",
    messages,
  };
}

export function getDatabaseIntegrityAttestation(
  database: SqliteDatabase,
): DatabaseIntegrityAttestation | undefined {
  return integrityAttestations.get(database);
}

export function assertDatabaseIntegrity(
  database: SqliteDatabase,
  checker: DatabaseIntegrityChecker = checkDatabaseIntegrity,
  source: DatabaseIntegrityAttestation["source"] = "diagnostic",
): void {
  const result = checker(database);
  integrityAttestations.set(database, Object.freeze({
    ...result,
    messages: Object.freeze([...result.messages]),
    checkedAt: new Date().toISOString(),
    source,
  }));
  if (!result.ok) {
    throw new Error(`SQLite integrity check failed: ${result.messages.join("; ")}`);
  }
}

/** Open and harden a Ti-Scale SQLite connection. */
export function createDatabaseConnection(
  options: DatabaseConnectionOptions,
): SqliteDatabase {
  if (!options.filename.trim()) throw new Error("A database filename is required");

  const memory = isMemoryDatabase(options.filename);
  if (!memory && !options.readonly) {
    const parent = dirname(options.filename);
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    if (existsSync(options.filename) && !statSync(options.filename).isFile()) {
      throw new Error(`Database path is not a regular file: ${options.filename}`);
    }
  }

  const busyTimeoutMs = normalizeBusyTimeout(options.busyTimeoutMs);
  if (options.fileMustExist && !memory && !existsSync(options.filename)) {
    throw new Error(`Database does not exist: ${options.filename}`);
  }

  let database: SqliteDatabase;
  if ("bun" in process.versions) {
    database = createBunCompatibilityDatabase(
      options.filename,
      options.readonly ?? false,
      options.fileMustExist ?? false,
    );
  } else {
    const sqliteOptions: Database.Options = {
      readonly: options.readonly ?? false,
      fileMustExist: options.fileMustExist ?? false,
      timeout: busyTimeoutMs,
    };
    if (options.verbose) sqliteOptions.verbose = options.verbose;
    database = new Database(options.filename, sqliteOptions);
  }
  // Both better-sqlite3 and the Bun compatibility adapter historically exposed
  // a direct online-backup method. Keep that compatibility name fail-closed so
  // an exact or dynamically typed caller cannot bypass the operator policy.
  Object.defineProperty(database, "backup", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: async (): Promise<never> => {
      throw new Error(DATABASE_BACKUP_DISABLED_ERROR);
    },
  });

  try {
    database.pragma("foreign_keys = ON");
    database.pragma(`busy_timeout = ${busyTimeoutMs}`);

    if (!options.readonly) {
      // WAL is persistent for file-backed databases. SQLite returns "memory"
      // for in-memory databases, which is the correct equivalent there.
      database.pragma("journal_mode = WAL");
      database.pragma("synchronous = NORMAL");
    }

    if (options.verifyIntegrity ?? true) {
      assertDatabaseIntegrity(
        database,
        options.integrityChecker ?? checkDatabaseIntegrity,
        "startup",
      );
    }

    if (!memory && !options.readonly) {
      chmodSync(options.filename, 0o600);
    }
    return database;
  } catch (error) {
    database.close();
    throw error;
  }
}

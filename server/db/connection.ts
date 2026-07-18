import {
  chmodSync,
  existsSync,
  mkdirSync,
  statSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import type { SqliteDatabase } from "./types";

export interface DatabaseConnectionOptions {
  readonly filename: string;
  readonly readonly?: boolean;
  readonly fileMustExist?: boolean;
  readonly busyTimeoutMs?: number;
  readonly verifyIntegrity?: boolean;
  readonly verbose?: (message?: unknown, ...additionalArgs: unknown[]) => void;
}

export interface IntegrityResult {
  readonly ok: boolean;
  readonly messages: readonly string[];
}

interface IntegrityRow {
  readonly quick_check: string;
}

const DEFAULT_BUSY_TIMEOUT_MS = 5_000;
const MAX_BUSY_TIMEOUT_MS = 120_000;
const require = createRequire(import.meta.url);

interface BunStatement {
  get(...parameters: unknown[]): unknown;
  all(...parameters: unknown[]): unknown[];
  run(...parameters: unknown[]): { changes: number; lastInsertRowid: number | bigint };
}

interface BunTransaction<T extends (...parameters: never[]) => unknown> {
  (...parameters: Parameters<T>): ReturnType<T>;
  immediate(...parameters: Parameters<T>): ReturnType<T>;
  deferred(...parameters: Parameters<T>): ReturnType<T>;
  exclusive(...parameters: Parameters<T>): ReturnType<T>;
}

interface BunDatabaseInstance {
  readonly filename: string;
  readonly inTransaction: boolean;
  prepare(sql: string): BunStatement;
  exec(sql: string): unknown;
  transaction<T extends (...parameters: never[]) => unknown>(operation: T): BunTransaction<T>;
  serialize(): Buffer;
  close(): void;
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
  const module = require("bun:sqlite") as { Database: BunDatabaseConstructor };
  const BunDatabase = module.Database;
  const inner = new BunDatabase(filename, {
    readonly,
    create: !readonly && !fileMustExist,
    readwrite: !readonly,
    strict: true,
  });
  let open = true;

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
      return inner.prepare(sql);
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
      const rows = inner.prepare(`PRAGMA ${source}`).all() as Record<string, unknown>[];
      if (!options?.simple) return rows;
      const first = rows[0];
      return first ? Object.values(first)[0] : undefined;
    },
    async backup(destinationFile: string): Promise<{
      totalPages: number;
      remainingPages: number;
    }> {
      const pageRows = inner.prepare("PRAGMA page_count").all() as Array<{
        page_count: number;
      }>;
      const pageCount = Number(pageRows[0]?.page_count ?? 0);
      // `serialize()` materializes the entire database in memory and can exhaust
      // the runtime on real engagement stores. SQLite performs VACUUM INTO as a
      // consistent file-backed snapshot without holding the database in RAM.
      inner.prepare("VACUUM INTO ?").run(destinationFile);
      return { totalPages: pageCount, remainingPages: 0 };
    },
    serialize(): Buffer {
      return inner.serialize();
    },
    close(): void {
      inner.close();
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

export function assertDatabaseIntegrity(database: SqliteDatabase): void {
  const result = checkDatabaseIntegrity(database);
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

  try {
    database.pragma("foreign_keys = ON");
    database.pragma(`busy_timeout = ${busyTimeoutMs}`);

    if (!options.readonly) {
      // WAL is persistent for file-backed databases. SQLite returns "memory"
      // for in-memory databases, which is the correct equivalent there.
      database.pragma("journal_mode = WAL");
      database.pragma("synchronous = NORMAL");
    }

    if ((options.verifyIntegrity ?? true) && options.fileMustExist) {
      assertDatabaseIntegrity(database);
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

import type Database from "better-sqlite3";

export type SqliteDatabase = Database.Database;

export interface Migration {
  readonly version: number;
  readonly name: string;
  readonly sql: string;
  /**
   * Columns owned by this migration that may be absent when an older runtime
   * created the table outside the canonical migration ledger. The runner
   * applies these additions atomically before `sql`, but only when the table
   * already exists. Fresh databases continue to use the canonical CREATE
   * TABLE statement in `sql`.
   */
  readonly compatibilityAddColumns?: readonly {
    readonly table: string;
    readonly columns: readonly {
      readonly name: string;
      readonly definition: string;
    }[];
  }[];
  /**
   * Reserved for startup-only table rebuilds whose SQLite CHECK constraints
   * cannot be widened in place. The runner disables foreign keys only outside
   * the transaction, checks every reference before commit, and restores FK
   * enforcement before returning.
   */
  readonly requiresForeignKeysDisabled?: true;
  /**
   * Retired compatibility metadata only. The forward-only runner never creates
   * or requires a database copy, and direct backup APIs fail closed.
   */
  readonly requiresVerifiedBackup?: true;
}

export interface AppliedMigration {
  readonly version: number;
  readonly name: string;
  readonly checksum: string;
  readonly appliedAt: string;
}

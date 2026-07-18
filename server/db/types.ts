import type Database from "better-sqlite3";

export type SqliteDatabase = Database.Database;

export interface Migration {
  readonly version: number;
  readonly name: string;
  readonly sql: string;
}

export interface AppliedMigration {
  readonly version: number;
  readonly name: string;
  readonly checksum: string;
  readonly appliedAt: string;
}

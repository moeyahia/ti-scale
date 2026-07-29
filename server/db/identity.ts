import { createHash } from "node:crypto";
import type { SqliteDatabase } from "./types";

const SHA256 = /^[a-f0-9]{64}$/u;

export interface CanonicalDatabaseIdentity {
  readonly schemaVersion: "ti-scale.canonical-database-identity.v1";
  readonly databaseIdentitySha256: string;
  readonly migrationVersion: number;
}

/**
 * Returns the content-free identity used to join independently inspected
 * production components to one canonical SQLite database. In-memory and
 * anonymous databases are deliberately ineligible for runtime activation.
 */
export function inspectCanonicalDatabaseIdentity(
  database: SqliteDatabase,
): CanonicalDatabaseIdentity | undefined {
  try {
    const databases = database.pragma("database_list") as readonly {
      readonly name: string;
      readonly file: string;
    }[];
    const main = databases.find(({ name }) => name === "main");
    const migration = database.prepare(`
      SELECT COALESCE(MAX(version), 0) AS version
      FROM schema_migrations
    `).get() as { readonly version: number };
    if (!main?.file
      || !Number.isSafeInteger(migration.version)
      || migration.version < 1) return undefined;
    const databaseIdentitySha256 = createHash("sha256")
      .update(`${main.name}\u0000${main.file}`, "utf8")
      .digest("hex");
    if (!SHA256.test(databaseIdentitySha256)) return undefined;
    return Object.freeze({
      schemaVersion: "ti-scale.canonical-database-identity.v1",
      databaseIdentitySha256,
      migrationVersion: migration.version,
    });
  } catch {
    return undefined;
  }
}

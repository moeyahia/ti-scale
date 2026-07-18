export {
  assertDatabaseIntegrity,
  checkDatabaseIntegrity,
  createDatabaseConnection,
  type DatabaseConnectionOptions,
  type IntegrityResult,
} from "./connection";
export { backupDatabase, createTimestampedBackup } from "./backup";
export { getDatabaseHealth, type DatabaseHealth } from "./health";
export { inImmediateTransaction } from "./transaction";
export { DATABASE_MIGRATIONS } from "./migrations";
export {
  listAppliedMigrations,
  migrateDatabase,
  type MigrationResult,
} from "./migrations/runner";
export type {
  AppliedMigration,
  Migration,
  SqliteDatabase,
} from "./types";

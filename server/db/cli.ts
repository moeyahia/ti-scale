#!/usr/bin/env bun
import { resolveCliDatabasePath, type TiScaleCliEnvironment } from "../app/StandaloneCliConfiguration";
import { createDatabaseConnection } from "./connection";
import { getDatabaseHealth } from "./health";
import { DATABASE_MIGRATIONS } from "./migrations";
import { migrateDatabase } from "./migrations/runner";
import type { Migration } from "./types";

export const NO_BACKUP_ACKNOWLEDGEMENT_FLAG = "--acknowledge-no-backup-risk";

export type DatabaseMigrationBackupPolicy =
  { readonly mode: "operator-acknowledged-no-backup" };

function value(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(`--${name}`);
  return index >= 0 ? argv[index + 1] : undefined;
}

function count(argv: readonly string[], flag: string): number {
  return argv.reduce((total, argument) => total + Number(argument === flag), 0);
}

/**
 * This standalone installation is forward-only by explicit operator policy.
 * Database migration is therefore never allowed to create a restorable copy.
 * The former acknowledgement flags remain accepted as a compatibility spelling,
 * but omitting them cannot re-enable backup behavior.
 */
export function resolveDatabaseMigrationBackupPolicy(
  argv: readonly string[],
): DatabaseMigrationBackupPolicy {
  const noBackupCount = count(argv, "--no-backup");
  const acknowledgementCount = count(argv, NO_BACKUP_ACKNOWLEDGEMENT_FLAG);
  if (noBackupCount > 1 || acknowledgementCount > 1) {
    throw new Error("The no-backup flags may each be supplied only once");
  }

  const noBackup = noBackupCount === 1;
  const acknowledged = acknowledgementCount === 1;
  if (noBackup && !acknowledged) {
    throw new Error(
      `--no-backup requires ${NO_BACKUP_ACKNOWLEDGEMENT_FLAG}; refusing to migrate without explicit acknowledgement`,
    );
  }
  if (acknowledged && !noBackup) {
    throw new Error(`${NO_BACKUP_ACKNOWLEDGEMENT_FLAG} is valid only with --no-backup`);
  }
  if (argv.includes("--backup-dir")) {
    throw new Error("--backup-dir is unavailable because backups are disabled by operator policy");
  }

  return { mode: "operator-acknowledged-no-backup" };
}

function migrationsForBackupPolicy(
  _policy: DatabaseMigrationBackupPolicy,
): readonly Migration[] {
  return DATABASE_MIGRATIONS.map((migration): Migration => {
    const {
      requiresVerifiedBackup,
      ...migrationWithoutBackupRequirement
    } = migration;
    return requiresVerifiedBackup
      ? migrationWithoutBackupRequirement
      : migration;
  });
}

export async function runDatabaseCli(
  argv = process.argv.slice(2),
  environment: TiScaleCliEnvironment = process.env,
): Promise<number> {
  const [command = "help"] = argv;
  if (command === "help" || argv.includes("--help")) {
    process.stdout.write(
      `Usage: bun run server/db/cli.ts migrate [--db PATH]\n` +
      `       bun run server/db/cli.ts migrate [--db PATH] --no-backup ${NO_BACKUP_ACKNOWLEDGEMENT_FLAG}\n` +
      "Database fallback: TI_SCALE_DATABASE_PATH\n" +
      "Backups are disabled by operator policy. --backup-dir is rejected; the paired no-backup flags remain an optional explicit acknowledgement.\n",
    );
    return 0;
  }
  if (command !== "migrate") throw new Error(`Unknown database command: ${command}`);
  const backupPolicy = resolveDatabaseMigrationBackupPolicy(argv);
  const path = resolveCliDatabasePath(value(argv, "db"), environment);
  const database = createDatabaseConnection({ filename: path });
  try {
    const backup = undefined;
    const applied = migrateDatabase(database, migrationsForBackupPolicy(backupPolicy));
    const health = getDatabaseHealth(database);
    process.stdout.write(`${JSON.stringify({
      applied,
      backup: backup ?? null,
      backupPolicy: backupPolicy.mode,
      health,
    }, null, 2)}\n`);
    return health.healthy ? 0 : 2;
  } finally { database.close(); }
}

if (import.meta.main) {
  runDatabaseCli().then((code) => { process.exitCode = code; }).catch((error) => {
    process.stderr.write(`Database migration failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
    process.exitCode = 1;
  });
}

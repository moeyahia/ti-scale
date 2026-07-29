import { afterEach, describe, expect, spyOn, test } from "bun:test";
import {
  existsSync,
  mkdtempSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection } from "../connection";
import {
  NO_BACKUP_ACKNOWLEDGEMENT_FLAG,
  resolveDatabaseMigrationBackupPolicy,
  runDatabaseCli,
} from "../cli";
import { DATABASE_MIGRATIONS } from "../migrations";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-db-cli-backup-policy-"));
  temporaryDirectories.push(directory);
  return directory;
}

async function runWithCapturedOutput(argv: readonly string[]): Promise<{
  readonly code: number;
  readonly output: Record<string, unknown>;
}> {
  const stdout = spyOn(process.stdout, "write").mockImplementation(() => true);
  try {
    const code = await runDatabaseCli([...argv], {});
    const text = stdout.mock.calls.map((call) => String(call[0])).join("");
    return { code, output: JSON.parse(text) as Record<string, unknown> };
  } finally {
    stdout.mockRestore();
  }
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("database migration CLI backup policy", () => {
  test("keeps forward-only no-backup migration as the default and accepts the compatibility acknowledgement", () => {
    expect(resolveDatabaseMigrationBackupPolicy(["migrate"]))
      .toEqual({ mode: "operator-acknowledged-no-backup" });
    expect(resolveDatabaseMigrationBackupPolicy([
      "migrate",
      "--no-backup",
      NO_BACKUP_ACKNOWLEDGEMENT_FLAG,
    ])).toEqual({ mode: "operator-acknowledged-no-backup" });
  });

  test("rejects partial, contradictory, and duplicate no-backup flags", () => {
    expect(() => resolveDatabaseMigrationBackupPolicy(["migrate", "--no-backup"]))
      .toThrow(`--no-backup requires ${NO_BACKUP_ACKNOWLEDGEMENT_FLAG}`);
    expect(() => resolveDatabaseMigrationBackupPolicy([
      "migrate",
      NO_BACKUP_ACKNOWLEDGEMENT_FLAG,
    ])).toThrow(`${NO_BACKUP_ACKNOWLEDGEMENT_FLAG} is valid only with --no-backup`);
    expect(() => resolveDatabaseMigrationBackupPolicy([
      "migrate",
      "--no-backup",
      NO_BACKUP_ACKNOWLEDGEMENT_FLAG,
      "--backup-dir",
      "/tmp/backups",
    ])).toThrow("--backup-dir is unavailable");
    expect(() => resolveDatabaseMigrationBackupPolicy([
      "migrate",
      "--no-backup",
      "--no-backup",
      NO_BACKUP_ACKNOWLEDGEMENT_FLAG,
    ])).toThrow("may each be supplied only once");
  });

  test("fails before creating a database when the no-backup acknowledgement is incomplete", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "state", "ti-scale.sqlite");

    await expect(runDatabaseCli([
      "migrate",
      "--db",
      databasePath,
      "--no-backup",
    ], {})).rejects.toThrow(`--no-backup requires ${NO_BACKUP_ACKNOWLEDGEMENT_FLAG}`);
    expect(existsSync(databasePath)).toBe(false);
  });

  test("the acknowledged no-backup mode suppresses both CLI and migration-specific snapshots", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "state", "ti-scale.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    database.close();

    const result = await runWithCapturedOutput([
      "migrate",
      "--db",
      databasePath,
      "--no-backup",
      NO_BACKUP_ACKNOWLEDGEMENT_FLAG,
    ]);

    expect(result.code).toBe(0);
    expect(result.output).toMatchObject({
      backup: null,
      backupPolicy: "operator-acknowledged-no-backup",
    });
    expect(existsSync(join(root, "state", "backups"))).toBe(false);
    expect(existsSync(join(root, "state", "migration-backups"))).toBe(false);

    const verification = createDatabaseConnection({
      filename: databasePath,
      readonly: true,
      fileMustExist: true,
    });
    try {
      const row = verification.prepare(
        "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations",
      ).get() as { version: number };
      expect(row.version).toBe(DATABASE_MIGRATIONS.at(-1)!.version);
    } finally {
      verification.close();
    }
  });

  test("the default mode creates no backup and rejects any backup directory", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "state", "ti-scale.sqlite");
    const backupDirectory = join(root, "operator-backups");
    const initialized = await runWithCapturedOutput([
      "migrate",
      "--db",
      databasePath,
      "--no-backup",
      NO_BACKUP_ACKNOWLEDGEMENT_FLAG,
    ]);
    expect(initialized.code).toBe(0);

    const result = await runWithCapturedOutput([
      "migrate",
      "--db",
      databasePath,
    ]);

    expect(result.code).toBe(0);
    expect(result.output.backupPolicy).toBe("operator-acknowledged-no-backup");
    expect(result.output.backup).toBeNull();
    expect(existsSync(backupDirectory)).toBe(false);
    await expect(runDatabaseCli([
      "migrate",
      "--db",
      databasePath,
      "--backup-dir",
      backupDirectory,
    ], {})).rejects.toThrow("--backup-dir is unavailable");
    expect(existsSync(backupDirectory)).toBe(false);
  });
});

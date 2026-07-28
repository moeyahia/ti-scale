import { afterEach, expect, spyOn, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../../memory";
import { runVaultCli } from "../cli";
import { ObsidianVaultBridge } from "../ObsidianVaultBridge";
import { VaultPathPolicy } from "../VaultPathPolicy";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Vault import is forward-only and cannot create a database backup", async () => {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-vault-cli-no-backup-"));
  temporaryDirectories.push(directory);
  const databasePath = join(directory, "ti-scale.sqlite");
  const vaultRoot = join(directory, "vaults");
  const database = createDatabaseConnection({ filename: databasePath });
  migrateDatabase(database);
  const bridge = new ObsidianVaultBridge(
    database,
    new MemoryRepository(database),
    new VaultPathPolicy(vaultRoot),
  );
  const connection = bridge.connect({
    id: "vault-cli-no-backup",
    vaultPath: "Attack-Knowledge",
    displayName: "Attack Knowledge",
    permissionGranted: true,
  });
  await expect(
    bridge.createPortableExport(
      connection.id,
      [],
      "operator:test",
    ),
  ).rejects.toThrow(
    "Portable Vault ZIP creation is disabled by operator no-backup policy",
  );
  expect(
    existsSync(join(connection.vaultPath, ".ti-scale", "exports")),
  ).toBe(false);
  database.close();

  const stdout = spyOn(process.stdout, "write").mockImplementation(() => true);
  try {
    expect(await runVaultCli([
      "import",
      "--db",
      databasePath,
      "--vault-root",
      vaultRoot,
      "--connection",
      connection.id,
    ], {})).toBe(0);
    const output = JSON.parse(
      stdout.mock.calls.map((call) => String(call[0])).join(""),
    ) as Record<string, unknown>;
    expect(output).toMatchObject({
      backup: null,
      backupPolicy: "disabled_by_operator",
      processed: 0,
    });
  } finally {
    stdout.mockRestore();
  }
  expect(existsSync(join(directory, "backups"))).toBe(false);

  await expect(runVaultCli([
    "import",
    "--db",
    databasePath,
    "--vault-root",
    vaultRoot,
    "--connection",
    connection.id,
    "--backup-dir",
    join(directory, "forbidden-backups"),
  ], {})).rejects.toThrow("--backup-dir is unavailable");
  expect(existsSync(join(directory, "forbidden-backups"))).toBe(false);

  await expect(runVaultCli([
    "export",
    "--db",
    databasePath,
    "--vault-root",
    vaultRoot,
    "--connection",
    connection.id,
    "--zip",
  ], {})).rejects.toThrow("Portable Vault ZIP creation is disabled");
  await expect(runVaultCli([
    "export",
    "--db",
    databasePath,
    "--vault-root",
    vaultRoot,
    "--connection",
    connection.id,
    "--brain-atlas",
  ], {})).rejects.toThrow("Portable Vault ZIP creation is disabled");
  expect(existsSync(join(connection.vaultPath, ".ti-scale", "exports"))).toBe(false);
});

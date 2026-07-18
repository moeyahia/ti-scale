import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { runDatabaseCli } from "../../db/cli";
import { MemoryRepository } from "../../memory";
import { runMigrationCli } from "../../migration/cli";
import { ObsidianVaultBridge } from "../../vault/ObsidianVaultBridge";
import { runVaultCli } from "../../vault/cli";
import { VaultPathPolicy } from "../../vault/VaultPathPolicy";
import {
  resolveCliDatabasePath,
  resolveCliVaultRoot,
  type TiScaleCliEnvironment,
} from "../StandaloneCliConfiguration";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-cli-config-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("standalone CLI path configuration", () => {
  test("accepts only the Ti-Scale database and Vault environment fallbacks", () => {
    const root = temporaryDirectory();
    const environmentDatabase = join(root, "environment.sqlite");
    const explicitDatabase = join(root, "explicit.sqlite");
    const environmentVault = join(root, "environment-vaults");
    const explicitVault = join(root, "explicit-vaults");
    const environment: TiScaleCliEnvironment = {
      TI_SCALE_DATABASE_PATH: `  ${environmentDatabase}  `,
      TI_SCALE_VAULT_ROOT: `  ${environmentVault}  `,
    };

    expect(resolveCliDatabasePath(undefined, environment)).toBe(resolve(environmentDatabase));
    expect(resolveCliVaultRoot(undefined, environment)).toBe(resolve(environmentVault));
    expect(resolveCliDatabasePath(explicitDatabase, environment)).toBe(resolve(explicitDatabase));
    expect(resolveCliVaultRoot(explicitVault, environment)).toBe(resolve(explicitVault));

    expect(() => resolveCliDatabasePath(undefined, { DATABASE_PATH: environmentDatabase }))
      .toThrow("--db or TI_SCALE_DATABASE_PATH is required");
    expect(() => resolveCliVaultRoot(undefined, { VAULT_ROOT: environmentVault }))
      .toThrow("--vault-root or TI_SCALE_VAULT_ROOT is required");
    expect(() => resolveCliDatabasePath("  ", environment)).toThrow("--db must not be empty");
    expect(() => resolveCliVaultRoot("relative/vaults", environment))
      .toThrow("--vault-root or TI_SCALE_VAULT_ROOT must be an absolute path");
  });

  test("database migrate and verify commands share TI_SCALE_DATABASE_PATH", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "state", "ti-scale.sqlite");
    const environment = { TI_SCALE_DATABASE_PATH: databasePath };

    expect(await runDatabaseCli(["migrate"], environment)).toBe(0);
    expect(existsSync(databasePath)).toBe(true);
    expect(await runMigrationCli(["verify"], environment)).toBe(0);
  });

  test("Vault verification shares both standalone path variables", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "state", "ti-scale.sqlite");
    const allowedRoot = join(root, "vaults");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(database);
      const bridge = new ObsidianVaultBridge(
        database,
        new MemoryRepository(database),
        new VaultPathPolicy(allowedRoot),
      );
      bridge.connect({
        id: "vault-cli-config",
        vaultPath: "Ti-Scale-Brain",
        displayName: "Ti-Scale Brain",
        permissionGranted: true,
      });
    } finally {
      database.close();
    }

    expect(await runVaultCli([
      "sync-verify",
      "--connection", "vault-cli-config",
    ], {
      TI_SCALE_DATABASE_PATH: databasePath,
      TI_SCALE_VAULT_ROOT: allowedRoot,
    })).toBe(0);
  });
});

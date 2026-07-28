import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { restoreMigrationBackup } from "../LegacyMigrationService";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-forward-only-migration-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("forward-only migration restore boundary", () => {
  test("rejects before resolving or opening caller-controlled paths", async () => {
    const root = temporaryDirectory();
    const inaccessibleParent = join(root, "must-not-exist");
    let phaseCalled = false;

    await expect(restoreMigrationBackup({
      databasePath: join(inaccessibleParent, "canonical.sqlite"),
      backupPath: join(inaccessibleParent, "retained-copy.sqlite"),
      expectedSha256: "0".repeat(64),
      serviceStopped: true,
      onPhase: () => {
        phaseCalled = true;
      },
    })).rejects.toThrow(
      "restore is disabled by operator policy",
    );

    expect(phaseCalled).toBe(false);
    expect(existsSync(inaccessibleParent)).toBe(false);
  });

  test("does not change an existing destination or create sidecars/copies", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "canonical.sqlite");
    const original = "forward-only-destination-sentinel\n";
    writeFileSync(databasePath, original, { mode: 0o600 });

    await expect(restoreMigrationBackup({
      databasePath,
      backupPath: join(root, "does-not-exist.sqlite"),
      expectedSha256: "f".repeat(64),
      serviceStopped: false,
    })).rejects.toThrow(
      "restore is disabled by operator policy",
    );

    expect(readFileSync(databasePath, "utf8")).toBe(original);
    expect(readdirSync(root)).toEqual(["canonical.sqlite"]);
  });

  test("is absent from the production migration barrel export", async () => {
    const migration = await import("../index");
    expect("restoreMigrationBackup" in migration).toBe(false);
  });
});

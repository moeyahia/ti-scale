import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import {
  createHistoricalSqliteSnapshot,
  HISTORICAL_SQLITE_SNAPSHOT_DISABLED_ERROR,
  inspectHistoricalSqliteSource,
  type HistoricalSqliteSnapshotOptions,
} from "../HistoricalSqliteSnapshotService";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

function temporaryDirectory(): string {
  const path = mkdtempSync(join(tmpdir(), "ti-scale-historical-sqlite-policy-"));
  temporaryDirectories.push(path);
  return path;
}

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function inspectionFixture(): {
  readonly root: string;
  readonly sourceDatabasePath: string;
  readonly sourceContainmentRoot: string;
  readonly destinationPath: string;
  readonly receiptPath: string;
} {
  const root = temporaryDirectory();
  const sourceContainmentRoot = join(root, "source");
  const output = join(root, "output");
  mkdirSync(sourceContainmentRoot, { mode: 0o700 });
  mkdirSync(output, { mode: 0o700 });
  const sourceDatabasePath = join(sourceContainmentRoot, "historical.sqlite");
  writeFileSync(sourceDatabasePath, "read-only historical fixture\n", { mode: 0o600 });
  return {
    root,
    sourceDatabasePath,
    sourceContainmentRoot,
    destinationPath: join(output, "normalized.sqlite"),
    receiptPath: join(output, "normalized.receipt.json"),
  };
}

describe("HistoricalSqliteSnapshotService no-backup boundary", () => {
  test("keeps source inspection read-only", () => {
    const paths = inspectionFixture();
    const beforeState = lstatSync(paths.sourceDatabasePath, { bigint: true });
    const before = {
      sha256: sha256(paths.sourceDatabasePath),
      size: Number(beforeState.size),
      modifiedAt: beforeState.mtimeNs,
    };

    const result = inspectHistoricalSqliteSource(paths);

    expect(result.canonicalDatabasePath).toBe(paths.sourceDatabasePath);
    expect(result.files.database).toMatchObject({
      present: true,
      sha256: before.sha256,
      sizeBytes: before.size,
    });
    const afterState = lstatSync(paths.sourceDatabasePath, { bigint: true });
    expect({
      sha256: sha256(paths.sourceDatabasePath),
      size: Number(afterState.size),
      modifiedAt: afterState.mtimeNs,
    }).toEqual(before);
    expect(existsSync(paths.destinationPath)).toBe(false);
    expect(existsSync(paths.receiptPath)).toBe(false);
  });

  test("rejects an exact direct create call before reading options or touching a path", async () => {
    const root = temporaryDirectory();
    const forbiddenRoot = join(root, "must-not-be-created");
    let optionReads = 0;
    const options = new Proxy({} as HistoricalSqliteSnapshotOptions, {
      get() {
        optionReads += 1;
        throw new Error("snapshot options were accessed");
      },
    });

    await expect(createHistoricalSqliteSnapshot(options)).rejects.toThrow(
      HISTORICAL_SQLITE_SNAPSHOT_DISABLED_ERROR,
    );

    expect(optionReads).toBe(0);
    expect(existsSync(forbiddenRoot)).toBe(false);
  });

  test("does not expose the retired creator through the production migration barrel", async () => {
    const migration = await import("../index");
    expect("createHistoricalSqliteSnapshot" in migration).toBe(false);
    expect(typeof migration.inspectHistoricalSqliteSource).toBe("function");
  });

  test("CLI permits inspection and denies snapshot creation without output", () => {
    const paths = inspectionFixture();
    const cli = resolve("server/migration/historical-sqlite-snapshot-cli.ts");
    const common = [
      "--source", paths.sourceDatabasePath,
      "--source-root", paths.sourceContainmentRoot,
      "--destination", paths.destinationPath,
      "--receipt", paths.receiptPath,
    ];
    const inspection = spawnSync("bun", [cli, "inspect", ...common], {
      cwd: resolve("."),
      encoding: "utf8",
    });
    expect(inspection.status).toBe(0);
    expect(inspection.stderr).toBe("");

    const rejected = spawnSync("bun", [
      cli,
      "snapshot",
      ...common,
      "--expected-source-bundle-sha256",
      JSON.parse(inspection.stdout).sourceBundleSha256,
      "--execute",
    ], { cwd: resolve("."), encoding: "utf8" });

    expect(rejected.status).toBe(1);
    expect(rejected.stderr).toContain(HISTORICAL_SQLITE_SNAPSHOT_DISABLED_ERROR);
    expect(existsSync(paths.destinationPath)).toBe(false);
    expect(existsSync(paths.receiptPath)).toBe(false);
  });
});

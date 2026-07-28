import { afterEach, describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertReleaseMigrationAttestationsMatch,
  assertValidReleaseMigrationAttestation,
  attestReleaseMigrationCeiling,
} from "../../../scripts/release/ReleaseMigrationAttestation";
import { stageServerRelease } from "../../../scripts/release/FunctionalReleasePrimitives";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function migrationExport(version: number): string {
  return `migration${String(version).padStart(3, "0")}`;
}

function migrationFile(version: number): string {
  return `${String(version).padStart(3, "0")}_fixture_${String(version).padStart(3, "0")}.ts`;
}

function createMigrationSource(count: number): string {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-release-migrations-"));
  roots.push(root);
  const migrations = join(root, "server", "db", "migrations");
  mkdirSync(migrations, { recursive: true });
  writeFileSync(join(root, "package.json"), '{"name":"migration-attestation-fixture"}\n');
  writeFileSync(join(root, "server", "index.ts"), "export {};\n");
  const imports: string[] = [];
  const entries: string[] = [];
  for (let version = 1; version <= count; version += 1) {
    const exportName = migrationExport(version);
    const fileName = migrationFile(version);
    imports.push(`import { ${exportName} } from "./${fileName.slice(0, -3)}";`);
    entries.push(`  ${exportName},`);
    writeFileSync(join(migrations, fileName), [
      'import type { Migration } from "../types";',
      `export const ${exportName}: Migration = {`,
      `  version: ${String(version)},`,
      `  name: "fixture_${String(version).padStart(3, "0")}",`,
      "  sql: `SELECT 1;`,",
      "};",
      "",
    ].join("\n"));
  }
  writeFileSync(join(migrations, "index.ts"), [
    'import type { Migration } from "../types";',
    ...imports,
    "",
    "export const DATABASE_MIGRATIONS: readonly Migration[] = Object.freeze([",
    ...entries,
    "]);",
    "",
  ].join("\n"));
  return root;
}

describe("release migration ceiling attestation", () => {
  test("selects a schema-37 source independently of the schema-60 controller checkout", () => {
    const controller = attestReleaseMigrationCeiling(process.cwd());
    const selectedSource = attestReleaseMigrationCeiling(createMigrationSource(37));

    expect(controller.targetSchema).toBe(60);
    expect(controller.migrationCount).toBe(60);
    expect(selectedSource.targetSchema).toBe(37);
    expect(selectedSource.migrationCount).toBe(37);
    expect(selectedSource.attestationSha256).not.toBe(controller.attestationSha256);
  });

  test("accepts an exact staged copy and rejects content drift after source attestation", () => {
    const source = createMigrationSource(37);
    const staged = createMigrationSource(37);
    const sourceAttestation = attestReleaseMigrationCeiling(source);
    const stagedAttestation = attestReleaseMigrationCeiling(staged);

    expect(assertReleaseMigrationAttestationsMatch(sourceAttestation, stagedAttestation))
      .toEqual(sourceAttestation);

    const changedPath = join(staged, "server", "db", "migrations", migrationFile(37));
    writeFileSync(changedPath, `${readFileSync(changedPath, "utf8")}\n// staged drift\n`);
    expect(() => assertReleaseMigrationAttestationsMatch(
      sourceAttestation,
      attestReleaseMigrationCeiling(staged),
      "Staged release migration attestation",
    )).toThrow("does not match the selected source migration attestation");
  });

  test("binds the source ceiling to the immutable staged release and detects source drift", async () => {
    const source = createMigrationSource(37);
    const releaseRoot = mkdtempSync(join(tmpdir(), "ti-scale-release-migration-stage-"));
    roots.push(releaseRoot);
    const sourceAttestation = attestReleaseMigrationCeiling(source);
    const staged = await stageServerRelease({
      sourceRoot: source,
      releaseRoot,
      releaseId: "schema37-stage",
      createdAt: "2026-07-22T00:00:00.000Z",
    });

    expect(assertReleaseMigrationAttestationsMatch(
      sourceAttestation,
      attestReleaseMigrationCeiling(staged.releaseDirectory),
    )).toEqual(sourceAttestation);

    const changedPath = join(source, "server", "db", "migrations", migrationFile(37));
    writeFileSync(changedPath, `${readFileSync(changedPath, "utf8")}\n// changed after staging\n`);
    expect(() => assertReleaseMigrationAttestationsMatch(
      attestReleaseMigrationCeiling(source),
      attestReleaseMigrationCeiling(staged.releaseDirectory),
    )).toThrow("does not match the selected source migration attestation");
  });

  test("fails closed when a migration file is not registered", () => {
    const source = createMigrationSource(37);
    writeFileSync(
      join(source, "server", "db", "migrations", migrationFile(38)),
      `export const ${migrationExport(38)} = { version: 38, name: "fixture_038", sql: "SELECT 1;" };\n`,
    );
    expect(() => attestReleaseMigrationCeiling(source))
      .toThrow("registry and migration files do not form one exact set");
  });

  test("fails closed when a migration version is computed rather than literal", () => {
    const source = createMigrationSource(37);
    const path = join(source, "server", "db", "migrations", migrationFile(37));
    writeFileSync(path, readFileSync(path, "utf8").replace("version: 37", "version: 36 + 1"));
    expect(() => attestReleaseMigrationCeiling(source)).toThrow("version must be a numeric literal");
  });

  test("rejects receipt or journal attestation field tampering", () => {
    const attestation = attestReleaseMigrationCeiling(createMigrationSource(37));
    expect(() => assertValidReleaseMigrationAttestation({ ...attestation, targetSchema: 39 }))
      .toThrow("aggregate is inconsistent");
    expect(() => assertValidReleaseMigrationAttestation({
      ...attestation,
      attestationSha256: "0".repeat(64),
    })).toThrow("checksum is invalid");
  });
});

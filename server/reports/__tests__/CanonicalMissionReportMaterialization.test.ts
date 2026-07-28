import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { CanonicalMissionReportService } from "../CanonicalMissionReportService";

const NOW = "2026-07-22T08:00:00.000Z";
const ACTOR = { id: "system:report-test", type: "system" } as const;
const ACCESS = {
  maximumSensitivity: "restricted",
  allEngagements: true,
  allowGlobalKnowledge: true,
  allowUnscopedSystemData: true,
} as const;

const databases: ReturnType<typeof createDatabaseConnection>[] = [];
const directories: string[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixture() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at
    ) VALUES (
      'mission-report-materialization', 'Report materialization',
      'Produce one canonical completion report.', 'autonomous', 'completed',
      'verified', 'operator:test', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, started_at, ended_at,
      created_at, updated_at
    ) VALUES (
      'run-report-materialization', 'mission-report-materialization',
      'autonomous', 'completed', 1, 'Completed with verified evidence.',
      '{}', '{}', ?, ?, ?, ?
    )
  `).run(NOW, NOW, NOW, NOW);
  const artifactRoot = mkdtempSync(join(tmpdir(), "ti-scale-report-materialization-"));
  directories.push(artifactRoot);
  return {
    database,
    artifactRoot,
    reports: new CanonicalMissionReportService(database, {
      artifactRoot,
      clock: () => new Date(NOW),
    }),
  };
}

function contentFiles(root: string): string[] {
  return readdirSync(root).filter((name) => name.endsWith(".md") || name.endsWith(".json")).sort();
}

describe("CanonicalMissionReportService materialization compensation", () => {
  test("removes only newly materialized report files when the caller-owned transaction rolls back", () => {
    const { database, artifactRoot, reports } = fixture();

    expect(() => reports.withMaterializationCompensation(() =>
      database.transaction(() => {
        reports.generate(
          "run-report-materialization",
          1,
          ACTOR,
          ACCESS,
          "terminal-report-materialization-v1",
        );
        throw new Error("injected failure after report generation");
      }).immediate())).toThrow("injected failure after report generation");

    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 0 });
    expect(contentFiles(artifactRoot)).toEqual([]);
    expect(readdirSync(artifactRoot).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });

  test("never removes pre-existing content-addressed files during a later rollback", () => {
    const { database, artifactRoot, reports } = fixture();
    const generated = reports.generate(
      "run-report-materialization",
      1,
      ACTOR,
      ACCESS,
      "terminal-report-materialization-v1",
    );
    const before = contentFiles(artifactRoot);
    expect(before).toHaveLength(2);

    expect(() => reports.withMaterializationCompensation(() =>
      database.transaction(() => {
        expect(reports.generate(
          "run-report-materialization",
          1,
          ACTOR,
          ACCESS,
          "terminal-report-materialization-v1",
        ).artifacts).toEqual(generated.artifacts);
        throw new Error("injected replay rollback");
      }).immediate())).toThrow("injected replay rollback");

    expect(contentFiles(artifactRoot)).toEqual(before);
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 2 });
  });

  test("cleans materializations when canonical artifact insertion detects a conflict", () => {
    const { database, artifactRoot, reports } = fixture();
    const artifactId = `report_${createHash("sha256")
      .update("mission-report-materialization\nrun-report-materialization\n1\nmarkdown")
      .digest("hex").slice(0, 40)}`;
    database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, journey, artifact_type, storage_uri,
        content_hash, byte_size, media_type, sensitivity, metadata_json, created_at
      ) VALUES (?, 'mission-report-materialization', 'run-report-materialization',
        'autonomous', 'mission_report_markdown', ?, ?, 1,
        'text/markdown; charset=utf-8', 'private', '{}', ?)
    `).run(
      artifactId,
      `ti-scale-report://sha256/${"f".repeat(64)}/markdown`,
      "f".repeat(64),
      NOW,
    );

    expect(() => reports.generate(
      "run-report-materialization",
      1,
      ACTOR,
      ACCESS,
      "terminal-report-materialization-v1",
    )).toThrow("different immutable artifact");

    expect(contentFiles(artifactRoot)).toEqual([]);
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 1 });
  });

  test("refuses an uncompensated caller-owned transaction", () => {
    const { database, reports } = fixture();
    expect(() => database.transaction(() => reports.generate(
      "run-report-materialization",
      1,
      ACTOR,
      ACCESS,
      "terminal-report-materialization-v1",
    )).immediate()).toThrow("requires materialization compensation");
  });

  test("rejects a report download when retained bytes no longer match canonical SHA-256", () => {
    const { artifactRoot, reports } = fixture();
    const generated = reports.generate(
      "run-report-materialization",
      1,
      ACTOR,
      ACCESS,
      "terminal-report-materialization-v1",
    );
    const artifact = generated.artifacts.find(({ format }) =>
      format === "markdown");
    if (!artifact) throw new Error("Canonical report omitted Markdown");
    writeFileSync(
      join(artifactRoot, `${artifact.contentHash}.md`),
      Buffer.alloc(artifact.byteSize, 0x78),
    );

    expect(() => reports.download(artifact.id, ACCESS))
      .toThrow("failed containment or integrity verification");
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  closeSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  LegacyMigrationService,
  MAX_SETTLE_SECONDS,
  MIN_SETTLE_SECONDS,
} from "../LegacyMigrationService";
import {
  EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON,
  SETTLED_SOURCE_DEFERRED_REASON,
} from "../LegacyEngagementDiscovery";

const temporaryDirectories: string[] = [];
const FIRST_START = new Date("2026-07-20T12:00:00.000Z");
const SECOND_START = new Date("2026-07-20T12:02:00.000Z");

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-settled-source-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function write(path: string, body: string, modifiedAt: Date): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, body, { mode: 0o600 });
  utimesSync(path, modifiedAt, modifiedAt);
}

function createCanonicalDatabase(path: string): void {
  const database = createDatabaseConnection({ filename: path });
  try {
    migrateDatabase(database);
  } finally {
    database.close();
  }
}

function count(databasePath: string, table: string): number {
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: true,
    fileMustExist: true,
  });
  try {
    return Number((database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as {
      count: number;
    }).count);
  } finally {
    database.close();
  }
}

function sourceObjectPaths(databasePath: string, migrationId: string): string[] {
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: true,
    fileMustExist: true,
  });
  try {
    return (database.prepare(`
      SELECT source_path FROM legacy_migration_source_objects
      WHERE migration_id = ? ORDER BY source_path
    `).all(migrationId) as Array<{ source_path: string }>).map(({ source_path }) => source_path);
  } finally {
    database.close();
  }
}

function databaseSha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function migrationOptions(input: {
  databasePath: string;
  sourceRoot: string;
  outputDirectory: string;
  clock: () => Date;
  dryRun?: boolean;
}) {
  return {
    databasePath: input.databasePath,
    sourceRoots: [input.sourceRoot],
    outputDirectory: input.outputDirectory,
    sourceRetention: "verified-reference" as const,
    verifiedReferenceAcknowledged: true,
    brainProjectionMode: "attack-knowledge-only" as const,
    attackKnowledgeOnlyAcknowledged: true,
    settleSeconds: MIN_SETTLE_SECONDS,
    clock: input.clock,
    ...(input.dryRun ? { dryRun: true } : {}),
  };
}

async function runCli(args: readonly string[]): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}> {
  const child = Bun.spawn([
    globalThis.process.execPath,
    "run",
    "server/migration/cli.ts",
    ...args,
  ], {
    cwd: globalThis.process.cwd(),
    env: globalThis.process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { exitCode, stdout, stderr };
}

describe("historical migration settled-source boundary", () => {
  test("defers recent engagement and generic files, imports stable files, and admits deferred files after they settle", async () => {
    const root = temporaryDirectory();
    const sourceRoot = join(root, "history");
    const databasePath = join(root, "ti-scale.sqlite");
    const outputDirectory = join(root, "migration-output");
    const stableAt = new Date("2026-07-20T11:57:00.000Z");
    const recentAt = new Date("2026-07-20T11:59:30.000Z");
    const stableEngagement = join(sourceRoot, "assessment-a", "notes", "stable.md");
    const recentEngagement = join(sourceRoot, "assessment-a", "notes", "recent.md");
    const stableGeneric = join(sourceRoot, "runtime", "runs", "stable.json");
    const recentGeneric = join(sourceRoot, "logs", "live.log");
    const recentEngagementBody = "Recent attack-path observation.\n";
    const recentGenericBody = "2026-07-20 recent runtime event\n";
    write(stableEngagement, "Stable service-version observation.\n", stableAt);
    write(recentEngagement, recentEngagementBody, recentAt);
    write(stableGeneric, '{"run":{"id":"stable","status":"completed"}}\n', stableAt);
    write(recentGeneric, recentGenericBody, recentAt);
    createCanonicalDatabase(databasePath);

    const first = await new LegacyMigrationService(migrationOptions({
      databasePath,
      sourceRoot,
      outputDirectory,
      clock: () => FIRST_START,
    })).run();

    expect(first.report.settledSourceBoundary).toEqual({
      settleSeconds: 60,
      migrationStartedAt: FIRST_START.toISOString(),
      cutoffAt: "2026-07-20T11:59:00.000Z",
      deferredObjects: 2,
      deferredBytes: Buffer.byteLength(recentEngagementBody) + Buffer.byteLength(recentGenericBody),
      reason: SETTLED_SOURCE_DEFERRED_REASON,
      deferredReasonCounts: {
        [SETTLED_SOURCE_DEFERRED_REASON]: 2,
        [EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON]: 0,
      },
    });
    expect(first.report.engagementDiscovery).toMatchObject({
      deferredFiles: 1,
      deferredBytes: Buffer.byteLength(recentEngagementBody),
    });
    expect(first.report.excluded).toEqual(expect.arrayContaining([
      {
        absolutePath: resolve(recentEngagement),
        reason: `deferred_recent: ${SETTLED_SOURCE_DEFERRED_REASON}`,
      },
      {
        absolutePath: resolve(recentGeneric),
        reason: `deferred_recent: ${SETTLED_SOURCE_DEFERRED_REASON}`,
      },
    ]));
    expect(sourceObjectPaths(databasePath, first.migrationId)).toEqual(expect.arrayContaining([
      resolve(stableEngagement),
      resolve(stableGeneric),
    ]));
    expect(sourceObjectPaths(databasePath, first.migrationId)).not.toEqual(expect.arrayContaining([
      resolve(recentEngagement),
      resolve(recentGeneric),
    ]));

    const second = await new LegacyMigrationService(migrationOptions({
      databasePath,
      sourceRoot,
      outputDirectory,
      clock: () => SECOND_START,
    })).run();

    expect(second.report.settledSourceBoundary).toMatchObject({
      cutoffAt: "2026-07-20T12:01:00.000Z",
      deferredObjects: 0,
      deferredBytes: 0,
    });
    expect(sourceObjectPaths(databasePath, second.migrationId)).toEqual(expect.arrayContaining([
      resolve(stableEngagement),
      resolve(recentEngagement),
      resolve(stableGeneric),
      resolve(recentGeneric),
    ]));
  });

  test("aborts when an included generic source changes during the later semantic phase", async () => {
    const root = temporaryDirectory();
    const sourceRoot = join(root, "history");
    const databasePath = join(root, "ti-scale.sqlite");
    const outputDirectory = join(root, "migration-output");
    const source = join(sourceRoot, "runtime", "runs", "stable.json");
    write(source, '{"run":{"id":"stable","status":"completed"}}\n', new Date("2026-07-20T11:00:00.000Z"));
    createCanonicalDatabase(databasePath);

    const service = new LegacyMigrationService({
      ...migrationOptions({
        databasePath,
        sourceRoot,
        outputDirectory,
        clock: () => FIRST_START,
      }),
      genericAttackKnowledgeSourceHandler: () => {
        writeFileSync(source, '{"run":{"id":"changed","status":"completed"}}\n', { mode: 0o600 });
        return [];
      },
    });

    await expect(service.run()).rejects.toThrow("Historical source no longer matches discovery provenance");
    const database = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect(database.prepare(`
        SELECT status, error_summary FROM legacy_migration_runs
        ORDER BY started_at DESC LIMIT 1
      `).get()).toMatchObject({
        status: "failed",
        error_summary: "Historical source no longer matches discovery provenance",
      });
    } finally {
      database.close();
    }
  });

  test("dry-run reports the boundary without changing canonical database state", async () => {
    const root = temporaryDirectory();
    const sourceRoot = join(root, "history");
    const databasePath = join(root, "ti-scale.sqlite");
    const outputDirectory = join(root, "migration-output");
    write(
      join(sourceRoot, "runtime", "runs", "stable.json"),
      '{"run":{"id":"stable","status":"completed"}}\n',
      new Date("2026-07-20T11:00:00.000Z"),
    );
    write(
      join(sourceRoot, "logs", "recent.log"),
      "recent event\n",
      new Date("2026-07-20T11:59:30.000Z"),
    );
    createCanonicalDatabase(databasePath);
    const beforeHash = databaseSha256(databasePath);
    const beforeRuns = count(databasePath, "legacy_migration_runs");
    const beforeSources = count(databasePath, "legacy_migration_source_objects");

    const result = await new LegacyMigrationService(migrationOptions({
      databasePath,
      sourceRoot,
      outputDirectory,
      clock: () => FIRST_START,
      dryRun: true,
    })).run();

    expect(result.report.dryRun).toBeTrue();
    expect(result.report.settledSourceBoundary).toMatchObject({
      settleSeconds: 60,
      deferredObjects: 1,
      cutoffAt: "2026-07-20T11:59:00.000Z",
    });
    expect(count(databasePath, "legacy_migration_runs")).toBe(beforeRuns);
    expect(count(databasePath, "legacy_migration_source_objects")).toBe(beforeSources);
    expect(databaseSha256(databasePath)).toBe(beforeHash);
  });

  test("persists an immutable, bounded migration-start cutoff", () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "ti-scale.sqlite");
    createCanonicalDatabase(databasePath);
    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      expect(() => database.prepare(`
        INSERT INTO legacy_migration_runs (
          id, status, source_roots_json, database_path, output_directory,
          settle_seconds, started_at
        ) VALUES ('invalid-boundary', 'running', '[]', ?, ?, 60, ?)
      `).run(databasePath, root, FIRST_START.toISOString())).toThrow(
        "legacy migration settled-source boundary is incomplete or outside policy",
      );
      database.prepare(`
        INSERT INTO legacy_migration_runs (
          id, status, source_roots_json, database_path, output_directory,
          settle_seconds, settle_cutoff_at, started_at
        ) VALUES ('valid-boundary', 'running', '[]', ?, ?, 60, ?, ?)
      `).run(databasePath, root, "2026-07-20T11:59:00.000Z", FIRST_START.toISOString());
      expect(() => database.prepare(`
        UPDATE legacy_migration_runs SET settle_seconds = 120 WHERE id = 'valid-boundary'
      `).run()).toThrow("legacy migration settled-source boundary is immutable");
    } finally {
      database.close();
    }
  });

  test("imports settled files while an explicitly verified stale open writer is deferred", async () => {
    const root = temporaryDirectory();
    const sourceRoot = join(root, "history");
    const databasePath = join(root, "ti-scale.sqlite");
    const outputDirectory = join(root, "migration-output");
    const stable = join(sourceRoot, "assessment-a", "notes", "stable.md");
    const active = join(sourceRoot, "assessment-a", "logs", "listener.log");
    const old = new Date("2026-07-20T11:00:00.000Z");
    write(stable, "Stable reusable technique observation.\n", old);
    write(active, "Listener remains attached.\n", old);
    createCanonicalDatabase(databasePath);
    const descriptor = openSync(active, "a");
    try {
      const result = await new LegacyMigrationService({
        ...migrationOptions({
          databasePath,
          sourceRoot,
          outputDirectory,
          clock: () => FIRST_START,
        }),
        explicitActiveSourceDeferrals: [active],
      }).run();

      expect(result.report.settledSourceBoundary).toMatchObject({
        deferredObjects: 1,
        deferredReasonCounts: {
          [SETTLED_SOURCE_DEFERRED_REASON]: 0,
          [EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON]: 1,
        },
      });
      expect(result.report.excluded).toContainEqual({
        absolutePath: resolve(active),
        reason: `deferred_recent: ${EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON}`,
      });
      expect(sourceObjectPaths(databasePath, result.migrationId)).toContain(resolve(stable));
      expect(sourceObjectPaths(databasePath, result.migrationId)).not.toContain(resolve(active));
    } finally {
      closeSync(descriptor);
    }
  });

  test("rejects an explicit deferral that is neither recent nor open for write", async () => {
    const root = temporaryDirectory();
    const sourceRoot = join(root, "history");
    const databasePath = join(root, "ti-scale.sqlite");
    const inactive = join(sourceRoot, "assessment-a", "logs", "inactive.log");
    write(inactive, "Closed historical output.\n", new Date("2026-07-20T11:00:00.000Z"));
    createCanonicalDatabase(databasePath);

    await expect(new LegacyMigrationService({
      ...migrationOptions({
        databasePath,
        sourceRoot,
        outputDirectory: join(root, "migration-output"),
        clock: () => FIRST_START,
      }),
      explicitActiveSourceDeferrals: [inactive],
    }).run()).rejects.toThrow("neither newer than the settled-source cutoff nor open for write");
    expect(count(databasePath, "legacy_migration_runs")).toBe(0);
  });

  test("resume preserves the original explicit active deferral after its writer closes", async () => {
    const root = temporaryDirectory();
    const sourceRoot = join(root, "history");
    const databasePath = join(root, "ti-scale.sqlite");
    const outputDirectory = join(root, "migration-output");
    const active = join(sourceRoot, "logs", "listener.log");
    const stable = join(sourceRoot, "runtime", "runs", "stable.json");
    write(active, "Listener remains attached.\n", new Date("2026-07-20T11:00:00.000Z"));
    write(stable, '{"run":{"id":"stable","status":"completed"}}\n', new Date("2026-07-20T11:00:00.000Z"));
    createCanonicalDatabase(databasePath);
    const descriptor = openSync(active, "a");
    let migrationId = "";
    try {
      await expect(new LegacyMigrationService({
        ...migrationOptions({ databasePath, sourceRoot, outputDirectory, clock: () => FIRST_START }),
        explicitActiveSourceDeferrals: [active],
        genericAttackKnowledgeSourceHandler: () => { throw new Error("forced resumable interruption"); },
      }).run()).rejects.toThrow("forced resumable interruption");
      const database = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
      try {
        migrationId = String((database.prepare(`
          SELECT id FROM legacy_migration_runs ORDER BY started_at DESC LIMIT 1
        `).get() as { id: string }).id);
      } finally {
        database.close();
      }
    } finally {
      closeSync(descriptor);
    }

    const resumed = await new LegacyMigrationService({
      ...migrationOptions({ databasePath, sourceRoot, outputDirectory, clock: () => SECOND_START }),
      explicitActiveSourceDeferrals: [active],
      resumeMigrationId: migrationId,
      genericAttackKnowledgeSourceHandler: () => [],
    }).run();
    expect(resumed.migrationId).toBe(migrationId);
    expect(resumed.report.settledSourceBoundary?.deferredReasonCounts).toMatchObject({
      [EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON]: 1,
    });
    expect(sourceObjectPaths(databasePath, migrationId)).not.toContain(resolve(active));
  });

  test("CLI requires deliberate acknowledgement for explicit active-source deferrals", async () => {
    const root = temporaryDirectory();
    const sourceRoot = join(root, "history");
    const active = join(sourceRoot, "assessment-a", "logs", "listener.log");
    write(active, "Listener remains attached.\n", new Date("2026-07-20T11:00:00.000Z"));
    const result = await runCli([
      "migrate",
      "--db", join(root, "ti-scale.sqlite"),
      "--engagement-root", join(sourceRoot, "assessment-a"),
      "--output", join(root, "migration-output"),
      "--source-retention", "verified-reference",
      "--acknowledge-verified-reference",
      "--brain-projection", "attack-knowledge-only",
      "--acknowledge-attack-knowledge-only",
      "--settle-seconds", "60",
      "--defer-active-source", active,
    ]);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("--acknowledge-active-source-deferrals is required");
    expect(result.stdout).toBe("");
  });

  for (const invalid of [
    { args: ["--settle-seconds"], message: "--settle-seconds requires an integer value" },
    { args: ["--settle-seconds", String(MIN_SETTLE_SECONDS - 1)], message: "must be an integer between 60 and 86400" },
    { args: ["--settle-seconds", String(MAX_SETTLE_SECONDS + 1)], message: "must be an integer between 60 and 86400" },
    { args: ["--settle-seconds", "60.5"], message: "must be an integer between 60 and 86400" },
    { args: ["--settle-seconds", "60", "--settle-seconds", "120"], message: "may be supplied only once" },
  ] as const) {
    test(`rejects invalid CLI boundary: ${invalid.args.join(" ")}`, async () => {
      const root = temporaryDirectory();
      const sourceRoot = join(root, "history");
      mkdirSync(sourceRoot, { recursive: true });
      const result = await runCli([
        "migrate",
        "--db", join(root, "ti-scale.sqlite"),
        "--source", sourceRoot,
        "--output", join(root, "migration-output"),
        "--acknowledge-verified-reference",
        ...invalid.args,
      ]);
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain(invalid.message);
      expect(result.stdout).toBe("");
    });
  }
});

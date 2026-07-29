import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import {
  createDatabaseConnection,
  migrateDatabase,
} from "../../db";
import {
  HISTORICAL_SOURCE_ROOT_CONFIGURATION_SCHEMA_VERSION,
  HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
  loadTrustedHistoricalSourceRootConfiguration,
  parseHistoricalSourceRootConfiguration,
  requiredHistoricalParentRoots,
  resolveRequiredHistoricalSourceRoots,
} from "../HistoricalSourceRootConfiguration";
import { EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON } from "../LegacyEngagementDiscovery";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-historical-roots-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function configuration(roots: readonly { id: string; path: string }[]): unknown {
  return {
    schemaVersion: HISTORICAL_SOURCE_ROOT_CONFIGURATION_SCHEMA_VERSION,
    configurationVersion: "historical-fixture-v1",
    roots: roots.map((root) => ({ ...root, mode: "children", required: true })),
  };
}

function configurationV2(
  roots: readonly { id: string; path: string; mode: "children" | "engagement-root" | "history-root" }[],
): unknown {
  return {
    schemaVersion: HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
    configurationVersion: "historical-fixture-v2",
    roots: roots.map((root) => ({ ...root, required: true })),
  };
}

function writeConfiguration(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function createCanonicalDatabase(path: string): void {
  const database = createDatabaseConnection({ filename: path });
  try {
    migrateDatabase(database);
    database.pragma("wal_checkpoint(TRUNCATE)");
  }
  finally { database.close(); }
}

async function runConfiguredCli(args: readonly string[]): Promise<{
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}> {
  const process = Bun.spawn([
    globalThis.process.execPath,
    "run",
    "server/migration/configured-historical-cli.ts",
    ...args,
  ], {
    cwd: globalThis.process.cwd(),
    env: globalThis.process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
    process.exited,
  ]);
  return { exitCode, stdout, stderr };
}

describe("historical source-root configuration", () => {
  test("pins the reviewed v2 all-source deployment manifest", () => {
    const path = resolve("deployment/runtime-config/historical-source-roots.v2.json");
    expect(sha256(path)).toBe("e695fd23511e3ee5e01981a306b937ae81d7338e6e27a18d87af7771d480a704");
    const parsed = parseHistoricalSourceRootConfiguration(
      JSON.parse(readFileSync(path, "utf8")) as unknown,
    );
    expect(parsed.schemaVersion).toBe(HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION);
    expect(parsed.roots.filter(({ mode }) => mode === "children")).toHaveLength(3);
    expect(parsed.roots.filter(({ mode }) => mode === "history-root")).toHaveLength(7);
  });

  test("accepts only strict required parent-root definitions", () => {
    const root = temporaryDirectory();
    const first = join(root, "first");
    const second = join(root, "second");
    mkdirSync(first);
    mkdirSync(second);
    const parsed = parseHistoricalSourceRootConfiguration(configuration([
      { id: "first-root", path: first },
      { id: "second-root", path: second },
    ]));
    expect(parsed.roots.map(({ path }) => path)).toEqual([first, second]);

    expect(() => parseHistoricalSourceRootConfiguration({
      ...(configuration([{ id: "first-root", path: first }]) as Record<string, unknown>),
      command: "find / -type f",
    })).toThrow("unexpected: command");
    expect(() => parseHistoricalSourceRootConfiguration(configuration([
      { id: "duplicate", path: first },
      { id: "duplicate", path: second },
    ]))).toThrow("duplicate root IDs");
    expect(() => parseHistoricalSourceRootConfiguration(configuration([
      { id: "relative", path: "relative/history" },
    ]))).toThrow("normalized absolute path");
  });

  test("loads one stable hash-pinned manifest and fails closed for missing required roots", () => {
    const sandbox = temporaryDirectory();
    const source = join(sandbox, "sources");
    const configurationPath = join(sandbox, "config", "historical-source-roots.json");
    mkdirSync(source, { recursive: true });
    writeConfiguration(configurationPath, configuration([{ id: "source", path: source }]));
    const loaded = loadTrustedHistoricalSourceRootConfiguration({
      path: configurationPath,
      trustRoot: dirname(configurationPath),
      expectedSha256: sha256(configurationPath),
      allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
    });
    expect(loaded.receipt.sourceSha256).toBe(sha256(configurationPath));
    expect(requiredHistoricalParentRoots(loaded.value)).toEqual([source]);

    expect(() => loadTrustedHistoricalSourceRootConfiguration({
      path: configurationPath,
      trustRoot: dirname(configurationPath),
      expectedSha256: "0".repeat(64),
      allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
    })).toThrow("does not match its reviewed SHA-256");

    rmSync(source, { recursive: true });
    expect(() => requiredHistoricalParentRoots(loaded.value))
      .toThrow("Required historical source root is unavailable: source");
  });

  test("routes strict v2 children, engagement, and generic-only history roots", () => {
    const sandbox = temporaryDirectory();
    const children = join(sandbox, "children");
    const engagement = join(sandbox, "engagement");
    const history = join(sandbox, "history");
    [children, engagement, history].forEach((path) => mkdirSync(path));
    const parsed = parseHistoricalSourceRootConfiguration(configurationV2([
      { id: "children", path: children, mode: "children" },
      { id: "engagement", path: engagement, mode: "engagement-root" },
      { id: "history", path: history, mode: "history-root" },
    ]));
    expect(resolveRequiredHistoricalSourceRoots(parsed)).toEqual({
      childrenRoots: [children],
      engagementRoots: [engagement],
      historyRoots: [history],
    });
    expect(() => requiredHistoricalParentRoots(parsed)).toThrow(
      "supports only children roots",
    );
    expect(() => parseHistoricalSourceRootConfiguration(configurationV2([
      { id: "parent", path: sandbox, mode: "children" },
      { id: "nested", path: history, mode: "history-root" },
    ]))).toThrow("overlapping root paths");
    expect(() => parseHistoricalSourceRootConfiguration({
      schemaVersion: HISTORICAL_SOURCE_ROOT_CONFIGURATION_SCHEMA_VERSION,
      configurationVersion: "invalid-v1-mode",
      roots: [{ id: "history", path: history, mode: "history-root", required: true }],
    })).toThrow("must be children for the v1 schema");
  });

  test("drives a read-only semantic dry run, collapses physical aliases, and quarantines secrets", async () => {
    const sandbox = temporaryDirectory();
    const firstRoot = join(sandbox, "history-a");
    const firstAlias = join(sandbox, "history-a-alias");
    const secondRoot = join(sandbox, "history-b");
    const configurationPath = join(sandbox, "config", "historical-source-roots.json");
    const databasePath = join(sandbox, "canonical.sqlite");
    const output = join(sandbox, "dry-run-output");

    mkdirSync(join(firstRoot, "assessment-a", "notes"), { recursive: true, mode: 0o700 });
    writeFileSync(
      join(firstRoot, "assessment-a", "notes", "stack.md"),
      "The application reported nginx 1.24.0 in two independent service observations.\n",
      { mode: 0o600 },
    );
    symlinkSync(firstRoot, firstAlias, "dir");
    mkdirSync(join(secondRoot, "assessment-b", "notes"), { recursive: true, mode: 0o700 });
    mkdirSync(join(secondRoot, "assessment-b", "creds"), { recursive: true, mode: 0o700 });
    writeFileSync(
      join(secondRoot, "assessment-b", "notes", "recovery.md"),
      "After service degradation, verify the health check before any bounded retry.\n",
      { mode: 0o600 },
    );
    writeFileSync(
      join(secondRoot, "assessment-b", "creds", "password.txt"),
      "password=NeverEnterReusableMemory123!\n",
      { mode: 0o600 },
    );
    writeConfiguration(configurationPath, configuration([
      { id: "history-a", path: firstRoot },
      { id: "history-a-alias", path: firstAlias },
      { id: "history-b", path: secondRoot },
    ]));
    createCanonicalDatabase(databasePath);
    const databaseBefore = sha256(databasePath);

    const result = await runConfiguredCli([
      "--config", configurationPath,
      "--config-sha256", sha256(configurationPath),
      "--db", databasePath,
      "--output", output,
      "--acknowledge-verified-reference",
      "--acknowledge-attack-knowledge-only",
      "--dry-run",
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    const summary = JSON.parse(result.stdout) as {
      reportPath: string;
      attackKnowledge: {
        manifestsParsed: number;
        evidenceAutomaticallyVerified: number;
        reusableMemoryAutomaticallyPromoted: number;
        sourceEvidenceCandidateCount: number;
      };
    };
    const report = JSON.parse(readFileSync(summary.reportPath, "utf8")) as {
      sourceRoots: readonly string[];
      engagementDiscovery: {
        manifests: number;
        classifiedFiles: number;
        quarantinedPaths: number;
        rootAliases: readonly unknown[];
      };
    };
    expect(report.sourceRoots).toEqual([firstRoot, secondRoot].sort());
    expect(report.engagementDiscovery).toMatchObject({
      manifests: 2,
      classifiedFiles: 2,
      quarantinedPaths: 1,
    });
    expect(report.engagementDiscovery.rootAliases).toHaveLength(1);
    expect(summary.attackKnowledge).toMatchObject({
      manifestsParsed: 2,
      evidenceAutomaticallyVerified: 0,
      reusableMemoryAutomaticallyPromoted: 0,
    });
    expect(summary.attackKnowledge.sourceEvidenceCandidateCount).toBeGreaterThanOrEqual(0);
    expect(result.stdout).not.toContain("sourceEvidenceCandidateIds");
    expect(sha256(databasePath)).toBe(databaseBefore);
  });

  test("requires an explicit dry-run or execute choice and exact acknowledgements", async () => {
    const sandbox = temporaryDirectory();
    const source = join(sandbox, "source");
    const configurationPath = join(sandbox, "config", "historical-source-roots.json");
    mkdirSync(source);
    writeConfiguration(configurationPath, configuration([{ id: "source", path: source }]));
    chmodSync(configurationPath, 0o600);
    const common = [
      "--config", configurationPath,
      "--config-sha256", sha256(configurationPath),
      "--db", join(sandbox, "missing.sqlite"),
      "--output", join(sandbox, "output"),
    ];
    const noMode = await runConfiguredCli(common);
    expect(noMode.exitCode).toBe(1);
    expect(noMode.stderr).toContain("Select exactly one of --dry-run or --execute");

    const noAcknowledgement = await runConfiguredCli([...common, "--dry-run"]);
    expect(noAcknowledgement.exitCode).toBe(1);
    expect(noAcknowledgement.stderr).toContain("--acknowledge-verified-reference is required");
  });

  test("forwards repeatable reviewed active-source deferrals and requires their acknowledgement", async () => {
    const sandbox = temporaryDirectory();
    const source = join(sandbox, "source");
    const engagement = join(source, "assessment-a");
    const stable = join(engagement, "notes", "stable.md");
    const activeLog = join(engagement, "logs", "listener.log");
    const activeSession = join(engagement, "logs", "session.jsonl");
    const configurationPath = join(sandbox, "config", "historical-source-roots.json");
    const databasePath = join(sandbox, "canonical.sqlite");
    const output = join(sandbox, "dry-run-output");

    mkdirSync(dirname(stable), { recursive: true });
    mkdirSync(dirname(activeLog), { recursive: true });
    writeFileSync(stable, "Stable service-version observation.\n", { mode: 0o600 });
    const settledAt = new Date(Date.now() - 120_000);
    utimesSync(stable, settledAt, settledAt);
    writeFileSync(activeLog, "Live listener output.\n", { mode: 0o600 });
    writeFileSync(activeSession, '{"event":"live provider turn"}\n', { mode: 0o600 });
    writeConfiguration(configurationPath, configuration([{ id: "source", path: source }]));
    createCanonicalDatabase(databasePath);

    const common = [
      "--config", configurationPath,
      "--config-sha256", sha256(configurationPath),
      "--db", databasePath,
      "--output", output,
      "--settle-seconds", "60",
      "--acknowledge-verified-reference",
      "--acknowledge-attack-knowledge-only",
      "--defer-active-source", activeLog,
      "--defer-active-source", activeSession,
      "--dry-run",
    ];
    const missingAcknowledgement = await runConfiguredCli(common);
    expect(missingAcknowledgement.exitCode).toBe(1);
    expect(missingAcknowledgement.stderr).toContain(
      "--acknowledge-active-source-deferrals is required because explicitly deferred files are omitted",
    );

    const result = await runConfiguredCli([
      ...common,
      "--acknowledge-active-source-deferrals",
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    const summary = JSON.parse(result.stdout) as { reportPath: string };
    const report = JSON.parse(readFileSync(summary.reportPath, "utf8")) as {
      settledSourceBoundary: {
        deferredObjects: number;
        deferredReasonCounts: Record<string, number>;
      };
      excluded: readonly { absolutePath: string; reason: string }[];
    };
    expect(report.settledSourceBoundary.deferredObjects).toBe(2);
    expect(report.settledSourceBoundary.deferredReasonCounts[EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON]).toBe(2);
    expect(report.excluded).toEqual(expect.arrayContaining([
      {
        absolutePath: resolve(activeLog),
        reason: `deferred_recent: ${EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON}`,
      },
      {
        absolutePath: resolve(activeSession),
        reason: `deferred_recent: ${EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON}`,
      },
    ]));

    const acknowledgementWithoutPaths = await runConfiguredCli([
      ...common.filter((value, index, values) =>
        value !== "--defer-active-source" && values[index - 1] !== "--defer-active-source"),
      "--acknowledge-active-source-deferrals",
    ]);
    expect(acknowledgementWithoutPaths.exitCode).toBe(1);
    expect(acknowledgementWithoutPaths.stderr).toContain(
      "--acknowledge-active-source-deferrals requires at least one --defer-active-source path",
    );

    const helpResult = await runConfiguredCli(["--help"]);
    expect(helpResult.exitCode).toBe(0);
    expect(helpResult.stdout).toContain("--defer-active-source PATH ...");
    expect(helpResult.stdout).toContain("identical paths must be repeated for resume");
  });

  test("imports mixed v2 roots with bounded provider and Markdown coverage", async () => {
    const sandbox = temporaryDirectory();
    const parent = join(sandbox, "engagements");
    const explicit = join(sandbox, "single-engagement");
    const provider = join(sandbox, ".claude", "projects");
    const hermes = join(sandbox, "hermes");
    const configurationPath = join(sandbox, "config", "historical-source-roots.v2.json");
    const databasePath = join(sandbox, "canonical.sqlite");
    const output = join(sandbox, "dry-run-output");

    mkdirSync(join(parent, "assessment-a", "notes"), { recursive: true });
    writeFileSync(
      join(parent, "assessment-a", "notes", "stack.md"),
      "nginx 1.24.0 was confirmed before path traversal validation.\n",
    );
    mkdirSync(join(explicit, "notes"), { recursive: true });
    writeFileSync(
      join(explicit, "notes", "stack.md"),
      "Apache HTTP Server 2.4.58 required a bounded recovery check.\n",
    );
    mkdirSync(join(provider, "project-a"), { recursive: true });
    writeFileSync(
      join(provider, "project-a", "session.jsonl"),
      `${JSON.stringify({ message: "OpenSSH 9.2 path traversal failed, then reset and verify health" })}\n`,
    );
    mkdirSync(join(hermes, "conversations"), { recursive: true });
    writeFileSync(
      join(hermes, "conversations", "history.md"),
      "# Historical analysis\n\nPostgreSQL 15.4 authentication bypass was reported as successful.\n",
    );
    writeFileSync(join(hermes, "unknown.bin"), "unsupported but counted");
    writeFileSync(join(hermes, "state.db"), "SQLite fixture is intentionally active");
    writeFileSync(join(hermes, "state.db-wal"), "active-wal");
    mkdirSync(join(hermes, "projected-vault", ".obsidian"), { recursive: true });
    writeFileSync(join(hermes, "projected-vault", "projection.md"), "must not feed back");

    writeConfiguration(configurationPath, configurationV2([
      { id: "parent", path: parent, mode: "children" },
      { id: "explicit", path: explicit, mode: "engagement-root" },
      { id: "provider", path: provider, mode: "history-root" },
      { id: "hermes", path: hermes, mode: "history-root" },
    ]));
    createCanonicalDatabase(databasePath);

    const result = await runConfiguredCli([
      "--config", configurationPath,
      "--config-sha256", sha256(configurationPath),
      "--db", databasePath,
      "--output", output,
      "--acknowledge-verified-reference",
      "--acknowledge-attack-knowledge-only",
      "--dry-run",
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    const summary = JSON.parse(result.stdout) as {
      reportPath: string;
      genericSourceDiscovery: {
        supplementalHistoryRoots: number;
        classifiedFiles: number;
        unsupportedFiles: number;
        activeSqliteFiles: number;
        vaultProjectionDirectories: number;
      };
      attackKnowledge: { genericSourcesDiscovered: number };
    };
    const report = JSON.parse(readFileSync(summary.reportPath, "utf8")) as {
      engagementDiscovery: { manifests: number };
      sources: readonly { type: string }[];
    };
    expect(report.engagementDiscovery.manifests).toBe(2);
    expect(report.sources.map(({ type }) => type)).toEqual(expect.arrayContaining([
      "provider_session_jsonl",
      "conversation_markdown",
    ]));
    expect(summary.genericSourceDiscovery).toMatchObject({
      supplementalHistoryRoots: 2,
      unsupportedFiles: 1,
      activeSqliteFiles: 1,
      vaultProjectionDirectories: 1,
    });
    expect(summary.genericSourceDiscovery.classifiedFiles).toBeGreaterThanOrEqual(3);
    expect(summary.attackKnowledge.genericSourcesDiscovered).toBe(2);
  });
});

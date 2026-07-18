import { afterEach, describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../../memory";
import { ObsidianVaultBridge, VaultPathPolicy } from "../../vault";
import { LegacyMigrationService } from "../LegacyMigrationService";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const path = mkdtempSync(join(tmpdir(), "ti-scale-import-vault-cli-"));
  temporaryDirectories.push(path);
  return path;
}

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

function markdownFiles(root: string): string[] {
  const found: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && entry.name.endsWith(".md")) found.push(path);
    }
  };
  visit(root);
  return found.sort();
}

async function runCli(args: readonly string[]): Promise<{
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}> {
  const process = Bun.spawn([
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
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
    process.exited,
  ]);
  return { exitCode, stdout, stderr };
}

describe("approved legacy Vault projection CLI", () => {
  test("previews without writes, binds approval to both hashes, then projects idempotently", async () => {
    const root = temporaryDirectory();
    const databasePath = join(root, "ti-scale.sqlite");
    const sourceRoot = join(root, "historical-engagements");
    const migrationOutput = join(root, "migration-output");
    const vaultSandbox = join(root, "vaults");
    const engagement = join(sourceRoot, "reapertwo");
    mkdirSync(join(engagement, "notes"), { recursive: true });
    mkdirSync(join(engagement, "scans"), { recursive: true });
    mkdirSync(join(engagement, "evidence"), { recursive: true });
    mkdirSync(vaultSandbox, { recursive: true });
    writeFileSync(
      join(engagement, "notes", "summary.md"),
      "Authorized historical assessment summary with no retained credentials.\n",
      { mode: 0o600 },
    );
    writeFileSync(
      join(engagement, "scans", "discovery.nmap"),
      "Host web-01 was observed with tcp/443 open.\n",
      { mode: 0o600 },
    );
    writeFileSync(
      join(engagement, "evidence", "service-proof.txt"),
      "Historical service observation requires operator verification.\n",
      { mode: 0o600 },
    );

    const canonical = createDatabaseConnection({ filename: databasePath });
    try { migrateDatabase(canonical); }
    finally { canonical.close(); }

    const migration = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [sourceRoot],
      outputDirectory: migrationOutput,
      clock: () => new Date("2026-07-17T10:00:00.000Z"),
    }).run();

    const setup = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    let reconciliationHash: string;
    let vaultPath: string;
    try {
      reconciliationHash = (setup.prepare(`
        SELECT report_hash FROM legacy_migration_reconciliation WHERE migration_id = ?
      `).get(migration.migrationId) as { report_hash: string }).report_hash;
      const bridge = new ObsidianVaultBridge(
        setup,
        new MemoryRepository(setup),
        new VaultPathPolicy(vaultSandbox),
        { clock: () => new Date("2026-07-17T10:01:00.000Z") },
      );
      vaultPath = bridge.connect({
        id: "vault-reapertwo",
        vaultPath: "Ti-Scale-Brain",
        displayName: "Ti-Scale Brain",
        permissionGranted: true,
      }).vaultPath;
    } finally {
      setup.close();
    }

    expect(markdownFiles(vaultPath!)).toHaveLength(0);
    const common = [
      "--db", databasePath,
      "--vault-root", vaultSandbox,
      "--migration-id", migration.migrationId,
      "--reconciliation-hash", reconciliationHash!,
      "--connection", "vault-reapertwo",
    ];
    const previewRun = await runCli(["project-vault", ...common, "--dry-run"]);
    expect(previewRun.exitCode).toBe(0);
    expect(previewRun.stderr).toBe("");
    const preview = JSON.parse(previewRun.stdout) as {
      status: string;
      dryRun: boolean;
      projectionHash: string;
      counts: { mapped: number; eligible: number; excludedByPolicyOrConnectionScope: number };
    };
    expect(preview).toMatchObject({ status: "ready_for_approval", dryRun: true });
    expect(preview.projectionHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(preview.counts.eligible).toBeGreaterThanOrEqual(6);
    expect(preview.counts.excludedByPolicyOrConnectionScope).toBe(1);
    expect(markdownFiles(vaultPath!)).toHaveLength(0);

    const afterPreview = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect(afterPreview.prepare(`
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name = 'legacy_vault_projection_approvals'
      `).get()).toBeNull();
    } finally { afterPreview.close(); }

    const unapproved = await runCli([
      "project-vault", ...common,
      "--projection-hash", preview.projectionHash,
      "--approved-by", "operator:test",
    ]);
    expect(unapproved.exitCode).toBe(1);
    expect(unapproved.stderr).toContain("--approve-projection");
    expect(markdownFiles(vaultPath!)).toHaveLength(0);

    const changedSelection = await runCli([
      "project-vault", ...common,
      "--projection-hash", "0".repeat(64),
      "--approved-by", "operator:test",
      "--approve-projection",
    ]);
    expect(changedSelection.exitCode).toBe(1);
    expect(changedSelection.stderr).toContain("Projection hash does not match");
    expect(markdownFiles(vaultPath!)).toHaveLength(0);

    const appliedRun = await runCli([
      "project-vault", ...common,
      "--projection-hash", preview.projectionHash,
      "--approved-by", "operator:test",
      "--approve-projection",
    ]);
    expect(appliedRun.exitCode).toBe(0);
    expect(appliedRun.stderr).toBe("");
    const applied = JSON.parse(appliedRun.stdout) as {
      status: string;
      approvalId: string;
      projectionHash: string;
      projectedNodes: number;
      export: { counts: { failed: number; conflicts: number } };
    };
    expect(applied).toMatchObject({
      status: "completed",
      projectionHash: preview.projectionHash,
      projectedNodes: preview.counts.eligible,
      export: { counts: { failed: 0, conflicts: 0 } },
    });
    const projectedNotes = markdownFiles(vaultPath!);
    expect(projectedNotes).toHaveLength(applied.projectedNodes);
    expect(projectedNotes.map((path) => readFileSync(path, "utf8")).join("\n")).toContain("[[");

    const verified = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect(verified.prepare(`
        SELECT migration_id, reconciliation_hash, projection_hash, connection_id,
          approved_by, status, json_array_length(projected_node_ids_json) AS projected_nodes
        FROM legacy_vault_projection_approvals
      `).get()).toEqual({
        migration_id: migration.migrationId,
        reconciliation_hash: reconciliationHash!,
        projection_hash: preview.projectionHash,
        connection_id: "vault-reapertwo",
        approved_by: "operator:test",
        status: "completed",
        projected_nodes: preview.counts.eligible,
      });
    } finally { verified.close(); }

    const replay = await runCli([
      "project-vault", ...common,
      "--projection-hash", preview.projectionHash,
      "--approved-by", "operator:test",
      "--approve-projection",
    ]);
    expect(replay.exitCode).toBe(0);
    const replayed = JSON.parse(replay.stdout) as { projectedNodes: number; export: { counts: { skipped: number } } };
    expect(replayed.projectedNodes).toBe(applied.projectedNodes);
    expect(replayed.export.counts.skipped).toBe(applied.projectedNodes);
    expect(markdownFiles(vaultPath!)).toHaveLength(applied.projectedNodes);
  });
});

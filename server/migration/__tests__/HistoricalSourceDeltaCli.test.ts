import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION } from "../HistoricalSourceRootConfiguration";

const sandboxes: string[] = [];

afterEach(() => {
  for (const sandbox of sandboxes.splice(0)) rmSync(sandbox, { recursive: true, force: true });
});

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

async function run(script: string, args: readonly string[]) {
  const child = Bun.spawn([process.execPath, "run", script, ...args], {
    cwd: process.cwd(),
    env: process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { stdout, stderr, exitCode };
}

describe("historical source delta CLI", () => {
  test("seals a reviewed private plan and configured dry-run consumes only that exact batch", async () => {
    const sandbox = mkdtempSync(join(tmpdir(), "ti-scale-delta-cli-"));
    sandboxes.push(sandbox);
    const historyRoot = join(sandbox, "history");
    const source = join(historyRoot, "one", "runtime", "events.jsonl");
    const configDirectory = join(sandbox, "config");
    const planDirectory = join(sandbox, "plans");
    const configPath = join(configDirectory, "historical-roots.json");
    const planPath = join(planDirectory, "delta.private.json");
    const databasePath = join(sandbox, "canonical.sqlite");
    mkdirSync(join(source, ".."), { recursive: true, mode: 0o700 });
    mkdirSync(configDirectory, { recursive: true, mode: 0o700 });
    mkdirSync(planDirectory, { recursive: true, mode: 0o700 });
    writeFileSync(source, `${JSON.stringify({ message: "safe reviewed observation" })}\n`, { mode: 0o600 });
    const old = new Date(Date.now() - 10 * 60_000);
    utimesSync(source, old, old);
    writeFileSync(configPath, `${JSON.stringify({
      schemaVersion: HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
      configurationVersion: "delta-cli-test-v1",
      roots: [{ id: "history", path: historyRoot, mode: "history-root", required: true }],
    }, null, 2)}\n`, { mode: 0o600 });
    chmodSync(configPath, 0o600);
    const database = createDatabaseConnection({ filename: databasePath });
    migrateDatabase(database);
    database.close();

    const planned = await run("server/migration/historical-source-delta-cli.ts", [
      "--config", configPath,
      "--config-sha256", sha256(configPath),
      "--db", databasePath,
      "--settle-seconds", "60",
      "--private-plan-output", planPath,
      "--acknowledge-private-source-paths",
      "--dry-run",
    ]);
    expect(planned.exitCode).toBe(0);
    expect(planned.stderr).toBe("");
    const publicResult = JSON.parse(planned.stdout) as {
      readonly delta: { readonly files: number };
      readonly sealedExecutionPlan: { readonly sourceSha256: string; readonly admittedFiles: number };
    };
    expect(publicResult.delta.files).toBe(1);
    expect(publicResult.sealedExecutionPlan).toMatchObject({
      sourceSha256: sha256(planPath),
      admittedFiles: 1,
    });
    expect(planned.stdout).not.toContain(historyRoot);
    const aggregateReceiptPath = join(planDirectory, "aggregate-public-receipt.json");
    writeFileSync(aggregateReceiptPath, planned.stdout, { mode: 0o600 });
    const aggregateAttempt = await run("server/migration/configured-historical-cli.ts", [
      "--config", configPath,
      "--config-sha256", sha256(configPath),
      "--db", databasePath,
      "--output", join(sandbox, "aggregate-rejected"),
      "--settle-seconds", "60",
      "--reviewed-source-delta-plan", aggregateReceiptPath,
      "--reviewed-source-delta-plan-sha256", sha256(aggregateReceiptPath),
      "--acknowledge-reviewed-source-delta",
      "--acknowledge-verified-reference",
      "--acknowledge-attack-knowledge-only",
      "--dry-run",
    ]);
    expect(aggregateAttempt.exitCode).toBe(1);
    expect(aggregateAttempt.stderr).toContain("Historical source delta execution plan");

    const unreviewed = join(historyRoot, "two", "runtime", "events.jsonl");
    mkdirSync(join(unreviewed, ".."), { recursive: true, mode: 0o700 });
    writeFileSync(unreviewed, `${JSON.stringify({ message: "unreviewed later observation" })}\n`, { mode: 0o600 });
    utimesSync(unreviewed, old, old);
    const migrated = await run("server/migration/configured-historical-cli.ts", [
      "--config", configPath,
      "--config-sha256", sha256(configPath),
      "--db", databasePath,
      "--output", join(sandbox, "dry-run-output"),
      "--settle-seconds", "60",
      "--reviewed-source-delta-plan", planPath,
      "--reviewed-source-delta-plan-sha256", sha256(planPath),
      "--acknowledge-reviewed-source-delta",
      "--acknowledge-verified-reference",
      "--acknowledge-attack-knowledge-only",
      "--dry-run",
    ]);
    expect(migrated.exitCode).toBe(0);
    expect(migrated.stderr).toBe("");
    const summary = JSON.parse(migrated.stdout) as {
      readonly reportPath: string;
      readonly genericSourceDiscovery: { readonly scannedFiles: number; readonly includedFiles: number };
    };
    expect(summary.genericSourceDiscovery).toMatchObject({ scannedFiles: 1, includedFiles: 1 });
    const report = readFileSync(summary.reportPath, "utf8");
    expect(report).toContain(source);
    expect(report).not.toContain(unreviewed);
  }, 30_000);
});

#!/usr/bin/env bun
import { resolveCliDatabasePath, type TiScaleCliEnvironment } from "../app/StandaloneCliConfiguration";
import { createDatabaseConnection } from "../db";
import { canonicalJson } from "../orchestration/serialization";
import { HistoricalAttackAttemptOutcomeDryRunPlanner } from "./HistoricalAttackAttemptOutcomeDryRunPlanner";

interface CliIo {
  readonly write?: (value: string) => void;
  readonly writeError?: (value: string) => void;
}

class UsageError extends Error {}

function help(): string {
  return `Ti-Scale historical AttackAttempt/outcome integrity audit

Usage:
  bun run server/migration/historical-attempt-outcome-dry-run-cli.ts audit
    --dry-run [--db PATH] [--after SHA256]
    [--max-records 1..1000] [--max-pages 1..1000]
    [--max-ms 1..3600000]

The database path may come from --db or TI_SCALE_DATABASE_PATH. The command
opens SQLite read-only and emits only counts, reason categories, cursors, and
SHA-256 receipts. It never returns historical paths or source content and
never creates an AttackAttempt or reusable outcome link.
`;
}

function value(tokens: readonly string[], name: string): string | undefined {
  const indexes = tokens.flatMap((token, index) => token === `--${name}` ? [index] : []);
  if (indexes.length > 1) throw new UsageError(`--${name} may be supplied only once`);
  const index = indexes[0];
  if (index === undefined) return undefined;
  const result = tokens[index + 1];
  if (!result || result.startsWith("--")) throw new UsageError(`--${name} requires one value`);
  return result;
}

function integer(tokens: readonly string[], name: string): number | undefined {
  const raw = value(tokens, name);
  if (raw === undefined) return undefined;
  if (!/^\d+$/u.test(raw)) throw new UsageError(`--${name} must be a positive integer`);
  return Number(raw);
}

function assertKnown(tokens: readonly string[]): void {
  const valued = new Set(["--db", "--after", "--max-records", "--max-pages", "--max-ms"]);
  const flags = new Set(["--dry-run"]);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (valued.has(token)) {
      index += 1;
      continue;
    }
    if (flags.has(token)) continue;
    throw new UsageError(`Unsupported audit option: ${token}`);
  }
}

export async function runHistoricalAttemptOutcomeDryRunCli(
  argv: readonly string[] = process.argv.slice(2),
  environment: TiScaleCliEnvironment = process.env,
  io: CliIo = {},
): Promise<number> {
  const write = io.write ?? ((value: string) => process.stdout.write(value));
  const writeError = io.writeError ?? ((value: string) => process.stderr.write(value));
  const [command = "help", ...tokens] = argv;
  if (["help", "--help", "-h"].includes(command)) {
    write(help());
    return 0;
  }
  if (command !== "audit") {
    writeError(`${help()}\nUnsupported command: ${command}\n`);
    return 2;
  }
  try {
    assertKnown(tokens);
    if (!tokens.includes("--dry-run")) {
      throw new UsageError("--dry-run is required; this command has no mutation mode");
    }
    const databasePath = resolveCliDatabasePath(value(tokens, "db"), environment);
    const database = createDatabaseConnection({
      filename: databasePath,
      readonly: true,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    try {
      const report = new HistoricalAttackAttemptOutcomeDryRunPlanner(database).audit({
        afterBundleFingerprint: value(tokens, "after"),
        maxRecordsPerPage: integer(tokens, "max-records"),
        maxPages: integer(tokens, "max-pages"),
        maxDurationMs: integer(tokens, "max-ms"),
      });
      write(`${canonicalJson(report)}\n`);
      return report.status === "completed" ? 0 : 3;
    } finally {
      database.close();
    }
  } catch (error) {
    writeError(`${error instanceof Error ? error.message : String(error)}\n`);
    return error instanceof UsageError ? 2 : 1;
  }
}

if (import.meta.main) {
  process.exitCode = await runHistoricalAttemptOutcomeDryRunCli();
}

#!/usr/bin/env bun
import { dirname, resolve } from "node:path";
import { createDatabaseConnection } from "../db";
import {
  loadTrustedHistoricalSourceRootConfiguration,
} from "./HistoricalSourceRootConfiguration";
import { HistoricalSourceDeltaPlanner } from "./HistoricalSourceDeltaPlanner";
import { sealHistoricalSourceDeltaExecutionPlan } from "./HistoricalSourceDeltaExecutionPlan";
import { loadHistoricalSqliteSnapshotQuarantineMapping } from "./HistoricalSqliteSnapshotQuarantineMapping";
import { redactLegacyText } from "./SecretSafety";

interface Arguments {
  readonly values: ReadonlyMap<string, string>;
  readonly flags: ReadonlySet<string>;
}

const VALUE_OPTIONS = new Set([
  "config",
  "config-sha256",
  "db",
  "settle-seconds",
  "sqlite-snapshot-receipt",
  "sqlite-snapshot-receipt-sha256",
  "private-plan-output",
]);
const FLAG_OPTIONS = new Set(["acknowledge-private-source-paths", "dry-run", "help"]);

function help(): string {
  return `Ti-Scale historical source delta planner

Usage:
  bun run history:plan-delta -- --config PATH --config-sha256 SHA256 \\
    --db PATH --settle-seconds 60..86400 --dry-run \\
    [--private-plan-output PATH --acknowledge-private-source-paths]

Optional exact SQLite quarantine mapping:
  --sqlite-snapshot-receipt PATH --sqlite-snapshot-receipt-sha256 SHA256

Safety:
  This command opens the canonical database read-only, reads source files
  through the canonical stable-file discovery policy, and writes nothing to
  the database, source roots, service, or Obsidian Vault. Output contains only
  aggregate root IDs, parser/sensitivity classes, counts, and inventory hashes;
  source paths and source content are never returned.
  --private-plan-output creates one exclusive mode-0600 local-only plan with
  exact paths and identities. Its reviewed byte hash is required by the delta
  importer; aggregate output is never executable.
`;
}

function parse(argv: readonly string[]): Arguments {
  const values = new Map<string, string>();
  const flags = new Set<string>();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index]!;
    if (!token.startsWith("--")) throw new Error("Positional arguments are unsupported");
    const name = token.slice(2);
    if (FLAG_OPTIONS.has(name)) {
      if (flags.has(name)) throw new Error(`--${name} may be supplied only once`);
      flags.add(name);
      continue;
    }
    if (!VALUE_OPTIONS.has(name)) throw new Error(`Unsupported option: --${name}`);
    if (values.has(name)) throw new Error(`--${name} may be supplied only once`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`--${name} requires one value`);
    values.set(name, value);
    index += 1;
  }
  return { values, flags };
}

function required(args: Arguments, name: string): string {
  const value = args.values.get(name)?.trim();
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

export async function runHistoricalSourceDeltaCli(
  argv = process.argv.slice(2),
): Promise<number> {
  const args = parse(argv);
  if (args.flags.has("help")) {
    process.stdout.write(help());
    return 0;
  }
  if (!args.flags.has("dry-run")) {
    throw new Error("--dry-run is required; this planner has no mutation mode");
  }
  const configurationSha256 = required(args, "config-sha256").toLowerCase();
  if (!/^[a-f0-9]{64}$/u.test(configurationSha256)) {
    throw new Error("--config-sha256 must be a lowercase SHA-256");
  }
  const settleRaw = required(args, "settle-seconds");
  if (!/^\d+$/u.test(settleRaw)) throw new Error("--settle-seconds must be an integer");
  const settleSeconds = Number(settleRaw);
  const configurationPath = resolve(required(args, "config"));
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const loaded = loadTrustedHistoricalSourceRootConfiguration({
    path: configurationPath,
    trustRoot: dirname(configurationPath),
    expectedSha256: configurationSha256,
    allowedOwnerUids: currentUid === 0 ? [0] : [0, currentUid],
  });
  const sqliteReceipt = args.values.get("sqlite-snapshot-receipt");
  const sqliteReceiptSha256 = args.values.get("sqlite-snapshot-receipt-sha256")?.trim().toLowerCase();
  if (Boolean(sqliteReceipt) !== Boolean(sqliteReceiptSha256)) {
    throw new Error(
      "--sqlite-snapshot-receipt and --sqlite-snapshot-receipt-sha256 must be supplied together",
    );
  }
  if (sqliteReceiptSha256 && !/^[a-f0-9]{64}$/u.test(sqliteReceiptSha256)) {
    throw new Error("--sqlite-snapshot-receipt-sha256 must be a lowercase SHA-256");
  }
  const sqliteSnapshotQuarantineMappings = sqliteReceipt && sqliteReceiptSha256
    ? [await loadHistoricalSqliteSnapshotQuarantineMapping({
      receipt: {
        path: resolve(sqliteReceipt),
        trustRoot: dirname(resolve(sqliteReceipt)),
        expectedSha256: sqliteReceiptSha256,
        allowedOwnerUids: currentUid === 0 ? [0] : [0, currentUid],
        maximumBytes: 64 * 1024,
      },
      allowedSourceRoots: loaded.value.roots.map(({ path }) => path),
    })]
    : [];
  const database = createDatabaseConnection({
    filename: resolve(required(args, "db")),
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const privatePlanOutput = args.values.get("private-plan-output");
    if (privatePlanOutput && !args.flags.has("acknowledge-private-source-paths")) {
      throw new Error("--acknowledge-private-source-paths is required to seal a path-bearing plan");
    }
    if (!privatePlanOutput && args.flags.has("acknowledge-private-source-paths")) {
      throw new Error("Private source-path acknowledgement requires --private-plan-output");
    }
    const planner = new HistoricalSourceDeltaPlanner(database);
    const plannerInput = {
      configuration: loaded.value,
      configurationSha256,
      settleSeconds,
      ...(sqliteSnapshotQuarantineMappings.length > 0
        ? { sqliteSnapshotQuarantineMappings }
        : {}),
    };
    if (privatePlanOutput) {
      const planned = await planner.planForExecution(plannerInput);
      const sealed = sealHistoricalSourceDeltaExecutionPlan({
        path: resolve(privatePlanOutput),
        plan: planned.executionPlan,
        sourceRoots: loaded.value.roots.map(({ path }) => path),
      });
      process.stdout.write(`${JSON.stringify({
        ...planned.publicPlan,
        sealedExecutionPlan: {
          sourceSha256: sealed.sourceSha256,
          planHash: sealed.planHash,
          byteSize: sealed.byteSize,
          mode: sealed.mode,
          admittedFiles: planned.executionPlan.delta.files,
          admittedBytes: planned.executionPlan.delta.bytes,
        },
      }, null, 2)}\n`);
      return 0;
    }
    const result = await planner.plan(plannerInput);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result.status === "blocked_active_sqlite" ? 2 : 0;
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  runHistoricalSourceDeltaCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(
      `Historical source delta planning failed: ${redactLegacyText(error instanceof Error ? error.message : String(error), 1_000)}\n`,
    );
    process.exitCode = 1;
  });
}

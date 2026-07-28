#!/usr/bin/env bun
import { dirname, resolve } from "node:path";
import {
  loadTrustedHistoricalSourceRootConfiguration,
  resolveRequiredHistoricalSourceRoots,
} from "./HistoricalSourceRootConfiguration";
import { runMigrationCli } from "./cli";
import { redactLegacyText } from "./SecretSafety";

interface ParsedArguments {
  readonly values: ReadonlyMap<string, string>;
  readonly repeatableValues: ReadonlyMap<string, readonly string[]>;
  readonly flags: ReadonlySet<string>;
}

const VALUE_OPTIONS = new Set([
  "config",
  "config-sha256",
  "db",
  "output",
  "reviewed-source-delta-plan",
  "reviewed-source-delta-plan-sha256",
  "resume",
  "settle-seconds",
  "sqlite-snapshot-receipt",
  "sqlite-snapshot-receipt-sha256",
]);
const REPEATABLE_VALUE_OPTIONS = new Set([
  "defer-active-source",
]);
const FLAG_OPTIONS = new Set([
  "acknowledge-active-source-deferrals",
  "acknowledge-attack-knowledge-only",
  "acknowledge-verified-reference",
  "bounded-resume",
  "dry-run",
  "execute",
  "help",
  "acknowledge-empty-sqlite-snapshot-quarantine",
  "acknowledge-reviewed-source-delta",
]);
const SHA256 = /^[a-f0-9]{64}$/u;

function help(): string {
  return `Ti-Scale configured historical attack-knowledge migration

Usage:
  bun run history:migrate-configured -- --config PATH --config-sha256 SHA256 \\
    --db PATH --output DIR --settle-seconds 60..86400 \\
    --acknowledge-verified-reference --acknowledge-attack-knowledge-only \\
    [--defer-active-source PATH ... --acknowledge-active-source-deferrals] \\
    [--sqlite-snapshot-receipt PATH --sqlite-snapshot-receipt-sha256 SHA256 \\
      --acknowledge-empty-sqlite-snapshot-quarantine] \\
    [--reviewed-source-delta-plan PATH --reviewed-source-delta-plan-sha256 SHA256 \\
      --acknowledge-reviewed-source-delta] \\
    (--dry-run | --execute) [--resume MIGRATION_ID --bounded-resume]

Safety:
  The configuration is a hash-pinned, strict list of required source roots.
  children roots discover safe direct-child engagements; engagement-root
  entries import exactly one engagement; history-root entries ingest only
  deterministic runtime/provider history and never infer engagements.
  Missing roots fail closed; physical aliases are collapsed by device/inode.
  Attack-knowledge-only extraction retains private source provenance, rejects
  secret-bearing reusable content, and never fabricates cross-source edges.
  --dry-run uses a disposable database for semantic preview and never writes
  the configured canonical database or Obsidian Vault.
  --defer-active-source is repeatable and narrowly omits an exact reviewed
  live file only when the migration boundary proves it is recent or currently
  held open for write. It requires the explicit acknowledgement, and the
  identical paths must be repeated for resume.
  --bounded-resume continues an already captured migration from its latest
  immutable extractor cursor and closes SQLite after every bounded page.
  A reviewed source-delta plan is a private mode-0600 exact-file admission;
  aggregate delta output alone cannot authorize dry-run or execution.
`;
}

function parseArguments(argv: readonly string[]): ParsedArguments {
  const values = new Map<string, string>();
  const repeatableValues = new Map<string, string[]>();
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
    if (REPEATABLE_VALUE_OPTIONS.has(name)) {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error("--" + name + " requires one value");
      }
      repeatableValues.set(name, [...(repeatableValues.get(name) ?? []), value]);
      index += 1;
      continue;
    }
    if (!VALUE_OPTIONS.has(name)) throw new Error(`Unsupported option: --${name}`);
    if (values.has(name)) throw new Error(`--${name} may be supplied only once`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`--${name} requires one value`);
    values.set(name, value);
    index += 1;
  }
  return { values, repeatableValues, flags };
}

function required(args: ParsedArguments, name: string): string {
  const value = args.values.get(name)?.trim();
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

export async function runConfiguredHistoricalMigrationCli(
  argv = process.argv.slice(2),
): Promise<number> {
  const args = parseArguments(argv);
  if (args.flags.has("help")) {
    process.stdout.write(help());
    return 0;
  }
  const dryRun = args.flags.has("dry-run");
  const execute = args.flags.has("execute");
  if (dryRun === execute) {
    throw new Error("Select exactly one of --dry-run or --execute");
  }
  for (const acknowledgement of [
    "acknowledge-verified-reference",
    "acknowledge-attack-knowledge-only",
  ]) {
    if (!args.flags.has(acknowledgement)) {
      throw new Error(`--${acknowledgement} is required`);
    }
  }
  if (dryRun && args.values.has("resume")) {
    throw new Error("--resume is available only with --execute");
  }
  if (args.flags.has("bounded-resume") && (!execute || !args.values.has("resume"))) {
    throw new Error("--bounded-resume requires --execute and --resume MIGRATION_ID");
  }
  const activeSourceDeferrals = args.repeatableValues.get("defer-active-source") ?? [];
  if (activeSourceDeferrals.length > 0 && !args.flags.has("acknowledge-active-source-deferrals")) {
    throw new Error(
      "--acknowledge-active-source-deferrals is required because explicitly deferred files are omitted from this migration receipt",
    );
  }
  if (args.flags.has("acknowledge-active-source-deferrals") && activeSourceDeferrals.length === 0) {
    throw new Error(
      "--acknowledge-active-source-deferrals requires at least one --defer-active-source path",
    );
  }
  const sqliteSnapshotReceipt = args.values.get("sqlite-snapshot-receipt");
  const sqliteSnapshotReceiptSha256 = args.values.get("sqlite-snapshot-receipt-sha256")?.toLowerCase();
  if (Boolean(sqliteSnapshotReceipt) !== Boolean(sqliteSnapshotReceiptSha256)) {
    throw new Error(
      "--sqlite-snapshot-receipt and --sqlite-snapshot-receipt-sha256 must be supplied together",
    );
  }
  if (sqliteSnapshotReceiptSha256 && !SHA256.test(sqliteSnapshotReceiptSha256)) {
    throw new Error("--sqlite-snapshot-receipt-sha256 must be a lowercase SHA-256");
  }
  if (sqliteSnapshotReceipt && !args.flags.has("acknowledge-empty-sqlite-snapshot-quarantine")) {
    throw new Error(
      "--acknowledge-empty-sqlite-snapshot-quarantine is required for receipt-bound content-free custody",
    );
  }
  if (!sqliteSnapshotReceipt && args.flags.has("acknowledge-empty-sqlite-snapshot-quarantine")) {
    throw new Error(
      "SQLite snapshot quarantine acknowledgement requires a receipt and reviewed SHA-256",
    );
  }
  const expectedSha256 = required(args, "config-sha256").toLowerCase();
  if (!SHA256.test(expectedSha256)) {
    throw new Error("--config-sha256 must be a lowercase SHA-256");
  }
  const configurationPath = resolve(required(args, "config"));
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const loaded = loadTrustedHistoricalSourceRootConfiguration({
    path: configurationPath,
    trustRoot: dirname(configurationPath),
    expectedSha256,
    allowedOwnerUids: currentUid === 0 ? [0] : [0, currentUid],
  });
  const roots = resolveRequiredHistoricalSourceRoots(loaded.value);
  const reviewedDeltaPlan = args.values.get("reviewed-source-delta-plan");
  const reviewedDeltaPlanSha256 = args.values.get("reviewed-source-delta-plan-sha256")?.toLowerCase();
  if (Boolean(reviewedDeltaPlan) !== Boolean(reviewedDeltaPlanSha256)) {
    throw new Error(
      "--reviewed-source-delta-plan and --reviewed-source-delta-plan-sha256 must be supplied together",
    );
  }
  if (reviewedDeltaPlanSha256 && !SHA256.test(reviewedDeltaPlanSha256)) {
    throw new Error("--reviewed-source-delta-plan-sha256 must be a lowercase SHA-256");
  }
  if (reviewedDeltaPlan && !args.flags.has("acknowledge-reviewed-source-delta")) {
    throw new Error("--acknowledge-reviewed-source-delta is required for exact-file execution");
  }
  if (!reviewedDeltaPlan && args.flags.has("acknowledge-reviewed-source-delta")) {
    throw new Error("Reviewed source-delta acknowledgement requires a sealed plan and reviewed hash");
  }
  const delegated = [
    "migrate",
    ...roots.childrenRoots.flatMap((root) => ["--source", root]),
    ...roots.engagementRoots.flatMap((root) => ["--engagement-root", root]),
    ...roots.historyRoots.flatMap((root) => ["--history-root", root]),
    "--db", resolve(required(args, "db")),
    "--output", resolve(required(args, "output")),
    "--source-retention", "verified-reference",
    "--acknowledge-verified-reference",
    "--brain-projection", "attack-knowledge-only",
    "--acknowledge-attack-knowledge-only",
    "--summary-output",
    ...(args.values.has("settle-seconds")
      ? ["--settle-seconds", args.values.get("settle-seconds")!]
      : []),
    ...activeSourceDeferrals.flatMap((path) => ["--defer-active-source", resolve(path)]),
    ...(args.flags.has("acknowledge-active-source-deferrals")
      ? ["--acknowledge-active-source-deferrals"]
      : []),
    ...(sqliteSnapshotReceipt && sqliteSnapshotReceiptSha256 ? [
      "--sqlite-snapshot-receipt", resolve(sqliteSnapshotReceipt),
      "--sqlite-snapshot-receipt-sha256", sqliteSnapshotReceiptSha256,
      "--acknowledge-empty-sqlite-snapshot-quarantine",
    ] : []),
    ...(reviewedDeltaPlan && reviewedDeltaPlanSha256 ? [
      "--reviewed-source-delta-plan", resolve(reviewedDeltaPlan),
      "--reviewed-source-delta-plan-sha256", reviewedDeltaPlanSha256,
      "--reviewed-source-config-sha256", expectedSha256,
      "--acknowledge-reviewed-source-delta",
    ] : []),
    ...(dryRun ? ["--dry-run"] : []),
    ...(args.values.has("resume") ? ["--resume", args.values.get("resume")!] : []),
    ...(args.flags.has("bounded-resume") ? ["--bounded-resume"] : []),
  ];
  return runMigrationCli(delegated);
}

if (import.meta.main) {
  runConfiguredHistoricalMigrationCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(
      `Configured historical migration failed: ${redactLegacyText(error instanceof Error ? error.message : String(error), 1_000)}\n`,
    );
    process.exitCode = 1;
  });
}

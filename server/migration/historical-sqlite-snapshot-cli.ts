#!/usr/bin/env bun
import { resolve } from "node:path";
import { inspectHistoricalSqliteSource } from "./HistoricalSqliteSnapshotService";
import { canonicalJson } from "../orchestration/serialization";
import { redactLegacyText } from "./SecretSafety";

interface ParsedArguments {
  readonly command: "inspect" | "snapshot";
  readonly values: ReadonlyMap<string, string>;
  readonly flags: ReadonlySet<string>;
}

const VALUE_OPTIONS = new Set([
  "source",
  "source-root",
  "destination",
  "receipt",
  "expected-source-bundle-sha256",
]);
const FLAG_OPTIONS = new Set(["execute", "help"]);
function help(): string {
  return `Ti-Scale historical SQLite source inspection utility

Usage:
  bun run server/migration/historical-sqlite-snapshot-cli.ts inspect \\
    --source PATH --source-root PATH --destination PATH [--receipt PATH]

The inspect command is source-read-only and emits the exact DB/WAL/SHM bundle
hash to review. Historical SQLite snapshot creation is disabled by the
operator's no-backup policy; use forward-only verified-reference migration.
`;
}

function parseArguments(argv: readonly string[]): ParsedArguments {
  if (argv.length === 0 || argv[0] === "--help") {
    return { command: "inspect", values: new Map(), flags: new Set(["help"]) };
  }
  const command = argv[0];
  if (command !== "inspect" && command !== "snapshot") {
    throw new Error("First argument must be inspect or snapshot");
  }
  const values = new Map<string, string>();
  const flags = new Set<string>();
  for (let index = 1; index < argv.length; index += 1) {
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
  return { command, values, flags };
}

function required(arguments_: ParsedArguments, name: string): string {
  const value = arguments_.values.get(name)?.trim();
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

export async function runHistoricalSqliteSnapshotCli(
  argv = process.argv.slice(2),
): Promise<number> {
  const arguments_ = parseArguments(argv);
  if (arguments_.flags.has("help")) {
    process.stdout.write(help());
    return 0;
  }
  if (arguments_.command === "snapshot") {
    throw new Error(
      "Historical SQLite snapshot creation is disabled by operator no-backup policy; use forward-only verified-reference migration",
    );
  }
  const sourceDatabasePath = resolve(required(arguments_, "source"));
  const sourceContainmentRoot = resolve(required(arguments_, "source-root"));
  const destinationPath = resolve(required(arguments_, "destination"));
  const receiptValue = arguments_.values.get("receipt")?.trim();
  const receiptPath = receiptValue ? resolve(receiptValue) : undefined;
  if (arguments_.flags.has("execute")) throw new Error("--execute is invalid for inspect");
  const result = inspectHistoricalSqliteSource({
    sourceDatabasePath,
    sourceContainmentRoot,
    destinationPath,
    ...(receiptPath ? { receiptPath } : {}),
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
  return 0;
}

if (import.meta.main) {
  runHistoricalSqliteSnapshotCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(
      `Historical SQLite snapshot failed: ${redactLegacyText(
        error instanceof Error ? error.message : String(error),
        1_000,
      )}\n`,
    );
    process.exitCode = 1;
  });
}

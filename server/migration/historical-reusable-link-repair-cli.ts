#!/usr/bin/env bun
import { randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  openSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { resolveCliDatabasePath, type TiScaleCliEnvironment } from "../app/StandaloneCliConfiguration";
import { createDatabaseConnection } from "../db";
import { withCanonicalWriterLease } from "../maintenance";
import { canonicalJson } from "../orchestration/serialization";
import { HistoricalReusableKnowledgeLinkRepairService } from "./HistoricalReusableKnowledgeLinkRepairService";

interface CliIo {
  readonly cwd?: string;
  readonly write?: (value: string) => void;
}

class UsageError extends Error {}

const MAX_RELATIONSHIPS = 5_000;

function help(): string {
  return `Ti-Scale historical reusable-knowledge orphan-link repair

Usage:
  bun run brain:repair-historical-links:reconcile -- [--db PATH] [--output PATH]

  bun run brain:repair-historical-links:preview -- [--db PATH]
    --actor ACTOR --reason TEXT --dry-run
    [--after SHA256] [--max-relationships 1..5000] [--output PATH]

  bun run brain:repair-historical-links:execute -- [--db PATH]
    --actor ACTOR --reason TEXT --expected-preview-hash SHA256
    --acknowledge-reviewed-orphan-links --receipt PATH
    [--after SHA256] [--max-relationships 1..5000]

The database path may come from --db or TI_SCALE_DATABASE_PATH. Reconcile and
preview open SQLite read-only. Preview selects one deterministic bounded page;
execute must repeat the same actor, reason, cursor, page size, and exact preview
hash. Execute is fenced by the canonical writer lease and writes a mode-0600
receipt after the transaction commits.

This command never scans or re-extracts historical files. Run the existing
configured historical migration/re-extraction first with
"bun run history:migrate-configured -- <configured options>" so the current
parser can stage exact typed relationships. This repair never guesses links from titles,
co-occurrence, target names, addresses, mission IDs, or run IDs.
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

function required(tokens: readonly string[], name: string): string {
  const result = value(tokens, name)?.trim();
  if (!result) throw new UsageError(`--${name} is required`);
  return result;
}

function pageSize(tokens: readonly string[]): number | undefined {
  const raw = value(tokens, "max-relationships");
  if (raw === undefined) return undefined;
  if (!/^\d+$/u.test(raw)) throw new UsageError("--max-relationships must be a positive integer");
  const result = Number(raw);
  if (!Number.isSafeInteger(result) || result < 1 || result > MAX_RELATIONSHIPS) {
    throw new UsageError(`--max-relationships must be between 1 and ${MAX_RELATIONSHIPS}`);
  }
  return result;
}

function assertKnown(tokens: readonly string[], command: string): void {
  const valuedByCommand = {
    reconcile: new Set(["--db", "--output"]),
    preview: new Set([
      "--db", "--actor", "--reason", "--after", "--max-relationships", "--output",
    ]),
    execute: new Set([
      "--db", "--actor", "--reason", "--after", "--max-relationships",
      "--expected-preview-hash", "--receipt",
    ]),
  } as const;
  const flagsByCommand = {
    reconcile: new Set<string>(),
    preview: new Set(["--dry-run"]),
    execute: new Set(["--acknowledge-reviewed-orphan-links"]),
  } as const;
  const valued = valuedByCommand[command as keyof typeof valuedByCommand];
  const flags = flagsByCommand[command as keyof typeof flagsByCommand];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (valued.has(token)) {
      index += 1;
      continue;
    }
    if (flags.has(token)) continue;
    throw new UsageError(`Unsupported ${command} option: ${token}`);
  }
}

function safeOutputPath(requestedPath: string, cwd: string, databasePath: string): string {
  const absolute = resolve(cwd, requestedPath);
  const parent = dirname(absolute);
  if (!existsSync(parent)) throw new UsageError("The output parent directory must exist");
  const parentState = lstatSync(parent);
  if (parentState.isSymbolicLink() || !parentState.isDirectory()) {
    throw new UsageError("The output parent must be a non-link directory");
  }
  const canonical = join(realpathSync(parent), basename(absolute));
  const canonicalDatabase = realpathSync(databasePath);
  if ([
    canonicalDatabase,
    `${canonicalDatabase}-wal`,
    `${canonicalDatabase}-shm`,
    `${canonicalDatabase}-journal`,
  ].includes(canonical)) {
    throw new UsageError("The output path must not replace the database or a SQLite sidecar");
  }
  if (existsSync(canonical)) {
    const outputState = lstatSync(canonical);
    if (outputState.isSymbolicLink() || !outputState.isFile()) {
      throw new UsageError("The output path must be a regular non-link file");
    }
    const databaseState = statSync(canonicalDatabase);
    if (outputState.dev === databaseState.dev && outputState.ino === databaseState.ino) {
      throw new UsageError("The output path must not alias the database");
    }
  }
  return canonical;
}

function writeOutput(path: string, payload: unknown): void {
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    writeFileSync(descriptor, `${canonicalJson(payload)}\n`, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
    chmodSync(path, 0o600);
    const directory = openSync(dirname(path), constants.O_RDONLY);
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    rmSync(temporary, { force: true });
    throw error;
  }
}

export async function runHistoricalReusableLinkRepairCli(
  argv: readonly string[] = process.argv.slice(2),
  environment: TiScaleCliEnvironment = process.env,
  io: CliIo = {},
): Promise<number> {
  const write = io.write ?? ((output: string) => process.stdout.write(output));
  const cwd = io.cwd ?? process.cwd();
  const [command = "help", ...tokens] = argv;
  if (command === "help" || command === "--help" || tokens.includes("--help")) {
    write(help());
    return 0;
  }
  if (command !== "reconcile" && command !== "preview" && command !== "execute") {
    throw new UsageError("Command must be reconcile, preview, or execute");
  }
  assertKnown(tokens, command);
  if (command === "preview" && !tokens.includes("--dry-run")) {
    throw new UsageError("preview requires --dry-run to make the read-only intent explicit");
  }
  if (command === "execute" && !tokens.includes("--acknowledge-reviewed-orphan-links")) {
    throw new UsageError("execute requires --acknowledge-reviewed-orphan-links");
  }

  const databasePath = resolveCliDatabasePath(value(tokens, "db"), environment);
  const requestedOutput = command === "execute" ? required(tokens, "receipt") : value(tokens, "output");
  const outputPath = requestedOutput
    ? safeOutputPath(requestedOutput, cwd, databasePath)
    : undefined;
  const common = command === "reconcile" ? undefined : {
    actorId: required(tokens, "actor"),
    reason: required(tokens, "reason"),
    ...(value(tokens, "after") ? { afterProposalKey: value(tokens, "after")! } : {}),
    ...(pageSize(tokens) === undefined ? {} : { maxRelationships: pageSize(tokens)! }),
  };
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: command !== "execute",
    fileMustExist: true,
    verifyIntegrity: false,
  });
  let payload: unknown;
  try {
    const service = new HistoricalReusableKnowledgeLinkRepairService(database);
    if (command === "reconcile") {
      payload = Object.freeze({
        schemaVersion: "ti_scale.historical_reusable_orphan_link_cli/v1" as const,
        mode: "reconcile" as const,
        result: service.reconcile(),
      });
    } else if (command === "preview") {
      payload = Object.freeze({
        schemaVersion: "ti_scale.historical_reusable_orphan_link_cli/v1" as const,
        mode: "preview" as const,
        result: service.preview(common!),
      });
    } else {
      const actorId = common!.actorId;
      const result = await withCanonicalWriterLease(database, {
        ownerId: actorId,
        operation: "historical-reusable-orphan-link-repair",
      }, (handle, leases) => service.execute({
        ...common!,
        expectedPreviewHash: required(tokens, "expected-preview-hash"),
        acknowledged: true,
      }, { handle, leases }));
      payload = Object.freeze({
        schemaVersion: "ti_scale.historical_reusable_orphan_link_cli/v1" as const,
        mode: "execute" as const,
        result,
      });
    }
  } finally {
    database.close();
  }
  if (outputPath) writeOutput(outputPath, payload);
  write(`${canonicalJson(payload)}\n`);
  return 0;
}

if (import.meta.main) {
  runHistoricalReusableLinkRepairCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(
      `Historical orphan-link repair failed: ${error instanceof Error ? error.message : "unknown error"}\n`,
    );
    process.exitCode = 1;
  });
}

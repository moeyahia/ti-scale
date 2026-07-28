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
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { resolveCliDatabasePath, type TiScaleCliEnvironment } from "../app/StandaloneCliConfiguration";
import { createDatabaseConnection } from "../db";
import { withCanonicalWriterLease } from "../maintenance";
import { canonicalJson } from "../orchestration/serialization";
import { HistoricalAttackKnowledgeConfirmationOrchestrator } from "./HistoricalAttackKnowledgeConfirmationOrchestrator";

interface CliIo {
  readonly cwd?: string;
  readonly write?: (value: string) => void;
}

class UsageError extends Error {}

function help(): string {
  return `Ti-Scale bounded all-page historical memory confirmation

Usage:
  bun run brain:confirm-historical-all -- run --db PATH --migration ID --actor ACTOR --reason TEXT
    --receipt PATH --acknowledge-confirm-all-safe [--page-size 1..1000] [--max-pages 1..1000]

The command binds actor, reason, page size, migration, and inventory receipt to
one durable private database checkpoint. It generates a fresh hash-bound
preview for every page, executes that exact preview, and advances only through
the returned fingerprint cursor. A compact 0600 receipt is also written to
--receipt. Re-run the exact command to resume after the per-invocation page
bound or an interruption. A completed invocation replays without mutations.
Changing actor, reason, or page size after the first checkpoint fails closed.
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

function positiveInteger(tokens: readonly string[], name: string): number | undefined {
  const raw = value(tokens, name);
  if (raw === undefined) return undefined;
  if (!/^\d+$/u.test(raw)) throw new UsageError(`--${name} must be a positive integer`);
  const result = Number(raw);
  if (!Number.isSafeInteger(result) || result < 1 || result > 1_000) {
    throw new UsageError(`--${name} must be between 1 and 1000`);
  }
  return result;
}

function assertKnown(tokens: readonly string[]): void {
  const valued = new Set([
    "--db", "--migration", "--actor", "--reason", "--receipt", "--page-size", "--max-pages",
  ]);
  const flags = new Set(["--acknowledge-confirm-all-safe"]);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (valued.has(token)) {
      index += 1;
      continue;
    }
    if (flags.has(token)) continue;
    throw new UsageError(`Unsupported run option: ${token}`);
  }
}

function atomicReceiptPath(requestedPath: string, cwd: string): string {
  const absolute = resolve(cwd, requestedPath);
  const parent = dirname(absolute);
  if (!existsSync(parent)) throw new UsageError("The parent of --receipt must exist");
  const parentState = lstatSync(parent);
  if (parentState.isSymbolicLink() || !parentState.isDirectory()) {
    throw new UsageError("The parent of --receipt must be a non-link directory");
  }
  const canonical = join(realpathSync(parent), basename(absolute));
  if (existsSync(canonical)) {
    const state = lstatSync(canonical);
    if (state.isSymbolicLink() || !state.isFile()) {
      throw new UsageError("--receipt must be a regular non-link file path");
    }
  }
  return canonical;
}

function writeReceipt(path: string, value: unknown): void {
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    writeFileSync(descriptor, `${canonicalJson(value)}\n`, "utf8");
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

export async function runHistoricalAttackConfirmationAllCli(
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
  if (command !== "run") throw new UsageError("Command must be run");
  assertKnown(tokens);
  if (!tokens.includes("--acknowledge-confirm-all-safe")) {
    throw new UsageError("run requires --acknowledge-confirm-all-safe");
  }
  const receiptPath = atomicReceiptPath(required(tokens, "receipt"), cwd);
  const database = createDatabaseConnection({
    filename: resolveCliDatabasePath(value(tokens, "db"), environment),
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const actorId = required(tokens, "actor");
    const migrationId = required(tokens, "migration");
    const result = await withCanonicalWriterLease(database, {
      ownerId: actorId,
      operation: `historical-attack-confirmation-all:${migrationId}`,
    }, (handle, leases, heartbeat) => {
      leases.assertActive(handle);
      return new HistoricalAttackKnowledgeConfirmationOrchestrator(
        database,
        undefined,
        undefined,
        () => { heartbeat.renew(); },
      ).run({
        migrationId,
        actorId,
        reason: required(tokens, "reason"),
        ...(positiveInteger(tokens, "page-size") === undefined
          ? {} : { pageSize: positiveInteger(tokens, "page-size")! }),
        ...(positiveInteger(tokens, "max-pages") === undefined
          ? {} : { maxPages: positiveInteger(tokens, "max-pages")! }),
      });
    });
    const output = {
      schemaVersion: "ti_scale.historical_attack_confirmation_all_pages_cli/v1",
      mode: "execute",
      outcome: result.outcome,
      pagesProcessedThisInvocation: result.pagesProcessedThisInvocation,
      stateVersion: result.stateVersion,
      receiptPath,
      receipt: result.receipt,
    } as const;
    writeReceipt(receiptPath, output);
    write(`${canonicalJson(output)}\n`);
    return 0;
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  runHistoricalAttackConfirmationAllCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(
      `Historical all-page confirmation failed: ${error instanceof Error ? error.message : "unknown error"}\n`,
    );
    process.exitCode = 1;
  });
}

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
import { createDatabaseConnection, inImmediateTransaction } from "../db";
import { withCanonicalWriterLease } from "../maintenance";
import { canonicalJson } from "../orchestration/serialization";
import { HistoricalResidualCandidateSuppressionService } from "./HistoricalResidualCandidateSuppressionService";

interface CliIo {
  readonly cwd?: string;
  readonly write?: (value: string) => void;
}
class UsageError extends Error {}

function help(): string {
  return `Ti-Scale residual historical-memory privacy suppression

Usage:
  bun run brain:suppress-historical-residuals -- preview --db PATH --actor ACTOR --reason TEXT --dry-run
    [--after SHA256] [--max-candidates 1..1000]

  bun run brain:suppress-historical-residuals -- run --db PATH --actor ACTOR --reason TEXT
    --expected-preview-hash SHA256 --receipt PATH
    --acknowledge-suppress-sensitive-residuals
    [--after SHA256] [--max-candidates 1..1000]

This is a post-import privacy cleanup, not a confirmation workflow. It selects
only unmaterialized pending compiler candidates whose every exact historical
origin has a completed receipt-backed sensitive_content quarantine, with no
accepted completed source, current receipt, active import, or conflicting
terminal classification. Run erases reusable candidate content, creates a
do-not-relearn suppression, appends per-candidate and aggregate audits, and
writes a compact mode-0600 receipt. A source or inventory change makes the
preview stale. Complete catch-up and supplemental imports before using it.
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

function assertKnown(tokens: readonly string[], command: string): void {
  const valued = new Set([
    "--db", "--actor", "--reason", "--after", "--max-candidates",
    "--expected-preview-hash", "--receipt",
  ]);
  const flags = new Set(["--dry-run", "--acknowledge-suppress-sensitive-residuals"]);
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

function atomicReceiptPath(requestedPath: string, cwd: string): string {
  const absolute = resolve(cwd, requestedPath);
  const parent = dirname(absolute);
  if (!existsSync(parent)) throw new UsageError("The parent of --receipt must exist");
  const state = lstatSync(parent);
  if (state.isSymbolicLink() || !state.isDirectory()) {
    throw new UsageError("The parent of --receipt must be a non-link directory");
  }
  const canonical = join(realpathSync(parent), basename(absolute));
  if (existsSync(canonical)) {
    const receiptState = lstatSync(canonical);
    if (receiptState.isSymbolicLink() || !receiptState.isFile()) {
      throw new UsageError("--receipt must be a regular non-link file path");
    }
  }
  return canonical;
}

function writeReceipt(path: string, payload: unknown): void {
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

export async function runHistoricalResidualSuppressionCli(
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
  if (command !== "preview" && command !== "run") {
    throw new UsageError("Command must be preview or run");
  }
  assertKnown(tokens, command);
  if (command === "preview" && !tokens.includes("--dry-run")) {
    throw new UsageError("preview requires --dry-run");
  }
  if (command === "run" && tokens.includes("--dry-run")) {
    throw new UsageError("run cannot include --dry-run");
  }
  if (command === "preview" && tokens.includes("--acknowledge-suppress-sensitive-residuals")) {
    throw new UsageError("preview must not include the execution acknowledgement");
  }
  if (command === "preview" && value(tokens, "receipt") !== undefined) {
    throw new UsageError("preview does not write --receipt");
  }
  const actorId = required(tokens, "actor");
  const common = {
    actorId,
    reason: required(tokens, "reason"),
    ...(value(tokens, "after") ? { afterContentFingerprint: value(tokens, "after")! } : {}),
    ...(positiveInteger(tokens, "max-candidates") === undefined
      ? {} : { maxCandidates: positiveInteger(tokens, "max-candidates")! }),
  };
  const database = createDatabaseConnection({
    filename: resolveCliDatabasePath(value(tokens, "db"), environment),
    readonly: command === "preview",
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const service = new HistoricalResidualCandidateSuppressionService(database);
    if (command === "preview") {
      write(`${JSON.stringify(service.preview(common), null, 2)}\n`);
      return 0;
    }
    if (!tokens.includes("--acknowledge-suppress-sensitive-residuals")) {
      throw new UsageError("run requires --acknowledge-suppress-sensitive-residuals");
    }
    const receiptPath = atomicReceiptPath(required(tokens, "receipt"), cwd);
    const result = await withCanonicalWriterLease(database, {
      ownerId: actorId,
      operation: "historical-residual-sensitive-suppression",
    }, (handle, leases) => inImmediateTransaction(database, () => service.execute({
      ...common,
      expectedPreviewHash: required(tokens, "expected-preview-hash"),
      acknowledgeSuppressSensitiveResiduals: true,
    }, {
      assertActiveInCurrentTransaction: () => leases.assertActiveInCurrentTransaction(handle),
    })));
    const output = {
      schemaVersion: "ti_scale.historical_residual_suppression_cli/v1",
      mode: "execute",
      status: result.status,
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
  runHistoricalResidualSuppressionCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(
      `Historical residual suppression failed: ${error instanceof Error ? error.message : "unknown error"}\n`,
    );
    process.exitCode = 1;
  });
}

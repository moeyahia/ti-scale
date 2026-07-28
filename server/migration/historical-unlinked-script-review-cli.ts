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
import { HistoricalUnlinkedScriptArtifactReviewService } from "./HistoricalUnlinkedScriptArtifactReviewService";

interface CliIo {
  readonly cwd?: string;
  readonly write?: (value: string) => void;
}

class UsageError extends Error {}

function help(): string {
  return `Ti-Scale historical unlinked-script review

Usage:
  bun run brain:review-unlinked-scripts:reconcile -- --db PATH

  bun run brain:review-unlinked-scripts:preview -- --db PATH --actor ACTOR
    --reason TEXT --dry-run [--after SHA256] [--max-candidates 1..1000]

  bun run brain:review-unlinked-scripts:execute -- --db PATH --actor ACTOR
    --reason TEXT --expected-preview-hash SHA256 --receipt PATH
    --acknowledge-mark-confirmed-unlinked-scripts-stale
    [--after SHA256] [--max-candidates 1..1000]

This tool never scans source files, fabricates graph links, classifies an attack
outcome, deletes evidence, or changes verified memory. It can only mark a
reviewed page of confirmed script artifacts stale when every exact source
bundle has receipt-backed custody but no typed relationship, canonical
evidence binding, Context Pack use, outcome link, or materialized promotion.
Unlinked CVEs are reported separately and retained for applicability review.
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
  const flags = new Set(["--dry-run", "--acknowledge-mark-confirmed-unlinked-scripts-stale"]);
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

export async function runHistoricalUnlinkedScriptReviewCli(
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
  if (!["reconcile", "preview", "execute"].includes(command)) {
    throw new UsageError("Command must be reconcile, preview, or execute");
  }
  assertKnown(tokens, command);
  if (command === "reconcile") {
    const unexpected = tokens.filter((token) => token !== "--db" && token !== value(tokens, "db"));
    if (unexpected.length > 0) throw new UsageError("reconcile accepts only --db");
  }
  if (command === "preview" && !tokens.includes("--dry-run")) {
    throw new UsageError("preview requires --dry-run");
  }
  if (command !== "execute" && tokens.includes("--acknowledge-mark-confirmed-unlinked-scripts-stale")) {
    throw new UsageError("Only execute accepts the stale-review acknowledgement");
  }
  if (command !== "execute" && value(tokens, "receipt") !== undefined) {
    throw new UsageError("Only execute writes --receipt");
  }
  const database = createDatabaseConnection({
    filename: resolveCliDatabasePath(value(tokens, "db"), environment),
    readonly: command !== "execute",
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const service = new HistoricalUnlinkedScriptArtifactReviewService(database);
    if (command === "reconcile") {
      write(`${JSON.stringify(service.reconcile(), null, 2)}\n`);
      return 0;
    }
    const maxCandidates = positiveInteger(tokens, "max-candidates");
    const common = {
      actorId: required(tokens, "actor"),
      reason: required(tokens, "reason"),
      ...(value(tokens, "after") ? { afterContentFingerprint: value(tokens, "after")! } : {}),
      ...(maxCandidates === undefined ? {} : { maxCandidates }),
    };
    if (command === "preview") {
      write(`${JSON.stringify(service.preview(common), null, 2)}\n`);
      return 0;
    }
    if (!tokens.includes("--acknowledge-mark-confirmed-unlinked-scripts-stale")) {
      throw new UsageError("execute requires --acknowledge-mark-confirmed-unlinked-scripts-stale");
    }
    const receiptPath = atomicReceiptPath(required(tokens, "receipt"), cwd);
    const result = await withCanonicalWriterLease(database, {
      ownerId: common.actorId,
      operation: "historical-unlinked-script-artifact-review",
    }, (_handle, leases) => inImmediateTransaction(database, () => service.execute({
      ...common,
      expectedPreviewHash: required(tokens, "expected-preview-hash"),
      acknowledgeMarkConfirmedUnlinkedScriptsStale: true,
    }, {
      assertActiveInCurrentTransaction: () => leases.assertActiveInCurrentTransaction(_handle),
    })));
    const output = {
      schemaVersion: "ti_scale.historical_unlinked_script_artifact_review_cli/v1",
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
  runHistoricalUnlinkedScriptReviewCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

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
import { HistoricalBundleEdgeBindingReconciliationService } from "./HistoricalBundleEdgeBindingReconciliationService";

interface CliIo {
  readonly cwd?: string;
  readonly write?: (value: string) => void;
}

class UsageError extends Error {}

const MAX_BINDINGS = 5_000;

function help(): string {
  return `Ti-Scale historical bundle-edge provenance reconciliation

Usage:
  bun run brain:reconcile-historical-bundle-edge-bindings -- reconcile
    [--db PATH] [--output PATH]

  bun run brain:reconcile-historical-bundle-edge-bindings -- preview
    [--db PATH] --actor ACTOR --reason TEXT --dry-run
    [--after BUNDLE_ID/EDGE_KEY] [--max-bindings 1..5000] [--output PATH]

  bun run brain:reconcile-historical-bundle-edge-bindings -- execute
    [--db PATH] --actor ACTOR --reason TEXT
    --expected-preview-hash SHA256 --acknowledge-existing-edge-bindings
    --receipt PATH
    [--after BUNDLE_ID/EDGE_KEY] [--max-bindings 1..5000]

Reconcile and preview open the canonical database strictly read-only. Preview
hash-binds one deterministic bounded page and its complete verified-reference
custody set. Execute requires the same actor, reason, cursor, page size, and
preview hash, holds the canonical writer lease, and writes a mode-0600 receipt.

This command only fills a missing bundle-edge pointer to an exact existing
global operator-confirmed canonical edge. It never creates relationships,
verifies evidence, changes bundle status, classifies outcomes, revives stale
memory, or changes attempt, evidence, reproducibility, or reset counters.
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

function maxBindings(tokens: readonly string[]): number | undefined {
  const raw = value(tokens, "max-bindings");
  if (raw === undefined) return undefined;
  if (!/^\d+$/u.test(raw)) throw new UsageError("--max-bindings must be a positive integer");
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_BINDINGS) {
    throw new UsageError(`--max-bindings must be between 1 and ${MAX_BINDINGS}`);
  }
  return parsed;
}

function assertKnown(tokens: readonly string[], command: string): void {
  const valuedByCommand = {
    reconcile: new Set(["--db", "--output"]),
    preview: new Set([
      "--db", "--actor", "--reason", "--after", "--max-bindings", "--output",
    ]),
    execute: new Set([
      "--db", "--actor", "--reason", "--after", "--max-bindings",
      "--expected-preview-hash", "--receipt",
    ]),
  } as const;
  const flagsByCommand = {
    reconcile: new Set<string>(),
    preview: new Set(["--dry-run"]),
    execute: new Set(["--acknowledge-existing-edge-bindings"]),
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

export async function runHistoricalBundleEdgeBindingCli(
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
  if (command === "execute" && !tokens.includes("--acknowledge-existing-edge-bindings")) {
    throw new UsageError("execute requires --acknowledge-existing-edge-bindings");
  }

  const databasePath = resolveCliDatabasePath(value(tokens, "db"), environment);
  const requestedOutput = command === "execute" ? required(tokens, "receipt") : value(tokens, "output");
  const outputPath = requestedOutput
    ? safeOutputPath(requestedOutput, cwd, databasePath)
    : undefined;
  const common = command === "reconcile" ? undefined : {
    actorId: required(tokens, "actor"),
    reason: required(tokens, "reason"),
    ...(value(tokens, "after") ? { afterBindingCursor: value(tokens, "after")! } : {}),
    ...(maxBindings(tokens) === undefined ? {} : { maxBindings: maxBindings(tokens)! }),
  };
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: command !== "execute",
    fileMustExist: true,
    verifyIntegrity: false,
  });
  let payload: unknown;
  try {
    const service = new HistoricalBundleEdgeBindingReconciliationService(database);
    if (command === "reconcile") {
      payload = Object.freeze({
        schemaVersion: "ti_scale.historical_bundle_edge_binding_cli/v1" as const,
        mode: "reconcile" as const,
        result: service.reconcile(),
      });
    } else if (command === "preview") {
      payload = Object.freeze({
        schemaVersion: "ti_scale.historical_bundle_edge_binding_cli/v1" as const,
        mode: "preview" as const,
        result: service.preview(common!),
      });
    } else {
      const result = await withCanonicalWriterLease(database, {
        ownerId: common!.actorId,
        operation: "historical-bundle-edge-binding-reconciliation",
      }, (handle, leases) => service.execute({
        ...common!,
        expectedPreviewHash: required(tokens, "expected-preview-hash"),
        acknowledgeExistingEdgeBindingOnly: true,
      }, { handle, leases }));
      payload = Object.freeze({
        schemaVersion: "ti_scale.historical_bundle_edge_binding_cli/v1" as const,
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
  runHistoricalBundleEdgeBindingCli().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    process.stderr.write(
      `Historical bundle-edge reconciliation failed: ${error instanceof Error ? error.message : "unknown error"}\n`,
    );
    process.exitCode = 1;
  });
}

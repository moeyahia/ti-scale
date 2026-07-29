#!/usr/bin/env bun
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { canonicalJson, hashJson } from "../orchestration/serialization";
import {
  LEGACY_HISTORICAL_SOURCE_KINDS,
  discoverLegacyHistoricalSources,
  parseLegacyHistoricalSource,
  type LegacyHistoricalDiscovery,
  type LegacyHistoricalParseResult,
} from "./LegacyHistoricalSourceAdapter";

export const LEGACY_HISTORICAL_RECEIPT_FILE = "legacy-historical-receipt.json";
export const LEGACY_HISTORICAL_CANDIDATE_FILE = "legacy-historical-candidates.private.json";

const RECEIPT_SCHEMA = "ti_scale.legacy_historical_collection_receipt/v1" as const;
const CANDIDATE_SCHEMA = "ti_scale.legacy_historical_candidates/v1" as const;
const DEFAULT_BOUNDS = Object.freeze({
  maximumFiles: 10_000,
  maximumDepth: 12,
  maximumTextBytes: 8 * 1024 * 1024,
  maximumSqliteBytes: 256 * 1024 * 1024,
  maximumRecords: 5_000,
  maximumLineBytes: 512 * 1024,
});

export interface LegacyHistoricalCollectionBounds {
  readonly maximumFiles: number;
  readonly maximumDepth: number;
  readonly maximumTextBytes: number;
  readonly maximumSqliteBytes: number;
  readonly maximumRecords: number;
  readonly maximumLineBytes: number;
}

export interface LegacyHistoricalCollectionInput {
  readonly roots: readonly string[];
  readonly activeDatabasePaths: readonly string[];
  readonly outputDirectory: string;
  readonly bounds: LegacyHistoricalCollectionBounds;
}

interface ParsedCliArguments {
  readonly help: boolean;
  readonly collection?: LegacyHistoricalCollectionInput;
}

export interface LegacyHistoricalCollectionReceiptBody {
  readonly schemaVersion: typeof RECEIPT_SCHEMA;
  readonly operation: "discover_and_parse";
  readonly status: "completed";
  readonly verificationState: LegacyHistoricalDiscovery["verificationState"];
  readonly manifestHash: string;
  readonly privateCandidatePayloadHash: string;
  readonly sourceClassCounts: Readonly<Record<(typeof LEGACY_HISTORICAL_SOURCE_KINDS)[number], number>>;
  readonly counts: {
    readonly sources: number;
    readonly exclusions: number;
    readonly rootAliases: number;
    readonly candidates: number;
    readonly quarantined: number;
  };
  readonly bounds: LegacyHistoricalCollectionBounds;
  readonly safety: {
    readonly disclosure: "local_only";
    readonly activeDatabaseExclusion: "required";
    readonly activeDatabaseOpened: false;
    readonly activeDatabaseWrites: false;
    readonly historicalSqliteAccess: "bounded_read_only";
    readonly directReusableMemoryWrites: false;
    readonly candidateLifecycle: "candidate";
    readonly outputFileMode: "0600";
  };
}

export interface LegacyHistoricalCollectionReceipt extends LegacyHistoricalCollectionReceiptBody {
  readonly receiptHash: string;
}

export interface LegacyHistoricalPrivateCandidatePayload {
  readonly schemaVersion: typeof CANDIDATE_SCHEMA;
  readonly classification: {
    readonly sensitivity: "private";
    readonly disclosure: "local_only";
    readonly lifecycle: "candidate";
    readonly reusableMemoryEligible: false;
    readonly directReusableMemoryWriteAllowed: false;
    readonly intendedNextStep: "semantic_extraction_review";
  };
  readonly discovery: LegacyHistoricalDiscovery;
  readonly parseResults: readonly LegacyHistoricalParseResult[];
}

export interface LegacyHistoricalPrivateCandidateDocument extends LegacyHistoricalPrivateCandidatePayload {
  readonly integrity: {
    readonly algorithm: "sha256";
    readonly payloadHash: string;
    readonly receiptHash: string;
  };
}

export interface LegacyHistoricalCliIo {
  readonly cwd?: string;
  readonly write?: (value: string) => void;
}

class LegacyHistoricalCliUsageError extends Error {}

function help(): string {
  return `Ti-Scale missed historical source collector

Usage:
  bun run history:collect --root PATH [--root PATH ...] --active-db PATH [--active-db PATH ...] --output DIR --acknowledge-local-only
    [--max-files N] [--max-depth N] [--max-text-bytes N] [--max-sqlite-bytes N]
    [--max-records N] [--max-line-bytes N]

Safety contract:
  --active-db is required only to exclude the active Ti-Scale database; this command never opens or writes it.
  Historical SQLite sources are opened only through the adapter's bounded read-only path.
  Numeric bounds may tighten the built-in limits shown in the deterministic receipt; they cannot loosen them.
  DIR must be outside every source root and must be absent or empty; no overwrite or resume mode exists.
  The receipt contains counts, policy, and integrity hashes only. Private candidate data is never printed.
  Both output files are created with mode 0600. No reusable-memory or other application-state writes occur.
`;
}

function parseBoundedInteger(value: string, label: string, maximum: number, allowZero = false): number {
  if (!/^\d+$/u.test(value)) throw new LegacyHistoricalCliUsageError(`${label} must be an integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum || (allowZero ? parsed < 0 : parsed < 1)) {
    throw new LegacyHistoricalCliUsageError(`${label} is outside its safe range`);
  }
  return parsed;
}

function parseArguments(argv: readonly string[], cwd: string): ParsedCliArguments {
  const [command, ...tokens] = argv;
  if (command === "help" || command === "--help") return { help: true };
  if (command !== "collect") {
    throw new LegacyHistoricalCliUsageError("Command must be collect (or help)");
  }
  if (tokens.includes("--help")) return { help: true };

  const repeatable = new Set(["--root", "--active-db"]);
  const numeric = new Set([
    "--max-files",
    "--max-depth",
    "--max-text-bytes",
    "--max-sqlite-bytes",
    "--max-records",
    "--max-line-bytes",
  ]);
  const valued = new Set(["--root", "--active-db", "--output", ...numeric]);
  const values = new Map<string, string[]>();
  let acknowledged = false;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token === "--acknowledge-local-only") {
      if (acknowledged) throw new LegacyHistoricalCliUsageError("--acknowledge-local-only may be supplied only once");
      acknowledged = true;
      continue;
    }
    if (!valued.has(token)) throw new LegacyHistoricalCliUsageError("Unsupported or positional CLI option");
    const next = tokens[index + 1];
    if (!next || next.startsWith("--")) {
      throw new LegacyHistoricalCliUsageError(`${token} requires one value`);
    }
    if (!repeatable.has(token) && values.has(token)) {
      throw new LegacyHistoricalCliUsageError(`${token} may be supplied only once`);
    }
    values.set(token, [...(values.get(token) ?? []), next]);
    index += 1;
  }
  if (!acknowledged) {
    throw new LegacyHistoricalCliUsageError("--acknowledge-local-only is required before private candidate collection");
  }
  const roots = values.get("--root")?.map((path) => resolve(cwd, path)) ?? [];
  const activeDatabasePaths = values.get("--active-db")?.map((path) => resolve(cwd, path)) ?? [];
  const output = values.get("--output")?.at(-1);
  if (roots.length === 0) throw new LegacyHistoricalCliUsageError("At least one --root is required");
  if (activeDatabasePaths.length === 0) throw new LegacyHistoricalCliUsageError("At least one --active-db is required");
  if (!output) throw new LegacyHistoricalCliUsageError("--output is required");

  const number = (name: string, fallback: number, allowZero = false): number => {
    const raw = values.get(name)?.at(-1);
    return raw === undefined ? fallback : parseBoundedInteger(raw, name, fallback, allowZero);
  };
  return {
    help: false,
    collection: {
      roots,
      activeDatabasePaths,
      outputDirectory: resolve(cwd, output),
      bounds: {
        maximumFiles: number("--max-files", DEFAULT_BOUNDS.maximumFiles),
        maximumDepth: number("--max-depth", DEFAULT_BOUNDS.maximumDepth, true),
        maximumTextBytes: number("--max-text-bytes", DEFAULT_BOUNDS.maximumTextBytes),
        maximumSqliteBytes: number("--max-sqlite-bytes", DEFAULT_BOUNDS.maximumSqliteBytes),
        maximumRecords: number("--max-records", DEFAULT_BOUNDS.maximumRecords),
        maximumLineBytes: number("--max-line-bytes", DEFAULT_BOUNDS.maximumLineBytes),
      },
    },
  };
}

function isInside(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`));
}

function canonicalExistingDirectories(paths: readonly string[]): readonly string[] {
  return paths.flatMap((path) => {
    try {
      const canonical = realpathSync(path);
      return lstatSync(canonical).isDirectory() ? [canonical] : [];
    } catch {
      return [];
    }
  });
}

function resolveOutputDirectory(
  requestedPath: string,
  roots: readonly string[],
  activeDatabasePaths: readonly string[],
): { readonly path: string; readonly exists: boolean } {
  let outputPath: string;
  let outputExists = false;
  if (existsSync(requestedPath)) {
    const state = lstatSync(requestedPath);
    if (state.isSymbolicLink() || !state.isDirectory()) {
      throw new LegacyHistoricalCliUsageError("--output must be a non-link directory path");
    }
    if (readdirSync(requestedPath).length !== 0) {
      throw new LegacyHistoricalCliUsageError("--output already exists and is not empty; overwrite and resume are intentionally unsupported");
    }
    outputPath = realpathSync(requestedPath);
    outputExists = true;
  } else {
    const parent = dirname(requestedPath);
    if (!existsSync(parent) || !lstatSync(parent).isDirectory()) {
      throw new LegacyHistoricalCliUsageError("The parent of --output must be an existing directory");
    }
    outputPath = resolve(realpathSync(parent), basename(requestedPath));
  }

  for (const root of canonicalExistingDirectories(roots)) {
    if (isInside(root, outputPath)) {
      throw new LegacyHistoricalCliUsageError("--output must be outside every historical source root");
    }
  }
  for (const databasePath of activeDatabasePaths) {
    let canonicalDatabasePath = resolve(databasePath);
    try {
      canonicalDatabasePath = realpathSync(databasePath);
      if (!lstatSync(canonicalDatabasePath).isFile()) {
        throw new LegacyHistoricalCliUsageError("Every existing --active-db path must resolve to a regular file");
      }
    } catch (error) {
      if (error instanceof LegacyHistoricalCliUsageError) throw error;
      // A missing active path remains lexically excluded by the adapter.
    }
    if (isInside(outputPath, canonicalDatabasePath)) {
      throw new LegacyHistoricalCliUsageError("--output must not contain an active database path");
    }
  }
  return { path: outputPath, exists: outputExists };
}

function writeExclusivePrivateJson(path: string, value: unknown): void {
  const descriptor = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8" });
    fchmodSync(descriptor, 0o600);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function sourceClassCounts(discovery: LegacyHistoricalDiscovery): LegacyHistoricalCollectionReceiptBody["sourceClassCounts"] {
  return Object.fromEntries(LEGACY_HISTORICAL_SOURCE_KINDS.map((kind) => [
    kind,
    discovery.sources.filter((source) => source.kind === kind).length,
  ])) as unknown as LegacyHistoricalCollectionReceiptBody["sourceClassCounts"];
}

function buildReceipt(
  discovery: LegacyHistoricalDiscovery,
  parseResults: readonly LegacyHistoricalParseResult[],
  privateCandidatePayloadHash: string,
  bounds: LegacyHistoricalCollectionBounds,
): LegacyHistoricalCollectionReceipt {
  const body: LegacyHistoricalCollectionReceiptBody = {
    schemaVersion: RECEIPT_SCHEMA,
    operation: "discover_and_parse",
    status: "completed",
    verificationState: discovery.verificationState,
    manifestHash: discovery.manifestHash,
    privateCandidatePayloadHash,
    sourceClassCounts: sourceClassCounts(discovery),
    counts: {
      sources: discovery.sources.length,
      exclusions: discovery.excluded.length,
      rootAliases: discovery.rootAliases.length,
      candidates: parseResults.reduce((total, result) => total + result.candidates.length, 0),
      quarantined: parseResults.reduce((total, result) => total + result.quarantined.length, 0),
    },
    bounds,
    safety: {
      disclosure: "local_only",
      activeDatabaseExclusion: "required",
      activeDatabaseOpened: false,
      activeDatabaseWrites: false,
      historicalSqliteAccess: "bounded_read_only",
      directReusableMemoryWrites: false,
      candidateLifecycle: "candidate",
      outputFileMode: "0600",
    },
  };
  return { ...body, receiptHash: hashJson(body) };
}

export async function collectLegacyHistoricalCandidates(
  input: LegacyHistoricalCollectionInput,
): Promise<LegacyHistoricalCollectionReceipt> {
  const output = resolveOutputDirectory(input.outputDirectory, input.roots, input.activeDatabasePaths);
  const discovery = await discoverLegacyHistoricalSources({
    roots: input.roots,
    canonicalDatabasePaths: input.activeDatabasePaths,
    maximumFiles: input.bounds.maximumFiles,
    maximumDepth: input.bounds.maximumDepth,
    maximumTextBytes: input.bounds.maximumTextBytes,
    maximumSqliteBytes: input.bounds.maximumSqliteBytes,
  });
  const parseResults = discovery.sources.map((source) => parseLegacyHistoricalSource(source, {
    maximumRecords: input.bounds.maximumRecords,
    maximumLineBytes: input.bounds.maximumLineBytes,
  }));
  const privatePayload: LegacyHistoricalPrivateCandidatePayload = {
    schemaVersion: CANDIDATE_SCHEMA,
    classification: {
      sensitivity: "private",
      disclosure: "local_only",
      lifecycle: "candidate",
      reusableMemoryEligible: false,
      directReusableMemoryWriteAllowed: false,
      intendedNextStep: "semantic_extraction_review",
    },
    discovery,
    parseResults,
  };
  const privateCandidatePayloadHash = hashJson(privatePayload);
  const receipt = buildReceipt(discovery, parseResults, privateCandidatePayloadHash, input.bounds);
  const candidateDocument: LegacyHistoricalPrivateCandidateDocument = {
    ...privatePayload,
    integrity: {
      algorithm: "sha256",
      payloadHash: privateCandidatePayloadHash,
      receiptHash: receipt.receiptHash,
    },
  };

  if (output.exists) {
    if (readdirSync(output.path).length !== 0) {
      throw new LegacyHistoricalCliUsageError("--output became non-empty during collection; no files were written");
    }
    chmodSync(output.path, 0o700);
  } else {
    mkdirSync(output.path, { mode: 0o700 });
  }
  writeExclusivePrivateJson(resolve(output.path, LEGACY_HISTORICAL_CANDIDATE_FILE), candidateDocument);
  writeExclusivePrivateJson(resolve(output.path, LEGACY_HISTORICAL_RECEIPT_FILE), receipt);
  return receipt;
}

export async function runLegacyHistoricalCli(
  argv: readonly string[],
  io: LegacyHistoricalCliIo = {},
): Promise<number> {
  const parsed = parseArguments(argv, io.cwd ?? process.cwd());
  const write = io.write ?? ((value: string) => process.stdout.write(value));
  if (parsed.help) {
    write(help());
    return 0;
  }
  const receipt = await collectLegacyHistoricalCandidates(parsed.collection!);
  // The receipt is intentionally content-free. Never print the private candidate document.
  write(`${JSON.stringify(receipt, null, 2)}\n`);
  return 0;
}

if (import.meta.main) {
  try {
    process.exitCode = await runLegacyHistoricalCli(process.argv.slice(2));
  } catch (error) {
    const message = error instanceof LegacyHistoricalCliUsageError
      ? error.message
      : "Historical source collection failed safely; no private candidate data was printed";
    process.stderr.write(`${canonicalJson({ code: "legacy_historical_collection_failed", message })}\n`);
    process.exitCode = 1;
  }
}

import { createHash } from "node:crypto";
import {
  createReadStream,
  existsSync,
  lstatSync,
  openSync,
  closeSync,
  readSync,
  readdirSync,
  realpathSync,
  statSync,
} from "node:fs";
import { basename, extname, relative, resolve, sep } from "node:path";
import type { LegacySource, LegacySourceType, SourceInventory } from "./types";
import {
  EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON,
  SETTLED_SOURCE_DEFERRED_REASON,
} from "./LegacyEngagementDiscovery";
import {
  verifyReceiptBoundSqliteQuarantineFile,
  type ReceiptBoundSqliteQuarantineFile,
} from "./HistoricalSqliteSnapshotQuarantineMapping";

const DENIED_BASENAME = /(?:^|[._-])(?:auth|credential|credentials|secret|secrets|token|tokens|key|keys|shell[-_]?snapshot|\.env)(?:$|[._-])/iu;
const DENIED_KEY_FILE = /^(?:id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|key|p12|pfx|keystore|jks)|request_dump_.*)$/iu;
const DENIED_PATH = /(?:^|\/)(?:node_modules|\.git|\.obsidian|dist|build|cache|tmp|backups?)(?:\/|$)/iu;
const BACKUP_SUFFIX = /(?:\.bak(?:\.|$)|\.backup(?:\.|$)|\.old$|\.pre-[^/]+$)/iu;
const SQLITE_EXTENSIONS = new Set([".db", ".sqlite", ".sqlite3"]);
const MAXIMUM_BOUNDED_HISTORY_SOURCE_BYTES = 8 * 1024 * 1024;

function classify(relativePath: string, absolutePath: string): LegacySourceType | undefined {
  const normalized = relativePath.split(sep).join("/");
  const absolute = absolutePath.split(sep).join("/").toLowerCase();
  const name = basename(normalized).toLowerCase();
  const extension = extname(name);
  if (
    extension === ".jsonl"
    && (
      /\/(?:\.claude|claude)\/projects\//u.test(absolute)
      || /\/\.codex\/sessions\//u.test(absolute)
    )
  ) return "provider_session_jsonl";
  if (
    [".json", ".jsonl"].includes(extension)
    && /\/\.grok\/sessions\//u.test(absolute)
  ) return extension === ".jsonl" ? "provider_session_jsonl" : "provider_session_json";
  if (
    [".log", ".txt", ".jsonl"].includes(extension)
    && /\/(?:\.claude|\.codex|\.grok)\/(?:debug|logs?)\//u.test(absolute)
  ) return "provider_log";
  if (name.endsWith(".system.txt") && /\/session-logs\//u.test(absolute)) {
    return "provider_log";
  }
  if (
    [".md", ".markdown"].includes(extension)
    && /\/hermes\/(?:conversations|memories)\//u.test(absolute)
  ) return "conversation_markdown";
  if (name === "kanban.db") return "kanban_sqlite";
  if (name === "state.db") return "conversation_state_sqlite";
  if (/\/runtime\/runs\/[^/]+\.json$/iu.test(`/${normalized}`)) return "run_json";
  if (/\/runtime\/memory\/items\.json$/iu.test(`/${normalized}`)) return "memory_json";
  if (/\/runtime\/training\/lessons\.json$/iu.test(`/${normalized}`)) return "training_json";
  if (/\/runtime\/(?:events|raw[^/]*)\.jsonl$/iu.test(`/${normalized}`)) return "event_jsonl";
  if (/\/(?:llm-logs|session-logs)\/[^/]+\.jsonl$/iu.test(`/${normalized}`)) return "raw_llm_jsonl";
  if (/\/sessions\/[^/]+\.jsonl$/iu.test(`/${normalized}`)) return "raw_llm_jsonl";
  if (/\/sessions\/[^/]+\.json$/iu.test(`/${normalized}`) && !/^request_dump_/iu.test(name)) return "session_json";
  if (/\/(?:logs|application\/logs)\/[^/]+\.(?:log|txt)$/iu.test(`/${normalized}`)) return "dashboard_log";
  if (/\/artifacts?\//iu.test(`/${normalized}`)) return "artifact";
  return undefined;
}

async function hashFile(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

function beginsWithPrivateKey(path: string): boolean {
  const descriptor = openSync(path, "r");
  try {
    const buffer = Buffer.allocUnsafe(65_536);
    const length = readSync(descriptor, buffer, 0, buffer.length, 0);
    return /-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(buffer.subarray(0, length).toString("utf8"));
  } finally { closeSync(descriptor); }
}

function safelyInside(root: string, candidate: string): boolean {
  const value = relative(root, candidate);
  return value === "" || (!value.startsWith(`..${sep}`) && value !== "..");
}

export interface LegacySourceDiscoveryOptions {
  /** Exact cutoff calculated once by the migration coordinator. */
  readonly settledSourceCutoffAt?: string;
  /** Canonical paths and inode identities admitted by the coordinator's active-source gate. */
  readonly explicitActiveSourceDeferrals?: ReadonlyMap<string, {
    readonly sourceDevice: number;
    readonly sourceInode: number;
  }>;
  /** Generic-only roots whose individual files must fit the canonical parser bound. */
  readonly boundedHistoryRoots?: readonly string[];
  /** May only tighten, never loosen, the canonical 8 MiB parser boundary. */
  readonly maximumBoundedSourceBytes?: number;
  /** Fail-closed traversal bounds for supplemental history roots. */
  readonly maximumBoundedFiles?: number;
  readonly maximumBoundedDepth?: number;
  /** Exact SQLite bundle files admitted only as receipt-backed quarantine. */
  readonly receiptBoundSqliteQuarantines?: ReadonlyMap<string, ReceiptBoundSqliteQuarantineFile>;
  /**
   * Hash-pinned delta execution only: inspect these exact paths instead of
   * traversing the configured roots. Classification, secret screening,
   * settled-source checks, hashing, and later importer revalidation still run.
   */
  readonly exactSourcePaths?: readonly string[];
}

/** Allowlist-based discovery; secret/config files are never selected even when explicitly rooted. */
export async function discoverLegacySources(
  sourceRoots: readonly string[],
  options: LegacySourceDiscoveryOptions = {},
): Promise<SourceInventory> {
  const included: LegacySource[] = [];
  const excluded: Array<{ absolutePath: string; reason: string }> = [];
  const deferred: SourceInventory["deferred"][number][] = [];
  const coverage = {
    scannedFiles: 0,
    scannedBytes: 0,
    classifiedFiles: 0,
    classifiedBytes: 0,
    includedFiles: 0,
    includedBytes: 0,
    deferredFiles: 0,
    deferredBytes: 0,
    unsupportedFiles: 0,
    unsupportedBytes: 0,
    excludedFiles: 0,
    excludedBytes: 0,
    oversizedFiles: 0,
    oversizedBytes: 0,
    activeSqliteFiles: 0,
    activeSqliteBytes: 0,
    receiptBoundSqliteFiles: 0,
    receiptBoundSqliteBytes: 0,
    vaultProjectionDirectories: 0,
    deniedDirectories: 0,
  };
  const seen = new Set<string>();
  const exactSourcePaths = options.exactSourcePaths === undefined
    ? undefined
    : options.exactSourcePaths.map((path) => resolve(path));
  if (exactSourcePaths && new Set(exactSourcePaths).size !== exactSourcePaths.length) {
    throw new Error("Exact historical source admission contains duplicate paths");
  }
  const exactPathsAccountedFor = new Set<string>();
  const boundedHistoryRoots = new Set(
    (options.boundedHistoryRoots ?? []).map((path) => resolve(path)),
  );
  const maximumBoundedSourceBytes = options.maximumBoundedSourceBytes
    ?? MAXIMUM_BOUNDED_HISTORY_SOURCE_BYTES;
  if (
    !Number.isSafeInteger(maximumBoundedSourceBytes)
    || maximumBoundedSourceBytes < 1
    || maximumBoundedSourceBytes > MAXIMUM_BOUNDED_HISTORY_SOURCE_BYTES
  ) {
    throw new RangeError("maximumBoundedSourceBytes must be between 1 byte and 8 MiB");
  }
  const maximumBoundedFiles = options.maximumBoundedFiles ?? 100_000;
  const maximumBoundedDepth = options.maximumBoundedDepth ?? 24;
  if (!Number.isSafeInteger(maximumBoundedFiles) || maximumBoundedFiles < 1 || maximumBoundedFiles > 100_000) {
    throw new RangeError("maximumBoundedFiles must be between 1 and 100000");
  }
  if (!Number.isSafeInteger(maximumBoundedDepth) || maximumBoundedDepth < 1 || maximumBoundedDepth > 32) {
    throw new RangeError("maximumBoundedDepth must be between 1 and 32");
  }
  let boundedFilesDiscovered = 0;
  const settledSourceCutoffMs = options.settledSourceCutoffAt === undefined
    ? undefined
    : Date.parse(options.settledSourceCutoffAt);
  if (settledSourceCutoffMs !== undefined && !Number.isFinite(settledSourceCutoffMs)) {
    throw new TypeError("Settled-source cutoff must be a valid timestamp");
  }

  for (const requestedRoot of sourceRoots) {
    const absoluteRoot = resolve(requestedRoot);
    let rootReal: string;
    try {
      rootReal = realpathSync(absoluteRoot);
    } catch {
      excluded.push({ absolutePath: absoluteRoot, reason: "source root does not exist" });
      continue;
    }
    const rootStat = lstatSync(rootReal);
    if (
      rootStat.isDirectory()
      && (basename(rootReal).toLowerCase() === ".obsidian" || existsSync(resolve(rootReal, ".obsidian")))
    ) {
      coverage.vaultProjectionDirectories += 1;
      excluded.push({
        absolutePath: rootReal,
        reason: "Obsidian vault projection roots are excluded to prevent a historical-import feedback loop",
      });
      continue;
    }
    const boundedHistoryRoot = boundedHistoryRoots.has(rootReal);
    const files: string[] = [];
    if (exactSourcePaths !== undefined) {
      for (const candidate of exactSourcePaths) {
        if (rootStat.isFile() ? candidate === rootReal : safelyInside(rootReal, candidate)) {
          if (candidate === rootReal && rootStat.isDirectory()) {
            throw new Error("Exact historical source admission cannot name a configured directory root");
          }
          files.push(candidate);
          exactPathsAccountedFor.add(candidate);
        }
      }
    }
    else if (rootStat.isFile()) files.push(rootReal);
    else if (rootStat.isDirectory()) {
      const pending: Array<{ readonly path: string; readonly depth: number }> = [{
        path: rootReal,
        depth: 0,
      }];
      while (pending.length) {
        const directory = pending.pop()!;
        for (const entry of readdirSync(directory.path, { withFileTypes: true })) {
          const candidate = resolve(directory.path, entry.name);
          if (entry.isSymbolicLink()) {
            excluded.push({ absolutePath: candidate, reason: "symbolic links are not migrated" });
            continue;
          }
          if (entry.isDirectory()) {
            const rel = relative(rootReal, candidate).split(sep).join("/");
            if (existsSync(resolve(candidate, ".obsidian"))) {
              coverage.vaultProjectionDirectories += 1;
              excluded.push({
                absolutePath: candidate,
                reason: "Obsidian vault projection directory is excluded to prevent a historical-import feedback loop",
              });
            } else if (!DENIED_PATH.test(`/${rel}/`)) {
              if (boundedHistoryRoot && directory.depth >= maximumBoundedDepth) {
                coverage.deniedDirectories += 1;
                excluded.push({
                  absolutePath: candidate,
                  reason: "history directory exceeds the bounded traversal depth",
                });
              } else pending.push({ path: candidate, depth: directory.depth + 1 });
            }
            else coverage.deniedDirectories += 1;
            continue;
          }
          if (entry.isFile()) {
            if (boundedHistoryRoot) {
              boundedFilesDiscovered += 1;
              if (boundedFilesDiscovered > maximumBoundedFiles) {
                throw new RangeError("supplemental history exceeds the configured bounded file discovery limit");
              }
            }
            files.push(candidate);
          }
        }
      }
    }

    for (const path of files.sort()) {
      let real: string;
      try { real = realpathSync(path); }
      catch {
        if (exactSourcePaths !== undefined) {
          throw new Error("Exact historical source admission disappeared before discovery");
        }
        excluded.push({ absolutePath: path, reason: "source disappeared during discovery" });
        continue;
      }
      if (!safelyInside(rootReal, real)) {
        if (exactSourcePaths !== undefined) {
          throw new Error("Exact historical source admission escaped its configured root");
        }
        continue;
      }
      if (seen.has(real)) continue;
      seen.add(real);
      let initialState;
      try { initialState = lstatSync(real); }
      catch {
        excluded.push({ absolutePath: real, reason: "source changed before classification" });
        continue;
      }
      coverage.scannedFiles += 1;
      coverage.scannedBytes += initialState.size;
      const rel = rootStat.isFile() ? basename(real) : relative(rootReal, real);
      const normalized = rel.split(sep).join("/");
      const sqliteQuarantine = options.receiptBoundSqliteQuarantines?.get(real);
      if (sqliteQuarantine) {
        verifyReceiptBoundSqliteQuarantineFile(sqliteQuarantine);
        excluded.push({
          absolutePath: real,
          reason: "receipt-bound normalized SQLite snapshot contains zero semantic records; exact source retained as quarantine custody",
        });
        coverage.receiptBoundSqliteFiles += 1;
        coverage.receiptBoundSqliteBytes += initialState.size;
        coverage.excludedFiles += 1;
        coverage.excludedBytes += initialState.size;
        continue;
      }
      if (/(?:\.db|\.sqlite|\.sqlite3)-(?:wal|journal|shm)$/iu.test(basename(real))) {
        excluded.push({ absolutePath: real, reason: "active SQLite sidecars are never historical source objects" });
        coverage.excludedFiles += 1;
        coverage.excludedBytes += initialState.size;
        continue;
      }
      if (DENIED_BASENAME.test(basename(real)) || DENIED_KEY_FILE.test(basename(real)) || DENIED_PATH.test(`/${normalized}`) || BACKUP_SUFFIX.test(basename(real))) {
        excluded.push({ absolutePath: real, reason: "sensitive, generated, or backup filename denied" });
        coverage.excludedFiles += 1;
        coverage.excludedBytes += initialState.size;
        continue;
      }
      const type = classify(normalized, real);
      const sqlite = SQLITE_EXTENSIONS.has(extname(real).toLowerCase());
      const activeSqlite = sqlite && ["-wal", "-journal"].some((suffix) => {
        const sidecar = `${real}${suffix}`;
        try { return existsSync(sidecar) && lstatSync(sidecar).size > 0; }
        catch { return true; }
      });
      if (!type) {
        coverage.unsupportedFiles += 1;
        coverage.unsupportedBytes += initialState.size;
        if (sqlite) {
          excluded.push({
            absolutePath: real,
            reason: activeSqlite
              ? "active SQLite WAL/journal detected; import only an allowlisted quiesced snapshot"
              : "SQLite source is not an allowlisted quiesced historical schema snapshot",
          });
          if (activeSqlite) {
            coverage.activeSqliteFiles += 1;
            coverage.activeSqliteBytes += initialState.size;
          }
          coverage.excludedFiles += 1;
          coverage.excludedBytes += initialState.size;
        }
        continue;
      }
      coverage.classifiedFiles += 1;
      coverage.classifiedBytes += initialState.size;
      if (activeSqlite) {
        excluded.push({
          absolutePath: real,
          reason: "active SQLite WAL/journal detected; import only a quiesced snapshot",
        });
        coverage.activeSqliteFiles += 1;
        coverage.activeSqliteBytes += initialState.size;
        coverage.excludedFiles += 1;
        coverage.excludedBytes += initialState.size;
        continue;
      }
      if (boundedHistoryRoot && initialState.size > maximumBoundedSourceBytes) {
        excluded.push({
          absolutePath: real,
          reason: "history source exceeds the bounded 8 MiB canonical semantic parser limit",
        });
        coverage.oversizedFiles += 1;
        coverage.oversizedBytes += initialState.size;
        coverage.excludedFiles += 1;
        coverage.excludedBytes += initialState.size;
        continue;
      }
      const explicitDeferral = options.explicitActiveSourceDeferrals?.get(real);
      if (explicitDeferral) {
        if (
          initialState.dev !== explicitDeferral.sourceDevice
          || initialState.ino !== explicitDeferral.sourceInode
        ) {
          throw new Error("Explicitly deferred source changed after active-source validation");
        }
        deferred.push({
          absolutePath: real,
          reason: EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON,
          byteSize: initialState.size,
          modifiedAt: initialState.mtime.toISOString(),
          sourceDevice: initialState.dev,
          sourceInode: initialState.ino,
        });
        coverage.deferredFiles += 1;
        coverage.deferredBytes += initialState.size;
        continue;
      }
      if (settledSourceCutoffMs !== undefined) {
        try {
          const state = lstatSync(real);
          if (state.isFile() && state.mtimeMs > settledSourceCutoffMs) {
            deferred.push({
              absolutePath: real,
              reason: SETTLED_SOURCE_DEFERRED_REASON,
              byteSize: state.size,
              modifiedAt: state.mtime.toISOString(),
              sourceDevice: state.dev,
              sourceInode: state.ino,
            });
            coverage.deferredFiles += 1;
            coverage.deferredBytes += state.size;
            continue;
          }
        } catch {
          excluded.push({ absolutePath: real, reason: "source changed during settled-source classification" });
          continue;
        }
      }
      if (type === "artifact" && beginsWithPrivateKey(real)) {
        excluded.push({ absolutePath: real, reason: "private-key material is never migrated as an artifact" });
        coverage.excludedFiles += 1;
        coverage.excludedBytes += initialState.size;
        continue;
      }
      let fileStat;
      try { fileStat = statSync(real); }
      catch {
        excluded.push({ absolutePath: real, reason: "source changed during discovery" });
        continue;
      }
      included.push({
        absolutePath: real,
        relativePath: normalized,
        root: rootReal,
        type,
        sha256: await hashFile(real),
        byteSize: fileStat.size,
        modifiedAt: fileStat.mtime.toISOString(),
      });
      coverage.includedFiles += 1;
      coverage.includedBytes += fileStat.size;
    }
  }

  if (exactSourcePaths !== undefined && exactPathsAccountedFor.size !== exactSourcePaths.length) {
    throw new Error("Exact historical source admission is not contained by the configured roots");
  }

  deferred.sort((left, right) => left.absolutePath.localeCompare(right.absolutePath));
  return { included, excluded, deferred, coverage };
}

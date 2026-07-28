import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, realpathSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { IntegrityResult } from "../db";

const CHILD = fileURLToPath(new URL("./StartupDatabaseIntegrityChild.ts", import.meta.url));
const OUTPUT_LIMIT_BYTES = 16 * 1_024;
const DEFAULT_TIMEOUT_MS = 15 * 60_000;

interface FileIdentity {
  readonly path: string;
  readonly device: string;
  readonly inode: string;
  readonly size: string;
  readonly modifiedNs: string;
}

interface DatabaseStorageIdentity {
  readonly database: FileIdentity;
  readonly wal?: FileIdentity;
}

interface IntegrityEnvelope {
  readonly schemaVersion: "ti-scale.startup-database-integrity.v1";
  readonly ok: boolean;
  readonly messages: readonly string[];
}

export interface StartupDatabaseIntegrityVerifierOptions {
  readonly timeoutMs?: number;
  readonly childEntrypoint?: string;
  readonly runtimeExecutable?: string;
}

function identity(path: string, ignoreEmpty = false): FileIdentity | undefined {
  if (!existsSync(path)) return undefined;
  const canonical = realpathSync(path);
  const stat = statSync(canonical, { bigint: true });
  if (!stat.isFile()) throw new Error("Startup database integrity input is not a regular file");
  // SQLite may create an empty WAL sidecar when a read-only connection opens
  // a WAL-mode database. It contains no canonical transaction and is therefore
  // normalized to absence on both sides of the receipt boundary.
  if (ignoreEmpty && stat.size === 0n) return undefined;
  // SQLite may update WAL lock/metadata state while opening a crash-left WAL
  // read-only; that can advance ctime without changing a byte (verified by the
  // stable inode, size, and mtime). Do not turn that normal recovery read into
  // a false startup failure.
  return Object.freeze({
    path: canonical,
    device: String(stat.dev),
    inode: String(stat.ino),
    size: String(stat.size),
    modifiedNs: String(stat.mtimeNs),
  });
}

function state(databasePath: string): DatabaseStorageIdentity {
  const database = identity(databasePath);
  if (!database) throw new Error("Startup database disappeared during integrity verification");
  const wal = identity(`${databasePath}-wal`, true);
  return Object.freeze({ database, ...(wal ? { wal } : {}) });
}

function identityEqual(left: FileIdentity | undefined, right: FileIdentity | undefined): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function parseEnvelope(raw: string): IntegrityResult {
  const parsed = JSON.parse(raw.trim()) as Partial<IntegrityEnvelope>;
  if (
    parsed.schemaVersion !== "ti-scale.startup-database-integrity.v1"
    || typeof parsed.ok !== "boolean"
    || !Array.isArray(parsed.messages)
    || parsed.messages.length < 1
    || parsed.messages.some((message) => typeof message !== "string" || message.length > 1_000)
  ) {
    throw new Error("Startup database integrity child returned an invalid receipt");
  }
  return Object.freeze({
    ok: parsed.ok,
    messages: Object.freeze([...parsed.messages]),
  });
}

/**
 * Runs SQLite's full startup quick-check outside Bun's HTTP event loop. The
 * child receives no provider, operator, MCP, or Vault secret and cannot admit
 * execution. Exact database + WAL identities bind the receipt to the bytes
 * subsequently opened by the canonical process.
 */
export class StartupDatabaseIntegrityVerifier {
  readonly #timeoutMs: number;
  readonly #childEntrypoint: string;
  readonly #runtimeExecutable: string;
  #child?: ChildProcess;
  #inFlight?: Promise<IntegrityResult>;
  #stopping = false;

  constructor(options: StartupDatabaseIntegrityVerifierOptions = {}) {
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#childEntrypoint = options.childEntrypoint ?? CHILD;
    this.#runtimeExecutable = options.runtimeExecutable ?? process.execPath;
    if (!Number.isSafeInteger(this.#timeoutMs) || this.#timeoutMs < 1_000 || this.#timeoutMs > 30 * 60_000) {
      throw new RangeError("Startup database integrity timeout must be 1000 through 1800000 ms");
    }
  }

  verify(databasePath: string): Promise<IntegrityResult> {
    if (this.#stopping) return Promise.reject(new Error("Startup database integrity verification is stopping"));
    if (this.#inFlight) return this.#inFlight;
    const canonical = realpathSync(resolve(databasePath));
    const before = state(canonical);
    const child = spawn(this.#runtimeExecutable, ["run", this.#childEntrypoint, canonical], {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        TMPDIR: process.env.TMPDIR,
        NODE_ENV: process.env.NODE_ENV,
      },
    });
    this.#child = child;
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let overflow = false;
    const append = (current: Buffer, chunk: Buffer): Buffer => {
      if (current.byteLength + chunk.byteLength > OUTPUT_LIMIT_BYTES) {
        overflow = true;
        return current;
      }
      return Buffer.concat([current, chunk]);
    };
    child.stdout?.on("data", (chunk: Buffer) => { stdout = append(stdout, chunk); });
    child.stderr?.on("data", (chunk: Buffer) => { stderr = append(stderr, chunk); });

    const result = new Promise<IntegrityResult>((resolveResult, rejectResult) => {
      const timeout = setTimeout(() => {
        child.kill("SIGTERM");
        rejectResult(new Error("Startup database integrity verification exceeded its deadline"));
      }, this.#timeoutMs);
      child.once("error", (error) => {
        clearTimeout(timeout);
        rejectResult(error);
      });
      child.once("close", (code, signal) => {
        clearTimeout(timeout);
        if (this.#stopping) {
          rejectResult(new Error("Startup database integrity verification was cancelled"));
          return;
        }
        if (overflow) {
          rejectResult(new Error("Startup database integrity child exceeded its output limit"));
          return;
        }
        if (code !== 0 || signal) {
          const failure = stderr.toString("utf8").trim().slice(0, 500);
          rejectResult(new Error(
            `Startup database integrity child failed${failure ? ` (${failure})` : ""}`,
          ));
          return;
        }
        try {
          const after = state(canonical);
          const changed = [
            ...(!identityEqual(before.database, after.database) ? ["database file"] : []),
            ...(!identityEqual(before.wal, after.wal) ? ["write-ahead log"] : []),
          ];
          if (changed.length > 0) {
            const walDetail = changed.includes("write-ahead log")
              ? ` (WAL size ${before.wal?.size ?? "absent"} -> ${after.wal?.size ?? "absent"}; inode ${before.wal?.inode ?? "absent"} -> ${after.wal?.inode ?? "absent"})`
              : "";
            throw new Error(`Canonical ${changed.join(" and ")} identity changed during startup integrity verification${walDetail}`);
          }
          resolveResult(parseEnvelope(stdout.toString("utf8")));
        } catch (error) {
          rejectResult(error);
        }
      });
    }).finally(() => {
      this.#child = undefined;
      this.#inFlight = undefined;
    });
    this.#inFlight = result;
    return result;
  }

  beginStop(): void {
    if (this.#stopping) return;
    this.#stopping = true;
    this.#child?.kill("SIGTERM");
  }

  async stop(): Promise<void> {
    this.beginStop();
    await this.#inFlight?.catch(() => undefined);
  }
}

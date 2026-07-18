import { watch, type FSWatcher } from "node:fs";
import { relative, sep } from "node:path";
import type { SqliteDatabase } from "../db/types";
import type { ObsidianVaultBridge } from "./ObsidianVaultBridge";

interface ConnectionRow {
  readonly id: string;
  readonly vault_path: string;
}

export interface VaultWatcherSyncPort {
  requireConnection(connectionId: string): { readonly vaultPath: string };
  syncChangedPath(connectionId: string, relativePath: string, actor: string): unknown;
  markConnectionHealth(connectionId: string, status: "connected" | "degraded" | "error"): void;
  vaultSyncEnabled?(): boolean;
}

export type VaultWatchFactory = (
  root: string,
  listener: (eventType: string, filename: string | Buffer | null) => void,
) => FSWatcher;

export interface ObsidianVaultWatcherOptions {
  readonly actor?: string;
  readonly debounceMs?: number;
  readonly connectionRefreshMs?: number;
  readonly yieldMs?: number;
  readonly onError?: (error: Error, context: { connectionId?: string; relativePath?: string }) => void;
  readonly onProcessed?: (context: { connectionId: string; relativePath: string }) => void;
  /** Test seam and platform adapter; production uses recursive node:fs watch. */
  readonly watchFactory?: VaultWatchFactory;
}

interface WatchedConnection {
  readonly root: string;
  readonly watcher: FSWatcher;
}

function safeChangedNotePath(filename: string): string | undefined {
  const normalized = filename.replaceAll(sep, "/").replace(/^\.\//u, "");
  if (!normalized || normalized.includes("\0") || normalized.startsWith("/") || normalized.includes("\\")) return undefined;
  const segments = normalized.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) return undefined;
  if (segments.some((segment) => [".obsidian", ".ti-scale"].includes(segment.toLowerCase()))) return undefined;
  if (!normalized.toLowerCase().endsWith(".md") || normalized.toLowerCase().endsWith(".tmp.md")) return undefined;
  return normalized;
}

/**
 * Low-priority filesystem observer. File-system callbacks only debounce and
 * enqueue; canonical synchronization runs one note per event-loop turn.
 */
export class ObsidianVaultWatcher {
  readonly #database: SqliteDatabase;
  readonly #bridge: VaultWatcherSyncPort;
  readonly #actor: string;
  readonly #debounceMs: number;
  readonly #connectionRefreshMs: number;
  readonly #yieldMs: number;
  readonly #onError?: ObsidianVaultWatcherOptions["onError"];
  readonly #onProcessed?: ObsidianVaultWatcherOptions["onProcessed"];
  readonly #watchFactory: VaultWatchFactory;
  readonly #connections = new Map<string, WatchedConnection>();
  readonly #pending = new Map<string, ReturnType<typeof setTimeout>>();
  readonly #queue: Array<{ connectionId: string; relativePath: string }> = [];
  #connectionTimer?: ReturnType<typeof setInterval>;
  #drainTimer?: ReturnType<typeof setTimeout>;
  #started = false;
  #stopped = false;
  #processing = false;

  constructor(
    database: SqliteDatabase,
    bridge: ObsidianVaultBridge | VaultWatcherSyncPort,
    options: ObsidianVaultWatcherOptions = {},
  ) {
    this.#database = database;
    this.#bridge = bridge;
    this.#actor = options.actor?.trim() || "operator:vault-watcher";
    this.#debounceMs = Math.max(10, Math.min(10_000, options.debounceMs ?? 350));
    this.#connectionRefreshMs = Math.max(1_000, Math.min(300_000, options.connectionRefreshMs ?? 15_000));
    this.#yieldMs = Math.max(0, Math.min(1_000, options.yieldMs ?? 5));
    this.#onError = options.onError;
    this.#onProcessed = options.onProcessed;
    this.#watchFactory = options.watchFactory ?? ((root, listener) => (
      watch(root, { persistent: false, recursive: true }, listener)
    ));
  }

  get started(): boolean { return this.#started && !this.#stopped; }
  get watchedConnectionCount(): number { return this.#connections.size; }
  get pendingCount(): number { return this.#pending.size + this.#queue.length + (this.#processing ? 1 : 0); }

  start(): void {
    if (this.#stopped) throw new Error("Obsidian vault watcher has already stopped");
    if (this.#started) return;
    this.#started = true;
    this.refreshConnections();
    this.#connectionTimer = setInterval(() => this.refreshConnections(), this.#connectionRefreshMs);
    this.#connectionTimer.unref?.();
  }

  refreshConnections(): void {
    if (!this.#started || this.#stopped) return;
    if (this.#bridge.vaultSyncEnabled?.() === false) {
      this.#clearQueuedWork();
      this.#closeWatchers();
      return;
    }
    const rows = this.#database.prepare(`
      SELECT id, vault_path FROM vault_connections
      WHERE status IN ('connected', 'degraded') ORDER BY id
    `).all() as ConnectionRow[];
    const wanted = new Set(rows.map((row) => row.id));
    for (const [id, watched] of this.#connections) {
      if (wanted.has(id)) continue;
      watched.watcher.close();
      this.#connections.delete(id);
    }
    for (const row of rows) {
      const existing = this.#connections.get(row.id);
      if (existing?.root === row.vault_path) continue;
      existing?.watcher.close();
      try {
        const connection = this.#bridge.requireConnection(row.id);
        const watcher = this.#watchFactory(connection.vaultPath, (_event, filename) => {
          if (!filename || this.#stopped) return;
          const changed = safeChangedNotePath(String(filename));
          if (changed) this.#debounce(row.id, changed);
        });
        watcher.on("error", (error) => this.#report(error, { connectionId: row.id }));
        this.#connections.set(row.id, { root: connection.vaultPath, watcher });
      } catch (error) {
        this.#bridge.markConnectionHealth(row.id, "degraded");
        this.#report(error, { connectionId: row.id });
      }
    }
  }

  #debounce(connectionId: string, relativePath: string): void {
    const key = `${connectionId}\0${relativePath}`;
    const prior = this.#pending.get(key);
    if (prior) clearTimeout(prior);
    const timer = setTimeout(() => {
      this.#pending.delete(key);
      if (this.#stopped) return;
      this.#queue.push({ connectionId, relativePath });
      this.#scheduleDrain();
    }, this.#debounceMs);
    timer.unref?.();
    this.#pending.set(key, timer);
  }

  #scheduleDrain(): void {
    if (this.#stopped || this.#processing || this.#drainTimer || this.#queue.length === 0) return;
    this.#drainTimer = setTimeout(() => {
      this.#drainTimer = undefined;
      this.#drainOne();
    }, this.#yieldMs);
    this.#drainTimer.unref?.();
  }

  #drainOne(): void {
    if (this.#stopped || this.#processing) return;
    const job = this.#queue.shift();
    if (!job) return;
    this.#processing = true;
    try {
      this.#bridge.syncChangedPath(job.connectionId, job.relativePath, this.#actor);
      this.#bridge.markConnectionHealth(job.connectionId, "connected");
      this.#onProcessed?.(job);
    } catch (error) {
      this.#bridge.markConnectionHealth(job.connectionId, "degraded");
      this.#report(error, job);
    } finally {
      this.#processing = false;
      this.#scheduleDrain();
    }
  }

  #report(error: unknown, context: { connectionId?: string; relativePath?: string }): void {
    this.#onError?.(error instanceof Error ? error : new Error("Obsidian watcher operation failed"), context);
  }

  #clearQueuedWork(): void {
    if (this.#drainTimer) clearTimeout(this.#drainTimer);
    this.#drainTimer = undefined;
    for (const timer of this.#pending.values()) clearTimeout(timer);
    this.#pending.clear();
    this.#queue.length = 0;
  }

  #closeWatchers(): void {
    for (const watched of this.#connections.values()) watched.watcher.close();
    this.#connections.clear();
  }

  async waitForIdle(timeoutMs = 5_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (this.pendingCount > 0) {
      if (Date.now() >= deadline) throw new Error("Timed out waiting for Obsidian watcher to become idle");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  async stop(): Promise<void> {
    if (this.#stopped) return;
    this.#stopped = true;
    this.#started = false;
    if (this.#connectionTimer) clearInterval(this.#connectionTimer);
    this.#clearQueuedWork();
    this.#closeWatchers();
    // Work is synchronous and bounded to one note, so processing is false by
    // the time the current event-loop callback can observe this promise.
    while (this.#processing) await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

export function watchedRelativePath(root: string, absolutePath: string): string | undefined {
  return safeChangedNotePath(relative(root, absolutePath));
}

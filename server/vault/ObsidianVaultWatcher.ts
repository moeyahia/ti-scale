import { watch, type FSWatcher } from "node:fs";
import { relative, sep } from "node:path";
import type { SqliteDatabase } from "../db/types";
import type { ObsidianVaultBridge } from "./ObsidianVaultBridge";

interface ConnectionRow {
  readonly id: string;
  readonly vault_path: string;
  readonly status: "connected" | "degraded";
}

export interface VaultWatcherSyncPort {
  requireConnection(connectionId: string): { readonly vaultPath: string };
  syncChangedPath(connectionId: string, relativePath: string, actor: string): unknown;
  markConnectionHealth(connectionId: string, status: "connected" | "degraded" | "error"): void;
  refreshConnectionHealthProof?(
    connectionId: string,
    actor?: string,
  ): { readonly checkedAt: string };
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
  /** Must remain below the active Vault proof maximum age. */
  readonly healthProofRefreshMs?: number;
  readonly maximumHealthProofRefreshBatch?: number;
  readonly clock?: () => number;
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
  readonly #healthProofRefreshMs: number;
  readonly #maximumHealthProofRefreshBatch: number;
  readonly #clock: () => number;
  readonly #yieldMs: number;
  readonly #onError?: ObsidianVaultWatcherOptions["onError"];
  readonly #onProcessed?: ObsidianVaultWatcherOptions["onProcessed"];
  readonly #watchFactory: VaultWatchFactory;
  readonly #connections = new Map<string, WatchedConnection>();
  readonly #lastHealthProofAt = new Map<string, number>();
  readonly #pending = new Map<string, ReturnType<typeof setTimeout>>();
  readonly #queue: Array<{ connectionId: string; relativePath: string }> = [];
  #connectionTimer?: ReturnType<typeof setInterval>;
  #drainTimer?: ReturnType<typeof setTimeout>;
  #started = false;
  #stopping = false;
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
    this.#healthProofRefreshMs = Math.max(
      1_000,
      Math.min(4 * 60_000, options.healthProofRefreshMs ?? 4 * 60_000),
    );
    this.#maximumHealthProofRefreshBatch = Math.max(
      1,
      Math.min(32, options.maximumHealthProofRefreshBatch ?? 16),
    );
    this.#clock = options.clock ?? (() => Date.now());
    this.#yieldMs = Math.max(0, Math.min(1_000, options.yieldMs ?? 5));
    this.#onError = options.onError;
    this.#onProcessed = options.onProcessed;
    this.#watchFactory = options.watchFactory ?? ((root, listener) => (
      watch(root, { persistent: false, recursive: true }, listener)
    ));
  }

  get started(): boolean { return this.#started && !this.#stopping && !this.#stopped; }
  get watchedConnectionCount(): number { return this.#connections.size; }
  get pendingCount(): number { return this.#pending.size + this.#queue.length + (this.#processing ? 1 : 0); }

  start(): void {
    if (this.#stopping || this.#stopped) throw new Error("Obsidian vault watcher has already stopped");
    if (this.#started) return;
    this.#started = true;
    this.refreshConnections();
    this.#connectionTimer = setInterval(() => this.refreshConnections(), this.#connectionRefreshMs);
    this.#connectionTimer.unref?.();
  }

  refreshConnections(): void {
    if (!this.#started || this.#stopping || this.#stopped) return;
    if (this.#bridge.vaultSyncEnabled?.() === false) {
      this.#clearQueuedWork();
      this.#closeWatchers();
      return;
    }
    const rows = this.#database.prepare(`
      SELECT id, vault_path, status FROM vault_connections
      WHERE status IN ('connected', 'degraded') ORDER BY id
    `).all() as ConnectionRow[];
    const wanted = new Set(rows.map((row) => row.id));
    for (const [id, watched] of this.#connections) {
      if (wanted.has(id)) continue;
      watched.watcher.close();
      this.#connections.delete(id);
      this.#lastHealthProofAt.delete(id);
      // A lifecycle change such as disconnect is a hard synchronization
      // fence. A debounced event captured while the connection was active
      // must not import, quarantine, or otherwise mutate a Vault after that
      // boundary has committed.
      this.#discardQueuedWorkForConnection(id);
    }
    for (const row of rows) {
      const existing = this.#connections.get(row.id);
      if (existing?.root === row.vault_path) continue;
      existing?.watcher.close();
      try {
        const connection = this.#bridge.requireConnection(row.id);
        const watcher = this.#watchFactory(connection.vaultPath, (_event, filename) => {
          if (!filename || this.#stopping || this.#stopped) return;
          const changed = safeChangedNotePath(String(filename));
          // Do not capture filesystem work while the persisted connection is
          // already in an error/recovery-required state. Replaying an old
          // event after a successful repair could otherwise overwrite the
          // explicit recovery receipt or recreate a projection the operator
          // was trying to diagnose. The drain performs the same check again
          // for status changes that happen after capture.
          if (changed && this.#connectionAcceptsSynchronization(row.id)) {
            this.#debounce(row.id, changed);
          }
        });
        watcher.on("error", (error) => this.#report(error, { connectionId: row.id }));
        this.#connections.set(row.id, { root: connection.vaultPath, watcher });
      } catch (error) {
        this.#markConnectionDegradedIfActive(row.id);
        this.#report(error, { connectionId: row.id });
      }
    }
    this.refreshHealthProofs(rows
      .filter(({ status }) => status === "connected")
      .map(({ id }) => id));
  }

  /**
   * Refresh a bounded number of due receipts per connection scan. The normal
   * 15-second scan means even a full default 16-connection batch is refreshed
   * well inside the five-minute composition window, without polling on a
   * mission request or granting an agent filesystem authority.
   */
  refreshHealthProofs(connectionIds = [...this.#connections.keys()]): void {
    if (!this.#bridge.refreshConnectionHealthProof
      || this.#stopping || this.#stopped) return;
    const now = this.#clock();
    const due = [...new Set(connectionIds)]
      .filter((id) =>
        now - (this.#lastHealthProofAt.get(id) ?? 0)
          >= this.#healthProofRefreshMs)
      .slice(0, this.#maximumHealthProofRefreshBatch);
    for (const connectionId of due) {
      try {
        this.#bridge.refreshConnectionHealthProof(
          connectionId,
          this.#actor,
        );
        this.#lastHealthProofAt.set(connectionId, now);
      } catch (error) {
        this.#markConnectionDegradedIfActive(connectionId);
        this.#report(error, { connectionId });
      }
    }
  }

  #debounce(connectionId: string, relativePath: string): void {
    if (this.#stopping || this.#stopped) return;
    const key = `${connectionId}\0${relativePath}`;
    const prior = this.#pending.get(key);
    if (prior) clearTimeout(prior);
    const timer = setTimeout(() => {
      this.#pending.delete(key);
      if (this.#stopping || this.#stopped) return;
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
    if (!this.#connectionAcceptsSynchronization(job.connectionId)) {
      this.#scheduleDrain();
      return;
    }
    this.#processing = true;
    try {
      this.#bridge.syncChangedPath(job.connectionId, job.relativePath, this.#actor);
      // Synchronizing one note proves neither rename/delete capability nor
      // current whole-Vault health. In particular, a degraded connection whose
      // path was removed and recreated must not become active by replaying a
      // queued file event against an older same-path receipt. Only the explicit
      // four-operation health verifier may restore active usability.
      this.#onProcessed?.(job);
    } catch (error) {
      this.#markConnectionDegradedIfActive(job.connectionId);
      this.#report(error, job);
    } finally {
      this.#processing = false;
      this.#scheduleDrain();
    }
  }

  #report(error: unknown, context: { connectionId?: string; relativePath?: string }): void {
    this.#onError?.(error instanceof Error ? error : new Error("Obsidian watcher operation failed"), context);
  }

  #connectionAcceptsSynchronization(connectionId: string): boolean {
    const current = this.#database.prepare(`
      SELECT status FROM vault_connections WHERE id = ?
    `).get(connectionId) as { readonly status: string } | undefined;
    return current?.status === "connected" || current?.status === "degraded";
  }

  #markConnectionDegradedIfActive(connectionId: string): void {
    if (!this.#connectionAcceptsSynchronization(connectionId)) return;
    try {
      this.#bridge.markConnectionHealth(connectionId, "degraded");
    } catch (healthError) {
      // Another process may commit a disconnect between the status read and
      // the conditional update. Reporting that race is sufficient; a watcher
      // callback must never terminate the server or revive retired state.
      this.#report(healthError, { connectionId });
    }
  }

  #discardQueuedWorkForConnection(connectionId: string): void {
    const prefix = `${connectionId}\0`;
    for (const [key, timer] of this.#pending) {
      if (!key.startsWith(prefix)) continue;
      clearTimeout(timer);
      this.#pending.delete(key);
    }
    for (let index = this.#queue.length - 1; index >= 0; index -= 1) {
      if (this.#queue[index]?.connectionId === connectionId) {
        this.#queue.splice(index, 1);
      }
    }
    if (this.#queue.length === 0 && this.#drainTimer) {
      clearTimeout(this.#drainTimer);
      this.#drainTimer = undefined;
    }
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

  /**
   * Fence new filesystem events while preserving already-debounced work for
   * the ordered shutdown drain. The bridge remains the sole synchronization
   * boundary; this method never reads or writes canonical memory directly.
   */
  beginStop(): void {
    if (this.#stopping || this.#stopped) return;
    this.#stopping = true;
    this.#started = false;
    if (this.#connectionTimer) clearInterval(this.#connectionTimer);
    this.#connectionTimer = undefined;
    this.#closeWatchers();

    const queued = new Set(this.#queue.map(({ connectionId, relativePath }) => (
      `${connectionId}\0${relativePath}`
    )));
    for (const [key, timer] of this.#pending) {
      clearTimeout(timer);
      if (queued.has(key)) continue;
      const separator = key.indexOf("\0");
      if (separator < 1 || separator === key.length - 1) continue;
      this.#queue.push({
        connectionId: key.slice(0, separator),
        relativePath: key.slice(separator + 1),
      });
      queued.add(key);
    }
    this.#pending.clear();
    this.#scheduleDrain();
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
    this.beginStop();
    try {
      await this.waitForIdle();
    } finally {
      this.#clearQueuedWork();
      this.#closeWatchers();
      this.#started = false;
      this.#stopped = true;
    }
  }
}

export function watchedRelativePath(root: string, absolutePath: string): string | undefined {
  return safeChangedNotePath(relative(root, absolutePath));
}

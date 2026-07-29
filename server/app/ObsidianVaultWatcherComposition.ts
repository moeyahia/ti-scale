import type { SqliteDatabase } from "../db/types";
import {
  ObsidianVaultWatcher,
  type ObsidianVaultWatcherOptions,
} from "../vault/ObsidianVaultWatcher";
import type { ObsidianVaultBridge } from "../vault/ObsidianVaultBridge";

export interface ProductionObsidianVaultWatcherOptions {
  readonly database: SqliteDatabase;
  /** Undefined when no Vault root was explicitly configured. */
  readonly bridge?: ObsidianVaultBridge;
  /** Test/platform seam. Production relies on the watcher defaults. */
  readonly watcherOptions?: ObsidianVaultWatcherOptions;
}

/**
 * Compose the production filesystem watcher only when the standalone process
 * has an explicitly configured Vault bridge. The watcher itself selects only
 * active persisted connections and writes through the bridge into canonical
 * SQLite; agents never receive direct Vault filesystem access.
 */
export function createProductionObsidianVaultWatcher(
  options: ProductionObsidianVaultWatcherOptions,
): ObsidianVaultWatcher | undefined {
  if (!options.bridge) return undefined;
  return new ObsidianVaultWatcher(
    options.database,
    options.bridge,
    options.watcherOptions,
  );
}

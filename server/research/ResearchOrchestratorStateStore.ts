import type { SqliteDatabase } from "../db";
import { canonicalJson, sha256, type JsonValue } from "./canonical";
import {
  ResearchOrchestrator,
  type ResearchOrchestratorSnapshot,
} from "./ResearchOrchestrator";

interface SnapshotRow {
  readonly value_json: string;
  readonly version: number;
}

function requireIdentity(value: string, label: string): string {
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 200 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new Error(`${label} is invalid.`);
  }
  return normalized;
}

/** Durable, namespaced state adapter for deterministic process restart. */
export class ResearchOrchestratorStateStore {
  readonly #key: string;

  constructor(
    private readonly database: SqliteDatabase,
    instanceId: string,
  ) {
    this.#key = `research.orchestrator.snapshot.${sha256(requireIdentity(instanceId, "Research orchestrator instance ID"))}`;
  }

  save(
    snapshot: ResearchOrchestratorSnapshot,
    actorId: string,
    savedAt: string,
  ): number {
    requireIdentity(actorId, "Research snapshot actor");
    if (!Number.isFinite(Date.parse(savedAt))) throw new Error("Research snapshot timestamp is invalid.");
    // Reconstruct before persistence so corrupt or non-reconciling snapshots never replace durable state.
    ResearchOrchestrator.restore(snapshot);
    const result = this.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', 1, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        value_json = excluded.value_json,
        sensitivity = 'private',
        version = settings.version + 1,
        updated_by = excluded.updated_by,
        updated_at = excluded.updated_at
    `).run(
      this.#key,
      canonicalJson(snapshot as unknown as JsonValue),
      actorId,
      savedAt,
    );
    if (result.changes !== 1) throw new Error("Research snapshot persistence did not update exactly one record.");
    const row = this.database.prepare("SELECT version FROM settings WHERE key = ?")
      .get(this.#key) as { readonly version: number } | undefined;
    if (row === undefined) throw new Error("Research snapshot version could not be read after persistence.");
    return row.version;
  }

  loadSnapshot(): ResearchOrchestratorSnapshot | undefined {
    const row = this.database.prepare("SELECT value_json, version FROM settings WHERE key = ?")
      .get(this.#key) as SnapshotRow | undefined;
    if (row === undefined) return undefined;
    let snapshot: ResearchOrchestratorSnapshot;
    try {
      snapshot = JSON.parse(row.value_json) as ResearchOrchestratorSnapshot;
    } catch {
      throw new Error("Persisted ResearchOrchestrator snapshot is malformed JSON.");
    }
    ResearchOrchestrator.restore(snapshot);
    return snapshot;
  }

  loadOrchestrator(): ResearchOrchestrator | undefined {
    const snapshot = this.loadSnapshot();
    return snapshot === undefined ? undefined : ResearchOrchestrator.restore(snapshot);
  }
}

import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { canonicalJson, canonicalValue, sha256, type JsonValue } from "../run-intelligence/serialization";
import type { ScriptArtifactActor } from "./types";
import { ScriptArtifactError } from "./types";

interface StoredMutation {
  readonly requestHash: string;
  readonly response: JsonValue;
}

function storageKey(scope: string, key: string, actor: ScriptArtifactActor): string {
  return `idempotency.script_artifacts_v24.${sha256(`${scope}\u0000${actor.type}\u0000${actor.id}\u0000${key}`)}`;
}

function storedMutation(value: string): StoredMutation {
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Script-artifact idempotency record is malformed");
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.requestHash !== "string" || !("response" in record)) {
    throw new Error("Script-artifact idempotency record is incomplete");
  }
  return { requestHash: record.requestHash, response: canonicalValue(record.response) };
}

/** Actor-bound, durable mutation replay that stores no submitted source body. */
export class ScriptArtifactIdempotencyStore {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  execute(
    scope: string,
    key: string,
    actor: ScriptArtifactActor,
    request: unknown,
    operation: () => unknown,
  ): { readonly response: JsonValue; readonly replayed: boolean } {
    const requestHash = sha256(canonicalJson(canonicalValue(request)));
    const settingKey = storageKey(scope, key, actor);
    return inImmediateTransaction(this.database, () => {
      const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(settingKey) as { readonly value_json: string } | undefined;
      if (row) {
        const stored = storedMutation(row.value_json);
        if (stored.requestHash !== requestHash) {
          throw new ScriptArtifactError(
            "script_artifact_idempotency_conflict",
            "Idempotency-Key was already used for a materially different script mutation",
            "state_conflict",
            409,
            "Use a new Idempotency-Key for the changed source or documentation.",
          );
        }
        return { response: stored.response, replayed: true };
      }
      const response = canonicalValue(operation());
      this.database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'restricted', 1, ?, ?)
      `).run(
        settingKey,
        canonicalJson({ requestHash, response }),
        actor.id,
        this.clock().toISOString(),
      );
      return { response, replayed: false };
    });
  }
}

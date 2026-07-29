import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { canonicalJson, canonicalValue, sha256, type JsonValue } from "./serialization";
import { idempotencyConflict } from "./RunIntelligenceHttpError";

interface StoredMutation {
  readonly requestHash: string;
  readonly response: JsonValue;
}

export interface RunIntelligenceIdempotentResult {
  readonly response: JsonValue;
  readonly replayed: boolean;
}

export interface RunIntelligenceIdempotencyActor {
  readonly id: string;
  readonly type: string;
}

function storageKey(scope: string, key: string, actor: RunIntelligenceIdempotencyActor): string {
  const digest = sha256(`${scope}\u0000${actor.type}\u0000${actor.id}\u0000${key}`);
  return `idempotency.run_intelligence_v24.${digest}`;
}

function storedMutation(value: string): StoredMutation {
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Run-intelligence idempotency record is malformed");
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.requestHash !== "string" || !("response" in record)) {
    throw new Error("Run-intelligence idempotency record is incomplete");
  }
  return { requestHash: record.requestHash, response: canonicalValue(record.response) };
}

/** Atomic, actor-bound mutation replay backed by the dedicated V2 database. */
export class RunIntelligenceIdempotencyStore {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  execute(
    scope: string,
    key: string,
    actor: RunIntelligenceIdempotencyActor,
    request: unknown,
    operation: () => unknown,
  ): RunIntelligenceIdempotentResult {
    const normalizedRequest = canonicalValue(request);
    const requestHash = sha256(canonicalJson(normalizedRequest));
    const settingKey = storageKey(scope, key, actor);
    return inImmediateTransaction(this.database, () => {
      const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(settingKey) as { readonly value_json: string } | undefined;
      if (row) {
        const stored = storedMutation(row.value_json);
        if (stored.requestHash !== requestHash) throw idempotencyConflict();
        return { response: stored.response, replayed: true };
      }

      const response = canonicalValue(operation());
      this.database.prepare(`
        INSERT INTO settings (
          key, value_json, sensitivity, version, updated_by, updated_at
        ) VALUES (?, ?, 'restricted', 1, ?, ?)
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

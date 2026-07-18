import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { stateConflict } from "./errors";
import type { JsonValue, OperationalActor } from "./types";
import { canonicalJson, sanitizedJson, sha256 } from "./validation";

interface StoredMutation {
  readonly requestHash: string;
  readonly response: JsonValue;
}

export interface IdempotentMutationResult {
  readonly response: JsonValue;
  readonly replayed: boolean;
}

function storageKey(scope: string, key: string, actor: OperationalActor): string {
  const digest = sha256(`${scope}\u0000${actor.type}\u0000${actor.id}\u0000${key}`);
  return `idempotency.operational_truth_v24.${digest}`;
}

function storedMutation(value: string): StoredMutation {
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Operational-truth idempotency record is malformed");
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.requestHash !== "string" || !("response" in record)) {
    throw new Error("Operational-truth idempotency record is incomplete");
  }
  return {
    requestHash: record.requestHash,
    response: sanitizedJson(record.response).value,
  };
}

/** Atomic mutation replay boundary backed by the dedicated V2 database. */
export class RouterIdempotencyStore {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  execute(
    scope: string,
    key: string,
    actor: OperationalActor,
    request: unknown,
    operation: () => unknown,
  ): IdempotentMutationResult {
    const normalizedRequest = sanitizedJson(request).value;
    const requestHash = sha256(canonicalJson(normalizedRequest));
    const settingKey = storageKey(scope, key, actor);
    return inImmediateTransaction(this.database, () => {
      const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(settingKey) as { readonly value_json: string } | undefined;
      if (row) {
        const stored = storedMutation(row.value_json);
        if (stored.requestHash !== requestHash) {
          throw stateConflict(
            "Idempotency-Key was already used for a materially different operational-truth mutation",
            "Use a new Idempotency-Key for the changed request.",
          );
        }
        return { response: stored.response, replayed: true };
      }

      const response = sanitizedJson(operation()).value;
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

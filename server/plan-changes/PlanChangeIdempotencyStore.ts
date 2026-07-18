import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import type { PlanChangeActor, PlanChangeJson } from "./types";
import { PlanChangeError } from "./types";

function canonical(value: unknown): PlanChangeJson {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") throw new TypeError("Idempotency input is not JSON-safe");
  return Object.fromEntries(Object.entries(value as Record<string, unknown>)
    .filter(([, child]) => child !== undefined)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, child]) => [key, canonical(child)]));
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Actor-bound, durable replay for harmful plan-change mutations. */
export class PlanChangeIdempotencyStore {
  constructor(private readonly database: SqliteDatabase, private readonly clock: () => Date = () => new Date()) {}

  execute(scope: string, key: string, actor: PlanChangeActor, request: unknown, operation: () => unknown): { readonly response: PlanChangeJson; readonly replayed: boolean } {
    const requestHash = digest(JSON.stringify(canonical(request)));
    const settingKey = `idempotency.plan_changes_v24.${digest(`${scope}\u0000${actor.type}\u0000${actor.id}\u0000${key}`)}`;
    return inImmediateTransaction(this.database, () => {
      const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?").get(settingKey) as { readonly value_json: string } | undefined;
      if (row) {
        const stored = JSON.parse(row.value_json) as { readonly requestHash?: unknown; readonly response?: unknown };
        if (stored.requestHash !== requestHash) throw new PlanChangeError("plan_change_idempotency_conflict", "Idempotency-Key was already used for a different plan mutation", "state_conflict", 409, "Use the original request body or a new Idempotency-Key.");
        return { response: canonical(stored.response), replayed: true };
      }
      const response = canonical(operation());
      this.database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'restricted', 1, ?, ?)
      `).run(settingKey, JSON.stringify({ requestHash, response }), actor.id, this.clock().toISOString());
      return { response, replayed: false };
    });
  }
}

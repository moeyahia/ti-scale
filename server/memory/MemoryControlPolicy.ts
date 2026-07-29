import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db/types";
import { inImmediateTransaction } from "../db/transaction";

export const MEMORY_CONTROL_KEY = "memory.control.global";

export const PERSONAL_PREFERENCE_POLICIES = ["candidate_only", "disabled"] as const;
export const OBSIDIAN_SYNC_SCOPES = ["disabled", "confirmed", "confirmed_and_verified"] as const;

export type PersonalPreferencePolicy = (typeof PERSONAL_PREFERENCE_POLICIES)[number];
export type ObsidianSyncScope = (typeof OBSIDIAN_SYNC_SCOPES)[number];

/**
 * Operator-owned global memory controls. Two safety invariants are deliberately
 * not switchable: engagement isolation and secret exclusion. A preference can
 * personalize presentation, but it can never broaden authorization or memory
 * scope.
 */
export interface MemoryControlPolicy {
  readonly enabled: boolean;
  readonly personalPreferencePolicy: PersonalPreferencePolicy;
  readonly operationalMemoryEnabled: boolean;
  readonly engagementIsolation: true;
  readonly defaultRetentionDays: number | null;
  readonly autonomousUse: boolean;
  readonly guidedUse: boolean;
  readonly obsidianSyncScope: ObsidianSyncScope;
  readonly secretsNeverRetained: true;
  readonly version: number;
  readonly updatedBy: string;
  readonly updatedAt: string;
}

export interface MemoryControlUpdate {
  readonly enabled: boolean;
  readonly personalPreferencePolicy: PersonalPreferencePolicy;
  readonly operationalMemoryEnabled: boolean;
  readonly engagementIsolation: true;
  readonly defaultRetentionDays: number | null;
  readonly autonomousUse: boolean;
  readonly guidedUse: boolean;
  readonly obsidianSyncScope: ObsidianSyncScope;
  readonly secretsNeverRetained: true;
}

const DEFAULT_CONTROL: Omit<MemoryControlPolicy, "version" | "updatedBy" | "updatedAt"> = {
  enabled: true,
  personalPreferencePolicy: "candidate_only",
  operationalMemoryEnabled: true,
  engagementIsolation: true,
  defaultRetentionDays: 365,
  autonomousUse: true,
  guidedUse: true,
  obsidianSyncScope: "confirmed_and_verified",
  secretsNeverRetained: true,
};

interface SettingRow {
  readonly value_json: string;
  readonly version: number;
  readonly updated_by: string;
  readonly updated_at: string;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function requiredBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new TypeError(`${label} must be boolean`);
  return value;
}

export function validateMemoryControlUpdate(value: unknown): MemoryControlUpdate {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("memory control policy must be an object");
  }
  const input = value as Record<string, unknown>;
  const personalPreferencePolicy = input.personalPreferencePolicy;
  if (typeof personalPreferencePolicy !== "string" || !PERSONAL_PREFERENCE_POLICIES.includes(personalPreferencePolicy as PersonalPreferencePolicy)) {
    throw new TypeError("personalPreferencePolicy is invalid");
  }
  const obsidianSyncScope = input.obsidianSyncScope;
  if (typeof obsidianSyncScope !== "string" || !OBSIDIAN_SYNC_SCOPES.includes(obsidianSyncScope as ObsidianSyncScope)) {
    throw new TypeError("obsidianSyncScope is invalid");
  }
  const defaultRetentionDays = input.defaultRetentionDays;
  if (defaultRetentionDays !== null && (!Number.isSafeInteger(defaultRetentionDays) || Number(defaultRetentionDays) < 1 || Number(defaultRetentionDays) > 3_650)) {
    throw new RangeError("defaultRetentionDays must be null or an integer from 1 through 3650");
  }
  if (input.engagementIsolation !== true) {
    throw new TypeError("engagementIsolation is a mandatory safety invariant and must remain true");
  }
  if (input.secretsNeverRetained !== true) {
    throw new TypeError("secretsNeverRetained is a mandatory safety invariant and must remain true");
  }
  return {
    enabled: requiredBoolean(input.enabled, "enabled"),
    personalPreferencePolicy: personalPreferencePolicy as PersonalPreferencePolicy,
    operationalMemoryEnabled: requiredBoolean(input.operationalMemoryEnabled, "operationalMemoryEnabled"),
    engagementIsolation: true,
    defaultRetentionDays: defaultRetentionDays === null ? null : Number(defaultRetentionDays),
    autonomousUse: requiredBoolean(input.autonomousUse, "autonomousUse"),
    guidedUse: requiredBoolean(input.guidedUse, "guidedUse"),
    obsidianSyncScope: obsidianSyncScope as ObsidianSyncScope,
    secretsNeverRetained: true,
  };
}

function decode(row: SettingRow): MemoryControlPolicy {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.value_json);
  } catch {
    throw new Error("Stored memory control policy is malformed");
  }
  return {
    ...validateMemoryControlUpdate(parsed),
    version: row.version,
    updatedBy: row.updated_by,
    updatedAt: row.updated_at,
  };
}

export function getMemoryControlPolicy(database: SqliteDatabase): MemoryControlPolicy {
  const row = database.prepare(`
    SELECT value_json, version, updated_by, updated_at FROM settings WHERE key = ?
  `).get(MEMORY_CONTROL_KEY) as SettingRow | undefined;
  return row
    ? decode(row)
    : {
        ...DEFAULT_CONTROL,
        version: 0,
        updatedBy: "system-default",
        updatedAt: "1970-01-01T00:00:00.000Z",
      };
}

export function updateMemoryControlPolicy(input: {
  readonly database: SqliteDatabase;
  readonly expectedVersion: number;
  readonly actor: string;
  readonly policy: unknown;
  readonly now?: string;
}): MemoryControlPolicy {
  if (!Number.isSafeInteger(input.expectedVersion) || input.expectedVersion < 0) {
    throw new RangeError("expectedVersion must be a non-negative integer");
  }
  if (!input.actor.trim() || input.actor.length > 256) throw new TypeError("memory policy actor is invalid");
  const policy = validateMemoryControlUpdate(input.policy);
  const now = input.now ?? new Date().toISOString();
  if (Number.isNaN(Date.parse(now))) throw new TypeError("memory policy timestamp is invalid");

  return inImmediateTransaction(input.database, () => {
    const current = getMemoryControlPolicy(input.database);
    if (current.version !== input.expectedVersion) {
      throw new Error(`memory control policy version does not match; expected ${input.expectedVersion}, current ${current.version}`);
    }
    const nextVersion = current.version + 1;
    const stored = canonicalJson(policy);
    input.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', ?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        value_json = excluded.value_json,
        sensitivity = excluded.sensitivity,
        version = excluded.version,
        updated_by = excluded.updated_by,
        updated_at = excluded.updated_at
    `).run(MEMORY_CONTROL_KEY, stored, nextVersion, input.actor, now);

    const previous = input.database.prepare(
      "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
    ).get() as { record_hash: string } | undefined;
    const auditId = `audit-memory-control-${randomUUID()}`;
    const changedFields = Object.keys(policy).filter((key) => (
      current[key as keyof typeof policy] !== policy[key as keyof typeof policy]
    )).sort();
    const auditDetails = { previousVersion: current.version, version: nextVersion, changedFields };
    const hashMaterial = {
      id: auditId,
      actor: input.actor,
      action: "memory.control.updated",
      resourceType: "memory_control_policy",
      resourceId: MEMORY_CONTROL_KEY,
      reason: "Operator updated explicit Second Brain controls",
      details: auditDetails,
      previousHash: previous?.record_hash ?? null,
      occurredAt: now,
    };
    const recordHash = sha256(canonicalJson(hashMaterial));
    input.database.prepare(`
      INSERT INTO audit_records (
        id, actor_type, actor_id, action, resource_type, resource_id, reason,
        details_json, previous_hash, record_hash, occurred_at
      ) VALUES (?, 'operator', ?, 'memory.control.updated', 'memory_control_policy', ?, ?, ?, ?, ?, ?)
    `).run(
      auditId,
      input.actor,
      MEMORY_CONTROL_KEY,
      "Operator updated explicit Second Brain controls",
      canonicalJson(auditDetails),
      previous?.record_hash ?? null,
      recordHash,
      now,
    );
    return getMemoryControlPolicy(input.database);
  });
}

export function memoryUseAllowed(
  policy: MemoryControlPolicy,
  journey: "autonomous" | "guided",
): boolean {
  return policy.enabled && (journey === "autonomous" ? policy.autonomousUse : policy.guidedUse);
}

export function memoryCandidateAllowed(
  policy: MemoryControlPolicy,
  nodeType: string,
): boolean {
  if (!policy.enabled) return false;
  if (nodeType === "preference") return policy.personalPreferencePolicy === "candidate_only";
  return policy.operationalMemoryEnabled;
}

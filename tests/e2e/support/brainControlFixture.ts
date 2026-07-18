import { mkdir, rmdir, stat, utimes } from "node:fs/promises";
import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { MEMORY_CONTROL_KEY } from "../../../server/memory/MemoryControlPolicy";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_TIME = "2099-07-16T19:00:00.000Z";
const LOCK_STALE_AFTER_MS = 30_000;
const LOCK_WAIT_LIMIT_MS = 5 * 60 * 1_000;
const lockHeartbeats = new Map<string, ReturnType<typeof setInterval>>();

export const BRAIN_CONTROL_FIXTURE_SECRET = "brain-control-fixture-auth-token-that-must-never-leave-the-database";

export const BRAIN_CONTROL_START_POLICY = {
  enabled: true,
  personalPreferencePolicy: "candidate_only",
  operationalMemoryEnabled: true,
  engagementIsolation: true,
  defaultRetentionDays: 365,
  autonomousUse: true,
  guidedUse: true,
  obsidianSyncScope: "confirmed_and_verified",
  secretsNeverRetained: true,
} as const;

export interface BrainControlFixture {
  readonly namespace: string;
  readonly seededVersion: number;
  readonly baselineAuditRowId: number;
  readonly lockDirectory: string;
}

export interface BrainControlFixtureSnapshot {
  readonly version: number;
  readonly updatedBy: string;
  readonly storedValue: Record<string, unknown>;
  readonly audits: readonly {
    readonly action: string;
    readonly actorId: string | null;
    readonly details: Record<string, unknown>;
    readonly previousHash: string | null;
    readonly recordHash: string;
  }[];
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Brain Control E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

function lockDirectory(): string {
  return `${databasePath()}.brain-control-fixture-lock`;
}

async function wait(milliseconds: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/**
 * The policy is intentionally global, so matrix projects must not mutate it
 * concurrently. This lock only coordinates this dedicated disposable fixture;
 * production behavior continues to rely on SQLite optimistic concurrency.
 */
export async function acquireBrainControlFixtureLock(): Promise<string> {
  const directory = lockDirectory();
  const deadline = Date.now() + LOCK_WAIT_LIMIT_MS;
  while (Date.now() < deadline) {
    try {
      await mkdir(directory);
      const heartbeat = setInterval(() => {
        const now = new Date();
        void utimes(directory, now, now).catch(() => undefined);
      }, 5_000);
      heartbeat.unref?.();
      lockHeartbeats.set(directory, heartbeat);
      return directory;
    } catch (error) {
      const code = error && typeof error === "object" && "code" in error
        ? String((error as { code?: unknown }).code)
        : "";
      if (code !== "EEXIST") throw error;
      try {
        const details = await stat(directory);
        if (Date.now() - details.mtimeMs > LOCK_STALE_AFTER_MS) {
          await rmdir(directory).catch(() => undefined);
          continue;
        }
      } catch {
        continue;
      }
      await wait(100);
    }
  }
  throw new Error("Timed out waiting for the isolated Brain Control fixture lock");
}

export async function releaseBrainControlFixtureLock(directory: string): Promise<void> {
  if (directory !== lockDirectory()) throw new Error("Refusing to release an unrelated fixture lock");
  const heartbeat = lockHeartbeats.get(directory);
  if (heartbeat) clearInterval(heartbeat);
  lockHeartbeats.delete(directory);
  await rmdir(directory).catch((error: unknown) => {
    const code = error && typeof error === "object" && "code" in error
      ? String((error as { code?: unknown }).code)
      : "";
    if (code !== "ENOENT") throw error;
  });
}

/**
 * Seeds the real settings table with one unknown secret-bearing fixture field.
 * The mounted API must strip that field on read, and a successful operator save
 * must replace the raw value with the validated canonical policy.
 */
export function createBrainControlFixture(instanceId: string, directory: string): BrainControlFixture {
  if (directory !== lockDirectory()) throw new Error("Brain Control fixture lock is not held");
  const namespace = normalizeFixtureNamespace(instanceId);
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    return inImmediateTransaction(database, () => {
      const current = database.prepare("SELECT version FROM settings WHERE key = ?")
        .get(MEMORY_CONTROL_KEY) as { readonly version: number } | undefined;
      const seededVersion = (current?.version ?? 0) + 1;
      const storedValue = {
        ...BRAIN_CONTROL_START_POLICY,
        fixtureAuthenticationToken: BRAIN_CONTROL_FIXTURE_SECRET,
      };
      database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'private', ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
          value_json = excluded.value_json,
          sensitivity = excluded.sensitivity,
          version = excluded.version,
          updated_by = excluded.updated_by,
          updated_at = excluded.updated_at
      `).run(
        MEMORY_CONTROL_KEY,
        JSON.stringify(storedValue),
        seededVersion,
        `e2e-brain-control-fixture-${namespace}`,
        FIXTURE_TIME,
      );
      const audit = database.prepare("SELECT COALESCE(MAX(rowid), 0) AS rowId FROM audit_records")
        .get() as { readonly rowId: number };
      return {
        namespace,
        seededVersion,
        baselineAuditRowId: audit.rowId,
        lockDirectory: directory,
      };
    });
  } finally {
    database.close();
  }
}

export function readBrainControlFixtureSnapshot(fixture: BrainControlFixture): BrainControlFixtureSnapshot {
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const setting = database.prepare(`
      SELECT value_json, version, updated_by FROM settings WHERE key = ?
    `).get(MEMORY_CONTROL_KEY) as {
      readonly value_json: string;
      readonly version: number;
      readonly updated_by: string;
    } | undefined;
    if (!setting) throw new Error("Canonical Brain Control fixture setting is missing");
    const audits = database.prepare(`
      SELECT actor_id, action, details_json, previous_hash, record_hash
      FROM audit_records
      WHERE rowid > ?
        AND resource_type = 'memory_control_policy'
        AND resource_id = ?
      ORDER BY rowid
    `).all(fixture.baselineAuditRowId, MEMORY_CONTROL_KEY) as Array<{
      readonly actor_id: string | null;
      readonly action: string;
      readonly details_json: string;
      readonly previous_hash: string | null;
      readonly record_hash: string;
    }>;
    return {
      version: setting.version,
      updatedBy: setting.updated_by,
      storedValue: JSON.parse(setting.value_json) as Record<string, unknown>,
      audits: audits.map((audit) => ({
        action: audit.action,
        actorId: audit.actor_id,
        details: JSON.parse(audit.details_json) as Record<string, unknown>,
        previousHash: audit.previous_hash,
        recordHash: audit.record_hash,
      })),
    };
  } finally {
    database.close();
  }
}

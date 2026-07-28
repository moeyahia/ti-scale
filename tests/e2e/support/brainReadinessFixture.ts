import { createHash } from "node:crypto";
import { join } from "node:path";
import { createDatabaseConnection } from "../../../server/db";
import { E2E_DATABASE_PATH, E2E_VAULT_ROOT } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

/**
 * Persists a previously verified Obsidian connection whose optional
 * filesystem projection is now unavailable. Canonical SQLite memory remains
 * untouched so browser tests can prove the two readiness signals are not
 * conflated.
 */
export function createOfflineVaultProjectionFixture(instanceId: string): void {
  if (!E2E_DATABASE_PATH) throw new Error("Brain readiness E2E requires the isolated V2 database path");
  const namespace = normalizeFixtureNamespace(instanceId);
  const connectionId = `vault-readiness-${namespace}`;
  const vaultPath = join(E2E_VAULT_ROOT, `offline-vault-${namespace}`);
  const now = new Date().toISOString();
  const database = createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    database.prepare(`
      INSERT INTO vault_connections (
        id, vault_path, display_name, status, sync_scope_json,
        permission_granted_at, created_at, updated_at
      ) VALUES (?, ?, ?, 'connected', '{}', ?, ?, ?)
    `).run(connectionId, vaultPath, `Offline readiness fixture ${namespace}`, now, now, now);
    database.prepare(`
      INSERT INTO audit_records (
        id, actor_type, actor_id, action, resource_type, resource_id,
        reason, details_json, record_hash, occurred_at
      ) VALUES (?, 'operator', 'e2e-local-operator', 'vault.health.verified',
        'vault_connection', ?, 'Prior bounded proof', '{}', ?, ?)
    `).run(
      `audit-vault-readiness-${namespace}`,
      connectionId,
      createHash("sha256").update(`offline-vault-readiness:${namespace}`, "utf8").digest("hex"),
      now,
    );
  } finally {
    database.close();
  }
}

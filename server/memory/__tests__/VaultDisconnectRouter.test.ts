import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import express from "express";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../MemoryRepository";
import { createSecondBrainRouter, type MemoryAccessPolicy } from "../SecondBrainRouter";
import { ObsidianVaultBridge } from "../../vault/ObsidianVaultBridge";
import { VaultPathPolicy } from "../../vault/VaultPathPolicy";

const directories: string[] = [];
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

async function fixture(options: {
  actor?: string;
  access?: MemoryAccessPolicy;
  replacement?: boolean;
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "vault-disconnect-router-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(database);
  const pathPolicy = new VaultPathPolicy(join(directory, "vaults"));
  const bridge = new ObsidianVaultBridge(database, new MemoryRepository(database), pathPolicy);
  const retiring = bridge.connect({
    id: "vault-generic",
    vaultPath: "Ti-Scale-Brain",
    displayName: "Ti-Scale Brain",
    permissionGranted: true,
  });
  const notePath = join(retiring.vaultPath, "operator-note.md");
  writeFileSync(notePath, "# Preserved operator note\n\nNo rewrite is permitted.\n", { mode: 0o600 });
  const replacement = options.replacement === false ? undefined : bridge.connect({
    id: "vault-attack-knowledge",
    vaultPath: "Attack-Knowledge-Vault",
    displayName: "Ti-Scale Attack Knowledge Vault",
    permissionGranted: true,
  });
  for (const [index, connection] of [retiring, replacement].filter(Boolean).entries()) {
    database.prepare(`
      INSERT INTO audit_records (
        id, actor_type, actor_id, action, resource_type, resource_id, reason,
        details_json, record_hash, occurred_at
      ) VALUES (?, 'operator', 'operator-fixture', 'vault.health.verified',
        'vault_connection', ?, 'Round trip passed', '{}', ?, ?)
    `).run(
      `audit-health-${index}`,
      connection!.id,
      createHash("sha256").update(`health-${index}`).digest("hex"),
      `2026-07-20T18:0${index}:00.000Z`,
    );
  }

  const app = express();
  app.use(express.json());
  app.use(createSecondBrainRouter({
    database,
    resolveActor: () => options.actor ?? "operator:vault-admin",
    resolveAccess: () => options.access ?? {
      maximumSensitivity: "restricted",
      allowGlobal: true,
      allEngagements: true,
    },
    vaultPathPolicy: pathPolicy,
    vaultBridge: bridge,
  }));
  const server = createServer(app);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Test server did not bind");
  return {
    database,
    bridge,
    retiring,
    replacement,
    notePath,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
}

function disconnectRequest(baseUrl: string, connectionId: string, body: Record<string, unknown>, key: string) {
  return fetch(`${baseUrl}/api/v2/brain/vault/${connectionId}/disconnect`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": key },
    body: JSON.stringify(body),
  });
}

describe("Obsidian Vault disconnect API", () => {
  test("disconnects once with optimistic concurrency and an immutable metadata-only audit", async () => {
    const state = await fixture();
    try {
      const noteBefore = readFileSync(state.notePath);
      const body = {
        expectedUpdatedAt: state.retiring.updatedAt,
        reason: "Retire the generic projection after the reviewed replacement passed health checks.",
        disconnectAcknowledged: true,
        allowProjectionDegraded: false,
        controlPlane: "ti_scale",
      };
      const response = await disconnectRequest(state.baseUrl, state.retiring.id, body, "vault-disconnect-router-0001");
      expect(response.status).toBe(200);
      const payload = await response.json() as {
        connection: { status: string; vaultPath: string };
        result: {
          auditRecordId: string;
          projectionState: string;
          replacementConnectionId: string;
          connectionVersion: string;
        };
      };
      expect(payload).toMatchObject({
        connection: { status: "disconnected", vaultPath: "Ti-Scale-Brain" },
        result: {
          projectionState: "healthy",
          replacementConnectionId: state.replacement!.id,
        },
      });
      expect(readFileSync(state.notePath)).toEqual(noteBefore);
      expect(() => state.bridge.requireConnection(state.retiring.id)).toThrow("disconnected");

      const replay = await disconnectRequest(state.baseUrl, state.retiring.id, body, "vault-disconnect-router-0001");
      expect(replay.status).toBe(200);
      expect((await replay.json() as { result: { auditRecordId: string } }).result.auditRecordId).toBe(payload.result.auditRecordId);
      expect(state.database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'vault.connection.disconnected' AND resource_id = ?
      `).get(state.retiring.id)).toEqual({ count: 1 });
      const audit = state.database.prepare(`
        SELECT reason, details_json AS detailsJson FROM audit_records WHERE id = ?
      `).get(payload.result.auditRecordId) as { reason: string; detailsJson: string };
      expect(audit.reason).toBe(body.reason);
      expect(JSON.parse(audit.detailsJson)).toMatchObject({
        syncStopped: true,
        filesDeleted: 0,
        notesRewritten: 0,
        controlPlane: "ti_scale",
      });
      expect(audit.detailsJson).not.toContain(state.retiring.vaultPath);

      const sync = await fetch(`${state.baseUrl}/api/v2/brain/vault/sync`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "vault-disconnect-sync-0001" },
        body: JSON.stringify({ connectionId: state.retiring.id }),
      });
      expect(sync.status).toBe(409);
      expect(await sync.json()).toMatchObject({ error: { code: "vault_connection_disconnected" } });
      for (const operation of ["repair", "reindex"] as const) {
        const recovery = await fetch(`${state.baseUrl}/api/v2/brain/vault/${operation}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": `vault-disconnect-${operation}-0001`,
          },
          body: JSON.stringify({
            connectionId: state.retiring.id,
            expectedUpdatedAt: payload.result.connectionVersion,
            controlPlane: "ti_scale",
          }),
        });
        expect(recovery.status).toBe(409);
        expect(await recovery.json()).toMatchObject({ error: { code: "vault_connection_disconnected" } });
      }
      expect(state.bridge.requireExistingConnection(state.retiring.id).status).toBe("disconnected");
      expect(readFileSync(state.notePath)).toEqual(noteBefore);
    } finally {
      state.database.close();
    }
  });

  test("fails closed for stale, under-authorized, and unacknowledged requests", async () => {
    const restricted = await fixture({ access: { maximumSensitivity: "restricted", allowGlobal: true, allEngagements: false } });
    try {
      const body = {
        expectedUpdatedAt: restricted.retiring.updatedAt,
        reason: "This request must not cross the workspace-wide authorization boundary.",
        disconnectAcknowledged: true,
        allowProjectionDegraded: false,
        controlPlane: "ti_scale",
      };
      const denied = await disconnectRequest(restricted.baseUrl, restricted.retiring.id, body, "vault-disconnect-denied-0001");
      expect(denied.status).toBe(403);
      expect(restricted.bridge.requireConnection(restricted.retiring.id).status).toBe("connected");
    } finally {
      restricted.database.close();
    }

    const state = await fixture();
    try {
      const missingAck = await disconnectRequest(state.baseUrl, state.retiring.id, {
        expectedUpdatedAt: state.retiring.updatedAt,
        reason: "The acknowledgement is deliberately absent from this request.",
        allowProjectionDegraded: false,
        controlPlane: "ti_scale",
      }, "vault-disconnect-no-ack-0001");
      expect(missingAck.status).toBe(400);
      const stale = await disconnectRequest(state.baseUrl, state.retiring.id, {
        expectedUpdatedAt: "2026-07-19T00:00:00.000Z",
        reason: "This stale version must not disconnect the current Vault connection.",
        disconnectAcknowledged: true,
        allowProjectionDegraded: false,
        controlPlane: "ti_scale",
      }, "vault-disconnect-stale-0001");
      expect(stale.status).toBe(409);
      expect(await stale.json()).toMatchObject({ error: { code: "vault_connection_version_conflict" } });
      expect(state.bridge.requireConnection(state.retiring.id).status).toBe("connected");
    } finally {
      state.database.close();
    }
  });

  test("requires explicit controlled degradation when no healthy replacement exists", async () => {
    const state = await fixture({ replacement: false });
    try {
      const common = {
        expectedUpdatedAt: state.retiring.updatedAt,
        reason: "Temporarily stop optional Obsidian projection while canonical SQLite memory remains active.",
        disconnectAcknowledged: true,
        controlPlane: "ti_scale",
      };
      const blocked = await disconnectRequest(state.baseUrl, state.retiring.id, {
        ...common,
        allowProjectionDegraded: false,
      }, "vault-disconnect-last-blocked-0001");
      expect(blocked.status).toBe(409);
      expect(await blocked.json()).toMatchObject({ error: { code: "vault_last_healthy_connection" } });

      const allowed = await disconnectRequest(state.baseUrl, state.retiring.id, {
        ...common,
        allowProjectionDegraded: true,
      }, "vault-disconnect-last-allowed-0001");
      expect(allowed.status).toBe(200);
      expect(await allowed.json()).toMatchObject({ result: { projectionState: "degraded" } });
    } finally {
      state.database.close();
    }
  });
});

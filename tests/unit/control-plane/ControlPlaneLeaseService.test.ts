import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ControlPlaneLeaseError,
  ControlPlaneLeaseService,
  type ControlPlaneLeaseErrorCode,
} from "../../../server/control-plane";
import { createDatabaseConnection, migrateDatabase } from "../../../server/db";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-control-plane-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "state.sqlite") });
  migrateDatabase(database);
  const now = "2026-07-16T09:00:00.000Z";
  database.prepare(`
    INSERT INTO missions (id, name, objective, journey, control_plane, created_by, created_at, updated_at)
    VALUES ('mission-v2', 'Lease fixture', 'Validate control ownership', 'autonomous',
      'ti_scale', 'operator', ?, ?)
  `).run(now, now);
  database.prepare(`
    INSERT INTO runs (id, mission_id, journey, status, control_plane, created_at, updated_at)
    VALUES ('run-v2', 'mission-v2', 'autonomous', 'queued', 'ti_scale', ?, ?)
  `).run(now, now);
  return { database, service: new ControlPlaneLeaseService(database) };
}

function expectCode(action: () => unknown, code: ControlPlaneLeaseErrorCode): void {
  try {
    action();
    throw new Error("Expected a ControlPlaneLeaseError");
  } catch (error) {
    expect(error).toBeInstanceOf(ControlPlaneLeaseError);
    expect((error as ControlPlaneLeaseError).code).toBe(code);
  }
}

describe("server-enforced control-plane leases", () => {
  test("stores only a token digest and authorizes the exact owner and plane", () => {
    const { database, service } = fixture();
    try {
      const acquired = service.acquire({
        runId: "run-v2",
        controlPlane: "ti_scale",
        leaseOwner: "worker-v2-a",
        leaseToken: "lease-token-a-000000000000",
        now: new Date("2026-07-16T09:00:00.000Z"),
      });
      expect(acquired.leaseToken).toBeUndefined();
      expect(acquired.lease.controlPlane).toBe("ti_scale");
      expect(service.assertMutationAuthority({
        runId: "run-v2",
        controlPlane: "ti_scale",
        leaseOwner: "worker-v2-a",
        leaseToken: "lease-token-a-000000000000",
        now: new Date("2026-07-16T09:00:10.000Z"),
      }).runId).toBe("run-v2");
      const stored = database.prepare(
        "SELECT lease_token_hash FROM control_plane_leases WHERE run_id = 'run-v2'",
      ).get() as { lease_token_hash: string };
      expect(stored.lease_token_hash).not.toContain("lease-token-a");
      expect(stored.lease_token_hash).toHaveLength(64);
    } finally {
      database.close();
    }
  });

  test("rejects legacy control, concurrent owners, wrong tokens, and expired authority", () => {
    const { database, service } = fixture();
    try {
      expectCode(() => service.acquire({
        runId: "run-v2",
        controlPlane: "legacy",
        leaseOwner: "legacy-ui",
      }), "control_plane_mismatch");
      service.acquire({
        runId: "run-v2",
        controlPlane: "ti_scale",
        leaseOwner: "worker-v2-a",
        leaseToken: "lease-token-a-000000000000",
        ttlMs: 5_000,
        now: new Date("2026-07-16T09:00:00.000Z"),
      });
      expectCode(() => service.acquire({
        runId: "run-v2",
        controlPlane: "ti_scale",
        leaseOwner: "worker-v2-b",
        leaseToken: "lease-token-b-000000000000",
        now: new Date("2026-07-16T09:00:01.000Z"),
      }), "lease_conflict");
      expectCode(() => service.assertMutationAuthority({
        runId: "run-v2",
        controlPlane: "ti_scale",
        leaseOwner: "worker-v2-a",
        leaseToken: "wrong-token-00000000000000",
        now: new Date("2026-07-16T09:00:02.000Z"),
      }), "lease_token_invalid");
      expectCode(() => service.assertMutationAuthority({
        runId: "run-v2",
        controlPlane: "ti_scale",
        leaseOwner: "worker-v2-a",
        leaseToken: "lease-token-a-000000000000",
        now: new Date("2026-07-16T09:00:06.000Z"),
      }), "lease_expired");
    } finally {
      database.close();
    }
  });

  test("heartbeats idempotently, releases with fencing, and permits expired takeover", () => {
    const { database, service } = fixture();
    try {
      const tokenA = "lease-token-a-000000000000";
      service.acquire({
        runId: "run-v2", controlPlane: "ti_scale", leaseOwner: "worker-v2-a",
        leaseToken: tokenA, ttlMs: 2_000, now: new Date("2026-07-16T09:00:00.000Z"),
      });
      const heartbeat = service.heartbeat({
        runId: "run-v2", controlPlane: "ti_scale", leaseOwner: "worker-v2-a",
        leaseToken: tokenA, ttlMs: 2_000, now: new Date("2026-07-16T09:00:01.000Z"),
      });
      expect(heartbeat.version).toBe(2);
      service.release({
        runId: "run-v2", controlPlane: "ti_scale", leaseOwner: "worker-v2-a",
        leaseToken: tokenA, now: new Date("2026-07-16T09:00:01.500Z"),
      });
      expectCode(() => service.assertMutationAuthority({
        runId: "run-v2", controlPlane: "ti_scale", leaseOwner: "worker-v2-a",
        leaseToken: tokenA, now: new Date("2026-07-16T09:00:01.600Z"),
      }), "lease_missing");
      const takeover = service.acquire({
        runId: "run-v2", controlPlane: "ti_scale", leaseOwner: "worker-v2-b",
        leaseToken: "lease-token-b-000000000000", now: new Date("2026-07-16T09:00:02.000Z"),
      });
      expect(takeover.lease.leaseOwner).toBe("worker-v2-b");
      expect(takeover.lease.version).toBe(4);
    } finally {
      database.close();
    }
  });
});

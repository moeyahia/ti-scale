import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  ControlPlaneLeaseError,
  ControlPlaneLeaseService,
} from "../ControlPlaneLeaseService";

function databaseWithRun(
  runId = "run-v2-control",
  controlPlane: "legacy" | "ti_scale" = "ti_scale",
) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  const now = "2026-07-16T12:00:00.000Z";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, control_plane,
      created_by, created_at, updated_at
    ) VALUES (?, ?, ?, 'autonomous', ?, 'operator', ?, ?)
  `).run(`mission-${runId}`, `Mission ${runId}`, "Validate one authorized target", controlPlane, now, now);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, control_plane, created_at, updated_at
    ) VALUES (?, ?, 'autonomous', 'queued', ?, ?, ?)
  `).run(runId, `mission-${runId}`, controlPlane, now, now);
  return database;
}

function expectLeaseCode(
  operation: () => unknown,
  code: ControlPlaneLeaseError["code"],
): void {
  try {
    operation();
    throw new Error("Expected the control-plane lease operation to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(ControlPlaneLeaseError);
    expect((error as ControlPlaneLeaseError).code).toBe(code);
  }
}

describe("ControlPlaneLeaseService", () => {
  test("grants one V2 authority, stores only a digest, and validates mutation ownership", () => {
    const database = databaseWithRun();
    try {
      const service = new ControlPlaneLeaseService(database);
      const acquired = service.acquire({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
        now: new Date("2026-07-16T12:00:00.000Z"),
        ttlMs: 30_000,
      });

      expect(acquired.leaseToken).toBeString();
      expect(acquired.lease).toMatchObject({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
        version: 1,
      });
      const raw = database.prepare(`
        SELECT lease_token_hash, lease_owner, released_at
        FROM control_plane_leases WHERE run_id = ?
      `).get("run-v2-control") as {
        lease_token_hash: string;
        lease_owner: string;
        released_at: string | null;
      };
      expect(raw.lease_token_hash).toHaveLength(64);
      expect(raw.lease_token_hash).not.toBe(acquired.leaseToken!);
      expect(raw.lease_owner).toBe("v2-worker-a");
      expect(raw.released_at).toBeNull();

      expect(service.assertMutationAuthority({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
        leaseToken: acquired.leaseToken!,
        now: new Date("2026-07-16T12:00:10.000Z"),
      })).toEqual(acquired.lease);
    } finally {
      database.close();
    }
  });

  test("rejects the wrong control plane, owner, token, and concurrent controller", () => {
    const database = databaseWithRun();
    try {
      const service = new ControlPlaneLeaseService(database);
      expectLeaseCode(() => service.acquire({
        runId: "run-v2-control",
        controlPlane: "legacy",
        leaseOwner: "legacy-ui",
      }), "control_plane_mismatch");

      const first = service.acquire({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
        leaseToken: "owner-a-token-material",
        now: new Date("2026-07-16T12:00:00.000Z"),
      });
      expect(first.leaseToken).toBeUndefined();

      expectLeaseCode(() => service.acquire({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-b",
        leaseToken: "owner-b-token-material",
        now: new Date("2026-07-16T12:00:01.000Z"),
      }), "lease_conflict");
      expectLeaseCode(() => service.assertMutationAuthority({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-b",
        leaseToken: "owner-a-token-material",
        now: new Date("2026-07-16T12:00:01.000Z"),
      }), "lease_token_invalid");
      expectLeaseCode(() => service.assertMutationAuthority({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
        leaseToken: "wrong-token-material",
        now: new Date("2026-07-16T12:00:01.000Z"),
      }), "lease_token_invalid");
    } finally {
      database.close();
    }
  });

  test("heartbeats the same authority, fences expiry, and permits deterministic takeover", () => {
    const database = databaseWithRun();
    try {
      const service = new ControlPlaneLeaseService(database);
      service.acquire({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
        leaseToken: "owner-a-token-material",
        ttlMs: 1_000,
        now: new Date("2026-07-16T12:00:00.000Z"),
      });
      const heartbeat = service.heartbeat({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
        leaseToken: "owner-a-token-material",
        ttlMs: 1_000,
        now: new Date("2026-07-16T12:00:00.750Z"),
      });
      expect(heartbeat.version).toBe(2);
      expect(heartbeat.expiresAt).toBe("2026-07-16T12:00:01.750Z");

      expectLeaseCode(() => service.assertMutationAuthority({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
        leaseToken: "owner-a-token-material",
        now: new Date("2026-07-16T12:00:01.750Z"),
      }), "lease_expired");

      const takeover = service.acquire({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-b",
        leaseToken: "owner-b-token-material",
        ttlMs: 5_000,
        now: new Date("2026-07-16T12:00:01.750Z"),
      });
      expect(takeover.lease).toMatchObject({ leaseOwner: "v2-worker-b", version: 3 });
      expect(service.assertMutationAuthority({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-b",
        leaseToken: "owner-b-token-material",
        now: new Date("2026-07-16T12:00:02.000Z"),
      }).leaseOwner).toBe("v2-worker-b");
    } finally {
      database.close();
    }
  });

  test("release is version-fenced and removes mutation authority", () => {
    const database = databaseWithRun();
    try {
      const service = new ControlPlaneLeaseService(database);
      const acquired = service.acquire({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
        now: new Date("2026-07-16T12:00:00.000Z"),
      });
      service.release({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
        leaseToken: acquired.leaseToken!,
        now: new Date("2026-07-16T12:00:01.000Z"),
      });
      expectLeaseCode(() => service.assertMutationAuthority({
        runId: "run-v2-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
        leaseToken: acquired.leaseToken!,
        now: new Date("2026-07-16T12:00:01.001Z"),
      }), "lease_missing");

      const released = database.prepare(`
        SELECT released_at, version FROM control_plane_leases WHERE run_id = ?
      `).get("run-v2-control") as { released_at: string | null; version: number };
      expect(released).toEqual({ released_at: "2026-07-16T12:00:01.000Z", version: 2 });
    } finally {
      database.close();
    }
  });

  test("never creates authority for a missing run or a legacy-owned run", () => {
    const database = databaseWithRun("run-legacy-control", "legacy");
    try {
      const service = new ControlPlaneLeaseService(database);
      expectLeaseCode(() => service.acquire({
        runId: "run-missing",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
      }), "run_not_found");
      expectLeaseCode(() => service.acquire({
        runId: "run-legacy-control",
        controlPlane: "ti_scale",
        leaseOwner: "v2-worker-a",
      }), "control_plane_mismatch");
      expect(database.prepare("SELECT COUNT(*) AS count FROM control_plane_leases").get())
        .toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });
});

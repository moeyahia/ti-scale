import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { CanonicalDatabaseLeaseConflictError } from "../CanonicalDatabaseLeaseService";
import { CanonicalDatabaseLeaseService } from "../CanonicalDatabaseLeaseService";
import {
  StoppedServiceRuntimeLeaseReconciliationService,
  type ServiceProcessBoundarySnapshot,
} from "../StoppedServiceRuntimeLeaseReconciliationService";

const NOW = new Date("2026-07-22T14:00:00.000Z");
const CGROUP = "/system.slice/ti-scale.service";

function database() {
  const result = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(result);
  return result;
}

function preStop(
  overrides: Partial<ServiceProcessBoundarySnapshot> = {},
): ServiceProcessBoundarySnapshot {
  return {
    activeState: "active",
    mainPid: 4100,
    controlGroup: CGROUP,
    controlGroupProcessIds: [4100, 4242],
    portListening: true,
    ...overrides,
  };
}

function stopped(
  overrides: Partial<ServiceProcessBoundarySnapshot> = {},
): ServiceProcessBoundarySnapshot {
  return {
    activeState: "inactive",
    mainPid: 0,
    controlGroup: CGROUP,
    controlGroupProcessIds: [],
    portListening: false,
    ...overrides,
  };
}

function input(overrides: Partial<{
  actorId: string;
  boundaryId: string;
  preStop: ServiceProcessBoundarySnapshot;
  stopped: ServiceProcessBoundarySnapshot;
}> = {}) {
  return {
    actorId: "release-controller:9000",
    boundaryId: "functional-release:release-a:service-stop",
    preStop: preStop(),
    stopped: stopped(),
    ...overrides,
  };
}

describe("StoppedServiceRuntimeLeaseReconciliationService", () => {
  test("releases and audits only the absent owner from the exact pre-stop cgroup", () => {
    const value = database();
    try {
      const leases = new CanonicalDatabaseLeaseService(value, { clock: () => NOW });
      const serviceLease = leases.acquireWriter({
        ownerId: "ti-scale-service:4242",
        operation: "standalone-service-runtime",
        ttlMs: 60_000,
      });
      const reconciler = new StoppedServiceRuntimeLeaseReconciliationService(value, {
        clock: () => NOW,
        createId: () => "audit_stopped_service_fixture",
        processExists: () => false,
      });
      const result = reconciler.reconcile(input());
      expect(result).toEqual({
        status: "released",
        leaseId: serviceLease.id,
        fencingToken: serviceLease.fencingToken,
        ownerPid: 4242,
        releasedAt: NOW.toISOString(),
        releaseReason: "stopped_service_owner_absent",
        auditRecordId: "audit_stopped_service_fixture",
        auditRecordHash: expect.stringMatching(/^[a-f0-9]{64}$/u),
      });
      expect(value.prepare(`
        SELECT released_at, release_reason
        FROM canonical_database_leases WHERE id = ?
      `).get(serviceLease.id)).toEqual({
        released_at: NOW.toISOString(),
        release_reason: "stopped_service_owner_absent",
      });
      const audit = value.prepare(`
        SELECT actor_type, actor_id, action, resource_type, resource_id,
          reason, details_json, record_hash
        FROM audit_records WHERE id = ?
      `).get("audit_stopped_service_fixture") as Record<string, string>;
      expect(audit).toMatchObject({
        actor_type: "system",
        actor_id: "release-controller:9000",
        action: "canonical_database_lease.stopped_service_owner_reconciled",
        resource_type: "canonical_database_lease",
        resource_id: serviceLease.id,
        record_hash: result.status === "released" ? result.auditRecordHash : "unreachable",
      });
      expect(JSON.parse(audit.details_json)).toMatchObject({
        schemaVersion: "ti-scale.stopped-service-runtime-lease-reconciliation.v1",
        boundaryId: "functional-release:release-a:service-stop",
        ownerPid: 4242,
        ownerProcessProvenAbsent: true,
        additionalActiveLeases: 0,
      });

      const maintenance = leases.acquireMaintenance({
        ownerId: "release-controller:9000",
        operation: "functional-release",
      });
      expect(maintenance.fencingToken).toBeGreaterThan(serviceLease.fencingToken);
    } finally {
      value.close();
    }
  });

  test("is idempotently a no-op when graceful shutdown already released the lease", () => {
    const value = database();
    try {
      const leases = new CanonicalDatabaseLeaseService(value, { clock: () => NOW });
      const handle = leases.acquireWriter({
        ownerId: "ti-scale-service:4242",
        operation: "standalone-service-runtime",
        ttlMs: 60_000,
      });
      leases.release(handle, "service-shutdown:SIGTERM");
      const reconciler = new StoppedServiceRuntimeLeaseReconciliationService(value, {
        clock: () => NOW,
        processExists: () => { throw new Error("must not probe a released owner"); },
      });
      expect(reconciler.reconcile(input())).toEqual({
        status: "not_required",
        inspectedAt: NOW.toISOString(),
      });
      expect(value.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'canonical_database_lease.stopped_service_owner_reconciled'
      `).get()).toEqual({ count: 0 });
    } finally {
      value.close();
    }
  });

  test("refuses a PID outside the pre-stop cgroup or one still present", () => {
    for (const scenario of ["not-in-cgroup", "still-alive"] as const) {
      const value = database();
      try {
        const leases = new CanonicalDatabaseLeaseService(value, { clock: () => NOW });
        const handle = leases.acquireWriter({
          ownerId: "ti-scale-service:4242",
          operation: "standalone-service-runtime",
          ttlMs: 60_000,
        });
        const reconciler = new StoppedServiceRuntimeLeaseReconciliationService(value, {
          clock: () => NOW,
          processExists: () => scenario === "still-alive",
        });
        expect(() => reconciler.reconcile(input({
          ...(scenario === "not-in-cgroup"
            ? { preStop: preStop({ controlGroupProcessIds: [4100] }) }
            : {}),
        }))).toThrow(
          scenario === "not-in-cgroup" ? "not present in the captured pre-stop cgroup" : "still present",
        );
        expect(value.prepare(`
          SELECT released_at, release_reason FROM canonical_database_leases WHERE id = ?
        `).get(handle.id)).toEqual({ released_at: null, release_reason: null });
      } finally {
        value.close();
      }
    }
  });

  test("does not weaken any other active canonical lease conflict", () => {
    const value = database();
    try {
      const leases = new CanonicalDatabaseLeaseService(value, { clock: () => NOW });
      const service = leases.acquireWriter({
        ownerId: "ti-scale-service:4242",
        operation: "standalone-service-runtime",
        ttlMs: 60_000,
      });
      const other = leases.acquireWriter({
        ownerId: "vault:worker",
        operation: "obsidian-sync",
        ttlMs: 60_000,
      });
      const reconciler = new StoppedServiceRuntimeLeaseReconciliationService(value, {
        clock: () => NOW,
        processExists: () => false,
      });
      expect(() => reconciler.reconcile(input())).toThrow("additional canonical database lease");
      expect(value.prepare(`
        SELECT id, released_at FROM canonical_database_leases ORDER BY fencing_token
      `).all()).toEqual([
        { id: service.id, released_at: null },
        { id: other.id, released_at: null },
      ]);
      expect(() => leases.acquireMaintenance({
        ownerId: "release-controller:9000",
        operation: "functional-release",
      })).toThrow(CanonicalDatabaseLeaseConflictError);
    } finally {
      value.close();
    }
  });

  test("refuses non-service ownership and an incomplete stopped boundary", () => {
    for (const scenario of ["wrong-owner", "nonempty-stop", "changed-cgroup"] as const) {
      const value = database();
      try {
        const leases = new CanonicalDatabaseLeaseService(value, { clock: () => NOW });
        const handle = leases.acquireWriter({
          ownerId: scenario === "wrong-owner" ? "worker:4242" : "ti-scale-service:4242",
          operation: "standalone-service-runtime",
          ttlMs: 60_000,
        });
        const reconciler = new StoppedServiceRuntimeLeaseReconciliationService(value, {
          clock: () => NOW,
          processExists: () => false,
        });
        expect(() => reconciler.reconcile(input({
          ...(scenario === "nonempty-stop"
            ? { stopped: stopped({ controlGroupProcessIds: [4242] }) }
            : scenario === "changed-cgroup"
              ? { stopped: stopped({ controlGroup: "/system.slice/other.service" }) }
              : {}),
        }))).toThrow(
          scenario === "wrong-owner"
            ? "not the exact standalone service writer"
            : scenario === "nonempty-stop"
              ? "inactive, empty, non-listening"
              : "unchanged systemd cgroup identity",
        );
        expect(value.prepare(`
          SELECT released_at FROM canonical_database_leases WHERE id = ?
        `).get(handle.id)).toEqual({ released_at: null });
      } finally {
        value.close();
      }
    }
  });
});

import { describe, expect, test } from "bun:test";
import type { RuntimeReadinessSnapshot } from "../../../src/domain/types/runtimeReadiness";
import {
  runtimeReadinessChanged,
  runtimeReadinessVersion,
} from "../../../src/features/missions/runtimeReadinessVersion";

function readiness(
  overrides: Partial<RuntimeReadinessSnapshot["execution"]> = {},
  checkedAt = "2026-07-20T00:00:00.000Z",
): RuntimeReadinessSnapshot {
  return {
    schemaVersion: "2.4",
    status: "healthy",
    execution: {
      autonomous: "ready",
      guided: "ready",
      guidedToolExecution: "ready",
      localCommanderGuidance: "ready",
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
      ...overrides,
    },
    dependencies: {
      providers: {
        status: "available",
        initializing: false,
        probing: 0,
        reason: null,
        declared: 1,
        callable: 1,
        enforcing: 1,
        guidedCapable: 1,
      },
      mcp: {
        status: "available",
        initializing: false,
        probingServers: 0,
        reason: null,
        configuredServers: 1,
        runnableServers: 1,
        executionMode: "enabled",
      },
      secondBrain: {
        status: "healthy",
        canonicalStoreAvailable: true,
        reason: null,
      },
    },
    checkedAt,
  };
}

describe("Autonomous runtime readiness version", () => {
  test("does not retire a review for a later observation of the same capability state", () => {
    const original = readiness();
    const later = readiness({}, "2026-07-20T00:01:00.000Z");

    expect(runtimeReadinessVersion(original).signature)
      .toBe(runtimeReadinessVersion(later).signature);
    expect(runtimeReadinessChanged(runtimeReadinessVersion(original), later)).toBe(false);
  });

  test("ignores rotating nested attestation timestamps and completion receipts", () => {
    const base = readiness();
    const original = {
      ...base,
      dependencies: {
        ...base.dependencies,
        localTools: {
          status: "available",
          readyToolIds: ["kali:nmap", "kali:host"],
          route: {
            status: "ready",
            reason: "Reviewed local boundary is active.",
            checkedAt: "2026-07-20T00:00:00.000Z",
            attestedAt: "2026-07-20T00:00:00.000Z",
            expiresAt: "2026-07-20T00:01:00.000Z",
            completionReceiptId: "receipt-old",
          },
        },
      },
    } as unknown as RuntimeReadinessSnapshot;
    const rotated = {
      ...base,
      dependencies: {
        ...base.dependencies,
        localTools: {
          status: "available",
          readyToolIds: ["kali:host", "kali:nmap"],
          route: {
            status: "ready",
            reason: "Reviewed local boundary is active.",
            checkedAt: "2026-07-20T00:01:00.000Z",
            attestedAt: "2026-07-20T00:01:00.000Z",
            expiresAt: "2026-07-20T00:02:00.000Z",
            completionReceiptId: "receipt-new",
          },
        },
      },
    } as unknown as RuntimeReadinessSnapshot;

    expect(runtimeReadinessVersion(original).signature)
      .toBe(runtimeReadinessVersion(rotated).signature);
    expect(runtimeReadinessChanged(runtimeReadinessVersion(original), rotated)).toBe(false);
  });

  test("preserves semantic ready IDs when volatile metadata is removed", () => {
    const base = readiness();
    const original = {
      ...base,
      dependencies: {
        ...base.dependencies,
        localTools: { status: "available", readyToolIds: ["kali:host"] },
      },
    } as unknown as RuntimeReadinessSnapshot;
    const expanded = {
      ...base,
      dependencies: {
        ...base.dependencies,
        localTools: { status: "available", readyToolIds: ["kali:host", "kali:nmap"] },
      },
    } as unknown as RuntimeReadinessSnapshot;

    expect(runtimeReadinessChanged(runtimeReadinessVersion(original), expanded)).toBe(true);
  });

  test("retires a review when a material execution boundary changes", () => {
    const original = readiness({ autonomous: "unavailable", actionBoundaryActive: false });
    const recovered = readiness({ autonomous: "ready", actionBoundaryActive: true });

    expect(runtimeReadinessChanged(runtimeReadinessVersion(original), recovered)).toBe(true);
  });

  test("retires a review when dependency readiness changes", () => {
    const original = readiness();
    const changed: RuntimeReadinessSnapshot = {
      ...original,
      dependencies: {
        ...original.dependencies,
        mcp: {
          ...original.dependencies.mcp,
          status: "unavailable",
          runnableServers: 0,
          reason: "The reviewed server stopped responding.",
        },
      },
    };

    expect(runtimeReadinessChanged(runtimeReadinessVersion(original), changed)).toBe(true);
  });
});

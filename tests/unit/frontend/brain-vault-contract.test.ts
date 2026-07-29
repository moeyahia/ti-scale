/// <reference lib="dom" />

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { checkVaultHealth } from "../../../src/data/api/brain";
import { parseVaultSnapshot } from "../../../src/domain/schemas/brain";

let originalFetch: typeof globalThis.fetch;
let originalDocument: PropertyDescriptor | undefined;
let requests: Array<{ path: string; init?: RequestInit }>;

beforeEach(() => {
  originalFetch = globalThis.fetch;
  originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  requests = [];
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: { cookie: "ti_scale_csrf=vault-csrf-proof" },
  });
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    requests.push({ path: typeof input === "string" ? input : input.toString(), init });
    return new Response(JSON.stringify({
      schemaVersion: "2.4",
      result: {
        status: "healthy",
        connectionId: "vault-one",
        vaultPath: "Disposable-Brain",
        checkedAt: "2026-07-16T21:00:00.000Z",
        checks: { write: true, read: true, rename: true, delete: true },
        message: "Vault path completed the round-trip.",
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } });
  }) as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalDocument) Object.defineProperty(globalThis, "document", originalDocument);
  else Reflect.deleteProperty(globalThis, "document");
});

describe("Brain Vault presentation contract", () => {
  test("uses the mounted mutation for candidate and connected round-trip checks", async () => {
    await checkVaultHealth({ vaultPath: "Disposable-Brain", permissionGranted: true });
    await checkVaultHealth({ connectionId: "vault-one" });

    expect(requests.map((item) => item.path)).toEqual([
      "/api/v2/brain/vault/health-check",
      "/api/v2/brain/vault/health-check",
    ]);
    expect(requests.map((item) => JSON.parse(String(item.init?.body)))).toEqual([
      { vaultPath: "Disposable-Brain", permissionGranted: true },
      { connectionId: "vault-one" },
    ]);
    expect(requests.every((item) => Boolean(new Headers(item.init?.headers).get("Idempotency-Key")))).toBe(true);
    expect(requests.every((item) => new Headers(item.init?.headers).get("X-Ti-Scale-CSRF") === "vault-csrf-proof"))
      .toBe(true);
  });

  test("preserves truthful disabled and health-verified connection states", () => {
    expect(parseVaultSnapshot({ schemaVersion: "2.4", enabled: false, connections: [], syncStates: [], conflicts: [] }))
      .toEqual({ enabled: false, connections: [], syncStates: [], conflicts: [] });

    const connected = parseVaultSnapshot({
      schemaVersion: "2.4",
      enabled: true,
      syncEnabled: true,
      allowedRootLabel: "vaults-fixture",
      connections: [{
        id: "vault-one",
        vaultPath: "Disposable-Brain",
        displayName: "Disposable Brain",
        status: "connected",
        syncScope: {},
        permissionGrantedAt: "2026-07-16T21:00:00.000Z",
        lastHealthCheckAt: "2026-07-16T21:00:01.000Z",
        healthChecks: { write: true, read: true, rename: true, delete: true },
        trackedNoteCount: 64_697,
        needsReviewCount: 0,
        createdAt: "2026-07-16T21:00:00.000Z",
        updatedAt: "2026-07-16T21:00:01.000Z",
      }],
      syncStates: [],
      conflicts: [],
    });
    expect(connected.connections[0]).toMatchObject({
      status: "connected",
      healthChecks: { write: true, read: true, rename: true, delete: true },
      trackedNoteCount: 64_697,
      needsReviewCount: 0,
    });
  });

  test("requires a conflict path so a post-mutation snapshot can render its recovery controls", () => {
    const snapshot = parseVaultSnapshot({
      schemaVersion: "2.4",
      enabled: true,
      syncEnabled: true,
      connections: [],
      syncStates: [],
      conflicts: [{
        id: "conflict-one",
        connectionId: "vault-one",
        nodeId: "memory-one",
        relativePath: "41 Attack Paths/example--memory-one.md",
        status: "open",
        databaseVersion: 2,
        detectedAt: "2026-07-16T21:00:02.000Z",
      }],
    });
    expect(snapshot.conflicts[0]).toMatchObject({
      relativePath: "41 Attack Paths/example--memory-one.md",
      status: "open",
      databaseVersion: 2,
    });
    expect(() => parseVaultSnapshot({
      schemaVersion: "2.4",
      enabled: true,
      connections: [],
      syncStates: [],
      conflicts: [{
        id: "conflict-without-path",
        connectionId: "vault-one",
        status: "open",
        detectedAt: "2026-07-16T21:00:02.000Z",
      }],
    })).toThrow("vault conflict path");
  });
});

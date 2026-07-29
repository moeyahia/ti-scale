import { describe, expect, test } from "bun:test";
import {
  clearMutationAttemptStorage,
  resolveLocalSessionState,
} from "../../../src/app/providers/AuthProvider";
import { parseLocalSession } from "../../../src/data/api/auth";
import { BROWSER_STORAGE_KEYS } from "../../../src/lib/browserNamespaces";

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();

  get length(): number {
    return this.values.size;
  }

  clear(): void {
    this.values.clear();
  }

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  key(index: number): string | null {
    return [...this.values.keys()][index] ?? null;
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
}

function seedMutationIntents(storage: Storage): {
  readonly recovery: string;
  readonly research: string;
  readonly unrelated: string;
} {
  const recovery =
    `${BROWSER_STORAGE_KEYS.recoveryMutationIntentPrefix}.run-1`;
  const research =
    `${BROWSER_STORAGE_KEYS.researchPromotionIntentPrefix}.operator.experiment-1`;
  const unrelated = "ti-scale.unrelated-session-value";
  storage.setItem(recovery, "recovery-intent");
  storage.setItem(research, "research-intent");
  storage.setItem(unrelated, "keep");
  return { recovery, research, unrelated };
}

describe("strict local session boundary", () => {
  test("accepts only canonical authenticated and unauthenticated session shapes", () => {
    expect(parseLocalSession({
      schemaVersion: "2.4",
      authenticated: true,
      actorId: "operator-research",
      expiresAt: "2026-07-24T20:00:00.000Z",
    })).toEqual({
      schemaVersion: "2.4",
      configured: true,
      authenticated: true,
      actorId: "operator-research",
      expiresAt: "2026-07-24T20:00:00.000Z",
    });
    expect(parseLocalSession({
      schemaVersion: "2.4",
      configured: false,
      authenticated: false,
    })).toEqual({
      schemaVersion: "2.4",
      configured: false,
      authenticated: false,
    });
    expect(parseLocalSession({
      schemaVersion: "2.4",
      authenticated: false,
    })).toEqual({
      schemaVersion: "2.4",
      configured: true,
      authenticated: false,
    });
  });

  test("rejects missing, malformed, contradictory, and surplus session identity", () => {
    const invalid = [
      {
        schemaVersion: "2.4",
        authenticated: true,
        expiresAt: "2026-07-24T20:00:00.000Z",
      },
      {
        schemaVersion: "2.4",
        authenticated: true,
        actorId: "operator-research",
      },
      {
        schemaVersion: "2.4",
        authenticated: true,
        actorId: "operator research",
        expiresAt: "2026-07-24T20:00:00.000Z",
      },
      {
        schemaVersion: "2.4",
        configured: false,
        authenticated: true,
        actorId: "operator-research",
        expiresAt: "2026-07-24T20:00:00.000Z",
      },
      {
        schemaVersion: "2.4",
        authenticated: true,
        actorId: "operator-research",
        expiresAt: "not-a-time",
      },
      {
        schemaVersion: "2.4",
        authenticated: false,
        actorId: "operator-research",
      },
      {
        schemaVersion: "2.4",
        authenticated: false,
        unexpected: "field",
      },
    ];
    for (const session of invalid) {
      expect(() => parseLocalSession(session)).toThrow();
    }
  });

  test("clears retained mutation intent on logout and expiry without touching unrelated state", () => {
    const storage = new MemoryStorage();
    const keys = seedMutationIntents(storage);

    const loggedOut = resolveLocalSessionState({
      schemaVersion: "2.4",
      configured: true,
      authenticated: false,
    }, Date.parse("2026-07-24T12:00:00.000Z"), storage);
    expect(loggedOut.authenticated).toBe(false);
    expect(storage.getItem(keys.recovery)).toBeNull();
    expect(storage.getItem(keys.research)).toBeNull();
    expect(storage.getItem(keys.unrelated)).toBe("keep");

    seedMutationIntents(storage);
    const expired = resolveLocalSessionState({
      schemaVersion: "2.4",
      configured: true,
      authenticated: true,
      actorId: "operator-research",
      expiresAt: "2026-07-24T11:59:59.000Z",
    }, Date.parse("2026-07-24T12:00:00.000Z"), storage);
    expect(expired).toEqual({
      schemaVersion: "2.4",
      configured: true,
      authenticated: false,
    });
    expect(storage.getItem(keys.recovery)).toBeNull();
    expect(storage.getItem(keys.research)).toBeNull();
    expect(storage.getItem(keys.unrelated)).toBe("keep");
  });

  test("retains mutation intent only while the canonical session remains active", () => {
    const storage = new MemoryStorage();
    const keys = seedMutationIntents(storage);
    const active = resolveLocalSessionState({
      schemaVersion: "2.4",
      configured: true,
      authenticated: true,
      actorId: "operator-research",
      expiresAt: "2026-07-24T12:30:00.000Z",
    }, Date.parse("2026-07-24T12:00:00.000Z"), storage);
    expect(active.authenticated).toBe(true);
    expect(storage.getItem(keys.recovery)).toBe("recovery-intent");
    expect(storage.getItem(keys.research)).toBe("research-intent");

    clearMutationAttemptStorage(storage);
    expect(storage.getItem(keys.recovery)).toBeNull();
    expect(storage.getItem(keys.research)).toBeNull();
    expect(storage.getItem(keys.unrelated)).toBe("keep");
  });
});

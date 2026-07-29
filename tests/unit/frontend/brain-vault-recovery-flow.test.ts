import { describe, expect, test } from "bun:test";
import type { VaultRecoveryResult } from "../../../src/domain/types/brain";
import {
  commitThenReconcile,
  createVaultRecoveryAttempt,
  executeVaultRecoveryAttempt,
} from "../../../src/features/brain/vaultRecoveryFlow";

const receipt: VaultRecoveryResult = {
  operation: "repair",
  connectionId: "vault-one",
  status: "completed",
  startedAt: "2026-07-17T00:00:00.000Z",
  completedAt: "2026-07-17T00:00:01.000Z",
  elapsedMs: 1_000,
  expectedConnectionVersion: "2026-07-17T00:00:00.000Z",
  connectionVersion: "2026-07-17T00:00:01.000Z",
  health: {
    checkedAt: "2026-07-17T00:00:00.500Z",
    checks: { write: true, read: true, rename: true, delete: true },
  },
  progress: { discovered: 1, processed: 1, remaining: 0 },
  counts: {
    synced: 1,
    databaseAhead: 0,
    vaultAhead: 0,
    conflictsPreserved: 0,
    quarantined: 0,
    missing: 0,
    pending: 0,
    indexed: 0,
    skipped: 0,
    errors: 0,
  },
  issues: [],
  issueSampleTruncated: false,
  message: "Vault repair committed.",
};

describe("Brain Vault committed-mutation recovery flow", () => {
  test("preserves the committed receipt when the snapshot refresh fails", async () => {
    let committed: VaultRecoveryResult | undefined;
    let mutations = 0;
    let reconciliations = 0;
    const outcome = await commitThenReconcile({
      mutate: async () => {
        mutations += 1;
        return receipt;
      },
      reconcile: async () => {
        reconciliations += 1;
        throw new Error("GET /brain/vault failed after commit");
      },
      onCommitted: (result) => { committed = result; },
    });

    expect(mutations).toBe(1);
    expect(reconciliations).toBe(1);
    expect(committed).toBe(receipt);
    expect(outcome.result).toBe(receipt);
    expect(outcome.reconcileError?.message).toContain("failed after commit");

    // A UI refresh retry is read-only; the committed mutation is not repeated.
    await Promise.resolve().then(() => { reconciliations += 1; });
    expect(mutations).toBe(1);
    expect(reconciliations).toBe(2);
  });

  test("reuses one operation and idempotency key after an ambiguous POST failure", async () => {
    const attempt = createVaultRecoveryAttempt({
      operation: "repair",
      connectionId: "vault-one",
      expectedUpdatedAt: "2026-07-17T00:00:00.000Z",
      idempotencyKey: "vault-repair-stable-key",
    });
    const calls: Array<{ connectionId: string; version: string; key: string }> = [];
    const repair = async (connectionId: string, version: string, key: string) => {
      calls.push({ connectionId, version, key });
      if (calls.length === 1) throw new Error("response lost after server commit");
      return receipt;
    };
    const reindex = async () => ({ ...receipt, operation: "reindex" as const });

    await expect(executeVaultRecoveryAttempt(attempt, repair, reindex)).rejects.toThrow("response lost");
    expect(await executeVaultRecoveryAttempt(attempt, repair, reindex)).toBe(receipt);
    expect(calls).toEqual([
      { connectionId: "vault-one", version: attempt.expectedUpdatedAt, key: "vault-repair-stable-key" },
      { connectionId: "vault-one", version: attempt.expectedUpdatedAt, key: "vault-repair-stable-key" },
    ]);
  });
});

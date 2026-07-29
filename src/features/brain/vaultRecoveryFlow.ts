import type { VaultRecoveryResult } from "../../domain/types/brain";

export interface VaultRecoveryAttempt {
  readonly operation: "repair" | "reindex";
  readonly connectionId: string;
  readonly expectedUpdatedAt: string;
  readonly idempotencyKey: string;
}

export interface CommitReconcileOutcome<T> {
  readonly result: T;
  readonly reconcileError?: Error;
}

export function createVaultRecoveryAttempt(input: VaultRecoveryAttempt): VaultRecoveryAttempt {
  return Object.freeze({ ...input });
}

/**
 * Mutation success is durable independently from the read-after-write refresh.
 * The committed callback runs before reconciliation so a failed GET cannot
 * erase the server receipt or cause a second mutation under a new key.
 */
export async function commitThenReconcile<T>(input: {
  readonly mutate: () => Promise<T>;
  readonly reconcile: () => Promise<unknown>;
  readonly onCommitted?: (result: T) => void;
}): Promise<CommitReconcileOutcome<T>> {
  const result = await input.mutate();
  input.onCommitted?.(result);
  try {
    await input.reconcile();
    return { result };
  } catch (error) {
    return {
      result,
      reconcileError: error instanceof Error ? error : new Error("Vault status refresh failed"),
    };
  }
}

export type VaultRecoveryMutation = (
  connectionId: string,
  expectedUpdatedAt: string,
  idempotencyKey: string,
) => Promise<VaultRecoveryResult>;

export function executeVaultRecoveryAttempt(
  attempt: VaultRecoveryAttempt,
  repair: VaultRecoveryMutation,
  reindex: VaultRecoveryMutation,
): Promise<VaultRecoveryResult> {
  return (attempt.operation === "repair" ? repair : reindex)(
    attempt.connectionId,
    attempt.expectedUpdatedAt,
    attempt.idempotencyKey,
  );
}

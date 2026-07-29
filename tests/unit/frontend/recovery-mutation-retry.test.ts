import { afterEach, describe, expect, test } from "bun:test";
import { ApiError } from "../../../src/data/api/client";
import { dispatchRecoveryOperation } from "../../../src/data/api/operations";
import type { RunRecoveryRecord } from "../../../src/domain/types/operations";
import {
  classifyRecoveryMutationFailure,
  clearRecoveryMutationAttempt,
  createRecoveryMutationAttempt,
  loadRecoveryMutationAttempt,
  recoveryAttemptMatchesProjection,
  recoveryMutationAttemptStorageKey,
  saveRecoveryMutationAttempt,
  withRecoveryAttemptFailure,
} from "../../../src/features/runs/recoveryMutationRetry";

const ACTOR_ID = "operator-recovery";
const RUN_ID = "run-recovery";
const HASH = "a".repeat(64);
const FINGERPRINT = "b".repeat(64);
const CREATED_AT = new Date("2026-07-24T12:00:00.000Z");

async function sha256Text(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();
  get length(): number { return this.values.size; }
  clear(): void { this.values.clear(); }
  getItem(key: string): string | null { return this.values.get(key) ?? null; }
  key(index: number): string | null { return [...this.values.keys()][index] ?? null; }
  removeItem(key: string): void { this.values.delete(key); }
  setItem(key: string, value: string): void { this.values.set(key, value); }
}

function recovery(overrides: {
  readonly runVersion?: number;
  readonly assignmentId?: string;
  readonly candidateStatus?: "present" | "absent";
} = {}): RunRecoveryRecord {
  const assignmentId = overrides.assignmentId ?? "assignment-recovery";
  return {
    schemaVersion: "2.4",
    recoveryRequired: true,
    run: {
      id: RUN_ID,
      missionId: "mission-recovery",
      missionName: "Recovery fixture",
      journey: "guided",
      status: "blocked",
      version: overrides.runVersion ?? 7,
      statusReason: "Stopped safely",
      currentStepId: "step-recovery",
      currentOwnerId: "agent-current",
      nextAction: "Review exact recovery action",
      leaseExpiresAt: null,
    },
    boundary: {
      planId: "plan-recovery",
      planVersion: 3,
      stepId: "step-recovery",
      assignmentId,
      agentId: "agent-current",
      actionKind: "manual",
    },
    reassignmentCandidates: overrides.candidateStatus === "absent" ? [] : [{
      agentId: "agent-next",
      displayName: "Next specialist",
      status: "available",
      capabilities: ["network.recon"],
    }],
    providerCandidates: [],
    detection: { summary: "Stopped safely", category: "timeout", evidence: [], failedActions: [] },
    checkpoint: {
      id: "checkpoint-recovery",
      eventSequence: 14,
      planVersion: 3,
      createdAt: CREATED_AT.toISOString(),
      stateHash: HASH,
      inFlightClassification: "safe_no_in_flight_action",
      completedActionCount: 0,
      inFlightActions: [],
    },
    attempts: {
      retryCount: 0,
      retryLimit: 2,
      retriesRemaining: 2,
      replanCount: 0,
      replanLimit: 2,
      replansRemaining: 2,
    },
    proposedRecovery: {
      kind: "guided_decision",
      summary: "Choose a bounded recovery",
      basis: "Exact stopped boundary",
      impact: { time: "bounded", cost: "none", scope: "unchanged" },
    },
    guidedDecision: {
      id: "decision-recovery",
      stepId: "step-recovery",
      actionFingerprint: FINGERPRINT,
      rationale: "Review exact action",
      riskClass: "low",
      expiresAt: "2026-07-24T13:00:00.000Z",
    },
    failedAttemptMemories: [],
    actions: [{
      kind: "reassign",
      label: "Reassign specialist",
      available: true,
      reason: "A compatible specialist is ready.",
      command: "reassign",
    }],
  };
}

function reassignBody() {
  return {
    expectedRunVersion: 7,
    expectedPlanId: "plan-recovery",
    expectedPlanVersion: 3,
    expectedStepId: "step-recovery",
    expectedAssignmentId: "assignment-recovery",
    expectedCheckpointId: "checkpoint-recovery",
    expectedCheckpointStateHash: HASH,
    expectedCheckpointEventSequence: 14,
    targetAgentId: "agent-next",
    capability: "network.recon",
    reason: "Move the exact stopped assignment to the attested specialist.",
    guidedDecisionId: "decision-recovery",
    expectedDecisionFingerprint: FINGERPRINT,
  };
}

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

describe("Recovery Panel exact mutation retry contract", () => {
  test("persists exact bytes, body hash, key, actor, and boundary; a remounted dispatch becomes uncertain", async () => {
    const storage = new MemoryStorage();
    const attempt = await createRecoveryMutationAttempt({
      actorId: ACTOR_ID,
      runId: RUN_ID,
      command: "reassign",
      body: reassignBody(),
      idempotencyKey: "recovery-reassign-stable-key",
      recovery: recovery(),
      now: CREATED_AT,
    });
    expect(attempt.bodySha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(attempt.serializedBody).toBe(JSON.stringify(reassignBody()));
    expect(attempt.representedBoundary).toMatchObject({
      runVersion: 7,
      planId: "plan-recovery",
      assignmentId: "assignment-recovery",
      checkpointId: "checkpoint-recovery",
      checkpointStateHash: HASH,
      checkpointEventSequence: 14,
    });
    expect(await saveRecoveryMutationAttempt(storage, attempt, CREATED_AT)).toBe(true);

    const restored = await loadRecoveryMutationAttempt(
      storage,
      ACTOR_ID,
      RUN_ID,
      new Date("2026-07-24T12:01:00.000Z"),
    );
    expect(restored).toEqual({ ...attempt, disposition: "uncertain" });
    expect(restored?.serializedBody).toBe(attempt.serializedBody);
    expect(restored?.idempotencyKey).toBe(attempt.idempotencyKey);
    expect(storage.getItem(recoveryMutationAttemptStorageKey(ACTOR_ID, RUN_ID))).toContain('"disposition":"uncertain"');

    clearRecoveryMutationAttempt(storage, ACTOR_ID, RUN_ID);
    expect(storage.length).toBe(0);
  });

  test("allows exact retry only while canonical boundary, decision, and capability still match", async () => {
    const attempt = withRecoveryAttemptFailure(
      await createRecoveryMutationAttempt({
        actorId: ACTOR_ID,
        runId: RUN_ID,
        command: "reassign",
        body: reassignBody(),
        idempotencyKey: "recovery-reassign-retry-key",
        recovery: recovery(),
        now: CREATED_AT,
      }),
      "retryable",
      new Error("retryable"),
    );
    expect(recoveryAttemptMatchesProjection(attempt, recovery())).toBe(true);
    expect(recoveryAttemptMatchesProjection(attempt, recovery({ runVersion: 8 }))).toBe(false);
    expect(recoveryAttemptMatchesProjection(attempt, recovery({ assignmentId: "assignment-new" }))).toBe(false);
    expect(recoveryAttemptMatchesProjection(attempt, recovery({ candidateStatus: "absent" }))).toBe(false);
  });

  test("classifies only canonical retryable errors as retry and treats response loss as reconciliation", () => {
    expect(classifyRecoveryMutationFailure(new ApiError(503, {
      code: "provider_unavailable",
      message: "Provider unavailable",
      humanMessage: "Provider is temporarily unavailable.",
      retryable: true,
      category: "dependency_unavailable",
      traceId: "trace-retryable",
      timestamp: CREATED_AT.toISOString(),
    }))).toBe("retryable");
    expect(classifyRecoveryMutationFailure(new ApiError(409, {
      code: "recovery_boundary_changed",
      message: "Boundary changed",
      humanMessage: "Review current state.",
      retryable: false,
      category: "conflict",
      traceId: "trace-stale",
      timestamp: CREATED_AT.toISOString(),
    }))).toBe("fresh_review");
    expect(classifyRecoveryMutationFailure(new TypeError("Failed to fetch"))).toBe("uncertain");
  });

  test("discards malformed, expired, hash-mutated, cross-actor, and correctly hashed secret-bearing stored intent", async () => {
    const storage = new MemoryStorage();
    await expect(createRecoveryMutationAttempt({
      actorId: ACTOR_ID,
      runId: RUN_ID,
      command: "reassign",
      body: { ...reassignBody(), reason: "authorization=synthetic-secret-value" },
      idempotencyKey: "recovery-reassign-secret-key",
      recovery: recovery(),
      now: CREATED_AT,
    })).rejects.toThrow("cannot be retained safely");

    const attempt = await createRecoveryMutationAttempt({
      actorId: ACTOR_ID,
      runId: RUN_ID,
      command: "reassign",
      body: reassignBody(),
      idempotencyKey: "recovery-reassign-expiry-key",
      recovery: recovery(),
      now: CREATED_AT,
    });
    await saveRecoveryMutationAttempt(storage, attempt, CREATED_AT);
    expect(await loadRecoveryMutationAttempt(
      storage,
      ACTOR_ID,
      RUN_ID,
      new Date("2026-07-24T12:11:00.000Z"),
    )).toBeNull();
    expect(storage.length).toBe(0);

    storage.setItem(recoveryMutationAttemptStorageKey(ACTOR_ID, RUN_ID), "{");
    expect(await loadRecoveryMutationAttempt(
      storage,
      ACTOR_ID,
      RUN_ID,
      new Date("2026-07-24T12:01:00.000Z"),
    )).toBeNull();
    expect(storage.length).toBe(0);

    storage.setItem(
      recoveryMutationAttemptStorageKey(ACTOR_ID, RUN_ID),
      JSON.stringify({ ...attempt, bodySha256: "f".repeat(64) }),
    );
    expect(await loadRecoveryMutationAttempt(storage, ACTOR_ID, RUN_ID, new Date("2026-07-24T12:01:00.000Z"))).toBeNull();

    const secretBody = JSON.stringify({
      ...reassignBody(),
      reason: "authorization=synthetic-secret-value",
    });
    storage.setItem(
      recoveryMutationAttemptStorageKey(ACTOR_ID, RUN_ID),
      JSON.stringify({
        ...attempt,
        serializedBody: secretBody,
        bodySha256: await sha256Text(secretBody),
      }),
    );
    expect(await loadRecoveryMutationAttempt(
      storage,
      ACTOR_ID,
      RUN_ID,
      new Date("2026-07-24T12:01:00.000Z"),
    )).toBeNull();
    expect(storage.length).toBe(0);

    storage.setItem(
      recoveryMutationAttemptStorageKey("another-operator", RUN_ID),
      JSON.stringify(attempt),
    );
    expect(await loadRecoveryMutationAttempt(
      storage,
      "another-operator",
      RUN_ID,
      new Date("2026-07-24T12:01:00.000Z"),
    )).toBeNull();
    expect(storage.getItem(recoveryMutationAttemptStorageKey("another-operator", RUN_ID))).toBeNull();
  });

  test("dispatches the exact retained JSON bytes and Idempotency-Key", async () => {
    const attempt = await createRecoveryMutationAttempt({
      actorId: ACTOR_ID,
      runId: RUN_ID,
      command: "reassign",
      body: reassignBody(),
      idempotencyKey: "recovery-reassign-dispatch-key",
      recovery: recovery(),
      now: CREATED_AT,
    });
    let postedBody = "";
    let postedKey = "";
    globalThis.fetch = (async (input, init) => {
      expect(String(input)).toBe(`/api/v2/operations/runs/${RUN_ID}/recovery/reassign`);
      postedBody = String(init?.body);
      postedKey = new Headers(init?.headers).get("Idempotency-Key") ?? "";
      return new Response(JSON.stringify({
        schemaVersion: "2.4",
        mutation: {
          kind: "reassign",
          eventId: "event-reassign",
          checkpointId: "checkpoint-reassign",
          continuationId: null,
          agentId: "agent-next",
          assignmentId: "assignment-next",
          providerId: null,
          modelId: null,
          modelConfigurationHash: null,
          providerRouteVersion: null,
        },
        run: {
          id: RUN_ID,
          journey: "guided",
          status: "blocked",
          version: 8,
          planId: "plan-recovery",
          planVersion: 3,
          stepId: "step-recovery",
          assignmentId: "assignment-next",
        },
      }), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;

    await dispatchRecoveryOperation({
      runId: attempt.runId,
      command: attempt.command,
      serializedBody: attempt.serializedBody,
      idempotencyKey: attempt.idempotencyKey,
    });
    expect(postedBody).toBe(attempt.serializedBody);
    expect(postedKey).toBe(attempt.idempotencyKey);
  });

  test("fails closed when the exact attempt cannot be persisted before dispatch", async () => {
    const attempt = await createRecoveryMutationAttempt({
      actorId: ACTOR_ID,
      runId: RUN_ID,
      command: "reassign",
      body: reassignBody(),
      idempotencyKey: "recovery-reassign-storage-failure",
      recovery: recovery(),
      now: CREATED_AT,
    });
    const unavailable = {
      getItem: () => null,
      removeItem: () => undefined,
      setItem: () => { throw new Error("Storage unavailable"); },
    };
    expect(await saveRecoveryMutationAttempt(unavailable, attempt, CREATED_AT)).toBe(false);
  });
});

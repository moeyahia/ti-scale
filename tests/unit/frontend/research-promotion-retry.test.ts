import { afterEach, describe, expect, test } from "bun:test";
import { ApiError } from "../../../src/data/api/client";
import {
  researchApi,
  serializeResearchPromotionRequest,
} from "../../../src/data/api/research";
import type {
  HumanResearchPromotionAction,
  ResearchPromotionLifecycleRecord,
} from "../../../src/domain/types/research";
import {
  classifyResearchPromotionOutcomeAttribution,
  classifyResearchPromotionFailure,
  clearResearchPromotionAttempt,
  createResearchPromotionAttempt,
  loadResearchPromotionAttempt,
  researchPromotionAttemptMatchesProjection,
  researchPromotionAttemptStorageKey,
  researchPromotionOutcomeReached,
  saveResearchPromotionAttempt,
  withResearchPromotionFailure,
} from "../../../src/features/learning/researchPromotionRetry";

const ACTOR_ID = "operator-research";
const EXPERIMENT_ID = "experiment-research";
const NOW = new Date("2026-07-24T12:00:00.000Z");

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();
  get length(): number { return this.values.size; }
  clear(): void { this.values.clear(); }
  getItem(key: string): string | null { return this.values.get(key) ?? null; }
  key(index: number): string | null {
    return [...this.values.keys()][index] ?? null;
  }
  removeItem(key: string): void { this.values.delete(key); }
  setItem(key: string, value: string): void { this.values.set(key, value); }
}

function serialized(
  action: HumanResearchPromotionAction = "approve_human_review",
): string {
  return serializeResearchPromotionRequest({
    expectedVersion: 6,
    action,
    rationale: "The signed holdout passed every immutable local gate.",
    evidenceRefs: ["integrity-holdout"],
    ...(action === "rollback"
      ? { targetStrategyVersionId: "strategy-previous" }
      : {}),
    ...(action === "start_canary"
      ? { canaryBounds: { maxMissions: 2, maxWallClockMs: 3_600_000 } }
      : {}),
  });
}

function promotion(
  overrides: {
    readonly version?: number;
    readonly state?: ResearchPromotionLifecycleRecord["state"];
    readonly action?: HumanResearchPromotionAction;
    readonly actorId?: string;
    readonly decisionFingerprint?: string;
  } = {},
): ResearchPromotionLifecycleRecord {
  const action = overrides.action ?? "approve_human_review";
  return {
    experimentId: EXPERIMENT_ID,
    campaignId: "campaign-research",
    strategyVersionId: "strategy-research",
    state: overrides.state ?? "benchmarked",
    stage: overrides.version && overrides.version > 6 ? "shadow" : "human_review",
    milestones: {
      developmentPassed: true,
      validationPassed: true,
      hiddenHoldoutPassed: true,
      humanReviewApproved: Boolean(overrides.version && overrides.version > 6),
      shadowPassed: false,
      canaryPassed: false,
    },
    version: overrides.version ?? 6,
    updatedAt: NOW.toISOString(),
    latestIntegrityReceiptId: "integrity-holdout",
    availableHumanActions: overrides.version && overrides.version > 6
      ? ["start_shadow", "reject"]
      : [action, "reject_human_review"],
    rollbackTargets: [],
    transitions: overrides.version && overrides.version > 6
      ? [{
          id: "transition-applied",
          sequence: 6,
          version: 7,
          fromState: "benchmarked",
          toState: "shadow_ready",
          action,
          actorKind: "human_reviewer",
          actorId: overrides.actorId ?? ACTOR_ID,
          rationale: "Approved after review.",
          evidenceRefs: ["integrity-holdout"],
          hardGateFailures: [],
          ...(overrides.decisionFingerprint
            ? { decisionFingerprint: overrides.decisionFingerprint }
            : {}),
          exposureReceiptIds: [],
          createdAt: NOW.toISOString(),
        }]
      : [],
  };
}

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("Research promotion durable retry boundary", () => {
  test("persists exact bytes, hash, key, actor, experiment, and lifecycle version", async () => {
    const storage = new MemoryStorage();
    const attempt = await createResearchPromotionAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      serializedBody: serialized(),
      idempotencyKey: "research-promotion-stable-key",
      now: NOW,
    });
    expect(attempt.bodySha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(attempt.decisionFingerprint).toMatch(/^[a-f0-9]{64}$/u);
    expect(attempt.decisionFingerprint).not.toBe(attempt.bodySha256);
    expect(attempt.expectedVersion).toBe(6);
    expect(attempt.action).toBe("approve_human_review");
    expect(await saveResearchPromotionAttempt(storage, attempt, NOW)).toBe(true);

    const restored = await loadResearchPromotionAttempt(
      storage,
      ACTOR_ID,
      EXPERIMENT_ID,
      new Date("2026-07-24T12:01:00.000Z"),
    );
    expect(restored).toEqual({ ...attempt, disposition: "uncertain" });
    expect(restored?.serializedBody).toBe(attempt.serializedBody);
    expect(restored?.idempotencyKey).toBe(attempt.idempotencyKey);

    clearResearchPromotionAttempt(storage, ACTOR_ID, EXPERIMENT_ID);
    expect(storage.length).toBe(0);
  });

  test("retries only an unchanged represented lifecycle and recognizes an applied outcome", async () => {
    const attempt = await createResearchPromotionAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      serializedBody: serialized(),
      idempotencyKey: "research-promotion-projection-key",
      now: NOW,
    });
    expect(researchPromotionAttemptMatchesProjection(attempt, promotion()))
      .toBe(true);
    expect(researchPromotionAttemptMatchesProjection(
      attempt,
      promotion({
        version: 7,
        state: "shadow_ready",
        decisionFingerprint: attempt.decisionFingerprint,
      }),
    )).toBe(false);
    expect(researchPromotionOutcomeReached(
      attempt,
      promotion({
        version: 7,
        state: "shadow_ready",
        decisionFingerprint: attempt.decisionFingerprint,
      }),
    )).toBe(true);
    expect(researchPromotionOutcomeReached(
      { ...attempt, action: "reject_human_review" },
      promotion({ version: 7, state: "shadow_ready" }),
    )).toBe(false);
    const otherActorProjection = {
      ...promotion({
        version: 7,
        state: "shadow_ready",
        actorId: "different-authorized-reviewer",
        decisionFingerprint: attempt.decisionFingerprint,
      }),
    };
    expect(classifyResearchPromotionOutcomeAttribution(
      attempt,
      otherActorProjection,
    )).toBe("other_actor");
    expect(researchPromotionOutcomeReached(
      attempt,
      otherActorProjection,
    )).toBe(false);

    const differentRationale = await createResearchPromotionAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      serializedBody: serializeResearchPromotionRequest({
        expectedVersion: 6,
        action: "approve_human_review",
        rationale: "A different review conclusion for the same represented action.",
        evidenceRefs: ["integrity-holdout"],
      }),
      idempotencyKey: "research-promotion-different-rationale",
      now: NOW,
    });
    const differentEvidence = await createResearchPromotionAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      serializedBody: serializeResearchPromotionRequest({
        expectedVersion: 6,
        action: "approve_human_review",
        rationale: "The signed holdout passed every immutable local gate.",
        evidenceRefs: ["integrity-holdout", "review-note-different"],
      }),
      idempotencyKey: "research-promotion-different-evidence",
      now: NOW,
    });
    for (const decisionFingerprint of [
      differentRationale.decisionFingerprint,
      differentEvidence.decisionFingerprint,
    ]) {
      const differentDecisionProjection = promotion({
        version: 7,
        state: "shadow_ready",
        decisionFingerprint,
      });
      expect(classifyResearchPromotionOutcomeAttribution(
        attempt,
        differentDecisionProjection,
      )).toBe("other_decision");
      expect(researchPromotionOutcomeReached(
        attempt,
        differentDecisionProjection,
      )).toBe(false);
    }
    expect(classifyResearchPromotionOutcomeAttribution(
      attempt,
      promotion({ version: 7, state: "shadow_ready" }),
    )).toBe("other_decision");
  });

  test("retains readable multiline rationale but rejects control-bearing evidence", async () => {
    const multiline = serializeResearchPromotionRequest({
      expectedVersion: 6,
      action: "approve_human_review",
      rationale: "Holdout passed every hard gate.\nEvidence quality remained stable.",
      evidenceRefs: ["integrity-holdout"],
    });
    await expect(createResearchPromotionAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      serializedBody: multiline,
      idempotencyKey: "research-promotion-multiline-key",
      now: NOW,
    })).resolves.toMatchObject({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
    });

    const controlBearing = serializeResearchPromotionRequest({
      expectedVersion: 6,
      action: "approve_human_review",
      rationale: "Holdout passed every hard gate.",
      evidenceRefs: ["integrity-holdout\u0000hidden"],
    });
    await expect(createResearchPromotionAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      serializedBody: controlBearing,
      idempotencyKey: "research-promotion-control-key",
      now: NOW,
    })).rejects.toThrow("cannot be retained safely");
  });

  test("rejects expired, mutated, cross-actor, and secret-bearing intent", async () => {
    const storage = new MemoryStorage();
    await expect(createResearchPromotionAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      serializedBody: serializeResearchPromotionRequest({
        expectedVersion: 6,
        action: "approve_human_review",
        rationale: "authorization=synthetic-secret-value",
        evidenceRefs: ["integrity-holdout"],
      }),
      idempotencyKey: "research-promotion-secret-key",
      now: NOW,
    })).rejects.toThrow("cannot be retained safely");

    const attempt = await createResearchPromotionAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      serializedBody: serialized(),
      idempotencyKey: "research-promotion-expiry-key",
      now: NOW,
    });
    await saveResearchPromotionAttempt(storage, attempt, NOW);
    expect(await loadResearchPromotionAttempt(
      storage,
      ACTOR_ID,
      EXPERIMENT_ID,
      new Date("2026-07-24T12:11:00.000Z"),
    )).toBeNull();
    expect(storage.length).toBe(0);

    storage.setItem(
      researchPromotionAttemptStorageKey(ACTOR_ID, EXPERIMENT_ID),
      JSON.stringify({ ...attempt, bodySha256: "f".repeat(64) }),
    );
    expect(await loadResearchPromotionAttempt(
      storage,
      ACTOR_ID,
      EXPERIMENT_ID,
      new Date("2026-07-24T12:01:00.000Z"),
    )).toBeNull();

    storage.setItem(
      researchPromotionAttemptStorageKey(ACTOR_ID, EXPERIMENT_ID),
      JSON.stringify({ ...attempt, decisionFingerprint: "f".repeat(64) }),
    );
    expect(await loadResearchPromotionAttempt(
      storage,
      ACTOR_ID,
      EXPERIMENT_ID,
      new Date("2026-07-24T12:01:00.000Z"),
    )).toBeNull();

    storage.setItem(
      researchPromotionAttemptStorageKey("other-operator", EXPERIMENT_ID),
      JSON.stringify(attempt),
    );
    expect(await loadResearchPromotionAttempt(
      storage,
      "other-operator",
      EXPERIMENT_ID,
      new Date("2026-07-24T12:01:00.000Z"),
    )).toBeNull();
  });

  test("classifies retryable, uncertain, and fresh-review failures", async () => {
    const retryable = new ApiError(503, {
      code: "research_store_busy",
      message: "Store busy",
      humanMessage: "The store is busy.",
      retryable: true,
      category: "persistence",
      traceId: "trace-retry",
      timestamp: NOW.toISOString(),
    });
    expect(classifyResearchPromotionFailure(retryable)).toBe("retryable");
    expect(classifyResearchPromotionFailure(new TypeError("Failed to fetch")))
      .toBe("uncertain");
    expect(classifyResearchPromotionFailure(new ApiError(409, {
      code: "research_lifecycle_version_conflict",
      message: "Version changed",
      humanMessage: "Review current state.",
      retryable: false,
      category: "conflict",
      traceId: "trace-conflict",
      timestamp: NOW.toISOString(),
    }))).toBe("fresh_review");

    const attempt = await createResearchPromotionAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      serializedBody: serialized(),
      idempotencyKey: "research-promotion-failure-key",
      now: NOW,
    });
    expect(withResearchPromotionFailure(attempt, "retryable", retryable))
      .toMatchObject({
        disposition: "retryable",
        failureCode: "research_store_busy",
      });
  });

  test("dispatches the retained body and original idempotency key byte-for-byte", async () => {
    const body = serialized("start_canary");
    let postedBody = "";
    let postedKey = "";
    globalThis.fetch = (async (input, init) => {
      expect(String(input)).toBe(
        `/api/v2/research/experiments/${EXPERIMENT_ID}/promotion`,
      );
      postedBody = String(init?.body);
      postedKey = new Headers(init?.headers).get("Idempotency-Key") ?? "";
      return new Response(JSON.stringify({
        schemaVersion: "2.4",
        lifecycle: promotion(),
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    await expect(researchApi.transitionPromotionSerialized(
      EXPERIMENT_ID,
      body,
      "research-promotion-dispatch-key",
    )).rejects.toMatchObject({ code: "invalid_response_schema" });
    expect(postedBody).toBe(body);
    expect(postedKey).toBe("research-promotion-dispatch-key");
  });
});

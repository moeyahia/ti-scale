import { describe, expect, test } from "bun:test";
import { ApiError } from "../../../src/data/api/client";
import {
  classifyResearchExperimentFailure,
  clearResearchExperimentAttempt,
  createResearchExperimentCancelAttempt,
  createResearchExperimentStartAttempt,
  loadResearchExperimentAttempt,
  researchExperimentAttemptMatchesProjection,
  researchExperimentAttemptOutcomeReached,
  researchExperimentAttemptStorageKey,
  saveResearchExperimentAttempt,
  serializeResearchExperimentCancelRequest,
  serializeResearchExperimentStartRequest,
  withResearchExperimentFailure,
  type ResearchExperimentProjection,
} from "../../../src/features/learning/researchExperimentRetry";

const ACTOR_ID = "operator-research";
const EXPERIMENT_ID = "experiment-research";
const SCENARIO_ID = "scenario-development";
const RUN_ID = "run-development";
const NOW = new Date("2026-07-27T12:00:00.000Z");

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();
  get length(): number { return this.values.size; }
  clear(): void { this.values.clear(); }
  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }
  key(index: number): string | null {
    return [...this.values.keys()][index] ?? null;
  }
  removeItem(key: string): void { this.values.delete(key); }
  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
}

function projection(
  overrides: Partial<ResearchExperimentProjection> = {},
): ResearchExperimentProjection {
  return {
    experimentId: EXPERIMENT_ID,
    scenarioId: SCENARIO_ID,
    experimentStatus: "queued",
    latestRunId: null,
    latestRunStatus: null,
    ...overrides,
  };
}

describe("Research experiment exact retry boundary", () => {
  test("retains exact start bytes, hash, key, actor, and experiment per tab", async () => {
    const storage = new MemoryStorage();
    const attempt = await createResearchExperimentStartAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      scenarioId: SCENARIO_ID,
      seed: " development-fixed ",
      idempotencyKey: "research-run-stable-key",
      now: NOW,
    });
    expect(attempt.serializedBody).toBe(
      serializeResearchExperimentStartRequest({
        scenarioId: SCENARIO_ID,
        seed: "development-fixed",
      }),
    );
    expect(attempt.bodySha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(attempt.idempotencyKey).toBe("research-run-stable-key");
    expect(attempt.expectedLatestRunId).toBeNull();
    expect(await saveResearchExperimentAttempt(storage, attempt, NOW))
      .toBe(true);

    const restored = await loadResearchExperimentAttempt(
      storage,
      ACTOR_ID,
      EXPERIMENT_ID,
      new Date("2026-07-27T12:01:00.000Z"),
    );
    expect(restored).toEqual({ ...attempt, disposition: "uncertain" });
    expect(restored?.serializedBody).toBe(attempt.serializedBody);
    expect(restored?.idempotencyKey).toBe(attempt.idempotencyKey);
    expect(researchExperimentAttemptStorageKey(
      ACTOR_ID,
      EXPERIMENT_ID,
    )).toContain("ti-scale.research.experiment-intent.v1");

    clearResearchExperimentAttempt(storage, ACTOR_ID, EXPERIMENT_ID);
    expect(storage.length).toBe(0);
  });

  test("retains an exact normalized cancellation and binds it to one run", async () => {
    const attempt = await createResearchExperimentCancelAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      runId: RUN_ID,
      reason: " Fixture changed during review. ",
      idempotencyKey: "research-cancel-stable-key",
      now: NOW,
    });
    expect(attempt.reason).toBe("Fixture changed during review.");
    expect(attempt.serializedBody).toBe(
      serializeResearchExperimentCancelRequest({
        reason: "Fixture changed during review.",
      }),
    );
    expect(attempt.runId).toBe(RUN_ID);
    expect(attempt.expectedLatestRunId).toBe(RUN_ID);
  });

  test("fails closed when seed, scenario, run, or status changes", async () => {
    const start = await createResearchExperimentStartAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      scenarioId: SCENARIO_ID,
      seed: "development-fixed",
      idempotencyKey: "research-run-projection-key",
      now: NOW,
    });
    expect(researchExperimentAttemptMatchesProjection(start, projection()))
      .toBe(true);
    expect(researchExperimentAttemptMatchesProjection(
      start,
      projection({ scenarioId: "scenario-changed" }),
    )).toBe(false);
    expect(researchExperimentAttemptMatchesProjection(
      start,
      projection({ experimentStatus: "running" }),
    )).toBe(false);
    expect(researchExperimentAttemptOutcomeReached(
      start,
      projection({
        latestRunId: RUN_ID,
        latestRunStatus: "queued",
      }),
    )).toBe(true);

    const cancel = await createResearchExperimentCancelAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      runId: RUN_ID,
      reason: "Fixture changed during review.",
      idempotencyKey: "research-cancel-projection-key",
      now: NOW,
    });
    expect(researchExperimentAttemptMatchesProjection(
      cancel,
      projection({
        latestRunId: RUN_ID,
        latestRunStatus: "running",
      }),
    )).toBe(true);
    expect(researchExperimentAttemptMatchesProjection(
      cancel,
      projection({
        latestRunId: "run-other",
        latestRunStatus: "running",
      }),
    )).toBe(false);
    expect(researchExperimentAttemptOutcomeReached(
      cancel,
      projection({
        latestRunId: RUN_ID,
        latestRunStatus: "cancelled",
      }),
    )).toBe(true);
    expect(researchExperimentAttemptOutcomeReached(
      cancel,
      projection({
        latestRunId: RUN_ID,
        latestRunStatus: "completed",
      }),
    )).toBe(true);
  });

  test("classifies retryable, response-loss, and reconciliation failures", async () => {
    const retryable = new ApiError(503, {
      code: "research_store_busy",
      message: "Store busy",
      humanMessage: "The store is busy.",
      retryable: true,
      category: "persistence",
      traceId: "trace-retry",
      timestamp: NOW.toISOString(),
    });
    expect(classifyResearchExperimentFailure(retryable))
      .toBe("retryable");
    expect(classifyResearchExperimentFailure(
      new TypeError("Failed to fetch"),
    )).toBe("uncertain");
    expect(classifyResearchExperimentFailure(new ApiError(409, {
      code: "research_run_conflict",
      message: "Run changed",
      humanMessage: "Refresh current state.",
      retryable: false,
      category: "conflict",
      traceId: "trace-conflict",
      timestamp: NOW.toISOString(),
    }))).toBe("reconcile");

    const attempt = await createResearchExperimentStartAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      scenarioId: SCENARIO_ID,
      seed: "development-fixed",
      idempotencyKey: "research-run-failure-key",
      now: NOW,
    });
    expect(withResearchExperimentFailure(
      attempt,
      "retryable",
      retryable,
    )).toMatchObject({
      disposition: "retryable",
      failureCode: "research_store_busy",
      idempotencyKey: attempt.idempotencyKey,
      serializedBody: attempt.serializedBody,
    });
  });

  test("rejects tampering, expiry, cross-actor restore, and secret-bearing reasons", async () => {
    const storage = new MemoryStorage();
    const attempt = await createResearchExperimentStartAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      scenarioId: SCENARIO_ID,
      seed: "development-fixed",
      idempotencyKey: "research-run-expiry-key",
      now: NOW,
    });
    await saveResearchExperimentAttempt(storage, attempt, NOW);
    expect(await loadResearchExperimentAttempt(
      storage,
      ACTOR_ID,
      EXPERIMENT_ID,
      new Date("2026-07-27T12:11:00.000Z"),
    )).toBeNull();
    expect(storage.length).toBe(0);

    storage.setItem(
      researchExperimentAttemptStorageKey(ACTOR_ID, EXPERIMENT_ID),
      JSON.stringify({ ...attempt, bodySha256: "f".repeat(64) }),
    );
    expect(await loadResearchExperimentAttempt(
      storage,
      ACTOR_ID,
      EXPERIMENT_ID,
      new Date("2026-07-27T12:01:00.000Z"),
    )).toBeNull();

    storage.setItem(
      researchExperimentAttemptStorageKey("other-operator", EXPERIMENT_ID),
      JSON.stringify(attempt),
    );
    expect(await loadResearchExperimentAttempt(
      storage,
      "other-operator",
      EXPERIMENT_ID,
      new Date("2026-07-27T12:01:00.000Z"),
    )).toBeNull();

    await expect(createResearchExperimentCancelAttempt({
      actorId: ACTOR_ID,
      experimentId: EXPERIMENT_ID,
      runId: RUN_ID,
      reason: "authorization=synthetic-secret-value",
      idempotencyKey: "research-cancel-secret-key",
      now: NOW,
    })).rejects.toThrow("cannot be retained safely");
  });
});

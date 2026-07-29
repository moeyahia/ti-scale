import { describe, expect, test } from "bun:test";
import { exactResumeBoundary } from "../../../src/data/api/runtimeV2";
import { parseRunSnapshot } from "../../../src/domain/schemas/runtimeV2";

function payload(overrides: {
  runVersion?: number;
  checkpointVersion?: number;
  checkpointState?: string;
  inFlight?: unknown[];
  hash?: string;
} = {}): unknown {
  const runVersion = overrides.runVersion ?? 4;
  return {
    schemaVersion: "2.4",
    run: {
      id: "run-resume",
      missionId: "mission-resume",
      missionName: "Resume boundary",
      objective: "Resume one exact checkpoint",
      journey: "guided",
      status: "blocked",
      statusReason: "Paused by operator: inspect exact state",
      progress: 0.4,
      nextAction: "Wait for exact resume",
      currentPlanId: "plan-resume",
      currentStepId: "step-resume",
      currentOwnerId: "agent-resume",
      lastHeartbeatAt: null,
      leaseExpiresAt: null,
      startedAt: "2026-07-16T12:00:00.000Z",
      endedAt: null,
      createdAt: "2026-07-16T12:00:00.000Z",
      updatedAt: "2026-07-16T12:02:00.000Z",
      version: runVersion,
    },
    latestCheckpoint: {
      id: "checkpoint-resume",
      journey: "guided",
      eventSequence: 7,
      stateHash: overrides.hash ?? "a".repeat(64),
      createdAt: "2026-07-16T12:02:00.000Z",
      state: {
        run: {
          id: "run-resume",
          state: overrides.checkpointState ?? "blocked",
          stateVersion: overrides.checkpointVersion ?? runVersion,
          leaseOwner: null,
          leaseExpiresAt: null,
        },
        inFlightActions: overrides.inFlight ?? [],
        lastEventSequence: 7,
      },
    },
  };
}

describe("V2 exact resume boundary", () => {
  test("derives the complete server-bound resume identity from a validated snapshot", () => {
    const snapshot = parseRunSnapshot(payload());
    expect(exactResumeBoundary(snapshot)).toEqual({
      expectedRunVersion: 4,
      expectedRunStatus: "blocked",
      expectedCheckpointId: "checkpoint-resume",
      expectedCheckpointStateHash: "a".repeat(64),
      expectedCheckpointEventSequence: 7,
    });
  });

  test("withholds resume for stale state versions or checkpoint-recorded in-flight work", () => {
    expect(exactResumeBoundary(parseRunSnapshot(payload({ checkpointVersion: 3 })))).toBeNull();
    expect(exactResumeBoundary(parseRunSnapshot(payload({
      inFlight: [{ id: "action-active", status: "running", idempotent: true, destructive: false }],
    })))).toBeNull();
  });

  test("rejects malformed checkpoint hashes before a control can be enabled", () => {
    expect(() => parseRunSnapshot(payload({ hash: "not-a-sha256" }))).toThrow(
      "latestCheckpoint.stateHash must be a SHA-256 digest",
    );
  });
});

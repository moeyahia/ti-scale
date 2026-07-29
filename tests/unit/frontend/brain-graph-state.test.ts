import { describe, expect, test } from "bun:test";
import {
  brainGraphStateToQuery,
  brainGraphStateToUrl,
  parseBrainGraphState,
} from "../../../src/features/brain/brainGraphState";

describe("memory graph default knowledge boundary", () => {
  test("defaults the unfiltered global canvas to the server-reviewed reusable boundary", () => {
    const state = parseBrainGraphState({});
    expect(state.includeSourceProvenance).toBe(false);
    expect(brainGraphStateToQuery(state)).toMatchObject({
      view: "global",
      scope: "global",
    });
    expect(brainGraphStateToQuery(state).status).toBeUndefined();
  });

  test("never serializes a verified-only lifecycle for the default reusable canvas", () => {
    const state = parseBrainGraphState({});
    expect(brainGraphStateToUrl(state).lifecycle).toBeUndefined();
    expect(brainGraphStateToQuery(state)).toEqual(expect.objectContaining({
      view: "global",
      scope: "global",
    }));
    expect(brainGraphStateToQuery(state)).not.toHaveProperty("status");

    expect(brainGraphStateToQuery(parseBrainGraphState({ lifecycle: "verified" })).status).toBe("verified");
    expect(brainGraphStateToQuery(parseBrainGraphState({ lifecycle: "confirmed" })).status).toBe("confirmed");
  });

  test("requires an explicit URL state before loading all permitted source provenance", () => {
    const state = parseBrainGraphState({ provenance: "1" });
    const query = brainGraphStateToQuery(state);
    expect(state.includeSourceProvenance).toBe(true);
    expect(query.scope).toBeUndefined();
    expect(query.status).toBeUndefined();
    expect(brainGraphStateToUrl(state).provenance).toBe("1");
  });

  test("does not override an engagement-isolated graph with global defaults", () => {
    const state = parseBrainGraphState({ engagement: "engagement-fixture" });
    const query = brainGraphStateToQuery(state);
    expect(query.engagementId).toBe("engagement-fixture");
    expect(query.scope).toBeUndefined();
    expect(query.status).toBeUndefined();
  });

  test("keeps verified and historical outcome filters separate and server-backed", () => {
    for (const outcome of ["success", "failed", "unclassified"] as const) {
      const state = parseBrainGraphState({ outcome });
      expect(state.outcomeFilter).toBe(outcome);
      expect(brainGraphStateToUrl(state).outcome).toBe(outcome);
      expect(brainGraphStateToQuery(state).outcome).toBe(outcome);
    }
    expect(parseBrainGraphState({ outcome: "partial" }).outcomeFilter).toBe("");

    for (const reported of [
      "reported_success", "reported_failure", "mixed", "unknown", "not_reported",
    ] as const) {
      const state = parseBrainGraphState({ reported });
      expect(state.reportedOutcomeFilter).toBe(reported);
      expect(brainGraphStateToUrl(state).reported).toBe(reported);
      expect(brainGraphStateToQuery(state).reportedOutcome).toBe(reported);
    }
    expect(parseBrainGraphState({ reported: "verified_success" }).reportedOutcomeFilter).toBe("");
  });
});

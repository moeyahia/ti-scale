import { afterEach, describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { operationsApi } from "../../../src/data/api/operations";
import { parseRecoveryMutation } from "../../../src/domain/schemas/operations";
import type { RunRecoveryRecord } from "../../../src/domain/types/operations";
import {
  RecoveryProviderChoices,
  providerChoiceValue,
} from "../../../src/features/runs/RecoveryPanel";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

const MODEL_ID = "openai/gpt-recovery-20260722";
const MODEL_CONFIGURATION_HASH = "d".repeat(64);

function candidate(
  providerId: string,
  eligibility: RunRecoveryRecord["providerCandidates"][number]["eligibility"],
  reason: string,
): RunRecoveryRecord["providerCandidates"][number] {
  const enabled = eligibility === "compatible";
  return {
    providerId,
    modelId: providerId === "model-absent" ? null : MODEL_ID,
    modelConfigurationHash: providerId === "model-absent" ? null : MODEL_CONFIGURATION_HASH,
    status: eligibility === "unavailable" ? "unhealthy" : "healthy",
    eligibility,
    enabled,
    reason,
    supportsGuided: eligibility !== "enforcement_incompatible",
    enforcesAutonomousBoundary: false,
    reportsExactTokenUsage: eligibility !== "budget_incompatible",
    reportsExactCostUsage: true,
  };
}

const candidates: RunRecoveryRecord["providerCandidates"] = [
  candidate("compatible", "compatible", "Ready with a fresh exact model attestation."),
  candidate("unavailable", "unavailable", "Unavailable because the provider route is unhealthy."),
  candidate("stale", "stale", "Stale readiness must be refreshed."),
  candidate("budget", "budget_incompatible", "Budget incompatible because exact token usage is absent."),
  candidate("enforcement", "enforcement_incompatible", "Enforcement incompatible with this journey."),
  candidate("model-absent", "unavailable", "Unavailable because no exact model is attested."),
];

describe("model-aware recovery provider UI and client", () => {
  test("renders every provider/model state and disables every ineligible option instead of hiding it", () => {
    const markup = renderToStaticMarkup(
      <RecoveryProviderChoices candidates={candidates} value="" disabled={false} onChange={() => undefined} />,
    );
    expect(markup).toContain("Provider and exact model");
    expect(markup).toContain("Provider and model compatibility");
    expect(markup).toContain("compatible · openai/gpt-recovery-20260722 · compatible");
    expect(markup).toContain("unavailable · openai/gpt-recovery-20260722 · unavailable");
    expect(markup).toContain("stale · openai/gpt-recovery-20260722 · stale");
    expect(markup).toContain("budget · openai/gpt-recovery-20260722 · budget incompatible");
    expect(markup).toContain("enforcement · openai/gpt-recovery-20260722 · enforcement incompatible");
    expect(markup).toContain("model-absent · No attested model · unavailable");
    expect(markup).toContain(`Configuration ${MODEL_CONFIGURATION_HASH.slice(0, 12)}…`);
    for (const item of candidates) expect(markup).toContain(item.reason);
    expect((markup.match(/<option[^>]*disabled=""/gu) ?? [])).toHaveLength(5);
    expect(providerChoiceValue(candidates[0]!)).toContain(encodeURIComponent(MODEL_CONFIGURATION_HASH));
  });

  test("sends the exact server-returned model pin and validates it in the response", async () => {
    let posted: Record<string, unknown> | null = null;
    globalThis.fetch = (async (input, init) => {
      expect(String(input)).toBe("/api/v2/operations/runs/run-provider/recovery/provider");
      posted = JSON.parse(String(init?.body));
      return new Response(JSON.stringify({
        schemaVersion: "2.4",
        mutation: {
          kind: "change_provider",
          eventId: "event-provider",
          checkpointId: "checkpoint-provider-next",
          continuationId: null,
          agentId: null,
          assignmentId: null,
          providerId: "compatible",
          modelId: MODEL_ID,
          modelConfigurationHash: MODEL_CONFIGURATION_HASH,
          providerRouteVersion: 4,
        },
        run: {
          id: "run-provider", journey: "guided", status: "blocked", version: 8,
          planId: "plan-provider", planVersion: 3, stepId: "step-provider", assignmentId: "assignment-provider",
        },
      }), { status: 200, headers: { "content-type": "application/json", "x-request-id": "request-provider" } });
    }) as typeof fetch;

    const result = await operationsApi.changeRecoveryProvider("run-provider", {
      expectedRunVersion: 7,
      expectedPlanId: "plan-provider",
      expectedPlanVersion: 3,
      expectedStepId: "step-provider",
      expectedAssignmentId: "assignment-provider",
      expectedCheckpointId: "checkpoint-provider",
      expectedCheckpointStateHash: "a".repeat(64),
      expectedCheckpointEventSequence: 12,
      providerId: "compatible",
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      reason: "Use the exact fresh compatible provider and model.",
    }, "recovery-provider-model-test");

    expect(posted).toMatchObject({
      providerId: "compatible",
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
    });
    expect(result.mutation).toMatchObject({
      providerId: "compatible",
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
    });
  });

  test("rejects a provider mutation response whose exact model pin is absent or malformed", () => {
    const base = {
      schemaVersion: "2.4",
      mutation: {
        kind: "change_provider", eventId: "event-provider", checkpointId: "checkpoint-provider",
        continuationId: null, agentId: null, assignmentId: null, providerId: "compatible",
        modelId: MODEL_ID, modelConfigurationHash: MODEL_CONFIGURATION_HASH, providerRouteVersion: 1,
      },
      run: {
        id: "run-provider", journey: "guided", status: "blocked", version: 2,
        planId: "plan-provider", planVersion: 1, stepId: "step-provider", assignmentId: "assignment-provider",
      },
    };
    expect(parseRecoveryMutation(base).mutation.modelId).toBe(MODEL_ID);
    expect(() => parseRecoveryMutation({
      ...base,
      mutation: { ...base.mutation, modelId: null, modelConfigurationHash: null },
    })).toThrow("provider recovery mutation model pin is incomplete");
    expect(() => parseRecoveryMutation({
      ...base,
      mutation: { ...base.mutation, modelConfigurationHash: "not-a-digest" },
    })).toThrow("modelConfigurationHash is invalid");
  });
});

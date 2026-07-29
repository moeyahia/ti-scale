import { describe, expect, test } from "bun:test";
import {
  parseRecoveryProviderRouteBinding,
  parseRecoveryProviderRouteTombstone,
  recoveryProviderModelPin,
} from "../recoveryProviderRoute";

const MODEL_ID = "openai/gpt-recovery-20260722";
const MODEL_CONFIGURATION_HASH = "a".repeat(64);

function guidedBinding(schemaVersion: 1 | 2) {
  return {
    schemaVersion,
    version: 3,
    runId: "run-provider-route",
    journey: "guided",
    providerId: "openrouter",
    ...(schemaVersion === 2 ? {
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
    } : {}),
    planId: "plan-provider-route",
    planVersion: 2,
    stepId: "step-provider-route",
    assignmentId: "assignment-provider-route",
    guidedDecision: { id: "decision-provider-route", fingerprint: "b".repeat(64) },
    selectedBy: "operator-one",
    selectedAt: "2026-07-22T12:00:00.000Z",
  };
}

describe("model-aware recovery provider route", () => {
  test("derives a pin only from one exact requested-and-returned model attestation", () => {
    expect(recoveryProviderModelPin({
      requestedModel: MODEL_ID,
      returnedModel: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
    })).toEqual({ modelId: MODEL_ID, modelConfigurationHash: MODEL_CONFIGURATION_HASH });
    expect(recoveryProviderModelPin({
      requestedModel: MODEL_ID,
      returnedModel: "openai/different-model",
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
    })).toBeNull();
    expect(recoveryProviderModelPin({ requestedModel: MODEL_ID, returnedModel: MODEL_ID })).toBeNull();
    expect(recoveryProviderModelPin({
      requestedModel: MODEL_ID,
      returnedModel: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH.toUpperCase(),
    })).toBeNull();
  });

  test("reads historical provider-only bindings but requires exact model fields for new bindings", () => {
    expect(parseRecoveryProviderRouteBinding(guidedBinding(1))).toMatchObject({
      schemaVersion: 1,
      providerId: "openrouter",
    });
    expect(parseRecoveryProviderRouteBinding(guidedBinding(2))).toMatchObject({
      schemaVersion: 2,
      providerId: "openrouter",
      modelId: MODEL_ID,
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
    });
    expect(parseRecoveryProviderRouteBinding({
      ...guidedBinding(2),
      modelConfigurationHash: undefined,
    })).toBeNull();
  });

  test("retains exact prior model provenance when a route is invalidated", () => {
    expect(parseRecoveryProviderRouteTombstone({
      schemaVersion: 2,
      invalidated: true,
      runId: "run-provider-route",
      previousProviderId: "openrouter",
      previousModelId: MODEL_ID,
      previousModelConfigurationHash: MODEL_CONFIGURATION_HASH,
      previousVersion: 3,
      planId: "plan-provider-route",
      stepId: "step-provider-route",
      assignmentId: "assignment-provider-route",
      reason: "assignment_changed",
      invalidatedBy: "operator-one",
      invalidatedAt: "2026-07-22T12:01:00.000Z",
    })).toMatchObject({
      previousProviderId: "openrouter",
      previousModelId: MODEL_ID,
      previousModelConfigurationHash: MODEL_CONFIGURATION_HASH,
    });
  });
});

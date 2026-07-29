import { describe, expect, test } from "bun:test";
import { guidedRuntimeCapabilities } from "../../../src/domain/guidedRuntimeCapabilities";
import type {
  ExecutionReadiness,
  GuidedExecutionReadiness,
  RuntimeComponentHealth,
  RuntimeReadinessSnapshot,
} from "../../../src/domain/types/runtimeReadiness";

function readiness(options: {
  guided?: GuidedExecutionReadiness;
  guidedToolExecution?: ExecutionReadiness;
  localCommanderGuidance?: ExecutionReadiness;
  guidedProviders?: number;
  brainStatus?: RuntimeComponentHealth;
  canonicalBrain?: boolean;
} = {}): RuntimeReadinessSnapshot {
  return {
    schemaVersion: "2.4",
    status: "degraded",
    execution: {
      autonomous: "unavailable",
      guided: options.guided ?? "unavailable",
      guidedToolExecution: options.guidedToolExecution ?? "unavailable",
      localCommanderGuidance: options.localCommanderGuidance ?? "unavailable",
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
    },
    dependencies: {
      providers: {
        status: (options.guidedProviders ?? 0) > 0 ? "available" : "unavailable",
        initializing: false,
        probing: 0,
        reason: null,
        declared: options.guidedProviders ?? 0,
        callable: options.guidedProviders ?? 0,
        enforcing: 0,
        guidedCapable: options.guidedProviders ?? 0,
      },
      mcp: {
        status: "unavailable",
        initializing: false,
        probingServers: 0,
        reason: null,
        configuredServers: 0,
        runnableServers: 0,
        executionMode: "disabled",
      },
      secondBrain: {
        status: options.brainStatus ?? "healthy",
        canonicalStoreAvailable: options.canonicalBrain ?? true,
        reason: null,
      },
    },
    checkedAt: "2026-07-19T16:30:00.000Z",
  };
}

describe("Guided runtime capability mapping", () => {
  test("keeps local Commander guidance and reviewed tool dispatch separate from providers", () => {
    expect(guidedRuntimeCapabilities(readiness({
      guided: "ready",
      guidedToolExecution: "ready",
      localCommanderGuidance: "ready",
      guidedProviders: 0,
    }))).toEqual({
      mode: "ready",
      manualOnly: false,
      decisionMutations: true,
      manualResultHandling: "ingestion_only",
      manualResultReview: true,
      manualResultCompletion: false,
      localCommanderGuidance: true,
      providerGuidance: false,
      memoryCandidateActions: true,
      toolDispatch: true,
    });
  });

  test("derives provider Commander features only from a callable Guided provider", () => {
    expect(guidedRuntimeCapabilities(readiness({
      guided: "ready",
      guidedToolExecution: "unavailable",
      guidedProviders: 1,
    }))).toEqual({
      mode: "ready",
      manualOnly: false,
      decisionMutations: true,
      manualResultHandling: "semantic_interpretation",
      manualResultReview: true,
      manualResultCompletion: true,
      localCommanderGuidance: false,
      providerGuidance: true,
      memoryCandidateActions: true,
      toolDispatch: false,
    });
  });

  test("attests memory candidate controls independently from providers and tool dispatch", () => {
    const result = guidedRuntimeCapabilities(readiness({
      guided: "ready",
      guidedToolExecution: "ready",
      localCommanderGuidance: "ready",
      guidedProviders: 0,
      brainStatus: "unhealthy",
      canonicalBrain: true,
    }));
    expect(result).toMatchObject({
      localCommanderGuidance: true,
      providerGuidance: false,
      memoryCandidateActions: false,
      toolDispatch: true,
    });
  });

  test("manual_only permits local ingestion and decisions but never agent dispatch", () => {
    expect(guidedRuntimeCapabilities(readiness({
      guided: "manual_only",
      guidedToolExecution: "ready",
      localCommanderGuidance: "ready",
      guidedProviders: 0,
    }))).toMatchObject({
      mode: "manual_only",
      manualOnly: true,
      decisionMutations: true,
      manualResultHandling: "ingestion_only",
      manualResultReview: true,
      manualResultCompletion: false,
      localCommanderGuidance: true,
      providerGuidance: false,
      memoryCandidateActions: true,
      toolDispatch: false,
    });
  });

  test("missing readiness fails closed", () => {
    expect(guidedRuntimeCapabilities(undefined)).toEqual({
      mode: "unavailable",
      manualOnly: false,
      decisionMutations: false,
      manualResultHandling: "unavailable",
      manualResultReview: false,
      manualResultCompletion: false,
      localCommanderGuidance: false,
      providerGuidance: false,
      memoryCandidateActions: false,
      toolDispatch: false,
    });
  });
});

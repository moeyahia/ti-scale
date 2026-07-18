import { describe, expect, test } from "bun:test";
import { ReadinessService, type AutonomousMissionRequest } from "../../missions";
import {
  createRuntimeReadinessProviders,
  type RuntimeReadinessSnapshot,
} from "../RuntimeReadiness";

const REQUEST: AutonomousMissionRequest = {
  journey: "autonomous",
  launch: true,
  title: "Authorized assessment",
  objective: "Collect evidence inside the approved scope",
  successCriteria: ["Evidence collected"],
  authorization: {
    allowedTargets: ["192.0.2.40"],
    prohibitedTargets: [],
    authorizationConfirmed: true,
  },
  contract: {
    allowedActionClasses: ["network"],
    prohibitedActionClasses: ["destructive"],
    destructivePolicy: "prohibited",
    evidenceRequirements: ["Hash every capture"],
    timeBudgetMinutes: 30,
    retryBudget: 2,
    replanBudget: 2,
    concurrencyLimit: 2,
    evidenceStorageBudgetBytes: 64 * 1024 * 1024,
    artifactStorageBudgetBytes: 256 * 1024 * 1024,
    notificationPolicy: "in_app_only",
    reportingFormat: "ti_scale_json",
    dataHandlingPolicy: "local_private",
    retentionPolicy: "operator_managed",
    providerPolicy: "automatic_enforcing_only",
    toolPolicy: "contract_allowlist",
    specialistAgentIds: ["agent-recon"],
    memoryScopes: ["verified_lessons"],
    contextNodeIds: [],
    safeStopConditions: ["Scope conflict"],
    deliverables: ["Evidence bundle"],
  },
};

function healthy(): RuntimeReadinessSnapshot {
  return {
    actionBoundaryActive: true,
    delegationEnforced: true,
    noHandsCommanderEnforced: true,
    directCommanderToolsDenied: true,
    specialistAssignmentRequired: true,
    specialistsConfigured: 12,
    providers: [{
      id: "xai-grok",
      health: "healthy",
      authenticated: true,
      callable: true,
      supportsGuided: true,
      enforcesAutonomousBoundary: true,
      reportsExactTokenUsage: true,
      reportsExactCostUsage: true,
    }],
    mcp: {
      enabled: true,
      executionMode: "enabled",
      startPermitted: true,
      configuredServers: 12,
      runnableServers: 10,
      missingDependencies: 0,
      missingSecrets: 0,
    },
    eventStream: "healthy",
    secondBrain: "healthy",
    legacyExecutionEnabled: false,
  };
}

describe("runtime-backed readiness", () => {
  test("permits an Autonomous contract only when every execution dependency is real", async () => {
    const service = new ReadinessService(createRuntimeReadinessProviders(healthy));
    const result = await service.evaluateJourney("autonomous", { request: REQUEST });
    expect(result.status).toBe("ready");
    expect(result.checks.some((item) => item.status === "fail")).toBe(false);
    expect(result.checks.some((item) => item.id === "execution_boundary_autonomous")).toBe(true);
    expect(result.checks.some((item) => item.id === "provider_execution_autonomous")).toBe(true);
  });

  test("fails Autonomous closed while preserving manual Guided operation as degraded", async () => {
    const broken: RuntimeReadinessSnapshot = {
      ...healthy(),
      actionBoundaryActive: false,
      providers: [{
        id: "xai-grok",
        health: "healthy",
        authenticated: true,
        callable: true,
        supportsGuided: true,
        enforcesAutonomousBoundary: false,
        reportsExactTokenUsage: true,
        reportsExactCostUsage: false,
      }],
      mcp: {
        enabled: false,
        executionMode: "disabled",
        startPermitted: false,
        configuredServers: 0,
        runnableServers: 0,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      eventStream: "unhealthy",
      secondBrain: "unknown",
      legacyExecutionEnabled: false,
    };
    const service = new ReadinessService(createRuntimeReadinessProviders(() => broken));
    const autonomous = await service.evaluateJourney("autonomous", { request: REQUEST });
    expect(autonomous.status).toBe("blocked");
    expect(autonomous.checks.filter((item) => item.status === "fail").map((item) => item.id))
      .toEqual(expect.arrayContaining([
        "execution_boundary_autonomous",
        "provider_execution_autonomous",
        "mcp_execution_autonomous",
        "memory_policy",
      ]));

    const guided = await service.evaluateJourney("guided");
    expect(guided.status).toBe("degraded");
    expect(guided.checks.some((item) => item.status === "fail")).toBe(false);
    expect(guided.checks.find((item) => item.id === "execution_boundary_guided")?.status).toBe("pass");
    const guidedMcp = guided.checks.find((item) => item.id === "mcp_execution_guided");
    expect(guidedMcp?.status).toBe("warn");
  });

  test("fails closed when finite token or cost budgets lack exact provider telemetry", async () => {
    const unsupported: RuntimeReadinessSnapshot = {
      ...healthy(),
      providers: healthy().providers.map((provider) => ({
        ...provider,
        reportsExactTokenUsage: false,
        reportsExactCostUsage: false,
      })),
    };
    const request: AutonomousMissionRequest = {
      ...REQUEST,
      contract: { ...REQUEST.contract, tokenBudget: 25_000, costBudget: 5 },
    };
    const result = await new ReadinessService(createRuntimeReadinessProviders(() => unsupported))
      .evaluateJourney("autonomous", { request });
    expect(result.status).toBe("blocked");
    expect(result.checks.filter((item) => item.status === "fail").map((item) => item.id))
      .toEqual(expect.arrayContaining([
        "provider_token_accounting_autonomous",
        "provider_cost_accounting_autonomous",
      ]));
  });

  test("does not authorize an unprobed or revoked Grok route", async () => {
    for (const provider of [
      {
        ...healthy().providers[0]!,
        health: "degraded" as const,
        authenticated: false,
        callable: false,
        reason: "Grok OAuth has not completed a live attestation",
      },
      {
        ...healthy().providers[0]!,
        health: "unhealthy" as const,
        authenticated: false,
        callable: false,
        reason: "Live Grok OAuth authentication was rejected",
      },
    ]) {
      const result = await new ReadinessService(createRuntimeReadinessProviders(() => ({
        ...healthy(),
        providers: [provider],
      }))).evaluateJourney("autonomous", { request: REQUEST });
      expect(result.status).toBe("blocked");
      expect(result.checks.find((item) => item.id === "provider_execution_autonomous")?.status)
        .toBe("fail");
    }
  });

  test("surfaces an explicit degraded state when the legacy execution rollback window is active", async () => {
    const compatibility = { ...healthy(), legacyExecutionEnabled: true };
    const result = await new ReadinessService(createRuntimeReadinessProviders(() => compatibility))
      .evaluateJourney("guided");
    expect(result.status).toBe("degraded");
    expect(result.checks.find((item) => item.id === "legacy_execution_surface")).toMatchObject({
      status: "warn",
      remediation: expect.stringContaining("ENABLE_LEGACY_EXECUTION_API"),
    });
  });
});

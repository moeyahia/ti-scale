import { describe, expect, test } from "bun:test";
import { ReadinessService, type AutonomousMissionRequest } from "../../missions";
import {
  createRuntimeReadinessProviders,
  type RuntimeReadinessSnapshot,
} from "../RuntimeReadiness";
import {
  exactCandidateLinuxTargetScope,
} from "../../autonomous-runtime/CandidateLinuxTargetScope";

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
    agentModelAssignments: [{
      agentId: "agent-recon",
      primaryConfigurationId: "modelcfg_runtime_readiness_test",
      fallbackConfigurationId: null,
    }],
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
    autonomousRuntime: {
      schemaVersion: "ti-scale.autonomous-runtime-composition.v1",
      status: "ready",
      readyActionClassIds: ["active_host_discovery"],
      components: {
        plannerAdapter: true,
        outcomeEvaluator: true,
        resultAwareSpecialistExecution: true,
        enforcingProvider: true,
        durableActionBoundary: true,
        specialistFleet: true,
        mcpExecution: true,
        localProcessExecution: false,
        exactRuntimeManifest: true,
      },
      blockers: [],
    },
    eventStream: "healthy",
    secondBrain: "healthy",
    legacyExecutionEnabled: false,
  };
}

function exactTargetCandidateReadiness(): NonNullable<
  RuntimeReadinessSnapshot["candidateLinuxTransport"]
> {
  const targetScope = exactCandidateLinuxTargetScope(
    "127.0.0.2",
    { transport: "tcp", port: 8080 },
  );
  return {
    status: "ready",
    code: "candidate_linux_transport_ready",
    reason: "The exact reviewed provider is installed.",
    manifestSha256: "a".repeat(64),
    bindingIds: ["binding.complete-autonomous-candidate"],
    bindingCapabilities: [{
      bindingId: "binding.complete-autonomous-candidate",
      candidateClass: "reviewed_real_candidate_v1",
      realTargetSupport: true,
      targetScope,
    }],
    readinessScope: "reviewed_real_candidate",
    activationModel: "run_scoped_after_discovery",
    candidateProcedurePresentAtLaunch: true,
    procedureProviderPresentAtLaunch: true,
    runScopedProcedureActivationPresentAtLaunch: false,
    candidateDispatchAuthorityPresentAtLaunch: false,
    conditionalPlanningReady: true,
    targetScopes: [targetScope],
    missionExecutionReady: false,
    expiresAt: "2026-07-29T12:05:00.000Z",
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

  test("admits exact-target candidate classes without advertising them globally", async () => {
    const request: AutonomousMissionRequest = {
      ...REQUEST,
      authorization: {
        ...REQUEST.authorization,
        allowedTargets: ["127.0.0.2"],
      },
      contract: {
        ...REQUEST.contract,
        allowedActionClasses: ["exploit_validation"],
      },
    };
    const snapshot: RuntimeReadinessSnapshot = {
      ...healthy(),
      candidateLinuxTransport: exactTargetCandidateReadiness(),
      autonomousRuntime: {
        ...healthy().autonomousRuntime!,
        readyActionClassIds: ["active_host_discovery"],
        components: {
          ...healthy().autonomousRuntime!.components,
          mcpExecution: false,
          localProcessExecution: true,
        },
      },
    };

    expect(snapshot.autonomousRuntime?.readyActionClassIds)
      .not.toContain("exploit_validation");
    const result = await new ReadinessService(
      createRuntimeReadinessProviders(() => snapshot),
    ).evaluateJourney("autonomous", { request });
    expect(result.checks.find(({ id }) => id === "candidate_linux_target_scope"))
      .toMatchObject({ status: "pass" });
    expect(result.checks.find(({ id }) => id === "mcp_execution_autonomous"))
      .toMatchObject({ status: "pass" });
  });

  test("does not require the candidate provider for an already-ready local exploit boundary", async () => {
    const request: AutonomousMissionRequest = {
      ...REQUEST,
      authorization: {
        ...REQUEST.authorization,
        allowedTargets: ["127.0.0.2"],
      },
      contract: {
        ...REQUEST.contract,
        allowedActionClasses: ["exploit_validation"],
      },
    };
    const baseline = healthy();
    const snapshot: RuntimeReadinessSnapshot = {
      ...baseline,
      autonomousRuntime: {
        ...baseline.autonomousRuntime!,
        readyActionClassIds: [
          ...baseline.autonomousRuntime!.readyActionClassIds,
          "exploit_validation",
        ],
      },
    };

    const result = await new ReadinessService(
      createRuntimeReadinessProviders(() => snapshot),
    ).evaluateJourney("autonomous", { request });

    expect(result.checks.find(({ id }) => id === "candidate_linux_target_scope"))
      .toMatchObject({ status: "pass" });
    expect(result.checks.find(({ id }) => id === "mcp_execution_autonomous"))
      .toMatchObject({ status: "pass" });
  });

  test.each([
    "127.0.0.3",
    "10.129.39.191",
  ])("rejects target-scoped candidate readiness for unrelated target %s", async (target) => {
    const request: AutonomousMissionRequest = {
      ...REQUEST,
      authorization: {
        ...REQUEST.authorization,
        allowedTargets: [target],
      },
      contract: {
        ...REQUEST.contract,
        allowedActionClasses: ["exploit_validation"],
      },
    };
    const snapshot: RuntimeReadinessSnapshot = {
      ...healthy(),
      candidateLinuxTransport: exactTargetCandidateReadiness(),
      autonomousRuntime: {
        ...healthy().autonomousRuntime!,
        readyActionClassIds: ["active_host_discovery"],
        components: {
          ...healthy().autonomousRuntime!.components,
          mcpExecution: false,
          localProcessExecution: true,
        },
      },
    };
    const result = await new ReadinessService(
      createRuntimeReadinessProviders(() => snapshot),
    ).evaluateJourney("autonomous", { request });

    expect(result.status).toBe("blocked");
    expect(result.checks.find(({ id }) => id === "candidate_linux_target_scope"))
      .toMatchObject({
        status: "fail",
        impact: expect.stringContaining("not all covered"),
      });
    expect(result.checks.find(({ id }) => id === "mcp_execution_autonomous"))
      .toMatchObject({ status: "fail" });
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

  test("does not infer Autonomous composition from optimistic legacy booleans", async () => {
    const { autonomousRuntime: _omitted, ...withoutComposition } = healthy();
    const result = await new ReadinessService(createRuntimeReadinessProviders(
      () => withoutComposition,
    )).evaluateJourney("autonomous", { request: REQUEST });

    expect(result.status).toBe("blocked");
    expect(result.checks.find(({ id }) => id === "execution_boundary_autonomous"))
      .toMatchObject({
        status: "fail",
        impact: expect.stringContaining("no exact proof"),
      });
  });

  test("reports the no-provider local Guided path as manual-only without inventing a specialist", async () => {
    const manualOnly: RuntimeReadinessSnapshot = {
      ...healthy(),
      actionBoundaryActive: false,
      delegationEnforced: false,
      noHandsCommanderEnforced: false,
      specialistsConfigured: 0,
      providers: [],
      mcp: {
        enabled: false,
        executionMode: "disabled",
        startPermitted: false,
        configuredServers: 0,
        runnableServers: 0,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      guidedManualPlanning: {
        status: "ready",
        plannerId: "ti-scale.local-guided-manual-planner",
        executionMode: "manual_only",
        targetInteraction: "operator_only",
        providerContact: false,
        toolDispatch: false,
        reason: "Local deterministic represented-manual planning is ready.",
      },
    };
    const service = new ReadinessService(createRuntimeReadinessProviders(() => manualOnly));
    const guided = await service.evaluateJourney("guided");
    expect(guided.status).toBe("degraded");
    expect(guided.checks.some((item) => item.status === "fail")).toBe(false);
    expect(guided.checks.find((item) => item.id === "execution_boundary_guided"))
      .toMatchObject({ status: "pass", impact: expect.stringContaining("manual steps only") });
    expect(guided.checks.find((item) => item.id === "provider_execution_guided"))
      .toMatchObject({ status: "warn", impact: expect.stringContaining("No public provider") });
    expect(guided.checks.find((item) => item.id === "specialist_fleet_guided"))
      .toMatchObject({ status: "warn", impact: expect.stringContaining("not advertised as a specialist") });

    const autonomous = await service.evaluateJourney("autonomous", { request: REQUEST });
    expect(autonomous.status).toBe("blocked");
    expect(autonomous.checks.find((item) => item.id === "specialist_fleet_autonomous")?.status)
      .toBe("fail");
  });

  test("reports reviewed local Guided execution without inventing MCP or provider readiness", async () => {
    const localGuided: RuntimeReadinessSnapshot = {
      ...healthy(),
      actionBoundaryActive: false,
      delegationEnforced: false,
      noHandsCommanderEnforced: false,
      specialistsConfigured: 0,
      providers: [],
      mcp: {
        enabled: false,
        executionMode: "disabled",
        startPermitted: false,
        configuredServers: 0,
        runnableServers: 0,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      guidedLocalToolExecution: {
        status: "ready",
        specialistId: "specialist:local-recon",
        executionBinding: "reviewed_local_process",
        readyToolIds: ["kali:host-dns-query"],
        exactDecisionRequired: true,
        targetInteraction: "operator_approved_exact_step",
        providerContact: false,
        mcpTransport: false,
        checkedAt: "2026-07-19T12:00:00.000Z",
        expiresAt: "2026-07-19T12:01:00.000Z",
        reason: "The exact local binding is current.",
      },
    };
    const service = new ReadinessService(createRuntimeReadinessProviders(() => localGuided));
    const guided = await service.evaluateJourney("guided");

    expect(guided.status).toBe("degraded");
    expect(guided.checks.some((item) => item.status === "fail")).toBe(false);
    expect(guided.checks.find((item) => item.id === "execution_boundary_guided"))
      .toMatchObject({ status: "pass", impact: expect.stringContaining("reviewed executable/argv") });
    expect(guided.checks.find((item) => item.id === "guided_local_tool_execution"))
      .toMatchObject({ status: "pass", impact: expect.stringContaining("not MCP servers") });
    expect(guided.checks.find((item) => item.id === "mcp_execution_guided"))
      .toMatchObject({ status: "warn", impact: expect.stringContaining("not represented as MCP") });
    expect(guided.checks.find((item) => item.id === "provider_execution_guided"))
      .toMatchObject({ status: "warn", impact: expect.stringContaining("reviewed local specialist") });

    const autonomous = await service.evaluateJourney("autonomous", { request: REQUEST });
    expect(autonomous.status).toBe("blocked");
    expect(autonomous.checks.find((item) => item.id === "mcp_execution_autonomous")?.status)
      .toBe("fail");
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

  test("fails a memory-scoped Autonomous contract closed when canonical Brain retrieval is degraded", async () => {
    const degraded: RuntimeReadinessSnapshot = {
      ...healthy(),
      secondBrain: "degraded",
    };
    const result = await new ReadinessService(createRuntimeReadinessProviders(() => degraded))
      .evaluateJourney("autonomous", { request: REQUEST });
    expect(result.status).toBe("blocked");
    expect(result.checks.find((item) => item.id === "memory_policy")).toMatchObject({
      status: "fail",
      remediation: "Restore the canonical memory service or remove memory scopes from the contract.",
    });
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

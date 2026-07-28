import { describe, expect, test } from "bun:test";
import { BrainContextService } from "../../brain-runtime";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import type { ResultAwareExecutionPort } from "../../command-runtime";
import { MemoryRepository, SecondBrainService } from "../../memory";
import { digestCanonicalJson } from "../../mcp";
import {
  modelConfigurationBindingHash,
  ModelConfigurationRepository,
  ModelConfigurationService,
} from "../../model-config";
import {
  MissionRepository,
  type AutonomousMissionRequest,
} from "../../missions";
import type { DurableAction } from "../../orchestration";
import {
  RuntimeProjectionService,
  type RuntimeProjectionInput,
} from "../RuntimeProjectionService";
import {
  AutonomousRuntimeCompositionError,
  createProductionAutonomousRuntime,
  inspectAutonomousRuntimeComposition,
  type ProductionAutonomousRuntimeAdapters,
} from "../AutonomousRuntimeComposition";

const MODEL_CONFIGURATION_HASH = "a".repeat(64);
const NOW = new Date("2026-07-19T00:00:30.000Z");

function readyProjection(now = NOW): RuntimeProjectionInput {
  const observedAt = new Date(now.getTime() - 30_000).toISOString();
  const expiresAt = new Date(now.getTime() + 5 * 60_000).toISOString();
  return {
    readiness: {
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: true,
      specialistsConfigured: 1,
      providers: [{
        id: "provider-autonomous",
        health: "healthy",
        configured: true,
        authenticated: true,
        callable: true,
        attestedAt: observedAt,
        expiresAt,
        circuitState: "closed",
        completionProbeReceiptId: "probe-autonomous-reviewed",
        supportsGuided: false,
        enforcesAutonomousBoundary: true,
        reportsExactTokenUsage: true,
        reportsExactCostUsage: true,
        requestedModel: "model-reviewed",
        returnedModel: "model-reviewed",
        modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      }],
      mcp: {
        enabled: true,
        executionMode: "enabled",
        startPermitted: true,
        configuredServers: 1,
        runnableServers: 1,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      eventStream: "healthy",
      secondBrain: "healthy",
      legacyExecutionEnabled: false,
    },
    agents: [{
      id: "ReconScout",
      role: "reconnaissance",
      displayName: "Recon Scout",
      status: "available",
      providerPolicy: {},
      toolPolicy: {
        allowedTools: ["tool-active-host-discovery"],
        deniedTools: [],
        approvalRequiredTools: [],
      },
      configuration: {
        schemaVersion: "ti-scale.autonomous-specialist-runtime.v1",
        executionMode: "specialist_runtime",
        adapterId: "isolated-specialist-transport",
        toolSelection: "exact_persisted_binding_only",
        resultDelivery: "bound_execution_result_sink",
        shellInterpolation: false,
        publicProviderToolExecution: false,
      },
      version: "reviewed-1",
      lastHeartbeatAt: observedAt,
      capabilities: [{ name: "cap-recon", source: "reviewed", enabled: true }],
    }],
    mcpServers: [{
      id: "specialist-mcp",
      name: "Specialist MCP",
      transport: "isolated-local",
      status: "healthy",
      capabilities: ["tool-active-host-discovery"],
      policy: {
        schemaVersion: "ti-scale.specialist-mcp-execution-policy.v1",
        enabled: true,
        startPermitted: true,
        executionAuthorization: "signed_contract_specialist_action",
        autonomousExecution: true,
        exactInventoryRequired: true,
        directCommanderToolsAllowed: false,
        assignedAgents: ["ReconScout"],
      },
      lastCheckedAt: observedAt,
    }],
    capabilityManifests: {
      riskClasses: [{
        id: "risk-low",
        label: "Low",
        actionClassIds: ["active_host_discovery"],
      }],
      evidenceKinds: [{
        id: "evidence-assets",
        label: "Asset discovery",
        evidenceTypeIds: ["asset_discovery_proof"],
      }],
      capabilities: [{
        id: "cap-recon",
        label: "Reconnaissance",
        actionClassIds: ["active_host_discovery"],
        evidenceTypeIds: ["asset_discovery_proof"],
      }],
      tools: [{
        id: "tool-active-host-discovery",
        label: "Bounded active host discovery",
        available: true,
        locallyPolicyEnforced: true,
        requiresModel: true,
        actionClassIds: ["active_host_discovery"],
        evidenceTypeIds: ["asset_discovery_proof"],
        riskClassIds: ["risk-low"],
        mcpServerId: "specialist-mcp",
      }],
      mcpServers: [{
        id: "specialist-mcp",
        label: "Specialist MCP",
        status: "healthy",
        toolIds: ["tool-active-host-discovery"],
      }],
      agents: [{
        id: "ReconScout",
        label: "Recon Scout",
        available: true,
        capabilityIds: ["cap-recon"],
        actionClassIds: ["active_host_discovery"],
        toolIds: ["tool-active-host-discovery"],
        modelRefs: [{ providerId: "provider-autonomous", modelId: "model-reviewed" }],
      }],
      providers: [{
        id: "provider-autonomous",
        authenticated: true,
        healthy: true,
        catalogObservedAt: observedAt,
        models: [{
          id: "model-reviewed",
          displayName: "Reviewed model",
          toolCalling: true,
          structuredOutput: true,
          enforcement: "enforced_executor",
          compatibleActionClassIds: ["active_host_discovery"],
          disclosureClasses: ["public"],
        }],
      }],
    },
  };
}

function adapters(): ProductionAutonomousRuntimeAdapters {
  const executionBindings = [{
    bindingId: "binding-active-host-discovery",
    actionClassId: "active_host_discovery",
    agentId: "ReconScout",
    providerId: "provider-autonomous",
    modelId: "model-reviewed",
    modelConfigurationHash: MODEL_CONFIGURATION_HASH,
    mcpServerId: "specialist-mcp",
    toolName: "tool-active-host-discovery",
  }] as const;
  return {
    planner: {
      providerBoundary: {
        kind: "public_provider",
        agentId: "ReconScout",
        providerId: "provider-autonomous",
        modelId: "model-reviewed",
        modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      },
      localPlanningBoundary: {
        schemaVersion: "ti-scale.local-autonomous-planner-boundary.v1",
        kind: "local_deterministic",
        providerContact: false,
        canonicalContractRequired: true,
        runtimeManifestRequired: true,
        heuristicToolArguments: false,
        policyId: "reviewed-local-policy",
        policyHash: "b".repeat(64),
        bindings: executionBindings,
      },
      autonomousExecutionBindings: executionBindings,
      autonomousContract: {
        schemaVersion: "ti-scale.autonomous-planner-adapter.v1",
        plannerId: "bounded-planner",
        planAuthority: "signed_contract_bounded_plan",
        providerToolDeclarations: "none",
        directToolDispatch: false,
      },
      async plan() {
        throw new Error("contract fixture does not invoke a provider");
      },
    },
    outcomeEvaluator: {
      autonomousContract: {
        schemaVersion: "ti-scale.autonomous-outcome-evaluator.v1",
        evaluatorId: "verified-evidence-evaluator",
        evidenceAuthority: "verified_evidence_only",
        successAuthority: "criteria_evaluation_only",
        providerContact: false,
      },
      async evaluate() {
        throw new Error("contract fixture does not evaluate a mission");
      },
    },
    execution: {
      adapterContract: {
        schemaVersion: "ti-scale.specialist-tool-invocation-adapter.v1",
        adapterId: "isolated-specialist-transport",
        toolSelection: "exact_persisted_binding_only",
        resultDelivery: "bound_execution_result_sink",
        cancellation: "run_scoped_cooperative",
        shellInterpolation: false,
        publicProviderToolExecution: false,
      },
      create() {
        throw new Error("contract fixture does not construct a transport");
      },
    },
  };
}

describe("Autonomous runtime production composition", () => {
  test("binds the operator-selected exact execution model locally without creating an advisor turn, then rejects selection drift", async () => {
    const runCase = async (
      selectedModelId: "model-reviewed" | "model-drifted",
      options: Readonly<{
        now?: Date;
        omitRuntimeClock?: boolean;
        catalogRetrievedAt?: string;
      }> = {},
    ) => {
      const caseNow = options.now ?? NOW;
      const database = createDatabaseConnection({ filename: ":memory:" });
      migrateDatabase(database);
      const projection = readyProjection(caseNow);
      const manifests = projection.capabilityManifests!;
      const expandedManifests = {
        ...manifests,
        agents: manifests.agents.map((agent) => ({
          ...agent,
          modelRefs: [
            ...agent.modelRefs,
            { providerId: "provider-autonomous", modelId: "model-drifted" },
          ],
        })),
        providers: manifests.providers.map((provider) => ({
          ...provider,
          models: [
            ...provider.models.map((model) => ({
              ...model,
              reasoningEfforts: ["low", "high"],
            })),
            {
              ...provider.models[0]!,
              id: "model-drifted",
              displayName: "Drifted model",
              reasoningEfforts: ["high"],
            },
          ],
        })),
      };
      const expandedProjection = {
        ...projection,
        capabilityManifests: expandedManifests,
      };
      new RuntimeProjectionService({
        database,
        read: () => expandedProjection,
        clock: () => caseNow,
      }).projectNow(expandedProjection);
      const modelConfigurations = new ModelConfigurationService(
        new ModelConfigurationRepository(database, () => caseNow),
        {
          readRuntimeManifests: () => expandedManifests,
          clock: () => caseNow,
        },
      );
      const selected = modelConfigurations.catalog().items.find((item) =>
        item.modelId === selectedModelId && item.reasoningEffort === "high");
      if (!selected) throw new Error("Exact high-reasoning model fixture is missing");
      const request: AutonomousMissionRequest = {
        journey: "autonomous",
        launch: true,
        title: "Exact runtime model binding",
        objective: "Discover the authorized lab host with one reviewed specialist",
        successCriteria: ["Record one attributable host discovery result"],
        authorization: {
          allowedTargets: ["lab.internal"],
          prohibitedTargets: [],
          authorizationConfirmed: true,
        },
        contract: {
          allowedActionClasses: ["active_host_discovery"],
          prohibitedActionClasses: [],
          destructivePolicy: "prohibited",
          evidenceRequirements: ["asset_discovery_proof"],
          timeBudgetMinutes: 30,
          retryBudget: 1,
          replanBudget: 1,
          concurrencyLimit: 1,
          evidenceStorageBudgetBytes: 1_024,
          artifactStorageBudgetBytes: 1_024,
          notificationPolicy: "in_app_only",
          reportingFormat: "ti_scale_json",
          dataHandlingPolicy: "local_private",
          retentionPolicy: "operator_managed",
          providerPolicy: "automatic_enforcing_only",
          toolPolicy: "contract_allowlist",
          specialistAgentIds: ["ReconScout"],
          agentModelAssignments: [{
            agentId: "ReconScout",
            primaryConfigurationId: selected.configurationId,
            fallbackConfigurationId: null,
            source: "operator_override",
          }],
          memoryScopes: [],
          contextNodeIds: [],
          safeStopConditions: [],
          deliverables: [],
        },
      };
      const created = new MissionRepository(database, () => caseNow).create({
        request,
        requestHash: selected.configurationId.padEnd(64, "0").slice(0, 64),
        idempotencyKey: `runtime-model-${selectedModelId}`,
        actorId: "operator",
        pinModelAssignments: ({
          missionId,
          runId,
          specialistAgentIds,
          agentModelAssignments,
          allowedActionClasses,
        }) => modelConfigurations.pinExactAutonomousAssignments({
          missionId,
          runId,
          specialistAgentIds,
          assignments: agentModelAssignments,
          requiredActionClassIds: allowedActionClasses,
        }).map(({ id }) => id),
      });
      let selectedConfiguration = modelConfigurations.listConfigurations([
        selected.configurationId,
      ])[0];
      if (!selectedConfiguration) {
        throw new Error("Pinned model configuration fixture was not materialized");
      }
      if (options.catalogRetrievedAt) {
        database.prepare(`
          UPDATE model_configurations
          SET catalog_retrieved_at = ?
          WHERE id = ?
        `).run(options.catalogRetrievedAt, selected.configurationId);
        selectedConfiguration = modelConfigurations.listConfigurations([
          selected.configurationId,
        ])[0];
        if (!selectedConfiguration) {
          throw new Error(
            "Updated model configuration fixture was not materialized",
          );
        }
      }
      let dispatched: DurableAction | undefined;
      const execution: ResultAwareExecutionPort = {
        async dispatch(action) {
          dispatched = action;
        },
        async resume() {},
        async cancelRun() {},
      };
      const configured = adapters();
      const executionConfigurationHash =
        modelConfigurationBindingHash(selectedConfiguration);
      const executionBindings = [{
        bindingId: "binding-active-host-discovery",
        actionClassId: "active_host_discovery",
        agentId: "ReconScout",
        providerId: "provider-autonomous",
        modelId: "model-reviewed",
        modelConfigurationHash: executionConfigurationHash,
        mcpServerId: "specialist-mcp",
        toolName: "tool-active-host-discovery",
      }] as const;
      const inputSchema = Object.freeze({
        type: "object",
        additionalProperties: false,
      });
      const inputSchemaDigest = digestCanonicalJson(inputSchema, {
        maxBytes: 64 * 1_024,
        maxDepth: 32,
      });
      const unsignedCapabilityAttestation = {
        schemaVersion: "ti-scale.mcp-capability-attestation.v1" as const,
        connectionId: "specialist-mcp",
        transport: "stdio" as const,
        server: { name: "specialist-mcp", version: "fixture-1" },
        protocolVersion: "2025-06-18",
        capabilities: { toolsListChanged: false },
        configurationSha256: "d".repeat(64),
        tools: [{
          name: "tool-active-host-discovery",
          inputSchema,
          inputSchemaSha256: inputSchemaDigest.sha256,
          inputSchemaBytes: inputSchemaDigest.bytes,
          annotations: {
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: false,
            openWorldHint: false,
          },
        }],
        attestedAt: new Date(
          caseNow.getTime() - 30_000,
        ).toISOString(),
        expiresAt: new Date(
          caseNow.getTime() + 5 * 60_000,
        ).toISOString(),
        executionAuthorization: "none" as const,
      };
      const capabilityAttestation = {
        ...unsignedCapabilityAttestation,
        manifestSha256: digestCanonicalJson(
          unsignedCapabilityAttestation,
          {
            maxBytes: 64 * 1024 * 1024,
            maxDepth: 256,
          },
        ).sha256,
      };
      const runtimeProjection: RuntimeProjectionInput = {
        ...expandedProjection,
        readiness: {
          ...expandedProjection.readiness,
          providers: expandedProjection.readiness.providers.map(
            (provider) => ({
              ...provider,
              modelConfigurationHash: executionConfigurationHash,
            }),
          ),
        },
        mcpServers: expandedProjection.mcpServers.map((server) => ({
          ...server,
          capabilityAttestation,
        })),
        capabilityManifests: {
          ...expandedManifests,
          tools: expandedManifests.tools.map((tool) => ({
            ...tool,
            executionJourneys: ["autonomous"] as const,
          })),
        },
      };
      const runtime = createProductionAutonomousRuntime({
        database,
        adapters: {
          ...configured,
          planner: {
            ...configured.planner,
            localPlanningBoundary: {
              ...configured.planner.localPlanningBoundary!,
              bindings: executionBindings,
            },
            autonomousExecutionBindings: executionBindings,
            async plan() {
              return {
                strategySummary: "Use one exact reviewed discovery route",
                rationaleSummary: "The selected specialist owns the signed action class",
                steps: [{
                  phase: "reconnaissance",
                  title: "Discover the exact lab host",
                  objective: "Establish current reachability",
                  explanation: "Send one bounded discovery request to the authorized host.",
                  rationale: "This is the first evidence-producing step.",
                  successCriteria: ["An attributable liveness result is recorded"],
                  dependencyOrdinals: [],
                  assignedAgentId: "ReconScout",
                  riskClass: "low",
                  reversibility: "Read-only and naturally reversible.",
                  action: {
                    actionType: "active_host_discovery",
                    actionClass: "active_host_discovery",
                    target: "lab.internal",
                    arguments: {
                      mcpServer: "specialist-mcp",
                      toolName: "tool-active-host-discovery",
                      parameters: { target: "lab.internal" },
                    },
                    intentSummary: "Check whether the exact authorized lab host responds",
                    kind: "tool",
                    idempotent: true,
                    destructive: false,
                  },
                }],
              };
            },
          },
          execution: {
            ...configured.execution,
            create() {
              return execution as never;
            },
          },
        },
        readRuntimeProjection: () => runtimeProjection,
        ...(options.omitRuntimeClock ? {} : { now: () => caseNow }),
      });
      try {
        await runtime.processRunNow(created.run.id);
        const providerTurn = database.prepare(`
          SELECT agent_id, model_assignment_id, model_configuration_id,
            model_configuration_hash, model_assignment_configuration_hash,
            status
          FROM provider_turns WHERE run_id = ?
          ORDER BY started_at, id LIMIT 1
        `).get(created.run.id) as Record<string, unknown> | undefined;
        return {
          database,
          runtime,
          dispatched,
          providerTurn,
          selected,
          selectedConfiguration,
          created,
        };
      } catch (error) {
        await runtime.stop();
        database.close();
        throw error;
      }
    };

    const exact = await runCase("model-reviewed");
    try {
      expect(exact.dispatched?.runtimeModelBinding).toMatchObject({
        schemaVersion: "ti-scale.runtime-model-binding.v1",
        agentId: "ReconScout",
        modelConfigurationId: exact.selected.configurationId,
        providerId: "provider-autonomous",
        modelId: "model-reviewed",
        reasoningEffort: "high",
        modelConfigurationHash: modelConfigurationBindingHash(
          exact.selectedConfiguration,
        ),
        providerConfigurationHash:
          modelConfigurationBindingHash(exact.selectedConfiguration),
      });
      expect(exact.providerTurn).toBeNull();
    } finally {
      await exact.runtime.stop();
      exact.database.close();
    }

    await expect(runCase("model-drifted")).rejects.toMatchObject({
      code: "activation_execution_model_configuration_mismatch",
    });

    const systemNow = new Date();
    await expect(runCase("model-reviewed", {
      now: systemNow,
      omitRuntimeClock: true,
      catalogRetrievedAt: new Date(
        systemNow.getTime() - 15 * 60_000 - 1,
      ).toISOString(),
    })).rejects.toMatchObject({
      code: "agent_runtime_binding_model_configuration_unavailable",
    });
  });

  test("forwards the shared Brain context and post-commit projection sink into the Autonomous runtime", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const configured = adapters();
    const projectMemoryNodes = (_nodeIds: readonly string[]): void => undefined;
    const brainContext = new BrainContextService({
      database,
      secondBrain: new SecondBrainService(new MemoryRepository(database, {
        clock: () => NOW,
      })),
    });
    const execution: ResultAwareExecutionPort = {
      async dispatch() {},
      async resume() {},
      async cancelRun() {},
    };
    const runtime = createProductionAutonomousRuntime({
      database,
      adapters: {
        ...configured,
        execution: {
          ...configured.execution,
          create() {
            return execution as never;
          },
        },
      },
      readRuntimeProjection: readyProjection,
      brainContext,
      projectMemoryNodes,
      now: () => NOW,
    });
    try {
      expect(runtime.brainContext).toBe(brainContext);
      expect(runtime.learning.options.projectMemoryNodes).toBe(projectMemoryNodes);
    } finally {
      await runtime.stop();
      database.close();
    }
  });

  test("keeps reset-signing authority out of the generic execution factory", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const configured = adapters();
    const signingKey = Buffer.from("server-only-operational-hazard-key-material-2026", "utf8");
    let receivedFactoryInput: Readonly<Record<string, unknown>> | undefined;
    const execution: ResultAwareExecutionPort = {
      async dispatch() {},
      async resume() {},
      async cancelRun() {},
    };
    const runtime = createProductionAutonomousRuntime({
      database,
      operationalHazardHmacKey: signingKey,
      adapters: {
        ...configured,
        execution: {
          ...configured.execution,
          create(input) {
            receivedFactoryInput = input;
            return execution as never;
          },
        },
      },
      readRuntimeProjection: readyProjection,
      now: () => NOW,
    });
    try {
      expect(receivedFactoryInput).toBeDefined();
      expect(Object.keys(receivedFactoryInput ?? {}).sort()).toEqual([
        "assertControlPlaneAuthority",
        "database",
      ]);
      expect(receivedFactoryInput).not.toHaveProperty("operationalHazardHmacKey");
      expect(runtime.operationalHazardResetReceiptIssuer).toBeDefined();
      expect(runtime.operationalHazardResetHealthRecorder).toBeDefined();
    } finally {
      await runtime.stop();
      database.close();
    }
  });

  test("fails closed with exact adapter blockers even when legacy readiness booleans are optimistic", () => {
    const report = inspectAutonomousRuntimeComposition({
      projection: readyProjection(),
      now: NOW,
    });

    expect(report.status).toBe("blocked");
    expect(report.readyActionClassIds).toEqual([]);
    expect(report.blockers.map(({ code }) => code)).toEqual(expect.arrayContaining([
      "autonomous_planner_adapter_missing",
      "autonomous_outcome_evaluator_missing",
      "specialist_execution_factory_missing",
    ]));
  });

  test("recognizes one fully cross-referenced executable action class only with concrete adapter contracts", () => {
    const report = inspectAutonomousRuntimeComposition({
      projection: readyProjection(),
      adapters: adapters(),
      now: NOW,
    });

    expect(report).toMatchObject({
      status: "ready",
      readyActionClassIds: ["active_host_discovery"],
      blockers: [],
      components: {
        plannerAdapter: true,
        outcomeEvaluator: true,
        resultAwareSpecialistExecution: true,
        enforcingProvider: true,
        durableActionBoundary: true,
        specialistFleet: true,
        mcpExecution: true,
        exactRuntimeManifest: true,
      },
    });
  });

  test("accepts a tool-free local deterministic planner while preserving exact specialist model readiness", () => {
    const configured = adapters();
    const report = inspectAutonomousRuntimeComposition({
      projection: readyProjection(),
      adapters: {
        ...configured,
        planner: {
          autonomousContract: {
            schemaVersion: "ti-scale.autonomous-planner-adapter.v1",
            plannerId: "ti-scale.local-autonomous-contract-planner",
            planAuthority: "signed_contract_bounded_plan",
            providerToolDeclarations: "none",
            directToolDispatch: false,
          },
          localPlanningBoundary: {
            schemaVersion: "ti-scale.local-autonomous-planner-boundary.v1",
            kind: "local_deterministic",
            providerContact: false,
            canonicalContractRequired: true,
            runtimeManifestRequired: true,
            heuristicToolArguments: false,
            policyId: "reviewed-local-policy",
            policyHash: "b".repeat(64),
            bindings: [{
              bindingId: "binding-active-host-discovery",
              actionClassId: "active_host_discovery",
              agentId: "ReconScout",
              providerId: "provider-autonomous",
              modelId: "model-reviewed",
              modelConfigurationHash: MODEL_CONFIGURATION_HASH,
              mcpServerId: "specialist-mcp",
              toolName: "tool-active-host-discovery",
            }],
          },
          async plan() {
            throw new Error("Composition inspection must not invoke the local planner");
          },
        },
      },
      now: NOW,
    });

    expect(report).toMatchObject({
      status: "ready",
      readyActionClassIds: ["active_host_discovery"],
      blockers: [],
      components: {
        plannerAdapter: true,
        enforcingProvider: true,
        resultAwareSpecialistExecution: true,
      },
    });
  });

  test("keeps local planning blocked when the specialist tool policy requires a runtime approval", () => {
    const configured = adapters();
    const projection = readyProjection();
    const approvalGatedProjection: RuntimeProjectionInput = {
      ...projection,
      agents: projection.agents.map((agent) => ({
        ...agent,
        toolPolicy: {
          allowedTools: ["tool-active-host-discovery"],
          deniedTools: [],
          approvalRequiredTools: ["tool-active-host-discovery"],
        },
      })),
    };

    const report = inspectAutonomousRuntimeComposition({
      projection: approvalGatedProjection,
      adapters: configured,
      now: NOW,
    });

    expect(report.status).toBe("blocked");
    expect(report.readyActionClassIds).toEqual([]);
    expect(report.blockers).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "autonomous_action_mapping_unavailable" }),
    ]));
  });

  test("rejects a discovery-only MCP projection even if counts claim one runnable server", () => {
    const projection = readyProjection();
    const publicPolicyProjection: RuntimeProjectionInput = {
      ...projection,
      mcpServers: projection.mcpServers.map((server) => ({
        ...server,
        policy: {
          schemaVersion: "ti-scale.specialist-mcp-execution-policy.v1",
          enabled: true,
          startPermitted: true,
          executionAuthorization: "none",
          autonomousExecution: false,
          exactInventoryRequired: true,
          directCommanderToolsAllowed: false,
          assignedAgents: ["ReconScout"],
        },
      })),
    };
    const report = inspectAutonomousRuntimeComposition({
      projection: publicPolicyProjection,
      adapters: adapters(),
      now: NOW,
    });

    expect(report.status).toBe("blocked");
    expect(report.readyActionClassIds).toEqual([]);
    expect(report.blockers).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "autonomous_action_mapping_unavailable" }),
    ]));
  });

  test("rejects provider tool declarations and provider-backed outcome evaluation", () => {
    const configured = adapters();
    const report = inspectAutonomousRuntimeComposition({
      projection: readyProjection(),
      adapters: {
        ...configured,
        planner: {
          ...configured.planner,
          autonomousContract: {
            ...configured.planner.autonomousContract,
            providerToolDeclarations: "tools",
          },
        } as unknown as ProductionAutonomousRuntimeAdapters["planner"],
        outcomeEvaluator: {
          ...configured.outcomeEvaluator,
          autonomousContract: {
            ...configured.outcomeEvaluator.autonomousContract,
            providerContact: true,
          },
        } as unknown as ProductionAutonomousRuntimeAdapters["outcomeEvaluator"],
      },
      now: NOW,
    });

    expect(report.status).toBe("blocked");
    expect(report.blockers).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "autonomous_planner_contract_invalid" }),
      expect.objectContaining({ code: "autonomous_outcome_evaluator_contract_invalid" }),
    ]));
  });

  test("does not align a declared specialist with a different mounted transport", () => {
    const projection = readyProjection();
    const drifted: RuntimeProjectionInput = {
      ...projection,
      agents: projection.agents.map((agent) => ({
        ...agent,
        configuration: { ...agent.configuration, adapterId: "different-adapter" },
      })),
    };
    const report = inspectAutonomousRuntimeComposition({
      projection: drifted,
      adapters: adapters(),
      now: NOW,
    });

    expect(report.status).toBe("blocked");
    expect(report.readyActionClassIds).toEqual([]);
    expect(report.blockers).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "autonomous_specialist_unavailable" }),
      expect.objectContaining({ code: "autonomous_action_mapping_unavailable" }),
    ]));
  });

  test("does not call the execution factory when the live projection is blocked", () => {
    const projection = readyProjection();
    let createCalls = 0;
    const configured = adapters();
    const blocked: RuntimeProjectionInput = {
      ...projection,
      readiness: { ...projection.readiness, specialistsConfigured: 0 },
    };

    expect(() => createProductionAutonomousRuntime({
      database: {} as SqliteDatabase,
      adapters: {
        ...configured,
        execution: {
          ...configured.execution,
          create(input) {
            createCalls += 1;
            return configured.execution.create(input);
          },
        } as ProductionAutonomousRuntimeAdapters["execution"],
      },
      readRuntimeProjection: () => blocked,
      now: () => NOW,
    })).toThrow(AutonomousRuntimeCompositionError);
    expect(createCalls).toBe(0);
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import {
  createRuntimeAdapterAttestation,
  type RuntimeSourceManifests,
} from "../../domain";
import { createModelConfigurationRouter } from "../ModelConfigurationRouter";
import {
  MODEL_CONFIGURATION_BINDING_HASH_SCHEMA_VERSION,
  modelConfigurationBindingHash,
} from "../ModelConfigurationBindingHash";
import { ModelConfigurationRepository } from "../ModelConfigurationRepository";
import { ModelConfigurationService } from "../ModelConfigurationService";
import {
  MissionRepository,
  type AutonomousMissionRequest,
} from "../../missions";
import {
  AgentRuntimeBindingError,
  AgentRuntimeBindingService,
} from "../../agent-runtime";

const NOW = "2026-07-23T15:00:00.000Z";
const servers: Server[] = [];
const databases: SqliteDatabase[] = [];
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) =>
    new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const database of databases.splice(0)) database.close();
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function manifests(): RuntimeSourceManifests {
  return {
    riskClasses: [],
    evidenceKinds: [],
    capabilities: [],
    tools: [],
    mcpServers: [],
    agents: [{
      id: "runtime:recon-adapter",
      label: "Internal reconnaissance adapter",
      available: true,
      capabilityIds: [],
      actionClassIds: ["active_host_discovery"],
      toolIds: [],
      modelRefs: [{
        providerId: "provider-open",
        modelId: "model-frontier",
      }],
    }],
    providers: [{
      id: "provider-open",
      authenticated: true,
      healthy: true,
      catalogObservedAt: NOW,
      models: [{
        id: "model-frontier",
        displayName: "Frontier Model",
        toolCalling: true,
        structuredOutput: true,
        enforcement: "enforced_executor",
        compatibleActionClassIds: ["active_host_discovery"],
        disclosureClasses: ["public"],
        contextLimit: 128_000,
        reasoningEfforts: ["low", "high"],
      }],
    }],
  };
}

interface LocalDeterministicManifestOptions {
  readonly agentAvailable?: boolean;
  readonly dependencyReady?: boolean;
  readonly executionBoundary?:
    | "provider_tool_calling"
    | "local_deterministic_policy";
  readonly executionJourneys?: readonly ("autonomous" | "guided")[];
  readonly locallyPolicyEnforced?: boolean;
  readonly mcpStatus?: "healthy" | "degraded" | "offline" | "unconfigured";
  readonly modelActionClassIds?: readonly string[];
  readonly requiresModel?: boolean;
  readonly runtimeAdapterWindow?: Readonly<{
    readonly observedAt: string;
    readonly expiresAt: string;
  }>;
  readonly toolActionClassIds?: readonly string[];
  readonly toolAvailable?: boolean;
  readonly toolPresent?: boolean;
}

function localDeterministicManifests(
  options: LocalDeterministicManifestOptions = {},
): RuntimeSourceManifests {
  const toolPresent = options.toolPresent ?? true;
  const toolActionClassIds =
    options.toolActionClassIds ?? ["active_host_discovery"];
  const modelActionClassIds =
    options.modelActionClassIds ?? ["active_host_discovery"];
  const mcpServerId = options.mcpStatus === undefined
    ? undefined
    : "mcp-local-recon";
  return {
    riskClasses: [],
    evidenceKinds: [],
    capabilities: [],
    tools: toolPresent
      ? [{
          id: "tool-local-recon",
          label: "Reviewed local reconnaissance tool",
          available: options.toolAvailable ?? true,
          locallyPolicyEnforced: options.locallyPolicyEnforced ?? true,
          requiresModel: options.requiresModel ?? false,
          executionJourneys: options.executionJourneys ?? ["autonomous"],
          actionClassIds: toolActionClassIds,
          evidenceTypeIds: [],
          riskClassIds: [],
          ...(mcpServerId ? { mcpServerId } : {}),
          ...(options.runtimeAdapterWindow
            ? {
                runtimeAdapterAttestation: createRuntimeAdapterAttestation({
                  toolId: "tool-local-recon",
                  executionJourneys: ["autonomous"],
                  binding: {
                    configurationSha256: "1".repeat(64),
                    providerReceiptSha256: "2".repeat(64),
                    localManifestSha256: "3".repeat(64),
                    componentReceiptSha256s: ["4".repeat(64)],
                  },
                  observedAt: options.runtimeAdapterWindow.observedAt,
                  expiresAt: options.runtimeAdapterWindow.expiresAt,
                }),
              }
            : {}),
          ...(options.dependencyReady === undefined
            ? {}
            : {
                dependencies: [{
                  id: "local-recon-dependency",
                  ready: options.dependencyReady,
                }],
              }),
        }]
      : [],
    mcpServers: mcpServerId
      ? [{
          id: mcpServerId,
          label: "Local reconnaissance MCP",
          status: options.mcpStatus!,
          toolIds: toolPresent ? ["tool-local-recon"] : [],
        }]
      : [],
    agents: [{
      id: "runtime:local-recon",
      label: "Reviewed local reconnaissance adapter",
      available: options.agentAvailable ?? true,
      capabilityIds: [],
      actionClassIds: modelActionClassIds,
      toolIds: toolPresent ? ["tool-local-recon"] : [],
      modelRefs: [{
        providerId: "provider-local",
        modelId: "model-local-policy",
      }],
    }],
    providers: [{
      id: "provider-local",
      authenticated: true,
      healthy: true,
      catalogObservedAt: NOW,
      models: [{
        id: "model-local-policy",
        displayName: "Local deterministic policy",
        executionBoundary:
          options.executionBoundary ?? "local_deterministic_policy",
        toolCalling: false,
        structuredOutput: true,
        enforcement: "enforced_executor",
        compatibleActionClassIds: modelActionClassIds,
        disclosureClasses: ["local"],
        contextLimit: 32_000,
      }],
    }],
  };
}

function database(): SqliteDatabase {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-model-router-"));
  temporaryDirectories.push(directory);
  const value = createDatabaseConnection({
    filename: join(directory, "ti-scale.sqlite"),
  });
  migrateDatabase(value);
  databases.push(value);
  value.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES (
      'ReconScout', 'reconnaissance', 'ReconScout', 'available', '1', ?, ?
    )
  `).run(NOW, NOW);
  value.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, created_by, created_at, updated_at
    ) VALUES (
      'mission-model', 'Model mission', 'Assess the authorized lab',
      'autonomous', 'operator', ?, ?
    )
  `).run(NOW, NOW);
  value.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, created_at, updated_at
    ) VALUES (
      'run-model', 'mission-model', 'autonomous', 'queued', ?, ?
    )
  `).run(NOW, NOW);
  value.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      content_hash, content_hash_version, created_by, created_at
    ) VALUES (
      'plan-model', 'run-model', 1, 'active', 'Model plan', ?, ?, 1,
      'operator', ?
    )
  `).run("a".repeat(64), "b".repeat(64), NOW);
  value.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      created_at, updated_at
    ) VALUES (
      'step-model', 'plan-model', 'run-model', 0, 'reconnaissance',
      'Map services', 'Map approved services', 'pending', ?, ?
    )
  `).run(NOW, NOW);
  return value;
}

async function server(
  db: SqliteDatabase,
  resolveActor: () => string | undefined = () => "operator-test",
): Promise<string> {
  const app = express();
  app.use(express.json());
  app.use(createModelConfigurationRouter({
    database: db,
    readRuntimeManifests: manifests,
    resolveActor,
    clock: () => new Date(NOW),
  }));
  const http = createServer(app);
  servers.push(http);
  await new Promise<void>((resolve) => http.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
}

async function json(response: Response): Promise<Record<string, any>> {
  return await response.json() as Record<string, any>;
}

describe("model configuration control plane", () => {
  test("admits and immutably records a no-model Autonomous route only through its exact local deterministic tool coverage", () => {
    const db = database();
    const repository = new ModelConfigurationRepository(
      db,
      () => new Date(NOW),
    );
    const service = new ModelConfigurationService(repository, {
      readRuntimeManifests: () => localDeterministicManifests(),
      clock: () => new Date(NOW),
    });

    const item = service.catalog().items[0]!;
    expect(item).toMatchObject({
      executionBoundary: "local_deterministic_policy",
      selectable: true,
      capabilities: {
        toolCalling: false,
        structuredOutput: true,
        localDeterministicActionClassIdsByAgent: {
          ReconScout: ["active_host_discovery"],
        },
      },
    });
    const resolved = service.resolveAutonomousAssignments({
      specialistAgentIds: ["ReconScout"],
      requiredActionClassIds: ["active_host_discovery"],
    });
    expect(resolved.receipts).toEqual([expect.objectContaining({
      agentId: "ReconScout",
      ready: true,
      reasons: [],
      primary: expect.objectContaining({
        executionBoundary: "local_deterministic_policy",
      }),
    })]);

    const stored = repository.materializeCatalogConfiguration(item);
    expect(stored.executionBoundary).toBe("local_deterministic_policy");
    expect(stored.capabilities).toMatchObject({
      executionBoundary: "local_deterministic_policy",
      localDeterministicActionClassIdsByAgent: {
        ReconScout: ["active_host_discovery"],
      },
    });
    expect(MODEL_CONFIGURATION_BINDING_HASH_SCHEMA_VERSION).toBe(
      "ti-scale.model-configuration-binding-hash.v2",
    );
    expect(modelConfigurationBindingHash({
      ...stored,
      executionBoundary: "provider_tool_calling",
    })).not.toBe(modelConfigurationBindingHash(stored));
    expect(modelConfigurationBindingHash({
      ...stored,
      capabilities: {
        ...stored.capabilities,
        localDeterministicActionClassIdsByAgent: {},
      },
    })).not.toBe(modelConfigurationBindingHash(stored));
  });

  test("defaults historical immutable rows without an execution-boundary field to provider tool-calling", () => {
    const db = database();
    const repository = new ModelConfigurationRepository(
      db,
      () => new Date(NOW),
    );
    const service = new ModelConfigurationService(repository, {
      readRuntimeManifests: () => manifests(),
      clock: () => new Date(NOW),
    });
    const item = service.catalog().items[0]!;
    repository.materializeCatalogConfiguration(item);
    const row = db.prepare(`
      SELECT capabilities_json
      FROM model_configurations
      WHERE id = ?
    `).get(item.configurationId) as {
      readonly capabilities_json: string;
    };
    const historicalCapabilities = JSON.parse(
      row.capabilities_json,
    ) as Record<string, unknown>;
    delete historicalCapabilities.executionBoundary;
    db.prepare(`
      UPDATE model_configurations
      SET capabilities_json = ?
      WHERE id = ?
    `).run(JSON.stringify(historicalCapabilities), item.configurationId);

    expect(repository.getConfiguration(item.configurationId).executionBoundary)
      .toBe("provider_tool_calling");
  });

  test("rejects false local-boundary labels and every incomplete no-model route", () => {
    const cases: readonly Readonly<{
      label: string;
      manifests: RuntimeSourceManifests;
      expectedCatalogReason: string;
    }>[] = [
      {
        label: "missing exact tool",
        manifests: localDeterministicManifests({ toolPresent: false }),
        expectedCatalogReason: "No exact available Autonomous local-policy tool binding",
      },
      {
        label: "model-required tool",
        manifests: localDeterministicManifests({ requiresModel: true }),
        expectedCatalogReason: "No exact available Autonomous local-policy tool binding",
      },
      {
        label: "unavailable tool",
        manifests: localDeterministicManifests({ toolAvailable: false }),
        expectedCatalogReason: "No exact available Autonomous local-policy tool binding",
      },
      {
        label: "unenforced tool",
        manifests: localDeterministicManifests({
          locallyPolicyEnforced: false,
        }),
        expectedCatalogReason: "No exact available Autonomous local-policy tool binding",
      },
      {
        label: "Guided-only tool",
        manifests: localDeterministicManifests({
          executionJourneys: ["guided"],
        }),
        expectedCatalogReason: "No exact available Autonomous local-policy tool binding",
      },
      {
        label: "unavailable runtime agent",
        manifests: localDeterministicManifests({ agentAvailable: false }),
        expectedCatalogReason: "No exact available Autonomous local-policy tool binding",
      },
      {
        label: "failed local dependency",
        manifests: localDeterministicManifests({ dependencyReady: false }),
        expectedCatalogReason: "No exact available Autonomous local-policy tool binding",
      },
      {
        label: "unhealthy MCP inventory",
        manifests: localDeterministicManifests({ mcpStatus: "offline" }),
        expectedCatalogReason: "No exact available Autonomous local-policy tool binding",
      },
      {
        label: "expired runtime-adapter attestation",
        manifests: localDeterministicManifests({
          runtimeAdapterWindow: {
            observedAt: "2026-07-23T14:50:00.000Z",
            expiresAt: "2026-07-23T14:55:00.000Z",
          },
        }),
        expectedCatalogReason: "No exact available Autonomous local-policy tool binding",
      },
      {
        label: "future-dated runtime-adapter attestation",
        manifests: localDeterministicManifests({
          runtimeAdapterWindow: {
            observedAt: "2026-07-23T15:01:00.000Z",
            expiresAt: "2026-07-23T15:05:00.000Z",
          },
        }),
        expectedCatalogReason: "No exact available Autonomous local-policy tool binding",
      },
    ];

    for (const entry of cases) {
      const service = new ModelConfigurationService(
        new ModelConfigurationRepository(database(), () => new Date(NOW)),
        {
          readRuntimeManifests: () => entry.manifests,
          clock: () => new Date(NOW),
        },
      );
      const item = service.catalog().items[0]!;
      expect(item.executionBoundary, entry.label)
        .toBe("local_deterministic_policy");
      expect(item.capabilities.toolCalling, entry.label).toBe(false);
      expect(item.selectable, entry.label).toBe(false);
      expect(item.unavailableReasons.join(" "), entry.label)
        .toContain(entry.expectedCatalogReason);
      expect(
        () => service.resolveAutonomousAssignments({
          specialistAgentIds: ["ReconScout"],
          requiredActionClassIds: ["active_host_discovery"],
        }),
        entry.label,
      ).toThrow("No live catalog configuration is currently executable");
    }
  });

  test("rejects a local deterministic route that covers only one of multiple required agent action classes", () => {
    const service = new ModelConfigurationService(
      new ModelConfigurationRepository(database(), () => new Date(NOW)),
      {
        readRuntimeManifests: () => localDeterministicManifests({
          modelActionClassIds: [
            "active_host_discovery",
            "port_service_enumeration",
          ],
          toolActionClassIds: ["active_host_discovery"],
        }),
        clock: () => new Date(NOW),
      },
    );
    const item = service.catalog().items[0]!;
    expect(item.selectable).toBe(true);
    expect(item.capabilities.localDeterministicActionClassIdsByAgent)
      .toEqual({ ReconScout: ["active_host_discovery"] });
    expect(
      () => service.resolveAutonomousAssignments({
        specialistAgentIds: ["ReconScout"],
        requiredActionClassIds: [
          "active_host_discovery",
          "port_service_enumeration",
        ],
      }),
    ).toThrow("No live catalog configuration is currently executable");
  });

  test("keeps provider tool-calling mandatory even when a local no-model tool happens to exist", () => {
    const service = new ModelConfigurationService(
      new ModelConfigurationRepository(database(), () => new Date(NOW)),
      {
        readRuntimeManifests: () => localDeterministicManifests({
          executionBoundary: "provider_tool_calling",
        }),
        clock: () => new Date(NOW),
      },
    );
    const item = service.catalog().items[0]!;
    expect(item.executionBoundary).toBe("provider_tool_calling");
    expect(item.capabilities.localDeterministicActionClassIdsByAgent)
      .toEqual({});
    expect(
      () => service.resolveAutonomousAssignments({
        specialistAgentIds: ["ReconScout"],
        requiredActionClassIds: ["active_host_discovery"],
      }),
    ).toThrow("No live catalog configuration is currently executable");
  });

  test("keeps advisor models configurable without treating them as Autonomous executors", () => {
    const db = database();
    const baseManifests = manifests();
    const advisorManifests: RuntimeSourceManifests = {
      ...baseManifests,
      providers: baseManifests.providers.map((provider, providerIndex) => ({
        ...provider,
        models: provider.models.map((model, modelIndex) =>
          providerIndex === 0 && modelIndex === 0
            ? {
                ...model,
                toolCalling: false,
                structuredOutput: false,
                enforcement: "advisor_only" as const,
              }
            : model),
      })),
    };
    const service = new ModelConfigurationService(
      new ModelConfigurationRepository(db, () => new Date(NOW)),
      {
        readRuntimeManifests: () => advisorManifests,
        clock: () => new Date(NOW),
      },
    );
    const selected = service.catalog().items[0]!;
    expect(selected).toMatchObject({
      selectable: true,
      enforcementMode: "advisor_only",
      capabilities: {
        toolCalling: false,
        structuredOutput: false,
      },
    });
    service.putPreference({
      scopeType: "global",
      scopeId: "global",
      agentId: null,
      primaryConfigurationId: selected.configurationId,
      fallbackConfigurationId: null,
      expectedVersion: 0,
      reason: "Use the advisor for planning and critique",
    }, "operator-test");
    const resolution = service.resolve({ agentId: "ReconScout" });
    expect(() => service.assertAutonomousExecutable(resolution))
      .toThrow("cannot enforce the Autonomous mission contract");
  });

  test("projects a secret-free live catalog and persists versioned scoped preferences", async () => {
    const db = database();
    const base = await server(db);

    const catalogResponse = await fetch(`${base}/api/v2/model-catalog`);
    expect(catalogResponse.status).toBe(200);
    const catalog = await json(catalogResponse);
    expect(catalog).toMatchObject({
      schemaVersion: "2.4",
      observedAt: NOW,
    });
    expect(catalog.items).toHaveLength(3);
    expect(catalog.items.map((item: any) => item.reasoningEffort)).toEqual([
      null,
      "high",
      "low",
    ]);
    expect(catalog.items[0]).toMatchObject({
      providerId: "provider-open",
      modelId: "model-frontier",
      displayName: "Frontier Model",
      compatibleAgentIds: ["ReconScout"],
      enforcementMode: "enforced_executor",
      authState: "authenticated",
      healthState: "healthy",
      selectable: true,
    });
    expect(JSON.stringify(catalog)).not.toContain("credential");
    expect(JSON.stringify(catalog)).not.toContain("secret");
    const primaryConfigurationId = catalog.items[0].configurationId as string;
    const fallbackConfigurationId = catalog.items[1].configurationId as string;

    const createGlobal = await fetch(
      `${base}/api/v2/model-preferences/global/global`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "global-model-pref-0001",
        },
        body: JSON.stringify({
          agentId: null,
          primaryConfigurationId,
          fallbackConfigurationId,
          expectedVersion: 0,
          reason: "Operator selected the global default",
        }),
      },
    );
    expect(createGlobal.status).toBe(201);
    const created = await json(createGlobal);
    expect(created.preference).toMatchObject({
      scopeType: "global",
      scopeId: "global",
      agentId: null,
      primaryConfigurationId,
      fallbackConfigurationId,
      resolutionReason: "Operator selected the global default",
      version: 1,
    });

    const replay = await fetch(
      `${base}/api/v2/model-preferences/global/global`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "global-model-pref-0001",
        },
        body: JSON.stringify({
          agentId: null,
          primaryConfigurationId,
          fallbackConfigurationId,
          expectedVersion: 0,
          reason: "Operator selected the global default",
        }),
      },
    );
    expect(replay.status).toBe(201);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect((await json(replay)).preference.id).toBe(created.preference.id);

    const conflict = await fetch(
      `${base}/api/v2/model-preferences/global/global`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "global-model-pref-0002",
        },
        body: JSON.stringify({
          agentId: null,
          primaryConfigurationId,
          fallbackConfigurationId: null,
          expectedVersion: 0,
          reason: "Stale editor tried to replace the default",
        }),
      },
    );
    expect(conflict.status).toBe(409);
    expect(await json(conflict)).toMatchObject({
      error: {
        code: "model_preference_version_conflict",
        category: "state_conflict",
      },
    });

    const exact = await fetch(
      `${base}/api/v2/model-preferences?scopeType=global&scopeId=global`,
    );
    expect(exact.status).toBe(200);
    const exactBody = await json(exact);
    expect(exactBody.items).toHaveLength(1);
    expect(exactBody.items[0]).toMatchObject({
      resolutionReason: "Operator selected the global default",
    });

    const resolved = await fetch(
      `${base}/api/v2/model-resolution?agentId=ReconScout`,
    );
    expect(resolved.status).toBe(200);
    expect(await json(resolved)).toMatchObject({
      schemaVersion: "2.4",
      assignmentSemantics: {
        purpose: "execution",
        preferenceResolutionOrder:
          "global_then_agent_then_mission_then_run_then_step",
        saveEffect: "future_resolutions_only",
        activeRunPinning: "immutable",
        planningRoute: "autonomous_mission_contract",
      },
      availability: {
        status: "configured",
        agentId: "ReconScout",
        remediation: null,
      },
      resolution: {
        agentId: "ReconScout",
        source: {
          scopeType: "global",
          preferenceId: created.preference.id,
          preferenceVersion: 1,
        },
      },
    });

    const configurations = await fetch(
      `${base}/api/v2/model-configurations?ids=${primaryConfigurationId},${fallbackConfigurationId}`,
    );
    expect(configurations.status).toBe(200);
    expect((await json(configurations)).items).toHaveLength(2);
  });

  test("resolves step over run, mission, agent, and global then pins immutably", async () => {
    const db = database();
    const service = new ModelConfigurationService(
      new ModelConfigurationRepository(db, () => new Date(NOW)),
      { readRuntimeManifests: manifests, clock: () => new Date(NOW) },
    );
    const options = service.catalog().items;
    const [globalConfig, stepConfig] = [options[0]!, options[1]!];

    service.putPreference({
      scopeType: "global",
      scopeId: "global",
      agentId: null,
      primaryConfigurationId: globalConfig.configurationId,
      fallbackConfigurationId: null,
      expectedVersion: 0,
      reason: "Global default",
    }, "operator");
    service.putPreference({
      scopeType: "agent",
      scopeId: "ReconScout",
      agentId: "ReconScout",
      primaryConfigurationId: globalConfig.configurationId,
      fallbackConfigurationId: null,
      expectedVersion: 0,
      reason: "Agent default",
    }, "operator");
    service.putPreference({
      scopeType: "mission",
      scopeId: "mission-model",
      agentId: "ReconScout",
      primaryConfigurationId: globalConfig.configurationId,
      fallbackConfigurationId: null,
      expectedVersion: 0,
      reason: "Mission default",
    }, "operator");
    service.putPreference({
      scopeType: "run",
      scopeId: "run-model",
      agentId: "ReconScout",
      primaryConfigurationId: globalConfig.configurationId,
      fallbackConfigurationId: null,
      expectedVersion: 0,
      reason: "Run default",
    }, "operator");
    const stepV1 = service.putPreference({
      scopeType: "step",
      scopeId: "step-model",
      agentId: "ReconScout",
      primaryConfigurationId: stepConfig.configurationId,
      fallbackConfigurationId: globalConfig.configurationId,
      expectedVersion: 0,
      reason: "Step-specific deeper reasoning",
    }, "operator");

    const resolution = service.resolve({
      agentId: "ReconScout",
      missionId: "mission-model",
      runId: "run-model",
      stepId: "step-model",
    });
    expect(resolution.source).toMatchObject({
      scopeType: "step",
      scopeId: "step-model",
      preferenceId: stepV1.id,
      preferenceVersion: 1,
    });
    expect(resolution.primaryConfiguration.id).toBe(stepConfig.configurationId);

    const pinned = service.resolveAndPin({
      agentId: "ReconScout",
      missionId: "mission-model",
      runId: "run-model",
      stepId: "step-model",
    });
    expect(pinned).toMatchObject({
      pinned: true,
      inheritanceLevel: "step",
      primaryConfigurationId: stepConfig.configurationId,
    });

    service.putPreference({
      scopeType: "step",
      scopeId: "step-model",
      agentId: "ReconScout",
      primaryConfigurationId: globalConfig.configurationId,
      fallbackConfigurationId: null,
      expectedVersion: 1,
      reason: "Operator changed future step resolution",
    }, "operator");
    const pinnedAgain = service.resolveAndPin({
      agentId: "ReconScout",
      missionId: "mission-model",
      runId: "run-model",
      stepId: "step-model",
    });
    expect(pinnedAgain.id).toBe(pinned.id);
    expect(pinnedAgain.primaryConfigurationId).toBe(stepConfig.configurationId);
    expect(db.prepare(`
      SELECT version, active, is_current
      FROM model_assignment_preferences
      WHERE scope_type = 'step'
      ORDER BY version
    `).all()).toEqual([
      { version: 1, active: 0, is_current: 0 },
      { version: 2, active: 1, is_current: 1 },
    ]);
  });

  test("returns authentication errors and a clean unconfigured resolution state", async () => {
    const db = database();
    const unauthenticated = await server(db, () => undefined);
    const unauthorized = await fetch(
      `${unauthenticated}/api/v2/model-catalog`,
    );
    expect(unauthorized.status).toBe(401);
    expect(await json(unauthorized)).toMatchObject({
      error: {
        code: "model_configuration_authentication_required",
        category: "policy_denied",
      },
    });

    const authenticated = await server(db);
    const unresolved = await fetch(
      `${authenticated}/api/v2/model-resolution?agentId=ReconScout`,
    );
    expect(unresolved.status).toBe(200);
    expect(await json(unresolved)).toMatchObject({
      schemaVersion: "2.4",
      assignmentSemantics: {
        purpose: "execution",
        activeRunPinning: "immutable",
        planningRoute: "autonomous_mission_contract",
      },
      resolution: null,
      availability: {
        status: "unconfigured",
        agentId: "ReconScout",
        humanMessage:
          "This agent does not have a model assignment for the requested scope.",
        remediation:
          "Choose a compatible provider and model on the agent profile, or configure a global default.",
      },
    });
  });

  test("pins launch-time specialist models transactionally and never rewrites an existing run", () => {
    const db = database();
    const modelConfigurations = new ModelConfigurationService(
      new ModelConfigurationRepository(db, () => new Date(NOW)),
      { readRuntimeManifests: manifests, clock: () => new Date(NOW) },
    );
    const [globalConfig, initialAgentConfig, futureAgentConfig] =
      modelConfigurations.catalog().items;
    if (!globalConfig || !initialAgentConfig || !futureAgentConfig) {
      throw new Error("Catalog fixture is incomplete");
    }
    modelConfigurations.putPreference({
      scopeType: "global",
      scopeId: "global",
      agentId: null,
      primaryConfigurationId: globalConfig.configurationId,
      fallbackConfigurationId: null,
      expectedVersion: 0,
      reason: "Initial global specialist model",
    }, "operator");
    modelConfigurations.putPreference({
      scopeType: "agent",
      scopeId: "ReconScout",
      agentId: "ReconScout",
      primaryConfigurationId: initialAgentConfig.configurationId,
      fallbackConfigurationId: globalConfig.configurationId,
      expectedVersion: 0,
      reason: "ReconScout-specific model and fallback",
    }, "operator");

    const request: AutonomousMissionRequest = {
      journey: "autonomous",
      launch: true,
      title: "Pinned model mission",
      objective: "Assess the authorized disposable lab",
      successCriteria: ["Create an evidence-backed service inventory"],
      authorization: {
        allowedTargets: ["lab.internal"],
        prohibitedTargets: [],
        authorizationConfirmed: true,
      },
      contract: {
        allowedActionClasses: ["active_host_discovery"],
        prohibitedActionClasses: [],
        destructivePolicy: "prohibited",
        evidenceRequirements: [],
        timeBudgetMinutes: 30,
        retryBudget: 1,
        replanBudget: 1,
        concurrencyLimit: 1,
        evidenceStorageBudgetBytes: 1024,
        artifactStorageBudgetBytes: 1024,
        notificationPolicy: "in_app_only",
        reportingFormat: "ti_scale_json",
        dataHandlingPolicy: "local_private",
        retentionPolicy: "operator_managed",
        providerPolicy: "automatic_enforcing_only",
        toolPolicy: "contract_allowlist",
        specialistAgentIds: ["ReconScout"],
        agentModelAssignments: [{
          agentId: "ReconScout",
          primaryConfigurationId: initialAgentConfig.configurationId,
          fallbackConfigurationId: globalConfig.configurationId,
        }],
        memoryScopes: [],
        contextNodeIds: [],
        safeStopConditions: [],
        deliverables: [],
      },
    };
    const missions = new MissionRepository(db, () => new Date(NOW));
    const create = (idempotencyKey: string) => missions.create({
      request,
      requestHash: idempotencyKey.padEnd(64, "0"),
      idempotencyKey,
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

    const first = create("model-mission-create-0001");
    expect(db.prepare(`
      SELECT agent_id, mission_id, run_id, primary_configuration_id, pinned
      FROM agent_model_assignments WHERE run_id = ?
    `).all(first.run.id)).toEqual([{
      agent_id: "ReconScout",
      mission_id: first.mission.id,
      run_id: first.run.id,
      primary_configuration_id: initialAgentConfig.configurationId,
      pinned: 1,
    }]);

    modelConfigurations.putPreference({
      scopeType: "agent",
      scopeId: "ReconScout",
      agentId: "ReconScout",
      primaryConfigurationId: futureAgentConfig.configurationId,
      fallbackConfigurationId: globalConfig.configurationId,
      expectedVersion: 1,
      reason: "New ReconScout default for future runs",
    }, "operator");
    expect(db.prepare(`
      SELECT primary_configuration_id
      FROM agent_model_assignments WHERE run_id = ?
    `).get(first.run.id)).toEqual({
      primary_configuration_id: initialAgentConfig.configurationId,
    });

    const second = create("model-mission-create-0002");
    expect(db.prepare(`
      SELECT primary_configuration_id
      FROM agent_model_assignments WHERE run_id = ?
    `).get(second.run.id)).toEqual({
      primary_configuration_id: initialAgentConfig.configurationId,
    });
  });

  test("materializes partial overrides deterministically and returns readable live-catalog receipts", () => {
    const db = database();
    const service = new ModelConfigurationService(
      new ModelConfigurationRepository(db, () => new Date(NOW)),
      { readRuntimeManifests: manifests, clock: () => new Date(NOW) },
    );
    const catalog = service.catalog();
    const explicit = catalog.items.find(({ reasoningEffort }) =>
      reasoningEffort === "high");
    if (!explicit) throw new Error("High-reasoning fixture configuration is missing");

    const resolved = service.resolveAutonomousAssignments({
      specialistAgentIds: ["ReconScout"],
      overrides: [{
        agentId: "ReconScout",
        primaryConfigurationId: explicit.configurationId,
        fallbackConfigurationId: null,
      }],
      requiredActionClassIds: ["active_host_discovery"],
    });

    expect(resolved.observedAt).toBe(NOW);
    expect(resolved.selections).toEqual([{
      agentId: "ReconScout",
      primaryConfigurationId: explicit.configurationId,
      fallbackConfigurationId: null,
      source: "operator_override",
    }]);
    expect(resolved.receipts).toEqual([{
      agentId: "ReconScout",
      source: "operator_override",
      ready: true,
      reasons: [],
      primary: {
        configurationId: explicit.configurationId,
        providerId: "provider-open",
        modelId: "model-frontier",
        displayName: "Frontier Model",
        executionBoundary: "provider_tool_calling",
        reasoningEffort: "high",
        enforcementMode: "enforced_executor",
        authState: "authenticated",
        healthState: "healthy",
        disclosureClass: "public_only",
        costClass: "unknown",
        latencyClass: "unknown",
        contextLimit: 128_000,
        catalogSource: "runtime-source-manifest",
        catalogRetrievedAt: NOW,
      },
      fallback: null,
    }]);
  });

  test("renews freshness with a new immutable catalog snapshot while retaining the stale snapshot", () => {
    const db = database();
    const refreshedAt = "2026-07-23T15:16:00.000Z";
    let currentNow = new Date(NOW);
    let currentManifests = manifests();
    const repository = new ModelConfigurationRepository(db, () => currentNow);
    const service = new ModelConfigurationService(repository, {
      readRuntimeManifests: () => currentManifests,
      clock: () => currentNow,
    });
    const initial = service.catalog().items.find(
      ({ reasoningEffort }) => reasoningEffort === "high",
    );
    if (!initial) throw new Error("Initial high-reasoning fixture is missing");
    const initialStored = repository.materializeCatalogConfiguration(initial);

    currentNow = new Date(refreshedAt);
    currentManifests = {
      ...currentManifests,
      providers: currentManifests.providers.map((provider) => ({
        ...provider,
        catalogObservedAt: refreshedAt,
      })),
    };
    const refreshed = service.catalog().items.find(
      ({ reasoningEffort }) => reasoningEffort === "high",
    );
    if (!refreshed) throw new Error("Refreshed high-reasoning fixture is missing");
    const refreshedStored = repository.materializeCatalogConfiguration(refreshed);

    expect(refreshed.configurationId).not.toBe(initial.configurationId);
    expect(initialStored).toMatchObject({
      id: initial.configurationId,
      catalogRetrievedAt: NOW,
      version: 1,
    });
    expect(refreshedStored).toMatchObject({
      id: refreshed.configurationId,
      catalogRetrievedAt: refreshedAt,
      version: 2,
    });
    expect(repository.getConfiguration(initial.configurationId)).toEqual(
      initialStored,
    );
    expect(modelConfigurationBindingHash(refreshedStored)).not.toBe(
      modelConfigurationBindingHash(initialStored),
    );
    expect(repository.listConfigurations()).toHaveLength(2);

    db.prepare(`
      UPDATE missions SET journey = 'guided' WHERE id = 'mission-model'
    `).run();
    db.prepare(`
      UPDATE runs SET journey = 'guided' WHERE id = 'run-model'
    `).run();
    db.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, created_at, updated_at
      ) VALUES (
        'run-model-stale-snapshot', 'mission-model', 'guided', 'queued', ?, ?
      )
    `).run(refreshedAt, refreshedAt);
    repository.createExactPinnedAssignment({
      agentId: "ReconScout",
      missionId: "mission-model",
      runId: "run-model-stale-snapshot",
      primaryConfigurationId: initial.configurationId,
      fallbackConfigurationId: null,
      inheritanceLevel: "run",
    });
    repository.createExactPinnedAssignment({
      agentId: "ReconScout",
      missionId: "mission-model",
      runId: "run-model",
      primaryConfigurationId: refreshed.configurationId,
      fallbackConfigurationId: null,
      inheritanceLevel: "run",
    });
    const runtimeBindings = new AgentRuntimeBindingService(
      db,
      repository,
      { clock: () => currentNow },
    );

    expect(() => runtimeBindings.resolveRun({
      missionId: "mission-model",
      runId: "run-model-stale-snapshot",
      agentId: "ReconScout",
    })).toThrow(AgentRuntimeBindingError);
    try {
      runtimeBindings.resolveRun({
        missionId: "mission-model",
        runId: "run-model-stale-snapshot",
        agentId: "ReconScout",
      });
      throw new Error("Expected the original catalog snapshot to remain stale");
    } catch (error) {
      expect(error).toMatchObject({
        code: "agent_runtime_binding_model_configuration_unavailable",
      });
    }
    expect(runtimeBindings.resolveRun({
      missionId: "mission-model",
      runId: "run-model",
      agentId: "ReconScout",
    })).toMatchObject({
      primaryConfigurationId: refreshed.configurationId,
      primaryConfiguration: {
        catalogRetrievedAt: refreshedAt,
      },
    });
  });

  test("fails closed with a specific drift error when a reviewed configuration disappears before materialization", () => {
    const db = database();
    let currentManifests = manifests();
    const service = new ModelConfigurationService(
      new ModelConfigurationRepository(db, () => new Date(NOW)),
      {
        readRuntimeManifests: () => currentManifests,
        clock: () => new Date(NOW),
      },
    );
    const reviewed = service.resolveAutonomousAssignments({
      specialistAgentIds: ["ReconScout"],
      requiredActionClassIds: ["active_host_discovery"],
    }).selections;
    currentManifests = { ...currentManifests, providers: [] };

    try {
      service.validateAutonomousAssignments({
        assignments: reviewed,
        specialistAgentIds: ["ReconScout"],
        requiredActionClassIds: ["active_host_discovery"],
      });
      throw new Error("Expected reviewed catalog drift to fail closed");
    } catch (error) {
      expect(error).toMatchObject({
        code: "model_catalog_configuration_drift",
        category: "not_found",
        retryable: false,
      });
    }
    expect(db.prepare("SELECT COUNT(*) AS count FROM model_configurations").get())
      .toEqual({ count: 0 });
  });

  test("rolls back a mission aggregate when exact model pinning cannot complete", () => {
    const db = database();
    const service = new ModelConfigurationService(
      new ModelConfigurationRepository(db, () => new Date(NOW)),
      { readRuntimeManifests: manifests, clock: () => new Date(NOW) },
    );
    const repository = new MissionRepository(db, () => new Date(NOW));
    const selection = service.resolveAutonomousAssignments({
      specialistAgentIds: ["ReconScout"],
      requiredActionClassIds: ["active_host_discovery"],
    }).selections[0]!;
    const before = {
      missions: db.prepare("SELECT COUNT(*) AS count FROM missions").get(),
      runs: db.prepare("SELECT COUNT(*) AS count FROM runs").get(),
      assignments: db.prepare(
        "SELECT COUNT(*) AS count FROM agent_model_assignments",
      ).get(),
    };
    let currentManifests = manifests();
    const drifting = new ModelConfigurationService(
      new ModelConfigurationRepository(db, () => new Date(NOW)),
      {
        readRuntimeManifests: () => currentManifests,
        clock: () => new Date(NOW),
      },
    );
    currentManifests = { ...currentManifests, providers: [] };

    expect(() => repository.create({
      request: {
        journey: "autonomous",
        launch: true,
        title: "Atomic exact model pin",
        objective: "Prove mission creation rolls back when its reviewed model disappears",
        successCriteria: ["No partial mission state remains"],
        authorization: {
          allowedTargets: ["lab.internal"],
          prohibitedTargets: [],
          authorizationConfirmed: true,
        },
        contract: {
          allowedActionClasses: ["active_host_discovery"],
          prohibitedActionClasses: [],
          destructivePolicy: "prohibited",
          evidenceRequirements: [],
          timeBudgetMinutes: 30,
          retryBudget: 1,
          replanBudget: 1,
          concurrencyLimit: 1,
          evidenceStorageBudgetBytes: 1024,
          artifactStorageBudgetBytes: 1024,
          notificationPolicy: "in_app_only",
          reportingFormat: "ti_scale_json",
          dataHandlingPolicy: "local_private",
          retentionPolicy: "operator_managed",
          providerPolicy: "automatic_enforcing_only",
          toolPolicy: "contract_allowlist",
          specialistAgentIds: ["ReconScout"],
          agentModelAssignments: [selection],
          memoryScopes: [],
          contextNodeIds: [],
          safeStopConditions: [],
          deliverables: [],
        },
      },
      requestHash: "f".repeat(64),
      idempotencyKey: "atomic-exact-pin-failure-0001",
      actorId: "operator",
      pinModelAssignments: ({
        missionId,
        runId,
        specialistAgentIds,
        agentModelAssignments,
        allowedActionClasses,
      }) => drifting.pinExactAutonomousAssignments({
        missionId,
        runId,
        specialistAgentIds,
        assignments: agentModelAssignments,
        requiredActionClassIds: allowedActionClasses,
      }).map(({ id }) => id),
    })).toThrow("absent from both the live catalog");
    expect({
      missions: db.prepare("SELECT COUNT(*) AS count FROM missions").get(),
      runs: db.prepare("SELECT COUNT(*) AS count FROM runs").get(),
      assignments: db.prepare(
        "SELECT COUNT(*) AS count FROM agent_model_assignments",
      ).get(),
    }).toEqual(before);
  });
});

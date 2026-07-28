import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import type { RuntimeSourceManifests } from "../../domain";
import type { GuidedCommanderPort } from "../../guided-commander";
import {
  ModelConfigurationRepository,
  ModelConfigurationService,
  type ModelCatalogItem,
  type StoredModelConfiguration,
} from "../../model-config";
import {
  AgentRuntimeBindingError,
  AgentRuntimeBindingService,
  GuidedAgentRuntimeResolver,
  type GuidedPlanningPortFactory,
} from "../index";

const NOW = "2026-07-23T18:00:00.000Z";
const MISSION_ID = "mission-guided-runtime";
const RUN_ID = "run-guided-runtime";
const PLAN_ID = "plan-guided-runtime";
const STEP_ID = "step-guided-runtime";

function manifests(): RuntimeSourceManifests {
  return {
    riskClasses: [],
    evidenceKinds: [],
    capabilities: [],
    tools: [],
    mcpServers: [],
    agents: [{
      id: "runtime:guided-recon",
      label: "Internal Guided reconnaissance adapter",
      available: true,
      capabilityIds: [],
      actionClassIds: ["port_service_enumeration"],
      toolIds: [],
      modelRefs: [{
        providerId: "provider-guided",
        modelId: "model-primary",
      }, {
        providerId: "provider-guided",
        modelId: "model-fallback",
      }],
    }],
    providers: [{
      id: "provider-guided",
      authenticated: true,
      healthy: true,
      catalogObservedAt: NOW,
      models: [{
        id: "model-primary",
        displayName: "Primary Guided Model",
        toolCalling: false,
        structuredOutput: true,
        enforcement: "advisor_only",
        compatibleActionClassIds: ["port_service_enumeration"],
        disclosureClasses: ["sanitized_internal"],
        contextLimit: 64_000,
        reasoningEfforts: [],
      }, {
        id: "model-fallback",
        displayName: "Fallback Guided Model",
        toolCalling: false,
        structuredOutput: true,
        enforcement: "advisor_only",
        compatibleActionClassIds: ["port_service_enumeration"],
        disclosureClasses: ["sanitized_internal"],
        contextLimit: 32_000,
        reasoningEfforts: [],
      }],
    }],
  };
}

function exactPlanningPort(
  configuration: Pick<StoredModelConfiguration, "providerId" | "modelId">,
): GuidedCommanderPort {
  return Object.freeze({
    kind: "planning_only",
    supportsToolExecution: false,
    providerId: configuration.providerId,
    model: configuration.modelId,
    async respond() {
      return {
        body: "Bound Guided response",
        summary: "Bound Guided response",
        confidence: 1,
      };
    },
  });
}

class RecordingPlanningPortFactory implements GuidedPlanningPortFactory {
  readonly configurationIds: string[] = [];

  constructor(
    private readonly createPort: (
      configuration: StoredModelConfiguration,
      callNumber: number,
    ) => GuidedCommanderPort | undefined,
  ) {}

  create(configuration: StoredModelConfiguration): GuidedCommanderPort | undefined {
    this.configurationIds.push(configuration.id);
    return this.createPort(configuration, this.configurationIds.length);
  }
}

describe("GuidedAgentRuntimeResolver", () => {
  let database: SqliteDatabase;
  let repository: ModelConfigurationRepository;
  let modelConfigurations: ModelConfigurationService;
  let bindings: AgentRuntimeBindingService;
  let primary: ModelCatalogItem;
  let fallback: ModelCatalogItem;

  beforeEach(() => {
    database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const insertAgent = database.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, version, created_at, updated_at
      ) VALUES (?, ?, ?, 'available', 'test-v1', ?, ?)
    `);
    insertAgent.run(
      "ReconScout",
      "reconnaissance",
      "ReconScout",
      NOW,
      NOW,
    );
    insertAgent.run(
      "runtime:guided-recon",
      "runtime adapter",
      "Internal Guided reconnaissance adapter",
      NOW,
      NOW,
    );
    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, created_by, created_at, updated_at
      ) VALUES (?, 'Guided runtime mission', 'Assess the authorized lab',
        'guided', 'operator', ?, ?)
    `).run(MISSION_ID, NOW, NOW);
    database.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, created_at, updated_at
      ) VALUES (?, ?, 'guided', 'waiting_guided_decision', ?, ?)
    `).run(RUN_ID, MISSION_ID, NOW, NOW);
    database.prepare(`
      INSERT INTO plans (
        id, run_id, version, status, strategy_summary, plan_hash,
        content_hash, content_hash_version, created_by, created_at
      ) VALUES (?, ?, 1, 'active', 'Guided runtime plan', ?, ?, 1,
        'operator', ?)
    `).run(PLAN_ID, RUN_ID, "a".repeat(64), "b".repeat(64), NOW);
    database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        action_class, assigned_agent_id, created_at, updated_at
      ) VALUES (?, ?, ?, 0, 'reconnaissance', 'Map services',
        'Map approved services', 'waiting_guided_decision',
        'port_service_enumeration', 'ReconScout', ?, ?)
    `).run(STEP_ID, PLAN_ID, RUN_ID, NOW, NOW);

    repository = new ModelConfigurationRepository(
      database,
      () => new Date(NOW),
    );
    modelConfigurations = new ModelConfigurationService(repository, {
      readRuntimeManifests: manifests,
      clock: () => new Date(NOW),
    });
    bindings = new AgentRuntimeBindingService(database, repository, {
      clock: () => new Date(NOW),
    });
    const catalog = modelConfigurations.catalog().items;
    const primaryItem = catalog.find(({ modelId }) => modelId === "model-primary");
    const fallbackItem = catalog.find(({ modelId }) => modelId === "model-fallback");
    if (!primaryItem || !fallbackItem) {
      throw new Error("Guided model catalog fixture is incomplete");
    }
    primary = primaryItem;
    fallback = fallbackItem;
    modelConfigurations.putPreference({
      scopeType: "agent",
      scopeId: "ReconScout",
      agentId: "ReconScout",
      primaryConfigurationId: primary.configurationId,
      fallbackConfigurationId: fallback.configurationId,
      expectedVersion: 0,
      reason: "Guided runtime test preference",
    }, "operator");
  });

  afterEach(() => database.close());

  function scope(overrides: Readonly<{
    assignedAgentId?: string | null;
    actionClassId?: string | null;
  }> = {}) {
    return {
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: STEP_ID,
      assignedAgentId: overrides.assignedAgentId === undefined
        ? "ReconScout"
        : overrides.assignedAgentId,
      actionClassId: overrides.actionClassId === undefined
        ? "port_service_enumeration"
        : overrides.actionClassId,
    };
  }

  function pinRun(): string {
    return modelConfigurations.resolveAndPin({
      agentId: "ReconScout",
      missionId: MISSION_ID,
      runId: RUN_ID,
      resolutionReason: "Pinned at Guided run creation",
    }).id;
  }

  function resolver(factory: GuidedPlanningPortFactory): GuidedAgentRuntimeResolver {
    return new GuidedAgentRuntimeResolver({
      bindings,
      modelConfigurations,
      planningPorts: factory,
    });
  }

  function expectBindingError(
    operation: () => unknown,
    code: AgentRuntimeBindingError["code"],
  ): AgentRuntimeBindingError {
    try {
      operation();
    } catch (error) {
      expect(error).toBeInstanceOf(AgentRuntimeBindingError);
      expect((error as AgentRuntimeBindingError).code).toBe(code);
      return error as AgentRuntimeBindingError;
    }
    throw new Error(`Expected AgentRuntimeBindingError ${code}`);
  }

  test("consumes an existing run pin without creating a step assignment", () => {
    const runAssignmentId = pinRun();
    const factory = new RecordingPlanningPortFactory((configuration) =>
      exactPlanningPort(configuration));

    const resolved = resolver(factory).resolve(scope());

    expect(resolved).toMatchObject({
      productAgentId: "ReconScout",
      modelAssignmentId: runAssignmentId,
      modelConfigurationId: primary.configurationId,
      usedFallback: false,
    });
    expect(database.prepare(`
      SELECT id, step_id
      FROM agent_model_assignments
      ORDER BY created_at, id
    `).all()).toEqual([{
      id: runAssignmentId,
      step_id: null,
    }]);
  });

  test("creates a missing historical step pin exactly once before selecting a port", () => {
    const pinnedCountsObservedByFactory: number[] = [];
    const factory = new RecordingPlanningPortFactory((configuration) => {
      const row = database.prepare(`
        SELECT count(*) AS count
        FROM agent_model_assignments
        WHERE agent_id = 'ReconScout'
          AND mission_id = ?
          AND run_id = ?
          AND step_id = ?
          AND pinned = 1
      `).get(MISSION_ID, RUN_ID, STEP_ID) as { readonly count: number };
      pinnedCountsObservedByFactory.push(row.count);
      return exactPlanningPort(configuration);
    });
    const guidedResolver = resolver(factory);

    const first = guidedResolver.resolve(scope());
    const second = guidedResolver.resolve(scope());

    expect(first.modelAssignmentId).toBe(second.modelAssignmentId);
    expect(first.modelConfigurationId).toBe(primary.configurationId);
    expect(pinnedCountsObservedByFactory).toEqual([1, 1]);
    expect(database.prepare(`
      SELECT count(*) AS count
      FROM agent_model_assignments
      WHERE step_id = ? AND pinned = 1
    `).get(STEP_ID)).toEqual({ count: 1 });
  });

  test("uses the exact primary planning port without probing the fallback", () => {
    pinRun();
    const factory = new RecordingPlanningPortFactory((configuration) =>
      exactPlanningPort(configuration));

    const resolved = resolver(factory).resolve(scope());

    expect(resolved.usedFallback).toBeFalse();
    expect(resolved.modelConfigurationId).toBe(primary.configurationId);
    expect(factory.configurationIds).toEqual([primary.configurationId]);
    expect(resolved.port.providerId).toBe(primary.providerId);
    expect(resolved.port.model).toBe(primary.modelId);
  });

  test("uses the fallback only when no primary adapter is mounted", () => {
    pinRun();
    const factory = new RecordingPlanningPortFactory((configuration) =>
      configuration.id === fallback.configurationId
        ? exactPlanningPort(configuration)
        : undefined);

    const resolved = resolver(factory).resolve(scope());

    expect(resolved.usedFallback).toBeTrue();
    expect(resolved.modelConfigurationId).toBe(fallback.configurationId);
    expect(factory.configurationIds).toEqual([
      primary.configurationId,
      fallback.configurationId,
    ]);
    expect(resolved.port.providerId).toBe(fallback.providerId);
    expect(resolved.port.model).toBe(fallback.modelId);
  });

  test("fails closed when neither pinned configuration has an operational port", () => {
    pinRun();
    const factory = new RecordingPlanningPortFactory(() => undefined);

    expectBindingError(
      () => resolver(factory).resolve(scope()),
      "agent_runtime_binding_model_configuration_unavailable",
    );
    expect(factory.configurationIds).toEqual([
      primary.configurationId,
      fallback.configurationId,
    ]);
  });

  test("maps an internally assigned adapter to the product agent through its action class", () => {
    database.prepare(`
      UPDATE plan_steps
      SET assigned_agent_id = 'runtime:guided-recon'
      WHERE id = ?
    `).run(STEP_ID);
    pinRun();
    const factory = new RecordingPlanningPortFactory((configuration) =>
      exactPlanningPort(configuration));

    const resolved = resolver(factory).resolve(scope({
      assignedAgentId: "runtime:guided-recon",
    }));

    expect(resolved.productAgentId).toBe("ReconScout");
    expect(resolved.modelConfigurationId).toBe(primary.configurationId);
  });

  test.each([
    ["provider", "provider-wrong", "model-primary"],
    ["model", "provider-guided", "model-wrong"],
  ])("rejects a planning port whose %s does not match the pinned configuration", (
    _field,
    providerId,
    model,
  ) => {
    pinRun();
    const factory = new RecordingPlanningPortFactory(() =>
      exactPlanningPort({ providerId, modelId: model }));

    expectBindingError(
      () => resolver(factory).resolve(scope()),
      "agent_runtime_binding_model_configuration_incompatible",
    );
    expect(factory.configurationIds).toEqual([primary.configurationId]);
  });
});

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import type { RuntimeSourceManifests } from "../../domain";
import {
  AUTONOMOUS_LOCAL_PLANNING_SELECTION,
  ModelConfigurationError,
  ModelConfigurationRepository,
  ModelConfigurationService,
} from "../index";

const NOW = "2026-07-28T13:00:00.000Z";
const MISSION_ID = "mission-autonomous-planning-selection";
const RUN_ID = "run-autonomous-planning-selection";

function manifests(): RuntimeSourceManifests {
  return {
    riskClasses: [],
    evidenceKinds: [],
    capabilities: [],
    tools: [],
    mcpServers: [],
    agents: [{
      id: "ReconScout",
      label: "ReconScout",
      available: true,
      capabilityIds: [],
      actionClassIds: [],
      toolIds: [],
      modelRefs: [
        { providerId: "provider-planning", modelId: "advisor-primary" },
        { providerId: "provider-planning", modelId: "advisor-fallback" },
        { providerId: "provider-planning", modelId: "executor" },
      ],
    }],
    providers: [{
      id: "provider-planning",
      authenticated: true,
      healthy: true,
      catalogObservedAt: NOW,
      models: [
        {
          id: "advisor-primary",
          displayName: "Planning advisor primary",
          toolCalling: false,
          structuredOutput: true,
          enforcement: "advisor_only",
          compatibleActionClassIds: [],
          disclosureClasses: ["sanitized_internal"],
        },
        {
          id: "advisor-fallback",
          displayName: "Planning advisor fallback",
          toolCalling: false,
          structuredOutput: true,
          enforcement: "advisor_only",
          compatibleActionClassIds: [],
          disclosureClasses: ["sanitized_internal"],
        },
        {
          id: "executor",
          displayName: "Execution model",
          toolCalling: true,
          structuredOutput: true,
          enforcement: "enforced_executor",
          compatibleActionClassIds: [],
          disclosureClasses: ["public"],
        },
      ],
    }],
  };
}

describe("Autonomous provider-advisory planning selection", () => {
  let database: SqliteDatabase;
  let service: ModelConfigurationService;

  beforeEach(() => {
    database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    database.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, version, created_at, updated_at
      ) VALUES ('ReconScout', 'planning', 'ReconScout', 'available', '1.0.0', ?, ?)
    `).run(NOW, NOW);
    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, created_by, created_at, updated_at
      ) VALUES (
        ?, 'Planning selection mission', 'Build an authorized bounded plan',
        'autonomous', 'operator', ?, ?
      )
    `).run(MISSION_ID, NOW, NOW);
    database.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, created_at, updated_at
      ) VALUES (?, ?, 'autonomous', 'planning', ?, ?)
    `).run(RUN_ID, MISSION_ID, NOW, NOW);
    service = new ModelConfigurationService(
      new ModelConfigurationRepository(database, () => new Date(NOW)),
      {
        readRuntimeManifests: manifests,
        clock: () => new Date(NOW),
      },
    );
  });

  afterEach(() => database.close());

  test("pins advisor-only primary and fallback as planning without changing execution authority", () => {
    const catalog = service.catalog().items;
    const primary = catalog.find(({ modelId, reasoningEffort }) =>
      modelId === "advisor-primary" && reasoningEffort === null)!;
    const fallback = catalog.find(({ modelId, reasoningEffort }) =>
      modelId === "advisor-fallback" && reasoningEffort === null)!;
    const executor = catalog.find(({ modelId, reasoningEffort }) =>
      modelId === "executor" && reasoningEffort === null)!;
    const selection = {
      route: "provider_advisory" as const,
      agentId: "ReconScout",
      primaryConfigurationId: primary.configurationId,
      fallbackConfigurationId: fallback.configurationId,
      enforcementMode: "advisor_only" as const,
      disclosureClass: "sanitized_internal" as const,
      executionAuthority: "none" as const,
    };

    expect(service.validateAutonomousPlanningSelection(selection))
      .toMatchObject({
        agentId: "ReconScout",
        ready: true,
        primary: { enforcementMode: "advisor_only" },
        fallback: { enforcementMode: "advisor_only" },
      });
    const planning = service.pinExactAutonomousPlanningSelection({
      selection,
      missionId: MISSION_ID,
      runId: RUN_ID,
    });
    const execution = service.pinExactAutonomousAssignments({
      assignments: [{
        agentId: "ReconScout",
        primaryConfigurationId: executor.configurationId,
        fallbackConfigurationId: null,
      }],
      specialistAgentIds: ["ReconScout"],
      requiredActionClassIds: [],
      missionId: MISSION_ID,
      runId: RUN_ID,
    })[0]!;

    expect(planning).toMatchObject({
      purpose: "planning",
      primaryConfigurationId: primary.configurationId,
      fallbackConfigurationId: fallback.configurationId,
    });
    expect(execution).toMatchObject({
      purpose: "execution",
      primaryConfigurationId: executor.configurationId,
    });
    expect(database.prepare(`
      SELECT assignment_purpose, primary_configuration_id
      FROM agent_model_assignments
      WHERE run_id = ?
      ORDER BY assignment_purpose
    `).all(RUN_ID)).toEqual([
      {
        assignment_purpose: "execution",
        primary_configuration_id: executor.configurationId,
      },
      {
        assignment_purpose: "planning",
        primary_configuration_id: primary.configurationId,
      },
    ]);
  });

  test("never relabels an enforced executor as an advisory planner", () => {
    const executor = service.catalog().items.find(
      ({ modelId, reasoningEffort }) =>
        modelId === "executor" && reasoningEffort === null,
    )!;
    const selection = {
      route: "provider_advisory" as const,
      agentId: "ReconScout",
      primaryConfigurationId: executor.configurationId,
      fallbackConfigurationId: null,
      enforcementMode: "advisor_only" as const,
      disclosureClass: "public_only" as const,
      executionAuthority: "none" as const,
    };
    expect(service.validateAutonomousPlanningSelection(selection))
      .toMatchObject({
        ready: false,
        primary: { enforcementMode: "enforced_executor" },
      });
    expect(() => service.pinExactAutonomousPlanningSelection({
      selection,
      missionId: MISSION_ID,
      runId: RUN_ID,
    })).toThrow(ModelConfigurationError);
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM agent_model_assignments
      WHERE assignment_purpose = 'planning'
    `).get()).toEqual({ count: 0 });
  });

  test("keeps local deterministic planning model-free", () => {
    expect(service.validateAutonomousPlanningSelection(
      AUTONOMOUS_LOCAL_PLANNING_SELECTION,
    )).toBeNull();
    expect(service.pinExactAutonomousPlanningSelection({
      selection: AUTONOMOUS_LOCAL_PLANNING_SELECTION,
      missionId: MISSION_ID,
      runId: RUN_ID,
    })).toBeNull();
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM agent_model_assignments
    `).get()).toEqual({ count: 0 });
  });
});

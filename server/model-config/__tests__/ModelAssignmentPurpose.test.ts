import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import {
  ModelConfigurationError,
  ModelConfigurationRepository,
} from "../index";

const NOW = "2026-07-28T12:30:00.000Z";
const MISSION_ID = "mission-model-assignment-purpose";
const RUN_ID = "run-model-assignment-purpose";

describe("ModelConfigurationRepository assignment purpose", () => {
  let database: SqliteDatabase;
  let repository: ModelConfigurationRepository;

  beforeEach(() => {
    database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    database.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, version, created_at, updated_at
      ) VALUES (
        'ReconScout', 'reconnaissance', 'ReconScout', 'available',
        '1.0.0', ?, ?
      )
    `).run(NOW, NOW);
    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, created_by, created_at, updated_at
      ) VALUES (
        ?, 'Assignment purpose mission', 'Assess the authorized lab',
        'autonomous', 'operator', ?, ?
      )
    `).run(MISSION_ID, NOW, NOW);
    database.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, created_at, updated_at
      ) VALUES (?, ?, 'autonomous', 'queued', ?, ?)
    `).run(RUN_ID, MISSION_ID, NOW, NOW);
    for (const [id, modelId] of [
      ["configuration-execution", "execution-model"],
      ["configuration-planning", "planning-model"],
      ["configuration-planning-alternative", "planning-model-alternative"],
    ] as const) {
      database.prepare(`
        INSERT INTO model_configurations (
          id, provider_id, model_id, context_policy_json, capabilities_json,
          context_limit, cost_class, latency_class, disclosure_class,
          enforcement_mode, auth_state, health_state, catalog_source,
          catalog_retrieved_at, configuration_source, created_at, updated_at,
          version
        ) VALUES (
          ?, 'test-provider', ?, '{}', ?, 32768, 'standard', 'standard',
          'local_only', 'enforced', 'healthy', 'healthy', 'test-catalog',
          ?, 'manual', ?, ?, 1
        )
      `).run(
        id,
        modelId,
        JSON.stringify({ displayName: modelId }),
        NOW,
        NOW,
        NOW,
      );
    }
    repository = new ModelConfigurationRepository(
      database,
      () => new Date(NOW),
    );
  });

  afterEach(() => database.close());

  test("keeps default execution and explicit planning pins independent", () => {
    const execution = repository.createExactPinnedAssignment({
      agentId: "ReconScout",
      missionId: MISSION_ID,
      runId: RUN_ID,
      primaryConfigurationId: "configuration-execution",
      fallbackConfigurationId: null,
      inheritanceLevel: "run",
    });
    const planning = repository.createExactPinnedAssignment({
      agentId: "ReconScout",
      missionId: MISSION_ID,
      runId: RUN_ID,
      purpose: "planning",
      primaryConfigurationId: "configuration-planning",
      fallbackConfigurationId: null,
      inheritanceLevel: "run",
    });

    expect(execution).toMatchObject({
      purpose: "execution",
      primaryConfigurationId: "configuration-execution",
    });
    expect(planning).toMatchObject({
      purpose: "planning",
      primaryConfigurationId: "configuration-planning",
    });
    expect(repository.findPinnedAssignment({
      agentId: "ReconScout",
      missionId: MISSION_ID,
      runId: RUN_ID,
    })?.id).toBe(execution.id);
    expect(repository.findPinnedAssignment({
      agentId: "ReconScout",
      missionId: MISSION_ID,
      runId: RUN_ID,
      purpose: "planning",
    })?.id).toBe(planning.id);

    try {
      repository.createExactPinnedAssignment({
        agentId: "ReconScout",
        missionId: MISSION_ID,
        runId: RUN_ID,
        purpose: "planning",
        primaryConfigurationId: "configuration-planning-alternative",
        fallbackConfigurationId: null,
        inheritanceLevel: "run",
      });
      throw new Error("Expected a purpose-local immutable assignment conflict");
    } catch (error) {
      expect(error).toBeInstanceOf(ModelConfigurationError);
      expect((error as ModelConfigurationError).code).toBe(
        "model_assignment_pin_conflict",
      );
    }

    expect(repository.findPinnedAssignment({
      agentId: "ReconScout",
      missionId: MISSION_ID,
      runId: RUN_ID,
    })?.primaryConfigurationId).toBe("configuration-execution");
  });

  test("persists purpose for a preference-derived pin", () => {
    const assignment = repository.createPinnedAssignment({
      agentId: "ReconScout",
      missionId: MISSION_ID,
      runId: RUN_ID,
      purpose: "planning",
    }, {
      id: "preference-planning",
      purpose: "planning",
      scopeType: "run",
      scopeId: RUN_ID,
      agentId: "ReconScout",
      primaryConfigurationId: "configuration-planning",
      fallbackConfigurationId: null,
      resolutionReason: "Use the reviewed planning advisor",
      version: 1,
      createdBy: "operator",
      createdAt: NOW,
      updatedBy: "operator",
      updatedAt: NOW,
    });

    expect(assignment).toMatchObject({
      purpose: "planning",
      primaryConfigurationId: "configuration-planning",
      inheritanceLevel: "run",
    });
    expect(repository.findPinnedAssignment({
      agentId: "ReconScout",
      missionId: MISSION_ID,
      runId: RUN_ID,
      purpose: "planning",
    })?.id).toBe(assignment.id);
  });
});

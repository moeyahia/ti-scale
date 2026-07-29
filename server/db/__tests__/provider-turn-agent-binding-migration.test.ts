import { describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  listAppliedMigrations,
  migrateDatabase,
} from "../index";
import {
  GuidedCommanderRepository,
  type GuidedScope,
} from "../../guided-commander/GuidedCommanderRepository";

const NOW = "2026-07-23T16:30:00.000Z";
const PROMPT_TEMPLATE_HASH = "a".repeat(64);
const MODEL_CONFIGURATION_HASH = "b".repeat(64);

function createDatabase() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  return database;
}

function insertBindingFixture(
  database: ReturnType<typeof createDatabaseConnection>,
): GuidedScope {
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
      'mission-guided', 'Guided assessment', 'Map the authorized service',
      'guided', 'operator', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, created_at, updated_at
    ) VALUES (
      'run-guided', 'mission-guided', 'guided',
      'waiting_guided_decision', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      content_hash, content_hash_version, created_by, created_at
    ) VALUES (
      'plan-guided', 'run-guided', 1, 'active',
      'Inspect the authorized target without changing it',
      ?, ?, 1, 'system', ?
    )
  `).run("c".repeat(64), "d".repeat(64), NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      action_class, assigned_agent_id, created_at, updated_at
    ) VALUES (
      'step-guided', 'plan-guided', 'run-guided', 0, 'reconnaissance',
      'Inspect the exposed service', 'Identify the exposed service',
      'pending', 'active_host_discovery', 'ReconScout', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO model_configurations (
      id, provider_id, model_id, context_policy_json, capabilities_json,
      context_limit, cost_class, latency_class, disclosure_class,
      enforcement_mode, auth_state, health_state, catalog_source,
      catalog_retrieved_at, configuration_source, prompt_template_hash,
      created_at, updated_at, version
    ) VALUES (
      'model-configuration-local', 'local-deterministic-safe-recon',
      'policy:local-safe-recon-v2', '{}', '["structured_output"]',
      32768, 'low', 'fast', 'local_only', 'enforced', 'healthy', 'healthy',
      'test-catalog', ?, 'manual', ?, ?, ?, 1
    )
  `).run(NOW, PROMPT_TEMPLATE_HASH, NOW, NOW);
  database.prepare(`
    INSERT INTO agent_model_assignments (
      id, agent_id, mission_id, run_id, step_id,
      primary_configuration_id, fallback_configuration_id,
      inheritance_level, pinned, resolution_reason, resolved_at, created_at
    ) VALUES (
      'model-assignment-guided', 'ReconScout', 'mission-guided',
      'run-guided', 'step-guided', 'model-configuration-local', NULL,
      'step', 1, 'Pinned before the provider turn', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, step_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, retrieval_metrics_json,
      created_by, created_at
    ) VALUES (
      'context-pack-guided', 'mission-guided', 'run-guided', 'step-guided',
      'guided', 'Explain the represented Guided step',
      'authorized service context', '{}', 256, '{}', 'BrainContextService', ?
    )
  `).run(NOW);

  return {
    mission: {
      id: "mission-guided",
      name: "Guided assessment",
      objective: "Map the authorized service",
      engagementId: null,
      authorizationStatus: "authorized",
      scope: {},
    },
    run: {
      id: "run-guided",
      status: "waiting_guided_decision",
      currentStepId: "step-guided",
      progress: 0,
    },
    step: {
      id: "step-guided",
      planId: "plan-guided",
      planVersion: 1,
      phase: "reconnaissance",
      title: "Inspect the exposed service",
      objective: "Identify the exposed service",
      status: "pending",
      assignedAgentId: "ReconScout",
      riskClass: "network",
      successCriteria: ["The service is identified"],
      explanation: "Inspect the approved target without changing it.",
      rationale: "The service identity determines the next safe step.",
      reversibility: "This read-only inspection does not change the target.",
      representedAction: {
        actionClass: "active_host_discovery",
        target: "authorized-service",
      },
      decisionParameters: {
        target: "authorized-service",
      },
      actionFingerprint: "guided-action-fingerprint",
      guidedDecisionId: "decision-guided",
      guidedDecisionStatus: "pending",
    },
  };
}

describe("migration 048 provider-turn agent binding", () => {
  test("registers the additive migration and persists repository-written lineage", () => {
    const database = createDatabase();
    try {
      expect(DATABASE_MIGRATIONS.find((migration) => migration.version === 48)).toMatchObject({
        version: 48,
        name: "provider_turn_agent_binding",
      });
      expect(listAppliedMigrations(database).find((migration) => migration.version === 48)).toMatchObject({
        version: 48,
        name: "provider_turn_agent_binding",
      });

      const scope = insertBindingFixture(database);
      const repository = new GuidedCommanderRepository(database, {
        clock: () => new Date(NOW),
        createId: () => "provider-turn-guided",
      });
      const turn = repository.startProviderTurn(
        scope,
        "local-deterministic-safe-recon",
        "policy:local-safe-recon-v2",
        MODEL_CONFIGURATION_HASH,
        {
          agentId: "ReconScout",
          modelAssignmentId: "model-assignment-guided",
          modelConfigurationId: "model-configuration-local",
          promptTemplateHash: PROMPT_TEMPLATE_HASH,
          contextPackId: "context-pack-guided",
        },
      );

      expect(turn.id).toBe("provider-turn-guided");
      expect(database.prepare(`
        SELECT
          provider_turns.agent_id AS agentId,
          provider_turns.model_assignment_id AS modelAssignmentId,
          provider_turns.model_configuration_id AS modelConfigurationId,
          provider_turns.model_assignment_configuration_hash AS assignmentConfigurationHash,
          provider_turns.prompt_template_hash AS promptTemplateHash,
          provider_turns.context_pack_id AS contextPackId,
          agent_model_assignments.agent_id AS assignmentAgentId,
          agent_model_assignments.primary_configuration_id AS assignmentConfigurationId,
          memory_context_packs.run_id AS contextRunId,
          memory_context_packs.step_id AS contextStepId
        FROM provider_turns
        JOIN agents
          ON agents.id = provider_turns.agent_id
        JOIN agent_model_assignments
          ON agent_model_assignments.id = provider_turns.model_assignment_id
        JOIN model_configurations
          ON model_configurations.id = provider_turns.model_configuration_id
        JOIN memory_context_packs
          ON memory_context_packs.id = provider_turns.context_pack_id
        WHERE provider_turns.id = 'provider-turn-guided'
      `).get()).toEqual({
        agentId: "ReconScout",
        modelAssignmentId: "model-assignment-guided",
        modelConfigurationId: "model-configuration-local",
        assignmentConfigurationHash: null,
        promptTemplateHash: PROMPT_TEMPLATE_HASH,
        contextPackId: "context-pack-guided",
        assignmentAgentId: "ReconScout",
        assignmentConfigurationId: "model-configuration-local",
        contextRunId: "run-guided",
        contextStepId: "step-guided",
      });
      expect(database.prepare("PRAGMA foreign_key_check").all()).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("rejects a malformed provider-turn prompt-template hash", () => {
    const database = createDatabase();
    try {
      insertBindingFixture(database);
      expect(() => database.prepare(`
        INSERT INTO provider_turns (
          id, run_id, provider, model, status, started_at,
          agent_id, model_assignment_id, model_configuration_id,
          prompt_template_hash, context_pack_id
        ) VALUES (
          'provider-turn-invalid-hash', 'run-guided',
          'local-deterministic-safe-recon', 'policy:local-safe-recon-v2',
          'started', ?, 'ReconScout', 'model-assignment-guided',
          'model-configuration-local', 'not-a-sha256',
          'context-pack-guided'
        )
      `).run(NOW)).toThrow();
      expect(database.prepare(`
        SELECT COUNT(*) AS count
        FROM provider_turns
        WHERE id = 'provider-turn-invalid-hash'
      `).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("rejects a malformed immutable assignment-configuration hash", () => {
    const database = createDatabase();
    try {
      insertBindingFixture(database);
      expect(() => database.prepare(`
        INSERT INTO provider_turns (
          id, run_id, provider, model, model_configuration_hash,
          agent_id, model_assignment_id, model_configuration_id,
          model_assignment_configuration_hash, status, started_at
        ) VALUES (
          'provider-turn-invalid-assignment-hash', 'run-guided',
          'local-deterministic-safe-recon', 'policy:local-safe-recon-v2',
          ?, 'ReconScout', 'model-assignment-guided',
          'model-configuration-local', 'not-a-sha256', 'started', ?
        )
      `).run(MODEL_CONFIGURATION_HASH, NOW)).toThrow();
      expect(database.prepare(`
        SELECT COUNT(*) AS count
        FROM provider_turns
        WHERE id = 'provider-turn-invalid-assignment-hash'
      `).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("rejects a second pinned model assignment for the same exact scope", () => {
    const database = createDatabase();
    try {
      insertBindingFixture(database);
      expect(() => database.prepare(`
        INSERT INTO agent_model_assignments (
          id, agent_id, mission_id, run_id, step_id,
          primary_configuration_id, fallback_configuration_id,
          inheritance_level, pinned, resolution_reason, resolved_at, created_at
        ) VALUES (
          'model-assignment-duplicate', 'ReconScout', 'mission-guided',
          'run-guided', 'step-guided', 'model-configuration-local', NULL,
          'step', 1, 'Duplicate exact scope', ?, ?
        )
      `).run(NOW, NOW)).toThrow();

      database.prepare(`
        INSERT INTO agent_model_assignments (
          id, agent_id, mission_id, run_id, step_id,
          primary_configuration_id, fallback_configuration_id,
          inheritance_level, pinned, resolution_reason, resolved_at, created_at
        ) VALUES (
          'model-assignment-unpinned', 'ReconScout', 'mission-guided',
          'run-guided', 'step-guided', 'model-configuration-local', NULL,
          'step', 0, 'Unpinned candidate is allowed', ?, ?
        )
      `).run(NOW, NOW);
      expect(database.prepare(`
        SELECT id, pinned
        FROM agent_model_assignments
        WHERE agent_id = 'ReconScout'
        ORDER BY id
      `).all()).toEqual([
        { id: "model-assignment-guided", pinned: 1 },
        { id: "model-assignment-unpinned", pinned: 0 },
      ]);
    } finally {
      database.close();
    }
  });
});

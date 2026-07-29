import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  listAppliedMigrations,
  migrateDatabase,
} from "../index";

const temporaryDirectories: string[] = [];
const NOW = "2026-07-23T13:00:00.000Z";

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function createDatabase() {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-model-preferences-"));
  temporaryDirectories.push(directory);
  const database = createDatabaseConnection({
    filename: join(directory, "ti-scale.sqlite"),
  });
  migrateDatabase(database);
  return database;
}

function insertModelConfiguration(
  database: ReturnType<typeof createDatabaseConnection>,
  id: string,
  modelId: string,
): void {
  database.prepare(`
    INSERT INTO model_configurations (
      id, provider_id, model_id, context_policy_json, capabilities_json,
      context_limit, cost_class, latency_class, disclosure_class,
      enforcement_mode, auth_state, health_state, catalog_source,
      catalog_retrieved_at, configuration_source, created_at, updated_at,
      version
    ) VALUES (
      ?, 'local-test-provider', ?, '{}', '["structured_output"]',
      32768, 'standard', 'fast', 'local_only',
      'enforced', 'healthy', 'healthy', 'test-catalog',
      ?, 'manual', ?, ?, 1
    )
  `).run(id, modelId, NOW, NOW, NOW);
}

function insertScopeFixture(
  database: ReturnType<typeof createDatabaseConnection>,
): void {
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES (
      'agent-recon', 'reconnaissance', 'Recon Scout', 'available',
      '1.0.0', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, created_by, created_at, updated_at
    ) VALUES (
      'mission-alpha', 'Mission Alpha', 'Assess the authorized target',
      'autonomous', 'operator', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, created_by, created_at, updated_at
    ) VALUES (
      'mission-beta', 'Mission Beta', 'Assess another authorized target',
      'autonomous', 'operator', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, created_at, updated_at
    ) VALUES (
      'run-alpha', 'mission-alpha', 'autonomous', 'queued', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, created_at, updated_at
    ) VALUES (
      'run-beta', 'mission-alpha', 'autonomous', 'queued', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      content_hash, content_hash_version, created_by, created_at
    ) VALUES (
      'plan-alpha', 'run-alpha', 1, 'active', 'Authorized plan',
      ?, ?, 1, 'operator', ?
    )
  `).run("a".repeat(64), "b".repeat(64), NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      created_at, updated_at
    ) VALUES (
      'step-alpha', 'plan-alpha', 'run-alpha', 0, 'reconnaissance',
      'Map services', 'Identify exposed services', 'pending', ?, ?
    )
  `).run(NOW, NOW);
}

function insertPreference(
  database: ReturnType<typeof createDatabaseConnection>,
  input: {
    readonly id: string;
    readonly scopeType: "global" | "agent" | "mission" | "run" | "step";
    readonly scopeId: string;
    readonly agentId?: string | null;
    readonly missionId?: string | null;
    readonly runId?: string | null;
    readonly stepId?: string | null;
    readonly primaryConfigurationId?: string;
    readonly fallbackConfigurationId?: string | null;
    readonly version?: number;
    readonly active?: 0 | 1;
    readonly supersedesPreferenceId?: string | null;
  },
): void {
  database.prepare(`
    INSERT INTO model_assignment_preferences (
      id, scope_type, scope_id, agent_id, mission_id, run_id, step_id,
      primary_configuration_id, fallback_configuration_id, version,
      active, is_current, supersedes_preference_id, resolution_reason,
      created_by, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 'operator', ?)
  `).run(
    input.id,
    input.scopeType,
    input.scopeId,
    input.agentId ?? null,
    input.missionId ?? null,
    input.runId ?? null,
    input.stepId ?? null,
    input.primaryConfigurationId ?? "model-primary",
    input.fallbackConfigurationId ?? null,
    input.version ?? 1,
    input.active ?? 1,
    input.supersedesPreferenceId ?? null,
    `Preference for ${input.scopeType}`,
    NOW,
  );
}

describe("migration 047 model assignment preferences", () => {
  test("registers the additive migration after the immutable model records", () => {
    const database = createDatabase();
    try {
      expect(DATABASE_MIGRATIONS.find(({ version }) => version === 47)).toMatchObject({
        version: 47,
        name: "model_assignment_preferences",
      });
      expect(listAppliedMigrations(database).find(({ version }) => version === 47)).toMatchObject({
        version: 47,
        name: "model_assignment_preferences",
      });
      expect(
        database.prepare(`
          SELECT name FROM sqlite_master
          WHERE type = 'table' AND name IN (
            'model_configurations',
            'agent_model_assignments',
            'model_assignment_preferences'
          )
          ORDER BY name
        `).all(),
      ).toEqual([
        { name: "agent_model_assignments" },
        { name: "model_assignment_preferences" },
        { name: "model_configurations" },
      ]);
    } finally {
      database.close();
    }
  });

  test("stores exact global through step scopes and appends a CAS successor", () => {
    const database = createDatabase();
    try {
      insertScopeFixture(database);
      insertModelConfiguration(database, "model-primary", "model-primary-v1");
      insertModelConfiguration(database, "model-fallback", "model-fallback-v1");
      insertModelConfiguration(database, "model-step-v2", "model-step-v2");

      database.prepare(`
        INSERT INTO agent_model_assignments (
          id, agent_id, mission_id, run_id, step_id,
          primary_configuration_id, fallback_configuration_id,
          inheritance_level, pinned, resolution_reason, resolved_at, created_at
        ) VALUES (
          'assignment-original', 'agent-recon', 'mission-alpha', 'run-alpha',
          'step-alpha', 'model-primary', 'model-fallback', 'step', 1,
          'Pinned before preference mutation', ?, ?
        )
      `).run(NOW, NOW);

      insertPreference(database, {
        id: "preference-global-v1",
        scopeType: "global",
        scopeId: "global",
      });
      insertPreference(database, {
        id: "preference-agent-v1",
        scopeType: "agent",
        scopeId: "agent-recon",
        agentId: "agent-recon",
      });
      insertPreference(database, {
        id: "preference-mission-v1",
        scopeType: "mission",
        scopeId: "mission-alpha",
        agentId: "agent-recon",
        missionId: "mission-alpha",
      });
      insertPreference(database, {
        id: "preference-run-v1",
        scopeType: "run",
        scopeId: "run-alpha",
        agentId: "agent-recon",
        missionId: "mission-alpha",
        runId: "run-alpha",
      });
      insertPreference(database, {
        id: "preference-step-v1",
        scopeType: "step",
        scopeId: "step-alpha",
        agentId: "agent-recon",
        missionId: "mission-alpha",
        runId: "run-alpha",
        stepId: "step-alpha",
        fallbackConfigurationId: "model-fallback",
      });

      expect(database.prepare(`
        SELECT COUNT(*) AS count
        FROM model_assignment_preferences
        WHERE active = 1 AND is_current = 1
      `).get()).toEqual({ count: 5 });

      insertPreference(database, {
        id: "preference-step-v2",
        scopeType: "step",
        scopeId: "step-alpha",
        agentId: "agent-recon",
        missionId: "mission-alpha",
        runId: "run-alpha",
        stepId: "step-alpha",
        primaryConfigurationId: "model-step-v2",
        fallbackConfigurationId: "model-fallback",
        version: 2,
        supersedesPreferenceId: "preference-step-v1",
      });

      expect(database.prepare(`
        SELECT id, primary_configuration_id, version, active, is_current,
               supersedes_preference_id
        FROM model_assignment_preferences
        WHERE scope_type = 'step' AND scope_id = 'step-alpha'
        ORDER BY version
      `).all()).toEqual([
        {
          id: "preference-step-v1",
          primary_configuration_id: "model-primary",
          version: 1,
          active: 0,
          is_current: 0,
          supersedes_preference_id: null,
        },
        {
          id: "preference-step-v2",
          primary_configuration_id: "model-step-v2",
          version: 2,
          active: 1,
          is_current: 1,
          supersedes_preference_id: "preference-step-v1",
        },
      ]);
      expect(database.prepare(`
        SELECT primary_configuration_id, fallback_configuration_id, pinned,
               resolution_reason
        FROM agent_model_assignments
        WHERE id = 'assignment-original'
      `).get()).toEqual({
        primary_configuration_id: "model-primary",
        fallback_configuration_id: "model-fallback",
        pinned: 1,
        resolution_reason: "Pinned before preference mutation",
      });
      expect(database.prepare(`
        SELECT model_id, version
        FROM model_configurations
        WHERE id = 'model-primary'
      `).get()).toEqual({
        model_id: "model-primary-v1",
        version: 1,
      });
    } finally {
      database.close();
    }
  });

  test("rejects malformed scope identities, lineage errors, and version races", () => {
    const database = createDatabase();
    try {
      insertScopeFixture(database);
      insertModelConfiguration(database, "model-primary", "model-primary-v1");
      insertModelConfiguration(database, "model-fallback", "model-fallback-v1");

      expect(() => insertPreference(database, {
        id: "bad-global",
        scopeType: "global",
        scopeId: "global",
        agentId: "agent-recon",
      })).toThrow();
      expect(() => insertPreference(database, {
        id: "bad-agent",
        scopeType: "agent",
        scopeId: "agent-recon",
      })).toThrow();
      expect(() => insertPreference(database, {
        id: "bad-run-lineage",
        scopeType: "run",
        scopeId: "run-alpha",
        agentId: "agent-recon",
        missionId: "mission-beta",
        runId: "run-alpha",
      })).toThrow("model preference run does not belong to its mission");
      expect(() => insertPreference(database, {
        id: "bad-step-lineage",
        scopeType: "step",
        scopeId: "step-alpha",
        agentId: "agent-recon",
        missionId: "mission-alpha",
        runId: "run-beta",
        stepId: "step-alpha",
      })).toThrow("model preference step does not belong to its run");
      expect(() => insertPreference(database, {
        id: "bad-fallback",
        scopeType: "agent",
        scopeId: "agent-recon",
        agentId: "agent-recon",
        fallbackConfigurationId: "model-primary",
      })).toThrow();

      insertPreference(database, {
        id: "preference-agent-v1",
        scopeType: "agent",
        scopeId: "agent-recon",
        agentId: "agent-recon",
      });
      insertPreference(database, {
        id: "preference-mission-v1",
        scopeType: "mission",
        scopeId: "mission-alpha",
        agentId: "agent-recon",
        missionId: "mission-alpha",
      });

      expect(() => insertPreference(database, {
        id: "duplicate-agent-v1",
        scopeType: "agent",
        scopeId: "agent-recon",
        agentId: "agent-recon",
      })).toThrow("model preference scope already has version history");
      expect(() => insertPreference(database, {
        id: "agent-version-gap",
        scopeType: "agent",
        scopeId: "agent-recon",
        agentId: "agent-recon",
        version: 3,
        supersedesPreferenceId: "preference-agent-v1",
      })).toThrow(
        "model preference successor does not match current scope version",
      );
      expect(() => insertPreference(database, {
        id: "agent-wrong-predecessor",
        scopeType: "agent",
        scopeId: "agent-recon",
        agentId: "agent-recon",
        version: 2,
        supersedesPreferenceId: "preference-mission-v1",
      })).toThrow(
        "model preference successor does not match current scope version",
      );

      expect(database.prepare(`
        SELECT active, is_current
        FROM model_assignment_preferences
        WHERE id = 'preference-agent-v1'
      `).get()).toEqual({ active: 1, is_current: 1 });
    } finally {
      database.close();
    }
  });

  test("retains immutable history and restricts referenced configuration deletion", () => {
    const database = createDatabase();
    try {
      insertScopeFixture(database);
      insertModelConfiguration(database, "model-primary", "model-primary-v1");
      insertPreference(database, {
        id: "preference-agent-v1",
        scopeType: "agent",
        scopeId: "agent-recon",
        agentId: "agent-recon",
      });

      expect(() => database.prepare(`
        UPDATE model_assignment_preferences
        SET primary_configuration_id = 'missing-model'
        WHERE id = 'preference-agent-v1'
      `).run()).toThrow(
        "model assignment preference versions are immutable",
      );
      expect(() => database.prepare(`
        DELETE FROM model_assignment_preferences
        WHERE id = 'preference-agent-v1'
      `).run()).toThrow(
        "model assignment preference history cannot be deleted",
      );
      expect(() => database.prepare(`
        DELETE FROM model_configurations
        WHERE id = 'model-primary'
      `).run()).toThrow();
    } finally {
      database.close();
    }
  });
});

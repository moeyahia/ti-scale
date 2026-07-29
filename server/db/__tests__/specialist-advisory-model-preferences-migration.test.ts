import { describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  listAppliedMigrations,
  migrateDatabase,
} from "../index";

const NOW = "2026-07-28T18:00:00.000Z";

function insertConfiguration(
  database: ReturnType<typeof createDatabaseConnection>,
  id: string,
): void {
  database.prepare(`
    INSERT INTO model_configurations (
      id, provider_id, model_id, context_policy_json, capabilities_json,
      context_limit, cost_class, latency_class, disclosure_class,
      enforcement_mode, auth_state, health_state, catalog_source,
      catalog_retrieved_at, configuration_source, created_at, updated_at,
      version
    ) VALUES (
      ?, 'fixture-provider', ?, '{}', '{}', 32000, 'standard', 'standard',
      'public_only', 'advisory_only', 'healthy', 'healthy',
      'fixture-catalog', ?, 'manual', ?, ?, 1
    )
  `).run(id, id, NOW, NOW, NOW);
}

function insertPreference(
  database: ReturnType<typeof createDatabaseConnection>,
  input: {
    readonly id: string;
    readonly configurationId: string;
    readonly purpose?: "execution" | "planning";
    readonly version?: number;
    readonly predecessorId?: string | null;
  },
): void {
  const purposeColumn = input.purpose ? ", assignment_purpose" : "";
  const purposeValue = input.purpose ? ", ?" : "";
  database.prepare(`
    INSERT INTO model_assignment_preferences (
      id, scope_type, scope_id, agent_id, mission_id, run_id, step_id,
      primary_configuration_id, fallback_configuration_id, version,
      active, is_current, supersedes_preference_id, resolution_reason,
      created_by, created_at${purposeColumn}
    ) VALUES (
      ?, 'global', 'global', NULL, NULL, NULL, NULL, ?, NULL, ?,
      1, 1, ?, 'Purpose-separated fixture', 'operator', ?${purposeValue}
    )
  `).run(
    input.id,
    input.configurationId,
    input.version ?? 1,
    input.predecessorId ?? null,
    NOW,
    ...(input.purpose ? [input.purpose] : []),
  );
}

describe("migration 061 specialist advisory model preferences", () => {
  test("remains registered before the run-scoped Linux activation and admission migrations", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      expect(DATABASE_MIGRATIONS.find(({ version }) => version === 61))
        .toMatchObject({
          version: 61,
          name: "specialist_advisory_model_preferences",
        });
      expect(listAppliedMigrations(database).slice(-3)).toEqual([
        expect.objectContaining({
          version: 61,
          name: "specialist_advisory_model_preferences",
        }),
        expect.objectContaining({
          version: 62,
          name: "run_scoped_candidate_linux_procedure_activations",
        }),
        expect.objectContaining({
          version: 63,
          name: "reviewed_candidate_linux_procedure_admissions",
        }),
      ]);
    } finally {
      database.close();
    }
  });

  test("classifies legacy preferences as execution and permits an independent planning preference", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(
        database,
        DATABASE_MIGRATIONS.filter(({ version }) => version < 61),
      );
      insertConfiguration(database, "configuration-execution");
      insertConfiguration(database, "configuration-advisory");
      insertPreference(database, {
        id: "preference-legacy",
        configurationId: "configuration-execution",
      });

      migrateDatabase(
        database,
        DATABASE_MIGRATIONS.filter(({ version }) => version <= 61),
      );
      insertPreference(database, {
        id: "preference-advisory",
        configurationId: "configuration-advisory",
        purpose: "planning",
      });

      expect(database.prepare(`
        SELECT id, assignment_purpose AS purpose
        FROM model_assignment_preferences
        ORDER BY assignment_purpose
      `).all()).toEqual([
        { id: "preference-legacy", purpose: "execution" },
        { id: "preference-advisory", purpose: "planning" },
      ]);
      expect(database.prepare("PRAGMA foreign_key_check").all()).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("versions execution and planning histories independently and preserves purpose immutability", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      insertConfiguration(database, "configuration-one");
      insertConfiguration(database, "configuration-two");
      insertPreference(database, {
        id: "execution-v1",
        configurationId: "configuration-one",
        purpose: "execution",
      });
      insertPreference(database, {
        id: "planning-v1",
        configurationId: "configuration-one",
        purpose: "planning",
      });
      insertPreference(database, {
        id: "planning-v2",
        configurationId: "configuration-two",
        purpose: "planning",
        version: 2,
        predecessorId: "planning-v1",
      });

      expect(database.prepare(`
        SELECT assignment_purpose AS purpose, version, is_current
        FROM model_assignment_preferences
        ORDER BY assignment_purpose, version
      `).all()).toEqual([
        { purpose: "execution", version: 1, is_current: 1 },
        { purpose: "planning", version: 1, is_current: 0 },
        { purpose: "planning", version: 2, is_current: 1 },
      ]);
      expect(() => database.prepare(`
        UPDATE model_assignment_preferences
        SET assignment_purpose = 'execution'
        WHERE id = 'planning-v2'
      `).run()).toThrow("model assignment preference versions are immutable");
      expect(() => insertPreference(database, {
        id: "planning-duplicate-v1",
        configurationId: "configuration-one",
        purpose: "planning",
      })).toThrow();
    } finally {
      database.close();
    }
  });
});

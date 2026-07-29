import { describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  listAppliedMigrations,
  migrateDatabase,
} from "../index";

const NOW = "2026-07-28T12:00:00.000Z";

function insertFixture(
  database: ReturnType<typeof createDatabaseConnection>,
): void {
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES (
      'ReconScout', 'reconnaissance', 'ReconScout', 'available',
      '1.0.0', ?, ?
    )
  `).run(NOW, NOW);
  for (const [id, modelId] of [
    ["configuration-execution", "execution-model"],
    ["configuration-planning", "planning-model"],
  ] as const) {
    database.prepare(`
      INSERT INTO model_configurations (
        id, provider_id, model_id, context_policy_json, capabilities_json,
        context_limit, cost_class, latency_class, disclosure_class,
        enforcement_mode, auth_state, health_state, catalog_source,
        catalog_retrieved_at, configuration_source, created_at, updated_at,
        version
      ) VALUES (
        ?, 'test-provider', ?, '{}', '{}', 32768, 'standard', 'standard',
        'local_only', 'enforced', 'healthy', 'healthy', 'test-catalog',
        ?, 'manual', ?, ?, 1
      )
    `).run(id, modelId, NOW, NOW, NOW);
  }
}

function createDatabase() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  insertFixture(database);
  return database;
}

function insertAssignment(
  database: ReturnType<typeof createDatabaseConnection>,
  input: Readonly<{
    id: string;
    configurationId: string;
    purpose?: string;
  }>,
): void {
  const purposeColumn = input.purpose === undefined
    ? ""
    : ", assignment_purpose";
  const purposePlaceholder = input.purpose === undefined ? "" : ", ?";
  database.prepare(`
    INSERT INTO agent_model_assignments (
      id, agent_id, primary_configuration_id, fallback_configuration_id,
      inheritance_level, pinned, resolution_reason, resolved_at, created_at
      ${purposeColumn}
    ) VALUES (
      ?, 'ReconScout', ?, NULL, 'agent', 1, 'Purpose migration fixture',
      ?, ? ${purposePlaceholder}
    )
  `).run(
    input.id,
    input.configurationId,
    NOW,
    NOW,
    ...(input.purpose === undefined ? [] : [input.purpose]),
  );
}

describe("migration 057 model assignment purpose", () => {
  test("is registered and applied before later migrations", () => {
    const database = createDatabase();
    try {
      expect(DATABASE_MIGRATIONS.find((migration) => migration.version === 57)).toMatchObject({
        version: 57,
        name: "model_assignment_purpose",
      });
      expect(listAppliedMigrations(database).find((migration) => migration.version === 57)).toMatchObject({
        version: 57,
        name: "model_assignment_purpose",
      });
    } finally {
      database.close();
    }
  });

  test("defaults legacy inserts to execution and permits one pin per purpose", () => {
    const database = createDatabase();
    try {
      insertAssignment(database, {
        id: "assignment-execution",
        configurationId: "configuration-execution",
      });
      insertAssignment(database, {
        id: "assignment-planning",
        configurationId: "configuration-planning",
        purpose: "planning",
      });

      expect(database.prepare(`
        SELECT id, assignment_purpose AS purpose
        FROM agent_model_assignments
        ORDER BY assignment_purpose, id
      `).all()).toEqual([
        { id: "assignment-execution", purpose: "execution" },
        { id: "assignment-planning", purpose: "planning" },
      ]);

      expect(() => insertAssignment(database, {
        id: "assignment-execution-duplicate",
        configurationId: "configuration-execution",
        purpose: "execution",
      })).toThrow();
      expect(() => insertAssignment(database, {
        id: "assignment-planning-duplicate",
        configurationId: "configuration-planning",
        purpose: "planning",
      })).toThrow();
      expect(() => insertAssignment(database, {
        id: "assignment-invalid-purpose",
        configurationId: "configuration-planning",
        purpose: "advisory",
      })).toThrow();

      expect(database.prepare("PRAGMA foreign_key_check").all()).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("classifies a pre-migration pinned assignment as execution", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(
        database,
        DATABASE_MIGRATIONS.filter((migration) => migration.version < 57),
      );
      insertFixture(database);
      insertAssignment(database, {
        id: "assignment-before-purpose-migration",
        configurationId: "configuration-execution",
      });

      migrateDatabase(
        database,
        DATABASE_MIGRATIONS.filter((migration) => migration.version <= 57),
      );

      expect(database.prepare(`
        SELECT assignment_purpose AS purpose
        FROM agent_model_assignments
        WHERE id = 'assignment-before-purpose-migration'
      `).get()).toEqual({ purpose: "execution" });
      expect(listAppliedMigrations(database).at(-1)).toMatchObject({
        version: 57,
        name: "model_assignment_purpose",
      });
    } finally {
      database.close();
    }
  });
});

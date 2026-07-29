import { describe, expect, test } from "bun:test";
import {
  BrainContextService,
} from "../../brain-runtime";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository, SecondBrainService } from "../../memory";
import {
  MissionRepository,
  MissionService,
  OverviewRepository,
  ReadinessService,
} from "../index";

interface MissionFixture {
  readonly id: string;
  readonly runId: string;
  readonly name: string;
  readonly status: "active" | "archived";
  readonly journey: "autonomous" | "guided";
  readonly engagementId: string;
  readonly updatedAt: string;
}

function seedMission(database: SqliteDatabase, fixture: MissionFixture): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      engagement_id, scope_json, success_criteria_json,
      retention_policy_json, memory_policy_json, created_by,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'verified', ?, '{}', '[]', '{}', '{}',
      'operator:portfolio-search-test', ?, ?)
  `).run(
    fixture.id,
    fixture.name,
    `Evidence-backed objective for ${fixture.name}`,
    fixture.journey,
    fixture.status,
    fixture.engagementId,
    fixture.updatedAt,
    fixture.updatedAt,
  );
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      next_action_summary, budget_json, budget_usage_json,
      started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, 'completed', 1, 'Fixture completed',
      'Review the retained mission record', '{}', '{}', ?, ?, ?, ?)
  `).run(
    fixture.runId,
    fixture.id,
    fixture.journey,
    fixture.updatedAt,
    fixture.updatedAt,
    fixture.updatedAt,
    fixture.updatedAt,
  );
}

function fixtures(database: SqliteDatabase): {
  readonly active: MissionFixture;
  readonly archived: MissionFixture;
} {
  const active: MissionFixture = {
    id: "mission_active_stable_id_search",
    runId: "run_active_stable_id_search",
    name: "Current cobalt assessment",
    status: "active",
    journey: "guided",
    engagementId: "engagement-current",
    updatedAt: "2026-07-22T09:01:00.000Z",
  };
  const archived: MissionFixture = {
    id: "mission_archived_stable_id_search",
    runId: "run_archived_stable_id_search",
    name: "Private historical source archive beacon",
    status: "archived",
    journey: "autonomous",
    engagementId: "engagement-archive",
    updatedAt: "2026-07-22T09:00:00.000Z",
  };
  seedMission(database, active);
  seedMission(database, archived);
  return { active, archived };
}

function missionService(database: SqliteDatabase): MissionService {
  return new MissionService(
    new MissionRepository(database),
    new OverviewRepository(database),
    new ReadinessService([{
      id: "portfolio-search-service",
      label: "Portfolio search service fixture",
      journeys: ["autonomous", "guided"],
      evaluate: () => ({
        id: "portfolio-search-service",
        label: "Portfolio search service fixture",
        status: "pass",
        journeys: ["autonomous", "guided"],
        impact: "The isolated service fixture is available.",
      }),
    }]),
    new BrainContextService({
      database,
      secondBrain: new SecondBrainService(new MemoryRepository(database)),
    }),
  );
}

describe("Mission Portfolio stable-ID search", () => {
  test("repository resolves an archived mission only by its exact stable ID and preserves all other filters", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const { active, archived } = fixtures(database);
      const repository = new MissionRepository(database);

      expect(repository.list().items.map(({ id }) => id)).toEqual([active.id]);
      expect(repository.list({ query: "cobalt assessment" }).items.map(({ id }) => id)).toEqual([active.id]);
      expect(repository.list({ query: active.id }).items.map(({ id }) => id)).toEqual([active.id]);
      expect(repository.list({ query: archived.name }).items).toEqual([]);
      expect(repository.list({ query: "mission_archived_stable" }).items).toEqual([]);

      const exact = repository.list({ query: archived.id });
      expect(exact.items).toHaveLength(1);
      expect(exact.items[0]).toMatchObject({
        id: archived.id,
        missionStatus: "archived",
        engagementId: archived.engagementId,
      });
      expect(repository.list({ query: `  ${archived.id}  ` }).items.map(({ id }) => id)).toEqual([
        archived.id,
      ]);

      expect(repository.list({ query: archived.id, journey: "guided" }).items).toEqual([]);
      expect(repository.list({ query: archived.id, engagement: active.engagementId }).items).toEqual([]);
      expect(repository.list({
        query: archived.id,
        journey: archived.journey,
        engagement: archived.engagementId,
      }).items.map(({ id }) => id)).toEqual([archived.id]);
    } finally {
      database.close();
    }
  });

  test("service preserves active text search while reconciling an exact archived stable ID", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const { active, archived } = fixtures(database);
      const service = missionService(database);

      expect(service.list({ query: "CURRENT COBALT" }).items.map(({ id }) => id)).toEqual([active.id]);
      expect(service.list({ query: ` ${active.id} ` }).items.map(({ id }) => id)).toEqual([active.id]);
      expect(service.list({ query: archived.id }).items.map(({ id }) => id)).toEqual([archived.id]);
      expect(service.list({ query: archived.runId }).items).toEqual([]);
    } finally {
      database.close();
    }
  });
});

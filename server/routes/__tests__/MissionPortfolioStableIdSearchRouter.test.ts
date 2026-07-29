import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { RuntimeRepository } from "../../command-runtime/RuntimeRepository";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import type { ReadinessCheckProvider } from "../../missions";
import { createCommandOsRouter } from "../commandOsRoutes";
import { createMissionRuntimeReadRouter } from "../MissionRuntimeReadRouter";
import {
  AutonomousActivationReceiptRepository,
  AutonomousActivationReceiptVerifier,
} from "../../autonomous-runtime";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
});

const readiness: ReadinessCheckProvider = {
  id: "portfolio-search-route",
  label: "Portfolio search route fixture",
  journeys: ["autonomous", "guided"],
  evaluate: () => ({
    id: "portfolio-search-route",
    label: "Portfolio search route fixture",
    status: "pass",
    journeys: ["autonomous", "guided"],
    impact: "The isolated route fixture is available.",
  }),
};

function seedMission(input: {
  readonly database: SqliteDatabase;
  readonly id: string;
  readonly runId: string;
  readonly name: string;
  readonly status: "active" | "archived";
  readonly journey: "autonomous" | "guided";
  readonly engagementId: string;
  readonly updatedAt: string;
}): void {
  input.database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      engagement_id, scope_json, success_criteria_json,
      retention_policy_json, memory_policy_json, created_by,
      created_at, updated_at
    ) VALUES (?, ?, 'Verify stable mission-link reconciliation', ?, ?, 'verified',
      ?, '{}', '[]', '{}', '{}', 'operator:route-test', ?, ?)
  `).run(
    input.id,
    input.name,
    input.journey,
    input.status,
    input.engagementId,
    input.updatedAt,
    input.updatedAt,
  );
  input.database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress,
      budget_json, budget_usage_json, created_at, updated_at
    ) VALUES (?, ?, ?, 'completed', 1, '{}', '{}', ?, ?)
  `).run(input.runId, input.id, input.journey, input.updatedAt, input.updatedAt);
}

async function application(database: SqliteDatabase): Promise<string> {
  const app = express();
  app.use(express.json());
  app.use(createCommandOsRouter({
    database,
    readinessProviders: [readiness],
    resolveActor: () => "operator:portfolio-search-route",
  }));
  app.use(createMissionRuntimeReadRouter({
    repository: new RuntimeRepository(database),
    checkpoints: { latest: () => undefined },
    autonomousActivationReceipts: new AutonomousActivationReceiptRepository(database),
    autonomousActivationReceiptVerifier: new AutonomousActivationReceiptVerifier(database),
    resolveActor: () => "operator:portfolio-search-route",
    authorizeMission: () => true,
    authorizeRun: () => true,
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

interface MissionPageBody {
  readonly schemaVersion: "2.4";
  readonly items: ReadonlyArray<{
    readonly id: string;
    readonly missionStatus: string;
    readonly engagementId: string | null;
  }>;
}

async function readPage(url: string): Promise<{ readonly response: Response; readonly body: MissionPageBody }> {
  const response = await fetch(url);
  return { response, body: await response.json() as MissionPageBody };
}

describe("GET /api/v2/missions stable-ID reconciliation", () => {
  test("returns exact archived IDs without exposing archives to normal text, partial-ID, or mismatched-scope search", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const activeId = "mission_route_active_search";
      const archivedId = "mission_route_archived_search";
      seedMission({
        database,
        id: activeId,
        runId: "run_route_active_search",
        name: "Live titanium route beacon",
        status: "active",
        journey: "guided",
        engagementId: "engagement-live-route",
        updatedAt: "2026-07-22T10:01:00.000Z",
      });
      seedMission({
        database,
        id: archivedId,
        runId: "run_route_archived_search",
        name: "Archived titanium route beacon",
        status: "archived",
        journey: "autonomous",
        engagementId: "engagement-archived-route",
        updatedAt: "2026-07-22T10:00:00.000Z",
      });
      const base = await application(database);

      const active = await readPage(`${base}/api/v2/missions?query=${encodeURIComponent("TITANIUM ROUTE BEACON")}`);
      expect(active.response.status).toBe(200);
      expect(active.body.items.map(({ id }) => id)).toEqual([activeId]);
      const activeById = await readPage(`${base}/api/v2/missions?query=${encodeURIComponent(activeId)}`);
      expect(activeById.body.items.map(({ id }) => id)).toEqual([activeId]);

      const archived = await readPage(`${base}/api/v2/missions?query=${encodeURIComponent(archivedId)}`);
      expect(archived.response.status).toBe(200);
      expect(archived.body.items).toEqual([
        expect.objectContaining({
          id: archivedId,
          missionStatus: "archived",
          engagementId: "engagement-archived-route",
        }),
      ]);
      const whitespaceNormalized = await readPage(
        `${base}/api/v2/missions?query=${encodeURIComponent(`  ${archivedId}  `)}`,
      );
      expect(whitespaceNormalized.body.items.map(({ id }) => id)).toEqual([archivedId]);

      const returnedMissionId = archived.body.items[0]!.id;
      const deepLink = await fetch(
        `${base}/api/v2/missions/${encodeURIComponent(returnedMissionId)}/runtime`,
      );
      expect(deepLink.status).toBe(200);
      expect(await deepLink.json()).toMatchObject({
        schemaVersion: "2.4",
        mission: { id: archivedId, name: "Archived titanium route beacon" },
        runs: [{ id: "run_route_archived_search", missionId: archivedId }],
      });

      const titleProbe = await readPage(`${base}/api/v2/missions?query=${encodeURIComponent("Archived titanium route beacon")}`);
      expect(titleProbe.body.items).toEqual([]);
      const partialIdProbe = await readPage(`${base}/api/v2/missions?query=mission_route_archived`);
      expect(partialIdProbe.body.items).toEqual([]);
      const wrongEngagement = await readPage(
        `${base}/api/v2/missions?query=${encodeURIComponent(archivedId)}&engagement=engagement-live-route`,
      );
      expect(wrongEngagement.body.items).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("retains the bounded API query contract", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const base = await application(database);
      const response = await fetch(`${base}/api/v2/missions?query=${"x".repeat(301)}`);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({
        error: {
          code: "invalid_mission_search",
          retryable: false,
          category: "invalid_input",
        },
      });
    } finally {
      database.close();
    }
  });
});

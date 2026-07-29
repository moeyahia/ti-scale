import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import { GuidedCommanderRepository } from "../GuidedCommanderRepository";
import { createGuidedTranscriptReadRouter } from "../GuidedTranscriptReadRouter";

const NOW = "2026-07-16T15:00:00.000Z";
const servers: Server[] = [];
const databases: SqliteDatabase[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
  for (const database of databases.splice(0)) database.close();
});

function seed(database: SqliteDatabase): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
      created_by, created_at, updated_at
    ) VALUES (
      'mission-guided-empty', 'New Guided mission',
      'Assess the authorized empty.lab target', 'guided', 'active', 'verified',
      '{"allowedTargets":["empty.lab"]}', '[]', '{}', '{}',
      'operator:test', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      next_action_summary, created_at, updated_at
    ) VALUES (
      'run-guided-planning', 'mission-guided-empty', 'guided', 'planning', 0,
      'Building the first evidence-led plan', 'Prepare the first represented Guided step',
      ?, ?
    )
  `).run(NOW, NOW);
}

interface ErrorEnvelope {
  readonly error: {
    readonly code: string;
    readonly category: string;
    readonly retryable: boolean;
    readonly traceId: string;
  };
}

async function json<T>(response: Response): Promise<T> {
  return response.json() as Promise<T>;
}

async function application() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  seed(database);
  let actor: string | undefined = "operator:test";
  let allowed = true;
  const authorizationCalls: string[] = [];
  const app = express();
  app.use(express.json());
  app.use(createGuidedTranscriptReadRouter({
    repository: new GuidedCommanderRepository(database),
    resolveActor: () => actor,
    authorize: (_request, actorId, scope) => {
      authorizationCalls.push(`${actorId}:${scope.missionId}:${scope.runId}`);
      return allowed;
    },
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    database,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    authorizationCalls,
    setActor(value: string | undefined) { actor = value; },
    setAllowed(value: boolean) { allowed = value; },
  };
}

describe("GuidedTranscriptReadRouter", () => {
  test("returns a durable empty transcript for a newly created planning run", async () => {
    const fixture = await application();
    const response = await fetch(
      `${fixture.url}/api/v2/guided/mission-guided-empty/commander/transcript?runId=run-guided-planning`,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-request-id")).toBeTruthy();
    expect(await json<unknown>(response)).toEqual({
      schemaVersion: "2.4",
      mission: {
        id: "mission-guided-empty",
        name: "New Guided mission",
        objective: "Assess the authorized empty.lab target",
        engagementId: null,
        authorizationStatus: "verified",
        scope: { allowedTargets: ["empty.lab"] },
      },
      run: {
        id: "run-guided-planning",
        status: "planning",
        currentStepId: null,
        progress: 0,
      },
      currentStep: null,
      currentObservation: null,
      items: [],
      nextCursor: null,
    });
    expect(fixture.authorizationCalls).toEqual([
      "operator:test:mission-guided-empty:run-guided-planning",
    ]);
  });

  test("authenticates and authorizes the exact mission/run scope before reading", async () => {
    const fixture = await application();
    fixture.setActor(undefined);
    const unauthenticated = await fetch(
      `${fixture.url}/api/v2/guided/mission-guided-empty/commander/transcript?runId=run-guided-planning`,
    );
    expect(unauthenticated.status).toBe(401);
    expect(await json<ErrorEnvelope>(unauthenticated)).toMatchObject({
      error: {
        code: "guided_transcript_authentication_required",
        category: "authentication_missing",
        retryable: false,
      },
    });
    expect(fixture.authorizationCalls).toEqual([]);

    fixture.setActor("operator:test");
    fixture.setAllowed(false);
    const denied = await fetch(
      `${fixture.url}/api/v2/guided/mission-guided-empty/commander/transcript?runId=run-guided-planning`,
    );
    expect(denied.status).toBe(403);
    expect(await json<ErrorEnvelope>(denied)).toMatchObject({
      error: {
        code: "guided_transcript_policy_denied",
        category: "policy_denied",
        retryable: false,
      },
    });
    expect(fixture.authorizationCalls).toEqual([
      "operator:test:mission-guided-empty:run-guided-planning",
    ]);
  });

  test("validates bounded transcript query input and rejects unsupported filters", async () => {
    const fixture = await application();
    for (const [query, code] of [
      ["", "invalid_resource_id"],
      ["?runId=bad%2Fid", "invalid_resource_id"],
      ["?runId=run-guided-planning&limit=0", "invalid_transcript_limit"],
      ["?runId=run-guided-planning&limit=1e2", "invalid_transcript_limit"],
      ["?runId=run-guided-planning&cursor=%20", "invalid_transcript_cursor"],
      ["?runId=run-guided-planning&offset=1", "unsupported_guided_transcript_filter"],
    ] as const) {
      const response = await fetch(
        `${fixture.url}/api/v2/guided/mission-guided-empty/commander/transcript${query}`,
      );
      expect(response.status).toBe(400);
      expect(await json<ErrorEnvelope>(response)).toMatchObject({
        error: { code, category: "invalid_input", retryable: false },
      });
    }
  });

  test("returns canonical not-found state for a nonexistent or mismatched Guided run", async () => {
    const fixture = await application();
    const response = await fetch(
      `${fixture.url}/api/v2/guided/mission-guided-empty/commander/transcript?runId=run-missing`,
    );
    expect(response.status).toBe(404);
    expect(await json<ErrorEnvelope>(response)).toMatchObject({
      error: {
        code: "guided_run_not_found",
        category: "not_found",
        retryable: false,
      },
    });
  });

  test("exposes no provider or mutation route and rejects writes without changing state", async () => {
    const fixture = await application();
    const before = fixture.database.prepare(`
      SELECT
        (SELECT COUNT(*) FROM messages) AS messages,
        (SELECT COUNT(*) FROM conversations) AS conversations,
        (SELECT COUNT(*) FROM provider_turns) AS provider_turns,
        (SELECT COUNT(*) FROM events) AS events
    `).get();
    const transcriptWrite = await fetch(
      `${fixture.url}/api/v2/guided/mission-guided-empty/commander/transcript?runId=run-guided-planning`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
    );
    expect(transcriptWrite.status).toBe(405);
    expect(transcriptWrite.headers.get("allow")).toBe("GET");
    expect(await json<ErrorEnvelope>(transcriptWrite)).toMatchObject({
      error: {
        code: "guided_transcript_read_method_not_allowed",
        category: "method_not_allowed",
        retryable: false,
      },
    });

    const providerMutation = await fetch(
      `${fixture.url}/api/v2/guided/mission-guided-empty/commander/explain-more`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
    );
    expect(providerMutation.status).toBe(404);
    expect(fixture.database.prepare(`
      SELECT
        (SELECT COUNT(*) FROM messages) AS messages,
        (SELECT COUNT(*) FROM conversations) AS conversations,
        (SELECT COUNT(*) FROM provider_turns) AS provider_turns,
        (SELECT COUNT(*) FROM events) AS events
    `).get()).toEqual(before);
  });
});

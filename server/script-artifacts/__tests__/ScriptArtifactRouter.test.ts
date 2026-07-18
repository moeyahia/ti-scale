import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { SqliteDatabase } from "../../db";
import {
  createScriptArtifactRouter,
  MemoryScriptSourceStore,
  type ScriptArtifactActor,
  type ScriptArtifactAuthorizationRequest,
  type ScriptArtifactSummary,
} from "..";
import {
  AGENT_ONE_ID,
  createTestDatabase,
  MISSION_ID,
  NOW,
  PLAN_ID,
  RUN_ID,
  STEP_ONE_ID,
} from "../../../tests/unit/run-intelligence/fixtures";

const TARGET_ID = "asset-script-router";

interface Harness {
  readonly database: SqliteDatabase;
  readonly server: Server;
  readonly origin: string;
  readonly state: {
    actor: ScriptArtifactActor | undefined;
    allowed: boolean;
    readonly authorizations: ScriptArtifactAuthorizationRequest[];
  };
}

const openHarnesses: Harness[] = [];

function seedTarget(database: SqliteDatabase): void {
  database.prepare(`
    INSERT INTO topology_nodes (
      id, mission_id, run_id, node_type, primary_label, normalized_identity,
      scope_status, lifecycle_state, confidence, verification_state,
      originating_agent_id, sensitivity, first_seen_at, last_seen_at,
      created_at, updated_at
    ) VALUES (?, ?, ?, 'asset', 'router-web', '10.10.10.30', 'allowed',
      'observed', 0.9, 'verified', ?, 'internal', ?, ?, ?, ?)
  `).run(TARGET_ID, MISSION_ID, RUN_ID, AGENT_ONE_ID, NOW, NOW, NOW, NOW);
}

async function createHarness(): Promise<Harness> {
  const database = createTestDatabase();
  seedTarget(database);
  const state: Harness["state"] = {
    actor: { id: "operator-script-router", type: "operator" },
    allowed: true,
    authorizations: [],
  };
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use(createScriptArtifactRouter({
    database,
    sourceStore: new MemoryScriptSourceStore(),
    resolveActor: () => state.actor,
    authorize: (_request, _actor, authorization) => {
      state.authorizations.push(authorization);
      return state.allowed;
    },
    clock: () => new Date("2026-07-16T13:10:00.000Z"),
  }));
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  const harness = { database, server, origin: `http://127.0.0.1:${address.port}`, state };
  openHarnesses.push(harness);
  return harness;
}

async function closeHarness(harness: Harness): Promise<void> {
  const index = openHarnesses.indexOf(harness);
  if (index >= 0) openHarnesses.splice(index, 1);
  if (harness.server.listening) {
    await new Promise<void>((resolve, reject) => harness.server.close((error) => error ? reject(error) : resolve()));
  }
  harness.database.close();
}

afterEach(async () => Promise.all(openHarnesses.splice(0).map(closeHarness)).then(() => undefined));

function createBody(overrides: Readonly<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    runId: RUN_ID,
    planId: PLAN_ID,
    stepId: STEP_ONE_ID,
    targetNodeId: TARGET_ID,
    name: "guided/router_probe.ts",
    language: "typescript",
    source: "const marker: string = 'ready';\nconsole.log(marker);\n",
    laymanExplanation: "Produces one deterministic marker for an isolated review fixture.",
    technicalPurpose: "Exercises immutable TypeScript source documentation without executing a process.",
    inputs: [],
    expectedOutputs: [{
      label: "Readiness marker",
      description: "One local marker line if separately executed in an approved fixture.",
      successRecognition: "The exact line ready is present.",
      failureRecognition: "No marker is emitted or the process exits unsuccessfully.",
    }],
    prerequisites: ["TypeScript compiler is available in a separately authorized test environment."],
    dependencies: [],
    touches: { files: [], network: [], services: [] },
    sideEffects: ["Creating the artifact performs no execution and changes no target state."],
    riskClass: "low",
    reversibility: "Exclude the record from a plan while retaining immutable audit history.",
    cleanupNotes: "No cleanup is required because the source is not executed by this service.",
    secretsHandling: "No secrets are accepted or retained by this source artifact.",
    evidenceExpectations: ["Link a canonical test artifact before marking this script tested."],
    validation: {
      state: "unvalidated",
      summary: "Documented only; no test or execution claim is made.",
      tests: [],
    },
    provenance: {
      origin: "operator_authored",
      explanation: "Operator supplied a bounded documentation fixture.",
      sourceRefs: ["router-fixture:script-v1"],
    },
    sensitivity: "internal",
    ...overrides,
  };
}

function versionBody(record: ScriptArtifactSummary, overrides: Readonly<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    expectedVersion: record.version,
    changeSummary: "Refine the readiness marker without executing the source.",
    language: record.language,
    source: "const marker: string = 'ready:v2';\nconsole.log(marker);\n",
    laymanExplanation: record.laymanExplanation,
    technicalPurpose: record.technicalPurpose,
    inputs: record.inputs,
    expectedOutputs: [{ ...record.expectedOutputs[0], successRecognition: "The exact line ready:v2 is present." }],
    prerequisites: record.requirements.prerequisites,
    dependencies: record.requirements.dependencies,
    touches: record.touches,
    sideEffects: record.risk.sideEffects,
    riskClass: record.risk.riskClass,
    reversibility: record.risk.reversibility,
    cleanupNotes: record.cleanupNotes,
    secretsHandling: record.secretsHandling,
    evidenceExpectations: record.evidenceExpectations,
    validation: record.validation,
    provenance: {
      origin: "modified",
      explanation: "Operator amended one deterministic output marker.",
      sourceRefs: [`script-artifact:${record.id}`],
    },
    sensitivity: record.sensitivity,
    ...overrides,
  };
}

async function request(harness: Harness, path: string, input: {
  readonly method?: string;
  readonly body?: unknown;
  readonly idempotencyKey?: string;
} = {}): Promise<{ readonly status: number; readonly headers: Headers; readonly body: unknown }> {
  const headers = new Headers({ "X-Request-ID": "script-router-test" });
  if (input.body !== undefined) headers.set("Content-Type", "application/json");
  if (input.idempotencyKey) headers.set("Idempotency-Key", input.idempotencyKey);
  const response = await fetch(`${harness.origin}${path}`, {
    method: input.method ?? "GET",
    headers,
    ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
  });
  const body = response.headers.get("content-type")?.includes("application/json")
    ? await response.json() as unknown
    : await response.text();
  return { status: response.status, headers: response.headers, body };
}

function error(value: unknown): { readonly error: { readonly code: string; readonly category: string; readonly traceId: string; readonly remediation?: string } } {
  return value as { readonly error: { readonly code: string; readonly category: string; readonly traceId: string; readonly remediation?: string } };
}

describe("ScriptArtifactRouter", () => {
  test("fails closed for missing authentication and denied mission authorization", async () => {
    const harness = await createHarness();
    harness.state.actor = undefined;
    const missing = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts`);
    expect(missing.status).toBe(401);
    expect(error(missing.body).error).toMatchObject({
      code: "script_artifact_authentication_required",
      category: "authentication_missing",
      traceId: "script-router-test",
    });

    harness.state.actor = { id: "operator-script-router", type: "operator" };
    harness.state.allowed = false;
    const denied = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts?runId=${RUN_ID}`);
    expect(denied.status).toBe(403);
    expect(error(denied.body).error.code).toBe("script_artifact_policy_denied");
    expect(harness.state.authorizations.at(-1)).toEqual({
      missionId: MISSION_ID,
      runId: RUN_ID,
      capability: "read_script_artifacts",
    });
  });

  test("creates, replays, lists, reads source, and creates one immutable version", async () => {
    const harness = await createHarness();
    const created = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts`, {
      method: "POST",
      idempotencyKey: "script-create-router-0001",
      body: createBody(),
    });
    expect(created.status).toBe(201);
    expect(created.headers.get("idempotency-replayed")).toBe("false");
    const record = (created.body as { readonly record: ScriptArtifactSummary }).record;
    expect(record).toMatchObject({ missionId: MISSION_ID, runId: RUN_ID, version: 1 });
    expect(created.body).not.toHaveProperty("record.source");

    const replay = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts`, {
      method: "POST",
      idempotencyKey: "script-create-router-0001",
      body: createBody(),
    });
    expect(replay.status).toBe(201);
    expect(replay.headers.get("idempotency-replayed")).toBe("true");
    expect(replay.body).toEqual(created.body);
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM script_artifacts").get() as { count: number }).count).toBe(1);

    const list = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts?runId=${RUN_ID}&language=typescript`);
    expect((list.body as { readonly items: ScriptArtifactSummary[] }).items).toHaveLength(1);
    const detail = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts/${record.id}`);
    expect((detail.body as { readonly record: { readonly source: string } }).record.source).toContain("ready");

    const version = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts/${record.id}/versions`, {
      method: "POST",
      idempotencyKey: "script-version-router-0001",
      body: versionBody(record),
    });
    expect(version.status).toBe(201);
    const versionRecord = (version.body as { readonly record: ScriptArtifactSummary }).record;
    expect(versionRecord).toMatchObject({ version: 2, name: record.name });
    expect(versionRecord.diff).toMatchObject({ previousScriptArtifactId: record.id, sourceChanged: true });
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM actions").get() as { count: number }).count).toBe(0);
    expect(harness.state.authorizations.at(-1)).toMatchObject({ capability: "manage_script_artifacts", scriptArtifactId: record.id });

    const execute = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts/${versionRecord.id}/execute`, { method: "POST" });
    expect(execute.status).toBe(404);
  });

  test("requires idempotency, rejects changed replay bodies, and returns exact remediation envelopes", async () => {
    const harness = await createHarness();
    const missing = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts`, {
      method: "POST",
      body: createBody(),
    });
    expect(missing.status).toBe(400);
    expect(error(missing.body).error.code).toBe("script_artifact_idempotency_key_required");

    const first = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts`, {
      method: "POST",
      idempotencyKey: "script-replay-conflict-0001",
      body: createBody(),
    });
    expect(first.status).toBe(201);
    const conflictResponse = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts`, {
      method: "POST",
      idempotencyKey: "script-replay-conflict-0001",
      body: createBody({ laymanExplanation: "A materially changed explanation for the same replay key." }),
    });
    expect(conflictResponse.status).toBe(409);
    expect(error(conflictResponse.body).error).toMatchObject({
      code: "script_artifact_idempotency_conflict",
      category: "state_conflict",
      traceId: "script-router-test",
    });
    expect(error(conflictResponse.body).error.remediation).toContain("new Idempotency-Key");

    const secret = await request(harness, `/api/v2/missions/${MISSION_ID}/script-artifacts`, {
      method: "POST",
      idempotencyKey: "script-secret-reject-0001",
      body: createBody({ source: "const api_key = 'sk-fixturemustneverpersist';\n" }),
    });
    expect(secret.status).toBe(400);
    expect(error(secret.body).error).toMatchObject({
      code: "embedded_script_secret_rejected",
      category: "secret_handling",
    });
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM artifacts").get() as { count: number }).count).toBe(1);
  });
});

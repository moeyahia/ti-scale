import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { OperationalActor } from "../../intelligence-v24";
import {
  AGENT_ID,
  ASSET_ID,
  MISSION_ID,
  PLAN_ID,
  RUN_ID,
  STEP_ID,
  createPageCaptureFixtureDatabase,
  validPageCaptureInput,
} from "../../page-captures/__tests__/fixtures";
import type { PageCaptureAuthorizationRequest } from "../../page-captures";
import {
  MemoryScriptSourceStore,
  type ScriptArtifactActor,
  type ScriptArtifactAuthorizationRequest,
} from "../../script-artifacts";
import { createRuntimeReadinessProviders } from "../RuntimeReadiness";
import { createCommandOsApplication, type CommandOsApplication } from "../CommandOsApplication";

const directories: string[] = [];
const servers: Server[] = [];
const applications: CommandOsApplication[] = [];

afterEach(async () => {
  await Promise.all(applications.splice(0).map((application) => application.stop()));
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolveClose) => {
    server.close(() => resolveClose());
  })));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

const runtime = {
  actionBoundaryActive: false,
  delegationEnforced: false,
  noHandsCommanderEnforced: true,
  directCommanderToolsDenied: true,
  specialistAssignmentRequired: false,
  specialistsConfigured: 0,
  providers: [],
  mcp: {
    enabled: false,
    executionMode: "disabled" as const,
    startPermitted: false,
    configuredServers: 0,
    runnableServers: 0,
    missingDependencies: 0,
    missingSecrets: 0,
  },
  eventStream: "healthy" as const,
  secondBrain: "healthy" as const,
  legacyExecutionEnabled: false,
};

function scriptBody(name = "guided/page_capture_review.ts"): Record<string, unknown> {
  return {
    runId: RUN_ID,
    planId: PLAN_ID,
    stepId: STEP_ID,
    targetNodeId: ASSET_ID,
    name,
    language: "typescript",
    source: "const captureStatus: number = 200;\nconsole.log(captureStatus);\n",
    laymanExplanation: "Documents a deterministic status marker without executing the source.",
    technicalPurpose: "Preserves a reviewable TypeScript helper linked to the authorized page-capture step.",
    inputs: [],
    expectedOutputs: [{
      label: "Status marker",
      description: "One status value if separately tested in an authorized isolated environment.",
      successRecognition: "The exact value 200 is emitted.",
      failureRecognition: "No value is emitted or an external test reports failure.",
    }],
    prerequisites: ["A separate authorized test environment is required before execution."],
    dependencies: [],
    touches: { files: [], network: [], services: [] },
    sideEffects: ["Recording this immutable source performs no execution."],
    riskClass: "low",
    reversibility: "Exclude it from future planning while retaining immutable audit history.",
    cleanupNotes: "No target cleanup is required because the service cannot execute source.",
    secretsHandling: "No credentials or secret values are accepted or stored.",
    evidenceExpectations: ["Attach a canonical test artifact before claiming tested status."],
    validation: {
      state: "unvalidated",
      summary: "Documented only; no execution or test claim is made.",
      tests: [],
    },
    provenance: {
      origin: "operator_authored",
      explanation: "The authenticated operator supplied a bounded source-review fixture.",
      sourceRefs: [`plan-step:${STEP_ID}`],
    },
    sensitivity: "internal",
  };
}

async function fetchJson(origin: string, path: string, input: {
  readonly method?: string;
  readonly body?: unknown;
  readonly idempotencyKey?: string;
} = {}): Promise<{ readonly status: number; readonly headers: Headers; readonly body: any }> {
  const headers = new Headers({ "X-Request-ID": "artifact-application-test" });
  if (input.body !== undefined) headers.set("Content-Type", "application/json");
  if (input.idempotencyKey) headers.set("Idempotency-Key", input.idempotencyKey);
  const response = await fetch(`${origin}${path}`, {
    method: input.method ?? "GET",
    headers,
    ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
  });
  const body = response.headers.get("content-type")?.includes("application/json")
    ? await response.json()
    : await response.text();
  return { status: response.status, headers: response.headers, body };
}

describe("CommandOsApplication artifact and page-capture composition", () => {
  test("does not expose source routes without an explicitly injected source store", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-no-script-store-"));
    directories.push(directory);
    const commandOs = createCommandOsApplication({
      databasePath: join(directory, "ti-scale.sqlite"),
      readinessProviders: () => createRuntimeReadinessProviders(() => runtime),
      runtimeProjection: () => ({ readiness: runtime, agents: [], mcpServers: [] }),
      resolveActor: () => "application-operator",
      projectionIntervalMs: 60_000,
    });
    applications.push(commandOs);
    const app = express();
    app.use(commandOs.router);
    const server = createServer(app);
    servers.push(server);
    await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Test server has no TCP address");
    const origin = `http://127.0.0.1:${address.port}`;
    expect((await fetchJson(origin, "/api/v2/missions/unknown/script-artifacts")).status).toBe(404);
  });

  test("authenticates reads, preserves idempotency and V2 ownership, and exposes no execution route", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-artifact-app-"));
    directories.push(directory);
    const databasePath = join(directory, "ti-scale.sqlite");
    const fixture = createPageCaptureFixtureDatabase(databasePath);
    fixture.close();

    const state: {
      pageActor?: OperationalActor;
      scriptActor?: ScriptArtifactActor;
      readonly pageAuthorizations: PageCaptureAuthorizationRequest[];
      readonly scriptAuthorizations: ScriptArtifactAuthorizationRequest[];
    } = { pageAuthorizations: [], scriptAuthorizations: [] };
    const commandOs = createCommandOsApplication({
      databasePath,
      readinessProviders: () => createRuntimeReadinessProviders(() => runtime),
      runtimeProjection: () => ({ readiness: runtime, agents: [], mcpServers: [] }),
      resolveActor: () => "application-operator",
      resolvePageCaptureActor: () => state.pageActor,
      authorizePageCaptures: (_request, _actor, authorization) => {
        state.pageAuthorizations.push(authorization);
        return true;
      },
      scriptSourceStore: new MemoryScriptSourceStore(),
      resolveScriptArtifactActor: () => state.scriptActor,
      authorizeScriptArtifacts: (_request, _actor, authorization) => {
        state.scriptAuthorizations.push(authorization);
        return true;
      },
      projectionIntervalMs: 60_000,
    });
    applications.push(commandOs);
    const app = express();
    app.use(express.json({ limit: "1mb" }));
    app.use(commandOs.router);
    const server = createServer(app);
    servers.push(server);
    await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Test server has no TCP address");
    const origin = `http://127.0.0.1:${address.port}`;

    const pagePath = `/api/v2/missions/${MISSION_ID}/intelligence/page-captures`;
    const scriptPath = `/api/v2/missions/${MISSION_ID}/script-artifacts`;
    expect((await fetchJson(origin, pagePath)).status).toBe(401);
    expect((await fetchJson(origin, scriptPath)).status).toBe(401);

    state.pageActor = { id: "application-operator", type: "operator" };
    state.scriptActor = { id: "application-operator", type: "operator" };
    const { missionId: _missionId, ...pageBody } = validPageCaptureInput({
      capturedAt: new Date().toISOString(),
    });
    const pageCreated = await fetchJson(origin, pagePath, {
      method: "POST",
      idempotencyKey: "application-page-capture-0001",
      body: pageBody,
    });
    expect(pageCreated.status).toBe(201);
    expect(pageCreated.headers.get("idempotency-replayed")).toBe("false");
    const pageReplay = await fetchJson(origin, pagePath, {
      method: "POST",
      idempotencyKey: "application-page-capture-0001",
      body: pageBody,
    });
    expect(pageReplay.status).toBe(200);
    expect(pageReplay.headers.get("idempotency-replayed")).toBe("true");
    expect(pageReplay.body).toEqual(pageCreated.body);
    const captureId = pageCreated.body.record.id as string;
    expect((await fetchJson(origin, pagePath)).body.items).toHaveLength(1);
    expect((await fetchJson(origin, `${pagePath}/${captureId}`)).body.record.id).toBe(captureId);

    const scriptCreated = await fetchJson(origin, scriptPath, {
      method: "POST",
      idempotencyKey: "application-script-artifact-0001",
      body: scriptBody(),
    });
    expect(scriptCreated.status).toBe(201);
    expect(scriptCreated.headers.get("idempotency-replayed")).toBe("false");
    const scriptReplay = await fetchJson(origin, scriptPath, {
      method: "POST",
      idempotencyKey: "application-script-artifact-0001",
      body: scriptBody(),
    });
    expect(scriptReplay.status).toBe(201);
    expect(scriptReplay.headers.get("idempotency-replayed")).toBe("true");
    expect(scriptReplay.body).toEqual(scriptCreated.body);
    const scriptId = scriptCreated.body.record.id as string;
    const scripts = await fetchJson(origin, scriptPath);
    expect(scripts.body.items).toHaveLength(1);
    expect(scripts.body.items[0]).not.toHaveProperty("source");
    expect((await fetchJson(origin, `${scriptPath}/${scriptId}`)).body.record).toMatchObject({
      id: scriptId,
      source: "const captureStatus: number = 200;\nconsole.log(captureStatus);\n",
    });

    expect(state.pageAuthorizations).toContainEqual({
      missionId: MISSION_ID,
      runId: RUN_ID,
      capability: "manage_page_captures",
    });
    expect(state.scriptAuthorizations).toContainEqual({
      missionId: MISSION_ID,
      runId: RUN_ID,
      capability: "manage_script_artifacts",
    });
    expect((commandOs.database.prepare("SELECT COUNT(*) AS count FROM page_captures").get() as { count: number }).count).toBe(1);
    expect((commandOs.database.prepare("SELECT COUNT(*) AS count FROM script_artifacts").get() as { count: number }).count).toBe(1);

    commandOs.database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = ?").run(RUN_ID);
    const deniedPage = await fetchJson(origin, pagePath, {
      method: "POST",
      idempotencyKey: "application-page-capture-0002",
      body: { ...pageBody, contentHash: "e".repeat(64) },
    });
    expect(deniedPage.status).toBe(403);
    commandOs.database.prepare("UPDATE runs SET control_plane = 'ti_scale' WHERE id = ?").run(RUN_ID);
    commandOs.database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = ?").run(MISSION_ID);
    const deniedScript = await fetchJson(origin, scriptPath, {
      method: "POST",
      idempotencyKey: "application-script-artifact-0002",
      body: scriptBody("guided/legacy_controlled.ts"),
    });
    expect(deniedScript.status).toBe(403);
    expect((commandOs.database.prepare("SELECT COUNT(*) AS count FROM page_captures").get() as { count: number }).count).toBe(1);
    expect((commandOs.database.prepare("SELECT COUNT(*) AS count FROM script_artifacts").get() as { count: number }).count).toBe(1);

    expect((await fetchJson(origin, `${scriptPath}/${scriptId}/execute`, { method: "POST", body: {} })).status).toBe(404);
    expect((await fetchJson(origin, `${pagePath}/${captureId}/execute`, { method: "POST", body: {} })).status).toBe(404);
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PRODUCT_AGENT_REGISTRY } from "../../../agents";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../../db";
import {
  createOpenRouterConnectionRouter,
  loadOpenRouterConnectionConfiguration,
  OpenRouterConnectionService,
  OpenRouterConnectionStore,
  type OpenRouterReadinessRuntimeSnapshot,
} from "../index";

const KEY = "sk-or-v1-router-private-value-that-must-never-be-returned";
const NOW = "2026-07-24T11:00:00.000Z";
const servers: Server[] = [];
const databases: SqliteDatabase[] = [];
const roots: string[] = [];

function runtime(
  status: "disabled" | "ready" = "disabled",
): OpenRouterReadinessRuntimeSnapshot {
  const callable = status === "ready";
  return {
    status,
    configured: callable,
    authenticated: callable,
    callable,
    supportsGuided: callable,
    enforcesAutonomousBoundary: false,
    reportsExactTokenUsage: callable,
    reportsExactCostUsage: callable,
    ...(callable
      ? {
          requestedModel: "openai/gpt-5.2",
          returnedModel: "openai/gpt-5.2",
          lastCheckedAt: NOW,
          attestedAt: NOW,
          expiresAt: "2026-07-24T11:05:00.000Z",
        }
      : { lastCheckedAt: NOW }),
    reason: callable
      ? "The exact provider and model passed the bounded fixture attestation."
      : "No provider configuration is loaded by this fixture process.",
  };
}

function database(): SqliteDatabase {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-openrouter-router-"));
  roots.push(root);
  const db = createDatabaseConnection({
    filename: join(root, "state", "ti-scale.sqlite"),
  });
  migrateDatabase(db);
  databases.push(db);
  return db;
}

function configurationRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-openrouter-config-"));
  roots.push(root);
  return join(root, "provider-config");
}

async function listen(
  service: OpenRouterConnectionService,
): Promise<string> {
  const application = express();
  application.use(express.json());
  application.use(createOpenRouterConnectionRouter({
    service,
    resolveActor: (request) => request.get("x-test-actor") ?? undefined,
  }));
  const http = createServer(application);
  servers.push(http);
  await new Promise<void>((resolve) => http.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) =>
    new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const db of databases.splice(0)) db.close();
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("OpenRouter provider connection API", () => {
  test("authenticates, versions, and idempotently saves a secret-free restart-bound connection", async () => {
    const db = database();
    const store = new OpenRouterConnectionStore({ root: configurationRoot() });
    const service = new OpenRouterConnectionService({
      database: db,
      store,
      activeConfiguration: {
        state: "disabled",
        reasonCode: "not_configured",
        reason: "No provider is loaded.",
      },
      activeConfigurationSource: "none",
      activeConfigurationVersion: null,
      readRuntime: () => runtime(),
      refreshRuntime: async () => runtime(),
      publishRuntimeProjection: () => undefined,
      clock: () => new Date(NOW),
    });
    const base = await listen(service);

    const unauthenticated = await fetch(
      `${base}/api/v2/provider-connections/openrouter`,
    );
    expect(unauthenticated.status).toBe(401);

    const request = {
      enabled: true,
      model: "openai/gpt-5.2",
      credential: { action: "replace", value: KEY },
      expectedVersion: 0,
    };
    const saved = await fetch(`${base}/api/v2/provider-connections/openrouter`, {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        "idempotency-key": "openrouter-router-save-0001",
        "x-test-actor": "operator:test",
      },
      body: JSON.stringify(request),
    });
    expect(saved.status).toBe(201);
    const text = await saved.text();
    expect(text).not.toContain(KEY);
    const payload = JSON.parse(text) as Record<string, any>;
    expect(payload).toMatchObject({
      providerId: "openrouter",
      configuration: {
        source: "canonical_provider_config",
        version: 1,
        enabled: true,
        credentialConfigured: true,
        storage: "service_owned_mode_0600",
        browserStorage: false,
      },
      activation: {
        configuredVersion: 1,
        restartRequired: true,
        status: "restart_required",
      },
      planningCompatibility: {
        enforcementMode: "advisor_only",
        localExecutionAuthorityUnchanged: true,
      },
      mutation: { savedVersion: 1, replayed: false },
    });
    expect(payload.configuration).not.toHaveProperty("credentialSha256");
    expect(payload.configuration).not.toHaveProperty("credential");
    const durableSettings = db.prepare(
      "SELECT key, value_json FROM settings ORDER BY key",
    ).all() as readonly {
      readonly key: string;
      readonly value_json: string;
    }[];
    expect(JSON.stringify(durableSettings)).not.toContain(KEY);
    expect(payload.planningCompatibility.compatibleAgentIds).toEqual(
      PRODUCT_AGENT_REGISTRY.map(({ id }) => id),
    );
    expect(payload.planningCompatibility.compatibleAgentIds).toHaveLength(12);

    const replay = await fetch(`${base}/api/v2/provider-connections/openrouter`, {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        "idempotency-key": "openrouter-router-save-0001",
        "x-test-actor": "operator:test",
      },
      body: JSON.stringify(request),
    });
    expect(replay.status).toBe(200);
    expect(replay.headers.get("idempotency-replayed")).toBe("true");
    expect(await replay.json()).toMatchObject({
      configuration: { version: 1 },
      mutation: { savedVersion: 1, replayed: true },
    });
  });

  test("refreshes and republishes only the exact loaded canonical version", async () => {
    const root = configurationRoot();
    const preparingStore = new OpenRouterConnectionStore({ root });
    preparingStore.put({
      enabled: true,
      model: "openai/gpt-5.2",
      credential: { action: "replace", value: KEY },
      expectedVersion: 0,
    }, "operator:test", "openrouter-router-prepare-0001");
    const loaded = loadOpenRouterConnectionConfiguration({
      environment: { TI_SCALE_PROVIDER_CONFIG_ROOT: root },
    });
    let refreshes = 0;
    let publications = 0;
    const service = new OpenRouterConnectionService({
      database: database(),
      store: loaded.store,
      activeConfiguration: loaded.configuration,
      activeConfigurationSource: loaded.source,
      activeConfigurationVersion: loaded.activeConfigurationVersion,
      readRuntime: () => runtime("ready"),
      refreshRuntime: async () => {
        refreshes += 1;
        return runtime("ready");
      },
      publishRuntimeProjection: () => {
        publications += 1;
      },
      clock: () => new Date(NOW),
    });
    const base = await listen(service);
    const call = () => fetch(
      `${base}/api/v2/provider-connections/openrouter/attestation`,
      {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          "idempotency-key": "openrouter-router-attest-0001",
          "x-test-actor": "operator:test",
        },
        body: JSON.stringify({ expectedVersion: 1 }),
      },
    );

    const refreshed = await call();
    expect(refreshed.status).toBe(200);
    expect(await refreshed.json()).toMatchObject({
      providerId: "openrouter",
      replayed: false,
      connection: {
        activation: {
          activeConfigurationVersion: 1,
          configuredVersion: 1,
          restartRequired: false,
          status: "active",
        },
        planningCompatibility: {
          enforcementMode: "advisor_only",
          localExecutionAuthorityUnchanged: true,
        },
      },
    });
    expect(refreshes).toBe(1);
    expect(publications).toBe(1);
    expect(readdirSync(root).sort()).toEqual([
      "openrouter.credential",
      "openrouter.json",
    ]);
    expect(readdirSync(root).some((name) =>
      /(?:backup|previous|\.bak|\.old|~$)/iu.test(name))).toBe(false);

    const replay = await call();
    expect(replay.status).toBe(200);
    expect(await replay.json()).toMatchObject({ replayed: true });
    expect(refreshes).toBe(1);
    expect(publications).toBe(1);
  });
});

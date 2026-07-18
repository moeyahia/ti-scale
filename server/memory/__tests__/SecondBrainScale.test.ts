import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { performance } from "node:perf_hooks";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { createSecondBrainRouter } from "../SecondBrainRouter";

const NODE_COUNT = 50_000;
const EDGE_COUNT = NODE_COUNT - 1;
const ROOT_EDGE_COUNT = 999;
const SEARCH_SAMPLES = 20;
const NEIGHBORHOOD_SAMPLES = 20;
const SEARCH_P95_BUDGET_MS = 300;
const NEIGHBORHOOD_P95_BUDGET_MS = 200;
const GRAPH_SHELL_BUDGET_MS = 1_500;
const FIXTURE_TIME = "2026-07-17T00:00:00.000Z";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

interface NodeListResponse {
  readonly schemaVersion: "2.1";
  readonly items: readonly { readonly id: string; readonly title: string }[];
  readonly nextCursor: string | null;
  readonly totalReturned: number;
}

interface GraphResponse {
  readonly schemaVersion: "2.4";
  readonly view: "global" | "local";
  readonly rootNodeId?: string;
  readonly nodes: readonly { readonly id: string }[];
  readonly edges: readonly { readonly sourceNodeId: string; readonly targetNodeId: string }[];
  readonly availableNodeCount: number;
  readonly truncated: boolean;
}

function percentile95(samples: readonly number[]): number {
  const sorted = [...samples].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)] ?? Number.POSITIVE_INFINITY;
}

async function measuredJson<T>(url: string): Promise<{ readonly durationMs: number; readonly body: T }> {
  const startedAt = performance.now();
  const response = await fetch(url);
  const durationMs = performance.now() - startedAt;
  expect(response.status).toBe(200);
  return { durationMs, body: await response.json() as T };
}

function insertScaleGraph(database: ReturnType<typeof createDatabaseConnection>): number {
  const startedAt = performance.now();
  const insertNode = database.prepare(`
    INSERT INTO memory_nodes (
      id, node_type, title, summary, body, scope, engagement_id, mission_id,
      sensitivity, confidence, lifecycle_status, confirmation_state,
      provenance_json, author_type, author_id, version, retention_policy_json,
      expires_at, pinned, created_at, updated_at
    ) VALUES (?, 'technique', ?, ?, ?, 'global', NULL, NULL,
      'internal', 0.9, 'confirmed', 'confirmed', ?, 'import',
      'scale-fixture', 1, '{}', NULL, ?, ?, ?)
  `);
  const insertEdge = database.prepare(`
    INSERT INTO memory_edges (
      id, source_node_id, target_node_id, edge_type, title, summary, scope,
      sensitivity, confidence, lifecycle_status, provenance_json, explanation,
      author_type, author_id, version, expires_at, created_at, updated_at,
      engagement_id, mission_id
    ) VALUES (?, ?, ?, 'similar_to', 'Related scale node',
      'Bounded deterministic graph-neighborhood fixture', 'global', 'internal',
      0.8, 'confirmed', ?, 'Shares an indexed local neighborhood', 'import',
      'scale-fixture', 1, NULL, ?, ?, NULL, NULL)
  `);
  const provenance = JSON.stringify({
    method: "imported",
    explanation: "Deterministic non-sensitive Second Brain scale fixture",
    sources: [],
  });

  database.transaction(() => {
    for (let index = 0; index < NODE_COUNT; index += 1) {
      const ordinal = String(index).padStart(5, "0");
      const needle = index === 42_424 ? " unique scale needle alpha42424" : "";
      insertNode.run(
        `mem-scale-${ordinal}`,
        `Scale memory node ${ordinal}${needle}`,
        `Indexed operational memory ${ordinal}`,
        `Bounded local-first scale content for node ${ordinal}.`,
        provenance,
        index === 0 ? 1 : 0,
        FIXTURE_TIME,
        FIXTURE_TIME,
      );
    }
    for (let index = 1; index <= EDGE_COUNT; index += 1) {
      const ordinal = String(index).padStart(5, "0");
      const sourceOrdinal = index <= ROOT_EDGE_COUNT
        ? "00000"
        : String(index - 1).padStart(5, "0");
      insertEdge.run(
        `medge-scale-${ordinal}`,
        `mem-scale-${sourceOrdinal}`,
        `mem-scale-${ordinal}`,
        provenance,
        FIXTURE_TIME,
        FIXTURE_TIME,
      );
    }
  }).immediate();
  database.exec("ANALYZE memory_nodes; ANALYZE memory_edges; PRAGMA optimize;");
  return performance.now() - startedAt;
}

async function scaleApplication() {
  const directory = mkdtempSync(join(tmpdir(), "second-brain-scale-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(database);
  const seedDurationMs = insertScaleGraph(database);
  const app = express();
  app.use(express.json({ limit: "2mb" }));
  app.use(createSecondBrainRouter({
    database,
    vaultAllowedRoot: join(directory, "vaults"),
    resolveActor: () => "scale-benchmark",
    resolveAccess: () => ({ maximumSensitivity: "restricted", allEngagements: true }),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const port = (server.address() as AddressInfo).port;
  return { database, seedDurationMs, url: `http://127.0.0.1:${port}` };
}

describe("Second Brain 50,000-node scale contract", () => {
  test("keeps indexed search, progressive graph shell, and local neighborhoods within their budgets", async () => {
    const { database, seedDurationMs, url } = await scaleApplication();
    try {
      const count = database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get() as { count: number };
      const edgeCount = database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get() as { count: number };
      const ftsCount = database.prepare("SELECT COUNT(*) AS count FROM memory_nodes_fts").get() as { count: number };
      expect(Number(count.count)).toBe(NODE_COUNT);
      expect(Number(edgeCount.count)).toBe(EDGE_COUNT);
      expect(Number(ftsCount.count)).toBe(NODE_COUNT);

      const searchUrl = `${url}/api/v2/brain/nodes?query=${encodeURIComponent("alpha42424")}&limit=10`;
      const localUrl = `${url}/api/v2/brain/graph?view=local&nodeId=mem-scale-00000&depth=1&limit=250`;
      const globalUrl = `${url}/api/v2/brain/graph?view=global&depth=1&limit=250`;

      // Warm the prepared statements, SQLite page cache, FTS index, and HTTP
      // projection before collecting the p95 contract samples.
      await measuredJson<NodeListResponse>(searchUrl);
      await measuredJson<GraphResponse>(localUrl);

      const searchSamples: number[] = [];
      for (let index = 0; index < SEARCH_SAMPLES; index += 1) {
        const result = await measuredJson<NodeListResponse>(searchUrl);
        searchSamples.push(result.durationMs);
        expect(result.body.totalReturned).toBe(1);
        expect(result.body.items[0]?.id).toBe("mem-scale-42424");
      }

      const neighborhoodSamples: number[] = [];
      for (let index = 0; index < NEIGHBORHOOD_SAMPLES; index += 1) {
        const result = await measuredJson<GraphResponse>(localUrl);
        neighborhoodSamples.push(result.durationMs);
        expect(result.body.rootNodeId).toBe("mem-scale-00000");
        expect(result.body.nodes).toHaveLength(250);
        expect(result.body.availableNodeCount).toBe(ROOT_EDGE_COUNT + 1);
        expect(result.body.truncated).toBe(true);
        expect(result.body.edges.length).toBeGreaterThan(0);
      }

      const global = await measuredJson<GraphResponse>(globalUrl);
      expect(global.body.nodes).toHaveLength(250);
      expect(global.body.availableNodeCount).toBe(NODE_COUNT);
      expect(global.body.truncated).toBe(true);
      expect(global.durationMs).toBeLessThan(GRAPH_SHELL_BUDGET_MS);

      const searchP95 = percentile95(searchSamples);
      const neighborhoodP95 = percentile95(neighborhoodSamples);
      console.info(
        `[second-brain-scale] nodes=${NODE_COUNT} seed=${seedDurationMs.toFixed(1)}ms `
        + `search_p95=${searchP95.toFixed(1)}ms neighborhood_p95=${neighborhoodP95.toFixed(1)}ms `
        + `global_shell=${global.durationMs.toFixed(1)}ms`,
      );
      expect(searchP95).toBeLessThan(SEARCH_P95_BUDGET_MS);
      expect(neighborhoodP95).toBeLessThan(NEIGHBORHOOD_P95_BUDGET_MS);
    } finally {
      database.close();
    }
  }, 60_000);
});

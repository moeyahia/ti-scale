import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import type { SqliteDatabase } from "../../db/types";
import {
  getMemoryControlPolicy,
  updateMemoryControlPolicy,
  type MemoryControlPolicy,
} from "../MemoryControlPolicy";
import { MemoryRepository } from "../MemoryRepository";
import {
  createSecondBrainRouter,
  type MemoryAccessPolicy,
} from "../SecondBrainRouter";
import type { MemoryProvenance, MemoryScope, MemorySensitivity } from "../types";
import { ObsidianVaultBridge } from "../../vault/ObsidianVaultBridge";
import { VaultPathPolicy } from "../../vault/VaultPathPolicy";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function provenance(sourceId: string): MemoryProvenance {
  return {
    method: "operator_statement",
    explanation: "Confirmed by the authorized test operator",
    sources: [{
      sourceType: "message",
      sourceId,
      acquiredAt: "2026-07-15T10:00:00.000Z",
    }],
  };
}

function insertMission(
  database: SqliteDatabase,
  id: string,
  engagementId: string,
  journey: "autonomous" | "guided" = "guided",
): void {
  const now = "2026-07-15T10:00:00.000Z";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, engagement_id, created_by, created_at, updated_at
    ) VALUES (?, ?, 'Authorized privacy-boundary fixture', ?, ?, 'operator:test', ?, ?)
  `).run(id, id, journey, engagementId, now, now);
}

function addNode(
  repository: MemoryRepository,
  id: string,
  scope: MemoryScope,
  title: string,
  body: string,
  sensitivity: MemorySensitivity = "private",
) {
  return repository.createNode({
    id,
    nodeType: "technique",
    title,
    summary: `Evidence-backed memory for ${title}`,
    body,
    scope,
    sensitivity,
    confidence: 0.95,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: provenance(`source-${id}`),
    authorType: "operator",
    authorId: "operator:test",
  });
}

interface Fixture {
  readonly database: SqliteDatabase;
  readonly repository: MemoryRepository;
  readonly bridge: ObsidianVaultBridge;
  readonly vaultRoot: string;
  readonly url: string;
}

async function fixture(): Promise<Fixture> {
  const directory = mkdtempSync(join(tmpdir(), "brain-privacy-boundary-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(database);
  insertMission(database, "mission-a", "eng-a");
  insertMission(database, "mission-b", "eng-b", "autonomous");
  const repository = new MemoryRepository(database);
  addNode(
    repository,
    "node-global",
    { kind: "global" },
    "Global reusable method",
    "Globally reusable procedure body.",
  );
  addNode(
    repository,
    "node-a",
    { kind: "engagement", engagementId: "eng-a" },
    "Engagement A secret technique title",
    "ENGAGEMENT_A_CANONICAL_PRIVATE_BODY",
  );
  addNode(
    repository,
    "node-b",
    { kind: "engagement", engagementId: "eng-b" },
    "Engagement B private technique title",
    "ENGAGEMENT_B_CANONICAL_PRIVATE_BODY",
  );
  repository.createEdge({
    id: "edge-global-to-a",
    sourceNodeId: "node-global",
    targetNodeId: "node-a",
    edgeType: "applies_to",
    title: "Global method applies to engagement A",
    summary: "The global memory is related to a scoped memory",
    scope: { kind: "engagement", engagementId: "eng-a" },
    sensitivity: "private",
    confidence: 0.9,
    lifecycleStatus: "confirmed",
    provenance: provenance("source-edge-global-to-a"),
    explanation: "ENGAGEMENT_A_PRIVATE_EDGE_EXPLANATION",
    authorType: "operator",
    authorId: "operator:test",
  });

  const access = (value: string | undefined): MemoryAccessPolicy => {
    if (value === "all") {
      return { maximumSensitivity: "restricted", allEngagements: true };
    }
    if (value === "b") {
      return { maximumSensitivity: "private", engagementIds: ["eng-b"], missionIds: ["mission-b"] };
    }
    return { maximumSensitivity: "private", engagementIds: ["eng-a"], missionIds: ["mission-a"] };
  };
  const vaultRoot = join(directory, "vaults");
  const app = express();
  app.use(express.json({ limit: "2mb" }));
  app.use(createSecondBrainRouter({
    database,
    vaultAllowedRoot: vaultRoot,
    resolveActor: (request) => request.get("X-Test-Actor") ?? "operator:test",
    resolveAccess: (request) => access(request.get("X-Test-Access")),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    database,
    repository,
    bridge: new ObsidianVaultBridge(database, repository, new VaultPathPolicy(vaultRoot)),
    vaultRoot,
    url: `http://127.0.0.1:${port}`,
  };
}

async function responseJson(response: Response): Promise<Record<string, any>> {
  return response.json() as Promise<Record<string, any>>;
}

function mutationHeaders(key: string, access?: "all" | "b"): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "Idempotency-Key": key,
    ...(access ? { "X-Test-Access": access } : {}),
  };
}

async function connectVault(
  app: Fixture,
  name: string,
  options: { readonly access?: "all" | "b"; readonly syncScope?: Record<string, unknown> } = {},
): Promise<{ readonly id: string; readonly path: string }> {
  const response = await fetch(`${app.url}/api/v2/brain/vault/connect`, {
    method: "POST",
    headers: mutationHeaders(`connect-${name.toLowerCase().replaceAll(/[^a-z0-9]+/gu, "-")}-0001`, options.access),
    body: JSON.stringify({
      vaultPath: name,
      displayName: name,
      permissionGranted: true,
      ...(options.syncScope ? { syncScope: options.syncScope } : {}),
    }),
  });
  expect(response.status).toBe(201);
  const payload = await responseJson(response);
  return {
    id: String(payload.connection.id),
    path: join(app.vaultRoot, name),
  };
}

function replaceFirst(source: string, expected: string, replacement: string): string {
  const index = source.indexOf(expected);
  if (index < 0) throw new Error(`Fixture text was not found: ${expected}`);
  return `${source.slice(0, index)}${replacement}${source.slice(index + expected.length)}`;
}

function markdownFiles(root: string): readonly string[] {
  const files: string[] = [];
  const visit = (path: string): void => {
    if (!existsSync(path)) return;
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) visit(child);
      else if (entry.isFile() && entry.name.endsWith(".md")) files.push(child);
    }
  };
  visit(root);
  return files.sort();
}

function filesystemContains(root: string, marker: string): boolean {
  let found = false;
  const visit = (path: string): void => {
    if (found || !existsSync(path)) return;
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) visit(child);
      else if (entry.isFile() && readFileSync(child).includes(Buffer.from(marker, "utf8"))) {
        found = true;
        return;
      }
    }
  };
  visit(root);
  return found;
}

function logicalDatabaseText(database: SqliteDatabase): string {
  const tables = database.prepare(`
    SELECT name FROM sqlite_master
    WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
    ORDER BY name
  `).all() as Array<{ name: string }>;
  const snapshot: Record<string, unknown> = {};
  const quote = (value: string): string => `"${value.replaceAll('"', '""')}"`;
  for (const { name } of tables) {
    const columns = database.prepare(`PRAGMA table_info(${quote(name)})`).all() as Array<{
      name: string;
      type: string;
    }>;
    const textual = columns.filter((column) => (
      !column.type || /CHAR|CLOB|TEXT/iu.test(column.type)
    ));
    if (textual.length === 0) continue;
    snapshot[name] = database.prepare(
      `SELECT ${textual.map((column) => quote(column.name)).join(", ")} FROM ${quote(name)}`,
    ).all();
  }
  return JSON.stringify(snapshot);
}

function logicalDatabaseMarkerTables(database: SqliteDatabase, marker: string): readonly string[] {
  const tables = database.prepare(`
    SELECT name FROM sqlite_master
    WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
    ORDER BY name
  `).all() as Array<{ name: string }>;
  const quote = (value: string): string => `"${value.replaceAll('"', '""')}"`;
  const matches: string[] = [];
  for (const { name } of tables) {
    const columns = database.prepare(`PRAGMA table_info(${quote(name)})`).all() as Array<{
      name: string;
      type: string;
    }>;
    const textual = columns.filter((column) => !column.type || /CHAR|CLOB|TEXT/iu.test(column.type));
    if (textual.length === 0) continue;
    const rows = database.prepare(
      `SELECT ${textual.map((column) => quote(column.name)).join(", ")} FROM ${quote(name)}`,
    ).all();
    if (JSON.stringify(rows).includes(marker)) matches.push(name);
  }
  return matches;
}

function policyUpdate(
  current: MemoryControlPolicy,
  overrides: Partial<Pick<MemoryControlPolicy, "enabled" | "obsidianSyncScope">> = {},
): Record<string, unknown> {
  return {
    enabled: overrides.enabled ?? current.enabled,
    personalPreferencePolicy: current.personalPreferencePolicy,
    operationalMemoryEnabled: current.operationalMemoryEnabled,
    engagementIsolation: true,
    defaultRetentionDays: current.defaultRetentionDays,
    autonomousUse: current.autonomousUse,
    guidedUse: current.guidedUse,
    obsidianSyncScope: overrides.obsidianSyncScope ?? current.obsidianSyncScope,
    secretsNeverRetained: true,
  };
}

async function portableExport(
  app: Fixture,
  connectionId: string,
  key: string,
  access?: "all" | "b",
): Promise<{ readonly request: RequestInit; readonly payload: Record<string, any>; readonly archivePath: string }> {
  const request: RequestInit = {
    method: "POST",
    headers: mutationHeaders(key, access),
    body: JSON.stringify({ connectionId }),
  };
  const response = await fetch(`${app.url}/api/v2/brain/vault/portable-export`, request);
  expect(response.status).toBe(200);
  const payload = await responseJson(response);
  const connection = app.bridge.requireConnection(connectionId);
  return {
    request,
    payload,
    archivePath: join(connection.vaultPath, ".ti-scale", "exports", String(payload.result.archiveName)),
  };
}

describe("Second Brain privacy boundaries", () => {
  test("confirming an imported candidate and then forgetting it erases DB, caches, and the source projection", async () => {
    const app = await fixture();
    try {
      const connection = await connectVault(app, "Forget-Import-Vault", {
        syncScope: {
          nodeTypes: ["technique"],
          scopeKinds: ["engagement"],
          engagementIds: ["eng-a"],
          sensitivities: ["private"],
          lifecycleStatuses: ["confirmed"],
        },
      });
      const bodyMarker = "FORGET_IMPORTED_BODY_MARKER_8f73e5b2";
      const pathMarker = "forget-imported-path-marker-8f73e5b2";
      const relativePath = `00 Inbox/${pathMarker}.md`;
      let source = app.bridge.renderNode("node-a").text;
      source = replaceFirst(source, 'id: "node-a"', 'id: "imported-forget-candidate"');
      source = replaceFirst(source, "# Engagement A secret technique title", "# Imported memory to forget");
      source = replaceFirst(source, "ENGAGEMENT_A_CANONICAL_PRIVATE_BODY", bodyMarker);
      writeFileSync(join(connection.path, relativePath), source, "utf8");

      const imported = await fetch(`${app.url}/api/v2/brain/vault/import`, {
        method: "POST",
        headers: mutationHeaders("import-then-forget-0001"),
        body: JSON.stringify({ connectionId: connection.id, relativePath }),
      });
      expect(imported.status).toBe(200);
      const candidate = app.database.prepare(`
        SELECT id FROM memory_candidates WHERE title = 'Imported memory to forget'
      `).get() as { id: string };
      const confirmedResponse = await fetch(`${app.url}/api/v2/brain/candidates/${candidate.id}/confirm`, {
        method: "POST",
        headers: mutationHeaders("confirm-import-then-forget-0001"),
        body: "{}",
      });
      expect(confirmedResponse.status).toBe(201);
      const confirmed = await responseJson(confirmedResponse);
      const forgottenResponse = await fetch(`${app.url}/api/v2/brain/nodes/${confirmed.node.id}/forget`, {
        method: "POST",
        headers: mutationHeaders("forget-confirmed-import-0001"),
        body: JSON.stringify({ expectedVersion: confirmed.node.version, reason: "Operator requested erasure" }),
      });
      expect(forgottenResponse.status).toBe(200);

      const databaseText = logicalDatabaseText(app.database);
      const pathTables = logicalDatabaseMarkerTables(app.database, pathMarker);
      expect({
        bodyInDatabase: databaseText.includes(bodyMarker),
        pathInDatabase: databaseText.includes(pathMarker),
        pathTables,
        bodyOnFilesystem: filesystemContains(connection.path, bodyMarker),
        pathStillExists: existsSync(join(connection.path, relativePath)),
      }).toEqual({
        bodyInDatabase: false,
        pathInDatabase: false,
        pathTables: [],
        bodyOnFilesystem: false,
        pathStillExists: false,
      });
    } finally {
      app.database.close();
    }
  }, 15_000);

  test("reject-and-do-not-relearn removes candidate plaintext while retaining only a suppression hash", async () => {
    const app = await fixture();
    try {
      const marker = "REJECTED_CANDIDATE_PLAINTEXT_MARKER_74cb9831";
      app.repository.createCandidate({
        id: "candidate-reject-privacy",
        nodeType: "preference",
        title: `Rejected title ${marker}`,
        summary: `Rejected summary ${marker}`,
        body: `Rejected body ${marker}`,
        scope: { kind: "engagement", engagementId: "eng-a" },
        sensitivity: "private",
        confidence: 0.8,
        provenance: provenance(`source-${marker}`),
        proposedBy: "agent:test",
      });
      const rejected = await fetch(`${app.url}/api/v2/brain/candidates/candidate-reject-privacy/reject`, {
        method: "POST",
        headers: mutationHeaders("reject-candidate-privacy-0001"),
        body: JSON.stringify({ reason: "Operator rejected this candidate and prohibited relearning" }),
      });
      expect(rejected.status).toBe(200);
      const row = app.database.prepare(`
        SELECT title, summary, body, source_json, status
        FROM memory_candidates WHERE id = 'candidate-reject-privacy'
      `).get() as Record<string, unknown>;
      expect({
        status: row.status,
        retainedMarker: JSON.stringify(row).includes(marker),
        logicalDatabaseRetainedMarker: logicalDatabaseText(app.database).includes(marker),
      }).toEqual({
        status: "suppressed",
        retainedMarker: false,
        logicalDatabaseRetainedMarker: false,
      });
    } finally {
      app.database.close();
    }
  });

  test("vault and portable exports do not leak an inaccessible outgoing-edge target through a global node", async () => {
    const app = await fixture();
    try {
      const connection = await connectVault(app, "Engagement-B-Only-Export", { access: "b" });
      const exported = await fetch(`${app.url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: mutationHeaders("bulk-export-engagement-b-0001", "b"),
        body: JSON.stringify({ connectionId: connection.id }),
      });
      expect(exported.status).toBe(200);
      const portable = await portableExport(
        app,
        connection.id,
        "portable-export-engagement-b-0001",
        "b",
      );
      const vaultText = markdownFiles(connection.path)
        .map((path) => readFileSync(path, "utf8"))
        .join("\n");
      const archiveBytes = readFileSync(portable.archivePath);
      const forbidden = [
        "node-a",
        "Engagement A secret technique title",
        "ENGAGEMENT_A_CANONICAL_PRIVATE_BODY",
        "ENGAGEMENT_A_PRIVATE_EDGE_EXPLANATION",
      ];
      expect({
        leakedToVault: forbidden.filter((marker) => vaultText.includes(marker)),
        leakedToPortableArchive: forbidden.filter((marker) => archiveBytes.includes(Buffer.from(marker, "utf8"))),
      }).toEqual({ leakedToVault: [], leakedToPortableArchive: [] });
    } finally {
      app.database.close();
    }
  }, 15_000);

  test("connection syncScope governs targeted, bulk, import, sync, portable, and existing projections", async () => {
    const app = await fixture();
    try {
      const connection = await connectVault(app, "Scoped-Vault", { access: "all" });
      const initialB = await fetch(`${app.url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: mutationHeaders("scope-seed-node-b-0001", "all"),
        body: JSON.stringify({ connectionId: connection.id, nodeId: "node-b" }),
      });
      expect(initialB.status).toBe(200);
      const initialPayload = await responseJson(initialB);
      const oldBProjection = join(connection.path, String(initialPayload.result.relativePath));
      expect(existsSync(oldBProjection)).toBe(true);
      const initialBulkRequest = {
        method: "POST",
        headers: mutationHeaders("scope-bulk-replay-guard-0001", "all"),
        body: JSON.stringify({ connectionId: connection.id }),
      } as const;
      expect((await fetch(`${app.url}/api/v2/brain/vault/export`, initialBulkRequest)).status).toBe(200);

      const narrowedScope = {
        nodeTypes: ["technique"],
        scopeKinds: ["engagement"],
        engagementIds: ["eng-a"],
        sensitivities: ["private"],
        lifecycleStatuses: ["confirmed"],
      };
      app.database.prepare(`
        UPDATE vault_connections SET sync_scope_json = ?, updated_at = ? WHERE id = ?
      `).run(JSON.stringify(narrowedScope), new Date().toISOString(), connection.id);

      const staleBulkReplay = await fetch(`${app.url}/api/v2/brain/vault/export`, initialBulkRequest);

      const targetedExport = await fetch(`${app.url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: mutationHeaders("scope-targeted-export-denied-0001", "all"),
        body: JSON.stringify({ connectionId: connection.id, nodeId: "node-b" }),
      });
      const bulkExport = await fetch(`${app.url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: mutationHeaders("scope-bulk-export-0001", "all"),
        body: JSON.stringify({ connectionId: connection.id }),
      });
      expect(bulkExport.status).toBe(200);

      const targetedSync = await fetch(`${app.url}/api/v2/brain/vault/sync`, {
        method: "POST",
        headers: mutationHeaders("scope-targeted-sync-denied-0001", "all"),
        body: JSON.stringify({ connectionId: connection.id, nodeId: "node-b" }),
      });
      const bulkSync = await fetch(`${app.url}/api/v2/brain/vault/sync`, {
        method: "POST",
        headers: mutationHeaders("scope-bulk-sync-0001", "all"),
        body: JSON.stringify({ connectionId: connection.id }),
      });
      expect(bulkSync.status).toBe(200);

      const importPath = "00 Inbox/outside-connection-scope.md";
      writeFileSync(join(connection.path, importPath), app.bridge.renderNode("node-b").text, "utf8");
      const imported = await fetch(`${app.url}/api/v2/brain/vault/import`, {
        method: "POST",
        headers: mutationHeaders("scope-import-denied-0001", "all"),
        body: JSON.stringify({ connectionId: connection.id, relativePath: importPath }),
      });
      const portable = await portableExport(app, connection.id, "scope-portable-0001", "all");
      const portableBytes = readFileSync(portable.archivePath);

      expect({
        targetedExportDenied: targetedExport.status >= 400,
        staleBulkReplayDenied: staleBulkReplay.status === 404,
        targetedSyncDenied: targetedSync.status >= 400,
        importDenied: imported.status >= 400,
        portableContainsExcludedNode: portableBytes.includes(Buffer.from("node-b", "utf8")),
        portableContainsExcludedBody: portableBytes.includes(Buffer.from("ENGAGEMENT_B_CANONICAL_PRIVATE_BODY", "utf8")),
        excludedProjectionStillExistsAfterRevocation: existsSync(oldBProjection),
      }).toEqual({
        targetedExportDenied: true,
        staleBulkReplayDenied: true,
        targetedSyncDenied: true,
        importDenied: true,
        portableContainsExcludedNode: false,
        portableContainsExcludedBody: false,
        excludedProjectionStillExistsAfterRevocation: false,
      });
    } finally {
      app.database.close();
    }
  }, 15_000);

  test("a crafted accessible note cannot select or disclose an existing inaccessible canonical node", async () => {
    const app = await fixture();
    try {
      const connection = await connectVault(app, "Crafted-Existing-Id-Vault");
      const relativePath = "41 Attack Paths/crafted-existing-id.md";
      let crafted = app.bridge.renderNode("node-a").text;
      crafted = replaceFirst(crafted, 'id: "node-a"', 'id: "node-b"');
      crafted = replaceFirst(crafted, "ENGAGEMENT_A_CANONICAL_PRIVATE_BODY", "ATTACKER_CONTROLLED_NOTE_BODY");
      writeFileSync(join(connection.path, relativePath), crafted, "utf8");

      const response = await fetch(`${app.url}/api/v2/brain/vault/import`, {
        method: "POST",
        headers: mutationHeaders("crafted-existing-id-denied-0001"),
        body: JSON.stringify({ connectionId: connection.id, relativePath }),
      });
      const payload = await responseJson(response);
      const state = app.database.prepare(`
        SELECT id FROM vault_sync_state WHERE connection_id = ? AND node_id = 'node-b'
      `).get(connection.id);
      const sourceAfter = readFileSync(join(connection.path, relativePath), "utf8");
      expect({
        status: response.status,
        errorCode: payload.error?.code,
        responseLeakedNodeId: JSON.stringify(payload).includes("node-b"),
        responseLeakedTitle: JSON.stringify(payload).includes("Engagement B private technique title"),
        canonicalBodyWrittenToAttackerPath: sourceAfter.includes("ENGAGEMENT_B_CANONICAL_PRIVATE_BODY"),
        createdCanonicalSyncState: Boolean(state),
      }).toEqual({
        status: 404,
        errorCode: "brain_resource_not_found",
        responseLeakedNodeId: false,
        responseLeakedTitle: false,
        canonicalBodyWrittenToAttackerPath: false,
        createdCanonicalSyncState: false,
      });
    } finally {
      app.database.close();
    }
  });

  test("portable replay and download fail closed after Memory Control disables Obsidian sync", async () => {
    const app = await fixture();
    try {
      const connection = await connectVault(app, "Portable-Policy-Revocation");
      const portable = await portableExport(app, connection.id, "portable-policy-revoke-0001");
      const current = getMemoryControlPolicy(app.database);
      updateMemoryControlPolicy({
        database: app.database,
        expectedVersion: current.version,
        actor: "operator:test",
        policy: policyUpdate(current, { obsidianSyncScope: "disabled" }),
      });
      const replay = await fetch(`${app.url}/api/v2/brain/vault/portable-export`, portable.request);
      const download = await fetch(`${app.url}${portable.payload.result.downloadUrl}`);
      expect({ replay: replay.status, download: download.status }).toEqual({ replay: 404, download: 404 });
    } finally {
      app.database.close();
    }
  });

  test("portable replay and download fail closed after connection syncScope narrows", async () => {
    const app = await fixture();
    try {
      const connection = await connectVault(app, "Portable-Scope-Revocation");
      const portable = await portableExport(app, connection.id, "portable-scope-revoke-0001");
      app.database.prepare(`
        UPDATE vault_connections SET sync_scope_json = ?, updated_at = ? WHERE id = ?
      `).run(JSON.stringify({ engagementIds: ["eng-b"], scopeKinds: ["engagement"] }), new Date().toISOString(), connection.id);
      const replay = await fetch(`${app.url}/api/v2/brain/vault/portable-export`, portable.request);
      const download = await fetch(`${app.url}${portable.payload.result.downloadUrl}`);
      expect({ replay: replay.status, download: download.status }).toEqual({ replay: 404, download: 404 });
    } finally {
      app.database.close();
    }
  });

  test("portable replay and download are revoked after a retained node is corrected", async () => {
    const app = await fixture();
    try {
      const connection = await connectVault(app, "Portable-Correction-Revocation");
      const portable = await portableExport(app, connection.id, "portable-correction-revoke-0001");
      app.repository.correctNode("node-a", {
        body: "Operator-corrected canonical body with the stale material removed.",
        authorType: "operator",
        authorId: "operator:test",
        changeReason: "Redact stale memory from future projections",
      });
      const replay = await fetch(`${app.url}/api/v2/brain/vault/portable-export`, portable.request);
      const download = await fetch(`${app.url}${portable.payload.result.downloadUrl}`);
      expect({ replay: replay.status, download: download.status }).toEqual({ replay: 404, download: 404 });
    } finally {
      app.database.close();
    }
  });

  test("forgetting revokes portable replay/download and physically removes every managed archive containing the node", async () => {
    const app = await fixture();
    try {
      const connection = await connectVault(app, "Portable-Forget-Revocation");
      const portable = await portableExport(app, connection.id, "portable-forget-revoke-0001");
      expect(existsSync(portable.archivePath)).toBe(true);
      const current = app.repository.requireNode("node-a");
      const forgotten = await fetch(`${app.url}/api/v2/brain/nodes/node-a/forget`, {
        method: "POST",
        headers: mutationHeaders("forget-portable-node-0001"),
        body: JSON.stringify({ expectedVersion: current.version, reason: "Erase node and every managed export" }),
      });
      expect(forgotten.status).toBe(200);
      const replay = await fetch(`${app.url}/api/v2/brain/vault/portable-export`, portable.request);
      const download = await fetch(`${app.url}${portable.payload.result.downloadUrl}`);
      expect({
        replayDenied: replay.status >= 400,
        download: download.status,
        archiveStillExists: existsSync(portable.archivePath),
      }).toEqual({ replayDenied: true, download: 404, archiveStillExists: false });
    } finally {
      app.database.close();
    }
  }, 15_000);

  test("direct bridge/CLI-style portable archives are also physically removed by forgetting", async () => {
    const app = await fixture();
    try {
      const connection = await connectVault(app, "Portable-Direct-Forget");
      const direct = await app.bridge.createPortableExport(connection.id, ["node-a"], "operator:cli-test");
      expect(existsSync(direct.archivePath)).toBe(true);
      app.bridge.forgetMemory("node-a", "operator:test", "Erase all managed portable copies");
      expect(existsSync(direct.archivePath)).toBe(false);
    } finally {
      app.database.close();
    }
  });
});

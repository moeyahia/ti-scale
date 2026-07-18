import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createHash } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { existsSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db/index";
import { MemoryRepository } from "../MemoryRepository";
import { createSecondBrainRouter, type MemoryAccessPolicy } from "../SecondBrainRouter";
import type { MemoryNodeType, MemoryProvenance, MemoryScope } from "../types";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function provenance(id: string): MemoryProvenance {
  return {
    method: "operator_statement",
    explanation: "Confirmed by the authorized operator",
    sources: [{
      sourceType: "message",
      sourceId: id,
      acquiredAt: "2026-07-15T10:00:00.000Z",
    }],
  };
}

function projectionHash(nodeIds: readonly string[]): string {
  const canonical = `[${nodeIds.map((nodeId) => JSON.stringify(nodeId)).join(",")}]`;
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

function insertMission(
  database: ReturnType<typeof createDatabaseConnection>,
  id: string,
  engagementId: string,
  journey: "autonomous" | "guided" = "guided",
): void {
  const now = "2026-07-15T10:00:00.000Z";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, engagement_id, created_by, created_at, updated_at
    ) VALUES (?, ?, 'Authorized scope', ?, ?, 'operator', ?, ?)
  `).run(id, id, journey, engagementId, now, now);
}

function node(
  repository: MemoryRepository,
  id: string,
  scope: MemoryScope,
  title: string,
  nodeType: MemoryNodeType = "technique",
) {
  return repository.createNode({
    id,
    nodeType,
    title,
    summary: `Evidence-backed memory for ${title}`,
    body: `Procedure details for ${title}`,
    scope,
    sensitivity: "private",
    confidence: 0.9,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: provenance(`source-${id}`),
    authorType: "operator",
    authorId: "operator-route-test",
  });
}

async function application() {
  const directory = mkdtempSync(join(tmpdir(), "brain-router-test-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(database);
  insertMission(database, "mission-a", "eng-a");
  insertMission(database, "mission-b", "eng-b", "autonomous");
  const repository = new MemoryRepository(database);
  node(repository, "node-global", { kind: "global" }, "Global evidence method");
  node(repository, "node-a", { kind: "engagement", engagementId: "eng-a" }, "Engagement A credential path");
  node(repository, "node-b", { kind: "engagement", engagementId: "eng-b" }, "Engagement B credential path");
  node(repository, "node-mission-a", {
    kind: "mission",
    engagementId: "eng-a",
    missionId: "mission-a",
  }, "Mission A attack path");
  repository.createEdge({
    sourceNodeId: "node-global",
    targetNodeId: "node-a",
    edgeType: "applies_to",
    title: "Global method applies to engagement A",
    summary: "Scoped operational relationship",
    scope: { kind: "engagement", engagementId: "eng-a" },
    sensitivity: "private",
    confidence: 0.8,
    lifecycleStatus: "confirmed",
    provenance: provenance("edge-a"),
    explanation: "The evidence method was reused in this engagement",
    authorType: "operator",
  });
  repository.createCandidate({
    id: "candidate-a",
    nodeType: "preference",
    title: "Use deeper evidence explanations",
    summary: "Candidate Guided teaching preference",
    scope: { kind: "engagement", engagementId: "eng-a" },
    sensitivity: "private",
    confidence: 0.75,
    provenance: provenance("candidate-a-source"),
    proposedBy: "agent",
  });
  repository.createCandidate({
    id: "candidate-b",
    nodeType: "preference",
    title: "Engagement B preference",
    summary: "Must not cross the tenant boundary",
    scope: { kind: "engagement", engagementId: "eng-b" },
    sensitivity: "private",
    confidence: 0.75,
    provenance: provenance("candidate-b-source"),
    proposedBy: "agent",
  });

  const policy = (access: string | undefined): MemoryAccessPolicy => {
    if (access === "all") return { maximumSensitivity: "restricted", allEngagements: true };
    if (access === "b") return { maximumSensitivity: "private", engagementIds: ["eng-b"] };
    return { maximumSensitivity: "private", engagementIds: ["eng-a"], missionIds: ["mission-a"] };
  };
  const app = express();
  app.use(express.json({ limit: "2mb" }));
  app.use(createSecondBrainRouter({
    database,
    vaultAllowedRoot: join(directory, "vaults"),
    resolveActor: (request) => request.get("X-Test-Actor") ?? "operator-route-test",
    resolveAccess: (request) => policy(request.get("X-Test-Access")),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const port = (server.address() as AddressInfo).port;
  return { database, repository, directory, url: `http://127.0.0.1:${port}` };
}

async function json(response: Response): Promise<Record<string, any>> {
  return response.json() as Promise<Record<string, any>>;
}

describe("Second Brain HTTP boundary", () => {
  test("memory controls are versioned, idempotent, and cannot disable safety invariants", async () => {
    const { database, url } = await application();
    try {
      const initial = await json(await fetch(`${url}/api/v2/brain/control`));
      expect(initial.policy).toMatchObject({ version: 0, enabled: true, engagementIsolation: true, secretsNeverRetained: true });
      const request = {
        method: "PUT",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "memory-control-update-0001" },
        body: JSON.stringify({
          expectedVersion: 0,
          policy: {
            enabled: true,
            personalPreferencePolicy: "disabled",
            operationalMemoryEnabled: true,
            engagementIsolation: true,
            defaultRetentionDays: 90,
            autonomousUse: false,
            guidedUse: true,
            obsidianSyncScope: "confirmed",
            secretsNeverRetained: true,
          },
        }),
      };
      const saved = await json(await fetch(`${url}/api/v2/brain/control`, request));
      expect(saved.policy).toMatchObject({ version: 1, autonomousUse: false, personalPreferencePolicy: "disabled" });
      expect(await json(await fetch(`${url}/api/v2/brain/control`, request))).toEqual(saved);

      const unsafe = await fetch(`${url}/api/v2/brain/control`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "memory-control-unsafe-0001" },
        body: JSON.stringify({ expectedVersion: 1, policy: { ...saved.policy, engagementIsolation: false } }),
      });
      expect(unsafe.status).toBe(400);

      const candidateConfirm = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "confirm-disabled-preference-0001" },
        body: JSON.stringify({}),
      });
      expect(candidateConfirm.status).toBe(403);
      expect(await candidateConfirm.json()).toMatchObject({ error: { code: "memory_retention_disabled" } });
    } finally {
      database.close();
    }
  });

  test("summary, search, graph, and detail never leak another engagement", async () => {
    const { database, url } = await application();
    try {
      const summary = await json(await fetch(`${url}/api/v2/brain/summary`));
      expect(summary).toMatchObject({
        schemaVersion: "2.4",
        counts: { confirmed: 3, verified: 0, candidates: 1, edges: 1 },
        health: { database: "healthy", fts: "healthy" },
      });

      const nodes = await json(await fetch(`${url}/api/v2/brain/nodes?query=credential&limit=20`));
      expect(nodes.items.map((item: { id: string }) => item.id)).toEqual(["node-a"]);
      expect(JSON.stringify(nodes)).not.toContain("Engagement B");

      const graph = await json(await fetch(`${url}/api/v2/brain/graph?view=global&limit=50`));
      expect(graph.availableNodeCount).toBe(3);
      expect(graph.nodes.map((item: { id: string }) => item.id)).toContain("node-a");
      expect(graph.nodes.map((item: { id: string }) => item.id)).not.toContain("node-b");
      expect(graph.edges).toHaveLength(1);

      // The graph workspace expands its bounded view in 250-node increments.
      // Keep that public contract covered even when the fixture is smaller.
      const expandedGraph = await fetch(`${url}/api/v2/brain/graph?view=global&limit=500`);
      expect(expandedGraph.status).toBe(200);

      const denied = await fetch(`${url}/api/v2/brain/nodes/node-b`);
      expect(denied.status).toBe(404);
      expect(await denied.json()).toMatchObject({ error: { code: "memory_node_not_found" } });
      const detail = await json(await fetch(`${url}/api/v2/brain/nodes/node-a`));
      expect(detail.node).toMatchObject({ id: "node-a", scope: { engagementId: "eng-a" } });
      expect(detail.sources[0]).toMatchObject({ sourceId: "source-node-a" });
      expect(detail.versions).toHaveLength(1);
    } finally {
      database.close();
    }
  });

  test("graph metadata filters execute inside the bounded access-controlled query", async () => {
    const { database, repository, url } = await application();
    try {
      repository.createEdge({
        sourceNodeId: "node-global",
        targetNodeId: "node-b",
        edgeType: "similar_to",
        title: "Cross-engagement access-policy fixture",
        summary: "The inaccessible endpoint must never affect the visible local count.",
        scope: { kind: "engagement", engagementId: "eng-b" },
        sensitivity: "private",
        confidence: 0.7,
        lifecycleStatus: "confirmed",
        provenance: provenance("edge-hidden-local"),
        explanation: "Exercises access-controlled local-neighborhood counting.",
        authorType: "operator",
      });
      const local = await json(await fetch(`${url}/api/v2/brain/graph?view=local&nodeId=node-global&depth=1&limit=1`));
      expect(local).toMatchObject({ availableNodeCount: 2, truncated: true });
      expect(local.nodes.map((item: { id: string }) => item.id)).toEqual(["node-global"]);
      const localAll = await json(await fetch(`${url}/api/v2/brain/graph?view=local&nodeId=node-global&depth=1&limit=50`, {
        headers: { "X-Test-Access": "all" },
      }));
      expect(localAll.availableNodeCount).toBe(3);

      const relationship = await json(await fetch(`${url}/api/v2/brain/graph?view=global&edgeType=applies_to&limit=50`));
      expect(relationship.availableNodeCount).toBe(2);
      expect(relationship.nodes.map((item: { id: string }) => item.id).sort()).toEqual(["node-a", "node-global"]);
      expect(relationship.edges.map((item: { edgeType: string }) => item.edgeType)).toEqual(["applies_to"]);

      const scoped = await json(await fetch(`${url}/api/v2/brain/graph?view=global&scope=engagement&engagementId=eng-a&status=confirmed&minConfidence=0.75&limit=50`));
      expect(scoped.availableNodeCount).toBe(1);
      expect(scoped.nodes.map((item: { id: string }) => item.id)).toEqual(["node-a"]);
      expect(JSON.stringify(scoped)).not.toContain("Engagement B");

      const future = await json(await fetch(`${url}/api/v2/brain/graph?view=global&updatedAfter=2099-01-01T00%3A00%3A00.000Z&limit=50`));
      expect(future.availableNodeCount).toBe(0);
      expect(future.nodes).toEqual([]);
      node(repository, "lesson-a", { kind: "engagement", engagementId: "eng-a" }, "Engagement A recovery lesson", "lesson");
      const preset = await json(await fetch(`${url}/api/v2/brain/graph?view=global&preset=lessons_failures&limit=50`));
      expect(preset.availableNodeCount).toBe(1);
      expect(preset.nodes.map((item: { id: string }) => item.id)).toEqual(["lesson-a"]);
      expect(preset.edges).toEqual([]);

      const invalidConfidence = await fetch(`${url}/api/v2/brain/graph?view=global&minConfidence=1.5`);
      expect(invalidConfidence.status).toBe(400);
      const inheritedPreset = await fetch(`${url}/api/v2/brain/graph?view=global&preset=constructor`);
      expect(inheritedPreset.status).toBe(400);
      const invalidRange = await fetch(`${url}/api/v2/brain/graph?view=global&updatedAfter=2026-07-15T00%3A00%3A00Z&updatedBefore=2026-07-01T00%3A00%3A00Z`);
      expect(invalidRange.status).toBe(400);
    } finally {
      database.close();
    }
  });

  test("candidate consent mutations require idempotency and cannot cross scope", async () => {
    const { database, repository, url } = await application();
    try {
      const inbox = await json(await fetch(`${url}/api/v2/brain/candidates`));
      expect(inbox.items.map((item: { id: string }) => item.id)).toEqual(["candidate-a"]);

      const missingKey = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(missingKey.status).toBe(400);
      expect(await missingKey.json()).toMatchObject({ error: { code: "idempotency_key_required" } });

      const mutation = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "confirm-candidate-a-0001",
        },
        body: JSON.stringify({ edits: { summary: "Operator-confirmed deep evidence preference" } }),
      };
      const first = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, mutation);
      expect(first.status).toBe(201);
      const confirmed = await json(first);
      expect(confirmed.node).toMatchObject({ nodeType: "preference", lifecycleStatus: "confirmed" });
      const replay = await json(await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, mutation));
      expect(replay).toEqual(confirmed);

      const revokedReplay = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, {
        ...mutation,
        headers: { ...mutation.headers, "X-Test-Access": "b" },
      });
      expect(revokedReplay.status).toBe(404);
      const revokedBody = await json(revokedReplay);
      expect(revokedBody).toMatchObject({ error: { category: "not_found" } });
      expect(JSON.stringify(revokedBody)).not.toContain("Operator-confirmed deep evidence preference");
      expect(repository.getNode(confirmed.node.id)).toMatchObject({ version: 1 });

      const otherActor = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, {
        ...mutation,
        headers: { ...mutation.headers, "X-Test-Actor": "operator-route-test-other" },
      });
      expect(otherActor.status).toBe(409);
      expect(JSON.stringify(await otherActor.json())).not.toContain("Operator-confirmed deep evidence preference");

      const denied = await fetch(`${url}/api/v2/brain/candidates/candidate-b/confirm`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "confirm-candidate-b-0001",
        },
        body: JSON.stringify({}),
      });
      expect(denied.status).toBe(404);

      repository.createCandidate({
        id: "candidate-b-plain-reject",
        nodeType: "preference",
        title: "Incorrect engagement B preference",
        summary: "Reject without creating a durable relearning suppression",
        scope: { kind: "engagement", engagementId: "eng-b" },
        sensitivity: "private",
        confidence: 0.7,
        provenance: provenance("candidate-b-plain-source"),
        proposedBy: "agent",
      });
      const plainRejected = await fetch(`${url}/api/v2/brain/candidates/candidate-b-plain-reject/reject`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "reject-candidate-b-plain-0001",
          "X-Test-Access": "b",
        },
        body: JSON.stringify({
          reason: "Operator rejected this candidate without suppressing a future corrected observation",
          doNotRelearn: false,
        }),
      });
      expect(plainRejected.status).toBe(200);
      expect(await json(plainRejected)).toMatchObject({
        candidateId: "candidate-b-plain-reject",
        status: "rejected",
      });
      expect(repository.requireCandidate("candidate-b-plain-reject")).toMatchObject({
        status: "rejected",
        reviewedBy: "operator-route-test",
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_suppressions").get()).toEqual({ count: 0 });

      const rejectRequest = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "reject-candidate-b-0001",
          "X-Test-Access": "b",
        },
        body: JSON.stringify({ reason: "Operator rejected this engagement-specific preference" }),
      };
      const rejected = await fetch(`${url}/api/v2/brain/candidates/candidate-b/reject`, rejectRequest);
      expect(rejected.status).toBe(200);
      const rejectedBody = await json(rejected);
      expect(rejectedBody.status).toBe("suppressed");
      expect(typeof rejectedBody.suppressionId).toBe("string");
      const suppressionId = rejectedBody.suppressionId as string;
      expect(suppressionId.length).toBeGreaterThan(0);
      const rejectedReplay = await fetch(`${url}/api/v2/brain/candidates/candidate-b/reject`, {
        ...rejectRequest,
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "reject-candidate-b-0001",
        },
      });
      expect(rejectedReplay.status).toBe(404);
      expect(JSON.stringify(await rejectedReplay.json())).not.toContain(suppressionId);
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_suppressions").get()).toEqual({ count: 1 });
    } finally {
      database.close();
    }
  });

  test("run-filtered candidates require exact canonical provenance and remain scope isolated", async () => {
    const { database, repository, url } = await application();
    try {
      const now = "2026-07-15T10:00:00.000Z";
      const insertRun = database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES (?, ?, ?, 'completed', ?, ?)
      `);
      insertRun.run("run-a-one", "mission-a", "guided", now, now);
      insertRun.run("run-a-two", "mission-a", "guided", now, now);
      insertRun.run("run-b-one", "mission-b", "autonomous", now, now);
      insertMission(database, "mission-a-other", "eng-a");
      const insertConversation = database.prepare(`
        INSERT INTO conversations (id, mission_id, run_id, conversation_type, created_at, updated_at)
        VALUES (?, ?, ?, 'guided', ?, ?)
      `);
      insertConversation.run("conversation-a-one", "mission-a", "run-a-one", now, now);
      insertConversation.run("conversation-a-two", "mission-a", "run-a-two", now, now);
      insertConversation.run("conversation-b-one", "mission-b", "run-b-one", now, now);
      const insertMessage = database.prepare(`
        INSERT INTO messages (id, conversation_id, role, body, created_at)
        VALUES (?, ?, 'assistant', 'Bounded reusable insight', ?)
      `);
      insertMessage.run("message-a-one", "conversation-a-one", now);
      insertMessage.run("message-a-two", "conversation-a-two", now);
      insertMessage.run("message-b-one", "conversation-b-one", now);
      for (const [id, missionId, messageId] of [
        ["candidate-run-a-one", "mission-a", "message-a-one"],
        ["candidate-run-a-two", "mission-a", "message-a-two"],
        ["candidate-run-b-one", "mission-b", "message-b-one"],
      ] as const) {
        repository.createCandidate({
          id,
          nodeType: "procedure",
          title: `Procedure from ${id}`,
          summary: "Reviewable exact-run procedure",
          scope: id === "candidate-run-a-one"
            ? { kind: "engagement", engagementId: "eng-a" }
            : { kind: "mission", missionId },
          sensitivity: "private",
          confidence: 0.8,
          provenance: {
            method: "operator_statement",
            explanation: "Created from one exact Guided message.",
            sources: [{ sourceType: "message", sourceId: messageId, acquiredAt: now }],
          },
          proposedBy: "operator-route-test",
        });
      }

      for (const [id, scope, messageId] of [
        ["candidate-run-a-global", { kind: "global" }, "message-a-one"],
        ["candidate-run-a-wrong-mission", {
          kind: "mission",
          engagementId: "eng-a",
          missionId: "mission-a-other",
        }, "message-a-one"],
        ["candidate-run-a-wrong-engagement", {
          kind: "engagement",
          engagementId: "eng-b",
        }, "message-a-one"],
        ["candidate-global-other-run", { kind: "global" }, "message-a-two"],
      ] as const) {
        repository.createCandidate({
          id,
          nodeType: "procedure",
          title: `Procedure from ${id}`,
          summary: "Reviewable scope-isolation procedure",
          scope,
          sensitivity: "private",
          confidence: 0.8,
          provenance: {
            method: "operator_statement",
            explanation: "Created from one exact Guided message.",
            sources: [{ sourceType: "message", sourceId: messageId, acquiredAt: now }],
          },
          proposedBy: "operator-route-test",
        });
      }

      const exact = await json(await fetch(`${url}/api/v2/brain/candidates?missionId=mission-a&runId=run-a-one`, {
        headers: { "X-Test-Access": "all" },
      }));
      expect(exact.items.map((item: { id: string }) => item.id).sort()).toEqual([
        "candidate-run-a-global",
        "candidate-run-a-one",
      ]);
      expect(JSON.stringify(exact)).not.toContain("candidate-run-a-two");
      expect(JSON.stringify(exact)).not.toContain("candidate-run-b-one");
      expect(JSON.stringify(exact)).not.toContain("candidate-run-a-wrong-mission");
      expect(JSON.stringify(exact)).not.toContain("candidate-run-a-wrong-engagement");
      expect(JSON.stringify(exact)).not.toContain("candidate-global-other-run");

      const inaccessible = await json(await fetch(`${url}/api/v2/brain/candidates?runId=run-b-one`));
      expect(inaccessible.items).toEqual([]);
      const mismatched = await json(await fetch(`${url}/api/v2/brain/candidates?missionId=mission-a&runId=run-b-one`, {
        headers: { "X-Test-Access": "all" },
      }));
      expect(mismatched.items).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("versioned node mutations reject stale writes and forgetting is idempotent", async () => {
    const { database, url } = await application();
    try {
      const correctedResponse = await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "correct-node-a-0001",
        },
        body: JSON.stringify({
          expectedVersion: 1,
          summary: "Corrected engagement A memory",
          reason: "Operator corrected the summary",
        }),
      });
      expect(correctedResponse.status).toBe(200);
      const corrected = await json(correctedResponse);
      expect(corrected.node).toMatchObject({ version: 2, summary: "Corrected engagement A memory" });

      const stale = await fetch(`${url}/api/v2/brain/nodes/node-a/pin`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "pin-node-a-stale-0001",
        },
        body: JSON.stringify({ expectedVersion: 1, pinned: true }),
      });
      expect(stale.status).toBe(409);

      const forgetRequest = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "forget-node-a-0001",
        },
        body: JSON.stringify({ expectedVersion: 2, reason: "Privacy request" }),
      };
      const forgotten = await json(await fetch(`${url}/api/v2/brain/nodes/node-a/forget`, forgetRequest));
      expect(forgotten.result).toMatchObject({ nodeId: "node-a", removed: { versions: 2 } });
      const replay = await json(await fetch(`${url}/api/v2/brain/nodes/node-a/forget`, forgetRequest));
      expect(replay).toEqual(forgotten);
      expect((await fetch(`${url}/api/v2/brain/nodes/node-a`)).status).toBe(200);
      expect((await json(await fetch(`${url}/api/v2/brain/nodes/node-a`))).node.lifecycleStatus).toBe("forgotten");
    } finally {
      database.close();
    }
  });

  test("cached node mutations reauthorize the current canonical resource before replay", async () => {
    const { database, repository, url } = await application();
    try {
      const request = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "correct-node-resource-reauth-0001",
        },
        body: JSON.stringify({
          expectedVersion: 1,
          summary: "Scoped result that must not survive revoked access",
          reason: "Exercise replay authorization",
        }),
      };
      const firstResponse = await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, request);
      expect(firstResponse.status).toBe(200);
      const first = await json(firstResponse);
      expect(first.node).toMatchObject({ id: "node-a", version: 2 });
      expect(await json(await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, request))).toEqual(first);

      repository.correctNode("node-a", {
        scope: { kind: "engagement", engagementId: "eng-b" },
        authorType: "operator",
        authorId: "scope-administrator",
        changeReason: "Resource moved outside the original operator scope",
      });
      const denied = await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, request);
      expect(denied.status).toBe(404);
      const deniedBody = await json(denied);
      expect(deniedBody).toMatchObject({ error: { category: "not_found" } });
      expect(JSON.stringify(deniedBody)).not.toContain("Scoped result that must not survive revoked access");
      expect(repository.getNode("node-a")).toMatchObject({ version: 3, scope: { engagementId: "eng-b" } });
    } finally {
      database.close();
    }
  });

  test("context-pack detail enforces mission scope and exposes concise use explanations", async () => {
    const { database, repository, url } = await application();
    try {
      const item = repository.requireNode("node-mission-a");
      const pack = repository.persistContextPack({
        id: "ctx-route-a",
        missionId: "mission-a",
        journey: "guided",
        purpose: "Explain the next step",
        scopePolicy: {
          engagementId: "eng-a",
          missionId: "mission-a",
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node: item, score: 1, relevanceReason: "Same mission", signals: ["exact"] }],
      });
      repository.setContextItemDisposition(pack.id, {
        nodeId: item.id,
        used: true,
        relevanceReason: "Same mission and phase",
        influenceSummary: "Expanded the evidence validation guidance",
      });
      repository.persistContextPack({
        id: "ctx-route-b",
        missionId: "mission-b",
        journey: "autonomous",
        purpose: "Hidden engagement planning context",
        scopePolicy: {
          engagementId: "eng-b",
          missionId: "mission-b",
          journey: "autonomous",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node: repository.requireNode("node-b"), score: 1, relevanceReason: "Other engagement", signals: ["exact"] }],
      });
      database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES ('run-b', 'mission-b', 'autonomous', 'planning', ?, ?)
      `).run("2026-07-15T10:00:00.000Z", "2026-07-15T10:00:00.000Z");
      repository.persistContextPack({
        id: "ctx-route-b-linked",
        runId: "run-b",
        journey: "autonomous",
        purpose: "Run-linked hidden engagement planning context",
        scopePolicy: {
          engagementId: "eng-b",
          missionId: "mission-b",
          journey: "autonomous",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node: repository.requireNode("node-b"), score: 1, relevanceReason: "Other engagement run", signals: ["exact"] }],
      });
      database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES ('run-a', 'mission-a', 'guided', 'planning', ?, ?)
      `).run("2026-07-15T10:00:00.000Z", "2026-07-15T10:00:00.000Z");
      repository.persistContextPack({
        id: "ctx-route-a-linked",
        runId: "run-a",
        journey: "guided",
        purpose: "Run-linked visible planning context",
        scopePolicy: {
          engagementId: "eng-a",
          missionId: "mission-a",
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node: item, score: 1, relevanceReason: "Same engagement run", signals: ["exact"] }],
      });
      const summaryA = await json(await fetch(`${url}/api/v2/brain/summary`));
      const summaryB = await json(await fetch(`${url}/api/v2/brain/summary`, {
        headers: { "X-Test-Access": "b" },
      }));
      expect(summaryA.counts.contextPacks).toBe(2);
      expect(summaryB.counts.contextPacks).toBe(2);
      const listed = await json(await fetch(`${url}/api/v2/brain/context-packs?missionId=mission-a`));
      expect(listed.schemaVersion).toBe("2.4");
      expect(listed.totalReturned).toBe(2);
      expect(listed.items.map((entry: { id: string }) => entry.id).sort()).toEqual(["ctx-route-a", "ctx-route-a-linked"]);
      expect(listed.items.find((entry: { id: string }) => entry.id === "ctx-route-a")).toMatchObject({
        missionId: "mission-a", journey: "guided", purpose: "Explain the next step",
        retrievedItemCount: 1, usedItemCount: 1, correctedItemCount: 0,
      });
      expect(listed.items.find((entry: { id: string }) => entry.id === "ctx-route-a-linked"))
        .toMatchObject({ missionId: "mission-a", runId: "run-a" });
      const visibleToA = JSON.stringify(await json(await fetch(`${url}/api/v2/brain/context-packs`)));
      expect(visibleToA).not.toContain("ctx-route-b");
      expect(visibleToA).not.toContain("ctx-route-b-linked");
      const detail = await json(await fetch(`${url}/api/v2/brain/context-packs/${pack.id}`));
      expect(detail.items[0]).toMatchObject({
        used: true,
        influenceSummary: "Expanded the evidence validation guidance",
        node: { id: "node-mission-a" },
      });
      const denied = await fetch(`${url}/api/v2/brain/context-packs/${pack.id}`, { headers: { "X-Test-Access": "b" } });
      expect(denied.status).toBe(404);
      const linkedDenied = await fetch(`${url}/api/v2/brain/context-packs/ctx-route-b-linked`);
      expect(linkedDenied.status).toBe(404);
      const engagementB = await json(await fetch(`${url}/api/v2/brain/context-packs`, { headers: { "X-Test-Access": "b" } }));
      expect(engagementB.items.map((item: { id: string }) => item.id).sort()).toEqual(["ctx-route-b", "ctx-route-b-linked"]);
    } finally {
      database.close();
    }
  });

  test("vault connection remains inside the configured root", async () => {
    const { database, directory, url } = await application();
    try {
      const health = await fetch(`${url}/api/v2/brain/vault/health-check`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "health-vault-safe-0001",
        },
        body: JSON.stringify({
          vaultPath: "Operator-Brain",
          permissionGranted: true,
        }),
      });
      expect(health.status).toBe(200);
      expect(await json(health)).toMatchObject({
        result: {
          status: "healthy",
          vaultPath: "Operator-Brain",
          checks: { write: true, read: true, rename: true, delete: true },
        },
      });
      expect(readdirSync(join(directory, "vaults", "Operator-Brain"))
        .some((entry) => /^\.ti-scale-health-/u.test(entry))).toBe(false);
      const connect = await fetch(`${url}/api/v2/brain/vault/connect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "connect-vault-safe-0001",
        },
        body: JSON.stringify({
          vaultPath: "Operator-Brain",
          displayName: "Operator Brain",
          permissionGranted: true,
        }),
      });
      expect(connect.status).toBe(201);
      const connected = await json(connect);
      expect(connected).toMatchObject({ connection: { vaultPath: "Operator-Brain", status: "connected" } });

      const exportRequest = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "export-vault-safe-0001",
        },
        body: JSON.stringify({ connectionId: connected.connection.id }),
      };
      const exported = await fetch(`${url}/api/v2/brain/vault/export`, exportRequest);
      expect(exported.status).toBe(200);
      const exportedPayload = await json(exported);
      expect(exportedPayload).toMatchObject({ result: { connectionId: connected.connection.id, status: "synced" } });
      expect(await json(await fetch(`${url}/api/v2/brain/vault/export`, exportRequest))).toEqual(exportedPayload);
      const revokedExportReplay = await fetch(`${url}/api/v2/brain/vault/export`, {
        ...exportRequest,
        headers: { ...exportRequest.headers, "X-Test-Access": "b" },
      });
      expect(revokedExportReplay.status).toBe(404);
      expect(JSON.stringify(await revokedExportReplay.json())).not.toContain("Exported 3 accessible canonical notes");
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'memory.exported' AND resource_type = 'memory_node'
      `).get()).toEqual({ count: 3 });
      const snapshot = await json(await fetch(`${url}/api/v2/brain/vault`));
      expect(snapshot.syncStates.length).toBe(3);
      expect(snapshot.connections[0]).toMatchObject({
        status: "connected",
        healthChecks: { write: true, read: true, rename: true, delete: true },
        trackedNoteCount: 3,
        needsReviewCount: 0,
      });
      expect(typeof snapshot.connections[0].lastHealthCheckAt).toBe("string");
      expect(JSON.stringify(snapshot)).not.toContain(join(directory, "vaults"));

      const insertAggregateFixture = database.prepare(`
        INSERT INTO vault_sync_state (
          id, connection_id, relative_path, status, last_scanned_at
        ) VALUES (?, ?, ?, ?, ?)
      `);
      database.transaction(() => {
        for (let index = 0; index < 260; index += 1) {
          insertAggregateFixture.run(
            `aggregate-fixture-${index}`,
            connected.connection.id,
            `.ti-scale/quarantine/aggregate-fixture-${index}.md`,
            index === 0 ? "quarantined" : "synced",
            "2026-07-16T22:00:00.000Z",
          );
        }
      })();
      const aggregateSnapshot = await json(await fetch(`${url}/api/v2/brain/vault`, {
        headers: { "X-Test-Access": "all" },
      }));
      expect(aggregateSnapshot.syncStates).toHaveLength(250);
      expect(aggregateSnapshot.connections[0]).toMatchObject({
        trackedNoteCount: 263,
        needsReviewCount: 1,
      });
      database.prepare("DELETE FROM vault_sync_state WHERE id LIKE 'aggregate-fixture-%'").run();

      const audits = database.prepare(`
        SELECT action, resource_type, details_json FROM audit_records
        WHERE action IN ('vault.health.verified', 'vault.connection.connected')
        ORDER BY rowid
      `).all() as Array<{ action: string; resource_type: string; details_json: string }>;
      expect(audits.map((item) => [item.action, item.resource_type])).toEqual([
        ["vault.health.verified", "vault_path_candidate"],
        ["vault.health.verified", "vault_connection"],
        ["vault.connection.connected", "vault_connection"],
      ]);
      expect(JSON.stringify(audits)).not.toContain(join(directory, "vaults"));

      const synchronized = await fetch(`${url}/api/v2/brain/vault/sync`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "sync-vault-safe-0001",
        },
        body: JSON.stringify({ connectionId: connected.connection.id }),
      });
      expect(synchronized.status).toBe(200);
      expect(await synchronized.json()).toMatchObject({ result: { status: "synced" } });

      const traversal = await fetch(`${url}/api/v2/brain/vault/connect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "connect-vault-escape-0001",
        },
        body: JSON.stringify({
          vaultPath: "../../outside",
          displayName: "Outside",
          permissionGranted: true,
        }),
      });
      expect([400, 403]).toContain(traversal.status);
      expect(JSON.stringify(await traversal.json())).not.toContain(directory.replaceAll("\\", "/"));
    } finally {
      database.close();
    }
  });

  test("generic Vault export cannot bypass the exact approved legacy projection", async () => {
    const { database, url } = await application();
    try {
      database.exec(`
        CREATE TABLE legacy_migration_runs (
          id TEXT PRIMARY KEY,
          status TEXT NOT NULL,
          source_roots_json TEXT NOT NULL,
          database_path TEXT NOT NULL,
          output_directory TEXT NOT NULL,
          started_at TEXT NOT NULL,
          completed_at TEXT
        ) STRICT;
        CREATE TABLE legacy_migration_reconciliation (
          migration_id TEXT PRIMARY KEY,
          report_json TEXT NOT NULL,
          report_hash TEXT NOT NULL,
          created_at TEXT NOT NULL
        ) STRICT;
        CREATE TABLE legacy_engagement_brain_nodes (
          migration_id TEXT NOT NULL,
          manifest_id TEXT NOT NULL,
          node_id TEXT NOT NULL,
          created_at TEXT NOT NULL,
          PRIMARY KEY (migration_id, node_id)
        ) STRICT;
        CREATE TABLE legacy_vault_projection_approvals (
          id TEXT PRIMARY KEY,
          migration_id TEXT NOT NULL,
          reconciliation_hash TEXT NOT NULL,
          projection_hash TEXT NOT NULL,
          connection_id TEXT NOT NULL,
          approved_by TEXT NOT NULL,
          status TEXT NOT NULL,
          projected_node_ids_json TEXT NOT NULL,
          result_json TEXT,
          approved_at TEXT NOT NULL,
          completed_at TEXT
        ) STRICT;
      `);
      const migrationId = "migration-vault-export-gate";
      const reconciliationHash = "a".repeat(64);
      const now = "2026-07-17T16:00:00.000Z";
      database.prepare(`
        INSERT INTO legacy_migration_runs (
          id, status, source_roots_json, database_path, output_directory,
          started_at, completed_at
        ) VALUES (?, 'completed', '[]', '/redacted/database', '/redacted/output', ?, ?)
      `).run(migrationId, now, now);
      database.prepare(`
        INSERT INTO legacy_migration_reconciliation (
          migration_id, report_json, report_hash, created_at
        ) VALUES (?, '{}', ?, ?)
      `).run(migrationId, reconciliationHash, now);
      database.prepare(`
        INSERT INTO legacy_engagement_brain_nodes (
          migration_id, manifest_id, node_id, created_at
        ) VALUES (?, 'manifest-vault-export-gate', 'node-a', ?)
      `).run(migrationId, now);

      const connectedResponse = await fetch(`${url}/api/v2/brain/vault/connect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "connect-legacy-export-gate-0001",
        },
        body: JSON.stringify({
          vaultPath: "Legacy-Export-Gate",
          displayName: "Legacy Export Gate",
          permissionGranted: true,
        }),
      });
      expect(connectedResponse.status).toBe(201);
      const connected = await json(connectedResponse);
      const connectionId = String(connected.connection.id);

      const unapprovedTarget = await fetch(`${url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "legacy-target-export-unapproved-0001",
        },
        body: JSON.stringify({ connectionId, nodeId: "node-a" }),
      });
      const unapprovedBulk = await fetch(`${url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "legacy-bulk-export-unapproved-0001",
        },
        body: JSON.stringify({ connectionId }),
      });
      expect(unapprovedTarget.status).toBe(409);
      expect(unapprovedBulk.status).toBe(409);
      expect(await unapprovedTarget.json()).toMatchObject({
        error: {
          code: "legacy_vault_projection_approval_required",
          remediation: expect.stringContaining("projection preview"),
        },
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM vault_sync_state
        WHERE connection_id = ? AND node_id = 'node-a'
      `).get(connectionId)).toEqual({ count: 0 });

      const expectedProjectionHash = projectionHash(["node-a"]);
      database.prepare(`
        INSERT INTO legacy_vault_projection_approvals (
          id, migration_id, reconciliation_hash, projection_hash, connection_id,
          approved_by, status, projected_node_ids_json, result_json,
          approved_at, completed_at
        ) VALUES (
          'approval-vault-export-gate', ?, ?, ?, ?, 'operator-route-test',
          'completed', '["node-a"]', '{}', ?, ?
        )
      `).run(migrationId, reconciliationHash, "b".repeat(64), connectionId, now, now);
      const wrongProjectionHash = await fetch(`${url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "legacy-target-export-wrong-hash-0001",
        },
        body: JSON.stringify({ connectionId, nodeId: "node-a" }),
      });
      expect(wrongProjectionHash.status).toBe(409);

      database.prepare(`
        UPDATE legacy_vault_projection_approvals SET projection_hash = ?
        WHERE id = 'approval-vault-export-gate'
      `).run(expectedProjectionHash);
      const approvedRequest = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "legacy-target-export-approved-0001",
        },
        body: JSON.stringify({ connectionId, nodeId: "node-a" }),
      } as const;
      const approved = await fetch(`${url}/api/v2/brain/vault/export`, approvedRequest);
      expect(approved.status).toBe(200);

      database.prepare(`
        UPDATE legacy_migration_reconciliation SET report_hash = ? WHERE migration_id = ?
      `).run("c".repeat(64), migrationId);
      const staleReplay = await fetch(`${url}/api/v2/brain/vault/export`, approvedRequest);
      expect(staleReplay.status).toBe(409);
      expect(await staleReplay.json()).toMatchObject({
        error: { code: "legacy_vault_projection_approval_required" },
      });
    } finally {
      database.close();
    }
  });

  test("vault repair and reindex enforce V2 ownership, optimistic versions, idempotency, and offline safety", async () => {
    const { database, directory, url } = await application();
    try {
      const commonHeaders = {
        "Content-Type": "application/json",
        "X-Test-Access": "all",
      };
      const connectedResponse = await fetch(`${url}/api/v2/brain/vault/connect`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "connect-vault-recovery-0001" },
        body: JSON.stringify({
          vaultPath: "Recovery-Brain",
          displayName: "Recovery Brain",
          permissionGranted: true,
        }),
      });
      expect(connectedResponse.status).toBe(201);
      const connected = await json(connectedResponse);
      const connectionId = String(connected.connection.id);
      const exported = await fetch(`${url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "export-vault-recovery-0001" },
        body: JSON.stringify({ connectionId }),
      });
      expect(exported.status).toBe(200);

      let snapshot = await json(await fetch(`${url}/api/v2/brain/vault`, { headers: { "X-Test-Access": "all" } }));
      let connection = snapshot.connections.find((item: { id: string }) => item.id === connectionId);
      const repairRequest = {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "repair-vault-recovery-0001" },
        body: JSON.stringify({
          connectionId,
          expectedUpdatedAt: connection.updatedAt,
          controlPlane: "ti_scale",
        }),
      };
      const repairedResponse = await fetch(`${url}/api/v2/brain/vault/repair`, repairRequest);
      expect(repairedResponse.status).toBe(200);
      const repaired = await json(repairedResponse);
      expect(repaired).toMatchObject({
        result: {
          operation: "repair",
          status: "completed",
          connectionId,
          health: { checks: { write: true, read: true, rename: true, delete: true } },
          progress: { remaining: 0 },
        },
      });
      expect(repaired.result.connectionVersion).not.toBe(connection.updatedAt);
      expect(await json(await fetch(`${url}/api/v2/brain/vault/repair`, repairRequest))).toEqual(repaired);

      const stale = await fetch(`${url}/api/v2/brain/vault/reindex`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "reindex-vault-stale-0001" },
        body: JSON.stringify({
          connectionId,
          expectedUpdatedAt: connection.updatedAt,
          controlPlane: "ti_scale",
        }),
      });
      expect(stale.status).toBe(409);
      expect(await stale.json()).toMatchObject({ error: { code: "vault_connection_version_conflict" } });

      snapshot = await json(await fetch(`${url}/api/v2/brain/vault`, { headers: { "X-Test-Access": "all" } }));
      connection = snapshot.connections.find((item: { id: string }) => item.id === connectionId);
      const wrongPlane = await fetch(`${url}/api/v2/brain/vault/reindex`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "reindex-vault-plane-0001" },
        body: JSON.stringify({ connectionId, expectedUpdatedAt: connection.updatedAt, controlPlane: "legacy" }),
      });
      expect(wrongPlane.status).toBe(409);
      expect(await wrongPlane.json()).toMatchObject({ error: { code: "vault_control_plane_conflict" } });

      const limited = await fetch(`${url}/api/v2/brain/vault/reindex`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "reindex-vault-limited-0001" },
        body: JSON.stringify({ connectionId, expectedUpdatedAt: connection.updatedAt, controlPlane: "ti_scale" }),
      });
      expect(limited.status).toBe(403);
      expect(await limited.json()).toMatchObject({ error: { code: "vault_recovery_admin_required" } });

      const reindexed = await fetch(`${url}/api/v2/brain/vault/reindex`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "reindex-vault-recovery-0001" },
        body: JSON.stringify({ connectionId, expectedUpdatedAt: connection.updatedAt, controlPlane: "ti_scale" }),
      });
      expect(reindexed.status).toBe(200);
      expect(await reindexed.json()).toMatchObject({
        result: { operation: "reindex", status: "completed", counts: { indexed: 4 } },
      });

      snapshot = await json(await fetch(`${url}/api/v2/brain/vault`, { headers: { "X-Test-Access": "all" } }));
      connection = snapshot.connections.find((item: { id: string }) => item.id === connectionId);
      const vaultPath = join(directory, "vaults", "Recovery-Brain");
      const offlinePath = `${vaultPath}-offline`;
      renameSync(vaultPath, offlinePath);
      const offline = await fetch(`${url}/api/v2/brain/vault/repair`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "repair-vault-offline-0001" },
        body: JSON.stringify({ connectionId, expectedUpdatedAt: connection.updatedAt, controlPlane: "ti_scale" }),
      });
      expect(offline.status).toBe(503);
      expect(await offline.json()).toMatchObject({ error: { code: "vault_connection_offline" } });
      const offlineSnapshot = await json(await fetch(`${url}/api/v2/brain/vault`, { headers: { "X-Test-Access": "all" } }));
      expect(offlineSnapshot.connections.find((item: { id: string }) => item.id === connectionId)).toMatchObject({
        status: "error",
        pathAvailable: false,
      });
      expect(existsSync(vaultPath)).toBe(false);
      expect(existsSync(offlinePath)).toBe(true);

      const recoveryAudits = database.prepare(`
        SELECT action, details_json FROM audit_records
        WHERE resource_id = ? AND action IN ('vault.repair.completed', 'vault.reindex.completed')
        ORDER BY rowid
      `).all(connectionId) as Array<{ action: string; details_json: string }>;
      expect(recoveryAudits.map((item) => item.action)).toEqual(["vault.repair.completed", "vault.reindex.completed"]);
      expect(recoveryAudits.every((item) => JSON.parse(item.details_json).controlPlane === "ti_scale")).toBe(true);
    } finally {
      database.close();
    }
  });

  test("portable exports bind downloads and idempotent replay to owner, access, and live nodes", async () => {
    const { database, repository, directory, url } = await application();
    try {
      const connect = await fetch(`${url}/api/v2/brain/vault/connect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "connect-portable-vault-0001",
        },
        body: JSON.stringify({
          vaultPath: "Portable-Brain",
          displayName: "Portable Brain",
          permissionGranted: true,
        }),
      });
      expect(connect.status).toBe(201);
      const connected = await json(connect);
      const portableRequest = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "portable-export-owner-bound-0001",
        },
        body: JSON.stringify({ connectionId: connected.connection.id }),
      };
      const createdResponse = await fetch(`${url}/api/v2/brain/vault/portable-export`, portableRequest);
      expect(createdResponse.status).toBe(200);
      const created = await json(createdResponse);
      const archiveName = String(created.result.archiveName);
      expect(created.result.status).toBe("ready");
      expect(archiveName).toMatch(/\.zip$/u);
      expect(await json(await fetch(`${url}/api/v2/brain/vault/portable-export`, portableRequest))).toEqual(created);

      const authorizedDownload = await fetch(`${url}${created.result.downloadUrl}`);
      expect(authorizedDownload.status).toBe(200);
      expect(authorizedDownload.headers.get("content-type")).toContain("application/zip");
      expect(authorizedDownload.headers.get("content-disposition")).toBe(
        `attachment; filename="${archiveName}"`,
      );
      expect(authorizedDownload.headers.get("x-content-type-options")).toBe("nosniff");
      expect(authorizedDownload.headers.get("cross-origin-resource-policy")).toBe("same-origin");
      expect(authorizedDownload.headers.get("content-security-policy")).toBe("sandbox");
      expect(authorizedDownload.headers.get("referrer-policy")).toBe("no-referrer");

      const crossActorDownload = await fetch(`${url}${created.result.downloadUrl}`, {
        headers: { "X-Test-Actor": "operator-route-test-other" },
      });
      expect(crossActorDownload.status).toBe(404);
      expect(JSON.stringify(await crossActorDownload.json())).not.toContain(archiveName);

      const revokedDownload = await fetch(`${url}${created.result.downloadUrl}`, {
        headers: { "X-Test-Access": "b" },
      });
      expect(revokedDownload.status).toBe(404);
      expect(JSON.stringify(await revokedDownload.json())).not.toContain(archiveName);

      const revokedReplay = await fetch(`${url}/api/v2/brain/vault/portable-export`, {
        ...portableRequest,
        headers: { ...portableRequest.headers, "X-Test-Access": "b" },
      });
      expect(revokedReplay.status).toBe(404);
      expect(JSON.stringify(await revokedReplay.json())).not.toContain(archiveName);

      const archivePath = join(directory, "vaults", "Portable-Brain", ".ti-scale", "exports", archiveName);
      const originalArchive = readFileSync(archivePath);
      const tamperedArchive = Buffer.from(originalArchive);
      tamperedArchive[0] = tamperedArchive[0]! ^ 0xff;
      writeFileSync(archivePath, tamperedArchive);
      const tamperedDownload = await fetch(`${url}${created.result.downloadUrl}`);
      expect(tamperedDownload.status).toBe(404);
      expect(JSON.stringify(await tamperedDownload.json())).not.toContain(archiveName);
      writeFileSync(archivePath, originalArchive);

      repository.forgetNode("node-a", "operator-route-test", "Exercise portable-export resource revocation");
      const forgottenNodeDownload = await fetch(`${url}${created.result.downloadUrl}`);
      expect(forgottenNodeDownload.status).toBe(404);
      expect(JSON.stringify(await forgottenNodeDownload.json())).not.toContain(archiveName);
    } finally {
      database.close();
    }
  });

  test("candidate confirmation and manual correction reject authentication material with safe metadata", async () => {
    const { database, repository, url } = await application();
    try {
      const sessionMaterial = ["session_token", ": ", "unit-test-session-material-123456789"].join("");
      const confirm = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "confirm-candidate-secret-denied-0001",
        },
        body: JSON.stringify({ edits: { body: sessionMaterial } }),
      });
      expect(confirm.status).toBe(422);
      const confirmBody = await json(confirm);
      expect(confirmBody).toMatchObject({
        error: {
          code: "sensitive_material_not_retained",
          category: "policy_denied",
          retryable: false,
        },
      });
      expect(JSON.stringify(confirmBody)).not.toContain(sessionMaterial);
      expect(repository.requireCandidate("candidate-a").status).toBe("pending");
      expect(repository.requireCandidate("candidate-a").proposedNodeId).toBeUndefined();

      const current = repository.requireNode("node-a");
      const correct = await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "correct-node-secret-denied-0001",
        },
        body: JSON.stringify({
          expectedVersion: current.version,
          body: sessionMaterial,
          reason: "Operator correction",
        }),
      });
      expect(correct.status).toBe(422);
      const correctionBody = await json(correct);
      expect(correctionBody.error.code).toBe("sensitive_material_not_retained");
      expect(JSON.stringify(correctionBody)).not.toContain(sessionMaterial);
      expect(repository.requireNode("node-a")).toMatchObject({ version: current.version, body: current.body });
      expect(repository.listVersions("node-a")).toHaveLength(1);

      const safe = await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "correct-node-placeholder-safe-0001",
        },
        body: JSON.stringify({
          expectedVersion: current.version,
          body: "Use Authorization: Bearer <TOKEN> and retain only evidence ID evidence-route-001.",
          reason: "Document safe credential indirection",
        }),
      });
      expect(safe.status).toBe(200);
      expect((await json(safe)).node.body).toContain("Bearer <TOKEN>");
    } finally {
      database.close();
    }
  });
});

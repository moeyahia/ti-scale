import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db/index";
import {
  MemoryRepository,
  SecondBrainService,
  type CreateMemoryNodeInput,
  type MemoryProvenance,
  type MemoryScope,
} from "../index";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function database() {
  const directory = mkdtempSync(join(tmpdir(), "second-brain-test-"));
  temporaryDirectories.push(directory);
  const db = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(db);
  return db;
}

function provenance(sourceId: string): MemoryProvenance {
  return {
    method: "operator_statement",
    explanation: "The operator explicitly confirmed this information",
    sources: [{
      sourceType: "message",
      sourceId,
      acquiredAt: "2026-07-15T10:00:00.000Z",
    }],
  };
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function insertMission(db: ReturnType<typeof database>, id: string, engagementId: string): void {
  const now = "2026-07-15T10:00:00.000Z";
  db.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, engagement_id, created_by, created_at, updated_at
    ) VALUES (?, ?, 'Authorized assessment', 'guided', ?, 'operator', ?, ?)
  `).run(id, id, engagementId, now, now);
}

function insertContextLinkage(
  db: ReturnType<typeof database>,
  prefix: string,
  journey: "autonomous" | "guided" = "guided",
): {
  missionId: string;
  runId: string;
  planId: string;
  stepId: string;
  actionId: string;
  messageId: string;
} {
  const now = "2026-07-15T10:00:00.000Z";
  const missionId = `mission-${prefix}`;
  const runId = `run-${prefix}`;
  const planId = `plan-${prefix}`;
  const stepId = `step-${prefix}`;
  const actionId = `action-${prefix}`;
  const conversationId = `conversation-${prefix}`;
  const messageId = `message-${prefix}`;
  db.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, engagement_id, created_by, created_at, updated_at
    ) VALUES (?, ?, 'Authorized context fixture', ?, ?, 'operator', ?, ?)
  `).run(missionId, missionId, journey, `eng-${prefix}`, now, now);
  db.prepare(`
    INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
    VALUES (?, ?, ?, 'planning', ?, ?)
  `).run(runId, missionId, journey, now, now);
  db.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash, created_by, created_at
    ) VALUES (?, ?, 1, 'active', 'Bounded context plan', ?, 'planner', ?)
  `).run(planId, runId, `hash-${prefix}`, now);
  db.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'recon', 'Context step', 'Collect scoped context', 'ready', ?, ?)
  `).run(stepId, planId, runId, now, now);
  db.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, action_type, action_class, fingerprint,
      normalized_arguments_json, status, intent_summary, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'reconnaissance', 'reconnaissance', ?, '{}',
      'succeeded', 'Collect bounded context', ?, ?)
  `).run(actionId, missionId, runId, stepId, `fingerprint-${prefix}`, now, now);
  db.prepare(`
    INSERT INTO conversations (
      id, mission_id, run_id, step_id, conversation_type, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'guided', ?, ?)
  `).run(conversationId, missionId, runId, stepId, now, now);
  db.prepare(`
    INSERT INTO messages (id, conversation_id, role, body, created_at)
    VALUES (?, ?, 'assistant', 'Scoped context explanation', ?)
  `).run(messageId, conversationId, now);
  return { missionId, runId, planId, stepId, actionId, messageId };
}

function createNode(
  repository: MemoryRepository,
  id: string,
  scope: MemoryScope,
  title = "Credential discovery pattern",
  body = "Enumerate identity boundaries before selecting the next authorized action.",
): ReturnType<MemoryRepository["createNode"]> {
  const input: CreateMemoryNodeInput = {
    id,
    nodeType: "technique",
    title,
    summary: "A confirmed operational technique for scoped identity discovery",
    body,
    scope,
    sensitivity: "internal",
    confidence: 0.9,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: provenance(`source-${id}`),
    authorType: "operator",
    authorId: "operator-1",
    retentionPolicy: { journeys: ["autonomous", "guided"] },
  };
  return repository.createNode(input);
}

describe("Second Brain canonical memory", () => {
  test("hybrid retrieval enforces engagement and mission isolation", () => {
    const db = database();
    try {
      insertMission(db, "mission-a", "eng-a");
      insertMission(db, "mission-b", "eng-b");
      const repository = new MemoryRepository(db);
      const brain = new SecondBrainService(repository);
      createNode(repository, "node-global", { kind: "global" });
      createNode(repository, "node-eng-a", { kind: "engagement", engagementId: "eng-a" });
      createNode(repository, "node-eng-b", { kind: "engagement", engagementId: "eng-b" });
      createNode(repository, "node-mission-a", {
        kind: "mission",
        engagementId: "eng-a",
        missionId: "mission-a",
      });
      createNode(repository, "node-mission-b", {
        kind: "mission",
        engagementId: "eng-b",
        missionId: "mission-b",
      });

      const result = brain.retrieve("credential discovery", {
        engagementId: "eng-a",
        missionId: "mission-a",
        journey: "guided",
        maximumSensitivity: "private",
        contextBudget: 2_000,
        graphDepth: 1,
      });
      const ids = result.map((item) => item.node.id);
      expect(ids).toContain("node-global");
      expect(ids).toContain("node-eng-a");
      expect(ids).toContain("node-mission-a");
      expect(ids).not.toContain("node-eng-b");
      expect(ids).not.toContain("node-mission-b");
      expect(result.every((item) => item.relevanceReason.length > 0)).toBe(true);

      const engagementOnly = brain.retrieve("credential discovery", {
        engagementId: "eng-a",
        missionId: "mission-a",
        allowGlobal: false,
        journey: "autonomous",
        maximumSensitivity: "private",
        contextBudget: 2_000,
        graphDepth: 1,
      }).map((item) => item.node.id);
      expect(engagementOnly).not.toContain("node-global");
      expect(engagementOnly).toContain("node-eng-a");
      expect(engagementOnly).toContain("node-mission-a");

      const exactOnly = brain.retrieve("credential discovery", {
        engagementId: "eng-a",
        missionId: "mission-a",
        journey: "autonomous",
        maximumSensitivity: "private",
        contextBudget: 2_000,
        exactNodeIds: ["node-eng-a", "node-eng-b"],
        exactNodeIdsOnly: true,
        graphDepth: 2,
      }).map((item) => item.node.id);
      expect(exactOnly).toEqual(["node-eng-a"]);
    } finally {
      db.close();
    }
  });

  test("canonical mission engagement gates memory creation, retrieval, and Context Pack persistence", () => {
    const db = database();
    try {
      insertMission(db, "mission-scope-a", "eng-scope-a");
      insertMission(db, "mission-scope-b", "eng-scope-b");
      const repository = new MemoryRepository(db);
      const brain = new SecondBrainService(repository);
      const conflictingScope = {
        kind: "mission" as const,
        engagementId: "eng-scope-b",
        missionId: "mission-scope-a",
      };

      expect(() => createNode(repository, "node-scope-conflict", conflictingScope))
        .toThrow("engagement does not match its canonical mission");
      expect(() => repository.createCandidate({
        id: "candidate-scope-conflict",
        nodeType: "preference",
        title: "Conflicting mission preference",
        summary: "This candidate must not cross the canonical engagement boundary",
        body: "Keep the candidate isolated to its real engagement.",
        scope: conflictingScope,
        sensitivity: "private",
        confidence: 0.8,
        provenance: provenance("candidate-scope-conflict-source"),
        proposedBy: "agent-commander",
      })).toThrow("engagement does not match its canonical mission");

      const valid = createNode(repository, "node-scope-valid", {
        kind: "mission",
        engagementId: "eng-scope-a",
        missionId: "mission-scope-a",
      });
      expect(() => repository.correctNode(valid.id, {
        scope: conflictingScope,
        changeReason: "Attempt a contradictory engagement correction",
        authorType: "operator",
        authorId: "operator-1",
      })).toThrow("engagement does not match its canonical mission");

      // Simulate a malformed legacy/import row that bypassed repository writes.
      db.prepare("UPDATE memory_nodes SET engagement_id = ? WHERE id = ?")
        .run("eng-scope-b", valid.id);
      const malformed = repository.requireNode(valid.id);
      const retrieved = brain.retrieve("credential discovery", {
        engagementId: "eng-scope-a",
        missionId: "mission-scope-a",
        journey: "guided",
        maximumSensitivity: "private",
        contextBudget: 1_000,
        exactNodeIds: [valid.id],
        exactNodeIdsOnly: true,
      });
      expect(retrieved).toEqual([]);

      expect(() => repository.persistContextPack({
        id: "ctx-conflicting-policy-engagement",
        missionId: "mission-scope-a",
        journey: "guided",
        purpose: "Reject a policy that contradicts the canonical engagement",
        scopePolicy: {
          engagementId: "eng-scope-b",
          missionId: "mission-scope-a",
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [],
      })).toThrow("engagement does not match its canonical mission");
      expect(() => repository.persistContextPack({
        id: "ctx-conflicting-item-engagement",
        missionId: "mission-scope-a",
        journey: "guided",
        purpose: "Reject a malformed item that contradicts its canonical engagement",
        scopePolicy: {
          engagementId: "eng-scope-a",
          missionId: "mission-scope-a",
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
          exactNodeIds: [valid.id],
          exactNodeIdsOnly: true,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{
          node: malformed,
          score: 10,
          relevanceReason: "Must fail closed before persistence",
          signals: ["exact"],
        }],
      })).toThrow("outside its canonical retrieval scope");
      expect(db.prepare(`
        SELECT
          (SELECT COUNT(*) FROM memory_context_packs
            WHERE id IN ('ctx-conflicting-policy-engagement', 'ctx-conflicting-item-engagement')) AS packs,
          (SELECT COUNT(*) FROM memory_context_items
            WHERE context_pack_id IN ('ctx-conflicting-policy-engagement', 'ctx-conflicting-item-engagement')) AS items
      `).get()).toEqual({ packs: 0, items: 0 });
    } finally {
      db.close();
    }
  });

  test("memory edges derive mission engagement canonically even when node labels omit it", () => {
    const db = database();
    try {
      insertMission(db, "mission-edge-a", "eng-edge-a");
      insertMission(db, "mission-edge-b", "eng-edge-b");
      const repository = new MemoryRepository(db);
      const nodeA = createNode(repository, "node-edge-a", {
        kind: "mission",
        missionId: "mission-edge-a",
      });
      const nodeASecond = createNode(repository, "node-edge-a-second", {
        kind: "mission",
        missionId: "mission-edge-a",
      });
      const nodeB = createNode(repository, "node-edge-b", {
        kind: "mission",
        missionId: "mission-edge-b",
      });
      const global = createNode(repository, "node-edge-global", { kind: "global" });
      const edge = (sourceNodeId: string, targetNodeId: string, scope: MemoryScope) => ({
        sourceNodeId,
        targetNodeId,
        edgeType: "supports" as const,
        title: "Scoped relationship",
        summary: "A relationship that must preserve canonical engagement isolation",
        scope,
        sensitivity: "internal" as const,
        confidence: 0.9,
        lifecycleStatus: "confirmed" as const,
        provenance: provenance(`edge-${sourceNodeId}-${targetNodeId}`),
        explanation: "The linked operational facts share one canonical scope",
        authorType: "operator" as const,
      });

      expect(() => repository.createEdge(edge(nodeA.id, nodeB.id, { kind: "global" })))
        .toThrow("Cross-engagement memory edges are not permitted");
      expect(() => repository.createEdge(edge(global.id, nodeA.id, {
        kind: "mission",
        missionId: "mission-edge-b",
      }))).toThrow("Mission edge scope does not match its nodes");
      const accepted = repository.createEdge(edge(nodeA.id, nodeASecond.id, {
        kind: "mission",
        missionId: "mission-edge-a",
      }));
      expect(accepted.sourceNodeId).toBe(nodeA.id);
      expect(repository.listEdges(nodeA.id)[0]?.scope).toEqual({
        kind: "mission",
        engagementId: "eng-edge-a",
        missionId: "mission-edge-a",
      });

      const engagementNode = createNode(repository, "node-edge-engagement", {
        kind: "engagement",
        engagementId: "eng-edge-a",
      });
      const engagementNodeSecond = createNode(repository, "node-edge-engagement-second", {
        kind: "engagement",
        engagementId: "eng-edge-a",
      });
      repository.createEdge(edge(engagementNode.id, engagementNodeSecond.id, {
        kind: "mission",
        missionId: "mission-edge-a",
      }));
      expect(repository.listEdges(engagementNode.id)[0]?.scope).toEqual({
        kind: "mission",
        engagementId: "eng-edge-a",
        missionId: "mission-edge-a",
      });
      expect(db.prepare(`
        SELECT scope, engagement_id, mission_id FROM memory_edges
        WHERE source_node_id = ? AND target_node_id = ?
      `).get(engagementNode.id, engagementNodeSecond.id)).toEqual({
        scope: "mission",
        engagement_id: "eng-edge-a",
        mission_id: "mission-edge-a",
      });
      expect(db.prepare("SELECT COUNT(*) AS count FROM memory_edges").get()).toEqual({ count: 2 });
    } finally {
      db.close();
    }
  });

  test("personal candidates require operator confirmation and suppression prevents relearning", () => {
    const db = database();
    try {
      const repository = new MemoryRepository(db);
      const candidateInput = {
        id: "candidate-depth",
        nodeType: "preference" as const,
        title: "Prefers deep explanations",
        summary: "Use detailed teaching for Guided missions",
        body: "Explain prerequisites and expected evidence.",
        scope: { kind: "global" as const },
        sensitivity: "private" as const,
        confidence: 0.75,
        provenance: provenance("message-preference"),
        proposedBy: "agent-commander",
      };
      const candidate = repository.createCandidate(candidateInput);
      expect(candidate.status).toBe("pending");
      expect(repository.getNode("candidate-depth")).toBeUndefined();

      const confirmed = repository.confirmCandidate(candidate.id, "operator-1", {
        summary: "Use detailed, evidence-led teaching for Guided missions",
      });
      expect(confirmed.nodeType).toBe("preference");
      expect(confirmed.lifecycleStatus).toBe("confirmed");
      expect(confirmed.authorType).toBe("operator");
      expect(repository.requireCandidate(candidate.id).status).toBe("edited_confirmed");

      const plainlyRejected = repository.createCandidate({
        ...candidateInput,
        id: "candidate-plain-reject",
        title: "Incorrect report preference",
      });
      const rejectedCandidate = repository.rejectCandidate(
        plainlyRejected.id,
        "operator-1",
        "This candidate is incorrect but does not need a relearning suppression",
      );
      expect(rejectedCandidate.status).toBe("rejected");
      expect(rejectedCandidate.reviewedBy).toBe("operator-1");
      expect(db.prepare("SELECT COUNT(*) AS count FROM memory_suppressions").get()).toEqual({ count: 0 });
      expect(db.prepare(`
        SELECT action, resource_type, resource_id, reason, details_json
        FROM audit_records WHERE resource_id = ?
      `).get(plainlyRejected.id)).toMatchObject({
        action: "memory_candidate.rejected",
        resource_type: "memory_candidate",
        resource_id: plainlyRejected.id,
        reason: "This candidate is incorrect but does not need a relearning suppression",
        details_json: expect.stringContaining('"doNotRelearn":false'),
      });

      const rejected = repository.createCandidate({ ...candidateInput, id: "candidate-reject", title: "Prefers terse reports" });
      const suppressionId = repository.rejectCandidateAndSuppress(
        rejected.id,
        "operator-1",
        "This preference is incorrect",
      );
      expect(suppressionId.startsWith("msup_")).toBe(true);
      expect(db.prepare(`
        SELECT action, resource_id, details_json FROM audit_records WHERE resource_id = ?
      `).get(rejected.id)).toMatchObject({
        action: "memory_candidate.suppressed",
        resource_id: rejected.id,
        details_json: expect.stringContaining('"doNotRelearn":true'),
      });
      expect(() => repository.createCandidate({ ...candidateInput, id: "candidate-repeat", title: "Prefers terse reports" }))
        .toThrow("suppressed");
    } finally {
      db.close();
    }
  });

  test("persists inspectable context packs and requires used/ignored explanations", () => {
    const db = database();
    try {
      insertMission(db, "mission-context", "eng-context");
      const repository = new MemoryRepository(db);
      const brain = new SecondBrainService(repository);
      createNode(repository, "node-context", { kind: "engagement", engagementId: "eng-context" });

      const pack = brain.retrieveAndPersistContext({
        query: "credential discovery",
        queryRedacted: "credential discovery",
        policy: {
          engagementId: "eng-context",
          missionId: "mission-context",
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        purpose: "Explain the next Guided step",
        createdBy: "commander",
        missionId: "mission-context",
      });
      expect(pack.items).toHaveLength(1);
      expect(pack.items[0]?.ignoredReason).toBe("Not yet evaluated");
      expect(() => brain.recordContextUse(pack.id, {
        nodeId: "node-context",
        used: true,
        relevanceReason: "Matched the current phase",
      })).toThrow("influence summary");
      brain.recordContextUse(pack.id, {
        nodeId: "node-context",
        used: true,
        relevanceReason: "Matched the current phase and engagement",
        influenceSummary: "Expanded the prerequisite and evidence explanation",
      });
      const stored = repository.requireContextPack(pack.id);
      expect(stored.items[0]?.used).toBe(true);
      expect(stored.items[0]?.influenceSummary).toContain("prerequisite");
      expect(JSON.stringify(stored)).not.toContain("chain-of-thought");
    } finally {
      db.close();
    }
  });

  test("persists a fully correlated Context Pack and preserves an unlinked global pack", () => {
    const db = database();
    try {
      const linked = insertContextLinkage(db, "valid");
      const repository = new MemoryRepository(db);
      const node = createNode(repository, "node-context-link-valid", { kind: "global" });
      const pack = repository.persistContextPack({
        id: "ctx-link-valid",
        ...linked,
        journey: "guided",
        purpose: "Use canonical context for one represented step",
        scopePolicy: {
          missionId: linked.missionId,
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node, score: 1, relevanceReason: "Exact canonical scope", signals: ["exact"] }],
      });
      expect(pack).toMatchObject({
        id: "ctx-link-valid",
        missionId: linked.missionId,
        runId: linked.runId,
        stepId: linked.stepId,
        actionId: linked.actionId,
        messageId: linked.messageId,
        journey: "guided",
      });
      expect(pack.items).toHaveLength(1);

      const global = repository.persistContextPack({
        id: "ctx-link-global",
        journey: "guided",
        purpose: "Use global confirmed context",
        scopePolicy: {
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node, score: 1, relevanceReason: "Confirmed global node", signals: ["exact"] }],
      });
      expect(global).not.toHaveProperty("missionId");
      expect(global).not.toHaveProperty("runId");
      expect(global.items).toHaveLength(1);
    } finally {
      db.close();
    }
  });

  test("rejects a step whose direct run does not match its plan without partial writes", () => {
    const db = database();
    try {
      const first = insertContextLinkage(db, "step-plan-a");
      const second = insertContextLinkage(db, "step-plan-b");
      const repository = new MemoryRepository(db);
      const node = createNode(repository, "node-context-step-plan", { kind: "global" });
      db.prepare("UPDATE plan_steps SET run_id = ? WHERE id = ?").run(second.runId, first.stepId);

      expect(() => repository.persistContextPack({
        id: "ctx-step-plan-mismatch",
        stepId: first.stepId,
        journey: "guided",
        purpose: "Reject corrupt step linkage",
        scopePolicy: {
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node, score: 1, relevanceReason: "Must not persist", signals: ["exact"] }],
      })).toThrow("step run does not match its canonical plan");
      expect(db.prepare(`
        SELECT COUNT(*) AS count FROM memory_context_packs WHERE id = 'ctx-step-plan-mismatch'
      `).get()).toEqual({ count: 0 });
      expect(db.prepare(`
        SELECT COUNT(*) AS count FROM memory_context_items
        WHERE context_pack_id = 'ctx-step-plan-mismatch'
      `).get()).toEqual({ count: 0 });
    } finally {
      db.close();
    }
  });

  test("rejects cross-mission action and message links transactionally", () => {
    const db = database();
    try {
      const first = insertContextLinkage(db, "cross-a");
      const second = insertContextLinkage(db, "cross-b");
      const repository = new MemoryRepository(db);
      const node = createNode(repository, "node-context-cross", { kind: "global" });
      expect(() => repository.persistContextPack({
        id: "ctx-cross-action-message",
        actionId: first.actionId,
        messageId: second.messageId,
        journey: "guided",
        purpose: "Reject cross-mission linkage",
        scopePolicy: {
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node, score: 1, relevanceReason: "Must not persist", signals: ["exact"] }],
      })).toThrow("mission links cross canonical scopes");
      expect(db.prepare(`
        SELECT
          (SELECT COUNT(*) FROM memory_context_packs WHERE id = 'ctx-cross-action-message') AS packs,
          (SELECT COUNT(*) FROM memory_context_items
            WHERE context_pack_id = 'ctx-cross-action-message') AS items
      `).get()).toEqual({ packs: 0, items: 0 });
    } finally {
      db.close();
    }
  });

  test("rejects journey mismatch and missing canonical links with no partial writes", () => {
    const db = database();
    try {
      const linked = insertContextLinkage(db, "journey-guided", "guided");
      const repository = new MemoryRepository(db);
      const node = createNode(repository, "node-context-journey", { kind: "global" });
      const base = {
        purpose: "Reject invalid canonical linkage",
        scopePolicy: {
          journey: "autonomous" as const,
          maximumSensitivity: "private" as const,
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node, score: 1, relevanceReason: "Must not persist", signals: ["exact" as const] }],
      };
      expect(() => repository.persistContextPack({
        ...base,
        id: "ctx-journey-mismatch",
        missionId: linked.missionId,
        journey: "autonomous",
      })).toThrow("journey does not match its canonical scope");
      expect(() => repository.persistContextPack({
        ...base,
        id: "ctx-missing-action",
        actionId: "action-does-not-exist",
        journey: "autonomous",
      })).toThrow("action link is missing");
      expect(db.prepare(`
        SELECT
          (SELECT COUNT(*) FROM memory_context_packs
            WHERE id IN ('ctx-journey-mismatch', 'ctx-missing-action')) AS packs,
          (SELECT COUNT(*) FROM memory_context_items
            WHERE context_pack_id IN ('ctx-journey-mismatch', 'ctx-missing-action')) AS items
      `).get()).toEqual({ packs: 0, items: 0 });
    } finally {
      db.close();
    }
  });

  test("forgetting erases reusable content and leaves a content-free audit and suppression", () => {
    const db = database();
    try {
      const repository = new MemoryRepository(db);
      const secretPhrase = "uniquely-sensitive-memory-phrase";
      createNode(repository, "node-forget", { kind: "global" }, "Sensitive operator note", secretPhrase);
      createNode(repository, "node-peer", { kind: "global" }, "Peer technique");
      expect(() => repository.createEdge({
        sourceNodeId: "node-forget",
        targetNodeId: "node-peer",
        edgeType: "related" as never,
        title: "Invalid edge should fail",
        summary: "Invalid",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "confirmed",
        provenance: provenance("edge-source"),
        explanation: "Invalid relationship",
        authorType: "operator",
      })).toThrow("memory edge type is invalid");
    } finally {
      db.close();
    }

    const db2 = database();
    try {
      const repository = new MemoryRepository(db2);
      const brain = new SecondBrainService(repository);
      const secretPhrase = "uniquely-sensitive-memory-phrase";
      createNode(repository, "node-forget", { kind: "global" }, "Sensitive operator note", secretPhrase);
      createNode(repository, "node-peer", { kind: "global" }, "Peer technique");
      db2.prepare(`
        INSERT INTO memory_candidates (
          id, proposed_node_id, candidate_type, title, summary, body, proposed_scope,
          sensitivity, confidence, source_json, status, proposed_by, reviewed_by,
          reviewed_at, created_at
        ) VALUES (?, ?, 'technique', ?, ?, ?, 'global', 'private', 1, ?, 'confirmed',
          'agent-forget-test', 'operator-1', ?, ?)
      `).run(
        "candidate-forget-copy",
        "node-forget",
        "Sensitive operator note",
        secretPhrase,
        secretPhrase,
        JSON.stringify(provenance(`candidate-${secretPhrase}`)),
        "2026-07-15T10:00:00.000Z",
        "2026-07-15T10:00:00.000Z",
      );
      const cachedNode = repository.requireNode("node-forget");
      db2.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, updated_by, updated_at)
        VALUES (?, ?, 'private', 'operator-1', ?), (?, ?, 'private', 'operator-1', ?),
          (?, ?, 'private', 'operator-1', ?)
      `).run(
        "idempotency.brain.forget-content-copy",
        JSON.stringify({ requestHash: "a".repeat(64), response: { node: cachedNode } }),
        "2026-07-15T10:00:00.000Z",
        "brain.portable_export.authorization.forget-content-copy",
        JSON.stringify({
          connectionId: "vault-forget-copy",
          archiveName: "ti-scale-brain-forget-copy.zip",
          nodeIds: ["node-forget"],
          marker: secretPhrase,
        }),
        "2026-07-15T10:00:00.000Z",
        "idempotency.brain.portable-forget-copy",
        JSON.stringify({
          response: {
            result: {
              connectionId: "vault-forget-copy",
              archiveName: "ti-scale-brain-forget-copy.zip",
              marker: secretPhrase,
            },
          },
        }),
        "2026-07-15T10:00:00.000Z",
      );
      repository.createEdge({
        sourceNodeId: "node-forget",
        targetNodeId: "node-peer",
        edgeType: "depends_on",
        title: "Sensitive note depends on peer",
        summary: "Confirmed relationship",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "confirmed",
        provenance: provenance("edge-source"),
        explanation: "The operator linked these memories",
        authorType: "operator",
      });
      db2.prepare(`
        INSERT INTO memory_embeddings (
          node_id, model, provider, dimensions, embedding, content_hash, created_at
        ) VALUES ('node-forget', 'local-test', 'local', 2, ?, ?, ?)
      `).run(Buffer.from([1, 2]), "a".repeat(64), "2026-07-15T10:00:00.000Z");
      const retrieved = brain.retrieve("sensitive memory", {
        journey: "guided",
        maximumSensitivity: "private",
        contextBudget: 1_000,
      });
      const pack = repository.persistContextPack({
        journey: "guided",
        purpose: "Test forgetting",
        scopePolicy: {
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "test",
        items: retrieved,
      });
      expect(pack.items.some((item) => item.nodeId === "node-forget")).toBe(true);

      const forgotten = brain.forget("node-forget", "operator-1", "Remove this memory everywhere");
      expect(forgotten.removed.versions).toBe(1);
      expect(forgotten.removed.embeddings).toBe(1);
      expect(forgotten.removed.edges).toBe(1);
      expect(forgotten.removed.contextItems).toBe(1);
      const tombstone = repository.requireNode("node-forget", true);
      expect(tombstone.lifecycleStatus).toBe("forgotten");
      expect(tombstone.body).toBe("");
      expect(repository.listVersions("node-forget")).toHaveLength(0);
      expect(db2.prepare("SELECT count(*) AS count FROM memory_sources WHERE node_id = 'node-forget'").get())
        .toEqual({ count: 0 });
      const audit = db2.prepare("SELECT * FROM audit_records WHERE id = ?").get(forgotten.auditRecordId);
      expect(JSON.stringify(audit)).not.toContain(secretPhrase);
      expect(JSON.stringify(audit)).not.toContain("Sensitive operator note");
      const candidateCopy = db2.prepare(`
        SELECT proposed_node_id, title, summary, body, confidence, source_json, status
        FROM memory_candidates WHERE id = 'candidate-forget-copy'
      `).get() as Record<string, unknown>;
      expect(candidateCopy).toMatchObject({
        proposed_node_id: null,
        title: "[Forgotten candidate]",
        summary: "",
        body: "",
        confidence: 0,
        status: "suppressed",
      });
      expect(JSON.stringify(candidateCopy)).not.toContain(secretPhrase);
      expect(db2.prepare(`
        SELECT COUNT(*) AS count FROM settings
        WHERE key = 'brain.portable_export.authorization.forget-content-copy'
      `).get()).toEqual({ count: 0 });
      const revokedCaches = db2.prepare(`
        SELECT key, value_json FROM settings
        WHERE key IN (
          'idempotency.brain.forget-content-copy',
          'idempotency.brain.portable-forget-copy'
        ) ORDER BY key
      `).all() as Array<{ key: string; value_json: string }>;
      expect(revokedCaches).toHaveLength(2);
      expect(revokedCaches.every((row) => JSON.parse(row.value_json).state === "revoked")).toBe(true);
      expect(JSON.stringify(revokedCaches)).not.toContain(secretPhrase);
      expect(brain.retrieve(secretPhrase, {
        journey: "guided",
        maximumSensitivity: "restricted",
        contextBudget: 1_000,
      })).toHaveLength(0);
      // Erasure restores the append-only trigger for all remaining memory.
      expect(() => db2.prepare("DELETE FROM memory_versions WHERE node_id = 'node-peer'").run()).toThrow("append-only");
    } finally {
      db2.close();
    }
  });

  test("mission and run scoped memory audits satisfy migration 007 journey triggers and hash the journey", () => {
    const db = database();
    try {
      const now = "2026-07-15T14:00:00.000Z";
      insertMission(db, "mission-memory-audit", "eng-memory-audit");
      db.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES ('run-memory-audit', 'mission-memory-audit', 'guided', 'running', ?, ?)
      `).run(now, now);
      let sequence = 0;
      const repository = new MemoryRepository(db, {
        clock: () => new Date(now),
        createId: (prefix) => `${prefix}-memory-audit-${++sequence}`,
      });
      repository.createNode({
        id: "node-memory-audit",
        nodeType: "run",
        title: "Run memory projection",
        summary: "Content-free projection linked to the canonical run",
        body: "Retain only the run and evidence identifiers.",
        scope: {
          kind: "mission",
          engagementId: "eng-memory-audit",
          missionId: "mission-memory-audit",
        },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "confirmed",
        confirmationState: "confirmed",
        provenance: {
          method: "derived",
          explanation: "Projected from the canonical run",
          sources: [{ sourceType: "run", sourceId: "run-memory-audit", acquiredAt: now }],
        },
        authorType: "operator",
        authorId: "operator-memory-audit",
      });

      const forgotten = repository.forgetNode("node-memory-audit", "operator-memory-audit");
      const audit = db.prepare(`
        SELECT id, mission_id, run_id, journey, actor_id, action, resource_type,
          resource_id, reason, details_json, previous_hash, record_hash, occurred_at
        FROM audit_records WHERE id = ?
      `).get(forgotten.auditRecordId) as Record<string, string | null>;
      expect(audit).toMatchObject({
        mission_id: "mission-memory-audit",
        run_id: "run-memory-audit",
        journey: "guided",
        previous_hash: null,
      });
      const expectedHash = createHash("sha256").update(canonicalJson({
        id: audit.id,
        actor: audit.actor_id,
        action: audit.action,
        resourceType: audit.resource_type,
        resourceId: audit.resource_id,
        reason: audit.reason,
        details: JSON.parse(audit.details_json!),
        missionId: audit.mission_id,
        runId: audit.run_id,
        journey: audit.journey,
        previousHash: audit.previous_hash,
        occurredAt: audit.occurred_at,
      }), "utf8").digest("hex");
      expect(audit.record_hash).toBe(expectedHash);

      const insert = db.prepare(`
        INSERT INTO audit_records (
          id, mission_id, run_id, journey, actor_type, actor_id, action,
          resource_type, resource_id, reason, details_json, previous_hash,
          record_hash, occurred_at
        ) VALUES (?, 'mission-memory-audit', 'run-memory-audit', ?, 'operator',
          'operator-memory-audit', 'memory.test', 'memory_node', 'node-memory-audit',
          'Trigger test', '{}', ?, ?, ?)
      `);
      expect(() => insert.run("audit-memory-missing", null, audit.record_hash, "missing", now))
        .toThrow("require a journey");
      expect(() => insert.run("audit-memory-mismatch", "autonomous", audit.record_hash, "mismatch", now))
        .toThrow("match run journey");
    } finally {
      db.close();
    }
  });
});

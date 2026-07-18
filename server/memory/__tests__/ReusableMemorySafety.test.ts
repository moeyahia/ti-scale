import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db/index";
import {
  MemoryRepository,
  REUSABLE_MEMORY_LIMITS,
  ReusableMemorySafetyError,
  type CreateMemoryNodeInput,
  type MemoryProvenance,
} from "../index";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function setup() {
  const directory = mkdtempSync(join(tmpdir(), "memory-safety-test-"));
  temporaryDirectories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(database);
  return { database, repository: new MemoryRepository(database) };
}

function provenance(sourceId = "evidence-safe-001", excerptRedacted?: string): MemoryProvenance {
  return {
    method: "evidence",
    explanation: "Derived from a verified immutable evidence reference",
    sources: [{
      sourceType: "evidence",
      sourceId,
      acquiredAt: "2026-07-15T10:00:00.000Z",
      ...(excerptRedacted ? { excerptRedacted } : {}),
    }],
  };
}

function nodeInput(id: string): CreateMemoryNodeInput {
  return {
    id,
    nodeType: "procedure",
    title: "Token-safe authorization procedure",
    summary: "Reference protected credentials by identifier and keep values outside memory",
    body: "Send Authorization: Bearer <TOKEN> and use password=<PASSWORD>. Preserve only evidence ID evidence-safe-001.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.95,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: provenance(),
    authorType: "operator",
    authorId: "operator-safety-test",
    retentionPolicy: { allowAutonomous: true, allowGuided: true },
  };
}

function privateKeyMaterial(): string {
  return [
    ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].join(""),
    "unit-test-authentication-material",
    ["-----END OPENSSH ", "PRIVATE KEY-----"].join(""),
  ].join("\n");
}

function sessionMaterial(): string {
  return ["session_token", ": ", "unit-test-session-material-123456789"].join("");
}

function providerMaterial(): string {
  return ["sk-", "unitTestProviderMaterial123456789"].join("");
}

function expectSafetyError(operation: () => unknown, expectedCode = "sensitive_material_not_retained"): void {
  let caught: unknown;
  try {
    operation();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(ReusableMemorySafetyError);
  expect((caught as ReusableMemorySafetyError).code).toBe(expectedCode);
  expect(JSON.stringify((caught as ReusableMemorySafetyError).details)).not.toContain("unit-test-authentication-material");
}

describe("reusable-memory persistence boundary", () => {
  test("allows safe operational placeholders and immutable evidence links to round-trip", () => {
    const { database, repository } = setup();
    try {
      const created = repository.createNode(nodeInput("memory-safe-roundtrip"));
      expect(created.body).toContain("Bearer <TOKEN>");
      expect(created.provenance.sources[0]?.sourceId).toBe("evidence-safe-001");
      expect(repository.listVersions(created.id)).toHaveLength(1);
      expect(database.prepare("SELECT source_id FROM memory_sources WHERE node_id = ?").get(created.id))
        .toEqual({ source_id: "evidence-safe-001" });
    } finally {
      database.close();
    }
  });

  test("rejects credential, token, private-key, provenance, and oversized node content before persistence", () => {
    const { database, repository } = setup();
    try {
      expectSafetyError(() => repository.createNode({ ...nodeInput("memory-private-key"), body: privateKeyMaterial() }));
      expectSafetyError(() => repository.createNode({ ...nodeInput("memory-provider-token"), summary: providerMaterial() }));
      expectSafetyError(() => repository.createNode({
        ...nodeInput("memory-authentication-hash"),
        body: ["ntlm", "=", "a".repeat(32)].join(""),
      }));
      expectSafetyError(() => repository.createNode({
        ...nodeInput("memory-source-secret"),
        provenance: provenance("evidence-safe-002", sessionMaterial()),
      }));
      expectSafetyError(
        () => repository.createNode({
          ...nodeInput("memory-too-large"),
          body: "a".repeat(REUSABLE_MEMORY_LIMITS.body + 1),
        }),
        "reusable_memory_content_too_large",
      );
      expect((database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get() as { count: number }).count).toBe(0);
      expect((database.prepare("SELECT COUNT(*) AS count FROM memory_versions").get() as { count: number }).count).toBe(0);
      expect((database.prepare("SELECT COUNT(*) AS count FROM memory_sources").get() as { count: number }).count).toBe(0);
    } finally {
      database.close();
    }
  });

  test("blocks unsafe candidates, confirmation edits, and direct corrections atomically", () => {
    const { database, repository } = setup();
    try {
      expectSafetyError(() => repository.createCandidate({
        id: "candidate-unsafe",
        nodeType: "procedure",
        title: "Unsafe candidate",
        summary: "Candidate should not persist",
        body: sessionMaterial(),
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.8,
        provenance: provenance(),
        proposedBy: "agent-safety-test",
      }));
      expect(repository.getCandidate("candidate-unsafe")).toBeUndefined();

      const candidate = repository.createCandidate({
        id: "candidate-safe",
        nodeType: "procedure",
        title: "Safe candidate",
        summary: "Awaiting explicit operator review",
        body: "Reference the protected credential by opaque ID.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.8,
        provenance: provenance(),
        proposedBy: "agent-safety-test",
      });
      expectSafetyError(() => repository.confirmCandidate(candidate.id, "operator-safety-test", {
        body: privateKeyMaterial(),
      }));
      expect(repository.requireCandidate(candidate.id).status).toBe("pending");
      expect(repository.requireCandidate(candidate.id).proposedNodeId).toBeUndefined();

      const node = repository.createNode(nodeInput("memory-correction-safe"));
      expectSafetyError(() => repository.correctNode(node.id, {
        body: sessionMaterial(),
        authorType: "operator",
        authorId: "operator-safety-test",
        changeReason: "Attempted unsafe correction",
      }));
      expect(repository.requireNode(node.id)).toMatchObject({ version: 1, body: node.body });
      expect(repository.listVersions(node.id)).toHaveLength(1);
    } finally {
      database.close();
    }
  });

  test("applies the same boundary to edges and inspectable context metadata", () => {
    const { database, repository } = setup();
    try {
      const source = repository.createNode(nodeInput("memory-edge-source"));
      const target = repository.createNode({ ...nodeInput("memory-edge-target"), title: "Target procedure" });
      expectSafetyError(() => repository.createEdge({
        sourceNodeId: source.id,
        targetNodeId: target.id,
        edgeType: "supports",
        title: "Unsafe edge",
        summary: sessionMaterial(),
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.8,
        lifecycleStatus: "confirmed",
        provenance: provenance(),
        explanation: "Should not persist",
        authorType: "operator",
      }));
      expectSafetyError(() => repository.persistContextPack({
        id: "context-unsafe",
        journey: "guided",
        purpose: "Explain a safe procedure",
        queryRedacted: providerMaterial(),
        scopePolicy: {
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node: source, score: 1, relevanceReason: "Exact match", signals: ["exact"] }],
      }));
      expect((database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get() as { count: number }).count).toBe(0);
      expect((database.prepare("SELECT COUNT(*) AS count FROM memory_context_packs").get() as { count: number }).count).toBe(0);
    } finally {
      database.close();
    }
  });
});

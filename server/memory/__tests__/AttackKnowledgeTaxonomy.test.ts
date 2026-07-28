import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../MemoryRepository";
import type { CreateMemoryNodeInput, MemoryNodeType, MemoryProvenance } from "../types";

const NOW = "2026-07-20T00:00:00.000Z";

function opaqueId(label: string): string {
  return `mem_${createHash("sha256").update(label).digest("hex")}`;
}

function provenance(sourceId = "private-run_42:10.129.39.191"): MemoryProvenance {
  return {
    method: "derived",
    explanation: "Generalized locally from private operational provenance",
    sources: [{ sourceType: "private_operational_record", sourceId, acquiredAt: NOW }],
  };
}

function node(
  nodeType: MemoryNodeType,
  id: string,
  overrides: Partial<CreateMemoryNodeInput> = {},
): CreateMemoryNodeInput {
  return {
    id: opaqueId(id),
    nodeType,
    title: `${nodeType.replaceAll("_", " ")} fixture`,
    summary: "Generalized attack knowledge without an engagement locator.",
    body: "Reusable behavior is described by product, version, prerequisites, state, and outcome.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.9,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    provenance: provenance(),
    authorType: "operator",
    authorId: "operator-reviewer",
    ...overrides,
  };
}

describe("attack-centric reusable memory taxonomy", () => {
  test("rejects operational locators, mission scope, unreviewed promotion, and source excerpts", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
    try {
      expect(() => memory.createNode(node("attack_procedure", "semantic-id", {
        id: "mem_ReaperTwo_customer_app",
      }))).toThrow("opaque generated memory IDs");
      expect(() => memory.createNode(node("attack_procedure", "attack-scope", {
        scope: { kind: "mission", engagementId: "engagement-one", missionId: "mission-one" },
      }))).toThrow("global scope");
      expect(() => memory.createNode(node("attack_procedure", "attack-agent-promoted", {
        authorType: "agent",
        lifecycleStatus: "verified",
      }))).toThrow("pending candidate");
      expect(() => memory.createNode(node("operational_hazard", "attack-excerpt", {
        provenance: {
          ...provenance(),
          sources: [{
            sourceType: "private_operational_record",
            sourceId: "private-run-42",
            acquiredAt: NOW,
            excerptRedacted: "Raw mission excerpt must stay private",
          }],
        },
      }))).toThrow("without source excerpts");
      expect(() => memory.createNode(node("attack_procedure", "attack-address", {
        summary: "Retry the procedure against 10.129.39.191.",
      }))).toThrow("network_address");
      expect(() => memory.createCandidate({
        id: "candidate-address",
        nodeType: "attack_procedure",
        title: "Candidate tied to 10.129.39.191",
        summary: "This operational locator must never enter the review inbox.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.8,
        provenance: provenance(),
        proposedBy: "system:attack-knowledge-compiler",
      })).toThrow("network_address");
      expect(() => memory.createCandidate({
        id: "candidate-mission-scoped",
        nodeType: "attack_procedure",
        title: "Mission-scoped candidate",
        summary: "A reusable candidate cannot carry mission scope.",
        scope: { kind: "mission", missionId: "mission-one", engagementId: "engagement-one" },
        sensitivity: "internal",
        confidence: 0.8,
        provenance: provenance(),
        proposedBy: "system:attack-knowledge-compiler",
      })).toThrow("global scope");
      expect(memory.createCandidate({
        id: "candidate-generalized",
        nodeType: "attack_procedure",
        title: "Generalized bounded validation procedure",
        summary: "A reviewable procedure without operational identity.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.8,
        provenance: provenance(),
        proposedBy: "system:attack-knowledge-compiler",
      })).toMatchObject({ status: "pending", scope: { kind: "global" } });

      for (const unsafeText of [
        "Inspect /usr before validation.",
        "Inspect /dev before validation.",
        "Load /usr/local/bin/procedure.py before validation.",
        "Connect to customer.internal before validation.",
        "Notify operator@example.com before validation.",
      ]) {
        expect(() => memory.createNode(node("attack_procedure", unsafeText, {
          summary: unsafeText,
        }))).toThrow("private operational locators");
      }
      expect(memory.createNode(node("attack_procedure", "placeholder-path", {
        summary: "Load /<workspace>/procedure.py from the approved artifact.",
      })).summary).toContain("/<workspace>/procedure.py");
      expect(memory.createNode(node("attack_procedure", "dotted-technologies", {
        summary: "The reusable stack includes ASP.NET, Node.js, and Next.js components.",
      })).summary).toContain("ASP.NET");
    } finally {
      database.close();
    }
  });

  test("accepts private provenance IDs while enforcing typed reusable edge endpoints", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
    try {
      const procedure = memory.createNode(node("attack_procedure", "attack-procedure"));
      const procedureVersion = memory.createNode(node("procedure_version", "attack-procedure-version"));
      const product = memory.createNode(node("technology_product", "technology-product"));
      const exactProductVersion = memory.createNode(node("exact_version_fingerprint", "technology-product-version"));
      const hazard = memory.createNode(node("operational_hazard", "attack-hazard"));
      const recovery = memory.createNode(node("recovery_pattern", "attack-recovery"));
      const failedOutcome = memory.createNode(node("outcome", "attack-failed-outcome"));
      const technique = memory.createNode(node("attack_technique", "attack-technique"));
      expect(procedure.provenance.sources[0]?.sourceId).toContain("10.129.39.191");

      expect(memory.createEdge({
        id: "procedure-has-exact-version",
        sourceNodeId: procedure.id,
        targetNodeId: procedureVersion.id,
        edgeType: "has_exact_version",
        title: "Procedure has exact reviewed version",
        summary: "The reusable procedure is bound to one exact reviewed procedure version.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.98,
        lifecycleStatus: "verified",
        provenance: provenance("private-procedure-version-source"),
        explanation: "The procedure version and procedure were reviewed as one bounded contract.",
        authorType: "operator",
        authorId: "operator-reviewer",
      }).edgeType).toBe("has_exact_version");
      for (const [id, sourceNodeId, targetNodeId, expected] of [
        ["invalid-procedure-product-version", procedure.id, exactProductVersion.id,
          "cannot connect attack_procedure to exact_version_fingerprint"],
        ["invalid-product-procedure-version", product.id, procedureVersion.id,
          "cannot connect technology_product to procedure_version"],
      ] as const) {
        expect(() => memory.createEdge({
          id,
          sourceNodeId,
          targetNodeId,
          edgeType: "has_exact_version",
          title: "Invalid exact-version pairing",
          summary: "Exact-version edges must preserve product and procedure version domains.",
          scope: { kind: "global" },
          sensitivity: "internal",
          confidence: 0.8,
          lifecycleStatus: "candidate",
          provenance: provenance(`private-${id}`),
          explanation: "This cross-domain exact-version relationship must be rejected.",
          authorType: "agent",
        })).toThrow(expected);
      }

      expect(memory.createEdge({
        id: "attack-caused-hazard",
        sourceNodeId: procedure.id,
        targetNodeId: hazard.id,
        edgeType: "caused",
        title: "Procedure caused operational hazard",
        summary: "A reviewed procedure version produced the generalized harmful state.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.94,
        lifecycleStatus: "verified",
        provenance: provenance("private-edge-source"),
        explanation: "The reviewed procedure consistently produced this state transition.",
        authorType: "operator",
        authorId: "operator-reviewer",
      }).edgeType).toBe("caused");
      expect(memory.createEdge({
        id: "hazard-requires-recovery",
        sourceNodeId: hazard.id,
        targetNodeId: recovery.id,
        edgeType: "requires_recovery",
        title: "Hazard requires recovery",
        summary: "The target state must be restored before a safe retry.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.98,
        lifecycleStatus: "verified",
        provenance: provenance("private-recovery-source"),
        explanation: "A passing health check after recovery is the retry gate.",
        authorType: "operator",
        authorId: "operator-reviewer",
      }).edgeType).toBe("requires_recovery");
      expect(memory.createEdge({
        id: "outcome-recovered-with-pattern",
        sourceNodeId: failedOutcome.id,
        targetNodeId: recovery.id,
        edgeType: "recovered_with",
        title: "Outcome recovered with reusable pattern",
        summary: "The reviewed recovery pattern restored the reusable healthy state.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.96,
        lifecycleStatus: "verified",
        provenance: provenance("private-recovery-outcome-source"),
        explanation: "The outcome and recovery pattern were reviewed together.",
        authorType: "operator",
        authorId: "operator-reviewer",
      }).edgeType).toBe("recovered_with");
      expect(memory.createEdge({
        id: "procedure-classified-as-technique",
        sourceNodeId: procedure.id,
        targetNodeId: technique.id,
        edgeType: "classified_as",
        title: "Procedure implements reviewed technique",
        summary: "The source explicitly classifies the bounded procedure as this reusable attack technique.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.96,
        lifecycleStatus: "verified",
        provenance: provenance("private-classification-source"),
        explanation: "Both endpoints were explicitly described in the same hash-bound source scope.",
        authorType: "operator",
        authorId: "operator-reviewer",
      }).edgeType).toBe("classified_as");
      expect(() => memory.createEdge({
        id: "invalid-reversed-procedure-classification",
        sourceNodeId: technique.id,
        targetNodeId: procedure.id,
        edgeType: "classified_as",
        title: "Invalid reversed procedure classification",
        summary: "The endpoint registry must reject the reverse direction.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.5,
        lifecycleStatus: "candidate",
        provenance: provenance("private-invalid-classification-source"),
        explanation: "This relation is intentionally backwards.",
        authorType: "agent",
      })).toThrow("cannot connect attack_technique to attack_procedure");

      expect(() => memory.createEdge({
        id: "invalid-reversed-hazard",
        sourceNodeId: hazard.id,
        targetNodeId: procedure.id,
        edgeType: "caused",
        title: "Invalid reversed relationship",
        summary: "The endpoint registry must reject this direction.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.5,
        lifecycleStatus: "candidate",
        provenance: provenance("invalid-edge-source"),
        explanation: "This relation is intentionally backwards.",
        authorType: "agent",
      })).toThrow("cannot connect operational_hazard to attack_procedure");
      expect(() => memory.createEdge({
        id: "invalid-scoped-hazard",
        sourceNodeId: procedure.id,
        targetNodeId: hazard.id,
        edgeType: "caused",
        title: "Invalid mission-scoped relationship",
        summary: "Reusable knowledge edges cannot carry mission identity.",
        scope: { kind: "mission", missionId: "mission-one", engagementId: "engagement-one" },
        sensitivity: "internal",
        confidence: 0.5,
        lifecycleStatus: "candidate",
        provenance: provenance("invalid-scope-source"),
        explanation: "This relation intentionally carries operational scope.",
        authorType: "agent",
      })).toThrow("global scope");

      const privateTarget = memory.createNode({
        ...node("target", "private-target"),
        nodeType: "target",
        title: "Private operational target",
        sensitivity: "private",
      });
      expect(() => memory.createEdge({
        id: "legacy-supports-cross-boundary",
        sourceNodeId: procedure.id,
        targetNodeId: privateTarget.id,
        edgeType: "supports",
        title: "Legacy support edge",
        summary: "A legacy edge type must not bypass the reusable boundary.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.8,
        lifecycleStatus: "verified",
        provenance: provenance("private-cross-boundary-source"),
        explanation: "This relationship must be rejected before persistence.",
        authorType: "operator",
      })).toThrow("cannot connect to private operational memory");

      expect(() => memory.createEdge({
        id: "legacy-supports-unreviewed",
        sourceNodeId: procedure.id,
        targetNodeId: recovery.id,
        edgeType: "supports",
        title: "Unreviewed reusable relation",
        summary: "System-authored reusable edges cannot self-promote.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.8,
        lifecycleStatus: "verified",
        provenance: provenance("private-unreviewed-source"),
        explanation: "This relationship requires operator review.",
        authorType: "system",
      })).toThrow("must remain candidates");
      expect(memory.createEdge({
        id: "legacy-supports-candidate",
        sourceNodeId: procedure.id,
        targetNodeId: recovery.id,
        edgeType: "supports",
        title: "Reviewable reusable relation",
        summary: "The system may propose this relationship for review.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.8,
        lifecycleStatus: "candidate",
        provenance: provenance("private-candidate-source"),
        explanation: "The relationship is not active until reviewed.",
        authorType: "system",
      }).lifecycleStatus).toBe("candidate");
    } finally {
      database.close();
    }
  });

  test("quarantines known engagement labels and targets resolved from private provenance", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
    try {
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, engagement_id, created_by, created_at, updated_at
        ) VALUES (?, ?, ?, 'guided', ?, 'operator', ?, ?)
      `).run("mission-known-label", "ReaperTwo", "Authorized fixture", "engagement-customer", NOW, NOW);
      database.prepare(`
        INSERT INTO mission_targets (
          id, mission_id, target, target_type, normalized_target, created_at
        ) VALUES (?, ?, ?, 'domain', ?, ?)
      `).run("target-known-label", "mission-known-label", "portal.example.com", "portal.example.com", NOW);
      const linkedProvenance = provenance("mission-known-label");
      expect(() => memory.createNode(node("attack_procedure", "known-engagement", {
        title: "ReaperTwo retry procedure",
        provenance: linkedProvenance,
      }))).toThrow("engagement_label");
      expect(() => memory.createCandidate({
        nodeType: "attack_procedure",
        title: "Portal retry procedure",
        summary: "Validate portal.example.com after recovery.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.8,
        provenance: linkedProvenance,
        proposedBy: "system:attack-knowledge-compiler",
      })).toThrow("target_identifier");

      const unrelatedProvenance = provenance("attack_knowledge_receipt:opaque-unrelated-source");
      expect(() => memory.createCandidate({
        nodeType: "attack_procedure",
        title: "ReaperTwo retry procedure",
        summary: "A reusable candidate must not disclose any known engagement label.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.8,
        provenance: unrelatedProvenance,
        proposedBy: "system:attack-knowledge-compiler",
      })).toThrow("engagement_label");
      expect(() => memory.createCandidate({
        nodeType: "attack_procedure",
        title: "Portal retry procedure",
        summary: "Validate portal.example.com after recovery.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.8,
        provenance: unrelatedProvenance,
        proposedBy: "system:attack-knowledge-compiler",
      })).toThrow("target_identifier");

      const reusable = memory.createNode(node("attack_procedure", "global-label-correction", {
        title: "Generalized bounded retry procedure",
        provenance: unrelatedProvenance,
      }));
      expect(() => memory.correctNode(reusable.id, {
        title: "ReaperTwo bounded retry procedure",
        authorType: "operator",
        authorId: "operator-reviewer",
        changeReason: "Attempt to add a private engagement label",
      })).toThrow("engagement_label");
    } finally {
      database.close();
    }
  });
});

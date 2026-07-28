import { describe, expect, test } from "bun:test";
import type { MemoryNode, MemoryNodeType } from "../../memory";
import {
  selectRelevantPhaseTransitionMemory,
  type BrainContextResult,
  type PhaseTransitionSemanticSignal,
} from "..";

const NOW = "2026-07-23T09:00:00.000Z";

function node(
  id: string,
  nodeType: MemoryNodeType,
  title: string,
  summary: string,
): MemoryNode {
  return {
    id,
    nodeType,
    title,
    summary,
    body: "",
    scope: { kind: "global" },
    sensitivity: "private",
    confidence: 1,
    lifecycleStatus: "verified",
    confirmationState: "not_required",
    provenance: {
      method: "derived",
      explanation: "Deterministic phase relevance fixture.",
      sources: [{ sourceType: "test_fixture", sourceId: id, acquiredAt: NOW }],
    },
    authorType: "system",
    authorId: "test",
    version: 1,
    retentionPolicy: { allowAutonomous: true, allowGuided: true },
    pinned: false,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function context(nodes: readonly MemoryNode[]): BrainContextResult {
  return {
    hook: "phase_transition",
    status: "ready",
    auditRecordId: "audit-phase-relevance",
    items: nodes.map((item) => ({
      node: item,
      relevanceReason: "Lexical phase query match",
    })),
    contextPack: {
      id: "context-phase-relevance",
      missionId: "mission-phase-relevance",
      runId: "run-phase-relevance",
      journey: "autonomous",
      purpose: "Phase transition relevance",
      scopePolicy: {
        journey: "autonomous",
        maximumSensitivity: "private",
        contextBudget: 4_000,
      },
      contextBudget: 4_000,
      retrievalMetrics: {},
      releaseDataClass: "canonical",
      createdBy: "phase-supervisor",
      createdAt: NOW,
      items: nodes.map((item) => ({
        nodeId: item.id,
        used: false,
        relevanceReason: "Lexical phase query match",
      })),
    },
  };
}

const signals: readonly PhaseTransitionSemanticSignal[] = [
  { kind: "action", key: "action_type", value: "web_endpoint_discovery" },
  { kind: "action", key: "action_class", value: "web_content_endpoint_discovery_fuzzing" },
  { kind: "phase", key: "phase", value: "Reconnaissance" },
  { kind: "observation", key: "observation", value: "service_fingerprint" },
  { kind: "technology", key: "product", value: "Apache HTTP Server" },
  { kind: "version", key: "version", value: "2.4.58" },
  { kind: "evidence", key: "evidence", value: "service_version_fingerprint" },
];

describe("phase-transition memory relevance", () => {
  test("prefers exact web-recon memory and never marks unrelated RDX/kernel history used", () => {
    const exact = node(
      "memory-web-recon-exact",
      "discovery_pattern",
      "Apache HTTP Server 2.4.58 endpoint reconnaissance",
      "Use bounded web endpoint discovery and preserve the service fingerprint.",
    );
    const generic = node(
      "memory-web-recon-generic",
      "attack_lesson",
      "Web endpoint discovery reconnaissance",
      "Corroborate endpoint fingerprints before choosing the next web phase.",
    );
    const exactVersion = node(
      "memory-web-version-exact",
      "exact_version_fingerprint",
      "Apache release 2.4.58",
      "Use this exact version fingerprint during endpoint discovery.",
    );
    const unrelated = node(
      "memory-rdx-kernel-unrelated",
      "kernel",
      "RDX kernel 6.1 historical service-version attribute",
      "A different target recorded kernel discovery and unrelated historical attributes.",
    );
    const unrelatedAttribute = node(
      "memory-rdx-attribute-unrelated",
      "attribute",
      "RDX return-register historical attribute",
      "A kernel calling-convention attribute from another technology stack.",
    );
    const result = selectRelevantPhaseTransitionMemory({
      context: context([unrelated, unrelatedAttribute, generic, exactVersion, exact]),
      semanticSignals: signals,
      allowedNodeTypes: new Set([
        "discovery_pattern",
        "attack_lesson",
        "exact_version_fingerprint",
        "kernel",
        "attribute",
      ]),
      activeVaultBackedNodeIds: new Set([
        exact.id,
        exactVersion.id,
        generic.id,
        unrelated.id,
        unrelatedAttribute.id,
      ]),
    });
    expect(result.nodeIds).toEqual([exact.id, exactVersion.id, generic.id]);
    expect(result.nodeIds).not.toContain(unrelated.id);
    expect(result.nodeIds).not.toContain(unrelatedAttribute.id);
    expect(result.activeVaultCandidateCount).toBe(5);
    expect(result.semanticallyRelevantCount).toBe(3);
  });

  test("keeps a relevant but unsynchronized node unused while still consulting the pack", () => {
    const relevant = node(
      "memory-web-recon-not-in-active-vault",
      "discovery_pattern",
      "Apache HTTP Server endpoint discovery",
      "Use the exact web fingerprint while enumerating endpoints.",
    );
    const result = selectRelevantPhaseTransitionMemory({
      context: context([relevant]),
      semanticSignals: signals,
      allowedNodeTypes: new Set(["discovery_pattern"]),
      activeVaultBackedNodeIds: new Set(),
    });
    expect(result).toEqual({
      nodeIds: [],
      activeVaultCandidateCount: 0,
      semanticallyRelevantCount: 0,
    });
  });
});

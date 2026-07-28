import { describe, expect, test } from "bun:test";
import {
  parseMemoryGraph,
  parseMemoryNodeDetail,
  parseMemoryOriginPage,
  parseMemorySourcePage,
  parseOperatorPreferencePage,
  parseProvenanceSource,
} from "../../../src/domain/schemas/brain";

const node = {
  id: "mem-graph-total-contract",
  nodeType: "technique",
  title: "Evidence-led enumeration",
  summary: "Confirm services before selecting a procedure.",
  scope: { kind: "global" },
  sensitivity: "internal",
  confidence: 0.92,
  lifecycleStatus: "verified",
  confirmationState: "not_required",
  version: 1,
  pinned: false,
  createdAt: "2026-07-17T00:00:00.000Z",
  updatedAt: "2026-07-17T00:00:00.000Z",
  edgeCount: 0,
  sourceCount: 1,
};

describe("Second Brain graph total schema", () => {
  test("retains access-controlled source custody and confirmed preference metadata", () => {
    expect(parseProvenanceSource({
      sourceType: "attack_knowledge_evidence_binding",
      sourceId: "source-receipt",
      sourceHash: "a".repeat(64),
      acquiredAt: "2026-07-21T10:00:00.000Z",
      origins: [{
        engagementLabel: "reapertwo",
        missionId: "mission-import",
        missionName: "Historical source import",
        runId: "run-import",
        runStatus: "completed",
        evidenceId: "evidence-source",
        privateSourceReference: "legacy-private-source://source-object",
        sourceLocator: "web/scripts/ready_after_reset.sh",
      }],
    }).origins).toEqual([{
      engagementLabel: "reapertwo",
      missionId: "mission-import",
      missionName: "Historical source import",
      runId: "run-import",
      runStatus: "completed",
      evidenceId: "evidence-source",
      privateSourceReference: "legacy-private-source://source-object",
      sourceLocator: "web/scripts/ready_after_reset.sh",
    }]);

    expect(parseOperatorPreferencePage({
      schemaVersion: "2.4",
      items: [{
        node: { ...node, id: "preference-readable", nodeType: "preference", lifecycleStatus: "confirmed", confirmationState: "confirmed" },
        preferenceKey: "guided.explanation_depth",
        value: { depth: "readable_technical" },
        appliesTo: ["guided_explanations"],
        operatorId: "operator",
        confirmationState: "confirmed",
        consentPolicy: "explicit_operator_confirmation",
        profileVersion: 1,
        lastConfirmedAt: "2026-07-21T10:00:00.000Z",
        provenance: {
          method: "operator_statement",
          explanation: "Explicitly confirmed by the operator.",
          sources: [{ sourceType: "operator_instruction_manifest", sourceId: "preference-readable", acquiredAt: "2026-07-21T10:00:00.000Z" }],
        },
      }],
      totalReturned: 1,
    })).toMatchObject({
      totalReturned: 1,
      items: [{ preferenceKey: "guided.explanation_depth", lastConfirmedAt: "2026-07-21T10:00:00.000Z" }],
    });
  });

  test("keeps loaded, available, and truncation metadata internally consistent", () => {
    expect(parseMemoryGraph({
      schemaVersion: "2.4",
      view: "global",
      nodes: [node],
      edges: [],
      availableNodeCount: 2,
      truncated: true,
    })).toMatchObject({ availableNodeCount: 2, truncated: true });

    expect(() => parseMemoryGraph({
      schemaVersion: "2.4",
      view: "global",
      nodes: [node],
      edges: [],
      availableNodeCount: 0,
      truncated: false,
    })).toThrow("cannot be smaller");

    expect(() => parseMemoryGraph({
      schemaVersion: "2.4",
      view: "global",
      nodes: [node],
      edges: [],
      availableNodeCount: 2,
      truncated: false,
    })).toThrow("truncation");
  });

  test("keeps evidence-linked success and failed outcomes independent and canonical", () => {
    const graph = parseMemoryGraph({
      schemaVersion: "2.4",
      view: "global",
      nodes: [{ ...node, outcomeTags: ["failed", "success", "failed"] }],
      edges: [],
      availableNodeCount: 1,
      truncated: false,
    });
    expect(graph.nodes[0]?.outcomeTags).toEqual(["success", "failed"]);

    const unclassified = parseMemoryGraph({
      schemaVersion: "2.4",
      view: "global",
      nodes: [{ ...node, outcomeTags: [] }],
      edges: [],
      availableNodeCount: 1,
      truncated: false,
    });
    expect(unclassified.nodes[0]?.outcomeTags).toBeUndefined();

    expect(() => parseMemoryGraph({
      schemaVersion: "2.4",
      view: "global",
      nodes: [{ ...node, outcomeTags: ["likely_success"] }],
      edges: [],
      availableNodeCount: 1,
      truncated: false,
    })).toThrow("memory outcome tag is invalid");
  });

  test("parses historical source reports without converting them into verified outcome tags", () => {
    const graph = parseMemoryGraph({
      schemaVersion: "2.4",
      view: "global",
      nodes: [{
        ...node,
        outcomeTags: [],
        reportedOutcome: {
          classification: "reported_failure",
          classificationConfidence: 0.86,
          claimCount: 4,
          sourceCount: 3,
          policyVersion: "historical-reported-outcome/v1",
        },
      }],
      edges: [],
      availableNodeCount: 1,
      truncated: false,
    });
    expect(graph.nodes[0]?.outcomeTags).toBeUndefined();
    expect(graph.nodes[0]?.reportedOutcome).toEqual({
      classification: "reported_failure",
      classificationConfidence: 0.86,
      claimCount: 4,
      sourceCount: 3,
      policyVersion: "historical-reported-outcome/v1",
    });

    expect(() => parseMemoryGraph({
      schemaVersion: "2.4",
      view: "global",
      nodes: [{
        ...node,
        reportedOutcome: {
          classification: "success",
          classificationConfidence: 0.9,
          claimCount: 1,
          sourceCount: 1,
          policyVersion: "historical-reported-outcome/v1",
        },
      }],
      edges: [],
      availableNodeCount: 1,
      truncated: false,
    })).toThrow("historical reported outcome classification is invalid");
  });

  test("parses bounded provenance pages while retaining old complete-detail responses", () => {
    const source = {
      sourceRecordId: "source-page-1",
      sourceType: "fixture",
      sourceId: "fixture-1",
      acquiredAt: "2026-07-21T10:00:00.000Z",
      originCount: 2,
      origins: [{ missionId: "mission-one" }],
      originsNextCursor: "origin-cursor",
    };
    expect(parseMemorySourcePage({
      schemaVersion: "2.4",
      nodeId: node.id,
      items: [source],
      totalCount: 12,
      nextCursor: "source-cursor",
    })).toMatchObject({ totalCount: 12, nextCursor: "source-cursor", items: [{ originCount: 2 }] });
    expect(parseMemoryOriginPage({
      schemaVersion: "2.4",
      nodeId: node.id,
      sourceRecordId: "source-page-1",
      items: [{ missionId: "mission-two" }],
      totalCount: 2,
      nextCursor: null,
    })).toMatchObject({ sourceRecordId: "source-page-1", totalCount: 2 });

    const { sourceCount: _missingSourceCount, ...oldNode } = node;
    const oldDetail = parseMemoryNodeDetail({
      schemaVersion: "2.4",
      node: {
        ...oldNode,
        body: "Legacy complete detail response",
        authorType: "import",
        provenance: {
          method: "imported",
          explanation: "Legacy response returned every source.",
          sources: [source],
        },
        retentionPolicy: {},
      },
      sources: [source],
      versions: [],
      backlinks: [],
      outgoing: [],
      usage: [],
    });
    expect(oldDetail.node.sourceCount).toBe(1);
    expect(oldDetail.sourcesNextCursor).toBeNull();

    expect(() => parseMemorySourcePage({
      schemaVersion: "2.4",
      nodeId: node.id,
      items: [source],
      totalCount: 0,
      nextCursor: null,
    })).toThrow("cannot be smaller");
    expect(() => parseProvenanceSource({
      ...source,
      originCount: 0,
    })).toThrow("cannot be smaller");
  });
});

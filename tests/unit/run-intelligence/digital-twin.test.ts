import { describe, expect, test } from "bun:test";
import { ReconDigitalTwinService } from "../../../server/run-intelligence";
import {
  AGENT_ONE_ID,
  MISSION_ID,
  NOW,
  RUN_ID,
  createTestDatabase,
  insertEvidence,
} from "./fixtures";

function nodeInput(evidenceId: string) {
  return {
    missionId: MISSION_ID,
    runId: RUN_ID,
    nodeType: "asset",
    primaryLabel: `Asset ${evidenceId}`,
    normalizedIdentity: `asset-${evidenceId}`,
    scopeStatus: "allowed" as const,
    lifecycleState: "observed" as const,
    properties: { address: "fixture.local" },
    provenance: {
      method: "structured_scan_parser",
      sourceRef: evidenceId,
      sourceAgentId: AGENT_ONE_ID,
      sourceTool: "fixture-scanner",
    },
    confidence: 0.9,
    verificationState: "verified" as const,
    sensitivity: "internal" as const,
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    evidence: [{ evidenceId, relationship: "supports" as const }],
  };
}

describe("evidence-backed recon digital twin", () => {
  test("requires scoped evidence, bounded confidence, and attributable provenance", () => {
    const database = createTestDatabase();
    try {
      insertEvidence(database, { id: "evidence-valid-topology" });
      insertEvidence(database, { id: "evidence-empty-provenance", provenance: {} });
      insertEvidence(database, { id: "evidence-unverified-topology", verificationState: "unverified" });
      const twin = new ReconDigitalTwinService(database, () => new Date(NOW));

      expect(() => twin.createNode({
        ...nodeInput("evidence-valid-topology"),
        evidence: [],
      })).toThrow("requires canonical evidence");
      expect(() => twin.createNode({
        ...nodeInput("evidence-valid-topology"),
        confidence: 1.01,
      })).toThrow("between zero and one");
      expect(() => twin.createNode({
        ...nodeInput("evidence-valid-topology"),
        provenance: { method: "parser", sourceRef: "record-without-origin" },
      })).toThrow("originating agent or tool");
      expect(() => twin.createNode(nodeInput("evidence-empty-provenance"))).toThrow("canonical provenance");
      expect(() => twin.createNode(nodeInput("evidence-unverified-topology"))).toThrow("requires verified evidence");

      const node = twin.createNode(nodeInput("evidence-valid-topology"));
      expect(node).toMatchObject({
        missionId: MISSION_ID,
        runId: RUN_ID,
        confidence: 0.9,
        verificationState: "verified",
        provenance: {
          method: "structured_scan_parser",
          sourceRef: "evidence-valid-topology",
          sourceAgentId: AGENT_ONE_ID,
          sourceTool: "fixture-scanner",
        },
      });
      expect(node.evidence).toEqual([
        expect.objectContaining({
          evidenceId: "evidence-valid-topology",
          relationship: "supports",
          verificationState: "verified",
        }),
      ]);
    } finally {
      database.close();
    }
  });

  test("preserves supporting and contradicting graph evidence without selecting a hidden winner", () => {
    const database = createTestDatabase();
    try {
      insertEvidence(database, { id: "evidence-support" });
      insertEvidence(database, { id: "evidence-contradict", verificationState: "disputed", confidence: 0.6 });
      const twin = new ReconDigitalTwinService(database, () => new Date(NOW));
      const source = twin.createNode(nodeInput("evidence-support"));
      const target = twin.createNode({
        ...nodeInput("evidence-support"),
        nodeType: "service",
        primaryLabel: "HTTPS service",
        normalizedIdentity: "service-https-fixture",
      });
      const edge = twin.createEdge({
        missionId: MISSION_ID,
        sourceNodeId: source.id,
        targetNodeId: target.id,
        edgeType: "exposes",
        properties: { transport: "tcp" },
        provenance: {
          method: "observation_reconciliation",
          sourceRef: "edge-observation-group",
          sourceAgentId: AGENT_ONE_ID,
        },
        confidence: 0.55,
        verificationState: "conflicting",
        sensitivity: "internal",
        firstSeenAt: NOW,
        lastSeenAt: NOW,
        evidence: [
          { evidenceId: "evidence-support", relationship: "supports" },
          { evidenceId: "evidence-contradict", relationship: "contradicts" },
        ],
      });
      expect(edge.verificationState).toBe("conflicting");
      expect(edge.evidence.map(({ relationship }) => relationship)).toEqual(["supports", "contradicts"]);
      const graph = twin.getGraph(MISSION_ID, RUN_ID);
      expect(graph.nodes.map(({ id }) => id).sort()).toEqual([source.id, target.id].sort());
      expect(graph.edges).toEqual([expect.objectContaining({ id: edge.id, verificationState: "conflicting" })]);
    } finally {
      database.close();
    }
  });

  test("synthesizes all seven OSI layers and leaves unknown layers not_observed", () => {
    const database = createTestDatabase();
    try {
      insertEvidence(database, { id: "evidence-layer-3" });
      insertEvidence(database, { id: "evidence-layer-7-a" });
      insertEvidence(database, { id: "evidence-layer-7-b", verificationState: "disputed" });
      insertEvidence(database, { id: "evidence-layer-unverified", verificationState: "unverified" });
      const twin = new ReconDigitalTwinService(database, () => new Date(NOW));
      const asset = twin.createNode(nodeInput("evidence-layer-3"));

      twin.recordOsiObservation({
        assetNodeId: asset.id,
        layer: 3,
        category: "address",
        value: "canonical-address-reference",
        derivation: "actively_verified",
        confidence: 0.95,
        evidenceId: "evidence-layer-3",
        observedAt: NOW,
      });
      let stack = twin.getOsiStack(asset.id);
      expect(stack.layers).toHaveLength(7);
      expect(stack.layers.map(({ layer }) => layer)).toEqual([1, 2, 3, 4, 5, 6, 7]);
      expect(stack.layers[2]).toMatchObject({ layer: 3, name: "Network", state: "observed" });
      for (const layer of stack.layers.filter(({ layer }) => layer !== 3)) {
        expect(layer.state).toBe("not_observed");
        expect(layer.observations).toEqual([]);
      }

      twin.recordOsiObservation({
        assetNodeId: asset.id,
        layer: 7,
        category: "service_product",
        value: "product-a",
        versionValue: "1.0",
        derivation: "observed",
        confidence: 0.7,
        evidenceId: "evidence-layer-7-a",
        observedAt: "2026-07-16T12:02:00.000Z",
        conflictGroupId: "product-banner-conflict",
      });
      twin.recordOsiObservation({
        assetNodeId: asset.id,
        layer: 7,
        category: "service_product",
        value: "product-b",
        versionValue: "2.0",
        derivation: "observed",
        confidence: 0.6,
        evidenceId: "evidence-layer-7-b",
        observedAt: "2026-07-16T12:03:00.000Z",
        conflictGroupId: "product-banner-conflict",
      });
      stack = twin.getOsiStack(asset.id);
      expect(stack.layers[6]?.state).toBe("conflicting");
      expect(stack.layers[6]?.observations.map(({ value }) => value)).toEqual(["product-a", "product-b"]);
      expect(stack.layers[0]).toEqual({ layer: 1, name: "Physical", state: "not_observed", observations: [] });

      expect(() => twin.recordOsiObservation({
        assetNodeId: asset.id,
        layer: 4,
        category: "port",
        value: "443/tcp",
        derivation: "actively_verified",
        confidence: 0.8,
        evidenceId: "evidence-layer-unverified",
        observedAt: NOW,
      })).toThrow("requires verified evidence");
    } finally {
      database.close();
    }
  });
});

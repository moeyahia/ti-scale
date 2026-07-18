import { afterEach, describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { NavigationProvider } from "../../../src/app/router/navigation";
import { AttackAttemptService, ReconDigitalTwinService, RunMetricsService } from "../../../server/run-intelligence";
import { runIntelligenceApi } from "../../../src/data/api/runIntelligence";
import {
  parseAssetOsiStackDetail,
  parseAttackAttemptDetail,
  parseReconDigitalTwinDetail,
  parseRunMetricsSnapshotDetail,
  parseRunMetricsSnapshotList,
  parseTopologyNodeDetail,
} from "../../../src/domain/schemas/runIntelligence";
import { ReconDigitalTwinPanel } from "../../../src/features/run-intelligence/ReconDigitalTwinPanel";
import { RunMetricsPanel } from "../../../src/features/run-intelligence/RunMetricsPanel";
import {
  AGENT_ONE_ID,
  MISSION_ID,
  NOW,
  RUN_ID,
  createTestDatabase,
  insertEvidence,
} from "../run-intelligence/fixtures";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

function createIntelligenceFixture() {
  const database = createTestDatabase();
  insertEvidence(database, { id: "evidence-browser-contract" });
  const twin = new ReconDigitalTwinService(database, () => new Date(NOW));
  const base = {
    missionId: MISSION_ID,
    runId: RUN_ID,
    scopeStatus: "allowed" as const,
    lifecycleState: "observed" as const,
    provenance: {
      method: "structured_fixture_parser",
      sourceRef: "evidence-browser-contract",
      sourceAgentId: AGENT_ONE_ID,
      sourceTool: "fixture-parser",
    },
    confidence: 0.92,
    verificationState: "verified" as const,
    sensitivity: "internal" as const,
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    evidence: [{ evidenceId: "evidence-browser-contract", relationship: "supports" as const }],
  };
  const asset = twin.createNode({
    ...base, nodeType: "asset", primaryLabel: "Authorized fixture host",
    normalizedIdentity: "fixture-host", properties: { address: "fixture.local" },
  });
  const service = twin.createNode({
    ...base, nodeType: "service", primaryLabel: "HTTPS service",
    normalizedIdentity: "fixture-https", properties: { transport: "tcp", port: 443 },
  });
  twin.createEdge({
    missionId: MISSION_ID, sourceNodeId: asset.id, targetNodeId: service.id, edgeType: "exposes",
    properties: { transport: "tcp" }, provenance: base.provenance, confidence: 0.92,
    verificationState: "verified", sensitivity: "internal", firstSeenAt: NOW, lastSeenAt: NOW,
    evidence: base.evidence,
  });
  twin.recordOsiObservation({
    assetNodeId: asset.id, layer: 3, category: "address", value: "fixture.local",
    derivation: "actively_verified", confidence: 0.92, evidenceId: "evidence-browser-contract", observedAt: NOW,
  });
  const attempt = new AttackAttemptService(database, () => new Date(NOW)).create({
    missionId: MISSION_ID, runId: RUN_ID, targetAssetId: asset.id, targetServiceId: service.id,
    objective: "Classify a bounded, authorized service hypothesis", techniqueName: "Service validation",
    actionClass: "vulnerability_scanning", assignedAgentId: AGENT_ONE_ID,
  });
  return { database, twin, asset, attempt };
}

describe("strict run-intelligence browser boundary", () => {
  test("accepts canonical metric, attempt, topology, node, and seven-layer OSI responses", () => {
    const fixture = createIntelligenceFixture();
    try {
      const snapshot = new RunMetricsService(fixture.database).compute(RUN_ID);
      expect(parseRunMetricsSnapshotDetail({ schemaVersion: "2.4", snapshot }).snapshot.metrics).toHaveLength(57);
      expect(parseRunMetricsSnapshotList({ schemaVersion: "2.4", items: [snapshot], latestSnapshotId: snapshot.id }).latestSnapshotId).toBe(snapshot.id);
      expect(parseAttackAttemptDetail({ schemaVersion: "2.4", attempt: fixture.attempt }).attempt.status).toBe("planned");
      const graph = fixture.twin.getGraph(MISSION_ID, RUN_ID);
      expect(parseReconDigitalTwinDetail({ schemaVersion: "2.4", digitalTwin: graph }).digitalTwin.edges).toHaveLength(1);
      expect(parseTopologyNodeDetail({ schemaVersion: "2.4", node: fixture.asset }).node.evidence).toHaveLength(1);
      const stack = parseAssetOsiStackDetail({ schemaVersion: "2.4", stack: fixture.twin.getOsiStack(fixture.asset.id) }).stack;
      expect(stack.layers).toHaveLength(7);
      expect(stack.layers[0]).toEqual({ layer: 1, name: "Physical", state: "not_observed", observations: [] });
      expect(stack.layers[2]?.state).toBe("observed");
    } finally { fixture.database.close(); }
  });

  test("rejects incomplete metrics, scope-escaping drill-downs, unsupported fields, and incomplete OSI stacks", () => {
    const fixture = createIntelligenceFixture();
    try {
      const snapshot = new RunMetricsService(fixture.database).compute(RUN_ID);
      expect(() => parseRunMetricsSnapshotDetail({
        schemaVersion: "2.4", snapshot: { ...snapshot, metrics: snapshot.metrics.slice(1) },
      })).toThrow("incomplete or contains duplicate metrics");
      const [first, ...rest] = snapshot.metrics;
      expect(first).toBeDefined();
      expect(() => parseRunMetricsSnapshotDetail({
        schemaVersion: "2.4",
        snapshot: {
          ...snapshot,
          metrics: [{ ...first!, drillDown: [{ ...first!.drillDown[0]!, runId: "another-run" }] }, ...rest],
        },
      })).toThrow("escapes its snapshot scope");
      expect(() => parseAttackAttemptDetail({ schemaVersion: "2.4", attempt: { ...fixture.attempt, decorativeScore: 99 } })).toThrow("unsupported field decorativeScore");
      const stack = fixture.twin.getOsiStack(fixture.asset.id);
      expect(() => parseAssetOsiStackDetail({ schemaVersion: "2.4", stack: { ...stack, layers: stack.layers.slice(0, 6) } })).toThrow("all seven ordered layers");
    } finally { fixture.database.close(); }
  });

  test("uses only authenticated read paths and validates the returned snapshot", async () => {
    const fixture = createIntelligenceFixture();
    try {
      const snapshot = new RunMetricsService(fixture.database).compute(RUN_ID);
      globalThis.fetch = (async (input, init) => {
        expect(String(input)).toBe(`/api/v2/runs/${RUN_ID}/intelligence/metrics/snapshots?limit=10`);
        expect(init?.method).toBe("GET");
        return new Response(JSON.stringify({ schemaVersion: "2.4", items: [snapshot], latestSnapshotId: snapshot.id }), {
          status: 200, headers: { "content-type": "application/json", "x-request-id": "request-run-intelligence" },
        });
      }) as typeof fetch;
      const response = await runIntelligenceApi.listMetricSnapshots(RUN_ID, 10);
      expect(response.items[0]?.recomputationHash).toBe(snapshot.recomputationHash);
      expect(() => runIntelligenceApi.listMetricSnapshots(RUN_ID, 101)).toThrow("1 through 100");
    } finally { fixture.database.close(); }
  });
});

describe("run-intelligence presentational panels", () => {
  test("renders inspectable canonical drill-downs and does not turn a missing attempt outcome into failure", () => {
    const fixture = createIntelligenceFixture();
    try {
      const snapshot = parseRunMetricsSnapshotDetail({
        schemaVersion: "2.4", snapshot: new RunMetricsService(fixture.database).compute(RUN_ID),
      }).snapshot;
      const markup = renderToStaticMarkup(
        <NavigationProvider>
          <RunMetricsPanel snapshot={snapshot} attackAttempts={[fixture.attempt]} />
        </NavigationProvider>,
      );
      expect(markup).toContain("Inspect 1 canonical drill-down");
      expect(markup).toContain("run_id eq run-intelligence");
      expect(markup).toContain("Not observed");
      expect(markup).toContain("Not classified");
      expect(markup).not.toContain("decorative");
    } finally { fixture.database.close(); }
  });

  test("renders the evidence-backed relationship list and says Not observed for unknown OSI layers", () => {
    const fixture = createIntelligenceFixture();
    try {
      const graph = parseReconDigitalTwinDetail({ schemaVersion: "2.4", digitalTwin: fixture.twin.getGraph(MISSION_ID, RUN_ID) }).digitalTwin;
      const stack = parseAssetOsiStackDetail({ schemaVersion: "2.4", stack: fixture.twin.getOsiStack(fixture.asset.id) }).stack;
      const markup = renderToStaticMarkup(
        <NavigationProvider>
          <ReconDigitalTwinPanel graph={graph} selectedNode={fixture.asset} osiStack={stack} />
        </NavigationProvider>,
      );
      expect(markup).toContain("Evidence-backed topology list");
      expect(markup).toContain("evidence-browser-contract");
      expect(markup).toContain("exposes");
      expect(markup.match(/Not observed/g)?.length).toBeGreaterThanOrEqual(6);
      expect(markup).toContain("Unobserved layers remain explicitly unknown");
    } finally { fixture.database.close(); }
  });
});

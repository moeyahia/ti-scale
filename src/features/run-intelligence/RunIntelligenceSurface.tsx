import { useEffect, useMemo, useState } from "react";
import { runIntelligenceApi } from "../../data/api/runIntelligence";
import { cveIntelligenceApi } from "../../data/api/cveIntelligence";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, Card, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { DegradedNotice } from "../runs/OperationalSurface";
import { ReconDigitalTwinPanel } from "./ReconDigitalTwinPanel";
import { RunMetricsPanel } from "./RunMetricsPanel";
import { CveApplicabilityPanel } from "./CveApplicabilityPanel";

const ASSET_NODE_TYPES = new Set([
  "asset", "host", "network_device", "cloud_asset", "container", "cluster",
]);
const CVE_SERVICE_NODE_TYPES = new Set([
  "service", "application", "package", "operating_system", "kernel", "component",
]);

export function RunMetricsSurface({ runId }: { readonly runId: string }) {
  const snapshots = useQuery(
    `run-intelligence:metrics:${runId}`,
    (signal) => runIntelligenceApi.listMetricSnapshots(runId, 20, signal),
    { staleTime: 5_000 },
  );
  const attempts = useQuery(
    `run-intelligence:attempts:${runId}`,
    (signal) => runIntelligenceApi.listAttackAttempts(runId, signal),
    { staleTime: 5_000 },
  );
  if (snapshots.isLoading && !snapshots.data) return <LoadingPanel label="Loading reproducible run metrics" />;
  if (snapshots.error && !snapshots.data) {
    return <ErrorPanel title="Run metrics are unavailable" error={snapshots.error} onRetry={snapshots.refresh} />;
  }
  const latest = snapshots.data?.items.find((item) => item.id === snapshots.data?.latestSnapshotId)
    ?? snapshots.data?.items[0]
    ?? null;
  return <section aria-label="Reproducible run metrics">
    <div className="os-card-heading">
      <div><p className="os-eyebrow">Canonical statistics</p><h2>Recomputed run intelligence</h2></div>
      <Button variant="secondary" onClick={() => { snapshots.refresh(); attempts.refresh(); }}>Refresh records</Button>
    </div>
    {snapshots.error && snapshots.data && <DegradedNotice>The latest metrics refresh failed; the last validated snapshot remains visible.</DegradedNotice>}
    {attempts.error && <DegradedNotice>Attack-attempt classifications could not be refreshed. Metrics remain visible without inventing attempt outcomes.</DegradedNotice>}
    <RunMetricsPanel snapshot={latest} attackAttempts={attempts.data?.items ?? []} />
  </section>;
}

export function ReconDigitalTwinSurface({ missionId, runId }: {
  readonly missionId: string;
  readonly runId?: string;
}) {
  const [selectedNodeId, setSelectedNodeId] = useState("");
  const graph = useQuery(
    `run-intelligence:topology:${missionId}:${runId ?? "mission"}`,
    (signal) => runIntelligenceApi.getMissionTopology(missionId, runId, signal),
    { staleTime: 5_000 },
  );
  const availableIds = useMemo(
    () => new Set(graph.data?.digitalTwin.nodes.map((node) => node.id) ?? []),
    [graph.data?.digitalTwin.nodes],
  );
  useEffect(() => {
    if (selectedNodeId && !availableIds.has(selectedNodeId)) setSelectedNodeId("");
  }, [availableIds, selectedNodeId]);
  const selectedFromGraph = graph.data?.digitalTwin.nodes.find((node) => node.id === selectedNodeId);
  const selected = useQuery(
    `run-intelligence:topology-node:${missionId}:${selectedNodeId || "none"}:${runId ?? "mission"}`,
    (signal) => selectedNodeId
      ? runIntelligenceApi.getTopologyNode(missionId, selectedNodeId, runId, signal)
      : Promise.resolve(undefined),
    { staleTime: 5_000 },
  );
  const selectedNode = selected.data?.node ?? selectedFromGraph;
  const isAsset = Boolean(selectedNode && ASSET_NODE_TYPES.has(selectedNode.nodeType));
  const osi = useQuery(
    `run-intelligence:osi:${missionId}:${isAsset ? selectedNodeId : "none"}:${runId ?? "mission"}`,
    (signal) => isAsset && selectedNodeId
      ? runIntelligenceApi.getAssetOsiStack(missionId, selectedNodeId, runId, signal)
      : Promise.resolve(undefined),
    { staleTime: 5_000 },
  );
  const isCveService = Boolean(selectedNode && CVE_SERVICE_NODE_TYPES.has(selectedNode.nodeType));
  const cves = useQuery(
    `run-intelligence:cves:${missionId}:${selectedNodeId || "none"}:${runId ?? "mission"}`,
    (signal) => selectedNodeId && (isAsset || isCveService)
      ? cveIntelligenceApi.list(missionId, {
        ...(runId ? { runId } : {}),
        ...(isAsset ? { assetNodeId: selectedNodeId } : { serviceNodeId: selectedNodeId }),
        limit: 100,
      }, signal)
      : Promise.resolve(undefined),
    { staleTime: 5_000 },
  );

  if (graph.isLoading && !graph.data) return <LoadingPanel label="Loading evidence-backed recon topology" />;
  if (graph.error && !graph.data) {
    return <ErrorPanel title="Recon digital twin is unavailable" error={graph.error} onRetry={graph.refresh} />;
  }
  if (!graph.data) return null;
  const nodes = graph.data.digitalTwin.nodes;
  return <section aria-label="Recon digital twin">
    <Card>
      <div className="os-card-heading">
        <div><p className="os-eyebrow">Evidence-backed environment</p><h2>Inspect a discovered node</h2></div>
        <StatusPill status={nodes.length ? "observed" : "not_observed"}>{nodes.length} canonical nodes</StatusPill>
      </div>
      <label>
        <span>Asset, service, identity, or zone</span>
        <select value={selectedNodeId} onChange={(event) => setSelectedNodeId(event.target.value)}>
          <option value="">No node selected</option>
          {nodes.map((node) => <option key={node.id} value={node.id}>{node.primaryLabel} · {node.nodeType.replaceAll("_", " ")}</option>)}
        </select>
      </label>
      <p className="os-muted">Selecting an asset loads its complete seven-layer projection. Unobserved layers remain explicitly unknown.</p>
      <Button variant="secondary" onClick={() => { graph.refresh(); if (selectedNodeId) selected.refresh(); if (isAsset) osi.refresh(); if (isAsset || isCveService) cves.refresh(); }}>Refresh topology</Button>
    </Card>
    {graph.error && <DegradedNotice>The topology refresh failed; the last validated graph remains visible.</DegradedNotice>}
    {selected.error && <DegradedNotice>The selected node detail is unavailable; its last graph projection remains visible.</DegradedNotice>}
    {osi.error && <DegradedNotice>The selected asset’s OSI projection could not be loaded. No layer values were inferred.</DegradedNotice>}
    {cves.error && <DegradedNotice>CVE applicability could not be refreshed. The interface will not infer candidates from a product banner.</DegradedNotice>}
    <ReconDigitalTwinPanel
      graph={graph.data.digitalTwin}
      {...(selectedNode ? { selectedNode } : {})}
      {...(osi.data?.stack ? { osiStack: osi.data.stack } : {})}
    />
    {selectedNode && (isAsset || isCveService) && <CveApplicabilityPanel
      records={cves.data?.items ?? []}
      targetLabel={selectedNode.primaryLabel}
    />}
  </section>;
}

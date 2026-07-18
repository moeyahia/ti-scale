import { Card, EmptyState, StatusPill } from "../../design-system/components/Primitives";
import { AppLink } from "../../app/router/navigation";
import type {
  AssetOsiStack,
  OsiLayerProjection,
  ReconDigitalTwin,
  TopologyEdge,
  TopologyEvidenceLink,
  TopologyNode,
} from "../../domain/types/runIntelligence";

function formatTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium", timeStyle: "short",
  }).format(date);
}

function EvidenceList({ evidence, label }: { readonly evidence: readonly TopologyEvidenceLink[]; readonly label: string }) {
  return <details className="os-raw-details">
    <summary>{evidence.length} evidence record{evidence.length === 1 ? "" : "s"}</summary>
    <ul aria-label={label}>{evidence.map((item) => <li key={`${item.evidenceId}-${item.relationship}`}>
      <strong>{item.summary}</strong><br />
      <AppLink href={`/intelligence/evidence/${encodeURIComponent(item.evidenceId)}`}>{item.evidenceId}</AppLink> · {item.relationship} · {item.verificationState} · {Math.round(item.confidence * 100)}%
      <small> Captured {formatTimestamp(item.createdAt)} · hash <code>{item.contentHash}</code></small>
    </li>)}</ul>
  </details>;
}

function RelationshipList({ node, graph, outgoing, incoming }: {
  readonly node: TopologyNode;
  readonly graph: ReconDigitalTwin;
  readonly outgoing: readonly TopologyEdge[];
  readonly incoming: readonly TopologyEdge[];
}) {
  const nodes = new Map(graph.nodes.map((candidate) => [candidate.id, candidate]));
  if (outgoing.length === 0 && incoming.length === 0) return <p>No evidence-backed relationships are represented.</p>;
  return <ul aria-label={`Relationships for ${node.primaryLabel}`}>
    {outgoing.map((edge) => <li key={edge.id}>
      <span aria-label="outgoing relationship">→</span> <strong>{edge.edgeType.replaceAll("_", " ")}</strong> {nodes.get(edge.targetNodeId)?.primaryLabel ?? edge.targetNodeId}
      <span> · {edge.verificationState} · {Math.round(edge.confidence * 100)}%</span>
      <EvidenceList evidence={edge.evidence} label={`Evidence for ${edge.edgeType} relationship`} />
    </li>)}
    {incoming.map((edge) => <li key={edge.id}>
      <span aria-label="incoming relationship">←</span> <strong>{edge.edgeType.replaceAll("_", " ")}</strong> {nodes.get(edge.sourceNodeId)?.primaryLabel ?? edge.sourceNodeId}
      <span> · {edge.verificationState} · {Math.round(edge.confidence * 100)}%</span>
      <EvidenceList evidence={edge.evidence} label={`Evidence for ${edge.edgeType} relationship`} />
    </li>)}
  </ul>;
}

function TopologyNodeItem({ node, graph }: { readonly node: TopologyNode; readonly graph: ReconDigitalTwin }) {
  const outgoing = graph.edges.filter(({ sourceNodeId }) => sourceNodeId === node.id);
  const incoming = graph.edges.filter(({ targetNodeId }) => targetNodeId === node.id);
  return <li>
    <article className="os-card" aria-labelledby={`topology-node-${node.id}`}>
      <div className="os-card-heading"><div><p className="os-eyebrow">{node.nodeType.replaceAll("_", " ")}</p><h3 id={`topology-node-${node.id}`}>{node.primaryLabel}</h3><p><code>{node.normalizedIdentity}</code></p></div><StatusPill status={node.lifecycleState}>{node.lifecycleState}</StatusPill></div>
      <dl className="os-key-values">
        <div><dt>Scope</dt><dd>{node.scopeStatus.replaceAll("_", " ")}</dd></div>
        <div><dt>Verification</dt><dd>{node.verificationState}</dd></div>
        <div><dt>Confidence</dt><dd>{Math.round(node.confidence * 100)}%</dd></div>
        <div><dt>Last seen</dt><dd>{formatTimestamp(node.lastSeenAt)}</dd></div>
      </dl>
      <EvidenceList evidence={node.evidence} label={`Evidence for ${node.primaryLabel}`} />
      <details className="os-raw-details"><summary>Evidence-backed relationships ({outgoing.length + incoming.length})</summary><RelationshipList node={node} graph={graph} outgoing={outgoing} incoming={incoming} /></details>
    </article>
  </li>;
}

function SelectedNodeInspector({ node }: { readonly node: TopologyNode }) {
  return <Card aria-labelledby="selected-topology-node">
    <p className="os-eyebrow">Asset inspector</p><h2 id="selected-topology-node">{node.primaryLabel}</h2>
    <p>{node.nodeType.replaceAll("_", " ")} · <code>{node.id}</code></p>
    <dl className="os-key-values">
      <div><dt>Normalized identity</dt><dd><code>{node.normalizedIdentity}</code></dd></div>
      <div><dt>Scope</dt><dd>{node.scopeStatus.replaceAll("_", " ")}</dd></div>
      <div><dt>Sensitivity</dt><dd>{node.sensitivity}</dd></div>
      <div><dt>Verification</dt><dd>{node.verificationState}</dd></div>
      <div><dt>First seen</dt><dd>{formatTimestamp(node.firstSeenAt)}</dd></div>
      <div><dt>Last seen</dt><dd>{formatTimestamp(node.lastSeenAt)}</dd></div>
      <div><dt>Origin method</dt><dd>{node.provenance.method}</dd></div>
      <div><dt>Origin</dt><dd>{node.provenance.sourceAgentId ?? node.provenance.sourceTool ?? "Not attributed"}</dd></div>
    </dl>
    <details className="os-raw-details"><summary>Observed properties</summary><pre>{JSON.stringify(node.properties, null, 2)}</pre></details>
    <EvidenceList evidence={node.evidence} label={`Inspector evidence for ${node.primaryLabel}`} />
  </Card>;
}

function OsiLayer({ layer }: { readonly layer: OsiLayerProjection }) {
  return <li>
    <article aria-labelledby={`osi-layer-${layer.layer}`}>
      <div className="os-card-heading"><div><p className="os-eyebrow">Layer {layer.layer}</p><h3 id={`osi-layer-${layer.layer}`}>{layer.name}</h3></div><StatusPill status={layer.state}>{layer.state === "not_observed" ? "Not observed" : layer.state}</StatusPill></div>
      {layer.state === "not_observed" ? <p>Not observed</p> : <ul>{layer.observations.map((observation) => <li key={observation.id}>
        <strong>{observation.category.replaceAll("_", " ")}: {observation.value}</strong>{observation.versionValue && <> · version {observation.versionValue}</>}
        <small> {observation.derivation.replaceAll("_", " ")} · {Math.round(observation.confidence * 100)}% · {formatTimestamp(observation.observedAt)}</small><br />
        <span>Evidence <AppLink href={`/intelligence/evidence/${encodeURIComponent(observation.evidenceId)}`}>{observation.evidenceId}</AppLink> · {observation.evidenceVerificationState}</span>
        {observation.conflictGroupId && <span> · conflict group <code>{observation.conflictGroupId}</code></span>}
      </li>)}</ul>}
    </article>
  </li>;
}

function OsiStack({ stack }: { readonly stack: AssetOsiStack }) {
  return <Card aria-labelledby="asset-osi-stack">
    <p className="os-eyebrow">Evidence-backed layer view</p><h2 id="asset-osi-stack">OSI and application stack</h2>
    <p>Asset <code>{stack.assetNodeId}</code>. Unobserved layers remain explicitly unknown.</p>
    <ol>{stack.layers.map((layer) => <OsiLayer key={layer.layer} layer={layer} />)}</ol>
  </Card>;
}

export function ReconDigitalTwinPanel({ graph, selectedNode, osiStack }: {
  readonly graph: ReconDigitalTwin;
  readonly selectedNode?: TopologyNode;
  readonly osiStack?: AssetOsiStack;
}) {
  if (graph.nodes.length === 0) return <Card><EmptyState title="No evidence-backed topology yet" description="No recon nodes or relationships have been promoted into the canonical digital twin. Unknown topology is not synthesized in the browser." /></Card>;
  return <div>
    <Card><div className="os-card-heading"><div><p className="os-eyebrow">Recon digital twin</p><h2>Discovered environment</h2><p>An accessible relationship list backed by canonical evidence. It does not infer missing links.</p></div><StatusPill status="observed">{graph.nodes.length} nodes · {graph.edges.length} edges</StatusPill></div><dl className="os-key-values"><div><dt>Mission</dt><dd><code>{graph.missionId}</code></dd></div><div><dt>Run scope</dt><dd>{graph.runId ? <code>{graph.runId}</code> : "Mission-wide"}</dd></div></dl></Card>
    <section aria-labelledby="digital-twin-list"><h2 id="digital-twin-list">Evidence-backed topology list</h2><ul aria-label="Recon digital twin nodes">{graph.nodes.map((node) => <TopologyNodeItem key={node.id} node={node} graph={graph} />)}</ul></section>
    {selectedNode && <SelectedNodeInspector node={selectedNode} />}
    {osiStack && <OsiStack stack={osiStack} />}
  </div>;
}

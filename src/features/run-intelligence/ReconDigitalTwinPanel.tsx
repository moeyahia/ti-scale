import { useMemo } from "react";
import { Button, Card, EmptyState, StatusPill } from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import { AppLink } from "../../app/router/navigation";
import type {
  AssetOsiStack,
  OsiLayerProjection,
  ReconDigitalTwin,
  TopologyEdge,
  TopologyEvidenceLink,
  TopologyNode,
  TopologyVerificationState,
} from "../../domain/types/runIntelligence";
import { TopologyGraphViewport } from "./TopologyGraphViewport";
import {
  buildTopologyGraphModel,
  type TopologyGraphFilters,
} from "./topologyGraphModel";

export interface TopologyViewState {
  readonly view: "graph" | "list";
  readonly search: string;
  readonly nodeType: string;
  readonly lifecycleState: string;
  readonly scopeStatus: string;
  readonly verificationState: string;
}

const DEFAULT_TOPOLOGY_VIEW_STATE: TopologyViewState = Object.freeze({
  view: "graph",
  search: "",
  nodeType: "",
  lifecycleState: "",
  scopeStatus: "",
  verificationState: "",
});

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
  if (outgoing.length === 0 && incoming.length === 0) return <p>No canonical relationships are represented.</p>;
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

function TopologyNodeItem({ node, graph, outgoing, incoming }: {
  readonly node: TopologyNode;
  readonly graph: ReconDigitalTwin;
  readonly outgoing: readonly TopologyEdge[];
  readonly incoming: readonly TopologyEdge[];
}) {
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
      <details className="os-raw-details"><summary>Canonical relationships ({outgoing.length + incoming.length})</summary><RelationshipList node={node} graph={graph} outgoing={outgoing} incoming={incoming} /></details>
    </article>
  </li>;
}

function SelectedNodeInspector({ node }: { readonly node: TopologyNode }) {
  return <aside className="os-topology-inspector" aria-label="Selected topology node"><Card aria-labelledby="selected-topology-node">
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
  </Card></aside>;
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

function optionValues(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function selectFilters(state: TopologyViewState): TopologyGraphFilters {
  return {
    ...(state.search ? { search: state.search } : {}),
    ...(state.nodeType ? { nodeTypes: [state.nodeType] } : {}),
    ...(state.lifecycleState
      ? { lifecycleStates: [state.lifecycleState as TopologyNode["lifecycleState"]] }
      : {}),
    ...(state.scopeStatus
      ? { scopeStatuses: [state.scopeStatus as TopologyNode["scopeStatus"]] }
      : {}),
    ...(state.verificationState
      ? { verificationStates: [state.verificationState as TopologyVerificationState] }
      : {}),
  };
}

function TopologyList({
  graph,
  nodes,
  selectedNodeId,
  onSelectNode,
  controlNamespace,
}: {
  readonly graph: ReconDigitalTwin;
  readonly nodes: readonly TopologyNode[];
  readonly selectedNodeId?: string;
  readonly onSelectNode?: (nodeId: string) => void;
  readonly controlNamespace: string;
}) {
  return <div className="os-table-wrap"><table className="os-data-table os-topology-list-table" aria-label="Accessible recon topology node list">
    <thead><tr><th>Inspect</th><th>Node</th><th>Type</th><th>State</th><th>Scope</th><th>Verification</th><th>Relationships</th></tr></thead>
    <tbody>{nodes.map((node) => {
      const outgoing = graph.edges.filter((edge) => edge.sourceNodeId === node.id);
      const incoming = graph.edges.filter((edge) => edge.targetNodeId === node.id);
      return <tr key={node.id}>
        <td><Button
          type="button"
          variant="quiet"
          aria-label={`Inspect ${node.primaryLabel}`}
          aria-current={selectedNodeId === node.id ? "true" : undefined}
          data-control-id={`${controlNamespace}-list-selection`}
          onClick={() => onSelectNode?.(node.id)}
        >Inspect</Button></td>
        <th scope="row">{node.primaryLabel}<small><code>{node.normalizedIdentity}</code></small></th>
        <td>{node.nodeType.replaceAll("_", " ")}</td>
        <td><StatusPill status={node.lifecycleState} /></td>
        <td>{node.scopeStatus.replaceAll("_", " ")}</td>
        <td>{node.verificationState}</td>
        <td>{outgoing.length + incoming.length}</td>
      </tr>;
    })}</tbody>
  </table></div>;
}

export function ReconDigitalTwinPanel({
  graph,
  selectedNode,
  osiStack,
  selectedNodeId,
  onSelectNode,
  viewState = DEFAULT_TOPOLOGY_VIEW_STATE,
  onViewStateChange,
  surface = "plan",
}: {
  readonly graph: ReconDigitalTwin;
  readonly selectedNode?: TopologyNode;
  readonly osiStack?: AssetOsiStack;
  readonly selectedNodeId?: string;
  readonly onSelectNode?: (nodeId: string) => void;
  readonly viewState?: TopologyViewState;
  readonly onViewStateChange?: (patch: Partial<TopologyViewState>) => void;
  readonly surface?: "plan" | "live";
}) {
  const model = useMemo(() => buildTopologyGraphModel(
    graph,
    selectFilters(viewState),
    { width: 960, height: 520, padding: 64, nodeRadius: 12 },
  ), [graph, viewState]);
  const outgoingByNode = useMemo(() => {
    const result = new Map<string, TopologyEdge[]>();
    for (const edge of graph.edges) {
      const bucket = result.get(edge.sourceNodeId) ?? [];
      bucket.push(edge);
      result.set(edge.sourceNodeId, bucket);
    }
    return result;
  }, [graph.edges]);
  const incomingByNode = useMemo(() => {
    const result = new Map<string, TopologyEdge[]>();
    for (const edge of graph.edges) {
      const bucket = result.get(edge.targetNodeId) ?? [];
      bucket.push(edge);
      result.set(edge.targetNodeId, bucket);
    }
    return result;
  }, [graph.edges]);
  const nodeTypes = optionValues(graph.nodes.map((node) => node.nodeType));
  const lifecycleStates = optionValues(graph.nodes.map((node) => node.lifecycleState));
  const scopeStatuses = optionValues(graph.nodes.map((node) => node.scopeStatus));
  const verificationStates = optionValues(graph.nodes.map((node) => node.verificationState));
  const controlNamespace = `run-intelligence-${surface}-topology`;
  const updateView = (patch: Partial<TopologyViewState>) => onViewStateChange?.(patch);
  if (graph.nodes.length === 0) return <Card><EmptyState title="No evidence-backed topology yet" description="No recon nodes or relationships have been promoted into the canonical digital twin. Unknown topology is not synthesized in the browser." /></Card>;
  return <div>
    <Card><div className="os-card-heading"><div><p className="os-eyebrow">Recon digital twin</p><h2>Discovered environment</h2><p>An interactive projection of canonical nodes and typed relationships. Missing links remain unknown rather than being drawn for appearance.</p></div><StatusPill status="observed">{graph.nodes.length} nodes · {graph.edges.length} edges</StatusPill></div><dl className="os-key-values"><div><dt>Mission</dt><dd><code>{graph.missionId}</code></dd></div><div><dt>Run scope</dt><dd>{graph.runId ? <code>{graph.runId}</code> : "Mission-wide"}</dd></div></dl>
      <div className="os-topology-view-toggle" role="group" aria-label="Topology view">
        <Button
          type="button"
          variant={viewState.view === "graph" ? "secondary" : "quiet"}
          aria-label="Graph"
          aria-pressed={viewState.view === "graph"}
          data-control-id={`${controlNamespace}-view-graph`}
          onClick={() => updateView({ view: "graph" })}
        >Graph</Button>
        <Button
          type="button"
          variant={viewState.view === "list" ? "secondary" : "quiet"}
          aria-label="List"
          aria-pressed={viewState.view === "list"}
          data-control-id={`${controlNamespace}-view-list`}
          onClick={() => updateView({ view: "list" })}
        >List</Button>
      </div>
      <div className="os-topology-controls">
        <label><span>Search topology</span><input
          type="search"
          aria-label="Search topology"
          data-control-id={`${controlNamespace}-search`}
          value={viewState.search}
          onChange={(event) => updateView({ search: event.target.value })}
          placeholder="Asset, service, identity, state…"
        /></label>
        <label><span>Node type</span><TitaniumSelect
          aria-label="Node type"
          data-control-id={`${controlNamespace}-node-type`}
          value={viewState.nodeType}
          onChange={(event) => updateView({ nodeType: event.target.value })}
        ><option value="">All node types</option>{nodeTypes.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</TitaniumSelect></label>
        <label><span>Lifecycle</span><TitaniumSelect
          aria-label="Lifecycle"
          data-control-id={`${controlNamespace}-lifecycle`}
          value={viewState.lifecycleState}
          onChange={(event) => updateView({ lifecycleState: event.target.value })}
        ><option value="">All lifecycle states</option>{lifecycleStates.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</TitaniumSelect></label>
        <label><span>Scope</span><TitaniumSelect
          aria-label="Scope"
          data-control-id={`${controlNamespace}-scope`}
          value={viewState.scopeStatus}
          onChange={(event) => updateView({ scopeStatus: event.target.value })}
        ><option value="">All scope states</option>{scopeStatuses.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</TitaniumSelect></label>
        <label><span>Verification</span><TitaniumSelect
          aria-label="Verification"
          data-control-id={`${controlNamespace}-verification`}
          value={viewState.verificationState}
          onChange={(event) => updateView({ verificationState: event.target.value })}
        ><option value="">All verification states</option>{verificationStates.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</TitaniumSelect></label>
      </div>
      <p className="os-topology-result-summary" role="status" aria-label="Topology result summary">
        {model.nodes.length} displayed {model.nodes.length === 1 ? "node" : "nodes"} · {model.edges.length} canonical {model.edges.length === 1 ? "relationship" : "relationships"} · {model.unconnectedNodeIds.length} unconnected {model.unconnectedNodeIds.length === 1 ? "node" : "nodes"}
      </p>
      {model.ignoredEdges.length > 0 && <p className="os-state-remediation" role="alert">
        {model.ignoredEdges.length} malformed {model.ignoredEdges.length === 1 ? "relationship was" : "relationships were"} excluded because a canonical endpoint is missing.
      </p>}
      {viewState.view === "graph"
        ? <TopologyGraphViewport
            model={model}
            selectedNodeId={selectedNodeId ?? selectedNode?.id}
            onSelectNode={onSelectNode}
            controlNamespace={controlNamespace}
          />
        : <TopologyList
            graph={{ ...graph, nodes: model.nodes, edges: model.edges }}
            nodes={model.nodes}
            selectedNodeId={selectedNodeId ?? selectedNode?.id}
            onSelectNode={onSelectNode}
            controlNamespace={controlNamespace}
          />}
    </Card>
    <section aria-labelledby="digital-twin-list"><h2 id="digital-twin-list">Canonical topology record list</h2><ul aria-label="Recon digital twin nodes">{model.nodes.map((node) => <TopologyNodeItem
      key={node.id}
      node={node}
      graph={graph}
      outgoing={outgoingByNode.get(node.id) ?? []}
      incoming={incomingByNode.get(node.id) ?? []}
    />)}</ul></section>
    {selectedNode && <SelectedNodeInspector node={selectedNode} />}
    {osiStack && <OsiStack stack={osiStack} />}
  </div>;
}

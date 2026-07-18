import { useMemo, useState, type FormEvent } from "react";
import { fetchMemoryGraph } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, ButtonLink, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import {
  MEMORY_EDGE_TYPES,
  MEMORY_LIFECYCLE_STATES,
  MEMORY_NODE_TYPES,
  MEMORY_SENSITIVITIES,
  type MemoryGraphView,
  type MemoryScope,
} from "../../domain/types/brain";
import { useUrlFilters } from "../runs/OperationalSurface";
import { BrainEmpty, BrainNav, scopeLabel } from "./BrainNav";
import {
  BRAIN_GRAPH_URL_KEYS,
  brainGraphStateToQuery,
  brainGraphStateToUrl,
  parsePinnedGraphPositions,
  parseBrainGraphState,
  parseSavedBrainGraphViews,
  persistPinnedGraphPositions as persistPinnedGraphPositionsToStorage,
  type BrainGraphPreset,
  type SavedBrainGraphView,
} from "./brainGraphState";
import { MemoryGraphCanvas } from "./MemoryGraphCanvas";
import { MemoryNodeInspector } from "./MemoryNodeInspector";
import { GRAPH_CLUSTERS, nodeCluster, type GraphCluster } from "./graphUtils";
import { BROWSER_STORAGE_KEYS } from "../../lib/browserNamespaces";

const SAVED_VIEWS_KEY = BROWSER_STORAGE_KEYS.brainSavedViews;
const PINNED_POSITIONS_KEY = BROWSER_STORAGE_KEYS.brainPinnedPositions;

function label(value: string): string {
  return value.replaceAll("_", " ").replace(/^./u, (first) => first.toUpperCase());
}

function availableLocalStorage(): Storage | null {
  try {
    return globalThis.localStorage;
  } catch {
    return null;
  }
}

function storedValue(key: string): string | null {
  try {
    return availableLocalStorage()?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

export default function BrainGraphPage() {
  const url = useUrlFilters();
  const state = useMemo(() => parseBrainGraphState(url.values), [url.key]);
  const [savedViews, setSavedViews] = useState<SavedBrainGraphView[]>(() => parseSavedBrainGraphViews(storedValue(SAVED_VIEWS_KEY)));
  const [pinnedPositions, setPinnedPositions] = useState(() => parsePinnedGraphPositions(storedValue(PINNED_POSITIONS_KEY)));
  const [viewName, setViewName] = useState("");
  const [notice, setNotice] = useState("");

  const request = useMemo(() => brainGraphStateToQuery(state), [state]);
  const graph = useQuery(`brain-graph:${JSON.stringify(request)}`, (signal) => fetchMemoryGraph(request, signal), { staleTime: 15_000 });
  const filtered = useMemo(() => {
    if (!graph.data) return { nodes: [], edges: [] };
    const search = state.search.trim().toLocaleLowerCase();
    const nodes = graph.data.nodes.filter((node) => !search || `${node.title} ${node.summary} ${node.id}`.toLocaleLowerCase().includes(search));
    const ids = new Set(nodes.map((node) => node.id));
    return { nodes, edges: graph.data.edges.filter((edge) => ids.has(edge.sourceNodeId) && ids.has(edge.targetNodeId)) };
  }, [graph.data, state.search]);
  const hasActiveFilter = Boolean(state.search || state.nodeType || state.edgeType || state.scope || state.engagementId || state.lifecycle || state.sensitivity || state.minConfidence || state.updatedAfter || state.updatedBefore || state.preset);
  const clusterCounts = useMemo(() => {
    const counts = new Map<GraphCluster, number>();
    filtered.nodes.forEach((node) => {
      const cluster = nodeCluster(node);
      counts.set(cluster, (counts.get(cluster) ?? 0) + 1);
    });
    return counts;
  }, [filtered.nodes]);

  const patchUrl = (patch: Record<string, string | undefined>) => url.set(patch, { replace: true, resetCursor: false });
  const selectView = (view: MemoryGraphView) => {
    if (view === "global") {
      patchUrl({ view: undefined, root: undefined, preset: undefined });
      return;
    }
    patchUrl({ view, preset: undefined });
  };
  const selectPreset = (preset: BrainGraphPreset) => {
    patchUrl({ view: undefined, preset, root: undefined, mission: undefined, selected: undefined, nodeType: undefined, edgeType: undefined });
  };
  const useAsRoot = (nodeId: string) => {
    patchUrl({ view: "local", root: nodeId, selected: nodeId, preset: undefined });
  };
  const setPathStart = (nodeId?: string) => {
    patchUrl({ pathFrom: nodeId });
    setNotice(nodeId
      ? "Path start selected. Choose another visible memory to highlight the shortest explanatory path."
      : "Memory path selection cleared.");
  };
  const toggleCluster = (cluster: GraphCluster, expand = false) => {
    const next = new Set(state.collapsedClusters);
    if (expand || next.has(cluster)) next.delete(cluster);
    else next.add(cluster);
    const selected = filtered.nodes.find((node) => node.id === state.selectedId);
    patchUrl({
      collapsed: next.size > 0 ? [...next].join(",") : undefined,
      ...(selected && next.has(nodeCluster(selected)) ? { selected: undefined } : {}),
    });
  };
  const clearFilters = () => {
    patchUrl(Object.fromEntries(BRAIN_GRAPH_URL_KEYS.map((key) => [key, undefined])));
  };
  const persistViews = (next: SavedBrainGraphView[]) => {
    setSavedViews(next);
    try {
      availableLocalStorage()?.setItem(SAVED_VIEWS_KEY, JSON.stringify(next));
    } catch {
      setNotice("The view remains available for this session, but browser storage is unavailable.");
    }
  };
  const persistPinnedPositions = (next: typeof pinnedPositions) => {
    const result = persistPinnedGraphPositionsToStorage(
      availableLocalStorage(),
      PINNED_POSITIONS_KEY,
      next,
    );
    setPinnedPositions(result.positions);
    if (!result.persisted) {
      setNotice("The graph position is retained for this session, but browser storage is unavailable.");
    }
    return result.persisted;
  };
  const pinPosition = (nodeId: string, point: { x: number; y: number }) => {
    persistPinnedPositions({ ...pinnedPositions, [nodeId]: { ...point, updatedAt: new Date().toISOString() } });
  };
  const clearPinnedPositions = (nodeIds: readonly string[]) => {
    const next = { ...pinnedPositions };
    nodeIds.forEach((nodeId) => { delete next[nodeId]; });
    if (persistPinnedPositions(next)) {
      setNotice(`Reset ${nodeIds.length} visible node position${nodeIds.length === 1 ? "" : "s"}.`);
    }
  };
  const saveNamedView = (event: FormEvent) => {
    event.preventDefault();
    const name = viewName.trim().slice(0, 80);
    if (!name) return;
    const now = new Date().toISOString();
    const existing = savedViews.find((item) => item.name.toLocaleLowerCase() === name.toLocaleLowerCase());
    const saved: SavedBrainGraphView = {
      id: existing?.id ?? globalThis.crypto?.randomUUID?.() ?? `graph-view-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      name,
      state,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    persistViews([saved, ...savedViews.filter((item) => item.id !== saved.id)].slice(0, 24));
    setViewName("");
    setNotice(`Saved “${name}” in this browser.`);
  };
  const applySavedView = (saved: SavedBrainGraphView) => {
    const cleared = Object.fromEntries(BRAIN_GRAPH_URL_KEYS.map((key) => [key, undefined])) as Record<string, string | undefined>;
    patchUrl({ ...cleared, ...brainGraphStateToUrl(saved.state) });
    setNotice(`Applied “${saved.name}”. The address now contains the shareable view.`);
  };
  const removeSavedView = (id: string) => {
    const removed = savedViews.find((item) => item.id === id);
    persistViews(savedViews.filter((item) => item.id !== id));
    setNotice(removed ? `Removed “${removed.name}” from this browser.` : "Saved view removed.");
  };
  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setNotice("Shareable graph link copied. It contains filters and view state, not memory content.");
    } catch {
      setNotice("Clipboard access was denied. Copy the current address from the browser bar.");
    }
  };

  return (
    <div className="os-page brain-page brain-graph-page">
      <PageHeader eyebrow="Connected operational knowledge" title="Memory Graph" description="Explore real relationships and bounded neighborhoods. Filters live in the URL; memory content remains behind the canonical access boundary." actions={<><Button variant="secondary" onClick={copyLink}>Copy shareable link</Button><ButtonLink href="/brain/inbox">Review candidates</ButtonLink></>} />
      <BrainNav />

      <section className="brain-graph-toolbar" aria-label="Memory graph controls">
        <div className="brain-view-switch" role="group" aria-label="Graph view">
          {(["global", "local", "mission", "operator"] as const).map((item) => <button key={item} type="button" className={!state.preset && state.view === item ? "is-active" : ""} onClick={() => selectView(item)} disabled={item === "local" && !state.rootNodeId}>{item === "operator" ? "Operator profile" : label(item)}</button>)}
          <button type="button" className={state.preset === "attack_path" ? "is-active" : ""} onClick={() => selectPreset("attack_path")}>Attack path</button>
          <button type="button" className={state.preset === "lessons_failures" ? "is-active" : ""} onClick={() => selectPreset("lessons_failures")}>Lessons &amp; failures</button>
        </div>
        {state.view === "mission" && <label>Mission ID<input value={state.missionId} onChange={(event) => patchUrl({ mission: event.target.value || undefined })} placeholder="Mission stable ID" /></label>}
        <label className="brain-graph-search">Search visible graph<input value={state.search} onChange={(event) => patchUrl({ search: event.target.value || undefined })} placeholder="Title, summary, ID" /></label>
        <label>Edge type<select value={state.edgeType} onChange={(event) => patchUrl({ edgeType: event.target.value || undefined })}><option value="">All relationships</option>{MEMORY_EDGE_TYPES.map((item) => <option key={item} value={item}>{label(item)}</option>)}</select></label>
        <div className="brain-graph-toggles"><Button variant="quiet" onClick={() => patchUrl({ layout: state.compact ? undefined : "compact" })}>Layout: {state.compact ? "compact" : "clusters"}</Button><Button variant="quiet" aria-pressed={state.physics} onClick={() => patchUrl({ physics: state.physics ? undefined : "1" })}>Physics: {state.physics ? "relationship weighted" : "fixed clusters"}</Button><Button variant="quiet" onClick={() => patchUrl({ table: state.table ? undefined : "1" })}>{state.table ? "Canvas view" : "Accessible table"}</Button></div>
      </section>

      <details className="brain-graph-advanced">
        <summary>Filters, labels, and time range</summary>
        <div>
          <label>Node type<select value={state.nodeType} onChange={(event) => patchUrl({ nodeType: event.target.value || undefined })}><option value="">All node types</option>{MEMORY_NODE_TYPES.map((item) => <option key={item} value={item}>{label(item)}</option>)}</select></label>
          <label>Scope<select value={state.scope} onChange={(event) => patchUrl({ scope: event.target.value || undefined })}><option value="">All permitted scopes</option>{(["global", "engagement", "mission"] as MemoryScope["kind"][]).map((item) => <option key={item} value={item}>{label(item)}</option>)}</select></label>
          <label>Engagement ID<input value={state.engagementId} onChange={(event) => patchUrl({ engagement: event.target.value || undefined })} placeholder="Exact isolated scope" /></label>
          <label>Lifecycle<select value={state.lifecycle} onChange={(event) => patchUrl({ lifecycle: event.target.value || undefined })}><option value="">Active states</option>{MEMORY_LIFECYCLE_STATES.filter((item) => item !== "forgotten").map((item) => <option key={item} value={item}>{label(item)}</option>)}</select></label>
          <label>Sensitivity<select value={state.sensitivity} onChange={(event) => patchUrl({ sensitivity: event.target.value || undefined })}><option value="">All permitted</option>{MEMORY_SENSITIVITIES.map((item) => <option key={item} value={item}>{label(item)}</option>)}</select></label>
          <label>Minimum confidence<select value={state.minConfidence || ""} onChange={(event) => patchUrl({ confidence: event.target.value || undefined })}><option value="">Any confidence</option><option value="0.25">25%</option><option value="0.5">50%</option><option value="0.75">75%</option><option value="0.9">90%</option></select></label>
          <label>Updated from<input type="date" value={state.updatedAfter} max={state.updatedBefore || undefined} onChange={(event) => patchUrl({ from: event.target.value || undefined })} /></label>
          <label>Updated through<input type="date" value={state.updatedBefore} min={state.updatedAfter || undefined} onChange={(event) => patchUrl({ to: event.target.value || undefined })} /></label>
          <label>Label density<select value={state.labelDensity} onChange={(event) => patchUrl({ labels: event.target.value === "balanced" ? undefined : event.target.value })}><option value="minimal">Minimal</option><option value="balanced">Balanced</option><option value="all">All labels</option></select></label>
          <fieldset className="brain-cluster-controls"><legend>Canvas clusters</legend>{GRAPH_CLUSTERS.filter((cluster) => (clusterCounts.get(cluster) ?? 0) > 0).map((cluster) => <Button key={cluster} variant="quiet" aria-pressed={state.collapsedClusters.includes(cluster)} onClick={() => toggleCluster(cluster)}>{state.collapsedClusters.includes(cluster) ? "Expand" : "Collapse"} {label(cluster)} ({clusterCounts.get(cluster)})</Button>)}</fieldset>
          <Button variant="quiet" aria-label="Reset graph view" onClick={clearFilters}>Reset graph view</Button>
        </div>
      </details>

      <section className="brain-saved-views" aria-labelledby="brain-saved-views-title">
        <div><strong id="brain-saved-views-title">Named views</strong><span>Operator-owned display settings stored only in this browser.</span></div>
        <form onSubmit={saveNamedView}><label><span className="os-visually-hidden">View name</span><input value={viewName} maxLength={80} onChange={(event) => setViewName(event.target.value)} placeholder="Name this view" /></label><Button type="submit" variant="secondary" disabled={!viewName.trim()}>Save current</Button></form>
        {savedViews.length > 0 && <ul>{savedViews.map((saved) => <li key={saved.id}><button type="button" onClick={() => applySavedView(saved)}>{saved.name}</button><button type="button" aria-label={`Delete saved view ${saved.name}`} onClick={() => removeSavedView(saved.id)}>×</button></li>)}</ul>}
      </section>
      {notice && <p className="brain-graph-notice" role="status" aria-live="polite">{notice}</p>}

      {state.view === "local" && state.rootNodeId && <p className="brain-active-filter"><span>Local neighborhood</span><code>{state.rootNodeId}</code><button onClick={() => patchUrl({ root: undefined, view: undefined, selected: undefined })}>Clear</button></p>}
      {state.pathFromId && <p className="brain-active-filter"><span>Shortest path from</span><code>{state.pathFromId}</code><span>to</span><code>{state.selectedId || "select another memory"}</code><button onClick={() => setPathStart(undefined)}>Clear</button></p>}
      {state.view === "mission" && !state.missionId && <p className="brain-guidance" role="status">Enter a mission ID to load its isolated cluster. The global graph remains visible until then.</p>}
      {graph.isLoading && <LoadingPanel label="Loading a bounded memory neighborhood" />}
      {graph.error && !graph.data && <ErrorPanel error={graph.error} onRetry={graph.refresh} />}
      {graph.data && graph.data.nodes.length === 0 && <BrainEmpty title={hasActiveFilter ? "No memories match this graph view" : "The Second Brain is empty"} description={hasActiveFilter ? "No accessible canonical memory nodes match these filters. Reset the view or review a memory candidate." : "No canonical memory nodes are available for this view. Confirm a candidate or complete an evidence-backed mission to build the graph."} action={hasActiveFilter ? <Button variant="secondary" onClick={clearFilters}>Reset graph view</Button> : <ButtonLink href="/brain/inbox" variant="secondary">Open Memory Inbox</ButtonLink>} />}
      {graph.data && graph.data.nodes.length > 0 && (
        <>
          <div className="brain-graph-meta"><span>{filtered.nodes.length} visible of {graph.data.nodes.length} loaded · {new Intl.NumberFormat().format(graph.data.availableNodeCount)} accessible in this view</span><span>{filtered.edges.length} visible relationships</span><span>{filtered.nodes.filter((node) => pinnedPositions[node.id]).length} positioned nodes</span><span>{state.labelDensity} labels</span><StatusPill status={graph.data.truncated ? "bounded" : "complete"}>{graph.data.truncated ? "Bounded view" : "Complete view"}</StatusPill></div>
          {filtered.nodes.length > 1 && filtered.edges.length === 0 && <p className="brain-guidance" role="status">These memories are currently isolated: no evidence-backed relationships are recorded for this view. Ti-Scale will keep them separate until an import, mission event, or operator-reviewed link provides real provenance.</p>}
          {state.table ? (
            <div className="os-card os-table-card brain-graph-table"><div className="os-table-scroll"><table><caption className="os-visually-hidden">Accessible memory graph node list</caption><thead><tr><th>Memory</th><th>Type</th><th>State</th><th>Scope</th><th>Confidence</th><th>Updated</th><th>Connections</th><th>Action</th></tr></thead><tbody>{filtered.nodes.map((node) => <tr key={node.id}><th scope="row">{node.title}<small className="brain-table-summary">{node.summary}</small></th><td>{label(node.nodeType)}</td><td><StatusPill status={node.lifecycleStatus} /></td><td>{scopeLabel(node.scope)}</td><td>{Math.round(node.confidence * 100)}%</td><td><time dateTime={node.updatedAt}>{new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(node.updatedAt))}</time></td><td>{node.edgeCount}</td><td><Button variant="quiet" onClick={() => patchUrl({ selected: node.id })}>Inspect</Button></td></tr>)}</tbody></table></div></div>
          ) : (
            <div className="brain-graph-workspace"><MemoryGraphCanvas nodes={filtered.nodes} edges={filtered.edges} selectedId={state.selectedId || undefined} rootNodeId={(graph.data.rootNodeId ?? state.rootNodeId) || undefined} pathStartNodeId={state.pathFromId || undefined} onSelect={(nodeId) => patchUrl({ selected: nodeId })} compact={state.compact} physics={state.physics} labelDensity={state.labelDensity} collapsedClusters={state.collapsedClusters} pinnedPositions={pinnedPositions} onPinPosition={pinPosition} onClearPinnedPositions={clearPinnedPositions} onExpandCluster={(cluster) => toggleCluster(cluster, true)} /><MemoryNodeInspector nodeId={state.selectedId || undefined} onUseAsRoot={useAsRoot} pathStartId={state.pathFromId || undefined} onSetPathStart={setPathStart} /></div>
          )}
          {state.table && <MemoryNodeInspector nodeId={state.selectedId || undefined} onUseAsRoot={useAsRoot} pathStartId={state.pathFromId || undefined} onSetPathStart={setPathStart} />}
          {graph.data.truncated && <div className="brain-load-more"><p>The service bounded this neighborhood to protect rendering and retrieval latency.</p><Button variant="secondary" onClick={() => patchUrl({ limit: String(Math.min(1000, state.limit + 250)) })} disabled={state.limit >= 1000}>Load another bounded segment</Button></div>}
        </>
      )}
    </div>
  );
}

import { useEffect, useMemo, useState, type FormEvent } from "react";
import { fetchMemoryGraph } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, ButtonLink, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
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
import {
  MemoryOutcomeTags,
  memoryMatchesOutcomeFilter,
} from "./MemoryOutcomeTags";
import {
  HistoricalReportedOutcomeBadge,
  memoryMatchesHistoricalReportedOutcome,
} from "./HistoricalReportedOutcomeBadge";
import { collapseGraphClusters, GRAPH_CLUSTER_LABELS, GRAPH_CLUSTERS, nodeCluster, type GraphCluster } from "./graphUtils";
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
  const [advancedOpen, setAdvancedOpen] = useState(state.collapsedClusters.length > 0);

  const request = useMemo(() => brainGraphStateToQuery(state), [state]);
  const graph = useQuery(`brain-graph:${JSON.stringify(request)}`, (signal) => fetchMemoryGraph(request, signal), { staleTime: 15_000 });
  const filtered = useMemo(() => {
    if (!graph.data) return {
      nodes: [],
      edges: [],
      outcomeCounts: { success: 0, failed: 0, unclassified: 0 },
      reportedOutcomeCounts: { reported_success: 0, reported_failure: 0, mixed: 0, unknown: 0, not_reported: 0 },
    };
    const search = state.search.trim().toLocaleLowerCase();
    const searchMatched = graph.data.nodes.filter((node) => !search || `${node.title} ${node.summary} ${node.id}`.toLocaleLowerCase().includes(search));
    const outcomeCounts = searchMatched.reduce((counts, node) => {
      const tags = node.outcomeTags ?? [];
      if (tags.length === 0) counts.unclassified += 1;
      if (tags.includes("success")) counts.success += 1;
      if (tags.includes("failed")) counts.failed += 1;
      return counts;
    }, { success: 0, failed: 0, unclassified: 0 });
    const reportedOutcomeCounts = searchMatched.reduce((counts, node) => {
      counts[node.reportedOutcome?.classification ?? "not_reported"] += 1;
      return counts;
    }, { reported_success: 0, reported_failure: 0, mixed: 0, unknown: 0, not_reported: 0 });
    const nodes = searchMatched.filter((node) => (
      memoryMatchesOutcomeFilter(node.outcomeTags, state.outcomeFilter)
      && memoryMatchesHistoricalReportedOutcome(node.reportedOutcome, state.reportedOutcomeFilter)
    ));
    const ids = new Set(nodes.map((node) => node.id));
    return {
      nodes,
      edges: graph.data.edges.filter((edge) => ids.has(edge.sourceNodeId) && ids.has(edge.targetNodeId)),
      outcomeCounts,
      reportedOutcomeCounts,
    };
  }, [graph.data, state.outcomeFilter, state.reportedOutcomeFilter, state.search]);
  const canvasProjection = useMemo(() => collapseGraphClusters(
    filtered.nodes,
    filtered.edges,
    new Set(state.collapsedClusters),
  ), [filtered.edges, filtered.nodes, state.collapsedClusters]);
  const hasActiveFilter = Boolean(state.search || state.nodeType || state.edgeType || state.scope || state.engagementId || state.lifecycle || state.sensitivity || state.outcomeFilter || state.reportedOutcomeFilter || state.minConfidence || state.updatedAfter || state.updatedBefore || state.preset);
  const isReusableKnowledgeView = state.view === "global"
    && !state.includeSourceProvenance
    && !state.engagementId
    && !state.preset
    && (!state.scope || state.scope === "global");
  const clusterCounts = useMemo(() => {
    const counts = new Map<GraphCluster, number>();
    filtered.nodes.forEach((node) => {
      const cluster = nodeCluster(node);
      counts.set(cluster, (counts.get(cluster) ?? 0) + 1);
    });
    return counts;
  }, [filtered.nodes]);

  useEffect(() => {
    if (state.collapsedClusters.length > 0) setAdvancedOpen(true);
  }, [state.collapsedClusters.length]);

  const patchUrl = (patch: Record<string, string | undefined>) => url.set(patch, { replace: true, resetCursor: false });
  const selectView = (view: MemoryGraphView) => {
    if (view === "global") {
      patchUrl({ view: undefined, root: undefined, preset: undefined, provenance: undefined });
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
      <PageHeader eyebrow="Reusable attack intelligence" title="Memory Graph" description="Match technology and version fingerprints to attack vectors, scripts, discoveries, outcomes, failures, and recovery paths. Mission and target identifiers remain provenance—not reusable knowledge." actions={<><Button variant="secondary" onClick={copyLink}>Copy shareable link</Button><ButtonLink href="/brain/inbox">Review candidates</ButtonLink></>} />
      <BrainNav />

      <section className="brain-graph-toolbar" aria-label="Memory graph controls">
        <div className="brain-view-switch" role="group" aria-label="Graph view">
          {(["global", "local", "mission", "operator"] as const).map((item) => <button key={item} type="button" className={!state.preset && state.view === item && !(item === "global" && state.includeSourceProvenance) ? "is-active" : ""} onClick={() => selectView(item)} disabled={item === "local" && !state.rootNodeId}>{item === "operator" ? "Operator Preferences / Profile" : label(item)}</button>)}
          <button type="button" className={state.preset === "attack_path" ? "is-active" : ""} onClick={() => selectPreset("attack_path")}>Attack path</button>
          <button type="button" className={state.preset === "lessons_failures" ? "is-active" : ""} onClick={() => selectPreset("lessons_failures")}>Lessons &amp; failures</button>
        </div>
        {state.view === "mission" && <label>Mission ID<input value={state.missionId} onChange={(event) => patchUrl({ mission: event.target.value || undefined })} placeholder="Mission stable ID" /></label>}
        <label className="brain-graph-search">Search visible graph<input value={state.search} onChange={(event) => patchUrl({ search: event.target.value || undefined })} placeholder="Title, summary, ID" /></label>
        <label>Edge type<TitaniumSelect value={state.edgeType} onChange={(event) => patchUrl({ edgeType: event.target.value || undefined })}><option value="">All relationships</option>{MEMORY_EDGE_TYPES.map((item) => <option key={item} value={item}>{label(item)}</option>)}</TitaniumSelect></label>
        <label>Verified outcome<TitaniumSelect value={state.outcomeFilter} onChange={(event) => patchUrl({ outcome: event.target.value || undefined })}><option value="">All verified outcomes</option><option value="success">Verified success</option><option value="failed">Verified failure</option><option value="unclassified">No verified outcome</option></TitaniumSelect></label>
        <label>Historical report<TitaniumSelect value={state.reportedOutcomeFilter} onChange={(event) => patchUrl({ reported: event.target.value || undefined })}><option value="">All historical reports</option><option value="reported_success">Reported success</option><option value="reported_failure">Reported failure</option><option value="mixed">Mixed reports</option><option value="unknown">No outcome stated</option><option value="not_reported">Not reported</option></TitaniumSelect></label>
        <div className="brain-graph-toggles"><Button variant="quiet" onClick={() => patchUrl({ layout: state.compact ? undefined : "compact" })}>Layout: {state.compact ? "compact" : "clusters"}</Button><Button variant="quiet" aria-pressed={state.physics} onClick={() => patchUrl({ physics: state.physics ? undefined : "1" })}>Physics: {state.physics ? "relationship weighted" : "fixed clusters"}</Button><Button variant="quiet" onClick={() => patchUrl({ table: state.table ? undefined : "1" })}>{state.table ? "Canvas view" : "Accessible table"}</Button></div>
      </section>

      <details className="brain-graph-advanced" open={advancedOpen} onToggle={(event) => setAdvancedOpen(event.currentTarget.open)}>
        <summary>Filters, labels, and time range{state.collapsedClusters.length > 0 ? ` · ${state.collapsedClusters.length} collapsed cluster${state.collapsedClusters.length === 1 ? "" : "s"}` : ""}</summary>
        <div>
          <label>Node type<TitaniumSelect value={state.nodeType} onChange={(event) => patchUrl({ nodeType: event.target.value || undefined })}><option value="">All node types</option>{MEMORY_NODE_TYPES.map((item) => <option key={item} value={item}>{label(item)}</option>)}</TitaniumSelect></label>
          <label>Scope<TitaniumSelect value={state.includeSourceProvenance ? "all" : state.scope} onChange={(event) => {
            const value = event.target.value;
            patchUrl(value === "all"
              ? { provenance: "1", scope: undefined, engagement: undefined, lifecycle: undefined, view: undefined, root: undefined, mission: undefined, preset: undefined }
              : { provenance: undefined, scope: value || undefined });
          }}><option value="">{isReusableKnowledgeView ? "Default · confirmed + verified global knowledge" : "Current context · all permitted scopes"}</option><option value="all">All permitted scopes · source provenance</option>{(["global", "engagement", "mission"] as MemoryScope["kind"][]).map((item) => <option key={item} value={item}>{label(item)}</option>)}</TitaniumSelect></label>
          <label>Engagement ID<input value={state.engagementId} onChange={(event) => patchUrl({ engagement: event.target.value || undefined })} placeholder="Exact isolated scope" /></label>
          <label>Lifecycle<TitaniumSelect value={state.lifecycle} onChange={(event) => patchUrl({ lifecycle: event.target.value || undefined })}><option value="">{isReusableKnowledgeView ? "Confirmed + verified knowledge" : "Active states"}</option>{MEMORY_LIFECYCLE_STATES.filter((item) => item !== "forgotten").map((item) => <option key={item} value={item}>{label(item)}</option>)}</TitaniumSelect></label>
          <label>Sensitivity<TitaniumSelect value={state.sensitivity} onChange={(event) => patchUrl({ sensitivity: event.target.value || undefined })}><option value="">All permitted</option>{MEMORY_SENSITIVITIES.map((item) => <option key={item} value={item}>{label(item)}</option>)}</TitaniumSelect></label>
          <label>Minimum confidence<TitaniumSelect value={state.minConfidence || ""} onChange={(event) => patchUrl({ confidence: event.target.value || undefined })}><option value="">Any confidence</option><option value="0.25">25%</option><option value="0.5">50%</option><option value="0.75">75%</option><option value="0.9">90%</option></TitaniumSelect></label>
          <label>Updated from<input type="date" value={state.updatedAfter} max={state.updatedBefore || undefined} onChange={(event) => patchUrl({ from: event.target.value || undefined })} /></label>
          <label>Updated through<input type="date" value={state.updatedBefore} min={state.updatedAfter || undefined} onChange={(event) => patchUrl({ to: event.target.value || undefined })} /></label>
          <label>Label density<TitaniumSelect value={state.labelDensity} onChange={(event) => patchUrl({ labels: event.target.value === "balanced" ? undefined : event.target.value })}><option value="minimal">Minimal</option><option value="balanced">Balanced</option><option value="all">All labels</option></TitaniumSelect></label>
          <fieldset className="brain-cluster-controls"><legend>Attack-knowledge anatomy</legend>{GRAPH_CLUSTERS.filter((cluster) => (clusterCounts.get(cluster) ?? 0) > 0).map((cluster) => <Button key={cluster} variant="quiet" aria-pressed={state.collapsedClusters.includes(cluster)} onClick={() => toggleCluster(cluster)}>{state.collapsedClusters.includes(cluster) ? "Expand" : "Collapse"} {GRAPH_CLUSTER_LABELS[cluster]} ({clusterCounts.get(cluster)})</Button>)}</fieldset>
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
      {isReusableKnowledgeView && <p className="brain-guidance" role="status">Showing confirmed and verified reusable global knowledge by default. Open Filters and choose “All permitted scopes · source provenance” to inspect engagement, mission, target, and runtime history.</p>}
      {state.includeSourceProvenance && <p className="brain-guidance" role="status">Source provenance is visible. Engagement, mission, target, and runtime records remain traceability context—not reusable attack knowledge.</p>}
      {graph.isLoading && <LoadingPanel label="Loading a bounded memory neighborhood" />}
      {graph.error && !graph.data && <ErrorPanel error={graph.error} onRetry={graph.refresh} />}
      {graph.data && graph.data.nodes.length === 0 && <BrainEmpty
        title={hasActiveFilter ? "No memories match this graph view" : isReusableKnowledgeView ? "No confirmed or verified reusable knowledge yet" : "The Second Brain is empty"}
        description={hasActiveFilter
          ? "No accessible canonical memory nodes match these filters. Reset the view or review a memory candidate."
          : isReusableKnowledgeView
            ? "No reviewed global attack knowledge matches this view. Review candidates, or choose “All permitted scopes · source provenance” in Filters to inspect retained traceability records without promoting them as reusable knowledge."
            : "No canonical memory nodes are available for this view. Confirm a candidate or complete an evidence-backed mission to build the graph."}
        action={hasActiveFilter ? <Button variant="secondary" onClick={clearFilters}>Reset graph view</Button> : <ButtonLink href="/brain/inbox" variant="secondary">Open Memory Inbox</ButtonLink>}
      />}
      {graph.data && graph.data.nodes.length > 0 && (
        <>
          <div className="brain-graph-meta"><span>{canvasProjection.nodes.length} displayed from {filtered.nodes.length} matching · {graph.data.nodes.length} loaded · {new Intl.NumberFormat().format(graph.data.availableNodeCount)} accessible in this view</span><span>{canvasProjection.edges.length} displayed from {filtered.edges.length} matching relationships</span><span>{filtered.nodes.filter((node) => pinnedPositions[node.id]).length} positioned nodes</span><span>{state.labelDensity} labels</span><StatusPill status={graph.data.truncated ? "bounded" : "complete"}>{graph.data.truncated ? "Bounded view" : "Complete view"}</StatusPill></div>
          <div className="brain-outcome-summary" aria-label="Loaded verified outcome evidence categories">
            <strong>Verified outcomes</strong>
            <MemoryOutcomeTags tags={["success"]} counts={{ success: filtered.outcomeCounts.success }} />
            <MemoryOutcomeTags tags={["failed"]} counts={{ failed: filtered.outcomeCounts.failed }} />
            <MemoryOutcomeTags tags={[]} counts={{ unclassified: filtered.outcomeCounts.unclassified }} />
            <small>These require evidence-linked terminal attempts. Success and Failed may both apply in different exact contexts.</small>
          </div>
          <div className="brain-outcome-summary" aria-label="Loaded historical source report categories">
            <strong>Historical reports</strong>
            <HistoricalReportedOutcomeBadge classification="reported_success" count={filtered.reportedOutcomeCounts.reported_success} />
            <HistoricalReportedOutcomeBadge classification="reported_failure" count={filtered.reportedOutcomeCounts.reported_failure} />
            <HistoricalReportedOutcomeBadge classification="mixed" count={filtered.reportedOutcomeCounts.mixed} />
            <HistoricalReportedOutcomeBadge classification="unknown" count={filtered.reportedOutcomeCounts.unknown} />
            <HistoricalReportedOutcomeBadge classification="not_reported" count={filtered.reportedOutcomeCounts.not_reported} />
            <small>These describe what imported sources reported; they are visible but are not independently verified attack outcomes.</small>
          </div>
          {state.collapsedClusters.length > 0 && <p className="brain-guidance" role="status">The canvas is showing aggregate cluster nodes, not missing memories. Expand the named clusters in the open controls above to restore every loaded canonical node.</p>}
          {filtered.nodes.length > 1 && filtered.edges.length === 0 && <p className="brain-guidance" role="status">These memories are currently isolated: no evidence-backed relationships are recorded for this view. Ti-Scale will keep them separate until an import, mission event, or operator-reviewed link provides real provenance.</p>}
          {state.table ? (
            <div className="os-card os-table-card brain-graph-table"><div className="os-table-scroll"><table><caption className="os-visually-hidden">Accessible memory graph node list</caption><thead><tr><th>Memory</th><th>Type</th><th>Verified outcome</th><th>Historical report</th><th>State</th><th>Scope</th><th>Confidence</th><th>Updated</th><th>Connections</th><th>Action</th></tr></thead><tbody>{filtered.nodes.map((node) => <tr key={node.id}><th scope="row">{node.title}<small className="brain-table-summary">{node.summary}</small></th><td>{label(node.nodeType)}</td><td><MemoryOutcomeTags tags={node.outcomeTags} /></td><td><HistoricalReportedOutcomeBadge outcome={node.reportedOutcome} /></td><td><StatusPill status={node.lifecycleStatus} /></td><td>{scopeLabel(node.scope)}</td><td>{Math.round(node.confidence * 100)}%</td><td><time dateTime={node.updatedAt}>{new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(node.updatedAt))}</time></td><td>{node.edgeCount}</td><td><Button variant="quiet" onClick={() => patchUrl({ selected: node.id })}>Inspect</Button></td></tr>)}</tbody></table></div></div>
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

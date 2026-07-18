import { useEffect, useMemo, useState } from "react";
import { fetchBrainSummary, fetchMemoryNodes } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, ButtonLink, Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import type { MemoryLifecycle, MemoryNodeType, MemorySensitivity } from "../../domain/types/brain";
import { MEMORY_LIFECYCLE_STATES, MEMORY_NODE_TYPES, MEMORY_SENSITIVITIES } from "../../domain/types/brain";
import { CursorControls, useUrlFilters } from "../runs/OperationalSurface";
import { BrainEmpty, BrainNav, formatBrainDate, scopeLabel } from "./BrainNav";

function keyFor(filters: Record<string, unknown>): string {
  return `brain-node-search:${JSON.stringify(filters)}`;
}

export default function BrainHomePage() {
  const summary = useQuery("brain-summary", fetchBrainSummary, { staleTime: 10_000 });
  const urlFilters = useUrlFilters();
  const [query, setQuery] = useState(urlFilters.values.query ?? "");
  useEffect(() => setQuery(urlFilters.values.query ?? ""), [urlFilters.values.query]);
  const nodeType = MEMORY_NODE_TYPES.includes(urlFilters.values.nodeType as MemoryNodeType)
    ? urlFilters.values.nodeType as MemoryNodeType
    : "";
  const status = MEMORY_LIFECYCLE_STATES.includes(urlFilters.values.status as MemoryLifecycle)
    && urlFilters.values.status !== "forgotten"
    ? urlFilters.values.status as MemoryLifecycle
    : "";
  const sensitivity = MEMORY_SENSITIVITIES.includes(urlFilters.values.sensitivity as MemorySensitivity)
    ? urlFilters.values.sensitivity as MemorySensitivity
    : "";
  const filters = useMemo(() => ({
    query: urlFilters.values.query || undefined,
    nodeType: nodeType || undefined,
    status: status || undefined,
    sensitivity: sensitivity || undefined,
    cursor: urlFilters.values.cursor || undefined,
    limit: 50,
  }), [urlFilters.values.query, urlFilters.values.cursor, nodeType, status, sensitivity]);
  const nodes = useQuery(keyFor(filters), (signal) => fetchMemoryNodes(filters, signal), { staleTime: 10_000 });

  return (
    <div className="os-page brain-page">
      <PageHeader eyebrow="User-owned operational memory" title="Second Brain" description="Inspectable memory with provenance, explicit lifecycle, scope isolation, and operator-controlled retention." actions={<ButtonLink href="/brain/graph">Open graph</ButtonLink>} />
      <BrainNav />
      {summary.isLoading && <LoadingPanel label="Loading canonical memory health" />}
      {summary.error && !summary.data && <ErrorPanel error={summary.error} onRetry={summary.refresh} />}
      {summary.data && (
        <>
          <section className="brain-pulse" aria-label="Memory health">
            <div><span>Confirmed</span><strong>{summary.data.counts.confirmed}</strong></div>
            <div><span>Verified</span><strong>{summary.data.counts.verified}</strong></div>
            <div><span>Candidates</span><strong>{summary.data.counts.candidates}</strong></div>
            <div><span>Stale</span><strong>{summary.data.counts.stale}</strong></div>
            <div><span>Disputed</span><strong>{summary.data.counts.disputed}</strong></div>
            <div><span>Relationships</span><strong>{summary.data.counts.edges}</strong></div>
            <div><span>Context packs</span><strong>{summary.data.counts.contextPacks}</strong></div>
          </section>
          <div className="brain-health-grid">
            <Card>
              <div className="os-section-heading"><div><p className="os-eyebrow">Retrieval</p><h2>Canonical memory health</h2></div></div>
              <ul className="brain-health-list"><li><span>Database</span><StatusPill status={summary.data.health.database} /></li><li><span>Lexical index</span><StatusPill status={summary.data.health.fts} /></li><li><span>Forgotten audit records</span><strong>{summary.data.counts.forgotten}</strong></li></ul>
            </Card>
            <Card>
              <div className="os-section-heading"><div><p className="os-eyebrow">Human-readable projection</p><h2>Obsidian vault</h2></div><ButtonLink href="/brain/vault" variant="quiet">Manage</ButtonLink></div>
              <ul className="brain-health-list"><li><span>Status</span><StatusPill status={summary.data.vault.status} /></li><li><span>Connections</span><strong>{summary.data.vault.connections}</strong></li><li><span>Open conflicts</span><strong>{summary.data.vault.conflicts}</strong></li><li><span>Last synchronized</span><time>{formatBrainDate(summary.data.vault.lastSyncAt)}</time></li></ul>
            </Card>
          </div>
        </>
      )}

      <Card className="brain-browser">
        <div className="os-section-heading"><div><p className="os-eyebrow">Search and review</p><h2>Memory nodes</h2></div><ButtonLink href="/brain/inbox" variant="secondary">Review candidates</ButtonLink></div>
        <form className="brain-search" onSubmit={(event) => { event.preventDefault(); urlFilters.set({ query: query.trim() || undefined }); }} role="search">
          <label>Search title, summary, and note text<input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search operational memory" /></label>
          <label>Node type<select value={nodeType} onChange={(event) => urlFilters.set({ nodeType: event.target.value || undefined })}><option value="">All types</option>{MEMORY_NODE_TYPES.map((type) => <option key={type} value={type}>{type.replaceAll("_", " ")}</option>)}</select></label>
          <label>Lifecycle<select value={status} onChange={(event) => urlFilters.set({ status: event.target.value || undefined })}><option value="">All active states</option>{MEMORY_LIFECYCLE_STATES.filter((item) => item !== "forgotten").map((item) => <option key={item}>{item}</option>)}</select></label>
          <label>Sensitivity<select value={sensitivity} onChange={(event) => urlFilters.set({ sensitivity: event.target.value || undefined })}><option value="">Permitted levels</option>{MEMORY_SENSITIVITIES.map((item) => <option key={item}>{item}</option>)}</select></label>
          <Button type="submit">Search</Button>
        </form>
        {nodes.isLoading && <LoadingPanel label="Searching canonical memory" />}
        {nodes.error && !nodes.data && <ErrorPanel error={nodes.error} onRetry={nodes.refresh} />}
        {nodes.data && nodes.data.items.length === 0 && <BrainEmpty title="No matching memory" description="No canonical nodes match the current query and scope filters. Candidate memories may still be awaiting review." action={<ButtonLink href="/brain/inbox" variant="secondary">Open Memory Inbox</ButtonLink>} />}
        {nodes.data && nodes.data.items.length > 0 && (
          <div className="os-table-scroll"><table><thead><tr><th>Memory</th><th>Type</th><th>State</th><th>Scope</th><th>Confidence</th><th>Sources</th><th>Updated</th></tr></thead><tbody>{nodes.data.items.map((node) => <tr key={node.id}><th scope="row"><ButtonLink href={`/brain/nodes/${encodeURIComponent(node.id)}`} variant="quiet" aria-label={`Open memory ${node.title} (${node.id})`}>{node.title}</ButtonLink><small className="brain-table-summary">{node.summary}</small></th><td>{node.nodeType.replaceAll("_", " ")}</td><td><StatusPill status={node.lifecycleStatus} /></td><td>{scopeLabel(node.scope)}</td><td>{Math.round(node.confidence * 100)}%</td><td>{node.sourceCount}</td><td>{formatBrainDate(node.updatedAt)}</td></tr>)}</tbody></table></div>
        )}
        {nodes.data && <CursorControls
          cursor={urlFilters.values.cursor}
          nextCursor={nodes.data.nextCursor}
          onChange={(cursor) => urlFilters.set({ cursor }, { resetCursor: false, replace: false })}
        />}
      </Card>
    </div>
  );
}

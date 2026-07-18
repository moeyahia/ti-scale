import { useState } from "react";
import { fetchMemoryNode, pinMemoryNode } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, ButtonLink, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { ContextPackPanel } from "./ContextPackPanel";
import { formatBrainDate, scopeLabel } from "./BrainNav";

export function MemoryNodeInspector({ nodeId, onUseAsRoot, pathStartId, onSetPathStart }: { nodeId?: string; onUseAsRoot?: (nodeId: string) => void; pathStartId?: string; onSetPathStart?: (nodeId?: string) => void }) {
  const detail = useQuery(`brain-node:${nodeId ?? "none"}`, (signal) => nodeId ? fetchMemoryNode(nodeId, signal) : Promise.reject(new Error("No memory selected")), { staleTime: 20_000 });
  const [contextPackId, setContextPackId] = useState<string>();
  const [mutation, setMutation] = useState<{ busy: boolean; message?: string; error?: Error }>({ busy: false });
  if (!nodeId) return <aside className="brain-inspector brain-inspector--empty"><p className="os-eyebrow">Node inspector</p><h2>Select a memory</h2><p>Choose a node to inspect its provenance, scope, relationships, version history, and recorded influence.</p></aside>;
  if (detail.isLoading) return <aside className="brain-inspector"><LoadingPanel label="Loading memory provenance" /></aside>;
  if (detail.error && !detail.data) return <aside className="brain-inspector"><ErrorPanel error={detail.error} onRetry={detail.refresh} /></aside>;
  if (!detail.data) return null;
  const { node } = detail.data;
  const togglePin = async () => {
    setMutation({ busy: true });
    try {
      await pinMemoryNode(node.id, node.version, !node.pinned);
      setMutation({ busy: false, message: node.pinned ? "Memory unpinned" : "Memory pinned" });
      detail.refresh();
    } catch (error) { setMutation({ busy: false, error: error instanceof Error ? error : new Error("Unable to update pin") }); }
  };
  return (
    <aside className="brain-inspector" aria-label="Selected memory details">
      <div className="brain-inspector-heading"><div><p className="os-eyebrow">{node.nodeType.replaceAll("_", " ")}</p><h2>{node.title}</h2></div><StatusPill status={node.lifecycleStatus} /></div>
      <p className="brain-inspector-summary">{node.summary}</p>
      <dl className="brain-inspector-facts"><div><dt>Scope</dt><dd>{scopeLabel(node.scope)}</dd></div><div><dt>Sensitivity</dt><dd>{node.sensitivity}</dd></div><div><dt>Confidence</dt><dd>{Math.round(node.confidence * 100)}%</dd></div><div><dt>Version</dt><dd>{node.version}</dd></div><div><dt>Author</dt><dd>{node.authorId ?? node.authorType}</dd></div><div><dt>Updated</dt><dd>{formatBrainDate(node.updatedAt)}</dd></div></dl>
      <section><h3>Why this exists</h3><p>{node.provenance.explanation}</p>{detail.data.sources.length > 0 && <ul className="brain-source-list">{detail.data.sources.map((source) => <li key={`${source.sourceType}:${source.sourceId}`}><strong>{source.sourceType}</strong><span>{source.sourceId}</span>{source.excerptRedacted && <p>{source.excerptRedacted}</p>}</li>)}</ul>}</section>
      {node.body && <section><h3>Note</h3><div className="brain-note-body">{node.body}</div></section>}
      <section><h3>Relationships</h3><p>{detail.data.backlinks.length} backlinks · {detail.data.outgoing.length} outgoing</p></section>
      {detail.data.usage.length > 0 && <section><h3>Where it influenced work</h3><ul className="brain-usage-list">{detail.data.usage.map((usage) => <li key={`${usage.contextPackId}:${usage.createdAt}`}><button onClick={() => setContextPackId(contextPackId === usage.contextPackId ? undefined : usage.contextPackId)}><span>{usage.purpose}</span><StatusPill status={usage.used ? "used" : "ignored"} /></button>{usage.influenceSummary && <p>{usage.influenceSummary}</p>}</li>)}</ul></section>}
      {contextPackId && <ContextPackPanel packId={contextPackId} />}
      {mutation.message && <p className="brain-mutation-note" role="status">{mutation.message}</p>}
      {mutation.error && <p className="brain-mutation-note is-error" role="alert">{mutation.error.message}</p>}
      <div className="brain-inspector-actions"><ButtonLink href={`/brain/nodes/${encodeURIComponent(node.id)}`} variant="secondary">Full memory record</ButtonLink>{onUseAsRoot && <Button variant="secondary" onClick={() => onUseAsRoot(node.id)}>Open local graph</Button>}{onSetPathStart && <Button variant="secondary" onClick={() => onSetPathStart(pathStartId === node.id ? undefined : node.id)}>{pathStartId === node.id ? "Clear path start" : "Set as path start"}</Button>}<Button variant="quiet" disabled={mutation.busy} onClick={togglePin}>{node.pinned ? "Unpin" : "Pin"}</Button></div>
    </aside>
  );
}

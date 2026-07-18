import { useState } from "react";
import { useNavigation } from "../../app/router/navigation";
import { correctMemoryNode, disputeMemoryNode, expireMemoryNode, exportVault, fetchMemoryNode, fetchVaultSnapshot, forgetMemoryNode, pinMemoryNode } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, ButtonLink, Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { useModalFocus } from "../../design-system/hooks/useModalFocus";
import { MEMORY_SENSITIVITIES, type MemorySensitivity } from "../../domain/types/brain";
import { BrainNav, formatBrainDate, scopeLabel } from "./BrainNav";
import { ContextPackPanel } from "./ContextPackPanel";

export default function BrainNodePage({ nodeId }: { nodeId: string }) {
  const navigation = useNavigation();
  const detail = useQuery(`brain-node:${nodeId}`, (signal) => fetchMemoryNode(nodeId, signal), { staleTime: 0 });
  const vault = useQuery("brain-vault:node-export", fetchVaultSnapshot, { staleTime: 30_000 });
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [body, setBody] = useState("");
  const [sensitivity, setSensitivity] = useState<MemorySensitivity>("private");
  const [changeReason, setChangeReason] = useState("");
  const [disputeReason, setDisputeReason] = useState("");
  const [expiry, setExpiry] = useState("");
  const [forgetReason, setForgetReason] = useState("");
  const [forgetConfirmation, setForgetConfirmation] = useState("");
  const [contextPackId, setContextPackId] = useState<string>();
  const [vaultConnectionId, setVaultConnectionId] = useState("");
  const [operation, setOperation] = useState<{ busy?: string; message?: string; error?: Error }>({});
  const closeEditor = () => { if (!operation.busy) setEditing(false); };
  const editorFocus = useModalFocus(editing, closeEditor, Boolean(operation.busy));
  const run = async (name: string, action: () => Promise<unknown>, message: string, after?: () => void) => {
    setOperation({ busy: name });
    try { await action(); setOperation({ message }); detail.refresh(); after?.(); }
    catch (error) { setOperation({ error: error instanceof Error ? error : new Error("Memory update failed") }); }
  };
  const beginEdit = () => {
    if (!detail.data) return;
    setTitle(detail.data.node.title); setSummary(detail.data.node.summary); setBody(detail.data.node.body);
    setSensitivity(detail.data.node.sensitivity); setChangeReason(""); setEditing(true);
  };

  return (
    <div className="os-page brain-page brain-node-page">
      <PageHeader eyebrow="Canonical memory record" title={detail.data?.node.title ?? "Memory node"} description="Provenance, lifecycle, scope, usage, corrections, and relationships remain visible and operator-controlled." actions={<Button variant="secondary" onClick={() => navigation.navigate(`/brain/graph?view=local&root=${encodeURIComponent(nodeId)}&selected=${encodeURIComponent(nodeId)}`)}>Show in graph</Button>} />
      <BrainNav />
      {detail.isLoading && <LoadingPanel label="Loading complete memory record" />}
      {detail.error && !detail.data && <ErrorPanel error={detail.error} onRetry={detail.refresh} />}
      {detail.data && (() => {
        const { node } = detail.data;
        const selectedVaultId = vaultConnectionId || vault.data?.connections[0]?.id || "";
        const nodeVaultState = vault.data?.syncStates.find((item) => (
          item.connectionId === selectedVaultId && item.nodeId === node.id
        ));
        return <>
          <section className="brain-node-banner"><div><span>Type</span><strong>{node.nodeType.replaceAll("_", " ")}</strong></div><div><span>Lifecycle</span><StatusPill status={node.lifecycleStatus} /></div><div><span>Scope</span><strong>{scopeLabel(node.scope)}</strong></div><div><span>Confidence</span><strong>{Math.round(node.confidence * 100)}%</strong></div><div><span>Sensitivity</span><strong>{node.sensitivity}</strong></div><div><span>Version</span><strong>{node.version}</strong></div></section>
          <div className="brain-node-layout">
            <section aria-label="Memory record detail">
              <Card><div className="os-section-heading"><div><p className="os-eyebrow">Inspect</p><h2>Memory note</h2></div><Button variant="secondary" onClick={beginEdit}>Correct memory</Button></div><p className="brain-node-summary">{node.summary}</p><div className="brain-node-body">{node.body || "This memory has no additional note body."}</div></Card>
              <Card><div className="os-section-heading"><div><p className="os-eyebrow">Source of truth</p><h2>Provenance</h2></div></div><p>{node.provenance.explanation}</p><ul className="brain-provenance-list">{detail.data.sources.map((source) => <li key={`${source.sourceType}:${source.sourceId}`}><div><StatusPill status={source.sourceType} /><code>{source.sourceId}</code></div><span>Acquired {formatBrainDate(source.acquiredAt)}</span>{source.excerptRedacted && <blockquote>{source.excerptRedacted}</blockquote>}</li>)}</ul></Card>
              <Card><div className="os-section-heading"><div><p className="os-eyebrow">Connections</p><h2>Backlinks and outgoing relationships</h2></div></div>{detail.data.backlinks.length + detail.data.outgoing.length === 0 ? <p className="os-muted">No canonical relationships are recorded for this node.</p> : <ul className="brain-edge-list">{[...detail.data.backlinks, ...detail.data.outgoing].map((edge) => { const peer = edge.sourceNodeId === node.id ? edge.targetNodeId : edge.sourceNodeId; return <li key={`${edge.id}:${peer}`}><StatusPill status={edge.edgeType} /><div><ButtonLink href={`/brain/nodes/${encodeURIComponent(peer)}`} variant="quiet">{edge.title}</ButtonLink><p>{edge.explanation}</p></div><span>{Math.round(edge.confidence * 100)}%</span></li>; })}</ul>}</Card>
              <Card><div className="os-section-heading"><div><p className="os-eyebrow">Memory transparency</p><h2>Context use history</h2></div></div>{detail.data.usage.length === 0 ? <p className="os-muted">No plan, response, action, or report has recorded using this memory.</p> : <ul className="brain-context-history">{detail.data.usage.map((usage) => <li key={`${usage.contextPackId}:${usage.createdAt}`}><button onClick={() => setContextPackId(contextPackId === usage.contextPackId ? undefined : usage.contextPackId)}><div><strong>{usage.purpose}</strong><span>{formatBrainDate(usage.createdAt)}</span></div><StatusPill status={usage.used ? "used" : "ignored"} /></button><p>{usage.influenceSummary ?? usage.ignoredReason ?? usage.relevanceReason}</p></li>)}</ul>}{contextPackId && <ContextPackPanel packId={contextPackId} />}</Card>
              <Card><div className="os-section-heading"><div><p className="os-eyebrow">Audit</p><h2>Version history</h2></div></div><ol className="brain-version-list">{detail.data.versions.map((version) => <li key={version.version}><span>{version.version}</span><div><strong>{version.title}</strong><p>{version.changeReason ?? version.summary}</p><small>{version.changedBy} · {formatBrainDate(version.changedAt)}</small></div></li>)}</ol></Card>
            </section>
            <aside>
              <Card className="brain-control-card"><div className="os-section-heading"><div><p className="os-eyebrow">Operator controls</p><h2>Lifecycle and retention</h2></div></div><Button variant="secondary" disabled={Boolean(operation.busy)} onClick={() => run("pin", () => pinMemoryNode(node.id, node.version, !node.pinned), node.pinned ? "Memory unpinned." : "Memory pinned.")}>{node.pinned ? "Unpin memory" : "Pin memory"}</Button><label>Expire on<input type="datetime-local" value={expiry} onChange={(event) => setExpiry(event.target.value)} /></label><Button variant="secondary" disabled={!expiry || Boolean(operation.busy)} onClick={() => run("expire", () => expireMemoryNode(node.id, node.version, new Date(expiry).toISOString(), "Operator configured retention expiry"), "Memory expiry updated.")}>Set expiry</Button><label>Dispute reason<textarea value={disputeReason} onChange={(event) => setDisputeReason(event.target.value)} placeholder="Describe the contradiction or uncertainty" /></label><Button variant="secondary" disabled={!disputeReason.trim() || Boolean(operation.busy)} onClick={() => run("dispute", () => disputeMemoryNode(node.id, node.version, disputeReason.trim()), "Memory marked disputed.")}>Mark disputed</Button></Card>
              <Card className="brain-control-card"><div className="os-section-heading"><div><p className="os-eyebrow">Human-readable projection</p><h2>Obsidian note</h2></div></div>{vault.isLoading ? <p className="os-muted">Checking configured vaults…</p> : vault.error && !vault.data ? <ErrorPanel error={vault.error} onRetry={vault.refresh} /> : vault.data?.enabled && vault.data.connections.length > 0 ? <><label>Vault<select value={selectedVaultId} onChange={(event) => setVaultConnectionId(event.target.value)}>{vault.data.connections.map((connection) => <option key={connection.id} value={connection.id}>{connection.displayName}</option>)}</select></label><Button variant="secondary" disabled={!selectedVaultId || Boolean(operation.busy)} onClick={() => run("export-node", () => exportVault(selectedVaultId, node.id), "This memory was exported as a versioned Obsidian note.", vault.refresh)}>Export this memory</Button>{nodeVaultState?.obsidianUrl ? <a className="os-button os-button--quiet" href={nodeVaultState.obsidianUrl} rel="noopener noreferrer">Open this note in Obsidian</a> : <p className="os-muted">Export this memory once to create its stable note and deep link.</p>}</> : <p className="os-muted">Connect an explicitly permitted vault before exporting this memory.</p>}<ButtonLink href="/brain/vault" variant="quiet">Open Obsidian vault controls</ButtonLink></Card>
              <Card className="brain-forget-card"><p className="os-eyebrow">Privacy erasure</p><h2>Forget this memory</h2><p>This removes reusable content, embeddings, derived edges, context references, and synchronized projections. Only a content-free audit event and optional suppression fingerprint remain.</p><label>Reason<textarea value={forgetReason} onChange={(event) => setForgetReason(event.target.value)} /></label><label>Type FORGET<input value={forgetConfirmation} onChange={(event) => setForgetConfirmation(event.target.value)} autoComplete="off" /></label><Button variant="danger" disabled={forgetConfirmation !== "FORGET" || !forgetReason.trim() || Boolean(operation.busy)} onClick={() => run("forget", () => forgetMemoryNode(node.id, node.version, forgetReason.trim()), "Memory forgotten.", () => navigation.navigate("/brain"))}>Forget permanently</Button></Card>
              {operation.message && <p className="brain-mutation-note" role="status">{operation.message}</p>}{operation.error && <ErrorPanel error={operation.error} onRetry={() => { setOperation({}); detail.refresh(); }} />}
            </aside>
          </div>
          {editing && <div className="brain-modal-layer" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) closeEditor(); }}><section ref={editorFocus.dialogRef} className="brain-edit-dialog" role="dialog" aria-modal="true" aria-labelledby="brain-edit-title" tabIndex={-1} onKeyDown={editorFocus.onDialogKeyDown}><p className="os-eyebrow">Versioned correction</p><h2 id="brain-edit-title">Correct memory</h2><label>Title<input data-modal-initial-focus value={title} onChange={(event) => setTitle(event.target.value)} /></label><label>Summary<textarea value={summary} onChange={(event) => setSummary(event.target.value)} /></label><label>Note body<textarea value={body} onChange={(event) => setBody(event.target.value)} /></label><label>Sensitivity<select value={sensitivity} onChange={(event) => setSensitivity(event.target.value as MemorySensitivity)}>{MEMORY_SENSITIVITIES.map((item) => <option key={item}>{item}</option>)}</select></label><label>Reason for correction<textarea value={changeReason} onChange={(event) => setChangeReason(event.target.value)} placeholder="What changed and why" /></label><div><Button variant="secondary" disabled={Boolean(operation.busy)} onClick={closeEditor}>Cancel</Button><Button disabled={!title.trim() || !summary.trim() || !changeReason.trim() || Boolean(operation.busy)} onClick={() => run("correct", () => correctMemoryNode(node.id, node.version, { title: title.trim(), summary: summary.trim(), body, sensitivity }, changeReason.trim()), "Memory corrected and versioned.", () => setEditing(false))}>Save correction</Button></div></section></div>}
        </>;
      })()}
    </div>
  );
}

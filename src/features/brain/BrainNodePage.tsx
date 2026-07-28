import { useEffect, useState } from "react";
import { useNavigation } from "../../app/router/navigation";
import { correctMemoryNode, disputeMemoryNode, expireMemoryNode, exportVault, fetchMemoryNode, fetchMemorySourceOrigins, fetchMemorySources, fetchVaultSnapshot, forgetMemoryNode, pinMemoryNode } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, ButtonLink, Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import { useModalFocus } from "../../design-system/hooks/useModalFocus";
import { MEMORY_SENSITIVITIES, type MemorySensitivity, type OperationalHazardDetail, type OperationalHazardReference, type ProvenanceSource } from "../../domain/types/brain";
import { BrainNav, formatBrainDate, scopeLabel } from "./BrainNav";
import { ContextPackPanel } from "./ContextPackPanel";
import { OperationalHazardResetReview } from "./OperationalHazardResetReview";
import { operationalHazardResetAttribution } from "./hazardAttribution";
import { PrivateSourceCustody, privateSourceBindingCount } from "./PrivateSourceCustody";
import { HistoricalReportedOutcomeBadge } from "./HistoricalReportedOutcomeBadge";
import { MemoryOutcomeTags } from "./MemoryOutcomeTags";

function formatHazardDuration(milliseconds: number | null): string {
  if (milliseconds === null) return "Not constrained";
  if (milliseconds < 1_000) return `${milliseconds} ms`;
  if (milliseconds < 60_000) return `${milliseconds / 1_000} seconds`;
  return `${milliseconds / 60_000} minutes`;
}

function ProvenanceSourceItem({ nodeId, source }: { nodeId: string; source: ProvenanceSource }) {
  const [additionalOrigins, setAdditionalOrigins] = useState(source.origins ?? []);
  const [nextCursor, setNextCursor] = useState(source.originsNextCursor ?? null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error>();
  useEffect(() => {
    setAdditionalOrigins(source.origins ?? []);
    setNextCursor(source.originsNextCursor ?? null);
    setError(undefined);
  }, [source.sourceRecordId, source.origins, source.originsNextCursor]);
  const visibleSource = { ...source, origins: additionalOrigins };
  const loadMoreOrigins = async () => {
    if (!source.sourceRecordId || !nextCursor || loading) return;
    setLoading(true);
    setError(undefined);
    const controller = new AbortController();
    try {
      const page = await fetchMemorySourceOrigins(
        nodeId,
        source.sourceRecordId,
        controller.signal,
        { cursor: nextCursor, limit: 50 },
      );
      setAdditionalOrigins((current) => [...current, ...page.items]);
      setNextCursor(page.nextCursor);
    } catch (reason) {
      setError(reason instanceof Error ? reason : new Error("Additional private custody could not be loaded"));
    } finally {
      setLoading(false);
    }
  };
  return (
    <li>
      <div><StatusPill status={source.sourceType} /><code>{source.sourceId}</code></div>
      <span>Acquired {formatBrainDate(source.acquiredAt)}</span>
      {source.excerptRedacted && <blockquote>{source.excerptRedacted}</blockquote>}
      <PrivateSourceCustody source={visibleSource} />
      {nextCursor && <Button variant="quiet" disabled={loading} onClick={() => void loadMoreOrigins()}>{loading ? "Loading custody…" : `Load more private custody (${additionalOrigins.length} of ${source.originCount ?? additionalOrigins.length})`}</Button>}
      {error && <p className="brain-mutation-note is-error" role="alert">{error.message}</p>}
    </li>
  );
}

function HazardReferences({ label, items }: { label: string; items: readonly OperationalHazardReference[] }) {
  return (
    <div className="brain-hazard-reference-group">
      <h4>{label}</h4>
      {items.length === 0 ? <p className="os-muted">No reusable constraint is recorded.</p> : <ul>{items.map((item) => (
        <li key={item.id}>
          <div><ButtonLink href={`/brain/nodes/${encodeURIComponent(item.id)}`} variant="quiet">{item.title}</ButtonLink><StatusPill status={item.lifecycleStatus} /></div>
          <p>{item.summary}</p>
          <small>{item.nodeType.replaceAll("_", " ")} · {Math.round(item.confidence * 100)}% confidence</small>
        </li>
      ))}</ul>}
    </div>
  );
}

function OperationalHazardPanel({ hazard }: { hazard: OperationalHazardDetail }) {
  const trueConstraints = Object.entries(hazard.applicabilityConstraints)
    .filter(([, enabled]) => enabled)
    .map(([key]) => ({
      requireExactProcedureVersion: "Exact procedure version required",
      requireVerifiedVersionRelationship: "Verified version relationship required",
      requireAllStackNodes: "Every recorded stack component must match",
      requireAllPrerequisites: "Every prerequisite must be present",
      requireObservedState: "The recorded system state must be observed",
    }[key] ?? key));
  const parameters = Object.entries(hazard.normalizedExecution.parameters);
  const exactProcedure = hazard.procedure ? [hazard.procedure] : [];
  const exactProcedureVersion = hazard.procedureVersion ? [hazard.procedureVersion] : [];
  const alternativeProcedure = hazard.alternatives.procedure ? [hazard.alternatives.procedure] : [];
  const recoveryPattern = hazard.recovery.pattern ? [hazard.recovery.pattern] : [];
  const resetAttribution = operationalHazardResetAttribution(hazard);
  return (
    <Card className="brain-hazard-card" aria-label="Operational hazard guardrail">
      <div className="os-section-heading"><div><p className="os-eyebrow">Execution guardrail</p><h2>Operational hazard</h2></div><StatusPill status={hazard.freshness.status} /></div>
      <p className="brain-hazard-lead">This structured reusable failure knowledge explains the recorded conditions that made this procedure unsafe and the safer represented route for future work. Its lifecycle, freshness, confidence, and provenance remain visible below.</p>
      <div className="brain-hazard-warning" role="note">
        <strong>A healthy baseline is not permission to repeat the known-bad procedure.</strong>
        <p>The health gate only proves the affected component recovered. A new represented attempt must also use the recorded safer sequence and parameter exclusions, or select the alternative procedure.</p>
      </div>

      <section className="brain-hazard-section" aria-labelledby="hazard-applicability-title">
        <h3 id="hazard-applicability-title">Where this warning applies</h3>
        <div className="brain-hazard-reference-grid">
          <HazardReferences label="Exact procedure" items={exactProcedure} />
          <HazardReferences label="Exact procedure version" items={exactProcedureVersion} />
          <HazardReferences label="Affected products" items={hazard.affectedProducts} />
          <HazardReferences label="Affected versions" items={hazard.affectedVersions} />
          <HazardReferences label="Affected stack" items={hazard.affectedStack} />
          <HazardReferences label="Prerequisites" items={hazard.prerequisites} />
        </div>
        {trueConstraints.length > 0 && <div className="brain-hazard-constraints"><h4>Required match conditions</h4><ul>{trueConstraints.map((constraint) => <li key={constraint}>{constraint}</li>)}</ul></div>}
      </section>

      <section className="brain-hazard-section" aria-labelledby="hazard-sequence-title">
        <h3 id="hazard-sequence-title">Recorded execution shape</h3>
        <dl className="brain-hazard-metrics">
          <div><dt>Minimum load</dt><dd>{hazard.normalizedExecution.loadMinimum ?? "Not constrained"}</dd></div>
          <div><dt>Minimum concurrency</dt><dd>{hazard.normalizedExecution.concurrencyMinimum ?? "Not constrained"}</dd></div>
          <div><dt>Timing window</dt><dd>{formatHazardDuration(hazard.normalizedExecution.timingWindowMs)}</dd></div>
          <div><dt>Observed attempts</dt><dd>{hazard.corroboration.observedAttemptCount}</dd></div>
        </dl>
        <div className="brain-hazard-columns">
          <div><h4>Ordered sequence</h4><ol>{hazard.orderedSequence.map((step, index) => <li key={`${index}:${step}`}>{step}</li>)}</ol></div>
          <div><h4>Normalized parameters</h4>{parameters.length === 0 ? <p className="os-muted">No reusable parameters are recorded.</p> : <dl className="brain-hazard-parameters">{parameters.map(([key, value]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{String(value)}</dd></div>)}</dl>}</div>
        </div>
      </section>

      <section className="brain-hazard-section" aria-labelledby="hazard-outcome-title">
        <h3 id="hazard-outcome-title">What failed</h3>
        <p><strong>{hazard.symptom.affectedComponent}:</strong> {hazard.symptom.observed}</p>
        <div className="brain-hazard-state"><div><span>Before</span><p>{hazard.stateTransition.before}</p></div><div><span>After</span><p>{hazard.stateTransition.after}</p></div></div>
        <dl className="brain-hazard-counts">
          <div><dt>Exact corroborated hang count</dt><dd>{hazard.corroboration.exactHangCount}</dd><small>Locally evidenced repetitions of this exact procedure and context.</small></div>
          <div><dt>Exact resets for this procedure</dt><dd>{resetAttribution.exactProcedureResetCount}</dd><small>Reset episodes linked to this exact procedure version and target-state transition.</small></div>
          <div><dt>Operator-reported overall reset minimum</dt><dd>{resetAttribution.operatorReportedOverallMinimum ?? "Not reported"}</dd><small>Reported recovery burden across the source history; it is not counted as exact procedure evidence.</small></div>
          <div><dt>Overall minimum not tied to this procedure</dt><dd>{resetAttribution.minimumNotAttributedToThisProcedure ?? "Not reported"}</dd><small>Reset episodes from the broader source history that this exact procedure receipt does not explain.</small></div>
        </dl>
        <HazardReferences label="Observed state" items={hazard.observedStates} />
      </section>

      <section className="brain-hazard-section brain-hazard-recovery" aria-labelledby="hazard-recovery-title">
        <h3 id="hazard-recovery-title">Recovery and safer continuation</h3>
        <div className="brain-hazard-columns">
          <div><h4>Safe health gate</h4><ul>{hazard.safeHealthGate.map((item) => <li key={item}>{item}</li>)}</ul></div>
          <div><h4>Unsafe retry conditions</h4><ul>{hazard.unsafeRetryConditions.map((item) => <li key={item}>{item}</li>)}</ul></div>
          <div><h4>Safer sequence</h4><ol>{hazard.alternatives.sequence.map((item, index) => <li key={`${index}:${item}`}>{item}</li>)}</ol></div>
          <div><h4>Recovery</h4><p>{hazard.recovery.summary}</p></div>
        </div>
        <div className="brain-hazard-reference-grid">
          <HazardReferences label="Recovery pattern" items={recoveryPattern} />
          <HazardReferences label="Alternative procedure" items={alternativeProcedure} />
        </div>
      </section>

      <footer className="brain-hazard-receipt">
        <div><span>Knowledge confidence</span><strong>{Math.round(hazard.confidence * 100)}%</strong></div>
        <div><span>Observed</span><strong>{formatBrainDate(hazard.freshness.observedAt)}</strong></div>
        <div><span>Fresh until</span><strong>{hazard.freshness.freshUntil ? formatBrainDate(hazard.freshness.freshUntil) : "No fixed expiry"}</strong></div>
        <div><span>Provenance receipt</span><strong className="os-mono">{hazard.provenanceReceipt.receiptHash.slice(0, 16)}…</strong><small>{hazard.provenanceReceipt.sourceCount} opaque source receipt{hazard.provenanceReceipt.sourceCount === 1 ? "" : "s"} · profile v{hazard.provenanceReceipt.profileVersion}</small></div>
      </footer>
    </Card>
  );
}

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
  const [additionalSources, setAdditionalSources] = useState<ProvenanceSource[]>([]);
  const [sourcesNextCursor, setSourcesNextCursor] = useState<string | null | undefined>();
  const [sourcesLoading, setSourcesLoading] = useState(false);
  const [sourcesError, setSourcesError] = useState<Error>();
  useEffect(() => {
    setAdditionalSources([]);
    setSourcesNextCursor(undefined);
    setSourcesError(undefined);
  }, [nodeId, detail.data?.node.version]);
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
        const loadedSources = [...detail.data.sources, ...additionalSources];
        const nextSourceCursor = sourcesNextCursor === undefined
          ? detail.data.sourcesNextCursor
          : sourcesNextCursor;
        const loadMoreSources = async () => {
          if (!nextSourceCursor || sourcesLoading) return;
          setSourcesLoading(true);
          setSourcesError(undefined);
          const controller = new AbortController();
          try {
            const page = await fetchMemorySources(node.id, controller.signal, {
              cursor: nextSourceCursor,
              limit: 25,
            });
            setAdditionalSources((current) => [...current, ...page.items]);
            setSourcesNextCursor(page.nextCursor);
          } catch (reason) {
            setSourcesError(reason instanceof Error ? reason : new Error("Additional provenance could not be loaded"));
          } finally {
            setSourcesLoading(false);
          }
        };
        const selectedVaultId = vaultConnectionId || vault.data?.connections[0]?.id || "";
        const reusableEdgeCount = detail.data.backlinks.length + detail.data.outgoing.length;
        const privateBindingCount = privateSourceBindingCount(loadedSources);
        const nodeVaultState = vault.data?.syncStates.find((item) => (
          item.connectionId === selectedVaultId && item.nodeId === node.id
        ));
        return <>
          <section className="brain-node-banner"><div><span>Type</span><strong>{node.nodeType.replaceAll("_", " ")}</strong></div><div><span>Lifecycle</span><StatusPill status={node.lifecycleStatus} /></div><div><span>Verified outcome</span><MemoryOutcomeTags tags={node.outcomeTags} /></div><div><span>Historical report</span><HistoricalReportedOutcomeBadge outcome={node.reportedOutcome} /></div><div><span>Scope</span><strong>{scopeLabel(node.scope)}</strong></div><div><span>Confidence</span><strong>{Math.round(node.confidence * 100)}%</strong></div><div><span>Sensitivity</span><strong>{node.sensitivity}</strong></div><div><span>Version</span><strong>{node.version}</strong></div></section>
          <div className="brain-node-layout">
            <section aria-label="Memory record detail">
              <Card><div className="os-section-heading"><div><p className="os-eyebrow">Inspect</p><h2>Memory note</h2></div><Button variant="secondary" onClick={beginEdit}>Correct memory</Button></div><p className="brain-node-summary">{node.summary}</p><div className="brain-node-body">{node.body || "This memory has no additional note body."}</div></Card>
              {node.nodeType === "operational_hazard" && (detail.data.operationalHazard
                ? <><OperationalHazardPanel hazard={detail.data.operationalHazard} /><OperationalHazardResetReview hazard={detail.data.operationalHazard} usage={detail.data.usage} /></>
                : <Card className="brain-hazard-card" aria-label="Operational hazard guardrail"><div className="os-section-heading"><div><p className="os-eyebrow">Execution guardrail</p><h2>Operational hazard</h2></div></div><p className="os-muted">This memory has no structured operational-hazard profile. It cannot gate execution until its reusable procedure, conditions, recovery, and provenance are represented.</p></Card>)}
              <Card><div className="os-section-heading"><div><p className="os-eyebrow">Source of truth</p><h2>Provenance</h2></div></div><p>{node.provenance.explanation}</p>{loadedSources.length === 0 ? <p className="os-muted">No canonical source custody is recorded. This memory requires reconciliation before it can be treated as attributable.</p> : <><p className="os-muted">Showing {loadedSources.length} of {node.sourceCount} canonical source records.</p><ul className="brain-provenance-list">{loadedSources.map((source) => <ProvenanceSourceItem key={source.sourceRecordId ?? `${source.sourceType}:${source.sourceId}`} nodeId={node.id} source={source} />)}</ul>{nextSourceCursor && <Button variant="secondary" disabled={sourcesLoading} onClick={() => void loadMoreSources()}>{sourcesLoading ? "Loading more provenance…" : "Load more provenance"}</Button>}{sourcesError && <p className="brain-mutation-note is-error" role="alert">{sourcesError.message}</p>}</>}</Card>
              <Card><div className="os-section-heading"><div><p className="os-eyebrow">Connections</p><h2>Reusable relationships and private custody</h2></div></div><p className="os-muted">{detail.data.backlinks.length} backlinks · {detail.data.outgoing.length} outgoing · {privateBindingCount} loaded exact private custody binding{privateBindingCount === 1 ? "" : "s"}</p>{reusableEdgeCount === 0 ? <p className="os-muted">{privateBindingCount > 0 ? "No reusable graph edges are recorded. Exact private custody remains linked in Provenance without becoming reusable attack content." : "No reusable relationships or loaded exact private custody bindings are recorded for this node."}</p> : <ul className="brain-edge-list">{[...detail.data.backlinks, ...detail.data.outgoing].map((edge) => { const peer = edge.sourceNodeId === node.id ? edge.targetNodeId : edge.sourceNodeId; return <li key={`${edge.id}:${peer}`}><StatusPill status={edge.edgeType} /><div><ButtonLink href={`/brain/nodes/${encodeURIComponent(peer)}`} variant="quiet">{edge.title}</ButtonLink><p>{edge.explanation}</p></div><span>{Math.round(edge.confidence * 100)}%</span></li>; })}</ul>}</Card>
              <Card><div className="os-section-heading"><div><p className="os-eyebrow">Memory transparency</p><h2>Context use history</h2></div></div>{detail.data.usage.length === 0 ? <p className="os-muted">No plan, response, action, or report has recorded using this memory.</p> : <ul className="brain-context-history">{detail.data.usage.map((usage) => <li key={`${usage.contextPackId}:${usage.createdAt}`}><button onClick={() => setContextPackId(contextPackId === usage.contextPackId ? undefined : usage.contextPackId)}><div><strong>{usage.purpose}</strong><span>{formatBrainDate(usage.createdAt)}</span></div><StatusPill status={usage.used ? "used" : "ignored"} /></button><p>{usage.influenceSummary ?? usage.ignoredReason ?? usage.relevanceReason}</p></li>)}</ul>}{contextPackId && <ContextPackPanel packId={contextPackId} />}</Card>
              <Card><div className="os-section-heading"><div><p className="os-eyebrow">Audit</p><h2>Version history</h2></div></div><ol className="brain-version-list">{detail.data.versions.map((version) => <li key={version.version}><span>{version.version}</span><div><strong>{version.title}</strong><p>{version.changeReason ?? version.summary}</p><small>{version.changedBy} · {formatBrainDate(version.changedAt)}</small></div></li>)}</ol></Card>
            </section>
            <aside>
              <Card className="brain-control-card"><div className="os-section-heading"><div><p className="os-eyebrow">Operator controls</p><h2>Lifecycle and retention</h2></div></div><Button variant="secondary" disabled={Boolean(operation.busy)} onClick={() => run("pin", () => pinMemoryNode(node.id, node.version, !node.pinned), node.pinned ? "Memory unpinned." : "Memory pinned.")}>{node.pinned ? "Unpin memory" : "Pin memory"}</Button><label>Expire on<input type="datetime-local" value={expiry} onChange={(event) => setExpiry(event.target.value)} /></label><Button variant="secondary" disabled={!expiry || Boolean(operation.busy)} onClick={() => run("expire", () => expireMemoryNode(node.id, node.version, new Date(expiry).toISOString(), "Operator configured retention expiry"), "Memory expiry updated.")}>Set expiry</Button><label>Dispute reason<textarea value={disputeReason} onChange={(event) => setDisputeReason(event.target.value)} placeholder="Describe the contradiction or uncertainty" /></label><Button variant="secondary" disabled={!disputeReason.trim() || Boolean(operation.busy)} onClick={() => run("dispute", () => disputeMemoryNode(node.id, node.version, disputeReason.trim()), "Memory marked disputed.")}>Mark disputed</Button></Card>
              <Card className="brain-control-card"><div className="os-section-heading"><div><p className="os-eyebrow">Human-readable projection</p><h2>Obsidian note</h2></div></div>{vault.isLoading ? <p className="os-muted">Checking configured vaults…</p> : vault.error && !vault.data ? <ErrorPanel error={vault.error} onRetry={vault.refresh} /> : vault.data?.enabled && vault.data.connections.length > 0 ? <><label>Vault<TitaniumSelect value={selectedVaultId} onChange={(event) => setVaultConnectionId(event.target.value)}>{vault.data.connections.map((connection) => <option key={connection.id} value={connection.id}>{connection.displayName}</option>)}</TitaniumSelect></label><Button variant="secondary" disabled={!selectedVaultId || Boolean(operation.busy)} onClick={() => run("export-node", () => exportVault(selectedVaultId, node.id), "This memory was exported as a versioned Obsidian note.", vault.refresh)}>Export this memory</Button>{nodeVaultState?.obsidianUrl ? <a className="os-button os-button--quiet" href={nodeVaultState.obsidianUrl} rel="noopener noreferrer">Open this note in Obsidian</a> : <p className="os-muted">Export this memory once to create its stable note and deep link.</p>}</> : <p className="os-muted">Connect an explicitly permitted vault before exporting this memory.</p>}<ButtonLink href="/brain/vault" variant="quiet">Open Obsidian vault controls</ButtonLink></Card>
              <Card className="brain-forget-card"><p className="os-eyebrow">Privacy erasure</p><h2>Forget this memory</h2><p>This removes reusable content, embeddings, derived edges, context references, and synchronized projections. Only a content-free audit event and optional suppression fingerprint remain.</p><label>Reason<textarea value={forgetReason} onChange={(event) => setForgetReason(event.target.value)} /></label><label>Type FORGET<input value={forgetConfirmation} onChange={(event) => setForgetConfirmation(event.target.value)} autoComplete="off" /></label><Button variant="danger" disabled={forgetConfirmation !== "FORGET" || !forgetReason.trim() || Boolean(operation.busy)} onClick={() => run("forget", () => forgetMemoryNode(node.id, node.version, forgetReason.trim()), "Memory forgotten.", () => navigation.navigate("/brain"))}>Forget permanently</Button></Card>
              {operation.message && <p className="brain-mutation-note" role="status">{operation.message}</p>}{operation.error && <ErrorPanel error={operation.error} onRetry={() => { setOperation({}); detail.refresh(); }} />}
            </aside>
          </div>
          {editing && <div className="brain-modal-layer" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) closeEditor(); }}><section ref={editorFocus.dialogRef} className="brain-edit-dialog" role="dialog" aria-modal="true" aria-labelledby="brain-edit-title" tabIndex={-1} onKeyDown={editorFocus.onDialogKeyDown}><p className="os-eyebrow">Versioned correction</p><h2 id="brain-edit-title">Correct memory</h2><label>Title<input data-modal-initial-focus value={title} onChange={(event) => setTitle(event.target.value)} /></label><label>Summary<textarea value={summary} onChange={(event) => setSummary(event.target.value)} /></label><label>Note body<textarea value={body} onChange={(event) => setBody(event.target.value)} /></label><label>Sensitivity<TitaniumSelect value={sensitivity} onChange={(event) => setSensitivity(event.target.value as MemorySensitivity)}>{MEMORY_SENSITIVITIES.map((item) => <option key={item}>{item}</option>)}</TitaniumSelect></label><label>Reason for correction<textarea value={changeReason} onChange={(event) => setChangeReason(event.target.value)} placeholder="What changed and why" /></label><div><Button variant="secondary" disabled={Boolean(operation.busy)} onClick={closeEditor}>Cancel</Button><Button disabled={!title.trim() || !summary.trim() || !changeReason.trim() || Boolean(operation.busy)} onClick={() => run("correct", () => correctMemoryNode(node.id, node.version, { title: title.trim(), summary: summary.trim(), body, sensitivity }, changeReason.trim()), "Memory corrected and versioned.", () => setEditing(false))}>Save correction</Button></div></section></div>}
        </>;
      })()}
    </div>
  );
}

import { type FormEvent, useState } from "react";
import { AppLink } from "../../app/router/navigation";
import { operationsApi } from "../../data/api/operations";
import { useQuery } from "../../data/cache/QueryProvider";
import type { ArtifactRecord, EvidenceRecord, FindingRecord } from "../../domain/types/operations";
import { Button, Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { CursorControls, FilterForm, formatTime, JsonDetails, KeyValueGrid, QueryBoundary, SelectFilter, StreamState, SurfaceTabs, useActionState, useUrlFilters } from "../runs/OperationalSurface";

type IntelligenceView = "evidence" | "findings" | "artifacts";

export function missionDetailHref(missionId: string): string {
  return `/missions/${encodeURIComponent(missionId)}`;
}

export function runDetailHref(missionId: string, runId: string): string {
  return `${missionDetailHref(missionId)}/runs/${encodeURIComponent(runId)}`;
}

export function evidenceDetailHref(evidenceId: string): string {
  return `/intelligence/evidence/${encodeURIComponent(evidenceId)}`;
}

export function artifactDetailHref(artifactId: string): string {
  return `/intelligence/artifacts/${encodeURIComponent(artifactId)}`;
}

function MissionRelation({ mission }: { mission: { id: string; name: string } }) {
  return <AppLink href={missionDetailHref(mission.id)}>{mission.name}</AppLink>;
}

function RunRelation({ missionId, rawRunId, run }: {
  missionId: string;
  rawRunId: string | null;
  run?: { id: string } | null;
}) {
  if (run) return <AppLink href={runDetailHref(missionId, run.id)}>{run.id}</AppLink>;
  return <span className="os-muted">{rawRunId
    ? "Referenced run is unavailable or belongs to another mission."
    : "No run relation was retained."}</span>;
}

export default function IntelligencePage({ view, selectedId }: { view: IntelligenceView; selectedId?: string }) {
  return <div className="os-page"><PageHeader eyebrow="Verified intelligence" title="Evidence, findings, and artifacts" description="Immutable provenance and evidence-gated conclusions from authorized missions." actions={<StreamState />} />
    <SurfaceTabs current={view} items={[{ id: "evidence", label: "Evidence", href: "/intelligence/evidence" }, { id: "findings", label: "Findings", href: "/intelligence/findings" }, { id: "artifacts", label: "Artifacts", href: "/intelligence/artifacts" }]} />
    {view === "evidence" && <EvidenceView selectedId={selectedId} />}{view === "findings" && <FindingView selectedId={selectedId} />}{view === "artifacts" && <ArtifactView selectedId={selectedId} />}
  </div>;
}

function EvidenceView({ selectedId }: { selectedId?: string }) {
  const filters = useUrlFilters({ limit: "25" });
  const list = useQuery(`evidence:${filters.key}`, (signal) => operationsApi.evidence(filters.values, signal));
  const detail = useQuery(`evidence-detail:${selectedId ?? "none"}`, (signal) => selectedId ? operationsApi.evidenceDetail(selectedId, signal) : Promise.resolve(undefined));
  const exportBoundary = selectedId
    ? detail.data
      ? resolveEvidenceExportBoundary([detail.data], detail.data.runId, true)
      : HIDDEN_EVIDENCE_EXPORT_BOUNDARY
    : list.data
      ? resolveEvidenceExportBoundary(list.data.items, filters.values.runId, Boolean(filters.values.runId))
      : HIDDEN_EVIDENCE_EXPORT_BOUNDARY;
  return <><FilterForm filters={filters}><SelectFilter filters={filters} name="recordClass" label="Record class" defaultLabel="Evidence only" options={[{ value: "operational_log", label: "Imported operational logs" }, { value: "all", label: "Evidence and operational logs" }]} /><SelectFilter filters={filters} name="verificationState" label="Verification" options={["unverified", "verified", "disputed", "rejected"].map((value) => ({ value, label: value }))} /></FilterForm>
    <p className="os-muted">Raw command output is hidden by default because a technical log is not proof. Choose imported operational logs only when reconciling historical records or deep links.</p>
    <EvidenceRunExportControl boundary={exportBoundary} />
    <IntelligenceLayout list={<QueryBoundary data={list.data?.items} error={list.error} isLoading={list.isLoading} onRetry={list.refresh} emptyTitle="No evidence retained" emptyDescription="Evidence appears when an attributable observation or artifact is deliberately retained and classified through the evidence workflow.">{(items) => <><EvidenceTable items={items} selectedId={selectedId} /><CursorControls cursor={filters.values.cursor} nextCursor={list.data?.nextCursor ?? null} onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })} /></>}</QueryBoundary>} detail={<EvidenceDetail item={detail.data} loading={detail.isLoading && Boolean(selectedId)} error={detail.error} onRetry={detail.refresh} />} />
  </>;
}

type EvidenceRunProjection = Pick<EvidenceRecord, "runId" | "run">;

export type EvidenceExportBoundary =
  | { readonly state: "hidden" }
  | { readonly state: "canonical"; readonly runId: string }
  | { readonly state: "missing_relation" }
  | { readonly state: "unresolved_relation" };

const HIDDEN_EVIDENCE_EXPORT_BOUNDARY: EvidenceExportBoundary = { state: "hidden" };

/**
 * A raw run_id is retained for reconciliation only. It is never sufficient to
 * construct a navigation or export URL. The repository's same-mission `run`
 * projection must agree with that raw relation before the boundary is usable.
 */
export function resolveEvidenceExportBoundary(
  records: readonly EvidenceRunProjection[],
  requestedRunId: string | null | undefined,
  explainMissing: boolean,
): EvidenceExportBoundary {
  const expectedRunId = requestedRunId?.trim();
  if (!expectedRunId) return explainMissing ? { state: "missing_relation" } : HIDDEN_EVIDENCE_EXPORT_BOUNDARY;
  const verified = records.some((record) => record.runId === expectedRunId && record.run?.id === expectedRunId);
  return verified ? { state: "canonical", runId: expectedRunId } : { state: "unresolved_relation" };
}

export function EvidenceRunExportControl({ boundary }: { boundary: EvidenceExportBoundary }) {
  if (boundary.state === "hidden") return null;
  if (boundary.state === "missing_relation") return <Card aria-label="Evidence export reconciliation">
    <div className="os-card-heading"><div><p className="os-eyebrow">Reconciliation required</p><h2>Run-scoped export unavailable</h2></div></div>
    <p className="os-muted">No canonical run relation was retained for this evidence. Reconcile it to an authorized run in the same mission before exporting run-scoped metadata.</p>
  </Card>;
  if (boundary.state === "unresolved_relation") return <Card aria-label="Evidence export reconciliation">
    <div className="os-card-heading"><div><p className="os-eyebrow">Reconciliation required</p><h2>Run-scoped export unavailable</h2></div></div>
    <p className="os-muted">The retained run reference is unavailable or belongs to another mission. It is shown only for reconciliation and is never used to construct a run or export link.</p>
  </Card>;
  return <Card aria-label="Exact run evidence export">
    <div className="os-card-heading">
      <div><p className="os-eyebrow">Exact run scope</p><h2>Bounded evidence metadata export</h2></div>
      <a className="os-button os-button--secondary" href={operationsApi.evidenceRunExportUrl(boundary.runId)} download>Export evidence metadata</a>
    </div>
    <p className="os-muted">Run <span className="os-mono">{boundary.runId}</span> is a repository-verified same-mission export boundary. The server re-checks authorization and sensitivity, bounds the record count and size, and excludes raw evidence content and storage paths.</p>
  </Card>;
}

function EvidenceTable({ items, selectedId }: { items: EvidenceRecord[]; selectedId?: string }) {
  return <div className="os-table-wrap"><table className="os-data-table"><thead><tr><th>Record</th><th>Mission</th><th>Type</th><th>Verification</th><th>Acquired</th></tr></thead><tbody>{items.map((item) => <tr key={item.id} className={item.id === selectedId ? "is-selected" : undefined}><th scope="row"><AppLink href={evidenceDetailHref(item.id)}>{item.summary || item.id}</AppLink><small>{item.recordClass === "operational_log" ? "Historical operational log · not evidence" : "Retained evidence"}</small><small className="os-mono">{item.contentHash.slice(0, 12)}…</small></th><td><MissionRelation mission={item.mission} /></td><td>{item.evidenceType}</td><td><StatusPill status={item.verificationState} /></td><td>{formatTime(item.acquiredAt)}</td></tr>)}</tbody></table></div>;
}

function EvidenceDetail({ item, loading, error, onRetry }: { item?: EvidenceRecord; loading: boolean; error?: Error; onRetry: () => void }) {
  if (loading) return <LoadingPanel label="Loading evidence provenance" />; if (error && !item) return <ErrorPanel error={error} onRetry={onRetry} />; if (!item) return <Card><p className="os-muted">Select evidence to inspect provenance and chain of custody.</p></Card>;
  return <Card><div className="os-card-heading"><h2>{item.summary || "Evidence record"}</h2><StatusPill status={item.verificationState} /></div>{item.recordClass === "operational_log" && <div className="os-callout" role="note"><strong>Historical operational log — not verified evidence.</strong><p className="os-muted">This raw command output is retained under its stable ID for audit and reconciliation. Review and promote a supported observation through the evidence workflow before using it to prove a finding.</p></div>}<KeyValueGrid items={[{ label: "Target", value: item.target ?? "Not reported" }, { label: "Confidence", value: item.confidence === null ? "Not scored" : `${Math.round(item.confidence * 100)}%` }, { label: "Sensitivity", value: item.sensitivity }, { label: "Hash", value: <span className="os-mono">{item.contentHash}</span> }]} />
    <h3>Canonical relationships</h3><KeyValueGrid items={[
      { label: "Mission", value: <MissionRelation mission={item.mission} /> },
      { label: "Run", value: <RunRelation missionId={item.mission.id} rawRunId={item.runId} run={item.run} /> },
      { label: "Artifact", value: item.artifact
        ? <AppLink href={artifactDetailHref(item.artifact.id)}>{item.artifact.artifactType}</AppLink>
        : <span className="os-muted">{item.artifactId
          ? "Referenced artifact is unavailable or outside the current scope."
          : "No artifact relation was retained."}</span> },
    ]} />
    <h3>Chain of custody</h3>{item.chainOfCustody?.length ? <ol className="os-timeline">{item.chainOfCustody.map((event) => <li key={event.id}><strong>{event.eventType}</strong><span>{event.actor} · {formatTime(event.occurredAt)}</span><JsonDetails value={event.details} /></li>)}</ol> : <p className="os-muted">No custody events returned.</p>}<JsonDetails label="Provenance" value={item.provenance} /></Card>;
}

function FindingView({ selectedId }: { selectedId?: string }) {
  const filters = useUrlFilters({ limit: "25" });
  const list = useQuery(`findings:${filters.key}`, (signal) => operationsApi.findings(filters.values, signal));
  const detail = useQuery(`finding-detail:${selectedId ?? "none"}`, (signal) => selectedId ? operationsApi.finding(selectedId, signal) : Promise.resolve(undefined), { staleTime: 0 });
  return <><FilterForm filters={filters}><SelectFilter filters={filters} name="severity" label="Severity" options={["informational", "low", "medium", "high", "critical"].map((value) => ({ value, label: value }))} /><SelectFilter filters={filters} name="reviewStatus" label="Review" options={["draft", "under_review", "verified", "rejected", "accepted_risk"].map((value) => ({ value, label: value }))} /></FilterForm>
    <IntelligenceLayout list={<QueryBoundary data={list.data?.items} error={list.error} isLoading={list.isLoading} onRetry={list.refresh} emptyTitle="No findings recorded" emptyDescription="Evidence-linked conclusions will appear here for review.">{(items) => <><div className="os-table-wrap"><table className="os-data-table"><thead><tr><th>Finding</th><th>Severity</th><th>Evidence</th><th>Review</th><th>Updated</th></tr></thead><tbody>{items.map((item) => <tr key={item.id} className={item.id === selectedId ? "is-selected" : undefined}><th scope="row" className="os-finding-link-stack"><AppLink className="os-finding-primary-link" href={`/intelligence/findings/${encodeURIComponent(item.id)}`}>{item.title}</AppLink><small className="os-finding-secondary-link"><MissionRelation mission={item.mission} /></small></th><td><StatusPill status={item.severity} /></td><td>{item.verifiedEvidenceCount}/{item.evidenceCount} verified</td><td><StatusPill status={item.reviewStatus} /></td><td>{formatTime(item.updatedAt)}</td></tr>)}</tbody></table></div><CursorControls cursor={filters.values.cursor} nextCursor={list.data?.nextCursor ?? null} onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })} /></>}</QueryBoundary>} detail={<FindingDetail item={detail.data} loading={detail.isLoading && Boolean(selectedId)} error={detail.error} onRetry={detail.refresh} onChanged={() => { detail.refresh(); list.refresh(); }} />} />
  </>;
}

function FindingDetail({ item, loading, error, onRetry, onChanged }: { item?: FindingRecord; loading: boolean; error?: Error; onRetry: () => void; onChanged: () => void }) {
  const [status, setStatus] = useState("under_review"); const [reason, setReason] = useState(""); const [override, setOverride] = useState(false); const action = useActionState();
  if (loading) return <LoadingPanel label="Loading finding evidence" />; if (error && !item) return <ErrorPanel error={error} onRetry={onRetry} />; if (!item) return <Card><p className="os-muted">Select a finding to inspect impact and linked evidence.</p></Card>;
  const submit = (event: FormEvent) => { event.preventDefault(); void action.run(() => operationsApi.reviewFinding(item.id, { expectedVersion: item.version, status, reason, operatorOverride: override }, `finding-${crypto.randomUUID()}`).then(onChanged), "Finding review recorded."); };
  return <Card><div className="os-card-heading"><h2>{item.title}</h2><StatusPill status={item.severity} /></div><p>{item.description}</p><h3>Impact</h3><p>{item.impact}</p>{item.remediation && <><h3>Remediation</h3><p>{item.remediation}</p></>}<KeyValueGrid items={[{ label: "Affected scope", value: item.affectedScope }, { label: "Confidence", value: item.confidence === null ? "Not scored" : `${Math.round(item.confidence * 100)}%` }, { label: "Evidence", value: `${item.verifiedEvidenceCount}/${item.evidenceCount} verified` }, { label: "Version", value: item.version }]} />
    <h3>Canonical relationships</h3><KeyValueGrid items={[
      { label: "Mission", value: <MissionRelation mission={item.mission} /> },
      { label: "Run", value: <RunRelation missionId={item.mission.id} rawRunId={item.runId} run={item.run} /> },
    ]} />
    {item.evidence?.length ? <ul className="os-compact-list">{item.evidence.map((evidence) => <li key={evidence.id}><AppLink href={evidenceDetailHref(evidence.id)}>{evidence.summary}</AppLink><StatusPill status={evidence.verificationState} /></li>)}</ul> : <p className="os-muted">No evidence links were returned. Verification remains evidence-gated.</p>}
    <form className="os-review-form" onSubmit={submit}><h3>Record review decision</h3><label><span>Status</span><select value={status} onChange={(event) => setStatus(event.target.value)}>{["under_review", "verified", "rejected", "accepted_risk"].map((value) => <option key={value}>{value}</option>)}</select></label><label><span>Reason</span><textarea required value={reason} onChange={(event) => setReason(event.target.value)} /></label><label className="os-check"><input type="checkbox" checked={override} onChange={(event) => setOverride(event.target.checked)} /><span>Explicit evidence-gate override (audited)</span></label>{action.error && <ErrorPanel error={action.error} />}{action.message && <p role="status" className="os-success-note">{action.message}</p>}<Button disabled={action.pending || reason.trim().length < 3}>{action.pending ? "Recording…" : "Record decision"}</Button></form>
  </Card>;
}

function ArtifactView({ selectedId }: { selectedId?: string }) {
  const filters = useUrlFilters({ limit: "25" }); const list = useQuery(`artifacts:${filters.key}`, (signal) => operationsApi.artifacts(filters.values, signal)); const detail = useQuery(`artifact:${selectedId ?? "none"}`, (signal) => selectedId ? operationsApi.artifact(selectedId, signal) : Promise.resolve(undefined));
  return <><FilterForm filters={filters} searchKey="artifactType" searchLabel="Artifact type" /><IntelligenceLayout list={<QueryBoundary data={list.data?.items} error={list.error} isLoading={list.isLoading} onRetry={list.refresh} emptyTitle="No artifacts produced" emptyDescription="Reports, captures, and exports will appear after durable creation.">{(items) => <><div className="os-table-wrap"><table className="os-data-table"><thead><tr><th>Artifact</th><th>Mission</th><th>Size</th><th>Storage</th><th>Created</th></tr></thead><tbody>{items.map((item) => <tr key={item.id} className={item.id === selectedId ? "is-selected" : undefined}><th scope="row"><AppLink href={artifactDetailHref(item.id)}>{item.artifactType}</AppLink><small>{item.mediaType}</small></th><td><MissionRelation mission={item.mission} /></td><td>{new Intl.NumberFormat(undefined, { notation: "compact", style: "unit", unit: "byte" }).format(item.byteSize)}</td><td><StatusPill status={item.storage.available ? "available" : "unavailable"}>{item.storage.scheme}</StatusPill></td><td>{formatTime(item.createdAt)}</td></tr>)}</tbody></table></div><CursorControls cursor={filters.values.cursor} nextCursor={list.data?.nextCursor ?? null} onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })} /></>}</QueryBoundary>} detail={<ArtifactDetail item={detail.data} loading={detail.isLoading && Boolean(selectedId)} error={detail.error} onRetry={detail.refresh} />} /></>;
}

export function supportsVerifiedArtifactDownload(item: Pick<ArtifactRecord, "artifactType" | "storage" | "evidence" | "delivery">): boolean {
  return item.delivery?.state === "ready"
    && item.delivery.downloadable
    && item.delivery.verifiedEvidenceCount > 0
    && item.evidence?.some((evidence) => evidence.verificationState === "verified") === true
    && item.artifactType === "obsidian_attachment"
    && item.storage.scheme === "vault-attachment"
    && item.storage.available;
}

export function artifactDeliveryEvidenceLabel(count: number): string {
  return `${count} visible verified evidence record${count === 1 ? "" : "s"} ${count === 1 ? "supports" : "support"} this delivery boundary.`;
}

export function ArtifactDetail({ item, loading, error, onRetry }: { item?: ArtifactRecord; loading: boolean; error?: Error; onRetry: () => void }) {
  if (loading) return <LoadingPanel label="Loading artifact metadata" />;
  if (error && !item) return <ErrorPanel error={error} onRetry={onRetry} />;
  if (!item) return <Card><p className="os-muted">Select an artifact to inspect its hash, provenance-safe storage projection, and evaluation link.</p></Card>;
  const supportsDownload = supportsVerifiedArtifactDownload(item);
  const deliveryLabel = supportsDownload
    ? "Verified delivery"
    : item.delivery?.state === "quarantined"
      ? "Quarantined"
      : item.delivery?.state === "reconciliation_required"
        ? "Reconciliation required"
        : "Metadata only";
  return <Card>
    <div className="os-card-heading"><h2>{item.artifactType}</h2><StatusPill status={supportsDownload ? "verified_delivery" : item.delivery?.state ?? "metadata_only"}>{deliveryLabel}</StatusPill></div>
    <KeyValueGrid items={[{ label: "Mission", value: <MissionRelation mission={item.mission} /> }, { label: "Run", value: <RunRelation missionId={item.mission.id} rawRunId={item.runId} run={item.run} /> }, { label: "Media type", value: item.mediaType }, { label: "Byte size", value: item.byteSize.toLocaleString() }, { label: "Storage scheme", value: item.storage.scheme }, { label: "Hash", value: <span className="os-mono">{item.contentHash}</span> }]} />
    <h3>Related evidence</h3>
    {item.evidence?.length ? <ul className="os-compact-list">{item.evidence.map((evidence) => <li key={evidence.id}><AppLink href={evidenceDetailHref(evidence.id)}>{evidence.summary}</AppLink><StatusPill status={evidence.verificationState} /></li>)}</ul> : <p className="os-muted">No evidence records reference this artifact.</p>}
    <JsonDetails label="Artifact metadata" value={item.metadata} />
    {item.delivery && <section aria-label="Artifact content delivery"><h3>Content delivery</h3><p>{item.delivery.reason}</p>{item.delivery.remediation && <p className="os-muted">{item.delivery.remediation}</p>}<p className="os-muted">{artifactDeliveryEvidenceLabel(item.delivery.verifiedEvidenceCount)}</p></section>}
    {supportsDownload ? <>
      <div className="os-completion-actions"><a className="os-button os-button--primary" href={operationsApi.artifactDownloadUrl(item.id)} download>Download verified content</a></div>
      <p className="os-muted">The server will re-check mission scope, sensitivity, vault permission, file containment, byte size, and SHA-256 before returning an inert attachment.</p>
    </> : !item.delivery && <p className="os-muted">Artifact content remains metadata-only. Storage scheme <span className="os-mono">{item.storage.scheme}</span> has no approved canonical content-delivery adapter.</p>}
  </Card>;
}

function IntelligenceLayout({ list, detail }: { list: React.ReactNode; detail: React.ReactNode }) { return <div className="os-master-detail"><section>{list}</section><aside className="os-detail-panel">{detail}</aside></div>; }

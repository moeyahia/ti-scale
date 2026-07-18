import { type FormEvent, useState } from "react";
import { researchApi } from "../../data/api/research";
import { useQuery, useQueryCache } from "../../data/cache/QueryProvider";
import { Button, Card, EmptyState, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import type { ResearchCampaignRecord, ResearchLabSnapshot } from "../../domain/types/research";
import { formatTime, JsonDetails, KeyValueGrid } from "../runs/OperationalSurface";

export default function ResearchLabPage() {
  const query = useQuery("research-lab", (signal) => researchApi.snapshot(signal), { staleTime: 10_000 });
  const cache = useQueryCache();
  const [ownerAcknowledged, setOwnerAcknowledged] = useState(false);
  const [pendingId, setPendingId] = useState<string>();
  const [mutationError, setMutationError] = useState<Error>();
  const [message, setMessage] = useState<string>();
  const create = async (catalogId: ResearchLabSnapshot["catalog"][number]["id"]) => {
    setPendingId(catalogId); setMutationError(undefined); setMessage(undefined);
    try {
      await researchApi.createCampaign(catalogId, `research-create-${crypto.randomUUID()}`);
      setMessage("Draft campaign created. Execution remains blocked until its trusted charter, benchmark, lab, worker, and integrity signer are ready.");
      cache.invalidate("research-lab");
    } catch (error) { setMutationError(error instanceof Error ? error : new Error("Research campaign could not be created")); }
    finally { setPendingId(undefined); }
  };
  if (query.isLoading) return <LoadingPanel label="Loading bounded Research Lab state" />;
  if (query.error && !query.data) return <ErrorPanel title="Research Lab state is unavailable" error={query.error} onRetry={query.refresh} />;
  const data = query.data!;
  return <div className="os-research-lab">
    <section className="os-research-principle"><StatusPill status={data.readiness.status} /><div><strong>{data.readiness.status === "ready" ? "Local research harness ready" : "Research execution is safely blocked"}</strong><p>{data.governingPrinciple}</p></div></section>
    <div className="os-research-layout"><section><Card><div className="os-card-heading"><div><p className="os-eyebrow">Immutable local boundary</p><h2>Readiness gate</h2></div><StatusPill status={data.readiness.status} /></div><ul className="os-review-list">{data.readiness.checks.map((check) => <li key={check.id}><StatusPill status={check.status} /><span><strong>{check.label}</strong><small>{check.impact}</small>{check.remediation && check.status === "fail" && <small>{check.remediation}</small>}</span></li>)}</ul></Card>
      <div className="os-section-heading"><div><p className="os-eyebrow">First campaigns</p><h2>Safety and reliability tracks</h2></div></div>
      <label className="os-check-field os-research-owner"><input type="checkbox" checked={ownerAcknowledged} onChange={(event) => setOwnerAcknowledged(event.target.checked)} /><span><strong>I own this campaign and its promotion decisions</strong><small>Creating a draft does not approve a charter, start an experiment, or deploy a strategy.</small></span></label>
      {mutationError && <ErrorPanel title="Research campaign change was not recorded" error={mutationError} />}{message && <p role="status" className="os-success-note">{message}</p>}
      <div className="os-research-campaigns">{data.catalog.map((catalog) => {
        const existing = data.campaigns.filter(({ catalogId }) => catalogId === catalog.id);
        const active = existing.find(({ status }) => ["draft", "approved", "running", "paused"].includes(status));
        return <Card key={catalog.id}><div className="os-card-heading"><div><h3>{catalog.title}</h3><p>{catalog.purpose}</p></div>{active && <StatusPill status={active.status} />}</div><KeyValueGrid items={[{ label: "Primary metric", value: catalog.primaryMetric.replaceAll("_", " ") }, { label: "Mutable dimensions", value: catalog.mutablePaths.length }, { label: "Prior campaigns", value: existing.length }]} /><JsonDetails label="Allowed strategy paths" value={catalog.mutablePaths} />{active ? <CampaignControl campaign={active} onChanged={() => cache.invalidate("research-lab")} /> : <Button disabled={!ownerAcknowledged || Boolean(pendingId)} onClick={() => void create(catalog.id)}>{pendingId === catalog.id ? "Creating draft…" : "Create bounded draft"}</Button>}</Card>;
      })}</div>
      <div className="os-section-heading"><div><p className="os-eyebrow">Experiment history</p><h2>Measured candidates and near misses</h2></div></div>{data.experiments.length === 0 ? <Card><EmptyState title="No experiments have run" description="This is an honest empty state: no trusted benchmark run, metric, receipt, or performance claim exists yet." /></Card> : <div className="os-table-wrap"><table className="os-data-table"><thead><tr><th>Hypothesis</th><th>Dimension</th><th>Status</th><th>Updated</th></tr></thead><tbody>{data.experiments.map((experiment) => <tr key={experiment.id}><th scope="row">{experiment.hypothesis}<small>{experiment.candidateStrategyId}</small></th><td>{experiment.dimensionId}</td><td><StatusPill status={experiment.status} /></td><td>{formatTime(experiment.updatedAt)}</td></tr>)}</tbody></table></div>}</section>
      <aside><Card><p className="os-eyebrow">Public-provider trust boundary</p><h2>Proposal only</h2><ul className="os-policy-list"><li>Raw client evidence: prohibited</li><li>Direct experiment tools: prohibited</li><li>Authoritative scoring: local evaluator only</li><li>Automatic promotion: prohibited</li></ul></Card><Card><p className="os-eyebrow">Promotion path</p><ol className="os-promotion-path">{data.promotionPath.map((stage, index) => <li key={stage}><span>{index + 1}</span>{stage.replaceAll("_", " ")}</li>)}</ol></Card><Card><p className="os-eyebrow">Integrity records</p><KeyValueGrid items={[{ label: "Benchmark families", value: data.integrity.benchmarkFamilies }, { label: "Frozen snapshots", value: data.integrity.benchmarkSnapshots }, { label: "Approved charters", value: data.integrity.approvedCharters }, { label: "Signed receipts", value: data.integrity.integrityReceipts }, { label: "Exposure receipts", value: data.integrity.providerExposureReceipts }, { label: "Blocked exposures", value: data.integrity.blockedProviderExposures }]} /></Card></aside></div>
  </div>;
}

function CampaignControl({ campaign, onChanged }: { readonly campaign: ResearchCampaignRecord; readonly onChanged: () => void }) {
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<Error>();
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setPending(true); setError(undefined);
    try {
      await researchApi.stopCampaign(campaign.id, campaign.updatedAt, reason, `research-stop-${crypto.randomUUID()}`);
      onChanged();
    } catch (cause) { setError(cause instanceof Error ? cause : new Error("Campaign could not be stopped")); }
    finally { setPending(false); }
  };
  return <details className="os-advanced-section os-research-control"><summary>Campaign controls</summary><div className="os-details-content"><p>This draft cannot execute until every local readiness gate passes. Stopping preserves its audit history.</p><form onSubmit={submit}><label>Reason for stopping<textarea required minLength={3} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="The benchmark fixture requires revision before experiments begin." /></label>{error && <ErrorPanel title="Campaign was not stopped" error={error} />}<Button variant="danger" disabled={pending || reason.trim().length < 3}>{pending ? "Stopping…" : "Stop campaign"}</Button></form></div></details>;
}

import { AppLink } from "../../app/router/navigation";
import { operationsApi } from "../../data/api/operations";
import { useQuery } from "../../data/cache/QueryProvider";
import { Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { CursorControls, formatDuration, formatTime, JsonDetails, KeyValueGrid, QueryBoundary, SelectFilter, StreamState, useUrlFilters } from "../runs/OperationalSurface";

export default function AgentsPage({ agentId }: { agentId?: string }) {
  const filters = useUrlFilters({ limit: "25" });
  const listing = useQuery(`agents:${filters.key}`, (signal) => operationsApi.agents({ ...filters.values }, signal));
  const detail = useQuery(`agent:${agentId ?? "none"}`, (signal) => agentId ? operationsApi.agent(agentId, signal) : Promise.resolve(undefined), { staleTime: 5_000 });
  const assignments = useQuery(`agent-assignments:${agentId ?? "none"}`, (signal) => agentId ? operationsApi.assignments(agentId, { limit: 25 }, signal) : Promise.resolve(undefined), { staleTime: 5_000 });
  return <div className="os-page">
    <PageHeader eyebrow="Operational fleet" title="Agents" description="Actual specialist capability, assignment load, heartbeat, policy boundaries, and recent outcomes." actions={<StreamState />} />
    <div className="os-filter-bar"><SelectFilter filters={filters} name="status" label="Status" options={["available", "busy", "degraded", "offline", "quarantined"].map((value) => ({ value, label: value }))} /></div>
    <div className="os-master-detail">
      <section aria-label="Agent fleet">
        <QueryBoundary data={listing.data?.items} error={listing.error} isLoading={listing.isLoading} onRetry={listing.refresh} emptyTitle="No agents are registered" emptyDescription="Connect a real agent runtime before assignments can be routed.">
          {(agents) => <><div className="os-table-wrap"><table className="os-data-table"><thead><tr><th>Agent</th><th>Status</th><th>Queue</th><th>Success</th><th>Heartbeat</th></tr></thead><tbody>{agents.map((agent) => <tr key={agent.id} className={agent.id === agentId ? "is-selected" : undefined}><th scope="row"><AppLink href={`/agents/${encodeURIComponent(agent.id)}`} aria-label={`Open agent ${agent.displayName} (${agent.id})`}>{agent.displayName}</AppLink><small>{agent.role}</small></th><td><StatusPill status={agent.status} /></td><td>{agent.assignmentHealth.queueDepth}</td><td>{agent.assignmentHealth.successRate === null ? "—" : `${Math.round(agent.assignmentHealth.successRate * 100)}%`}</td><td>{formatTime(agent.lastHeartbeatAt)}</td></tr>)}</tbody></table></div><CursorControls context="agents" cursor={filters.values.cursor} nextCursor={listing.data?.nextCursor ?? null} onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })} /></>}
        </QueryBoundary>
      </section>
      <aside className="os-detail-panel" aria-label="Selected agent detail">
        {!agentId && <Card><p className="os-muted">Select an agent to inspect capabilities, policies, assignments, and health.</p></Card>}
        {agentId && detail.isLoading && <LoadingPanel label="Loading agent profile" />}
        {agentId && detail.error && !detail.data && <ErrorPanel error={detail.error} onRetry={detail.refresh} />}
        {detail.data && <Card><div className="os-card-heading"><div><p className="os-eyebrow">{detail.data.role}</p><h2>{detail.data.displayName}</h2></div><StatusPill status={detail.data.status} /></div>
          <KeyValueGrid items={[{ label: "Queue depth", value: detail.data.assignmentHealth.queueDepth }, { label: "Active work", value: detail.data.assignmentHealth.active }, { label: "Mean completion", value: formatDuration(detail.data.assignmentHealth.meanCompletionSeconds) }, { label: "Version", value: detail.data.version }]} />
          <h3>Capabilities</h3>{detail.data.capabilities?.length ? <ul className="os-compact-list">{detail.data.capabilities.map((capability) => <li key={`${capability.source}:${capability.name}`}><span>{capability.name}</span><StatusPill status={capability.enabled ? "enabled" : "disabled"} /></li>)}</ul> : <p className="os-muted">No capabilities reported.</p>}
          <JsonDetails label="Provider and tool policy" value={{ providerPolicy: detail.data.providerPolicy, toolPolicy: detail.data.toolPolicy, configuration: detail.data.configuration }} />
        </Card>}
        {assignments.data?.items.length ? <Card><h3>Recent assignments</h3><ol className="os-timeline">{assignments.data.items.map((assignment) => <li key={assignment.id}><div><strong>{assignment.step?.title ?? assignment.mission.name}</strong><span>{assignment.step?.phase ?? assignment.run.journey}</span></div><StatusPill status={assignment.status} /><small>{formatTime(assignment.updatedAt)}{assignment.lease.expired ? " · lease expired" : ""}</small></li>)}</ol></Card> : null}
      </aside>
    </div>
  </div>;
}

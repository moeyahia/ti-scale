import { AppLink } from "../../app/router/navigation";
import { operationsApi } from "../../data/api/operations";
import { useQuery } from "../../data/cache/QueryProvider";
import { Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import type { AgentRecord } from "../../domain/types/operations";
import { CursorControls, formatDuration, formatTime, JsonDetails, KeyValueGrid, QueryBoundary, SelectFilter, StreamState, useUrlFilters } from "../runs/OperationalSurface";
import {
  productRosterDescription,
  productRosterReadinessSummary,
  productRosterSource,
  runtimeBindingSummaries,
} from "./agentRuntimeBindings";
import { ModelAssignmentEditor } from "./ModelAssignmentEditor";

function RuntimeBindingSummary({ agent }: { readonly agent: AgentRecord }) {
  const bindings = runtimeBindingSummaries(agent);
  return bindings.length > 0
    ? <span data-runtime-binding-source="current-executable-runtime-manifest">
        <strong>{bindings.length} executable runtime binding{bindings.length === 1 ? "" : "s"}</strong>
        <small>{bindings.map(({ id }) => id).join(", ")}</small>
      </span>
    : <span data-runtime-binding-source="none">
        <strong>No executable runtime binding</strong>
        <small>This role cannot execute until the runtime publishes a compatible binding.</small>
      </span>;
}

function CanonicalRosterSummary({
  agents,
}: {
  readonly agents: readonly AgentRecord[];
}) {
  const summary = productRosterReadinessSummary(agents);
  return <section
    className="os-metric-row"
    aria-label="Canonical specialist roster status"
    data-product-roster-version={agents[0]
      ? productRosterSource(agents[0])
      : "unavailable"}
  >
    <div>
      <span>Canonical specialist roles</span>
      <strong>{summary.canonicalRoleCount}</strong>
      <small>Stable operator-facing identities</small>
    </div>
    <div>
      <span>Roles with execution</span>
      <strong>{summary.runtimeBoundRoleCount}</strong>
      <small>At least one current executable binding</small>
    </div>
    <div>
      <span>Roles awaiting runtime</span>
      <strong>{summary.runtimeUnboundRoleCount}</strong>
      <small>Settings visible; unavailable paths stay disabled</small>
    </div>
    <div>
      <span>Runtime adapters</span>
      <strong>{summary.executableRuntimeBindingCount}</strong>
      <small>Internal adapters remain separate from agents</small>
    </div>
  </section>;
}

export default function AgentsPage({ agentId }: { agentId?: string }) {
  const filters = useUrlFilters({ limit: "25" });
  const canonicalRoster = useQuery(
    "agents:canonical-product-roster",
    (signal) => operationsApi.agents({ limit: 100 }, signal),
    { staleTime: 5_000 },
  );
  const listing = useQuery(`agents:${filters.key}`, (signal) => operationsApi.agents({ ...filters.values }, signal));
  const detail = useQuery(`agent:${agentId ?? "none"}`, (signal) => agentId ? operationsApi.agent(agentId, signal) : Promise.resolve(undefined), { staleTime: 5_000 });
  const assignments = useQuery(`agent-assignments:${agentId ?? "none"}`, (signal) => agentId ? operationsApi.assignments(agentId, { limit: 25 }, signal) : Promise.resolve(undefined), { staleTime: 5_000 });
  return <div className="os-page">
    <PageHeader eyebrow="Operational fleet" title="Agents" description="Stable specialist roles mapped to the exact current runtime bindings, model catalog, assignment load, heartbeat, and policy boundaries." actions={<StreamState />} />
    {canonicalRoster.data && <CanonicalRosterSummary agents={canonicalRoster.data.items} />}
    {canonicalRoster.error && <p className="os-state-remediation" role="status">The canonical roster summary could not refresh. The filtered fleet below remains available from its independent query.</p>}
    <div className="os-filter-bar"><SelectFilter filters={filters} name="status" label="Status" options={["available", "busy", "degraded", "offline", "quarantined"].map((value) => ({ value, label: value }))} /></div>
    <div className="os-master-detail">
      <section aria-label="Agent fleet">
        <QueryBoundary data={listing.data?.items} error={listing.error} isLoading={listing.isLoading} onRetry={listing.refresh} emptyTitle="No agents are registered" emptyDescription="Connect a real agent runtime before assignments can be routed.">
          {(agents) => <><div className="os-table-wrap"><table className="os-data-table"><thead><tr><th>Agent</th><th>Runtime truth</th><th>Status</th><th>LLM assignment</th><th>Queue</th><th>Success</th><th>Heartbeat</th></tr></thead><tbody>{agents.map((agent) => <tr key={agent.id} className={agent.id === agentId ? "is-selected" : undefined}><th scope="row"><AppLink href={`/agents/${encodeURIComponent(agent.id)}`} aria-label={`Open agent ${agent.displayName} (${agent.id})`}>{agent.displayName}</AppLink><small>{agent.role}</small></th><td><RuntimeBindingSummary agent={agent} /></td><td><StatusPill status={agent.status} /></td><td><AppLink className="agent-model-entry" data-control-id="agents-model-configure" href={`/agents/${encodeURIComponent(agent.id)}#agent-model-configuration`} aria-label={`LLM settings for ${agent.displayName}`}><strong>LLM settings</strong><small>Provider · model · reasoning</small></AppLink></td><td>{agent.assignmentHealth.queueDepth}</td><td>{agent.assignmentHealth.successRate === null ? "—" : `${Math.round(agent.assignmentHealth.successRate * 100)}%`}</td><td>{formatTime(agent.lastHeartbeatAt)}</td></tr>)}</tbody></table></div><CursorControls context="agents" cursor={filters.values.cursor} nextCursor={listing.data?.nextCursor ?? null} onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })} /></>}
        </QueryBoundary>
      </section>
      <aside className="os-detail-panel" aria-label="Selected agent detail">
        {!agentId && <Card><p className="os-muted">Select a specialist to configure its provider, primary model, reasoning effort, fallback, capabilities, and health.</p></Card>}
        {agentId && detail.isLoading && <LoadingPanel label="Loading agent profile" />}
        {agentId && detail.error && !detail.data && <ErrorPanel error={detail.error} onRetry={detail.refresh} />}
        {detail.data && <ModelAssignmentEditor scope={{
          type: "agent",
          id: detail.data.id,
          agentId: detail.data.id,
          label: detail.data.displayName,
        }} />}
        {detail.data && <ModelAssignmentEditor
          purpose="planning"
          scope={{
            type: "agent",
            id: detail.data.id,
            agentId: detail.data.id,
            label: detail.data.displayName,
          }}
        />}
        {detail.data && <Card aria-label={`${detail.data.displayName} runtime bindings`}>
          <div className="os-card-heading"><div><p className="os-eyebrow">Runtime source of truth</p><h2>Execution bindings</h2></div><StatusPill status={runtimeBindingSummaries(detail.data).length > 0 ? "ready" : "unavailable"} /></div>
          <p>{productRosterDescription(detail.data) ?? "This specialist role is projected from current runtime manifests and capability attestations."}</p>
          <KeyValueGrid items={[
            { label: "Roster contract", value: productRosterSource(detail.data) },
            { label: "Executable bindings", value: runtimeBindingSummaries(detail.data).length },
            { label: "Last worker heartbeat", value: formatTime(detail.data.lastHeartbeatAt) },
          ]} />
          {runtimeBindingSummaries(detail.data).length > 0
            ? <ul className="os-compact-list" data-runtime-binding-source="current-executable-runtime-manifest">{runtimeBindingSummaries(detail.data).map((binding) => <li key={binding.id}><span><strong>{binding.id}</strong><small>{binding.version ? `Runtime version ${binding.version}` : "Runtime version was not published"}</small></span><StatusPill status="bound" /></li>)}</ul>
            : <p className="os-state-remediation">No current runtime manifest maps an executable adapter to this role. Model selection does not create an execution binding; connect or restore the relevant runtime capability first.</p>}
          <JsonDetails controlId="agents-runtime-bound-policies" label="Bound provider and tool policies" value={{ providerPolicy: detail.data.providerPolicy, toolPolicy: detail.data.toolPolicy }} />
        </Card>}
        {detail.data && <Card><div className="os-card-heading"><div><p className="os-eyebrow">{detail.data.role}</p><h2>{detail.data.displayName}</h2></div><StatusPill status={detail.data.status} /></div>
          <KeyValueGrid items={[{ label: "Queue depth", value: detail.data.assignmentHealth.queueDepth }, { label: "Active work", value: detail.data.assignmentHealth.active }, { label: "Mean completion", value: formatDuration(detail.data.assignmentHealth.meanCompletionSeconds) }, { label: "Version", value: detail.data.version }]} />
          <h3>Capabilities</h3>{detail.data.capabilities?.length ? <ul className="os-compact-list">{detail.data.capabilities.map((capability) => <li key={`${capability.source}:${capability.name}`}><span>{capability.name}</span><StatusPill status={capability.enabled ? "enabled" : "disabled"} /></li>)}</ul> : <p className="os-muted">No capabilities reported.</p>}
          <JsonDetails controlId="agents-provider-tool-policy" label="Provider and tool policy" value={{ providerPolicy: detail.data.providerPolicy, toolPolicy: detail.data.toolPolicy, configuration: detail.data.configuration }} />
        </Card>}
        {assignments.data?.items.length ? <Card><h3>Recent assignments</h3><ol className="os-timeline">{assignments.data.items.map((assignment) => <li key={assignment.id}><div><strong>{assignment.step?.title ?? assignment.mission.name}</strong><span>{assignment.step?.phase ?? assignment.run.journey}</span></div><StatusPill status={assignment.status} /><small>{formatTime(assignment.updatedAt)}{assignment.lease.expired ? " · lease expired" : ""}</small></li>)}</ol></Card> : null}
      </aside>
    </div>
  </div>;
}

import { operationsApi } from "../../data/api/operations";
import { fetchCapabilitySelfTests } from "../../data/api/capabilitySelfTests";
import { useQuery, type QueryResult } from "../../data/cache/QueryProvider";
import type { CapabilitySelfTestSnapshot } from "../../domain/types/capabilitySelfTests";
import { Button, Card, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { GlobalModelAssignmentEditor } from "../agents/ModelAssignmentEditor";
import { CursorControls, formatTime, JsonDetails, KeyValueGrid, QueryBoundary, SelectFilter, StreamState, SurfaceTabs, useUrlFilters } from "../runs/OperationalSurface";
import { OpenRouterConnectionPanel } from "./OpenRouterConnectionPanel";

type View = "connections" | "policies" | "settings";
export default function SystemPage({ view }: { view: View }) {
  return <div className="os-page"><PageHeader eyebrow="Runtime configuration" title="System" description="Redacted provider, MCP, policy, and health projections from canonical operational state." actions={<StreamState />} />
    <SurfaceTabs current={view} items={[{ id: "connections", label: "Connections", href: "/system/connections" }, { id: "policies", label: "Policies", href: "/system/policies" }, { id: "settings", label: "Settings status", href: "/system/settings" }]} />
    {view === "connections" && <Connections />}{view === "policies" && <Policies />}{view === "settings" && <SettingsStatus />}
  </div>;
}

function Connections() {
  const filters = useUrlFilters({ limit: "25" });
  const capabilities = useQuery("system-capability-self-tests", fetchCapabilitySelfTests, { staleTime: 5_000 });
  const providers = useQuery(`system-providers:${filters.values.providerCursor ?? "first"}`, (signal) => operationsApi.providers({ limit: 25, cursor: filters.values.providerCursor }, signal));
  const mcp = useQuery(`system-mcp:${filters.values.mcpCursor ?? "first"}:${filters.values.status ?? "all"}`, (signal) => operationsApi.mcp({ limit: 25, cursor: filters.values.mcpCursor, status: filters.values.status }, signal));
  return <div className="os-section-stack"><OpenRouterConnectionPanel /><CapabilityReadiness query={capabilities} /><section><h2>Providers</h2><p>Completed and failed provider turns appear here after a connection is active. Connection readiness is configured above.</p><QueryBoundary data={providers.data?.items} error={providers.error} isLoading={providers.isLoading} onRetry={providers.refresh} emptyTitle="No provider turns recorded" emptyDescription="No provider call has produced a durable turn record yet.">{(items) => <><div className="os-health-grid">{items.map((provider) => <article key={provider.id}><div><strong>{provider.provider}</strong><span>{provider.model ?? "Default model"}</span></div><StatusPill status={provider.status} /><KeyValueGrid items={[{ label: "Turns", value: provider.turnCount }, { label: "Failures", value: provider.failedCount }, { label: "Mean latency", value: provider.meanLatencyMs === null ? "—" : `${Math.round(provider.meanLatencyMs)} ms` }, { label: "Last turn", value: formatTime(provider.lastTurnAt) }]} /></article>)}</div><CursorControls cursor={filters.values.providerCursor} nextCursor={providers.data?.nextCursor ?? null} onChange={(cursor) => filters.set({ providerCursor: cursor }, { resetCursor: false, replace: false })} /></>}</QueryBoundary></section>
    <section><div className="os-section-heading"><h2>MCP servers</h2><div className="os-inline-filter"><SelectFilter filters={filters} name="status" label="Status" resetKeys={["mcpCursor"]} options={["unknown", "healthy", "degraded", "offline", "quarantined"].map((value) => ({ value, label: value }))} /></div></div><QueryBoundary data={mcp.data?.items} error={mcp.error} isLoading={mcp.isLoading} onRetry={mcp.refresh} emptyTitle="No MCP servers registered" emptyDescription="The registry has not returned any real MCP connection records.">{(items) => <><div className="os-table-wrap"><table className="os-data-table"><thead><tr><th>Server</th><th>Status</th><th>Transport</th><th>Endpoint</th><th>Checked</th></tr></thead><tbody>{items.map((server) => <tr key={server.id}><th scope="row">{server.name}<JsonDetails label="Capabilities and policy" value={{ capabilities: server.capabilities, policy: server.policy }} /></th><td><StatusPill status={server.status} /></td><td>{server.transport}</td><td className="os-mono">{server.endpointRedacted ?? "Hidden"}</td><td>{formatTime(server.lastCheckedAt)}</td></tr>)}</tbody></table></div><CursorControls cursor={filters.values.mcpCursor} nextCursor={mcp.data?.nextCursor ?? null} onChange={(cursor) => filters.set({ mcpCursor: cursor }, { resetCursor: false, replace: false })} /></>}</QueryBoundary></section></div>;
}

function CapabilityReadiness({ query }: {
  readonly query: QueryResult<CapabilitySelfTestSnapshot>;
}) {
  return <section aria-labelledby="system-capability-readiness-heading">
    <div className="os-section-heading">
      <div><p className="os-eyebrow">Target-free dependency truth</p><h2 id="system-capability-readiness-heading">Capability readiness</h2></div>
      <Button variant="secondary" disabled={query.isLoading || query.isRefreshing} onClick={query.refresh}>
        {query.isRefreshing ? "Refreshing readiness records" : "Refresh readiness records"}
      </Button>
    </div>
    <p>This reads bounded startup and local integrity attestations for every registered provider, MCP server, tool, and dependency. It never contacts a mission target and does not authorize execution.</p>
    <QueryBoundary
      data={query.data ? [...query.data.results] : undefined}
      error={query.error}
      isLoading={query.isLoading}
      onRetry={query.refresh}
      emptyTitle="No capability readiness records"
      emptyDescription="The runtime registry returned no attributable provider, MCP, tool, dependency, or local integrity result."
    >{(results) => <>
      <KeyValueGrid items={[
        { label: "Registered", value: `${query.data?.accounting.registered.providers ?? 0} providers · ${query.data?.accounting.registered.mcpServers ?? 0} MCP servers · ${query.data?.accounting.registered.tools ?? 0} tools · ${query.data?.accounting.registered.toolDependencies ?? 0} dependencies` },
        { label: "Reported", value: `${query.data?.accounting.reported.providers ?? 0} providers · ${query.data?.accounting.reported.mcpServers ?? 0} MCP servers · ${query.data?.accounting.reported.tools ?? 0} tools · ${query.data?.accounting.reported.toolDependencies ?? 0} dependencies` },
        { label: "Accounting", value: query.data?.accounting.complete ? "Complete" : "Incomplete — registry and result counts do not reconcile" },
        { label: "Outcome", value: `${query.data?.summary.pass ?? 0} passed · ${query.data?.summary.degraded ?? 0} degraded · ${query.data?.summary.fail ?? 0} failed` },
        { label: "Snapshot", value: formatTime(query.data?.checkedAt ?? null) },
        { label: "Execution authority", value: "Not granted by these checks" },
      ]} />
      <div className="os-table-wrap"><table className="os-data-table">
        <thead><tr><th>Component</th><th>Check</th><th>Status</th><th>Availability</th><th>Freshness</th><th>Meaning</th></tr></thead>
        <tbody>{results.map((result) => <tr key={result.id}>
          <th scope="row">{result.component.label}<small>{result.component.kind.replaceAll("_", " ")}</small></th>
          <td>{result.testKind.replaceAll("_", " ")}</td>
          <td><StatusPill status={result.status} /></td>
          <td>{result.availability}</td>
          <td>{result.freshness.state}<small>{formatTime(result.freshness.observedAt)}</small></td>
          <td><span>{result.explanation}</span>{result.remediation && <small><strong>Remediation:</strong> {result.remediation}</small>}<JsonDetails label="Read-only authorization detail" value={{ executionAuthorization: result.executionAuthorization, checkedAt: result.checkedAt, freshness: result.freshness }} /></td>
        </tr>)}</tbody>
      </table></div>
    </>}</QueryBoundary>
  </section>;
}

function Policies() {
  const filters = useUrlFilters({ limit: "25" }); const query = useQuery(`system-policies:${filters.key}`, (signal) => operationsApi.policies(filters.values, signal));
  return <QueryBoundary data={query.data?.items} error={query.error} isLoading={query.isLoading} onRetry={query.refresh} emptyTitle="No policy projections" emptyDescription="No authorization, runtime, agent, or MCP policy records are visible in this access scope.">{(items) => <><div className="os-policy-list">{items.map((policy) => <Card key={policy.id}><div className="os-card-heading"><div><p className="os-eyebrow">{policy.sourceType}</p><h2>{policy.label}</h2></div><StatusPill status={policy.sensitivity} /></div><time>{formatTime(policy.updatedAt)}</time><JsonDetails label="Redacted policy document" value={policy.policy} /></Card>)}</div><CursorControls cursor={filters.values.cursor} nextCursor={query.data?.nextCursor ?? null} onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })} /></>}</QueryBoundary>;
}

function SettingsStatus() {
  const filters = useUrlFilters({ limit: "50" }); const health = useQuery(`system-health:${filters.key}`, (signal) => operationsApi.systemHealth(filters.values, signal)); const policies = useQuery("system-settings-policies", (signal) => operationsApi.policies({ limit: 100 }, signal));
  return <>
    <GlobalModelAssignmentEditor />
    <Card className="os-callout"><h2>Versioned configuration boundaries</h2><p>Provider and model preferences are editable above. Authorization, action policy, disclosure controls, and active-run model receipts remain independently versioned and cannot be changed by a model preference.</p><div className="os-page-actions"><a className="os-button os-button--secondary" href="/api/v2/openapi.json" target="_blank" rel="noreferrer">Open API contract</a><a className="os-button os-button--quiet" href="/api/v2/contracts/events" target="_blank" rel="noreferrer">Open event contract</a></div></Card>
    <section aria-labelledby="system-health-heading">
      <h2 id="system-health-heading">System health</h2>
      <QueryBoundary data={health.data?.items} error={health.error} isLoading={health.isLoading} onRetry={health.refresh} emptyTitle="No system health data" emptyDescription="No canonical settings-health snapshots have been captured.">{(items) => <div className="os-health-grid">{items.map((item) => <article key={item.id}><div><strong>{item.componentId ?? "System"}</strong><span>{item.componentType ?? "component"}</span></div><StatusPill status={item.status} />{item.message && <p>{item.message}</p>}<time>{formatTime(item.capturedAt)}</time><JsonDetails label="Metrics" value={item.metrics} /></article>)}</div>}</QueryBoundary>
    </section>
    <section aria-labelledby="system-policy-inventory-heading">
      <h2 id="system-policy-inventory-heading">Policy projection inventory</h2>
      <QueryBoundary data={policies.data?.items} error={policies.error} isLoading={policies.isLoading} onRetry={policies.refresh} emptyTitle="No policy projections" emptyDescription="No canonical policy records are visible to this operator.">{(items) => <p className="os-muted">{items.length} policy projections are currently visible to this operator.</p>}</QueryBoundary>
    </section>
  </>;
}

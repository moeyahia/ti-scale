import { operationsApi, type QueryValue } from "../../data/api/operations";
import { useQuery } from "../../data/cache/QueryProvider";
import { Card, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import {
  CursorControls, FilterForm, formatTime, JsonDetails, QueryBoundary, SelectFilter,
  StreamState, SurfaceTabs, useUrlFilters,
} from "../runs/OperationalSurface";
import { TraceWaterfall } from "./TraceWaterfall";
import { operatorText } from "../../lib/operatorLanguage";

type View = "traces" | "events" | "logs" | "health";

export default function ObservabilityPage() {
  const filters = useUrlFilters({ view: "traces", limit: "50" });
  const view = (["traces", "events", "logs", "health"].includes(filters.values.view)
    ? filters.values.view
    : "traces") as View;
  return <div className="os-page">
    <PageHeader
      eyebrow="Correlated operational truth"
      title="Observability"
      description="Semantic traces and events first, with scope-checked redacted technical records available on demand."
      actions={<StreamState />}
    />
    <SurfaceTabs current={view} items={["traces", "events", "logs", "health"].map((id) => ({
      id,
      label: id[0].toUpperCase() + id.slice(1),
      onSelect: () => filters.set({ view: id, cursor: undefined, recordCursor: undefined }),
    }))} />
    {view === "traces" && <TracesView filters={filters} />}
    {view === "events" && <EventsView filters={filters} />}
    {view === "logs" && <LogsView filters={filters} />}
    {view === "health" && <HealthView filters={filters} />}
  </div>;
}

function traceListFilters(values: Readonly<Record<string, string>>): Record<string, QueryValue> {
  return {
    limit: values.limit,
    cursor: values.cursor,
    missionId: values.missionId,
    runId: values.runId,
    query: values.query,
    status: values.status,
    from: values.from,
    to: values.to,
  };
}

function TracesView({ filters }: { filters: ReturnType<typeof useUrlFilters> }) {
  const queryValues = traceListFilters(filters.values);
  const query = useQuery(
    `observability-traces:${JSON.stringify(queryValues)}`,
    (signal) => operationsApi.traces(queryValues, signal),
  );
  return <>
    <FilterForm filters={filters} searchLabel="Trace, event, action, tool, or message">
      <SelectFilter
        filters={filters}
        name="status"
        label="Trace state"
        options={["active", "completed", "failed"].map((value) => ({ value, label: value }))}
      />
    </FilterForm>
    <div className="os-trace-layout">
      <section aria-label="Trace results">
        <QueryBoundary
          data={query.data?.items}
          error={query.error}
          isLoading={query.isLoading}
          onRetry={query.refresh}
          emptyTitle="No correlated traces"
          emptyDescription="No trace-linked events, logs, actions, or tool calls match this authorization scope."
        >{(items) => <>
          <ol className="os-trace-list">{items.map((trace) => <li
            key={trace.traceId}
            className={filters.values.traceId === trace.traceId ? "is-selected" : undefined}
          >
            <button
              type="button"
              aria-label={`Inspect trace ${trace.summary} (${trace.traceId})`}
              onClick={() => filters.set(
                { traceId: trace.traceId, recordCursor: undefined },
                { resetCursor: false, replace: false },
              )}
            >
              <span><strong>{trace.summary}</strong><code>{trace.traceId}</code></span>
              <StatusPill status={trace.status} />
              <small>{trace.counts.events} events · {trace.counts.actions} actions · {trace.counts.toolCalls} tools · {trace.counts.errors} errors</small>
              <time dateTime={trace.endedAt}>{formatTime(trace.endedAt)}</time>
            </button>
          </li>)}</ol>
          <CursorControls
            context="traces"
            cursor={filters.values.cursor}
            nextCursor={query.data?.nextCursor ?? null}
            onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })}
          />
        </>}</QueryBoundary>
      </section>
      <aside className="os-trace-detail" aria-label="Selected trace detail">
        {filters.values.traceId
          ? <TraceDetailPanel traceId={filters.values.traceId} filters={filters} />
          : <Card><div className="os-empty"><strong>Select a trace</strong><p>Choose a correlated trace to inspect its real event, log, action, and tool-call waterfall.</p></div></Card>}
      </aside>
    </div>
  </>;
}

function TraceDetailPanel({ traceId, filters }: {
  traceId: string;
  filters: ReturnType<typeof useUrlFilters>;
}) {
  const query = useQuery(
    `observability-trace:${traceId}:${filters.values.recordCursor ?? ""}`,
    (signal) => operationsApi.trace(traceId, {
      limit: filters.values.limit,
      cursor: filters.values.recordCursor,
    }, signal),
  );
  if (query.isLoading) return <Card><div className="os-state-panel" role="status"><div><strong>Building the bounded trace waterfall</strong><p>Correlating visible canonical records without loading the full run.</p></div></div></Card>;
  if (query.error || !query.data) return <Card><div className="os-state-panel os-state-panel--error" role="alert"><div><strong>Trace detail is unavailable</strong><p>{query.error?.message ?? "No authorized trace records were returned."}</p><button type="button" className="os-text-button" onClick={query.refresh}>Try again</button></div></div></Card>;
  const { trace, records } = query.data;
  return <Card>
    <header className="os-card-heading">
      <div><p className="os-eyebrow">Correlated trace</p><h2>{trace.summary}</h2></div>
      <StatusPill status={trace.status} />
    </header>
    <div className="os-trace-summary">
      <span><small>Trace ID</small><code>{trace.traceId}</code></span>
      <span><small>Journey</small>{trace.journey ?? "Mixed/system"}</span>
      <span><small>Mission scope</small>{trace.mission?.name ?? `${trace.missionCount} visible missions`}</span>
      <span><small>Duration</small>{trace.durationMs < 1_000 ? `${trace.durationMs}ms` : `${(trace.durationMs / 1_000).toFixed(1)}s`}</span>
    </div>
    <TraceWaterfall trace={trace} records={records.items} />
    <CursorControls
      cursor={filters.values.recordCursor}
      nextCursor={records.nextCursor}
      onChange={(recordCursor) => filters.set({ recordCursor }, { resetCursor: false, replace: false })}
    />
  </Card>;
}

function EventsView({ filters }: { filters: ReturnType<typeof useUrlFilters> }) {
  const query = useQuery(`observability-events:${filters.key}`, (signal) => operationsApi.events(filters.values, signal));
  return <>
    <FilterForm filters={filters} searchKey="eventType" searchLabel="Event type">
      <SelectFilter filters={filters} name="journey" label="Journey" options={[{ value: "autonomous", label: "Autonomous" }, { value: "guided", label: "Guided" }]} />
    </FilterForm>
    <QueryBoundary data={query.data?.items} error={query.error} isLoading={query.isLoading} onRetry={query.refresh} emptyTitle="No operational events" emptyDescription="The append-only event stream has no records in this filter scope.">{(items) => <>
      <ol className="os-semantic-feed">{items.map((event) => <li key={event.id}><div className="os-feed-marker" aria-hidden="true" /><article><header><div><strong>{operatorText(event.summary, { kind: "event" })}</strong><span>{event.eventType}</span></div><time dateTime={event.occurredAt}>{formatTime(event.occurredAt)}</time></header><div className="os-feed-meta"><StatusPill status={event.journey ?? "system"} />{event.mission && <span>{event.mission.name}</span>}{event.actor.id && <span>{event.actor.type}: {event.actor.id}</span>}{event.correlation.traceId && <button type="button" onClick={() => filters.set({ view: "traces", traceId: event.correlation.traceId ?? undefined, cursor: undefined, recordCursor: undefined })}>Trace {event.correlation.traceId.slice(0, 12)}</button>}</div><JsonDetails label="Structured event payload and original wording" value={{ rawSummary: event.summary, payload: event.payload, correlation: event.correlation, redaction: event.redaction }} /></article></li>)}</ol>
      <CursorControls cursor={filters.values.cursor} nextCursor={query.data?.nextCursor ?? null} onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })} />
    </>}</QueryBoundary>
  </>;
}

function LogsView({ filters }: { filters: ReturnType<typeof useUrlFilters> }) {
  const query = useQuery(`observability-logs:${filters.key}`, (signal) => operationsApi.logs(filters.values, signal));
  return <>
    <FilterForm filters={filters}><SelectFilter filters={filters} name="severity" label="Severity" options={["trace", "debug", "info", "warn", "error", "fatal"].map((value) => ({ value, label: value }))} /></FilterForm>
    <QueryBoundary data={query.data?.items} error={query.error} isLoading={query.isLoading} onRetry={query.refresh} emptyTitle="No structured logs" emptyDescription="No redacted logs match the selected correlation and severity filters.">{(items) => <>
      <div className="os-table-wrap"><table className="os-data-table"><thead><tr><th>Message</th><th>Severity</th><th>Domain</th><th>Correlation</th><th>Time</th></tr></thead><tbody>{items.map((log) => <tr key={log.id}><th scope="row"><span>{log.message}</span><JsonDetails label="Attributes" value={log.attributes} /></th><td><StatusPill status={log.severity} /></td><td>{log.domain}</td><td>{log.correlation.traceId ? <button type="button" className="os-text-button" onClick={() => filters.set({ view: "traces", traceId: log.correlation.traceId ?? undefined, cursor: undefined, recordCursor: undefined })}>{log.correlation.traceId.slice(0, 12)}</button> : "—"}</td><td>{formatTime(log.occurredAt)}</td></tr>)}</tbody></table></div>
      <CursorControls cursor={filters.values.cursor} nextCursor={query.data?.nextCursor ?? null} onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })} />
    </>}</QueryBoundary>
  </>;
}

function HealthView({ filters }: { filters: ReturnType<typeof useUrlFilters> }) {
  const query = useQuery(`observability-health:${filters.key}`, (signal) => operationsApi.health(filters.values, signal));
  return <>
    <FilterForm filters={filters} searchKey="componentType" searchLabel="Component type"><SelectFilter filters={filters} name="status" label="Status" options={["healthy", "degraded", "unhealthy", "unknown"].map((value) => ({ value, label: value }))} /></FilterForm>
    <QueryBoundary data={query.data?.items} error={query.error} isLoading={query.isLoading} onRetry={query.refresh} emptyTitle="No health snapshots" emptyDescription="No component heartbeat has been captured in this scope.">{(items) => <>
      <div className="os-health-grid">{items.map((item) => <article key={item.id}><div><strong>{item.componentId ?? "System"}</strong><span>{item.componentType ?? "component"}</span></div><StatusPill status={item.status} />{item.message && <p>{item.message}</p>}<time dateTime={item.capturedAt}>{formatTime(item.capturedAt)}</time><JsonDetails label="Health metrics" value={item.metrics} /></article>)}</div>
      <CursorControls cursor={filters.values.cursor} nextCursor={query.data?.nextCursor ?? null} onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })} />
    </>}</QueryBoundary>
  </>;
}

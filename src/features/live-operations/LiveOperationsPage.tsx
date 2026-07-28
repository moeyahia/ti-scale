import { useEffect } from "react";
import { AppLink } from "../../app/router/navigation";
import { fetchJourneyRuns } from "../../data/api/runtimeV2";
import { useQuery } from "../../data/cache/QueryProvider";
import { useEventStream } from "../../data/events/EventStreamProvider";
import { ButtonLink, Card, EmptyState, PageHeader, ProgressBar, StatusPill } from "../../design-system/components/Primitives";
import { CursorControls, DegradedNotice, formatTime, percent, QueryBoundary, SelectFilter, StreamState, useUrlFilters } from "../runs/OperationalSurface";
import RunWorkspacePage from "../runs/RunWorkspacePage";
import { operatorText } from "../../lib/operatorLanguage";
import { runStatusLabel } from "../runs/runStatus";

export const LIVE_RUN_STATE_OPTIONS = [
  { value: "queued", label: "Queued" },
  { value: "planning", label: "Planning" },
  { value: "awaiting_contract_confirmation", label: "Awaiting contract confirmation" },
  { value: "running", label: "Executing" },
  { value: "blocked", label: "Safe-stopped" },
  { value: "recovering", label: "Recovering" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed safely" },
  { value: "cancelled", label: "Cancelled" },
] as const;

export default function LiveOperationsPage({ runId }: { runId?: string }) {
  if (runId) return <RunWorkspacePage runId={runId} />;
  return <LivePortfolio />;
}

function LivePortfolio() {
  const filters = useUrlFilters();
  const selectedStatus = LIVE_RUN_STATE_OPTIONS.find((option) => option.value === filters.values.status)?.value;
  const cursor = filters.values.cursor;
  const query = useQuery(
    `autonomous-runs:${selectedStatus ?? "operational"}:${cursor ?? "first"}`,
    (signal) => fetchJourneyRuns("autonomous", {
      ...(selectedStatus ? { status: selectedStatus } : {}),
      ...(!selectedStatus ? { view: "operational" as const } : {}),
      ...(cursor ? { cursor } : {}),
      limit: 50,
    }, signal),
    { staleTime: 0 },
  );
  const stream = useEventStream();
  useEffect(() => { if (stream.lastEvent?.journey === "autonomous") query.refresh(); }, [stream.lastEvent?.id]);
  const runs = query.data?.runs;
  return <div className="os-page"><PageHeader eyebrow="Autonomous observation" title="Live Operations" description="Durable Autonomous execution, recovery, heartbeat, ownership, and next action—without a chat dependency." actions={<><StreamState /><ButtonLink href="/missions/new/autonomous">Go Autonomous</ButtonLink></>} />
    <div className="os-filter-bar"><SelectFilter filters={filters} name="status" label="Run state" options={[...LIVE_RUN_STATE_OPTIONS]} /></div>
    {query.data?.failures.length ? <DegradedNotice>{query.data.failures.length} mission runtime projection{query.data.failures.length === 1 ? " is" : "s are"} temporarily unavailable. Available runs remain visible.</DegradedNotice> : null}
    <QueryBoundary data={runs} error={query.error} isLoading={query.isLoading} onRetry={query.refresh} emptyTitle="No Autonomous runs match" emptyDescription="Launch an authorized Autonomous mission or adjust the state filter.">{(items) => <div className="os-operation-list">{items.map((run) => <Card key={run.id}><div className="os-operation-main"><div><p className="os-eyebrow">{run.currentOwnerId ?? "Supervisor"}</p><h2 aria-label={run.missionName}><AppLink href={`/live/${encodeURIComponent(run.id)}`} aria-label={`Open Autonomous run ${run.missionName} (${run.id})`}>{run.missionName}</AppLink></h2><p>{run.objective}</p></div><StatusPill status={run.status}>{runStatusLabel(run)}</StatusPill></div>{run.statusReason && <p className="os-muted"><strong>Status detail:</strong> {operatorText(run.statusReason, { kind: "status", agent: run.currentOwnerId })}</p>}<div className="os-operation-metrics"><span><small>Phase/step</small>{run.currentStepId ?? "Planning"}</span><span><small>Progress</small>{percent(run.progress)}</span><span><small>Heartbeat</small>{formatTime(run.lastHeartbeatAt)}</span><span title={run.nextAction ?? undefined}><small>Next action</small>{operatorText(run.nextAction, { kind: "next_action", agent: run.currentOwnerId }, "Not reported")}</span></div><ProgressBar label={`${run.missionName} progress`} value={run.progress} /></Card>)}</div>}</QueryBoundary>
    {!query.isLoading && !query.error && (cursor || query.data?.nextCursor) && <CursorControls
      cursor={cursor}
      nextCursor={query.data?.nextCursor ?? null}
      context="Autonomous runs"
      onChange={(nextCursor) => filters.set({ cursor: nextCursor }, { resetCursor: false })}
    />}
    {!query.isLoading && !runs?.length && <Card className="os-callout"><EmptyState title="Ready for an end-to-end mission" description="The Autonomous contract gate validates authorization, dependencies, enforcement, and budgets before launch." action={<ButtonLink href="/missions/new/autonomous">Build mission contract</ButtonLink>} /></Card>}
  </div>;
}

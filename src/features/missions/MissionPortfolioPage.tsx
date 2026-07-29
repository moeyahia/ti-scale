import { type FormEvent, useEffect, useMemo, useState } from "react";
import {
  archiveMissions,
  deleteMissionView,
  exportMissionMetadata,
  fetchMissions,
  fetchSavedMissionViews,
  saveMissionView,
} from "../../data/api/commandOs";
import { useQuery } from "../../data/cache/QueryProvider";
import type {
  MissionBulkArchiveResult,
  MissionBulkExportResult,
  MissionSummary,
  SavedMissionView,
} from "../../domain/types/commandOs";
import { Button, ButtonLink, Card, EmptyState, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import { useModalFocus } from "../../design-system/hooks/useModalFocus";
import { AppLink } from "../../app/router/navigation";
import { CursorControls, FilterForm, SelectFilter, useUrlFilters } from "../runs/OperationalSurface";
import {
  missionBoardLane,
  missionPortfolioStateToUrl,
  parseMissionPortfolioState,
  type MissionPortfolioState,
} from "./missionPortfolioState";
import { operatorText } from "../../lib/operatorLanguage";

const STATUS_OPTIONS = [
  "queued", "planning", "awaiting_contract_confirmation", "running",
  "waiting_guided_decision", "blocked", "recovering", "completed", "failed", "cancelled",
];
const DECISION_OPTIONS = ["pending", "approved", "manual", "alternative", "rejected", "expired", "cancelled"];
const SEVERITY_OPTIONS = ["informational", "low", "medium", "high", "critical"];

function mutationKey(prefix: string): string {
  return `${prefix}-${globalThis.crypto.randomUUID()}`;
}

type SavedViewAttempt =
  | {
      readonly kind: "save";
      readonly expectedVersion: number;
      readonly idempotencyKey: string;
      readonly name: string;
      readonly state: MissionPortfolioState;
    }
  | {
      readonly kind: "delete";
      readonly expectedVersion: number;
      readonly idempotencyKey: string;
      readonly viewId: string;
      readonly viewName: string;
    };

interface SavedViewFailure {
  readonly attempt: SavedViewAttempt;
  readonly error: Error;
}

interface BulkAttempt {
  readonly mode: "archive" | "export";
  readonly idempotencyKey: string;
  readonly missions: MissionSummary[];
}

function samePortfolioState(left: MissionPortfolioState, right: MissionPortfolioState): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function missionHref(mission: MissionSummary): string {
  return mission.journey === "guided" ? `/guided/${mission.id}` : `/missions/${mission.id}`;
}

function dateTime(value: string | null): string {
  if (!value) return "Unknown";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? "Unknown"
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}

function durationBetween(start: string | null, end: string | null): string {
  if (!start) return "Unknown";
  const startMs = Date.parse(start);
  const endMs = end ? Date.parse(end) : Date.now();
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs < startMs) return "Unknown";
  const minutes = Math.floor((endMs - startMs) / 60_000);
  if (minutes < 1) return "<1m";
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}

function scopeSummary(mission: MissionSummary): string {
  if (mission.scope.allowedTargetCount === 0) return "No allowed targets recorded";
  const visible = mission.scope.allowedTargets.slice(0, 2);
  const remaining = mission.scope.allowedTargetCount - visible.length;
  return `${visible.join(", ")}${remaining > 0 ? ` +${remaining}` : ""}`;
}

function ownerSummary(mission: MissionSummary): string {
  if (mission.currentOwner) return mission.currentOwner.name ?? mission.currentOwner.id;
  return "Unassigned";
}

function teamSummary(mission: MissionSummary): string {
  if (mission.team.length === 0) return "No team recorded";
  return mission.team.map((member) => member.name ?? member.id).join(", ");
}

function budgetSummary(mission: MissionSummary): string {
  const pairs: Array<[string, string]> = [
    ["providerTokens", "tokens"],
    ["estimatedCost", "cost"],
    ["toolCalls", "tools"],
    ["wallClockMs", "time"],
  ];
  for (const [key, label] of pairs) {
    const limit = mission.budget.limits[key];
    const used = mission.budget.usage[key];
    if (limit !== undefined || used !== undefined) {
      if (key === "wallClockMs") {
        const format = (value: number | undefined) => value === undefined ? "?" : `${Math.round(value / 60_000)}m`;
        return `${format(used)} / ${format(limit)} ${label}`;
      }
      return `${used ?? "?"} / ${limit ?? "?"} ${label}`;
    }
  }
  return "Not reported";
}

function MissionCard({ mission, selected, onSelected }: {
  mission: MissionSummary;
  selected: boolean;
  onSelected: (selected: boolean) => void;
}) {
  return (
    <article className="mission-board-card">
      <div className="os-card-heading">
        <div><p className="os-eyebrow">{mission.journey}</p><h3 aria-label={mission.title}><AppLink href={missionHref(mission)} aria-label={`Open mission ${mission.title} (${mission.id})`}>{mission.title}</AppLink></h3></div>
        <StatusPill status={mission.status} />
      </div>
      <label className="mission-select"><input type="checkbox" aria-label={`Select mission ${mission.title} (${mission.id})`} checked={selected} onChange={(event) => onSelected(event.target.checked)} /><span>Select mission</span></label>
      <dl>
        <div><dt>Engagement / scope</dt><dd>{mission.engagementId ?? "No engagement"} · {scopeSummary(mission)}</dd></div>
        <div><dt>Active run</dt><dd>{mission.activeRunId ?? "No active run"}</dd></div>
        <div><dt>Phase / owner</dt><dd>{mission.currentPhase ?? "Unknown"} · {ownerSummary(mission)}</dd></div>
        <div><dt>Risk / evidence</dt><dd>{mission.risk ?? "Unknown"} · {mission.evidenceCount}</dd></div>
        <div><dt>Progress</dt><dd>{mission.progress === null ? "Not measured" : `${Math.round(mission.progress)}%`}</dd></div>
        <div><dt>Next</dt><dd title={mission.nextAction ?? undefined}>{operatorText(mission.nextAction, { kind: "next_action", agent: mission.currentOwner?.id }, "No next action reported")}</dd></div>
      </dl>
      <time dateTime={mission.updatedAt}>{dateTime(mission.updatedAt)}</time>
    </article>
  );
}

function MissionBoard({ missions, selected, onSelected }: {
  missions: MissionSummary[];
  selected: ReadonlySet<string>;
  onSelected: (missionId: string, selected: boolean) => void;
}) {
  const lanes = useMemo(() => ({
    attention: missions.filter((mission) => missionBoardLane(mission.status) === "attention"),
    active: missions.filter((mission) => missionBoardLane(mission.status) === "active"),
    finished: missions.filter((mission) => missionBoardLane(mission.status) === "finished"),
  }), [missions]);
  const labels = { attention: "Needs attention", active: "In progress", finished: "Finished" } as const;
  return (
    <div className="mission-board" aria-label="Mission board">
      {(Object.keys(lanes) as Array<keyof typeof lanes>).map((lane) => (
        <section key={lane} className="mission-board-lane" aria-labelledby={`mission-lane-${lane}`}>
          <header><h2 id={`mission-lane-${lane}`}>{labels[lane]}</h2><span>{lanes[lane].length}</span></header>
          {lanes[lane].length > 0
            ? lanes[lane].map((mission) => <MissionCard key={mission.id} mission={mission} selected={selected.has(mission.id)} onSelected={(checked) => onSelected(mission.id, checked)} />)
            : <p>No missions in this lane.</p>}
        </section>
      ))}
    </div>
  );
}

function BulkDialog({ mode, missions, pending, error, onCancel, onConfirm }: {
  mode: "archive" | "export";
  missions: MissionSummary[];
  pending: boolean;
  error?: Error;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const modalFocus = useModalFocus(true, onCancel, pending);
  useEffect(() => {
    if (!error || pending) return undefined;
    const frame = requestAnimationFrame(() => {
      modalFocus.dialogRef.current
        ?.querySelector<HTMLElement>("[data-bulk-confirm]")
        ?.focus();
    });
    return () => cancelAnimationFrame(frame);
  }, [error, modalFocus.dialogRef, pending]);
  return (
    <div className="mission-bulk-modal" role="presentation">
      <section ref={modalFocus.dialogRef} role="dialog" aria-modal="true" aria-labelledby="mission-bulk-title" aria-describedby="mission-bulk-description" className="mission-bulk-dialog" tabIndex={-1} onKeyDown={modalFocus.onDialogKeyDown}>
        <p className="os-eyebrow">Exact selection · {missions.length} mission{missions.length === 1 ? "" : "s"}</p>
        <h2 id="mission-bulk-title">Confirm {mode === "archive" ? "terminal mission archive" : "redacted metadata export"}</h2>
        <p id="mission-bulk-description">{mode === "archive"
          ? "Only durably terminal missions will archive. Active runs, actions, or assignments remain unchanged and will be reported as ineligible."
          : "The export includes bounded mission metadata, hashes, counts, and timestamps. Evidence blobs, objectives, target values, and confidential payloads are excluded."}</p>
        <ul>{missions.map((mission) => <li key={mission.id}><strong>{mission.title}</strong><code>{mission.id}</code><span>{mission.status}</span></li>)}</ul>
        {error && <ErrorPanel title={mode === "archive" ? "Mission archive did not complete" : "Mission metadata export did not complete"} error={error} />}
        <div className="mission-bulk-actions"><Button data-modal-initial-focus variant="secondary" disabled={pending} onClick={onCancel}>Cancel</Button><Button data-bulk-confirm variant={mode === "archive" ? "danger" : "primary"} disabled={pending} onClick={onConfirm}>{pending ? "Working…" : error ? `Retry ${mode}` : `Confirm ${mode}`}</Button></div>
      </section>
    </div>
  );
}

export default function MissionPortfolioPage() {
  const filters = useUrlFilters();
  const state = parseMissionPortfolioState(filters.values);
  const missions = useQuery(`ti-scale-missions:${filters.key}`, (signal) => fetchMissions({
    cursor: filters.values.cursor,
    limit: 50,
    ...(state.query ? { query: state.query } : {}),
    ...(state.journey ? { journey: state.journey } : {}),
    ...(state.status ? { status: state.status } : {}),
    ...(state.engagement ? { engagement: state.engagement } : {}),
    ...(state.target ? { target: state.target } : {}),
    ...(state.agent ? { agent: state.agent } : {}),
    ...(state.provider ? { provider: state.provider } : {}),
    ...(state.updatedFrom ? { updatedFrom: state.updatedFrom } : {}),
    ...(state.updatedTo ? { updatedTo: state.updatedTo } : {}),
    ...(state.risk ? { risk: state.risk } : {}),
    ...(state.evidence ? { evidence: state.evidence } : {}),
    ...(state.findingSeverity ? { findingSeverity: state.findingSeverity } : {}),
    ...(state.decisionState ? { decisionState: state.decisionState } : {}),
    ...(state.recoveryState ? { recoveryState: state.recoveryState } : {}),
  }, signal));
  const saved = useQuery("ti-scale-mission-saved-views", fetchSavedMissionViews, { staleTime: 5_000 });
  const [viewName, setViewName] = useState("");
  const [viewFailure, setViewFailure] = useState<SavedViewFailure>();
  const [viewPending, setViewPending] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkAttempt, setBulkAttempt] = useState<BulkAttempt>();
  const [bulkPending, setBulkPending] = useState(false);
  const [bulkError, setBulkError] = useState<Error>();
  const [bulkResult, setBulkResult] = useState<MissionBulkArchiveResult | MissionBulkExportResult>();

  useEffect(() => {
    const visible = new Set(missions.data?.items.map((mission) => mission.id) ?? []);
    setSelected((current) => new Set([...current].filter((missionId) => visible.has(missionId))));
  }, [missions.data]);

  const executeViewAttempt = async (attempt: SavedViewAttempt) => {
    setViewPending(true); setViewFailure(undefined);
    try {
      if (attempt.kind === "save") {
        await saveMissionView({
          expectedVersion: attempt.expectedVersion,
          name: attempt.name,
          state: attempt.state,
        }, attempt.idempotencyKey);
        setViewName((current) => current.trim() === attempt.name ? "" : current);
      } else {
        await deleteMissionView(
          attempt.viewId,
          attempt.expectedVersion,
          attempt.idempotencyKey,
        );
      }
      saved.refresh();
    } catch (cause) {
      setViewFailure({
        attempt,
        error: cause instanceof Error ? cause : new Error(
          attempt.kind === "save" ? "Saved view failed" : "Saved view deletion failed",
        ),
      });
    } finally {
      setViewPending(false);
    }
  };

  const saveView = async (event: FormEvent) => {
    event.preventDefault();
    const name = viewName.trim();
    if (!name || !saved.data) return;
    const failedAttempt = viewFailure?.attempt;
    const attempt = failedAttempt?.kind === "save"
      && failedAttempt.name === name
      && samePortfolioState(failedAttempt.state, state)
      ? failedAttempt
      : {
          kind: "save" as const,
          expectedVersion: saved.data.version,
          idempotencyKey: mutationKey("mission-view"),
          name,
          state,
        };
    await executeViewAttempt(attempt);
  };

  const removeView = async (view: SavedMissionView) => {
    if (!saved.data) return;
    const failedAttempt = viewFailure?.attempt;
    await executeViewAttempt(failedAttempt?.kind === "delete" && failedAttempt.viewId === view.id
      ? failedAttempt
      : {
          kind: "delete",
          expectedVersion: saved.data.version,
          idempotencyKey: mutationKey("mission-view-delete"),
          viewId: view.id,
          viewName: view.name,
        });
  };

  const applyView = (view: SavedMissionView) => filters.set({
    ...missionPortfolioStateToUrl(view.state),
    cursor: undefined,
  }, { replace: false });

  const setMissionSelected = (missionId: string, checked: boolean) => setSelected((current) => {
    const next = new Set(current);
    if (checked) next.add(missionId); else next.delete(missionId);
    return next;
  });

  const visibleMissions = missions.data?.items ?? [];
  const allVisibleSelected = visibleMissions.length > 0 && visibleMissions.every((mission) => selected.has(mission.id));
  const selectedMissions = visibleMissions.filter((mission) => selected.has(mission.id));

  const openBulk = (mode: "archive" | "export") => {
    if (selectedMissions.length === 0) return;
    setBulkError(undefined);
    setBulkResult(undefined);
    setBulkAttempt({
      mode,
      idempotencyKey: mutationKey(`mission-bulk-${mode}`),
      missions: selectedMissions,
    });
  };

  const confirmBulk = async () => {
    if (!bulkAttempt || bulkAttempt.missions.length === 0) return;
    setBulkPending(true); setBulkError(undefined); setBulkResult(undefined);
    try {
      const ids = bulkAttempt.missions.map((mission) => mission.id);
      if (bulkAttempt.mode === "archive") {
        const result = await archiveMissions(ids, bulkAttempt.idempotencyKey);
        setBulkResult(result);
        missions.refresh();
        setSelected(new Set());
      } else {
        const result = await exportMissionMetadata(ids, bulkAttempt.idempotencyKey);
        setBulkResult(result);
        const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `ti-scale-mission-metadata-${result.selectionHash.slice(0, 12)}.json`;
        link.click();
        URL.revokeObjectURL(url);
      }
      setBulkAttempt(undefined);
    } catch (cause) {
      setBulkError(cause instanceof Error ? cause : new Error("Bulk operation failed"));
    } finally {
      setBulkPending(false);
    }
  };

  return (
    <div className="os-page">
      <PageHeader
        eyebrow="Portfolio"
        title="Missions"
        description="Search durable objectives and inspect their current execution attempts. Filters query canonical mission state; provider details remain secondary."
        actions={<ButtonLink href="/missions/new">New mission</ButtonLink>}
      />

      <FilterForm filters={filters} searchLabel="Mission, phase, run, or next action">
        <SelectFilter filters={filters} name="journey" label="Journey" options={[{ value: "autonomous", label: "Autonomous" }, { value: "guided", label: "Guided" }]} />
        <SelectFilter filters={filters} name="status" label="Run state" options={STATUS_OPTIONS.map((status) => ({ value: status, label: status.replaceAll("_", " ") }))} />
        <label><span>Engagement</span><input value={state.engagement} onChange={(event) => filters.set({ engagement: event.target.value || undefined })} /></label>
        <label><span>Target</span><input value={state.target} onChange={(event) => filters.set({ target: event.target.value || undefined })} /></label>
        <label><span>View</span><TitaniumSelect value={state.view} onChange={(event) => filters.set({ view: event.target.value === "board" ? "board" : undefined })}><option value="table">Table</option><option value="board">Compact board</option></TitaniumSelect></label>
        <details className="mission-advanced-filters">
          <summary>More canonical filters</summary>
          <div>
            <label><span>Agent / owner ID</span><input value={state.agent} onChange={(event) => filters.set({ agent: event.target.value || undefined })} /></label>
            <label><span>Provider</span><input value={state.provider} onChange={(event) => filters.set({ provider: event.target.value || undefined })} /></label>
            <label><span>Updated from</span><input type="date" value={state.updatedFrom} onChange={(event) => filters.set({ updatedFrom: event.target.value || undefined })} /></label>
            <label><span>Updated to</span><input type="date" value={state.updatedTo} onChange={(event) => filters.set({ updatedTo: event.target.value || undefined })} /></label>
            <SelectFilter filters={filters} name="risk" label="Current risk" options={SEVERITY_OPTIONS.map((value) => ({ value, label: value }))} />
            <SelectFilter filters={filters} name="evidence" label="Evidence" options={[{ value: "present", label: "Has evidence" }, { value: "none", label: "No evidence" }]} />
            <SelectFilter filters={filters} name="findingSeverity" label="Finding severity" options={SEVERITY_OPTIONS.map((value) => ({ value, label: value }))} />
            <SelectFilter filters={filters} name="decisionState" label="Decision state" options={DECISION_OPTIONS.map((value) => ({ value, label: value }))} />
            <SelectFilter filters={filters} name="recoveryState" label="Recovery state" options={[{ value: "recovering", label: "Recovering" }, { value: "blocked", label: "Blocked" }, { value: "none", label: "No recovery state" }]} />
          </div>
        </details>
      </FilterForm>

      <section className="mission-saved-views" aria-labelledby="mission-saved-title">
        <div><strong id="mission-saved-title">Synchronized saved views</strong><span>Actor-scoped filter and layout settings are versioned on the Ti-Scale server. Mission and evidence content is never copied into a view.</span></div>
        <form onSubmit={(event) => void saveView(event)}><label><span className="os-visually-hidden">Saved view name</span><input maxLength={80} value={viewName} onChange={(event) => { setViewName(event.target.value); if (viewFailure?.attempt.kind === "save") setViewFailure(undefined); }} placeholder="Name current filters" /></label><Button type="submit" variant="secondary" disabled={!viewName.trim() || viewPending || !saved.data}>Save view</Button></form>
        {saved.isLoading && <span role="status">Loading saved views…</span>}
        {saved.data && saved.data.items.length > 0 && <ul>{saved.data.items.map((view) => <li key={view.id}><button type="button" onClick={() => applyView(view)}>{view.name}</button><button type="button" disabled={viewPending} aria-label={`Delete saved view ${view.name}`} onClick={() => void removeView(view)}>×</button></li>)}</ul>}
        {viewFailure && <div className="mission-saved-failure"><ErrorPanel title={viewFailure.attempt.kind === "save" ? "Saved view was not saved" : `Saved view ${viewFailure.attempt.viewName} was not deleted`} error={viewFailure.error} /></div>}
      </section>

      {missions.data && missions.data.items.length > 0 && (
        <section className="mission-bulk-toolbar" aria-label="Mission selection actions">
          <label><input type="checkbox" checked={allVisibleSelected} onChange={(event) => setSelected(event.target.checked ? new Set(visibleMissions.map((mission) => mission.id)) : new Set())} /><span>Select all {visibleMissions.length} visible missions</span></label>
          <strong>{selected.size} selected</strong>
          <Button variant="secondary" disabled={selected.size === 0} onClick={() => openBulk("export")}>Export redacted metadata</Button>
          <Button variant="danger" disabled={selected.size === 0} onClick={() => openBulk("archive")}>Archive terminal missions</Button>
        </section>
      )}
      {bulkResult && <div className="mission-bulk-result" role="status"><strong>Bulk operation recorded</strong><span>{bulkResult.outcomes.filter((outcome) => outcome.status === "archived" || outcome.status === "exported").length} succeeded; {bulkResult.outcomes.filter((outcome) => outcome.status === "ineligible" || outcome.status === "not_found").length} unchanged.</span><details><summary>Per-mission outcomes</summary><ul>{bulkResult.outcomes.map((outcome) => <li key={outcome.missionId}><code>{outcome.missionId}</code> · {outcome.status} · {outcome.reason}</li>)}</ul></details></div>}

      {missions.isLoading && <LoadingPanel label="Loading mission portfolio" />}
      {missions.error && !missions.data && <ErrorPanel error={missions.error} onRetry={missions.refresh} />}
      {missions.data && missions.data.items.length === 0 && (
        <Card><EmptyState title="No missions match this view" description="Change the filters or create a new Autonomous or Guided mission." action={<ButtonLink href="/missions/new">Create mission</ButtonLink>} /></Card>
      )}
      {missions.data && missions.data.items.length > 0 && state.view === "board" && <MissionBoard missions={missions.data.items} selected={selected} onSelected={setMissionSelected} />}
      {missions.data && missions.data.items.length > 0 && state.view === "table" && (
        <Card className="os-table-card mission-portfolio-table">
          <div className="os-table-scroll">
            <table>
              <caption className="os-visually-hidden">Filtered mission portfolio</caption>
              <thead><tr><th>Select</th><th>Mission / scope</th><th>Journey / state</th><th>Active run</th><th>Phase / owner / team</th><th>Risk / evidence</th><th>Last meaningful event</th><th>Elapsed / age</th><th>Budget</th><th>Next action</th></tr></thead>
              <tbody>{missions.data.items.map((mission) => (
                <tr key={mission.id}>
                  <td><label className="mission-row-select"><input type="checkbox" aria-label={`Select mission ${mission.title} (${mission.id})`} checked={selected.has(mission.id)} onChange={(event) => setMissionSelected(mission.id, event.target.checked)} /></label></td>
                  <th scope="row"><ButtonLink variant="quiet" href={missionHref(mission)} aria-label={`Open mission ${mission.title} (${mission.id})`}>{mission.title}</ButtonLink><span>{mission.engagementId ?? "No engagement"}</span><small>{scopeSummary(mission)}{mission.scope.prohibitedTargetCount > 0 ? ` · ${mission.scope.prohibitedTargetCount} prohibited` : ""}</small></th>
                  <td><StatusPill status={mission.journey} /><StatusPill status={mission.status} /><small>Authorization: {mission.authorizationStatus}</small></td>
                  <td>{mission.activeRunId ? <code>{mission.activeRunId}</code> : <span>No active run</span>}{mission.runId && !mission.activeRunId && <small>Latest: {mission.runId}</small>}{mission.provider && <small>Provider: {mission.provider}</small>}</td>
                  <td><strong>{mission.currentPhase ?? "Unknown phase"}</strong><span>{ownerSummary(mission)}</span><small>{teamSummary(mission)}</small></td>
                  <td><span>Risk: {mission.risk ?? "Unknown"}</span><span>Evidence: {mission.evidenceCount}</span><small>Finding: {mission.highestFindingSeverity ?? "None"}</small>{mission.decisionState && <small>Decision: {mission.decisionState}</small>}</td>
                  <td>{mission.lastMeaningfulEvent ? <><strong title={mission.lastMeaningfulEvent.summary}>{operatorText(mission.lastMeaningfulEvent.summary, { kind: "event" })}</strong><time dateTime={mission.lastMeaningfulEvent.occurredAt}>{dateTime(mission.lastMeaningfulEvent.occurredAt)}</time></> : "No semantic event reported"}</td>
                  <td><span>Elapsed: {durationBetween(mission.runStartedAt, mission.runEndedAt)}</span><small>Age: {durationBetween(mission.createdAt, null)}</small><small>Updated: {dateTime(mission.updatedAt)}</small></td>
                  <td>{budgetSummary(mission)}</td>
                  <td title={mission.nextAction ?? undefined}>{operatorText(mission.nextAction, { kind: "next_action", agent: mission.currentOwner?.id }, "Not reported")}{mission.progress !== null && <small>{Math.round(mission.progress)}% complete</small>}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </Card>
      )}
      {missions.data && <CursorControls cursor={filters.values.cursor} nextCursor={missions.data.nextCursor} onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })} />}
      {bulkAttempt && <BulkDialog mode={bulkAttempt.mode} missions={bulkAttempt.missions} pending={bulkPending} error={bulkError} onCancel={() => { setBulkAttempt(undefined); setBulkError(undefined); }} onConfirm={() => void confirmBulk()} />}
    </div>
  );
}

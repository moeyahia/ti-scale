import { useEffect } from "react";
import { AppLink } from "../../app/router/navigation";
import { fetchRuntimeReadiness } from "../../data/api/runtimeReadiness";
import { fetchJourneyRuns, runtimeV2Api } from "../../data/api/runtimeV2";
import { useQuery } from "../../data/cache/QueryProvider";
import { useEventStream } from "../../data/events/EventStreamProvider";
import { ButtonLink, Card, EmptyState, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { DecisionCard } from "../decisions/DecisionsPage";
import { RunCockpit } from "../runs/RunWorkspacePage";
import { DegradedNotice, formatTime, JsonDetails, percent, QueryBoundary, SelectFilter, StreamState, useUrlFilters } from "../runs/OperationalSurface";
import { GuidedCommanderPanel } from "./GuidedCommanderPanel";
import { operatorText } from "../../lib/operatorLanguage";
import { guidedRuntimeCapabilities } from "../../domain/guidedRuntimeCapabilities";

const GUIDED_RUN_STATES = [
  "planning", "running", "waiting_guided_decision", "blocked", "recovering", "completed", "failed", "cancelled",
] as const;

export default function GuidedWorkspacePage({ missionId }: { missionId?: string }) { return missionId ? <GuidedMission missionId={missionId} /> : <GuidedPortfolio />; }

function GuidedPortfolio() {
  const filters = useUrlFilters();
  const selectedStatus = GUIDED_RUN_STATES.find((status) => status === filters.values.status);
  const query = useQuery(
    `guided-runs:${selectedStatus ?? "operational"}`,
    (signal) => fetchJourneyRuns("guided", selectedStatus ? { status: selectedStatus } : {}, signal),
    { staleTime: 0 },
  );
  const stream = useEventStream();
  useEffect(() => { if (stream.lastEvent?.journey === "guided") query.refresh(); }, [stream.lastEvent?.id]);
  const runs = query.data?.runs;
  return <div className="os-page"><PageHeader eyebrow="Collaborative mission control" title="Guided Workspace" description="Explain, recommend, choose, observe, interpret, record, and advance—one deliberate consequential step at a time." actions={<><StreamState /><ButtonLink href="/missions/new/guided">Start Guided Mission</ButtonLink></>} />
    <div className="os-filter-bar"><SelectFilter filters={filters} name="status" label="Checkpoint state" options={GUIDED_RUN_STATES.map((value) => ({ value, label: value }))} /></div>{query.data?.failures.length ? <DegradedNotice>{query.data.failures.length} Guided mission projection{query.data.failures.length === 1 ? " is" : "s are"} unavailable.</DegradedNotice> : null}
    <QueryBoundary data={runs} error={query.error} isLoading={query.isLoading} onRetry={query.refresh} emptyTitle="No Guided missions match" emptyDescription="Start a Guided mission or change the checkpoint filter.">{(items) => <div className="os-operation-list">{items.map((run) => <Card key={run.id}><div className="os-operation-main"><div><p className="os-eyebrow">{run.status === "waiting_guided_decision" ? "Waiting for your deliberate step" : run.currentOwnerId ?? "Commander"}</p><h2 aria-label={run.missionName}><AppLink href={`/guided/${encodeURIComponent(run.missionId)}`} aria-label={`Open Guided mission ${run.missionName} (${run.missionId})`}>{run.missionName}</AppLink></h2><p>{run.objective}</p></div><StatusPill status={run.status} /></div><div className="os-operation-metrics"><span><small>Progress</small>{percent(run.progress)}</span><span><small>Checkpoint</small>{run.currentStepId ?? "Planning"}</span><span><small>Last activity</small>{formatTime(run.updatedAt)}</span><span title={run.nextAction ?? undefined}><small>Next</small>{operatorText(run.nextAction, { kind: "next_action", agent: run.currentOwnerId }, "Awaiting plan")}</span></div></Card>)}</div>}</QueryBoundary>
  </div>;
}

function GuidedMission({ missionId }: { missionId: string }) {
  const mission = useQuery(`guided-mission:${missionId}`, (signal) => runtimeV2Api.mission(missionId, signal), { staleTime: 0 });
  const readiness = useQuery("runtime-readiness", fetchRuntimeReadiness, { staleTime: 5_000 });
  const run = mission.data?.runs.find((item) => !["completed", "failed", "cancelled"].includes(item.status)) ?? mission.data?.runs[0];
  const plans = useQuery(`guided-plans:${run?.id ?? "none"}`, (signal) => run ? runtimeV2Api.plans(run.id, signal) : Promise.resolve(undefined), { staleTime: 0 });
  const decisions = useQuery(`guided-current-decision:${run?.id ?? "none"}`, (signal) => run ? runtimeV2Api.decisions({ runId: run.id, status: "pending", limit: 10 }, signal) : Promise.resolve(undefined), { staleTime: 0 });
  const capabilities = guidedRuntimeCapabilities(readiness.data);
  if (mission.isLoading) return <div className="os-page"><LoadingPanel label="Loading Guided checkpoint" /></div>; if (mission.error && !mission.data) return <div className="os-page"><ErrorPanel error={mission.error} onRetry={mission.refresh} /></div>; if (!mission.data) return null;
  const currentPlan = plans.data?.items.find((plan) => plan.id === run?.currentPlanId) ?? plans.data?.items[0]; const currentStep = currentPlan?.steps.find((step) => step.id === run?.currentStepId) ?? currentPlan?.steps.find((step) => !["completed", "cancelled"].includes(step.status));
  return <div className="os-page os-guided-mission-page"><PageHeader eyebrow="Guided mission" title={mission.data.mission.name} description={mission.data.mission.objective} actions={<><StatusPill status={run?.status ?? "not_started"} /><StreamState /></>} />
    <section className="os-mission-banner"><div><span>Scope</span><strong>{mission.data.mission.allowedTargets.join(", ") || "Not reported"}</strong></div><div><span>Authorization</span><strong>{mission.data.mission.authorizationStatus}</strong></div><div><span>Current phase</span><strong>{currentStep?.phase ?? "Planning"}</strong></div><div><span>Checkpoint</span><strong>{run?.currentStepId ?? "Not started"}</strong></div></section>
    {plans.error && <DegradedNotice>The versioned plan could not be refreshed; the last validated checkpoint remains visible.</DegradedNotice>}
    {decisions.error && <DegradedNotice>The current exact-step decision could not be loaded.</DegradedNotice>}
    {run && <div className="os-guided-workspace-layout">
      <aside className="os-guided-step-rail" aria-label="Current Guided step">
        {currentStep ? <Card className="os-guided-step"><p className="os-eyebrow">Explain → recommend → choose</p><h2>{operatorText(currentStep.title, { kind: "plan", agent: currentStep.assignedAgentId, target: currentStep.action.target })}</h2><p>{operatorText(currentStep.explanation || currentStep.objective, { kind: "plan", agent: currentStep.assignedAgentId, target: currentStep.action.target })}</p><div className="os-guided-step-detail"><div><h3>Why this matters</h3><p>{operatorText(currentStep.rationale, { kind: "plan", agent: currentStep.assignedAgentId, target: currentStep.action.target }, "No rationale was returned by the versioned plan.")}</p></div><div><h3>Expected evidence</h3><ul>{currentStep.successCriteria.map((criterion) => <li key={criterion}>{operatorText(criterion, { kind: "plan" })}</li>)}</ul></div><div><h3>Risk and reversal</h3><p><StatusPill status={currentStep.riskClass || "unclassified"} /> {operatorText(currentStep.reversibility, { kind: "plan" }, "Not reported")}</p></div></div><JsonDetails label="Exact proposed procedure and original wording" value={{ action: currentStep.action, narrative: { title: currentStep.title, objective: currentStep.objective, explanation: currentStep.explanation, rationale: currentStep.rationale, reversibility: currentStep.reversibility } }} /></Card> : plans.isLoading
          ? <Card><LoadingPanel label="Loading the represented Guided step" /></Card>
          : <Card><EmptyState
              title="Planning has not produced a represented step"
              description={`${operatorText(run.statusReason, { kind: "status", agent: run.currentOwnerId }, "No planning result has been committed.")} Next expected transition: ${operatorText(run.nextAction, { kind: "next_action", agent: run.currentOwnerId }, "the runtime must publish an explained, decision-bound step")} No consequential action can run in this state.`}
            /></Card>}
      </aside>
      <section className="os-guided-conversation-column" aria-label="Guided Commander conversation"><GuidedCommanderPanel
        missionId={missionId}
        runId={run.id}
        capabilities={capabilities}
        availabilityPending={readiness.isLoading}
        onAdvanced={() => { mission.refresh(); plans.refresh(); decisions.refresh(); }}
      /></section>
      <aside className="os-guided-decision-rail" aria-label="Exact Guided decision">
        <div className="os-guided-rail-heading"><p className="os-eyebrow">Deliberate control</p><h2>Exact step decision</h2><p>Explanation never grants authority. Only the fingerprint-bound control below can execute or record this represented step.</p></div>
        {decisions.isLoading && <LoadingPanel label="Loading the exact Guided decision" />}
        {!decisions.isLoading && decisions.data?.items.length === 0 && <Card><EmptyState title="No decision is waiting" description={run.status === "planning" ? "The Commander is still forming the represented step." : "This checkpoint has no pending consequential action."} /></Card>}
        {decisions.data?.items.map((decision) => <DecisionCard
          key={decision.id}
          decision={decision}
          runtimeAvailable={capabilities.decisionMutations}
          toolExecutionAvailable={capabilities.toolDispatch}
          availabilityPending={readiness.isLoading}
          onChanged={() => { decisions.refresh(); mission.refresh(); plans.refresh(); }}
        />)}
      </aside>
    </div>}
    {!run && <Card><EmptyState title="No Guided run exists" description="The mission object exists, but the runtime has not attached a run." /></Card>}{run && <RunCockpit run={run} />}
  </div>;
}

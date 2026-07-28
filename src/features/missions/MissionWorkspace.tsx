import { lazy, Suspense, type ReactNode, useEffect, useMemo, useState } from "react";
import { AppLink } from "../../app/router/navigation";
import { fetchContextPacks, fetchMemoryNodes } from "../../data/api/brain";
import { operationsApi } from "../../data/api/operations";
import { fetchRuntimeReadiness } from "../../data/api/runtimeReadiness";
import { runtimeV2Api } from "../../data/api/runtimeV2";
import { useQuery } from "../../data/cache/QueryProvider";
import type { EventRecord } from "../../domain/types/operations";
import type { MissionRuntimeSnapshot, RunPlan, RuntimeRun } from "../../domain/types/runtimeV2";
import { Button, ButtonLink, Card, EmptyState, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { ContextPackPanel } from "../brain/ContextPackPanel";
import { ContextUsedDisclosure } from "../brain/ContextUsedDisclosure";
import { scopeLabel } from "../brain/BrainNav";
import { DecisionCard } from "../decisions/DecisionsPage";
import { GuidedCommanderPanel } from "../guided/GuidedCommanderPanel";
import { CompletionReview } from "../runs/CompletionReview";
import { ActionActivity } from "../runs/ActionActivity";
import { DegradedNotice, formatTime, JsonDetails, KeyValueGrid, percent, QueryBoundary, SurfaceTabs, useUrlFilters } from "../runs/OperationalSurface";
import { missionWorkspaceTabs, resolveMissionWorkspaceTab, type MissionWorkspaceTab } from "./missionWorkspaceModel";
import { AutonomousBranchPanel } from "./AutonomousBranchPanel";
import { ReconDigitalTwinSurface, RunMetricsSurface } from "../run-intelligence/RunIntelligenceSurface";
import OperationalTruthPanel from "../intelligence/OperationalTruthPanel";
import { PlanChangePanel } from "./PlanChangePanel";
import { operatorText } from "../../lib/operatorLanguage";
import { guidedRuntimeCapabilities } from "../../domain/guidedRuntimeCapabilities";

const TERMINAL = new Set(["completed", "failed", "cancelled"]);
const ArtifactIntelligenceSurface = lazy(() => import("../run-intelligence/ArtifactIntelligenceSurface"));

export function MissionWorkspace({ snapshot, run, liveContent }: {
  snapshot: MissionRuntimeSnapshot;
  run?: RuntimeRun;
  liveContent?: ReactNode;
}) {
  const filters = useUrlFilters();
  const requestedTab = filters.values.tab;
  const activeTab = resolveMissionWorkspaceTab(requestedTab, snapshot.mission.journey);
  const tabs = missionWorkspaceTabs(snapshot.mission.journey);

  useEffect(() => {
    if (!requestedTab || requestedTab === activeTab) return;
    filters.set({ tab: activeTab === "summary" ? undefined : activeTab }, { resetCursor: false, replace: true });
  }, [activeTab, requestedTab]);

  return <section className="os-mission-workspace" aria-label="Mission workspace">
    <SurfaceTabs current={activeTab} items={tabs.map((tab) => ({
      ...tab,
      onSelect: () => filters.set({ tab: tab.id === "summary" ? undefined : tab.id }, { resetCursor: false, replace: false }),
    }))} />
    <div className="os-mission-tab-panel" data-mission-tab={activeTab}>
      <MissionTabContent activeTab={activeTab} snapshot={snapshot} run={run} liveContent={liveContent} />
    </div>
  </section>;
}

function MissionTabContent({ activeTab, snapshot, run, liveContent }: {
  activeTab: MissionWorkspaceTab;
  snapshot: MissionRuntimeSnapshot;
  run?: RuntimeRun;
  liveContent?: ReactNode;
}) {
  if (activeTab === "summary") return <MissionSummary snapshot={snapshot} run={run} />;
  if (activeTab === "plan") return <PlanPanel missionId={snapshot.mission.id} run={run} />;
  if (activeTab === "live") return <>{liveContent ?? <NoRunState />}</>;
  if (activeTab === "guide") return <GuidePanel missionId={snapshot.mission.id} run={run} />;
  if (activeTab === "evidence") return <MissionEvidencePanel missionId={snapshot.mission.id} runId={run?.id} />;
  if (activeTab === "findings") return <FindingsPanel missionId={snapshot.mission.id} />;
  if (activeTab === "conversation") return <ConversationPanel missionId={snapshot.mission.id} run={run} />;
  if (activeTab === "brain") return <BrainPanel missionId={snapshot.mission.id} run={run} />;
  if (activeTab === "learning") return <LearningPanel missionId={snapshot.mission.id} />;
  if (activeTab === "history") return <HistoryPanel missionId={snapshot.mission.id} />;
  return <SettingsPanel snapshot={snapshot} selectedRun={run} />;
}

function NoRunState() {
  return <Card><EmptyState title="No execution run exists" description="The mission is durable, but no run projection is currently attached." /></Card>;
}

function MissionSummary({ snapshot, run }: { snapshot: MissionRuntimeSnapshot; run?: RuntimeRun }) {
  const plans = useQuery(`run-plans:${run?.id ?? "none"}`, (signal) => run ? runtimeV2Api.plans(run.id, signal) : Promise.resolve(undefined), { staleTime: 0 });
  const events = useQuery(`observability-events:mission-summary:${snapshot.mission.id}`, (signal) => operationsApi.events({ missionId: snapshot.mission.id, limit: 8 }, signal), { staleTime: 0 });
  const evidence = useQuery(`evidence:mission-summary:${snapshot.mission.id}`, (signal) => operationsApi.evidence({ missionId: snapshot.mission.id, limit: 100 }, signal), { staleTime: 15_000 });
  const findings = useQuery(`findings:mission-summary:${snapshot.mission.id}`, (signal) => operationsApi.findings({ missionId: snapshot.mission.id, limit: 100 }, signal), { staleTime: 15_000 });
  const decisions = useQuery(`guided-decisions:mission-summary:${run?.id ?? "none"}`, (signal) => run && run.journey === "guided" ? runtimeV2Api.decisions({ runId: run.id, status: "pending", limit: 100 }, signal) : Promise.resolve(undefined), { staleTime: 0 });
  const actions = useQuery(`actions:mission-summary:${run?.id ?? "none"}`, (signal) => run ? operationsApi.actions({ runId: run.id, limit: 100 }, signal) : Promise.resolve(undefined), { staleTime: 0 });
  const activePlan = plans.data?.items.find((plan) => plan.id === run?.currentPlanId) ?? plans.data?.items[0];
  const currentStep = activePlan?.steps.find((step) => step.id === run?.currentStepId);
  const verifiedEvidence = evidence.data?.items.filter((item) => item.verificationState === "verified").length ?? 0;
  const verifiedFindings = findings.data?.items.filter((item) => item.reviewStatus === "verified").length ?? 0;
  const outstanding = decisions.data?.items.length ?? 0;
  const currentTarget = currentStep?.action.target ?? snapshot.mission.allowedTargets[0] ?? null;
  const currentTitleRaw = currentStep?.title ?? run?.nextAction;
  const currentDescriptionRaw = currentStep?.explanation || currentStep?.objective || run?.statusReason;

  return <div className="os-mission-summary">
    <Card className="os-scope-card"><div className="os-card-heading"><div><p className="os-eyebrow">Mission truth</p><h2>Objective and authorization scope</h2></div><StatusPill status={snapshot.mission.authorizationStatus} /></div>
      <p>{snapshot.mission.objective}</p>
      <KeyValueGrid items={[
        { label: "Engagement", value: snapshot.mission.engagementId ?? "Not assigned" },
        { label: "Allowed", value: snapshot.mission.allowedTargets.join(", ") || "None" },
        { label: "Prohibited", value: snapshot.mission.prohibitedTargets.join(", ") || "None" },
        { label: "Success criteria", value: snapshot.mission.successCriteria.join(" · ") || "None" },
      ]} />
    </Card>
    {!run && <NoRunState />}
    {run && <>
      <section className="os-metric-row" aria-label="Mission progress summary">
        <div><span>Current phase</span><strong>{currentStep?.phase ?? (run.status === "planning" ? "Planning" : "Not reported")}</strong></div>
        <div><span>Evidence verified</span><strong>{verifiedEvidence}/{evidence.data?.items.length ?? 0}</strong></div>
        <div><span>Findings verified</span><strong>{verifiedFindings}/{findings.data?.items.length ?? 0}</strong></div>
        <div><span>Outstanding decisions</span><strong>{outstanding}</strong></div>
        <div><span>Durable actions</span><strong>{actions.data?.items.length ?? 0}</strong></div>
      </section>
      <div className="os-mission-summary-grid">
        <Card><p className="os-eyebrow">Current work</p><h2>{operatorText(currentTitleRaw, { kind: "plan", agent: run.currentOwnerId, target: currentTarget }, "No active step reported")}</h2><p>{operatorText(currentDescriptionRaw, { kind: "plan", agent: run.currentOwnerId, target: currentTarget }, "The runtime has not reported a current-step explanation.")}</p><KeyValueGrid items={[{ label: "Owner", value: run.currentOwnerId ?? "Supervisor" }, { label: "Checkpoint", value: run.currentStepId ?? "Not started" }, { label: "Progress", value: percent(run.progress) }, { label: "Next action", value: operatorText(run.nextAction, { kind: "next_action", agent: run.currentOwnerId, target: currentTarget }, "Not reported") }]} /><JsonDetails label="Technical runtime wording" value={{ title: currentTitleRaw ?? null, description: currentDescriptionRaw ?? null, statusReason: run.statusReason, nextAction: run.nextAction }} /></Card>
        <Card><p className="os-eyebrow">Recent meaningful progress</p><QueryBoundary data={events.data?.items} error={events.error} isLoading={events.isLoading} onRetry={events.refresh} emptyTitle="No semantic events" emptyDescription="The mission has not emitted a durable state change yet.">{(items) => <EventList items={items.slice(0, 6)} />}</QueryBoundary></Card>
      </div>
      <RunMetricsSurface runId={run.id} />
      {TERMINAL.has(run.status) && <CompletionReview run={run} plan={activePlan} missionSuccessCriteria={snapshot.mission.successCriteria} />}
    </>}
    {[plans.error, evidence.error, findings.error, decisions.error, actions.error].some(Boolean) && <DegradedNotice>One or more summary projections could not refresh. Visible records remain the last validated canonical state.</DegradedNotice>}
  </div>;
}

function PlanPanel({ missionId, run }: { missionId: string; run?: RuntimeRun }) {
  const plans = useQuery(`run-plans:${run?.id ?? "none"}`, (signal) => run ? runtimeV2Api.plans(run.id, signal) : Promise.resolve(undefined), { staleTime: 0 });
  const contexts = useQuery(`brain-contexts:plan:${run?.id ?? "none"}`, (signal) => run ? fetchContextPacks({ runId: run.id, journey: run.journey, limit: 100 }, signal) : Promise.resolve(undefined), { staleTime: 0 });
  if (!run) return <NoRunState />;
  if (plans.isLoading) return <LoadingPanel label="Loading versioned mission plan" />;
  if (plans.error && !plans.data) return <ErrorPanel title="Plan history is unavailable" error={plans.error} onRetry={plans.refresh} />;
  const activePlan = plans.data?.items.find((plan) => plan.id === run.currentPlanId) ?? plans.data?.items[0];
  if (!activePlan) return <><ReconDigitalTwinSurface missionId={missionId} runId={run.id} currentStepId={run.currentStepId} /><Card><EmptyState title="No plan available" description="The runtime has not persisted a versioned plan for this run." /></Card><Suspense fallback={<LoadingPanel label="Loading script and page-capture intelligence" />}><ArtifactIntelligenceSurface missionId={missionId} runId={run.id} /></Suspense></>;
  const planningContexts = contexts.data?.items.filter((item) => /\bplan\b/iu.test(item.purpose)) ?? [];
  return <><ReconDigitalTwinSurface missionId={missionId} runId={run.id} currentStepId={run.currentStepId} />
    <PlanView plan={activePlan} currentStepId={run.currentStepId} />
    <PlanChangePanel
      run={run}
      plan={activePlan}
      plans={plans.data?.items ?? [activePlan]}
      planHistoryCurrent={Boolean(plans.data && !plans.error && !plans.isRefreshing)}
      onPlanApplied={plans.reconcile}
    />
    <Suspense fallback={<LoadingPanel label="Loading script and page-capture intelligence" />}>
      <ArtifactIntelligenceSurface missionId={missionId} runId={run.id} />
    </Suspense>
    <Card className="os-plan-context"><div className="os-card-heading"><div><p className="os-eyebrow">Memory transparency</p><h2>Context used to build this run’s plans</h2></div><StatusPill status={planningContexts.length ? "recorded" : "not_used"} /></div>
      {contexts.isLoading && <LoadingPanel label="Loading persisted planning context" />}
      {contexts.error && !contexts.data && <ErrorPanel title="Planning context is unavailable" error={contexts.error} onRetry={contexts.refresh} />}
      {planningContexts.length ? <ul className="os-compact-list">{planningContexts.map((context) => <li key={context.id}><span><strong>{context.purpose}</strong><small>{context.usedItemCount}/{context.retrievedItemCount} memories used · created by {context.createdBy} · {formatTime(context.createdAt)}</small></span><ContextUsedDisclosure packId={context.id} /></li>)}</ul> : !contexts.isLoading && <p className="os-muted">No persisted Context Pack influenced this plan. The interface does not imply memory use without a canonical record.</p>}
    </Card>
  </>;
}

function PlanView({ plan, currentStepId }: { plan: RunPlan; currentStepId: string | null }) {
  return <section aria-labelledby={`mission-plan-${plan.id}`}><Card className="os-plan-summary"><div className="os-card-heading"><div><p className="os-eyebrow">Plan v{plan.version}</p><h2 id={`mission-plan-${plan.id}`}>{operatorText(plan.strategySummary, { kind: "plan" })}</h2></div><StatusPill status={plan.status} /></div>{plan.rationaleSummary && <p>{operatorText(plan.rationaleSummary, { kind: "plan" })}</p>}<KeyValueGrid items={[{ label: "Created", value: formatTime(plan.createdAt) }, { label: "Activated", value: formatTime(plan.activatedAt) }, { label: "Steps", value: plan.steps.length }]} /><JsonDetails label="Technical plan wording" value={{ strategySummary: plan.strategySummary, rationaleSummary: plan.rationaleSummary }} /></Card>
    <ol className="os-step-rail">{plan.steps.map((step) => <li key={step.id} className={step.id === currentStepId ? "is-current" : undefined}><div className="os-step-index">{step.ordinal + 1}</div><article><header><div><span>{step.phase}</span><h3>{operatorText(step.title, { kind: "plan", agent: step.assignedAgentId, target: step.action.target })}</h3></div><StatusPill status={step.status} /></header><p>{operatorText(step.explanation || step.objective, { kind: "plan", agent: step.assignedAgentId, target: step.action.target })}</p><KeyValueGrid items={[{ label: "Owner", value: step.assignedAgentId || "Unassigned" }, { label: "Risk", value: step.riskClass || "Not classified" }, { label: "Target", value: step.action.target || "Not reported" }, { label: "Reversibility", value: operatorText(step.reversibility, { kind: "plan" }, "Not reported") }]} /><p className="os-intent"><strong>Intent:</strong> {operatorText(step.action.intentSummary, { kind: "action_intent", agent: step.assignedAgentId, target: step.action.target, destructive: step.action.destructive })}</p><JsonDetails label="Normalized action and original wording" value={{ action: step.action, narrative: { title: step.title, objective: step.objective, explanation: step.explanation, rationale: step.rationale, reversibility: step.reversibility } }} /></article></li>)}</ol>
  </section>;
}

function GuidePanel({ missionId, run }: { missionId: string; run?: RuntimeRun }) {
  const readiness = useQuery("runtime-readiness", fetchRuntimeReadiness, { staleTime: 5_000 });
  const plans = useQuery(`run-plans:${run?.id ?? "none"}`, (signal) => run ? runtimeV2Api.plans(run.id, signal) : Promise.resolve(undefined), { staleTime: 0 });
  const decisions = useQuery(`guided-decisions:mission-guide:${run?.id ?? "none"}`, (signal) => run ? runtimeV2Api.decisions({ runId: run.id, status: "pending", limit: 20 }, signal) : Promise.resolve(undefined), { staleTime: 0 });
  if (!run) return <NoRunState />;
  const capabilities = guidedRuntimeCapabilities(readiness.data);
  const activePlan = plans.data?.items.find((plan) => plan.id === run.currentPlanId) ?? plans.data?.items[0];
  const step = activePlan?.steps.find((item) => item.id === run.currentStepId) ?? activePlan?.steps.find((item) => !TERMINAL.has(item.status));
  return <>{capabilities.manualOnly && <p className="os-guided-inline-warning" role="status">Manual Guided runtime is active. Operator result review and exact reject, skip, or stop decisions are available. {capabilities.localCommanderGuidance ? "Local deterministic Commander explanations are available without provider, tool, target, or plan authority." : "Commander explanations are unavailable until their local capability is attested."} Provider semantic interpretation and agent tool execution remain unavailable.</p>}{capabilities.mode === "ready" && !capabilities.providerGuidance && <p className="os-guided-inline-warning" role="status">Reviewed local Guided execution is active. Exact tool dispatch follows its separate readiness receipt. {capabilities.localCommanderGuidance ? "Local deterministic Commander explanations are available without contacting a provider or granting execution authority." : "Local Commander guidance is not currently attested."} Provider-backed semantic interpretation remains unavailable.</p>}<div className="os-mission-guide-grid">
    <section>{plans.isLoading && <LoadingPanel label="Loading represented Guided step" />}{plans.error && !plans.data && <ErrorPanel error={plans.error} onRetry={plans.refresh} />}{step ? <Card className="os-guided-step"><p className="os-eyebrow">Explain → recommend → choose</p><h2>{operatorText(step.title, { kind: "plan", agent: step.assignedAgentId, target: step.action.target })}</h2><p>{operatorText(step.explanation || step.objective, { kind: "plan", agent: step.assignedAgentId, target: step.action.target })}</p><div className="os-guided-columns"><div><h3>Why this matters</h3><p>{operatorText(step.rationale, { kind: "plan", agent: step.assignedAgentId, target: step.action.target }, "No rationale was returned by the versioned plan.")}</p></div><div><h3>Expected evidence</h3>{step.successCriteria.length ? <ul>{step.successCriteria.map((criterion) => <li key={criterion}>{operatorText(criterion, { kind: "plan" })}</li>)}</ul> : <p>Not specified</p>}</div><div><h3>Risk and reversal</h3><p><StatusPill status={step.riskClass || "unclassified"} /> {operatorText(step.reversibility, { kind: "plan" }, "Not reported")}</p></div></div><JsonDetails label="Exact proposed procedure and original wording" value={{ action: step.action, narrative: { title: step.title, objective: step.objective, explanation: step.explanation, rationale: step.rationale, reversibility: step.reversibility } }} /></Card> : !plans.isLoading && <Card><EmptyState title="No represented Guided step" description="The runtime has not persisted a current deliberate step." /></Card>}</section>
    <aside><p className="os-eyebrow">Exact-step boundary</p><h2>Guided decision</h2><p>Only the fingerprint-bound decision below may execute or record this represented action.</p>{decisions.isLoading && <LoadingPanel label="Loading exact Guided decision" />}{decisions.error && !decisions.data && <ErrorPanel error={decisions.error} onRetry={decisions.refresh} />}{decisions.data?.items.map((decision) => <DecisionCard key={decision.id} decision={decision} runtimeAvailable={capabilities.decisionMutations} toolExecutionAvailable={capabilities.toolDispatch} availabilityPending={readiness.isLoading} onChanged={() => decisions.refresh()} />)}{decisions.data?.items.length === 0 && <Card><EmptyState title="No decision is waiting" description="This Guided checkpoint has no pending consequential action." /></Card>}<ButtonLink href={`/guided/${encodeURIComponent(missionId)}`} variant="secondary">Open focused Guided Workspace</ButtonLink></aside>
  </div><ActionActivity runId={run.id} title="Guided action record" /></>;
}

export function MissionEvidencePanel({ missionId, runId }: { missionId: string; runId?: string }) {
  return <div
    className="os-mission-evidence"
    data-mission-id={missionId}
    data-run-id={runId}
    data-evidence-scope={runId ? "selected-run" : "all-mission-runs"}
  >
    <OperationalTruthPanel missionId={missionId} runId={runId} />
  </div>;
}

function FindingsPanel({ missionId }: { missionId: string }) {
  const query = useQuery(`findings:mission:${missionId}`, (signal) => operationsApi.findings({ missionId, limit: 100 }, signal), { staleTime: 0 });
  return <QueryBoundary data={query.data?.items} error={query.error} isLoading={query.isLoading} onRetry={query.refresh} emptyTitle="No findings recorded" emptyDescription="The mission has not produced an evidence-linked conclusion.">{(items) => <div className="os-table-wrap"><table className="os-data-table"><thead><tr><th>Finding</th><th>Severity</th><th>Evidence</th><th>Review</th><th>Updated</th></tr></thead><tbody>{items.map((item) => <tr key={item.id}><th scope="row"><AppLink href={`/intelligence/findings/${encodeURIComponent(item.id)}`}>{item.title}</AppLink><small>{item.affectedScope}</small></th><td><StatusPill status={item.severity} /></td><td>{item.verifiedEvidenceCount}/{item.evidenceCount} verified</td><td><StatusPill status={item.reviewStatus} /></td><td>{formatTime(item.updatedAt)}</td></tr>)}</tbody></table></div>}</QueryBoundary>;
}

function ConversationPanel({ missionId, run }: { missionId: string; run?: RuntimeRun }) {
  const readiness = useQuery("runtime-readiness", fetchRuntimeReadiness, { staleTime: 5_000 });
  if (!run) return <NoRunState />;
  if (run.journey === "guided") return <GuidedCommanderPanel missionId={missionId} runId={run.id} capabilities={guidedRuntimeCapabilities(readiness.data)} availabilityPending={readiness.isLoading} />;
  return <AutonomousObserverHistory missionId={missionId} />;
}

function AutonomousObserverHistory({ missionId }: { missionId: string }) {
  const query = useQuery(`observability-events:mission-conversation:${missionId}`, (signal) => operationsApi.events({ missionId, journey: "autonomous", limit: 100 }, signal), { staleTime: 0 });
  return <Card><div className="os-card-heading"><div><p className="os-eyebrow">Autonomous observer layer</p><h2>Commander explanations and semantic activity</h2></div><StatusPill status="read_only">Read only</StatusPill></div><p>Autonomous execution does not depend on chat. This view presents its durable, operator-readable event history; technical payloads remain expandable.</p><QueryBoundary data={query.data?.items} error={query.error} isLoading={query.isLoading} onRetry={query.refresh} emptyTitle="No observer history" emptyDescription="The run has not emitted a semantic event yet.">{(items) => <EventList items={items} />}</QueryBoundary></Card>;
}

function BrainPanel({ missionId, run }: { missionId: string; run?: RuntimeRun }) {
  const nodes = useQuery(`brain-mission:${missionId}`, (signal) => fetchMemoryNodes({ missionId, limit: 100 }, signal), { staleTime: 0 });
  const events = useQuery(`observability-events:mission-memory:${missionId}`, (signal) => operationsApi.events({ missionId, limit: 100 }, signal), { staleTime: 0 });
  const contexts = useQuery(`brain-contexts:mission:${missionId}`, (signal) => fetchContextPacks({ missionId, limit: 200 }, signal), { staleTime: 0 });
  const contextPackIds = useMemo(() => [...new Set([
    ...(contexts.data?.items.map((item) => item.id) ?? []),
    ...(events.data?.items.map((event) => event.correlation.contextPackId).filter((id): id is string => Boolean(id)) ?? []),
  ])], [contexts.data?.items, events.data?.items]);
  const [selectedPack, setSelectedPack] = useState<string>();
  return <div className="os-mission-brain-grid"><section><div className="os-card-heading"><div><p className="os-eyebrow">Mission-isolated memory</p><h2>Second Brain nodes</h2></div><ButtonLink href={`/brain/graph?view=mission&mission=${encodeURIComponent(missionId)}`} variant="secondary">Open mission graph</ButtonLink></div><QueryBoundary data={nodes.data?.items} error={nodes.error} isLoading={nodes.isLoading} onRetry={nodes.refresh} emptyTitle="No mission memory nodes" emptyDescription="No confirmed or verified memory has been scoped to this mission yet.">{(items) => <ul className="os-compact-list">{items.map((node) => <li key={node.id}><span><AppLink href={`/brain/nodes/${encodeURIComponent(node.id)}`}>{node.title}</AppLink><small>{node.nodeType.replaceAll("_", " ")} · {scopeLabel(node.scope)} · {Math.round(node.confidence * 100)}% confidence</small></span><StatusPill status={node.lifecycleStatus} /></li>)}</ul>}</QueryBoundary></section><aside><Card><p className="os-eyebrow">Why the system knew something</p><h2>Context packs used</h2><p>These records come directly from the canonical Context Pack store, including planning packs that do not depend on an event correlation.</p>{contexts.isLoading && <LoadingPanel label="Loading mission Context Packs" />}{contexts.error && !contexts.data && <ErrorPanel title="Context Pack history is unavailable" error={contexts.error} onRetry={contexts.refresh} />}{contextPackIds.length ? <div className="os-context-pack-links">{contextPackIds.map((packId) => { const context = contexts.data?.items.find((item) => item.id === packId); return <Button key={packId} variant="quiet" onClick={() => setSelectedPack(selectedPack === packId ? undefined : packId)}>{selectedPack === packId ? "Hide context" : context?.purpose ?? packId}</Button>; })}</div> : !contexts.isLoading && <p className="os-muted">No Context Pack has been persisted for this mission.</p>}{selectedPack && <ContextPackPanel packId={selectedPack} />}{run && <p className="os-muted">Selected run: <span className="os-mono">{run.id}</span></p>}</Card></aside></div>;
}

function LearningPanel({ missionId }: { missionId: string }) {
  const evaluations = useQuery(`evaluations:mission:${missionId}`, (signal) => operationsApi.evaluations({ missionId, limit: 100 }, signal), { staleTime: 0 });
  const lessons = useQuery(`lessons:mission:${missionId}`, (signal) => operationsApi.lessons({ missionId, limit: 100 }, signal), { staleTime: 0 });
  const usage = useQuery(`lesson-usage:mission:${missionId}`, (signal) => operationsApi.lessonUsage({ missionId, limit: 100 }, signal), { staleTime: 0 });
  const loading = evaluations.isLoading || lessons.isLoading || usage.isLoading;
  const errors = [evaluations.error, lessons.error, usage.error].filter(Boolean);
  return <div className="os-mission-learning"><div className="os-card-heading"><div><p className="os-eyebrow">Evidence-gated improvement</p><h2>Mission learning record</h2></div><ButtonLink href="/learning" variant="secondary">Open Learning Lab</ButtonLink></div>{loading && <LoadingPanel label="Loading mission evaluations and lessons" />}{errors.length > 0 && <DegradedNotice>{errors.length} learning projection{errors.length === 1 ? " is" : "s are"} unavailable.</DegradedNotice>}<div className="os-mission-learning-grid"><Card><h3>Run evaluations</h3>{evaluations.data?.items.length ? evaluations.data.items.map((evaluation) => <article className="os-mission-record" key={evaluation.id}><div><strong>{evaluation.run.id}</strong><StatusPill status={evaluation.run.status} /></div><p>{evaluation.retrospective}</p><KeyValueGrid items={[{ label: "Evidence coverage", value: percent(evaluation.evidenceCoverage) }, { label: "Created", value: formatTime(evaluation.createdAt) }]} /><JsonDetails label="Scores and measurements" value={{ scores: evaluation.scores, metrics: evaluation.metrics }} /></article>) : <p className="os-muted">No terminal run evaluation is recorded.</p>}</Card><Card><h3>Candidate and verified lessons</h3>{lessons.data?.items.length ? <ul className="os-compact-list">{lessons.data.items.map((lesson) => <li key={lesson.id}><span><strong>{lesson.statement}</strong><small>{lesson.lessonType} · {lesson.supportingEvidenceCount}/{lesson.evidenceCount} supporting evidence</small></span><StatusPill status={lesson.status} /></li>)}</ul> : <p className="os-muted">No lesson was proposed from this mission.</p>}</Card><Card><h3>Verified lesson reuse</h3>{usage.data?.items.length ? <ul className="os-compact-list">{usage.data.items.map((item) => <li key={item.id}><span><strong>{item.lesson.statement}</strong><small>{item.influenceSummary}</small></span><StatusPill status="reused" /></li>)}</ul> : <p className="os-muted">No verified lesson usage was recorded.</p>}</Card></div></div>;
}

function HistoryPanel({ missionId }: { missionId: string }) {
  const query = useQuery(`observability-events:mission-history:${missionId}`, (signal) => operationsApi.events({ missionId, limit: 100 }, signal), { staleTime: 0 });
  return <><QueryBoundary data={query.data?.items} error={query.error} isLoading={query.isLoading} onRetry={query.refresh} emptyTitle="No mission history" emptyDescription="No append-only event has been recorded for this mission.">{(items) => <ol className="os-semantic-feed">{items.map((event) => <li key={event.id}><div className="os-feed-marker" /><article><header><div><strong>{operatorText(event.summary, { kind: "event" })}</strong><span>{event.eventType} · {event.actor.id ?? event.actor.type}</span></div><time>{formatTime(event.occurredAt)}</time></header><p className="os-feed-meta">Run {event.runId ?? "mission-level"} · sequence {event.sequence ?? "—"}</p>{event.correlation.contextPackId && <ContextUsedDisclosure packId={event.correlation.contextPackId} />}<JsonDetails label="Technical event detail" value={{ rawSummary: event.summary, payload: event.payload, correlation: event.correlation, redaction: event.redaction }} /></article></li>)}</ol>}</QueryBoundary><ActionActivity missionId={missionId} title="Action history" /></>;
}

function SettingsPanel({ snapshot, selectedRun }: { snapshot: MissionRuntimeSnapshot; selectedRun?: RuntimeRun }) {
  return <><div className="os-mission-settings-grid"><Card><p className="os-eyebrow">Authorization</p><h2>Mission settings</h2><p>These values are the current canonical mission contract projection. Changes require a versioned mission or contract amendment; this workspace does not silently mutate scope.</p><KeyValueGrid items={[{ label: "Journey", value: snapshot.mission.journey === "autonomous" ? "Autonomous" : "Guided" }, { label: "Authorization", value: snapshot.mission.authorizationStatus }, { label: "Engagement", value: snapshot.mission.engagementId ?? "Not assigned" }, { label: "Mission ID", value: <span className="os-mono">{snapshot.mission.id}</span> }]} /><JsonDetails label="Memory policy" value={snapshot.mission.memoryPolicy} /></Card><Card><p className="os-eyebrow">Scope boundaries</p><h2>Targets and criteria</h2><h3>Allowed targets</h3>{snapshot.mission.allowedTargets.length ? <ul>{snapshot.mission.allowedTargets.map((target) => <li key={target}>{target}</li>)}</ul> : <p className="os-muted">None recorded.</p>}<h3>Prohibited targets</h3>{snapshot.mission.prohibitedTargets.length ? <ul>{snapshot.mission.prohibitedTargets.map((target) => <li key={target}>{target}</li>)}</ul> : <p className="os-muted">None recorded.</p>}<h3>Success criteria</h3>{snapshot.mission.successCriteria.length ? <ul>{snapshot.mission.successCriteria.map((criterion) => <li key={criterion}>{criterion}</li>)}</ul> : <p className="os-muted">None recorded.</p>}</Card><Card><p className="os-eyebrow">Durable attempts</p><h2>Mission runs</h2>{snapshot.runs.length ? <ul className="os-compact-list">{snapshot.runs.map((run) => <li key={run.id}><span><AppLink href={`/missions/${encodeURIComponent(snapshot.mission.id)}/runs/${encodeURIComponent(run.id)}`}>{run.id}</AppLink><small>Updated {formatTime(run.updatedAt)} · {percent(run.progress)}</small></span><StatusPill status={run.id === selectedRun?.id ? "selected" : run.status}>{run.id === selectedRun?.id ? `Selected · ${run.status}` : run.status}</StatusPill></li>)}</ul> : <p className="os-muted">No execution attempts are attached.</p>}</Card></div>{snapshot.mission.journey === "autonomous" && selectedRun && <AutonomousBranchPanel missionId={snapshot.mission.id} selectedRun={selectedRun} />}</>;
}

function EventList({ items }: { items: readonly EventRecord[] }) {
  return <ol className="os-timeline">{items.map((event) => <li key={event.id}><strong>{operatorText(event.summary, { kind: "event" })}</strong><span>{event.eventType} · {formatTime(event.occurredAt)}</span>{event.correlation.contextPackId && <ContextUsedDisclosure packId={event.correlation.contextPackId} />}<JsonDetails label="Technical event detail" value={{ rawSummary: event.summary, payload: event.payload, correlation: event.correlation }} /></li>)}</ol>;
}

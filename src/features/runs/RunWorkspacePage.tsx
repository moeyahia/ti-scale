import { type FormEvent, useEffect, useState } from "react";
import { operationsApi } from "../../data/api/operations";
import { runtimeV2Api } from "../../data/api/runtimeV2";
import { useQuery } from "../../data/cache/QueryProvider";
import { useEventStream } from "../../data/events/EventStreamProvider";
import type { MissionRuntimeSnapshot, RuntimeRun } from "../../domain/types/runtimeV2";
import { Button, Card, EmptyState, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { DegradedNotice, formatTime, JsonDetails, KeyValueGrid, percent, QueryBoundary, StreamState, useActionState } from "./OperationalSurface";
import { CompletionReview } from "./CompletionReview";
import { RecoveryPanel } from "./RecoveryPanel";
import { MissionWorkspace } from "../missions/MissionWorkspace";
import { ContextUsedDisclosure } from "../brain/ContextUsedDisclosure";
import { ActionActivity } from "./ActionActivity";
import { ReconDigitalTwinSurface } from "../run-intelligence/RunIntelligenceSurface";
import { FailureDiagnosisPanel } from "./FailureDiagnosisPanel";
import { operatorText } from "../../lib/operatorLanguage";
import { runStatusLabel } from "./runStatus";
import { AutonomousActivationProofPanel } from "./AutonomousActivationProofPanel";
import type { AutonomousActivationReceiptSummary } from "../../domain/types/runtimeV2";

export default function RunWorkspacePage({ missionId, runId }: { missionId?: string; runId?: string; guided?: boolean }) {
  const mission = useQuery(`mission-runtime:${missionId ?? "none"}`, (signal) => missionId ? runtimeV2Api.mission(missionId, signal) : Promise.resolve(undefined), { staleTime: 0 });
  if (missionId) {
    if (mission.isLoading) return <div className="os-page"><LoadingPanel label="Loading durable mission state" /></div>;
    if (mission.error && !mission.data) return <div className="os-page"><ErrorPanel error={mission.error} onRetry={mission.refresh} /></div>;
    if (!mission.data) return <div className="os-page"><Card><EmptyState title="Mission runtime unavailable" description="The mission did not return a durable runtime projection." /></Card></div>;
    const selected = runId ? mission.data.runs.find((item) => item.id === runId) : mission.data.runs.find((item) => !["completed", "failed", "cancelled"].includes(item.status)) ?? mission.data.runs[0];
    return <MissionFrame
      snapshot={mission.data}
      run={selected}
      controlIdNamespace={runId ? "run-workspace" : "mission"}
    />;
  }
  return runId ? <RunOnlyFrame runId={runId} /> : <div className="os-page"><Card><EmptyState title="No run selected" description="Open a run from Live Operations or a mission workspace." /></Card></div>;
}

function MissionFrame({
  snapshot,
  run,
  controlIdNamespace,
}: {
  snapshot: MissionRuntimeSnapshot;
  run?: RuntimeRun;
  controlIdNamespace: "mission" | "run-workspace";
}) {
  return <div className="os-page"><PageHeader eyebrow={`${snapshot.mission.journey === "autonomous" ? "Autonomous" : "Guided"} mission`} title={snapshot.mission.name} description={snapshot.mission.objective} actions={<><StatusPill status={snapshot.mission.authorizationStatus} /><StreamState /></>} />
    <section className="os-mission-banner"><div><span>Journey</span><strong>{snapshot.mission.journey === "autonomous" ? "Autonomous" : "Guided"}</strong></div><div><span>Authorization</span><strong>{snapshot.mission.authorizationStatus}</strong></div><div><span>Allowed targets</span><strong>{snapshot.mission.allowedTargets.length}</strong></div><div><span>Runs</span><strong>{snapshot.runs.length}</strong></div></section>
    <MissionRuntimeWorkspace
      snapshot={snapshot}
      initialRun={run}
      controlIdNamespace={controlIdNamespace}
    />
  </div>;
}

function MissionRuntimeWorkspace({
  snapshot,
  initialRun,
  controlIdNamespace,
}: {
  snapshot: MissionRuntimeSnapshot;
  initialRun?: RuntimeRun;
  controlIdNamespace: "mission" | "run-workspace";
}) {
  const current = useQuery(`run:${initialRun?.id ?? "none"}`, (signal) => initialRun ? runtimeV2Api.run(initialRun.id, signal) : Promise.resolve(undefined), { staleTime: 0 });
  const stream = useEventStream();
  useEffect(() => { if (initialRun && stream.lastEvent?.runId === initialRun.id) current.refresh(); }, [stream.lastEvent?.id, initialRun?.id]);
  const run = current.data?.run ?? initialRun;
  const terminal = run ? ["completed", "failed", "cancelled"].includes(run.status) : false;
  return <>
    {run && <>
      <RunStatusBand run={run} />
      {current.error && <DegradedNotice>Run refresh failed; the last validated projection remains visible.</DegradedNotice>}
      {!terminal && !["blocked", "recovering"].includes(run.status) && <RunControls run={run} onChanged={current.refresh} />}
    </>}
    <MissionWorkspace
      snapshot={snapshot}
      run={run}
      controlIdNamespace={controlIdNamespace}
      liveContent={run ? <RunCockpit
      run={run}
      missionSuccessCriteria={snapshot.mission.successCriteria}
      showRunChrome={false}
      initialActivationReceipt={
        current.data?.currentAutonomousActivationReceipt
      }
    /> : undefined}
    />
  </>;
}

function RunOnlyFrame({ runId }: { runId: string }) {
  const snapshot = useQuery(`run:${runId}`, (signal) => runtimeV2Api.run(runId, signal), { staleTime: 0 });
  if (snapshot.isLoading) return <div className="os-page"><LoadingPanel label="Loading live run checkpoint" /></div>;
  if (snapshot.error && !snapshot.data) return <div className="os-page"><ErrorPanel error={snapshot.error} onRetry={snapshot.refresh} /></div>;
  if (!snapshot.data) return null;
  return <div className="os-page"><PageHeader eyebrow={`${snapshot.data.run.journey === "autonomous" ? "Autonomous" : "Guided"} run`} title={snapshot.data.run.missionName} description={snapshot.data.run.objective} actions={<StreamState />} /><RunCockpit
    run={snapshot.data.run}
    initialActivationReceipt={
      snapshot.data.currentAutonomousActivationReceipt
    }
  /></div>;
}

export function RunCockpit({
  run,
  missionSuccessCriteria = [],
  showRunChrome = true,
  initialActivationReceipt,
}: {
  run: RuntimeRun;
  missionSuccessCriteria?: readonly string[];
  showRunChrome?: boolean;
  initialActivationReceipt?: AutonomousActivationReceiptSummary | null;
}) {
  const current = useQuery(`run:${run.id}`, (signal) => runtimeV2Api.run(run.id, signal), { staleTime: 0 });
  const plans = useQuery(`run-plans:${run.id}`, (signal) => runtimeV2Api.plans(run.id, signal), { staleTime: 0 });
  const events = useQuery(`run-events:${run.id}`, (signal) => operationsApi.events({ runId: run.id, limit: 30 }, signal), { staleTime: 0 });
  const stream = useEventStream();
  useEffect(() => { if (stream.lastEvent?.runId === run.id) { current.refresh(); plans.refresh(); events.refresh(); } }, [stream.lastEvent?.id, run.id]);
  const authoritative = current.data?.run ?? run;
  const activationReceipt = current.data
    ? current.data.currentAutonomousActivationReceipt
    : initialActivationReceipt;
  const activePlan = plans.data?.items.find((plan) => plan.id === authoritative.currentPlanId) ?? plans.data?.items[0];
  const terminal = ["completed", "failed", "cancelled"].includes(authoritative.status);
  return <>{showRunChrome && <RunStatusBand run={authoritative} />}
    {current.error && <DegradedNotice>Run refresh failed; the last validated projection remains visible.</DegradedNotice>}
    {authoritative.journey === "autonomous" && <AutonomousActivationProofPanel
      runId={authoritative.id}
      current={activationReceipt}
      onRefresh={current.refresh}
    />}
    {showRunChrome && !terminal && !["blocked", "recovering"].includes(authoritative.status) && <RunControls run={authoritative} onChanged={() => { current.refresh(); events.refresh(); }} />}
    {terminal && <CompletionReview run={authoritative} plan={activePlan} missionSuccessCriteria={missionSuccessCriteria} />}
    {["blocked", "recovering", "failed"].includes(authoritative.status) &&
      <FailureDiagnosisPanel missionId={authoritative.missionId} runId={authoritative.id} onChanged={() => { current.refresh(); plans.refresh(); events.refresh(); }} />
    }
    {["blocked", "recovering", "failed", "waiting_guided_decision"].includes(authoritative.status) &&
      <RecoveryPanel runId={authoritative.id} onChanged={() => { current.refresh(); plans.refresh(); events.refresh(); }} />
    }
    <ReconDigitalTwinSurface missionId={authoritative.missionId} runId={authoritative.id} currentStepId={authoritative.currentStepId} surface="live" />
    <div className="os-live-layout"><section><h2>Plan and agent ownership</h2>{plans.isLoading && <LoadingPanel label="Loading versioned plan" />}{plans.error && !plans.data && <ErrorPanel error={plans.error} onRetry={plans.refresh} />}{activePlan ? <><Card className="os-plan-summary"><div className="os-card-heading"><div><p className="os-eyebrow">Plan v{activePlan.version}</p><h3>{operatorText(activePlan.strategySummary, { kind: "plan" })}</h3></div><StatusPill status={activePlan.status} /></div>{activePlan.rationaleSummary && <p>{operatorText(activePlan.rationaleSummary, { kind: "plan" })}</p>}<JsonDetails controlId="live-technical-plan-wording" label="Technical plan wording" value={{ strategySummary: activePlan.strategySummary, rationaleSummary: activePlan.rationaleSummary }} /></Card><ol className="os-step-rail">{activePlan.steps.map((step) => <li key={step.id} className={step.id === authoritative.currentStepId ? "is-current" : undefined}><div className="os-step-index">{step.ordinal + 1}</div><article><header><div><span>{step.phase}</span><h3>{operatorText(step.title, { kind: "plan", agent: step.assignedAgentId, target: step.action.target })}</h3></div><StatusPill status={step.status} /></header><p>{operatorText(step.explanation || step.objective, { kind: "plan", agent: step.assignedAgentId, target: step.action.target })}</p><KeyValueGrid items={[{ label: "Owner", value: step.assignedAgentId || "Unassigned" }, { label: "Risk", value: step.riskClass || "Not classified" }, { label: "Target", value: step.action.target }, { label: "Reversibility", value: operatorText(step.reversibility, { kind: "plan" }, "Not reported") }]} /><p className="os-intent"><strong>Intent:</strong> {operatorText(step.action.intentSummary, { kind: "action_intent", agent: step.assignedAgentId, target: step.action.target, destructive: step.action.destructive })}</p><JsonDetails controlId="live-normalized-action-wording" label="Normalized action and original wording" value={{ action: step.action, narrative: { title: step.title, objective: step.objective, explanation: step.explanation, rationale: step.rationale, reversibility: step.reversibility } }} /></article></li>)}</ol></> : !plans.isLoading && <Card><EmptyState title="No plan available" description="The run has not persisted a versioned plan yet." /></Card>}</section>
      <aside><h2>Meaningful activity</h2><QueryBoundary data={events.data?.items} error={events.error} isLoading={events.isLoading} onRetry={events.refresh} emptyTitle="No semantic events" emptyDescription="The run has not emitted an authorized state change yet.">{(items) => <ol className="os-timeline">{items.map((event) => <li key={event.id}><strong>{operatorText(event.summary, { kind: "event" })}</strong><span>{event.eventType} · {formatTime(event.occurredAt)}</span>{event.correlation.contextPackId && <ContextUsedDisclosure packId={event.correlation.contextPackId} />}<JsonDetails controlId="live-technical-event-detail" label="Technical event detail" value={{ rawSummary: event.summary, payload: event.payload, correlation: event.correlation }} /></li>)}</ol>}</QueryBoundary></aside>
    </div><ActionActivity runId={authoritative.id} />
  </>;
}

function RunStatusBand({ run }: { run: RuntimeRun }) {
  return <section className="os-run-band" aria-label="Selected run status"><div><span>Status</span><StatusPill status={run.status}>{runStatusLabel(run)}</StatusPill></div><div><span>Progress</span><strong>{percent(run.progress)}</strong></div><div><span>Owner</span><strong>{run.currentOwnerId ?? "Supervisor"}</strong></div><div><span>Heartbeat</span><strong>{formatTime(run.lastHeartbeatAt)}</strong></div><div><span>Next</span><strong title={run.nextAction ?? undefined}>{operatorText(run.nextAction, { kind: "next_action", agent: run.currentOwnerId }, "No next action reported")}</strong></div></section>;
}

function RunControls({ run, onChanged }: { run: RuntimeRun; onChanged: () => void }) {
  const [reason, setReason] = useState(""); const action = useActionState(); const terminal = ["completed", "failed", "cancelled"].includes(run.status);
  const command = (value: "pause" | "cancel", event: FormEvent) => { event.preventDefault(); void action.run(() => runtimeV2Api.controlRun(run.id, { command: value, reason }, `run-${crypto.randomUUID()}`).then(() => onChanged()), `Run ${value} recorded.`); };
  return <Card className="os-run-controls"><form onSubmit={(event) => command("pause", event)}><label><span>Operator reason (audited)</span><input required value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Why is this intervention necessary?" /></label><div><Button variant="secondary" disabled={terminal || action.pending || !reason.trim()}>Pause run</Button><Button type="button" variant="danger" disabled={terminal || action.pending || !reason.trim()} onClick={(event) => command("cancel", event as unknown as FormEvent)}>Cancel run</Button></div></form>{action.error && <ErrorPanel error={action.error} />}{action.message && <p role="status" className="os-success-note">{action.message}</p>}</Card>;
}

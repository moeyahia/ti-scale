import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { planChangesApi } from "../../data/api/planChanges";
import { useQuery } from "../../data/cache/QueryProvider";
import type {
  PlanChangeInflightResolution,
  PlanChangeInflightResolutionMode,
  PlanChangeOperation,
  PlanChangeRequest,
} from "../../domain/types/planChanges";
import type { RunPlan, RuntimeRun } from "../../domain/types/runtimeV2";
import { Button, Card, EmptyState, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import { formatTime, JsonDetails, KeyValueGrid } from "../runs/OperationalSurface";
import { DirectPlanEditor } from "./DirectPlanEditor";

export function PlanChangePanel({ run, plan, plans, planHistoryCurrent = true, onPlanApplied }: {
  readonly run: RuntimeRun;
  readonly plan: RunPlan;
  readonly plans: readonly RunPlan[];
  readonly planHistoryCurrent?: boolean;
  readonly onPlanApplied?: () => void | Promise<void>;
}) {
  const query = useQuery(`plan-changes:${run.id}`, (signal) => planChangesApi.list(run.id, signal), { staleTime: 0 });
  const [requestText, setRequestText] = useState("");
  const [strategySummary, setStrategySummary] = useState(plan.strategySummary);
  const [submitting, setSubmitting] = useState(false);
  const [mutationError, setMutationError] = useState<Error>();
  const [mutationOutcome, setMutationOutcome] = useState<string>();
  const [reconciliationError, setReconciliationError] = useState<Error>();
  const [directEdit, setDirectEdit] = useState<{ readonly request: PlanChangeRequest; readonly operationIndex: number }>();
  const [directEditOutcome, setDirectEditOutcome] = useState<string>();
  const [inflightOutcome, setInflightOutcome] = useState<{
    readonly sourceRequestId: string;
    readonly resolution: PlanChangeInflightResolution;
  }>();
  const directEditTrigger = useRef<HTMLButtonElement | null>(null);
  const directEditCandidate = query.data?.items.find((request) => request.id === directEdit?.request.id);
  const directEditRequest = directEdit && (!query.data || (directEditCandidate && (directEditCandidate.status === "proposed" || directEditCandidate.status === "validated")))
    ? directEdit.request
    : undefined;

  useEffect(() => {
    setRequestText("");
    setStrategySummary(plan.strategySummary);
    setMutationError(undefined);
    setMutationOutcome(undefined);
    setReconciliationError(undefined);
    setDirectEdit(undefined);
    setDirectEditOutcome(undefined);
    setInflightOutcome(undefined);
  }, [plan.id, plan.version, plan.strategySummary]);

  useEffect(() => {
    if (!directEdit || !query.data || directEditRequest) return;
    setDirectEdit(undefined);
  }, [directEdit, directEditRequest, query.data]);

  function closeDirectEdit(outcome?: string) {
    const trigger = directEditTrigger.current;
    setDirectEdit(undefined);
    if (outcome) setDirectEditOutcome(outcome);
    if (typeof window !== "undefined") {
      window.requestAnimationFrame(() => {
        if (trigger?.isConnected) trigger.focus();
      });
    }
  }

  async function propose(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setMutationError(undefined);
    setMutationOutcome(undefined);
    setReconciliationError(undefined);
    try {
      const response = await planChangesApi.create(run.id, {
        basePlanId: plan.id,
        expectedRunVersion: run.version,
        expectedPlanVersion: plan.version,
        requestText,
        operations: [{ kind: "update_plan", strategySummary }],
      });
      setRequestText("");
      setMutationOutcome(`Proposal ${response.request.id} was created with status ${response.request.status}. The active plan did not change.`);
      try {
        await query.reconcile();
      } catch (error) {
        setReconciliationError(new Error(
          `Proposal ${response.request.id} was created, but the canonical proposal list could not be refreshed. Retry the list before taking another action.`,
          { cause: error },
        ));
      }
    } catch (error) {
      setMutationError(error instanceof Error ? error : new Error("The plan proposal could not be created"));
    } finally { setSubmitting(false); }
  }

  return <section className="os-plan-changes" aria-labelledby="plan-change-heading">
    <div className="os-card-heading">
      <div><p className="os-eyebrow">Versioned operator amendments</p><h2 id="plan-change-heading">Plan change requests</h2></div>
      <StatusPill status={query.data?.items.some((item) => item.status === "validated") ? "review_ready" : "review_required"} />
    </div>
    <Card className="os-plan-change-create">
      <h3>Propose a bounded strategy amendment</h3>
      <p>The service normalizes this instruction into an exact diff, policy check, dependency check, readiness check, and in-flight impact. Creating a proposal never runs work.</p>
      <form onSubmit={propose}>
        <label><span>Why should the plan change? <small>Required</small></span><textarea value={requestText} onChange={(event) => setRequestText(event.target.value)} required minLength={3} maxLength={4000} placeholder="Example: Prior evidence ruled out the original service hypothesis, so focus the remaining plan on the verified HTTPS application." /></label>
        <label><span>Revised strategy summary <small>Required</small></span><textarea value={strategySummary} onChange={(event) => setStrategySummary(event.target.value)} required minLength={3} maxLength={2000} placeholder="Example: Validate the confirmed web service, preserve attributable evidence, and stop before any prohibited action class." /></label>
        <Button type="submit" disabled={submitting || strategySummary.trim() === plan.strategySummary.trim()}>{submitting ? "Creating proposal…" : "Create reviewable proposal"}</Button>
      </form>
      {mutationError && <ErrorPanel title="Plan proposal was not created" error={mutationError} />}
      {mutationOutcome && <p className="os-plan-change-outcome" role="status" aria-live="polite"><strong>Proposal committed.</strong> {mutationOutcome}</p>}
      {reconciliationError && <ErrorPanel title="Proposal created; refresh incomplete" error={reconciliationError} onRetry={query.refresh} />}
    </Card>
    <PlanVersionHistory
      run={run}
      activePlan={plan}
      plans={plans}
      historyCurrent={planHistoryCurrent}
      onProposalCreated={query.reconcile}
    />
    <DirectPlanEditor
      key={directEditRequest ? `${directEditRequest.id}:${directEditRequest.version}:${directEdit?.operationIndex ?? 0}` : `${plan.id}:${plan.version}`}
      run={run}
      plan={plan}
      onProposalCreated={query.reconcile}
      {...(directEditRequest && directEdit ? {
        editRequest: directEditRequest,
        editOperationIndex: directEdit.operationIndex,
        onEditCancelled: () => closeDirectEdit(),
        onEditCompleted: (request) => closeDirectEdit(`Proposal ${request.id} was saved as version ${request.version} and revalidated without applying it.`),
      } : {})}
    />
    {directEditOutcome && <p className="os-plan-change-outcome" role="status" aria-live="polite"><strong>Structured revision saved.</strong> {directEditOutcome}</p>}
    {inflightOutcome && <p className="os-plan-change-outcome os-plan-change-inflight-outcome" role="status" aria-live="polite">
      <strong>Fresh review is ready.</strong>{" "}
      Proposal <span className="os-mono">{inflightOutcome.sourceRequestId}</span> reached checkpoint{" "}
      <span className="os-mono">{inflightOutcome.resolution.sourceCheckpointId}</span>. Fresh proposal:{" "}
      <span className="os-mono">{inflightOutcome.resolution.freshRequestId}</span>. It still requires exact review and apply.
    </p>}
    {query.isLoading && !query.data && <LoadingPanel label="Loading versioned plan proposals" />}
    {query.error && !query.data && <ErrorPanel title="Plan proposals are unavailable" error={query.error} onRetry={query.refresh} />}
    {query.data?.items.length === 0 && <Card><EmptyState title="No plan amendments proposed" description="The active plan remains unchanged. A proposal must show an exact reviewed diff before it can become a new plan version." /></Card>}
    <div className="os-plan-change-list">
      {query.data?.items.map((request) => <PlanChangeRequestCard
        key={request.id}
        request={request}
        runVersion={run.version}
        basePlanVersion={plan.version}
        onChanged={query.reconcile}
        onApplied={async () => { await query.reconcile(); await onPlanApplied?.(); }}
        onInflightFinalized={(resolution) => setInflightOutcome({
          sourceRequestId: request.id,
          resolution,
        })}
        onEditDirect={(operationIndex, trigger) => {
          directEditTrigger.current = trigger;
          setDirectEditOutcome(undefined);
          setDirectEdit({ request, operationIndex });
        }}
      />)}
    </div>
  </section>;
}

export function PlanVersionHistory({ run, activePlan, plans, historyCurrent = true, onProposalCreated }: {
  readonly run: RuntimeRun;
  readonly activePlan: RunPlan;
  readonly plans: readonly RunPlan[];
  readonly historyCurrent?: boolean;
  readonly onProposalCreated?: () => void | Promise<void>;
}) {
  const historicalPlans = useMemo(() => plans
    .filter((candidate) => candidate.id !== activePlan.id && candidate.status === "superseded" && candidate.version < activePlan.version)
    .sort((left, right) => right.version - left.version), [activePlan.id, activePlan.version, plans]);
  const [targetPlanId, setTargetPlanId] = useState(historicalPlans[0]?.id ?? "");
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [outcome, setOutcome] = useState<string>();
  const [error, setError] = useState<Error>();
  const [reconciliationError, setReconciliationError] = useState<Error>();
  const selected = historicalPlans.find((candidate) => candidate.id === targetPlanId) ?? historicalPlans[0];
  const activeBoundaryCurrent = historyCurrent
    && run.currentPlanId === activePlan.id
    && activePlan.status === "active"
    && plans.some((candidate) => candidate.id === activePlan.id && candidate.version === activePlan.version && candidate.status === "active");

  useEffect(() => {
    if (!historicalPlans.some((candidate) => candidate.id === targetPlanId)) setTargetPlanId(historicalPlans[0]?.id ?? "");
  }, [historicalPlans, targetPlanId]);

  async function prepareRollback(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    setSubmitting(true);
    setError(undefined);
    setReconciliationError(undefined);
    setOutcome(undefined);
    try {
      const response = await planChangesApi.create(run.id, {
        basePlanId: activePlan.id,
        expectedRunVersion: run.version,
        expectedPlanVersion: activePlan.version,
        requestText: reason,
        operations: [{ kind: "restore_plan_version", targetPlanId: selected.id, targetPlanVersion: selected.version }],
      });
      setReason("");
      setOutcome(`Proposal ${response.request.id} compares plan v${activePlan.version} with historical plan v${selected.version}. The active plan has not changed.`);
      try {
        await onProposalCreated?.();
      } catch (refreshError) {
        setReconciliationError(new Error(
          `Rollback proposal ${response.request.id} was created, but the canonical proposal list could not be refreshed. Refresh plan history before taking another action.`,
          { cause: refreshError },
        ));
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught : new Error("The rollback proposal could not be prepared"));
    } finally { setSubmitting(false); }
  }

  return <Card className="os-plan-version-history">
    <div className="os-card-heading">
      <div><p className="os-eyebrow">Immutable history</p><h3>Compare and prepare a rollback</h3></div>
      <StatusPill status={!activeBoundaryCurrent ? "history_stale" : historicalPlans.length ? "history_available" : "current_only"}>
        {!activeBoundaryCurrent ? "History stale" : historicalPlans.length ? "History available" : "Current only"}
      </StatusPill>
    </div>
    <p>A rollback never reactivates or edits an old record. It creates an exact reviewed proposal, reruns current scope, policy, specialist, dependency, and in-flight checks, then requires a separate apply action to create a new plan version.</p>
    {!activeBoundaryCurrent && <p className="os-plan-change-blockers" role="status"><strong>Plan history is not current.</strong> Refresh the run plan before preparing a rollback; cached history cannot authorize a restore.</p>}
    {historicalPlans.length === 0 ? <EmptyState title="No earlier plan version" description="This run has only its current immutable plan. History will appear after a reviewed plan change creates another version." /> : <form onSubmit={prepareRollback} aria-busy={submitting || undefined}>
      <label>
        <span>Historical plan to compare <small>Required</small></span>
        <TitaniumSelect
          value={selected?.id ?? ""}
          aria-label="Historical plan to compare"
          data-control-id="plan-version-history-select"
          disabled={submitting || !activeBoundaryCurrent}
          loading={submitting}
          onChange={(event) => { setTargetPlanId(event.target.value); setOutcome(undefined); }}
        >
          {historicalPlans.map((candidate) => <option key={candidate.id} value={candidate.id}>Plan v{candidate.version} · {candidate.strategySummary}</option>)}
        </TitaniumSelect>
      </label>
      {selected && <div className="os-plan-version-compare" role="region" aria-label={`Plan v${activePlan.version} and plan v${selected.version} comparison`}>
        <article><p className="os-eyebrow">Current · v{activePlan.version}</p><h4>{activePlan.strategySummary}</h4><p>{activePlan.rationaleSummary ?? "No recorded rationale"}</p><ol>{activePlan.steps.map((step) => <li key={step.id}>{step.ordinal + 1}. {step.title}</li>)}</ol></article>
        <article><p className="os-eyebrow">Historical · v{selected.version}</p><h4>{selected.strategySummary}</h4><p>{selected.rationaleSummary ?? "No recorded rationale"}</p><ol>{selected.steps.map((step) => <li key={step.id}>{step.ordinal + 1}. {step.title}</li>)}</ol></article>
      </div>}
      <p className="os-muted">Visible comparison: {activePlan.steps.length} current steps versus {selected?.steps.length ?? 0} historical steps. The server produces the canonical field-by-field diff before anything can be applied.</p>
      <label><span>Why restore this version? <small>Required</small></span><textarea data-control-id="plan-version-rollback-reason" value={reason} disabled={submitting || !activeBoundaryCurrent} required minLength={3} maxLength={4000} onChange={(event) => setReason(event.target.value)} placeholder="Example: The latest hypothesis was disproved by verified evidence, so return to the earlier bounded strategy before proposing a different branch." /></label>
      <Button type="submit" data-control-id="plan-version-rollback-prepare" disabled={submitting || !activeBoundaryCurrent || !selected || reason.trim().length < 3}>{submitting ? "Preparing reviewed rollback…" : `Prepare rollback to plan v${selected?.version ?? "—"}`}</Button>
    </form>}
    {outcome && <p className="os-plan-change-outcome" role="status" aria-live="polite"><strong>Rollback proposal prepared.</strong> {outcome}</p>}
    {error && <ErrorPanel title="Rollback proposal was not prepared" error={error} />}
    {reconciliationError && <ErrorPanel title="Rollback prepared; refresh incomplete" error={reconciliationError} />}
  </Card>;
}

export function PlanChangeRequestCard({ request, runVersion, basePlanVersion, onChanged, onApplied, onInflightFinalized, onEditDirect }: {
  readonly request: PlanChangeRequest;
  readonly runVersion: number;
  readonly basePlanVersion: number;
  readonly onChanged?: () => void | Promise<void>;
  readonly onApplied?: () => void | Promise<void>;
  readonly onInflightFinalized?: (resolution: PlanChangeInflightResolution) => void;
  readonly onEditDirect?: (operationIndex: number, trigger: HTMLButtonElement) => void;
}) {
  const canonicalRevision = strategyRevision(request);
  const canonicalRevisionRef = useRef(canonicalRevision);
  const [revision, setRevision] = useState(canonicalRevision);
  const [rejectionReason, setRejectionReason] = useState("");
  const [busy, setBusy] = useState<
    "edit" | "apply" | "reject" | "resolve" | "finalize" | "refresh-resolution"
  >();
  const [acceptedMutation, setAcceptedMutation] = useState<"edit" | "apply" | "reject">();
  const [error, setError] = useState<Error>();
  const [resolutionReason, setResolutionReason] = useState("");
  const [resolution, setResolution] = useState<PlanChangeInflightResolution>();
  const open = request.status === "proposed" || request.status === "validated";
  const unavailable = Boolean(busy || acceptedMutation);
  const revisionDirty = revision.trim() !== canonicalRevision.trim();

  useEffect(() => {
    const priorCanonical = canonicalRevisionRef.current;
    setRevision((current) => current.trim() === priorCanonical.trim() ? canonicalRevision : current);
    canonicalRevisionRef.current = canonicalRevision;
    setAcceptedMutation(undefined);
  }, [canonicalRevision, request.status, request.version]);

  useEffect(() => {
    if (!request.inflightImpact.requiresCancellation) {
      setResolution(undefined);
      return;
    }
    // This bounded read is intentionally allowed to settle after a component
    // cleanup. React's development StrictMode performs a synthetic
    // setup/cleanup/setup cycle; aborting the first fetch there creates a
    // browser-visible failed required request even though the second request
    // succeeds. Ignore a late result instead, while preserving a clean network
    // contract in development and release browsers.
    let current = true;
    void planChangesApi.inflightResolution(
      request.runId,
      request.id,
    ).then((response) => {
      if (current && response.resolution) setResolution(response.resolution);
    }).catch((caught) => {
      if (current) {
        setError(caught instanceof Error
          ? caught
          : new Error("The in-flight amendment boundary could not be loaded"));
      }
    });
    return () => { current = false; };
  }, [request.id, request.inflightImpact.requiresCancellation, request.runId]);

  async function execute(kind: "edit" | "apply" | "reject") {
    setBusy(kind);
    setError(undefined);
    try {
      if (kind === "edit") {
        const operations = reviseEffectiveStrategyOperation(request.normalizedChange.operations, revision);
        await planChangesApi.edit(request.runId, request.id, {
          expectedRequestVersion: request.version,
          expectedRunVersion: runVersion,
          expectedPlanVersion: basePlanVersion,
          ...(request.requestText ? { requestText: request.requestText } : {}),
          operations,
        });
        setAcceptedMutation("edit");
        try { await onChanged?.(); } catch (refreshError) {
          throw new Error(`Proposal ${request.id} was saved and revalidated, but its canonical state could not be refreshed.`, { cause: refreshError });
        }
      } else if (kind === "apply") {
        await planChangesApi.apply(request.runId, request.id, { expectedRequestVersion: request.version, expectedRunVersion: runVersion, expectedPlanVersion: basePlanVersion });
        setAcceptedMutation("apply");
        try { await onApplied?.(); } catch (refreshError) {
          throw new Error(`Proposal ${request.id} was applied as a new plan version, but the canonical plan view could not be refreshed.`, { cause: refreshError });
        }
      } else {
        await planChangesApi.reject(request.runId, request.id, { expectedRequestVersion: request.version, reason: rejectionReason });
        setAcceptedMutation("reject");
        try { await onChanged?.(); } catch (refreshError) {
          throw new Error(`Proposal ${request.id} was rejected, but its canonical state could not be refreshed.`, { cause: refreshError });
        }
      }
    } catch (caught) { setError(caught instanceof Error ? caught : new Error("Plan change mutation failed")); }
    finally { setBusy(undefined); }
  }

  async function resolveInflight(mode: PlanChangeInflightResolutionMode) {
    setBusy("resolve");
    setError(undefined);
    try {
      const response = await planChangesApi.resolveInflight(
        request.runId,
        request.id,
        {
          mode,
          expectedRequestVersion: request.version,
          expectedRunVersion: runVersion,
          expectedPlanVersion: basePlanVersion,
          reason: resolutionReason,
        },
      );
      if (!response.resolution) {
        throw new Error("The server accepted the boundary but returned no canonical resolution");
      }
      setResolution(response.resolution);
      setResolutionReason("");
      await onChanged?.();
    } catch (caught) {
      setError(caught instanceof Error
        ? caught
        : new Error("The in-flight amendment boundary was not established"));
    } finally {
      setBusy(undefined);
    }
  }

  async function refreshResolution() {
    setBusy("refresh-resolution");
    setError(undefined);
    try {
      const response = await planChangesApi.inflightResolution(
        request.runId,
        request.id,
      );
      setResolution(response.resolution ?? undefined);
    } catch (caught) {
      setError(caught instanceof Error
        ? caught
        : new Error("The amendment boundary status could not be refreshed"));
    } finally {
      setBusy(undefined);
    }
  }

  async function finalizeResolution() {
    if (!resolution) return;
    setBusy("finalize");
    setError(undefined);
    try {
      const response = await planChangesApi.finalizeInflight(
        request.runId,
        request.id,
        { expectedResolutionVersion: resolution.version },
      );
      setResolution(response.resolution);
      onInflightFinalized?.(response.resolution);
      await onChanged?.();
    } catch (caught) {
      setError(caught instanceof Error
        ? caught
        : new Error("The amendment boundary has not reached a durable review state"));
    } finally {
      setBusy(undefined);
    }
  }

  const blockers = [...request.dependencyImpact.issues, ...request.policyValidation.reasons, ...request.readinessImpact.reasons, ...request.inflightImpact.reasons];
  return <Card className="os-plan-change-card">
    <div className="os-card-heading"><div><p className="os-eyebrow">Proposal {request.id}</p><h3>{request.normalizedChange.summary}</h3></div><StatusPill status={request.status} /></div>
    {request.requestText && <blockquote>{request.requestText}</blockquote>}
    <KeyValueGrid items={[
      { label: "Base plan", value: `${request.basePlanId} · v${request.basePlanVersion}` },
      { label: "Proposal version", value: request.version },
      { label: "Requested by", value: request.requestedBy },
      { label: "Created", value: formatTime(request.createdAt) },
      { label: "Dependency graph", value: request.dependencyImpact.valid ? "Valid" : "Invalid" },
      { label: "Policy", value: request.policyValidation.valid ? "Inside policy" : "Blocked by policy" },
      { label: "Specialists", value: request.readinessImpact.valid ? "Ready" : "Not ready" },
      { label: "In-flight work", value: request.inflightImpact.safeToApply ? "Safe pre-execution boundary" : "Checkpoint or cancellation required" },
    ]} />
    <div className="os-plan-diff" role="region" aria-label={`Exact diff for ${request.id}`}>
      <h4>Exact reviewed diff</h4>
      <table><thead><tr><th>Change</th><th>Field</th><th>Before</th><th>After</th></tr></thead><tbody>{request.structuredDiff.map((entry) => <tr key={`${entry.kind}:${entry.path}`}><td><StatusPill status={entry.kind} /></td><th scope="row">{entry.label}<small>{entry.path}</small></th><td><code>{display(entry.before)}</code></td><td><code>{display(entry.after)}</code></td></tr>)}</tbody></table>
    </div>
    {blockers.length > 0 && <div className="os-plan-change-blockers" role="status"><strong>This proposal cannot be applied yet</strong><ul>{blockers.map((reason) => <li key={reason}>{reason}</li>)}</ul></div>}
    <p className="os-muted">Budget impact: {signed(request.budgetImpact.netStepChange)} steps. Duration and provider cost are not observed; no estimate is fabricated.</p>
    <JsonDetails label="Structured interpretation and impact" value={{ operations: request.normalizedChange.operations, affectedRefs: request.affectedRefs, dependencyImpact: request.dependencyImpact, policyValidation: request.policyValidation, readinessImpact: request.readinessImpact, budgetImpact: request.budgetImpact, inflightImpact: request.inflightImpact }} />
    {open && request.inflightImpact.requiresCancellation && <section
      className="os-plan-change-resolution"
      aria-labelledby={`plan-change-resolution-${request.id}`}
    >
      <div className="os-card-heading">
        <div>
          <p className="os-eyebrow">In-flight amendment boundary</p>
          <h4 id={`plan-change-resolution-${request.id}`}>
            Choose how the affected work reaches a checkpoint
          </h4>
        </div>
        <StatusPill status={resolution?.status ?? "decision_required"} />
      </div>
      <p>
        Only work in the changed step and its dependent steps is affected.
        Unrelated work is shown separately and will not be cancelled.
      </p>
      <div className="os-plan-change-work-grid">
        <article>
          <h5>Affected work</h5>
          {request.inflightImpact.affectedActions.length === 0
            ? <p>No started action is attached; queued assignments or decisions still need invalidation.</p>
            : <ul>{request.inflightImpact.affectedActions.map((action) => <li key={action.id}>
              <strong>{action.intentSummary}</strong>
              <span>{action.status} · {action.actionClass} · {action.target ?? "No target recorded"}</span>
              <small>{action.idempotent && !action.destructive ? "Repeat-safe" : "Must be stopped"}</small>
            </li>)}</ul>}
          {request.inflightImpact.affectedAttackAttempts.map((attempt) => <p key={attempt.id}>
            Attempt: <strong>{attempt.techniqueName}</strong> · {attempt.status}
          </p>)}
        </article>
        <article>
          <h5>Unrelated work left untouched</h5>
          {request.inflightImpact.unaffectedActions.length === 0
            ? <p>No unrelated active actions.</p>
            : <ul>{request.inflightImpact.unaffectedActions.map((action) => <li key={action.id}>
              <strong>{action.intentSummary}</strong>
              <span>{action.status} · {action.actionClass}</span>
            </li>)}</ul>}
        </article>
      </div>
      {!resolution && <>
        <label>
          <span>Reason for pausing at this boundary <small>Required</small></span>
          <input
            data-control-id="plan-change-inflight-reason"
            value={resolutionReason}
            disabled={unavailable}
            minLength={3}
            maxLength={2000}
            onChange={(event) => setResolutionReason(event.target.value)}
            placeholder="Example: Apply the reviewed service-specific plan after the current repeat-safe scan reaches a durable result."
          />
        </label>
        <div className="os-plan-change-resolution-options">
          {request.inflightImpact.resolutionOptions.map((option) => <article key={option.mode}>
            <h5>{option.label}</h5>
            <p>{option.consequence}</p>
            {option.disabledReason && <p role="status">{option.disabledReason}</p>}
            <Button
              type="button"
              variant={option.mode === "checkpoint_cancel_affected_work" ? "danger" : "secondary"}
              data-control-id={`plan-change-${option.mode}`}
              disabled={unavailable || !option.enabled || resolutionReason.trim().length < 3}
              onClick={() => resolveInflight(option.mode)}
            >
              {busy === "resolve" ? "Establishing checkpoint…" : option.label}
            </Button>
          </article>)}
        </div>
      </>}
      {resolution && <div className="os-plan-change-resolution-status" role="status" aria-live="polite">
        <p>
          <strong>{resolution.status === "ready_for_review"
            ? "Fresh review is ready."
            : resolution.status === "failed"
              ? "Settlement stopped at its bound."
              : "Dispatch is fenced while work settles."}</strong>
          {" "}Checkpoint <span className="os-mono">{resolution.sourceCheckpointId}</span>.
        </p>
        <p>Bounded settlement deadline: {formatTime(resolution.settleDeadlineAt)}.</p>
        {resolution.failureReason && <p>{resolution.failureReason}</p>}
        {resolution.freshRequestId && <p>
          Fresh proposal: <span className="os-mono">{resolution.freshRequestId}</span>.
          It still requires exact review and apply.
        </p>}
        {resolution.status === "waiting_for_terminal_work" && <div className="os-plan-change-actions">
          <Button
            type="button"
            variant="secondary"
            data-control-id="plan-change-resolution-refresh"
            disabled={Boolean(busy)}
            onClick={refreshResolution}
          >{busy === "refresh-resolution" ? "Refreshing…" : "Refresh work status"}</Button>
          <Button
            type="button"
            data-control-id="plan-change-resolution-finalize"
            disabled={Boolean(busy)}
            onClick={finalizeResolution}
          >{busy === "finalize" ? "Checking durable results…" : "Complete boundary and prepare fresh review"}</Button>
        </div>}
      </div>}
    </section>}
    {open && <div className="os-plan-change-actions">
      {request.normalizedChange.operations.some((operation) => operation.kind === "update_plan" && operation.strategySummary !== undefined) && <>
        <label><span>Revised strategy summary for {request.id}</span><input value={revision} disabled={unavailable} onChange={(event) => setRevision(event.target.value)} /></label>
        <Button aria-label={`Save and revalidate ${request.id}`} variant="secondary" disabled={unavailable || revision.trim().length < 3 || !revisionDirty} onClick={() => execute("edit")}>{busy === "edit" ? "Saving…" : "Save and revalidate"}</Button>
      </>}
      {request.normalizedChange.operations.some((operation) => operation.kind === "restore_plan_version") && <p className="os-plan-version-restore-notice"><strong>Historical snapshot:</strong> this proposal restores plan v{request.normalizedChange.operations.find((operation) => operation.kind === "restore_plan_version")?.targetPlanVersion} as a new immutable version. Edit the rollback reason by rejecting and preparing a fresh comparison; the historical snapshot itself cannot be rewritten.</p>}
      {request.normalizedChange.operations.map((operation, operationIndex) => operation.kind === "update_plan" || operation.kind === "restore_plan_version" ? null : <Button
        key={`${operation.kind}:${operationIndex}`}
        type="button"
        variant="secondary"
        data-control-id="plan-change-direct-edit-open"
        aria-label={`Edit ${directOperationLabel(operation)} in ${request.id}`}
        disabled={unavailable || !onEditDirect}
        onClick={(event) => onEditDirect?.(operationIndex, event.currentTarget)}
      >Edit structured proposal</Button>)}
      <Button aria-label={`Apply new plan version from ${request.id}`} disabled={unavailable || request.status !== "validated" || !request.inflightImpact.safeToApply} onClick={() => execute("apply")}>{busy === "apply" ? "Applying…" : "Apply new plan version"}</Button>
      <label><span>Rejection reason for {request.id}</span><input value={rejectionReason} disabled={unavailable} onChange={(event) => setRejectionReason(event.target.value)} placeholder="Explain why this exact proposal should not proceed." /></label>
      <Button aria-label={`Reject plan proposal ${request.id}`} variant="danger" disabled={unavailable || rejectionReason.trim().length < 3} onClick={() => execute("reject")}>{busy === "reject" ? "Rejecting…" : "Reject proposal"}</Button>
    </div>}
    {acceptedMutation && open && <p className="os-plan-change-outcome" role="status" aria-live="polite"><strong>Mutation accepted.</strong> Refreshing the canonical proposal before another action is allowed.</p>}
    {request.status === "applied" && <p className="os-plan-change-outcome"><strong>Applied as plan:</strong> <span className="os-mono">{request.resultPlanId}</span>. Activation did not execute an action.</p>}
    {request.status === "rejected" && <p className="os-plan-change-outcome"><strong>Rejected:</strong> the base plan and execution state were not changed.</p>}
    {error && <ErrorPanel title={acceptedMutation ? "Plan change accepted; refresh incomplete" : "Plan change was not updated"} error={error} />}
  </Card>;
}

function display(value: unknown): string {
  if (value === null) return "Not set";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function signed(value: number): string { return value > 0 ? `+${value}` : String(value); }

function strategyRevision(request: PlanChangeRequest): string {
  const index = effectiveStrategyOperationIndex(request.normalizedChange.operations);
  const operation = index < 0 ? undefined : request.normalizedChange.operations[index];
  return operation?.kind === "update_plan" ? operation.strategySummary ?? "" : "";
}

function effectiveStrategyOperationIndex(operations: readonly PlanChangeOperation[]): number {
  for (let index = operations.length - 1; index >= 0; index -= 1) {
    const operation = operations[index];
    if (operation?.kind === "update_plan" && operation.strategySummary !== undefined) return index;
  }
  return -1;
}

export function reviseEffectiveStrategyOperation(
  operations: readonly PlanChangeOperation[],
  strategySummary: string,
): PlanChangeOperation[] {
  const targetIndex = effectiveStrategyOperationIndex(operations);
  if (targetIndex < 0) return [...operations, { kind: "update_plan", strategySummary }];
  return operations.map((operation, index) => index === targetIndex && operation.kind === "update_plan"
    ? { ...operation, strategySummary }
    : operation);
}

function directOperationLabel(operation: Exclude<PlanChangeOperation, { readonly kind: "update_plan" | "restore_plan_version" }>): string {
  switch (operation.kind) {
    case "add_step": return "exact new step";
    case "update_step": return "step details or ownership";
    case "set_dependencies": return "step dependencies";
    case "reorder_steps": return "complete step order";
    case "remove_step": return "step removal";
    case "set_represented_action": return "exact represented action";
  }
}

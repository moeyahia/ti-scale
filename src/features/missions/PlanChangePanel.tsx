import { type FormEvent, useEffect, useRef, useState } from "react";
import { planChangesApi } from "../../data/api/planChanges";
import { useQuery } from "../../data/cache/QueryProvider";
import type { PlanChangeOperation, PlanChangeRequest } from "../../domain/types/planChanges";
import type { RunPlan, RuntimeRun } from "../../domain/types/runtimeV2";
import { Button, Card, EmptyState, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { formatTime, JsonDetails, KeyValueGrid } from "../runs/OperationalSurface";
import { DirectPlanEditor } from "./DirectPlanEditor";

export function PlanChangePanel({ run, plan, onPlanApplied }: {
  readonly run: RuntimeRun;
  readonly plan: RunPlan;
  readonly onPlanApplied?: () => void | Promise<void>;
}) {
  const query = useQuery(`plan-changes:${run.id}`, (signal) => planChangesApi.list(run.id, signal), { staleTime: 0 });
  const [requestText, setRequestText] = useState("");
  const [strategySummary, setStrategySummary] = useState(plan.strategySummary);
  const [submitting, setSubmitting] = useState(false);
  const [mutationError, setMutationError] = useState<Error>();
  const [directEdit, setDirectEdit] = useState<{ readonly request: PlanChangeRequest; readonly operationIndex: number }>();
  const [directEditOutcome, setDirectEditOutcome] = useState<string>();
  const directEditTrigger = useRef<HTMLButtonElement | null>(null);
  const directEditCandidate = query.data?.items.find((request) => request.id === directEdit?.request.id);
  const directEditRequest = directEdit && (!query.data || (directEditCandidate && (directEditCandidate.status === "proposed" || directEditCandidate.status === "validated")))
    ? directEdit.request
    : undefined;

  useEffect(() => {
    setRequestText("");
    setStrategySummary(plan.strategySummary);
    setMutationError(undefined);
    setDirectEdit(undefined);
    setDirectEditOutcome(undefined);
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
    try {
      await planChangesApi.create(run.id, {
        basePlanId: plan.id,
        expectedRunVersion: run.version,
        expectedPlanVersion: plan.version,
        requestText,
        operations: [{ kind: "update_plan", strategySummary }],
      });
      setRequestText("");
      await query.refresh();
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
    </Card>
    <DirectPlanEditor
      key={directEditRequest ? `${directEditRequest.id}:${directEditRequest.version}:${directEdit?.operationIndex ?? 0}` : `${plan.id}:${plan.version}`}
      run={run}
      plan={plan}
      onProposalCreated={query.refresh}
      {...(directEditRequest && directEdit ? {
        editRequest: directEditRequest,
        editOperationIndex: directEdit.operationIndex,
        onEditCancelled: () => closeDirectEdit(),
        onEditCompleted: (request) => closeDirectEdit(`Proposal ${request.id} was saved as version ${request.version} and revalidated without applying it.`),
      } : {})}
    />
    {directEditOutcome && <p className="os-plan-change-outcome" role="status" aria-live="polite"><strong>Structured revision saved.</strong> {directEditOutcome}</p>}
    {query.isLoading && !query.data && <LoadingPanel label="Loading versioned plan proposals" />}
    {query.error && !query.data && <ErrorPanel title="Plan proposals are unavailable" error={query.error} onRetry={query.refresh} />}
    {query.data?.items.length === 0 && <Card><EmptyState title="No plan amendments proposed" description="The active plan remains unchanged. A proposal must show an exact reviewed diff before it can become a new plan version." /></Card>}
    <div className="os-plan-change-list">
      {query.data?.items.map((request) => <PlanChangeRequestCard
        key={request.id}
        request={request}
        runVersion={run.version}
        basePlanVersion={plan.version}
        onChanged={query.refresh}
        onApplied={async () => { query.refresh(); await onPlanApplied?.(); }}
        onEditDirect={(operationIndex, trigger) => {
          directEditTrigger.current = trigger;
          setDirectEditOutcome(undefined);
          setDirectEdit({ request, operationIndex });
        }}
      />)}
    </div>
  </section>;
}

export function PlanChangeRequestCard({ request, runVersion, basePlanVersion, onChanged, onApplied, onEditDirect }: {
  readonly request: PlanChangeRequest;
  readonly runVersion: number;
  readonly basePlanVersion: number;
  readonly onChanged?: () => void | Promise<void>;
  readonly onApplied?: () => void | Promise<void>;
  readonly onEditDirect?: (operationIndex: number, trigger: HTMLButtonElement) => void;
}) {
  const canonicalRevision = strategyRevision(request);
  const canonicalRevisionRef = useRef(canonicalRevision);
  const [revision, setRevision] = useState(canonicalRevision);
  const [rejectionReason, setRejectionReason] = useState("");
  const [busy, setBusy] = useState<"edit" | "apply" | "reject">();
  const [acceptedMutation, setAcceptedMutation] = useState<"edit" | "apply" | "reject">();
  const [error, setError] = useState<Error>();
  const open = request.status === "proposed" || request.status === "validated";
  const unavailable = Boolean(busy || acceptedMutation);
  const revisionDirty = revision.trim() !== canonicalRevision.trim();

  useEffect(() => {
    const priorCanonical = canonicalRevisionRef.current;
    setRevision((current) => current.trim() === priorCanonical.trim() ? canonicalRevision : current);
    canonicalRevisionRef.current = canonicalRevision;
    setAcceptedMutation(undefined);
  }, [canonicalRevision, request.status, request.version]);

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
        await onChanged?.();
      } else if (kind === "apply") {
        await planChangesApi.apply(request.runId, request.id, { expectedRequestVersion: request.version, expectedRunVersion: runVersion, expectedPlanVersion: basePlanVersion });
        setAcceptedMutation("apply");
        await onApplied?.();
      } else {
        await planChangesApi.reject(request.runId, request.id, { expectedRequestVersion: request.version, reason: rejectionReason });
        setAcceptedMutation("reject");
        await onChanged?.();
      }
    } catch (caught) { setError(caught instanceof Error ? caught : new Error("Plan change mutation failed")); }
    finally { setBusy(undefined); }
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
    {open && <div className="os-plan-change-actions">
      {request.normalizedChange.operations.some((operation) => operation.kind === "update_plan" && operation.strategySummary !== undefined) && <>
        <label><span>Revised strategy summary for {request.id}</span><input value={revision} disabled={unavailable} onChange={(event) => setRevision(event.target.value)} /></label>
        <Button aria-label={`Save and revalidate ${request.id}`} variant="secondary" disabled={unavailable || revision.trim().length < 3 || !revisionDirty} onClick={() => execute("edit")}>{busy === "edit" ? "Saving…" : "Save and revalidate"}</Button>
      </>}
      {request.normalizedChange.operations.map((operation, operationIndex) => operation.kind === "update_plan" ? null : <Button
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
    {error && <ErrorPanel title="Plan change was not updated" error={error} />}
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

function directOperationLabel(operation: Exclude<PlanChangeOperation, { readonly kind: "update_plan" }>): string {
  switch (operation.kind) {
    case "add_step": return "exact new step";
    case "update_step": return "step details or ownership";
    case "set_dependencies": return "step dependencies";
    case "reorder_steps": return "complete step order";
    case "remove_step": return "step removal";
    case "set_represented_action": return "exact represented action";
  }
}

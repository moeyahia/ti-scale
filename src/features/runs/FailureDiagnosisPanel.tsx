import { type FormEvent, useMemo, useState } from "react";
import { operationalTruthApi } from "../../data/api/operationalTruth";
import { useQuery } from "../../data/cache/QueryProvider";
import type {
  FailureDiagnosisV24,
  FailureOperatorActionKindV24,
  OperationalJsonValue,
  ResolveFailureDiagnosisRequestV24,
} from "../../domain/types/operationalTruth";
import {
  Button,
  Card,
  EmptyState,
  ErrorPanel,
  LoadingPanel,
  StatusPill,
} from "../../design-system/components/Primitives";
import {
  DegradedNotice,
  formatTime,
  JsonDetails,
  KeyValueGrid,
  useActionState,
} from "./OperationalSurface";

const RESOLVABLE_STATES = new Set<FailureDiagnosisV24["state"]>(["active", "terminal"]);

export function declaredFailureActions(
  diagnosis: Pick<FailureDiagnosisV24, "operatorActions">,
): FailureDiagnosisV24["operatorActions"] {
  // The runtime declaration is intentionally the complete list. Retryability,
  // category, and UI heuristics must never manufacture another action.
  return diagnosis.operatorActions;
}

export function buildFailureResolutionRequest(
  diagnosis: Pick<FailureDiagnosisV24, "state" | "operatorActions">,
  actionKind: FailureOperatorActionKindV24 | "",
  outcome: string,
  confirmed: boolean,
): ResolveFailureDiagnosisRequestV24 {
  if (!RESOLVABLE_STATES.has(diagnosis.state)) {
    throw new Error("Only an active or terminal diagnosis can be resolved.");
  }
  const action = declaredFailureActions(diagnosis).find((item) => item.kind === actionKind);
  if (!action) throw new Error("Select an operator action declared by the server.");
  const normalized = outcome.trim();
  if (normalized.length < 16) {
    throw new Error("Record at least 16 characters explaining what changed and how it was verified.");
  }
  if (!confirmed) {
    throw new Error("Confirm that the declared action was completed and its outcome was verified.");
  }
  return { actionKind: action.kind, verifiedOutcome: normalized, confirmed: true };
}

function jsonSummary(value: OperationalJsonValue, empty: string, singular: string): string {
  if (value === null) return empty;
  if (Array.isArray(value)) return value.length === 0 ? empty : `${value.length} ${singular}${value.length === 1 ? "" : "s"} recorded.`;
  if (typeof value === "object") {
    const count = Object.keys(value).length;
    return count === 0 ? empty : `${count} ${singular} field${count === 1 ? "" : "s"} recorded.`;
  }
  return typeof value === "string" ? value : String(value);
}

function diagnosisLabel(diagnosis: FailureDiagnosisV24): string {
  return `${diagnosis.category.replaceAll("_", " ")} · ${diagnosis.code}`;
}

export function FailureDiagnosisDetailView({
  diagnosis,
  pending = false,
  mutationError,
  successMessage,
  onResolve,
}: {
  readonly diagnosis: FailureDiagnosisV24;
  readonly pending?: boolean;
  readonly mutationError?: Error;
  readonly successMessage?: string;
  readonly onResolve: (request: ResolveFailureDiagnosisRequestV24) => void | Promise<void>;
}) {
  const [selectedAction, setSelectedAction] = useState<FailureOperatorActionKindV24 | "">("");
  const [outcome, setOutcome] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [validationError, setValidationError] = useState<string>();
  const actions = declaredFailureActions(diagnosis);
  const resolvable = RESOLVABLE_STATES.has(diagnosis.state);
  const selected = actions.find((action) => action.kind === selectedAction);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setValidationError(undefined);
    if (!confirmed) {
      setValidationError("Confirm that the declared action was completed and its outcome was verified.");
      return;
    }
    try {
      void onResolve(buildFailureResolutionRequest(diagnosis, selectedAction, outcome, confirmed));
    } catch (error) {
      setValidationError(error instanceof Error ? error.message : "The resolution record is invalid.");
    }
  };

  return <article className="os-failure-diagnosis-detail" aria-labelledby={`failure-diagnosis-${diagnosis.id}`}>
    <header className="os-card-heading">
      <div>
        <p className="os-eyebrow">Canonical failure diagnosis</p>
        <h3 id={`failure-diagnosis-${diagnosis.id}`}>{diagnosis.humanReason}</h3>
      </div>
      <StatusPill status={diagnosis.state} />
    </header>

    <KeyValueGrid items={[
      { label: "Category", value: diagnosis.category.replaceAll("_", " ") },
      { label: "Machine code", value: <code>{diagnosis.code}</code> },
      { label: "Originating component", value: diagnosis.originatingComponent },
      { label: "Subject", value: `${diagnosis.subjectType} · ${diagnosis.subjectId}` },
      { label: "Target and scope", value: diagnosis.targetSummary ?? "No target summary was recorded" },
      { label: "Policy or dependency", value: diagnosis.policyOrDependency ?? "No policy or dependency reference" },
      { label: "Retryability", value: diagnosis.retryable ? "Retryable only through a declared bounded action" : "Not automatically retryable" },
      { label: "Detected", value: formatTime(diagnosis.createdAt) },
      { label: "Resolution status", value: diagnosis.resolvedAt ? `Resolved ${formatTime(diagnosis.resolvedAt)}` : "Open" },
    ]} />

    <div className="os-failure-diagnosis-grid">
      <section aria-labelledby={`failure-references-${diagnosis.id}`}>
        <p className="os-eyebrow">Causal references</p>
        <h4 id={`failure-references-${diagnosis.id}`}>Last success and raw failure source</h4>
        <KeyValueGrid items={[
          { label: "Last successful event", value: diagnosis.lastSuccessEventId ?? "No prior successful event was linked" },
          { label: "Failed component reference", value: diagnosis.failedComponentRef ?? "No component reference was recorded" },
          { label: "Raw error log", value: diagnosis.rawErrorLogId ?? "No raw error log was linked" },
        ]} />
      </section>

      <section aria-labelledby={`failure-impact-${diagnosis.id}`}>
        <p className="os-eyebrow">Mission impact</p>
        <h4 id={`failure-impact-${diagnosis.id}`}>Effect on the objective</h4>
        <p>{diagnosis.objectiveImpact}</p>
        <p><strong>Recommended remediation:</strong> {diagnosis.remediation}</p>
      </section>
    </div>

    <div className="os-failure-diagnosis-grid">
      <section aria-labelledby={`failure-recovery-${diagnosis.id}`}>
        <p className="os-eyebrow">Automatic recovery</p>
        <h4 id={`failure-recovery-${diagnosis.id}`}>{jsonSummary(
          diagnosis.automaticRecovery,
          "No automatic recovery attempt was recorded.",
          "automatic recovery attempt",
        )}</h4>
        <JsonDetails label="Automatic recovery record" value={diagnosis.automaticRecovery} />
        <JsonDetails label="Retry history" value={diagnosis.retryHistory} />
        <JsonDetails label="Progress preserved before failure" value={diagnosis.progressBeforeFailure} />
      </section>

      <section aria-labelledby={`failure-preserved-${diagnosis.id}`}>
        <p className="os-eyebrow">Preserved records</p>
        <h4 id={`failure-preserved-${diagnosis.id}`}>{diagnosis.preservedReferences.length
          ? `${diagnosis.preservedReferences.length} canonical record${diagnosis.preservedReferences.length === 1 ? "" : "s"} retained`
          : "No preserved record reference was supplied"}</h4>
        {diagnosis.preservedReferences.length > 0 && <ul className="os-failure-reference-list">
          {diagnosis.preservedReferences.map((reference) => <li key={`${reference.kind}:${reference.id}`}>
            <strong>{reference.meaning}</strong>
            <span><code>{reference.kind}</code> · <code>{reference.id}</code></span>
          </li>)}
        </ul>}
      </section>
    </div>

    <section className="os-failure-declared-actions" aria-labelledby={`failure-actions-${diagnosis.id}`}>
      <p className="os-eyebrow">Server-declared operator actions</p>
      <h4 id={`failure-actions-${diagnosis.id}`}>Only these recovery routes are valid for this diagnosis</h4>
      <p className="os-muted">Selecting an action here does not execute it. Recovery commands remain in the enforced recovery panel; this form closes the diagnosis only after the outcome has been verified.</p>
      <ul>
        {actions.map((action) => <li key={action.kind}>
          <label>
            <input
              type="radio"
              name={`failure-action-${diagnosis.id}`}
              value={action.kind}
              checked={selectedAction === action.kind}
              disabled={!resolvable || pending}
              onChange={() => setSelectedAction(action.kind)}
            />
            <span><strong>{action.label}</strong><small><code>{action.kind}</code> · {action.consequence}</small></span>
          </label>
          <StatusPill status={action.requiresConfirmation ? "confirmation required" : "declared"} />
        </li>)}
      </ul>

      {resolvable ? <form className="os-failure-resolution" onSubmit={submit}>
        <label>
          <span>Verified resolution outcome</span>
          <textarea
            value={outcome}
            disabled={pending}
            onChange={(event) => setOutcome(event.target.value)}
            placeholder="Explain what changed, the bounded check performed, and why this diagnosis is now resolved."
          />
        </label>
        <label className="os-checkbox-row">
          <input
            type="checkbox"
            checked={confirmed}
            disabled={pending}
            onChange={(event) => setConfirmed(event.target.checked)}
          />
          <span>I confirm the selected declared action was completed and its outcome was verified. This resolution will be written to the immutable audit trail.</span>
        </label>
        <Button
          type="submit"
          variant="secondary"
          disabled={pending || !selected || outcome.trim().length < 16 || !confirmed}
        >{pending ? "Recording resolution" : "Record audited resolution"}</Button>
      </form> : <p className="os-state-note">This diagnosis is {diagnosis.state}. Its original declared actions remain visible for audit, but it cannot be resolved again.</p>}
      {validationError && <p className="os-state-panel os-state-panel--error" role="alert">{validationError}</p>}
      {mutationError && <ErrorPanel title="Diagnosis resolution was not accepted" error={mutationError} />}
      {successMessage && <p className="os-success-note" role="status">{successMessage}</p>}
    </section>
  </article>;
}

export function FailureDiagnosisPanel({
  missionId,
  runId,
  onChanged,
}: {
  readonly missionId: string;
  readonly runId: string;
  readonly onChanged?: () => void;
}) {
  const diagnoses = useQuery(
    `failure-diagnoses:${missionId}:${runId}`,
    (signal) => operationalTruthApi.listFailureDiagnoses(missionId, runId, {
      states: ["active", "terminal", "resolved", "superseded"],
      limit: 100,
    }, signal),
    { staleTime: 0 },
  );
  const [requestedId, setRequestedId] = useState<string>();
  const selectedId = useMemo(() => {
    if (requestedId && diagnoses.data?.items.some((item) => item.id === requestedId)) return requestedId;
    return diagnoses.data?.items.find((item) => item.state === "active" || item.state === "terminal")?.id
      ?? diagnoses.data?.items[0]?.id;
  }, [diagnoses.data?.items, requestedId]);
  const detail = useQuery(
    `failure-diagnosis:${missionId}:${runId}:${selectedId ?? "none"}`,
    (signal) => selectedId
      ? operationalTruthApi.failureDiagnosis(missionId, runId, selectedId, signal)
      : Promise.resolve(undefined),
    { staleTime: 0 },
  );
  const resolution = useActionState();

  const resolve = async (request: ResolveFailureDiagnosisRequestV24) => {
    if (!selectedId) return;
    await resolution.run(async () => {
      await operationalTruthApi.resolveFailureDiagnosis(
        missionId,
        runId,
        selectedId,
        request,
        `failure-resolution-${crypto.randomUUID()}`,
      );
      diagnoses.refresh();
      detail.refresh();
      onChanged?.();
    }, "The diagnosis resolution was recorded in the immutable audit trail.");
  };

  if (diagnoses.isLoading) return <Card className="os-failure-diagnosis-panel"><LoadingPanel label="Loading structured failure diagnoses" /></Card>;
  if (diagnoses.error && !diagnoses.data) return <Card className="os-failure-diagnosis-panel"><ErrorPanel title="Failure diagnosis is unavailable" error={diagnoses.error} onRetry={diagnoses.refresh} /></Card>;
  if (!diagnoses.data?.items.length) return <Card className="os-failure-diagnosis-panel">
    <EmptyState
      title="No structured failure diagnosis"
      description="The supervisor has not persisted a canonical cause for this run. Do not infer a cause from a generic status badge; use the technical recovery record below while diagnosis catches up."
      action={<Button variant="secondary" onClick={diagnoses.refresh}>Check again</Button>}
    />
  </Card>;

  return <Card className="os-failure-diagnosis-panel" aria-labelledby={`failure-diagnoses-${runId}`}>
    <div className="os-card-heading">
      <div>
        <p className="os-eyebrow">Explainable failure record</p>
        <h2 id={`failure-diagnoses-${runId}`}>What failed, why, and what can resolve it</h2>
      </div>
      <Button variant="quiet" onClick={() => { diagnoses.refresh(); detail.refresh(); }}>Refresh diagnoses</Button>
    </div>
    <p className="os-page-description">These records are canonical and audit-backed. The separate recovery panel executes only runtime-supported recovery commands.</p>
    {diagnoses.error && <DegradedNotice>Refresh failed; the last validated diagnosis list remains visible.</DegradedNotice>}

    <div className="os-failure-diagnosis-layout">
      <nav aria-label="Failure diagnoses">
        <ol className="os-failure-diagnosis-list">
          {diagnoses.data.items.map((diagnosis) => <li key={diagnosis.id}>
            <button
              type="button"
              className={diagnosis.id === selectedId ? "is-current" : undefined}
              aria-current={diagnosis.id === selectedId ? "true" : undefined}
              onClick={() => { resolution.clear(); setRequestedId(diagnosis.id); }}
            >
              <span><strong>{diagnosisLabel(diagnosis)}</strong><small>{diagnosis.subjectType} · {formatTime(diagnosis.createdAt)}</small></span>
              <StatusPill status={diagnosis.state} />
            </button>
          </li>)}
        </ol>
      </nav>
      <section aria-label="Selected failure diagnosis">
        {detail.isLoading && <LoadingPanel label="Loading complete failure diagnosis" />}
        {detail.error && !detail.data && <ErrorPanel title="Failure detail is unavailable" error={detail.error} onRetry={detail.refresh} />}
        {detail.error && detail.data && <DegradedNotice>Detail refresh failed; the last validated diagnosis remains visible.</DegradedNotice>}
        {detail.data && <FailureDiagnosisDetailView
          key={detail.data.diagnosis.id}
          diagnosis={detail.data.diagnosis}
          pending={resolution.pending}
          mutationError={resolution.error}
          successMessage={resolution.message}
          onResolve={resolve}
        />}
      </section>
    </div>
  </Card>;
}

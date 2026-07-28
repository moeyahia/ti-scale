import { useEffect, useRef, useState } from "react";
import { AppLink } from "../../app/router/navigation";
import { useAuth } from "../../app/providers/AuthProvider";
import { dispatchRecoveryOperation, operationsApi } from "../../data/api/operations";
import { useQuery } from "../../data/cache/QueryProvider";
import { useEventStream } from "../../data/events/EventStreamProvider";
import type { RecoveryActionAvailability, RunRecoveryRecord } from "../../domain/types/operations";
import { Button, ButtonLink, Card, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import { formatTime, JsonDetails, KeyValueGrid } from "./OperationalSurface";
import { operatorText } from "../../lib/operatorLanguage";
import {
  availableRecoveryAttemptStorage,
  classifyRecoveryMutationFailure,
  clearRecoveryMutationAttempt,
  createRecoveryMutationAttempt,
  loadRecoveryMutationAttempt,
  recoveryAttemptCommandLabel,
  recoveryAttemptMatchesProjection,
  saveRecoveryMutationAttempt,
  type RecoveryMutationAttempt,
  type RecoveryOperationCommand,
  withRecoveryAttemptFailure,
} from "./recoveryMutationRetry";

function bounded(value: number, limit: number | null, remaining: number | null): string {
  if (limit === null) return `${value} used · limit not reported`;
  return `${value}/${limit} used · ${remaining ?? Math.max(0, limit - value)} remaining`;
}

function memoryHref(item: RunRecoveryRecord["failedAttemptMemories"][number]): string {
  return item.kind === "memory"
    ? `/brain/nodes/${encodeURIComponent(item.id)}`
    : `/learning/lessons/${encodeURIComponent(item.id)}`;
}

export function providerChoiceValue(provider: RunRecoveryRecord["providerCandidates"][number]): string {
  return [provider.providerId, provider.modelId ?? "", provider.modelConfigurationHash ?? ""]
    .map((value) => encodeURIComponent(value))
    .join("::");
}

export function RecoveryProviderChoices({
  candidates,
  value,
  disabled,
  onChange,
}: {
  readonly candidates: RunRecoveryRecord["providerCandidates"];
  readonly value: string;
  readonly disabled: boolean;
  readonly onChange: (value: string) => void;
}) {
  return <div className="os-recovery-provider-options">
    <label><span>Provider and exact model</span><TitaniumSelect value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)}>
      <option value="">Choose an enabled provider and model</option>
      {candidates.map((provider) => <option
        key={providerChoiceValue(provider)}
        value={providerChoiceValue(provider)}
        disabled={!provider.enabled}
      >{provider.providerId} · {provider.modelId ?? "No attested model"} · {provider.eligibility.replaceAll("_", " ")}</option>)}
    </TitaniumSelect></label>
    <ul className="os-compact-list" aria-label="Provider and model compatibility">
      {candidates.map((provider) => <li key={`reason:${providerChoiceValue(provider)}`}>
        <span><strong>{provider.providerId} · {provider.modelId ?? "Model unavailable"}</strong><small>{provider.reason}{provider.modelConfigurationHash
          ? ` · Configuration ${provider.modelConfigurationHash.slice(0, 12)}…`
          : ""}</small></span>
        <StatusPill status={provider.eligibility.replaceAll("_", " ")} />
      </li>)}
    </ul>
  </div>;
}

function actionVariant(action: RecoveryActionAvailability): "secondary" | "danger" {
  return action.kind === "terminate" ? "danger" : "secondary";
}

const RECOVERY_UNMOUNT_EVENTS = new Set([
  "run.cancellation_requested",
  "run.cancelled",
  "run.completed",
  "run.evaluation_recorded",
]);

interface PreparedRecoveryOperation {
  readonly command: RecoveryOperationCommand;
  readonly body: Readonly<Record<string, unknown>>;
}

function recoverySuccessMessage(command: RecoveryOperationCommand): string {
  if (command === "replan") {
    return "The materially different strategy was checkpointed and queued through the bounded supervisor.";
  }
  if (command === "reassign") {
    return "The exact stopped assignment was transferred to the declared-capable specialist; execution remains stopped.";
  }
  if (command === "change_provider") {
    return "The provider route was versioned for the exact current step; execution remains stopped.";
  }
  if (command === "resume") return "Run resumed from its durable checkpoint.";
  return "Run terminated gracefully.";
}

function recoveryReviewError(message: string, remediation: string): Error {
  return Object.assign(new Error(message), {
    humanMessage: message,
    remediation,
  });
}

export function RecoveryPanel({ runId, onChanged }: { runId: string; onChanged: () => void }) {
  const auth = useAuth();
  const actorId = auth.session.actorId ?? "";
  const query = useQuery(`run-recovery:${runId}`, (signal) => operationsApi.recovery(runId, signal), { staleTime: 0 });
  const stream = useEventStream();
  const [reason, setReason] = useState("");
  const [strategyReason, setStrategyReason] = useState("");
  const [targetAgentId, setTargetAgentId] = useState("");
  const [capability, setCapability] = useState("");
  const [providerChoice, setProviderChoice] = useState("");
  const [attempt, setAttempt] = useState<RecoveryMutationAttempt>();
  const [pending, setPending] = useState(false);
  const [mutationError, setMutationError] = useState<Error>();
  const [reconciliationError, setReconciliationError] = useState<Error>();
  const [message, setMessage] = useState<string>();
  const [freshReviewNotice, setFreshReviewNotice] = useState<string>();
  const attemptActionRef = useRef<HTMLDivElement>(null);
  const storage = availableRecoveryAttemptStorage();

  useEffect(() => {
    let active = true;
    setAttempt(undefined);
    setMutationError(undefined);
    setReconciliationError(undefined);
    setFreshReviewNotice(undefined);
    if (!actorId) return () => { active = false; };
    void loadRecoveryMutationAttempt(storage, actorId, runId).then((restored) => {
      if (!active || !restored) return;
      setAttempt(restored);
      setMutationError(recoveryReviewError(
        restored.disposition === "retryable"
          ? "A retryable recovery rejection is awaiting an exact retry."
          : "The earlier recovery response was not received, so its result is not yet confirmed.",
        restored.disposition === "retryable"
          ? "Retry only after Ti-Scale refreshes and reauthorizes the exact represented boundary."
          : "Reconcile the original body and Idempotency-Key with canonical server state before taking another action.",
      ));
    });
    return () => { active = false; };
  }, [actorId, runId]);

  useEffect(() => {
    if (!attempt || attempt.disposition === "dispatching" || pending) return;
    attemptActionRef.current?.querySelector<HTMLButtonElement>("button")?.focus();
  }, [attempt, pending]);

  useEffect(() => {
    if (!attempt) return;
    const delay = Math.max(0, Date.parse(attempt.expiresAt) - Date.now());
    const timeout = window.setTimeout(() => {
      clearRecoveryMutationAttempt(storage, actorId, runId);
      setAttempt(undefined);
      setMutationError(undefined);
      setFreshReviewNotice("The unconfirmed recovery attempt expired. Review current canonical state before creating a fresh request.");
    }, Math.min(delay, 2_147_483_647));
    return () => window.clearTimeout(timeout);
  }, [actorId, attempt?.expiresAt, runId]);

  useEffect(() => {
    if (stream.lastEvent?.runId === runId && !RECOVERY_UNMOUNT_EVENTS.has(stream.lastEvent.type)) query.refresh();
  }, [stream.lastEvent?.id, runId]);

  useEffect(() => {
    if (
      attempt?.disposition !== "retryable"
      || !query.data
      || recoveryAttemptMatchesProjection(attempt, query.data)
    ) return;
    clearRecoveryMutationAttempt(storage, actorId, runId);
    setAttempt(undefined);
    setMutationError(recoveryReviewError(
      "Canonical recovery state changed while the exact retry was waiting.",
      "Review the current run, policy, candidates, and checkpoint before submitting a fresh request.",
    ));
    setFreshReviewNotice("The stale exact retry was cleared. Any new deliberate submission will use a fresh Idempotency-Key.");
  }, [actorId, attempt, query.data, runId]);

  if (query.isLoading) return <Card className="os-recovery-panel"><LoadingPanel label="Loading canonical recovery intelligence" /></Card>;
  if (query.error && !query.data) return <Card className="os-recovery-panel"><ErrorPanel title="Recovery intelligence is unavailable" error={query.error} onRetry={query.refresh} /></Card>;
  const recovery = query.data;
  if (!recovery) return null;
  if (!recovery.recoveryRequired && !attempt) return null;

  const selectedAgent = recovery.reassignmentCandidates.find((candidate) => candidate.agentId === targetAgentId);
  const selectedProvider = recovery.providerCandidates.find(
    (candidate) => providerChoiceValue(candidate) === providerChoice,
  );
  const exactBoundary = recovery.boundary && recovery.checkpoint ? {
    expectedRunVersion: recovery.run.version,
    expectedPlanId: recovery.boundary.planId,
    expectedPlanVersion: recovery.boundary.planVersion,
    expectedStepId: recovery.boundary.stepId,
    expectedAssignmentId: recovery.boundary.assignmentId,
    expectedCheckpointId: recovery.checkpoint.id,
    expectedCheckpointStateHash: recovery.checkpoint.stateHash,
    expectedCheckpointEventSequence: recovery.checkpoint.eventSequence,
  } : null;
  const resumeBoundary = recovery.run.status === "blocked" && recovery.checkpoint && recovery.checkpoint.inFlightActions.length === 0 ? {
    expectedRunVersion: recovery.run.version,
    expectedRunStatus: "blocked" as const,
    expectedCheckpointId: recovery.checkpoint.id,
    expectedCheckpointStateHash: recovery.checkpoint.stateHash,
    expectedCheckpointEventSequence: recovery.checkpoint.eventSequence,
  } : null;
  const guidedBinding = recovery.guidedDecision ? {
    guidedDecisionId: recovery.guidedDecision.id,
    expectedDecisionFingerprint: recovery.guidedDecision.actionFingerprint,
  } : {};

  const actionReady = (action: RecoveryActionAvailability): boolean => {
    if (!action.available || !action.command || pending || attempt) return false;
    if (action.command === "replan") return Boolean(exactBoundary && strategyReason.trim().length >= 12);
    if (action.command === "reassign") return Boolean(exactBoundary && reason.trim() && selectedAgent && capability);
    if (action.command === "change_provider") return Boolean(
      exactBoundary && reason.trim() && selectedProvider?.enabled &&
      selectedProvider.modelId && selectedProvider.modelConfigurationHash,
    );
    if (action.command === "resume") return Boolean(resumeBoundary && reason.trim());
    return Boolean(reason.trim());
  };

  const clearAttempt = () => {
    clearRecoveryMutationAttempt(storage, actorId, runId);
    setAttempt(undefined);
  };

  const clearDraft = () => {
    setReason("");
    setStrategyReason("");
    setTargetAgentId("");
    setCapability("");
    setProviderChoice("");
  };

  const finishMutation = async (command: RecoveryOperationCommand) => {
    clearAttempt();
    clearDraft();
    setMutationError(undefined);
    setFreshReviewNotice(undefined);
    setMessage(recoverySuccessMessage(command));
    onChanged();
    try {
      await query.reconcile();
      setReconciliationError(undefined);
    } catch (cause) {
      setReconciliationError(recoveryReviewError(
        "The recovery receipt was accepted, but current canonical recovery state could not be refreshed.",
        cause instanceof Error
          ? cause.message
          : "Refresh the run before taking another action; do not resubmit the accepted mutation.",
      ));
    }
  };

  const executeAttempt = async (representedAttempt: RecoveryMutationAttempt) => {
    const dispatching: RecoveryMutationAttempt = {
      ...representedAttempt,
      disposition: "dispatching",
      failureCode: null,
    };
    setAttempt(dispatching);
    if (!await saveRecoveryMutationAttempt(storage, dispatching)) {
      setAttempt(representedAttempt.disposition === "dispatching" ? undefined : representedAttempt);
      setMutationError(recoveryReviewError(
        "The exact recovery request could not be persisted before dispatch.",
        "Browser session storage is unavailable or the attempt expired. No request was sent; restore storage access and review current canonical state.",
      ));
      setFreshReviewNotice("No recovery request was dispatched without a durable actor-and-run-scoped exact attempt.");
      setPending(false);
      return;
    }
    setPending(true);
    setMutationError(undefined);
    setReconciliationError(undefined);
    setMessage(undefined);
    try {
      await dispatchRecoveryOperation({
        runId: dispatching.runId,
        command: dispatching.command,
        serializedBody: dispatching.serializedBody,
        idempotencyKey: dispatching.idempotencyKey,
      });
      await finishMutation(dispatching.command);
    } catch (cause) {
      const error = cause instanceof Error ? cause : new Error("Recovery action failed");
      const disposition = classifyRecoveryMutationFailure(error);
      setMutationError(error);
      if (disposition === "fresh_review") {
        clearAttempt();
        setFreshReviewNotice(
          "The server rejected this attempt as nonretryable. Review current canonical state before creating a fresh request and key.",
        );
      } else {
        const retained = withRecoveryAttemptFailure(dispatching, disposition, error);
        setAttempt(retained);
        await saveRecoveryMutationAttempt(storage, retained);
      }
    } finally {
      setPending(false);
    }
  };

  const preparedOperation = (action: RecoveryActionAvailability): PreparedRecoveryOperation | null => {
    if (!action.command) return null;
    if (action.command === "replan" && exactBoundary) {
      return {
        command: "replan",
        body: { ...exactBoundary, strategyReason: strategyReason.trim() },
      };
    } else if (action.command === "reassign" && exactBoundary && selectedAgent) {
      return {
        command: "reassign",
        body: {
          ...exactBoundary,
          targetAgentId: selectedAgent.agentId,
          capability,
          reason: reason.trim(),
          ...guidedBinding,
        },
      };
    } else if (
      action.command === "change_provider" && exactBoundary && selectedProvider?.enabled &&
      selectedProvider.modelId && selectedProvider.modelConfigurationHash
    ) {
      return {
        command: "change_provider",
        body: {
          ...exactBoundary,
          providerId: selectedProvider.providerId,
          modelId: selectedProvider.modelId,
          modelConfigurationHash: selectedProvider.modelConfigurationHash,
          reason: reason.trim(),
          ...guidedBinding,
        },
      };
    } else if (action.command === "resume" && resumeBoundary) {
      return { command: "resume", body: { reason: reason.trim(), ...resumeBoundary } };
    } else if (action.command === "cancel") {
      return { command: "cancel", body: { reason: reason.trim() } };
    }
    return null;
  };

  const perform = (action: RecoveryActionAvailability) => {
    if (!actionReady(action)) return;
    const prepared = preparedOperation(action);
    if (!prepared) return;
    setPending(true);
    setMutationError(undefined);
    setReconciliationError(undefined);
    setMessage(undefined);
    setFreshReviewNotice(undefined);
    void createRecoveryMutationAttempt({
      actorId,
      runId,
      command: prepared.command,
      body: prepared.body,
      idempotencyKey: `recovery-${prepared.command}-${crypto.randomUUID()}`,
      recovery,
    }).then(async (created) => {
      await executeAttempt(created);
    }).catch((cause) => {
      clearAttempt();
      setMutationError(cause instanceof Error
        ? cause
        : new Error("The exact recovery request could not be represented safely."));
      setFreshReviewNotice("No recovery request was dispatched. Review the current fields and remove any credential-like material.");
      setPending(false);
    });
  };

  const reconcileAttempt = async () => {
    if (!attempt || attempt.disposition === "dispatching" || pending) return;
    setPending(true);
    setMutationError(undefined);
    setReconciliationError(undefined);
    let canonical: RunRecoveryRecord;
    try {
      canonical = await operationsApi.recovery(runId);
    } catch (cause) {
      setMutationError(cause instanceof Error ? cause : new Error("Canonical recovery state could not be refreshed"));
      setPending(false);
      return;
    }
    const boundaryMatches = recoveryAttemptMatchesProjection(attempt, canonical);
    if (attempt.disposition === "retryable" && !boundaryMatches) {
      clearAttempt();
      setMutationError(recoveryReviewError(
        "The represented recovery boundary or selected capability changed after the retryable rejection.",
        "Review the refreshed run, plan, step, assignment, checkpoint, policy, and candidate state before submitting a fresh request.",
      ));
      setFreshReviewNotice("Exact retry is disabled because canonical state changed. A fresh review will create a new Idempotency-Key.");
      setPending(false);
      await query.reconcile().catch(() => undefined);
      return;
    }
    // An ambiguous result is never inferred from status alone. Every recovery
    // route receives the exact original key/body after this fresh projection:
    // its canonical idempotency receipt returns the committed result, while a
    // missing receipt must pass the server's current lease and version fences.
    setPending(false);
    await executeAttempt(attempt);
  };

  return <Card className="os-recovery-panel" aria-labelledby={`recovery-${runId}`}>
    <div className="os-card-heading">
      <div>
        <p className="os-eyebrow">Canonical recovery panel</p>
        <h2 id={`recovery-${runId}`}>{recovery.run.journey === "autonomous"
          ? recovery.proposedRecovery.kind === "safe_stop" ? "Autonomous run safe-stopped" : "Autonomous recovery intelligence"
          : recovery.guidedDecision ? "Guided recovery needs your decision" : "Guided recovery intelligence"}</h2>
      </div>
      <StatusPill status={recovery.run.status} />
    </div>
    {query.error && <p className="os-degraded" role="status">Refresh failed; the last validated recovery projection remains visible.</p>}

    <section className="os-recovery-summary" aria-labelledby={`detected-${runId}`}>
      <p className="os-eyebrow">What was detected</p>
      <h3 id={`detected-${runId}`}>{operatorText(recovery.detection.summary, { kind: "status", agent: recovery.run.currentOwnerId })}</h3>
      <KeyValueGrid items={[
        { label: "Failure category", value: recovery.detection.category ?? "Not classified" },
        { label: "Current owner", value: recovery.run.currentOwnerId ?? "Supervisor" },
        { label: "Current step", value: recovery.run.currentStepId ?? "Not reported" },
        { label: "Lease expiry", value: formatTime(recovery.run.leaseExpiresAt) },
      ]} />
    </section>

    <div className="os-recovery-grid">
      <section aria-labelledby={`checkpoint-${runId}`}>
        <p className="os-eyebrow">Last durable boundary</p>
        <h3 id={`checkpoint-${runId}`}>Checkpoint</h3>
        {recovery.checkpoint ? <>
          <KeyValueGrid items={[
            { label: "Recorded", value: formatTime(recovery.checkpoint.createdAt) },
            { label: "Event sequence", value: recovery.checkpoint.eventSequence },
            { label: "Plan version", value: recovery.checkpoint.planVersion ?? "Not recorded" },
            { label: "Completed actions", value: recovery.checkpoint.completedActionCount },
            { label: "In-flight classification", value: recovery.checkpoint.inFlightClassification ?? "No special classification" },
            { label: "In-flight actions", value: recovery.checkpoint.inFlightActions.length },
          ]} />
          <p className="os-muted os-mono">Integrity {recovery.checkpoint.stateHash.slice(0, 16)}…</p>
          {recovery.checkpoint.inFlightActions.length > 0 && <ul className="os-compact-list">
            {recovery.checkpoint.inFlightActions.map((action) => <li key={action.id}><span><strong>{action.id}</strong><small>{action.status} · {action.idempotent ? "idempotent" : "non-idempotent"} · {action.destructive ? "destructive" : "non-destructive"}</small></span></li>)}
          </ul>}
        </> : <p className="os-state-note">No validated checkpoint is available. Resume is disabled.</p>}
      </section>

      <section aria-labelledby={`attempts-${runId}`}>
        <p className="os-eyebrow">Attempts and bounded budgets</p>
        <h3 id={`attempts-${runId}`}>Recovery budget</h3>
        <KeyValueGrid items={[
          { label: "Retries", value: bounded(recovery.attempts.retryCount, recovery.attempts.retryLimit, recovery.attempts.retriesRemaining) },
          { label: "Replans", value: bounded(recovery.attempts.replanCount, recovery.attempts.replanLimit, recovery.attempts.replansRemaining) },
          { label: "Failed actions retained", value: recovery.detection.failedActions.length },
          { label: "Detection events retained", value: recovery.detection.evidence.length },
        ]} />
        {recovery.detection.failedActions.length > 0 && <ol className="os-recovery-attempts">
          {recovery.detection.failedActions.map((action) => <li key={action.id}>
            <div><strong>{operatorText(action.intentSummary, { kind: "action_intent", agent: recovery.run.currentOwnerId })}</strong><StatusPill status={action.status} /></div>
            <p>{operatorText(action.resultSummary, { kind: "action_result" }, "No result summary was recorded.")}</p>
            <small>{action.errorCategory ?? "unclassified"} · action retries {action.retryCount} · {formatTime(action.endedAt)}</small>
          </li>)}
        </ol>}
      </section>
    </div>

    <section className="os-recovery-proposal" aria-labelledby={`proposal-${runId}`}>
      <div className="os-card-heading"><div><p className="os-eyebrow">Proposed recovery</p><h3 id={`proposal-${runId}`}>{operatorText(recovery.proposedRecovery.summary, { kind: "status", agent: recovery.run.currentOwnerId })}</h3></div><StatusPill status={recovery.proposedRecovery.kind} /></div>
      <p>{operatorText(recovery.proposedRecovery.basis, { kind: "status", agent: recovery.run.currentOwnerId })}</p>
      <KeyValueGrid items={[
        { label: "Time impact", value: recovery.proposedRecovery.impact.time },
        { label: "Cost impact", value: recovery.proposedRecovery.impact.cost },
        { label: "Scope impact", value: recovery.proposedRecovery.impact.scope },
        { label: "Next runtime action", value: operatorText(recovery.run.nextAction, { kind: "next_action", agent: recovery.run.currentOwnerId }, "No next action is scheduled") },
      ]} />
      {recovery.guidedDecision && <div className="os-guided-recovery-decision">
        <div><p className="os-eyebrow">Exact Guided decision</p><h4>{recovery.guidedDecision.rationale}</h4><p>{recovery.guidedDecision.riskClass} risk · expires {formatTime(recovery.guidedDecision.expiresAt)}</p></div>
        <ButtonLink href={`/guided/${encodeURIComponent(recovery.run.missionId)}`} variant="primary">Review exact step</ButtonLink>
      </div>}
    </section>

    <div className="os-recovery-grid">
      <section aria-labelledby={`evidence-${runId}`}>
        <p className="os-eyebrow">Detection evidence</p>
        <h3 id={`evidence-${runId}`}>Immutable recovery events</h3>
        {recovery.detection.evidence.length > 0 ? <ol className="os-timeline">
          {recovery.detection.evidence.map((event) => <li key={event.id}><strong>{operatorText(event.summary, { kind: "event" })}</strong><span>{event.eventType} · sequence {event.sequence} · {formatTime(event.occurredAt)}</span></li>)}
        </ol> : <p className="os-muted">No recovery-specific event has been persisted; the run status and failed actions are the available detection evidence.</p>}
      </section>

      <section aria-labelledby={`memory-${runId}`}>
        <p className="os-eyebrow">Failed-attempt memory</p>
        <h3 id={`memory-${runId}`}>Related avoidance knowledge</h3>
        {recovery.failedAttemptMemories.length > 0 ? <ul className="os-compact-list">
          {recovery.failedAttemptMemories.map((item) => <li key={`${item.kind}:${item.id}`}><span><AppLink href={memoryHref(item)}>{item.title}</AppLink><small>{item.kind} · {item.status}{item.failureCategory ? ` · ${item.failureCategory}` : ""}{item.confidence === null ? "" : ` · ${Math.round(item.confidence * 100)}% confidence`}</small></span></li>)}
        </ul> : <p className="os-muted">No scoped failed-attempt memory is linked to this run or failure category.</p>}
      </section>
    </div>

    <section className="os-recovery-actions" aria-labelledby={`actions-${runId}`}>
      <p className="os-eyebrow">Supported recovery controls</p>
      <h3 id={`actions-${runId}`}>Act only through enforced backend boundaries</h3>
      <label><span>Operator reason (audited)</span><input
        value={reason}
        disabled={pending || Boolean(attempt)}
        onChange={(event) => setReason(event.target.value)}
        placeholder="Why is this recovery action necessary?"
      /></label>
      {attempt && <div ref={attemptActionRef} className="os-state-panel os-recovery-mutation-attempt" role="status" aria-live="polite">
        <div className="os-state-symbol" aria-hidden="true">{attempt.disposition === "dispatching" ? "…" : "↻"}</div>
        <div>
          <div className="os-card-heading"><div>
            <strong>{attempt.disposition === "retryable"
              ? "Exact recovery retry available"
              : attempt.disposition === "uncertain"
                ? "Recovery result needs reconciliation"
                : "Submitting exact recovery action"}</strong>
            <p>{attempt.disposition === "retryable"
              ? `The server marked this ${recoveryAttemptCommandLabel(attempt.command)} failure retryable. Ti-Scale will refresh and reauthorize the represented boundary before reusing the exact body and key.`
              : attempt.disposition === "uncertain"
                ? `The ${recoveryAttemptCommandLabel(attempt.command)} response was lost or could not be interpreted. Canonical state and the durable idempotency receipt must be reconciled before another action.`
                : `The exact ${recoveryAttemptCommandLabel(attempt.command)} body and key are awaiting an authoritative response.`}</p>
          </div><StatusPill status={attempt.disposition} /></div>
          <p className="os-mono">Body SHA-256 {attempt.bodySha256.slice(0, 16)}… · expires {formatTime(attempt.expiresAt)}</p>
          {attempt.disposition !== "dispatching" && <div className="os-inline-actions">
            <Button
              type="button"
              data-control-id="run-recovery-exact-attempt"
              disabled={pending}
              onClick={() => void reconcileAttempt()}
            >{attempt.disposition === "retryable"
                ? "Retry exact recovery action"
                : "Reconcile exact recovery attempt"}</Button>
            <Button
              type="button"
              variant="secondary"
              data-control-id="run-recovery-discard-attempt"
              disabled={pending}
              onClick={() => {
                clearAttempt();
                setMutationError(undefined);
                setReconciliationError(undefined);
                setFreshReviewNotice("The unconfirmed local attempt was discarded. Review current canonical state before submitting a fresh request and key.");
              }}
            >Discard attempt and review current state</Button>
          </div>}
        </div>
      </div>}
      <ul>
        {recovery.actions.map((action) => <li key={action.kind}>
          <div className="os-recovery-action-control">
            {action.kind === "replan" && action.available && <label>
              <span>Materially different in-scope strategy</span>
              <textarea disabled={pending || Boolean(attempt)} value={strategyReason} onChange={(event) => setStrategyReason(event.target.value)} placeholder="Describe the new fact or strategy that makes another bounded plan useful." />
            </label>}
            {action.kind === "reassign" && action.available && <>
              <label><span>Healthy capable specialist</span><TitaniumSelect disabled={pending || Boolean(attempt)} value={targetAgentId} onChange={(event) => {
                const next = recovery.reassignmentCandidates.find((candidate) => candidate.agentId === event.target.value);
                setTargetAgentId(event.target.value);
                setCapability(next?.capabilities[0] ?? "");
              }}><option value="">Choose a specialist</option>{recovery.reassignmentCandidates.map((candidate) => <option key={candidate.agentId} value={candidate.agentId}>{candidate.displayName} · {candidate.agentId}</option>)}</TitaniumSelect></label>
              <label><span>Declared shared capability</span><TitaniumSelect value={capability} disabled={!selectedAgent || pending || Boolean(attempt)} onChange={(event) => setCapability(event.target.value)}><option value="">Choose a capability</option>{selectedAgent?.capabilities.map((name) => <option key={name} value={name}>{name}</option>)}</TitaniumSelect></label>
            </>}
            {action.kind === "change_provider" && recovery.providerCandidates.length > 0 && <RecoveryProviderChoices
              candidates={recovery.providerCandidates}
              value={providerChoice}
              disabled={pending || Boolean(attempt)}
              onChange={setProviderChoice}
            />}
            <Button variant={actionVariant(action)} disabled={!actionReady(action)} onClick={() => perform(action)}>{action.label}</Button>
          </div>
          <span><StatusPill status={action.available ? "available" : "unavailable"} />{action.reason}</span>
        </li>)}
      </ul>
      {mutationError && <ErrorPanel title="Recovery action was not accepted" error={mutationError} />}
      {reconciliationError && <ErrorPanel title="Recovery committed; canonical refresh incomplete" error={reconciliationError} onRetry={query.refresh} />}
      {freshReviewNotice && <p role="status" className="os-state-remediation"><strong>Fresh review required.</strong> {freshReviewNotice}</p>}
      {message && <p role="status" className="os-success-note">{message}</p>}
    </section>
    <JsonDetails controlId="live-technical-recovery-wording" label="Technical recovery wording" value={{
      detectionSummary: recovery.detection.summary,
      proposedRecovery: recovery.proposedRecovery,
      nextAction: recovery.run.nextAction,
      failedActions: recovery.detection.failedActions,
      evidence: recovery.detection.evidence,
    }} />
  </Card>;
}

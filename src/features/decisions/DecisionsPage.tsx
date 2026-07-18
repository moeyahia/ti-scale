import { type FormEvent, useState } from "react";
import { operationsApi } from "../../data/api/operations";
import { fetchRuntimeReadiness } from "../../data/api/runtimeReadiness";
import { runtimeV2Api } from "../../data/api/runtimeV2";
import { useQuery } from "../../data/cache/QueryProvider";
import type {
  AdministrativeApprovalInboxRecord,
  AutonomousContractInboxRecord,
  AutonomousExceptionInboxRecord,
  DecisionInboxKind,
  DecisionInboxRecord,
  GuidedDecisionInboxRecord,
} from "../../domain/types/operations";
import type { GuidedDecision, GuidedDecisionControl } from "../../domain/types/runtimeV2";
import { Button, ButtonLink, Card, ErrorPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { CursorControls, FilterForm, formatTime, JsonDetails, QueryBoundary, SelectFilter, StreamState, useActionState, useUrlFilters } from "../runs/OperationalSurface";

const SECTION_ORDER: DecisionInboxKind[] = [
  "autonomous_exception",
  "administrative_approval",
  "guided_decision",
  "autonomous_contract",
];

const SECTION_LABELS: Record<DecisionInboxKind, { title: string; description: string }> = {
  autonomous_exception: {
    title: "Autonomous safe stops and exceptions",
    description: "Explicit canonical exception events. These records never become mid-run approval prompts.",
  },
  administrative_approval: {
    title: "Administrative approvals",
    description: "Future policy, configuration, and review decisions. Resolving one never resumes Autonomous execution.",
  },
  guided_decision: {
    title: "Guided exact-step decisions",
    description: "One fingerprint-bound operator choice for each represented consequential Guided step.",
  },
  autonomous_contract: {
    title: "Autonomous mission contracts",
    description: "Versioned authority and boundary records, including signed and historical contract lineage.",
  },
};

const GUIDED_ACTION_KINDS = new Set([
  "tool",
  "provider_turn",
  "replan",
  "delegation",
  "manual",
] as const);

export type GuidedActionKind = "tool" | "provider_turn" | "replan" | "delegation" | "manual";

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function knownActionKind(value: unknown): GuidedActionKind | null {
  return typeof value === "string" && GUIDED_ACTION_KINDS.has(value as GuidedActionKind)
    ? value as GuidedActionKind
    : null;
}

/**
 * Current represented-step envelopes keep the dispatch kind under `action`.
 * Earlier decisions stored the action fields directly. A conflicting compatibility
 * projection is resolved fail-closed: either representation saying `manual`
 * prevents the UI from offering agent execution.
 */
export function guidedDecisionActionKind(requestedParameters: unknown): GuidedActionKind | null {
  const parameters = record(requestedParameters);
  if (!parameters) return null;
  const nested = knownActionKind(record(parameters.action)?.kind);
  const flattened = knownActionKind(parameters.kind);
  if (nested === "manual" || flattened === "manual") return "manual";
  return nested ?? flattened;
}

export default function DecisionsPage() {
  const filters = useUrlFilters({ limit: "50" });
  const readiness = useQuery("runtime-readiness", fetchRuntimeReadiness, { staleTime: 5_000 });
  const inbox = useQuery(`decision-inbox:${filters.key}`, (signal) => operationsApi.decisionInbox({
    kind: filters.values.kind,
    status: filters.values.status,
    missionId: filters.values.missionId,
    runId: filters.values.runId,
    query: filters.values.query,
    cursor: filters.values.cursor,
    limit: Number(filters.values.limit ?? 50),
  }, signal), { staleTime: 0 });
  return <div className="os-page"><PageHeader eyebrow="Deliberate control" title="Decisions" description="Exact Guided-step decisions and real Autonomous exceptions. Autonomous runs never wait here for routine approval." actions={<StreamState />} />
    <FilterForm filters={filters} searchKey="query" searchLabel="Mission, run, record, or event">
      <SelectFilter filters={filters} name="kind" label="Record type" options={SECTION_ORDER.map((kind) => ({ value: kind, label: SECTION_LABELS[kind].title }))} />
      <SelectFilter filters={filters} name="status" label="State" options={["pending", "attention", "post_run", "draft", "confirmed", "superseded", "revoked", "approved", "manual", "alternative", "rejected", "expired", "cancelled"].map((value) => ({ value, label: value.replaceAll("_", " ") }))} />
      <label><span>Mission ID</span><input value={filters.values.missionId ?? ""} onChange={(event) => filters.set({ missionId: event.target.value || undefined })} /></label>
      <label><span>Run ID</span><input value={filters.values.runId ?? ""} onChange={(event) => filters.set({ runId: event.target.value || undefined })} /></label>
    </FilterForm>
    {readiness.data?.execution.guided === "unavailable" && <p className="os-guided-inline-warning" role="status">Exact Guided runtime controls are read-only because this Ti-Scale instance has no callable Guided provider or execution boundary. Connect and verify that boundary before executing a represented step.</p>}
    <QueryBoundary data={inbox.data?.items} error={inbox.error} isLoading={inbox.isLoading} onRetry={inbox.refresh} emptyTitle="No canonical decision records match" emptyDescription="No signed contract, explicit exception, administrative approval, or exact Guided decision matches these filters.">{(items) => <DecisionInboxSections
      items={items}
      onChanged={inbox.refresh}
      runtimeAvailable={readiness.data?.execution.guided === "ready"}
      availabilityPending={readiness.isLoading}
    />}</QueryBoundary>
    <CursorControls nextCursor={inbox.data?.nextCursor ?? null} cursor={filters.values.cursor} onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })} />
  </div>;
}

export function DecisionInboxSections({ items, onChanged, runtimeAvailable = true, availabilityPending = false }: {
  items: DecisionInboxRecord[];
  onChanged: () => void;
  runtimeAvailable?: boolean;
  availabilityPending?: boolean;
}) {
  return <>{SECTION_ORDER.map((kind) => {
    const records = items.filter((item) => item.kind === kind);
    if (!records.length) return null;
    const section = SECTION_LABELS[kind];
    return <section key={kind} aria-labelledby={`decision-section-${kind}`}>
      <div className="os-section-heading"><div><h2 id={`decision-section-${kind}`}>{section.title}</h2><p>{section.description}</p></div><StatusPill status="canonical">{records.length} on this page</StatusPill></div>
      <div className="os-decision-grid">{records.map((record) => <DecisionInboxCard key={`${record.kind}:${record.id}`} record={record} onChanged={onChanged} runtimeAvailable={runtimeAvailable} availabilityPending={availabilityPending} />)}</div>
    </section>;
  })}</>;
}

function DecisionInboxCard({ record, onChanged, runtimeAvailable, availabilityPending }: { record: DecisionInboxRecord; onChanged: () => void; runtimeAvailable: boolean; availabilityPending: boolean }) {
  if (record.kind === "guided_decision") return <GuidedInboxCard record={record} onChanged={onChanged} runtimeAvailable={runtimeAvailable} availabilityPending={availabilityPending} />;
  if (record.kind === "autonomous_contract") return <ContractCard record={record} />;
  if (record.kind === "autonomous_exception") return <ExceptionCard record={record} />;
  return <AdministrativeApprovalCard record={record} onChanged={onChanged} />;
}

function GuidedInboxCard({ record, onChanged, runtimeAvailable, availabilityPending }: { record: GuidedDecisionInboxRecord; onChanged: () => void; runtimeAvailable: boolean; availabilityPending: boolean }) {
  const decision: GuidedDecision = {
    id: record.id,
    missionId: record.mission.id,
    runId: record.run.id,
    stepId: record.exactStep.stepId,
    status: record.status as GuidedDecision["status"],
    actionFingerprint: record.exactStep.actionFingerprint,
    requestedParameters: record.exactStep.requestedParameters,
    rationale: record.exactStep.rationale,
    riskClass: record.exactStep.riskClass,
    reversibility: record.exactStep.reversibility,
    expiresAt: record.expiresAt ?? record.createdAt,
    createdAt: record.createdAt,
  };
  return <DecisionCard decision={decision} onChanged={onChanged} runtimeAvailable={runtimeAvailable} availabilityPending={availabilityPending} />;
}

function ContractCard({ record }: { record: AutonomousContractInboxRecord }) {
  return <Card>
    <div className="os-card-heading"><div><p className="os-eyebrow">Mission contract · v{record.contract.version}</p><h3>{record.title}</h3></div><StatusPill status={record.contract.state} /></div>
    <p>{record.summary}</p>
    <dl className="os-key-values"><div><dt>Mission</dt><dd>{record.mission.name}</dd></div><div><dt>Contract hash</dt><dd className="os-mono">{record.contract.hash.slice(0, 16)}…</dd></div><div><dt>Confirmed by</dt><dd>{record.contract.confirmedBy ?? "Not confirmed"}</dd></div><div><dt>Confirmed</dt><dd>{formatTime(record.contract.confirmedAt)}</dd></div></dl>
    <ButtonLink variant="secondary" href={record.deepLink}>Open contract settings</ButtonLink>
  </Card>;
}

function ExceptionCard({ record }: { record: AutonomousExceptionInboxRecord }) {
  return <Card>
    <div className="os-card-heading"><div><p className="os-eyebrow">{record.exception.phase === "post_run" ? "Post-run exception" : "Active safe stop"}</p><h3>{record.title}</h3></div><StatusPill status={record.status} /></div>
    <p>{record.summary}</p>
    <dl className="os-key-values"><div><dt>Mission</dt><dd>{record.mission.name}</dd></div><div><dt>Run state</dt><dd>{record.run.status}</dd></div><div><dt>Event</dt><dd className="os-mono">{record.exception.eventType} #{record.exception.sequence}</dd></div><div><dt>Category</dt><dd>{record.exception.category ?? record.exception.code ?? "Not classified"}</dd></div></dl>
    <p className="os-muted">This is an immutable exception record, not an approval request. Continue only through an in-contract recovery, a new run, or a versioned contract amendment.</p>
    <JsonDetails label="Redacted exception detail" value={record.exception.details} />
    <ButtonLink variant="secondary" href={record.deepLink}>Open run recovery</ButtonLink>
  </Card>;
}

export function AdministrativeApprovalCard({ record, onChanged }: { record: AdministrativeApprovalInboxRecord; onChanged: () => void }) {
  const [reason, setReason] = useState("");
  const action = useActionState();
  const submit = (status: "approved" | "rejected", event: { preventDefault(): void }): void => {
    event.preventDefault();
    void action.run(
      () => operationsApi.reviewAdministrativeApproval(
        record.id,
        { status, reason },
        `administrative-review-${crypto.randomUUID()}`,
      ).then(onChanged),
      status === "approved"
        ? "Administrative record approved. No runtime work was resumed."
        : "Administrative record rejected. No runtime work was changed.",
    );
  };
  return <Card>
    <div className="os-card-heading"><div><p className="os-eyebrow">Administrative · {record.approval.approvalType.replaceAll("_", " ")}</p><h3>{record.title}</h3></div><StatusPill status={record.status} /></div>
    <p>{record.summary}</p>
    <dl className="os-key-values"><div><dt>Requested by</dt><dd>{record.approval.requestedBy}</dd></div><div><dt>Policy rule</dt><dd>{record.approval.policyRule ?? "Not specified"}</dd></div><div><dt>Mission</dt><dd>{record.mission?.name ?? "System-wide"}</dd></div><div><dt>Expires</dt><dd>{formatTime(record.expiresAt)}</dd></div></dl>
    <JsonDetails label="Redacted administrative request" value={record.approval.request} />
    {record.approval.reviewAvailable ? <form onSubmit={(event) => submit("approved", event)}>
      <label><span>Required administrative decision reason</span><input required minLength={2} maxLength={2000} value={reason} onChange={(event) => setReason(event.target.value)} /></label>
      <div className="os-inline-actions"><Button disabled={action.pending || reason.trim().length < 2}>Approve for future/admin effect</Button><Button type="button" variant="danger" disabled={action.pending || reason.trim().length < 2} onClick={(event) => submit("rejected", event)}>Reject</Button></div>
      <p className="os-muted">This review updates only the administrative record and audit chain. It cannot authorize or resume an Autonomous action.</p>
    </form> : <p className="os-muted">{record.approval.reviewUnavailableReason ?? "This record is read only."}</p>}
    <ButtonLink variant="secondary" href={record.deepLink}>Open related context</ButtonLink>
    {action.error && <ErrorPanel error={action.error} />}{action.message && <p className="os-success-note" role="status">{action.message}</p>}
  </Card>;
}

export function DecisionCard({ decision, onChanged, runtimeAvailable = true, availabilityPending = false }: {
  decision: GuidedDecision;
  onChanged: () => void;
  runtimeAvailable?: boolean;
  availabilityPending?: boolean;
}) {
  const [authorizationNote, setAuthorizationNote] = useState("");
  const [rejectionReason, setRejectionReason] = useState("");
  const [skipReason, setSkipReason] = useState("");
  const [stopReason, setStopReason] = useState("");
  const [stopConfirmed, setStopConfirmed] = useState(false);
  const action = useActionState();
  const pending = decision.status === "pending" && Date.parse(decision.expiresAt) > Date.now();
  const actionKind = guidedDecisionActionKind(decision.requestedParameters);
  const agentExecutable = actionKind !== null && actionKind !== "manual";
  const submit = (operation: GuidedDecisionControl, event: FormEvent): void => {
    event.preventDefault();
    const exact = {
      expectedFingerprint: decision.actionFingerprint,
      expectedParameters: decision.requestedParameters,
    };
    const body = operation === "reject"
        ? { ...exact, reason: rejectionReason }
        : operation === "stop"
          ? { ...exact, reason: stopReason }
          : operation === "skip"
            ? { ...exact, reason: skipReason }
          : { ...exact, reason: authorizationNote };
    const success = operation === "approve"
      ? "Exact step authorized."
      : operation === "reject"
        ? "Step rejected; the runtime will form a new represented approach."
        : operation === "stop"
            ? "Mission stopped; open work was cancelled and the exact-step control was audited."
            : "Exact step skipped; canonical execution moved to the next valid checkpoint.";
    void action.run(
      () => runtimeV2Api.decision(
        decision.id,
        operation,
        body,
        `decision-${operation}-${crypto.randomUUID()}`,
      ).then(onChanged),
      success,
    );
  };
  return <Card className="os-guided-decision-card">
    <div className="os-card-heading"><div><p className="os-eyebrow">Step {decision.stepId}</p><h3>{decision.rationale}</h3></div><StatusPill status={pending ? decision.status : decision.status === "pending" ? "expired" : decision.status} /></div>
    <dl className="os-key-values"><div><dt>Risk</dt><dd>{decision.riskClass}</dd></div><div><dt>Reversibility</dt><dd>{decision.reversibility}</dd></div><div><dt>Expires</dt><dd>{formatTime(decision.expiresAt)}</dd></div><div><dt>Fingerprint</dt><dd className="os-mono">{decision.actionFingerprint.slice(0, 16)}…</dd></div></dl>
    <JsonDetails label="Exact normalized parameters" value={decision.requestedParameters} />
    {pending && <div className="os-decision-actions">
      {!runtimeAvailable && <p className="os-guided-inline-warning" role="status">{availabilityPending ? "Checking the exact-step runtime boundary." : "This represented decision is read-only until a callable, policy-enforced Guided runtime is connected."}</p>}
      <section aria-labelledby={`execute-${decision.id}`}>
        <h4 id={`execute-${decision.id}`}>Authorize represented execution</h4>
        <p>Authorizes only the fingerprint and normalized parameters shown above.</p>
        <form onSubmit={(event) => submit("approve", event)}>
          <label><span>Optional authorization note</span><input maxLength={2000} value={authorizationNote} onChange={(event) => setAuthorizationNote(event.target.value)} /></label>
          {!agentExecutable
            ? <p className="os-muted">{actionKind === "manual"
              ? "This operator-run step cannot be dispatched through MCP. Perform only the represented procedure, then open the Guided result review below."
              : "This retained step has no recognized executable action kind. It cannot be dispatched; choose another approach or stop safely."}</p>
            : <Button disabled={!runtimeAvailable || availabilityPending || action.pending}>Run this exact step</Button>}
        </form>
      </section>

      <section className="os-decision-completion" aria-labelledby={`complete-${decision.id}`}>
        <h4 id={`complete-${decision.id}`}>I ran it — submit and interpret output</h4>
        <p>Manual completion is evidence-gated. Submit bounded output in the Guided workspace, review the persisted Commander interpretation, then deliberately accept that evidence to advance.</p>
        <ButtonLink variant="secondary" href={`/guided/${encodeURIComponent(decision.missionId)}`}>Open Guided result review</ButtonLink>
      </section>

      <section aria-labelledby={`change-${decision.id}`}>
        <h4 id={`change-${decision.id}`}>Choose a different approach</h4>
        <p>Rejecting does not complete or skip this step. It asks the runtime to recover with a materially different represented action.</p>
        <form onSubmit={(event) => submit("reject", event)}>
          <label><span>Required rejection reason</span><input required minLength={2} maxLength={2000} value={rejectionReason} onChange={(event) => setRejectionReason(event.target.value)} /></label>
          <Button variant="secondary" disabled={!runtimeAvailable || availabilityPending || action.pending || rejectionReason.trim().length < 2}>Reject and replan</Button>
        </form>
      </section>

      <section className="os-decision-skip" aria-labelledby={`skip-${decision.id}`}>
        <h4 id={`skip-${decision.id}`}>Skip this exact step</h4>
        <p id={`skip-warning-${decision.id}`}>Creates no action and no evidence. It marks only this represented step as skipped, records the reason and exact parameter hash, then advances to the next dependency-eligible checkpoint. Mission success is still evaluated from real retained evidence.</p>
        <form onSubmit={(event) => submit("skip", event)}>
          <label><span>Required skip reason</span><input required minLength={2} maxLength={2000} value={skipReason} onChange={(event) => setSkipReason(event.target.value)} aria-describedby={`skip-warning-${decision.id}`} /></label>
          <Button variant="secondary" disabled={!runtimeAvailable || availabilityPending || action.pending || skipReason.trim().length < 2}>Skip exact step</Button>
        </form>
      </section>

      <section className="os-decision-stop" aria-labelledby={`stop-${decision.id}`}>
        <h4 id={`stop-${decision.id}`}>Stop this mission</h4>
        <p id={`stop-warning-${decision.id}`}>Cancels the run and all open work. The stop is bound to this exact pending step and retained in the canonical event and audit history.</p>
        <form onSubmit={(event) => submit("stop", event)}>
          <label><span>Required stop reason</span><input required minLength={2} maxLength={2000} value={stopReason} onChange={(event) => setStopReason(event.target.value)} /></label>
          <label className="os-checkbox-row"><input type="checkbox" checked={stopConfirmed} onChange={(event) => setStopConfirmed(event.target.checked)} aria-describedby={`stop-warning-${decision.id}`} /><span>I understand this stops the entire mission, not only this step.</span></label>
          <Button variant="danger" disabled={!runtimeAvailable || availabilityPending || action.pending || stopReason.trim().length < 2 || !stopConfirmed}>Stop mission</Button>
        </form>
      </section>
    </div>}
    {action.error && <ErrorPanel error={action.error} />}{action.message && <p className="os-success-note" role="status">{action.message}</p>}
  </Card>;
}

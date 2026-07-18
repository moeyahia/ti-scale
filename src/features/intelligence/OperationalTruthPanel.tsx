import {
  type FormEvent,
  type KeyboardEvent,
  type ReactNode,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import { operationalTruthApi } from "../../data/api/operationalTruth";
import { useQuery } from "../../data/cache/QueryProvider";
import type {
  EngagementLogRecordV24,
  EvidenceCandidateStateV24,
  EvidenceCandidateV24,
  ObservationV24,
  OperationalTruthPage,
  VerifiedEvidenceV24,
  VerifyEvidenceCandidateRequestV24,
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
} from "../runs/OperationalSurface";

export type OperationalTruthStage = "logs" | "observations" | "candidates" | "verified";

export const OPERATIONAL_TRUTH_STAGES: readonly {
  readonly id: OperationalTruthStage;
  readonly label: string;
  readonly explanation: string;
}[] = [
  {
    id: "logs",
    label: "Logs",
    explanation: "Chronological technical records. Raw output is not evidence.",
  },
  {
    id: "observations",
    label: "Observations",
    explanation: "Parsed, attributable statements that can remain uncertain or conflicting.",
  },
  {
    id: "candidates",
    label: "Candidates",
    explanation: "Potential support awaiting an explicit human review decision.",
  },
  {
    id: "verified",
    label: "Verified evidence",
    explanation: "Immutable support with provenance, hash, and chain of custody.",
  },
] as const;

export type CandidateReviewAction = "promote" | "reject" | "verify" | "demote";

const CANDIDATE_ACTIONS: Readonly<Record<EvidenceCandidateStateV24, readonly CandidateReviewAction[]>> = {
  candidate: ["promote", "reject"],
  validating: ["verify", "reject"],
  promoted: ["demote"],
  rejected: [],
  demoted: ["promote", "reject"],
};

const CORE_REQUIREMENTS = new Set([
  "immutable_content_hash",
  "attributable_provenance",
  "normalized_target",
  "acquired_time",
  "chain_of_custody",
]);

export function candidateReviewActions(state: EvidenceCandidateStateV24): readonly CandidateReviewAction[] {
  return CANDIDATE_ACTIONS[state];
}

export interface CandidateProvenanceSource {
  readonly kind: "observation" | "engagement_log" | "artifact";
  readonly id: string;
}

export function deriveCandidateProvenanceSources(
  candidate: Pick<EvidenceCandidateV24, "observationId" | "artifactId">,
  observation?: Pick<ObservationV24, "id" | "sources">,
): readonly CandidateProvenanceSource[] {
  if (candidate.observationId && (!observation || observation.id !== candidate.observationId)) {
    throw new Error("The canonical observation detail is required before evidence can be verified.");
  }
  const sources: CandidateProvenanceSource[] = [];
  if (candidate.observationId) {
    sources.push({ kind: "observation", id: candidate.observationId });
    for (const source of observation?.sources ?? []) {
      sources.push({ kind: "engagement_log", id: source.logRecordId });
    }
  }
  if (candidate.artifactId) sources.push({ kind: "artifact", id: candidate.artifactId });
  const unique = new Map(sources.map((source) => [`${source.kind}:${source.id}`, source]));
  if (unique.size === 0) throw new Error("The candidate no longer has a canonical observation or artifact source.");
  return [...unique.values()];
}

export interface EvidenceVerificationFields {
  readonly reason: string;
  readonly source: string;
  readonly target: string;
  readonly acquiredAt: string;
  readonly confidence: number;
  readonly method: string;
  readonly explanation: string;
  readonly custodyActor: string;
  readonly custodyOccurredAt: string;
  readonly confirmedIndependentReview: boolean;
  readonly satisfiedAdditionalRequirements: readonly string[];
}

export function additionalCandidateRequirements(candidate: Pick<EvidenceCandidateV24, "validationRequirements">): readonly string[] {
  return candidate.validationRequirements.filter((requirement) => !CORE_REQUIREMENTS.has(requirement));
}

export function buildEvidenceVerificationRequest(
  candidate: Pick<EvidenceCandidateV24, "state" | "validationRequirements">,
  sources: readonly CandidateProvenanceSource[],
  fields: EvidenceVerificationFields,
): VerifyEvidenceCandidateRequestV24 {
  if (candidate.state !== "validating") throw new Error("Only a validating candidate can be verified.");
  if (!fields.confirmedIndependentReview) throw new Error("Independent human review must be confirmed.");
  const requiredText: Array<[string, string]> = [
    ["Review reason", fields.reason],
    ["Source description", fields.source],
    ["Normalized target", fields.target],
    ["Provenance method", fields.method],
    ["Provenance explanation", fields.explanation],
    ["Custody actor", fields.custodyActor],
  ];
  for (const [label, value] of requiredText) {
    if (value.trim().length < 3) throw new Error(`${label} must contain at least three characters.`);
  }
  if (!Number.isFinite(fields.confidence) || fields.confidence < 0 || fields.confidence > 1) {
    throw new Error("Confidence must be between zero and one.");
  }
  const acquiredAt = new Date(fields.acquiredAt);
  const custodyOccurredAt = new Date(fields.custodyOccurredAt);
  if (Number.isNaN(acquiredAt.getTime()) || Number.isNaN(custodyOccurredAt.getTime())) {
    throw new Error("Acquisition and custody times must be valid.");
  }
  if (custodyOccurredAt.getTime() < acquiredAt.getTime()) {
    throw new Error("The custody event cannot precede acquisition.");
  }
  if (sources.length === 0) throw new Error("At least one canonical provenance source is required.");
  const additional = additionalCandidateRequirements(candidate);
  const satisfied = new Set(fields.satisfiedAdditionalRequirements);
  const missing = additional.filter((requirement) => !satisfied.has(requirement));
  if (missing.length > 0) throw new Error(`Additional requirements remain unsatisfied: ${missing.join(", ")}`);
  return {
    reason: fields.reason.trim(),
    source: fields.source.trim(),
    target: fields.target.trim(),
    acquiredAt: acquiredAt.toISOString(),
    confidence: fields.confidence,
    provenance: {
      method: fields.method.trim(),
      explanation: fields.explanation.trim(),
      sources,
    },
    custody: [{
      eventType: "acquired",
      actor: fields.custodyActor.trim(),
      occurredAt: custodyOccurredAt.toISOString(),
      details: { review: "Canonical source and acquisition were explicitly reviewed by a human operator." },
    }],
    ...(additional.length ? { satisfiedAdditionalRequirements: additional } : {}),
  };
}

export function OperationalTruthStageTabs({
  current,
  onSelect,
  idPrefix = "operational-truth",
}: {
  readonly current: OperationalTruthStage;
  readonly onSelect: (stage: OperationalTruthStage) => void;
  readonly idPrefix?: string;
}) {
  const buttons = useRef<Partial<Record<OperationalTruthStage, HTMLButtonElement>>>({});
  const move = (event: KeyboardEvent<HTMLButtonElement>, stage: OperationalTruthStage): void => {
    const navigationKeys: readonly string[] = ["ArrowLeft", "ArrowRight", "Home", "End"];
    if (!navigationKeys.includes(event.key)) return;
    event.preventDefault();
    const currentIndex = OPERATIONAL_TRUTH_STAGES.findIndex((item) => item.id === stage);
    const nextIndex = event.key === "Home"
      ? 0
      : event.key === "End"
        ? OPERATIONAL_TRUTH_STAGES.length - 1
        : (currentIndex + (event.key === "ArrowRight" ? 1 : -1) + OPERATIONAL_TRUTH_STAGES.length)
          % OPERATIONAL_TRUTH_STAGES.length;
    const next = OPERATIONAL_TRUTH_STAGES[nextIndex]!;
    onSelect(next.id);
    buttons.current[next.id]?.focus();
  };
  return <div className="os-surface-tabs" role="tablist" aria-label="Operational truth stages">
    {OPERATIONAL_TRUTH_STAGES.map((stage) => <button
      key={stage.id}
      ref={(node) => { buttons.current[stage.id] = node ?? undefined; }}
      type="button"
      role="tab"
      id={`${idPrefix}-tab-${stage.id}`}
      aria-controls={`${idPrefix}-panel-${stage.id}`}
      aria-selected={current === stage.id}
      tabIndex={current === stage.id ? 0 : -1}
      onClick={() => onSelect(stage.id)}
      onKeyDown={(event) => move(event, stage.id)}
    >{stage.label}</button>)}
  </div>;
}

export default function OperationalTruthPanel({ missionId, runId }: {
  readonly missionId: string;
  readonly runId?: string;
}) {
  const [stage, setStage] = useState<OperationalTruthStage>("logs");
  const idPrefix = `operational-truth-${useId().replaceAll(":", "")}`;
  const definition = OPERATIONAL_TRUTH_STAGES.find((item) => item.id === stage)!;
  return <section aria-label="Operational truth" className="os-autonomous-branch">
    <Card>
      <div className="os-card-heading">
        <div>
          <p className="os-eyebrow">Operational truth</p>
          <h2>From technical record to verified support</h2>
        </div>
        <StatusPill status="human_review">Human reviewed</StatusPill>
      </div>
      <p className="os-muted">
        Command output remains a troubleshooting log. It becomes evidence only after parsing, explicit review,
        provenance validation, immutable hashing, and a complete chain of custody.
      </p>
    </Card>
    <div>
      <OperationalTruthStageTabs current={stage} onSelect={setStage} idPrefix={idPrefix} />
      <p id={`${idPrefix}-explanation`} className="os-muted">{definition.explanation}</p>
      <div
        role="tabpanel"
        id={`${idPrefix}-panel-${stage}`}
        aria-labelledby={`${idPrefix}-tab-${stage}`}
        aria-describedby={`${idPrefix}-explanation`}
        tabIndex={0}
      >
        {stage === "logs" && <LogsStage missionId={missionId} runId={runId} />}
        {stage === "observations" && <ObservationsStage missionId={missionId} runId={runId} />}
        {stage === "candidates" && <CandidatesStage missionId={missionId} runId={runId} />}
        {stage === "verified" && <VerifiedEvidenceStage missionId={missionId} runId={runId} />}
      </div>
    </div>
  </section>;
}

function useCursor(missionId: string, runId?: string) {
  const [trail, setTrail] = useState<readonly (string | undefined)[]>([undefined]);
  useEffect(() => setTrail([undefined]), [missionId, runId]);
  const cursor = trail[trail.length - 1];
  return {
    cursor,
    page: trail.length,
    first: () => setTrail([undefined]),
    previous: () => setTrail((current) => current.length > 1 ? current.slice(0, -1) : current),
    next: (value: string) => setTrail((current) => [...current, value]),
  };
}

function CursorPager({
  page,
  canGoBack,
  nextCursor,
  onFirst,
  onPrevious,
  onNext,
}: {
  readonly page: number;
  readonly canGoBack: boolean;
  readonly nextCursor: string | null;
  readonly onFirst: () => void;
  readonly onPrevious: () => void;
  readonly onNext: (cursor: string) => void;
}) {
  return <nav className="os-pagination" aria-label="Operational truth pages">
    <span className="os-muted" role="status">Page {page}</span>
    <Button type="button" variant="quiet" disabled={!canGoBack} onClick={onFirst}>First page</Button>
    <Button type="button" variant="secondary" disabled={!canGoBack} onClick={onPrevious}>Previous page</Button>
    <Button type="button" variant="secondary" disabled={!nextCursor} onClick={() => nextCursor && onNext(nextCursor)}>Next page</Button>
  </nav>;
}

function StageBoundary<T>({
  page,
  error,
  loading,
  onRetry,
  loadingLabel,
  emptyTitle,
  emptyDescription,
  children,
}: {
  readonly page?: OperationalTruthPage<T>;
  readonly error?: Error;
  readonly loading: boolean;
  readonly onRetry: () => void;
  readonly loadingLabel: string;
  readonly emptyTitle: string;
  readonly emptyDescription: string;
  readonly children: (page: OperationalTruthPage<T>) => ReactNode;
}) {
  if (loading) return <LoadingPanel label={loadingLabel} />;
  if (error && !page) return <ErrorPanel title={`${loadingLabel} failed`} error={error} onRetry={onRetry} />;
  if (!page?.items.length) return <Card><EmptyState title={emptyTitle} description={emptyDescription} /></Card>;
  return <>{error && <DegradedNotice>Refresh failed. The last validated page remains visible.</DegradedNotice>}{children(page)}</>;
}

function LogsStage({ missionId, runId }: { readonly missionId: string; readonly runId?: string }) {
  const paging = useCursor(missionId, runId);
  const query = useQuery(
    `operational-truth:logs:${missionId}:${runId ?? "all"}:${paging.cursor ?? "first"}`,
    (signal) => operationalTruthApi.listLogs(missionId, {
      ...(runId ? { runId } : {}),
      ...(paging.cursor ? { cursor: paging.cursor } : {}),
      limit: 25,
    }, signal),
  );
  return <StageBoundary
    page={query.data}
    error={query.error}
    loading={query.isLoading}
    onRetry={query.refresh}
    loadingLabel="Loading engagement logs"
    emptyTitle="No technical logs recorded"
    emptyDescription="Authorized tool, provider, and operator records will appear here. An empty log is not an evidence failure."
  >{(page) => <>
    <Card>
      <p className="os-muted"><strong>Technical record only.</strong> These records support troubleshooting and parsing; none is labelled or counted as evidence.</p>
      <ul className="os-semantic-feed">{page.items.map((log) => <LogRecord key={log.id} log={log} />)}</ul>
    </Card>
    <CursorPager page={paging.page} canGoBack={paging.page > 1} nextCursor={page.nextCursor} onFirst={paging.first} onPrevious={paging.previous} onNext={paging.next} />
  </>}</StageBoundary>;
}

function LogRecord({ log }: { readonly log: EngagementLogRecordV24 }) {
  return <li>
    <span className="os-feed-marker" aria-hidden="true" />
    <article>
      <header>
        <div><strong>{log.humanSummary}</strong><span>{log.domain} · {log.recordType}</span></div>
        <StatusPill status={log.severity} />
      </header>
      <p className="os-feed-meta">
        <time dateTime={log.occurredAt}>{formatTime(log.occurredAt)}</time>
        <span>Technical log · not evidence</span>
        {log.agentId && <span>Agent {log.agentId}</span>}
        {log.stepId && <span>Step {log.stepId}</span>}
      </p>
      <JsonDetails label="View redacted technical payload" value={log.technicalPayload} />
    </article>
  </li>;
}

function ObservationsStage({ missionId, runId }: { readonly missionId: string; readonly runId?: string }) {
  const paging = useCursor(missionId, runId);
  const query = useQuery(
    `operational-truth:observations:${missionId}:${runId ?? "all"}:${paging.cursor ?? "first"}`,
    (signal) => operationalTruthApi.listObservations(missionId, {
      ...(runId ? { runId } : {}),
      ...(paging.cursor ? { cursor: paging.cursor } : {}),
      limit: 25,
    }, signal),
  );
  return <StageBoundary
    page={query.data}
    error={query.error}
    loading={query.isLoading}
    onRetry={query.refresh}
    loadingLabel="Loading parsed observations"
    emptyTitle="No observations parsed"
    emptyDescription="Observations appear only after attributable technical records are parsed. They remain distinct from verified evidence."
  >{(page) => <>
    <div className="os-table-wrap"><table className="os-data-table">
      <thead><tr><th>Observation</th><th>State</th><th>Confidence</th><th>Sources</th><th>Last seen</th></tr></thead>
      <tbody>{page.items.map((observation) => <tr key={observation.id}>
        <th scope="row">{observation.statement}<small>{observation.observationType} · structured observation, not evidence</small><JsonDetails label="Normalized observation" value={observation.normalizedValue} /></th>
        <td><StatusPill status={observation.verificationState} /></td>
        <td>{Math.round(observation.confidence * 100)}%</td>
        <td>{observation.sources.length}<small>{observation.sources.map((source) => source.logRecordId).join(", ")}</small></td>
        <td><time dateTime={observation.lastSeenAt}>{formatTime(observation.lastSeenAt)}</time></td>
      </tr>)}</tbody>
    </table></div>
    <CursorPager page={paging.page} canGoBack={paging.page > 1} nextCursor={page.nextCursor} onFirst={paging.first} onPrevious={paging.previous} onNext={paging.next} />
  </>}</StageBoundary>;
}

function CandidatesStage({ missionId, runId }: { readonly missionId: string; readonly runId?: string }) {
  const paging = useCursor(missionId, runId);
  const [selectedId, setSelectedId] = useState<string>();
  const query = useQuery(
    `operational-truth:candidates:${missionId}:${runId ?? "all"}:${paging.cursor ?? "first"}`,
    (signal) => operationalTruthApi.listEvidenceCandidates(missionId, {
      ...(runId ? { runId } : {}),
      ...(paging.cursor ? { cursor: paging.cursor } : {}),
      limit: 25,
    }, signal),
    { staleTime: 0 },
  );
  return <StageBoundary
    page={query.data}
    error={query.error}
    loading={query.isLoading}
    onRetry={query.refresh}
    loadingLabel="Loading evidence candidates"
    emptyTitle="No evidence candidates awaiting review"
    emptyDescription="Potential support appears here only after an observation or artifact is explicitly proposed for human review."
  >{(page) => {
    const selected = page.items.find((item) => item.id === selectedId) ?? page.items[0]!;
    return <>
      <div className="os-master-detail">
        <section>
          <div className="os-table-wrap"><table className="os-data-table">
            <thead><tr><th>Candidate</th><th>State</th><th>Source</th><th>Proposed</th></tr></thead>
            <tbody>{page.items.map((candidate) => <tr key={candidate.id} className={candidate.id === selected.id ? "is-selected" : undefined}>
              <th scope="row"><button type="button" className="os-text-button" onClick={() => setSelectedId(candidate.id)} aria-pressed={candidate.id === selected.id}>{candidate.label}</button><small>{candidate.meaning}</small></th>
              <td><StatusPill status={candidate.state} /></td>
              <td>{candidate.observationId ? "Observation" : "Artifact"}<small className="os-mono">{candidate.observationId ?? candidate.artifactId}</small></td>
              <td><time dateTime={candidate.createdAt}>{formatTime(candidate.createdAt)}</time></td>
            </tr>)}</tbody>
          </table></div>
        </section>
        <aside className="os-detail-panel"><CandidateReviewCard key={`${selected.id}:${selected.state}`} missionId={missionId} candidate={selected} onChanged={query.refresh} /></aside>
      </div>
      <CursorPager page={paging.page} canGoBack={paging.page > 1} nextCursor={page.nextCursor} onFirst={paging.first} onPrevious={paging.previous} onNext={paging.next} />
    </>;
  }}</StageBoundary>;
}

function CandidateReviewCard({
  missionId,
  candidate,
  onChanged,
}: {
  readonly missionId: string;
  readonly candidate: EvidenceCandidateV24;
  readonly onChanged: () => void;
}) {
  const [reason, setReason] = useState("");
  const decision = useActionState();
  const actions = candidateReviewActions(candidate.state);
  const needsObservation = actions.includes("verify") && Boolean(candidate.observationId);
  const observation = useQuery(
    `operational-truth:observation:${missionId}:${needsObservation ? candidate.observationId : "not-required"}`,
    (signal) => needsObservation && candidate.observationId
      ? operationalTruthApi.observation(missionId, candidate.observationId, signal)
      : Promise.resolve(undefined),
  );
  const decide = (action: Exclude<CandidateReviewAction, "verify">): void => {
    const trimmed = reason.trim();
    if (trimmed.length < 12) return;
    const operation = action === "promote"
      ? operationalTruthApi.promoteEvidenceCandidate(missionId, candidate.id, trimmed, `candidate-promote-${crypto.randomUUID()}`)
      : action === "reject"
        ? operationalTruthApi.rejectEvidenceCandidate(missionId, candidate.id, trimmed, `candidate-reject-${crypto.randomUUID()}`)
        : operationalTruthApi.demoteEvidenceCandidate(missionId, candidate.id, trimmed, `candidate-demote-${crypto.randomUUID()}`);
    void decision.run(async () => {
      await operation;
      setReason("");
      onChanged();
    }, action === "promote"
      ? "Candidate moved into human validation. It is not verified evidence yet."
      : action === "reject"
        ? "Candidate rejected with an audited human reason."
        : "Verified evidence demoted; dependent policy checks remain server-enforced.");
  };
  const actionLabels: Record<Exclude<CandidateReviewAction, "verify">, string> = {
    promote: "Begin validation",
    reject: "Reject candidate",
    demote: "Demote evidence",
  };
  return <Card>
    <div className="os-card-heading"><h2>{candidate.label}</h2><StatusPill status={candidate.state} /></div>
    <p>{candidate.meaning}</p>
    <KeyValueGrid items={[
      { label: "Type", value: candidate.evidenceType },
      { label: "Sensitivity", value: candidate.sensitivity },
      { label: "Proposed by", value: candidate.proposedBy },
      { label: "Run", value: candidate.runId ?? "Mission scoped" },
    ]} />
    <h3>Why it was proposed</h3><p className="os-muted">{candidate.promotionReason}</p>
    <h3>Validation requirements</h3>
    <ul className="os-compact-list">{candidate.validationRequirements.map((requirement) => <li key={requirement}><span>{humanize(requirement)}</span><StatusPill status="required">Required</StatusPill></li>)}</ul>
    {candidate.reviewReason && <p className="os-muted"><strong>Last human decision:</strong> {candidate.reviewReason} · {candidate.reviewedBy} · {formatTime(candidate.reviewedAt)}</p>}
    {actions.some((action) => action !== "verify") && <div className="os-review-form">
      <h3>Record a human review decision</h3>
      <p className="os-muted">Explain the attributable reason. Moving a candidate to validation does not make it evidence.</p>
      <label><span>Decision reason</span><textarea value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Explain what was reviewed and why this state change is justified." /></label>
      <div className="os-completion-actions">{actions.filter((action): action is Exclude<CandidateReviewAction, "verify"> => action !== "verify").map((action) => <Button
        key={action}
        type="button"
        variant={action === "reject" || action === "demote" ? "danger" : "primary"}
        disabled={decision.pending || reason.trim().length < 12}
        onClick={() => decide(action)}
      >{decision.pending ? "Recording…" : actionLabels[action]}</Button>)}</div>
    </div>}
    {decision.error && <ErrorPanel title="Review decision was not recorded" error={decision.error} />}
    {decision.message && <p className="os-success-note" role="status">{decision.message}</p>}
    {actions.includes("verify") && candidate.observationId && observation.isLoading && <LoadingPanel label="Resolving canonical observation sources" />}
    {actions.includes("verify") && candidate.observationId && observation.error && !observation.data && <ErrorPanel title="Canonical provenance is unavailable" error={observation.error} onRetry={observation.refresh} />}
    {actions.includes("verify") && (!candidate.observationId || observation.data) && <VerificationForm
      missionId={missionId}
      candidate={candidate}
      observation={observation.data?.observation}
      onChanged={onChanged}
    />}
    {actions.length === 0 && <p className="os-muted">This rejected candidate is retained for audit. It has no valid review mutation from its current state.</p>}
  </Card>;
}

function VerificationForm({
  missionId,
  candidate,
  observation,
  onChanged,
}: {
  readonly missionId: string;
  readonly candidate: EvidenceCandidateV24;
  readonly observation?: ObservationV24;
  readonly onChanged: () => void;
}) {
  const sources = useMemo(() => deriveCandidateProvenanceSources(candidate, observation), [candidate, observation]);
  const defaultAcquiredAt = observation?.lastSeenAt ?? candidate.createdAt;
  const [reason, setReason] = useState("");
  const [source, setSource] = useState(observation?.sourceTool ? `${observation.sourceTool} structured result` : candidate.artifactId ? "Hashed mission artifact" : "Attributed operational record");
  const [target, setTarget] = useState(observation?.assetId ?? "");
  const [acquiredAt, setAcquiredAt] = useState(toLocalDateTime(defaultAcquiredAt));
  const [confidence, setConfidence] = useState(observation?.confidence ?? 0.8);
  const [method, setMethod] = useState(observation ? "Structured observation with independent human review" : "Artifact inspection with independent human review");
  const [explanation, setExplanation] = useState("");
  const [custodyActor, setCustodyActor] = useState(candidate.proposedBy);
  const [custodyOccurredAt, setCustodyOccurredAt] = useState(toLocalDateTime(defaultAcquiredAt));
  const [confirmed, setConfirmed] = useState(false);
  const [satisfied, setSatisfied] = useState<readonly string[]>([]);
  const verification = useActionState();
  const additional = additionalCandidateRequirements(candidate);
  const ready = reason.trim().length >= 12 && source.trim().length >= 3 && target.trim().length >= 3
    && explanation.trim().length >= 12 && method.trim().length >= 3 && custodyActor.trim().length >= 3
    && Boolean(acquiredAt) && Boolean(custodyOccurredAt) && confirmed
    && additional.every((requirement) => satisfied.includes(requirement));
  const submit = (event: FormEvent): void => {
    event.preventDefault();
    if (!ready) return;
    let request: VerifyEvidenceCandidateRequestV24;
    try {
      request = buildEvidenceVerificationRequest(candidate, sources, {
        reason, source, target, acquiredAt, confidence, method, explanation, custodyActor,
        custodyOccurredAt, confirmedIndependentReview: confirmed,
        satisfiedAdditionalRequirements: satisfied,
      });
    } catch (cause) {
      void verification.run(() => Promise.reject(cause), "");
      return;
    }
    void verification.run(async () => {
      await operationalTruthApi.verifyEvidenceCandidate(
        missionId,
        candidate.id,
        request,
        `candidate-verify-${crypto.randomUUID()}`,
      );
      onChanged();
    }, "Evidence verified with canonical provenance and an acquisition custody event.");
  };
  return <form className="os-review-form" onSubmit={submit}>
    <h3>Verify as evidence</h3>
    <p className="os-muted">Verification is an independent human act. The source references below are canonical and cannot be edited here.</p>
    <ul className="os-compact-list">{sources.map((item) => <li key={`${item.kind}:${item.id}`}><span><strong>{humanize(item.kind)}</strong><small className="os-mono">{item.id}</small></span><StatusPill status="bound">Provenance bound</StatusPill></li>)}</ul>
    <label><span>Independent review reason</span><textarea required value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Describe the independent checks that justify verification." /></label>
    <label><span>Source description</span><input required value={source} onChange={(event) => setSource(event.target.value)} /></label>
    <label><span>Normalized target</span><input required value={target} onChange={(event) => setTarget(event.target.value)} placeholder="Exact authorized asset, service, endpoint, or identity" /></label>
    <label><span>Acquired at</span><input required type="datetime-local" value={acquiredAt} onChange={(event) => setAcquiredAt(event.target.value)} /></label>
    <label><span>Confidence ({Math.round(confidence * 100)}%)</span><input type="range" min="0" max="1" step="0.05" value={confidence} onChange={(event) => setConfidence(Number(event.target.value))} /></label>
    <label><span>Provenance method</span><input required value={method} onChange={(event) => setMethod(event.target.value)} /></label>
    <label><span>Provenance explanation</span><textarea required value={explanation} onChange={(event) => setExplanation(event.target.value)} placeholder="Explain how the canonical sources support this evidence and how attribution was checked." /></label>
    <label><span>Acquisition custody actor</span><input required value={custodyActor} onChange={(event) => setCustodyActor(event.target.value)} /></label>
    <label><span>Custody event time</span><input required type="datetime-local" value={custodyOccurredAt} min={acquiredAt} onChange={(event) => setCustodyOccurredAt(event.target.value)} /></label>
    {additional.map((requirement) => <label key={requirement} className="os-check"><input type="checkbox" checked={satisfied.includes(requirement)} onChange={(event) => setSatisfied((current) => event.target.checked ? [...current, requirement] : current.filter((item) => item !== requirement))} /><span>I verified the additional requirement: {humanize(requirement)}</span></label>)}
    <label className="os-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>I independently reviewed attribution, scope, hash-bound source, acquisition time, and custody. I understand raw output alone is not evidence.</span></label>
    {verification.error && <ErrorPanel title="Evidence was not verified" error={verification.error} />}
    {verification.message && <p className="os-success-note" role="status">{verification.message}</p>}
    <Button type="submit" disabled={!ready || verification.pending}>{verification.pending ? "Verifying…" : "Verify evidence"}</Button>
  </form>;
}

function VerifiedEvidenceStage({ missionId, runId }: { readonly missionId: string; readonly runId?: string }) {
  const paging = useCursor(missionId, runId);
  const [selectedId, setSelectedId] = useState<string>();
  const query = useQuery(
    `operational-truth:verified:${missionId}:${runId ?? "all"}:${paging.cursor ?? "first"}`,
    (signal) => operationalTruthApi.listVerifiedEvidence(missionId, {
      ...(runId ? { runId } : {}),
      ...(paging.cursor ? { cursor: paging.cursor } : {}),
      limit: 25,
    }, signal),
  );
  const selected = query.data?.items.find((item) => item.id === selectedId) ?? query.data?.items[0];
  const detail = useQuery(
    `operational-truth:verified-detail:${missionId}:${selected?.id ?? "none"}`,
    (signal) => selected ? operationalTruthApi.verifiedEvidence(missionId, selected.id, signal) : Promise.resolve(undefined),
  );
  return <StageBoundary
    page={query.data}
    error={query.error}
    loading={query.isLoading}
    onRetry={query.refresh}
    loadingLabel="Loading verified evidence"
    emptyTitle="No verified evidence retained"
    emptyDescription="This is a truthful empty state: logs and observations may exist, but nothing has passed the required human evidence gate."
  >{(page) => <>
    <div className="os-master-detail">
      <section><div className="os-table-wrap"><table className="os-data-table">
        <thead><tr><th>Verified evidence</th><th>Target</th><th>Confidence</th><th>Acquired</th></tr></thead>
        <tbody>{page.items.map((evidence) => <tr key={evidence.id} className={evidence.id === selected?.id ? "is-selected" : undefined}>
          <th scope="row"><button type="button" className="os-text-button" onClick={() => setSelectedId(evidence.id)} aria-pressed={evidence.id === selected?.id}>{evidence.summary}</button><small>{evidence.evidenceType} · {evidence.source}</small></th>
          <td>{evidence.target}</td><td>{Math.round(evidence.confidence * 100)}%</td><td><time dateTime={evidence.acquiredAt}>{formatTime(evidence.acquiredAt)}</time></td>
        </tr>)}</tbody>
      </table></div></section>
      <aside className="os-detail-panel"><VerifiedEvidenceDetail selected={selected} data={detail.data} loading={detail.isLoading && Boolean(selected)} error={detail.error} onRetry={detail.refresh} /></aside>
    </div>
    <CursorPager page={paging.page} canGoBack={paging.page > 1} nextCursor={page.nextCursor} onFirst={paging.first} onPrevious={paging.previous} onNext={paging.next} />
  </>}</StageBoundary>;
}

function VerifiedEvidenceDetail({
  selected,
  data,
  loading,
  error,
  onRetry,
}: {
  readonly selected?: VerifiedEvidenceV24;
  readonly data?: Awaited<ReturnType<typeof operationalTruthApi.verifiedEvidence>>;
  readonly loading: boolean;
  readonly error?: Error;
  readonly onRetry: () => void;
}) {
  if (loading) return <LoadingPanel label="Loading evidence provenance and custody" />;
  if (error && !data) return <ErrorPanel title="Evidence detail is unavailable" error={error} onRetry={onRetry} />;
  if (!selected || !data) return <Card><p className="os-muted">Select verified evidence to inspect its canonical provenance and custody history.</p></Card>;
  return <Card>
    <div className="os-card-heading"><h2>{data.evidence.summary}</h2><StatusPill status="verified">Verified</StatusPill></div>
    <KeyValueGrid items={[
      { label: "Target", value: data.evidence.target },
      { label: "Sensitivity", value: data.evidence.sensitivity },
      { label: "Verified by", value: data.evidence.createdBy },
      { label: "Hash", value: <span className="os-mono">{data.evidence.contentHash}</span> },
    ]} />
    <JsonDetails label="Inspect provenance" value={data.evidence.provenance} />
    <h3>Chain of custody</h3>
    {data.chainOfCustody.length ? <ol className="os-timeline">{data.chainOfCustody.map((event) => <li key={event.id}><strong>{humanize(event.eventType)}</strong><span>{event.actor} · {formatTime(event.occurredAt)}</span><JsonDetails label="Custody detail" value={event.details} /></li>)}</ol> : <p className="os-muted">No custody event was returned. This record requires reconciliation before downstream reliance.</p>}
  </Card>;
}

function humanize(value: string): string {
  const result = value.replaceAll("_", " ");
  return result.charAt(0).toUpperCase() + result.slice(1);
}

function toLocalDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

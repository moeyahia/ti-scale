import { useMemo, useState } from "react";
import { confirmMemoryCandidate, fetchMemoryCandidates, rejectMemoryCandidate } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { MEMORY_SENSITIVITIES, type MemoryCandidate, type MemoryScope, type MemorySensitivity } from "../../domain/types/brain";
import { CursorControls, useUrlFilters } from "../runs/OperationalSurface";
import { BrainEmpty, BrainNav, formatBrainDate, scopeLabel } from "./BrainNav";

export function memoryCandidateEditorDefaults(candidate: MemoryCandidate) {
  return {
    title: candidate.title,
    summary: candidate.summary,
    body: candidate.body,
    sensitivity: candidate.sensitivity,
    scopeKind: candidate.scope.kind,
    engagementId: candidate.scope.engagementId ?? "",
    missionId: candidate.scope.missionId ?? "",
  } as const;
}

export function memoryMutationErrorDetails(error: Error) {
  const details = error as Error & { humanMessage?: string; remediation?: string; traceId?: string };
  return {
    message: details.humanMessage ?? error.message,
    remediation: details.remediation,
    traceId: details.traceId,
  } as const;
}

function CandidateCard({ candidate, onChanged }: { candidate: MemoryCandidate; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState(candidate.title);
  const [summary, setSummary] = useState(candidate.summary);
  const [body, setBody] = useState(candidate.body);
  const [sensitivity, setSensitivity] = useState<MemorySensitivity>(candidate.sensitivity);
  const [scopeKind, setScopeKind] = useState<MemoryScope["kind"]>(candidate.scope.kind);
  const [engagementId, setEngagementId] = useState(candidate.scope.engagementId ?? "");
  const [missionId, setMissionId] = useState(candidate.scope.missionId ?? "");
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState("");
  const [suppress, setSuppress] = useState(true);
  const [state, setState] = useState<{ busy: boolean; message?: string; error?: Error }>({ busy: false });
  const toggleEditing = () => {
    if (editing) {
      const defaults = memoryCandidateEditorDefaults(candidate);
      setTitle(defaults.title);
      setSummary(defaults.summary);
      setBody(defaults.body);
      setSensitivity(defaults.sensitivity);
      setScopeKind(defaults.scopeKind);
      setEngagementId(defaults.engagementId);
      setMissionId(defaults.missionId);
    }
    setEditing((value) => !value);
  };
  const scope = (): MemoryScope => scopeKind === "global" ? { kind: "global" } : scopeKind === "engagement" ? { kind: "engagement", engagementId: engagementId.trim() } : { kind: "mission", ...(engagementId.trim() ? { engagementId: engagementId.trim() } : {}), missionId: missionId.trim() };
  const scopeValid = scopeKind === "global" || (scopeKind === "engagement" ? Boolean(engagementId.trim()) : Boolean(missionId.trim()));
  const confirm = async () => {
    setState({ busy: true });
    try {
      await confirmMemoryCandidate(candidate.id, editing ? { title: title.trim(), summary: summary.trim(), body, sensitivity, scope: scope() } : undefined);
      setState({ busy: false, message: "Memory confirmed with its provenance intact." });
      onChanged();
    } catch (error) { setState({ busy: false, error: error instanceof Error ? error : new Error("Unable to confirm memory") }); }
  };
  const reject = async () => {
    if (!reason.trim()) { setState({ busy: false, error: new Error("Record a reason before rejecting this candidate") }); return; }
    setState({ busy: true });
    try {
      const result = await rejectMemoryCandidate(candidate.id, reason.trim(), suppress);
      setState({ busy: false, message: result.suppressionId ? "Rejected and suppressed from immediate relearning." : "Memory candidate rejected without a relearning suppression." });
      onChanged();
    } catch (error) { setState({ busy: false, error: error instanceof Error ? error : new Error("Unable to reject memory") }); }
  };
  return (
    <article className="brain-candidate">
      <header><div><p className="os-eyebrow">{candidate.nodeType.replaceAll("_", " ")} candidate</p><h2>{candidate.title}</h2></div><StatusPill status={candidate.status} /></header>
      <p className="brain-candidate-summary">{candidate.summary}</p>
      <dl><div><dt>Proposed by</dt><dd>{candidate.proposedBy}</dd></div><div><dt>Scope</dt><dd>{scopeLabel(candidate.scope)}</dd></div><div><dt>Sensitivity</dt><dd>{candidate.sensitivity}</dd></div><div><dt>Confidence</dt><dd>{Math.round(candidate.confidence * 100)}%</dd></div><div><dt>Created</dt><dd>{formatBrainDate(candidate.createdAt)}</dd></div></dl>
      <section className="brain-candidate-source"><h3>Why it was proposed</h3><p>{candidate.provenance.explanation}</p>{candidate.provenance.sources.map((source) => <div key={`${source.sourceType}:${source.sourceId}`}><strong>{source.sourceType}</strong><code>{source.sourceId}</code>{source.excerptRedacted && <blockquote>{source.excerptRedacted}</blockquote>}</div>)}</section>
      {editing && <fieldset className="brain-candidate-editor"><legend>Edit before confirming</legend><label>Title<input value={title} onChange={(event) => setTitle(event.target.value)} /></label><label>Summary<textarea value={summary} onChange={(event) => setSummary(event.target.value)} /></label><label>Note body<textarea value={body} onChange={(event) => setBody(event.target.value)} /></label><div className="os-field-grid"><label>Sensitivity<select value={sensitivity} onChange={(event) => setSensitivity(event.target.value as MemorySensitivity)}>{MEMORY_SENSITIVITIES.map((item) => <option key={item}>{item}</option>)}</select></label><label>Scope<select value={scopeKind} onChange={(event) => setScopeKind(event.target.value as MemoryScope["kind"])}><option value="global">Global</option><option value="engagement">Engagement</option><option value="mission">Mission</option></select></label></div>{scopeKind !== "global" && <label>Engagement ID<input value={engagementId} onChange={(event) => setEngagementId(event.target.value)} required={scopeKind === "engagement"} /></label>}{scopeKind === "mission" && <label>Mission ID<input value={missionId} onChange={(event) => setMissionId(event.target.value)} required /></label>}</fieldset>}
      {rejecting && <fieldset className="brain-reject-panel"><legend>Reject candidate</legend><label>Reason<textarea value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Why this should not enter reusable memory" /></label><label className="os-check-field"><input type="checkbox" checked={suppress} onChange={(event) => setSuppress(event.target.checked)} /><span><strong>Do not relearn this memory</strong><small>Create a privacy-safe suppression fingerprint without retaining the rejected content.</small></span></label><Button variant="danger" onClick={reject} disabled={state.busy}>Confirm rejection</Button></fieldset>}
      {state.message && <p className="brain-mutation-note" role="status">{state.message}</p>}
      {state.error && (() => {
        const details = memoryMutationErrorDetails(state.error);
        return <div className="brain-mutation-note is-error" role="alert"><p>{details.message}</p>{details.remediation && <p>{details.remediation}</p>}{details.traceId && <p className="os-mono">Trace {details.traceId}</p>}</div>;
      })()}
      <footer><Button onClick={confirm} disabled={state.busy || !scopeValid || !title.trim() || !summary.trim()}>{editing ? "Confirm edited memory" : "Confirm memory"}</Button><Button variant="secondary" onClick={toggleEditing} disabled={state.busy}>{editing ? "Discard edits" : "Edit then confirm"}</Button><Button variant="quiet" onClick={() => setRejecting((value) => !value)} disabled={state.busy}>{rejecting ? "Cancel rejection" : "Reject"}</Button></footer>
    </article>
  );
}

export default function BrainInboxPage() {
  const filters = useUrlFilters();
  const exactScope = useMemo(() => {
    const missionId = filters.values.missionId?.trim() || undefined;
    const runId = filters.values.runId?.trim() || undefined;
    return { missionId, runId };
  }, [filters.values.missionId, filters.values.runId]);
  const candidateQuery = useMemo(() => ({
    ...exactScope,
    cursor: filters.values.cursor || undefined,
    limit: 50,
  }), [exactScope, filters.values.cursor]);
  const candidates = useQuery(
    `brain-candidates:${exactScope.missionId ?? "all"}:${exactScope.runId ?? "all"}:${filters.values.cursor ?? "first"}`,
    (signal) => fetchMemoryCandidates(candidateQuery, signal),
    { staleTime: 0 },
  );
  const pending = candidates.data?.items.filter((item) => item.status === "pending") ?? [];
  return (
    <div className="os-page brain-page">
      <PageHeader eyebrow="Consent and confirmation" title="Memory Inbox" description="Confirm, correct, scope, or reject proposed memories. Personal preferences remain candidates until your consent policy permits promotion." />
      <BrainNav />
      {exactScope.runId && <Card><p className="os-eyebrow">Exact-run review scope</p><p>Only candidates whose canonical provenance resolves to run <code>{exactScope.runId}</code>{exactScope.missionId ? <> in mission <code>{exactScope.missionId}</code></> : null} are shown.</p></Card>}
      {candidates.isLoading && <LoadingPanel label="Loading memory candidates and provenance" />}
      {candidates.error && !candidates.data && <ErrorPanel error={candidates.error} onRetry={candidates.refresh} />}
      {candidates.data && pending.length === 0 && <Card><BrainEmpty title="No memories awaiting review" description="New operator-preference and uncertain operational candidates will appear here with their source and confidence." /></Card>}
      {pending.length > 0 && <div className="brain-candidate-list">{pending.map((candidate) => <CandidateCard key={candidate.id} candidate={candidate} onChanged={candidates.refresh} />)}</div>}
      {candidates.data && <CursorControls
        cursor={filters.values.cursor}
        nextCursor={candidates.data.nextCursor}
        onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })}
      />}
    </div>
  );
}

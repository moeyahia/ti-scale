import { useEffect, useMemo, useState } from "react";
import { useNavigation } from "../../app/router/navigation";
import { operationsApi } from "../../data/api/operations";
import { confirmMemoryCandidate, fetchContextPacks, fetchMemoryCandidates, rejectMemoryCandidate } from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, ButtonLink, Card, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import type { MemoryCandidate } from "../../domain/types/brain";
import type { FindingRecord, LessonRecord } from "../../domain/types/operations";
import type { RunPlan, RuntimeRun } from "../../domain/types/runtimeV2";
import { budgetStatusLabel, comparisonBasisLabel, completionArtifactPageTruth, completionOutcomeLabel, findingReviewOptions, formatBudgetMetricValue, formatComparisonMetricValue, lessonReviewOptions, summarizeCompletionEvents, unresolvedCompletionTruth, type CompletionArtifactPageTruth, type UnresolvedCompletionTruth } from "../../lib/completionReview";
import { ContextPackPanel } from "../brain/ContextPackPanel";
import { DegradedNotice, formatDuration, formatTime, JsonDetails, percent, useActionState } from "./OperationalSurface";

const TERMINAL = new Set(["completed", "failed", "cancelled"]);

function elapsedSeconds(run: RuntimeRun): number | null {
  if (!run.startedAt || !run.endedAt) return null;
  const elapsed = Date.parse(run.endedAt) - Date.parse(run.startedAt);
  return Number.isFinite(elapsed) && elapsed >= 0 ? elapsed / 1_000 : null;
}

function text(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

function humanStatus(value: string): string {
  return value.replaceAll("_", " ");
}

export function FindingReviewControl({ finding, onReviewed }: { finding: FindingRecord; onReviewed: () => void }) {
  const options = findingReviewOptions(finding.reviewStatus);
  const [status, setStatus] = useState(options[0] ?? "under_review");
  const [reason, setReason] = useState("");
  const [operatorOverride, setOperatorOverride] = useState(false);
  const action = useActionState();
  useEffect(() => {
    setStatus(findingReviewOptions(finding.reviewStatus)[0] ?? "under_review");
    setReason("");
    setOperatorOverride(false);
  }, [finding.reviewStatus, finding.version]);
  if (options.length === 0) return <p className="os-muted">No in-place review transition is available from {humanStatus(finding.reviewStatus)}.</p>;
  const overrideRequired = status === "verified" && finding.evidenceCount === 0;
  return <form className="os-review-form os-inline-review" aria-label={`Review finding ${finding.title}`} onSubmit={(event) => {
    event.preventDefault();
    if (!reason.trim() || action.pending || (overrideRequired && !operatorOverride)) return;
    void action.run(async () => {
      await operationsApi.reviewFinding(finding.id, {
        expectedVersion: finding.version,
        status,
        reason: reason.trim(),
        ...(status === "verified" ? { operatorOverride } : {}),
      }, `completion-finding-${crypto.randomUUID()}`);
      onReviewed();
    }, `Finding moved to ${humanStatus(status)} with an audited version-aware review.`);
  }}>
    <label><span>Review outcome</span><select aria-label={`Finding outcome for ${finding.title}`} value={status} onChange={(event) => { setStatus(event.target.value as typeof status); setOperatorOverride(false); }}>{options.map((item) => <option value={item} key={item}>{humanStatus(item)}</option>)}</select></label>
    <label><span>Review reason</span><textarea aria-label={`Finding review reason for ${finding.title}`} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Evidence-linked reason for this review decision" /></label>
    {overrideRequired && <label className="os-check"><input type="checkbox" checked={operatorOverride} onChange={(event) => setOperatorOverride(event.target.checked)} /><span><strong>Use audited operator override</strong><small>No visible supporting evidence is linked. Verification is blocked unless your identity has override permission; the override and reason are written to the audit chain.</small></span></label>}
    <Button type="submit" variant={status === "rejected" ? "danger" : "secondary"} disabled={action.pending || !reason.trim() || (overrideRequired && !operatorOverride)}>Record finding review</Button>
    {action.error && <ErrorPanel title="Finding review was not recorded" error={action.error} />}
    {action.message && <p role="status" className="os-success-note">{action.message}</p>}
  </form>;
}

export function LessonReviewControl({ lesson, onReviewed }: { lesson: LessonRecord; onReviewed: () => void }) {
  const options = lessonReviewOptions(lesson.status);
  const [status, setStatus] = useState(options[0] ?? "under_review");
  const [reason, setReason] = useState("");
  const action = useActionState();
  useEffect(() => {
    setStatus(lessonReviewOptions(lesson.status)[0] ?? "under_review");
    setReason("");
  }, [lesson.status, lesson.updatedAt]);
  if (options.length === 0) return <p className="os-muted">No in-place review transition is available from {humanStatus(lesson.status)}.</p>;
  return <form className="os-review-form os-inline-review" aria-label={`Review lesson ${lesson.statement}`} onSubmit={(event) => {
    event.preventDefault();
    if (!reason.trim() || action.pending) return;
    void action.run(async () => {
      await operationsApi.reviewLesson(lesson.id, {
        expectedUpdatedAt: lesson.updatedAt,
        status,
        reason: reason.trim(),
      }, `completion-lesson-${crypto.randomUUID()}`);
      onReviewed();
    }, `Lesson moved to ${humanStatus(status)} through independent review.`);
  }}>
    <label><span>Review outcome</span><select aria-label={`Lesson outcome for ${lesson.statement}`} value={status} onChange={(event) => setStatus(event.target.value as typeof status)}>{options.map((item) => <option value={item} key={item}>{humanStatus(item)}</option>)}</select></label>
    <label><span>Independent review reason</span><textarea aria-label={`Lesson review reason for ${lesson.statement}`} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Why the evidence supports this lifecycle decision" /></label>
    <p className="os-muted">Author: {lesson.authoringAgentId ?? "unknown"}. The service blocks an agent from verifying its own lesson and requires supporting evidence.</p>
    <Button type="submit" variant={status === "rejected" ? "danger" : "secondary"} disabled={action.pending || !reason.trim()}>Record lesson review</Button>
    {action.error && <ErrorPanel title="Lesson review was not recorded" error={action.error} />}
    {action.message && <p role="status" className="os-success-note">{action.message}</p>}
  </form>;
}

export function ArtifactReportPageSummary({ truth }: { truth: CompletionArtifactPageTruth }) {
  return <p className="os-muted" data-page-state={truth.partial ? "partial" : "complete"}>{truth.reportSummary}</p>;
}

export function UnresolvedCompletionRecords({ truth, findingsAvailable = true }: {
  truth: UnresolvedCompletionTruth;
  findingsAvailable?: boolean;
}) {
  if (!findingsAvailable) {
    return <>
      {truth.items.length > 0 && <ul className="os-compact-list">{truth.items.map((item) => <li key={`${item.type}:${item.id}`}><span><strong>{item.summary}</strong><small>{item.type} · {item.id}</small></span><StatusPill status={item.status} /></li>)}</ul>}
      <p className="os-muted" data-page-state="unavailable">Finding records are unavailable, so the unresolved review is incomplete and no all-clear result is claimed.</p>
    </>;
  }
  return <>
    {truth.items.length === 0
      ? <p className="os-muted" data-page-state={truth.partial ? "partial" : "complete"}>{truth.emptyMessage}</p>
      : <ul className="os-compact-list">{truth.items.map((item) => <li key={`${item.type}:${item.id}`}><span><strong>{item.summary}</strong><small>{item.type} · {item.id}</small></span><StatusPill status={item.status} /></li>)}</ul>}
    {truth.partialMessage && <p className="os-muted" data-page-state="partial">{truth.partialMessage}</p>}
  </>;
}

function MemoryCandidateReview({ candidate, missionId, runId, onReviewed }: { candidate: MemoryCandidate; missionId: string; runId: string; onReviewed: () => void }) {
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState("");
  const action = useActionState();
  return <article className="os-completion-review-item">
    <div className="os-card-heading"><div><strong>{candidate.title}</strong><p>{candidate.summary}</p></div><StatusPill status={candidate.status} /></div>
    <p className="os-muted">{candidate.nodeType} · {candidate.scope.kind} scope · {candidate.sensitivity} · proposed by {candidate.proposedBy}</p>
    <p><strong>Why proposed:</strong> {candidate.provenance.explanation}</p>
    {rejecting && <label><span>Rejection and do-not-relearn reason</span><textarea aria-label={`Memory rejection reason for ${candidate.title}`} value={reason} onChange={(event) => setReason(event.target.value)} /></label>}
    <div className="os-completion-actions">
      <Button variant="secondary" disabled={action.pending} onClick={() => { void action.run(async () => { await confirmMemoryCandidate(candidate.id); onReviewed(); }, "Memory candidate confirmed with its provenance intact."); }}>Confirm memory</Button>
      <Button variant={rejecting ? "danger" : "quiet"} disabled={action.pending || (rejecting && !reason.trim())} onClick={() => {
        if (!rejecting) { setRejecting(true); return; }
        void action.run(async () => { await rejectMemoryCandidate(candidate.id, reason.trim(), true); onReviewed(); }, "Memory candidate rejected and suppressed from immediate relearning.");
      }}>{rejecting ? "Confirm rejection" : "Reject and do not relearn"}</Button>
      <a className="os-button os-button--quiet" href={`/brain/inbox?missionId=${encodeURIComponent(missionId)}&runId=${encodeURIComponent(runId)}`}>Edit in exact-run Memory Inbox</a>
    </div>
    {action.error && <ErrorPanel title="Memory review was not recorded" error={action.error} />}
    {action.message && <p role="status" className="os-success-note">{action.message}</p>}
  </article>;
}

/** A reusable, real-data completion review rendered only for terminal runs. */
export function CompletionReview({ run, plan, missionSuccessCriteria = [] }: {
  run: RuntimeRun;
  plan?: RunPlan;
  missionSuccessCriteria?: readonly string[];
}) {
  const [selectedContextPackId, setSelectedContextPackId] = useState<string>();
  const [selectedLessonIds, setSelectedLessonIds] = useState<string[]>([]);
  const [followUpReason, setFollowUpReason] = useState("");
  const followUp = useActionState();
  const navigation = useNavigation();
  const evidence = useQuery(`completion-evidence:${run.id}`, (signal) => operationsApi.evidence({ runId: run.id, limit: 100 }, signal), { staleTime: 15_000 });
  const findings = useQuery(`completion-findings:${run.id}`, (signal) => operationsApi.findings({ runId: run.id, limit: 100 }, signal), { staleTime: 15_000 });
  const artifacts = useQuery(`completion-artifacts:${run.id}`, (signal) => operationsApi.artifacts({ runId: run.id, limit: 100 }, signal), { staleTime: 15_000 });
  const evaluations = useQuery(`completion-evaluations:${run.id}`, (signal) => operationsApi.evaluations({ runId: run.id, limit: 10 }, signal), { staleTime: 15_000 });
  const events = useQuery(`completion-events:${run.id}`, (signal) => operationsApi.events({ runId: run.id, limit: 100 }, signal), { staleTime: 15_000 });
  const lessons = useQuery(`completion-lessons:${run.id}`, (signal) => operationsApi.lessons({ runId: run.id, limit: 100 }, signal), { staleTime: 15_000 });
  const lessonUsage = useQuery(`completion-lesson-usage:${run.id}`, (signal) => operationsApi.lessonUsage({ runId: run.id, limit: 100 }, signal), { staleTime: 15_000 });
  const contexts = useQuery(`completion-context-packs:${run.id}`, (signal) => fetchContextPacks({ runId: run.id, journey: run.journey, limit: 200 }, signal), { staleTime: 15_000 });
  const memoryCandidates = useQuery(`completion-memory-candidates:${run.id}`, (signal) => fetchMemoryCandidates({ missionId: run.missionId, runId: run.id, status: "pending", limit: 100 }, signal), { staleTime: 15_000 });

  const eventSummary = useMemo(() => summarizeCompletionEvents(events.data?.items ?? []), [events.data?.items]);
  const contextPackIds = useMemo(() => [...new Set([
    ...eventSummary.contextPackIds,
    ...(lessonUsage.data?.items.map((item) => item.contextPackId).filter((id): id is string => Boolean(id)) ?? []),
    ...(contexts.data?.items.map((item) => item.id) ?? []),
  ])], [contexts.data?.items, eventSummary.contextPackIds, lessonUsage.data?.items]);
  const unresolved = unresolvedCompletionTruth(plan?.steps ?? [], findings.data?.items ?? [], findings.data?.nextCursor);
  const evaluation = evaluations.data?.items[0];
  const artifactTruth = completionArtifactPageTruth(
    artifacts.data?.items.map((item) => item.artifactType) ?? [],
    artifacts.data?.nextCursor,
  );
  const verifiedEvidence = evidence.data?.items.filter((item) => item.verificationState === "verified").length ?? 0;
  const verifiedFindings = findings.data?.items.filter((item) => item.reviewStatus === "verified").length ?? 0;
  const verifiedLessons = lessons.data?.items.filter((item) => item.status === "verified") ?? [];
  const loading = [evidence, findings, artifacts, evaluations, events, lessons, lessonUsage, contexts, memoryCandidates].some((query) => query.isLoading && !query.data);
  const errors = [evidence.error, findings.error, artifacts.error, evaluations.error, events.error, lessons.error, lessonUsage.error, contexts.error, memoryCandidates.error].filter((error): error is Error => Boolean(error));
  const criteria = plan?.steps.flatMap((step) => step.successCriteria.map((criterion) => ({ criterion, status: step.status, step: step.title }))) ?? [];

  if (!TERMINAL.has(run.status)) return null;

  return <section className="os-completion-review" aria-labelledby={`completion-review-${run.id}`}>
    <Card className={`os-completion-hero os-completion-hero--${run.status}`}>
      <div className="os-card-heading"><div><p className="os-eyebrow">Mission completion review</p><h2 id={`completion-review-${run.id}`}>{completionOutcomeLabel(run)}</h2></div><StatusPill status={run.status} /></div>
      <p>{run.statusReason ?? evaluation?.retrospective ?? "The run reached a terminal state. Evaluation details remain linked below."}</p>
      <div className="os-completion-actions">
        <a className="os-button os-button--primary" href={operationsApi.runCompletionExportUrl(run.id)} download>Export authorized completion bundle</a>
        <a className="os-button os-button--secondary" href={operationsApi.evidenceRunExportUrl(run.id)}>Export bounded evidence metadata</a>
        <a className="os-button os-button--secondary" href={operationsApi.runAuditExportUrl(run.id)}>Export restricted run audit</a>
        <ButtonLink href={`/intelligence/evidence?runId=${encodeURIComponent(run.id)}`} variant="secondary">Review evidence</ButtonLink>
        <ButtonLink href={`/reports?runId=${encodeURIComponent(run.id)}`} variant="quiet">Open reports</ButtonLink>
      </div>
      <p className="os-muted">Every export is server-generated for this exact run and scope-checked. The completion and evidence bundles are bounded and metadata-only; the restricted audit export is redacted and may omit adjacent hashes outside your visible scope. Raw evidence, storage paths, tool/provider payloads, memory-note bodies, and authentication material are excluded.</p>
    </Card>

    {loading && <LoadingPanel label="Assembling evidence-linked completion records" />}
    {errors.length > 0 && <DegradedNotice>{errors.length} completion data source{errors.length === 1 ? " is" : "s are"} unavailable. The visible records remain authoritative; retry from the linked domain view.</DegradedNotice>}

    <section className="os-metric-row" aria-label="Completion metrics">
      <div><span>Visible evidence verified</span><strong>{verifiedEvidence}/{evidence.data?.items.length ?? 0}{evidence.data?.nextCursor ? "+" : ""}</strong></div>
      <div><span>Visible findings verified</span><strong>{verifiedFindings}/{findings.data?.items.length ?? 0}{findings.data?.nextCursor ? "+" : ""}</strong></div>
      <div><span>Evidence coverage</span><strong>{percent(evaluation?.evidenceCoverage)}</strong></div>
      <div><span>Elapsed</span><strong>{formatDuration(elapsedSeconds(run))}</strong></div>
    </section>

    <div className="os-completion-grid">
      <Card>
        <div className="os-card-heading"><div><p className="os-eyebrow">Outcome validation</p><h3>Success criteria and evaluation</h3></div><StatusPill status={evaluation ? "evaluated" : "pending"} /></div>
        {missionSuccessCriteria.length > 0 && <><h4>Mission criteria</h4><ul className="os-compact-list">{missionSuccessCriteria.map((criterion) => <li key={criterion}><span>{criterion}</span><StatusPill status={evaluation ? "evaluation_recorded" : "awaiting_evaluation"} /></li>)}</ul><p className="os-muted">A run evaluation is shown at aggregate level. A criterion is not labeled passed unless a canonical per-criterion verdict exists.</p></>}
        {criteria.length > 0 && <><h4>Plan criteria</h4><ul className="os-compact-list">{criteria.map((item, index) => <li key={`${item.step}:${index}`}><span><strong>{item.criterion}</strong><small>{item.step}</small></span><StatusPill status={item.status} /></li>)}</ul></>}
        {!evaluation && <p className="os-muted">No journey-aware run evaluation has been persisted yet. The terminal outcome is visible, but the system does not claim an evaluation score.</p>}
        {evaluation && <><p>{evaluation.retrospective}</p><JsonDetails label="Evaluation scores and measured metrics" value={{ scores: evaluation.scores, metrics: evaluation.metrics, createdAt: evaluation.createdAt }} /></>}
      </Card>

      <Card aria-label="Terminal run budget review">
        <div className="os-card-heading"><div><p className="os-eyebrow">Budget accountability</p><h3>Limit versus recorded usage</h3></div><StatusPill status={evaluation ? "recorded" : "unknown"} /></div>
        {!evaluation && <p className="os-muted">Budget usage is unknown because no canonical terminal evaluation is available. Ti-Scale does not infer usage from UI activity.</p>}
        {evaluation && <>
          <ul className="os-compact-list os-budget-review-list">{evaluation.budget.metrics.map((metric) => <li key={metric.key}>
            <span><strong>{metric.label}</strong><small>Usage {formatBudgetMetricValue(metric, metric.usage)} · limit {metric.limitStatus === "configured" ? formatBudgetMetricValue(metric, metric.limit) : "not configured"}</small><small>{metric.usageStatus === "recorded_estimate" ? "Recorded estimate" : metric.usageStatus === "recorded_exact" ? "Recorded exact usage" : "Usage was not verifiably reported"} · {metric.usageSource?.replaceAll("_", " ") ?? "source unavailable"}</small></span>
            <StatusPill status={metric.status}>{budgetStatusLabel(metric)}</StatusPill>
          </li>)}</ul>
          <p className="os-muted">Provider-token usage remains unknown when any provider turn omitted exact token counts. Cost is always labeled as an estimate. A missing limit means no terminal-run limit was configured; it never means unlimited usage was verified.</p>
        </>}
      </Card>

      <Card>
        <div className="os-card-heading"><div><p className="os-eyebrow">Reliability and policy</p><h3>Retries, recoveries, and interventions</h3></div><StatusPill status={eventSummary.safeStopEvents > 0 ? "safe_stopped" : "recorded"} /></div>
        <dl className="os-review-grid"><div><dt>Retry events</dt><dd>{eventSummary.retryEvents}</dd></div><div><dt>Recovery events</dt><dd>{eventSummary.recoveryEvents}</dd></div><div><dt>Policy/decision events</dt><dd>{eventSummary.policyEvents}</dd></div><div><dt>Safe stops</dt><dd>{eventSummary.safeStopEvents}</dd></div></dl>
        <p className="os-muted">Counts reflect the latest 100 scope-visible semantic events; the downloadable bundle includes up to 1,000 records per domain and declares truncation.</p>
        {(events.data?.items ?? []).filter((item) => /recover|retry|policy|contract|scope|approval|decision/iu.test(`${item.eventType} ${item.summary}`)).slice(0, 6).map((item) => <article className="os-completion-event" key={item.id}><strong>{item.summary}</strong><span>{item.eventType} · {formatTime(item.occurredAt)}</span></article>)}
      </Card>

      <Card>
        <div className="os-card-heading"><div><p className="os-eyebrow">Measured comparison</p><h3>Comparable prior-run performance</h3></div><StatusPill status={evaluation?.comparison.status === "available" ? "recorded" : "insufficient_data"} /></div>
        {!evaluation && <p className="os-muted">Insufficient comparable data: the current run does not yet have a persisted evaluation.</p>}
        {evaluation && <>
          <p>{evaluation.comparison.summary}</p>
          <dl className="os-review-grid">
            <div><dt>Basis</dt><dd>{comparisonBasisLabel(evaluation.comparison.basis)}</dd></div>
            <div><dt>Prior outcome</dt><dd>{evaluation.comparison.prior?.terminalStatus ?? "Not available"}</dd></div>
            <div><dt>Outcome matched</dt><dd>{evaluation.comparison.terminalStatusMatch === null ? "Not available" : evaluation.comparison.terminalStatusMatch ? "Yes" : "No"}</dd></div>
            <div><dt>Metrics compared</dt><dd>{evaluation.comparison.metrics.length}</dd></div>
          </dl>
          {evaluation.comparison.status === "available" && <ul className="os-compact-list">
            {evaluation.comparison.metrics.map((metric) => <li key={metric.key}><span><strong>{metric.label}</strong><small>Current {formatComparisonMetricValue(metric, metric.current)} · prior {formatComparisonMetricValue(metric, metric.prior)} · delta {metric.delta > 0 ? "+" : ""}{formatComparisonMetricValue(metric, metric.delta)}</small></span><StatusPill status={metric.movement}>{metric.movement}</StatusPill></li>)}
          </ul>}
          <p className="os-muted">The baseline is selected deterministically from canonical evaluations and never crosses an engagement. Directional changes are descriptive and are not proof that the system improved.</p>
        </>}
      </Card>

      <Card>
        <div className="os-card-heading"><div><p className="os-eyebrow">Intelligence</p><h3>Evidence, findings, and deliverables</h3></div><StatusPill status={(findings.data?.nextCursor || artifacts.data?.nextCursor) ? "partial" : evidence.data?.items.length ? "available" : "empty"} /></div>
        <ul className="os-compact-list">
          {(findings.data?.items ?? []).slice(0, 6).map((finding) => <li key={finding.id}><span><strong>{finding.title}</strong><small>{finding.evidenceCount} linked evidence · {finding.severity} · version {finding.version}</small><FindingReviewControl finding={finding} onReviewed={findings.refresh} /></span><StatusPill status={finding.reviewStatus} /></li>)}
          {findings.data && findings.data.items.length === 0 && <li><span>{findings.data.nextCursor ? "No finding records are visible in this loaded page; additional records were not loaded." : "No finding records were produced for this run."}</span></li>}
          {!findings.data && !findings.isLoading && <li><span>Finding records are unavailable; no total is claimed.</span></li>}
        </ul>
        <h4>Artifacts and reports</h4>
        <ul className="os-compact-list">{(artifacts.data?.items ?? []).slice(0, 6).map((artifact) => <li key={artifact.id}><span><strong>{artifact.artifactType}</strong><small>{artifact.byteSize.toLocaleString()} B · {artifact.contentHash.slice(0, 12)}…</small></span><StatusPill status={artifact.storage.available ? "available" : "unavailable"} /></li>)}{artifacts.data && artifacts.data.items.length === 0 && <li><span>{artifactTruth.emptyArtifactMessage}</span></li>}{!artifacts.data && !artifacts.isLoading && <li><span>Artifact metadata is unavailable; no total is claimed.</span></li>}</ul>
        {artifacts.data
          ? <ArtifactReportPageSummary truth={artifactTruth} />
          : <p className="os-muted" data-page-state="unavailable">Report count is unavailable until artifact metadata loads.</p>}
      </Card>

      <Card>
        <div className="os-card-heading"><div><p className="os-eyebrow">Second Brain and learning</p><h3>Context used and lessons proposed</h3></div><StatusPill status={contextPackIds.length ? "recorded" : "not_used"} /></div>
        <ul className="os-compact-list">{(lessonUsage.data?.items ?? []).map((usage) => <li key={usage.id}><span><strong>{usage.lesson.statement}</strong><small>{usage.influenceSummary}</small></span><StatusPill status="reused" /></li>)}{(lessonUsage.data?.items.length ?? 0) === 0 && <li><span>No verified lesson usage was recorded for this run.</span></li>}</ul>
        {(lessons.data?.items.length ?? 0) > 0 && <section aria-label="Exact-run lesson reviews"><h4>Lessons proposed from this exact run</h4>{lessons.data?.items.map((lesson) => <article className="os-completion-review-item" key={lesson.id}><div className="os-card-heading"><div><strong>{lesson.statement}</strong><p>{lesson.supportingEvidenceCount} supporting record{lesson.supportingEvidenceCount === 1 ? "" : "s"} · {lesson.applicabilityScope}</p></div><StatusPill status={lesson.status} /></div><LessonReviewControl lesson={lesson} onReviewed={lessons.refresh} /></article>)}</section>}
        {(lessons.data?.items.length ?? 0) === 0 && <p className="os-muted">No lesson candidate is linked through canonical provenance to this exact run.</p>}
        {(memoryCandidates.data?.items.length ?? 0) > 0 && <section aria-label="Exact-run memory candidate reviews"><h4>Memory candidates from this exact run</h4>{memoryCandidates.data?.items.map((candidate) => <MemoryCandidateReview key={candidate.id} candidate={candidate} missionId={run.missionId} runId={run.id} onReviewed={memoryCandidates.refresh} />)}</section>}
        {(memoryCandidates.data?.items.length ?? 0) === 0 && <p className="os-muted">No pending memory candidate has provenance resolving to this exact run.</p>}
        {contextPackIds.length > 0 && <div className="os-context-pack-links"><span>Inspectable context packs</span>{contextPackIds.map((packId) => { const context = contexts.data?.items.find((item) => item.id === packId); return <Button key={packId} variant="quiet" onClick={() => setSelectedContextPackId(selectedContextPackId === packId ? undefined : packId)}>{selectedContextPackId === packId ? "Hide context" : context?.purpose ?? `Inspect ${packId}`}</Button>; })}</div>}
        {selectedContextPackId && <ContextPackPanel packId={selectedContextPackId} />}
        <ButtonLink href={`/brain/graph?view=mission&mission=${encodeURIComponent(run.missionId)}`} variant="secondary">Open mission memory graph</ButtonLink>
      </Card>
    </div>

    <Card className="os-unresolved-review">
      <div className="os-card-heading"><div><p className="os-eyebrow">Follow-up</p><h3>Unresolved items</h3></div><StatusPill status={findings.data ? unresolved.status : unresolved.items.length ? "attention" : "unknown"}>{findings.data ? unresolved.statusLabel : unresolved.items.length ? "Attention · incomplete" : "Incomplete"}</StatusPill></div>
      <UnresolvedCompletionRecords truth={unresolved} findingsAvailable={Boolean(findings.data)} />
      {run.statusReason && <p><strong>Terminal reason:</strong> {text(run.statusReason)}</p>}
    </Card>

    <Card className="os-follow-up-review">
      <div className="os-card-heading">
        <div><p className="os-eyebrow">Next execution attempt</p><h3>Create a follow-up run</h3></div>
        <StatusPill status={run.journey} />
      </div>
      <p>This creates another run on the same durable mission. It preserves the {run.journey === "autonomous" ? "signed Autonomous contract" : "Guided exact-step boundary"}; changing the objective, scope, or journey requires a new mission or versioned amendment.</p>
      <form className="os-review-form" onSubmit={(event) => {
        event.preventDefault();
        if (!followUpReason.trim() || followUp.pending) return;
        void followUp.run(async () => {
          const created = await operationsApi.createFollowUpRun(
            run.id,
            { reason: followUpReason.trim(), selectedLessonIds },
            `follow-up-${crypto.randomUUID()}`,
          );
          navigation.navigate(created.nextUrl);
        }, "Follow-up run created with an audited context selection.");
      }}>
        <fieldset>
          <legend>Verified lessons eligible for planning</legend>
          {verifiedLessons.length > 0 ? <ul className="os-compact-list">
            {verifiedLessons.map((lesson) => <li key={lesson.id}>
              <label className="os-check">
                <input
                  type="checkbox"
                  checked={selectedLessonIds.includes(lesson.id)}
                  onChange={(event) => setSelectedLessonIds((current) => event.target.checked
                    ? [...new Set([...current, lesson.id])]
                    : current.filter((id) => id !== lesson.id))}
                />
                <span><strong>{lesson.statement}</strong><small>{lesson.applicabilityScope} · {lesson.supportingEvidenceCount} supporting record{lesson.supportingEvidenceCount === 1 ? "" : "s"} · used {lesson.usageCount} time{lesson.usageCount === 1 ? "" : "s"}</small></span>
              </label>
            </li>)}
          </ul> : <p className="os-muted">No independently verified mission lesson is currently eligible for explicit selection. The follow-up can still start without retained lesson context.</p>}
          <p className="os-muted">Selection makes a lesson eligible for this plan. Ti-Scale records reuse only if the planner actually cites the verified lesson and explains its influence.</p>
        </fieldset>
        <label><span>Reason for the follow-up (audited)</span><textarea value={followUpReason} onChange={(event) => setFollowUpReason(event.target.value)} placeholder="What should this new attempt validate, recover, or improve?" /></label>
        <div className="os-completion-actions">
          <Button type="submit" variant="primary" disabled={followUp.pending || !followUpReason.trim()}>Create follow-up run</Button>
          <ButtonLink href="/missions/new" variant="quiet">Create a different mission</ButtonLink>
          <ButtonLink href="/learning" variant="secondary">Review lesson candidates</ButtonLink>
        </div>
      </form>
      {followUp.error && <ErrorPanel title="Follow-up run was not created" error={followUp.error} />}
      {followUp.message && <p role="status" className="os-success-note">{followUp.message}</p>}
    </Card>
  </section>;
}

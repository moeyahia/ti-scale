import {
  type FormEvent,
  useEffect,
  useRef,
  useState,
} from "react";
import { cveIntelligenceApi } from "../../data/api/cveIntelligence";
import {
  Button,
  Card,
  ErrorPanel,
  StatusPill,
} from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import type {
  CveApplicabilityRecord,
  CveApplicabilityReviewDecision,
} from "../../domain/types/cveIntelligence";

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(parsed);
}

function readable(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/gu, (character) => (
    character.toLocaleUpperCase()
  ));
}

export function CveApplicabilityReview({
  record,
  open,
  onToggle,
  onReviewed,
}: {
  readonly record: CveApplicabilityRecord;
  readonly open: boolean;
  readonly onToggle: (open: boolean) => void;
  readonly onReviewed: () => Promise<void>;
}) {
  const [decision, setDecision] = useState<CveApplicabilityReviewDecision | "">("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState<Error>();
  const [outcome, setOutcome] = useState("");
  const [reconciliationError, setReconciliationError] = useState<Error>();
  const activeRequest = useRef<AbortController | undefined>(undefined);

  useEffect(() => () => activeRequest.current?.abort(), []);
  useEffect(() => {
    activeRequest.current?.abort();
    activeRequest.current = undefined;
    setDecision("");
    setReason("");
    setBusy(false);
    setMutationError(undefined);
    setOutcome("");
    setReconciliationError(undefined);
  }, [record.id]);

  const canConclude = Boolean(
    record.runId
    && record.detectedVersion
    && record.affectedRange
    && record.versionEvidenceId,
  );
  const canSubmit = Boolean(
    record.runId
    && decision
    && reason.trim().length >= 3
    && !busy
    && (decision === "request_more_evidence" || canConclude),
  );

  const reconcile = async (): Promise<void> => {
    setMutationError(undefined);
    setReconciliationError(undefined);
    try {
      await onReviewed();
    } catch (error) {
      setReconciliationError(error instanceof Error
        ? error
        : new Error("The canonical CVE review could not be reloaded"));
    }
  };

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (!canSubmit || !decision || !record.runId) return;
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    setBusy(true);
    setMutationError(undefined);
    setOutcome("");
    setReconciliationError(undefined);
    try {
      const result = await cveIntelligenceApi.review(record.missionId, record.id, {
        expectedRunId: record.runId,
        decision,
        reason: reason.trim(),
        expectedReviewVersion: record.reviewVersion,
        expectedUpdatedAt: record.updatedAt,
      }, controller.signal);
      setDecision("");
      setReason("");
      setOutcome(
        `${result.record.cveId} review version ${result.receipt.version} was committed as `
        + `${readable(result.record.reviewState)}. Audit ${result.receipt.auditRecordId} and event `
        + `${result.receipt.eventId} are retained.`,
      );
      try {
        await onReviewed();
      } catch (error) {
        setReconciliationError(new Error(
          `Review version ${result.receipt.version} was committed, but the canonical CVE list could not be refreshed. Reload the current review before another decision.`,
          { cause: error },
        ));
      }
    } catch (error) {
      if (!controller.signal.aborted) {
        setMutationError(error instanceof Error
          ? error
          : new Error("The CVE applicability review could not be committed"));
      }
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = undefined;
        setBusy(false);
      }
    }
  };

  const latest = record.latestReview;
  return <section
    className="os-section-stack"
    aria-label={`Applicability review for ${record.cveId}`}
  >
    <div>
      <Button
        type="button"
        variant={open ? "secondary" : "quiet"}
        data-control-id="cve-applicability-review-toggle"
        aria-expanded={open}
        aria-controls={`cve-review-editor-${record.id}`}
        onClick={() => onToggle(!open)}
      >
        {open ? `Close review for ${record.cveId}` : `Review ${record.cveId} applicability`}
      </Button>
    </div>

    {open && <Card
      id={`cve-review-editor-${record.id}`}
      className="os-section-stack"
      aria-labelledby={`cve-review-heading-${record.id}`}
    >
      <div className="os-card-heading">
        <div>
          <p className="os-eyebrow">Human-owned versioned decision</p>
          <h4 id={`cve-review-heading-${record.id}`}>Review {record.cveId} applicability</h4>
        </div>
        <StatusPill status={record.reviewState}>
          {readable(record.reviewState)} · v{record.reviewVersion}
        </StatusPill>
      </div>
      <p>
        This decision changes only the mission-scoped applicability record. It
        never contacts the target. Every accepted version retains an immutable
        receipt, hash-linked audit record, and run event.
      </p>

      {latest
        ? <section aria-label={`Latest review receipt for ${record.cveId}`}>
            {record.reviewState === "unreviewed" && <p role="status">
              <strong>Fresh review required.</strong> Source intelligence changed after
              receipt v{latest.version}; the prior receipt remains immutable.
            </p>}
            <dl className="os-key-values">
              <div><dt>Latest decision</dt><dd>{readable(latest.decision)}</dd></div>
              <div><dt>Review reason</dt><dd>{latest.reason}</dd></div>
              <div><dt>Reviewer</dt><dd>{latest.actor.id} · {latest.actor.type}</dd></div>
              <div><dt>Reviewed</dt><dd>{formatTimestamp(latest.createdAt)}</dd></div>
              <div><dt>Audit record</dt><dd><code>{latest.auditRecordId}</code></dd></div>
              <div><dt>Run event</dt><dd><code>{latest.eventId}</code></dd></div>
            </dl>
          </section>
        : <p className="os-muted">No human applicability review has been recorded.</p>}

      {!record.runId
        ? <p role="status">
            This record is not linked to a canonical run and remains read-only.
          </p>
        : <form onSubmit={(event) => { void submit(event); }} aria-busy={busy || undefined}>
            <label>
              <span>Review decision <small>Required</small></span>
              <TitaniumSelect
                data-control-id="cve-applicability-review-decision"
                aria-label={`Review decision for ${record.cveId}`}
                value={decision}
                disabled={busy}
                loading={busy}
                onChange={(event) => {
                  setDecision(event.target.value as CveApplicabilityReviewDecision | "");
                  setMutationError(undefined);
                  setOutcome("");
                }}
              >
                <option value="">Choose a review decision</option>
                <option value="confirm_applicability" disabled={!canConclude}>
                  Confirm applicability
                </option>
                <option value="mark_not_applicable" disabled={!canConclude}>
                  Mark not applicable
                </option>
                <option value="request_more_evidence">Request more evidence</option>
              </TitaniumSelect>
            </label>
            {!canConclude && <p className="os-muted">
              Confirm and not-applicable decisions remain unavailable until a
              detected version, affected range, and verified version-evidence
              record are all attached.
            </p>}
            <label>
              <span>Review reason <small>Required · 3–4,000 characters</small></span>
              <textarea
                data-control-id="cve-applicability-review-reason"
                aria-label={`Review reason for ${record.cveId}`}
                value={reason}
                minLength={3}
                maxLength={4_000}
                required
                disabled={busy}
                onChange={(event) => {
                  setReason(event.target.value);
                  setMutationError(undefined);
                  setOutcome("");
                }}
                placeholder="State what the retained evidence supports or what additional evidence is required."
              />
            </label>
            <Button
              type="submit"
              data-control-id="cve-applicability-review-submit"
              aria-label={`Commit review decision for ${record.cveId}`}
              disabled={!canSubmit}
            >
              {busy ? "Committing review…" : "Commit versioned review"}
            </Button>
          </form>}

      {mutationError && <>
        <ErrorPanel
          title={`Review decision was not committed for ${record.cveId}`}
          error={mutationError}
        />
        <Button
          type="button"
          variant="secondary"
          data-control-id="cve-applicability-review-reload"
          aria-label={`Reload current CVE review for ${record.cveId}`}
          disabled={busy}
          onClick={() => { void reconcile(); }}
        >
          Reload current review
        </Button>
      </>}
      {outcome && <p role="status" aria-live="polite" className="os-success-note">
        <strong>Review committed.</strong> {outcome}
      </p>}
      {reconciliationError && <>
        <ErrorPanel
          title={`Review committed; refresh incomplete for ${record.cveId}`}
          error={reconciliationError}
        />
        <Button
          type="button"
          variant="secondary"
          data-control-id="cve-applicability-review-reload"
          aria-label={`Reload current CVE review for ${record.cveId}`}
          disabled={busy}
          onClick={() => { void reconcile(); }}
        >
          Reload current review
        </Button>
      </>}
    </Card>}
  </section>;
}

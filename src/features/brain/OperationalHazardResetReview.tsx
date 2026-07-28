import { useRef, useState } from "react";
import {
  createBrainMutationKey,
  fetchOperationalHazardResetTotals,
  reportOperationalHazardResetMinimum,
} from "../../data/api/brain";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, ErrorPanel, StatusPill } from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import type {
  MemoryUsage,
  OperationalHazardAggregateObservationResult,
  OperationalHazardDetail,
  OperationalHazardResetTotals,
} from "../../domain/types/brain";
import { formatBrainDate } from "./BrainNav";
import { OperationalHazardResetDraftKey, operationalHazardRunContexts } from "./hazardAttribution";

function contextKey(missionId: string, runId: string): string {
  return `${missionId}\u0000${runId}`;
}

function wholePositiveNumber(value: string): number | null {
  if (!/^[1-9][0-9]*$/u.test(value.trim())) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

export function OperationalHazardResetReview({
  hazard,
  usage,
}: {
  readonly hazard: OperationalHazardDetail;
  readonly usage: readonly MemoryUsage[];
}) {
  const contexts = operationalHazardRunContexts(usage);
  const [selectedKey, setSelectedKey] = useState(
    contexts[0] ? contextKey(contexts[0].missionId, contexts[0].runId) : "",
  );
  const [open, setOpen] = useState(false);
  const [reportedMinimum, setReportedMinimum] = useState("");
  const [aggregateOnlyConfirmed, setAggregateOnlyConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [receipt, setReceipt] = useState<OperationalHazardAggregateObservationResult>();
  const [mutationError, setMutationError] = useState<Error>();
  const idempotency = useRef(new OperationalHazardResetDraftKey());
  const selectedContext = contexts.find((context) => (
    contextKey(context.missionId, context.runId) === selectedKey
  )) ?? contexts[0];
  const totals = useQuery<OperationalHazardResetTotals | null>(
    `operational-hazard-reset-totals:${selectedContext?.missionId ?? "unlinked"}:${selectedContext?.runId ?? "unlinked"}`,
    (signal) => selectedContext
      ? fetchOperationalHazardResetTotals(selectedContext.missionId, selectedContext.runId, signal)
      : Promise.resolve(null),
    { staleTime: 0 },
  );
  const representedMinimum = wholePositiveNumber(reportedMinimum);
  const canonicalTotals = receipt
    && receipt.totals.missionId === selectedContext?.missionId
    && receipt.totals.runId === selectedContext?.runId
    ? receipt.totals
    : totals.data;

  const submit = async () => {
    if (!selectedContext || representedMinimum === null || !aggregateOnlyConfirmed || busy) return;
    setBusy(true);
    setMutationError(undefined);
    const draft = {
      missionId: selectedContext.missionId,
      runId: selectedContext.runId,
      reportedMinimum: representedMinimum,
    };
    try {
      const result = await reportOperationalHazardResetMinimum(
        draft,
        idempotency.current.keyFor(draft, createBrainMutationKey),
      );
      idempotency.current.confirm(draft);
      setReceipt(result);
      setReportedMinimum("");
      setAggregateOnlyConfirmed(false);
      try {
        await totals.reconcile();
      } catch (error) {
        setMutationError(error instanceof Error
          ? error
          : new Error("The reset minimum was recorded, but the canonical total could not be refreshed."));
      }
    } catch (error) {
      setMutationError(error instanceof Error ? error : new Error("The overall reset minimum could not be recorded."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="brain-hazard-reset-review" aria-label="Reset attribution review">
      <div className="brain-hazard-reset-review__heading">
        <div>
          <p className="os-eyebrow">Operator review</p>
          <h3>Separate recovery burden from procedure evidence</h3>
        </div>
        <Button id="brain-node-hazard-reset-review-toggle" data-testid="brain-node-hazard-reset-review-toggle" type="button" variant="secondary" onClick={() => setOpen((value) => !value)}>
          {open ? "Close reset review" : "Review reset attribution"}
        </Button>
      </div>
      <p>
        Exact reset counts require a local receipt tying one recovery to one procedure and state transition.
        Your overall minimum records that a run needed at least that many reset episodes; it never assigns the
        unresolved remainder to this procedure.
      </p>

      {open && <div className="brain-hazard-reset-review__body">
        {contexts.length === 0 ? <div className="brain-hazard-reset-review__unlinked" role="note">
          <strong>No related run is available for a safe report.</strong>
          <p>This memory must first appear in a persisted mission/run Context Pack. Open it from that run's Brain history, then report the aggregate lower bound there. The reusable procedure count remains unchanged.</p>
        </div> : <>
          {contexts.length > 1 ? <label>
            Related mission run
            <TitaniumSelect
              id="brain-node-hazard-reset-run"
              value={selectedKey}
              onChange={(event) => {
                setSelectedKey(event.target.value);
                setReceipt(undefined);
                setMutationError(undefined);
              }}
            >
              {contexts.map((context) => <option
                key={contextKey(context.missionId, context.runId)}
                value={contextKey(context.missionId, context.runId)}
              >{context.purpose} · {context.runId}</option>)}
            </TitaniumSelect>
          </label> : selectedContext && <div className="brain-hazard-reset-review__scope">
            <span>Related run</span>
            <strong>{selectedContext.purpose}</strong>
            <code>{selectedContext.runId}</code>
          </div>}

          {totals.isLoading && !canonicalTotals && <p className="os-muted" role="status">Loading the run's canonical reset totals…</p>}
          {totals.error && !canonicalTotals && <ErrorPanel
            title="Reset totals are unavailable"
            error={totals.error}
            onRetry={totals.refresh}
          />}
          {canonicalTotals && <dl className="brain-hazard-reset-totals">
            <div><dt>Exact attributable resets in this run</dt><dd>{canonicalTotals.exactAttributableResetCount}</dd><small>Backed by exact local recovery receipts.</small></div>
            <div><dt>Operator-reported overall minimum for this run</dt><dd>{canonicalTotals.operatorReportedResetMinimum ?? "Not reported"}</dd><small>The greatest aggregate lower bound reported for this run.</small></div>
            <div><dt>Still awaiting procedure attribution</dt><dd>{canonicalTotals.minimumUnattributedResetCount}</dd><small>Review work only; these episodes are not redistributed.</small></div>
          </dl>}

          <div className="brain-hazard-reset-review__form">
            <label>
              Overall reset episodes (minimum)
              <input
                id="brain-node-hazard-reset-minimum"
                data-testid="brain-node-hazard-reset-minimum"
                type="number"
                aria-label="Overall reset episodes (minimum)"
                min="1"
                step="1"
                inputMode="numeric"
                value={reportedMinimum}
                onChange={(event) => setReportedMinimum(event.target.value)}
                placeholder="For example, 11"
              />
              <small>Enter the lowest total you are certain occurred across this run. Do not estimate per-procedure counts here.</small>
            </label>
            <label className="brain-hazard-reset-review__confirmation">
              <input
                id="brain-node-hazard-reset-boundary"
                data-testid="brain-node-hazard-reset-boundary"
                type="checkbox"
                checked={aggregateOnlyConfirmed}
                onChange={(event) => setAggregateOnlyConfirmed(event.target.checked)}
              />
              Keep this as an overall run minimum only; do not assign it to this procedure.
            </label>
            <Button
              id="brain-node-hazard-reset-record"
              data-testid="brain-node-hazard-reset-record"
              type="button"
              disabled={!selectedContext || representedMinimum === null || !aggregateOnlyConfirmed || busy}
              onClick={() => void submit()}
            >{busy ? "Recording lower bound…" : "Record overall lower bound"}</Button>
          </div>
          {receipt && <div className="brain-hazard-reset-review__receipt" role="status">
            <StatusPill status={receipt.replayed ? "already recorded" : "recorded"} />
            <p>Recorded at least {receipt.observation.reportedMinimum} reset episodes for this run at {formatBrainDate(receipt.observation.reportedAt)}. Exact procedure attribution was not changed.</p>
          </div>}
          {mutationError && <ErrorPanel
            title={receipt ? "The report was saved, but totals need refreshing" : "The reset minimum was not recorded"}
            error={mutationError}
            onRetry={receipt ? totals.refresh : () => void submit()}
          />}
        </>}
      </div>}
      <small className="brain-hazard-reset-review__boundary">
        This review does not change the {hazard.recovery.cost.resetCount ?? 0} exact reset receipt{hazard.recovery.cost.resetCount === 1 ? "" : "s"} shown for this procedure.
      </small>
    </section>
  );
}

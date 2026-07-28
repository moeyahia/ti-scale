import { useEffect, useMemo, useRef, useState } from "react";
import {
  createAttackKnowledgePromotionKey,
  fetchAttackKnowledgeBundles,
  fetchAttackKnowledgeEvidence,
  previewAttackKnowledgePromotion,
  promoteAttackKnowledge,
} from "../../data/api/attackKnowledgePromotion";
import { useQuery } from "../../data/cache/QueryProvider";
import { Button, Card, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import type {
  AttackKnowledgeBundleSummary,
  AttackKnowledgePromotionPreview,
  AttackKnowledgePromotionReceipt,
} from "../../domain/types/attackKnowledgePromotion";
import { formatBrainDate } from "./BrainNav";

function shortHash(value: string): string {
  return value.length <= 16 ? value : `${value.slice(0, 8)}…${value.slice(-8)}`;
}

export function exactResetSemantics(bundle: AttackKnowledgeBundleSummary): readonly {
  readonly label: string;
  readonly value: string;
  readonly explanation: string;
}[] {
  const counts = bundle.exactProcedureCounts;
  return [
    {
      label: "Exact resets attributable to this procedure",
      value: String(counts.exactResets),
      explanation: "Counted only when a reset receipt is bound to this exact procedure version and evidence lineage.",
    },
    {
      label: "Overall operator-reported reset minimum",
      value: counts.operatorReportedAggregateResetMinimum === null
        ? "Not reported"
        : `At least ${counts.operatorReportedAggregateResetMinimum}`,
      explanation: "Context only. This overall minimum is not silently assigned to this procedure.",
    },
  ];
}

function BundleSummary({ bundle, selected, onSelect }: {
  readonly bundle: AttackKnowledgeBundleSummary;
  readonly selected: boolean;
  readonly onSelect: () => void;
}) {
  const label = bundle.kind === "operational_hazard" ? "Operational hazard" : "Reusable attack fact";
  return (
    <article className={`attack-promotion-bundle${selected ? " is-selected" : ""}`}>
      <header>
        <div>
          <p className="os-eyebrow">{label}</p>
          <h3>{label} · {shortHash(bundle.bundleFingerprint)}</h3>
        </div>
        <StatusPill status={bundle.status} />
      </header>
      <dl className="attack-promotion-counts">
        <div><dt>Reviewed candidates</dt><dd>{bundle.candidates.reviewed} / {bundle.candidates.total}</dd></div>
        <div><dt>Pending candidates</dt><dd>{bundle.candidates.pending}</dd></div>
        <div><dt>Bundle-linked evidence</dt><dd>{bundle.boundEvidenceCount}</dd></div>
        <div><dt>Last observed</dt><dd>{formatBrainDate(bundle.lastObservedAt)}</dd></div>
      </dl>
      {bundle.kind === "operational_hazard" && <dl className="attack-promotion-reset-semantics">
        {exactResetSemantics(bundle).map((item) => <div key={item.label}>
          <dt>{item.label}</dt><dd><strong>{item.value}</strong><small>{item.explanation}</small></dd>
        </div>)}
      </dl>}
      {bundle.promotedReceipt && <section className="attack-promotion-bundle-receipt" aria-label="Immutable promotion receipt summary">
        <strong>Immutable receipt</strong>
        <code>{bundle.promotedReceipt.id}</code>
        <small>Review {bundle.promotedReceipt.reviewHash} · audit {bundle.promotedReceipt.auditRecordId} · {formatBrainDate(bundle.promotedReceipt.promotedAt)}</small>
      </section>}
      <Button
        variant={selected ? "quiet" : "secondary"}
        aria-pressed={selected}
        onClick={onSelect}
      >{selected ? "Selected for review" : `Review ${label.toLowerCase()} bundle ${shortHash(bundle.bundleFingerprint)}`}</Button>
    </article>
  );
}

function ReviewDiff({ preview }: { readonly preview: AttackKnowledgePromotionPreview }) {
  return (
    <section className="attack-promotion-diff" aria-label="Exact promotion diff">
      <header>
        <div><p className="os-eyebrow">Exact immutable review</p><h3>Promotion diff</h3></div>
        <StatusPill status={preview.ready ? "ready" : "blocked"} />
      </header>
      <p>This SHA-256 digest binds the candidate versions, proposed relationships, hazard profile change, and selected canonical evidence.</p>
      <code className="attack-promotion-review-hash">{preview.reviewHash}</code>
      {preview.blockers.length > 0 && <div className="os-validation-summary" role="alert">
        <strong>{preview.blockers.length} promotion blocker{preview.blockers.length === 1 ? "" : "s"}</strong>
        <ul>{preview.blockers.map((blocker, index) => <li key={`${blocker.code}:${blocker.role ?? blocker.edgeKey ?? index}`}>
          <strong>{blocker.code.replaceAll("_", " ")}</strong> — {blocker.message}
        </li>)}</ul>
      </div>}
      <div className="attack-promotion-diff-grid">
        <section><h4>Candidate nodes</h4><ol>{preview.review.candidates.map((candidate) => <li key={candidate.role}>
          <strong>{candidate.role}</strong> · {candidate.expectedNodeType.replaceAll("_", " ")} · {candidate.candidateStatus.replaceAll("_", " ")}
          {candidate.proposedNode && <span>{candidate.proposedNode.title}<small>{candidate.proposedNode.summary}</small></span>}
        </li>)}</ol></section>
        <section><h4>Relationships</h4><ol>{preview.review.edges.map((edge) => <li key={edge.edgeKey}>
          <strong>{edge.action}</strong> · {edge.sourceRole} → {edge.edgeType.replaceAll("_", " ")} → {edge.targetRole}
        </li>)}</ol></section>
      </div>
      {preview.review.operationalHazardProfile && <p><strong>Hazard profile:</strong> {preview.review.operationalHazardProfile.action}. Existing version: {preview.review.operationalHazardProfile.expectedVersion ?? "none"}.</p>}
      <p><strong>Canonical evidence:</strong> {preview.review.verification.evidence.length} selected; minimum {preview.review.verification.minimumEvidenceItems}.</p>
    </section>
  );
}

function ImmutableReceipt({ receipt }: { readonly receipt: AttackKnowledgePromotionReceipt }) {
  return (
    <section className="attack-promotion-receipt" aria-label="Immutable promotion receipt" role="status">
      <p className="os-eyebrow">Promotion committed</p>
      <h3>Immutable operator receipt</h3>
      <p>The reviewed attack knowledge is now verified reusable memory. The receipt and its audit chain cannot be edited or deleted.</p>
      <dl>
        <div><dt>Receipt</dt><dd><code>{receipt.receiptId}</code></dd></div>
        <div><dt>Review hash</dt><dd><code>{receipt.reviewHash}</code></dd></div>
        <div><dt>Audit record</dt><dd><code>{receipt.auditRecordId}</code></dd></div>
        <div><dt>Verified relationships</dt><dd>{receipt.edgeIds.length}</dd></div>
        <div><dt>Committed</dt><dd>{formatBrainDate(receipt.promotedAt)}</dd></div>
      </dl>
    </section>
  );
}

export default function AttackKnowledgePromotionReview({ candidateRevision = 0 }: { readonly candidateRevision?: number }) {
  const bundles = useQuery(
    `attack-knowledge-bundles:${candidateRevision}`,
    fetchAttackKnowledgeBundles,
    { staleTime: 0 },
  );
  const [selectedFingerprint, setSelectedFingerprint] = useState<string>();
  const [selectedEvidenceIds, setSelectedEvidenceIds] = useState<readonly string[]>([]);
  const [preview, setPreview] = useState<AttackKnowledgePromotionPreview>();
  const [receipt, setReceipt] = useState<AttackKnowledgePromotionReceipt>();
  const [acknowledged, setAcknowledged] = useState(false);
  const [mutation, setMutation] = useState<{ readonly busy: boolean; readonly error?: Error }>({ busy: false });
  const promotionKey = useRef<{ readonly reviewHash: string; readonly key: string } | undefined>(undefined);
  const selectedBundle = useMemo(
    () => bundles.data?.items.find((bundle) => bundle.bundleFingerprint === selectedFingerprint),
    [bundles.data?.items, selectedFingerprint],
  );
  const evidence = useQuery(
    `attack-knowledge-evidence:${selectedFingerprint ?? "none"}`,
    (signal) => selectedFingerprint
      ? fetchAttackKnowledgeEvidence(selectedFingerprint, signal)
      : Promise.resolve({ schemaVersion: "2.4" as const, bundleId: "none", bundleFingerprint: "none", items: [], totalReturned: 0 }),
    { staleTime: 0 },
  );

  useEffect(() => {
    setSelectedEvidenceIds([]);
    setPreview(undefined);
    setReceipt(undefined);
    setAcknowledged(false);
    setMutation({ busy: false });
    promotionKey.current = undefined;
  }, [selectedFingerprint]);

  const toggleEvidence = (id: string) => {
    setSelectedEvidenceIds((current) => current.includes(id)
      ? current.filter((item) => item !== id)
      : [...current, id].sort());
    setPreview(undefined);
    setReceipt(undefined);
    setAcknowledged(false);
    setMutation({ busy: false });
    promotionKey.current = undefined;
  };

  const createPreview = async () => {
    if (!selectedFingerprint) return;
    setMutation({ busy: true });
    try {
      const result = await previewAttackKnowledgePromotion(selectedFingerprint, selectedEvidenceIds);
      setPreview(result);
      setReceipt(undefined);
      setAcknowledged(false);
      promotionKey.current = { reviewHash: result.reviewHash, key: createAttackKnowledgePromotionKey() };
      setMutation({ busy: false });
    } catch (error) {
      setMutation({ busy: false, error: error instanceof Error ? error : new Error("Promotion preview failed") });
    }
  };

  const promote = async () => {
    if (!selectedFingerprint || !preview?.ready || !acknowledged) return;
    const key = promotionKey.current?.reviewHash === preview.reviewHash
      ? promotionKey.current.key
      : createAttackKnowledgePromotionKey();
    promotionKey.current = { reviewHash: preview.reviewHash, key };
    setMutation({ busy: true });
    try {
      const result = await promoteAttackKnowledge({
        bundleFingerprint: selectedFingerprint,
        expectedReviewHash: preview.reviewHash,
        verificationEvidenceIds: selectedEvidenceIds,
      }, key);
      setReceipt(result);
      setMutation({ busy: false });
      bundles.refresh();
    } catch (error) {
      // Retain the same key so an ambiguous network retry cannot create a
      // second represented operator decision.
      setMutation({ busy: false, error: error instanceof Error ? error : new Error("Promotion failed") });
    }
  };

  return (
    <Card className="attack-promotion-review">
      <section aria-label="Attack knowledge promotion">
        <header className="attack-promotion-header">
          <div><p className="os-eyebrow">Evidence-gated reusable memory</p><h2>Attack Knowledge Promotion</h2></div>
          <Button variant="quiet" onClick={bundles.refresh} disabled={bundles.isLoading}>Refresh promotion queue</Button>
        </header>
        <p>Review the generalized bundle, select only its compiler-bound canonical evidence, inspect the exact hash, then deliberately promote. Nothing is promoted automatically.</p>
        {bundles.isLoading && <LoadingPanel label="Loading staged attack knowledge" />}
        {bundles.error && !bundles.data && <ErrorPanel
          error={bundles.error}
          onRetry={bundles.refresh}
          retryControlId="brain-inbox-promotion-queue-retry"
          retryLabel="Retry promotion queue"
        />}
        {bundles.data?.items.length === 0 && <p className="brain-mutation-note">No staged or recently promoted attack-knowledge bundles are available.</p>}
        {bundles.data && bundles.data.items.length > 0 && <div className="attack-promotion-bundle-list">
          {bundles.data.items.map((bundle) => <BundleSummary
            key={bundle.bundleId}
            bundle={bundle}
            selected={bundle.bundleFingerprint === selectedFingerprint}
            onSelect={() => setSelectedFingerprint(bundle.bundleFingerprint)}
          />)}
        </div>}

        {selectedBundle && <section className="attack-promotion-evidence" aria-label="Bundle-linked verified evidence">
          <header><div><p className="os-eyebrow">Private review input</p><h3>Bundle-linked verified evidence</h3></div><span>{selectedEvidenceIds.length} selected</span></header>
          <p>Only evidence immutably linked by the local compiler is offered here. Raw command output and unrelated evidence cannot be selected.</p>
          {evidence.isLoading && <LoadingPanel label="Loading bound canonical evidence" />}
          {evidence.error && !evidence.data && <ErrorPanel
            error={evidence.error}
            onRetry={evidence.refresh}
            retryControlId="brain-inbox-promotion-evidence-retry"
            retryLabel="Retry promotion evidence"
          />}
          {evidence.data?.items.length === 0 && <div className="os-validation-summary" role="status"><strong>No canonical evidence is bound to this bundle</strong><p>The bundle remains visibly blocked. Re-run trusted local compilation with its canonical evidence lineage; this review surface cannot create or repair bindings.</p></div>}
          {evidence.data && evidence.data.items.length > 0 && <fieldset>
            <legend>Select evidence for this exact review</legend>
            {evidence.data.items.map((item) => <label className="os-check-field" key={item.id}>
              <input
                type="checkbox"
                checked={selectedEvidenceIds.includes(item.id)}
                onChange={() => toggleEvidence(item.id)}
              />
              <span><strong>Use verified evidence {item.id}</strong><small>{item.evidenceType.replaceAll("_", " ")} · acquired {formatBrainDate(item.acquiredAt)} · SHA-256 {shortHash(item.contentHash)}</small></span>
            </label>)}
          </fieldset>}
          <Button onClick={createPreview} disabled={mutation.busy || selectedBundle.status !== "staged"}>
            {mutation.busy ? "Building exact preview…" : "Preview exact promotion"}
          </Button>
        </section>}

        {preview && <ReviewDiff preview={preview} />}
        {preview?.ready && !receipt && <section className="attack-promotion-commit">
          <label className="os-check-field">
            <input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />
            <span><strong>I reviewed this exact diff and evidence set</strong><small>Promotion verifies reusable nodes and relationships and writes an immutable operator receipt. It does not copy target names, addresses, mission mode, or private source paths into reusable memory.</small></span>
          </label>
          <Button onClick={promote} disabled={!acknowledged || mutation.busy}>
            {mutation.busy ? "Committing verified memory…" : "Promote verified attack knowledge"}
          </Button>
        </section>}
        {mutation.error && <ErrorPanel
          error={mutation.error}
          onRetry={preview?.ready && acknowledged ? promote : createPreview}
          retryControlId={preview?.ready && acknowledged
            ? "brain-inbox-promotion-commit-retry"
            : "brain-inbox-promotion-preview-retry"}
          retryLabel={preview?.ready && acknowledged
            ? "Retry promotion commit"
            : "Retry promotion preview"}
        />}
        {receipt && <ImmutableReceipt receipt={receipt} />}
      </section>
    </Card>
  );
}

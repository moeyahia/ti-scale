import { useEffect, useRef, useState } from "react";
import { AppLink } from "../../app/router/navigation";
import { cveIntelligenceApi } from "../../data/api/cveIntelligence";
import { Button, Card, EmptyState, ErrorPanel, StatusPill } from "../../design-system/components/Primitives";
import type {
  CveApplicabilityRecord,
  CveIntelligenceJson,
  MissionScopedNvdDetail,
} from "../../domain/types/cveIntelligence";
import { CveApplicabilityReview } from "./CveApplicabilityReview";

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium", timeStyle: "short",
  }).format(parsed);
}

function scalar(value: CveIntelligenceJson | undefined): string | undefined {
  return typeof value === "string" || typeof value === "number" ? String(value) : undefined;
}

function applicabilityLabel(value: CveApplicabilityRecord["applicability"]): string {
  return value.replaceAll("_", " ").replace(/^./u, (character) => character.toLocaleUpperCase());
}

interface NvdLookupContext {
  readonly missionId: string;
  readonly runId: string;
  readonly stepId: string;
}

function contextMismatchError(cveId: string): Error {
  const error = new Error(`The official NVD result did not match ${cveId}.`) as Error & {
    humanMessage: string;
    remediation: string;
  };
  error.humanMessage = `Ti-Scale stopped the official lookup because its CVE identity did not match ${cveId}.`;
  error.remediation = "Refresh the mission plan and select the reviewed CVE again. No target action was performed.";
  return error;
}

function OfficialNvdDetail({ record, context }: {
  readonly record: CveApplicabilityRecord;
  readonly context?: NvdLookupContext;
}) {
  const [result, setResult] = useState<MissionScopedNvdDetail>();
  const [error, setError] = useState<Error>();
  const [pending, setPending] = useState(false);
  const active = useRef<AbortController | undefined>(undefined);

  useEffect(() => () => active.current?.abort(), []);
  useEffect(() => {
    active.current?.abort();
    setResult(undefined);
    setError(undefined);
    setPending(false);
  }, [context?.missionId, context?.runId, context?.stepId, record.id]);

  if (!context) {
    return <p className="os-muted">Official NVD detail becomes available when this run has a current represented plan step. No lookup is performed without that scope.</p>;
  }

  const lookup = async (): Promise<void> => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    setPending(true);
    setError(undefined);
    try {
      const detail = await cveIntelligenceApi.officialNvdDetail(
        context.missionId,
        context.runId,
        context.stepId,
        record.id,
        controller.signal,
      );
      if (detail.detail.cveId !== record.cveId) throw contextMismatchError(record.cveId);
      setResult(detail);
    } catch (cause) {
      if (!controller.signal.aborted) {
        setError(cause instanceof Error ? cause : new Error("The official NVD lookup failed safely."));
      }
    } finally {
      if (active.current === controller) {
        active.current = undefined;
        setPending(false);
      }
    }
  };

  return <section className="os-section-stack" aria-label={`Official NVD detail for ${record.cveId}`}>
    <div>
      <p><strong>Public-source check:</strong> This reads the official NVD record for the reviewed candidate. It does not connect to, scan, or change the assessed target.</p>
      <Button
        type="button"
        variant="secondary"
        aria-label={`Check official public NVD record for ${record.cveId} without touching the target`}
        disabled={pending}
        onClick={() => { void lookup(); }}
      >{pending ? "Checking official NVD record…" : result ? "Refresh official NVD record — no target contact" : "Check official NVD record — no target contact"}</Button>
    </div>
    {pending && <p role="status" aria-live="polite">Checking the official public NVD record. The assessed target is not contacted.</p>}
    {error && <ErrorPanel title={`Official NVD detail is unavailable for ${record.cveId}`} error={error} />}
    {result && <section aria-labelledby={`official-nvd-${record.id}`}>
      <div className="os-card-heading">
        <div><p className="os-eyebrow">Redacted public-intelligence receipt</p><h4 id={`official-nvd-${record.id}`}>{result.detail.cveId} official NVD detail</h4></div>
        <StatusPill status="read_only">Public read only</StatusPill>
      </div>
      <p>{result.summary}</p>
      <dl className="os-key-values">
        <div><dt>Strongest CVSS</dt><dd>{result.detail.strongestCvss
          ? `${result.detail.strongestCvss.baseScore} · ${result.detail.strongestCvss.baseSeverity} · v${result.detail.strongestCvss.version}`
          : "Not supplied by NVD"}</dd></div>
        <div><dt>Published</dt><dd>{result.detail.publishedAt ? formatTimestamp(result.detail.publishedAt) : "Not supplied"}</dd></div>
        <div><dt>Last modified</dt><dd>{result.detail.lastModifiedAt ? formatTimestamp(result.detail.lastModifiedAt) : "Not supplied"}</dd></div>
        <div><dt>Weaknesses</dt><dd>{result.detail.weaknesses.length ? result.detail.weaknesses.join(", ") : "None supplied"}</dd></div>
        <div><dt>Official references</dt><dd>{result.detail.referenceCount} retained as a count only</dd></div>
        <div><dt>Target interaction</dt><dd>No — public NVD only</dd></div>
        <div><dt>Execution authority</dt><dd>None — this lookup cannot run a target action</dd></div>
      </dl>
      <p className="os-muted"><strong>External description:</strong> quarantined and not returned to the browser. Its content hash is retained for provenance; it is not eligible for model prompts.</p>
      <details className="os-raw-details">
        <summary>Redacted provenance for {record.cveId}</summary>
        <dl className="os-key-values">
          <div><dt>Authority</dt><dd>{result.provenance.authority} · {result.provenance.api}</dd></div>
          <div><dt>Official record</dt><dd className="os-mono">{result.provenance.recordUrl}</dd></div>
          <div><dt>Retrieved</dt><dd>{formatTimestamp(result.provenance.retrievedAt)}</dd></div>
          <div><dt>Reviewed candidate</dt><dd className="os-mono">{result.context.reviewedCveRef}</dd></div>
          <div><dt>Plan step</dt><dd className="os-mono">{result.context.stepId}</dd></div>
          <div><dt>Tool receipt</dt><dd className="os-mono">{result.provenance.toolName} · {result.provenance.invocationId}</dd></div>
          <div><dt>Audit record</dt><dd className="os-mono">{result.provenance.auditRecordId}</dd></div>
          <div><dt>Description hash</dt><dd className="os-mono">{result.detail.externalDescription.contentSha256}</dd></div>
          <div><dt>Result hash</dt><dd className="os-mono">{result.provenance.resultSha256}</dd></div>
          <div><dt>Redaction</dt><dd>API URL removed · description quarantined · references count only · provider error body never retained</dd></div>
        </dl>
      </details>
    </section>}
  </section>;
}

function CveRecord({
  record,
  nvdLookupContext,
  reviewOpen,
  onReviewToggle,
  onReviewed,
}: {
  readonly record: CveApplicabilityRecord;
  readonly nvdLookupContext?: NvdLookupContext;
  readonly reviewOpen: boolean;
  readonly onReviewToggle: (open: boolean) => void;
  readonly onReviewed: () => Promise<void>;
}) {
  const cvssScore = scalar(record.cvss.score);
  const cvssVector = scalar(record.cvss.vector);
  return <article className="os-card" aria-labelledby={`cve-${record.id}`}>
    <div className="os-card-heading">
      <div>
        <p className="os-eyebrow">{record.cveId} · {record.component}</p>
        <h3 id={`cve-${record.id}`}>{record.title}</h3>
      </div>
      <StatusPill status={record.applicability}>{applicabilityLabel(record.applicability)}</StatusPill>
    </div>
    <p>{record.description}</p>
    <p><strong>Applicability reasoning:</strong> {record.reasoningSummary}</p>
    <dl className="os-key-values">
      <div><dt>Detected version</dt><dd>{record.detectedVersion ?? "Insufficient evidence"}</dd></div>
      <div><dt>Affected range</dt><dd>{record.affectedRange ?? "Not established"}</dd></div>
      <div><dt>Confidence</dt><dd>{Math.round(record.confidence * 100)}%</dd></div>
      <div><dt>CVSS</dt><dd>{cvssScore ?? "Not supplied"}{cvssVector ? ` · ${cvssVector}` : ""}</dd></div>
      <div><dt>EPSS</dt><dd>{record.epss === undefined ? "Not supplied" : `${(record.epss * 100).toFixed(2)}%`}</dd></div>
      <div><dt>CISA KEV</dt><dd>{record.kevStatus?.replaceAll("_", " ") ?? "Not checked"}</dd></div>
      <div><dt>CWE</dt><dd>{record.cwe.length ? record.cwe.join(", ") : "Not supplied"}</dd></div>
      <div><dt>Exploit maturity</dt><dd>{record.exploitMaturity ?? "Not assessed"}</dd></div>
    </dl>
    {record.versionEvidenceId
      ? <p>Version evidence: <AppLink href={`/intelligence/evidence/${encodeURIComponent(record.versionEvidenceId)}`}>{record.versionEvidenceId}</AppLink></p>
      : <p className="os-muted">No verified version-evidence record is linked; this item cannot be treated as confirmed.</p>}
    <details className="os-raw-details">
      <summary>Authoritative sources for {record.cveId} ({record.sourceLinks.length})</summary>
      <ul aria-label={`Authoritative sources for ${record.cveId}`}>{record.sourceLinks.map((source) => <li key={`${source.kind}:${source.url}`}>
        <a aria-label={`${source.label} for ${record.cveId}`} href={source.url} target="_blank" rel="noreferrer noopener">{source.label}</a> · {source.kind.replaceAll("_", " ")}
      </li>)}</ul>
      <p>Retrieved {formatTimestamp(record.sourceRetrievedAt)}{record.sourceVersion ? ` · ${record.sourceVersion}` : ""}</p>
    </details>
    <details className="os-raw-details"><summary>CPE/package and scoring details for {record.cveId}</summary><pre>{JSON.stringify({ cpeOrPackage: record.cpeOrPackage, cvss: record.cvss }, null, 2)}</pre></details>
    <CveApplicabilityReview
      record={record}
      open={reviewOpen}
      onToggle={onReviewToggle}
      onReviewed={onReviewed}
    />
    <OfficialNvdDetail record={record} context={nvdLookupContext} />
  </article>;
}

export function CveApplicabilityPanel({
  records,
  targetLabel,
  missionId,
  runId,
  currentStepId,
  selectedReviewId,
  onReviewSelection,
  onReviewed,
}: {
  readonly records: readonly CveApplicabilityRecord[];
  readonly targetLabel: string;
  readonly missionId?: string;
  readonly runId?: string;
  readonly currentStepId?: string | null;
  readonly selectedReviewId?: string;
  readonly onReviewSelection?: (recordId?: string) => void;
  readonly onReviewed?: () => Promise<void>;
}) {
  const [localReviewId, setLocalReviewId] = useState("");
  const activeReviewId = selectedReviewId ?? localReviewId;
  const selectReview = (recordId?: string) => {
    if (onReviewSelection) onReviewSelection(recordId);
    else setLocalReviewId(recordId ?? "");
  };
  const nvdLookupContext = missionId && runId && currentStepId
    ? { missionId, runId, stepId: currentStepId }
    : undefined;
  return <Card aria-labelledby="cve-applicability-heading">
    <div className="os-card-heading">
      <div><p className="os-eyebrow">Version-aware vulnerability intelligence</p><h2 id="cve-applicability-heading">CVE applicability</h2></div>
      <StatusPill status={records.length ? "observed" : "not_observed"}>{records.length} record{records.length === 1 ? "" : "s"}</StatusPill>
    </div>
    <p>Applicability for <strong>{targetLabel}</strong> is kept separate from discovery. Confirmed and not-applicable conclusions require a detected-version comparison and verified evidence.</p>
    {records.length === 0
      ? <EmptyState title="No evidence-backed CVE applicability records" description="No version-aware mapping has been recorded for this topology node. A banner or product name alone is not promoted into a vulnerability claim." />
      : <div className="os-section-stack">{records.map((record) => <CveRecord
          key={record.id}
          record={record}
          nvdLookupContext={nvdLookupContext}
          reviewOpen={activeReviewId === record.id}
          onReviewToggle={(open) => selectReview(open ? record.id : undefined)}
          onReviewed={onReviewed ?? (async () => undefined)}
        />)}</div>}
  </Card>;
}

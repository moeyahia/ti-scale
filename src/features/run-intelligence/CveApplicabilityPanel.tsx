import { AppLink } from "../../app/router/navigation";
import { Card, EmptyState, StatusPill } from "../../design-system/components/Primitives";
import type { CveApplicabilityRecord, CveIntelligenceJson } from "../../domain/types/cveIntelligence";

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

function CveRecord({ record }: { readonly record: CveApplicabilityRecord }) {
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
  </article>;
}

export function CveApplicabilityPanel({ records, targetLabel }: {
  readonly records: readonly CveApplicabilityRecord[];
  readonly targetLabel: string;
}) {
  return <Card aria-labelledby="cve-applicability-heading">
    <div className="os-card-heading">
      <div><p className="os-eyebrow">Version-aware vulnerability intelligence</p><h2 id="cve-applicability-heading">CVE applicability</h2></div>
      <StatusPill status={records.length ? "observed" : "not_observed"}>{records.length} record{records.length === 1 ? "" : "s"}</StatusPill>
    </div>
    <p>Applicability for <strong>{targetLabel}</strong> is kept separate from discovery. Confirmed and not-applicable conclusions require a detected-version comparison and verified evidence.</p>
    {records.length === 0
      ? <EmptyState title="No evidence-backed CVE applicability records" description="No version-aware mapping has been recorded for this topology node. A banner or product name alone is not promoted into a vulnerability claim." />
      : <div className="os-section-stack">{records.map((record) => <CveRecord key={record.id} record={record} />)}</div>}
  </Card>;
}

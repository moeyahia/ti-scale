import { useState, type FormEvent } from "react";
import { AppLink } from "../../app/router/navigation";
import { operationsApi } from "../../data/api/operations";
import { useQuery } from "../../data/cache/QueryProvider";
import type { ReportGenerationRecord } from "../../domain/types/operations";
import { Button, Card, ErrorPanel, LoadingPanel, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { CursorControls, FilterForm, formatTime, JsonDetails, KeyValueGrid, QueryBoundary, StreamState, useUrlFilters } from "../runs/OperationalSurface";
import { ContextUsedDisclosure } from "../brain/ContextUsedDisclosure";

function canonicalReportMetadata(value: unknown): { reportVersion: number; downloadUrl: string } | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  return Number.isSafeInteger(record.reportVersion)
    && typeof record.downloadUrl === "string"
    && record.downloadUrl.startsWith("/api/v2/reports/")
    && record.downloadUrl.endsWith("/download")
    ? { reportVersion: Number(record.reportVersion), downloadUrl: record.downloadUrl }
    : null;
}

function ReportGenerator({
  onGenerated,
}: {
  readonly onGenerated: (generation: ReportGenerationRecord) => void;
}) {
  const [runId, setRunId] = useState("");
  const [reportVersion, setReportVersion] = useState("1");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [generation, setGeneration] = useState<ReportGenerationRecord | null>(null);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const normalizedRunId = runId.trim();
    const version = Number(reportVersion);
    if (!normalizedRunId || !Number.isSafeInteger(version) || version < 1 || version > 999) return;
    setSubmitting(true);
    setError(null);
    try {
      const result = await operationsApi.generateReport(
        normalizedRunId,
        version,
        `report:${normalizedRunId}:${version}`,
      );
      setGeneration(result);
      onGenerated(result);
    } catch (caught) {
      setError(caught instanceof Error ? caught : new Error("Report generation failed"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Card aria-label="Generate a canonical mission report">
      <div className="os-card-heading">
        <div>
          <p className="os-eyebrow">Canonical report generator</p>
          <h2>Generate Markdown + JSON</h2>
        </div>
        <StatusPill status="verified">Redacted</StatusPill>
      </div>
      <p className="os-muted">
        Creates deterministic, integrity-checked artifacts from one canonical run. Raw payloads,
        secrets, extracted evidence text, and unverified claims are excluded.
      </p>
      <form className="os-form-grid" onSubmit={submit}>
        <label>
          <span>Run ID</span>
          <input
            id="reports-run-id"
            name="runId"
            value={runId}
            onChange={(event) => setRunId(event.currentTarget.value)}
            placeholder="run_…"
            autoComplete="off"
            required
          />
        </label>
        <label>
          <span>Report version</span>
          <input
            id="reports-report-version"
            name="reportVersion"
            value={reportVersion}
            onChange={(event) => setReportVersion(event.currentTarget.value)}
            type="text"
            inputMode="numeric"
            pattern="[1-9][0-9]{0,2}"
            required
          />
        </label>
        <Button id="reports-generate" type="submit" disabled={submitting || !runId.trim()}>
          {submitting ? "Generating report…" : "Generate report"}
        </Button>
      </form>
      {error && <ErrorPanel title="Report was not generated" error={error} />}
      {generation && (
        <div className="os-stack" role="status" aria-live="polite">
          <p>
            Version {generation.reportVersion} is ready. Both files represent the same canonical
            snapshot through {formatTime(generation.snapshotThrough)}.
          </p>
          <div className="os-cluster">
            {generation.artifacts.map((artifact) => (
              <a
                key={artifact.id}
                data-control-id="reports-generated-download"
                className="os-button os-button--secondary"
                href={artifact.downloadUrl}
                download
              >
                Download {artifact.format === "markdown" ? "Markdown" : "JSON"}
              </a>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}

export default function ReportsPage({ reportId }: { reportId?: string }) {
  const filters = useUrlFilters({ limit: "25" });
  const list = useQuery(`reports:${filters.key}`, (signal) => operationsApi.reports(filters.values, signal));
  const detail = useQuery(
    `report:${reportId ?? "none"}`,
    (signal) => reportId ? operationsApi.report(reportId, signal) : Promise.resolve(undefined),
  );
  const generated = () => list.refresh();
  const reportDownload = detail.data ? canonicalReportMetadata(detail.data.metadata) : null;

  return (
    <div className="os-page">
      <PageHeader
        eyebrow="Mission deliverables"
        title="Reports"
        description="Generate and download durable redacted mission reports with immutable hashes and canonical evidence coverage."
        actions={<StreamState />}
      />
      <ReportGenerator onGenerated={generated} />
      <FilterForm filters={filters} searchKey="missionId" searchLabel="Mission ID" />
      <div className="os-master-detail">
        <section aria-label="Report records">
          <QueryBoundary
            data={list.data?.items}
            error={list.error}
            isLoading={list.isLoading}
            onRetry={list.refresh}
            emptyTitle="No reports generated"
            emptyDescription="Enter a canonical run ID above to create deterministic Markdown and JSON report artifacts."
          >
            {(items) => (
              <>
                <div className="os-table-wrap">
                  <table className="os-data-table">
                    <thead><tr><th>Report</th><th>Mission</th><th>Coverage</th><th>Size</th><th>Created</th></tr></thead>
                    <tbody>
                      {items.map((report) => (
                        <tr key={report.id} className={report.id === reportId ? "is-selected" : undefined}>
                          <th scope="row">
                            <AppLink
                              href={`/reports/${encodeURIComponent(report.id)}`}
                              aria-label={`Open report ${report.artifactType} (${report.id})`}
                            >
                              {report.artifactType}
                            </AppLink>
                            <small>{report.mediaType}</small>
                          </th>
                          <td>{report.mission.name}</td>
                          <td>{report.evaluation?.evidenceCoverage === null || report.evaluation === null ? "—" : `${Math.round(report.evaluation.evidenceCoverage * 100)}%`}</td>
                          <td>{report.byteSize.toLocaleString()} B</td>
                          <td>{formatTime(report.createdAt)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <CursorControls
                  context="reports"
                  cursor={filters.values.cursor}
                  nextCursor={list.data?.nextCursor ?? null}
                  onChange={(cursor) => filters.set({ cursor }, { resetCursor: false, replace: false })}
                />
              </>
            )}
          </QueryBoundary>
        </section>
        <aside className="os-detail-panel">
          {reportId && detail.isLoading && <LoadingPanel label="Loading report metadata" />}
          {reportId && detail.error && !detail.data && <ErrorPanel error={detail.error} onRetry={detail.refresh} />}
          {!reportId && <Card><p className="os-muted">Select a report to inspect its immutable hash, evidence coverage, and download state.</p></Card>}
          {detail.data && (
            <Card>
              <div className="os-card-heading">
                <div><p className="os-eyebrow">{detail.data.mission.name}</p><h2>{detail.data.artifactType}</h2></div>
                <StatusPill status={detail.data.storage.available ? "available" : "unavailable"} />
              </div>
              <KeyValueGrid items={[
                { label: "Journey", value: detail.data.journey === "autonomous" ? "Autonomous" : "Guided" },
                { label: "Media", value: detail.data.mediaType },
                { label: "Size", value: `${detail.data.byteSize.toLocaleString()} bytes` },
                { label: "Sensitivity", value: detail.data.sensitivity },
                { label: "Evidence coverage", value: detail.data.evaluation?.evidenceCoverage === null || !detail.data.evaluation ? "Not evaluated" : `${Math.round(detail.data.evaluation.evidenceCoverage * 100)}%` },
                { label: "Hash", value: <span className="os-mono">{detail.data.contentHash}</span> },
              ]} />
              {reportDownload && (
                <a
                  className="os-button os-button--primary"
                  data-control-id="reports-detail-download"
                  href={operationsApi.reportDownloadUrl(detail.data.id)}
                  download
                >
                  Download report v{reportDownload.reportVersion}
                </a>
              )}
              {detail.data.contextPackIds.length > 0 ? (
                <section aria-label="Report memory context">
                  <p className="os-eyebrow">Memory transparency</p>
                  {detail.data.contextPackIds.map((packId) => <ContextUsedDisclosure key={packId} packId={packId} />)}
                </section>
              ) : <p className="os-muted">No producing action Context Pack is linked. The generated report still lists the run’s canonical Context Pack IDs and usage counts without copying memory content.</p>}
              <JsonDetails label="Report metadata" value={detail.data.metadata} />
              {!reportDownload && <p className="os-muted">This historical report has metadata only and no canonical report-download adapter.</p>}
            </Card>
          )}
        </aside>
      </div>
    </div>
  );
}

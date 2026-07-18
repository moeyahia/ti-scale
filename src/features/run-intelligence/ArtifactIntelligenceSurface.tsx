import { useEffect, useState } from "react";
import { AppLink } from "../../app/router/navigation";
import { pageCapturesApi } from "../../data/api/pageCaptures";
import { scriptArtifactsApi } from "../../data/api/scriptArtifacts";
import { useQuery } from "../../data/cache/QueryProvider";
import type { PageCaptureRecord } from "../../domain/types/pageCaptures";
import type { ScriptArtifactDetail, ScriptArtifactSummary } from "../../domain/types/scriptArtifacts";
import { Button, Card, EmptyState, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { DegradedNotice, formatTime, KeyValueGrid } from "../runs/OperationalSurface";

function bytes(value: number): string {
  if (value < 1_024) return `${value} B`;
  if (value < 1_048_576) return `${(value / 1_024).toFixed(1)} KiB`;
  return `${(value / 1_048_576).toFixed(1)} MiB`;
}

function Values({ title, values, empty = "None recorded" }: { readonly title: string; readonly values: readonly string[]; readonly empty?: string }) {
  return <section className="os-artifact-values"><h4>{title}</h4>{values.length ? <ul>{values.map((value) => <li key={value}>{value}</li>)}</ul> : <p className="os-muted">{empty}</p>}</section>;
}

function ScriptDetail({ record }: { readonly record: ScriptArtifactDetail }) {
  return <Card className="os-script-detail" aria-label={`Read-only script ${record.name} version ${record.version}`}>
    <header className="os-artifact-detail-heading">
      <div><p className="os-eyebrow">Immutable source version {record.version}</p><h3>{record.name}</h3><p>{record.laymanExplanation}</p></div>
      <div><StatusPill status={record.validation.state} /><StatusPill status={record.risk.riskClass}>{record.risk.riskClass} risk</StatusPill></div>
    </header>
    <KeyValueGrid items={[
      { label: "Language", value: record.language }, { label: "Size", value: bytes(record.byteSize) },
      { label: "Sensitivity", value: record.sensitivity }, { label: "Created", value: formatTime(record.createdAt) },
      { label: "SHA-256", value: <code className="os-breakable">{record.contentHash}</code> }, { label: "Author", value: `${record.provenance.createdByType} · ${record.provenance.createdBy}` },
    ]} />
    <section><h4>Technical purpose</h4><p>{record.technicalPurpose}</p></section>
    <section className="os-source-readonly" aria-label="Immutable script source">
      <header><h4>Source</h4><span>Read only · hash verified by the canonical service</span></header>
      <pre tabIndex={0}><code>{record.source}</code></pre>
    </section>
    <div className="os-artifact-columns">
      <section><h4>Inputs</h4>{record.inputs.length ? <ul>{record.inputs.map((input) => <li key={input.name}><strong>{input.name}</strong> · {input.required ? "required" : "optional"} · {input.sensitivity.replaceAll("_", " ")}<span>{input.description}</span></li>)}</ul> : <p className="os-muted">No inputs documented.</p>}</section>
      <section><h4>Expected outputs</h4>{record.expectedOutputs.length ? <ul>{record.expectedOutputs.map((output) => <li key={output.label}><strong>{output.label}</strong><span>{output.description}</span><small>Success: {output.successRecognition}</small><small>Failure: {output.failureRecognition}</small></li>)}</ul> : <p className="os-muted">No outputs documented.</p>}</section>
    </div>
    <div className="os-artifact-columns">
      <Values title="Prerequisites" values={record.requirements.prerequisites} />
      <Values title="Dependencies" values={record.requirements.dependencies} />
      <Values title="Files touched if separately executed" values={record.touches.files} />
      <Values title="Network and services touched if separately executed" values={[...record.touches.network, ...record.touches.services]} />
    </div>
    <section className="os-script-risk"><h4>Risk, reversal, and secrets</h4><p>{record.risk.reversibility}</p><Values title="Possible side effects" values={record.risk.sideEffects} /><p><strong>Cleanup:</strong> {record.cleanupNotes}</p><p><strong>Secrets:</strong> {record.secretsHandling}</p></section>
    <section><h4>Validation and tests</h4><p>{record.validation.summary}</p>{record.validation.tests.length ? <table className="os-data-table"><thead><tr><th>Test</th><th>Status</th><th>Result</th></tr></thead><tbody>{record.validation.tests.map((test) => <tr key={test.name}><th scope="row">{test.name}</th><td><StatusPill status={test.status} /></td><td>{test.summary}</td></tr>)}</tbody></table> : <p className="os-muted">No test was recorded. This source is not represented as executed or verified.</p>}
      {record.validation.testArtifactId && <AppLink aria-label={`Open script test artifact ${record.validation.testArtifactId}`} href={`/intelligence/artifacts/${encodeURIComponent(record.validation.testArtifactId)}`}>Open test artifact {record.validation.testArtifactId}</AppLink>}
    </section>
    <section><h4>Bounded version diff</h4><p>{record.diff.changeSummary}</p><KeyValueGrid items={[
      { label: "From", value: record.diff.fromVersion ?? "Initial version" }, { label: "To", value: record.diff.toVersion },
      { label: "Source changed", value: record.diff.sourceChanged ? "Yes" : "No" }, { label: "Lines added", value: record.diff.addedLineCount },
      { label: "Lines removed", value: record.diff.removedLineCount }, { label: "Changed fields", value: record.diff.changedFields.join(", ") || "None" },
    ]} /></section>
    <section><h4>Provenance and evidence expectations</h4><p>{record.provenance.explanation}</p><Values title="Source references" values={record.provenance.sourceRefs} /><Values title="Evidence expected from separately authorized execution" values={record.evidenceExpectations} /></section>
    <footer className="os-artifact-links">
      <AppLink aria-label={`Open source artifact ${record.artifactId}`} href={`/intelligence/artifacts/${encodeURIComponent(record.artifactId)}`}>Open canonical source artifact</AppLink>
      {record.planId && record.runId && <AppLink aria-label="Open associated plan" href={`/missions/${encodeURIComponent(record.missionId)}/runs/${encodeURIComponent(record.runId)}?tab=plan`}>Open associated plan</AppLink>}
    </footer>
    <p className="os-boundary-note">This workspace is intentionally read only. It exposes no execution control and makes no claim that unrecorded tests ran.</p>
  </Card>;
}

function ScriptWorkspace({ missionId, runId }: { readonly missionId: string; readonly runId?: string }) {
  const [selectedId, setSelectedId] = useState("");
  const scripts = useQuery(`script-artifacts:${missionId}:${runId ?? "mission"}`, (signal) => scriptArtifactsApi.list(missionId, { ...(runId ? { runId } : {}), limit: 100 }, signal), { staleTime: 5_000 });
  const scriptItems = scripts.data?.items ?? [];
  const effectiveSelectedId = scriptItems.some((item) => item.id === selectedId) ? selectedId : scriptItems[0]?.id ?? "";
  useEffect(() => { if (effectiveSelectedId && effectiveSelectedId !== selectedId) setSelectedId(effectiveSelectedId); }, [effectiveSelectedId, selectedId]);
  const detail = useQuery(`script-artifact:${missionId}:${effectiveSelectedId || "none"}`, (signal) => effectiveSelectedId ? scriptArtifactsApi.detail(missionId, effectiveSelectedId, signal) : Promise.resolve(undefined), { staleTime: 5_000 });

  return <section aria-label="Generated script artifacts" className="os-artifact-surface">
    <div className="os-card-heading"><div><p className="os-eyebrow">Canonical ScriptArtifact records</p><h2>Generated scripts</h2><p>Inspect immutable source, documentation, tests, provenance, and bounded version differences without executing code.</p></div><Button variant="secondary" onClick={() => { scripts.refresh(); if (effectiveSelectedId) detail.refresh(); }}>Refresh script artifacts</Button></div>
    {scripts.isLoading && !scripts.data && <LoadingPanel label="Loading immutable script artifacts" />}
    {scripts.error && !scripts.data && <ErrorPanel title="Script artifacts are unavailable" error={scripts.error} onRetry={scripts.refresh} />}
    {scripts.error && scripts.data && <DegradedNotice>The script list could not refresh; the last validated records remain visible.</DegradedNotice>}
    {scripts.data?.items.length === 0 && <Card><EmptyState title="No generated scripts recorded" description="No immutable ScriptArtifact version is linked to this run. The interface does not invent an editor workspace." /></Card>}
    {(scripts.data?.items.length ?? 0) > 0 && <div className="os-artifact-master-detail"><nav aria-label="Script versions"><ul>{scripts.data!.items.map((script: ScriptArtifactSummary) => <li key={script.id}><button type="button" aria-pressed={script.id === effectiveSelectedId} aria-label={`Inspect script ${script.name} version ${script.version}`} onClick={() => setSelectedId(script.id)}><strong>{script.name}</strong><span>v{script.version} · {script.language} · {script.validation.state}</span><small>{script.contentHash.slice(0, 12)}…</small></button></li>)}</ul></nav><main>
      {detail.isLoading && !detail.data && <LoadingPanel label="Loading verified script source" />}
      {detail.error && !detail.data && <ErrorPanel title="Script source is unavailable" error={detail.error} onRetry={detail.refresh} />}
      {detail.error && detail.data && <DegradedNotice>The selected script could not refresh; its last hash-validated detail remains visible.</DegradedNotice>}
      {detail.data?.record && <ScriptDetail record={detail.data.record} />}
    </main></div>}
  </section>;
}

function RelatedLinks({ capture }: { readonly capture: PageCaptureRecord }) {
  return <section className="os-capture-links"><h4>Canonical relationships</h4><div>
    {capture.related.evidenceIds.map((id) => <AppLink key={id} href={`/intelligence/evidence/${encodeURIComponent(id)}`}>{id}</AppLink>)}
    {capture.related.findingIds.map((id) => <AppLink key={id} href={`/intelligence/findings/${encodeURIComponent(id)}`}>{id}</AppLink>)}
    {capture.screenshot && <AppLink aria-label={`Open preview artifact ${capture.screenshot.artifactId}`} href={`/intelligence/artifacts/${encodeURIComponent(capture.screenshot.artifactId)}`}>Preview artifact metadata</AppLink>}
    {capture.fullPageScreenshot && <AppLink aria-label={`Open full-page artifact ${capture.fullPageScreenshot.artifactId}`} href={`/intelligence/artifacts/${encodeURIComponent(capture.fullPageScreenshot.artifactId)}`}>Full-page artifact metadata</AppLink>}
    {capture.planId && capture.runId && <AppLink aria-label="Open capture plan" href={`/missions/${encodeURIComponent(capture.missionId)}/runs/${encodeURIComponent(capture.runId)}?tab=plan`}>Open capture plan</AppLink>}
  </div><p className="os-muted">Observation references: {capture.related.observationIds.join(", ") || "none"}</p></section>;
}

function CaptureDetail({ record }: { readonly record: PageCaptureRecord }) {
  const previewReady = record.gallery.previewAvailable && record.gallery.previewArtifactId !== null;
  return <Card className="os-capture-detail" aria-label={`Page capture ${record.gallery.label}`}>
    <header className="os-artifact-detail-heading"><div><p className="os-eyebrow">Evidence-backed page capture</p><h3>{record.title ?? record.gallery.label}</h3><p className="os-breakable">{record.normalizedUrl}</p></div><div><StatusPill status={record.redactionState} /><StatusPill status={record.responseStatus ? `http-${record.responseStatus}` : "status_unknown"}>{record.responseStatus ? `HTTP ${record.responseStatus}` : "Status unknown"}</StatusPill></div></header>
    {previewReady ? <section className="os-capture-preview is-ready" aria-label="Capture preview ready"><div aria-hidden="true" className="os-capture-preview-mark" /><div><strong>Preview artifact is ready</strong><p>The canonical service marked this screenshot visible after redaction policy. This deployment has not registered an approved inline image-delivery adapter, so Ti-Scale shows verified metadata and a canonical artifact link instead of fabricating or bypassing content delivery.</p><AppLink aria-label={`Open preview artifact ${record.gallery.previewArtifactId}`} href={`/intelligence/artifacts/${encodeURIComponent(record.gallery.previewArtifactId!)}`}>Open preview artifact metadata</AppLink></div></section>
      : <section className="os-capture-preview is-withheld" aria-label="Capture preview unavailable"><div aria-hidden="true" className="os-capture-preview-mark" /><div><strong>Preview withheld</strong><p>{record.redactionState === "pending" ? "Redaction review is still pending." : record.redactionState === "quarantined" ? "The capture is quarantined and cannot be previewed." : "No immutable screenshot artifact is attached."}</p></div></section>}
    <KeyValueGrid items={[
      { label: "Captured", value: formatTime(record.capturedAt) }, { label: "Viewport", value: `${record.viewport.width}×${record.viewport.height} @ ${record.viewport.deviceScaleFactor}x${record.viewport.isMobile ? " · mobile" : ""}` },
      { label: "Full page", value: record.viewport.fullPage ? "Yes" : "No" }, { label: "Sensitivity", value: record.sensitivity },
      { label: "Agent", value: record.capturedByAgentName ?? record.capturedByAgentId ?? "Not reported" }, { label: "Tool", value: record.captureTool },
      { label: "Content SHA-256", value: <code className="os-breakable">{record.contentHash}</code> }, { label: "Screenshot SHA-256", value: <code className="os-breakable">{record.screenshotHash ?? "Not recorded"}</code> },
    ]} />
    <div className="os-artifact-columns">
      <section><h4>Site metadata</h4><KeyValueGrid items={[
        { label: "Content type", value: record.site.contentType ?? "Not observed" }, { label: "Content length", value: record.site.contentLength === undefined ? "Not observed" : bytes(record.site.contentLength) },
        { label: "Encoding", value: record.site.contentEncoding ?? "Not observed" }, { label: "Language", value: record.site.language ?? "Not observed" },
        { label: "Server", value: record.site.serverProduct ?? "Not observed" }, { label: "Technologies", value: record.site.technologies?.join(", ") || "Not observed" },
      ]} />{record.site.securityHeaders?.length ? <ul>{record.site.securityHeaders.map((header) => <li key={header.name}><strong>{header.name}</strong><span>{header.value}</span></li>)}</ul> : <p className="os-muted">No security headers were retained.</p>}</section>
      <section><h4>Certificate metadata</h4><KeyValueGrid items={[
        { label: "Protocol", value: record.certificate.protocol ?? "Not observed" }, { label: "Cipher", value: record.certificate.cipher ?? "Not observed" },
        { label: "Subject", value: record.certificate.subjectCommonName ?? "Not observed" }, { label: "Issuer", value: record.certificate.issuerCommonName ?? "Not observed" },
        { label: "SANs", value: record.certificate.sanDnsNames?.join(", ") || "Not observed" }, { label: "Verified", value: record.certificate.verified === undefined ? "Not observed" : record.certificate.verified ? "Yes" : "No" },
      ]} />{record.certificate.fingerprintSha256 && <p><strong>Certificate SHA-256:</strong> <code className="os-breakable">{record.certificate.fingerprintSha256}</code></p>}</section>
    </div>
    <RelatedLinks capture={record} />
  </Card>;
}

function PageCaptureGallery({ missionId, runId }: { readonly missionId: string; readonly runId?: string }) {
  const [selectedId, setSelectedId] = useState("");
  const captures = useQuery(`page-captures:${missionId}:${runId ?? "mission"}`, (signal) => pageCapturesApi.list(missionId, { ...(runId ? { runId } : {}), limit: 100 }, signal), { staleTime: 5_000 });
  const captureItems = captures.data?.items ?? [];
  const effectiveSelectedId = captureItems.some((item) => item.id === selectedId) ? selectedId : captureItems[0]?.id ?? "";
  useEffect(() => { if (effectiveSelectedId && effectiveSelectedId !== selectedId) setSelectedId(effectiveSelectedId); }, [effectiveSelectedId, selectedId]);
  const detail = useQuery(`page-capture:${missionId}:${effectiveSelectedId || "none"}`, (signal) => effectiveSelectedId ? pageCapturesApi.detail(missionId, effectiveSelectedId, signal) : Promise.resolve(undefined), { staleTime: 5_000 });
  return <section aria-label="Web page capture gallery" className="os-artifact-surface">
    <div className="os-card-heading"><div><p className="os-eyebrow">Canonical PageCapture records</p><h2>Web-page captures</h2><p>Review URL, response, viewport, hashes, redaction, site and certificate metadata, and evidence relationships.</p></div><Button variant="secondary" onClick={() => { captures.refresh(); if (effectiveSelectedId) detail.refresh(); }}>Refresh page captures</Button></div>
    {captures.isLoading && !captures.data && <LoadingPanel label="Loading evidence-backed page captures" />}
    {captures.error && !captures.data && <ErrorPanel title="Page captures are unavailable" error={captures.error} onRetry={captures.refresh} />}
    {captures.error && captures.data && <DegradedNotice>The capture gallery could not refresh; the last validated records remain visible.</DegradedNotice>}
    {captures.data?.items.length === 0 && <Card><EmptyState title="No page captures recorded" description="No authorized PageCapture record is linked to this run." /></Card>}
    {(captures.data?.items.length ?? 0) > 0 && <div className="os-artifact-master-detail"><nav aria-label="Page captures"><ul>{captures.data!.items.map((capture) => <li key={capture.id}><button type="button" aria-pressed={capture.id === effectiveSelectedId} aria-label={`Inspect page capture ${capture.gallery.label}`} onClick={() => setSelectedId(capture.id)}><strong>{capture.gallery.label}</strong><span>{capture.responseStatus ? `HTTP ${capture.responseStatus}` : "Status unknown"} · {capture.redactionState.replaceAll("_", " ")}</span><small>{formatTime(capture.capturedAt)}</small></button></li>)}</ul></nav><main>
      {detail.isLoading && !detail.data && <LoadingPanel label="Loading page-capture provenance" />}
      {detail.error && !detail.data && <ErrorPanel title="Page-capture detail is unavailable" error={detail.error} onRetry={detail.refresh} />}
      {detail.error && detail.data && <DegradedNotice>The selected capture could not refresh; its last validated detail remains visible.</DegradedNotice>}
      {detail.data?.record && <CaptureDetail record={detail.data.record} />}
    </main></div>}
  </section>;
}

export default function ArtifactIntelligenceSurface({ missionId, runId }: { readonly missionId: string; readonly runId?: string }) {
  return <div className="os-artifact-intelligence" aria-label="Script and page-capture intelligence"><ScriptWorkspace missionId={missionId} runId={runId} /><PageCaptureGallery missionId={missionId} runId={runId} /></div>;
}

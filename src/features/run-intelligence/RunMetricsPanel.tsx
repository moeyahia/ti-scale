import { Card, EmptyState, StatusPill } from "../../design-system/components/Primitives";
import { AppLink } from "../../app/router/navigation";
import type {
  AttackAttempt,
  MetricDrillDownFilter,
  MetricDrillDownReference,
  RunMetric,
  RunMetricCategory,
  RunMetricsSnapshot,
} from "../../domain/types/runIntelligence";

const CATEGORY_LABELS: Readonly<Record<RunMetricCategory, string>> = {
  objective: "Objective and plan",
  orchestration: "Agent orchestration",
  attempts: "Attack attempts",
  discovery: "Discovery and topology",
  evidence: "Evidence quality",
  reliability: "Reliability",
  resources: "Resources",
  learning: "Brain and learning",
};

const CATEGORY_ORDER = Object.keys(CATEGORY_LABELS) as RunMetricCategory[];

function formatTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium", timeStyle: "medium",
  }).format(date);
}

function formatDuration(milliseconds: number): string {
  if (milliseconds < 1_000) return `${Math.round(milliseconds)} ms`;
  const seconds = milliseconds / 1_000;
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);
  return `${minutes}m ${remainder}s`;
}

export function formatRunMetric(metric: RunMetric): string {
  if (metric.measurement === "not_observed" || metric.value === null) return "Not observed";
  if (metric.unit === "ratio") return new Intl.NumberFormat(undefined, { style: "percent", maximumFractionDigits: 1 }).format(metric.value);
  if (metric.unit === "milliseconds") return formatDuration(metric.value);
  if (metric.unit === "cost") return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 6 }).format(metric.value)} cost units`;
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(metric.value);
}

function formatFilter(filter: MetricDrillDownFilter): string {
  const value = Array.isArray(filter.value) ? filter.value.join(", ") : filter.value === null ? "null" : String(filter.value);
  return `${filter.field} ${filter.operator.replaceAll("_", " ")} ${value}`;
}

function drillDownHref(reference: MetricDrillDownReference): string {
  const run = encodeURIComponent(reference.runId);
  const mission = encodeURIComponent(reference.missionId);
  if (reference.resource === "evidence") return `/intelligence/evidence?runId=${run}`;
  if (reference.resource === "findings") return `/intelligence/findings?runId=${run}`;
  if (reference.resource === "artifacts") return `/intelligence/artifacts?runId=${run}`;
  if (["events", "actions", "tool_calls", "provider_turns", "engagement_log_records"].includes(reference.resource)) {
    return `/observability?runId=${run}`;
  }
  if (["memory_context_packs", "memory_context_items"].includes(reference.resource)) return `/brain?runId=${run}`;
  if (reference.resource === "lesson_usage") return `/learning?runId=${run}`;
  if (["observations", "evidence_candidates"].includes(reference.resource)) {
    return `/missions/${mission}/runs/${run}?tab=evidence`;
  }
  return `/missions/${mission}/runs/${run}?tab=plan`;
}

function MetricDrillDown({ metric }: { readonly metric: RunMetric }) {
  return <details className="os-raw-details">
    <summary>Inspect {metric.drillDown.length} canonical drill-down{metric.drillDown.length === 1 ? "" : "s"}</summary>
    <ol>
      {metric.drillDown.map((reference) => <li key={reference.id}>
        <strong>{reference.resource.replaceAll("_", " ")}</strong>
        <dl className="os-key-values">
          <div><dt>Role</dt><dd>{reference.role}</dd></div>
          <div><dt>Aggregation</dt><dd>{reference.aggregation.replaceAll("_", " ")}</dd></div>
          <div><dt>Field</dt><dd>{reference.field ?? "Whole record"}</dd></div>
          <div><dt>Mission</dt><dd><code>{reference.missionId}</code></dd></div>
          <div><dt>Run</dt><dd><code>{reference.runId}</code></dd></div>
        </dl>
        <ul aria-label={`Filters for ${metric.label}`}>
          {reference.filters.map((filter, index) => <li key={`${reference.id}-${index}`}><code>{formatFilter(filter)}</code></li>)}
        </ul>
        <AppLink href={drillDownHref(reference)}>Open filtered canonical records</AppLink>
      </li>)}
    </ol>
  </details>;
}

function MetricCategory({ category, metrics }: { readonly category: RunMetricCategory; readonly metrics: readonly RunMetric[] }) {
  return <section aria-labelledby={`run-metrics-${category}`}>
    <h3 id={`run-metrics-${category}`}>{CATEGORY_LABELS[category]}</h3>
    <div className="os-table-wrap">
      <table className="os-data-table">
        <thead><tr><th>Metric</th><th>Value</th><th>Quality</th><th>Canonical records</th></tr></thead>
        <tbody>{metrics.map((metric) => <tr key={metric.key}>
          <th scope="row">{metric.label}<small><code>{metric.key}</code></small></th>
          <td>{formatRunMetric(metric)}</td>
          <td><StatusPill status={metric.measurement}>{metric.measurement.replaceAll("_", " ")}</StatusPill></td>
          <td><MetricDrillDown metric={metric} /></td>
        </tr>)}</tbody>
      </table>
    </div>
  </section>;
}

function AttemptTarget({ attempt }: { readonly attempt: AttackAttempt }) {
  if (!attempt.targetAssetId && !attempt.targetServiceId) return <>Not represented</>;
  return <span>
    {attempt.targetAssetId && <code>{attempt.targetAssetId}</code>}
    {attempt.targetAssetId && attempt.targetServiceId && " / "}
    {attempt.targetServiceId && <code>{attempt.targetServiceId}</code>}
  </span>;
}

function AttackAttemptsTable({ attempts }: { readonly attempts: readonly AttackAttempt[] }) {
  if (attempts.length === 0) return <EmptyState title="No classified attack attempts" description="No canonical AttackAttempt records exist for this run. Tool process failures are not silently counted as failed attacks." />;
  return <div className="os-table-wrap"><table className="os-data-table">
    <thead><tr><th>Technique and objective</th><th>Target</th><th>Status</th><th>Outcome</th><th>Evidence</th></tr></thead>
    <tbody>{attempts.map((attempt) => <tr key={attempt.id}>
      <th scope="row">{attempt.techniqueName}<small>{attempt.objective}</small><small><code>{attempt.id}</code></small></th>
      <td><AttemptTarget attempt={attempt} /></td>
      <td><StatusPill status={attempt.status}>{attempt.status.replaceAll("_", " ")}</StatusPill></td>
      <td>{attempt.outcomeSummary ?? (attempt.failureCategory ? `Failure category: ${attempt.failureCategory}` : "Not classified")}</td>
      <td>{attempt.evidence.length === 0 ? "No evidence linked" : <details className="os-raw-details"><summary>{attempt.evidence.length} linked item{attempt.evidence.length === 1 ? "" : "s"}</summary><ul>{attempt.evidence.map((evidence) => <li key={`${evidence.evidenceId}-${evidence.relationship}`}><AppLink href={`/intelligence/evidence/${encodeURIComponent(evidence.evidenceId)}`}>{evidence.evidenceId}</AppLink> · {evidence.relationship} · {evidence.verificationState} · {Math.round(evidence.confidence * 100)}%</li>)}</ul></details>}</td>
    </tr>)}</tbody>
  </table></div>;
}

export function RunMetricsPanel({ snapshot, attackAttempts = [] }: {
  readonly snapshot: RunMetricsSnapshot | null;
  readonly attackAttempts?: readonly AttackAttempt[];
}) {
  if (!snapshot) return <Card><EmptyState title="No reproducible metrics snapshot" description="Run statistics will appear only after the server stores a canonical RunMetricsSnapshot. No values are estimated in the browser." /></Card>;
  return <div>
    <Card>
      <div className="os-card-heading"><div><p className="os-eyebrow">Reproducible run truth</p><h2>Run intelligence</h2><p>Computed through event sequence {snapshot.throughEventSequence} at {formatTimestamp(snapshot.computedAt)}.</p></div><StatusPill status="verified">Canonical snapshot</StatusPill></div>
      <dl className="os-key-values">
        <div><dt>Snapshot</dt><dd><code>{snapshot.id}</code></dd></div>
        <div><dt>Schema</dt><dd>{snapshot.metricSchemaVersion}</dd></div>
        <div><dt>Recomputation hash</dt><dd><code>{snapshot.recomputationHash}</code></dd></div>
        <div><dt>Source records</dt><dd>{Object.values(snapshot.sourceCounts).reduce((total, count) => total + count, 0)}</dd></div>
      </dl>
    </Card>
    {CATEGORY_ORDER.map((category) => <MetricCategory key={category} category={category} metrics={snapshot.metrics.filter((metric) => metric.category === category)} />)}
    <section aria-labelledby="run-attack-attempts"><h3 id="run-attack-attempts">Classified attack attempts</h3><AttackAttemptsTable attempts={attackAttempts} /></section>
  </div>;
}

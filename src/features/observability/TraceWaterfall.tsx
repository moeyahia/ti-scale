import type { CSSProperties } from "react";
import type { TraceRecord, TraceSummaryRecord } from "../../domain/types/operations";
import { StatusPill } from "../../design-system/components/Primitives";
import { formatTime, JsonDetails } from "../runs/OperationalSurface";

function compactDuration(milliseconds: number): string {
  if (milliseconds < 1_000) return `${Math.round(milliseconds)}ms`;
  if (milliseconds < 60_000) return `${(milliseconds / 1_000).toFixed(milliseconds < 10_000 ? 1 : 0)}s`;
  return `${Math.floor(milliseconds / 60_000)}m ${Math.round((milliseconds % 60_000) / 1_000)}s`;
}

function barStyle(record: TraceRecord, trace: TraceSummaryRecord): CSSProperties {
  const traceStart = Date.parse(trace.startedAt);
  const traceDuration = Math.max(1, trace.durationMs);
  const recordStart = Date.parse(record.startedAt);
  const offset = Number.isFinite(recordStart) ? Math.max(0, Math.min(98, ((recordStart - traceStart) / traceDuration) * 100)) : 0;
  const width = Math.max(1.5, Math.min(100 - offset, (Math.max(record.durationMs, traceDuration * .015) / traceDuration) * 100));
  return { "--trace-offset": `${offset}%`, "--trace-width": `${width}%` } as CSSProperties;
}

export function TraceWaterfall({ trace, records }: { trace: TraceSummaryRecord; records: TraceRecord[] }) {
  const chronological = [...records].reverse();
  return <ol className="os-trace-waterfall" aria-label={`Correlated records for trace ${trace.traceId}`}>
    {chronological.map((record) => <li key={record.id}>
      <div className="os-trace-record-heading">
        <div><span className="os-trace-kind">{record.kind.replace("_", " ")}</span><strong>{record.title}</strong></div>
        <StatusPill status={record.status} />
      </div>
      <div className="os-trace-track" aria-hidden="true">
        <span className={`os-trace-bar os-trace-bar--${record.kind}`} style={barStyle(record, trace)} />
      </div>
      <div className="os-trace-record-body">
        <p>{record.summary}</p>
        <dl>
          <div><dt>Start</dt><dd>{formatTime(record.startedAt)}</dd></div>
          <div><dt>Duration</dt><dd>{compactDuration(record.durationMs)}</dd></div>
          <div><dt>Owner</dt><dd>{record.agentId ?? "System"}</dd></div>
          <div><dt>Span</dt><dd>{record.correlation.spanId ?? "Not emitted"}</dd></div>
        </dl>
        <JsonDetails label="Redacted technical detail" value={{
          sourceId: record.sourceId,
          mission: record.mission,
          runId: record.runId,
          stepId: record.stepId,
          actionId: record.actionId,
          correlation: record.correlation,
          raw: record.raw,
        }} />
      </div>
    </li>)}
  </ol>;
}

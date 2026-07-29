import type { MissionReference, OperationsPage } from "../operations/types";

export type TraceStatus = "active" | "completed" | "failed";
export type TraceRecordKind = "event" | "log" | "action" | "tool_call";

export interface TraceSummaryProjection {
  readonly id: string;
  readonly traceId: string;
  readonly status: TraceStatus;
  readonly summary: string;
  readonly mission: MissionReference | null;
  readonly missionCount: number;
  readonly runId: string | null;
  readonly runCount: number;
  readonly journey: "autonomous" | "guided" | null;
  readonly startedAt: string;
  readonly endedAt: string;
  readonly durationMs: number;
  readonly counts: {
    readonly events: number;
    readonly logs: number;
    readonly actions: number;
    readonly toolCalls: number;
    readonly errors: number;
  };
}

export interface TraceRecordProjection {
  /** Source-qualified stable identifier, safe to use as a cursor tie-breaker. */
  readonly id: string;
  readonly sourceId: string;
  readonly kind: TraceRecordKind;
  readonly title: string;
  readonly summary: string;
  readonly status: string;
  readonly mission: MissionReference | null;
  readonly runId: string | null;
  readonly stepId: string | null;
  readonly actionId: string | null;
  readonly agentId: string | null;
  readonly startedAt: string;
  readonly endedAt: string;
  readonly durationMs: number;
  readonly correlation: {
    readonly traceId: string;
    readonly spanId: string | null;
    readonly parentSpanId: string | null;
  };
  /** Redacted, source-specific technical detail. Never contains normalized arguments. */
  readonly raw: unknown;
}

export interface TraceDetailProjection {
  readonly schemaVersion: "2.4";
  readonly trace: TraceSummaryProjection;
  readonly records: OperationsPage<TraceRecordProjection>;
}

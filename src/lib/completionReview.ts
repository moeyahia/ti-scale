import type { EvaluationBudgetMetric, EvaluationComparisonMetric, EventRecord, FindingRecord } from "../domain/types/operations";
import type { PlanStep, RuntimeRun } from "../domain/types/runtimeV2";

export interface CompletionEventSummary {
  retryEvents: number;
  recoveryEvents: number;
  policyEvents: number;
  safeStopEvents: number;
  contextPackIds: string[];
}

export function summarizeCompletionEvents(events: readonly EventRecord[]): CompletionEventSummary {
  const contextPackIds = new Set<string>();
  let retryEvents = 0;
  let recoveryEvents = 0;
  let policyEvents = 0;
  let safeStopEvents = 0;
  for (const event of events) {
    const semantic = `${event.eventType} ${event.summary}`.toLocaleLowerCase("en-US");
    if (/retry|attempt\.repeated/u.test(semantic)) retryEvents += 1;
    if (/recover|stagn|loop|lease\.expired|worker\.lost/u.test(semantic)) recoveryEvents += 1;
    if (/policy|contract|authori[sz]|scope|approval|decision/u.test(semantic)) policyEvents += 1;
    if (/safe[-_. ]?stop|outside (?:the )?contract/u.test(semantic)) safeStopEvents += 1;
    if (event.correlation.contextPackId) contextPackIds.add(event.correlation.contextPackId);
  }
  return { retryEvents, recoveryEvents, policyEvents, safeStopEvents, contextPackIds: [...contextPackIds] };
}

export function completionOutcomeLabel(run: Pick<RuntimeRun, "journey" | "status" | "statusReason">): string {
  if (run.status === "completed") return run.journey === "autonomous" ? "Completed autonomously" : "Guided mission completed";
  if (run.status === "cancelled") return "Cancelled by an authorized operator";
  if (run.status === "failed") {
    return run.journey === "autonomous" && /contract|scope|policy/iu.test(run.statusReason ?? "")
      ? "Safe-stopped outside contract"
      : "Failed safely";
  }
  return "Completion review unavailable";
}

export function unresolvedCompletionItems(
  steps: readonly PlanStep[],
  findings: readonly FindingRecord[],
): Array<{ id: string; type: "step" | "finding"; status: string; summary: string }> {
  return [
    ...steps
      .filter((step) => !["completed", "skipped", "cancelled"].includes(step.status))
      .map((step) => ({ id: step.id, type: "step" as const, status: step.status, summary: step.title })),
    ...findings
      .filter((finding) => !["verified", "accepted_risk", "rejected"].includes(finding.reviewStatus))
      .map((finding) => ({ id: finding.id, type: "finding" as const, status: finding.reviewStatus, summary: finding.title })),
  ];
}

export interface CompletionArtifactPageTruth {
  readonly partial: boolean;
  readonly visibleArtifactCount: number;
  readonly visibleReportCount: number;
  readonly emptyArtifactMessage: string;
  readonly reportSummary: string;
}

export function completionArtifactPageTruth(
  artifactTypes: readonly string[],
  nextCursor: string | null | undefined,
): CompletionArtifactPageTruth {
  const partial = Boolean(nextCursor);
  const visibleReportCount = artifactTypes.filter((type) => type.toLocaleLowerCase("en-US").includes("report")).length;
  const reportNoun = `report artifact${visibleReportCount === 1 ? "" : "s"}`;
  return {
    partial,
    visibleArtifactCount: artifactTypes.length,
    visibleReportCount,
    emptyArtifactMessage: partial
      ? "No artifact metadata is visible in the loaded page. Additional artifact records were not loaded, so no total can be concluded."
      : "No artifact metadata was recorded for this run.",
    reportSummary: partial
      ? visibleReportCount > 0
        ? `${visibleReportCount} ${reportNoun} visible in the loaded page. Additional artifact records were not loaded, so the total report count is unknown.`
        : "No report artifacts are visible in the loaded page. Additional artifact records were not loaded, so the total report count is unknown."
      : `${visibleReportCount} ${reportNoun} linked to this run.`,
  };
}

export interface UnresolvedCompletionTruth {
  readonly items: ReturnType<typeof unresolvedCompletionItems>;
  readonly partial: boolean;
  readonly status: "attention" | "partial" | "clear";
  readonly statusLabel: "Attention" | "Attention · partial" | "Partial" | "Clear";
  readonly emptyMessage: string;
  readonly partialMessage: string | null;
}

export function unresolvedCompletionTruth(
  steps: readonly PlanStep[],
  findings: readonly FindingRecord[],
  findingsNextCursor: string | null | undefined,
): UnresolvedCompletionTruth {
  const items = unresolvedCompletionItems(steps, findings);
  const partial = Boolean(findingsNextCursor);
  if (items.length > 0) {
    return {
      items,
      partial,
      status: "attention",
      statusLabel: partial ? "Attention · partial" : "Attention",
      emptyMessage: "",
      partialMessage: partial
        ? "Additional finding records were not loaded. This unresolved-items list is partial."
        : null,
    };
  }
  if (partial) {
    return {
      items,
      partial: true,
      status: "partial",
      statusLabel: "Partial",
      emptyMessage: "No unresolved latest-plan steps or unreviewed findings are visible in the loaded records. Additional finding records were not loaded, so this is not an all-clear result.",
      partialMessage: null,
    };
  }
  return {
    items,
    partial: false,
    status: "clear",
    statusLabel: "Clear",
    emptyMessage: "No unresolved latest-plan steps or unreviewed findings are visible in the complete current scope.",
    partialMessage: null,
  };
}

export function comparisonBasisLabel(basis: "same_mission_and_journey" | "same_engagement_and_journey" | null): string {
  if (basis === "same_mission_and_journey") return "Same mission and journey";
  if (basis === "same_engagement_and_journey") return "Same engagement and journey";
  return "No in-scope comparison basis";
}

export function formatComparisonMetricValue(metric: Pick<EvaluationComparisonMetric, "unit">, value: number): string {
  if (metric.unit === "ratio") return `${Math.round(value * 10_000) / 100}%`;
  if (metric.unit === "milliseconds") {
    const magnitude = Math.abs(value);
    if (magnitude < 1_000) return `${Math.round(value)} ms`;
    if (magnitude < 60_000) return `${Math.round(value / 100) / 10} s`;
    return `${Math.round(value / 6_000) / 10} min`;
  }
  if (metric.unit === "cost") return new Intl.NumberFormat(undefined, { style: "currency", currency: "USD", maximumFractionDigits: 4 }).format(value);
  return new Intl.NumberFormat().format(value);
}

export function formatBudgetMetricValue(metric: Pick<EvaluationBudgetMetric, "unit">, value: number | null): string {
  if (value === null) return "Unknown";
  if (metric.unit === "milliseconds") {
    if (value < 1_000) return `${Math.round(value)} ms`;
    if (value < 60_000) return `${Math.round(value / 100) / 10} s`;
    if (value < 3_600_000) return `${Math.round(value / 6_000) / 10} min`;
    return `${Math.round(value / 360_000) / 10} hr`;
  }
  if (metric.unit === "cost") {
    return new Intl.NumberFormat(undefined, { style: "currency", currency: "USD", maximumFractionDigits: 4 }).format(value);
  }
  return new Intl.NumberFormat().format(value);
}

export function budgetStatusLabel(metric: EvaluationBudgetMetric): string {
  if (metric.status === "unknown_usage") return "Usage unknown";
  if (metric.status === "not_configured") return "No limit configured";
  if (metric.status === "limit_exceeded") return "Limit exceeded";
  if (metric.status === "limit_reached") return "Limit reached";
  return "Within limit";
}

export function findingReviewOptions(status: string): readonly ("under_review" | "verified" | "rejected" | "accepted_risk")[] {
  if (status === "draft" || status === "verified" || status === "rejected" || status === "accepted_risk") return ["under_review"];
  if (status === "under_review") return ["verified", "rejected", "accepted_risk"];
  return [];
}

export function lessonReviewOptions(status: string): readonly ("under_review" | "verified" | "rejected" | "stale" | "superseded")[] {
  if (status === "proposed" || status === "rejected") return ["under_review", ...(status === "proposed" ? ["rejected" as const] : [])];
  if (status === "under_review") return ["verified", "rejected"];
  if (status === "verified") return ["stale", "superseded"];
  if (status === "stale") return ["under_review", "superseded"];
  return [];
}

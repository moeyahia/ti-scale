import {
  HISTORICAL_REPORTED_OUTCOME_CLASSIFICATIONS,
  type HistoricalReportedOutcomeClassification,
  type HistoricalReportedOutcomeSummary,
} from "../../domain/types/brain";

export const HISTORICAL_REPORTED_OUTCOME_FILTERS = [
  ...HISTORICAL_REPORTED_OUTCOME_CLASSIFICATIONS,
  "not_reported",
] as const;

export type HistoricalReportedOutcomeFilter =
  (typeof HISTORICAL_REPORTED_OUTCOME_FILTERS)[number] | "";

export function historicalReportedOutcomeLabel(
  classification: HistoricalReportedOutcomeClassification | "not_reported",
): string {
  if (classification === "reported_success") return "Reported success";
  if (classification === "reported_failure") return "Reported failure";
  if (classification === "mixed") return "Mixed reports";
  if (classification === "unknown") return "No outcome stated";
  return "Not reported";
}

export function memoryMatchesHistoricalReportedOutcome(
  outcome: HistoricalReportedOutcomeSummary | undefined,
  filter: HistoricalReportedOutcomeFilter,
): boolean {
  if (!filter) return true;
  if (filter === "not_reported") return outcome === undefined;
  return outcome?.classification === filter;
}

export function HistoricalReportedOutcomeBadge({
  outcome,
  classification,
  count,
  showNotReported = true,
}: {
  readonly outcome?: HistoricalReportedOutcomeSummary;
  readonly classification?: HistoricalReportedOutcomeClassification | "not_reported";
  readonly count?: number;
  readonly showNotReported?: boolean;
}) {
  const represented = outcome?.classification ?? classification ?? "not_reported";
  if (represented === "not_reported" && !showNotReported) return null;
  const label = historicalReportedOutcomeLabel(represented);
  const custody = outcome
    ? ` ${outcome.claimCount} historical claim${outcome.claimCount === 1 ? "" : "s"} from ${outcome.sourceCount} source${outcome.sourceCount === 1 ? "" : "s"}.`
    : "";
  return (
    <span
      className={`brain-outcome-badge brain-reported-outcome-badge brain-reported-outcome-badge--${represented}`}
      role="note"
      aria-label={`Historical source report: ${label}${count === undefined ? "" : `, ${count}`}.${custody} This is not a verified attack outcome.`}
      title="Historical source report only — not independently verified"
    >
      {label}{count === undefined ? "" : ` ${count}`}
    </span>
  );
}

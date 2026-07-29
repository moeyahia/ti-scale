export const HISTORICAL_REPORTED_OUTCOME_CLASSIFICATIONS = [
  "reported_success",
  "reported_failure",
  "mixed",
  "unknown",
] as const;

export const HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION =
  "historical-reported-outcome/v1" as const;

export type HistoricalReportedOutcomeClassification =
  (typeof HISTORICAL_REPORTED_OUTCOME_CLASSIFICATIONS)[number];

export interface HistoricalReportedOutcomeSummary {
  readonly classification: HistoricalReportedOutcomeClassification;
  /** Confidence that the source claim was classified correctly, not confidence that the attack succeeded. */
  readonly classificationConfidence: number;
  readonly claimCount: number;
  readonly sourceCount: number;
  readonly policyVersion: string;
}

export function isHistoricalReportedOutcomeClassification(
  value: unknown,
): value is HistoricalReportedOutcomeClassification {
  return typeof value === "string"
    && (HISTORICAL_REPORTED_OUTCOME_CLASSIFICATIONS as readonly string[]).includes(value);
}

export function historicalReportedOutcomeTag(
  classification: HistoricalReportedOutcomeClassification,
): string {
  return `ti-scale/reported-outcome/${classification.replaceAll("_", "-")}`;
}

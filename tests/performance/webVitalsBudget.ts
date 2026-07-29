export const WEB_VITAL_SAMPLE_COUNT = 7;
export const CLS_SESSION_GAP_MS = 1_000;
export const CLS_SESSION_MAX_MS = 5_000;

export interface LayoutShiftSample {
  readonly startTime: number;
  readonly value: number;
  readonly hadRecentInput: boolean;
}

export interface WebVitalValues {
  readonly fcpMs: number;
  readonly lcpMs: number;
  readonly inpMs: number;
  readonly cls: number;
}

export interface WebVitalBudget extends WebVitalValues {
  readonly environment: "desktop" | "mid-tier-mobile";
}

export interface WebVitalSample extends WebVitalValues {
  readonly sample: number;
  readonly navigationStartEpochMs: number;
  readonly domContentLoadedMs: number;
  readonly loadEventMs: number;
}

export interface WebVitalPercentiles extends WebVitalValues {
  readonly method: "nearest-rank";
  readonly percentile: 75;
  readonly sampleCount: number;
}

export interface WebVitalBudgetFailure {
  readonly metric: keyof WebVitalValues;
  readonly actual: number;
  readonly budget: number;
  readonly message: string;
}

export const WEB_VITAL_BUDGETS: Readonly<Record<WebVitalBudget["environment"], WebVitalBudget>> =
  Object.freeze({
    desktop: Object.freeze({
      environment: "desktop",
      fcpMs: 1_000,
      lcpMs: 1_800,
      inpMs: 150,
      cls: 0.05,
    }),
    "mid-tier-mobile": Object.freeze({
      environment: "mid-tier-mobile",
      fcpMs: 1_500,
      lcpMs: 2_500,
      inpMs: 200,
      cls: 0.05,
    }),
  });

function finiteNonNegative(value: number, label: string): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${label} must be a finite non-negative number`);
  }
  return value;
}

/**
 * Compute the current Core Web Vitals CLS definition: the largest burst of
 * unexpected shifts, where adjacent shifts are less than one second apart and
 * one session window remains shorter than five seconds.
 */
export function maximumClsSessionWindow(
  shifts: readonly LayoutShiftSample[],
): number {
  const eligible = shifts
    .map((shift, index) => ({
      startTime: finiteNonNegative(
        shift.startTime,
        `Layout shift ${index + 1} start time`,
      ),
      value: finiteNonNegative(
        shift.value,
        `Layout shift ${index + 1} value`,
      ),
      hadRecentInput: shift.hadRecentInput,
    }))
    .filter(({ hadRecentInput }) => !hadRecentInput)
    .sort((left, right) => left.startTime - right.startTime);
  let maximum = 0;
  let sessionValue = 0;
  let sessionStartedAt: number | undefined;
  let previousShiftAt: number | undefined;
  for (const shift of eligible) {
    const continuesSession = sessionStartedAt !== undefined
      && previousShiftAt !== undefined
      && shift.startTime - previousShiftAt < CLS_SESSION_GAP_MS
      && shift.startTime - sessionStartedAt < CLS_SESSION_MAX_MS;
    if (continuesSession) {
      sessionValue += shift.value;
    } else {
      sessionStartedAt = shift.startTime;
      sessionValue = shift.value;
    }
    previousShiftAt = shift.startTime;
    maximum = Math.max(maximum, sessionValue);
  }
  return maximum;
}

export function nearestRankPercentile(
  values: readonly number[],
  percentile: number,
): number {
  if (values.length === 0) throw new Error("A percentile requires at least one sample");
  if (!Number.isFinite(percentile) || percentile <= 0 || percentile > 100) {
    throw new Error("Percentile must be greater than zero and at most 100");
  }
  const ordered = values
    .map((value, index) => finiteNonNegative(value, `Sample ${index + 1}`))
    .sort((left, right) => left - right);
  return ordered[Math.ceil((percentile / 100) * ordered.length) - 1]!;
}

export function webVitalP75(
  samples: readonly WebVitalSample[],
): WebVitalPercentiles {
  if (samples.length < WEB_VITAL_SAMPLE_COUNT) {
    throw new Error(
      `The browser-performance gate requires at least ${WEB_VITAL_SAMPLE_COUNT} samples`,
    );
  }
  return Object.freeze({
    method: "nearest-rank",
    percentile: 75,
    sampleCount: samples.length,
    fcpMs: nearestRankPercentile(samples.map(({ fcpMs }) => fcpMs), 75),
    lcpMs: nearestRankPercentile(samples.map(({ lcpMs }) => lcpMs), 75),
    inpMs: nearestRankPercentile(samples.map(({ inpMs }) => inpMs), 75),
    cls: nearestRankPercentile(samples.map(({ cls }) => cls), 75),
  });
}

export function evaluateWebVitalBudget(
  percentiles: WebVitalPercentiles,
  budget: WebVitalBudget,
): readonly WebVitalBudgetFailure[] {
  const metrics = ["fcpMs", "lcpMs", "inpMs", "cls"] as const;
  return Object.freeze(metrics.flatMap((metric) => {
    const actual = finiteNonNegative(percentiles[metric], `Measured ${metric}`);
    const maximum = finiteNonNegative(budget[metric], `Budget ${metric}`);
    if (actual <= maximum) return [];
    const unit = metric === "cls" ? "" : " ms";
    return [{
      metric,
      actual,
      budget: maximum,
      message: `${metric} p75 is ${actual}${unit}; ${budget.environment} budget is ${maximum}${unit}.`,
    }];
  }));
}

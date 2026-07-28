import { describe, expect, test } from "bun:test";
import {
  evaluateWebVitalBudget,
  maximumClsSessionWindow,
  nearestRankPercentile,
  WEB_VITAL_BUDGETS,
  WEB_VITAL_SAMPLE_COUNT,
  webVitalP75,
  type WebVitalSample,
} from "../../performance/webVitalsBudget";

function sample(
  index: number,
  overrides: Partial<WebVitalSample> = {},
): WebVitalSample {
  return {
    sample: index,
    navigationStartEpochMs: 1_000 + index,
    domContentLoadedMs: 200 + index,
    loadEventMs: 300 + index,
    fcpMs: 400 + index,
    lcpMs: 700 + index,
    inpMs: 40 + index,
    cls: index / 1_000,
    ...overrides,
  };
}

describe("browser Web Vitals release budget", () => {
  test("computes CLS as the largest valid session window", () => {
    expect(maximumClsSessionWindow([
      { startTime: 2_000, value: 0.03, hadRecentInput: false },
      { startTime: 0, value: 0.02, hadRecentInput: false },
      { startTime: 500, value: 0.02, hadRecentInput: false },
      { startTime: 2_400, value: 0.005, hadRecentInput: true },
    ])).toBe(0.04);
  });

  test("starts a new CLS window at the one and five second boundaries", () => {
    expect(maximumClsSessionWindow([
      { startTime: 0, value: 0.01, hadRecentInput: false },
      { startTime: 900, value: 0.01, hadRecentInput: false },
      { startTime: 1_800, value: 0.01, hadRecentInput: false },
      { startTime: 2_700, value: 0.01, hadRecentInput: false },
      { startTime: 3_600, value: 0.01, hadRecentInput: false },
      { startTime: 4_500, value: 0.01, hadRecentInput: false },
      { startTime: 5_000, value: 0.02, hadRecentInput: false },
      { startTime: 6_000, value: 0.03, hadRecentInput: false },
    ])).toBeCloseTo(0.06, 12);
  });

  test("rejects malformed CLS entries", () => {
    expect(() => maximumClsSessionWindow([
      { startTime: -1, value: 0.01, hadRecentInput: false },
    ])).toThrow("finite non-negative");
    expect(() => maximumClsSessionWindow([
      { startTime: 1, value: Number.NaN, hadRecentInput: false },
    ])).toThrow("finite non-negative");
  });

  test("computes the documented nearest-rank p75", () => {
    expect(nearestRankPercentile([7, 1, 6, 2, 5, 3, 4], 75)).toBe(6);
    expect(nearestRankPercentile([0, 0, 0, 0], 75)).toBe(0);
  });

  test("rejects empty, invalid, and negative samples", () => {
    expect(() => nearestRankPercentile([], 75)).toThrow("at least one sample");
    expect(() => nearestRankPercentile([1], 0)).toThrow("greater than zero");
    expect(() => nearestRankPercentile([-1], 75)).toThrow("finite non-negative");
    expect(() => nearestRankPercentile([Number.NaN], 75)).toThrow("finite non-negative");
  });

  test("requires seven samples and computes every p75 from the same sample set", () => {
    const samples = Array.from({ length: WEB_VITAL_SAMPLE_COUNT }, (_, index) =>
      sample(index + 1));
    const result = webVitalP75(samples);
    expect(result).toEqual({
      method: "nearest-rank",
      percentile: 75,
      sampleCount: 7,
      fcpMs: 406,
      lcpMs: 706,
      inpMs: 46,
      cls: 0.006,
    });
    expect(() => webVitalP75(samples.slice(0, 6))).toThrow("at least 7 samples");
  });

  test("reports each p75 budget violation without collapsing metrics into one score", () => {
    const failures = evaluateWebVitalBudget({
      method: "nearest-rank",
      percentile: 75,
      sampleCount: 7,
      fcpMs: 1_001,
      lcpMs: 1_801,
      inpMs: 151,
      cls: 0.051,
    }, WEB_VITAL_BUDGETS.desktop);
    expect(failures.map(({ metric }) => metric)).toEqual([
      "fcpMs",
      "lcpMs",
      "inpMs",
      "cls",
    ]);
    expect(failures.every(({ message }) => message.includes("budget"))).toBe(true);
  });

  test("accepts values exactly on each environment budget", () => {
    for (const budget of Object.values(WEB_VITAL_BUDGETS)) {
      expect(evaluateWebVitalBudget({
        method: "nearest-rank",
        percentile: 75,
        sampleCount: 7,
        fcpMs: budget.fcpMs,
        lcpMs: budget.lcpMs,
        inpMs: budget.inpMs,
        cls: budget.cls,
      }, budget)).toEqual([]);
    }
  });

  test("does not round a just-over-budget CLS value into a pass", () => {
    const failures = evaluateWebVitalBudget({
      method: "nearest-rank",
      percentile: 75,
      sampleCount: 7,
      fcpMs: 1_000,
      lcpMs: 1_800,
      inpMs: 150,
      cls: 0.0504,
    }, WEB_VITAL_BUDGETS.desktop);
    expect(failures.map(({ metric }) => metric)).toEqual(["cls"]);
  });
});

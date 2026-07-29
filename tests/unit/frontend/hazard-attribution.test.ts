import { describe, expect, test } from "bun:test";
import { operationalHazardResetAttribution } from "../../../src/features/brain/hazardAttribution";

function hazard(exactResets: number | undefined, overallMinimum: number | null) {
  return {
    corroboration: {
      exactHangCount: 3,
      observedAttemptCount: 3,
      operatorReportedResetMinimum: overallMinimum,
    },
    recovery: {
      summary: "Restore the affected component and prove the baseline.",
      pattern: null,
      cost: exactResets === undefined ? {} : { resetCount: exactResets },
    },
  };
}

describe("operational hazard reset attribution", () => {
  test("keeps an aggregate recovery burden separate from exact procedure receipts", () => {
    expect(operationalHazardResetAttribution(hazard(2, 11))).toEqual({
      exactProcedureResetCount: 2,
      operatorReportedOverallMinimum: 11,
      minimumNotAttributedToThisProcedure: 9,
    });
  });

  test("does not invent an unattributed count when no aggregate was reported", () => {
    expect(operationalHazardResetAttribution(hazard(undefined, null))).toEqual({
      exactProcedureResetCount: 0,
      operatorReportedOverallMinimum: null,
      minimumNotAttributedToThisProcedure: null,
    });
  });

  test("never renders a negative unattributed minimum for inconsistent historical input", () => {
    expect(operationalHazardResetAttribution(hazard(4, 2)).minimumNotAttributedToThisProcedure).toBe(0);
  });
});

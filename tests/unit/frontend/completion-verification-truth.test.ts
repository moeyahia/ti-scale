import { describe, expect, test } from "bun:test";
import { completionVerificationTruth } from "../../../src/lib/completionReview";

describe("completion verification truth", () => {
  test("labels an exact Guided result without evidence as workflow-only", () => {
    expect(completionVerificationTruth({
      scores: { objectiveCompletion: 1, verifiedObjectiveCompletion: 0 },
      metrics: { completionBasis: "canonical_result_without_verified_evidence" },
      evidenceCoverage: 0,
    })).toEqual({
      status: "workflow_only",
      label: "Workflow complete · not evidence-verified",
      explanation: "The exact bounded workflow returned a canonical result, but no verified retained evidence supports a stronger claim. Engagement Logs are not evidence.",
    });
  });

  test("labels completion as verified only when the evaluator records that basis", () => {
    expect(completionVerificationTruth({
      scores: { objectiveCompletion: 1, verifiedObjectiveCompletion: 1 },
      metrics: { completionBasis: "verified_evidence" },
      evidenceCoverage: 1,
    }).status).toBe("verified");
  });

  test("does not turn a terminal record without successful objective evaluation into completion", () => {
    expect(completionVerificationTruth({
      scores: { objectiveCompletion: 0, verifiedObjectiveCompletion: 0 },
      metrics: { completionBasis: "outcome_not_completed" },
      evidenceCoverage: 0,
    }).status).toBe("not_completed");
    expect(completionVerificationTruth(undefined).status).toBe("not_evaluated");
  });
});

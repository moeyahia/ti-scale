import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import {
  MemoryOutcomeTags,
  canonicalMemoryOutcomeTags,
  memoryMatchesOutcomeFilter,
} from "../../../src/features/brain/MemoryOutcomeTags";
import {
  HistoricalReportedOutcomeBadge,
  historicalReportedOutcomeLabel,
  memoryMatchesHistoricalReportedOutcome,
} from "../../../src/features/brain/HistoricalReportedOutcomeBadge";

describe("Second Brain outcome evidence", () => {
  test("supports success and failed on the same reusable node", () => {
    expect(canonicalMemoryOutcomeTags(["failed", "success", "failed"])).toEqual([
      "success",
      "failed",
    ]);
    expect(memoryMatchesOutcomeFilter(["success", "failed"], "success")).toBe(true);
    expect(memoryMatchesOutcomeFilter(["success", "failed"], "failed")).toBe(true);
    expect(memoryMatchesOutcomeFilter(["success", "failed"], "unclassified")).toBe(false);
  });

  test("does not infer a terminal outcome for supporting knowledge", () => {
    expect(memoryMatchesOutcomeFilter(undefined, "unclassified")).toBe(true);
    expect(memoryMatchesOutcomeFilter([], "success")).toBe(false);
    const markup = renderToStaticMarkup(<MemoryOutcomeTags />);
    expect(markup).toContain('class="brain-outcome-tags" role="group"');
    expect(markup).toContain("Verified outcome evidence: Supporting or unclassified");
    expect(markup).toContain("Supporting / unclassified");
    expect(markup).not.toContain("Success");
    expect(markup).not.toContain("Failed");
  });

  test("renders both evidence-backed badges with non-color text cues", () => {
    const markup = renderToStaticMarkup(<MemoryOutcomeTags tags={["success", "failed"]} />);
    expect(markup).toContain('class="brain-outcome-tags" role="group"');
    expect(markup).toContain("Verified outcome evidence: Success and Failed");
    expect(markup).toContain("brain-outcome-badge--success");
    expect(markup).toContain("brain-outcome-badge--failed");
    expect(markup).toContain("Success");
    expect(markup).toContain("Failed");
  });

  test("renders reported outcomes with explicit unverified source semantics", () => {
    const outcome = {
      classification: "reported_failure" as const,
      classificationConfidence: 0.82,
      claimCount: 5,
      sourceCount: 2,
      policyVersion: "historical-reported-outcome/v1",
    };
    expect(historicalReportedOutcomeLabel(outcome.classification)).toBe("Reported failure");
    expect(memoryMatchesHistoricalReportedOutcome(outcome, "reported_failure")).toBe(true);
    expect(memoryMatchesHistoricalReportedOutcome(outcome, "reported_success")).toBe(false);
    expect(memoryMatchesHistoricalReportedOutcome(undefined, "not_reported")).toBe(true);
    const markup = renderToStaticMarkup(<HistoricalReportedOutcomeBadge outcome={outcome} />);
    expect(markup).toContain('brain-reported-outcome-badge--reported_failure" role="note"');
    expect(markup).toContain("Reported failure");
    expect(markup).toContain("5 historical claims from 2 sources");
    expect(markup).toContain("not a verified attack outcome");
    expect(markup).toContain("brain-reported-outcome-badge--reported_failure");
  });
});

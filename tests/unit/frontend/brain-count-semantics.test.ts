import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const overview = readFileSync(new URL("../../../src/features/overview/OverviewPage.tsx", import.meta.url), "utf8");
const brainHome = readFileSync(new URL("../../../src/features/brain/BrainHomePage.tsx", import.meta.url), "utf8");

describe("Second Brain count language", () => {
  test("labels graph lifecycle candidates separately from reviewable Inbox proposals", () => {
    for (const source of [overview, brainHome]) {
      expect(source).toContain("Candidate nodes");
      expect(source).toContain("Inbox reviews");
    }
    expect(overview).not.toContain("candidates to review");
    expect(overview).not.toContain("data.brain.candidates");
    expect(brainHome).not.toContain("summary.data.counts.candidates");
  });
});

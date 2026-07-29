import { describe, expect, test } from "bun:test";
import {
  projectRunNextAction,
  runNextActionOverride,
} from "../RunNextAction";

describe("run next-action projection", () => {
  test.each(["completed", "failed", "cancelled"] as const)(
    "clears stale work after a %s outcome",
    (state) => {
      expect(runNextActionOverride(state, "autonomous")).toBeNull();
      expect(projectRunNextAction({
        state,
        journey: "autonomous",
        persisted: "Validate mission success criteria",
      })).toBeNull();
    },
  );

  test("replaces stale Autonomous work with a safe-stop recovery direction", () => {
    expect(projectRunNextAction({
      state: "blocked",
      journey: "autonomous",
      persisted: "Validate mission success criteria",
    })).toBe("Review the safe-stop diagnosis, then amend the contract or start a new run.");
  });

  test("uses a represented recovery direction for blocked Guided work", () => {
    expect(projectRunNextAction({
      state: "blocked",
      journey: "guided",
      persisted: "Run the previous command again",
    })).toBe("Review the blocker, then choose an available represented recovery action.");
  });

  test("preserves a current nonterminal action and normalizes empty values", () => {
    expect(projectRunNextAction({
      state: "running",
      journey: "autonomous",
      persisted: "  Await the exact specialist result  ",
    })).toBe("Await the exact specialist result");
    expect(projectRunNextAction({
      state: "planning",
      journey: "autonomous",
      persisted: "   ",
    })).toBeNull();
  });
});

import { describe, expect, test } from "bun:test";
import { evaluateDestructiveAuthorization } from "../../../server/domain";

describe("destructive action policy", () => {
  test("allows non-destructive work under every policy", () => {
    expect(evaluateDestructiveAuthorization({ destructive: false, policy: "prohibited", target: "lab-01", boundedTargets: [] })).toEqual({ allowed: true, reason: "non_destructive" });
  });

  test("denies prohibited, validate-only, missing, and legacy vague policies", () => {
    for (const policy of ["prohibited", "validate_without_executing", "contract_only", undefined]) {
      expect(evaluateDestructiveAuthorization({ destructive: true, policy, target: "lab-01", boundedTargets: ["lab-01"] }).allowed).toBe(false);
    }
  });

  test("allows only an exact named target under bounded lab policy", () => {
    expect(evaluateDestructiveAuthorization({ destructive: true, policy: "bounded_lab_only", target: "lab-01", boundedTargets: ["lab-01"] })).toEqual({ allowed: true, reason: "bounded_lab_target" });
    expect(evaluateDestructiveAuthorization({ destructive: true, policy: "bounded_lab_only", target: "lab-02", boundedTargets: ["lab-01"] })).toEqual({ allowed: false, reason: "target_not_bounded" });
  });
});

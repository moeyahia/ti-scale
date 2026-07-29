import { describe, expect, test } from "bun:test";
import {
  allAuthorizedIpCandidateLinuxTargetScope,
  candidateLinuxTargetScopeMatches,
  candidateLinuxTargetScopesCover,
  exactCandidateLinuxTargetScope,
  parseCandidateLinuxTargetScope,
} from "../CandidateLinuxTargetScope";

describe("CandidateLinuxTargetScope", () => {
  test("keeps an exact reviewed endpoint conditional and matches only its IP", () => {
    const scope = exactCandidateLinuxTargetScope(
      "127.0.0.2",
      { transport: "tcp", port: 8080 },
    );

    expect(scope.generalMissionReadinessEligible).toBe(false);
    expect(candidateLinuxTargetScopeMatches(scope, "127.0.0.2")).toBe(true);
    expect(candidateLinuxTargetScopeMatches(scope, "127.0.0.3")).toBe(false);
    expect(candidateLinuxTargetScopeMatches(scope, "10.129.39.191")).toBe(false);
    expect(candidateLinuxTargetScopesCover([scope], ["127.0.0.2"])).toBe(true);
    expect(candidateLinuxTargetScopesCover([scope], ["127.0.0.2", "127.0.0.3"]))
      .toBe(false);
  });

  test("allows global readiness only through the explicit all-authorized-IP scope", () => {
    const scope = allAuthorizedIpCandidateLinuxTargetScope();

    expect(scope.generalMissionReadinessEligible).toBe(true);
    expect(candidateLinuxTargetScopesCover(
      [scope],
      ["127.0.0.2", "10.129.39.191"],
    )).toBe(true);
  });

  test("rejects an exact-target scope that claims global mission readiness", () => {
    expect(() => parseCandidateLinuxTargetScope({
      schemaVersion: "ti-scale.candidate-linux-target-scope.v1",
      kind: "exact_target",
      exactTarget: "127.0.0.2",
      endpoint: { transport: "tcp", port: 8080 },
      generalMissionReadinessEligible: true,
    })).toThrow("cannot advertise general mission readiness");
  });
});

import { describe, expect, test } from "bun:test";
import { LoopDetector, detectDelegationCycle, type ActionObservation } from "../LoopDetector";
import { evaluateProgress, progressSignature, type ProgressSnapshot } from "../ProgressEvaluator";

describe("meaningful progress evaluation", () => {
  test("tool output by itself is not progress", () => {
    const before = {} as ProgressSnapshot & { rawToolOutput?: string };
    const after = { rawToolOutput: "thousands of output lines" } as ProgressSnapshot & { rawToolOutput?: string };
    expect(evaluateProgress(before, after)).toMatchObject({
      meaningful: false,
      dimensions: [],
      summary: "No meaningful progress detected",
    });
  });

  test("recognizes every canonical progress dimension", () => {
    const before: ProgressSnapshot = {
      stepStates: { step1: "pending" },
      evidenceIds: ["ev1"],
      findingProgress: { finding1: { confidence: 0.3, evidenceCount: 1 } },
      discoveredEntityIds: [],
      resolvedDependencyIds: [],
      resolvedDecisionIds: [],
      contractMilestoneIds: [],
      artifactIds: [],
      verifiedWorkerResultIds: [],
      uncertainty: 0.8,
      planVersion: 1,
      strategyFingerprint: "old",
      successCriteria: { access: 0.1 },
    };
    const after: ProgressSnapshot = {
      stepStates: { step1: "running" },
      evidenceIds: ["ev1", "ev2"],
      findingProgress: { finding1: { confidence: 0.8, evidenceCount: 2 } },
      discoveredEntityIds: ["service:ssh"],
      resolvedDependencyIds: ["vpn"],
      resolvedDecisionIds: ["decision1"],
      contractMilestoneIds: ["planned"],
      artifactIds: ["report1"],
      verifiedWorkerResultIds: ["worker1"],
      uncertainty: 0.2,
      planVersion: 2,
      strategyFingerprint: "new",
      planChangeReason: "New service changed the attack surface",
      successCriteria: { access: 0.6 },
    };
    const result = evaluateProgress(before, after);
    expect(result.meaningful).toBe(true);
    expect(result.dimensions).toHaveLength(12);
  });

  test("a version bump is not meaningful replanning without new strategy and reason", () => {
    const before = { planVersion: 1, strategyFingerprint: "same" };
    expect(evaluateProgress(before, { planVersion: 2, strategyFingerprint: "same" }).meaningful).toBe(false);
    expect(evaluateProgress(before, { planVersion: 2, strategyFingerprint: "new" }).meaningful).toBe(false);
    expect(
      evaluateProgress(before, {
        planVersion: 2,
        strategyFingerprint: "new",
        planChangeReason: "New evidence",
      }).dimensions,
    ).toContain("plan_materially_changed");
  });

  test("signatures are stable across set ordering but change for material state", () => {
    const a = progressSignature({ evidenceIds: ["b", "a", "a"] });
    const b = progressSignature({ evidenceIds: ["a", "b"] });
    expect(a).toBe(b);
    expect(progressSignature({ evidenceIds: ["a", "c"] })).not.toBe(a);
  });
});

function observation(
  id: string,
  fingerprint: string,
  overrides: Partial<ActionObservation> = {},
): ActionObservation {
  return {
    actionId: id,
    actionFingerprint: fingerprint,
    meaningfulProgress: false,
    progressSignatureAfter: "unchanged",
    completedAt: `2026-01-01T00:00:${id.padStart(2, "0")}Z`,
    actionKind: "tool",
    ...overrides,
  };
}

describe("loop and stagnation detection", () => {
  test("detects the third identical action, not the second", () => {
    const detector = new LoopDetector();
    expect(detector.inspect([observation("1", "A"), observation("2", "A")])).toEqual([]);
    const findings = detector.inspect([
      observation("1", "A"),
      observation("2", "A"),
      observation("3", "A"),
    ]);
    expect(findings.map((finding) => finding.kind)).toContain("identical_action");
    expect(findings.map((finding) => finding.kind)).toContain("stagnation");
  });

  test("detects an A/B alternating cycle within configured bounds", () => {
    const findings = new LoopDetector().inspect([
      observation("1", "A"),
      observation("2", "B"),
      observation("3", "A"),
      observation("4", "B"),
    ]);
    expect(findings.map((finding) => finding.kind)).toContain("alternating_cycle");
  });

  test("meaningful progress resets the no-progress window", () => {
    const history = [
      observation("1", "A"),
      observation("2", "A"),
      observation("3", "progress", { meaningfulProgress: true, progressSignatureAfter: "new" }),
      observation("4", "A"),
      observation("5", "A"),
    ];
    expect(new LoopDetector().inspect(history)).toEqual([]);
  });

  test("detects repeated error categories and equivalent replans", () => {
    const errorFindings = new LoopDetector().inspect([
      observation("1", "A", { errorCategory: "timeout" }),
      observation("2", "B", { errorCategory: "timeout" }),
      observation("3", "C", { errorCategory: "timeout" }),
    ]);
    expect(errorFindings.map((finding) => finding.kind)).toContain("repeated_error");
    const replanFindings = new LoopDetector().inspect([
      observation("1", "R1", { actionKind: "replan", planFingerprint: "plan-A" }),
      observation("2", "R2", { actionKind: "replan", planFingerprint: "plan-A" }),
    ]);
    expect(replanFindings.map((finding) => finding.kind)).toContain("equivalent_replan");
  });

  test("history is bounded and explicit routing violations are surfaced", () => {
    const detector = new LoopDetector({ maxHistory: 3 });
    expect(detector.boundHistory([1, 2, 3, 4, 5].map((n) => observation(String(n), String(n))))).toHaveLength(3);
    expect(
      detector.inspect([observation("1", "command", { routingViolation: true })])[0]?.kind,
    ).toBe("routing_violation");
  });

  test("delegation cycles return the smallest repeated path", () => {
    expect(detectDelegationCycle(["commander", "recon", "web", "recon"])).toEqual([
      "recon",
      "web",
      "recon",
    ]);
    expect(detectDelegationCycle(["commander", "recon", "web"])).toBeNull();
  });
});

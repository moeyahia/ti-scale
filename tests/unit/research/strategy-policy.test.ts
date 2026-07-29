import { describe, expect, test } from "bun:test";

import {
  DEFAULT_STRATEGY_BUNDLE,
  FORBIDDEN_STRATEGY_PATH_PREFIXES,
  MUTABLE_STRATEGY_PATHS,
  applyStrategyPatch,
  validateStrategyBundle,
  validateStrategyPatch,
} from "../../../server/research";

describe("typed StrategyBundle policy", () => {
  const loopPolicy = {
    approvedMutablePaths: [
      "/loopControl/maxIdenticalFingerprints",
      "/loopControl/noProgressActionLimit",
    ] as const,
    maxOperations: 2,
  };

  test("applies a typed bounded replacement without changing safety invariants", () => {
    const result = applyStrategyPatch(
      DEFAULT_STRATEGY_BUNDLE,
      [{ op: "replace", path: "/loopControl/maxIdenticalFingerprints", value: 2 }],
      loopPolicy,
    );
    expect(result.bundle.loopControl.maxIdenticalFingerprints).toBe(2);
    expect(result.bundle.safety).toEqual(DEFAULT_STRATEGY_BUNDLE.safety);
    expect(result.bundleHash).toHaveLength(64);
    expect(result.patchHash).toHaveLength(64);
    expect(Object.isFrozen(result.bundle)).toBe(true);
  });

  test("rejects every immutable safety/evaluator/deployment prefix", () => {
    for (const path of FORBIDDEN_STRATEGY_PATH_PREFIXES) {
      const result = validateStrategyPatch(
        [{ op: "replace", path: `${path}/attemptedMutation`, value: true }],
        { approvedMutablePaths: MUTABLE_STRATEGY_PATHS, maxOperations: 2 },
      );
      expect(result.valid, path).toBe(false);
      expect(result.violations[0]?.code, path).toBe("forbidden_path");
    }
  });

  test("rejects offensive scope expansion and prototype paths", () => {
    for (const path of [
      "/exploitPayloads/newCapability",
      "/authorization/allowedTargets",
      "/toolAllowlists/exploit",
      "/__proto__/polluted",
      "/loopControl/constructor/prototype",
    ]) {
      const result = validateStrategyPatch(
        [{ op: "replace", path, value: true }],
        { approvedMutablePaths: MUTABLE_STRATEGY_PATHS, maxOperations: 2 },
      );
      expect(result.valid, path).toBe(false);
    }
  });

  test("rejects add, remove, move, copy, unknown, and out-of-dimension operations", () => {
    for (const op of ["add", "remove", "move", "copy"] as const) {
      const result = validateStrategyPatch(
        [{ op, path: "/loopControl/maxIdenticalFingerprints", value: 2 }],
        loopPolicy,
      );
      expect(result.violations[0]?.code).toBe("invalid_operation");
    }
    expect(
      validateStrategyPatch(
        [{ op: "replace", path: "/notARealDimension", value: 2 }],
        loopPolicy,
      ).violations[0]?.code,
    ).toBe("invalid_path");
    expect(
      validateStrategyPatch(
        [{ op: "replace", path: "/memoryRetrieval/maxContextItems", value: 8 }],
        loopPolicy,
      ).violations[0]?.code,
    ).toBe("dimension_not_approved");
  });

  test("enforces operation count, scalar type, and numeric bounds", () => {
    expect(validateStrategyPatch([], loopPolicy).valid).toBe(false);
    expect(
      validateStrategyPatch(
        [
          { op: "replace", path: "/loopControl/maxIdenticalFingerprints", value: 2 },
          { op: "replace", path: "/loopControl/noProgressActionLimit", value: 2 },
          { op: "test", path: "/loopControl/noProgressActionLimit", value: 2 },
        ],
        loopPolicy,
      ).valid,
    ).toBe(false);
    for (const value of [0, 6, 2.5, "2", null]) {
      const result = validateStrategyPatch(
        [{ op: "replace", path: "/loopControl/maxIdenticalFingerprints", value }],
        loopPolicy,
      );
      expect(result.violations[0]?.code).toBe("invalid_value");
    }
  });

  test("requires JSON Patch tests to match the baseline", () => {
    expect(() =>
      applyStrategyPatch(
        DEFAULT_STRATEGY_BUNDLE,
        [
          { op: "test", path: "/loopControl/maxIdenticalFingerprints", value: 2 },
          { op: "replace", path: "/loopControl/maxIdenticalFingerprints", value: 2 },
        ],
        loopPolicy,
      ),
    ).toThrow("test failed");
  });

  test("rejects duplicate replacements and encoded attempts to escape the typed path surface", () => {
    expect(validateStrategyPatch([
      { op: "replace", path: "/loopControl/maxIdenticalFingerprints", value: 2 },
      { op: "replace", path: "/loopControl/maxIdenticalFingerprints", value: 1 },
    ], loopPolicy).violations.some(({ message }) => message.includes("only once"))).toBe(true);
    for (const path of [
      "/safety~1engagementIsolation",
      "/%73afety/engagementIsolation",
      "/loopControl~1maxIdenticalFingerprints",
    ]) {
      expect(validateStrategyPatch(
        [{ op: "replace", path, value: false }],
        { approvedMutablePaths: MUTABLE_STRATEGY_PATHS, maxOperations: 2 },
      ).valid).toBe(false);
    }
  });

  test("detects direct mutation of immutable safety invariants", () => {
    const mutated = structuredClone(DEFAULT_STRATEGY_BUNDLE);
    (mutated.safety as { commanderDirectExecutionAllowed: boolean }).commanderDirectExecutionAllowed = true;
    expect(validateStrategyBundle(mutated).join(" ")).toContain("safety invariants");
  });
});

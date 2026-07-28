import {
  afterEach,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";
import {
  existsSync,
  unlinkSync,
} from "node:fs";
import type {
  FullConfig,
  FullResult,
  Suite,
  TestCase,
  TestResult,
} from "@playwright/test/reporter";
import ReleaseResultPolicyReporter from "../../e2e/support/releaseResultPolicyReporter";
import InteractionActivationReporter from "../../e2e/support/interactionActivationReporter";

const originalPolicy = process.env.TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY;
const originalDiscovery = process.env.TI_SCALE_E2E_DISCOVERY_ONLY;
const discoveryArtifact = `/tmp/ti-scale-activation-discovery-${String(process.pid)}.json`;

afterEach(() => {
  if (originalPolicy === undefined) {
    delete process.env.TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY;
  } else {
    process.env.TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY = originalPolicy;
  }
  if (originalDiscovery === undefined) {
    delete process.env.TI_SCALE_E2E_DISCOVERY_ONLY;
  } else {
    process.env.TI_SCALE_E2E_DISCOVERY_ONLY = originalDiscovery;
  }
  if (existsSync(discoveryArtifact)) unlinkSync(discoveryArtifact);
});

function fixture(
  expectedStatus: TestCase["expectedStatus"] = "passed",
  retries = 0,
): TestCase {
  return {
    id: "fixture",
    expectedStatus,
    retries,
    parent: {
      project: () => ({ name: "chromium-1440" }),
    },
    titlePath: () => ["fixture.spec.ts", "release contract"],
  } as unknown as TestCase;
}

function result(
  status: TestResult["status"] = "passed",
  annotations: TestResult["annotations"] = [],
): TestResult {
  return {
    status,
    retry: 0,
    annotations,
  } as TestResult;
}

function fullResult(status: FullResult["status"] = "passed"): FullResult {
  return { status } as FullResult;
}

describe("release browser result policy reporter", () => {
  test("accepts one retry-free pass for every discovered test", async () => {
    process.env.TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY = "1";
    const reporter = new ReleaseResultPolicyReporter();
    const candidate = fixture();
    reporter.onBegin?.({} as FullConfig, {
      allTests: () => [candidate],
    } as unknown as Suite);
    reporter.onTestEnd?.(candidate, result());
    expect(await reporter.onEnd?.(fullResult())).toBeUndefined();
  });

  test("turns skipped, fixme, expected-failure, retry, and missing results into failure", async () => {
    process.env.TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY = "1";
    const stderr = spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      const expectedFailure = fixture("failed", 1);
      const skipped = fixture();
      const missing = { ...fixture(), id: "missing" } as TestCase;
      const reporter = new ReleaseResultPolicyReporter();
      reporter.onBegin?.({} as FullConfig, {
        allTests: () => [expectedFailure, skipped, missing],
      } as unknown as Suite);
      reporter.onTestEnd?.(expectedFailure, result("passed", [{ type: "fail" }]));
      reporter.onTestEnd?.(skipped, {
        ...result("skipped", [{ type: "skip" }]),
        retry: 1,
      } as TestResult);
      expect(await reporter.onEnd?.(fullResult())).toEqual({ status: "failed" });
      expect(stderr).toHaveBeenCalled();
    } finally {
      stderr.mockRestore();
    }
  });

  test("allows side-effect-free discovery without weakening the workflow contract", async () => {
    process.env.TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY = "1";
    process.env.TI_SCALE_E2E_DISCOVERY_ONLY = "1";
    try {
      const reporter = new ReleaseResultPolicyReporter();
      reporter.onBegin?.({} as FullConfig, {
        allTests: () => [fixture()],
      } as unknown as Suite);
      expect(await reporter.onEnd?.(fullResult())).toBeUndefined();
    } finally {
      delete process.env.TI_SCALE_E2E_DISCOVERY_ONLY;
    }
  });

  test("does not write an activation artifact during side-effect-free discovery", async () => {
    process.env.TI_SCALE_E2E_DISCOVERY_ONLY = "1";
    const reporter = new InteractionActivationReporter({
      outputFile: discoveryArtifact,
      requiredProjects: ["chromium-1440"],
      enforce: true,
    });
    expect(await reporter.onEnd?.(fullResult())).toBeUndefined();
    expect(existsSync(discoveryArtifact)).toBe(false);
  });
});

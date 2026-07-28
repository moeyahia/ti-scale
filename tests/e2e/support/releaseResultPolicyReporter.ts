import type {
  FullConfig,
  FullResult,
  Reporter,
  Suite,
  TestCase,
  TestResult,
} from "@playwright/test/reporter";

interface ObservedResult {
  readonly status: TestResult["status"];
  readonly retry: number;
  readonly annotations: readonly string[];
}

export default class ReleaseResultPolicyReporter implements Reporter {
  private tests: readonly TestCase[] = [];
  private readonly observed = new Map<string, ObservedResult[]>();

  onBegin(_config: FullConfig, suite: Suite): void {
    this.tests = Object.freeze([...suite.allTests()]);
  }

  onTestEnd(test: TestCase, result: TestResult): void {
    const previous = this.observed.get(test.id) ?? [];
    previous.push(Object.freeze({
      status: result.status,
      retry: result.retry,
      annotations: Object.freeze(result.annotations.map((annotation) => annotation.type)),
    }));
    this.observed.set(test.id, previous);
  }

  async onEnd(
    result: FullResult,
  ): Promise<{ status?: FullResult["status"] } | undefined> {
    if (process.env.TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY !== "1") return undefined;
    // Playwright's side-effect-free discovery command calls reporters without
    // executing tests. The reviewed workflow rejects --list, so this exception
    // cannot turn a release execution into a passing discovery-only run.
    if (process.env.TI_SCALE_E2E_DISCOVERY_ONLY === "1") return undefined;
    const violations: string[] = [];
    if (result.status !== "passed") {
      violations.push(`full run status was ${result.status}`);
    }

    for (const test of this.tests) {
      const label = `${test.parent.project()?.name ?? "unknown-project"} :: ${test.titlePath().join(" > ")}`;
      if (test.expectedStatus !== "passed") {
        violations.push(`${label} expected ${test.expectedStatus} instead of passed`);
      }
      if (test.retries !== 0) {
        violations.push(`${label} configured ${String(test.retries)} retries`);
      }
      const results = this.observed.get(test.id) ?? [];
      if (results.length !== 1) {
        violations.push(`${label} executed ${String(results.length)} times`);
        continue;
      }
      const [observed] = results;
      if (!observed) continue;
      if (observed.retry !== 0) {
        violations.push(`${label} ran at retry index ${String(observed.retry)}`);
      }
      if (observed.status !== "passed") {
        violations.push(`${label} ended as ${observed.status}`);
      }
      for (const annotation of observed.annotations) {
        if (annotation === "skip" || annotation === "fixme" || annotation === "fail") {
          violations.push(`${label} carried forbidden ${annotation} annotation`);
        }
      }
    }

    if (violations.length === 0) return undefined;
    process.stderr.write(
      `Release result policy failed:\n- ${violations.join("\n- ")}\n`,
    );
    return { status: "failed" };
  }
}

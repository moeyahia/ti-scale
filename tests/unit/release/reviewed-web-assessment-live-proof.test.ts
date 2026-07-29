import { describe, expect, test } from "bun:test";
import {
  REVIEWED_WEB_LIVE_PROOF_CONFIRMATION,
  REVIEWED_WEB_TOOL_IDS,
  assertExactWebDecision,
  assertReviewedWebReadiness,
  assertReviewedWebLiveness,
  parseReviewedWebLiveProofArguments,
  reviewedWebLiveProofUsage,
} from "../../../scripts/smoke-reviewed-web-assessment";

const NOW = new Date("2026-07-20T10:00:00.000Z");
const CHECKED_AT = "2026-07-20T09:59:30.000Z";
const EXPIRES_AT = "2026-07-20T10:01:00.000Z";
const DEPENDENCIES = [
  "operator-activation",
  "executable-integrity",
  "isolated-target-free-readiness",
  "direct-argv-adapter",
  "workspace-confinement",
  "result-sink",
  "cancellation",
] as const;

function health(readyToolIds: readonly string[] = REVIEWED_WEB_TOOL_IDS) {
  return {
    status: "healthy",
    dependencies: {
      guidedLocalToolExecution: {
        status: "ready",
        executionBinding: "reviewed_local_process",
        readyToolIds,
        exactDecisionRequired: true,
        targetInteraction: "operator_approved_exact_step",
        providerContact: false,
        mcpTransport: false,
        checkedAt: CHECKED_AT,
        expiresAt: EXPIRES_AT,
      },
    },
  };
}

function selfTests() {
  return {
    results: REVIEWED_WEB_TOOL_IDS.flatMap((toolId) => [toolId, ...DEPENDENCIES.map((suffix) => `${toolId}/${suffix}`)])
      .map((componentId, index) => ({
        id: `self-test-${index}`,
        component: { id: componentId },
        status: "pass",
        availability: "available",
        freshness: { state: "fresh", observedAt: CHECKED_AT, expiresAt: EXPIRES_AT },
        executionAuthorization: { state: "not_granted", grantsMissionExecution: false },
      })),
  };
}

function intake() {
  return {
    actionClasses: {
      classes: {
        os_technology_fingerprinting: {
          capability: {
            availability: "supported",
            availableToolIds: [REVIEWED_WEB_TOOL_IDS[0]],
          },
        },
        web_content_endpoint_discovery_fuzzing: {
          capability: {
            availability: "supported",
            availableToolIds: [REVIEWED_WEB_TOOL_IDS[1]],
          },
        },
      },
    },
  };
}

function decision(toolId: typeof REVIEWED_WEB_TOOL_IDS[number], target = "http://127.0.0.1:43210/") {
  return {
    id: `decision-${toolId}`,
    stepId: `step-${toolId}`,
    status: "pending",
    actionFingerprint: `fingerprint-${toolId}`,
    requestedParameters: {
      kind: "tool",
      actionType: toolId,
      target,
      arguments: {
        executionBinding: "reviewed_local_process",
        toolId,
        parameters: { workspace: "/engagements", url: target },
      },
    },
  };
}

describe("reviewed web authenticated live-proof contract", () => {
  test("requires fast process liveness separately from rich tool readiness", () => {
    expect(() => assertReviewedWebLiveness({
      schemaVersion: "2.4",
      status: "healthy",
      service: "ti-scale",
      database: { healthy: true },
      eventStream: { status: "healthy" },
    })).not.toThrow();
    expect(() => assertReviewedWebLiveness({
      schemaVersion: "2.4",
      status: "degraded",
      database: { healthy: true },
      eventStream: { status: "healthy" },
    })).toThrow("liveness is not fully healthy");
  });

  test("requires the exact explicit destructive-proof confirmation", () => {
    expect(() => parseReviewedWebLiveProofArguments([
      "--execute",
      "--confirm",
      REVIEWED_WEB_LIVE_PROOF_CONFIRMATION,
    ])).not.toThrow();
    expect(() => parseReviewedWebLiveProofArguments([])).toThrow(reviewedWebLiveProofUsage());
    expect(() => parseReviewedWebLiveProofArguments([
      "--execute",
      "--confirm",
      "wrong",
    ])).toThrow(reviewedWebLiveProofUsage());
  });

  test("accepts only fresh live receipts, complete dependency checks, and intake advertisement", () => {
    expect(assertReviewedWebReadiness(health(), selfTests(), intake(), NOW)).toEqual({
      checkedAt: CHECKED_AT,
      expiresAt: EXPIRES_AT,
      readyToolIds: REVIEWED_WEB_TOOL_IDS,
      selfTestIds: expect.any(Array),
      intakeActionClassIds: [
        "os_technology_fingerprinting",
        "web_content_endpoint_discovery_fuzzing",
      ],
    });
    expect(assertReviewedWebReadiness(health(), selfTests(), intake(), NOW).selfTestIds).toHaveLength(16);

    expect(() => assertReviewedWebReadiness(
      health([REVIEWED_WEB_TOOL_IDS[0]]), selfTests(), intake(), NOW,
    )).toThrow("not live");

    const failedDependency = structuredClone(selfTests());
    failedDependency.results.find(({ component }) => component.id.endsWith("/cancellation"))!.status = "fail";
    expect(() => assertReviewedWebReadiness(health(), failedDependency, intake(), NOW))
      .toThrow("did not pass");

    const missingIntake = structuredClone(intake());
    missingIntake.actionClasses.classes.web_content_endpoint_discovery_fuzzing.capability.availableToolIds = [];
    expect(() => assertReviewedWebReadiness(health(), selfTests(), missingIntake, NOW))
      .toThrow("does not advertise");

    expect(() => assertReviewedWebReadiness(health(), selfTests(), intake(), new Date(EXPIRES_AT)))
      .toThrow("expired");
  });

  test("accepts only a pending exact local-process decision for the canonical URL", () => {
    const target = "http://127.0.0.1:43210/";
    for (const toolId of REVIEWED_WEB_TOOL_IDS) {
      expect(assertExactWebDecision(decision(toolId, target), toolId, target)).toMatchObject({
        decisionId: `decision-${toolId}`,
        stepId: `step-${toolId}`,
        fingerprint: `fingerprint-${toolId}`,
      });
    }
    const changedTarget = structuredClone(decision(REVIEWED_WEB_TOOL_IDS[0], target));
    changedTarget.requestedParameters.arguments.parameters.url = "http://127.0.0.1:43211/";
    expect(() => assertExactWebDecision(changedTarget, REVIEWED_WEB_TOOL_IDS[0], target))
      .toThrow("canonical URL");

    const providerRoute = structuredClone(decision(REVIEWED_WEB_TOOL_IDS[1], target));
    providerRoute.requestedParameters.arguments.executionBinding = "provider_tool_call";
    expect(() => assertExactWebDecision(providerRoute, REVIEWED_WEB_TOOL_IDS[1], target))
      .toThrow("exact reviewed");
  });
});

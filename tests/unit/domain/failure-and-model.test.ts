import { describe, expect, test } from "bun:test";

import {
  FAILURE_CATEGORY_DEFINITIONS,
  buildFailureTaxonomy,
  classifyFailure,
  evaluateModelReadiness,
  type ProviderModelCapability,
} from "../../../server/domain";

describe("failure taxonomy", () => {
  test("allows automatic retries only for explicitly transient categories", () => {
    for (const definition of FAILURE_CATEGORY_DEFINITIONS) {
      if (definition.retryPolicy === "bounded_transient") {
        expect(definition.transient).toBe(true);
      } else {
        expect(definition.transient).toBe(false);
      }
    }

    expect(
      FAILURE_CATEGORY_DEFINITIONS.find(({ id }) => id === "provider_rate_limited")
        ?.retryPolicy,
    ).toBe("bounded_transient");
    expect(
      FAILURE_CATEGORY_DEFINITIONS.find(({ id }) => id === "scope_policy_denial")
        ?.retryPolicy,
    ).toBe("never_automatic");
    expect(
      FAILURE_CATEGORY_DEFINITIONS.find(({ id }) => id === "tool_deterministic_error")
        ?.retryPolicy,
    ).toBe("never_automatic");
  });

  test("classifies exact runtime codes without guessing from raw error text", () => {
    const taxonomy = buildFailureTaxonomy([
      {
        component: "provider-gateway",
        code: "RATE_LIMITED",
        categoryId: "provider_rate_limited",
      },
      {
        component: "policy",
        code: "OUTSIDE_SCOPE",
        categoryId: "scope_policy_denial",
      },
    ]);
    const rateLimit = classifyFailure(taxonomy, {
      id: "diagnosis-1",
      component: "provider-gateway",
      code: "RATE_LIMITED",
      failedObjectType: "action",
      failedObjectId: "action-1",
      progressBeforeFailure: "The plan and assignment were persisted.",
    });
    expect(rateLimit.categoryId).toBe("provider_rate_limited");
    expect(rateLimit.retryable).toBe(true);
    expect(rateLimit.recommendedRecoveryActions).toContain("retry_bounded");

    const unknown = classifyFailure(taxonomy, {
      id: "diagnosis-2",
      component: "other-component",
      code: "text happened to contain rate limit",
      failedObjectType: "run",
      failedObjectId: "run-1",
    });
    expect(unknown.categoryId).toBe("unknown");
    expect(unknown.retryable).toBe(false);
  });

  test("rejects ambiguous duplicate runtime-code mappings", () => {
    expect(() =>
      buildFailureTaxonomy([
        { component: "worker", code: "LOST", categoryId: "worker_heartbeat_lost" },
        { component: "worker", code: "LOST", categoryId: "process_crash" },
      ]),
    ).toThrow("Duplicate failure-code mapping");
  });
});

describe("model enforcement readiness", () => {
  const base: ProviderModelCapability = {
    providerId: "provider-1",
    modelId: "model-1",
    displayName: "Model 1",
    providerAuthenticated: true,
    providerHealthy: true,
    catalogObservedAt: "2026-07-16T00:00:00.000Z",
    toolCalling: true,
    structuredOutput: true,
    declaredEnforcement: "enforced_executor",
    compatibleActionClassIds: ["port_service_enumeration", "local_report_artifact_generation"],
    disclosureClasses: ["internal_sanitized"],
  };

  test("accepts a compatible enforced executor for Autonomous", () => {
    const readiness = evaluateModelReadiness(base, {
      journey: "autonomous",
      requiredActionClassIds: ["port_service_enumeration"],
      requiredDisclosureClass: "internal_sanitized",
    });
    expect(readiness.state).toBe("enforced_executor");
    expect(readiness.ready).toBe(true);
    expect(readiness.reasons).toEqual([]);
  });

  test("does not represent observe-only as an Autonomous executor", () => {
    const readiness = evaluateModelReadiness(
      { ...base, declaredEnforcement: "observe_only_executor" },
      {
        journey: "autonomous",
        requiredActionClassIds: ["port_service_enumeration"],
      },
    );
    expect(readiness.state).toBe("observe_only_executor");
    expect(readiness.ready).toBe(false);
    expect(readiness.reasons).toContain("Autonomous execution requires an enforced executor.");
  });

  test("reports unavailable, incompatible, and disclosure-denied configurations", () => {
    const unavailable = evaluateModelReadiness(
      { ...base, providerAuthenticated: false },
      {
        journey: "guided",
        requiredActionClassIds: ["exploit_validation"],
        requiredDisclosureClass: "confidential",
      },
    );
    expect(unavailable.state).toBe("unavailable");
    expect(unavailable.ready).toBe(false);
    expect(unavailable.incompatibleActionClassIds).toEqual(["exploit_validation"]);
    expect(unavailable.reasons.join(" ")).toContain("authentication");
    expect(unavailable.reasons.join(" ")).toContain("not approved for confidential");
  });
});

import { describe, expect, test } from "bun:test";
import { CommandRuntimeError, type MissionPlanDraft } from "../types";
import { validateMissionPlanDraft } from "../validation";

type DeepMutable<T> = T extends readonly (infer Item)[]
  ? DeepMutable<Item>[]
  : T extends object
    ? { -readonly [Key in keyof T]: DeepMutable<T[Key]> }
    : T;

function draft(): DeepMutable<MissionPlanDraft> {
  return {
    strategySummary: "Use one bounded specialist action",
    rationaleSummary: "The action is sufficient for the authorized objective",
    steps: [{
      phase: "reconnaissance",
      title: "Inspect the approved target",
      objective: "Collect one verified result",
      explanation: "The specialist will perform one read-only observation.",
      rationale: "This is the smallest action that advances the objective.",
      successCriteria: ["One result is retained"],
      dependencyOrdinals: [],
      assignedAgentId: "ReconScout",
      riskClass: "low",
      reversibility: "Read-only",
      action: {
        actionType: "reconnaissance",
        actionClass: "reconnaissance",
        target: "lab.internal",
        arguments: {},
        intentSummary: "Inspect the approved target",
        kind: "tool",
        idempotent: true,
        destructive: false,
      },
    }],
  };
}

function expectRepairableDiagnostic(
  value: MissionPlanDraft,
  expected: {
    readonly code?: "invalid_plan" | "invalid_plan_dependency" | "invalid_plan_step_count";
    readonly field: string;
    readonly rule: string;
  },
  maximumSteps = 32,
): void {
  let rejection: unknown;
  try {
    validateMissionPlanDraft(value, maximumSteps);
  } catch (error) {
    rejection = error;
  }
  expect(rejection).toBeInstanceOf(CommandRuntimeError);
  expect(rejection).toMatchObject({
    code: expected.code ?? "invalid_plan",
    options: {
      category: "invalid_input",
      details: {
        validationField: expected.field,
        validationRule: expected.rule,
      },
    },
  });
  expect((rejection as CommandRuntimeError).options.details).not.toHaveProperty("value");
}

describe("mission-plan provider boundary validation", () => {
  test("reports only the safe path and rule for a missing required string", () => {
    const invalid = draft() as unknown as Record<string, any>;
    delete invalid.steps[0].reversibility;
    try {
      validateMissionPlanDraft(invalid as unknown as MissionPlanDraft);
      throw new Error("expected plan validation to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(CommandRuntimeError);
      expect(error).toMatchObject({
        code: "invalid_plan",
        message: "steps[0].reversibility is required",
        options: {
          category: "invalid_input",
          details: {
            validationField: "steps[0].reversibility",
            validationRule: "required_nonempty_string",
          },
        },
      });
      expect((error as CommandRuntimeError).options.details).not.toHaveProperty("value");
    }
  });

  test("rejects malformed dependency containers as provider drift rather than throwing a TypeError", () => {
    const invalid = draft() as unknown as Record<string, any>;
    invalid.steps[0].dependencyOrdinals = "none";
    expect(() => validateMissionPlanDraft(invalid as unknown as MissionPlanDraft)).toThrow(CommandRuntimeError);
    try {
      validateMissionPlanDraft(invalid as unknown as MissionPlanDraft);
    } catch (error) {
      expect(error).toMatchObject({
        code: "invalid_plan",
        options: {
          details: {
            validationField: "steps[0].dependencyOrdinals",
            validationRule: "array_of_prior_step_ordinals",
          },
        },
      });
    }
  });

  test("reports safe bounded-array diagnostics for missing, empty, and oversized step lists", () => {
    const missing = draft() as unknown as Record<string, any>;
    delete missing.steps;
    expectRepairableDiagnostic(missing as MissionPlanDraft, {
      field: "steps",
      rule: "required_array",
    });

    const empty = draft();
    empty.steps = [];
    expectRepairableDiagnostic(empty, {
      code: "invalid_plan_step_count",
      field: "steps",
      rule: "bounded_nonempty_array",
    });

    const oversized = draft();
    oversized.steps = [draft().steps[0]!, draft().steps[0]!];
    expectRepairableDiagnostic(oversized, {
      code: "invalid_plan_step_count",
      field: "steps",
      rule: "bounded_nonempty_array",
    }, 1);
  });

  test("reports only the field and maximum for oversized text", () => {
    const invalid = draft();
    invalid.strategySummary = "x".repeat(4_001);
    expectRepairableDiagnostic(invalid, {
      field: "strategySummary",
      rule: "maximum_4000_characters",
    });
  });

  test("reports safe structural diagnostics for every JSON safety bound", () => {
    const tooDeep = draft();
    let nested = tooDeep.steps[0]!.action.arguments as Record<string, unknown>;
    let depthPath = "steps[0].action.arguments";
    for (let depth = 0; depth < 13; depth += 1) {
      const child: Record<string, unknown> = {};
      nested.child = child;
      nested = child;
      depthPath += ".child";
    }
    expectRepairableDiagnostic(tooDeep, {
      field: depthPath,
      rule: "maximum_json_depth_12",
    });

    const tooMany = draft();
    tooMany.steps[0]!.action.arguments.items = Array.from({ length: 501 }, () => null);
    expectRepairableDiagnostic(tooMany, {
      field: "steps[0].action.arguments.items",
      rule: "maximum_json_array_items_500",
    });

    const nonFinite = draft();
    nonFinite.steps[0]!.action.arguments.score = Number.POSITIVE_INFINITY;
    expectRepairableDiagnostic(nonFinite, {
      field: "steps[0].action.arguments.score",
      rule: "finite_json_number",
    });

    const unsupported = draft();
    unsupported.steps[0]!.action.arguments.unsupported = undefined;
    expectRepairableDiagnostic(unsupported, {
      field: "steps[0].action.arguments.unsupported",
      rule: "json_serializable_value",
    });
  });

  test("reports safe structural diagnostics for malformed steps and actions", () => {
    const malformedStep = draft() as unknown as Record<string, any>;
    malformedStep.steps[0] = null;
    expectRepairableDiagnostic(malformedStep as MissionPlanDraft, {
      field: "steps[0]",
      rule: "required_object",
    });

    const missingAction = draft() as unknown as Record<string, any>;
    missingAction.steps[0].action = null;
    expectRepairableDiagnostic(missingAction as MissionPlanDraft, {
      field: "steps[0].action",
      rule: "required_object",
    });

    const invalidKind = draft() as unknown as Record<string, any>;
    invalidKind.steps[0].action.kind = "shell";
    expectRepairableDiagnostic(invalidKind as MissionPlanDraft, {
      field: "steps[0].action.kind",
      rule: "allowed_action_kind",
    });

    const malformedArguments = draft() as unknown as Record<string, any>;
    malformedArguments.steps[0].action.arguments = [];
    expectRepairableDiagnostic(malformedArguments as MissionPlanDraft, {
      field: "steps[0].action.arguments",
      rule: "required_json_object",
    });

    const invalidRisk = draft() as unknown as Record<string, any>;
    invalidRisk.steps[0].riskClass = "severe";
    expectRepairableDiagnostic(invalidRisk as MissionPlanDraft, {
      field: "steps[0].riskClass",
      rule: "allowed_risk_class",
    });
  });

  test("reports the dependency field and prior-ordinal rule for an invalid dependency", () => {
    const invalid = draft();
    invalid.steps[0]!.dependencyOrdinals = [0];
    expectRepairableDiagnostic(invalid, {
      code: "invalid_plan_dependency",
      field: "steps[0].dependencyOrdinals",
      rule: "array_of_prior_step_ordinals",
    });
  });

  test("keeps secret material and Autonomous manual actions outside the repairable schema path", () => {
    const secret = draft();
    secret.steps[0]!.action.arguments.api_key = "must-not-be-repaired";
    let secretRejection: unknown;
    try {
      validateMissionPlanDraft(secret);
    } catch (error) {
      secretRejection = error;
    }
    expect(secretRejection).toMatchObject({
      status: 422,
      code: "plan_contains_secret_material",
      options: { category: "policy_denied" },
    });
    expect((secretRejection as CommandRuntimeError).options.details).toBeUndefined();

    const manual = draft();
    manual.steps[0]!.action.kind = "manual";
    let manualRejection: unknown;
    try {
      validateMissionPlanDraft(manual, 32, "autonomous");
    } catch (error) {
      manualRejection = error;
    }
    expect(manualRejection).toMatchObject({
      status: 409,
      code: "autonomous_manual_action_forbidden",
      options: { category: "policy_denied" },
    });
    expect((manualRejection as CommandRuntimeError).options.details).toBeUndefined();
  });
});

import type { Journey } from "../supervisor";
import type { MissionPlanDraft, PlannedAction, PlannedStep } from "./types";
import { CommandRuntimeError } from "./types";

const SECRET_KEY = /(?:^|[_-])(api[_-]?key|auth|authorization|bearer|credential|password|private[_-]?key|secret|session|token)(?:$|[_-])/iu;

function repairablePlanError(
  code: "invalid_plan" | "invalid_plan_dependency" | "invalid_plan_step_count",
  message: string,
  validationField: string,
  validationRule: string,
  humanMessage = "The planning provider returned a malformed bounded plan. No action was created.",
): CommandRuntimeError {
  return new CommandRuntimeError(422, code, message, {
    humanMessage,
    category: "invalid_input",
    details: { validationField, validationRule },
    remediation: "Regenerate the bounded plan using only the documented schema and authorized values.",
  });
}

function text(value: unknown, field: string, maximum = 2_000): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new CommandRuntimeError(422, "invalid_plan", `${field} is required`, {
      humanMessage: `The planning provider omitted or malformed the required ${field} field. No action was created.`,
      category: "invalid_input",
      details: { validationField: field, validationRule: "required_nonempty_string" },
      remediation: "Correct the planning provider so every bounded step includes the required fields.",
    });
  }
  const normalized = value.trim();
  if (normalized.length > maximum) {
    throw repairablePlanError(
      "invalid_plan",
      `${field} exceeds ${maximum} characters`,
      field,
      `maximum_${maximum}_characters`,
      "The planning provider returned an oversized plan field.",
    );
  }
  return normalized;
}

function assertJsonSafe(value: unknown, path = "arguments", depth = 0): void {
  if (depth > 12) {
    throw repairablePlanError(
      "invalid_plan",
      `${path} is too deeply nested`,
      path,
      "maximum_json_depth_12",
    );
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw repairablePlanError(
        "invalid_plan",
        `${path} contains a non-finite number`,
        path,
        "finite_json_number",
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 500) {
      throw repairablePlanError(
        "invalid_plan",
        `${path} contains too many items`,
        path,
        "maximum_json_array_items_500",
      );
    }
    value.forEach((item, index) => assertJsonSafe(item, `${path}[${index}]`, depth + 1));
    return;
  }
  if (!value || typeof value !== "object") {
    throw repairablePlanError(
      "invalid_plan",
      `${path} is not JSON serializable`,
      path,
      "json_serializable_value",
    );
  }
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_KEY.test(key)) {
      throw new CommandRuntimeError(422, "plan_contains_secret_material", `${path}.${key} looks sensitive`, {
        humanMessage: "The proposed plan contains credential-like material and was not persisted.",
        category: "policy_denied",
        remediation: "Reference a configured credential by opaque ID; never place a secret in plan parameters.",
      });
    }
    assertJsonSafe(item, `${path}.${key}`, depth + 1);
  }
}

function validateAction(value: PlannedAction, index: number): PlannedAction {
  if (!value || typeof value !== "object") {
    throw repairablePlanError(
      "invalid_plan",
      `steps[${index}].action is required`,
      `steps[${index}].action`,
      "required_object",
    );
  }
  const kind = value.kind;
  if (kind !== "tool" && kind !== "provider_turn" && kind !== "replan" && kind !== "delegation" && kind !== "manual") {
    throw repairablePlanError(
      "invalid_plan",
      `steps[${index}].action.kind is invalid`,
      `steps[${index}].action.kind`,
      "allowed_action_kind",
    );
  }
  if (!value.arguments || typeof value.arguments !== "object" || Array.isArray(value.arguments)) {
    throw repairablePlanError(
      "invalid_plan",
      `steps[${index}].action.arguments must be an object`,
      `steps[${index}].action.arguments`,
      "required_json_object",
    );
  }
  assertJsonSafe(value.arguments, `steps[${index}].action.arguments`);
  return {
    actionType: text(value.actionType, `steps[${index}].action.actionType`, 120).toLowerCase(),
    actionClass: text(value.actionClass, `steps[${index}].action.actionClass`, 120).toLowerCase(),
    target: text(value.target, `steps[${index}].action.target`, 2_000),
    arguments: JSON.parse(JSON.stringify(value.arguments)) as Record<string, unknown>,
    intentSummary: text(value.intentSummary, `steps[${index}].action.intentSummary`, 1_000),
    kind,
    idempotent: value.idempotent === true,
    destructive: value.destructive === true,
  };
}

function validateStep(value: PlannedStep, index: number, count: number): PlannedStep {
  if (!value || typeof value !== "object") {
    throw repairablePlanError(
      "invalid_plan",
      `steps[${index}] must be an object`,
      `steps[${index}]`,
      "required_object",
    );
  }
  if (!(["low", "medium", "high", "critical"] as const).includes(value.riskClass)) {
    throw repairablePlanError(
      "invalid_plan",
      `steps[${index}].riskClass is invalid`,
      `steps[${index}].riskClass`,
      "allowed_risk_class",
    );
  }
  if (value.dependencyOrdinals !== undefined && !Array.isArray(value.dependencyOrdinals)) {
    throw new CommandRuntimeError(422, "invalid_plan", `steps[${index}].dependencyOrdinals must be an array`, {
      humanMessage: `The planning provider malformed the required steps[${index}].dependencyOrdinals array. No action was created.`,
      category: "invalid_input",
      details: {
        validationField: `steps[${index}].dependencyOrdinals`,
        validationRule: "array_of_prior_step_ordinals",
      },
      remediation: "Return an array of zero-based prior step ordinals; use an empty array when there are no dependencies.",
    });
  }
  const dependencies = [...new Set(value.dependencyOrdinals ?? [])];
  for (const dependency of dependencies) {
    if (!Number.isSafeInteger(dependency) || dependency < 0 || dependency >= count || dependency >= index) {
      throw new CommandRuntimeError(
        422,
        "invalid_plan_dependency",
        `Step ${index} has a non-prior dependency ${String(dependency)}`,
        {
          humanMessage: "The proposed plan contains a dependency cycle or invalid step reference.",
          category: "invalid_input",
          details: {
            validationField: `steps[${index}].dependencyOrdinals`,
            validationRule: "array_of_prior_step_ordinals",
          },
          remediation: "Return an ordered acyclic plan whose dependencies refer only to earlier steps.",
        },
      );
    }
  }
  const criteria = Array.isArray(value.successCriteria)
    ? value.successCriteria.map((criterion, criterionIndex) =>
        text(criterion, `steps[${index}].successCriteria[${criterionIndex}]`, 1_000))
    : [];
  return {
    phase: text(value.phase, `steps[${index}].phase`, 120),
    title: text(value.title, `steps[${index}].title`, 240),
    objective: text(value.objective, `steps[${index}].objective`, 2_000),
    explanation: text(value.explanation, `steps[${index}].explanation`, 4_000),
    rationale: text(value.rationale, `steps[${index}].rationale`, 4_000),
    successCriteria: criteria,
    dependencyOrdinals: dependencies,
    assignedAgentId: text(value.assignedAgentId, `steps[${index}].assignedAgentId`, 200),
    riskClass: value.riskClass,
    reversibility: text(value.reversibility, `steps[${index}].reversibility`, 1_000),
    action: validateAction(value.action, index),
  };
}

export function validateMissionPlanDraft(
  value: MissionPlanDraft,
  maximumSteps = 32,
  journey?: Journey,
): MissionPlanDraft {
  if (!value || typeof value !== "object" || !Array.isArray(value.steps)) {
    throw repairablePlanError(
      "invalid_plan",
      "The planning provider did not return a step list",
      "steps",
      "required_array",
    );
  }
  if (value.steps.length < 1 || value.steps.length > maximumSteps) {
    throw new CommandRuntimeError(
      422,
      "invalid_plan_step_count",
      `A plan must contain 1 through ${maximumSteps} bounded steps`,
      {
        humanMessage: "The proposed plan is empty or exceeds the bounded step limit.",
        category: "invalid_input",
        details: {
          validationField: "steps",
          validationRule: "bounded_nonempty_array",
        },
      },
    );
  }
  const plan = {
    strategySummary: text(value.strategySummary, "strategySummary", 4_000),
    rationaleSummary: text(value.rationaleSummary, "rationaleSummary", 4_000),
    steps: value.steps.map((step, index) => validateStep(step, index, value.steps.length)),
  };
  if (journey === "autonomous" && plan.steps.some((step) => step.action.kind === "manual")) {
    throw new CommandRuntimeError(
      409,
      "autonomous_manual_action_forbidden",
      "Autonomous plans cannot contain operator-executed manual actions",
      {
        humanMessage: "Safe-stopped: the proposed Autonomous plan requires operator execution and is outside the mission contract.",
        category: "policy_denied",
        remediation: "Choose an enforceable specialist tool binding or create a Guided run for operator-executed work.",
      },
    );
  }
  return plan;
}

export function validateExecutionResultSummary(value: unknown): string {
  return text(value, "summary", 8_000);
}

export function validateReason(value: unknown, field = "reason"): string {
  return text(value, field, 2_000);
}

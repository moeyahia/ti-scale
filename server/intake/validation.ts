import {
  ACTION_CLASS_IDS,
  ACTION_POLICY_STATES,
  BUDGET_PRESET_IDS,
  MISSION_TEMPLATE_IDS,
  type ActionClassId,
  type ActionPolicyState,
  type BudgetPresetId,
  type DestructiveActionPolicy,
  type MissionTarget,
  type MissionTemplateId,
} from "../domain";
import { MissionIntakeValidationError } from "./MissionIntakeService";
import type { MissionIntakeRequest, MissionIntakeTargetInput } from "./types";

type RecordValue = Record<string, unknown>;

const TARGET_TYPES: readonly MissionTarget["type"][] = [
  "host", "cidr", "url", "domain", "cloud_account", "scope_file", "engagement", "lab_environment",
];
const DESTRUCTIVE_POLICIES: readonly DestructiveActionPolicy[] = [
  "prohibited", "validate_without_executing", "bounded_lab_only",
];
const EXPLANATION_DEPTHS = ["concise", "balanced", "deep"] as const;
const EXECUTION_PREFERENCES = ["manual", "single_step_agent"] as const;

function record(value: unknown, label: string, issues: string[]): RecordValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    issues.push(`${label} must be an object.`);
    return {};
  }
  return value as RecordValue;
}

function optionalString(value: unknown, label: string, issues: string[], maximum = 20_000): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    issues.push(`${label} must be non-empty text no longer than ${maximum} characters.`);
    return undefined;
  }
  return value.trim();
}

function stringArray(value: unknown, label: string, issues: string[]): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 250) {
    issues.push(`${label} must be an array with no more than 250 text values.`);
    return undefined;
  }
  const parsed = value.flatMap((item, index) => {
    const result = optionalString(item, `${label}[${index}]`, issues, 4_000);
    return result ? [result] : [];
  });
  return parsed;
}

function choice<const T extends string>(
  value: unknown,
  choices: readonly T[],
  label: string,
  issues: string[],
): T | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "string" && choices.includes(value as T)) return value as T;
  issues.push(`${label} must be one of: ${choices.join(", ")}.`);
  return undefined;
}

function targets(value: unknown, issues: string[]): MissionIntakeTargetInput[] {
  if (!Array.isArray(value)) {
    issues.push("targets must be an array.");
    return [];
  }
  return value.slice(0, 250).map((candidate, index) => {
    const item = record(candidate, `targets[${index}]`, issues);
    const parsedValue = optionalString(item.value, `targets[${index}].value`, issues, 2_000) ?? "";
    const type = choice(item.type, TARGET_TYPES, `targets[${index}].type`, issues);
    if (item.excluded !== undefined && typeof item.excluded !== "boolean") {
      issues.push(`targets[${index}].excluded must be true or false.`);
    }
    return {
      value: parsedValue,
      ...(type ? { type } : {}),
      ...(item.excluded === true ? { excluded: true } : {}),
    };
  });
}

function actionOverrides(value: unknown, issues: string[]): Partial<Record<ActionClassId, ActionPolicyState>> | undefined {
  if (value === undefined) return undefined;
  const input = record(value, "actionPolicyOverrides", issues);
  const known = new Set<string>(ACTION_CLASS_IDS);
  const result: Partial<Record<ActionClassId, ActionPolicyState>> = {};
  for (const [key, candidate] of Object.entries(input)) {
    if (!known.has(key)) {
      issues.push(`actionPolicyOverrides contains unknown action class ${key}.`);
      continue;
    }
    const policy = choice(candidate, ACTION_POLICY_STATES, `actionPolicyOverrides.${key}`, issues);
    if (policy) result[key as ActionClassId] = policy;
  }
  return result;
}

export function validateMissionIntakeRequest(value: unknown): MissionIntakeRequest {
  const issues: string[] = [];
  const input = record(value, "Mission intake", issues);
  const journey = choice(input.journey, ["autonomous", "guided"] as const, "journey", issues);
  if (input.authorizationAcknowledged !== true) {
    issues.push("authorizationAcknowledged must be true.");
  }
  const parsedTargets = targets(input.targets, issues);
  const templateId = choice(input.templateId, MISSION_TEMPLATE_IDS, "templateId", issues) as MissionTemplateId | undefined;
  const budgetPresetId = choice(input.budgetPresetId, BUDGET_PRESET_IDS, "budgetPresetId", issues) as BudgetPresetId | undefined;
  const destructivePolicy = choice(input.destructivePolicy, DESTRUCTIVE_POLICIES, "destructivePolicy", issues);
  const explanationDepth = choice(input.explanationDepth, EXPLANATION_DEPTHS, "explanationDepth", issues);
  const executionPreference = choice(input.executionPreference, EXECUTION_PREFERENCES, "executionPreference", issues);
  const title = optionalString(input.title, "title", issues, 240);
  const objective = optionalString(input.objective, "objective", issues);
  const engagementId = optionalString(input.engagementId, "engagementId", issues, 240);
  const successCriteria = stringArray(input.successCriteria, "successCriteria", issues);
  const deliverableIds = stringArray(input.deliverableIds, "deliverableIds", issues);
  const evidenceTypeIds = stringArray(input.evidenceTypeIds, "evidenceTypeIds", issues);
  const optionalSafeStopIds = stringArray(input.optionalSafeStopIds, "optionalSafeStopIds", issues);
  const boundedDestructiveTargetIds = stringArray(input.boundedDestructiveTargetIds, "boundedDestructiveTargetIds", issues);
  const specialistAgentIds = stringArray(input.specialistAgentIds, "specialistAgentIds", issues);
  const memoryScopes = stringArray(input.memoryScopes, "memoryScopes", issues);
  const contextNodeIds = stringArray(input.contextNodeIds, "contextNodeIds", issues);
  const overrides = actionOverrides(input.actionPolicyOverrides, issues);
  if (issues.length > 0 || !journey) throw new MissionIntakeValidationError(issues);
  return {
    journey,
    authorizationAcknowledged: true,
    targets: parsedTargets,
    ...(templateId ? { templateId } : {}),
    ...(title ? { title } : {}),
    ...(objective ? { objective } : {}),
    ...(successCriteria ? { successCriteria } : {}),
    ...(deliverableIds ? { deliverableIds } : {}),
    ...(evidenceTypeIds ? { evidenceTypeIds } : {}),
    ...(optionalSafeStopIds ? { optionalSafeStopIds } : {}),
    ...(overrides ? { actionPolicyOverrides: overrides } : {}),
    ...(destructivePolicy ? { destructivePolicy } : {}),
    ...(boundedDestructiveTargetIds ? { boundedDestructiveTargetIds } : {}),
    ...(budgetPresetId ? { budgetPresetId } : {}),
    ...(engagementId ? { engagementId } : {}),
    ...(explanationDepth ? { explanationDepth } : {}),
    ...(executionPreference ? { executionPreference } : {}),
    ...(specialistAgentIds ? { specialistAgentIds } : {}),
    ...(memoryScopes ? { memoryScopes } : {}),
    ...(contextNodeIds ? { contextNodeIds } : {}),
  };
}

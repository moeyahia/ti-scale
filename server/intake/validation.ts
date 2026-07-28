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
import { parseGuidedReconnaissanceSelection } from "../missions/GuidedReconnaissance";
import {
  type AgentModelAssignmentSelection,
  type AutonomousPlanningSelection,
} from "../model-config";

type RecordValue = Record<string, unknown>;

const TARGET_TYPES: readonly MissionTarget["type"][] = [
  "host", "cidr", "url", "domain", "cloud_account", "scope_file", "engagement", "lab_environment",
];
const DESTRUCTIVE_POLICIES: readonly DestructiveActionPolicy[] = [
  "prohibited", "validate_without_executing", "bounded_lab_only",
];
const EXPLANATION_DEPTHS = ["concise", "balanced", "deep"] as const;
const EXECUTION_PREFERENCES = ["manual", "single_step_agent"] as const;
const ENVIRONMENT_CLASSIFICATIONS = [
  "client_or_public",
  "internal",
  "htb",
  "ctf",
  "local_disposable_lab",
] as const;

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

function agentModelAssignments(
  value: unknown,
  issues: string[],
): AgentModelAssignmentSelection[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 250) {
    issues.push("agentModelAssignments must be an array with no more than 250 exact assignment overrides.");
    return undefined;
  }
  const result: AgentModelAssignmentSelection[] = [];
  const seen = new Set<string>();
  for (const [index, candidate] of value.entries()) {
    const item = record(candidate, `agentModelAssignments[${index}]`, issues);
    const unexpected = Object.keys(item).filter((key) =>
      !["agentId", "primaryConfigurationId", "fallbackConfigurationId"].includes(key));
    if (unexpected.length > 0) {
      issues.push(`agentModelAssignments[${index}] contains unsupported fields: ${unexpected.sort().join(", ")}.`);
    }
    const agentId = optionalString(
      item.agentId,
      `agentModelAssignments[${index}].agentId`,
      issues,
      200,
    ) ?? "";
    const primaryConfigurationId = optionalString(
      item.primaryConfigurationId,
      `agentModelAssignments[${index}].primaryConfigurationId`,
      issues,
      240,
    ) ?? "";
    let fallbackConfigurationId: string | null = null;
    if (item.fallbackConfigurationId !== null) {
      if (item.fallbackConfigurationId === undefined) {
        issues.push(`agentModelAssignments[${index}].fallbackConfigurationId must be a string or null.`);
      } else {
        fallbackConfigurationId = optionalString(
          item.fallbackConfigurationId,
          `agentModelAssignments[${index}].fallbackConfigurationId`,
          issues,
          240,
        ) ?? null;
      }
    }
    for (const [label, identifier] of [
      ["agentId", agentId],
      ["primaryConfigurationId", primaryConfigurationId],
      ["fallbackConfigurationId", fallbackConfigurationId],
    ] as const) {
      if (
        identifier
        && !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,239}$/u.test(identifier)
      ) {
        issues.push(`agentModelAssignments[${index}].${label} is not a valid stable identifier.`);
      }
    }
    if (fallbackConfigurationId === primaryConfigurationId) {
      issues.push(`agentModelAssignments[${index}].fallbackConfigurationId must differ from the primary configuration.`);
    }
    if (seen.has(agentId)) {
      issues.push(`agentModelAssignments contains duplicate agent ${agentId}.`);
      continue;
    }
    seen.add(agentId);
    result.push({ agentId, primaryConfigurationId, fallbackConfigurationId });
  }
  return result.sort((left, right) => left.agentId.localeCompare(right.agentId));
}

function stableIdentifier(
  value: unknown,
  label: string,
  issues: string[],
  maximum: number,
): string {
  const parsed = optionalString(value, label, issues, maximum) ?? "";
  if (
    parsed
    && !new RegExp(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,${maximum - 1}}$`, "u")
      .test(parsed)
  ) {
    issues.push(`${label} is not a valid stable identifier.`);
  }
  return parsed;
}

function literal<const T extends string>(
  value: unknown,
  expected: T,
  label: string,
  issues: string[],
): T {
  if (value !== expected) issues.push(`${label} must be ${expected}.`);
  return expected;
}

function autonomousPlanningSelection(
  value: unknown,
  issues: string[],
): AutonomousPlanningSelection | undefined {
  if (value === undefined) return undefined;
  const item = record(value, "planningSelection", issues);
  if (item.route === "local_deterministic") {
    const supported = new Set([
      "route",
      "plannerId",
      "enforcementMode",
      "disclosureClass",
      "executionAuthority",
    ]);
    const unexpected = Object.keys(item).filter((key) => !supported.has(key));
    if (unexpected.length > 0) {
      issues.push(
        `planningSelection contains unsupported local_deterministic fields: ${unexpected.sort().join(", ")}.`,
      );
    }
    return {
      route: "local_deterministic",
      plannerId: literal(
        item.plannerId,
        "ti-scale.local-autonomous-contract-planner.v1",
        "planningSelection.plannerId",
        issues,
      ),
      enforcementMode: literal(
        item.enforcementMode,
        "local_policy",
        "planningSelection.enforcementMode",
        issues,
      ),
      disclosureClass: literal(
        item.disclosureClass,
        "local_only",
        "planningSelection.disclosureClass",
        issues,
      ),
      executionAuthority: literal(
        item.executionAuthority,
        "none",
        "planningSelection.executionAuthority",
        issues,
      ),
    };
  }
  if (item.route === "provider_advisory") {
    const supported = new Set([
      "route",
      "agentId",
      "primaryConfigurationId",
      "fallbackConfigurationId",
      "enforcementMode",
      "disclosureClass",
      "executionAuthority",
    ]);
    const unexpected = Object.keys(item).filter((key) => !supported.has(key));
    if (unexpected.length > 0) {
      issues.push(
        `planningSelection contains unsupported provider_advisory fields: ${unexpected.sort().join(", ")}.`,
      );
    }
    const agentId = stableIdentifier(
      item.agentId,
      "planningSelection.agentId",
      issues,
      200,
    );
    const primaryConfigurationId = stableIdentifier(
      item.primaryConfigurationId,
      "planningSelection.primaryConfigurationId",
      issues,
      240,
    );
    let fallbackConfigurationId: string | null = null;
    if (item.fallbackConfigurationId !== null) {
      if (item.fallbackConfigurationId === undefined) {
        issues.push("planningSelection.fallbackConfigurationId must be a string or null.");
      } else {
        fallbackConfigurationId = stableIdentifier(
          item.fallbackConfigurationId,
          "planningSelection.fallbackConfigurationId",
          issues,
          240,
        ) || null;
      }
    }
    if (fallbackConfigurationId === primaryConfigurationId) {
      issues.push(
        "planningSelection.fallbackConfigurationId must differ from the primary configuration.",
      );
    }
    const disclosureClass = choice(
      item.disclosureClass,
      ["public_only", "sanitized_internal"] as const,
      "planningSelection.disclosureClass",
      issues,
    ) ?? "public_only";
    return {
      route: "provider_advisory",
      agentId,
      primaryConfigurationId,
      fallbackConfigurationId,
      enforcementMode: literal(
        item.enforcementMode,
        "advisor_only",
        "planningSelection.enforcementMode",
        issues,
      ),
      disclosureClass,
      executionAuthority: literal(
        item.executionAuthority,
        "none",
        "planningSelection.executionAuthority",
        issues,
      ),
    };
  }
  issues.push("planningSelection.route must be local_deterministic or provider_advisory.");
  return undefined;
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
  const environmentClassification = choice(
    input.environmentClassification,
    ENVIRONMENT_CLASSIFICATIONS,
    "environmentClassification",
    issues,
  );
  if (input.environmentClassification !== undefined && journey !== "autonomous") {
    issues.push("environmentClassification is available only for the Autonomous journey.");
  }
  const guidedReconnaissance = parseGuidedReconnaissanceSelection(input.guidedReconnaissance);
  issues.push(...guidedReconnaissance.issues);
  if (input.guidedReconnaissance !== undefined && journey !== "guided") {
    issues.push("guidedReconnaissance is available only for the Guided journey.");
  }
  const title = optionalString(input.title, "title", issues, 240);
  const objective = optionalString(input.objective, "objective", issues);
  const engagementId = optionalString(input.engagementId, "engagementId", issues, 240);
  const successCriteria = stringArray(input.successCriteria, "successCriteria", issues);
  const deliverableIds = stringArray(input.deliverableIds, "deliverableIds", issues);
  const evidenceTypeIds = stringArray(input.evidenceTypeIds, "evidenceTypeIds", issues);
  const optionalSafeStopIds = stringArray(input.optionalSafeStopIds, "optionalSafeStopIds", issues);
  const boundedDestructiveTargetIds = stringArray(input.boundedDestructiveTargetIds, "boundedDestructiveTargetIds", issues);
  const specialistAgentIds = stringArray(input.specialistAgentIds, "specialistAgentIds", issues);
  const modelAssignments = agentModelAssignments(input.agentModelAssignments, issues);
  if (input.agentModelAssignments !== undefined && journey !== "autonomous") {
    issues.push("agentModelAssignments is available only for the Autonomous journey.");
  }
  const planningSelection = autonomousPlanningSelection(
    input.planningSelection,
    issues,
  );
  if (input.planningSelection !== undefined && journey !== "autonomous") {
    issues.push("planningSelection is available only for the Autonomous journey.");
  }
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
    ...(environmentClassification ? { environmentClassification } : {}),
    ...(explanationDepth ? { explanationDepth } : {}),
    ...(executionPreference ? { executionPreference } : {}),
    ...(guidedReconnaissance.selection ? { guidedReconnaissance: guidedReconnaissance.selection } : {}),
    ...(specialistAgentIds ? { specialistAgentIds } : {}),
    ...(modelAssignments ? { agentModelAssignments: modelAssignments } : {}),
    ...(planningSelection ? { planningSelection } : {}),
    ...(memoryScopes ? { memoryScopes } : {}),
    ...(contextNodeIds ? { contextNodeIds } : {}),
  };
}

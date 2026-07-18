import { array, boolean, nonEmpty, number, object, schema, string, stringList, type JsonRecord } from "./common";
import type { AutonomousMissionRequest, GuidedMissionRequest, MissionCreateRequest } from "../types/commandOs";
import type {
  ActionPolicyState,
  BudgetPresetId,
  CapabilityMapping,
  DestructiveActionPolicy,
  IntakeActionClass,
  IntakeActionClassRegistry,
  IntakeDeliverable,
  IntakeEvidenceType,
  IntakeFieldDefinition,
  IntakeMissionTemplate,
  IntakeRegistrySnapshot,
  MissionBudgetPreset,
  MissionIntakeTargetInput,
  MissionTemplateId,
  ResolvedMissionIntake,
  SafeStopDefinition,
} from "../types/intake";

function literal<const T extends string>(value: unknown, choices: readonly T[], label: string): T {
  if (typeof value === "string" && choices.includes(value as T)) return value as T;
  throw new Error(`${label} is invalid`);
}

function optionalString(value: unknown, label: string): string | undefined {
  return value === undefined || value === null ? undefined : string(value, label);
}

function recordOf<T>(value: unknown, label: string, parser: (item: unknown, key: string) => T): Record<string, T> {
  const source = object(value, label);
  return Object.fromEntries(Object.entries(source).map(([key, item]) => [key, parser(item, key)]));
}

function parseCapability(value: unknown): CapabilityMapping {
  const item = object(value, "action capability");
  return {
    availability: literal(item.availability, ["supported", "unavailable", "unsupported"], "capability availability"),
    riskClassIds: stringList(item.riskClassIds, "capability risk classes"),
    agentIds: stringList(item.agentIds, "capability agents"),
    availableAgentIds: stringList(item.availableAgentIds, "available capability agents"),
    toolIds: stringList(item.toolIds, "capability tools"),
    availableToolIds: stringList(item.availableToolIds, "available capability tools"),
    mcpServerIds: stringList(item.mcpServerIds, "capability MCP servers"),
    providerModelRefs: stringList(item.providerModelRefs, "capability provider models"),
    enforcedProviderModelRefs: stringList(item.enforcedProviderModelRefs, "enforced provider models"),
    locallyEnforcedToolIds: stringList(item.locallyEnforcedToolIds, "locally enforced tools"),
    evidenceTypeIds: stringList(item.evidenceTypeIds, "capability evidence types"),
    enforcementReady: boolean(item.enforcementReady, "capability enforcement readiness"),
    readinessReasons: stringList(item.readinessReasons, "capability readiness reasons"),
  };
}

function parseActionClass(value: unknown, key: string): IntakeActionClass {
  const item = object(value, `action class ${key}`);
  return {
    id: nonEmpty(item.id, "action class id"),
    label: nonEmpty(item.label, "action class label"),
    plainLanguageDescription: nonEmpty(item.plainLanguageDescription, "action class description"),
    technicalDescription: nonEmpty(item.technicalDescription, "action class technical description"),
    riskBand: literal(item.riskBand, ["low", "moderate", "high", "critical"], "action risk band"),
    likelySideEffects: stringList(item.likelySideEffects, "action side effects"),
    defaultPolicyState: literal(item.defaultPolicyState, ["pre_authorized", "prohibited", "guided_only"], "default action policy"),
    defaultEvidenceTypeIds: stringList(item.defaultEvidenceTypeIds, "default action evidence"),
    destructiveOrDisruptive: boolean(item.destructiveOrDisruptive, "destructive action marker"),
    policyState: literal(item.policyState, ["pre_authorized", "prohibited", "guided_only"], "resolved action policy"),
    policySource: literal(item.policySource, ["platform_default", "preset", "operator_override"], "action policy source"),
    capability: parseCapability(item.capability),
    launchBlockingReasons: stringList(item.launchBlockingReasons, "action launch blockers"),
  };
}

function parseActionRegistry(value: unknown): IntakeActionClassRegistry {
  const item = object(value, "action-class registry");
  return {
    journey: literal(item.journey, ["autonomous", "guided"], "registry journey"),
    presetId: literal(item.presetId, ["safe_recon", "external_web_assessment", "internal_network_assessment", "active_directory_lab", "cloud_read_only", "full_authorized_lab_compromise", "custom"], "policy preset"),
    destructivePolicy: literal(item.destructivePolicy, ["prohibited", "validate_without_executing", "bounded_lab_only"], "destructive policy"),
    classes: recordOf(item.classes, "action classes", parseActionClass),
    autonomousLaunchReady: boolean(item.autonomousLaunchReady, "Autonomous launch readiness"),
    launchBlockingReasons: stringList(item.launchBlockingReasons, "registry launch blockers"),
  };
}

function parseEvidenceType(value: unknown): IntakeEvidenceType {
  const item = object(value, "evidence type");
  const capability = object(item.capability, "evidence capability");
  return {
    id: nonEmpty(item.id, "evidence type id"), label: nonEmpty(item.label, "evidence label"),
    proves: nonEmpty(item.proves, "evidence purpose"), storageAndSensitivity: nonEmpty(item.storageAndSensitivity, "evidence sensitivity"),
    normallyRequiredForActionClassIds: stringList(item.normallyRequiredForActionClassIds, "evidence action classes"),
    immutableHashRequired: boolean(item.immutableHashRequired, "evidence hash requirement"),
    chainOfCustodyRequired: boolean(item.chainOfCustodyRequired, "evidence custody requirement"),
    capability: {
      evidenceTypeId: nonEmpty(capability.evidenceTypeId, "evidence capability id"),
      runtimeEvidenceKindIds: stringList(capability.runtimeEvidenceKindIds, "runtime evidence kinds"),
      producerToolIds: stringList(capability.producerToolIds, "evidence producer tools"),
      availability: literal(capability.availability, ["supported", "unavailable", "unsupported"], "evidence availability"),
    },
  };
}

function parseDeliverable(value: unknown): IntakeDeliverable {
  const item = object(value, "deliverable");
  const capability = object(item.capability, "deliverable capability");
  return {
    id: nonEmpty(item.id, "deliverable id"), label: nonEmpty(item.label, "deliverable label"),
    purpose: nonEmpty(item.purpose, "deliverable purpose"), formats: stringList(item.formats, "deliverable formats"),
    sensitivityNotes: nonEmpty(item.sensitivityNotes, "deliverable sensitivity"),
    capability: {
      deliverableId: nonEmpty(capability.deliverableId, "deliverable capability id"),
      producerAgentIds: stringList(capability.producerAgentIds, "deliverable agents"),
      producerToolIds: stringList(capability.producerToolIds, "deliverable tools"),
      availability: literal(capability.availability, ["supported", "unavailable", "unsupported"], "deliverable availability"),
    },
  };
}

const TEMPLATE_IDS = ["safe_recon", "external_web_assessment", "internal_network_assessment", "active_directory_lab", "cloud_read_only", "full_authorized_lab_compromise", "custom"] as const;
const BUDGET_IDS = ["quick", "standard", "deep", "custom"] as const;

function parseTemplate(value: unknown): IntakeMissionTemplate {
  const item = object(value, "mission template");
  return {
    id: literal(item.id, TEMPLATE_IDS, "mission template id"), version: number(item.version, "mission template version"),
    label: nonEmpty(item.label, "mission template label"), summary: nonEmpty(item.summary, "mission template summary"),
    supportedJourneys: array(item.supportedJourneys, "template journeys").map((journey) => literal(journey, ["autonomous", "guided"], "template journey")),
    actionPolicyPresetId: literal(item.actionPolicyPresetId, TEMPLATE_IDS, "template policy preset"),
    scopeHints: stringList(item.scopeHints, "template scope hints"), objectivePattern: nonEmpty(item.objectivePattern, "template objective"),
    successCriteria: stringList(item.successCriteria, "template success criteria"),
    recommendedActionClassIds: stringList(item.recommendedActionClassIds, "template actions"),
    recommendedEvidenceTypeIds: stringList(item.recommendedEvidenceTypeIds, "template evidence"),
    recommendedDeliverableIds: stringList(item.recommendedDeliverableIds, "template deliverables"),
    recommendedOptionalSafeStops: stringList(item.recommendedOptionalSafeStops, "template safe stops"),
    recommendedAgentCapabilityIds: stringList(item.recommendedAgentCapabilityIds, "template agents"),
    modelReadinessRequirements: stringList(item.modelReadinessRequirements, "template model requirements"),
    budgetPreset: literal(item.budgetPreset, BUDGET_IDS, "template budget"),
    unsupportedActionClassIds: stringList(item.unsupportedActionClassIds, "unsupported template actions"),
    unavailableEvidenceTypeIds: stringList(item.unavailableEvidenceTypeIds, "unavailable template evidence"),
    unavailableDeliverableIds: stringList(item.unavailableDeliverableIds, "unavailable template deliverables"),
  };
}

function parseSafeStop(value: unknown): SafeStopDefinition {
  const item = object(value, "safe-stop definition");
  return { id: nonEmpty(item.id, "safe-stop id"), label: nonEmpty(item.label, "safe-stop label"), explanation: nonEmpty(item.explanation, "safe-stop explanation"), remediation: nonEmpty(item.remediation, "safe-stop remediation"), mandatory: boolean(item.mandatory, "safe-stop mandatory"), userRemovable: boolean(item.userRemovable, "safe-stop removability") };
}

function parseBudget(value: unknown): MissionBudgetPreset {
  const item = object(value, "budget preset");
  return {
    id: literal(item.id, ["quick", "standard", "deep"], "budget id"), label: nonEmpty(item.label, "budget label"), description: nonEmpty(item.description, "budget description"),
    timeBudgetMinutes: number(item.timeBudgetMinutes, "time budget"), tokenBudget: number(item.tokenBudget, "token budget"), estimatedCostBudget: number(item.estimatedCostBudget, "cost budget"), toolCallBudget: number(item.toolCallBudget, "tool-call budget"), retryBudget: number(item.retryBudget, "retry budget"), replanBudget: number(item.replanBudget, "replan budget"), concurrencyLimit: number(item.concurrencyLimit, "concurrency budget"), screenshotBudget: number(item.screenshotBudget, "screenshot budget"), evidenceStorageBudgetBytes: number(item.evidenceStorageBudgetBytes, "evidence storage budget"), artifactStorageBudgetBytes: number(item.artifactStorageBudgetBytes, "artifact storage budget"), maximumArtifactBytes: number(item.maximumArtifactBytes, "maximum artifact size"),
  };
}

function parseField(value: unknown): IntakeFieldDefinition {
  const item = object(value, "intake field");
  return { id: nonEmpty(item.id, "field id"), label: nonEmpty(item.label, "field label"), purpose: nonEmpty(item.purpose, "field purpose"), example: nonEmpty(item.example, "field example"), optional: boolean(item.optional, "field optional"), structuredWhenPossible: boolean(item.structuredWhenPossible, "field structure marker") };
}

export function parseIntakeRegistrySnapshot(payload: unknown): IntakeRegistrySnapshot {
  const root = object(payload, "intake registry"); schema(root);
  const source = object(root.source, "intake registry source");
  const evidence = object(root.evidenceTypes, "evidence registry");
  const deliverables = object(root.deliverables, "deliverable registry");
  const templates = object(root.templates, "template registry");
  const safeStops = object(root.safeStops, "safe-stop registry");
  return {
    schemaVersion: "2.4",
    source: { status: literal(source.status, ["live", "unavailable"], "registry source status"), explanation: nonEmpty(source.explanation, "registry source explanation"), counts: Object.fromEntries(Object.entries(object(source.counts, "registry source counts")).map(([key, value]) => [key, number(value, `source count ${key}`)])) },
    fields: array(root.fields, "intake fields").map(parseField),
    actionClasses: parseActionRegistry(root.actionClasses),
    evidenceTypes: { types: recordOf(evidence.types, "evidence types", (value) => parseEvidenceType(value)) },
    deliverables: { deliverables: recordOf(deliverables.deliverables, "deliverables", (value) => parseDeliverable(value)) },
    templates: { templates: recordOf(templates.templates, "mission templates", (value) => parseTemplate(value)) },
    safeStops: { mandatory: array(safeStops.mandatory, "mandatory safe stops").map(parseSafeStop), optional: array(safeStops.optional, "optional safe stops").map(parseSafeStop) },
    budgets: recordOf(root.budgets, "budget presets", (value) => parseBudget(value)) as IntakeRegistrySnapshot["budgets"],
  };
}

function parseGuidedRequest(root: JsonRecord): GuidedMissionRequest {
  return {
    journey: "guided", launch: true, authorizationConfirmed: true,
    title: nonEmpty(root.title, "Guided title"), objective: nonEmpty(root.objective, "Guided objective"),
    ...(optionalString(root.target, "Guided target") ? { target: optionalString(root.target, "Guided target") } : {}),
    ...(optionalString(root.engagementId, "Guided engagement") ? { engagementId: optionalString(root.engagementId, "Guided engagement") } : {}),
    explanationDepth: literal(root.explanationDepth, ["concise", "balanced", "deep"], "Guided explanation depth"),
    executionPreference: literal(root.executionPreference, ["manual", "single_step_agent"], "Guided execution preference"),
    evidenceExpectations: stringList(root.evidenceExpectations, "Guided evidence expectations"),
  };
}

function parseAutonomousRequest(root: JsonRecord): AutonomousMissionRequest {
  const authorization = object(root.authorization, "Autonomous authorization");
  const contract = object(root.contract, "Autonomous contract");
  const tokenBudget = contract.tokenBudget === undefined ? undefined : number(contract.tokenBudget, "token budget");
  const costBudget = contract.costBudget === undefined ? undefined : number(contract.costBudget, "cost budget");
  return {
    journey: "autonomous", launch: true, title: nonEmpty(root.title, "Autonomous title"), objective: nonEmpty(root.objective, "Autonomous objective"), successCriteria: stringList(root.successCriteria, "Autonomous success criteria"),
    authorization: {
      ...(optionalString(authorization.engagementId, "engagement ID") ? { engagementId: optionalString(authorization.engagementId, "engagement ID") } : {}),
      allowedTargets: stringList(authorization.allowedTargets, "allowed targets"), prohibitedTargets: stringList(authorization.prohibitedTargets, "prohibited targets"), authorizationConfirmed: boolean(authorization.authorizationConfirmed, "authorization acknowledgement"),
      ...(optionalString(authorization.timeWindow, "time window") ? { timeWindow: optionalString(authorization.timeWindow, "time window") } : {}),
      ...(optionalString(authorization.dataHandling, "data handling") ? { dataHandling: optionalString(authorization.dataHandling, "data handling") } : {}),
    },
    contract: {
      allowedActionClasses: stringList(contract.allowedActionClasses, "allowed action classes"), prohibitedActionClasses: stringList(contract.prohibitedActionClasses, "prohibited action classes"), destructivePolicy: literal(contract.destructivePolicy, ["prohibited", "validate_without_executing", "bounded_lab_only"], "destructive policy"), boundedDestructiveTargets: contract.boundedDestructiveTargets === undefined ? [] : stringList(contract.boundedDestructiveTargets, "bounded destructive targets"), evidenceRequirements: stringList(contract.evidenceRequirements, "evidence requirements"),
      timeBudgetMinutes: number(contract.timeBudgetMinutes, "time budget"), ...(tokenBudget === undefined ? {} : { tokenBudget }), ...(costBudget === undefined ? {} : { costBudget }), retryBudget: number(contract.retryBudget, "retry budget"), replanBudget: number(contract.replanBudget, "replan budget"), concurrencyLimit: number(contract.concurrencyLimit, "concurrency"), evidenceStorageBudgetBytes: number(contract.evidenceStorageBudgetBytes, "evidence storage"), artifactStorageBudgetBytes: number(contract.artifactStorageBudgetBytes, "artifact storage"),
      notificationPolicy: literal(contract.notificationPolicy, ["in_app_only"], "notification policy"), reportingFormat: literal(contract.reportingFormat, ["ti_scale_json"], "reporting format"), dataHandlingPolicy: literal(contract.dataHandlingPolicy, ["local_private"], "data handling policy"), retentionPolicy: literal(contract.retentionPolicy, ["operator_managed"], "retention policy"), providerPolicy: literal(contract.providerPolicy, ["automatic_enforcing_only"], "provider policy"), toolPolicy: literal(contract.toolPolicy, ["contract_allowlist"], "tool policy"), specialistAgentIds: stringList(contract.specialistAgentIds, "specialist agents"), memoryScopes: stringList(contract.memoryScopes, "memory scopes"), contextNodeIds: stringList(contract.contextNodeIds, "context nodes"), safeStopConditions: stringList(contract.safeStopConditions, "safe stops"), deliverables: stringList(contract.deliverables, "deliverables"),
    },
  };
}

function parseMissionRequest(value: unknown): MissionCreateRequest {
  const root = object(value, "resolved mission request");
  if (root.journey === "guided") return parseGuidedRequest(root);
  if (root.journey === "autonomous") return parseAutonomousRequest(root);
  throw new Error("resolved journey is invalid");
}

export function parseResolvedMissionIntake(payload: unknown): ResolvedMissionIntake {
  const root = object(payload, "resolved mission intake"); schema(root);
  const template = object(root.template, "resolved template");
  return {
    schemaVersion: "2.4", request: parseMissionRequest(root.request),
    normalizedTargets: array(root.normalizedTargets, "normalized targets").map((value) => {
      const item = object(value, "normalized target");
      return { id: nonEmpty(item.id, "target id"), value: nonEmpty(item.value, "target value"), type: literal(item.type, ["host", "cidr", "url", "domain", "cloud_account", "scope_file", "engagement", "lab_environment"], "target type"), ...(item.excluded === true ? { excluded: true } : {}) };
    }),
    template: { id: literal(template.id, TEMPLATE_IDS, "resolved template id"), version: number(template.version, "resolved template version") },
    policyMatrix: parseActionRegistry(root.policyMatrix), evidenceTypeIds: stringList(root.evidenceTypeIds, "resolved evidence"), deliverableIds: stringList(root.deliverableIds, "resolved deliverables"), mandatorySafeStopIds: stringList(root.mandatorySafeStopIds, "mandatory safe stops"), optionalSafeStopIds: stringList(root.optionalSafeStopIds, "optional safe stops"), budget: parseBudget(root.budget), inferredFields: stringList(root.inferredFields, "inferred fields"), limitations: stringList(root.limitations, "intake limitations"),
  };
}

export type { ActionPolicyState, BudgetPresetId, DestructiveActionPolicy, MissionIntakeTargetInput, MissionTemplateId };

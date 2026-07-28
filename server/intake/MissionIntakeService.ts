import { createHash } from "node:crypto";
import { isIP } from "node:net";
import {
  ACTION_CLASS_IDS,
  AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
  AUTONOMOUS_OUTCOME_CAPABILITIES,
  DELIVERABLE_IDS,
  EVIDENCE_TYPE_IDS,
  MANDATORY_PLATFORM_SAFE_STOPS,
  MISSION_BUDGET_PRESETS,
  MISSION_TEMPLATES,
  OPTIONAL_MISSION_SAFE_STOPS,
  OPTIONAL_SAFE_STOP_IDS,
  applyMissionTemplate,
  assertTemplatePreservedTargetScope,
  autonomousMaterialObjectiveActionClassIds,
  autonomousMaterialObjectiveRequirements,
  autonomousMaterialObjectiveSuccessCriteria,
  resolveAutonomousOutcomeProfile,
  buildActionClassRegistry,
  buildDeliverableRegistry,
  buildEvidenceTypeRegistry,
  buildMissionTemplateRegistry,
  buildRuntimeCapabilityProjection,
  emptyRuntimeSourceManifests,
  missionBudgetPreset,
  type ActionClassId,
  type BudgetPresetId,
  type MissionBudgetPreset,
  type MissionTarget,
  type MissionTemplate,
  type MissionTemplateId,
  type RuntimeCapabilityProjection,
  type RuntimeSourceManifests,
} from "../domain";
import type {
  IntakeFieldDefinition,
  IntakeRegistrySnapshot,
  MissionIntakeRequest,
  MissionIntakeTargetInput,
  ResolvedMissionIntake,
} from "./types";
import { buildGuidedReconnaissanceRegistry } from "./GuidedReconnaissanceRegistry";
import { parseGuidedReconnaissanceSelection } from "../missions/GuidedReconnaissance";
import {
  PRODUCT_AGENT_IDS,
  PRODUCT_AGENT_REGISTRY,
  productAgentIdsForRuntimeManifestAgent,
} from "../agents";
import {
  AUTONOMOUS_LOCAL_PLANNING_SELECTION,
  ModelConfigurationError,
  autonomousModelCatalogItemReadinessReasons,
  modelCatalogItems,
  type AgentModelAssignmentSelection,
  type AutonomousPlanningSelection,
  type ModelConfigurationService,
} from "../model-config";

const MAX_TARGETS = 250;
const MAX_TEXT = 20_000;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const DISPOSABLE_ENVIRONMENT_CLASSIFICATIONS = new Set([
  "htb",
  "ctf",
  "local_disposable_lab",
]);

export class MissionIntakeValidationError extends Error {
  constructor(readonly issues: readonly string[]) {
    super(issues.join("; "));
    this.name = "MissionIntakeValidationError";
  }
}

export const INTAKE_FIELD_DEFINITIONS: readonly IntakeFieldDefinition[] = [
  {
    id: "authorizationAcknowledged",
    label: "Authorization acknowledgement",
    purpose: "Confirms that the supplied targets and proposed actions are authorized.",
    example: "I confirm that I am authorized to assess the targets in this mission.",
    optional: false,
    structuredWhenPossible: true,
  },
  {
    id: "targets",
    label: "Target or environment",
    purpose: "Defines the exact host, network, URL, domain, account, scope file, engagement, or lab boundary.",
    example: "https://portal.example.test or 10.10.10.0/24",
    optional: false,
    structuredWhenPossible: true,
  },
  {
    id: "environmentClassification",
    label: "Environment classification",
    purpose: "Separates a target's technical type from whether the surrounding environment is disposable and suitable for tightly bounded lab-only execution.",
    example: "Hack The Box — disposable lab",
    optional: true,
    structuredWhenPossible: true,
  },
  {
    id: "title",
    label: "Mission title",
    purpose: "Provides a human-readable name for dashboards, reports, search, and the Vault.",
    example: "Q3 External Web Assessment — Customer Portal",
    optional: true,
    structuredWhenPossible: false,
  },
  {
    id: "objective",
    label: "Authorized objective",
    purpose: "States the outcome Ti-Scale is permitted to establish without expanding target scope.",
    example: "Evaluate the approved customer portal for authentication, authorization, and exposed-service weaknesses.",
    optional: true,
    structuredWhenPossible: false,
  },
  {
    id: "successCriteria",
    label: "Measurable success criteria",
    purpose: "Defines the evidence-backed outcomes used to evaluate mission completion.",
    example: "All approved targets are discovered or explicitly reported unreachable.",
    optional: true,
    structuredWhenPossible: true,
  },
  {
    id: "engagementId",
    label: "Engagement",
    purpose: "Scopes retained knowledge and links the mission to an existing authorized engagement.",
    example: "eng_customer-portal_q3",
    optional: true,
    structuredWhenPossible: true,
  },
] as const;

function text(value: string | undefined, label: string, maximum = MAX_TEXT): string | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  const normalized = value.trim();
  if (normalized.length > maximum || /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/u.test(normalized)) {
    throw new MissionIntakeValidationError([`${label} is too long or contains control characters.`]);
  }
  return normalized;
}

function unique<T extends string>(values: readonly T[]): T[] {
  const seen = new Set<string>();
  return values.flatMap((value) => {
    const normalized = value.trim();
    const key = normalized.toLocaleLowerCase("en-US");
    if (!normalized || seen.has(key)) return [];
    seen.add(key);
    return [normalized as T];
  });
}

function detectTargetType(value: string): MissionTarget["type"] {
  try {
    const url = new URL(value);
    if (url.protocol === "http:" || url.protocol === "https:") return "url";
  } catch {
    // Continue through deterministic non-URL classifications.
  }
  const cidr = value.match(/^(.+)\/(\d{1,3})$/u);
  if (cidr && isIP(cidr[1] ?? "") > 0) return "cidr";
  if (isIP(value) > 0) return "host";
  if (/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}$/u.test(value)) return "domain";
  if (/^(?:aws|azure|gcp|cloud):/iu.test(value)) return "cloud_account";
  if (/^(?:lab|htb|thm|ctf):/iu.test(value)) return "lab_environment";
  return "host";
}

function targetId(type: MissionTarget["type"], value: string): string {
  return `target_${createHash("sha256").update(`${type}\0${value.toLocaleLowerCase("en-US")}`).digest("hex").slice(0, 16)}`;
}

function normalizeTargets(inputs: readonly MissionIntakeTargetInput[]): MissionTarget[] {
  const issues: string[] = [];
  if (!Array.isArray(inputs) || inputs.length === 0) issues.push("At least one authorized target or environment is required.");
  if (inputs.length > MAX_TARGETS) issues.push(`No more than ${MAX_TARGETS} target entries are allowed.`);
  const seen = new Set<string>();
  const targets = inputs.slice(0, MAX_TARGETS).flatMap((input, index) => {
    if (!input || typeof input !== "object") {
      issues.push(`Target ${index + 1} must be a structured target value.`);
      return [];
    }
    const value = text(input.value, `Target ${index + 1}`, 2_000);
    if (!value) {
      issues.push(`Target ${index + 1} must not be blank.`);
      return [];
    }
    const type = input.type ?? detectTargetType(value);
    const key = `${type}\0${value.toLocaleLowerCase("en-US")}`;
    if (seen.has(key)) return [];
    seen.add(key);
    return [{ id: targetId(type, value), type, value, ...(input.excluded ? { excluded: true } : {}) }];
  });
  const allowed = targets.filter(({ excluded }) => !excluded);
  if (allowed.length === 0) issues.push("At least one non-excluded authorized target is required.");
  if (issues.length > 0) throw new MissionIntakeValidationError(issues);
  return targets;
}

function templateById(id: MissionTemplateId): MissionTemplate {
  const template = MISSION_TEMPLATES.find((candidate) => candidate.id === id);
  if (!template) throw new MissionIntakeValidationError([`Unknown mission template: ${id}.`]);
  return template;
}

function assertKnownIds(values: readonly string[], known: readonly string[], label: string): string[] {
  const normalized = unique(values);
  const knownSet = new Set(known);
  const unknown = normalized.filter((value) => !knownSet.has(value));
  if (unknown.length > 0) throw new MissionIntakeValidationError([`${label} contains unknown values: ${unknown.join(", ")}.`]);
  return normalized;
}

function boundedTitle(template: MissionTemplate, target: MissionTarget, now: Date): string {
  const targetLabel = target.value.length > 80 ? `${target.value.slice(0, 77)}…` : target.value;
  return `${template.label} — ${targetLabel} — ${now.toISOString().slice(0, 10)}`.slice(0, 240);
}

function hasLiveSource(manifests: RuntimeSourceManifests): boolean {
  return manifests.agents.length > 0 || manifests.tools.length > 0 || manifests.providers.length > 0;
}

function autonomousAgentsForActionClasses(
  manifests: RuntimeSourceManifests,
  projection: RuntimeCapabilityProjection,
  actionClassIds: readonly ActionClassId[],
): string[] {
  const selected = new Set(actionClassIds);
  const providers = new Map(manifests.providers.map((provider) => [provider.id, provider]));
  const productAgents = new Set<string>();
  for (const agent of manifests.agents) {
    if (!agent.available) continue;
    const assignedContractClasses = [...selected].filter((actionClassId) =>
      projection.actionClasses[actionClassId].availableAgentIds.includes(agent.id));
    if (assignedContractClasses.length === 0) continue;
    const executable = agent.modelRefs.some(({ providerId, modelId }) => {
      const provider = providers.get(providerId);
      const model = provider?.models.find(({ id }) => id === modelId);
      const compatibleClasses = new Set(model?.compatibleActionClassIds ?? []);
      return provider?.authenticated === true
        && provider.healthy === true
        && model?.enforcement === "enforced_executor"
        && model.structuredOutput === true
        && assignedContractClasses.every((actionClassId) => compatibleClasses.has(actionClassId));
    });
    if (!executable) continue;
    for (const productAgentId of productAgentIdsForRuntimeManifestAgent(agent, manifests)) {
      const definition = PRODUCT_AGENT_REGISTRY.find(({ id }) => id === productAgentId);
      if (definition?.capabilities.some(({ actionClassIds: owned }) =>
        owned.some((actionClassId) => assignedContractClasses.includes(actionClassId)))) {
        productAgents.add(productAgentId);
      }
    }
  }
  return PRODUCT_AGENT_REGISTRY
    .map(({ id }) => id)
    .filter((id) => productAgents.has(id));
}

function normalizeRequestedProductAgents(
  requestedAgentIds: readonly string[],
  manifests: RuntimeSourceManifests,
  actionClassIds: readonly ActionClassId[],
): string[] {
  const selectedActionClasses = new Set(actionClassIds);
  const normalized = new Set<string>();
  for (const requestedAgentId of requestedAgentIds) {
    if (PRODUCT_AGENT_IDS.has(requestedAgentId)) {
      normalized.add(requestedAgentId);
      continue;
    }
    const runtimeAgent = manifests.agents.find(({ id }) => id === requestedAgentId);
    if (!runtimeAgent) {
      normalized.add(requestedAgentId);
      continue;
    }
    const mapped = productAgentIdsForRuntimeManifestAgent(runtimeAgent, manifests)
      .filter((productAgentId) => PRODUCT_AGENT_REGISTRY
        .find(({ id }) => id === productAgentId)
        ?.capabilities.some(({ actionClassIds: owned }) =>
          owned.some((actionClassId) => selectedActionClasses.has(actionClassId))));
    if (mapped.length === 0) normalized.add(requestedAgentId);
    for (const productAgentId of mapped) normalized.add(productAgentId);
  }
  return [
    ...PRODUCT_AGENT_REGISTRY
      .map(({ id }) => id)
      .filter((id) => normalized.has(id)),
    ...[...normalized]
      .filter((id) => !PRODUCT_AGENT_IDS.has(id))
      .sort(),
  ];
}

function fallbackAutonomousModelAssignments(input: {
  readonly manifests: RuntimeSourceManifests;
  readonly specialistAgentIds: readonly string[];
  readonly overrides: readonly AgentModelAssignmentSelection[];
  readonly requiredActionClassIds: readonly string[];
  readonly now: Date;
}): AgentModelAssignmentSelection[] {
  const catalog = modelCatalogItems(input.manifests, { now: input.now });
  const overrides = new Map(input.overrides.map((item) => [item.agentId, item]));
  const selected = new Set(input.specialistAgentIds);
  const extra = [...overrides.keys()].filter((agentId) => !selected.has(agentId));
  if (extra.length > 0) {
    throw new MissionIntakeValidationError([
      `Model assignment overrides name unselected specialists: ${extra.sort().join(", ")}.`,
    ]);
  }
  return [...input.specialistAgentIds]
    .sort((left, right) => left.localeCompare(right))
    .map((agentId) => {
      const ownedActionClassIds = new Set<string>(
        PRODUCT_AGENT_REGISTRY
          .find(({ id }) => id === agentId)
          ?.capabilities.flatMap(({ actionClassIds }) => [...actionClassIds])
          ?? [],
      );
      const required = input.requiredActionClassIds.filter((id) =>
        ownedActionClassIds.has(id));
      const override = overrides.get(agentId);
      if (override) {
        const primary = catalog.find(({ configurationId }) =>
          configurationId === override.primaryConfigurationId);
        const fallback = override.fallbackConfigurationId
          ? catalog.find(({ configurationId }) =>
              configurationId === override.fallbackConfigurationId)
          : undefined;
        if (!primary || (override.fallbackConfigurationId && !fallback)) {
          throw new MissionIntakeValidationError([
            `The model override for ${agentId} is not present in the current live catalog.`,
          ]);
        }
        const reasons = [
          ...autonomousModelCatalogItemReadinessReasons(
            primary,
            agentId,
            required,
          ),
          ...(fallback
            ? autonomousModelCatalogItemReadinessReasons(
                fallback,
                agentId,
                required,
              ).map((reason) => reason.replace(/^The primary /u, "The fallback "))
            : []),
        ];
        if (reasons.length > 0) {
          throw new MissionIntakeValidationError([
            `The model override for ${agentId} is not Autonomous-ready: ${reasons.join(" ")}`,
          ]);
        }
        return { ...override, source: "operator_override" as const };
      }
      const recommendation = catalog.find((item) => {
        const compatibleActionClassIds = new Set(
          item.capabilities.compatibleActionClassIds,
        );
        return item.selectable
          && item.compatibleAgentIds.includes(agentId)
          && required.every((id) => compatibleActionClassIds.has(id))
          && autonomousModelCatalogItemReadinessReasons(
            item,
            agentId,
            required,
          ).length === 0;
      });
      if (!recommendation) {
        throw new MissionIntakeValidationError([
          `No current Autonomous-ready model configuration is available for selected specialist ${agentId}. Connect a healthy enforced provider tool-calling route or an exact available local deterministic tool route for every required action class.`,
        ]);
      }
      return {
        agentId,
        primaryConfigurationId: recommendation.configurationId,
        fallbackConfigurationId: null,
        source: "recommended" as const,
      };
    });
}

export interface MissionIntakeServiceOptions {
  readonly readRuntimeManifests?: () => RuntimeSourceManifests;
  readonly clock?: () => Date;
  readonly modelConfigurations?: Pick<
    ModelConfigurationService,
    "resolveAutonomousAssignments"
  > & Partial<Pick<
    ModelConfigurationService,
    "validateAutonomousPlanningSelection"
  >>;
}

export class MissionIntakeService {
  private readonly readRuntimeManifests: () => RuntimeSourceManifests;
  private readonly clock: () => Date;
  private readonly modelConfigurations?: MissionIntakeServiceOptions["modelConfigurations"];

  constructor(options: MissionIntakeServiceOptions = {}) {
    this.readRuntimeManifests = options.readRuntimeManifests ?? emptyRuntimeSourceManifests;
    this.clock = options.clock ?? (() => new Date());
    this.modelConfigurations = options.modelConfigurations;
  }

  snapshot(journey: "autonomous" | "guided" = "autonomous", templateId: MissionTemplateId = "safe_recon"): IntakeRegistrySnapshot {
    const manifests = this.readRuntimeManifests();
    const projection = buildRuntimeCapabilityProjection(manifests);
    return {
      schemaVersion: "2.4",
      source: {
        status: hasLiveSource(manifests) ? "live" : "unavailable",
        explanation: hasLiveSource(manifests)
          ? "Capability readiness is derived from the current attested runtime manifests."
          : "No attested runtime capability manifest is connected. Definitions remain inspectable, but execution readiness is fail-closed.",
        counts: projection.sourceCounts,
      },
      fields: INTAKE_FIELD_DEFINITIONS,
      actionClasses: buildActionClassRegistry({
        journey,
        presetId: templateId,
        destructivePolicy: "prohibited",
        projection,
      }),
      evidenceTypes: buildEvidenceTypeRegistry(projection),
      deliverables: buildDeliverableRegistry(projection),
      templates: buildMissionTemplateRegistry(projection),
      safeStops: {
        mandatory: MANDATORY_PLATFORM_SAFE_STOPS,
        optional: OPTIONAL_MISSION_SAFE_STOPS,
      },
      budgets: MISSION_BUDGET_PRESETS,
      guidedReconnaissance: buildGuidedReconnaissanceRegistry(manifests),
    };
  }

  resolve(input: MissionIntakeRequest): ResolvedMissionIntake {
    const issues: string[] = [];
    if (input.journey !== "autonomous" && input.journey !== "guided") issues.push("Journey must be Autonomous or Guided.");
    if (input.authorizationAcknowledged !== true) issues.push("Explicit authorization acknowledgement is required.");
    if (issues.length > 0) throw new MissionIntakeValidationError(issues);

    const normalizedTargets = normalizeTargets(input.targets);
    const allowedTargets = normalizedTargets.filter(({ excluded }) => !excluded);
    const prohibitedTargets = normalizedTargets.filter(({ excluded }) => excluded);
    const guidedReconnaissance = parseGuidedReconnaissanceSelection(input.guidedReconnaissance);
    if (guidedReconnaissance.issues.length > 0) {
      throw new MissionIntakeValidationError(guidedReconnaissance.issues);
    }
    if (input.guidedReconnaissance && input.journey !== "guided") {
      throw new MissionIntakeValidationError(["The first represented reconnaissance step is available only in Guided missions."]);
    }
    if (guidedReconnaissance.selection && !["host", "domain"].includes(allowedTargets[0]!.type)) {
      throw new MissionIntakeValidationError([
        "The selected first reconnaissance step requires one host, IP address, or hostname as the first authorized target. Remove the selection to keep target-derived behavior, or supply a host target instead of a URL, CIDR, cloud, file, engagement, or lab reference.",
      ]);
    }
    const templateId = input.templateId ?? "safe_recon";
    const template = templateById(templateId);
    const applied = applyMissionTemplate(template, input.journey, normalizedTargets);
    assertTemplatePreservedTargetScope(normalizedTargets, applied);
    const manifests = this.readRuntimeManifests();
    const projection = buildRuntimeCapabilityProjection(manifests);
    const registeredTemplate = buildMissionTemplateRegistry(projection).templates[template.id];
    const allowedTargetKinds = new Set<"domain" | "ip">(
      allowedTargets.flatMap(({ type, value }) =>
        type === "domain" ? ["domain" as const] : isIP(value) > 0 ? ["ip" as const] : []),
    );
    const defaultAllowedActionClassIds = ACTION_CLASS_IDS.filter((actionClassId) => {
      const capability = AUTONOMOUS_OUTCOME_CAPABILITIES[actionClassId];
      return capability?.targetKinds.some((kind) => allowedTargetKinds.has(kind)) === true;
    });
    const destructivePolicy = input.destructivePolicy ?? "prohibited";
    const boundedDestructiveTargetIds = unique(input.boundedDestructiveTargetIds ?? []);
    const boundedTargetIssues: string[] = [];
    const disposableEnvironment = input.environmentClassification !== undefined
      && DISPOSABLE_ENVIRONMENT_CLASSIFICATIONS.has(input.environmentClassification);
    const explicitlyNonDisposableEnvironment = input.environmentClassification === "client_or_public"
      || input.environmentClassification === "internal";
    if (destructivePolicy === "bounded_lab_only" && boundedDestructiveTargetIds.length === 0) {
      boundedTargetIssues.push("Named disposable lab targets are required for the bounded lab-only destructive policy.");
    }
    if (destructivePolicy !== "bounded_lab_only" && boundedDestructiveTargetIds.length > 0) {
      boundedTargetIssues.push("Bounded destructive targets may be supplied only with the bounded lab-only destructive policy.");
    }
    for (const boundedTargetId of boundedDestructiveTargetIds) {
      const boundedTarget = allowedTargets.find(({ id }) => id === boundedTargetId);
      if (!boundedTarget) {
        boundedTargetIssues.push(`Bounded destructive target ${boundedTargetId} is outside the supplied authorization.`);
      } else if (explicitlyNonDisposableEnvironment) {
        boundedTargetIssues.push(
          `${boundedTarget.value} cannot be bounded for lab-only execution because the mission environment is explicitly classified as non-disposable.`,
        );
      } else if (boundedTarget.type === "host" && !disposableEnvironment) {
        boundedTargetIssues.push(
          `${boundedTarget.value} is an exact host, but the mission environment is not explicitly classified as Hack The Box, CTF, or a local disposable lab.`,
        );
      } else if (boundedTarget.type !== "host" && boundedTarget.type !== "lab_environment") {
        boundedTargetIssues.push(
          `${boundedTarget.value} is not an exact host or disposable lab target. CIDRs, URLs, domains, cloud accounts, scope files, and engagement references cannot be used as bounded destructive targets.`,
        );
      }
    }
    if (boundedTargetIssues.length > 0) throw new MissionIntakeValidationError(boundedTargetIssues);
    const policyMatrix = buildActionClassRegistry({
      journey: input.journey,
      presetId: template.actionPolicyPresetId,
      destructivePolicy,
      projection,
      overrides: input.actionPolicyOverrides,
      ...(input.journey === "autonomous" ? { defaultAllowedActionClassIds } : {}),
      authorizedTargetIds: allowedTargets.map(({ id }) => id),
      boundedDestructiveTargetIds,
    });
    const preAuthorized = ACTION_CLASS_IDS.filter(
      (id) => policyMatrix.classes[id].policyState === "pre_authorized",
    );
    const modelAssignmentActionClassIds = preAuthorized.filter(
      (id) => policyMatrix.classes[id].capability.enforcementReady,
    );
    const inferredOutcomeCapabilities = preAuthorized.flatMap((actionClassId) => {
      const capability = AUTONOMOUS_OUTCOME_CAPABILITIES[actionClassId];
      return capability?.targetKinds.some((kind) => allowedTargetKinds.has(kind))
        ? [capability]
        : [];
    });
    const inferredEvidenceTypeIds = unique(inferredOutcomeCapabilities.flatMap(
      ({ evidenceTypeIds }) => evidenceTypeIds,
    )).filter((evidenceTypeId) =>
      projection.evidenceTypes[evidenceTypeId].availability === "supported");
    const evidenceTypeIds = assertKnownIds(
      input.evidenceTypeIds ?? (input.journey === "autonomous"
        ? inferredEvidenceTypeIds
        : registeredTemplate.recommendedEvidenceTypeIds),
      EVIDENCE_TYPE_IDS,
      "Evidence requirements",
    ) as typeof EVIDENCE_TYPE_IDS[number][];
    const deliverableIds = assertKnownIds(
      input.deliverableIds ?? (input.journey === "autonomous"
        ? registeredTemplate.recommendedDeliverableIds.filter(
            (id) => !registeredTemplate.unavailableDeliverableIds.includes(id),
          )
        : registeredTemplate.recommendedDeliverableIds),
      DELIVERABLE_IDS,
      "Deliverables",
    );
    const optionalSafeStopIds = assertKnownIds(
      input.optionalSafeStopIds ?? template.recommendedOptionalSafeStops,
      OPTIONAL_SAFE_STOP_IDS,
      "Optional safe stops",
    );
    const budgetPresetId: BudgetPresetId = input.budgetPresetId ?? template.budgetPreset;
    const budget: MissionBudgetPreset = missionBudgetPreset(budgetPresetId);
    const now = this.clock();
    const title = text(input.title, "Mission title", 240) ?? boundedTitle(template, allowedTargets[0]!, now);
    const objective = text(input.objective, "Authorized objective")
      ?? `${applied.generatedObjective} Authorized scope: ${allowedTargets.map(({ value }) => value).join(", ")}.`;
    const materialObjectiveRequirements =
      input.journey === "autonomous"
        ? autonomousMaterialObjectiveRequirements(objective)
        : [];
    const materialObjectiveSuccessCriteria =
      autonomousMaterialObjectiveSuccessCriteria(objective);
    const autonomousOutcome = input.journey === "autonomous"
      ? resolveAutonomousOutcomeProfile({
          templateId: template.id,
          objective,
          successCriteria: input.successCriteria,
        })
      : undefined;
    const inferredSuccessCriteria = unique(inferredOutcomeCapabilities.flatMap(
      ({ successCriteria }) => successCriteria,
    ));
    const terminalHtbCriteria = new Set<string>(
      AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
    );
    const defaultSuccessCriteria =
      autonomousOutcome?.id === "complete_engagement"
      ? [
          ...inferredSuccessCriteria.filter((criterion) =>
            !terminalHtbCriteria.has(criterion)),
          ...AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
        ]
      : inferredSuccessCriteria;
    const selectedSuccessCriteria = input.successCriteria && input.successCriteria.length > 0
      ? unique(input.successCriteria)
      : defaultSuccessCriteria.length > 0
        ? defaultSuccessCriteria
        : [...applied.successCriteria];
    const successCriteria = unique([
      ...selectedSuccessCriteria,
      ...materialObjectiveSuccessCriteria,
      ...(autonomousOutcome?.requiredTerminalSuccessCriteria ?? []),
    ]);
    const defaultMemoryScopes = [
      "confirmed_preferences",
      "verified_lessons",
      "confirmed_attack_knowledge",
      "verified_attack_knowledge",
      ...(text(input.engagementId, "Engagement ID", 240) ? ["engagement_memory"] : []),
    ];
    const memoryScopes = input.memoryScopes ? unique(input.memoryScopes) : defaultMemoryScopes;
    const inferredFields = [
      ...(input.title ? [] : ["title"]),
      ...(input.objective ? [] : ["objective"]),
      ...(input.successCriteria?.length
        && materialObjectiveSuccessCriteria.length === 0
        && (autonomousOutcome?.requiredTerminalSuccessCriteria.length ?? 0) === 0
        ? []
        : ["successCriteria"]),
      ...(input.deliverableIds ? [] : ["deliverables"]),
      ...(input.evidenceTypeIds ? [] : ["evidenceRequirements"]),
      ...(input.optionalSafeStopIds ? [] : ["optionalSafeStops"]),
      ...(input.budgetPresetId ? [] : ["budget"]),
      ...(input.specialistAgentIds ? [] : ["specialistAgentIds"]),
      ...(input.journey === "autonomous" && !input.memoryScopes ? ["memoryScopes"] : []),
    ];
    const selectedAgentIds = input.specialistAgentIds
      ? normalizeRequestedProductAgents(unique(input.specialistAgentIds), manifests, preAuthorized)
      : unique(autonomousAgentsForActionClasses(manifests, projection, preAuthorized));
    const signedSpecialistAgentIds = selectedAgentIds
      .filter((id) => SAFE_ID.test(id))
      .sort((left, right) => left.localeCompare(right));
    let agentModelAssignments: readonly AgentModelAssignmentSelection[] = [];
    let planningSelection: AutonomousPlanningSelection =
      AUTONOMOUS_LOCAL_PLANNING_SELECTION;
    if (input.journey === "autonomous") {
      planningSelection =
        input.planningSelection ?? AUTONOMOUS_LOCAL_PLANNING_SELECTION;
      if (planningSelection.route === "provider_advisory") {
        if (!this.modelConfigurations?.validateAutonomousPlanningSelection) {
          throw new MissionIntakeValidationError([
            "Provider-backed plan construction cannot be reviewed because the live planning-model catalog is unavailable. Restore the catalog or use the local deterministic planner.",
          ]);
        }
        try {
          const receipt =
            this.modelConfigurations.validateAutonomousPlanningSelection(
            planningSelection,
          );
          if (!receipt?.ready) {
            throw new MissionIntakeValidationError([
              `The selected provider-backed planning route is not ready: ${
                receipt?.reasons.join(" ").trim()
                || "the exact advisor-only configuration could not be attested"
              }. Choose a current authenticated, healthy advisor-only model with structured output and the exact disclosure class, or use the local deterministic planner.`,
            ]);
          }
        } catch (error) {
          if (error instanceof MissionIntakeValidationError) throw error;
          if (!(error instanceof ModelConfigurationError)) throw error;
          throw new MissionIntakeValidationError([
            `${error.message} ${error.remediation}`,
          ]);
        }
      }
      try {
        agentModelAssignments = this.modelConfigurations
          ? this.modelConfigurations.resolveAutonomousAssignments({
              specialistAgentIds: signedSpecialistAgentIds,
              overrides: input.agentModelAssignments ?? [],
              requiredActionClassIds: modelAssignmentActionClassIds,
            }).selections
          : fallbackAutonomousModelAssignments({
              manifests,
              specialistAgentIds: signedSpecialistAgentIds,
              overrides: input.agentModelAssignments ?? [],
              requiredActionClassIds: modelAssignmentActionClassIds,
              now: this.clock(),
            });
      } catch (error) {
        if (!(error instanceof ModelConfigurationError)) throw error;
        throw new MissionIntakeValidationError([
          `${error.message} ${error.remediation}`,
        ]);
      }
      if (
        signedSpecialistAgentIds.some((agentId) =>
          !(input.agentModelAssignments ?? []).some((item) =>
            item.agentId === agentId))
      ) {
        inferredFields.push("agentModelAssignments");
      }
      if (!input.planningSelection) inferredFields.push("planningSelection");
    }
    const blockedActionLabels = ACTION_CLASS_IDS
      .filter((id) => policyMatrix.classes[id].launchBlockingReasons.length > 0)
      .map((id) => policyMatrix.classes[id].label);
    const missingMaterialObjectiveActionClassIds =
      autonomousMaterialObjectiveActionClassIds(objective)
        .filter((actionClassId) => !preAuthorized.includes(actionClassId));
    const limitations = [
      ...(!hasLiveSource(manifests) ? ["No attested runtime capability manifest is connected; operational launch readiness is unavailable."] : []),
      ...(input.journey === "autonomous" && inferredOutcomeCapabilities.length === 0 ? [
        "No target-compatible reviewed outcome producer is mounted for the supplied target type. The generated draft remains inspectable, but Autonomous preflight must block until an exact executor is connected or the target is narrowed to a supported form.",
      ] : []),
      ...(blockedActionLabels.length > 0 ? [
        `Autonomous execution is not ready for ${blockedActionLabels.length} contract action classes: ${blockedActionLabels.join(", ")}. Connect compatible specialists, tools, and locally enforced provider paths, or change those classes to Guided only or Prohibited. Exact class-level reasons remain in the Action-class policy matrix.`,
      ] : []),
      ...(missingMaterialObjectiveActionClassIds.length > 0 ? [
        `The authorized objective explicitly requests ${materialObjectiveRequirements.map(({ label }) => label).join(", ")}, so Ti-Scale added the matching evidence-backed success criteria. Launch remains blocked because the signed action policy does not pre-authorize: ${missingMaterialObjectiveActionClassIds.join(", ")}. Select a reviewed capable contract or narrow the objective; Ti-Scale will not silently reduce this mission to reconnaissance.`,
      ] : []),
    ];

    if (input.journey === "guided") {
      if (allowedTargets.length > 1) {
        limitations.push("The current Guided execution contract represents the first supplied target; remaining targets stay visible for a future versioned scope amendment.");
      }
      return {
        schemaVersion: "2.4",
        request: {
          journey: "guided",
          launch: true,
          authorizationConfirmed: true,
          title,
          objective,
          target: allowedTargets[0]!.value,
          ...(text(input.engagementId, "Engagement ID", 240) ? { engagementId: text(input.engagementId, "Engagement ID", 240) } : {}),
          explanationDepth: input.explanationDepth ?? "balanced",
          executionPreference: input.executionPreference ?? "manual",
          evidenceExpectations: evidenceTypeIds,
          ...(guidedReconnaissance.selection ? { guidedReconnaissance: guidedReconnaissance.selection } : {}),
        },
        normalizedTargets,
        template: { id: template.id, version: template.version },
        policyMatrix,
        evidenceTypeIds,
        deliverableIds,
        mandatorySafeStopIds: MANDATORY_PLATFORM_SAFE_STOPS.map(({ id }) => id),
        optionalSafeStopIds,
        budget,
        inferredFields,
        limitations,
      };
    }

    const prohibited = ACTION_CLASS_IDS.filter((id) => policyMatrix.classes[id].policyState !== "pre_authorized");
    return {
      schemaVersion: "2.4",
      autonomousOutcome,
      request: {
        journey: "autonomous",
        launch: true,
        title,
        objective,
        successCriteria,
        authorization: {
          ...(text(input.engagementId, "Engagement ID", 240) ? { engagementId: text(input.engagementId, "Engagement ID", 240) } : {}),
          ...(input.environmentClassification ? {
            environmentClassification: input.environmentClassification,
          } : {}),
          allowedTargets: allowedTargets.map(({ value }) => value),
          prohibitedTargets: prohibitedTargets.map(({ value }) => value),
          authorizationConfirmed: true,
        },
        contract: {
          outcomeProfile: autonomousOutcome!.id,
          allowedActionClasses: preAuthorized,
          prohibitedActionClasses: prohibited,
          destructivePolicy,
          boundedDestructiveTargets: boundedDestructiveTargetIds.flatMap((targetId) => {
            const target = allowedTargets.find(({ id }) => id === targetId);
            return target ? [target.value] : [];
          }),
          evidenceRequirements: evidenceTypeIds,
          timeBudgetMinutes: budget.timeBudgetMinutes,
          toolCallBudget: budget.toolCallBudget,
          tokenBudget: budget.tokenBudget,
          costBudget: budget.estimatedCostBudget,
          retryBudget: budget.retryBudget,
          replanBudget: budget.replanBudget,
          concurrencyLimit: budget.concurrencyLimit,
          evidenceStorageBudgetBytes: budget.evidenceStorageBudgetBytes,
          artifactStorageBudgetBytes: budget.artifactStorageBudgetBytes,
          notificationPolicy: "in_app_only",
          reportingFormat: "ti_scale_json",
          dataHandlingPolicy: "local_private",
          retentionPolicy: "operator_managed",
          providerPolicy: "automatic_enforcing_only",
          toolPolicy: "contract_allowlist",
          specialistAgentIds: signedSpecialistAgentIds,
          agentModelAssignments,
          planningSelection,
          memoryScopes,
          contextNodeIds: input.contextNodeIds ? unique(input.contextNodeIds) : [],
          safeStopConditions: optionalSafeStopIds,
          deliverables: deliverableIds,
        },
      },
      normalizedTargets,
      template: { id: template.id, version: template.version },
      policyMatrix,
      evidenceTypeIds,
      deliverableIds,
      mandatorySafeStopIds: MANDATORY_PLATFORM_SAFE_STOPS.map(({ id }) => id),
      optionalSafeStopIds,
      budget,
      inferredFields,
      limitations,
    };
  }
}

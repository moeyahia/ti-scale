import { createHash } from "node:crypto";
import { isIP } from "node:net";
import {
  ACTION_CLASS_IDS,
  DELIVERABLE_IDS,
  EVIDENCE_TYPE_IDS,
  MANDATORY_PLATFORM_SAFE_STOPS,
  MISSION_BUDGET_PRESETS,
  MISSION_TEMPLATES,
  OPTIONAL_MISSION_SAFE_STOPS,
  OPTIONAL_SAFE_STOP_IDS,
  applyMissionTemplate,
  assertTemplatePreservedTargetScope,
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
  type RuntimeSourceManifests,
} from "../domain";
import type {
  IntakeFieldDefinition,
  IntakeRegistrySnapshot,
  MissionIntakeRequest,
  MissionIntakeTargetInput,
  ResolvedMissionIntake,
} from "./types";

const MAX_TARGETS = 250;
const MAX_TEXT = 20_000;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;

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

function unique(values: readonly string[]): string[] {
  const seen = new Set<string>();
  return values.flatMap((value) => {
    const normalized = value.trim();
    const key = normalized.toLocaleLowerCase("en-US");
    if (!normalized || seen.has(key)) return [];
    seen.add(key);
    return [normalized];
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

export interface MissionIntakeServiceOptions {
  readonly readRuntimeManifests?: () => RuntimeSourceManifests;
  readonly clock?: () => Date;
}

export class MissionIntakeService {
  private readonly readRuntimeManifests: () => RuntimeSourceManifests;
  private readonly clock: () => Date;

  constructor(options: MissionIntakeServiceOptions = {}) {
    this.readRuntimeManifests = options.readRuntimeManifests ?? emptyRuntimeSourceManifests;
    this.clock = options.clock ?? (() => new Date());
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
    const templateId = input.templateId ?? "safe_recon";
    const template = templateById(templateId);
    const applied = applyMissionTemplate(template, input.journey, normalizedTargets);
    assertTemplatePreservedTargetScope(normalizedTargets, applied);
    const manifests = this.readRuntimeManifests();
    const projection = buildRuntimeCapabilityProjection(manifests);
    const registeredTemplate = buildMissionTemplateRegistry(projection).templates[template.id];
    const destructivePolicy = input.destructivePolicy ?? "prohibited";
    const boundedDestructiveTargetIds = unique(input.boundedDestructiveTargetIds ?? []);
    const boundedTargetIssues: string[] = [];
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
      } else if (boundedTarget.type !== "lab_environment") {
        boundedTargetIssues.push(`${boundedTarget.value} is not classified as a disposable lab environment.`);
      }
    }
    if (boundedTargetIssues.length > 0) throw new MissionIntakeValidationError(boundedTargetIssues);
    const policyMatrix = buildActionClassRegistry({
      journey: input.journey,
      presetId: template.actionPolicyPresetId,
      destructivePolicy,
      projection,
      overrides: input.actionPolicyOverrides,
      authorizedTargetIds: allowedTargets.map(({ id }) => id),
      boundedDestructiveTargetIds,
    });
    const evidenceTypeIds = assertKnownIds(
      input.evidenceTypeIds ?? registeredTemplate.recommendedEvidenceTypeIds,
      EVIDENCE_TYPE_IDS,
      "Evidence requirements",
    ) as typeof EVIDENCE_TYPE_IDS[number][];
    const deliverableIds = assertKnownIds(
      input.deliverableIds ?? template.recommendedDeliverableIds,
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
    const successCriteria = input.successCriteria && input.successCriteria.length > 0
      ? unique(input.successCriteria)
      : [...applied.successCriteria];
    const defaultMemoryScopes = [
      "confirmed_preferences",
      "verified_lessons",
      ...(text(input.engagementId, "Engagement ID", 240) ? ["engagement_memory"] : []),
    ];
    const memoryScopes = input.memoryScopes ? unique(input.memoryScopes) : defaultMemoryScopes;
    const inferredFields = [
      ...(input.title ? [] : ["title"]),
      ...(input.objective ? [] : ["objective"]),
      ...(input.successCriteria?.length ? [] : ["successCriteria"]),
      ...(input.deliverableIds ? [] : ["deliverables"]),
      ...(input.evidenceTypeIds ? [] : ["evidenceRequirements"]),
      ...(input.optionalSafeStopIds ? [] : ["optionalSafeStops"]),
      ...(input.budgetPresetId ? [] : ["budget"]),
      ...(input.specialistAgentIds ? [] : ["specialistAgentIds"]),
      ...(input.journey === "autonomous" && !input.memoryScopes ? ["memoryScopes"] : []),
    ];
    const selectedAgentIds = input.specialistAgentIds
      ? unique(input.specialistAgentIds)
      : unique(ACTION_CLASS_IDS.flatMap((id) =>
          policyMatrix.classes[id].policyState === "pre_authorized"
            ? policyMatrix.classes[id].capability.availableAgentIds
            : []));
    const blockedActionLabels = ACTION_CLASS_IDS
      .filter((id) => policyMatrix.classes[id].launchBlockingReasons.length > 0)
      .map((id) => policyMatrix.classes[id].label);
    const limitations = [
      ...(!hasLiveSource(manifests) ? ["No attested runtime capability manifest is connected; operational launch readiness is unavailable."] : []),
      ...(blockedActionLabels.length > 0 ? [
        `Autonomous execution is not ready for ${blockedActionLabels.length} contract action classes: ${blockedActionLabels.join(", ")}. Connect compatible specialists, tools, and locally enforced provider paths, or change those classes to Guided only or Prohibited. Exact class-level reasons remain in the Action-class policy matrix.`,
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

    const preAuthorized = ACTION_CLASS_IDS.filter((id) => policyMatrix.classes[id].policyState === "pre_authorized");
    const prohibited = ACTION_CLASS_IDS.filter((id) => policyMatrix.classes[id].policyState !== "pre_authorized");
    return {
      schemaVersion: "2.4",
      request: {
        journey: "autonomous",
        launch: true,
        title,
        objective,
        successCriteria,
        authorization: {
          ...(text(input.engagementId, "Engagement ID", 240) ? { engagementId: text(input.engagementId, "Engagement ID", 240) } : {}),
          allowedTargets: allowedTargets.map(({ value }) => value),
          prohibitedTargets: prohibitedTargets.map(({ value }) => value),
          authorizationConfirmed: true,
        },
        contract: {
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
          specialistAgentIds: selectedAgentIds.filter((id) => SAFE_ID.test(id)),
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

import type {
  ModelAuthState,
  ModelAssignmentSemantics,
  ModelCatalog,
  ModelCatalogItem,
  ModelConfiguration,
  ModelConfigurationPage,
  ModelEnforcementMode,
  ModelExecutionBoundary,
  ModelHealthState,
  ModelPreference,
  ModelPreferenceMutation,
  ModelPreferencePage,
  ModelPreferenceScope,
  ModelResolutionResult,
} from "../types/modelConfiguration";
import {
  array,
  boolean,
  nonEmpty,
  nullableNumber,
  nullableString,
  number,
  object,
  schema,
  stringList,
} from "./common";

function oneOf<T extends string>(value: unknown, allowed: readonly T[], label: string): T {
  const result = nonEmpty(value, label);
  if (!allowed.includes(result as T)) throw new Error(`${label} is invalid`);
  return result as T;
}

const enforcementModes = [
  "enforced_executor",
  "observe_only_executor",
  "advisor_only",
  "unavailable",
] as const;
const authStates = ["authenticated", "unconfigured", "invalid", "unknown"] as const;
const healthStates = ["healthy", "degraded", "unavailable", "unknown"] as const;
const executionBoundaries = [
  "provider_tool_calling",
  "local_deterministic_policy",
] as const;
const scopes = ["global", "agent", "mission", "run", "step"] as const;

function assignmentSemantics(value: unknown): ModelAssignmentSemantics {
  const item = object(value, "model resolution.assignmentSemantics");
  return {
    purpose: oneOf(
      item.purpose,
      ["execution"] as const,
      "model resolution assignment purpose",
    ),
    preferenceResolutionOrder: oneOf(
      item.preferenceResolutionOrder,
      ["global_then_agent_then_mission_then_run_then_step"] as const,
      "model resolution preference order",
    ),
    saveEffect: oneOf(
      item.saveEffect,
      ["future_resolutions_only"] as const,
      "model resolution save effect",
    ),
    activeRunPinning: oneOf(
      item.activeRunPinning,
      ["immutable"] as const,
      "model resolution active-run pinning",
    ),
    planningRoute: oneOf(
      item.planningRoute,
      ["autonomous_mission_contract"] as const,
      "model resolution planning route",
    ),
  };
}

function enforcementMode(value: unknown): ModelEnforcementMode {
  return oneOf(value, enforcementModes, "model enforcementMode");
}

function authState(value: unknown): ModelAuthState {
  return oneOf(value, authStates, "model authState");
}

function healthState(value: unknown): ModelHealthState {
  return oneOf(value, healthStates, "model healthState");
}

function executionBoundary(value: unknown): ModelExecutionBoundary {
  return oneOf(value, executionBoundaries, "model executionBoundary");
}

function actionClassIdsByAgent(
  value: unknown,
  label: string,
): Readonly<Record<string, readonly string[]>> {
  const entries = object(value, label);
  return Object.fromEntries(Object.entries(entries).map(([agentId, actionClassIds]) => [
    nonEmpty(agentId, `${label} agent ID`),
    stringList(actionClassIds, `${label}.${agentId}`),
  ]));
}

function scope(value: unknown): ModelPreferenceScope {
  return oneOf(value, scopes, "model preference scopeType");
}

function positiveIntegerOrNull(value: unknown, label: string): number | null {
  const result = nullableNumber(value, label);
  if (result !== null && (!Number.isSafeInteger(result) || result < 1)) {
    throw new Error(`${label} must be a positive whole number or null`);
  }
  return result;
}

function catalogItem(value: unknown, index: number): ModelCatalogItem {
  const item = object(value, `model catalog item ${index}`);
  const capabilities = object(item.capabilities, `model catalog item ${index}.capabilities`);
  return {
    configurationId: nonEmpty(item.configurationId, "model catalog configurationId"),
    providerId: nonEmpty(item.providerId, "model catalog providerId"),
    modelId: nonEmpty(item.modelId, "model catalog modelId"),
    displayName: nonEmpty(item.displayName, "model catalog displayName"),
    executionBoundary: executionBoundary(item.executionBoundary),
    reasoningEffort: nullableString(item.reasoningEffort, "model catalog reasoningEffort"),
    supportedReasoningEfforts: stringList(
      item.supportedReasoningEfforts,
      "model catalog supportedReasoningEfforts",
    ),
    contextLimit: positiveIntegerOrNull(item.contextLimit, "model catalog contextLimit"),
    costClass: nonEmpty(item.costClass, "model catalog costClass"),
    latencyClass: nonEmpty(item.latencyClass, "model catalog latencyClass"),
    disclosureClass: nonEmpty(item.disclosureClass, "model catalog disclosureClass"),
    enforcementMode: enforcementMode(item.enforcementMode),
    authState: authState(item.authState),
    healthState: healthState(item.healthState),
    catalogSource: nonEmpty(item.catalogSource, "model catalog catalogSource"),
    catalogRetrievedAt: nullableString(
      item.catalogRetrievedAt,
      "model catalog catalogRetrievedAt",
    ),
    capabilities: {
      toolCalling: boolean(capabilities.toolCalling, "model catalog toolCalling"),
      structuredOutput: boolean(
        capabilities.structuredOutput,
        "model catalog structuredOutput",
      ),
      compatibleActionClassIds: stringList(
        capabilities.compatibleActionClassIds,
        "model catalog compatibleActionClassIds",
      ),
      localDeterministicActionClassIdsByAgent: actionClassIdsByAgent(
        capabilities.localDeterministicActionClassIdsByAgent,
        "model catalog localDeterministicActionClassIdsByAgent",
      ),
    },
    compatibleAgentIds: stringList(
      item.compatibleAgentIds,
      "model catalog compatibleAgentIds",
    ),
    selectable: boolean(item.selectable, "model catalog selectable"),
    unavailableReasons: stringList(
      item.unavailableReasons,
      "model catalog unavailableReasons",
    ),
  };
}

export function parseModelCatalog(payload: unknown): ModelCatalog {
  const root = object(payload, "model catalog");
  schema(root);
  return {
    schemaVersion: "2.4",
    observedAt: nonEmpty(root.observedAt, "model catalog observedAt"),
    items: array(root.items, "model catalog items").map(catalogItem),
  };
}

function configuration(value: unknown, label = "model configuration"): ModelConfiguration {
  const item = object(value, label);
  const version = number(item.version, `${label}.version`);
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new Error(`${label}.version must be a positive whole number`);
  }
  return {
    id: nonEmpty(item.id, `${label}.id`),
    providerId: nonEmpty(item.providerId, `${label}.providerId`),
    modelId: nonEmpty(item.modelId, `${label}.modelId`),
    displayName: nonEmpty(item.displayName, `${label}.displayName`),
    executionBoundary: executionBoundary(item.executionBoundary),
    reasoningEffort: nullableString(item.reasoningEffort, `${label}.reasoningEffort`),
    contextPolicy: object(item.contextPolicy, `${label}.contextPolicy`),
    capabilities: object(item.capabilities, `${label}.capabilities`),
    contextLimit: positiveIntegerOrNull(item.contextLimit, `${label}.contextLimit`),
    costClass: nonEmpty(item.costClass, `${label}.costClass`),
    latencyClass: nonEmpty(item.latencyClass, `${label}.latencyClass`),
    disclosureClass: nonEmpty(item.disclosureClass, `${label}.disclosureClass`),
    enforcementMode: enforcementMode(item.enforcementMode),
    authState: authState(item.authState),
    healthState: healthState(item.healthState),
    catalogSource: nonEmpty(item.catalogSource, `${label}.catalogSource`),
    catalogRetrievedAt: nullableString(
      item.catalogRetrievedAt,
      `${label}.catalogRetrievedAt`,
    ),
    configurationSource: nonEmpty(
      item.configurationSource,
      `${label}.configurationSource`,
    ),
    version,
    createdAt: nonEmpty(item.createdAt, `${label}.createdAt`),
    updatedAt: nonEmpty(item.updatedAt, `${label}.updatedAt`),
  };
}

export function parseModelConfigurations(payload: unknown): ModelConfigurationPage {
  const root = object(payload, "model configurations");
  schema(root);
  return {
    schemaVersion: "2.4",
    items: array(root.items, "model configurations.items").map((item, index) => (
      configuration(item, `model configurations.items[${index}]`)
    )),
  };
}

function preference(value: unknown, label = "model preference"): ModelPreference {
  const item = object(value, label);
  const version = number(item.version, `${label}.version`);
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new Error(`${label}.version must be a positive whole number`);
  }
  return {
    id: nonEmpty(item.id, `${label}.id`),
    scopeType: scope(item.scopeType),
    scopeId: nonEmpty(item.scopeId, `${label}.scopeId`),
    agentId: nullableString(item.agentId, `${label}.agentId`),
    primaryConfigurationId: nonEmpty(
      item.primaryConfigurationId,
      `${label}.primaryConfigurationId`,
    ),
    fallbackConfigurationId: nullableString(
      item.fallbackConfigurationId,
      `${label}.fallbackConfigurationId`,
    ),
    resolutionReason: nonEmpty(
      item.resolutionReason,
      `${label}.resolutionReason`,
    ),
    version,
    createdBy: nonEmpty(item.createdBy, `${label}.createdBy`),
    createdAt: nonEmpty(item.createdAt, `${label}.createdAt`),
    updatedBy: nonEmpty(item.updatedBy, `${label}.updatedBy`),
    updatedAt: nonEmpty(item.updatedAt, `${label}.updatedAt`),
  };
}

export function parseModelPreferences(payload: unknown): ModelPreferencePage {
  const root = object(payload, "model preferences");
  schema(root);
  return {
    schemaVersion: "2.4",
    items: array(root.items, "model preferences.items").map((item, index) => (
      preference(item, `model preferences.items[${index}]`)
    )),
  };
}

export function parseModelPreferenceMutation(payload: unknown): ModelPreferenceMutation {
  const root = object(payload, "model preference mutation");
  schema(root);
  return {
    schemaVersion: "2.4",
    preference: preference(root.preference),
  };
}

export function parseModelResolution(payload: unknown): ModelResolutionResult {
  const root = object(payload, "model resolution");
  schema(root);
  const semantics = assignmentSemantics(root.assignmentSemantics);
  const availabilityValue = object(
    root.availability,
    "model resolution.availability",
  );
  const availability = {
    status: oneOf(
      availabilityValue.status,
      ["configured", "unconfigured"] as const,
      "model resolution availability status",
    ),
    agentId: nonEmpty(
      availabilityValue.agentId,
      "model resolution availability agentId",
    ),
    humanMessage: nonEmpty(
      availabilityValue.humanMessage,
      "model resolution availability humanMessage",
    ),
    remediation: nullableString(
      availabilityValue.remediation,
      "model resolution availability remediation",
    ),
  };
  if (root.resolution === null) {
    if (availability.status !== "unconfigured") {
      throw new Error(
        "model resolution availability must be unconfigured when resolution is null",
      );
    }
    return {
      schemaVersion: "2.4",
      assignmentSemantics: semantics,
      resolution: null,
      availability,
    };
  }
  if (availability.status !== "configured") {
    throw new Error(
      "model resolution availability must be configured when resolution is present",
    );
  }
  const resolution = object(root.resolution, "model resolution.resolution");
  const context = object(resolution.context, "model resolution.context");
  const source = object(resolution.source, "model resolution.source");
  const sourceVersion = number(
    source.preferenceVersion,
    "model resolution source preferenceVersion",
  );
  if (!Number.isSafeInteger(sourceVersion) || sourceVersion < 1) {
    throw new Error("model resolution source preferenceVersion must be positive");
  }
  return {
    schemaVersion: "2.4",
    assignmentSemantics: semantics,
    availability,
    resolution: {
      agentId: nonEmpty(resolution.agentId, "model resolution agentId"),
      context: {
        missionId: nullableString(context.missionId, "model resolution missionId"),
        runId: nullableString(context.runId, "model resolution runId"),
        stepId: nullableString(context.stepId, "model resolution stepId"),
      },
      source: {
        scopeType: scope(source.scopeType),
        scopeId: nonEmpty(source.scopeId, "model resolution source scopeId"),
        preferenceId: nonEmpty(
          source.preferenceId,
          "model resolution source preferenceId",
        ),
        preferenceVersion: sourceVersion,
      },
      primaryConfiguration: configuration(
        resolution.primaryConfiguration,
        "model resolution primaryConfiguration",
      ),
      fallbackConfiguration: resolution.fallbackConfiguration === null
        ? null
        : configuration(
            resolution.fallbackConfiguration,
            "model resolution fallbackConfiguration",
          ),
      resolvedAt: nonEmpty(resolution.resolvedAt, "model resolution resolvedAt"),
    },
  };
}

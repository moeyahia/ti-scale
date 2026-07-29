import { createHash } from "node:crypto";
import {
  buildRuntimeCapabilityProjection,
  type RuntimeProviderModelManifest,
  type RuntimeSourceManifests,
} from "../domain";
import { productAgentIdsForRuntimeManifestAgent } from "../agents";
import {
  invalidModelConfiguration,
  ModelConfigurationError,
  modelConfigurationNotFound,
  modelConfigurationPolicyDenied,
  modelConfigurationScopeConflict,
  modelConfigurationUnavailable,
} from "./ModelConfigurationError";
import { ModelConfigurationRepository } from "./ModelConfigurationRepository";
import type {
  AgentModelAssignmentBatch,
  AgentModelAssignmentReceipt,
  AgentModelAssignmentSelection,
  AgentModelAssignmentSource,
  AutonomousPlanningSelection,
  ModelCatalogItem,
  ModelConfigurationServiceDependencies,
  ModelAssignmentPurpose,
  ModelPreferenceFilters,
  ModelResolution,
  PinModelAssignmentInput,
  PinnedModelAssignment,
  PinnedModelAssignmentReadback,
  PutModelPreferenceInput,
  StoredModelConfiguration,
} from "./types";
import {
  COMMANDER_AGENT_ID,
  PRODUCT_AGENT_IDS,
  PRODUCT_AGENT_REGISTRY,
} from "../agents";

export const DEFAULT_MODEL_CATALOG_MAXIMUM_AGE_MS = 15 * 60 * 1_000;
export const DEFAULT_MODEL_CATALOG_MAXIMUM_FUTURE_SKEW_MS = 5 * 1_000;

function sorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function disclosureClass(
  values: readonly string[],
): ModelCatalogItem["disclosureClass"] {
  const normalized = new Set(values.map((value) => value.toLowerCase()));
  if (normalized.size === 0) return "unavailable";
  if (
    [...normalized].every((value) =>
      value === "local" || value === "local_only")
  ) return "local_only";
  if (
    normalized.has("internal")
    || normalized.has("sanitized_internal")
    || normalized.has("private")
    || normalized.has("restricted")
  ) return "sanitized_internal";
  return "public_only";
}

function localDeterministicCoverage(
  manifests: RuntimeSourceManifests,
  providerId: string,
  modelId: string,
  now: Date,
): Readonly<Record<string, readonly string[]>> {
  const projection = buildRuntimeCapabilityProjection(manifests, now);
  const coverage = new Map<string, Set<string>>();
  const mcpById = new Map(manifests.mcpServers.map((server) => [
    server.id,
    server,
  ]));
  const toolsById = new Map(manifests.tools.map((tool) => [tool.id, tool]));
  for (const agent of manifests.agents) {
    if (
      !agent.available
      || !agent.modelRefs.some((reference) =>
        reference.providerId === providerId && reference.modelId === modelId)
    ) continue;
    const productAgentIds = productAgentIdsForRuntimeManifestAgent(
      agent,
      manifests,
    );
    if (productAgentIds.length === 0) continue;
    const actionClassIds = agent.toolIds.flatMap((toolId) => {
      const tool = toolsById.get(toolId);
      if (
        !tool
        || tool.available !== true
        || tool.locallyPolicyEnforced !== true
        || tool.requiresModel !== false
        || !tool.executionJourneys?.includes("autonomous")
        || !(tool.dependencies ?? []).every(({ ready }) => ready)
      ) return [];
      if (tool.mcpServerId) {
        const server = mcpById.get(tool.mcpServerId);
        if (server?.status !== "healthy" || !server.toolIds.includes(tool.id)) {
          return [];
        }
      }
      return tool.actionClassIds.filter((actionClassId) => {
        const mapping = projection.actionClasses[
          actionClassId as keyof typeof projection.actionClasses
        ];
        return mapping?.enforcementReady === true
          && mapping.availableAgentIds.includes(agent.id)
          && mapping.availableToolIds.includes(tool.id);
      });
    });
    for (const productAgentId of productAgentIds) {
      const current = coverage.get(productAgentId) ?? new Set<string>();
      for (const actionClassId of actionClassIds) current.add(actionClassId);
      coverage.set(productAgentId, current);
    }
  }
  return Object.freeze(Object.fromEntries(
    [...coverage.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([agentId, actionClassIds]) => [
        agentId,
        Object.freeze(sorted([...actionClassIds])),
      ]),
  ));
}

function configurationId(value: Readonly<Record<string, unknown>>): string {
  const hash = createHash("sha256")
    .update(JSON.stringify(value))
    .digest("hex");
  return `modelcfg_${hash.slice(0, 40)}`;
}

function catalogOptions(
  manifests: RuntimeSourceManifests,
  freshness?: Readonly<{
    nowMs: number;
    maximumAgeMs: number;
    maximumFutureSkewMs: number;
  }>,
): ModelCatalogItem[] {
  const observedAt = new Date(freshness?.nowMs ?? Date.now());
  const agentRefs = new Map<string, string[]>();
  for (const agent of manifests.agents) {
    const productAgentIds = productAgentIdsForRuntimeManifestAgent(
      agent,
      manifests,
    );
    for (const reference of agent.modelRefs) {
      const key = `${reference.providerId}\u0000${reference.modelId}`;
      agentRefs.set(key, [
        ...(agentRefs.get(key) ?? []),
        ...productAgentIds,
      ]);
    }
  }

  const items: ModelCatalogItem[] = [];
  for (const provider of manifests.providers) {
    for (const model of provider.models) {
      const supportedReasoningEfforts = sorted(model.reasoningEfforts ?? []);
      const reasoningOptions: readonly (string | null)[] = [
        null,
        ...supportedReasoningEfforts,
      ];
      for (const reasoningEffort of reasoningOptions) {
        const unavailableReasons: string[] = [];
        const executionBoundary = model.executionBoundary
          ?? "provider_tool_calling";
        const deterministicCoverage:
          Readonly<Record<string, readonly string[]>> =
          executionBoundary === "local_deterministic_policy"
            ? localDeterministicCoverage(
                manifests,
                provider.id,
                model.id,
                observedAt,
              )
            : Object.freeze({});
        if (!provider.authenticated) {
          unavailableReasons.push("Provider authentication is unavailable.");
        }
        if (!provider.healthy) {
          unavailableReasons.push("Provider health check is failing.");
        }
        const timestampValid = Number.isFinite(Date.parse(provider.catalogObservedAt));
        const catalogRetrievedAt = timestampValid
          ? new Date(provider.catalogObservedAt).toISOString()
          : null;
        if (!timestampValid) {
          unavailableReasons.push("The provider catalog attestation timestamp is invalid.");
        } else if (freshness) {
          const observedAt = Date.parse(provider.catalogObservedAt);
          if (observedAt < freshness.nowMs - freshness.maximumAgeMs) {
            unavailableReasons.push(
              `The provider catalog attestation is older than the ${freshness.maximumAgeMs} ms maximum age.`,
            );
          }
          if (observedAt > freshness.nowMs + freshness.maximumFutureSkewMs) {
            unavailableReasons.push(
              `The provider catalog attestation is more than ${freshness.maximumFutureSkewMs} ms in the future.`,
            );
          }
        }
        const compatibleAgentIds = sorted(
          agentRefs.get(`${provider.id}\u0000${model.id}`) ?? [],
        );
        if (compatibleAgentIds.length === 0) {
          unavailableReasons.push("No live agent declares this provider/model binding.");
        }
        if (
          executionBoundary === "local_deterministic_policy"
          && !Object.values(deterministicCoverage).some(
            (actionClassIds) => actionClassIds.length > 0,
          )
        ) {
          unavailableReasons.push(
            "No exact available Autonomous local-policy tool binding substantiates the declared local deterministic execution boundary.",
          );
        }
        // The catalog attestation and provider readiness are part of the
        // immutable snapshot identity. A renewed attestation must materialize
        // a new row; reusing the capability-only ID would strand the original
        // row's stale catalog_retrieved_at forever or require mutating a pin.
        const identity = {
          providerId: provider.id,
          modelId: model.id,
          displayName: model.displayName,
          executionBoundary,
          reasoningEffort,
          providerAuthenticated: provider.authenticated,
          providerHealthy: provider.healthy,
          toolCalling: model.toolCalling,
          structuredOutput: model.structuredOutput,
          enforcement: model.enforcement,
          compatibleActionClassIds: sorted(model.compatibleActionClassIds),
          disclosureClasses: sorted(model.disclosureClasses),
          contextLimit: model.contextLimit ?? null,
          supportedReasoningEfforts,
          compatibleAgentIds,
          localDeterministicActionClassIdsByAgent: deterministicCoverage,
          catalogSource: "runtime-source-manifest",
          catalogRetrievedAt,
        };
        items.push({
          configurationId: configurationId(identity),
          providerId: provider.id,
          modelId: model.id,
          displayName: model.displayName,
          executionBoundary,
          reasoningEffort,
          supportedReasoningEfforts,
          contextLimit: model.contextLimit ?? null,
          costClass: "unknown",
          latencyClass: "unknown",
          disclosureClass: disclosureClass(model.disclosureClasses),
          enforcementMode: !provider.authenticated || !provider.healthy
            ? "unavailable"
            : model.enforcement,
          authState: provider.authenticated ? "authenticated" : "unconfigured",
          healthState: provider.healthy ? "healthy" : "unavailable",
          catalogSource: "runtime-source-manifest",
          catalogRetrievedAt,
          capabilities: {
            toolCalling: model.toolCalling,
            structuredOutput: model.structuredOutput,
            compatibleActionClassIds: sorted(model.compatibleActionClassIds),
            localDeterministicActionClassIdsByAgent: deterministicCoverage,
          },
          compatibleAgentIds,
          selectable: unavailableReasons.length === 0,
          unavailableReasons,
        });
      }
    }
  }
  return items.sort((left, right) =>
    left.providerId.localeCompare(right.providerId)
    || left.displayName.localeCompare(right.displayName)
    || left.modelId.localeCompare(right.modelId)
    || (left.reasoningEffort ?? "").localeCompare(right.reasoningEffort ?? "")
    || left.configurationId.localeCompare(right.configurationId));
}

function catalogObservedAt(
  manifests: RuntimeSourceManifests,
  fallback: string,
): string {
  const timestamps = manifests.providers
    .map(({ catalogObservedAt: value }) => value)
    .filter((value) => Number.isFinite(Date.parse(value)))
    .sort((left, right) => Date.parse(right) - Date.parse(left));
  return timestamps[0] ?? fallback;
}

function configurationCompatibleWithAgent(
  value: StoredModelConfiguration,
  agentId: string,
): boolean {
  const compatibleAgentIds = value.capabilities.compatibleAgentIds;
  return Array.isArray(compatibleAgentIds)
    && compatibleAgentIds.every((item) => typeof item === "string")
    && compatibleAgentIds.includes(agentId);
}

function missingWorkspaceSpecialistAgentIds(
  value: Pick<ModelCatalogItem, "compatibleAgentIds">,
): string[] {
  return PRODUCT_AGENT_REGISTRY
    .map(({ id }) => id)
    .filter((agentId) => !value.compatibleAgentIds.includes(agentId))
    .sort((left, right) => left.localeCompare(right));
}

function orderedSelections(
  values: readonly AgentModelAssignmentSelection[],
): AgentModelAssignmentSelection[] {
  return [...values].sort((left, right) =>
    left.agentId.localeCompare(right.agentId));
}

function requiredActionClassesForAgent(
  agentId: string,
  requiredActionClassIds: readonly string[],
): string[] {
  const owned = new Set<string>(
    PRODUCT_AGENT_REGISTRY
      .find(({ id }) => id === agentId)
      ?.capabilities.flatMap(({ actionClassIds }) => [...actionClassIds]) ?? [],
  );
  return sorted(requiredActionClassIds.filter((id) => owned.has(id)));
}

function receiptConfiguration(
  item: ModelCatalogItem,
): AgentModelAssignmentReceipt["primary"] {
  return {
    configurationId: item.configurationId,
    providerId: item.providerId,
    modelId: item.modelId,
    displayName: item.displayName,
    executionBoundary: item.executionBoundary,
    reasoningEffort: item.reasoningEffort,
    enforcementMode: item.enforcementMode,
    authState: item.authState,
    healthState: item.healthState,
    disclosureClass: item.disclosureClass,
    costClass: item.costClass,
    latencyClass: item.latencyClass,
    contextLimit: item.contextLimit,
    catalogSource: item.catalogSource,
    catalogRetrievedAt: item.catalogRetrievedAt,
  };
}

function storedReceiptConfiguration(
  item: StoredModelConfiguration,
): AgentModelAssignmentReceipt["primary"] {
  return {
    configurationId: item.id,
    providerId: item.providerId,
    modelId: item.modelId,
    displayName: item.displayName,
    executionBoundary: item.executionBoundary,
    reasoningEffort: item.reasoningEffort,
    enforcementMode: item.enforcementMode,
    authState: item.authState,
    healthState: item.healthState,
    disclosureClass: item.disclosureClass,
    costClass: item.costClass,
    latencyClass: item.latencyClass,
    contextLimit: item.contextLimit,
    catalogSource: item.catalogSource,
    catalogRetrievedAt: item.catalogRetrievedAt,
  };
}

function itemReadinessReasons(
  item: ModelCatalogItem,
  agentId: string,
  requiredActionClassIds: readonly string[],
  role: "primary" | "fallback",
): string[] {
  const reasons = [...item.unavailableReasons];
  if (!item.compatibleAgentIds.includes(agentId)) {
    reasons.push(`The ${role} configuration is not declared compatible with ${agentId}.`);
  }
  if (item.enforcementMode !== "enforced_executor") {
    reasons.push(`The ${role} configuration is ${item.enforcementMode.replaceAll("_", " ")}; Autonomous requires an enforced executor.`);
  }
  if (item.authState !== "authenticated") {
    reasons.push(`The ${role} provider authentication state is ${item.authState}.`);
  }
  if (item.healthState !== "healthy") {
    reasons.push(`The ${role} provider health state is ${item.healthState}.`);
  }
  if (item.executionBoundary === "provider_tool_calling") {
    if (!item.capabilities.toolCalling) {
      reasons.push(`The ${role} configuration does not support the required provider tool-calling contract.`);
    }
  } else {
    const locallyExecutable = new Set(
      item.capabilities.localDeterministicActionClassIdsByAgent[agentId] ?? [],
    );
    const unboundActionClassIds = requiredActionClassIds.filter(
      (actionClassId) => !locallyExecutable.has(actionClassId),
    );
    if (unboundActionClassIds.length > 0) {
      reasons.push(
        `The ${role} local deterministic policy has no exact available, locally enforced, no-model Autonomous tool binding for: ${unboundActionClassIds.join(", ")}.`,
      );
    }
  }
  if (!item.capabilities.structuredOutput) {
    reasons.push(`The ${role} configuration does not support the required structured-output contract.`);
  }
  if (item.disclosureClass === "unavailable") {
    reasons.push(`The ${role} configuration has no enforceable disclosure classification.`);
  }
  if (
    !item.catalogRetrievedAt
    || !Number.isFinite(Date.parse(item.catalogRetrievedAt))
  ) {
    reasons.push(`The ${role} configuration has no valid live-catalog freshness receipt.`);
  }
  const compatibleActionClassIds = new Set(
    item.capabilities.compatibleActionClassIds,
  );
  const missingActionClassIds = requiredActionClassIds.filter(
    (id) => !compatibleActionClassIds.has(id),
  );
  if (missingActionClassIds.length > 0) {
    reasons.push(
      `The ${role} configuration is not declared compatible with required action classes: ${missingActionClassIds.join(", ")}.`,
    );
  }
  return sorted(reasons);
}

function planningItemReadinessReasons(
  item: ModelCatalogItem,
  selection: Extract<AutonomousPlanningSelection, {
    readonly route: "provider_advisory";
  }>,
  role: "primary" | "fallback",
): string[] {
  const reasons = [...item.unavailableReasons];
  if (selection.agentId !== COMMANDER_AGENT_ID) {
    reasons.push(
      `The ${role} planning configuration is assigned to ${selection.agentId}; provider-backed planning must use the canonical ${COMMANDER_AGENT_ID} identity.`,
    );
  }
  if (!item.compatibleAgentIds.includes(selection.agentId)) {
    reasons.push(
      `The ${role} planning configuration is not declared compatible with ${selection.agentId}.`,
    );
  }
  if (item.enforcementMode !== "advisor_only") {
    reasons.push(
      `The ${role} planning configuration is ${item.enforcementMode.replaceAll("_", " ")}; provider-backed planning must remain advisor only.`,
    );
  }
  if (item.executionBoundary !== "provider_tool_calling") {
    reasons.push(
      `The ${role} planning configuration is not a provider-backed advisory route.`,
    );
  }
  if (item.authState !== "authenticated") {
    reasons.push(
      `The ${role} planning provider authentication state is ${item.authState}.`,
    );
  }
  if (item.healthState !== "healthy") {
    reasons.push(
      `The ${role} planning provider health state is ${item.healthState}.`,
    );
  }
  if (!item.capabilities.structuredOutput) {
    reasons.push(
      `The ${role} planning configuration does not support the required structured-output contract.`,
    );
  }
  if (item.disclosureClass !== selection.disclosureClass) {
    reasons.push(
      `The ${role} planning disclosure class is ${item.disclosureClass}, not the signed ${selection.disclosureClass} boundary.`,
    );
  }
  if (
    !item.catalogRetrievedAt
    || !Number.isFinite(Date.parse(item.catalogRetrievedAt))
  ) {
    reasons.push(
      `The ${role} planning configuration has no valid live-catalog freshness receipt.`,
    );
  }
  return sorted(reasons);
}

function specialistAdvisoryItemReadinessReasons(
  item: ModelCatalogItem,
  agentId: string | null,
  role: "primary" | "fallback",
): string[] {
  const reasons = [...item.unavailableReasons];
  if (agentId && !item.compatibleAgentIds.includes(agentId)) {
    reasons.push(
      `The ${role} advisory configuration is not declared compatible with ${agentId}.`,
    );
  }
  if (item.enforcementMode !== "advisor_only") {
    reasons.push(
      `The ${role} advisory configuration is ${item.enforcementMode.replaceAll("_", " ")}; specialist reasoning must remain advisor only.`,
    );
  }
  if (item.executionBoundary !== "provider_tool_calling") {
    reasons.push(
      `The ${role} advisory configuration is not backed by an attested provider route.`,
    );
  }
  if (item.authState !== "authenticated") {
    reasons.push(
      `The ${role} advisory provider authentication state is ${item.authState}.`,
    );
  }
  if (item.healthState !== "healthy") {
    reasons.push(
      `The ${role} advisory provider health state is ${item.healthState}.`,
    );
  }
  if (!item.capabilities.structuredOutput) {
    reasons.push(
      `The ${role} advisory configuration does not support structured output.`,
    );
  }
  if (item.disclosureClass === "unavailable") {
    reasons.push(
      `The ${role} advisory configuration has no usable disclosure classification.`,
    );
  }
  if (
    !item.catalogRetrievedAt
    || !Number.isFinite(Date.parse(item.catalogRetrievedAt))
  ) {
    reasons.push(
      `The ${role} advisory configuration has no valid live-catalog freshness receipt.`,
    );
  }
  return sorted(reasons);
}

export function autonomousModelCatalogItemReadinessReasons(
  item: ModelCatalogItem,
  agentId: string,
  requiredActionClassIds: readonly string[],
): readonly string[] {
  return itemReadinessReasons(
    item,
    agentId,
    requiredActionClassIds,
    "primary",
  );
}

export class ModelConfigurationService {
  private readonly clock: () => Date;
  private readonly catalogMaximumAgeMs: number;
  private readonly catalogMaximumFutureSkewMs: number;

  constructor(
    private readonly repository: ModelConfigurationRepository,
    private readonly dependencies: ModelConfigurationServiceDependencies,
  ) {
    this.clock = dependencies.clock ?? (() => new Date());
    this.catalogMaximumAgeMs = dependencies.catalogMaximumAgeMs
      ?? DEFAULT_MODEL_CATALOG_MAXIMUM_AGE_MS;
    this.catalogMaximumFutureSkewMs = dependencies.catalogMaximumFutureSkewMs
      ?? DEFAULT_MODEL_CATALOG_MAXIMUM_FUTURE_SKEW_MS;
    if (
      !Number.isSafeInteger(this.catalogMaximumAgeMs)
      || this.catalogMaximumAgeMs < 1_000
      || this.catalogMaximumAgeMs > 24 * 60 * 60 * 1_000
    ) {
      throw new RangeError("catalogMaximumAgeMs must be 1000 through 86400000");
    }
    if (
      !Number.isSafeInteger(this.catalogMaximumFutureSkewMs)
      || this.catalogMaximumFutureSkewMs < 0
      || this.catalogMaximumFutureSkewMs > 60_000
    ) {
      throw new RangeError("catalogMaximumFutureSkewMs must be 0 through 60000");
    }
  }

  catalog(): {
    readonly observedAt: string;
    readonly items: readonly ModelCatalogItem[];
  } {
    const manifests = this.dependencies.readRuntimeManifests();
    const now = this.clock();
    if (!Number.isFinite(now.getTime())) {
      throw new RangeError("Model catalog clock returned an invalid date");
    }
    return {
      observedAt: catalogObservedAt(manifests, now.toISOString()),
      items: catalogOptions(manifests, {
        nowMs: now.getTime(),
        maximumAgeMs: this.catalogMaximumAgeMs,
        maximumFutureSkewMs: this.catalogMaximumFutureSkewMs,
      }),
    };
  }

  /**
   * Resolves a complete, deterministic mission-local selection from one live
   * catalog snapshot. Explicit rows are retained as operator overrides;
   * remaining agents use a currently valid scoped preference or the first
   * deterministic enforced catalog recommendation.
   */
  resolveAutonomousAssignments(input: {
    readonly specialistAgentIds: readonly string[];
    readonly overrides?: readonly AgentModelAssignmentSelection[];
    readonly requiredActionClassIds: readonly string[];
  }): AgentModelAssignmentBatch {
    const specialistAgentIds = sorted(input.specialistAgentIds);
    if (specialistAgentIds.length !== input.specialistAgentIds.length) {
      throw invalidModelConfiguration(
        "duplicate_specialist_agent_id",
        "Autonomous specialistAgentIds contains duplicate values",
      );
    }
    const nonSpecialistIds = specialistAgentIds.filter(
      (agentId) => !PRODUCT_AGENT_IDS.has(agentId),
    );
    if (nonSpecialistIds.length > 0) {
      throw modelConfigurationScopeConflict(
        `Autonomous execution assignments require canonical action-owning specialists; planning-only roster identities are not executable: ${nonSpecialistIds.join(", ")}`,
      );
    }
    const overrides = orderedSelections(input.overrides ?? []);
    const overrideMap = new Map<string, AgentModelAssignmentSelection>();
    for (const selection of overrides) {
      if (overrideMap.has(selection.agentId)) {
        throw invalidModelConfiguration(
          "duplicate_agent_model_assignment",
          `Autonomous model assignments contains duplicate agent ${selection.agentId}`,
        );
      }
      if (!specialistAgentIds.includes(selection.agentId)) {
        throw modelConfigurationScopeConflict(
          `Model assignment override names unselected specialist ${selection.agentId}`,
        );
      }
      if (
        selection.fallbackConfigurationId
        && selection.fallbackConfigurationId === selection.primaryConfigurationId
      ) {
        throw invalidModelConfiguration(
          "model_assignment_duplicate_fallback",
          `Fallback configuration must differ from the primary configuration for ${selection.agentId}`,
        );
      }
      overrideMap.set(selection.agentId, selection);
    }

    const snapshot = this.catalog();
    const selections: AgentModelAssignmentSelection[] = [];
    const sources = new Map<string, AgentModelAssignmentSource>();
    for (const agentId of specialistAgentIds) {
      const override = overrideMap.get(agentId);
      if (override) {
        this.assertCatalogSelectionExists(snapshot.items, override);
        selections.push(override);
        sources.set(agentId, "operator_override");
        continue;
      }

      let inherited: AgentModelAssignmentSelection | null = null;
      try {
        const resolution = this.resolveOptional({ agentId });
        if (resolution) {
          inherited = {
            agentId,
            primaryConfigurationId: resolution.primaryConfiguration.id,
            fallbackConfigurationId:
              resolution.fallbackConfiguration?.id ?? null,
          };
        }
      } catch {
        // A stale preference is not silently signed. A current live-catalog
        // recommendation is attempted below and preflight remains fail-closed.
      }
      if (inherited) {
        const receipt = this.receiptForSelection(
          snapshot.items,
          inherited,
          input.requiredActionClassIds,
          "inherited",
        );
        if (receipt.ready) {
          selections.push(inherited);
          sources.set(agentId, "inherited");
          continue;
        }
      }

      const recommendation = this.recommendedSelection(
        snapshot.items,
        agentId,
        input.requiredActionClassIds,
      );
      if (!recommendation) {
        throw modelConfigurationUnavailable(
          `No live catalog configuration is currently executable for selected specialist ${agentId}`,
          `Connect an authenticated, healthy enforced provider tool-calling route or an exact available local deterministic tool route that declares ${agentId} and every required action class, then resolve intake again.`,
        );
      }
      selections.push(recommendation);
      sources.set(agentId, "recommended");
    }
    const resolvedSelections = selections.map((selection) => ({
      ...selection,
      source: sources.get(selection.agentId)!,
    }));
    return this.validateAutonomousAssignmentsWithSnapshot(
      snapshot,
      resolvedSelections,
      specialistAgentIds,
      input.requiredActionClassIds,
      sources,
    );
  }

  /**
   * Revalidates an already signed selection against one current catalog
   * snapshot and returns a readable receipt for every selected specialist.
   */
  validateAutonomousAssignments(input: {
    readonly assignments: readonly AgentModelAssignmentSelection[];
    readonly specialistAgentIds: readonly string[];
    readonly requiredActionClassIds: readonly string[];
  }): AgentModelAssignmentBatch {
    const snapshot = this.catalog();
    return this.validateAutonomousAssignmentsWithSnapshot(
      snapshot,
      input.assignments,
      input.specialistAgentIds,
      input.requiredActionClassIds,
    );
  }

  /**
   * Revalidates a signed plan-construction route. Local deterministic planning
   * is product code and therefore has no model receipt. Provider planning is
   * admitted only when the exact live configuration remains advisor-only,
   * disclosure-compatible, authenticated, healthy, and structured.
   */
  validateAutonomousPlanningSelection(
    selection: AutonomousPlanningSelection,
  ): AgentModelAssignmentReceipt | null {
    if (selection.route === "local_deterministic") return null;
    return this.planningReceiptForSelection(this.catalog().items, selection);
  }

  /**
   * Pins only a provider-advisory planning configuration. The purpose marker
   * keeps this row distinct from the same agent's execution assignment and
   * prevents downstream execution resolution from treating it as authority.
   */
  pinExactAutonomousPlanningSelection(input: {
    readonly selection: AutonomousPlanningSelection;
    readonly missionId: string;
    readonly runId: string;
    readonly resolutionReason?: string;
  }): PinnedModelAssignment | null {
    if (input.selection.route === "local_deterministic") return null;
    const snapshot = this.catalog();
    const receipt = this.planningReceiptForSelection(
      snapshot.items,
      input.selection,
    );
    if (!receipt.ready) {
      const message =
        `Exact planning configuration for ${receipt.agentId} is no longer advisory-ready: ${receipt.reasons.join(" ")}`;
      const policyFailure = receipt.reasons.some((reason) =>
        /advisor only|provider-backed|structured-output|disclosure class|compatible with/u
          .test(reason));
      if (policyFailure) {
        throw modelConfigurationPolicyDenied(
          message,
          "Choose a current advisor-only provider configuration compatible with the planning agent and signed disclosure boundary, then review a new contract digest.",
        );
      }
      throw modelConfigurationUnavailable(message);
    }
    const catalogById = new Map(
      snapshot.items.map((item) => [item.configurationId, item]),
    );
    const primary = catalogById.get(
      input.selection.primaryConfigurationId,
    );
    if (!primary) {
      throw modelConfigurationNotFound(
        "planning_model_catalog_configuration_drift",
        `Reviewed planning configuration disappeared from the live catalog: ${input.selection.primaryConfigurationId}`,
        "Refresh the live model catalog and review a new Autonomous contract before launch.",
      );
    }
    this.repository.materializeCatalogConfiguration(primary);
    if (input.selection.fallbackConfigurationId) {
      const fallback = catalogById.get(
        input.selection.fallbackConfigurationId,
      );
      if (!fallback) {
        throw modelConfigurationNotFound(
          "planning_model_catalog_fallback_drift",
          `Reviewed planning fallback disappeared from the live catalog: ${input.selection.fallbackConfigurationId}`,
          "Refresh the live model catalog and review a new Autonomous contract before launch.",
        );
      }
      this.repository.materializeCatalogConfiguration(fallback);
    }
    return this.repository.createExactPinnedAssignment({
      agentId: input.selection.agentId,
      missionId: input.missionId,
      runId: input.runId,
      purpose: "planning",
      primaryConfigurationId: input.selection.primaryConfigurationId,
      fallbackConfigurationId: input.selection.fallbackConfigurationId,
      inheritanceLevel: "mission",
      resolutionReason: input.resolutionReason
        ?? "Pinned transactionally from the exact operator-reviewed Autonomous provider-advisory planning selection",
    });
  }

  /**
   * Revalidates, materializes, and pins all exact reviewed selections. Mission
   * and branch callers invoke this inside their outer IMMEDIATE transaction.
   */
  pinExactAutonomousAssignments(input: {
    readonly assignments: readonly AgentModelAssignmentSelection[];
    readonly specialistAgentIds: readonly string[];
    readonly requiredActionClassIds: readonly string[];
    readonly missionId: string;
    readonly runId: string;
    readonly resolutionReason?: string;
  }): readonly PinnedModelAssignment[] {
    const snapshot = this.catalog();
    const batch = this.validateAutonomousAssignmentsWithSnapshot(
      snapshot,
      input.assignments,
      input.specialistAgentIds,
      input.requiredActionClassIds,
    );
    const blocker = batch.receipts.find(({ ready }) => !ready);
    if (blocker) {
      const policyFailure = blocker.reasons.some((reason) =>
        /enforced executor|tool-calling|structured-output|action classes|disclosure|compatible with/u
          .test(reason));
      const message =
        `Exact model assignment for ${blocker.agentId} is no longer executable: ${blocker.reasons.join(" ")}`;
      if (policyFailure) {
        throw modelConfigurationPolicyDenied(
          message,
          "Select a current enforced executor compatible with this specialist, its signed action classes, tool contract, and disclosure boundary; then review a new contract digest.",
        );
      }
      throw modelConfigurationUnavailable(message);
    }

    const catalogById = new Map(
      snapshot.items.map((item) => [item.configurationId, item]),
    );
    for (const selection of batch.selections) {
      const primary = catalogById.get(selection.primaryConfigurationId);
      if (!primary) {
        throw modelConfigurationNotFound(
          "model_catalog_configuration_drift",
          `Reviewed primary configuration disappeared from the live catalog: ${selection.primaryConfigurationId}`,
          "Refresh the live model catalog and review a new Autonomous contract before launch.",
        );
      }
      this.repository.materializeCatalogConfiguration(primary);
      if (selection.fallbackConfigurationId) {
        const fallback = catalogById.get(selection.fallbackConfigurationId);
        if (!fallback) {
          throw modelConfigurationNotFound(
            "model_catalog_fallback_drift",
            `Reviewed fallback configuration disappeared from the live catalog: ${selection.fallbackConfigurationId}`,
            "Refresh the live model catalog and review a new Autonomous contract before launch.",
          );
        }
        this.repository.materializeCatalogConfiguration(fallback);
      }
    }
    return batch.selections.map((selection) =>
      this.repository.createExactPinnedAssignment({
        agentId: selection.agentId,
        missionId: input.missionId,
        runId: input.runId,
        purpose: "execution",
        primaryConfigurationId: selection.primaryConfigurationId,
        fallbackConfigurationId: selection.fallbackConfigurationId,
        inheritanceLevel: "mission",
        resolutionReason: input.resolutionReason
          ?? `Pinned transactionally from the exact operator-reviewed Autonomous mission contract (${selection.source ?? "operator_override"})`,
      }));
  }

  listConfigurations(ids?: readonly string[]): readonly StoredModelConfiguration[] {
    return this.repository.listConfigurations(ids);
  }

  listPreferences(filters: ModelPreferenceFilters = {}) {
    return this.repository.listPreferences(filters);
  }

  listPinnedAssignmentsForRun(
    runId: string,
  ): readonly PinnedModelAssignmentReadback[] {
    return this.repository.listPinnedAssignmentsForRun(runId)
      .map((assignment) => ({
        assignment,
        primaryConfiguration: this.repository.getConfiguration(
          assignment.primaryConfigurationId,
        ),
        fallbackConfiguration: assignment.fallbackConfigurationId
          ? this.repository.getConfiguration(
              assignment.fallbackConfigurationId,
            )
          : null,
      }));
  }

  putPreference(
    input: PutModelPreferenceInput,
    actorId: string,
  ) {
    const catalog = this.catalog().items;
    const primary = catalog.find(
      ({ configurationId: id }) => id === input.primaryConfigurationId,
    );
    if (!primary) {
      throw modelConfigurationNotFound(
        "model_catalog_configuration_not_found",
        `Primary configuration is not in the current live-attested catalog: ${input.primaryConfigurationId}`,
        "Refresh the model catalog and select a current configuration.",
      );
    }
    if (!primary.selectable) {
      throw modelConfigurationUnavailable(
        `Primary configuration is unavailable: ${primary.unavailableReasons.join(" ")}`,
      );
    }
    const fallback = input.fallbackConfigurationId
      ? catalog.find(({ configurationId: id }) => id === input.fallbackConfigurationId)
      : undefined;
    if (input.fallbackConfigurationId && !fallback) {
      throw modelConfigurationNotFound(
        "model_catalog_fallback_not_found",
        `Fallback configuration is not in the current live-attested catalog: ${input.fallbackConfigurationId}`,
        "Refresh the model catalog and select a current fallback configuration.",
      );
    }
    if (fallback && !fallback.selectable) {
      throw modelConfigurationUnavailable(
        `Fallback configuration is unavailable: ${fallback.unavailableReasons.join(" ")}`,
      );
    }
    if (input.purpose === "planning") {
      const primaryAdvisoryReasons = specialistAdvisoryItemReadinessReasons(
        primary,
        input.agentId,
        "primary",
      );
      const fallbackAdvisoryReasons = fallback
        ? specialistAdvisoryItemReadinessReasons(
            fallback,
            input.agentId,
            "fallback",
          )
        : [];
      const advisoryReasons = sorted([
        ...primaryAdvisoryReasons,
        ...fallbackAdvisoryReasons,
      ]);
      if (advisoryReasons.length > 0) {
        throw modelConfigurationPolicyDenied(
          `Specialist advisory assignment is not ready: ${advisoryReasons.join(" ")}`,
          "Choose a current authenticated, healthy advisor-only provider configuration declared for this specialist. The execution model remains configured separately.",
        );
      }
    }
    if (input.scopeType === "global") {
      const primaryMissingAgents = missingWorkspaceSpecialistAgentIds(primary);
      if (primaryMissingAgents.length > 0) {
        throw modelConfigurationScopeConflict(
          `Workspace primary configuration is not declared for every canonical specialist. Missing: ${primaryMissingAgents.join(", ")}`,
          "Choose a live primary route that covers every canonical specialist, or configure specialists individually.",
        );
      }
      const fallbackMissingAgents = fallback
        ? missingWorkspaceSpecialistAgentIds(fallback)
        : [];
      if (fallbackMissingAgents.length > 0) {
        throw modelConfigurationScopeConflict(
          `Workspace fallback configuration is not declared for every canonical specialist. Missing: ${fallbackMissingAgents.join(", ")}`,
          "Choose a live fallback route that covers every canonical specialist, remove the fallback, or configure specialists individually.",
        );
      }
    }
    if (input.agentId && !primary.compatibleAgentIds.includes(input.agentId)) {
      throw modelConfigurationScopeConflict(
        `Primary configuration is not declared for agent ${input.agentId}`,
      );
    }
    if (
      input.agentId
      && fallback
      && !fallback.compatibleAgentIds.includes(input.agentId)
    ) {
      throw modelConfigurationScopeConflict(
        `Fallback configuration is not declared for agent ${input.agentId}`,
      );
    }

    this.repository.materializeCatalogConfiguration(primary);
    if (fallback) this.repository.materializeCatalogConfiguration(fallback);
    return this.repository.putPreference(input, actorId);
  }

  resolve(input: {
    readonly agentId: string;
    readonly purpose?: ModelAssignmentPurpose;
    readonly missionId?: string;
    readonly runId?: string;
    readonly stepId?: string;
  }): ModelResolution {
    const resolution = this.resolveOptional(input);
    if (!resolution) {
      throw modelConfigurationNotFound(
        "model_resolution_not_found",
        `No model preference resolves for agent ${input.agentId}`,
        "Set a global default or an exact agent preference, then retry resolution.",
      );
    }
    return resolution;
  }

  resolveOptional(input: {
    readonly agentId: string;
    readonly purpose?: ModelAssignmentPurpose;
    readonly missionId?: string;
    readonly runId?: string;
    readonly stepId?: string;
  }): ModelResolution | null {
    const context = {
      missionId: input.missionId ?? null,
      runId: input.runId ?? null,
      stepId: input.stepId ?? null,
    };
    const purpose = input.purpose ?? "execution";
    const preference = this.repository.resolvePreference(
      input.agentId,
      context,
      purpose,
    );
    if (!preference) return null;
    const primary = this.repository.getConfiguration(
      preference.primaryConfigurationId,
    );
    const fallback = preference.fallbackConfigurationId
      ? this.repository.getConfiguration(preference.fallbackConfigurationId)
      : null;
    if (!configurationCompatibleWithAgent(primary, input.agentId)) {
      throw modelConfigurationScopeConflict(
        `Resolved primary configuration is not declared for agent ${input.agentId}`,
      );
    }
    if (fallback && !configurationCompatibleWithAgent(fallback, input.agentId)) {
      throw modelConfigurationScopeConflict(
        `Resolved fallback configuration is not declared for agent ${input.agentId}`,
      );
    }
    return {
      agentId: input.agentId,
      purpose,
      context,
      source: {
        scopeType: preference.scopeType,
        scopeId: preference.scopeId,
        preferenceId: preference.id,
        preferenceVersion: preference.version,
      },
      primaryConfiguration: primary,
      fallbackConfiguration: fallback,
      resolvedAt: this.clock().toISOString(),
    };
  }

  resolveAndPin(
    input: PinModelAssignmentInput,
    options: Readonly<{ requireAutonomousExecutor?: boolean }> = {},
  ): PinnedModelAssignment {
    const existing = this.repository.findPinnedAssignment(input);
    if (existing) return existing;
    const resolution = this.resolve(input);
    if (options.requireAutonomousExecutor) {
      this.assertAutonomousExecutable(resolution);
    } else {
      this.assertCurrentlySelectable(resolution);
    }
    const preference = this.repository.getCurrentPreference(
      resolution.source.scopeType,
      resolution.source.scopeId,
      resolution.source.scopeType === "global" ? null : input.agentId,
      input.purpose ?? "execution",
    );
    if (!preference || preference.id !== resolution.source.preferenceId) {
      throw modelConfigurationScopeConflict(
        "Model preference changed while the assignment was being resolved",
      );
    }
    return this.repository.createPinnedAssignment(input, preference);
  }

  assertCurrentlySelectable(resolution: ModelResolution): void {
    const catalog = this.catalog().items;
    const primary = catalog.find(({ configurationId }) =>
      configurationId === resolution.primaryConfiguration.id);
    if (!primary || !primary.selectable) {
      throw modelConfigurationUnavailable(
        primary
          ? `Resolved primary configuration is not currently selectable: ${primary.unavailableReasons.join(" ")}`
          : "Resolved primary configuration is absent from the current live-attested catalog",
      );
    }
    if (!primary.compatibleAgentIds.includes(resolution.agentId)) {
      throw modelConfigurationScopeConflict(
        `Resolved primary configuration is not currently declared for agent ${resolution.agentId}`,
      );
    }
    if (resolution.fallbackConfiguration) {
      const fallback = catalog.find(({ configurationId }) =>
        configurationId === resolution.fallbackConfiguration!.id);
      if (!fallback || !fallback.selectable) {
        throw modelConfigurationUnavailable(
          fallback
            ? `Resolved fallback configuration is not currently selectable: ${fallback.unavailableReasons.join(" ")}`
            : "Resolved fallback configuration is absent from the current live-attested catalog",
        );
      }
      if (!fallback.compatibleAgentIds.includes(resolution.agentId)) {
        throw modelConfigurationScopeConflict(
          `Resolved fallback configuration is not currently declared for agent ${resolution.agentId}`,
        );
      }
    }
  }

  /**
   * Autonomous specialists require a provider path whose local runtime can
   * enforce the signed tool and scope policy. Advisor-only and observe-only
   * models remain selectable for planning, critique, reporting, and Guided
   * use, but are never misrepresented as Autonomous executors.
   */
  assertAutonomousExecutable(resolution: ModelResolution): void {
    this.assertCurrentlySelectable(resolution);
    const assertExecutor = (
      label: "primary" | "fallback",
      configuration: StoredModelConfiguration,
    ): void => {
      if (configuration.enforcementMode !== "enforced_executor") {
        throw modelConfigurationPolicyDenied(
          `Resolved ${label} configuration is ${configuration.enforcementMode.replaceAll("_", " ")} and cannot enforce the Autonomous mission contract`,
          "Choose an enforced executor for this specialist, or use the model as an advisor in Guided or planning work.",
        );
      }
    };
    assertExecutor("primary", resolution.primaryConfiguration);
    if (resolution.fallbackConfiguration) {
      assertExecutor("fallback", resolution.fallbackConfiguration);
    }
  }

  /**
   * Pins optional per-specialist reasoning advice independently from the
   * signed execution authority. A missing or no-longer-attested advisory
   * route is omitted so an unconfigured public provider never becomes a
   * hidden Autonomous launch dependency.
   */
  pinSelectedSpecialistAdvisoryAssignments(input: {
    readonly specialistAgentIds: readonly string[];
    readonly missionId: string;
    readonly runId: string;
  }): readonly PinnedModelAssignment[] {
    const pinned: PinnedModelAssignment[] = [];
    for (const agentId of sorted(input.specialistAgentIds)) {
      if (!PRODUCT_AGENT_IDS.has(agentId)) continue;
      let resolution: ModelResolution | null;
      try {
        resolution = this.resolveOptional({
          agentId,
          purpose: "planning",
          missionId: input.missionId,
          runId: input.runId,
        });
        if (!resolution) continue;
        this.assertSpecialistAdvisorySelectable(resolution);
      } catch (error) {
        if (error instanceof ModelConfigurationError) continue;
        throw error;
      }
      const preference = this.repository.getCurrentPreference(
        resolution.source.scopeType,
        resolution.source.scopeId,
        resolution.source.scopeType === "global" ? null : agentId,
        "planning",
      );
      if (!preference || preference.id !== resolution.source.preferenceId) {
        continue;
      }
      pinned.push(this.repository.createPinnedAssignment({
        agentId,
        missionId: input.missionId,
        runId: input.runId,
        purpose: "planning",
        resolutionReason:
          `Pinned optional specialist advisory reasoning from ${preference.scopeType} preference ${preference.id} version ${preference.version}; execution authority remains separately pinned`,
      }, preference));
    }
    return pinned;
  }

  assertSpecialistAdvisorySelectable(resolution: ModelResolution): void {
    this.assertCurrentlySelectable(resolution);
    const assertAdvisor = (
      label: "primary" | "fallback",
      configuration: StoredModelConfiguration,
    ): void => {
      if (
        configuration.enforcementMode !== "advisor_only"
        || configuration.executionBoundary !== "provider_tool_calling"
        || configuration.authState !== "authenticated"
        || configuration.healthState !== "healthy"
        || configuration.capabilities.structuredOutput !== true
      ) {
        throw modelConfigurationPolicyDenied(
          `Resolved ${label} specialist reasoning configuration is not a current authenticated advisor-only provider route`,
          "Choose an attested advisor-only provider configuration for reasoning. Keep execution on its separate enforced model assignment.",
        );
      }
    };
    assertAdvisor("primary", resolution.primaryConfiguration);
    if (resolution.fallbackConfiguration) {
      assertAdvisor("fallback", resolution.fallbackConfiguration);
    }
  }

  private assertCatalogSelectionExists(
    items: readonly ModelCatalogItem[],
    selection: AgentModelAssignmentSelection,
  ): void {
    if (!items.some(({ configurationId: id }) =>
      id === selection.primaryConfigurationId)) {
      throw modelConfigurationNotFound(
        "model_catalog_configuration_not_found",
        `Primary configuration is not in the current live-attested catalog: ${selection.primaryConfigurationId}`,
        "Refresh the model catalog and select a current configuration.",
      );
    }
    if (
      selection.fallbackConfigurationId
      && !items.some(({ configurationId: id }) =>
        id === selection.fallbackConfigurationId)
    ) {
      throw modelConfigurationNotFound(
        "model_catalog_fallback_not_found",
        `Fallback configuration is not in the current live-attested catalog: ${selection.fallbackConfigurationId}`,
        "Refresh the model catalog and select a current fallback configuration.",
      );
    }
  }

  private recommendedSelection(
    items: readonly ModelCatalogItem[],
    agentId: string,
    requiredActionClassIds: readonly string[],
  ): AgentModelAssignmentSelection | null {
    const relevantActionClassIds = requiredActionClassesForAgent(
      agentId,
      requiredActionClassIds,
    );
    const compatible = items.filter((item) =>
      item.compatibleAgentIds.includes(agentId));
    const selected = compatible.find((item) =>
      itemReadinessReasons(
        item,
        agentId,
        relevantActionClassIds,
        "primary",
      ).length === 0);
    return selected
      ? {
          agentId,
          primaryConfigurationId: selected.configurationId,
          fallbackConfigurationId: null,
        }
      : null;
  }

  private receiptForSelection(
    items: readonly ModelCatalogItem[],
    selection: AgentModelAssignmentSelection,
    requiredActionClassIds: readonly string[],
    source: AgentModelAssignmentSource,
  ): AgentModelAssignmentReceipt {
    const relevantActionClassIds = requiredActionClassesForAgent(
      selection.agentId,
      requiredActionClassIds,
    );
    const primary = items.find(({ configurationId }) =>
      configurationId === selection.primaryConfigurationId);
    const fallback = selection.fallbackConfigurationId
      ? items.find(({ configurationId }) =>
          configurationId === selection.fallbackConfigurationId)
      : undefined;
    const reasons: string[] = [];
    if (!primary) {
      reasons.push(
        `The reviewed primary configuration ${selection.primaryConfigurationId} is absent from the current live catalog.`,
      );
    } else {
      reasons.push(...itemReadinessReasons(
        primary,
        selection.agentId,
        relevantActionClassIds,
        "primary",
      ));
    }
    if (selection.fallbackConfigurationId && !fallback) {
      reasons.push(
        `The reviewed fallback configuration ${selection.fallbackConfigurationId} is absent from the current live catalog.`,
      );
    } else if (fallback) {
      reasons.push(...itemReadinessReasons(
        fallback,
        selection.agentId,
        relevantActionClassIds,
        "fallback",
      ));
    }

    const storedPrimary = primary
      ? null
      : this.repository.findConfiguration(selection.primaryConfigurationId);
    const storedFallback = fallback || !selection.fallbackConfigurationId
      ? null
      : this.repository.findConfiguration(selection.fallbackConfigurationId);
    if (!primary && !storedPrimary) {
      throw modelConfigurationNotFound(
        "model_catalog_configuration_drift",
        `Reviewed primary configuration is absent from both the live catalog and immutable configuration history: ${selection.primaryConfigurationId}`,
        "Refresh the live model catalog, select a current exact configuration, and review a new contract digest.",
      );
    }
    if (selection.fallbackConfigurationId && !fallback && !storedFallback) {
      throw modelConfigurationNotFound(
        "model_catalog_fallback_drift",
        `Reviewed fallback configuration is absent from both the live catalog and immutable configuration history: ${selection.fallbackConfigurationId}`,
        "Refresh the live model catalog, select a current exact fallback, and review a new contract digest.",
      );
    }
    return {
      agentId: selection.agentId,
      source,
      ready: reasons.length === 0,
      reasons: sorted(reasons),
      primary: primary
        ? receiptConfiguration(primary)
        : storedReceiptConfiguration(storedPrimary!),
      fallback: fallback
        ? receiptConfiguration(fallback)
        : storedFallback
          ? storedReceiptConfiguration(storedFallback)
          : null,
    };
  }

  private planningReceiptForSelection(
    items: readonly ModelCatalogItem[],
    selection: Extract<AutonomousPlanningSelection, {
      readonly route: "provider_advisory";
    }>,
  ): AgentModelAssignmentReceipt {
    if (
      selection.fallbackConfigurationId
      && selection.fallbackConfigurationId
        === selection.primaryConfigurationId
    ) {
      throw invalidModelConfiguration(
        "planning_model_assignment_duplicate_fallback",
        "The provider-advisory planning fallback must differ from its primary configuration",
      );
    }
    const primary = items.find(({ configurationId }) =>
      configurationId === selection.primaryConfigurationId);
    const fallback = selection.fallbackConfigurationId
      ? items.find(({ configurationId }) =>
          configurationId === selection.fallbackConfigurationId)
      : undefined;
    if (!primary) {
      throw modelConfigurationNotFound(
        "planning_model_catalog_configuration_drift",
        `Reviewed planning configuration is absent from the current live catalog: ${selection.primaryConfigurationId}`,
        "Refresh the live model catalog and review a new Autonomous contract before launch.",
      );
    }
    if (selection.fallbackConfigurationId && !fallback) {
      throw modelConfigurationNotFound(
        "planning_model_catalog_fallback_drift",
        `Reviewed planning fallback is absent from the current live catalog: ${selection.fallbackConfigurationId}`,
        "Refresh the live model catalog and review a new Autonomous contract before launch.",
      );
    }
    const reasons = [
      ...planningItemReadinessReasons(
        primary,
        selection,
        "primary",
      ),
      ...(fallback
        ? planningItemReadinessReasons(fallback, selection, "fallback")
        : []),
    ];
    return {
      agentId: selection.agentId,
      source: "operator_override",
      ready: reasons.length === 0,
      reasons: sorted(reasons),
      primary: receiptConfiguration(primary),
      fallback: fallback ? receiptConfiguration(fallback) : null,
    };
  }

  private validateAutonomousAssignmentsWithSnapshot(
    snapshot: ReturnType<ModelConfigurationService["catalog"]>,
    assignments: readonly AgentModelAssignmentSelection[],
    specialistAgentIdsValue: readonly string[],
    requiredActionClassIds: readonly string[],
    explicitSources?: ReadonlyMap<string, AgentModelAssignmentSource>,
  ): AgentModelAssignmentBatch {
    const specialistAgentIds = sorted(specialistAgentIdsValue);
    if (specialistAgentIds.length !== specialistAgentIdsValue.length) {
      throw invalidModelConfiguration(
        "duplicate_specialist_agent_id",
        "Autonomous specialistAgentIds contains duplicate values",
      );
    }
    const nonSpecialistIds = specialistAgentIds.filter(
      (agentId) => !PRODUCT_AGENT_IDS.has(agentId),
    );
    if (nonSpecialistIds.length > 0) {
      throw modelConfigurationScopeConflict(
        `Autonomous execution assignments require canonical action-owning specialists; planning-only roster identities are not executable: ${nonSpecialistIds.join(", ")}`,
      );
    }
    const selections = orderedSelections(assignments);
    const seen = new Set<string>();
    for (const selection of selections) {
      if (seen.has(selection.agentId)) {
        throw invalidModelConfiguration(
          "duplicate_agent_model_assignment",
          `Autonomous model assignments contains duplicate agent ${selection.agentId}`,
        );
      }
      seen.add(selection.agentId);
      if (
        selection.fallbackConfigurationId
        && selection.fallbackConfigurationId === selection.primaryConfigurationId
      ) {
        throw invalidModelConfiguration(
          "model_assignment_duplicate_fallback",
          `Fallback configuration must differ from the primary configuration for ${selection.agentId}`,
        );
      }
    }
    const assignmentAgentIds = selections.map(({ agentId }) => agentId);
    const missing = specialistAgentIds.filter((id) =>
      !assignmentAgentIds.includes(id));
    const extra = assignmentAgentIds.filter((id) =>
      !specialistAgentIds.includes(id));
    if (missing.length > 0 || extra.length > 0) {
      throw modelConfigurationScopeConflict([
        ...(missing.length > 0
          ? [`Missing exact model assignments for: ${missing.join(", ")}`]
          : []),
        ...(extra.length > 0
          ? [`Model assignments name unselected specialists: ${extra.join(", ")}`]
          : []),
      ].join(". "));
    }

    const recommendations = new Map<string, AgentModelAssignmentSelection>();
    for (const agentId of specialistAgentIds) {
      const value = this.recommendedSelection(
        snapshot.items,
        agentId,
        requiredActionClassIds,
      );
      if (value) recommendations.set(agentId, value);
    }
    const receipts = selections.map((selection) => {
      let source = selection.source ?? explicitSources?.get(selection.agentId);
      if (!source) {
        try {
          const inherited = this.resolveOptional({ agentId: selection.agentId });
          if (
            inherited?.primaryConfiguration.id
              === selection.primaryConfigurationId
            && (inherited.fallbackConfiguration?.id ?? null)
              === selection.fallbackConfigurationId
          ) {
            source = "inherited";
          }
        } catch {
          // Stale defaults do not affect the signed selection classification.
        }
      }
      const recommendation = recommendations.get(selection.agentId);
      if (
        !source
        && recommendation?.primaryConfigurationId
          === selection.primaryConfigurationId
        && recommendation.fallbackConfigurationId
          === selection.fallbackConfigurationId
      ) {
        source = "recommended";
      }
      return this.receiptForSelection(
        snapshot.items,
        selection,
        requiredActionClassIds,
        source ?? "operator_override",
      );
    });
    return {
      observedAt: snapshot.observedAt,
      selections,
      receipts,
    };
  }
}

export function modelCatalogItems(
  manifests: RuntimeSourceManifests,
  freshness?: Readonly<{
    now: Date;
    maximumAgeMs?: number;
    maximumFutureSkewMs?: number;
  }>,
): readonly ModelCatalogItem[] {
  if (!freshness) return catalogOptions(manifests);
  const nowMs = freshness.now.getTime();
  if (!Number.isFinite(nowMs)) throw new RangeError("Model catalog time is invalid");
  return catalogOptions(manifests, {
    nowMs,
    maximumAgeMs: freshness.maximumAgeMs
      ?? DEFAULT_MODEL_CATALOG_MAXIMUM_AGE_MS,
    maximumFutureSkewMs: freshness.maximumFutureSkewMs
      ?? DEFAULT_MODEL_CATALOG_MAXIMUM_FUTURE_SKEW_MS,
  });
}

export function referencedProviderModel(
  manifests: RuntimeSourceManifests,
  providerId: string,
  modelId: string,
): RuntimeProviderModelManifest | undefined {
  return manifests.providers
    .find(({ id }) => id === providerId)
    ?.models.find(({ id }) => id === modelId);
}

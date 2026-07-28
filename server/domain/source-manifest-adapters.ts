import { createHash } from "node:crypto";
import {
  ACTION_CLASS_IDS,
  DELIVERABLE_IDS,
  EVIDENCE_TYPE_IDS,
  isActionClassId,
  isDeliverableId,
  isEvidenceTypeId,
  type ActionClassId,
  type DeliverableId,
  type EvidenceTypeId,
} from "./catalog-ids";
import type { ModelEnforcementState, ProviderModelCapability } from "./model-readiness";

export type CapabilityAvailability = "supported" | "unavailable" | "unsupported";

export interface RuntimeRiskClassManifest {
  readonly id: string;
  readonly label: string;
  readonly actionClassIds: readonly string[];
}

export interface RuntimeEvidenceKindManifest {
  readonly id: string;
  readonly label: string;
  readonly evidenceTypeIds: readonly string[];
}

export interface RuntimeCapabilityManifest {
  readonly id: string;
  readonly label: string;
  readonly actionClassIds: readonly string[];
  readonly evidenceTypeIds?: readonly string[];
  readonly deliverableIds?: readonly string[];
}

export interface RuntimeAdapterAttestation {
  readonly schemaVersion: "ti-scale.runtime-adapter-attestation.v1";
  readonly source: "autonomous_runtime_composition";
  readonly toolId: string;
  readonly dependencyId?: string;
  readonly parentBindingSha256?: string;
  readonly executionJourneys: readonly ("autonomous" | "guided")[];
  readonly binding: Readonly<{
    readonly configurationSha256: string;
    readonly providerReceiptSha256: string;
    readonly localManifestSha256: string;
    readonly componentReceiptSha256s: readonly string[];
  }>;
  readonly bindingSha256: string;
  readonly observedAt: string;
  readonly expiresAt: string;
  readonly receiptSha256: string;
}

export type RuntimeAdapterAttestationInput = Readonly<
  Omit<RuntimeAdapterAttestation, "schemaVersion" | "source" | "bindingSha256" | "receiptSha256">
>;

export const MAX_RUNTIME_ADAPTER_ATTESTATION_LIFETIME_MS = 5 * 60 * 1_000;

const RUNTIME_ADAPTER_PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const RUNTIME_ADAPTER_SHA256 = /^[a-f0-9]{64}$/u;

function runtimeAdapterHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
}

function canonicalRuntimeAdapterJourneys(
  values: readonly ("autonomous" | "guided")[],
): readonly ("autonomous" | "guided")[] {
  return Object.freeze([
    ...(values.includes("autonomous") ? ["autonomous" as const] : []),
    ...(values.includes("guided") ? ["guided" as const] : []),
  ]);
}

function canonicalRuntimeAdapterComponents(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort(
    (left, right) => left < right ? -1 : left > right ? 1 : 0,
  ));
}

function runtimeAdapterBindingPreimage(
  value: Pick<
    RuntimeAdapterAttestation,
    "toolId" | "dependencyId" | "parentBindingSha256" | "executionJourneys" | "binding"
  >,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    bindingSchemaVersion: "ti-scale.runtime-adapter-binding.v1",
    toolId: value.toolId,
    dependencyId: value.dependencyId ?? null,
    parentBindingSha256: value.parentBindingSha256 ?? null,
    executionJourneys: canonicalRuntimeAdapterJourneys(value.executionJourneys),
    binding: Object.freeze({
      configurationSha256: value.binding.configurationSha256,
      providerReceiptSha256: value.binding.providerReceiptSha256,
      localManifestSha256: value.binding.localManifestSha256,
      componentReceiptSha256s: canonicalRuntimeAdapterComponents(
        value.binding.componentReceiptSha256s,
      ),
    }),
  });
}

export function runtimeAdapterBindingSha256(
  value: Pick<
    RuntimeAdapterAttestation,
    "toolId" | "dependencyId" | "parentBindingSha256" | "executionJourneys" | "binding"
  >,
): string {
  return runtimeAdapterHash(runtimeAdapterBindingPreimage(value));
}

function runtimeAdapterReceiptPreimage(
  value: Omit<RuntimeAdapterAttestation, "receiptSha256">,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    schemaVersion: value.schemaVersion,
    source: value.source,
    ...runtimeAdapterBindingPreimage(value),
    bindingSha256: value.bindingSha256,
    observedAt: value.observedAt,
    expiresAt: value.expiresAt,
  });
}

export function runtimeAdapterReceiptSha256(
  value: Omit<RuntimeAdapterAttestation, "receiptSha256">,
): string {
  return runtimeAdapterHash(runtimeAdapterReceiptPreimage(value));
}

export function createRuntimeAdapterAttestation(
  input: RuntimeAdapterAttestationInput,
): RuntimeAdapterAttestation {
  const unsignedBinding = Object.freeze({
    toolId: input.toolId,
    ...(input.dependencyId ? { dependencyId: input.dependencyId } : {}),
    ...(input.parentBindingSha256
      ? { parentBindingSha256: input.parentBindingSha256 }
      : {}),
    executionJourneys: canonicalRuntimeAdapterJourneys(input.executionJourneys),
    binding: Object.freeze({
      configurationSha256: input.binding.configurationSha256,
      providerReceiptSha256: input.binding.providerReceiptSha256,
      localManifestSha256: input.binding.localManifestSha256,
      componentReceiptSha256s: canonicalRuntimeAdapterComponents(
        input.binding.componentReceiptSha256s,
      ),
    }),
  });
  const unsigned = Object.freeze({
    schemaVersion: "ti-scale.runtime-adapter-attestation.v1" as const,
    source: "autonomous_runtime_composition" as const,
    ...unsignedBinding,
    bindingSha256: runtimeAdapterBindingSha256(unsignedBinding),
    observedAt: input.observedAt,
    expiresAt: input.expiresAt,
  });
  const result = Object.freeze({
    ...unsigned,
    receiptSha256: runtimeAdapterReceiptSha256(unsigned),
  });
  if (!runtimeAdapterAttestationIntegrityValid(result)) {
    throw new TypeError("Runtime adapter attestation input is invalid.");
  }
  return result;
}

export function runtimeAdapterAttestationIntegrityValid(
  attestation: RuntimeAdapterAttestation,
): boolean {
  const observedAt = Date.parse(attestation.observedAt);
  const expiresAt = Date.parse(attestation.expiresAt);
  const canonicalJourneys = canonicalRuntimeAdapterJourneys(
    attestation.executionJourneys,
  );
  const canonicalComponents = canonicalRuntimeAdapterComponents(
    attestation.binding.componentReceiptSha256s,
  );
  const subjectValid = RUNTIME_ADAPTER_PUBLIC_ID.test(attestation.toolId)
    && (attestation.dependencyId === undefined
      ? attestation.parentBindingSha256 === undefined
      : RUNTIME_ADAPTER_PUBLIC_ID.test(attestation.dependencyId)
        && attestation.parentBindingSha256 !== undefined
        && RUNTIME_ADAPTER_SHA256.test(attestation.parentBindingSha256));
  const bindingValid = RUNTIME_ADAPTER_SHA256.test(
    attestation.binding.configurationSha256,
  )
    && RUNTIME_ADAPTER_SHA256.test(attestation.binding.providerReceiptSha256)
    && RUNTIME_ADAPTER_SHA256.test(attestation.binding.localManifestSha256)
    && attestation.binding.componentReceiptSha256s.length > 0
    && canonicalComponents.length === attestation.binding.componentReceiptSha256s.length
    && canonicalComponents.every(
      (value, index) => value === attestation.binding.componentReceiptSha256s[index]
        && RUNTIME_ADAPTER_SHA256.test(value),
    );
  const journeyValid = attestation.executionJourneys.length > 0
    && canonicalJourneys.length === attestation.executionJourneys.length
    && canonicalJourneys.every(
      (value, index) => value === attestation.executionJourneys[index],
    );
  if (!subjectValid
    || !bindingValid
    || !journeyValid
    || attestation.schemaVersion !== "ti-scale.runtime-adapter-attestation.v1"
    || attestation.source !== "autonomous_runtime_composition"
    || !RUNTIME_ADAPTER_SHA256.test(attestation.bindingSha256)
    || !RUNTIME_ADAPTER_SHA256.test(attestation.receiptSha256)
    || !Number.isFinite(observedAt)
    || new Date(observedAt).toISOString() !== attestation.observedAt
    || !Number.isFinite(expiresAt)
    || new Date(expiresAt).toISOString() !== attestation.expiresAt
    || expiresAt <= observedAt
    || expiresAt - observedAt > MAX_RUNTIME_ADAPTER_ATTESTATION_LIFETIME_MS) {
    return false;
  }
  const { receiptSha256, ...unsigned } = attestation;
  return attestation.bindingSha256 === runtimeAdapterBindingSha256(attestation)
    && receiptSha256 === runtimeAdapterReceiptSha256(unsigned);
}

export interface RuntimeToolManifest {
  readonly id: string;
  readonly label: string;
  readonly available: boolean;
  readonly locallyPolicyEnforced: boolean;
  readonly requiresModel?: boolean;
  /**
   * Whether a mission planner may select this exact binding. `available`
   * remains the runtime/dependency health fact used by self-tests and fleet
   * diagnostics; a healthy adapter can deliberately remain non-selectable
   * until its durable planning and result-persistence path is mounted.
   *
   * Missing preserves compatibility for existing reviewed bindings.
   */
  readonly missionSelectable?: boolean;
  /** Required operator-readable explanation when missionSelectable is false. */
  readonly missionSelectionReason?: string;
  /**
   * Journeys for which this exact mounted binding may grant execution.
   * Missing preserves the compatibility behavior of older reviewed runtime
   * manifests; new exact-step local adapters must declare this explicitly.
   */
  readonly executionJourneys?: readonly ("autonomous" | "guided")[];
  /**
   * Exact executable tool bindings that implement a planner-visible
   * composite action. Composite tools have no executable of their own and
   * are ready only while every named constituent has a current independent
   * activation receipt. A one-element list is valid for a derived-target
   * adapter that deliberately hides its physical tool from the planner.
   */
  readonly constituentToolIds?: readonly string[];
  readonly actionClassIds: readonly string[];
  readonly evidenceTypeIds: readonly string[];
  readonly deliverableIds?: readonly string[];
  readonly riskClassIds: readonly string[];
  readonly mcpServerId?: string;
  /**
   * Expiring proof for a planner-visible in-process adapter that has no
   * executable or MCP identity of its own. The trusted composition root emits
   * this only after validating the exact mounted adapter objects and their
   * versioned configuration. It must never be synthesized from a registry
   * boolean alone.
   */
  readonly runtimeAdapterAttestation?: Readonly<RuntimeAdapterAttestation>;
  readonly dependencies?: readonly {
    readonly id: string;
    readonly ready: boolean;
    /**
     * Optional expiring proof emitted by the trusted runtime that evaluated
     * this dependency. A manifest boolean alone is never fresh evidence.
     */
    readonly attestation?: Readonly<{
      readonly schemaVersion: "ti-scale.local-tool-activation-receipt.v1";
      readonly source: "local_guided_tool_activation";
      readonly manifestSha256: string;
      readonly toolBindingSha256: string;
      /** Exact hash of the bounded startup-probe specification. */
      readonly preflightBindingSha256: string;
      readonly executableSha256: string;
      readonly observedAt: string;
      readonly expiresAt: string;
    }>;
    /**
     * Component-specific proof for a dependency implemented inside the same
     * reviewed in-process adapter. Its binding hash is distinct from the
     * parent tool's hash so one dependency cannot stand in for another.
     */
    readonly runtimeAdapterAttestation?: Readonly<RuntimeAdapterAttestation>;
  }[];
}

export interface RuntimeMcpServerManifest {
  readonly id: string;
  readonly label: string;
  readonly status: "healthy" | "degraded" | "offline" | "unconfigured";
  readonly toolIds: readonly string[];
}

export interface RuntimeAgentManifest {
  readonly id: string;
  readonly label: string;
  readonly available: boolean;
  readonly capabilityIds: readonly string[];
  readonly actionClassIds?: readonly string[];
  readonly toolIds: readonly string[];
  readonly deliverableIds?: readonly string[];
  readonly modelRefs: readonly {
    readonly providerId: string;
    readonly modelId: string;
  }[];
}

export interface RuntimeProviderModelManifest {
  readonly id: string;
  readonly displayName: string;
  /**
   * Declares where consequential tool authority lives. The local deterministic
   * value is never sufficient by itself: model-catalog admission also proves
   * an exact available, locally enforced, no-model tool binding per action.
   */
  readonly executionBoundary?:
    | "provider_tool_calling"
    | "local_deterministic_policy";
  readonly toolCalling: boolean;
  readonly structuredOutput: boolean;
  readonly enforcement: Exclude<ModelEnforcementState, "unavailable">;
  readonly compatibleActionClassIds: readonly string[];
  readonly disclosureClasses: readonly string[];
  readonly contextLimit?: number;
  readonly reasoningEfforts?: readonly string[];
}

export interface RuntimeProviderManifest {
  readonly id: string;
  readonly authenticated: boolean;
  readonly healthy: boolean;
  readonly catalogObservedAt: string;
  readonly models: readonly RuntimeProviderModelManifest[];
}

export interface RuntimeSourceManifests {
  readonly riskClasses: readonly RuntimeRiskClassManifest[];
  readonly evidenceKinds: readonly RuntimeEvidenceKindManifest[];
  readonly capabilities: readonly RuntimeCapabilityManifest[];
  readonly tools: readonly RuntimeToolManifest[];
  readonly mcpServers: readonly RuntimeMcpServerManifest[];
  readonly agents: readonly RuntimeAgentManifest[];
  readonly providers: readonly RuntimeProviderManifest[];
}

/**
 * Fail-closed source used by the isolated preview until the live runtime has
 * supplied an attested capability manifest. Static registry definitions still
 * remain inspectable, but every operational capability resolves unsupported.
 */
export function emptyRuntimeSourceManifests(): RuntimeSourceManifests {
  return {
    riskClasses: [],
    evidenceKinds: [],
    capabilities: [],
    tools: [],
    mcpServers: [],
    agents: [],
    providers: [],
  };
}

export interface ActionCapabilityMapping {
  readonly actionClassId: ActionClassId;
  readonly availability: CapabilityAvailability;
  readonly riskClassIds: readonly string[];
  readonly agentIds: readonly string[];
  readonly availableAgentIds: readonly string[];
  readonly toolIds: readonly string[];
  readonly availableToolIds: readonly string[];
  readonly mcpServerIds: readonly string[];
  readonly providerModelRefs: readonly string[];
  readonly enforcedProviderModelRefs: readonly string[];
  readonly locallyEnforcedToolIds: readonly string[];
  readonly evidenceTypeIds: readonly EvidenceTypeId[];
  readonly enforcementReady: boolean;
  readonly readinessReasons: readonly string[];
}

export interface EvidenceCapabilityMapping {
  readonly evidenceTypeId: EvidenceTypeId;
  readonly runtimeEvidenceKindIds: readonly string[];
  readonly producerToolIds: readonly string[];
  readonly availability: CapabilityAvailability;
}

export interface DeliverableCapabilityMapping {
  readonly deliverableId: DeliverableId;
  readonly producerAgentIds: readonly string[];
  readonly producerToolIds: readonly string[];
  readonly availability: CapabilityAvailability;
}

export interface RuntimeCapabilityProjection {
  readonly actionClasses: Readonly<Record<ActionClassId, ActionCapabilityMapping>>;
  readonly evidenceTypes: Readonly<Record<EvidenceTypeId, EvidenceCapabilityMapping>>;
  readonly deliverables: Readonly<Record<DeliverableId, DeliverableCapabilityMapping>>;
  readonly models: readonly ProviderModelCapability[];
  readonly sourceCounts: {
    readonly riskClasses: number;
    readonly evidenceKinds: number;
    readonly capabilities: number;
    readonly tools: number;
    readonly mcpServers: number;
    readonly agents: number;
    readonly providers: number;
    readonly models: number;
  };
}

type RuntimeAdapterFreshness = "not_applicable" | "fresh" | "future" | "expired";

function runtimeAdapterFreshness(
  tool: RuntimeToolManifest,
  now: Date,
): RuntimeAdapterFreshness {
  const attestation = tool.runtimeAdapterAttestation;
  if (!attestation) return "not_applicable";
  const observedAt = Date.parse(attestation.observedAt);
  const expiresAt = Date.parse(attestation.expiresAt);
  if (observedAt > now.getTime()) return "future";
  return expiresAt <= now.getTime() ? "expired" : "fresh";
}

function sorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function assertUniqueIds<T extends { readonly id: string }>(
  kind: string,
  records: readonly T[],
): void {
  const seen = new Set<string>();
  for (const record of records) {
    if (record.id.trim().length === 0) {
      throw new Error(`${kind} manifest contains an empty id.`);
    }
    if (seen.has(record.id)) {
      throw new Error(`${kind} manifest contains duplicate id ${record.id}.`);
    }
    seen.add(record.id);
  }
}

function validateCatalogReferences(manifests: RuntimeSourceManifests): void {
  const unknown: string[] = [];
  const checkActionClasses = (owner: string, values: readonly string[]): void => {
    for (const value of values) {
      if (!isActionClassId(value)) unknown.push(`${owner}.actionClassIds:${value}`);
    }
  };
  const checkEvidenceTypes = (owner: string, values: readonly string[]): void => {
    for (const value of values) {
      if (!isEvidenceTypeId(value)) unknown.push(`${owner}.evidenceTypeIds:${value}`);
    }
  };
  const checkDeliverables = (owner: string, values: readonly string[]): void => {
    for (const value of values) {
      if (!isDeliverableId(value)) unknown.push(`${owner}.deliverableIds:${value}`);
    }
  };

  for (const risk of manifests.riskClasses) {
    checkActionClasses(`risk:${risk.id}`, risk.actionClassIds);
  }
  for (const evidence of manifests.evidenceKinds) {
    checkEvidenceTypes(`evidence-kind:${evidence.id}`, evidence.evidenceTypeIds);
  }
  for (const capability of manifests.capabilities) {
    checkActionClasses(`capability:${capability.id}`, capability.actionClassIds);
    checkEvidenceTypes(`capability:${capability.id}`, capability.evidenceTypeIds ?? []);
    checkDeliverables(`capability:${capability.id}`, capability.deliverableIds ?? []);
  }
  for (const tool of manifests.tools) {
    checkActionClasses(`tool:${tool.id}`, tool.actionClassIds);
    checkEvidenceTypes(`tool:${tool.id}`, tool.evidenceTypeIds);
    checkDeliverables(`tool:${tool.id}`, tool.deliverableIds ?? []);
  }
  for (const agent of manifests.agents) {
    checkActionClasses(`agent:${agent.id}`, agent.actionClassIds ?? []);
    checkDeliverables(`agent:${agent.id}`, agent.deliverableIds ?? []);
  }
  for (const provider of manifests.providers) {
    for (const model of provider.models) {
      checkActionClasses(
        `provider-model:${provider.id}/${model.id}`,
        model.compatibleActionClassIds,
      );
    }
  }

  if (unknown.length > 0) {
    throw new Error(`Runtime manifests reference unknown registry ids: ${unknown.join(", ")}`);
  }
}

function validateCrossReferences(manifests: RuntimeSourceManifests): void {
  const capabilityIds = new Set(manifests.capabilities.map(({ id }) => id));
  const toolIds = new Set(manifests.tools.map(({ id }) => id));
  const mcpIds = new Set(manifests.mcpServers.map(({ id }) => id));
  const modelRefs = new Set(
    manifests.providers.flatMap((provider) =>
      provider.models.map((model) => `${provider.id}/${model.id}`),
    ),
  );
  const errors: string[] = [];

  for (const tool of manifests.tools) {
    if (tool.mcpServerId !== undefined && !mcpIds.has(tool.mcpServerId)) {
      errors.push(`tool:${tool.id}.mcpServerId:${tool.mcpServerId}`);
    }
    for (const riskId of tool.riskClassIds) {
      if (!manifests.riskClasses.some(({ id }) => id === riskId)) {
        errors.push(`tool:${tool.id}.riskClassIds:${riskId}`);
      }
    }
    if (tool.missionSelectable === false
      && (typeof tool.missionSelectionReason !== "string"
        || tool.missionSelectionReason.trim().length < 20
        || tool.missionSelectionReason.trim().length > 500)) {
      errors.push(`tool:${tool.id}.missionSelectionReason:invalid`);
    }
    if (tool.missionSelectable !== false
      && tool.missionSelectionReason !== undefined) {
      errors.push(`tool:${tool.id}.missionSelectionReason:unexpected`);
    }
    if (tool.constituentToolIds !== undefined) {
      if (tool.mcpServerId !== undefined
        || tool.constituentToolIds.length < 1
        || new Set(tool.constituentToolIds).size !== tool.constituentToolIds.length) {
        errors.push(`tool:${tool.id}.constituentToolIds:invalid`);
      }
      for (const constituentToolId of tool.constituentToolIds) {
        const constituent = manifests.tools.find(({ id }) => id === constituentToolId);
        if (!constituent || constituent.id === tool.id
          || constituent.constituentToolIds !== undefined
          || constituent.mcpServerId !== undefined) {
          errors.push(`tool:${tool.id}.constituentToolIds:${constituentToolId}`);
        }
      }
    }
    const runtimeAttestation = tool.runtimeAdapterAttestation;
    const runtimeDependencyAttestations = (tool.dependencies ?? [])
      .map(({ runtimeAdapterAttestation: attestation }) => attestation)
      .filter((attestation): attestation is RuntimeAdapterAttestation =>
        attestation !== undefined);
    if (runtimeAttestation !== undefined) {
      const runtimeAttestationErrors: string[] = [];
      if (tool.mcpServerId !== undefined) runtimeAttestationErrors.push("mcp");
      if (tool.constituentToolIds !== undefined) runtimeAttestationErrors.push("constituents");
      if (!runtimeAdapterAttestationIntegrityValid(runtimeAttestation)
        || runtimeAttestation.toolId !== tool.id
        || runtimeAttestation.dependencyId !== undefined
        || runtimeAttestation.parentBindingSha256 !== undefined) {
        runtimeAttestationErrors.push("receipt");
      }
      if (tool.executionJourneys === undefined
        || tool.executionJourneys.length !== runtimeAttestation.executionJourneys.length
        || !tool.executionJourneys.every(
          (journey, index) => journey === runtimeAttestation.executionJourneys[index],
        )) {
        runtimeAttestationErrors.push("journey");
      }
      if ((tool.dependencies ?? []).some(({ attestation }) => attestation !== undefined)) {
        runtimeAttestationErrors.push("mixed-local-dependency");
      }
      if (runtimeDependencyAttestations.length !== (tool.dependencies ?? []).length) {
        runtimeAttestationErrors.push("missing-runtime-dependency");
      }
      if (runtimeAttestationErrors.length > 0) {
        errors.push(
          `tool:${tool.id}.runtimeAdapterAttestation:${runtimeAttestationErrors.join("+")}`,
        );
      } else {
        const dependencyHashes = new Set<string>();
        for (const dependency of tool.dependencies ?? []) {
          const dependencyAttestation = dependency.runtimeAdapterAttestation!;
          if (!runtimeAdapterAttestationIntegrityValid(dependencyAttestation)
            || dependencyAttestation.toolId !== tool.id
            || dependencyAttestation.dependencyId !== dependency.id
            || dependencyAttestation.parentBindingSha256
              !== runtimeAttestation.bindingSha256
            || dependencyAttestation.executionJourneys.length
              !== runtimeAttestation.executionJourneys.length
            || !dependencyAttestation.executionJourneys.every(
              (journey, index) =>
                journey === runtimeAttestation.executionJourneys[index],
            )
            || dependencyAttestation.observedAt !== runtimeAttestation.observedAt
            || dependencyAttestation.expiresAt !== runtimeAttestation.expiresAt
            || dependencyAttestation.bindingSha256 === runtimeAttestation.bindingSha256
            || dependencyHashes.has(dependencyAttestation.bindingSha256)) {
            errors.push(`tool:${tool.id}.dependencies.runtimeAdapterAttestation:invalid`);
            break;
          }
          dependencyHashes.add(dependencyAttestation.bindingSha256);
        }
      }
    } else if (runtimeDependencyAttestations.length > 0) {
      errors.push(`tool:${tool.id}.dependencies.runtimeAdapterAttestation:orphan`);
    }
  }
  for (const server of manifests.mcpServers) {
    for (const toolId of server.toolIds) {
      if (!toolIds.has(toolId)) errors.push(`mcp:${server.id}.toolIds:${toolId}`);
    }
  }
  for (const agent of manifests.agents) {
    for (const capabilityId of agent.capabilityIds) {
      if (!capabilityIds.has(capabilityId)) {
        errors.push(`agent:${agent.id}.capabilityIds:${capabilityId}`);
      }
    }
    for (const toolId of agent.toolIds) {
      if (!toolIds.has(toolId)) errors.push(`agent:${agent.id}.toolIds:${toolId}`);
    }
    for (const ref of agent.modelRefs) {
      const modelRef = `${ref.providerId}/${ref.modelId}`;
      if (!modelRefs.has(modelRef)) errors.push(`agent:${agent.id}.modelRefs:${modelRef}`);
    }
  }
  for (const provider of manifests.providers) {
    for (const model of provider.models) {
      if (
        model.executionBoundary !== undefined
        && model.executionBoundary !== "provider_tool_calling"
        && model.executionBoundary !== "local_deterministic_policy"
      ) {
        errors.push(
          `provider-model:${provider.id}/${model.id}.executionBoundary:invalid`,
        );
      }
    }
  }

  if (errors.length > 0) {
    throw new Error(`Runtime manifests contain broken references: ${errors.join(", ")}`);
  }
}

export function buildRuntimeCapabilityProjection(
  manifests: RuntimeSourceManifests,
  now: Date = new Date(),
): RuntimeCapabilityProjection {
  if (!Number.isFinite(now.getTime())) {
    throw new TypeError("Runtime capability projection time is invalid.");
  }
  assertUniqueIds("risk class", manifests.riskClasses);
  assertUniqueIds("evidence kind", manifests.evidenceKinds);
  assertUniqueIds("capability", manifests.capabilities);
  assertUniqueIds("tool", manifests.tools);
  assertUniqueIds("MCP server", manifests.mcpServers);
  assertUniqueIds("agent", manifests.agents);
  assertUniqueIds("provider", manifests.providers);
  for (const provider of manifests.providers) {
    assertUniqueIds(`provider ${provider.id} model`, provider.models);
  }
  for (const tool of manifests.tools) {
    assertUniqueIds(`tool ${tool.id} dependency`, tool.dependencies ?? []);
  }
  validateCatalogReferences(manifests);
  validateCrossReferences(manifests);

  const capabilitiesById = new Map(manifests.capabilities.map((item) => [item.id, item]));
  const mcpById = new Map(manifests.mcpServers.map((item) => [item.id, item]));
  const models: ProviderModelCapability[] = manifests.providers.flatMap((provider) =>
    provider.models.map((model) => ({
      providerId: provider.id,
      modelId: model.id,
      displayName: model.displayName,
      providerAuthenticated: provider.authenticated,
      providerHealthy: provider.healthy,
      catalogObservedAt: provider.catalogObservedAt,
      toolCalling: model.toolCalling,
      structuredOutput: model.structuredOutput,
      declaredEnforcement: model.enforcement,
      compatibleActionClassIds: model.compatibleActionClassIds.filter(isActionClassId),
      disclosureClasses: model.disclosureClasses,
      contextLimit: model.contextLimit,
      reasoningEfforts: model.reasoningEfforts,
    })),
  );
  const modelsByRef = new Map(
    models.map((model) => [`${model.providerId}/${model.modelId}`, model]),
  );

  const actionClasses = Object.fromEntries(
    ACTION_CLASS_IDS.map((actionClassId): [ActionClassId, ActionCapabilityMapping] => {
      const riskClassIds = manifests.riskClasses
        .filter(({ actionClassIds }) => actionClassIds.includes(actionClassId))
        .map(({ id }) => id);
      const agents = manifests.agents.filter((agent) => {
        if (agent.actionClassIds?.includes(actionClassId)) return true;
        return agent.capabilityIds.some((capabilityId) =>
          capabilitiesById.get(capabilityId)?.actionClassIds.includes(actionClassId),
        );
      });
      const tools = manifests.tools.filter(({ actionClassIds }) =>
        actionClassIds.includes(actionClassId),
      );
      const actionToolIds = new Set(tools.map(({ id }) => id));
      // A capability is executable only when one declared specialist is
      // actually bound to one of the tools that implements this exact action
      // class. Keeping the unjoined agent and tool lists below is useful for
      // diagnostics, but it must never manufacture a runnable route.
      const toolBoundAgents = agents.filter(({ toolIds }) =>
        toolIds.some((toolId) => actionToolIds.has(toolId)),
      );
      const availableTools = tools.filter((tool) => {
        const dependenciesReady = (tool.dependencies ?? []).every(({ ready }) => ready);
        const mcpReady =
          tool.mcpServerId === undefined || mcpById.get(tool.mcpServerId)?.status === "healthy";
        const adapterFreshness = runtimeAdapterFreshness(tool, now);
        return tool.available
          && tool.missionSelectable !== false
          && dependenciesReady
          && mcpReady
          && (adapterFreshness === "not_applicable" || adapterFreshness === "fresh");
      });
      const availableAgents = toolBoundAgents.filter(({ available }) => available);
      const providerModelRefs = sorted(
        toolBoundAgents.flatMap(({ modelRefs }) =>
          modelRefs.map(({ providerId, modelId }) => `${providerId}/${modelId}`),
        ),
      );
      const availableAgentModelRefs = new Set(availableAgents.flatMap(({ modelRefs }) =>
        modelRefs.map(({ providerId, modelId }) => `${providerId}/${modelId}`)));
      const enforcedProviderModelRefs = providerModelRefs.filter((ref) => {
        const model = modelsByRef.get(ref);
        return availableAgentModelRefs.has(ref)
          && model !== undefined
          && model.providerAuthenticated
          && model.providerHealthy
          && model.toolCalling
          && model.structuredOutput
          && model.declaredEnforcement === "enforced_executor"
          && model.compatibleActionClassIds.includes(actionClassId);
      });
      const locallyEnforcedTools = availableTools.filter(
        ({ locallyPolicyEnforced, executionJourneys }) => locallyPolicyEnforced
          && (executionJourneys === undefined || executionJourneys.includes("autonomous")),
      );
      const enforcedProviderModelRefSet = new Set(enforcedProviderModelRefs);
      const enforcementReady = availableAgents.some((agent) => {
        const agentModelRefs = agent.modelRefs.map(({ providerId, modelId }) =>
          `${providerId}/${modelId}`);
        return locallyEnforcedTools.some((tool) => agent.toolIds.includes(tool.id)
          && (tool.requiresModel === false
            || agentModelRefs.some((modelRef) => enforcedProviderModelRefSet.has(modelRef))));
      });
      const readinessReasons: string[] = [];

      if (agents.length === 0) readinessReasons.push("No agent declares this action class.");
      if (tools.length === 0) readinessReasons.push("No runtime tool declares this action class.");
      if (agents.length > 0 && toolBoundAgents.length === 0 && tools.length > 0) {
        readinessReasons.push(
          `No declared agent is bound to the mapped tool${tools.length === 1 ? "" : "s"}: ${sorted(tools.map(({ id }) => id)).join(", ")}.`,
        );
      } else if (toolBoundAgents.length > 0 && availableAgents.length === 0) {
        readinessReasons.push(
          `Mapped agent${toolBoundAgents.length === 1 ? " is" : "s are"} unavailable: ${sorted(toolBoundAgents.map(({ id }) => id)).join(", ")}.`,
        );
      }
      if (tools.length > 0 && availableTools.length === 0) {
        for (const tool of tools) {
          const missingDependencies = (tool.dependencies ?? [])
            .filter(({ ready }) => !ready)
            .map(({ id }) => id);
          const mcp = tool.mcpServerId === undefined
            ? undefined
            : mcpById.get(tool.mcpServerId);
          const adapterFreshness = runtimeAdapterFreshness(tool, now);
          if (!tool.available && tool.mcpServerId === undefined) {
            readinessReasons.push(
              `${tool.id} has no current activation receipt; run its reviewed target-free activation probe.`,
            );
          } else if (!tool.available && mcp?.status === "healthy") {
            readinessReasons.push(
              `${tool.id} is absent or unavailable in the current closed inventory for MCP server ${tool.mcpServerId}; repeat that server's tools/list attestation.`,
            );
          }
          if (tool.available && tool.missionSelectable === false) {
            readinessReasons.push(
              `${tool.id} is healthy for runtime inspection but is not mission-selectable: ${tool.missionSelectionReason}.`,
            );
          }
          if (adapterFreshness === "future") {
            readinessReasons.push(
              `${tool.id} has a future-dated runtime-composition receipt; re-attest it against the current trusted clock.`,
            );
          } else if (adapterFreshness === "expired") {
            readinessReasons.push(
              `${tool.id} has an expired runtime-composition receipt; recompose the exact reviewed in-process adapter before mission use.`,
            );
          }
          if (missingDependencies.length > 0) {
            readinessReasons.push(
              `${tool.id} is waiting for ${missingDependencies.length === 1 ? "dependency" : "dependencies"}: ${sorted(missingDependencies).join(", ")}.`,
            );
          }
          if (tool.mcpServerId !== undefined && mcp?.status !== "healthy") {
            readinessReasons.push(
              `${tool.id} requires MCP server ${tool.mcpServerId}, which is ${mcp?.status ?? "not registered"}; restore that exact server and repeat its inventory attestation.`,
            );
          }
        }
      } else if (availableTools.length > 0 && availableAgents.length > 0) {
        const agentToolIds = new Set(availableAgents.flatMap(({ toolIds }) => toolIds));
        const unassignedReadyTools = availableTools.filter(({ id }) => !agentToolIds.has(id));
        if (unassignedReadyTools.length === availableTools.length) {
          readinessReasons.push(
            `Ready tool${availableTools.length === 1 ? " is" : "s are"} not assigned to an available specialist: ${sorted(availableTools.map(({ id }) => id)).join(", ")}.`,
          );
        }
      }
      if (!enforcementReady && agents.length > 0 && tools.length > 0) {
        const autonomousDenied = availableTools.filter(({ locallyPolicyEnforced, executionJourneys }) =>
          locallyPolicyEnforced && executionJourneys !== undefined
          && !executionJourneys.includes("autonomous"));
        const unenforced = availableTools.filter(({ locallyPolicyEnforced }) => !locallyPolicyEnforced);
        const modelRequired = locallyEnforcedTools.filter(({ requiresModel }) => requiresModel !== false);
        if (autonomousDenied.length > 0) {
          readinessReasons.push(
            `Ready tool${autonomousDenied.length === 1 ? "" : "s"} ${sorted(autonomousDenied.map(({ id }) => id)).join(", ")} ${autonomousDenied.length === 1 ? "is" : "are"} approved for ${sorted(autonomousDenied.flatMap(({ executionJourneys }) => executionJourneys ?? [])).join(" and ") || "no"} execution, not Autonomous execution.`,
          );
        }
        if (unenforced.length > 0) {
          readinessReasons.push(
            `Ready tool${unenforced.length === 1 ? "" : "s"} ${sorted(unenforced.map(({ id }) => id)).join(", ")} ${unenforced.length === 1 ? "has" : "have"} no locally enforced policy adapter.`,
          );
        }
        if (modelRequired.length > 0 && enforcedProviderModelRefs.length === 0) {
          readinessReasons.push(
            `Model-backed tool${modelRequired.length === 1 ? "" : "s"} ${sorted(modelRequired.map(({ id }) => id)).join(", ")} ${modelRequired.length === 1 ? "requires" : "require"} a healthy authenticated enforced-executor model assigned to the same specialist.`,
          );
        }
        if (readinessReasons.length === 0) {
          readinessReasons.push("No available specialist is joined to a locally enforced tool and compatible executor route for this action class.");
        }
      }

      const hasMappings = agents.length > 0 && tools.length > 0;
      const joinedAvailableRoute = availableAgents.some((agent) =>
        availableTools.some((tool) => agent.toolIds.includes(tool.id)));
      const availability: CapabilityAvailability = !hasMappings
        ? "unsupported"
        : joinedAvailableRoute
          ? "supported"
          : "unavailable";

      return [
        actionClassId,
        {
          actionClassId,
          availability,
          riskClassIds: sorted([
            ...riskClassIds,
            ...tools.flatMap(({ riskClassIds }) => riskClassIds),
          ]),
          agentIds: sorted(agents.map(({ id }) => id)),
          availableAgentIds: sorted(availableAgents.map(({ id }) => id)),
          toolIds: sorted(tools.map(({ id }) => id)),
          availableToolIds: sorted(availableTools.map(({ id }) => id)),
          mcpServerIds: sorted(
            tools.flatMap(({ mcpServerId }) => (mcpServerId === undefined ? [] : [mcpServerId])),
          ),
          providerModelRefs,
          enforcedProviderModelRefs,
          locallyEnforcedToolIds: sorted(locallyEnforcedTools.map(({ id }) => id)),
          evidenceTypeIds: sorted(
            tools.flatMap(({ evidenceTypeIds }) => evidenceTypeIds),
          ).filter(isEvidenceTypeId),
          enforcementReady,
          readinessReasons,
        },
      ];
    }),
  ) as Record<ActionClassId, ActionCapabilityMapping>;

  const evidenceTypes = Object.fromEntries(
    EVIDENCE_TYPE_IDS.map((evidenceTypeId): [EvidenceTypeId, EvidenceCapabilityMapping] => {
      const runtimeEvidenceKindIds = manifests.evidenceKinds
        .filter(({ evidenceTypeIds }) => evidenceTypeIds.includes(evidenceTypeId))
        .map(({ id }) => id);
      const producerTools = manifests.tools.filter(({ evidenceTypeIds }) =>
        evidenceTypeIds.includes(evidenceTypeId),
      );
      const availableProducer = producerTools.some((tool) => {
        const dependenciesReady = (tool.dependencies ?? []).every(({ ready }) => ready);
        const mcpReady =
          tool.mcpServerId === undefined || mcpById.get(tool.mcpServerId)?.status === "healthy";
        return tool.available && dependenciesReady && mcpReady;
      });
      const hasSource = runtimeEvidenceKindIds.length > 0 || producerTools.length > 0;
      return [
        evidenceTypeId,
        {
          evidenceTypeId,
          runtimeEvidenceKindIds: sorted(runtimeEvidenceKindIds),
          producerToolIds: sorted(producerTools.map(({ id }) => id)),
          availability: !hasSource
            ? "unsupported"
            : availableProducer || (runtimeEvidenceKindIds.length > 0 && producerTools.length === 0)
              ? "supported"
              : "unavailable",
        },
      ];
    }),
  ) as Record<EvidenceTypeId, EvidenceCapabilityMapping>;

  const deliverables = Object.fromEntries(
    DELIVERABLE_IDS.map((deliverableId): [DeliverableId, DeliverableCapabilityMapping] => {
      const agents = manifests.agents.filter((agent) => {
        if (agent.deliverableIds?.includes(deliverableId)) return true;
        return agent.capabilityIds.some((capabilityId) =>
          capabilitiesById.get(capabilityId)?.deliverableIds?.includes(deliverableId),
        );
      });
      const tools = manifests.tools.filter(({ deliverableIds }) =>
        deliverableIds?.includes(deliverableId),
      );
      const hasProducer = agents.length > 0 || tools.length > 0;
      const availableProducer =
        agents.some(({ available }) => available) || tools.some(({ available }) => available);
      return [
        deliverableId,
        {
          deliverableId,
          producerAgentIds: sorted(agents.map(({ id }) => id)),
          producerToolIds: sorted(tools.map(({ id }) => id)),
          availability: !hasProducer
            ? "unsupported"
            : availableProducer
              ? "supported"
              : "unavailable",
        },
      ];
    }),
  ) as Record<DeliverableId, DeliverableCapabilityMapping>;

  return {
    actionClasses,
    evidenceTypes,
    deliverables,
    models,
    sourceCounts: {
      riskClasses: manifests.riskClasses.length,
      evidenceKinds: manifests.evidenceKinds.length,
      capabilities: manifests.capabilities.length,
      tools: manifests.tools.length,
      mcpServers: manifests.mcpServers.length,
      agents: manifests.agents.length,
      providers: manifests.providers.length,
      models: models.length,
    },
  };
}

import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  buildRuntimeCapabilityProjection,
  isSpecialistMcpExecutionPolicy,
  runtimeAdapterAttestationIntegrityValid,
  type RuntimeAgentManifest,
  type RuntimeSourceManifests,
  type RuntimeToolManifest,
} from "../domain";
import {
  isMcpAttestationFresh,
} from "../mcp";
import type { JsonValue } from "../events";
import {
  agentAssignmentBindsRuntimeAgent,
  productAgentIdForActionClass,
} from "../agents";
import type { AutonomousPlanningSelection } from "../model-config";
import {
  ModelConfigurationRepository,
  modelConfigurationBindingHash,
} from "../model-config";
import type { StoredModelConfiguration } from "../model-config/types";
import {
  CommandRuntimeError,
  type AutonomousActivationBoundaryReceipt,
  type AutonomousActivationRuntimePort,
} from "../command-runtime/types";
import type { RuntimeProjectionInput } from "../app/RuntimeProjectionService";
import {
  activationHashCanonical,
  autonomousActivationEvidencePolicyHash,
  AutonomousActivationReceiptRepository,
} from "./AutonomousActivationReceiptRepository";
import {
  AutonomousActivationReceiptIntegrityError,
  type AutonomousActivationPlanningInput,
  type AutonomousActivationReceipt,
  type AutonomousActivationRouteInput,
} from "./AutonomousActivationReceiptTypes";
import { AutonomousActivationReceiptVerifier } from "./AutonomousActivationReceiptVerifier";
import type { LocalAutonomousPlannerBindingReceipt } from "./types";

const SHA256 = /^[a-f0-9]{64}$/u;
const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,300}$/u;
const LOCAL_ACTIVATION_SCHEMA = "ti-scale.local-tool-activation-receipt.v1";
const RUNTIME_GENERATION_SCHEMA =
  "ti-scale.autonomous-runtime-generation.v1";

interface RunAuthorityRow {
  readonly mission_id: string;
  readonly journey: string;
  readonly contract_id: string | null;
  readonly contract_version_bound: number | null;
  readonly contract_hash_bound: string | null;
  readonly action_policy_json: string;
}

interface AssignmentRow {
  readonly id: string;
  readonly agent_id: string;
  readonly assignment_purpose: "execution" | "planning";
  readonly primary_configuration_id: string;
  readonly fallback_configuration_id: string | null;
  readonly provider_id: string;
  readonly model_id: string;
}

interface ActionRouteRow {
  readonly id: string;
  readonly action_class: string;
  readonly action_type: string;
  readonly fingerprint: string;
  readonly normalized_arguments_json: string;
  readonly contract_id: string | null;
  readonly context_pack_id: string | null;
  readonly plan_id: string;
  readonly step_id: string;
  readonly step_agent_id: string | null;
  readonly assignment_id: string | null;
  readonly assignment_agent_id: string | null;
}

interface ResolvedActivationProof {
  readonly id: string;
  readonly hash: string;
  readonly expiresAt: string;
  readonly evidenceProducerIds: readonly string[];
}

interface RuntimeGeneration {
  readonly projection: RuntimeProjectionInput;
  readonly manifests: RuntimeSourceManifests;
  readonly hash: string;
  readonly now: Date;
}

function stableRuntimeAdapterProof(
  attestation: RuntimeToolManifest["runtimeAdapterAttestation"],
): unknown {
  if (!attestation) return null;
  return {
    schemaVersion: attestation.schemaVersion,
    source: attestation.source,
    toolId: attestation.toolId,
    dependencyId: attestation.dependencyId ?? null,
    parentBindingSha256: attestation.parentBindingSha256 ?? null,
    executionJourneys: [...attestation.executionJourneys].sort(),
    binding: {
      configurationSha256: attestation.binding.configurationSha256,
      providerReceiptSha256: attestation.binding.providerReceiptSha256,
      localManifestSha256: attestation.binding.localManifestSha256,
      componentReceiptSha256s:
        [...attestation.binding.componentReceiptSha256s].sort(),
    },
    bindingSha256: attestation.bindingSha256,
  };
}

/**
 * Capability generation deliberately excludes expiring observation fields.
 * A health coordinator may refresh observedAt/expiresAt every few seconds
 * without changing the mounted executable, tool schema, model, or policy.
 * Those fresh proofs are still sealed into each immutable receipt route and
 * become mandatory when the previous receipt reaches its bounded expiry.
 */
function stableRuntimeGenerationPreimage(
  projection: RuntimeProjectionInput,
  manifests: RuntimeSourceManifests,
  executionBindings: readonly LocalAutonomousPlannerBindingReceipt[],
): unknown {
  return {
    schemaVersion: RUNTIME_GENERATION_SCHEMA,
    riskClasses: [...manifests.riskClasses].sort((left, right) =>
      left.id.localeCompare(right.id, "en-US")),
    evidenceKinds: [...manifests.evidenceKinds].sort((left, right) =>
      left.id.localeCompare(right.id, "en-US")),
    capabilities: [...manifests.capabilities].sort((left, right) =>
      left.id.localeCompare(right.id, "en-US")),
    tools: manifests.tools.map((tool) => ({
      id: tool.id,
      label: tool.label,
      available: tool.available,
      locallyPolicyEnforced: tool.locallyPolicyEnforced,
      requiresModel: tool.requiresModel ?? null,
      executionJourneys: [...(tool.executionJourneys ?? [])].sort(),
      constituentToolIds: [...(tool.constituentToolIds ?? [])].sort(),
      actionClassIds: [...tool.actionClassIds].sort(),
      evidenceTypeIds: [...tool.evidenceTypeIds].sort(),
      deliverableIds: [...(tool.deliverableIds ?? [])].sort(),
      riskClassIds: [...tool.riskClassIds].sort(),
      mcpServerId: tool.mcpServerId ?? null,
      runtimeAdapter: stableRuntimeAdapterProof(
        tool.runtimeAdapterAttestation,
      ),
      dependencies: (tool.dependencies ?? []).map((dependency) => ({
        id: dependency.id,
        ready: dependency.ready,
        activationBinding: dependency.attestation
          ? {
              schemaVersion: dependency.attestation.schemaVersion,
              source: dependency.attestation.source,
              manifestSha256: dependency.attestation.manifestSha256,
              toolBindingSha256: dependency.attestation.toolBindingSha256,
              preflightBindingSha256:
                dependency.attestation.preflightBindingSha256,
              executableSha256: dependency.attestation.executableSha256,
            }
          : null,
        runtimeAdapter: stableRuntimeAdapterProof(
          dependency.runtimeAdapterAttestation,
        ),
      })).sort((left, right) => left.id.localeCompare(right.id, "en-US")),
    })).sort((left, right) => left.id.localeCompare(right.id, "en-US")),
    mcpServers: [...manifests.mcpServers].sort((left, right) =>
      left.id.localeCompare(right.id, "en-US")),
    agents: manifests.agents.map((agent) => ({
      ...agent,
      capabilityIds: [...agent.capabilityIds].sort(),
      actionClassIds: [...(agent.actionClassIds ?? [])].sort(),
      toolIds: [...agent.toolIds].sort(),
      deliverableIds: [...(agent.deliverableIds ?? [])].sort(),
      modelRefs: [...agent.modelRefs].sort((left, right) =>
        `${left.providerId}\u0000${left.modelId}`.localeCompare(
          `${right.providerId}\u0000${right.modelId}`,
          "en-US",
        )),
    })).sort((left, right) => left.id.localeCompare(right.id, "en-US")),
    providers: manifests.providers.map((provider) => ({
      id: provider.id,
      authenticated: provider.authenticated,
      healthy: provider.healthy,
      models: [...provider.models].sort((left, right) =>
        left.id.localeCompare(right.id, "en-US")),
    })).sort((left, right) => left.id.localeCompare(right.id, "en-US")),
    mcpRoutes: projection.mcpServers.map((server) => {
      const attestation = server.capabilityAttestation;
      return {
        id: server.id,
        status: server.status,
        policy: server.policy,
        capability: attestation
          ? {
              schemaVersion: attestation.schemaVersion,
              connectionId: attestation.connectionId,
              transport: attestation.transport,
              server: attestation.server,
              protocolVersion: attestation.protocolVersion,
              capabilities: attestation.capabilities,
              configurationSha256: attestation.configurationSha256,
              tools: [...attestation.tools].sort((left, right) =>
                left.name.localeCompare(right.name, "en-US")),
              executionAuthorization: attestation.executionAuthorization,
            }
          : null,
      };
    }).sort((left, right) => left.id.localeCompare(right.id, "en-US")),
    exactExecutionBindings: [...executionBindings].sort((left, right) =>
      left.bindingId.localeCompare(right.bindingId, "en-US")),
  };
}

function uniqueSorted(
  values: readonly string[],
  label: string,
  options: Readonly<{ allowEmpty?: boolean }> = {},
): string[] {
  const normalized = values.map((value) => value.trim());
  if (
    (!options.allowEmpty && normalized.length === 0) ||
    normalized.some((value) => !value || !PUBLIC_ID.test(value)) ||
    new Set(normalized).size !== normalized.length
  ) {
    throw activationFailure(
      "activation_route_invalid",
      `${label} must contain unique stable IDs`,
      "policy_denied",
      "Reconcile the signed contract and exact runtime manifests, then start a new run.",
    );
  }
  return normalized.sort((left, right) => left.localeCompare(right, "en-US"));
}

function timestamp(value: string, label: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw activationFailure(
      "activation_proof_invalid",
      `${label} is not a canonical timestamp`,
      "dependency_missing",
      "Re-attest the exact runtime component against the trusted local clock.",
    );
  }
  return parsed;
}

function activationFailure(
  code: string,
  message: string,
  category: string,
  remediation: string,
  details?: JsonValue,
): CommandRuntimeError {
  return new CommandRuntimeError(409, code, message, {
    humanMessage:
      `Safe-stopped before runtime contact because the Autonomous activation boundary could not be verified: ${message}`,
    retryable: false,
    category,
    ...(details ? { details } : {}),
    remediation,
  });
}

function mapIntegrityError(error: unknown): CommandRuntimeError {
  if (error instanceof CommandRuntimeError) return error;
  if (error instanceof AutonomousActivationReceiptIntegrityError) {
    const tampered = error.code === "activation_receipt_tampered"
      || error.code === "activation_binding_chain_invalid";
    const drift = error.code === "activation_receipt_runtime_generation_drift";
    const expired = error.code === "activation_receipt_expired";
    return activationFailure(
      error.code,
      error.message,
      tampered ? "policy_denied" : "dependency_missing",
      tampered
        ? "Inspect the immutable receipt, model pins, Context Pack, and binding chain; do not resume this run in place."
        : drift
          ? "Restore the exact attested runtime generation or start a new run against the newly reviewed generation."
          : expired
            ? "Refresh runtime activation through a new reviewed run; expired authority is never renewed in place."
            : "Restore the exact signed contract, model pins, Brain Context Pack, and attested runtime route, then start a new run.",
    );
  }
  return activationFailure(
    "activation_runtime_resolution_failed",
    error instanceof Error ? error.message : "Autonomous activation failed",
    "dependency_missing",
    "Inspect the exact runtime manifest and activation receipts, then start a new run after readiness is current.",
  );
}

function record(value: unknown, label: string): Readonly<Record<string, unknown>> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw activationFailure(
      "activation_contract_invalid",
      `${label} is not an object`,
      "policy_denied",
      "Create a new run from a schema-valid confirmed Autonomous contract.",
    );
  }
  return value as Readonly<Record<string, unknown>>;
}

function stringArray(
  value: unknown,
  label: string,
  options: Readonly<{ allowEmpty?: boolean }> = {},
): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw activationFailure(
      "activation_contract_invalid",
      `${label} is not a string list`,
      "policy_denied",
      "Create a new run from a schema-valid confirmed Autonomous contract.",
    );
  }
  return uniqueSorted(value, label, options);
}

function planningSelection(value: unknown): AutonomousPlanningSelection {
  const input = record(value, "Contract planning selection");
  if (input.route === "local_deterministic") {
    return input as unknown as Extract<
      AutonomousPlanningSelection,
      { readonly route: "local_deterministic" }
    >;
  }
  if (input.route === "provider_advisory") {
    return input as unknown as Extract<
      AutonomousPlanningSelection,
      { readonly route: "provider_advisory" }
    >;
  }
  throw activationFailure(
    "activation_planning_selection_invalid",
    "The signed contract has no supported planning selection",
    "policy_denied",
    "Create a new run with either the exact local deterministic or provider-advisory planning route.",
  );
}

function boundary(receipt: AutonomousActivationReceipt): AutonomousActivationBoundaryReceipt {
  return {
    receiptId: receipt.id,
    receiptHash: receipt.receiptHash,
    runtimeGenerationHash: receipt.runtimeGenerationHash,
    evidencePolicyHash: receipt.evidencePolicyHash,
    expiresAt: receipt.expiresAt,
    items: Object.freeze(receipt.items.map((item) => Object.freeze({
      actionClassId: item.actionClassId,
      evidenceTypeIds: Object.freeze([...item.evidenceTypeIds]),
    }))),
    planning: receipt.planning.route === "local_deterministic"
      ? {
          route: receipt.planning.route,
          plannerId: receipt.planning.plannerId,
        }
      : {
          route: receipt.planning.route,
          plannerId: receipt.planning.plannerId,
          modelAssignmentId: receipt.planning.modelAssignmentId,
          primaryConfigurationId: receipt.planning.primaryConfigurationId,
          fallbackConfigurationId: receipt.planning.fallbackConfigurationId,
          primaryConfigurationHash: receipt.planning.primaryConfigurationHash,
          fallbackConfigurationHash: receipt.planning.fallbackConfigurationHash,
        },
  };
}

function localDependencyProof(
  tool: RuntimeToolManifest,
  now: Date,
): ResolvedActivationProof {
  const dependencies = tool.dependencies ?? [];
  if (dependencies.length === 0 || dependencies.some(({ ready }) => !ready)) {
    throw activationFailure(
      "activation_local_proof_missing",
      `Tool ${tool.id} has no complete local activation dependency set`,
      "dependency_missing",
      "Run the reviewed target-free activation probe for this exact tool and retry through a new run.",
    );
  }
  const attestations = dependencies.map(({ attestation }) => attestation);
  if (attestations.some((attestation) => attestation === undefined)) {
    throw activationFailure(
      "activation_local_proof_missing",
      `Tool ${tool.id} exposes readiness without an activation attestation`,
      "dependency_missing",
      "Publish the exact expiring local-tool activation receipt instead of readiness booleans.",
    );
  }
  const first = attestations[0]!;
  const firstHash = activationHashCanonical(first);
  const observedAt = timestamp(first.observedAt, `${tool.id} activation observedAt`);
  const expiresAt = timestamp(first.expiresAt, `${tool.id} activation expiresAt`);
  const exact = first.schemaVersion === LOCAL_ACTIVATION_SCHEMA
    && first.source === "local_guided_tool_activation"
    && SHA256.test(first.manifestSha256)
    && SHA256.test(first.toolBindingSha256)
    && SHA256.test(first.preflightBindingSha256)
    && SHA256.test(first.executableSha256)
    && observedAt <= now.getTime()
    && expiresAt > now.getTime()
    && expiresAt > observedAt
    && attestations.every((attestation) =>
      attestation !== undefined
      && activationHashCanonical(attestation) === firstHash);
  if (!exact) {
    throw activationFailure(
      "activation_local_proof_invalid",
      `Tool ${tool.id} has an expired, future-dated, mismatched, or malformed activation proof`,
      "dependency_missing",
      "Repeat the exact local activation probe and start a new run after the new receipt is current.",
    );
  }
  const proof = {
    schemaVersion: "ti-scale.aggregate-local-tool-proof.v1",
    toolId: tool.id,
    dependencyIds: uniqueSorted(
      dependencies.map(({ id }) => id),
      `${tool.id} activation dependencies`,
    ),
    attestation: first,
  };
  const hash = activationHashCanonical(proof);
  return {
    id: `local-tool:${tool.id}:${hash.slice(0, 32)}`,
    hash,
    expiresAt: first.expiresAt,
    evidenceProducerIds: [tool.id],
  };
}

function runtimeAdapterProof(
  tool: RuntimeToolManifest,
  now: Date,
): ResolvedActivationProof {
  const attestation = tool.runtimeAdapterAttestation;
  if (
    !attestation ||
    !runtimeAdapterAttestationIntegrityValid(attestation) ||
    attestation.toolId !== tool.id ||
    !attestation.executionJourneys.includes("autonomous") ||
    timestamp(attestation.observedAt, `${tool.id} adapter observedAt`) > now.getTime() ||
    timestamp(attestation.expiresAt, `${tool.id} adapter expiresAt`) <= now.getTime()
  ) {
    throw activationFailure(
      "activation_runtime_adapter_proof_invalid",
      `Runtime adapter ${tool.id} has no current integrity-valid Autonomous receipt`,
      "dependency_missing",
      "Recompose the exact reviewed adapter and start a new run against its current receipt.",
    );
  }
  for (const dependency of tool.dependencies ?? []) {
    const child = dependency.runtimeAdapterAttestation;
    if (
      !dependency.ready ||
      !child ||
      !runtimeAdapterAttestationIntegrityValid(child) ||
      child.toolId !== tool.id ||
      child.dependencyId !== dependency.id ||
      child.parentBindingSha256 !== attestation.bindingSha256 ||
      child.expiresAt !== attestation.expiresAt
    ) {
      throw activationFailure(
        "activation_runtime_adapter_dependency_invalid",
        `Runtime adapter ${tool.id} dependency ${dependency.id} has no matching current receipt`,
        "dependency_missing",
        "Recompose every exact adapter dependency before starting another run.",
      );
    }
  }
  return {
    id: `runtime-adapter:${tool.id}:${attestation.receiptSha256.slice(0, 32)}`,
    hash: attestation.receiptSha256,
    expiresAt: attestation.expiresAt,
    evidenceProducerIds: [tool.id],
  };
}

function mcpProof(
  tool: RuntimeToolManifest,
  agentId: string,
  projection: RuntimeProjectionInput,
  now: Date,
): ResolvedActivationProof {
  const serverId = tool.mcpServerId;
  const server = serverId
    ? projection.mcpServers.find(({ id }) => id === serverId)
    : undefined;
  const manifestServer = serverId
    ? projection.capabilityManifests?.mcpServers.find(({ id }) => id === serverId)
    : undefined;
  const attestation = server?.capabilityAttestation;
  if (
    !serverId ||
    !server ||
    !manifestServer ||
    server.status !== "healthy" ||
    !isSpecialistMcpExecutionPolicy(server.policy) ||
    !server.policy.assignedAgents.includes(agentId) ||
    !manifestServer.toolIds.includes(tool.id) ||
    !attestation ||
    !isMcpAttestationFresh(attestation, now) ||
    attestation.connectionId !== serverId ||
    !attestation.tools.some(({ name }) => name === tool.id)
  ) {
    throw activationFailure(
      "activation_mcp_proof_invalid",
      `MCP route ${serverId ?? "unknown"}/${tool.id} lacks a current exact inventory receipt and specialist execution policy`,
      "mcp_unavailable",
      "Restore the exact MCP server, repeat tools/list attestation, and start a new run after its specialist route is current.",
    );
  }
  return {
    id: `mcp-capability:${serverId}:${attestation.manifestSha256.slice(0, 32)}`,
    hash: attestation.manifestSha256,
    expiresAt: attestation.expiresAt,
    evidenceProducerIds: [tool.id],
  };
}

function resolveProof(
  tool: RuntimeToolManifest,
  agentId: string,
  generation: RuntimeGeneration,
  stack: ReadonlySet<string> = new Set(),
): ResolvedActivationProof {
  if (stack.has(tool.id)) {
    throw activationFailure(
      "activation_route_cycle",
      `Tool composition contains a cycle at ${tool.id}`,
      "policy_denied",
      "Repair the runtime manifest graph before starting another run.",
    );
  }
  if (tool.constituentToolIds?.length) {
    const next = new Set(stack);
    next.add(tool.id);
    const constituents = tool.constituentToolIds.map((toolId) => {
      const constituent = generation.manifests.tools.find(({ id }) => id === toolId);
      if (!constituent) {
        throw activationFailure(
          "activation_constituent_missing",
          `Composite tool ${tool.id} is missing constituent ${toolId}`,
          "dependency_missing",
          "Recompose the exact tool manifest before starting another run.",
        );
      }
      return {
        toolId,
        proof: resolveProof(constituent, agentId, generation, next),
      };
    }).sort((left, right) => left.toolId.localeCompare(right.toolId, "en-US"));
    const expiresAt = new Date(Math.min(...constituents.map(({ proof }) =>
      timestamp(proof.expiresAt, `${tool.id} constituent expiry`)))).toISOString();
    const preimage = {
      schemaVersion: "ti-scale.aggregate-composite-tool-proof.v1",
      toolId: tool.id,
      constituents: constituents.map(({ toolId, proof }) => ({
        toolId,
        proofId: proof.id,
        proofHash: proof.hash,
        expiresAt: proof.expiresAt,
      })),
    };
    const hash = activationHashCanonical(preimage);
    return {
      id: `composite-tool:${tool.id}:${hash.slice(0, 32)}`,
      hash,
      expiresAt,
      evidenceProducerIds: constituents.flatMap(({ proof }) =>
        proof.evidenceProducerIds),
    };
  }
  if (tool.mcpServerId) return mcpProof(tool, agentId, generation.projection, generation.now);
  if (tool.runtimeAdapterAttestation) return runtimeAdapterProof(tool, generation.now);
  return localDependencyProof(tool, generation.now);
}

function agentDeclaresActionClass(
  agent: RuntimeAgentManifest,
  actionClassId: string,
  manifests: RuntimeSourceManifests,
): boolean {
  return agent.actionClassIds?.includes(actionClassId) === true
    || agent.capabilityIds.some((capabilityId) =>
      manifests.capabilities.find(({ id }) => id === capabilityId)
        ?.actionClassIds.includes(actionClassId) === true);
}

function providerRouteReady(
  assignment: AssignmentRow,
  agent: RuntimeAgentManifest,
  actionClassId: string,
  requiresModel: boolean | undefined,
  manifests: RuntimeSourceManifests,
): boolean {
  if (!agent.modelRefs.some(({ providerId, modelId }) =>
    providerId === assignment.provider_id && modelId === assignment.model_id)) {
    return false;
  }
  const provider = manifests.providers.find(({ id }) => id === assignment.provider_id);
  const model = provider?.models.find(({ id }) => id === assignment.model_id);
  return provider?.authenticated === true
    && provider.healthy === true
    && model?.enforcement === "enforced_executor"
    && model.compatibleActionClassIds.includes(actionClassId)
    && (requiresModel === false || (model.toolCalling && model.structuredOutput));
}

function stringList(value: unknown): readonly string[] | null {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
    ? value
    : null;
}

/**
 * The provider configuration hash carried by a compiled execution binding is
 * the stable runtime/request-policy identity. A model assignment is bound to
 * a separate, immutable catalog-snapshot hash that includes its configuration
 * ID, catalog observation time, stored version, and timestamps. Comparing
 * those two different hash domains makes every freshly materialized catalog
 * row impossible to activate.
 *
 * Keep both proofs: validate the compiled hash against the fresh provider
 * attestation, and independently validate the complete pinned catalog
 * snapshot here. The activation receipt then seals the latter with
 * modelConfigurationBindingHash.
 */
function configurationBindsExecutionRoute(
  configuration: StoredModelConfiguration,
  assignmentAgentId: string,
  actionClassId: string,
): boolean {
  const compatibleAgents = stringList(
    configuration.capabilities.compatibleAgentIds,
  );
  const compatibleActionClasses = stringList(
    configuration.capabilities.compatibleActionClassIds,
  );
  if (
    configuration.enforcementMode !== "enforced_executor"
    || configuration.authState !== "authenticated"
    || configuration.healthState !== "healthy"
    || !compatibleAgents?.includes(assignmentAgentId)
    || !compatibleActionClasses?.includes(actionClassId)
  ) {
    return false;
  }
  if (configuration.executionBoundary !== "local_deterministic_policy") {
    return true;
  }
  const coverage =
    configuration.capabilities.localDeterministicActionClassIdsByAgent;
  if (
    !coverage
    || typeof coverage !== "object"
    || Array.isArray(coverage)
  ) {
    return false;
  }
  return stringList(
    (coverage as Readonly<Record<string, unknown>>)[assignmentAgentId],
  )?.includes(actionClassId) === true;
}

function compiledProviderBindingIsFresh(
  projection: RuntimeProjectionInput,
  binding: LocalAutonomousPlannerBindingReceipt,
  now: Date,
): boolean {
  const nowMs = now.getTime();
  return projection.readiness.providers.some((provider) => {
    const attestedAt = provider.attestedAt
      ? Date.parse(provider.attestedAt)
      : Number.NaN;
    const expiresAt = provider.expiresAt
      ? Date.parse(provider.expiresAt)
      : Number.NaN;
    return provider.id === binding.providerId
      && provider.health === "healthy"
      && provider.authenticated
      && provider.callable
      && provider.circuitState === "closed"
      && provider.enforcesAutonomousBoundary
      && provider.requestedModel === binding.modelId
      && provider.returnedModel === binding.modelId
      && provider.modelConfigurationHash === binding.modelConfigurationHash
      && typeof provider.completionProbeReceiptId === "string"
      && PUBLIC_ID.test(provider.completionProbeReceiptId)
      && Number.isFinite(attestedAt)
      && Number.isFinite(expiresAt)
      && attestedAt <= nowMs
      && expiresAt > nowMs
      && expiresAt > attestedAt;
  });
}

/**
 * Resolves and seals the one exact execution generation that a production
 * Autonomous run may use. Every public method re-reads current projection
 * truth; cached readiness never grants authority.
 */
export class AutonomousActivationRuntimeService
implements AutonomousActivationRuntimePort {
  readonly #repository: AutonomousActivationReceiptRepository;
  readonly #verifier: AutonomousActivationReceiptVerifier;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly readRuntimeProjection: () => RuntimeProjectionInput,
    private readonly clock: () => Date = () => new Date(),
    private readonly exactExecutionBindings:
      readonly LocalAutonomousPlannerBindingReceipt[] = [],
  ) {
    this.#repository = new AutonomousActivationReceiptRepository(database, clock);
    this.#verifier = new AutonomousActivationReceiptVerifier(database, clock);
  }

  ensureIssued(input: Readonly<{
    missionId: string;
    runId: string;
    brainContextPackId: string;
    issuedBy: string;
  }>): AutonomousActivationBoundaryReceipt {
    try {
      return inImmediateTransaction(this.database, () => {
        const authority = this.#authority(input.runId);
        if (authority.mission_id !== input.missionId) {
          throw activationFailure(
            "activation_run_lineage_mismatch",
            "Run and mission do not share one Autonomous contract lineage",
            "policy_denied",
            "Use the run through its canonical mission workspace.",
          );
        }
        const generation = this.#generation();
        const current = this.#repository.findCurrentForRun(input.runId);
        let nextGeneration = 1;
        if (current) {
          let currentExpired = false;
          let verified: AutonomousActivationReceipt;
          try {
            verified = this.#verify(authority, generation, current.id).receipt;
          } catch (error) {
            if (
              !(error instanceof AutonomousActivationReceiptIntegrityError) ||
              error.code !== "activation_receipt_expired"
            ) throw error;
            currentExpired = true;
            verified = this.#verify(
              authority,
              generation,
              current.id,
              true,
            ).receipt;
          }
          if (
            !currentExpired &&
            verified.brainContextPackId === input.brainContextPackId
          ) {
            return boundary(verified);
          }
          nextGeneration = verified.generation + 1;
        }
        return boundary(this.#issue({
          authority,
          generation,
          missionId: input.missionId,
          runId: input.runId,
          brainContextPackId: input.brainContextPackId,
          issuedBy: input.issuedBy,
          receiptGeneration: nextGeneration,
        }));
      });
    } catch (error) {
      throw mapIntegrityError(error);
    }
  }

  verifyCurrent(input: Readonly<{
    runId: string;
  }>): AutonomousActivationBoundaryReceipt {
    try {
      const authority = this.#authority(input.runId);
      const generation = this.#generation();
      const current = this.#repository.findCurrentForRun(input.runId);
      if (!current) {
        throw new AutonomousActivationReceiptIntegrityError(
          "activation_receipt_not_found",
          `No Autonomous activation receipt exists for run ${input.runId}`,
        );
      }
      return boundary(this.#verify(authority, generation, current.id).receipt);
    } catch (error) {
      throw mapIntegrityError(error);
    }
  }

  verifyAndBind(input: Parameters<AutonomousActivationRuntimePort["verifyAndBind"]>[0]):
  AutonomousActivationBoundaryReceipt {
    try {
      return inImmediateTransaction(this.database, () => {
        const authority = this.#authority(input.runId);
        const generation = this.#generation();
        const current = this.#repository.findCurrentForRun(input.runId);
        if (!current) {
          throw new AutonomousActivationReceiptIntegrityError(
            "activation_receipt_not_found",
            `No Autonomous activation receipt exists for run ${input.runId}`,
          );
        }
        let rotated = false;
        let verified: AutonomousActivationReceipt;
        try {
          verified = this.#verify(authority, generation, current.id).receipt;
        } catch (error) {
          if (
            !(error instanceof AutonomousActivationReceiptIntegrityError) ||
            error.code !== "activation_receipt_expired"
          ) throw error;
          const expired = this.#verify(
            authority,
            generation,
            current.id,
            true,
          ).receipt;
          verified = this.#issue({
            authority,
            generation,
            missionId: expired.missionId,
            runId: expired.runId,
            brainContextPackId:
              input.contextPackId ?? expired.brainContextPackId,
            issuedBy: input.boundBy,
            receiptGeneration: expired.generation + 1,
          });
          rotated = true;
        }
        if (
          input.contextPackId !== undefined &&
          input.contextPackId !== null &&
          input.contextPackId !== verified.brainContextPackId
        ) {
          verified = this.#issue({
            authority,
            generation,
            missionId: verified.missionId,
            runId: verified.runId,
            brainContextPackId: input.contextPackId,
            issuedBy: input.boundBy,
            receiptGeneration: verified.generation + 1,
          });
          rotated = true;
        }
        if (
          rotated &&
          input.planId &&
          input.bindingType !== "plan_version"
        ) {
          verified = this.#bindRolloverPlan(
            verified,
            input.planId,
            input.boundBy,
            generation,
          );
        }
        if (input.bindingType === "plan_version") {
          this.#assertPlanVersion(verified, input);
        }
        if (input.bindingType === "dispatch" || input.bindingType === "resume") {
          this.#assertActionRoute(verified, input);
        }
        const exact = {
          bindingType: input.bindingType,
          subjectId: input.subjectId,
          subjectDigest: input.subjectDigest.toLowerCase(),
          planId: input.planId ?? null,
          stepId: input.stepId ?? null,
          actionId: input.actionId ?? null,
          contextPackId: input.contextPackId ?? null,
          providerTurnId: input.providerTurnId ?? null,
        };
        const existing = verified.bindings.find((binding) =>
          binding.bindingType === exact.bindingType
          && binding.subjectId === exact.subjectId);
        if (existing) {
          if (
            existing.subjectDigest !== exact.subjectDigest
            || existing.planId !== exact.planId
            || existing.stepId !== exact.stepId
            || existing.actionId !== exact.actionId
            || existing.contextPackId !== exact.contextPackId
            || existing.providerTurnId !== exact.providerTurnId
          ) {
            throw new AutonomousActivationReceiptIntegrityError(
              "activation_binding_chain_invalid",
              `Activation binding ${exact.bindingType}/${exact.subjectId} was replayed with different canonical content`,
            );
          }
          return boundary(verified);
        }
        if (!SHA256.test(exact.subjectDigest)) {
          throw activationFailure(
            "activation_binding_digest_invalid",
            "Activation binding subject digest is not a canonical SHA-256 value",
            "policy_denied",
            "Repair the lifecycle caller before starting a new run.",
          );
        }
        const bindingId = `autonomous_activation_binding:${activationHashCanonical({
          receiptId: verified.id,
          ...exact,
        }).slice(0, 48)}`;
        this.#repository.appendBinding({
          id: bindingId,
          receiptId: verified.id,
          bindingType: exact.bindingType,
          subjectId: exact.subjectId,
          subjectDigest: exact.subjectDigest,
          planId: exact.planId,
          stepId: exact.stepId,
          actionId: exact.actionId,
          contextPackId: exact.contextPackId,
          providerTurnId: exact.providerTurnId,
          boundBy: input.boundBy,
          boundAt: generation.now.toISOString(),
        });
        return boundary(this.#repository.getById(verified.id));
      });
    } catch (error) {
      throw mapIntegrityError(error);
    }
  }

  #issue(input: Readonly<{
    authority: RunAuthorityRow;
    generation: RuntimeGeneration;
    missionId: string;
    runId: string;
    brainContextPackId: string;
    issuedBy: string;
    receiptGeneration: number;
  }>): AutonomousActivationReceipt {
    const actionPolicy = record(
      JSON.parse(input.authority.action_policy_json) as unknown,
      "Contract action policy",
    );
    const actionClassIds = stringArray(
      actionPolicy.allowedActionClasses,
      "Allowed action classes",
    );
    const evidenceRequirementIds = stringArray(
      actionPolicy.evidenceRequirements,
      "Evidence requirements",
      { allowEmpty: true },
    );
    const selection = planningSelection(actionPolicy.planningSelection);
    const routes = this.#routes(
      input.missionId,
      input.runId,
      actionClassIds,
      input.generation,
    );
    const planning = this.#planning(
      input.missionId,
      input.runId,
      selection,
    );
    const expiresAt = new Date(Math.min(...routes.map((route) =>
      timestamp(
        route.routeExpiresAt,
        `${route.actionClassId} route expiry`,
      )))).toISOString();
    return this.#repository.issue({
      id:
        `autonomous_activation_receipt:${input.runId}:${input.receiptGeneration}`,
      missionId: input.missionId,
      runId: input.runId,
      contractId: input.authority.contract_id!,
      contractVersion: input.authority.contract_version_bound!,
      contractHash: input.authority.contract_hash_bound!,
      generation: input.receiptGeneration,
      runtimeGenerationHash: input.generation.hash,
      evidencePolicyHash:
        autonomousActivationEvidencePolicyHash(
          uniqueSorted(
            evidenceRequirementIds,
            "Evidence requirements",
            { allowEmpty: true },
          ),
        ),
      brainContextPackId: input.brainContextPackId,
      planning,
      routes,
      issuedBy: input.issuedBy,
      issuedAt: input.generation.now.toISOString(),
      expiresAt,
    });
  }

  #bindRolloverPlan(
    receipt: AutonomousActivationReceipt,
    planId: string,
    boundBy: string,
    generation: RuntimeGeneration,
  ): AutonomousActivationReceipt {
    const plan = this.database.prepare(`
      SELECT plan_hash FROM plans WHERE id = ? AND run_id = ?
    `).get(planId, receipt.runId) as { plan_hash: string } | undefined;
    if (!plan) {
      throw activationFailure(
        "activation_rollover_plan_missing",
        `Fresh activation generation ${receipt.generation} cannot bind missing plan ${planId}`,
        "policy_denied",
        "Restore the exact immutable plan checkpoint before resuming this run.",
      );
    }
    const bindingInput = {
      runId: receipt.runId,
      bindingType: "plan_version" as const,
      subjectId: planId,
      subjectDigest: plan.plan_hash,
      planId,
      contextPackId: receipt.brainContextPackId,
      boundBy,
    };
    this.#assertPlanVersion(receipt, bindingInput);
    const existing = receipt.bindings.find((binding) =>
      binding.bindingType === "plan_version" &&
      binding.subjectId === planId);
    if (existing) {
      if (
        existing.subjectDigest !== plan.plan_hash ||
        existing.contextPackId !== receipt.brainContextPackId
      ) {
        throw new AutonomousActivationReceiptIntegrityError(
          "activation_binding_chain_invalid",
          `Rollover plan ${planId} was already bound with different canonical content`,
        );
      }
      return receipt;
    }
    this.#repository.appendBinding({
      id: `autonomous_activation_binding:${activationHashCanonical({
        receiptId: receipt.id,
        bindingType: "plan_version",
        subjectId: planId,
        subjectDigest: plan.plan_hash,
        contextPackId: receipt.brainContextPackId,
      }).slice(0, 48)}`,
      receiptId: receipt.id,
      bindingType: "plan_version",
      subjectId: planId,
      subjectDigest: plan.plan_hash,
      planId,
      contextPackId: receipt.brainContextPackId,
      boundBy,
      boundAt: generation.now.toISOString(),
    });
    return this.#repository.getById(receipt.id);
  }

  #authority(runId: string): RunAuthorityRow {
    const row = this.database.prepare(`
      SELECT r.mission_id, r.journey, r.contract_id,
        r.contract_version_bound, r.contract_hash_bound,
        c.action_policy_json
      FROM runs r
      JOIN mission_contracts c ON c.id = r.contract_id
      WHERE r.id = ? AND c.mission_id = r.mission_id
    `).get(runId) as RunAuthorityRow | undefined;
    if (
      !row ||
      row.journey !== "autonomous" ||
      !row.contract_id ||
      !row.contract_version_bound ||
      !row.contract_hash_bound
    ) {
      throw activationFailure(
        "activation_contract_lineage_missing",
        `Run ${runId} has no exact confirmed Autonomous contract lineage`,
        "policy_denied",
        "Create a new run from a confirmed Autonomous contract.",
      );
    }
    return row;
  }

  #assertActionRoute(
    receipt: AutonomousActivationReceipt,
    input: Parameters<AutonomousActivationRuntimePort["verifyAndBind"]>[0],
  ): void {
    if (!input.actionId || input.subjectId !== input.actionId) {
      throw activationFailure(
        "activation_action_binding_invalid",
        "Dispatch and action-resume bindings require the exact action as their subject",
        "policy_denied",
        "Repair the execution-boundary caller before starting another run.",
      );
    }
    const row = this.database.prepare(`
      SELECT a.id, a.action_class, a.action_type, a.fingerprint,
        a.normalized_arguments_json, a.contract_id, a.context_pack_id,
        ps.plan_id, ps.id AS step_id, ps.assigned_agent_id AS step_agent_id,
        a.assignment_id, assignment.agent_id AS assignment_agent_id
      FROM actions a
      JOIN plan_steps ps ON ps.id = a.step_id AND ps.run_id = a.run_id
      LEFT JOIN assignments assignment
        ON assignment.id = a.assignment_id
        AND assignment.run_id = a.run_id
        AND assignment.step_id = a.step_id
      WHERE a.id = ? AND a.run_id = ? AND a.mission_id = ?
    `).get(input.actionId, receipt.runId, receipt.missionId) as
      | ActionRouteRow
      | undefined;
    const route = row
      ? receipt.items.find(({ actionClassId }) =>
          actionClassId === row.action_class)
      : undefined;
    let persisted: Readonly<Record<string, unknown>> | undefined;
    let actionInput: Readonly<Record<string, unknown>> | undefined;
    let orchestration: Readonly<Record<string, unknown>> | undefined;
    try {
      const candidate = row
        ? JSON.parse(row.normalized_arguments_json) as unknown
        : undefined;
      if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
        persisted = candidate as Readonly<Record<string, unknown>>;
        const rawInput = persisted.input;
        const rawOrchestration = persisted.orchestration;
        if (rawInput && typeof rawInput === "object" && !Array.isArray(rawInput)) {
          actionInput = rawInput as Readonly<Record<string, unknown>>;
        }
        if (
          rawOrchestration &&
          typeof rawOrchestration === "object" &&
          !Array.isArray(rawOrchestration)
        ) {
          orchestration = rawOrchestration as Readonly<Record<string, unknown>>;
        }
      }
    } catch {
      // The canonical mismatch below produces one stable fail-closed diagnosis.
    }
    const rawModelBinding = orchestration?.runtimeModelBinding;
    const modelBinding = rawModelBinding
      && typeof rawModelBinding === "object"
      && !Array.isArray(rawModelBinding)
      ? rawModelBinding as Readonly<Record<string, unknown>>
      : undefined;
    const selectedToolId = typeof actionInput?.toolId === "string"
      ? actionInput.toolId
      : typeof actionInput?.toolName === "string"
        ? actionInput.toolName
        : row?.action_type;
    const selectedMcpServerId = typeof actionInput?.mcpServer === "string"
      ? actionInput.mcpServer
      : null;
    if (
      !row ||
      !route ||
      row.fingerprint !== input.subjectDigest ||
      row.contract_id !== receipt.contractId ||
      row.plan_id !== input.planId ||
      row.step_id !== input.stepId ||
      row.id !== input.actionId ||
      row.context_pack_id !== (input.contextPackId ?? null) ||
      row.step_agent_id !== route.agentId ||
      row.assignment_id === null ||
      row.assignment_agent_id !== route.agentId ||
      selectedToolId !== route.toolId ||
      selectedMcpServerId !== route.mcpServerId ||
      modelBinding?.schemaVersion !== "ti-scale.runtime-model-binding.v1" ||
      modelBinding.agentId !== route.agentId ||
      modelBinding.modelAssignmentId !==
        route.executionModelAssignmentId ||
      modelBinding.modelConfigurationId !==
        route.executionPrimaryConfigurationId
    ) {
      throw activationFailure(
        "activation_action_route_mismatch",
        `Action ${input.actionId} does not match its exact activated action-class, specialist, model assignment, tool, or Context Pack route`,
        "policy_denied",
        "Do not dispatch this action. Rebuild the plan from the exact signed contract and current aggregate receipt in a new run.",
        {
          actionId: input.actionId,
          actionClassId: row?.action_class ?? null,
          activatedRouteFound: route !== undefined,
        },
      );
    }
  }

  #assertPlanVersion(
    receipt: AutonomousActivationReceipt,
    input: Parameters<AutonomousActivationRuntimePort["verifyAndBind"]>[0],
  ): void {
    if (!input.planId || input.subjectId !== input.planId) {
      throw activationFailure(
        "activation_plan_binding_invalid",
        "Plan-version activation requires the exact plan as its subject",
        "policy_denied",
        "Repair the plan activation caller before starting another run.",
      );
    }
    const plan = this.database.prepare(`
      SELECT id, plan_hash FROM plans WHERE id = ? AND run_id = ?
    `).get(input.planId, receipt.runId) as {
      id: string;
      plan_hash: string;
    } | undefined;
    const steps = this.database.prepare(`
      SELECT id, action_class, assigned_agent_id
      FROM plan_steps
      WHERE plan_id = ? AND run_id = ?
      ORDER BY ordinal, id
    `).all(input.planId, receipt.runId) as Array<{
      id: string;
      action_class: string | null;
      assigned_agent_id: string | null;
    }>;
    const stepOverride = this.database.prepare(`
      SELECT assignment.id
      FROM agent_model_assignments assignment
      JOIN plan_steps step ON step.id = assignment.step_id
      WHERE step.plan_id = ? AND step.run_id = ?
        AND assignment.assignment_purpose = 'execution'
      ORDER BY assignment.id LIMIT 1
    `).get(input.planId, receipt.runId) as { id: string } | undefined;
    const routeMismatch = steps.find((step) => {
      const route = receipt.items.find(({ actionClassId }) =>
        actionClassId === step.action_class);
      return !route || route.agentId !== step.assigned_agent_id;
    });
    if (
      !plan ||
      plan.plan_hash !== input.subjectDigest ||
      steps.length === 0 ||
      routeMismatch ||
      stepOverride
    ) {
      throw activationFailure(
        stepOverride
          ? "activation_step_model_override_requires_rotation"
          : "activation_plan_route_mismatch",
        stepOverride
          ? `Plan ${input.planId} introduces step-level model assignment ${stepOverride.id} that is not bound by this pre-plan aggregate receipt`
          : `Plan ${input.planId} does not preserve every activated action-class and specialist route`,
        "policy_denied",
        stepOverride
          ? "Create a new immutable activation generation that explicitly binds the amended step assignment before applying the plan."
          : "Recompile the plan from the exact locally reviewed execution bindings before activation.",
        {
          planId: input.planId,
          mismatchedStepId: routeMismatch?.id ?? null,
          stepModelAssignmentId: stepOverride?.id ?? null,
        },
      );
    }
  }

  #generation(): RuntimeGeneration {
    const now = this.clock();
    if (!Number.isFinite(now.getTime())) {
      throw activationFailure(
        "activation_clock_invalid",
        "Trusted activation clock is invalid",
        "dependency_missing",
        "Restore the local runtime clock before launching another run.",
      );
    }
    const projection = this.readRuntimeProjection();
    const manifests = projection.capabilityManifests;
    if (!manifests) {
      throw activationFailure(
        "activation_runtime_manifest_missing",
        "The current runtime projection has no exact capability manifests",
        "dependency_missing",
        "Publish the exact mounted runtime manifest before launching another run.",
      );
    }
    buildRuntimeCapabilityProjection(manifests, now);
    return {
      projection,
      manifests,
      now,
      hash: activationHashCanonical(stableRuntimeGenerationPreimage(
        projection,
        manifests,
        this.exactExecutionBindings,
      )),
    };
  }

  #executionAssignments(
    missionId: string,
    runId: string,
  ): readonly AssignmentRow[] {
    return this.database.prepare(`
      SELECT a.id, a.agent_id, a.assignment_purpose,
        a.primary_configuration_id, a.fallback_configuration_id,
        c.provider_id, c.model_id
      FROM agent_model_assignments a
      JOIN model_configurations c ON c.id = a.primary_configuration_id
      WHERE a.mission_id = ? AND a.run_id = ? AND a.step_id IS NULL
        AND a.pinned = 1 AND a.assignment_purpose = 'execution'
      ORDER BY a.agent_id, a.id
    `).all(missionId, runId) as AssignmentRow[];
  }

  #routes(
    missionId: string,
    runId: string,
    actionClassIds: readonly string[],
    generation: RuntimeGeneration,
  ): AutonomousActivationRouteInput[] {
    const projection = buildRuntimeCapabilityProjection(
      generation.manifests,
      generation.now,
    );
    const assignments = this.#executionAssignments(missionId, runId);
    const routes = actionClassIds.map((actionClassId) => {
      const selectedBindings = this.exactExecutionBindings.filter(
        (binding) => binding.actionClassId === actionClassId,
      );
      if (selectedBindings.length !== 1) {
        throw activationFailure(
          "activation_execution_binding_unresolved",
          `Signed action class ${actionClassId} does not have one exact locally compiled execution binding`,
          "policy_denied",
          "Compile exactly one reviewed specialist/model/tool binding for this signed action class before starting another run.",
          {
            actionClassId,
            matchingBindingCount: selectedBindings.length,
          },
        );
      }
      const selectedBinding = selectedBindings[0]!;
      if (!compiledProviderBindingIsFresh(
        generation.projection,
        selectedBinding,
        generation.now,
      )) {
        throw activationFailure(
          "activation_execution_model_configuration_mismatch",
          `Signed action class ${actionClassId} does not match the fresh provider and runtime-policy attestation`,
          "policy_denied",
          "Refresh the reviewed provider attestation for the compiled execution binding before starting another run.",
          {
            actionClassId,
            agentId: selectedBinding.agentId,
            providerId: selectedBinding.providerId,
            modelId: selectedBinding.modelId,
            providerConfigurationHash:
              selectedBinding.modelConfigurationHash,
          },
        );
      }
      const productAgentId = productAgentIdForActionClass(actionClassId);
      const selectedAssignments = assignments.filter(({ agent_id }) =>
        agent_id === selectedBinding.agentId
        || (
          agent_id === productAgentId
          && agentAssignmentBindsRuntimeAgent(
            this.database,
            agent_id,
            selectedBinding.agentId,
          )
        ));
      if (selectedAssignments.length !== 1) {
        throw activationFailure(
          "activation_execution_assignment_unresolved",
          `Signed action class ${actionClassId} is not joined to exactly one pinned execution assignment for ${selectedBinding.agentId}`,
          "policy_denied",
          "Resolve one run-level execution model assignment for the selected specialist before starting another run.",
          {
            actionClassId,
            agentId: selectedBinding.agentId,
            matchingAssignmentCount: selectedAssignments.length,
          },
        );
      }
      const selectedAssignment = selectedAssignments[0]!;
      const selectedConfiguration =
        new ModelConfigurationRepository(this.database).getConfiguration(
          selectedAssignment.primary_configuration_id,
        );
      const selectedConfigurationHash = modelConfigurationBindingHash(
        selectedConfiguration,
      );
      if (
        selectedAssignment.provider_id !== selectedBinding.providerId ||
        selectedAssignment.model_id !== selectedBinding.modelId ||
        !configurationBindsExecutionRoute(
          selectedConfiguration,
          selectedAssignment.agent_id,
          actionClassId,
        )
      ) {
        throw activationFailure(
          "activation_execution_model_configuration_mismatch",
          `Signed action class ${actionClassId} does not match the exact healthy pinned execution-model snapshot`,
          "policy_denied",
          "Select one healthy enforced model snapshot that explicitly supports this specialist and action class before starting another run.",
          {
            actionClassId,
            agentId: selectedBinding.agentId,
            modelAssignmentId: selectedAssignment.id,
            providerConfigurationHash:
              selectedBinding.modelConfigurationHash,
            pinnedConfigurationSnapshotHash: selectedConfigurationHash,
          },
        );
      }
      const selectedToolId = "executionBinding" in selectedBinding
        ? selectedBinding.toolId
        : selectedBinding.toolName;
      const selectedMcpServerId = "executionBinding" in selectedBinding
        ? null
        : selectedBinding.mcpServerId;
      const mapping = projection.actionClasses[
        actionClassId as keyof typeof projection.actionClasses
      ];
      if (!mapping?.enforcementReady) {
        throw activationFailure(
          "activation_action_class_unavailable",
          `Signed action class ${actionClassId} has no current enforced runtime route`,
          "dependency_missing",
          "Restore one exact specialist, execution model, tool proof, and evidence producer for this action class, then start a new run.",
          {
            actionClassId,
            readinessReasons: [...(mapping?.readinessReasons ?? [])],
          },
        );
      }
      const candidates: Array<{
        readonly route: AutonomousActivationRouteInput;
        readonly sortKey: string;
      }> = [];
      for (const tool of generation.manifests.tools) {
        if (
          !tool.actionClassIds.includes(actionClassId) ||
          tool.id !== selectedToolId ||
          (tool.mcpServerId ?? null) !== selectedMcpServerId ||
          !tool.available ||
          !tool.locallyPolicyEnforced ||
          !tool.executionJourneys?.includes("autonomous")
        ) continue;
        const evidenceTypeIds = uniqueSorted(
          tool.evidenceTypeIds,
          `${tool.id} evidence types`,
        );
        if (evidenceTypeIds.some((evidenceTypeId) =>
          projection.evidenceTypes[
            evidenceTypeId as keyof typeof projection.evidenceTypes
          ]?.availability !== "supported")) {
          continue;
        }
        for (const agent of generation.manifests.agents) {
          if (
            !agent.available ||
            agent.id !== selectedBinding.agentId ||
            !agent.toolIds.includes(tool.id) ||
            !agentDeclaresActionClass(agent, actionClassId, generation.manifests)
          ) continue;
          const assignment = selectedAssignment;
          if (!providerRouteReady(
            assignment,
            agent,
            actionClassId,
            tool.requiresModel,
            generation.manifests,
          )) continue;
          const proof = resolveProof(tool, agent.id, generation);
          const producers = uniqueSorted(
            proof.evidenceProducerIds,
            `${tool.id} evidence producers`,
          );
          const route: AutonomousActivationRouteInput = {
            actionClassId,
            // Durable plans/assignments use the canonical product agent. The
            // manifest-only internal adapter remains bound above for exact
            // tool/proof validation.
            agentId: assignment.agent_id,
            executionModelAssignmentId: assignment.id,
            toolId: tool.id,
            toolBindingKind: tool.mcpServerId ? "mcp" : "local",
            mcpServerId: tool.mcpServerId ?? null,
            toolActivationReceiptId: proof.id,
            toolActivationReceiptHash: proof.hash,
            toolManifestHash: activationHashCanonical(tool),
            evidenceTypeIds,
            evidenceProducerIds: producers,
            routeExpiresAt: proof.expiresAt,
          };
          candidates.push({
            route,
            sortKey: `${agent.id}\u0000${tool.id}\u0000${assignment.id}\u0000${proof.hash}`,
          });
        }
      }
      candidates.sort((left, right) =>
        left.sortKey.localeCompare(right.sortKey, "en-US"));
      const selected = candidates[0];
      if (!selected) {
        throw activationFailure(
          "activation_exact_route_unresolved",
          `Signed action class ${actionClassId} has no exact route joined to one run-pinned execution assignment`,
          "dependency_missing",
          "Reconcile the specialist, pinned executor model, attested tool, and evidence producer before starting another run.",
          { actionClassId },
        );
      }
      return selected.route;
    });
    return routes.sort((left, right) =>
      left.actionClassId.localeCompare(right.actionClassId, "en-US"));
  }

  #planning(
    missionId: string,
    runId: string,
    selection: AutonomousPlanningSelection,
  ): AutonomousActivationPlanningInput {
    const assignments = this.database.prepare(`
      SELECT a.id, a.agent_id, a.assignment_purpose,
        a.primary_configuration_id, a.fallback_configuration_id,
        c.provider_id, c.model_id
      FROM agent_model_assignments a
      JOIN model_configurations c ON c.id = a.primary_configuration_id
      WHERE a.mission_id = ? AND a.run_id = ? AND a.step_id IS NULL
        AND a.pinned = 1 AND a.assignment_purpose = 'planning'
      ORDER BY a.agent_id, a.id
    `).all(missionId, runId) as AssignmentRow[];
    if (selection.route === "local_deterministic") {
      if (assignments.length !== 0) {
        throw activationFailure(
          "activation_local_planner_pin_conflict",
          "Local deterministic planning unexpectedly has a provider model pin",
          "policy_denied",
          "Create a new run whose local planning selection has no purpose=planning provider assignment.",
        );
      }
      return { selection };
    }
    const matches = assignments.filter((assignment) =>
      assignment.agent_id === selection.agentId
      && assignment.primary_configuration_id ===
        selection.primaryConfigurationId
      && assignment.fallback_configuration_id ===
        selection.fallbackConfigurationId);
    if (assignments.length !== 1 || matches.length !== 1) {
      throw activationFailure(
        "activation_planning_pin_unresolved",
        "Provider-advisory planning is not joined to one exact run-pinned purpose=planning assignment",
        "policy_denied",
        "Pin exactly the signed advisor-only provider configuration to the selected planning agent, then start a new run.",
      );
    }
    return {
      selection,
      modelAssignmentId: matches[0]!.id,
    };
  }

  #verify(
    authority: RunAuthorityRow,
    generation: RuntimeGeneration,
    receiptId: string,
    allowExpired = false,
  ) {
    const actionPolicy = record(
      JSON.parse(authority.action_policy_json) as unknown,
      "Contract action policy",
    );
    const actionClassIds = stringArray(
      actionPolicy.allowedActionClasses,
      "Allowed action classes",
    );
    const evidenceRequirementIds = stringArray(
      actionPolicy.evidenceRequirements,
      "Evidence requirements",
      { allowEmpty: true },
    );
    const selection = planningSelection(actionPolicy.planningSelection);
    return this.#verifier.verify(receiptId, {
      missionId: authority.mission_id,
      contractId: authority.contract_id!,
      contractVersion: authority.contract_version_bound!,
      contractHash: authority.contract_hash_bound!,
      runtimeGenerationHash: generation.hash,
      evidencePolicyHash:
        autonomousActivationEvidencePolicyHash(
          uniqueSorted(
            evidenceRequirementIds,
            "Evidence requirements",
            { allowEmpty: true },
          ),
        ),
      planningSelectionHash: activationHashCanonical(selection),
      selectedActionClassIds: actionClassIds,
      allowExpired,
    });
  }
}

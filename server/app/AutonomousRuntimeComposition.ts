import type { ControlPlaneLease } from "../control-plane";
import {
  buildRuntimeCapabilityProjection,
  isSpecialistMcpExecutionPolicy,
  SPECIALIST_MCP_EXECUTION_AUTHORIZATION,
  type RuntimeSourceManifests,
} from "../domain";
import type { SqliteDatabase } from "../db";
import {
  MissionRuntimeEngine,
  type AutonomousPostReconPlanExpansionPort,
  type MissionOutcomeEvaluatorPort,
  type MissionPlannerPort,
  type MissionPlannerProviderBoundary,
  type MissionRuntimeOptions,
  type AutonomousProviderPlanningContextPort,
  type ResultAwareExecutionPort,
} from "../command-runtime";
import type { ProviderAdvisoryRuntimePort } from "../autonomous-planning";
import {
  assertSpecialistToolInvocationAdapterContract,
  SpecialistToolDispatchService,
  type SpecialistToolInvocationAdapterContract,
} from "../specialist-runtime";
import type { BrainContextService } from "../brain-runtime";
import type { RuntimeProjectionInput } from "./RuntimeProjectionService";
import {
  AutonomousActivationRuntimeService,
  AutonomousTerminalDeliverableService,
  LOCAL_AUTONOMOUS_PLANNER_BOUNDARY_SCHEMA_VERSION,
  type LocalAutonomousPlannerBindingReceipt,
  type LocalAutonomousPlannerBoundary,
  type LocalAutonomousMcpPlannerBindingReceipt,
  type LocalAutonomousProcessPlannerBindingReceipt,
} from "../autonomous-runtime";
import { AgentRuntimeBindingService } from "../agent-runtime";

export const AUTONOMOUS_PLANNER_CONTRACT_SCHEMA_VERSION =
  "ti-scale.autonomous-planner-adapter.v1" as const;
export const AUTONOMOUS_OUTCOME_EVALUATOR_CONTRACT_SCHEMA_VERSION =
  "ti-scale.autonomous-outcome-evaluator.v1" as const;
export const AUTONOMOUS_SPECIALIST_EXECUTION_AUTHORIZATION =
  SPECIALIST_MCP_EXECUTION_AUTHORIZATION;
export const DEFAULT_AUTONOMOUS_SPECIALIST_HEARTBEAT_MAXIMUM_AGE_MS = 60_000;

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

export interface ProductionAutonomousPlannerPort extends MissionPlannerPort {
  /** Exactly one boundary is permitted: public-provider planning or local deterministic planning. */
  readonly providerBoundary?: MissionPlannerProviderBoundary;
  readonly localPlanningBoundary?: LocalAutonomousPlannerBoundary;
  /**
   * Provider-advisory planning may reorder only locally compiled candidates;
   * it must retain the same exact specialist/model/tool execution bindings.
   */
  readonly autonomousExecutionBindings?:
    readonly LocalAutonomousPlannerBindingReceipt[];
  readonly autonomousContract: Readonly<{
    schemaVersion: typeof AUTONOMOUS_PLANNER_CONTRACT_SCHEMA_VERSION;
    plannerId: string;
    planAuthority: "signed_contract_bounded_plan";
    providerToolDeclarations: "none";
    directToolDispatch: false;
  }>;
}

export interface ProductionAutonomousOutcomeEvaluatorPort extends MissionOutcomeEvaluatorPort {
  readonly autonomousContract: Readonly<{
    schemaVersion: typeof AUTONOMOUS_OUTCOME_EVALUATOR_CONTRACT_SCHEMA_VERSION;
    evaluatorId: string;
    evidenceAuthority: "verified_evidence_only";
    successAuthority: "criteria_evaluation_only";
    providerContact: false;
  }>;
}

/**
 * Factory shape resolves the runtime/service circular authority dependency
 * without exposing a raw control-plane token. The returned service still
 * validates the re-checkable proof inside every dispatch transaction.
 */
export interface ProductionAutonomousSpecialistExecutionFactory {
  readonly adapterContract: SpecialistToolInvocationAdapterContract;
  create(input: Readonly<{
    database: SqliteDatabase;
    assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
  }>): SpecialistToolDispatchService;
}

export interface ProductionAutonomousLocalProcessExecutionFactory {
  readonly localProcessContract: Readonly<{
    readonly schemaVersion: "ti-scale.autonomous-local-process-execution.v1";
    readonly adapterId: string;
    readonly executionBinding: "reviewed_local_process";
    readonly directArgv: true;
    readonly shell: false;
    readonly resultDelivery: "bound_execution_result_sink";
    readonly cancellation: "run_scoped_cooperative";
    readonly publicProviderToolExecution: false;
  }>;
  create(input: Readonly<{
    database: SqliteDatabase;
    assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
  }>): ResultAwareExecutionPort;
}

export type ProductionAutonomousExecutionFactory =
  | ProductionAutonomousSpecialistExecutionFactory
  | ProductionAutonomousLocalProcessExecutionFactory;

export interface ProductionAutonomousRuntimeAdapters {
  readonly planner: ProductionAutonomousPlannerPort;
  /** Optional advisor. The signed activation receipt selects it per run. */
  readonly providerAdvisory?: ProviderAdvisoryRuntimePort;
  /** Required with providerAdvisory; emits filtered local context items only. */
  readonly providerContext?: AutonomousProviderPlanningContextPort;
  readonly outcomeEvaluator: ProductionAutonomousOutcomeEvaluatorPort;
  readonly execution: ProductionAutonomousExecutionFactory;
}

export interface ProductionAutonomousSpecialistRuntimeConfiguration {
  readonly schemaVersion: "ti-scale.autonomous-specialist-runtime.v1";
  readonly executionMode: "specialist_runtime" | "reviewed_local_process";
  readonly adapterId: string;
  readonly toolSelection: "exact_persisted_binding_only";
  readonly resultDelivery: "bound_execution_result_sink";
  readonly shellInterpolation: false;
  readonly publicProviderToolExecution: false;
}

export type AutonomousRuntimeCompositionBlockerCode =
  | "autonomous_composition_report_missing"
  | "autonomous_planner_adapter_missing"
  | "autonomous_planner_contract_invalid"
  | "autonomous_outcome_evaluator_missing"
  | "autonomous_outcome_evaluator_contract_invalid"
  | "specialist_execution_factory_missing"
  | "specialist_execution_adapter_contract_invalid"
  | "autonomous_action_boundary_inactive"
  | "autonomous_provider_route_unavailable"
  | "autonomous_provider_advisory_boundary_invalid"
  | "autonomous_specialist_unavailable"
  | "autonomous_mcp_execution_unavailable"
  | "autonomous_activation_receipt_boundary_missing"
  | "runtime_manifest_invalid"
  | "autonomous_action_mapping_unavailable";

export interface AutonomousRuntimeCompositionBlocker {
  readonly code: AutonomousRuntimeCompositionBlockerCode;
  readonly component: "planner" | "evaluator" | "execution" | "provider" | "specialist" | "mcp" | "activation" | "manifest" | "policy";
  readonly impact: string;
  readonly remediation: string;
}

export interface AutonomousRuntimeCompositionReadiness {
  readonly schemaVersion: "ti-scale.autonomous-runtime-composition.v1";
  readonly status: "blocked" | "ready";
  readonly readyActionClassIds: readonly string[];
  readonly components: Readonly<{
    plannerAdapter: boolean;
    outcomeEvaluator: boolean;
    resultAwareSpecialistExecution: boolean;
    enforcingProvider: boolean;
    durableActionBoundary: boolean;
    specialistFleet: boolean;
    mcpExecution: boolean;
    localProcessExecution: boolean;
    providerAdvisoryBoundary?: boolean;
    aggregateActivationReceiptBoundary?: boolean;
    exactRuntimeManifest: boolean;
  }>;
  readonly blockers: readonly AutonomousRuntimeCompositionBlocker[];
}

export interface InspectAutonomousRuntimeCompositionInput {
  readonly projection: RuntimeProjectionInput;
  readonly adapters?: Partial<ProductionAutonomousRuntimeAdapters>;
  readonly now?: Date;
  readonly specialistHeartbeatMaximumAgeMs?: number;
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function isLocalProcessPlannerBinding(
  binding: LocalAutonomousPlannerBindingReceipt,
): binding is LocalAutonomousProcessPlannerBindingReceipt {
  return "executionBinding" in binding
    && binding.executionBinding === "reviewed_local_process";
}

function isMcpPlannerBinding(
  binding: LocalAutonomousPlannerBindingReceipt,
): binding is LocalAutonomousMcpPlannerBindingReceipt {
  return !isLocalProcessPlannerBinding(binding);
}

function plannerContractValid(planner: ProductionAutonomousPlannerPort | undefined): boolean {
  if (!planner) return false;
  const contract = planner.autonomousContract;
  const boundary = planner.providerBoundary;
  const providerBoundaryValid = boundary === undefined || (
    boundary.kind === "public_provider"
    && exactKeys(boundary, [
      "agentId",
      "kind",
      "providerId",
      "modelId",
      "modelConfigurationHash",
    ])
    && PUBLIC_ID.test(boundary.agentId ?? "")
    && PUBLIC_ID.test(boundary.providerId)
    && PUBLIC_ID.test(boundary.modelId)
    && SHA256.test(boundary.modelConfigurationHash)
  );
  const localBoundary = planner.localPlanningBoundary;
  const localBoundaryValid = localPlannerBoundaryValid(localBoundary);
  const providerExecutionBindingsValid = boundary === undefined ||
    (
      Array.isArray(planner.autonomousExecutionBindings) &&
      planner.autonomousExecutionBindings.length > 0 &&
      planner.autonomousExecutionBindings.every(localPlannerBindingValid)
    );
  return typeof planner.plan === "function"
    && contract !== null
    && typeof contract === "object"
    && exactKeys(contract, [
      "schemaVersion",
      "plannerId",
      "planAuthority",
      "providerToolDeclarations",
      "directToolDispatch",
    ])
    && contract.schemaVersion === AUTONOMOUS_PLANNER_CONTRACT_SCHEMA_VERSION
    && PUBLIC_ID.test(contract.plannerId)
    && contract.planAuthority === "signed_contract_bounded_plan"
    && contract.providerToolDeclarations === "none"
    && contract.directToolDispatch === false
    // Production Autonomous planning always begins with the exact local
    // compiler. A static provider boundary is compatibility metadata only;
    // signed activation selects the optional advisory port per run.
    && localBoundaryValid
    && providerBoundaryValid
    && providerExecutionBindingsValid;
}

function localPlannerBindingValid(binding: LocalAutonomousPlannerBindingReceipt): boolean {
  const localProcess = isLocalProcessPlannerBinding(binding);
  return exactKeys(binding, localProcess ? [
    "actionClassId", "agentId", "bindingId", "executionBinding",
    "modelConfigurationHash", "modelId", "providerId", "toolId",
  ] : [
    "actionClassId", "agentId", "bindingId", "mcpServerId",
    "modelConfigurationHash", "modelId", "providerId", "toolName",
  ])
    && PUBLIC_ID.test(binding.bindingId)
    && PUBLIC_ID.test(binding.actionClassId)
    && PUBLIC_ID.test(binding.agentId)
    && PUBLIC_ID.test(binding.providerId)
    && PUBLIC_ID.test(binding.modelId)
    && SHA256.test(binding.modelConfigurationHash)
    && (localProcess
      ? PUBLIC_ID.test(binding.toolId)
      : isMcpPlannerBinding(binding)
        && PUBLIC_ID.test(binding.mcpServerId)
        && PUBLIC_ID.test(binding.toolName));
}

function localPlannerBoundaryValid(
  boundary: LocalAutonomousPlannerBoundary | undefined,
): boundary is LocalAutonomousPlannerBoundary {
  if (!boundary || !exactKeys(boundary, [
    "bindings",
    "canonicalContractRequired",
    "heuristicToolArguments",
    "kind",
    "policyHash",
    "policyId",
    "providerContact",
    "runtimeManifestRequired",
    "schemaVersion",
  ])) return false;
  if (
    boundary.schemaVersion !== LOCAL_AUTONOMOUS_PLANNER_BOUNDARY_SCHEMA_VERSION
    || boundary.kind !== "local_deterministic"
    || boundary.providerContact !== false
    || boundary.canonicalContractRequired !== true
    || boundary.runtimeManifestRequired !== true
    || boundary.heuristicToolArguments !== false
    || !PUBLIC_ID.test(boundary.policyId)
    || !SHA256.test(boundary.policyHash)
    || !Array.isArray(boundary.bindings)
    || boundary.bindings.length === 0
    || boundary.bindings.length > 128
    || !boundary.bindings.every(localPlannerBindingValid)
  ) return false;
  const bindingIds = boundary.bindings.map(({ bindingId }) => bindingId);
  return new Set(bindingIds).size === bindingIds.length;
}

function evaluatorContractValid(
  evaluator: ProductionAutonomousOutcomeEvaluatorPort | undefined,
): boolean {
  if (!evaluator) return false;
  const contract = evaluator.autonomousContract;
  return typeof evaluator.evaluate === "function"
    && contract !== null
    && typeof contract === "object"
    && exactKeys(contract, [
      "schemaVersion",
      "evaluatorId",
      "evidenceAuthority",
      "successAuthority",
      "providerContact",
    ])
    && contract.schemaVersion === AUTONOMOUS_OUTCOME_EVALUATOR_CONTRACT_SCHEMA_VERSION
    && PUBLIC_ID.test(contract.evaluatorId)
    && contract.evidenceAuthority === "verified_evidence_only"
    && contract.successAuthority === "criteria_evaluation_only"
    && contract.providerContact === false;
}

function specialistExecutionContractValid(
  execution: ProductionAutonomousExecutionFactory | undefined,
): "mcp" | "reviewed_local_process" | null {
  if (!execution || typeof execution.create !== "function") return null;
  if ("localProcessContract" in execution) {
    const contract = execution.localProcessContract;
    return exactKeys(contract, [
      "adapterId", "cancellation", "directArgv", "executionBinding",
      "publicProviderToolExecution", "resultDelivery", "schemaVersion", "shell",
    ])
      && contract.schemaVersion === "ti-scale.autonomous-local-process-execution.v1"
      && PUBLIC_ID.test(contract.adapterId)
      && contract.executionBinding === "reviewed_local_process"
      && contract.directArgv === true
      && contract.shell === false
      && contract.resultDelivery === "bound_execution_result_sink"
      && contract.cancellation === "run_scoped_cooperative"
      && contract.publicProviderToolExecution === false
      ? "reviewed_local_process"
      : null;
  }
  try {
    assertSpecialistToolInvocationAdapterContract(execution.adapterContract);
    return "mcp";
  } catch {
    return null;
  }
}

function executableMcpPolicy(
  projection: RuntimeProjectionInput,
  serverId: string,
  agentId?: string,
): boolean {
  const server = projection.mcpServers.find(({ id }) => id === serverId);
  return server?.status === "healthy"
    && isSpecialistMcpExecutionPolicy(server.policy)
    && (agentId === undefined || server.policy.assignedAgents.includes(agentId));
}

function specialistToolPolicyAllows(
  projection: RuntimeProjectionInput,
  agentId: string,
  toolId: string,
): boolean {
  const policy = projection.agents.find(({ id }) => id === agentId)?.toolPolicy;
  if (!policy) return false;
  const allowed = Array.isArray(policy.allowedTools)
    ? policy.allowedTools.filter((value): value is string => typeof value === "string")
    : [];
  const denied = Array.isArray(policy.deniedTools)
    ? policy.deniedTools.filter((value): value is string => typeof value === "string")
    : [];
  const approvalRequired = Array.isArray(policy.approvalRequiredTools)
    ? policy.approvalRequiredTools.filter((value): value is string => typeof value === "string")
    : [];
  return allowed.includes(toolId)
    && !denied.includes(toolId)
    && !approvalRequired.includes(toolId);
}

function executableSpecialist(
  projection: RuntimeProjectionInput,
  agentId: string,
  adapterId: string | undefined,
  executionKind: "mcp" | "reviewed_local_process" | null,
  nowMs: number,
  heartbeatMaximumAgeMs: number,
): boolean {
  const agent = projection.agents.find(({ id }) => id === agentId);
  if (!agent || !adapterId) return false;
  const configuration = agent.configuration;
  const expected = [
    "adapterId",
    "executionMode",
    "publicProviderToolExecution",
    "resultDelivery",
    "schemaVersion",
    "shellInterpolation",
    "toolSelection",
  ];
  const heartbeatAt = typeof agent.lastHeartbeatAt === "string"
    ? Date.parse(agent.lastHeartbeatAt)
    : Number.NaN;
  return agent.status === "available"
    && exactKeys(configuration, expected)
    && configuration.schemaVersion === "ti-scale.autonomous-specialist-runtime.v1"
    && configuration.executionMode === (executionKind === "reviewed_local_process"
      ? "reviewed_local_process"
      : "specialist_runtime")
    && configuration.adapterId === adapterId
    && configuration.toolSelection === "exact_persisted_binding_only"
    && configuration.resultDelivery === "bound_execution_result_sink"
    && configuration.shellInterpolation === false
    && configuration.publicProviderToolExecution === false
    && Number.isFinite(heartbeatAt)
    && heartbeatAt <= nowMs
    && heartbeatAt >= nowMs - heartbeatMaximumAgeMs;
}

function readyActionClasses(
  projection: RuntimeProjectionInput,
  manifests: RuntimeSourceManifests,
  providerRefs: ReadonlySet<string>,
  localDeterministicProviderRefs: ReadonlySet<string>,
  adapterId: string | undefined,
  executionKind: "mcp" | "reviewed_local_process" | null,
  nowMs: number,
  heartbeatMaximumAgeMs: number,
  localBindings?: readonly LocalAutonomousPlannerBindingReceipt[],
): readonly string[] {
  const capability = buildRuntimeCapabilityProjection(manifests, new Date(nowMs));
  const tools = new Map(manifests.tools.map((tool) => [tool.id, tool]));
  const agents = new Map(manifests.agents.map((agent) => [agent.id, agent]));
  return Object.values(capability.actionClasses)
    .filter((mapping) => mapping.availability === "supported"
      && mapping.enforcementReady
      && (
        mapping.enforcedProviderModelRefs.some((providerRef) => providerRefs.has(providerRef))
        || mapping.providerModelRefs.some((providerRef) =>
          providerRefs.has(providerRef) && localDeterministicProviderRefs.has(providerRef))
      )
      && mapping.availableAgentIds.some((agentId) => {
        const agent = agents.get(agentId);
        if (
          !agent
          || !executableSpecialist(
            projection,
            agentId,
            adapterId,
            executionKind,
            nowMs,
            heartbeatMaximumAgeMs,
          )
        ) return false;
        const standardModelRoute = agent.modelRefs.some(({ providerId, modelId }) => {
            const providerRef = `${providerId}/${modelId}`;
            return providerRefs.has(providerRef)
              && mapping.enforcedProviderModelRefs.includes(providerRef);
          });
        const localDeterministicModelRoute = agent.modelRefs.some(({ providerId, modelId }) => {
          const providerRef = `${providerId}/${modelId}`;
          return providerRefs.has(providerRef)
            && localDeterministicProviderRefs.has(providerRef)
            && mapping.providerModelRefs.includes(providerRef);
        });
        if (!standardModelRoute && !localDeterministicModelRoute) return false;
        return mapping.availableToolIds.some((toolId) => {
          const tool = tools.get(toolId);
          const localBindingMatches = !localBindings || localBindings.some((binding) =>
            binding.actionClassId === mapping.actionClassId
            && binding.agentId === agentId
            && (isLocalProcessPlannerBinding(binding)
              ? binding.executionBinding === "reviewed_local_process"
                && binding.toolId === toolId
                && tool?.mcpServerId === undefined
              : isMcpPlannerBinding(binding)
                && binding.toolName === toolId
                && binding.mcpServerId === tool?.mcpServerId)
            && providerRefs.has(`${binding.providerId}/${binding.modelId}`));
          const executionRouteMatches = standardModelRoute
            || (localDeterministicModelRoute && tool?.requiresModel === false);
          return localBindingMatches && executionRouteMatches && tool !== undefined
            && agent.toolIds.includes(toolId)
            && specialistToolPolicyAllows(projection, agentId, toolId)
            && (executionKind === "reviewed_local_process"
              ? tool.mcpServerId === undefined
              : tool.mcpServerId !== undefined
                && executableMcpPolicy(projection, tool.mcpServerId, agentId));
        });
      }))
    .map(({ actionClassId }) => actionClassId)
    .sort((left, right) => left.localeCompare(right));
}

function enforcingProviderRoute(
  projection: RuntimeProjectionInput,
  input: Readonly<{ providerId: string; modelId: string; modelConfigurationHash: string }>,
  nowMs: number,
): boolean {
  return projection.readiness.providers.some((provider) => {
    const attestedAt = provider.attestedAt ? Date.parse(provider.attestedAt) : Number.NaN;
    const expiresAt = provider.expiresAt ? Date.parse(provider.expiresAt) : Number.NaN;
    return provider.id === input.providerId
      && provider.health === "healthy"
      && provider.authenticated
      && provider.callable
      && provider.circuitState === "closed"
      && provider.enforcesAutonomousBoundary
      && provider.requestedModel === input.modelId
      && provider.returnedModel === input.modelId
      && provider.modelConfigurationHash === input.modelConfigurationHash
      && typeof provider.completionProbeReceiptId === "string"
      && PUBLIC_ID.test(provider.completionProbeReceiptId)
      && Number.isFinite(attestedAt)
      && Number.isFinite(expiresAt)
      && attestedAt <= nowMs
      && expiresAt > nowMs
      && expiresAt > attestedAt;
  });
}

function blocker(
  code: AutonomousRuntimeCompositionBlockerCode,
  component: AutonomousRuntimeCompositionBlocker["component"],
  impact: string,
  remediation: string,
): AutonomousRuntimeCompositionBlocker {
  return { code, component, impact, remediation };
}

/**
 * Evaluates actual adapter objects plus the current live runtime projection.
 * Configuration flags alone cannot make this report ready.
 */
export function inspectAutonomousRuntimeComposition(
  input: InspectAutonomousRuntimeCompositionInput,
): AutonomousRuntimeCompositionReadiness {
  const { projection } = input;
  const now = input.now ?? new Date();
  const nowMs = now.getTime();
  const heartbeatMaximumAgeMs = input.specialistHeartbeatMaximumAgeMs
    ?? DEFAULT_AUTONOMOUS_SPECIALIST_HEARTBEAT_MAXIMUM_AGE_MS;
  if (!Number.isFinite(nowMs)) throw new RangeError("Autonomous composition time is invalid");
  if (
    !Number.isSafeInteger(heartbeatMaximumAgeMs)
    || heartbeatMaximumAgeMs < 1_000
    || heartbeatMaximumAgeMs > 300_000
  ) {
    throw new RangeError("specialistHeartbeatMaximumAgeMs must be 1000 through 300000");
  }
  const planner = input.adapters?.planner;
  const providerAdvisory = input.adapters?.providerAdvisory;
  const providerContext = input.adapters?.providerContext;
  const evaluator = input.adapters?.outcomeEvaluator;
  const execution = input.adapters?.execution;
  const blockers: AutonomousRuntimeCompositionBlocker[] = [];

  const plannerValid = plannerContractValid(planner);
  if (!planner) {
    blockers.push(blocker(
      "autonomous_planner_adapter_missing",
      "planner",
      "No Autonomous planner object is mounted; the Guided manual planner cannot plan this journey.",
      "Attach one reviewed bounded planner: either an exact public-provider planner or a local deterministic contract planner with reviewed specialist bindings.",
    ));
  } else if (!plannerValid) {
    blockers.push(blocker(
      "autonomous_planner_contract_invalid",
      "planner",
      "The mounted planner does not satisfy the exact signed-plan and tool-free provider-exposure contract.",
      "Implement ti-scale.autonomous-planner-adapter.v1 with no provider tool declarations and no dispatch authority.",
    ));
  }
  const providerAdvisoryBoundaryValid =
    providerAdvisory === undefined && providerContext === undefined
      ? true
      : providerAdvisory?.route === "provider_advisory"
        && providerAdvisory.executionAuthority === "none"
        && typeof providerAdvisory.plan === "function"
        && typeof providerContext?.prepare === "function";
  if (!providerAdvisoryBoundaryValid) {
    blockers.push(blocker(
      "autonomous_provider_advisory_boundary_invalid",
      "provider",
      "The optional provider-advisory route is incomplete or has execution authority.",
      "Mount the advisor-only runtime and provider-safe Brain context adapter together, or omit both for local-only planning.",
    ));
  }

  const evaluatorValid = evaluatorContractValid(evaluator);
  if (!evaluator) {
    blockers.push(blocker(
      "autonomous_outcome_evaluator_missing",
      "evaluator",
      "No evidence-aware Autonomous outcome evaluator is mounted.",
      "Attach an evaluator that uses verified evidence only and cannot declare success outside explicit criteria.",
    ));
  } else if (!evaluatorValid) {
    blockers.push(blocker(
      "autonomous_outcome_evaluator_contract_invalid",
      "evaluator",
      "The mounted outcome evaluator does not preserve local verified-evidence and criteria-only authority.",
      "Implement ti-scale.autonomous-outcome-evaluator.v1 without public-provider contact.",
    ));
  }

  const executionKind = specialistExecutionContractValid(execution);
  const executionValid = executionKind !== null;
  const aggregateActivationReceiptBoundary = Boolean(
    planner && evaluator && execution,
  );
  const executionAdapterId = executionKind === "reviewed_local_process"
    ? (execution as ProductionAutonomousLocalProcessExecutionFactory).localProcessContract.adapterId
    : executionKind === "mcp"
      ? (execution as ProductionAutonomousSpecialistExecutionFactory).adapterContract.adapterId
      : undefined;
  if (!execution) {
    blockers.push(blocker(
      "specialist_execution_factory_missing",
      "execution",
      "No result-aware specialist execution factory is mounted.",
      "Supply a reviewed local-process or SpecialistToolDispatchService factory that receives only the runtime's re-checkable lease proof callback.",
    ));
  } else if (!executionValid) {
    blockers.push(blocker(
      "specialist_execution_adapter_contract_invalid",
      "execution",
      "The specialist transport permits an unsafe selection, shell, result, cancellation, or public-provider execution boundary.",
      "Use exact persisted bindings, shellInterpolation=false, publicProviderToolExecution=false, cooperative run cancellation, and a bound result sink.",
    ));
  }
  if (!aggregateActivationReceiptBoundary) {
    blockers.push(blocker(
      "autonomous_activation_receipt_boundary_missing",
      "activation",
      "The production composition cannot issue and verify one aggregate run activation receipt.",
      "Mount the complete planner, evaluator, and execution composition so the mandatory aggregate receipt boundary is constructed with the runtime.",
    ));
  }

  const readiness = projection.readiness;
  const durableActionBoundary = readiness.actionBoundaryActive
    && readiness.delegationEnforced
    && readiness.noHandsCommanderEnforced
    && readiness.directCommanderToolsDenied
    && readiness.specialistAssignmentRequired;
  if (!durableActionBoundary) {
    blockers.push(blocker(
      "autonomous_action_boundary_inactive",
      "policy",
      "The live runtime does not enforce every durable delegation and no-hands commander invariant.",
      "Mount the V2 coordinator, require specialist assignment, deny direct commander tools, and re-evaluate current policy.",
    ));
  }

  const localBoundary = plannerValid ? planner!.localPlanningBoundary : undefined;
  const exactExecutionBindings = planner?.autonomousExecutionBindings
    ?? localBoundary?.bindings
    ?? [];
  // Readiness is about executable specialist pins, never the advisory model.
  // A provider advisor has no action authority and cannot satisfy this gate.
  const requiredProviderRoutes = exactExecutionBindings.map((binding) => ({
    providerId: binding.providerId,
    modelId: binding.modelId,
    modelConfigurationHash: binding.modelConfigurationHash,
  }));
  const uniqueProviderRoutes = [...new Map(requiredProviderRoutes.map((route) => [
    `${route.providerId}/${route.modelId}/${route.modelConfigurationHash}`,
    route,
  ])).values()];
  const enforcingProvider = uniqueProviderRoutes.length > 0
    && uniqueProviderRoutes.every((route) => enforcingProviderRoute(projection, route, nowMs));
  if (!enforcingProvider) {
    blockers.push(blocker(
      "autonomous_provider_route_unavailable",
      "provider",
      localBoundary
        ? "No fresh enforcing provider route matches every specialist model pinned by the local planning policy. Local planning does not weaken execution-model readiness."
        : "No fresh enforcing provider route matches the planner's exact requested and returned model configuration.",
      "Attach and attest every Autonomous-compatible specialist provider/model route; planning-only OpenRouter readiness is insufficient.",
    ));
  }

  const specialistFleet = readiness.specialistsConfigured > 0
    && projection.agents.some(({ id }) => executableSpecialist(
      projection,
      id,
      executionAdapterId,
      executionKind,
      nowMs,
      heartbeatMaximumAgeMs,
    ));
  if (!specialistFleet) {
    blockers.push(blocker(
      "autonomous_specialist_unavailable",
      "specialist",
      "No specialist has a current execution-capable runtime binding.",
      "Declare only real specialist workers whose provider, tool, assignment, and heartbeat state is current.",
    ));
  }

  const mcpExecution = executionKind === "mcp"
    && readiness.mcp.enabled
    && readiness.mcp.executionMode === "enabled"
    && readiness.mcp.startPermitted
    && readiness.mcp.runnableServers > 0
    && projection.mcpServers.some(({ id }) => executableMcpPolicy(projection, id));
  const localProcessExecution = executionKind === "reviewed_local_process";
  const requiresMcpExecution = executionKind === "mcp"
    || localBoundary?.bindings.some((binding) => !("executionBinding" in binding)) === true;
  if (requiresMcpExecution && !mcpExecution) {
    blockers.push(blocker(
      "autonomous_mcp_execution_unavailable",
      "mcp",
      "No reviewed runnable MCP execution route is mounted.",
      "Attach a closed exact-inventory route with signed-contract specialist-action authorization; the public NVD read adapter cannot be reused.",
    ));
  }

  const manifests = projection.capabilityManifests;
  let exactRuntimeManifest = false;
  let actionClassIds: readonly string[] = [];
  if (manifests) {
    try {
      buildRuntimeCapabilityProjection(manifests, now);
      exactRuntimeManifest = true;
      const providerRefs = new Set(uniqueProviderRoutes.map((route) =>
        `${route.providerId}/${route.modelId}`));
      const localDeterministicProviderRefs = new Set(
        projection.readiness.providers
          .filter((provider) => provider.executionBoundary === "local_deterministic_policy"
            && typeof provider.requestedModel === "string"
            && uniqueProviderRoutes.some((route) =>
              route.providerId === provider.id
              && route.modelId === provider.requestedModel
              && enforcingProviderRoute(projection, route, nowMs)))
          .map((provider) => `${provider.id}/${provider.requestedModel!}`),
      );
      actionClassIds = readyActionClasses(
        projection,
        manifests,
        providerRefs,
        localDeterministicProviderRefs,
        executionAdapterId,
        executionKind,
        nowMs,
        heartbeatMaximumAgeMs,
        exactExecutionBindings,
      );
    } catch {
      exactRuntimeManifest = false;
    }
  }
  if (!exactRuntimeManifest) {
    blockers.push(blocker(
      "runtime_manifest_invalid",
      "manifest",
      "The current runtime has no valid cross-referenced provider, specialist, execution-binding, and tool manifest.",
      "Publish one typed live manifest from the mounted adapters; a local binding registry cannot add capabilities.",
    ));
  } else if (actionClassIds.length === 0) {
    blockers.push(blocker(
      "autonomous_action_mapping_unavailable",
      "manifest",
      executionKind === "reviewed_local_process"
        ? "No action class has a live available specialist, reviewed local tool, and matching attested local-process route."
        : "No action class has a live available specialist, locally enforced exact MCP tool, and matching attested MCP route.",
      executionKind === "reviewed_local_process"
        ? "Reconcile the same stable IDs across the specialist, local deterministic boundary, tool, risk, and action-class manifests."
        : "Reconcile the same stable IDs across the specialist, provider, MCP policy, tool, risk, and action-class manifests.",
    ));
  }

  blockers.sort((left, right) => left.code.localeCompare(right.code));
  return Object.freeze({
    schemaVersion: "ti-scale.autonomous-runtime-composition.v1",
    status: blockers.length === 0 ? "ready" : "blocked",
    readyActionClassIds: Object.freeze([...actionClassIds]),
    components: Object.freeze({
      plannerAdapter: plannerValid,
      outcomeEvaluator: evaluatorValid,
      resultAwareSpecialistExecution: executionValid,
      enforcingProvider,
      durableActionBoundary,
      specialistFleet,
      mcpExecution,
      localProcessExecution,
      providerAdvisoryBoundary: providerAdvisoryBoundaryValid,
      aggregateActivationReceiptBoundary,
      exactRuntimeManifest,
    }),
    blockers: Object.freeze(blockers),
  });
}

export class AutonomousRuntimeCompositionError extends Error {
  constructor(readonly readiness: AutonomousRuntimeCompositionReadiness) {
    super(`Autonomous runtime composition is blocked: ${readiness.blockers.map(({ code }) => code).join(", ")}`);
    this.name = "AutonomousRuntimeCompositionError";
  }
}

export interface CreateProductionAutonomousRuntimeOptions {
  readonly database: SqliteDatabase;
  readonly operationalHazardHmacKey?: string | Buffer;
  readonly brainContext?: BrainContextService;
  readonly projectMemoryNodes?: MissionRuntimeOptions["projectMemoryNodes"];
  readonly postReconPlanExpansion?: AutonomousPostReconPlanExpansionPort;
  readonly reportArtifactRoot?: string;
  readonly adapters: ProductionAutonomousRuntimeAdapters;
  readonly readRuntimeProjection: () => RuntimeProjectionInput;
  readonly workerId?: string;
  readonly scanIntervalMs?: number;
  readonly leaseTtlMs?: number;
  readonly decisionTtlMs?: number;
  readonly now?: () => Date;
  readonly crashAfterCommit?: MissionRuntimeOptions["crashAfterCommit"];
}

/**
 * Creates, but does not start, an Autonomous-only runtime after the exact live
 * composition passes. The execution service receives no raw token and cannot
 * be constructed independently of the runtime-owned authority callback.
 */
export function createProductionAutonomousRuntime(
  options: CreateProductionAutonomousRuntimeOptions,
): MissionRuntimeEngine {
  const readiness = inspectAutonomousRuntimeComposition({
    projection: options.readRuntimeProjection(),
    adapters: options.adapters,
    now: options.now?.() ?? new Date(),
  });
  if (readiness.status !== "ready") throw new AutonomousRuntimeCompositionError(readiness);

  let runtime: MissionRuntimeEngine | undefined;
  const execution = options.adapters.execution.create({
    database: options.database,
    assertControlPlaneAuthority(runId) {
      if (!runtime) throw new Error("Autonomous runtime authority is not initialized");
      return runtime.assertControlPlaneMutationAuthority(runId);
    },
  });
  const autonomousActivation = new AutonomousActivationRuntimeService(
    options.database,
    options.readRuntimeProjection,
    options.now ?? (() => new Date()),
    options.adapters.planner.autonomousExecutionBindings
      ?? options.adapters.planner.localPlanningBoundary?.bindings
      ?? [],
  );
  runtime = new MissionRuntimeEngine({
    database: options.database,
    ...(options.operationalHazardHmacKey
      ? { operationalHazardHmacKey: options.operationalHazardHmacKey }
      : {}),
    planner: options.adapters.planner,
    outcomeEvaluator: options.adapters.outcomeEvaluator,
    execution,
    autonomousActivation,
    autonomousPlanning: {
      ...(options.adapters.providerAdvisory
        ? { providerAdvisory: options.adapters.providerAdvisory }
        : {}),
      ...(options.adapters.providerContext
        ? { providerContext: options.adapters.providerContext }
        : {}),
    },
    agentRuntimeBindings: new AgentRuntimeBindingService(
      options.database,
      undefined,
      {
        clock: options.now ?? (() => new Date()),
      },
    ),
    supportedJourneys: ["autonomous"],
    autonomousTerminalDeliverables: new AutonomousTerminalDeliverableService(
      options.database,
      {
        ...(options.reportArtifactRoot ? { artifactRoot: options.reportArtifactRoot } : {}),
        ...(options.now ? { clock: options.now } : {}),
      },
    ),
    ...(options.brainContext ? { brainContext: options.brainContext } : {}),
    ...(options.projectMemoryNodes ? { projectMemoryNodes: options.projectMemoryNodes } : {}),
    ...(options.workerId ? { workerId: options.workerId } : {}),
    ...(options.scanIntervalMs ? { scanIntervalMs: options.scanIntervalMs } : {}),
    ...(options.leaseTtlMs ? { leaseTtlMs: options.leaseTtlMs } : {}),
    ...(options.decisionTtlMs ? { decisionTtlMs: options.decisionTtlMs } : {}),
    ...(options.now ? { now: options.now } : {}),
    ...(options.crashAfterCommit
      ? { crashAfterCommit: options.crashAfterCommit }
      : {}),
  } satisfies MissionRuntimeOptions);
  if (options.postReconPlanExpansion) {
    runtime.configureAutonomousPostReconPlanExpansion(
      options.postReconPlanExpansion,
    );
  }
  return runtime;
}

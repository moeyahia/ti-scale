import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  BrainContextService,
  CanonicalMissionMemoryGraph,
} from "../../brain-runtime";
import {
  AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
  AutonomousActivationRuntimeService,
  autonomousSuccessCriterionId,
  LocalAutonomousContractPlanner,
  LocalVerifiedEvidenceOutcomeEvaluator,
  type LocalAutonomousPlannerBindingReceipt,
  type LocalAutonomousPlanningPolicy,
} from "../../autonomous-runtime";
import {
  PROVIDER_ADVISORY_SELECTION_SCHEMA_VERSION,
  ProviderAdvisoryBrainContextAdapter,
  ProviderAdvisoryRuntimeService,
} from "../../autonomous-planning";
import type {
  ExecutionResult,
  ExecutionResultReceipt,
} from "../../command-runtime";
import { RuntimeRepository } from "../../command-runtime";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { ACTION_CLASS_IDS } from "../../domain";
import { MissionIntakeService } from "../../intake";
import {
  MemoryRepository,
  SecondBrainService,
} from "../../memory";
import { digestCanonicalJson, type McpCapabilityAttestation } from "../../mcp";
import {
  ModelConfigurationRepository,
  ModelConfigurationService,
  modelConfigurationBindingHash,
  type AutonomousPlanningSelection,
} from "../../model-config";
import {
  MissionRepository,
  MissionService,
  OverviewRepository,
  ReadinessService,
} from "../../missions";
import { CanonicalMissionReportService } from "../../reports";
import {
  OpenRouterPlanningClient,
  OpenRouterProviderRequestAuditor,
} from "../../providers/openrouter";
import {
  SPECIALIST_TOOL_ADAPTER_CONTRACT_SCHEMA_VERSION,
  SpecialistToolDispatchService,
  type SpecialistMcpToolBinding,
  type SpecialistToolInvocation,
  type SpecialistToolInvocationAdapter,
  type SpecialistToolInvocationResultSink,
} from "../../specialist-runtime";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import {
  ConnectedVaultMemoryProjector,
  ObsidianVaultBridge,
  VaultPathPolicy,
  VaultProjectionReconciliationService,
} from "../../vault";
import type { RuntimeProjectionInput } from "../RuntimeProjectionService";
import { createRuntimeReadinessProviders } from "../RuntimeReadiness";
import {
  createProductionAutonomousRuntime,
  inspectAutonomousRuntimeComposition,
  type ProductionAutonomousRuntimeAdapters,
} from "../AutonomousRuntimeComposition";

const NOW = new Date("2026-07-19T10:30:00.000Z");
const TARGET = "fixture://authorized-host";
const INTAKE_TARGET = "127.0.0.254";
const MISSION_ID = "mission-autonomous-activation-fixture";
const RUN_ID = "run-autonomous-activation-fixture";
const CONTRACT_ID = "contract-autonomous-activation-fixture";
const CONTRACT_HASH = "c".repeat(64);
const MODEL_CONFIGURATION_HASH = "a".repeat(64);
const CRITERION = "The disposable authorized host baseline is supported by verified evidence";
const TOOL_ID = "tool-disposable-host-baseline";
const MCP_SERVER_ID = "fixture-specialist-mcp";
const AGENT_ID = "ReconScout";
const MODEL_CONFIGURATION_ID = "modelcfg-autonomous-activation-fixture";
const MODEL_ASSIGNMENT_ID = "modelassign-autonomous-activation-fixture";
const ADVISOR_MODEL_CONFIGURATION_ID =
  "modelcfg-autonomous-advisory-activation-fixture";
const ADVISOR_MODEL_ASSIGNMENT_ID =
  "modelassign-autonomous-advisory-activation-fixture";
const ADVISOR_MODEL_ID = "openai/gpt-5.2";
const ADAPTER_ID = "disposable-result-aware-specialist-transport";

const PROVIDER_ADVISORY_SELECTION = Object.freeze({
  route: "provider_advisory",
  agentId: AGENT_ID,
  primaryConfigurationId: ADVISOR_MODEL_CONFIGURATION_ID,
  fallbackConfigurationId: null,
  enforcementMode: "advisor_only",
  disclosureClass: "sanitized_internal",
  executionAuthority: "none",
} satisfies AutonomousPlanningSelection);

const TOOL_INPUT_SCHEMA = Object.freeze({
  type: "object",
  additionalProperties: false,
  required: ["mode", "target"],
  properties: {
    mode: { type: "string", const: "disposable_fixture_only" },
    target: { type: "string", minLength: 1, maxLength: 2_000 },
  },
} as const);

const databases: SqliteDatabase[] = [];
const runtimes: Array<ReturnType<typeof createProductionAutonomousRuntime>> = [];
const temporaryDirectories: string[] = [];

afterEach(async () => {
  for (const runtime of runtimes.splice(0)) await runtime.stop();
  for (const database of databases.splice(0)) database.close();
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { force: true, recursive: true })));
});

function planningPolicy(
  modelConfigurationHash = MODEL_CONFIGURATION_HASH,
): LocalAutonomousPlanningPolicy {
  return {
    schemaVersion: "ti-scale.local-autonomous-planning-policy.v1",
    policyId: "reviewed-disposable-activation-fixture-v1",
    maximumSteps: 1,
    bindings: [{
      bindingId: "binding-disposable-host-baseline-v1",
      actionClassId: "active_host_discovery",
      targetKinds: ["environment", "ip"],
      phase: "Disposable baseline",
      title: "Establish the disposable host baseline",
      objective: "Retain one attributable result for the exact disposable target",
      explanation: "The fixture specialist handles one exact in-memory binding without opening a socket, process, provider, or external MCP connection.",
      rationale: "This proves durable planning, dispatch correlation, evidence gating, evaluation, cancellation, and policy denial without granting a production execution route.",
      successCriteria: [CRITERION],
      reversibility: "The in-memory fixture has no external side effect and supports cooperative cancellation.",
      riskClass: "medium",
      idempotent: false,
      destructive: false,
      agentId: AGENT_ID,
      providerId: "fixture-enforcing-provider",
      modelId: "fixture-reviewed-model",
      modelConfigurationHash,
      mcpServerId: MCP_SERVER_ID,
      toolName: TOOL_ID,
      targetParameter: "target",
      staticParameters: { mode: "disposable_fixture_only" },
      capabilityIds: ["cap-disposable-recon"],
      requiredEvidenceTypeIds: ["asset_discovery_proof"],
    }],
  };
}

function projection(
  modelConfigurationHash = MODEL_CONFIGURATION_HASH,
): RuntimeProjectionInput {
  return {
    readiness: {
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: true,
      specialistsConfigured: 1,
      providers: [{
        id: "fixture-enforcing-provider",
        health: "healthy",
        configured: true,
        authenticated: true,
        callable: true,
        attestedAt: "2026-07-19T10:29:30.000Z",
        expiresAt: "2026-07-19T10:35:00.000Z",
        circuitState: "closed",
        completionProbeReceiptId: "fixture-provider-probe",
        supportsGuided: false,
        enforcesAutonomousBoundary: true,
        reportsExactTokenUsage: true,
        reportsExactCostUsage: true,
        requestedModel: "fixture-reviewed-model",
        returnedModel: "fixture-reviewed-model",
        modelConfigurationHash,
      }],
      mcp: {
        enabled: true,
        executionMode: "enabled",
        startPermitted: true,
        configuredServers: 1,
        runnableServers: 1,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      eventStream: "healthy",
      secondBrain: "healthy",
      legacyExecutionEnabled: false,
    },
    agents: [{
      id: AGENT_ID,
      role: "disposable-reconnaissance",
      displayName: "Disposable Recon Scout",
      status: "available",
      providerPolicy: {},
      toolPolicy: {
        allowedTools: [TOOL_ID],
        deniedTools: [],
        approvalRequiredTools: [],
      },
      configuration: {
        schemaVersion: "ti-scale.autonomous-specialist-runtime.v1",
        executionMode: "specialist_runtime",
        adapterId: ADAPTER_ID,
        toolSelection: "exact_persisted_binding_only",
        resultDelivery: "bound_execution_result_sink",
        shellInterpolation: false,
        publicProviderToolExecution: false,
      },
      version: "fixture-1",
      lastHeartbeatAt: "2026-07-19T10:29:45.000Z",
      capabilities: [{ name: "cap-disposable-recon", source: "fixture", enabled: true }],
    }],
    mcpServers: [{
      id: MCP_SERVER_ID,
      name: "Disposable specialist MCP fixture",
      transport: "in-memory-test-only",
      status: "healthy",
      capabilities: [TOOL_ID],
      policy: {
        schemaVersion: "ti-scale.specialist-mcp-execution-policy.v1",
        enabled: true,
        startPermitted: true,
        executionAuthorization: "signed_contract_specialist_action",
        autonomousExecution: true,
        exactInventoryRequired: true,
        directCommanderToolsAllowed: false,
        assignedAgents: [AGENT_ID],
      },
      capabilityAttestation: capabilityAttestation(),
      lastCheckedAt: "2026-07-19T10:29:45.000Z",
    }],
    capabilityManifests: {
      riskClasses: [{
        id: "risk-moderate",
        label: "Moderate",
        actionClassIds: ["active_host_discovery"],
      }],
      evidenceKinds: [{
        id: "evidence-asset-discovery",
        label: "Asset discovery proof",
        evidenceTypeIds: ["asset_discovery_proof"],
      }],
      capabilities: [{
        id: "cap-disposable-recon",
        label: "Disposable reconnaissance",
        actionClassIds: ["active_host_discovery"],
        evidenceTypeIds: ["asset_discovery_proof"],
      }],
      tools: [{
        id: TOOL_ID,
        label: "Disposable host baseline fixture",
        available: true,
        locallyPolicyEnforced: true,
        requiresModel: true,
        executionJourneys: ["autonomous"],
        actionClassIds: ["active_host_discovery"],
        evidenceTypeIds: ["asset_discovery_proof"],
        riskClassIds: ["risk-moderate"],
        mcpServerId: MCP_SERVER_ID,
      }],
      mcpServers: [{
        id: MCP_SERVER_ID,
        label: "Disposable specialist MCP fixture",
        status: "healthy",
        toolIds: [TOOL_ID],
      }],
      agents: [{
        id: AGENT_ID,
        label: "Disposable Recon Scout",
        available: true,
        capabilityIds: ["cap-disposable-recon"],
        actionClassIds: ["active_host_discovery"],
        toolIds: [TOOL_ID],
        modelRefs: [{ providerId: "fixture-enforcing-provider", modelId: "fixture-reviewed-model" }],
      }],
      providers: [{
        id: "fixture-enforcing-provider",
        authenticated: true,
        healthy: true,
        catalogObservedAt: "2026-07-19T10:29:45.000Z",
        models: [{
          id: "fixture-reviewed-model",
          displayName: "Fixture reviewed model",
          toolCalling: true,
          structuredOutput: true,
          enforcement: "enforced_executor",
          compatibleActionClassIds: ["active_host_discovery"],
          disclosureClasses: ["public"],
        }],
      }],
    },
  };
}

function capabilityAttestation(): McpCapabilityAttestation {
  const inputSchema = digestCanonicalJson(TOOL_INPUT_SCHEMA, {
    maxBytes: 64 * 1_024,
    maxDepth: 32,
  });
  const unsigned = {
    schemaVersion: "ti-scale.mcp-capability-attestation.v1",
    connectionId: MCP_SERVER_ID,
    transport: "stdio",
    server: { name: MCP_SERVER_ID, version: "fixture-1" },
    protocolVersion: "2025-06-18",
    capabilities: { toolsListChanged: false },
    configurationSha256: "d".repeat(64),
    tools: [{
      name: TOOL_ID,
      description: "Test-only in-memory disposable host baseline binding.",
      inputSchema: TOOL_INPUT_SCHEMA,
      inputSchemaSha256: inputSchema.sha256,
      inputSchemaBytes: inputSchema.bytes,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    }],
    attestedAt: "2026-07-19T10:29:30.000Z",
    expiresAt: "2026-07-19T10:35:00.000Z",
    executionAuthorization: "none",
  } as const;
  return {
    ...unsigned,
    manifestSha256: digestCanonicalJson(unsigned, {
      maxBytes: 64 * 1024 * 1024,
      maxDepth: 256,
    }).sha256,
  };
}

function localToolAttestation(observedAt: string, expiresAt: string) {
  return {
    schemaVersion: "ti-scale.local-tool-activation-receipt.v1" as const,
    source: "local_guided_tool_activation" as const,
    manifestSha256: "1".repeat(64),
    toolBindingSha256: "2".repeat(64),
    preflightBindingSha256: "3".repeat(64),
    executableSha256: "4".repeat(64),
    observedAt,
    expiresAt,
  };
}

function localActivationProjection(
  modelConfigurationHash: string,
  attestation: ReturnType<typeof localToolAttestation>,
): RuntimeProjectionInput {
  const base = projection(modelConfigurationHash);
  const manifest = base.capabilityManifests!;
  const sourceTool = manifest.tools[0]!;
  const { mcpServerId: _mcpServerId, ...localTool } = sourceTool;
  return {
    ...base,
    mcpServers: [],
    capabilityManifests: {
      ...manifest,
      tools: [{
        ...localTool,
        dependencies: [{
          id: "fixture-local-executable",
          ready: true,
          attestation,
        }],
      }],
      mcpServers: [],
    },
  };
}

function localExecutionBinding(
  modelConfigurationHash: string,
): LocalAutonomousPlannerBindingReceipt {
  return {
    bindingId: "binding-disposable-host-baseline-local-v1",
    actionClassId: "active_host_discovery",
    agentId: AGENT_ID,
    providerId: "fixture-enforcing-provider",
    modelId: "fixture-reviewed-model",
    modelConfigurationHash,
    executionBinding: "reviewed_local_process",
    toolId: TOOL_ID,
  };
}

function seedLocalActivationLifecycle(
  database: SqliteDatabase,
  modelConfigurationHash: string,
) {
  const now = NOW.toISOString();
  const contextPackId = "context-pack-local-activation-lifecycle";
  const planId = "plan-local-activation-lifecycle";
  const planHash = "5".repeat(64);
  const runtimeModelBinding = {
    schemaVersion: "ti-scale.runtime-model-binding.v1",
    agentId: AGENT_ID,
    modelAssignmentId: MODEL_ASSIGNMENT_ID,
    modelConfigurationId: MODEL_CONFIGURATION_ID,
    modelConfigurationHash,
    providerConfigurationHash: "6".repeat(64),
    providerId: "fixture-enforcing-provider",
    modelId: "fixture-reviewed-model",
    reasoningEffort: null,
  };
  database.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, retrieval_metrics_json,
      created_by, created_at
    ) VALUES (?, ?, ?, 'autonomous', 'planning',
      'Local lifecycle activation context', '{}', 2048, '{}',
      'fixture-runtime', ?)
  `).run(contextPackId, MISSION_ID, RUN_ID, now);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Two bounded local lifecycle actions',
      'Prove immutable activation renewal', ?, 'fixture-runtime', ?, ?)
  `).run(planId, RUN_ID, planHash, now, now);
  const insertStep = database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'Local activation', ?, ?, 'ready',
      '[]', ?, 'active_host_discovery', 'medium', ?, ?, ?)
  `);
  insertStep.run(
    "step-local-activation-1",
    planId,
    RUN_ID,
    0,
    "First bounded local action",
    "Bind the first action before receipt expiry",
    "[]",
    AGENT_ID,
    now,
    now,
  );
  insertStep.run(
    "step-local-activation-2",
    planId,
    RUN_ID,
    1,
    "Second bounded local action",
    "Bind the second action after receipt renewal",
    JSON.stringify(["step-local-activation-1"]),
    AGENT_ID,
    now,
    now,
  );
  const insertAssignment = database.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'active', ?, ?)
  `);
  insertAssignment.run(
    "assignment-local-activation-1",
    RUN_ID,
    "step-local-activation-1",
    AGENT_ID,
    now,
    now,
  );
  insertAssignment.run(
    "assignment-local-activation-2",
    RUN_ID,
    "step-local-activation-2",
    AGENT_ID,
    now,
    now,
  );
  const insertAction = database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, assignment_id, action_type,
      action_class, fingerprint, normalized_arguments_json, scoped_target,
      status, intent_summary, contract_id, context_pack_id, created_at,
      updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'active_host_discovery', ?, ?, ?,
      'running', ?, ?, ?, ?, ?)
  `);
  const actionRows = [
    {
      id: "action-local-activation-1",
      stepId: "step-local-activation-1",
      assignmentId: "assignment-local-activation-1",
      fingerprint: "7".repeat(64),
      intent: "Execute the first bounded local lifecycle action",
    },
    {
      id: "action-local-activation-2",
      stepId: "step-local-activation-2",
      assignmentId: "assignment-local-activation-2",
      fingerprint: "8".repeat(64),
      intent: "Execute the second bounded local lifecycle action",
    },
  ] as const;
  for (const action of actionRows) {
    insertAction.run(
      action.id,
      MISSION_ID,
      RUN_ID,
      action.stepId,
      action.assignmentId,
      TOOL_ID,
      action.fingerprint,
      JSON.stringify({
        input: { toolId: TOOL_ID, target: TARGET },
        orchestration: {
          target: TARGET,
          kind: "tool",
          idempotent: false,
          destructive: false,
          planVersion: 1,
          runtimeModelBinding,
        },
      }),
      TARGET,
      action.intent,
      CONTRACT_ID,
      contextPackId,
      now,
      now,
    );
  }
  return {
    contextPackId,
    planId,
    planHash,
    actionRows,
  };
}

class DisposableResultAwareAdapter implements SpecialistToolInvocationAdapter {
  readonly contract = Object.freeze({
    schemaVersion: SPECIALIST_TOOL_ADAPTER_CONTRACT_SCHEMA_VERSION,
    adapterId: ADAPTER_ID,
    toolSelection: "exact_persisted_binding_only",
    resultDelivery: "bound_execution_result_sink",
    cancellation: "run_scoped_cooperative",
    shellInterpolation: false,
    publicProviderToolExecution: false,
  } as const);
  dispatchCount = 0;
  cancelCount = 0;
  invocation?: SpecialistToolInvocation;
  signal?: AbortSignal;
  cancellation?: Readonly<{ runId: string; reason: string }>;
  #sink?: SpecialistToolInvocationResultSink;

  constructor(
    private readonly dispatchDelayMs = 0,
    private readonly dispatchError?: Error,
  ) {}

  bindResultSink(sink: SpecialistToolInvocationResultSink): () => void {
    this.#sink = sink;
    return () => {
      if (this.#sink === sink) this.#sink = undefined;
    };
  }

  async dispatch(invocation: SpecialistToolInvocation, signal: AbortSignal): Promise<void> {
    this.dispatchCount += 1;
    this.invocation = invocation;
    this.signal = signal;
    if (this.dispatchDelayMs > 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, this.dispatchDelayMs));
    }
    if (this.dispatchError) throw this.dispatchError;
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    this.cancelCount += 1;
    this.cancellation = { runId, reason };
  }

  async emit(result: ExecutionResult): Promise<ExecutionResultReceipt> {
    if (!this.#sink || !this.invocation) throw new Error("Disposable adapter is not bound and dispatched");
    return this.#sink.acceptSpecialistToolResult({
      invocationId: this.invocation.invocationId,
      result,
    });
  }
}

function database(): SqliteDatabase {
  const value = createDatabaseConnection({ filename: ":memory:" });
  databases.push(value);
  migrateDatabase(value);
  return value;
}

function seed(
  database: SqliteDatabase,
  options: {
    databaseToolAllowed?: boolean;
    providerAdvisoryPlanning?: boolean;
    seedMission?: boolean;
  } = {},
): void {
  const now = NOW.toISOString();
  if (options.seedMission !== false) {
    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, status, authorization_status,
        success_criteria_json, memory_policy_json, created_by, created_at,
        updated_at, control_plane
      ) VALUES (?, 'Disposable Autonomous activation fixture',
        'Prove one exact result-aware local execution path', 'autonomous', 'active',
        'verified', ?, '{"exactContextNodeIds":[],"allowedScopes":[]}',
        'operator:fixture', ?, ?, 'ti_scale')
    `).run(MISSION_ID, JSON.stringify([CRITERION]), now, now);
    database.prepare(`
      INSERT INTO mission_targets (
        id, mission_id, target, target_type, disposition, normalized_target, created_at
      ) VALUES ('target-autonomous-activation-fixture', ?, ?, 'environment', 'allowed', ?, ?)
    `).run(MISSION_ID, TARGET, TARGET, now);
  }
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES (?, 'disposable-reconnaissance', 'Disposable Recon Scout', 'available',
      '{}', ?, ?, 'fixture-1', ?, ?, ?)
  `).run(
    AGENT_ID,
    JSON.stringify({
      allowedTools: options.databaseToolAllowed === false ? [] : [TOOL_ID],
      deniedTools: options.databaseToolAllowed === false ? [TOOL_ID] : [],
      approvalRequiredTools: [],
    }),
    JSON.stringify({
      schemaVersion: "ti-scale.autonomous-specialist-runtime.v1",
      executionMode: "specialist_runtime",
      adapterId: ADAPTER_ID,
      toolSelection: "exact_persisted_binding_only",
      resultDelivery: "bound_execution_result_sink",
      shellInterpolation: false,
      publicProviderToolExecution: false,
    }),
    now,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO agent_capabilities (
      agent_id, capability, source, enabled, metadata_json
    ) VALUES (
      ?, ?, 'runtime-manifest-tool-binding', 1, ?
    )
  `).run(AGENT_ID, TOOL_ID, JSON.stringify({
    toolId: TOOL_ID,
    actionClassIds: ["active_host_discovery"],
    runtimeBindingAgentId: AGENT_ID,
    productAgentId: "ReconScout",
  }));
  database.prepare(`
    INSERT INTO mcp_servers (
      id, name, transport, status, capabilities_json, policy_json,
      last_checked_at, created_at, updated_at
    ) VALUES (?, 'Disposable specialist MCP fixture', 'in-memory-test-only',
      'healthy', ?, ?, ?, ?, ?)
  `).run(
    MCP_SERVER_ID,
    JSON.stringify([TOOL_ID]),
    JSON.stringify({
      schemaVersion: "ti-scale.specialist-mcp-execution-policy.v1",
      enabled: true,
      startPermitted: true,
      executionAuthorization: "signed_contract_specialist_action",
      autonomousExecution: true,
      exactInventoryRequired: true,
      directCommanderToolsAllowed: false,
      assignedAgents: [AGENT_ID],
    }),
    now,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO model_configurations (
      id, provider_id, model_id, returned_model_id, reasoning_effort,
      context_policy_json, capabilities_json, context_limit,
      cost_class, latency_class, disclosure_class, enforcement_mode,
      auth_state, health_state, catalog_source, catalog_retrieved_at,
      configuration_source, prompt_template_hash,
      created_at, updated_at, version
    ) VALUES (?, 'fixture-enforcing-provider', 'fixture-reviewed-model',
      NULL, NULL, '{"source":"reviewed-disposable-activation-fixture"}', ?,
      32768, 'low', 'fast', 'public_only', 'enforced',
      'healthy', 'healthy', 'disposable-activation-fixture', ?,
      'manual', NULL, ?, ?, 1)
  `).run(
    MODEL_CONFIGURATION_ID,
    JSON.stringify({
      displayName: "Fixture reviewed model",
      toolCalling: true,
      structuredOutput: true,
      compatibleActionClassIds: ["active_host_discovery"],
      compatibleAgentIds: [AGENT_ID],
      supportedReasoningEfforts: [],
    }),
    now,
    now,
    now,
  );
  if (options.providerAdvisoryPlanning) {
    database.prepare(`
      INSERT INTO model_configurations (
        id, provider_id, model_id, returned_model_id, reasoning_effort,
        context_policy_json, capabilities_json, context_limit,
        cost_class, latency_class, disclosure_class, enforcement_mode,
        auth_state, health_state, catalog_source, catalog_retrieved_at,
        configuration_source, prompt_template_hash,
        created_at, updated_at, version
      ) VALUES (?, 'openrouter', ?, NULL, NULL,
        '{"source":"reviewed-provider-advisory-activation-fixture"}', ?,
        65536, 'standard', 'standard', 'sanitized_internal',
        'advisory_only', 'healthy', 'healthy',
        'disposable-provider-advisory-activation-fixture', ?,
        'manual', NULL, ?, ?, 1)
    `).run(
      ADVISOR_MODEL_CONFIGURATION_ID,
      ADVISOR_MODEL_ID,
      JSON.stringify({
        displayName: "OpenRouter advisory activation fixture",
        toolCalling: false,
        structuredOutput: true,
        compatibleActionClassIds: [],
        compatibleAgentIds: [AGENT_ID],
        supportedReasoningEfforts: [],
      }),
      now,
      now,
      now,
    );
  }
  if (options.seedMission === false) return;
  const actionPolicy = {
    allowedActionClasses: ["active_host_discovery"],
    prohibitedActionClasses: [],
    destructivePolicy: "prohibited",
    boundedDestructiveTargets: [],
    evidenceRequirements: ["asset_discovery_proof"],
    notificationPolicy: "in_app_only",
    reportingFormat: "ti_scale_json",
    dataHandlingPolicy: "local_private",
    retentionPolicy: "operator_managed",
    providerPolicy: "automatic_enforcing_only",
    toolPolicy: "contract_allowlist",
    specialistAgentIds: [AGENT_ID],
    agentModelAssignments: [{
      agentId: AGENT_ID,
      primaryConfigurationId: MODEL_CONFIGURATION_ID,
      fallbackConfigurationId: null,
      source: "operator_override",
    }],
    contextNodeIds: [],
    planningSelection: options.providerAdvisoryPlanning
      ? PROVIDER_ADVISORY_SELECTION
      : {
          route: "local_deterministic",
          plannerId: "ti-scale.local-autonomous-contract-planner.v1",
          enforcementMode: "local_policy",
          disclosureClass: "local_only",
          executionAuthority: "none",
        },
  };
  database.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, ?, '{"conditions":[]}',
      '[]', '[]', 'operator:fixture', ?, ?)
  `).run(
    CONTRACT_ID,
    MISSION_ID,
    CONTRACT_HASH,
    JSON.stringify(actionPolicy),
    JSON.stringify({ toolCalls: 1, retries: 0, replans: 0, concurrency: 1 }),
    now,
    now,
  );
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, contract_version_bound,
      contract_hash_bound, progress, status_reason, budget_json,
      budget_usage_json, started_at, created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'autonomous', 'planning', ?, 1, ?, 0,
      'Build the exact disposable plan', ?, '{}', ?, ?, ?, 1, 'ti_scale')
  `).run(
    RUN_ID,
    MISSION_ID,
    CONTRACT_ID,
    CONTRACT_HASH,
    JSON.stringify({ toolCalls: 1, retries: 0, replans: 0, concurrency: 1 }),
    now,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO agent_model_assignments (
      id, agent_id, mission_id, run_id, step_id,
      primary_configuration_id, fallback_configuration_id,
      inheritance_level, pinned, resolution_reason, resolved_at, created_at
    ) VALUES (?, ?, ?, ?, NULL, ?, NULL, 'run', 1,
      'Pinned from the confirmed disposable activation contract', ?, ?)
  `).run(
    MODEL_ASSIGNMENT_ID,
    AGENT_ID,
    MISSION_ID,
    RUN_ID,
    MODEL_CONFIGURATION_ID,
    now,
    now,
  );
  if (options.providerAdvisoryPlanning) {
    database.prepare(`
      INSERT INTO agent_model_assignments (
        id, agent_id, mission_id, run_id, step_id, assignment_purpose,
        primary_configuration_id, fallback_configuration_id,
        inheritance_level, pinned, resolution_reason, resolved_at, created_at
      ) VALUES (?, ?, ?, ?, NULL, 'planning', ?, NULL, 'run', 1,
        'Pinned from the confirmed provider-advisory planning selection', ?, ?)
    `).run(
      ADVISOR_MODEL_ASSIGNMENT_ID,
      AGENT_ID,
      MISSION_ID,
      RUN_ID,
      ADVISOR_MODEL_CONFIGURATION_ID,
      now,
      now,
    );
  }
}

async function workspaceResolver(): Promise<EngagementWorkspaceResolver> {
  const runtimeRoot = await mkdtemp(join(tmpdir(), "ti-scale-autonomous-activation-"));
  temporaryDirectories.push(runtimeRoot);
  return new EngagementWorkspaceResolver([{
    logicalRoot: "/fixture/engagements",
    runtimeRoot,
  }]);
}

async function fixture(options: {
  database?: SqliteDatabase;
  skipSeed?: boolean;
  databaseToolAllowed?: boolean;
  bindingModelConfigurationHash?: string;
  dispatchDelayMs?: number;
  dispatchError?: Error;
  leaseTtlMs?: number;
  now?: () => Date;
  brainContext?: BrainContextService;
  projectMemoryNodes?: (nodeIds: readonly string[]) => void;
  reportArtifactRoot?: string;
  providerAdvisoryFetch?: NonNullable<
    ConstructorParameters<typeof OpenRouterPlanningClient>[0]["fetch"]
  >;
  crashAfterCommit?: NonNullable<
    Parameters<typeof createProductionAutonomousRuntime>[0]["crashAfterCommit"]
  >;
} = {}) {
  const db = options.database ?? database();
  if (!options.skipSeed) {
    seed(db, {
      databaseToolAllowed: options.databaseToolAllowed,
      providerAdvisoryPlanning:
        options.providerAdvisoryFetch !== undefined,
    });
  }
  const canonicalModelConfigurationHash = modelConfigurationBindingHash(
    new ModelConfigurationRepository(db).getConfiguration(
      MODEL_CONFIGURATION_ID,
    ),
  );
  const selectedModelConfigurationHash =
    options.bindingModelConfigurationHash ??
    canonicalModelConfigurationHash;
  const policy = planningPolicy(selectedModelConfigurationHash);
  const liveProjection = projection(selectedModelConfigurationHash);
  const adapter = new DisposableResultAwareAdapter(
    options.dispatchDelayMs,
    options.dispatchError,
  );
  const binding = {
    serverId: MCP_SERVER_ID,
    toolName: TOOL_ID,
    attestation: capabilityAttestation(),
  } satisfies SpecialistMcpToolBinding;
  const resolver = await workspaceResolver();
  const planner = new LocalAutonomousContractPlanner({
    database: db,
    readRuntimeProjection: () => liveProjection,
    policy,
    now: options.now ?? (() => NOW),
  });
  const providerAdvisory = options.providerAdvisoryFetch
    ? new ProviderAdvisoryRuntimeService({
        database: db,
        providerClient: new OpenRouterPlanningClient({
          credentialPath: "/not-read-by-provider-advisory-integration-test",
          credentialReader: () => "test-openrouter-key",
          requestAuditor: new OpenRouterProviderRequestAuditor({
            database: db,
            maximumReceiptAgeMs: 60_000,
            now: options.now ?? (() => NOW),
          }),
          fetch: options.providerAdvisoryFetch,
          now: options.now ?? (() => NOW),
        }),
      })
    : undefined;
  const providerContextAdapter = providerAdvisory
    ? new ProviderAdvisoryBrainContextAdapter({
        database: db,
        clock: options.now ?? (() => NOW),
      })
    : undefined;
  const providerContext = providerContextAdapter
    ? {
        prepare(input: Parameters<
          ProviderAdvisoryBrainContextAdapter["prepare"]
        >[0]) {
          const prepared = providerContextAdapter.prepare(input);
          return {
            items: prepared.items,
            telemetry: { ...prepared.telemetry },
          };
        },
      }
    : undefined;
  const adapters: ProductionAutonomousRuntimeAdapters = {
    planner,
    ...(providerAdvisory ? { providerAdvisory } : {}),
    ...(providerContext ? { providerContext } : {}),
    outcomeEvaluator: new LocalVerifiedEvidenceOutcomeEvaluator(db),
    execution: {
      adapterContract: adapter.contract,
      create(input) {
        return new SpecialistToolDispatchService({
          database: input.database,
          assertControlPlaneAuthority: input.assertControlPlaneAuthority,
          resolveBinding(serverId, toolName) {
            return serverId === binding.serverId && toolName === binding.toolName
              ? binding
              : undefined;
          },
          adapter,
          workspaceResolver: resolver,
          actorId: "disposable-specialist-dispatch",
          now: () => NOW,
        });
      },
    },
  };
  const readiness = inspectAutonomousRuntimeComposition({
    projection: liveProjection,
    adapters,
    now: options.now?.() ?? NOW,
  });
  const runtime = createProductionAutonomousRuntime({
    database: db,
    adapters,
    readRuntimeProjection: () => liveProjection,
    workerId: "disposable-autonomous-worker",
    leaseTtlMs: options.leaseTtlMs ?? 5_000,
    now: options.now ?? (() => NOW),
    ...(options.brainContext ? { brainContext: options.brainContext } : {}),
    ...(options.projectMemoryNodes
      ? { projectMemoryNodes: options.projectMemoryNodes }
      : {}),
    ...(options.reportArtifactRoot
      ? { reportArtifactRoot: options.reportArtifactRoot }
      : {}),
    ...(options.crashAfterCommit
      ? { crashAfterCommit: options.crashAfterCommit }
      : {}),
  });
  runtimes.push(runtime);
  return {
    db,
    adapter,
    executionBindings: planner.localPlanningBoundary.bindings,
    policy,
    liveProjection,
    providerAdvisory,
    providerContext,
    providerContextAdapter,
    readiness,
    runtime,
  };
}

function recordVerifiedFixtureEvidence(
  database: SqliteDatabase,
  invocation: SpecialistToolInvocation,
): string {
  const evidenceId = "evidence-autonomous-activation-fixture";
  const now = NOW.toISOString();
  const content = JSON.stringify({
    target: invocation.action.target,
    outcome: "reachable_in_disposable_fixture",
    invocationId: invocation.invocationId,
    inputSha256: invocation.inputSha256,
  });
  const contentHash = createHash("sha256").update(content, "utf8").digest("hex");
  const provenance = {
    acquisition: "disposable_in_memory_specialist_fixture",
    invocationId: invocation.invocationId,
    actionId: invocation.action.id,
    actionFingerprint: invocation.action.fingerprint,
    binding: {
      serverId: invocation.binding.serverId,
      toolName: invocation.binding.toolName,
      manifestSha256: invocation.binding.attestation.manifestSha256,
      inputSha256: invocation.inputSha256,
    },
    targetContact: false,
    fixtureOnly: true,
    successCriterionReferences: [{
      schemaVersion: AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
      criterionId: autonomousSuccessCriterionId(CRITERION),
      outcome: "achieved",
    }],
  };
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, extracted_text, created_by, created_at
    ) VALUES (?, ?, ?, ?, ?, 'specialist:disposable-fixture', ?, ?,
      'asset_discovery_proof', ?, ?, 1, 'private', 'verified',
      'Disposable fixture retained one exact attributable host-baseline result',
      ?, 'fixture-local-verifier', ?)
  `).run(
    evidenceId,
    invocation.action.missionId,
    invocation.action.runId,
    invocation.action.stepId,
    invocation.action.id,
    now,
    invocation.action.target,
    contentHash,
    JSON.stringify(provenance),
    content,
    now,
  );
  database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES (
      'evidence-chain-autonomous-activation-acquired', ?, 'acquired',
      'disposable-specialist-transport', ?, ?
    ), (
      'evidence-chain-autonomous-activation-verified', ?, 'verified',
      'fixture-local-verifier', ?, ?
    )
  `).run(
    evidenceId,
    JSON.stringify({ invocationId: invocation.invocationId, contentHash }),
    now,
    evidenceId,
    JSON.stringify({ method: "deterministic_fixture_ground_truth", contentHash }),
    now,
  );
  return evidenceId;
}

function waitingGuidedCount(database: SqliteDatabase): number {
  return Number((database.prepare(`
    SELECT COUNT(*) AS count FROM events
    WHERE run_id = ? AND (
      event_type LIKE 'guided.%'
      OR payload_json LIKE '%waiting_guided_decision%'
      OR summary LIKE '%waiting_guided_decision%'
    )
  `).get(RUN_ID) as { count: number }).count);
}

function providerAdvisorySuccessResponse(
  requestBody: string,
  selectionExtra: Readonly<Record<string, unknown>> = {},
): Response {
  const request = JSON.parse(requestBody) as {
    readonly model: string;
    readonly messages: readonly {
      readonly role: string;
      readonly content: string;
    }[];
  };
  const userMessage = request.messages.find(({ role }) => role === "user");
  if (!userMessage) throw new Error("Provider advisory request has no user brief");
  const brief = JSON.parse(userMessage.content) as {
    readonly catalogHash: string;
    readonly candidates: readonly {
      readonly candidateId: string;
    }[];
  };
  return new Response(JSON.stringify({
    model: request.model,
    choices: [{
      finish_reason: "stop",
      message: {
        content: JSON.stringify({
          schemaVersion: PROVIDER_ADVISORY_SELECTION_SCHEMA_VERSION,
          catalogHash: brief.catalogHash,
          advisoryOnly: true,
          executionRequested: false,
          orderedCandidateIds: [...brief.candidates]
            .reverse()
            .map(({ candidateId }) => candidateId),
          rationale:
            "Use the locally compiled candidate ordering; no executable field was added or changed.",
          ...selectionExtra,
        }),
      },
    }],
    usage: {
      prompt_tokens: 23,
      completion_tokens: 11,
      total_tokens: 34,
      cost: 0.0007,
    },
  }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

describe("disposable Autonomous activation proof", () => {
  test("plans, dispatches one exact reviewed binding, accepts verified evidence, and completes through the local evaluator", async () => {
    const item = await fixture();
    expect(item.readiness).toMatchObject({
      status: "ready",
      readyActionClassIds: ["active_host_discovery"],
      blockers: [],
    });

    await item.runtime.processRunNow(RUN_ID);

    const invocation = item.adapter.invocation;
    expect(invocation).toMatchObject({
      action: {
        missionId: MISSION_ID,
        runId: RUN_ID,
        actionClass: "active_host_discovery",
        target: TARGET,
        contractId: CONTRACT_ID,
      },
      binding: { serverId: MCP_SERVER_ID, toolName: TOOL_ID },
      arguments: { mode: "disposable_fixture_only", target: TARGET },
    });
    expect(item.adapter.dispatchCount).toBe(1);
    expect(invocation?.inputSha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(item.db.prepare(`
      SELECT generation, brain_context_pack_id
      FROM autonomous_activation_receipts
      WHERE run_id = ? ORDER BY generation
    `).all(RUN_ID)).toEqual([
      { generation: 1, brain_context_pack_id: expect.any(String) },
      {
        generation: 2,
        brain_context_pack_id: invocation!.action.contextPackId,
      },
    ]);
    expect(item.db.prepare(`
      SELECT binding_type
      FROM autonomous_activation_bindings
      WHERE receipt_id = (
        SELECT id FROM autonomous_activation_receipts
        WHERE run_id = ? ORDER BY generation DESC LIMIT 1
      )
      ORDER BY sequence
    `).all(RUN_ID)).toEqual([
      { binding_type: "launch" },
      { binding_type: "plan_version" },
      { binding_type: "dispatch" },
    ]);
    expect(item.db.prepare("SELECT status FROM runs WHERE id = ?").get(RUN_ID))
      .toEqual({ status: "running" });

    const evidenceId = recordVerifiedFixtureEvidence(item.db, invocation!);
    const receipt = await item.adapter.emit({
      actionId: invocation!.action.id,
      runId: invocation!.action.runId,
      actionFingerprint: invocation!.action.fingerprint,
      success: true,
      summary: "The exact disposable specialist result was correlated and retained as verified evidence.",
      progress: {
        stepStates: { [invocation!.action.stepId]: "completed" },
        evidenceIds: [evidenceId],
        discoveredEntityIds: ["asset-disposable-authorized-host"],
        successCriteria: { [autonomousSuccessCriterionId(CRITERION)]: 1 },
      },
      usage: { wallClockMs: 1, evidenceBytes: 256 },
    });

    expect(receipt).toMatchObject({
      accepted: true,
      duplicate: false,
      actionId: invocation!.action.id,
      runId: RUN_ID,
      runState: "completed",
      nextAction: null,
    });
    expect(item.db.prepare(`
      SELECT status, result_summary FROM actions WHERE id = ?
    `).get(invocation!.action.id)).toMatchObject({ status: "succeeded" });
    expect(item.db.prepare(`
      SELECT status, output_summary, ended_at FROM tool_calls WHERE action_id = ?
    `).get(invocation!.action.id)).toMatchObject({
      status: "succeeded",
      output_summary: "The exact disposable specialist result was correlated and retained as verified evidence.",
      ended_at: NOW.toISOString(),
    });
    expect(item.db.prepare(`
      SELECT verification_state, action_id, evidence_type FROM evidence WHERE id = ?
    `).get(evidenceId)).toEqual({
      verification_state: "verified",
      action_id: invocation!.action.id,
      evidence_type: "asset_discovery_proof",
    });
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM evidence_chain_events WHERE evidence_id = ?
    `).get(evidenceId)).toEqual({ count: 2 });
    expect(item.db.prepare(`
      SELECT status, status_reason, next_action_summary, current_step_id,
        current_owner_id, lease_owner, lease_expires_at, ended_at
      FROM runs WHERE id = ?
    `).get(RUN_ID)).toMatchObject({
      status: "completed",
      status_reason: expect.stringContaining("Completed autonomously with verified support"),
      next_action_summary: null,
      current_step_id: null,
      current_owner_id: null,
      lease_owner: null,
      lease_expires_at: null,
      ended_at: NOW.toISOString(),
    });
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM run_evaluations WHERE run_id = ?
    `).get(RUN_ID)).toEqual({ count: 1 });
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'run.success_validated'
    `).get(RUN_ID)).toEqual({ count: 1 });
    expect(item.db.prepare("SELECT COUNT(*) AS count FROM provider_turns WHERE run_id = ?").get(RUN_ID))
      .toEqual({ count: 0 });
    expect(waitingGuidedCount(item.db)).toBe(0);
  });

  test("creates a reviewed mission through intake and closes the production runtime through reports, Brain, and a disposable Vault", async () => {
    const db = database();
    seed(db, { seedMission: false });
    const intakeReadinessExpiresAt = new Date(
      NOW.getTime() + 5 * 60_000,
    ).toISOString();
    db.prepare(`
      UPDATE agents
      SET configuration_json = ?, updated_at = ?
      WHERE id = ?
    `).run(
      JSON.stringify({
        schemaVersion: "ti-scale.autonomous-specialist-runtime.v1",
        executionMode: "specialist_runtime",
        adapterId: ADAPTER_ID,
        toolSelection: "exact_persisted_binding_only",
        resultDelivery: "bound_execution_result_sink",
        shellInterpolation: false,
        publicProviderToolExecution: false,
        userFacing: true,
        productAgent: true,
        runtimeBindingAgentIds: [AGENT_ID],
      }),
      NOW.toISOString(),
      AGENT_ID,
    );
    db.prepare(`
      INSERT INTO agent_capabilities (
        agent_id, capability, source, enabled, metadata_json
      ) VALUES (?, ?, 'live-route-attestation', 1, ?)
    `).run(
      AGENT_ID,
      TOOL_ID,
      JSON.stringify({
        attestedAt: NOW.toISOString(),
        validUntil: intakeReadinessExpiresAt,
        providerIds: ["fixture-enforcing-provider"],
        toolId: TOOL_ID,
        executionJourneys: ["autonomous"],
        actionClassId: "active_host_discovery",
        runtimeBindingAgentId: AGENT_ID,
      }),
    );
    db.prepare(`
      INSERT INTO health_snapshots (
        id, component_type, component_id, status, metrics_json, message,
        captured_at
      ) VALUES (
        'health-disposable-intake-provider',
        'provider',
        'fixture-enforcing-provider',
        'healthy',
        ?,
        'Deterministic fixture provider boundary is locally attested',
        ?
      )
    `).run(
      JSON.stringify({
        authenticated: true,
        callable: true,
        attestedAt: NOW.toISOString(),
        expiresAt: intakeReadinessExpiresAt,
        enforcesAutonomousBoundary: true,
        reportsExactTokenUsage: true,
        reportsExactCostUsage: true,
      }),
      NOW.toISOString(),
    );
    const root = await mkdtemp(join(
      tmpdir(),
      "ti-scale-autonomous-intake-completion-",
    ));
    temporaryDirectories.push(root);
    const reportArtifactRoot = join(root, "artifacts", "reports");
    const clock = () => NOW;

    const memory = new MemoryRepository(db, { clock });
    const secondBrain = new SecondBrainService(memory);
    const vaultPaths = new VaultPathPolicy(join(root, "allowed-vaults"));
    const brain = new BrainContextService({
      database: db,
      secondBrain,
      resolveExistingVaultPath: (vaultPath) =>
        vaultPaths.resolveExistingVault(vaultPath),
      clock,
    });
    const vault = new ObsidianVaultBridge(db, memory, vaultPaths, { clock });
    const connection = vault.connect({
      id: "vault-disposable-intake-completion",
      vaultPath: "Disposable-Autonomous-Brain",
      displayName: "Disposable Autonomous completion Vault",
      syncScope: {
        nodeTypes: ["attack_procedure", "outcome"],
        lifecycleStatuses: ["verified"],
        scopeKinds: ["global"],
        sensitivities: ["internal"],
      },
      permissionGranted: true,
    });
    vault.refreshConnectionHealthProof(
      connection.id,
      "system:disposable-intake-completion",
    );
    const procedureNode = memory.createNode({
      id: `mem_${createHash("sha256")
        .update("disposable-intake-completion-procedure", "utf8")
        .digest("hex")}`,
      nodeType: "attack_procedure",
      title: "Attribute one deterministic local specialist result",
      summary:
        "Use one exact reviewed in-memory specialist binding and require custody-complete verified evidence before completion.",
      body:
        "This fixture procedure cannot open a socket, start a process, contact a provider, or dispatch an external MCP tool.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "confirmed",
      provenance: {
        method: "derived",
        explanation:
          "Operator-reviewed disposable integration procedure used only by the bounded local proof.",
        sources: [{
          sourceType: "review_receipt",
          sourceId: "review-disposable-intake-completion",
          acquiredAt: NOW.toISOString(),
        }],
      },
      authorType: "operator",
      authorId: "operator:disposable-intake-completion",
    });
    expect(vault.exportNode(connection.id, procedureNode.id).status).toBe(
      "synced",
    );
    const projector = new ConnectedVaultMemoryProjector(db, vault, { clock });

    const baseProjection = projection(MODEL_CONFIGURATION_HASH);
    const modelRepository = new ModelConfigurationRepository(db, clock);
    const modelConfigurations = new ModelConfigurationService(
      modelRepository,
      {
        readRuntimeManifests: () => baseProjection.capabilityManifests!,
        clock,
      },
    );
    const selectedConfiguration = modelConfigurations.catalog().items.find(
      (candidate) =>
        candidate.selectable
        && candidate.providerId === "fixture-enforcing-provider"
        && candidate.modelId === "fixture-reviewed-model"
        && candidate.compatibleAgentIds.includes(AGENT_ID),
    );
    if (!selectedConfiguration) {
      throw new Error(
        "Disposable intake proof could not resolve its exact local model configuration",
      );
    }
    modelRepository.materializeCatalogConfiguration(selectedConfiguration);
    const selectedConfigurationHash = modelConfigurationBindingHash(
      modelRepository.getConfiguration(
        selectedConfiguration.configurationId,
      ),
    );

    const item = await fixture({
      database: db,
      skipSeed: true,
      bindingModelConfigurationHash: selectedConfigurationHash,
      brainContext: brain,
      projectMemoryNodes: (nodeIds) => {
        projector.project(nodeIds);
      },
      reportArtifactRoot,
    });
    const serviceProjection: RuntimeProjectionInput = {
      ...item.liveProjection,
      readiness: {
        ...item.liveProjection.readiness,
        autonomousRuntime: item.readiness,
      },
    };
    const actionPolicyOverrides = Object.fromEntries(
      ACTION_CLASS_IDS.map((actionClassId) => [
        actionClassId,
        actionClassId === "active_host_discovery"
          ? "pre_authorized"
          : "prohibited",
      ]),
    ) as Record<
      (typeof ACTION_CLASS_IDS)[number],
      "pre_authorized" | "prohibited"
    >;
    const intake = new MissionIntakeService({
      readRuntimeManifests: () => serviceProjection.capabilityManifests!,
      modelConfigurations,
      clock,
    });
    const resolved = intake.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: INTAKE_TARGET, type: "host" }],
      templateId: "safe_recon",
      title: "Disposable intake-to-closeout proof",
      objective:
        "Establish one attributable baseline for the exact disposable fixture without contacting it.",
      successCriteria: [CRITERION],
      deliverableIds: [
        "machine_readable_export",
        "pdf_html_markdown_report",
      ],
      evidenceTypeIds: ["asset_discovery_proof"],
      optionalSafeStopIds: [],
      actionPolicyOverrides,
      specialistAgentIds: [AGENT_ID],
      agentModelAssignments: [{
        agentId: AGENT_ID,
        primaryConfigurationId: selectedConfiguration.configurationId,
        fallbackConfigurationId: null,
        source: "operator_override",
      }],
      memoryScopes: ["verified_attack_knowledge"],
      contextNodeIds: [procedureNode.id],
      environmentClassification: "local_disposable_lab",
    });
    expect(resolved.limitations).toEqual([]);
    expect(resolved.request.journey).toBe("autonomous");
    if (resolved.request.journey !== "autonomous") {
      throw new Error("Disposable intake unexpectedly changed journey");
    }
    expect(resolved.request.contract.allowedActionClasses).toEqual([
      "active_host_discovery",
    ]);

    const memoryGraph = new CanonicalMissionMemoryGraph(db, { clock });
    const missions = new MissionService(
      new MissionRepository(db, clock),
      new OverviewRepository(db),
      new ReadinessService(
        createRuntimeReadinessProviders(() => serviceProjection.readiness),
      ),
      brain,
      () => serviceProjection.capabilityManifests!,
      memoryGraph,
      (nodeIds) => {
        projector.project(nodeIds);
      },
      modelConfigurations,
    );
    const preflight = await missions.preflightAutonomous(resolved.request);
    expect(preflight.readiness).toMatchObject({
      status: "ready",
      score: 100,
    });
    const created = await missions.create(
      {
        ...resolved.request,
        contractReview: preflight.contract,
      },
      "disposable-intake-completion-v1",
      "operator:disposable-intake-completion",
    );
    expect(created.run.status).toBe("planning");
    expect(created.run.journey).toBe("autonomous");
    expect(db.prepare(`
      SELECT COUNT(*) AS count FROM agent_model_assignments
      WHERE run_id = ? AND agent_id = ? AND pinned = 1
    `).get(created.run.id, AGENT_ID)).toEqual({ count: 1 });

    await item.runtime.processRunNow(created.run.id);
    const invocation = item.adapter.invocation;
    const createdRunBinding = db.prepare(
      "SELECT contract_id FROM runs WHERE id = ?",
    ).get(created.run.id) as { contract_id: string };
    expect(invocation).toMatchObject({
      action: {
        missionId: created.mission.id,
        runId: created.run.id,
        actionClass: "active_host_discovery",
        target: INTAKE_TARGET,
        contractId: createdRunBinding.contract_id,
      },
      binding: { serverId: MCP_SERVER_ID, toolName: TOOL_ID },
      arguments: {
        mode: "disposable_fixture_only",
        target: INTAKE_TARGET,
      },
    });
    expect(item.adapter.dispatchCount).toBe(1);

    const evidenceId = recordVerifiedFixtureEvidence(db, invocation!);
    const result = await item.adapter.emit({
      actionId: invocation!.action.id,
      runId: created.run.id,
      actionFingerprint: invocation!.action.fingerprint,
      success: true,
      summary:
        "The deterministic in-memory specialist result was correlated to verified evidence.",
      progress: {
        stepStates: { [invocation!.action.stepId]: "completed" },
        evidenceIds: [evidenceId],
        discoveredEntityIds: ["asset-disposable-intake-completion"],
        successCriteria: {
          [autonomousSuccessCriterionId(CRITERION)]: 1,
        },
      },
      usage: { wallClockMs: 1, evidenceBytes: 256 },
    });
    expect(result).toMatchObject({
      accepted: true,
      duplicate: false,
      runId: created.run.id,
      runState: "completed",
      nextAction: null,
    });
    await item.runtime.replayContinuations(
      created.run.id,
      ["memory_projection_pending"],
    );
    expect(db.prepare(`
      SELECT action.status AS action_status,
        action.ended_at AS action_ended_at,
        assignment.status AS assignment_status,
        assignment.ended_at AS assignment_ended_at,
        assignment.lease_owner AS assignment_lease_owner,
        assignment.lease_acquired_at AS assignment_lease_acquired_at,
        assignment.last_heartbeat_at AS assignment_last_heartbeat_at,
        assignment.lease_expires_at AS assignment_lease_expires_at,
        tool.status AS tool_status,
        tool.ended_at AS tool_ended_at
      FROM actions action
      JOIN assignments assignment ON assignment.id = action.assignment_id
      JOIN tool_calls tool ON tool.action_id = action.id
      WHERE action.id = ?
    `).get(invocation!.action.id)).toEqual({
      action_status: "succeeded",
      action_ended_at: NOW.toISOString(),
      assignment_status: "completed",
      assignment_ended_at: NOW.toISOString(),
      assignment_lease_owner: null,
      assignment_lease_acquired_at: null,
      assignment_last_heartbeat_at: null,
      assignment_lease_expires_at: null,
      tool_status: "succeeded",
      tool_ended_at: NOW.toISOString(),
    });
    expect(db.prepare(`
      SELECT COUNT(*) AS count
      FROM actions action
      LEFT JOIN assignments assignment ON assignment.id = action.assignment_id
      LEFT JOIN tool_calls tool ON tool.action_id = action.id
      WHERE action.run_id = ? AND (
        action.status IN ('queued', 'running')
        OR assignment.status IN ('queued', 'active', 'blocked')
        OR assignment.lease_owner IS NOT NULL
        OR assignment.lease_acquired_at IS NOT NULL
        OR assignment.last_heartbeat_at IS NOT NULL
        OR assignment.lease_expires_at IS NOT NULL
        OR tool.status IN ('queued', 'running')
      )
    `).get(created.run.id)).toEqual({ count: 0 });

    const reportRows = db.prepare(`
      SELECT id, artifact_type, content_hash, byte_size
      FROM artifacts
      WHERE run_id = ?
        AND artifact_type IN ('mission_report_markdown', 'mission_report_json')
      ORDER BY artifact_type
    `).all(created.run.id) as Array<{
      readonly id: string;
      readonly artifact_type: string;
      readonly content_hash: string;
      readonly byte_size: number;
    }>;
    expect(reportRows).toHaveLength(2);
    const reports = new CanonicalMissionReportService(db, {
      artifactRoot: reportArtifactRoot,
      clock,
    });
    let canonicalJsonReport: Readonly<Record<string, unknown>> | undefined;
    for (const report of reportRows) {
      const downloaded = reports.download(report.id, {
        maximumSensitivity: "restricted",
        allEngagements: true,
        allowGlobalKnowledge: true,
        allowUnscopedSystemData: true,
      });
      expect(downloaded.contentHash).toBe(report.content_hash);
      expect(downloaded.byteSize).toBe(report.byte_size);
      expect(downloaded.body.length).toBeGreaterThan(0);
      if (report.artifact_type === "mission_report_json") {
        canonicalJsonReport = JSON.parse(
          downloaded.body.toString("utf8"),
        ) as Readonly<Record<string, unknown>>;
      }
    }
    const storedEvaluation = db.prepare(`
      SELECT id, scores_json, metrics_json, retrospective, evidence_coverage,
        created_by, created_at
      FROM run_evaluations WHERE run_id = ?
    `).get(created.run.id) as {
      readonly id: string;
      readonly scores_json: string;
      readonly metrics_json: string;
      readonly retrospective: string;
      readonly evidence_coverage: number;
      readonly created_by: string;
      readonly created_at: string;
    };
    expect(canonicalJsonReport?.evaluation).toEqual({
      id: storedEvaluation.id,
      scores: JSON.parse(storedEvaluation.scores_json),
      metrics: JSON.parse(storedEvaluation.metrics_json),
      retrospective: storedEvaluation.retrospective,
      evidenceCoverage: storedEvaluation.evidence_coverage,
      createdBy: storedEvaluation.created_by,
      createdAt: storedEvaluation.created_at,
    });
    expect(canonicalJsonReport?.verifiedEvidence).toMatchObject({
      classification: "canonical_verified_evidence_only",
      records: [{ id: evidenceId }],
    });

    const evidenceHash = (db.prepare(
      "SELECT content_hash FROM evidence WHERE id = ?",
    ).get(evidenceId) as { readonly content_hash: string }).content_hash;
    const outcomeNode = memory.createNode({
      id: `mem_${createHash("sha256")
        .update("disposable-intake-completion-outcome", "utf8")
        .digest("hex")}`,
      nodeType: "outcome",
      title: "Deterministic local specialist proof completed",
      summary:
        "The exact in-memory binding completed with custody-complete verified evidence and canonical reports.",
      body:
        "This successful outcome applies only to the disposable fixture and grants no authority for a real target.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "confirmed",
      provenance: {
        method: "evidence",
        explanation:
          "Derived from the completed disposable run and its immutable verified evidence.",
        sources: [{
          sourceType: "evidence",
          sourceId: evidenceId,
          sourceHash: evidenceHash,
          acquiredAt: NOW.toISOString(),
        }],
      },
      authorType: "operator",
      authorId: "operator:disposable-intake-completion",
    });
    memory.createEdge({
      id: "edge-disposable-intake-completion-outcome",
      sourceNodeId: procedureNode.id,
      targetNodeId: outcomeNode.id,
      edgeType: "produces_outcome",
      title: "Procedure produced verified outcome",
      summary:
        "The reviewed disposable procedure produced one custody-complete verified result.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "verified",
      provenance: {
        method: "evidence",
        explanation: "Bound to the exact verified specialist result.",
        sources: [{
          sourceType: "evidence",
          sourceId: evidenceId,
          sourceHash: evidenceHash,
          acquiredAt: NOW.toISOString(),
        }],
      },
      explanation:
        "The exact reviewed in-memory procedure produced this evidence-backed result.",
      authorType: "operator",
      authorId: "operator:disposable-intake-completion",
    });
    for (const nodeId of [procedureNode.id, outcomeNode.id]) {
      expect(vault.exportNode(connection.id, nodeId).status).toBe("synced");
    }
    const vaultVerification = vault.verifyConnection(connection.id);
    expect(vaultVerification.healthy).toBeTrue();
    expect(vaultVerification.counts.synced).toBe(2);
    const reconciliation = new VaultProjectionReconciliationService(
      db,
      vault,
      vaultPaths,
      { clock },
    ).reconcile(connection.id);
    expect(reconciliation).toMatchObject({
      status: "complete",
      unresolvedWikilinkCount: 0,
      issueCount: 0,
    });
    expect(reconciliation.wikilinkCount).toBeGreaterThanOrEqual(1);

    const contextCoverage = brain.coverage({
      missionId: created.mission.id,
      runId: created.run.id,
    });
    expect(contextCoverage.coveredHooks).toEqual(
      expect.arrayContaining([
        "intake",
        "planning",
        "tool_selection",
        "evaluation",
        "lesson_proposal",
        "reporting",
        "closeout",
      ]),
    );
    expect(db.prepare(`
      SELECT COUNT(*) AS count FROM provider_turns WHERE run_id = ?
    `).get(created.run.id)).toEqual({ count: 0 });
    expect(db.prepare(`
      SELECT status, progress FROM runs WHERE id = ?
    `).get(created.run.id)).toEqual({ status: "completed", progress: 1 });
    expect(db.prepare(`
      SELECT status FROM missions WHERE id = ?
    `).get(created.mission.id)).toEqual({ status: "completed" });
    expect(db.prepare(`
      SELECT COUNT(*) AS count FROM run_evaluations WHERE run_id = ?
    `).get(created.run.id)).toEqual({ count: 1 });

    const noteRows = db.prepare(`
      SELECT connection.vault_path, sync.relative_path
      FROM vault_sync_state sync
      JOIN vault_connections connection ON connection.id = sync.connection_id
      WHERE sync.connection_id = ? AND sync.status = 'synced'
      ORDER BY sync.relative_path
    `).all(connection.id) as Array<{
      readonly vault_path: string;
      readonly relative_path: string;
    }>;
    expect(noteRows).toHaveLength(2);
    const notes = await Promise.all(
      noteRows.map((row) =>
        readFile(join(row.vault_path, row.relative_path), "utf8")),
    );
    expect(notes.every((note) => note.startsWith("---\n"))).toBeTrue();
    expect(notes.some((note) => note.includes("[["))).toBeTrue();
  });

  test("heartbeats the run, control plane, and exact assignment before and throughout dispatch longer than the lease TTL", async () => {
    const realStartedAt = Date.now();
    const now = () => new Date(NOW.getTime() + (Date.now() - realStartedAt));
    const item = await fixture({
      dispatchDelayMs: 1_600,
      leaseTtlMs: 1_000,
      now,
    });

    const processing = item.runtime.processRunNow(RUN_ID);
    const invocationDeadline = Date.now() + 2_000;
    while (!item.adapter.invocation && Date.now() < invocationDeadline) {
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
    }
    const invocation = item.adapter.invocation;
    expect(invocation).toBeDefined();

    const dispatchStartLease = item.db.prepare(`
      SELECT r.last_heartbeat_at AS run_heartbeat_at,
        r.lease_expires_at AS run_expires_at,
        a.last_heartbeat_at AS assignment_heartbeat_at,
        a.lease_expires_at AS assignment_expires_at,
        c.heartbeat_at AS control_heartbeat_at,
        c.expires_at AS control_expires_at
      FROM runs r
      JOIN actions x ON x.run_id = r.id
      JOIN assignments a ON a.id = x.assignment_id
      JOIN control_plane_leases c ON c.run_id = r.id AND c.released_at IS NULL
      WHERE r.id = ? AND x.id = ?
    `).get(RUN_ID, invocation!.action.id) as {
      run_heartbeat_at: string;
      run_expires_at: string;
      assignment_heartbeat_at: string;
      assignment_expires_at: string;
      control_heartbeat_at: string;
      control_expires_at: string;
    };
    expect(dispatchStartLease.run_expires_at).toBe(dispatchStartLease.assignment_expires_at);

    await processing;

    const renewed = item.db.prepare(`
      SELECT r.lease_owner AS run_owner,
        r.last_heartbeat_at AS run_heartbeat_at,
        r.lease_expires_at AS run_expires_at,
        a.lease_owner AS assignment_owner,
        a.last_heartbeat_at AS assignment_heartbeat_at,
        a.lease_expires_at AS assignment_expires_at,
        c.lease_owner AS control_owner,
        c.heartbeat_at AS control_heartbeat_at,
        c.expires_at AS control_expires_at
      FROM runs r
      JOIN actions x ON x.run_id = r.id
      JOIN assignments a ON a.id = x.assignment_id
      JOIN control_plane_leases c ON c.run_id = r.id AND c.released_at IS NULL
      WHERE r.id = ? AND x.id = ?
    `).get(RUN_ID, invocation!.action.id) as {
      run_owner: string;
      run_heartbeat_at: string;
      run_expires_at: string;
      assignment_owner: string;
      assignment_heartbeat_at: string;
      assignment_expires_at: string;
      control_owner: string;
      control_heartbeat_at: string;
      control_expires_at: string;
    };
    expect(renewed.run_owner).toBe("disposable-autonomous-worker");
    expect(renewed.assignment_owner).toBe(renewed.run_owner);
    expect(renewed.control_owner).toBe(renewed.run_owner);
    expect(Date.parse(renewed.run_heartbeat_at)).toBeGreaterThan(
      Date.parse(dispatchStartLease.run_heartbeat_at),
    );
    expect(Date.parse(renewed.assignment_heartbeat_at)).toBeGreaterThan(
      Date.parse(dispatchStartLease.assignment_heartbeat_at),
    );
    expect(Date.parse(renewed.control_heartbeat_at)).toBeGreaterThan(
      Date.parse(dispatchStartLease.control_heartbeat_at),
    );
    expect(renewed.run_expires_at).toBe(renewed.assignment_expires_at);
    expect(Date.parse(renewed.run_expires_at)).toBeGreaterThan(now().getTime());
    expect(Date.parse(renewed.control_expires_at)).toBeGreaterThan(now().getTime());

    const evidenceId = recordVerifiedFixtureEvidence(item.db, invocation!);
    const receipt = await item.adapter.emit({
      actionId: invocation!.action.id,
      runId: invocation!.action.runId,
      actionFingerprint: invocation!.action.fingerprint,
      success: true,
      summary: "The delayed disposable execution retained its owner fences and completed with verified evidence.",
      progress: {
        stepStates: { [invocation!.action.stepId]: "completed" },
        evidenceIds: [evidenceId],
        discoveredEntityIds: ["asset-disposable-authorized-host"],
        successCriteria: { [autonomousSuccessCriterionId(CRITERION)]: 1 },
      },
      usage: { wallClockMs: 1_600, evidenceBytes: 256 },
    });
    expect(receipt).toMatchObject({ accepted: true, runState: "completed" });
  });

  test("rejects a swapped MCP tool route on restart before any specialist contact", async () => {
    const item = await fixture({
      crashAfterCommit(point) {
        if (point === "action_reserved_before_dispatch") {
          throw new Error("fixture crash before execution contact");
        }
      },
    });
    await expect(item.runtime.processRunNow(RUN_ID)).rejects.toThrow(
      "Injected process crash",
    );
    expect(item.adapter.dispatchCount).toBe(0);
    const action = item.db.prepare(`
      SELECT id, normalized_arguments_json FROM actions
      WHERE run_id = ? ORDER BY created_at, id LIMIT 1
    `).get(RUN_ID) as {
      id: string;
      normalized_arguments_json: string;
    };
    const stored = JSON.parse(action.normalized_arguments_json) as {
      input: Record<string, unknown>;
      orchestration: Record<string, unknown>;
    };
    stored.input.toolName = "tool-swapped-after-activation";
    item.db.prepare(`
      UPDATE actions SET normalized_arguments_json = ? WHERE id = ?
    `).run(JSON.stringify(stored), action.id);
    item.db.prepare(`
      UPDATE runs SET lease_expires_at = '2026-07-19T10:29:59.000Z'
      WHERE id = ?
    `).run(RUN_ID);

    const recovered = await item.runtime.recover();

    expect(recovered).toBe(1);
    expect(item.adapter.dispatchCount).toBe(0);
    expect(item.db.prepare(`
      SELECT status FROM runs WHERE id = ?
    `).get(RUN_ID)).toEqual({ status: "blocked" });
    expect(item.db.prepare(`
      SELECT binding_type FROM autonomous_activation_bindings
      WHERE receipt_id = (
        SELECT id FROM autonomous_activation_receipts
        WHERE run_id = ? ORDER BY generation DESC LIMIT 1
      )
      ORDER BY sequence
    `).all(RUN_ID)).toEqual([
      { binding_type: "launch" },
      { binding_type: "planning" },
      { binding_type: "plan_version" },
      { binding_type: "restart_recovery" },
    ]);
  });

  test("rotates the immutable receipt generation when replanning retrieves a new Context Pack", async () => {
    const item = await fixture({
      crashAfterCommit(point) {
        if (point === "action_reserved_before_dispatch") {
          throw new Error("fixture crash after initial planning");
        }
      },
    });
    await expect(item.runtime.processRunNow(RUN_ID)).rejects.toThrow(
      "Injected process crash",
    );
    const first = item.db.prepare(`
      SELECT id, generation, brain_context_pack_id
      FROM autonomous_activation_receipts
      WHERE run_id = ? ORDER BY generation DESC LIMIT 1
    `).get(RUN_ID) as {
      id: string;
      generation: number;
      brain_context_pack_id: string;
    };
    const service = new AutonomousActivationRuntimeService(
      item.db,
      () => item.liveProjection,
      () => NOW,
      item.executionBindings,
    );
    expect(service.ensureIssued({
      missionId: MISSION_ID,
      runId: RUN_ID,
      brainContextPackId: first.brain_context_pack_id,
      issuedBy: "replan-fixture",
    }).receiptId).toBe(first.id);
    item.db.prepare(`
      INSERT INTO memory_context_packs (
        id, mission_id, run_id, journey, purpose, query_redacted,
        scope_policy_json, context_budget, retrieval_metrics_json,
        created_by, created_at
      ) VALUES (
        'context-pack-replan-fixture', ?, ?, 'autonomous', 'replan',
        'Bounded replan context', '{}', 2048, '{}', 'runtime', ?
      )
    `).run(MISSION_ID, RUN_ID, NOW.toISOString());

    const rotated = service.ensureIssued({
      missionId: MISSION_ID,
      runId: RUN_ID,
      brainContextPackId: "context-pack-replan-fixture",
      issuedBy: "replan-fixture",
    });

    expect(rotated.receiptId).not.toBe(first.id);
    expect(item.db.prepare(`
      SELECT generation, brain_context_pack_id
      FROM autonomous_activation_receipts
      WHERE run_id = ? ORDER BY generation
    `).all(RUN_ID)).toEqual([
      {
        generation: 1,
        brain_context_pack_id: first.brain_context_pack_id,
      },
      {
        generation: 2,
        brain_context_pack_id: "context-pack-replan-fixture",
      },
    ]);
  });

  test("keeps a local receipt through a same-capability observation refresh, then renews immutably for the next step after expiry and restart", () => {
    const db = database();
    seed(db);
    const configurationHash = modelConfigurationBindingHash(
      new ModelConfigurationRepository(db).getConfiguration(
        MODEL_CONFIGURATION_ID,
      ),
    );
    const lifecycle = seedLocalActivationLifecycle(db, configurationHash);
    let current = NOW;
    let liveProjection = localActivationProjection(
      configurationHash,
      localToolAttestation(
        NOW.toISOString(),
        "2026-07-19T10:31:00.000Z",
      ),
    );
    const binding = localExecutionBinding(configurationHash);
    const service = new AutonomousActivationRuntimeService(
      db,
      () => liveProjection,
      () => current,
      [binding],
    );
    const first = service.ensureIssued({
      missionId: MISSION_ID,
      runId: RUN_ID,
      brainContextPackId: lifecycle.contextPackId,
      issuedBy: "fixture-local-runtime",
    });
    service.verifyAndBind({
      runId: RUN_ID,
      bindingType: "plan_version",
      subjectId: lifecycle.planId,
      subjectDigest: lifecycle.planHash,
      planId: lifecycle.planId,
      contextPackId: lifecycle.contextPackId,
      boundBy: "fixture-local-runtime",
    });

    current = new Date("2026-07-19T10:30:30.000Z");
    liveProjection = localActivationProjection(
      configurationHash,
      localToolAttestation(
        "2026-07-19T10:30:30.000Z",
        "2026-07-19T10:31:30.000Z",
      ),
    );
    expect(service.verifyCurrent({ runId: RUN_ID }).receiptId).toBe(
      first.receiptId,
    );
    service.verifyAndBind({
      runId: RUN_ID,
      bindingType: "dispatch",
      subjectId: lifecycle.actionRows[0].id,
      subjectDigest: lifecycle.actionRows[0].fingerprint,
      planId: lifecycle.planId,
      stepId: lifecycle.actionRows[0].stepId,
      actionId: lifecycle.actionRows[0].id,
      contextPackId: lifecycle.contextPackId,
      boundBy: "fixture-local-runtime",
    });

    current = new Date("2026-07-19T10:31:31.000Z");
    const staleRestart = new AutonomousActivationRuntimeService(
      db,
      () => liveProjection,
      () => current,
      [binding],
    );
    let staleProofError: unknown;
    try {
      staleRestart.verifyAndBind({
        runId: RUN_ID,
        bindingType: "dispatch",
        subjectId: lifecycle.actionRows[1].id,
        subjectDigest: lifecycle.actionRows[1].fingerprint,
        planId: lifecycle.planId,
        stepId: lifecycle.actionRows[1].stepId,
        actionId: lifecycle.actionRows[1].id,
        contextPackId: lifecycle.contextPackId,
        boundBy: "fixture-stale-local-runtime",
      });
    } catch (error) {
      staleProofError = error;
    }
    expect(staleProofError).toMatchObject({
      code: "activation_local_proof_invalid",
    });
    expect(db.prepare(`
      SELECT COUNT(*) AS count FROM autonomous_activation_receipts
      WHERE run_id = ?
    `).get(RUN_ID)).toEqual({ count: 1 });

    liveProjection = localActivationProjection(
      configurationHash,
      localToolAttestation(
        "2026-07-19T10:31:31.000Z",
        "2026-07-19T10:32:31.000Z",
      ),
    );
    const restarted = new AutonomousActivationRuntimeService(
      db,
      () => liveProjection,
      () => current,
      [binding],
    );
    const second = restarted.verifyAndBind({
      runId: RUN_ID,
      bindingType: "dispatch",
      subjectId: lifecycle.actionRows[1].id,
      subjectDigest: lifecycle.actionRows[1].fingerprint,
      planId: lifecycle.planId,
      stepId: lifecycle.actionRows[1].stepId,
      actionId: lifecycle.actionRows[1].id,
      contextPackId: lifecycle.contextPackId,
      boundBy: "fixture-restarted-local-runtime",
    });
    expect(second.receiptId).not.toBe(first.receiptId);
    expect(db.prepare(`
      SELECT generation, runtime_generation_hash, tool_activation_receipt_hash
      FROM autonomous_activation_receipts receipt
      JOIN autonomous_activation_receipt_items item
        ON item.receipt_id = receipt.id
      WHERE receipt.run_id = ?
      ORDER BY generation
    `).all(RUN_ID)).toEqual([
      {
        generation: 1,
        runtime_generation_hash: first.runtimeGenerationHash,
        tool_activation_receipt_hash: expect.any(String),
      },
      {
        generation: 2,
        runtime_generation_hash: first.runtimeGenerationHash,
        tool_activation_receipt_hash: expect.any(String),
      },
    ]);
    const proofHashes = db.prepare(`
      SELECT item.tool_activation_receipt_hash AS hash
      FROM autonomous_activation_receipts receipt
      JOIN autonomous_activation_receipt_items item
        ON item.receipt_id = receipt.id
      WHERE receipt.run_id = ? ORDER BY receipt.generation
    `).all(RUN_ID) as Array<{ hash: string }>;
    expect(proofHashes[1]!.hash).not.toBe(proofHashes[0]!.hash);
    expect(db.prepare(`
      SELECT receipt.generation, binding.binding_type,
        binding.subject_id
      FROM autonomous_activation_receipts receipt
      JOIN autonomous_activation_bindings binding
        ON binding.receipt_id = receipt.id
      WHERE receipt.run_id = ?
      ORDER BY receipt.generation, binding.sequence
    `).all(RUN_ID)).toEqual([
      { generation: 1, binding_type: "launch", subject_id: RUN_ID },
      {
        generation: 1,
        binding_type: "plan_version",
        subject_id: lifecycle.planId,
      },
      {
        generation: 1,
        binding_type: "dispatch",
        subject_id: lifecycle.actionRows[0].id,
      },
      { generation: 2, binding_type: "launch", subject_id: RUN_ID },
      {
        generation: 2,
        binding_type: "plan_version",
        subject_id: lifecycle.planId,
      },
      {
        generation: 2,
        binding_type: "dispatch",
        subject_id: lifecycle.actionRows[1].id,
      },
    ]);
    expect(restarted.verifyAndBind({
      runId: RUN_ID,
      bindingType: "dispatch",
      subjectId: lifecycle.actionRows[1].id,
      subjectDigest: lifecycle.actionRows[1].fingerprint,
      planId: lifecycle.planId,
      stepId: lifecycle.actionRows[1].stepId,
      actionId: lifecycle.actionRows[1].id,
      contextPackId: lifecycle.contextPackId,
      boundBy: "fixture-restarted-local-runtime",
    }).receiptId).toBe(second.receiptId);
    expect(db.prepare(`
      SELECT COUNT(*) AS count FROM autonomous_activation_bindings
      WHERE receipt_id = ? AND binding_type = 'dispatch'
        AND subject_id = ?
    `).get(second.receiptId, lifecycle.actionRows[1].id)).toEqual({
      count: 1,
    });
  });

  test("uses the latest heartbeat token to close a dispatch failure after the original lease TTL", async () => {
    const realStartedAt = Date.now();
    const now = () => new Date(NOW.getTime() + (Date.now() - realStartedAt));
    const item = await fixture({
      dispatchDelayMs: 1_300,
      dispatchError: new Error("delayed disposable adapter rejection"),
      leaseTtlMs: 1_000,
      now,
    });

    await item.runtime.processRunNow(RUN_ID);
    const actionId = item.adapter.invocation?.action.id;
    expect(actionId).toBeDefined();
    expect(item.db.prepare(`
      SELECT status, error_category, ended_at FROM actions WHERE id = ?
    `).get(actionId!)).toMatchObject({
      status: "failed",
      ended_at: expect.any(String),
    });
    expect(item.db.prepare(`
      SELECT status, lease_owner, last_heartbeat_at, lease_expires_at
      FROM assignments WHERE id = (
        SELECT assignment_id FROM actions WHERE id = ?
      )
    `).get(actionId!)).toEqual({
      status: "failed",
      lease_owner: null,
      last_heartbeat_at: null,
      lease_expires_at: null,
    });
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM actions
      WHERE run_id = ? AND status IN ('queued', 'running')
    `).get(RUN_ID)).toEqual({ count: 0 });
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM assignments
      WHERE run_id = ? AND (status IN ('queued', 'active') OR lease_owner IS NOT NULL)
    `).get(RUN_ID)).toEqual({ count: 0 });
    expect(item.db.prepare(`
      SELECT status, lease_owner, lease_expires_at FROM runs WHERE id = ?
    `).get(RUN_ID)).toMatchObject({
      status: "failed",
      lease_owner: null,
      lease_expires_at: null,
    });
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM failure_diagnoses
      WHERE action_id = ? AND code = 'dispatch_failed'
    `).get(actionId!)).toEqual({ count: 1 });
  });

  test("propagates cooperative cancellation and leaves no running specialist child", async () => {
    const item = await fixture();
    await item.runtime.processRunNow(RUN_ID);
    const actionId = item.adapter.invocation!.action.id;

    await item.runtime.cancelRun(
      RUN_ID,
      "operator:fixture",
      "Stop the disposable activation fixture",
      "cancel-disposable-activation-fixture",
    );

    expect(item.adapter.cancelCount).toBe(1);
    expect(item.adapter.cancellation).toEqual({
      runId: RUN_ID,
      reason: "Stop the disposable activation fixture",
    });
    expect(item.adapter.signal?.aborted).toBe(true);
    expect(item.db.prepare("SELECT status, next_action_summary FROM runs WHERE id = ?").get(RUN_ID))
      .toEqual({ status: "cancelled", next_action_summary: null });
    expect(new RuntimeRepository(item.db).getRunProjection(RUN_ID).nextAction).toBeNull();
    expect(item.db.prepare("SELECT status FROM actions WHERE id = ?").get(actionId))
      .toEqual({ status: "cancelled" });
    expect(item.db.prepare("SELECT status FROM tool_calls WHERE action_id = ?").get(actionId))
      .toEqual({ status: "cancelled" });
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM assignments
      WHERE run_id = ? AND (status IN ('queued', 'active') OR lease_owner IS NOT NULL)
    `).get(RUN_ID)).toEqual({ count: 0 });
    expect(item.db.prepare("SELECT COUNT(*) AS count FROM provider_turns WHERE run_id = ?").get(RUN_ID))
      .toEqual({ count: 0 });
    expect(waitingGuidedCount(item.db)).toBe(0);
  });

  test("safe-stops on canonical specialist policy denial without dispatch or a Guided wait", async () => {
    const item = await fixture({ databaseToolAllowed: false });
    await item.runtime.processRunNow(RUN_ID);

    expect(item.adapter.dispatchCount).toBe(0);
    expect(item.db.prepare("SELECT status, next_action_summary FROM runs WHERE id = ?").get(RUN_ID))
      .toEqual({
        status: "blocked",
        next_action_summary: "Review the safe-stop diagnosis, then amend the contract or start a new run.",
      });
    expect(new RuntimeRepository(item.db).getRunProjection(RUN_ID).nextAction)
      .toBe("Review the safe-stop diagnosis, then amend the contract or start a new run.");
    expect(item.db.prepare(`
      SELECT event_type, summary, payload_json FROM events
      WHERE run_id = ? AND event_type = 'run.autonomous_safe_stopped'
      ORDER BY sequence DESC LIMIT 1
    `).get(RUN_ID)).toMatchObject({
      event_type: "run.autonomous_safe_stopped",
      summary: expect.stringContaining("Safe-stopped"),
      payload_json: expect.stringContaining("autonomous_tool_policy_denied"),
    });
    expect(item.db.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?").get(RUN_ID))
      .toEqual({ count: 0 });
    expect(item.db.prepare("SELECT COUNT(*) AS count FROM tool_calls").get())
      .toEqual({ count: 0 });
    expect(item.db.prepare("SELECT COUNT(*) AS count FROM provider_turns WHERE run_id = ?").get(RUN_ID))
      .toEqual({ count: 0 });
    expect(waitingGuidedCount(item.db)).toBe(0);
  });

  test("rejects a planner binding whose model snapshot hash differs from the run pin before planner or specialist contact", async () => {
    const item = await fixture({
      bindingModelConfigurationHash: "b".repeat(64),
    });

    await expect(item.runtime.processRunNow(RUN_ID)).rejects.toMatchObject({
      code: "activation_execution_model_configuration_mismatch",
    });

    expect(item.adapter.dispatchCount).toBe(0);
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM actions WHERE run_id = ?
    `).get(RUN_ID)).toEqual({ count: 0 });
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM autonomous_activation_receipts
      WHERE run_id = ?
    `).get(RUN_ID)).toEqual({ count: 0 });
    expect(item.db.prepare(`
      SELECT status FROM runs WHERE id = ?
    `).get(RUN_ID)).toEqual({ status: "blocked" });
    expect(item.db.prepare(`
      SELECT event_type, payload_json FROM events
      WHERE run_id = ? AND event_type = 'run.autonomous_safe_stopped'
      ORDER BY sequence DESC LIMIT 1
    `).get(RUN_ID)).toMatchObject({
      event_type: "run.autonomous_safe_stopped",
      payload_json: expect.stringContaining(
        "activation_execution_model_configuration_mismatch",
      ),
    });
  });

  test("clears the stale validation action when verified evidence cannot satisfy completion", async () => {
    const item = await fixture();
    await item.runtime.processRunNow(RUN_ID);
    const invocation = item.adapter.invocation!;

    const receipt = await item.adapter.emit({
      actionId: invocation.action.id,
      runId: invocation.action.runId,
      actionFingerprint: invocation.action.fingerprint,
      success: true,
      summary: "The disposable specialist result completed without eligible verified evidence.",
      progress: {
        stepStates: { [invocation.action.stepId]: "completed" },
        discoveredEntityIds: ["asset-disposable-unverified-host"],
      },
    });

    expect(receipt).toMatchObject({
      accepted: true,
      duplicate: false,
      runState: "failed",
      nextAction: null,
    });
    expect(item.db.prepare(`
      SELECT status, status_reason, next_action_summary FROM runs WHERE id = ?
    `).get(RUN_ID)).toMatchObject({
      status: "failed",
      status_reason: expect.stringContaining("Failed safely"),
      next_action_summary: null,
    });
    expect(new RuntimeRepository(item.db).getRunProjection(RUN_ID).nextAction).toBeNull();
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'run.success_criteria_failed'
    `).get(RUN_ID)).toEqual({ count: 1 });
    expect(waitingGuidedCount(item.db)).toBe(0);
  });
});

describe("signed local-first provider-advisory Autonomous planning", () => {
  test("persists the exact disclosure/request proof, accepts only an opaque ordering, and dispatches the specialist model", async () => {
    let networkCalls = 0;
    let capturedBody = "";
    let capturedBrief = "";
    let capturedProof:
      | Readonly<{
          provider_turn_id: string;
          context_pack_id: string;
          advisory_planning_request_id: string;
          planning_disclosure_mode: string;
          advisory_identity_hash: string;
          request_body_hash: string;
          request_body_bytes: number;
          request_contract_version: string;
          request_endpoint: string;
          request_authorized_at: string;
          turn_status: string;
        }>
      | undefined;
    let capturedActivation:
      | Readonly<{
          planning_route: string;
          planning_planner_id: string;
          planning_model_assignment_id: string;
          planning_primary_configuration_id: string;
        }>
      | undefined;
    let item:
      Awaited<ReturnType<typeof fixture>>;
    item = await fixture({
      providerAdvisoryFetch: async (_url, init) => {
        networkCalls += 1;
        capturedBody = String(init?.body ?? "");
        const outbound = JSON.parse(capturedBody) as {
          readonly messages: readonly {
            readonly role: string;
            readonly content: string;
          }[];
        };
        capturedBrief = outbound.messages.find(
          ({ role }) => role === "user",
        )?.content ?? "";

        capturedProof = item.db.prepare(`
          SELECT
            receipt.provider_turn_id,
            receipt.context_pack_id,
            receipt.advisory_planning_request_id,
            receipt.planning_disclosure_mode,
            receipt.advisory_identity_hash,
            receipt.request_body_hash,
            receipt.request_body_bytes,
            receipt.request_contract_version,
            receipt.request_endpoint,
            receipt.request_authorized_at,
            turn.status AS turn_status
          FROM provider_exposure_receipts AS receipt
          JOIN provider_turns AS turn ON turn.id = receipt.provider_turn_id
        `).get() as typeof capturedProof;
        capturedActivation = item.db.prepare(`
          SELECT planning_route, planning_planner_id,
            planning_model_assignment_id,
            planning_primary_configuration_id
          FROM autonomous_activation_receipts
          WHERE run_id = ? ORDER BY generation DESC LIMIT 1
        `).get(RUN_ID) as typeof capturedActivation;
        return providerAdvisorySuccessResponse(capturedBody);
      },
    });

    expect(item.readiness).toMatchObject({
      status: "ready",
      components: {
        providerAdvisoryBoundary: true,
      },
    });
    await item.runtime.processRunNow(RUN_ID);

    expect(networkCalls).toBe(1);
    expect(capturedProof).toMatchObject({
      provider_turn_id: expect.stringMatching(/^provider-turn-/u),
      context_pack_id: expect.any(String),
      advisory_planning_request_id:
        expect.stringMatching(/^planning-request-/u),
      planning_disclosure_mode: "sanitized_internal",
      advisory_identity_hash: expect.stringMatching(/^[a-f0-9]{64}$/u),
      request_body_hash: createHash("sha256")
        .update(capturedBody, "utf8")
        .digest("hex"),
      request_body_bytes: Buffer.byteLength(capturedBody, "utf8"),
      request_contract_version:
        "ti-scale.openrouter-structured-request.v1",
      request_endpoint:
        "https://openrouter.ai/api/v1/chat/completions",
      request_authorized_at: NOW.toISOString(),
      turn_status: "started",
    });
    expect(capturedActivation).toEqual({
      planning_route: "provider_advisory",
      planning_planner_id: AGENT_ID,
      planning_model_assignment_id: ADVISOR_MODEL_ASSIGNMENT_ID,
      planning_primary_configuration_id:
        ADVISOR_MODEL_CONFIGURATION_ID,
    });
    const parsedBrief = JSON.parse(capturedBrief) as {
      readonly candidates: readonly {
        readonly candidateId: string;
      }[];
    };
    expect(parsedBrief.candidates).toHaveLength(1);
    expect(parsedBrief.candidates[0]!.candidateId).toMatch(
      /^candidate_[a-f0-9]{24}$/u,
    );
    for (const forbidden of [
      TARGET,
      TOOL_ID,
      MCP_SERVER_ID,
      AGENT_ID,
      "fixture-enforcing-provider",
      "fixture-reviewed-model",
      MODEL_CONFIGURATION_ID,
      MODEL_ASSIGNMENT_ID,
    ]) {
      expect(capturedBrief).not.toContain(forbidden);
    }
    expect(capturedBrief).toContain("candidate_");

    expect(item.adapter.dispatchCount).toBe(1);
    expect(item.adapter.invocation).toBeDefined();
    const action = item.db.prepare(`
      SELECT normalized_arguments_json
      FROM actions WHERE run_id = ?
    `).get(RUN_ID) as { normalized_arguments_json: string };
    const argumentsRecord = JSON.parse(action.normalized_arguments_json) as {
      readonly orchestration: {
        readonly runtimeModelBinding: {
          readonly providerId: string;
          readonly modelId: string;
          readonly modelConfigurationId: string;
          readonly modelAssignmentId: string;
        };
      };
    };
    expect(argumentsRecord.orchestration.runtimeModelBinding).toMatchObject({
      providerId: "fixture-enforcing-provider",
      modelId: "fixture-reviewed-model",
      modelConfigurationId: MODEL_CONFIGURATION_ID,
      modelAssignmentId: MODEL_ASSIGNMENT_ID,
    });
    expect(argumentsRecord.orchestration.runtimeModelBinding.modelId)
      .not.toBe(ADVISOR_MODEL_ID);

    expect(item.db.prepare(`
      SELECT provider, model, agent_id, model_assignment_id,
        model_configuration_id, status, input_tokens, output_tokens,
        total_tokens, billed_cost_usd, exact_token_usage, exact_cost_usage,
        returned_model
      FROM provider_turns WHERE run_id = ?
    `).all(RUN_ID)).toEqual([{
      provider: "openrouter",
      model: ADVISOR_MODEL_ID,
      agent_id: AGENT_ID,
      model_assignment_id: ADVISOR_MODEL_ASSIGNMENT_ID,
      model_configuration_id: ADVISOR_MODEL_CONFIGURATION_ID,
      status: "completed",
      input_tokens: 23,
      output_tokens: 11,
      total_tokens: 34,
      billed_cost_usd: 0.0007,
      exact_token_usage: 1,
      exact_cost_usage: 1,
      returned_model: ADVISOR_MODEL_ID,
    }]);
    expect(item.db.prepare(`
      SELECT binding_type, provider_turn_id
      FROM autonomous_activation_bindings
      WHERE binding_type = 'planning'
    `).all()).toEqual([{
      binding_type: "planning",
      provider_turn_id: expect.stringMatching(/^provider-turn-/u),
    }]);
    expect(item.db.prepare(`
      SELECT status FROM runs WHERE id = ?
    `).get(RUN_ID)).toEqual({ status: "running" });
    expect(waitingGuidedCount(item.db)).toBe(0);
  });

  test("accounts a completed advisor turn before a downstream execution-model drift safe-stops activation", async () => {
    let item:
      Awaited<ReturnType<typeof fixture>>;
    item = await fixture({
      providerAdvisoryFetch: async (_url, init) => {
        const body = String(init?.body ?? "");
        item.db.prepare(`
          UPDATE model_configurations
          SET model_id = 'fixture-drifted-after-provider-response',
              updated_at = ?, version = version + 1
          WHERE id = ?
        `).run(NOW.toISOString(), MODEL_CONFIGURATION_ID);
        return providerAdvisorySuccessResponse(body);
      },
    });

    await expect(item.runtime.processRunNow(RUN_ID)).rejects.toMatchObject({
      code: "autonomous_runtime_model_assignment_mismatch",
    });

    expect(item.adapter.dispatchCount).toBe(0);
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM plans WHERE run_id = ?
    `).get(RUN_ID)).toEqual({ count: 0 });
    expect(item.db.prepare(`
      SELECT status, input_tokens, output_tokens, total_tokens,
        billed_cost_usd, exact_token_usage, exact_cost_usage
      FROM provider_turns WHERE run_id = ?
    `).get(RUN_ID)).toEqual({
      status: "completed",
      input_tokens: 23,
      output_tokens: 11,
      total_tokens: 34,
      billed_cost_usd: 0.0007,
      exact_token_usage: 1,
      exact_cost_usage: 1,
    });
    const run = item.db.prepare(`
      SELECT status, budget_usage_json FROM runs WHERE id = ?
    `).get(RUN_ID) as {
      status: string;
      budget_usage_json: string;
    };
    expect(run.status).toBe("blocked");
    expect(JSON.parse(run.budget_usage_json)).toMatchObject({
      providerTurns: 1,
      providerTokens: 34,
      estimatedCost: 0.0007,
    });
    expect(item.db.prepare(`
      SELECT code, originating_component
      FROM failure_diagnoses
      WHERE run_id = ? ORDER BY created_at DESC LIMIT 1
    `).get(RUN_ID)).toEqual({
      code: "autonomous_runtime_model_assignment_mismatch",
      originating_component: "command-runtime.planning-provider",
    });
  });

  test("retains exact billed usage when a structured 200 response is rejected locally", async () => {
    const item = await fixture({
      providerAdvisoryFetch: async (_url, init) =>
        providerAdvisorySuccessResponse(
          String(init?.body ?? ""),
          { toolArguments: { command: "id" } },
        ),
    });

    await expect(item.runtime.processRunNow(RUN_ID)).rejects.toMatchObject({
      code: "openrouter_structured_json_rejected",
    });

    expect(item.adapter.dispatchCount).toBe(0);
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM plans WHERE run_id = ?
    `).get(RUN_ID)).toEqual({ count: 0 });
    expect(item.db.prepare(`
      SELECT status, error_category, input_tokens, output_tokens,
        total_tokens, billed_cost_usd, exact_token_usage, exact_cost_usage,
        returned_model
      FROM provider_turns WHERE run_id = ?
    `).get(RUN_ID)).toEqual({
      status: "failed",
      error_category: "provider_refused",
      input_tokens: 23,
      output_tokens: 11,
      total_tokens: 34,
      billed_cost_usd: 0.0007,
      exact_token_usage: 1,
      exact_cost_usage: 1,
      returned_model: ADVISOR_MODEL_ID,
    });
    const run = item.db.prepare(`
      SELECT status, budget_usage_json FROM runs WHERE id = ?
    `).get(RUN_ID) as {
      status: string;
      budget_usage_json: string;
    };
    expect(run.status).toBe("blocked");
    expect(JSON.parse(run.budget_usage_json)).toMatchObject({
      providerTurns: 1,
      providerTokens: 34,
      estimatedCost: 0.0007,
    });
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM actions WHERE run_id = ?
    `).get(RUN_ID)).toEqual({ count: 0 });
  });

  test("provider outage and refusal safe-stop without activating the local candidate or dispatching a specialist", async () => {
    const cases = [
      {
        label: "outage",
        expectedCategory: "provider_unavailable",
        expectedTurnCategory: "provider_unavailable",
        expectedDiagnosisCode:
          "mission_runtime_provider_unavailable_retry_exhausted",
        expectedDiagnosisCategory: "provider_unavailable",
        fetch: async () => {
          throw new TypeError("test-only provider transport outage");
        },
      },
      {
        label: "refusal",
        expectedCategory: "provider_refused",
        expectedTurnCategory: "provider_refused",
        expectedDiagnosisCode: "openrouter_request_rejected",
        expectedDiagnosisCategory: "invalid_input",
        fetch: async () =>
          new Response("{}", {
            status: 400,
            headers: { "content-type": "application/json" },
          }),
      },
    ] as const;

    for (const scenario of cases) {
      let networkCalls = 0;
      const item = await fixture({
        providerAdvisoryFetch: async () => {
          networkCalls += 1;
          return scenario.fetch();
        },
      });

      if (scenario.expectedCategory === "provider_unavailable") {
        await expect(item.runtime.processRunNow(RUN_ID)).rejects.toMatchObject({
          code: "mission_runtime_provider_unavailable_retry_exhausted",
        });
      } else {
        await expect(item.runtime.processRunNow(RUN_ID)).rejects.toMatchObject({
          code: "openrouter_request_rejected",
        });
      }

      expect(networkCalls, scenario.label).toBe(1);
      expect(item.adapter.dispatchCount, scenario.label).toBe(0);
      expect(item.db.prepare(`
        SELECT COUNT(*) AS count FROM plans WHERE run_id = ?
      `).get(RUN_ID), scenario.label).toEqual({ count: 0 });
      expect(item.db.prepare(`
        SELECT COUNT(*) AS count FROM actions WHERE run_id = ?
      `).get(RUN_ID), scenario.label).toEqual({ count: 0 });
      expect(item.db.prepare(`
        SELECT status, error_category
        FROM provider_turns WHERE run_id = ?
      `).all(RUN_ID), scenario.label).toEqual([{
        status: "failed",
        error_category: scenario.expectedTurnCategory,
      }]);
      expect(item.db.prepare(`
        SELECT COUNT(*) AS count
        FROM provider_exposure_receipts
        WHERE run_id = ? AND request_authorized_at IS NOT NULL
          AND request_body_hash IS NOT NULL
      `).get(RUN_ID), scenario.label).toEqual({ count: 1 });
      expect(item.db.prepare(`
        SELECT status, next_action_summary
        FROM runs WHERE id = ?
      `).get(RUN_ID), scenario.label).toEqual({
        status: "blocked",
        next_action_summary:
          "Review the safe-stop diagnosis, then amend the contract or start a new run.",
      });
      const diagnosis = item.db.prepare(`
        SELECT code, category, retryable, human_reason
        FROM failure_diagnoses
        WHERE run_id = ? ORDER BY created_at DESC LIMIT 1
      `).get(RUN_ID) as {
        code: string;
        category: string;
        retryable: number;
        human_reason: string;
      };
      expect(diagnosis, scenario.label).toMatchObject({
        code: scenario.expectedDiagnosisCode,
        category: scenario.expectedDiagnosisCategory,
      });
      expect(
        diagnosis.human_reason.toLowerCase(),
        scenario.label,
      ).toContain("safe-stopped");
      expect(item.db.prepare(`
        SELECT payload_json
        FROM events
        WHERE run_id = ? AND event_type = 'run.autonomous_safe_stopped'
        ORDER BY sequence DESC LIMIT 1
      `).get(RUN_ID), scenario.label).toMatchObject({
        payload_json: expect.stringContaining(
          scenario.expectedDiagnosisCategory,
        ),
      });
      expect(waitingGuidedCount(item.db), scenario.label).toBe(0);
    }
  });

  test("preserves Retry-After on a rate-limited signed advisor and performs no fallback dispatch", async () => {
    let networkCalls = 0;
    const item = await fixture({
      providerAdvisoryFetch: async () => {
        networkCalls += 1;
        return new Response("{}", {
          status: 429,
          headers: {
            "content-type": "application/json",
            "retry-after": "7",
          },
        });
      },
    });

    await expect(item.runtime.processRunNow(RUN_ID)).rejects.toMatchObject({
      code: "mission_runtime_rate_limit_retry_exhausted",
      options: {
        details: {
          retryAfterMs: 7_000,
        },
      },
    });

    expect(networkCalls).toBe(1);
    expect(item.adapter.dispatchCount).toBe(0);
    expect(item.db.prepare(`
      SELECT status, error_category FROM provider_turns WHERE run_id = ?
    `).get(RUN_ID)).toEqual({
      status: "failed",
      error_category: "rate_limit",
    });
    const safeStop = item.db.prepare(`
      SELECT payload_json
      FROM events
      WHERE run_id = ? AND event_type = 'run.autonomous_safe_stopped'
      ORDER BY sequence DESC LIMIT 1
    `).get(RUN_ID) as { payload_json: string };
    expect(safeStop.payload_json).toContain('"retryAfterMs":7000');
    expect(safeStop.payload_json).toContain(
      '"retryReason":"signed_budget_exhausted"',
    );
    expect(item.db.prepare(`
      SELECT COUNT(*) AS count FROM plans WHERE run_id = ?
    `).get(RUN_ID)).toEqual({ count: 0 });
  });
});

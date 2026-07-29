import { afterEach, describe, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS,
  AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
  type RuntimeSourceManifests,
} from "../../domain";
import {
  BrainContextService,
  CanonicalMissionMemoryGraph,
  type BrainDependencyAvailability,
} from "../../brain-runtime";
import {
  MemoryRepository,
  SecondBrainService,
  type MemoryLifecycle,
  type MemoryNodeType,
  type MemoryScope,
  type MemorySensitivity,
} from "../../memory";
import {
  ObsidianVaultBridge,
  VaultPathPolicy,
} from "../../vault";
import {
  AutonomousReadinessError,
  IdempotencyConflictError,
  MissionRepository,
  MissionService,
  MissionValidationError,
  OverviewRepository,
  ReadinessService,
  autonomousContractHash,
  validateMissionCreateRequest,
  type AutonomousMissionRequest,
  type GuidedMissionRequest,
  type ReadinessCheckProvider,
} from "../index";

const disposableVaultRoots = new Set<string>();

afterEach(() => {
  for (const root of disposableVaultRoots) {
    rmSync(root, { recursive: true, force: true });
  }
  disposableVaultRoots.clear();
});

function autonomousRequest(overrides: Partial<AutonomousMissionRequest> = {}): AutonomousMissionRequest {
  const request: AutonomousMissionRequest = {
    journey: "autonomous",
    launch: true,
    title: "Authorized service assessment",
    objective: "Validate exposed services within the signed lab scope",
    successCriteria: ["Every approved target has evidence-backed service inventory"],
    authorization: {
      engagementId: "engagement-lab",
      allowedTargets: ["10.10.10.0/24"],
      prohibitedTargets: ["10.10.10.1"],
      authorizationConfirmed: true,
      timeWindow: "2026-07-15T00:00:00Z/2026-07-16T00:00:00Z",
      dataHandling: "Keep evidence local",
    },
    contract: {
      allowedActionClasses: ["reconnaissance"],
      prohibitedActionClasses: ["destructive"],
      destructivePolicy: "prohibited",
      evidenceRequirements: ["Hash every retained artifact"],
      timeBudgetMinutes: 60,
      toolCallBudget: 100,
      tokenBudget: 50_000,
      costBudget: 10,
      retryBudget: 2,
      replanBudget: 2,
      concurrencyLimit: 3,
      evidenceStorageBudgetBytes: 64 * 1024 * 1024,
      artifactStorageBudgetBytes: 256 * 1024 * 1024,
      notificationPolicy: "in_app_only",
      reportingFormat: "ti_scale_json",
      dataHandlingPolicy: "local_private",
      retentionPolicy: "operator_managed",
      providerPolicy: "automatic_enforcing_only",
      toolPolicy: "contract_allowlist",
      specialistAgentIds: ["agent-recon"],
      agentModelAssignments: [{
        agentId: "agent-recon",
        primaryConfigurationId: "modelcfg_test_agent_recon",
        fallbackConfigurationId: null,
      }],
      memoryScopes: ["verified_lessons"],
      contextNodeIds: [],
      safeStopConditions: ["Target resolves outside approved scope"],
      deliverables: ["Evidence-backed mission report"],
    },
    ...overrides,
  };
  return {
    ...request,
    contractReview: { version: 1, hash: autonomousContractHash(request) },
  };
}

function guidedRequest(overrides: Partial<GuidedMissionRequest> = {}): GuidedMissionRequest {
  return {
    journey: "guided",
    launch: true,
    authorizationConfirmed: true,
    title: "Guided lab assessment",
    objective: "Understand the authorized service exposure one step at a time",
    target: "lab.internal",
    engagementId: "engagement-lab",
    explanationDepth: "deep",
    executionPreference: "manual",
    evidenceExpectations: ["Retain normalized scan output"],
    ...overrides,
  };
}

function provider(
  status: "pass" | "warn" | "fail" = "pass",
  id = "runtime-enforcement",
): ReadinessCheckProvider {
  return {
    id,
    label: "Runtime enforcement",
    journeys: ["autonomous", "guided"],
    evaluate: () => ({
      id,
      label: "Runtime enforcement",
      status,
      journeys: ["autonomous", "guided"],
      impact: status === "pass" ? "Policy boundary is enforceable." : "Policy boundary is unavailable.",
      ...(status === "fail" ? { remediation: "Restore the enforcing runtime." } : {}),
    }),
  };
}

function service(
  database: ReturnType<typeof createDatabaseConnection>,
  readinessProviders: readonly ReadinessCheckProvider[] = [provider()],
  brainAvailability?: () => BrainDependencyAvailability,
  readRuntimeManifests?: () => RuntimeSourceManifests,
  memoryGraph?: CanonicalMissionMemoryGraph,
  projectMemoryNodes?: (nodeIds: readonly string[]) => void,
  resolveExistingVaultPath?: (vaultPath: string) => string,
): MissionService {
  const now = new Date().toISOString();
  const validUntil = new Date(Date.now() + 5 * 60_000).toISOString();
  database.prepare(`
    INSERT OR IGNORE INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES ('agent-recon', 'reconnaissance', 'Recon specialist', 'available',
      '{"defaultProvider":"xai-grok-oauth"}',
      '{"allowedTools":["nmap"],"deniedTools":[],"approvalRequiredTools":[]}',
      '{"userFacing":true,"productAgent":true}', '2.4', ?, ?, ?)
  `).run(now, now, now);
  database.prepare(`
    INSERT OR IGNORE INTO agent_capabilities (
      agent_id, capability, source, enabled, metadata_json
    ) VALUES ('agent-recon', 'nmap', 'live-route-attestation', 1, ?)
  `).run(JSON.stringify({ validUntil, attestedAt: now, providerIds: ["xai-grok-oauth"] }));
  database.prepare(`
    INSERT OR IGNORE INTO mcp_servers (
      id, name, transport, endpoint_redacted, status, capabilities_json,
      policy_json, last_checked_at, created_at, updated_at
    ) VALUES ('mcp:nmap', 'nmap', 'stdio', 'local stdio', 'healthy', '["nmap"]',
      '{"enabled":true,"assignedAgents":["agent-recon"],"startPermitted":true,"riskClass":"medium"}',
      ?, ?, ?)
  `).run(now, now, now);
  database.prepare(`
    INSERT INTO health_snapshots (
      id, component_type, component_id, status, metrics_json, message, captured_at
    ) VALUES (?, 'provider', 'xai-grok-oauth', 'healthy',
      ?,
      'OAuth and Autonomous boundary verified', ?)
  `).run(`health-${randomUUID()}`, JSON.stringify({
    authenticated: true,
    callable: true,
    attestedAt: now,
    expiresAt: validUntil,
    enforcesAutonomousBoundary: true,
    reportsExactTokenUsage: true,
    reportsExactCostUsage: true,
  }), now);
  return new MissionService(
    new MissionRepository(database),
    new OverviewRepository(database),
    new ReadinessService(readinessProviders),
    new BrainContextService({
      database,
      secondBrain: new SecondBrainService(new MemoryRepository(database)),
      ...(brainAvailability ? { availability: brainAvailability } : {}),
      ...(resolveExistingVaultPath ? { resolveExistingVaultPath } : {}),
    }),
    readRuntimeManifests,
    memoryGraph,
    projectMemoryNodes,
    {
      resolveAutonomousAssignments: ({
        specialistAgentIds,
        overrides = [],
      }) => {
        if (specialistAgentIds.includes("agent-without-model")) {
          throw new Error(
            "No live catalog configuration is currently executable for selected specialist agent-without-model",
          );
        }
        const selections = specialistAgentIds.map((agentId) =>
          overrides.find((selection) => selection.agentId === agentId) ?? {
            agentId,
            primaryConfigurationId: `modelcfg_test_${agentId}`,
            fallbackConfigurationId: null,
            source: "recommended" as const,
          });
        return {
          observedAt: now,
          selections,
          receipts: selections.map((selection) => ({
            agentId: selection.agentId,
            source: selection.source ?? "recommended",
            ready: true,
            reasons: [],
            primary: {
              configurationId: selection.primaryConfigurationId,
              providerId: "provider-test",
              modelId: "model-test",
              displayName: "Test enforced model",
              executionBoundary: "provider_tool_calling" as const,
              reasoningEffort: null,
              enforcementMode: "enforced_executor" as const,
              authState: "authenticated" as const,
              healthState: "healthy" as const,
              disclosureClass: "public_only" as const,
              costClass: "unknown" as const,
              latencyClass: "unknown" as const,
              contextLimit: 128_000,
              catalogSource: "mission-service-test",
              catalogRetrievedAt: now,
            },
            fallback: null,
          })),
        };
      },
      validateAutonomousAssignments: ({
        assignments,
        specialistAgentIds,
      }) => ({
        observedAt: now,
        selections: [...assignments].sort((left, right) =>
          left.agentId.localeCompare(right.agentId)),
        receipts: specialistAgentIds.map((agentId) => {
          const selection = assignments.find((item) => item.agentId === agentId)!;
          return {
            agentId,
            source: "operator_override" as const,
            ready: Boolean(selection),
            reasons: selection ? [] : [`Missing assignment for ${agentId}`],
            primary: {
              configurationId:
                selection?.primaryConfigurationId ?? "modelcfg_missing",
              providerId: "provider-test",
              modelId: "model-test",
              displayName: "Test enforced model",
              executionBoundary: "provider_tool_calling" as const,
              reasoningEffort: null,
              enforcementMode: "enforced_executor" as const,
              authState: "authenticated" as const,
              healthState: "healthy" as const,
              disclosureClass: "public_only" as const,
              costClass: "unknown" as const,
              latencyClass: "unknown" as const,
              contextLimit: 128_000,
              catalogSource: "mission-service-test",
              catalogRetrievedAt: now,
            },
            fallback: null,
          };
        }),
      }),
      pinExactAutonomousAssignments: ({
        assignments,
        missionId,
        runId,
      }) => assignments.map((selection, index) => ({
        id: `modelassign_test_${index}`,
        agentId: selection.agentId,
        missionId,
        runId,
        stepId: null,
        purpose: "execution" as const,
        primaryConfigurationId: selection.primaryConfigurationId,
        fallbackConfigurationId: selection.fallbackConfigurationId,
        inheritanceLevel: "mission" as const,
        pinned: true as const,
        resolutionReason: "Exact test contract assignment",
        resolvedAt: now,
        createdAt: now,
      })),
      validateAutonomousPlanningSelection: (selection) =>
        selection.route === "local_deterministic"
          ? null
          : {
              agentId: selection.agentId,
              source: "operator_override" as const,
              ready: true,
              reasons: [],
              primary: {
                configurationId: selection.primaryConfigurationId,
                providerId: "provider-test",
                modelId: "model-planning-test",
                displayName: "Test advisor model",
                executionBoundary: "provider_tool_calling" as const,
                reasoningEffort: null,
                enforcementMode: "advisor_only" as const,
                authState: "authenticated" as const,
                healthState: "healthy" as const,
                disclosureClass: selection.disclosureClass,
                costClass: "unknown" as const,
                latencyClass: "unknown" as const,
                contextLimit: 128_000,
                catalogSource: "mission-service-test",
                catalogRetrievedAt: now,
              },
              fallback: null,
            },
      pinExactAutonomousPlanningSelection: ({
        selection,
        missionId,
        runId,
      }) => selection.route === "local_deterministic"
        ? null
        : {
            id: "modelassign_test_planning",
            agentId: selection.agentId,
            missionId,
            runId,
            stepId: null,
            purpose: "planning" as const,
            primaryConfigurationId: selection.primaryConfigurationId,
            fallbackConfigurationId: selection.fallbackConfigurationId,
            inheritanceLevel: "mission" as const,
            pinned: true as const,
            resolutionReason: "Exact test planning selection",
            resolvedAt: now,
            createdAt: now,
          },
    },
  );
}

function evidenceRuntimeManifests(): RuntimeSourceManifests {
  return {
    riskClasses: [],
    evidenceKinds: [],
    capabilities: [],
    tools: [
      {
        id: "scan-evidence-producer",
        label: "Available scan evidence producer",
        available: true,
        locallyPolicyEnforced: true,
        requiresModel: false,
        actionClassIds: [],
        evidenceTypeIds: ["port_service_scan_result"],
        riskClassIds: [],
      },
      {
        id: "dns-evidence-producer",
        label: "Unavailable DNS evidence producer",
        available: false,
        locallyPolicyEnforced: true,
        requiresModel: false,
        actionClassIds: [],
        evidenceTypeIds: ["dns_certificate_record"],
        riskClassIds: [],
      },
    ],
    mcpServers: [],
    agents: [],
    providers: [],
  };
}

function count(database: ReturnType<typeof createDatabaseConnection>, table: string): number {
  return (database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count;
}

function memoryNode(
  database: ReturnType<typeof createDatabaseConnection>,
  input: {
    id: string;
    nodeType: MemoryNodeType;
    scope: MemoryScope;
    status: MemoryLifecycle;
    sensitivity?: MemorySensitivity;
    allowAutonomous?: boolean;
    expiresAt?: string;
  },
): void {
  new MemoryRepository(database).createNode({
    id: input.id,
    nodeType: input.nodeType,
    title: `${input.nodeType} ${input.id}`,
    summary: `Canonical ${input.status} context`,
    scope: input.scope,
    sensitivity: input.sensitivity ?? "private",
    confidence: 0.9,
    lifecycleStatus: input.status,
    confirmationState: input.status === "confirmed" ? "confirmed" : "not_required",
    provenance: {
      method: "operator_statement",
      explanation: "Confirmed in the focused contract test",
      sources: [{ sourceType: "test", sourceId: input.id, acquiredAt: new Date().toISOString() }],
    },
    authorType: "operator",
    retentionPolicy: { allowAutonomous: input.allowAutonomous ?? true },
    ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
  });
}

function operatorPreferenceProfile(
  database: ReturnType<typeof createDatabaseConnection>,
  input: {
    readonly id: string;
    readonly preferenceKey: string;
    readonly value: Readonly<Record<string, unknown>>;
    readonly appliesTo: readonly string[];
    readonly scope?: MemoryScope;
    readonly actorId?: string;
  },
): void {
  const actorId = input.actorId ?? "operator-1";
  const scope = input.scope ?? { kind: "global" as const };
  const confirmedAt = new Date().toISOString();
  new MemoryRepository(database).createNode({
    id: input.id,
    nodeType: "preference",
    title: `Confirmed ${input.preferenceKey}`,
    summary: `Typed, explicitly confirmed operator preference for ${input.preferenceKey}.`,
    scope,
    sensitivity: "private",
    confidence: 1,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: {
      method: "operator_statement",
      explanation: "Explicitly confirmed by the operator in this intake preference fixture.",
      sources: [{
        sourceType: "operator_instruction_manifest",
        sourceId: input.id,
        acquiredAt: confirmedAt,
      }],
    },
    authorType: "operator",
    authorId: actorId,
    retentionPolicy: { allowAutonomous: true },
  });
  database.prepare(`
    INSERT INTO preference_profiles (
      id, operator_id, scope, engagement_id, mission_type, preference_key,
      value_json, confirmation_state, confidence, source_node_id,
      consent_policy, version, confirmed_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'autonomous', ?, ?, 'confirmed', 1, ?,
      'explicit_operator_confirmation', 1, ?, ?, ?)
  `).run(
    `profile-${input.id}`,
    actorId,
    scope.kind === "engagement" ? "engagement" : "global",
    scope.kind === "engagement" ? scope.engagementId ?? null : null,
    input.preferenceKey,
    JSON.stringify({
      category: input.preferenceKey.split(".")[0],
      value: input.value,
      appliesTo: input.appliesTo,
    }),
    input.id,
    confirmedAt,
    confirmedAt,
    confirmedAt,
  );
}

function connectHealthyTestVault(
  database: ReturnType<typeof createDatabaseConnection>,
  nodeIds: readonly string[],
): Readonly<{
  resolveExistingVaultPath(vaultPath: string): string;
}> {
  const connectionId = "vault-mission-service-preferences";
  const root = mkdtempSync(join(tmpdir(), "ti-scale-mission-service-vault-"));
  disposableVaultRoots.add(root);
  const paths = new VaultPathPolicy(root);
  const bridge = new ObsidianVaultBridge(
    database,
    new MemoryRepository(database),
    paths,
  );
  const connection = bridge.connect({
    id: connectionId,
    vaultPath: "Mission-Service-Vault",
    displayName: "Mission service preference Vault",
    syncScope: {},
    permissionGranted: true,
  });
  bridge.refreshConnectionHealthProof(
    connection.id,
    "system:mission-service-test-vault-health",
  );
  const now = new Date().toISOString();
  const insertSync = database.prepare(`
    INSERT INTO vault_sync_state (
      id, connection_id, node_id, relative_path, database_version,
      vault_content_hash, database_content_hash, status,
      last_scanned_at, last_synced_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'synced', ?, ?)
  `);
  for (const nodeId of nodeIds) {
    const current = database.prepare(`
      SELECT node.version, version.content_hash
      FROM memory_nodes node
      JOIN memory_versions version
        ON version.node_id = node.id AND version.version = node.version
      WHERE node.id = ?
    `).get(nodeId) as {
      readonly version: number;
      readonly content_hash: string;
    };
    insertSync.run(
      `sync-${nodeId}`,
      connectionId,
      nodeId,
      `10 Operator/${nodeId}.md`,
      current.version,
      current.content_hash,
      current.content_hash,
      now,
      now,
    );
  }
  return Object.freeze({
    resolveExistingVaultPath: (vaultPath: string) =>
      paths.resolveExistingVault(vaultPath),
  });
}

describe("Ti-Scale mission vertical slice", () => {
  test("accepts exactly Autonomous and Guided as journeys", () => {
    expect(() =>
      validateMissionCreateRequest({
        ...guidedRequest(),
        journey: "ask",
      }),
    ).toThrow(MissionValidationError);
    expect(() =>
      validateMissionCreateRequest({
        ...guidedRequest(),
        journey: "supervised",
      }),
    ).toThrow(MissionValidationError);
    expect(validateMissionCreateRequest(guidedRequest()).journey).toBe("guided");
    expect(validateMissionCreateRequest(autonomousRequest()).journey).toBe("autonomous");
  });

  test("requires an explicit authorization assertion for Guided creation", () => {
    expect(() => validateMissionCreateRequest({
      ...guidedRequest(),
      authorizationConfirmed: false,
    })).toThrow(MissionValidationError);
  });

  test("requires one exact model assignment per selected specialist and canonicalizes their order", () => {
    const base = autonomousRequest();
    const validated = validateMissionCreateRequest({
      ...base,
      contract: {
        ...base.contract,
        specialistAgentIds: ["agent-web", "agent-recon"],
        agentModelAssignments: [
          {
            agentId: "agent-web",
            primaryConfigurationId: "modelcfg_web",
            fallbackConfigurationId: "modelcfg_web_fallback",
          },
          {
            agentId: "agent-recon",
            primaryConfigurationId: "modelcfg_recon",
            fallbackConfigurationId: null,
          },
        ],
      },
    });
    if (validated.journey !== "autonomous") {
      throw new Error("Expected an Autonomous request");
    }
    expect(validated.contract.specialistAgentIds).toEqual([
      "agent-recon",
      "agent-web",
    ]);
    expect(validated.contract.agentModelAssignments).toEqual([
      {
        agentId: "agent-recon",
        primaryConfigurationId: "modelcfg_recon",
        fallbackConfigurationId: null,
      },
      {
        agentId: "agent-web",
        primaryConfigurationId: "modelcfg_web",
        fallbackConfigurationId: "modelcfg_web_fallback",
      },
    ]);

    const reordered: AutonomousMissionRequest = {
      ...validated,
      contract: {
        ...validated.contract,
        specialistAgentIds: [...validated.contract.specialistAgentIds].reverse(),
        agentModelAssignments: [
          ...validated.contract.agentModelAssignments,
        ].reverse(),
      },
    };
    expect(autonomousContractHash(reordered))
      .toBe(autonomousContractHash(validated));
  });

  test("rejects missing, extra, duplicate, malformed, or self-fallback model assignments", () => {
    const base = autonomousRequest();
    const invalidContracts: unknown[] = [
      {
        ...base.contract,
        agentModelAssignments: [],
      },
      {
        ...base.contract,
        agentModelAssignments: [
          ...base.contract.agentModelAssignments,
          {
            agentId: "agent-extra",
            primaryConfigurationId: "modelcfg_extra",
            fallbackConfigurationId: null,
          },
        ],
      },
      {
        ...base.contract,
        specialistAgentIds: ["agent-recon", "agent-recon"],
      },
      {
        ...base.contract,
        agentModelAssignments: [
          ...base.contract.agentModelAssignments,
          ...base.contract.agentModelAssignments,
        ],
      },
      {
        ...base.contract,
        agentModelAssignments: [{
          agentId: "agent-recon",
          primaryConfigurationId: "modelcfg_same",
          fallbackConfigurationId: "modelcfg_same",
        }],
      },
      {
        ...base.contract,
        agentModelAssignments: [{
          agentId: "agent-recon",
          primaryConfigurationId: "modelcfg_recon",
        }],
      },
      {
        ...base.contract,
        agentModelAssignments: [{
          agentId: "agent-recon",
          primaryConfigurationId: "modelcfg_recon",
          fallbackConfigurationId: null,
          mutablePreferenceId: "modelpref_not_contract_authority",
        }],
      },
    ];
    for (const contract of invalidContracts) {
      expect(() => validateMissionCreateRequest({
        ...base,
        contract,
      })).toThrow(MissionValidationError);
    }
  });

  test("normalizes, strictly validates, and hashes the distinct signed planning selection", () => {
    const base = autonomousRequest();
    const local = validateMissionCreateRequest({
      ...base,
      contract: {
        ...base.contract,
        planningSelection: undefined,
      },
    });
    if (local.journey !== "autonomous") {
      throw new Error("Expected an Autonomous request");
    }
    expect(local.contract.planningSelection).toEqual({
      route: "local_deterministic",
      plannerId: "ti-scale.local-autonomous-contract-planner.v1",
      enforcementMode: "local_policy",
      disclosureClass: "local_only",
      executionAuthority: "none",
    });
    expect(autonomousContractHash(local)).toBe(autonomousContractHash({
      ...local,
      contract: {
        ...local.contract,
        planningSelection: undefined,
      },
    }));

    const providerPlanning = validateMissionCreateRequest({
      ...base,
      contract: {
        ...base.contract,
        planningSelection: {
          route: "provider_advisory",
          agentId: "agent-planner",
          primaryConfigurationId: "modelcfg_planner_primary",
          fallbackConfigurationId: "modelcfg_planner_fallback",
          enforcementMode: "advisor_only",
          disclosureClass: "sanitized_internal",
          executionAuthority: "none",
        },
      },
    });
    if (providerPlanning.journey !== "autonomous") {
      throw new Error("Expected an Autonomous request");
    }
    expect(providerPlanning.contract.planningSelection).toMatchObject({
      route: "provider_advisory",
      enforcementMode: "advisor_only",
      disclosureClass: "sanitized_internal",
      executionAuthority: "none",
    });
    expect(autonomousContractHash(providerPlanning))
      .not.toBe(autonomousContractHash(local));
    expect(autonomousContractHash({
      ...providerPlanning,
      contract: {
        ...providerPlanning.contract,
        planningSelection: {
          ...providerPlanning.contract.planningSelection!,
          primaryConfigurationId: "modelcfg_planner_changed",
        } as NonNullable<AutonomousMissionRequest["contract"]["planningSelection"]>,
      },
    })).not.toBe(autonomousContractHash(providerPlanning));

    for (const planningSelection of [
      {
        route: "provider_advisory",
        agentId: "agent-planner",
        primaryConfigurationId: "modelcfg_planner",
        fallbackConfigurationId: null,
        enforcementMode: "enforced_executor",
        disclosureClass: "public_only",
        executionAuthority: "none",
      },
      {
        route: "provider_advisory",
        agentId: "agent-planner",
        primaryConfigurationId: "modelcfg_planner",
        enforcementMode: "advisor_only",
        disclosureClass: "public_only",
        executionAuthority: "none",
      },
      {
        route: "local_deterministic",
        plannerId: "ti-scale.local-autonomous-contract-planner.v1",
        enforcementMode: "local_policy",
        disclosureClass: "local_only",
        executionAuthority: "none",
        primaryConfigurationId: "modelcfg_must_not_be_accepted",
      },
    ]) {
      expect(() => validateMissionCreateRequest({
        ...base,
        contract: {
          ...base.contract,
          planningSelection,
        },
      })).toThrow(MissionValidationError);
    }
  });

  test("projects readable model-assignment receipts during Autonomous preflight", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const preflight = await service(database).preflightAutonomous(
        autonomousRequest(),
      );
      expect(preflight.execution.team.modelAssignments).toEqual([
        expect.objectContaining({
          agentId: "agent-recon",
          source: "operator_override",
          ready: true,
          reasons: [],
          primary: expect.objectContaining({
            configurationId: "modelcfg_test_agent_recon",
            providerId: "provider-test",
            modelId: "model-test",
            displayName: "Test enforced model",
            enforcementMode: "enforced_executor",
            authState: "authenticated",
            healthState: "healthy",
          }),
          fallback: null,
        }),
      ]);
      expect(preflight.readiness.checks.find(
        ({ id }) => id === "contract_agent_model_assignments",
      )).toMatchObject({
        status: "pass",
        label: "Pinned specialist model configurations",
      });
      expect(preflight.readiness.checks.find(
        ({ id }) => id === "contract_planning_selection",
      )).toMatchObject({
        status: "pass",
        label: "Signed planning route",
        impact: expect.stringContaining("local deterministic planner"),
      });
    } finally {
      database.close();
    }
  });

  test("rejects incomplete Autonomous authority, scope, action policy, budgets, and deliverables", () => {
    expect(() =>
      validateMissionCreateRequest({
        ...autonomousRequest(),
        authorization: {
          allowedTargets: [],
          prohibitedTargets: [],
          authorizationConfirmed: false,
        },
        contract: {
          ...autonomousRequest().contract,
          allowedActionClasses: [],
          timeBudgetMinutes: 0,
          concurrencyLimit: 0,
          safeStopConditions: [],
          deliverables: [],
        },
      }),
    ).toThrow(MissionValidationError);
  });

  test("accepts only closed destructive-action policy values", () => {
    const validated = validateMissionCreateRequest(autonomousRequest({
      contract: { ...autonomousRequest().contract, destructivePolicy: "validate_without_executing" },
    }));
    expect(validated.journey).toBe("autonomous");
    if (validated.journey !== "autonomous") throw new Error("Expected an Autonomous request");
    expect(validated.contract.destructivePolicy).toBe("validate_without_executing");
    const bounded = validateMissionCreateRequest(autonomousRequest({
      authorization: {
        ...autonomousRequest().authorization,
        environmentClassification: "htb",
        allowedTargets: ["10.129.39.191"],
        prohibitedTargets: [],
      },
      contract: {
        ...autonomousRequest().contract,
        destructivePolicy: "bounded_lab_only",
        boundedDestructiveTargets: ["10.129.39.191"],
      },
    }));
    expect(bounded.journey === "autonomous" && bounded.contract.boundedDestructiveTargets).toEqual(["10.129.39.191"]);
    expect(() => validateMissionCreateRequest(autonomousRequest({
      authorization: {
        ...autonomousRequest().authorization,
        environmentClassification: "internal",
        allowedTargets: ["10.129.39.191"],
        prohibitedTargets: [],
      },
      contract: {
        ...autonomousRequest().contract,
        destructivePolicy: "bounded_lab_only",
        boundedDestructiveTargets: ["10.129.39.191"],
      },
    }))).toThrow(MissionValidationError);
    expect(() => validateMissionCreateRequest(autonomousRequest({
      contract: { ...autonomousRequest().contract, destructivePolicy: "bounded_lab_only" },
    }))).toThrow(MissionValidationError);
    expect(() => validateMissionCreateRequest({
      ...autonomousRequest(),
      contract: { ...autonomousRequest().contract, destructivePolicy: "ask_operator" },
    })).toThrow(MissionValidationError);
  });

  test("rejects cross-engagement memory use without an engagement boundary and canonical target overlap", () => {
    expect(() =>
      validateMissionCreateRequest({
        ...autonomousRequest(),
        authorization: {
          ...autonomousRequest().authorization,
          engagementId: undefined,
        },
        contract: {
          ...autonomousRequest().contract,
          memoryScopes: ["engagement_memory"],
        },
      }),
    ).toThrow(MissionValidationError);
    expect(() =>
      validateMissionCreateRequest({
        ...autonomousRequest(),
        authorization: {
          ...autonomousRequest().authorization,
          allowedTargets: ["HTTP://LAB.INTERNAL"],
          prohibitedTargets: ["http://lab.internal/"],
        },
      }),
    ).toThrow(MissionValidationError);
  });

  test("creates an Autonomous aggregate, confirmed contract, targets, constraints, events, and audit atomically", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const created = await service(database).create(
        autonomousRequest(),
        "autonomous-request-0001",
        "operator-1",
      );
      expect(created.run).toMatchObject({ journey: "autonomous", status: "planning" });
      expect(created.nextUrl).toBe(`/missions/${created.mission.id}`);

      const run = database
        .prepare("SELECT journey, status, contract_id FROM runs WHERE id = ?")
        .get(created.run.id) as { journey: string; status: string; contract_id: string | null };
      expect(run).toMatchObject({ journey: "autonomous", status: "planning" });
      expect(run.contract_id).not.toBeNull();
      expect(count(database, "mission_contracts")).toBe(1);
      expect(count(database, "mission_targets")).toBe(2);
      expect(count(database, "mission_constraints")).toBe(5);
      const persisted = database.prepare(`
        SELECT m.retention_policy_json, m.memory_policy_json,
          mc.contract_hash, mc.action_policy_json, mc.budgets_json,
          r.budget_json AS run_budget_json
        FROM missions m JOIN runs r ON r.mission_id = m.id
        JOIN mission_contracts mc ON mc.id = r.contract_id WHERE r.id = ?
      `).get(created.run.id) as Record<string, string>;
      expect(JSON.parse(persisted.retention_policy_json)).toEqual({
        dataHandling: "local_private",
        mode: "operator_managed",
      });
      expect(JSON.parse(persisted.memory_policy_json)).toMatchObject({ exactContextNodeIds: [] });
      expect(JSON.parse(persisted.action_policy_json)).toMatchObject({
        notificationPolicy: "in_app_only",
        reportingFormat: "ti_scale_json",
        providerPolicy: "automatic_enforcing_only",
        toolPolicy: "contract_allowlist",
        specialistAgentIds: ["agent-recon"],
        planningSelection: {
          route: "local_deterministic",
          executionAuthority: "none",
        },
      });
      expect(JSON.parse(persisted.budgets_json)).toMatchObject({
        toolCalls: 100,
        evidenceBytes: 64 * 1024 * 1024,
        artifactBytes: 256 * 1024 * 1024,
      });
      expect(JSON.parse(persisted.run_budget_json)).toMatchObject({ toolCalls: 100 });
      expect(persisted.contract_hash).toMatch(/^[a-f0-9]{64}$/u);
      expect(count(database, "events")).toBe(2);
      expect(count(database, "event_outbox")).toBe(2);
      expect(count(database, "audit_records")).toBe(2);
      expect(
        database.prepare("SELECT COUNT(*) AS count FROM runs WHERE status = 'waiting_guided_decision'").get(),
      ).toEqual({ count: 0 });
      const journeys = database
        .prepare("SELECT DISTINCT journey FROM events")
        .all() as Array<{ journey: string }>;
      expect(journeys).toEqual([{ journey: "autonomous" }]);
    } finally {
      database.close();
    }
  });

  test("previews and fail-closed validates exact confirmed preferences and verified lessons", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      memoryNode(database, { id: "mem-preference", nodeType: "preference", scope: { kind: "global" }, status: "confirmed" });
      memoryNode(database, { id: "mem-lesson", nodeType: "lesson", scope: { kind: "engagement", engagementId: "engagement-lab" }, status: "verified" });
      memoryNode(database, { id: "mem-cross-scope", nodeType: "lesson", scope: { kind: "engagement", engagementId: "other-engagement" }, status: "verified" });
      const missionService = service(database);
      const requested = autonomousRequest({
        contract: {
          ...autonomousRequest().contract,
          memoryScopes: ["confirmed_preferences", "verified_lessons", "engagement_memory"],
          contextNodeIds: ["mem-preference", "mem-lesson"],
        },
      });
      const preview = await missionService.preflightAutonomous(requested);
      expect(preview.readiness.status).toBe("ready");
      expect(preview.context.candidates.map((candidate) => candidate.id).sort()).toEqual([
        "mem-lesson",
        "mem-preference",
      ]);
      expect(preview.context.selectedNodeIds).toEqual(["mem-preference", "mem-lesson"]);
      expect(preview.context.invalidSelectedNodeIds).toEqual([]);
      expect(preview.readiness.checks.find((check) => check.id === "contract_memory_selection")?.impact)
        .toContain("core agent will also retrieve the smallest relevant confirmed or verified context");

      const invalid = await missionService.preflightAutonomous({
        ...requested,
        contract: { ...requested.contract, contextNodeIds: ["mem-cross-scope"] },
      });
      expect(invalid.readiness.status).toBe("blocked");
      expect(invalid.context.invalidSelectedNodeIds).toEqual(["mem-cross-scope"]);

      const created = await missionService.create(
        { ...requested, contractReview: preview.contract },
        "exact-memory-contract-001",
        "operator-1",
      );
      expect(created.intakeContext).toMatchObject({
        hook: "intake",
        status: "ready",
        retrievedCount: 2,
        memoryInfluencedDefaults: false,
      });
      const policy = database.prepare(`
        SELECT mc.action_policy_json FROM runs r
        JOIN mission_contracts mc ON mc.id = r.contract_id WHERE r.id = ?
      `).get(created.run.id) as { action_policy_json: string };
      expect(JSON.parse(policy.action_policy_json).contextNodeIds).toEqual(["mem-preference", "mem-lesson"]);
    } finally {
      database.close();
    }
  });

  test("applies only typed confirmed presentation defaults and preserves the reviewed Autonomous contract byte-for-byte", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      operatorPreferenceProfile(database, {
        id: "mem-autonomy-presentation",
        preferenceKey: "autonomy.default_posture",
        value: {
          posture: "high_autonomy",
          boundary: "signed_contract_and_platform_policy",
        },
        appliesTo: ["autonomy_presentation"],
      });
      operatorPreferenceProfile(database, {
        id: "mem-readable-technical",
        preferenceKey: "communication.technical_readability",
        value: {
          style: "technical_readable",
          avoid: ["oversimplified wording", "opaque internal jargon"],
          include: ["purpose", "operational meaning", "useful technical detail"],
        },
        appliesTo: ["guided_explanations", "evidence_presentation", "reports"],
      });
      operatorPreferenceProfile(database, {
        id: "mem-evidence-first",
        preferenceKey: "communication.evidence_first",
        value: {
          structure: [
            "observation",
            "meaning",
            "confidence",
            "uncertainty",
            "next justified action",
          ],
          rawLogs: "not_automatically_evidence",
        },
        appliesTo: ["evidence_presentation", "guided_explanations", "reports"],
      });
      const vault = connectHealthyTestVault(database, [
        "mem-autonomy-presentation",
        "mem-readable-technical",
        "mem-evidence-first",
      ]);
      const request = autonomousRequest({
        contract: {
          ...autonomousRequest().contract,
          memoryScopes: ["confirmed_preferences"],
          // The lifecycle resolver must seed these confirmed profiles even
          // when the signed exact selection is deliberately empty.
          contextNodeIds: [],
        },
      });
      const expectedHash = autonomousContractHash(request);
      const created = await service(
        database,
        [provider()],
        undefined,
        undefined,
        undefined,
        undefined,
        vault.resolveExistingVaultPath,
      ).create(
        request,
        "autonomous-applied-intake-preferences-0001",
        "operator-1",
      );

      expect(created.intakeContext).toMatchObject({
        status: "ready",
        retrievedCount: 3,
        memoryInfluencedDefaults: true,
        safeOptionalDefaults: {
          autonomyPresentation: "high_autonomy",
          explanationTemplate: "technical_readable",
          reportTemplate: "evidence_first",
          safetyBoundary: "presentation_only_contract_unchanged",
        },
      });
      expect(created.intakeContext?.influenceExplanation).toContain(
        "Authorization, targets, action permissions, budgets, evidence rules",
      );

      const persisted = database.prepare(`
        SELECT m.name, m.objective, m.scope_json, m.success_criteria_json,
          m.memory_policy_json,
          mc.contract_hash, mc.action_policy_json, mc.budgets_json,
          mc.safe_stop_json, mc.deliverables_json
        FROM missions m
        JOIN runs r ON r.mission_id = m.id
        JOIN mission_contracts mc ON mc.id = r.contract_id
        WHERE m.id = ?
      `).get(created.mission.id) as Record<string, string>;
      expect(persisted.name).toBe(request.title);
      expect(persisted.objective).toBe(request.objective);
      expect(JSON.parse(persisted.scope_json)).toEqual({
        allowedTargets: request.authorization.allowedTargets,
        prohibitedTargets: request.authorization.prohibitedTargets,
        timeWindow: request.authorization.timeWindow,
        dataHandling: request.authorization.dataHandling,
      });
      expect(JSON.parse(persisted.success_criteria_json)).toEqual(request.successCriteria);
      expect(JSON.parse(persisted.memory_policy_json).intakeContext).toMatchObject({
        memoryInfluencedDefaults: true,
        safeOptionalDefaults: {
          autonomyPresentation: "high_autonomy",
          explanationTemplate: "technical_readable",
          reportTemplate: "evidence_first",
          safetyBoundary: "presentation_only_contract_unchanged",
        },
      });
      expect(persisted.contract_hash).toBe(expectedHash);
      expect(JSON.parse(persisted.action_policy_json)).toMatchObject({
        allowedActionClasses: request.contract.allowedActionClasses,
        prohibitedActionClasses: request.contract.prohibitedActionClasses,
        destructivePolicy: request.contract.destructivePolicy,
        providerPolicy: request.contract.providerPolicy,
        toolPolicy: request.contract.toolPolicy,
      });
      expect(JSON.parse(persisted.budgets_json)).toMatchObject({
        timeBudgetMinutes: request.contract.timeBudgetMinutes,
        toolCalls: request.contract.toolCallBudget,
        retryBudget: request.contract.retryBudget,
        replanBudget: request.contract.replanBudget,
        concurrencyLimit: request.contract.concurrencyLimit,
      });
      expect(JSON.parse(persisted.safe_stop_json)).toEqual({
        conditions: request.contract.safeStopConditions,
      });
      expect(JSON.parse(persisted.deliverables_json)).toEqual(request.contract.deliverables);

      const dispositions = database.prepare(`
        SELECT node_id, used, influence_summary, ignored_reason
        FROM memory_context_items WHERE context_pack_id = ? ORDER BY node_id
      `).all(created.intakeContext?.contextPackId) as Array<{
        node_id: string;
        used: number;
        influence_summary: string | null;
        ignored_reason: string | null;
      }>;
      expect(dispositions).toHaveLength(3);
      expect(dispositions.every(({ used }) => used === 1)).toBe(true);
      expect(dispositions.every(({ influence_summary }) =>
        influence_summary?.includes("unchanged") === true)).toBe(true);
      expect(dispositions.every(({ ignored_reason }) => ignored_reason === null)).toBe(true);

      const event = database.prepare(`
        SELECT payload_json FROM events
        WHERE run_id = ? AND event_type = 'mission.created'
      `).get(created.run.id) as { payload_json: string };
      expect(JSON.parse(event.payload_json).intakeContext).toMatchObject({
        memoryInfluencedDefaults: true,
        safeOptionalDefaults: {
          safetyBoundary: "presentation_only_contract_unchanged",
        },
      });
    } finally {
      database.close();
    }
  });

  test("ignores free-form, malformed, and policy-affecting memory instead of weakening Autonomous authority", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      operatorPreferenceProfile(database, {
        id: "mem-policy-override-attempt",
        preferenceKey: "autonomy.action_permissions",
        value: {
          allowedActionClasses: ["destructive_data_system_modification"],
          authorizationConfirmed: true,
        },
        appliesTo: ["autonomy_presentation"],
      });
      operatorPreferenceProfile(database, {
        id: "mem-malformed-readable-template",
        preferenceKey: "communication.technical_readability",
        value: {
          style: "execute_everything",
          allowedTargets: ["0.0.0.0/0"],
        },
        appliesTo: ["reports"],
      });
      memoryNode(database, {
        id: "mem-free-form-preference",
        nodeType: "preference",
        scope: { kind: "global" },
        status: "confirmed",
      });
      const selectedNodeIds = [
        "mem-policy-override-attempt",
        "mem-malformed-readable-template",
        "mem-free-form-preference",
      ];
      const request = autonomousRequest({
        contract: {
          ...autonomousRequest().contract,
          memoryScopes: ["confirmed_preferences"],
          contextNodeIds: selectedNodeIds,
        },
      });
      const created = await service(database).create(
        request,
        "autonomous-rejected-intake-preferences-0001",
        "operator-1",
      );

      expect(created.intakeContext).toMatchObject({
        status: "ready",
        retrievedCount: 3,
        memoryInfluencedDefaults: false,
      });
      expect(created.intakeContext?.safeOptionalDefaults).toBeUndefined();
      expect(created.intakeContext?.influenceExplanation).toBeUndefined();
      const contract = database.prepare(`
        SELECT mc.contract_hash, mc.action_policy_json
        FROM runs r JOIN mission_contracts mc ON mc.id = r.contract_id
        WHERE r.id = ?
      `).get(created.run.id) as { contract_hash: string; action_policy_json: string };
      expect(contract.contract_hash).toBe(autonomousContractHash(request));
      expect(JSON.parse(contract.action_policy_json)).toMatchObject({
        allowedActionClasses: request.contract.allowedActionClasses,
        prohibitedActionClasses: request.contract.prohibitedActionClasses,
        destructivePolicy: "prohibited",
        providerPolicy: "automatic_enforcing_only",
        toolPolicy: "contract_allowlist",
      });
      const dispositions = database.prepare(`
        SELECT node_id, used, influence_summary, ignored_reason
        FROM memory_context_items WHERE context_pack_id = ? ORDER BY node_id
      `).all(created.intakeContext?.contextPackId) as Array<{
        node_id: string;
        used: number;
        influence_summary: string | null;
        ignored_reason: string | null;
      }>;
      expect(dispositions).toHaveLength(3);
      expect(dispositions.every(({ used }) => used === 0)).toBe(true);
      expect(dispositions.every(({ influence_summary }) => influence_summary === null)).toBe(true);
      expect(dispositions.every(({ ignored_reason }) =>
        (ignored_reason?.length ?? 0) > 20)).toBe(true);
    } finally {
      database.close();
    }
  });

  test("previews taxonomy-backed attack knowledge and excludes ineligible reusable context", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const attackConfirmedId = "mem_11111111111111111111111111111111";
      const hazardVerifiedId = "mem_22222222222222222222222222222222";
      const foreignMemoryId = "mem-foreign-lesson";
      const restrictedFailureId = "mem_44444444444444444444444444444444";
      const staleRecoveryId = "mem_55555555555555555555555555555555";
      const autonomousDisabledId = "mem_66666666666666666666666666666666";
      const clockExpiredId = "mem_77777777777777777777777777777777";
      memoryNode(database, {
        id: attackConfirmedId,
        nodeType: "attack_procedure",
        scope: { kind: "global" },
        status: "confirmed",
      });
      memoryNode(database, {
        id: hazardVerifiedId,
        nodeType: "operational_hazard",
        scope: { kind: "global" },
        status: "verified",
      });
      memoryNode(database, {
        id: foreignMemoryId,
        nodeType: "lesson",
        scope: { kind: "engagement", engagementId: "other-engagement" },
        status: "verified",
      });
      memoryNode(database, {
        id: restrictedFailureId,
        nodeType: "failure_mode",
        scope: { kind: "global" },
        status: "verified",
        sensitivity: "restricted",
      });
      memoryNode(database, {
        id: staleRecoveryId,
        nodeType: "recovery_pattern",
        scope: { kind: "global" },
        status: "stale",
      });
      memoryNode(database, {
        id: autonomousDisabledId,
        nodeType: "attack_lesson",
        scope: { kind: "global" },
        status: "verified",
        allowAutonomous: false,
      });
      memoryNode(database, {
        id: clockExpiredId,
        nodeType: "attack_procedure",
        scope: { kind: "global" },
        status: "confirmed",
        expiresAt: "2030-01-01T00:00:00.000Z",
      });
      memoryNode(database, {
        id: "mem-operational-not-reusable",
        nodeType: "mission",
        scope: { kind: "global" },
        status: "verified",
      });

      const selectedIds = [
        attackConfirmedId,
        hazardVerifiedId,
        foreignMemoryId,
        restrictedFailureId,
        staleRecoveryId,
        autonomousDisabledId,
        clockExpiredId,
        "mem-operational-not-reusable",
      ];
      const request = autonomousRequest({
        contract: {
          ...autonomousRequest().contract,
          memoryScopes: [
            "confirmed_preferences",
            "verified_lessons",
            "confirmed_attack_knowledge",
            "verified_attack_knowledge",
            "engagement_memory",
          ],
          contextNodeIds: selectedIds,
        },
      });
      const preview = new MissionRepository(
        database,
        () => new Date("2031-01-01T00:00:00.000Z"),
      ).autonomousContextPreview(request);

      expect(preview.candidates.map(({ id }) => id).sort()).toEqual([
        attackConfirmedId,
        hazardVerifiedId,
      ].sort());
      expect(preview.candidates).toEqual(expect.arrayContaining([
        expect.objectContaining({
          id: attackConfirmedId,
          nodeType: "attack_procedure",
          lifecycleStatus: "confirmed",
        }),
        expect.objectContaining({
          id: hazardVerifiedId,
          nodeType: "operational_hazard",
          lifecycleStatus: "verified",
          scope: { kind: "global" },
        }),
      ]));
      expect(preview.selectedNodeIds).toEqual([
        attackConfirmedId,
        hazardVerifiedId,
      ]);
      expect(preview.invalidSelectedNodeIds).toEqual([
        foreignMemoryId,
        restrictedFailureId,
        staleRecoveryId,
        autonomousDisabledId,
        clockExpiredId,
        "mem-operational-not-reusable",
      ]);
    } finally {
      database.close();
    }
  });

  test("inspects real provider, MCP, and specialist policy then rejects an incompatible signed pool", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const missionService = service(database);
      const now = new Date().toISOString();
      database.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, provider_policy_json, tool_policy_json,
          configuration_json, version, last_heartbeat_at, created_at, updated_at
        ) VALUES (
          'Commander', 'mission orchestration', 'Commander', 'available',
          '{"defaultProvider":"xai-grok-oauth"}',
          '{"allowedTools":[],"deniedTools":[],"approvalRequiredTools":[]}',
          '{"userFacing":true,"productAgent":true,"orchestrationAgent":true,"executionAuthority":"none"}',
          '2.4', ?, ?, ?
        )
      `).run(now, now, now);
      const preview = await missionService.preflightAutonomous(autonomousRequest());
      expect(preview.readiness.status).toBe("ready");
      expect(preview.execution.providers).toEqual([
        expect.objectContaining({
          id: "xai-grok-oauth",
          authenticated: true,
          enforcesAutonomousBoundary: true,
          compatible: true,
        }),
      ]);
      expect(preview.execution.tools).toEqual([
        expect.objectContaining({
          id: "mcp:nmap",
          status: "healthy",
          assignedAgentIds: ["agent-recon"],
          capabilities: ["nmap"],
        }),
      ]);
      expect(preview.execution.team).toMatchObject({
        selectedAgentIds: ["agent-recon"],
        invalidSelectedAgentIds: [],
        effectiveAgentIds: ["agent-recon"],
      });
      expect(preview.execution.team.candidates).toEqual([
        expect.objectContaining({
          id: "agent-recon",
          compatible: true,
          runnableTools: ["nmap"],
          providerPolicy: { defaultProvider: "xai-grok-oauth" },
        }),
      ]);

      database.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, provider_policy_json, tool_policy_json,
          configuration_json, version, last_heartbeat_at, created_at, updated_at
        ) VALUES (
          'specialist:internal-recon-adapter',
          'runtime adapter',
          'Internal recon adapter',
          'available',
          '{"defaultProvider":"xai-grok-oauth"}',
          '{"allowedTools":["nmap"],"deniedTools":[],"approvalRequiredTools":[]}',
          '{"userFacing":false,"internalComponent":true}',
          '2.4',
          datetime('now'),
          datetime('now'),
          datetime('now')
        )
      `).run();
      database.prepare(`
        INSERT INTO agent_capabilities (
          agent_id, capability, source, enabled, metadata_json
        ) VALUES (
          'specialist:internal-recon-adapter',
          'nmap',
          'live-route-attestation',
          1,
          ?
        )
      `).run(JSON.stringify({
        validUntil: new Date(Date.now() + 5 * 60_000).toISOString(),
        executionBinding: "reviewed_local_process",
        executionJourneys: ["autonomous"],
        actionClassId: "active_host_discovery",
        toolId: "nmap",
      }));
      database.prepare(`
        UPDATE agents SET configuration_json = ?
        WHERE id = 'agent-recon'
      `).run(JSON.stringify({
        userFacing: true,
        productAgent: true,
        runtimeBindingAgentIds: ["specialist:internal-recon-adapter"],
      }));
      database.prepare(`
        UPDATE mcp_servers SET policy_json = ?
        WHERE id = 'mcp:nmap'
      `).run(JSON.stringify({
        enabled: true,
        assignedAgents: ["specialist:internal-recon-adapter"],
        startPermitted: true,
        riskClass: "medium",
      }));

      const internalAdapterHidden = await missionService.preflightAutonomous(autonomousRequest());
      expect(internalAdapterHidden.readiness.status).toBe("ready");
      expect(internalAdapterHidden.execution.tools).toEqual([
        expect.objectContaining({
          id: "mcp:nmap",
          assignedAgentIds: ["agent-recon"],
          capabilities: ["nmap"],
        }),
      ]);
      expect(internalAdapterHidden.execution.team.candidates.map(({ id }) => id))
        .toEqual(["agent-recon"]);
      expect(internalAdapterHidden.execution.team.recommendedAgentIds)
        .toEqual(["agent-recon"]);

      const unknown = await missionService.preflightAutonomous(autonomousRequest({
        contract: { ...autonomousRequest().contract, specialistAgentIds: ["agent-unknown"] },
      }));
      expect(unknown.readiness.status).toBe("blocked");
      expect(unknown.contract.hash).not.toBe(preview.contract.hash);
      expect(unknown.execution.team.invalidSelectedAgentIds).toEqual(["agent-unknown"]);
      expect(unknown.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_specialist_selection",
        status: "fail",
      }));

      database.prepare("UPDATE mcp_servers SET status = 'offline' WHERE id = 'mcp:nmap'").run();
      const unavailable = await missionService.preflightAutonomous(autonomousRequest());
      expect(unavailable.readiness.status).toBe("blocked");
      expect(unavailable.execution.team.invalidSelectedAgentIds).toEqual(["agent-recon"]);
      expect(unavailable.execution.team.candidates[0]).toMatchObject({
        compatible: false,
        runnableTools: [],
      });
    } finally {
      database.close();
    }
  });

  test("never recommends a specialist whose live model assignment cannot be resolved", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const now = new Date().toISOString();
      const validUntil = new Date(Date.now() + 5 * 60_000).toISOString();
      const missionService = service(database);
      database.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, provider_policy_json, tool_policy_json,
          configuration_json, version, last_heartbeat_at, created_at, updated_at
        ) VALUES (
          'agent-without-model',
          'reconnaissance',
          'No-model specialist',
          'available',
          '{"defaultProvider":"xai-grok-oauth"}',
          '{"allowedTools":["nmap"],"deniedTools":[],"approvalRequiredTools":[]}',
          '{"userFacing":true,"productAgent":true}',
          '2.4',
          ?,
          ?,
          ?
        )
      `).run(now, now, now);
      database.prepare(`
        INSERT INTO agent_capabilities (
          agent_id, capability, source, enabled, metadata_json
        ) VALUES (
          'agent-without-model',
          'nmap',
          'live-route-attestation',
          1,
          ?
        )
      `).run(JSON.stringify({
        validUntil,
        attestedAt: now,
        providerIds: ["xai-grok-oauth"],
      }));
      database.prepare(`
        UPDATE mcp_servers SET policy_json = ?
        WHERE id = 'mcp:nmap'
      `).run(JSON.stringify({
        enabled: true,
        assignedAgents: ["agent-recon", "agent-without-model"],
        startPermitted: true,
        riskClass: "medium",
      }));

      const preflight = await missionService.preflightAutonomous(
        autonomousRequest(),
      );
      const unavailable = preflight.execution.team.candidates.find(
        ({ id }) => id === "agent-without-model",
      );
      expect(unavailable).toMatchObject({
        compatible: false,
        runnableTools: ["nmap"],
      });
      expect(unavailable?.incompatibilityReasons).toContain(
        "The live model catalog could not verify an executable configuration for this specialist.",
      );
      expect(preflight.execution.team.recommendedAgentIds).toEqual([
        "agent-recon",
      ]);
      expect(preflight.execution.team.invalidSelectedAgentIds).toEqual([]);
      expect(preflight.execution.team.effectiveAgentIds).toEqual([
        "agent-recon",
      ]);
    } finally {
      database.close();
    }
  });

  test("preflight requires an exact disposable-lab boundary and verified attack memory for exploit validation", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const missionService = service(database);
      const ordinaryHost = autonomousRequest({
        authorization: {
          ...autonomousRequest().authorization,
          environmentClassification: "internal",
          allowedTargets: ["10.129.39.191"],
          prohibitedTargets: [],
        },
        contract: {
          ...autonomousRequest().contract,
          allowedActionClasses: ["exploit_validation"],
          destructivePolicy: "prohibited",
          memoryScopes: ["verified_lessons"],
        },
      });
      const blocked = await missionService.preflightAutonomous(ordinaryHost);
      expect(blocked.readiness.checks).toEqual(expect.arrayContaining([
        expect.objectContaining({
          id: "contract_exploit_disposable_lab_boundary",
          status: "fail",
        }),
        expect.objectContaining({
          id: "contract_exploit_verified_attack_memory",
          status: "fail",
        }),
      ]));

      const disposableLab = autonomousRequest({
        authorization: {
          ...autonomousRequest().authorization,
          environmentClassification: "htb",
          allowedTargets: ["10.129.39.191"],
          prohibitedTargets: [],
        },
        contract: {
          ...autonomousRequest().contract,
          allowedActionClasses: ["exploit_validation"],
          destructivePolicy: "bounded_lab_only",
          boundedDestructiveTargets: ["10.129.39.191"],
          memoryScopes: ["verified_attack_knowledge"],
        },
      });
      const eligible = await missionService.preflightAutonomous(disposableLab);
      expect(eligible.readiness.checks).toEqual(expect.arrayContaining([
        expect.objectContaining({
          id: "contract_exploit_disposable_lab_boundary",
          status: "pass",
        }),
        expect.objectContaining({
          id: "contract_exploit_verified_attack_memory",
          status: "pass",
        }),
        expect.objectContaining({
          id: "contract_attack_memory_vault",
          status: "fail",
        }),
      ]));
      expect(eligible.readiness.status).toBe("blocked");

      const vault = connectHealthyTestVault(database, []);
      const vaultReady = await service(
        database,
        [provider()],
        undefined,
        undefined,
        undefined,
        undefined,
        vault.resolveExistingVaultPath,
      ).preflightAutonomous(disposableLab);
      expect(vaultReady.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_attack_memory_vault",
        status: "pass",
      }));
      expect(vaultReady.readiness.status).toBe("ready");
    } finally {
      database.close();
    }
  });

  test("blocks a material access objective when a direct contract silently omits its criteria or execution classes", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const missionService = service(database);
      const silentlyReduced = autonomousRequest({
        objective:
          "Prove user/root access and capture the user and root flags on the authorized lab host.",
      });
      const blocked = await missionService.preflightAutonomous(silentlyReduced);
      expect(blocked.outcome.id).toBe("complete_engagement");
      expect(blocked.readiness.status).toBe("blocked");
      expect(blocked.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_autonomous_outcome",
        status: "fail",
      }));
      expect(blocked.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_material_objective_coverage",
        status: "fail",
        remediation: expect.stringContaining(
          "Reconnaissance alone cannot satisfy",
        ),
      }));
      const coverage = blocked.readiness.checks.find(
        ({ id }) => id === "contract_material_objective_coverage",
      );
      expect(coverage?.impact).toContain("Missing evidence-backed success criteria");
      expect(coverage?.impact).toContain("Missing pre-authorized action classes");

      const represented = autonomousRequest({
        objective:
          "Prove user/root access and capture the user and root flags on the authorized lab host.",
        successCriteria: [
          ...AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
        ],
        authorization: {
          ...autonomousRequest().authorization,
          environmentClassification: "htb",
          allowedTargets: ["10.129.39.191"],
          prohibitedTargets: [],
        },
        contract: {
          ...autonomousRequest().contract,
          allowedActionClasses: [
            ...AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS,
          ],
          destructivePolicy: "bounded_lab_only",
          boundedDestructiveTargets: ["10.129.39.191"],
          memoryScopes: ["verified_attack_knowledge"],
        },
      });
      const representedPreview = await missionService.preflightAutonomous(
        represented,
      );
      expect(representedPreview.outcome).toMatchObject({
        id: "complete_engagement",
        label: "Complete Autonomous Engagement",
        requiredTerminalSuccessCriteria:
          AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
        requiredActionClassIds:
          AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS,
      });
      expect(representedPreview.readiness.checks).toContainEqual(
        expect.objectContaining({
          id: "contract_autonomous_outcome",
          status: "pass",
        }),
      );
      expect(representedPreview.readiness.checks).toContainEqual(
        expect.objectContaining({
          id: "contract_material_objective_coverage",
          status: "pass",
        }),
      );
    } finally {
      database.close();
    }
  });

  test("blocks required evidence that has no available runtime producer without rewriting the draft", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const missionService = service(
        database,
        [provider()],
        undefined,
        evidenceRuntimeManifests,
      );
      const supportedRequest = autonomousRequest({
        contract: {
          ...autonomousRequest().contract,
          evidenceRequirements: ["port_service_scan_result"],
        },
      });
      const supported = await missionService.preflightAutonomous(supportedRequest);
      expect(supported.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_evidence_capability",
        status: "pass",
      }));

      const impossibleRequest = autonomousRequest({
        contract: {
          ...autonomousRequest().contract,
          evidenceRequirements: [
            "port_service_scan_result",
            "os_platform_fingerprint",
            "dns_certificate_record",
          ],
        },
      });
      const blocked = await missionService.preflightAutonomous(impossibleRequest);
      expect(blocked.readiness.status).toBe("blocked");
      expect(impossibleRequest.contract.evidenceRequirements).toEqual([
        "port_service_scan_result",
        "os_platform_fingerprint",
        "dns_certificate_record",
      ]);
      expect(blocked.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_evidence_capability",
        status: "fail",
        impact: expect.stringContaining("OS, kernel, or platform fingerprint (unsupported)"),
        remediation: expect.stringContaining("Verified findings still require their immutable evidence"),
      }));
      expect(blocked.readiness.checks.find(({ id }) => id === "contract_evidence_capability")?.impact)
        .toContain("DNS or certificate record (unavailable)");
      await expect(missionService.create(
        { ...impossibleRequest, contractReview: blocked.contract },
        "unsupported-evidence-contract-001",
        "operator-1",
      )).rejects.toBeInstanceOf(AutonomousReadinessError);
    } finally {
      database.close();
    }
  });

  test("excludes approval-required tools from Autonomous readiness and blocks an approval-only specialist", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const missionService = service(database);
      database.prepare(`
        UPDATE agents SET tool_policy_json = ? WHERE id = 'agent-recon'
      `).run(JSON.stringify({
        allowedTools: ["nmap"],
        deniedTools: [],
        approvalRequiredTools: ["nmap"],
      }));

      const preview = await missionService.preflightAutonomous(autonomousRequest());
      expect(preview.readiness.status).toBe("blocked");
      expect(preview.execution.tools).toEqual([]);
      expect(preview.execution.team.candidates).toEqual([
        expect.objectContaining({
          id: "agent-recon",
          compatible: false,
          runnableTools: [],
          incompatibilityReasons: [
            "No approval-free reviewed local-process or MCP tool binding is available for this tool-requiring contract.",
          ],
          toolPolicy: expect.objectContaining({ approvalRequiredTools: ["nmap"] }),
        }),
      ]);
      expect(preview.execution.team.invalidSelectedAgentIds).toEqual(["agent-recon"]);
      expect(preview.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_specialist_selection",
        status: "fail",
      }));
    } finally {
      database.close();
    }
  });

  test("creates a durable Guided mission without inventing an Autonomous contract", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const created = await service(database).create(
        guidedRequest(),
        "guided-request-0000001",
        "operator-1",
      );
      expect(created.run).toEqual({
        id: created.run.id,
        journey: "guided",
        status: "planning",
      });
      expect(created.nextUrl).toBe(`/guided/${created.mission.id}`);
      expect(count(database, "mission_contracts")).toBe(0);
      expect(count(database, "mission_targets")).toBe(1);
      expect(count(database, "mission_constraints")).toBe(1);
      const mission = database
        .prepare("SELECT authorization_status FROM missions WHERE id = ?")
        .get(created.mission.id) as { authorization_status: string };
      expect(mission.authorization_status).toBe("verified");
    } finally {
      database.close();
    }
  });

  test("retrieves and binds a scope-safe intake Context Pack without claiming it changed defaults", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      new MemoryRepository(database).createNode({
        id: "mem-guided-intake-preference",
        nodeType: "preference",
        title: "Guided lab assessment explanation preference",
        summary: "Use a concise explanation after the operator confirms the preference.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "confirmed",
        confirmationState: "confirmed",
        provenance: {
          method: "operator_statement",
          explanation: "Confirmed by the operator in the intake lifecycle fixture.",
          sources: [{ sourceType: "test", sourceId: "guided-intake", acquiredAt: new Date().toISOString() }],
        },
        authorType: "operator",
        authorId: "operator-1",
        retentionPolicy: { allowGuided: true },
      });
      const created = await service(database).create(
        guidedRequest(),
        "guided-intake-context-0001",
        "operator-1",
      );
      expect(created.intakeContext).toMatchObject({
        hook: "intake",
        status: "ready",
        retrievedCount: 1,
        memoryInfluencedDefaults: false,
      });
      if (!created.intakeContext) throw new Error("Expected a durable intake Context Pack binding");
      const policy = database.prepare("SELECT memory_policy_json FROM missions WHERE id = ?")
        .get(created.mission.id) as { memory_policy_json: string };
      expect(JSON.parse(policy.memory_policy_json).intakeContext).toMatchObject({
        contextPackId: created.intakeContext.contextPackId,
        status: "ready",
        memoryInfluencedDefaults: false,
      });
      const disposition = database.prepare(`
        SELECT used, ignored_reason FROM memory_context_items
        WHERE context_pack_id = ? AND node_id = 'mem-guided-intake-preference'
      `).get(created.intakeContext.contextPackId) as { used: number; ignored_reason: string };
      expect(disposition.used).toBe(0);
      expect(disposition.ignored_reason).toContain("defaults remained deterministic");
      const createdEvent = database.prepare(`
        SELECT context_pack_id, payload_json FROM events
        WHERE run_id = ? AND event_type = 'mission.created'
      `).get(created.run.id) as { context_pack_id: string | null; payload_json: string };
      expect(createdEvent.context_pack_id).toBe(created.intakeContext.contextPackId);
      expect(JSON.parse(createdEvent.payload_json).intakeContext).toMatchObject({
        status: "ready",
        memoryInfluencedDefaults: false,
      });
      const missionAudit = database.prepare(`
        SELECT details_json FROM audit_records
        WHERE mission_id = ? AND action = 'mission.created'
      `).get(created.mission.id) as { details_json: string };
      expect(JSON.parse(missionAudit.details_json).intakeContext).toMatchObject({
        contextPackId: created.intakeContext.contextPackId,
        status: "ready",
      });
    } finally {
      database.close();
    }
  });

  test("continues Guided intake with an audited empty degraded Context Pack when the Brain is unavailable", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const created = await service(database, [provider()], () => ({
        available: false,
        code: "brain_offline",
        explanation: "The local Second Brain index is offline.",
      })).create(guidedRequest(), "guided-intake-degraded-0001", "operator-1");
      expect(created.intakeContext).toMatchObject({
        status: "degraded",
        retrievedCount: 0,
        memoryInfluencedDefaults: false,
        degradation: { code: "brain_offline" },
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM memory_context_items WHERE context_pack_id = ?
      `).get(created.intakeContext?.contextPackId)).toEqual({ count: 0 });
      const hookAudit = database.prepare(`
        SELECT details_json FROM audit_records WHERE id = ?
      `).get(created.intakeContext?.auditRecordId) as { details_json: string };
      expect(JSON.parse(hookAudit.details_json)).toMatchObject({
        hook: "intake",
        status: "degraded",
        contextPackId: created.intakeContext?.contextPackId,
        dependencyCode: "brain_offline",
      });
    } finally {
      database.close();
    }
  });

  test("blocks a signed-memory Autonomous launch at preflight before mission or context persistence", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const missionService = service(database, [provider()], () => ({
        available: false,
        code: "brain_offline",
        explanation: "The local Second Brain index is offline.",
      }));
      const preflight = await missionService.preflightAutonomous(
        autonomousRequest(),
      );
      expect(preflight.readiness.status).toBe("blocked");
      expect(preflight.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_memory_runtime",
        status: "fail",
      }));
      const action = missionService.create(
        autonomousRequest(),
        "autonomous-intake-required-0001",
        "operator-1",
      );
      await expect(action).rejects.toBeInstanceOf(AutonomousReadinessError);
      expect(count(database, "missions")).toBe(0);
      expect(count(database, "runs")).toBe(0);
      expect(count(database, "memory_context_packs")).toBe(0);
      const receiptCount = database.prepare(`
        SELECT COUNT(*) AS count
        FROM audit_records WHERE action = 'mission.intake_context.blocked'
      `).get();
      expect(receiptCount).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("persists truthful degraded Autonomous intake when the signed contract selected no memory", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const request = autonomousRequest({
        contract: {
          ...autonomousRequest().contract,
          memoryScopes: [],
          contextNodeIds: [],
        },
      });
      const created = await service(database, [provider()], () => ({
        available: false,
        code: "brain_offline",
        explanation: "The local Second Brain index is offline.",
      })).create(request, "autonomous-intake-empty-0001", "operator-1");
      expect(created.intakeContext).toMatchObject({
        status: "degraded",
        retrievedCount: 0,
        memoryInfluencedDefaults: false,
      });
      expect(created.run.status).toBe("planning");
    } finally {
      database.close();
    }
  });

  test("blocks Autonomous launch on a real failed readiness check without partial writes", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const action = service(database, [provider("fail")]).create(
        autonomousRequest(),
        "blocked-request-00001",
        "operator-1",
      );
      await expect(action).rejects.toBeInstanceOf(AutonomousReadinessError);
      expect(count(database, "missions")).toBe(0);
      expect(count(database, "runs")).toBe(0);
      expect(count(database, "settings")).toBe(0);
    } finally {
      database.close();
    }
  });

  test("replays one successful idempotent mutation and rejects key reuse with a different contract", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      let checks = 0;
      const dynamicProvider: ReadinessCheckProvider = {
        ...provider(),
        evaluate: () => {
          checks += 1;
          return provider(checks === 1 ? "pass" : "fail").evaluate({});
        },
      };
      const missionService = service(database, [dynamicProvider]);
      const first = await missionService.create(
        autonomousRequest(),
        "stable-request-key-001",
        "operator-1",
      );
      const replay = await missionService.create(
        autonomousRequest(),
        "stable-request-key-001",
        "operator-1",
      );
      expect(replay).toEqual(first);
      expect(checks).toBe(1);
      expect(count(database, "missions")).toBe(1);
      expect(count(database, "events")).toBe(2);
      await expect(
        missionService.create(
          autonomousRequest({ title: "Different mission" }),
          "stable-request-key-001",
          "operator-1",
        ),
      ).rejects.toBeInstanceOf(IdempotencyConflictError);
    } finally {
      database.close();
    }
  });

  test("materializes the run anchor inside mission commit and defers replay repair failures", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      class FailureInjectingGraph extends CanonicalMissionMemoryGraph {
        failRun = false;

        override ensureRun(runId: string) {
          if (this.failRun) throw new Error("injected canonical graph failure");
          return super.ensureRun(runId);
        }
      }
      const graph = new FailureInjectingGraph(database);
      const projected: string[][] = [];
      const missionService = service(
        database,
        [provider()],
        undefined,
        undefined,
        graph,
        (nodeIds) => projected.push([...nodeIds]),
      );
      const first = await missionService.create(
        guidedRequest(),
        "guided-graph-atomic-0001",
        "operator-1",
      );
      expect(count(database, "missions")).toBe(1);
      expect(count(database, "runs")).toBe(1);
      expect(count(database, "memory_nodes")).toBe(2);
      expect(count(database, "memory_edges")).toBe(1);
      expect(projected).toHaveLength(1);

      graph.failRun = true;
      const replay = await missionService.create(
        guidedRequest(),
        "guided-graph-atomic-0001",
        "operator-1",
      );
      expect(replay).toEqual(first);
      expect(count(database, "missions")).toBe(1);
      expect(count(database, "runs")).toBe(1);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE mission_id = ? AND run_id = ?
          AND action = 'memory.canonical_graph_reconciliation_deferred'
      `).get(first.mission.id, first.run.id)).toEqual({ count: 1 });

      const failingDatabase = createDatabaseConnection({ filename: ":memory:" });
      try {
        migrateDatabase(failingDatabase);
        const failingGraph = new FailureInjectingGraph(failingDatabase);
        failingGraph.failRun = true;
        const action = service(
          failingDatabase,
          [provider()],
          undefined,
          undefined,
          failingGraph,
        ).create(guidedRequest(), "guided-graph-atomic-0002", "operator-1");
        await expect(action).rejects.toThrow("injected canonical graph failure");
        expect(count(failingDatabase, "missions")).toBe(0);
        expect(count(failingDatabase, "runs")).toBe(0);
        expect(count(failingDatabase, "memory_nodes")).toBe(0);
        expect(count(failingDatabase, "memory_context_packs")).toBe(0);
      } finally {
        failingDatabase.close();
      }
    } finally {
      database.close();
    }
  });

  test("rolls back the entire aggregate when durable event delivery cannot be recorded", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      database.exec(`
        CREATE TRIGGER reject_mission_outbox
        BEFORE INSERT ON event_outbox BEGIN
          SELECT RAISE(ABORT, 'mission outbox unavailable');
        END;
      `);
      await service(database)
        .create(autonomousRequest(), "rollback-request-001", "operator-1")
        .catch((error: unknown) => expect(String(error)).toContain("mission outbox unavailable"));
      for (const table of [
        "missions",
        "runs",
        "mission_targets",
        "mission_constraints",
        "mission_contracts",
        "events",
        "audit_records",
        "settings",
      ]) {
        expect(count(database, table)).toBe(0);
      }
    } finally {
      database.close();
    }
  });

  test("paginates missions with opaque cursors and returns real overview state", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const missionService = service(database, [provider("warn")]);
      await missionService.create(guidedRequest({ title: "Mission A" }), "page-request-0001", "operator");
      await missionService.create(guidedRequest({ title: "Mission B" }), "page-request-0002", "operator");
      await missionService.create(guidedRequest({ title: "Mission C" }), "page-request-0003", "operator");

      const first = missionService.list({ limit: 2 });
      expect(first.items).toHaveLength(2);
      expect(first.nextCursor).not.toBeNull();
      const second = missionService.list({ limit: 2, cursor: first.nextCursor! });
      expect(second.items).toHaveLength(1);
      expect(second.nextCursor).toBeNull();
      expect(new Set([...first.items, ...second.items].map((mission) => mission.id)).size).toBe(3);

      const overview = await missionService.getOverview();
      expect(overview.schemaVersion).toBe("2.4");
      expect(overview.readiness).toMatchObject({ status: "degraded", score: 65 });
      expect(overview.summary.activeMissions).toBe(3);
      expect(overview.missions).toHaveLength(3);
      expect(overview.system.database).toBe("healthy");
      expect(overview.system.providers).toBe("healthy");
      expect(overview.agents).toEqual([{
        id: "agent-recon",
        name: "Recon specialist",
        status: "available",
      }]);
    } finally {
      database.close();
    }
  });
});

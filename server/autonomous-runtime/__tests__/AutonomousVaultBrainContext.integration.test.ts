import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { RuntimeProjectionInput } from "../../app/RuntimeProjectionService";
import {
  BrainContextService,
  retrieveMissionBrainContext,
} from "../../brain-runtime";
import { commitPlanningContextAttribution } from "../../command-runtime/PlanningContextAttribution";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import { MemoryRepository, SecondBrainService } from "../../memory";
import { attackKnowledgeVaultSyncScope } from "../../vault/AttackKnowledgeVaultPreset";
import { ObsidianVaultBridge } from "../../vault/ObsidianVaultBridge";
import { VaultPathPolicy } from "../../vault/VaultPathPolicy";
import {
  LocalAutonomousContractPlanner,
  type LocalAutonomousPlanningPolicy,
} from "../index";

const NOW = new Date("2026-07-22T19:00:00.000Z");
const TARGET = "203.0.113.25";
const MISSION_ID = "mission-vault-memory-planning";
const RUN_ID = "run-vault-memory-planning";
const CONTRACT_ID = "contract-vault-memory-planning";
const MODEL_CONFIGURATION_HASH = "a".repeat(64);
const SEARCH_MARKER = "spectralcorroboration";
const FORGOTTEN_SEARCH_MARKER = "forgottenphasecalibration";
const CURRENT_ENGAGEMENT_ID = "engagement-vault-memory-current";
const OTHER_ENGAGEMENT_ID = "engagement-vault-memory-other";

const databases: SqliteDatabase[] = [];
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function setup(): {
  readonly directory: string;
  readonly database: SqliteDatabase;
  readonly memory: MemoryRepository;
  readonly brain: SecondBrainService;
  readonly brainContext: BrainContextService;
  readonly bridge: ObsidianVaultBridge;
  readonly connectionId: string;
  readonly vaultPath: string;
} {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-vault-core-proof-"));
  temporaryDirectories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "ti-scale.sqlite") });
  databases.push(database);
  migrateDatabase(database);
  const memory = new MemoryRepository(database, { clock: () => NOW });
  const brain = new SecondBrainService(memory);
  const vaultPaths = new VaultPathPolicy(join(directory, "allowed-vaults"));
  const bridge = new ObsidianVaultBridge(
    database,
    memory,
    vaultPaths,
    { clock: () => NOW },
  );
  const connection = bridge.connect({
    id: "vault-autonomous-core-proof",
    vaultPath: "Attack-Knowledge-Vault",
    displayName: "Ti-Scale Attack Knowledge Vault",
    syncScope: attackKnowledgeVaultSyncScope({ includeConfirmed: true }),
    permissionGranted: true,
  });
  bridge.refreshConnectionHealthProof(
    connection.id,
    "system:autonomous-core-proof-vault-health",
  );
  const brainContext = new BrainContextService({
    database,
    secondBrain: brain,
    resolveExistingVaultPath: (vaultPath) =>
      vaultPaths.resolveExistingVault(vaultPath),
    clock: () => NOW,
  });
  return {
    directory,
    database,
    memory,
    brain,
    brainContext,
    bridge,
    connectionId: connection.id,
    vaultPath: connection.vaultPath,
  };
}

function importAndConfirmAttackKnowledge(
  input: ReturnType<typeof setup>,
  options: Readonly<{
    key?: string;
    marker?: string;
    scope?: { readonly kind: "global" } | {
      readonly kind: "engagement";
      readonly engagementId: string;
    };
  }> = {},
) {
  const key = options.key ?? "eligible";
  const marker = options.marker ?? SEARCH_MARKER;
  const scope = options.scope ?? { kind: "global" as const };
  const template = input.memory.createNode({
    id: `mem_${createHash("sha256").update(`vault-template:${key}`).digest("hex")}`,
    nodeType: "attack_technique",
    title: "Generic evidence-gated technique review",
    summary: "Require current attributable observations before choosing a historical technique.",
    body: "Historical outcomes remain reference data until current prerequisites are independently corroborated.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.9,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: {
      method: "operator_statement",
      explanation: "Template used only to produce schema-valid Obsidian Markdown.",
      sources: [{
        sourceType: "message",
        sourceId: "vault-template-source",
        acquiredAt: NOW.toISOString(),
      }],
    },
    authorType: "operator",
    authorId: "operator-proof",
    retentionPolicy: { allowAutonomous: true, allowGuided: true },
  });
  const templateText = input.bridge.renderNode(template.id).text;
  const inboxRelativePath = `00 Inbox/version-corroboration-${key}.md`;
  const inboxPath = join(input.vaultPath, inboxRelativePath);
  const importedTitle = `Evidence-gated version corroboration ${key}`;
  const importedSummary = `Use ${marker} as a test-only retrieval marker for a product/version prerequisite guard.`;
  const importedBody = "Require current product, version, and prerequisite observations before considering historical technique outcomes. The retained note is reference data and grants no target, tool, scope, or authority.";
  let source = templateText
    .replace(
      `id: "${template.id}"`,
      `id: "mem_${createHash("sha256").update(`vault-import:${key}`).digest("hex")}"`,
    )
    .replaceAll(template.title, importedTitle)
    .replace(template.summary, importedSummary)
    .replace(template.body, importedBody);
  if (scope.kind === "engagement") {
    source = source.replace(
      'scope: "global"',
      `scope: "engagement"\nengagement_id: "${scope.engagementId}"`,
    );
  }
  writeFileSync(inboxPath, source, { encoding: "utf8", mode: 0o600 });

  const imported = input.bridge.importNote(
    input.connectionId,
    inboxRelativePath,
    "operator-proof",
  );
  expect(imported).toMatchObject({ status: "candidate", relativePath: inboxRelativePath });
  expect(imported.candidateId).toBeDefined();
  const node = input.brain.confirmCandidate(imported.candidateId!, "operator-proof");
  expect(node).toMatchObject({
    nodeType: "attack_technique",
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    scope,
    title: importedTitle,
  });
  expect(node.provenance).toMatchObject({
    method: "imported",
    sources: [{
      sourceType: "obsidian_note",
      sourceId: `${input.connectionId}:${inboxRelativePath}`,
    }],
  });

  const projection = input.bridge.exportNode(input.connectionId, node.id);
  expect(projection.status).toBe("synced");
  expect(existsSync(join(input.vaultPath, projection.relativePath))).toBe(true);
  expect(input.bridge.inspectManagedNote(input.connectionId, projection.relativePath).note.id)
    .toBe(node.id);
  return { node, projection };
}

function seedAutonomousContract(database: SqliteDatabase): void {
  const now = NOW.toISOString();
  const memoryPolicy = {
    exactContextNodeIds: [],
    allowedScopes: ["confirmed_attack_knowledge", "engagement_memory"],
  };
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      success_criteria_json, memory_policy_json, created_by, created_at, updated_at
    ) VALUES (?, 'Vault memory planning proof', ?, 'autonomous', 'active', 'verified', ?, ?, ?,
      'operator-proof', ?, ?)
  `).run(
    MISSION_ID,
    `Establish the authorized host baseline using ${SEARCH_MARKER} context where relevant`,
    CURRENT_ENGAGEMENT_ID,
    JSON.stringify(["The exact host reachability result is retained"]),
    JSON.stringify(memoryPolicy),
    now,
    now,
  );
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-vault-memory-proof', ?, ?, 'ip', 'allowed', ?, ?)
  `).run(MISSION_ID, TARGET, TARGET, now);
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
    specialistAgentIds: ["ReconScout"],
    contextNodeIds: [],
  };
  const contractHash = "c".repeat(64);
  database.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, '{"toolCalls":8}',
      '{"conditions":[]}', '[]', ?, 'operator-proof', ?, ?)
  `).run(
    CONTRACT_ID,
    MISSION_ID,
    contractHash,
    JSON.stringify(actionPolicy),
    JSON.stringify(memoryPolicy.allowedScopes),
    now,
    now,
  );
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, progress, status_reason,
      budget_json, budget_usage_json, started_at, created_at, updated_at, version
    ) VALUES (?, ?, 'autonomous', 'planning', ?, 0, 'Build the in-contract plan',
      '{"toolCalls":8}', '{}', ?, ?, ?, 1)
  `).run(RUN_ID, MISSION_ID, CONTRACT_ID, now, now, now);
}

function planningPolicy(): LocalAutonomousPlanningPolicy {
  return {
    schemaVersion: "ti-scale.local-autonomous-planning-policy.v1",
    policyId: "vault-core-proof-policy-v1",
    maximumSteps: 1,
    bindings: [{
      bindingId: "binding-vault-core-proof-v1",
      actionClassId: "active_host_discovery",
      targetKinds: ["ip"],
      phase: "Reachability baseline",
      title: "Confirm approved target reachability",
      objective: "Determine whether the approved target is reachable",
      explanation: "The reconnaissance specialist performs one bounded check against the exact approved target.",
      rationale: "Reachability is established before deeper service work.",
      successCriteria: ["An attributable reachability result is retained"],
      reversibility: "The probe makes no persistent target change.",
      riskClass: "medium",
      idempotent: false,
      destructive: false,
      agentId: "ReconScout",
      providerId: "provider-autonomous",
      modelId: "model-reviewed",
      modelConfigurationHash: MODEL_CONFIGURATION_HASH,
      mcpServerId: "specialist-mcp",
      toolName: "tool-active-host-discovery",
      targetParameter: "target",
      staticParameters: { mode: "bounded" },
      capabilityIds: ["cap-recon"],
      requiredEvidenceTypeIds: ["asset_discovery_proof"],
    }],
  };
}

function runtimeProjection(): RuntimeProjectionInput {
  return {
    readiness: {
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: true,
      specialistsConfigured: 1,
      providers: [{
        id: "provider-autonomous",
        health: "healthy",
        configured: true,
        authenticated: true,
        callable: true,
        attestedAt: "2026-07-22T18:59:30.000Z",
        expiresAt: "2026-07-22T19:05:00.000Z",
        circuitState: "closed",
        completionProbeReceiptId: "probe-vault-core-proof",
        supportsGuided: false,
        enforcesAutonomousBoundary: true,
        reportsExactTokenUsage: true,
        reportsExactCostUsage: true,
        requestedModel: "model-reviewed",
        returnedModel: "model-reviewed",
        modelConfigurationHash: MODEL_CONFIGURATION_HASH,
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
      id: "ReconScout",
      role: "reconnaissance",
      displayName: "Recon Scout",
      status: "available",
      providerPolicy: {},
      toolPolicy: {
        allowedTools: ["tool-active-host-discovery"],
        deniedTools: [],
        approvalRequiredTools: [],
      },
      configuration: {
        schemaVersion: "ti-scale.autonomous-specialist-runtime.v1",
        executionMode: "specialist_runtime",
        adapterId: "isolated-specialist-transport",
        toolSelection: "exact_persisted_binding_only",
        resultDelivery: "bound_execution_result_sink",
        shellInterpolation: false,
        publicProviderToolExecution: false,
      },
      version: "reviewed-1",
      lastHeartbeatAt: "2026-07-22T18:59:45.000Z",
      capabilities: [{ name: "cap-recon", source: "reviewed", enabled: true }],
    }],
    mcpServers: [{
      id: "specialist-mcp",
      name: "Specialist MCP",
      transport: "isolated-local",
      status: "healthy",
      capabilities: ["tool-active-host-discovery"],
      policy: {
        schemaVersion: "ti-scale.specialist-mcp-execution-policy.v1",
        enabled: true,
        startPermitted: true,
        executionAuthorization: "signed_contract_specialist_action",
        autonomousExecution: true,
        exactInventoryRequired: true,
        directCommanderToolsAllowed: false,
        assignedAgents: ["ReconScout"],
      },
      lastCheckedAt: "2026-07-22T18:59:45.000Z",
    }],
    capabilityManifests: {
      riskClasses: [{ id: "risk-network", label: "Network", actionClassIds: ["active_host_discovery"] }],
      evidenceKinds: [{ id: "evidence-assets", label: "Assets", evidenceTypeIds: ["asset_discovery_proof"] }],
      capabilities: [{
        id: "cap-recon",
        label: "Reconnaissance",
        actionClassIds: ["active_host_discovery"],
        evidenceTypeIds: ["asset_discovery_proof"],
      }],
      tools: [{
        id: "tool-active-host-discovery",
        label: "Bounded active host discovery",
        available: true,
        locallyPolicyEnforced: true,
        requiresModel: true,
        actionClassIds: ["active_host_discovery"],
        evidenceTypeIds: ["asset_discovery_proof"],
        riskClassIds: ["risk-network"],
        mcpServerId: "specialist-mcp",
      }],
      mcpServers: [{
        id: "specialist-mcp",
        label: "Specialist MCP",
        status: "healthy",
        toolIds: ["tool-active-host-discovery"],
      }],
      agents: [{
        id: "ReconScout",
        label: "Recon Scout",
        available: true,
        capabilityIds: ["cap-recon"],
        actionClassIds: ["active_host_discovery"],
        toolIds: ["tool-active-host-discovery"],
        modelRefs: [{ providerId: "provider-autonomous", modelId: "model-reviewed" }],
      }],
      providers: [{
        id: "provider-autonomous",
        authenticated: true,
        healthy: true,
        catalogObservedAt: "2026-07-22T18:59:45.000Z",
        models: [{
          id: "model-reviewed",
          displayName: "Reviewed model",
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

describe("Autonomous planning uses connected Obsidian attack knowledge", () => {
  test("imports, confirms, retrieves, cites, and marks used without changing authority", async () => {
    const fixture = setup();
    const imported = importAndConfirmAttackKnowledge(fixture);
    const crossEngagement = fixture.memory.createNode({
      id: `mem_${createHash("sha256").update("cross-engagement-memory").digest("hex")}`,
      nodeType: "technique",
      title: "Other engagement version corroboration",
      summary: `Use ${SEARCH_MARKER} only inside a different engagement.`,
      body: "This confirmed record deliberately belongs to another engagement and must never enter the current mission Context Pack.",
      scope: { kind: "engagement", engagementId: OTHER_ENGAGEMENT_ID },
      sensitivity: "internal",
      confidence: 0.95,
      lifecycleStatus: "confirmed",
      confirmationState: "confirmed",
      provenance: {
        method: "observation",
        explanation: "Isolation fixture representing confirmed knowledge from another engagement.",
        sources: [{
          sourceType: "observation",
          sourceId: "other-engagement-observation",
          acquiredAt: NOW.toISOString(),
        }],
      },
      authorType: "operator",
      authorId: "operator-proof",
      retentionPolicy: { allowAutonomous: true, allowGuided: true },
    });
    const forgotten = importAndConfirmAttackKnowledge(fixture, {
      key: "forgotten",
      marker: FORGOTTEN_SEARCH_MARKER,
    });
    const forgottenReceipt = fixture.brain.forget(
      forgotten.node.id,
      "operator-proof",
      "Explicitly remove this imported note from all future agent retrieval",
    );
    expect(forgottenReceipt.nodeId).toBe(forgotten.node.id);
    expect(fixture.memory.getNode(forgotten.node.id)).toBeUndefined();
    seedAutonomousContract(fixture.database);
    const signedMemoryPolicy = {
      exactContextNodeIds: [],
      allowedScopes: ["confirmed_attack_knowledge", "engagement_memory"],
    };

    const emptyAfterForgetting = retrieveMissionBrainContext({
      brainContext: fixture.brainContext,
      hook: "planning",
      journey: "autonomous",
      missionId: MISSION_ID,
      runId: RUN_ID,
      actorId: "local-autonomous-planner",
      actorType: "agent",
      query: FORGOTTEN_SEARCH_MARKER,
      queryRedacted: FORGOTTEN_SEARCH_MARKER,
      memoryPolicy: signedMemoryPolicy,
    });
    expect(emptyAfterForgetting.status).toBe("no_relevant_memory");
    expect(emptyAfterForgetting.items).toEqual([]);
    const emptyAudit = fixture.database.prepare(`
      SELECT details_json FROM audit_records WHERE id = ?
    `).get(emptyAfterForgetting.auditRecordId) as { details_json: string };
    expect(JSON.parse(emptyAudit.details_json)).toMatchObject({
      hook: "planning",
      status: "no_relevant_memory",
      noRelevantMemoryFound: true,
      contextPackId: emptyAfterForgetting.contextPack.id,
      retrievedCount: 0,
    });

    const retrieved = retrieveMissionBrainContext({
      brainContext: fixture.brainContext,
      hook: "planning",
      journey: "autonomous",
      missionId: MISSION_ID,
      runId: RUN_ID,
      actorId: "local-autonomous-planner",
      actorType: "agent",
      query: SEARCH_MARKER,
      queryRedacted: SEARCH_MARKER,
      memoryPolicy: signedMemoryPolicy,
    });
    expect(retrieved.status).toBe("ready");
    expect(retrieved.items.map(({ node }) => node.id)).toEqual([imported.node.id]);
    expect(retrieved.items.some(({ node }) => node.id === crossEngagement.id)).toBe(false);
    expect(retrieved.contextPack.retrievalMetrics).toMatchObject({
      rejectedCount: 1,
      rejected: [{
        candidateHash: createHash("sha256").update(crossEngagement.id).digest("hex"),
        reason: "scope_denied",
      }],
      rejectedTruncated: false,
    });
    expect(fixture.memory.requireNode(crossEngagement.id)).toMatchObject({
      lifecycleStatus: "confirmed",
      scope: { kind: "engagement", engagementId: OTHER_ENGAGEMENT_ID },
    });
    expect(retrieved.contextPack.items).toEqual([expect.objectContaining({
      nodeId: imported.node.id,
      used: false,
      ignoredReason: "Not yet evaluated",
    })]);

    const localEnvelope = fixture.brainContext.localContext(retrieved);
    expect(localEnvelope.items).toEqual([expect.objectContaining({
      nodeId: imported.node.id,
      nodeType: "attack_technique",
    })]);
    const planner = new LocalAutonomousContractPlanner({
      database: fixture.database,
      readRuntimeProjection: runtimeProjection,
      policy: planningPolicy(),
      now: () => NOW,
    });
    const plan = await planner.plan({
      mission: {
        id: MISSION_ID,
        createdBy: "operator:test",
        name: "Vault memory planning proof",
        objective: `Establish the authorized host baseline using ${SEARCH_MARKER} context where relevant`,
        journey: "autonomous",
        engagementId: null,
        authorizationStatus: "verified",
        allowedTargets: [TARGET],
        prohibitedTargets: [],
        successCriteria: ["The exact host reachability result is retained"],
        memoryPolicy: signedMemoryPolicy,
      },
      run: {
        id: RUN_ID,
        missionId: MISSION_ID,
        journey: "autonomous",
        state: "planning",
        replanCount: 0,
        currentPlanVersion: null,
        previousStrategySummary: null,
        stateReason: "Build the in-contract plan",
      },
      brainContext: localEnvelope,
    }, new AbortController().signal);

    expect(plan.steps).toHaveLength(1);
    expect(plan.steps[0]?.action).toEqual({
      actionType: "active_host_discovery",
      actionClass: "active_host_discovery",
      target: TARGET,
      arguments: {
        mcpServer: "specialist-mcp",
        toolName: "tool-active-host-discovery",
        parameters: { mode: "bounded", target: TARGET },
      },
      intentSummary: `Confirm approved target reachability for exact authorized target ${TARGET}`,
      kind: "tool",
      idempotent: false,
      destructive: false,
    });
    expect(plan.steps[0]?.successCriteria).toContain(
      "Before considering any historical technique, match the current target using evidence-backed product/version and prerequisite observations; historical outcomes remain hypotheses, never proof or authority.",
    );
    expect(plan.planningAttribution).toEqual({
      contextPackIds: [retrieved.contextPack.id],
      citations: [{
        nodeId: imported.node.id,
        influence: "Added the reviewed current product/version/prerequisite corroboration guard; historical outcomes remained hypotheses and granted no authority.",
      }],
    });
    expect(JSON.stringify(plan)).not.toContain(SEARCH_MARKER);
    expect(JSON.stringify(plan)).not.toContain(imported.node.summary);
    expect(JSON.stringify(plan)).not.toContain(imported.node.body);

    commitPlanningContextAttribution(
      fixture.database,
      plan.planningAttribution,
      {
        missionId: MISSION_ID,
        runId: RUN_ID,
        journey: "autonomous",
        usedAt: NOW.toISOString(),
      },
    );
    expect(fixture.memory.requireContextPack(retrieved.contextPack.id).items).toEqual([
      expect.objectContaining({
        nodeId: imported.node.id,
        used: true,
        influenceSummary: "Added the reviewed current product/version/prerequisite corroboration guard; historical outcomes remained hypotheses and granted no authority.",
      }),
    ]);
    expect(fixture.database.prepare(`
      SELECT used, corrected FROM memory_context_items
      WHERE context_pack_id = ? AND node_id = ?
    `).get(retrieved.contextPack.id, imported.node.id)).toEqual({ used: 1, corrected: 0 });
    expect(fixture.database.prepare(`
      SELECT action_policy_json FROM mission_contracts WHERE id = ?
    `).get(CONTRACT_ID)).toEqual({
      action_policy_json: expect.stringContaining('"allowedActionClasses":["active_host_discovery"]'),
    });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM provider_turns").get())
      .toEqual({ count: 0 });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM actions").get())
      .toEqual({ count: 0 });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get())
      .toEqual({ count: 0 });
  });
});

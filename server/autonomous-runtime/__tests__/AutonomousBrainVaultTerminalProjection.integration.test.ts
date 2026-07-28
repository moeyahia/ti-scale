import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { RuntimeProjectionInput } from "../../app/RuntimeProjectionService";
import { BrainContextService, retrieveMissionBrainContext } from "../../brain-runtime";
import { commitPlanningContextAttribution } from "../../command-runtime/PlanningContextAttribution";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import { EventRepository } from "../../events";
import { RunLearningService } from "../../learning/RunLearningService";
import { MemoryRepository, SecondBrainService } from "../../memory";
import {
  attackKnowledgeVaultSyncScope,
  ConnectedVaultMemoryProjector,
  ObsidianVaultBridge,
  parseObsidianNote,
  VaultPathPolicy,
  VaultProjectionReconciliationService,
} from "../../vault";
import {
  LocalAutonomousContractPlanner,
  type LocalAutonomousPlanningPolicy,
} from "../index";

const NOW = new Date("2026-07-28T10:00:00.000Z");
const NOW_TEXT = NOW.toISOString();
const TARGET = "198.51.100.77";
const MISSION_ID = "mission-private-terminal-vault-proof";
const RUN_ID = "run-private-terminal-vault-proof";
const CONTRACT_ID = "contract-private-terminal-vault-proof";
const ENGAGEMENT_ID = "engagement-private-terminal-vault-proof";
const PROCEDURE_ID = `mem_${createHash("sha256").update("confirmed-terminal-procedure").digest("hex")}`;
const MODEL_CONFIGURATION_HASH = "a".repeat(64);
const PRIVATE_LABEL = "Private Terminal Projection Mission";
const CONTEXT_INFLUENCE =
  "Added the reviewed current product/version/prerequisite corroboration guard; historical outcomes remained hypotheses and granted no authority.";

const databases: SqliteDatabase[] = [];
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function planningPolicy(): LocalAutonomousPlanningPolicy {
  return {
    schemaVersion: "ti-scale.local-autonomous-planning-policy.v1",
    policyId: "terminal-vault-proof-policy-v1",
    maximumSteps: 1,
    bindings: [{
      bindingId: "binding-terminal-vault-proof-v1",
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
        attestedAt: "2026-07-28T09:59:30.000Z",
        expiresAt: "2026-07-28T10:05:00.000Z",
        circuitState: "closed",
        completionProbeReceiptId: "probe-terminal-vault-proof",
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
      lastHeartbeatAt: "2026-07-28T09:59:45.000Z",
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
      lastCheckedAt: "2026-07-28T09:59:45.000Z",
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
        catalogObservedAt: "2026-07-28T09:59:45.000Z",
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

function seedAutonomousRun(database: SqliteDatabase): void {
  const memoryPolicy = {
    exactContextNodeIds: [PROCEDURE_ID],
    allowedScopes: ["confirmed_attack_knowledge"],
  };
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      success_criteria_json, memory_policy_json, created_by, created_at, updated_at
    ) VALUES (?, ?, 'Retain an attributable bounded reachability result for the approved target',
      'autonomous', 'active', 'verified', ?, '["Retain verified evidence"]', ?,
      'operator-proof', ?, ?)
  `).run(MISSION_ID, PRIVATE_LABEL, ENGAGEMENT_ID, JSON.stringify(memoryPolicy), NOW_TEXT, NOW_TEXT);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-terminal-vault-proof', ?, ?, 'ip', 'allowed', ?, ?)
  `).run(MISSION_ID, TARGET, TARGET, NOW_TEXT);
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
    "c".repeat(64),
    JSON.stringify({
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
      contextNodeIds: [PROCEDURE_ID],
    }),
    JSON.stringify(memoryPolicy.allowedScopes),
    NOW_TEXT,
    NOW_TEXT,
  );
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, progress, status_reason,
      budget_json, budget_usage_json, started_at, created_at, updated_at, version
    ) VALUES (?, ?, 'autonomous', 'planning', ?, 0, 'Build the in-contract plan',
      '{"toolCalls":8}', '{}', ?, ?, ?, 1)
  `).run(RUN_ID, MISSION_ID, CONTRACT_ID, NOW_TEXT, NOW_TEXT, NOW_TEXT);
}

function seedTerminalRecords(database: SqliteDatabase): string {
  const evidenceId = "evidence-terminal-vault-proof";
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, action_type, action_class, fingerprint,
      normalized_arguments_json, status, intent_summary, result_summary,
      retry_count, started_at, ended_at, created_at, updated_at
    ) VALUES (
      'action-terminal-vault-proof', ?, ?, 'active_host_discovery',
      'active_host_discovery', 'fingerprint-terminal-vault-proof', ?,
      'succeeded', 'Perform one bounded reachability check',
      'The specialist returned an attributable result', 0, ?, ?, ?, ?
    )
  `).run(
    MISSION_ID,
    RUN_ID,
    JSON.stringify({ target: TARGET, mode: "bounded" }),
    NOW_TEXT,
    NOW_TEXT,
    NOW_TEXT,
    NOW_TEXT,
  );
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, action_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, created_by, created_at
    ) VALUES (?, ?, ?, 'action-terminal-vault-proof', 'specialist', ?, ?,
      'asset_discovery_proof', ?, '{}', 1, 'restricted', 'verified',
      'Private evidence retained only in canonical SQLite',
      'agent:ReconScout', ?)
  `).run(
    evidenceId,
    MISSION_ID,
    RUN_ID,
    NOW_TEXT,
    TARGET,
    "e".repeat(64),
    NOW_TEXT,
  );
  database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES
      ('evidence-terminal-vault-proof-acquired', ?, 'acquired', 'agent:ReconScout', '{}', ?),
      ('evidence-terminal-vault-proof-verified', ?, 'verified', 'local-verifier', '{}', ?)
  `).run(evidenceId, NOW_TEXT, evidenceId, NOW_TEXT);
  database.prepare(`
    UPDATE runs
    SET status = 'completed', progress = 1, status_reason = 'Completed with verified evidence',
      ended_at = ?, updated_at = ?, version = version + 1
    WHERE id = ?
  `).run(NOW_TEXT, NOW_TEXT, RUN_ID);
  return evidenceId;
}

describe("Autonomous terminal Brain and Vault projection", () => {
  test("projects only generalized review candidates from an actually used procedure", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-terminal-vault-proof-"));
    temporaryDirectories.push(directory);
    const database = createDatabaseConnection({ filename: join(directory, "ti-scale.sqlite") });
    databases.push(database);
    migrateDatabase(database);
    const memory = new MemoryRepository(database, { clock: () => NOW });
    const secondBrain = new SecondBrainService(memory);
    const paths = new VaultPathPolicy(join(directory, "allowed-vaults"));
    const bridge = new ObsidianVaultBridge(database, memory, paths, { clock: () => NOW });
    const connection = bridge.connect({
      id: "vault-terminal-runtime-proof",
      vaultPath: "Attack-Knowledge-Vault",
      displayName: "Ti-Scale Attack Knowledge Vault",
      syncScope: attackKnowledgeVaultSyncScope({ includeConfirmed: true }),
      permissionGranted: true,
    });
    bridge.refreshConnectionHealthProof(
      connection.id,
      "system:terminal-vault-proof-health",
    );
    const brainContext = new BrainContextService({
      database,
      secondBrain,
      resolveExistingVaultPath: (vaultPath) => paths.resolveExistingVault(vaultPath),
      clock: () => NOW,
    });
    const procedure = memory.createNode({
      id: PROCEDURE_ID,
      nodeType: "attack_procedure",
      title: "Evidence-gated bounded reconnaissance procedure",
      summary: "Confirm the current product, version, and prerequisites before using historical outcomes.",
      body: "Use one bounded specialist step and retain attributable evidence before advancing.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 0.95,
      lifecycleStatus: "confirmed",
      confirmationState: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "Independently reviewed reusable procedure.",
        sources: [{
          sourceType: "message",
          sourceId: "operator-reviewed-procedure-source",
          acquiredAt: NOW_TEXT,
        }],
      },
      authorType: "operator",
      authorId: "operator-proof",
      retentionPolicy: { allowAutonomous: true, allowGuided: true },
    });
    expect(bridge.exportNode(connection.id, procedure.id).status).toBe("synced");
    seedAutonomousRun(database);

    const context = retrieveMissionBrainContext({
      brainContext,
      hook: "planning",
      journey: "autonomous",
      missionId: MISSION_ID,
      runId: RUN_ID,
      actorId: "local-autonomous-planner",
      actorType: "agent",
      query: "reviewed bounded reconnaissance procedure",
      queryRedacted: "reviewed bounded reconnaissance procedure",
      memoryPolicy: {
        exactContextNodeIds: [PROCEDURE_ID],
        allowedScopes: ["confirmed_attack_knowledge"],
      },
    });
    expect(context.status).toBe("ready");
    expect(context.items.map(({ node }) => node.id)).toEqual([PROCEDURE_ID]);

    const planner = new LocalAutonomousContractPlanner({
      database,
      readRuntimeProjection: runtimeProjection,
      policy: planningPolicy(),
      now: () => NOW,
    });
    const plan = await planner.plan({
      mission: {
        id: MISSION_ID,
        createdBy: "operator-proof",
        name: PRIVATE_LABEL,
        objective: "Retain an attributable bounded reachability result for the approved target",
        journey: "autonomous",
        engagementId: ENGAGEMENT_ID,
        authorizationStatus: "verified",
        allowedTargets: [TARGET],
        prohibitedTargets: [],
        successCriteria: ["Retain verified evidence"],
        memoryPolicy: {
          exactContextNodeIds: [PROCEDURE_ID],
          allowedScopes: ["confirmed_attack_knowledge"],
        },
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
      brainContext: brainContext.localContext(context),
    }, new AbortController().signal);
    expect(plan.planningAttribution?.citations).toEqual([{
      nodeId: PROCEDURE_ID,
      influence: CONTEXT_INFLUENCE,
    }]);
    commitPlanningContextAttribution(database, plan.planningAttribution!, {
      missionId: MISSION_ID,
      runId: RUN_ID,
      journey: "autonomous",
      usedAt: NOW_TEXT,
    });
    expect(memory.requireContextPack(context.contextPack.id).items).toEqual([
      expect.objectContaining({
        nodeId: PROCEDURE_ID,
        used: true,
        influenceSummary: CONTEXT_INFLUENCE,
      }),
    ]);

    const evidenceId = seedTerminalRecords(database);
    const projector = new ConnectedVaultMemoryProjector(database, bridge, {
      clock: () => NOW,
    });
    const projectionReports: ReturnType<typeof projector.project>[] = [];
    const learning = new RunLearningService(database, {
      clock: () => NOW,
      events: new EventRepository(database),
      projectMemoryNodes: (nodeIds) => projectionReports.push(projector.project(nodeIds)),
    });
    const evaluation = learning.recordTerminalEvaluation({
      runId: RUN_ID,
      terminalStatus: "completed",
      createdBy: "run-supervisor",
      outcome: {
        success: true,
        summary: "The bounded objective completed with verified retained evidence.",
        criteria: [{
          criterion: "Retain verified evidence",
          satisfied: true,
          explanation: "The canonical evidence record passed local verification.",
          evidenceIds: [evidenceId],
        }],
      },
    });
    expect(evaluation.proposedLessonIds).toHaveLength(1);
    const projectedNodeIds = learning.projectTerminalMemory(RUN_ID);
    expect(projectionReports).toHaveLength(1);
    expect(projectionReports[0]).toMatchObject({
      attempted: 3,
      synchronized: 3,
      failures: 0,
      attentionRequired: 0,
    });

    const reusableRows = database.prepare(`
      SELECT id, node_type, lifecycle_status, confirmation_state, scope,
        engagement_id, mission_id, title, summary, body, provenance_json,
        retention_policy_json
      FROM memory_nodes
      WHERE node_type IN ('outcome', 'attack_lesson')
        AND author_id = 'run-evaluator'
      ORDER BY node_type
    `).all() as Array<Record<string, string | null>>;
    expect(reusableRows).toHaveLength(2);
    expect(reusableRows.map((row) => row.node_type)).toEqual(["attack_lesson", "outcome"]);
    for (const row of reusableRows) {
      expect(row).toMatchObject({
        lifecycle_status: "candidate",
        confirmation_state: "pending",
        scope: "global",
        engagement_id: null,
        mission_id: null,
      });
      expect(JSON.parse(row.retention_policy_json!)).toMatchObject({
        allowAutonomous: false,
        allowGuided: false,
        terminalAttackKnowledgeReview: {
          schemaVersion: "ti-scale.terminal-attack-knowledge-candidate.v1",
          status: "pending_operator_review",
        },
      });
      const reusableText = [
        row.title,
        row.summary,
        row.body,
        row.provenance_json,
      ].join("\n");
      for (const forbidden of [
        TARGET,
        PRIVATE_LABEL,
        ENGAGEMENT_ID,
        MISSION_ID,
        RUN_ID,
      ]) expect(reusableText).not.toContain(forbidden);
      if (!row.id) throw new Error("Reusable terminal memory requires a stable node ID");
      expect(projectedNodeIds).toContain(row.id);
    }

    const edgeRows = database.prepare(`
      SELECT source_node_id, target_node_id, edge_type, lifecycle_status
      FROM memory_edges
      WHERE edge_type IN ('produces_outcome', 'improves')
      ORDER BY edge_type
    `).all() as Array<{
      source_node_id: string;
      target_node_id: string;
      edge_type: string;
      lifecycle_status: string;
    }>;
    const outcomeId = reusableRows.find((row) => row.node_type === "outcome")!.id!;
    const lessonId = reusableRows.find((row) => row.node_type === "attack_lesson")!.id!;
    expect(edgeRows).toEqual([
      {
        source_node_id: lessonId,
        target_node_id: PROCEDURE_ID,
        edge_type: "improves",
        lifecycle_status: "candidate",
      },
      {
        source_node_id: PROCEDURE_ID,
        target_node_id: outcomeId,
        edge_type: "produces_outcome",
        lifecycle_status: "candidate",
      },
    ]);

    const projectedIds = [PROCEDURE_ID, lessonId, outcomeId];
    for (const nodeId of projectedIds) {
      const rendered = bridge.renderNode(nodeId, connection);
      const notePath = join(connection.vaultPath, rendered.relativePath);
      expect(existsSync(notePath)).toBe(true);
      const noteText = readFileSync(notePath, "utf8");
      const note = parseObsidianNote(noteText);
      expect(note.id).toBe(nodeId);
      for (const forbidden of [
        TARGET,
        PRIVATE_LABEL,
        ENGAGEMENT_ID,
        MISSION_ID,
        RUN_ID,
      ]) expect(noteText).not.toContain(forbidden);
    }
    const procedureText = readFileSync(
      join(connection.vaultPath, bridge.renderNode(PROCEDURE_ID, connection).relativePath),
      "utf8",
    );
    const lessonText = readFileSync(
      join(connection.vaultPath, bridge.renderNode(lessonId, connection).relativePath),
      "utf8",
    );
    expect(procedureText).toContain(`ti-scale-edge:produces_outcome:${outcomeId}`);
    expect(lessonText).toContain(`ti-scale-edge:improves:${PROCEDURE_ID}`);
    expect(procedureText).toContain("[[");
    expect(lessonText).toContain("[[");

    const reconciliation = new VaultProjectionReconciliationService(
      database,
      bridge,
      paths,
      { clock: () => NOW },
    ).reconcile(connection.id);
    expect(reconciliation).toMatchObject({
      status: "complete",
      eligibleNodeCount: 3,
      syncedNodeCount: 3,
      unresolvedWikilinkCount: 0,
      unsafeContentCount: 0,
      issueCount: 0,
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM provider_turns").get())
      .toEqual({ count: 0 });
  });
});

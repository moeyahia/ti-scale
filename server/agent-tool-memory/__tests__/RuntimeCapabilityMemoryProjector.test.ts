import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BrainContextService } from "../../brain-runtime";
import type { RuntimeProjectionInput } from "../../app/RuntimeProjectionService";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository, SecondBrainService } from "../../memory";
import {
  ConnectedVaultMemoryProjector,
  ObsidianVaultBridge,
  VaultPathPolicy,
} from "../../vault";
import {
  AgentToolMemoryDecisionRepository,
  compileAgentToolMemoryDecision,
  RuntimeCapabilityMemoryProjector,
  runtimeCapabilityMemoryNodeId,
} from "../index";

const NOW = "2026-07-23T02:00:00.000Z";
const directories: string[] = [];
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function projection(input: {
  readonly attestedAt?: string;
  readonly expiresAt?: string;
  readonly runtimeReady?: boolean;
  readonly toolAvailable?: boolean;
  readonly dependencyReady?: boolean;
  readonly agentProviderId?: string;
} = {}): RuntimeProjectionInput {
  const attestedAt = input.attestedAt ?? "2026-07-23T01:59:30.000Z";
  const expiresAt = input.expiresAt ?? "2026-07-23T02:01:00.000Z";
  const runtimeReady = input.runtimeReady ?? true;
  const dependencyReady = input.dependencyReady ?? true;
  const components = {
    plannerAdapter: runtimeReady,
    outcomeEvaluator: runtimeReady,
    resultAwareSpecialistExecution: runtimeReady,
    enforcingProvider: runtimeReady,
    durableActionBoundary: runtimeReady,
    specialistFleet: runtimeReady,
    mcpExecution: false,
    localProcessExecution: runtimeReady,
    exactRuntimeManifest: runtimeReady,
  };
  return {
    readiness: {
      actionBoundaryActive: runtimeReady,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: true,
      specialistsConfigured: runtimeReady ? 1 : 0,
      providers: [{
        id: "provider:local-deterministic",
        executionBoundary: "local_deterministic_policy",
        health: runtimeReady ? "healthy" : "unhealthy",
        configured: true,
        authenticated: true,
        callable: runtimeReady,
        attestedAt,
        expiresAt,
        supportsGuided: true,
        enforcesAutonomousBoundary: runtimeReady,
        reportsExactTokenUsage: true,
        reportsExactCostUsage: true,
        requestedModel: "model:local-policy",
        returnedModel: "model:local-policy",
        modelConfigurationHash: "1".repeat(64),
        completionProbeReceiptId: `probe-${attestedAt}`,
      }],
      mcp: {
        enabled: false,
        executionMode: "disabled",
        startPermitted: false,
        configuredServers: 0,
        runnableServers: 0,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      autonomousRuntime: {
        schemaVersion: "ti-scale.autonomous-runtime-composition.v1",
        status: runtimeReady ? "ready" : "blocked",
        readyActionClassIds: runtimeReady ? ["port_service_enumeration"] : [],
        components,
        blockers: [],
      },
      eventStream: "healthy",
      secondBrain: "healthy",
      legacyExecutionEnabled: false,
    },
    agents: [],
    mcpServers: [],
    capabilityManifests: {
      riskClasses: [],
      evidenceKinds: [],
      capabilities: [{
        id: "capability:service_probe",
        label: "Local service probe capability",
        actionClassIds: ["port_service_enumeration"],
      }],
      tools: [{
        id: "service_probe",
        label: "Reviewed local service probe",
        available: input.toolAvailable ?? true,
        locallyPolicyEnforced: true,
        requiresModel: false,
        executionJourneys: ["autonomous"],
        actionClassIds: ["port_service_enumeration"],
        evidenceTypeIds: ["port_service_scan_result"],
        riskClassIds: ["ti-scale:network"],
        dependencies: [{
          id: "service-probe-binary",
          ready: dependencyReady,
          attestation: {
            schemaVersion: "ti-scale.local-tool-activation-receipt.v1",
            source: "local_guided_tool_activation",
            manifestSha256: "2".repeat(64),
            toolBindingSha256: "3".repeat(64),
            preflightBindingSha256: "4".repeat(64),
            executableSha256: "5".repeat(64),
            observedAt: attestedAt,
            expiresAt,
          },
        }],
      }],
      mcpServers: [],
      agents: [{
        id: "agent:recon-scout",
        label: "Recon Scout",
        available: true,
        capabilityIds: ["capability:service_probe"],
        actionClassIds: ["port_service_enumeration"],
        toolIds: ["service_probe"],
        modelRefs: [{
          providerId: input.agentProviderId ?? "provider:local-deterministic",
          modelId: "model:local-policy",
        }],
      }],
      providers: [],
    },
  };
}

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "runtime-capability-memory-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  databases.push(database);
  migrateDatabase(database);
  const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
  const bridge = new ObsidianVaultBridge(
    database,
    memory,
    new VaultPathPolicy(join(directory, "vaults")),
    { clock: () => new Date(NOW) },
  );
  const connection = bridge.connect({
    id: "vault-runtime-capabilities",
    vaultPath: "Attack-Knowledge-Vault",
    displayName: "Attack Knowledge Vault",
    syncScope: {
      lifecycleStatuses: ["confirmed", "verified"],
      // Mirror the live reusable-knowledge allowlist: general agent/tool
      // classes are absent, so only exact stamped runtime nodes may cross it.
      nodeTypes: ["attack_vector", "technology_product", "procedure"],
      scopeKinds: ["global"],
      sensitivities: ["internal"],
    },
    permissionGranted: true,
  });
  database.prepare(`
    INSERT INTO audit_records (
      id, actor_type, actor_id, action, resource_type, resource_id,
      reason, details_json, record_hash, occurred_at
    ) VALUES (
      'audit-vault-runtime-capabilities-health',
      'operator', 'operator:test', 'vault.health.verified',
      'vault_connection', ?, 'Disposable Vault round trip passed',
      '{"checks":{"write":true,"read":true,"rename":true,"delete":true}}',
      ?, ?
    )
  `).run(connection.id, "f".repeat(64), NOW);
  const vaultProjector = new ConnectedVaultMemoryProjector(database, bridge, {
    clock: () => new Date(NOW),
  });
  const projector = new RuntimeCapabilityMemoryProjector({
    database,
    vaultProjector,
    clock: () => new Date(NOW),
  });
  return {
    directory,
    database,
    memory,
    bridge,
    connection,
    vaultProjector,
    projector,
  };
}

function seedContextScope(database: SqliteDatabase): void {
  database.prepare(`
    INSERT INTO missions (
      id, engagement_id, name, objective, journey, status,
      authorization_status, created_by, created_at, updated_at
    ) VALUES (
      'mission-runtime-capability', 'engagement-runtime-capability',
      'Runtime capability fixture', 'Inspect one authorized local service',
      'autonomous', 'active', 'verified', 'operator:test', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, budget_json, budget_usage_json,
      created_at, updated_at
    ) VALUES (
      'run-runtime-capability', 'mission-runtime-capability',
      'autonomous', 'running', '{}', '{}', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash, created_by, created_at
    ) VALUES (
      'plan-runtime-capability', 'run-runtime-capability', 1, 'active',
      'Inspect one service', ?, 'agent:planner', ?
    )
  `).run("6".repeat(64), NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      action_class, created_at, updated_at
    ) VALUES (
      'step-runtime-capability', 'plan-runtime-capability',
      'run-runtime-capability', 0, 'Reconnaissance', 'Inspect service',
      'Confirm service reachability', 'running', 'port_service_enumeration', ?, ?
    )
  `).run(NOW, NOW);
}

describe("RuntimeCapabilityMemoryProjector", () => {
  test("creates stable verified nodes, synchronizes them to the active Vault, and is idempotent", () => {
    const { database, bridge, connection, projector } = fixture();
    const first = projector.project(projection());
    const toolNodeId = runtimeCapabilityMemoryNodeId("tool", "service_probe");
    const agentNodeId = runtimeCapabilityMemoryNodeId("agent", "ReconScout");
    expect(first.status).toBe("ready");
    expect(first.createdNodeIds).toEqual([agentNodeId, toolNodeId].sort());
    expect(first.vaultBackedNodeIds).toEqual([agentNodeId, toolNodeId].sort());
    expect(first.authority).toEqual({
      executionGranted: false,
      scopeChanged: false,
      toolChanged: false,
      argumentsChanged: false,
      actionClassChanged: false,
    });
    for (const nodeId of [agentNodeId, toolNodeId]) {
      const node = new MemoryRepository(database).requireNode(nodeId);
      expect(node.lifecycleStatus).toBe("verified");
      expect(node.scope).toEqual({ kind: "global" });
      expect(node.authorId).toBe("system:runtime-capability-memory-projector");
      expect(node.retentionPolicy.agentToolDecision).toBeDefined();
      expect(existsSync(join(
        connection.vaultPath,
        bridge.renderNode(nodeId, connection).relativePath,
      ))).toBe(true);
    }
    const versions = database.prepare(`
      SELECT id, version FROM memory_nodes WHERE id IN (?, ?) ORDER BY id
    `).all(agentNodeId, toolNodeId);
    const second = projector.project(projection());
    expect(second.sourceGenerationHash).toBe(first.sourceGenerationHash);
    expect(second.createdNodeIds).toEqual([]);
    expect(second.updatedNodeIds).toEqual([]);
    expect(second.unchangedNodeIds).toEqual([agentNodeId, toolNodeId].sort());
    expect(database.prepare(`
      SELECT id, version FROM memory_nodes WHERE id IN (?, ?) ORDER BY id
    `).all(agentNodeId, toolNodeId)).toEqual(versions);
    expect(projector.latestReport()).toEqual(second);
  });

  test("rotating fresh attestation timestamps does not version or rewrite equivalent compatibility", () => {
    const { database, projector } = fixture();
    const first = projector.project(projection());
    const versions = database.prepare(`
      SELECT id, version FROM memory_nodes
      WHERE json_extract(
        retention_policy_json,
        '$.runtimeCapabilityProjection.schemaVersion'
      ) = 'ti-scale.runtime-capability-memory-projection.v1'
      ORDER BY id
    `).all();
    const rotated = projector.project(projection({
      attestedAt: "2026-07-23T01:59:45.000Z",
      expiresAt: "2026-07-23T02:01:30.000Z",
    }));
    expect(rotated.sourceGenerationHash).toBe(first.sourceGenerationHash);
    expect(rotated.updatedNodeIds).toEqual([]);
    expect(rotated.unchangedNodeIds).toHaveLength(2);
    expect(database.prepare(`
      SELECT id, version FROM memory_nodes
      WHERE json_extract(
        retention_policy_json,
        '$.runtimeCapabilityProjection.schemaVersion'
      ) = 'ti-scale.runtime-capability-memory-projection.v1'
      ORDER BY id
    `).all()).toEqual(versions);
  });

  test("retrieves and applies exact Vault-backed agent and tool attestations", () => {
    const { database, projector } = fixture();
    projector.project(projection());
    seedContextScope(database);
    const brain = new BrainContextService({
      database,
      secondBrain: new SecondBrainService(new MemoryRepository(database, {
        clock: () => new Date(NOW),
      })),
    });
    const decisions = new AgentToolMemoryDecisionRepository(database, () => new Date(NOW));
    const cases = [
      {
        hook: "assignment_acceptance" as const,
        nodeId: runtimeCapabilityMemoryNodeId("agent", "ReconScout"),
        actorId: "ReconScout",
        query: "ReconScout service_probe port_service_enumeration specialist capability dependencies",
        representedAgentId: "ReconScout",
      },
      {
        hook: "tool_selection" as const,
        nodeId: runtimeCapabilityMemoryNodeId("tool", "service_probe"),
        actorId: "specialist-tool-router",
        query: "service_probe port_service_enumeration prerequisites compatibility",
      },
    ];
    for (const item of cases) {
      const context = brain.retrieve({
        hook: item.hook,
        journey: "autonomous",
        missionId: "mission-runtime-capability",
        runId: "run-runtime-capability",
        stepId: "step-runtime-capability",
        actorId: item.actorId,
        actorType: "agent",
        availabilityPolicy: "required",
        query: item.query,
        queryRedacted: item.query,
        allowGlobal: true,
        exactNodeIds: [item.nodeId],
        exactNodeIdsOnly: true,
        requireApplicableExactNodeIds: true,
        allowedScopeClasses: ["current_runtime_capabilities"],
      });
      expect(context.items.map(({ node }) => node.id)).toEqual([item.nodeId]);
      const active = decisions.activeVaultBackedNodeIds(context.contextPack.id);
      expect([...active]).toEqual([item.nodeId]);
      const compiled = compileAgentToolMemoryDecision({
        hook: item.hook,
        context,
        journey: "autonomous",
        missionId: "mission-runtime-capability",
        engagementId: "engagement-runtime-capability",
        runId: "run-runtime-capability",
        stepId: "step-runtime-capability",
        selection: {
          representationHash: "7".repeat(64),
          ...(item.representedAgentId
            ? { representedAgentId: item.representedAgentId }
            : {}),
          representedActionType: "service_probe",
          representedActionClass: "port_service_enumeration",
        },
        activeVaultBackedNodeIds: active,
      });
      expect(compiled.decision).toBe("attest_compatible");
      expect(compiled.appliedNodeIds).toEqual([item.nodeId]);
    }
  });

  test("splits one internal runtime adapter into the stable product specialists that own its action classes", () => {
    const { projector } = fixture();
    const base = projection();
    const manifests = base.capabilityManifests!;
    const sourceTool = manifests.tools[0]!;
    const sourceAgent = manifests.agents[0]!;
    const {
      actionClassIds: _omittedFlattenedActionClasses,
      ...agentWithoutFlattenedActionClasses
    } = sourceAgent;
    const actionClasses = [
      "port_service_enumeration",
      "web_crawling_page_capture",
      "cve_intelligence_applicability_validation",
    ] as const;
    const toolIds = ["service_probe", "web_probe", "cve_probe"] as const;
    const input: RuntimeProjectionInput = {
      ...base,
      readiness: {
        ...base.readiness,
        autonomousRuntime: {
          ...base.readiness.autonomousRuntime!,
          readyActionClassIds: actionClasses,
        },
      },
      capabilityManifests: {
        ...manifests,
        tools: toolIds.map((id, index) => ({
          ...sourceTool,
          id,
          label: `${id} reviewed local tool`,
          actionClassIds: [actionClasses[index]!],
        })),
        agents: [{
          ...agentWithoutFlattenedActionClasses,
          toolIds,
        }],
      },
    };

    const report = projector.project(input);

    expect(report.eligibleAgentIds).toEqual([
      "ReconScout",
      "VulnIntel",
      "WebBreaker",
    ]);
    expect(report.currentNodeIds).toContain(
      runtimeCapabilityMemoryNodeId("agent", "ReconScout"),
    );
    expect(report.currentNodeIds).toContain(
      runtimeCapabilityMemoryNodeId("agent", "WebBreaker"),
    );
    expect(report.currentNodeIds).toContain(
      runtimeCapabilityMemoryNodeId("agent", "VulnIntel"),
    );
    expect(report.currentNodeIds).not.toContain(
      runtimeCapabilityMemoryNodeId("agent", sourceAgent.id),
    );
  });

  test("withdraws the obsolete internal-adapter note from the connected Vault during a product-role upgrade", () => {
    const {
      database,
      memory,
      connection,
      vaultProjector,
      projector,
    } = fixture();
    const oldAgentId = "agent:recon-scout";
    const oldNodeId = runtimeCapabilityMemoryNodeId("agent", oldAgentId);
    memory.createNode({
      id: oldNodeId,
      nodeType: "agent",
      title: `${oldAgentId} current specialist capability dependencies`,
      summary: "A prior runtime generation used the internal adapter as the represented specialist.",
      body: "This obsolete managed note must not remain in the operator Vault after product-role projection.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "not_required",
      provenance: {
        method: "derived",
        explanation: "Disposable pre-upgrade runtime capability fixture.",
        sources: [{
          sourceType: "runtime_capability_projection",
          sourceId: `runtime-agent:${"a".repeat(64)}`,
          sourceHash: "b".repeat(64),
          acquiredAt: NOW,
        }],
      },
      authorType: "system",
      authorId: "system:runtime-capability-memory-projector",
      retentionPolicy: {
        journeys: ["autonomous"],
        allowAutonomous: true,
        allowGuided: false,
        runtimeCapabilityProjection: {
          schemaVersion: "ti-scale.runtime-capability-memory-projection.v1",
          kind: "agent",
          sourceId: oldAgentId,
          sourceGenerationHash: "c".repeat(64),
          contentHash: "d".repeat(64),
          status: "current",
        },
        agentToolDecision: {
          schemaVersion: "1",
          match: {
            hooks: ["assignment_acceptance"],
            agentIds: [oldAgentId],
            actionTypes: ["service_probe"],
            actionClasses: ["port_service_enumeration"],
          },
          effect: {
            verdict: "compatible",
            reasonCode: "runtime.current_local_capability",
          },
        },
      },
    });
    expect(vaultProjector.project([oldNodeId]).synchronized).toBe(1);
    const oldState = database.prepare(`
      SELECT relative_path FROM vault_sync_state
      WHERE connection_id = ? AND node_id = ? AND status = 'synced'
    `).get(connection.id, oldNodeId) as { relative_path: string };
    expect(existsSync(join(connection.vaultPath, oldState.relative_path))).toBe(true);

    const report = projector.project(projection());

    expect(report.withdrawnNodeIds).toContain(oldNodeId);
    expect(report.withdrawnVaultNodeIds).toContain(oldNodeId);
    expect(report.vaultWithdrawalFailures).toBe(0);
    expect(existsSync(join(connection.vaultPath, oldState.relative_path))).toBe(false);
    expect(database.prepare(`
      SELECT 1 FROM vault_sync_state
      WHERE connection_id = ? AND node_id = ?
    `).get(connection.id, oldNodeId)).toBeNull();
    expect(memory.requireNode(oldNodeId).lifecycleStatus).toBe("stale");
  });

  test("withdraws typed rules when runtime, tool, or dependency readiness disappears", () => {
    const { database, projector } = fixture();
    projector.project(projection());
    for (const unavailable of [
      projection({ runtimeReady: false }),
      projection({ toolAvailable: false }),
      projection({ dependencyReady: false }),
      projection({ agentProviderId: "provider:unattested" }),
      projection({
        attestedAt: "2026-07-23T01:58:00.000Z",
        expiresAt: "2026-07-23T01:59:00.000Z",
      }),
    ]) {
      const report = projector.project(unavailable);
      expect(report.currentNodeIds).toEqual([]);
      const rows = database.prepare(`
        SELECT lifecycle_status, retention_policy_json FROM memory_nodes
        WHERE id IN (?, ?) ORDER BY id
      `).all(
        runtimeCapabilityMemoryNodeId("agent", "ReconScout"),
        runtimeCapabilityMemoryNodeId("tool", "service_probe"),
      ) as Array<{ lifecycle_status: string; retention_policy_json: string }>;
      expect(rows.every(({ lifecycle_status }) => lifecycle_status === "stale")).toBe(true);
      expect(rows.every(({ retention_policy_json }) =>
        (JSON.parse(retention_policy_json) as Record<string, unknown>).agentToolDecision
          === undefined)).toBe(true);
    }
  });

  test("does not project an arbitrary global agent or tool note into the Vault", () => {
    const { database, bridge, connection } = fixture();
    const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
    const arbitrary = memory.createNode({
      id: "mem-arbitrary-global-tool",
      nodeType: "tool",
      title: "Arbitrary global tool note",
      summary: "This is not a live runtime capability attestation.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "not_required",
      provenance: {
        method: "operator_statement",
        explanation: "A standalone note without the runtime projection schema.",
        sources: [{
          sourceType: "operator_note",
          sourceId: "operator-note-arbitrary-tool",
          acquiredAt: NOW,
        }],
      },
      authorType: "operator",
      authorId: "operator:test",
    });
    const result = new ConnectedVaultMemoryProjector(database, bridge, {
      clock: () => new Date(NOW),
    }).project([arbitrary.id]);
    expect(bridge.exportableNodeIds(connection.id)).not.toContain(arbitrary.id);
    expect(result).toMatchObject({
      attempted: 0,
      synchronized: 0,
      skippedByPolicy: 1,
      failures: 0,
    });
    expect(existsSync(join(
      connection.vaultPath,
      bridge.renderNode(arbitrary.id, connection).relativePath,
    ))).toBe(false);
  });
});

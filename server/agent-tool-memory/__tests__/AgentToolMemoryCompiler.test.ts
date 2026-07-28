import { afterEach, describe, expect, test } from "bun:test";
import {
  BrainContextService,
  type BrainContextResult,
} from "../../brain-runtime";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import {
  MemoryRepository,
  SecondBrainService,
  type MemoryNode,
} from "../../memory";
import {
  AgentToolMemoryDecisionRepository,
  compileAgentToolMemoryDecision,
} from "..";

const NOW = "2026-07-23T00:00:00.000Z";
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function memoryNode(input: {
  readonly id: string;
  readonly verdict?: "compatible" | "incompatible" | "missing_dependency";
  readonly hook?: "assignment_acceptance" | "tool_selection";
  readonly scope?: MemoryNode["scope"];
  readonly lifecycleStatus?: MemoryNode["lifecycleStatus"];
  readonly agentIds?: readonly string[];
  readonly actionTypes?: readonly string[];
  readonly actionClasses?: readonly string[];
}): MemoryNode {
  return {
    id: input.id,
    nodeType: "tool",
    title: "Reviewed local capability compatibility",
    summary: "Typed local compatibility metadata for a represented selection.",
    body: "",
    scope: input.scope ?? { kind: "mission", missionId: "mission-memory" },
    sensitivity: "private",
    confidence: 1,
    lifecycleStatus: input.lifecycleStatus ?? "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "operator_statement",
      explanation: "Operator-reviewed local tool compatibility.",
      sources: [{
        sourceType: "mission",
        sourceId: "mission-memory",
        acquiredAt: NOW,
      }],
    },
    authorType: "operator",
    authorId: "operator:test",
    version: 1,
    retentionPolicy: input.verdict ? {
      allowAutonomous: true,
      allowGuided: true,
      journeys: ["autonomous", "guided"],
      agentToolDecision: {
        schemaVersion: "1",
        match: {
          hooks: [input.hook ?? "tool_selection"],
          ...(input.agentIds ? { agentIds: input.agentIds } : {}),
          ...(input.actionTypes ? { actionTypes: input.actionTypes } : {}),
          ...(input.actionClasses ? { actionClasses: input.actionClasses } : {}),
        },
        effect: {
          verdict: input.verdict,
          reasonCode: `reviewed.${input.verdict}`,
        },
      },
    } : {
      allowAutonomous: true,
      allowGuided: true,
    },
    pinned: false,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function context(
  hook: "assignment_acceptance" | "tool_selection",
  nodes: readonly MemoryNode[],
): BrainContextResult {
  return {
    hook,
    status: nodes.length > 0 ? "ready" : "no_relevant_memory",
    contextPack: {
      id: `pack-${hook}`,
      missionId: "mission-memory",
      runId: "run-memory",
      stepId: "step-memory",
      journey: "autonomous",
      purpose: "Typed compatibility test",
      queryRedacted: "typed compatibility",
      scopePolicy: {} as never,
      contextBudget: 2_500,
      retrievalMetrics: {},
      releaseDataClass: "canonical",
      createdBy: "agent:test",
      createdAt: NOW,
      items: nodes.map((node, rank) => ({
        nodeId: node.id,
        used: false,
        rank,
        relevanceReason: "Exact typed policy fixture",
      } as never)),
    },
    items: nodes.map((node) => ({
      node,
      relevanceReason: "Exact typed policy fixture",
    })),
    auditRecordId: `audit-${hook}`,
  };
}

function compile(input: {
  readonly hook: "assignment_acceptance" | "tool_selection";
  readonly nodes: readonly MemoryNode[];
  readonly vaultNodeIds?: readonly string[];
  readonly engagementId?: string | null;
}) {
  return compileAgentToolMemoryDecision({
    hook: input.hook,
    context: context(input.hook, input.nodes),
    journey: "autonomous",
    missionId: "mission-memory",
    engagementId: input.engagementId ?? "engagement-memory",
    runId: "run-memory",
    stepId: "step-memory",
    selection: {
      representationHash: "a".repeat(64),
      assignmentId: "assignment-memory",
      representedAgentId: "agent-recon",
      representedActionType: "service_probe",
      representedActionClass: "port_service_enumeration",
    },
    activeVaultBackedNodeIds: new Set(input.vaultNodeIds ?? input.nodes.map((node) => node.id)),
  });
}

describe("AgentToolMemoryCompiler", () => {
  test("vetoes an exact represented tool when synchronized typed memory records a missing dependency", () => {
    const node = memoryNode({
      id: "memory-missing-dependency",
      verdict: "missing_dependency",
      actionTypes: ["service_probe"],
      actionClasses: ["port_service_enumeration"],
    });
    const result = compile({ hook: "tool_selection", nodes: [node] });
    expect(result.decision).toBe("veto_missing_dependency");
    expect(result.appliedNodeIds).toEqual([node.id]);
    expect(result.selection).toEqual({
      representationHash: "a".repeat(64),
      assignmentId: "assignment-memory",
      representedAgentId: "agent-recon",
      representedActionType: "service_probe",
      representedActionClass: "port_service_enumeration",
    });
    expect(JSON.stringify(result)).not.toContain("target");
    expect(JSON.stringify(result)).not.toContain("arguments");
  });

  test("attests an already represented compatible assignment and leaves unrelated memory unused", () => {
    const compatible = memoryNode({
      id: "memory-agent-compatible",
      hook: "assignment_acceptance",
      verdict: "compatible",
      agentIds: ["agent-recon"],
      actionClasses: ["port_service_enumeration"],
    });
    const unrelated = memoryNode({
      id: "memory-unrelated-tool",
      verdict: "incompatible",
      actionTypes: ["another_tool"],
    });
    const result = compile({
      hook: "assignment_acceptance",
      nodes: [compatible, unrelated],
    });
    expect(result.decision).toBe("attest_compatible");
    expect(result.appliedNodeIds).toEqual([compatible.id]);
    expect(result.ignored[unrelated.id]).toBe("hook_mismatch");
  });

  test("rejects cross-engagement and non-synchronized memory", () => {
    const crossEngagement = memoryNode({
      id: "memory-cross-engagement",
      verdict: "incompatible",
      scope: { kind: "engagement", engagementId: "another-engagement" },
      actionTypes: ["service_probe"],
    });
    const notSynchronized = memoryNode({
      id: "memory-not-synchronized",
      verdict: "missing_dependency",
      actionTypes: ["service_probe"],
    });
    const result = compile({
      hook: "tool_selection",
      nodes: [crossEngagement, notSynchronized],
      vaultNodeIds: [crossEngagement.id],
    });
    expect(result.decision).toBe("no_applicable_memory");
    expect(result.appliedNodeIds).toEqual([]);
    expect(result.ignored[crossEngagement.id]).toBe("scope_mismatch");
    expect(result.ignored[notSynchronized.id]).toBe("node_not_active_vault_backed");
  });

  test("records a truthful empty decision without inventing memory influence", () => {
    const result = compile({ hook: "tool_selection", nodes: [] });
    expect(result.decision).toBe("no_applicable_memory");
    expect(result.candidates).toEqual([]);
    expect(result.appliedNodeIds).toEqual([]);
    expect(result.ignored).toEqual({});
  });
});

function seedCanonicalBoundary(database: SqliteDatabase) {
  database.prepare(`
    INSERT INTO missions (
      id, engagement_id, name, objective, journey, status,
      authorization_status, memory_policy_json, created_by,
      created_at, updated_at, control_plane
    ) VALUES (
      'mission-receipt', 'engagement-receipt', 'Receipt mission',
      'Inspect one approved local service', 'guided', 'active', 'verified',
      '{}', 'operator:test', ?, ?, 'ti_scale'
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, created_at, updated_at, version, control_plane
    ) VALUES (
      'run-receipt', 'mission-receipt', 'guided', 'running', 0,
      'Execute one represented step',
      '{"wallClockMs":60000,"toolCalls":5,"providerTurns":2,"retries":1,"replans":1,"concurrency":1}',
      '{}', ?, ?, 1, 'ti_scale'
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, created_by,
      created_at, activated_at, plan_hash
    ) VALUES ('plan-receipt', 'run-receipt', 1, 'active',
      'One represented local tool action', 'agent:test', ?, ?, ?)
  `).run(NOW, NOW, "b".repeat(64));
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      action_class, risk_class, created_at, updated_at
    ) VALUES (
      'step-receipt', 'plan-receipt', 'run-receipt', 0, 'Reconnaissance',
      'Inspect service', 'Record one bounded response', 'ready',
      'port_service_enumeration', 'low', ?, ?
    )
  `).run(NOW, NOW);
}

describe("AgentToolMemoryDecisionRepository", () => {
  test("persists a hash-linked receipt and marks only applied synchronized nodes used", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    seedCanonicalBoundary(database);
    const memory = new MemoryRepository(database, {
      clock: () => new Date(NOW),
      createId: () => "memory-receipt-compatible",
    });
    const node = memory.createNode({
      nodeType: "tool",
      title: "Reviewed service probe compatibility",
      summary: "The represented service probe is compatible with the local runtime.",
      scope: { kind: "mission", missionId: "mission-receipt" },
      sensitivity: "private",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "Operator reviewed the installed local capability.",
        sources: [{
          sourceType: "mission",
          sourceId: "mission-receipt",
          acquiredAt: NOW,
        }],
      },
      authorType: "operator",
      authorId: "operator:test",
      retentionPolicy: {
        allowGuided: true,
        journeys: ["guided"],
        agentToolDecision: {
          schemaVersion: "1",
          match: {
            hooks: ["tool_selection"],
            actionTypes: ["service_probe"],
            actionClasses: ["port_service_enumeration"],
          },
          effect: {
            verdict: "compatible",
            reasonCode: "reviewed.local_runtime_compatible",
          },
        },
      },
    });
    const brain = new BrainContextService({
      database,
      secondBrain: new SecondBrainService(memory),
    });
    const context = brain.retrieve({
      hook: "tool_selection",
      journey: "guided",
      missionId: "mission-receipt",
      runId: "run-receipt",
      stepId: "step-receipt",
      actorId: "specialist-tool-router",
      actorType: "agent",
      availabilityPolicy: "degraded_allowed",
      query: "service probe compatibility prerequisite",
      queryRedacted: "service probe compatibility",
      allowGlobal: true,
      exactNodeIds: [node.id],
      exactNodeIdsOnly: true,
    });
    database.prepare(`
      INSERT INTO vault_connections (
        id, vault_path, display_name, status, sync_scope_json,
        permission_granted_at, last_sync_at, created_at, updated_at
      ) VALUES (
        'vault-receipt', '/tmp/agent-tool-memory-vault', 'Agent tool memory',
        'connected', '{}', ?, ?, ?, ?
      )
    `).run(NOW, NOW, NOW, NOW);
    database.prepare(`
      INSERT INTO audit_records (
        id, actor_type, actor_id, action, resource_type, resource_id,
        reason, details_json, record_hash, occurred_at
      ) VALUES (
        'audit-vault-receipt-health',
        'operator', 'operator:test', 'vault.health.verified',
        'vault_connection', 'vault-receipt',
        'Disposable Vault round trip passed',
        '{"checks":{"write":true,"read":true,"rename":true,"delete":true}}',
        ?, ?
      )
    `).run("f".repeat(64), NOW);
    database.prepare(`
      INSERT INTO vault_sync_state (
        id, connection_id, node_id, relative_path, database_version,
        vault_content_hash, database_content_hash, status,
        last_scanned_at, last_synced_at
      ) VALUES (
        'vault-state-receipt', 'vault-receipt', ?, '40 Tools and Capabilities/receipt.md',
        1, ?, ?, 'synced', ?, ?
      )
    `).run(node.id, "c".repeat(64), "c".repeat(64), NOW, NOW);
    const repository = new AgentToolMemoryDecisionRepository(database, () => new Date(NOW));
    const compiled = compileAgentToolMemoryDecision({
      hook: "tool_selection",
      context,
      journey: "guided",
      missionId: "mission-receipt",
      engagementId: "engagement-receipt",
      runId: "run-receipt",
      stepId: "step-receipt",
      selection: {
        representationHash: "d".repeat(64),
        representedActionType: "service_probe",
        representedActionClass: "port_service_enumeration",
      },
      activeVaultBackedNodeIds: repository.activeVaultBackedNodeIds(context.contextPack.id),
    });
    const receipt = repository.persist({
      compiled,
      actorId: "specialist-tool-router",
    });
    expect(receipt.decision).toBe("attest_compatible");
    expect(receipt.appliedNodeIds).toEqual([node.id]);
    expect(receipt.representationUnchanged).toBe(true);
    expect(receipt.scopeExpanded).toBe(false);
    expect(receipt.toolChanged).toBe(false);
    expect(receipt.argumentsChanged).toBe(false);
    expect(receipt.decisionAuditRecordId).toBe(receipt.id);
    expect(database.prepare(`
      SELECT action, resource_type, resource_id
      FROM audit_records WHERE id = ?
    `).get(receipt.id)).toEqual({
      action: "brain.agent_tool_memory.decision",
      resource_type: "agent_tool_memory_decision",
      resource_id: receipt.id,
    });
    expect(database.prepare(`
      SELECT used, influence_summary, ignored_reason
      FROM memory_context_items WHERE context_pack_id = ? AND node_id = ?
    `).get(context.contextPack.id, node.id)).toEqual({
      used: 1,
      influence_summary: "Typed synchronized Vault memory attested the already represented agent/tool selection; no field changed.",
      ignored_reason: null,
    });
  });
});

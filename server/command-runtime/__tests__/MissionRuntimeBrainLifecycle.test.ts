import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import type { DurableAction } from "../../orchestration";
import type { RunSupervisor } from "../../supervisor";
import { AttackAttemptService } from "../../run-intelligence";
import type { BrainProviderContextEnvelope } from "../../brain-runtime";
import { canonicalLessonMemoryNodeId } from "../../learning/AttackChainLessonRepository";
import { MemoryRepository } from "../../memory";
import {
  createMissionRuntime,
  type MissionOutcomeEvaluatorPort,
  type MissionPlannerPort,
  type ResultAwareExecutionPort,
} from "..";

const NOW = "2026-07-16T12:00:00.000Z";
const PHASE_RELEVANT_MEMORY_ID = "mem_11111111111111111111111111111111";
const PHASE_UNRELATED_MEMORY_ID = "mem_22222222222222222222222222222222";
const PHASE_UNSYNCED_MEMORY_ID = "mem_33333333333333333333333333333333";
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

class CapturingExecution implements ResultAwareExecutionPort {
  readonly dispatched: DurableAction[] = [];
  async dispatch(action: DurableAction, _signal: AbortSignal): Promise<void> {
    this.dispatched.push(action);
  }
  async resume(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async cancelRun(_runId: string, _reason: string): Promise<void> {}
}

function seed(database: SqliteDatabase) {
  const missionId = "mission-brain-runtime";
  const runId = "run-brain-runtime";
  const agentId = "agent-brain-runtime";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Guided Brain runtime', 'Inspect the authorized lab service',
      'guided', 'active', 'verified', '{}', 'operator:test', ?, ?, 'ti_scale')
  `).run(missionId, NOW, NOW);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-brain-runtime', ?, 'lab.internal', 'domain', 'allowed', 'lab.internal', ?)
  `).run(missionId, NOW);
  database.prepare(`
    INSERT INTO agents (id, role, display_name, status, version, created_at, updated_at)
    VALUES (?, 'recon-specialist', 'Recon specialist', 'available', 'test-1', ?, ?)
  `).run(agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'guided', 'planning', 0, 'Create the first represented Guided step',
      '{"wallClockMs":60000,"toolCalls":10,"providerTurns":10,"retries":2,"replans":2,"concurrency":1}',
      '{}', ?, ?, 1, 'ti_scale')
  `).run(runId, missionId, NOW, NOW);
  return { missionId, runId, agentId };
}

describe("MissionRuntimeEngine mandatory Brain lifecycle order", () => {
  test("retrieves planning, assignment, tool, and canonical attack-attempt context before dispatch", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database);
    const preferenceRepository = new MemoryRepository(database, {
      clock: () => new Date(NOW),
    });
    preferenceRepository.createNode({
      id: "memory-reporting-readability",
      nodeType: "preference",
      title: "Readable technical reports",
      summary: "Use readable technical language while preserving exact evidence meaning.",
      scope: { kind: "global" },
      sensitivity: "private",
      confidence: 1,
      lifecycleStatus: "confirmed",
      confirmationState: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "Explicitly confirmed by the canonical mission creator.",
        sources: [{
          sourceType: "test_fixture",
          sourceId: "reporting-readability",
          acquiredAt: NOW,
        }],
      },
      authorType: "operator",
      authorId: "operator:test",
      retentionPolicy: { allowAutonomous: true, allowGuided: true },
    });
    database.prepare(`
      INSERT INTO preference_profiles (
        id, operator_id, scope, engagement_id, mission_type, preference_key,
        value_json, confirmation_state, confidence, source_node_id,
        consent_policy, version, confirmed_at, created_at, updated_at
      ) VALUES (
        'profile-reporting-readability', 'operator:test', 'global', NULL,
        'guided', 'communication.technical_readability', ?,
        'confirmed', 1, 'memory-reporting-readability',
        'explicit_operator_confirmation', 1, ?, ?, ?
      )
    `).run(JSON.stringify({
      value: {
        style: "technical_readable",
        avoid: ["oversimplified wording", "opaque internal jargon"],
        include: ["purpose", "operational meaning", "useful technical detail"],
      },
      appliesTo: ["reports"],
    }), NOW, NOW, NOW);
    const observedProviderContextIds: string[] = [];
    const observedEvaluatorContextIds: string[] = [];
    let observedPlanningContext: BrainProviderContextEnvelope | undefined;
    const projectedNodeSets: string[][] = [];
    const planner: MissionPlannerPort = {
      async plan(input) {
        observedProviderContextIds.push(input.brainContext.contextPackId);
        observedPlanningContext = input.brainContext;
        return {
          strategySummary: "Collect one bounded service observation",
          rationaleSummary: "A single reversible step reduces uncertainty without broad execution",
          steps: [{
            phase: "Reconnaissance",
            title: "Inspect approved HTTPS service",
            objective: "Confirm whether the approved service responds",
            explanation: "The specialist performs one represented read-only service check.",
            rationale: "The result determines whether deeper authorized analysis is useful.",
            successCriteria: ["A bounded service response is recorded"],
            dependencyOrdinals: [],
            assignedAgentId: fixture.agentId,
            riskClass: "low",
            reversibility: "Read-only and immediately reversible",
            action: {
              actionType: "service_probe",
              actionClass: "port_service_enumeration",
              target: "lab.internal",
              arguments: { target: "lab.internal", port: 443 },
              intentSummary: "Inspect the approved HTTPS service once",
              kind: "tool",
              idempotent: true,
              destructive: false,
            },
          }],
        };
      },
    };
    const evaluator: MissionOutcomeEvaluatorPort = {
      async evaluate(input) {
        observedEvaluatorContextIds.push(input.brainContext.contextPackId);
        expect(input.brainContext.items).toEqual([]);
        return {
          success: true,
          summary: "The represented Guided step completed and the bounded objective was satisfied.",
          criteria: [{
            criterion: "Retain one verified bounded result",
            satisfied: true,
            explanation: "The exact represented action has immutable verified evidence.",
            evidenceIds: ["evidence-brain-runtime"],
          }],
        };
      },
    };
    const execution = new CapturingExecution();
    const runtime = createMissionRuntime({
      database,
      planner,
      outcomeEvaluator: evaluator,
      execution,
      workerId: "brain-runtime-worker",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
      projectMemoryNodes: (nodeIds) => {
        expect(database.inTransaction).toBe(false);
        projectedNodeSets.push([...nodeIds]);
      },
    });
    try {
      await runtime.processRunNow(fixture.runId);
      const decision = database.prepare(`
        SELECT gd.id, gd.step_id, ps.plan_id
        FROM guided_decisions gd
        JOIN plan_steps ps ON ps.id = gd.step_id
        WHERE gd.run_id = ? AND gd.status = 'pending'
      `).get(fixture.runId) as { id: string; step_id: string; plan_id: string };
      database.prepare(`
        INSERT INTO topology_nodes (
          id, mission_id, run_id, node_type, primary_label, normalized_identity,
          scope_status, lifecycle_state, confidence, verification_state,
          sensitivity, first_seen_at, last_seen_at, created_at, updated_at
        ) VALUES (
          'asset-brain-runtime', ?, ?, 'asset', 'Approved lab service', 'lab.internal',
          'allowed', 'observed', 1, 'verified', 'internal', ?, ?, ?, ?
        )
      `).run(fixture.missionId, fixture.runId, NOW, NOW, NOW, NOW);
      const attemptService = new AttackAttemptService(database, () => new Date(NOW));
      const attempt = attemptService.create({
        missionId: fixture.missionId,
        runId: fixture.runId,
        planId: decision.plan_id,
        stepId: decision.step_id,
        targetAssetId: "asset-brain-runtime",
        objective: "Validate one bounded service behavior",
        techniqueName: "Represented HTTPS behavior validation",
        actionClass: "port_service_enumeration",
        assignedAgentId: fixture.agentId,
        normalizedParameters: { target: "lab.internal", port: 443 },
      });
      attemptService.transition({
        attemptId: attempt.id,
        expectedVersion: attempt.version,
        status: "ready",
        actorId: "operator:test",
        actorType: "operator",
      });
      const action = await runtime.approveGuidedDecision(
        decision.id,
        "operator:test",
        "Run this exact represented read-only step",
      );
      expect(execution.dispatched).toHaveLength(1);
      expect(action.contextPackId).toBeTruthy();
      expect(execution.dispatched[0]?.contextPackId).toBe(action.contextPackId);
      database.prepare(`
        INSERT INTO tool_calls (
          id, action_id, provider, tool_name, mcp_server_id,
          normalized_arguments_json, status, started_at, created_at
        ) VALUES (
          'tool-call-brain-runtime', ?, 'specialist-mcp', 'service_probe',
          'specialist-mcp', '{}', 'running', ?, ?
        )
      `).run(action.id, NOW, NOW);
      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, step_id, action_id, source, acquired_at,
          target, evidence_type, content_hash, provenance_json, confidence,
          sensitivity, verification_state, summary, created_by, created_at
        ) VALUES (
          'evidence-brain-runtime', ?, ?, ?, ?, 'specialist', ?,
          'lab.internal', 'service_observation', ?, '{}', 1,
          'restricted', 'verified',
          'Bounded result token=do-not-project remains only in immutable evidence',
          ?, ?
        )
      `).run(
        fixture.missionId,
        fixture.runId,
        action.stepId,
        action.id,
        NOW,
        "a".repeat(64),
        fixture.agentId,
        NOW,
      );
      database.prepare(`
        INSERT INTO engagement_log_records (
          id, mission_id, run_id, step_id, action_id, agent_id, tool_call_id,
          severity, domain, record_type, human_summary, technical_payload_json,
          content_hash, sensitivity, occurred_at, created_at
        ) VALUES
          ('log-phase-current', ?, ?, ?, ?, ?, 'tool-call-brain-runtime',
            'info', 'tool', 'structured_result', 'Current action parser input', '{}', ?, 'internal', ?, ?),
          ('log-phase-unrelated', ?, ?, ?, NULL, ?, NULL,
            'info', 'tool', 'structured_result', 'Unrelated same-step parser input', '{}', ?, 'internal', ?, ?)
      `).run(
        fixture.missionId, fixture.runId, action.stepId, action.id, fixture.agentId,
        "b".repeat(64), NOW, NOW,
        fixture.missionId, fixture.runId, action.stepId, fixture.agentId,
        "c".repeat(64), NOW, NOW,
      );
      database.prepare(`
        INSERT INTO observations (
          id, mission_id, run_id, step_id, observation_type, statement,
          normalized_value_json, confidence, verification_state, source_agent_id,
          source_tool, first_seen_at, last_seen_at, sensitivity, created_at
        ) VALUES
          ('observation-phase-current', ?, ?, ?, 'service_fingerprint',
            'Current action identified the reviewed service.',
            '{"product":"fixture-service","version":"1.0"}', 1, 'corroborated', ?,
            'service_probe', ?, ?, 'internal', ?),
          ('observation-phase-unrelated', ?, ?, ?, 'service_fingerprint',
            'Unrelated same-step observation must not influence this action.',
            '{"product":"unrelated-service","version":"9.9"}', 1, 'corroborated', ?,
            'other_probe', ?, ?, 'internal', ?)
      `).run(
        fixture.missionId, fixture.runId, action.stepId, fixture.agentId, NOW, NOW, NOW,
        fixture.missionId, fixture.runId, action.stepId, fixture.agentId, NOW, NOW, NOW,
      );
      database.prepare(`
        INSERT INTO observation_log_sources (
          observation_id, log_record_id, parser_id, parser_version, created_at
        ) VALUES
          ('observation-phase-current', 'log-phase-current', 'fixture-parser', '1', ?),
          ('observation-phase-unrelated', 'log-phase-unrelated', 'fixture-parser', '1', ?)
      `).run(NOW, NOW);
      preferenceRepository.createNode({
        id: "memory-finding-validation-lesson",
        nodeType: "lesson",
        title: "Verified evidence comparison pattern",
        summary: "Cross-check verified evidence before accepting a terminal finding or success claim.",
        scope: { kind: "mission", missionId: fixture.missionId },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: {
          method: "derived",
          explanation: "Focused runtime lifecycle fixture.",
          sources: [{ sourceType: "test_fixture", sourceId: "finding-validation", acquiredAt: NOW }],
        },
        authorType: "system",
        authorId: "test",
        retentionPolicy: { allowAutonomous: true, allowGuided: true },
      });
      preferenceRepository.createNode({
        id: PHASE_RELEVANT_MEMORY_ID,
        nodeType: "discovery_pattern",
        title: "Fixture service 1.0 HTTPS reconnaissance",
        summary: "Use a bounded service probe and preserve the exact service fingerprint before the next web decision.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: {
          method: "derived",
          explanation: "Relevant active-Vault phase-memory fixture.",
          sources: [{ sourceType: "test_fixture", sourceId: "phase-web-recon", acquiredAt: NOW }],
        },
        authorType: "operator",
        authorId: "operator:test",
        retentionPolicy: { allowAutonomous: true, allowGuided: true },
      });
      preferenceRepository.createNode({
        id: PHASE_UNRELATED_MEMORY_ID,
        nodeType: "kernel",
        title: "RDX kernel 6.1 service-probe reconnaissance history",
        summary: "A different technology stack recorded unrelated historical version attributes.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: {
          method: "derived",
          explanation: "Unrelated active-Vault phase-memory fixture.",
          sources: [{ sourceType: "test_fixture", sourceId: "phase-rdx-kernel", acquiredAt: NOW }],
        },
        authorType: "operator",
        authorId: "operator:test",
        retentionPolicy: { allowAutonomous: true, allowGuided: true },
      });
      preferenceRepository.createNode({
        id: PHASE_UNSYNCED_MEMORY_ID,
        nodeType: "discovery_pattern",
        title: "Fixture service 1.0 web reconnaissance fallback",
        summary: "This otherwise relevant item is not synchronized to the connected active Vault.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: {
          method: "derived",
          explanation: "Unsynchronized phase-memory fixture.",
          sources: [{ sourceType: "test_fixture", sourceId: "phase-web-unsynced", acquiredAt: NOW }],
        },
        authorType: "operator",
        authorId: "operator:test",
        retentionPolicy: { allowAutonomous: true, allowGuided: true },
      });
      database.prepare(`
        INSERT INTO vault_connections (
          id, vault_path, display_name, status, sync_scope_json,
          permission_granted_at, last_sync_at, created_at, updated_at
        ) VALUES (
          'vault-phase-relevance', '/tmp/vault-phase-relevance',
          'Phase relevance Vault', 'connected', '{}', ?, ?, ?, ?
        )
      `).run(NOW, NOW, NOW, NOW);
      database.prepare(`
        INSERT INTO audit_records (
          id, actor_type, actor_id, action, resource_type, resource_id,
          reason, details_json, record_hash, occurred_at
        ) VALUES (
          'audit-vault-phase-relevance-health',
          'operator', 'operator:test', 'vault.health.verified',
          'vault_connection', 'vault-phase-relevance',
          'Disposable Vault completed its round-trip fixture',
          '{"checks":{"write":true,"read":true,"rename":true,"delete":true}}',
          ?, ?
        )
      `).run("f".repeat(64), NOW);
      database.prepare(`
        INSERT INTO vault_sync_state (
          id, connection_id, node_id, relative_path, database_version,
          vault_content_hash, database_content_hash, status,
          last_scanned_at, last_synced_at
        ) VALUES
          ('vault-sync-phase-relevant', 'vault-phase-relevance',
            ?,
            '30 Attack Patterns/Fixture service web reconnaissance.md',
            1, ?, ?, 'synced', ?, ?),
          ('vault-sync-phase-unrelated', 'vault-phase-relevance',
            ?,
            '32 Applications and Services/RDX kernel history.md',
            1, ?, ?, 'synced', ?, ?)
      `).run(
        PHASE_RELEVANT_MEMORY_ID,
        "d".repeat(64), "d".repeat(64), NOW, NOW,
        PHASE_UNRELATED_MEMORY_ID,
        "e".repeat(64), "e".repeat(64), NOW, NOW,
      );
      const receipt = await runtime.acceptExecutionResult({
        actionId: action.id,
        runId: fixture.runId,
        actionFingerprint: action.fingerprint,
        success: true,
        summary: "The approved HTTPS service returned one bounded response.",
        progress: { uncertainty: 0.25 },
      });
      expect(receipt.runState).toBe("completed");
      expect(database.prepare(`
        SELECT status, error_category, output_summary, ended_at
        FROM tool_calls WHERE id = 'tool-call-brain-runtime'
      `).get()).toEqual({
        status: "succeeded",
        error_category: null,
        output_summary: "The approved HTTPS service returned one bounded response.",
        ended_at: NOW,
      });
      const hooks = database.prepare(`
        SELECT json_extract(details_json, '$.hook') AS hook,
          json_extract(details_json, '$.status') AS status,
          json_extract(details_json, '$.contextPackId') AS context_pack_id
        FROM audit_records
        WHERE run_id = ? AND action = 'brain.context_hook.invoked'
        ORDER BY rowid
      `).all(fixture.runId) as Array<{
        hook: string;
        status: string;
        context_pack_id: string;
      }>;
      expect(hooks.map(({ hook }) => hook)).toEqual([
        "planning",
        "assignment_acceptance",
        "tool_selection",
        "attack_attempt",
        "phase_transition",
        "evaluation",
        "finding_validation",
        "lesson_proposal",
        "reporting",
        "closeout",
      ]);
      expect(hooks.map(({ status }) => status)).toEqual([
        "ready",
        "no_relevant_memory",
        "no_relevant_memory",
        "no_relevant_memory",
        "ready",
        "ready",
        "ready",
        "ready",
        "ready",
        "ready",
      ]);
      expect(observedProviderContextIds).toEqual([hooks[0]!.context_pack_id]);
      expect(observedEvaluatorContextIds).toEqual([hooks[5]!.context_pack_id]);
      expect(observedPlanningContext).toMatchObject({
        status: "ready",
        trust: "untrusted_memory_summary",
        items: [
          { nodeType: "mission" },
          { nodeType: "run" },
        ],
        rejected: [],
      });
      expect(action.contextPackId).toBe(hooks[3]!.context_pack_id);
      expect(database.prepare(`
        SELECT step_id, action_id, created_by
        FROM memory_context_packs
        WHERE id = ? AND purpose LIKE 'Attack attempt:%'
      `).get(action.contextPackId!)).toEqual({
        step_id: decision.step_id,
        action_id: null,
        created_by: fixture.agentId,
      });
      expect(database.prepare(`
        SELECT used, influence_summary, ignored_reason
        FROM memory_context_items
        WHERE context_pack_id = ? AND node_id = ?
      `).get(hooks[4]!.context_pack_id, PHASE_RELEVANT_MEMORY_ID)).toMatchObject({
        used: 1,
        influence_summary: expect.stringContaining("active-Vault-backed memory"),
        ignored_reason: null,
      });
      expect(database.prepare(`
        SELECT used, influence_summary, ignored_reason
        FROM memory_context_items
        WHERE context_pack_id = ? AND node_id = ?
      `).get(hooks[4]!.context_pack_id, PHASE_UNRELATED_MEMORY_ID)).toMatchObject({
        used: 0,
        influence_summary: null,
        ignored_reason: expect.stringContaining("not both active-Vault-backed and deterministically relevant"),
      });
      expect(database.prepare(`
        SELECT used, influence_summary, ignored_reason
        FROM memory_context_items
        WHERE context_pack_id = ? AND node_id = ?
      `).get(hooks[4]!.context_pack_id, PHASE_UNSYNCED_MEMORY_ID)).toMatchObject({
        used: 0,
        influence_summary: null,
        ignored_reason: expect.stringContaining("not both active-Vault-backed and deterministically relevant"),
      });
      expect(database.prepare(`
        SELECT json_extract(payload_json, '$.usedNodeIds') AS used_node_ids,
          json_extract(payload_json, '$.activeVaultCandidateCount') AS active_vault_candidates,
          json_extract(payload_json, '$.semanticallyRelevantCount') AS relevant_candidates
        FROM events
        WHERE run_id = ? AND event_type = 'brain.phase_transition_guard_selected'
        ORDER BY sequence DESC LIMIT 1
      `).get(fixture.runId)).toEqual({
        used_node_ids: JSON.stringify([PHASE_RELEVANT_MEMORY_ID]),
        active_vault_candidates: 2,
        relevant_candidates: 1,
      });
      expect(database.prepare(`
        SELECT query_redacted FROM memory_context_packs WHERE id = ?
      `).get(hooks[4]!.context_pack_id)).toEqual({
        query_redacted: "Refresh scoped phase context from 1 canonical parsed observation(s) and 1 verified evidence type(s); raw action output was excluded.",
      });
      expect(database.prepare(`
        SELECT used, influence_summary, ignored_reason
        FROM memory_context_items
        WHERE context_pack_id = ? AND node_id = 'memory-finding-validation-lesson'
      `).get(hooks[6]!.context_pack_id)).toMatchObject({
        used: 1,
        influence_summary: expect.stringContaining("canonical verified evidence"),
        ignored_reason: null,
      });
      const reportingUsed = database.prepare(`
        SELECT mn.node_type
        FROM memory_context_items mci
        JOIN memory_nodes mn ON mn.id = mci.node_id
        WHERE mci.context_pack_id = ? AND mci.used = 1
        ORDER BY mn.node_type
      `).all(hooks[8]!.context_pack_id) as Array<{ node_type: string }>;
      expect(reportingUsed.map(({ node_type }) => node_type)).toContain("evaluation");
      expect(reportingUsed.every(({ node_type }) => ["evaluation", "lesson"].includes(node_type))).toBe(true);
      expect(database.prepare(`
        SELECT mci.used, mci.ignored_reason
        FROM memory_context_items mci
        WHERE mci.context_pack_id = ?
          AND mci.node_id = 'memory-reporting-readability'
      `).get(hooks[8]!.context_pack_id)).toMatchObject({
        used: 0,
        ignored_reason: expect.stringContaining("not an evaluation or lesson"),
      });
      const closeoutUsed = database.prepare(`
        SELECT mn.node_type
        FROM memory_context_items mci
        JOIN memory_nodes mn ON mn.id = mci.node_id
        WHERE mci.context_pack_id = ? AND mci.used = 1
        ORDER BY mn.node_type
      `).all(hooks[9]!.context_pack_id) as Array<{ node_type: string }>;
      expect(closeoutUsed.map(({ node_type }) => node_type)).toEqual(
        expect.arrayContaining(["evaluation", "mission", "run"]),
      );
      expect(database.prepare(`
        SELECT json_extract(payload_json, '$.reportingContextPackId') AS reporting_pack,
          json_extract(payload_json, '$.closeoutContextPackId') AS closeout_pack
        FROM events
        WHERE run_id = ? AND event_type = 'brain.terminal_projection_context_selected'
        ORDER BY sequence DESC LIMIT 1
      `).get(fixture.runId)).toEqual({
        reporting_pack: hooks[8]!.context_pack_id,
        closeout_pack: hooks[9]!.context_pack_id,
      });

      const lessonId = (database.prepare(`
        SELECT lesson_id FROM lesson_evidence WHERE run_id = ?
      `).get(fixture.runId) as { lesson_id: string }).lesson_id;
      const projectedNodeIds = projectedNodeSets.at(-1)!;
      expect(projectedNodeIds).toHaveLength(4);
      expect(projectedNodeIds).toContain(canonicalLessonMemoryNodeId(lessonId));
      expect(database.prepare(`
        SELECT node_type, lifecycle_status, confirmation_state, author_type, author_id
        FROM memory_nodes WHERE id IN (${projectedNodeIds.map(() => "?").join(",")})
        ORDER BY node_type
      `).all(...projectedNodeIds)).toEqual([
        {
          node_type: "evaluation",
          lifecycle_status: "verified",
          confirmation_state: "not_required",
          author_type: "agent",
          author_id: "run-evaluator",
        },
        {
          node_type: "lesson",
          lifecycle_status: "candidate",
          confirmation_state: "pending",
          author_type: "agent",
          author_id: "run-evaluator",
        },
        {
          node_type: "mission",
          lifecycle_status: "verified",
          confirmation_state: "not_required",
          author_type: "system",
          author_id: "system:canonical-mission-memory",
        },
        {
          node_type: "run",
          lifecycle_status: "verified",
          confirmation_state: "not_required",
          author_type: "system",
          author_id: "system:canonical-mission-memory",
        },
      ]);
      const projectedText = (database.prepare(`
        SELECT group_concat(title || ' ' || summary || ' ' || body, ' ')
          AS content
        FROM memory_nodes WHERE id IN (${projectedNodeIds.map(() => "?").join(",")})
      `).get(...projectedNodeIds) as { content: string }).content;
      expect(projectedText).not.toContain("token=do-not-project");
      expect(database.prepare(`
        SELECT status, attempt_count FROM runtime_continuations
        WHERE run_id = ? AND kind = 'memory_projection_pending'
      `).get(fixture.runId)).toEqual({ status: "completed", attempt_count: 1 });

      // Reproduce the pre-fix restart shape: the evaluation/lesson graph is
      // canonical, but no projection continuation survived. Startup
      // reconciliation must rebuild it once; replay remains idempotent.
      database.prepare(`
        DELETE FROM runtime_continuations
        WHERE run_id = ? AND kind = 'memory_projection_pending'
      `).run(fixture.runId);
      projectedNodeSets.splice(0);
      expect(runtime.continuations.reconcileFromCanonicalState(NOW, "ti_scale")).toBe(1);
      expect(await runtime.replayContinuations(
        fixture.runId,
        ["memory_projection_pending"],
      )).toBe(1);
      expect(projectedNodeSets).toEqual([projectedNodeIds]);
      expect(runtime.continuations.reconcileFromCanonicalState(NOW, "ti_scale")).toBe(0);
      expect(await runtime.replayContinuations(
        fixture.runId,
        ["memory_projection_pending"],
      )).toBe(0);
    } finally {
      await runtime.stop();
    }
  });

  test("persists action-scoped failure context before the supervisor chooses recovery", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database);
    const planner: MissionPlannerPort = {
      async plan() {
        return {
          strategySummary: "Collect one bounded service observation",
          rationaleSummary: "A single reversible step reduces uncertainty",
          steps: [{
            phase: "Reconnaissance",
            title: "Inspect approved HTTPS service",
            objective: "Confirm whether the approved service responds",
            explanation: "Perform one represented read-only service check.",
            rationale: "The result determines the next authorized step.",
            successCriteria: ["A bounded response is recorded"],
            dependencyOrdinals: [],
            assignedAgentId: fixture.agentId,
            riskClass: "low",
            reversibility: "Read-only and immediately reversible",
            action: {
              actionType: "service_probe",
              actionClass: "port_service_enumeration",
              target: "lab.internal",
              arguments: { target: "lab.internal", port: 443 },
              intentSummary: "Inspect the approved HTTPS service once",
              kind: "tool",
              idempotent: true,
              destructive: false,
            },
          }],
        };
      },
    };
    const execution = new CapturingExecution();
    const runtime = createMissionRuntime({
      database,
      planner,
      outcomeEvaluator: { async evaluate() { throw new Error("blocked run must not evaluate"); } },
      execution,
      workerId: "brain-recovery-order-worker",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
    });
    try {
      await runtime.processRunNow(fixture.runId);
      const decision = database.prepare(`
        SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending'
      `).get(fixture.runId) as { id: string };
      const action = await runtime.approveGuidedDecision(
        decision.id,
        "operator:test",
        "Run this exact represented read-only step",
      );

      const order: string[] = [];
      const originalRetrieve = runtime.brainContext.retrieve.bind(runtime.brainContext);
      runtime.brainContext.retrieve = (request) => {
        if (request.hook === "failure") order.push("failure_context");
        return originalRetrieve(request);
      };
      const supervisor = (runtime.coordinator as unknown as { supervisor: RunSupervisor }).supervisor;
      const originalDecision = supervisor.decideRecovery.bind(supervisor);
      supervisor.decideRecovery = (input) => {
        order.push("recovery_decision");
        expect(order[0]).toBe("failure_context");
        return originalDecision(input);
      };

      const receipt = await runtime.acceptExecutionResult({
        actionId: action.id,
        runId: fixture.runId,
        actionFingerprint: action.fingerprint,
        success: false,
        summary: "The represented action was denied by the local policy boundary.",
        failureCategory: "policy_denied",
        progress: {},
      });
      expect(receipt.runState).toBe("blocked");
      expect(order).toEqual(["failure_context", "recovery_decision"]);
      expect(database.prepare(`
        SELECT step_id, action_id FROM memory_context_packs
        WHERE run_id = ? AND purpose LIKE 'Failure handling:%'
      `).get(fixture.runId)).toEqual({ step_id: action.stepId, action_id: action.id });
    } finally {
      await runtime.stop();
    }
  });
});

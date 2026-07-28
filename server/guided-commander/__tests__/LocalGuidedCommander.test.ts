import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { BrainContextService } from "../../brain-runtime";
import { ControlPlaneLeaseService } from "../../control-plane";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository, SecondBrainService } from "../../memory";
import { canonicalJson } from "../../missions/canonical";
import { fingerprintAction } from "../../supervisor";
import { createLocalGuidedManualInterpreterRouter } from "../LocalGuidedManualInterpreter";

const servers: Server[] = [];
const NOW = "2026-07-20T08:00:00.000Z";
const IDS = {
  mission: "mission-local-guidance",
  run: "run-local-guidance",
  plan: "plan-local-guidance",
  step: "step-local-guidance",
  agent: "agent-local-guidance",
  assignment: "assignment-local-guidance",
  decision: "decision-local-guidance",
  observation: "observation-local-guidance",
  action: "action-local-guidance",
  toolCall: "local_tool_local_guidance",
  log: "log-local-guidance",
};
const REPRESENTED_ACTION = {
  actionType: "kali:nmap-tcp-connect-service-scan",
  actionClass: "port_service_enumeration",
  target: "192.0.2.20",
  arguments: {
    schemaVersion: "ti-scale.reviewed-local-tool-action.v1",
    executionBinding: "reviewed_local_process",
    toolId: "kali:nmap-tcp-connect-service-scan",
    parameters: { workspace: "/engagements", target: "192.0.2.20", ports: "22,80" },
  },
  intentSummary: "Check TCP ports 22 and 80 on the exact approved host",
  kind: "tool",
  idempotent: true,
  destructive: false,
};
const REPRESENTED_INTENT = {
  missionId: IDS.mission,
  runId: IDS.run,
  stepId: IDS.step,
  assignmentId: IDS.assignment,
  planVersion: 1,
  ...REPRESENTED_ACTION,
};
const FINGERPRINT = fingerprintAction(REPRESENTED_INTENT).hash;

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) =>
    new Promise<void>((resolve) => server.close(() => resolve()))));
});

function seed(database: SqliteDatabase, terminal = false): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      scope_json, created_by, created_at, updated_at
    ) VALUES (?, 'Local Guided mission', 'Establish the exact approved host service baseline',
      'guided', ?, 'verified', 'eng-local-guidance', ?, 'operator:test', ?, ?)
  `).run(
    IDS.mission,
    terminal ? "completed" : "active",
    canonicalJson({ allowedTargets: ["192.0.2.20"] }),
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-local-guidance', ?, '192.0.2.20', 'ip', 'allowed', '192.0.2.20', ?)
  `).run(IDS.mission, NOW);
  database.prepare(`
    INSERT INTO agents (id, role, display_name, status, version, created_at, updated_at)
    VALUES (?, 'recon', 'Local Recon Specialist', 'available', '1', ?, ?)
  `).run(IDS.agent, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, current_plan_id, current_step_id,
      current_owner_id, progress, status_reason, next_action_summary,
      started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, 'guided', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    IDS.run,
    IDS.mission,
    terminal ? "completed" : "waiting_guided_decision",
    IDS.plan,
    IDS.step,
    IDS.agent,
    terminal ? 1 : 0,
    terminal ? "One exact reviewed tool step completed" : "Waiting for one exact decision",
    terminal ? "Review the canonical result" : "Review the exact action card",
    NOW,
    terminal ? NOW : null,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, ?, 'Check one bounded port set', 'Do not scan neighboring ports',
      ?, 'local-guided-planner', ?, ?)
  `).run(IDS.plan, IDS.run, terminal ? "completed" : "active", "b".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'Service baseline', 'Check selected TCP services',
      'Identify responding services on the exact approved host', ?, ?, '[]',
      'port_service_enumeration', 'medium', ?, ?, ?, ?, ?)
  `).run(
    IDS.step,
    IDS.plan,
    IDS.run,
    terminal ? "completed" : "waiting_guided_decision",
    canonicalJson([
      "Only the exact selected ports were checked",
      "Open services are retained as attributable observations",
    ]),
    IDS.agent,
    terminal ? NOW : null,
    terminal ? NOW : null,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO assignments (id, run_id, step_id, agent_id, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(IDS.assignment, IDS.run, IDS.step, IDS.agent, terminal ? "completed" : "queued", NOW, NOW);
  database.prepare(`
    INSERT INTO mission_constraints (
      id, mission_id, constraint_type, value_json, source, created_at
    ) VALUES ('constraint-local-guidance', ?, 'represented_action', ?, ?, ?)
  `).run(IDS.mission, canonicalJson({
    action: REPRESENTED_ACTION,
    explanation: "Check two selected TCP ports using ordinary bounded connections.",
    rationale: "Service observations determine whether deeper authorized work is justified.",
    reversibility: "The connection-only process can be cancelled and makes no target change.",
  }), IDS.step, NOW);
  database.prepare(`
    INSERT INTO guided_decisions (
      id, mission_id, run_id, step_id, requested_action_fingerprint,
      requested_parameters_json, rationale, risk_class, reversibility,
      status, decision_actor, decided_at, expires_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'Check only the exact represented ports', 'medium',
      'Connection-only and cancellable', ?, ?, ?, '2099-01-01T00:00:00.000Z', ?)
  `).run(
    IDS.decision,
    IDS.mission,
    IDS.run,
    IDS.step,
    FINGERPRINT,
    canonicalJson(REPRESENTED_INTENT),
    terminal ? "approved" : "pending",
    terminal ? "operator:test" : null,
    terminal ? NOW : null,
    NOW,
  );
  database.prepare(`
    INSERT INTO checkpoints (
      id, mission_id, run_id, journey, event_sequence, plan_version,
      state_json, state_hash, created_at
    ) VALUES ('checkpoint-local-guidance', ?, ?, 'guided', 0, 1, '{}', ?, ?)
  `).run(IDS.mission, IDS.run, "c".repeat(64), NOW);
  if (!terminal) return;

  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, assignment_id, action_type, action_class,
      fingerprint, normalized_arguments_json, scoped_target, status, intent_summary,
      result_summary, guided_decision_id, started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'kali:nmap-tcp-connect-service-scan',
      'port_service_enumeration', ?, ?, '192.0.2.20', 'succeeded',
      'Check only ports 22 and 80', 'One open service was observed', ?, ?, ?, ?, ?)
  `).run(
    IDS.action,
    IDS.mission,
    IDS.run,
    IDS.step,
    IDS.assignment,
    FINGERPRINT,
    canonicalJson(REPRESENTED_ACTION.arguments),
    IDS.decision,
    NOW,
    NOW,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO tool_calls (
      id, action_id, provider, tool_name, normalized_arguments_json, status,
      latency_ms, output_summary, started_at, ended_at, created_at
    ) VALUES (?, ?, 'reviewed-local-process', 'kali:nmap-tcp-connect-service-scan',
      ?, 'succeeded', 40, 'One open service was observed', ?, ?, ?)
  `).run(IDS.toolCall, IDS.action, canonicalJson(REPRESENTED_ACTION.arguments), NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO engagement_log_records (
      id, mission_id, run_id, plan_id, step_id, action_id, agent_id, tool_call_id,
      severity, domain, record_type, human_summary, technical_payload_json,
      content_hash, sensitivity, occurred_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'notice', 'local_tool_execution',
      'bounded_process_output', 'The reviewed scan completed', ?, ?, 'private', ?, ?)
  `).run(
    IDS.log,
    IDS.mission,
    IDS.run,
    IDS.plan,
    IDS.step,
    IDS.action,
    IDS.agent,
    IDS.toolCall,
    canonicalJson({ stdout: "RAW_OUTPUT_MUST_NOT_BE_READ", outputSha256: "d".repeat(64) }),
    "e".repeat(64),
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO observations (
      id, mission_id, run_id, step_id, observation_type, statement,
      normalized_value_json, confidence, verification_state, source_agent_id,
      source_tool, first_seen_at, last_seen_at, sensitivity, created_at
    ) VALUES (?, ?, ?, ?, 'tcp_service_scan',
      'The approved scan checked two ports and found one open service.', ?, 0.95,
      'unverified', ?, 'kali:nmap-tcp-connect-service-scan', ?, ?, 'private', ?)
  `).run(
    IDS.observation,
    IDS.mission,
    IDS.run,
    IDS.step,
    canonicalJson({
      schemaVersion: "ti-scale.reviewed-local-tool-observation.v1",
      semanticOutcome: "positive_observation",
      missionId: IDS.mission,
      runId: IDS.run,
      stepId: IDS.step,
      actionId: IDS.action,
      toolCallId: IDS.toolCall,
      toolId: "kali:nmap-tcp-connect-service-scan",
      target: "192.0.2.20",
      result: {
        host: "192.0.2.20",
        requestedPorts: [22, 80],
        openPortCount: 1,
        openPorts: [{ port: 80, transport: "tcp", state: "open", service: "http", version: "nginx 1.24" }],
      },
      provenance: { logRecordId: IDS.log, actionId: IDS.action, toolCallId: IDS.toolCall },
    }),
    IDS.agent,
    NOW,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO observation_log_sources (
      observation_id, log_record_id, parser_id, parser_version, created_at
    ) VALUES (?, ?, 'ti-scale.reviewed-local-tool-normalizer', '1.1.0', ?)
  `).run(IDS.observation, IDS.log, NOW);
}

async function fixture(terminal = false): Promise<{ database: SqliteDatabase; url: string }> {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  seed(database, terminal);
  const memory = new MemoryRepository(database);
  const secondBrain = new SecondBrainService(memory);
  const brainContext = new BrainContextService({ database, secondBrain });
  if (!terminal) {
    memory.createNode({
      id: "memory-local-guidance",
      nodeType: "preference",
      title: "Service baseline explanation preference",
      summary: "Explain the exact approved host service baseline in readable technical language",
      body: "For a Guided service baseline step, keep protocol terms but explain their operational meaning.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "confirmed",
      confirmationState: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "Confirmed by operator",
        sources: [{ sourceType: "message", sourceId: "message-preference", acquiredAt: NOW }],
      },
      authorType: "operator",
      authorId: "operator:test",
      retentionPolicy: { allowGuided: true, publicProviderDisclosure: "local_only" },
    });
  }
  const leases = new ControlPlaneLeaseService(database);
  const token = "local-guidance-test-token-00000001";
  if (!terminal) {
    leases.acquire({
      runId: IDS.run,
      controlPlane: "ti_scale",
      leaseOwner: "local-guidance-runtime",
      leaseToken: token,
      ttlMs: 300_000,
    });
  }
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(createLocalGuidedManualInterpreterRouter({
    database,
    brainContext,
    resolveActor: () => "operator:test",
    ...(terminal ? {} : {
      assertRunMutationLease: ({ runId }: { readonly runId: string }) =>
        leases.assertMutationAuthority({
          runId,
          controlPlane: "ti_scale",
          leaseOwner: "local-guidance-runtime",
          leaseToken: token,
        }),
    }),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return { database, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

describe("provider-independent local Guided Commander", () => {
  test("persists one lease-fenced exact-step briefing and Context Pack without execution", async () => {
    const { database, url } = await fixture();
    const response = await fetch(`${url}/api/v2/guided/${IDS.mission}/commander/show-next-step`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "local-guidance-show-next-0001",
      },
      body: JSON.stringify({
        runId: IDS.run,
        stepId: IDS.step,
        expectedFingerprint: FINGERPRINT,
      }),
    });
    const payload = await response.json() as Record<string, any>;
    expect({ status: response.status, payload }).toMatchObject({ status: 200 });
    expect(payload.guidance).toEqual({
      mode: "local_deterministic",
      providerContacted: false,
      toolDispatched: false,
      targetContacted: false,
      planMutated: false,
      exactDecisionRequired: true,
    });
    expect(payload.result.assistantMessage.body).toContain("Phase — Service baseline");
    expect(payload.result.assistantMessage.body).toContain("Exact scope — 192.0.2.20");
    expect(payload.result.assistantMessage.body).toContain("Only the exact decision card can authorize one represented action");
    expect(payload.result.assistantMessage.structuredContent).toMatchObject({
      guidanceMode: "local_deterministic",
      providerContacted: false,
      toolDispatched: false,
      nextConsequentialActionRequiresDecision: true,
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM conversations").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM messages").get()).toEqual({ count: 2 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_context_packs WHERE run_id = ?").get(IDS.run))
      .toEqual({ count: 1 });
    expect(database.prepare(`
      SELECT used, ignored_reason FROM memory_context_items
      WHERE context_pack_id = ? AND node_id = 'memory-local-guidance'
    `).get(payload.result.contextPackId)).toMatchObject({
      used: 0,
      ignored_reason: expect.stringContaining("canonical mission, plan, decision"),
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM checkpoints WHERE run_id = ?").get(IDS.run))
      .toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?").get(IDS.run))
      .toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM provider_turns").get()).toEqual({ count: 0 });

    const replay = await fetch(`${url}/api/v2/guided/${IDS.mission}/commander/show-next-step`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "local-guidance-show-next-0001",
      },
      body: JSON.stringify({ runId: IDS.run, stepId: IDS.step, expectedFingerprint: FINGERPRINT }),
    });
    expect(replay.status).toBe(200);
    expect(database.prepare("SELECT COUNT(*) AS count FROM messages").get()).toEqual({ count: 2 });
  });

  test("reads and explains one completed reviewed observation without mutating the terminal run", async () => {
    const { database, url } = await fixture(true);
    const before = {
      messages: database.prepare("SELECT COUNT(*) AS count FROM messages").get(),
      evidence: database.prepare("SELECT COUNT(*) AS count FROM evidence").get(),
      candidates: database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get(),
      checkpoints: database.prepare("SELECT COUNT(*) AS count FROM checkpoints").get(),
      events: database.prepare("SELECT COUNT(*) AS count FROM events").get(),
    };
    const response = await fetch(
      `${url}/api/v2/guided/${IDS.mission}/commander/reviewed-observations/${IDS.observation}/interpretation?runId=${IDS.run}`,
    );
    expect(response.status).toBe(200);
    const payload = await response.json() as Record<string, any>;
    expect(payload.interpretation).toEqual({
      mode: "local_deterministic_canonical_read",
      terminalRunMutated: false,
      rawLogRead: false,
      evidencePromoted: false,
      providerContacted: false,
    });
    expect(payload.result).toMatchObject({
      observationId: IDS.observation,
      verificationState: "unverified",
      sourceTool: "kali:nmap-tcp-connect-service-scan",
      meaning: expect.stringContaining("TCP/80 http — nginx 1.24"),
      evidencePromoted: false,
      rawLogRead: false,
    });
    expect(JSON.stringify(payload)).not.toContain("RAW_OUTPUT_MUST_NOT_BE_READ");
    expect(database.prepare("SELECT status FROM runs WHERE id = ?").get(IDS.run)).toEqual({ status: "completed" });
    expect({
      messages: database.prepare("SELECT COUNT(*) AS count FROM messages").get(),
      evidence: database.prepare("SELECT COUNT(*) AS count FROM evidence").get(),
      candidates: database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get(),
      checkpoints: database.prepare("SELECT COUNT(*) AS count FROM checkpoints").get(),
      events: database.prepare("SELECT COUNT(*) AS count FROM events").get(),
    }).toEqual(before);
  });

  test("fails stale fingerprints before any briefing or context persistence", async () => {
    const { database, url } = await fixture();
    const response = await fetch(`${url}/api/v2/guided/${IDS.mission}/commander/explain-more`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "local-guidance-stale-fingerprint-0001",
      },
      body: JSON.stringify({ runId: IDS.run, stepId: IDS.step, expectedFingerprint: "a".repeat(64) }),
    });
    expect(response.status).toBe(409);
    const payload = await response.json() as Record<string, any>;
    expect(payload.error.code).toBe("guided_action_changed");
    expect(database.prepare("SELECT COUNT(*) AS count FROM messages").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_context_packs").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM actions").get()).toEqual({ count: 0 });
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { ControlPlaneLeaseService } from "../../control-plane";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { AttackChainLearningService } from "../../learning";
import { hashJson } from "../../orchestration/serialization";
import { recoveryProviderRouteSettingKey } from "../recoveryProviderRoute";
import { createOperationsRouter } from "../../routes/operationsRoutes";
import type { OperationsAccessPolicy } from "../types";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

type Db = ReturnType<typeof createDatabaseConnection>;
const A = "2026-07-15T10:00:00.000Z";
const B = "2026-07-15T10:01:00.000Z";
const C = "2026-07-15T10:02:00.000Z";
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const RECOVERY_MODEL_ID = "xai/grok-recovery-20260715";
const RECOVERY_MODEL_CONFIGURATION_HASH = "9".repeat(64);

function seed(database: Db): void {
  const mission = database.prepare(`
    INSERT INTO missions (id, name, objective, journey, engagement_id, created_by, created_at, updated_at)
    VALUES (?, ?, 'Authorized test objective', 'guided', ?, 'operator', ?, ?)
  `);
  mission.run("mission-a", "Engagement A", "eng-a", A, C);
  mission.run("mission-b", "Engagement B", "eng-b", A, C);
  const run = database.prepare(`
    INSERT INTO runs (id, mission_id, journey, status, progress, created_at, updated_at)
    VALUES (?, ?, 'guided', 'running', 0.5, ?, ?)
  `);
  run.run("run-a", "mission-a", A, C);
  run.run("run-b", "mission-b", A, C);
  database.prepare(`
    UPDATE runs SET status = 'completed', progress = 1, retry_count = 1,
      replan_count = 1, status_reason = 'Authorized objective completed',
      budget_json = ?, budget_usage_json = ?, started_at = ?, ended_at = ?
    WHERE id = 'run-a'
  `).run(
    JSON.stringify({ timeBudgetMinutes: 10, tokenBudget: 100, costBudget: 1, toolCalls: 5, retryBudget: 3, replanBudget: 2 }),
    JSON.stringify({ wallClockMs: 120_000, providerTokens: 30, estimatedCost: 0, toolCalls: 1, retries: 2, replans: 1 }),
    A,
    C,
  );

  const agent = database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, '{}', '1', ?, ?, ?)
  `);
  agent.run("agent-one", "recon", "Recon One", "busy", JSON.stringify({ provider: "grok", api_key: "provider-secret-123" }), JSON.stringify({ allow: ["scan"], token: "tool-secret-123" }), C, A, C);
  agent.run("agent-two", "report", "Report Two", "available", "{}", "{}", C, A, B);
  database.prepare(`INSERT INTO agent_capabilities (agent_id, capability, source, enabled) VALUES ('agent-one', 'network.recon', 'runtime', 1)`).run();
  const assignment = database.prepare(`
    INSERT INTO assignments (
      id, run_id, agent_id, status, lease_owner, last_heartbeat_at,
      lease_expires_at, started_at, created_at, updated_at
    ) VALUES (?, ?, 'agent-one', 'active', 'worker', ?, ?, ?, ?, ?)
  `);
  assignment.run("assignment-a", "run-a", B, "2026-07-15T11:00:00.000Z", A, A, C);
  assignment.run("assignment-b", "run-b", B, "2026-07-15T11:00:00.000Z", A, A, C);

  const evidence = database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, source, acquired_at, target, evidence_type,
      content_hash, provenance_json, confidence, sensitivity, verification_state,
      summary, extracted_text, artifact_id, created_by, created_at
    ) VALUES (?, ?, ?, 'specialist', ?, 'lab.internal', 'service', ?, ?, 0.9, 'private', 'verified', ?, ?, ?, 'agent-one', ?)
  `);
  evidence.run("evidence-a-new", "mission-a", "run-a", C, HASH_A, JSON.stringify({ source: "scan", credential: "provenance-secret-123" }), "Credential service confirmed", "password=raw-secret-123", "artifact-report-a", C); // gitleaks:allow -- synthetic redaction fixture
  evidence.run("evidence-a-old", "mission-a", "run-a", B, HASH_B, "{}", "Older service evidence", null, null, B);
  evidence.run("evidence-b", "mission-b", "run-b", C, HASH_B, "{}", "Engagement B must remain hidden", null, null, C);
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, source, acquired_at, target, evidence_type,
      content_hash, provenance_json, confidence, sensitivity, verification_state,
      summary, extracted_text, created_by, created_at
    ) VALUES (
      'evidence-a-operational-log', 'mission-a', 'run-a', 'legacy_runtime', ?,
      'lab.internal', 'command_output', ?, '{"legacyId":"raw-output-1"}', 0.5,
      'private', 'unverified', 'observed output (observe-only)', 'raw terminal output',
      'import:legacy', ?
    )
  `).run("2026-07-15T10:03:00.000Z", HASH_B, "2026-07-15T10:03:00.000Z");
  database.prepare(`
    INSERT INTO evidence_chain_events (id, evidence_id, event_type, actor, details_json, occurred_at)
    VALUES ('chain-a', 'evidence-a-new', 'acquired', 'agent-one', '{"api_key":"chain-secret-123"}', ?) -- gitleaks:allow: synthetic redaction fixture
  `).run(C);

  const finding = database.prepare(`
    INSERT INTO findings (
      id, mission_id, run_id, title, severity, confidence, affected_scope,
      description, impact, review_status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'high', 0.9, 'lab.internal', 'Evidence-backed issue', 'Authorized impact', 'under_review', ?, ?)
  `);
  finding.run("finding-a-empty", "mission-a", "run-a", "No linked evidence", B, B);
  finding.run("finding-a-ready", "mission-a", "run-a", "Ready to verify", B, B);
  finding.run("finding-b", "mission-b", "run-b", "Hidden finding", B, B);
  database.prepare(`INSERT INTO finding_evidence (finding_id, evidence_id, relationship, added_at) VALUES ('finding-a-ready', 'evidence-a-new', 'supports', ?)`).run(C);

  const artifact = database.prepare(`
    INSERT INTO artifacts (
      id, mission_id, run_id, journey, artifact_type, storage_uri, content_hash,
      byte_size, media_type, sensitivity, metadata_json, created_at
    ) VALUES (?, ?, ?, 'guided', ?, ?, ?, 128, 'application/json', 'private', ?, ?)
  `);
  artifact.run(
    "artifact-report-a",
    "mission-a",
    "run-a",
    "mission_report",
    "https://user:password@storage.invalid/report",
    HASH_A,
    JSON.stringify({
      title: "Report",
      access_token: "artifact-secret-123",
      downloadUrl: "/api/v2/reports/artifact-report-a/download",
      producerPath: "/restricted/report.md",
    }),
    C,
  );
  artifact.run("artifact-data-a", "mission-a", "run-a", "capture", "file:///restricted/capture", HASH_B, "{}", B);
  artifact.run("artifact-report-b", "mission-b", "run-b", "mission_report", "file:///hidden/report", HASH_B, "{}", C);

  const event = database.prepare(`
    INSERT INTO events (
      id, mission_id, run_id, sequence, event_type, occurred_at, actor_type,
      actor_id, summary, payload_json, journey, trace_id, sensitivity, created_at
    ) VALUES (?, ?, ?, 1, 'evidence.added', ?, 'agent', 'agent-one', ?, ?, 'guided', 'trace-shared', 'private', ?)
  `);
  event.run("event-a", "mission-a", "run-a", C, "Evidence added", JSON.stringify({ api_key: "event-secret-123", result: "Bearer event-bearer-secret" }), C);
  event.run("event-b", "mission-b", "run-b", C, "Hidden event", "{}", C);
  const log = database.prepare(`
    INSERT INTO structured_logs (
      id, mission_id, run_id, severity, domain, message, attributes_json,
      trace_id, sensitivity, occurred_at
    ) VALUES (?, ?, ?, 'error', 'runtime', ?, ?, 'trace-shared', 'private', ?)
  `);
  log.run("log-a", "mission-a", "run-a", "Provider error Bearer log-bearer-secret", JSON.stringify({ password: "log-secret-123", category: "timeout" }), C);
  log.run("log-b", "mission-b", "run-b", "Hidden engagement error", "{}", C);
  database.prepare(`
    INSERT INTO health_snapshots (id, component_type, component_id, status, metrics_json, message, captured_at)
    VALUES ('health-agent', 'agent', 'agent-one', 'healthy', '{"token":"health-secret-123","latency":5}', 'Healthy', ?)
  `).run(C);

  database.prepare(`
    INSERT INTO run_evaluations (
      id, mission_id, run_id, journey, scores_json, metrics_json,
      retrospective, evidence_coverage, created_by, created_at
    ) VALUES (?, ?, ?, 'guided', '{"completion":0.9}', '{"retries":0}', 'Evidence-linked evaluation', 0.8, 'evaluator', ?)
  `).run("evaluation-a", "mission-a", "run-a", C);
  database.prepare(`
    INSERT INTO run_evaluations (
      id, mission_id, run_id, journey, scores_json, metrics_json,
      retrospective, evidence_coverage, created_by, created_at
    ) VALUES (?, ?, ?, 'guided', '{}', '{}', 'Hidden evaluation', 0.5, 'evaluator', ?)
  `).run("evaluation-b", "mission-b", "run-b", C);
  const comparison = database.prepare(`
    INSERT INTO run_evaluation_comparisons (
      evaluation_id, run_id, comparison_status, reason, metrics_json, summary, created_at
    ) VALUES (?, ?, 'insufficient_data', 'no_prior_same_scope_evaluation', '[]',
      'Insufficient comparable data: no earlier evaluated run exists in this scope.', ?)
  `);
  comparison.run("evaluation-a", "run-a", C);
  comparison.run("evaluation-b", "run-b", C);

  const lesson = database.prepare(`
    INSERT INTO lessons (
      id, statement, lesson_type, applicability_scope, engagement_id, mission_id,
      confidence, expected_benefit, risk, status, authoring_agent_id, created_at, updated_at
    ) VALUES (?, ?, 'strategy', 'engagement', ?, ?, 0.8, 'Avoid repeated work', 'Low', 'under_review', ?, ?, ?)
  `);
  lesson.run("lesson-ready", "Use confirmed service evidence", "eng-a", "mission-a", "agent-other", B, B);
  lesson.run("lesson-self", "Self-authored lesson", "eng-a", "mission-a", "agent-self", B, B);
  lesson.run("lesson-empty", "Lesson without support", "eng-a", "mission-a", "agent-other", B, B);
  lesson.run("lesson-b", "Hidden lesson", "eng-b", "mission-b", "agent-other", B, B);
  const lessonEvidence = database.prepare(`
    INSERT INTO lesson_evidence (lesson_id, evidence_id, relationship, rationale, created_at)
    VALUES (?, 'evidence-a-new', 'supports', 'Direct supporting evidence', ?)
  `);
  lessonEvidence.run("lesson-ready", C);
  lessonEvidence.run("lesson-self", C);
  database.prepare(`
    INSERT INTO lesson_evidence (lesson_id, run_id, relationship, rationale, created_at)
    VALUES ('lesson-ready', 'run-a', 'counterexample', 'Produced by this exact terminal run', ?)
  `).run(C);
  database.prepare(`
    INSERT INTO lesson_usage (
      id, lesson_id, mission_id, run_id, influence_summary, measured_impact_json, used_at
    ) VALUES ('usage-a', 'lesson-ready', 'mission-a', 'run-a', 'Changed the plan', '{"savedActions":2}', ?)
  `).run(C);

  const providerTurn = database.prepare(`
    INSERT INTO provider_turns (
      id, run_id, provider, model, status, input_tokens, output_tokens,
      estimated_cost, latency_ms, started_at, ended_at
    ) VALUES (?, ?, 'grok', 'expert', 'completed', 10, 20, 0, 100, ?, ?)
  `);
  providerTurn.run("turn-a", "run-a", B, C);
  providerTurn.run("turn-b", "run-b", B, C);
  database.prepare(`
    INSERT INTO mcp_servers (
      id, name, transport, endpoint_redacted, status, capabilities_json,
      policy_json, last_checked_at, created_at, updated_at
    ) VALUES ('mcp-one', 'Higgsfield', 'http', 'https://mcp.invalid/[redacted]', 'healthy', '["analyze"]', '{"client_secret":"mcp-secret-123","allow":true}', ?, ?, ?)
  `).run(C, A, C);
  database.prepare(`
    INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
    VALUES ('policy.execution', '{"authorization":"policy-secret-123","mode":"enforce"}', 'internal', 1, 'admin', ?)
  `).run(C);
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, action_type, action_class, fingerprint,
      normalized_arguments_json, status, intent_summary, result_summary,
      error_category, retry_count, created_at, updated_at
    ) VALUES (
      'action-a', 'mission-a', 'run-a', 'scan', 'reconnaissance', ?,
      '{"password":"action-secret-123"}', 'succeeded', 'Map approved target', -- gitleaks:allow -- synthetic redaction fixture
      'Unique evidence retained', NULL, 1, ?, ?
    )
  `).run("f".repeat(64), B, C);
  database.prepare(`
    INSERT INTO approvals (
      id, mission_id, run_id, approval_type, status, requested_by,
      decided_by, reason, policy_rule, request_json, decided_at, created_at
    ) VALUES (
      'approval-a', 'mission-a', 'run-a', 'finding_review', 'approved',
      'reviewer-one', 'reviewer-one', 'Reviewed authorization token=approval-secret-123', -- gitleaks:allow -- synthetic redaction fixture
      'evidence.required', '{"credential":"approval-request-secret-123"}', ?, ? -- gitleaks:allow -- synthetic redaction fixture
    )
  `).run(C, B);
  database.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, retrieval_metrics_json, created_by, created_at
    ) VALUES (
      'context-a', 'mission-a', 'run-a', 'guided', 'Select verified lesson',
      '[REDACTED]', '{}', 512, '{"precision":1}', 'commander', ?
    )
  `).run(B);
  database.prepare("UPDATE actions SET context_pack_id = 'context-a' WHERE id = 'action-a'").run();
  database.prepare("UPDATE artifacts SET action_id = 'action-a' WHERE id = 'artifact-report-a'").run();
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, action_type, action_class, fingerprint,
      normalized_arguments_json, status, intent_summary, result_summary,
      retry_count, created_at, updated_at
    ) VALUES (
      'action-b', 'mission-b', 'run-b', 'scan', 'reconnaissance', ?, '{}',
      'succeeded', 'Hidden engagement action', 'Hidden engagement result', 0, ?, ?
    )
  `).run("e".repeat(64), B, C);
}

function retainAttackChainDetails(
  database: Db,
  lessonId: string,
  runId: string,
  evidenceId?: string,
): void {
  new AttackChainLearningService(database, { clock: () => new Date(C) }).retainCandidateDetails(
    lessonId,
    {
      title: `Bounded review chain ${lessonId}`,
      techniqueName: "Scoped service validation",
      techniqueCategory: "recon",
      summary: "Correlate authorized observations before selecting the next bounded technique.",
      prerequisites: ["Confirmed authorization and normalized target scope"],
      observedSignals: ["A distinct service response is retained as evidence"],
      orderedSteps: ["Use nmap service detection against <TARGET_HOST>."],
      tools: ["nmap"],
      publicReferences: ["https://nmap.org/book/man-version-detection.html"],
      validationCheckpoints: ["Confirm a retained evidence identifier records the expected response"],
      failureRecovery: ["If no new evidence is produced, change conditions before one bounded retry"],
      antiReuseWarnings: ["Do not treat one unverified banner as proof"],
      expectedOutcome: "Service identity uncertainty is reduced with retained evidence",
      reuseGuidance: "Apply only when authorization and prerequisite signals match",
      confidence: 0.85,
      scope: "mission",
      sources: [{
        sourceType: "run_evaluation",
        sourceId: `evaluation-${lessonId}`,
        sourceHash: "c".repeat(64),
        runId,
        ...(evidenceId ? { evidenceId } : {}),
      }],
    },
    "agent-other",
  );
}

async function application(options: {
  readonly providerRouteIds?: readonly string[];
  readonly includeRecoveryLeaseResolver?: boolean;
} = {}) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  seed(database);
  const mutationLeases = new ControlPlaneLeaseService(database);
  const leaseOwners = new Map<string, { readonly owner: string; readonly fence: string }>();
  let recoveryLeaseChecks = 0;
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(createOperationsRouter({
    database,
    clock: () => new Date("2026-07-15T10:30:00.000Z"),
    ...(options.providerRouteIds === undefined ? {} : { providerRouteIds: options.providerRouteIds }),
    ...(options.includeRecoveryLeaseResolver === false ? {} : {
      assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
        recoveryLeaseChecks += 1;
        let authority = leaseOwners.get(runId);
        if (!authority) {
          authority = {
            owner: `operations-router-runtime-${runId}`,
            fence: `operations-router-fence-${runId}-00000000`,
          };
          mutationLeases.acquire({
            runId,
            controlPlane: "ti_scale",
            leaseOwner: authority.owner,
            leaseToken: authority.fence,
            ttlMs: 300_000,
            now: new Date("2026-07-15T10:30:00.000Z"),
          });
          leaseOwners.set(runId, authority);
        }
        return mutationLeases.assertMutationAuthority({
          runId,
          controlPlane: "ti_scale",
          leaseOwner: authority.owner,
          leaseToken: authority.fence,
          now: new Date("2026-07-15T10:30:00.000Z"),
        });
      },
    }),
    resolveActor: (request) => {
      const id = request.get("X-Test-Actor") ?? "reviewer-one";
      return {
        id,
        type: id.startsWith("agent-") ? "agent" : id.startsWith("operator-") ? "operator" : "reviewer",
      };
    },
    resolveAccess: (request): OperationsAccessPolicy => {
      const access = request.get("X-Test-Access");
      if (access === "all") return {
          maximumSensitivity: "restricted", allEngagements: true,
          allowUnscopedSystemData: true, allowGlobalKnowledge: true,
          canReviewFindings: true, canOverrideEvidenceGate: true, canReviewLessons: true,
          canManageRecovery: true,
        };
      return {
        maximumSensitivity: "private", engagementIds: ["eng-a"], missionIds: ["mission-a"],
        allowUnscopedSystemData: true, allowGlobalKnowledge: true,
        canReviewFindings: true, canOverrideEvidenceGate: true, canReviewLessons: true,
        ...(access === "recovery" ? { canManageRecovery: true } : {}),
      };
    },
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    database,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    recoveryLeaseCheckCount: () => recoveryLeaseChecks,
  };
}

async function body(response: Response): Promise<any> {
  return response.json() as Promise<any>;
}

function seedGuidedRecoveryMutationBoundary(
  database: Db,
  suffix: string,
  actionKind: "manual" | "provider_turn",
  expiresAt: string,
) {
  const ids = {
    runId: `run-guided-recovery-${suffix}`,
    planId: `plan-guided-recovery-${suffix}`,
    stepId: `step-guided-recovery-${suffix}`,
    assignmentId: `assignment-guided-recovery-${suffix}`,
    ownerId: `agent-guided-owner-${suffix}`,
    candidateId: `agent-guided-candidate-${suffix}`,
    decisionId: `decision-guided-recovery-${suffix}`,
    checkpointId: `checkpoint-guided-recovery-${suffix}`,
    fingerprint: "d".repeat(64),
  };
  const agent = database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES (?, 'recon', ?, ?, '{}', '{}', '{}', '1', ?, ?, ?)
  `);
  agent.run(ids.ownerId, `Recovery owner ${suffix}`, "busy", "2026-07-15T10:30:00.000Z", A, C);
  agent.run(ids.candidateId, `Recovery candidate ${suffix}`, "available", "2026-07-15T10:30:00.000Z", A, C);
  database.prepare(`
    INSERT INTO agent_capabilities (agent_id, capability, source, enabled, metadata_json)
    VALUES (?, 'network.recon', 'runtime', 1, '{}')
  `).run(ids.ownerId);
  database.prepare(`
    INSERT INTO agent_capabilities (agent_id, capability, source, enabled, metadata_json)
    VALUES (?, 'network.recon', 'live-route-attestation', 1, ?)
  `).run(ids.candidateId, JSON.stringify({ validUntil: "2026-07-15T11:30:00.000Z" }));
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, current_plan_id, current_step_id,
      current_owner_id, status_reason, next_action_summary, budget_json,
      budget_usage_json, control_plane, created_at, updated_at, version
    ) VALUES (?, 'mission-a', 'guided', 'blocked', ?, ?, ?,
      'Diagnosed Guided recovery requires one exact decision',
      'Choose one represented recovery', '{"retries":2,"replans":2}', '{}',
      'ti_scale', ?, ?, 1)
  `).run(ids.runId, ids.planId, ids.stepId, ids.ownerId, A, C);
  database.prepare(`
    INSERT INTO plans (id, run_id, version, status, strategy_summary, plan_hash, created_by, created_at)
    VALUES (?, ?, 1, 'active', 'Use one bounded recovery path', ?, 'commander', ?)
  `).run(ids.planId, ids.runId, "4".repeat(64), A);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'recovery', 'Collect bounded evidence',
      'Reduce uncertainty without repeating work', 'blocked', '[]', '[]',
      'passive_intelligence_osint', 'low', ?, ?, ?)
  `).run(ids.stepId, ids.planId, ids.runId, ids.ownerId, A, C);
  database.prepare(`
    INSERT INTO assignments (id, run_id, step_id, agent_id, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, 'blocked', ?, ?)
  `).run(ids.assignmentId, ids.runId, ids.stepId, ids.ownerId, A, C);
  database.prepare(`
    INSERT INTO mission_constraints (id, mission_id, constraint_type, value_json, source, created_at)
    VALUES (?, 'mission-a', 'represented_action', ?, ?, ?)
  `).run(`constraint-guided-recovery-${suffix}`, JSON.stringify({
    action: {
      actionType: "passive_intelligence_osint",
      actionClass: "passive_intelligence_osint",
      target: "lab.internal",
      arguments: { mode: "bounded" },
      intentSummary: "Collect one attributable observation",
      kind: actionKind,
      idempotent: true,
      destructive: false,
    },
    explanation: "Collect one bounded observation without changing target state.",
    rationale: "Reduce uncertainty while preserving the exact Guided boundary.",
    reversibility: "Read-only",
  }), ids.stepId, A);
  database.prepare(`
    INSERT INTO guided_decisions (
      id, mission_id, run_id, step_id, requested_action_fingerprint,
      requested_parameters_json, rationale, risk_class, reversibility,
      status, expires_at, created_at
    ) VALUES (?, 'mission-a', ?, ?, ?, '{}', 'Choose this exact recovery',
      'low', 'Read-only', 'pending', ?, ?)
  `).run(ids.decisionId, ids.runId, ids.stepId, ids.fingerprint, expiresAt, C);
  const state = {
    schemaVersion: 1,
    run: {
      id: ids.runId, missionId: "mission-a", journey: "guided", state: "blocked",
      stateVersion: 1, reason: "Diagnosed Guided recovery requires one exact decision",
      leaseOwner: null, leaseExpiresAt: null,
    },
    control: { budget: { limits: { retries: 2, replans: 2 }, usage: {} }, retryCount: 0, replanCount: 0, circuits: {}, progress: {} },
    completedActionIds: [], inFlightActions: [], lastEventSequence: 0,
  };
  const stateHash = hashJson(state);
  database.prepare(`
    INSERT INTO checkpoints (
      id, mission_id, run_id, journey, event_sequence, plan_version,
      state_json, state_hash, in_flight_classification, created_at
    ) VALUES (?, 'mission-a', ?, 'guided', 0, 1, ?, ?, 'safe_no_in_flight_action', ?)
  `).run(ids.checkpointId, ids.runId, JSON.stringify(state), stateHash, C);
  return {
    ...ids,
    exact: {
      expectedRunVersion: 1,
      expectedPlanId: ids.planId,
      expectedPlanVersion: 1,
      expectedStepId: ids.stepId,
      expectedAssignmentId: ids.assignmentId,
      expectedCheckpointId: ids.checkpointId,
      expectedCheckpointStateHash: stateHash,
      expectedCheckpointEventSequence: 0,
    },
  };
}

describe("canonical operations HTTP API", () => {
  test("projects canonical Guided recovery evidence, checkpoint budgets, memory links, and only real controls", async () => {
    const { database, url } = await application();
    try {
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, current_step_id, progress, status_reason,
          next_action_summary, budget_json, budget_usage_json, retry_count, replan_count,
          created_at, updated_at
        ) VALUES (
          'run-recovery-a', 'mission-a', 'guided', 'blocked', NULL, 0.25,
          'Guided recovery blocked after timeout; a new exact decision is ready.',
          'Review the replacement action', ?, ?, 1, 0, ?, ?
        )
      `).run(JSON.stringify({ retryBudget: 2, replanBudget: 1 }), JSON.stringify({ retries: 1 }), A, C);
      database.prepare(`
        INSERT INTO plans (id, run_id, version, status, strategy_summary, plan_hash, created_by, created_at)
        VALUES ('plan-recovery-a', 'run-recovery-a', 1, 'active', 'Bounded recovery plan', ?, 'commander', ?)
      `).run("1".repeat(64), A);
      database.prepare(`
        INSERT INTO plan_steps (
          id, plan_id, run_id, ordinal, phase, title, objective, status,
          success_criteria_json, dependencies_json, action_class, risk_class,
          assigned_agent_id, created_at, updated_at
        ) VALUES (
          'step-recovery-a', 'plan-recovery-a', 'run-recovery-a', 0, 'recovery',
          'Try bounded alternative', 'Collect different evidence', 'waiting_guided_decision',
          '[]', '[]', 'reconnaissance', 'low', 'agent-one', ?, ?
        )
      `).run(A, C);
      database.prepare(`UPDATE runs SET current_plan_id = 'plan-recovery-a', current_step_id = 'step-recovery-a', current_owner_id = 'agent-one' WHERE id = 'run-recovery-a'`).run();
      database.prepare(`
        INSERT INTO guided_decisions (
          id, mission_id, run_id, step_id, requested_action_fingerprint,
          requested_parameters_json, rationale, risk_class, reversibility,
          status, expires_at, created_at
        ) VALUES (
          'decision-recovery-a', 'mission-a', 'run-recovery-a', 'step-recovery-a', ?,
          '{}', 'Use a materially different bounded check', 'low', 'Read-only',
          'pending', '2026-07-16T10:00:00.000Z', ?
        )
      `).run("2".repeat(64), C);
      database.prepare(`
        INSERT INTO actions (
          id, mission_id, run_id, step_id, action_type, action_class, fingerprint,
          normalized_arguments_json, status, intent_summary, result_summary,
          error_category, retry_count, ended_at, created_at, updated_at
        ) VALUES (
          'action-recovery-a', 'mission-a', 'run-recovery-a', 'step-recovery-a',
          'scan', 'reconnaissance', ?, '{}', 'timed_out', 'Map the approved service',
          'Provider timed out without evidence', 'timeout', 0, ?, ?, ?
        )
      `).run("3".repeat(64), B, A, B);
      database.prepare(`
        INSERT INTO events (
          id, mission_id, run_id, sequence, event_type, occurred_at, actor_type,
          summary, payload_json, journey, sensitivity, created_at
        ) VALUES (
          'event-recovery-a', 'mission-a', 'run-recovery-a', 1, 'action.completed', ?,
          'worker', 'Bounded action timed out; Guided recovery prepared',
          '{"directive":"recover","errorCategory":"timeout"}', 'guided', 'internal', ?
        )
      `).run(B, B);
      const state = {
        schemaVersion: 1,
        run: { id: "run-recovery-a", missionId: "mission-a", journey: "guided", state: "blocked", stateVersion: 1, reason: "Guided recovery blocked after timeout", leaseOwner: null, leaseExpiresAt: null },
        control: { budget: { limits: { retries: 2, replans: 1 }, usage: { retries: 1 } }, retryCount: 1, replanCount: 0, circuits: {}, progress: {} },
        completedActionIds: [], inFlightActions: [], lastEventSequence: 1,
      };
      database.prepare(`
        INSERT INTO checkpoints (
          id, mission_id, run_id, journey, event_sequence, plan_version, state_json,
          state_hash, in_flight_classification, created_at
        ) VALUES ('checkpoint-recovery-a', 'mission-a', 'run-recovery-a', 'guided', 1, 1, ?, ?, 'safe_no_in_flight_action', ?)
      `).run(JSON.stringify(state), hashJson(state), B);
      database.prepare(`
        INSERT INTO memory_nodes (
          id, node_type, title, summary, body, scope, engagement_id, mission_id,
          sensitivity, confidence, lifecycle_status, confirmation_state,
          provenance_json, author_type, created_at, updated_at
        ) VALUES (
          'memory-failure-a', 'failure', 'Timeout produced no evidence', 'Avoid an identical retry', '',
          'mission', 'eng-a', 'mission-a', 'private', 0.9, 'verified', 'not_required',
          '{}', 'system', ?, ?
        )
      `).run(B, B);
      database.prepare(`
        INSERT INTO memory_sources (
          id, node_id, source_type, source_id, mission_id, run_id, acquired_at, created_at
        ) VALUES ('source-failure-a', 'memory-failure-a', 'run', 'run-recovery-a', 'mission-a', 'run-recovery-a', ?, ?)
      `).run(B, B);
      database.prepare(`
        INSERT INTO lessons (
          id, statement, lesson_type, applicability_scope, engagement_id, mission_id,
          failure_category, retry_conditions, confidence, expected_benefit, risk,
          status, authoring_agent_id, created_at, updated_at
        ) VALUES (
          'lesson-failure-a', 'Use a different provider only after policy validation', 'failed_attempt',
          'mission', 'eng-a', 'mission-a', 'timeout', 'Provider health materially changes',
          0.8, 'Avoid repeated timeout', 'Low', 'under_review', 'agent-one', ?, ?
        )
      `).run(B, B);
      database.prepare(`
        INSERT INTO lesson_evidence (lesson_id, run_id, relationship, rationale, created_at)
        VALUES ('lesson-failure-a', 'run-recovery-a', 'supports', 'Canonical failed run', ?)
      `).run(B);

      const unauthorizedRecovery = await body(await fetch(`${url}/api/v2/operations/runs/run-recovery-a/recovery`));
      expect(unauthorizedRecovery.actions.find((item: any) => item.kind === "resume")).toMatchObject({
        available: false,
        command: null,
        reason: "Recovery-management permission is required.",
      });
      const response = await fetch(`${url}/api/v2/operations/runs/run-recovery-a/recovery`, {
        headers: { "X-Test-Access": "recovery" },
      });
      expect(response.status).toBe(200);
      const recovery = await body(response);
      expect(recovery).toMatchObject({
        schemaVersion: "2.4",
        recoveryRequired: true,
        run: { id: "run-recovery-a", journey: "guided", status: "blocked" },
        detection: { category: "timeout", failedActions: [{ id: "action-recovery-a", status: "timed_out" }] },
        checkpoint: { id: "checkpoint-recovery-a", eventSequence: 1, planVersion: 1 },
        attempts: { retryCount: 1, retryLimit: 2, retriesRemaining: 1, replanCount: 0, replanLimit: 1, replansRemaining: 1 },
        proposedRecovery: { kind: "guided_decision" },
        guidedDecision: { id: "decision-recovery-a", stepId: "step-recovery-a" },
      });
      expect(recovery.failedAttemptMemories.map((item: any) => `${item.kind}:${item.id}`).sort()).toEqual([
        "lesson:lesson-failure-a", "memory:memory-failure-a",
      ]);
      expect(recovery.actions.find((item: any) => item.kind === "resume")).toMatchObject({ available: true, command: "resume" });
      expect(recovery.actions.find((item: any) => item.kind === "terminate")).toMatchObject({ available: true, command: "cancel" });
      for (const kind of ["replan", "reassign", "change_provider"]) {
        expect(recovery.actions.find((item: any) => item.kind === kind)).toMatchObject({ available: false, command: null });
      }
      expect((await fetch(`${url}/api/v2/operations/runs/run-b/recovery`)).status).toBe(404);
    } finally { database.close(); }
  });

  test("fails recovery closed across control planes before idempotent replay and permits the same exact V2-owned boundary", async () => {
    const { database, url, recoveryLeaseCheckCount } = await application();
    try {
      database.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, provider_policy_json, tool_policy_json,
          configuration_json, version, last_heartbeat_at, created_at, updated_at
        ) VALUES (
          'agent-recovery-owner', 'recon', 'Recovery owner', 'available', '{}', '{}',
          '{}', '1', ?, ?, ?
        )
      `).run(C, A, C);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, current_plan_id, current_step_id,
          current_owner_id, status_reason, next_action_summary, budget_json,
          budget_usage_json, control_plane, created_at, updated_at, version
        ) VALUES (
          'run-control-plane-recovery', 'mission-a', 'guided', 'blocked',
          'plan-control-plane-recovery', 'step-control-plane-recovery',
          'agent-recovery-owner', 'Timed-out predecessor retained at an exact checkpoint',
          'Choose one bounded recovery', '{"replans":1}', '{}', 'legacy', ?, ?, 1
        )
      `).run(A, C);
      database.prepare(`
        INSERT INTO plans (
          id, run_id, version, status, strategy_summary, plan_hash,
          created_by, created_at, activated_at
        ) VALUES (
          'plan-control-plane-recovery', 'run-control-plane-recovery', 1, 'active',
          'Retry the unchanged timed-out strategy', ?, 'commander', ?, ?
        )
      `).run("4".repeat(64), A, A);
      database.prepare(`
        INSERT INTO plan_steps (
          id, plan_id, run_id, ordinal, phase, title, objective, status,
          success_criteria_json, dependencies_json, action_class, risk_class,
          assigned_agent_id, created_at, updated_at
        ) VALUES (
          'step-control-plane-recovery', 'plan-control-plane-recovery',
          'run-control-plane-recovery', 0, 'recovery', 'Use a different observation path',
          'Reduce uncertainty without repeating the failed action', 'blocked',
          '[]', '[]', 'passive_intelligence_osint', 'low',
          'agent-recovery-owner', ?, ?
        )
      `).run(A, C);
      database.prepare(`
        INSERT INTO assignments (
          id, run_id, step_id, agent_id, status, created_at, updated_at
        ) VALUES (
          'assignment-control-plane-recovery', 'run-control-plane-recovery',
          'step-control-plane-recovery', 'agent-recovery-owner', 'blocked', ?, ?
        )
      `).run(A, C);
      database.prepare(`
        INSERT INTO mission_constraints (
          id, mission_id, constraint_type, value_json, source, created_at
        ) VALUES (
          'constraint-control-plane-recovery', 'mission-a', 'represented_action',
          '{"action":{"kind":"manual"}}', 'step-control-plane-recovery', ?
        )
      `).run(A);
      database.prepare(`
        INSERT INTO actions (
          id, mission_id, run_id, step_id, assignment_id, action_type,
          action_class, fingerprint, normalized_arguments_json, status,
          intent_summary, result_summary, error_category, ended_at,
          created_at, updated_at
        ) VALUES (
          'action-control-plane-recovery', 'mission-a', 'run-control-plane-recovery',
          'step-control-plane-recovery', 'assignment-control-plane-recovery',
          'scan', 'passive_intelligence_osint', ?, '{}', 'timed_out',
          'Collect a bounded observation', 'Timed out without evidence', 'timeout',
          ?, ?, ?
        )
      `).run("5".repeat(64), B, A, B);
      const checkpointState = {
        schemaVersion: 1,
        run: {
          id: "run-control-plane-recovery", missionId: "mission-a", journey: "guided",
          state: "blocked", stateVersion: 1,
          reason: "Timed-out predecessor retained at an exact checkpoint",
          leaseOwner: null, leaseExpiresAt: null,
        },
        control: {
          budget: { limits: { replans: 1 }, usage: {} }, retryCount: 0,
          replanCount: 0, circuits: {}, progress: {},
        },
        completedActionIds: [], inFlightActions: [], lastEventSequence: 0,
      };
      database.prepare(`
        INSERT INTO checkpoints (
          id, mission_id, run_id, journey, event_sequence, plan_version,
          state_json, state_hash, in_flight_classification, created_at
        ) VALUES (
          'checkpoint-control-plane-recovery', 'mission-a', 'run-control-plane-recovery',
          'guided', 0, 1, ?, ?, 'safe_no_in_flight_action', ?
        )
      `).run(JSON.stringify(checkpointState), hashJson(checkpointState), B);

      const headers = {
        "Content-Type": "application/json",
        "Idempotency-Key": "recovery-control-plane-replay",
        "X-Test-Actor": "operator-one",
        "X-Test-Access": "recovery",
      };
      const requestBody = JSON.stringify({
        expectedRunVersion: 1,
        expectedPlanId: "plan-control-plane-recovery",
        expectedPlanVersion: 1,
        expectedStepId: "step-control-plane-recovery",
        expectedAssignmentId: "assignment-control-plane-recovery",
        expectedCheckpointId: "checkpoint-control-plane-recovery",
        expectedCheckpointStateHash: hashJson(checkpointState),
        expectedCheckpointEventSequence: 0,
        strategyReason: "Use a materially different passive correlation path",
      });

      const projected = await body(await fetch(`${url}/api/v2/operations/runs/run-control-plane-recovery/recovery`, {
        headers,
      }));
      expect(projected.actions).toHaveLength(5);
      expect(projected.actions.every((action: any) => action.available === false && action.command === null)).toBe(true);
      expect(projected.actions.every((action: any) => action.reason.includes("legacy control plane"))).toBe(true);

      const rejected = await fetch(`${url}/api/v2/operations/runs/run-control-plane-recovery/recovery/replan`, {
        method: "POST", headers, body: requestBody,
      });
      expect(rejected.status).toBe(409);
      expect(await body(rejected)).toMatchObject({
        error: {
          code: "control_plane_mismatch",
          humanMessage: "Run run-control-plane-recovery is not exclusively owned by Ti-Scale",
          remediation: "Open this run through its owning control plane; imported legacy runs remain read-only in Ti-Scale.",
        },
      });
      expect((database.prepare(`SELECT count(*) AS count FROM events WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count).toBe(0);

      database.prepare(`UPDATE runs SET control_plane = 'ti_scale' WHERE id = 'run-control-plane-recovery'`).run();
      const missingCheckpointBoundary = await fetch(`${url}/api/v2/operations/runs/run-control-plane-recovery/recovery/replan`, {
        method: "POST",
        headers: { ...headers, "Idempotency-Key": "recovery-missing-checkpoint" },
        body: JSON.stringify({
          expectedRunVersion: 1,
          expectedPlanId: "plan-control-plane-recovery",
          expectedPlanVersion: 1,
          expectedStepId: "step-control-plane-recovery",
          expectedAssignmentId: "assignment-control-plane-recovery",
          strategyReason: "Use a materially different passive correlation path",
        }),
      });
      expect(missingCheckpointBoundary.status).toBe(400);
      for (const [field, value] of [
        ["expectedCheckpointId", "checkpoint-stale"],
        ["expectedCheckpointStateHash", "c".repeat(64)],
        ["expectedCheckpointEventSequence", 1],
      ] as const) {
        const stale = await fetch(`${url}/api/v2/operations/runs/run-control-plane-recovery/recovery/replan`, {
          method: "POST",
          headers: { ...headers, "Idempotency-Key": `recovery-stale-${field}` },
          body: JSON.stringify({ ...JSON.parse(requestBody), [field]: value }),
        });
        expect(stale.status).toBe(409);
        expect(await body(stale)).toMatchObject({ error: { code: "recovery_checkpoint_boundary_changed" } });
      }
      expect((database.prepare(`SELECT count(*) AS count FROM events WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count).toBe(0);
      expect((database.prepare(`SELECT count(*) AS count FROM audit_records WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count).toBe(0);
      expect((database.prepare(`SELECT count(*) AS count FROM settings WHERE key LIKE 'ti_scale.recovery.idempotency.%'`).get() as { count: number }).count).toBe(0);
      const checksBeforeAccepted = recoveryLeaseCheckCount();
      const accepted = await fetch(`${url}/api/v2/operations/runs/run-control-plane-recovery/recovery/replan`, {
        method: "POST", headers, body: requestBody,
      });
      expect(accepted.status).toBe(200);
      const acceptedReceipt = await body(accepted);
      expect(acceptedReceipt).toMatchObject({
        mutation: { kind: "replan" },
        run: {
          id: "run-control-plane-recovery",
          status: "recovering",
          planId: "plan-control-plane-recovery",
          planVersion: 1,
          stepId: "step-control-plane-recovery",
          assignmentId: "assignment-control-plane-recovery",
        },
      });
      expect(recoveryLeaseCheckCount() - checksBeforeAccepted).toBe(2);
      const acceptedCounts = {
        events: (database.prepare(`SELECT count(*) AS count FROM events WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count,
        audits: (database.prepare(`SELECT count(*) AS count FROM audit_records WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count,
        checkpoints: (database.prepare(`SELECT count(*) AS count FROM checkpoints WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count,
        outbox: (database.prepare(`
          SELECT count(*) AS count FROM event_outbox
          WHERE event_id IN (SELECT id FROM events WHERE run_id = 'run-control-plane-recovery')
        `).get() as { count: number }).count,
        receipts: (database.prepare(`
          SELECT count(*) AS count FROM settings
          WHERE key LIKE 'ti_scale.recovery.idempotency.%'
        `).get() as { count: number }).count,
      };
      expect(acceptedCounts.events).toBeGreaterThanOrEqual(2);
      expect(acceptedCounts.audits).toBe(1);
      expect(acceptedCounts.checkpoints).toBe(2);

      const checksBeforeReplay = recoveryLeaseCheckCount();
      const immediateReplay = await fetch(`${url}/api/v2/operations/runs/run-control-plane-recovery/recovery/replan`, {
        method: "POST", headers, body: requestBody,
      });
      expect(immediateReplay.status).toBe(200);
      expect(await body(immediateReplay)).toEqual(acceptedReceipt);
      expect(recoveryLeaseCheckCount() - checksBeforeReplay).toBe(2);
      expect({
        events: (database.prepare(`SELECT count(*) AS count FROM events WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count,
        audits: (database.prepare(`SELECT count(*) AS count FROM audit_records WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count,
        checkpoints: (database.prepare(`SELECT count(*) AS count FROM checkpoints WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count,
        outbox: (database.prepare(`
          SELECT count(*) AS count FROM event_outbox
          WHERE event_id IN (SELECT id FROM events WHERE run_id = 'run-control-plane-recovery')
        `).get() as { count: number }).count,
        receipts: (database.prepare(`
          SELECT count(*) AS count FROM settings
          WHERE key LIKE 'ti_scale.recovery.idempotency.%'
        `).get() as { count: number }).count,
      }).toEqual(acceptedCounts);

      database.prepare(`UPDATE runs SET version = version + 1 WHERE id = 'run-control-plane-recovery'`).run();
      const staleReplay = await fetch(`${url}/api/v2/operations/runs/run-control-plane-recovery/recovery/replan`, {
        method: "POST", headers, body: requestBody,
      });
      expect(staleReplay.status).toBe(409);
      expect(await body(staleReplay)).toMatchObject({ error: { code: "recovery_idempotent_replay_stale" } });

      database.prepare(`UPDATE runs SET control_plane = 'legacy' WHERE id = 'run-control-plane-recovery'`).run();
      const replayAfterOwnershipChange = await fetch(`${url}/api/v2/operations/runs/run-control-plane-recovery/recovery/replan`, {
        method: "POST", headers, body: requestBody,
      });
      expect(replayAfterOwnershipChange.status).toBe(409);
      expect(await body(replayAfterOwnershipChange)).toMatchObject({ error: { code: "control_plane_mismatch" } });
      expect({
        events: (database.prepare(`SELECT count(*) AS count FROM events WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count,
        audits: (database.prepare(`SELECT count(*) AS count FROM audit_records WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count,
        checkpoints: (database.prepare(`SELECT count(*) AS count FROM checkpoints WHERE run_id = 'run-control-plane-recovery'`).get() as { count: number }).count,
        outbox: (database.prepare(`
          SELECT count(*) AS count FROM event_outbox
          WHERE event_id IN (SELECT id FROM events WHERE run_id = 'run-control-plane-recovery')
        `).get() as { count: number }).count,
        receipts: (database.prepare(`
          SELECT count(*) AS count FROM settings
          WHERE key LIKE 'ti_scale.recovery.idempotency.%'
        `).get() as { count: number }).count,
      }).toEqual(acceptedCounts);
    } finally { database.close(); }
  });

  test("fails a recovery mutation closed without trusted lease authority before event, audit, checkpoint, outbox, or receipt writes", async () => {
    const { database, url } = await application({ includeRecoveryLeaseResolver: false });
    try {
      const boundary = seedGuidedRecoveryMutationBoundary(
        database,
        "missing-authority",
        "manual",
        "2026-07-15T11:30:00.000Z",
      );
      const before = {
        events: (database.prepare("SELECT count(*) AS count FROM events WHERE run_id = ?")
          .get(boundary.runId) as { count: number }).count,
        audits: (database.prepare("SELECT count(*) AS count FROM audit_records WHERE run_id = ?")
          .get(boundary.runId) as { count: number }).count,
        checkpoints: (database.prepare("SELECT count(*) AS count FROM checkpoints WHERE run_id = ?")
          .get(boundary.runId) as { count: number }).count,
        outbox: (database.prepare(`
          SELECT count(*) AS count FROM event_outbox
          WHERE event_id IN (SELECT id FROM events WHERE run_id = ?)
        `).get(boundary.runId) as { count: number }).count,
        receipts: (database.prepare(`
          SELECT count(*) AS count FROM settings
          WHERE key LIKE 'ti_scale.recovery.idempotency.%'
        `).get() as { count: number }).count,
      };
      const rejected = await fetch(
        `${url}/api/v2/operations/runs/${boundary.runId}/recovery/reassign`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": "recovery-missing-authority-key",
            "X-Test-Actor": "operator-one",
            "X-Test-Access": "recovery",
          },
          body: JSON.stringify({
            ...boundary.exact,
            targetAgentId: boundary.candidateId,
            capability: "network.recon",
            reason: "Move the exact stopped assignment only after trusted authority is proven.",
            guidedDecisionId: boundary.decisionId,
            expectedDecisionFingerprint: boundary.fingerprint,
          }),
        },
      );
      expect(rejected.status).toBe(409);
      expect(await body(rejected)).toMatchObject({
        error: {
          code: "control_plane_lease_missing",
          retryable: false,
          remediation: "Use the active V2 runtime controller for this mutation; the HTTP boundary cannot mint or infer lease authority.",
        },
      });
      expect({
        events: (database.prepare("SELECT count(*) AS count FROM events WHERE run_id = ?")
          .get(boundary.runId) as { count: number }).count,
        audits: (database.prepare("SELECT count(*) AS count FROM audit_records WHERE run_id = ?")
          .get(boundary.runId) as { count: number }).count,
        checkpoints: (database.prepare("SELECT count(*) AS count FROM checkpoints WHERE run_id = ?")
          .get(boundary.runId) as { count: number }).count,
        outbox: (database.prepare(`
          SELECT count(*) AS count FROM event_outbox
          WHERE event_id IN (SELECT id FROM events WHERE run_id = ?)
        `).get(boundary.runId) as { count: number }).count,
        receipts: (database.prepare(`
          SELECT count(*) AS count FROM settings
          WHERE key LIKE 'ti_scale.recovery.idempotency.%'
        `).get() as { count: number }).count,
      }).toEqual(before);
    } finally { database.close(); }
  });

  test("labels an out-of-contract Autonomous terminal state as a safe stop", async () => {
    const { database, url } = await application();
    try {
      database.prepare(`
        INSERT INTO missions (id, name, objective, journey, engagement_id, created_by, created_at, updated_at)
        VALUES ('mission-auto-a', 'Autonomous A', 'Stay in authorized scope', 'autonomous', 'eng-a', 'operator', ?, ?)
      `).run(A, C);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, status_reason, budget_json,
          budget_usage_json, retry_count, replan_count, ended_at, created_at, updated_at
        ) VALUES (
          'run-auto-safe-stop', 'mission-auto-a', 'autonomous', 'failed', 0.4,
          'No in-contract path remains after scope policy denial',
          '{"retryBudget":2,"replanBudget":2}', '{}', 0, 0, ?, ?, ?
        )
      `).run(C, A, C);
      database.prepare(`
        INSERT INTO events (
          id, mission_id, run_id, sequence, event_type, occurred_at, actor_type,
          summary, payload_json, journey, sensitivity, created_at
        ) VALUES (
          'event-auto-safe-stop', 'mission-auto-a', 'run-auto-safe-stop', 1,
          'run.autonomous_safe_stopped', ?, 'system',
          'Safe-stopped because no in-contract path remains', '{}',
          'autonomous', 'internal', ?
        )
      `).run(C, C);
      const recovery = await body(await fetch(`${url}/api/v2/operations/runs/run-auto-safe-stop/recovery`));
      expect(recovery).toMatchObject({
        recoveryRequired: true,
        run: { journey: "autonomous", status: "failed" },
        proposedRecovery: { kind: "safe_stop" },
      });
      expect(recovery.detection.evidence).toEqual([
        expect.objectContaining({ id: "event-auto-safe-stop", eventType: "run.autonomous_safe_stopped" }),
      ]);
      expect(recovery.proposedRecovery.impact.scope).toContain("contract remains unchanged");
      expect(recovery.actions.find((item: any) => item.kind === "terminate")).toMatchObject({ available: false, command: null });

      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, status_reason, budget_json,
          budget_usage_json, retry_count, replan_count, created_at, updated_at
        ) VALUES (
          'run-auto-blocked-safe-stop', 'mission-auto-a', 'autonomous', 'blocked', 0.4,
          'Safe-stopped because the next action is outside the signed contract',
          '{"retryBudget":2,"replanBudget":2}', '{}', 0, 0, ?, ?
        )
      `).run(A, C);
      database.prepare(`
        INSERT INTO events (
          id, mission_id, run_id, sequence, event_type, occurred_at, actor_type,
          summary, payload_json, journey, sensitivity, created_at
        ) VALUES (
          'event-auto-blocked-safe-stop', 'mission-auto-a', 'run-auto-blocked-safe-stop', 1,
          'run.autonomous_safe_stopped', ?, 'system', 'No in-contract path remains', '{}',
          'autonomous', 'internal', ?
        )
      `).run(C, C);
      const lateRecoveryEvent = database.prepare(`
        INSERT INTO events (
          id, mission_id, run_id, sequence, event_type, occurred_at, actor_type,
          summary, payload_json, journey, sensitivity, created_at
        ) VALUES (?, 'mission-auto-a', 'run-auto-blocked-safe-stop', ?,
          'run.recovery_started', ?, 'system', 'Later diagnostic event', '{}',
          'autonomous', 'internal', ?)
      `);
      for (let sequence = 2; sequence <= 14; sequence += 1) {
        lateRecoveryEvent.run(`event-auto-late-${sequence}`, sequence, C, C);
      }
      const blockedSafeStopState = {
        schemaVersion: 1,
        run: {
          id: "run-auto-blocked-safe-stop", missionId: "mission-auto-a", journey: "autonomous",
          state: "blocked", stateVersion: 1,
          reason: "Safe-stopped because the next action is outside the signed contract",
          leaseOwner: null, leaseExpiresAt: null,
        },
        control: {
          budget: {}, retryCount: 0, replanCount: 0, circuits: {}, progress: {},
          recovery: {
            kind: "retry", failedActionId: "action-outside-contract", notBefore: C,
            reason: "A stale recovery directive must not override the durable safe stop",
          },
        },
        completedActionIds: [], inFlightActions: [], lastEventSequence: 14,
      };
      database.prepare(`
        INSERT INTO checkpoints (
          id, mission_id, run_id, journey, event_sequence, plan_version,
          state_json, state_hash, in_flight_classification, created_at
        ) VALUES (
          'checkpoint-auto-blocked-safe-stop', 'mission-auto-a', 'run-auto-blocked-safe-stop',
          'autonomous', 14, NULL, ?, ?, 'safe_no_in_flight_action', ?
        )
      `).run(JSON.stringify(blockedSafeStopState), hashJson(blockedSafeStopState), C);
      const blockedSafeStop = await body(await fetch(
        `${url}/api/v2/operations/runs/run-auto-blocked-safe-stop/recovery`,
        { headers: { "X-Test-Access": "recovery" } },
      ));
      expect(blockedSafeStop.proposedRecovery).toMatchObject({ kind: "safe_stop" });
      expect(blockedSafeStop.actions.find((item: any) => item.kind === "resume")).toMatchObject({
        available: false,
        command: null,
      });
    } finally { database.close(); }
  });

  test("preserves a legacy planning rate-limit diagnosis and offers safe zero-in-flight resume", async () => {
    const { database, url } = await application();
    try {
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          engagement_id, created_by, created_at, updated_at, control_plane
        ) VALUES (
          'mission-auto-rate-limit', 'ReaperTwo', 'Plan the authorized lab assessment',
          'autonomous', 'active', 'verified', 'eng-a', 'operator', ?, ?, 'ti_scale'
        )
      `).run(A, C);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, status_reason,
          next_action_summary, budget_json, budget_usage_json, retry_count,
          replan_count, started_at, created_at, updated_at, version, control_plane
        ) VALUES (
          'run-auto-rate-limit', 'mission-auto-rate-limit', 'autonomous', 'blocked', 0,
          'The planning provider is rate-limited and no result was committed.',
          'Build and version the first in-contract plan',
          '{"retries":2,"replans":2,"wallClockMs":3600000}', '{}', 0, 0,
          ?, ?, ?, 4, 'ti_scale'
        )
      `).run(A, A, C);
      const event = database.prepare(`
        INSERT INTO events (
          id, mission_id, run_id, sequence, event_type, occurred_at,
          actor_type, summary, payload_json, journey, sensitivity, created_at
        ) VALUES (?, 'mission-auto-rate-limit', 'run-auto-rate-limit', ?, ?, ?, ?, ?, ?,
          'autonomous', 'internal', ?)
      `);
      event.run(
        'event-auto-rate-limit-created', 1, 'mission.created', A, 'operator',
        'Autonomous mission created as a durable objective', '{}', A,
      );
      event.run(
        'event-auto-rate-limit-started', 2, 'run.autonomous_planning_started', A, 'system',
        'Autonomous planning started under the confirmed mission contract', '{}', A,
      );
      event.run(
        'event-auto-rate-limit-blocked', 3, 'run.state_changed', B, 'worker',
        'planning -> blocked: The planning provider is rate-limited and no result was committed.',
        '{"from":"planning","to":"blocked","stateVersion":4}', B,
      );
      event.run(
        'event-auto-rate-limit-safe-stop', 4, 'run.autonomous_safe_stopped', B, 'system',
        'The planning provider is rate-limited and no result was committed.',
        '{"code":"mission_runtime_rate_limit","category":"rate_limit"}', B,
      );
      const state = {
        schemaVersion: 1,
        run: {
          id: 'run-auto-rate-limit', missionId: 'mission-auto-rate-limit', journey: 'autonomous',
          state: 'blocked', stateVersion: 4,
          reason: 'The planning provider is rate-limited and no result was committed.',
          leaseOwner: null, leaseExpiresAt: null,
        },
        control: {
          budget: { limits: { retries: 2, replans: 2, wallClockMs: 3_600_000 }, usage: {} },
          retryCount: 0, replanCount: 0, circuits: {}, progress: {},
        },
        completedActionIds: [],
        inFlightActions: [],
        lastEventSequence: 3,
      };
      database.prepare(`
        INSERT INTO checkpoints (
          id, mission_id, run_id, journey, event_sequence, plan_version,
          state_json, state_hash, in_flight_classification, created_at
        ) VALUES (
          'checkpoint-auto-rate-limit', 'mission-auto-rate-limit', 'run-auto-rate-limit',
          'autonomous', 3, NULL, ?, ?, NULL, ?
        )
      `).run(JSON.stringify(state), hashJson(state), B);

      const response = await fetch(`${url}/api/v2/operations/runs/run-auto-rate-limit/recovery`, {
        headers: { "X-Test-Access": "all" },
      });
      expect(response.status).toBe(200);
      const recovery = await body(response);
      expect(recovery).toMatchObject({
        recoveryRequired: true,
        run: { journey: "autonomous", status: "blocked" },
        detection: { category: "rate_limit" },
        checkpoint: {
          id: "checkpoint-auto-rate-limit",
          eventSequence: 3,
          inFlightClassification: null,
          inFlightActions: [],
        },
        attempts: { retryCount: 0, retryLimit: 2, retriesRemaining: 2 },
        proposedRecovery: { kind: "operator_resume" },
      });
      expect(recovery.actions.find((item: any) => item.kind === "resume")).toMatchObject({
        available: true,
        command: "resume",
      });
      expect(recovery.proposedRecovery.summary).toContain("bounded planning retry");
    } finally { database.close(); }
  });

  test("projects every model-aware provider choice with truthful eligibility and keeps an empty route registry fail-closed", async () => {
    const providerIds = [
      "provider-compatible",
      "provider-unavailable",
      "provider-stale",
      "provider-budget",
      "provider-enforcement",
      "provider-model-absent",
    ] as const;
    const { database, url } = await application({ providerRouteIds: providerIds });
    try {
      const boundary = seedGuidedRecoveryMutationBoundary(
        database, "provider-candidates", "provider_turn", "2026-07-15T11:00:00.000Z",
      );
      database.prepare(`UPDATE runs SET budget_json = ? WHERE id = ?`)
        .run(JSON.stringify({ retries: 2, replans: 2, providerTokens: 100 }), boundary.runId);
      const insertHealth = database.prepare(`
        INSERT INTO health_snapshots (
          id, component_type, component_id, status, metrics_json, message, captured_at
        ) VALUES (?, 'provider', ?, ?, ?, 'Recovery provider fixture', ?)
      `);
      const ready = (overrides: Record<string, unknown> = {}) => ({
        configured: true,
        authenticated: true,
        callable: true,
        supportsGuided: true,
        enforcesAutonomousBoundary: false,
        reportsExactTokenUsage: true,
        reportsExactCostUsage: true,
        requestedModel: RECOVERY_MODEL_ID,
        returnedModel: RECOVERY_MODEL_ID,
        modelConfigurationHash: RECOVERY_MODEL_CONFIGURATION_HASH,
        attestedAt: "2026-07-15T10:30:00.000Z",
        ...overrides,
      });
      insertHealth.run("health-provider-compatible", providerIds[0], "healthy", JSON.stringify(ready()), C);
      insertHealth.run("health-provider-unavailable", providerIds[1], "unhealthy", JSON.stringify(ready()), C);
      insertHealth.run("health-provider-stale", providerIds[2], "healthy", JSON.stringify(ready({
        attestedAt: "2026-07-15T10:20:00.000Z",
      })), C);
      insertHealth.run("health-provider-budget", providerIds[3], "healthy", JSON.stringify(ready({
        reportsExactTokenUsage: false,
      })), C);
      insertHealth.run("health-provider-enforcement", providerIds[4], "healthy", JSON.stringify(ready({
        supportsGuided: false,
      })), C);
      insertHealth.run("health-provider-model-absent", providerIds[5], "healthy", JSON.stringify(ready({
        requestedModel: undefined,
        returnedModel: undefined,
        modelConfigurationHash: undefined,
      })), C);

      const response = await fetch(`${url}/api/v2/operations/runs/${boundary.runId}/recovery`, {
        headers: { "X-Test-Actor": "operator-one", "X-Test-Access": "recovery" },
      });
      expect(response.status).toBe(200);
      const recovery = await body(response);
      expect(recovery.providerCandidates).toHaveLength(providerIds.length);
      expect(recovery.providerCandidates).toEqual(expect.arrayContaining([
        expect.objectContaining({
          providerId: providerIds[0], modelId: RECOVERY_MODEL_ID,
          modelConfigurationHash: RECOVERY_MODEL_CONFIGURATION_HASH,
          eligibility: "compatible", enabled: true,
        }),
        expect.objectContaining({ providerId: providerIds[1], eligibility: "unavailable", enabled: false }),
        expect.objectContaining({ providerId: providerIds[2], eligibility: "stale", enabled: false }),
        expect.objectContaining({ providerId: providerIds[3], eligibility: "budget_incompatible", enabled: false }),
        expect.objectContaining({ providerId: providerIds[4], eligibility: "enforcement_incompatible", enabled: false }),
        expect.objectContaining({
          providerId: providerIds[5], modelId: null, modelConfigurationHash: null,
          eligibility: "unavailable", enabled: false,
        }),
      ]));
      for (const candidate of recovery.providerCandidates) expect(candidate.reason).toMatch(/\S/u);
      expect(recovery.actions.find((item: any) => item.kind === "change_provider")).toMatchObject({
        available: true,
        command: "change_provider",
      });
    } finally { database.close(); }

    const failClosed = await application({ providerRouteIds: [] });
    try {
      const boundary = seedGuidedRecoveryMutationBoundary(
        failClosed.database, "provider-none", "provider_turn", "2026-07-15T11:00:00.000Z",
      );
      const response = await fetch(`${failClosed.url}/api/v2/operations/runs/${boundary.runId}/recovery`, {
        headers: { "X-Test-Actor": "operator-one", "X-Test-Access": "recovery" },
      });
      const recovery = await body(response);
      expect(recovery.providerCandidates).toEqual([]);
      expect(recovery.actions.find((item: any) => item.kind === "change_provider")).toMatchObject({
        available: false,
        command: null,
      });
      const mutation = await fetch(
        `${failClosed.url}/api/v2/operations/runs/${boundary.runId}/recovery/provider`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": "provider-empty-registry",
            "X-Test-Actor": "operator-one",
            "X-Test-Access": "recovery",
          },
          body: JSON.stringify({
            ...boundary.exact,
            providerId: "grok-acp",
            modelId: RECOVERY_MODEL_ID,
            modelConfigurationHash: RECOVERY_MODEL_CONFIGURATION_HASH,
            guidedDecisionId: boundary.decisionId,
            expectedDecisionFingerprint: boundary.fingerprint,
            reason: "Prove the empty provider registry stays fail closed",
          }),
        },
      );
      expect(mutation.status).toBe(409);
      expect(await body(mutation)).toMatchObject({ error: { code: "provider_route_not_callable" } });
    } finally { failClosed.database.close(); }
  });

  test("binds Guided recovery changes to the current unexpired exact decision without renewing expiry", async () => {
    const { database, url } = await application();
    try {
      database.prepare(`
        INSERT INTO health_snapshots (
          id, component_type, component_id, status, metrics_json, message, captured_at
        ) VALUES (
          'health-guided-recovery-provider', 'provider', 'grok-acp', 'healthy', ?,
          'Callable Guided recovery route', '2026-07-15T10:30:00.000Z'
        )
      `).run(JSON.stringify({
        authenticated: true,
        callable: true,
        supportsGuided: true,
        enforcesAutonomousBoundary: true,
        reportsExactTokenUsage: true,
        reportsExactCostUsage: true,
        requestedModel: RECOVERY_MODEL_ID,
        returnedModel: RECOVERY_MODEL_ID,
        modelConfigurationHash: RECOVERY_MODEL_CONFIGURATION_HASH,
        attestedAt: "2026-07-15T10:30:00.000Z",
      }));
      const headers = (key: string) => ({
        "Content-Type": "application/json",
        "Idempotency-Key": key,
        "X-Test-Actor": "operator-one",
        "X-Test-Access": "recovery",
      });

      const expiredReassign = seedGuidedRecoveryMutationBoundary(
        database, "expired-reassign", "manual", "2026-07-15T10:29:59.000Z",
      );
      const expiredReassignResponse = await fetch(
        `${url}/api/v2/operations/runs/${expiredReassign.runId}/recovery/reassign`,
        {
          method: "POST",
          headers: headers("guided-expired-reassign"),
          body: JSON.stringify({
            ...expiredReassign.exact,
            targetAgentId: expiredReassign.candidateId,
            capability: "network.recon",
            guidedDecisionId: expiredReassign.decisionId,
            expectedDecisionFingerprint: expiredReassign.fingerprint,
            reason: "Use the declared-capable replacement specialist",
          }),
        },
      );
      expect(expiredReassignResponse.status).toBe(409);
      expect(await body(expiredReassignResponse)).toMatchObject({ error: { code: "guided_recovery_decision_expired" } });
      expect((database.prepare(`SELECT count(*) AS count FROM assignments WHERE run_id = ?`).get(expiredReassign.runId) as { count: number }).count).toBe(1);

      const expiredProvider = seedGuidedRecoveryMutationBoundary(
        database, "expired-provider", "provider_turn", "2026-07-15T10:29:59.000Z",
      );
      const expiredProviderResponse = await fetch(
        `${url}/api/v2/operations/runs/${expiredProvider.runId}/recovery/provider`,
        {
          method: "POST",
          headers: headers("guided-expired-provider"),
          body: JSON.stringify({
            ...expiredProvider.exact,
            providerId: "grok-acp",
            modelId: RECOVERY_MODEL_ID,
            modelConfigurationHash: RECOVERY_MODEL_CONFIGURATION_HASH,
            guidedDecisionId: expiredProvider.decisionId,
            expectedDecisionFingerprint: expiredProvider.fingerprint,
            reason: "Use the healthy callable provider route",
          }),
        },
      );
      expect(expiredProviderResponse.status).toBe(409);
      expect(await body(expiredProviderResponse)).toMatchObject({ error: { code: "guided_recovery_decision_expired" } });

      const currentReassign = seedGuidedRecoveryMutationBoundary(
        database, "current-reassign", "manual", "2026-07-15T11:00:00.000Z",
      );
      const fingerprintMismatch = await fetch(
        `${url}/api/v2/operations/runs/${currentReassign.runId}/recovery/reassign`,
        {
          method: "POST",
          headers: headers("guided-fingerprint-mismatch"),
          body: JSON.stringify({
            ...currentReassign.exact,
            targetAgentId: currentReassign.candidateId,
            capability: "network.recon",
            guidedDecisionId: currentReassign.decisionId,
            expectedDecisionFingerprint: "e".repeat(64),
            reason: "Use the declared-capable replacement specialist",
          }),
        },
      );
      expect(fingerprintMismatch.status).toBe(409);
      expect(await body(fingerprintMismatch)).toMatchObject({ error: { code: "guided_recovery_not_represented" } });

      const reassignBody = JSON.stringify({
        ...currentReassign.exact,
        targetAgentId: currentReassign.candidateId,
        capability: "network.recon",
        guidedDecisionId: currentReassign.decisionId,
        expectedDecisionFingerprint: currentReassign.fingerprint,
        reason: "Use the declared-capable replacement specialist",
      });
      const reassigned = await fetch(
        `${url}/api/v2/operations/runs/${currentReassign.runId}/recovery/reassign`,
        { method: "POST", headers: headers("guided-current-reassign"), body: reassignBody },
      );
      expect(reassigned.status).toBe(200);
      expect(await body(reassigned)).toMatchObject({
        mutation: { kind: "reassign", assignmentId: expect.any(String), agentId: currentReassign.candidateId },
      });
      const decisions = database.prepare(`
        SELECT id, status, expires_at FROM guided_decisions WHERE run_id = ? ORDER BY created_at, id
      `).all(currentReassign.runId) as Array<{ id: string; status: string; expires_at: string }>;
      expect(decisions).toHaveLength(2);
      expect(decisions.find((item) => item.id === currentReassign.decisionId)?.status).toBe("cancelled");
      expect(decisions.find((item) => item.status === "pending")?.expires_at).toBe("2026-07-15T11:00:00.000Z");
      const replayedReassignment = await fetch(
        `${url}/api/v2/operations/runs/${currentReassign.runId}/recovery/reassign`,
        { method: "POST", headers: headers("guided-current-reassign"), body: reassignBody },
      );
      expect(replayedReassignment.status).toBe(200);

      const currentProvider = seedGuidedRecoveryMutationBoundary(
        database, "current-provider", "provider_turn", "2026-07-15T11:00:00.000Z",
      );
      const missingModelHash = await fetch(
        `${url}/api/v2/operations/runs/${currentProvider.runId}/recovery/provider`,
        {
          method: "POST",
          headers: headers("guided-current-provider-missing-model-hash"),
          body: JSON.stringify({
            ...currentProvider.exact,
            providerId: "grok-acp",
            modelId: RECOVERY_MODEL_ID,
            guidedDecisionId: currentProvider.decisionId,
            expectedDecisionFingerprint: currentProvider.fingerprint,
            reason: "Use only an exact provider and model configuration",
          }),
        },
      );
      expect(missingModelHash.status).toBe(400);
      expect(await body(missingModelHash)).toMatchObject({ error: { code: "invalid_request" } });
      const changedReadiness = await fetch(
        `${url}/api/v2/operations/runs/${currentProvider.runId}/recovery/provider`,
        {
          method: "POST",
          headers: headers("guided-current-provider-stale-model"),
          body: JSON.stringify({
            ...currentProvider.exact,
            providerId: "grok-acp",
            modelId: "xai/different-model",
            modelConfigurationHash: RECOVERY_MODEL_CONFIGURATION_HASH,
            guidedDecisionId: currentProvider.decisionId,
            expectedDecisionFingerprint: currentProvider.fingerprint,
            reason: "Use only the exact provider model shown by readiness",
          }),
        },
      );
      expect(changedReadiness.status).toBe(409);
      expect(await body(changedReadiness)).toMatchObject({ error: { code: "provider_route_model_changed" } });
      const changedProvider = await fetch(
        `${url}/api/v2/operations/runs/${currentProvider.runId}/recovery/provider`,
        {
          method: "POST",
          headers: headers("guided-current-provider"),
          body: JSON.stringify({
            ...currentProvider.exact,
            providerId: "grok-acp",
            modelId: RECOVERY_MODEL_ID,
            modelConfigurationHash: RECOVERY_MODEL_CONFIGURATION_HASH,
            guidedDecisionId: currentProvider.decisionId,
            expectedDecisionFingerprint: currentProvider.fingerprint,
            reason: "Use the healthy callable provider route",
          }),
        },
      );
      expect(changedProvider.status).toBe(200);
      expect(await body(changedProvider)).toMatchObject({
        mutation: {
          kind: "change_provider",
          providerId: "grok-acp",
          modelId: RECOVERY_MODEL_ID,
          modelConfigurationHash: RECOVERY_MODEL_CONFIGURATION_HASH,
          providerRouteVersion: 1,
        },
      });
      const binding = JSON.parse((database.prepare(`SELECT value_json FROM settings WHERE key = ?`)
        .get(recoveryProviderRouteSettingKey(currentProvider.runId)) as { value_json: string }).value_json);
      expect(binding).toMatchObject({
        schemaVersion: 2,
        providerId: "grok-acp",
        modelId: RECOVERY_MODEL_ID,
        modelConfigurationHash: RECOVERY_MODEL_CONFIGURATION_HASH,
        stepId: currentProvider.stepId,
        assignmentId: currentProvider.assignmentId,
      });
      const routeEvent = database.prepare(`
        SELECT payload_json FROM events WHERE run_id = ? AND event_type = 'run.provider_route_changed'
      `).get(currentProvider.runId) as { payload_json: string };
      expect(JSON.parse(routeEvent.payload_json)).toMatchObject({
        providerId: "grok-acp",
        modelId: RECOVERY_MODEL_ID,
        modelConfigurationHash: RECOVERY_MODEL_CONFIGURATION_HASH,
      });
    } finally { database.close(); }
  });

  test("cursor pagination and assignment projections remain engagement scoped", async () => {
    const { database, url } = await application();
    try {
      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity, verification_state,
          summary, extracted_text, created_by, created_at
        ) VALUES ('evidence-a-legacy-tool-output', 'mission-a', 'run-a',
          'mcp:scanner.run', '2026-07-15T10:04:00.000Z', 'lab.internal', 'tool_result',
          ?, '{"processSucceeded":true}', 0.95, 'private', 'verified',
          'Legacy successful tool output', 'raw legacy output', 'runtime',
          '2026-07-15T10:04:00.000Z')
      `).run("f".repeat(64));
      const first = await body(await fetch(`${url}/api/v2/agents?limit=1`));
      expect(first.items).toHaveLength(1);
      expect(first.nextCursor).toEqual(expect.any(String));
      const second = await body(await fetch(`${url}/api/v2/agents?limit=1&cursor=${encodeURIComponent(first.nextCursor)}`));
      expect(second.items).toHaveLength(1);
      expect(second.items[0].id).not.toBe(first.items[0].id);

      const assignments = await body(await fetch(`${url}/api/v2/agents/agent-one/assignments`));
      expect(assignments.items.map((item: any) => item.id)).toEqual(["assignment-a"]);
      expect(JSON.stringify(assignments)).not.toContain("assignment-b");

      const evidenceFirst = await body(await fetch(`${url}/api/v2/intelligence/evidence?limit=1`));
      expect(evidenceFirst.items[0].id).toBe("evidence-a-new");
      expect(evidenceFirst.items[0].recordClass).toBe("evidence");
      const evidenceSecond = await body(await fetch(`${url}/api/v2/intelligence/evidence?limit=1&cursor=${encodeURIComponent(evidenceFirst.nextCursor)}`));
      expect(evidenceSecond.items[0].id).toBe("evidence-a-old");
      expect(JSON.stringify(evidenceFirst)).not.toContain("Engagement B");
      expect(JSON.stringify(evidenceFirst)).not.toContain("observed output (observe-only)");
      const operationalLogs = await body(await fetch(`${url}/api/v2/intelligence/evidence?recordClass=operational_log`));
      expect(operationalLogs.items).toEqual([
        expect.objectContaining({
          id: "evidence-a-legacy-tool-output",
          evidenceType: "tool_result",
          recordClass: "operational_log",
        }),
        expect.objectContaining({
          id: "evidence-a-operational-log",
          evidenceType: "command_output",
          recordClass: "operational_log",
        }),
      ]);
      const allEvidenceRecords = await body(await fetch(`${url}/api/v2/intelligence/evidence?recordClass=all`));
      expect(allEvidenceRecords.items.map((item: any) => item.id)).toContain("evidence-a-operational-log");
      const operationalLogDetail = await body(await fetch(`${url}/api/v2/intelligence/evidence/evidence-a-operational-log`));
      expect(operationalLogDetail).toMatchObject({
        id: "evidence-a-operational-log",
        recordClass: "operational_log",
        summary: "observed output (observe-only)",
      });
      expect(await body(await fetch(`${url}/api/v2/intelligence/evidence/evidence-a-legacy-tool-output`)))
        .toMatchObject({ id: "evidence-a-legacy-tool-output", recordClass: "operational_log" });
      expect((await fetch(`${url}/api/v2/intelligence/evidence?recordClass=raw_output`)).status).toBe(400);
      const searched = await body(await fetch(`${url}/api/v2/intelligence/evidence?query=Credential`));
      expect(searched.items.map((item: any) => item.id)).toEqual(["evidence-a-new"]);
      const findings = await body(await fetch(`${url}/api/v2/intelligence/findings?query=Ready`));
      expect(findings.items.map((item: any) => item.id)).toEqual(["finding-a-ready"]);
    } finally { database.close(); }
  });

  test("keeps archived-run evidence deep links stable and never constructs deleted or cross-scope relationships", async () => {
    const { database, url } = await application();
    try {
      database.prepare("UPDATE missions SET status = 'archived' WHERE id = 'mission-a'").run();
      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity, verification_state,
          summary, artifact_id, created_by, created_at
        ) VALUES (
          'evidence-cross-relation', 'mission-a', 'run-b', 'fixture', ?, 'lab.internal',
          'service', ?, '{}', 0.5, 'private', 'unverified',
          'Cross-mission historical relation', 'artifact-report-b', 'operator', ?
        )
      `).run(A, HASH_B, A);
      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity, verification_state,
          summary, artifact_id, created_by, created_at
        ) VALUES (
          'evidence-deleted-artifact', 'mission-a', 'run-a', 'fixture', ?, 'lab.internal',
          'file_artifact_with_hash', ?, '{"lifecycle":"deleted_artifact"}', 0.5,
          'private', 'disputed', 'Archived evidence with a deleted artifact reference',
          'artifact-deleted', 'operator', ?
        )
      `).run(A, HASH_B, A);
      database.prepare(`
        INSERT INTO findings (
          id, mission_id, run_id, title, severity, confidence, affected_scope,
          description, impact, review_status, created_at, updated_at
        ) VALUES (
          'finding-cross-relation', 'mission-a', 'run-b', 'Cross-mission historical finding',
          'informational', 0.5, 'lab.internal', 'No same-mission run', 'No impact asserted',
          'draft', ?, ?
        )
      `).run(A, A);
      database.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, journey, artifact_type, storage_uri, content_hash,
          byte_size, media_type, sensitivity, metadata_json, created_at
        ) VALUES (
          'artifact-cross-relation', 'mission-a', 'run-b', 'guided', 'imported_metadata',
          'artifact-store://metadata/cross', ?, 1, 'application/json', 'private', '{}', ?
        )
      `).run(HASH_B, A);
      expect(database.prepare("SELECT status FROM missions WHERE id = 'mission-a'").get())
        .toEqual({ status: "archived" });
      const archivedEvidenceResponse = await fetch(
        `${url}/api/v2/intelligence/evidence/evidence-a-new`,
      );
      expect(archivedEvidenceResponse.status).toBe(200);
      const evidence = await body(archivedEvidenceResponse);
      expect(evidence).toMatchObject({
        id: "evidence-a-new",
        mission: { id: "mission-a", name: "Engagement A" },
        runId: "run-a",
        run: { id: "run-a" },
        artifactId: "artifact-report-a",
        artifact: { id: "artifact-report-a", artifactType: "mission_report" },
      });
      const deletedArtifactEvidenceResponse = await fetch(
        `${url}/api/v2/intelligence/evidence/evidence-deleted-artifact`,
      );
      expect(deletedArtifactEvidenceResponse.status).toBe(200);
      expect(await body(deletedArtifactEvidenceResponse)).toMatchObject({
        id: "evidence-deleted-artifact",
        mission: { id: "mission-a", name: "Engagement A" },
        runId: "run-a",
        run: { id: "run-a" },
        artifactId: "artifact-deleted",
        artifact: null,
      });

      const mismatchedEvidence = await body(await fetch(`${url}/api/v2/intelligence/evidence/evidence-cross-relation`));
      expect(mismatchedEvidence).toMatchObject({
        id: "evidence-cross-relation",
        runId: "run-b",
        run: null,
        artifactId: "artifact-report-b",
        artifact: null,
      });

      const finding = await body(await fetch(`${url}/api/v2/intelligence/findings/finding-a-ready`));
      expect(finding).toMatchObject({ runId: "run-a", run: { id: "run-a" } });
      expect(finding.evidence).toEqual([
        expect.objectContaining({ id: "evidence-a-new", relationship: "supports" }),
      ]);
      const mismatchedFinding = await body(await fetch(`${url}/api/v2/intelligence/findings/finding-cross-relation`));
      expect(mismatchedFinding).toMatchObject({ runId: "run-b", run: null, evidence: [] });

      const artifact = await body(await fetch(`${url}/api/v2/intelligence/artifacts/artifact-report-a`));
      expect(artifact).toMatchObject({ runId: "run-a", run: { id: "run-a" } });
      expect(artifact.evidence).toEqual([
        expect.objectContaining({ id: "evidence-a-new", verificationState: "verified" }),
      ]);
      const mismatchedArtifact = await body(await fetch(`${url}/api/v2/intelligence/artifacts/artifact-cross-relation`));
      expect(mismatchedArtifact).toMatchObject({ runId: "run-b", run: null, evidence: [] });
      expect(JSON.stringify({ evidence, artifact })).not.toContain("artifact-report-b");
    } finally { database.close(); }
  });

  test("correlated observability and system projections redact secrets", async () => {
    const { database, url } = await application();
    try {
      const events = await body(await fetch(`${url}/api/v2/observability/events?traceId=trace-shared`));
      expect(events.items.map((item: any) => item.id)).toEqual(["event-a"]);
      expect(events.items[0].correlation.traceId).toBe("trace-shared");
      const logs = await body(await fetch(`${url}/api/v2/observability/logs?traceId=trace-shared&query=Provider`));
      expect(logs.items.map((item: any) => item.id)).toEqual(["log-a"]);
      const agent = await body(await fetch(`${url}/api/v2/agents/agent-one`));
      const evidence = await body(await fetch(`${url}/api/v2/intelligence/evidence/evidence-a-new`));
      const policies = await body(await fetch(`${url}/api/v2/system/policies`));
      const mcp = await body(await fetch(`${url}/api/v2/system/mcp`));
      const report = await body(await fetch(`${url}/api/v2/reports`));
      expect(report.items.map((item: any) => item.id)).toEqual(["artifact-report-a"]);
      expect(report.items[0].storage).toEqual({ scheme: "https", available: true });
      expect(report.items[0].contextPackIds).toEqual(["context-a"]);
      expect(report.items[0].metadata).toMatchObject({
        downloadUrl: "/api/v2/reports/artifact-report-a/download",
        producerPath: "[REDACTED LOCATION]",
      });
      const actions = await body(await fetch(`${url}/api/v2/operations/actions?runId=run-a`));
      expect(actions.items).toMatchObject([{
        id: "action-a", runId: "run-a", journey: "guided", status: "succeeded",
        intentSummary: "Map approved target", resultSummary: "Unique evidence retained",
        retryCount: 1, contextPackId: "context-a",
      }]);
      expect(JSON.stringify(actions)).not.toContain("action-secret-123");
      expect(JSON.stringify(await body(await fetch(`${url}/api/v2/operations/actions`)))).not.toContain("action-b");
      expect((await fetch(`${url}/api/v2/reports/artifact-data-a`)).status).toBe(404);
      const providers = await body(await fetch(`${url}/api/v2/system/providers`));
      expect(providers.items).toMatchObject([{ provider: "grok", model: "expert", turnCount: 1 }]);
      const health = await body(await fetch(`${url}/api/v2/system/health`));
      expect(health.items).toMatchObject([{ componentType: "agent", componentId: "agent-one", status: "healthy" }]);
      const evaluations = await body(await fetch(`${url}/api/v2/learning/evaluations`));
      expect(evaluations.items.map((item: any) => item.id)).toEqual(["evaluation-a"]);
      expect(evaluations.items[0].comparison).toMatchObject({
        status: "insufficient_data",
        reason: "no_prior_same_scope_evaluation",
        prior: null,
        metrics: [],
      });
      expect(evaluations.items[0].budget.metrics).toMatchObject([
        { key: "wallClockMs", limit: 600_000, usage: 120_000, usageStatus: "recorded_exact", status: "within_limit" },
        { key: "providerTokens", limit: 100, usage: 30, usageStatus: "recorded_exact", status: "within_limit" },
        { key: "estimatedCost", limit: 1, usage: 0, usageStatus: "recorded_estimate", status: "within_limit" },
        { key: "toolCalls", limit: 5, usage: 1, usageStatus: "recorded_exact", status: "within_limit" },
        { key: "retries", limit: 3, usage: 2, usageStatus: "recorded_exact", status: "within_limit" },
        { key: "replans", limit: 2, usage: 1, usageStatus: "recorded_exact", status: "within_limit" },
      ]);

      database.prepare("UPDATE runs SET budget_usage_json = '{}' WHERE id = 'run-a'").run();
      database.prepare("UPDATE provider_turns SET input_tokens = NULL WHERE id = 'turn-a'").run();
      const unknownUsage = await body(await fetch(`${url}/api/v2/learning/evaluations?runId=run-a`));
      expect(unknownUsage.items[0].budget.metrics.find((metric: any) => metric.key === "providerTokens"))
        .toMatchObject({ limit: 100, usage: null, usageStatus: "unknown", status: "unknown_usage", usageSource: null });
      const combined = JSON.stringify({ events, logs, agent, evidence, policies, mcp, report });
      for (const secret of [
        "provider-secret-123", "tool-secret-123", "event-secret-123", "event-bearer-secret",
        "log-bearer-secret", "log-secret-123", "raw-secret-123", "provenance-secret-123", // gitleaks:allow -- synthetic redaction fixtures
        "chain-secret-123", "artifact-secret-123", "mcp-secret-123", "policy-secret-123", // gitleaks:allow -- synthetic redaction fixtures
        "user:password", "/restricted/capture",
      ]) expect(combined).not.toContain(secret);
      expect(combined).toContain("[REDACTED]");
    } finally { database.close(); }
  });

  test("returns the canonical prior-run comparison with real metrics", async () => {
    const { database, url } = await application();
    try {
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, started_at, ended_at, created_at, updated_at
        ) VALUES ('run-a-prior', 'mission-a', 'guided', 'completed', 1, ?, ?, ?, ?)
      `).run(A, B, A, B);
      database.prepare(`
        INSERT INTO run_evaluations (
          id, mission_id, run_id, journey, scores_json, metrics_json,
          retrospective, evidence_coverage, created_by, created_at
        ) VALUES (
          'evaluation-a-prior', 'mission-a', 'run-a-prior', 'guided',
          '{"objectiveCompletion":1,"evidenceQuality":0.5}',
          '{"durationMs":120000,"repeatedActionRate":0.5}',
          'Earlier canonical evaluation', 0.5, 'evaluator', ?
        )
      `).run(B);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, started_at, ended_at, created_at, updated_at
        ) VALUES ('run-a-current', 'mission-a', 'guided', 'completed', 1, ?, ?, ?, ?)
      `).run(B, C, B, C);
      database.prepare(`
        INSERT INTO run_evaluations (
          id, mission_id, run_id, journey, scores_json, metrics_json,
          retrospective, evidence_coverage, created_by, created_at
        ) VALUES (
          'evaluation-a-current', 'mission-a', 'run-a-current', 'guided',
          '{"objectiveCompletion":1,"evidenceQuality":0.8}',
          '{"durationMs":60000,"repeatedActionRate":0}',
          'Current canonical evaluation', 0.8, 'evaluator', ?
        )
      `).run(C);
      database.prepare(`
        INSERT INTO run_evaluation_comparisons (
          evaluation_id, run_id, comparison_status, basis, reason,
          prior_evaluation_id, prior_run_id, prior_terminal_status,
          terminal_status_match, metrics_json, summary, created_at
        ) VALUES (
          'evaluation-a-current', 'run-a-current', 'available', 'same_mission_and_journey',
          'canonical_prior_selected', 'evaluation-a-prior', 'run-a-prior', 'completed', 1,
          ?, 'Compared with one earlier same-mission guided run. This descriptive comparison does not establish that the system improved.', ?
        )
      `).run(JSON.stringify([{
        key: "durationMs", label: "Elapsed time", unit: "milliseconds",
        favorableDirection: "lower", current: 60_000, prior: 120_000,
        delta: -60_000, relativeDelta: -0.5, movement: "favorable",
      }]), C);

      const response = await body(await fetch(`${url}/api/v2/learning/evaluations?runId=run-a-current`));
      expect(response.items).toHaveLength(1);
      expect(response.items[0].comparison).toMatchObject({
        status: "available",
        basis: "same_mission_and_journey",
        prior: { evaluationId: "evaluation-a-prior", runId: "run-a-prior", terminalStatus: "completed" },
        terminalStatusMatch: true,
        metrics: [{ key: "durationMs", current: 60_000, prior: 120_000, movement: "favorable" }],
      });
      expect(response.items[0].budget.metrics.find((metric: any) => metric.key === "providerTokens"))
        .toMatchObject({ limit: null, usage: null, usageStatus: "unknown", status: "unknown_usage" });
      expect(response.items[0].comparison.summary).toContain("does not establish that the system improved");
    } finally { database.close(); }
  });

  test("finding verification is evidence-gated, idempotent, versioned, and audited", async () => {
    const { database, url } = await application();
    try {
      const headers = { "Content-Type": "application/json", "Idempotency-Key": "finding-review-empty-001" };
      const denied = await fetch(`${url}/api/v2/intelligence/findings/finding-a-empty/review`, {
        method: "POST", headers,
        body: JSON.stringify({ expectedVersion: 1, status: "verified", reason: "No evidence is linked", operatorOverride: false }),
      });
      expect(denied.status).toBe(409);
      expect(await body(denied)).toMatchObject({ error: { code: "operations_state_conflict" } });

      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity, verification_state,
          summary, created_by, created_at
        ) VALUES ('evidence-a-raw-success', 'mission-a', 'run-a', 'mcp:scanner.run', ?,
          'lab.internal', 'command_output', ?, '{"processSucceeded":true}', 0.95,
          'private', 'verified', 'Successful raw tool output', 'runtime', ?)
      `).run(C, "f".repeat(64), C);
      database.prepare(`
        INSERT INTO findings (
          id, mission_id, run_id, title, severity, confidence, affected_scope,
          description, impact, review_status, created_at, updated_at
        ) VALUES ('finding-a-raw-success', 'mission-a', 'run-a', 'Raw output only',
          'high', 0.9, 'lab.internal', 'No verified evidence', 'No supported impact',
          'under_review', ?, ?)
      `).run(B, B);
      database.prepare(`
        INSERT INTO finding_evidence (finding_id, evidence_id, relationship, added_at)
        VALUES ('finding-a-raw-success', 'evidence-a-raw-success', 'supports', ?)
      `).run(C);
      const rawDenied = await fetch(`${url}/api/v2/intelligence/findings/finding-a-raw-success/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "finding-review-raw-001" },
        body: JSON.stringify({ expectedVersion: 1, status: "verified", reason: "Tool process succeeded", operatorOverride: false }),
      });
      expect(rawDenied.status).toBe(409);
      expect(await body(rawDenied)).toMatchObject({ error: { code: "operations_state_conflict" } });

      const request = {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "finding-review-ready-001" },
        body: JSON.stringify({ expectedVersion: 1, status: "verified", reason: "Reviewed immutable supporting evidence token=review-secret-123", operatorOverride: false }),
      };
      const firstResponse = await fetch(`${url}/api/v2/intelligence/findings/finding-a-ready/review`, request);
      const first = await body(firstResponse);
      expect(firstResponse.status).toBe(200);
      expect(first.finding).toMatchObject({ reviewStatus: "verified", evidenceCount: 1, version: 2 });
      expect(await body(await fetch(`${url}/api/v2/intelligence/findings/finding-a-ready/review`, request))).toEqual(first);
      const stale = await fetch(`${url}/api/v2/intelligence/findings/finding-a-ready/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "finding-review-ready-002" },
        body: JSON.stringify({ expectedVersion: 1, status: "rejected", reason: "Stale review" }),
      });
      expect(stale.status).toBe(409);
      expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE resource_id = 'finding-a-ready'").get()).toEqual({ count: 1 });
      expect(JSON.stringify(database.prepare("SELECT reason, details_json FROM audit_records WHERE resource_id = 'finding-a-ready'").get())).not.toContain("review-secret-123");
    } finally { database.close(); }
  });

  test("finding and lesson gates ignore hidden, foreign-mission, and foreign-run support", async () => {
    const { database, url } = await application();
    try {
      database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES ('run-a-other', 'mission-a', 'guided', 'completed', ?, ?)
      `).run(A, C);
      const evidence = database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, evidence_type,
          content_hash, provenance_json, confidence, sensitivity,
          verification_state, summary, created_by, created_at
        ) VALUES (?, ?, ?, 'specialist', ?, 'service', ?, '{}', 0.9, ?,
          'verified', ?, 'agent-one', ?)
      `);
      evidence.run("evidence-a-restricted", "mission-a", "run-a", C, "d".repeat(64), "restricted", "Exact but restricted support", C);
      evidence.run("evidence-a-other-run", "mission-a", "run-a-other", C, "e".repeat(64), "private", "Different run support", C);

      const finding = database.prepare(`
        INSERT INTO findings (
          id, mission_id, run_id, title, severity, confidence, affected_scope,
          description, impact, review_status, created_at, updated_at
        ) VALUES (?, 'mission-a', 'run-a', ?, 'high', 0.9, 'lab.internal',
          'Adversarial support fixture', 'Authorized impact', 'under_review', ?, ?)
      `);
      finding.run("finding-hidden-support", "Hidden exact support", B, B);
      finding.run("finding-foreign-support", "Foreign engagement support", B, B);
      finding.run("finding-other-run-support", "Other run support", B, B);
      const findingEvidence = database.prepare(`
        INSERT INTO finding_evidence (finding_id, evidence_id, relationship, added_at)
        VALUES (?, ?, 'supports', ?)
      `);
      findingEvidence.run("finding-hidden-support", "evidence-a-restricted", C);
      findingEvidence.run("finding-foreign-support", "evidence-b", C);
      findingEvidence.run("finding-other-run-support", "evidence-a-other-run", C);

      const reviewFinding = (id: string, key: string, all = false) => fetch(
        `${url}/api/v2/intelligence/findings/${id}/review`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": key,
            ...(all ? { "X-Test-Access": "all" } : {}),
          },
          body: JSON.stringify({
            expectedVersion: 1,
            status: "verified",
            reason: "Adversarial scope-bound review",
            operatorOverride: false,
          }),
        },
      );
      expect((await reviewFinding("finding-hidden-support", "finding-hidden-default-001")).status).toBe(409);
      expect((await reviewFinding("finding-hidden-support", "finding-hidden-all-001", true)).status).toBe(200);
      expect((await reviewFinding("finding-foreign-support", "finding-foreign-all-001", true)).status).toBe(409);
      expect((await reviewFinding("finding-other-run-support", "finding-other-run-all-001", true)).status).toBe(409);

      const lesson = database.prepare(`
        INSERT INTO lessons (
          id, statement, lesson_type, applicability_scope, engagement_id, mission_id,
          confidence, expected_benefit, risk, status, authoring_agent_id, created_at, updated_at
        ) VALUES (?, ?, 'strategy', ?, ?, ?, 0.8, 'Bounded reuse', 'Low',
          'under_review', 'agent-other', ?, ?)
      `);
      lesson.run("lesson-global-hidden", "Global lesson with hidden support", "global", null, null, B, B);
      lesson.run("lesson-foreign-evidence", "Mission lesson with foreign evidence", "mission", "eng-a", "mission-a", B, B);
      lesson.run("lesson-foreign-run", "Mission lesson with foreign run", "mission", "eng-a", "mission-a", B, B);
      lesson.run("lesson-run-only", "Mission lesson with an exact supporting run", "mission", "eng-a", "mission-a", B, B);
      const lessonEvidence = database.prepare(`
        INSERT INTO lesson_evidence (
          lesson_id, evidence_id, run_id, relationship, rationale, created_at
        ) VALUES (?, ?, ?, 'supports', 'Adversarial support fixture', ?)
      `);
      lessonEvidence.run("lesson-global-hidden", "evidence-b", null, C);
      lessonEvidence.run("lesson-foreign-evidence", "evidence-b", null, C);
      lessonEvidence.run("lesson-foreign-run", null, "run-b", C);
      lessonEvidence.run("lesson-run-only", null, "run-a", C);

      const reviewLesson = (id: string, key: string, all = false) => fetch(
        `${url}/api/v2/learning/lessons/${id}/review`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": key,
            ...(all ? { "X-Test-Access": "all" } : {}),
          },
          body: JSON.stringify({ expectedUpdatedAt: B, status: "verified", reason: "Independent scope-bound review" }),
        },
      );
      expect((await reviewLesson("lesson-global-hidden", "lesson-global-hidden-001")).status).toBe(409);
      expect((await reviewLesson("lesson-foreign-evidence", "lesson-foreign-evidence-001", true)).status).toBe(409);
      expect((await reviewLesson("lesson-foreign-run", "lesson-foreign-run-001", true)).status).toBe(409);
      const runOnly = await body(await reviewLesson("lesson-run-only", "lesson-run-only-001"));
      expect(runOnly.lesson).toMatchObject({ status: "verified", supportingEvidenceCount: 1 });
    } finally { database.close(); }
  });

  test("lesson verification requires support and denies author self-approval", async () => {
    const { database, url } = await application();
    try {
      const self = await fetch(`${url}/api/v2/learning/lessons/lesson-self/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "lesson-self-review-001", "X-Test-Actor": "agent-self" },
        body: JSON.stringify({ expectedUpdatedAt: B, status: "verified", reason: "Attempt self approval" }),
      });
      expect(self.status).toBe(403);
      expect(await body(self)).toMatchObject({ error: { code: "operations_policy_denied" } });

      const noEvidence = await fetch(`${url}/api/v2/learning/lessons/lesson-empty/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "lesson-empty-review-001" },
        body: JSON.stringify({ expectedUpdatedAt: B, status: "verified", reason: "Independent review" }),
      });
      expect(noEvidence.status).toBe(409);

      const request = {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "lesson-ready-review-001" },
        body: JSON.stringify({ expectedUpdatedAt: B, status: "verified", reason: "Independent evidence review" }),
      };
      const firstResponse = await fetch(`${url}/api/v2/learning/lessons/lesson-ready/review`, request);
      const first = await body(firstResponse);
      expect(firstResponse.status).toBe(200);
      expect(first.lesson).toMatchObject({ status: "verified", supportingEvidenceCount: 1, reviewedBy: "reviewer-one" });
      expect(await body(await fetch(`${url}/api/v2/learning/lessons/lesson-ready/review`, request))).toEqual(first);
      const list = await body(await fetch(`${url}/api/v2/learning/lessons`));
      expect(list.items.map((item: any) => item.id)).not.toContain("lesson-b");
      const exactRun = await body(await fetch(`${url}/api/v2/learning/lessons?runId=run-a`));
      expect(exactRun.items.map((item: any) => item.id)).toEqual(["lesson-ready"]);
      const inaccessibleRun = await body(await fetch(`${url}/api/v2/learning/lessons?runId=run-b`));
      expect(inaccessibleRun.items).toEqual([]);
      const usage = await body(await fetch(`${url}/api/v2/learning/usage`));
      expect(usage.items.map((item: any) => item.id)).toEqual(["usage-a"]);
    } finally { database.close(); }
  });

  test("attack-chain verification requires visible verified evidence and exact-context chain sources", async () => {
    const { database, url } = await application();
    try {
      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, evidence_type,
          content_hash, provenance_json, confidence, sensitivity,
          verification_state, summary, created_by, created_at
        ) VALUES ('evidence-a-unverified', 'mission-a', 'run-a', 'specialist', ?,
          'service', ?, '{}', 0.8, 'private', 'unverified',
          'Not independently verified', 'agent-one', ?)
      `).run(C, "f".repeat(64), C);
      const lesson = database.prepare(`
        INSERT INTO lessons (
          id, statement, lesson_type, applicability_scope, engagement_id, mission_id,
          confidence, expected_benefit, risk, status, authoring_agent_id, created_at, updated_at
        ) VALUES (?, ?, 'attack_chain', 'mission', 'eng-a', 'mission-a', 0.85,
          'Bounded executable reuse', 'Independent review required', 'under_review',
          'agent-other', ?, ?)
      `);
      lesson.run("lesson-chain-unverified", "Chain backed only by unverified evidence", B, B);
      lesson.run("lesson-chain-foreign-source", "Chain whose normalized source crosses engagement", B, B);
      lesson.run("lesson-chain-ready", "Chain with exact verified provenance", B, B);

      retainAttackChainDetails(database, "lesson-chain-unverified", "run-a");
      retainAttackChainDetails(database, "lesson-chain-foreign-source", "run-b", "evidence-b");
      retainAttackChainDetails(database, "lesson-chain-ready", "run-a", "evidence-a-new");

      const unverifiedDetail = database.prepare(`
        SELECT id FROM lesson_attack_chain_details
        WHERE lesson_id = 'lesson-chain-unverified' ORDER BY version DESC LIMIT 1
      `).get() as { id: string };
      database.prepare(`
        INSERT INTO lesson_attack_chain_sources (
          id, lesson_id, detail_id, source_type, source_id, evidence_id,
          provenance_json, created_at
        ) VALUES ('chain-source-unverified', 'lesson-chain-unverified', ?, 'operator',
          'unverified-evidence-source', 'evidence-a-unverified', '{}', ?)
      `).run(unverifiedDetail.id, C);

      const support = database.prepare(`
        INSERT INTO lesson_evidence (
          lesson_id, evidence_id, run_id, relationship, rationale, created_at
        ) VALUES (?, ?, ?, 'supports', 'Canonical review support', ?)
      `);
      support.run("lesson-chain-unverified", "evidence-a-unverified", null, C);
      support.run("lesson-chain-unverified", null, "run-a", C);
      support.run("lesson-chain-foreign-source", "evidence-a-new", null, C);
      support.run("lesson-chain-foreign-source", null, "run-a", C);
      support.run("lesson-chain-ready", "evidence-a-new", null, C);
      support.run("lesson-chain-ready", null, "run-a", C);

      const review = (id: string, key: string, all = false) => fetch(
        `${url}/api/v2/learning/lessons/${id}/review`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": key,
            ...(all ? { "X-Test-Access": "all" } : {}),
          },
          body: JSON.stringify({ expectedUpdatedAt: B, status: "verified", reason: "Independent chain review" }),
        },
      );
      expect((await review("lesson-chain-unverified", "chain-unverified-001")).status).toBe(409);
      expect((await review("lesson-chain-foreign-source", "chain-foreign-source-001", true)).status).toBe(409);
      const ready = await body(await review("lesson-chain-ready", "chain-ready-001"));
      expect(ready.lesson).toMatchObject({ status: "verified", supportingEvidenceCount: 2 });
    } finally { database.close(); }
  });

  test("terminal completion export is scoped, metadata-only, redacted, and downloadable", async () => {
    const { database, url } = await application();
    try {
      const response = await fetch(`${url}/api/v2/reports/runs/run-a/export`);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain("application/json");
      expect(response.headers.get("content-disposition")).toBe('attachment; filename="ti-scale-run-a-completion.json"');
      expect(response.headers.get("x-content-type-options")).toBe("nosniff");
      expect(response.headers.get("cross-origin-resource-policy")).toBe("same-origin");
      const exported = await body(response);
      expect(exported).toMatchObject({
        schemaVersion: "2.4",
        exportKind: "run_completion_metadata",
        mission: { id: "mission-a", journey: "guided", authorizationStatus: "unverified" },
        run: { id: "run-a", status: "completed", retryCount: 1, replanCount: 1 },
        reportingContext: {
          status: "no_relevant_memory",
          retrievedItems: 0,
          appliedItems: 0,
          degradation: null,
        },
        privacy: { metadataOnly: true },
        integrity: { algorithm: "sha256" },
      });
      expect(exported.evidence.map((item: any) => item.id)).toEqual(["evidence-a-new", "evidence-a-old"]);
      expect(exported.findings.map((item: any) => item.id).sort()).toEqual(["finding-a-empty", "finding-a-ready"]);
      expect(exported.reports.map((item: any) => item.id)).toEqual(["artifact-report-a"]);
      expect(exported.actions).toMatchObject([{ id: "action-a", retryCount: 1 }]);
      expect(exported.decisions).toMatchObject([{ id: "approval-a", decisionType: "administrative", status: "approved" }]);
      expect(exported.memoryContext).toContainEqual(expect.objectContaining({
        id: "context-a", purpose: "Select verified lesson",
      }));
      expect(exported.memoryContext).toContainEqual(expect.objectContaining({
        id: exported.reportingContext.contextPackId,
        purpose: expect.stringContaining("Reporting:"),
      }));
      expect(exported.lessons.proposedOrVerified.map((item: any) => item.id)).toEqual(["lesson-ready"]);
      expect(exported.integrity.digest).toMatch(/^[a-f0-9]{64}$/u);
      expect(exported.events[0]).not.toHaveProperty("payload");
      expect(exported.evidence[0]).not.toHaveProperty("extractedText");
      expect(exported.evidence[0]).not.toHaveProperty("provenance");
      expect(exported.artifacts[0]).not.toHaveProperty("metadata");
      expect(exported.artifacts[0]).not.toHaveProperty("storage");
      expect(database.prepare(`
        SELECT actor_id, action, resource_type, resource_id, record_hash
        FROM audit_records WHERE action = 'run.completion_exported'
      `).get()).toMatchObject({
        actor_id: "reviewer-one", action: "run.completion_exported",
        resource_type: "run", resource_id: "run-a", record_hash: expect.stringMatching(/^[a-f0-9]{64}$/u),
      });
      const serialized = JSON.stringify(exported);
      for (const secret of [
        "raw-secret-123", "provenance-secret-123", "event-secret-123", // gitleaks:allow -- synthetic redaction fixtures
        "artifact-secret-123", "action-secret-123", "approval-secret-123", // gitleaks:allow -- synthetic redaction fixtures
        "approval-request-secret-123", "Engagement B must remain hidden", "artifact-report-b", // gitleaks:allow -- synthetic redaction fixtures
      ]) expect(serialized).not.toContain(secret);

      expect((await fetch(`${url}/api/v2/reports/runs/run-b/export`)).status).toBe(404);
      const nonterminal = await fetch(`${url}/api/v2/reports/runs/run-b/export`, { headers: { "X-Test-Access": "all" } });
      expect(nonterminal.status).toBe(409);
      expect(await body(nonterminal)).toMatchObject({ error: { code: "operations_state_conflict" } });
    } finally { database.close(); }
  });
});

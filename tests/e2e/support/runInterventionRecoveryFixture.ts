import { createHash } from "node:crypto";
import { acquireTestRunMutationAuthority } from "../../../server/control-plane/TestRunMutationAuthority";
import { createDatabaseConnection, inImmediateTransaction, type SqliteDatabase } from "../../../server/db";
import { EventRepository } from "../../../server/events";
import { hashJson } from "../../../server/orchestration/serialization";
import type { DurableActionIntent } from "../../../server/orchestration/types";
import { fingerprintAction } from "../../../server/supervisor/ActionFingerprint";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

export type RunInterventionRecoveryState =
  | "legacy_control"
  | "pause_resume"
  | "cancel"
  | "replan"
  | "reassign";

export interface RunInterventionRecoveryFixture {
  readonly state: RunInterventionRecoveryState;
  readonly missionId: string;
  readonly runId: string;
  readonly planId: string;
  readonly stepId: string;
  readonly assignmentId: string;
  readonly agentId: string;
  readonly candidateAgentId?: string;
  readonly decisionId?: string;
  readonly actionId?: string;
  readonly target: string;
}

export interface RunInterventionRecoverySnapshot {
  readonly run: {
    readonly status: string;
    readonly version: number;
    readonly controlPlane: string;
    readonly leaseOwner: string | null;
    readonly leaseExpiresAt: string | null;
    readonly statusReason: string | null;
  };
  readonly missionStatus: string;
  readonly planStatuses: readonly string[];
  readonly stepStatuses: readonly string[];
  readonly assignments: readonly { readonly id: string; readonly agentId: string; readonly status: string; readonly leaseOwner: string | null }[];
  readonly actionStatuses: readonly string[];
  readonly toolCallStatuses: readonly string[];
  readonly decisionStatuses: readonly string[];
  readonly approvalStatuses: readonly string[];
  readonly providerTurnStatuses: readonly string[];
  readonly runtimeContinuationStatuses: readonly string[];
  readonly durableRunLeaseActive: boolean;
  readonly activeControlPlaneLeaseCount: number;
  readonly executingChildCount: number;
  readonly activeChildCount: number;
  readonly events: readonly { readonly type: string; readonly sequence: number; readonly summary: string }[];
  readonly audits: readonly { readonly action: string; readonly reason: string | null }[];
  readonly checkpoints: readonly {
    readonly id: string;
    readonly eventSequence: number;
    readonly planVersion: number | null;
    readonly stateHash: string;
    readonly stateHashVerified: boolean;
    readonly inFlightCount: number;
  }[];
  readonly eventOutboxCount: number;
  readonly runtimeIdempotencyCount: number;
  readonly recoveryIdempotencyCount: number;
}

function database(): SqliteDatabase {
  if (!E2E_DATABASE_PATH) throw new Error("The isolated Playwright database path was not configured");
  return createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function representedAction(target: string): string {
  return JSON.stringify({
    action: {
      actionType: "passive_intelligence_osint",
      actionClass: "passive_intelligence_osint",
      target,
      arguments: { mode: "bounded" },
      intentSummary: "Collect one attributable observation inside the approved local fixture",
      kind: "manual",
      idempotent: true,
      destructive: false,
    },
    explanation: "Collect one bounded observation without changing target state.",
    rationale: "Reduce uncertainty while preserving an exact Guided boundary.",
    reversibility: "Read-only",
    dependencies: [],
  });
}

function representedIntent(fixture: RunInterventionRecoveryFixture): DurableActionIntent {
  return {
    missionId: fixture.missionId,
    runId: fixture.runId,
    stepId: fixture.stepId,
    assignmentId: fixture.assignmentId,
    planVersion: 1,
    actionType: "passive_intelligence_osint",
    actionClass: "passive_intelligence_osint",
    target: fixture.target,
    arguments: { mode: "bounded" },
    intentSummary: "Collect one attributable observation inside the approved local fixture",
    kind: "manual",
    idempotent: true,
    destructive: false,
  };
}

function checkpointState(input: {
  fixture: RunInterventionRecoveryFixture;
  status: string;
  reason: string;
  version: number;
  eventSequence?: number;
}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    run: {
      id: input.fixture.runId,
      missionId: input.fixture.missionId,
      journey: "guided",
      state: input.status,
      stateVersion: input.version,
      reason: input.reason,
      leaseOwner: null,
      leaseExpiresAt: null,
    },
    control: {
      budget: { limits: { retries: 2, replans: 2, concurrency: 1 }, usage: {} },
      retryCount: 0,
      replanCount: 0,
      circuits: {},
      progress: {},
    },
    completedActionIds: [],
    inFlightActions: [],
    lastEventSequence: input.eventSequence ?? 0,
  };
}

/**
 * Seeds V2 persistence records while every intervention and recovery mutation
 * is still executed through the authenticated production HTTP surface.
 *
 * The `cancel` state is deliberately different: it is an adversarial
 * durable-residue cleanup fixture. It combines child records that a valid
 * Guided lifecycle would not normally leave open together so cancellation can
 * prove it closes every durable residue class. It must not be treated as a
 * canonical Guided lifecycle fixture.
 */
export function createRunInterventionRecoveryFixture(
  state: RunInterventionRecoveryState,
  instanceId: string,
): RunInterventionRecoveryFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const suffix = `${state.replaceAll("_", "-")}-${namespace}`;
  const fixture: RunInterventionRecoveryFixture = {
    state,
    missionId: `mission-run-control-e2e-${suffix}`,
    runId: `run-control-e2e-${suffix}`,
    planId: `plan-control-e2e-${suffix}`,
    stepId: `step-control-e2e-${suffix}`,
    assignmentId: `assignment-control-e2e-${suffix}`,
    agentId: `agent-control-e2e-${suffix}`,
    ...(state === "reassign" ? { candidateAgentId: `agent-control-e2e-${suffix}-candidate` } : {}),
    ...(["pause_resume", "cancel", "replan", "reassign"].includes(state)
      ? { decisionId: `decision-control-e2e-${suffix}` }
      : {}),
    ...(["cancel", "replan", "reassign"].includes(state)
      ? { actionId: `action-control-e2e-${suffix}` }
      : {}),
    target: `${suffix}.fixture.test`,
  };
  const now = new Date();
  const nowIso = now.toISOString();
  const expiresAt = new Date(now.getTime() + 30 * 60_000).toISOString();
  const active = state === "legacy_control" || state === "pause_resume" || state === "cancel";
  const waitingAtDecision = state === "pause_resume";
  const runStatus = waitingAtDecision ? "waiting_guided_decision" : active ? "running" : "blocked";
  const reason = waitingAtDecision
    ? "The represented Guided step is waiting at an exact operator decision."
    : active
    ? "The represented Guided step is running inside the approved local fixture."
    : "A timed-out predecessor is retained at a safe exact recovery boundary.";
  const connection = database();

  try {
    inImmediateTransaction(connection, () => {
      connection.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          engagement_id, scope_json, success_criteria_json, retention_policy_json,
          memory_policy_json, created_by, created_at, updated_at, control_plane
        ) VALUES (?, ?, ?, 'guided', 'active', 'verified', ?, ?, ?, '{}', '{}',
          'e2e-local-operator', ?, ?, ?)
      `).run(
        fixture.missionId,
        `Run intervention ${suffix}`,
        "Exercise one represented intervention or recovery mutation without changing authorization scope.",
        `engagement-control-e2e-${suffix}`,
        JSON.stringify({ environment: "local_test_fixture", target: fixture.target }),
        JSON.stringify(["Every operator intervention is audited and checkpointed"]),
        nowIso,
        nowIso,
        state === "legacy_control" ? "legacy" : "ti_scale",
      );
      connection.prepare(`
        INSERT INTO mission_targets (
          id, mission_id, target, target_type, disposition, normalized_target,
          metadata_json, created_at
        ) VALUES (?, ?, ?, 'domain', 'allowed', ?, '{}', ?)
      `).run(`target-control-e2e-${suffix}`, fixture.missionId, fixture.target, fixture.target, nowIso);
      connection.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, provider_policy_json, tool_policy_json,
          configuration_json, version, last_heartbeat_at, created_at, updated_at
        ) VALUES (?, 'recon-specialist', 'Current recon specialist', 'available',
          '{}', '{}', '{}', 'e2e-1', ?, ?, ?)
      `).run(fixture.agentId, nowIso, nowIso, nowIso);
      connection.prepare(`
        INSERT INTO agent_capabilities (
          agent_id, capability, source, enabled, metadata_json
        ) VALUES (?, 'network.recon', 'runtime', 1, '{}')
      `).run(fixture.agentId);
      if (fixture.candidateAgentId) {
        connection.prepare(`
          INSERT INTO agents (
            id, role, display_name, status, provider_policy_json, tool_policy_json,
            configuration_json, version, last_heartbeat_at, created_at, updated_at
          ) VALUES (?, 'recon-specialist', 'Alternate recon specialist', 'available',
            '{}', '{}', '{}', 'e2e-1', ?, ?, ?)
        `).run(fixture.candidateAgentId, nowIso, nowIso, nowIso);
        connection.prepare(`
          INSERT INTO agent_capabilities (
            agent_id, capability, source, enabled, metadata_json
          ) VALUES (?, 'network.recon', 'live-route-attestation', 1, ?)
        `).run(fixture.candidateAgentId, JSON.stringify({ validUntil: expiresAt, attestedAt: nowIso }));
      }
      connection.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, current_plan_id, current_step_id,
          current_owner_id, progress, status_reason, next_action_summary,
          budget_json, budget_usage_json, retry_count, replan_count, started_at,
          created_at, updated_at, version, control_plane
        ) VALUES (?, ?, 'guided', ?, ?, ?, ?, ?, ?, ?, ?, '{}', 0, 0, ?, ?, ?, 1, ?)
      `).run(
        fixture.runId,
        fixture.missionId,
        runStatus,
        fixture.planId,
        fixture.stepId,
        fixture.agentId,
        active ? 0.3 : 0.4,
        reason,
        waitingAtDecision
          ? "Wait for the exact represented decision"
          : active ? "Reach the next durable checkpoint" : "Choose one server-declared recovery action",
        JSON.stringify({ retries: 2, replans: 2, concurrency: 1 }),
        active ? nowIso : null,
        nowIso,
        nowIso,
        state === "legacy_control" ? "legacy" : "ti_scale",
      );
      connection.prepare(`
        INSERT INTO plans (
          id, run_id, version, status, strategy_summary, rationale_summary,
          plan_hash, created_by, created_at, activated_at
        ) VALUES (?, ?, 1, 'active', ?, 'Preserve exact scope and evidence boundaries',
          ?, 'e2e-runtime-planner', ?, ?)
      `).run(
        fixture.planId,
        fixture.runId,
        `Correlate one bounded observation for ${fixture.target}`,
        digest(`${fixture.planId}:v1`),
        nowIso,
        nowIso,
      );
      connection.prepare(`
        INSERT INTO plan_steps (
          id, plan_id, run_id, ordinal, phase, title, objective, status,
          success_criteria_json, dependencies_json, action_class, risk_class,
          assigned_agent_id, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, 0, 'Recon', 'Collect bounded observation',
          'Reduce uncertainty with attributable local-fixture data', ?,
          '["One attributable observation is retained"]', '[]',
          'passive_intelligence_osint', 'low', ?, ?, ?, ?)
      `).run(
        fixture.stepId,
        fixture.planId,
        fixture.runId,
        waitingAtDecision ? "waiting_guided_decision" : active ? "running" : "blocked",
        fixture.agentId,
        active ? nowIso : null,
        nowIso,
        nowIso,
      );
      connection.prepare(`
        INSERT INTO mission_constraints (
          id, mission_id, constraint_type, value_json, source, created_at
        ) VALUES (?, ?, 'represented_action', ?, ?, ?)
      `).run(
        `constraint-control-e2e-${suffix}`,
        fixture.missionId,
        representedAction(fixture.target),
        fixture.stepId,
        nowIso,
      );
      connection.prepare(`
        INSERT INTO assignments (
          id, run_id, step_id, agent_id, status, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        fixture.assignmentId,
        fixture.runId,
        fixture.stepId,
        fixture.agentId,
        waitingAtDecision ? "queued" : active ? "active" : "blocked",
        waitingAtDecision ? null : active ? nowIso : null,
        nowIso,
        nowIso,
      );
      if (fixture.decisionId) {
        const intent = representedIntent(fixture);
        connection.prepare(`
          INSERT INTO guided_decisions (
            id, mission_id, run_id, step_id, requested_action_fingerprint,
            requested_parameters_json, rationale, risk_class, reversibility,
            status, expires_at, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 'low', 'Read-only', 'pending', ?, ?)
        `).run(
          fixture.decisionId,
          fixture.missionId,
          fixture.runId,
          fixture.stepId,
          fingerprintAction(intent).hash,
          JSON.stringify(intent),
          "Keep the exact represented Guided boundary while the operator decides.",
          expiresAt,
          nowIso,
        );
      }
      if (fixture.actionId) {
        const status = state === "cancel" ? "queued" : "timed_out";
        connection.prepare(`
          INSERT INTO actions (
            id, mission_id, run_id, step_id, assignment_id, action_type,
            action_class, fingerprint, normalized_arguments_json, scoped_target,
            status, intent_summary, result_summary, error_category, guided_decision_id,
            started_at, ended_at, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, 'scan', 'passive_intelligence_osint', ?, ?, ?, ?,
            'Collect one bounded observation', ?, ?, ?, ?, ?, ?, ?)
        `).run(
          fixture.actionId,
          fixture.missionId,
          fixture.runId,
          fixture.stepId,
          fixture.assignmentId,
          digest(`${fixture.actionId}:fingerprint`),
          JSON.stringify({ target: fixture.target, mode: "bounded" }),
          fixture.target,
          status,
          status === "queued" ? null : "Timed out without producing evidence",
          status === "queued" ? null : "timeout",
          fixture.decisionId ?? null,
          status === "queued" ? null : nowIso,
          status === "queued" ? null : nowIso,
          nowIso,
          nowIso,
        );
        if (state === "cancel") {
          connection.prepare(`
            INSERT INTO tool_calls (
              id, action_id, provider, tool_name, normalized_arguments_json,
              status, created_at
            ) VALUES (?, ?, 'local-fixture', 'bounded-observation', '{}', 'queued', ?)
          `).run(`tool-call-control-e2e-${suffix}`, fixture.actionId, nowIso);
          connection.prepare(`
            INSERT INTO approvals (
              id, mission_id, run_id, approval_type, status, requested_by,
              reason, request_json, created_at
            ) VALUES (?, ?, ?, 'administrative', 'pending', 'run-supervisor',
              'Adversarial durable-residue cleanup fixture; not a valid Guided lifecycle', '{}', ?)
          `).run(`approval-control-e2e-${suffix}`, fixture.missionId, fixture.runId, nowIso);
          connection.prepare(`
            INSERT INTO provider_turns (
              id, run_id, provider, model, status, started_at
            ) VALUES (?, ?, 'local-fixture', 'bounded-provider-turn', 'started', ?)
          `).run(`provider-turn-control-e2e-${suffix}`, fixture.runId, nowIso);
          connection.prepare(`
            INSERT INTO runtime_continuations (
              id, run_id, kind, source_id, payload_json, status, attempt_count,
              available_at, lease_owner, lease_expires_at, created_at, updated_at
            ) VALUES (?, ?, 'action_result_to_advance', ?, '{}', 'processing', 1,
              ?, 'fixture-continuation-worker', ?, ?, ?)
          `).run(
            `continuation-control-e2e-${suffix}`,
            fixture.runId,
            `open-child-${fixture.actionId}`,
            nowIso,
            expiresAt,
            nowIso,
            nowIso,
          );
        }
      }
      if (!active) {
        const stateJson = checkpointState({ fixture, status: runStatus, reason, version: 1 });
        connection.prepare(`
          INSERT INTO checkpoints (
            id, mission_id, run_id, journey, event_sequence, plan_version,
            state_json, state_hash, in_flight_classification, created_at
          ) VALUES (?, ?, ?, 'guided', 0, 1, ?, ?, 'safe_no_in_flight_action', ?)
        `).run(
          `checkpoint-control-e2e-${suffix}`,
          fixture.missionId,
          fixture.runId,
          JSON.stringify(stateJson),
          hashJson(stateJson),
          nowIso,
        );
      }
    });
    if (state === "replan" || state === "reassign") {
      acquireTestRunMutationAuthority(connection, fixture.runId);
    }
  } finally {
    connection.close();
  }
  return fixture;
}

export function refreshRunInterventionRecoveryAttestations(fixture: RunInterventionRecoveryFixture): void {
  const connection = database();
  const now = new Date();
  const nowIso = now.toISOString();
  const validUntil = new Date(now.getTime() + 30 * 60_000).toISOString();
  try {
    connection.prepare(`
      UPDATE agents SET status = 'available', last_heartbeat_at = ?, updated_at = ?
      WHERE id IN (?, ?)
    `).run(nowIso, nowIso, fixture.agentId, fixture.candidateAgentId ?? fixture.agentId);
    if (fixture.candidateAgentId) {
      connection.prepare(`
        UPDATE agent_capabilities SET metadata_json = ?
        WHERE agent_id = ? AND capability = 'network.recon'
          AND source = 'live-route-attestation'
      `).run(JSON.stringify({ validUntil, attestedAt: nowIso }), fixture.candidateAgentId);
    }
  } finally {
    connection.close();
  }
}

export function advanceRunInterventionRecoveryVersion(fixture: RunInterventionRecoveryFixture): number {
  const connection = database();
  try {
    return inImmediateTransaction(connection, () => {
      const now = new Date().toISOString();
      const result = connection.prepare(`
        UPDATE runs SET version = version + 1, updated_at = ? WHERE id = ?
      `).run(now, fixture.runId);
      if (result.changes !== 1) throw new Error("The fixture run version was not advanced");
      const run = connection.prepare(`
        SELECT status, status_reason, version FROM runs WHERE id = ?
      `).get(fixture.runId) as { status: string; status_reason: string | null; version: number };
      const event = new EventRepository(connection).append({
        missionId: fixture.missionId,
        runId: fixture.runId,
        journey: "guided",
        eventType: "run.fixture_boundary_advanced",
        actorType: "system",
        actorId: "e2e-fixture",
        summary: "The disposable fixture advanced to a newer durable boundary",
        payload: { stateVersion: run.version, fixtureOnly: true },
      });
      // This helper intentionally creates a canonical state change behind an
      // already-rendered page. Mark only its delivery envelope complete so the
      // stale-control test, rather than the live refresh path, observes it.
      connection.prepare(`
        UPDATE event_outbox SET status = 'delivered', delivered_at = ?,
          claimed_by = NULL, claimed_at = NULL
        WHERE event_id = ? AND status = 'pending'
      `).run(now, event.id);
      const eventSequence = event.sequence;
      const planVersion = (connection.prepare(`
        SELECT version FROM plans WHERE id = (SELECT current_plan_id FROM runs WHERE id = ?)
      `).get(fixture.runId) as { version: number } | undefined)?.version ?? null;
      const stateJson = checkpointState({
        fixture,
        status: run.status,
        reason: run.status_reason ?? `Run is ${run.status}`,
        version: run.version,
        eventSequence,
      });
      connection.prepare(`
        INSERT INTO checkpoints (
          id, mission_id, run_id, journey, event_sequence, plan_version,
          state_json, state_hash, in_flight_classification, created_at
        ) VALUES (?, ?, ?, 'guided', ?, ?, ?, ?, 'safe_no_in_flight_action', ?)
      `).run(
        `checkpoint-control-e2e-${fixture.state}-${run.version}-${digest(now).slice(0, 12)}`,
        fixture.missionId,
        fixture.runId,
        eventSequence,
        planVersion,
        JSON.stringify(stateJson),
        hashJson(stateJson),
        now,
      );
      return run.version;
    });
  } finally {
    connection.close();
  }
}

export function readRunInterventionRecoverySnapshot(
  fixture: RunInterventionRecoveryFixture,
): RunInterventionRecoverySnapshot {
  const connection = database();
  try {
    const run = connection.prepare(`
      SELECT status, version, control_plane, lease_owner, lease_expires_at, status_reason
      FROM runs WHERE id = ?
    `).get(fixture.runId) as {
      status: string;
      version: number;
      control_plane: string;
      lease_owner: string | null;
      lease_expires_at: string | null;
      status_reason: string | null;
    };
    const checkpoints = (connection.prepare(`
      SELECT id, event_sequence, plan_version, state_json, state_hash
      FROM checkpoints WHERE run_id = ? ORDER BY event_sequence, created_at, id
    `).all(fixture.runId) as Array<{
      id: string;
      event_sequence: number;
      plan_version: number | null;
      state_json: string;
      state_hash: string;
    }>).map((row) => {
      const state = JSON.parse(row.state_json) as { inFlightActions?: unknown[] };
      return {
        id: row.id,
        eventSequence: row.event_sequence,
        planVersion: row.plan_version,
        stateHash: row.state_hash,
        stateHashVerified: hashJson(state) === row.state_hash,
        inFlightCount: Array.isArray(state.inFlightActions) ? state.inFlightActions.length : 0,
      };
    });
    const activeChildCount = (connection.prepare(`
      SELECT
        (SELECT count(*) FROM assignments WHERE run_id = ? AND status IN ('queued', 'active', 'blocked')) +
        (SELECT count(*) FROM actions WHERE run_id = ? AND status IN ('queued', 'running')) +
        (SELECT count(*) FROM tool_calls WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
          AND status IN ('queued', 'running')) +
        (SELECT count(*) FROM guided_decisions WHERE run_id = ? AND status = 'pending') +
        (SELECT count(*) FROM approvals WHERE run_id = ? AND status = 'pending') +
        (SELECT count(*) FROM provider_turns WHERE run_id = ? AND status = 'started') +
        (SELECT count(*) FROM runtime_continuations WHERE run_id = ? AND status IN ('pending', 'processing')) +
        (SELECT count(*) FROM runs WHERE id = ? AND lease_owner IS NOT NULL
          AND lease_expires_at IS NOT NULL AND lease_expires_at > ?) +
        (SELECT count(*) FROM control_plane_leases WHERE run_id = ? AND released_at IS NULL
          AND expires_at > ?) AS count
    `).get(
      fixture.runId,
      fixture.runId,
      fixture.runId,
      fixture.runId,
      fixture.runId,
      fixture.runId,
      fixture.runId,
      fixture.runId,
      new Date().toISOString(),
      fixture.runId,
      new Date().toISOString(),
    ) as { count: number }).count;
    const executingChildCount = (connection.prepare(`
      SELECT
        (SELECT count(*) FROM assignments WHERE run_id = ? AND status = 'active') +
        (SELECT count(*) FROM actions WHERE run_id = ? AND status IN ('queued', 'running')) +
        (SELECT count(*) FROM tool_calls WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
          AND status IN ('queued', 'running')) +
        (SELECT count(*) FROM provider_turns WHERE run_id = ? AND status = 'started') +
        (SELECT count(*) FROM runtime_continuations WHERE run_id = ? AND status IN ('pending', 'processing')) +
        (SELECT count(*) FROM runs WHERE id = ? AND lease_owner IS NOT NULL
          AND lease_expires_at IS NOT NULL AND lease_expires_at > ?) AS count
    `).get(
      fixture.runId,
      fixture.runId,
      fixture.runId,
      fixture.runId,
      fixture.runId,
      fixture.runId,
      new Date().toISOString(),
    ) as { count: number }).count;
    const durableRunLeaseActive = (connection.prepare(`
      SELECT count(*) AS count FROM runs WHERE id = ? AND lease_owner IS NOT NULL
        AND lease_expires_at IS NOT NULL AND lease_expires_at > ?
    `).get(fixture.runId, new Date().toISOString()) as { count: number }).count > 0;
    const activeControlPlaneLeaseCount = (connection.prepare(`
      SELECT count(*) AS count FROM control_plane_leases
      WHERE run_id = ? AND released_at IS NULL AND expires_at > ?
    `).get(fixture.runId, new Date().toISOString()) as { count: number }).count;
    return {
      run: {
        status: run.status,
        version: run.version,
        controlPlane: run.control_plane,
        leaseOwner: run.lease_owner,
        leaseExpiresAt: run.lease_expires_at,
        statusReason: run.status_reason,
      },
      missionStatus: (connection.prepare("SELECT status FROM missions WHERE id = ?").get(fixture.missionId) as { status: string }).status,
      planStatuses: (connection.prepare("SELECT status FROM plans WHERE run_id = ? ORDER BY version").all(fixture.runId) as Array<{ status: string }>).map((row) => row.status),
      stepStatuses: (connection.prepare("SELECT status FROM plan_steps WHERE run_id = ? ORDER BY ordinal").all(fixture.runId) as Array<{ status: string }>).map((row) => row.status),
      assignments: (connection.prepare(`
        SELECT id, agent_id, status, lease_owner FROM assignments
        WHERE run_id = ? ORDER BY created_at, id
      `).all(fixture.runId) as Array<{ id: string; agent_id: string; status: string; lease_owner: string | null }>).map((row) => ({
        id: row.id, agentId: row.agent_id, status: row.status, leaseOwner: row.lease_owner,
      })),
      actionStatuses: (connection.prepare("SELECT status FROM actions WHERE run_id = ? ORDER BY created_at, id").all(fixture.runId) as Array<{ status: string }>).map((row) => row.status),
      toolCallStatuses: (connection.prepare(`
        SELECT tc.status FROM tool_calls tc JOIN actions a ON a.id = tc.action_id
        WHERE a.run_id = ? ORDER BY tc.created_at, tc.id
      `).all(fixture.runId) as Array<{ status: string }>).map((row) => row.status),
      decisionStatuses: (connection.prepare("SELECT status FROM guided_decisions WHERE run_id = ? ORDER BY created_at, id").all(fixture.runId) as Array<{ status: string }>).map((row) => row.status),
      approvalStatuses: (connection.prepare("SELECT status FROM approvals WHERE run_id = ? ORDER BY created_at, id").all(fixture.runId) as Array<{ status: string }>).map((row) => row.status),
      providerTurnStatuses: (connection.prepare("SELECT status FROM provider_turns WHERE run_id = ? ORDER BY started_at, id").all(fixture.runId) as Array<{ status: string }>).map((row) => row.status),
      runtimeContinuationStatuses: (connection.prepare("SELECT status FROM runtime_continuations WHERE run_id = ? ORDER BY created_at, id").all(fixture.runId) as Array<{ status: string }>).map((row) => row.status),
      durableRunLeaseActive,
      activeControlPlaneLeaseCount,
      executingChildCount,
      activeChildCount,
      events: (connection.prepare(`
        SELECT event_type, sequence, summary FROM events WHERE run_id = ? ORDER BY sequence
      `).all(fixture.runId) as Array<{ event_type: string; sequence: number; summary: string }>).map((row) => ({
        type: row.event_type, sequence: row.sequence, summary: row.summary,
      })),
      audits: (connection.prepare(`
        SELECT action, reason FROM audit_records WHERE run_id = ? ORDER BY occurred_at, rowid
      `).all(fixture.runId) as Array<{ action: string; reason: string | null }>),
      checkpoints,
      eventOutboxCount: (connection.prepare(`
        SELECT count(*) AS count FROM event_outbox
        WHERE event_id IN (SELECT id FROM events WHERE run_id = ?)
      `).get(fixture.runId) as { count: number }).count,
      runtimeIdempotencyCount: (connection.prepare(`
        SELECT count(*) AS count FROM settings WHERE key LIKE 'idempotency.runtime.run.%'
          AND instr(value_json, ?) > 0
      `).get(fixture.runId) as { count: number }).count,
      recoveryIdempotencyCount: (connection.prepare(`
        SELECT count(*) AS count FROM settings WHERE key LIKE 'ti_scale.recovery.idempotency.%'
          AND instr(value_json, ?) > 0
      `).get(fixture.runId) as { count: number }).count,
    };
  } finally {
    connection.close();
  }
}

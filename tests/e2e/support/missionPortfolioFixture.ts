import { createHash } from "node:crypto";
import { acquireTestRunMutationAuthority } from "../../../server/control-plane/TestRunMutationAuthority";
import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import type { Journey, RunStatus } from "../../../server/missions";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_DATE = "2099-07-16";
const FIXTURE_BASE_TIME = Date.parse(`${FIXTURE_DATE}T23:59:59.000Z`);
const PORTFOLIO_PAGE_SIZE = 50;

type FixtureRunStatus = Extract<RunStatus, "running" | "recovering" | "completed">;

interface InsertMissionInput {
  readonly id: string;
  readonly title: string;
  readonly objective: string;
  readonly journey: Journey;
  readonly missionStatus: "active" | "completed";
  readonly runStatus: FixtureRunStatus;
  readonly engagementId: string;
  readonly target: string;
  readonly updatedAt: string;
  readonly agentId?: string;
  readonly provider?: string;
  readonly risk?: "low" | "medium" | "high" | "critical";
  readonly evidence?: boolean;
  readonly findingSeverity?: "informational" | "low" | "medium" | "high" | "critical";
  readonly pendingDecision?: boolean;
  readonly representedPlan?: boolean;
}

export interface MissionPortfolioFixture {
  readonly namespace: string;
  readonly sharedQuery: string;
  readonly primaryQuery: string;
  readonly fixtureDate: string;
  readonly engagementId: string;
  readonly target: string;
  readonly agentId: string;
  readonly provider: string;
  readonly primaryMissionId: string;
  readonly primaryRunId: string;
  readonly primaryTitle: string;
  readonly autonomousMissionId: string;
  readonly autonomousRunId: string;
  readonly autonomousTitle: string;
  readonly terminalMissionId: string;
  readonly terminalRunId: string;
  readonly terminalTitle: string;
  readonly totalMissionCount: number;
}

export interface MissionPortfolioFixtureState {
  readonly visibleFixtureMissions: number;
  readonly terminalMissionStatus: string;
  readonly terminalRunStatus: string;
  readonly terminalArchiveAuditCount: number;
  readonly terminalExportAuditCount: number;
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Mission-portfolio E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function fixtureTime(index: number): string {
  return new Date(FIXTURE_BASE_TIME - index * 1_000).toISOString();
}

function representedAction(target: string): string {
  return JSON.stringify({
    action: {
      actionType: "inspect_authorized_target",
      actionClass: "passive_intelligence_osint",
      target,
      arguments: { readOnly: true },
      intentSummary: "Inspect the represented authorized fixture without changing it.",
      kind: "tool",
      idempotent: true,
      destructive: false,
    },
    explanation: "Inspect one exact authorized fixture target and retain attributable observations.",
    rationale: "The bounded read-only step establishes canonical portfolio and deep-link state.",
    reversibility: "Read-only and reversible by ending the local fixture session.",
    dependencies: [],
  });
}

function insertMission(
  database: ReturnType<typeof createDatabaseConnection>,
  input: InsertMissionInput,
): { readonly runId: string } {
  const runId = `run-${input.id}`;
  const planId = `plan-${input.id}`;
  const stepId = `step-${input.id}`;
  const createdAt = new Date(Date.parse(input.updatedAt) - 60_000).toISOString();
  const terminal = input.runStatus === "completed";
  const progress = terminal ? 1 : input.runStatus === "recovering" ? 0.45 : 0.3;

  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
      created_by, version, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'verified', ?, ?, '["Fixture result remains attributable"]',
      '{}', '{}', 'e2e-local-operator', 1, ?, ?)
  `).run(
    input.id,
    input.title,
    input.objective,
    input.journey,
    input.missionStatus,
    input.engagementId,
    JSON.stringify({ target: input.target }),
    createdAt,
    input.updatedAt,
  );
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, metadata_json, created_at
    ) VALUES (?, ?, ?, 'domain', 'allowed', ?, '{}', ?)
  `).run(`target-${input.id}`, input.id, input.target, input.target.toLocaleLowerCase("en-US"), createdAt);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, current_plan_id, current_step_id, current_owner_id,
      progress, status_reason, next_action_summary, budget_json, budget_usage_json,
      last_heartbeat_at, started_at, ended_at, created_at, updated_at, version
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
  `).run(
    runId,
    input.id,
    input.journey,
    input.runStatus,
    input.representedPlan ? planId : null,
    input.representedPlan ? stepId : null,
    input.agentId ?? null,
    progress,
    input.runStatus === "recovering"
      ? "A bounded fixture dependency requires an explained recovery path."
      : terminal
        ? "The disposable fixture mission completed cleanly."
        : "The represented fixture mission is executing inside scope.",
    input.runStatus === "recovering"
      ? "Inspect bounded recovery evidence"
      : terminal
        ? "Review the completed fixture result"
        : "Continue the represented read-only step",
    JSON.stringify({ providerTokens: 10_000, toolCalls: 20, wallClockMs: 3_600_000 }),
    JSON.stringify({ providerTokens: 750, toolCalls: 4, wallClockMs: 120_000 }),
    terminal ? null : input.updatedAt,
    createdAt,
    terminal ? input.updatedAt : null,
    createdAt,
    input.updatedAt,
  );

  if (input.representedPlan) {
    database.prepare(`
      INSERT INTO plans (
        id, run_id, version, status, strategy_summary, rationale_summary,
        plan_hash, created_by, created_at, activated_at
      ) VALUES (?, ?, 1, ?, 'Bounded fixture strategy', 'Canonical browser traversal', ?,
        'e2e-fixture', ?, ?)
    `).run(planId, runId, terminal ? "completed" : "active", digest(planId), createdAt, createdAt);
    database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        success_criteria_json, dependencies_json, action_class, risk_class,
        assigned_agent_id, started_at, ended_at, created_at, updated_at
      ) VALUES (?, ?, ?, 0, 'reconnaissance', 'Inspect represented fixture target',
        'Collect bounded attributable state', ?, '["Attributable state is visible"]', '[]',
        'passive_intelligence_osint', ?, ?, ?, ?, ?, ?)
    `).run(
      stepId,
      planId,
      runId,
      input.runStatus,
      input.risk ?? "low",
      input.agentId ?? null,
      createdAt,
      terminal ? input.updatedAt : null,
      createdAt,
      input.updatedAt,
    );
    database.prepare(`
      INSERT INTO mission_constraints (
        id, mission_id, constraint_type, value_json, source, created_at
      ) VALUES (?, ?, 'represented_action', ?, ?, ?)
    `).run(`representation-${input.id}`, input.id, representedAction(input.target), stepId, createdAt);
  }

  if (input.agentId && input.representedPlan) {
    database.prepare(`
      INSERT INTO assignments (
        id, run_id, step_id, agent_id, status, started_at, ended_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      `assignment-${input.id}`,
      runId,
      stepId,
      input.agentId,
      terminal ? "completed" : input.runStatus === "recovering" ? "blocked" : "active",
      createdAt,
      terminal ? input.updatedAt : null,
      createdAt,
      input.updatedAt,
    );
  }
  if (input.provider) {
    database.prepare(`
      INSERT INTO provider_turns (
        id, run_id, provider, model, status, input_tokens, output_tokens,
        latency_ms, started_at, ended_at
      ) VALUES (?, ?, ?, 'fixture-executor', 'completed', 100, 50, 120, ?, ?)
    `).run(`provider-${input.id}`, runId, input.provider, createdAt, input.updatedAt);
  }
  if (input.pendingDecision && input.representedPlan) {
    database.prepare(`
      INSERT INTO guided_decisions (
        id, mission_id, run_id, step_id, requested_action_fingerprint,
        requested_parameters_json, rationale, risk_class, reversibility,
        status, expires_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'Choose the represented bounded recovery action.', 'high',
        'Read-only and reversible', 'pending', '2100-01-01T00:00:00.000Z', ?)
    `).run(
      `decision-${input.id}`,
      input.id,
      runId,
      stepId,
      digest(`decision-${input.id}`),
      representedAction(input.target),
      input.updatedAt,
    );
  }
  if (input.evidence && input.representedPlan) {
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, step_id, source, acquired_at, target, evidence_type,
        content_hash, provenance_json, confidence, sensitivity, verification_state,
        summary, extracted_text, created_by, created_at
      ) VALUES (?, ?, ?, ?, 'e2e-fixture', ?, ?, 'port_service_scan_result', ?, ?, 0.99,
        'internal', 'verified', 'Verified bounded portfolio fixture evidence',
        'Sanitized deterministic fixture observation', 'e2e-fixture', ?)
    `).run(
      `evidence-${input.id}`,
      input.id,
      runId,
      stepId,
      input.updatedAt,
      input.target,
      digest(`evidence-${input.id}`),
      JSON.stringify({ method: "isolated_fixture", sources: [{ kind: "fixture", id: input.id }] }),
      input.updatedAt,
    );
  }
  if (input.findingSeverity) {
    database.prepare(`
      INSERT INTO findings (
        id, mission_id, run_id, title, severity, confidence, affected_scope,
        description, impact, remediation, review_status, created_at, updated_at
      ) VALUES (?, ?, ?, 'Canonical fixture finding', ?, 0.99, ?,
        'A deterministic browser fixture finding.', 'Fixture-only impact.',
        'Retain the isolated fixture boundary.', 'verified', ?, ?)
    `).run(
      `finding-${input.id}`,
      input.id,
      runId,
      input.findingSeverity,
      input.target,
      input.updatedAt,
      input.updatedAt,
    );
  }

  database.prepare("INSERT INTO run_event_sequences (run_id, last_sequence) VALUES (?, 1)")
    .run(runId);
  database.prepare(`
    INSERT INTO events (
      id, mission_id, run_id, sequence, event_type, occurred_at, actor_type,
      actor_id, summary, payload_json, schema_version, journey, sensitivity,
      redaction_json, created_at
    ) VALUES (?, ?, ?, 1, ?, ?, 'system', 'e2e-fixture', ?, '{}', 1, ?, 'internal', '{}', ?)
  `).run(
    `event-${input.id}`,
    input.id,
    runId,
    terminal ? "run.completed" : input.runStatus === "recovering" ? "run.recovery_started" : "run.execution_progressed",
    input.updatedAt,
    terminal
      ? "Disposable fixture mission completed with attributable state"
      : input.runStatus === "recovering"
        ? "Recovery started after a bounded fixture dependency"
        : "Represented fixture execution made meaningful progress",
    input.journey,
    input.updatedAt,
  );
  return { runId };
}

export function createMissionPortfolioFixture(instanceId: string): MissionPortfolioFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const sharedQuery = `portfolioset-${namespace}`;
  const primaryQuery = `recovery-filter-${namespace}`;
  const engagementId = `engagement-${namespace}`;
  const target = `recover-${namespace}.example.test`;
  const agentId = `agent-${namespace}`;
  const provider = `provider-${namespace}`;
  const primaryMissionId = `mission-portfolio-primary-${namespace}`;
  const autonomousMissionId = `mission-portfolio-autonomous-${namespace}`;
  const terminalMissionId = `mission-portfolio-terminal-${namespace}`;
  const primaryTitle = `Guided recovery ${namespace}`;
  const autonomousTitle = `Autonomous active ${namespace}`;
  const terminalTitle = `Disposable terminal ${namespace}`;
  const totalMissionCount = PORTFOLIO_PAGE_SIZE + 1;
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    let primaryRunId = "";
    let autonomousRunId = "";
    let terminalRunId = "";
    inImmediateTransaction(database, () => {
      database.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, provider_policy_json, tool_policy_json,
          configuration_json, version, last_heartbeat_at, created_at, updated_at
        ) VALUES (?, 'recon', ?, 'busy', '{}', '{}', '{}', '2.4', ?, ?, ?)
      `).run(
        agentId,
        `Portfolio Recon ${namespace}`,
        fixtureTime(0),
        fixtureTime(60),
        fixtureTime(0),
      );

      primaryRunId = insertMission(database, {
        id: primaryMissionId,
        title: primaryTitle,
        objective: `${sharedQuery} ${primaryQuery} exercises every canonical portfolio filter.`,
        journey: "guided",
        missionStatus: "active",
        runStatus: "recovering",
        engagementId,
        target,
        updatedAt: fixtureTime(0),
        agentId,
        provider,
        risk: "high",
        evidence: true,
        findingSeverity: "critical",
        pendingDecision: true,
        representedPlan: true,
      }).runId;
      autonomousRunId = insertMission(database, {
        id: autonomousMissionId,
        title: autonomousTitle,
        objective: `${sharedQuery} keeps an Autonomous deep link available for browser refresh.`,
        journey: "autonomous",
        missionStatus: "active",
        runStatus: "running",
        engagementId: `autonomous-${engagementId}`,
        target: `autonomous-${namespace}.example.test`,
        updatedAt: fixtureTime(1),
        agentId,
        provider,
        risk: "low",
        representedPlan: true,
      }).runId;
      terminalRunId = insertMission(database, {
        id: terminalMissionId,
        title: terminalTitle,
        objective: `${sharedQuery} is the only disposable terminal mission selected for administrative mutation.`,
        journey: "autonomous",
        missionStatus: "completed",
        runStatus: "completed",
        engagementId: `terminal-${engagementId}`,
        target: `terminal-${namespace}.example.test`,
        updatedAt: fixtureTime(2),
        risk: "low",
      }).runId;
      // Bulk archive is a real mission mutation and therefore remains fenced
      // by the same trusted, server-side control-plane authority as production.
      // Publish the disposable terminal run and its E2E runtime lease in the
      // same transaction so no browser request can observe an unfenced fixture;
      // the raw lease token is never exposed to the page or HTTP boundary.
      acquireTestRunMutationAuthority(database, terminalRunId);

      for (let index = 0; index < PORTFOLIO_PAGE_SIZE - 2; index += 1) {
        insertMission(database, {
          id: `mission-portfolio-filler-${String(index).padStart(2, "0")}-${namespace}`,
          title: `Completed portfolio fixture ${String(index + 1).padStart(2, "0")} ${namespace}`,
          objective: `${sharedQuery} provides deterministic cursor pagination.`,
          journey: index % 2 === 0 ? "guided" : "autonomous",
          missionStatus: "completed",
          runStatus: "completed",
          engagementId: `filler-${index}-${engagementId}`,
          target: `filler-${index}-${namespace}.example.test`,
          updatedAt: fixtureTime(index + 3),
        });
      }
    });
    return {
      namespace,
      sharedQuery,
      primaryQuery,
      fixtureDate: FIXTURE_DATE,
      engagementId,
      target,
      agentId,
      provider,
      primaryMissionId,
      primaryRunId,
      primaryTitle,
      autonomousMissionId,
      autonomousRunId,
      autonomousTitle,
      terminalMissionId,
      terminalRunId,
      terminalTitle,
      totalMissionCount,
    };
  } finally {
    database.close();
  }
}

export function readMissionPortfolioFixtureState(
  fixture: MissionPortfolioFixture,
): MissionPortfolioFixtureState {
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const visible = database.prepare(`
      SELECT COUNT(*) AS count FROM missions
      WHERE objective LIKE ? AND status != 'archived'
    `).get(`%${fixture.sharedQuery}%`) as { readonly count: number };
    const terminal = database.prepare(`
      SELECT m.status AS mission_status, r.status AS run_status
      FROM missions m JOIN runs r ON r.id = ? WHERE m.id = ?
    `).get(fixture.terminalRunId, fixture.terminalMissionId) as {
      readonly mission_status: string;
      readonly run_status: string;
    } | undefined;
    if (!terminal) throw new Error("The disposable terminal portfolio fixture is missing");
    const auditCounts = database.prepare(`
      SELECT
        SUM(CASE WHEN action = 'mission.archived' AND resource_id = ? THEN 1 ELSE 0 END) AS archive_count,
        SUM(CASE WHEN action = 'mission.bulk_metadata_exported'
          AND instr(details_json, ?) > 0 THEN 1 ELSE 0 END) AS export_count
      FROM audit_records
    `).get(fixture.terminalMissionId, fixture.terminalMissionId) as {
      readonly archive_count: number | null;
      readonly export_count: number | null;
    };
    return {
      visibleFixtureMissions: Number(visible.count),
      terminalMissionStatus: terminal.mission_status,
      terminalRunStatus: terminal.run_status,
      terminalArchiveAuditCount: Number(auditCounts.archive_count ?? 0),
      terminalExportAuditCount: Number(auditCounts.export_count ?? 0),
    };
  } finally {
    database.close();
  }
}

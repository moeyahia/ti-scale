import type { SqliteDatabase } from "../db";
import {
  evaluateDestructiveAuthorization,
  isSpecialistMcpExecutionPolicy,
} from "../domain";
import {
  acquireLease,
  heartbeatLease,
  isRunState,
  runNextActionOverride,
  type AutonomousContractBoundary,
  type BudgetKey,
  type BudgetState,
  type BudgetValues,
  type GuidedDecision,
  type Journey,
  type SupervisedRun,
} from "../supervisor";
import {
  DurableOrchestrationError,
  type DurableAction,
  type DurableActionIntent,
  type DurableControlState,
  type DurableRun,
  type RunLeaseToken,
} from "./types";
import { canonicalJson, parseObject } from "./serialization";

interface RunRow {
  readonly id: string;
  readonly mission_id: string;
  readonly journey: Journey;
  readonly status: string;
  readonly contract_id: string | null;
  readonly contract_version_bound: number | null;
  readonly contract_hash_bound: string | null;
  readonly contract_current_version: number | null;
  readonly contract_confirmed_at: string | null;
  readonly budget_json: string;
  readonly budget_usage_json: string;
  readonly retry_count: number;
  readonly replan_count: number;
  readonly lease_owner: string | null;
  readonly lease_acquired_at: string | null;
  readonly last_heartbeat_at: string | null;
  readonly lease_expires_at: string | null;
  readonly started_at: string | null;
  readonly ended_at: string | null;
  readonly status_reason: string | null;
  readonly created_at: string;
  readonly updated_at: string;
  readonly version: number;
}

interface ContractRow {
  readonly id: string;
  readonly version: number;
  readonly state: "draft" | "confirmed" | "superseded" | "revoked";
  readonly contract_hash: string;
  readonly action_policy_json: string;
}

interface TargetRow {
  readonly target: string;
}

interface GuidedDecisionRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly step_id: string;
  readonly requested_action_fingerprint: string;
  readonly status: string;
  readonly decided_at: string | null;
  readonly expires_at: string;
  readonly consumed_count: number;
}

interface ActionAssignmentRow {
  readonly assignment_id: string | null;
  readonly assignment_run_id: string | null;
  readonly assignment_step_id: string | null;
  readonly assignment_status: string | null;
  readonly agent_id: string | null;
  readonly agent_status: string | null;
  readonly step_run_id: string | null;
  readonly step_status: string | null;
  readonly step_agent_id: string | null;
  readonly plan_id: string | null;
  readonly plan_run_id: string | null;
  readonly plan_status: string | null;
  readonly current_plan_id: string | null;
  readonly current_step_id: string | null;
}

interface IntentAssignmentRow {
  readonly assignment_id: string;
  readonly assignment_run_id: string;
  readonly assignment_step_id: string | null;
  readonly assignment_status: string;
  readonly agent_id: string;
  readonly agent_status: string;
  readonly step_run_id: string;
  readonly step_status: string;
  readonly step_agent_id: string | null;
  readonly plan_id: string;
  readonly plan_run_id: string;
  readonly plan_version: number;
  readonly plan_status: string;
  readonly current_plan_id: string | null;
  readonly current_step_id: string | null;
}

export type AutonomousIntentBoundaryResult =
  | { readonly allowed: true; readonly agentId: string }
  | { readonly allowed: false; readonly code: string; readonly humanMessage: string };

export type CurrentActionBoundaryResult =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly code: string; readonly humanMessage: string };

export const REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION =
  "ti-scale.reviewed-local-tool-action.v1" as const;

export interface ReviewedLocalToolActionEnvelope {
  readonly schemaVersion: typeof REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION;
  readonly executionBinding: "reviewed_local_process";
  readonly toolId: string;
  readonly parameters: Readonly<Record<string, unknown>>;
}

const PUBLIC_TOOL_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;

/**
 * Truthful local-process action envelope. It is intentionally distinct from
 * the MCP `{mcpServer, toolName, parameters}` shape so a direct executable is
 * never represented as an MCP invocation in events, readiness, or policy.
 */
export function reviewedLocalToolActionEnvelope(
  value: Readonly<Record<string, unknown>>,
): ReviewedLocalToolActionEnvelope | undefined {
  const keys = Object.keys(value).sort();
  const expected = ["executionBinding", "parameters", "schemaVersion", "toolId"].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    return undefined;
  }
  if (
    value.schemaVersion !== REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION
    || value.executionBinding !== "reviewed_local_process"
    || typeof value.toolId !== "string"
    || value.toolId !== value.toolId.trim()
    || !PUBLIC_TOOL_ID.test(value.toolId)
    || value.parameters === null
    || typeof value.parameters !== "object"
    || Array.isArray(value.parameters)
    || (Object.getPrototypeOf(value.parameters) !== Object.prototype
      && Object.getPrototypeOf(value.parameters) !== null)
  ) return undefined;
  return {
    schemaVersion: REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
    executionBinding: "reviewed_local_process",
    toolId: value.toolId,
    parameters: value.parameters as Readonly<Record<string, unknown>>,
  };
}

const BUDGET_KEYS: readonly BudgetKey[] = [
  "wallClockMs",
  "providerTokens",
  "estimatedCost",
  "toolCalls",
  "providerTurns",
  "retries",
  "replans",
  "concurrency",
  "evidenceBytes",
  "artifactBytes",
];

function isoMs(value: string | null): number {
  const parsed = value ? Date.parse(value) : Number.NaN;
  return Number.isFinite(parsed) ? parsed : 0;
}

function budgetValues(value: string, limits: boolean): BudgetValues {
  const source = parseObject(value);
  const result: Partial<Record<BudgetKey, number>> = {};
  for (const key of BUDGET_KEYS) {
    const candidate = source[key];
    if (typeof candidate === "number" && Number.isFinite(candidate) && candidate >= 0) {
      result[key] = candidate;
    }
  }
  if (limits) {
    if (typeof source.timeBudgetMinutes === "number" && source.timeBudgetMinutes >= 0) {
      result.wallClockMs = source.timeBudgetMinutes * 60_000;
    }
    if (typeof source.tokenBudget === "number" && source.tokenBudget >= 0) {
      result.providerTokens = source.tokenBudget;
    }
    if (typeof source.costBudget === "number" && source.costBudget >= 0) {
      result.estimatedCost = source.costBudget;
    }
    if (typeof source.retryBudget === "number" && source.retryBudget >= 0) {
      result.retries = source.retryBudget;
    }
    if (typeof source.replanBudget === "number" && source.replanBudget >= 0) {
      result.replans = source.replanBudget;
    }
    if (typeof source.concurrencyLimit === "number" && source.concurrencyLimit >= 0) {
      result.concurrency = source.concurrencyLimit;
    }
  }
  return result;
}

function mapRow(row: RunRow): DurableRun {
  if (!isRunState(row.status)) {
    throw new DurableOrchestrationError("invalid_run_state", `Run ${row.id} has invalid state ${row.status}`);
  }
  const lease = row.lease_owner && row.lease_expires_at
    ? {
        runId: row.id,
        ownerId: row.lease_owner,
        fence: row.version,
        expiresAt: row.lease_expires_at,
      }
    : null;
  const run: SupervisedRun = {
    id: row.id,
    missionId: row.mission_id,
    journey: row.journey,
    state: row.status,
    launched: row.started_at !== null,
    ...(row.contract_version_bound === null ? {} : { contractVersion: row.contract_version_bound }),
    ...(row.contract_confirmed_at ? { contractConfirmedAt: row.contract_confirmed_at } : {}),
    stateVersion: row.version,
    stateReason: row.status_reason ?? `Run is ${row.status}`,
    createdAt: row.created_at,
    ...(row.started_at ? { startedAt: row.started_at } : {}),
    updatedAt: row.updated_at,
    ...(row.ended_at ? { endedAt: row.ended_at } : {}),
  };
  return {
    run,
    contractId: row.contract_id,
    lease,
    control: {
      budget: {
        limits: budgetValues(row.budget_json, true),
        usage: budgetValues(row.budget_usage_json, false),
      },
      retryCount: row.retry_count,
      replanCount: row.replan_count,
      circuits: {},
      progress: {},
    },
  };
}

const RUN_SELECT = `
  SELECT r.*,
    c.version AS contract_current_version,
    c.confirmed_at AS contract_confirmed_at
  FROM runs r
  LEFT JOIN mission_contracts c ON c.id = r.contract_id
`;

export class RunRepository {
  constructor(private readonly database: SqliteDatabase) {}

  get(runId: string): DurableRun {
    const row = this.database
      .prepare(`${RUN_SELECT} WHERE r.id = ?`)
      .get(runId) as RunRow | undefined;
    if (!row) throw new DurableOrchestrationError("run_not_found", `Run not found: ${runId}`);
    return mapRow(row);
  }

  listExpiredNonterminal(now: string): DurableRun[] {
    const rows = this.database
      .prepare(`${RUN_SELECT}
        WHERE r.status NOT IN ('completed', 'failed', 'cancelled')
          AND r.lease_expires_at IS NOT NULL
          AND r.lease_expires_at <= ?
        ORDER BY r.lease_expires_at ASC, r.id ASC
      `)
      .all(now) as RunRow[];
    return rows.map(mapRow);
  }

  assertLease(run: DurableRun, token: RunLeaseToken, now: string): void {
    if (
      token.runId !== run.run.id ||
      !run.lease ||
      run.lease.ownerId !== token.ownerId ||
      run.lease.fence !== token.fence ||
      run.lease.expiresAt !== token.expiresAt
    ) {
      throw new DurableOrchestrationError("stale_lease", "Run lease owner or fencing token is stale");
    }
    if (Date.parse(run.lease.expiresAt) <= Date.parse(now)) {
      throw new DurableOrchestrationError("expired_lease", "Run lease has expired");
    }
  }

  acquire(runId: string, ownerId: string, now: string, ttlMs: number): RunLeaseToken {
    const current = this.get(runId);
    const existing = current.lease
      ? {
          resourceType: "run" as const,
          resourceId: runId,
          ownerId: current.lease.ownerId,
          acquiredAt: isoMs(
            (this.database.prepare("SELECT lease_acquired_at AS value FROM runs WHERE id = ?").get(runId) as { value: string | null }).value,
          ),
          lastHeartbeatAt: isoMs(
            (this.database.prepare("SELECT last_heartbeat_at AS value FROM runs WHERE id = ?").get(runId) as { value: string | null }).value,
          ),
          expiresAt: isoMs(current.lease.expiresAt),
          version: current.lease.fence,
        }
      : undefined;
    const acquired = acquireLease({
      existing,
      resourceType: "run",
      resourceId: runId,
      ownerId,
      now: Date.parse(now),
      ttlMs,
    });
    const expiresAt = new Date(acquired.expiresAt).toISOString();
    const result = this.database
      .prepare(`
        UPDATE runs SET
          lease_owner = ?, lease_acquired_at = ?, last_heartbeat_at = ?,
          lease_expires_at = ?, version = version + 1, updated_at = ?
        WHERE id = ? AND version = ?
      `)
      .run(ownerId, now, now, expiresAt, now, runId, current.run.stateVersion);
    if (result.changes !== 1) throw new DurableOrchestrationError("lease_conflict", "Run changed while acquiring lease");
    return { runId, ownerId, fence: current.run.stateVersion + 1, expiresAt };
  }

  heartbeat(token: RunLeaseToken, now: string, ttlMs: number): RunLeaseToken {
    const current = this.get(token.runId);
    this.assertLease(current, token, now);
    const refreshed = heartbeatLease({
      lease: {
        resourceType: "run",
        resourceId: token.runId,
        ownerId: token.ownerId,
        acquiredAt: Date.parse(
          (this.database.prepare("SELECT lease_acquired_at AS value FROM runs WHERE id = ?").get(token.runId) as { value: string }).value,
        ),
        lastHeartbeatAt: Date.parse(current.run.updatedAt),
        expiresAt: Date.parse(token.expiresAt),
        version: token.fence,
      },
      ownerId: token.ownerId,
      expectedVersion: token.fence,
      now: Date.parse(now),
      ttlMs,
    });
    const expiresAt = new Date(refreshed.expiresAt).toISOString();
    const result = this.database
      .prepare(`
        UPDATE runs SET last_heartbeat_at = ?, lease_expires_at = ?,
          version = version + 1, updated_at = ?
        WHERE id = ? AND lease_owner = ? AND version = ?
      `)
      .run(now, expiresAt, now, token.runId, token.ownerId, token.fence);
    if (result.changes !== 1) throw new DurableOrchestrationError("stale_lease", "Heartbeat fencing token is stale");
    return { ...token, fence: token.fence + 1, expiresAt };
  }

  persistMutation(input: {
    current: DurableRun;
    nextRun: SupervisedRun;
    control: DurableControlState;
    now: string;
    lease: "keep" | "clear" | { ownerId: string; expiresAt: string; acquiredAt?: string };
  }): DurableRun {
    const expected = input.current.run.stateVersion;
    if (input.nextRun.stateVersion !== expected + 1) {
      throw new DurableOrchestrationError("invalid_fence_advance", "Every durable run mutation must advance the fence exactly once");
    }
    const retained = input.lease === "keep" ? input.current.lease : null;
    const replacement = typeof input.lease === "object" ? input.lease : null;
    const owner = replacement?.ownerId ?? retained?.ownerId ?? null;
    const acquiredAt = replacement?.acquiredAt ?? (owner ? input.now : null);
    const expiresAt = replacement?.expiresAt ?? retained?.expiresAt ?? null;
    const heartbeatAt = owner ? input.now : null;
    const startedAt = input.nextRun.launched ? input.nextRun.updatedAt : null;
    const terminal = ["completed", "failed", "cancelled"].includes(input.nextRun.state);
    const nextActionOverride = runNextActionOverride(
      input.nextRun.state,
      input.nextRun.journey,
    );
    const result = this.database
      .prepare(`
        UPDATE runs SET
          status = ?, status_reason = ?, budget_json = ?, budget_usage_json = ?,
          next_action_summary = CASE WHEN ? = 1 THEN ? ELSE next_action_summary END,
          retry_count = ?, replan_count = ?, lease_owner = ?,
          lease_acquired_at = CASE
            WHEN ? IS NULL THEN NULL
            WHEN ? = 1 THEN ?
            ELSE lease_acquired_at
          END,
          last_heartbeat_at = ?, lease_expires_at = ?,
          current_step_id = CASE WHEN ? = 1 THEN NULL ELSE current_step_id END,
          current_owner_id = CASE WHEN ? = 1 THEN NULL ELSE current_owner_id END,
          started_at = CASE WHEN ? IS NULL THEN started_at ELSE COALESCE(started_at, ?) END,
          ended_at = ?, updated_at = ?, version = ?
        WHERE id = ? AND version = ?
      `)
      .run(
        input.nextRun.state,
        input.nextRun.stateReason,
        canonicalJson(input.control.budget.limits),
        canonicalJson(input.control.budget.usage),
        nextActionOverride === undefined ? 0 : 1,
        nextActionOverride ?? null,
        input.control.retryCount,
        input.control.replanCount,
        owner,
        owner,
        replacement ? 1 : 0,
        acquiredAt,
        heartbeatAt,
        expiresAt,
        terminal ? 1 : 0,
        terminal ? 1 : 0,
        startedAt,
        startedAt,
        input.nextRun.endedAt ?? null,
        input.now,
        input.nextRun.stateVersion,
        input.current.run.id,
        expected,
      );
    if (result.changes !== 1) throw new DurableOrchestrationError("stale_lease", "Run mutation lost its fencing race");
    return {
      ...input.current,
      run: input.nextRun,
      lease: owner && expiresAt
        ? { runId: input.current.run.id, ownerId: owner, fence: input.nextRun.stateVersion, expiresAt }
        : null,
      control: input.control,
    };
  }

  autonomousContract(run: DurableRun): AutonomousContractBoundary | undefined {
    if (!run.contractId) return undefined;
    const contract = this.database
      .prepare("SELECT id, version, state, contract_hash, action_policy_json FROM mission_contracts WHERE id = ?")
      .get(run.contractId) as ContractRow | undefined;
    if (!contract) return undefined;
    const policy = parseObject(contract.action_policy_json);
    const allowed = Array.isArray(policy.allowedActionClasses)
      ? policy.allowedActionClasses.filter((value): value is string => typeof value === "string")
      : [];
    const prohibited = Array.isArray(policy.prohibitedActionClasses)
      ? policy.prohibitedActionClasses.filter((value): value is string => typeof value === "string")
      : [];
    const targets = this.database
      .prepare("SELECT target FROM mission_targets WHERE mission_id = ? AND disposition = 'allowed' ORDER BY id")
      .all(run.run.missionId) as TargetRow[];
    return {
      runId: run.run.id,
      version: contract.version,
      status: contract.state === "confirmed" ? "signed" : contract.state === "superseded" ? "superseded" : "draft",
      allowedActionTypes: allowed,
      prohibitedActionTypes: prohibited,
      allowedTargets: targets.map((row) => row.target),
    };
  }

  /**
   * Authorize an unpersisted Autonomous intent from current canonical state.
   * This is intentionally stronger than the journey-level fingerprint gate:
   * it is called inside startAction's IMMEDIATE transaction immediately before
   * the action, assignment, and step are mutated.
   */
  authorizeAutonomousIntent(
    run: DurableRun,
    intent: DurableActionIntent,
  ): AutonomousIntentBoundaryResult {
    const deny = (code: string, humanMessage: string): AutonomousIntentBoundaryResult => ({
      allowed: false,
      code,
      humanMessage,
    });
    if (
      run.run.journey !== "autonomous" ||
      intent.runId !== run.run.id ||
      intent.missionId !== run.run.missionId
    ) {
      return deny("autonomous_intent_scope_mismatch", "The action does not belong to this Autonomous run.");
    }
    const mission = this.database.prepare(`
      SELECT authorization_status FROM missions WHERE id = ?
    `).get(run.run.missionId) as { authorization_status: string } | undefined;
    if (mission?.authorization_status !== "verified") {
      return deny("autonomous_authorization_not_verified", "Mission authorization is no longer verified.");
    }
    if (!run.contractId) {
      return deny("autonomous_contract_not_current", "The run has no canonical Autonomous contract.");
    }
    const contract = this.database.prepare(`
      SELECT id, version, state, contract_hash, action_policy_json
      FROM mission_contracts WHERE id = ?
    `).get(run.contractId) as ContractRow | undefined;
    const binding = this.database.prepare(`
      SELECT contract_version_bound, contract_hash_bound
      FROM runs WHERE id = ?
    `).get(run.run.id) as {
      contract_version_bound: number | null;
      contract_hash_bound: string | null;
    } | undefined;
    if (
      !contract || contract.id !== run.contractId || contract.state !== "confirmed" ||
      !binding || binding.contract_version_bound === null || binding.contract_hash_bound === null ||
      contract.version !== binding.contract_version_bound ||
      contract.contract_hash !== binding.contract_hash_bound ||
      contract.version !== run.run.contractVersion
    ) {
      return deny("autonomous_contract_not_current", "The run contract is missing, superseded, revoked, or version-mismatched.");
    }
    const normalize = (value: string): string => value.trim().toLowerCase();
    const policy = parseObject(contract.action_policy_json);
    const allowed = new Set(
      (Array.isArray(policy.allowedActionClasses) ? policy.allowedActionClasses : [])
        .filter((value): value is string => typeof value === "string")
        .map(normalize)
        .filter(Boolean),
    );
    const prohibited = new Set(
      (Array.isArray(policy.prohibitedActionClasses) ? policy.prohibitedActionClasses : [])
        .filter((value): value is string => typeof value === "string")
        .map(normalize)
        .filter(Boolean),
    );
    const localEnvelope = intent.kind === "tool"
      ? reviewedLocalToolActionEnvelope(intent.arguments)
      : null;
    const actionType = normalize(intent.actionType);
    const actionClass = normalize(intent.actionClass);
    if (
      (!localEnvelope && !allowed.has(actionType)) ||
      !allowed.has(actionClass) ||
      (!localEnvelope && prohibited.has(actionType)) ||
      prohibited.has(actionClass)
    ) {
      return deny("autonomous_action_not_allowed", "The action class is outside the current signed contract.");
    }
    const destructivePolicy = typeof policy.destructivePolicy === "string"
      ? normalize(policy.destructivePolicy)
      : "";
    const boundedDestructiveTargets = new Set(
      (Array.isArray(policy.boundedDestructiveTargets) ? policy.boundedDestructiveTargets : [])
        .filter((value): value is string => typeof value === "string")
        .map((value) => value.trim())
        .filter(Boolean),
    );
    if (!evaluateDestructiveAuthorization({
      destructive: intent.destructive,
      policy: destructivePolicy,
      target: intent.target,
      boundedTargets: [...boundedDestructiveTargets],
    }).allowed) {
      return deny("autonomous_destructive_action_not_authorized", "The contract does not authorize destructive execution.");
    }
    const target = intent.target.trim();
    const targetAllowed = Boolean(this.database.prepare(`
      SELECT 1 AS present FROM mission_targets
      WHERE mission_id = ? AND disposition = 'allowed' AND target = ?
      LIMIT 1
    `).get(run.run.missionId, target));
    if (!targetAllowed) {
      return deny("autonomous_target_not_allowed", "The action target is outside the current authorized mission scope.");
    }
    if (!intent.assignmentId) {
      return deny("autonomous_assignment_not_authorized", "The action has no exact specialist assignment.");
    }
    const assignment = this.database.prepare(`
      SELECT ass.id AS assignment_id, ass.run_id AS assignment_run_id,
        ass.step_id AS assignment_step_id, ass.status AS assignment_status,
        ass.agent_id, ag.status AS agent_status,
        ps.run_id AS step_run_id, ps.status AS step_status,
        ps.assigned_agent_id AS step_agent_id,
        p.id AS plan_id, p.run_id AS plan_run_id, p.version AS plan_version,
        p.status AS plan_status, r.current_plan_id, r.current_step_id
      FROM assignments ass
      JOIN agents ag ON ag.id = ass.agent_id
      JOIN plan_steps ps ON ps.id = ass.step_id
      JOIN plans p ON p.id = ps.plan_id
      JOIN runs r ON r.id = ass.run_id
      WHERE ass.id = ?
    `).get(intent.assignmentId) as IntentAssignmentRow | undefined;
    if (
      !assignment || assignment.assignment_run_id !== intent.runId ||
      assignment.assignment_step_id !== intent.stepId ||
      assignment.step_run_id !== intent.runId || assignment.plan_run_id !== intent.runId ||
      assignment.plan_id !== assignment.current_plan_id ||
      assignment.assignment_step_id !== assignment.current_step_id ||
      assignment.plan_version !== intent.planVersion || assignment.plan_status !== "active" ||
      assignment.step_agent_id !== assignment.agent_id ||
      assignment.assignment_status !== "queued" ||
      assignment.step_status !== "ready" ||
      ["offline", "quarantined"].includes(assignment.agent_status)
    ) {
      return deny("autonomous_assignment_not_authorized", "The exact run, plan, step, and specialist assignment is no longer executable.");
    }
    const signedSpecialists = new Set(
      (Array.isArray(policy.specialistAgentIds) ? policy.specialistAgentIds : [])
        .filter((value): value is string => typeof value === "string")
        .map((value) => value.trim())
        .filter(Boolean),
    );
    if (!signedSpecialists.has(assignment.agent_id)) {
      return deny("autonomous_specialist_not_signed", "The assigned specialist is not in the current signed specialist pool.");
    }
    if (intent.kind === "tool") {
      if (localEnvelope) {
        if (!this.localToolAllowed(
          assignment.agent_id,
          localEnvelope.toolId,
          intent.actionClass,
        )) {
          return deny(
            "autonomous_tool_policy_denied",
            "The current specialist policy does not allow this exact reviewed local tool binding.",
          );
        }
        return { allowed: true, agentId: assignment.agent_id };
      }
      const mcpServer = intent.arguments.mcpServer;
      const toolName = intent.arguments.toolName;
      if (
        typeof mcpServer !== "string" || !mcpServer.trim() || mcpServer !== mcpServer.trim() ||
        typeof toolName !== "string" || !toolName.trim() || toolName !== toolName.trim()
      ) {
        return deny("autonomous_tool_binding_invalid", "The tool action lacks an exact MCP server and tool binding.");
      }
      if (!this.specialistToolAllowed(
        assignment.agent_id,
        mcpServer,
        toolName,
        intent.actionClass,
      )) {
        return deny("autonomous_tool_policy_denied", "The current specialist policy does not allow this exact MCP tool binding.");
      }
    }
    return { allowed: true, agentId: assignment.agent_id };
  }

  authorizeGuidedIntent(run: DurableRun, intent: DurableActionIntent): CurrentActionBoundaryResult {
    if (
      run.run.journey !== "guided" || intent.runId !== run.run.id ||
      intent.missionId !== run.run.missionId
    ) {
      return { allowed: false, code: "guided_intent_scope_mismatch", humanMessage: "The represented action does not belong to this Guided run." };
    }
    const scope = this.currentMissionScope(run.run.missionId, intent.target);
    if (!scope.allowed) return scope;
    if (!intent.assignmentId) {
      return { allowed: false, code: "guided_assignment_not_authorized", humanMessage: "The represented action has no exact specialist assignment." };
    }
    const assignment = this.database.prepare(`
      SELECT ass.id AS assignment_id, ass.run_id AS assignment_run_id,
        ass.step_id AS assignment_step_id, ass.status AS assignment_status,
        ass.agent_id, ag.status AS agent_status,
        ps.run_id AS step_run_id, ps.status AS step_status,
        ps.assigned_agent_id AS step_agent_id,
        p.id AS plan_id, p.run_id AS plan_run_id, p.version AS plan_version,
        p.status AS plan_status, r.current_plan_id, r.current_step_id
      FROM assignments ass
      JOIN agents ag ON ag.id = ass.agent_id
      JOIN plan_steps ps ON ps.id = ass.step_id
      JOIN plans p ON p.id = ps.plan_id
      JOIN runs r ON r.id = ass.run_id
      WHERE ass.id = ?
    `).get(intent.assignmentId) as IntentAssignmentRow | undefined;
    if (
      !assignment || assignment.assignment_run_id !== intent.runId ||
      assignment.assignment_step_id !== intent.stepId ||
      assignment.step_run_id !== intent.runId || assignment.plan_run_id !== intent.runId ||
      assignment.plan_id !== assignment.current_plan_id ||
      assignment.assignment_step_id !== assignment.current_step_id ||
      assignment.plan_version !== intent.planVersion || assignment.plan_status !== "active" ||
      assignment.step_agent_id !== assignment.agent_id ||
      assignment.assignment_status !== "queued" ||
      !["ready", "waiting_guided_decision"].includes(assignment.step_status) ||
      ["offline", "quarantined"].includes(assignment.agent_status)
    ) {
      return { allowed: false, code: "guided_assignment_not_authorized", humanMessage: "The exact current plan, step, and specialist assignment is no longer executable." };
    }
    return { allowed: true };
  }

  /** Side-effect-free final assertion for dispatch and crash resume. */
  authorizePersistedAction(run: DurableRun, action: DurableAction): CurrentActionBoundaryResult {
    if (!["running", "recovering"].includes(run.run.state)) {
      return { allowed: false, code: "action_run_not_executable", humanMessage: "The run is no longer in an executable state." };
    }
    const scope = this.currentMissionScope(run.run.missionId, action.target);
    if (!scope.allowed) return scope;
    const assignment = this.currentPersistedActionAssignment(action);
    if (!assignment) {
      return { allowed: false, code: "action_assignment_no_longer_authorized", humanMessage: "The current plan, step, specialist assignment, or agent health no longer authorizes dispatch." };
    }
    if (run.run.journey === "autonomous") {
      return this.autonomousActionRemainsInContract(run, action, assignment)
        ? { allowed: true }
        : {
            allowed: false,
            code: "autonomous_action_no_longer_authorized",
            humanMessage: "The reserved action no longer matches the exact current contract, assignment, or tool policy.",
          };
    }
    if (!action.guidedDecisionId) {
      return { allowed: false, code: "guided_decision_required", humanMessage: "The Guided action has no exact decision." };
    }
    const decision = this.database.prepare(`
      SELECT mission_id, run_id, step_id, requested_action_fingerprint, status
      FROM guided_decisions WHERE id = ?
    `).get(action.guidedDecisionId) as {
      mission_id: string;
      run_id: string;
      step_id: string;
      requested_action_fingerprint: string;
      status: string;
    } | undefined;
    if (
      !decision || decision.status !== "approved" ||
      decision.mission_id !== action.missionId || decision.run_id !== action.runId ||
      decision.step_id !== action.stepId || decision.requested_action_fingerprint !== action.fingerprint
    ) {
      return { allowed: false, code: "guided_decision_no_longer_authorized", humanMessage: "The reserved action no longer matches the approved exact Guided decision." };
    }
    return { allowed: true };
  }

  /**
   * Final specialist-tool assertion for the execution adapter immediately
   * before an MCP call. Guided exact-step authorization is necessary but not
   * sufficient: the current assigned specialist, MCP server, and tool policy
   * must still permit this exact binding.
   */
  authorizePersistedSpecialistTool(
    run: DurableRun,
    action: DurableAction,
    mcpServer: string,
    toolName: string,
  ): CurrentActionBoundaryResult {
    const base = this.authorizePersistedAction(run, action);
    if (!base.allowed) return base;
    if (action.kind !== "tool") {
      return {
        allowed: false,
        code: "action_not_specialist_tool",
        humanMessage: "The persisted action is not a specialist tool action.",
      };
    }
    const persistedServer = action.arguments.mcpServer;
    const persistedTool = action.arguments.toolName;
    if (
      typeof persistedServer !== "string" || persistedServer !== mcpServer || !persistedServer.trim() ||
      typeof persistedTool !== "string" || persistedTool !== toolName || !persistedTool.trim()
    ) {
      return {
        allowed: false,
        code: "action_tool_binding_changed",
        humanMessage: "The requested MCP server or tool differs from the exact persisted action binding.",
      };
    }
    const assignment = this.currentPersistedActionAssignment(action);
    if (!assignment?.agent_id || !this.specialistToolAllowed(
      assignment.agent_id,
      mcpServer,
      toolName,
      action.actionClass,
    )) {
      return {
        allowed: false,
        code: "action_specialist_tool_policy_denied",
        humanMessage: "The current specialist, MCP server, or tool policy no longer permits this exact binding.",
      };
    }
    return { allowed: true };
  }

  /**
   * Final direct-process assertion. This repeats the canonical mission,
   * target, decision/contract, assignment, agent-health, and per-agent tool
   * policy checks immediately before a reviewed local executable starts.
   */
  authorizePersistedLocalTool(
    run: DurableRun,
    action: DurableAction,
    toolId: string,
  ): CurrentActionBoundaryResult {
    const envelope = reviewedLocalToolActionEnvelope(action.arguments);
    if (!envelope || envelope.toolId !== toolId) {
      return {
        allowed: false,
        code: "action_local_tool_binding_changed",
        humanMessage: "The requested local executable differs from the exact persisted action binding.",
      };
    }
    return this.authorizePersistedReviewedProcessTool(
      run,
      action,
      toolId,
      "reviewed_local_process",
    );
  }

  /**
   * Shared final boundary for explicitly reviewed direct-process families.
   * The binding string is closed here so arbitrary action envelopes cannot
   * opt themselves into local execution.
   */
  authorizePersistedReviewedProcessTool(
    run: DurableRun,
    action: DurableAction,
    toolId: string,
    executionBinding: "reviewed_local_process" | "reviewed_windows_identity_process",
  ): CurrentActionBoundaryResult {
    const base = this.authorizePersistedAction(run, action);
    if (!base.allowed) return base;
    if (action.kind !== "tool") {
      return {
        allowed: false,
        code: "action_not_local_tool",
        humanMessage: "The persisted action is not a reviewed local tool action.",
      };
    }
    if (action.arguments.executionBinding !== executionBinding
      || action.arguments.toolId !== toolId) {
      return {
        allowed: false,
        code: "action_local_tool_binding_changed",
        humanMessage: "The requested local executable differs from the exact persisted action binding.",
      };
    }
    const assignment = this.currentPersistedActionAssignment(action);
    if (!assignment?.agent_id || !this.localToolAllowed(
      assignment.agent_id,
      toolId,
      action.actionClass,
    )) {
      return {
        allowed: false,
        code: "action_local_tool_policy_denied",
        humanMessage: "The current specialist or local tool policy no longer permits this exact executable binding.",
      };
    }
    return { allowed: true };
  }

  private currentMissionScope(missionId: string, target: string): CurrentActionBoundaryResult {
    const mission = this.database.prepare(`
      SELECT authorization_status FROM missions WHERE id = ?
    `).get(missionId) as { authorization_status: string } | undefined;
    if (mission?.authorization_status !== "verified") {
      return { allowed: false, code: "mission_authorization_not_verified", humanMessage: "Mission authorization is no longer verified." };
    }
    const normalizedTarget = target.trim();
    const disposition = this.database.prepare(`
      SELECT
        MAX(CASE WHEN disposition = 'allowed' THEN 1 ELSE 0 END) AS allowed,
        MAX(CASE WHEN disposition = 'prohibited' THEN 1 ELSE 0 END) AS prohibited
      FROM mission_targets WHERE mission_id = ? AND target = ?
    `).get(missionId, normalizedTarget) as { allowed: number; prohibited: number };
    if (disposition.allowed !== 1 || disposition.prohibited === 1) {
      return { allowed: false, code: "mission_target_not_authorized", humanMessage: "The action target is no longer in the current allowed scope or is now prohibited." };
    }
    return { allowed: true };
  }

  /**
   * Re-check the failed action against current canonical authorization and the
   * currently signed contract. Recovery must never rely on the historical fact
   * that an action was once allowed.
   */
  autonomousActionRemainsInContract(
    run: DurableRun,
    action: DurableAction,
    currentAssignment = this.currentPersistedActionAssignment(action),
  ): boolean {
    if (run.run.journey !== "autonomous" || action.runId !== run.run.id) return false;
    const mission = this.database.prepare(
      "SELECT authorization_status FROM missions WHERE id = ?",
    ).get(run.run.missionId) as { authorization_status: string } | undefined;
    if (mission?.authorization_status !== "verified") return false;
    if (!run.contractId || action.contractId !== run.contractId) return false;
    const contract = this.database
      .prepare("SELECT id, version, state, contract_hash, action_policy_json FROM mission_contracts WHERE id = ?")
      .get(run.contractId) as ContractRow | undefined;
    const binding = this.database.prepare(`
      SELECT contract_version_bound, contract_hash_bound
      FROM runs WHERE id = ?
    `).get(run.run.id) as {
      contract_version_bound: number | null;
      contract_hash_bound: string | null;
    } | undefined;
    if (
      !contract || contract.state !== "confirmed" ||
      !binding || binding.contract_version_bound === null || binding.contract_hash_bound === null ||
      contract.version !== binding.contract_version_bound ||
      contract.contract_hash !== binding.contract_hash_bound ||
      contract.version !== run.run.contractVersion ||
      contract.id !== run.contractId
    ) return false;
    const normalize = (value: string): string => value.trim().toLowerCase();
    const policy = parseObject(contract.action_policy_json);
    const allowed = new Set(
      (Array.isArray(policy.allowedActionClasses) ? policy.allowedActionClasses : [])
        .filter((value): value is string => typeof value === "string")
        .map(normalize)
        .filter(Boolean),
    );
    const prohibited = new Set(
      (Array.isArray(policy.prohibitedActionClasses) ? policy.prohibitedActionClasses : [])
        .filter((value): value is string => typeof value === "string")
        .map(normalize)
        .filter(Boolean),
    );
    const signedSpecialists = new Set(
      (Array.isArray(policy.specialistAgentIds) ? policy.specialistAgentIds : [])
        .filter((value): value is string => typeof value === "string")
        .map((value) => value.trim())
        .filter(Boolean),
    );
    const localEnvelope = action.kind === "tool"
      ? reviewedLocalToolActionEnvelope(action.arguments)
      : null;
    const actionType = normalize(action.actionType);
    const actionClass = normalize(action.actionClass);
    // ActionClassRegistry values belong to the signed mission contract. Tool
    // IDs are authorized independently by canonical specialist tool policy,
    // capabilities, and the exact persisted execution envelope below.
    if (
      (!localEnvelope && !allowed.has(actionType)) ||
      !allowed.has(actionClass) ||
      (!localEnvelope && prohibited.has(actionType)) ||
      prohibited.has(actionClass)
    ) return false;
    const destructivePolicy = typeof policy.destructivePolicy === "string"
      ? normalize(policy.destructivePolicy)
      : "";
    const boundedDestructiveTargets = new Set(
      (Array.isArray(policy.boundedDestructiveTargets) ? policy.boundedDestructiveTargets : [])
        .filter((value): value is string => typeof value === "string")
        .map((value) => value.trim())
        .filter(Boolean),
    );
    if (!evaluateDestructiveAuthorization({
      destructive: action.destructive,
      policy: destructivePolicy,
      target: action.target,
      boundedTargets: [...boundedDestructiveTargets],
    }).allowed) return false;
    const target = action.target.trim();
    const targetScope = this.currentMissionScope(run.run.missionId, target);
    if (!targetScope.allowed || signedSpecialists.size === 0) return false;
    if (!currentAssignment?.agent_id || !signedSpecialists.has(currentAssignment.agent_id)) return false;
    if (action.kind !== "tool") return true;
    const local = reviewedLocalToolActionEnvelope(action.arguments);
    if (local) {
      return this.localToolAllowed(
        currentAssignment.agent_id,
        local.toolId,
        action.actionClass,
      );
    }
    const mcpServer = action.arguments.mcpServer;
    const toolName = action.arguments.toolName;
    if (
      typeof mcpServer !== "string" || !mcpServer.trim() || mcpServer !== mcpServer.trim() ||
      typeof toolName !== "string" || !toolName.trim() || toolName !== toolName.trim()
    ) return false;
    return this.specialistToolAllowed(
      currentAssignment.agent_id,
      mcpServer,
      toolName,
      action.actionClass,
    );
  }

  private localToolCapabilityAllowsActionClass(
    agentId: string,
    toolId: string,
    actionClass: string,
  ): boolean {
    const rows = this.database.prepare(`
      SELECT metadata_json
      FROM agent_capabilities
      WHERE agent_id = ? AND capability = ? AND enabled = 1
    `).all(agentId, toolId) as Array<{ metadata_json: string }>;
    if (rows.length === 0) return false;
    const declaredRows = rows.flatMap(({ metadata_json }) => {
      const metadata = parseObject(metadata_json);
      const actionClassIds = [
        ...(typeof metadata.actionClassId === "string"
          ? [metadata.actionClassId]
          : []),
        ...(Array.isArray(metadata.actionClassIds)
          ? metadata.actionClassIds.filter(
              (value): value is string => typeof value === "string",
            )
          : []),
      ];
      return actionClassIds.length > 0 ? [actionClassIds] : [];
    });
    // Historical reviewed-local capability rows did not carry the manifest
    // relation. Preserve that compatibility; once the projection exposes the
    // relation, however, it becomes an exact fail-closed dispatch constraint.
    return declaredRows.length === 0
      || declaredRows.some((actionClassIds) => actionClassIds.includes(actionClass));
  }

  private localToolAllowed(
    agentId: string,
    toolId: string,
    actionClass: string,
  ): boolean {
    const agent = this.database.prepare(`
      SELECT status, tool_policy_json, configuration_json
      FROM agents WHERE id = ?
    `).get(agentId) as {
      status: string;
      tool_policy_json: string;
      configuration_json: string;
    } | undefined;
    if (!agent || ["offline", "quarantined"].includes(agent.status)) return false;
    const toolPolicy = parseObject(agent.tool_policy_json);
    const strings = (value: unknown): string[] => Array.isArray(value)
      ? value.filter((item): item is string => typeof item === "string")
      : [];
    const allowed = new Set(strings(toolPolicy.allowedTools));
    const denied = new Set(strings(toolPolicy.deniedTools));
    const approvalRequired = new Set(strings(toolPolicy.approvalRequiredTools));
    if (!allowed.has(toolId) || denied.has(toolId) || approvalRequired.has(toolId)) return false;
    if (!this.localToolCapabilityAllowsActionClass(
      agentId,
      toolId,
      actionClass,
    )) return false;
    const configuration = parseObject(agent.configuration_json);
    const configuredBindings = configuration.productAgent === true
      ? this.runtimeBindingAgentIds(agentId, configuration).filter((id) => id !== agentId)
      : [];
    const executionAgentIds = configuredBindings.length > 0
      ? configuredBindings
      : [agentId];
    return executionAgentIds.some((runtimeAgentId) => {
      const runtimeAgent = this.database.prepare(`
        SELECT status FROM agents WHERE id = ?
      `).get(runtimeAgentId) as { status: string } | undefined;
      return Boolean(
        runtimeAgent
        && !["offline", "quarantined"].includes(runtimeAgent.status)
        && this.localToolCapabilityAllowsActionClass(
          runtimeAgentId,
          toolId,
          actionClass,
        ),
      );
    });
  }

  /**
   * Product assignments remain the durable/audited owner. Execution policies
   * may still name one or more internal runtime adapters; those bindings are
   * projected into the product row and resolved only at this final boundary.
   */
  private runtimeBindingAgentIds(
    agentId: string,
    configuration: Readonly<Record<string, unknown>>,
  ): readonly string[] {
    const configured = configuration.productAgent === true
      && Array.isArray(configuration.runtimeBindingAgentIds)
      ? configuration.runtimeBindingAgentIds
        .filter((value): value is string => typeof value === "string")
        .map((value) => value.trim())
        .filter(Boolean)
      : [];
    return [...new Set([agentId, ...configured])];
  }

  /**
   * Resolve the exact specialist/MCP/tool boundary from the V2 database.
   * Missing, malformed, stale, approval-requiring, or unhealthy projections
   * fail closed. This replaces the legacy in-process roster import and keeps
   * the parallel server independent from legacy agent and MCP modules.
   */
  private manifestToolCapabilityAllowsActionClass(
    agentId: string,
    toolName: string,
    actionClass: string,
  ): boolean {
    const rows = this.database.prepare(`
      SELECT metadata_json
      FROM agent_capabilities
      WHERE agent_id = ? AND capability = ? AND enabled = 1
        AND source = 'runtime-manifest-tool-binding'
    `).all(agentId, toolName) as Array<{ metadata_json: string }>;
    return rows.some(({ metadata_json }) => {
      const metadata = parseObject(metadata_json);
      const actionClassIds = Array.isArray(metadata.actionClassIds)
        ? metadata.actionClassIds.filter(
            (value): value is string => typeof value === "string",
          )
        : [];
      return metadata.toolId === toolName
        && actionClassIds.includes(actionClass);
    });
  }

  private specialistToolAllowed(
    agentId: string,
    mcpServer: string,
    toolName: string,
    actionClass: string,
  ): boolean {
    const agent = this.database.prepare(`
      SELECT status, tool_policy_json, configuration_json
      FROM agents WHERE id = ?
    `).get(agentId) as {
      status: string;
      tool_policy_json: string;
      configuration_json: string;
    } | undefined;
    if (!agent || ["offline", "quarantined"].includes(agent.status)) return false;
    const toolPolicy = parseObject(agent.tool_policy_json);
    const strings = (value: unknown): string[] => Array.isArray(value)
      ? value.filter((item): item is string => typeof item === "string")
      : [];
    const allowed = new Set(strings(toolPolicy.allowedTools));
    const denied = new Set(strings(toolPolicy.deniedTools));
    const approvalRequired = new Set(strings(toolPolicy.approvalRequiredTools));
    if (!allowed.has(toolName) || denied.has(toolName) || approvalRequired.has(toolName)) return false;

    if (!this.manifestToolCapabilityAllowsActionClass(
      agentId,
      toolName,
      actionClass,
    )) return false;

    const server = this.database.prepare(`
      SELECT status, capabilities_json, policy_json
      FROM mcp_servers WHERE id = ? OR name = ?
      ORDER BY CASE WHEN id = ? THEN 0 ELSE 1 END
      LIMIT 1
    `).get(mcpServer, mcpServer, mcpServer) as {
      status: string;
      capabilities_json: string;
      policy_json: string;
    } | undefined;
    if (!server || server.status !== "healthy") return false;
    const serverPolicy = parseObject(server.policy_json);
    const capabilities = new Set(strings(parseObject(`{\"items\":${server.capabilities_json}}`).items));
    if (!isSpecialistMcpExecutionPolicy(serverPolicy)) return false;
    const assignedAgents = new Set(serverPolicy.assignedAgents);
    const runtimeBindingAgentIds = this.runtimeBindingAgentIds(
      agentId,
      parseObject(agent.configuration_json),
    );
    const exactLiveBinding = runtimeBindingAgentIds.some((runtimeAgentId) => {
      if (!assignedAgents.has(runtimeAgentId)) return false;
      const runtimeAgent = this.database.prepare(`
        SELECT status FROM agents WHERE id = ?
      `).get(runtimeAgentId) as { status: string } | undefined;
      if (!runtimeAgent || ["offline", "quarantined"].includes(runtimeAgent.status)) return false;
      return this.manifestToolCapabilityAllowsActionClass(
        runtimeAgentId,
        toolName,
        actionClass,
      );
    });
    return serverPolicy.enabled
      && serverPolicy.startPermitted
      && exactLiveBinding
      && capabilities.has(toolName);
  }

  private currentPersistedActionAssignment(action: DurableAction): ActionAssignmentRow | undefined {
    const assignment = this.database.prepare(`
      SELECT a.assignment_id, ass.run_id AS assignment_run_id,
        ass.step_id AS assignment_step_id, ass.status AS assignment_status,
        ass.agent_id, ag.status AS agent_status,
        ps.run_id AS step_run_id, ps.status AS step_status,
        ps.assigned_agent_id AS step_agent_id,
        p.id AS plan_id, p.run_id AS plan_run_id, p.status AS plan_status,
        r.current_plan_id, r.current_step_id
      FROM actions a
      JOIN assignments ass ON ass.id = a.assignment_id
      JOIN agents ag ON ag.id = ass.agent_id
      JOIN plan_steps ps ON ps.id = ass.step_id
      JOIN plans p ON p.id = ps.plan_id
      JOIN runs r ON r.id = a.run_id
      WHERE a.id = ? AND a.run_id = ?
    `).get(action.id, action.runId) as ActionAssignmentRow | undefined;
    if (
      !assignment?.assignment_id ||
      assignment.assignment_run_id !== action.runId ||
      assignment.assignment_step_id !== action.stepId ||
      assignment.step_run_id !== action.runId || assignment.plan_run_id !== action.runId ||
      assignment.plan_id !== assignment.current_plan_id ||
      assignment.assignment_step_id !== assignment.current_step_id ||
      assignment.assignment_status !== "active" || assignment.step_status !== "running" ||
      assignment.plan_status !== "active" ||
      !assignment.agent_id || assignment.step_agent_id !== assignment.agent_id ||
      !assignment.agent_status || ["offline", "quarantined"].includes(assignment.agent_status)
    ) return undefined;
    return assignment;
  }

  guidedDecision(decisionId: string): GuidedDecision | undefined {
    const row = this.database
      .prepare(`
        SELECT gd.*,
          (SELECT COUNT(*) FROM actions a WHERE a.guided_decision_id = gd.id) AS consumed_count
        FROM guided_decisions gd WHERE gd.id = ?
      `)
      .get(decisionId) as GuidedDecisionRow | undefined;
    if (!row) return undefined;
    const status: GuidedDecision["status"] = row.consumed_count > 0
      ? "consumed"
      : row.status === "approved"
        ? "authorized"
        : row.status === "pending"
          ? "pending"
          : row.status === "expired"
            ? "expired"
            : "rejected";
    return {
      id: row.id,
      missionId: row.mission_id,
      runId: row.run_id,
      stepId: row.step_id,
      journey: "guided",
      actionFingerprint: row.requested_action_fingerprint,
      status,
      ...(row.decided_at ? { authorizedAt: row.decided_at } : {}),
      expiresAt: row.expires_at,
      version: row.consumed_count > 0 ? 2 : 1,
    };
  }
}

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import {
  ATTACK_CENTRIC_REUSABLE_NODE_TYPES,
  getMemoryControlPolicy,
  isAttackCentricReusableNodeType,
  MemoryRepository,
  type MemoryNode,
} from "../memory";
import {
  resolveAutonomousPlanningSelection,
  type AutonomousPlanningSelection,
} from "../model-config";
import { autonomousContractHash, canonicalJson, hashCanonical, sha256 } from "./canonical";
import { IdempotencyConflictError } from "./errors";
import type {
  AutonomousContextCandidate,
  AutonomousExecutionPreview,
  AutonomousMissionRequest,
  CreatedMission,
  Journey,
  MissionCreateRequest,
  MissionIntakeContextBinding,
  MissionListPage,
  MissionSummary,
} from "./types";

type JsonObject = Record<string, unknown>;

interface IdempotencyRow {
  readonly value_json: string;
}

interface StoredIdempotency {
  readonly requestHash: string;
  readonly response: CreatedMission;
}

interface MissionSummaryRow {
  readonly id: string;
  readonly title: string;
  readonly journey: Journey;
  readonly mission_status: string;
  readonly authorization_status: string;
  readonly engagement_id: string | null;
  readonly created_at: string;
  readonly run_status: string | null;
  readonly run_id: string | null;
  readonly active_run_id: string | null;
  readonly run_started_at: string | null;
  readonly run_ended_at: string | null;
  readonly updated_at: string;
  readonly current_phase: string | null;
  readonly progress: number | null;
  readonly current_owner_id: string | null;
  readonly current_owner_name: string | null;
  readonly team_json: string;
  readonly scope_targets_json: string;
  readonly allowed_target_count: number;
  readonly prohibited_target_count: number;
  readonly provider: string | null;
  readonly risk: string | null;
  readonly evidence_count: number;
  readonly highest_finding_severity: MissionSummary["highestFindingSeverity"];
  readonly decision_state: string | null;
  readonly last_event_type: string | null;
  readonly last_event_summary: string | null;
  readonly last_event_at: string | null;
  readonly budget_json: string | null;
  readonly budget_usage_json: string | null;
  readonly next_action: string | null;
}

interface CursorValue {
  readonly version: 1;
  readonly updatedAt: string;
  readonly id: string;
  readonly filterHash: string;
  readonly signature: string;
}

export interface ListMissionsOptions {
  readonly cursor?: string;
  readonly limit?: number;
  readonly journey?: Journey;
  readonly status?: string;
  readonly query?: string;
  readonly engagement?: string;
  readonly target?: string;
  readonly agent?: string;
  readonly provider?: string;
  readonly updatedFrom?: string;
  readonly updatedTo?: string;
  readonly risk?: string;
  readonly evidence?: "present" | "none";
  readonly findingSeverity?: string;
  readonly decisionState?: string;
  readonly recoveryState?: "recovering" | "blocked" | "none";
}

export interface CreateMissionOptions {
  readonly request: MissionCreateRequest;
  readonly requestHash: string;
  readonly idempotencyKey: string;
  readonly actorId: string;
  /**
   * Runs after the canonical mission scope exists, but before constraints,
   * contract, run, events, or the idempotent response are committed. Throwing
   * rolls the entire launch back.
   */
  readonly resolveIntakeContext?: (input: {
    readonly missionId: string;
    readonly journey: Journey;
    readonly memoryPolicy: Readonly<Record<string, unknown>>;
  }) => MissionIntakeContextBinding;
  /**
   * Runs after the canonical run exists but inside the same outer IMMEDIATE
   * transaction. A graph failure therefore rolls back the complete launch
   * instead of surfacing an ambiguous error after mission commit.
   */
  readonly materializeCanonicalGraph?: (input: {
    readonly missionId: string;
    readonly runId: string;
  }) => readonly string[];
  /**
   * Resolves and immutably pins every launch-time specialist configuration
   * after the run exists, but before any planning event is committed.
   * Throwing rolls the complete mission launch back.
   */
  readonly pinModelAssignments?: (input: {
    readonly missionId: string;
    readonly runId: string;
    readonly journey: Journey;
    readonly specialistAgentIds: readonly string[];
    readonly planningSelection: AutonomousPlanningSelection;
    readonly agentModelAssignments: AutonomousMissionRequest["contract"]["agentModelAssignments"];
    readonly allowedActionClasses: readonly string[];
  }) => readonly string[];
}

function json(value: unknown): string {
  return canonicalJson(value);
}

function id(prefix: string): string {
  return `${prefix}_${randomUUID()}`;
}

function idempotencySettingKey(key: string): string {
  return `idempotency.mission.${sha256(key)}`;
}

function targetType(target: string): string {
  if (/^https?:\/\//iu.test(target)) return "url";
  if (/^[0-9a-f:.]+\/\d+$/iu.test(target)) return "cidr";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(target) || target.includes(":")) return "ip";
  if (target.includes("*") || target.includes("?")) return "pattern";
  if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/iu.test(target)) return "domain";
  return "other";
}

function normalizeTarget(target: string): string {
  const trimmed = target.trim().normalize("NFKC");
  try {
    const url = new URL(trimmed);
    url.hostname = url.hostname.toLocaleLowerCase("en-US");
    return url.toString();
  } catch {
    return trimmed.toLocaleLowerCase("en-US");
  }
}

function parseJsonObject(value: string | null | undefined): JsonObject {
  if (!value) return {};
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as JsonObject
      : {};
  } catch {
    return {};
  }
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? [...new Set(value.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
      .map((item) => item.trim()))]
    : [];
}

function requiresExecutionTools(request: AutonomousMissionRequest): boolean {
  const advisoryOnly = new Set(["analysis", "planning", "reporting", "summarization", "documentation"]);
  return request.contract.allowedActionClasses.some(
    (actionClass) => !advisoryOnly.has(actionClass.trim().toLocaleLowerCase("en-US")),
  );
}

function mapSummary(row: MissionSummaryRow): MissionSummary {
  const parseArray = (value: string): unknown[] => {
    try {
      const parsed = JSON.parse(value) as unknown;
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  };
  const numericRecord = (value: string | null): Record<string, number> => {
    const source = parseJsonObject(value);
    return Object.fromEntries(Object.entries(source).flatMap(([key, candidate]) => (
      typeof candidate === "number" && Number.isFinite(candidate) && candidate >= 0
        ? [[key, candidate]]
        : []
    )));
  };
  const team = parseArray(row.team_json).flatMap((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
    const item = entry as Record<string, unknown>;
    return typeof item.id === "string"
      ? [{ id: item.id, name: typeof item.name === "string" ? item.name : null }]
      : [];
  });
  const allowedTargets = parseArray(row.scope_targets_json)
    .filter((target): target is string => typeof target === "string");
  return {
    id: row.id,
    title: row.title,
    journey: row.journey,
    status: row.run_status ?? row.mission_status,
    missionStatus: row.mission_status,
    authorizationStatus: row.authorization_status,
    engagementId: row.engagement_id,
    scope: {
      allowedTargets,
      allowedTargetCount: row.allowed_target_count,
      prohibitedTargetCount: row.prohibited_target_count,
    },
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    runId: row.run_id,
    activeRunId: row.active_run_id,
    runStartedAt: row.run_started_at,
    runEndedAt: row.run_ended_at,
    currentPhase: row.current_phase,
    progress: row.progress === null ? null : Math.round(row.progress * 10_000) / 100,
    currentOwner: row.current_owner_id
      ? { id: row.current_owner_id, name: row.current_owner_name }
      : null,
    team,
    provider: row.provider,
    risk: row.risk,
    evidenceCount: row.evidence_count,
    highestFindingSeverity: row.highest_finding_severity,
    decisionState: row.decision_state,
    recoveryState: row.run_status === "recovering" || row.run_status === "blocked"
      ? row.run_status
      : null,
    lastMeaningfulEvent: row.last_event_type && row.last_event_summary && row.last_event_at
      ? { type: row.last_event_type, summary: row.last_event_summary, occurredAt: row.last_event_at }
      : null,
    budget: {
      limits: numericRecord(row.budget_json),
      usage: numericRecord(row.budget_usage_json),
    },
    nextAction: row.next_action,
  };
}

function autonomousContextEligible(
  node: MemoryNode,
  request: AutonomousMissionRequest,
  nowMs: number,
  requirePermittedScope = true,
): boolean {
  const attackKnowledge = isAttackCentricReusableNodeType(node.nodeType);
  if (node.nodeType === "preference") {
    if (node.lifecycleStatus !== "confirmed") return false;
  } else if (node.nodeType === "lesson") {
    if (node.lifecycleStatus !== "verified") return false;
  } else if (!attackKnowledge || !["confirmed", "verified"].includes(node.lifecycleStatus)) {
    return false;
  }
  if (node.nodeType === "preference" && node.confirmationState !== "confirmed") return false;
  if (node.sensitivity === "restricted") return false;
  if (node.expiresAt && Date.parse(node.expiresAt) <= nowMs) return false;
  if (node.retentionPolicy.allowAutonomous === false) return false;
  if (node.retentionPolicy.journeys && !node.retentionPolicy.journeys.includes("autonomous")) return false;
  if (node.scope.kind === "mission") return false;
  if (node.scope.kind === "engagement" && node.scope.engagementId !== request.authorization.engagementId) {
    return false;
  }
  if (requirePermittedScope) {
    const scopes = new Set(request.contract.memoryScopes);
    if (node.nodeType === "preference" && !scopes.has("confirmed_preferences")) return false;
    if (node.nodeType === "lesson" && !scopes.has("verified_lessons")) return false;
    if (
      attackKnowledge && node.lifecycleStatus === "confirmed"
      && !scopes.has("confirmed_attack_knowledge")
    ) return false;
    if (
      attackKnowledge && node.lifecycleStatus === "verified"
      && !scopes.has("verified_attack_knowledge")
      && !scopes.has("confirmed_attack_knowledge")
    ) return false;
    if (node.scope.kind === "engagement" && !scopes.has("engagement_memory")) return false;
  }
  return true;
}

function contextCandidate(node: MemoryNode): AutonomousContextCandidate {
  if (
    node.nodeType !== "preference" && node.nodeType !== "lesson"
    && !isAttackCentricReusableNodeType(node.nodeType)
  ) {
    throw new TypeError("Autonomous context candidate is not reusable memory");
  }
  return {
    id: node.id,
    nodeType: node.nodeType,
    title: node.title,
    summary: node.summary,
    lifecycleStatus: node.lifecycleStatus as "confirmed" | "verified",
    scope: node.scope.kind === "engagement"
      ? { kind: "engagement", engagementId: node.scope.engagementId }
      : { kind: "global" },
    sensitivity: node.sensitivity as "public" | "internal" | "private",
    confidence: node.confidence,
    provenanceExplanation: node.provenance.explanation,
    updatedAt: node.updatedAt,
  };
}

function cursorSignature(
  value: Omit<CursorValue, "signature">,
  secret: string,
): string {
  return createHmac("sha256", secret).update(canonicalJson(value), "utf8").digest("hex");
}

function decodeCursor(
  cursor: string | undefined,
  expectedFilterHash: string,
  secret: string,
): CursorValue | undefined {
  if (!cursor) return undefined;
  try {
    const value = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as unknown;
    if (!value || typeof value !== "object") throw new Error("invalid cursor");
    const candidate = value as Record<string, unknown>;
    if (
      candidate.version !== 1 ||
      typeof candidate.updatedAt !== "string" ||
      Number.isNaN(Date.parse(candidate.updatedAt)) ||
      typeof candidate.id !== "string" ||
      !candidate.id ||
      typeof candidate.filterHash !== "string" ||
      candidate.filterHash !== expectedFilterHash ||
      typeof candidate.signature !== "string" ||
      !/^[a-f0-9]{64}$/u.test(candidate.signature)
    ) {
      throw new Error("invalid cursor");
    }
    const unsigned = {
      version: 1 as const,
      updatedAt: candidate.updatedAt,
      id: candidate.id,
      filterHash: candidate.filterHash,
    };
    const expected = Buffer.from(cursorSignature(unsigned, secret), "hex");
    const supplied = Buffer.from(candidate.signature, "hex");
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) {
      throw new Error("invalid cursor signature");
    }
    return { ...unsigned, signature: candidate.signature };
  } catch {
    throw new RangeError("cursor is invalid");
  }
}

function encodeCursor(row: MissionSummaryRow, filterHash: string, secret: string): string {
  const unsigned = { version: 1 as const, updatedAt: row.updated_at, id: row.id, filterHash };
  return Buffer.from(canonicalJson({ ...unsigned, signature: cursorSignature(unsigned, secret) }), "utf8").toString(
    "base64url",
  );
}

function portfolioFilterHash(options: ListMissionsOptions): string {
  return hashCanonical({
    journey: options.journey ?? null,
    status: options.status ?? null,
    query: options.query ?? null,
    engagement: options.engagement ?? null,
    target: options.target ?? null,
    agent: options.agent ?? null,
    provider: options.provider ?? null,
    updatedFrom: options.updatedFrom ?? null,
    updatedTo: options.updatedTo ?? null,
    risk: options.risk ?? null,
    evidence: options.evidence ?? null,
    findingSeverity: options.findingSeverity ?? null,
    decisionState: options.decisionState ?? null,
    recoveryState: options.recoveryState ?? null,
  });
}

function parseStoredIdempotency(value: string): StoredIdempotency {
  const parsed = JSON.parse(value) as StoredIdempotency;
  if (!parsed.requestHash || !parsed.response?.mission?.id || !parsed.response?.run?.id) {
    throw new Error("Stored mission idempotency record is corrupt");
  }
  return parsed;
}

const SUMMARY_SELECT = `
  WITH ranked_runs AS (
    SELECT r.*,
      ROW_NUMBER() OVER (PARTITION BY r.mission_id ORDER BY r.created_at DESC, r.id DESC) AS rank
    FROM runs r
  )
  SELECT
    m.id,
    m.name AS title,
    m.journey,
    m.status AS mission_status,
    m.authorization_status,
    m.engagement_id,
    m.created_at,
    r.status AS run_status,
    r.id AS run_id,
    (SELECT active_run.id FROM runs active_run
      WHERE active_run.mission_id = m.id
        AND active_run.status IN ('queued', 'planning', 'awaiting_contract_confirmation', 'running',
          'waiting_guided_decision', 'blocked', 'recovering')
      ORDER BY active_run.updated_at DESC, active_run.created_at DESC, active_run.id DESC
      LIMIT 1) AS active_run_id,
    r.started_at AS run_started_at,
    r.ended_at AS run_ended_at,
    m.updated_at,
    ps.phase AS current_phase,
    r.progress,
    r.current_owner_id,
    owner.display_name AS current_owner_name,
    COALESCE((
      SELECT json_group_array(json_object('id', team.agent_id, 'name', team.display_name))
      FROM (
        SELECT DISTINCT a.agent_id, ag.display_name
        FROM assignments a
        LEFT JOIN agents ag ON ag.id = a.agent_id
        WHERE a.run_id = r.id
        ORDER BY a.agent_id
      ) team
    ), '[]') AS team_json,
    COALESCE((
      SELECT json_group_array(scope.target)
      FROM (
        SELECT mt.target
        FROM mission_targets mt
        WHERE mt.mission_id = m.id AND mt.disposition = 'allowed'
        ORDER BY mt.normalized_target
      ) scope
    ), '[]') AS scope_targets_json,
    (SELECT COUNT(*) FROM mission_targets mt WHERE mt.mission_id = m.id AND mt.disposition = 'allowed') AS allowed_target_count,
    (SELECT COUNT(*) FROM mission_targets mt WHERE mt.mission_id = m.id AND mt.disposition = 'prohibited') AS prohibited_target_count,
    (SELECT pt.provider FROM provider_turns pt WHERE pt.run_id = r.id ORDER BY pt.started_at DESC, pt.id DESC LIMIT 1) AS provider,
    ps.risk_class AS risk,
    (SELECT COUNT(*) FROM evidence e WHERE e.mission_id = m.id) AS evidence_count,
    (SELECT f.severity FROM findings f WHERE f.mission_id = m.id ORDER BY
      CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
        WHEN 'low' THEN 2 WHEN 'informational' THEN 1 ELSE 0 END DESC,
      f.updated_at DESC, f.id DESC LIMIT 1) AS highest_finding_severity,
    (SELECT gd.status FROM guided_decisions gd WHERE gd.run_id = r.id ORDER BY
      CASE WHEN gd.status = 'pending' THEN 0 ELSE 1 END, gd.created_at DESC, gd.id DESC LIMIT 1) AS decision_state,
    (SELECT e.event_type FROM events e WHERE e.run_id = r.id AND lower(e.event_type) NOT LIKE '%heartbeat%'
      ORDER BY e.sequence DESC, e.occurred_at DESC, e.id DESC LIMIT 1) AS last_event_type,
    (SELECT e.summary FROM events e WHERE e.run_id = r.id AND lower(e.event_type) NOT LIKE '%heartbeat%'
      ORDER BY e.sequence DESC, e.occurred_at DESC, e.id DESC LIMIT 1) AS last_event_summary,
    (SELECT e.occurred_at FROM events e WHERE e.run_id = r.id AND lower(e.event_type) NOT LIKE '%heartbeat%'
      ORDER BY e.sequence DESC, e.occurred_at DESC, e.id DESC LIMIT 1) AS last_event_at,
    r.budget_json,
    r.budget_usage_json,
    r.next_action_summary AS next_action
  FROM missions m
  LEFT JOIN ranked_runs r ON r.mission_id = m.id AND r.rank = 1
  LEFT JOIN plan_steps ps ON ps.id = r.current_step_id
  LEFT JOIN agents owner ON owner.id = r.current_owner_id
`;

/** Transactional persistence for mission aggregate creation and portfolio reads. */
export class MissionRepository {
  private readonly events: EventRepository;
  private portfolioCursorSecret?: string;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {
    this.events = new EventRepository(database);
  }

  /** Minimal ownership projection used by shared control-plane guards. */
  getControlPlaneOwnership(missionId: string): {
    readonly missionId: string;
    readonly controlPlane: "legacy" | "ti_scale";
  } | undefined {
    const row = this.database.prepare(
      "SELECT id, control_plane FROM missions WHERE id = ?",
    ).get(missionId) as { readonly id: string; readonly control_plane: "legacy" | "ti_scale" } | undefined;
    return row ? { missionId: row.id, controlPlane: row.control_plane } : undefined;
  }

  private cursorSecret(): string {
    if (this.portfolioCursorSecret) return this.portfolioCursorSecret;
    this.portfolioCursorSecret = inImmediateTransaction(this.database, () => {
      const key = "mission.portfolio.cursor-secret.v1";
      const existing = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(key) as { value_json: string } | undefined;
      if (existing) {
        const parsed = parseJsonObject(existing.value_json);
        if (typeof parsed.secret === "string" && /^[a-f0-9]{64}$/u.test(parsed.secret)) {
          return parsed.secret;
        }
        throw new Error("Mission portfolio cursor secret is corrupt");
      }
      const secret = randomBytes(32).toString("hex");
      const now = this.clock().toISOString();
      this.database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'restricted', 1, 'system:mission-portfolio', ?)
      `).run(key, json({ secret }), now);
      return secret;
    });
    return this.portfolioCursorSecret;
  }

  /**
   * Returns only real, currently eligible memory. Selected IDs are validated
   * independently of the bounded preview so older valid nodes remain usable.
   */
  autonomousContextPreview(request: AutonomousMissionRequest): {
    readonly candidates: readonly AutonomousContextCandidate[];
    readonly selectedNodeIds: readonly string[];
    readonly invalidSelectedNodeIds: readonly string[];
  } {
    const now = this.clock();
    const control = getMemoryControlPolicy(this.database);
    if (!control.enabled || !control.autonomousUse) {
      return {
        candidates: [],
        selectedNodeIds: [],
        invalidSelectedNodeIds: [...request.contract.contextNodeIds],
      };
    }
    const memory = new MemoryRepository(this.database);
    const eligible = (node: MemoryNode | undefined, requirePermittedScope = true): node is MemoryNode => Boolean(
      node
      && (control.operationalMemoryEnabled || node.nodeType === "preference")
      && autonomousContextEligible(
        node,
        request,
        now.getTime(),
        requirePermittedScope,
      ),
    );
    const invalidSelectedNodeIds = request.contract.contextNodeIds.filter((nodeId) => {
      const node = memory.getNode(nodeId);
      return !eligible(node);
    });
    const selectedNodeIds = request.contract.contextNodeIds.filter(
      (nodeId) => !invalidSelectedNodeIds.includes(nodeId),
    );
    const reusableNodeTypes = [
      "preference",
      "lesson",
      ...ATTACK_CENTRIC_REUSABLE_NODE_TYPES,
    ] as const;
    const reusableTypePlaceholders = reusableNodeTypes.map(() => "?").join(", ");
    const rows = this.database.prepare(`
      SELECT id FROM memory_nodes
      WHERE node_type IN (${reusableTypePlaceholders})
        AND lifecycle_status IN ('confirmed', 'verified')
        AND sensitivity IN ('public', 'internal', 'private')
        AND (expires_at IS NULL OR expires_at > ?)
        AND (scope = 'global' OR (scope = 'engagement' AND engagement_id = ?))
      ORDER BY pinned DESC, updated_at DESC, id DESC LIMIT 200
    `).all(
      ...reusableNodeTypes,
      now.toISOString(),
      request.authorization.engagementId ?? "",
    ) as Array<{ id: string }>;
    const listed = rows.flatMap(({ id: nodeId }) => {
      const node = memory.getNode(nodeId);
      return eligible(node, false) ? [contextCandidate(node)] : [];
    });
    const selectedCandidates = selectedNodeIds.flatMap((nodeId) => {
      const node = memory.getNode(nodeId);
      return eligible(node) ? [contextCandidate(node)] : [];
    });
    const selectedSet = new Set(selectedCandidates.map((candidate) => candidate.id));
    const candidates = [
      ...selectedCandidates,
      ...listed.filter((candidate) => !selectedSet.has(candidate.id)),
    ].slice(0, Math.max(100, selectedCandidates.length));
    return { candidates, selectedNodeIds, invalidSelectedNodeIds };
  }

  /**
   * Projects the secret-free provider, MCP, and specialist inventory that the
   * runtime most recently materialized into the canonical database. Launch
   * still reruns live readiness; this projection exists for inspectable team
   * selection and never substitutes for the enforcing runtime checks.
   */
  autonomousExecutionPreview(request: AutonomousMissionRequest): AutonomousExecutionPreview {
    const now = this.clock().toISOString();
    const providerRows = this.database.prepare(`
      WITH ranked AS (
        SELECT component_id, status, metrics_json, message, captured_at,
          ROW_NUMBER() OVER (
            PARTITION BY component_id ORDER BY captured_at DESC, id DESC
          ) AS row_number
        FROM health_snapshots WHERE component_type = 'provider'
      )
      SELECT component_id, status, metrics_json, message, captured_at
      FROM ranked WHERE row_number = 1 ORDER BY component_id
    `).all() as Array<{
      component_id: string;
      status: "healthy" | "degraded" | "unhealthy" | "unknown";
      metrics_json: string;
      message: string | null;
      captured_at: string;
    }>;
    const providers = providerRows.map((row) => {
      const metrics = parseJsonObject(row.metrics_json);
      const authenticated = metrics.authenticated === true;
      const callable = metrics.callable === true;
      const enforcesAutonomousBoundary = metrics.enforcesAutonomousBoundary === true;
      const expiresAt = typeof metrics.expiresAt === "string" ? metrics.expiresAt : "";
      const fresh = Number.isFinite(Date.parse(expiresAt)) && expiresAt >= now;
      return {
        id: row.component_id,
        status: row.status,
        authenticated,
        enforcesAutonomousBoundary,
        reportsExactTokenUsage: metrics.reportsExactTokenUsage === true,
        reportsExactCostUsage: metrics.reportsExactCostUsage === true,
        compatible: authenticated
          && callable
          && fresh
          && enforcesAutonomousBoundary
          && row.status === "healthy",
        reason: row.message?.trim() || "No provider health explanation was reported.",
        checkedAt: row.captured_at,
      } as const;
    });

    const toolRows = this.database.prepare(`
      SELECT id, name, status, capabilities_json, policy_json, last_checked_at
      FROM mcp_servers ORDER BY name, id
    `).all() as Array<{
      id: string;
      name: string;
      status: "unknown" | "healthy" | "degraded" | "offline" | "quarantined";
      capabilities_json: string;
      policy_json: string;
      last_checked_at: string | null;
    }>;
    const projectedToolRows = toolRows.map((row) => {
      const policy = parseJsonObject(row.policy_json);
      return {
        id: row.id,
        name: row.name,
        status: row.status,
        capabilities: stringArray(JSON.parse(row.capabilities_json) as unknown),
        runtimeAssignedAgentIds: stringArray(policy.assignedAgents),
        enabled: policy.enabled === true,
        startPermitted: policy.startPermitted === true,
        riskClass: typeof policy.riskClass === "string" && policy.riskClass.trim()
          ? policy.riskClass.trim()
          : "unspecified",
        ...(row.last_checked_at ? { checkedAt: row.last_checked_at } : {}),
      };
    });
    const needsTools = requiresExecutionTools(request);
    const agentRows = this.database.prepare(`
      SELECT id, display_name, role, status, provider_policy_json,
        tool_policy_json, configuration_json, last_heartbeat_at
      FROM agents
      WHERE json_extract(configuration_json, '$.userFacing') = 1
      ORDER BY display_name, id
    `).all() as Array<{
      id: string;
      display_name: string;
      role: string;
      status: "available" | "busy" | "degraded" | "offline" | "quarantined";
      provider_policy_json: string;
      tool_policy_json: string;
      configuration_json: string;
      last_heartbeat_at: string | null;
    }>;
    const projectedTools = projectedToolRows.map((tool) => {
      const { runtimeAssignedAgentIds, ...projectedTool } = tool;
      return {
        ...projectedTool,
        assignedAgentIds: agentRows.flatMap((agent) => {
          const configuration = parseJsonObject(agent.configuration_json);
          const runtimeBindingAgentIds = stringArray(configuration.runtimeBindingAgentIds);
          return runtimeAssignedAgentIds.includes(agent.id)
            || runtimeBindingAgentIds.some((agentId) =>
              runtimeAssignedAgentIds.includes(agentId))
            ? [agent.id]
            : [];
        }),
      };
    });
    const toolBoundaryByAgent = new Map(agentRows.map((row) => {
      const toolPolicy = parseJsonObject(row.tool_policy_json);
      const capabilityRows = this.database.prepare(`
        SELECT capability, metadata_json FROM agent_capabilities
        WHERE agent_id = ? AND enabled = 1
          AND source = 'live-route-attestation'
          AND json_extract(metadata_json, '$.validUntil') >= ?
        ORDER BY capability
      `).all(row.id, now) as Array<{ capability: string; metadata_json: string }>;
      const capabilities = capabilityRows.map((item) => item.capability);
      const autonomousLocalTools = capabilityRows.flatMap((item) => {
        const metadata = parseJsonObject(item.metadata_json);
        const journeys = stringArray(metadata.executionJourneys);
        const actionClasses = [
          ...(typeof metadata.actionClassId === "string" ? [metadata.actionClassId] : []),
          ...stringArray(metadata.actionClassIds),
        ];
        return metadata.executionBinding === "reviewed_local_process"
          && metadata.toolId === item.capability
          && journeys.includes("autonomous")
          && actionClasses.some((actionClass) => request.contract.allowedActionClasses.includes(actionClass))
          ? [item.capability]
          : [];
      });
      return [row.id, {
        capabilities,
        capabilitySet: new Set(capabilities),
        autonomousLocalTools: new Set(autonomousLocalTools),
        allowed: new Set(stringArray(toolPolicy.allowedTools)),
        denied: new Set(stringArray(toolPolicy.deniedTools)),
        approvalRequired: new Set(stringArray(toolPolicy.approvalRequiredTools)),
      }] as const;
    }));
    // This is an Autonomous readiness projection, not a raw MCP catalogue.
    // Omit every capability that would need a mid-run approval (and every
    // capability outside the assigned specialist's explicit allowlist).
    const tools = projectedTools.flatMap((tool) => {
      const capabilities = tool.capabilities.filter((capability) =>
        tool.assignedAgentIds.some((agentId) => {
          const boundary = toolBoundaryByAgent.get(agentId);
          return Boolean(
            boundary
            && boundary.capabilitySet.has(capability)
            && boundary.allowed.has(capability)
            && !boundary.denied.has(capability)
            && !boundary.approvalRequired.has(capability),
          );
        }));
      return capabilities.length > 0 ? [{ ...tool, capabilities }] : [];
    });
    const runnableTools = tools.filter((tool) =>
      tool.status === "healthy"
      && tool.enabled
      && tool.startPermitted);
    const candidates = agentRows.map((row) => {
      const providerPolicy = parseJsonObject(row.provider_policy_json);
      const toolPolicy = parseJsonObject(row.tool_policy_json);
      const boundary = toolBoundaryByAgent.get(row.id)!;
      const capabilities = boundary.capabilities;
      const deniedTools = stringArray(toolPolicy.deniedTools);
      const boundServers = runnableTools.filter((server) => server.assignedAgentIds.includes(row.id));
      const executableTools = [...new Set([
        ...boundServers.flatMap((server) => server.capabilities),
        ...boundary.autonomousLocalTools,
      ].filter((tool) =>
          boundary.capabilitySet.has(tool)
          && boundary.allowed.has(tool)
          && !boundary.denied.has(tool)
          && !boundary.approvalRequired.has(tool)))].sort();
      const incompatibilityReasons: string[] = [];
      if (row.status !== "available") {
        incompatibilityReasons.push(`Specialist status is ${row.status}; a fresh callable route is required.`);
      }
      if (needsTools && executableTools.length === 0) {
        incompatibilityReasons.push("No approval-free reviewed local-process or MCP tool binding is available for this tool-requiring contract.");
      }
      return {
        id: row.id,
        displayName: row.display_name,
        role: row.role,
        status: row.status,
        capabilities,
        runnableTools: executableTools,
        mcpServerIds: boundServers.map((server) => server.id),
        providerPolicy: {
          ...(typeof providerPolicy.defaultProvider === "string" && providerPolicy.defaultProvider.trim()
            ? { defaultProvider: providerPolicy.defaultProvider.trim() }
            : {}),
        },
        toolPolicy: {
          allowedTools: stringArray(toolPolicy.allowedTools),
          deniedTools,
          approvalRequiredTools: stringArray(toolPolicy.approvalRequiredTools),
        },
        compatible: incompatibilityReasons.length === 0,
        incompatibilityReasons,
        ...(row.last_heartbeat_at ? { lastHeartbeatAt: row.last_heartbeat_at } : {}),
      };
    });
    const candidateById = new Map(candidates.map((candidate) => [candidate.id, candidate]));
    const selectedAgentIds = [...new Set(request.contract.specialistAgentIds)];
    const invalidSelectedAgentIds = selectedAgentIds.filter((agentId) =>
      candidateById.get(agentId)?.compatible !== true);
    const recommendedAgentIds = candidates.filter((candidate) => candidate.compatible)
      .map((candidate) => candidate.id);
    const effectiveAgentIds = selectedAgentIds.filter((agentId) => !invalidSelectedAgentIds.includes(agentId));
    return {
      providers,
      tools,
      team: {
        candidates,
        selectedAgentIds,
        invalidSelectedAgentIds,
        recommendedAgentIds,
        effectiveAgentIds,
        modelAssignments: [],
      },
    };
  }

  getIdempotentCreate(
    idempotencyKey: string,
    requestHash: string,
  ): CreatedMission | undefined {
    const row = this.database
      .prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(idempotencySettingKey(idempotencyKey)) as IdempotencyRow | undefined;
    if (!row) return undefined;
    const stored = parseStoredIdempotency(row.value_json);
    if (stored.requestHash !== requestHash) throw new IdempotencyConflictError();
    return stored.response;
  }

  /**
   * Records a fail-closed intake attempt after its provisional mission
   * transaction has rolled back. The request hash is the only resource
   * identifier retained; objective text, targets, and raw memory queries are
   * deliberately excluded.
   */
  recordIntakeContextBlocked(input: {
    readonly requestHash: string;
    readonly journey: Journey;
    readonly actorId: string;
    readonly code: string;
    readonly explanation: string;
  }): string {
    return inImmediateTransaction(this.database, () => {
      const now = this.clock().toISOString();
      const auditId = id("audit-intake-blocked");
      const details = {
        hook: "intake",
        status: "blocked",
        contextPackId: null,
        memoryInfluencedDefaults: false,
        code: input.code.slice(0, 128),
        explanation: input.explanation.slice(0, 512),
      };
      const previous = this.database
        .prepare("SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1")
        .get() as { record_hash: string } | undefined;
      const reason = "Mission launch failed closed before a run was committed because signed Second Brain context was unavailable";
      const recordHash = hashCanonical({
        id: auditId,
        previousHash: previous?.record_hash ?? null,
        journey: input.journey,
        actor: input.actorId,
        action: "mission.intake_context.blocked",
        resourceId: input.requestHash,
        reason,
        details,
        occurredAt: now,
      });
      this.database.prepare(`
        INSERT INTO audit_records (
          id, journey, actor_type, actor_id, action, resource_type,
          resource_id, reason, details_json, previous_hash, record_hash,
          occurred_at
        ) VALUES (?, ?, 'operator', ?, 'mission.intake_context.blocked',
          'mission_intake_request', ?, ?, ?, ?, ?, ?)
      `).run(
        auditId,
        input.journey,
        input.actorId,
        input.requestHash,
        reason,
        json(details),
        previous?.record_hash ?? null,
        recordHash,
        now,
      );
      return auditId;
    });
  }

  recordCanonicalGraphDeferred(input: {
    readonly missionId: string;
    readonly runId: string;
  }): string {
    return inImmediateTransaction(this.database, () => new AuditTrailWriter(this.database).append({
      missionId: input.missionId,
      runId: input.runId,
      actor: { type: "system", id: "system:canonical-memory-reconciliation" },
      action: "memory.canonical_graph_reconciliation_deferred",
      resourceType: "memory_graph",
      resourceId: input.missionId,
      reason: "The committed idempotent mission replay remained valid while canonical graph repair was deferred for explicit reconciliation.",
      details: { retrySafe: true, mutationCommittedPreviously: true },
      occurredAt: this.clock().toISOString(),
    }));
  }

  create(options: CreateMissionOptions): CreatedMission {
    return inImmediateTransaction(this.database, () => {
      const replay = this.getIdempotentCreate(options.idempotencyKey, options.requestHash);
      if (replay) return replay;

      const now = this.clock().toISOString();
      const missionId = id("mission");
      const runId = id("run");
      const { request } = options;
      const autonomous = request.journey === "autonomous";
      const engagementId = autonomous
        ? request.authorization.engagementId
        : request.engagementId;
      const scope = autonomous
        ? {
            allowedTargets: request.authorization.allowedTargets,
            prohibitedTargets: request.authorization.prohibitedTargets,
            ...(request.authorization.environmentClassification ? {
              environmentClassification: request.authorization.environmentClassification,
            } : {}),
            timeWindow: request.authorization.timeWindow ?? null,
            dataHandling: request.authorization.dataHandling ?? null,
          }
        : { target: request.target ?? null };
      const memoryPolicy = autonomous
        ? {
            allowedScopes: request.contract.memoryScopes,
            exactContextNodeIds: request.contract.contextNodeIds,
          }
        : { preferenceUse: "confirmed_or_consent_governed" };
      const retentionPolicy = autonomous
        ? {
            mode: request.contract.retentionPolicy,
            dataHandling: request.contract.dataHandlingPolicy,
          }
        : {};

      this.database
        .prepare(`
          INSERT INTO missions (
            id, name, objective, journey, status, authorization_status,
            engagement_id, scope_json, success_criteria_json,
            retention_policy_json, memory_policy_json, created_by,
            version, created_at, updated_at
          ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        `)
        .run(
          missionId,
          request.title,
          request.objective,
          request.journey,
          "verified",
          engagementId ?? null,
          json(scope),
          json(autonomous ? request.successCriteria : []),
          json(retentionPolicy),
          json(memoryPolicy),
          options.actorId,
          now,
          now,
        );

      const insertTarget = this.database.prepare(`
        INSERT INTO mission_targets (
          id, mission_id, target, target_type, disposition,
          normalized_target, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, '{}', ?)
      `);
      if (autonomous) {
        for (const target of request.authorization.allowedTargets) {
          insertTarget.run(
            id("target"),
            missionId,
            target,
            targetType(target),
            "allowed",
            normalizeTarget(target),
            now,
          );
        }
        for (const target of request.authorization.prohibitedTargets) {
          insertTarget.run(
            id("target"),
            missionId,
            target,
            targetType(target),
            "prohibited",
            normalizeTarget(target),
            now,
          );
        }
      } else if (request.target) {
        insertTarget.run(
          id("target"),
          missionId,
          request.target,
          targetType(request.target),
          "allowed",
          normalizeTarget(request.target),
          now,
        );
      }

      const intakeContext = options.resolveIntakeContext?.({
        missionId,
        journey: request.journey,
        memoryPolicy,
      });
      const intakeContextEvent = intakeContext
        ? {
            hook: intakeContext.hook,
            contextPackId: intakeContext.contextPackId,
            auditRecordId: intakeContext.auditRecordId,
            status: intakeContext.status,
            retrievedCount: intakeContext.retrievedCount,
            memoryInfluencedDefaults: intakeContext.memoryInfluencedDefaults,
            ...(intakeContext.safeOptionalDefaults
              ? { safeOptionalDefaults: intakeContext.safeOptionalDefaults }
              : {}),
            ...(intakeContext.influenceExplanation
              ? { influenceExplanation: intakeContext.influenceExplanation }
              : {}),
            ...(intakeContext.degradation
              ? { degradation: { ...intakeContext.degradation } }
              : {}),
          }
        : undefined;
      if (intakeContext) {
        this.database.prepare(`
          UPDATE missions SET memory_policy_json = ? WHERE id = ?
        `).run(json({ ...memoryPolicy, intakeContext }), missionId);
      }

      const insertConstraint = this.database.prepare(`
        INSERT INTO mission_constraints (
          id, mission_id, constraint_type, value_json, source, created_at
        ) VALUES (?, ?, ?, ?, 'operator', ?)
      `);
      if (autonomous) {
        insertConstraint.run(
          id("constraint"),
          missionId,
          "authorization",
          json(request.authorization),
          now,
        );
        insertConstraint.run(
          id("constraint"),
          missionId,
          "action_policy",
          json({
            allowedActionClasses: request.contract.allowedActionClasses,
            prohibitedActionClasses: request.contract.prohibitedActionClasses,
            destructivePolicy: request.contract.destructivePolicy,
            boundedDestructiveTargets: request.contract.boundedDestructiveTargets ?? [],
            specialistAgentIds: request.contract.specialistAgentIds,
            planningSelection: resolveAutonomousPlanningSelection(
              request.contract.planningSelection,
            ),
            agentModelAssignments: request.contract.agentModelAssignments,
          }),
          now,
        );
        insertConstraint.run(
          id("constraint"),
          missionId,
          "evidence_requirements",
          json(request.contract.evidenceRequirements),
          now,
        );
        insertConstraint.run(
          id("constraint"),
          missionId,
          "data_retention",
          json({
            dataHandlingPolicy: request.contract.dataHandlingPolicy,
            retentionPolicy: request.contract.retentionPolicy,
            operatorConstraints: request.authorization.dataHandling ?? null,
          }),
          now,
        );
        insertConstraint.run(
          id("constraint"),
          missionId,
          "delivery_policy",
          json({
            notificationPolicy: request.contract.notificationPolicy,
            reportingFormat: request.contract.reportingFormat,
            providerPolicy: request.contract.providerPolicy,
            toolPolicy: request.contract.toolPolicy,
          }),
          now,
        );
      } else {
        insertConstraint.run(
          id("constraint"),
          missionId,
          "guided_collaboration",
          json({
            explanationDepth: request.explanationDepth,
            executionPreference: request.executionPreference,
            evidenceExpectations: request.evidenceExpectations,
            ...(request.guidedReconnaissance === undefined
              ? {}
              : { guidedReconnaissance: request.guidedReconnaissance }),
            ...(request.guidedWindowsIdentity === undefined
              ? {}
              : { guidedWindowsIdentity: request.guidedWindowsIdentity }),
          }),
          now,
        );
      }

      let contractId: string | null = null;
      let contractHash: string | null = null;
      const budget = autonomous
        ? {
            timeBudgetMinutes: request.contract.timeBudgetMinutes,
            ...(request.contract.toolCallBudget === undefined
              ? {}
              : { toolCalls: request.contract.toolCallBudget }),
            tokenBudget: request.contract.tokenBudget ?? null,
            costBudget: request.contract.costBudget ?? null,
            retryBudget: request.contract.retryBudget,
            replanBudget: request.contract.replanBudget,
            concurrencyLimit: request.contract.concurrencyLimit,
            evidenceBytes: request.contract.evidenceStorageBudgetBytes,
            artifactBytes: request.contract.artifactStorageBudgetBytes,
          }
        : {};
      if (autonomous) {
        contractId = id("contract");
        contractHash = autonomousContractHash(request);
        this.database
          .prepare(`
            INSERT INTO mission_contracts (
              id, mission_id, version, state, contract_hash,
              authorization_json, action_policy_json, budgets_json,
              safe_stop_json, deliverables_json, memory_scopes_json,
              confirmed_by, confirmed_at, created_at
            ) VALUES (?, ?, 1, 'confirmed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
          .run(
            contractId,
            missionId,
            contractHash,
            json(request.authorization),
            json({
              allowedActionClasses: request.contract.allowedActionClasses,
              prohibitedActionClasses: request.contract.prohibitedActionClasses,
              destructivePolicy: request.contract.destructivePolicy,
              boundedDestructiveTargets: request.contract.boundedDestructiveTargets ?? [],
              evidenceRequirements: request.contract.evidenceRequirements,
              notificationPolicy: request.contract.notificationPolicy,
              reportingFormat: request.contract.reportingFormat,
              dataHandlingPolicy: request.contract.dataHandlingPolicy,
              retentionPolicy: request.contract.retentionPolicy,
              providerPolicy: request.contract.providerPolicy,
              toolPolicy: request.contract.toolPolicy,
              specialistAgentIds: request.contract.specialistAgentIds,
              planningSelection: resolveAutonomousPlanningSelection(
                request.contract.planningSelection,
              ),
              agentModelAssignments: request.contract.agentModelAssignments,
              contextNodeIds: request.contract.contextNodeIds,
            }),
            json(budget),
            json({ conditions: request.contract.safeStopConditions }),
            json(request.contract.deliverables),
            json(request.contract.memoryScopes),
            options.actorId,
            now,
            now,
          );
      }

      const nextAction = autonomous
        ? "Build and version the first in-contract plan"
        : "Explain the assessment path and recommend the first bounded step";
      this.database
        .prepare(`
          INSERT INTO runs (
            id, mission_id, journey, status, contract_id,
            contract_version_bound, contract_hash_bound,
            progress, status_reason, next_action_summary,
            budget_json, budget_usage_json, started_at,
            created_at, updated_at, version
          ) VALUES (?, ?, ?, 'planning', ?, ?, ?, 0, ?, ?, ?, '{}', ?, ?, ?, 1)
        `)
        .run(
          runId,
          missionId,
          request.journey,
          contractId,
          autonomous ? 1 : null,
          autonomous ? contractHash : null,
          autonomous
            ? "Autonomous contract confirmed; durable planning may proceed without routine input."
            : "Guided mission created; an explained first step must precede any consequential action.",
          nextAction,
          json(budget),
          now,
          now,
          now,
        );

      const pinnedModelAssignmentIds = options.pinModelAssignments?.({
        missionId,
        runId,
        journey: request.journey,
        specialistAgentIds: autonomous
          ? request.contract.specialistAgentIds
          : [],
        planningSelection: autonomous
          ? resolveAutonomousPlanningSelection(request.contract.planningSelection)
          : resolveAutonomousPlanningSelection(undefined),
        agentModelAssignments: autonomous
          ? request.contract.agentModelAssignments
          : [],
        allowedActionClasses: autonomous
          ? request.contract.allowedActionClasses
          : [],
      }) ?? [];

      options.materializeCanonicalGraph?.({ missionId, runId });

      this.events.append({
        missionId,
        runId,
        journey: request.journey,
        eventType: "mission.created",
        actorType: "operator",
        actorId: options.actorId,
        summary: `${autonomous ? "Autonomous" : "Guided"} mission created as a durable objective`,
        ...(intakeContext ? { contextPackId: intakeContext.contextPackId } : {}),
        payload: {
          missionId,
          runId,
          journey: request.journey,
          authorizationStatus: "verified",
          pinnedModelAssignmentIds: [...pinnedModelAssignmentIds],
          ...(intakeContextEvent ? { intakeContext: intakeContextEvent } : {}),
        },
      });
      this.events.append({
        missionId,
        runId,
        journey: request.journey,
        eventType: autonomous ? "run.autonomous_planning_started" : "run.guided_planning_started",
        actorType: "system",
        summary: autonomous
          ? "Autonomous planning started under the confirmed mission contract"
          : "Guided planning started and must produce an explained operator decision",
        payload: {
          status: "planning",
          nextAction,
          ...(contractHash ? { contractHash } : {}),
          ...(intakeContext
            ? {
                intakeContextStatus: intakeContext.status,
                intakeContextPackId: intakeContext.contextPackId,
                memoryInfluencedDefaults: intakeContext.memoryInfluencedDefaults,
                ...(intakeContext.safeOptionalDefaults
                  ? { safeOptionalDefaults: intakeContext.safeOptionalDefaults }
                  : {}),
                ...(intakeContext.influenceExplanation
                  ? { influenceExplanation: intakeContext.influenceExplanation }
                  : {}),
              }
            : {}),
        },
      });

      const response: CreatedMission = {
        mission: {
          id: missionId,
          title: request.title,
          journey: request.journey,
          status: "active",
          version: 1,
          createdAt: now,
          updatedAt: now,
        },
        run: { id: runId, status: "planning", journey: request.journey },
        ...(intakeContext ? { intakeContext } : {}),
        nextUrl: autonomous ? `/missions/${missionId}` : `/guided/${missionId}`,
      };

      const auditDetails = {
        journey: request.journey,
        runId,
        contractHash,
        idempotentMutation: true,
        pinnedModelAssignmentIds: [...pinnedModelAssignmentIds],
        intakeContext: intakeContext ?? null,
      };
      const previous = this.database
        .prepare("SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1")
        .get() as { record_hash: string } | undefined;
      const auditId = id("audit");
      const auditHash = hashCanonical({
        id: auditId,
        previousHash: previous?.record_hash ?? null,
        journey: request.journey,
        actor: options.actorId,
        action: "mission.created",
        resourceId: missionId,
        details: auditDetails,
        occurredAt: now,
      });
      this.database
        .prepare(`
          INSERT INTO audit_records (
            id, mission_id, run_id, journey, actor_type, actor_id, action,
            resource_type, resource_id, reason, details_json,
            previous_hash, record_hash, occurred_at
          ) VALUES (?, ?, ?, ?, 'operator', ?, 'mission.created', 'mission', ?, ?, ?, ?, ?, ?)
        `)
        .run(
          auditId,
          missionId,
          runId,
          request.journey,
          options.actorId,
          missionId,
          autonomous ? "Confirmed Autonomous contract" : "Created Guided mission",
          json(auditDetails),
          previous?.record_hash ?? null,
          auditHash,
          now,
        );

      this.database
        .prepare(`
          INSERT INTO settings (
            key, value_json, sensitivity, version, updated_by, updated_at
          ) VALUES (?, ?, 'private', 1, ?, ?)
        `)
        .run(
          idempotencySettingKey(options.idempotencyKey),
          json({ requestHash: options.requestHash, response }),
          options.actorId,
          now,
        );

      return response;
    });
  }

  list(options: ListMissionsOptions = {}): MissionListPage {
    const limit = options.limit ?? 50;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new RangeError("limit must be an integer between 1 and 100");
    }
    const filterHash = portfolioFilterHash(options);
    const cursorSecret = this.cursorSecret();
    const cursor = decodeCursor(options.cursor, filterHash, cursorSecret);
    const normalizedQuery = options.query?.trim();
    // Archived missions stay out of ordinary portfolio browsing and text
    // discovery, but a caller holding the canonical stable ID must be able to
    // reconcile an imported/archive deep link. Every other supplied filter is
    // still applied below, so the ID escape hatch does not bypass journey,
    // engagement, date, or other portfolio boundaries.
    const where: string[] = normalizedQuery
      ? ["(m.status != 'archived' OR m.id = ?)"]
      : ["m.status != 'archived'"];
    const parameters: unknown[] = [];
    if (normalizedQuery) parameters.push(normalizedQuery);
    if (cursor) {
      where.push("(m.updated_at < ? OR (m.updated_at = ? AND m.id < ?))");
      parameters.push(cursor.updatedAt, cursor.updatedAt, cursor.id);
    }
    if (options.journey) {
      where.push("m.journey = ?");
      parameters.push(options.journey);
    }
    if (options.status) {
      where.push("COALESCE(r.status, m.status) = ?");
      parameters.push(options.status);
    }
    if (normalizedQuery) {
      where.push(`instr(lower(
        m.id || ' ' || m.name || ' ' || m.objective || ' ' || m.journey || ' ' ||
        COALESCE(r.id, '') || ' ' || COALESCE(r.status, '') || ' ' ||
        COALESCE(ps.phase, '') || ' ' || COALESCE(r.next_action_summary, '')
      ), lower(?)) > 0`);
      parameters.push(normalizedQuery);
    }
    if (options.engagement) {
      where.push("lower(COALESCE(m.engagement_id, '')) = lower(?)");
      parameters.push(options.engagement);
    }
    if (options.target) {
      where.push(`EXISTS (
        SELECT 1 FROM mission_targets target_filter
        WHERE target_filter.mission_id = m.id AND instr(lower(
          target_filter.target || ' ' || target_filter.normalized_target
        ), lower(?)) > 0
      )`);
      parameters.push(options.target);
    }
    if (options.agent) {
      where.push(`(
        lower(COALESCE(r.current_owner_id, '')) = lower(?) OR EXISTS (
          SELECT 1 FROM assignments assignment_filter
          WHERE assignment_filter.run_id = r.id AND lower(assignment_filter.agent_id) = lower(?)
        )
      )`);
      parameters.push(options.agent, options.agent);
    }
    if (options.provider) {
      where.push(`EXISTS (
        SELECT 1 FROM provider_turns provider_filter
        WHERE provider_filter.run_id = r.id AND lower(provider_filter.provider) = lower(?)
      )`);
      parameters.push(options.provider);
    }
    if (options.updatedFrom) {
      where.push("m.updated_at >= ?");
      parameters.push(options.updatedFrom);
    }
    if (options.updatedTo) {
      where.push("m.updated_at <= ?");
      parameters.push(options.updatedTo);
    }
    if (options.risk) {
      where.push("lower(COALESCE(ps.risk_class, '')) = lower(?)");
      parameters.push(options.risk);
    }
    if (options.evidence === "present") {
      where.push("EXISTS (SELECT 1 FROM evidence evidence_filter WHERE evidence_filter.mission_id = m.id)");
    } else if (options.evidence === "none") {
      where.push("NOT EXISTS (SELECT 1 FROM evidence evidence_filter WHERE evidence_filter.mission_id = m.id)");
    }
    if (options.findingSeverity) {
      where.push(`EXISTS (
        SELECT 1 FROM findings finding_filter
        WHERE finding_filter.mission_id = m.id AND finding_filter.severity = ?
      )`);
      parameters.push(options.findingSeverity);
    }
    if (options.decisionState) {
      where.push(`EXISTS (
        SELECT 1 FROM guided_decisions decision_filter
        WHERE decision_filter.run_id = r.id AND decision_filter.status = ?
      )`);
      parameters.push(options.decisionState);
    }
    if (options.recoveryState === "recovering" || options.recoveryState === "blocked") {
      where.push("r.status = ?");
      parameters.push(options.recoveryState);
    } else if (options.recoveryState === "none") {
      where.push("COALESCE(r.status, '') NOT IN ('recovering', 'blocked')");
    }
    parameters.push(limit + 1);
    const rows = this.database
      .prepare(`${SUMMARY_SELECT} WHERE ${where.join(" AND ")} ORDER BY m.updated_at DESC, m.id DESC LIMIT ?`)
      .all(...parameters) as MissionSummaryRow[];
    const hasMore = rows.length > limit;
    const visible = rows.slice(0, limit);
    return {
      schemaVersion: "2.4",
      items: visible.map(mapSummary),
      nextCursor: hasMore && visible.length > 0
        ? encodeCursor(visible[visible.length - 1]!, filterHash, cursorSecret)
        : null,
    };
  }

  listRecent(limit = 12): MissionSummary[] {
    return [...this.list({ limit }).items];
  }
}

import { createHash, randomUUID } from "node:crypto";
import {
  resolveAutonomousRunMemoryPolicy,
  retrieveMissionBrainContext,
  type BrainContextResult,
  type BrainContextService,
} from "../brain-runtime";
import type { ControlPlaneLease } from "../control-plane";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  activeConnectedVaultBackedMemoryNodeIds,
  activeConnectedVaultBackedNodeIds,
  autonomousInfluenceRejection,
  isAttackCentricReusableNodeType,
} from "../memory";
import {
  AUTONOMOUS_PRIVILEGE_SUCCESS_CRITERION,
  AUTONOMOUS_ROOT_ACCESS_PROOF_SUCCESS_CRITERION,
  AUTONOMOUS_SESSION_CLEANUP_SUCCESS_CRITERION,
} from "../domain/autonomous-outcome-registry";
import { digestCanonicalJson } from "../mcp";
import {
  ActionRepository,
  ExecutionBoundaryError,
  type DurableAction,
} from "../orchestration";
import {
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_CLASS,
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
  AUTONOMOUS_LINUX_ROOT_FLAG_PATH,
  AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_CLASS,
  AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
  AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_CLASS,
  AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
  CandidateLinuxPrivilegeContinuationError,
  type AutonomousLinuxPrivilegeActionArguments,
  type AutonomousLinuxPrivilegeContinuationActionType,
  type CandidateLinuxPrivilegeContinuationAdapterPort,
  type CandidateLinuxPrivilegeSessionBinding,
  type IndependentRootIdentityObservation,
  type LoopbackLinuxCleanupAck,
  type LoopbackLinuxPrivilegeAck,
  type RootFlagHashProof,
  parseAutonomousLinuxPrivilegeActionArguments,
} from "./CandidateLinuxPrivilegeContinuation";
import {
  AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
  autonomousSuccessCriterionId,
} from "./LocalVerifiedEvidenceOutcomeEvaluator";

export const AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION =
  "ti-scale.autonomous-linux-privilege-runtime-result.v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const DEFAULT_LEASE_MS = 30_000;
const MAX_LEASE_MS = 120_000;

interface CanonicalSessionRow {
  readonly session_id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly plan_id: string;
  readonly post_exploit_spec_id: string;
  readonly origin_attack_attempt_id: string;
  readonly target_node_id: string;
  readonly script_artifact_id: string;
  readonly exploit_outcome_evidence_id: string;
  readonly exact_target: string;
  readonly candidate_binding_hash: string;
  readonly session_status: string;
  readonly access_level: string;
  readonly session_version: number;
  readonly transport_type:
    | "loopback_http_session_v1"
    | "candidate_runtime_session_v1";
  readonly transport_binding_id: string;
  readonly transport_origin: string | null;
  readonly privilege_path: CandidateLinuxPrivilegeSessionBinding["privilegePath"];
  readonly root_identity_path: CandidateLinuxPrivilegeSessionBinding["rootIdentityPath"];
  readonly root_flag_proof_path: CandidateLinuxPrivilegeSessionBinding["rootFlagProofPath"];
  readonly cleanup_path: CandidateLinuxPrivilegeSessionBinding["cleanupPath"];
  readonly declared_root_flag_path: string;
  readonly spec_status: string;
  readonly attack_status: string;
  readonly evidence_verification_state: string;
  readonly journey: string;
  readonly run_control_plane: string;
  readonly run_status: string;
  readonly current_plan_id: string | null;
  readonly mission_control_plane: string;
  readonly authorization_status: string;
  readonly step_plan_id: string;
  readonly assigned_agent_id: string | null;
  readonly memory_policy_json: string;
  readonly outcome_linked: number;
  readonly root_identity_count: number;
}

interface ActiveLeaseRow {
  readonly id: string;
  readonly session_artifact_id: string;
  readonly lease_owner: string;
  readonly lease_token_hash: string;
  readonly fencing_token: number;
  readonly acquired_at: string;
  readonly heartbeat_at: string;
  readonly expires_at: string;
  readonly released_at: string | null;
}

interface AcquiredLease {
  readonly id: string;
  readonly owner: string;
  readonly rawToken: string;
  readonly tokenHash: string;
  readonly fencingToken: number;
  readonly expiresAt: string;
  /** Latest durable SessionArtifact version fenced immediately before dispatch. */
  readonly sessionVersion: number;
  readonly binding: CandidateLinuxPrivilegeSessionBinding;
}

export interface CandidateLinuxPrivilegeBrainReceipt {
  readonly contextPackId: string;
  readonly auditRecordId: string;
  readonly usedNodeIds: readonly string[];
}

export interface CandidateLinuxPrivilegeBrainPort {
  beforeAction(
    action: DurableAction,
    stage: "privilege_escalation" | "root_flag_proof" | "cleanup",
  ): CandidateLinuxPrivilegeBrainReceipt;
  assertAvailable(receipt: CandidateLinuxPrivilegeBrainReceipt): void;
}

export interface CandidateLinuxPrivilegeRuntimeResult {
  readonly schemaVersion:
    typeof AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION;
  readonly actionId: string;
  readonly actionType: AutonomousLinuxPrivilegeContinuationActionType;
  readonly sessionArtifactId: string;
  readonly contextPackId: string;
  readonly evidenceIds: readonly string[];
  readonly privilegeReceiptSha256?: string;
  readonly rootIdentityObservationSha256?: string;
  readonly rootFlagProofSha256?: string;
  readonly rootFlagContentSha256?: string;
  readonly cleanupReceiptSha256?: string;
  readonly cleanupCompleted: boolean;
  readonly summary: string;
  readonly resultSha256: string;
}

function hash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function clean(value: string, maximum = 500): string {
  return value.replace(/[\u0000-\u001F\u007F]/gu, " ")
    .trim().replace(/\s+/gu, " ").slice(0, maximum);
}

function canonicalActionType(
  value: string,
): AutonomousLinuxPrivilegeContinuationActionType | undefined {
  return [
    AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
    AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
    AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
  ].includes(value as AutonomousLinuxPrivilegeContinuationActionType)
    ? value as AutonomousLinuxPrivilegeContinuationActionType
    : undefined;
}

function expectedActionClass(
  actionType: AutonomousLinuxPrivilegeContinuationActionType,
): string {
  if (actionType === AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE) {
    return AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_CLASS;
  }
  if (actionType === AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE) {
    return AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_CLASS;
  }
  return AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_CLASS;
}

function expectedIdempotency(
  actionType: AutonomousLinuxPrivilegeContinuationActionType,
): boolean {
  return actionType !== AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE;
}

function stage(
  actionType: AutonomousLinuxPrivilegeContinuationActionType,
): "privilege_escalation" | "root_flag_proof" | "cleanup" {
  if (actionType === AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE) {
    return "privilege_escalation";
  }
  if (actionType === AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE) {
    return "root_flag_proof";
  }
  return "cleanup";
}

function materialResult(
  input: Omit<CandidateLinuxPrivilegeRuntimeResult, "resultSha256">,
): CandidateLinuxPrivilegeRuntimeResult {
  const resultSha256 = digestCanonicalJson(
    input,
    { maxBytes: 128 * 1_024, maxDepth: 16 },
  ).sha256;
  return Object.freeze({ ...input, resultSha256 });
}

/**
 * Advance one exact active user SessionArtifact through an optimistic CAS.
 *
 * Bun's sqlite Statement.run().changes is cumulative across earlier writes in
 * the surrounding transaction. Read SQLite's changes() immediately after the
 * UPDATE instead, then verify the exact durable postcondition. A stale version
 * therefore remains rejected even when evidence rows were inserted first.
 */
export function advanceCandidateSessionToPrivileged(input: Readonly<{
  database: SqliteDatabase;
  sessionArtifactId: string;
  expectedVersion: number;
  updatedAt: string;
}>): void {
  if (!Number.isSafeInteger(input.expectedVersion) || input.expectedVersion < 1) {
    throw new TypeError("Candidate session expected version is invalid");
  }
  input.database.prepare(`
    UPDATE session_artifacts
    SET status = 'privileged', access_level = 'root',
      updated_at = ?, version = version + 1
    WHERE id = ? AND status = 'active' AND access_level = 'user'
      AND version = ?
  `).run(
    input.updatedAt,
    input.sessionArtifactId,
    input.expectedVersion,
  );
  const direct = input.database.prepare(
    "SELECT changes() AS changed",
  ).get() as { readonly changed: number };
  const observed = input.database.prepare(`
    SELECT version, status, access_level
    FROM session_artifacts WHERE id = ?
  `).get(input.sessionArtifactId) as {
    readonly version: number;
    readonly status: string;
    readonly access_level: string;
  } | undefined;
  if (
    Number(direct.changed) !== 1
    || !observed
    || observed.version !== input.expectedVersion + 1
    || observed.status !== "privileged"
    || observed.access_level !== "root"
  ) {
    throw new ExecutionBoundaryError(
      "autonomous_linux_root_identity_state_conflict",
      "worker_lost",
      "The candidate session changed before the independent root proof committed.",
    );
  }
}

function sessionRow(
  database: SqliteDatabase,
  sessionArtifactId: string,
): CanonicalSessionRow | undefined {
  return database.prepare(`
    SELECT session.id AS session_id, session.mission_id, session.run_id,
      session.plan_id, session.post_exploit_spec_id,
      session.origin_attack_attempt_id, session.target_node_id,
      session.script_artifact_id, session.exploit_outcome_evidence_id,
      session.exact_target, session.candidate_binding_hash,
      session.status AS session_status, session.access_level,
      session.version AS session_version,
      spec.transport_type, spec.transport_binding_id, spec.transport_origin,
      spec.privilege_path, spec.root_identity_path,
      spec.root_flag_proof_path, spec.cleanup_path,
      spec.declared_root_flag_path, spec.status AS spec_status,
      attempt.status AS attack_status,
      proof.verification_state AS evidence_verification_state,
      run.journey, run.control_plane AS run_control_plane,
      run.status AS run_status, run.current_plan_id,
      mission.control_plane AS mission_control_plane,
      mission.authorization_status,
      step.plan_id AS step_plan_id, step.assigned_agent_id,
      mission.memory_policy_json,
      EXISTS (
        SELECT 1 FROM attack_attempt_evidence link
        WHERE link.attack_attempt_id = session.origin_attack_attempt_id
          AND link.evidence_id = session.exploit_outcome_evidence_id
          AND link.relationship = 'outcome'
      ) AS outcome_linked,
      (
        SELECT COUNT(*) FROM session_identity_observations identity
        WHERE identity.session_artifact_id = session.id
          AND identity.observer_kind = 'root_identity'
          AND identity.principal = 'root' AND identity.uid = 0
      ) AS root_identity_count
    FROM session_artifacts session
    JOIN candidate_linux_post_exploit_specs spec
      ON spec.id = session.post_exploit_spec_id
    JOIN attack_attempts attempt
      ON attempt.id = session.origin_attack_attempt_id
    JOIN evidence proof
      ON proof.id = session.exploit_outcome_evidence_id
    JOIN runs run ON run.id = session.run_id
    JOIN missions mission ON mission.id = session.mission_id
    JOIN plan_steps step ON step.id = session.step_id
    WHERE session.id = ?
  `).get(sessionArtifactId) as CanonicalSessionRow | undefined;
}

/**
 * Canonical Brain bridge for candidate-bound post-exploit work. Retrieved
 * memory remains data: it may reinforce the fixed candidate, hazard, and
 * cleanup posture but cannot add commands, paths, targets, or permissions.
 */
export class MissionBrainCandidateLinuxPrivilegeContext
implements CandidateLinuxPrivilegeBrainPort {
  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    brainContext: BrainContextService;
  }>) {}

  beforeAction(
    action: DurableAction,
    actionStage: "privilege_escalation" | "root_flag_proof" | "cleanup",
  ): CandidateLinuxPrivilegeBrainReceipt {
    const actionType = canonicalActionType(action.actionType);
    if (!actionType) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_privilege_brain_action_invalid",
        "policy_denied",
        "The represented Linux continuation action is not eligible for Brain context.",
      );
    }
    const args = parseAutonomousLinuxPrivilegeActionArguments(
      actionType,
      action.arguments,
    );
    const session = sessionRow(this.options.database, args.sessionArtifactId);
    if (
      !session
      || session.mission_id !== action.missionId
      || session.run_id !== action.runId
    ) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_privilege_brain_session_missing",
        "dependency_missing",
        "The exact candidate-bound session is unavailable for Brain context selection.",
      );
    }
    const row = this.options.database.prepare(`
      SELECT step.assigned_agent_id
      FROM actions action
      JOIN plan_steps step ON step.id = action.step_id
      WHERE action.id = ? AND action.mission_id = ? AND action.run_id = ?
    `).get(action.id, action.missionId, action.runId) as {
      readonly assigned_agent_id: string | null;
    } | undefined;
    if (!row) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_privilege_brain_scope_missing",
        "dependency_missing",
        "The canonical mission memory scope is unavailable for this post-exploit action.",
      );
    }
    const memoryPolicy = resolveAutonomousRunMemoryPolicy({
      database: this.options.database,
      missionId: action.missionId,
      runId: action.runId,
    });
    const result: BrainContextResult = retrieveMissionBrainContext({
      brainContext: this.options.brainContext,
      hook: "tool_selection",
      journey: "autonomous",
      missionId: action.missionId,
      runId: action.runId,
      stepId: action.stepId,
      actionId: action.id,
      actorId: row.assigned_agent_id ?? "autonomous-linux-post-exploit-specialist",
      actorType: "agent",
      query:
        `Select only confirmed memory relevant to the fixed candidate-bound ${actionStage} `
        + `operation for ${action.target}. Check known hazards, prerequisite failures, `
        + "recovery constraints, and cleanup guidance without proposing commands, paths, "
        + "targets, or broader authority.",
      queryRedacted:
        `Select confirmed candidate, hazard, recovery, and cleanup memory for the fixed ${actionStage} operation.`,
      memoryPolicy,
      maximumSensitivity: "private",
      contextBudget: 3_000,
      limit: 10,
      ...(actionStage === "cleanup" ? { terminalSafe: true } : {}),
    });
    const knowledge = this.options.database.prepare(`
      SELECT procedure_node_id, procedure_version_node_id,
        product_node_ids_json, version_node_ids_json, stack_node_ids_json,
        prerequisite_node_ids_json, observed_state_node_ids_json
      FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = ?
    `).get(session.origin_attack_attempt_id) as {
      readonly procedure_node_id: string;
      readonly procedure_version_node_id: string | null;
      readonly product_node_ids_json: string;
      readonly version_node_ids_json: string;
      readonly stack_node_ids_json: string;
      readonly prerequisite_node_ids_json: string;
      readonly observed_state_node_ids_json: string;
    } | undefined;
    const parseNodeIds = (value: string): readonly string[] => {
      try {
        const parsed = JSON.parse(value) as unknown;
        return Array.isArray(parsed)
          ? parsed.filter((item): item is string => typeof item === "string")
          : [];
      } catch {
        return [];
      }
    };
    const exactOriginNodeIds = new Set(knowledge
      ? [
          knowledge.procedure_node_id,
          ...(knowledge.procedure_version_node_id
            ? [knowledge.procedure_version_node_id]
            : []),
          ...parseNodeIds(knowledge.product_node_ids_json),
          ...parseNodeIds(knowledge.version_node_ids_json),
          ...parseNodeIds(knowledge.stack_node_ids_json),
          ...parseNodeIds(knowledge.prerequisite_node_ids_json),
          ...parseNodeIds(knowledge.observed_state_node_ids_json),
        ]
      : []);
    const activeVaultBacked = activeConnectedVaultBackedNodeIds(
      this.options.database,
      result.contextPack.id,
    );
    const currentOriginVaultBacked = activeConnectedVaultBackedMemoryNodeIds(
      this.options.database,
      [...exactOriginNodeIds],
    );
    const usedNodeIds = Object.freeze(
      result.items
        .filter(({ node }) =>
          exactOriginNodeIds.has(node.id)
          && activeVaultBacked.has(node.id)
          && isAttackCentricReusableNodeType(node.nodeType))
        .map(({ node }) => node.id),
    );
    if (usedNodeIds.length > 0) {
      this.options.brainContext.recordContextUse(
        result,
        usedNodeIds,
        "Confirmed, typed, active-Vault-backed origin-attempt memory was consulted while preserving the fixed candidate operation and exact scope.",
        "The retrieved item was not typed reusable attack knowledge that was both synchronized to the active connected Vault and bound to the exact origin AttackAttempt.",
      );
    } else {
      this.options.brainContext.recordUnusedContext(
        result,
        "No typed reusable origin-attempt memory synchronized to the active connected Vault was eligible; the operation retained its fixed candidate-bound conservative behavior.",
      );
    }
    if (
      exactOriginNodeIds.size === 0
      || currentOriginVaultBacked.size !== exactOriginNodeIds.size
      || usedNodeIds.length !== exactOriginNodeIds.size
    ) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_privilege_active_vault_memory_required",
        "dependency_missing",
        "The exact origin attack procedure, product, version, prerequisite, and observed-state memory must remain confirmed or verified and synchronized at its current version to the active health-verified Obsidian Vault before this continuation adapter may be contacted.",
      );
    }
    const receipt = Object.freeze({
      contextPackId: result.contextPack.id,
      auditRecordId: result.auditRecordId,
      usedNodeIds,
    });
    this.assertAvailable(receipt);
    return receipt;
  }

  assertAvailable(receipt: CandidateLinuxPrivilegeBrainReceipt): void {
    const availability = this.options.brainContext.readActiveVaultAvailability(
      receipt.usedNodeIds,
    );
    const persistedUsed = new Set((this.options.database.prepare(`
      SELECT node_id FROM memory_context_items
      WHERE context_pack_id = ? AND used = 1
    `).all(receipt.contextPackId) as Array<{ readonly node_id: string }>)
      .map(({ node_id }) => node_id));
    if (
      receipt.usedNodeIds.length === 0
      || !availability.available
      || receipt.usedNodeIds.some((nodeId) =>
        !persistedUsed.has(nodeId)
        || autonomousInfluenceRejection(
          this.options.database,
          receipt.contextPackId,
          nodeId,
        ) !== undefined)
    ) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_privilege_active_vault_memory_required",
        "dependency_missing",
        "The exact origin attack memory is no longer confirmed, current, and available from the active health-verified Obsidian Vault. Target execution stopped before the next adapter operation.",
      );
    }
  }
}

/**
 * Repository and executor for the privilege/root-proof/cleanup continuation.
 * Every network operation owns one fresh fenced session lease. No lease token,
 * target data, flag content, shell text, or arbitrary command is retained.
 */
export class CandidateLinuxPrivilegeContinuationRuntime {
  readonly #actions: ActionRepository;
  readonly #now: () => Date;
  readonly #leaseMs: number;

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    adapter: CandidateLinuxPrivilegeContinuationAdapterPort;
    brain: CandidateLinuxPrivilegeBrainPort;
    assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
    leaseOwner: string;
    leaseMs?: number;
    randomToken?: () => string;
    now?: () => Date;
  }>) {
    if (!options.leaseOwner.trim()
      || options.leaseOwner.length > 255
      || /[\u0000-\u001F\u007F]/u.test(options.leaseOwner)) {
      throw new TypeError("Candidate Linux session lease owner is invalid");
    }
    this.#leaseMs = options.leaseMs ?? DEFAULT_LEASE_MS;
    if (!Number.isSafeInteger(this.#leaseMs)
      || this.#leaseMs < 1_000
      || this.#leaseMs > MAX_LEASE_MS) {
      throw new RangeError("Candidate Linux session lease duration is outside its reviewed bound");
    }
    this.#actions = new ActionRepository(options.database);
    this.#now = options.now ?? (() => new Date());
  }

  private canonical(input: DurableAction): Readonly<{
    action: DurableAction;
    actionType: AutonomousLinuxPrivilegeContinuationActionType;
    arguments: AutonomousLinuxPrivilegeActionArguments;
  }> {
    const action = this.#actions.get(input.id);
    const actionType = canonicalActionType(action.actionType);
    if (digestCanonicalJson(action, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      !== digestCanonicalJson(input, { maxBytes: 1_048_576, maxDepth: 64 }).sha256
      || !actionType
      || action.status !== "running"
      || action.actionClass !== expectedActionClass(actionType)
      || action.kind !== "tool"
      || action.idempotent !== expectedIdempotency(actionType)
      || action.destructive
      || action.guidedDecisionId !== null) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_privilege_action_not_canonical",
        "policy_denied",
        "Only the exact canonical candidate-bound Linux continuation action may execute.",
      );
    }
    const lease = this.options.assertControlPlaneAuthority(action.runId);
    if (lease.runId !== action.runId || lease.controlPlane !== "ti_scale") {
      throw new ExecutionBoundaryError(
        "autonomous_linux_privilege_control_plane_invalid",
        "authorization_denied",
        "The candidate-bound Linux action is not owned by the Ti-Scale control plane.",
      );
    }
    const currentPlan = this.options.database.prepare(`
      SELECT 1 AS present
      FROM plan_steps step
      JOIN runs run ON run.id = step.run_id
        AND run.id = ?
        AND run.mission_id = ?
        AND run.current_plan_id = step.plan_id
        AND run.journey = 'autonomous'
        AND run.control_plane = 'ti_scale'
      JOIN missions mission ON mission.id = run.mission_id
        AND mission.control_plane = 'ti_scale'
        AND mission.authorization_status = 'verified'
      JOIN mission_contracts contract ON contract.id = run.contract_id
        AND contract.id = ?
        AND contract.state = 'confirmed'
        AND contract.version = run.contract_version_bound
        AND contract.contract_hash = run.contract_hash_bound
      WHERE step.id = ? AND step.run_id = run.id
      LIMIT 1
    `).get(
      action.runId,
      action.missionId,
      action.contractId,
      action.stepId,
    );
    if (!currentPlan) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_privilege_current_plan_required",
        "policy_denied",
        "The candidate-bound Linux continuation no longer belongs to the current signed Autonomous plan and contract.",
      );
    }
    return Object.freeze({
      action,
      actionType,
      arguments: parseAutonomousLinuxPrivilegeActionArguments(
        actionType,
        action.arguments,
      ),
    });
  }

  private validateSession(
    action: DurableAction,
    actionType: AutonomousLinuxPrivilegeContinuationActionType,
    args: AutonomousLinuxPrivilegeActionArguments,
  ): CanonicalSessionRow {
    const row = sessionRow(this.options.database, args.sessionArtifactId);
    const actionStep = this.options.database.prepare(`
      SELECT step.plan_id, step.run_id
      FROM plan_steps step
      WHERE step.id = ?
    `).get(action.stepId) as {
      readonly plan_id: string;
      readonly run_id: string;
    } | undefined;
    const validStatus = actionType === AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE
      ? row?.session_status === "active" && row.access_level === "user"
      : actionType === AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE
        ? row?.session_status === "privileged"
          && row.access_level === "root"
          && row.root_identity_count === 1
        : row?.session_status === "active" || row?.session_status === "privileged";
    if (!row
      || row.mission_id !== action.missionId
      || row.run_id !== action.runId
      || row.post_exploit_spec_id !== args.postExploitSpecId
      || row.exact_target !== action.target
      || row.current_plan_id !== row.plan_id
      || row.step_plan_id !== row.plan_id
      || !actionStep
      || actionStep.plan_id !== row.plan_id
      || actionStep.run_id !== action.runId
      || row.spec_status !== "active"
      || row.attack_status !== "succeeded"
      || row.evidence_verification_state !== "verified"
      || row.outcome_linked !== 1
      || row.journey !== "autonomous"
      || row.run_control_plane !== "ti_scale"
      || !["running", "recovering"].includes(row.run_status)
      || row.mission_control_plane !== "ti_scale"
      || row.authorization_status !== "verified"
      || !SHA256.test(row.candidate_binding_hash)
      || !row.transport_binding_id.trim()
      || row.transport_binding_id.length > 200
      || (
        row.transport_type === "loopback_http_session_v1"
          ? row.transport_origin === null
          : row.transport_type !== "candidate_runtime_session_v1"
            || row.transport_origin !== null
      )
      || row.privilege_path !== "/ti-scale/session/privilege-escalation"
      || row.root_identity_path !== "/ti-scale/session/root-identity"
      || row.root_flag_proof_path !== "/ti-scale/session/root-flag-proof"
      || row.cleanup_path !== "/ti-scale/session/cleanup"
      || row.declared_root_flag_path !== AUTONOMOUS_LINUX_ROOT_FLAG_PATH
      || !validStatus) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_privilege_session_gate_failed",
        "evidence_insufficient",
        "The session is not an active candidate-bound continuation of one independently verified exploit outcome at the required access level.",
      );
    }
    return row;
  }

  private acquire(
    action: DurableAction,
    actionType: AutonomousLinuxPrivilegeContinuationActionType,
    args: AutonomousLinuxPrivilegeActionArguments,
  ): AcquiredLease {
    return inImmediateTransaction(this.options.database, () => {
      const current = this.canonical(action);
      if (current.actionType !== actionType
        || digestCanonicalJson(current.arguments, {
          maxBytes: 64 * 1_024,
          maxDepth: 12,
        }).sha256 !== digestCanonicalJson(args, {
          maxBytes: 64 * 1_024,
          maxDepth: 12,
        }).sha256) {
        throw new ExecutionBoundaryError(
          "autonomous_linux_privilege_action_changed",
          "policy_denied",
          "The canonical represented action changed before session lease acquisition.",
        );
      }
      const row = this.validateSession(current.action, actionType, args);
      const now = this.#now();
      const active = this.options.database.prepare(`
        SELECT id, session_artifact_id, lease_owner, lease_token_hash,
          fencing_token, acquired_at, heartbeat_at, expires_at, released_at
        FROM session_artifact_leases
        WHERE session_artifact_id = ? AND released_at IS NULL
        ORDER BY fencing_token DESC LIMIT 1
      `).get(row.session_id) as ActiveLeaseRow | undefined;
      if (active && Date.parse(active.expires_at) > now.getTime()) {
        throw new ExecutionBoundaryError(
          "autonomous_linux_session_lease_busy",
          "worker_lost",
          "The exact candidate session is already owned by another in-flight operation.",
        );
      }
      if (active) {
        this.options.database.prepare(`
          UPDATE session_artifact_leases
          SET released_at = ?, release_reason = 'expired_lease_reclaimed'
          WHERE id = ? AND released_at IS NULL
        `).run(now.toISOString(), active.id);
      }
      const maximum = this.options.database.prepare(`
        SELECT COALESCE(MAX(fencing_token), 0) AS fencing_token
        FROM session_artifact_leases WHERE session_artifact_id = ?
      `).get(row.session_id) as { readonly fencing_token: number };
      const nextFence = Number(maximum.fencing_token) + 1;
      const rawToken = this.options.randomToken?.() ?? randomUUID();
      const tokenHash = hash(rawToken);
      const leaseId = `session_lease_${hash(
        `${row.session_id}\u0000${nextFence}\u0000${action.id}`,
      ).slice(0, 40)}`;
      const expiresAt = new Date(now.getTime() + this.#leaseMs).toISOString();
      this.options.database.prepare(`
        INSERT INTO session_artifact_leases (
          id, session_artifact_id, lease_owner, lease_token_hash,
          fencing_token, acquired_at, heartbeat_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        leaseId,
        row.session_id,
        this.options.leaseOwner,
        tokenHash,
        nextFence,
        now.toISOString(),
        now.toISOString(),
        expiresAt,
      );
      return Object.freeze({
        id: leaseId,
        owner: this.options.leaseOwner,
        rawToken,
        tokenHash,
        fencingToken: nextFence,
        expiresAt,
        sessionVersion: row.session_version,
        binding: Object.freeze({
          sessionArtifactId: row.session_id,
          postExploitSpecId: row.post_exploit_spec_id,
          missionId: row.mission_id,
          runId: row.run_id,
          exactTarget: row.exact_target,
          candidateBindingHash: row.candidate_binding_hash,
          leaseFencingToken: nextFence,
          transportType: row.transport_type,
          transportBindingId: row.transport_binding_id,
          ...(row.transport_origin
            ? { transportOrigin: row.transport_origin }
            : {}),
          privilegePath: row.privilege_path,
          rootIdentityPath: row.root_identity_path,
          rootFlagProofPath: row.root_flag_proof_path,
          cleanupPath: row.cleanup_path,
          declaredRootFlagPath: AUTONOMOUS_LINUX_ROOT_FLAG_PATH,
        }),
      });
    });
  }

  private assertLease(lease: AcquiredLease): ActiveLeaseRow {
    const row = this.options.database.prepare(`
      SELECT id, session_artifact_id, lease_owner, lease_token_hash,
        fencing_token, acquired_at, heartbeat_at, expires_at, released_at
      FROM session_artifact_leases WHERE id = ?
    `).get(lease.id) as ActiveLeaseRow | undefined;
    if (!row
      || row.session_artifact_id !== lease.binding.sessionArtifactId
      || row.lease_owner !== lease.owner
      || row.lease_token_hash !== hash(lease.rawToken)
      || row.lease_token_hash !== lease.tokenHash
      || row.fencing_token !== lease.fencingToken
      || row.released_at !== null
      || Date.parse(row.expires_at) <= this.#now().getTime()) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_session_lease_fence_invalid",
        "worker_lost",
        "The candidate session lease owner, token hash, fence, or expiry changed before commit.",
      );
    }
    return row;
  }

  /**
   * The plan cannot know a SessionArtifact version before the session exists.
   * Resolve it under the fenced lease immediately before target dispatch and
   * reject any intervening durable state transition. This complements rather
   * than replaces the candidate-binding and lease-fencing checks.
   */
  private assertSessionVersion(lease: AcquiredLease): CanonicalSessionRow {
    const row = sessionRow(
      this.options.database,
      lease.binding.sessionArtifactId,
    );
    if (
      !row
      || row.session_version !== lease.sessionVersion
      || row.candidate_binding_hash !== lease.binding.candidateBindingHash
      || row.exact_target !== lease.binding.exactTarget
      || row.post_exploit_spec_id !== lease.binding.postExploitSpecId
    ) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_session_version_fence_invalid",
        "worker_lost",
        "The candidate session changed after its latest durable version was fenced for this represented action.",
      );
    }
    return row;
  }

  private release(
    lease: AcquiredLease,
    reason: string,
  ): void {
    const now = this.#now().toISOString();
    const changed = this.options.database.prepare(`
      UPDATE session_artifact_leases
      SET released_at = ?, release_reason = ?
      WHERE id = ? AND lease_owner = ? AND lease_token_hash = ?
        AND fencing_token = ? AND released_at IS NULL
    `).run(
      now,
      clean(reason, 300),
      lease.id,
      lease.owner,
      lease.tokenHash,
      lease.fencingToken,
    ).changes;
    if (changed !== 1) {
      throw new ExecutionBoundaryError(
        "autonomous_linux_session_lease_release_failed",
        "worker_lost",
        "The exact session lease could not be released through its original fence.",
      );
    }
  }

  private identityEvidenceId(actionId: string): string {
    return `evidence_root_identity_${hash(actionId).slice(0, 40)}`;
  }

  private rootProofEvidenceId(actionId: string): string {
    return `evidence_root_flag_${hash(actionId).slice(0, 40)}`;
  }

  private commitRootIdentity(
    action: DurableAction,
    lease: AcquiredLease,
    acknowledgement: LoopbackLinuxPrivilegeAck,
    observation: IndependentRootIdentityObservation,
    brain: CandidateLinuxPrivilegeBrainReceipt,
  ): string {
    return inImmediateTransaction(this.options.database, () => {
      this.assertLease(lease);
      const current = this.canonical(action);
      const row = this.validateSession(
        current.action,
        current.actionType,
        current.arguments,
      );
      if (current.actionType !== AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE
        || acknowledgement.sessionArtifactId !== row.session_id
        || observation.sessionArtifactId !== row.session_id
        || observation.principal !== "root"
        || observation.uid !== 0
        || observation.gid !== 0
        || !SHA256.test(acknowledgement.receiptSha256)
        || !SHA256.test(observation.observationSha256)) {
        throw new ExecutionBoundaryError(
          "autonomous_linux_root_identity_correlation_failed",
          "evidence_insufficient",
          "The independent root identity proof no longer matches the canonical candidate session.",
        );
      }
      const evidenceId = this.identityEvidenceId(action.id);
      const now = this.#now().toISOString();
      const evidenceSource = row.transport_type
        === "candidate_runtime_session_v1"
        ? "candidate_bound_root_identity_observer"
        : "independent_loopback_root_identity";
      const provenance = digestCanonicalJson({
        schemaVersion: "ti-scale.autonomous-root-identity-evidence.v1",
        sessionArtifactId: row.session_id,
        postExploitSpecId: row.post_exploit_spec_id,
        originAttackAttemptId: row.origin_attack_attempt_id,
        exploitOutcomeEvidenceId: row.exploit_outcome_evidence_id,
        candidateBindingHash: row.candidate_binding_hash,
        privilegeReceiptSha256: acknowledgement.receiptSha256,
        independentObserver: true,
        observationSha256: observation.observationSha256,
        principal: observation.principal,
        uid: observation.uid,
        gid: observation.gid,
        groups: observation.groups,
        contextPackId: brain.contextPackId,
        publicProvider: false,
        genericCommandExecution: false,
        successCriterionReferences: [{
          schemaVersion:
            AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
          criterionId: autonomousSuccessCriterionId(
            AUTONOMOUS_PRIVILEGE_SUCCESS_CRITERION,
          ),
          outcome: "achieved",
        }],
      }, { maxBytes: 64 * 1_024, maxDepth: 12 });
      this.options.database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, step_id, action_id, source, acquired_at,
          target, evidence_type, content_hash, provenance_json, confidence,
          sensitivity, verification_state, summary, extracted_text,
          artifact_id, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?,
          ?, ?, 'privilege_access_proof', ?, ?, 1, 'restricted', 'verified',
          ?, ?, NULL, ?, ?)
      `).run(
        evidenceId,
        action.missionId,
        action.runId,
        action.stepId,
        action.id,
        evidenceSource,
        observation.observedAt,
        action.target,
        observation.observationSha256,
        provenance.canonicalJson,
        "A separate candidate-bound identity observer verified the root principal with UID and GID zero.",
        "principal=root; uid=0; gid=0",
        row.assigned_agent_id ?? "autonomous-linux-post-exploit-specialist",
        now,
      );
      this.options.database.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES (?, ?, 'verified', ?, ?, ?)
      `).run(
        `chain_root_identity_${hash(action.id).slice(0, 40)}`,
        evidenceId,
        row.assigned_agent_id ?? "autonomous-linux-post-exploit-specialist",
        digestCanonicalJson({
          method: "independent_root_identity_observer",
          privilegeResponseDidNotSupplyIdentity: true,
          contextPackId: brain.contextPackId,
        }, { maxBytes: 16 * 1_024, maxDepth: 8 }).canonicalJson,
        now,
      );
      this.options.database.prepare(`
        INSERT INTO session_identity_observations (
          id, session_artifact_id, action_id, observer_kind, principal,
          uid, gid, groups_json, observation_hash, evidence_id, observed_at
        ) VALUES (?, ?, ?, 'root_identity', 'root', 0, 0, ?, ?, ?, ?)
      `).run(
        `session_identity_root_${hash(action.id).slice(0, 40)}`,
        row.session_id,
        action.id,
        JSON.stringify(observation.groups),
        observation.observationSha256,
        evidenceId,
        observation.observedAt,
      );
      // Evidence/observation persistence may legitimately advance auxiliary
      // durable state in the same transaction. Re-read the SessionArtifact
      // immediately before its optimistic transition, preserving both the
      // required access state and an exact latest-version comparison.
      const latest = this.options.database.prepare(`
        SELECT version, status, access_level
        FROM session_artifacts WHERE id = ?
      `).get(row.session_id) as {
        readonly version: number;
        readonly status: string;
        readonly access_level: string;
      } | undefined;
      if (
        !latest
        || latest.status !== "active"
        || latest.access_level !== "user"
        || latest.version < row.session_version
      ) {
        throw new ExecutionBoundaryError(
          "autonomous_linux_root_identity_state_conflict",
          "worker_lost",
          "The candidate session changed before the independent root proof committed.",
        );
      }
      advanceCandidateSessionToPrivileged({
        database: this.options.database,
        sessionArtifactId: row.session_id,
        expectedVersion: latest.version,
        updatedAt: now,
      });
      this.release(lease, "privilege_identity_committed");
      return evidenceId;
    });
  }

  private commitRootFlag(
    action: DurableAction,
    lease: AcquiredLease,
    proof: RootFlagHashProof,
    brain: CandidateLinuxPrivilegeBrainReceipt,
  ): string {
    return inImmediateTransaction(this.options.database, () => {
      this.assertLease(lease);
      const current = this.canonical(action);
      const row = this.validateSession(
        current.action,
        current.actionType,
        current.arguments,
      );
      if (current.actionType !== AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE
        || proof.sessionArtifactId !== row.session_id
        || proof.declaredPath !== AUTONOMOUS_LINUX_ROOT_FLAG_PATH
        || current.arguments.declaredPath !== AUTONOMOUS_LINUX_ROOT_FLAG_PATH
        || !SHA256.test(proof.contentSha256)
        || !SHA256.test(proof.proofSha256)
        || proof.byteSize < 1
        || proof.byteSize > 4_096) {
        throw new ExecutionBoundaryError(
          "autonomous_linux_root_flag_correlation_failed",
          "evidence_insufficient",
          "The hash-only root proof no longer matches the canonical privileged candidate session and declared path.",
        );
      }
      const evidenceId = this.rootProofEvidenceId(action.id);
      const now = this.#now().toISOString();
      const evidenceSource = row.transport_type
        === "candidate_runtime_session_v1"
        ? "candidate_bound_root_flag_hash_observer"
        : "loopback_root_flag_hash_observer";
      const provenance = digestCanonicalJson({
        schemaVersion: "ti-scale.autonomous-root-flag-hash-evidence.v1",
        sessionArtifactId: row.session_id,
        postExploitSpecId: row.post_exploit_spec_id,
        originAttackAttemptId: row.origin_attack_attempt_id,
        candidateBindingHash: row.candidate_binding_hash,
        declaredPath: AUTONOMOUS_LINUX_ROOT_FLAG_PATH,
        contentSha256: proof.contentSha256,
        byteSize: proof.byteSize,
        proofSha256: proof.proofSha256,
        contextPackId: brain.contextPackId,
        rawContentRetained: false,
        publicProvider: false,
        genericCommandExecution: false,
        successCriterionReferences: [{
          schemaVersion:
            AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
          criterionId: autonomousSuccessCriterionId(
            AUTONOMOUS_ROOT_ACCESS_PROOF_SUCCESS_CRITERION,
          ),
          outcome: "achieved",
        }],
      }, { maxBytes: 64 * 1_024, maxDepth: 12 });
      this.options.database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, step_id, action_id, source, acquired_at,
          target, evidence_type, content_hash, provenance_json, confidence,
          sensitivity, verification_state, summary, extracted_text,
          artifact_id, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?,
          ?, ?, 'privilege_access_proof', ?, ?, 1, 'restricted', 'verified',
          ?, NULL, NULL, ?, ?)
      `).run(
        evidenceId,
        action.missionId,
        action.runId,
        action.stepId,
        action.id,
        evidenceSource,
        proof.observedAt,
        action.target,
        proof.proofSha256,
        provenance.canonicalJson,
        `The disposable /root/root.txt file was proven by SHA-256 and byte count only; its content was not retained.`,
        row.assigned_agent_id ?? "autonomous-linux-post-exploit-specialist",
        now,
      );
      this.options.database.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES (?, ?, 'verified', ?, ?, ?)
      `).run(
        `chain_root_flag_${hash(action.id).slice(0, 40)}`,
        evidenceId,
        row.assigned_agent_id ?? "autonomous-linux-post-exploit-specialist",
        digestCanonicalJson({
          method: "candidate_bound_root_flag_hash_only",
          declaredPath: AUTONOMOUS_LINUX_ROOT_FLAG_PATH,
          rawContentRetained: false,
          contextPackId: brain.contextPackId,
        }, { maxBytes: 16 * 1_024, maxDepth: 8 }).canonicalJson,
        now,
      );
      this.options.database.prepare(`
        INSERT INTO session_flag_proofs (
          id, session_artifact_id, action_id, proof_kind, declared_path,
          content_sha256, byte_size, evidence_id, observed_at
        ) VALUES (?, ?, ?, 'root_flag', ?, ?, ?, ?, ?)
      `).run(
        `session_flag_root_${hash(action.id).slice(0, 40)}`,
        row.session_id,
        action.id,
        AUTONOMOUS_LINUX_ROOT_FLAG_PATH,
        proof.contentSha256,
        proof.byteSize,
        evidenceId,
        proof.observedAt,
      );
      this.release(lease, "root_flag_hash_proof_committed");
      return evidenceId;
    });
  }

  private commitCleanup(
    action: DurableAction | undefined,
    lease: AcquiredLease,
    acknowledgement: LoopbackLinuxCleanupAck,
    reason: string,
    brain?: CandidateLinuxPrivilegeBrainReceipt,
  ): string | undefined {
    return inImmediateTransaction(this.options.database, () => {
      this.assertLease(lease);
      if (acknowledgement.sessionArtifactId
        !== lease.binding.sessionArtifactId
        || !SHA256.test(acknowledgement.receiptSha256)) {
        throw new ExecutionBoundaryError(
          "autonomous_linux_cleanup_correlation_failed",
          "evidence_insufficient",
          "The cleanup acknowledgement does not match the exact candidate session.",
        );
      }
      if (action) {
        const current = this.canonical(action);
        if (current.actionType !== AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE
          || current.arguments.sessionArtifactId
            !== lease.binding.sessionArtifactId) {
          throw new ExecutionBoundaryError(
            "autonomous_linux_cleanup_action_changed",
            "policy_denied",
            "The represented cleanup action changed before session closure.",
          );
        }
      }
      const now = this.#now().toISOString();
      const changed = this.options.database.prepare(`
        UPDATE session_artifacts
        SET status = 'closed', closed_at = ?, close_reason = ?,
          updated_at = ?, version = version + 1
        WHERE id = ? AND status IN ('active', 'privileged', 'closing')
      `).run(
        now,
        clean(reason, 300),
        now,
        lease.binding.sessionArtifactId,
      ).changes;
      if (changed !== 1) {
        throw new ExecutionBoundaryError(
          "autonomous_linux_cleanup_state_conflict",
          "worker_lost",
          "The candidate session changed before cleanup committed.",
        );
      }
      let evidenceId: string | undefined;
      if (action) {
        evidenceId = `evidence_session_cleanup_${hash(action.id).slice(0, 40)}`;
        const provenance = digestCanonicalJson({
          schemaVersion: "ti-scale.autonomous-session-cleanup-evidence.v1",
          sessionArtifactId: lease.binding.sessionArtifactId,
          postExploitSpecId: lease.binding.postExploitSpecId,
          exactTarget: lease.binding.exactTarget,
          cleanupReceiptSha256: acknowledgement.receiptSha256,
          closeReason: clean(reason, 300),
          activeLeaseRemaining: false,
          contextPackId: brain?.contextPackId ?? null,
          genericCommandExecution: false,
          successCriterionReferences: [{
            schemaVersion:
              AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
            criterionId: autonomousSuccessCriterionId(
              AUTONOMOUS_SESSION_CLEANUP_SUCCESS_CRITERION,
            ),
            outcome: "achieved",
          }],
        }, { maxBytes: 32 * 1_024, maxDepth: 10 });
        this.options.database.prepare(`
          INSERT INTO evidence (
            id, mission_id, run_id, step_id, action_id, source, acquired_at,
            target, evidence_type, content_hash, provenance_json, confidence,
            sensitivity, verification_state, summary, extracted_text,
            artifact_id, created_by, created_at
          ) VALUES (?, ?, ?, ?, ?, 'candidate_bound_session_cleanup',
            ?, ?, 'session_command_outcome', ?, ?, 1, 'private', 'verified',
            ?, NULL, NULL, ?, ?)
        `).run(
          evidenceId,
          action.missionId,
          action.runId,
          action.stepId,
          action.id,
          acknowledgement.observedAt,
          action.target,
          provenance.sha256,
          provenance.canonicalJson,
          "The candidate-bound session closed and its fenced execution lease was released.",
          "autonomous-linux-post-exploit-specialist",
          now,
        );
        this.options.database.prepare(`
          INSERT INTO evidence_chain_events (
            id, evidence_id, event_type, actor, details_json, occurred_at
          ) VALUES (?, ?, 'verified', ?, ?, ?)
        `).run(
          `chain_session_cleanup_${hash(action.id).slice(0, 40)}`,
          evidenceId,
          "autonomous-linux-post-exploit-specialist",
          digestCanonicalJson({
            method: "candidate_bound_session_cleanup",
            cleanupReceiptSha256: acknowledgement.receiptSha256,
            activeLeaseRemaining: false,
          }, { maxBytes: 16 * 1_024, maxDepth: 8 }).canonicalJson,
          now,
        );
      }
      this.release(lease, "candidate_session_closed");
      return evidenceId;
    });
  }

  private releaseFailure(
    lease: AcquiredLease,
    error: unknown,
  ): void {
    inImmediateTransaction(this.options.database, () => {
      const row = this.options.database.prepare(
        "SELECT released_at FROM session_artifact_leases WHERE id = ?",
      ).get(lease.id) as { readonly released_at: string | null } | undefined;
      if (!row || row.released_at !== null) return;
      this.release(
        lease,
        `operation_failed:${clean(
          typeof (error as { readonly code?: unknown })?.code === "string"
            ? String((error as { readonly code: string }).code)
            : "unknown",
          100,
        )}`,
      );
    });
  }

  async execute(
    input: DurableAction,
    signal: AbortSignal,
  ): Promise<CandidateLinuxPrivilegeRuntimeResult> {
    const canonical = this.canonical(input);
    const brain = this.options.brain.beforeAction(
      canonical.action,
      stage(canonical.actionType),
    );
    // Brain retrieval can take local indexed time. Re-read the complete
    // authority/session boundary immediately before acquiring the target lease.
    const lease = this.acquire(
      canonical.action,
      canonical.actionType,
      canonical.arguments,
    );
    try {
      if (canonical.actionType
        === AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE) {
        this.assertSessionVersion(lease);
        this.options.brain.assertAvailable(brain);
        const acknowledgement =
          await this.options.adapter.requestPrivilegeEscalation(
            lease.binding,
            canonical.action.id,
            signal,
          );
        // This is deliberately a distinct request after escalation. Identity
        // fields in the escalation acknowledgement are structurally rejected.
        this.assertSessionVersion(lease);
        this.options.brain.assertAvailable(brain);
        const observation = await this.options.adapter.observeRootIdentity(
          lease.binding,
          canonical.action.id,
          signal,
        );
        const evidenceId = this.commitRootIdentity(
          canonical.action,
          lease,
          acknowledgement,
          observation,
          brain,
        );
        return materialResult({
          schemaVersion:
            AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION,
          actionId: canonical.action.id,
          actionType: canonical.actionType,
          sessionArtifactId: lease.binding.sessionArtifactId,
          contextPackId: brain.contextPackId,
          evidenceIds: Object.freeze([evidenceId]),
          privilegeReceiptSha256: acknowledgement.receiptSha256,
          rootIdentityObservationSha256: observation.observationSha256,
          cleanupCompleted: false,
          summary:
            "The fixed candidate privilege operation completed, then a separate identity observer verified root with UID and GID zero.",
        });
      }
      if (canonical.actionType === AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE) {
        this.assertSessionVersion(lease);
        this.options.brain.assertAvailable(brain);
        const proof = await this.options.adapter.proveRootFlag(
          lease.binding,
          canonical.action.id,
          signal,
        );
        const evidenceId = this.commitRootFlag(
          canonical.action,
          lease,
          proof,
          brain,
        );
        return materialResult({
          schemaVersion:
            AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION,
          actionId: canonical.action.id,
          actionType: canonical.actionType,
          sessionArtifactId: lease.binding.sessionArtifactId,
          contextPackId: brain.contextPackId,
          evidenceIds: Object.freeze([evidenceId]),
          rootFlagProofSha256: proof.proofSha256,
          rootFlagContentSha256: proof.contentSha256,
          cleanupCompleted: false,
          summary:
            "The fixed root proof returned only the SHA-256 and byte count for /root/root.txt; no flag content was retained.",
        });
      }
      this.assertSessionVersion(lease);
      this.options.brain.assertAvailable(brain);
      const acknowledgement = await this.options.adapter.cleanup(
        lease.binding,
        "mission_post_exploit_sequence_complete",
        signal,
      );
      const cleanupEvidenceId = this.commitCleanup(
        canonical.action,
        lease,
        acknowledgement,
        "mission_post_exploit_sequence_complete",
        brain,
      );
      return materialResult({
        schemaVersion: AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION,
        actionId: canonical.action.id,
        actionType: canonical.actionType,
        sessionArtifactId: lease.binding.sessionArtifactId,
        contextPackId: brain.contextPackId,
        evidenceIds: Object.freeze(
          cleanupEvidenceId ? [cleanupEvidenceId] : [],
        ),
        cleanupReceiptSha256: acknowledgement.receiptSha256,
        cleanupCompleted: true,
        summary:
          "The fixed candidate-bound session closed cleanly and its fenced lease was released.",
      });
    } catch (error) {
      this.releaseFailure(lease, error);
      throw error;
    }
  }

  /**
   * Cancellation cleanup is intentionally a separate fixed operation. It
   * never receives an arbitrary action or command and it processes only
   * candidate sessions for the exact Ti-Scale run.
   */
  async cleanupRun(
    runId: string,
    reason: string,
    signal: AbortSignal,
  ): Promise<number> {
    const authority = this.options.assertControlPlaneAuthority(runId);
    if (authority.runId !== runId || authority.controlPlane !== "ti_scale") {
      throw new ExecutionBoundaryError(
        "autonomous_linux_cleanup_control_plane_invalid",
        "authorization_denied",
        "Run cleanup is not owned by the Ti-Scale control plane.",
      );
    }
    const rows = this.options.database.prepare(`
      SELECT session.id
      FROM session_artifacts session
      JOIN runs run ON run.id = session.run_id
      JOIN missions mission ON mission.id = session.mission_id
      JOIN candidate_linux_post_exploit_specs spec
        ON spec.id = session.post_exploit_spec_id
      WHERE session.run_id = ?
        AND session.status IN ('active', 'privileged')
        AND run.control_plane = 'ti_scale'
        AND mission.control_plane = 'ti_scale'
        AND spec.status = 'active'
      ORDER BY session.created_at, session.id
    `).all(runId) as Array<{ readonly id: string }>;
    let closed = 0;
    for (const { id } of rows) {
      if (signal.aborted) break;
      const syntheticAction: DurableAction = Object.freeze({
        id: `system-cleanup-${hash(`${runId}\u0000${id}`).slice(0, 32)}`,
        missionId: "",
        runId,
        stepId: "",
        actionType: AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
        actionClass: AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_CLASS,
        fingerprint: hash(`system-cleanup\u0000${runId}\u0000${id}`),
        arguments: {},
        target: "",
        kind: "tool",
        intentSummary: "Cancel and close the candidate-bound session.",
        status: "running",
        idempotent: true,
        destructive: false,
        guidedDecisionId: null,
        contractId: null,
        contextPackId: null,
        resultSummary: null,
        errorCategory: null,
        retryCount: 0,
        progressSignature: null,
        createdAt: this.#now().toISOString(),
        startedAt: this.#now().toISOString(),
        endedAt: null,
      });
      let acquired: AcquiredLease | undefined;
      try {
        acquired = this.acquireSystemCleanup(syntheticAction, id);
        this.assertSessionVersion(acquired);
        const acknowledgement = await this.options.adapter.cleanup(
          acquired.binding,
          reason,
          signal,
        );
        this.commitCleanup(undefined, acquired, acknowledgement, reason);
        closed += 1;
      } catch (error) {
        if (acquired) this.releaseFailure(acquired, error);
        if (signal.aborted) break;
        throw error;
      }
    }
    return closed;
  }

  private acquireSystemCleanup(
    syntheticAction: DurableAction,
    sessionArtifactId: string,
  ): AcquiredLease {
    return inImmediateTransaction(this.options.database, () => {
      const row = sessionRow(this.options.database, sessionArtifactId);
      if (!row
        || row.run_id !== syntheticAction.runId
        || !["active", "privileged"].includes(row.session_status)
        || row.spec_status !== "active"
        || row.run_control_plane !== "ti_scale"
        || row.mission_control_plane !== "ti_scale"
        || row.attack_status !== "succeeded"
        || row.evidence_verification_state !== "verified"
        || row.outcome_linked !== 1) {
        throw new ExecutionBoundaryError(
          "autonomous_linux_cleanup_session_gate_failed",
          "evidence_insufficient",
          "Cancellation cleanup found a session outside the exact verified candidate boundary.",
        );
      }
      const active = this.options.database.prepare(`
        SELECT id, session_artifact_id, lease_owner, lease_token_hash,
          fencing_token, acquired_at, heartbeat_at, expires_at, released_at
        FROM session_artifact_leases
        WHERE session_artifact_id = ? AND released_at IS NULL
        ORDER BY fencing_token DESC LIMIT 1
      `).get(row.session_id) as ActiveLeaseRow | undefined;
      const now = this.#now();
      if (active && Date.parse(active.expires_at) > now.getTime()) {
        throw new ExecutionBoundaryError(
          "autonomous_linux_cleanup_lease_busy",
          "worker_lost",
          "Cancellation cleanup is waiting for the in-flight session operation to settle.",
        );
      }
      if (active) {
        this.options.database.prepare(`
          UPDATE session_artifact_leases
          SET released_at = ?, release_reason = 'expired_cleanup_lease_reclaimed'
          WHERE id = ? AND released_at IS NULL
        `).run(now.toISOString(), active.id);
      }
      const maximum = this.options.database.prepare(`
        SELECT COALESCE(MAX(fencing_token), 0) AS fencing_token
        FROM session_artifact_leases WHERE session_artifact_id = ?
      `).get(row.session_id) as { readonly fencing_token: number };
      const nextFence = Number(maximum.fencing_token) + 1;
      const rawToken = this.options.randomToken?.() ?? randomUUID();
      const tokenHash = hash(rawToken);
      const leaseId = `session_lease_${hash(
        `${row.session_id}\u0000${nextFence}\u0000system-cleanup`,
      ).slice(0, 40)}`;
      const expiresAt = new Date(now.getTime() + this.#leaseMs).toISOString();
      this.options.database.prepare(`
        INSERT INTO session_artifact_leases (
          id, session_artifact_id, lease_owner, lease_token_hash,
          fencing_token, acquired_at, heartbeat_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        leaseId,
        row.session_id,
        this.options.leaseOwner,
        tokenHash,
        nextFence,
        now.toISOString(),
        now.toISOString(),
        expiresAt,
      );
      return Object.freeze({
        id: leaseId,
        owner: this.options.leaseOwner,
        rawToken,
        tokenHash,
        fencingToken: nextFence,
        expiresAt,
        sessionVersion: row.session_version,
        binding: Object.freeze({
          sessionArtifactId: row.session_id,
          postExploitSpecId: row.post_exploit_spec_id,
          missionId: row.mission_id,
          runId: row.run_id,
          exactTarget: row.exact_target,
          candidateBindingHash: row.candidate_binding_hash,
          leaseFencingToken: nextFence,
          transportType: row.transport_type,
          transportBindingId: row.transport_binding_id,
          ...(row.transport_origin
            ? { transportOrigin: row.transport_origin }
            : {}),
          privilegePath: row.privilege_path,
          rootIdentityPath: row.root_identity_path,
          rootFlagProofPath: row.root_flag_proof_path,
          cleanupPath: row.cleanup_path,
          declaredRootFlagPath: AUTONOMOUS_LINUX_ROOT_FLAG_PATH,
        }),
      });
    });
  }
}

export function isCandidateLinuxPrivilegeContinuationError(
  error: unknown,
): error is CandidateLinuxPrivilegeContinuationError {
  return error instanceof CandidateLinuxPrivilegeContinuationError;
}

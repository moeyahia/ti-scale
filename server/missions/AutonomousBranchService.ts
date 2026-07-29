import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { redactSecrets } from "../contracts/redaction";
import { autonomousContractHash, canonicalJson, hashCanonical, sha256 } from "./canonical";
import { AutonomousReadinessError, IdempotencyConflictError, MissionApiError } from "./errors";
import type { MissionService } from "./MissionService";
import type { AutonomousMissionPreflight, AutonomousMissionRequest } from "./types";
import {
  validateLegacyAutonomousMissionRequest,
  validateMissionCreateRequest,
} from "./validation";
import {
  ModelConfigurationError,
  resolveAutonomousPlanningSelection,
  type ModelConfigurationService,
} from "../model-config";

type BranchMode = "unchanged_contract" | "contract_amendment";

interface SourceRow {
  readonly mission_id: string;
  readonly mission_name: string;
  readonly mission_objective: string;
  readonly mission_journey: string;
  readonly mission_status: string;
  readonly mission_version: number;
  readonly engagement_id: string | null;
  readonly success_criteria_json: string;
  readonly run_id: string;
  readonly run_journey: string;
  readonly run_status: string;
  readonly run_status_reason: string | null;
  readonly run_version: number;
  readonly contract_id: string | null;
  readonly contract_version: number | null;
  readonly contract_state: string | null;
  readonly contract_hash: string | null;
  readonly authorization_json: string | null;
  readonly action_policy_json: string | null;
  readonly budgets_json: string | null;
  readonly safe_stop_json: string | null;
  readonly deliverables_json: string | null;
  readonly memory_scopes_json: string | null;
}

interface ContractRow {
  readonly id: string;
  readonly mission_id: string;
  readonly version: number;
  readonly state: "draft" | "confirmed" | "superseded" | "revoked";
  readonly contract_hash: string;
  readonly authorization_json: string;
  readonly action_policy_json: string;
  readonly budgets_json: string;
  readonly safe_stop_json: string;
  readonly deliverables_json: string;
  readonly memory_scopes_json: string;
  readonly source_contract_id: string | null;
  readonly request_json: string | null;
}

export interface AutonomousBranchContext {
  readonly schemaVersion: "2.4";
  readonly mission: { readonly id: string; readonly name: string; readonly version: number };
  readonly sourceRun: {
    readonly id: string;
    readonly status: string;
    readonly statusReason: string | null;
    readonly version: number;
    readonly safeToBranch: boolean;
    readonly safeToBranchReason: string;
  };
  readonly contract: {
    readonly id: string;
    readonly version: number;
    readonly state: string;
    readonly hash: string;
  };
  readonly request: AutonomousMissionRequest;
  readonly history: readonly {
    readonly id: string;
    readonly version: number;
    readonly state: string;
    readonly hash: string;
    readonly sourceContractId: string | null;
    readonly confirmedBy: string | null;
    readonly confirmedAt: string | null;
    readonly createdAt: string;
  }[];
}

export interface AutonomousBranchPreflight {
  readonly schemaVersion: "2.4";
  readonly mode: BranchMode;
  readonly sourceRunId: string;
  readonly sourceRunVersion: number;
  readonly safeToBranch: boolean;
  readonly safeToBranchReason: string;
  readonly contract: {
    readonly id: string | null;
    readonly version: number;
    readonly state: "confirmed" | "draft" | "unpersisted";
    readonly hash: string;
    readonly sourceContractId: string;
  };
  readonly request: AutonomousMissionRequest;
  readonly preflight: VersionedAutonomousPreflight;
}

export type VersionedAutonomousPreflight = Omit<AutonomousMissionPreflight, "contract"> & {
  readonly contract: { readonly version: number; readonly hash: string };
};

export interface AutonomousBranchResult {
  readonly schemaVersion: "2.4";
  readonly sourceRunId: string;
  readonly branchMode: BranchMode;
  readonly run: {
    readonly id: string;
    readonly missionId: string;
    readonly journey: "autonomous";
    readonly status: "planning";
    readonly contractId: string;
    readonly createdAt: string;
  };
  readonly contract: {
    readonly id: string;
    readonly version: number;
    readonly state: "confirmed";
    readonly hash: string;
  };
  readonly nextUrl: string;
}

interface StoredMutation<T> {
  readonly requestHash: string;
  readonly response: T;
}

const TERMINAL = new Set(["completed", "failed", "cancelled"]);

function id(prefix: string): string {
  return `${prefix}_${randomUUID()}`;
}

function parseObject(value: string | null): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value ?? "{}") as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

function parseArray(value: string | null): unknown[] {
  try {
    const parsed = JSON.parse(value ?? "[]") as unknown;
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function withoutReview(request: AutonomousMissionRequest): AutonomousMissionRequest {
  const { contractReview: _review, ...rest } = request;
  return rest;
}

function safeReason(value: unknown): string {
  if (typeof value !== "string" || value.trim().length < 3 || value.length > 2_000) {
    throw new MissionApiError(400, "invalid_branch_reason", "Branch reason is invalid", {
      humanMessage: "Explain why the new Autonomous run or contract amendment is needed.",
      category: "invalid_input",
    });
  }
  const normalized = value.trim();
  if (redactSecrets(normalized) !== normalized) {
    throw new MissionApiError(422, "sensitive_material_not_retained", "Sensitive material was rejected", {
      humanMessage: "The branch reason appears to contain authentication or credential material and was not retained.",
      category: "policy_denied",
      remediation: "Remove the sensitive value and reference it by an opaque identifier.",
    });
  }
  return normalized;
}

function branchSettingKey(kind: "draft" | "create", key: string): string {
  return `idempotency.mission.autonomous_branch.${kind}.${sha256(key)}`;
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

export class AutonomousBranchService {
  private readonly events: EventRepository;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly missions: MissionService,
    private readonly clock: () => Date = () => new Date(),
    private readonly modelConfigurations?: ModelConfigurationService,
  ) {
    this.events = new EventRepository(database);
  }

  context(missionId: string, sourceRunId: string): AutonomousBranchContext {
    const source = this.source(missionId, sourceRunId);
    const request = this.requestForSource(source);
    const safety = this.branchSafety(source);
    const history = this.database.prepare(`
      SELECT mc.id, mc.version, mc.state, mc.contract_hash,
        mcs.source_contract_id, mc.confirmed_by, mc.confirmed_at, mc.created_at
      FROM mission_contracts mc
      LEFT JOIN mission_contract_snapshots mcs ON mcs.contract_id = mc.id
      WHERE mc.mission_id = ? ORDER BY mc.version DESC, mc.created_at DESC
    `).all(missionId) as Array<{
      id: string; version: number; state: string; contract_hash: string;
      source_contract_id: string | null; confirmed_by: string | null;
      confirmed_at: string | null; created_at: string;
    }>;
    return {
      schemaVersion: "2.4",
      mission: { id: source.mission_id, name: source.mission_name, version: source.mission_version },
      sourceRun: {
        id: source.run_id,
        status: source.run_status,
        statusReason: source.run_status_reason,
        version: source.run_version,
        safeToBranch: safety.safe,
        safeToBranchReason: safety.reason,
      },
      contract: {
        id: source.contract_id!,
        version: source.contract_version!,
        state: source.contract_state!,
        hash: source.contract_hash!,
      },
      request,
      history: history.map((row) => ({
        id: row.id,
        version: row.version,
        state: row.state,
        hash: row.contract_hash,
        sourceContractId: row.source_contract_id,
        confirmedBy: row.confirmed_by,
        confirmedAt: row.confirmed_at,
        createdAt: row.created_at,
      })),
    };
  }

  async preflight(
    missionId: string,
    input: {
      readonly sourceRunId: string;
      readonly sourceRunVersion: number;
      readonly mode: BranchMode;
      readonly reason: string;
      readonly request?: AutonomousMissionRequest;
    },
    idempotencyKey: string,
    actorId: string,
    assertMutationAuthority: () => void,
  ): Promise<AutonomousBranchPreflight> {
    const reason = safeReason(input.reason);
    const requestHash = hashCanonical({
      missionId,
      sourceRunId: input.sourceRunId,
      sourceRunVersion: input.sourceRunVersion,
      mode: input.mode,
      reason,
      request: input.mode === "contract_amendment" && input.request
        ? withoutReview(input.request)
        : null,
      actorId,
    });
    const settingKey = branchSettingKey("draft", idempotencyKey);
    // A replay is still a disclosure of mutation-owned mission state. Resolve
    // it only while the current runtime authority is fenced in the same
    // IMMEDIATE transaction used by the eventual write.
    const prior = inImmediateTransaction(this.database, () => {
      assertMutationAuthority();
      return this.stored<AutonomousBranchPreflight>(settingKey, requestHash);
    });
    if (prior) return prior;
    const source = this.source(missionId, input.sourceRunId);
    if (source.run_version !== input.sourceRunVersion) {
      throw this.staleSource();
    }
    const safety = this.branchSafety(source);
    const sourceRequest = this.requestForSource(source);
    const request = input.mode === "unchanged_contract"
      ? sourceRequest
      : withoutReview(input.request ?? sourceRequest);
    // An unchanged branch inherits the exact persisted contract authority.
    // Legacy contracts may reconstruct omitted optional values as explicit
    // empty arrays, which must not invent a new digest for an unchanged run.
    // Amendments still hash their full newly reviewed request.
    const hash = input.mode === "unchanged_contract"
      ? source.contract_hash!
      : autonomousContractHash(request);
    if (input.mode === "contract_amendment" && hash === source.contract_hash) {
      throw new MissionApiError(409, "amendment_has_no_changes", "The amendment matches the signed contract", {
        humanMessage: "No contract authority changed. Choose the unchanged-contract branch instead.",
        category: "conflict",
      });
    }
    const checked = await this.missions.preflightAutonomous(request);
    const nextVersion = input.mode === "unchanged_contract"
      ? source.contract_version!
      : this.nextContractVersion(missionId);
    const preflight = { ...checked, contract: { version: nextVersion, hash } };
    if (input.mode === "unchanged_contract" || checked.readiness.status === "blocked" || !safety.safe) {
      return inImmediateTransaction(this.database, () => {
        assertMutationAuthority();
        const replay = this.stored<AutonomousBranchPreflight>(settingKey, requestHash);
        if (replay) return replay;
        const current = this.source(missionId, input.sourceRunId);
        if (current.run_version !== input.sourceRunVersion) throw this.staleSource();
        return {
          schemaVersion: "2.4",
          mode: input.mode,
          sourceRunId: current.run_id,
          sourceRunVersion: current.run_version,
          safeToBranch: safety.safe,
          safeToBranchReason: safety.reason,
          contract: {
            id: input.mode === "unchanged_contract" ? current.contract_id : null,
            version: nextVersion,
            state: input.mode === "unchanged_contract" ? "confirmed" : "unpersisted",
            hash,
            sourceContractId: current.contract_id!,
          },
          request,
          preflight,
        };
      });
    }

    return inImmediateTransaction(this.database, () => {
      assertMutationAuthority();
      const replay = this.stored<AutonomousBranchPreflight>(settingKey, requestHash);
      if (replay) return replay;
      const current = this.source(missionId, input.sourceRunId);
      if (current.run_version !== input.sourceRunVersion) throw this.staleSource();
      this.assertSafeToBranch(current);
      this.assertCurrentConfirmedContract(current);
      const version = this.nextContractVersion(missionId);
      const existing = this.database.prepare(`
        SELECT id, state FROM mission_contracts WHERE mission_id = ? AND contract_hash = ?
      `).get(missionId, hash) as { id: string; state: string } | undefined;
      if (existing) {
        throw new MissionApiError(409, "contract_hash_already_exists", "This exact contract version already exists", {
          humanMessage: "This exact contract has already been drafted or confirmed for the mission.",
          category: "conflict",
          details: { contractId: existing.id, state: existing.state },
          remediation: "Refresh contract history and continue from the existing version.",
        });
      }
      const now = this.timestamp();
      this.ensureSourceSnapshot(current, sourceRequest, actorId, now);
      const contractId = id("contract");
      this.insertContract(contractId, missionId, version, "draft", hash, request, null, null, now);
      this.database.prepare(`
        INSERT INTO mission_contract_snapshots (
          contract_id, mission_id, source_contract_id, request_json,
          amendment_reason, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(contractId, missionId, current.contract_id, canonicalJson(request), reason, actorId, now);
      const event = this.events.append({
        missionId,
        runId: current.run_id,
        journey: "autonomous",
        eventType: "mission.contract_amendment_drafted",
        actorType: "operator",
        actorId,
        summary: `Drafted Autonomous contract version ${version} after readiness validation`,
        payload: {
          sourceContractId: current.contract_id,
          draftContractId: contractId,
          version,
          contractHash: hash,
          sourceRunVersion: current.run_version,
        },
        occurredAt: now,
        sensitivity: "private",
      });
      this.appendAudit({
        missionId, runId: current.run_id, actorId,
        action: "mission.contract_amendment_drafted",
        resourceType: "mission_contract", resourceId: contractId, reason,
        details: { sourceContractId: current.contract_id, version, contractHash: hash, eventId: event.id }, now,
      });
      const response: AutonomousBranchPreflight = {
        schemaVersion: "2.4",
        mode: "contract_amendment",
        sourceRunId: current.run_id,
        sourceRunVersion: current.run_version,
        safeToBranch: true,
        safeToBranchReason: safety.reason,
        contract: {
          id: contractId,
          version,
          state: "draft",
          hash,
          sourceContractId: current.contract_id!,
        },
        request,
        preflight: { ...preflight, contract: { version, hash } },
      };
      this.store(settingKey, requestHash, response, actorId, now);
      return response;
    });
  }

  async createBranch(
    missionId: string,
    input: {
      readonly sourceRunId: string;
      readonly sourceRunVersion: number;
      readonly mode: BranchMode;
      readonly reason: string;
      readonly draftContractId?: string;
      readonly review: { readonly version: number; readonly hash: string };
    },
    idempotencyKey: string,
    actorId: string,
    assertMutationAuthority: () => void,
  ): Promise<AutonomousBranchResult> {
    const reason = safeReason(input.reason);
    const requestHash = hashCanonical({
      missionId,
      sourceRunId: input.sourceRunId,
      sourceRunVersion: input.sourceRunVersion,
      mode: input.mode,
      reason,
      draftContractId: input.draftContractId ?? null,
      review: input.review,
      actorId,
    });
    const settingKey = branchSettingKey("create", idempotencyKey);
    // Idempotency never outlives mutation authority. Keep the replay read under
    // an IMMEDIATE authority fence so a lost lease cannot disclose or recreate
    // control-plane state after a successful response was lost.
    const prior = inImmediateTransaction(this.database, () => {
      assertMutationAuthority();
      return this.stored<AutonomousBranchResult>(settingKey, requestHash);
    });
    if (prior) return prior;
    const source = this.source(missionId, input.sourceRunId);
    if (source.run_version !== input.sourceRunVersion) throw this.staleSource();
    this.assertSafeToBranch(source);
    this.assertCurrentConfirmedContract(source);
    const target = input.mode === "unchanged_contract"
      ? this.contract(source.contract_id!)
      : this.draftContract(missionId, input.draftContractId, source.contract_id!);
    const request = input.mode === "unchanged_contract"
      ? this.requestForSource(source)
      : this.requestFromSnapshot(target);
    if (target.version !== input.review.version || target.contract_hash !== input.review.hash) {
      throw new MissionApiError(409, "contract_review_stale", "The reviewed contract digest is stale", {
        humanMessage: "The reviewed version or SHA-256 no longer matches the exact contract to be confirmed.",
        category: "conflict",
        remediation: "Run branch preflight again and deliberately review the current version and digest.",
      });
    }
    const checked = await this.missions.preflightAutonomous(request);
    const blockers = checked.readiness.checks.filter((check) => check.status === "fail");
    if (blockers.length > 0) {
      throw new AutonomousReadinessError({
        status: checked.readiness.status,
        score: checked.readiness.score,
        checks: blockers.map((check) => ({
          id: check.id,
          label: check.label,
          status: check.status,
          impact: check.impact,
          journeys: [...check.journeys],
          remediation: check.remediation ?? null,
        })),
      });
    }
    return inImmediateTransaction(this.database, () => {
      assertMutationAuthority();
      const replay = this.stored<AutonomousBranchResult>(settingKey, requestHash);
      if (replay) return replay;
      const current = this.source(missionId, input.sourceRunId);
      if (current.run_version !== input.sourceRunVersion) throw this.staleSource();
      this.assertSafeToBranch(current);
      this.assertCurrentConfirmedContract(current);
      this.assertNoOtherActiveRun(missionId, current.run_id);
      const currentTarget = input.mode === "unchanged_contract"
        ? this.contract(current.contract_id!)
        : this.draftContract(missionId, input.draftContractId, current.contract_id!);
      if (currentTarget.version !== input.review.version || currentTarget.contract_hash !== input.review.hash) {
        throw new MissionApiError(409, "contract_review_stale", "The reviewed contract digest is stale", {
          humanMessage: "The reviewed contract changed before the branch could be created.",
          category: "conflict",
        });
      }
      const currentRequest = input.mode === "unchanged_contract"
        ? this.requestForSource(current)
        : this.requestFromSnapshot(currentTarget);
      const now = this.timestamp();
      this.ensureSourceSnapshot(current, this.requestForSource(current), actorId, now);
      if (input.mode === "contract_amendment") {
        this.database.prepare(`
          UPDATE mission_contracts SET state = 'superseded'
          WHERE mission_id = ? AND state = 'confirmed' AND id != ?
        `).run(missionId, currentTarget.id);
        this.database.prepare(`
          UPDATE mission_contracts
          SET state = 'confirmed', confirmed_by = ?, confirmed_at = ?
          WHERE id = ? AND state = 'draft'
        `).run(actorId, now, currentTarget.id);
        this.updateMissionProjection(missionId, currentRequest, now);
      } else {
        this.database.prepare(`
          UPDATE missions SET status = 'active', version = version + 1, updated_at = ? WHERE id = ?
        `).run(now, missionId);
      }
      const runId = id("run");
      const statusReason = input.mode === "contract_amendment"
        ? `Autonomous contract version ${currentTarget.version} deliberately confirmed; planning may proceed without routine input.`
        : `New run created under unchanged confirmed Autonomous contract version ${currentTarget.version}.`;
      this.database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, control_plane, contract_id,
          contract_version_bound, contract_hash_bound, progress,
          status_reason, next_action_summary, budget_json, budget_usage_json,
          retry_count, replan_count, started_at, created_at, updated_at, version
        ) VALUES (?, ?, 'autonomous', 'planning', 'ti_scale', ?, ?, ?, 0, ?,
          'Build and version a new plan inside the confirmed contract', ?, '{}',
          0, 0, ?, ?, ?, 1)
      `).run(
        runId, missionId, currentTarget.id,
        currentTarget.version, currentTarget.contract_hash, statusReason,
        currentTarget.budgets_json, now, now, now,
      );
      let pinnedModelAssignmentIds: string[];
      if (!this.modelConfigurations) {
        throw new MissionApiError(
          503,
          "branch_model_configuration_service_unavailable",
          "Exact branch model assignment service is unavailable",
          {
            humanMessage:
              "The new run was not created because Ti-Scale could not revalidate and pin its exact signed specialist models.",
            category: "dependency_missing",
            remediation:
              "Restore the canonical model-configuration service, rerun branch preflight, and retry the unchanged reviewed contract.",
          },
        );
      }
      try {
        pinnedModelAssignmentIds =
          this.modelConfigurations.pinExactAutonomousAssignments({
            assignments: currentRequest.contract.agentModelAssignments,
            specialistAgentIds: currentRequest.contract.specialistAgentIds,
            requiredActionClassIds:
              currentRequest.contract.allowedActionClasses,
            missionId,
            runId,
            resolutionReason: input.mode === "contract_amendment"
              ? `Pinned transactionally from reviewed Autonomous contract amendment version ${currentTarget.version}`
              : `Repinned transactionally from unchanged reviewed Autonomous contract version ${currentTarget.version}`,
          }).map(({ id }) => id);
        const planningSelection = resolveAutonomousPlanningSelection(
          currentRequest.contract.planningSelection,
        );
        if (planningSelection.route === "provider_advisory") {
          const planningPin =
            this.modelConfigurations.pinExactAutonomousPlanningSelection({
              selection: planningSelection,
              missionId,
              runId,
              resolutionReason: input.mode === "contract_amendment"
                ? `Pinned transactionally from reviewed provider-advisory planning selection in contract amendment version ${currentTarget.version}`
                : `Repinned transactionally from unchanged provider-advisory planning selection in contract version ${currentTarget.version}`,
            });
          if (planningPin) pinnedModelAssignmentIds.push(planningPin.id);
        }
        pinnedModelAssignmentIds.push(
          ...this.modelConfigurations
            .pinSelectedSpecialistAdvisoryAssignments({
              specialistAgentIds:
                currentRequest.contract.specialistAgentIds,
              missionId,
              runId,
            })
            .map(({ id }) => id),
        );
      } catch (error) {
        if (!(error instanceof ModelConfigurationError)) throw error;
        throw new MissionApiError(
          error.status === 404 ? 409 : error.status,
          "branch_model_configuration_unavailable",
          error.message,
          {
            humanMessage:
              "The new run was not created because an exact signed specialist model changed or became unavailable after review.",
            category: error.category,
            remediation:
              "Refresh the live model catalog, amend and review the exact assignment if needed, then create a new branch.",
          },
        );
      }
      const branchId = id("branch");
      this.database.prepare(`
        INSERT INTO run_branches (
          id, mission_id, source_run_id, run_id, branch_mode,
          source_contract_id, target_contract_id, reason, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        branchId, missionId, current.run_id, runId, input.mode,
        current.contract_id, currentTarget.id, reason, actorId, now,
      );
      const event = this.events.append({
        missionId,
        runId,
        journey: "autonomous",
        eventType: "run.autonomous_branch_created",
        actorType: "operator",
        actorId,
        summary: input.mode === "contract_amendment"
          ? `Created a new Autonomous run under confirmed contract version ${currentTarget.version}`
          : `Created a new Autonomous run under unchanged contract version ${currentTarget.version}`,
        payload: {
          branchId,
          sourceRunId: current.run_id,
          sourceRunVersion: current.run_version,
          branchMode: input.mode,
          sourceContractId: current.contract_id,
          targetContractId: currentTarget.id,
          contractVersion: currentTarget.version,
          contractHash: currentTarget.contract_hash,
          contractChanged: input.mode === "contract_amendment",
          journeyChanged: false,
          status: "planning",
          pinnedModelAssignmentIds: [...pinnedModelAssignmentIds],
        },
        occurredAt: now,
        sensitivity: "private",
      });
      this.appendAudit({
        missionId, runId, actorId, action: "run.autonomous_branch_created",
        resourceType: "run", resourceId: runId, reason,
        details: {
          branchId,
          sourceRunId: current.run_id,
          branchMode: input.mode,
          sourceContractId: current.contract_id,
          targetContractId: currentTarget.id,
          contractVersion: currentTarget.version,
          contractHash: currentTarget.contract_hash,
          pinnedModelAssignmentIds: [...pinnedModelAssignmentIds],
          eventId: event.id,
        },
        now,
      });
      const response: AutonomousBranchResult = {
        schemaVersion: "2.4",
        sourceRunId: current.run_id,
        branchMode: input.mode,
        run: {
          id: runId,
          missionId,
          journey: "autonomous",
          status: "planning",
          contractId: currentTarget.id,
          createdAt: now,
        },
        contract: {
          id: currentTarget.id,
          version: currentTarget.version,
          state: "confirmed",
          hash: currentTarget.contract_hash,
        },
        nextUrl: `/missions/${encodeURIComponent(missionId)}/runs/${encodeURIComponent(runId)}`,
      };
      this.store(settingKey, requestHash, response, actorId, now);
      return response;
    });
  }

  private timestamp(): string {
    return this.clock().toISOString();
  }

  private source(missionId: string, runId: string): SourceRow {
    const row = this.database.prepare(`
      SELECT
        m.id AS mission_id, m.name AS mission_name, m.objective AS mission_objective,
        m.journey AS mission_journey, m.status AS mission_status,
        m.version AS mission_version, m.engagement_id, m.success_criteria_json,
        r.id AS run_id, r.journey AS run_journey, r.status AS run_status,
        r.status_reason AS run_status_reason, r.version AS run_version, r.contract_id,
        mc.version AS contract_version, mc.state AS contract_state,
        mc.contract_hash, mc.authorization_json, mc.action_policy_json,
        mc.budgets_json, mc.safe_stop_json, mc.deliverables_json,
        mc.memory_scopes_json
      FROM missions m
      JOIN runs r ON r.mission_id = m.id AND r.id = ?
      LEFT JOIN mission_contracts mc ON mc.id = r.contract_id
      WHERE m.id = ?
    `).get(runId, missionId) as SourceRow | undefined;
    if (!row) {
      throw new MissionApiError(404, "autonomous_branch_source_not_found", "Mission or source run was not found", {
        humanMessage: "The selected mission run is no longer available.",
        category: "not_found",
      });
    }
    if (
      row.mission_journey !== "autonomous" || row.run_journey !== "autonomous" ||
      !row.contract_id || !row.contract_version || !row.contract_hash || !row.contract_state
    ) {
      throw new MissionApiError(409, "autonomous_contract_unavailable", "The source is not a contract-bound Autonomous run", {
        humanMessage: "Only a contract-bound Autonomous run can create this branch.",
        category: "contract",
      });
    }
    return row;
  }

  private requestForSource(source: SourceRow): AutonomousMissionRequest {
    const snapshot = this.database.prepare(`
      SELECT request_json FROM mission_contract_snapshots WHERE contract_id = ?
    `).get(source.contract_id) as { request_json: string } | undefined;
    if (snapshot) return this.validStoredRequest(JSON.parse(snapshot.request_json) as unknown);
    const authorization = parseObject(source.authorization_json);
    const policy = parseObject(source.action_policy_json);
    const budgets = parseObject(source.budgets_json);
    const safeStop = parseObject(source.safe_stop_json);
    return this.validStoredRequest({
      journey: "autonomous",
      launch: true,
      title: source.mission_name,
      objective: source.mission_objective,
      successCriteria: parseArray(source.success_criteria_json),
      authorization,
      contract: {
        allowedActionClasses: policy.allowedActionClasses,
        prohibitedActionClasses: policy.prohibitedActionClasses,
        destructivePolicy: policy.destructivePolicy,
        boundedDestructiveTargets: policy.boundedDestructiveTargets,
        evidenceRequirements: policy.evidenceRequirements,
        timeBudgetMinutes: budgets.timeBudgetMinutes,
        toolCallBudget: budgets.toolCalls ?? budgets.toolCallBudget ?? undefined,
        tokenBudget: budgets.tokenBudget ?? undefined,
        costBudget: budgets.costBudget ?? undefined,
        retryBudget: budgets.retryBudget,
        replanBudget: budgets.replanBudget,
        concurrencyLimit: budgets.concurrencyLimit,
        evidenceStorageBudgetBytes: budgets.evidenceBytes,
        artifactStorageBudgetBytes: budgets.artifactBytes,
        notificationPolicy: policy.notificationPolicy,
        reportingFormat: policy.reportingFormat,
        dataHandlingPolicy: policy.dataHandlingPolicy,
        retentionPolicy: policy.retentionPolicy,
        providerPolicy: policy.providerPolicy,
        planningSelection: policy.planningSelection,
        toolPolicy: policy.toolPolicy,
        specialistAgentIds: policy.specialistAgentIds,
        agentModelAssignments: policy.agentModelAssignments,
        memoryScopes: parseArray(source.memory_scopes_json),
        contextNodeIds: policy.contextNodeIds,
        safeStopConditions: safeStop.conditions,
        deliverables: parseArray(source.deliverables_json),
      },
    });
  }

  private requestFromSnapshot(contract: ContractRow): AutonomousMissionRequest {
    if (!contract.request_json) {
      throw new MissionApiError(409, "contract_snapshot_missing", "The contract snapshot is unavailable", {
        humanMessage: "This draft cannot be confirmed because its immutable full-contract snapshot is unavailable.",
        category: "contract",
      });
    }
    return this.validRequest(JSON.parse(contract.request_json) as unknown);
  }

  private validRequest(value: unknown): AutonomousMissionRequest {
    const request = validateMissionCreateRequest(value);
    if (request.journey !== "autonomous") {
      throw new MissionApiError(409, "autonomous_contract_corrupt", "Stored contract is not Autonomous", {
        category: "contract",
      });
    }
    return withoutReview(request);
  }

  private validStoredRequest(value: unknown): AutonomousMissionRequest {
    const root = value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : {};
    const contract = root.contract && typeof root.contract === "object"
      && !Array.isArray(root.contract)
      ? root.contract as Record<string, unknown>
      : {};
    const specialistAgentIds = Array.isArray(contract.specialistAgentIds)
      ? contract.specialistAgentIds
      : [];
    const assignments = Array.isArray(contract.agentModelAssignments)
      ? contract.agentModelAssignments
      : null;
    if (
      assignments === null
      || (specialistAgentIds.length > 0 && assignments.length === 0)
    ) {
      return withoutReview(validateLegacyAutonomousMissionRequest(value));
    }
    return this.validRequest(value);
  }

  private branchSafety(source: SourceRow): { readonly safe: boolean; readonly reason: string } {
    if (TERMINAL.has(source.run_status)) {
      return { safe: true, reason: `Source run is terminal (${source.run_status}).` };
    }
    if (source.run_status !== "blocked" || !source.run_status_reason?.startsWith("Paused by operator:")) {
      return { safe: false, reason: "Pause at a durable checkpoint or cancel the active source run before branching." };
    }
    const control = this.database.prepare(`
      SELECT action FROM audit_records
      WHERE run_id = ? AND action IN ('run.paused', 'run.resumed', 'run.cancelled')
      ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get(source.run_id) as { action: string } | undefined;
    if (control?.action !== "run.paused") {
      return { safe: false, reason: "The source run does not have a current durable operator-pause record." };
    }
    const active = this.database.prepare(`
      SELECT
        (SELECT COUNT(*) FROM actions WHERE run_id = ? AND status = 'running') +
        (SELECT COUNT(*) FROM tool_calls tc JOIN actions a ON a.id = tc.action_id
          WHERE a.run_id = ? AND tc.status = 'running') AS count
    `).get(source.run_id, source.run_id) as { count: number };
    if (active.count > 0) {
      return { safe: false, reason: "The paused source still has in-flight work; cancel it before branching." };
    }
    return { safe: true, reason: "Source run is paused at a durable checkpoint with no in-flight action." };
  }

  private assertSafeToBranch(source: SourceRow): void {
    const safety = this.branchSafety(source);
    if (!safety.safe) {
      throw new MissionApiError(409, "source_run_must_stop", "The source run is not safely stopped", {
        humanMessage: safety.reason,
        category: "conflict",
        remediation: "Use the existing Pause or Cancel runtime control, refresh the run, then rerun contract preflight.",
      });
    }
  }

  private assertCurrentConfirmedContract(source: SourceRow): void {
    const latest = this.database.prepare(`
      SELECT id, version FROM mission_contracts
      WHERE mission_id = ? AND state = 'confirmed'
      ORDER BY version DESC LIMIT 1
    `).get(source.mission_id) as { id: string; version: number } | undefined;
    if (source.contract_state !== "confirmed" || latest?.id !== source.contract_id) {
      throw new MissionApiError(409, "source_contract_superseded", "The source contract is not the current confirmed version", {
        humanMessage: "This source run uses a superseded or unavailable contract and cannot authorize another run.",
        category: "contract",
        remediation: "Refresh the mission and branch from the latest confirmed contract-bound run.",
      });
    }
  }

  private assertNoOtherActiveRun(missionId: string, sourceRunId: string): void {
    const row = this.database.prepare(`
      SELECT id, status FROM runs
      WHERE mission_id = ? AND id != ? AND status NOT IN ('completed', 'failed', 'cancelled')
      ORDER BY created_at DESC LIMIT 1
    `).get(missionId, sourceRunId) as { id: string; status: string } | undefined;
    if (row) {
      throw new MissionApiError(409, "another_run_is_active", "Another mission run is nonterminal", {
        humanMessage: "Another run on this mission must be paused or cancelled before a new branch can start.",
        category: "conflict",
        details: { runId: row.id, status: row.status },
      });
    }
  }

  private nextContractVersion(missionId: string): number {
    const row = this.database.prepare(`
      SELECT COALESCE(MAX(version), 0) + 1 AS version FROM mission_contracts WHERE mission_id = ?
    `).get(missionId) as { version: number };
    return row.version;
  }

  private contract(contractId: string): ContractRow {
    const row = this.database.prepare(`
      SELECT mc.*, mcs.source_contract_id, mcs.request_json
      FROM mission_contracts mc
      LEFT JOIN mission_contract_snapshots mcs ON mcs.contract_id = mc.id
      WHERE mc.id = ?
    `).get(contractId) as ContractRow | undefined;
    if (!row) throw new MissionApiError(409, "contract_unavailable", "Contract is unavailable", { category: "contract" });
    return row;
  }

  private draftContract(missionId: string, contractId: string | undefined, sourceContractId: string): ContractRow {
    if (!contractId) {
      throw new MissionApiError(400, "draft_contract_required", "Draft contract ID is required", { category: "invalid_input" });
    }
    const row = this.contract(contractId);
    if (
      row.mission_id !== missionId || row.state !== "draft" ||
      row.source_contract_id !== sourceContractId || !row.request_json
    ) {
      throw new MissionApiError(409, "draft_contract_stale", "Draft contract no longer matches this source", {
        humanMessage: "The selected amendment draft is stale or belongs to another contract lineage.",
        category: "contract",
        remediation: "Rerun amendment preflight from the current source run.",
      });
    }
    return row;
  }

  private insertContract(
    contractId: string,
    missionId: string,
    version: number,
    state: "draft" | "confirmed",
    hash: string,
    request: AutonomousMissionRequest,
    confirmedBy: string | null,
    confirmedAt: string | null,
    now: string,
  ): void {
    const budget = {
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
    };
    this.database.prepare(`
      INSERT INTO mission_contracts (
        id, mission_id, version, state, contract_hash,
        authorization_json, action_policy_json, budgets_json,
        safe_stop_json, deliverables_json, memory_scopes_json,
        confirmed_by, confirmed_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      contractId, missionId, version, state, hash,
      canonicalJson(request.authorization),
      canonicalJson({
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
        planningSelection: resolveAutonomousPlanningSelection(
          request.contract.planningSelection,
        ),
        toolPolicy: request.contract.toolPolicy,
        specialistAgentIds: request.contract.specialistAgentIds,
        agentModelAssignments: request.contract.agentModelAssignments,
        contextNodeIds: request.contract.contextNodeIds,
      }),
      canonicalJson(budget),
      canonicalJson({ conditions: request.contract.safeStopConditions }),
      canonicalJson(request.contract.deliverables),
      canonicalJson(request.contract.memoryScopes),
      confirmedBy, confirmedAt, now,
    );
  }

  private ensureSourceSnapshot(
    source: SourceRow,
    request: AutonomousMissionRequest,
    actorId: string,
    now: string,
  ): void {
    this.database.prepare(`
      INSERT OR IGNORE INTO mission_contract_snapshots (
        contract_id, mission_id, source_contract_id, request_json,
        amendment_reason, created_by, created_at
      ) VALUES (?, ?, NULL, ?, NULL, ?, ?)
    `).run(source.contract_id, source.mission_id, canonicalJson(request), actorId, now);
  }

  private updateMissionProjection(missionId: string, request: AutonomousMissionRequest, now: string): void {
    const scope = {
      allowedTargets: request.authorization.allowedTargets,
      prohibitedTargets: request.authorization.prohibitedTargets,
      environmentClassification:
        request.authorization.environmentClassification ?? null,
      timeWindow: request.authorization.timeWindow ?? null,
      dataHandling: request.authorization.dataHandling ?? null,
    };
    const retention = {
      mode: request.contract.retentionPolicy,
      dataHandling: request.contract.dataHandlingPolicy,
    };
    const memory = {
      allowedScopes: request.contract.memoryScopes,
      exactContextNodeIds: request.contract.contextNodeIds,
    };
    this.database.prepare(`
      UPDATE missions SET name = ?, objective = ?, status = 'active',
        authorization_status = 'verified', engagement_id = ?, scope_json = ?,
        success_criteria_json = ?, retention_policy_json = ?, memory_policy_json = ?,
        version = version + 1, updated_at = ? WHERE id = ?
    `).run(
      request.title, request.objective, request.authorization.engagementId ?? null,
      canonicalJson(scope), canonicalJson(request.successCriteria),
      canonicalJson(retention), canonicalJson(memory), now, missionId,
    );
    this.database.prepare("DELETE FROM mission_targets WHERE mission_id = ?").run(missionId);
    const insertTarget = this.database.prepare(`
      INSERT INTO mission_targets (
        id, mission_id, target, target_type, disposition,
        normalized_target, metadata_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, '{}', ?)
    `);
    for (const target of request.authorization.allowedTargets) {
      insertTarget.run(id("target"), missionId, target, targetType(target), "allowed", normalizeTarget(target), now);
    }
    for (const target of request.authorization.prohibitedTargets) {
      insertTarget.run(id("target"), missionId, target, targetType(target), "prohibited", normalizeTarget(target), now);
    }
    const upsert = this.database.prepare(`
      INSERT INTO mission_constraints (
        id, mission_id, constraint_type, value_json, source, created_at
      ) VALUES (?, ?, ?, ?, 'operator', ?)
      ON CONFLICT(mission_id, constraint_type, source)
      DO UPDATE SET value_json = excluded.value_json, created_at = excluded.created_at
    `);
    upsert.run(id("constraint"), missionId, "authorization", canonicalJson(request.authorization), now);
    upsert.run(id("constraint"), missionId, "action_policy", canonicalJson({
      allowedActionClasses: request.contract.allowedActionClasses,
      prohibitedActionClasses: request.contract.prohibitedActionClasses,
      destructivePolicy: request.contract.destructivePolicy,
      boundedDestructiveTargets: request.contract.boundedDestructiveTargets ?? [],
      specialistAgentIds: request.contract.specialistAgentIds,
      planningSelection: resolveAutonomousPlanningSelection(
        request.contract.planningSelection,
      ),
      agentModelAssignments: request.contract.agentModelAssignments,
    }), now);
    upsert.run(id("constraint"), missionId, "evidence_requirements", canonicalJson(request.contract.evidenceRequirements), now);
    upsert.run(id("constraint"), missionId, "data_retention", canonicalJson({
      dataHandlingPolicy: request.contract.dataHandlingPolicy,
      retentionPolicy: request.contract.retentionPolicy,
      operatorConstraints: request.authorization.dataHandling ?? null,
    }), now);
    upsert.run(id("constraint"), missionId, "delivery_policy", canonicalJson({
      notificationPolicy: request.contract.notificationPolicy,
      reportingFormat: request.contract.reportingFormat,
      providerPolicy: request.contract.providerPolicy,
      toolPolicy: request.contract.toolPolicy,
    }), now);
  }

  private stored<T>(key: string, requestHash: string): T | undefined {
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(key) as { value_json: string } | undefined;
    if (!row) return undefined;
    const stored = JSON.parse(row.value_json) as StoredMutation<T>;
    if (stored.requestHash !== requestHash) throw new IdempotencyConflictError();
    return stored.response;
  }

  private store<T>(key: string, requestHash: string, response: T, actorId: string, now: string): void {
    this.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', 1, ?, ?)
    `).run(key, canonicalJson({ requestHash, response }), actorId, now);
  }

  private appendAudit(input: {
    readonly missionId: string;
    readonly runId: string;
    readonly actorId: string;
    readonly action: string;
    readonly resourceType: string;
    readonly resourceId: string;
    readonly reason: string;
    readonly details: Record<string, unknown>;
    readonly now: string;
  }): void {
    const previous = this.database.prepare(`
      SELECT record_hash FROM audit_records ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get() as { record_hash: string } | undefined;
    const auditId = id("audit");
    const recordHash = hashCanonical({
      id: auditId,
      previousHash: previous?.record_hash ?? null,
      journey: "autonomous",
      actorId: input.actorId,
      action: input.action,
      missionId: input.missionId,
      runId: input.runId,
      reason: input.reason,
      details: input.details,
      occurredAt: input.now,
    });
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json,
        previous_hash, record_hash, occurred_at
      ) VALUES (?, ?, ?, 'autonomous', 'operator', ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      auditId, input.missionId, input.runId, input.actorId, input.action,
      input.resourceType, input.resourceId, input.reason,
      canonicalJson(input.details), previous?.record_hash ?? null, recordHash, input.now,
    );
  }

  private staleSource(): MissionApiError {
    return new MissionApiError(409, "source_run_changed", "The source run changed after review", {
      humanMessage: "The source run changed after this branch was reviewed.",
      category: "conflict",
      remediation: "Refresh the source run and rerun branch preflight.",
    });
  }
}

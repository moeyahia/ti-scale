import { randomUUID } from "node:crypto";
import { inImmediateTransaction, type SqliteDatabase } from "../db";
import {
  parseMissionMemoryPolicy,
  retrieveMissionBrainContext,
  type BrainContextService,
} from "../brain-runtime";
import { canonicalObject, canonicalValue } from "./serialization";
import { AttackAttemptRepository } from "./AttackAttemptRepository";
import {
  RunIntelligenceError,
  type AttackAttempt,
  type AttackAttemptEvidenceRelationship,
  type AttackAttemptStatus,
  type CreateAttackAttemptInput,
  type ToolFailureSignal,
} from "./types";

const NON_TERMINAL_TRANSITIONS: Readonly<Record<AttackAttemptStatus, readonly AttackAttemptStatus[]>> = {
  planned: ["ready", "blocked", "cancelled"],
  ready: ["running", "blocked", "waiting_conditions", "cancelled"],
  running: ["blocked", "waiting_conditions", "cancelled"],
  blocked: ["ready", "waiting_conditions", "cancelled"],
  waiting_conditions: ["ready", "blocked", "cancelled"],
  succeeded: [],
  failed: [],
  safely_aborted: [],
  cancelled: [],
};

const COMPLETION_SOURCES: Readonly<Record<"succeeded" | "failed" | "safely_aborted", readonly AttackAttemptStatus[]>> = {
  succeeded: ["running"],
  failed: ["running"],
  safely_aborted: ["ready", "running", "blocked", "waiting_conditions"],
};

function text(value: string, label: string): string {
  const normalized = value.normalize("NFKC").trim();
  if (!normalized) throw new RunIntelligenceError("invalid_attack_attempt", `${label} is required`);
  if (normalized.length > 4_000) throw new RunIntelligenceError("invalid_attack_attempt", `${label} exceeds 4,000 characters`);
  return normalized;
}

function iso(value: string, label: string): string {
  if (!Number.isFinite(Date.parse(value))) throw new RunIntelligenceError("invalid_timestamp", `${label} must be an ISO timestamp`);
  return value;
}

export class AttackAttemptService {
  readonly repository: AttackAttemptRepository;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
    private readonly brainContext?: BrainContextService,
  ) {
    this.repository = new AttackAttemptRepository(database);
  }

  create(input: CreateAttackAttemptInput): AttackAttempt {
    if (!input.targetAssetId && !input.targetServiceId) {
      throw new RunIntelligenceError("attack_target_required", "An attack attempt needs a canonical target asset or service");
    }
    const normalized: CreateAttackAttemptInput = {
      ...input,
      objective: text(input.objective, "Attack objective"),
      techniqueName: text(input.techniqueName, "Technique name"),
      actionClass: text(input.actionClass, "Action class"),
      prerequisites: (input.prerequisites ?? []).map((item) => canonicalValue(item)),
      normalizedParameters: canonicalObject(input.normalizedParameters ?? {}),
    };
    const now = this.clock().toISOString();
    return inImmediateTransaction(this.database, () => {
      this.repository.assertCreateReferences(normalized);
      return this.repository.insert({ ...normalized, id: `attempt_${randomUUID()}`, now });
    });
  }

  get(id: string): AttackAttempt {
    return this.repository.get(id);
  }

  listForRun(runId: string): AttackAttempt[] {
    return this.repository.listForRun(runId);
  }

  transition(input: {
    readonly attemptId: string;
    readonly expectedVersion: number;
    readonly status: "ready" | "running" | "blocked" | "waiting_conditions" | "cancelled";
    readonly reason?: string;
    readonly at?: string;
    readonly actorId?: string;
    readonly actorType?: "operator" | "agent" | "worker" | "system";
  }): AttackAttempt {
    const at = iso(input.at ?? this.clock().toISOString(), "Transition time");
    const preflight = this.repository.get(input.attemptId);
    if (preflight.version !== input.expectedVersion) {
      throw new RunIntelligenceError(
        "attack_attempt_transition_conflict",
        "Attack attempt state or version changed; reload it before applying an outcome",
      );
    }
    if (!NON_TERMINAL_TRANSITIONS[preflight.status].includes(input.status)) {
      throw new RunIntelligenceError(
        "invalid_attack_attempt_transition",
        `Attack attempt cannot transition from ${preflight.status} to ${input.status}`,
      );
    }
    // Persist the blocked/degraded/ready Context Pack and coverage receipt
    // outside the state transaction so a required-memory failure remains
    // explainable instead of being rolled back with the refused transition.
    if (input.status === "running" && this.brainContext) {
      if (!preflight.stepId) {
        throw new RunIntelligenceError(
          "attack_attempt_step_required_for_brain_context",
          "A represented attack attempt cannot start without a canonical plan step for scoped Second Brain retrieval",
        );
      }
      const scope = this.database.prepare(`
        SELECT r.journey, m.memory_policy_json
        FROM runs r JOIN missions m ON m.id = r.mission_id
        WHERE r.id = ? AND r.mission_id = ?
      `).get(preflight.runId, preflight.missionId) as {
        readonly journey: "autonomous" | "guided";
        readonly memory_policy_json: string;
      } | undefined;
      if (!scope) {
        throw new RunIntelligenceError("attack_attempt_scope_missing", "Attack attempt mission/run scope is unavailable");
      }
      const context = retrieveMissionBrainContext({
        brainContext: this.brainContext,
        hook: "attack_attempt",
        journey: scope.journey,
        missionId: preflight.missionId,
        runId: preflight.runId,
        stepId: preflight.stepId,
        actorId: input.actorId ?? preflight.assignedAgentId ?? "attack-attempt-service",
        actorType: input.actorType ?? (preflight.assignedAgentId ? "agent" : "system"),
        query: `Start the represented ${preflight.techniqueName} attempt against its exact canonical target using only in-scope prerequisites, evidence rules, and failure memory.`,
        queryRedacted: "Start the represented attack attempt using only in-scope prerequisites, evidence rules, and failure memory.",
        memoryPolicy: parseMissionMemoryPolicy(scope.memory_policy_json),
      });
      this.brainContext.recordUnusedContext(
        context,
        "The deterministic attack-attempt start gate used memory only for scoped readiness and audit context; it did not silently change the represented target, technique, or parameters.",
      );
    }
    return inImmediateTransaction(this.database, () => {
      const current = this.repository.get(input.attemptId);
      if (!NON_TERMINAL_TRANSITIONS[current.status].includes(input.status)) {
        throw new RunIntelligenceError(
          "invalid_attack_attempt_transition",
          `Attack attempt cannot transition from ${current.status} to ${input.status}`,
        );
      }
      return this.repository.updateStatus({
        attemptId: current.id,
        expectedVersion: input.expectedVersion,
        fromStatuses: [current.status],
        status: input.status,
        ...(input.reason ? { outcomeSummary: text(input.reason, "Transition reason") } : {}),
        ...(input.status === "running" ? { startedAt: at } : {}),
        ...(input.status === "cancelled" ? { endedAt: at } : {}),
        now: at,
      });
    });
  }

  linkEvidence(input: {
    readonly attemptId: string;
    readonly evidenceId: string;
    readonly relationship: AttackAttemptEvidenceRelationship;
    readonly at?: string;
  }): AttackAttempt {
    const at = iso(input.at ?? this.clock().toISOString(), "Evidence link time");
    return inImmediateTransaction(this.database, () => {
      const attempt = this.repository.get(input.attemptId);
      this.repository.evidenceReference(attempt, input.evidenceId);
      this.repository.linkEvidence(attempt.id, input.evidenceId, input.relationship, at);
      return this.repository.get(attempt.id);
    });
  }

  complete(input: {
    readonly attemptId: string;
    readonly expectedVersion: number;
    readonly outcome: "succeeded" | "failed" | "safely_aborted";
    readonly outcomeSummary: string;
    readonly failureCategory?: string;
    readonly failureDiagnosisId?: string;
    readonly evidence?: readonly {
      readonly evidenceId: string;
      readonly relationship: "supports" | "contradicts" | "context" | "outcome";
    }[];
    readonly endedAt?: string;
  }): AttackAttempt {
    const endedAt = iso(input.endedAt ?? this.clock().toISOString(), "Attack outcome time");
    return inImmediateTransaction(this.database, () => {
      const attempt = this.repository.get(input.attemptId);
      if (!COMPLETION_SOURCES[input.outcome].includes(attempt.status)) {
        throw new RunIntelligenceError(
          "invalid_attack_attempt_transition",
          `Attack attempt cannot complete as ${input.outcome} from ${attempt.status}`,
        );
      }
      if (input.outcome === "failed" && !input.failureCategory?.trim()) {
        throw new RunIntelligenceError("failure_category_required", "A failed attack attempt needs an explicit failure category");
      }
      if (input.outcome !== "failed" && input.failureCategory !== undefined) {
        throw new RunIntelligenceError("unexpected_failure_category", "Only a failed attack attempt may record a failure category");
      }
      for (const link of input.evidence ?? []) {
        this.repository.evidenceReference(attempt, link.evidenceId);
        this.repository.linkEvidence(attempt.id, link.evidenceId, link.relationship, endedAt);
      }
      if (input.outcome === "succeeded" && this.repository.countVerifiedOutcomeEvidence(attempt.id) === 0) {
        throw new RunIntelligenceError(
          "verified_outcome_evidence_required",
          "A successful attack attempt requires verified supporting or outcome evidence",
        );
      }
      return this.repository.updateStatus({
        attemptId: attempt.id,
        expectedVersion: input.expectedVersion,
        fromStatuses: COMPLETION_SOURCES[input.outcome],
        status: input.outcome,
        outcomeSummary: text(input.outcomeSummary, "Outcome summary"),
        ...(input.failureCategory ? { failureCategory: text(input.failureCategory, "Failure category") } : {}),
        ...(input.failureDiagnosisId ? { failureDiagnosisId: input.failureDiagnosisId } : {}),
        endedAt,
        now: endedAt,
      });
    });
  }

  observeToolFailure(attemptId: string, toolCallId: string): ToolFailureSignal {
    return this.repository.observeToolFailure(attemptId, toolCallId);
  }
}

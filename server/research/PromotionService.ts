import { deepFreeze } from "./canonical";

export const PROMOTION_STATES = [
  "proposed",
  "policy_rejected",
  "queued",
  "running",
  "early_aborted",
  "failed",
  "benchmarked",
  "holdout_failed",
  "shadow_ready",
  "shadow_running",
  "canary_ready",
  "canary_running",
  "verified",
  "rejected",
  "stale",
  "superseded",
  "rolled_back",
] as const;

export type PromotionState = (typeof PROMOTION_STATES)[number];
export type PromotionActorKind = "local_policy" | "local_evaluator" | "human_reviewer";

export interface PromotionMilestones {
  readonly developmentPassed: boolean;
  readonly validationPassed: boolean;
  readonly hiddenHoldoutPassed: boolean;
  readonly humanReviewApproved: boolean;
  readonly shadowPassed: boolean;
  readonly canaryPassed: boolean;
}

export interface PromotionHistoryEntry {
  readonly sequence: number;
  readonly from: PromotionState;
  readonly to: PromotionState;
  readonly actorId: string;
  readonly actorKind: PromotionActorKind;
  readonly rationale: string;
  readonly evidenceRefs: readonly string[];
  readonly occurredAt: string;
}

export interface PromotionRecord {
  readonly strategyVersionId: string;
  readonly state: PromotionState;
  readonly milestones: PromotionMilestones;
  readonly history: readonly PromotionHistoryEntry[];
}

export interface PromotionDecisionContext {
  readonly actorId: string;
  readonly actorKind: PromotionActorKind;
  readonly rationale: string;
  readonly evidenceRefs: readonly string[];
  readonly occurredAt: string;
}

export interface StrategyRollbackRecord {
  readonly fromStrategyVersionId: string;
  readonly toStrategyVersionId: string;
  readonly reason: string;
  readonly initiatedBy: string;
  readonly integrityVerified: true;
  readonly rolledBackAt: string;
}

function initialMilestones(): PromotionMilestones {
  return {
    developmentPassed: false,
    validationPassed: false,
    hiddenHoldoutPassed: false,
    humanReviewApproved: false,
    shadowPassed: false,
    canaryPassed: false,
  };
}

function requireActor(context: PromotionDecisionContext, kind: PromotionActorKind): void {
  if (context.actorKind !== kind || context.actorId.trim().length === 0) {
    throw new Error(`Promotion action requires a named ${kind}.`);
  }
  if (context.rationale.trim().length === 0) throw new Error("Promotion action requires a rationale.");
  if (
    context.evidenceRefs.length === 0 ||
    context.evidenceRefs.some((reference) => reference.trim().length === 0)
  ) {
    throw new Error("Promotion action requires at least one stable evidence reference.");
  }
  if (!Number.isFinite(Date.parse(context.occurredAt))) {
    throw new Error("Promotion action requires a valid decision timestamp.");
  }
}

const ALLOWED_TRANSITIONS: Readonly<Record<PromotionState, readonly PromotionState[]>> = {
  proposed: ["queued", "policy_rejected", "rejected"],
  policy_rejected: [],
  queued: ["running", "rejected"],
  running: ["running", "early_aborted", "failed", "benchmarked", "rejected"],
  early_aborted: [],
  failed: [],
  benchmarked: ["benchmarked", "holdout_failed", "shadow_ready", "rejected", "stale"],
  holdout_failed: [],
  shadow_ready: ["shadow_running", "rejected"],
  shadow_running: ["shadow_running", "canary_ready", "rejected", "rolled_back"],
  canary_ready: ["canary_running", "rejected"],
  canary_running: ["canary_running", "verified", "rejected", "rolled_back"],
  verified: ["rejected", "stale", "superseded", "rolled_back"],
  rejected: [],
  stale: [],
  superseded: [],
  rolled_back: [],
};

function requiredTransitionActor(from: PromotionState, to: PromotionState): PromotionActorKind {
  if (from === "proposed" && (to === "queued" || to === "policy_rejected")) return "local_policy";
  if (
    (from === "queued" && to === "running") ||
    (from === "running" && to !== "rejected") ||
    (from === "benchmarked" && (to === "benchmarked" || to === "holdout_failed")) ||
    (from === "shadow_running" && to === "shadow_running") ||
    (from === "canary_running" && to === "canary_running")
  ) return "local_evaluator";
  return "human_reviewer";
}

function assertRecordIntegrity(record: PromotionRecord): void {
  if (record.strategyVersionId.trim().length === 0) throw new Error("Promotion record has no strategy identity.");
  let state: PromotionState = "proposed";
  for (const [index, entry] of record.history.entries()) {
    if (entry.sequence !== index + 1 || entry.from !== state) {
      throw new Error("Promotion history sequence or source state is invalid.");
    }
    if (!ALLOWED_TRANSITIONS[state].includes(entry.to)) {
      throw new Error(`Promotion history contains forbidden transition ${state} to ${entry.to}.`);
    }
    if (entry.actorKind !== requiredTransitionActor(state, entry.to)) {
      throw new Error(`Promotion transition ${state} to ${entry.to} has the wrong decision authority.`);
    }
    if (
      entry.actorId.trim().length === 0 ||
      entry.rationale.trim().length === 0 ||
      entry.evidenceRefs.length === 0 ||
      !Number.isFinite(Date.parse(entry.occurredAt))
    ) {
      throw new Error("Promotion history contains an incomplete decision record.");
    }
    state = entry.to;
  }
  if (state !== record.state) throw new Error("Promotion record state does not match its history.");
  const hasTransition = (from: PromotionState, to: PromotionState) =>
    record.history.some((entry) => entry.from === from && entry.to === to);
  const expectedMilestones: PromotionMilestones = {
    developmentPassed: hasTransition("running", "running"),
    validationPassed: hasTransition("running", "benchmarked"),
    hiddenHoldoutPassed: hasTransition("benchmarked", "benchmarked"),
    humanReviewApproved: hasTransition("benchmarked", "shadow_ready"),
    shadowPassed: hasTransition("shadow_running", "shadow_running"),
    canaryPassed: hasTransition("canary_running", "canary_running"),
  };
  for (const key of Object.keys(expectedMilestones) as (keyof PromotionMilestones)[]) {
    if (record.milestones[key] !== expectedMilestones[key]) {
      throw new Error(`Promotion milestone ${key} does not match immutable history.`);
    }
  }
}

function move(
  record: PromotionRecord,
  to: PromotionState,
  context: PromotionDecisionContext,
  milestones: PromotionMilestones = record.milestones,
): PromotionRecord {
  return deepFreeze({
    ...record,
    state: to,
    milestones,
    history: [
      ...record.history,
      {
        sequence: record.history.length + 1,
        from: record.state,
        to,
        actorId: context.actorId,
        actorKind: context.actorKind,
        rationale: context.rationale,
        evidenceRefs: [...context.evidenceRefs],
        occurredAt: context.occurredAt,
      },
    ],
  });
}

function requireState(record: PromotionRecord, expected: PromotionState): void {
  assertRecordIntegrity(record);
  if (record.state !== expected) {
    throw new Error(`Cannot advance ${record.strategyVersionId} from ${record.state}; expected ${expected}.`);
  }
}

export class PromotionService {
  create(strategyVersionId: string): PromotionRecord {
    if (strategyVersionId.trim().length === 0) throw new Error("Strategy version ID is required.");
    return deepFreeze({
      strategyVersionId,
      state: "proposed",
      milestones: initialMilestones(),
      history: [],
    });
  }

  policyDecision(
    record: PromotionRecord,
    accepted: boolean,
    context: PromotionDecisionContext,
  ): PromotionRecord {
    requireState(record, "proposed");
    requireActor(context, "local_policy");
    return move(record, accepted ? "queued" : "policy_rejected", context);
  }

  startBenchmark(record: PromotionRecord, context: PromotionDecisionContext): PromotionRecord {
    requireState(record, "queued");
    requireActor(context, "local_evaluator");
    return move(record, "running", context);
  }

  developmentResult(
    record: PromotionRecord,
    passed: boolean,
    context: PromotionDecisionContext,
  ): PromotionRecord {
    requireState(record, "running");
    requireActor(context, "local_evaluator");
    if (!passed) return move(record, "early_aborted", context);
    return move(record, "running", context, { ...record.milestones, developmentPassed: true });
  }

  validationResult(
    record: PromotionRecord,
    passed: boolean,
    context: PromotionDecisionContext,
  ): PromotionRecord {
    requireState(record, "running");
    requireActor(context, "local_evaluator");
    if (!record.milestones.developmentPassed) {
      throw new Error("Validation cannot run before development passes.");
    }
    if (!passed) return move(record, "failed", context);
    return move(record, "benchmarked", context, { ...record.milestones, validationPassed: true });
  }

  hiddenHoldoutResult(
    record: PromotionRecord,
    passed: boolean,
    context: PromotionDecisionContext,
  ): PromotionRecord {
    requireState(record, "benchmarked");
    requireActor(context, "local_evaluator");
    if (!record.milestones.validationPassed) {
      throw new Error("Hidden holdout cannot run before validation passes.");
    }
    if (!passed) return move(record, "holdout_failed", context);
    return move(record, "benchmarked", context, { ...record.milestones, hiddenHoldoutPassed: true });
  }

  humanReview(
    record: PromotionRecord,
    approved: boolean,
    context: PromotionDecisionContext,
  ): PromotionRecord {
    requireState(record, "benchmarked");
    requireActor(context, "human_reviewer");
    if (!record.milestones.hiddenHoldoutPassed) {
      throw new Error("Human promotion review cannot approve before hidden holdout passes.");
    }
    if (!approved) return move(record, "rejected", context);
    return move(record, "shadow_ready", context, { ...record.milestones, humanReviewApproved: true });
  }

  startShadow(record: PromotionRecord, context: PromotionDecisionContext): PromotionRecord {
    requireState(record, "shadow_ready");
    requireActor(context, "human_reviewer");
    return move(record, "shadow_running", context);
  }

  shadowResult(
    record: PromotionRecord,
    passed: boolean,
    context: PromotionDecisionContext,
  ): PromotionRecord {
    requireState(record, "shadow_running");
    requireActor(context, "local_evaluator");
    if (!passed) return move(record, "rejected", context);
    return move(record, "shadow_running", context, { ...record.milestones, shadowPassed: true });
  }

  approveCanary(record: PromotionRecord, context: PromotionDecisionContext): PromotionRecord {
    requireState(record, "shadow_running");
    requireActor(context, "human_reviewer");
    if (!record.milestones.shadowPassed) throw new Error("Canary cannot be approved before shadow passes.");
    return move(record, "canary_ready", context);
  }

  startCanary(record: PromotionRecord, context: PromotionDecisionContext): PromotionRecord {
    requireState(record, "canary_ready");
    requireActor(context, "human_reviewer");
    return move(record, "canary_running", context);
  }

  canaryResult(
    record: PromotionRecord,
    passed: boolean,
    context: PromotionDecisionContext,
  ): PromotionRecord {
    requireState(record, "canary_running");
    requireActor(context, "local_evaluator");
    if (!passed) return move(record, "rejected", context);
    return move(record, "canary_running", context, { ...record.milestones, canaryPassed: true });
  }

  verify(record: PromotionRecord, context: PromotionDecisionContext): PromotionRecord {
    requireState(record, "canary_running");
    requireActor(context, "human_reviewer");
    if (!record.milestones.canaryPassed) throw new Error("Verification cannot occur before bounded canary passes.");
    return move(record, "verified", context);
  }

  reject(record: PromotionRecord, context: PromotionDecisionContext): PromotionRecord {
    assertRecordIntegrity(record);
    requireActor(context, "human_reviewer");
    if (["policy_rejected", "rejected", "rolled_back", "superseded"].includes(record.state)) {
      throw new Error(`Cannot reject terminal promotion state ${record.state}.`);
    }
    return move(record, "rejected", context);
  }

  markStale(record: PromotionRecord, context: PromotionDecisionContext): PromotionRecord {
    assertRecordIntegrity(record);
    requireActor(context, "human_reviewer");
    if (record.state !== "verified" && record.state !== "benchmarked") {
      throw new Error("Only benchmarked or verified strategies can be marked stale.");
    }
    return move(record, "stale", context);
  }

  supersede(record: PromotionRecord, context: PromotionDecisionContext): PromotionRecord {
    requireActor(context, "human_reviewer");
    requireState(record, "verified");
    return move(record, "superseded", context);
  }

  rollback(
    record: PromotionRecord,
    target: { readonly strategyVersionId: string; readonly state: PromotionState },
    integrityVerified: boolean,
    context: PromotionDecisionContext,
  ): { readonly promotion: PromotionRecord; readonly rollback: StrategyRollbackRecord } {
    assertRecordIntegrity(record);
    requireActor(context, "human_reviewer");
    if (record.state !== "verified" && record.state !== "canary_running" && record.state !== "shadow_running") {
      throw new Error(`Strategy in ${record.state} cannot be rolled back as a deployment candidate.`);
    }
    if (target.state !== "verified" || target.strategyVersionId === record.strategyVersionId) {
      throw new Error("Rollback target must be a different previously verified strategy.");
    }
    if (!integrityVerified) throw new Error("Rollback target integrity must be verified locally.");
    const promotion = move(record, "rolled_back", context);
    return deepFreeze({
      promotion,
      rollback: {
        fromStrategyVersionId: record.strategyVersionId,
        toStrategyVersionId: target.strategyVersionId,
        reason: context.rationale,
        initiatedBy: context.actorId,
        integrityVerified: true,
        rolledBackAt: context.occurredAt,
      },
    });
  }
}

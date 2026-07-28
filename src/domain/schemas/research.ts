import {
  array,
  boolean,
  nonEmpty,
  nullableString,
  number,
  object,
  schema,
  stringList,
} from "./common";
import type {
  InitialResearchCampaignId,
  ResearchBudgets,
  ResearchCampaignMutation,
  ResearchCampaignRecord,
  ResearchLabSnapshot,
  ResearchPromotionLifecycleRecord,
  ResearchPromotionMutation,
  ResearchPromotionState,
  HumanResearchPromotionAction,
  ResearchHardGateCode,
  ResearchPromotionAction,
  ResearchCampaignSetupMutation,
  ResearchCampaignSetupPreview,
  ResearchExperimentRunMutation,
  ResearchExperimentRunRecord,
  ResearchExperimentRunStatus,
} from "../types/research";

const CAMPAIGN_IDS = new Set<InitialResearchCampaignId>([
  "repeated_no_progress_action_reduction",
  "specialist_routing_quality",
  "memory_retrieval_precision",
]);
const CAMPAIGN_STATES = new Set<ResearchCampaignRecord["status"]>([
  "draft", "approved", "running", "paused", "completed", "stopped", "rejected",
]);
const PROMOTION_STATES = new Set<ResearchPromotionState>([
  "proposed", "policy_rejected", "queued", "running", "early_aborted",
  "failed", "benchmarked", "holdout_failed", "shadow_ready",
  "shadow_running", "canary_ready", "canary_running", "verified",
  "rejected", "stale", "superseded", "rolled_back",
]);
const PROMOTION_STAGES = new Set<ResearchPromotionLifecycleRecord["stage"]>([
  "development", "validation", "hidden_holdout", "human_review", "shadow",
  "bounded_canary", "verified", "terminal",
]);
const HUMAN_PROMOTION_ACTIONS = new Set<HumanResearchPromotionAction>([
  "approve_human_review", "reject_human_review", "start_shadow",
  "approve_canary", "start_canary", "verify", "reject", "mark_stale",
  "supersede", "rollback",
]);
const PROMOTION_ACTORS = new Set([
  "local_policy", "local_evaluator", "human_reviewer",
] as const);
const PROMOTION_ACTIONS = new Set<ResearchPromotionAction>([
  "policy_accept", "policy_reject", "start_benchmark",
  "development_pass", "development_fail", "validation_pass",
  "validation_fail", "hidden_holdout_pass", "hidden_holdout_fail",
  "approve_human_review", "reject_human_review", "start_shadow",
  "shadow_pass", "shadow_fail", "approve_canary", "start_canary",
  "canary_pass", "canary_fail", "verify", "reject", "mark_stale",
  "supersede", "rollback",
]);
const HARD_GATE_CODES = new Set<ResearchHardGateCode>([
  "scope_violation", "policy_bypass", "unauthorized_destructive_action",
  "provider_sensitive_exposure", "prompt_injection_compliance",
  "fabricated_evidence", "unsupported_finding", "evaluator_mutation",
  "benchmark_mutation", "budget_overrun", "unbounded_loop",
  "orphaned_process", "cross_engagement_memory_leak",
  "commander_direct_execution", "integrity_receipt_mismatch",
]);
const SHA256 = /^[a-f0-9]{64}$/u;
const EXPERIMENT_RUN_STATES = new Set<ResearchExperimentRunStatus>([
  "queued",
  "running",
  "completed",
  "failed",
  "cancelled",
  "early_aborted",
]);

function campaignId(value: unknown): InitialResearchCampaignId {
  const result = nonEmpty(value, "research campaign catalog ID") as InitialResearchCampaignId;
  if (!CAMPAIGN_IDS.has(result)) throw new Error("research campaign catalog ID is not registered");
  return result;
}

function integer(value: unknown, label: string): number {
  const result = number(value, label);
  if (!Number.isSafeInteger(result) || result < 0) throw new Error(`${label} must be a non-negative integer`);
  return result;
}

function positiveInteger(value: unknown, label: string): number {
  const result = integer(value, label);
  if (result < 1) throw new Error(`${label} must be a positive integer`);
  return result;
}

function promotionAction(value: unknown): ResearchPromotionAction {
  const result = nonEmpty(value, "promotion transition action") as ResearchPromotionAction;
  if (!PROMOTION_ACTIONS.has(result)) throw new Error("promotion transition action is invalid");
  return result;
}

function hardGateCodes(value: unknown): ResearchHardGateCode[] {
  const values = stringList(value, "promotion hard-gate failures");
  if (
    values.some((code) => !HARD_GATE_CODES.has(code as ResearchHardGateCode))
    || new Set(values).size !== values.length
  ) {
    throw new Error("promotion hard-gate failures are invalid");
  }
  return values as ResearchHardGateCode[];
}

function validPromotionTransition(
  from: ResearchPromotionState,
  to: ResearchPromotionState,
  action: ResearchPromotionAction,
  actorKind: "local_policy" | "local_evaluator" | "human_reviewer",
): boolean {
  const exact = (
    expectedFrom: ResearchPromotionState,
    expectedTo: ResearchPromotionState,
    expectedAction: ResearchPromotionAction,
    expectedActor: typeof actorKind,
  ) => from === expectedFrom && to === expectedTo
    && action === expectedAction && actorKind === expectedActor;
  if (exact("proposed", "queued", "policy_accept", "local_policy")) return true;
  if (exact("proposed", "policy_rejected", "policy_reject", "local_policy")) return true;
  if (exact("queued", "running", "start_benchmark", "local_evaluator")) return true;
  if (exact("running", "running", "development_pass", "local_evaluator")) return true;
  if (exact("running", "early_aborted", "development_fail", "local_evaluator")) return true;
  if (exact("running", "benchmarked", "validation_pass", "local_evaluator")) return true;
  if (exact("running", "failed", "validation_fail", "local_evaluator")) return true;
  if (exact("benchmarked", "benchmarked", "hidden_holdout_pass", "local_evaluator")) return true;
  if (exact("benchmarked", "holdout_failed", "hidden_holdout_fail", "local_evaluator")) return true;
  if (exact("benchmarked", "shadow_ready", "approve_human_review", "human_reviewer")) return true;
  if (exact("benchmarked", "rejected", "reject_human_review", "human_reviewer")) return true;
  if (exact("shadow_ready", "shadow_running", "start_shadow", "human_reviewer")) return true;
  if (exact("shadow_running", "shadow_running", "shadow_pass", "local_evaluator")) return true;
  if (exact("shadow_running", "rejected", "shadow_fail", "local_evaluator")) return true;
  if (exact("shadow_running", "canary_ready", "approve_canary", "human_reviewer")) return true;
  if (exact("canary_ready", "canary_running", "start_canary", "human_reviewer")) return true;
  if (exact("canary_running", "canary_running", "canary_pass", "local_evaluator")) return true;
  if (exact("canary_running", "rejected", "canary_fail", "local_evaluator")) return true;
  if (exact("canary_running", "verified", "verify", "human_reviewer")) return true;
  if (action === "reject" && actorKind === "human_reviewer" && to === "rejected") {
    return [
      "proposed",
      "queued",
      "running",
      "shadow_ready",
      "shadow_running",
      "canary_ready",
      "canary_running",
    ].includes(from);
  }
  if (action === "mark_stale" && actorKind === "human_reviewer" && to === "stale") {
    return from === "verified";
  }
  if (exact("verified", "superseded", "supersede", "human_reviewer")) return true;
  return exact("verified", "rolled_back", "rollback", "human_reviewer");
}

const EVALUATOR_RESULT_ACTIONS = new Set<ResearchPromotionAction>([
  "development_pass",
  "development_fail",
  "validation_pass",
  "validation_fail",
  "hidden_holdout_pass",
  "hidden_holdout_fail",
  "shadow_pass",
  "shadow_fail",
  "canary_pass",
  "canary_fail",
]);

const HUMAN_RECEIPT_ACTIONS = new Set<ResearchPromotionAction>([
  "approve_human_review",
  "start_shadow",
  "approve_canary",
  "start_canary",
  "verify",
  "rollback",
]);

const DEPLOYMENT_ACTIONS = new Set<ResearchPromotionAction>([
  "start_shadow",
  "start_canary",
  "rollback",
]);
function budgets(value: unknown): ResearchBudgets {
  const item = object(value, "research budgets");
  return {
    maxExperiments: integer(item.maxExperiments, "maxExperiments"),
    maxWallClockMs: integer(item.maxWallClockMs, "maxWallClockMs"),
    maxPublicLlmTokens: integer(item.maxPublicLlmTokens, "maxPublicLlmTokens"),
    maxEstimatedCost: number(item.maxEstimatedCost, "maxEstimatedCost"),
    maxToolCalls: integer(item.maxToolCalls, "maxToolCalls"),
    maxConcurrentExperiments: integer(item.maxConcurrentExperiments, "maxConcurrentExperiments"),
    maxFailures: integer(item.maxFailures, "maxFailures"),
    maxRetries: integer(item.maxRetries, "maxRetries"),
    maxPatchOperations: integer(item.maxPatchOperations, "maxPatchOperations"),
    maxTrialsPerDimension: integer(item.maxTrialsPerDimension, "maxTrialsPerDimension"),
    safetyFailureCircuitBreaker: integer(item.safetyFailureCircuitBreaker, "safetyFailureCircuitBreaker"),
  };
}

function nullableHash(value: unknown, label: string): string | null {
  const result = nullableString(value, label);
  if (result !== null && !SHA256.test(result)) {
    throw new Error(`${label} must be a SHA-256 hash or null`);
  }
  return result;
}

function parseSetupPreview(value: unknown): ResearchCampaignSetupPreview {
  const item = object(value, "research campaign setup preview");
  const splitCounts = object(
    item.splitCounts,
    "research benchmark split counts",
  );
  if (
    splitCounts.development !== 1
    || splitCounts.validation !== 1
    || splitCounts.hiddenHoldout !== "operator_descriptor_required"
  ) {
    throw new Error(
      "research benchmark splits must expose only one public development and validation fixture while requiring an operator-owned holdout descriptor",
    );
  }
  const executionReadiness =
    item.executionReadiness === "ready"
    || item.executionReadiness === "blocked"
      ? item.executionReadiness
      : (() => {
          throw new Error("research execution readiness is invalid");
        })();
  const boundary = object(
    item.executionBoundary,
    "research execution boundary",
  );
  if (
    boundary.targetClass !== "synthetic_fixture"
    || boolean(
      boundary.liveClientTargetAllowed,
      "liveClientTargetAllowed",
    ) !== false
    || boolean(
      boundary.outboundNetworkAllowed,
      "outboundNetworkAllowed",
    ) !== false
    || boolean(boundary.publicProviderUsed, "publicProviderUsed") !== false
    || boolean(
      boundary.arbitrarySourcePatchAllowed,
      "arbitrarySourcePatchAllowed",
    ) !== false
    || boolean(
      boundary.automaticPromotionAllowed,
      "automaticPromotionAllowed",
    ) !== false
    || boolean(
      boundary.automaticDeploymentAllowed,
      "automaticDeploymentAllowed",
    ) !== false
  ) {
    throw new Error("research execution boundary is unsafe");
  }
  const patch = array(item.patch, "research strategy patch").map(
    (value, index) => {
      const operation = object(value, `research strategy patch[${index}]`);
      if (
        operation.op !== "replace"
        || ![
          "string",
          "number",
          "boolean",
          "object",
        ].includes(typeof operation.value)
        || (
          typeof operation.value === "object"
          && operation.value !== null
        )
      ) {
        throw new Error(
          "research setup patch must contain scalar replace operations",
        );
      }
      return {
        op: "replace" as const,
        path: nonEmpty(operation.path, "research strategy patch path"),
        value: operation.value as string | number | boolean | null,
      };
    },
  );
  if (patch.length !== 1) {
    throw new Error("research setup must contain exactly one strategy patch");
  }
  const hashes = {
    baselineBundleHash: nullableHash(
      item.baselineBundleHash,
      "baseline bundle hash",
    ),
    candidateBundleHash: nullableHash(
      item.candidateBundleHash,
      "candidate bundle hash",
    ),
    evaluatorHash: nullableHash(item.evaluatorHash, "evaluator hash"),
    toolManifestHash: nullableHash(
      item.toolManifestHash,
      "tool manifest hash",
    ),
    executionEnvironmentIdentityHash: nullableHash(
      item.executionEnvironmentIdentityHash,
      "execution environment identity hash",
    ),
  };
  if (
    executionReadiness === "ready"
    && Object.values(hashes).some((hash) => hash === null)
  ) {
    throw new Error("ready research setup is missing an immutable hash");
  }
  return {
    candidatePresetId: nonEmpty(
      item.candidatePresetId,
      "research candidate preset ID",
    ),
    dimensionId: nonEmpty(item.dimensionId, "research dimension ID"),
    path: nonEmpty(item.path, "research mutable path"),
    hypothesis: nonEmpty(item.hypothesis, "research hypothesis"),
    patch,
    developmentScenarioId: nonEmpty(
      item.developmentScenarioId,
      "development scenario ID",
    ),
    splitCounts: {
      development: 1,
      validation: 1,
      hiddenHoldout: "operator_descriptor_required",
    },
    ...hashes,
    executionReadiness,
    executionBoundary: {
      targetClass: "synthetic_fixture",
      liveClientTargetAllowed: false,
      outboundNetworkAllowed: false,
      publicProviderUsed: false,
      arbitrarySourcePatchAllowed: false,
      automaticPromotionAllowed: false,
      automaticDeploymentAllowed: false,
    },
  };
}

export function parseResearchExperimentRun(
  value: unknown,
): ResearchExperimentRunRecord {
  const item = object(value, "research experiment run");
  const status = nonEmpty(
    item.status,
    "research experiment run status",
  ) as ResearchExperimentRunStatus;
  if (!EXPERIMENT_RUN_STATES.has(status)) {
    throw new Error("research experiment run status is invalid");
  }
  return {
    id: nonEmpty(item.id, "research experiment run ID"),
    experimentId: nonEmpty(
      item.experimentId,
      "research experiment ID",
    ),
    scenarioId: nonEmpty(item.scenarioId, "benchmark scenario ID"),
    seed: nonEmpty(item.seed, "research experiment seed"),
    workerId: nonEmpty(item.workerId, "research worker ID"),
    status,
    startedAt: nullableString(item.startedAt, "research run startedAt"),
    endedAt: nullableString(item.endedAt, "research run endedAt"),
    createdAt: nonEmpty(item.createdAt, "research run createdAt"),
  };
}

export function parseResearchCampaign(value: unknown): ResearchCampaignRecord {
  const item = object(value, "research campaign");
  const status = nonEmpty(item.status, "research campaign status") as ResearchCampaignRecord["status"];
  if (!CAMPAIGN_STATES.has(status)) throw new Error("research campaign status is invalid");
  return {
    id: nonEmpty(item.id, "research campaign ID"),
    catalogId: campaignId(item.catalogId),
    name: nonEmpty(item.name, "research campaign name"),
    purpose: nonEmpty(item.purpose, "research campaign purpose"),
    status,
    owner: nonEmpty(item.owner, "research campaign owner"),
    budgets: budgets(item.budgets),
    dimensionCount: integer(item.dimensionCount, "dimensionCount"),
    experimentCount: integer(item.experimentCount, "experimentCount"),
    charterCount: integer(item.charterCount, "charterCount"),
    createdAt: nonEmpty(item.createdAt, "research campaign createdAt"),
    updatedAt: nonEmpty(item.updatedAt, "research campaign updatedAt"),
  };
}

function promotionState(value: unknown, label: string): ResearchPromotionState {
  const result = nonEmpty(value, label) as ResearchPromotionState;
  if (!PROMOTION_STATES.has(result)) throw new Error(`${label} is invalid`);
  return result;
}

function parseResearchPromotion(
  value: unknown,
): ResearchPromotionLifecycleRecord {
  const item = object(value, "research promotion lifecycle");
  const stage = nonEmpty(
    item.stage,
    "research promotion stage",
  ) as ResearchPromotionLifecycleRecord["stage"];
  if (!PROMOTION_STAGES.has(stage)) {
    throw new Error("research promotion stage is invalid");
  }
  const milestones = object(
    item.milestones,
    "research promotion milestones",
  );
  const availableHumanActions = stringList(
    item.availableHumanActions,
    "available human promotion actions",
  ).map((action) => {
    if (!HUMAN_PROMOTION_ACTIONS.has(action as HumanResearchPromotionAction)) {
      throw new Error("available human promotion action is invalid");
    }
    return action as HumanResearchPromotionAction;
  });
  const state = promotionState(item.state, "research promotion state");
  const parsedMilestones = {
    developmentPassed: boolean(
      milestones.developmentPassed,
      "developmentPassed",
    ),
    validationPassed: boolean(
      milestones.validationPassed,
      "validationPassed",
    ),
    hiddenHoldoutPassed: boolean(
      milestones.hiddenHoldoutPassed,
      "hiddenHoldoutPassed",
    ),
    humanReviewApproved: boolean(
      milestones.humanReviewApproved,
      "humanReviewApproved",
    ),
    shadowPassed: boolean(milestones.shadowPassed, "shadowPassed"),
    canaryPassed: boolean(milestones.canaryPassed, "canaryPassed"),
  };
  const transitions = array(
    item.transitions,
    "research promotion transitions",
  ).map((value, index) => {
    const transition = object(value, "research promotion transition");
    const actorKind = nonEmpty(
      transition.actorKind,
      "promotion actor kind",
    ) as "local_policy" | "local_evaluator" | "human_reviewer";
    if (!PROMOTION_ACTORS.has(actorKind)) {
      throw new Error("promotion actor kind is invalid");
    }
    const fromState = promotionState(
      transition.fromState,
      "promotion source state",
    );
    const toState = promotionState(
      transition.toState,
      "promotion target state",
    );
    const action = promotionAction(transition.action);
    const sequence = positiveInteger(
      transition.sequence,
      "promotion sequence",
    );
    const version = positiveInteger(
      transition.version,
      "promotion transition version",
    );
    if (sequence !== index + 1 || version !== sequence + 1) {
      throw new Error("promotion transition sequence or version is not monotonic");
    }
    if (!validPromotionTransition(fromState, toState, action, actorKind)) {
      throw new Error("promotion transition action, state, or authority is invalid");
    }
    const evidenceRefs = stringList(
      transition.evidenceRefs,
      "promotion evidence references",
    );
    if (evidenceRefs.length === 0 || new Set(evidenceRefs).size !== evidenceRefs.length) {
      throw new Error("promotion evidence references are empty or duplicated");
    }
    const createdAt = nonEmpty(
      transition.createdAt,
      "promotion transition createdAt",
    );
    if (!Number.isFinite(Date.parse(createdAt))) {
      throw new Error("promotion transition timestamp is invalid");
    }
    const hardGateFailures = hardGateCodes(transition.hardGateFailures);
    const decisionFingerprint =
      typeof transition.decisionFingerprint === "string"
        ? nonEmpty(
            transition.decisionFingerprint,
            "promotion decision fingerprint",
          )
        : undefined;
    if (decisionFingerprint && !SHA256.test(decisionFingerprint)) {
      throw new Error("promotion decision fingerprint is invalid");
    }
    if (actorKind !== "human_reviewer" && decisionFingerprint) {
      throw new Error(
        "local promotion transitions cannot carry a human decision fingerprint",
      );
    }
    const integrityReceiptId = typeof transition.integrityReceiptId === "string"
      ? nonEmpty(
          transition.integrityReceiptId,
          "promotion integrity receipt ID",
        )
      : undefined;
    const exposureReceiptIds = stringList(
      transition.exposureReceiptIds,
      "promotion exposure receipt IDs",
    );
    if (new Set(exposureReceiptIds).size !== exposureReceiptIds.length) {
      throw new Error("promotion exposure receipt IDs are duplicated");
    }
    const deploymentId = typeof transition.deploymentId === "string"
      ? nonEmpty(
          transition.deploymentId,
          "promotion deployment ID",
        )
      : undefined;
    if (
      action.endsWith("_pass")
      && hardGateFailures.length > 0
    ) {
      throw new Error("passing promotion transitions cannot contain hard-gate failures");
    }
    if (
      !action.endsWith("_fail")
      && action !== "policy_reject"
      && hardGateFailures.length > 0
    ) {
      throw new Error("only failed evaluator or policy transitions can contain hard-gate failures");
    }
    const receiptRequired = EVALUATOR_RESULT_ACTIONS.has(action)
      || HUMAN_RECEIPT_ACTIONS.has(action);
    if (receiptRequired !== Boolean(integrityReceiptId)) {
      throw new Error(
        receiptRequired
          ? "promotion transition is missing its required integrity receipt"
          : "promotion transition has an unexpected integrity receipt",
      );
    }
    if (!integrityReceiptId && exposureReceiptIds.length > 0) {
      throw new Error("promotion exposure receipts require an integrity receipt");
    }
    const deploymentRequired = DEPLOYMENT_ACTIONS.has(action);
    if (deploymentRequired !== Boolean(deploymentId)) {
      throw new Error(
        deploymentRequired
          ? "promotion transition is missing its required deployment binding"
          : "promotion transition has an unexpected deployment binding",
      );
    }
    return {
      id: nonEmpty(transition.id, "promotion transition ID"),
      sequence,
      version,
      fromState,
      toState,
      action,
      actorKind,
      actorId: nonEmpty(transition.actorId, "promotion actor ID"),
      rationale: nonEmpty(
        transition.rationale,
        "promotion transition rationale",
      ),
      evidenceRefs,
      hardGateFailures,
      ...(decisionFingerprint ? { decisionFingerprint } : {}),
      ...(integrityReceiptId ? { integrityReceiptId } : {}),
      exposureReceiptIds,
      ...(deploymentId ? { deploymentId } : {}),
      createdAt,
    };
  });
  const transitionIds = transitions.map(({ id }) => id);
  if (new Set(transitionIds).size !== transitionIds.length) {
    throw new Error("promotion transition IDs are duplicated");
  }
  let priorState: ResearchPromotionState = "proposed";
  let priorTimestamp = Number.NEGATIVE_INFINITY;
  const derivedMilestones = {
    developmentPassed: false,
    validationPassed: false,
    hiddenHoldoutPassed: false,
    humanReviewApproved: false,
    shadowPassed: false,
    canaryPassed: false,
  };
  for (const transition of transitions) {
    if (transition.fromState !== priorState) {
      throw new Error("promotion transition history contains a broken state chain");
    }
    const timestamp = Date.parse(transition.createdAt);
    if (timestamp < priorTimestamp) {
      throw new Error("promotion transition timestamps are not monotonic");
    }
    priorTimestamp = timestamp;
    if (
      (transition.action === "validation_pass"
        || transition.action === "validation_fail")
      && !derivedMilestones.developmentPassed
    ) {
      throw new Error("validation cannot precede a passed development stage");
    }
    if (
      (transition.action === "hidden_holdout_pass"
        || transition.action === "hidden_holdout_fail")
      && !derivedMilestones.validationPassed
    ) {
      throw new Error("hidden holdout cannot precede a passed validation stage");
    }
    if (
      (transition.action === "approve_human_review"
        || transition.action === "reject_human_review")
      && !derivedMilestones.hiddenHoldoutPassed
    ) {
      throw new Error("human review cannot precede a passed hidden holdout");
    }
    if (
      transition.action === "start_shadow"
      && !derivedMilestones.humanReviewApproved
    ) {
      throw new Error("shadow cannot start before human review approval");
    }
    if (
      transition.action === "approve_canary"
      && !derivedMilestones.shadowPassed
    ) {
      throw new Error("canary cannot be approved before shadow passes");
    }
    if (
      transition.action === "start_canary"
      && !derivedMilestones.shadowPassed
    ) {
      throw new Error("canary cannot start before shadow passes");
    }
    if (
      transition.action === "verify"
      && !derivedMilestones.canaryPassed
    ) {
      throw new Error("verification cannot precede a passed bounded canary");
    }
    if (transition.action === "development_pass") {
      derivedMilestones.developmentPassed = true;
    } else if (transition.action === "validation_pass") {
      derivedMilestones.validationPassed = true;
    } else if (transition.action === "hidden_holdout_pass") {
      derivedMilestones.hiddenHoldoutPassed = true;
    } else if (transition.action === "approve_human_review") {
      derivedMilestones.humanReviewApproved = true;
    } else if (transition.action === "shadow_pass") {
      derivedMilestones.shadowPassed = true;
    } else if (transition.action === "canary_pass") {
      derivedMilestones.canaryPassed = true;
    }
    priorState = transition.toState;
  }
  if (priorState !== state) {
    throw new Error("promotion lifecycle state does not match transition history");
  }
  const expectedMilestones = derivedMilestones;
  for (const key of Object.keys(expectedMilestones) as Array<keyof typeof expectedMilestones>) {
    if (parsedMilestones[key] !== expectedMilestones[key]) {
      throw new Error(`promotion milestone ${key} does not match transition history`);
    }
  }
  const expectedStage: ResearchPromotionLifecycleRecord["stage"] =
    ["policy_rejected", "early_aborted", "failed", "holdout_failed", "rejected", "stale", "superseded", "rolled_back"].includes(state)
      ? "terminal"
      : state === "verified"
        ? "verified"
        : state === "shadow_ready" || state === "shadow_running"
          ? "shadow"
          : state === "canary_ready" || state === "canary_running"
            ? "bounded_canary"
            : state === "benchmarked"
              ? parsedMilestones.hiddenHoldoutPassed ? "human_review" : "hidden_holdout"
              : state === "running" && parsedMilestones.developmentPassed
                ? "validation"
                : "development";
  if (stage !== expectedStage) {
    throw new Error("research promotion stage does not match lifecycle state");
  }
  const expectedHumanActions: HumanResearchPromotionAction[] =
    state === "benchmarked" && parsedMilestones.hiddenHoldoutPassed
      ? ["approve_human_review", "reject_human_review"]
      : state === "shadow_ready"
        ? ["start_shadow", "reject"]
        : state === "shadow_running" && parsedMilestones.shadowPassed
          ? ["approve_canary", "reject"]
          : state === "canary_ready"
            ? ["start_canary", "reject"]
            : state === "canary_running" && parsedMilestones.canaryPassed
              ? ["verify", "reject"]
              : state === "verified"
                ? ["mark_stale", "supersede", "rollback"]
                : ["proposed", "queued", "running", "shadow_running", "canary_running"].includes(state)
                  ? ["reject"]
                  : [];
  if (availableHumanActions.join("|") !== expectedHumanActions.join("|")) {
    throw new Error("available human promotion actions do not match lifecycle state");
  }
  const version = positiveInteger(item.version, "promotion lifecycle version");
  if (version !== transitions.length + 1) {
    throw new Error("promotion lifecycle version does not match transition history");
  }
  const updatedAt = nonEmpty(item.updatedAt, "promotion updatedAt");
  const updatedTimestamp = Date.parse(updatedAt);
  if (
    !Number.isFinite(updatedTimestamp)
    || (
      transitions.length > 0
      && updatedTimestamp < Date.parse(transitions.at(-1)!.createdAt)
    )
  ) {
    throw new Error("promotion updatedAt is invalid or precedes transition history");
  }
  const rollbackTargets = array(
    item.rollbackTargets,
    "promotion rollback targets",
  ).map((value) => {
    const target = object(value, "promotion rollback target");
    return {
      experimentId: nonEmpty(
        target.experimentId,
        "rollback experiment ID",
      ),
      strategyVersionId: nonEmpty(
        target.strategyVersionId,
        "rollback strategy ID",
      ),
    };
  });
  if (
    new Set(rollbackTargets.map(({ strategyVersionId }) => strategyVersionId))
      .size !== rollbackTargets.length
    || rollbackTargets.some(({ strategyVersionId }) =>
      strategyVersionId === item.strategyVersionId)
  ) {
    throw new Error("promotion rollback targets are duplicated or include the current strategy");
  }
  return {
    experimentId: nonEmpty(item.experimentId, "promotion experiment ID"),
    campaignId: nonEmpty(item.campaignId, "promotion campaign ID"),
    strategyVersionId: nonEmpty(
      item.strategyVersionId,
      "promotion strategy version ID",
    ),
    state,
    stage,
    milestones: parsedMilestones,
    version,
    updatedAt,
    ...(typeof item.latestIntegrityReceiptId === "string"
      ? {
          latestIntegrityReceiptId: nonEmpty(
            item.latestIntegrityReceiptId,
            "latest integrity receipt ID",
          ),
        }
      : {}),
    availableHumanActions,
    rollbackTargets,
    transitions,
  };
}

export function parseResearchLab(payload: unknown): ResearchLabSnapshot {
  const root = object(payload, "Research Lab");
  schema(root);
  const readiness = object(root.readiness, "research readiness");
  const readinessStatus = readiness.status === "ready" || readiness.status === "blocked"
    ? readiness.status : (() => { throw new Error("research readiness status is invalid"); })();
  const boundary = object(root.publicLlmBoundary, "public LLM boundary");
  if (
    boundary.role !== "proposal_only"
    || boolean(boundary.rawClientEvidenceAllowed, "rawClientEvidenceAllowed") !== false
    || boolean(boundary.directToolExecutionAllowed, "directToolExecutionAllowed") !== false
    || boolean(boundary.authoritativeScoringAllowed, "authoritativeScoringAllowed") !== false
    || boolean(boundary.automaticPromotionAllowed, "automaticPromotionAllowed") !== false
  ) throw new Error("public LLM research boundary is unsafe");
  const promotionPath = stringList(root.promotionPath, "promotion path");
  const expectedPath = ["development", "validation", "hidden_holdout", "human_review", "shadow", "bounded_canary", "verified"];
  if (promotionPath.join("|") !== expectedPath.join("|")) throw new Error("research promotion path is invalid");
  const integrity = object(root.integrity, "research integrity");
  return {
    schemaVersion: "2.4",
    governingPrinciple: nonEmpty(root.governingPrinciple, "governing principle"),
    readiness: {
      status: readinessStatus,
      checks: array(readiness.checks, "research readiness checks").map((value) => {
        const item = object(value, "research readiness check");
        const status = item.status === "pass" || item.status === "fail"
          ? item.status : (() => { throw new Error("research readiness check status is invalid"); })();
        return {
          id: nonEmpty(item.id, "research readiness check ID"), status,
          label: nonEmpty(item.label, "research readiness check label"),
          impact: nonEmpty(item.impact, "research readiness check impact"),
          ...(typeof item.remediation === "string" ? { remediation: item.remediation } : {}),
        };
      }),
    },
    publicLlmBoundary: {
      role: "proposal_only",
      rawClientEvidenceAllowed: false,
      directToolExecutionAllowed: false,
      authoritativeScoringAllowed: false,
      automaticPromotionAllowed: false,
    },
    promotionPath: expectedPath as ResearchLabSnapshot["promotionPath"],
    catalog: array(root.catalog, "research catalog").map((value) => {
      const item = object(value, "research catalog item");
      const direction = item.primaryMetricDirection === "higher_better" || item.primaryMetricDirection === "lower_better"
        ? item.primaryMetricDirection : (() => { throw new Error("primary metric direction is invalid"); })();
      return {
        id: campaignId(item.id), title: nonEmpty(item.title, "catalog title"),
        purpose: nonEmpty(item.purpose, "catalog purpose"),
        primaryMetric: nonEmpty(item.primaryMetric, "primary metric"),
        primaryMetricDirection: direction,
        mutablePaths: stringList(item.mutablePaths, "mutable paths"),
        existingCampaignIds: stringList(item.existingCampaignIds, "existing campaign IDs"),
        setup: parseSetupPreview(item.setup),
      };
    }),
    campaigns: array(root.campaigns, "research campaigns").map(parseResearchCampaign),
    experiments: array(root.experiments, "research experiments").map((value) => {
      const item = object(value, "research experiment");
      return {
        id: nonEmpty(item.id, "experiment ID"), campaignId: nonEmpty(item.campaignId, "experiment campaign ID"),
        hypothesis: nonEmpty(item.hypothesis, "experiment hypothesis"), status: nonEmpty(item.status, "experiment status"),
        dimensionId: nonEmpty(item.dimensionId, "experiment dimension"),
        candidateStrategyId: nonEmpty(item.candidateStrategyId, "candidate strategy ID"),
        scenarioId: nonEmpty(item.scenarioId, "experiment development scenario ID"),
        ...(item.latestRun === undefined
          ? {}
          : {
              latestRun: (() => {
                const run = object(item.latestRun, "latest research experiment run");
                const status = nonEmpty(
                  run.status,
                  "latest research experiment run status",
                ) as ResearchExperimentRunStatus;
                if (!EXPERIMENT_RUN_STATES.has(status)) {
                  throw new Error("latest research experiment run status is invalid");
                }
                return {
                  id: nonEmpty(run.id, "latest research experiment run ID"),
                  status,
                  startedAt: nullableString(
                    run.startedAt,
                    "latest research run startedAt",
                  ),
                  endedAt: nullableString(
                    run.endedAt,
                    "latest research run endedAt",
                  ),
                };
              })(),
            }),
        updatedAt: nonEmpty(item.updatedAt, "experiment updatedAt"),
      };
    }),
    promotions: array(
      root.promotions,
      "research promotion lifecycles",
    ).map(parseResearchPromotion),
    integrity: {
      benchmarkFamilies: integer(integrity.benchmarkFamilies, "benchmarkFamilies"),
      benchmarkSnapshots: integer(integrity.benchmarkSnapshots, "benchmarkSnapshots"),
      approvedCharters: integer(integrity.approvedCharters, "approvedCharters"),
      integrityReceipts: integer(integrity.integrityReceipts, "integrityReceipts"),
      providerExposureReceipts: integer(integrity.providerExposureReceipts, "providerExposureReceipts"),
      blockedProviderExposures: integer(integrity.blockedProviderExposures, "blockedProviderExposures"),
    },
  };
}

export function parseResearchCampaignMutation(payload: unknown): ResearchCampaignMutation {
  const root = object(payload, "research campaign mutation");
  schema(root);
  return {
    schemaVersion: "2.4",
    campaign: parseResearchCampaign(root.campaign),
    ...(typeof root.nextUrl === "string" ? { nextUrl: root.nextUrl } : {}),
  };
}

export function parseResearchPromotionMutation(
  payload: unknown,
): ResearchPromotionMutation {
  const root = object(payload, "research promotion mutation");
  schema(root);
  return {
    schemaVersion: "2.4",
    lifecycle: parseResearchPromotion(root.lifecycle),
  };
}

export function parseResearchCampaignSetupMutation(
  payload: unknown,
): ResearchCampaignSetupMutation {
  const root = object(payload, "research campaign setup mutation");
  schema(root);
  const setup = object(root.setup, "research campaign setup");
  const experimentStatus = nonEmpty(
    setup.experimentStatus,
    "research setup experiment status",
  );
  if (experimentStatus !== "queued") {
    throw new Error("research setup experiment must begin queued");
  }
  if (
    boolean(setup.automaticPromotion, "automaticPromotion") !== false
    || boolean(setup.automaticDeployment, "automaticDeployment") !== false
  ) {
    throw new Error("research setup cannot auto-promote or auto-deploy");
  }
  const hash = (value: unknown, label: string): string => {
    const result = nonEmpty(value, label);
    if (!SHA256.test(result)) throw new Error(`${label} must be a SHA-256 hash`);
    return result;
  };
  return {
    schemaVersion: "2.4",
    campaign: parseResearchCampaign(root.campaign),
    setup: {
      charterId: nonEmpty(setup.charterId, "research charter ID"),
      charterHash: hash(setup.charterHash, "research charter hash"),
      benchmarkFamilyId: nonEmpty(
        setup.benchmarkFamilyId,
        "research benchmark family ID",
      ),
      benchmarkSnapshotId: nonEmpty(
        setup.benchmarkSnapshotId,
        "research benchmark snapshot ID",
      ),
      benchmarkSnapshotHash: hash(
        setup.benchmarkSnapshotHash,
        "research benchmark snapshot hash",
      ),
      developmentScenarioId: nonEmpty(
        setup.developmentScenarioId,
        "research development scenario ID",
      ),
      baselineStrategyId: nonEmpty(
        setup.baselineStrategyId,
        "research baseline strategy ID",
      ),
      baselineStrategyHash: hash(
        setup.baselineStrategyHash,
        "research baseline strategy hash",
      ),
      candidateStrategyId: nonEmpty(
        setup.candidateStrategyId,
        "research candidate strategy ID",
      ),
      candidateStrategyHash: hash(
        setup.candidateStrategyHash,
        "research candidate strategy hash",
      ),
      strategyPatchId: nonEmpty(
        setup.strategyPatchId,
        "research strategy patch ID",
      ),
      strategyPatchHash: hash(
        setup.strategyPatchHash,
        "research strategy patch hash",
      ),
      experimentId: nonEmpty(setup.experimentId, "research experiment ID"),
      experimentStatus: "queued",
      candidatePresetId: nonEmpty(
        setup.candidatePresetId,
        "research candidate preset ID",
      ),
      dimensionId: nonEmpty(setup.dimensionId, "research dimension ID"),
      hypothesis: nonEmpty(setup.hypothesis, "research hypothesis"),
      automaticPromotion: false,
      automaticDeployment: false,
    },
  };
}

export function parseResearchExperimentRunMutation(
  payload: unknown,
): ResearchExperimentRunMutation {
  const root = object(payload, "research experiment run mutation");
  schema(root);
  return {
    schemaVersion: "2.4",
    run: parseResearchExperimentRun(root.run),
  };
}

import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../../server/db";
import {
  IntegrityAuthority,
  LlmExposurePolicy,
  ResearchPromotionLifecycleRepository,
  type ExperimentIntegrityPayload,
  type HumanResearchPromotionAction,
  type LocalResearchPromotionAction,
} from "../../../server/research";
import {
  canonicalJson,
  sha256,
} from "../../../server/missions/canonical";
import { canonicalResearchPromotionDecision } from "../../../shared/ResearchPromotionDecision";
import {
  DEFAULT_STRATEGY_BUNDLE,
} from "../../../server/research/StrategyBundleSchema";
import { hashCanonical } from "../../../server/research/canonical";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const CAMPAIGN_ID = "research-campaign-lifecycle";
const DIMENSION_ID = "research-dimension-lifecycle";
const DIMENSION_NAME = "loop.max_identical_fingerprints";
const CHARTER_ID = "research-charter-lifecycle";
const SNAPSHOT_ID = "research-snapshot-lifecycle";
const BASELINE_ID = "strategy-baseline";
const KEY = "local-research-integrity-key-material-32-bytes";

interface Fixture {
  readonly database: ReturnType<typeof createDatabaseConnection>;
  readonly authority: IntegrityAuthority;
  readonly repository: ResearchPromotionLifecycleRepository;
}

function fixture(): Fixture {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO research_campaigns (
      id, name, purpose, status, owner, budgets_json, created_at, updated_at
    ) VALUES (?, ?, ?, 'running', 'operator-research', '{}', ?, ?)
  `).run(
    CAMPAIGN_ID,
    "Repeated and no-progress action reduction",
    "Verify the complete promotion lifecycle.",
    "2026-07-24T00:00:00.000Z",
    "2026-07-24T00:00:00.000Z",
  );
  database.prepare(`
    INSERT INTO research_dimensions (
      id, campaign_id, name, schema_path
    ) VALUES (?, ?, ?, '/loopControl/maxIdenticalFingerprints')
  `).run(DIMENSION_ID, CAMPAIGN_ID, DIMENSION_NAME);
  database.prepare(`
    INSERT INTO research_charters (
      id, campaign_id, version, immutable_scope_json,
      mutable_dimensions_json, forbidden_paths_json, budgets_json,
      charter_hash, approved_by, approved_at
    ) VALUES (?, ?, 1, '{}', '[]', '[]', '{}', ?, ?, ?)
  `).run(
    CHARTER_ID,
    CAMPAIGN_ID,
    HASH_A,
    "operator-research",
    "2026-07-24T00:00:00.000Z",
  );
  database.prepare(`
    INSERT INTO benchmark_families (
      id, name, evaluator_version, hard_gates_json, metrics_json,
      promotion_criteria_json, created_at
    ) VALUES (
      'benchmark-family-lifecycle', 'Lifecycle fixtures',
      'security-evaluator-v1', '[]', '[]', '{}', ?
    )
  `).run("2026-07-24T00:00:00.000Z");
  database.prepare(`
    INSERT INTO benchmark_snapshots (
      id, family_id, evaluator_hash, scenario_set_hash,
      tool_manifest_hash, snapshot_hash, container_image_digest,
      execution_environment_kind, execution_environment_identity_hash,
      created_at
    ) VALUES (
      ?, 'benchmark-family-lifecycle', ?, ?, ?, ?, ?,
      'oci_container', ?, ?
    )
  `).run(
    SNAPSHOT_ID,
    HASH_C,
    HASH_A,
    HASH_B,
    HASH_B,
    `sha256:${HASH_A}`,
    HASH_A,
    "2026-07-24T00:00:00.000Z",
  );
  database.prepare(`
    INSERT INTO strategy_versions (
      id, campaign_id, version, bundle_json, bundle_hash,
      status, created_by, created_at
    ) VALUES (?, ?, 1, ?, ?, 'verified', 'operator-research', ?)
  `).run(
    BASELINE_ID,
    CAMPAIGN_ID,
    canonicalJson(DEFAULT_STRATEGY_BUNDLE),
    hashCanonical(JSON.parse(canonicalJson(DEFAULT_STRATEGY_BUNDLE))),
    "2026-07-24T00:00:00.000Z",
  );
  const authority = new IntegrityAuthority(KEY);
  return {
    database,
    authority,
    repository: new ResearchPromotionLifecycleRepository(
      database,
      authority,
      () => new Date("2026-07-24T12:00:00.000Z"),
    ),
  };
}

function addExperiment(
  fixtureValue: Fixture,
  suffix: string,
  strategyVersion: number,
): {
  readonly experimentId: string;
  readonly strategyId: string;
  readonly exposureReceiptId: string;
} {
  const { database, repository } = fixtureValue;
  const experimentId = `experiment-${suffix}`;
  const strategyId = `strategy-${suffix}`;
  const bundle = {
    ...DEFAULT_STRATEGY_BUNDLE,
    loopControl: {
      ...DEFAULT_STRATEGY_BUNDLE.loopControl,
      maxIdenticalFingerprints: strategyVersion % 2 === 0 ? 2 : 4,
    },
  };
  database.prepare(`
    INSERT INTO strategy_versions (
      id, campaign_id, parent_id, version, bundle_json, bundle_hash,
      status, created_by, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'proposed', 'local-policy', ?)
  `).run(
    strategyId,
    CAMPAIGN_ID,
    BASELINE_ID,
    strategyVersion,
    canonicalJson(bundle),
    hashCanonical(bundle),
    "2026-07-24T00:00:00.000Z",
  );
  database.prepare(`
    INSERT INTO experiments (
      id, campaign_id, charter_id, dimension_id, baseline_strategy_id,
      candidate_strategy_id, benchmark_snapshot_id, hypothesis, status,
      public_llm_spec_hash, created_by, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, 'local-policy', ?, ?)
  `).run(
    experimentId,
    CAMPAIGN_ID,
    CHARTER_ID,
    DIMENSION_ID,
    BASELINE_ID,
    strategyId,
    SNAPSHOT_ID,
    `Candidate ${suffix} reduces repeated actions.`,
    HASH_C,
    "2026-07-24T00:00:00.000Z",
    "2026-07-24T00:00:00.000Z",
  );
  const exposure = new LlmExposurePolicy("research-exposure-v1")
    .buildResearchBrief({
      campaignId: CAMPAIGN_ID,
      dimensionId: DIMENSION_NAME,
      objective: "Reduce repeated no-progress actions in isolated fixtures.",
      providerId: "public-proposal-provider",
      modelId: "proposal-model",
      experimentId,
      createdAt: "2026-07-24T00:01:00.000Z",
      items: [{
        id: `sanitized-metric-${suffix}`,
        kind: "metric_summary",
        classification: "internal",
        disclosureClass: "internal_sanitized",
        content: "Duplicate action rate changed on an anonymous lab fixture.",
        verified: true,
      }],
    }).receipt;
  repository.persistExposureReceipt(exposure);
  repository.initialize({
    experimentId,
    actorId: "local-policy",
  });
  return {
    experimentId,
    strategyId,
    exposureReceiptId: exposure.id,
  };
}

function integrityReceipt(
  fixtureValue: Fixture,
  input: {
    readonly experimentId: string;
    readonly strategyId: string;
    readonly exposureReceiptId: string;
    readonly sequence: number;
    readonly evaluationAction:
      ExperimentIntegrityPayload["evaluationAction"];
    readonly hardGateFailures?: readonly string[];
    readonly persist?: boolean;
  },
) {
  const baselineHash = (
    fixtureValue.database.prepare(
      "SELECT bundle_hash FROM strategy_versions WHERE id = ?",
    ).get(BASELINE_ID) as { readonly bundle_hash: string }
  ).bundle_hash;
  const candidateHash = (
    fixtureValue.database.prepare(
      "SELECT bundle_hash FROM strategy_versions WHERE id = ?",
    ).get(input.strategyId) as { readonly bundle_hash: string }
  ).bundle_hash;
  const payload: ExperimentIntegrityPayload = {
    experimentId: input.experimentId,
    charterHash: HASH_A,
    strategyHashes: {
      baseline: baselineHash,
      candidate: candidateHash,
    },
    evaluatorVersion: "security-evaluator-v1",
    evaluatorHash: HASH_C,
    benchmarkSnapshotHash: HASH_B,
    containerImageDigest: `sha256:${HASH_A}`,
    executionEnvironment: {
      kind: "oci_container",
      identityHash: HASH_A,
    },
    toolManifestHash: HASH_B,
    providerModel: {
      providerId: "public-proposal-provider",
      modelId: "proposal-model",
      promptTemplateHash: HASH_C,
    },
    contextPackIds: [`context-${input.experimentId}`],
    randomSeeds: [`seed-${input.sequence}`],
    eventHash: input.sequence % 2 === 0 ? HASH_A : HASH_B,
    evidenceHash: input.sequence % 2 === 0 ? HASH_B : HASH_C,
    metricsHash: input.sequence % 2 === 0 ? HASH_C : HASH_A,
    exposureReceiptIds: [input.exposureReceiptId],
    evaluationStage: input.evaluationAction.startsWith("hidden_holdout_")
      ? "hidden_holdout"
      : input.evaluationAction.split("_", 1)[0] as
        ExperimentIntegrityPayload["evaluationStage"],
    evaluationAction: input.evaluationAction,
    evaluationResult: input.evaluationAction.endsWith("_pass")
      ? "pass"
      : "fail",
    evaluationAttemptId: `attempt-${input.experimentId}-${input.sequence}`,
    hardGateFailures: input.hardGateFailures ?? [],
    signedAt: `2026-07-24T${String(input.sequence).padStart(2, "0")}:00:00.000Z`,
  };
  const receipt = fixtureValue.authority.createReceipt(payload);
  if (input.persist !== false) {
    fixtureValue.repository.persistIntegrityReceipt(receipt);
  }
  return receipt;
}

function appendDirectAudit(
  fixtureValue: Fixture,
  experimentId: string,
  suffix: string,
): string {
  const id = `audit-direct-${suffix}`;
  fixtureValue.database.prepare(`
    INSERT INTO audit_records (
      id, actor_type, actor_id, action, resource_type, resource_id,
      reason, details_json, record_hash, occurred_at
    ) VALUES (?, 'operator', 'direct-sql-test', 'research_promotion.direct',
      'research_promotion', ?, 'Direct SQL invariant test.', '{}', ?, ?)
  `).run(
    id,
    experimentId,
    HASH_A,
    "2026-07-24T13:00:00.000Z",
  );
  return id;
}

function insertDirectTransition(
  fixtureValue: Fixture,
  input: {
    readonly experimentId: string;
    readonly strategyId: string;
    readonly suffix: string;
    readonly fromState: string;
    readonly toState: string;
    readonly action: string;
    readonly actorKind: string;
    readonly integrityReceiptId?: string;
    readonly hardGateFailures?: readonly string[];
    readonly exposureReceiptIds?: readonly string[];
    readonly decisionFingerprint?: string | null;
  },
) {
  const lifecycle = fixtureValue.database.prepare(`
    SELECT version, record_hash, promotion_record_json
    FROM research_promotion_lifecycles
    WHERE experiment_id = ?
  `).get(input.experimentId) as {
    readonly version: number;
    readonly record_hash: string;
    readonly promotion_record_json: string;
  };
  const record = JSON.parse(lifecycle.promotion_record_json) as {
    readonly history: readonly unknown[];
  };
  const auditId = appendDirectAudit(
    fixtureValue,
    input.experimentId,
    input.suffix,
  );
  const decisionFingerprint = Object.prototype.hasOwnProperty.call(
    input,
    "decisionFingerprint",
  )
    ? input.decisionFingerprint ?? null
    : input.actorKind === "human_reviewer" ? HASH_A : null;
  return fixtureValue.database.prepare(`
    INSERT INTO research_promotion_transitions (
      id, experiment_id, strategy_version_id, sequence,
      lifecycle_version, from_state, to_state, action,
      actor_kind, actor_id, rationale, evidence_refs_json,
      hard_gate_failures_json, integrity_receipt_id,
      exposure_receipt_ids_json, decision_fingerprint, previous_record_hash,
      resulting_record_hash, audit_record_id, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'direct-sql-test',
      'Direct SQL invariant test.', '["direct-sql-evidence"]',
      ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    `transition-direct-${input.suffix}`,
    input.experimentId,
    input.strategyId,
    record.history.length + 1,
    lifecycle.version + 1,
    input.fromState,
    input.toState,
    input.action,
    input.actorKind,
    canonicalJson(input.hardGateFailures ?? []),
    input.integrityReceiptId ?? null,
    canonicalJson(input.exposureReceiptIds ?? []),
    decisionFingerprint,
    lifecycle.record_hash,
    HASH_C,
    auditId,
    "2026-07-24T13:00:00.000Z",
  );
}

function local(
  fixtureValue: Fixture,
  experimentId: string,
  action: LocalResearchPromotionAction,
  integrityReceiptId?: string,
  hardGateFailures: readonly string[] = [],
) {
  const lifecycle = fixtureValue.repository.get(experimentId);
  return fixtureValue.repository.applyLocalTransition({
    experimentId,
    expectedVersion: lifecycle.version,
    action,
    actorId: action.startsWith("policy_") ? "local-policy" : "local-evaluator",
    rationale: `${action.replaceAll("_", " ")} recorded by the trusted local boundary.`,
    evidenceRefs: [integrityReceiptId ?? `policy-${action}`],
    hardGateFailures,
    ...(integrityReceiptId ? { integrityReceiptId } : {}),
  });
}

function human(
  fixtureValue: Fixture,
  experimentId: string,
  action: HumanResearchPromotionAction,
  options: {
    readonly targetStrategyVersionId?: string;
    readonly canaryBounds?: {
      readonly maxMissions: number;
      readonly maxWallClockMs: number;
    };
  } = {},
) {
  const lifecycle = fixtureValue.repository.get(experimentId);
  return fixtureValue.repository.applyHumanTransition({
    experimentId,
    expectedVersion: lifecycle.version,
    action,
    actorId: "operator-research",
    rationale: `${action.replaceAll("_", " ")} approved after reviewing signed local evidence.`,
    evidenceRefs: [lifecycle.latestIntegrityReceiptId ?? `review-${action}`],
    ...options,
    idempotencyKey: `idempotency-${experimentId}-${action}-${lifecycle.version}`,
  });
}

function verifyCandidate(
  fixtureValue: Fixture,
  candidate: ReturnType<typeof addExperiment>,
  receiptOffset: number,
) {
  local(fixtureValue, candidate.experimentId, "policy_accept");
  local(fixtureValue, candidate.experimentId, "start_benchmark");
  const development = integrityReceipt(fixtureValue, {
    ...candidate,
    sequence: receiptOffset + 1,
    evaluationAction: "development_pass",
  });
  local(
    fixtureValue,
    candidate.experimentId,
    "development_pass",
    development.id,
  );
  const validation = integrityReceipt(fixtureValue, {
    ...candidate,
    sequence: receiptOffset + 2,
    evaluationAction: "validation_pass",
  });
  local(
    fixtureValue,
    candidate.experimentId,
    "validation_pass",
    validation.id,
  );
  const holdout = integrityReceipt(fixtureValue, {
    ...candidate,
    sequence: receiptOffset + 3,
    evaluationAction: "hidden_holdout_pass",
  });
  local(
    fixtureValue,
    candidate.experimentId,
    "hidden_holdout_pass",
    holdout.id,
  );
  human(fixtureValue, candidate.experimentId, "approve_human_review");
  human(fixtureValue, candidate.experimentId, "start_shadow");
  const shadow = integrityReceipt(fixtureValue, {
    ...candidate,
    sequence: receiptOffset + 4,
    evaluationAction: "shadow_pass",
  });
  local(fixtureValue, candidate.experimentId, "shadow_pass", shadow.id);
  human(fixtureValue, candidate.experimentId, "approve_canary");
  human(fixtureValue, candidate.experimentId, "start_canary", {
    canaryBounds: { maxMissions: 2, maxWallClockMs: 3_600_000 },
  });
  const canary = integrityReceipt(fixtureValue, {
    ...candidate,
    sequence: receiptOffset + 5,
    evaluationAction: "canary_pass",
  });
  local(fixtureValue, candidate.experimentId, "canary_pass", canary.id);
  return human(fixtureValue, candidate.experimentId, "verify").lifecycle;
}

describe("durable Research Lab promotion lifecycle", () => {
  test("requires every signed stage, keeps shadow isolated, bounds canary, and never auto-deploys verified strategy", () => {
    const value = fixture();
    try {
      const candidate = addExperiment(value, "candidate-a", 2);
      const verified = verifyCandidate(value, candidate, 0);
      expect(verified.state).toBe("verified");
      expect(verified.stage).toBe("verified");
      expect(verified.milestones).toEqual({
        developmentPassed: true,
        validationPassed: true,
        hiddenHoldoutPassed: true,
        humanReviewApproved: true,
        shadowPassed: true,
        canaryPassed: true,
      });
      expect(verified.transitions.map(({ action }) => action)).toEqual([
        "policy_accept",
        "start_benchmark",
        "development_pass",
        "validation_pass",
        "hidden_holdout_pass",
        "approve_human_review",
        "start_shadow",
        "shadow_pass",
        "approve_canary",
        "start_canary",
        "canary_pass",
        "verify",
      ]);
      expect(value.database.prepare(`
        SELECT deployment_stage, isolation_mode, max_missions,
          max_wall_clock_ms
        FROM strategy_deployments
        ORDER BY created_at, deployment_stage DESC
      `).all()).toEqual([
        {
          deployment_stage: "shadow",
          isolation_mode: "no_live_effect",
          max_missions: null,
          max_wall_clock_ms: null,
        },
        {
          deployment_stage: "canary",
          isolation_mode: "bounded_canary",
          max_missions: 2,
          max_wall_clock_ms: 3_600_000,
        },
      ]);
      expect(value.database.prepare(`
        SELECT COUNT(*) AS count
        FROM strategy_deployments
        WHERE deployment_stage = 'verified'
      `).get()).toEqual({ count: 0 });
      expect(value.database.prepare(`
        SELECT action, selected_strategy_version_id
        FROM research_strategy_activation_versions
      `).get()).toEqual({
        action: "verified_selection",
        selected_strategy_version_id: candidate.strategyId,
      });
    } finally {
      value.database.close();
    }
  });

  test("hard gates prevent a passing transition and leave version, state, and immutable history unchanged", () => {
    const value = fixture();
    try {
      const candidate = addExperiment(value, "gated", 2);
      local(value, candidate.experimentId, "policy_accept");
      local(value, candidate.experimentId, "start_benchmark");
      const receipt = integrityReceipt(value, {
        ...candidate,
        sequence: 1,
        evaluationAction: "development_pass",
      });
      const before = value.repository.get(candidate.experimentId);
      expect(() => local(
        value,
        candidate.experimentId,
        "development_pass",
        receipt.id,
        ["scope_violation"],
      )).toThrow("hard-gate failure");
      const after = value.repository.get(candidate.experimentId);
      expect(after).toEqual(before);
      const failedReceipt = integrityReceipt(value, {
        ...candidate,
        sequence: 2,
        evaluationAction: "development_fail",
        hardGateFailures: ["scope_violation"],
      });
      const failed = local(
        value,
        candidate.experimentId,
        "development_fail",
        failedReceipt.id,
        ["scope_violation"],
      );
      expect(failed.state).toBe("early_aborted");
      expect(failed.transitions.at(-1)?.hardGateFailures).toEqual([
        "scope_violation",
      ]);
    } finally {
      value.database.close();
    }
  });

  test("rejects missing, tampered, and exposure-unbound evaluator receipts before lifecycle mutation", () => {
    const value = fixture();
    try {
      const candidate = addExperiment(value, "receipt-guard", 2);
      local(value, candidate.experimentId, "policy_accept");
      local(value, candidate.experimentId, "start_benchmark");
      const before = value.repository.get(candidate.experimentId);
      expect(() => local(
        value,
        candidate.experimentId,
        "development_pass",
      )).toThrow("signed integrity receipt");

      const receipt = integrityReceipt(value, {
        ...candidate,
        sequence: 1,
        evaluationAction: "development_pass",
      });
      expect(() => value.repository.persistIntegrityReceipt({
        ...receipt,
        signature: HASH_A,
      })).toThrow("signature");

      const {
        id: _id,
        algorithm: _algorithm,
        signature: _signature,
        ...payload
      } = receipt;
      const unbound = value.authority.createReceipt({
        ...payload,
        randomSeeds: ["seed-unbound-exposure"],
        exposureReceiptIds: ["missing-exposure-receipt"],
      });
      expect(() =>
        value.repository.persistIntegrityReceipt(unbound),
      ).toThrow("missing, blocked, or differently scoped");
      expect(value.repository.get(candidate.experimentId)).toEqual(before);
    } finally {
      value.database.close();
    }
  });

  test("enforces optimistic concurrency and exact idempotency for human decisions", () => {
    const value = fixture();
    try {
      const candidate = addExperiment(value, "human-review", 2);
      local(value, candidate.experimentId, "policy_accept");
      local(value, candidate.experimentId, "start_benchmark");
      for (const [index, action] of [
        "development_pass",
        "validation_pass",
        "hidden_holdout_pass",
      ].entries()) {
        const receipt = integrityReceipt(value, {
          ...candidate,
          sequence: index + 1,
          evaluationAction: action as
            ExperimentIntegrityPayload["evaluationAction"],
        });
        local(
          value,
          candidate.experimentId,
          action as LocalResearchPromotionAction,
          receipt.id,
        );
      }
      const current = value.repository.get(candidate.experimentId);
      const request = {
        experimentId: candidate.experimentId,
        expectedVersion: current.version,
        action: "approve_human_review" as const,
        actorId: "operator-research",
        rationale:
          "Signed holdout passed every immutable hard gate.\nEvidence quality remained stable.",
        evidenceRefs: [current.latestIntegrityReceiptId!],
        idempotencyKey: "human-review-idempotency",
      };
      expect(() => value.repository.applyHumanTransition({
        ...request,
        evidenceRefs: [`${current.latestIntegrityReceiptId!}\u0000hidden`],
        idempotencyKey: "human-review-control-bearing-evidence",
      })).toThrow("stable evidence or receipt reference");
      const accepted = value.repository.applyHumanTransition(request);
      const expectedDecisionFingerprint = sha256(
        canonicalResearchPromotionDecision({
          expectedVersion: current.version,
          action: request.action,
          actorId: request.actorId,
          rationale: request.rationale,
          evidenceRefs: request.evidenceRefs,
        }),
      );
      expect(accepted.lifecycle.transitions.at(-1)?.decisionFingerprint)
        .toBe(expectedDecisionFingerprint);
      expect(value.database.prepare(`
        SELECT decision_fingerprint
        FROM research_promotion_transitions
        WHERE experiment_id = ?
        ORDER BY sequence DESC
        LIMIT 1
      `).get(candidate.experimentId)).toEqual({
        decision_fingerprint: expectedDecisionFingerprint,
      });
      expect(value.repository.applyHumanTransition(request)).toEqual(accepted);
      expect(() => value.repository.applyHumanTransition({
        ...request,
        rationale: "A materially different decision.",
      })).toThrow("already used for a different decision");
      expect(() => value.repository.applyHumanTransition({
        ...request,
        idempotencyKey: "stale-human-review-version",
      })).toThrow("changed after this view loaded");
      expect(value.database.prepare(`
        SELECT COUNT(*) AS count
        FROM promotion_reviews
        WHERE strategy_version_id = ?
      `).get(candidate.strategyId)).toEqual({ count: 1 });
    } finally {
      value.database.close();
    }
  });

  test("rolls back through a new immutable activation pointer without copying a strategy bundle", () => {
    const value = fixture();
    try {
      const first = addExperiment(value, "first-verified", 2);
      verifyCandidate(value, first, 0);
      const second = addExperiment(value, "second-verified", 3);
      verifyCandidate(value, second, 6);
      const strategyCountBefore = (
        value.database.prepare(
          "SELECT COUNT(*) AS count FROM strategy_versions",
        ).get() as { readonly count: number }
      ).count;
      const rolledBack = human(
        value,
        second.experimentId,
        "rollback",
        { targetStrategyVersionId: first.strategyId },
      ).lifecycle;
      expect(rolledBack.state).toBe("rolled_back");
      expect(
        value.database.prepare(
          "SELECT COUNT(*) AS count FROM strategy_versions",
        ).get(),
      ).toEqual({ count: strategyCountBefore });
      expect(value.database.prepare(`
        SELECT ordinal, action, selected_strategy_version_id,
          previous_activation_id
        FROM research_strategy_activation_versions
        ORDER BY ordinal
      `).all()).toEqual([
        {
          ordinal: 1,
          action: "verified_selection",
          selected_strategy_version_id: first.strategyId,
          previous_activation_id: null,
        },
        {
          ordinal: 2,
          action: "verified_selection",
          selected_strategy_version_id: second.strategyId,
          previous_activation_id: expect.any(String),
        },
        {
          ordinal: 3,
          action: "forward_rollback",
          selected_strategy_version_id: first.strategyId,
          previous_activation_id: expect.any(String),
        },
      ]);
      expect(value.database.prepare(`
        SELECT from_strategy_id, to_strategy_id, integrity_verified,
          activation_version_id
        FROM strategy_rollbacks
      `).get()).toEqual({
        from_strategy_id: second.strategyId,
        to_strategy_id: first.strategyId,
        integrity_verified: 1,
        activation_version_id: expect.any(String),
      });
      expect(() => value.database.prepare(`
        UPDATE research_strategy_activation_versions
        SET action = 'verified_selection'
        WHERE ordinal = 3
      `).run()).toThrow("immutable");
      expect(() => value.database.prepare(`
        UPDATE integrity_receipts
        SET metrics_hash = ?
        WHERE experiment_id = ?
      `).run(HASH_B, first.experimentId)).toThrow("immutable");
      expect(() => value.database.prepare(`
        DELETE FROM provider_exposure_receipts
        WHERE experiment_id = ?
      `).run(first.experimentId)).toThrow("immutable");
      expect(() => value.database.prepare(`
        UPDATE strategy_deployments
        SET max_missions = 10
        WHERE strategy_version_id = ?
          AND deployment_stage = 'canary'
      `).run(first.strategyId)).toThrow(
        "scope, isolation, bounds, and provenance are immutable",
      );
      expect(() => value.database.prepare(`
        DELETE FROM strategy_deployments
        WHERE strategy_version_id = ?
      `).run(first.strategyId)).toThrow("immutable");
    } finally {
      value.database.close();
    }
  });

  test("rejects direct activation inserts with cross-campaign strategies, mismatched receipts, or a broken chain", () => {
    const value = fixture();
    try {
      const candidate = addExperiment(value, "activation-guard", 2);
      verifyCandidate(value, candidate, 0);
      const current = value.database.prepare(`
        SELECT id, ordinal
        FROM research_strategy_activation_versions
        WHERE campaign_id = ?
      `).get(CAMPAIGN_ID) as {
        readonly id: string;
        readonly ordinal: number;
      };
      const receipt = value.database.prepare(`
        SELECT id
        FROM integrity_receipts
        WHERE experiment_id = ?
        ORDER BY signed_at DESC, id DESC
        LIMIT 1
      `).get(candidate.experimentId) as { readonly id: string };
      const insert = (input: {
        readonly id: string;
        readonly campaignId: string;
        readonly previousActivationId: string | null;
        readonly selectedStrategyVersionId: string;
        readonly ordinal: number;
        readonly sourceExperimentId?: string;
        readonly integrityReceiptId?: string;
      }) => value.database.prepare(`
        INSERT INTO research_strategy_activation_versions (
          id, campaign_id, previous_activation_id,
          selected_strategy_version_id, source_experiment_id, ordinal,
          action, reason, actor_id, integrity_receipt_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'verified_selection', ?, ?, ?, ?)
      `).run(
        input.id,
        input.campaignId,
        input.previousActivationId,
        input.selectedStrategyVersionId,
        input.sourceExperimentId ?? candidate.experimentId,
        input.ordinal,
        "Direct activation integrity test.",
        "operator-research",
        input.integrityReceiptId ?? receipt.id,
        "2026-07-24T13:00:00.000Z",
      );

      value.database.prepare(`
        INSERT INTO research_campaigns (
          id, name, purpose, status, owner, budgets_json,
          created_at, updated_at
        ) VALUES (
          'research-campaign-other', 'Repeated and no-progress action reduction',
          'Cross-campaign activation guard fixture.', 'running',
          'operator-research', '{}', ?, ?
        )
      `).run(
        "2026-07-24T13:00:00.000Z",
        "2026-07-24T13:00:00.000Z",
      );

      expect(() => insert({
        id: "activation-cross-campaign",
        campaignId: "research-campaign-other",
        previousActivationId: null,
        selectedStrategyVersionId: candidate.strategyId,
        ordinal: 1,
      })).toThrow("selected strategy is not verified in its campaign");

      expect(() => insert({
        id: "activation-receipt-mismatch",
        campaignId: CAMPAIGN_ID,
        previousActivationId: current.id,
        selectedStrategyVersionId: BASELINE_ID,
        ordinal: current.ordinal + 1,
      })).toThrow("receipt does not bind its selected strategy");

      expect(() => insert({
        id: "activation-broken-chain",
        campaignId: CAMPAIGN_ID,
        previousActivationId: current.id,
        selectedStrategyVersionId: candidate.strategyId,
        ordinal: current.ordinal + 2,
      })).toThrow("previous pointer or ordinal is invalid");

      expect(value.database.prepare(`
        SELECT COUNT(*) AS count
        FROM research_strategy_activation_versions
        WHERE campaign_id = ?
      `).get(CAMPAIGN_ID)).toEqual({ count: 1 });
    } finally {
      value.database.close();
    }
  });

  test("rejects a second signed receipt for the same evaluator attempt", () => {
    const value = fixture();
    try {
      const candidate = addExperiment(value, "attempt-reuse", 2);
      const first = integrityReceipt(value, {
        ...candidate,
        sequence: 1,
        evaluationAction: "development_pass",
      });
      const {
        id: _id,
        algorithm: _algorithm,
        signature: _signature,
        ...payload
      } = first;
      const contradictory = value.authority.createReceipt({
        ...payload,
        metricsHash: HASH_B,
        evaluationResult: "fail",
        evaluationAction: "development_fail",
        hardGateFailures: ["scope_violation"],
      });
      expect(() =>
        value.repository.persistIntegrityReceipt(contradictory)
      ).toThrow();
      expect(value.database.prepare(`
        SELECT evaluation_attempt_id, evaluation_action, evaluation_result
        FROM integrity_receipts
        WHERE experiment_id = ?
      `).all(candidate.experimentId)).toEqual([{
        evaluation_attempt_id: first.evaluationAttemptId,
        evaluation_action: "development_pass",
        evaluation_result: "pass",
      }]);
    } finally {
      value.database.close();
    }
  });

  test("rejects evaluator receipts that diverge from canonical evaluator, tool, container, prompt, or provider bindings", () => {
    const value = fixture();
    try {
      const candidate = addExperiment(value, "canonical-bindings", 2);
      const valid = integrityReceipt(value, {
        ...candidate,
        sequence: 1,
        evaluationAction: "development_pass",
        persist: false,
      });
      const {
        id: _id,
        algorithm: _algorithm,
        signature: _signature,
        ...payload
      } = valid;
      const invalidPayloads: readonly ExperimentIntegrityPayload[] = [
        { ...payload, evaluatorVersion: "security-evaluator-v2" },
        { ...payload, evaluatorHash: HASH_A },
        { ...payload, toolManifestHash: HASH_C },
        { ...payload, containerImageDigest: `sha256:${HASH_B}` },
        {
          ...payload,
          providerModel: {
            ...payload.providerModel!,
            promptTemplateHash: HASH_A,
          },
        },
        {
          ...payload,
          providerModel: {
            ...payload.providerModel!,
            modelId: "different-model",
          },
        },
      ];
      for (const invalidPayload of invalidPayloads) {
        expect(() => value.repository.persistIntegrityReceipt(
          value.authority.createReceipt(invalidPayload),
        )).toThrow();
      }
      expect(value.database.prepare(`
        SELECT COUNT(*) AS count
        FROM integrity_receipts
        WHERE experiment_id = ?
      `).get(candidate.experimentId)).toEqual({ count: 0 });
    } finally {
      value.database.close();
    }
  });

  test("database triggers deny direct lifecycle, transition, exposure, and production-deployment bypasses", () => {
    const lifecycleValue = fixture();
    try {
      const candidate = addExperiment(lifecycleValue, "direct-lifecycle", 2);
      expect(() => lifecycleValue.database.prepare(`
        UPDATE research_promotion_lifecycles
        SET version = version + 1,
          record_hash = ?,
          updated_at = ?
        WHERE experiment_id = ?
      `).run(
        HASH_C,
        "2026-07-24T13:00:00.000Z",
        candidate.experimentId,
      )).toThrow("not bound to its transition");

      expect(() => insertDirectTransition(lifecycleValue, {
        ...candidate,
        suffix: "wrong-actor",
        fromState: "proposed",
        toState: "queued",
        action: "policy_accept",
        actorKind: "human_reviewer",
      })).toThrow("action, state, or actor authority is invalid");

      expect(() => insertDirectTransition(lifecycleValue, {
        ...candidate,
        suffix: "human-fingerprint-missing",
        fromState: "proposed",
        toState: "rejected",
        action: "reject",
        actorKind: "human_reviewer",
        decisionFingerprint: null,
      })).toThrow("human decision fingerprint binding is invalid");

      expect(() => insertDirectTransition(lifecycleValue, {
        ...candidate,
        suffix: "local-fingerprint-present",
        fromState: "proposed",
        toState: "queued",
        action: "policy_accept",
        actorKind: "local_policy",
        decisionFingerprint: HASH_A,
      })).toThrow("human decision fingerprint binding is invalid");

      expect(() => lifecycleValue.database.prepare(`
        INSERT INTO strategy_deployments (
          id, strategy_version_id, deployment_stage, scope_json,
          status, approved_by, created_at, isolation_mode,
          lifecycle_version
        ) VALUES (
          'deployment-direct-verified', ?, 'verified', '{}',
          'ready', 'direct-sql-test', ?, 'no_live_effect', 1
        )
      `).run(
        candidate.strategyId,
        "2026-07-24T13:00:00.000Z",
      )).toThrow("cannot deploy it");
    } finally {
      lifecycleValue.database.close();
    }

    const receiptValue = fixture();
    try {
      const candidate = addExperiment(receiptValue, "direct-receipt", 2);
      local(receiptValue, candidate.experimentId, "policy_accept");
      local(receiptValue, candidate.experimentId, "start_benchmark");
      const receipt = integrityReceipt(receiptValue, {
        ...candidate,
        sequence: 1,
        evaluationAction: "development_pass",
      });
      expect(() => insertDirectTransition(receiptValue, {
        ...candidate,
        suffix: "wrong-stage",
        fromState: "running",
        toState: "benchmarked",
        action: "validation_pass",
        actorKind: "local_evaluator",
        integrityReceiptId: receipt.id,
        exposureReceiptIds: [candidate.exposureReceiptId],
      })).toThrow("receipt is missing or misbound");

      expect(() => insertDirectTransition(receiptValue, {
        ...candidate,
        suffix: "wrong-exposure",
        fromState: "running",
        toState: "running",
        action: "development_pass",
        actorKind: "local_evaluator",
        integrityReceiptId: receipt.id,
        exposureReceiptIds: [],
      })).toThrow("receipt is missing or misbound");
    } finally {
      receiptValue.database.close();
    }
  });

  test("only the latest active strategy can initiate rollback and it cannot be stale or superseded in place", () => {
    const value = fixture();
    try {
      const first = addExperiment(value, "selection-first", 2);
      verifyCandidate(value, first, 0);
      const second = addExperiment(value, "selection-second", 3);
      verifyCandidate(value, second, 6);

      expect(() => human(
        value,
        first.experimentId,
        "rollback",
        { targetStrategyVersionId: second.strategyId },
      )).toThrow("latest immutable activation");
      expect(() => human(
        value,
        second.experimentId,
        "mark_stale",
      )).toThrow("cannot become stale or superseded");
      expect(() => human(
        value,
        second.experimentId,
        "supersede",
      )).toThrow("cannot become stale or superseded");

      const latest = value.database.prepare(`
        SELECT selected_strategy_version_id
        FROM research_strategy_activation_versions
        WHERE campaign_id = ?
        ORDER BY ordinal DESC
        LIMIT 1
      `).get(CAMPAIGN_ID);
      expect(latest).toEqual({
        selected_strategy_version_id: second.strategyId,
      });
      expect(value.repository.get(second.experimentId).state).toBe("verified");
    } finally {
      value.database.close();
    }
  });
});

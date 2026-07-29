import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { AttackAttemptService } from "../../run-intelligence";
import {
  MemoryRepository,
  OperationalHazardHealthGateError,
  OperationalHazardHealthGateService,
  OperationalHazardMatcher,
  OperationalHazardProfileRepository,
  operationalHazardRetryContractHash,
  type MemoryNodeType,
  type OperationalHazardContext,
} from "../index";

const START = Date.parse("2026-07-20T12:00:00.000Z");

function opaqueMemoryId(label: string): string {
  return `mem_${createHash("sha256").update(label).digest("hex")}`;
}

function addNode(repository: MemoryRepository, id: string, nodeType: MemoryNodeType): void {
  repository.createNode({
    id,
    nodeType,
    title: `${nodeType.replaceAll("_", " ")} reviewed fixture`,
    summary: "Generalized, reviewed attack knowledge without private target identifiers.",
    body: "Use only with an exact procedure, version, environment, and target-context match.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.98,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "Locally evaluated evidence was reviewed before this reusable node was verified.",
      sources: [{ sourceType: "evaluation", sourceId: `receipt-${id}`, acquiredAt: new Date(START).toISOString() }],
    },
    authorType: "operator",
    authorId: "operator:test",
    retentionPolicy: { journeys: ["autonomous", "guided"] },
  });
}

function fixture(options: {
  readonly evidenceState?: "verified" | "unverified";
  readonly evidenceType?: string;
  readonly evidenceSource?: string;
  readonly evidenceProvenance?: Readonly<Record<string, unknown>>;
  readonly baselineRestored?: boolean;
  readonly retryConditionResults?: Readonly<Record<string, boolean>>;
  readonly omitRetryContract?: boolean;
} = {}) {
  let nowMs = START;
  const clock = () => new Date(nowMs);
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  const now = clock().toISOString();
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      engagement_id, scope_json, memory_policy_json, created_by,
      created_at, updated_at, control_plane
    ) VALUES ('mission-health', 'Private fixture', 'Validate one bounded lab procedure',
      'guided', 'active', 'verified', 'environment-health', '{"environment":"disposable"}',
      '{}', 'operator:test', ?, ?, 'ti_scale')
  `).run(now, now);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-health', 'mission-health', 'service.local', 'domain', 'allowed', 'service.local', ?)
  `).run(now);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, budget_json, budget_usage_json,
      created_at, updated_at, control_plane
    ) VALUES ('run-health', 'mission-health', 'guided', 'running', '{}', '{}', ?, ?, 'ti_scale')
  `).run(now, now);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      content_hash, content_hash_version, created_by, created_at
    ) VALUES ('plan-health', 'run-health', 1, 'active', 'Health-gated recovery', ?, ?, 1, 'planner', ?)
  `).run("a".repeat(64), "a".repeat(64), now);
  for (const [id, ordinal, title] of [
    ["step-source", 0, "Known-bad attempt"],
    ["step-health", 1, "Represented health check"],
    ["step-safer", 2, "Distinct safer attempt"],
    ["step-cross", 3, "Different target attempt"],
  ] as const) {
    database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        action_class, risk_class, created_at, updated_at
      ) VALUES (?, 'plan-health', 'run-health', ?, 'validation', ?,
        'Verify a bounded recovery path', 'ready', 'exploit_validation', 'high', ?, ?)
    `).run(id, ordinal, title, now, now);
  }
  for (const [id, identity] of [["asset-primary", "service.local"], ["asset-other", "other.local"]] as const) {
    database.prepare(`
      INSERT INTO topology_nodes (
        id, mission_id, run_id, node_type, primary_label, normalized_identity,
        scope_status, lifecycle_state, properties_json, confidence,
        verification_state, sensitivity, first_seen_at, last_seen_at,
        created_at, updated_at
      ) VALUES (?, 'mission-health', 'run-health', 'asset', ?, ?, 'allowed',
        'observed', '{"stack":"reviewed"}', 1, 'verified', 'private', ?, ?, ?, ?)
    `).run(id, identity, identity, now, now, now, now);
  }

  const memory = new MemoryRepository(database, { clock });
  const ids = {
    hazard: opaqueMemoryId("health-gate-hazard-worker-hang"),
    procedure: opaqueMemoryId("health-gate-procedure-known-bad"),
    procedureVersion: opaqueMemoryId("health-gate-procedure-version-known-bad"),
    saferProcedure: opaqueMemoryId("health-gate-procedure-reviewed-safer"),
    saferProcedureVersion: opaqueMemoryId("health-gate-procedure-version-safer"),
    arbitraryProcedureVersion: opaqueMemoryId("health-gate-procedure-version-arbitrary"),
    product: opaqueMemoryId("health-gate-product-reviewed"),
    version: opaqueMemoryId("health-gate-version-reviewed"),
    stack: opaqueMemoryId("health-gate-runtime-reviewed"),
  } as const;
  addNode(memory, ids.hazard, "operational_hazard");
  addNode(memory, ids.procedure, "attack_procedure");
  addNode(memory, ids.procedureVersion, "procedure_version");
  addNode(memory, ids.saferProcedure, "attack_procedure");
  addNode(memory, ids.saferProcedureVersion, "procedure_version");
  addNode(memory, ids.arbitraryProcedureVersion, "procedure_version");
  addNode(memory, ids.product, "technology_product");
  addNode(memory, ids.version, "exact_version_fingerprint");
  addNode(memory, ids.stack, "runtime");
  const reviewedRetryContract = {
    schema: "ti_scale.operational_hazard_retry_contract/v1" as const,
    alternativeKind: "explicit_alternative" as const,
    source: {
      procedureNodeId: ids.procedure,
      procedureVersionNodeId: ids.procedureVersion,
      normalizedParameters: { payload_shape: "known-bad" },
      load: 1,
      concurrency: 1,
      timingWindowMs: 2_000,
    },
    alternative: {
      procedureNodeId: ids.saferProcedure,
      procedureVersionNodeId: ids.saferProcedureVersion,
      normalizedParameters: { payload_shape: "bounded-safer" },
      load: 1,
      concurrency: 1,
      timingWindowMs: 2_000,
    },
    retryValidConditions: [
      {
        id: "baseline_restored",
        statement: "A locally evaluated response proves baseline health",
        evidenceKey: "baseline_response_ok",
      },
      {
        id: "worker_queue_drained",
        statement: "The local worker queue has returned to its reviewed safe bound",
        evidenceKey: "worker_queue_within_bound",
      },
    ],
  };
  new OperationalHazardProfileRepository(database, { clock }).create({
    hazardNodeId: ids.hazard,
    procedureNodeId: ids.procedure,
    procedureVersionNodeId: ids.procedureVersion,
    productNodeIds: [ids.product],
    versionNodeIds: [ids.version],
    stackNodeIds: [ids.stack],
    prerequisiteNodeIds: [],
    observedStateNodeIds: [],
    orderedSteps: ["Check baseline", "Use one bounded safer attempt"],
    normalizedParameters: { payload_shape: "known-bad" },
    loadMinimum: 1,
    concurrencyMinimum: 1,
    timingWindowMs: 5_000,
    observedSymptom: "The application worker stopped returning responses",
    affectedComponent: "Managed application worker",
    stateBefore: "Healthy bounded-response state",
    stateAfter: "Wedged response state",
    reproducibilityCount: 2,
    attemptCount: 2,
    recoveryActionSummary: "Recycle the disposable worker and prove baseline health",
    recoveryCost: {
      resetCount: 2,
      operatorReportedResetCountMinimum: 11,
      serviceRecycleCount: 2,
      requiresDisposableTargetReset: true,
    },
    unsafeRetryConditions: ["Baseline health check is failing"],
    safeRetryGate: [
      "A locally evaluated response proves baseline health",
      "The local worker queue has returned to its reviewed safe bound",
    ],
    alternativeSequence: ["Restore baseline", "Use the bounded safer variant once"],
    alternativeProcedureNodeId: ids.saferProcedure,
    ...(options.omitRetryContract ? {} : { reviewedRetryContract }),
    confidence: 0.98,
    observedAt: now,
    freshUntil: new Date(START + 24 * 60 * 60_000).toISOString(),
  });

  const attempts = new AttackAttemptService(database, clock);
  const context = (
    version: string,
    payload: string,
    procedureNodeId = ids.procedure,
  ): OperationalHazardContext => ({
    procedureNodeId,
    procedureVersionNodeId: version,
    productNodeIds: [ids.product],
    versionNodeIds: [ids.version],
    stackNodeIds: [ids.stack],
    prerequisiteNodeIds: [],
    observedStateNodeIds: [],
    normalizedParameters: { payload_shape: payload },
    load: 1,
    concurrency: 1,
    timingWindowMs: 2_000,
  });
  const createAttempt = (
    stepId: string,
    assetId: string,
    knowledge: OperationalHazardContext,
    recoverySourceAttackAttemptId?: string,
  ) => {
    const created = attempts.create({
      missionId: "mission-health",
      runId: "run-health",
      planId: "plan-health",
      stepId,
      targetAssetId: assetId,
      objective: "Validate one bounded procedure",
      techniqueName: "Reviewed bounded procedure",
      actionClass: "exploit_validation",
      normalizedParameters: { represented: true },
      representedActionBinding: {
        actionType: "bounded_safer_validation",
        actionClass: "exploit_validation",
        normalizedArguments: {},
        scopedTarget: assetId === "asset-primary" ? "service.local" : "other.local",
      },
      reviewedKnowledgeBinding: knowledge,
      ...(recoverySourceAttackAttemptId ? { recoverySourceAttackAttemptId } : {}),
    });
    return attempts.transition({
      attemptId: created.id,
      expectedVersion: created.version,
      status: "ready",
      actorId: "operator:test",
      actorType: "operator",
    });
  };
  const sourceReady = createAttempt("step-source", "asset-primary", context(ids.procedureVersion, "known-bad"));
  const source = attempts.transition({
    attemptId: sourceReady.id,
    expectedVersion: sourceReady.version,
    status: "waiting_conditions",
    reason: "Exact verified operational hazard requires a health check",
    actorId: "operational-hazard-gate",
    actorType: "system",
  });
  const safer = createAttempt(
    "step-safer", "asset-primary",
    context(ids.saferProcedureVersion, "bounded-safer", ids.saferProcedure), source.id,
  );
  const unlinkedSafer = createAttempt(
    "step-safer", "asset-primary",
    context(ids.saferProcedureVersion, "bounded-safer", ids.saferProcedure),
  );
  const identical = createAttempt(
    "step-safer", "asset-primary", context(ids.procedureVersion, "known-bad"), source.id,
  );
  const crossTarget = createAttempt(
    "step-cross", "asset-other",
    context(ids.saferProcedureVersion, "bounded-safer", ids.saferProcedure),
  );
  const arbitraryVersion = createAttempt(
    "step-safer", "asset-primary",
    context(ids.arbitraryProcedureVersion, "different-version"), source.id,
  );
  const arbitraryParameters = createAttempt(
    "step-safer", "asset-primary",
    context(ids.procedureVersion, "merely-different"), source.id,
  );
  const createCrossTargetRecovery = () => attempts.create({
    missionId: "mission-health",
    runId: "run-health",
    planId: "plan-health",
    stepId: "step-cross",
    targetAssetId: "asset-other",
    recoverySourceAttackAttemptId: source.id,
    objective: "Attempt to cross a private target boundary",
    techniqueName: "Invalid cross-target recovery",
    actionClass: "exploit_validation",
    normalizedParameters: { represented: true },
    representedActionBinding: {
      actionType: "bounded_safer_validation",
      actionClass: "exploit_validation",
      normalizedArguments: {},
      scopedTarget: "other.local",
    },
    reviewedKnowledgeBinding: context(ids.saferProcedureVersion, "bounded-safer", ids.saferProcedure),
  });

  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, action_type, action_class, fingerprint,
      normalized_arguments_json, scoped_target, status, intent_summary,
      result_summary, retry_count, started_at, ended_at, created_at, updated_at
    ) VALUES ('action-health', 'mission-health', 'run-health', 'step-health',
      'operational_hazard_health_check', 'passive_intelligence_osint', ?,
      ?,
      'service.local', 'succeeded', 'Check the exact target baseline',
      'Expected bounded baseline response observed', 0, ?, ?, ?, ?)
  `).run(
    "b".repeat(64),
    JSON.stringify({
      input: {
        hazardNodeId: ids.hazard,
        hazardProfileVersion: 1,
        blockedAttackAttemptId: source.id,
        contextPackId: "pack-health",
      },
      orchestration: { kind: "tool", idempotent: true, destructive: false },
    }),
    now, now, now, now,
  );
  const evidenceHash = "c".repeat(64);
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, created_by, created_at
    ) VALUES ('evidence-health', 'mission-health', 'run-health', 'step-health',
      'action-health', ?, ?, 'service.local', ?, ?, ?, 1, 'private', ?,
      'Local baseline response matched the immutable evaluator', 'local-evidence-verifier', ?)
  `).run(
    options.evidenceSource ?? "local_tool_health_verifier",
    now,
    options.evidenceType ?? "health_check_result",
    evidenceHash,
    JSON.stringify({
      method: "local_tool_verification",
      boundary: "trusted_local",
      healthAssessment: {
        schema: "ti_scale.operational_health/v2",
        baselineRestored: options.baselineRestored ?? true,
        retryContractHash: operationalHazardRetryContractHash(reviewedRetryContract),
        retryConditionResults: options.retryConditionResults ?? {
          baseline_response_ok: true,
          worker_queue_within_bound: true,
        },
      },
      ...(options.evidenceProvenance ?? {}),
    }),
    options.evidenceState ?? "verified",
    now,
  );
  database.prepare(`
    INSERT INTO evidence_chain_events (id, evidence_id, event_type, actor, details_json, occurred_at)
    VALUES ('custody-health', 'evidence-health', 'verified', 'local-evidence-verifier',
      '{"method":"local_evaluator"}', ?)
  `).run(now);
  database.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, step_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, retrieval_metrics_json, created_by, created_at
    ) VALUES ('pack-health', 'mission-health', 'run-health', 'step-health', 'guided',
      'Operational hazard health gate', 'Exact hazard health gate', '{}', 3000, '{}',
      'local-operational-hazard-evaluator', ?)
  `).run(now);
  const insertItem = database.prepare(`
    INSERT INTO memory_context_items (
      context_pack_id, node_id, rank, retrieval_score, used,
      relevance_reason, influence_summary
    ) VALUES ('pack-health', ?, ?, 1, 1, 'Exact reviewed gate input', 'Required the local health gate')
  `);
  [ids.hazard, ids.procedure, ids.procedureVersion].forEach((id, rank) => insertItem.run(id, rank));

  const service = new OperationalHazardHealthGateService(database, { clock });
  const assess = (ttlMs = 60_000) => service.recordAssessment({
    hazardNodeId: ids.hazard,
    hazardProfileVersion: 1,
    blockedAttackAttemptId: source.id,
    representedHealthCheckActionId: "action-health",
    verifiedEvidenceId: "evidence-health",
    verifiedEvidenceHash: evidenceHash,
    contextPackId: "pack-health",
    actor: { id: "operator:test", type: "operator" },
    ttlMs,
  });
  const insertRunningAction = (
    id: string,
    stepId = "step-safer",
    argumentsValue: Readonly<Record<string, unknown>> = {},
  ) => {
    database.prepare(`
      INSERT INTO actions (
        id, mission_id, run_id, step_id, action_type, action_class, fingerprint,
        normalized_arguments_json, scoped_target, status, intent_summary,
        retry_count, started_at, created_at, updated_at
      ) VALUES (?, 'mission-health', 'run-health', ?, 'bounded_safer_validation',
        'exploit_validation', ?, ?,
        'service.local', 'running', 'Run one represented safer attempt', 0, ?, ?, ?)
    `).run(
      id,
      stepId,
      "e".repeat(64),
      JSON.stringify({
        input: argumentsValue,
        orchestration: { kind: "tool", idempotent: false, destructive: false },
      }),
      clock().toISOString(),
      clock().toISOString(),
      clock().toISOString(),
    );
    return {
      id, missionId: "mission-health", runId: "run-health", stepId,
      actionType: "bounded_safer_validation", actionClass: "exploit_validation",
      fingerprint: "e".repeat(64), arguments: argumentsValue, target: "service.local",
      kind: "tool" as const, intentSummary: "Run one represented safer attempt",
      status: "running" as const, idempotent: false, destructive: false,
      guidedDecisionId: null, contractId: null, contextPackId: null,
      resultSummary: null, errorCategory: null, retryCount: 0,
      progressSignature: null, createdAt: clock().toISOString(),
      startedAt: clock().toISOString(), endedAt: null,
    };
  };
  return {
    database, clock, advance: (milliseconds: number) => { nowMs += milliseconds; },
    service, assess, insertRunningAction, createCrossTargetRecovery,
    ids, source, safer, unlinkedSafer, identical, crossTarget,
    arbitraryVersion, arbitraryParameters,
  };
}

function expectCode(operation: () => unknown, code: string): void {
  expect(operation).toThrow(OperationalHazardHealthGateError);
  try { operation(); } catch (error) {
    expect((error as OperationalHazardHealthGateError).code).toBe(code);
  }
}

describe("OperationalHazardHealthGateService", () => {
  test("persists an immutable local pass while keeping exact and operator-reported reset costs distinct", () => {
    const value = fixture();
    try {
      const assessment = value.assess();
      expect(assessment).toMatchObject({
        result: "pass",
        evaluatorVersion: "operational-hazard-health/v2",
        evaluatorHash: "a5deb63c76404c368d0fd360cf7240786031399416329467e6daf9d10447af14",
        exactProcedureAttemptCount: 2,
        exactProcedureReproducibilityCount: 2,
        exactProcedureResetCount: 2,
        operatorReportedResetCountMinimum: 11,
      });
      expect(assessment.assessmentHash).toMatch(/^[a-f0-9]{64}$/u);
      expect(assessment.retryContractHash).toMatch(/^[a-f0-9]{64}$/u);
      expect(assessment.reviewedAlternativeHash).toMatch(/^[a-f0-9]{64}$/u);
      expect(assessment.retryConditionProofs).toHaveLength(2);
      expect(assessment.retryConditionProofsHash).toMatch(/^[a-f0-9]{64}$/u);
      expect(assessment.auditRecordHash).toMatch(/^[a-f0-9]{64}$/u);
      expect(value.database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_retry_authorizations").get())
        .toEqual({ count: 0 });
      expect(value.database.prepare(`
        SELECT json_extract(payload_json, '$.identicalKnownBadProcedureAuthorized') AS authorized,
          json_extract(payload_json, '$.exactProcedureResetCount') AS exact_resets,
          json_extract(payload_json, '$.operatorReportedResetCountMinimum') AS reported_resets
        FROM events WHERE event_type = 'operational_hazard.health_assessed'
      `).get()).toEqual({ authorized: 0, exact_resets: 2, reported_resets: 11 });
    } finally { value.database.close(); }
  });

  test("a failed or expired health assessment cannot authorize an attempt", () => {
    const failed = fixture({ baselineRestored: false });
    try {
      const assessment = failed.assess();
      expect(assessment.result).toBe("fail");
      expectCode(() => failed.service.authorizeSaferAttempt({
        healthAssessmentId: assessment.id,
        attackAttemptId: failed.safer.id,
        actor: { id: "operator:test", type: "operator" },
      }), "hazard_health_gate_failed");
    } finally { failed.database.close(); }

    const expired = fixture();
    try {
      const assessment = expired.assess(1_000);
      expired.advance(1_001);
      expectCode(() => expired.service.authorizeSaferAttempt({
        healthAssessmentId: assessment.id,
        attackAttemptId: expired.safer.id,
        actor: { id: "operator:test", type: "operator" },
      }), "hazard_health_assessment_expired");
    } finally { expired.database.close(); }
  });

  test("fails closed without a reviewed contract or complete exact condition proof", () => {
    const missingContract = fixture({ omitRetryContract: true });
    try {
      expectCode(() => missingContract.assess(), "hazard_retry_contract_required");
    } finally { missingContract.database.close(); }

    const incompleteConditionResults: ReadonlyArray<Readonly<Record<string, boolean>>> = [
      { baseline_response_ok: true },
      {
        baseline_response_ok: true,
        worker_queue_within_bound: true,
        unreviewed_extra_result: true,
      },
    ];
    for (const retryConditionResults of incompleteConditionResults) {
      const incomplete = fixture({ retryConditionResults });
      try {
        expectCode(() => incomplete.assess(), "hazard_retry_condition_proof_incomplete");
      } finally { incomplete.database.close(); }
    }

    const unsatisfied = fixture({
      retryConditionResults: {
        baseline_response_ok: true,
        worker_queue_within_bound: false,
      },
    });
    try {
      const assessment = unsatisfied.assess();
      expect(assessment.result).toBe("fail");
      expect(assessment.retryConditionProofs?.map((proof) => proof.satisfied)).toEqual([true, false]);
      expectCode(() => unsatisfied.service.authorizeSaferAttempt({
        healthAssessmentId: assessment.id,
        attackAttemptId: unsatisfied.safer.id,
        actor: { id: "operator:test", type: "operator" },
      }), "hazard_health_gate_failed");
    } finally { unsatisfied.database.close(); }
  });

  test("rejects the identical known-bad procedure and cross-target reuse", () => {
    const value = fixture();
    try {
      const assessment = value.assess();
      expectCode(
        () => value.service.assertReservationAuthorized(value.safer.id),
        "hazard_retry_authorization_required",
      );
      expectCode(
        () => value.service.assertReservationAuthorized(value.unlinkedSafer.id),
        "hazard_retry_lineage_required",
      );
      expectCode(() => value.service.authorizeSaferAttempt({
        healthAssessmentId: assessment.id,
        attackAttemptId: value.identical.id,
        actor: { id: "operator:test", type: "operator" },
      }), "hazard_retry_identical_known_bad_denied");
      expectCode(() => value.service.authorizeSaferAttempt({
        healthAssessmentId: assessment.id,
        attackAttemptId: value.arbitraryVersion.id,
        actor: { id: "operator:test", type: "operator" },
      }), "hazard_retry_alternative_not_reviewed");
      expectCode(() => value.service.authorizeSaferAttempt({
        healthAssessmentId: assessment.id,
        attackAttemptId: value.arbitraryParameters.id,
        actor: { id: "operator:test", type: "operator" },
      }), "hazard_retry_alternative_not_reviewed");
      expectCode(() => value.service.authorizeSaferAttempt({
        healthAssessmentId: assessment.id,
        attackAttemptId: value.crossTarget.id,
        actor: { id: "operator:test", type: "operator" },
      }), "hazard_retry_lineage_mismatch");
      expect(value.createCrossTargetRecovery).toThrow("Recovery source must use the same mission, run, target asset, and target service");
    } finally { value.database.close(); }
  });

  test("consumes one safer authorization once and remains idempotent after service restart", () => {
    const value = fixture();
    try {
      const assessment = value.assess();
      const authorization = value.service.authorizeSaferAttempt({
        healthAssessmentId: assessment.id,
        attackAttemptId: value.safer.id,
        actor: { id: "operator:test", type: "operator" },
      });
      expect(authorization).toMatchObject({ maxAttempts: 1, automaticRetry: false });
      expect(authorization.authorizationBasis).toBe("explicit_alternative");
      expect(authorization.healthAssessmentHash).toBe(assessment.assessmentHash);
      expect(authorization.retryContractHash).toBe(assessment.retryContractHash);
      expect(authorization.reviewedAlternativeHash).toBe(assessment.reviewedAlternativeHash);
      expect(authorization.retryConditionProofsHash).toBe(assessment.retryConditionProofsHash);
      const action = value.insertRunningAction("action-safer");
      const first = value.service.consumeForAction({
        authorizationId: authorization.id,
        attackAttemptId: value.safer.id,
        action,
        actorId: "worker:test",
      });
      expect(first.duplicate).toBe(false);
      const restarted = new OperationalHazardHealthGateService(value.database, { clock: value.clock });
      expect(restarted.consumeForAction({
        authorizationId: authorization.id,
        attackAttemptId: value.safer.id,
        action,
        actorId: "worker:test",
      }).duplicate).toBe(true);
      const replay = value.insertRunningAction("action-safer-replay");
      expectCode(() => restarted.consumeForAction({
        authorizationId: authorization.id,
        attackAttemptId: value.safer.id,
        action: replay,
        actorId: "worker:test",
      }), "hazard_retry_authorization_replayed");
      expect(value.database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_retry_consumptions").get())
        .toEqual({ count: 1 });
      expect(value.database.prepare("SELECT COUNT(*) AS count FROM events WHERE event_type = 'operational_hazard.safer_attempt_consumed'").get())
        .toEqual({ count: 1 });
    } finally { value.database.close(); }
  });

  test("expires an issued authorization before target contact", () => {
    const value = fixture();
    try {
      const assessment = value.assess(10_000);
      const authorization = value.service.authorizeSaferAttempt({
        healthAssessmentId: assessment.id,
        attackAttemptId: value.safer.id,
        actor: { id: "operator:test", type: "operator" },
        ttlMs: 1_000,
      });
      value.advance(1_001);
      const action = value.insertRunningAction("action-expired");
      expectCode(() => value.service.consumeForAction({
        authorizationId: authorization.id,
        attackAttemptId: value.safer.id,
        action,
        actorId: "worker:test",
      }), "hazard_retry_authorization_expired");
      expect(value.database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_retry_consumptions").get())
        .toEqual({ count: 0 });
    } finally { value.database.close(); }
  });

  test("rejects substituted action arguments before consuming the one-use authorization", () => {
    const value = fixture();
    try {
      const authorization = value.service.authorizeSaferAttempt({
        healthAssessmentId: value.assess().id,
        attackAttemptId: value.safer.id,
        actor: { id: "operator:test", type: "operator" },
      });
      const substituted = value.insertRunningAction(
        "action-substituted",
        "step-safer",
        { payload_shape: "known-bad" },
      );
      expectCode(() => value.service.consumeForAction({
        authorizationId: authorization.id,
        attackAttemptId: value.safer.id,
        action: substituted,
        actorId: "worker:test",
      }), "hazard_retry_action_binding_mismatch");
      expect(value.database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_retry_consumptions").get())
        .toEqual({ count: 0 });
    } finally { value.database.close(); }
  });

  test("keeps reviewed attack-attempt knowledge immutable while allowing exact idempotent replay", () => {
    const value = fixture();
    try {
      const matcher = new OperationalHazardMatcher(value.database, { clock: value.clock });
      const current = matcher.requireAttackAttemptContext(value.safer.id);
      expect(matcher.bindAttackAttempt(current).procedureVersionNodeId).toBe(value.ids.saferProcedureVersion);
      expect(() => matcher.bindAttackAttempt({
        ...current,
        procedureVersionNodeId: value.ids.procedureVersion,
        normalizedParameters: { payload_shape: "known-bad" },
      })).toThrow("Attack-attempt knowledge is immutable");
      expect(() => value.database.prepare(`
        UPDATE attack_attempt_knowledge_contexts
        SET normalized_parameters_json = '{"payload_shape":"known-bad"}'
        WHERE attack_attempt_id = ?
      `).run(value.safer.id)).toThrow("attack attempt knowledge binding is immutable");
    } finally { value.database.close(); }
  });

  test("rejects operator acknowledgements, unverified evidence, and public-model self-reports", () => {
    for (const [name, options] of [
      ["unverified", { evidenceState: "unverified" as const }],
      ["operator", { evidenceType: "operator_supplied" }],
      ["public-model", { evidenceSource: "public_llm_self_report", evidenceProvenance: { method: "provider_turn" } }],
    ] as const) {
      const value = fixture(options);
      try {
        expectCode(() => value.assess(), "hazard_health_verified_local_evidence_required");
      } finally {
        value.database.close();
      }
      expect(name.length).toBeGreaterThan(0);
    }
  });
});

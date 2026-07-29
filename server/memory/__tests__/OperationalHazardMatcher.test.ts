import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import {
  MemoryRepository,
  OperationalHazardMatcher,
  OperationalHazardMatcherError,
  type MemoryLifecycle,
  type MemoryNodeType,
} from "../index";

const NOW = "2026-07-20T12:00:00.000Z";

function opaqueId(label: string): string {
  return `mem_${createHash("sha256").update(label).digest("hex")}`;
}

function database(): SqliteDatabase {
  const value = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(value);
  return value;
}

function seedAttempt(db: SqliteDatabase, suffix: string): string {
  const missionId = `mission-${suffix}`;
  const runId = `run-${suffix}`;
  const planId = `plan-${suffix}`;
  const stepId = `step-${suffix}`;
  const attemptId = `attempt-${suffix}`;
  db.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, engagement_id, created_by, created_at, updated_at
    ) VALUES (?, ?, 'Validate an authorized lab path', 'autonomous', ?, 'operator', ?, ?)
  `).run(missionId, `Operational scenario ${suffix}`, `engagement-${suffix}`, NOW, NOW);
  db.prepare(`
    INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
    VALUES (?, ?, 'autonomous', 'running', ?, ?)
  `).run(runId, missionId, NOW, NOW);
  db.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      content_hash, content_hash_version, created_by, created_at
    ) VALUES (?, ?, 1, 'active', 'Health-gated attack validation', ?, ?, 1, 'planner', ?)
  `).run(planId, runId, "a".repeat(64), "a".repeat(64), NOW);
  db.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      action_class, risk_class, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'validation', 'Validate backend execution',
      'Confirm the authorized path without repeating an unsafe request',
      'ready', 'exploit_validation', 'high', ?, ?)
  `).run(stepId, planId, runId, NOW, NOW);
  db.prepare(`
    INSERT INTO attack_attempts (
      id, mission_id, run_id, plan_id, step_id, objective, technique_name,
      action_class, prerequisites_json, normalized_parameters_json,
      status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'Validate a bounded server-side procedure',
      'Bounded calculator execution validation', 'exploit_validation', '[]', '{}',
      'ready', ?, ?)
  `).run(attemptId, missionId, runId, planId, stepId, NOW, NOW);
  return attemptId;
}

function node(
  repository: MemoryRepository,
  id: string,
  nodeType: MemoryNodeType,
  lifecycleStatus: MemoryLifecycle = "verified",
  confidence = 0.98,
): void {
  repository.createNode({
    id,
    nodeType,
    title: `${nodeType.replaceAll("_", " ")} reusable knowledge`,
    summary: "Generalized operator-reviewed attack knowledge without target-specific identifiers.",
    body: "This reusable knowledge is applicable only when its explicit procedure and environment fingerprints match.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence,
    lifecycleStatus,
    confirmationState: lifecycleStatus === "candidate" ? "pending" : "confirmed",
    provenance: {
      method: "derived",
      explanation: "Promoted from repeated locally evaluated outcomes with private source records retained separately.",
      sources: [{
        sourceType: "evaluation",
        sourceId: `source-${id}`,
        acquiredAt: NOW,
      }],
    },
    authorType: "operator",
    authorId: "operator-test",
    retentionPolicy: { journeys: ["autonomous", "guided"] },
  });
}

function seedKnowledge(
  db: SqliteDatabase,
  options: {
    readonly hazardId?: string;
    readonly hazardLifecycle?: MemoryLifecycle;
    readonly hazardConfidence?: number;
    readonly freshUntil?: string | null;
    readonly reproducibilityCount?: number;
    readonly recoveryCost?: Readonly<Record<string, unknown>>;
  } = {},
): {
  readonly procedure: string;
  readonly procedureVersion: string;
  readonly product: string;
  readonly version: string;
  readonly versionRange: string;
  readonly alternateVersion: string;
  readonly stack: string;
  readonly alternateStack: string;
  readonly prerequisite: string;
  readonly state: string;
  readonly hazard: string;
} {
  const repository = new MemoryRepository(db, { clock: () => new Date(NOW) });
  const ids = {
    procedure: opaqueId("procedure-calculator-post"),
    procedureVersion: opaqueId("procedure-version-bounded-print"),
    product: opaqueId("product-server-calculator"),
    version: opaqueId("version-server-calculator-v1"),
    versionRange: opaqueId("version-range-server-calculator-v1"),
    alternateVersion: opaqueId("version-server-calculator-v2"),
    stack: opaqueId("stack-managed-web-runtime"),
    alternateStack: opaqueId("stack-native-web-runtime"),
    prerequisite: opaqueId("prerequisite-backend-healthy"),
    state: opaqueId("state-backend-wedged"),
    hazard: opaqueId(options.hazardId ?? "hazard-backend-hang"),
  } as const;
  node(repository, ids.procedure, "attack_procedure");
  node(repository, ids.procedureVersion, "procedure_version");
  node(repository, ids.product, "technology_product");
  node(repository, ids.version, "exact_version_fingerprint");
  node(repository, ids.versionRange, "version_range_fingerprint");
  node(repository, ids.alternateVersion, "exact_version_fingerprint");
  node(repository, ids.stack, "framework");
  node(repository, ids.alternateStack, "runtime");
  node(repository, ids.prerequisite, "prerequisite");
  node(repository, ids.state, "target_state_transition");
  node(
    repository,
    ids.hazard,
    "operational_hazard",
    options.hazardLifecycle ?? "verified",
    options.hazardConfidence ?? 0.98,
  );
  const reproducibility = options.reproducibilityCount ?? 11;
  db.prepare(`
    INSERT INTO operational_hazard_profiles (
      node_id, procedure_node_id, procedure_version_node_id,
      product_node_ids_json, version_node_ids_json, stack_node_ids_json,
      prerequisite_node_ids_json, observed_state_node_ids_json,
      ordered_steps_json, normalized_parameters_json,
      load_min, concurrency_min, timing_window_ms,
      observed_symptom, affected_component, state_before, state_after,
      state_transition_node_id, reproducibility_count, attempt_count,
      recovery_action_summary, recovery_cost_json,
      unsafe_retry_conditions_json, safe_retry_gate_json,
      alternative_sequence_json, applicability_constraints_json,
      confidence, observed_at, fresh_until, version, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 5000,
      'The backend stopped returning bounded execution responses',
      'Server-side calculator worker', 'Healthy response path', 'Wedged response path',
      ?, ?, ?, 'Recycle the disposable lab worker and prove health before retry', ?,
      ?, ?, ?, '{}', ?, ?, ?, 1, ?, ?)
  `).run(
    ids.hazard,
    ids.procedure,
    ids.procedureVersion,
    JSON.stringify([ids.product]),
    JSON.stringify([ids.version]),
    JSON.stringify([ids.stack]),
    JSON.stringify([ids.prerequisite]),
    JSON.stringify([ids.state]),
    JSON.stringify(["Confirm the service is healthy", "Use one bounded validation request"]),
    JSON.stringify({ payload_shape: "bounded-print-probe" }),
    ids.state,
    reproducibility,
    reproducibility,
    JSON.stringify(options.recoveryCost ?? {}),
    JSON.stringify(["The health probe is not returning the expected bounded response"]),
    JSON.stringify([
      "Confirm the service health probe returns the expected bounded response",
      "Confirm the disposable worker was recycled after the prior hang",
    ]),
    JSON.stringify([
      "Run a read-only health probe",
      "Recycle the disposable worker when the health probe fails",
      "Issue one bounded validation request only after the health probe succeeds",
    ]),
    options.hazardConfidence ?? 0.98,
    "2026-07-19T12:00:00.000Z",
    options.freshUntil === undefined ? "2026-08-20T12:00:00.000Z" : options.freshUntil,
    NOW,
    NOW,
  );
  return ids;
}

function exactContext(ids: ReturnType<typeof seedKnowledge>) {
  return {
    procedureNodeId: ids.procedure,
    procedureVersionNodeId: ids.procedureVersion,
    productNodeIds: [ids.product],
    versionNodeIds: [ids.version],
    stackNodeIds: [ids.stack],
    prerequisiteNodeIds: [ids.prerequisite],
    observedStateNodeIds: [ids.state],
    normalizedParameters: { payload_shape: "bounded-print-probe" },
    load: 1,
    concurrency: 1,
    timingWindowMs: 2_000,
  } as const;
}

describe("OperationalHazardMatcher", () => {
  test("blocks a blind retry after a repeatedly reproduced exact hang and exposes a health-gated safer sequence", () => {
    const db = database();
    try {
      const attemptId = seedAttempt(db, "repeated-hang");
      const ids = seedKnowledge(db);
      const matcher = new OperationalHazardMatcher(db, { clock: () => new Date(NOW) });
      const bound = matcher.bindAttackAttempt({ attackAttemptId: attemptId, ...exactContext(ids) });
      const assessment = matcher.assessAttackAttempt(attemptId);

      expect(bound.procedureNodeId).toBe(ids.procedure);
      expect(assessment).toEqual({
        decision: "block",
        matchedHazardNodeIds: [ids.hazard],
        blockedProcedureNodeIds: [ids.procedure],
        warning: expect.stringContaining("blind retry"),
        checklist: [
          "Confirm the disposable worker was recycled after the prior hang",
          "Confirm the service health probe returns the expected bounded response",
        ],
        healthGate: [
          "Confirm the disposable worker was recycled after the prior hang",
          "Confirm the service health probe returns the expected bounded response",
        ],
        safeRetryGate: [
          "Confirm the disposable worker was recycled after the prior hang",
          "Confirm the service health probe returns the expected bounded response",
        ],
        unsafeRetryConditions: ["The health probe is not returning the expected bounded response"],
        saferKnownSequence: [
          "Issue one bounded validation request only after the health probe succeeds",
          "Recycle the disposable worker when the health probe fails",
          "Run a read-only health probe",
        ],
      });
    } finally {
      db.close();
    }
  });

  test("reuses a verified hazard across different mission identities only when the generalized stack and procedure still match", () => {
    const db = database();
    try {
      const historicalAttemptId = seedAttempt(db, "historical-source-identity");
      const freshTargetAttemptId = seedAttempt(db, "fresh-unrelated-target-identity");
      const changedStackAttemptId = seedAttempt(db, "fresh-changed-stack-identity");
      db.prepare("UPDATE missions SET name = ?, engagement_id = ? WHERE id = ?")
        .run("Historical disposable system Alpha", "engagement-private-alpha", `mission-historical-source-identity`);
      db.prepare("UPDATE missions SET name = ?, engagement_id = ? WHERE id = ?")
        .run("Fresh authorized system Omega", "engagement-private-omega", `mission-fresh-unrelated-target-identity`);
      const ids = seedKnowledge(db);
      const matcher = new OperationalHazardMatcher(db, { clock: () => new Date(NOW) });

      matcher.bindAttackAttempt({ attackAttemptId: freshTargetAttemptId, ...exactContext(ids) });
      const sameTechnologyAssessment = matcher.assessAttackAttempt(freshTargetAttemptId);
      expect(freshTargetAttemptId).not.toBe(historicalAttemptId);
      expect(sameTechnologyAssessment).toMatchObject({
        decision: "block",
        matchedHazardNodeIds: [ids.hazard],
        blockedProcedureNodeIds: [ids.procedure],
      });

      matcher.bindAttackAttempt({
        attackAttemptId: changedStackAttemptId,
        ...exactContext(ids),
        versionNodeIds: [ids.alternateVersion],
        stackNodeIds: [ids.alternateStack],
      });
      expect(matcher.assessAttackAttempt(changedStackAttemptId)).toMatchObject({
        decision: "allow",
        matchedHazardNodeIds: [],
        blockedProcedureNodeIds: [],
      });

      const reusableProfileText = JSON.stringify(db.prepare(`
        SELECT product_node_ids_json, version_node_ids_json, stack_node_ids_json,
          prerequisite_node_ids_json, observed_state_node_ids_json,
          normalized_parameters_json
        FROM operational_hazard_profiles WHERE node_id = ?
      `).get(ids.hazard));
      expect(reusableProfileText).not.toContain("historical-source-identity");
      expect(reusableProfileText).not.toContain("fresh-unrelated-target-identity");
      expect(reusableProfileText).not.toContain("private-alpha");
      expect(reusableProfileText).not.toContain("private-omega");
    } finally {
      db.close();
    }
  });

  test("does not claim applicability for an explicitly different stack or version", () => {
    const db = database();
    try {
      seedAttempt(db, "different-stack");
      const ids = seedKnowledge(db);
      const matcher = new OperationalHazardMatcher(db, { clock: () => new Date(NOW) });
      const assessment = matcher.assess({
        ...exactContext(ids),
        versionNodeIds: [ids.alternateVersion],
        stackNodeIds: [ids.alternateStack],
      });

      expect(assessment.decision).toBe("allow");
      expect(assessment.matchedHazardNodeIds).toEqual([]);
      expect(assessment.warning).toBeUndefined();
    } finally {
      db.close();
    }
  });

  test("matches a bounded version range only through a verified global version-in-range edge", () => {
    const db = database();
    try {
      seedAttempt(db, "verified-range");
      const ids = seedKnowledge(db);
      db.prepare(`
        UPDATE operational_hazard_profiles SET version_node_ids_json = ? WHERE node_id = ?
      `).run(JSON.stringify([ids.versionRange]), ids.hazard);
      new MemoryRepository(db, { clock: () => new Date(NOW) }).createEdge({
        id: "edge-version-in-range-verified",
        sourceNodeId: ids.version,
        targetNodeId: ids.versionRange,
        edgeType: "version_in_range",
        title: "Observed release is in the reviewed affected range",
        summary: "A local evaluator verified the exact release against the bounded affected range.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.98,
        lifecycleStatus: "verified",
        provenance: {
          method: "derived",
          explanation: "A trusted local version evaluator produced this relationship.",
          sources: [{ sourceType: "evaluation", sourceId: "source-version-range", acquiredAt: NOW }],
        },
        explanation: "The exact observed version satisfied the locally evaluated range boundary.",
        authorType: "operator",
        authorId: "operator-test",
      });
      const assessment = new OperationalHazardMatcher(db, { clock: () => new Date(NOW) })
        .assess(exactContext(ids));
      expect(assessment.decision).toBe("block");
      expect(assessment.matchedHazardNodeIds).toEqual([ids.hazard]);
    } finally {
      db.close();
    }
  });

  test("a missing or unverified version-in-range edge is warning-only and never guessed from version text", () => {
    for (const edgeLifecycle of [undefined, "candidate" as const]) {
      const db = database();
      try {
        seedAttempt(db, `untrusted-range-${edgeLifecycle ?? "missing"}`);
        const ids = seedKnowledge(db);
        db.prepare(`
          UPDATE operational_hazard_profiles SET version_node_ids_json = ? WHERE node_id = ?
        `).run(JSON.stringify([ids.versionRange]), ids.hazard);
        if (edgeLifecycle) {
          new MemoryRepository(db, { clock: () => new Date(NOW) }).createEdge({
            id: "edge-version-in-range-candidate",
            sourceNodeId: ids.version,
            targetNodeId: ids.versionRange,
            edgeType: "version_in_range",
            title: "Unreviewed version relationship",
            summary: "This relationship is still a candidate and cannot gate execution.",
            scope: { kind: "global" },
            sensitivity: "internal",
            confidence: 0.98,
            lifecycleStatus: edgeLifecycle,
            provenance: {
              method: "derived",
              explanation: "The range relationship has not passed operator review.",
              sources: [{ sourceType: "evaluation", sourceId: "source-range-candidate", acquiredAt: NOW }],
            },
            explanation: "Candidate range applicability must not be treated as verified.",
            authorType: "operator",
            authorId: "operator-test",
          });
        }
        const assessment = new OperationalHazardMatcher(db, { clock: () => new Date(NOW) })
          .assess(exactContext(ids));
        expect(assessment.decision).toBe("warn");
        expect(assessment.blockedProcedureNodeIds).toEqual([]);
      } finally {
        db.close();
      }
    }
  });

  test("all supported applicability constraints retain an exact blocking match when satisfied", () => {
    const db = database();
    try {
      seedAttempt(db, "all-applicability-constraints");
      const ids = seedKnowledge(db);
      db.prepare(`
        UPDATE operational_hazard_profiles
        SET version_node_ids_json = ?, applicability_constraints_json = ?
        WHERE node_id = ?
      `).run(
        JSON.stringify([ids.versionRange]),
        JSON.stringify({
          requireExactProcedureVersion: true,
          requireVerifiedVersionRelationship: true,
          requireAllStackNodes: true,
          requireAllPrerequisites: true,
          requireObservedState: true,
        }),
        ids.hazard,
      );
      new MemoryRepository(db, { clock: () => new Date(NOW) }).createEdge({
        id: "edge-all-constraints-version-in-range",
        sourceNodeId: ids.version,
        targetNodeId: ids.versionRange,
        edgeType: "version_in_range",
        title: "Observed release satisfies the reviewed range",
        summary: "The local evaluator verified this exact release against the bounded range.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.98,
        lifecycleStatus: "verified",
        provenance: {
          method: "derived",
          explanation: "A trusted local version evaluator produced this relationship.",
          sources: [{ sourceType: "evaluation", sourceId: "source-all-constraints-range", acquiredAt: NOW }],
        },
        explanation: "The exact observed release is inside the locally verified range.",
        authorType: "operator",
        authorId: "operator-test",
      });

      const assessment = new OperationalHazardMatcher(db, { clock: () => new Date(NOW) })
        .assess(exactContext(ids));

      expect(assessment.decision).toBe("block");
      expect(assessment.matchedHazardNodeIds).toEqual([ids.hazard]);
      expect(assessment.blockedProcedureNodeIds).toEqual([ids.procedure]);
    } finally {
      db.close();
    }
  });

  test("required observed state remains warning-only when the profile lacks that binding", () => {
    const db = database();
    try {
      seedAttempt(db, "missing-required-observed-state");
      const ids = seedKnowledge(db);
      db.prepare(`
        UPDATE operational_hazard_profiles
        SET observed_state_node_ids_json = '[]',
            applicability_constraints_json = '{"requireObservedState":true}'
        WHERE node_id = ?
      `).run(ids.hazard);

      const assessment = new OperationalHazardMatcher(db, { clock: () => new Date(NOW) })
        .assess({ ...exactContext(ids), observedStateNodeIds: [] });

      expect(assessment.decision).toBe("warn");
      expect(assessment.matchedHazardNodeIds).toEqual([ids.hazard]);
      expect(assessment.blockedProcedureNodeIds).toEqual([]);
    } finally {
      db.close();
    }
  });

  test("an unsupported imported applicability constraint cannot be treated as an exact match", () => {
    const db = database();
    try {
      seedAttempt(db, "unsupported-applicability-constraint");
      const ids = seedKnowledge(db);
      db.prepare(`
        UPDATE operational_hazard_profiles
        SET applicability_constraints_json = '{"futureConstraint":true}'
        WHERE node_id = ?
      `).run(ids.hazard);

      const assessment = new OperationalHazardMatcher(db, { clock: () => new Date(NOW) })
        .assess(exactContext(ids));

      expect(assessment.decision).toBe("warn");
      expect(assessment.matchedHazardNodeIds).toEqual([ids.hazard]);
      expect(assessment.blockedProcedureNodeIds).toEqual([]);
    } finally {
      db.close();
    }
  });

  test("stale, candidate, low-confidence, or insufficiently reproduced knowledge can warn but cannot block", () => {
    for (const fixture of [
      { hazardLifecycle: "candidate" as const },
      { freshUntil: "2026-07-19T11:59:59.000Z" },
      { hazardConfidence: 0.6 },
      { reproducibilityCount: 1 },
    ]) {
      const db = database();
      try {
        seedAttempt(db, `nonblocking-${Object.keys(fixture)[0]}`);
        const ids = seedKnowledge(db, fixture);
        const matcher = new OperationalHazardMatcher(db, { clock: () => new Date(NOW) });
        const assessment = matcher.assess(exactContext(ids));
        expect(assessment.decision).toBe("warn");
        expect(assessment.matchedHazardNodeIds).toEqual([ids.hazard]);
        expect(assessment.blockedProcedureNodeIds).toEqual([]);
      } finally {
        db.close();
      }
    }
  });

  test("asserted reset metadata cannot lower the repeated-evidence blocking threshold", () => {
    const assertedReset = database();
    try {
      seedAttempt(assertedReset, "single-asserted-reset");
      const ids = seedKnowledge(assertedReset, {
        reproducibilityCount: 1,
        recoveryCost: {
          resetCount: 1,
          operatorReportedResetCountMinimum: 11,
          requiresDisposableTargetReset: true,
        },
      });
      expect(new OperationalHazardMatcher(assertedReset, { clock: () => new Date(NOW) })
        .assess(exactContext(ids))).toMatchObject({
        decision: "warn",
        blockedProcedureNodeIds: [],
      });
    } finally {
      assertedReset.close();
    }

    const aggregateOnly = database();
    try {
      seedAttempt(aggregateOnly, "single-aggregate-only");
      const ids = seedKnowledge(aggregateOnly, {
        reproducibilityCount: 1,
        recoveryCost: {
          operatorReportedResetCountMinimum: 11,
          requiresDisposableTargetReset: true,
        },
      });
      expect(new OperationalHazardMatcher(aggregateOnly, { clock: () => new Date(NOW) })
        .assess(exactContext(ids)).decision).toBe("warn");
    } finally {
      aggregateOnly.close();
    }
  });

  test("a partial context warns without fabricating exact applicability", () => {
    const db = database();
    try {
      seedAttempt(db, "partial");
      const ids = seedKnowledge(db);
      const matcher = new OperationalHazardMatcher(db, { clock: () => new Date(NOW) });
      const assessment = matcher.assess({
        ...exactContext(ids),
        versionNodeIds: [],
        stackNodeIds: [],
        normalizedParameters: {},
        load: undefined,
        concurrency: undefined,
        timingWindowMs: undefined,
      });
      expect(assessment.decision).toBe("warn");
      expect(assessment.matchedHazardNodeIds).toEqual([ids.hazard]);
      expect(assessment.blockedProcedureNodeIds).toEqual([]);
    } finally {
      db.close();
    }
  });

  test("rejects target addresses and operational record IDs from reusable procedure parameters", () => {
    const db = database();
    try {
      const attemptId = seedAttempt(db, "private-locator");
      const ids = seedKnowledge(db);
      const matcher = new OperationalHazardMatcher(db, { clock: () => new Date(NOW) });
      for (const target of ["10.129.39.191", "target_private-client"] as const) {
        try {
          matcher.bindAttackAttempt({
            attackAttemptId: attemptId,
            ...exactContext(ids),
            normalizedParameters: { target },
          });
          throw new Error("Expected private locator rejection");
        } catch (error) {
          expect(error).toBeInstanceOf(OperationalHazardMatcherError);
          expect((error as OperationalHazardMatcherError).code)
            .toBe("attack_knowledge_context_contains_operational_locator");
        }
      }
      expect(matcher.getAttackAttemptContext(attemptId)).toBeUndefined();
    } finally {
      db.close();
    }
  });
});

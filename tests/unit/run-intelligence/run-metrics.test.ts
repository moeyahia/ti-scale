import { describe, expect, test } from "bun:test";
import {
  AttackAttemptService,
  ReconDigitalTwinService,
  RunMetricsService,
  type RunMetricKey,
} from "../../../server/run-intelligence";
import {
  AGENT_ONE_ID,
  AGENT_TWO_ID,
  MISSION_ID,
  NOW,
  PLAN_ID,
  RUN_ID,
  STEP_ONE_ID,
  STEP_TWO_ID,
  createTestDatabase,
  insertEvent,
  insertEvidence,
  insertFailedToolCall,
} from "./fixtures";

function metricValue(snapshot: ReturnType<RunMetricsService["compute"]>, key: RunMetricKey): number | null {
  const metric = snapshot.metrics.find((candidate) => candidate.key === key);
  if (!metric) throw new Error(`Missing test metric ${key}`);
  return metric.value;
}

function populateCanonicalRun(database: ReturnType<typeof createTestDatabase>): void {
  insertEvidence(database, {
    id: "evidence-metrics-primary",
    acquiredAt: "2026-07-16T12:01:00.000Z",
  });
  for (const [id, stepId, agentId, status, startedAt, endedAt] of [
    ["assignment-metrics-1", STEP_ONE_ID, AGENT_ONE_ID, "completed", "2026-07-16T12:01:00.000Z", "2026-07-16T12:04:00.000Z"],
    ["assignment-metrics-2", STEP_ONE_ID, AGENT_TWO_ID, "active", "2026-07-16T12:03:30.000Z", null],
    ["assignment-metrics-3", STEP_TWO_ID, AGENT_ONE_ID, "failed", "2026-07-16T12:02:00.000Z", "2026-07-16T12:03:00.000Z"],
  ] as const) {
    database.prepare(`
      INSERT INTO assignments (
        id, run_id, step_id, agent_id, status, started_at, ended_at,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, RUN_ID, stepId, agentId, status, startedAt, endedAt, startedAt, endedAt ?? NOW);
  }

  const twin = new ReconDigitalTwinService(database, () => new Date(NOW));
  const asset = twin.createNode({
    missionId: MISSION_ID,
    runId: RUN_ID,
    nodeType: "asset",
    primaryLabel: "Metrics asset",
    normalizedIdentity: "metrics-asset",
    scopeStatus: "allowed",
    lifecycleState: "observed",
    properties: { address: "canonical-reference" },
    provenance: {
      method: "structured_fixture_parser",
      sourceRef: "evidence-metrics-primary",
      sourceAgentId: AGENT_ONE_ID,
      sourceTool: "fixture-parser",
    },
    confidence: 0.9,
    verificationState: "verified",
    sensitivity: "internal",
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    evidence: [{ evidenceId: "evidence-metrics-primary", relationship: "supports" }],
  });
  const service = twin.createNode({
    missionId: MISSION_ID,
    runId: RUN_ID,
    nodeType: "service",
    primaryLabel: "Metrics HTTPS service",
    normalizedIdentity: "metrics-service-https",
    scopeStatus: "allowed",
    lifecycleState: "observed",
    properties: { transport: "tcp" },
    provenance: {
      method: "structured_fixture_parser",
      sourceRef: "evidence-metrics-primary",
      sourceAgentId: AGENT_ONE_ID,
      sourceTool: "fixture-parser",
    },
    confidence: 0.9,
    verificationState: "verified",
    sensitivity: "internal",
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    evidence: [{ evidenceId: "evidence-metrics-primary", relationship: "supports" }],
  });
  twin.createEdge({
    missionId: MISSION_ID,
    sourceNodeId: asset.id,
    targetNodeId: service.id,
    edgeType: "exposes",
    provenance: {
      method: "structured_fixture_parser",
      sourceRef: "evidence-metrics-primary",
      sourceAgentId: AGENT_ONE_ID,
    },
    confidence: 0.9,
    verificationState: "verified",
    sensitivity: "internal",
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    evidence: [{ evidenceId: "evidence-metrics-primary", relationship: "supports" }],
  });
  twin.recordOsiObservation({
    assetNodeId: asset.id,
    layer: 3,
    category: "address",
    value: "canonical-reference",
    derivation: "actively_verified",
    confidence: 0.9,
    evidenceId: "evidence-metrics-primary",
    observedAt: NOW,
  });

  const attempts = new AttackAttemptService(database, () => new Date(NOW));
  let attempt = attempts.create({
    missionId: MISSION_ID,
    runId: RUN_ID,
    planId: PLAN_ID,
    stepId: STEP_TWO_ID,
    targetAssetId: asset.id,
    targetServiceId: service.id,
    objective: "Classify a bounded technique independently from its tool process",
    techniqueName: "Metrics fixture technique",
    actionClass: "exploit_validation",
    assignedAgentId: AGENT_ONE_ID,
  });
  attempt = attempts.transition({ attemptId: attempt.id, expectedVersion: attempt.version, status: "ready" });
  attempt = attempts.transition({ attemptId: attempt.id, expectedVersion: attempt.version, status: "running" });
  insertFailedToolCall(database, attempt.id);

  database.prepare(`
    INSERT INTO observations (
      id, mission_id, run_id, step_id, asset_id, observation_type,
      statement, normalized_value_json, confidence, verification_state,
      source_agent_id, source_tool, first_seen_at, last_seen_at,
      sensitivity, created_at
    ) VALUES ('observation-metrics', ?, ?, ?, ?, 'service',
      'The canonical fixture exposed one service', '{}', 0.9, 'corroborated',
      ?, 'fixture-parser', ?, ?, 'internal', ?)
  `).run(MISSION_ID, RUN_ID, STEP_ONE_ID, asset.id, AGENT_ONE_ID, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO evidence_candidates (
      id, mission_id, run_id, step_id, observation_id, evidence_type,
      label, meaning, promotion_reason, validation_requirements_json,
      state, sensitivity, proposed_by, created_at
    ) VALUES ('candidate-metrics', ?, ?, ?, 'observation-metrics',
      'service_fingerprint', 'Service candidate', 'Potential corroboration',
      'Structured parser output', '[]', 'candidate', 'internal', ?, ?)
  `).run(MISSION_ID, RUN_ID, STEP_ONE_ID, AGENT_ONE_ID, NOW);
  database.prepare(`
    INSERT INTO findings (
      id, mission_id, run_id, title, severity, confidence, affected_scope,
      description, impact, remediation, review_status, created_at, updated_at
    ) VALUES ('finding-metrics', ?, ?, 'Fixture service exposure', 'low', 0.9,
      'metrics-asset', 'Evidence-backed fixture finding', 'Fixture impact',
      'Fixture remediation', 'verified', ?, ?)
  `).run(MISSION_ID, RUN_ID, NOW, NOW);
  database.prepare(`
    INSERT INTO finding_evidence (finding_id, evidence_id, relationship, added_at)
    VALUES ('finding-metrics', 'evidence-metrics-primary', 'supports', ?)
  `).run(NOW);
  database.prepare(`
    INSERT INTO artifacts (
      id, mission_id, run_id, step_id, artifact_type, storage_uri,
      content_hash, byte_size, media_type, sensitivity, metadata_json,
      created_at, journey
    ) VALUES ('artifact-metrics', ?, ?, ?, 'scan', 'artifact://metrics', ?,
      100, 'application/json', 'internal', '{}', ?, 'autonomous')
  `).run(MISSION_ID, RUN_ID, STEP_ONE_ID, "c".repeat(64), NOW);
  database.prepare(`
    INSERT INTO provider_turns (
      id, run_id, provider, model, status, input_tokens, output_tokens,
      estimated_cost, latency_ms, started_at, ended_at
    ) VALUES ('provider-turn-metrics', ?, 'fixture-provider', 'fixture-model',
      'completed', 100, 50, 0.01, 250,
      '2026-07-16T12:00:30.000Z', '2026-07-16T12:00:30.250Z')
  `).run(RUN_ID);
  insertEvent(database, 1, "run.started", "2026-07-16T12:00:00.000Z");
  insertEvent(database, 2, "intelligence.updated", "2026-07-16T12:10:00.000Z");
}

describe("deterministic RunMetricsSnapshot", () => {
  test("recomputes stable metrics and typed drill-downs from canonical records", () => {
    const database = createTestDatabase();
    try {
      populateCanonicalRun(database);
      const firstService = new RunMetricsService(database, () => new Date("2026-07-16T13:00:00.000Z"));
      const secondService = new RunMetricsService(database, () => new Date("2026-07-16T14:00:00.000Z"));
      const first = firstService.compute(RUN_ID);
      const second = secondService.compute(RUN_ID);

      expect(second.recomputationHash).toBe(first.recomputationHash);
      expect(second.id).toBe(first.id);
      expect(second.metrics).toEqual(first.metrics);
      expect(second.sourceCounts).toEqual(first.sourceCounts);
      expect(second.computedAt).not.toBe(first.computedAt);
      expect(first.throughEventSequence).toBe(2);
      expect(new Set(first.metrics.map(({ key }) => key)).size).toBe(first.metrics.length);
      for (const item of first.metrics) {
        expect(item.drillDown.length, item.key).toBeGreaterThan(0);
        for (const reference of item.drillDown) {
          expect(reference.id).toMatch(/^metric_ref_[a-f0-9]{24}$/u);
          expect(reference.runId).toBe(RUN_ID);
          expect(reference.missionId).toBe(MISSION_ID);
          expect(reference.filters.some(({ field, value }) => field === "run_id" && value === RUN_ID)).toBe(true);
        }
      }

      expect(metricValue(first, "steps_total")).toBe(2);
      expect(metricValue(first, "steps_completed")).toBe(1);
      expect(metricValue(first, "plan_completion_ratio")).toBe(0.5);
      expect(metricValue(first, "unique_agents")).toBe(2);
      expect(metricValue(first, "peak_concurrent_agents")).toBe(2);
      expect(metricValue(first, "agent_handoffs")).toBe(1);
      expect(metricValue(first, "attack_attempts_started")).toBe(1);
      expect(metricValue(first, "attack_attempts_failed")).toBe(0);
      expect(metricValue(first, "tool_calls_failed")).toBe(1);
      expect(metricValue(first, "assets_discovered")).toBe(1);
      expect(metricValue(first, "services_discovered")).toBe(1);
      expect(metricValue(first, "topology_edges")).toBe(1);
      expect(metricValue(first, "osi_observations")).toBe(1);
      expect(metricValue(first, "verified_evidence")).toBe(1);
      expect(metricValue(first, "finding_evidence_coverage_ratio")).toBe(1);
      expect(metricValue(first, "provider_tokens")).toBe(150);
      expect(metricValue(first, "estimated_provider_cost")).toBe(0.01);
      expect(metricValue(first, "time_to_first_evidence_ms")).toBe(60_000);

      const stored = firstService.recomputeAndStore(RUN_ID);
      const replayed = secondService.recomputeAndStore(RUN_ID);
      expect(replayed).toEqual(stored);
      expect(replayed.computedAt).toBe("2026-07-16T13:00:00.000Z");
      expect(database.prepare("SELECT COUNT(*) AS count FROM run_metrics_snapshots WHERE run_id = ?")
        .get(RUN_ID)).toEqual({ count: 1 });
    } finally {
      database.close();
    }
  });

  test("detects canonical drift at one event sequence and creates a new snapshot only after an event", () => {
    const database = createTestDatabase();
    try {
      insertEvent(database, 1, "run.started", NOW);
      const service = new RunMetricsService(database, () => new Date("2026-07-16T13:00:00.000Z"));
      const first = service.recomputeAndStore(RUN_ID);
      insertEvidence(database, { id: "evidence-after-snapshot" });
      expect(() => service.recomputeAndStore(RUN_ID)).toThrow("without advancing the event sequence");

      insertEvent(database, 2, "evidence.recorded", "2026-07-16T12:01:00.000Z");
      const second = service.recomputeAndStore(RUN_ID);
      expect(second.throughEventSequence).toBe(2);
      expect(second.recomputationHash).not.toBe(first.recomputationHash);
      expect(metricValue(second, "verified_evidence")).toBe(1);
      expect(database.prepare("SELECT COUNT(*) AS count FROM run_metrics_snapshots WHERE run_id = ?")
        .get(RUN_ID)).toEqual({ count: 2 });
    } finally {
      database.close();
    }
  });

  test("represents unavailable provider telemetry as partial or not observed rather than inventing zero", () => {
    const database = createTestDatabase();
    try {
      database.prepare(`
        INSERT INTO provider_turns (
          id, run_id, provider, status, input_tokens, output_tokens,
          estimated_cost, latency_ms, started_at, ended_at
        ) VALUES
          ('turn-known', ?, 'fixture', 'completed', 10, 5, 0.1, 100, ?, ?),
          ('turn-unknown', ?, 'fixture', 'failed', NULL, NULL, NULL, NULL, ?, ?)
      `).run(RUN_ID, NOW, NOW, RUN_ID, NOW, NOW);
      insertEvent(database, 1, "run.started", NOW);
      const snapshot = new RunMetricsService(database).compute(RUN_ID);
      const tokens = snapshot.metrics.find(({ key }) => key === "provider_tokens")!;
      const cost = snapshot.metrics.find(({ key }) => key === "estimated_provider_cost")!;
      const latency = snapshot.metrics.find(({ key }) => key === "average_provider_latency_ms")!;
      expect(tokens).toMatchObject({ value: 15, measurement: "partial" });
      expect(cost).toMatchObject({ value: 0.1, measurement: "partial" });
      expect(latency).toMatchObject({ value: 100, measurement: "partial" });
    } finally {
      database.close();
    }
  });
});

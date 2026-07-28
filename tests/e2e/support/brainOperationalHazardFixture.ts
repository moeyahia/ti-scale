import { createDatabaseConnection } from "../../../server/db";
import { createHash } from "node:crypto";
import { MemoryRepository } from "../../../server/memory/MemoryRepository";
import { OperationalHazardProfileRepository } from "../../../server/memory/OperationalHazardProfileRepository";
import type { MemoryNodeType } from "../../../server/memory/types";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_TIME = "2099-07-16T12:00:00.000Z";

export interface BrainOperationalHazardFixture {
  readonly namespace: string;
  readonly missionId: string;
  readonly runId: string;
  readonly priorRunId: string;
  readonly nodeId: string;
  readonly procedureNodeId: string;
  readonly hazardTitle: string;
  readonly procedureTitle: string;
  readonly privateSourcePath: string;
  readonly privateSourceHash: string;
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Operational-hazard E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

export function createBrainOperationalHazardFixture(instanceId: string): BrainOperationalHazardFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  const id = (kind: string) => `mem_${createHash("sha256")
    .update(`brain-operational-hazard:${namespace}:${kind}`, "utf8")
    .digest("hex")}`;
  const nodeId = id("operational");
  const procedureNodeId = id("procedure");
  const missionId = `mission-brain-hazard-${namespace}`;
  const runId = `run-brain-hazard-${namespace}`;
  const priorRunId = `run-brain-hazard-prior-${namespace}`;
  const hazardTitle = `Bounded execution hang guardrail ${namespace}`;
  const procedureTitle = `Health-gated bounded validation ${namespace}`;
  const definitions: ReadonlyArray<readonly [string, MemoryNodeType, string]> = [
    [nodeId, "operational_hazard", hazardTitle],
    [procedureNodeId, "attack_procedure", procedureTitle],
    [id("procedure-version"), "procedure_version", `Represented validation revision ${namespace}`],
    [id("product"), "technology_product", `Managed execution worker ${namespace}`],
    [id("version"), "exact_version_fingerprint", `Managed execution release one ${namespace}`],
    [id("stack"), "framework", `Managed application runtime ${namespace}`],
    [id("prerequisite"), "prerequisite", `Execution health confirmed ${namespace}`],
    [id("state"), "target_state_transition", `Execution worker unresponsive ${namespace}`],
    [id("health"), "health_check", `Minimal execution health probe ${namespace}`],
    [id("recovery"), "recovery_pattern", `Recycle disposable execution worker ${namespace}`],
    [id("alternative"), "attack_procedure", `Lower-risk diagnostic procedure ${namespace}`],
  ];
  try {
    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, status, authorization_status, engagement_id,
        scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
        created_by, version, created_at, updated_at, control_plane
      ) VALUES (?, ?, ?, 'guided', 'active', 'verified', ?, ?, '[]', '{}', '{}',
        'e2e-local-operator', 1, ?, ?, 'ti_scale')
    `).run(
      missionId,
      `Operational hazard review ${namespace}`,
      "Review aggregate recovery burden without assigning it to a procedure.",
      `engagement-brain-hazard-${namespace}`,
      JSON.stringify({ environment: "local_test_fixture", target: `${namespace}.example.test` }),
      FIXTURE_TIME,
      FIXTURE_TIME,
    );
    database.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, progress, status_reason,
        next_action_summary, created_at, updated_at, version, control_plane
      ) VALUES (?, ?, 'guided', 'waiting_guided_decision', 0.5,
        'The operator is reviewing recovery burden.',
        'Preserve the aggregate lower bound without procedure attribution', ?, ?, 1, 'ti_scale')
    `).run(runId, missionId, FIXTURE_TIME, FIXTURE_TIME);
    database.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, progress, status_reason,
        next_action_summary, created_at, updated_at, version, control_plane
      ) VALUES (?, ?, 'guided', 'completed', 1,
        'A prior bounded recovery review completed.',
        'Retain the reviewed recovery record', ?, ?, 1, 'ti_scale')
    `).run(priorRunId, missionId, "2099-07-15T12:00:00.000Z", "2099-07-15T12:00:00.000Z");
    const memory = new MemoryRepository(database, { clock: () => new Date(FIXTURE_TIME) });
    for (const [nodeIdValue, nodeType, title] of definitions) {
      memory.createNode({
        id: nodeIdValue,
        nodeType,
        title,
        summary: `Generalized operator-reviewed knowledge for ${title.toLowerCase()}.`,
        body: "This reusable record contains no target locator, secret, or raw artifact content.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.97,
        lifecycleStatus: "verified",
        confirmationState: "confirmed",
        provenance: {
          method: "derived",
          explanation: "A trusted local review generalized private evidence before retaining this reusable guardrail.",
          sources: [{ sourceType: "private_receipt", sourceId: `source-${nodeIdValue}`, acquiredAt: FIXTURE_TIME }],
        },
        authorType: "operator",
        authorId: "e2e-local-operator",
      });
    }
    new OperationalHazardProfileRepository(database, { clock: () => new Date(FIXTURE_TIME) }).create({
      hazardNodeId: nodeId,
      procedureNodeId,
      procedureVersionNodeId: id("procedure-version"),
      productNodeIds: [id("product")],
      versionNodeIds: [id("version")],
      stackNodeIds: [id("stack")],
      prerequisiteNodeIds: [id("prerequisite")],
      observedStateNodeIds: [id("health"), id("state")],
      orderedSteps: [
        "Confirm the minimal execution health probe returns",
        "Run one bounded represented request",
        "Checkpoint the result before any continuation",
      ],
      normalizedParameters: { automaticRetries: 0, maximumStageCount: 1, healthProbeRequired: true },
      loadMinimum: 1,
      concurrencyMinimum: 1,
      timingWindowMs: 5_000,
      observedSymptom: "The base service responded while its execution worker stopped returning bounded results",
      affectedComponent: "Managed server-side execution worker",
      stateBefore: "The minimal execution health probe returned the expected scalar result",
      stateAfter: "Bounded execution requests timed out and the worker required recovery",
      stateTransitionNodeId: id("state"),
      reproducibilityCount: 2,
      attemptCount: 3,
      recoveryPatternNodeId: id("recovery"),
      recoveryActionSummary: "Recycle the disposable worker and restore a known-good baseline before selecting a safer represented route",
      recoveryCost: {
        resetCount: 2,
        operatorReportedResetCountMinimum: 11,
        serviceRecycleCount: 2,
        requiresDisposableTargetReset: true,
      },
      unsafeRetryConditions: ["The health probe does not return the expected bounded result"],
      safeRetryGate: ["A fresh minimal execution health probe returns the expected scalar result"],
      alternativeSequence: [
        "Restore a clean execution worker",
        "Use the lower-risk diagnostic procedure and recorded parameter exclusions",
        "Checkpoint health before any next represented stage",
      ],
      alternativeProcedureNodeId: id("alternative"),
      applicabilityConstraints: {
        requireExactProcedureVersion: true,
        requireAllStackNodes: true,
        requireAllPrerequisites: true,
        requireObservedState: true,
      },
      confidence: 0.96,
      observedAt: FIXTURE_TIME,
      freshUntil: "2100-07-16T12:00:00.000Z",
    });
    database.prepare(`
      INSERT INTO memory_context_packs (
        id, mission_id, run_id, journey, purpose, query_redacted,
        scope_policy_json, context_budget, retrieval_metrics_json, created_by, created_at
      ) VALUES (?, ?, ?, 'guided', 'Recovery burden review',
        'Exact operational-hazard recovery review', '{}', 1200, '{}',
        'local-operational-hazard-evaluator', ?)
    `).run(`pack-brain-hazard-${namespace}`, missionId, runId, FIXTURE_TIME);
    database.prepare(`
      INSERT INTO memory_context_items (
        context_pack_id, node_id, rank, retrieval_score, used,
        relevance_reason, influence_summary
      ) VALUES (?, ?, 0, 1, 1,
        'Exact reviewed operational hazard',
        'Kept aggregate reset history separate from exact procedure evidence')
    `).run(`pack-brain-hazard-${namespace}`, nodeId);
    database.prepare(`
      INSERT INTO memory_context_packs (
        id, mission_id, run_id, journey, purpose, query_redacted,
        scope_policy_json, context_budget, retrieval_metrics_json, created_by, created_at
      ) VALUES (?, ?, ?, 'guided', 'Prior recovery comparison',
        'Prior exact operational-hazard comparison', '{}', 1200, '{}',
        'local-operational-hazard-evaluator', ?)
    `).run(`pack-brain-hazard-prior-${namespace}`, missionId, priorRunId, "2099-07-15T12:00:00.000Z");
    database.prepare(`
      INSERT INTO memory_context_items (
        context_pack_id, node_id, rank, retrieval_score, used,
        relevance_reason, influence_summary
      ) VALUES (?, ?, 0, 0.9, 1,
        'Prior reviewed operational hazard',
        'Compared prior recovery burden without carrying target identity')
    `).run(`pack-brain-hazard-prior-${namespace}`, nodeId);
    const privateSourcePath = `/root/engagements/private-${namespace}/raw-output.json`;
    const privateSourceHash = "e".repeat(64);
    database.prepare(`
      UPDATE memory_sources SET source_id = ?, source_hash = ? WHERE node_id = ?
    `).run(privateSourcePath, privateSourceHash, nodeId);
    return {
      namespace,
      missionId,
      runId,
      priorRunId,
      nodeId,
      procedureNodeId,
      hazardTitle,
      procedureTitle,
      privateSourcePath,
      privateSourceHash,
    };
  } finally {
    database.close();
  }
}

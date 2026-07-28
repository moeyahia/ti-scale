import { createHash } from "node:crypto";
import { acquireTestRunMutationAuthority } from "../../../server/control-plane/TestRunMutationAuthority";
import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { fingerprintAction } from "../../../server/supervisor";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const BASE_TIME = Date.parse("2099-07-16T23:59:59.000Z");
const OPERATOR = "e2e-local-operator";
const GUIDED_MODEL_CONFIGURATION_ID = "modelcfg_e2e_local_guided_reconscout";

export interface DecisionsIntelligenceFixture {
  readonly namespace: string;
  readonly searchToken: string;
  readonly absentToken: string;
  readonly intelligenceMissionId: string;
  readonly intelligenceRunId: string;
  readonly intelligenceMissionTitle: string;
  readonly primaryEvidenceId: string;
  readonly primaryEvidenceSummary: string;
  readonly operationalLogEvidenceId: string;
  readonly operationalLogEvidenceSummary: string;
  readonly primaryFindingId: string;
  readonly primaryFindingTitle: string;
  readonly primaryArtifactId: string;
  readonly primaryArtifactType: string;
  readonly relationlessMissionId: string;
  readonly relationlessMissionTitle: string;
  readonly relationlessEvidenceId: string;
  readonly relationlessEvidenceSummary: string;
  readonly missingRunEvidenceId: string;
  readonly missingRunEvidenceSummary: string;
  readonly crossMissionRunEvidenceId: string;
  readonly crossMissionRunEvidenceSummary: string;
  readonly archivedMissionId: string;
  readonly archivedMissionTitle: string;
  readonly archivedRunId: string;
  readonly archivedEvidenceId: string;
  readonly archivedEvidenceSummary: string;
  readonly deletedArtifactEvidenceId: string;
  readonly deletedArtifactEvidenceSummary: string;
  readonly deletedArtifactId: string;
  readonly quarantinedArtifactId: string;
  readonly quarantinedArtifactType: string;
  readonly relationlessFindingId: string;
  readonly relationlessFindingTitle: string;
  readonly relationlessArtifactId: string;
  readonly relationlessArtifactType: string;
  readonly toolMissionId: string;
  readonly toolRunId: string;
  readonly toolStepId: string;
  readonly toolDecisionId: string;
  readonly guidedModelConfigurationId: string;
  readonly manualMissionId: string;
  readonly manualRunId: string;
  readonly manualStepId: string;
  readonly manualDecisionId: string;
  readonly autonomousTerminalMissionId: string;
  readonly autonomousTerminalRunId: string;
  readonly autonomousActiveMissionId: string;
  readonly autonomousActiveRunId: string;
  readonly terminalApprovalId: string;
  readonly activeApprovalId: string;
  readonly systemApprovalId: string;
  readonly terminalContractId: string;
  readonly terminalExceptionId: string;
  readonly activeExceptionId: string;
  readonly evidenceCount: number;
  readonly findingCount: number;
  readonly artifactCount: number;
  readonly decisionInboxCount: number;
}

export interface DecisionsIntelligenceFixtureSnapshot {
  readonly evidenceCount: number;
  readonly findingCount: number;
  readonly artifactCount: number;
  readonly decisionInboxCount: number;
  readonly toolDecisionStatus: string;
  readonly manualDecisionStatus: string;
  readonly terminalApprovalStatus: string;
  readonly activeApprovalStatus: string;
  readonly systemApprovalStatus: string;
  readonly fixtureAuditCount: number;
  readonly primaryFindingReview: FindingReviewFixtureSnapshot;
  readonly relationlessFindingReview: FindingReviewFixtureSnapshot;
}

export interface FindingReviewFixtureSnapshot {
  readonly status: string;
  readonly version: number;
  readonly operatorOverride: boolean;
  readonly audits: ReadonlyArray<{
    readonly action: string;
    readonly reason: string | null;
    readonly details: Record<string, unknown>;
  }>;
}

function database() {
  if (!E2E_DATABASE_PATH) throw new Error("Decisions/intelligence E2E requires the isolated V2 database path");
  return createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function at(offsetSeconds: number): string {
  return new Date(BASE_TIME - offsetSeconds * 1_000).toISOString();
}

function mission(
  connection: ReturnType<typeof createDatabaseConnection>,
  input: {
    readonly id: string;
    readonly name: string;
    readonly objective: string;
    readonly journey: "autonomous" | "guided";
    readonly status?: "active" | "failed" | "archived";
    readonly engagementId: string;
    readonly createdAt: string;
  },
): void {
  connection.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
      created_by, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'verified', ?, '{}',
      '["Retain one attributable evidence-backed result"]', '{}', '{}', ?, ?, ?)
  `).run(
    input.id,
    input.name,
    input.objective,
    input.journey,
    input.status ?? "active",
    input.engagementId,
    OPERATOR,
    input.createdAt,
    input.createdAt,
  );
}

function run(
  connection: ReturnType<typeof createDatabaseConnection>,
  input: {
    readonly id: string;
    readonly missionId: string;
    readonly journey: "autonomous" | "guided";
    readonly status: "waiting_guided_decision" | "running" | "completed" | "failed";
    readonly contractId?: string;
    readonly currentPlanId?: string;
    readonly currentStepId?: string;
    readonly createdAt: string;
  },
): void {
  const terminal = input.status === "failed" || input.status === "completed";
  connection.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, current_plan_id, current_step_id,
      progress, status_reason, next_action_summary, started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    input.id,
    input.missionId,
    input.journey,
    input.status,
    input.contractId ?? null,
    input.currentPlanId ?? null,
    input.currentStepId ?? null,
    input.status === "completed" ? 1 : terminal ? 0.55 : 0.3,
    input.status === "completed"
      ? "The authorized fixture completed and retained its immutable intelligence."
      : terminal
      ? "The authorized fixture stopped safely and retained every canonical record."
      : input.status === "waiting_guided_decision"
        ? "The exact represented Guided step is waiting for a deliberate operator choice."
        : "The bounded Autonomous fixture is active.",
    input.status === "completed"
      ? "Review the retained intelligence"
      : terminal
        ? "Review the immutable exception"
        : "Review the current bounded state",
    input.createdAt,
    terminal ? input.createdAt : null,
    input.createdAt,
    input.createdAt,
  );
  connection.prepare("INSERT INTO run_event_sequences (run_id, last_sequence) VALUES (?, 0)")
    .run(input.id);
}

function guidedPlan(
  connection: ReturnType<typeof createDatabaseConnection>,
  input: {
    readonly missionId: string;
    readonly runId: string;
    readonly planId: string;
    readonly stepId: string;
    readonly decisionId: string;
    readonly target: string;
    readonly kind: "tool" | "manual";
    readonly createdAt: string;
  },
): void {
  const agentId = `agent-${input.decisionId}`;
  const assignmentId = `assignment-${input.decisionId}`;
  const represented = {
    action: {
      actionType: input.kind === "manual" ? "manual_dns_review" : "bounded_dns_context_review",
      actionClass: "dns_domain_certificate_discovery",
      target: input.target,
      arguments: { target: input.target, readOnly: true, authorizationToken: "fixture-secret-must-redact" },
      intentSummary: "Inspect only the exact authorized fixture target.",
      kind: input.kind,
      idempotent: true,
      destructive: false,
    },
    explanation: "Collect one attributable read-only observation.",
    rationale: "The represented step reduces uncertainty without changing target state.",
    reversibility: "Read only",
    dependencies: [],
  };
  const representedJson = JSON.stringify(represented);
  const representedIntent = {
    missionId: input.missionId,
    runId: input.runId,
    stepId: input.stepId,
    assignmentId,
    planVersion: 1,
    ...represented.action,
  };
  const actionFingerprint = fingerprintAction(representedIntent).hash;
  connection.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES (?, ?, ?, 'url', 'allowed', ?, ?)
  `).run(
    `target-${input.decisionId}`,
    input.missionId,
    input.target,
    new URL(input.target).toString(),
    input.createdAt,
  );
  connection.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES (?, 'recon', ?, 'available', 'e2e-fixture', ?, ?)
  `).run(
    agentId,
    input.kind === "manual" ? "Fixture manual review specialist" : "Fixture reviewed local specialist",
    input.createdAt,
    input.createdAt,
  );
  connection.prepare(`
    INSERT OR IGNORE INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES (
      'ReconScout',
      'Reconnaissance and asset intelligence',
      'ReconScout',
      'available',
      'e2e-model-binding',
      ?,
      ?
    )
  `).run(input.createdAt, input.createdAt);
  connection.prepare(`
    INSERT OR IGNORE INTO model_configurations (
      id, provider_id, model_id, returned_model_id, reasoning_effort,
      context_policy_json, capabilities_json, context_limit,
      cost_class, latency_class, disclosure_class, enforcement_mode,
      auth_state, health_state, catalog_source, catalog_retrieved_at,
      configuration_source, prompt_template_hash,
      created_at, updated_at, version
    ) VALUES (
      ?,
      'provider:local-deterministic-safe-recon',
      'policy:local-safe-recon-v2',
      'policy:local-safe-recon-v2',
      NULL,
      '{}',
      ?,
      NULL,
      'low',
      'fast',
      'local_only',
      'enforced',
      'healthy',
      'healthy',
      'isolated-e2e-runtime-binding',
      ?,
      'recommended',
      NULL,
      ?,
      ?,
      1
    )
  `).run(
    GUIDED_MODEL_CONFIGURATION_ID,
    JSON.stringify({
      displayName: "Local deterministic Guided planner",
      toolCalling: false,
      structuredOutput: true,
      compatibleActionClassIds: ["dns_domain_certificate_discovery"],
      compatibleAgentIds: ["ReconScout"],
    }),
    input.createdAt,
    input.createdAt,
    input.createdAt,
  );
  connection.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Bounded Guided fixture plan',
      'Exercise the canonical exact-step projection without executing target work.', ?, ?, ?, ?)
  `).run(input.planId, input.runId, digest(input.planId), OPERATOR, input.createdAt, input.createdAt);
  connection.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'reconnaissance', ?,
      'Retain one attributable bounded observation.', 'waiting_guided_decision',
      '["The represented observation is attributable"]', '[]',
      'dns_domain_certificate_discovery', 'low', ?, ?, ?)
  `).run(
    input.stepId,
    input.planId,
    input.runId,
    input.kind === "manual" ? "Review a retained response manually" : "Inspect the exact approved endpoint",
    agentId,
    input.createdAt,
    input.createdAt,
  );
  connection.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'queued', ?, ?)
  `).run(
    assignmentId,
    input.runId,
    input.stepId,
    agentId,
    input.createdAt,
    input.createdAt,
  );
  connection.prepare(`
    INSERT INTO model_assignment_preferences (
      id, scope_type, scope_id, agent_id, mission_id, run_id, step_id,
      primary_configuration_id, fallback_configuration_id,
      version, active, is_current, supersedes_preference_id,
      resolution_reason, created_by, created_at
    ) VALUES (
      ?, 'step', ?, 'ReconScout', ?, ?, ?, ?, NULL,
      1, 1, 1, NULL, ?, ?, ?
    )
  `).run(
    `model-preference-${input.decisionId}`,
    input.stepId,
    input.missionId,
    input.runId,
    input.stepId,
    GUIDED_MODEL_CONFIGURATION_ID,
    "Isolated E2E exact-step specialist configuration",
    OPERATOR,
    input.createdAt,
  );
  connection.prepare(`
    INSERT INTO agent_model_assignments (
      id, agent_id, mission_id, run_id, step_id,
      primary_configuration_id, fallback_configuration_id,
      inheritance_level, pinned, resolution_reason, resolved_at, created_at
    ) VALUES (
      ?, 'ReconScout', ?, ?, ?, ?, NULL,
      'step', 1, ?, ?, ?
    )
  `).run(
    `model-assignment-${input.decisionId}`,
    input.missionId,
    input.runId,
    input.stepId,
    GUIDED_MODEL_CONFIGURATION_ID,
    "Pinned from the isolated exact-step model preference",
    input.createdAt,
    input.createdAt,
  );
  connection.prepare(`
    INSERT INTO mission_constraints (
      id, mission_id, constraint_type, value_json, source, created_at
    ) VALUES (?, ?, 'represented_action', ?, ?, ?)
  `).run(`constraint-${input.decisionId}`, input.missionId, representedJson, input.stepId, input.createdAt);
  connection.prepare(`
    INSERT INTO guided_decisions (
      id, mission_id, run_id, step_id, requested_action_fingerprint,
      requested_parameters_json, rationale, risk_class, reversibility,
      status, expires_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'low', 'Read only', 'pending',
      '2100-01-01T00:00:00.000Z', ?)
  `).run(
    input.decisionId,
    input.missionId,
    input.runId,
    input.stepId,
    actionFingerprint,
    JSON.stringify(representedIntent),
    input.kind === "manual"
      ? "Review the exact retained response manually before interpretation."
      : "Inspect the exact approved endpoint with the bounded read-only specialist.",
    input.createdAt,
  );
}

function contract(
  connection: ReturnType<typeof createDatabaseConnection>,
  input: {
    readonly id: string;
    readonly missionId: string;
    readonly version: number;
    readonly state: "confirmed" | "draft" | "superseded";
    readonly createdAt: string;
  },
): void {
  const authorization = JSON.stringify({
    allowedTargets: ["127.0.0.1"],
    prohibitedTargets: [],
    authorizationConfirmed: true,
    dataHandling: "Keep fixture evidence local",
  });
  const actionPolicy = JSON.stringify({
    allowedActionClasses: ["passive_intelligence_osint"],
    prohibitedActionClasses: [],
    destructivePolicy: "prohibited",
    boundedDestructiveTargets: [],
    evidenceRequirements: ["host_asset_discovery_proof"],
    notificationPolicy: "in_app_only",
    reportingFormat: "ti_scale_json",
    dataHandlingPolicy: "local_private",
    retentionPolicy: "operator_managed",
    providerPolicy: "automatic_enforcing_only",
    toolPolicy: "contract_allowlist",
    specialistAgentIds: [],
    contextNodeIds: [],
  });
  const budgets = JSON.stringify({
    timeBudgetMinutes: 30,
    retryBudget: 1,
    replanBudget: 1,
    concurrencyLimit: 1,
    evidenceBytes: 8 * 1024 * 1024,
    artifactBytes: 16 * 1024 * 1024,
  });
  const safeStops = JSON.stringify({ conditions: ["The target leaves the exact signed scope"] });
  connection.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,
      '["evidence_bundle"]', '["verified_lessons"]', ?, ?, ?)
  `).run(
    input.id,
    input.missionId,
    input.version,
    input.state,
    digest(input.id),
    authorization,
    actionPolicy,
    budgets,
    safeStops,
    input.state === "confirmed" ? OPERATOR : null,
    input.state === "confirmed" ? input.createdAt : null,
    input.createdAt,
  );
}

export function createDecisionsIntelligenceFixture(instanceId: string): DecisionsIntelligenceFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const id = (prefix: string): string => `${prefix}-${namespace}`;
  const searchToken = `decisionintelligence${digest(namespace).slice(0, 12)}`;
  const absentToken = `noresult${digest(`absent-${namespace}`).slice(0, 12)}`;
  const engagementId = id("engagement-decisions-intelligence-e2e");
  const toolMissionId = id("mission-guided-tool-decision-e2e");
  const toolRunId = id("run-guided-tool-decision-e2e");
  const toolPlanId = id("plan-guided-tool-decision-e2e");
  const toolStepId = id("step-guided-tool-decision-e2e");
  const toolDecisionId = id("decision-guided-tool-e2e");
  const manualMissionId = id("mission-guided-manual-decision-e2e");
  const manualRunId = id("run-guided-manual-decision-e2e");
  const manualPlanId = id("plan-guided-manual-decision-e2e");
  const manualStepId = id("step-guided-manual-decision-e2e");
  const manualDecisionId = id("decision-guided-manual-e2e");
  const autonomousTerminalMissionId = id("mission-autonomous-terminal-decision-e2e");
  const autonomousTerminalRunId = id("run-autonomous-terminal-decision-e2e");
  const autonomousActiveMissionId = id("mission-autonomous-active-decision-e2e");
  const autonomousActiveRunId = id("run-autonomous-active-decision-e2e");
  const terminalContractId = id("contract-autonomous-terminal-e2e");
  const activeContractId = id("contract-autonomous-active-e2e");
  const terminalApprovalId = id("approval-terminal-e2e");
  const activeApprovalId = id("approval-active-e2e");
  const systemApprovalId = id("approval-system-e2e");
  const terminalExceptionId = id("exception-terminal-e2e");
  const activeExceptionId = id("exception-active-e2e");
  const intelligenceMissionId = id("mission-intelligence-lists-e2e");
  const intelligenceRunId = id("run-intelligence-lists-e2e");
  const intelligenceMissionTitle = `${searchToken} canonical intelligence fixture`;
  const primaryEvidenceId = id("evidence-primary-intelligence-e2e");
  const primaryEvidenceSummary = `${searchToken} verified HTTPS service fingerprint`;
  const operationalLogEvidenceId = id("evidence-operational-log-intelligence-e2e");
  const operationalLogEvidenceSummary = "observed output (observe-only)";
  const primaryFindingId = id("finding-primary-intelligence-e2e");
  const primaryFindingTitle = `${searchToken} evidence-backed transport finding`;
  const primaryArtifactId = id("artifact-primary-intelligence-e2e");
  const primaryArtifactType = `network_map_${searchToken}`;
  const relationlessMissionId = id("mission-intelligence-relations-e2e");
  const relationlessMissionTitle = `${searchToken} imported intelligence without a run`;
  const relationlessEvidenceId = id("evidence-missing-relations-e2e");
  const relationlessEvidenceSummary = `${searchToken} evidence with unavailable historical relations`;
  const missingRunEvidenceId = relationlessEvidenceId;
  const missingRunEvidenceSummary = relationlessEvidenceSummary;
  const crossMissionRunEvidenceId = id("evidence-cross-mission-run-e2e");
  const crossMissionRunEvidenceSummary = `${searchToken} evidence with a cross-mission historical run reference`;
  const archivedMissionId = id("mission-archived-intelligence-e2e");
  const archivedMissionTitle = `${searchToken} archived intelligence mission`;
  const archivedRunId = id("run-archived-intelligence-e2e");
  const archivedEvidenceId = id("evidence-archived-run-e2e");
  const archivedEvidenceSummary = `${searchToken} evidence retained after mission archival`;
  const deletedArtifactEvidenceId = id("evidence-deleted-artifact-e2e");
  const deletedArtifactEvidenceSummary = `${searchToken} evidence retaining a deleted artifact reference`;
  const deletedArtifactId = id("artifact-deleted-e2e");
  const quarantinedArtifactId = id("artifact-quarantined-e2e");
  const quarantinedArtifactType = `quarantined_capture_${searchToken}`;
  const relationlessFindingId = id("finding-missing-relations-e2e");
  const relationlessFindingTitle = `${searchToken} finding without run or evidence relations`;
  const relationlessArtifactId = id("artifact-missing-relations-e2e");
  const relationlessArtifactType = `imported_metadata_${searchToken}`;
  const evidenceCount = 27;
  const findingCount = 27;
  const artifactCount = 27;
  const fillerContracts = 48;
  const connection = database();

  try {
    inImmediateTransaction(connection, () => {
      mission(connection, {
        id: toolMissionId,
        name: `${searchToken} Guided exact tool decision`,
        objective: "Represent one bounded specialist action for deliberate review.",
        journey: "guided",
        engagementId,
        createdAt: at(0),
      });
      run(connection, {
        id: toolRunId,
        missionId: toolMissionId,
        journey: "guided",
        status: "waiting_guided_decision",
        currentPlanId: toolPlanId,
        currentStepId: toolStepId,
        createdAt: at(0),
      });
      guidedPlan(connection, {
        missionId: toolMissionId,
        runId: toolRunId,
        planId: toolPlanId,
        stepId: toolStepId,
        decisionId: toolDecisionId,
        target: `https://tool-${namespace}.fixture.test`,
        kind: "tool",
        createdAt: at(0),
      });

      mission(connection, {
        id: manualMissionId,
        name: `${searchToken} Guided exact manual decision`,
        objective: "Represent one manual-only review for deliberate interpretation.",
        journey: "guided",
        engagementId,
        createdAt: at(1),
      });
      run(connection, {
        id: manualRunId,
        missionId: manualMissionId,
        journey: "guided",
        status: "waiting_guided_decision",
        currentPlanId: manualPlanId,
        currentStepId: manualStepId,
        createdAt: at(1),
      });
      guidedPlan(connection, {
        missionId: manualMissionId,
        runId: manualRunId,
        planId: manualPlanId,
        stepId: manualStepId,
        decisionId: manualDecisionId,
        target: `https://manual-${namespace}.fixture.test`,
        kind: "manual",
        createdAt: at(1),
      });

      mission(connection, {
        id: autonomousTerminalMissionId,
        name: `${searchToken} Autonomous terminal exception`,
        objective: "Retain a safe-stop exception and future-only administrative record.",
        journey: "autonomous",
        status: "failed",
        engagementId,
        createdAt: at(2),
      });
      contract(connection, {
        id: terminalContractId,
        missionId: autonomousTerminalMissionId,
        version: 1,
        state: "confirmed",
        createdAt: at(2),
      });
      run(connection, {
        id: autonomousTerminalRunId,
        missionId: autonomousTerminalMissionId,
        journey: "autonomous",
        status: "failed",
        contractId: terminalContractId,
        createdAt: at(2),
      });

      mission(connection, {
        id: autonomousActiveMissionId,
        name: `${searchToken} Autonomous active exception`,
        objective: "Retain an active exception without turning it into an approval prompt.",
        journey: "autonomous",
        engagementId,
        createdAt: at(3),
      });
      contract(connection, {
        id: activeContractId,
        missionId: autonomousActiveMissionId,
        version: 1,
        state: "confirmed",
        createdAt: at(3),
      });
      run(connection, {
        id: autonomousActiveRunId,
        missionId: autonomousActiveMissionId,
        journey: "autonomous",
        status: "running",
        contractId: activeContractId,
        createdAt: at(3),
      });

      for (let version = 2; version <= fillerContracts; version += 1) {
        contract(connection, {
          id: id(`contract-history-${String(version).padStart(2, "0")}-e2e`),
          missionId: autonomousTerminalMissionId,
          version,
          state: version === fillerContracts ? "draft" : "superseded",
          createdAt: at(20 + version),
        });
      }

      const approval = connection.prepare(`
        INSERT INTO approvals (
          id, mission_id, run_id, approval_type, status, requested_by, reason,
          policy_rule, request_json, expires_at, decided_by, decided_at, created_at
        ) VALUES (?, ?, ?, ?, ?, 'policy-service', ?, ?, ?, ?, ?, ?, ?)
      `);
      approval.run(
        terminalApprovalId,
        autonomousTerminalMissionId,
        autonomousTerminalRunId,
        "policy_change",
        "pending",
        `${searchToken} review a future-only policy change`,
        "future.policy",
        JSON.stringify({ change: "future-only", api_key: "fixture-secret-must-redact" }),
        "2100-01-01T00:00:00.000Z",
        null,
        null,
        at(4),
      );
      approval.run(
        activeApprovalId,
        autonomousActiveMissionId,
        autonomousActiveRunId,
        "configuration_change",
        "pending",
        `${searchToken} must never unblock active Autonomous work`,
        "future.configuration",
        "{}",
        "2100-01-01T00:00:00.000Z",
        null,
        null,
        at(5),
      );
      approval.run(
        systemApprovalId,
        null,
        null,
        "retention_policy",
        "pending",
        `${searchToken} system retention review`,
        "system.retention",
        "{\"scope\":\"future-runs\"}",
        "2100-01-01T00:00:00.000Z",
        null,
        null,
        at(6),
      );
      approval.run(
        id("approval-expired-e2e"),
        autonomousTerminalMissionId,
        autonomousTerminalRunId,
        "policy_change",
        "pending",
        `${searchToken} expired administrative record`,
        "future.policy",
        "{}",
        "2020-01-01T00:00:00.000Z",
        null,
        null,
        at(7),
      );

      const exception = connection.prepare(`
        INSERT INTO events (
          id, mission_id, run_id, sequence, event_type, occurred_at,
          actor_type, actor_id, summary, payload_json, schema_version, journey,
          trace_id, sensitivity, redaction_json, created_at
        ) VALUES (?, ?, ?, 1, ?, ?, 'system', 'run-supervisor', ?, ?, 1,
          'autonomous', ?, 'private', '{"paths":["authenticationToken"]}', ?)
      `);
      exception.run(
        terminalExceptionId,
        autonomousTerminalMissionId,
        autonomousTerminalRunId,
        "run.autonomous_safe_stopped",
        at(8),
        `${searchToken} no in-contract path remained after bounded recovery`,
        JSON.stringify({
          code: "outside_contract",
          category: "scope_conflict",
          authenticationToken: "fixture-secret-must-redact",
          retained: "checkpoint and prior evidence",
        }),
        id("trace-terminal-exception-e2e"),
        at(8),
      );
      connection.prepare("UPDATE run_event_sequences SET last_sequence = 1 WHERE run_id = ?")
        .run(autonomousTerminalRunId);
      exception.run(
        activeExceptionId,
        autonomousActiveMissionId,
        autonomousActiveRunId,
        "run.continuation_blocked",
        at(9),
        `${searchToken} unsafe in-flight action was not replayed`,
        JSON.stringify({ code: "unsafe_replay_blocked", category: "deterministic_tool_error" }),
        id("trace-active-exception-e2e"),
        at(9),
      );
      connection.prepare("UPDATE run_event_sequences SET last_sequence = 1 WHERE run_id = ?")
        .run(autonomousActiveRunId);

      mission(connection, {
        id: intelligenceMissionId,
        name: intelligenceMissionTitle,
        objective: "Exercise bounded canonical intelligence list, detail, filter, cursor, and export projections.",
        journey: "guided",
        engagementId,
        createdAt: at(100),
      });
      run(connection, {
        id: intelligenceRunId,
        missionId: intelligenceMissionId,
        journey: "guided",
        status: "running",
        createdAt: at(100),
      });

      const evidence = connection.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity, verification_state,
          summary, extracted_text, artifact_id, created_by, created_at
        ) VALUES (?, ?, ?, 'e2e-canonical-intelligence', ?, ?, ?, ?, ?, ?, 'internal', ?, ?, ?, ?, ?, ?)
      `);
      const evidenceStates = ["verified", "unverified", "disputed", "rejected"] as const;
      const evidenceTypes = ["port_service_scan_result", "http_request_response_pair", "configuration_snapshot"] as const;
      for (let index = 0; index < evidenceCount; index += 1) {
        const evidenceId = index === 0 ? primaryEvidenceId : id(`evidence-${String(index).padStart(2, "0")}-intelligence-e2e`);
        const acquiredAt = at(100 + index);
        const summary = index === 0
          ? primaryEvidenceSummary
          : `${searchToken} canonical evidence record ${index}`;
        evidence.run(
          evidenceId,
          intelligenceMissionId,
          intelligenceRunId,
          acquiredAt,
          `https://intelligence-${namespace}.fixture.test:${443 + index}`,
          evidenceTypes[index % evidenceTypes.length],
          digest(evidenceId),
          JSON.stringify({ method: "isolated_fixture", sourceIds: [`fixture-source-${index}`] }),
          1 - (index % 5) * 0.1,
          evidenceStates[index % evidenceStates.length],
          summary,
          `${summary} attributable normalized observation`,
          index === 0 ? primaryArtifactId : null,
          OPERATOR,
          acquiredAt,
        );
      }
      connection.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity, verification_state,
          summary, extracted_text, artifact_id, created_by, created_at
        ) VALUES (?, ?, ?, 'legacy_runtime', ?, ?, 'command_output', ?, ?, 0.5,
          'internal', 'unverified', ?, 'raw terminal output retained for reconciliation',
          NULL, 'import:legacy', ?)
      `).run(
        operationalLogEvidenceId,
        intelligenceMissionId,
        intelligenceRunId,
        at(99),
        `https://intelligence-${namespace}.fixture.test`,
        digest(operationalLogEvidenceId),
        JSON.stringify({ method: "legacy_import", rawOutputIsEvidence: false }),
        operationalLogEvidenceSummary,
        at(99),
      );
      connection.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES (?, ?, 'acquired', ?, ?, ?), (?, ?, 'verified', ?, ?, ?)
      `).run(
        id("custody-acquired-primary-e2e"),
        primaryEvidenceId,
        "ReconScout",
        JSON.stringify({ source: "bounded fixture probe", handling: "normalized metadata only" }),
        at(99),
        id("custody-verified-primary-e2e"),
        primaryEvidenceId,
        OPERATOR,
        JSON.stringify({ policy: "immutable finding evidence gate", outcome: "verified" }),
        at(98),
      );

      const finding = connection.prepare(`
        INSERT INTO findings (
          id, mission_id, run_id, title, severity, confidence, affected_scope,
          description, impact, reproduction_notes, remediation, review_status,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const severities = ["critical", "high", "medium", "low", "informational"] as const;
      const reviewStates = ["under_review", "draft", "verified", "rejected", "accepted_risk"] as const;
      for (let index = 0; index < findingCount; index += 1) {
        const findingId = index === 0 ? primaryFindingId : id(`finding-${String(index).padStart(2, "0")}-intelligence-e2e`);
        const updatedAt = at(200 + index);
        const title = index === 0 ? primaryFindingTitle : `${searchToken} canonical finding ${index}`;
        finding.run(
          findingId,
          intelligenceMissionId,
          intelligenceRunId,
          title,
          severities[index % severities.length],
          1 - (index % 5) * 0.1,
          `https://intelligence-${namespace}.fixture.test`,
          `${title} is supported only by attributable fixture records.`,
          "The fixture demonstrates review behavior without claiming target impact.",
          "Reproduce only against the isolated fixture record.",
          "Retain the evidence boundary and review the normalized observation.",
          reviewStates[index % reviewStates.length],
          updatedAt,
          updatedAt,
        );
      }
      connection.prepare(`
        INSERT INTO finding_evidence (finding_id, evidence_id, relationship, added_at)
        VALUES (?, ?, 'supports', ?)
      `).run(primaryFindingId, primaryEvidenceId, at(97));

      const artifact = connection.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, journey, artifact_type, storage_uri,
          content_hash, byte_size, media_type, sensitivity, metadata_json, created_at
        ) VALUES (?, ?, ?, 'guided', ?, ?, ?, ?, ?, 'internal', ?, ?)
      `);
      const artifactTypes = ["network_map", "scan_archive", "report_draft"] as const;
      for (let index = 0; index < artifactCount; index += 1) {
        const artifactId = index === 0 ? primaryArtifactId : id(`artifact-${String(index).padStart(2, "0")}-intelligence-e2e`);
        const artifactType = index === 0 ? primaryArtifactType : `${artifactTypes[index % artifactTypes.length]}_${index}`;
        const createdAt = at(300 + index);
        artifact.run(
          artifactId,
          intelligenceMissionId,
          intelligenceRunId,
          artifactType,
          `artifact-store://metadata/${artifactId}`,
          digest(artifactId),
          1_024 + index * 37,
          index % 2 === 0 ? "application/json" : "text/markdown",
          JSON.stringify({ source: "isolated_fixture", index, immutable: true }),
          createdAt,
        );
      }
      mission(connection, {
        id: relationlessMissionId,
        name: relationlessMissionTitle,
        objective: "Retain imported intelligence while explicitly representing absent and unavailable relationships.",
        journey: "guided",
        engagementId,
        createdAt: at(400),
      });
      evidence.run(
        relationlessEvidenceId,
        relationlessMissionId,
        null,
        at(400),
        `https://historical-${namespace}.fixture.test`,
        "configuration_snapshot",
        digest(relationlessEvidenceId),
        JSON.stringify({ method: "isolated_fixture", imported: true }),
        0.7,
        "unverified",
        relationlessEvidenceSummary,
        null,
        id("artifact-no-longer-present-e2e"),
        OPERATOR,
        at(400),
      );
      evidence.run(
        crossMissionRunEvidenceId,
        relationlessMissionId,
        intelligenceRunId,
        at(401),
        `https://historical-cross-mission-${namespace}.fixture.test`,
        "configuration_snapshot",
        digest(crossMissionRunEvidenceId),
        JSON.stringify({ method: "isolated_fixture", imported: true, reconciliation: "cross_mission_run" }),
        0.5,
        "unverified",
        crossMissionRunEvidenceSummary,
        null,
        null,
        OPERATOR,
        at(401),
      );
      mission(connection, {
        id: archivedMissionId,
        name: archivedMissionTitle,
        objective: "Prove archived canonical intelligence remains inspectable without reviving execution authority.",
        journey: "guided",
        status: "archived",
        engagementId,
        createdAt: at(402),
      });
      run(connection, {
        id: archivedRunId,
        missionId: archivedMissionId,
        journey: "guided",
        status: "completed",
        createdAt: at(402),
      });
      evidence.run(
        archivedEvidenceId,
        archivedMissionId,
        archivedRunId,
        at(402),
        `https://archived-${namespace}.fixture.test`,
        "web_page_capture",
        digest(archivedEvidenceId),
        JSON.stringify({ method: "isolated_fixture", lifecycle: "archived_run" }),
        0.9,
        "verified",
        archivedEvidenceSummary,
        null,
        quarantinedArtifactId,
        OPERATOR,
        at(402),
      );
      evidence.run(
        deletedArtifactEvidenceId,
        archivedMissionId,
        archivedRunId,
        at(403),
        `https://archived-${namespace}.fixture.test`,
        "file_artifact_with_hash",
        digest(deletedArtifactEvidenceId),
        JSON.stringify({ method: "isolated_fixture", lifecycle: "artifact_deleted_after_acquisition" }),
        0.6,
        "disputed",
        deletedArtifactEvidenceSummary,
        null,
        deletedArtifactId,
        OPERATOR,
        at(403),
      );
      connection.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES (?, ?, 'verified', ?, ?, ?), (?, ?, 'disputed', ?, ?, ?)
      `).run(
        id("custody-verified-archived-e2e"),
        archivedEvidenceId,
        OPERATOR,
        JSON.stringify({ outcome: "verified_before_quarantine", lifecycle: "archived_run" }),
        at(401),
        id("custody-disputed-deleted-artifact-e2e"),
        deletedArtifactEvidenceId,
        OPERATOR,
        JSON.stringify({ outcome: "artifact_reference_unavailable", lifecycle: "reconciliation_required" }),
        at(402),
      );
      finding.run(
        relationlessFindingId,
        relationlessMissionId,
        null,
        relationlessFindingTitle,
        "informational",
        0.6,
        `https://historical-${namespace}.fixture.test`,
        "This imported finding deliberately has no retained run or evidence relationship.",
        "No impact is asserted without attributable evidence.",
        null,
        "Acquire current evidence before validation.",
        "draft",
        at(401),
        at(401),
      );
      artifact.run(
        relationlessArtifactId,
        relationlessMissionId,
        null,
        relationlessArtifactType,
        `artifact-store://metadata/${relationlessArtifactId}`,
        digest(relationlessArtifactId),
        512,
        "application/json",
        JSON.stringify({ source: "isolated_fixture", imported: true }),
        at(402),
      );
      artifact.run(
        quarantinedArtifactId,
        archivedMissionId,
        archivedRunId,
        quarantinedArtifactType,
        `artifact-store://quarantine/${quarantinedArtifactId}`,
        digest(quarantinedArtifactId),
        768,
        "image/png",
        JSON.stringify({
          source: "isolated_fixture",
          lifecycleState: "quarantined",
          quarantineReason: "fixture_integrity_review",
        }),
        at(403),
      );
    });

    // Local Commander guidance writes only a conversation exchange and Context
    // Pack, but those durable writes still require the exact run control-plane
    // lease. Keep the manual-only fixture under the isolated Commander lease.
    // The tool-card fixture is deliberately left unleased so the mounted
    // deterministic Guided runtime must acquire and prove its own authority
    // when the browser rejects that exact step and requests a replan.
    acquireTestRunMutationAuthority(connection, manualRunId);

    const decisionInboxCount = Number((connection.prepare(`
      SELECT
        (SELECT COUNT(*) FROM guided_decisions WHERE mission_id IN (?, ?)) +
        (SELECT COUNT(*) FROM mission_contracts WHERE mission_id IN (?, ?)) +
        (SELECT COUNT(*) FROM events WHERE id IN (?, ?)) +
        (SELECT COUNT(*) FROM approvals WHERE reason LIKE ?) AS count
    `).get(
      toolMissionId,
      manualMissionId,
      autonomousTerminalMissionId,
      autonomousActiveMissionId,
      terminalExceptionId,
      activeExceptionId,
      `%${searchToken}%`,
    ) as { count: number }).count);

    return {
      namespace,
      searchToken,
      absentToken,
      intelligenceMissionId,
      intelligenceRunId,
      intelligenceMissionTitle,
      primaryEvidenceId,
      primaryEvidenceSummary,
      operationalLogEvidenceId,
      operationalLogEvidenceSummary,
      primaryFindingId,
      primaryFindingTitle,
      primaryArtifactId,
      primaryArtifactType,
      relationlessMissionId,
      relationlessMissionTitle,
      relationlessEvidenceId,
      relationlessEvidenceSummary,
      missingRunEvidenceId,
      missingRunEvidenceSummary,
      crossMissionRunEvidenceId,
      crossMissionRunEvidenceSummary,
      archivedMissionId,
      archivedMissionTitle,
      archivedRunId,
      archivedEvidenceId,
      archivedEvidenceSummary,
      deletedArtifactEvidenceId,
      deletedArtifactEvidenceSummary,
      deletedArtifactId,
      quarantinedArtifactId,
      quarantinedArtifactType,
      relationlessFindingId,
      relationlessFindingTitle,
      relationlessArtifactId,
      relationlessArtifactType,
      toolMissionId,
      toolRunId,
      toolStepId,
      toolDecisionId,
      guidedModelConfigurationId: GUIDED_MODEL_CONFIGURATION_ID,
      manualMissionId,
      manualRunId,
      manualStepId,
      manualDecisionId,
      autonomousTerminalMissionId,
      autonomousTerminalRunId,
      autonomousActiveMissionId,
      autonomousActiveRunId,
      terminalApprovalId,
      activeApprovalId,
      systemApprovalId,
      terminalContractId,
      terminalExceptionId,
      activeExceptionId,
      evidenceCount,
      findingCount,
      artifactCount,
      decisionInboxCount,
    };
  } finally {
    connection.close();
  }
}

export interface GuidedRuntimeBindingReceipt {
  readonly provider: string;
  readonly model: string | null;
  readonly status: string;
  readonly agentId: string | null;
  readonly modelAssignmentId: string | null;
  readonly modelConfigurationId: string | null;
  readonly promptTemplateHash: string | null;
  readonly contextPackId: string | null;
}

export function readGuidedRuntimeBindingReceipts(
  fixture: DecisionsIntelligenceFixture,
): readonly GuidedRuntimeBindingReceipt[] {
  const connection = database();
  try {
    return connection.prepare(`
      SELECT
        provider,
        model,
        status,
        agent_id AS agentId,
        model_assignment_id AS modelAssignmentId,
        model_configuration_id AS modelConfigurationId,
        prompt_template_hash AS promptTemplateHash,
        context_pack_id AS contextPackId
      FROM provider_turns
      WHERE run_id = ?
      ORDER BY started_at, id
    `).all(fixture.toolRunId) as GuidedRuntimeBindingReceipt[];
  } finally {
    connection.close();
  }
}

export function readDecisionsIntelligenceFixtureSnapshot(
  fixture: DecisionsIntelligenceFixture,
): DecisionsIntelligenceFixtureSnapshot {
  const connection = database();
  try {
    const scalar = (sql: string, ...params: unknown[]): number => Number((connection.prepare(sql).get(...params) as { count: number }).count);
    const status = (table: "guided_decisions" | "approvals", recordId: string): string => {
      const row = connection.prepare(`SELECT status FROM ${table} WHERE id = ?`).get(recordId) as { status: string } | undefined;
      if (!row) throw new Error(`Fixture record is missing: ${table}/${recordId}`);
      return row.status;
    };
    const findingReview = (findingId: string): FindingReviewFixtureSnapshot => {
      const finding = connection.prepare(`
        SELECT review_status, version, operator_override
        FROM findings WHERE id = ?
      `).get(findingId) as {
        review_status: string;
        version: number;
        operator_override: number;
      } | undefined;
      if (!finding) throw new Error(`Fixture finding is missing: ${findingId}`);
      const audits = connection.prepare(`
        SELECT action, reason, details_json
        FROM audit_records
        WHERE resource_type = 'finding' AND resource_id = ?
        ORDER BY occurred_at ASC, id ASC
      `).all(findingId) as Array<{
        action: string;
        reason: string | null;
        details_json: string;
      }>;
      return {
        status: finding.review_status,
        version: finding.version,
        operatorOverride: Boolean(finding.operator_override),
        audits: audits.map((audit) => ({
          action: audit.action,
          reason: audit.reason,
          details: JSON.parse(audit.details_json) as Record<string, unknown>,
        })),
      };
    };
    return {
      evidenceCount: scalar(
        "SELECT COUNT(*) AS count FROM evidence WHERE mission_id = ? AND lower(trim(evidence_type)) <> 'command_output'",
        fixture.intelligenceMissionId,
      ),
      findingCount: scalar("SELECT COUNT(*) AS count FROM findings WHERE mission_id = ?", fixture.intelligenceMissionId),
      artifactCount: scalar("SELECT COUNT(*) AS count FROM artifacts WHERE mission_id = ?", fixture.intelligenceMissionId),
      decisionInboxCount: fixture.decisionInboxCount,
      toolDecisionStatus: status("guided_decisions", fixture.toolDecisionId),
      manualDecisionStatus: status("guided_decisions", fixture.manualDecisionId),
      terminalApprovalStatus: status("approvals", fixture.terminalApprovalId),
      activeApprovalStatus: status("approvals", fixture.activeApprovalId),
      systemApprovalStatus: status("approvals", fixture.systemApprovalId),
      fixtureAuditCount: scalar(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE resource_id IN (?, ?, ?, ?, ?)
      `, fixture.toolDecisionId, fixture.manualDecisionId, fixture.terminalApprovalId, fixture.activeApprovalId, fixture.systemApprovalId),
      primaryFindingReview: findingReview(fixture.primaryFindingId),
      relationlessFindingReview: findingReview(fixture.relationlessFindingId),
    };
  } finally {
    connection.close();
  }
}

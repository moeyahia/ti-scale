import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { EventRepository } from "../../events";
import { RunLearningService } from "../../learning";
import { CanonicalMissionReportService } from "../../reports";
import type { CanonicalReportArtifactCommitment } from "../../reports";
import {
  AUTONOMOUS_CLEARTEXT_TELNET_FINDING_POLICY_ID,
  AUTONOMOUS_DETERMINISTIC_FINDING_REFERENCE_SCHEMA_VERSION,
} from "../AutonomousDeterministicFindingPolicy";
import { AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION } from "../AutonomousIpEvidenceVerifier";
import {
  AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
  AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE,
} from "../AutonomousIpSafeRecon";
import {
  AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS,
  AutonomousTerminalDeliverableError,
  AutonomousTerminalDeliverableService,
} from "../AutonomousTerminalDeliverableService";

const NOW = "2026-07-22T10:00:00.000Z";
const MISSION_ID = "mission-autonomous-terminal";
const RUN_ID = "run-autonomous-terminal";
const CONTRACT_ID = "contract-autonomous-terminal";
const PLAN_ID = "plan-autonomous-terminal";
const STEP_ID = "step-autonomous-terminal";
const ACTION_ID = "action-autonomous-terminal";
const ACCESS = {
  maximumSensitivity: "restricted",
  allEngagements: true,
  allowGlobalKnowledge: true,
  allowUnscopedSystemData: true,
} as const;

const databases: ReturnType<typeof createDatabaseConnection>[] = [];
const directories: string[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixture(input: {
  readonly deliverables?: readonly string[];
  readonly artifactBytes?: number;
} = {}) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  const artifactRoot = mkdtempSync(join(tmpdir(), "ti-scale-terminal-deliverables-"));
  directories.push(artifactRoot);
  const deliverables = input.deliverables ?? AUTONOMOUS_CANONICAL_REPORT_DELIVERABLE_IDS;
  const artifactBytes = input.artifactBytes ?? 2 * 1024 * 1024;
  const contractHash = "a".repeat(64);
  const policy = {
    reportingFormat: "ti_scale_json",
    dataHandlingPolicy: "local_private",
  };
  const budget = { artifactBytes, toolCalls: 1 };
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at
    ) VALUES (?, 'Autonomous terminal truth', 'Produce exact evidence-linked closeout.',
      'autonomous', 'active', 'verified', 'operator:test', ?, ?)
  `).run(MISSION_ID, NOW, NOW);
  database.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, ?, '{"conditions":[]}', ?,
      '[]', 'operator:test', ?, ?)
  `).run(
    CONTRACT_ID,
    MISSION_ID,
    contractHash,
    JSON.stringify(policy),
    JSON.stringify(budget),
    JSON.stringify(deliverables),
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, contract_version_bound,
      contract_hash_bound, current_plan_id, current_step_id, progress,
      status_reason, budget_json, budget_usage_json, started_at,
      created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'autonomous', 'running', ?, 1, ?, ?, ?, 0.8,
      'Awaiting evidence-backed evaluation', ?, '{}', ?, ?, ?, 1, 'ti_scale')
  `).run(
    RUN_ID,
    MISSION_ID,
    CONTRACT_ID,
    contractHash,
    PLAN_ID,
    STEP_ID,
    JSON.stringify(budget),
    NOW,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'completed', 'Bounded deterministic reconnaissance',
      'Use only reviewed local evidence', ?, 'mission-planner', ?, ?)
  `).run(PLAN_ID, RUN_ID, "b".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'recon', 'Check exact host', 'Retain attributable facts',
      'completed', '[]', '[]', 'port_service_enumeration', 'medium', ?, ?, ?, ?)
  `).run(STEP_ID, PLAN_ID, RUN_ID, NOW, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, action_type, action_class, fingerprint,
      normalized_arguments_json, scoped_target, status, intent_summary,
      result_summary, retry_count, started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'port_service_enumeration', ?, '{}', '192.0.2.10',
      'succeeded', 'Inspect the exact authorized host', 'Attributable facts retained',
      0, ?, ?, ?, ?)
  `).run(
    ACTION_ID,
    MISSION_ID,
    RUN_ID,
    STEP_ID,
    AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
    "c".repeat(64),
    NOW,
    NOW,
    NOW,
    NOW,
  );
  return {
    database,
    artifactRoot,
    service: new AutonomousTerminalDeliverableService(database, {
      artifactRoot,
      clock: () => new Date(NOW),
    }),
  };
}

function commitTerminal(database: ReturnType<typeof createDatabaseConnection>): string {
  database.prepare(`
    UPDATE runs SET status = 'completed', progress = 1,
      status_reason = 'All exact criteria passed.', ended_at = ?, updated_at = ?
    WHERE id = ?
  `).run(NOW, NOW, RUN_ID);
  database.prepare(`
    UPDATE missions SET status = 'completed', updated_at = ? WHERE id = ?
  `).run(NOW, MISSION_ID);
  database.prepare(`
    INSERT INTO run_evaluations (
      id, mission_id, run_id, journey, scores_json, metrics_json,
      retrospective, evidence_coverage, created_by, created_at
    ) VALUES ('evaluation-autonomous-terminal', ?, ?, 'autonomous',
      '{"completion":1}', '{"criteria":1}',
      'The exact authorized criteria passed against canonical evidence.',
      1, 'outcome-evaluator', ?)
  `).run(MISSION_ID, RUN_ID, NOW);
  return "terminal-committed";
}

function commitTerminalWithCanonicalEvaluation(
  database: ReturnType<typeof createDatabaseConnection>,
  reportCommitment: CanonicalReportArtifactCommitment | null,
) {
  database.prepare(`
    UPDATE runs SET status = 'completed', progress = 1,
      status_reason = 'All exact criteria passed.', ended_at = ?, updated_at = ?
    WHERE id = ?
  `).run(NOW, NOW, RUN_ID);
  database.prepare(`
    UPDATE missions SET status = 'completed', updated_at = ? WHERE id = ?
  `).run(NOW, MISSION_ID);
  return new RunLearningService(database, {
    clock: () => new Date(NOW),
    events: new EventRepository(database),
  }).recordTerminalEvaluation({
    runId: RUN_ID,
    terminalStatus: "completed",
    createdBy: "outcome-evaluator",
    outcome: {
      success: true,
      summary: "All exact criteria passed.",
      criteria: [],
    },
    ...(reportCommitment ? { terminalReportCommitment: reportCommitment } : {}),
  });
}

function contentFiles(root: string): readonly string[] {
  return readdirSync(root)
    .filter((name) => name.endsWith(".md") || name.endsWith(".json"))
    .sort();
}

function reportJson(
  database: ReturnType<typeof createDatabaseConnection>,
  artifactRoot: string,
  artifactId: string,
): Readonly<Record<string, unknown>> {
  const download = new CanonicalMissionReportService(database, { artifactRoot })
    .download(artifactId, ACCESS);
  return JSON.parse(download.body.toString("utf8")) as Readonly<Record<string, unknown>>;
}

function reportMarkdown(
  database: ReturnType<typeof createDatabaseConnection>,
  artifactRoot: string,
  artifactId: string,
): string {
  return new CanonicalMissionReportService(database, { artifactRoot })
    .download(artifactId, ACCESS).body.toString("utf8");
}

function seedTerminalReportPreferences(
  database: ReturnType<typeof createDatabaseConnection>,
  input: Readonly<{ supported?: boolean }> = {},
): readonly string[] {
  const contextPackId = "context-terminal-reporting";
  const supported = input.supported !== false;
  const preferences = [
    {
      nodeId: "memory-preference-technical-readable",
      key: "communication.technical_readability",
      title: "Readable technical language",
      value: supported
        ? {
            category: "communication",
            value: {
              style: "technical_readable",
              avoid: ["oversimplified wording", "opaque internal jargon"],
              include: ["purpose", "operational meaning", "useful technical detail"],
            },
            appliesTo: ["guided_explanations", "evidence_presentation", "reports"],
          }
        : {
            category: "communication",
            value: { style: "unreviewed_free_form" },
            appliesTo: ["reports"],
          },
    },
    {
      nodeId: "memory-preference-evidence-first",
      key: "communication.evidence_first",
      title: "Evidence-first explanations",
      value: supported
        ? {
            category: "communication",
            value: {
              rawLogs: "not_automatically_evidence",
              structure: [
                "observation",
                "meaning",
                "confidence",
                "uncertainty",
                "next justified action",
              ],
            },
            appliesTo: ["evidence_presentation", "guided_explanations", "reports"],
          }
        : {
            category: "communication",
            value: { rawLogs: "promote_all_output", structure: ["raw output"] },
            appliesTo: ["evidence_presentation", "reports"],
          },
    },
    {
      nodeId: "memory-preference-unrelated",
      key: "visual.titanium_identity",
      title: "Titanium visual identity",
      value: {
        category: "visual",
        value: { material: "titanium" },
        appliesTo: ["visual_identity"],
      },
    },
  ] as const;
  for (const [index, preference] of preferences.entries()) {
    database.prepare(`
      INSERT INTO memory_nodes (
        id, node_type, title, summary, body, scope, sensitivity, confidence,
        lifecycle_status, confirmation_state, provenance_json, author_type,
        author_id, version, retention_policy_json, created_at, updated_at
      ) VALUES (?, 'preference', ?, 'Explicit operator-confirmed preference.',
        'The node body is never interpreted as report instructions.', 'global',
        'private', 1, 'confirmed', 'confirmed', '{"method":"operator_statement","sources":[]}',
        'operator', 'operator:test', 1, '{}', ?, ?)
    `).run(preference.nodeId, preference.title, NOW, NOW);
    database.prepare(`
      INSERT INTO preference_profiles (
        id, operator_id, scope, preference_key, value_json,
        confirmation_state, confidence, source_node_id, consent_policy,
        version, confirmed_at, created_at, updated_at
      ) VALUES (?, 'operator:test', 'global', ?, ?, 'confirmed', 1, ?,
        'explicit_operator_confirmation', 1, ?, ?, ?)
    `).run(
      `profile-terminal-${index}`,
      preference.key,
      JSON.stringify(preference.value),
      preference.nodeId,
      NOW,
      NOW,
      NOW,
    );
  }
  const vaultConnectionId = "vault-terminal-reporting";
  database.prepare(`
    INSERT INTO vault_connections (
      id, vault_path, display_name, status, sync_scope_json,
      permission_granted_at, last_sync_at, created_at, updated_at
    ) VALUES (?, ?, 'Terminal reporting preference Vault', 'connected', '{}',
      ?, ?, ?, ?)
  `).run(
    vaultConnectionId,
    `/tmp/${vaultConnectionId}`,
    NOW,
    NOW,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO audit_records (
      id, actor_type, actor_id, action, resource_type, resource_id,
      reason, details_json, record_hash, occurred_at
    ) VALUES (?, 'operator', 'operator:test', 'vault.health.verified',
      'vault_connection', ?, 'Fixture round trip passed', '{}', ?, ?)
  `).run(
    `audit-${vaultConnectionId}`,
    vaultConnectionId,
    "f".repeat(64),
    NOW,
  );
  const insertSync = database.prepare(`
    INSERT INTO vault_sync_state (
      id, connection_id, node_id, relative_path, database_version,
      vault_content_hash, database_content_hash, status,
      last_scanned_at, last_synced_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'synced', ?, ?)
  `);
  for (const preference of preferences) {
    const current = database.prepare(`
      SELECT version FROM memory_nodes WHERE id = ?
    `).get(preference.nodeId) as {
      readonly version: number;
    };
    const contentHash = createHash("sha256")
      .update(`terminal-report-preference:${preference.nodeId}:v${current.version}`, "utf8")
      .digest("hex");
    insertSync.run(
      `sync-${preference.nodeId}`,
      vaultConnectionId,
      preference.nodeId,
      `10 Operator/${preference.nodeId}.md`,
      current.version,
      contentHash,
      contentHash,
      NOW,
      NOW,
    );
  }
  database.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, retrieval_metrics_json,
      release_data_class, created_by, created_at
    ) VALUES (?, ?, ?, 'autonomous', 'Reporting: confirmed presentation preferences',
      'Retrieve confirmed report preferences.', '{"journey":"autonomous"}',
      6000, '{"retrievedCount":3}', 'canonical', 'outcome-evaluator', ?)
  `).run(contextPackId, MISSION_ID, RUN_ID, NOW);
  for (const [rank, preference] of preferences.entries()) {
    database.prepare(`
      INSERT INTO memory_context_items (
        context_pack_id, node_id, rank, retrieval_score, used,
        relevance_reason, influence_summary, ignored_reason, corrected
      ) VALUES (?, ?, ?, 1, 0, 'Explicitly selected for terminal reporting.',
        NULL, 'Not yet applied to terminal reporting.', 0)
    `).run(contextPackId, preference.nodeId, rank);
  }
  new EventRepository(database).append({
    id: "event-terminal-projection-context",
    missionId: MISSION_ID,
    runId: RUN_ID,
    journey: "autonomous",
    eventType: "brain.terminal_projection_context_selected",
    occurredAt: NOW,
    actorType: "agent",
    actorId: "outcome-evaluator",
    summary: "Terminal reporting Context Pack selected.",
    contextPackId,
    payload: {
      evaluationId: "evaluation-autonomous-terminal",
      reportingContextPackId: contextPackId,
      closeoutContextPackId: "context-terminal-closeout",
      reportingExpectedNodeIds: [],
      closeoutExpectedNodeIds: [],
    },
  });
  return preferences.map(({ nodeId }) => nodeId);
}

function seedOrdinaryDnsObservation(database: ReturnType<typeof createDatabaseConnection>): void {
  database.prepare(`
    INSERT INTO engagement_log_records (
      id, mission_id, run_id, plan_id, step_id, action_id, severity, domain,
      record_type, human_summary, technical_payload_json, content_hash,
      sensitivity, occurred_at, created_at
    ) VALUES ('log-dns-ordinary', ?, ?, ?, ?, ?, 'notice', 'autonomous_dns',
      'bounded_dns_result', 'A DNS answer was parsed.', '{}', ?, 'private', ?, ?)
  `).run(MISSION_ID, RUN_ID, PLAN_ID, STEP_ID, ACTION_ID, "d".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO observations (
      id, mission_id, run_id, step_id, observation_type, statement,
      normalized_value_json, confidence, verification_state, source_tool,
      first_seen_at, last_seen_at, sensitivity, created_at
    ) VALUES ('observation-dns-ordinary', ?, ?, ?, 'dns_records',
      'The approved host returned one DNS answer.', '{"answers":["192.0.2.10"]}',
      0.95, 'corroborated', 'kali:host-dns-query', ?, ?, 'private', ?)
  `).run(MISSION_ID, RUN_ID, STEP_ID, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO observation_log_sources (
      observation_id, log_record_id, parser_id, parser_version, created_at
    ) VALUES ('observation-dns-ordinary', 'log-dns-ordinary',
      'deterministic-dns-parser', '1.0.0', ?)
  `).run(NOW);
}

function seedExplicitTelnetEvidence(database: ReturnType<typeof createDatabaseConnection>): string {
  const logId = "log-explicit-telnet";
  const observationId = "observation-explicit-telnet";
  const evidenceId = "evidence-explicit-telnet";
  const fingerprint = [{
    port: 23,
    transport: "tcp",
    state: "open",
    service: "telnet",
    version: "test fixture",
  }];
  database.prepare(`
    INSERT INTO engagement_log_records (
      id, mission_id, run_id, plan_id, step_id, action_id, severity, domain,
      record_type, human_summary, technical_payload_json, content_hash,
      sensitivity, occurred_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'notice', 'autonomous_ip_safe_recon',
      'bounded_ip_process_output', 'One attributable Telnet fingerprint was retained.',
      '{}', ?, 'private', ?, ?)
  `).run(logId, MISSION_ID, RUN_ID, PLAN_ID, STEP_ID, ACTION_ID, "e".repeat(64), NOW, NOW);
  const normalizedObservation = JSON.stringify({
    schemaVersion: AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION,
    host: "192.0.2.10",
    openPorts: fingerprint,
    actionId: ACTION_ID,
    toolId: AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
    rawOutputPromoted: false,
    cveClaimsCreated: false,
  });
  database.prepare(`
    INSERT INTO observations (
      id, mission_id, run_id, step_id, observation_type, statement,
      normalized_value_json, confidence, verification_state, source_tool,
      first_seen_at, last_seen_at, sensitivity, created_at
    ) VALUES (?, ?, ?, ?, 'tcp_service_scan',
      'The exact approved host exposed one attributable Telnet service.', ?,
      0.95, 'corroborated', ?, ?, ?, 'private', ?)
  `).run(
    observationId,
    MISSION_ID,
    RUN_ID,
    STEP_ID,
    normalizedObservation,
    AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
    NOW,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO observation_log_sources (
      observation_id, log_record_id, parser_id, parser_version, created_at
    ) VALUES (?, ?, 'ti-scale.autonomous-ip-deterministic-parser', '1.0.0', ?)
  `).run(observationId, logId, NOW);
  const extractedText = JSON.stringify({ host: "192.0.2.10", fingerprints: fingerprint });
  const contentHash = createHash("sha256").update(extractedText, "utf8").digest("hex");
  const provenance = JSON.stringify({
    schemaVersion: AUTONOMOUS_IP_EVIDENCE_VERIFIER_SCHEMA_VERSION,
    method: "deterministic_reviewed_ip_result_validation",
    actionId: ACTION_ID,
    toolId: AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
    specialistAgentId: "ReconScout",
    observationId,
    logRecordId: logId,
    rawOutputPromoted: false,
    cveClaimsCreated: false,
    deterministicFindingPolicyReferences: [{
      schemaVersion: AUTONOMOUS_DETERMINISTIC_FINDING_REFERENCE_SCHEMA_VERSION,
      policyId: AUTONOMOUS_CLEARTEXT_TELNET_FINDING_POLICY_ID,
    }],
  });
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, extracted_text, created_by, created_at
    ) VALUES (?, ?, ?, ?, ?, 'specialist:ReconScout', ?, '192.0.2.10', ?, ?, ?,
      0.9, 'private', 'verified', 'One exact service fingerprint was verified.', ?,
      'autonomous-ip-evidence-verifier', ?)
  `).run(
    evidenceId,
    MISSION_ID,
    RUN_ID,
    STEP_ID,
    ACTION_ID,
    NOW,
    AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE,
    contentHash,
    provenance,
    extractedText,
    NOW,
  );
  database.prepare(`
    INSERT INTO evidence_chain_events (id, evidence_id, event_type, actor, details_json, occurred_at)
    VALUES ('custody-telnet-acquired', ?, 'acquired', 'ReconScout', '{}', ?),
      ('custody-telnet-verified', ?, 'verified', 'autonomous-ip-evidence-verifier', '{}', ?)
  `).run(evidenceId, NOW, evidenceId, NOW);
  return evidenceId;
}

describe("AutonomousTerminalDeliverableService", () => {
  test("records one immutable evaluation that includes the atomically verified report pair", () => {
    const { database, artifactRoot, service } = fixture();
    seedOrdinaryDnsObservation(database);

    const first = service.completeAtomically(
      RUN_ID,
      (reportCommitment) =>
        commitTerminalWithCanonicalEvaluation(database, reportCommitment),
    );
    expect(first.terminal.metrics).toMatchObject({
      artifactCount: 2,
      reportCount: 2,
    });
    expect(first.terminal.scores.reportQuality).toBe(1);
    expect(first.deliverables.report?.artifacts).toHaveLength(2);

    const jsonArtifact = first.deliverables.report!.artifacts
      .find(({ format }) => format === "json")!;
    const embeddedEvaluation = reportJson(database, artifactRoot, jsonArtifact.id)
      .evaluation as {
        readonly scores: Readonly<Record<string, number | null>>;
        readonly metrics: Readonly<Record<string, number | string | null>>;
      };
    expect(embeddedEvaluation.metrics).toMatchObject({
      artifactCount: 2,
      reportCount: 2,
    });
    expect(embeddedEvaluation.scores.reportQuality).toBe(1);

    const replay = service.completeAtomically(RUN_ID, (reportCommitment) =>
      new RunLearningService(database, {
        clock: () => new Date(NOW),
        events: new EventRepository(database),
      }).recordTerminalEvaluation({
        runId: RUN_ID,
        terminalStatus: "completed",
        createdBy: "outcome-evaluator",
        ...(reportCommitment ? { terminalReportCommitment: reportCommitment } : {}),
      }));
    expect(replay.terminal).toEqual(first.terminal);
    expect(replay.deliverables.report?.artifacts).toEqual(first.deliverables.report?.artifacts);
    expect(database.prepare("SELECT COUNT(*) AS count FROM run_evaluations").get())
      .toEqual({ count: 1 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM events WHERE event_type = 'run.evaluation_recorded'
    `).get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get())
      .toEqual({ count: 2 });
  });

  test("applies only supported confirmed reporting preferences and persists their exact influence", () => {
    const { database, artifactRoot, service } = fixture();
    const preferenceNodeIds = seedTerminalReportPreferences(database);
    seedExplicitTelnetEvidence(database);

    const first = service.completeAtomically(RUN_ID, () => commitTerminal(database));
    const jsonArtifact = first.deliverables.report!.artifacts
      .find(({ format }) => format === "json")!;
    const markdownArtifact = first.deliverables.report!.artifacts
      .find(({ format }) => format === "markdown")!;
    const report = reportJson(database, artifactRoot, jsonArtifact.id);
    expect(report.presentation).toEqual({
      schemaVersion: "ti-scale.canonical-report-presentation.v1",
      contextPackId: "context-terminal-reporting",
      narrativeStyle: "technical_readable",
      evidencePresentation: "evidence_first",
      appliedPreferenceNodeIds: preferenceNodeIds.slice(0, 2),
      appliedPreferenceKeys: [
        "communication.technical_readability",
        "communication.evidence_first",
      ],
    });
    const markdown = reportMarkdown(database, artifactRoot, markdownArtifact.id);
    expect(markdown.indexOf("## Verified Evidence")).toBeLessThan(markdown.indexOf("## Plan"));
    expect(markdown).toContain("**Observed:** One exact service fingerprint was verified\\.");
    expect(markdown).toContain("**Integrity:** SHA-256");
    expect(markdown).toContain("**Why it matters:** Telnet does not provide transport encryption");
    expect(markdown).toContain("**Recommended action:** Disable Telnet");

    const dispositions = database.prepare(`
      SELECT node_id, used, influence_summary, ignored_reason
      FROM memory_context_items WHERE context_pack_id = ?
      ORDER BY rank
    `).all("context-terminal-reporting") as Array<Record<string, unknown>>;
    expect(dispositions.slice(0, 2).every(({ used, influence_summary }) =>
      used === 1 && typeof influence_summary === "string")).toBe(true);
    expect(dispositions[2]).toMatchObject({
      node_id: preferenceNodeIds[2],
      used: 0,
      influence_summary: null,
      ignored_reason: "Not yet applied to terminal reporting.",
    });
    expect(database.prepare(`
      SELECT context_pack_id,
        json_extract(payload_json, '$.safetyBoundary') AS safety_boundary
      FROM events WHERE event_type = ?
    `).get("brain.terminal_report_preferences_resolved")).toEqual({
      context_pack_id: "context-terminal-reporting",
      safety_boundary:
        "presentation_only_no_evidence_finding_scope_policy_or_deliverable_change",
    });

    database.prepare(`
      UPDATE preference_profiles SET value_json = '{"value":{"style":"changed"}}'
      WHERE preference_key = 'communication.technical_readability'
    `).run();
    const replay = service.completeAtomically(RUN_ID, () => "already-terminal");
    expect(replay.deliverables.report?.artifacts).toEqual(first.deliverables.report?.artifacts);
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM events WHERE event_type = ?
    `).get("brain.terminal_report_preferences_resolved")).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM findings").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 2 });
  });

  test("retains canonical report defaults and marks no node used for unsupported values", () => {
    const { database, artifactRoot, service } = fixture();
    seedTerminalReportPreferences(database, { supported: false });
    seedOrdinaryDnsObservation(database);

    const result = service.completeAtomically(RUN_ID, () => commitTerminal(database));
    const jsonArtifact = result.deliverables.report!.artifacts
      .find(({ format }) => format === "json")!;
    expect(reportJson(database, artifactRoot, jsonArtifact.id).presentation).toBeUndefined();
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM memory_context_items
      WHERE context_pack_id = ? AND used = 1
    `).get("context-terminal-reporting")).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT json_type(payload_json, '$.presentation') AS presentation_type
      FROM events WHERE event_type = ?
    `).get("brain.terminal_report_preferences_resolved")).toEqual({
      presentation_type: "null",
    });
  });

  test("produces only selected canonical report artifacts and keeps ordinary observations at zero findings", () => {
    const { database, artifactRoot, service } = fixture();
    seedOrdinaryDnsObservation(database);

    const first = service.completeAtomically(RUN_ID, () => commitTerminal(database));
    expect(first.terminal).toBe("terminal-committed");
    expect(first.deliverables.selectedDeliverableIds)
      .toEqual(["machine_readable_export", "pdf_html_markdown_report"]);
    expect(first.deliverables.findingIds).toEqual([]);
    expect(first.deliverables.report?.artifacts).toHaveLength(2);
    expect(contentFiles(artifactRoot)).toHaveLength(2);

    const jsonArtifact = first.deliverables.report!.artifacts.find(({ format }) => format === "json")!;
    const report = reportJson(database, artifactRoot, jsonArtifact.id);
    const findings = report.findings as { readonly verified: readonly unknown[] };
    expect(findings.verified).toEqual([]);
    expect(database.prepare("SELECT COUNT(*) AS count FROM findings").get()).toEqual({ count: 0 });

    const usageBefore = database.prepare("SELECT budget_usage_json FROM runs WHERE id = ?")
      .get(RUN_ID) as { readonly budget_usage_json: string };
    const replay = service.completeAtomically(RUN_ID, () => "already-terminal");
    expect(replay.deliverables.report?.artifacts).toEqual(first.deliverables.report?.artifacts);
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 2 });
    expect(database.prepare("SELECT budget_usage_json FROM runs WHERE id = ?").all(RUN_ID))
      .toEqual([usageBefore]);
    expect(contentFiles(artifactRoot)).toHaveLength(2);
  });

  test("materializes one stable verified finding only for an explicit exact Telnet policy reference", () => {
    const { database, artifactRoot, service } = fixture();
    const evidenceId = seedExplicitTelnetEvidence(database);

    const first = service.completeAtomically(RUN_ID, () => commitTerminal(database));
    expect(first.deliverables.findingIds).toHaveLength(1);
    const findingId = first.deliverables.findingIds[0]!;
    expect(database.prepare(`
      SELECT review_status, operator_override, version, severity, affected_scope
      FROM findings WHERE id = ?
    `).get(findingId)).toEqual({
      review_status: "verified",
      operator_override: 0,
      version: 2,
      severity: "low",
      affected_scope: "192.0.2.10:23/tcp",
    });
    expect(database.prepare(`
      SELECT relationship FROM finding_evidence WHERE finding_id = ? AND evidence_id = ?
    `).get(findingId, evidenceId)).toEqual({ relationship: "supports" });

    const jsonArtifact = first.deliverables.report!.artifacts.find(({ format }) => format === "json")!;
    const report = reportJson(database, artifactRoot, jsonArtifact.id);
    const findings = report.findings as { readonly verified: readonly { readonly id: string }[] };
    expect(findings.verified.map(({ id }) => id)).toEqual([findingId]);

    const replay = service.completeAtomically(RUN_ID, () => "already-terminal");
    expect(replay.deliverables.findingIds).toEqual([findingId]);
    expect(database.prepare("SELECT COUNT(*) AS count FROM findings").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM finding_evidence").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 2 });
  });

  test("rolls back terminal truth and new files on a post-materialization fault, then retries cleanly", () => {
    const { database, artifactRoot, service } = fixture();
    database.exec(`
      CREATE TEMP TRIGGER inject_terminal_report_failure
      BEFORE UPDATE OF budget_usage_json ON runs
      WHEN NEW.id = '${RUN_ID}'
      BEGIN
        SELECT RAISE(ABORT, 'injected post-materialization failure');
      END;
    `);

    expect(() => service.completeAtomically(RUN_ID, () => commitTerminal(database)))
      .toThrow("injected post-materialization failure");
    expect(database.prepare("SELECT status FROM runs WHERE id = ?").get(RUN_ID))
      .toEqual({ status: "running" });
    expect(database.prepare("SELECT status FROM missions WHERE id = ?").get(MISSION_ID))
      .toEqual({ status: "active" });
    expect(database.prepare("SELECT COUNT(*) AS count FROM run_evaluations").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 0 });
    expect(contentFiles(artifactRoot)).toEqual([]);

    database.exec("DROP TRIGGER inject_terminal_report_failure");
    const retried = service.completeAtomically(RUN_ID, () => commitTerminal(database));
    expect(retried.deliverables.report?.artifacts).toHaveLength(2);
    expect(database.prepare("SELECT status FROM runs WHERE id = ?").get(RUN_ID))
      .toEqual({ status: "completed" });
    expect(database.prepare("SELECT COUNT(*) AS count FROM run_evaluations").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 2 });
    expect(contentFiles(artifactRoot)).toHaveLength(2);
  });

  test("fails closed and rolls back when the contract selects an unproduced deliverable", () => {
    const { database, service } = fixture({ deliverables: ["executive_summary"] });
    expect(() => service.completeAtomically(RUN_ID, () => commitTerminal(database)))
      .toThrow(AutonomousTerminalDeliverableError);
    expect(database.prepare("SELECT status FROM runs WHERE id = ?").get(RUN_ID))
      .toEqual({ status: "running" });
    expect(database.prepare("SELECT COUNT(*) AS count FROM run_evaluations").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 0 });
  });
});

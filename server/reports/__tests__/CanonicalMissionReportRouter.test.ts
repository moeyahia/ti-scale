import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express from "express";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import type { OperationsAccessPolicy } from "../../operations";
import { createOperationsRouter } from "../../routes/operationsRoutes";

const NOW = "2026-07-20T05:00:00.000Z";
const LATER = "2026-07-20T05:10:00.000Z";
const HASH = "a".repeat(64);
const servers: Server[] = [];
const databases: ReturnType<typeof createDatabaseConnection>[] = [];
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const database of databases.splice(0)) database.close();
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function seedRun(
  database: ReturnType<typeof createDatabaseConnection>,
  input: {
    readonly missionId: string;
    readonly runId: string;
    readonly status: "running" | "blocked" | "completed";
    readonly controlPlane?: "legacy" | "ti_scale";
  },
): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, engagement_id, status, created_by, created_at, updated_at
    ) VALUES (?, ?, ?, 'guided', 'eng-report', ?, 'operator-test', ?, ?)
  `).run(
    input.missionId,
    `Mission ${input.missionId}`,
    "Assess the authorized lab. password=objective-secret",
    input.status === "completed" ? "completed" : "active",
    NOW,
    LATER,
  );
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      created_at, updated_at, started_at, ended_at
    ) VALUES (?, ?, 'guided', ?, ?, ?, ?, ?, ?, ?)
  `).run(
    input.runId,
    input.missionId,
    input.status,
    input.status === "completed" ? 1 : 0.5,
    input.status === "blocked" ? "Provider unavailable; token=run-secret" : "Canonical run state recorded",
    NOW,
    LATER,
    NOW,
    input.status === "completed" ? LATER : null,
  );
  if (input.controlPlane === "legacy") {
    database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = ?").run(input.missionId);
    database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = ?").run(input.runId);
  }
}

function seedCompletedTruth(database: ReturnType<typeof createDatabaseConnection>): void {
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES ('plan-complete', 'run-complete', 1, 'completed',
      'Map the authorized service', 'Use bounded local reconnaissance', ?, 'commander', ?, ?)
  `).run("b".repeat(64), NOW, NOW);
  database.prepare("UPDATE runs SET current_plan_id = 'plan-complete' WHERE id = 'run-complete'").run();
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      created_at, updated_at
    ) VALUES ('step-complete', 'plan-complete', 'run-complete', 0, 'recon',
      'Inspect the service', 'Identify the authorized service', 'completed', '[]', '[]',
      'service_enumeration', 'network', ?, ?)
  `).run(NOW, LATER);
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, action_type, action_class, fingerprint,
      normalized_arguments_json, scoped_target, status, intent_summary,
      result_summary, retry_count, created_at, updated_at
    ) VALUES ('action-complete', 'mission-complete', 'run-complete', 'step-complete',
      'scan', 'service_enumeration', ?, '{"password":"raw-action-secret"}', 'lab.local',
      'succeeded', 'Identify one approved service', 'Service observation retained', 0, ?, ?)
  `).run("c".repeat(64), NOW, LATER);
  database.prepare(`
    INSERT INTO engagement_log_records (
      id, mission_id, run_id, plan_id, step_id, action_id, severity, domain,
      record_type, human_summary, technical_payload_json, content_hash,
      sensitivity, occurred_at, created_at
    ) VALUES ('log-complete', 'mission-complete', 'run-complete', 'plan-complete',
      'step-complete', 'action-complete', 'notice', 'local_tool', 'command_result',
      'Tool finished; password=human-log-secret', '{"raw":"raw-payload-secret"}', ?,
      'private', ?, ?)
  `).run("d".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO observations (
      id, mission_id, run_id, step_id, observation_type, statement,
      normalized_value_json, confidence, verification_state, source_tool,
      first_seen_at, last_seen_at, sensitivity, created_at
    ) VALUES ('observation-complete', 'mission-complete', 'run-complete', 'step-complete',
      'service', 'TCP 443 appeared open', '{"secret":"observation-payload-secret"}',
      0.8, 'corroborated', 'nmap', ?, ?, 'private', ?)
  `).run(NOW, LATER, NOW);
  const evidence = database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, extracted_text, created_by, created_at
    ) VALUES (?, 'mission-complete', 'run-complete', 'step-complete', 'action-complete',
      ?, ?, 'lab.local', ?, ?, ?, 0.95, 'private', ?, ?, ?, 'reviewer', ?)
  `);
  evidence.run(
    "evidence-verified",
    "reviewed:local",
    NOW,
    "service_fingerprint",
    HASH,
    '{"password":"provenance-secret"}',
    "verified",
    "HTTPS service was independently verified",
    "raw evidence secret value",
    NOW,
  );
  evidence.run(
    "evidence-command-output",
    "local_tool",
    NOW,
    "command_output",
    "e".repeat(64),
    "{}",
    "verified",
    "Raw command output must not become verified evidence",
    "raw terminal body",
    NOW,
  );
  evidence.run(
    "evidence-mcp-unreviewed",
    "mcp:scanner",
    NOW,
    "tool_result",
    "f".repeat(64),
    "{}",
    "verified",
    "Unreviewed MCP process output",
    null,
    NOW,
  );
  evidence.run(
    "evidence-custody-incomplete",
    "reviewed:local",
    NOW,
    "service_fingerprint",
    "9".repeat(64),
    "{}",
    "verified",
    "Verification state without complete custody must remain review-only",
    null,
    NOW,
  );
  database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES
      ('custody-report-acquired', 'evidence-verified', 'acquired',
        'reviewed-local-verifier', '{}', ?),
      ('custody-report-verified', 'evidence-verified', 'verified',
        'reviewed-local-verifier', '{}', ?),
      ('custody-report-incomplete-acquired', 'evidence-custody-incomplete',
        'acquired', 'reviewed-local-verifier', '{}', ?)
  `).run(NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO findings (
      id, mission_id, run_id, title, severity, confidence, affected_scope,
      description, impact, remediation, review_status, created_at, updated_at
    ) VALUES (?, 'mission-complete', 'run-complete', ?, 'medium', 0.9,
      'lab.local', ?, 'Authorized impact only', 'Apply the tested correction', ?, ?, ?)
  `).run("finding-verified", "Verified service finding", "Evidence-backed conclusion", "verified", NOW, LATER);
  database.prepare(`
    INSERT INTO findings (
      id, mission_id, run_id, title, severity, confidence, affected_scope,
      description, impact, review_status, created_at, updated_at
    ) VALUES ('finding-unverified', 'mission-complete', 'run-complete',
      'Unverified service claim', 'high', 0.4, 'lab.local',
      'Must not be stated as fact', 'Unknown', 'draft', ?, ?)
  `).run(NOW, LATER);
  database.prepare(`
    INSERT INTO finding_evidence (finding_id, evidence_id, relationship, added_at)
    VALUES ('finding-verified', 'evidence-verified', 'supports', ?)
  `).run(NOW);
  database.prepare(`
    INSERT INTO topology_nodes (
      id, mission_id, run_id, node_type, primary_label, normalized_identity,
      scope_status, lifecycle_state, properties_json, confidence,
      verification_state, originating_tool, sensitivity, first_seen_at,
      last_seen_at, created_at, updated_at
    ) VALUES
      ('node-a', 'mission-complete', 'run-complete', 'asset', 'lab-web', 'lab-web',
        'allowed', 'validated', '{"password":"node-secret"}', 0.9, 'verified',
        'nmap', 'private', ?, ?, ?, ?),
      ('node-b', 'mission-complete', 'run-complete', 'service', 'HTTPS', 'lab-web:443',
        'allowed', 'validated', '{}', 0.9, 'verified', 'nmap', 'private', ?, ?, ?, ?)
  `).run(NOW, LATER, NOW, LATER, NOW, LATER, NOW, LATER);
  database.prepare(`
    INSERT INTO topology_edges (
      id, mission_id, source_node_id, target_node_id, edge_type, properties_json,
      confidence, verification_state, sensitivity, first_seen_at, last_seen_at
    ) VALUES ('edge-a', 'mission-complete', 'node-a', 'node-b', 'exposes',
      '{"token":"edge-secret"}', 0.9, 'verified', 'private', ?, ?)
  `).run(NOW, LATER);
  database.prepare(`
    INSERT INTO run_evaluations (
      id, mission_id, run_id, journey, scores_json, metrics_json, retrospective,
      evidence_coverage, created_by, created_at
    ) VALUES ('evaluation-complete', 'mission-complete', 'run-complete', 'guided',
      '{"completion":1}', '{"toolCalls":1}', 'Objective completed with verified evidence.',
      1, 'evaluator', ?)
  `).run(LATER);
  database.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, retrieval_metrics_json, created_by, created_at
    ) VALUES ('context-complete', 'mission-complete', 'run-complete', 'guided',
      'reporting', '[REDACTED]', '{}', 256, '{}', 'commander', ?)
  `).run(NOW);
}

function seedBlockedDiagnosis(database: ReturnType<typeof createDatabaseConnection>): void {
  database.prepare(`
    INSERT INTO failure_diagnoses (
      id, mission_id, run_id, subject_type, subject_id, human_reason, category,
      code, originating_component, retry_history_json, progress_before_failure_json,
      preserved_refs_json, retryable, automatic_recovery_json, remediation,
      operator_actions_json, objective_impact, state, created_at
    ) VALUES ('failure-blocked', 'mission-blocked', 'run-blocked', 'run', 'run-blocked',
      'Required provider is unavailable', 'provider_unavailable', 'provider_offline',
      'provider-router', '[]', '{}', '[]', 1, '[]',
      'Restore the configured provider and retry from the checkpoint.', '[]',
      'The remaining objective is paused.', 'active', ?)
  `).run(NOW);
}

async function application() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  seedRun(database, { missionId: "mission-complete", runId: "run-complete", status: "completed" });
  seedRun(database, { missionId: "mission-empty", runId: "run-empty", status: "running" });
  seedRun(database, { missionId: "mission-blocked", runId: "run-blocked", status: "blocked" });
  seedRun(database, { missionId: "mission-imported", runId: "run-imported", status: "completed", controlPlane: "legacy" });
  seedCompletedTruth(database);
  seedBlockedDiagnosis(database);
  const artifactRoot = mkdtempSync(join(tmpdir(), "ti-scale-report-tests-"));
  temporaryDirectories.push(artifactRoot);
  const access: OperationsAccessPolicy = {
    maximumSensitivity: "restricted",
    allEngagements: true,
    allowGlobalKnowledge: true,
    allowUnscopedSystemData: true,
  };
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(createOperationsRouter({
    database,
    reportArtifactRoot: artifactRoot,
    clock: () => new Date("2026-07-20T05:15:00.000Z"),
    resolveActor: (request) => request.get("X-Test-Authenticated") === "yes"
      ? { id: "operator-test", type: "operator" }
      : { id: "", type: "operator" },
    resolveAccess: () => access,
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address() as AddressInfo;
  return { database, artifactRoot, url: `http://127.0.0.1:${address.port}` };
}

const authenticated = {
  "Content-Type": "application/json",
  "X-Test-Authenticated": "yes",
} as const;

async function generate(url: string, runId: string, version: number, key = `report:${runId}:${version}`) {
  return fetch(`${url}/api/v2/reports/runs/${encodeURIComponent(runId)}/generate`, {
    method: "POST",
    headers: { ...authenticated, "Idempotency-Key": key },
    body: JSON.stringify({ reportVersion: version }),
  });
}

describe("canonical mission report routes", () => {
  test("requires an authenticated actor and idempotency key", async () => {
    const { url } = await application();
    const unauthenticated = await fetch(`${url}/api/v2/reports/runs/run-complete/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "report:unauthenticated" },
      body: JSON.stringify({ reportVersion: 1 }),
    });
    expect(unauthenticated.status).toBe(401);
    const missingKey = await fetch(`${url}/api/v2/reports/runs/run-complete/generate`, {
      method: "POST",
      headers: authenticated,
      body: JSON.stringify({ reportVersion: 1 }),
    });
    expect(missingKey.status).toBe(400);
  });

  test("generates deterministic redacted Markdown and JSON and preserves evidence taxonomy", async () => {
    const { database, url } = await application();
    const response = await generate(url, "run-complete", 1);
    expect(response.status).toBe(201);
    const generated = await response.json() as {
      sourceSnapshotHash: string;
      artifacts: Array<{ id: string; format: "markdown" | "json"; downloadUrl: string; contentHash: string }>;
    };
    expect(generated.artifacts).toHaveLength(2);
    const firstIds = generated.artifacts.map((item) => item.id);

    const repeated = await generate(url, "run-complete", 1, "report:run-complete:retry");
    expect(repeated.status).toBe(201);
    expect((await repeated.json() as typeof generated).artifacts.map((item) => item.id)).toEqual(firstIds);
    expect((database.prepare("SELECT COUNT(*) AS count FROM artifacts WHERE run_id = 'run-complete' AND artifact_type LIKE 'mission_report_%'").get() as { count: number }).count).toBe(2);
    expect((database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE action = 'report.generated' AND run_id = 'run-complete'").get() as { count: number }).count).toBe(1);

    const jsonArtifact = generated.artifacts.find((item) => item.format === "json")!;
    const jsonDownload = await fetch(`${url}${jsonArtifact.downloadUrl}`, { headers: { "X-Test-Authenticated": "yes" } });
    expect(jsonDownload.status).toBe(200);
    expect(jsonDownload.headers.get("content-disposition")).toContain("attachment");
    expect(jsonDownload.headers.get("digest")).toStartWith("sha-256=");
    const jsonText = await jsonDownload.text();
    expect(createHash("sha256").update(jsonText).digest("hex")).toBe(jsonArtifact.contentHash);
    const report = JSON.parse(jsonText) as Record<string, any>;
    expect(report.engagementLogs.classification).toBe("technical_record_not_evidence");
    expect(report.observations.classification).toBe("parsed_statement_not_automatically_verified");
    expect(report.verifiedEvidence.records.map((item: any) => item.id)).toEqual(["evidence-verified"]);
    expect(report.findings.verified.map((item: any) => item.id)).toEqual(["finding-verified"]);
    expect(report.findings.reviewRequired.map((item: any) => item.id)).toEqual(["finding-unverified"]);
    expect(jsonText).not.toContain("raw-payload-secret");
    expect(jsonText).not.toContain("raw-action-secret");
    expect(jsonText).not.toContain("raw evidence secret value");
    expect(jsonText).not.toContain("provenance-secret");
    expect(jsonText).not.toContain("objective-secret");
    expect(jsonText).not.toContain("human-log-secret");
    expect(jsonText).not.toContain("node-secret");
    expect(jsonText).not.toContain(
      "Verification state without complete custody must remain review-only",
    );

    const markdownArtifact = generated.artifacts.find((item) => item.format === "markdown")!;
    const markdownDownload = await fetch(`${url}${markdownArtifact.downloadUrl}`, { headers: { "X-Test-Authenticated": "yes" } });
    expect(markdownDownload.status).toBe(200);
    const markdown = await markdownDownload.text();
    expect(markdown).toContain("Engagement Log (not evidence)");
    expect(markdown).toContain("Observations (not automatically verified)");
    expect(markdown).toContain("Verified Evidence");
    expect(markdown).toContain("Review required (not asserted as fact)");
  });

  test("same report version conflicts after canonical state changes and a new version succeeds", async () => {
    const { database, url } = await application();
    expect((await generate(url, "run-complete", 1)).status).toBe(201);
    database.prepare("UPDATE runs SET status_reason = 'Canonical state changed', updated_at = ? WHERE id = 'run-complete'").run("2026-07-20T05:20:00.000Z");
    const staleVersion = await generate(url, "run-complete", 1, "report:run-complete:changed");
    expect(staleVersion.status).toBe(409);
    expect((await generate(url, "run-complete", 2)).status).toBe(201);
  });

  test("reports empty, blocked, and imported canonical runs without granting control authority", async () => {
    const { database, url } = await application();
    for (const [runId, version] of [["run-empty", 1], ["run-blocked", 1], ["run-imported", 1]] as const) {
      const generated = await generate(url, runId, version);
      expect(generated.status).toBe(201);
      const body = await generated.json() as { artifacts: Array<{ format: string; downloadUrl: string }> };
      const artifact = body.artifacts.find((item) => item.format === "json")!;
      const downloaded = await fetch(`${url}${artifact.downloadUrl}`, { headers: { "X-Test-Authenticated": "yes" } });
      expect(downloaded.status).toBe(200);
      const report = await downloaded.json() as Record<string, any>;
      if (runId === "run-empty") {
        expect(report.actions.records).toEqual([]);
        expect(report.verifiedEvidence.records).toEqual([]);
        expect(report.evaluation).toBeNull();
      }
      if (runId === "run-blocked") {
        expect(report.run.status).toBe("blocked");
        expect(report.failureDiagnoses.records[0]).toMatchObject({ code: "provider_offline", retryable: true });
      }
      if (runId === "run-imported") {
        expect(report.mission.imported).toBe(true);
        expect(report.mission.controlPlane).toBe("legacy");
        expect(report.run.controlPlane).toBe("legacy");
      }
    }
    expect((database.prepare("SELECT control_plane FROM missions WHERE id = 'mission-imported'").get() as { control_plane: string }).control_plane).toBe("legacy");
    expect((database.prepare("SELECT control_plane FROM runs WHERE id = 'run-imported'").get() as { control_plane: string }).control_plane).toBe("legacy");
    expect((database.prepare("SELECT COUNT(*) AS count FROM control_plane_leases WHERE run_id = 'run-imported'").get() as { count: number }).count).toBe(0);
  });

  test("exact download route never resolves artifact IDs into paths", async () => {
    const { url } = await application();
    const generated = await generate(url, "run-complete", 1);
    const body = await generated.json() as { artifacts: Array<{ downloadUrl: string }> };
    expect((await fetch(`${url}${body.artifacts[0]!.downloadUrl}`, { headers: { "X-Test-Authenticated": "yes" } })).status).toBe(200);
    expect((await fetch(`${url}/api/v2/reports/missing-report/download`, { headers: { "X-Test-Authenticated": "yes" } })).status).toBe(404);
    expect((await fetch(`${url}/api/v2/reports/%2e%2e%2fprivate-key/download`, { headers: { "X-Test-Authenticated": "yes" } })).status).toBe(404);
  });
});

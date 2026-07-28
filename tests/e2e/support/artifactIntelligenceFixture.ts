import { createHash } from "node:crypto";
import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
// Import the path-only module directly. The broad server/app barrel also
// exports Bun-native execution adapters, which must not be loaded into the
// Node-based Playwright fixture process.
import { resolveV2ScriptSourceRoot } from "../../../server/app/V2ArtifactPaths";
import { PageCaptureService } from "../../../server/page-captures";
import { FileScriptSourceStore, ScriptArtifactService } from "../../../server/script-artifacts";
import {
  E2E_DATABASE_PATH,
  E2E_SCRIPT_SOURCE_ROOT,
} from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const NOW = "2026-07-16T19:00:00.000Z";
const ACTOR = { id: "e2e-local-operator", type: "operator" as const };
const SCREENSHOT_HASH = "b".repeat(64);
const FULL_PAGE_HASH = "f".repeat(64);
const CONTENT_HASH = "c".repeat(64);

export interface ArtifactIntelligenceFixture {
  readonly missionId: string;
  readonly runId: string;
  readonly scriptName: string;
  readonly scriptVersionTwoId: string;
  readonly scriptArtifactId: string;
  readonly scriptTestArtifactId: string;
  readonly captureId: string;
  readonly captureTitle: string;
  readonly screenshotArtifactId: string;
  readonly fullPageArtifactId: string;
  readonly evidenceId: string;
  readonly findingId: string;
}

function representedAction(target: string): string {
  return JSON.stringify({
    action: {
      actionType: "web_crawling_page_capture",
      actionClass: "web_crawling_page_capture",
      target,
      arguments: {},
      intentSummary: "Preserve authorized application metadata",
      kind: "manual",
      idempotent: true,
      destructive: false,
    },
    explanation: "Preserve one attributable web-application observation.",
    rationale: "Reduce uncertainty without changing target state.",
    reversibility: "Read only",
    dependencies: [],
  });
}

export function createArtifactIntelligenceFixture(instanceId: string): ArtifactIntelligenceFixture {
  if (!E2E_DATABASE_PATH) throw new Error("Artifact-intelligence E2E requires the isolated V2 database path");
  const namespace = normalizeFixtureNamespace(instanceId);
  const fixtureId = (prefix: string): string => `${prefix}-${namespace}`;
  const missionId = fixtureId("mission-artifact-intelligence-e2e");
  const runId = fixtureId("run-artifact-intelligence-e2e");
  const planId = fixtureId("plan-artifact-intelligence-e2e");
  const stepId = fixtureId("step-artifact-intelligence-e2e");
  const agentId = fixtureId("agent-artifact-intelligence-e2e");
  const targetId = fixtureId("target-artifact-intelligence-e2e");
  const assetId = fixtureId("asset-artifact-intelligence-e2e");
  const serviceId = fixtureId("service-artifact-intelligence-e2e");
  const screenshotArtifactId = fixtureId("artifact-screenshot-intelligence-e2e");
  const fullPageArtifactId = fixtureId("artifact-full-page-intelligence-e2e");
  const scriptTestArtifactId = fixtureId("artifact-script-test-intelligence-e2e");
  const evidenceId = fixtureId("evidence-artifact-intelligence-e2e");
  const findingId = fixtureId("finding-artifact-intelligence-e2e");
  const target = "https://artifact-fixture.example.test/app";
  const scriptName = "recon/http_metadata_probe.py";
  const topologyProperties = JSON.stringify({
    data: {},
    provenance: {
      method: "e2e_browser_fixture",
      sourceRef: evidenceId,
      sourceAgentId: agentId,
      sourceTool: "e2e-browser-capture",
    },
  });
  const database = createDatabaseConnection({ filename: E2E_DATABASE_PATH, fileMustExist: true, busyTimeoutMs: 120_000 });
  try {
    inImmediateTransaction(database, () => {
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status, scope_json,
          success_criteria_json, retention_policy_json, memory_policy_json,
          created_by, created_at, updated_at
        ) VALUES (?, 'Artifact intelligence fixture', 'Inspect canonical scripts and page captures without execution',
          'guided', 'active', 'verified', ?, ?, '{}', '{}', ?, ?, ?)
      `).run(missionId, JSON.stringify({ environment: "authorized_local_fixture", controlPlane: "ti_scale" }), JSON.stringify(["Retain immutable source and capture provenance"]), ACTOR.id, NOW, NOW);
      database.prepare(`
        INSERT INTO mission_targets (id, mission_id, target, target_type, disposition, normalized_target, metadata_json, created_at)
        VALUES (?, ?, ?, 'url', 'allowed', ?, '{}', ?)
      `).run(targetId, missionId, target, target, NOW);
      database.prepare(`
        INSERT INTO agents (id, role, display_name, status, provider_policy_json, tool_policy_json, configuration_json, version, created_at, updated_at)
        VALUES (?, 'web', 'Web evidence specialist', 'available', '{}', '{}', '{}', 'e2e-1', ?, ?)
      `).run(agentId, NOW, NOW);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, current_plan_id, current_step_id, progress,
          status_reason, next_action_summary, budget_json, budget_usage_json,
          created_at, updated_at, version
        ) VALUES (?, ?, 'guided', 'queued', ?, ?, 0, 'Awaiting represented operator review',
          'Inspect immutable intelligence records', '{}', '{}', ?, ?, 1)
      `).run(runId, missionId, planId, stepId, NOW, NOW);
      database.prepare(`
        INSERT INTO plans (id, run_id, version, status, strategy_summary, rationale_summary, plan_hash, created_by, created_at, activated_at)
        VALUES (?, ?, 1, 'active', 'Inspect retained application intelligence', 'No execution occurs in this review fixture', ?, ?, ?, ?)
      `).run(planId, runId, createHash("sha256").update(planId).digest("hex"), ACTOR.id, NOW, NOW);
      database.prepare(`
        INSERT INTO plan_steps (
          id, plan_id, run_id, ordinal, phase, title, objective, status,
          success_criteria_json, dependencies_json, action_class, risk_class,
          assigned_agent_id, created_at, updated_at
        ) VALUES (?, ?, ?, 0, 'Recon', 'Review application metadata',
          'Inspect immutable evidence without executing the source', 'ready', ?, '[]',
          'web_crawling_page_capture', 'low', ?, ?, ?)
      `).run(stepId, planId, runId, JSON.stringify(["Source and capture provenance remain inspectable"]), agentId, NOW, NOW);
      database.prepare(`
        INSERT INTO mission_constraints (id, mission_id, constraint_type, value_json, source, created_at)
        VALUES (?, ?, 'represented_action', ?, ?, ?)
      `).run(fixtureId("constraint-artifact-intelligence-e2e"), missionId, representedAction(target), stepId, NOW);
      database.prepare(`
        INSERT INTO topology_nodes (
          id, mission_id, run_id, node_type, primary_label, normalized_identity,
          scope_status, lifecycle_state, properties_json, confidence,
          verification_state, originating_agent_id, originating_tool,
          sensitivity, first_seen_at, last_seen_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'allowed', 'observed', ?, 1, 'verified', ?,
          'e2e-browser-capture', 'internal', ?, ?, ?, ?)
      `).run(assetId, missionId, runId, "host", "artifact-fixture.example.test", "artifact-fixture.example.test", topologyProperties, agentId, NOW, NOW, NOW, NOW);
      database.prepare(`
        INSERT INTO topology_nodes (
          id, mission_id, run_id, node_type, primary_label, normalized_identity,
          scope_status, lifecycle_state, properties_json, confidence,
          verification_state, originating_agent_id, originating_tool,
          sensitivity, first_seen_at, last_seen_at, created_at, updated_at
        ) VALUES (?, ?, ?, 'web_application', 'Artifact Fixture HTTPS', ?, 'allowed',
          'observed', ?, 1, 'verified', ?, 'e2e-browser-capture', 'internal', ?, ?, ?, ?)
      `).run(serviceId, missionId, runId, target, topologyProperties, agentId, NOW, NOW, NOW, NOW);
      database.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, step_id, journey, artifact_type, storage_uri,
          content_hash, byte_size, media_type, sensitivity, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, 'guided', 'screenshot', ?, ?, 12400,
          'image/png', 'internal', '{}', ?)
      `).run(screenshotArtifactId, missionId, runId, stepId, `artifacts-v2/e2e/${namespace}/page.png`, SCREENSHOT_HASH, NOW);
      database.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, step_id, journey, artifact_type, storage_uri,
          content_hash, byte_size, media_type, sensitivity, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, 'guided', 'full_page_capture', ?, ?, 35800,
          'image/png', 'internal', '{}', ?)
      `).run(fullPageArtifactId, missionId, runId, stepId, `artifacts-v2/e2e/${namespace}/page-full.png`, FULL_PAGE_HASH, NOW);
      database.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, step_id, journey, artifact_type, storage_uri,
          content_hash, byte_size, media_type, sensitivity, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, 'guided', 'script_test_result', ?, ?, 480,
          'application/json', 'internal', '{}', ?)
      `).run(scriptTestArtifactId, missionId, runId, stepId, `artifacts-v2/e2e/${namespace}/script-test.json`, "e".repeat(64), NOW);
      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, step_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity, verification_state,
          summary, artifact_id, created_by, created_at
        ) VALUES (?, ?, ?, ?, 'e2e-browser-capture', ?, ?, 'web_page_capture', ?,
          '{"method":"local_browser_fixture","sources":[]}', 1, 'internal', 'verified',
          'Authorized application landing-page capture', ?, ?, ?)
      `).run(evidenceId, missionId, runId, stepId, NOW, target, SCREENSHOT_HASH, screenshotArtifactId, agentId, NOW);
      database.prepare(`
        INSERT INTO topology_evidence_links (subject_type, subject_id, evidence_id, relationship, created_at)
        VALUES ('node', ?, ?, 'source', ?)
      `).run(assetId, evidenceId, NOW);
      database.prepare(`
        INSERT INTO topology_evidence_links (subject_type, subject_id, evidence_id, relationship, created_at)
        VALUES ('node', ?, ?, 'source', ?)
      `).run(serviceId, evidenceId, NOW);
      database.prepare(`
        INSERT INTO findings (
          id, mission_id, run_id, title, severity, confidence, affected_scope,
          description, impact, remediation, review_status, created_at, updated_at
        ) VALUES (?, ?, ?, 'Fixture security-header observation', 'informational', 1, ?,
          'A retained capture records the fixture response metadata.', 'No exploitability claim is made.',
          'Review the evidence-linked metadata.', 'verified', ?, ?)
      `).run(findingId, missionId, runId, target, NOW, NOW);
      database.prepare("INSERT INTO finding_evidence (finding_id, evidence_id, relationship, added_at) VALUES (?, ?, 'supports', ?)").run(findingId, evidenceId, NOW);
    });

    const sourceStore = new FileScriptSourceStore(resolveV2ScriptSourceRoot(
      E2E_DATABASE_PATH,
      E2E_SCRIPT_SOURCE_ROOT,
    ));
    const scripts = new ScriptArtifactService(database, sourceStore, () => new Date(NOW));
    const documentation = {
      language: "python" as const,
      laymanExplanation: "Collects one bounded response-metadata marker from the authorized fixture.",
      technicalPurpose: "Parses supplied local fixture metadata and emits a deterministic summary without initiating a connection.",
      inputs: [{ name: "CAPTURE_PATH", description: "Path to an already retained local capture.", required: true, sensitivity: "ordinary" as const }],
      expectedOutputs: [{ label: "Metadata marker", description: "One normalized status line.", successRecognition: "The exact metadata-ready marker is present.", failureRecognition: "The parser exits before producing the marker." }],
      prerequisites: ["Python 3 in the approved isolated environment."], dependencies: ["Python standard library."],
      touches: { files: ["The supplied read-only capture path."], network: [], services: [] },
      sideEffects: ["No source execution occurs while creating or reviewing this record."], riskClass: "low" as const,
      reversibility: "Review is read only; immutable source history remains auditable.",
      cleanupNotes: "No target cleanup is needed because this record does not execute source.",
      secretsHandling: "No credentials are accepted or retained.", evidenceExpectations: ["A separately authorized parser test artifact before any tested classification."],
      provenance: { origin: "agent_generated" as const, explanation: "The web specialist proposed a bounded offline helper for operator review.", sourceRefs: [`plan-step:${stepId}`], authorAgentId: agentId },
      sensitivity: "internal" as const,
    };
    const first = scripts.create({ missionId, runId, planId, stepId, targetNodeId: assetId, name: scriptName, ...documentation, source: "#!/usr/bin/env python3\nprint('metadata-ready')\n", validation: { state: "unvalidated", summary: "Documented source has not been executed.", tests: [] } }, ACTOR);
    const second = scripts.createVersion({
      ...documentation, scriptArtifactId: first.id, expectedVersion: 1,
      source: "#!/usr/bin/env python3\n# Offline parser fixture; no network access.\nprint('metadata-ready:v2')\n",
      changeSummary: "Document offline-only behavior and make the deterministic marker version-specific.",
      expectedOutputs: [{ ...documentation.expectedOutputs[0], successRecognition: "The exact metadata-ready:v2 marker is present." }],
      validation: { state: "tested", summary: "An isolated offline parser test passed; no target action was performed.", tests: [{ name: "Offline parser fixture", status: "passed", summary: "The source produced the expected marker against an isolated local fixture." }], testArtifactId: scriptTestArtifactId },
      provenance: { ...documentation.provenance, origin: "modified", explanation: "Operator-reviewed documentation amendment to the prior immutable version." },
    }, ACTOR);

    const capture = new PageCaptureService(database, () => new Date(NOW)).create({
      missionId, runId, planId, stepId, assetNodeId: assetId, serviceNodeId: serviceId,
      url: `${target}/login?view=compact`, responseStatus: 200, title: "Authorized Fixture Sign In",
      viewport: { width: 1440, height: 900, deviceScaleFactor: 1, isMobile: false, fullPage: true },
      screenshot: { artifactId: screenshotArtifactId, sha256: SCREENSHOT_HASH }, fullPageScreenshot: { artifactId: fullPageArtifactId, sha256: FULL_PAGE_HASH }, contentHash: CONTENT_HASH,
      certificate: { protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", subjectCommonName: "artifact-fixture.example.test", issuerCommonName: "E2E Fixture CA", sanDnsNames: ["artifact-fixture.example.test"], validFrom: "2026-07-01T00:00:00.000Z", validTo: "2027-07-01T00:00:00.000Z", fingerprintSha256: "d".repeat(64), verified: true },
      site: { contentType: "text/html; charset=utf-8", contentLength: 4096, language: "en", contentEncoding: "gzip", serverProduct: "fixture-server/2.4", technologies: ["Fixture UI"], securityHeaders: [{ name: "content-security-policy", value: "default-src 'self'" }] },
      capturedByAgentId: agentId, captureTool: "playwright.page.screenshot", sensitivity: "internal", redactionState: "not_required", capturedAt: "2026-07-16T18:59:00.000Z",
      evidenceIds: [evidenceId], findingIds: [findingId], observationIds: [],
    }, ACTOR);
    return { missionId, runId, scriptName, scriptVersionTwoId: second.id, scriptArtifactId: second.artifactId, scriptTestArtifactId, captureId: capture.id, captureTitle: capture.title!, screenshotArtifactId, fullPageArtifactId, evidenceId, findingId };
  } finally { database.close(); }
}

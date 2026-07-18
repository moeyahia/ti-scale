import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import type { CreatePageCaptureInput } from "../types";

export const NOW = "2026-07-16T18:00:00.000Z";
export const MISSION_ID = "mission-page-capture";
export const RUN_ID = "run-page-capture";
export const PLAN_ID = "plan-page-capture";
export const STEP_ID = "step-page-capture";
export const AGENT_ID = "agent-page-capture";
export const ASSET_ID = "asset-page-capture";
export const SERVICE_ID = "service-page-capture";
export const SCREENSHOT_ID = "artifact-page-screenshot";
export const FULL_PAGE_ID = "artifact-page-full";
export const EVIDENCE_ID = "evidence-page-capture";
export const OBSERVATION_ID = "observation-page-capture";
export const FINDING_ID = "finding-page-capture";
export const FOREIGN_MISSION_ID = "mission-page-capture-foreign";
export const FOREIGN_RUN_ID = "run-page-capture-foreign";
export const FOREIGN_ARTIFACT_ID = "artifact-page-capture-foreign";

export const SCREENSHOT_HASH = "a".repeat(64);
export const FULL_PAGE_HASH = "b".repeat(64);
export const CONTENT_HASH = "c".repeat(64);

function insertMission(database: SqliteDatabase, id: string, authorization = "verified"): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, scope_json,
      success_criteria_json, retention_policy_json, memory_policy_json,
      created_by, created_at, updated_at
    ) VALUES (?, ?, 'Record supplied authorized page captures', 'guided', 'active', ?, '{}', '[]', '{}', '{}', 'operator', ?, ?)
  `).run(id, `Page capture fixture ${id}`, authorization, NOW, NOW);
}

function insertRun(database: SqliteDatabase, missionId: string, runId: string): void {
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, created_at, updated_at, version
    ) VALUES (?, ?, 'guided', 'running', ?, ?, 1)
  `).run(runId, missionId, NOW, NOW);
}

export function createPageCaptureFixtureDatabase(): SqliteDatabase {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  insertMission(database, MISSION_ID);
  insertMission(database, FOREIGN_MISSION_ID);
  insertRun(database, MISSION_ID, RUN_ID);
  insertRun(database, FOREIGN_MISSION_ID, FOREIGN_RUN_ID);

  const insertTarget = database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition,
      normalized_target, metadata_json, created_at
    ) VALUES (?, ?, ?, 'url', ?, ?, '{}', ?)
  `);
  insertTarget.run(
    "target-page-capture-allowed",
    MISSION_ID,
    "https://portal.example.test/app",
    "allowed",
    "https://portal.example.test/app",
    NOW,
  );
  insertTarget.run(
    "target-page-capture-prohibited",
    MISSION_ID,
    "https://portal.example.test/app/admin",
    "prohibited",
    "https://portal.example.test/app/admin",
    NOW,
  );
  insertTarget.run(
    "target-page-capture-foreign",
    FOREIGN_MISSION_ID,
    "https://foreign.example.test/",
    "allowed",
    "https://foreign.example.test/",
    NOW,
  );

  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, created_at, updated_at
    ) VALUES (?, 'web', 'Web capture specialist', 'available', '{}', '{}', '{}', '1', ?, ?)
  `).run(AGENT_ID, NOW, NOW);

  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Capture the authorized application landing page',
      'Preserve a screenshot and response metadata', ?, 'planner', ?, ?)
  `).run(PLAN_ID, RUN_ID, "1".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'Recon', 'Capture application landing page',
      'Preserve the authorized page state', 'completed', '[]', '[]',
      'web_crawling_page_capture', 'network', ?, ?, ?)
  `).run(STEP_ID, PLAN_ID, RUN_ID, AGENT_ID, NOW, NOW);

  const insertNode = database.prepare(`
    INSERT INTO topology_nodes (
      id, mission_id, run_id, node_type, primary_label, normalized_identity,
      scope_status, lifecycle_state, properties_json, confidence,
      verification_state, originating_agent_id, originating_tool,
      sensitivity, first_seen_at, last_seen_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'allowed', 'observed', '{}', 1,
      'verified', ?, 'fixture', 'internal', ?, ?, ?, ?)
  `);
  insertNode.run(ASSET_ID, MISSION_ID, RUN_ID, "host", "portal.example.test", "portal.example.test", AGENT_ID, NOW, NOW, NOW, NOW);
  insertNode.run(SERVICE_ID, MISSION_ID, RUN_ID, "web_application", "Customer Portal HTTPS", "https://portal.example.test:443", AGENT_ID, NOW, NOW, NOW, NOW);
  insertNode.run(
    "asset-page-capture-foreign",
    FOREIGN_MISSION_ID,
    FOREIGN_RUN_ID,
    "host",
    "foreign.example.test",
    "foreign.example.test",
    AGENT_ID,
    NOW,
    NOW,
    NOW,
    NOW,
  );

  const insertArtifact = database.prepare(`
    INSERT INTO artifacts (
      id, mission_id, run_id, step_id, artifact_type, storage_uri,
      content_hash, byte_size, media_type, sensitivity, metadata_json, created_at,
      journey
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'image/png', ?, '{}', ?, 'guided')
  `);
  insertArtifact.run(
    SCREENSHOT_ID, MISSION_ID, RUN_ID, STEP_ID, "screenshot",
    "artifacts-v2/page-captures/viewport.png", SCREENSHOT_HASH, 12_400, "internal", NOW,
  );
  insertArtifact.run(
    FULL_PAGE_ID, MISSION_ID, RUN_ID, STEP_ID, "full_page_capture",
    "artifacts-v2/page-captures/full.png", FULL_PAGE_HASH, 35_800, "internal", NOW,
  );
  insertArtifact.run(
    FOREIGN_ARTIFACT_ID, FOREIGN_MISSION_ID, FOREIGN_RUN_ID, null, "screenshot",
    "artifacts-v2/page-captures/foreign.png", "e".repeat(64), 3_100, "restricted", NOW,
  );

  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, artifact_id, created_by, created_at
    ) VALUES (?, ?, ?, ?, 'page-capture-fixture', ?, ?, 'web_page_capture', ?,
      '{"method":"local_capture","sources":[]}', 1, 'internal', 'verified',
      'Authorized portal landing page capture', ?, ?, ?)
  `).run(
    EVIDENCE_ID, MISSION_ID, RUN_ID, STEP_ID, NOW,
    "https://portal.example.test/app/login", SCREENSHOT_HASH,
    SCREENSHOT_ID, AGENT_ID, NOW,
  );
  database.prepare(`
    INSERT INTO observations (
      id, mission_id, run_id, step_id, asset_id, observation_type, statement,
      normalized_value_json, confidence, verification_state, source_agent_id,
      source_tool, first_seen_at, last_seen_at, sensitivity, created_at
    ) VALUES (?, ?, ?, ?, ?, 'http_response', 'Portal returned HTTP 200',
      '{"status":200}', 1, 'corroborated', ?, 'browser-capture', ?, ?, 'internal', ?)
  `).run(OBSERVATION_ID, MISSION_ID, RUN_ID, STEP_ID, ASSET_ID, AGENT_ID, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO findings (
      id, mission_id, run_id, title, severity, confidence, affected_scope,
      description, impact, remediation, review_status, created_at, updated_at
    ) VALUES (?, ?, ?, 'Missing framing protection', 'low', 0.95,
      'portal.example.test', 'The captured response omitted X-Frame-Options.',
      'The page may be frameable.', 'Set a CSP frame-ancestors directive.',
      'verified', ?, ?)
  `).run(FINDING_ID, MISSION_ID, RUN_ID, NOW, NOW);
  database.prepare(`
    INSERT INTO finding_evidence (finding_id, evidence_id, relationship, added_at)
    VALUES (?, ?, 'supports', ?)
  `).run(FINDING_ID, EVIDENCE_ID, NOW);

  return database;
}

export function validPageCaptureInput(overrides: Partial<CreatePageCaptureInput> = {}): CreatePageCaptureInput {
  return {
    missionId: MISSION_ID,
    runId: RUN_ID,
    planId: PLAN_ID,
    stepId: STEP_ID,
    assetNodeId: ASSET_ID,
    serviceNodeId: SERVICE_ID,
    url: "https://portal.example.test/app/login?lang=en&view=compact",
    responseStatus: 200,
    title: "Customer Portal Sign In",
    viewport: {
      width: 1_440,
      height: 900,
      deviceScaleFactor: 1,
      isMobile: false,
      fullPage: true,
    },
    screenshot: { artifactId: SCREENSHOT_ID, sha256: SCREENSHOT_HASH },
    fullPageScreenshot: { artifactId: FULL_PAGE_ID, sha256: FULL_PAGE_HASH },
    contentHash: CONTENT_HASH,
    certificate: {
      protocol: "TLSv1.3",
      cipher: "TLS_AES_256_GCM_SHA384",
      subjectCommonName: "portal.example.test",
      issuerCommonName: "Fixture Test CA",
      sanDnsNames: ["portal.example.test"],
      validFrom: "2026-07-01T00:00:00.000Z",
      validTo: "2027-07-01T00:00:00.000Z",
      fingerprintSha256: "d".repeat(64),
      verified: true,
    },
    site: {
      contentType: "text/html; charset=utf-8",
      contentLength: 4_096,
      language: "en",
      contentEncoding: "gzip",
      serverProduct: "nginx/1.24.0",
      technologies: ["nginx", "React"],
      securityHeaders: [
        { name: "content-security-policy", value: "default-src 'self'" },
        { name: "strict-transport-security", value: "max-age=31536000" },
      ],
    },
    capturedByAgentId: AGENT_ID,
    captureTool: "playwright.page.screenshot",
    sensitivity: "internal",
    redactionState: "not_required",
    capturedAt: "2026-07-16T17:59:00.000Z",
    evidenceIds: [EVIDENCE_ID],
    observationIds: [OBSERVATION_ID],
    findingIds: [FINDING_ID],
    ...overrides,
  };
}
